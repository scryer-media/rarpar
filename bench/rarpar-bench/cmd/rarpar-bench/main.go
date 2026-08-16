package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"strings"

	"github.com/scryer-media/rarpar/bench/rarpar-bench/internal/bench"
	"github.com/scryer-media/rarpar/bench/rarpar-bench/internal/oci"
	"github.com/scryer-media/rarpar/bench/rarpar-bench/internal/testcorpus"
)

func main() {
	if err := run(context.Background(), os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "rarpar-bench:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string) error {
	if len(args) == 0 {
		usage()
		return nil
	}
	switch args[0] {
	case "toolchains":
		return runToolchains(ctx, args[1:])
	case "corpus":
		return runCorpus(ctx, args[1:])
	case "payload":
		return runPayload(ctx, args[1:], os.Stdout)
	case "testcorpus":
		return runTestCorpus(ctx, args[1:])
	case "plan":
		return runPlan(args[1:])
	case "preflight":
		return runPreflight(ctx, args[1:])
	case "run":
		return runBenchmark(ctx, args[1:])
	case "report":
		return runReport(args[1:])
	case "render":
		return runRender(args[1:])
	case "fleet":
		return runFleet(ctx, args[1:])
	case "-h", "--help", "help":
		usage()
		return nil
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `Usage:
  rarpar-bench toolchains validate|build|resolve [--config PATH] [--docker PATH] [--mirror-base URL] [--publish] [--s3-endpoint URL] [--bucket NAME] [--cache DIR]
  rarpar-bench corpus generate --out DIR [--config PATH] [--toolchains PATH] [--docker PATH]
  rarpar-bench corpus verify --root DIR
  rarpar-bench corpus push --root DIR --image REGISTRY/REPO:TAG [--token-file PATH]
  rarpar-bench corpus fetch --image REGISTRY/REPO:TAG --out DIR [--token-file PATH]
  rarpar-bench payload video --profile ffmpeg-video|ffmpeg-video-hevc --target-bytes BYTES --out PATH [--toolchains PATH] [--docker PATH]
  rarpar-bench testcorpus generate [--only NAME]... [--jobs N] [--toolchains PATH] [--docker PATH]
  rarpar-bench testcorpus list
  rarpar-bench plan create --corpus DIR --out FILE [--seed TEXT] [--lane LANE] [--family rar|par2] [--par2-placement MODE] [--warmups N] [--repeats N] [--case ID]...
  rarpar-bench preflight [--docker PATH] [--perf]
  rarpar-bench run --corpus DIR --plan FILE --candidate PATH --out DIR [--reference-rar PATH --reference-par2 PATH] [--source-manifest PATH --source-target TRIPLE] [--perf]
  rarpar-bench report --input FILE --out FILE
  rarpar-bench render --input FILE --out DIR
  rarpar-bench fleet plan|run|collect|teardown --config PATH

LANE is cpu, metal, or docker-cpu. PAR2 placement is canonical or smart; canonical
matches conventional expected-path verification for direct comparisons. Corpus data and run evidence are
intentionally external to source control; use target/bench by convention.

Toolchain archives resolve from the public tool mirror first (--mirror-base,
default $RARPAR_TOOL_MIRROR_BASE; empty means official URLs only) and fall back
to their official URLs only when the mirror does not hold them. Every archive is
verified against the BLAKE3 digest config/toolchains.json pins before Docker
sees it, and the mirror keys are derived from that digest. --publish mirrors
what the bucket does not hold yet; it needs --s3-endpoint, --bucket and
R2_CORPUS_ACCESS_KEY_ID/R2_CORPUS_SECRET_ACCESS_KEY, and is for the protected
publish workflow. resolve does the resolving (and publishing) alone, without
building any image, printing "<kind> <name> blake3:<digest> <origin>".
`)
}

func runToolchains(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("toolchains requires validate, build, or resolve")
	}
	flags := flag.NewFlagSet("toolchains "+args[0], flag.ContinueOnError)
	config := flags.String("config", defaultPath("config/toolchains.json"), "toolchain lock")
	docker := flags.String("docker", "docker", "Docker executable")
	mirrorBase := flags.String("mirror-base", os.Getenv("RARPAR_TOOL_MIRROR_BASE"), "public read base URL of the tool source mirror")
	publish := flags.Bool("publish", false, "sign and upload archives the mirror does not hold yet (publish workflow only)")
	endpoint := flags.String("s3-endpoint", "", "S3 endpoint for uploads, e.g. https://<account>.r2.cloudflarestorage.com")
	bucket := flags.String("bucket", "", "bucket holding the tool mirror")
	cache := flags.String("cache", "", "directory for resolved archives (default: a rarpar-bench directory under the system temp dir)")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected argument %q", flags.Arg(0))
	}
	lock, err := bench.LoadToolchains(*config)
	if err != nil {
		return err
	}
	switch args[0] {
	case "validate":
		fmt.Println("toolchain lock is valid")
		return nil
	case "build":
		mirror, err := toolMirror(*mirrorBase, *endpoint, *bucket, *cache, *publish)
		if err != nil {
			return err
		}
		return bench.BuildToolchains(ctx, *docker, harnessRoot(), lock, mirror)
	case "resolve":
		mirror, err := toolMirror(*mirrorBase, *endpoint, *bucket, *cache, *publish)
		if err != nil {
			return err
		}
		return bench.ResolveToolchainSources(ctx, lock, mirror, os.Stdout)
	default:
		return fmt.Errorf("unknown toolchains command %q", args[0])
	}
}

// toolMirror builds the source resolver from the command line and the
// environment. Publishing is fail-closed on configuration: every piece the
// protected workflow supplies has to be present before anything is signed or
// uploaded, and the credentials only ever come from the environment.
func toolMirror(base, endpoint, bucket, cache string, publish bool) (*bench.SourceMirror, error) {
	mirror := &bench.SourceMirror{BaseURL: strings.TrimSuffix(base, "/"), CacheDir: cache}
	if !publish {
		if base == "" {
			fmt.Fprintln(os.Stderr, "rarpar-bench: no tool mirror configured (--mirror-base/RARPAR_TOOL_MIRROR_BASE); resolving archives from their official URLs")
		}
		return mirror, nil
	}
	if base == "" {
		return nil, fmt.Errorf("--publish requires --mirror-base (or RARPAR_TOOL_MIRROR_BASE): the stored copy has to be read back publicly")
	}
	if endpoint == "" {
		return nil, fmt.Errorf("--publish requires --s3-endpoint")
	}
	if bucket == "" {
		return nil, fmt.Errorf("--publish requires --bucket")
	}
	accessKeyID := os.Getenv("R2_CORPUS_ACCESS_KEY_ID")
	secretAccessKey := os.Getenv("R2_CORPUS_SECRET_ACCESS_KEY")
	if accessKeyID == "" || secretAccessKey == "" {
		return nil, fmt.Errorf("--publish requires R2_CORPUS_ACCESS_KEY_ID and R2_CORPUS_SECRET_ACCESS_KEY in the environment")
	}
	mirror.Publish = &bench.MirrorPublisher{
		WriteBase:       strings.TrimSuffix(endpoint, "/") + "/" + bucket,
		AccessKeyID:     accessKeyID,
		SecretAccessKey: secretAccessKey,
		Repository:      os.Getenv("GITHUB_REPOSITORY"),
		Commit:          os.Getenv("GITHUB_SHA"),
		WorkflowRef:     os.Getenv("GITHUB_WORKFLOW_REF"),
		RunURL:          workflowRunURL(),
	}
	return mirror, nil
}

// workflowRunURL is the run that mirrored an archive, when GitHub Actions says
// so; locally there is no run and the provenance field stays empty.
func workflowRunURL() string {
	server, repository, run := os.Getenv("GITHUB_SERVER_URL"), os.Getenv("GITHUB_REPOSITORY"), os.Getenv("GITHUB_RUN_ID")
	if server == "" || repository == "" || run == "" {
		return ""
	}
	return strings.TrimSuffix(server, "/") + "/" + repository + "/actions/runs/" + run
}

func runCorpus(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("corpus requires generate, verify, push, or fetch")
	}
	flags := flag.NewFlagSet("corpus "+args[0], flag.ContinueOnError)
	root := flags.String("root", "", "corpus directory")
	out := flags.String("out", "", "new corpus directory")
	config := flags.String("config", defaultPath("config/corpus.json"), "corpus configuration")
	toolchains := flags.String("toolchains", defaultPath("config/toolchains.json"), "toolchain lock")
	docker := flags.String("docker", "docker", "Docker executable")
	image := flags.String("image", "", "OCI image ref: <registry>/<repo>:<tag>")
	tokenFile := flags.String("token-file", "", "file holding a registry basic-auth token (ECR authorizationToken)")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	switch args[0] {
	case "push", "fetch":
		return runCorpusImage(ctx, args[0], *root, *out, *image, *tokenFile)
	case "verify":
		if *root == "" {
			return fmt.Errorf("--root is required")
		}
		return bench.VerifyCorpus(workspacePath(*root))
	case "generate":
		if *out == "" {
			return fmt.Errorf("--out is required")
		}
		lock, err := bench.LoadToolchains(*toolchains)
		if err != nil {
			return err
		}
		config, err := bench.LoadCorpusConfig(*config)
		if err != nil {
			return err
		}
		return bench.GenerateCorpus(ctx, *docker, harnessRoot(), workspacePath(*out), lock, config)
	default:
		return fmt.Errorf("unknown corpus command %q", args[0])
	}
}

// runPayload exposes the corpus generator's real-content payload encoders on
// their own, so the test corpus's generator scripts can ask the benchmark's
// pinned encoder for their video inputs instead of carrying an ffmpeg command
// line of their own. `payload video` is deliberately narrow: one profile, one
// target size, one output path; the recipe, image digest and determinism
// controls stay inside the harness.
func runPayload(ctx context.Context, args []string, stdout io.Writer) error {
	if len(args) == 0 || args[0] != "video" {
		return fmt.Errorf("payload requires video")
	}
	flags := flag.NewFlagSet("payload video", flag.ContinueOnError)
	profile := flags.String("profile", "", "video payload profile: "+strings.Join(bench.VideoPayloadProfiles(), " or "))
	targetBytes := flags.Int64("target-bytes", 0, "size to aim the encode at, in bytes")
	out := flags.String("out", "", "output file (must not exist)")
	toolchains := flags.String("toolchains", defaultPath("config/toolchains.json"), "toolchain lock")
	docker := flags.String("docker", "docker", "Docker executable")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("payload video takes no positional arguments")
	}
	if *profile == "" || *targetBytes <= 0 || *out == "" {
		return fmt.Errorf("--profile, a positive --target-bytes, and --out are required")
	}
	lock, err := bench.LoadToolchains(*toolchains)
	if err != nil {
		return err
	}
	result, err := bench.EncodeVideoPayload(ctx, *docker, harnessRoot(), lock, *profile, *targetBytes, workspacePath(*out))
	if err != nil {
		return err
	}
	return writeJSONTo(stdout, result)
}

// runCorpusImage moves a corpus through an OCI registry: push publishes a
// local corpus root once, fetch pulls it onto a bench host (in-region and
// digest-verified when the registry is ECR). Both sides are pure registry
// HTTP — no docker daemon involved.
func runCorpusImage(ctx context.Context, verb, root, out, image, tokenFile string) error {
	if image == "" {
		return fmt.Errorf("--image is required")
	}
	ref, err := oci.ParseImageRef(image)
	if err != nil {
		return err
	}
	token := ""
	if tokenFile != "" {
		raw, err := os.ReadFile(tokenFile)
		if err != nil {
			return fmt.Errorf("read token file: %w", err)
		}
		token = strings.TrimSpace(string(raw))
	}
	client := &oci.Client{Ref: ref, Token: token}
	logf := func(format string, args ...any) { fmt.Printf(format+"\n", args...) }
	switch verb {
	case "push":
		if root == "" {
			return fmt.Errorf("--root is required")
		}
		// Refuse to publish anything that is not a corpus root; the manifest
		// check mirrors the fleet's corpus_source preflight.
		if _, err := os.Stat(filepath.Join(workspacePath(root), "corpus.json")); err != nil {
			return fmt.Errorf("--root is not a corpus root: %w", err)
		}
		_, err := client.PushDir(ctx, workspacePath(root), logf)
		return err
	case "fetch":
		if out == "" {
			return fmt.Errorf("--out is required")
		}
		return client.FetchDir(ctx, workspacePath(out), logf)
	default:
		return fmt.Errorf("unknown corpus image verb %q", verb)
	}
}

func runPlan(args []string) error {
	if len(args) == 0 || args[0] != "create" {
		return fmt.Errorf("plan requires create")
	}
	flags := flag.NewFlagSet("plan create", flag.ContinueOnError)
	corpus := flags.String("corpus", "", "corpus directory")
	out := flags.String("out", "", "plan JSON path")
	seed := flags.String("seed", "rarpar-benchmark-plan-v1", "ordering seed")
	lane := flags.String("lane", "cpu", "execution lane")
	family := flags.String("family", "", "optional workload family: rar or par2")
	par2Placement := flags.String("par2-placement", "canonical", "PAR2 placement policy: canonical or smart")
	warmups := flags.Int("warmups", 1, "warmup count")
	repeats := flags.Int("repeats", 5, "measurement count")
	var cases []string
	flags.Func("case", "restrict the plan to this case id; repeat for more", func(value string) error {
		if value == "" {
			return fmt.Errorf("--case cannot be empty")
		}
		cases = append(cases, value)
		return nil
	})
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if *corpus == "" || *out == "" {
		return fmt.Errorf("--corpus and --out are required")
	}
	plan, err := bench.CreatePlanWithCases(workspacePath(*corpus), *seed, *lane, *family, *par2Placement, *warmups, *repeats, cases)
	if err != nil {
		return err
	}
	return bench.WritePlan(workspacePath(*out), plan)
}

func runPreflight(ctx context.Context, args []string) error {
	flags := flag.NewFlagSet("preflight", flag.ContinueOnError)
	docker := flags.String("docker", "docker", "Docker executable")
	perf := flags.Bool("perf", false, "require the Linux perf stat collector")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *perf {
		if err := bench.ValidatePerf(ctx); err != nil {
			return err
		}
	}
	return bench.Preflight(ctx, *docker)
}

func runBenchmark(ctx context.Context, args []string) error {
	flags := flag.NewFlagSet("run", flag.ContinueOnError)
	corpus := flags.String("corpus", "", "corpus directory")
	planPath := flags.String("plan", "", "plan JSON path")
	candidate := flags.String("candidate", "", "rarpar binary")
	candidateLabel := flags.String("candidate-label", "rarpar", "candidate label")
	referenceRAR := flags.String("reference-rar", "", "reference RAR binary")
	referencePAR2 := flags.String("reference-par2", "", "reference PAR2 binary")
	referenceLabel := flags.String("reference-label", "reference", "reference label")
	out := flags.String("out", "", "fresh run directory")
	machine := flags.String("machine", "local", "sanitized machine label")
	docker := flags.String("docker", "docker", "Docker executable")
	sourceManifest := flags.String("source-manifest", "", "source Cargo manifest; enables source-build audit")
	sourceTarget := flags.String("source-target", "", "Cargo target for source-build audit")
	perf := flags.Bool("perf", false, "collect Linux perf stat counters for every subject")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *corpus == "" || *planPath == "" || *candidate == "" || *out == "" {
		return fmt.Errorf("--corpus, --plan, --candidate, and --out are required")
	}
	var index struct {
		Digest string `json:"digest"`
	}
	corpusPath := workspacePath(*corpus)
	if err := readCorpusIndex(corpusPath, &index); err != nil {
		return err
	}
	plan, err := bench.LoadPlan(workspacePath(*planPath), index.Digest)
	if err != nil {
		return err
	}
	_, err = bench.Run(ctx, bench.RunOptions{CorpusRoot: corpusPath, Plan: plan, CandidatePath: workspacePath(*candidate), CandidateLabel: *candidateLabel, ReferenceRAR: workspacePath(*referenceRAR), ReferencePAR2: workspacePath(*referencePAR2), ReferenceLabel: *referenceLabel, Output: workspacePath(*out), MachineLabel: *machine, Docker: *docker, SourceManifest: workspacePath(*sourceManifest), SourceTarget: *sourceTarget, Perf: *perf})
	return err
}

func runReport(args []string) error {
	flags := flag.NewFlagSet("report", flag.ContinueOnError)
	input := flags.String("input", "", "raw.json")
	out := flags.String("out", "", "report.json")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *input == "" || *out == "" {
		return fmt.Errorf("--input and --out are required")
	}
	report, err := bench.BuildReport(workspacePath(*input))
	if err != nil {
		return err
	}
	return bench.WriteReport(workspacePath(*out), report)
}

func runRender(args []string) error {
	flags := flag.NewFlagSet("render", flag.ContinueOnError)
	var inputs []string
	flags.Func("input", "report.json; repeat for another comparable lane", func(value string) error {
		if value == "" {
			return fmt.Errorf("--input cannot be empty")
		}
		inputs = append(inputs, value)
		return nil
	})
	out := flags.String("out", "", "fresh chart directory")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if len(inputs) == 0 || *out == "" {
		return fmt.Errorf("--input and --out are required")
	}
	reports := make([]bench.Report, len(inputs))
	for index, input := range inputs {
		if err := readReport(workspacePath(input), &reports[index]); err != nil {
			return err
		}
	}
	_, err := bench.RenderChartSet(reports, workspacePath(*out))
	return err
}

func harnessRoot() string                { return filepath.Clean(".") }
func defaultPath(relative string) string { return filepath.Clean(relative) }

func workspacePath(path string) string {
	if path == "" || filepath.IsAbs(path) {
		return path
	}
	if root := os.Getenv("RARPAR_BENCH_WORKSPACE_ROOT"); root != "" {
		return filepath.Join(root, path)
	}
	return path
}

func readCorpusIndex(root string, destination any) error {
	return bench.ReadJSONFile(filepath.Join(root, "corpus.json"), destination)
}

func readReport(path string, destination any) error {
	return bench.ReadJSONFile(path, destination)
}

func writeJSONTo(writer io.Writer, value any) error {
	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}

// runTestCorpus produces the repository's test corpus: every checked-in recipe
// run on the pinned toolchain images, and every upstream import fetched at its
// pinned commit. `cargo run -p xtask -- test-corpus generate` delegates here and
// then does the ledger-side work — the path-set check against
// test-corpus/sources.json, the digest refresh, and the benchmark pin report.
func runTestCorpus(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("testcorpus requires generate or list")
	}
	flags := flag.NewFlagSet("testcorpus "+args[0], flag.ContinueOnError)
	toolchains := flags.String("toolchains", defaultPath("config/toolchains.json"), "toolchain lock")
	docker := flags.String("docker", "docker", "Docker executable")
	jobs := flags.Int("jobs", 1, "recipes to run at once within a stage")
	var only stringList
	flags.Var(&only, "only", "run only this recipe (repeatable); skips the upstream imports")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected argument %q", flags.Arg(0))
	}
	switch args[0] {
	case "list":
		for _, unit := range testcorpus.Units() {
			fmt.Printf("%s\t%d\t%s\n", unit.Name, unit.Stage, unit.Source)
		}
		return nil
	case "generate":
		root := os.Getenv("RARPAR_BENCH_WORKSPACE_ROOT")
		if root == "" {
			// The harness lives two levels under the repository root.
			absolute, err := filepath.Abs(filepath.Join("..", ".."))
			if err != nil {
				return err
			}
			root = absolute
		}
		return testcorpus.Generate(ctx, testcorpus.Options{
			RepoRoot:   root,
			Toolchains: *toolchains,
			Docker:     *docker,
			Only:       only,
			Jobs:       *jobs,
			Log:        os.Stdout,
		})
	default:
		return fmt.Errorf("unknown testcorpus command %q", args[0])
	}
}

// stringList is a repeatable string flag.
type stringList []string

func (list *stringList) String() string { return strings.Join(*list, ",") }

func (list *stringList) Set(value string) error {
	*list = append(*list, value)
	return nil
}

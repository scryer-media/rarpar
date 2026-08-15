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
  rarpar-bench toolchains validate|build [--config PATH] [--docker PATH]
  rarpar-bench corpus generate --out DIR [--config PATH] [--toolchains PATH] [--docker PATH]
  rarpar-bench corpus verify --root DIR
  rarpar-bench corpus push --root DIR --image REGISTRY/REPO:TAG [--token-file PATH]
  rarpar-bench corpus fetch --image REGISTRY/REPO:TAG --out DIR [--token-file PATH]
  rarpar-bench plan create --corpus DIR --out FILE [--seed TEXT] [--lane LANE] [--family rar|par2] [--par2-placement MODE] [--warmups N] [--repeats N] [--case ID]...
  rarpar-bench preflight [--docker PATH] [--perf]
  rarpar-bench run --corpus DIR --plan FILE --candidate PATH --out DIR [--reference-rar PATH --reference-par2 PATH] [--source-manifest PATH --source-target TRIPLE] [--perf]
  rarpar-bench report --input FILE --out FILE
  rarpar-bench render --input FILE --out DIR
  rarpar-bench fleet plan|run|collect|teardown --config PATH

LANE is cpu, metal, or docker-cpu. PAR2 placement is canonical or smart; canonical
matches conventional expected-path verification for direct comparisons. Corpus data and run evidence are
intentionally external to source control; use target/bench by convention.
`)
}

func runToolchains(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("toolchains requires validate or build")
	}
	flags := flag.NewFlagSet("toolchains "+args[0], flag.ContinueOnError)
	config := flags.String("config", defaultPath("config/toolchains.json"), "toolchain lock")
	docker := flags.String("docker", "docker", "Docker executable")
	if err := flags.Parse(args[1:]); err != nil {
		return err
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
		return bench.BuildToolchains(ctx, *docker, harnessRoot(), lock)
	default:
		return fmt.Errorf("unknown toolchains command %q", args[0])
	}
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

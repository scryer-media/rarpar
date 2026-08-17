// Package testcorpus produces the repository's test corpus.
//
// Every fixture under crates/unrar-rs/tests/fixtures and
// crates/par2-rs/tests/fixtures is either written by a recipe in this package or
// fetched from a public upstream at a pinned commit. Nothing is carried forward:
// `rarpar-bench testcorpus generate` rewrites the whole tree, which is what a
// corpus revision is. See docs/test-corpus.md.
//
// The recipes are Go rather than shell so they run wherever the harness does,
// Windows included. The only external processes are the pinned Docker images
// from config/toolchains.json — the RARLAB writers and par2cmdline-turbo, which
// have no library form — plus python3 for generate_ppmd_perf.py, the one
// remaining Python recipe (it drives the same pinned RARLAB writer). Everything
// else (digests, HTTP, tar/gzip, file operations, deterministic payloads, the
// FFmpeg-encoded video members) is stdlib and in-process. RAR fixtures are only
// ever written by RARLAB's writer: no recipe assembles or edits RAR bytes.
package testcorpus

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/scryer-media/rarpar/bench/rarpar-bench/internal/bench"
)

// FixtureRoots are the two directories that hold corpus content, relative to
// the repository root.
var FixtureRoots = []string{
	"crates/unrar-rs/tests/fixtures",
	"crates/par2-rs/tests/fixtures",
}

// Options is one `testcorpus generate` invocation.
type Options struct {
	// RepoRoot is the repository root; every path below is relative to it.
	RepoRoot string
	// Toolchains is the path to the shared toolchain lock.
	Toolchains string
	// Docker is the Docker executable.
	Docker string
	// Only, when non-empty, restricts the run to those unit names.
	Only []string
	// ImportsOnly fetches every upstream import at its pinned commit and runs
	// no recipe at all. It is how the publish workflow's `imports` job produces
	// its share of the corpus without a toolchain image in sight.
	ImportsOnly bool
	// Jobs is how many units may run at once within a stage.
	Jobs int
	// Log receives progress; nil means os.Stderr.
	Log io.Writer
}

// The pinned tools a recipe drives, named independently of the versions the
// lock pins for them: the lock is what says which RARLAB release `rar4` is
// today, and a lock bump must not have to be repeated in this table.
const (
	ToolRAR4  = "rar4"
	ToolRAR5  = "rar5"
	ToolPAR2  = "par2"
	ToolVideo = "video"
)

// The writer ids the two RAR tools resolve to. Generation is pinned to these
// two releases; the lock's other writers exist for the benchmark corpus.
const (
	rar4WriterID = "rarlab-6.24"
	rar5WriterID = "rarlab-7.20"
)

// Unit is one generator: a named recipe, the source file that is its
// definition, the stage that orders it against the others, and everything it
// needs before it can run.
type Unit struct {
	// Name is the ledger's generator key and the value `--only` takes.
	Name string
	// Source is the repository-relative file this recipe lives in. The ledger
	// records the same path, and `cargo test -p xtask` requires it to exist.
	Source string
	// Stage 0 writes the shared inputs under originals/ that later stages read.
	Stage int
	// Tools are the pinned toolchains this recipe drives, in the symbolic form
	// above. TestUnitToolsResolveToTheLedgersToolchains holds them to the
	// ledger's generator table, and `toolchains build --only-images-for` builds
	// exactly the images they name — which is what lets one runner per unit
	// build three images instead of seven.
	Tools []string
	// Upstreams are repository-relative paths of `upstream` ledger entries this
	// recipe READS. They are fetched from their pinned commit before it runs,
	// so a recipe never depends on what the checkout happened to leave in the
	// tree: with GIT_LFS_SKIP_SMUDGE that is a pointer file, not the bytes.
	Upstreams []string
	// Run writes this unit's fixtures.
	Run func(context.Context, *env) error
}

// units is the whole table, in run order. TestUnitsMatchTheLedger holds it to
// test-corpus/sources.json, so a recipe cannot be added to one and forgotten in
// the other — which would leave the corpus quietly short a fixture.
func units() []Unit {
	return []Unit{
		// Stage 0 — the shared inputs under originals/.
		{Name: "inputs", Source: source("inputs.go"), Stage: 0,
			Tools: []string{ToolVideo}, Run: generateInputs},
		{Name: "edge_cases", Source: source("edge_cases.go"), Stage: 0,
			Tools: []string{ToolRAR4, ToolRAR5}, Run: generateEdgeCases},

		// Stage 1 — everything that reads those inputs, or reads nothing.
		{Name: "core_sets", Source: source("core_sets.go"), Stage: 1,
			Tools: []string{ToolRAR4, ToolRAR5}, Run: generateCoreSets},
		{Name: "encrypted", Source: source("encrypted.go"), Stage: 1,
			Tools: []string{ToolRAR4, ToolRAR5}, Run: generateEncrypted},
		{Name: "recovery_volumes", Source: source("recovery_volumes.go"), Stage: 1,
			Tools: []string{ToolRAR4, ToolRAR5}, Run: generateRecoveryVolumes},
		{Name: "large_sets", Source: source("large_sets.go"), Stage: 1,
			Tools: []string{ToolRAR4, ToolRAR5, ToolVideo}, Run: generateLargeSets},
		{Name: "stored_layout", Source: source("stored_layout.go"), Stage: 1,
			Tools: []string{ToolRAR5}, Run: generateStoredLayout},
		{Name: "generated_matrix", Source: source("generated_matrix.go"), Stage: 1,
			Tools: []string{ToolRAR4, ToolRAR5, ToolVideo}, Run: generateGeneratedMatrix},
		{Name: "ppmd_solid", Source: source("ppmd_solid.go"), Stage: 1,
			Tools: []string{ToolRAR4}, Run: generatePPMdSolid},
		{Name: "ppmd_perf", Source: ppmdPerfScript, Stage: 1,
			Tools: []string{ToolRAR4}, Run: generatePPMdPerf},
		{Name: "real_world", Source: source("par2_real_world.go"), Stage: 1,
			Tools: []string{ToolRAR4, ToolRAR5, ToolVideo, ToolPAR2}, Run: generateRealWorld},
		{Name: "heavy_damage", Source: source("par2_heavy_damage.go"), Stage: 1,
			Tools: []string{ToolRAR5, ToolVideo, ToolPAR2}, Run: generateHeavyDamage},
		// The two upstream data tarballs are this recipe's *input*: it replays
		// the upstream scripts against them. They are fetched from the pinned
		// commit before it runs rather than read out of the checkout.
		{Name: "par2_captures", Source: source("par2_captures.go"), Stage: 1,
			Tools: []string{ToolPAR2},
			Upstreams: []string{
				"crates/par2-rs/tests/fixtures/par2cmdline-turbo/bug190.tar.gz",
				"crates/par2-rs/tests/fixtures/par2cmdline-turbo/flatdata.tar.gz",
			},
			Run: generatePar2Captures},
	}
}

// ToolchainIDs resolves a unit's tools to the lock ids the ledger records for
// its generator, sorted and deduplicated.
func ToolchainIDs(lock bench.ToolchainLock, tools []string) ([]string, error) {
	seen := map[string]bool{}
	var ids []string
	add := func(id string) {
		if id != "" && !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	}
	for _, tool := range tools {
		switch tool {
		case ToolRAR4:
			add(rar4WriterID)
		case ToolRAR5:
			add(rar5WriterID)
		case ToolPAR2:
			add(lock.PAR2Generator.ID)
		case ToolVideo:
			add(lock.VideoEncoder.ID)
		default:
			return nil, fmt.Errorf("unknown generator tool %q", tool)
		}
	}
	sort.Strings(ids)
	return ids, nil
}

// ToolchainIDsForUnits resolves the toolchain lock ids the named generator
// units need. An unknown name is an error rather than an empty set: a typo
// must not quietly build nothing.
func ToolchainIDsForUnits(lock bench.ToolchainLock, names []string) ([]string, error) {
	selected, err := selectUnits(names)
	if err != nil {
		return nil, err
	}
	var tools []string
	for _, unit := range selected {
		tools = append(tools, unit.Tools...)
	}
	return ToolchainIDs(lock, tools)
}

// UnitDescription is one unit as `testcorpus list --json` reports it. The
// publish workflow derives its per-generator job matrix from this, so the job
// list and the orchestrator's unit table cannot drift apart.
type UnitDescription struct {
	Name       string   `json:"name"`
	Stage      int      `json:"stage"`
	Source     string   `json:"source"`
	Tools      []string `json:"tools"`
	Toolchains []string `json:"toolchains"`
	Images     []string `json:"images"`
	Upstreams  []string `json:"upstreams"`
}

// Listing is what `testcorpus list --json` prints.
type Listing struct {
	Units []UnitDescription `json:"units"`
}

// Describe resolves every unit against the toolchain lock.
func Describe(lock bench.ToolchainLock) (Listing, error) {
	listing := Listing{Units: []UnitDescription{}}
	for _, unit := range units() {
		ids, err := ToolchainIDs(lock, unit.Tools)
		if err != nil {
			return Listing{}, fmt.Errorf("%s: %w", unit.Name, err)
		}
		images, err := ImagesFor(lock, unit.Tools)
		if err != nil {
			return Listing{}, fmt.Errorf("%s: %w", unit.Name, err)
		}
		listing.Units = append(listing.Units, UnitDescription{
			Name:       unit.Name,
			Stage:      unit.Stage,
			Source:     unit.Source,
			Tools:      nonNil(unit.Tools),
			Toolchains: nonNil(ids),
			Images:     nonNil(images),
			Upstreams:  nonNil(unit.Upstreams),
		})
	}
	return listing, nil
}

// nonNil keeps the JSON an empty array rather than null, so a consumer can
// index it without a nil check.
func nonNil(values []string) []string {
	if values == nil {
		return []string{}
	}
	return values
}

// ImagesFor is the set of Docker images the named tools need built. The video
// encoder is absent on purpose: it is pulled by digest on first use, never
// built from a source archive.
func ImagesFor(lock bench.ToolchainLock, tools []string) ([]string, error) {
	seen := map[string]bool{}
	var images []string
	add := func(image string) {
		if image != "" && !seen[image] {
			seen[image] = true
			images = append(images, image)
		}
	}
	for _, tool := range tools {
		switch tool {
		case ToolRAR4, ToolRAR5:
			id := rar4WriterID
			if tool == ToolRAR5 {
				id = rar5WriterID
			}
			writer, ok := lock.Writer(id)
			if !ok {
				return nil, fmt.Errorf("toolchain lock has no %s writer", id)
			}
			add(writer.Image)
		case ToolPAR2:
			add(lock.PAR2Generator.Image)
		case ToolVideo:
		default:
			return nil, fmt.Errorf("unknown generator tool %q", tool)
		}
	}
	sort.Strings(images)
	return images, nil
}

const packageDir = "bench/rarpar-bench/internal/testcorpus"

func source(file string) string { return packageDir + "/" + file }

// Units is the run order, for callers that only need the table.
func Units() []Unit { return units() }

// env is what every recipe is handed: resolved absolute paths, the pinned
// toolchain lock, and the Docker settings.
type env struct {
	repoRoot  string
	unrar     string // absolute crates/unrar-rs/tests/fixtures
	par2      string // absolute crates/par2-rs/tests/fixtures
	lock      bench.ToolchainLock
	docker    string
	log       io.Writer
	rar4      bench.RARWriter
	rar5      bench.RARWriter
	par2Image string
	logMu     *sync.Mutex
}

func (e *env) unrarPath(parts ...string) string {
	return filepath.Join(append([]string{e.unrar}, parts...)...)
}

func (e *env) par2Path(parts ...string) string {
	return filepath.Join(append([]string{e.par2}, parts...)...)
}

func (e *env) logf(format string, args ...any) {
	e.logMu.Lock()
	defer e.logMu.Unlock()
	fmt.Fprintf(e.log, format+"\n", args...)
}

// Generate runs the selected units, in stage order.
func Generate(ctx context.Context, options Options) error {
	if options.RepoRoot == "" {
		return errors.New("repository root is required")
	}
	logWriter := options.Log
	if logWriter == nil {
		logWriter = os.Stderr
	}
	lock, err := bench.LoadToolchains(options.Toolchains)
	if err != nil {
		return err
	}
	rar4, ok := lock.Writer(rar4WriterID)
	if !ok {
		return fmt.Errorf("toolchain lock has no %s writer", rar4WriterID)
	}
	rar5, ok := lock.Writer(rar5WriterID)
	if !ok {
		return fmt.Errorf("toolchain lock has no %s writer", rar5WriterID)
	}
	docker := options.Docker
	if docker == "" {
		docker = "docker"
	}
	environment := &env{
		repoRoot:  options.RepoRoot,
		unrar:     filepath.Join(options.RepoRoot, filepath.FromSlash(FixtureRoots[0])),
		par2:      filepath.Join(options.RepoRoot, filepath.FromSlash(FixtureRoots[1])),
		lock:      lock,
		docker:    docker,
		log:       logWriter,
		rar4:      rar4,
		rar5:      rar5,
		par2Image: lock.PAR2Generator.Image,
		logMu:     &sync.Mutex{},
	}

	jobs := options.Jobs
	if jobs < 1 {
		jobs = 1
	}

	if options.ImportsOnly {
		if len(options.Only) > 0 {
			return errors.New("--imports-only runs the upstream imports alone and takes no --only")
		}
		imported, err := fetchUpstreams(ctx, environment, jobs)
		if err != nil {
			return err
		}
		environment.logf("testcorpus: %d upstream import(s) fetched at their pinned commits", imported)
		return nil
	}

	selected, err := selectUnits(options.Only)
	if err != nil {
		return err
	}
	if err := requireImages(ctx, environment, selected); err != nil {
		return err
	}

	// The upstream imports the selected recipes *read*, placed from their
	// pinned commits before any of them runs. A recipe must never depend on
	// what the checkout happened to leave in the tree: under
	// GIT_LFS_SKIP_SMUDGE that is a pointer file, not the bytes, and the
	// whole-corpus upstream fetch below happens far too late to help.
	fetched, err := fetchUnitUpstreams(ctx, environment, selected, jobs)
	if err != nil {
		return err
	}
	if fetched > 0 {
		environment.logf("testcorpus: %d upstream input(s) fetched for the selected recipes", fetched)
	}

	for _, stage := range stagesOf(selected) {
		if err := runStage(ctx, environment, stage, jobs); err != nil {
			return err
		}
	}
	if len(options.Only) > 0 {
		// A partial run is for iterating on one recipe; the upstream imports are
		// part of producing a whole corpus revision.
		return nil
	}
	imported, err := fetchUpstreams(ctx, environment, jobs)
	if err != nil {
		return err
	}
	environment.logf("testcorpus: %d upstream import(s) fetched at their pinned commits", imported)
	return nil
}

func selectUnits(only []string) ([]Unit, error) {
	all := units()
	if len(only) == 0 {
		return all, nil
	}
	var selected []Unit
	for _, name := range only {
		index := -1
		for i, unit := range all {
			if unit.Name == name {
				index = i
				break
			}
		}
		if index < 0 {
			names := make([]string, 0, len(all))
			for _, unit := range all {
				names = append(names, unit.Name)
			}
			return nil, fmt.Errorf("--only %q is not a generator; known: %s", name, strings.Join(names, ", "))
		}
		if !containsUnit(selected, name) {
			selected = append(selected, all[index])
		}
	}
	return selected, nil
}

func containsUnit(units []Unit, name string) bool {
	for _, unit := range units {
		if unit.Name == name {
			return true
		}
	}
	return false
}

func stagesOf(selected []Unit) [][]Unit {
	byStage := map[int][]Unit{}
	var numbers []int
	for _, unit := range selected {
		if _, seen := byStage[unit.Stage]; !seen {
			numbers = append(numbers, unit.Stage)
		}
		byStage[unit.Stage] = append(byStage[unit.Stage], unit)
	}
	sort.Ints(numbers)
	stages := make([][]Unit, 0, len(numbers))
	for _, number := range numbers {
		stages = append(stages, byStage[number])
	}
	return stages
}

func runStage(ctx context.Context, environment *env, stage []Unit, jobs int) error {
	if jobs > len(stage) {
		jobs = len(stage)
	}
	next := make(chan Unit)
	failures := make(chan string, len(stage))
	var workers sync.WaitGroup
	for range jobs {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for unit := range next {
				environment.logf("testcorpus: [stage %d] %s", unit.Stage, unit.Name)
				if err := unit.Run(ctx, environment); err != nil {
					failures <- fmt.Sprintf("%s: %v", unit.Name, err)
				}
			}
		}()
	}
	for _, unit := range stage {
		next <- unit
	}
	close(next)
	workers.Wait()
	close(failures)
	var collected []string
	for failure := range failures {
		collected = append(collected, failure)
	}
	if len(collected) > 0 {
		sort.Strings(collected)
		return fmt.Errorf("%d generator(s) failed\n  %s", len(collected), strings.Join(collected, "\n  "))
	}
	return nil
}

// requireImages checks that the pinned images the selected units need are
// present. Building them downloads and digest-verifies the RARLAB and
// par2cmdline-turbo sources, which is a separate deliberate step.
//
// What each unit needs comes from its own Tools, so a job that generates one
// unit is told about one unit's images and no more.
func requireImages(ctx context.Context, environment *env, selected []Unit) error {
	wanted := map[string]bool{}
	for _, unit := range selected {
		images, err := ImagesFor(environment.lock, unit.Tools)
		if err != nil {
			return fmt.Errorf("%s: %w", unit.Name, err)
		}
		for _, image := range images {
			wanted[image] = true
		}
	}
	var missing []string
	for image := range wanted {
		command := exec.CommandContext(ctx, environment.docker, "image", "inspect", image)
		command.Stdout = io.Discard
		command.Stderr = io.Discard
		if err := command.Run(); err != nil {
			missing = append(missing, image)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		var units []string
		for _, unit := range selected {
			units = append(units, "--only-images-for "+unit.Name)
		}
		return fmt.Errorf(
			"pinned toolchain image(s) %s are not present; build them first:\n  cargo run --locked -p xtask -- bench toolchains build %s",
			strings.Join(missing, ", "), strings.Join(units, " "))
	}
	return nil
}

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
	// Jobs is how many units may run at once within a stage.
	Jobs int
	// Log receives progress; nil means os.Stderr.
	Log io.Writer
}

// Unit is one generator: a named recipe, the source file that is its
// definition, and the stage that orders it against the others.
type Unit struct {
	// Name is the ledger's generator key and the value `--only` takes.
	Name string
	// Source is the repository-relative file this recipe lives in. The ledger
	// records the same path, and `cargo test -p xtask` requires it to exist.
	Source string
	// Stage 0 writes the shared inputs under originals/ that later stages read.
	Stage int
	// Run writes this unit's fixtures.
	Run func(context.Context, *env) error
}

// units is the whole table, in run order. TestUnitsMatchTheLedger holds it to
// test-corpus/sources.json, so a recipe cannot be added to one and forgotten in
// the other — which would leave the corpus quietly short a fixture.
func units() []Unit {
	return []Unit{
		// Stage 0 — the shared inputs under originals/.
		{Name: "inputs", Source: source("inputs.go"), Stage: 0, Run: generateInputs},
		{Name: "edge_cases", Source: source("edge_cases.go"), Stage: 0, Run: generateEdgeCases},

		// Stage 1 — everything that reads those inputs, or reads nothing.
		{Name: "core_sets", Source: source("core_sets.go"), Stage: 1, Run: generateCoreSets},
		{Name: "encrypted", Source: source("encrypted.go"), Stage: 1, Run: generateEncrypted},
		{Name: "recovery_volumes", Source: source("recovery_volumes.go"), Stage: 1, Run: generateRecoveryVolumes},
		{Name: "large_sets", Source: source("large_sets.go"), Stage: 1, Run: generateLargeSets},
		{Name: "stored_layout", Source: source("stored_layout.go"), Stage: 1, Run: generateStoredLayout},
		{Name: "generated_matrix", Source: source("generated_matrix.go"), Stage: 1, Run: generateGeneratedMatrix},
		{Name: "ppmd_solid", Source: source("ppmd_solid.go"), Stage: 1, Run: generatePPMdSolid},
		{Name: "ppmd_perf", Source: ppmdPerfScript, Stage: 1, Run: generatePPMdPerf},
		{Name: "real_world", Source: source("par2_real_world.go"), Stage: 1, Run: generateRealWorld},
		{Name: "heavy_damage", Source: source("par2_heavy_damage.go"), Stage: 1, Run: generateHeavyDamage},
		{Name: "par2_captures", Source: source("par2_captures.go"), Stage: 1, Run: generatePar2Captures},
	}
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
	rar4, ok := lock.Writer("rarlab-6.24")
	if !ok {
		return errors.New("toolchain lock has no rarlab-6.24 writer")
	}
	rar5, ok := lock.Writer("rarlab-7.20")
	if !ok {
		return errors.New("toolchain lock has no rarlab-7.20 writer")
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

	selected, err := selectUnits(options.Only)
	if err != nil {
		return err
	}
	if err := requireImages(ctx, environment, selected); err != nil {
		return err
	}

	jobs := options.Jobs
	if jobs < 1 {
		jobs = 1
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
func requireImages(ctx context.Context, environment *env, selected []Unit) error {
	wanted := map[string]bool{}
	for _, unit := range selected {
		switch unit.Name {
		case "heavy_damage", "real_world", "par2_captures":
			wanted[environment.par2Image] = true
			if unit.Name != "par2_captures" {
				wanted[environment.rar5.Image] = true
				wanted[environment.rar4.Image] = true
			}
		case "inputs":
			// Only the encoder, which is pulled by digest on first use.
		default:
			wanted[environment.rar5.Image] = true
			wanted[environment.rar4.Image] = true
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
		return fmt.Errorf(
			"pinned toolchain image(s) %s are not present; build them first:\n  cargo run --locked -p xtask -- bench toolchains build",
			strings.Join(missing, ", "))
	}
	return nil
}

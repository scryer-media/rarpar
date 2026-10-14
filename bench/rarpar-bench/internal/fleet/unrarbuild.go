package fleet

import (
	"context"
	"crypto/sha256"
	"debug/elf"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// The unrar-portable-onhost recipe. RARLAB publishes no Linux arm64 UnRAR, so
// on that one platform the run script builds the sha256-pinned source tarball
// the orchestrator shipped, natively on the host, with the audited portable
// recipe below. Every other platform runs RARLAB's own binary.
const (
	unrarSourceName = "unrar-source.tar.gz"
	unrarBinaryName = "unrar"
)

// unrarMakeArgs is the whole recipe: the stock makefile with its stock
// CXXFLAGS, and only CXX and a static link set. Nothing in the build adds a
// -march/-mcpu/-mtune: an oracle tuned for the host it runs on would not be
// the oracle anyone else can reproduce.
var unrarMakeArgs = []string{"CXX=g++", "LDFLAGS=-pthread -static"}

// unrarTargetCPUFlag is what the makefile audit refuses outside comments.
var unrarTargetCPUFlag = regexp.MustCompile(`-march|-mcpu|-mtune|native`)

// unrarScrubbedEnv are the variables through which the host environment could
// add a flag to the build. The stock makefile's compile line reads CPPFLAGS
// and its link line reads LIBS without defining either, so a stray value would
// reach the compiler or the linker; MAKEFLAGS and its kin can pass make -e,
// which lets the environment override the makefile's own CXXFLAGS; and
// MAKEFILES names extra makefiles that make reads before the stock one.
var unrarScrubbedEnv = []string{"CPPFLAGS", "CFLAGS", "CXXFLAGS", "LDFLAGS", "LIBS", "MAKEFLAGS", "MFLAGS", "GNUMAKEFLAGS", "MAKEFILES"}

// UnrarBuildOptions configures `rarpar-bench fleet build-unrar`.
type UnrarBuildOptions struct {
	Source       string // the source tarball the orchestrator shipped
	SourceSHA256 string // its pinned digest, re-verified on the host
	SourceURL    string // where the orchestrator fetched it; recorded only
	Out          string // build directory: src/, the installed binary, unrar-build.json
	BinarySHA256 string // optional pin on the built binary
	Log          io.Writer
}

// UnrarBuild records how the oracle was produced.
type UnrarBuild struct {
	Recipe          string   `json:"recipe"`
	SourceURL       string   `json:"source_url,omitempty"`
	SourceSHA256    string   `json:"source_sha256"`
	MakefileSHA256  string   `json:"makefile_sha256"`
	FlagAudit       string   `json:"flag_audit"`
	MakeArgs        []string `json:"make_args"`
	ScrubbedEnv     []string `json:"scrubbed_env"`
	MakeVersion     string   `json:"make_version"`
	CompilerVersion string   `json:"compiler_version"`
	Binary          string   `json:"binary"`
	BinarySHA256    string   `json:"binary_sha256"`
	BinaryPinned    bool     `json:"binary_pinned"`
	ELFMachine      string   `json:"elf_machine"`
	StaticLink      bool     `json:"static_link"`
	BuiltUTC        string   `json:"built_utc"`
	GOOS            string   `json:"goos"`
	GOARCH          string   `json:"goarch"`
}

// BuildUnrar builds the UnRAR oracle from the shipped source tarball with the
// audited portable recipe. It fails closed: a source digest that does not
// match its pin, a makefile that carries a target-cpu flag, a dynamically
// linked result, or a binary that does not match its pin stops the build
// with no oracle where the suites look for one, not even an earlier build's.
func BuildUnrar(ctx context.Context, options UnrarBuildOptions) (UnrarBuild, error) {
	switch {
	case options.Source == "":
		return UnrarBuild{}, errors.New("--source (the shipped UnRAR source tarball) is required")
	case !isHexSHA256(options.SourceSHA256):
		return UnrarBuild{}, errors.New("--sha256 (the source tarball's pinned sha256, 64 hex characters) is required")
	case options.Out == "":
		return UnrarBuild{}, errors.New("--out is required")
	case options.BinarySHA256 != "" && !isHexSHA256(options.BinarySHA256):
		return UnrarBuild{}, errors.New("--binary-sha256 must be 64 hex characters")
	}
	logf := func(format string, args ...any) {
		if options.Log != nil {
			fmt.Fprintf(options.Log, "fleet build-unrar: "+format+"\n", args...)
		}
	}
	out, err := filepath.Abs(options.Out)
	if err != nil {
		return UnrarBuild{}, err
	}
	binary := filepath.Join(out, unrarBinaryName)
	record := filepath.Join(out, "unrar-build.json")
	// What an earlier build left here goes first, so a refused build never
	// leaves the suites a binary that this build did not check.
	for _, stale := range []string{binary, record} {
		if err := os.Remove(stale); err != nil && !errors.Is(err, os.ErrNotExist) {
			return UnrarBuild{}, fmt.Errorf("removing the previous build's %s: %w", stale, err)
		}
	}
	sourceDigest, err := fileSHA256(options.Source)
	if err != nil {
		return UnrarBuild{}, err
	}
	if sourceDigest != options.SourceSHA256 {
		return UnrarBuild{}, fmt.Errorf("source tarball %s has sha256 %s, but the pin is %s", options.Source, sourceDigest, options.SourceSHA256)
	}
	logf("source %s sha256 %s matches the pin", options.Source, sourceDigest)
	srcRoot := filepath.Join(out, "src")
	if err := os.RemoveAll(srcRoot); err != nil {
		return UnrarBuild{}, err
	}
	if err := os.MkdirAll(srcRoot, 0o755); err != nil {
		return UnrarBuild{}, err
	}
	if err := extractTarTree(options.Source, srcRoot); err != nil {
		return UnrarBuild{}, fmt.Errorf("extract %s: %w", options.Source, err)
	}
	dir, err := unrarSourceDir(srcRoot)
	if err != nil {
		return UnrarBuild{}, err
	}
	makefile, err := os.ReadFile(filepath.Join(dir, "makefile"))
	if err != nil {
		return UnrarBuild{}, err
	}
	if err := auditUnrarMakefile(makefile); err != nil {
		return UnrarBuild{}, err
	}
	const audit = "no -march/-mcpu/-mtune/native in the stock makefile outside comment lines"
	logf("flag audit: %s", audit)
	makeVersion, err := firstOutputLine(ctx, "make", "--version")
	if err != nil {
		return UnrarBuild{}, fmt.Errorf("make is required to build the UnRAR oracle (make --version: %v)", err)
	}
	compilerVersion, err := firstOutputLine(ctx, "g++", "--version")
	if err != nil {
		return UnrarBuild{}, fmt.Errorf("g++ is required to build the UnRAR oracle (g++ --version: %v)", err)
	}
	environment := unrarBuildEnv(os.Environ())
	// The tree was just extracted, so this only matters if the tarball
	// shipped objects: none of those may be linked into the oracle.
	if err := runBuildStep(ctx, options.Log, dir, environment, "make", "clean"); err != nil {
		logf("make clean: %v (ignored; the tree is freshly extracted)", err)
	}
	quoted := make([]string, len(unrarMakeArgs))
	for index, arg := range unrarMakeArgs {
		quoted[index] = strconv.Quote(arg)
	}
	logf("make %s (stock makefile and CXXFLAGS; %s scrubbed from the environment)", strings.Join(quoted, " "), strings.Join(unrarScrubbedEnv, ", "))
	if err := runBuildStep(ctx, options.Log, dir, environment, "make", unrarMakeArgs...); err != nil {
		return UnrarBuild{}, fmt.Errorf("make: %w", err)
	}
	built := filepath.Join(dir, unrarBinaryName)
	machine, err := checkStaticELF(built)
	if err != nil {
		return UnrarBuild{}, err
	}
	digest, err := fileSHA256(built)
	if err != nil {
		return UnrarBuild{}, err
	}
	if options.BinarySHA256 != "" && digest != options.BinarySHA256 {
		return UnrarBuild{}, fmt.Errorf("built UnRAR sha256 %s does not match the pinned binary_sha256 %s; nothing was installed", digest, options.BinarySHA256)
	}
	// Installed last, so the suites never find a binary that failed a check.
	if err := copyFileMode(built, binary, 0o755); err != nil {
		return UnrarBuild{}, err
	}
	logf("installed %s (%s, statically linked, sha256 %s)", binary, machine, digest)
	makefileSum := sha256.Sum256(makefile)
	build := UnrarBuild{
		Recipe: RecipeUnrarHost, SourceURL: options.SourceURL, SourceSHA256: sourceDigest,
		MakefileSHA256: hex.EncodeToString(makefileSum[:]), FlagAudit: audit,
		MakeArgs: append([]string(nil), unrarMakeArgs...), ScrubbedEnv: append([]string(nil), unrarScrubbedEnv...),
		MakeVersion: makeVersion, CompilerVersion: compilerVersion,
		Binary: binary, BinarySHA256: digest, BinaryPinned: options.BinarySHA256 != "",
		ELFMachine: machine, StaticLink: true,
		BuiltUTC: time.Now().UTC().Format(time.RFC3339), GOOS: runtime.GOOS, GOARCH: runtime.GOARCH,
	}
	if err := writeJSONFile(record, build); err != nil {
		return UnrarBuild{}, err
	}
	return build, nil
}

// unrarSourceDir finds the makefile: RARLAB's tarball unpacks into unrar/.
func unrarSourceDir(root string) (string, error) {
	for _, dir := range []string{filepath.Join(root, "unrar"), root} {
		if info, err := os.Stat(filepath.Join(dir, "makefile")); err == nil && info.Mode().IsRegular() {
			return dir, nil
		}
	}
	return "", fmt.Errorf("no makefile under %s or %s; is this RARLAB's unrarsrc tarball?", filepath.Join(root, "unrar"), root)
}

// auditUnrarMakefile is the fail-closed half of the recipe: the stock makefile
// must carry no target-cpu flag of its own. Comment lines are skipped first:
// UnRAR 7.2.3's makefile explains in a comment that upstream removed
// -march=native, and matching that text would refuse a makefile that carries
// no flag at all. Anything else that matches, a trailing comment included, is
// refused.
func auditUnrarMakefile(makefile []byte) error {
	var hits []string
	for number, line := range strings.Split(string(makefile), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		if unrarTargetCPUFlag.MatchString(line) {
			hits = append(hits, fmt.Sprintf("line %d: %s", number+1, strings.TrimSpace(line)))
		}
	}
	if len(hits) > 0 {
		return fmt.Errorf("refusing to build: the stock makefile carries a target-cpu flag (%s); the portable recipe adds none and will not build with one", strings.Join(hits, "; "))
	}
	return nil
}

// unrarBuildEnv is the host environment minus unrarScrubbedEnv.
func unrarBuildEnv(environ []string) []string {
	kept := make([]string, 0, len(environ))
	for _, entry := range environ {
		name, _, _ := strings.Cut(entry, "=")
		if !contains(unrarScrubbedEnv, name) {
			kept = append(kept, entry)
		}
	}
	return kept
}

// checkStaticELF proves the build produced a statically linked ELF
// executable: no program interpreter and no shared-library dependency.
func checkStaticELF(path string) (string, error) {
	file, err := elf.Open(path)
	if err != nil {
		return "", fmt.Errorf("%s is not an ELF executable: %w", path, err)
	}
	defer file.Close()
	for _, program := range file.Progs {
		if program.Type == elf.PT_INTERP {
			return "", fmt.Errorf("%s is dynamically linked (it names a program interpreter); the recipe links statically, so nothing was installed", path)
		}
	}
	libraries, err := file.ImportedLibraries()
	if err != nil {
		return "", fmt.Errorf("%s: reading its dynamic section: %w", path, err)
	}
	if len(libraries) > 0 {
		return "", fmt.Errorf("%s needs shared libraries (%s); the recipe links statically, so nothing was installed", path, strings.Join(libraries, ", "))
	}
	return file.Machine.String(), nil
}

// runBuildStep runs one build step with its output in the build log, so the
// log carries every compiler and linker command line the stock makefile ran.
func runBuildStep(ctx context.Context, log io.Writer, dir string, environment []string, name string, args ...string) error {
	if log == nil {
		log = io.Discard
	}
	command := exec.CommandContext(ctx, name, args...)
	command.Dir = dir
	command.Env = environment
	command.Stdout = log
	command.Stderr = log
	return command.Run()
}

func firstOutputLine(ctx context.Context, name string, args ...string) (string, error) {
	output, err := exec.CommandContext(ctx, name, args...).Output()
	if err != nil {
		return "", err
	}
	line, _, _ := strings.Cut(strings.TrimSpace(string(output)), "\n")
	return strings.TrimSpace(line), nil
}

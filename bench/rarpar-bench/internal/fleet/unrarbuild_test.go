package fleet

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"debug/elf"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

// stockLikeMakefile has the shape of UnRAR 7.2.3's makefile: comments that
// mention target-cpu flags, and flag lines that carry none.
const stockLikeMakefile = "#\n# Makefile for UNIX - unrar\n\n" +
	"# A comment may mention -march=native, -mcpu or -mtune freely.\n" +
	"\t# So may an indented one: -march=armv8-a+crypto\n" +
	"CXX=c++\nCXXFLAGS=-O2 -std=c++11 -Wno-switch\nDEFINES=-D_FILE_OFFSET_BITS=64 -DRAR_SMP\nSTRIP=strip\nLDFLAGS=-pthread\n"

func TestAuditUnrarMakefile(t *testing.T) {
	if err := auditUnrarMakefile([]byte(stockLikeMakefile)); err != nil {
		t.Fatalf("a makefile that mentions the flags only in comments must pass: %v", err)
	}
	for _, line := range []string{
		"CXXFLAGS=-O2 -march=native",
		"CXXFLAGS=-O2 -mcpu=neoverse-v2",
		"CXXFLAGS+=-mtune=generic",
		"CXXFLAGS=-O2 # a trailing comment is not exempt: -march=native",
	} {
		err := auditUnrarMakefile([]byte(stockLikeMakefile + line + "\n"))
		if err == nil || !strings.Contains(err.Error(), "refusing to build") || !strings.Contains(err.Error(), line) {
			t.Fatalf("%q must be refused, naming the line; got %v", line, err)
		}
	}
}

func TestUnrarBuildEnvScrubsMakeFlags(t *testing.T) {
	kept := unrarBuildEnv([]string{"PATH=/usr/bin", "CPPFLAGS=-march=native", "CXXFLAGS=-mcpu=native", "CFLAGS=-O3",
		"LDFLAGS=-shared", "LIBS=-lfoo", "MAKEFLAGS=-e", "MFLAGS=-e", "GNUMAKEFLAGS=-e", "MAKEFILES=/tmp/extra.mk", "LANG=C.UTF-8",
		"CPPFLAGS_NOTE=kept"})
	want := []string{"PATH=/usr/bin", "LANG=C.UTF-8", "CPPFLAGS_NOTE=kept"}
	if strings.Join(kept, "\n") != strings.Join(want, "\n") {
		t.Fatalf("build environment = %q, want %q", kept, want)
	}
}

// testELF is a minimal ELF64 header and program table: enough for debug/elf,
// and nothing that could run.
func testELF(dynamic bool) []byte {
	var buffer bytes.Buffer
	put := func(value any) { _ = binary.Write(&buffer, binary.LittleEndian, value) }
	header := elf.Header64{
		Type: uint16(elf.ET_EXEC), Machine: uint16(elf.EM_AARCH64), Version: uint32(elf.EV_CURRENT),
		Entry: 0x400000, Phoff: 64, Ehsize: 64, Phentsize: 56, Phnum: 1, Shentsize: 64,
	}
	if dynamic {
		header.Phnum = 2
	}
	copy(header.Ident[:], []byte{0x7f, 'E', 'L', 'F', byte(elf.ELFCLASS64), byte(elf.ELFDATA2LSB), byte(elf.EV_CURRENT)})
	put(header)
	put(elf.Prog64{Type: uint32(elf.PT_LOAD), Flags: uint32(elf.PF_R | elf.PF_X), Vaddr: 0x400000, Paddr: 0x400000, Filesz: 0x80, Memsz: 0x80, Align: 0x10000})
	if dynamic {
		interpreter := "/lib/ld-linux-aarch64.so.1\x00"
		put(elf.Prog64{Type: uint32(elf.PT_INTERP), Flags: uint32(elf.PF_R), Off: 64 + 2*56, Filesz: uint64(len(interpreter)), Memsz: uint64(len(interpreter)), Align: 1})
		buffer.WriteString(interpreter)
	}
	return buffer.Bytes()
}

func TestCheckStaticELF(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, data []byte) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, data, 0o755); err != nil {
			t.Fatal(err)
		}
		return path
	}
	if machine, err := checkStaticELF(write("static", testELF(false))); err != nil || machine != "EM_AARCH64" {
		t.Fatalf("a static ELF must pass and name its machine: %q, %v", machine, err)
	}
	if _, err := checkStaticELF(write("dynamic", testELF(true))); err == nil || !strings.Contains(err.Error(), "dynamically linked") {
		t.Fatalf("an ELF with a program interpreter must be refused, got %v", err)
	}
	if _, err := checkStaticELF(write("script", []byte("#!/bin/sh\n"))); err == nil || !strings.Contains(err.Error(), "not an ELF executable") {
		t.Fatalf("a non-ELF result must be refused, got %v", err)
	}
}

// unrarTestTarball is a source tarball laid out like RARLAB's (everything
// under unrar/), whose "build" output is the given bytes.
func unrarTestTarball(t *testing.T, makefile string, output []byte) (string, string) {
	t.Helper()
	var buffer bytes.Buffer
	compressed := gzip.NewWriter(&buffer)
	archive := tar.NewWriter(compressed)
	if err := archive.WriteHeader(&tar.Header{Name: "unrar/", Mode: 0o755, Typeflag: tar.TypeDir}); err != nil {
		t.Fatal(err)
	}
	for _, file := range []struct {
		name string
		data []byte
	}{{"unrar/makefile", []byte(makefile)}, {"unrar/output.elf", output}} {
		if err := archive.WriteHeader(&tar.Header{Name: file.name, Mode: 0o644, Size: int64(len(file.data)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := archive.Write(file.data); err != nil {
			t.Fatal(err)
		}
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	if err := compressed.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "unrarsrc-test.tar.gz")
	if err := os.WriteFile(path, buffer.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(buffer.Bytes())
	return path, hex.EncodeToString(sum[:])
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// TestBuildUnrarRecipe runs the builder with a make and a g++ test double on
// PATH: everything around the compile (source pin, extraction, makefile audit,
// scrubbed environment, exact make arguments, static-link check, binary pin,
// install-last) is exercised without compiling UnRAR.
func TestBuildUnrarRecipe(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the make and g++ test doubles are POSIX shell scripts")
	}
	tools := t.TempDir()
	for name, script := range map[string]string{
		"make": "#!/bin/sh\ncase \"$1\" in\n--version) echo 'GNU Make 4.3 (test double)'; exit 0 ;;\nclean) exit 0 ;;\nesac\n" +
			"for arg in \"$@\"; do printf '%s\\n' \"$arg\"; done > make-args.txt\nenv > make-env.txt\ncp output.elf unrar\n",
		"g++": "#!/bin/sh\necho 'g++ (test double) 13.2.0'\n",
	} {
		if err := os.WriteFile(filepath.Join(tools, name), []byte(script), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", tools+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("CPPFLAGS", "-march=native")
	static := testELF(false)

	build := func(t *testing.T, makefile string, output []byte, pinSource func(string) string, binaryPin string) (UnrarBuild, string, error) {
		t.Helper()
		source, digest := unrarTestTarball(t, makefile, output)
		out := filepath.Join(t.TempDir(), "unrar-reference")
		built, err := BuildUnrar(context.Background(), UnrarBuildOptions{
			Source: source, SourceSHA256: pinSource(digest), SourceURL: "https://example.invalid/unrarsrc-test.tar.gz",
			Out: out, BinarySHA256: binaryPin,
		})
		return built, out, err
	}
	same := func(digest string) string { return digest }
	installed := func(out string) bool {
		_, err := os.Stat(filepath.Join(out, unrarBinaryName))
		return err == nil
	}

	t.Run("the audited recipe builds and records itself", func(t *testing.T) {
		built, out, err := build(t, stockLikeMakefile, static, same, "")
		if err != nil {
			t.Fatal(err)
		}
		if built.Recipe != RecipeUnrarHost || !built.StaticLink || built.ELFMachine != "EM_AARCH64" || built.BinaryPinned ||
			built.BinarySHA256 != sha256Hex(static) || built.MakefileSHA256 != sha256Hex([]byte(stockLikeMakefile)) ||
			built.MakeVersion != "GNU Make 4.3 (test double)" || built.CompilerVersion != "g++ (test double) 13.2.0" {
			t.Fatalf("unexpected build record: %+v", built)
		}
		if digest, err := fileSHA256(filepath.Join(out, unrarBinaryName)); err != nil || digest != sha256Hex(static) {
			t.Fatalf("installed oracle digest %s, %v", digest, err)
		}
		args, err := os.ReadFile(filepath.Join(out, "src", "unrar", "make-args.txt"))
		if err != nil || string(args) != "CXX=g++\nLDFLAGS=-pthread -static\n" {
			t.Fatalf("make ran with %q (%v); the recipe sets only CXX and a static link", args, err)
		}
		environment, err := os.ReadFile(filepath.Join(out, "src", "unrar", "make-env.txt"))
		if err != nil || !strings.Contains("\n"+string(environment), "\nPATH=") || strings.Contains("\n"+string(environment), "\nCPPFLAGS=") {
			t.Fatalf("make must see the host environment minus CPPFLAGS (%v):\n%s", err, environment)
		}
		var record UnrarBuild
		data, err := os.ReadFile(filepath.Join(out, "unrar-build.json"))
		if err != nil || json.Unmarshal(data, &record) != nil || record.BinarySHA256 != built.BinarySHA256 || record.SourceURL == "" {
			t.Fatalf("unrar-build.json = %s (%v)", data, err)
		}
	})
	t.Run("a matching binary pin is recorded", func(t *testing.T) {
		built, _, err := build(t, stockLikeMakefile, static, same, sha256Hex(static))
		if err != nil || !built.BinaryPinned {
			t.Fatalf("pinned build: %+v, %v", built, err)
		}
	})
	t.Run("a refused build leaves no earlier oracle behind", func(t *testing.T) {
		source, _ := unrarTestTarball(t, stockLikeMakefile, static)
		out := filepath.Join(t.TempDir(), "unrar-reference")
		if err := os.MkdirAll(out, 0o755); err != nil {
			t.Fatal(err)
		}
		earlier := []string{unrarBinaryName, "unrar-build.json"}
		for _, name := range earlier {
			if err := os.WriteFile(filepath.Join(out, name), []byte("left by an earlier run"), 0o755); err != nil {
				t.Fatal(err)
			}
		}
		_, err := BuildUnrar(context.Background(), UnrarBuildOptions{Source: source, SourceSHA256: strings.Repeat("0", 64), Out: out})
		if err == nil || !strings.Contains(err.Error(), "but the pin is") {
			t.Fatalf("want the source pin refusal, got %v", err)
		}
		for _, name := range earlier {
			if _, err := os.Stat(filepath.Join(out, name)); !os.IsNotExist(err) {
				t.Fatalf("%s from an earlier build survived a refused one (%v)", name, err)
			}
		}
	})
	refusals := []struct {
		name, makefile string
		output         []byte
		pinSource      func(string) string
		binaryPin      string
		want           string
	}{
		{"a source that misses its pin", stockLikeMakefile, static, func(string) string { return strings.Repeat("0", 64) }, "", "but the pin is"},
		{"a makefile with a target-cpu flag", stockLikeMakefile + "CXXFLAGS+=-march=native\n", static, same, "", "refusing to build"},
		{"a dynamically linked result", stockLikeMakefile, testELF(true), same, "", "dynamically linked"},
		{"a binary that misses its pin", stockLikeMakefile, static, same, strings.Repeat("ab", 32), "does not match the pinned binary_sha256"},
	}
	for _, refusal := range refusals {
		t.Run(refusal.name+" installs nothing", func(t *testing.T) {
			_, out, err := build(t, refusal.makefile, refusal.output, refusal.pinSource, refusal.binaryPin)
			if err == nil || !strings.Contains(err.Error(), refusal.want) {
				t.Fatalf("want an error containing %q, got %v", refusal.want, err)
			}
			if installed(out) {
				t.Fatal("a refused build must not leave an oracle where the suites look for it")
			}
		})
	}
}

func TestUnrarOnHostRecipeWiring(t *testing.T) {
	config, machine := exampleMachine(t, "ec2-graviton4")
	layout := LayoutFor(machine, "fleet-testrun")
	oracle := machine.Oracles["rar"]
	resolution := sourceBuildResolution(machine, "rar", oracle, layout)
	// Spelled out from the staging root rather than through hostJoin, so the
	// layout is checked independently of the helper that builds it.
	if !strings.HasPrefix(layout.Base, "/") {
		t.Fatalf("staging root %q is not an absolute POSIX path", layout.Base)
	}
	if resolution.RemotePath != layout.Base+"/unrar-reference/unrar" ||
		!strings.Contains(resolution.Origin, RecipeUnrarHost) || !strings.Contains(resolution.Origin, oracle.URL) || resolution.Note != oracle.Reason {
		t.Fatalf("unexpected resolution: %+v", resolution)
	}
	script := RunScript(machine, config.Fleet.Defaults, "fleet-testrun", layout, map[string]string{"rar": resolution.RemotePath, "par2": "/o/par2"})
	buildLine := `"$BENCH" fleet build-unrar --source "$BIN/unrar-source.tar.gz" --sha256 '` + oracle.SHA256 +
		`' --url 'https://www.rarlab.com/rar/unrarsrc-7.2.3.tar.gz' --out '` + layout.Base + `/unrar-reference' \`
	environment := strings.Index(script, `> "$R/environment.txt"`)
	built := strings.Index(script, buildLine)
	binaries := strings.Index(script, `> "$R/binaries.txt"`)
	if environment < 0 || built < environment || binaries < built {
		t.Fatalf("the UnRAR build must run after environment.txt and before binaries.txt hashes the oracle:\n%s", script)
	}
	if !strings.Contains(script, `  > "$R/unrar-build.json" 2> "$R/unrar-build.log" || fail unrar-build`) {
		t.Fatal("the build record and log must land in the results, and a failed build must fail the host")
	}
	if packages := bootstrapPackages(machine); !contains(packages, "build-essential") || contains(packages, "cmake") {
		t.Fatalf("the on-host UnRAR build needs build-essential and nothing else: %v", packages)
	}
	plan := BuildPlan(config, []Machine{machine}, "fleet-testrun")
	if !strings.Contains(strings.Join(plan.Machines[0].Steps, "\n"), "build the UnRAR oracle from the shipped, sha256-pinned source") {
		t.Fatalf("plan steps miss the on-host UnRAR build:\n%s", strings.Join(plan.Machines[0].Steps, "\n"))
	}
	if got := plan.Machines[0].Oracles["rar"].RemotePath; got != resolution.RemotePath {
		t.Fatalf("plan oracle path %s, run path %s", got, resolution.RemotePath)
	}
	// RARLAB publishes the x86-64 binary: those hosts never build UnRAR.
	_, x86 := exampleMachine(t, "linux-avx2")
	if strings.Contains(RunScript(x86, config.Fleet.Defaults, "fleet-testrun", LayoutFor(x86, "fleet-testrun"), map[string]string{"rar": "/o/unrar"}), "build-unrar") {
		t.Fatal("an x86-64 host must not build UnRAR")
	}
}

func TestResolveOraclesShipsTheUnrarSource(t *testing.T) {
	_, machine := exampleMachine(t, "ec2-graviton4")
	source, digest := unrarTestTarball(t, stockLikeMakefile, testELF(false))
	cache := t.TempDir()
	// A pre-populated cache entry: nothing is fetched.
	if err := copyFileMode(source, filepath.Join(cache, digest[:16]+"-unrarsrc-test.tar.gz"), 0o644); err != nil {
		t.Fatal(err)
	}
	oracle := machine.Oracles["rar"]
	oracle.URL, oracle.SHA256 = "https://example.invalid/unrarsrc-test.tar.gz", digest
	machine.Oracles = map[string]Oracle{"rar": oracle}
	bundle := t.TempDir()
	resolutions, err := ResolveOracles(context.Background(), machine, bundle, cache, LayoutFor(machine, "fleet-testrun"), false)
	if err != nil {
		t.Fatal(err)
	}
	if shipped, err := fileSHA256(filepath.Join(bundle, unrarSourceName)); err != nil || shipped != digest {
		t.Fatalf("shipped source digest %s (%v), want the pinned %s", shipped, err, digest)
	}
	if _, err := os.Stat(filepath.Join(bundle, unrarBinaryName)); !os.IsNotExist(err) {
		t.Fatal("no prebuilt UnRAR may ship: the host builds it")
	}
	if got, want := resolutions["rar"].RemotePath, LayoutFor(machine, "fleet-testrun").Base+"/unrar-reference/unrar"; got != want {
		t.Fatalf("oracle path = %s, want %s", got, want)
	}
}

// TestFleetRunsNoContainer guards the rule that nothing in the fleet runs in a
// container: no non-test source may exec docker or podman.
func TestFleetRunsNoContainer(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fileSet := token.NewFileSet()
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		parsed, err := parser.ParseFile(fileSet, name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(parsed, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			selector, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || (selector.Sel.Name != "Command" && selector.Sel.Name != "CommandContext") {
				return true
			}
			for _, arg := range call.Args {
				if literal, ok := arg.(*ast.BasicLit); ok && literal.Kind == token.STRING {
					if program, err := strconv.Unquote(literal.Value); err == nil && (program == "docker" || program == "podman") {
						t.Errorf("%s: execs %s", fileSet.Position(call.Pos()), program)
					}
				}
			}
			return true
		})
	}
}

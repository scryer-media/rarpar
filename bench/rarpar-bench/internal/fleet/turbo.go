package fleet

// The turbo suites: lzma-turbo and sevenz-turbo measured by their own Go
// harnesses (bench/lzma-turbo-bench, bench/sevenz-turbo-bench), which each
// write a report.json a fleet collects.
//
// Both candidates are built ON THE HOST, not on the orchestrator. The
// lzma harness refuses a binary whose embedded commit is not the checkout's
// clean HEAD, both harnesses record the checkout's rustc and Cargo.lock as
// provenance, and lzma's fixture generation and pinned 7-Zip fetch run
// through `cargo xtask` in that checkout. So the bundle ships each checkout
// as a `git bundle` of its HEAD commit (a few MiB) plus the cross-compiled Go
// harness, and the run script installs a pinned rustup, clones the bundle,
// builds the candidates with the checkout's own rust-toolchain.toml and runs
// the harness. A dirty checkout is refused at build time: a fleet measures a
// committed harness and candidate, never a working tree.
//
// Oracles are the harnesses' own: the official 7-Zip release asset and XZ
// Utils built from its pinned release tarball, both digest-checked here with
// the same pins the lzma-turbo repository carries in xtask/src/fetch.rs and
// .github/scripts/install-xz.sh. Neither is a [machines.oracles] role: the
// harness reports record their path, digest, banner and provenance.

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
)

// TurboPlan configures the lzma-turbo and sevenz-turbo suites on one machine.
type TurboPlan struct {
	// LzmaProfile and SevenzProfile are the harness run profiles: quick, full
	// or fleet (default fleet: the whole matrix at three repeats).
	LzmaProfile   string   `json:"lzma_profile"`
	SevenzProfile string   `json:"sevenz_profile"`
	LzmaOnly      []string `json:"lzma_only,omitempty"`
	SevenzOnly    []string `json:"sevenz_only,omitempty"`
	// Repeats override the profile's measured repeats; 0 keeps the profile's.
	LzmaRepeats   int `json:"lzma_repeats,omitempty"`
	SevenzRepeats int `json:"sevenz_repeats,omitempty"`
	// PinCPUs confines every sevenz-turbo process to an inclusive CPU range
	// (the lzma harness has no pin flag). Empty means unpinned.
	PinCPUs string `json:"pin_cpus,omitempty"`
	// TimeoutMinutes bounds one measured process in either harness (default
	// 60); a run past it is recorded as DNF.
	TimeoutMinutes int `json:"timeout_minutes"`
}

var turboProfiles = []string{"quick", "full", "fleet"}

// turboSuites maps each turbo suite to the source tree it needs and the
// name its git bundle, commit sidecar and harness binary carry.
var turboSuites = map[string]string{SuiteLzmaTurbo: "lzma-turbo", SuiteSevenzTurbo: "sevenz-turbo"}

// Pinned host toolchain and oracles. Every URL below resolves to a
// digest-checked file; nothing is fetched as "latest".
const (
	rustupVersion = "1.29.1"
	// rustup-init digests per host triple, from
	// static.rust-lang.org/rustup/archive/<version>/<triple>/rustup-init.sha256.
	rustupSHA256X86 = "dda7234360b7f578ca8b0ddcb80145646fa61a67c1720a5abc7051b35c9fcb71"
	rustupSHA256ARM = "15f6e4ce9f583b929c996c91562bad6d4454f3281de858b02cdfdef615fac433"

	// XZ Utils, the lzma suite's xz oracle, built static-only under the run
	// root (never installed system-wide). Same pin as lzma-turbo's
	// .github/scripts/install-xz.sh.
	xzVersion = "5.8.3"
	xzSHA256  = "3d3a1b973af218114f4f889bbaa2f4c037deaae0c8e815eec381c3d546b974a0"

	// The official 7-Zip console binary for Linux, both suites' 7zz oracle.
	// Same pins as lzma-turbo's xtask/src/fetch.rs; the standing rule is to
	// use the official release asset, never a distribution package and never
	// a build of our own.
	sevenZipVersion   = "26.03"
	sevenZipAssetX86  = "7z2603-linux-x64.tar.xz"
	sevenZipSHA256X86 = "dc99eff5008f1ab79bd7084c68513701547a808a89502bf4133683535ab3c695"
	sevenZipAssetARM  = "7z2603-linux-arm64.tar.xz"
	sevenZipSHA256ARM = "2389ba20e4d8295e8709c20b6263b69bd1ec4972fe38a04ad7a1badbf595b996"
)

func rustupURL(triple string) string {
	return fmt.Sprintf("https://static.rust-lang.org/rustup/archive/%s/%s/rustup-init", rustupVersion, triple)
}

func xzURL() string {
	return fmt.Sprintf("https://github.com/tukaani-project/xz/releases/download/v%s/xz-%s.tar.gz", xzVersion, xzVersion)
}

func sevenZipURL(asset string) string {
	return fmt.Sprintf("https://github.com/ip7z/7zip/releases/download/%s/%s", sevenZipVersion, asset)
}

// turboPackages are the distro packages the turbo suites need on a fresh
// cloud host: a C/C++ toolchain and cmake for the Rust builds (aws-lc-sys,
// xz), git for the bundle clone, curl for the pinned downloads, and xz-utils
// so GNU tar can unpack the 7-Zip .tar.xz asset (the measured xz oracle is
// the separate pinned build).
var turboPackages = []string{"build-essential", "cmake", "pkg-config", "git", "curl", "xz-utils", "perl"}

// hasTurbo reports whether the machine runs either turbo suite.
func (machine Machine) hasTurbo() bool {
	return machine.hasSuite(SuiteLzmaTurbo) || machine.hasSuite(SuiteSevenzTurbo)
}

// turboSourcePath returns the configured checkout for a turbo suite.
func turboSourcePath(settings Settings, suite string) string {
	switch suite {
	case SuiteLzmaTurbo:
		return settings.LzmaTurboPath
	case SuiteSevenzTurbo:
		return settings.SevenzTurboPath
	}
	return ""
}

// turboSources lists (suite, tree name, checkout path) for the machine's
// turbo suites, in a fixed order.
func turboSources(settings Settings, machine Machine) [][3]string {
	var sources [][3]string
	for _, suite := range []string{SuiteLzmaTurbo, SuiteSevenzTurbo} {
		if machine.hasSuite(suite) {
			sources = append(sources, [3]string{suite, turboSuites[suite], turboSourcePath(settings, suite)})
		}
	}
	return sources
}

// turboTreeID identifies the turbo checkouts that go into the run's bundles,
// for the content-addressed shared bundle name: the HEAD commit of each (a
// dirty tree is refused later, so the commit does identify the content).
// Only the suites a selected machine runs count: a configured checkout that
// no bundle carries neither names one nor has to be a checkout.
func turboTreeID(ctx context.Context, settings Settings, machines []Machine) (string, error) {
	var parts []string
	for _, suite := range []string{SuiteLzmaTurbo, SuiteSevenzTurbo} {
		path := turboSourcePath(settings, suite)
		runs := func(machine Machine) bool { return machine.hasSuite(suite) }
		if path == "" || !slices.ContainsFunc(machines, runs) {
			continue
		}
		output, err := exec.CommandContext(ctx, "git", "-C", path, "rev-parse", "HEAD").Output()
		if err != nil {
			return "", fmt.Errorf("%s: %s is not a git checkout: %w", turboSuites[suite], path, err)
		}
		parts = append(parts, turboSuites[suite]+"="+strings.TrimSpace(string(output)))
	}
	return strings.Join(parts, "|"), nil
}

// stageTurbo puts each turbo suite's inputs into the bundle: a `git bundle`
// of the checkout's HEAD, a `.commit` sidecar the host verifies the clone
// against, and the harness cross-compiled with CGO off (it is not a measured
// binary). It refuses a dirty checkout.
func (bundler *Bundler) stageTurbo(ctx context.Context, machine Machine, outDir string, info *BuildInfo) error {
	for _, source := range turboSources(bundler.Settings, machine) {
		suite, name, path := source[0], source[1], source[2]
		if path == "" {
			return fmt.Errorf("suite %s needs fleet.%s_path", suite, strings.ReplaceAll(name, "-", "_"))
		}
		tree := describeTree(ctx, path)
		if tree.GitSHA == "" {
			return fmt.Errorf("suite %s: %s is not a git checkout", suite, path)
		}
		if tree.DirtyFiles > 0 {
			return fmt.Errorf("suite %s: %s has %d uncommitted change(s); a fleet measures a committed candidate and harness, commit first",
				suite, path, tree.DirtyFiles)
		}
		info.Trees[name] = tree
		bundlePath := filepath.Join(outDir, name+".bundle")
		bundle := exec.CommandContext(ctx, "git", "-C", path, "bundle", "create", "--quiet", bundlePath, "HEAD")
		if output, err := bundle.CombinedOutput(); err != nil {
			return fmt.Errorf("suite %s: git bundle of %s: %w: %s", suite, path, err, strings.TrimSpace(string(output)))
		}
		if err := os.WriteFile(filepath.Join(outDir, name+".commit"), []byte(tree.GitSHA+"\n"), 0o644); err != nil {
			return err
		}
		harness := exec.CommandContext(ctx, "go", "build", "-trimpath", "-o", filepath.Join(outDir, name+"-bench"), ".")
		harness.Dir = filepath.Join(path, "bench", name+"-bench")
		harness.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS="+machine.Bundle.GoOS, "GOARCH="+machine.Bundle.GoArch)
		if machine.Bundle.GOAMD64 != "" {
			harness.Env = append(harness.Env, "GOAMD64="+machine.Bundle.GOAMD64)
		}
		harness.Stdout = os.Stderr
		harness.Stderr = os.Stderr
		if err := harness.Run(); err != nil {
			return fmt.Errorf("suite %s: building the Go harness in %s: %w", suite, harness.Dir, err)
		}
		bundler.log("bundle: %s at %s staged (git bundle + harness)", name, short(tree.GitSHA))
	}
	return nil
}

// turboCorpus maps a sevenz-turbo run profile to the fixture corpus it reads.
func turboCorpus(profile string) string {
	if profile == "quick" {
		return "quick"
	}
	return "full"
}

// turboSection generates the host-side turbo suites: pinned rustup, the
// checkouts cloned from their bundles and verified against the shipped
// commit, the pinned oracles, then each harness's toolchain, fixtures and run.
func turboSection(machine Machine, layout RemoteLayout) string {
	var script strings.Builder
	write := func(format string, args ...any) { fmt.Fprintf(&script, format+"\n", args...) }
	plan := machine.Turbo

	write("# ---- turbo suites: lzma-turbo / sevenz-turbo, host-built from the shipped git bundles")
	write("TURBO=\"$BASE/turbo\"")
	write("mkdir -p \"$TURBO\" \"$R/turbo\"")
	write("export HOME=\"${HOME:-$TURBO/home}\"; mkdir -p \"$HOME\"")
	write("export CARGO_HOME=\"$TURBO/cargo\" RUSTUP_HOME=\"$TURBO/rustup\" CARGO_NET_RETRY=5")
	write("export PATH=\"$CARGO_HOME/bin:$PATH\"")
	write("TURBO_OK=1")
	write("turbo_digest() { [ -n \"$HASH\" ] || { fail turbo-no-sha256; return 1; }; got=$($HASH \"$1\" | cut -d' ' -f1); [ \"$got\" = \"$2\" ] || { log \"$1: sha256 $got, pinned $2\"; fail \"$3\"; return 1; }; }")
	write("turbo_fetch() { curl -fsSL --retry 3 -o \"$2\" \"$1\" || { fail \"$3\"; return 1; }; }")
	write("case \"$(uname -m)\" in")
	write("  x86_64) RUSTUP_TRIPLE=x86_64-unknown-linux-gnu; RUSTUP_SHA=%s; SEVENZIP_URL=%s; SEVENZIP_SHA=%s ;;",
		rustupSHA256X86, shellQuote(sevenZipURL(sevenZipAssetX86)), sevenZipSHA256X86)
	write("  aarch64|arm64) RUSTUP_TRIPLE=aarch64-unknown-linux-gnu; RUSTUP_SHA=%s; SEVENZIP_URL=%s; SEVENZIP_SHA=%s ;;",
		rustupSHA256ARM, shellQuote(sevenZipURL(sevenZipAssetARM)), sevenZipSHA256ARM)
	write("  *) fail turbo-unsupported-arch; TURBO_OK=0 ;;")
	write("esac")
	write("")

	// rustup: pinned installer, no default toolchain; each checkout's
	// rust-toolchain.toml selects and installs its own on first cargo call.
	write("if [ \"$TURBO_OK\" = 1 ]; then")
	write("  log 'installing rustup %s (pinned) under the run root'", rustupVersion)
	write("  RUSTUP_URL=\"https://static.rust-lang.org/rustup/archive/%s/$RUSTUP_TRIPLE/rustup-init\"", rustupVersion)
	write("  if turbo_fetch \"$RUSTUP_URL\" \"$TURBO/rustup-init\" turbo-rustup-fetch && turbo_digest \"$TURBO/rustup-init\" \"$RUSTUP_SHA\" turbo-rustup-digest; then")
	write("    chmod +x \"$TURBO/rustup-init\"")
	write("    \"$TURBO/rustup-init\" -y -q --no-modify-path --profile minimal --default-toolchain none > \"$R/turbo/rustup.log\" 2>&1 || { fail turbo-rustup-install; TURBO_OK=0; }")
	write("  else")
	write("    TURBO_OK=0")
	write("  fi")
	write("fi")
	write("")

	// 7-Zip: official asset, digest-checked, unpacked with the distro xz.
	write("SEVENZZ=\"$TURBO/7zz/7zz\"")
	write("if [ \"$TURBO_OK\" = 1 ]; then")
	write("  log \"fetching the official 7-Zip %s console binary\"", sevenZipVersion)
	write("  mkdir -p \"$TURBO/7zz\"")
	write("  if turbo_fetch \"$SEVENZIP_URL\" \"$TURBO/7zz/asset.tar.xz\" turbo-7zz-fetch && turbo_digest \"$TURBO/7zz/asset.tar.xz\" \"$SEVENZIP_SHA\" turbo-7zz-digest; then")
	write("    tar -xJf \"$TURBO/7zz/asset.tar.xz\" -C \"$TURBO/7zz\" 7zz || { fail turbo-7zz-unpack; TURBO_OK=0; }")
	write("  else")
	write("    TURBO_OK=0")
	write("  fi")
	write("fi")
	write("")

	// Checkouts: clone each bundle and prove the clone is the shipped commit.
	write("turbo_checkout() {")
	write("  name=\"$1\"; want=$(cat \"$BIN/$name.commit\" 2>/dev/null)")
	write("  rm -rf \"$TURBO/$name\"")
	write("  git clone --quiet \"$BIN/$name.bundle\" \"$TURBO/$name\" > \"$R/turbo/$name-clone.log\" 2>&1 || { fail \"$name-clone\"; return 1; }")
	write("  got=$(git -C \"$TURBO/$name\" rev-parse HEAD)")
	write("  [ -n \"$want\" ] && [ \"$got\" = \"$want\" ] || { log \"$name: cloned $got, bundle says $want\"; fail \"$name-commit\"; return 1; }")
	write("  [ -z \"$(git -C \"$TURBO/$name\" status --porcelain --untracked-files=no)\" ] || { fail \"$name-dirty\"; return 1; }")
	write("  log \"$name at $got\"")
	write("}")
	write("")

	if machine.EC2 != nil {
		write("export SEVENZ_BENCH_INSTANCE_TYPE=%s", shellQuote(machine.EC2.InstanceType))
	}
	timeout := fmt.Sprintf("%dm", plan.TimeoutMinutes)

	if machine.hasSuite(SuiteLzmaTurbo) {
		write("# ---- suite: lzma-turbo (lzma-turbo-bench against xz %s, 7-Zip %s)", xzVersion, sevenZipVersion)
		write("LZ=\"$TURBO/lzma-turbo\"")
		write("if [ \"$TURBO_OK\" = 1 ] && turbo_checkout lzma-turbo; then")
		// xz oracle: static-only build under the run root.
		write("  log 'building the xz %s oracle (static, under the run root)'", xzVersion)
		write("  mkdir -p \"$TURBO/xz-src\"")
		write("  LZ_OK=1")
		write("  if turbo_fetch %s \"$TURBO/xz-src/xz.tar.gz\" lzma-turbo-xz-fetch && turbo_digest \"$TURBO/xz-src/xz.tar.gz\" %s lzma-turbo-xz-digest; then",
			shellQuote(xzURL()), xzSHA256)
		write("    ( cd \"$TURBO/xz-src\" && tar xzf xz.tar.gz && cd \"xz-%s\" \\", xzVersion)
		write("      && ./configure --prefix=\"$TURBO/xz\" --disable-shared --enable-static --disable-doc --quiet \\")
		write("      && make -j\"$(nproc 2>/dev/null || echo 2)\" --silent && make install --silent ) > \"$R/turbo/xz-build.log\" 2>&1 || { fail lzma-turbo-xz-build; LZ_OK=0; }")
		write("  else")
		write("    LZ_OK=0")
		write("  fi")
		write("  export LZMA_TURBO_XZ=\"$TURBO/xz/bin/xz\" LZMA_TURBO_7ZZ=\"$SEVENZZ\"")
		write("  if [ \"$LZ_OK\" = 1 ]; then")
		write("    log 'lzma-turbo: toolchain --build (installs the checkout pinned rust toolchain, builds lzma-bench)'")
		write("    \"$BIN/lzma-turbo-bench\" toolchain --repo \"$LZ\" --build > \"$R/turbo/lzma-toolchain.txt\" 2> \"$R/turbo/lzma-toolchain.log\" || { fail lzma-turbo-toolchain; LZ_OK=0; }")
		write("  fi")
		write("  if [ \"$LZ_OK\" = 1 ]; then")
		write("    log 'lzma-turbo: fixtures'")
		write("    \"$BIN/lzma-turbo-bench\" fixtures --repo \"$LZ\" > \"$R/turbo/lzma-fixtures.txt\" 2> \"$R/turbo/lzma-fixtures.log\" || { fail lzma-turbo-fixtures; LZ_OK=0; }")
		write("  fi")
		write("  if [ \"$LZ_OK\" = 1 ]; then")
		write("    gate lzma-turbo")
		args := []string{"--profile", plan.LzmaProfile, "--timeout", timeout}
		if plan.LzmaRepeats > 0 {
			args = append(args, "--repeats", fmt.Sprint(plan.LzmaRepeats))
		}
		if len(plan.LzmaOnly) > 0 {
			args = append(args, "--only", strings.Join(plan.LzmaOnly, ","))
		}
		write("    \"$BIN/lzma-turbo-bench\" run --repo \"$LZ\" --out \"$R/lzma-turbo\" --machine \"$MACHINE\" %s \\", quoteAll(args))
		write("      > \"$R/turbo/lzma-run.stdout.log\" 2> \"$R/turbo/lzma-run.stderr.log\"")
		write("    rc=$?")
		write("    log \"lzma-turbo rc=$rc\"")
		write("    [ \"$rc\" -eq 0 ] || fail lzma-turbo")
		write("  fi")
		write("else")
		write("  fail lzma-turbo-setup")
		write("fi")
		write("rm -rf \"$TURBO/xz-src\"")
		write("")
	}

	if machine.hasSuite(SuiteSevenzTurbo) {
		write("# ---- suite: sevenz-turbo (sevenz-turbo-bench against 7-Zip %s)", sevenZipVersion)
		write("SZ=\"$TURBO/sevenz-turbo\"")
		write("SZ_FIX=\"$TURBO/sevenz-fixtures\"")
		write("if [ \"$TURBO_OK\" = 1 ] && turbo_checkout sevenz-turbo; then")
		write("  SZ_OK=1")
		write("  log 'sevenz-turbo: building decode-bench (AWS-LC) and decode-bench (native-crypto)'")
		write("  ( cd \"$SZ\" && cargo build --locked --release -p decode-bench ) > \"$R/turbo/sevenz-build.log\" 2>&1 || { fail sevenz-turbo-build; SZ_OK=0; }")
		write("  ( cd \"$SZ\" && cargo build --locked --release -p decode-bench --features native-crypto --target-dir target-native ) > \"$R/turbo/sevenz-build-native.log\" 2>&1 || { fail sevenz-turbo-build-native; SZ_OK=0; }")
		write("  SZ_CAND=\"$SZ/target/release/decode-bench\"; SZ_NATIVE=\"$SZ/target-native/release/decode-bench\"")
		write("  export SEVENZ_BENCH_ORACLE_OFFICIAL=1 SEVENZ_BENCH_ORACLE_PROVENANCE=\"$SEVENZIP_URL\"")
		write("  if [ \"$SZ_OK\" = 1 ]; then")
		write("    log 'sevenz-turbo: fixtures (%s corpus, written by the oracle)'", turboCorpus(plan.SevenzProfile))
		write("    rm -rf \"$SZ_FIX\"")
		write("    \"$BIN/sevenz-turbo-bench\" fixtures --profile %s --dir \"$SZ_FIX\" --oracle \"$SEVENZZ\" > \"$R/turbo/sevenz-fixtures.txt\" 2> \"$R/turbo/sevenz-fixtures.log\" || { fail sevenz-turbo-fixtures; SZ_OK=0; }",
			turboCorpus(plan.SevenzProfile))
		write("  fi")
		write("  if [ \"$SZ_OK\" = 1 ]; then")
		write("    \"$BIN/sevenz-turbo-bench\" toolchain --repo \"$SZ\" --candidate \"$SZ_CAND\" --candidate-native \"$SZ_NATIVE\" --oracle \"$SEVENZZ\" > \"$R/turbo/sevenz-toolchain.json\" 2> \"$R/turbo/sevenz-toolchain.log\" || { fail sevenz-turbo-toolchain; SZ_OK=0; }")
		write("  fi")
		write("  if [ \"$SZ_OK\" = 1 ]; then")
		write("    gate sevenz-turbo")
		args := []string{"--profile", plan.SevenzProfile, "--timeout", timeout}
		if plan.SevenzRepeats > 0 {
			args = append(args, "--repeats", fmt.Sprint(plan.SevenzRepeats))
		}
		if len(plan.SevenzOnly) > 0 {
			args = append(args, "--only", strings.Join(plan.SevenzOnly, ","))
		}
		if plan.PinCPUs != "" {
			args = append(args, "--pin-cpus", plan.PinCPUs)
		}
		write("    \"$BIN/sevenz-turbo-bench\" run --dir \"$SZ_FIX\" --out \"$R/sevenz-turbo\" --machine \"$MACHINE\" \\")
		write("      --candidate \"$SZ_CAND\" --candidate-native \"$SZ_NATIVE\" --oracle \"$SEVENZZ\" %s \\", quoteAll(args))
		write("      > \"$R/turbo/sevenz-run.stdout.log\" 2> \"$R/turbo/sevenz-run.stderr.log\"")
		write("    rc=$?")
		write("    log \"sevenz-turbo rc=$rc\"")
		write("    [ \"$rc\" -eq 0 ] || fail sevenz-turbo")
		write("  fi")
		write("else")
		write("  fail sevenz-turbo-setup")
		write("fi")
		write("rm -rf \"$SZ_FIX\"")
		write("")
	}

	// Build trees are not evidence and can run to gigabytes; the results
	// directory keeps the reports and every log.
	write("rm -rf \"$TURBO/lzma-turbo/target\" \"$TURBO/sevenz-turbo/target\" \"$TURBO/sevenz-turbo/target-native\" 2>/dev/null")
	write("")
	return script.String()
}

func quoteAll(args []string) string {
	quoted := make([]string, len(args))
	for index, arg := range args {
		quoted[index] = shellQuote(arg)
	}
	return strings.Join(quoted, " ")
}

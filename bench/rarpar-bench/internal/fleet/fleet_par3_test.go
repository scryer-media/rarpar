package fleet

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func exampleMachine(t *testing.T, name string) (Config, Machine) {
	t.Helper()
	config := loadExample(t)
	for _, machine := range config.Machines {
		if machine.Name == name {
			return config, machine
		}
	}
	t.Fatalf("example config has no machine %q", name)
	return config, Machine{}
}

func TestPAR3SuiteDecodes(t *testing.T) {
	_, machine := exampleMachine(t, "linux-avx2")
	if !machine.hasSuite(SuiteMacroPAR3) || !machine.needsCandidate() {
		t.Fatal("linux-avx2 runs macro-par3 and so needs the candidate CLI")
	}
	plan := machine.PAR3
	if plan.Profile != "full" || len(plan.Workers) != 2 || plan.Workers[0] != 1 || plan.Workers[1] != 8 ||
		plan.PinCPUs != "0-7" || plan.Work != "/home/bench/p3" || plan.TimeoutMinutes != 20 {
		t.Fatalf("unexpected par3 plan: %+v", plan)
	}
	if oracle := machine.Oracles["par3"]; oracle.Recipe != RecipePAR3CmdlineHost {
		t.Fatalf("par3 oracle recipe = %q", oracle.Recipe)
	}
	// macro-par3 alone needs no corpus.
	_, ssm := exampleMachine(t, "ec2-zen4-ssm")
	if ssm.needsCorpus() || !ssm.needsCandidate() {
		t.Fatal("a macro-par3-only machine needs the candidate but no corpus")
	}
}

func TestPAR3ConfigValidation(t *testing.T) {
	cases := []struct {
		name, old, new, want string
	}{
		{"unknown profile", `profile = "full"                         # full | smoke | fleet`, `profile = "huge"`, "par3.profile"},
		{"unknown set", `# sets = ["a-gf16", "c-gf16"]            # default: every set in the profile`, `sets = ["z-gf99"]`, "par3.sets"},
		{"unknown op", `# ops = ["create", "verify", "repair"]   # default; verify-damaged is opt-in`, `ops = ["explode"]`, "unknown op"},
		{"duplicate op", `# ops = ["create", "verify", "repair"]   # default; verify-damaged is opt-in`, `ops = ["create", "create"]`, `op "create" is listed more than once`},
		{"zero workers", `workers = [1, 8]                         # rarpar rows; the reference is single-threaded`, `workers = [0]`, "par3.workers must be positive"},
		{"bad kernel variant", `# kernel_variants = ["name:VAR=value"]`, `kernel_variants = ["novar"]`, "kernel_variants"},
		{"durability is gone", `# kernel_variants = ["name:VAR=value"]`, `durability = ["durable"]`,
			"par3.durability is no longer accepted: the PAR3 bench runs buffered rarpar rows only"},
		{"duplicate worker count", `workers = [1, 8]                         # rarpar rows; the reference is single-threaded`, `workers = [8, 8]`, "appears twice"},
		{"pin list", `pin_cpus = "0-7"`, `pin_cpus = "0,2"`, "par3.pin_cpus"},
		{"unknown versus profile", `versus = "versus"`, `versus = "versus-huge"`, "par3.versus"},
		{"missing par3 oracle", "[machines.oracles.par3]\npolicy = \"source-build\"\nreason = \"par3cmdline publishes no release and no Linux binary; the tree ships only windows/par3.exe\"\nrecipe = \"par3cmdline-onhost\"\nversion",
			"[machines.oracles.par3x]\npolicy = \"source-build\"\nreason = \"x\"\nrecipe = \"par3cmdline-onhost\"\nversion", "needs [machines.oracles.par3]"},
		{"onhost recipe takes no url", `recipe = "par3cmdline-onhost"
version = "par3cmdline 0.0.1 (2971702e)"`, `recipe = "par3cmdline-onhost"
url = "https://example.invalid/x.tar.gz"
sha256 = "0000000000000000000000000000000000000000000000000000000000000000"`, "drop url and sha256"},
		{"unrar recipe cannot build par3", `recipe = "par3cmdline-onhost"
version = "par3cmdline 0.0.1 (2971702e)"`, `recipe = "unrar-portable-onhost"
url = "https://example.invalid/x.tar.gz"
sha256 = "0000000000000000000000000000000000000000000000000000000000000000"`, `recipe "unrar-portable-onhost" builds the rar oracle, not par3`},
		{"ssm needs a bucket", `ssm_bucket = "example-bench-transfer-bucket"`, `ssm_bucket = ""`, "needs fleet.aws.ssm_bucket"},
		{"ssm needs an instance profile", `instance_profile = "example-bench-instance-profile"`, `instance_profile = ""`, "needs ec2.instance_profile"},
		{"unknown access", `access = "ssm"                           # ssh (default) | ssm`, `access = "telnet"`, "ec2.access must be"},
		{"spot needs ssm", `deadman_minutes = 180
max_hours = 2.0`, `deadman_minutes = 180
spot = true
max_hours = 2.0`, "ec2.spot is only supported"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := DecodeConfig("fleet.toml", mutate(t, testCase.old, testCase.new))
			if err == nil || !strings.Contains(err.Error(), testCase.want) {
				t.Fatalf("want an error containing %q, got %v", testCase.want, err)
			}
		})
	}
}

func TestPAR3RunScriptSection(t *testing.T) {
	config, machine := exampleMachine(t, "linux-avx2")
	layout := LayoutFor(machine, "fleet-testrun")
	resolution := sourceBuildResolution(machine, "par3", machine.Oracles["par3"], layout)
	if resolution.RemotePath != "/home/bench/fleet-stage/fleet-testrun/par3-reference/build/par3cmd/par3" {
		t.Fatalf("on-host reference path = %s", resolution.RemotePath)
	}
	script := RunScript(machine, config.Fleet.Defaults, "fleet-testrun", layout,
		map[string]string{"rar": "/o/unrar", "par2": "/o/par2", "par3": resolution.RemotePath})
	for _, expected := range []string{
		"# ---- suite: macro-par3",
		`par3 build-reference --out '/home/bench/fleet-stage/fleet-testrun/par3-reference' --toolchains "$BIN/toolchains.json"`,
		`par3 run --reference "$P3_REFERENCE" --candidate "$CANDIDATE" --work "$P3_WORK"`,
		"P3_WORK='/home/bench/p3'",
		"'--profile' 'full' '--workers' '1,8' '--warmups' '1' '--repeats' '5' '--timeout' '20m' '--pin-cpus' '0-7'",
		"gate macro-par3",
		"fail par3-reference-missing",
		"gate macro-par3-versus",
		`set -- par3 versus --candidate "$CANDIDATE" --work "$P3_WORK/vs" --out "$R/par3-versus" --machine "$MACHINE" '--profile' 'versus' '--warmups' '1' '--repeats' '5' '--timeout' '20m' '--pin-cpus' '0-7'`,
		`[ -n "$ORACLE_PAR2" ] && set -- "$@" --par2 "$ORACLE_PAR2"`,
		"fail macro-par3-versus",
	} {
		if !strings.Contains(script, expected) {
			t.Fatalf("run script is missing %q", expected)
		}
	}
	if _, err := exec.LookPath("sh"); err == nil {
		path := filepath.Join(t.TempDir(), "run.sh")
		if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
			t.Fatal(err)
		}
		if output, err := exec.Command("sh", "-n", path).CombinedOutput(); err != nil {
			t.Fatalf("generated script does not parse: %v\n%s", err, output)
		}
	}
}

func TestPAR3WindowsUsesTheOfficialBinaryAndHostPaths(t *testing.T) {
	config, machine := exampleMachine(t, "win-dgpu")
	layout := HostLayout(machine, "fleet-testrun")
	if layout.Bin != `C:\bench\fleet-stage\fleet-testrun\bin` {
		t.Fatalf("Windows layout bin = %s", layout.Bin)
	}
	oracle := machine.Oracles["par3"]
	if oracle.Policy != OracleOfficialBinary || oracleBinaryName(machine, "par3", oracle) != "par3.exe" {
		t.Fatalf("Windows par3 oracle must be the official par3.exe: %+v", oracle)
	}
	plan := BuildPlan(config, []Machine{machine}, "fleet-testrun")
	if got := plan.Machines[0].Oracles["par3"].RemotePath; got != `C:\bench\fleet-stage\fleet-testrun\bin\par3.exe` {
		t.Fatalf("Windows oracle path = %s", got)
	}
	machine.PAR3.Versus = "versus"
	script := WindowsRunScript(machine, config.Fleet.Defaults, "fleet-testrun", layout, map[string]string{"par3": `C:\x\par3.exe`})
	for _, expected := range []string{"$OraclePar3 = 'C:\\x\\par3.exe'", "Gate 'macro-par3'", "'par3','run','--reference',$OraclePar3", "$p3Work = 'C:\\p3'",
		"Gate 'macro-par3-versus'", "'par3','versus','--candidate',$Candidate", "if ($OraclePar2) { $vsArgs += @('--par2', $OraclePar2) }", "Check 'macro-par3-versus'"} {
		if !strings.Contains(script, expected) {
			t.Fatalf("Windows run script is missing %q", expected)
		}
	}
	if hostJoin(machine, `C:\a\`, "b/c", "d.exe") != `C:\a\b\c\d.exe` {
		t.Fatal("hostJoin must use backslashes on Windows")
	}
}

func TestPAR3PlanWarnsAboutALongWorkPathButRuns(t *testing.T) {
	config, machine := exampleMachine(t, "linux-avx2")
	layout := LayoutFor(machine, "fleet-testrun")
	view, problem := par3View(machine, layout)
	if problem != "" || len(view.Warnings) != 0 {
		t.Fatalf("the example work path must pass cleanly: %s %v", problem, view.Warnings)
	}
	// One buffered rarpar row per worker count for every op, plus at repair
	// one rarpar-wN-backup row per worker count.
	if len(view.Configs) == 0 || strings.Join(view.Variants, ",") != "reference,rarpar-w1,rarpar-w1-backup,rarpar-w8,rarpar-w8-backup" {
		t.Fatalf("unexpected view: %+v", view)
	}
	if strings.Join(view.Rows["create"], ",") != "reference,rarpar-w1,rarpar-w8" ||
		strings.Join(view.Rows["verify"], ",") != "reference,rarpar-w1,rarpar-w8" ||
		strings.Join(view.Rows["repair"], ",") != "reference,rarpar-w1,rarpar-w1-backup,rarpar-w8,rarpar-w8-backup" {
		t.Fatalf("unexpected rows: %v", view.Rows)
	}
	machine.PAR3.Work = "/home/bench/" + strings.Repeat("deep/", 20) + "p3"
	view, problem = par3View(machine, layout)
	if problem != "" {
		t.Fatalf("a long work path must not block the run: %q", problem)
	}
	if len(view.Warnings) == 0 || !strings.Contains(view.Warnings[0], "characters)") || !strings.Contains(view.Warnings[0], "DNF") {
		t.Fatalf("a long work path must warn with the character count: %v", view.Warnings)
	}
	plan := BuildPlan(config, []Machine{machine}, "fleet-testrun")
	warnings := strings.Join(plan.Warnings, "\n")
	if !strings.Contains(warnings, "par3 work path") || strings.Contains(warnings, "would refuse") {
		t.Fatalf("plan warnings: %s", warnings)
	}
	var step string
	for _, line := range plan.Machines[0].Steps {
		if strings.HasPrefix(line, "on host: macro-par3,") {
			step = line
		}
	}
	for _, want := range []string{
		"buffered rarpar rows only (never --fsync)",
		"rarpar-wN for every op, repairing in place with no backup",
		"rarpar-wN-backup, which keeps a numbered .1 as the reference does (like for like on bytes written)",
	} {
		if !strings.Contains(step, want) {
			t.Fatalf("macro-par3 plan step lacks %q: %q", want, step)
		}
	}
	if strings.Contains(step, "durable") {
		t.Fatalf("macro-par3 plan step = %q", step)
	}
}

func TestSSMMachinePlanAndLaunchArgs(t *testing.T) {
	config, machine := exampleMachine(t, "ec2-zen4-ssm")
	if !machine.usesSSM() || machine.EC2.InstanceProfile != "example-bench-instance-profile" || !machine.EC2.Spot {
		t.Fatalf("SSM machine did not decode: %+v", machine.EC2)
	}
	args := strings.Join(SSMLaunchArgs(*machine.EC2), " ")
	if !strings.Contains(args, "--iam-instance-profile Name=example-bench-instance-profile") || !strings.Contains(args, `"MarketType":"spot"`) {
		t.Fatalf("launch args = %s", args)
	}
	plan := BuildPlan(config, []Machine{machine}, "fleet-testrun")
	item := plan.Machines[0]
	if item.Endpoint != "ssm:<launched c7a.2xlarge in us-east-1>" || item.Cloud.Access != AccessSSM {
		t.Fatalf("unexpected SSM plan: %+v", item)
	}
	steps := strings.Join(item.Steps, "\n")
	for _, expected := range []string{"instance profile example-bench-instance-profile, no keypair and no inbound rule", "SSM agent to report Online", "S3 (tar object", "par3cmdline reference"} {
		if !strings.Contains(steps, expected) {
			t.Fatalf("SSM plan steps miss %q:\n%s", expected, steps)
		}
	}
	userData := UserDataSSM(240, bootstrapPackages(machine))
	if strings.Contains(userData, "snapd") && strings.Contains(userData, "disable --now snapd") {
		t.Fatal("SSM user-data must not disable snapd: the SSM agent is a snap")
	}
	for _, expected := range []string{"shutdown -h +240", "snap install aws-cli --classic", "apt-get install -y -q build-essential cmake", "BENCH_USERDATA_DONE"} {
		if !strings.Contains(userData, expected) {
			t.Fatalf("SSM user-data is missing %q", expected)
		}
	}
	if strings.Contains(UserData(180, 22022), "apt-get install") {
		t.Fatal("SSH user-data installs nothing unless a suite needs it")
	}
	if prefix := ssmPrefix("rarpar-fleet", "fleet-1", "m"); prefix != "rarpar-fleet/fleet-1/m" {
		t.Fatalf("ssm prefix = %s", prefix)
	}
}

func TestBundleRequiresExeNamesOnWindows(t *testing.T) {
	_, machine := exampleMachine(t, "win-dgpu")
	if !strings.Contains(buildKey(machine), "par3") {
		t.Fatalf("buildKey must carry the par3 feature: %s", buildKey(machine))
	}
	prebuilt := t.TempDir()
	for _, name := range []string{"rarpar-bench.exe", "rarpar.exe", "crc_probe.exe"} {
		if err := os.WriteFile(filepath.Join(prebuilt, name), []byte("MZ"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	machine.Bundle.Source = BundlePrebuilt
	machine.Bundle.Tag = ""
	machine.Bundle.Path = prebuilt
	rarpar, err := filepath.Abs("../../../..")
	if err != nil {
		t.Fatal(err)
	}
	bundler := &Bundler{Settings: Settings{RarparPath: rarpar}, RunDir: t.TempDir()}
	shared, info, err := bundler.SharedBuild(t.Context(), "shared-win", machine, []string{machine.Name})
	if err != nil {
		t.Fatalf("a Windows prebuilt bundle with .exe names must satisfy the required-binaries check: %v", err)
	}
	if info.Binaries["rarpar.exe"] == "" {
		t.Fatalf("binaries not recorded: %v", info.Binaries)
	}
	dir, _, err := bundler.Assemble(machine, shared, info)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "toolchains.json")); err != nil {
		t.Fatalf("a macro-par3 bundle must ship toolchains.json: %v", err)
	}
	if err := os.Remove(filepath.Join(prebuilt, "rarpar.exe")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := bundler.SharedBuild(t.Context(), "shared-win", machine, []string{machine.Name}); err == nil || !strings.Contains(err.Error(), "rarpar.exe") {
		t.Fatalf("a missing rarpar.exe must be refused, got %v", err)
	}
}

func TestPAR3ReferenceTimeoutReachesTheHost(t *testing.T) {
	machine := Machine{PAR3: PAR3Plan{Profile: "smoke", Workers: []int{1}, Repeats: 1, TimeoutMinutes: 20}}
	if strings.Contains(strings.Join(par3Args(machine), " "), "--reference-timeout") {
		t.Fatal("no reference timeout is passed when reference_timeout_minutes is unset")
	}
	machine.PAR3.ReferenceTimeoutMinutes = 45
	if args := strings.Join(par3Args(machine), " "); !strings.Contains(args, "--timeout 20m --reference-timeout 45m") {
		t.Fatalf("par3 args = %s", args)
	}
}

// UNC staging keeps its leading separators, and a trailing separator on a
// Windows staging path is not doubled into the layout.
func TestWindowsHostPaths(t *testing.T) {
	_, machine := exampleMachine(t, "win-dgpu")
	if got := hostJoin(machine, `\\fileserver\bench\run`, "work", "p3"); got != `\\fileserver\bench\run\work\p3` {
		t.Fatalf("UNC join = %q", got)
	}
	if got := hostJoin(machine, `C:\bench\`, `\bin\`, "par3.exe"); got != `C:\bench\bin\par3.exe` {
		t.Fatalf("drive join = %q", got)
	}
	machine.Paths.Staging = `C:\bench\`
	machine.Paths.Scratch = `D:\scratch\`
	layout := windowsLayout(machine, "run1")
	if layout.Base != `C:\bench\run1` || layout.Scratch != `D:\scratch\run1` {
		t.Fatalf("layout base %q scratch %q", layout.Base, layout.Scratch)
	}
}

// A manifest entry that points outside the evidence directory is refused
// before anything is stat'ed or hashed.
func TestVerifyManifestRefusesEscapingPaths(t *testing.T) {
	root := t.TempDir()
	manifest := `{"schema_version": 1, "files": [{"path": "../outside.txt", "bytes": 1, "sha256": ""}]}`
	if err := os.WriteFile(filepath.Join(root, "MANIFEST.json"), []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := verifyManifest(root); err == nil || !strings.Contains(err.Error(), "unsafe path") {
		t.Fatalf("want an unsafe-path refusal, got %v", err)
	}
}

// An SSH-access EC2 host answers on the bench port while user-data is still
// installing cmake, so the run script waits for the user-data sentinel before
// it builds the on-host reference; a local host has no user-data to wait for.
func TestRunScriptWaitsForEC2UserData(t *testing.T) {
	config, cloud := exampleMachine(t, "ec2-zen4-ssm")
	layout := LayoutFor(cloud, "fleet-testrun")
	resolution := sourceBuildResolution(cloud, "par3", cloud.Oracles["par3"], layout)
	script := RunScript(cloud, config.Fleet.Defaults, "fleet-testrun", layout, map[string]string{"par3": resolution.RemotePath})
	wait := strings.Index(script, `while [ ! -f "$USERDATA_DONE" ]`)
	build := strings.Index(script, "par3 build-reference")
	if wait < 0 || build < 0 || wait > build {
		t.Fatalf("user-data wait at %d must precede the reference build at %d", wait, build)
	}
	for _, expected := range []string{"USERDATA_DONE=/var/lib/cloud/instance/BENCH_USERDATA_DONE", "fail userdata-timeout"} {
		if !strings.Contains(script, expected) {
			t.Fatalf("EC2 run script is missing %q", expected)
		}
	}
	config, local := exampleMachine(t, "linux-avx2")
	if script := RunScript(local, config.Fleet.Defaults, "fleet-testrun", LayoutFor(local, "fleet-testrun"), map[string]string{}); strings.Contains(script, "USERDATA_DONE") {
		t.Fatal("a local host must not wait for EC2 user-data")
	}
}

// mutateExample applies old/new substitutions to the example config text in
// order, each to its first occurrence, which must exist.
func mutateExample(t *testing.T, pairs ...string) string {
	t.Helper()
	data, err := os.ReadFile(examplePath)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for i := 0; i+1 < len(pairs); i += 2 {
		if !strings.Contains(text, pairs[i]) {
			t.Fatalf("example config no longer contains %q; update the test", pairs[i])
		}
		text = strings.Replace(text, pairs[i], pairs[i+1], 1)
	}
	return text
}

func parsesAsShell(t *testing.T, script string) {
	t.Helper()
	if _, err := exec.LookPath("sh"); err != nil {
		return
	}
	path := filepath.Join(t.TempDir(), "run.sh")
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command("sh", "-n", path).CombinedOutput(); err != nil {
		t.Fatalf("generated script does not parse: %v\n%s", err, output)
	}
}

func planText(t *testing.T, config Config, machines []Machine) (FleetPlan, string) {
	t.Helper()
	plan := BuildPlan(config, machines, "fleet-testrun")
	var text strings.Builder
	WritePlanText(&text, plan)
	return plan, text.String()
}

// The 2026-10-14 round planned a macro-par3 perf pass ("stat repeats=3,
// record -F 499 on (none)") that never ran: the run script's perf section
// covered the corpus suites only, so a macro-par3 host kept nothing but
// perf --version. macro-par3 runs its own pass inside par3 run; the script
// must pass its flags, warn when the pass falls short, and do no corpus perf
// work on a host that runs no corpus suite, and the plan must say so.
func TestPAR3PerfPassReachesTheRunScript(t *testing.T) {
	config := loadExample(t)
	machines, err := Select(config, []string{"linux-avx2"}, []string{SuiteMacroPAR3})
	if err != nil {
		t.Fatal(err)
	}
	machine := machines[0]
	if machine.Bundle.Source != "release" || len(machine.families()) != 0 || machine.Capabilities.Perf != PerfLinux {
		t.Fatalf("want a linux-perf release-bundle machine running macro-par3 alone: %+v %v", machine.Bundle, machine.Suites)
	}
	script := RunScript(machine, config.Fleet.Defaults, "fleet-testrun", LayoutFor(machine, "fleet-testrun"),
		map[string]string{"par3": "/o/par3"})
	for _, expected := range []string{
		`  "$BENCH" par3 run --reference "$P3_REFERENCE" --candidate "$CANDIDATE" --work "$P3_WORK" \` + "\n" +
			`    --out "$R/par3" --machine "$MACHINE" '--profile' 'full' '--workers' '1,8' '--warmups' '1' '--repeats' '5' '--timeout' '20m' '--pin-cpus' '0-7' \` + "\n" +
			`    --perf-out "$R/perf/par3" '--perf-stat' '3' '--perf-ops' 'repair' '--perf-freq' '499' '--perf-record' 'a-gf16' \` + "\n" +
			`    > "$R/par3-run.stdout.log" 2> "$R/par3-run.stderr.log"`,
		`  if [ -f "$R/perf/par3/INCOMPLETE.txt" ] || [ -z "$(ls -A "$R/perf/par3" 2>/dev/null)" ]; then warn par3-perf-incomplete; fi`,
		`  perf --version > "$R/perf/perf-version.txt" 2>&1`,
	} {
		if !strings.Contains(script, expected) {
			t.Fatalf("run script is missing:\n%s", expected)
		}
	}
	for _, unexpected := range []string{"plan-perf-", "$RECORD_CASES", `perf record -F "$PERF_FREQ"`} {
		if strings.Contains(script, unexpected) {
			t.Fatalf("a host running no corpus suite must do no corpus perf work, but the script has %q", unexpected)
		}
	}
	parsesAsShell(t, script)

	plan, text := planText(t, config, machines)
	for _, expected := range []string{
		"  perf       linux-perf (macro-par3: stat repeats=3 on the reference and rarpar rows of repair, record -F 499 on the rarpar rows of a-gf16)\n",
		"on host: macro-par3 perf pass inside par3 run (untimed, after each op's timed runs) on the plain sets a-gf16,a-gf8,a-fft,b-gf16,c-gf16,c-fft,smoke-gf8,smoke-gf16,smoke-fft: " +
			"perf stat x3 of each repair row (reference,rarpar-w1,rarpar-w1-backup,rarpar-w8,rarpar-w8-backup), each run on a fresh stage; " +
			"on a-gf16, one perf record -F 499 with frame-pointer call graphs of each rarpar row, exported as perf script text and folded stacks; " +
			"up to 139 untimed runs; evidence under results/perf/par3, and INCOMPLETE.txt plus a par3-perf-incomplete warning when the pass falls short",
		"on host: record perf --version and kernel.perf_event_paranoid (no corpus suite runs here",
	} {
		if !strings.Contains(text, expected) {
			t.Fatalf("plan text is missing %q:\n%s", expected, text)
		}
	}
	for _, unexpected := range []string{"(none)", "par2-generate-rar5-v7-volumes", "perf diagnostic pass on the"} {
		if strings.Contains(text, unexpected) {
			t.Fatalf("the plan promises %q, which this run does not do", unexpected)
		}
	}
	protocol := plan.Machines[0].Protocol
	if len(protocol.PerfRecord) != 0 || strings.Join(protocol.PerfPAR3Ops, ",") != "repair" ||
		strings.Join(protocol.PerfPAR3RecordSets, ",") != "a-gf16" {
		t.Fatalf("plan protocol: %+v", protocol)
	}

	// With the corpus suites too, the plan names both passes, and the corpus
	// pass keeps its record loop.
	all, err := Select(config, []string{"linux-avx2"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, text := planText(t, config, all); !strings.Contains(text, "  perf       linux-perf (par2,rar: stat repeats=3 per case, record -F 499 on par2-generate-rar5-v7-volumes,rar5-v7-solid-multivolume; macro-par3: stat repeats=3 on the reference and rarpar rows of repair, record -F 499 on the rarpar rows of a-gf16)\n") {
		t.Fatalf("plan text for every suite:\n%s", text)
	}
	if script := RunScript(all[0], config.Fleet.Defaults, "fleet-testrun", LayoutFor(all[0], "fleet-testrun"), nil); !strings.Contains(script, "--perf-out \"$R/perf/par3\"") ||
		!strings.Contains(script, `perf record -F "$PERF_FREQ"`) {
		t.Fatal("with the corpus suites the script runs both perf passes")
	}
}

// A linux-perf macro-par3 host with no [machines.perf] block counts its
// repair rows and records nothing; par3_ops = [] turns the pass off.
func TestPAR3PerfPassDefaults(t *testing.T) {
	ssmNone := "[machines.capabilities]\nperf = \"none\"\n\n[machines.paths]\nstaging = \"/home/ubuntu/fs\""
	ssmPerf := "[machines.capabilities]\nperf = \"linux-perf\"\n\n[machines.paths]\nstaging = \"/home/ubuntu/fs\""
	config, err := DecodeConfig("fleet.toml", mutateExample(t, ssmNone, ssmPerf))
	if err != nil {
		t.Fatal(err)
	}
	machines, err := Select(config, []string{"ec2-zen4-ssm"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	machine := machines[0]
	if strings.Join(machine.Perf.PAR3Ops, ",") != "repair" || len(machine.Perf.PAR3RecordSets) != 0 {
		t.Fatalf("defaults: %+v", machine.Perf)
	}
	script := RunScript(machine, config.Fleet.Defaults, "fleet-testrun", LayoutFor(machine, "fleet-testrun"), nil)
	if !strings.Contains(script, `    --perf-out "$R/perf/par3" '--perf-stat' '3' '--perf-ops' 'repair' \`+"\n"+`    > "$R/par3-run.stdout.log"`) ||
		strings.Contains(script, "'--perf-record'") {
		t.Fatalf("an SSM macro-par3 host's run script must carry the default perf pass and no record:\n%s", script)
	}
	parsesAsShell(t, script)
	_, text := planText(t, config, machines)
	if !strings.Contains(text, "  perf       linux-perf (macro-par3: stat repeats=3 on the reference and rarpar rows of repair, no perf record)\n") ||
		!strings.Contains(text, "each run on a fresh stage; no perf record (perf.par3_record_sets is empty); up to 135 untimed runs;") {
		t.Fatalf("plan text:\n%s", text)
	}

	config, err = DecodeConfig("fleet.toml", mutateExample(t, `par3_record_sets = ["a-gf16"]`, `par3_record_sets = []`, `par3_ops = ["repair"]`, `par3_ops = []`))
	if err != nil {
		t.Fatal(err)
	}
	machines, err = Select(config, []string{"linux-avx2"}, []string{SuiteMacroPAR3})
	if err != nil {
		t.Fatal(err)
	}
	if script := RunScript(machines[0], config.Fleet.Defaults, "fleet-testrun", LayoutFor(machines[0], "fleet-testrun"), nil); strings.Contains(script, "'--perf-") ||
		strings.Contains(script, "--perf-out") ||
		strings.Contains(script, "par3-perf-incomplete") {
		t.Fatal("par3_ops = [] must turn the macro-par3 perf pass off")
	}
	if _, text := planText(t, config, machines); !strings.Contains(text, "  perf       linux-perf (macro-par3: off (perf.par3_ops is empty))\n") ||
		strings.Contains(text, "macro-par3 perf pass") {
		t.Fatalf("plan text:\n%s", text)
	}
}

func TestPAR3PerfConfigValidation(t *testing.T) {
	cases := []struct {
		name  string
		pairs []string
		want  string
	}{
		{"unknown op", []string{`par3_ops = ["repair"]`, `par3_ops = ["explode"]`}, "perf.par3_ops: unknown op"},
		{"op the run does not measure", []string{`par3_ops = ["repair"]`, `par3_ops = ["verify-damaged"]`},
			"perf.par3_ops: verify-damaged is not one of the macro-par3 ops (create,verify,repair)"},
		{"unknown record set", []string{`par3_record_sets = ["a-gf16"]`, `par3_record_sets = ["z-gf99"]`},
			`perf.par3_record_sets: "z-gf99" is not a set this machine's macro-par3 run selects`},
		{"duplicate record set", []string{`par3_record_sets = ["a-gf16"]`, `par3_record_sets = ["a-gf16", "a-gf16"]`},
			`perf.par3_record_sets: "a-gf16" is listed more than once`},
		{"record without ops", []string{`par3_ops = ["repair"]`, `par3_ops = []`}, "perf.par3_record_sets needs perf.par3_ops"},
		{"record set outside par3.sets", []string{`# sets = ["a-gf16", "c-gf16"]            # default: every set in the profile`, `sets = ["c-gf16"]`},
			`perf.par3_record_sets: "a-gf16" is not a set this machine's macro-par3 run selects (profile full, sets c-gf16)`},
		{"PAR-inside record set", []string{`profile = "full"                         # full | smoke | fleet`, `profile = "fleet"`,
			`par3_record_sets = ["a-gf16"]`, `par3_record_sets = ["zip-inside"]`},
			`perf.par3_record_sets: "zip-inside" is a PAR-inside set; the perf pass covers plain sets only`},
		{"keys on a host without perf", []string{`work = "/home/ubuntu/p3"`, "work = \"/home/ubuntu/p3\"\n\n[machines.perf]\npar3_ops = [\"repair\"]"},
			`machine "ec2-zen4-ssm": perf.par3_ops and perf.par3_record_sets configure the macro-par3 perf pass, which needs capabilities.perf = "linux-perf" and the macro-par3 suite`},
		{"keys on a host without macro-par3", []string{`record_cases = ["par2-generate-rar5-v7-volumes"]`, "record_cases = [\"par2-generate-rar5-v7-volumes\"]\npar3_record_sets = [\"a-gf16\"]"},
			`machine "ec2-graviton4": perf.par3_ops and perf.par3_record_sets configure the macro-par3 perf pass`},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := DecodeConfig("fleet.toml", mutateExample(t, testCase.pairs...))
			if err == nil || !strings.Contains(err.Error(), testCase.want) {
				t.Fatalf("want an error containing %q, got %v", testCase.want, err)
			}
		})
	}
}

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
		{"unknown profile", `profile = "full"                         # full | smoke`, `profile = "huge"`, "par3.profile"},
		{"unknown set", `# sets = ["a-gf16", "c-gf16"]            # default: every set in the profile`, `sets = ["z-gf99"]`, "par3.sets"},
		{"unknown op", `# ops = ["create", "verify", "repair"]   # default; verify-damaged is opt-in`, `ops = ["explode"]`, "unknown op"},
		{"duplicate op", `# ops = ["create", "verify", "repair"]   # default; verify-damaged is opt-in`, `ops = ["create", "create"]`, `op "create" is listed more than once`},
		{"zero workers", `workers = [1, 8]                         # rarpar rows; the reference is single-threaded`, `workers = [0]`, "par3.workers must be positive"},
		{"bad kernel variant", `# kernel_variants = ["name:VAR=value"]`, `kernel_variants = ["novar"]`, "kernel_variants"},
		{"duplicate worker count", `workers = [1, 8]                         # rarpar rows; the reference is single-threaded`, `workers = [8, 8]`, "appears twice"},
		{"pin list", `pin_cpus = "0-7"`, `pin_cpus = "0,2"`, "par3.pin_cpus"},
		{"unknown versus profile", `versus = "versus"`, `versus = "versus-huge"`, "par3.versus"},
		{"missing par3 oracle", "[machines.oracles.par3]\npolicy = \"source-build\"\nreason = \"par3cmdline publishes no Linux binary; built on the host from the toolchains.json pin\"\nrecipe = \"par3cmdline-onhost\"\nversion",
			"[machines.oracles.par3x]\npolicy = \"source-build\"\nreason = \"x\"\nrecipe = \"par3cmdline-onhost\"\nversion", "needs [machines.oracles.par3]"},
		{"onhost recipe takes no url", `recipe = "par3cmdline-onhost"
version = "par3cmdline 0.0.1 (2971702e)"`, `recipe = "par3cmdline-onhost"
url = "https://example.invalid/x.tar.gz"
sha256 = "0000000000000000000000000000000000000000000000000000000000000000"`, "drop url and sha256"},
		{"unrar recipe cannot build par3", `recipe = "par3cmdline-onhost"
version = "par3cmdline 0.0.1 (2971702e)"`, `recipe = "unrar-portable"
url = "https://example.invalid/x.tar.gz"
sha256 = "0000000000000000000000000000000000000000000000000000000000000000"`, "builds the rar oracle, not par3"},
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
	if len(view.Configs) == 0 || strings.Join(view.Variants, ",") != "reference,rarpar-w1,rarpar-w1-buffered,rarpar-w8,rarpar-w8-buffered" {
		t.Fatalf("unexpected view: %+v", view)
	}
	if strings.Join(view.Rows["create"], ",") != "reference,rarpar-w1,rarpar-w1-buffered,rarpar-w8,rarpar-w8-buffered" ||
		strings.Join(view.Rows["verify"], ",") != "reference,rarpar-w1,rarpar-w8" {
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
	machine.PAR3.Durability = []string{"buffered"}
	if _, problem := par3View(machine, layout); !strings.Contains(problem, "durable") {
		t.Fatalf("a durability list without durable must be refused: %q", problem)
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

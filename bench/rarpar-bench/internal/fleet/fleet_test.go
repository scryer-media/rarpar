package fleet

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const examplePath = "../../../fleet.example.toml"

func loadExample(t *testing.T) Config {
	t.Helper()
	config, err := LoadConfig(examplePath)
	if err != nil {
		t.Fatalf("committed example config must load: %v", err)
	}
	return config
}

func TestExampleConfigLoads(t *testing.T) {
	config := loadExample(t)
	if config.SchemaVersion != ConfigSchemaVersion {
		t.Fatalf("schema version = %d, want %d", config.SchemaVersion, ConfigSchemaVersion)
	}
	if len(config.Machines) != 6 {
		t.Fatalf("machines = %d, want 6 (one of each kind, an SSM cloud machine, the turbo machine, and the Windows example)", len(config.Machines))
	}
	if config.SHA256 == "" {
		t.Fatal("config digest must be recorded so a run can name the config it used")
	}
	kinds := map[string]int{}
	for _, machine := range config.Machines {
		kinds[machine.Kind]++
	}
	if kinds[KindAWSEC2] != 3 || kinds[KindLocalSSH] != 3 {
		t.Fatalf("unexpected machine kinds: %v", kinds)
	}
}

func TestExampleConfigCarriesNoSecrets(t *testing.T) {
	data, err := os.ReadFile(examplePath)
	if err != nil {
		t.Fatal(err)
	}
	lowered := strings.ToLower(string(data))
	for _, forbidden := range []string{"password =", "secret =", "token =", "aws_access_key", "aws_secret"} {
		if strings.Contains(lowered, forbidden) {
			t.Fatalf("example config must never contain %q", forbidden)
		}
	}
}

func TestExampleMachineDetails(t *testing.T) {
	config := loadExample(t)
	byName := map[string]Machine{}
	for _, machine := range config.Machines {
		byName[machine.Name] = machine
	}

	nas, ok := byName["nas-atom"]
	if !ok {
		t.Fatal("expected the appliance example machine")
	}
	if nas.Connection.Auth != "askpass" || nas.Connection.AskpassScript == "" {
		t.Fatalf("appliance machine must use an askpass helper: %+v", nas.Connection)
	}
	if !nas.Capabilities.NoPgrep {
		t.Fatal("the busybox-class appliance must be marked no_pgrep so the load gate uses ps")
	}
	if nas.Capabilities.Perf != PerfNone {
		t.Fatal("the appliance has no perf collector")
	}

	cloud, ok := byName["ec2-graviton4"]
	if !ok || cloud.EC2 == nil {
		t.Fatal("expected the EC2 example machine")
	}
	if float64(cloud.EC2.DeadmanMinutes) < cloud.EC2.MaxHours*60 {
		t.Fatal("the deadman must outlast the cost cap")
	}
	if rar := cloud.Oracles["rar"]; rar.Policy != OracleSourceBuild || rar.Recipe != RecipeUnrarHost || !strings.Contains(rar.Reason, "unrar-5.5.0-arm.gz") {
		t.Fatal("the linux-arm64 unrar oracle must be the on-host source build, with RARLAB's missing arm64 binary as its reason")
	}
	if cloud.EC2.CorpusSource == "" || cloud.Paths.Corpus != "" {
		t.Fatal("the EC2 example must provision its corpus via corpus_source, not a pre-seeded host path")
	}

	windows, ok := byName["win-dgpu"]
	if !ok {
		t.Fatal("expected the Windows example machine")
	}
	if !windows.isWindows() || windows.Capabilities.Perf != PerfNone {
		t.Fatal("Windows machines are powershell hosts with no perf collector")
	}
	if windows.Enabled {
		t.Fatal("the unvalidated Windows example must be disabled by default")
	}
}

// mutate returns the example config text with one substitution applied, so each
// validation case differs from a known-good config by exactly one thing.
func mutate(t *testing.T, old, new string) string {
	t.Helper()
	data, err := os.ReadFile(examplePath)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if !strings.Contains(text, old) {
		t.Fatalf("example config no longer contains %q; update the test", old)
	}
	return strings.Replace(text, old, new, 1)
}

func TestConfigValidation(t *testing.T) {
	cases := []struct {
		name string
		old  string
		new  string
		want string
	}{
		{
			name: "corpus_source excludes a host corpus path",
			old:  "staging = \"/home/ubuntu/fleet-stage\"",
			new:  "staging = \"/home/ubuntu/fleet-stage\"\ncorpus = \"/home/ubuntu/corpus\"",
			want: "mutually exclusive",
		},
		{
			name: "corpus_image excludes corpus_source",
			old:  "corpus_source = \"/Users/you/rarpar/target/bench/corpus\"",
			new:  "corpus_source = \"/Users/you/rarpar/target/bench/corpus\"\ncorpus_image = \"123456789012.dkr.ecr.us-east-1.amazonaws.com/rarpar-corpus:dca3e362\"",
			want: "mutually exclusive",
		},
		{
			name: "corpus_image must be an ECR ref (token minting is ECR-only)",
			old:  "corpus_source = \"/Users/you/rarpar/target/bench/corpus\"",
			new:  "corpus_image = \"ghcr.io/example/rarpar-corpus:dca3e362\"",
			want: "not an ECR host",
		},
		{
			name: "corpus_image must carry an explicit tag",
			old:  "corpus_source = \"/Users/you/rarpar/target/bench/corpus\"",
			new:  "corpus_image = \"123456789012.dkr.ecr.us-east-1.amazonaws.com/rarpar-corpus\"",
			want: "missing an explicit :tag",
		},
		{
			name: "schema version pinned",
			old:  "schema_version = 1",
			new:  "schema_version = 2",
			want: "schema_version must be 1",
		},
		{
			name: "ssh_ingress_port must be a real port",
			old:  "ssh_ingress_port = 22022",
			new:  "ssh_ingress_port = 0",
			want: "ssh_ingress_port must be 1-65535",
		},
		{
			name: "unknown key is refused, not ignored",
			old:  "run_id_prefix = \"fleet\"",
			new:  "run_id_prefx = \"fleet\"",
			want: "unknown configuration key",
		},
		{
			name: "inline secrets are refused",
			old:  "askpass_script = \"/Users/example/bin/nas-askpass.sh\"",
			new:  "askpass_script = \"/Users/example/bin/nas-askpass.sh\"\npassword = \"hunter2\"",
			want: "is not allowed",
		},
		{
			name: "ssh alias style host is refused",
			old:  "host = \"192.0.2.10\"",
			new:  "host = \"bench@192.0.2.10\"",
			want: "must be a bare host or address",
		},
		{
			name: "relative remote paths are refused",
			old:  "staging = \"/home/bench/fleet-stage\"",
			new:  "staging = \"fleet-stage\"",
			want: "must be an absolute POSIX path",
		},
		{
			name: "duplicate platform labels are refused",
			old:  "platform_label = \"linux-atom-c3538-noavx\"",
			new:  "platform_label = \"linux-x86_64-adl-avx2\"",
			want: "is already used by machine",
		},
		{
			name: "macro suite without an oracle is refused",
			old:  "[machines.oracles.par2]\npolicy = \"host-path\"\npath = \"/var/services/homes/bench/bench/bin/par2cmdline-turbo-1.4.0-linux-amd64\"\nversion = \"par2cmdline-turbo 1.4.0\"",
			new:  "",
			want: "needs [machines.oracles.par2]",
		},
		{
			name: "source build without a reason is refused",
			old:  "reason = \"RARLAB publishes no Linux arm64 UnRAR: rarlab.com/download.htm lists none, and the only Linux ARM entries on rarlab.com/rar_add.htm are unrar-4.1.3-armv4l.tar.gz and unrar-5.5.0-arm.gz, an UnRAR 5.5.0 (2017) ELF 32-bit ARM EABI5 binary dynamically linked against /lib/ld-linux-armhf.so.3, which an AArch64-only server core cannot execute and which predates RAR 7\"",
			new:  "",
			want: "reason is required",
		},
		{
			name: "unknown oracle recipe is refused",
			old:  "recipe = \"unrar-portable-onhost\"",
			new:  "recipe = \"unrar-native-march\"",
			want: "recipe must be one of",
		},
		{
			name: "the removed container recipe names the on-host one",
			old:  "recipe = \"unrar-portable-onhost\"",
			new:  "recipe = \"unrar-portable\"",
			want: "recipe \"unrar-portable\" was removed: it compiled UnRAR in a container on the orchestrating machine; use recipe \"unrar-portable-onhost\"",
		},
		{
			name: "the on-host UnRAR build is refused where RARLAB publishes a binary",
			old:  "go_arch = \"arm64\"                        # the linux-arm64-musl-direct asset",
			new:  "go_arch = \"amd64\"",
			want: "builds UnRAR only on linux/arm64, where RARLAB publishes no current binary; a linux/amd64 host uses RARLAB's official binary",
		},
		{
			name: "the on-host UnRAR build needs its source pin",
			old:  "sha256 = \"3995af0aa32b1505a566da053725551a1f0698dc42b2fdf7ba7d65db0d004e33\"",
			new:  "",
			want: "needs url and sha256 for RARLAB's unrarsrc source tarball",
		},
		{
			name: "the on-host UnRAR source is RARLAB's tarball",
			old:  "url = \"https://www.rarlab.com/rar/unrarsrc-7.2.3.tar.gz\"",
			new:  "url = \"https://www.rarlab.com/rar/unrarsrc-7.2.3.zip\"",
			want: "must name RARLAB's unrarsrc-*.tar.gz source tarball",
		},
		{
			name: "the container lane label is refused",
			old:  "lane = \"cpu\"                      # cpu | metal (fleet hosts run natively)",
			new:  "lane = \"docker-cpu\"",
			want: "fleet.defaults.lane must be cpu or metal",
		},
		{
			name: "deadman shorter than the cost cap is refused",
			old:  "deadman_minutes = 180",
			new:  "deadman_minutes = 30",
			want: "must be at least ec2.max_hours*60",
		},
		{
			name: "cost cap above the session ceiling is refused",
			old:  "max_hours = 2.0",
			new:  "max_hours = 9.0",
			want: "exceeds fleet.aws.max_session_hours",
		},
		{
			name: "cloud vcpus over quota is refused",
			old:  "total_vcpu_quota = 64",
			new:  "total_vcpu_quota = 2",
			want: "raise the quota, move machines to a later wave, or disable machines",
		},
		{
			name: "wave below one is refused",
			old:  "wave = 1",
			new:  "wave = 0",
			want: "wave must be >= 1",
		},
		{
			name: "wave on a local machine is refused",
			old:  "kind = \"local-ssh\"                       # local-ssh | aws-ec2",
			new:  "kind = \"local-ssh\"                       # local-ssh | aws-ec2\nwave = 2",
			want: "wave is only valid for kind",
		},
		{
			name: "unknown suite is refused",
			old:  "suites = [\"macro-rar\", \"macro-par2\"]",
			new:  "suites = [\"macro-rar\", \"macro-tar\"]",
			want: "unknown suite",
		},
		{
			name: "windows host-path oracle with a cmd metacharacter is refused",
			old:  "path = \"C:\\\\bench\\\\oracles\\\\UnRAR.exe\"",
			new:  "path = \"C:\\\\bench\\\\100%\\\\UnRAR.exe\"",
			want: "oracles.rar.path must not contain a double quote",
		},
		{
			name: "windows host with perf is refused",
			old:  "perf = \"none\"                            # enforced: Windows has no perf collector",
			new:  "perf = \"linux-perf\"",
			want: "Windows hosts have no perf collector",
		},
		{
			name: "askpass without a helper is refused",
			old:  "askpass_script = \"/Users/example/bin/nas-askpass.sh\"",
			new:  "",
			want: "askpass_script is required",
		},
		{
			name: "empty quiet load process list is refused",
			old:  "quiet_load_process_names = [\"rarpar-bench\", \"rarpar\", \"par2\", \"unrar\", \"decode_timing\", \"searchend_timing\", \"crc_probe\"]",
			new:  "quiet_load_process_names = []",
			want: "must not be empty",
		},
		{
			name: "inline tables are rejected rather than mis-parsed",
			old:  "ssh_options = [\"-o\", \"ConnectTimeout=20\"]",
			new:  "ssh_options = { a = 1 }",
			want: "inline tables are not supported",
		},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			_, err := DecodeConfig("fleet.toml", mutate(t, item.old, item.new))
			if err == nil {
				t.Fatalf("expected a validation failure mentioning %q", item.want)
			}
			if !strings.Contains(err.Error(), item.want) {
				t.Fatalf("error %q does not mention %q", err.Error(), item.want)
			}
		})
	}
}

func TestQuotaMath(t *testing.T) {
	config := loadExample(t)
	cases := []struct {
		name      string
		quota     int
		instances []EC2
		// waves assigns instances[i] to waves[i]; nil = everything in wave 1.
		waves     []int
		requested int
		fits      bool
		usd       float64
		// headroom is only consulted when waves is set; the default
		// expectation is quota-requested (single-wave arithmetic).
		headroom int
	}{
		{name: "no cloud machines", quota: 64, fits: true},
		{
			name:      "single instance fits",
			quota:     8,
			instances: []EC2{{InstanceType: "c8g.xlarge", VCPUs: 4, MaxHours: 2, HourlyUSD: 0.144}},
			requested: 4, fits: true, usd: 0.29,
		},
		{
			name:  "parallel launch is summed, not taken one at a time",
			quota: 16,
			instances: []EC2{
				{InstanceType: "c8g.xlarge", VCPUs: 4, MaxHours: 2, HourlyUSD: 0.144},
				{InstanceType: "c6g.4xlarge", VCPUs: 16, MaxHours: 1, HourlyUSD: 0.544},
			},
			requested: 20, fits: false, usd: 0.83,
		},
		{
			name:      "exactly at quota still fits",
			quota:     4,
			instances: []EC2{{InstanceType: "c8g.xlarge", VCPUs: 4, MaxHours: 0.5, HourlyUSD: 0.144}},
			requested: 4, fits: true, usd: 0.07,
		},
		{
			name:  "waves fit sequentially where one parallel launch would not",
			quota: 16,
			instances: []EC2{
				{InstanceType: "c8g.xlarge", VCPUs: 4, MaxHours: 2, HourlyUSD: 0.144},
				{InstanceType: "c6g.4xlarge", VCPUs: 16, MaxHours: 1, HourlyUSD: 0.544},
			},
			waves:     []int{2, 1},
			requested: 20, fits: true, usd: 0.83, headroom: 0,
		},
		{
			name:  "a single overfull wave still fails",
			quota: 16,
			instances: []EC2{
				{InstanceType: "c8g.xlarge", VCPUs: 4, MaxHours: 2, HourlyUSD: 0.144},
				{InstanceType: "c6g.4xlarge", VCPUs: 16, MaxHours: 1, HourlyUSD: 0.544},
			},
			waves:     []int{1, 1},
			requested: 20, fits: false, usd: 0.83, headroom: -4,
		},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			local := config
			local.Fleet.AWS.TotalVCPUQuota = item.quota
			var machines []Machine
			for index := range item.instances {
				spec := item.instances[index]
				wave := 0
				if item.waves != nil {
					wave = item.waves[index]
				}
				machines = append(machines, Machine{
					Name: "cloud", Kind: KindAWSEC2, Wave: wave, EC2: &spec,
				})
			}
			check := ComputeQuota(local, machines)
			if check.Requested != item.requested {
				t.Fatalf("requested = %d, want %d", check.Requested, item.requested)
			}
			if check.Fits != item.fits {
				t.Fatalf("fits = %t, want %t", check.Fits, item.fits)
			}
			if item.usd != 0 && check.EstimatedUSD != item.usd {
				t.Fatalf("estimated spend = %.2f, want %.2f", check.EstimatedUSD, item.usd)
			}
			wantHeadroom := item.quota - item.requested
			if item.waves != nil {
				wantHeadroom = item.headroom
			}
			if check.Headroom != wantHeadroom {
				t.Fatalf("headroom = %d, want %d", check.Headroom, wantHeadroom)
			}
		})
	}
}

func TestSelect(t *testing.T) {
	config := loadExample(t)
	t.Run("defaults skip disabled machines", func(t *testing.T) {
		machines, err := Select(config, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		for _, machine := range machines {
			if machine.Name == "win-dgpu" {
				t.Fatal("a disabled machine must not be selected by default")
			}
		}
	})
	t.Run("naming a disabled machine selects it", func(t *testing.T) {
		machines, err := Select(config, []string{"win-dgpu"}, nil)
		if err != nil {
			t.Fatal(err)
		}
		if len(machines) != 1 || machines[0].Name != "win-dgpu" {
			t.Fatalf("expected the named machine, got %+v", machines)
		}
	})
	t.Run("suite filter narrows a machine's suites", func(t *testing.T) {
		machines, err := Select(config, []string{"nas-atom"}, []string{SuiteMacroRAR})
		if err != nil {
			t.Fatal(err)
		}
		if len(machines) != 1 || len(machines[0].Suites) != 1 || machines[0].Suites[0] != SuiteMacroRAR {
			t.Fatalf("suite filter did not narrow the machine: %+v", machines)
		}
	})
	t.Run("unknown machine is an error", func(t *testing.T) {
		if _, err := Select(config, []string{"nope"}, nil); err == nil {
			t.Fatal("expected an error for an unknown machine")
		}
	})
	t.Run("unknown suite is an error", func(t *testing.T) {
		if _, err := Select(config, nil, []string{"macro-zip"}); err == nil {
			t.Fatal("expected an error for an unknown suite")
		}
	})
}

func TestBuildPlan(t *testing.T) {
	config := loadExample(t)
	machines, err := Select(config, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	plan := BuildPlan(config, machines, "fleet-testrun")
	if plan.RunID != "fleet-testrun" || plan.SchemaVersion != FleetPlanSchemaVersion {
		t.Fatalf("unexpected plan header: %+v", plan)
	}
	if len(plan.Machines) != len(machines) {
		t.Fatalf("plan covers %d machines, want %d", len(plan.Machines), len(machines))
	}
	// The release assets are verified first, then credentials are checked
	// before anything is built or launched.
	if len(plan.Preflight) < 2 || !strings.Contains(plan.Preflight[0], "SHA256SUMS") {
		t.Fatalf("release verification must come first: %v", plan.Preflight)
	}
	if !strings.Contains(plan.Preflight[1], "AWS credential check") {
		t.Fatalf("the AWS credential check must follow release verification: %v", plan.Preflight)
	}
	for _, machine := range plan.Machines {
		if !strings.Contains(machine.Remote.Base, "fleet-testrun") {
			t.Fatalf("machine %s does not stage under the run id: %s", machine.Name, machine.Remote.Base)
		}
		if len(machine.Steps) == 0 {
			t.Fatalf("machine %s has no steps", machine.Name)
		}
		if machine.Cloud != nil {
			last := machine.Steps[len(machine.Steps)-2]
			if !strings.Contains(last, "terminate and verify teardown") {
				t.Fatalf("cloud machine %s must terminate with verification: %q", machine.Name, last)
			}
		}
	}
	if plan.Quota.Requested != 28 || !plan.Quota.Fits {
		t.Fatalf("unexpected quota check: %+v", plan.Quota)
	}
	var text strings.Builder
	WritePlanText(&text, plan)
	for _, expected := range []string{"PREFLIGHT", "AWS QUOTA AND COST", "teardown:", "linux-atom-c3538-noavx",
		"bundle     release rarpar-v0.7.0, asset rarpar-rarpar-v0.7.0-linux-x86_64-musl-direct.tar.gz"} {
		if !strings.Contains(text.String(), expected) {
			t.Fatalf("plan text is missing %q", expected)
		}
	}
}

func TestRunScriptCorpusImageFetch(t *testing.T) {
	config := loadExample(t)
	var cloud Machine
	for _, machine := range config.Machines {
		if machine.Name == "ec2-graviton4" {
			cloud = machine
		}
	}
	cloud.EC2.CorpusSource = ""
	cloud.EC2.CorpusImage = "123456789012.dkr.ecr.us-east-1.amazonaws.com/rarpar-corpus:dca3e362"
	layout := LayoutFor(cloud, "fleet-testrun")
	cloud.Paths.Corpus = joinPosix(layout.Base, "corpus")
	script := RunScript(cloud, config.Fleet.Defaults, "fleet-testrun", layout, map[string]string{})
	for _, expected := range []string{
		"CORPUS_IMAGE='123456789012.dkr.ecr.us-east-1.amazonaws.com/rarpar-corpus:dca3e362'",
		"corpus fetch --image \"$CORPUS_IMAGE\" --token-file \"$ECR_TOKEN_FILE\" --out \"$CORPUS\"",
		"fail corpus-token-missing", // a missing token must be its own failure marker
		"fail corpus-fetch",
	} {
		if !strings.Contains(script, expected) {
			t.Fatalf("corpus_image run script is missing %q", expected)
		}
	}
	// Image mode has no orchestrator upload, so it must not wait on the
	// upload sentinel: CORPUS_READY stays empty and the wait is skipped.
	if !strings.Contains(script, "CORPUS_READY=''") {
		t.Fatal("corpus_image mode must not arm the upload sentinel")
	}

	// And the upload mode keeps its sentinel while never invoking a fetch.
	config = loadExample(t)
	for _, machine := range config.Machines {
		if machine.Name != "ec2-graviton4" {
			continue
		}
		layout := LayoutFor(machine, "fleet-testrun")
		machine.Paths.Corpus = joinPosix(layout.Base, "corpus")
		script := RunScript(machine, config.Fleet.Defaults, "fleet-testrun", layout, map[string]string{})
		if !strings.Contains(script, "CORPUS_READY='"+joinPosix(layout.Base, "CORPUS-UPLOADED")+"'") {
			t.Fatal("corpus_source mode must keep the upload sentinel")
		}
		if !strings.Contains(script, "CORPUS_IMAGE=''") {
			t.Fatal("corpus_source mode must leave CORPUS_IMAGE empty")
		}
	}
}

func TestRunScriptEncodesHouseRules(t *testing.T) {
	config := loadExample(t)
	byName := map[string]Machine{}
	for _, machine := range config.Machines {
		byName[machine.Name] = machine
	}

	nas := byName["nas-atom"]
	layout := LayoutFor(nas, "fleet-testrun")
	script := RunScript(nas, config.Fleet.Defaults, "fleet-testrun", layout, map[string]string{
		"rar":  nas.Oracles["rar"].Path,
		"par2": nas.Oracles["par2"].Path,
	})
	// A DSM-class host has no pgrep; the gate must fall back to ps.
	if !strings.Contains(script, "ps -ef | grep") {
		t.Fatal("no_pgrep hosts must gate with ps -ef | grep")
	}
	if strings.Contains(script, "pgrep -f") {
		t.Fatal("no_pgrep hosts must never invoke pgrep")
	}
	for _, expected := range []string{
		"gate rar", "gate par2", // quiet-load gate before every timed pass
		"--warmups \"$warm\"", "--repeats \"$reps\"", // the harness protocol, verbatim
		"plan_for rar \"$PLAN\" \"$WARMUPS\" \"$REPEATS\"",
		"MANIFEST.json", "DONE.tmp", // sentinel is renamed into place last
		"NO-COLLECTOR", // perf=none still exports phase timings
	} {
		if !strings.Contains(script, expected) {
			t.Fatalf("run script is missing %q", expected)
		}
	}
	if strings.Contains(script, "perf record") {
		t.Fatal("a perf=none host must not attempt perf record")
	}

	linux := byName["linux-avx2"]
	perfScript := RunScript(linux, config.Fleet.Defaults, "fleet-testrun", LayoutFor(linux, "fleet-testrun"), nil)
	for _, expected := range []string{
		"--perf",         // harness perf-stat counters for both subjects
		"perf record -F", // sampled profile on the designated heavy cases
		"perf script -i", // exported so diagnosis never needs a re-run
		".folded",        // collapsed stacks
		"perf stat -r",   // repeated counters per designated case
		"pgrep",          // this host has pgrep
	} {
		if !strings.Contains(perfScript, expected) {
			t.Fatalf("perf-capable run script is missing %q", expected)
		}
	}
}

// The perf stat -r pass re-invokes the harness once per repetition, and
// `run` refuses a non-empty --out directory — which the record pass just
// populated. Without a shim clearing it inside each repetition, every
// repetition measures the early refusal instead of the workload (caught
// live: two different workloads agreeing on instruction count to four
// significant figures across two fleet rounds). Failures must also warn,
// not vanish into a discarded stream.
func TestRunScriptStatPassMeasuresRealRunsNotRefusals(t *testing.T) {
	config := loadExample(t)
	byName := map[string]Machine{}
	for _, machine := range config.Machines {
		byName[machine.Name] = machine
	}
	linux := byName["linux-avx2"]
	script := RunScript(linux, config.Fleet.Defaults, "fleet-testrun", LayoutFor(linux, "fleet-testrun"), nil)
	if !strings.Contains(script, `sh -c 'rm -rf "$1" && shift && exec "$@"' stat-shim "$W/rec-$c"`) {
		t.Fatal("perf stat must clear the run's --out directory inside each repetition via the stat-shim")
	}
	if !strings.Contains(script, `|| warn "perf-stat-$c"`) {
		t.Fatal("a failed perf stat repetition must surface as a warning")
	}
	if strings.Contains(script, `"$BENCH" "$@" > /dev/null 2>&1 || log "perf stat`) {
		t.Fatal("the stat pass must not regress to discarding the harness's failure output")
	}
}

// A literal percent in a generated line silently becomes a format verb and
// produces "%!Y(MISSING)" in the shipped script, which the remote shell then
// rejects. This caught exactly that on the first live run.
func TestRunScriptHasNoFormatVerbDamage(t *testing.T) {
	config := loadExample(t)
	for _, machine := range config.Machines {
		if machine.isWindows() {
			continue
		}
		script := RunScript(machine, config.Fleet.Defaults, "fleet-testrun", LayoutFor(machine, "fleet-testrun"), nil)
		for _, damage := range []string{"%!", "(MISSING)", "(EXTRA"} {
			if strings.Contains(script, damage) {
				t.Fatalf("machine %s: generated script contains %q", machine.Name, damage)
			}
		}
		if !strings.Contains(script, "date -u +%Y-%m-%dT%H:%M:%SZ") {
			t.Fatalf("machine %s: the log timestamp format did not survive generation", machine.Name)
		}
	}
}

// The generated script has to parse on the remote shell. `sh -n` here is a
// coarse check (macOS /bin/sh is bash in POSIX mode), but it catches the class
// of damage that reaches a host as "Syntax error: unexpected (".
func TestRunScriptParses(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no POSIX shell available")
	}
	config := loadExample(t)
	for _, machine := range config.Machines {
		if machine.isWindows() {
			continue
		}
		script := RunScript(machine, config.Fleet.Defaults, "fleet-testrun", LayoutFor(machine, "fleet-testrun"),
			map[string]string{"rar": "/oracles/unrar", "par2": "/oracles/par2"})
		path := filepath.Join(t.TempDir(), machine.Name+".sh")
		if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
			t.Fatal(err)
		}
		output, err := exec.Command("sh", "-n", path).CombinedOutput()
		if err != nil {
			t.Fatalf("machine %s: generated script does not parse: %v\n%s", machine.Name, err, output)
		}
	}
}

func TestRunScriptQuotesEveryPath(t *testing.T) {
	config := loadExample(t)
	machine := config.Machines[0]
	machine.Paths.Staging = "/home/bench/fleet stage"
	layout := LayoutFor(machine, "fleet-testrun")
	script := RunScript(machine, config.Fleet.Defaults, "fleet-testrun", layout, nil)
	if !strings.Contains(script, "BASE='/home/bench/fleet stage/fleet-testrun'") {
		t.Fatal("paths with spaces must reach the host quoted")
	}
}

func TestLayoutUsesScratchForTimedWork(t *testing.T) {
	machine := Machine{
		Name:  "example",
		Paths: HostPaths{Staging: "/home/bench/stage", Scratch: "/dev/shm/fleet"},
	}
	layout := LayoutFor(machine, "run-1")
	if layout.Scratch != "/dev/shm/fleet/run-1" {
		t.Fatalf("scratch = %s", layout.Scratch)
	}
	if layout.Base != "/home/bench/stage/run-1" || layout.Bin != "/home/bench/stage/run-1/bin" {
		t.Fatalf("unexpected layout: %+v", layout)
	}
	without := LayoutFor(Machine{Paths: HostPaths{Staging: "/home/bench/stage"}}, "run-1")
	if without.Scratch != "/home/bench/stage/run-1/work" {
		t.Fatalf("scratch fallback = %s", without.Scratch)
	}
}

func TestShellQuote(t *testing.T) {
	cases := map[string]string{
		"/plain/path": "'/plain/path'",
		"/with space": "'/with space'",
		"/it's":       `'/it'\''s'`,
		"$(rm -rf /)": "'$(rm -rf /)'",
		"a\"b":        "'a\"b'",
	}
	for input, want := range cases {
		if got := shellQuote(input); got != want {
			t.Fatalf("shellQuote(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestManifestVerification(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "crc_probe.txt"), []byte("probe output\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	digest, err := fileSHA256(filepath.Join(root, "crc_probe.txt"))
	if err != nil {
		t.Fatal(err)
	}
	manifest := HostManifest{
		SchemaVersion: 1, RunID: "fleet-testrun", Machine: "example", Status: "ok",
		Files: []ManifestFile{{Path: "crc_probe.txt", Bytes: 13, SHA256: digest}},
	}
	if err := writeJSONFile(filepath.Join(root, "MANIFEST.json"), manifest); err != nil {
		t.Fatal(err)
	}
	if _, err := verifyManifest(root); err != nil {
		t.Fatalf("a matching manifest must verify: %v", err)
	}

	if err := os.WriteFile(filepath.Join(root, "crc_probe.txt"), []byte("tampered!!!!\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := verifyManifest(root); err == nil {
		t.Fatal("altered evidence must fail manifest verification")
	}
}

func TestTOMLSubset(t *testing.T) {
	t.Run("array of tables and dotted sections", func(t *testing.T) {
		root, err := parseTOML("t.toml", `
top = 1
[a]
x = "one"
[[m]]
name = "first"
[m.sub]
value = 2
[[m]]
name = "second"
`)
		if err != nil {
			t.Fatal(err)
		}
		if len(root.arrays["m"]) != 2 {
			t.Fatalf("array of tables = %d", len(root.arrays["m"]))
		}
		if root.arrays["m"][0].tables["sub"].values["value"].int != 2 {
			t.Fatal("[m.sub] must attach to the most recent [[m]]")
		}
		if root.arrays["m"][1].values["name"].str != "second" {
			t.Fatal("second array element lost its key")
		}
	})
	t.Run("hash inside a quoted value is not a comment", func(t *testing.T) {
		root, err := parseTOML("t.toml", `path = "/tmp/a#b" # trailing comment`)
		if err != nil {
			t.Fatal(err)
		}
		if got := root.values["path"].str; got != "/tmp/a#b" {
			t.Fatalf("path = %q", got)
		}
	})
	t.Run("duplicate keys are refused", func(t *testing.T) {
		if _, err := parseTOML("t.toml", "a = 1\na = 2\n"); err == nil {
			t.Fatal("expected a duplicate key error")
		}
	})
	t.Run("unsupported forms are named", func(t *testing.T) {
		for text, want := range map[string]string{
			"a = \"\"\"x\"\"\"": "multi-line strings",
			"a = [1,":           "multi-line arrays",
			"a = 1979-05-27":    "unsupported value",
		} {
			_, err := parseTOML("t.toml", text)
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("parsing %q: got %v, want a message mentioning %q", text, err, want)
			}
		}
	})
}

func TestUserDataAlwaysCarriesADeadman(t *testing.T) {
	script := UserData(180, 22022)
	if !strings.Contains(script, "shutdown -h +180") {
		t.Fatal("every cloud host must get a deadman shutdown")
	}
	if !strings.Contains(script, "unattended-upgrades") {
		t.Fatal("quiet-box hygiene must disable background updaters")
	}
}

// Round 1 lost perf on four of five boxes because the stock Ubuntu AMIs ship
// kernel.perf_event_paranoid=4 and perf refuses to count for an unprivileged user.
func TestUserDataOpensThePerfCountersToTheBenchUser(t *testing.T) {
	script := UserData(180, 22022)
	if !strings.Contains(script, "sysctl -w kernel.perf_event_paranoid=1") {
		t.Fatal("user-data must relax perf_event_paranoid for the running boot")
	}
	if !strings.Contains(script, "/etc/sysctl.d/99-bench-perf.conf") {
		t.Fatal("the perf_event_paranoid relaxation must survive a reboot via a sysctl.d drop-in")
	}
}

// The security group only opens the configured port, so sshd must move there
// or the box is unreachable. Both listener mechanisms have to be covered:
// classic sshd_config on service-managed images, and Ubuntu 22.10+ socket
// activation, where ssh.socket owns the listener and sshd_config Port lines
// bind nothing.
func TestUserDataRelocatesSSHDOntoTheConfiguredPort(t *testing.T) {
	script := UserData(180, 22022)
	for _, needed := range []string{
		// Existing Port lines are neutralised, so 22 is closed, not supplemented.
		`sed -i 's/^Port /#Port /' /etc/ssh/sshd_config`,
		// Prepended, not dropped into sshd_config.d: works without an Include
		// directive and stays outside any Match block.
		`sed -i '1i Port 22022' /etc/ssh/sshd_config`,
		`/etc/systemd/system/ssh.socket.d/50-bench-port.conf`,
		// ListenStream= first: clears 22 before adding the new port.
		`printf '[Socket]\nListenStream=\nListenStream=22022\n'`,
		`systemctl daemon-reload`,
		`systemctl restart ssh.socket`,
	} {
		if !strings.Contains(script, needed) {
			t.Fatalf("user-data must contain %q:\n%s", needed, script)
		}
	}
	if strings.Index(script, "shutdown -h") > strings.Index(script, "Relocate sshd") {
		t.Fatal("the deadman must be scheduled before anything else, including the sshd relocation")
	}
}

// Explicit port 22 is the operator saying "stock behavior"; user-data must not
// touch sshd at all in that case.
func TestUserDataLeavesSSHDAloneOnPort22(t *testing.T) {
	script := UserData(180, 22)
	for _, forbidden := range []string{"ssh.socket", "sshd_config", "Relocate sshd"} {
		if strings.Contains(script, forbidden) {
			t.Fatalf("port 22 must leave stock sshd untouched; found %q in:\n%s", forbidden, script)
		}
	}
}

// The security group is the run's only network exposure, so the rule set is
// asserted directly: one ingress rule per distinct configured port, scoped to
// the orchestrator's /32, and nothing else — 22 is reachable only if some
// machine explicitly configured it.
func TestCreateSessionOpensExactlyTheConfiguredPorts(t *testing.T) {
	var lines []string
	aws := &AWS{CLI: "aws", Region: "us-east-1", DryRun: true, Log: func(format string, args ...any) {
		lines = append(lines, fmt.Sprintf(format, args...))
	}}
	session, err := aws.CreateSession(context.Background(), "rarpar-fleet", "198.51.100.7", t.TempDir(), []int{22022, 2200, 22022})
	if err != nil {
		t.Fatal(err)
	}
	log := strings.Join(lines, "\n")
	if got := strings.Count(log, "authorize-security-group-ingress"); got != 2 {
		t.Fatalf("distinct ports must be authorized exactly once each; got %d rules:\n%s", got, log)
	}
	for _, needed := range []string{"--port 2200", "--port 22022", "--cidr 198.51.100.7/32", "ports=2200,22022"} {
		if !strings.Contains(log, needed) {
			t.Fatalf("session log must contain %q:\n%s", needed, log)
		}
	}
	if strings.Contains(log, "--port 22 ") {
		t.Fatalf("port 22 must never be opened unless configured:\n%s", log)
	}
	if session.PublicCIDR != "198.51.100.7/32" {
		t.Fatalf("ingress must be scoped to the orchestrator's /32, got %s", session.PublicCIDR)
	}
}

// Cloud machines resolve their SSH port at decode time — per-machine override
// or the fleet.aws.ssh_ingress_port default — so the security group rule, the
// sshd relocation, and every dial all share one value.
func TestCloudSSHPortInheritsTheFleetIngressPort(t *testing.T) {
	config := loadExample(t)
	for _, machine := range config.Machines {
		if machine.Kind == KindAWSEC2 && machine.Connection.Port != 22022 {
			t.Fatalf("machine %s: port = %d, want the fleet.aws.ssh_ingress_port value 22022", machine.Name, machine.Connection.Port)
		}
	}
}

func TestCloudSSHPortCanBePinnedPerMachine(t *testing.T) {
	config, err := DecodeConfig("fleet.toml", mutate(t, "user = \"ubuntu\"", "port = 2200\nuser = \"ubuntu\""))
	if err != nil {
		t.Fatal(err)
	}
	for _, machine := range config.Machines {
		// The substitution lands in the first cloud machine's block only.
		if machine.Name == "ec2-graviton4" && machine.Connection.Port != 2200 {
			t.Fatalf("machine %s: port = %d, want the per-machine pin 2200", machine.Name, machine.Connection.Port)
		}
	}
}

// --hold defers one host's terminate so an operator can run an extra pass (an
// env A/B) on the same silicon and the same binary. The cost-safety property is
// that it is opt-in per machine: an unnamed machine, and every machine when the
// flag is absent, still tears down the moment its evidence is collected.
func TestHoldIsOptInPerMachine(t *testing.T) {
	for _, testCase := range []struct {
		name    string
		hold    []string
		machine string
		want    bool
	}{
		{name: "no flag holds nothing", hold: nil, machine: "ec2-c7a", want: false},
		{name: "named machine is held", hold: []string{"ec2-c7a"}, machine: "ec2-c7a", want: true},
		{name: "unnamed machine still tears down", hold: []string{"ec2-c7a"}, machine: "ec2-n1", want: false},
		{name: "several machines held", hold: []string{"ec2-c7a", "ec2-c7i", "ec2-a72"}, machine: "ec2-a72", want: true},
		{name: "no substring matching", hold: []string{"ec2-c7"}, machine: "ec2-c7a", want: false},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			orch := &orchestrator{options: Options{Hold: testCase.hold}}
			if got := orch.holds(testCase.machine); got != testCase.want {
				t.Fatalf("holds(%q) with --hold %v = %t, want %t",
					testCase.machine, testCase.hold, got, testCase.want)
			}
		})
	}
}

func TestWindowsRunScriptExecutesAFile(t *testing.T) {
	config := loadExample(t)
	var windows Machine
	for _, machine := range config.Machines {
		if machine.Name == "win-dgpu" {
			windows = machine
		}
	}
	layout := windowsLayout(windows, "fleet-testrun")
	if !strings.HasSuffix(layout.Script, "run.ps1") {
		t.Fatalf("the Windows runner must execute a script file: %s", layout.Script)
	}
	script := WindowsRunScript(windows, config.Fleet.Defaults, "fleet-testrun", layout, map[string]string{"rar": "C:\\bench\\oracles\\UnRAR.exe"})
	for _, expected := range []string{"MANIFEST.json", "DONE", "Gate ", "ZipFile]::CreateFromDirectory"} {
		if !strings.Contains(script, expected) {
			t.Fatalf("Windows run script is missing %q", expected)
		}
	}
	if !strings.Contains(script, "\r\n") {
		t.Fatal("PowerShell scripts must use CRLF line endings")
	}
}

func TestBuildKeyGroupsIdenticalBundles(t *testing.T) {
	base := Machine{
		Name:   "a",
		Suites: []string{"macro-rar", "macro-par2"},
		Bundle: Bundle{Source: BundleRelease, Tag: "rarpar-v0.7.0", GoOS: "linux", GoArch: "arm64"},
	}
	twin := base
	twin.Name = "b"
	if buildKey(base) != buildKey(twin) {
		t.Fatal("machines with identical bundles and suite content must share one bundle")
	}
	// A version names the same release as its tag, and the default flavor is
	// musl-direct: all three stage the same asset.
	byVersion := base
	byVersion.Bundle.Tag, byVersion.Bundle.Version = "", "0.7.0"
	explicit := base
	explicit.Bundle.Flavor = FlavorMuslDirect
	if buildKey(byVersion) != buildKey(base) || buildKey(explicit) != buildKey(base) {
		t.Fatal("a version and its tag, or the default and explicit musl flavor, must share one bundle")
	}
	for name, change := range map[string]func(*Machine){
		"another release": func(machine *Machine) { machine.Bundle.Tag = "rarpar-v0.6.2" },
		"another flavor":  func(machine *Machine) { machine.Bundle.Flavor = FlavorGNUDirect },
		"another arch":    func(machine *Machine) { machine.Bundle.GoArch = "amd64" },
		"another source": func(machine *Machine) {
			machine.Bundle = Bundle{Source: BundlePrebuilt, Path: "/bundles/linux-arm64", GoOS: "linux", GoArch: "arm64"}
		},
		"other suite contents": func(machine *Machine) { machine.Suites = []string{"macro-rar", "macro-par3"} },
	} {
		other := base
		other.Name = "c"
		change(&other)
		if buildKey(base) == buildKey(other) {
			t.Fatalf("%s must not share a bundle", name)
		}
		if sharedBundleName(base, "tree0") == sharedBundleName(other, "tree0") {
			t.Fatalf("%s: shared bundle names must differ per key", name)
		}
	}
	if sharedBundleName(base, "tree0") == sharedBundleName(base, "tree1") {
		t.Fatal("shared bundle names must differ per harness tree")
	}
	if name := sharedBundleName(base, "tree0"); !strings.HasPrefix(name, "shared-linux-arm64-musl-direct-") {
		t.Fatalf("a release bundle is named after its platform: %s", name)
	}
	prebuilt := base
	prebuilt.Bundle = Bundle{Source: BundlePrebuilt, Path: "/bundles/linux-arm64"}
	if name := sharedBundleName(prebuilt, "tree0"); !strings.HasPrefix(name, "shared-prebuilt-") {
		t.Fatalf("a prebuilt bundle is named after its source: %s", name)
	}
}

func TestValidateRunID(t *testing.T) {
	if err := ValidateRunID(NewRunID("")); err != nil {
		t.Fatalf("a fresh run id must validate: %v", err)
	}
	if err := ValidateRunID("fleet-20261007T030000Z"); err != nil {
		t.Fatalf("a plain run id must validate: %v", err)
	}
	for _, bad := range []string{"", ".", "..", "../shared", "a/b", `a\b`, "with space", "/abs"} {
		if err := ValidateRunID(bad); err == nil {
			t.Errorf("run id %q must be rejected", bad)
		}
	}
}

// loadMutatedExample loads the example config with one textual substitution
// applied, for exercising validation of a single field.
func loadMutatedExample(t *testing.T, old, new string) (Config, error) {
	t.Helper()
	data, err := os.ReadFile(examplePath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), old) {
		t.Fatalf("example config does not contain %q", old)
	}
	path := filepath.Join(t.TempDir(), "fleet.toml")
	if err := os.WriteFile(path, []byte(strings.Replace(string(data), old, new, 1)), 0o644); err != nil {
		t.Fatal(err)
	}
	return LoadConfig(path)
}

func TestExampleTurboMachine(t *testing.T) {
	config := loadExample(t)
	var turbo Machine
	for _, machine := range config.Machines {
		if machine.Name == "ec2-zen4-turbo" {
			turbo = machine
		}
	}
	if turbo.Name == "" || turbo.EC2 == nil {
		t.Fatal("expected the EC2 turbo example machine")
	}
	if !turbo.hasTurbo() || !turbo.hasSuite(SuiteLzmaTurbo) || !turbo.hasSuite(SuiteSevenzTurbo) {
		t.Fatal("the turbo machine runs both turbo suites")
	}
	if turbo.Bundle.Source != BundleRelease || turbo.needsCandidate() {
		t.Fatal("the turbo machine stages the release like every other machine but runs no rarpar suite")
	}
	if turbo.Turbo.LzmaProfile != "fleet" || turbo.Turbo.SevenzProfile != "fleet" || turbo.Turbo.TimeoutMinutes != 60 {
		t.Fatalf("unexpected turbo plan: %+v", turbo.Turbo)
	}
	if !turbo.usesSSM() || !turbo.EC2.Spot {
		t.Fatal("the turbo example rides spot over SSM")
	}
	if float64(turbo.EC2.DeadmanMinutes) < turbo.EC2.MaxHours*60 {
		t.Fatal("the deadman must outlast the cost cap")
	}
	if config.Fleet.LzmaTurboPath == "" || config.Fleet.SevenzTurboPath == "" {
		t.Fatal("the example names both turbo checkouts")
	}
	packages := bootstrapPackages(turbo)
	for _, name := range []string{"build-essential", "cmake", "git", "curl", "xz-utils", "perl"} {
		if !contains(packages, name) {
			t.Fatalf("turbo hosts need %s; got %v", name, packages)
		}
	}
	if len(packages) != len(turboPackages) {
		t.Fatalf("turbo packages must not repeat: %v", packages)
	}
	key := buildKey(turbo)
	lzmaOnly := turbo
	lzmaOnly.Suites = []string{SuiteLzmaTurbo}
	if buildKey(lzmaOnly) == key {
		t.Fatal("bundles with different turbo suites carry different content and must not share a build")
	}
}

func TestTurboSectionIsPinnedAndComplete(t *testing.T) {
	config := loadExample(t)
	var turbo Machine
	for _, machine := range config.Machines {
		if machine.Name == "ec2-zen4-turbo" {
			turbo = machine
		}
	}
	layout := LayoutFor(turbo, "fleet-testrun")
	script := RunScript(turbo, config.Fleet.Defaults, "fleet-testrun", layout, nil)
	for _, expected := range []string{
		"https://static.rust-lang.org/rustup/archive/" + rustupVersion + "/$RUSTUP_TRIPLE/rustup-init",
		"RUSTUP_TRIPLE=x86_64-unknown-linux-gnu", "RUSTUP_TRIPLE=aarch64-unknown-linux-gnu",
		rustupSHA256X86, rustupSHA256ARM,
		sevenZipURL(sevenZipAssetX86), sevenZipURL(sevenZipAssetARM), sevenZipSHA256X86, sevenZipSHA256ARM,
		xzURL(), xzSHA256,
		"--profile minimal --default-toolchain none",
		"$BIN/$name.bundle", "$BIN/$name.commit", "turbo_checkout lzma-turbo", "turbo_checkout sevenz-turbo",
		"lzma-turbo-bench\" toolchain --repo \"$LZ\" --build",
		"cargo build --locked --release -p decode-bench",
		"--features native-crypto",
		"SEVENZ_BENCH_ORACLE_OFFICIAL=1",
		"LZMA_TURBO_XZ=", "LZMA_TURBO_7ZZ=",
		quoteAll([]string{"--profile", "fleet", "--timeout", "60m"}),
		"SEVENZ_BENCH_INSTANCE_TYPE=",
	} {
		if !strings.Contains(script, expected) {
			t.Fatalf("turbo script is missing %q", expected)
		}
	}
	for _, forbidden := range []string{"rustup-init.sh", "sh.rustup.rs", "curl | sh", "apt-get install -y 7zip", "p7zip"} {
		if strings.Contains(script, forbidden) {
			t.Fatalf("turbo script must not contain %q (unpinned install path)", forbidden)
		}
	}
	// The results land where the collector expects suite evidence.
	for _, dir := range []string{"$R/lzma-turbo", "$R/sevenz-turbo", "$R/turbo"} {
		if !strings.Contains(script, dir) {
			t.Fatalf("turbo script does not write to %s", dir)
		}
	}
}

func TestTurboPlanSteps(t *testing.T) {
	config := loadExample(t)
	machines, err := Select(config, []string{"ec2-zen4-turbo"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	plan := BuildPlan(config, machines, "fleet-testrun")
	steps := strings.Join(plan.Machines[0].Steps, "\n")
	for _, expected := range []string{"rustup " + rustupVersion, "7-Zip " + sevenZipVersion, "xz " + xzVersion,
		"lzma-turbo run, profile fleet", "sevenz-turbo run, profile fleet", "results/lzma-turbo", "results/sevenz-turbo"} {
		if !strings.Contains(steps, expected) {
			t.Fatalf("turbo plan steps are missing %q:\n%s", expected, steps)
		}
	}
}

func TestTurboConfigValidation(t *testing.T) {
	cases := []struct{ name, old, new, want string }{
		{"profile", `lzma_profile = "fleet"`, `lzma_profile = "huge"`, "turbo.lzma_profile must be one of"},
		{"timeout", "timeout_minutes = 60                     # per-case", "timeout_minutes = 0                     # per-case", "turbo.timeout_minutes must be positive"},
		{"path", `lzma_turbo_path = "/Users/example/dev/lzma-turbo"`, ``, "needs fleet.lzma_turbo_path"},
		{"relative", `lzma_turbo_path = "/Users/example/dev/lzma-turbo"`, `lzma_turbo_path = "dev/lzma-turbo"`, "must be an absolute path"},
		// The run script installs Linux rustup and 7-Zip builds, so a macOS
		// host would pass validation only to fail on the host.
		{"darwin", "flavor = \"gnu-direct\"\ngo_os = \"linux\"", "go_os = \"darwin\"", `bundle.go_os = "darwin" hosts are not supported`},
	}
	for _, tc := range cases {
		_, err := loadMutatedExample(t, tc.old, tc.new)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("%s: expected an error containing %q, got %v", tc.name, tc.want, err)
		}
	}
}

// A run's bundles carry only the turbo checkouts its selected machines use,
// so only those name the bundle and only those have to be checkouts.
func TestTurboTreeIDCoversOnlyTheSuitesInUse(t *testing.T) {
	toplevel, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		t.Skip("the test needs the git checkout it runs in")
	}
	repo := strings.TrimSpace(string(toplevel))
	head, err := exec.Command("git", "-C", repo, "rev-parse", "HEAD").Output()
	if err != nil {
		t.Fatal(err)
	}
	commit := strings.TrimSpace(string(head))
	ctx := context.Background()
	running := func(suites ...string) []Machine { return []Machine{{Name: "m", Suites: suites}} }
	settings := Settings{LzmaTurboPath: repo, SevenzTurboPath: filepath.Join(t.TempDir(), "not-a-checkout")}

	id, err := turboTreeID(ctx, settings, running(SuiteLzmaTurbo))
	if err != nil || id != "lzma-turbo="+commit {
		t.Fatalf("an lzma-turbo-only run must not read the sevenz-turbo path: id %q, err %v", id, err)
	}
	id, err = turboTreeID(ctx, settings, running(SuiteMacroPAR2))
	if err != nil || id != "" {
		t.Fatalf("a run without turbo suites names no turbo tree: id %q, err %v", id, err)
	}
	_, err = turboTreeID(ctx, settings, append(running(SuiteLzmaTurbo), running(SuiteSevenzTurbo)...))
	want := "sevenz-turbo: " + settings.SevenzTurboPath + " is not a git checkout"
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("a sevenz-turbo machine still needs its checkout: want %q, got %v", want, err)
	}
	// Both suites in use name the bundle as they always have.
	settings.SevenzTurboPath = repo
	id, err = turboTreeID(ctx, settings, running(SuiteSevenzTurbo, SuiteLzmaTurbo))
	if err != nil || id != "lzma-turbo="+commit+"|sevenz-turbo="+commit {
		t.Fatalf("both suites: id %q, err %v", id, err)
	}
}

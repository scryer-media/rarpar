package fleet

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/scryer-media/rarpar/bench/rarpar-bench/internal/par3bench"
)

const FleetPlanSchemaVersion = 1

// FleetPlan is what `fleet plan` prints and `fleet run` executes. Producing it
// is side-effect free, so an operator can read exactly what a run would do to
// their machines and their AWS account before anything is launched.
type FleetPlan struct {
	SchemaVersion int           `json:"schema_version"`
	RunID         string        `json:"run_id"`
	GeneratedUTC  string        `json:"generated_utc"`
	ConfigPath    string        `json:"config_path"`
	ConfigSHA256  string        `json:"config_sha256"`
	RunDir        string        `json:"run_dir"`
	Preflight     []string      `json:"preflight"`
	Machines      []MachinePlan `json:"machines"`
	Quota         QuotaCheck    `json:"quota,omitempty"`
	Warnings      []string      `json:"warnings,omitempty"`
}

type MachinePlan struct {
	Name          string                      `json:"name"`
	Kind          string                      `json:"kind"`
	PlatformLabel string                      `json:"platform_label"`
	BuildTarget   string                      `json:"build_target,omitempty"`
	Endpoint      string                      `json:"endpoint"`
	Auth          string                      `json:"auth"`
	Suites        []string                    `json:"suites"`
	Perf          string                      `json:"perf"`
	Bundle        Bundle                      `json:"bundle"`
	Release       *ReleasePlan                `json:"release,omitempty"`
	Oracles       map[string]OracleResolution `json:"oracles,omitempty"`
	Remote        RemoteLayout                `json:"remote"`
	Protocol      Protocol                    `json:"protocol"`
	Steps         []string                    `json:"steps"`
	Cloud         *CloudPlan                  `json:"cloud,omitempty"`
	PAR3          *PAR3View                   `json:"par3,omitempty"`
}

// ReleasePlan is the published release asset a release bundle will stage, and
// where it and the SHA256SUMS it is checked against come from.
type ReleasePlan struct {
	Tag        string `json:"tag"`
	Platform   string `json:"platform"`
	RustTarget string `json:"rust_target"`
	Asset      string `json:"asset"`
	Binary     string `json:"binary"`
	ReleaseURL string `json:"release_url"`
	AssetURL   string `json:"asset_url"`
	SumsURL    string `json:"sha256sums_url"`
}

// releasePlan describes a release bundle's asset; nil for any other bundle.
func releasePlan(bundle Bundle) *ReleasePlan {
	if bundle.Source != BundleRelease {
		return nil
	}
	platform, err := resolveReleasePlatform(bundle)
	if err != nil {
		return nil
	}
	tag := bundle.releaseTag()
	asset := releaseAssetName(tag, platform)
	return &ReleasePlan{
		Tag:        tag,
		Platform:   platform.Name,
		RustTarget: platform.RustTarget,
		Asset:      asset,
		Binary:     platform.Binary,
		ReleaseURL: releasePageURL(tag),
		AssetURL:   releaseAssetURL(tag, asset),
		SumsURL:    releaseAssetURL(tag, releaseSumsName),
	}
}

// PAR3View is the macro-par3 matrix one machine will run.
type PAR3View struct {
	Work     string   `json:"work"`
	Args     []string `json:"args"`
	Configs  []string `json:"configs"`
	Variants []string `json:"variants"`
	// Rows lists, per op, the rows each set produces: the reference, one
	// buffered rarpar row per worker count and kernel variant, and at repair
	// one rarpar-wN-backup row per worker count. The rarpar rows repair in
	// place with no backup; the -backup rows keep a numbered .1 as the
	// reference does, like for like on bytes written.
	Rows map[string][]string `json:"rows"`
	// Warnings are reference work-path warnings: the run goes ahead and a
	// reference that fails is recorded as DNF.
	Warnings []string `json:"warnings,omitempty"`
}

type Protocol struct {
	WarmupPass   bool     `json:"warmup_pass"`
	Warmups      int      `json:"warmups"`
	Repeats      int      `json:"repeats"`
	Families     []string `json:"families,omitempty"`
	Cases        []string `json:"cases,omitempty"`
	QuietLoadMax float64  `json:"quiet_load_threshold"`
	PerfStat     int      `json:"perf_stat_repeats,omitempty"`
	// PerfRecord are the corpus cases perf record (or samply) profiles; set
	// only when a corpus suite runs, since the record loop runs only then.
	PerfRecord    []string `json:"perf_record_cases,omitempty"`
	PerfFrequency int      `json:"perf_record_frequency,omitempty"`
	// PerfPAR3Ops and PerfPAR3RecordSets are the macro-par3 perf pass on a
	// linux-perf host: perf stat PerfStat times on every reference and rarpar
	// row of these ops, perf record on the rarpar rows of these sets.
	PerfPAR3Ops        []string `json:"perf_par3_ops,omitempty"`
	PerfPAR3RecordSets []string `json:"perf_par3_record_sets,omitempty"`
}

type CloudPlan struct {
	Access         string   `json:"access"`
	Spot           bool     `json:"spot,omitempty"`
	InstanceType   string   `json:"instance_type"`
	Region         string   `json:"region"`
	AMI            string   `json:"ami"`
	VCPUs          int      `json:"vcpus"`
	VolumeGB       int      `json:"volume_gb"`
	DeadmanMinutes int      `json:"deadman_minutes"`
	MaxHours       float64  `json:"max_hours"`
	MaxUSD         float64  `json:"max_usd"`
	Teardown       []string `json:"teardown"`
}

// BuildPlan derives the executable plan. runID is stable for a given run so
// `fleet plan` and the `fleet run` that follows describe the same directories.
func BuildPlan(config Config, machines []Machine, runID string) FleetPlan {
	runDir := joinLocal(config.Fleet.ResultsRoot, runID)
	plan := FleetPlan{
		SchemaVersion: FleetPlanSchemaVersion,
		RunID:         runID,
		GeneratedUTC:  time.Now().UTC().Format(time.RFC3339),
		ConfigPath:    config.Path,
		ConfigSHA256:  config.SHA256,
		RunDir:        runDir,
	}

	cloud, cloudSSH, cloudSSM, release := false, false, false, false
	for _, machine := range machines {
		if machine.Bundle.Source == BundleRelease {
			release = true
		}
		if machine.Kind == KindAWSEC2 {
			cloud = true
			if machine.usesSSM() {
				cloudSSM = true
			} else {
				cloudSSH = true
			}
		}
	}
	if release {
		// The candidates are fixed before anything else runs: a release
		// without the asset or its SHA256SUMS, or a hash mismatch, stops
		// the round here.
		plan.Preflight = append(plan.Preflight,
			"rarpar release assets and their SHA256SUMS downloaded from "+releaseBaseURL+", each asset's sha256 checked against SHA256SUMS, before any credential check, host probe or launch")
	}
	if cloud {
		// Credentials before anything is built or launched, always: an
		// expired session discovered after the first launch is how a fleet
		// strands paid instances.
		plan.Preflight = append(plan.Preflight,
			"AWS credential check (sts get-caller-identity) before anything is built or launched",
			fmt.Sprintf("vCPU quota arithmetic per launch wave against fleet.aws.total_vcpu_quota (%d), held machines charged against every later wave", config.Fleet.AWS.TotalVCPUQuota))
		if cloudSSH {
			plan.Preflight = append(plan.Preflight,
				"public IPv4 discovery by DNS for the session security group (HTTP echo services are blocked here)")
		}
		if cloudSSM {
			plan.Preflight = append(plan.Preflight,
				"SSM transfer bucket (s3api head-bucket) and instance profiles (iam get-instance-profile), read-only")
		}
	}
	plan.Preflight = append(plan.Preflight,
		"config validation (schema, paths, oracle policy, deadman vs cost cap)",
		"reachability probe of every local-ssh host over its own configured endpoint",
		"oracle artifacts present and sha256-verified, or fetched now")

	for _, machine := range machines {
		// Windows hosts stage under backslash paths and run a .ps1; the plan
		// must show the paths the runner will actually use.
		layout := HostLayout(machine, runID)
		item := MachinePlan{
			Name:          machine.Name,
			Kind:          machine.Kind,
			PlatformLabel: machine.PlatformLabel,
			BuildTarget:   machine.BuildTarget,
			Endpoint:      endpointOf(machine),
			Auth:          machine.Connection.Auth,
			Suites:        machine.Suites,
			Perf:          machine.Capabilities.Perf,
			Bundle:        machine.Bundle,
			Release:       releasePlan(machine.Bundle),
			Remote:        layout,
			Protocol: Protocol{
				WarmupPass:   machine.Run.WarmupPass(),
				Warmups:      machine.Run.Warmups,
				Repeats:      machine.Run.Repeats,
				Families:     machine.families(),
				Cases:        machine.Run.Cases,
				QuietLoadMax: machine.Run.QuietLoadThreshold,
			},
		}
		if machine.Capabilities.Perf != PerfNone {
			item.Protocol.PerfStat = machine.Perf.StatRepeats
			if len(machine.families()) > 0 {
				item.Protocol.PerfRecord = machine.Perf.RecordCases
			}
			item.Protocol.PerfFrequency = machine.Perf.RecordFrequency
			if ops := machine.par3PerfOps(); len(ops) > 0 {
				item.Protocol.PerfPAR3Ops = ops
				item.Protocol.PerfPAR3RecordSets = machine.Perf.PAR3RecordSets
			}
		}
		item.Oracles = map[string]OracleResolution{}
		for _, role := range sortedKeys(machine.Oracles) {
			oracle := machine.Oracles[role]
			resolution := OracleResolution{Role: role, Policy: oracle.Policy}
			switch oracle.Policy {
			case OracleHostPath:
				resolution.RemotePath = oracle.Path
				resolution.Origin = "preinstalled on the host"
			case OracleOfficialBinary:
				resolution.RemotePath = hostJoin(machine, layout.Bin, oracleBinaryName(machine, role, oracle))
				resolution.Origin = "official release asset " + oracle.URL
				resolution.SHA256 = oracle.SHA256
			case OracleSourceBuild:
				resolution = sourceBuildResolution(machine, role, oracle, layout)
			}
			item.Oracles[role] = resolution
		}

		if machine.usesSSM() {
			item.Auth = "ssm (instance profile " + machine.EC2.InstanceProfile + ")"
		}
		item.Steps = machineSteps(machine, layout)
		if machine.hasSuite(SuiteMacroPAR3) {
			view, problem := par3View(machine, layout)
			item.PAR3 = view
			if problem != "" {
				plan.Warnings = append(plan.Warnings, fmt.Sprintf("machine %s: %s; fleet run would refuse to start", machine.Name, problem))
			}
			for _, warning := range view.Warnings {
				plan.Warnings = append(plan.Warnings, fmt.Sprintf("machine %s: par3 work path: %s", machine.Name, warning))
			}
		}
		if machine.Kind == KindAWSEC2 && machine.EC2 != nil {
			teardown := []string{
				"terminate-instances then wait instance-terminated",
				"verify instance state, root volume deleted (DeleteOnTermination), no attached volumes, no ENIs",
				"session security group and keypair deleted after the last cloud host, then verified NotFound",
			}
			if machine.usesSSM() {
				teardown[2] = "transfer objects under s3://" + config.Fleet.AWS.SSMBucket + "/" + ssmPrefix(config.Fleet.AWS.ResourcePrefix, runID, machine.Name) + " are deleted after each transfer"
			}
			item.Cloud = &CloudPlan{
				Access:         machine.EC2.Access,
				Spot:           machine.EC2.Spot,
				InstanceType:   machine.EC2.InstanceType,
				Region:         machine.EC2.Region,
				AMI:            machine.EC2.AMI,
				VCPUs:          machine.EC2.VCPUs,
				VolumeGB:       machine.EC2.VolumeGB,
				DeadmanMinutes: machine.EC2.DeadmanMinutes,
				MaxHours:       machine.EC2.MaxHours,
				MaxUSD:         roundCents(machine.EC2.HourlyUSD * machine.EC2.MaxHours),
				Teardown:       teardown,
			}
		}
		if machine.Bundle.Source == BundlePrebuilt {
			plan.Warnings = append(plan.Warnings,
				fmt.Sprintf("machine %s stages a prebuilt bundle from %s: a dev spot test, not the published release artifacts", machine.Name, machine.Bundle.Path))
		}
		if machine.isWindows() {
			plan.Warnings = append(plan.Warnings,
				fmt.Sprintf("machine %s is a Windows host: UNVALIDATED, the Windows transport (scp + PowerShell, no sh or tar) has never run live; treat this run as bring-up. The runner uploads and executes a .ps1 and perf is unavailable", machine.Name))
		}
		plan.Machines = append(plan.Machines, item)
	}
	plan.Quota = ComputeQuota(config, machines)
	if cloud && !plan.Quota.Fits {
		for _, wave := range plan.Quota.Waves {
			if !wave.Fits {
				plan.Warnings = append(plan.Warnings,
					fmt.Sprintf("QUOTA: wave %d needs %d vCPUs but the configured quota is %d; fleet run would refuse to launch",
						wave.Wave, wave.Requested, plan.Quota.Quota))
			}
		}
	}
	return plan
}

// bundleStep is the first step of every machine: what its bundle holds.
func bundleStep(bundle Bundle) string {
	if release := releasePlan(bundle); release != nil {
		return fmt.Sprintf("assemble bundle (release %s: the verified %s from %s, Go harness cross-compiled here) and write BUILDINFO.json",
			release.Tag, release.Binary, release.Asset)
	}
	return fmt.Sprintf("assemble bundle (%s from %s, a dev spot test) and write BUILDINFO.json", bundle.Source, bundle.Path)
}

func machineSteps(machine Machine, layout RemoteLayout) []string {
	steps := []string{bundleStep(machine.Bundle)}
	switch {
	case machine.usesSSM():
		market := "on-demand"
		if machine.EC2.Spot {
			market = "one-time spot (terminate on interruption)"
		}
		steps = append(steps,
			fmt.Sprintf("launch %s EC2 instance with instance profile %s, no keypair and no inbound rule, DeleteOnTermination and the deadman shutdown", market, machine.EC2.InstanceProfile),
			"wait for the SSM agent to report Online, then for user-data (aws-cli) to finish")
	case machine.Kind == KindAWSEC2:
		steps = append(steps,
			"launch EC2 instance with the session security group, ephemeral keypair, DeleteOnTermination and the deadman shutdown",
			"wait for SSH over the multiplexed control master")
	default:
		steps = append(steps, "probe reachability and prepare "+layout.Base)
	}
	channel := "tar-over-ssh"
	switch {
	case machine.usesSSM():
		channel = "S3 (tar object, fetched by SSM RunCommand)"
	case machine.isWindows():
		channel = "scp (local zip, unpacked by Expand-Archive over PowerShell -EncodedCommand)"
	}
	steps = append(steps,
		"upload bundle by "+channel+" to "+layout.Bin,
		"upload the generated run script to "+layout.Script,
		startStep(machine))
	if oracle, ok := machine.Oracles["rar"]; ok && oracle.Policy == OracleSourceBuild && oracle.Recipe == RecipeUnrarHost {
		steps = append(steps, "on host: build the UnRAR oracle from the shipped, sha256-pinned source (stock makefile, CXXFLAGS and LDFLAGS, CXX=g++, no -march/-mcpu/-mtune; refused if the makefile carries one or the binary does not start)")
	}
	steps = append(steps, "on host: quiet-load gate")
	if len(machine.families()) > 0 {
		if machine.Run.WarmupPass() {
			steps = append(steps, "on host: warmup pass (evidence discarded)")
		}
		steps = append(steps, fmt.Sprintf("on host: timed pass, warmups=%d repeats=%d", machine.Run.Warmups, machine.Run.Repeats))
	}
	if machine.hasSuite(SuiteMacroPAR3) {
		if oracle, ok := machine.Oracles["par3"]; ok && oracle.Recipe == RecipePAR3CmdlineHost {
			steps = append(steps, "on host: build the par3cmdline reference from the toolchains.json pin (cmake, Release)")
		}
		timeout := fmt.Sprintf("%dm per-run timeout", machine.PAR3.TimeoutMinutes)
		if machine.PAR3.ReferenceTimeoutMinutes > 0 {
			timeout += fmt.Sprintf(" (reference %dm)", machine.PAR3.ReferenceTimeoutMinutes)
		}
		steps = append(steps, fmt.Sprintf("on host: macro-par3, profile %s, workers %v, buffered rarpar rows only (never --fsync): per worker count rarpar-wN for every op, repairing in place with no backup, and the repair row rarpar-wN-backup, which keeps a numbered .1 as the reference does (like for like on bytes written); warmups=%d repeats=%d, %s, reference failures are DNF, work %s",
			machine.PAR3.Profile, machine.PAR3.Workers, machine.PAR3.Warmups, machine.PAR3.Repeats,
			timeout, PAR3Work(machine, layout)))
		if step := par3PerfStep(machine); step != "" {
			steps = append(steps, step)
		}
		if machine.PAR3.Versus != "" {
			steps = append(steps, fmt.Sprintf("on host: par3 versus, profile %s: PAR2 (rarpar par, plus the par2 oracle when present) against PAR3 Cauchy and FFT, each PAR3 repair in place and as a -backup twin that keeps a .1, par2 ÷ par3, every repair SHA-256 checked",
				machine.PAR3.Versus))
		}
	}
	if machine.hasTurbo() {
		steps = append(steps,
			fmt.Sprintf("on host: install rustup %s (pinned digest) with no default toolchain; each checkout's rust-toolchain.toml installs its own", rustupVersion),
			fmt.Sprintf("on host: fetch the official 7-Zip %s release (pinned digest) as the 7zz oracle", sevenZipVersion))
	}
	if machine.hasSuite(SuiteLzmaTurbo) {
		steps = append(steps,
			"on host: clone lzma-turbo from the shipped git bundle, verify the commit, cargo build --locked lzma-bench",
			fmt.Sprintf("on host: build xz %s (pinned digest, static) as the xz oracle, generate the lzma fixtures", xzVersion),
			fmt.Sprintf("on host: lzma-turbo run, profile %s%s, %dm per-case timeout, results under results/lzma-turbo",
				machine.Turbo.LzmaProfile, turboOnlyNote(machine.Turbo.LzmaOnly, machine.Turbo.LzmaRepeats), machine.Turbo.TimeoutMinutes))
	}
	if machine.hasSuite(SuiteSevenzTurbo) {
		steps = append(steps,
			"on host: clone sevenz-turbo from the shipped git bundle, verify the commit, cargo build --locked decode-bench (aws-lc-rs and native-crypto)",
			fmt.Sprintf("on host: generate the %s sevenz fixture corpus with the official 7zz", turboCorpus(machine.Turbo.SevenzProfile)),
			fmt.Sprintf("on host: sevenz-turbo run, profile %s%s, %dm per-case timeout, results under results/sevenz-turbo",
				machine.Turbo.SevenzProfile, turboOnlyNote(machine.Turbo.SevenzOnly, machine.Turbo.SevenzRepeats), machine.Turbo.TimeoutMinutes))
	}
	steps = append(steps, perfStep(machine))
	steps = append(steps,
		"on host: "+remoteBase(layout.Tarball)+" + MANIFEST.json inventory + DONE sentinel",
		"orchestrator: poll for DONE, pull "+remoteBase(layout.Tarball)+", verify the manifest digests")
	if machine.Kind == KindAWSEC2 {
		steps = append(steps, "orchestrator: terminate and verify teardown resource-by-resource")
	} else if machine.Paths.Cleanup {
		steps = append(steps, "orchestrator: clean the host staging directory")
	}
	steps = append(steps, "orchestrator: render SVGs for "+machine.PlatformLabel+" and fold into the fleet summary")
	return steps
}

// par3PerfStep is the macro-par3 perf pass, which runs inside par3 run,
// naming the sets and rows it covers, or "" when the machine runs none (or
// its matrix does not resolve, which blocks the run anyway).
func par3PerfStep(machine Machine) string {
	ops := machine.par3PerfOps()
	if len(ops) == 0 {
		return ""
	}
	profile, err := par3bench.LookupProfile(machine.PAR3.Profile)
	if err == nil {
		profile, err = profile.Select(machine.PAR3.Sets)
	}
	if err != nil {
		return ""
	}
	var kernels []par3bench.KernelVariant
	for _, text := range machine.PAR3.KernelVariants {
		if variant, err := par3bench.ParseKernelVariant(text); err == nil {
			kernels = append(kernels, variant)
		}
	}
	variants := par3bench.Variants(machine.PAR3.Workers, kernels)
	rows := par3bench.RowsByOp(variants, ops)
	var plain, stat []string
	for _, config := range profile.Configs {
		if config.Carrier == "" {
			plain = append(plain, config.ID)
		}
	}
	for _, op := range ops {
		stat = append(stat, fmt.Sprintf("each %s row (%s)", op, strings.Join(rows[op], ",")))
	}
	step := fmt.Sprintf("on host: macro-par3 perf pass inside par3 run (untimed, after each op's timed runs) on the plain sets %s: perf stat x%d of %s, each run on a fresh stage",
		strings.Join(plain, ","), machine.Perf.StatRepeats, strings.Join(stat, " and "))
	if sets := machine.Perf.PAR3RecordSets; len(sets) > 0 {
		step += fmt.Sprintf("; on %s, one perf record -F %d with frame-pointer call graphs of each rarpar row, exported as perf script text and folded stacks",
			strings.Join(sets, ","), machine.Perf.RecordFrequency)
	} else {
		step += "; no perf record (perf.par3_record_sets is empty)"
	}
	perf := par3bench.PerfOptions{StatRepeats: machine.Perf.StatRepeats, Ops: ops, RecordSets: machine.Perf.PAR3RecordSets}
	return step + fmt.Sprintf("; up to %d untimed runs; evidence under results/perf/par3, and %s plus a par3-perf-incomplete warning when the pass falls short",
		par3bench.PerfPassRuns(profile, variants, perf), par3bench.PerfIncompleteFile)
}

// perfStep is the run script's perf section: the corpus suites' perf pass,
// or only the collector's version when no corpus suite runs here.
func perfStep(machine Machine) string {
	families := machine.families()
	cases := strings.Join(machine.Perf.RecordCases, ",")
	switch machine.Capabilities.Perf {
	case PerfLinux:
		if len(families) == 0 {
			return "on host: record perf --version and kernel.perf_event_paranoid (no corpus suite runs here: no harness --perf pass, no perf record of corpus cases)"
		}
		record := "perf record/script/folded on " + cases
		if cases == "" {
			record = "no perf record (perf.record_cases is empty)"
		}
		return fmt.Sprintf("on host: perf diagnostic pass on the %s cases (harness --perf counters for both subjects, x%d per case; %s)",
			strings.Join(families, ","), machine.Perf.StatRepeats, record)
	case PerfSamply:
		switch {
		case len(families) == 0:
			return "on host: record samply --version (no corpus suite runs here, so nothing is profiled)"
		case cases == "":
			return "on host: record samply --version (perf.record_cases is empty, so nothing is profiled)"
		}
		return "on host: samply diagnostic pass on " + cases
	default:
		return "on host: no sampling collector; harness phase timings only"
	}
}

// perfLine is the plan's account of what the perf pass runs, per suite; it
// names only what the run script does.
func perfLine(machine MachinePlan) string {
	protocol := machine.Protocol
	switch machine.Perf {
	case PerfLinux:
		var parts []string
		if len(protocol.Families) > 0 {
			record := "no perf record"
			if len(protocol.PerfRecord) > 0 {
				record = fmt.Sprintf("record -F %d on %s", protocol.PerfFrequency, strings.Join(protocol.PerfRecord, ","))
			}
			parts = append(parts, fmt.Sprintf("%s: stat repeats=%d per case, %s", strings.Join(protocol.Families, ","), protocol.PerfStat, record))
		}
		if len(protocol.PerfPAR3Ops) > 0 {
			record := "no perf record"
			if len(protocol.PerfPAR3RecordSets) > 0 {
				record = fmt.Sprintf("record -F %d on the rarpar rows of %s", protocol.PerfFrequency, strings.Join(protocol.PerfPAR3RecordSets, ","))
			}
			parts = append(parts, fmt.Sprintf("macro-par3: stat repeats=%d on the reference and rarpar rows of %s, %s",
				protocol.PerfStat, strings.Join(protocol.PerfPAR3Ops, ","), record))
		} else if contains(machine.Suites, SuiteMacroPAR3) {
			parts = append(parts, "macro-par3: off (perf.par3_ops is empty)")
		}
		if len(parts) == 0 {
			return PerfLinux + " (version and perf_event_paranoid only: no selected suite runs under perf)"
		}
		return PerfLinux + " (" + strings.Join(parts, "; ") + ")"
	case PerfSamply:
		if len(protocol.Families) > 0 && len(protocol.PerfRecord) > 0 {
			return fmt.Sprintf("%s (record --rate %d on %s)", PerfSamply, protocol.PerfFrequency, strings.Join(protocol.PerfRecord, ","))
		}
		return PerfSamply + " (version only: no designated corpus case runs here)"
	default:
		return machine.Perf
	}
}

// par3View resolves the macro-par3 matrix and checks the work path against the
// reference's name-buffer limit. A non-empty problem (a matrix that does not
// resolve) blocks the run; an over-long work path is only a warning, because
// the suite records a failing reference as DNF and still runs every rarpar
// row.
func par3View(machine Machine, layout RemoteLayout) (*PAR3View, string) {
	work := PAR3Work(machine, layout)
	view := &PAR3View{Work: work, Args: par3Args(machine)}
	profile, err := par3bench.LookupProfile(machine.PAR3.Profile)
	if err == nil {
		profile, err = profile.Select(machine.PAR3.Sets)
	}
	if err != nil {
		return view, "par3: " + err.Error()
	}
	view.Configs = profile.ConfigIDs()
	var variants []par3bench.KernelVariant
	for _, text := range machine.PAR3.KernelVariants {
		variant, err := par3bench.ParseKernelVariant(text)
		if err != nil {
			return view, "par3: " + err.Error()
		}
		variants = append(variants, variant)
	}
	all := par3bench.Variants(machine.PAR3.Workers, variants)
	for _, variant := range all {
		view.Variants = append(view.Variants, variant.Name)
	}
	ops := machine.PAR3.Ops
	if len(ops) == 0 {
		ops = par3bench.DefaultOps
	}
	view.Rows = par3bench.RowsByOp(all, ops)
	view.Warnings = par3bench.WorkPathWarnings(profile, work)
	return view, ""
}

func startStep(machine Machine) string {
	if machine.isWindows() {
		return "start it detached (Win32_Process.Create runs the uploaded .ps1 FILE outside the SSH session, never an inline command string); evidence returns as results.zip by scp"
	}
	return "start it detached (nohup/setsid); the orchestrator stops interacting with the host"
}

func endpointOf(machine Machine) string {
	if machine.usesSSM() {
		return fmt.Sprintf("ssm:<launched %s in %s>", machine.EC2.InstanceType, machine.EC2.Region)
	}
	if machine.Kind == KindAWSEC2 {
		return fmt.Sprintf("%s@<launched %s in %s>", machine.Connection.User, machine.EC2.InstanceType, machine.EC2.Region)
	}
	return fmt.Sprintf("%s@%s:%d", machine.Connection.User, machine.Connection.Host, machine.Connection.Port)
}

// WritePlanText renders the operator-facing dry run.
func WritePlanText(writer io.Writer, plan FleetPlan) {
	fmt.Fprintf(writer, "fleet plan %s\n", plan.RunID)
	fmt.Fprintf(writer, "  config      %s (sha256 %s)\n", plan.ConfigPath, short(plan.ConfigSHA256))
	fmt.Fprintf(writer, "  run dir     %s\n", plan.RunDir)
	fmt.Fprintf(writer, "  machines    %d, launched in parallel\n\n", len(plan.Machines))

	fmt.Fprintln(writer, "PREFLIGHT (fail-fast, no interaction after start)")
	for _, check := range plan.Preflight {
		fmt.Fprintf(writer, "  - %s\n", check)
	}
	fmt.Fprintln(writer)

	for _, machine := range plan.Machines {
		fmt.Fprintf(writer, "MACHINE %s  [%s]  platform=%s\n", machine.Name, machine.Kind, machine.PlatformLabel)
		fmt.Fprintf(writer, "  endpoint   %s (auth %s)\n", machine.Endpoint, machine.Auth)
		fmt.Fprintf(writer, "  suites     %s\n", strings.Join(machine.Suites, ", "))
		if release := machine.Release; release != nil {
			fmt.Fprintf(writer, "  bundle     release %s, asset %s (%s)\n", release.Tag, release.Asset, release.RustTarget)
			fmt.Fprintf(writer, "             sha256 checked against %s before any launch\n", release.SumsURL)
		} else {
			fmt.Fprintf(writer, "  bundle     %s from %s (dev spot test, not a published release artifact)\n", machine.Bundle.Source, machine.Bundle.Path)
		}
		protocol := machine.Protocol
		fmt.Fprintf(writer, "  protocol   warmup_pass=%t warmups=%d repeats=%d load<%s\n",
			protocol.WarmupPass, protocol.Warmups, protocol.Repeats, trimFloat(protocol.QuietLoadMax))
		if len(protocol.Families) > 0 {
			fmt.Fprintf(writer, "             families=%s", strings.Join(protocol.Families, ","))
			if len(protocol.Cases) > 0 {
				fmt.Fprintf(writer, " cases=%s", strings.Join(protocol.Cases, ","))
			}
			fmt.Fprintln(writer)
		}
		fmt.Fprintf(writer, "  perf       %s\n", perfLine(machine))
		for _, role := range sortedKeys(machine.Oracles) {
			oracle := machine.Oracles[role]
			fmt.Fprintf(writer, "  oracle %-4s %s -> %s\n", role, oracle.Policy, oracle.RemotePath)
			fmt.Fprintf(writer, "             %s\n", oracle.Origin)
			if oracle.Note != "" {
				fmt.Fprintf(writer, "             reason: %s\n", oracle.Note)
			}
		}
		if machine.PAR3 != nil {
			fmt.Fprintf(writer, "  par3       %s\n", strings.Join(machine.PAR3.Configs, ","))
			fmt.Fprintf(writer, "             variants=%s work=%s\n", strings.Join(machine.PAR3.Variants, ","), machine.PAR3.Work)
			for _, op := range par3bench.KnownOps {
				if rows, ok := machine.PAR3.Rows[op]; ok {
					fmt.Fprintf(writer, "             %-14s %s\n", op+":", strings.Join(rows, ","))
				}
			}
		}
		fmt.Fprintf(writer, "  remote     %s\n", machine.Remote.Base)
		if machine.Cloud != nil {
			cloud := machine.Cloud
			fmt.Fprintf(writer, "  ec2        %s %s ami=%s vcpus=%d disk=%dGiB access=%s spot=%t\n",
				cloud.InstanceType, cloud.Region, cloud.AMI, cloud.VCPUs, cloud.VolumeGB, cloud.Access, cloud.Spot)
			fmt.Fprintf(writer, "             deadman=%dmin cost cap=%.2fh (max $%.2f)\n",
				cloud.DeadmanMinutes, cloud.MaxHours, cloud.MaxUSD)
			for _, step := range cloud.Teardown {
				fmt.Fprintf(writer, "             teardown: %s\n", step)
			}
		}
		fmt.Fprintln(writer, "  steps")
		for index, step := range machine.Steps {
			fmt.Fprintf(writer, "    %2d. %s\n", index+1, step)
		}
		fmt.Fprintln(writer)
	}

	if len(plan.Quota.Instances) > 0 {
		fmt.Fprintln(writer, "AWS QUOTA AND COST")
		fmt.Fprintf(writer, "  region %s, quota %d vCPU\n", plan.Quota.Region, plan.Quota.Quota)
		for _, instance := range plan.Quota.Instances {
			fmt.Fprintf(writer, "  %-16s %-12s wave %d  %2d vCPU  cap %.2fh  max $%.2f\n",
				instance.Machine, instance.InstanceType, instance.Wave, instance.VCPUs, instance.MaxHours, instance.MaxUSD)
		}
		if len(plan.Quota.Waves) > 1 {
			for _, wave := range plan.Quota.Waves {
				verdict := "FITS"
				if !wave.Fits {
					verdict = "DOES NOT FIT"
				}
				fmt.Fprintf(writer, "  wave %d: %d vCPU of %d (%s)\n", wave.Wave, wave.Requested, plan.Quota.Quota, verdict)
			}
			fmt.Fprintf(writer, "  total %d vCPU across %d sequential waves, worst-case spend $%.2f\n\n",
				plan.Quota.Requested, len(plan.Quota.Waves), plan.Quota.EstimatedUSD)
		} else {
			verdict := "FITS"
			if !plan.Quota.Fits {
				verdict = "DOES NOT FIT"
			}
			fmt.Fprintf(writer, "  total %d vCPU of %d (%s), worst-case spend $%.2f\n\n",
				plan.Quota.Requested, plan.Quota.Quota, verdict, plan.Quota.EstimatedUSD)
		}
	}

	if len(plan.Warnings) > 0 {
		fmt.Fprintln(writer, "WARNINGS")
		for _, warning := range plan.Warnings {
			fmt.Fprintf(writer, "  ! %s\n", warning)
		}
	}
}

func short(value string) string {
	if len(value) <= 12 {
		return value
	}
	return value[:12]
}

func joinLocal(parts ...string) string {
	cleaned := make([]string, 0, len(parts))
	for _, part := range parts {
		if part != "" {
			cleaned = append(cleaned, strings.TrimSuffix(part, "/"))
		}
	}
	return strings.Join(cleaned, "/")
}

// turboOnlyNote renders a turbo suite's scenario filter and repeat override
// for the plan.
func turboOnlyNote(only []string, repeats int) string {
	note := ""
	if len(only) > 0 {
		note += ", only " + strings.Join(only, "+")
	}
	if repeats > 0 {
		note += fmt.Sprintf(", repeats=%d", repeats)
	}
	return note
}

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
	Oracles       map[string]OracleResolution `json:"oracles,omitempty"`
	Remote        RemoteLayout                `json:"remote"`
	Protocol      Protocol                    `json:"protocol"`
	Steps         []string                    `json:"steps"`
	Cloud         *CloudPlan                  `json:"cloud,omitempty"`
	PAR3          *PAR3View                   `json:"par3,omitempty"`
}

// PAR3View is the macro-par3 matrix one machine will run.
type PAR3View struct {
	Work     string   `json:"work"`
	Args     []string `json:"args"`
	Configs  []string `json:"configs"`
	Variants []string `json:"variants"`
	// Rows lists, per op, the rows each set produces: rarpar's create and
	// repair rows come in durable (default) and buffered pairs.
	Rows map[string][]string `json:"rows"`
	// Warnings are reference work-path warnings: the run goes ahead and a
	// reference that fails is recorded as DNF.
	Warnings []string `json:"warnings,omitempty"`
}

type Protocol struct {
	WarmupPass    bool     `json:"warmup_pass"`
	Warmups       int      `json:"warmups"`
	Repeats       int      `json:"repeats"`
	Families      []string `json:"families,omitempty"`
	Cases         []string `json:"cases,omitempty"`
	QuietLoadMax  float64  `json:"quiet_load_threshold"`
	PerfStat      int      `json:"perf_stat_repeats,omitempty"`
	PerfRecord    []string `json:"perf_record_cases,omitempty"`
	PerfFrequency int      `json:"perf_record_frequency,omitempty"`
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

	cloud, cloudSSH, cloudSSM := false, false, false
	for _, machine := range machines {
		if machine.Kind == KindAWSEC2 {
			cloud = true
			if machine.usesSSM() {
				cloudSSM = true
			} else {
				cloudSSH = true
			}
		}
	}
	if cloud {
		// Credentials first, always: an expired session discovered after the
		// first launch is how a fleet strands paid instances.
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
			item.Protocol.PerfRecord = machine.Perf.RecordCases
			item.Protocol.PerfFrequency = machine.Perf.RecordFrequency
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

func machineSteps(machine Machine, layout RemoteLayout) []string {
	steps := []string{
		fmt.Sprintf("assemble bundle (%s) and write BUILDINFO.json", machine.Bundle.Source),
	}
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
		steps = append(steps, fmt.Sprintf("on host: macro-par3, profile %s, workers %v, rarpar create/repair %s (verify runs once), warmups=%d repeats=%d, %s, reference failures are DNF, work %s",
			machine.PAR3.Profile, machine.PAR3.Workers, strings.Join(par3Durabilities(machine), "+"), machine.PAR3.Warmups, machine.PAR3.Repeats,
			timeout, PAR3Work(machine, layout)))
	}
	switch machine.Capabilities.Perf {
	case PerfLinux:
		steps = append(steps, "on host: perf diagnostic pass (harness --perf counters for both subjects, plus perf record/script/folded on the designated cases)")
	case PerfSamply:
		steps = append(steps, "on host: samply diagnostic pass on the designated cases")
	default:
		steps = append(steps, "on host: no sampling collector; harness phase timings only")
	}
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
	durabilities, err := par3bench.ParseDurabilities(strings.Join(machine.PAR3.Durability, ","))
	if err != nil {
		return view, "par3: " + err.Error()
	}
	all := par3bench.Variants(machine.PAR3.Workers, variants, durabilities)
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

func par3Durabilities(machine Machine) []string {
	durabilities, err := par3bench.ParseDurabilities(strings.Join(machine.PAR3.Durability, ","))
	if err != nil {
		return machine.PAR3.Durability
	}
	return durabilities
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
		fmt.Fprintf(writer, "  bundle     %s", machine.Bundle.Source)
		if machine.Bundle.Source == BundlePrebuilt {
			fmt.Fprintf(writer, " from %s", machine.Bundle.Path)
		} else {
			fmt.Fprintf(writer, " %s target=%s on %s", machine.Bundle.Image, machine.Bundle.RustTarget, machine.Bundle.BuildHost)
		}
		fmt.Fprintln(writer)
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
		fmt.Fprintf(writer, "  perf       %s", machine.Perf)
		if machine.Perf != PerfNone {
			fmt.Fprintf(writer, " (stat repeats=%d, record -F %d on %s)",
				protocol.PerfStat, protocol.PerfFrequency, orNone(strings.Join(protocol.PerfRecord, ",")))
		}
		fmt.Fprintln(writer)
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

func orNone(value string) string {
	if value == "" {
		return "(none)"
	}
	return value
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

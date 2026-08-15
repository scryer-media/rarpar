package fleet

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/scryer-media/rarpar/bench/rarpar-bench/internal/oci"
)

// Options drive `fleet run` and `fleet collect --resume`.
type Options struct {
	Config     Config
	Machines   []Machine
	RunID      string
	DryRunAWS  bool
	AllowFetch bool
	Resume     bool
	SkipRender bool
	// Hold names machines whose cloud host must survive collection instead of
	// being terminated with it. Nothing else changes: the evidence is collected
	// and verified exactly as always, only the terminate is deferred to
	// `fleet teardown --run-id`.
	Hold []string
	Log  io.Writer
}

// holds reports whether this machine was named by --hold.
func (orch *orchestrator) holds(name string) bool {
	for _, held := range orch.options.Hold {
		if held == name {
			return true
		}
	}
	return false
}

type orchestrator struct {
	options   Options
	state     *RunState
	runDir    string
	aws       *AWS
	session   *SessionResources
	sessionMu sync.Mutex
	logMu     sync.Mutex
	// ECR pull tokens by region, minted once and reused across machines.
	// Tokens live 12 hours, comfortably past any allowed round length.
	ecrTokens   map[string]string
	ecrTokensMu sync.Mutex
}

// ecrToken returns a cached pull token for the image's registry region,
// minting it on first use.
func (orch *orchestrator) ecrToken(ctx context.Context, image string) (string, error) {
	ref, err := oci.ParseImageRef(image)
	if err != nil {
		return "", err
	}
	region, err := oci.ECRRegion(ref.Registry)
	if err != nil {
		return "", err
	}
	orch.ecrTokensMu.Lock()
	defer orch.ecrTokensMu.Unlock()
	if token, ok := orch.ecrTokens[region]; ok {
		return token, nil
	}
	token, err := orch.aws.ECRAuthToken(ctx, region)
	if err != nil {
		return "", err
	}
	if orch.ecrTokens == nil {
		orch.ecrTokens = map[string]string{}
	}
	orch.ecrTokens[region] = token
	return token, nil
}

func (orch *orchestrator) log(format string, args ...any) {
	orch.logMu.Lock()
	defer orch.logMu.Unlock()
	fmt.Fprintf(orch.options.Log, "[%s] %s\n", time.Now().UTC().Format("15:04:05Z"), fmt.Sprintf(format, args...))
}

// Run executes a whole fleet round: preflight, build, parallel spawn, per-host
// detached protocol, collect-as-they-finish, teardown with verification, render,
// summary. It is non-interactive from the first line to the last.
func Run(ctx context.Context, options Options) (Summary, error) {
	if options.Log == nil {
		options.Log = os.Stderr
	}
	runDir := filepath.Join(options.Config.Fleet.ResultsRoot, options.RunID)
	if err := os.MkdirAll(runDir, 0o755); err != nil {
		return Summary{}, err
	}
	orch := &orchestrator{options: options, runDir: runDir}

	plan := BuildPlan(options.Config, options.Machines, options.RunID)
	if err := writeJSONFile(filepath.Join(runDir, "plan.json"), plan); err != nil {
		return Summary{}, err
	}
	planText, err := os.Create(filepath.Join(runDir, "plan.txt"))
	if err != nil {
		return Summary{}, err
	}
	WritePlanText(planText, plan)
	planText.Close()

	orch.state = NewRunState(runDir, options.RunID, options.Config, options.DryRunAWS)
	for _, machine := range options.Machines {
		orch.state.Machines = append(orch.state.Machines, &MachineState{
			Name:          machine.Name,
			Kind:          machine.Kind,
			PlatformLabel: machine.PlatformLabel,
			Status:        StatusPending,
			Suites:        machine.Suites,
			Endpoint:      endpointOf(machine),
			Remote:        LayoutFor(machine, options.RunID),
		})
	}
	if err := orch.state.Save(); err != nil {
		return Summary{}, err
	}

	if err := orch.preflight(ctx); err != nil {
		return Summary{}, err
	}
	if err := orch.build(ctx); err != nil {
		return Summary{}, err
	}
	orch.runAll(ctx)
	orch.closeSession(ctx)

	orch.state.FinishedUTC = time.Now().UTC().Format(time.RFC3339)
	_ = orch.state.Save()
	return orch.finish(ctx)
}

// Resume re-enters collection for hosts that are still running or failed
// collection, without touching hosts that already finished.
func Resume(ctx context.Context, options Options) (Summary, error) {
	if options.Log == nil {
		options.Log = os.Stderr
	}
	runDir := filepath.Join(options.Config.Fleet.ResultsRoot, options.RunID)
	state, err := LoadRunState(runDir)
	if err != nil {
		return Summary{}, err
	}
	orch := &orchestrator{options: options, state: state, runDir: runDir}
	orch.session = state.Session
	orch.prepareAWS()

	var wait sync.WaitGroup
	for _, machine := range options.Machines {
		hostState := state.Machine(machine.Name)
		if hostState == nil {
			orch.log("machine %s is not part of run %s; skipping", machine.Name, options.RunID)
			continue
		}
		if hostState.Status == StatusDone || hostState.Status == StatusTornDown {
			orch.log("machine %s already collected (%s); skipping", machine.Name, hostState.Status)
			continue
		}
		wait.Add(1)
		go func(machine Machine, hostState *MachineState) {
			defer wait.Done()
			orch.collectMachine(ctx, machine, hostState)
		}(machine, hostState)
	}
	wait.Wait()
	orch.closeSession(ctx)
	_ = orch.state.Save()
	return orch.finish(ctx)
}

func (orch *orchestrator) prepareAWS() {
	settings := orch.options.Config.Fleet.AWS
	profile := ""
	if settings.ProfileEnv != "" {
		profile = os.Getenv(settings.ProfileEnv)
	}
	orch.aws = &AWS{
		CLI:     settings.CLI,
		Region:  settings.Region,
		Profile: profile,
		DryRun:  orch.options.DryRunAWS,
		Log:     orch.log,
	}
}

func (orch *orchestrator) hasCloud() bool {
	for _, machine := range orch.options.Machines {
		if machine.Kind == KindAWSEC2 {
			return true
		}
	}
	return false
}

// preflight fails fast and, critically, before anything is created: credentials
// first, then quota arithmetic, then host reachability.
func (orch *orchestrator) preflight(ctx context.Context) error {
	// A corpus_source that does not hold a corpus must stop the round here,
	// before any instance exists; on-host it is only caught by the first
	// corpus-verify gate, after the spend.
	for _, machine := range orch.options.Config.Machines {
		if machine.EC2 == nil || machine.EC2.CorpusSource == "" {
			continue
		}
		manifest := filepath.Join(machine.EC2.CorpusSource, "corpus.json")
		if _, err := os.Stat(manifest); err != nil {
			return fmt.Errorf("machine %s: ec2.corpus_source is not a corpus root: %w", machine.Name, err)
		}
	}
	orch.prepareAWS()
	// Same fail-before-spend rule for corpus images: a tag missing from ECR
	// would otherwise only surface as an on-instance fetch failure.
	for _, machine := range orch.options.Config.Machines {
		if machine.EC2 == nil || machine.EC2.CorpusImage == "" {
			continue
		}
		token, err := orch.ecrToken(ctx, machine.EC2.CorpusImage)
		if err != nil {
			return fmt.Errorf("machine %s: %w", machine.Name, err)
		}
		ref, err := oci.ParseImageRef(machine.EC2.CorpusImage)
		if err != nil {
			return fmt.Errorf("machine %s: %w", machine.Name, err)
		}
		client := &oci.Client{Ref: ref, Token: token}
		exists, err := client.ManifestExists(ctx)
		if err != nil {
			return fmt.Errorf("machine %s: checking corpus image: %w", machine.Name, err)
		}
		if !exists {
			return fmt.Errorf("machine %s: corpus image %s is not in the registry; push it first with `rarpar-bench corpus push`", machine.Name, ref)
		}
		orch.log("preflight: corpus image %s present", ref)
	}
	if orch.hasCloud() {
		orch.log("preflight: AWS credentials")
		if _, err := orch.aws.CheckCredentials(ctx, orch.options.Config.Fleet.AWS.Account); err != nil {
			return err
		}
		quota := ComputeQuota(orch.options.Config, orch.options.Machines)
		var types []string
		for _, instance := range quota.Instances {
			types = append(types, instance.InstanceType)
		}
		// The quota check is against AWS's own vCPU numbers, not the config's
		// claim about them.
		if actual, err := orch.aws.DescribeInstanceTypes(ctx, types); err == nil {
			requested := 0
			for _, instance := range quota.Instances {
				vcpus, ok := actual[instance.InstanceType]
				if !ok {
					return fmt.Errorf("preflight: instance type %s is not offered in %s", instance.InstanceType, orch.aws.Region)
				}
				if vcpus != instance.VCPUs {
					return fmt.Errorf("preflight: machine %s declares %d vCPUs for %s but AWS reports %d; fix ec2.vcpus so the quota arithmetic is honest",
						instance.Machine, instance.VCPUs, instance.InstanceType, vcpus)
				}
				requested += vcpus
			}
			orch.log("preflight: quota %d/%d vCPU confirmed against describe-instance-types", requested, quota.Quota)
		} else {
			orch.log("preflight: describe-instance-types unavailable (%v); using configured vCPU counts", err)
		}
		for _, wave := range quota.Waves {
			if !wave.Fits {
				return fmt.Errorf("preflight: wave %d needs %d vCPUs but fleet.aws.total_vcpu_quota is %d; nothing was launched",
					wave.Wave, wave.Requested, quota.Quota)
			}
		}
		// A held machine keeps its instance past its wave, so its vCPUs stay
		// charged against every later wave. Caught here, before any spend.
		heldCarry := 0
		for _, wave := range quota.Waves {
			if wave.Requested+heldCarry > quota.Quota {
				return fmt.Errorf("preflight: wave %d needs %d vCPUs plus %d held over from earlier waves, but fleet.aws.total_vcpu_quota is %d; release holds or move machines; nothing was launched",
					wave.Wave, wave.Requested, heldCarry, quota.Quota)
			}
			for _, instance := range quota.Instances {
				if instance.Wave == wave.Wave && orch.holds(instance.Machine) {
					heldCarry += instance.VCPUs
				}
			}
		}
		if quota.EstimatedUSD > 0 {
			orch.log("preflight: worst-case cloud spend for this run is $%.2f", quota.EstimatedUSD)
		}
	}

	// Local hosts are probed in parallel; an unreachable host fails the run
	// before any bundle is built.
	var wait sync.WaitGroup
	problems := make([]string, len(orch.options.Machines))
	for index, machine := range orch.options.Machines {
		if machine.Kind != KindLocalSSH {
			continue
		}
		if machine.isWindows() {
			continue
		}
		wait.Add(1)
		go func(index int, machine Machine) {
			defer wait.Done()
			transport, err := NewTransport(machine, orch.runDir)
			if err != nil {
				problems[index] = fmt.Sprintf("machine %s: %v", machine.Name, err)
				return
			}
			probeCtx, cancel := context.WithTimeout(ctx, 90*time.Second)
			defer cancel()
			identity, err := transport.Probe(probeCtx)
			if err != nil {
				problems[index] = fmt.Sprintf("machine %s (%s): unreachable: %v", machine.Name, endpointOf(machine), err)
				return
			}
			orch.log("preflight: %s reachable — %s", machine.Name, identity)
			if err := orch.checkHostOracles(probeCtx, transport, machine); err != nil {
				problems[index] = err.Error()
			}
		}(index, machine)
	}
	wait.Wait()
	var failures []string
	for _, problem := range problems {
		if problem != "" {
			failures = append(failures, problem)
		}
	}
	if len(failures) > 0 {
		return fmt.Errorf("preflight failed:\n  - %s", strings.Join(failures, "\n  - "))
	}
	return nil
}

// checkHostOracles proves a host-path oracle exists (and matches its pinned
// digest) before the run starts, rather than discovering it in a failed suite.
func (orch *orchestrator) checkHostOracles(ctx context.Context, transport *Transport, machine Machine) error {
	for _, role := range sortedKeys(machine.Oracles) {
		oracle := machine.Oracles[role]
		if oracle.Policy != OracleHostPath {
			continue
		}
		script := fmt.Sprintf("if [ ! -x %s ]; then echo MISSING; exit 0; fi\nif command -v sha256sum >/dev/null 2>&1; then sha256sum %s | cut -d' ' -f1; else echo NOHASH; fi\n",
			shellQuote(oracle.Path), shellQuote(oracle.Path))
		stdout, _, err := transport.RunScript(ctx, script)
		if err != nil {
			return fmt.Errorf("machine %s: checking oracle %s: %v", machine.Name, role, err)
		}
		answer := strings.TrimSpace(stdout)
		if answer == "MISSING" {
			return fmt.Errorf("machine %s: oracle %s is not an executable at %s", machine.Name, role, oracle.Path)
		}
		if oracle.BinarySHA256 != "" && answer != "NOHASH" && answer != oracle.BinarySHA256 {
			return fmt.Errorf("machine %s: oracle %s at %s has sha256 %s, config pins %s",
				machine.Name, role, oracle.Path, answer, oracle.BinarySHA256)
		}
		orch.log("preflight: %s oracle %s ok (%s)", machine.Name, role, short(answer))
	}
	return nil
}

func (orch *orchestrator) build(ctx context.Context) error {
	bundler := &Bundler{Settings: orch.options.Config.Fleet, RunDir: orch.runDir, Log: orch.log}
	cacheDir := filepath.Join(orch.runDir, "oracle-cache")
	if orch.options.Config.Fleet.BundleCache != "" {
		cacheDir = filepath.Join(orch.options.Config.Fleet.BundleCache, "oracle-cache")
	}

	// One container build per unique bundle content, all of them in parallel:
	// machines sharing a target reuse the artifacts instead of rebuilding.
	type buildGroup struct {
		name     string
		machines []Machine
	}
	treeID, err := bundleTreeID(bundler.rarparPath())
	if err != nil {
		return err
	}
	byKey := map[string]*buildGroup{}
	groups := []*buildGroup{}
	for _, machine := range orch.options.Machines {
		key := buildKey(machine)
		entry, ok := byKey[key]
		if !ok {
			entry = &buildGroup{name: sharedBundleName(machine, treeID)}
			byKey[key] = entry
			groups = append(groups, entry)
		}
		entry.machines = append(entry.machines, machine)
		orch.state.SetStatus(orch.state.Machine(machine.Name), StatusBuilding)
	}
	sharedDirs := make([]string, len(groups))
	sharedInfos := make([]BuildInfo, len(groups))
	buildErrs := make([]error, len(groups))
	var wait sync.WaitGroup
	for index, entry := range groups {
		wait.Add(1)
		go func(index int, entry *buildGroup) {
			defer wait.Done()
			names := make([]string, len(entry.machines))
			for i, machine := range entry.machines {
				names[i] = machine.Name
			}
			orch.log("build: %s for %s (%s)", entry.name, strings.Join(names, ","), entry.machines[0].Bundle.Source)
			sharedDirs[index], sharedInfos[index], buildErrs[index] = bundler.SharedBuild(ctx, entry.name, entry.machines[0], names)
		}(index, entry)
	}
	wait.Wait()
	for _, err := range buildErrs {
		if err != nil {
			return err
		}
	}

	for index, entry := range groups {
		for _, machine := range entry.machines {
			hostState := orch.state.Machine(machine.Name)
			bundleDir, info, err := bundler.Assemble(machine, sharedDirs[index], sharedInfos[index])
			if err != nil {
				return err
			}
			layout := LayoutFor(machine, orch.options.RunID)
			oracles, err := ResolveOracles(ctx, machine, bundleDir, cacheDir, layout, orch.options.AllowFetch)
			if err != nil {
				return err
			}
			hostState.BundleDir = bundleDir
			hostState.Oracles = oracles
			orch.state.Record(hostState, "build", "bundle ready: %d binaries, rarpar tree %s (%d dirty)",
				len(info.Binaries), short(info.Trees["rarpar"].GitSHA), info.Trees["rarpar"].DirtyFiles)
		}
	}
	return nil
}

// runAll spawns every machine in parallel and lets each one own its whole
// lifecycle. A failed or hung host is terminated and recorded; it never blocks
// another host's collection.
func (orch *orchestrator) runAll(ctx context.Context) {
	runOne := func(wait *sync.WaitGroup, machine Machine) {
		defer wait.Done()
		hostState := orch.state.Machine(machine.Name)
		hostState.StartedUTC = time.Now().UTC().Format(time.RFC3339)
		if err := orch.runMachine(ctx, machine, hostState); err != nil {
			orch.log("machine %s FAILED: %v", machine.Name, err)
			hostState.Failure = err.Error()
			orch.state.SetStatus(hostState, StatusFailed)
			// A cloud host that failed still has to be torn down, and the
			// evidence of that teardown still has to be recorded.
			if machine.Kind == KindAWSEC2 && hostState.Cloud != nil {
				orch.teardownCloud(ctx, machine, hostState)
			}
		}
		hostState.FinishedUTC = time.Now().UTC().Format(time.RFC3339)
		_ = orch.state.Save()
	}

	// Local machines are quota-free and run for the whole round. Cloud
	// machines launch in waves: a wave's goroutines only return after the
	// wave's instances are terminated (runMachine collects and tears down, and
	// the failure arm above tears down too), so waiting on the wave IS waiting
	// on the quota being free again. Held machines are the exception; the
	// preflight already charged them against every later wave.
	var wait sync.WaitGroup
	cloudWaves := map[int][]Machine{}
	for _, machine := range orch.options.Machines {
		if machine.Kind == KindAWSEC2 {
			wave := waveOf(machine)
			cloudWaves[wave] = append(cloudWaves[wave], machine)
			continue
		}
		wait.Add(1)
		go runOne(&wait, machine)
	}
	waves := make([]int, 0, len(cloudWaves))
	for wave := range cloudWaves {
		waves = append(waves, wave)
	}
	sort.Ints(waves)
	for _, wave := range waves {
		if len(waves) > 1 {
			vcpus := 0
			for _, machine := range cloudWaves[wave] {
				vcpus += machine.EC2.VCPUs
			}
			orch.log("wave %d: launching %d cloud machines (%d vCPUs)", wave, len(cloudWaves[wave]), vcpus)
		}
		var waveWait sync.WaitGroup
		for _, machine := range cloudWaves[wave] {
			waveWait.Add(1)
			go runOne(&waveWait, machine)
		}
		waveWait.Wait()
		if len(waves) > 1 {
			orch.log("wave %d: complete", wave)
		}
	}
	wait.Wait()
}

func (orch *orchestrator) runMachine(ctx context.Context, machine Machine, hostState *MachineState) error {
	if machine.isWindows() {
		return orch.runWindows(ctx, machine, hostState)
	}
	orch.state.SetStatus(hostState, StatusSpawning)

	if machine.Kind == KindAWSEC2 {
		session, err := orch.ensureSession(ctx)
		if err != nil {
			return err
		}
		userDataPath := filepath.Join(orch.runDir, "userdata-"+machine.Name+".sh")
		if err := os.WriteFile(userDataPath, []byte(UserData(machine.EC2.DeadmanMinutes)), 0o644); err != nil {
			return err
		}
		cloud, err := orch.aws.Launch(ctx, machine, *session, userDataPath)
		hostState.Cloud = cloud
		_ = orch.state.Save()
		if err != nil {
			return err
		}
		orch.state.Record(hostState, "spawn", "instance %s at %s (deadman %dmin, cost cap %.2fh)",
			cloud.InstanceID, cloud.PublicIP, machine.EC2.DeadmanMinutes, machine.EC2.MaxHours)
		// The launched address, not a config hostname: cloud hosts have no
		// stable name and must never be reached through an ssh_config alias.
		machine.Connection.Host = cloud.PublicIP
		machine.Connection.KeyPath = session.KeyPath
		machine.Connection.Auth = "key"
		hostState.Endpoint = fmt.Sprintf("%s@%s:%d", machine.Connection.User, cloud.PublicIP, machine.Connection.Port)
		if orch.options.DryRunAWS {
			orch.state.Record(hostState, "spawn", "dry-run-aws: stopping before SSH; no instance exists")
			orch.state.SetStatus(hostState, StatusSkipped)
			return nil
		}
		if err := orch.waitForSSH(ctx, machine); err != nil {
			return err
		}
	}

	transport, err := NewTransport(machine, orch.runDir)
	if err != nil {
		return err
	}
	defer transport.Close()

	layout := LayoutFor(machine, orch.options.RunID)
	// corpus_source ships a local corpus into the run root; $CORPUS must point
	// there before RunScript bakes it into the script.
	corpusUpload := ""
	if machine.EC2 != nil && machine.EC2.CorpusSource != "" && machine.Paths.Corpus == "" {
		corpusUpload = machine.EC2.CorpusSource
		machine.Paths.Corpus = joinPosix(layout.Base, "corpus")
	}
	// corpus_image pulls in-region on the instance itself; the orchestrator
	// contributes only a pull token. $CORPUS points at where the fetch lands.
	corpusImage := ""
	if machine.EC2 != nil && machine.EC2.CorpusImage != "" && machine.Paths.Corpus == "" {
		corpusImage = machine.EC2.CorpusImage
		machine.Paths.Corpus = joinPosix(layout.Base, "corpus")
	}
	oracleTargets := map[string]string{}
	for role, resolution := range hostState.Oracles {
		oracleTargets[role] = resolution.RemotePath
	}
	script := RunScript(machine, orch.options.Config.Fleet.Defaults, orch.options.RunID, layout, oracleTargets)
	scriptPath := filepath.Join(orch.runDir, "run-"+machine.Name+".sh")
	if err := os.WriteFile(scriptPath, []byte(script), 0o755); err != nil {
		return err
	}

	orch.log("machine %s: uploading bundle to %s", machine.Name, layout.Bin)
	if err := transport.UploadDir(ctx, hostState.BundleDir, layout.Bin); err != nil {
		return err
	}
	upload := filepath.Join(orch.runDir, "upload-"+machine.Name)
	if err := os.MkdirAll(upload, 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(upload, "run.sh"), []byte(script), 0o755); err != nil {
		return err
	}
	if err := transport.UploadDir(ctx, upload, layout.Base); err != nil {
		return err
	}

	if corpusImage != "" {
		// The token is staged BEFORE the run starts so the script can never
		// race it, and it rides this transient command rather than the run
		// script, which is archived with the results.
		token, err := orch.ecrToken(ctx, corpusImage)
		if err != nil {
			return err
		}
		orch.log("machine %s: staging ECR pull token; corpus %s pulls in-region on the instance", machine.Name, corpusImage)
		stage := fmt.Sprintf("umask 077 && printf '%%s' %s > %s\n",
			shellQuote(token), shellQuote(joinPosix(layout.Base, "ecr-token")))
		if _, _, err := transport.RunScript(ctx, stage); err != nil {
			return err
		}
	}

	// Detached on purpose: once started, a dropped SSH session, a sleeping
	// laptop, or a restarted orchestrator cannot disturb a timed pass.
	start := fmt.Sprintf(`set -e
chmod +x %s %s/* 2>/dev/null || true
cd %s
if command -v setsid >/dev/null 2>&1; then
  setsid nohup sh %s > %s 2>&1 < /dev/null &
else
  nohup sh %s > %s 2>&1 < /dev/null &
fi
echo "started pid $!"
`, shellQuote(layout.Script), shellQuote(layout.Bin), shellQuote(layout.Base),
		shellQuote(layout.Script), shellQuote(layout.Log), shellQuote(layout.Script), shellQuote(layout.Log))
	stdout, _, err := transport.RunScript(ctx, start)
	if err != nil {
		return err
	}
	orch.state.Record(hostState, "spawn", "detached run started: %s", strings.TrimSpace(stdout))
	orch.state.SetStatus(hostState, StatusRunning)
	if corpusUpload != "" {
		// The run is already started: the host builds its candidate while this
		// upload rides alongside; the run script gates its macro suites on the
		// sentinel dropped here.
		orch.log("machine %s: uploading corpus %s to %s (concurrent with the on-host build)", machine.Name, corpusUpload, machine.Paths.Corpus)
		if err := transport.UploadDir(ctx, corpusUpload, machine.Paths.Corpus); err != nil {
			return err
		}
		if _, _, err := transport.RunScript(ctx, "touch "+shellQuote(joinPosix(layout.Base, "CORPUS-UPLOADED"))+"\n"); err != nil {
			return err
		}
	}
	return orch.collectMachine(ctx, machine, hostState)
}

func (orch *orchestrator) ensureSession(ctx context.Context) (*SessionResources, error) {
	orch.sessionMu.Lock()
	defer orch.sessionMu.Unlock()
	if orch.session != nil {
		return orch.session, nil
	}
	settings := orch.options.Config.Fleet.AWS
	publicIP, err := PublicIP(ctx, settings.PublicIPLookup)
	if err != nil {
		return nil, err
	}
	orch.log("session: this machine's public address is %s/32", publicIP)
	session, err := orch.aws.CreateSession(ctx, settings.ResourcePrefix, publicIP, orch.runDir, settings.SSHIngressPort)
	if err != nil {
		return nil, err
	}
	orch.session = &session
	orch.state.Session = &session
	_ = orch.state.Save()
	return orch.session, nil
}

func (orch *orchestrator) waitForSSH(ctx context.Context, machine Machine) error {
	transport, err := NewTransport(machine, orch.runDir)
	if err != nil {
		return err
	}
	// Per-machine: previous-generation Xen instance types measure 5-11 minute
	// boots (c4 straddled a fixed 10-minute wait roughly one launch in three,
	// each miss costing a terminated instance), while Nitro answers in 1-2.
	wait := 10 * time.Minute
	if machine.EC2 != nil && machine.EC2.SSHWaitMinutes > 0 {
		wait = time.Duration(machine.EC2.SSHWaitMinutes) * time.Minute
	}
	deadline := time.Now().Add(wait)
	for {
		attempt, cancel := context.WithTimeout(ctx, 30*time.Second)
		_, probeErr := transport.Probe(attempt)
		cancel()
		if probeErr == nil {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("machine %s: SSH never became available: %w", machine.Name, probeErr)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(10 * time.Second):
		}
	}
}

func (orch *orchestrator) closeSession(ctx context.Context) {
	orch.sessionMu.Lock()
	session := orch.session
	orch.sessionMu.Unlock()
	if session == nil {
		return
	}
	for _, hostState := range orch.state.Machines {
		if hostState.Kind != KindAWSEC2 || hostState.Cloud == nil || hostState.Cloud.DryRun {
			continue
		}
		if hostState.Teardown == nil {
			// A live instance still exists, so the shared keypair and security
			// group it depends on must outlive this call. `fleet teardown`
			// finishes the job.
			orch.log("session teardown deferred: %s has no teardown evidence yet", hostState.Name)
			return
		}
	}
	evidence, err := orch.aws.DeleteSession(ctx, *session)
	if err != nil {
		orch.log("session teardown error: %v", err)
	}
	for _, line := range evidence {
		orch.log("session teardown: %s", line)
	}
	if err := writeJSONFile(filepath.Join(orch.runDir, "session-teardown.json"), map[string]any{
		"session":  session,
		"evidence": evidence,
	}); err != nil {
		orch.log("session teardown: cannot write evidence: %v", err)
	}
	orch.sessionMu.Lock()
	orch.session = nil
	orch.state.Session = nil
	orch.sessionMu.Unlock()
	_ = orch.state.Save()
}

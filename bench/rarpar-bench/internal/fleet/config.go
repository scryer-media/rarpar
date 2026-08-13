// Package fleet orchestrates a full cross-machine rarpar benchmark round from
// one non-interactive command: build per-target bundles, spawn every configured
// host in parallel (local SSH targets and EC2 instances), run the standard
// protocol on each, collect results as hosts finish, tear cloud hosts down with
// verification, and render charts plus a fleet summary on the orchestrator.
//
// It productizes the per-round shell scripts that produced the recorded
// evidence rounds. House rules learned the hard way in those rounds are encoded
// here rather than left to the operator; each one is commented where it is not
// self-evident.
package fleet

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const ConfigSchemaVersion = 1

// Suites a machine can be asked to run.
const (
	SuiteCRCProbe  = "crc-probe"
	SuiteYencMicro = "yenc-micro"
	SuiteMacroRAR  = "macro-rar"
	SuiteMacroPAR2 = "macro-par2"
)

// Machine kinds.
const (
	KindLocalSSH = "local-ssh"
	KindAWSEC2   = "aws-ec2"
)

// Perf capability values.
const (
	PerfLinux  = "linux-perf"
	PerfSamply = "samply"
	PerfNone   = "none"
)

// Oracle policies. "Never build an oracle where an official binary exists" is a
// standing rule: source-build is only reachable with a recorded reason.
const (
	OracleHostPath       = "host-path"
	OracleOfficialBinary = "official-binary"
	OracleSourceBuild    = "source-build"
)

// Bundle sources.
const (
	BundlePrebuilt = "prebuilt"
	BundleDocker   = "docker"
)

var (
	knownSuites   = []string{SuiteCRCProbe, SuiteYencMicro, SuiteMacroRAR, SuiteMacroPAR2}
	knownRecipes  = []string{"unrar-portable"}
	knownShells   = []string{"sh", "bash", "powershell"}
	suiteFamilies = map[string]string{SuiteMacroRAR: "rar", SuiteMacroPAR2: "par2"}
)

type Config struct {
	Path          string    `json:"path"`
	SHA256        string    `json:"sha256"`
	SchemaVersion int       `json:"schema_version"`
	Fleet         Settings  `json:"fleet"`
	Machines      []Machine `json:"machines"`
}

type Settings struct {
	ResultsRoot        string      `json:"results_root"`
	RunIDPrefix        string      `json:"run_id_prefix"`
	BundleCache        string      `json:"bundle_cache"`
	RarparPath         string      `json:"rarpar_path,omitempty"`
	WeaverPath         string      `json:"weaver_path,omitempty"`
	RapidyencPath      string      `json:"rapidyenc_path,omitempty"`
	Docker             string      `json:"docker"`
	PollSeconds        int         `json:"poll_seconds"`
	HostTimeoutMinutes int         `json:"host_timeout_minutes"`
	Defaults           RunDefaults `json:"defaults"`
	AWS                AWSSettings `json:"aws"`
	Render             Render      `json:"render"`
}

type RunDefaults struct {
	Warmups                 int      `json:"warmups"`
	Repeats                 int      `json:"repeats"`
	Lane                    string   `json:"lane"`
	Par2Placement           string   `json:"par2_placement"`
	Seed                    string   `json:"seed"`
	QuietLoadThreshold      float64  `json:"quiet_load_threshold"`
	QuietLoadTimeoutSeconds int      `json:"quiet_load_timeout_seconds"`
	QuietLoadPollSeconds    int      `json:"quiet_load_poll_seconds"`
	QuietLoadProcessNames   []string `json:"quiet_load_process_names"`
	PerfStatRepeats         int      `json:"perf_stat_repeats"`
	PerfRecordFrequency     int      `json:"perf_record_frequency"`
}

type AWSSettings struct {
	CLI             string   `json:"cli"`
	Account         string   `json:"account"`
	Region          string   `json:"region"`
	ProfileEnv      string   `json:"profile_env,omitempty"`
	TotalVCPUQuota  int      `json:"total_vcpu_quota"`
	ResourcePrefix  string   `json:"resource_prefix"`
	PublicIPLookup  []string `json:"public_ip_lookup"`
	SSHIngressPort  int      `json:"ssh_ingress_port"`
	MaxSessionHours float64  `json:"max_session_hours"`
}

type Render struct {
	Enabled bool `json:"enabled"`
}

type Machine struct {
	Name          string            `json:"name"`
	Kind          string            `json:"kind"`
	PlatformLabel string            `json:"platform_label"`
	BuildTarget   string            `json:"build_target"`
	Enabled       bool              `json:"enabled"`
	Suites        []string          `json:"suites"`
	Connection    Connection        `json:"connection"`
	Capabilities  Capabilities      `json:"capabilities"`
	Paths         HostPaths         `json:"paths"`
	Bundle        Bundle            `json:"bundle"`
	Oracles       map[string]Oracle `json:"oracles,omitempty"`
	Run           RunOverrides      `json:"run"`
	Perf          PerfPlan          `json:"perf"`
	EC2           *EC2              `json:"ec2,omitempty"`
}

type Connection struct {
	Host          string   `json:"host"`
	Port          int      `json:"port"`
	User          string   `json:"user"`
	Auth          string   `json:"auth"`
	KeyPath       string   `json:"key_path,omitempty"`
	AskpassScript string   `json:"askpass_script,omitempty"`
	Shell         string   `json:"shell"`
	SSHOptions    []string `json:"ssh_options,omitempty"`
}

type Capabilities struct {
	Perf   string `json:"perf"`
	Docker bool   `json:"docker"`
	// NoPgrep marks hosts whose busybox-class userland has no pgrep. The run
	// script falls back to `ps -ef | grep` there; the DSM-class NAS taught us
	// that a missing pgrep silently makes every load gate pass.
	NoPgrep bool `json:"no_pgrep"`
}

type HostPaths struct {
	Staging string `json:"staging"`
	Scratch string `json:"scratch"`
	Corpus  string `json:"corpus"`
	Cleanup bool   `json:"cleanup"`
}

type Bundle struct {
	Source     string `json:"source"`
	Path       string `json:"path,omitempty"`
	Image      string `json:"image,omitempty"`
	BuildHost  string `json:"build_host,omitempty"`
	RustTarget string `json:"rust_target,omitempty"`
	GoOS       string `json:"go_os,omitempty"`
	GoArch     string `json:"go_arch,omitempty"`
	GOAMD64    string `json:"goamd64,omitempty"`
	CrtStatic  bool   `json:"crt_static"`
}

type Oracle struct {
	Role          string `json:"role"`
	Policy        string `json:"policy"`
	Path          string `json:"path,omitempty"`
	URL           string `json:"url,omitempty"`
	SHA256        string `json:"sha256,omitempty"`
	ArchiveMember string `json:"archive_member,omitempty"`
	BinarySHA256  string `json:"binary_sha256,omitempty"`
	Recipe        string `json:"recipe,omitempty"`
	Reason        string `json:"reason,omitempty"`
	Version       string `json:"version,omitempty"`
}

type RunOverrides struct {
	Warmups            int      `json:"warmups"`
	Repeats            int      `json:"repeats"`
	Cases              []string `json:"cases,omitempty"`
	QuietLoadThreshold float64  `json:"quiet_load_threshold"`
	Ghz                float64  `json:"ghz,omitempty"`
	// NoWarmupPass suppresses the discarded warmup pass that precedes the timed
	// repeats. It is stored inverted so the zero value keeps the warmup.
	NoWarmupPass bool `json:"no_warmup_pass,omitempty"`
}

type PerfPlan struct {
	RecordCases     []string `json:"record_cases,omitempty"`
	StatRepeats     int      `json:"stat_repeats"`
	RecordFrequency int      `json:"record_frequency"`
}

type EC2 struct {
	InstanceType   string  `json:"instance_type"`
	Region         string  `json:"region"`
	AMI            string  `json:"ami"`
	VCPUs          int     `json:"vcpus"`
	VolumeGB       int     `json:"volume_gb"`
	Subnet         string  `json:"subnet,omitempty"`
	DeadmanMinutes int     `json:"deadman_minutes"`
	MaxHours       float64 `json:"max_hours"`
	HourlyUSD      float64 `json:"hourly_usd"`
	CorpusSource   string  `json:"corpus_source,omitempty"`
}

// LoadConfig reads, decodes, and validates a fleet configuration.
func LoadConfig(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read fleet config: %w", err)
	}
	config, err := DecodeConfig(filepath.Base(path), string(data))
	if err != nil {
		return Config{}, err
	}
	config.Path = path
	digest := sha256.Sum256(data)
	config.SHA256 = hex.EncodeToString(digest[:])
	return config, nil
}

// DecodeConfig decodes and validates a config from memory. name appears in
// error messages only.
func DecodeConfig(name, data string) (Config, error) {
	root, err := parseTOML(name, data)
	if err != nil {
		return Config{}, err
	}
	state := &decodeState{file: name}
	top := newSection(state, root, "", true)

	config := Config{SchemaVersion: top.integer("schema_version", 0)}
	if config.SchemaVersion != ConfigSchemaVersion {
		state.fail("schema_version must be %d", ConfigSchemaVersion)
	}

	fleet := top.requiredChild("fleet")
	config.Fleet = decodeSettings(fleet)

	machines := top.list("machines")
	if len(machines) == 0 {
		state.fail("at least one [[machines]] entry is required")
	}
	for _, entry := range machines {
		config.Machines = append(config.Machines, decodeMachine(entry, config.Fleet))
	}
	fleet.finish()
	top.finish()

	validate(state, &config)
	if err := state.err(); err != nil {
		return Config{}, err
	}
	return config, nil
}

func decodeSettings(item *section) Settings {
	settings := Settings{
		ResultsRoot:        item.requiredStr("results_root"),
		RunIDPrefix:        item.str("run_id_prefix", "fleet"),
		BundleCache:        item.str("bundle_cache", ""),
		RarparPath:         item.str("rarpar_path", ""),
		WeaverPath:         item.str("weaver_path", ""),
		RapidyencPath:      item.str("rapidyenc_path", ""),
		Docker:             item.str("docker", "docker"),
		PollSeconds:        item.integer("poll_seconds", 20),
		HostTimeoutMinutes: item.integer("host_timeout_minutes", 240),
	}

	defaults := item.child("defaults")
	settings.Defaults = RunDefaults{
		Warmups:                 defaults.integer("warmups", 1),
		Repeats:                 defaults.integer("repeats", 7),
		Lane:                    defaults.str("lane", "cpu"),
		Par2Placement:           defaults.str("par2_placement", "canonical"),
		Seed:                    defaults.str("seed", "rarpar-benchmark-plan-v1"),
		QuietLoadThreshold:      defaults.float("quiet_load_threshold", 0.5),
		QuietLoadTimeoutSeconds: defaults.integer("quiet_load_timeout_seconds", 900),
		QuietLoadPollSeconds:    defaults.integer("quiet_load_poll_seconds", 30),
		QuietLoadProcessNames: defaults.strings("quiet_load_process_names", []string{
			"rarpar-bench", "rarpar", "par2", "unrar", "decode_timing", "searchend_timing", "crc_probe",
		}),
		PerfStatRepeats:     defaults.integer("perf_stat_repeats", 3),
		PerfRecordFrequency: defaults.integer("perf_record_frequency", 499),
	}
	defaults.finish()

	aws := item.child("aws")
	settings.AWS = AWSSettings{
		CLI:            aws.str("cli", "aws"),
		Account:        aws.str("account", ""),
		Region:         aws.str("region", ""),
		ProfileEnv:     aws.str("profile_env", ""),
		TotalVCPUQuota: aws.integer("total_vcpu_quota", 0),
		ResourcePrefix: aws.str("resource_prefix", "rarpar-fleet"),
		// Public-IP discovery is DNS-based on purpose: HTTP echo services are
		// blocked on the orchestrating network, and a blank answer would open
		// the session security group far wider than intended.
		PublicIPLookup: aws.strings("public_ip_lookup", []string{
			"dig +short -4 txt ch whoami.cloudflare @1.0.0.1",
			"dig +short -4 myip.opendns.com @resolver1.opendns.com",
		}),
		SSHIngressPort:  aws.integer("ssh_ingress_port", 22),
		MaxSessionHours: aws.float("max_session_hours", 3),
	}
	aws.finish()

	render := item.child("render")
	settings.Render = Render{Enabled: render.boolean("enabled", true)}
	render.finish()
	return settings
}

func decodeMachine(item *section, settings Settings) Machine {
	machine := Machine{
		Name:          item.requiredStr("name"),
		Kind:          item.requiredStr("kind"),
		PlatformLabel: item.requiredStr("platform_label"),
		BuildTarget:   item.str("build_target", ""),
		Enabled:       item.boolean("enabled", true),
		Suites:        item.strings("suites", nil),
	}

	connection := item.requiredChild("connection")
	machine.Connection = Connection{
		Host:          connection.str("host", ""),
		Port:          connection.integer("port", 22),
		User:          connection.requiredStr("user"),
		Auth:          connection.str("auth", "key"),
		KeyPath:       connection.str("key_path", ""),
		AskpassScript: connection.str("askpass_script", ""),
		Shell:         connection.str("shell", "sh"),
		SSHOptions:    connection.strings("ssh_options", nil),
	}
	// Secrets never live in this file. The strict unknown-key check already
	// rejects `password`, but say so in words the operator will recognise.
	for _, forbidden := range []string{"password", "passphrase", "secret", "token"} {
		if connection.has(forbidden) {
			item.state.fail("machine %q: [%s].%s is not allowed; use auth = \"askpass\" with askpass_script, or auth = \"key\" with key_path",
				machine.Name, connection.path, forbidden)
			connection.used[forbidden] = true
		}
	}
	connection.finish()

	capabilities := item.child("capabilities")
	machine.Capabilities = Capabilities{
		Perf:    capabilities.str("perf", PerfNone),
		Docker:  capabilities.boolean("docker", false),
		NoPgrep: capabilities.boolean("no_pgrep", false),
	}
	capabilities.finish()

	paths := item.requiredChild("paths")
	machine.Paths = HostPaths{
		Staging: paths.requiredStr("staging"),
		Scratch: paths.str("scratch", ""),
		Corpus:  paths.str("corpus", ""),
		Cleanup: paths.boolean("cleanup", true),
	}
	paths.finish()

	bundle := item.requiredChild("bundle")
	machine.Bundle = Bundle{
		Source:     bundle.requiredStr("source"),
		Path:       bundle.str("path", ""),
		Image:      bundle.str("image", ""),
		BuildHost:  bundle.str("build_host", "local"),
		RustTarget: bundle.str("rust_target", ""),
		GoOS:       bundle.str("go_os", "linux"),
		GoArch:     bundle.str("go_arch", ""),
		GOAMD64:    bundle.str("goamd64", ""),
		CrtStatic:  bundle.boolean("crt_static", true),
	}
	bundle.finish()

	oracles := item.child("oracles")
	for _, role := range oracles.childNames() {
		entry := oracles.child(role)
		oracle := Oracle{
			Role:          role,
			Policy:        entry.requiredStr("policy"),
			Path:          entry.str("path", ""),
			URL:           entry.str("url", ""),
			SHA256:        entry.str("sha256", ""),
			ArchiveMember: entry.str("archive_member", ""),
			BinarySHA256:  entry.str("binary_sha256", ""),
			Recipe:        entry.str("recipe", ""),
			Reason:        entry.str("reason", ""),
			Version:       entry.str("version", ""),
		}
		entry.finish()
		if machine.Oracles == nil {
			machine.Oracles = map[string]Oracle{}
		}
		machine.Oracles[role] = oracle
	}
	oracles.finish()

	run := item.child("run")
	machine.Run = RunOverrides{
		Warmups:            run.integer("warmups", settings.Defaults.Warmups),
		Repeats:            run.integer("repeats", settings.Defaults.Repeats),
		Cases:              run.strings("cases", nil),
		QuietLoadThreshold: run.float("quiet_load_threshold", settings.Defaults.QuietLoadThreshold),
		Ghz:                run.float("ghz", 0),
		NoWarmupPass:       !run.boolean("warmup_pass", true),
	}
	run.finish()

	perf := item.child("perf")
	machine.Perf = PerfPlan{
		RecordCases:     perf.strings("record_cases", nil),
		StatRepeats:     perf.integer("stat_repeats", settings.Defaults.PerfStatRepeats),
		RecordFrequency: perf.integer("record_frequency", settings.Defaults.PerfRecordFrequency),
	}
	perf.finish()

	if ec2 := item.child("ec2"); ec2.present {
		machine.EC2 = &EC2{
			InstanceType:   ec2.requiredStr("instance_type"),
			Region:         ec2.str("region", settings.AWS.Region),
			AMI:            ec2.requiredStr("ami"),
			VCPUs:          ec2.integer("vcpus", 0),
			VolumeGB:       ec2.integer("volume_gb", 30),
			Subnet:         ec2.str("subnet", ""),
			DeadmanMinutes: ec2.integer("deadman_minutes", 180),
			MaxHours:       ec2.float("max_hours", 2),
			HourlyUSD:      ec2.float("hourly_usd", 0),
			CorpusSource:   ec2.str("corpus_source", ""),
		}
		ec2.finish()
	}
	item.finish()
	return machine
}

func validate(state *decodeState, config *Config) {
	settings := &config.Fleet
	if settings.PollSeconds < 1 {
		state.fail("fleet.poll_seconds must be positive")
	}
	if settings.HostTimeoutMinutes < 1 {
		state.fail("fleet.host_timeout_minutes must be positive")
	}
	if !filepath.IsAbs(settings.ResultsRoot) {
		state.fail("fleet.results_root must be an absolute path: %s", settings.ResultsRoot)
	}
	defaults := settings.Defaults
	if defaults.Warmups < 0 || defaults.Repeats < 1 {
		state.fail("fleet.defaults: warmups must be >= 0 and repeats >= 1")
	}
	if defaults.Lane != "cpu" && defaults.Lane != "metal" && defaults.Lane != "docker-cpu" {
		state.fail("fleet.defaults.lane must be cpu, metal, or docker-cpu")
	}
	if defaults.Par2Placement != "canonical" && defaults.Par2Placement != "smart" {
		state.fail("fleet.defaults.par2_placement must be canonical or smart")
	}
	if defaults.QuietLoadThreshold <= 0 {
		state.fail("fleet.defaults.quiet_load_threshold must be positive")
	}
	if defaults.QuietLoadPollSeconds < 1 || defaults.QuietLoadTimeoutSeconds < 0 {
		state.fail("fleet.defaults: quiet_load_poll_seconds must be positive and the timeout non-negative")
	}
	if len(defaults.QuietLoadProcessNames) == 0 {
		state.fail("fleet.defaults.quiet_load_process_names must not be empty; the load gate is what keeps a timed pass off a busy box")
	}

	names := map[string]bool{}
	labels := map[string]string{}
	endpoints := map[string]string{}
	cloud := 0
	vcpus := 0
	for index := range config.Machines {
		machine := &config.Machines[index]
		prefix := fmt.Sprintf("machine %q", machine.Name)
		if machine.Name == "" {
			prefix = fmt.Sprintf("machines[%d]", index)
		}
		if names[machine.Name] {
			state.fail("%s: name is duplicated", prefix)
		}
		names[machine.Name] = true
		if strings.ContainsAny(machine.Name, " \t/\\") {
			state.fail("%s: name must be a path-safe token", prefix)
		}
		// Platform labels name the SVG files and the report machine label; a
		// collision silently overwrites another machine's chart.
		if other, exists := labels[machine.PlatformLabel]; exists {
			state.fail("%s: platform_label %q is already used by machine %q", prefix, machine.PlatformLabel, other)
		}
		labels[machine.PlatformLabel] = machine.Name

		if machine.Kind != KindLocalSSH && machine.Kind != KindAWSEC2 {
			state.fail("%s: kind must be %s or %s", prefix, KindLocalSSH, KindAWSEC2)
		}
		validateSuites(state, prefix, machine)

		connection := machine.Connection
		if machine.Kind == KindLocalSSH && strings.TrimSpace(connection.Host) == "" {
			state.fail("%s: connection.host is required for a %s machine", prefix, KindLocalSSH)
		}
		if strings.HasPrefix(connection.Host, "-") {
			state.fail("%s: connection.host must not begin with '-'", prefix)
		}
		// Explicit user@host:port only. An ssh_config alias resolved to the
		// wrong user once and mis-authenticated an entire round.
		if strings.Contains(connection.Host, "@") {
			state.fail("%s: connection.host must be a bare host or address; set connection.user separately", prefix)
		}
		if strings.Contains(connection.User, "@") {
			state.fail("%s: connection.user must not contain '@'", prefix)
		}
		if connection.Port < 1 || connection.Port > 65535 {
			state.fail("%s: connection.port must be 1-65535", prefix)
		}
		if !contains(knownShells, connection.Shell) {
			state.fail("%s: connection.shell must be one of %s", prefix, strings.Join(knownShells, ", "))
		}
		switch connection.Auth {
		case "key":
			if connection.KeyPath == "" && machine.Kind == KindLocalSSH {
				state.fail("%s: connection.key_path is required for auth = \"key\"", prefix)
			}
			if connection.AskpassScript != "" {
				state.fail("%s: connection.askpass_script is only used with auth = \"askpass\"", prefix)
			}
		case "askpass":
			if machine.Kind == KindAWSEC2 {
				state.fail("%s: cloud machines always use the ephemeral session keypair; auth must be \"key\"", prefix)
			}
			if connection.AskpassScript == "" {
				state.fail("%s: connection.askpass_script is required for auth = \"askpass\"", prefix)
			}
		default:
			state.fail("%s: connection.auth must be \"key\" or \"askpass\"", prefix)
		}
		for _, option := range connection.SSHOptions {
			if strings.TrimSpace(option) == "" {
				state.fail("%s: connection.ssh_options must not contain empty entries", prefix)
			}
		}
		if machine.Kind == KindLocalSSH {
			key := fmt.Sprintf("%s@%s:%d", connection.User, strings.ToLower(connection.Host), connection.Port)
			if other, exists := endpoints[key]; exists {
				state.fail("%s: SSH endpoint %s is already used by machine %q", prefix, key, other)
			}
			endpoints[key] = machine.Name
		}

		windows := connection.Shell == "powershell"
		validateHostPath(state, prefix, "paths.staging", machine.Paths.Staging, windows)
		if machine.Paths.Scratch != "" {
			validateHostPath(state, prefix, "paths.scratch", machine.Paths.Scratch, windows)
		}
		if machine.Paths.Corpus != "" {
			validateHostPath(state, prefix, "paths.corpus", machine.Paths.Corpus, windows)
		}
		if machine.needsCorpus() && machine.Paths.Corpus == "" && (machine.EC2 == nil || machine.EC2.CorpusSource == "") {
			state.fail("%s: paths.corpus is required for the macro suites", prefix)
		}
		if machine.EC2 != nil && machine.EC2.CorpusSource != "" && machine.Paths.Corpus != "" {
			state.fail("%s: ec2.corpus_source and paths.corpus are mutually exclusive; corpus_source uploads into the run root", prefix)
		}

		switch machine.Capabilities.Perf {
		case PerfLinux, PerfSamply, PerfNone:
		default:
			state.fail("%s: capabilities.perf must be %s, %s, or %s", prefix, PerfLinux, PerfSamply, PerfNone)
		}
		if windows && machine.Capabilities.Perf != PerfNone {
			state.fail("%s: Windows hosts have no perf collector; set capabilities.perf = \"none\"", prefix)
		}
		if machine.Perf.RecordFrequency < 1 {
			state.fail("%s: perf.record_frequency must be positive", prefix)
		}
		if machine.Perf.StatRepeats < 1 {
			state.fail("%s: perf.stat_repeats must be positive", prefix)
		}

		validateBundle(state, prefix, machine)
		validateOracles(state, prefix, machine)

		if machine.Run.Warmups < 0 || machine.Run.Repeats < 1 {
			state.fail("%s: run.warmups must be >= 0 and run.repeats >= 1", prefix)
		}
		if machine.Run.QuietLoadThreshold <= 0 {
			state.fail("%s: run.quiet_load_threshold must be positive", prefix)
		}

		if machine.Kind == KindAWSEC2 {
			cloud++
			validateEC2(state, prefix, machine, settings)
			if machine.EC2 != nil && machine.Enabled {
				vcpus += machine.EC2.VCPUs
			}
		} else if machine.EC2 != nil {
			state.fail("%s: [machines.ec2] is only valid for kind = %q", prefix, KindAWSEC2)
		}
	}

	if cloud > 0 {
		if settings.AWS.Region == "" {
			state.fail("fleet.aws.region is required when a machine has kind = %q", KindAWSEC2)
		}
		if settings.AWS.TotalVCPUQuota < 1 {
			state.fail("fleet.aws.total_vcpu_quota must be positive when cloud machines are configured")
		}
		if len(settings.AWS.PublicIPLookup) == 0 {
			state.fail("fleet.aws.public_ip_lookup must not be empty; the session security group is scoped to this machine's public address")
		}
		if vcpus > settings.AWS.TotalVCPUQuota {
			state.fail("parallel launch needs %d vCPUs but fleet.aws.total_vcpu_quota is %d; raise the quota or disable machines before running",
				vcpus, settings.AWS.TotalVCPUQuota)
		}
	}
}

func validateSuites(state *decodeState, prefix string, machine *Machine) {
	if len(machine.Suites) == 0 {
		state.fail("%s: suites must not be empty", prefix)
		return
	}
	seen := map[string]bool{}
	for _, suite := range machine.Suites {
		if !contains(knownSuites, suite) {
			state.fail("%s: unknown suite %q (known: %s)", prefix, suite, strings.Join(knownSuites, ", "))
		}
		if seen[suite] {
			state.fail("%s: suite %q is listed twice", prefix, suite)
		}
		seen[suite] = true
	}
}

func validateHostPath(state *decodeState, prefix, name, value string, windows bool) {
	if strings.TrimSpace(value) == "" {
		state.fail("%s: %s must not be empty", prefix, name)
		return
	}
	if windows {
		if !strings.Contains(value, ":\\") && !strings.HasPrefix(value, "\\\\") {
			state.fail("%s: %s must be an absolute Windows path: %s", prefix, name, value)
		}
		return
	}
	// Remote paths are never relative: a relative staging path once resolved
	// against an unexpected home directory on a non-interactive SSH session.
	if !strings.HasPrefix(value, "/") {
		state.fail("%s: %s must be an absolute POSIX path: %s", prefix, name, value)
	}
	if strings.ContainsAny(value, "'\"$`\n") {
		state.fail("%s: %s must not contain shell metacharacters: %s", prefix, name, value)
	}
}

func validateBundle(state *decodeState, prefix string, machine *Machine) {
	switch machine.Bundle.Source {
	case BundlePrebuilt:
		if machine.Bundle.Path == "" {
			state.fail("%s: bundle.path is required for source = %q", prefix, BundlePrebuilt)
		} else if !filepath.IsAbs(machine.Bundle.Path) {
			state.fail("%s: bundle.path must be absolute: %s", prefix, machine.Bundle.Path)
		}
	case BundleDocker:
		if machine.Bundle.Image == "" {
			state.fail("%s: bundle.image is required for source = %q", prefix, BundleDocker)
		}
		if machine.Bundle.RustTarget == "" {
			state.fail("%s: bundle.rust_target is required for source = %q", prefix, BundleDocker)
		}
		if machine.Bundle.GoArch == "" {
			state.fail("%s: bundle.go_arch is required for source = %q", prefix, BundleDocker)
		}
	default:
		state.fail("%s: bundle.source must be %q or %q", prefix, BundlePrebuilt, BundleDocker)
	}
}

func validateOracles(state *decodeState, prefix string, machine *Machine) {
	for _, suite := range machine.Suites {
		role, ok := suiteFamilies[suite]
		if !ok {
			continue
		}
		if _, exists := machine.Oracles[role]; !exists {
			state.fail("%s: suite %q needs [machines.oracles.%s]", prefix, suite, role)
		}
	}
	roles := make([]string, 0, len(machine.Oracles))
	for role := range machine.Oracles {
		roles = append(roles, role)
	}
	sort.Strings(roles)
	for _, role := range roles {
		oracle := machine.Oracles[role]
		if role != "rar" && role != "par2" {
			state.fail("%s: unknown oracle role %q (rar, par2)", prefix, role)
		}
		switch oracle.Policy {
		case OracleHostPath:
			if oracle.Path == "" {
				state.fail("%s: oracles.%s.path is required for policy %q", prefix, role, OracleHostPath)
			}
		case OracleOfficialBinary:
			if oracle.URL == "" || oracle.SHA256 == "" {
				state.fail("%s: oracles.%s needs url and sha256 for policy %q", prefix, role, OracleOfficialBinary)
			}
			if !isHexSHA256(oracle.SHA256) {
				state.fail("%s: oracles.%s.sha256 must be 64 hex characters", prefix, role)
			}
		case OracleSourceBuild:
			// House rule: never rebuild an oracle where an official binary
			// exists. Source builds stay reachable (linux-arm unrar has no
			// official binary) but must record why, use an audited recipe, and
			// pin the source tarball.
			if oracle.Reason == "" {
				state.fail("%s: oracles.%s.reason is required for policy %q; record why no official binary exists", prefix, role, OracleSourceBuild)
			}
			if oracle.URL == "" || oracle.SHA256 == "" {
				state.fail("%s: oracles.%s needs the source url and sha256 for policy %q", prefix, role, OracleSourceBuild)
			}
			if !contains(knownRecipes, oracle.Recipe) {
				state.fail("%s: oracles.%s.recipe must be one of %s", prefix, role, strings.Join(knownRecipes, ", "))
			}
		default:
			state.fail("%s: oracles.%s.policy must be %s, %s, or %s", prefix, role,
				OracleHostPath, OracleOfficialBinary, OracleSourceBuild)
		}
		if oracle.BinarySHA256 != "" && !isHexSHA256(oracle.BinarySHA256) {
			state.fail("%s: oracles.%s.binary_sha256 must be 64 hex characters", prefix, role)
		}
	}
}

func validateEC2(state *decodeState, prefix string, machine *Machine, settings *Settings) {
	if machine.EC2 == nil {
		state.fail("%s: [machines.ec2] is required for kind = %q", prefix, KindAWSEC2)
		return
	}
	ec2 := machine.EC2
	if ec2.VCPUs < 1 {
		state.fail("%s: ec2.vcpus must be positive; the fleet validates the parallel launch against the account quota before launching anything", prefix)
	}
	if ec2.VolumeGB < 8 {
		state.fail("%s: ec2.volume_gb must be at least 8", prefix)
	}
	if ec2.MaxHours <= 0 {
		state.fail("%s: ec2.max_hours must be positive; it is the cost cap that terminates a hung host", prefix)
	}
	if ec2.DeadmanMinutes < 1 {
		state.fail("%s: ec2.deadman_minutes must be positive; every cloud host gets a deadman shutdown", prefix)
	}
	// The deadman is the backstop, not the schedule: the orchestrator's cost cap
	// has to fire first, otherwise a box shuts down mid-measurement.
	if float64(ec2.DeadmanMinutes) < ec2.MaxHours*60 {
		state.fail("%s: ec2.deadman_minutes (%d) must be at least ec2.max_hours*60 (%.0f)", prefix, ec2.DeadmanMinutes, ec2.MaxHours*60)
	}
	if settings.AWS.MaxSessionHours > 0 && ec2.MaxHours > settings.AWS.MaxSessionHours {
		state.fail("%s: ec2.max_hours (%.2f) exceeds fleet.aws.max_session_hours (%.2f)", prefix, ec2.MaxHours, settings.AWS.MaxSessionHours)
	}
	if !strings.HasPrefix(ec2.AMI, "ami-") {
		state.fail("%s: ec2.ami must be an ami-… identifier", prefix)
	}
	if ec2.Region == "" {
		state.fail("%s: ec2.region is required (or set fleet.aws.region)", prefix)
	}
}

// QuotaCheck is the pre-launch arithmetic: the whole parallel launch has to fit
// the account's vCPU quota before a single instance is created.
type QuotaCheck struct {
	Region       string          `json:"region"`
	Quota        int             `json:"total_vcpu_quota"`
	Requested    int             `json:"requested_vcpus"`
	Headroom     int             `json:"headroom_vcpus"`
	Fits         bool            `json:"fits"`
	Instances    []QuotaInstance `json:"instances"`
	EstimatedUSD float64         `json:"estimated_max_usd"`
}

type QuotaInstance struct {
	Machine      string  `json:"machine"`
	InstanceType string  `json:"instance_type"`
	VCPUs        int     `json:"vcpus"`
	MaxHours     float64 `json:"max_hours"`
	HourlyUSD    float64 `json:"hourly_usd"`
	MaxUSD       float64 `json:"max_usd"`
}

func ComputeQuota(config Config, selected []Machine) QuotaCheck {
	check := QuotaCheck{Region: config.Fleet.AWS.Region, Quota: config.Fleet.AWS.TotalVCPUQuota}
	for _, machine := range selected {
		if machine.Kind != KindAWSEC2 || machine.EC2 == nil {
			continue
		}
		instance := QuotaInstance{
			Machine:      machine.Name,
			InstanceType: machine.EC2.InstanceType,
			VCPUs:        machine.EC2.VCPUs,
			MaxHours:     machine.EC2.MaxHours,
			HourlyUSD:    machine.EC2.HourlyUSD,
			MaxUSD:       roundCents(machine.EC2.HourlyUSD * machine.EC2.MaxHours),
		}
		check.Requested += instance.VCPUs
		check.EstimatedUSD += instance.MaxUSD
		check.Instances = append(check.Instances, instance)
	}
	check.EstimatedUSD = roundCents(check.EstimatedUSD)
	check.Headroom = check.Quota - check.Requested
	check.Fits = check.Requested <= check.Quota
	return check
}

func roundCents(value float64) float64 { return math.Round(value*100) / 100 }

func (machine Machine) needsCorpus() bool {
	return machine.hasSuite(SuiteMacroRAR) || machine.hasSuite(SuiteMacroPAR2)
}

func (machine Machine) hasSuite(name string) bool { return contains(machine.Suites, name) }

func (machine Machine) families() []string {
	var families []string
	for _, suite := range []string{SuiteMacroPAR2, SuiteMacroRAR} {
		if machine.hasSuite(suite) {
			families = append(families, suiteFamilies[suite])
		}
	}
	return families
}

func (machine Machine) isWindows() bool { return machine.Connection.Shell == "powershell" }

// Select filters machines by name and suite, keeping configuration order.
func Select(config Config, machineNames, suites []string) ([]Machine, error) {
	var selected []Machine
	requested := map[string]bool{}
	for _, name := range machineNames {
		requested[name] = false
	}
	for _, machine := range config.Machines {
		if len(machineNames) > 0 {
			if _, ok := requested[machine.Name]; !ok {
				continue
			}
			requested[machine.Name] = true
		} else if !machine.Enabled {
			continue
		}
		if len(suites) > 0 {
			var kept []string
			for _, suite := range machine.Suites {
				if contains(suites, suite) {
					kept = append(kept, suite)
				}
			}
			if len(kept) == 0 {
				continue
			}
			machine.Suites = kept
		}
		selected = append(selected, machine)
	}
	var missing []string
	for name, found := range requested {
		if !found {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return nil, fmt.Errorf("no such machine(s) in the config: %s", strings.Join(missing, ", "))
	}
	for _, suite := range suites {
		if !contains(knownSuites, suite) {
			return nil, fmt.Errorf("unknown suite %q (known: %s)", suite, strings.Join(knownSuites, ", "))
		}
	}
	if len(selected) == 0 {
		return nil, fmt.Errorf("no machines selected")
	}
	return selected, nil
}

func contains(list []string, value string) bool {
	for _, item := range list {
		if item == value {
			return true
		}
	}
	return false
}

func isHexSHA256(value string) bool {
	if len(value) != 64 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

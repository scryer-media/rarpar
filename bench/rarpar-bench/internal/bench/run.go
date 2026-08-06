package bench

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"
)

type RunOptions struct {
	CorpusRoot     string
	Plan           Plan
	CandidatePath  string
	CandidateLabel string
	ReferenceRAR   string
	ReferencePAR2  string
	ReferenceLabel string
	Output         string
	MachineLabel   string
	Docker         string
	SourceManifest string
	SourceTarget   string
}

func Run(ctx context.Context, options RunOptions) (RunRecord, error) {
	if err := VerifyCorpus(options.CorpusRoot); err != nil {
		return RunRecord{}, err
	}
	candidate, err := identifyBinary(ctx, options.CandidatePath, options.CandidateLabel, false)
	if err != nil {
		return RunRecord{}, fmt.Errorf("candidate: %w", err)
	}
	if options.SourceManifest != "" || options.SourceTarget != "" {
		if options.SourceManifest == "" || options.SourceTarget == "" {
			return RunRecord{}, fmt.Errorf("source benchmarking requires both source manifest and source target")
		}
		revision, auditErr := auditSourceBuild(ctx, options)
		if auditErr != nil {
			return RunRecord{}, auditErr
		}
		candidate.SourceRevision = revision
	}
	var reference *BinaryIdentity
	var referencePAR2 *BinaryIdentity
	if options.ReferenceRAR != "" || options.ReferencePAR2 != "" {
		if options.ReferenceRAR == "" || options.ReferencePAR2 == "" {
			return RunRecord{}, fmt.Errorf("a comparative corpus run requires both reference RAR and reference PAR2 binaries")
		}
		identity, identityErr := identifyBinary(ctx, options.ReferenceRAR, options.ReferenceLabel, true)
		if identityErr != nil {
			return RunRecord{}, fmt.Errorf("reference: %w", identityErr)
		}
		par2Identity, par2IdentityErr := identifyBinary(ctx, options.ReferencePAR2, options.ReferenceLabel, true)
		if par2IdentityErr != nil {
			return RunRecord{}, fmt.Errorf("PAR2 reference: %w", par2IdentityErr)
		}
		reference = &identity
		referencePAR2 = &par2Identity
	}
	if err := ensureEmptyDir(options.Output); err != nil {
		return RunRecord{}, err
	}
	record := RunRecord{
		SchemaVersion: RunSchemaVersion,
		Plan:          options.Plan,
		CorpusDigest:  options.Plan.CorpusDigest,
		Machine:       CollectMachine(ctx, options.MachineLabel, options.Docker),
		Candidate:     candidate,
		Reference:     reference,
		ReferencePAR2: referencePAR2,
	}
	for _, planCase := range options.Plan.Cases {
		manifest, err := loadCase(options.CorpusRoot, planCase.ID, options.Plan.CorpusDigest)
		if err != nil {
			return RunRecord{}, err
		}
		for run := 0; run < options.Plan.Warmups+options.Plan.Repeats; run++ {
			warmup := run < options.Plan.Warmups
			if referenceRunsFirst(run, reference != nil) {
				referenceExecution := executeReference(ctx, *reference, manifest, options, run+1, warmup)
				record.Executions = append(record.Executions, referenceExecution)
				candidateExecution := executeSubject(ctx, "candidate", candidate.Label, options.CandidatePath, manifest, options, run+1, warmup)
				record.Executions = append(record.Executions, candidateExecution)
			} else {
				candidateExecution := executeSubject(ctx, "candidate", candidate.Label, options.CandidatePath, manifest, options, run+1, warmup)
				record.Executions = append(record.Executions, candidateExecution)
				if reference != nil {
					referenceExecution := executeReference(ctx, *reference, manifest, options, run+1, warmup)
					record.Executions = append(record.Executions, referenceExecution)
				}
			}
		}
	}
	if err := writeJSON(filepath.Join(options.Output, "raw.json"), record); err != nil {
		return RunRecord{}, err
	}
	failed := 0
	for _, execution := range record.Executions {
		if !execution.Success {
			failed++
		}
	}
	if failed > 0 {
		return record, fmt.Errorf("benchmark run recorded %d failed sample(s); inspect %s", failed, filepath.Join(options.Output, "raw.json"))
	}
	return record, nil
}

func referenceRunsFirst(run int, hasReference bool) bool {
	return hasReference && run%2 == 1
}

func loadCase(corpusRoot, id, corpusDigest string) (CorpusCaseManifest, error) {
	var manifest CorpusCaseManifest
	if err := readJSON(filepath.Join(corpusRoot, id, "manifest.json"), &manifest); err != nil {
		return CorpusCaseManifest{}, err
	}
	if manifest.ID != id || manifest.CorpusDigest != corpusDigest {
		return CorpusCaseManifest{}, fmt.Errorf("corpus case %q has incompatible provenance", id)
	}
	return manifest, nil
}

func identifyBinary(ctx context.Context, path, label string, allowNoArgumentBanner bool) (BinaryIdentity, error) {
	if path == "" {
		return BinaryIdentity{}, fmt.Errorf("binary path is required")
	}
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() {
		return BinaryIdentity{}, fmt.Errorf("binary is missing: %s", path)
	}
	if runtime.GOOS != "windows" && info.Mode()&0o111 == 0 {
		return BinaryIdentity{}, fmt.Errorf("binary is not executable: %s", path)
	}
	digest, err := fileSHA256(path)
	if err != nil {
		return BinaryIdentity{}, err
	}
	output, err := exec.CommandContext(ctx, path, "--version").CombinedOutput()
	usedNoArgumentBanner := false
	if err != nil && allowNoArgumentBanner {
		output, err = exec.CommandContext(ctx, path).CombinedOutput()
		usedNoArgumentBanner = true
	}
	if err != nil && strings.TrimSpace(string(output)) == "" {
		return BinaryIdentity{}, fmt.Errorf("identity probe failed: %w", err)
	}
	version := strings.TrimSpace(string(output))
	if usedNoArgumentBanner {
		version = firstNonEmptyLine(version)
	}
	if version == "" || strings.Contains(version, string(os.PathSeparator)) {
		return BinaryIdentity{}, fmt.Errorf("identity probe did not return a portable identity")
	}
	return BinaryIdentity{Label: label, Path: path, SHA256: digest, Version: version}, nil
}

func firstNonEmptyLine(value string) string {
	for _, line := range strings.Split(value, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			return line
		}
	}
	return ""
}

func executeSubject(ctx context.Context, role, label, binary string, manifest CorpusCaseManifest, options RunOptions, run int, warmup bool) Execution {
	stage, cleanup, err := stageCase(options.CorpusRoot, manifest, options.Output, role, run)
	if err != nil {
		return failedExecution(role, label, manifest, run, warmup, err)
	}
	successful := false
	defer os.Remove(filepath.Join(stage, "passwords.txt"))
	defer func() {
		if successful {
			cleanup()
		}
	}()
	args, err := candidateArguments(manifest, stage, options.Plan.Par2Placement)
	if err != nil {
		return failedExecution(role, label, manifest, run, warmup, err)
	}
	measurement, stdout, stderr, err := timedCommand(ctx, binary, args, stage, true)
	backend, fallback := backendFromLogs(options.Plan.Lane, string(stdout)+string(stderr))
	if err == nil && requiresValidation(manifest) {
		validationStart := time.Now()
		err = validateBenchmarkOutput(stage, manifest)
		measurement.ValidationNanos = DurationNanos(time.Since(validationStart))
	}
	if err != nil {
		return failedExecutionWithMeasurement(role, label, manifest, run, warmup, backend, fallback, measurement, commandFailure(err, stdout, stderr))
	}
	successful = true
	return Execution{Subject: label, Role: role, CaseID: manifest.ID, Family: manifest.Config.Family, Workload: manifest.Config.Workload, Run: run, Warmup: warmup, Success: true, CompiledCapability: options.Plan.Lane, Backend: backend, FallbackReason: fallback, Measurement: measurement}
}

func executeReference(ctx context.Context, reference BinaryIdentity, manifest CorpusCaseManifest, options RunOptions, run int, warmup bool) Execution {
	stage, cleanup, err := stageCase(options.CorpusRoot, manifest, options.Output, "reference", run)
	if err != nil {
		return failedExecution("reference", reference.Label, manifest, run, warmup, err)
	}
	successful := false
	defer func() {
		if successful {
			cleanup()
		}
	}()
	var binary string
	var args []string
	if manifest.Config.Family == "rar" {
		binary = options.ReferenceRAR
		args, err = referenceRARArguments(manifest, stage)
	} else {
		binary = options.ReferencePAR2
		args, err = referencePAR2Arguments(manifest, stage)
	}
	if err != nil {
		return failedExecution("reference", reference.Label, manifest, run, warmup, err)
	}
	measurement, stdout, stderr, err := timedCommand(ctx, binary, args, stage, false)
	if err == nil && requiresValidation(manifest) {
		validationStart := time.Now()
		err = validateBenchmarkOutput(stage, manifest)
		measurement.ValidationNanos = DurationNanos(time.Since(validationStart))
	}
	if err != nil {
		return failedExecutionWithMeasurement("reference", reference.Label, manifest, run, warmup, "reference", "", measurement, commandFailure(err, stdout, stderr))
	}
	successful = true
	return Execution{Subject: reference.Label, Role: "reference", CaseID: manifest.ID, Family: manifest.Config.Family, Workload: manifest.Config.Workload, Run: run, Warmup: warmup, Success: true, CompiledCapability: "reference", Backend: "reference", Measurement: measurement}
}

func stageCase(corpusRoot string, manifest CorpusCaseManifest, output, role string, run int) (string, func(), error) {
	stage := filepath.Join(output, "staging", fmt.Sprintf("%s-%02d-%s", manifest.ID, run, role))
	if err := ensureEmptyDir(stage); err != nil {
		return "", nil, err
	}
	if err := copyTree(filepath.Join(corpusRoot, manifest.ID, "source"), stage); err != nil {
		return "", nil, err
	}
	if err := applyMutation(stage, manifest); err != nil {
		return "", nil, err
	}
	return stage, func() { _ = os.RemoveAll(stage) }, nil
}

func applyMutation(stage string, manifest CorpusCaseManifest) error {
	switch manifest.Config.Mutation {
	case "none":
		return nil
	case "damage":
		archive, err := firstArchive(stage)
		if err != nil {
			return err
		}
		file, err := os.OpenFile(archive, os.O_RDWR, 0)
		if err != nil {
			return err
		}
		defer file.Close()
		if _, err := file.WriteAt([]byte{0x52, 0x50, 0x42, 0x01}, 32*1024); err != nil {
			return err
		}
		return file.Sync()
	case "heavy-damage":
		archive, err := firstArchive(stage)
		if err != nil {
			return err
		}
		info, err := os.Stat(archive)
		if err != nil {
			return err
		}
		sliceSize := manifest.Config.PAR2SliceSize
		totalSlices := (info.Size() + sliceSize - 1) / sliceSize
		if int64(manifest.Config.DamageCount+1) > totalSlices {
			return fmt.Errorf("heavy damage count exceeds available slices")
		}
		stride := totalSlices / int64(manifest.Config.DamageCount+1)
		file, err := os.OpenFile(archive, os.O_WRONLY, 0)
		if err != nil {
			return err
		}
		defer file.Close()
		damage := bytes.Repeat([]byte{0xA5}, manifest.Config.DamageBytesPerSite)
		for index := 0; index < manifest.Config.DamageCount; index++ {
			offset := stride*int64(index+1)*sliceSize + 100
			if offset+int64(len(damage)) > info.Size() {
				return fmt.Errorf("heavy damage site exceeds archive length")
			}
			if _, err := file.WriteAt(damage, offset); err != nil {
				return err
			}
		}
		return file.Sync()
	case "remove-volume":
		archive, err := removableArchive(stage, manifest.Config.RecoveryVolumes)
		if err != nil {
			return err
		}
		return os.Remove(archive)
	default:
		return fmt.Errorf("unsupported mutation %q", manifest.Config.Mutation)
	}
}

func candidateArguments(manifest CorpusCaseManifest, stage, par2Placement string) ([]string, error) {
	if manifest.Config.Family == "rar" {
		archive, err := firstArchive(stage)
		if err != nil {
			return nil, err
		}
		args := []string{"x", "-idp", "-o+"}
		if manifest.Config.Encrypted {
			args = append(args, "-p"+benchmarkPassword)
		}
		return append(args, archive, filepath.Join(stage, "out")), nil
	}
	if manifest.Config.Family == "par2" && manifest.Config.Mutation == "none" {
		main, err := mainPAR2(stage)
		if err != nil {
			return nil, err
		}
		return []string{"par", "verify", "--par-placement", par2Placement, main}, nil
	}
	main, err := mainPAR2(stage)
	if err != nil {
		return nil, err
	}
	return []string{"par", "repair", "--par-placement", par2Placement, main}, nil
}

func referenceRARArguments(manifest CorpusCaseManifest, stage string) ([]string, error) {
	archive, err := firstArchive(stage)
	if err != nil {
		return nil, err
	}
	args := []string{"x", "-y"}
	if manifest.Config.Encrypted {
		args = append(args, "-p"+benchmarkPassword)
	}
	destination := filepath.Join(stage, "out") + string(os.PathSeparator)
	return append(args, archive, destination), nil
}

func referencePAR2Arguments(manifest CorpusCaseManifest, stage string) ([]string, error) {
	main, err := mainPAR2(stage)
	if err != nil {
		return nil, err
	}
	if manifest.Config.Mutation == "none" {
		return []string{"v", main}, nil
	}
	return []string{"r", main}, nil
}

func mainPAR2(stage string) (string, error) {
	entries, err := os.ReadDir(stage)
	if err != nil {
		return "", err
	}
	var candidates []string
	for _, entry := range entries {
		name := strings.ToLower(entry.Name())
		if entry.Type().IsRegular() && strings.HasSuffix(name, ".par2") && !strings.Contains(name, ".vol") {
			candidates = append(candidates, filepath.Join(stage, entry.Name()))
		}
	}
	sort.Strings(candidates)
	if len(candidates) != 1 {
		return "", fmt.Errorf("expected one main PAR2 file, found %d", len(candidates))
	}
	return candidates[0], nil
}

func firstArchive(stage string) (string, error) {
	archives, err := rarVolumes(stage)
	if err != nil {
		return "", err
	}
	for _, archive := range archives {
		name := strings.ToLower(filepath.Base(archive))
		if strings.Contains(name, ".part1.") || strings.Contains(name, ".part01.") {
			return archive, nil
		}
	}
	if len(archives) > 0 {
		return archives[0], nil
	}
	return "", fmt.Errorf("first archive volume not found")
}

func removableArchive(stage string, middle bool) (string, error) {
	archives, err := rarVolumes(stage)
	if err != nil {
		return "", err
	}
	if len(archives) < 2 {
		return "", fmt.Errorf("second archive volume not found")
	}
	if middle {
		return archives[len(archives)/2], nil
	}
	return archives[1], nil
}

func rarVolumes(stage string) ([]string, error) {
	entries, err := os.ReadDir(stage)
	if err != nil {
		return nil, err
	}
	var archives []string
	for _, entry := range entries {
		name := strings.ToLower(entry.Name())
		if entry.Type().IsRegular() && (strings.HasSuffix(name, ".rar") || regexp.MustCompile(`\.r\d\d$`).MatchString(name)) {
			archives = append(archives, filepath.Join(stage, entry.Name()))
		}
	}
	sort.Strings(archives)
	return archives, nil
}

func requiresValidation(manifest CorpusCaseManifest) bool {
	return manifest.Config.Family == "rar" || manifest.Config.Mutation != "none"
}

func validateBenchmarkOutput(stage string, manifest CorpusCaseManifest) error {
	if manifest.Config.Family == "rar" {
		return validateExpected(filepath.Join(stage, "out"), manifest.Expected)
	}
	expected := make([]ExpectedFile, len(manifest.Sources))
	for index, source := range manifest.Sources {
		expected[index] = ExpectedFile{Path: source.Path, Bytes: source.Bytes, SHA256: source.SHA256}
	}
	return validateExpected(stage, expected)
}

func timedCommand(ctx context.Context, program string, args []string, directory string, candidate bool) (Measurement, []byte, []byte, error) {
	command := exec.CommandContext(ctx, program, args...)
	command.Dir = directory
	if candidate {
		command.Env = append(os.Environ(), "RUST_LOG=info")
	}
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	started := time.Now()
	err := command.Run()
	measurement := Measurement{WallNanos: DurationNanos(time.Since(started)), CollectorNote: "instruction collector unavailable: opt-in Linux perf is not enabled"}
	if command.ProcessState != nil {
		measurement.UserNanos = DurationNanos(command.ProcessState.UserTime())
		measurement.SystemNanos = DurationNanos(command.ProcessState.SystemTime())
	}
	return measurement, stdout.Bytes(), stderr.Bytes(), err
}

var backendPattern = regexp.MustCompile(`backend="?(metal|wgpu)"?`)

func backendFromLogs(lane, stderr string) (string, string) {
	if match := backendPattern.FindStringSubmatch(stderr); len(match) == 2 {
		return match[1], ""
	}
	if lane == "metal" || lane == "wgpu" {
		return "cpu", "GPU lane was compiled but no GPU repair engagement was reported"
	}
	return "cpu", ""
}

func failedExecution(role, label string, manifest CorpusCaseManifest, run int, warmup bool, err error) Execution {
	return failedExecutionWithMeasurement(role, label, manifest, run, warmup, "unknown", "", Measurement{}, err.Error())
}

func failedExecutionWithMeasurement(role, label string, manifest CorpusCaseManifest, run int, warmup bool, backend, fallback string, measurement Measurement, failure string) Execution {
	return Execution{Subject: label, Role: role, CaseID: manifest.ID, Family: manifest.Config.Family, Workload: manifest.Config.Workload, Run: run, Warmup: warmup, Success: false, CompiledCapability: "unknown", Backend: backend, FallbackReason: fallback, Measurement: measurement, Failure: failure}
}

func commandFailure(err error, stdout, stderr []byte) string {
	message := strings.TrimSpace(string(stderr))
	if message == "" {
		message = strings.TrimSpace(string(stdout))
	}
	message = strings.ReplaceAll(message, benchmarkPassword, "[redacted]")
	message = strings.ReplaceAll(message, "\n", " ")
	message = pathPattern.ReplaceAllString(message, "[path]")
	if len(message) > 400 {
		message = message[:400]
	}
	if message == "" {
		return err.Error()
	}
	return err.Error() + ": " + message
}

var pathPattern = regexp.MustCompile(`(?:[A-Za-z]:)?[/\\][^[:space:]]+`)

func auditSourceBuild(ctx context.Context, options RunOptions) (string, error) {
	workspace := commandLine(ctx, "git", "-C", filepath.Dir(options.SourceManifest), "rev-parse", "--show-toplevel")
	if workspace == "" {
		return "", fmt.Errorf("source benchmark must run from a Git checkout")
	}
	command := exec.CommandContext(ctx, "cargo", "run", "--locked", "-p", "xtask", "--", "feature-audit", "--manifest", options.SourceManifest, "--target", options.SourceTarget, "--features", "runtime")
	command.Dir = workspace
	if output, err := command.CombinedOutput(); err != nil {
		return "", fmt.Errorf("source feature audit failed: %w: %s", err, redactRuntimeText(string(output)))
	}
	revision := commandLine(ctx, "git", "-C", workspace, "rev-parse", "HEAD")
	if revision == "" {
		return "", fmt.Errorf("source benchmark must run from a Git checkout")
	}
	return revision, nil
}

func redactRuntimeText(value string) string {
	value = strings.ReplaceAll(value, benchmarkPassword, "[redacted]")
	return pathPattern.ReplaceAllString(value, "[path]")
}

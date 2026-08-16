package bench

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReferenceIdentityAcceptsNoArgumentBanner(t *testing.T) {
	path := filepath.Join(t.TempDir(), "reference.sh")
	script := "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then exit 7; fi\necho 'Reference 1.0'\necho 'Usage: reference <path\\\\>'\nexit 7\n"
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := identifyBinary(context.Background(), path, "reference", false); err == nil {
		t.Fatal("candidate identity unexpectedly accepted a no-argument banner")
	}
	identity, err := identifyBinary(context.Background(), path, "reference", true)
	if err != nil {
		t.Fatal(err)
	}
	if identity.Version != "Reference 1.0" {
		t.Fatalf("unexpected reference identity %q", identity.Version)
	}
}

func TestReferenceRARArgumentsUseDirectoryDestination(t *testing.T) {
	stage := t.TempDir()
	if err := os.WriteFile(filepath.Join(stage, "release.part01.rar"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	args, err := referenceRARArguments(CorpusCaseManifest{}, stage)
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(stage, "out") + string(os.PathSeparator)
	if got := args[len(args)-1]; got != want {
		t.Fatalf("destination = %q, want %q", got, want)
	}
}

func TestCandidateRARArgumentsUseDirectExtraction(t *testing.T) {
	stage := t.TempDir()
	archive := filepath.Join(stage, "release.part01.rar")
	if err := os.WriteFile(archive, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	args, err := candidateArguments(CorpusCaseManifest{Config: CaseConfig{Family: "rar"}}, stage, "canonical")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"x", "-idp", "-o+", archive, filepath.Join(stage, "out")}
	if got := strings.Join(args, "\x00"); got != strings.Join(want, "\x00") {
		t.Fatalf("candidate RAR arguments = %q, want %q", args, want)
	}
}

func TestCandidateArgumentsCarryPAR2PlacementPolicy(t *testing.T) {
	stage := t.TempDir()
	if err := os.WriteFile(filepath.Join(stage, "release.par2"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	verify, err := candidateArguments(CorpusCaseManifest{Config: CaseConfig{Family: "par2", Mutation: "none"}}, stage, "canonical")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := strings.Join(verify, "\x00"), strings.Join([]string{"par", "verify", "--par-placement", "canonical", filepath.Join(stage, "release.par2")}, "\x00"); got != want {
		t.Fatalf("verify arguments = %q, want %q", verify, want)
	}

	repair, err := candidateArguments(CorpusCaseManifest{Config: CaseConfig{Family: "par2", Mutation: "damage"}}, stage, "smart")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := strings.Join(repair, "\x00"), strings.Join([]string{"par", "repair", "--par-placement", "smart", filepath.Join(stage, "release.par2")}, "\x00"); got != want {
		t.Fatalf("repair arguments = %q, want %q", repair, want)
	}
}

func TestPAR2GenerationArgumentsUseMatchedInputs(t *testing.T) {
	stage := t.TempDir()
	for _, name := range []string{"release.part01.rar", "release.part02.rar"} {
		if err := os.WriteFile(filepath.Join(stage, name), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	manifest := CorpusCaseManifest{Config: CaseConfig{
		Family:              "par2",
		PAR2Operation:       "create",
		PAR2SliceSize:       65_536,
		PAR2RecoveryPercent: 20,
	}}
	candidate, err := candidateArguments(manifest, stage, "canonical")
	if err != nil {
		t.Fatal(err)
	}
	wantCandidate := []string{
		"--quiet", "par", "create",
		"--base-path", stage,
		"--block-size", "65536",
		"--recovery-percent", "20",
		par2GenerationOutput,
		"release.part01.rar", "release.part02.rar",
	}
	if got := strings.Join(candidate, "\x00"); got != strings.Join(wantCandidate, "\x00") {
		t.Fatalf("candidate generation arguments = %q, want %q", candidate, wantCandidate)
	}
	reference, err := referencePAR2Arguments(manifest, stage)
	if err != nil {
		t.Fatal(err)
	}
	wantReference := []string{
		"c", "-q", "-r20", "-s65536", par2GenerationOutput,
		"release.part01.rar", "release.part02.rar",
	}
	if got := strings.Join(reference, "\x00"); got != strings.Join(wantReference, "\x00") {
		t.Fatalf("reference generation arguments = %q, want %q", reference, wantReference)
	}
}

func TestPayloadGenerationIsDeterministic(t *testing.T) {
	first := filepath.Join(t.TempDir(), "first.bin")
	second := filepath.Join(t.TempDir(), "second.bin")
	firstDigest, err := writePayloadFile(first, "seed", "case", "payload/part.bin", 97_321)
	if err != nil {
		t.Fatal(err)
	}
	secondDigest, err := writePayloadFile(second, "seed", "case", "payload/part.bin", 97_321)
	if err != nil {
		t.Fatal(err)
	}
	firstBytes, err := os.ReadFile(first)
	if err != nil {
		t.Fatal(err)
	}
	secondBytes, err := os.ReadFile(second)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(firstBytes, secondBytes) || firstDigest != secondDigest {
		t.Fatal("deterministic payload generation changed")
	}
}

func TestToolchainLockRequiresPinnedSources(t *testing.T) {
	lock := validToolchainLock()
	if err := lock.Validate(); err != nil {
		t.Fatal(err)
	}
	lock.RARWriters[0].SHA256 = "not-a-digest"
	if err := lock.Validate(); err == nil {
		t.Fatal("unlocked RAR source was accepted")
	}
}

// The lock is shared by the benchmark and the test corpus, so it has to carry
// the complete writer set — all six RARLAB releases — and refuse any entry that
// is missing, duplicated, floating, or wrongly hashed.
func TestToolchainLockRequiresAllSixRARLABWriters(t *testing.T) {
	if len(RequiredRARWriters) != 6 {
		t.Fatalf("required writer set = %v, want six RARLAB releases", RequiredRARWriters)
	}
	for _, id := range []string{"rarlab-3.93", "rarlab-4.20", "rarlab-5.00", "rarlab-6.24", "rarlab-7.20", "rarlab-7.23"} {
		found := false
		for _, required := range RequiredRARWriters {
			found = found || required == id
		}
		if !found {
			t.Errorf("required writer set is missing %q", id)
		}
	}
	for _, required := range RequiredRARWriters {
		t.Run("missing "+required, func(t *testing.T) {
			lock := validToolchainLock()
			var kept []RARWriter
			for _, writer := range lock.RARWriters {
				if writer.ID != required {
					kept = append(kept, writer)
				}
			}
			lock.RARWriters = kept
			if err := lock.Validate(); err == nil || !strings.Contains(err.Error(), required) {
				t.Fatalf("lock without %s: err = %v", required, err)
			}
		})
	}
}

func TestToolchainLockRejectsDuplicateFloatingOrMishashedWriters(t *testing.T) {
	cases := map[string]func(*ToolchainLock){
		"duplicate id": func(lock *ToolchainLock) {
			lock.RARWriters = append(lock.RARWriters, lock.RARWriters[0])
		},
		"duplicate url under a new id": func(lock *ToolchainLock) {
			extra := lock.RARWriters[5]
			extra.ID = "rarlab-7.24"
			extra.Image = "rar724"
			extra.SHA256 = strings.Repeat("f", 64)
			extra.URL = lock.RARWriters[4].URL // rarlab-7.20's tarball
			lock.RARWriters = append(lock.RARWriters, extra)
		},
		"duplicate digest under a new id": func(lock *ToolchainLock) {
			extra := lock.RARWriters[5]
			extra.ID = "rarlab-7.24"
			extra.Image = "rar724"
			extra.URL = "https://www.rarlab.com/rar/rarlinux-x64-724.tar.gz"
			extra.SHA256 = lock.RARWriters[4].SHA256
			lock.RARWriters = append(lock.RARWriters, extra)
		},
		"floating unversioned url": func(lock *ToolchainLock) {
			lock.RARWriters[5].URL = "https://www.rarlab.com/rar/rarlinux-x64.tar.gz"
		},
		"url naming another release": func(lock *ToolchainLock) {
			lock.RARWriters[4].URL = "https://www.rarlab.com/rar/rarlinux-x64-723.tar.gz"
			lock.RARWriters[5].URL = "https://www.rarlab.com/rar/rarlinux-x64-720.tar.gz"
		},
		"non-rarlab host": func(lock *ToolchainLock) {
			lock.RARWriters[5].URL = "https://mirror.example.test/rar/rarlinux-x64-723.tar.gz"
		},
		"plain http": func(lock *ToolchainLock) {
			lock.RARWriters[5].URL = "http://www.rarlab.com/rar/rarlinux-x64-723.tar.gz"
		},
		"id without release": func(lock *ToolchainLock) {
			lock.RARWriters[5].ID = "rarlab-latest"
			lock.RARWriters = append(lock.RARWriters, RARWriter{ID: "rarlab-7.23", Image: "rar723", Platform: "linux/amd64", URL: "https://www.rarlab.com/rar/rarlinux-x64-723.tar.gz", SHA256: strings.Repeat("e", 64), Binary: "rar"})
		},
		"short digest": func(lock *ToolchainLock) {
			lock.RARWriters[3].SHA256 = strings.Repeat("a", 63)
		},
		"uppercase digest": func(lock *ToolchainLock) {
			lock.RARWriters[3].SHA256 = strings.Repeat("A", 64)
		},
		"wrong platform": func(lock *ToolchainLock) {
			lock.RARWriters[2].Platform = "linux/arm64"
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			lock := validToolchainLock()
			mutate(&lock)
			if err := lock.Validate(); err == nil {
				t.Fatalf("%s was accepted", name)
			}
		})
	}
}

// The checked-in lock is the one both corpora build from; it must carry the
// six verified RARLAB packages, each pinned to its published digest.
func TestCheckedInToolchainLockPinsTheSixRARLABPackages(t *testing.T) {
	lock, err := LoadToolchains(filepath.Join("..", "..", "config", "toolchains.json"))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]struct{ url, sha256, binary string }{
		"rarlab-3.93": {"https://www.rarlab.com/rar/rarlinux-3.9.3.tar.gz", "55122286a2a72ccc2b866c5a0e415c05638dfe99cebb5f2ef036784387a8eff8", "rar_static"},
		"rarlab-4.20": {"https://www.rarlab.com/rar/rarlinux-4.2.0.tar.gz", "6826646bc9620055689f465e61f7d4a86e6ccc66940178d24f48d01734968eb5", "rar_static"},
		"rarlab-5.00": {"https://www.rarlab.com/rar/rarlinux-5.0.0.tar.gz", "4f942d79bb16dc1981ccb52893e4a24dbee908089d783d766ac45cd4f2c78610", "rar_static"},
		"rarlab-6.24": {"https://www.rarlab.com/rar/rarlinux-x64-624.tar.gz", "88e22a8e84125c947637bbf28c746e338a0a63279d80f9f9d7373603875db1eb", "rar"},
		"rarlab-7.20": {"https://www.rarlab.com/rar/rarlinux-x64-720.tar.gz", "d3e7fba3272385b1d0255ee332a1e8c1a6779bb5a5ff9d4d8ac2be846e49ca46", "rar"},
		"rarlab-7.23": {"https://www.rarlab.com/rar/rarlinux-x64-723.tar.gz", "759b4b6aa0d9f77131882162951193f3a0e54bf60e1d8dc4255aa308accab588", "rar"},
	}
	if len(lock.RARWriters) != len(want) {
		t.Fatalf("lock has %d writers, want %d", len(lock.RARWriters), len(want))
	}
	for id, expected := range want {
		writer, found := lock.Writer(id)
		if !found {
			t.Errorf("lock is missing %s", id)
			continue
		}
		if writer.URL != expected.url || writer.SHA256 != expected.sha256 || writer.Binary != expected.binary {
			t.Errorf("%s = %+v, want %+v", id, writer, expected)
		}
	}
}

func TestCorpusConfigRejectsMutatedCaseWithoutRecovery(t *testing.T) {
	config := validCorpusConfig()
	config.Cases[0].Mutation = "damage"
	if err := config.Validate(); err == nil {
		t.Fatal("damaged case without recovery material was accepted")
	}
}

func TestCorpusConfigAllowsCleanPAR2GenerationWithoutParity(t *testing.T) {
	config := validCorpusConfig()
	config.Cases[0] = CaseConfig{
		ID:                  "create",
		Family:              "par2",
		Writer:              "rarlab-5.00",
		Format:              5,
		PAR2Operation:       "create",
		PAR2SliceSize:       65_536,
		PAR2RecoveryPercent: 20,
		Mutation:            "none",
		Workload:            "PAR2 generation",
	}
	if err := config.Validate(); err != nil {
		t.Fatalf("clean PAR2 generation was rejected: %v", err)
	}
	config.Cases[0].PAR2RecoveryPercent = 0
	if err := config.Validate(); err == nil {
		t.Fatal("PAR2 generation without an explicit recovery percent was accepted")
	}
	config.Cases[0].PAR2RecoveryPercent = 20
	config.Cases[0].PAR2 = true
	if err := config.Validate(); err == nil {
		t.Fatal("PAR2 generation with pre-existing parity was accepted")
	}
}

func TestCorpusConfigRejectsPPMdOutsideRAR4(t *testing.T) {
	config := validCorpusConfig()
	config.Cases[0].PPMd = true
	if err := config.Validate(); err == nil {
		t.Fatal("PPMd outside RAR4 was accepted")
	}
}

func TestCorpusConfigRequiresEncryptionForEncryptedHeaders(t *testing.T) {
	config := validCorpusConfig()
	config.Cases[0].HeaderEncrypted = true
	if err := config.Validate(); err == nil {
		t.Fatal("header encryption without file encryption was accepted")
	}
	config.Cases[0].Encrypted = true
	if err := config.Validate(); err != nil {
		t.Fatalf("header encryption was rejected: %v", err)
	}
}

func TestCorpusConfigRequiresTextForPPMd(t *testing.T) {
	config := validCorpusConfig()
	config.Cases[0].Format = 4
	config.Cases[0].PPMd = true
	if err := config.Validate(); err == nil {
		t.Fatal("binary PPMd case was accepted")
	}
	config.Cases[0].PayloadProfile = "text"
	if err := config.Validate(); err != nil {
		t.Fatalf("text PPMd case was rejected: %v", err)
	}
}

func TestTextPayloadGenerationIsDeterministic(t *testing.T) {
	first := filepath.Join(t.TempDir(), "first.txt")
	second := filepath.Join(t.TempDir(), "second.txt")
	firstDigest, err := writePayloadFileWithProfile(first, "seed", "case", "payload/part.txt", 97_321, "text")
	if err != nil {
		t.Fatal(err)
	}
	secondDigest, err := writePayloadFileWithProfile(second, "seed", "case", "payload/part.txt", 97_321, "text")
	if err != nil {
		t.Fatal(err)
	}
	firstBytes, err := os.ReadFile(first)
	if err != nil {
		t.Fatal(err)
	}
	secondBytes, err := os.ReadFile(second)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(firstBytes, secondBytes) || firstDigest != secondDigest || !bytes.Contains(firstBytes, []byte("archive ")) {
		t.Fatal("deterministic text payload generation changed")
	}
}

func TestImportedFixtureDigestIsPinned(t *testing.T) {
	harnessRoot := t.TempDir()
	fixtureRoot := filepath.Join(harnessRoot, "fixture")
	if err := os.Mkdir(fixtureRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fixtureRoot, "case.rar"), []byte("rar"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fixtureRoot, "case.r00"), []byte("volume"), 0o644); err != nil {
		t.Fatal(err)
	}
	manifest, err := sourceManifest(fixtureRoot)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := canonicalJSON(manifest)
	if err != nil {
		t.Fatal(err)
	}
	item := CaseConfig{ID: "case", FixtureDir: "fixture", FixturePrefix: "case", FixtureSHA256: bytesSHA256(encoded)}
	workRoot := t.TempDir()
	if err := importFixture(workRoot, harnessRoot, item); err != nil {
		t.Fatal(err)
	}
	item.FixtureSHA256 = strings.Repeat("0", 64)
	if err := importFixture(t.TempDir(), harnessRoot, item); err == nil {
		t.Fatal("fixture digest mismatch was accepted")
	}
}

func TestHeavyDamageMutationUsesConfiguredSliceCount(t *testing.T) {
	stage := t.TempDir()
	archive := filepath.Join(stage, "release.rar")
	if err := os.WriteFile(archive, make([]byte, 20*1024), 0o644); err != nil {
		t.Fatal(err)
	}
	manifest := CorpusCaseManifest{Config: CaseConfig{
		Mutation:           "heavy-damage",
		DamageCount:        3,
		DamageBytesPerSite: 8,
		PAR2SliceSize:      1024,
	}}
	if err := applyMutation(stage, manifest); err != nil {
		t.Fatal(err)
	}
	contents, err := os.ReadFile(archive)
	if err != nil {
		t.Fatal(err)
	}
	for _, slice := range []int{5, 10, 15} {
		if got := contents[slice*1024+100 : slice*1024+108]; !bytes.Equal(got, bytes.Repeat([]byte{0xA5}, 8)) {
			t.Fatalf("slice %d was not damaged at the configured offset", slice)
		}
	}
}

func TestPlanOrderIsStable(t *testing.T) {
	ids := []string{"third", "first", "second"}
	first := deterministicOrder(ids, "seed")
	second := deterministicOrder(ids, "seed")
	if strings.Join(first, ",") != strings.Join(second, ",") {
		t.Fatal("plan order is not stable")
	}
}

func TestBenchmarkPairsAlternateWhichSubjectRunsFirst(t *testing.T) {
	if referenceRunsFirst(0, true) || !referenceRunsFirst(1, true) || referenceRunsFirst(1, false) {
		t.Fatal("benchmark pair order did not alternate deterministically")
	}
}

func TestRenderSVGIsDeterministicAndEscapesInput(t *testing.T) {
	report := fixtureReport()
	first, err := renderSVG(report, "rar", report.Comparisons)
	if err != nil {
		t.Fatal(err)
	}
	second, err := renderSVG(report, "rar", report.Comparisons)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("SVG output is not byte deterministic")
	}
	const goldenRARSVG = "2310e543c37b6238a5b8b541e50e525b424a63e6bcdbdd3094dc3191cff0b8e6"
	if got := bytesSHA256(first); got != goldenRARSVG {
		t.Fatalf("RAR SVG changed: got %s, want %s", got, goldenRARSVG)
	}
	for _, required := range []string{"<svg", "role=\"img\"", "1x parity", "&lt;unsafe&gt;", "report_sha256=report-digest", "collector=wall-clock", "par2_placement=canonical"} {
		if !strings.Contains(string(first), required) {
			t.Fatalf("SVG does not contain %q", required)
		}
	}
	if strings.Contains(string(first), "<unsafe>") {
		t.Fatal("SVG text was not escaped")
	}
}

func TestRenderPAR2SVGGolden(t *testing.T) {
	report := fixtureReport()
	report.Comparisons[0].Family = "par2"
	report.Comparisons[0].ReferenceLabel = "par2cmdline-turbo"
	chart, err := renderSVG(report, "par2", report.Comparisons)
	if err != nil {
		t.Fatal(err)
	}
	const goldenPAR2SVG = "48aaff49972f585f4fb80d78c0c9dc9b2a25c430bbd881aa3e56c9cdfa36f045"
	if got := bytesSHA256(chart); got != goldenPAR2SVG {
		t.Fatalf("PAR2 SVG changed: got %s, want %s", got, goldenPAR2SVG)
	}
}

func TestRenderSVGLegendIsFamilySpecific(t *testing.T) {
	rar, err := renderSVG(fixtureReport(), "rar", fixtureReport().Comparisons)
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		`<text class="tick" x="752.5" y="310" text-anchor="middle">UnRAR faster</text>`,
		`<text class="tick" x="1017.5" y="310" text-anchor="middle">rarpar faster</text>`,
		`<rect class="slower" x="570" y="84" width="14" height="14" rx="2"/><text class="subtitle" x="592" y="96">UnRAR faster</text>`,
		`<rect class="cpu" x="890" y="84" width="14" height="14" rx="2"/><text class="subtitle" x="912" y="96">rarpar / CPU</text>`,
	} {
		if strings.Contains(string(rar), "rarpar / GPU") || !strings.Contains(string(rar), required) {
			t.Fatalf("RAR direction labels are incorrect: %s", rar)
		}
	}
	report := fixtureReport()
	report.Comparisons[0].Family = "par2"
	report.Comparisons[0].ReferenceLabel = "par2cmdline-turbo"
	par2, err := renderSVG(report, "par2", report.Comparisons)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(par2), "rarpar / GPU") {
		t.Fatalf("unexpected GPU legend: %s", par2)
	}
	for _, required := range []string{`<text class="tick" x="752.5" y="310" text-anchor="middle">par2cmdline-turbo faster</text>`, `<text class="tick" x="1017.5" y="310" text-anchor="middle">rarpar faster</text>`, "<rect class=\"slower\" x=\"570\"", "<rect class=\"cpu\" x=\"890\""} {
		if !strings.Contains(string(par2), required) {
			t.Fatalf("PAR2 legend does not contain %q", required)
		}
	}
}

func TestRenderSVGOrdersFastestRarparWorkloadsFirst(t *testing.T) {
	report := fixtureReport()
	report.Plan.Cases = []PlanCase{{ID: "unrar-fast", Order: 1}, {ID: "rarpar-fast", Order: 2}}
	report.Comparisons = []Comparison{
		{CaseID: "unrar-fast", Family: "rar", Workload: "UnRAR fastest", Ratio: 0.5},
		{CaseID: "rarpar-fast", Family: "rar", Workload: "rarpar fastest", Ratio: 2},
	}
	chart, err := renderSVG(report, "rar", report.Comparisons)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Index(string(chart), "rarpar fastest") > strings.Index(string(chart), "UnRAR fastest") {
		t.Fatalf("workloads were not ordered by rarpar relative speed: %s", chart)
	}
}

func TestRenderComparableCPUAndGPULanes(t *testing.T) {
	cpu := fixtureReport()
	cpu.Plan.Lane = "cpu"
	cpu.Plan.ID = "cpu-plan"
	cpu.InputSHA256 = strings.Repeat("a", 64)
	cpu.Candidate.SHA256 = strings.Repeat("b", 64)
	cpu.Comparisons[0].Family = "par2"
	cpu.Comparisons[0].ReferenceLabel = "par2cmdline-turbo"

	gpu := fixtureReport()
	gpu.Plan.Lane = "wgpu"
	gpu.Plan.ID = "wgpu-plan"
	gpu.InputSHA256 = strings.Repeat("c", 64)
	gpu.Candidate.SHA256 = strings.Repeat("d", 64)
	gpu.Comparisons[0].Family = "par2"
	gpu.Comparisons[0].ReferenceLabel = "par2cmdline-turbo"
	gpu.Comparisons[0].Backend = "wgpu"

	chart, err := renderSVGGroups("par2", []chartGroup{
		{report: cpu, comparisons: cpu.Comparisons},
		{report: gpu, comparisons: gpu.Comparisons},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"/ cpu /", "/ wgpu /", "rarpar / GPU", "class=\"gpu\"", cpu.Candidate.SHA256, gpu.Candidate.SHA256} {
		if !strings.Contains(string(chart), required) {
			t.Fatalf("combined chart does not contain %q", required)
		}
	}
}

func TestRenderChartSetRejectsCollectorModesAcrossFamilies(t *testing.T) {
	rar := fixtureReport()
	rar.CollectorMode = wallClockCollector
	rar.Comparisons[0].Family = "rar"

	par2 := fixtureReport()
	par2.CollectorMode = perfStatCollector
	par2.Comparisons[0].Family = "par2"

	_, err := RenderChartSet([]Report{rar, par2}, filepath.Join(t.TempDir(), "charts"))
	if err == nil || !strings.Contains(err.Error(), "same collector mode") {
		t.Fatalf("mixed collector modes error = %v", err)
	}
}

func TestRenderChartSetRejectsUnsupportedCollectorMode(t *testing.T) {
	report := fixtureReport()
	report.CollectorMode = ""

	_, err := RenderChartSet([]Report{report}, filepath.Join(t.TempDir(), "charts"))
	if err == nil || !strings.Contains(err.Error(), "unsupported benchmark collector mode") {
		t.Fatalf("unsupported collector mode error = %v", err)
	}
}

func TestRenderRejectsMixedCollectorModes(t *testing.T) {
	wallClock := fixtureReport()
	perf := fixtureReport()
	perf.CollectorMode = perfStatCollector
	err := validateChartGroups("rar", []chartGroup{
		{report: wallClock, comparisons: wallClock.Comparisons},
		{report: perf, comparisons: perf.Comparisons},
	})
	if err == nil || !strings.Contains(err.Error(), "collector mode") {
		t.Fatalf("mixed collector modes were accepted: %v", err)
	}
}

func TestChartSummaryDoesNotSerializeOutputPath(t *testing.T) {
	dir := t.TempDir()
	if _, err := RenderCharts(fixtureReport(), dir); err != nil {
		t.Fatal(err)
	}
	summary, err := os.ReadFile(filepath.Join(dir, "chart-summary.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(summary), dir) || !strings.Contains(string(summary), "rarpar-rar-benchmark.svg") {
		t.Fatalf("chart summary contains an unsafe or missing chart path: %s", summary)
	}
}

func TestReportOmitsUnmatchedOrFailedSamples(t *testing.T) {
	dir := t.TempDir()
	raw := fixtureRunRecord()
	raw.Executions = raw.Executions[:1]
	path := filepath.Join(dir, "raw.json")
	if err := writeJSON(path, raw); err != nil {
		t.Fatal(err)
	}
	report, err := BuildReport(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Comparisons) != 0 || len(report.Omitted) != 1 {
		t.Fatalf("unmatched samples should be omitted: %#v", report)
	}
}

func TestRunRecordNeverSerializesBenchmarkPassword(t *testing.T) {
	raw := fixtureRunRecord()
	encoded, err := json.Marshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), benchmarkPassword) {
		t.Fatal("benchmark password leaked into artifact")
	}
}

func TestFailureDiagnosticsRedactPasswordsAndPaths(t *testing.T) {
	message := commandFailure(os.ErrPermission, nil, []byte("failed /tmp/private "+benchmarkPassword))
	if strings.Contains(message, benchmarkPassword) || strings.Contains(message, "/tmp/private") {
		t.Fatalf("unsafe diagnostic: %s", message)
	}
}

func TestAuditFeaturesFollowBenchmarkLane(t *testing.T) {
	tests := map[string]string{
		"cpu":        "runtime",
		"docker-cpu": "runtime",
		"metal":      "runtime,metal",
	}
	for lane, expected := range tests {
		actual, err := auditFeaturesForLane(lane)
		if err != nil || actual != expected {
			t.Fatalf("lane %q: features=%q err=%v", lane, actual, err)
		}
	}
	if _, err := auditFeaturesForLane("unknown"); err == nil {
		t.Fatal("unknown lane must fail source audit")
	}
	if _, err := auditFeaturesForLane("wgpu"); err == nil {
		t.Fatal("disabled WGPU lane must fail source audit")
	}
}

func TestBackendDetectionIgnoresAnsiFormatting(t *testing.T) {
	log := "\x1b[3mbackend\x1b[0m\x1b[2m=\x1b[0m\x1b[32m\"wgpu\"\x1b[0m"
	backend, fallback := backendFromLogs("wgpu", log)
	if backend != "wgpu" || fallback != "" {
		t.Fatalf("backend=%q fallback=%q", backend, fallback)
	}
}

func TestRAR5PhaseEvidenceSerializesOptionalFields(t *testing.T) {
	staging := int64(12_345)
	measurement := Measurement{RAR5Phases: &RAR5PhaseEvidence{
		StagingNanos:      &staging,
		UnavailableReason: "header scan was not emitted",
	}}
	encoded, err := json.Marshal(measurement)
	if err != nil {
		t.Fatal(err)
	}
	serialized := string(encoded)
	for _, required := range []string{`"staging_nanos":12345`, `"unavailable_reason":"header scan was not emitted"`} {
		if !strings.Contains(serialized, required) {
			t.Fatalf("phase evidence did not serialize %q: %s", required, serialized)
		}
	}
	if strings.Contains(serialized, `"header_scan_nanos":0`) {
		t.Fatalf("missing phase was serialized as zero: %s", serialized)
	}
	var decoded Measurement
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.RAR5Phases == nil || decoded.RAR5Phases.StagingNanos == nil || *decoded.RAR5Phases.StagingNanos != staging {
		t.Fatalf("phase evidence did not round-trip: %#v", decoded.RAR5Phases)
	}
}

func TestRAR5PhaseDiagnosticsMissingHasReason(t *testing.T) {
	evidence := collectRAR5PhaseDiagnostics([]byte("ordinary output\n"), []byte("ordinary logs\n"))
	if evidence == nil || evidence.UnavailableReason == "" {
		t.Fatalf("missing phase diagnostics did not carry a reason: %#v", evidence)
	}
	if evidence.StagingNanos != nil || evidence.HeaderScanNanos != nil || evidence.WorkerDecodeNanos != nil || evidence.SerialApplyNanos != nil {
		t.Fatalf("missing phase diagnostics fabricated values: %#v", evidence)
	}
	if !strings.Contains(evidence.UnavailableReason, "product hook required") {
		t.Fatalf("unexpected missing-phase reason: %q", evidence.UnavailableReason)
	}
}

func TestRAR5PhaseDiagnosticsAcceptStdoutStderrZeroAndDuplicates(t *testing.T) {
	stdout := []byte(strings.Join([]string{
		`RARPAR_BENCH_PHASE {"phase":"staging","nanos":10}`,
		`RARPAR_BENCH_PHASE {"phase":"worker_decode","nanos":30}`,
	}, "\n"))
	stderr := []byte(strings.Join([]string{
		`RARPAR_BENCH_PHASE {"phase":"staging","nanos":5}`,
		`RARPAR_BENCH_PHASE {"phase":"header_scan","nanos":0}`,
		`RARPAR_BENCH_PHASE {"phase":"serial_apply","nanos":40}`,
	}, "\n"))
	evidence := collectRAR5PhaseDiagnostics(stdout, stderr)
	if evidence.UnavailableReason != "" {
		t.Fatalf("valid diagnostics were rejected: %q", evidence.UnavailableReason)
	}
	for name, result := range map[string]struct {
		actual *int64
		want   int64
	}{
		"staging":       {evidence.StagingNanos, 15},
		"header_scan":   {evidence.HeaderScanNanos, 0},
		"worker_decode": {evidence.WorkerDecodeNanos, 30},
		"serial_apply":  {evidence.SerialApplyNanos, 40},
	} {
		if result.actual == nil || *result.actual != result.want {
			t.Fatalf("%s = %v, want %d", name, result.actual, result.want)
		}
	}
}

func TestRAR5PhaseDiagnosticsRejectDuplicateOverflow(t *testing.T) {
	markers := []byte(strings.Join([]string{
		`RARPAR_BENCH_PHASE {"phase":"worker_decode","nanos":9223372036854775807}`,
		`RARPAR_BENCH_PHASE {"phase":"worker_decode","nanos":1}`,
	}, "\n"))
	evidence := collectRAR5PhaseDiagnostics(markers, nil)
	if evidence.UnavailableReason == "" || !strings.Contains(evidence.UnavailableReason, "overflow") {
		t.Fatalf("overflow did not produce controlled unavailable evidence: %#v", evidence)
	}
	if evidence.StagingNanos != nil || evidence.HeaderScanNanos != nil || evidence.WorkerDecodeNanos != nil || evidence.SerialApplyNanos != nil {
		t.Fatalf("overflow retained wrapped or partial values: %#v", evidence)
	}
}

func TestRAR5PhaseDiagnosticsRejectMalformedAndUnknownMarkers(t *testing.T) {
	tests := map[string]string{
		"malformed": `RARPAR_BENCH_PHASE {`,
		"unknown":   `RARPAR_BENCH_PHASE {"phase":"other","nanos":1}`,
		"negative":  `RARPAR_BENCH_PHASE {"phase":"staging","nanos":-1}`,
	}
	for name, marker := range tests {
		t.Run(name, func(t *testing.T) {
			evidence := collectRAR5PhaseDiagnostics([]byte(marker), nil)
			if evidence.UnavailableReason == "" {
				t.Fatalf("invalid marker was accepted: %#v", evidence)
			}
			if evidence.StagingNanos != nil || evidence.HeaderScanNanos != nil || evidence.WorkerDecodeNanos != nil || evidence.SerialApplyNanos != nil {
				t.Fatalf("invalid marker retained partial values: %#v", evidence)
			}
		})
	}
}

func TestRAR5PhaseEnvironmentIsWarmupOnly(t *testing.T) {
	t.Setenv(phaseDiagnosticEnv, "inherited")
	value := func(environment []string) (string, bool) {
		for _, item := range environment {
			name, value, _ := strings.Cut(item, "=")
			if strings.EqualFold(name, phaseDiagnosticEnv) {
				return value, true
			}
		}
		return "", false
	}
	if _, found := value(benchmarkCommandEnvironment(true, false)); found {
		t.Fatal("measured candidate inherited phase diagnostics")
	}
	if _, found := value(benchmarkCommandEnvironment(false, true)); found {
		t.Fatal("reference execution enabled phase diagnostics")
	}
	if actual, found := value(benchmarkCommandEnvironment(true, true)); !found || actual != "1" {
		t.Fatalf("candidate warmup phase environment = %q, present=%v", actual, found)
	}
}

func TestCommandFailureFiltersPhaseMarkers(t *testing.T) {
	stdout := []byte("ordinary stdout\nRARPAR_BENCH_PHASE {\"phase\":\"staging\",\"nanos\":1}\n")
	stderr := []byte("RARPAR_BENCH_PHASE {malformed}\nordinary stderr\n")
	message := commandFailure(os.ErrPermission, stdout, stderr)
	if strings.Contains(message, phaseDiagnosticPrefix) || strings.Contains(message, "malformed") {
		t.Fatalf("phase marker leaked into failure text: %s", message)
	}
	if !strings.Contains(message, "ordinary stderr") {
		t.Fatalf("ordinary error text was removed: %s", message)
	}
	stdoutMessage := commandFailure(os.ErrPermission, stdout, []byte("RARPAR_BENCH_PHASE {malformed}\n"))
	if strings.Contains(stdoutMessage, phaseDiagnosticPrefix) || !strings.Contains(stdoutMessage, "ordinary stdout") {
		t.Fatalf("stdout phase filtering changed ordinary diagnostics: %s", stdoutMessage)
	}
}

func TestRAR5PhaseReportingUsesSuccessfulWarmupsAndIsDeterministic(t *testing.T) {
	stagingFirst := int64(10)
	stagingSecond := int64(30)
	headerFirst := int64(20)
	headerSecond := int64(40)
	workerFirst := int64(50)
	applyFirst := int64(60)
	measuredOnly := int64(9_999)
	raw := fixtureRunRecord()
	raw.Plan.Warmups = 2
	raw.Executions[0].Measurement.RAR5Phases = &RAR5PhaseEvidence{StagingNanos: &measuredOnly}
	raw.Executions = append(raw.Executions,
		Execution{Subject: "rarpar", Role: "candidate", CaseID: "case-1", Family: "rar", Workload: "RAR <unsafe>", Run: 1, Warmup: true, Success: true, Backend: "cpu", Measurement: Measurement{RAR5Phases: &RAR5PhaseEvidence{
			StagingNanos: &stagingFirst, HeaderScanNanos: &headerFirst, WorkerDecodeNanos: &workerFirst, SerialApplyNanos: &applyFirst,
		}}},
		Execution{Subject: "rarpar", Role: "candidate", CaseID: "case-1", Family: "rar", Workload: "RAR <unsafe>", Run: 2, Warmup: true, Success: true, Backend: "cpu", Measurement: Measurement{RAR5Phases: &RAR5PhaseEvidence{
			StagingNanos: &stagingSecond, HeaderScanNanos: &headerSecond, UnavailableReason: "worker decode was not emitted",
		}}},
		Execution{Subject: "rarpar", Role: "candidate", CaseID: "case-1", Family: "rar", Workload: "RAR <unsafe>", Run: 3, Warmup: true, Success: false, Backend: "cpu", Measurement: Measurement{RAR5Phases: &RAR5PhaseEvidence{StagingNanos: &measuredOnly}}},
	)
	dir := t.TempDir()
	path := filepath.Join(dir, "raw.json")
	if err := writeJSON(path, raw); err != nil {
		t.Fatal(err)
	}
	left, err := BuildReport(path)
	if err != nil {
		t.Fatal(err)
	}
	right, err := BuildReport(path)
	if err != nil {
		t.Fatal(err)
	}
	leftJSON, err := json.Marshal(left)
	if err != nil {
		t.Fatal(err)
	}
	rightJSON, err := json.Marshal(right)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(leftJSON, rightJSON) {
		t.Fatal("phase report JSON is not deterministic")
	}
	if left.Comparisons[0].Candidate.Median != 500_000_000 {
		t.Fatalf("warmup timing entered the comparison: %#v", left.Comparisons[0].Candidate)
	}
	phases := left.Comparisons[0].CandidateRAR5Phases
	if phases == nil || phases.Staging == nil || phases.Staging.Count != 2 || phases.Staging.Median != 20 {
		t.Fatalf("phase summary was not reported: %#v", left.Comparisons[0])
	}
	if phases.WorkerDecode == nil || phases.WorkerDecode.Count != 1 || phases.WorkerDecode.Median != 50 {
		t.Fatalf("partial phase samples were not summarized: %#v", phases)
	}
	if !strings.Contains(phases.UnavailableReason, "worker decode was not emitted") || !strings.Contains(phases.UnavailableReason, "missing successful samples") {
		t.Fatalf("phase summary lost unavailable reason: %#v", phases)
	}
}

func TestLegacyRawAndReportJSONRemainPhaseCompatible(t *testing.T) {
	raw := fixtureRunRecord()
	encodedRaw, err := json.Marshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encodedRaw), "rar5_phases") {
		t.Fatalf("legacy raw fixture unexpectedly contains phase evidence: %s", encodedRaw)
	}
	dir := t.TempDir()
	rawPath := filepath.Join(dir, "raw.json")
	if err := os.WriteFile(rawPath, encodedRaw, 0o644); err != nil {
		t.Fatal(err)
	}
	report, err := BuildReport(rawPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Comparisons) != 1 || report.Comparisons[0].CandidateRAR5Phases != nil {
		t.Fatalf("legacy raw evidence produced a phase summary: %#v", report.Comparisons)
	}
	encodedReport, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encodedReport), "candidate_rar5_phases") {
		t.Fatalf("legacy report unexpectedly contains phase summary: %s", encodedReport)
	}
	var decoded Report
	if err := json.Unmarshal(encodedReport, &decoded); err != nil {
		t.Fatal(err)
	}
	if len(decoded.Comparisons) != 1 || decoded.Comparisons[0].CandidateRAR5Phases != nil {
		t.Fatalf("legacy report did not round-trip compatibly: %#v", decoded.Comparisons)
	}
}

func validToolchainLock() ToolchainLock {
	digest := strings.Repeat("a", 64)
	// Every writer needs its own digest: the lock rejects two writers that
	// claim one archive.
	writerDigest := func(index int) string { return strings.Repeat(string(rune('a'+index)), 64) }
	return ToolchainLock{
		SchemaVersion: 1,
		DockerBase:    "debian@sha256:" + digest,
		RARWriters: []RARWriter{
			{ID: "rarlab-3.93", Image: "rar3", Platform: "linux/amd64", URL: "https://www.rarlab.com/rar/rarlinux-3.9.3.tar.gz", SHA256: writerDigest(0), Binary: "rar_static"},
			{ID: "rarlab-4.20", Image: "rar4", Platform: "linux/amd64", URL: "https://www.rarlab.com/rar/rarlinux-4.2.0.tar.gz", SHA256: writerDigest(1), Binary: "rar_static"},
			{ID: "rarlab-5.00", Image: "rar5", Platform: "linux/amd64", URL: "https://www.rarlab.com/rar/rarlinux-5.0.0.tar.gz", SHA256: writerDigest(2), Binary: "rar"},
			{ID: "rarlab-6.24", Image: "rar6", Platform: "linux/amd64", URL: "https://www.rarlab.com/rar/rarlinux-x64-624.tar.gz", SHA256: writerDigest(3), Binary: "rar"},
			{ID: "rarlab-7.20", Image: "rar720", Platform: "linux/amd64", URL: "https://www.rarlab.com/rar/rarlinux-x64-720.tar.gz", SHA256: writerDigest(4), Binary: "rar"},
			{ID: "rarlab-7.23", Image: "rar7", Platform: "linux/amd64", URL: "https://www.rarlab.com/rar/rarlinux-x64-723.tar.gz", SHA256: writerDigest(5), Binary: "rar"},
		},
		PAR2Generator: PAR2Generator{ID: "par2", Image: "par2", Platform: "linux/amd64", URL: "https://example.test/par2", SHA256: digest},
	}
}

func validCorpusConfig() CorpusConfig {
	return CorpusConfig{SchemaVersion: 1, ID: "test", Seed: "seed", PayloadBytes: 1024, VolumeSize: "1m", PAR2RedundancyPercent: 10, Cases: []CaseConfig{{ID: "rar", Family: "rar", Writer: "rarlab-5.00", Format: 5, Mutation: "none", Workload: "RAR"}}}
}

func fixtureRunRecord() RunRecord {
	plan := Plan{SchemaVersion: PlanSchemaVersion, ID: "plan-1", CorpusDigest: "corpus-digest", Seed: "seed", Warmups: 0, Repeats: 1, Lane: "cpu", Par2Placement: "canonical", Cases: []PlanCase{{ID: "case-1", Order: 1}}}
	return RunRecord{SchemaVersion: 1, CollectorMode: wallClockCollector, Plan: plan, CorpusDigest: "corpus-digest", Machine: Machine{Label: "test-machine", Architecture: "arm64"}, Candidate: BinaryIdentity{Label: "rarpar", SHA256: "candidate"}, Reference: &BinaryIdentity{Label: "reference", SHA256: "reference"}, Executions: []Execution{
		{Subject: "rarpar", Role: "candidate", CaseID: "case-1", Family: "rar", Workload: "RAR <unsafe>", Run: 1, Success: true, Backend: "cpu", Measurement: Measurement{WallNanos: 500_000_000}},
		{Subject: "reference", Role: "reference", CaseID: "case-1", Family: "rar", Workload: "RAR <unsafe>", Run: 1, Success: true, Backend: "reference", Measurement: Measurement{WallNanos: 1_000_000_000}},
	}}
}

func fixtureReport() Report {
	return Report{SchemaVersion: 1, CollectorMode: wallClockCollector, InputSHA256: "report-digest", Plan: Plan{ID: "plan-1", Lane: "cpu", Par2Placement: "canonical", Cases: []PlanCase{{ID: "case-1", Order: 1}}}, CorpusDigest: "corpus-digest", Machine: Machine{Label: "test-machine", Architecture: "arm64"}, Candidate: BinaryIdentity{SHA256: "candidate"}, Reference: &BinaryIdentity{SHA256: "reference"}, Comparisons: []Comparison{{CaseID: "case-1", Family: "rar", Workload: "RAR <unsafe>", CandidateLabel: "rarpar", ReferenceLabel: "UnRAR", Candidate: Summary{Median: 500_000_000}, Reference: Summary{Median: 1_000_000_000}, Ratio: 2, Backend: "cpu"}}}
}

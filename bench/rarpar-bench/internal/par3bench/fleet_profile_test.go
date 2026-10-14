package par3bench

import (
	"archive/zip"
	"crypto/sha256"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFleetProfileCoversTheRequestedShapes(t *testing.T) {
	profile, err := LookupProfile("fleet")
	if err != nil {
		t.Fatal(err)
	}
	if err := profile.Validate(); err != nil {
		t.Fatal(err)
	}
	want := []string{"b-gf16", "b-fft", "m-gf16", "m-fft", "a-gf16", "c-fft", "zip-inside"}
	if got := strings.Join(profile.ConfigIDs(), ","); got != strings.Join(want, ",") {
		t.Fatalf("fleet sets %s, want %s (Cauchy and FFT of one size adjacent)", got, strings.Join(want, ","))
	}
	full, _ := LookupProfile("full")
	for _, id := range []string{"b-gf16", "a-gf16", "c-fft"} {
		var fleetConfig, fullConfig Config
		for _, config := range profile.Configs {
			if config.ID == id {
				fleetConfig = config
			}
		}
		for _, config := range full.Configs {
			if config.ID == id {
				fullConfig = config
			}
		}
		if fleetConfig.BlockSize != fullConfig.BlockSize || fleetConfig.Recovery != fullConfig.Recovery ||
			fleetConfig.Codec != fullConfig.Codec || fleetConfig.Damage.LostBlocks() != fullConfig.Damage.LostBlocks() {
			t.Fatalf("%s drifted from the full profile's shape, so it no longer compares with earlier rounds", id)
		}
	}
	for _, pair := range [][2]string{{"b-gf16", "b-fft"}, {"m-gf16", "m-fft"}} {
		var cauchy, fft Config
		for _, config := range profile.Configs {
			switch config.ID {
			case pair[0]:
				cauchy = config
			case pair[1]:
				fft = config
			}
		}
		if cauchy.Dataset != fft.Dataset || cauchy.BlockSize != fft.BlockSize || cauchy.Recovery != fft.Recovery ||
			cauchy.Damage.LostBlocks() != fft.Damage.LostBlocks() || cauchy.Codec != "cauchy" || fft.Codec != "fft" {
			t.Fatalf("%s and %s are not a matched Cauchy/FFT pair", pair[0], pair[1])
		}
	}
}

func TestFleetShapesRecordPAR2Equivalence(t *testing.T) {
	profile, _ := LookupProfile("fleet")
	for _, config := range profile.Configs {
		dataset, _ := profile.Dataset(config.Dataset)
		summary := ConfigSummary{Config: config}
		summary.fillShape(dataset)
		wantEquivalent := config.ID != "c-fft" && config.ID != "zip-inside"
		if summary.PAR2Equivalent != wantEquivalent {
			t.Fatalf("%s: par2_equivalent %t, want %t", config.ID, summary.PAR2Equivalent, wantEquivalent)
		}
		if summary.LostBlocks != config.Damage.LostBlocks() {
			t.Fatalf("%s: lost_blocks %d", config.ID, summary.LostBlocks)
		}
	}
}

func TestMeasuredRepeatsHonoursTheSetCap(t *testing.T) {
	if got := measuredRepeats(Config{MaxRepeats: 3}, 7); got != 3 {
		t.Fatalf("capped repeats %d", got)
	}
	if got := measuredRepeats(Config{MaxRepeats: 9}, 7); got != 7 {
		t.Fatalf("a cap above the run's repeats raised them to %d", got)
	}
	if got := measuredRepeats(Config{}, 7); got != 7 {
		t.Fatalf("uncapped repeats %d", got)
	}
}

func TestValidateRefusesMalformedCarrierSets(t *testing.T) {
	dataset := Dataset{ID: "z", Files: []FileSpec{{Name: "z0.bin", Size: MiB}}}
	good := Config{ID: "zip", Dataset: "z", Codec: "cauchy", Carrier: CarrierZIP, InsertRedundancy: 10, Damage: spread("d", []int{0}, 2)}
	for name, mutate := range map[string]func(*Config){
		"unknown carrier": func(c *Config) { c.Carrier = "rar" },
		"redundancy 0":    func(c *Config) { c.InsertRedundancy = 0 },
		"redundancy 251":  func(c *Config) { c.InsertRedundancy = 251 },
		"own block size":  func(c *Config) { c.BlockSize = MiB },
		"fft":             func(c *Config) { c.Codec = "fft" },
		"damage file 1":   func(c *Config) { c.Damage = spread("d", []int{1}, 2) },
	} {
		config := good
		mutate(&config)
		profile := Profile{Name: "unit", Datasets: []Dataset{dataset}, Configs: []Config{config}}
		if err := profile.Validate(); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
	if err := (Profile{Name: "unit", Datasets: []Dataset{dataset}, Configs: []Config{good}}).Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestCarrierZIPIsDeterministicAndStored(t *testing.T) {
	dir := t.TempDir()
	dataset := Dataset{ID: "unit-zip", Files: []FileSpec{{Name: "a.bin", Size: 70000}, {Name: "b.bin", Size: 3}}}
	if _, err := EnsureDataset(filepath.Join(dir, "data"), dataset, nil); err != nil {
		t.Fatal(err)
	}
	var digests [2][32]byte
	for i := range digests {
		path := filepath.Join(dir, "c"+string(rune('0'+i))+".zip")
		size, err := BuildCarrierZIP(path, filepath.Join(dir, "data"), dataset)
		if err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if int64(len(data)) != size {
			t.Fatalf("reported size %d, file %d", size, len(data))
		}
		digests[i] = sha256.Sum256(data)
		reader, err := zip.OpenReader(path)
		if err != nil {
			t.Fatal(err)
		}
		for index, member := range reader.File {
			if member.Name != dataset.Files[index].Name || member.Method != zip.Store || member.Flags&0x8 != 0 ||
				int64(member.UncompressedSize64) != dataset.Files[index].Size {
				t.Fatalf("member %d: %+v", index, member.FileHeader)
			}
			body, err := member.Open()
			if err != nil {
				t.Fatal(err)
			}
			body.Close()
		}
		reader.Close()
	}
	if digests[0] != digests[1] {
		t.Fatal("two builds of one dataset differ")
	}
}

func TestScanEmbeddedRefusesACarrierWithoutPAR3(t *testing.T) {
	path := filepath.Join(t.TempDir(), "plain.zip")
	if err := os.WriteFile(path, []byte("PK\x05\x06 not a protected zip"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := scanEmbedded(path); err == nil {
		t.Fatal("a ZIP with no PAR3 region was accepted")
	}
}

func TestCarrierDamageStaysInTheOriginalBytes(t *testing.T) {
	view := carrierDamageDataset(10 * MiB)
	if view.Files[0].Name != carrierZIPName || view.Files[0].Size != 10*MiB-carrierDamageGuard {
		t.Fatalf("damage view %+v", view.Files[0])
	}
	for _, offset := range DamageOffsets(view.Files[0].Size, 256*KiB, 40) {
		if offset+256*KiB > 10*MiB {
			t.Fatalf("damage at %d reaches past the original ZIP", offset)
		}
	}
}

func TestCarrierRunsOneFrontEndRow(t *testing.T) {
	r := &runner{options: Options{Workers: []int{1, 4}}}
	carrier := Config{Carrier: CarrierZIP}
	variants := Variants([]int{1, 4}, []KernelVariant{{Name: "k", Env: []string{"X=1"}}})
	var kept []string
	for _, variant := range variants {
		if r.carrierRuns(carrier, variant) {
			kept = append(kept, variant.Name)
		}
		if !r.carrierRuns(Config{}, variant) {
			t.Fatalf("%s dropped from a plain set", variant.Name)
		}
	}
	if strings.Join(kept, ",") != "reference,rarpar-w4" {
		t.Fatalf("carrier rows %v, want the reference and rarpar-w4 only", kept)
	}
	if !r.carrierRuns(carrier, Variant{Name: "reference", Tool: ToolReference}) {
		t.Fatal("the reference row was dropped from a carrier set")
	}
}

func TestRenderSVGsCarriesWallCPUAndRSS(t *testing.T) {
	results := &Results{
		Schema: ResultsSchema, Profile: "unit", Ops: []string{OpCreate, OpRepair}, Repeats: 2, Workers: []int{4, 8},
		Variants: Variants([]int{4, 8}, nil),
		Configs:  []ConfigSummary{{Config: Config{ID: "u", BlockSize: MiB, Recovery: 3, Codec: "cauchy"}, InputBlocks: 30}},
		Status:   StatusOK,
	}
	add := func(op, variant, tool string, wall float64) {
		results.Runs = append(results.Runs, RunRecord{Config: "u", Op: op, Variant: variant, Tool: tool, Status: StatusOK,
			Measurement: Measurement{WallSeconds: wall, UserSeconds: wall * 2, MaxRSSBytes: 100 << 20}})
	}
	for range 2 {
		add(OpCreate, "reference", ToolReference, 4)
		add(OpCreate, "rarpar-w4", ToolCandidate, 1)
		add(OpCreate, "rarpar-w8", ToolCandidate, 0.5)
		add(OpRepair, "reference", ToolReference, 1)
		add(OpRepair, "rarpar-w4", ToolCandidate, 2)
	}
	out := t.TempDir()
	paths, err := RenderSVGs(results, out)
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 2 {
		t.Fatalf("charts %v", paths)
	}
	create, _ := os.ReadFile(filepath.Join(out, "rarpar-par3-create.svg"))
	for _, want := range []string{"wall 4.00 -&gt; 1.00 s", "CPU 8.00 -&gt; 2.00 s", "peak RSS 100 -&gt; 100 MiB", "4.0x"} {
		if !strings.Contains(string(create), want) {
			t.Fatalf("create chart lacks %q:\n%s", want, create)
		}
	}
	// Every rarpar row is drawn: one per worker count.
	for _, want := range []string{"u / rarpar-w4", "u / rarpar-w8", "8.0x"} {
		if !strings.Contains(string(create), want) {
			t.Fatalf("create chart lacks %q:\n%s", want, create)
		}
	}
	repair, _ := os.ReadFile(filepath.Join(out, "rarpar-par3-repair.svg"))
	if !strings.Contains(string(repair), "class=\"slower\"") {
		t.Fatal("a slower rarpar row was not drawn as slower")
	}
	again := t.TempDir()
	if _, err := RenderSVGs(results, again); err != nil {
		t.Fatal(err)
	}
	second, _ := os.ReadFile(filepath.Join(again, "rarpar-par3-create.svg"))
	if string(second) != string(create) {
		t.Fatal("rendering is not deterministic")
	}
	results.Runs[1].MaxRSSBytes = 0
	if _, err := RenderSVGs(results, t.TempDir()); err == nil {
		t.Fatal("rendered results whose ok rows lack peak RSS")
	}
}

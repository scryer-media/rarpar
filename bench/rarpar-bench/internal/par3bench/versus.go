package par3bench

// The PAR2-against-PAR3 lens over the suite's own rows. A posting shape
// (Config.Shape) is a pair of sets over the same generated inputs, block size,
// recovery count and damage: a Cauchy set, on which the PAR2 rows (par2-rs and
// par2cmdline-turbo) also run, and an FFT set. Every arm of a versus chart is
// one suite row on one of those sets, so the comparison needs no run of its
// own: PAR2 and both PAR3 tools, each codec, on one scale.

import "fmt"

const (
	// PAR2 limits shared by both PAR2 tools.
	par2MaxSourceBlocks   = 32768
	par2MaxRecoveryBlocks = 32768
)

// par2SourceBlocks counts PAR2 source blocks: PAR2 never packs file tails.
func par2SourceBlocks(dataset Dataset, blockSize int64) int64 {
	var blocks int64
	for _, file := range dataset.Files {
		blocks += (file.Size + blockSize - 1) / blockSize
	}
	return blocks
}

// VersusOps are the ops a versus chart draws.
var VersusOps = []string{OpCreate, OpRepair}

// Arm labels, in chart order. A repair label gains ", retains file" or
// ", in place" (see VersusArm.Label).
const (
	ArmPAR2           = "par2-rs"
	ArmPAR2Turbo      = "par2cmdline-turbo"
	ArmReference      = "par3cmdline (Cauchy)"
	ArmReferenceFFT   = "par3cmdline (FFT)"
	ArmRarparCauchy   = "rarpar par3 (Cauchy)"
	ArmRarparFFT      = "rarpar par3 (FFT)"
	versusArmFallback = ArmReference
)

// VersusShape is one posting shape in one suite run: its Cauchy set and its
// FFT set, either of which may be absent.
type VersusShape struct {
	ID          string
	Cauchy, FFT *ConfigSummary
}

// Set is the shape's defining set: the Cauchy one when it ran, else the FFT.
func (s VersusShape) Set() *ConfigSummary {
	if s.Cauchy != nil {
		return s.Cauchy
	}
	return s.FFT
}

// VersusShapes lists the shapes in a suite run, in set order.
func VersusShapes(results *Results) []VersusShape {
	var shapes []VersusShape
	index := map[string]int{}
	for i := range results.Configs {
		config := &results.Configs[i]
		if config.Shape == "" {
			continue
		}
		at, ok := index[config.Shape]
		if !ok {
			at = len(shapes)
			index[config.Shape] = at
			shapes = append(shapes, VersusShape{ID: config.Shape})
		}
		if config.Codec != "fft" {
			shapes[at].Cauchy = config
		} else {
			shapes[at].FFT = config
		}
	}
	return shapes
}

// VersusArm is one bar: a label and the suite row behind it. Row is nil when
// the row never ran; a row with no successful run has Wall.N == 0.
type VersusArm struct {
	Name string
	Row  *Row
}

// Measured reports whether the arm has a median to draw.
func (a VersusArm) Measured() bool { return a.Row != nil && a.Row.Wall.N > 0 }

// Label is the arm's name, and at repair what its runs left beside the
// repaired files: "par2cmdline-turbo, retains file" or "rarpar par3 (FFT), in
// place". A row that retains files kept a numbered .1 of every file it
// repaired, so only arms with the same mark write the same bytes.
func (a VersusArm) Label(op string) string {
	if op != OpRepair || !a.Measured() {
		return a.Name
	}
	switch a.Row.LeftBackup {
	case "true":
		return a.Name + ", retains file"
	case "false":
		return a.Name + ", in place"
	default:
		return a.Name + ", backups varied"
	}
}

// versusRarparRows names the rarpar rows a versus chart draws: the plain
// in-place row and its backup twin at the run's largest worker count, on the
// first storage target, with no kernel override.
func versusRarparRows(results *Results) (inPlace, backup string, workers int) {
	target, seen := "", false
	for _, variant := range results.Variants {
		if variant.Tool != ToolCandidate || variant.Kernel != "" {
			continue
		}
		if !seen {
			target, seen = variant.Target, true
		}
		if variant.Target != target || variant.Workers < workers {
			continue
		}
		if variant.Workers > workers {
			inPlace, backup = "", ""
		}
		workers = variant.Workers
		if variant.Backup {
			backup = variant.Name
		} else {
			inPlace = variant.Name
		}
	}
	return inPlace, backup, workers
}

// VersusArms lists the arms of one shape and op, in chart order, from the
// run's summarized rows. par2cmdline-turbo is left out of a run without it.
func VersusArms(results *Results, rows []Row, shape VersusShape, op string) []VersusArm {
	find := func(config *ConfigSummary, variant string) *Row {
		if config == nil || variant == "" {
			return nil
		}
		for i := range rows {
			if rows[i].Config == config.ID && rows[i].Op == op && rows[i].Variant == variant {
				return &rows[i]
			}
		}
		return nil
	}
	inPlace, backup, _ := versusRarparRows(results)
	var arms []VersusArm
	add := func(name string, config *ConfigSummary, variant string) {
		if config != nil {
			arms = append(arms, VersusArm{Name: name, Row: find(config, variant)})
		}
	}
	if shape.Cauchy != nil && shape.Cauchy.PAR2 {
		add(ArmPAR2, shape.Cauchy, ToolPAR2)
		if results.PAR2Turbo != nil {
			add(ArmPAR2Turbo, shape.Cauchy, ToolPAR2Turbo)
		}
	}
	add(ArmReference, shape.Cauchy, "reference")
	add(ArmReferenceFFT, shape.FFT, "reference")
	for _, set := range []struct {
		name   string
		config *ConfigSummary
	}{{ArmRarparCauchy, shape.Cauchy}, {ArmRarparFFT, shape.FFT}} {
		if op != OpRepair || !results.InPlaceUnsupported {
			add(set.name, set.config, inPlace)
		}
		if op == OpRepair {
			add(set.name, set.config, backup)
		}
	}
	return arms
}

// versusBaseline is the arm every ratio on a chart is measured against:
// par2cmdline-turbo when every machine measured it, else par2-rs, else the
// reference's Cauchy row.
func versusBaseline(groups [][]VersusArm) string {
	for _, name := range []string{ArmPAR2Turbo, ArmPAR2} {
		everywhere := len(groups) > 0
		for _, arms := range groups {
			found := false
			for _, arm := range arms {
				found = found || (arm.Name == name && arm.Measured())
			}
			everywhere = everywhere && found
		}
		if everywhere {
			return name
		}
	}
	return versusArmFallback
}

// sameShape reports whether two runs' sets of one shape mean the same
// comparison: dataset, block size, recovery and damage.
func sameShape(a, b *ConfigSummary) error {
	switch {
	case a.Dataset != b.Dataset || a.DatasetBytes != b.DatasetBytes:
		return fmt.Errorf("dataset %s (%d bytes) against %s (%d bytes)", a.Dataset, a.DatasetBytes, b.Dataset, b.DatasetBytes)
	case a.BlockSize != b.BlockSize || a.Recovery != b.Recovery:
		return fmt.Errorf("%d-byte blocks + %d against %d-byte blocks + %d", a.BlockSize, a.Recovery, b.BlockSize, b.Recovery)
	case a.Damage.Name != b.Damage.Name || a.Damage.LostBlocks() != b.Damage.LostBlocks():
		return fmt.Errorf("damage %s against %s", a.Damage.Name, b.Damage.Name)
	}
	return nil
}

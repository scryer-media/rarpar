// Package par3bench is the PAR3 macro benchmark: the shipped `rarpar par3`
// CLI against the pinned par3cmdline reference, on deterministic generated
// inputs, measuring create, verify and repair.
//
// It drives the CLI rather than the par3-rs engine_perf example for the same
// reason the PAR2 suite drives `rarpar par`: the CLI is what ships, so its
// startup, planning, durability and output layout are all part of the number.
// engine_perf is available as an optional, untimed stage-breakdown pass.
package par3bench

import (
	"fmt"
	"math/bits"
	"sort"
	"strings"
)

const (
	KiB = int64(1) << 10
	MiB = int64(1) << 20
	GiB = int64(1) << 30
)

// FileSpec is one generated input file.
type FileSpec struct {
	Name string `json:"name"`
	Size int64  `json:"size"`
}

// Dataset is a set of generated input files. Its bytes are a pure function of
// the dataset ID, the file names and the sizes, so every host benchmarks the
// same inputs without shipping them.
type Dataset struct {
	ID    string     `json:"id"`
	Files []FileSpec `json:"files"`
}

// TotalBytes is the dataset's payload size.
func (d Dataset) TotalBytes() int64 {
	var total int64
	for _, file := range d.Files {
		total += file.Size
	}
	return total
}

// DamageTarget zeroes Blocks whole blocks of one file, spread evenly across it.
type DamageTarget struct {
	File   int `json:"file"`
	Blocks int `json:"blocks"`
}

// Damage is a named damage profile applied before verify-damaged and repair.
type Damage struct {
	Name    string         `json:"name"`
	Targets []DamageTarget `json:"targets"`
}

// LostBlocks is the number of blocks the profile destroys.
func (d Damage) LostBlocks() int {
	var total int
	for _, target := range d.Targets {
		total += target.Blocks
	}
	return total
}

// Config is one benchmarked PAR3 configuration: a dataset, a block size, an
// explicit recovery count and a codec. Both tools get the same explicit count
// (`-c`), never a percentage: rarpar's `-r` plans with an extra source pass and
// the two tools could round differently, and the comparison needs equal work.
type Config struct {
	ID        string `json:"id"`
	Dataset   string `json:"dataset"`
	BlockSize int64  `json:"block_size"`
	Recovery  int64  `json:"recovery_count"`
	// Codec is "cauchy" or "fft".
	Codec string `json:"codec"`
	// ExpectedField is the Galois field the reference selects for this shape
	// (see ReferenceField). Validate refuses a label the rule contradicts; it
	// is never passed to either tool.
	ExpectedField string `json:"expected_field"`
	Damage        Damage `json:"damage"`
	Note          string `json:"note,omitempty"`
	// Carrier is empty for a recovery set beside its inputs, or CarrierZIP:
	// the dataset stored in a ZIP that the reference protects in place with
	// its PAR-inside insert (`par3 i -r<InsertRedundancy>`), and that both
	// tools then verify and self-repair (`vs`, `rs`). The reference picks the
	// block size and recovery count for an insert, so BlockSize and Recovery
	// are zero in the profile and are read from the inserted carrier at run
	// time. The damage names file 0, the carrier, and lands only in the
	// original ZIP bytes, never in the appended PAR3 region.
	Carrier          string `json:"carrier,omitempty"`
	InsertRedundancy int    `json:"insert_redundancy_percent,omitempty"`
	// MaxRepeats caps the measured runs of this set (0: the run's repeats).
	// The largest reference shapes use it so a slow host stays inside its
	// session cap; the report states the cap.
	MaxRepeats int `json:"max_repeats,omitempty"`
	// CarrierOriginalBytes is the original ZIP's size, before the
	// reference's insert; set at run time.
	CarrierOriginalBytes int64 `json:"carrier_original_bytes,omitempty"`
}

// CarrierZIP is the PAR-inside ZIP carrier kind.
const CarrierZIP = "zip"

// carrierZIPName is the protected ZIP's name in every carrier stage.
const carrierZIPName = "inside.zip"

// carrierDamageGuard keeps carrier damage clear of the ZIP's central
// directory and end records at the tail of the original bytes.
const carrierDamageGuard = 64 * KiB

// CapacityLog2 is the FFT cohort capacity both tools derive from the recovery
// count with one cohort: log2(next_power_of_two(recovery)). The reference
// computes it internally for `-e8`; rarpar takes it as --capacity-log2.
func (c Config) CapacityLog2() int {
	if c.Recovery <= 1 {
		return 0
	}
	return bits.Len64(uint64(c.Recovery - 1))
}

// Profile is a named selection of configurations.
type Profile struct {
	Name     string    `json:"name"`
	Datasets []Dataset `json:"datasets"`
	Configs  []Config  `json:"configs"`
}

// Dataset returns the named dataset.
func (p Profile) Dataset(id string) (Dataset, bool) {
	for _, dataset := range p.Datasets {
		if dataset.ID == id {
			return dataset, true
		}
	}
	return Dataset{}, false
}

// Select narrows the profile to the named configuration IDs (all when empty).
func (p Profile) Select(ids []string) (Profile, error) {
	if len(ids) == 0 {
		return p, nil
	}
	known := map[string]Config{}
	for _, config := range p.Configs {
		known[config.ID] = config
	}
	selected := Profile{Name: p.Name}
	used := map[string]bool{}
	picked := map[string]bool{}
	for _, id := range ids {
		config, ok := known[id]
		if !ok {
			return Profile{}, fmt.Errorf("profile %s has no set %q (known: %s)", p.Name, id, strings.Join(p.ConfigIDs(), ", "))
		}
		if picked[id] {
			// Running a set twice would merge twice the requested samples
			// under one row and print its tables twice.
			return Profile{}, fmt.Errorf("set %q is selected more than once", id)
		}
		picked[id] = true
		selected.Configs = append(selected.Configs, config)
		used[config.Dataset] = true
	}
	for _, dataset := range p.Datasets {
		if used[dataset.ID] {
			selected.Datasets = append(selected.Datasets, dataset)
		}
	}
	return selected, nil
}

// ConfigIDs lists the profile's configuration IDs in order.
func (p Profile) ConfigIDs() []string {
	ids := make([]string, 0, len(p.Configs))
	for _, config := range p.Configs {
		ids = append(ids, config.ID)
	}
	return ids
}

// spread damages blocks evenly over the given files.
func spread(name string, files []int, perFile int) Damage {
	damage := Damage{Name: name}
	for _, file := range files {
		damage.Targets = append(damage.Targets, DamageTarget{File: file, Blocks: perFile})
	}
	return damage
}

func smokeProfile() Profile {
	smoke := Dataset{ID: "smoke", Files: []FileSpec{
		{Name: "s0.bin", Size: 3 * MiB},
		{Name: "s1.bin", Size: 4*MiB + 20000},
		{Name: "s2.bin", Size: 1*MiB + 777},
	}}
	return Profile{
		Name:     "smoke",
		Datasets: []Dataset{smoke},
		Configs: []Config{
			{
				ID: "smoke-gf8", Dataset: "smoke", BlockSize: 128 * KiB, Recovery: 7,
				Codec: "cauchy", ExpectedField: "gf8",
				Damage: spread("lost-6x128k-3files", []int{0, 1, 2}, 2),
				Note:   "65 input + 7 recovery blocks: inside the reference's GF(2^8) limits (at most 128 input, 256 total)",
			},
			{
				ID: "smoke-gf16", Dataset: "smoke", BlockSize: 16 * KiB, Recovery: 52,
				Codec: "cauchy", ExpectedField: "gf16",
				Damage: spread("lost-30x16k-3files", []int{0, 1, 2}, 10),
				Note:   "514 input + 52 recovery blocks: GF(2^16)",
			},
			{
				ID: "smoke-fft", Dataset: "smoke", BlockSize: 16 * KiB, Recovery: 52,
				Codec: "fft", ExpectedField: "fft-gf16",
				Damage: spread("lost-30x16k-3files", []int{0, 1, 2}, 10),
				Note:   "reference -e8, one cohort, capacity 64",
			},
		},
	}
}

func fullProfile() Profile {
	a := Dataset{ID: "a", Files: []FileSpec{{Name: "data.bin", Size: 1 * GiB}}}
	bFiles := make([]FileSpec, 10)
	for i := range bFiles {
		bFiles[i] = FileSpec{Name: fmt.Sprintf("f%d.bin", i), Size: 30 * MiB}
	}
	b := Dataset{ID: "b", Files: bFiles}
	c := Dataset{ID: "c", Files: []FileSpec{{Name: "big.bin", Size: 3 * GiB / 2}}}
	smoke := smokeProfile()
	profile := Profile{
		Name:     "full",
		Datasets: append([]Dataset{a, b, c}, smoke.Datasets...),
		Configs: []Config{
			{
				ID: "a-gf16", Dataset: "a", BlockSize: 1 * MiB, Recovery: 103,
				Codec: "cauchy", ExpectedField: "gf16",
				Damage: spread("lost-50x1m", []int{0}, 50),
				Note:   "set A: 1 GiB, 1 MiB blocks, 10% (1024 + 103 blocks)",
			},
			{
				ID: "a-gf8", Dataset: "a", BlockSize: 8 * MiB, Recovery: 13,
				Codec: "cauchy", ExpectedField: "gf8",
				Damage: spread("lost-6x8m", []int{0}, 6),
				Note:   "set A data with 8 MiB blocks: 128 + 13 = 141 total, the real-size GF(2^8) row",
			},
			{
				ID: "a-fft", Dataset: "a", BlockSize: 1 * MiB, Recovery: 103,
				Codec: "fft", ExpectedField: "fft-gf16",
				Damage: spread("lost-50x1m", []int{0}, 50),
				Note:   "set A with the reference's -e8 FFT codec, one cohort, capacity 128",
			},
			{
				ID: "b-gf16", Dataset: "b", BlockSize: 1 * MiB, Recovery: 30,
				Codec: "cauchy", ExpectedField: "gf16",
				Damage: spread("lost-10x1m-5of10files", []int{0, 2, 4, 6, 8}, 2),
				Note:   "set B: 10 x 30 MiB, 1 MiB blocks, 10% (300 + 30 blocks)",
			},
			{
				ID: "c-gf16", Dataset: "c", BlockSize: 32 * KiB, Recovery: 4916,
				Codec: "cauchy", ExpectedField: "gf16",
				Damage: spread("lost-2000x32k", []int{0}, 2000),
				Note:   "set C oversized: 1.5 GiB, 32 KiB blocks (49152 + 4916 blocks)",
			},
			{
				ID: "c-fft", Dataset: "c", BlockSize: 32 * KiB, Recovery: 4916,
				Codec: "fft", ExpectedField: "fft-gf16",
				Damage: spread("lost-2000x32k", []int{0}, 2000),
				Note:   "set C with the FFT codec on both sides (reference -e8, one cohort, capacity 8192): the reference's Cauchy is quadratic at this block count",
			},
		},
	}
	profile.Configs = append(profile.Configs, smoke.Configs...)
	return profile
}

// fleetProfile is the cross-machine PAR3 round: create, verify and repair at
// three sizes with Cauchy and FFT side by side, a shape over PAR2's 32768
// input-block limit, and a PAR-inside ZIP. Sets A, B and C are the full
// profile's datasets and shapes, so the numbers compare with earlier rounds.
// Every FFT row is forced on both sides: the reference's explicit -e8 codec
// switch and rarpar's --codec fft with the same one-cohort capacity; neither
// tool picks FFT by size. The order keeps each size's Cauchy and FFT rows
// together.
func fleetProfile() Profile {
	full := fullProfile()
	a, _ := full.Dataset("a")
	b, _ := full.Dataset("b")
	c, _ := full.Dataset("c")
	mFiles := make([]FileSpec, 4)
	for i := range mFiles {
		mFiles[i] = FileSpec{Name: fmt.Sprintf("m%d.bin", i), Size: 128 * MiB}
	}
	m := Dataset{ID: "m", Files: mFiles}
	zFiles := make([]FileSpec, 4)
	for i := range zFiles {
		zFiles[i] = FileSpec{Name: fmt.Sprintf("z%d.bin", i), Size: 64 * MiB}
	}
	z := Dataset{ID: "z", Files: zFiles}
	byID := map[string]Config{}
	for _, config := range full.Configs {
		byID[config.ID] = config
	}
	bFFT := byID["b-gf16"]
	bFFT.ID, bFFT.Codec, bFFT.ExpectedField = "b-fft", "fft", "fft-gf16"
	bFFT.Note = "set B with the FFT codec on both sides (reference -e8, one cohort, capacity 32): the small FFT shape"
	aGF16 := byID["a-gf16"]
	aGF16.MaxRepeats = 3
	cFFT := byID["c-fft"]
	cFFT.MaxRepeats = 3
	cFFT.Note = "set C, over PAR2's cap: 49152 input blocks where PAR2 allows 32768, so there is no PAR2 equivalent; FFT on both sides (reference -e8, one cohort, capacity 8192); the reference's Cauchy is quadratic here"
	return Profile{
		Name:     "fleet",
		Datasets: []Dataset{b, m, a, c, z},
		Configs: []Config{
			byID["b-gf16"],
			bFFT,
			{
				ID: "m-gf16", Dataset: "m", BlockSize: 1 * MiB, Recovery: 52,
				Codec: "cauchy", ExpectedField: "gf16",
				Damage: spread("lost-24x1m-4files", []int{0, 1, 2, 3}, 6),
				Note:   "set M: 4 x 128 MiB, 1 MiB blocks, 10% (512 + 52 blocks): the medium Cauchy shape",
			},
			{
				ID: "m-fft", Dataset: "m", BlockSize: 1 * MiB, Recovery: 52,
				Codec: "fft", ExpectedField: "fft-gf16",
				Damage: spread("lost-24x1m-4files", []int{0, 1, 2, 3}, 6),
				Note:   "set M with the FFT codec on both sides (reference -e8, one cohort, capacity 64): the medium FFT shape",
			},
			aGF16,
			cFFT,
			{
				ID: "zip-inside", Dataset: "z", Codec: "cauchy", ExpectedField: "gf16",
				Carrier: CarrierZIP, InsertRedundancy: 10,
				Damage: spread("lost-40-blocks-in-zip", []int{0}, 40),
				Note:   "PAR-inside ZIP: 4 x 64 MiB stored in one ZIP, protected in place by the reference's insert (-r10, Cauchy; the reference picks the block size), self-repaired by both sides",
			},
		},
	}
}

// Profiles lists every built-in profile by name.
func Profiles() map[string]Profile {
	return map[string]Profile{"smoke": smokeProfile(), "full": fullProfile(), "fleet": fleetProfile()}
}

// LookupProfile returns a built-in profile.
func LookupProfile(name string) (Profile, error) {
	profiles := Profiles()
	profile, ok := profiles[name]
	if !ok {
		names := make([]string, 0, len(profiles))
		for known := range profiles {
			names = append(names, known)
		}
		sort.Strings(names)
		return Profile{}, fmt.Errorf("unknown PAR3 profile %q (known: %s)", name, strings.Join(names, ", "))
	}
	return profile, nil
}

// ReferenceField is the Galois field par3cmdline selects (libpar3
// packet_make.c) for a set with no maximum-recovery hint and no first
// recovery offset: Cauchy uses GF(2^8) only with at most 128 input blocks and
// at most 256 blocks in all; FFT uses Leopard's 8-bit field while
// next_pow2(next_pow2(recovery) + input) fits in 256.
func ReferenceField(config Config, inputBlocks int64) string {
	if config.Codec == "fft" {
		m := nextPow2(config.Recovery)
		if nextPow2(m+inputBlocks) <= 256 {
			return "fft-gf8"
		}
		return "fft-gf16"
	}
	if inputBlocks > 128 || inputBlocks+config.Recovery > 256 {
		return "gf16"
	}
	return "gf8"
}

func nextPow2(value int64) int64 {
	if value <= 1 {
		return 1
	}
	return int64(1) << bits.Len64(uint64(value-1))
}

// InputBlocks counts the input blocks of a configuration the way PAR3 lays
// them out by default: whole blocks per file, then every file's tail packed
// into shared blocks. It is used for the GF(2^8) sanity check and the damage
// bounds, never passed to either tool.
func InputBlocks(dataset Dataset, blockSize int64) int64 {
	var whole, tails int64
	for _, file := range dataset.Files {
		whole += file.Size / blockSize
		tails += file.Size % blockSize
	}
	return whole + (tails+blockSize-1)/blockSize
}

// Validate checks a profile's internal consistency: datasets exist, damage is
// repairable and within each file, and the GF(2^8) rows really fit in 256.
func (p Profile) Validate() error {
	seen := map[string]bool{}
	for _, config := range p.Configs {
		if seen[config.ID] {
			return fmt.Errorf("duplicate set %q", config.ID)
		}
		seen[config.ID] = true
		dataset, ok := p.Dataset(config.Dataset)
		if !ok {
			return fmt.Errorf("set %s: unknown dataset %q", config.ID, config.Dataset)
		}
		if config.MaxRepeats < 0 {
			return fmt.Errorf("set %s: max_repeats must not be negative", config.ID)
		}
		if config.Carrier != "" {
			if err := validateCarrier(config, dataset); err != nil {
				return err
			}
			continue
		}
		if config.BlockSize <= 0 || config.Recovery <= 0 {
			return fmt.Errorf("set %s: block size and recovery count must be positive", config.ID)
		}
		switch config.Codec {
		case "cauchy", "fft":
		default:
			return fmt.Errorf("set %s: unknown codec %q", config.ID, config.Codec)
		}
		blocks := InputBlocks(dataset, config.BlockSize)
		if field := ReferenceField(config, blocks); field != config.ExpectedField {
			return fmt.Errorf("set %s: %d input + %d recovery blocks select %s in the reference, not the labelled %s",
				config.ID, blocks, config.Recovery, field, config.ExpectedField)
		}
		if blocks+config.Recovery > 65536 {
			return fmt.Errorf("set %s: %d total blocks exceed the reference's 65536 limit", config.ID, blocks+config.Recovery)
		}
		if int64(config.Damage.LostBlocks()) > config.Recovery {
			return fmt.Errorf("set %s: damage %s loses %d blocks but only %d recovery blocks exist",
				config.ID, config.Damage.Name, config.Damage.LostBlocks(), config.Recovery)
		}
		for _, target := range config.Damage.Targets {
			if target.File < 0 || target.File >= len(dataset.Files) {
				return fmt.Errorf("set %s: damage names file %d of %d", config.ID, target.File, len(dataset.Files))
			}
			fileBlocks := (dataset.Files[target.File].Size + config.BlockSize - 1) / config.BlockSize
			if int64(target.Blocks) > fileBlocks {
				return fmt.Errorf("set %s: damage wants %d blocks of a %d-block file", config.ID, target.Blocks, fileBlocks)
			}
		}
	}
	return nil
}

// validateCarrier checks a PAR-inside set: a known carrier, an insert
// redundancy the reference accepts (it refuses above 250), no block size or
// recovery count of its own (the reference picks them), the Cauchy codec
// (the reference's insert is Cauchy only), and damage aimed at the carrier.
func validateCarrier(config Config, dataset Dataset) error {
	if config.Carrier != CarrierZIP {
		return fmt.Errorf("set %s: unknown carrier %q (known: %s)", config.ID, config.Carrier, CarrierZIP)
	}
	if config.InsertRedundancy < 1 || config.InsertRedundancy > 250 {
		return fmt.Errorf("set %s: insert redundancy %d%% is outside the reference's 1-250", config.ID, config.InsertRedundancy)
	}
	if config.BlockSize != 0 || config.Recovery != 0 {
		return fmt.Errorf("set %s: a carrier set takes its block size and recovery count from the reference's insert; leave them 0", config.ID)
	}
	if config.Codec != "cauchy" {
		return fmt.Errorf("set %s: the reference's PAR-inside insert writes Cauchy only", config.ID)
	}
	if len(dataset.Files) == 0 {
		return fmt.Errorf("set %s: a carrier needs at least one member", config.ID)
	}
	for _, target := range config.Damage.Targets {
		if target.File != 0 || target.Blocks <= 0 {
			return fmt.Errorf("set %s: carrier damage must name file 0 (the carrier) with a positive block count", config.ID)
		}
	}
	return nil
}

package bench

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadPlanRejectsIncompleteOrUnsupportedPlans(t *testing.T) {
	path := filepath.Join(t.TempDir(), "plan.json")
	valid := Plan{
		SchemaVersion: PlanSchemaVersion,
		ID:            "plan-test",
		CorpusDigest:  "corpus-test",
		Seed:          "seed",
		Warmups:       1,
		Repeats:       5,
		Lane:          "cpu",
		Par2Placement: "canonical",
		Cases:         []PlanCase{{ID: "case", Order: 1}},
	}
	for name, mutate := range map[string]func(*Plan){
		"negative warmups": func(plan *Plan) { plan.Warmups = -1 },
		"no cases":         func(plan *Plan) { plan.Cases = nil },
		"unsupported lane": func(plan *Plan) { plan.Lane = "wgpu" },
	} {
		t.Run(name, func(t *testing.T) {
			plan := valid
			mutate(&plan)
			if err := writeJSON(path, plan); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadPlan(path, valid.CorpusDigest); err == nil {
				t.Fatal("invalid plan was accepted")
			}
		})
	}
}

func TestCopyTreeCopiesFileContentsAndMode(t *testing.T) {
	source := filepath.Join(t.TempDir(), "source")
	destination := filepath.Join(t.TempDir(), "destination")
	if err := os.MkdirAll(filepath.Join(source, "nested"), 0o755); err != nil {
		t.Fatal(err)
	}
	input := filepath.Join(source, "nested", "payload.bin")
	if err := os.WriteFile(input, []byte("benchmark payload"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := copyTree(source, destination); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(destination, "nested", "payload.bin")
	contents, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if string(contents) != "benchmark payload" {
		t.Fatalf("copied contents = %q", contents)
	}
	info, err := os.Stat(output)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := info.Mode().Perm(), os.FileMode(0o640); got != want {
		t.Fatalf("copied mode = %#o, want %#o", got, want)
	}
}

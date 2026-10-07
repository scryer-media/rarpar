//go:build !windows

package par3bench

import (
	"os"
	"path/filepath"
	"testing"
)

func TestOnlyUnvouchedCreateSetsRepairThemselves(t *testing.T) {
	payloads := &Identity{RecoveryPayloads: true}
	different := &Identity{}
	cases := []struct {
		tool     string
		identity *Identity
		want     bool
	}{
		{ToolReference, nil, false},
		{ToolReference, different, false},
		{ToolCandidate, payloads, false},
		{ToolCandidate, different, true},
		{ToolCandidate, nil, true},
		{ToolEngine, different, true},
	}
	for _, c := range cases {
		if got := needsSelfRepair(c.tool, c.identity); got != c.want {
			t.Errorf("needsSelfRepair(%s, %+v) = %t, want %t", c.tool, c.identity, got, c.want)
		}
	}
}

// A create's own set must repair damaged inputs back to the originals: a
// candidate whose repair leaves the damage, or fails, fails the create row.
func TestSelfRepairJudgesTheCreatedSet(t *testing.T) {
	root := t.TempDir()
	dataset := Dataset{ID: "self", Files: []FileSpec{{Name: "quarry.bin", Size: 9*KiB + 7}, {Name: "beacon.bin", Size: 300}}}
	dataDir := filepath.Join(root, "data")
	manifest, err := EnsureDataset(dataDir, dataset, nil)
	if err != nil {
		t.Fatal(err)
	}
	created := filepath.Join(root, "create-rarpar")
	if err := os.MkdirAll(created, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(created, carrierName), []byte("carrier"), 0o644); err != nil {
		t.Fatal(err)
	}
	config := Config{ID: "self", BlockSize: KiB, Recovery: 2, Damage: Damage{Targets: []DamageTarget{{File: 0, Blocks: 1}}}}
	variant := Variant{Name: "rarpar-w1", Tool: ToolCandidate, Workers: 1}
	judge := func(script string) (RepairCheck, string) {
		t.Helper()
		candidate := filepath.Join(root, "candidate")
		if err := os.WriteFile(candidate, []byte("#!/bin/sh\n"+script+"\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		r := &runner{options: Options{Candidate: candidate}, results: &Results{}}
		check, failure, _, err := r.selfRepair(t.Context(), config, dataset, manifest, dataDir, created, variant)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(created + "-self-repair"); !os.IsNotExist(err) {
			t.Fatalf("the self-repair stage was left behind: %v", err)
		}
		return check, failure
	}
	if check, failure := judge("exit 0"); failure != "self-repair-mismatch" || check.Match {
		t.Fatalf("a repair that left the damage: failure %q check %+v", failure, check)
	}
	if _, failure := judge("exit 3"); failure != "self-repair-failed" {
		t.Fatalf("a failed repair: failure %q", failure)
	}
	restore := "cp '" + filepath.Join(dataDir, "quarry.bin") + "' quarry.bin"
	if check, failure := judge(restore); failure != "" || !check.Match {
		t.Fatalf("a repair that restored the inputs: failure %q check %+v", failure, check)
	}
}

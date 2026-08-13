package bench

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestParsePerfStatOutput(t *testing.T) {
	output := []byte(strings.Join([]string{
		"1000,,cycles,100.00",
		"2000,,instructions,100.00",
		"300,,branches,100.00",
		"4,,branch-misses,100.00",
		"5000,,cache-references,100.00",
		"600,,cache-misses,100.00",
		"12.5,msec,task-clock,100.00",
		"7,,context-switches,100.00",
		"8,,cpu-migrations,100.00",
		"123456789,,duration_time,100.00",
		"# comment from perf",
	}, "\n"))

	counters, err := parsePerfStatOutput(output)
	if err != nil {
		t.Fatal(err)
	}
	if counters == nil || counters.Cycles == nil || *counters.Cycles != 1000 {
		t.Fatalf("cycles = %#v", counters)
	}
	if counters.Instructions == nil || *counters.Instructions != 2000 {
		t.Fatalf("instructions = %#v", counters)
	}
	if counters.BranchMisses == nil || *counters.BranchMisses != 4 {
		t.Fatalf("branch misses = %#v", counters)
	}
	if counters.TaskClockMillis == nil || *counters.TaskClockMillis != 12.5 {
		t.Fatalf("task clock = %#v", counters)
	}
	if counters.CPUMigrations == nil || *counters.CPUMigrations != 8 {
		t.Fatalf("CPU migrations = %#v", counters)
	}
	if counters.DurationNanos == nil || *counters.DurationNanos != 123456789 {
		t.Fatalf("duration = %#v", counters)
	}
}

func TestParsePerfStatOutputRejectsUnavailableCountersWithoutZeroes(t *testing.T) {
	output := []byte("<not counted>,,cycles,0.00\n")
	counters, err := parsePerfStatOutput(output)
	if counters != nil {
		t.Fatalf("unavailable counters returned partial data: %#v", counters)
	}
	if err == nil || !strings.Contains(err.Error(), "cycles") {
		t.Fatalf("unavailable counter error = %v", err)
	}
}

func TestParsePerfStatOutputRejectsMissingCounters(t *testing.T) {
	_, err := parsePerfStatOutput([]byte("1,,cycles,100.00\n"))
	if err == nil || !strings.Contains(err.Error(), "instructions") {
		t.Fatalf("missing counter error = %v", err)
	}
}

func TestParsePerfStatOutputRejectsDuplicateCounters(t *testing.T) {
	output := []byte("1,,cycles,100.00\n2,,cycles,100.00\n")
	_, err := parsePerfStatOutput(output)
	if err == nil || !strings.Contains(err.Error(), "more than once") {
		t.Fatalf("duplicate counter error = %v", err)
	}
}

func TestParsePerfStatOutputRejectsMultiplexedCounters(t *testing.T) {
	output := []byte("1,,cycles,74.25\n")
	_, err := parsePerfStatOutput(output)
	if err == nil || !strings.Contains(err.Error(), "incomplete percentage") {
		t.Fatalf("multiplexed counter error = %v", err)
	}
}

func TestParsePerfStatOutputRejectsNonFiniteRunningPercentage(t *testing.T) {
	output := []byte("1,,cycles,NaN\n")
	_, err := parsePerfStatOutput(output)
	if err == nil || !strings.Contains(err.Error(), "incomplete percentage") {
		t.Fatalf("non-finite counter percentage error = %v", err)
	}
}

func TestPerfValidationRequiresLinuxAndPerf(t *testing.T) {
	lookup := func(string) (string, error) { return "/usr/bin/perf", nil }
	if err := validatePerfCollector("darwin", lookup); err == nil {
		t.Fatal("perf was accepted on non-Linux")
	}
	missing := func(string) (string, error) { return "", errors.New("not found") }
	if err := validatePerfCollector("linux", missing); err == nil {
		t.Fatal("missing perf was accepted")
	}
	if err := validatePerfCollector("linux", lookup); err != nil {
		t.Fatal(err)
	}
}

func TestPerfStatArgsPreserveChildCommand(t *testing.T) {
	args := perfStatArgs("rarpar", []string{"x", "-o+", "archive.rar", "out dir"})
	separator := -1
	for index, value := range args {
		if value == "--" {
			separator = index
			break
		}
	}
	if separator < 0 || strings.Join(args[separator+1:], "\x00") != "rarpar\x00x\x00-o+\x00archive.rar\x00out dir" {
		t.Fatalf("child command was not preserved: %#v", args)
	}
	if !strings.Contains(strings.Join(args, "\x00"), strings.Join(perfEvents, ",")) {
		t.Fatalf("perf event list missing: %#v", args)
	}
}

func TestPerfFieldsAreOmittedFromNormalMeasurementJSON(t *testing.T) {
	encoded, err := json.Marshal(Measurement{WallNanos: 1})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte(`"perf"`)) || bytes.Contains(encoded, []byte(`"perf_collector_note"`)) {
		t.Fatalf("normal measurement acquired perf fields: %s", encoded)
	}
}

func TestSetEnvironmentValueReplacesLocale(t *testing.T) {
	environment := []string{"PATH=/bin", "LANG=de_DE.UTF-8", "LC_ALL=fr_FR.UTF-8"}
	environment = setEnvironmentValue(environment, "LC_ALL", "C")
	environment = setEnvironmentValue(environment, "LANG", "C")
	joined := strings.Join(environment, "\n")
	if strings.Count(joined, "LC_ALL=") != 1 || strings.Count(joined, "LANG=") != 1 {
		t.Fatalf("locale variables were duplicated: %q", joined)
	}
	if !strings.Contains(joined, "LC_ALL=C") || !strings.Contains(joined, "LANG=C") {
		t.Fatalf("locale was not pinned: %q", joined)
	}
}

func TestParsePerfStatOutputSumsHybridPMUEvents(t *testing.T) {
	output := []byte(strings.Join([]string{
		"1000,,cpu_core/cycles/,100.00",
		"500,,cpu_atom/cycles/,100.00",
		"2000,,cpu_core/instructions/,100.00",
		"1000,,cpu_atom/instructions/,100.00",
		"300,,cpu_core/branches/,100.00",
		"<not counted>,,cpu_atom/branches/,0.00",
		"4,,cpu_core/branch-misses/,100.00",
		"2,,cpu_atom/branch-misses/,100.00",
		"5000,,cpu_core/cache-references/,100.00",
		"2500,,cpu_atom/cache-references/,100.00",
		"600,,cpu_core/cache-misses/,100.00",
		"300,,cpu_atom/cache-misses/,100.00",
		"12.5,msec,task-clock,100.00",
		"7,,context-switches,100.00",
		"8,,cpu-migrations,100.00",
		"123456789,,duration_time,100.00",
	}, "\n"))

	counters, err := parsePerfStatOutput(output)
	if err != nil {
		t.Fatal(err)
	}
	if counters.Cycles == nil || *counters.Cycles != 1500 {
		t.Fatalf("cycles = %#v", counters)
	}
	if counters.Instructions == nil || *counters.Instructions != 3000 {
		t.Fatalf("instructions = %#v", counters)
	}
	if counters.Branches == nil || *counters.Branches != 300 {
		t.Fatalf("branches = %#v", counters)
	}
	if counters.BranchMisses == nil || *counters.BranchMisses != 6 {
		t.Fatalf("branch misses = %#v", counters)
	}
	if counters.TaskClockMillis == nil || *counters.TaskClockMillis != 12.5 {
		t.Fatalf("task clock = %#v", counters)
	}
}

func TestParsePerfStatOutputRejectsDuplicatePlainRows(t *testing.T) {
	output := []byte("1000,,cycles,100.00\n1000,,cycles,100.00\n")
	if _, err := parsePerfStatOutput(output); err == nil || !strings.Contains(err.Error(), "more than once") {
		t.Fatalf("duplicate plain rows error = %v", err)
	}
}

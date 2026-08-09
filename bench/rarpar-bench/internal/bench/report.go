package bench

import (
	"fmt"
	"math"
	"path/filepath"
	"sort"
)

func BuildReport(rawPath string) (Report, error) {
	var raw RunRecord
	if err := readJSON(rawPath, &raw); err != nil {
		return Report{}, err
	}
	if raw.SchemaVersion != RunSchemaVersion || raw.Plan.SchemaVersion != PlanSchemaVersion || raw.CorpusDigest != raw.Plan.CorpusDigest {
		return Report{}, fmt.Errorf("raw benchmark record has invalid provenance")
	}
	collectorMode := raw.CollectorMode
	if collectorMode == "" {
		collectorMode = wallClockCollector
	}
	if collectorMode != wallClockCollector && collectorMode != perfStatCollector {
		return Report{}, fmt.Errorf("unsupported benchmark collector mode %q", collectorMode)
	}
	digest, err := fileSHA256(rawPath)
	if err != nil {
		return Report{}, err
	}
	report := Report{
		SchemaVersion: ReportSchemaVersion,
		CollectorMode: collectorMode,
		InputSHA256:   digest,
		Plan:          raw.Plan,
		CorpusDigest:  raw.CorpusDigest,
		Machine:       raw.Machine,
		Candidate:     raw.Candidate,
		Reference:     raw.Reference,
		ReferencePAR2: raw.ReferencePAR2,
	}
	if raw.Reference == nil {
		report.Omitted = []string{"no reference binary was supplied; relative-speed charts are unavailable"}
		return report, nil
	}
	for _, planCase := range raw.Plan.Cases {
		candidate := successfulMeasurements(raw.Executions, "candidate", planCase.ID)
		candidateWarmups := successfulWarmups(raw.Executions, "candidate", planCase.ID)
		reference := successfulMeasurements(raw.Executions, "reference", planCase.ID)
		if len(candidate) != raw.Plan.Repeats || len(reference) != raw.Plan.Repeats {
			report.Omitted = append(report.Omitted, fmt.Sprintf("%s: requires %d successful candidate and reference samples, got %d and %d", planCase.ID, raw.Plan.Repeats, len(candidate), len(reference)))
			continue
		}
		if candidate[0].Family != reference[0].Family || candidate[0].Workload != reference[0].Workload {
			report.Omitted = append(report.Omitted, fmt.Sprintf("%s: candidate/reference workload metadata does not match", planCase.ID))
			continue
		}
		candidateSummary := summarize(candidate)
		referenceSummary := summarize(reference)
		if candidateSummary.Median <= 0 || referenceSummary.Median <= 0 {
			report.Omitted = append(report.Omitted, fmt.Sprintf("%s: non-positive timing", planCase.ID))
			continue
		}
		comparison := Comparison{
			CaseID:             planCase.ID,
			Family:             candidate[0].Family,
			Workload:           candidate[0].Workload,
			CandidateLabel:     raw.Candidate.Label,
			ReferenceLabel:     referenceLabelForFamily(candidate[0].Family),
			Candidate:          candidateSummary,
			Reference:          referenceSummary,
			Ratio:              float64(referenceSummary.Median) / float64(candidateSummary.Median),
			CompiledCapability: consistentCapability(candidate),
			Backend:            consistentBackend(candidate),
		}
		comparison.CandidateRAR5Phases = summarizeRAR5Phases(candidateWarmups)
		report.Comparisons = append(report.Comparisons, comparison)
	}
	sort.SliceStable(report.Comparisons, func(left, right int) bool {
		return caseOrder(raw.Plan, report.Comparisons[left].CaseID) < caseOrder(raw.Plan, report.Comparisons[right].CaseID)
	})
	return report, nil
}

func referenceLabelForFamily(family string) string {
	if family == "par2" {
		return "par2cmdline-turbo"
	}
	return "UnRAR"
}

func consistentCapability(executions []Execution) string {
	capability := executions[0].CompiledCapability
	for _, execution := range executions[1:] {
		if execution.CompiledCapability != capability {
			return "mixed"
		}
	}
	return capability
}

func successfulMeasurements(executions []Execution, role, caseID string) []Execution {
	var successful []Execution
	for _, execution := range executions {
		if execution.Role == role && execution.CaseID == caseID && !execution.Warmup && execution.Success {
			successful = append(successful, execution)
		}
	}
	sort.Slice(successful, func(left, right int) bool { return successful[left].Run < successful[right].Run })
	return successful
}

func successfulWarmups(executions []Execution, role, caseID string) []Execution {
	var successful []Execution
	for _, execution := range executions {
		if execution.Role == role && execution.CaseID == caseID && execution.Warmup && execution.Success {
			successful = append(successful, execution)
		}
	}
	sort.Slice(successful, func(left, right int) bool { return successful[left].Run < successful[right].Run })
	return successful
}

func summarize(executions []Execution) Summary {
	values := make([]int64, len(executions))
	for index, execution := range executions {
		values[index] = execution.Measurement.WallNanos
	}
	sort.Slice(values, func(left, right int) bool { return values[left] < values[right] })
	return Summary{Count: len(values), Median: percentile(values, 0.5), Min: values[0], Max: values[len(values)-1], IQR: percentile(values, 0.75) - percentile(values, 0.25)}
}

func percentile(values []int64, percentile float64) int64 {
	if len(values) == 1 {
		return values[0]
	}
	position := percentile * float64(len(values)-1)
	lower := int(math.Floor(position))
	upper := int(math.Ceil(position))
	if lower == upper {
		return values[lower]
	}
	return int64(math.Round(float64(values[lower]) + (float64(values[upper])-float64(values[lower]))*(position-float64(lower))))
}

func consistentBackend(executions []Execution) string {
	backend := executions[0].Backend
	for _, execution := range executions[1:] {
		if execution.Backend != backend {
			return "mixed"
		}
	}
	return backend
}

func caseOrder(plan Plan, id string) int {
	for _, item := range plan.Cases {
		if item.ID == id {
			return item.Order
		}
	}
	return len(plan.Cases) + 1
}

func WriteReport(path string, report Report) error {
	return writeJSON(filepath.Clean(path), report)
}

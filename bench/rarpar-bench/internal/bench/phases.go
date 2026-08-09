package bench

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

const (
	phaseDiagnosticPrefix  = "RARPAR_BENCH_PHASE "
	decodeDiagnosticPrefix = "RARPAR_BENCH_DECODE "
	phaseDiagnosticEnv     = "RARPAR_BENCH_PHASES"
)

type phaseDiagnostic struct {
	Phase string `json:"phase"`
	Nanos int64  `json:"nanos"`
}

type decodeDiagnostic struct {
	Schema                  uint32  `json:"schema"`
	Kind                    string  `json:"kind"`
	TablePrepareNanos       *uint64 `json:"table_prepare_nanos"`
	SymbolDecodeNanos       *uint64 `json:"symbol_decode_nanos"`
	PoolDispatchNanos       *uint64 `json:"pool_dispatch_nanos"`
	PoolWaitNanos           *uint64 `json:"pool_wait_nanos"`
	TablePresentBlocks      *uint64 `json:"table_present_blocks"`
	TablelessBlocks         *uint64 `json:"tableless_blocks"`
	QuickHuffmanHits        *uint64 `json:"quick_huffman_hits"`
	SlowHuffmanHits         *uint64 `json:"slow_huffman_hits"`
	LiteralSymbols          *uint64 `json:"literal_symbols"`
	MatchSymbols            *uint64 `json:"match_symbols"`
	RepeatSymbols           *uint64 `json:"repeat_symbols"`
	FilterSymbols           *uint64 `json:"filter_symbols"`
	DecodedBufferGrowths    *uint64 `json:"decoded_buffer_growths"`
	DecodedBufferGrownBytes *uint64 `json:"decoded_buffer_grown_bytes"`
	Assignments             *uint64 `json:"assignments"`
	ActiveWorkerSlots       *uint64 `json:"active_worker_slots"`
	IdleWorkerSlots         *uint64 `json:"idle_worker_slots"`
}

func collectRAR5DecodeDiagnostics(stdout, stderr []byte) *RAR5DecodeEvidence {
	evidence := &RAR5DecodeEvidence{SchemaVersion: 1}
	for _, stream := range [][]byte{stdout, stderr} {
		for _, line := range strings.Split(string(stream), "\n") {
			line = strings.TrimSpace(line)
			if !strings.HasPrefix(line, decodeDiagnosticPrefix) {
				continue
			}
			var diagnostic decodeDiagnostic
			if err := json.Unmarshal([]byte(strings.TrimPrefix(line, decodeDiagnosticPrefix)), &diagnostic); err != nil {
				return unavailableRAR5Decode(fmt.Sprintf("invalid RAR5 decode diagnostic: %v", err))
			}
			if diagnostic.Schema != 1 || diagnostic.Kind != "rar5_decode" || !completeDecodeDiagnostic(diagnostic) {
				return unavailableRAR5Decode("unsupported RAR5 decode diagnostic schema or kind")
			}
			if !addDecodeDiagnostic(evidence, diagnostic) {
				return unavailableRAR5Decode("RAR5 decode diagnostic overflow")
			}
		}
	}
	if evidence.Batches == 0 {
		return unavailableRAR5Decode("no opt-in RAR5 decode diagnostics were emitted; product hook required")
	}
	return evidence
}

func completeDecodeDiagnostic(diagnostic decodeDiagnostic) bool {
	values := []*uint64{
		diagnostic.TablePrepareNanos, diagnostic.SymbolDecodeNanos,
		diagnostic.PoolDispatchNanos, diagnostic.PoolWaitNanos,
		diagnostic.TablePresentBlocks, diagnostic.TablelessBlocks,
		diagnostic.QuickHuffmanHits, diagnostic.SlowHuffmanHits,
		diagnostic.LiteralSymbols, diagnostic.MatchSymbols,
		diagnostic.RepeatSymbols, diagnostic.FilterSymbols,
		diagnostic.DecodedBufferGrowths, diagnostic.DecodedBufferGrownBytes,
		diagnostic.Assignments, diagnostic.ActiveWorkerSlots, diagnostic.IdleWorkerSlots,
	}
	for _, value := range values {
		if value == nil {
			return false
		}
	}
	return true
}

func addDecodeDiagnostic(evidence *RAR5DecodeEvidence, diagnostic decodeDiagnostic) bool {
	values := [][2]*uint64{
		{&evidence.Batches, uint64Pointer(1)},
		{&evidence.TablePrepareNanos, diagnostic.TablePrepareNanos},
		{&evidence.SymbolDecodeNanos, diagnostic.SymbolDecodeNanos},
		{&evidence.PoolDispatchNanos, diagnostic.PoolDispatchNanos},
		{&evidence.PoolWaitNanos, diagnostic.PoolWaitNanos},
		{&evidence.TablePresentBlocks, diagnostic.TablePresentBlocks},
		{&evidence.TablelessBlocks, diagnostic.TablelessBlocks},
		{&evidence.QuickHuffmanHits, diagnostic.QuickHuffmanHits},
		{&evidence.SlowHuffmanHits, diagnostic.SlowHuffmanHits},
		{&evidence.LiteralSymbols, diagnostic.LiteralSymbols},
		{&evidence.MatchSymbols, diagnostic.MatchSymbols},
		{&evidence.RepeatSymbols, diagnostic.RepeatSymbols},
		{&evidence.FilterSymbols, diagnostic.FilterSymbols},
		{&evidence.DecodedBufferGrowths, diagnostic.DecodedBufferGrowths},
		{&evidence.DecodedBufferGrownBytes, diagnostic.DecodedBufferGrownBytes},
		{&evidence.Assignments, diagnostic.Assignments},
		{&evidence.ActiveWorkerSlots, diagnostic.ActiveWorkerSlots},
		{&evidence.IdleWorkerSlots, diagnostic.IdleWorkerSlots},
	}
	for _, value := range values {
		if ^uint64(0)-*value[0] < *value[1] {
			return false
		}
	}
	for _, value := range values {
		*value[0] += *value[1]
	}
	return true
}

func uint64Pointer(value uint64) *uint64 {
	return &value
}

func unavailableRAR5Decode(reason string) *RAR5DecodeEvidence {
	return &RAR5DecodeEvidence{SchemaVersion: 1, UnavailableReason: reason}
}

// collectRAR5PhaseDiagnostics parses only the explicit benchmark marker. The
// product hook is deliberately optional: an ordinary run produces an
// unavailable reason instead of synthetic phase timings.
func collectRAR5PhaseDiagnostics(stdout, stderr []byte) *RAR5PhaseEvidence {
	evidence := &RAR5PhaseEvidence{}
	values := map[string]int64{}
	seen := map[string]bool{}
	for _, stream := range [][]byte{stdout, stderr} {
		for _, line := range strings.Split(string(stream), "\n") {
			line = strings.TrimSpace(line)
			if !strings.HasPrefix(line, phaseDiagnosticPrefix) {
				continue
			}
			var diagnostic phaseDiagnostic
			if err := json.Unmarshal([]byte(strings.TrimPrefix(line, phaseDiagnosticPrefix)), &diagnostic); err != nil {
				return unavailableRAR5Phases(fmt.Sprintf("invalid benchmark phase diagnostic: %v", err))
			}
			if !knownRAR5Phase(diagnostic.Phase) || diagnostic.Nanos < 0 {
				return unavailableRAR5Phases("invalid benchmark phase diagnostic values")
			}
			current := values[diagnostic.Phase]
			if diagnostic.Nanos > 0 && current > int64(^uint64(0)>>1)-diagnostic.Nanos {
				return unavailableRAR5Phases("benchmark phase diagnostic overflow")
			}
			seen[diagnostic.Phase] = true
			values[diagnostic.Phase] = current + diagnostic.Nanos
		}
	}
	if len(seen) == 0 {
		return unavailableRAR5Phases("no opt-in RAR5 phase diagnostics were emitted; product hook required")
	}
	evidence.StagingNanos = recordedPhase(values, seen, "staging")
	evidence.HeaderScanNanos = recordedPhase(values, seen, "header_scan")
	evidence.WorkerDecodeNanos = recordedPhase(values, seen, "worker_decode")
	evidence.SerialApplyNanos = recordedPhase(values, seen, "serial_apply")
	missing := missingRAR5Phases(evidence)
	if len(missing) > 0 {
		evidence.UnavailableReason = "missing phase diagnostics: " + strings.Join(missing, ", ")
	}
	return evidence
}

func recordedPhase(values map[string]int64, seen map[string]bool, phase string) *int64 {
	if !seen[phase] {
		return nil
	}
	value := values[phase]
	return &value
}

func stripPhaseDiagnosticLines(stream []byte) []byte {
	lines := strings.Split(string(stream), "\n")
	kept := lines[:0]
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, phaseDiagnosticPrefix) || strings.HasPrefix(trimmed, decodeDiagnosticPrefix) {
			continue
		}
		kept = append(kept, line)
	}
	return []byte(strings.Join(kept, "\n"))
}

func unavailableRAR5Phases(reason string) *RAR5PhaseEvidence {
	return &RAR5PhaseEvidence{UnavailableReason: reason}
}

func knownRAR5Phase(phase string) bool {
	switch phase {
	case "staging", "header_scan", "worker_decode", "serial_apply":
		return true
	default:
		return false
	}
}

func missingRAR5Phases(evidence *RAR5PhaseEvidence) []string {
	missing := make([]string, 0, 4)
	if evidence.StagingNanos == nil {
		missing = append(missing, "staging")
	}
	if evidence.HeaderScanNanos == nil {
		missing = append(missing, "header_scan")
	}
	if evidence.WorkerDecodeNanos == nil {
		missing = append(missing, "worker_decode")
	}
	if evidence.SerialApplyNanos == nil {
		missing = append(missing, "serial_apply")
	}
	return missing
}

func summarizeRAR5Phases(executions []Execution) *RAR5PhaseSummary {
	var staging, headerScan, workerDecode, serialApply []int64
	var reasons []string
	hasEvidence := false
	for _, execution := range executions {
		evidence := execution.Measurement.RAR5Phases
		if evidence == nil {
			continue
		}
		hasEvidence = true
		if evidence.StagingNanos != nil {
			staging = append(staging, *evidence.StagingNanos)
		}
		if evidence.HeaderScanNanos != nil {
			headerScan = append(headerScan, *evidence.HeaderScanNanos)
		}
		if evidence.WorkerDecodeNanos != nil {
			workerDecode = append(workerDecode, *evidence.WorkerDecodeNanos)
		}
		if evidence.SerialApplyNanos != nil {
			serialApply = append(serialApply, *evidence.SerialApplyNanos)
		}
		if evidence.UnavailableReason != "" && !containsString(reasons, evidence.UnavailableReason) {
			reasons = append(reasons, evidence.UnavailableReason)
		}
	}
	if !hasEvidence {
		return nil
	}
	missing := []string{}
	if len(staging) != len(executions) {
		missing = append(missing, "staging")
	}
	if len(headerScan) != len(executions) {
		missing = append(missing, "header_scan")
	}
	if len(workerDecode) != len(executions) {
		missing = append(missing, "worker_decode")
	}
	if len(serialApply) != len(executions) {
		missing = append(missing, "serial_apply")
	}
	if len(missing) > 0 {
		reasons = append(reasons, "missing successful samples: "+strings.Join(missing, ", "))
	}
	sort.Strings(reasons)
	return &RAR5PhaseSummary{
		Staging:           phaseSummary(staging),
		HeaderScan:        phaseSummary(headerScan),
		WorkerDecode:      phaseSummary(workerDecode),
		SerialApply:       phaseSummary(serialApply),
		UnavailableReason: strings.Join(reasons, "; "),
	}
}

func phaseSummary(values []int64) *Summary {
	if len(values) == 0 {
		return nil
	}
	sorted := append([]int64(nil), values...)
	sort.Slice(sorted, func(left, right int) bool { return sorted[left] < sorted[right] })
	return &Summary{
		Count:  len(sorted),
		Median: percentile(sorted, 0.5),
		Min:    sorted[0],
		Max:    sorted[len(sorted)-1],
		IQR:    percentile(sorted, 0.75) - percentile(sorted, 0.25),
	}
}

func containsString(values []string, needle string) bool {
	for _, value := range values {
		if value == needle {
			return true
		}
	}
	return false
}

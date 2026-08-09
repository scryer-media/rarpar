package bench

import (
	"math"
	"strings"
	"testing"
)

func TestCollectRAR5DecodeDiagnosticsAggregatesBatches(t *testing.T) {
	first := `RARPAR_BENCH_DECODE {"schema":1,"kind":"rar5_decode","table_prepare_nanos":11,"symbol_decode_nanos":13,"pool_dispatch_nanos":17,"pool_wait_nanos":19,"table_present_blocks":2,"tableless_blocks":3,"quick_huffman_hits":5,"slow_huffman_hits":7,"literal_symbols":23,"match_symbols":29,"repeat_symbols":31,"filter_symbols":37,"decoded_buffer_growths":41,"decoded_buffer_grown_bytes":43,"assignments":47,"active_worker_slots":53,"idle_worker_slots":59}`
	second := `RARPAR_BENCH_DECODE {"schema":1,"kind":"rar5_decode","table_prepare_nanos":1,"symbol_decode_nanos":2,"pool_dispatch_nanos":3,"pool_wait_nanos":4,"table_present_blocks":5,"tableless_blocks":6,"quick_huffman_hits":7,"slow_huffman_hits":8,"literal_symbols":9,"match_symbols":10,"repeat_symbols":11,"filter_symbols":12,"decoded_buffer_growths":13,"decoded_buffer_grown_bytes":14,"assignments":15,"active_worker_slots":16,"idle_worker_slots":17}`

	evidence := collectRAR5DecodeDiagnostics([]byte(first), []byte(second))
	if evidence.UnavailableReason != "" {
		t.Fatalf("unexpected unavailable reason: %s", evidence.UnavailableReason)
	}
	if evidence.Batches != 2 || evidence.TablePrepareNanos != 12 || evidence.SymbolDecodeNanos != 15 {
		t.Fatalf("unexpected timing aggregate: %+v", evidence)
	}
	if evidence.QuickHuffmanHits != 12 || evidence.LiteralSymbols != 32 || evidence.IdleWorkerSlots != 76 {
		t.Fatalf("unexpected counter aggregate: %+v", evidence)
	}
}

func TestCollectRAR5DecodeDiagnosticsRejectsInvalidMarkers(t *testing.T) {
	tests := []string{
		`RARPAR_BENCH_DECODE {`,
		`RARPAR_BENCH_DECODE {"schema":2,"kind":"rar5_decode"}`,
		`RARPAR_BENCH_DECODE {"schema":1,"kind":"other"}`,
	}
	for _, marker := range tests {
		if evidence := collectRAR5DecodeDiagnostics(nil, []byte(marker)); evidence.UnavailableReason == "" {
			t.Fatalf("marker should be rejected: %s", marker)
		}
	}
}

func TestAddRAR5DecodeDiagnosticRejectsOverflow(t *testing.T) {
	evidence := &RAR5DecodeEvidence{Batches: math.MaxUint64}
	if addDecodeDiagnostic(evidence, decodeDiagnostic{}) {
		t.Fatal("overflowing batch count was accepted")
	}
}

func TestStripPhaseDiagnosticLinesStripsDecodeMarkers(t *testing.T) {
	stream := []byte(strings.Join([]string{
		"ordinary output",
		`RARPAR_BENCH_PHASE {"phase":"worker_decode","nanos":1}`,
		`RARPAR_BENCH_DECODE {"schema":1,"kind":"rar5_decode"}`,
		"failure detail",
	}, "\n"))
	got := string(stripPhaseDiagnosticLines(stream))
	if got != "ordinary output\nfailure detail" {
		t.Fatalf("unexpected stripped output: %q", got)
	}
}

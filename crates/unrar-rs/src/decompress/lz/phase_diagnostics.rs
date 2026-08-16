use std::io::Write;
use std::sync::OnceLock;
use std::time::Instant;

const ENABLE_ENV: &str = "RARPAR_BENCH_PHASES";
const MARKER_PREFIX: &str = "RARPAR_BENCH_PHASE ";
const AGGREGATE_MARKER_PREFIX: &str = "RARPAR_BENCH_DECODE ";
const AGGREGATE_SCHEMA: u32 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Phase {
    Staging,
    HeaderScan,
    WorkerDecode,
    SerialApply,
}

impl Phase {
    const fn name(self) -> &'static str {
        match self {
            Self::Staging => "staging",
            Self::HeaderScan => "header_scan",
            Self::WorkerDecode => "worker_decode",
            Self::SerialApply => "serial_apply",
        }
    }
}

static ENABLED: OnceLock<bool> = OnceLock::new();

pub(super) fn enabled() -> bool {
    *ENABLED.get_or_init(|| {
        std::env::var_os(ENABLE_ENV).is_some_and(|value| value == std::ffi::OsStr::new("1"))
    })
}

pub(super) struct Timer {
    phase: Phase,
    started: Option<Instant>,
}

impl Timer {
    pub(super) fn new(phase: Phase) -> Self {
        Self {
            phase,
            started: enabled().then(Instant::now),
        }
    }

    pub(super) fn finish(self) {
        let Some(started) = self.started else {
            return;
        };

        let nanos = started.elapsed().as_nanos().min(i64::MAX as u128) as i64;
        emit(self.phase, nanos);
    }
}

pub(super) fn measure<T>(phase: Phase, operation: impl FnOnce() -> T) -> T {
    let timer = Timer::new(phase);
    let result = operation();
    timer.finish();
    result
}

pub(super) fn emit_zero(phase: Phase) {
    if enabled() {
        emit(phase, 0);
    }
}

/// A category of decoded RAR5 output recorded by a worker without timing each
/// symbol. The caller supplies aggregate durations once an assignment ends.
#[allow(dead_code)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SymbolKind {
    Literal,
    Match,
    Repeat,
    Filter,
}

/// Scalar counters owned by one decode worker for one or more assignments.
///
/// This type deliberately contains no timers, locks, atomics, or collections.
/// A worker can update it locally and transfer it to [`AggregateDiagnostics`]
/// after its assignment completes.
#[allow(dead_code)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) struct WorkerCounters {
    table_prepare_nanos: u64,
    symbol_decode_nanos: u64,
    table_present_blocks: u64,
    tableless_blocks: u64,
    quick_huffman_hits: u64,
    slow_huffman_hits: u64,
    literal_symbols: u64,
    match_symbols: u64,
    repeat_symbols: u64,
    filter_symbols: u64,
    decoded_buffer_growths: u64,
    decoded_buffer_grown_bytes: u64,
    assignments: u64,
}

#[allow(dead_code)]
impl WorkerCounters {
    pub(super) const fn new() -> Self {
        Self {
            table_prepare_nanos: 0,
            symbol_decode_nanos: 0,
            table_present_blocks: 0,
            tableless_blocks: 0,
            quick_huffman_hits: 0,
            slow_huffman_hits: 0,
            literal_symbols: 0,
            match_symbols: 0,
            repeat_symbols: 0,
            filter_symbols: 0,
            decoded_buffer_growths: 0,
            decoded_buffer_grown_bytes: 0,
            assignments: 0,
        }
    }

    pub(super) fn add_table_prepare_nanos(&mut self, nanos: u64) {
        self.table_prepare_nanos = self.table_prepare_nanos.saturating_add(nanos);
    }

    pub(super) fn add_symbol_decode_nanos(&mut self, nanos: u64) {
        self.symbol_decode_nanos = self.symbol_decode_nanos.saturating_add(nanos);
    }

    pub(super) fn record_block(&mut self, table_present: bool) {
        let counter = if table_present {
            &mut self.table_present_blocks
        } else {
            &mut self.tableless_blocks
        };
        *counter = counter.saturating_add(1);
    }

    pub(super) fn record_quick_huffman_hit(&mut self) {
        self.quick_huffman_hits = self.quick_huffman_hits.saturating_add(1);
    }

    pub(super) fn record_slow_huffman_hit(&mut self) {
        self.slow_huffman_hits = self.slow_huffman_hits.saturating_add(1);
    }

    pub(super) fn record_symbol(&mut self, kind: SymbolKind) {
        let counter = match kind {
            SymbolKind::Literal => &mut self.literal_symbols,
            SymbolKind::Match => &mut self.match_symbols,
            SymbolKind::Repeat => &mut self.repeat_symbols,
            SymbolKind::Filter => &mut self.filter_symbols,
        };
        *counter = counter.saturating_add(1);
    }

    pub(super) fn record_decoded_buffer_growth(
        &mut self,
        previous_capacity: usize,
        new_capacity: usize,
    ) {
        if new_capacity <= previous_capacity {
            return;
        }

        self.decoded_buffer_growths = self.decoded_buffer_growths.saturating_add(1);
        let grown_bytes = new_capacity - previous_capacity;
        self.decoded_buffer_grown_bytes = self
            .decoded_buffer_grown_bytes
            .saturating_add(grown_bytes as u64);
    }

    pub(super) fn record_assignment(&mut self) {
        self.assignments = self.assignments.saturating_add(1);
    }
}

/// Opt-in aggregate for one RAR5 decode batch.
///
/// The aggregate is intentionally a plain value. Disabled mode captures the
/// existing environment decision and emits no marker or heap allocation. The
/// caller is responsible for collecting worker-local counters and supplying
/// durations measured around larger operations.
#[allow(dead_code)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) struct AggregateDiagnostics {
    enabled: bool,
    table_prepare_nanos: u64,
    symbol_decode_nanos: u64,
    pool_dispatch_nanos: u64,
    pool_wait_nanos: u64,
    table_present_blocks: u64,
    tableless_blocks: u64,
    quick_huffman_hits: u64,
    slow_huffman_hits: u64,
    literal_symbols: u64,
    match_symbols: u64,
    repeat_symbols: u64,
    filter_symbols: u64,
    decoded_buffer_growths: u64,
    decoded_buffer_grown_bytes: u64,
    assignments: u64,
    active_worker_slots: u64,
    idle_worker_slots: u64,
}

#[allow(dead_code)]
impl AggregateDiagnostics {
    pub(super) fn new() -> Self {
        Self {
            enabled: enabled(),
            ..Self::default()
        }
    }

    pub(super) fn disabled() -> Self {
        Self {
            enabled: false,
            ..Self::default()
        }
    }

    pub(super) const fn is_enabled(self) -> bool {
        self.enabled
    }

    pub(super) fn add_pool_dispatch_nanos(&mut self, nanos: u64) {
        self.pool_dispatch_nanos = self.pool_dispatch_nanos.saturating_add(nanos);
    }

    pub(super) fn add_pool_wait_nanos(&mut self, nanos: u64) {
        self.pool_wait_nanos = self.pool_wait_nanos.saturating_add(nanos);
    }

    pub(super) fn record_worker_slots(&mut self, active: usize, idle: usize) {
        self.active_worker_slots = self.active_worker_slots.saturating_add(active as u64);
        self.idle_worker_slots = self.idle_worker_slots.saturating_add(idle as u64);
    }

    pub(super) fn absorb_worker(&mut self, worker: WorkerCounters) {
        self.table_prepare_nanos = self
            .table_prepare_nanos
            .saturating_add(worker.table_prepare_nanos);
        self.symbol_decode_nanos = self
            .symbol_decode_nanos
            .saturating_add(worker.symbol_decode_nanos);
        self.table_present_blocks = self
            .table_present_blocks
            .saturating_add(worker.table_present_blocks);
        self.tableless_blocks = self
            .tableless_blocks
            .saturating_add(worker.tableless_blocks);
        self.quick_huffman_hits = self
            .quick_huffman_hits
            .saturating_add(worker.quick_huffman_hits);
        self.slow_huffman_hits = self
            .slow_huffman_hits
            .saturating_add(worker.slow_huffman_hits);
        self.literal_symbols = self.literal_symbols.saturating_add(worker.literal_symbols);
        self.match_symbols = self.match_symbols.saturating_add(worker.match_symbols);
        self.repeat_symbols = self.repeat_symbols.saturating_add(worker.repeat_symbols);
        self.filter_symbols = self.filter_symbols.saturating_add(worker.filter_symbols);
        self.decoded_buffer_growths = self
            .decoded_buffer_growths
            .saturating_add(worker.decoded_buffer_growths);
        self.decoded_buffer_grown_bytes = self
            .decoded_buffer_grown_bytes
            .saturating_add(worker.decoded_buffer_grown_bytes);
        self.assignments = self.assignments.saturating_add(worker.assignments);
    }

    pub(super) fn emit(self) {
        if !self.enabled {
            return;
        }

        let mut marker = format_aggregate_marker(&self);
        marker.push('\n');
        let mut stderr = std::io::stderr().lock();
        let _ = stderr.write_all(marker.as_bytes());
    }
}

fn emit(phase: Phase, nanos: i64) {
    let mut marker = format_marker(phase, nanos);
    marker.push('\n');
    let mut stderr = std::io::stderr().lock();
    let _ = stderr.write_all(marker.as_bytes());
}

fn format_marker(phase: Phase, nanos: i64) -> String {
    format!(
        "{MARKER_PREFIX}{{\"phase\":\"{}\",\"nanos\":{nanos}}}",
        phase.name()
    )
}

fn format_aggregate_marker(diagnostics: &AggregateDiagnostics) -> String {
    format!(
        "{AGGREGATE_MARKER_PREFIX}{{\"schema\":{AGGREGATE_SCHEMA},\"kind\":\"rar5_decode\",\"table_prepare_nanos\":{},\"symbol_decode_nanos\":{},\"pool_dispatch_nanos\":{},\"pool_wait_nanos\":{},\"table_present_blocks\":{},\"tableless_blocks\":{},\"quick_huffman_hits\":{},\"slow_huffman_hits\":{},\"literal_symbols\":{},\"match_symbols\":{},\"repeat_symbols\":{},\"filter_symbols\":{},\"decoded_buffer_growths\":{},\"decoded_buffer_grown_bytes\":{},\"assignments\":{},\"active_worker_slots\":{},\"idle_worker_slots\":{}}}",
        diagnostics.table_prepare_nanos,
        diagnostics.symbol_decode_nanos,
        diagnostics.pool_dispatch_nanos,
        diagnostics.pool_wait_nanos,
        diagnostics.table_present_blocks,
        diagnostics.tableless_blocks,
        diagnostics.quick_huffman_hits,
        diagnostics.slow_huffman_hits,
        diagnostics.literal_symbols,
        diagnostics.match_symbols,
        diagnostics.repeat_symbols,
        diagnostics.filter_symbols,
        diagnostics.decoded_buffer_growths,
        diagnostics.decoded_buffer_grown_bytes,
        diagnostics.assignments,
        diagnostics.active_worker_slots,
        diagnostics.idle_worker_slots,
    )
}

#[cfg(test)]
mod tests {
    use super::{
        AggregateDiagnostics, Phase, SymbolKind, WorkerCounters, format_aggregate_marker,
        format_marker,
    };

    #[test]
    fn marker_payload_is_exact() {
        assert_eq!(
            format_marker(Phase::Staging, 123),
            "RARPAR_BENCH_PHASE {\"phase\":\"staging\",\"nanos\":123}"
        );
        assert_eq!(
            format_marker(Phase::SerialApply, 0),
            "RARPAR_BENCH_PHASE {\"phase\":\"serial_apply\",\"nanos\":0}"
        );
    }

    #[test]
    fn phase_names_are_stable() {
        let phases = [
            (Phase::Staging, "staging"),
            (Phase::HeaderScan, "header_scan"),
            (Phase::WorkerDecode, "worker_decode"),
            (Phase::SerialApply, "serial_apply"),
        ];

        for (phase, expected_name) in phases {
            assert_eq!(phase.name(), expected_name);
        }
    }

    #[test]
    fn worker_counters_accumulate_aggregate_values() {
        let mut worker = WorkerCounters::new();
        worker.add_table_prepare_nanos(11);
        worker.add_table_prepare_nanos(7);
        worker.add_symbol_decode_nanos(13);
        worker.record_block(true);
        worker.record_block(false);
        worker.record_quick_huffman_hit();
        worker.record_slow_huffman_hit();
        worker.record_symbol(SymbolKind::Literal);
        worker.record_symbol(SymbolKind::Match);
        worker.record_symbol(SymbolKind::Repeat);
        worker.record_symbol(SymbolKind::Filter);
        worker.record_decoded_buffer_growth(8, 24);
        worker.record_decoded_buffer_growth(24, 24);
        worker.record_assignment();

        let mut aggregate = AggregateDiagnostics::disabled();
        aggregate.absorb_worker(worker);
        aggregate.add_pool_dispatch_nanos(17);
        aggregate.add_pool_wait_nanos(19);
        aggregate.record_worker_slots(3, 1);

        assert_eq!(
            aggregate,
            AggregateDiagnostics {
                enabled: false,
                table_prepare_nanos: 18,
                symbol_decode_nanos: 13,
                pool_dispatch_nanos: 17,
                pool_wait_nanos: 19,
                table_present_blocks: 1,
                tableless_blocks: 1,
                quick_huffman_hits: 1,
                slow_huffman_hits: 1,
                literal_symbols: 1,
                match_symbols: 1,
                repeat_symbols: 1,
                filter_symbols: 1,
                decoded_buffer_growths: 1,
                decoded_buffer_grown_bytes: 16,
                assignments: 1,
                active_worker_slots: 3,
                idle_worker_slots: 1,
            }
        );
    }

    #[test]
    fn aggregate_marker_payload_is_deterministic() {
        let mut aggregate = AggregateDiagnostics::disabled();
        aggregate.add_pool_dispatch_nanos(17);
        aggregate.add_pool_wait_nanos(19);
        aggregate.record_worker_slots(3, 1);

        let marker = format_aggregate_marker(&aggregate);
        assert_eq!(
            marker,
            "RARPAR_BENCH_DECODE {\"schema\":1,\"kind\":\"rar5_decode\",\"table_prepare_nanos\":0,\"symbol_decode_nanos\":0,\"pool_dispatch_nanos\":17,\"pool_wait_nanos\":19,\"table_present_blocks\":0,\"tableless_blocks\":0,\"quick_huffman_hits\":0,\"slow_huffman_hits\":0,\"literal_symbols\":0,\"match_symbols\":0,\"repeat_symbols\":0,\"filter_symbols\":0,\"decoded_buffer_growths\":0,\"decoded_buffer_grown_bytes\":0,\"assignments\":0,\"active_worker_slots\":3,\"idle_worker_slots\":1}"
        );
    }

    #[test]
    fn disabled_aggregate_is_inert_and_saturating() {
        let mut worker = WorkerCounters::new();
        worker.add_table_prepare_nanos(u64::MAX);
        worker.add_table_prepare_nanos(1);
        worker.record_decoded_buffer_growth(0, usize::MAX);

        let mut aggregate = AggregateDiagnostics::disabled();
        aggregate.absorb_worker(worker);
        aggregate.add_pool_dispatch_nanos(u64::MAX);
        aggregate.add_pool_dispatch_nanos(1);

        assert!(!aggregate.is_enabled());
        assert_eq!(aggregate.table_prepare_nanos, u64::MAX);
        assert_eq!(aggregate.decoded_buffer_grown_bytes, u64::MAX);
        assert_eq!(aggregate.pool_dispatch_nanos, u64::MAX);
    }
}

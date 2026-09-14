//! Per-member staged decode feedback. No pool, allocation, or global policy.
use std::time::Duration;

#[derive(Default)]
pub(super) struct AdaptiveDecode {
    input_cost: Option<f64>,
    inline_cost: Option<f64>,
    parallel: bool,
}

impl AdaptiveDecode {
    pub(super) fn observe_input(&mut self, bytes: usize, elapsed: Duration) {
        if bytes != 0 {
            self.input_cost = Some(elapsed.as_secs_f64() / bytes as f64);
        }
    }

    pub(super) fn use_parallel(&mut self, bytes: usize) -> bool {
        // Small rounds do not establish a useful timing sample or amortize a
        // batch. The first substantial round calibrates inline decode.
        if bytes < 64 * 1024 {
            return false;
        }
        let (Some(input), Some(inline)) = (self.input_cost, self.inline_cost) else {
            return false;
        };
        // Hysteresis: require a clear CPU bottleneck to enter parallel mode;
        // leave it when filling the stage costs at least as much as decoding.
        if input * 2.0 < inline {
            self.parallel = true;
        } else if input >= inline {
            self.parallel = false;
        }
        self.parallel
    }

    pub(super) fn observe_inline(&mut self, bytes: usize, elapsed: Duration) {
        if bytes >= 64 * 1024 && !elapsed.is_zero() {
            self.inline_cost = Some(elapsed.as_secs_f64() / bytes as f64);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adapts_both_directions_without_a_fixed_throughput_threshold() {
        let mut state = AdaptiveDecode::default();
        let bytes = 1024 * 1024;
        state.observe_input(bytes, Duration::from_millis(1));
        assert!(!state.use_parallel(bytes));
        state.observe_inline(bytes, Duration::from_millis(10));
        assert!(state.use_parallel(bytes));
        state.observe_input(bytes, Duration::from_millis(100));
        assert!(!state.use_parallel(bytes));
        state.observe_inline(bytes, Duration::from_millis(8));
        state.observe_input(bytes, Duration::from_micros(100));
        assert!(state.use_parallel(bytes));
    }

    #[test]
    fn hysteresis_short_reads_and_eof_keep_meaningful_samples() {
        let mut state = AdaptiveDecode::default();
        let bytes = 1024 * 1024;
        state.observe_inline(bytes, Duration::from_millis(10));
        state.observe_input(bytes, Duration::from_millis(6));
        assert!(!state.use_parallel(bytes));
        state.observe_input(bytes, Duration::from_millis(4));
        assert!(state.use_parallel(bytes));
        state.observe_input(bytes, Duration::from_millis(6));
        assert!(state.use_parallel(bytes));
        state.observe_input(0, Duration::ZERO);
        state.observe_inline(1, Duration::from_secs(10));
        assert!(state.use_parallel(bytes));
        assert!(!state.use_parallel(1024));
        state.observe_input(bytes / 2, Duration::from_millis(5));
        assert!(!state.use_parallel(bytes));
    }
}

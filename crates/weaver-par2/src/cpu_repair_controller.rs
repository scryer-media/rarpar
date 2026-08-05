//! CPU repair-controller scheduling.
//!
//! This module deliberately owns policy rather than arithmetic: input grouping,
//! aligned chunk sizing, and the static chunk/output split used by the repair
//! engine. Kernel-specific preparation and multiplication stay in `repair` and
//! `reedsolomon-rs`.

const DEFAULT_INPUT_GROUPING: usize = 12;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct KernelCapabilities {
    pub(crate) stride: usize,
    pub(crate) ideal_input_multiple: usize,
    pub(crate) ideal_chunk_size: usize,
}

impl KernelCapabilities {
    pub(crate) fn input_grouping(self) -> usize {
        let multiple = self.ideal_input_multiple.max(1);
        let rounded = (DEFAULT_INPUT_GROUPING + multiple / 2) / multiple * multiple;
        rounded.max(multiple)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct WorkAssignment {
    pub(crate) worker: usize,
    pub(crate) byte_start: usize,
    pub(crate) byte_len: usize,
    pub(crate) output_start: usize,
    pub(crate) output_len: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ControllerLayout {
    pub(crate) aligned_len: usize,
    pub(crate) chunk_len: usize,
    pub(crate) num_chunks: usize,
    pub(crate) assignments: Vec<WorkAssignment>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct InputBatch {
    pub(crate) staging_area: usize,
    pub(crate) input_start: usize,
    pub(crate) input_len: usize,
    pub(crate) add: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CpuControllerPlan {
    pub(crate) input_grouping: usize,
    pub(crate) layout: ControllerLayout,
    pub(crate) input_batches: Vec<InputBatch>,
}

impl CpuControllerPlan {
    pub(crate) fn new(
        current_slice_size: usize,
        input_count: usize,
        output_count: usize,
        worker_count: usize,
        capabilities: KernelCapabilities,
    ) -> Self {
        assert!(input_count > 0);
        let input_grouping = capabilities.input_grouping();
        let input_batches = (0..input_count.div_ceil(input_grouping))
            .map(|batch| {
                let input_start = batch * input_grouping;
                InputBatch {
                    staging_area: batch % 2,
                    input_start,
                    input_len: input_grouping.min(input_count - input_start),
                    add: batch != 0,
                }
            })
            .collect();
        Self {
            input_grouping,
            layout: ControllerLayout::new(
                current_slice_size,
                output_count,
                worker_count,
                capabilities,
            ),
            input_batches,
        }
    }
}

impl ControllerLayout {
    pub(crate) fn new(
        current_slice_size: usize,
        output_count: usize,
        worker_count: usize,
        capabilities: KernelCapabilities,
    ) -> Self {
        assert!(current_slice_size > 0);
        assert!(output_count > 0);
        let workers = worker_count.max(1);
        let stride = capabilities.stride.max(1);
        let ideal_chunk = align_up(capabilities.ideal_chunk_size.max(stride), stride);
        let aligned_len = align_up(current_slice_size, stride);

        let target_thread_chunk = aligned_len.div_ceil(workers);
        let mut num_chunks = if target_thread_chunk <= ideal_chunk / 2 {
            round_div(aligned_len, ideal_chunk).max(1)
        } else {
            round_div(target_thread_chunk, ideal_chunk).max(1) * workers
        };
        let chunk_len = align_up(aligned_len.div_ceil(num_chunks), stride);
        num_chunks = aligned_len.div_ceil(chunk_len);

        let assignments =
            build_assignments(aligned_len, chunk_len, num_chunks, output_count, workers);
        Self {
            aligned_len,
            chunk_len,
            num_chunks,
            assignments,
        }
    }
}

fn build_assignments(
    aligned_len: usize,
    chunk_len: usize,
    num_chunks: usize,
    output_count: usize,
    workers: usize,
) -> Vec<WorkAssignment> {
    let full_chunks_per_worker = num_chunks / workers;
    let leftover_chunks = num_chunks % workers;
    let mut assignments = Vec::new();
    let mut chunk = 0usize;

    if leftover_chunks > 0 {
        let workers_per_chunk = workers
            .checked_div(leftover_chunks)
            .unwrap_or(1)
            .min(output_count)
            .max(1);
        for _ in 0..leftover_chunks {
            let byte_start = chunk * chunk_len;
            let byte_len = (aligned_len - byte_start).min(chunk_len);
            let mut output_start = 0usize;
            for split in 0..workers_per_chunk {
                let output_end = round_div(output_count * (split + 1), workers_per_chunk);
                assignments.push(WorkAssignment {
                    worker: assignments.len(),
                    byte_start,
                    byte_len,
                    output_start,
                    output_len: output_end - output_start,
                });
                output_start = output_end;
            }
            debug_assert_eq!(output_start, output_count);
            chunk += 1;
        }
    }

    if full_chunks_per_worker > 0 {
        for worker in 0..workers {
            let byte_start = chunk * chunk_len;
            let byte_len = (aligned_len - byte_start).min(chunk_len * full_chunks_per_worker);
            assignments.push(WorkAssignment {
                worker,
                byte_start,
                byte_len,
                output_start: 0,
                output_len: output_count,
            });
            chunk += full_chunks_per_worker;
        }
    }

    debug_assert_eq!(chunk, num_chunks);
    assignments
}

fn align_up(value: usize, alignment: usize) -> usize {
    value.div_ceil(alignment) * alignment
}

fn round_div(value: usize, divisor: usize) -> usize {
    (value + divisor / 2) / divisor
}

#[cfg(test)]
mod tests {
    use super::*;

    const CAPS: KernelCapabilities = KernelCapabilities {
        stride: 32,
        ideal_input_multiple: 1,
        ideal_chunk_size: 64 * 1024,
    };

    #[test]
    fn input_grouping_rounds_twelve_to_kernel_multiple() {
        assert_eq!(CAPS.input_grouping(), 12);
        assert_eq!(
            KernelCapabilities {
                ideal_input_multiple: 6,
                ..CAPS
            }
            .input_grouping(),
            12
        );
        assert_eq!(
            KernelCapabilities {
                ideal_input_multiple: 8,
                ..CAPS
            }
            .input_grouping(),
            16
        );
    }

    #[test]
    fn input_batches_rotate_staging_and_flush_partial_group() {
        let plan = CpuControllerPlan::new(64 * 1024, 25, 4, 8, CAPS);
        assert_eq!(plan.input_grouping, 12);
        assert_eq!(
            plan.input_batches,
            vec![
                InputBatch {
                    staging_area: 0,
                    input_start: 0,
                    input_len: 12,
                    add: false,
                },
                InputBatch {
                    staging_area: 1,
                    input_start: 12,
                    input_len: 12,
                    add: true,
                },
                InputBatch {
                    staging_area: 0,
                    input_start: 24,
                    input_len: 1,
                    add: true,
                },
            ]
        );
    }

    #[test]
    fn one_chunk_splits_outputs_across_workers() {
        let layout = ControllerLayout::new(64 * 1024, 512, 12, CAPS);
        assert_eq!(layout.num_chunks, 1);
        assert_eq!(layout.assignments.len(), 12);
        assert!(layout.assignments.iter().all(|work| work.byte_start == 0));
        assert!(
            layout
                .assignments
                .iter()
                .all(|work| work.byte_len == 64 * 1024)
        );
        assert_eq!(
            layout
                .assignments
                .iter()
                .map(|work| work.output_len)
                .sum::<usize>(),
            512
        );
    }

    #[test]
    fn large_slice_distributes_full_chunks_across_workers() {
        let layout = ControllerLayout::new(1024 * 1024, 8, 12, CAPS);
        assert_eq!(layout.num_chunks, 12);
        assert_eq!(layout.assignments.len(), 12);
        assert!(layout.assignments.iter().all(|work| work.output_len == 8));
        assert_eq!(
            layout
                .assignments
                .iter()
                .map(|work| work.byte_len)
                .sum::<usize>(),
            layout.aligned_len
        );
    }

    #[test]
    fn leftover_chunks_split_outputs_then_assign_full_chunks() {
        let caps = KernelCapabilities {
            ideal_chunk_size: 96 * 1024,
            ..CAPS
        };
        let layout = ControllerLayout::new(3 * 1024 * 1024, 17, 8, caps);
        assert!(layout.num_chunks > 8);

        let mut coverage = vec![0u8; layout.aligned_len * 17];
        for work in &layout.assignments {
            for output in work.output_start..work.output_start + work.output_len {
                for byte in work.byte_start..work.byte_start + work.byte_len {
                    coverage[output * layout.aligned_len + byte] += 1;
                }
            }
        }
        assert!(coverage.iter().all(|count| *count == 1));
    }

    #[test]
    fn short_slice_is_stride_aligned() {
        let layout = ControllerLayout::new(65_537, 3, 4, CAPS);
        assert_eq!(layout.aligned_len % CAPS.stride, 0);
        assert_eq!(layout.chunk_len % CAPS.stride, 0);
        assert!(layout.aligned_len >= 65_537);
    }
}

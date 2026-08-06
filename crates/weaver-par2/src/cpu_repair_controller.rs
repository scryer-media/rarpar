//! CPU repair-controller scheduling.
//!
//! This module deliberately owns policy rather than arithmetic: input grouping,
//! aligned chunk sizing, and the static chunk/output split used by the repair
//! engine. Kernel-specific preparation and multiplication stay in `repair` and
//! `reedsolomon-rs`.

const DEFAULT_INPUT_GROUPING: usize = 12;
const CONTROLLER_STAGING_AREAS: usize = 2;
const CONTROLLER_TRANSFER_BUFFERS: usize = 2;

/// Normalized live-execution events. These are distinct from the deterministic
/// lifecycle trace: they describe the operations the real controller actually
/// performed, including failure before staged output can be accepted.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ControllerExecutionEvent {
    SlotState {
        status: ControllerAddStatus,
        staging_area: usize,
    },
    Backpressure {
        staging_area: usize,
    },
    WaitForAdd {
        staging_area: usize,
    },
    SourceRead {
        source_index: usize,
        staging_area: usize,
    },
    InputQueued {
        source_index: usize,
        staging_area: usize,
        slot: usize,
    },
    PreparationCompleted {
        staging_area: usize,
        input_len: usize,
    },
    BatchSubmitted {
        staging_area: usize,
        input_start: usize,
        input_len: usize,
        add: bool,
        reason: BatchSubmitReason,
    },
    StagingRotated {
        from: usize,
        to: usize,
    },
    ComputeSubmitted {
        staging_area: usize,
        add: bool,
    },
    ComputeCompleted {
        staging_area: usize,
    },
    OutputTransferQueued {
        output: usize,
    },
    OutputWritten {
        output: usize,
    },
    InputEnded {
        partial_batch_flushed: bool,
    },
    ProcessingFinished,
    Failed {
        phase: ControllerFailurePhase,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ControllerFailurePhase {
    Read,
    Prepare,
    Compute,
    OutputTransfer,
    Write,
}

/// Disabled by default and enabled only by execution-level tests. The runtime
/// always emits through this object, so test traces cannot drift into a second
/// simulated controller path.
#[derive(Clone, Debug, Default)]
pub(crate) struct ControllerExecutionTrace {
    #[cfg(test)]
    events: Option<std::sync::Arc<std::sync::Mutex<Vec<ControllerExecutionEvent>>>>,
}

impl ControllerExecutionTrace {
    #[cfg(test)]
    pub(crate) fn capture() -> Self {
        Self {
            events: Some(std::sync::Arc::new(std::sync::Mutex::new(Vec::new()))),
        }
    }

    pub(crate) fn record(&self, event: ControllerExecutionEvent) {
        #[cfg(test)]
        if let Some(events) = &self.events {
            events.lock().expect("controller trace lock").push(event);
        }
        #[cfg(not(test))]
        let _ = event;
    }

    #[cfg(test)]
    pub(crate) fn events(&self) -> Vec<ControllerExecutionEvent> {
        self.events
            .as_ref()
            .map(|events| events.lock().expect("controller trace lock").clone())
            .unwrap_or_default()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ControllerAddStatus {
    Ready,
    ReadyBusy,
    Full,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BatchSubmitReason {
    GroupFull,
    ExplicitFlush,
    IdleThreshold,
    EndInput,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ControllerBufferAccounting {
    pub(crate) aligned_slice_len: usize,
    /// Physical allocation length for one row, including allocator padding.
    pub(crate) physical_row_len: usize,
    /// Number of live inputs submitted in one controller batch.
    pub(crate) input_grouping: usize,
    /// Physical rows reserved in each staging area; folded kernels may need
    /// more rows than the live input grouping.
    pub(crate) allocated_staging_width: usize,
    pub(crate) output_count: usize,
    pub(crate) transfer_buffer_count: usize,
    pub(crate) transfer_buffer_bytes: usize,
    pub(crate) staging_area_count: usize,
    pub(crate) staging_area_bytes: usize,
    pub(crate) output_area_bytes: usize,
    pub(crate) total_bytes: usize,
}

impl ControllerBufferAccounting {
    fn new(
        aligned_slice_len: usize,
        input_grouping: usize,
        allocated_staging_width: usize,
        output_count: usize,
        method: CpuMethodContract,
    ) -> Self {
        assert!(aligned_slice_len > 0);
        assert!(input_grouping > 0);
        assert!(allocated_staging_width >= input_grouping);
        let physical_row_len = align_up(aligned_slice_len, method.alignment.max(1));
        let staging_area_bytes = allocated_staging_width
            .checked_mul(physical_row_len)
            .expect("controller staging allocation size overflow");
        let transfer_buffer_bytes = physical_row_len;
        let transfer_bytes = CONTROLLER_TRANSFER_BUFFERS
            .checked_mul(transfer_buffer_bytes)
            .expect("controller transfer allocation size overflow");
        let output_area_bytes = output_count
            .checked_mul(physical_row_len)
            .expect("controller output allocation size overflow");
        let staging_bytes = CONTROLLER_STAGING_AREAS
            .checked_mul(staging_area_bytes)
            .expect("controller staging allocation size overflow");
        let total_bytes = transfer_bytes
            .checked_add(staging_bytes)
            .and_then(|bytes| bytes.checked_add(output_area_bytes))
            .expect("controller allocation size overflow");

        Self {
            aligned_slice_len,
            physical_row_len,
            input_grouping,
            allocated_staging_width,
            output_count,
            transfer_buffer_count: CONTROLLER_TRANSFER_BUFFERS,
            transfer_buffer_bytes,
            staging_area_count: CONTROLLER_STAGING_AREAS,
            staging_area_bytes,
            output_area_bytes,
            total_bytes,
        }
    }
}

#[cfg(test)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ControllerTraceEvent {
    Initialized {
        staging_area_count: usize,
        transfer_buffer_count: usize,
        input_grouping: usize,
        aligned_slice_len: usize,
        output_count: usize,
        worker_count: usize,
    },
    LayoutPlanned {
        aligned_len: usize,
        chunk_len: usize,
        num_chunks: usize,
        assignment_count: usize,
    },
    WorkScheduled {
        worker: usize,
        byte_start: usize,
        byte_len: usize,
        output_start: usize,
        output_len: usize,
    },
    SlotState {
        status: ControllerAddStatus,
        staging_area: usize,
    },
    InputAccepted {
        input_index: usize,
        staging_area: usize,
        slot: usize,
    },
    Backpressure {
        status: ControllerAddStatus,
        staging_area: usize,
    },
    WaitForAdd {
        staging_area: usize,
    },
    BatchSubmitted {
        staging_area: usize,
        input_start: usize,
        input_len: usize,
        add: bool,
        reason: BatchSubmitReason,
    },
    StagingRotated {
        from: usize,
        to: usize,
    },
    BatchCompleted {
        staging_area: usize,
    },
    InputEnded {
        partial_batch_flushed: bool,
    },
    ProcessingFinished,
}

#[cfg(test)]
macro_rules! record_controller_trace {
    ($lifecycle:expr, $event:expr) => {
        $lifecycle.trace.push($event);
    };
}

#[cfg(not(test))]
macro_rules! record_controller_trace {
    ($lifecycle:expr, $event:expr) => {};
}

/// The complete scheduling contract supplied by the selected CPU arithmetic
/// method.  It is deliberately a value rather than a collection of ad-hoc
/// kernel queries: allocation, transfer checksums, layout and invocation
/// prefetching must all describe the same method.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CpuMethodContract {
    pub(crate) stride: usize,
    pub(crate) alignment: usize,
    pub(crate) ideal_input_multiple: usize,
    /// Physical source rows required per logical input group.
    pub(crate) staging_multiple: usize,
    pub(crate) ideal_chunk_size: usize,
    pub(crate) checksum_width: usize,
    pub(crate) prefetch: CpuPrefetch,
    /// Cached process capability for a strict RW -> RX -> RW worker JIT
    /// transition. It is false for methods that do not execute JIT code.
    pub(crate) strict_wx_available: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CpuPrefetch {
    /// Inputs prepared per packed invocation. Zero disables input prefetch.
    pub(crate) inputs_per_invoke: usize,
    /// Exponent used by the input prefetch distance calculation.
    pub(crate) input_distance_shift: usize,
    /// Whether the next output range should be prefetched when available.
    pub(crate) output: bool,
}

impl CpuMethodContract {
    pub(crate) fn input_grouping(self) -> usize {
        let multiple = self.ideal_input_multiple.max(1);
        let rounded = (DEFAULT_INPUT_GROUPING + multiple / 2) / multiple * multiple;
        rounded.max(multiple)
    }

    pub(crate) fn staging_width(self) -> usize {
        let grouping = self.input_grouping();
        let multiple = self.staging_multiple.max(1);
        grouping.div_ceil(multiple) * multiple
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
    pub(crate) worker_count: usize,
    pub(crate) stride: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct InputBatch {
    pub(crate) staging_area: usize,
    pub(crate) input_start: usize,
    pub(crate) input_len: usize,
    pub(crate) add: bool,
    pub(crate) reason: BatchSubmitReason,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ControllerAddResult {
    Accepted {
        staging_area: usize,
        slot: usize,
        submitted: Option<InputBatch>,
    },
    Full,
}

/// Deterministic state for the two-area controller protocol.
///
/// The arithmetic backend consumes the submitted batches; this type owns the
/// slot protocol around them. An active area cannot be reused, and the caller
/// must complete it before retrying an add that reports `Full`.
#[derive(Clone, Debug)]
pub(crate) struct ControllerLifecycle {
    pub(crate) input_grouping: usize,
    pub(crate) min_input_batch_size: usize,
    pub(crate) current_staging_area: usize,
    pub(crate) current_staging_inputs: usize,
    pub(crate) next_input_index: usize,
    pub(crate) active_staging: [bool; CONTROLLER_STAGING_AREAS],
    pub(crate) processing_add: bool,
    pub(crate) ended: bool,
    pub(crate) batches_started: usize,
    execution_trace: ControllerExecutionTrace,
    #[cfg(test)]
    trace: Vec<ControllerTraceEvent>,
}

impl ControllerLifecycle {
    pub(crate) fn new(input_grouping: usize) -> Self {
        assert!(input_grouping > 0);
        Self {
            input_grouping,
            min_input_batch_size: input_grouping,
            current_staging_area: 0,
            current_staging_inputs: 0,
            next_input_index: 0,
            active_staging: [false; CONTROLLER_STAGING_AREAS],
            processing_add: false,
            ended: false,
            batches_started: 0,
            execution_trace: ControllerExecutionTrace::default(),
            #[cfg(test)]
            trace: Vec::new(),
        }
    }

    pub(crate) fn with_execution_trace(mut self, trace: ControllerExecutionTrace) -> Self {
        self.execution_trace = trace;
        self
    }

    #[cfg(test)]
    pub(crate) fn with_min_input_batch_size(mut self, min_input_batch_size: usize) -> Self {
        self.min_input_batch_size = min_input_batch_size.max(1);
        self
    }

    #[cfg(test)]
    pub(crate) fn trace(&self) -> &[ControllerTraceEvent] {
        &self.trace
    }

    pub(crate) fn can_add(&self) -> ControllerAddStatus {
        let status = if self.active_staging[self.current_staging_area] {
            ControllerAddStatus::Full
        } else if self.active_staging[self.previous_staging_area()] {
            ControllerAddStatus::ReadyBusy
        } else {
            ControllerAddStatus::Ready
        };
        self.execution_trace
            .record(ControllerExecutionEvent::SlotState {
                status,
                staging_area: self.current_staging_area,
            });
        status
    }

    pub(crate) fn observe_backpressure(&mut self) -> ControllerAddStatus {
        let status = self.can_add();
        if status == ControllerAddStatus::Full {
            self.execution_trace
                .record(ControllerExecutionEvent::Backpressure {
                    staging_area: self.current_staging_area,
                });
            record_controller_trace!(
                self,
                ControllerTraceEvent::Backpressure {
                    status,
                    staging_area: self.current_staging_area,
                }
            );
        }
        status
    }

    pub(crate) fn add_input(&mut self, flush: bool) -> ControllerAddResult {
        assert!(!self.ended, "cannot add input after end_input");
        let status = self.can_add();
        record_controller_trace!(
            self,
            ControllerTraceEvent::SlotState {
                status,
                staging_area: self.current_staging_area,
            }
        );
        if status == ControllerAddStatus::Full {
            self.observe_backpressure();
            return ControllerAddResult::Full;
        }

        let staging_area = self.current_staging_area;
        let slot = self.current_staging_inputs;
        #[cfg(test)]
        let input_index = self.next_input_index;
        self.current_staging_inputs += 1;
        self.next_input_index += 1;
        record_controller_trace!(
            self,
            ControllerTraceEvent::InputAccepted {
                input_index,
                staging_area,
                slot,
            }
        );

        let reason = if flush {
            Some(BatchSubmitReason::ExplicitFlush)
        } else if self.current_staging_inputs == self.input_grouping {
            Some(BatchSubmitReason::GroupFull)
        } else if self.active_staging_count() == 0
            && self.current_staging_inputs >= self.min_input_batch_size
        {
            Some(BatchSubmitReason::IdleThreshold)
        } else {
            None
        };
        let submitted = reason.map(|reason| self.submit_current_batch(reason));
        ControllerAddResult::Accepted {
            staging_area,
            slot,
            submitted,
        }
    }

    pub(crate) fn wait_for_add(&mut self) {
        assert_eq!(self.can_add(), ControllerAddStatus::Full);
        self.execution_trace
            .record(ControllerExecutionEvent::WaitForAdd {
                staging_area: self.current_staging_area,
            });
        record_controller_trace!(
            self,
            ControllerTraceEvent::WaitForAdd {
                staging_area: self.current_staging_area,
            }
        );
    }

    pub(crate) fn end_input(&mut self) -> Option<InputBatch> {
        assert!(!self.ended, "end_input called twice");
        let partial_batch_flushed = self.current_staging_inputs != 0;
        let submitted = if partial_batch_flushed {
            Some(self.submit_current_batch(BatchSubmitReason::EndInput))
        } else {
            None
        };
        self.ended = true;
        self.execution_trace
            .record(ControllerExecutionEvent::InputEnded {
                partial_batch_flushed,
            });
        record_controller_trace!(
            self,
            ControllerTraceEvent::InputEnded {
                partial_batch_flushed,
            }
        );
        submitted
    }

    pub(crate) fn complete_batch(&mut self, staging_area: usize) {
        assert!(staging_area < CONTROLLER_STAGING_AREAS);
        assert!(self.active_staging[staging_area]);
        self.active_staging[staging_area] = false;
        record_controller_trace!(self, ControllerTraceEvent::BatchCompleted { staging_area });
    }

    pub(crate) fn processing_finished(&mut self) {
        assert!(self.ended);
        assert!(self.active_staging.iter().all(|active| !active));
        self.execution_trace
            .record(ControllerExecutionEvent::ProcessingFinished);
        record_controller_trace!(self, ControllerTraceEvent::ProcessingFinished);
    }

    fn previous_staging_area(&self) -> usize {
        (self.current_staging_area + CONTROLLER_STAGING_AREAS - 1) % CONTROLLER_STAGING_AREAS
    }

    fn active_staging_count(&self) -> usize {
        self.active_staging.iter().filter(|active| **active).count()
    }

    fn submit_current_batch(&mut self, reason: BatchSubmitReason) -> InputBatch {
        let staging_area = self.current_staging_area;
        assert!(!self.active_staging[staging_area]);
        let input_len = self.current_staging_inputs;
        assert!(input_len > 0);
        let batch = InputBatch {
            staging_area,
            input_start: self.next_input_index - input_len,
            input_len,
            add: self.processing_add,
            reason,
        };
        self.processing_add = true;
        self.active_staging[staging_area] = true;
        self.batches_started += 1;
        self.current_staging_inputs = 0;
        record_controller_trace!(
            self,
            ControllerTraceEvent::BatchSubmitted {
                staging_area,
                input_start: batch.input_start,
                input_len,
                add: batch.add,
                reason,
            }
        );
        self.execution_trace
            .record(ControllerExecutionEvent::BatchSubmitted {
                staging_area,
                input_start: batch.input_start,
                input_len,
                add: batch.add,
                reason,
            });
        self.current_staging_area = (staging_area + 1) % CONTROLLER_STAGING_AREAS;
        self.execution_trace
            .record(ControllerExecutionEvent::StagingRotated {
                from: staging_area,
                to: self.current_staging_area,
            });
        record_controller_trace!(
            self,
            ControllerTraceEvent::StagingRotated {
                from: staging_area,
                to: self.current_staging_area,
            }
        );
        batch
    }
}

#[cfg(test)]
pub(crate) struct ControllerSimulation {
    pub(crate) batches: Vec<InputBatch>,
    pub(crate) trace: Vec<ControllerTraceEvent>,
}

#[cfg(test)]
impl ControllerLifecycle {
    /// Model-only driver for controller unit tests. Production execution drives
    /// this lifecycle directly; plans never synthesize submission events.
    pub(crate) fn simulate(input_count: usize, input_grouping: usize) -> ControllerSimulation {
        assert!(input_count > 0);
        let mut lifecycle = Self::new(input_grouping);
        let mut batches = Vec::new();

        for _ in 0..input_count {
            while lifecycle.can_add() == ControllerAddStatus::Full {
                lifecycle.observe_backpressure();
                lifecycle.wait_for_add();
                lifecycle.complete_batch(lifecycle.current_staging_area);
            }
            let ControllerAddResult::Accepted { submitted, .. } = lifecycle.add_input(false) else {
                unreachable!("full staging area was completed before retry");
            };
            if let Some(batch) = submitted {
                batches.push(batch);
            }
        }

        if let Some(batch) = lifecycle.end_input() {
            batches.push(batch);
        }
        for staging_area in 0..CONTROLLER_STAGING_AREAS {
            if lifecycle.active_staging[staging_area] {
                lifecycle.complete_batch(staging_area);
            }
        }
        lifecycle.processing_finished();

        ControllerSimulation {
            batches,
            #[cfg(test)]
            trace: lifecycle.trace,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CpuControllerPlan {
    layout: ControllerLayout,
    buffer_accounting: ControllerBufferAccounting,
}

impl CpuControllerPlan {
    #[cfg(test)]
    pub(crate) fn new(
        current_slice_size: usize,
        output_count: usize,
        worker_count: usize,
        method: CpuMethodContract,
    ) -> Self {
        let input_grouping = method.input_grouping();
        Self::new_with_input_grouping_and_staging_width(
            current_slice_size,
            output_count,
            worker_count,
            method,
            input_grouping,
            input_grouping,
        )
    }

    #[cfg(test)]
    pub(crate) fn new_with_input_grouping(
        current_slice_size: usize,
        output_count: usize,
        worker_count: usize,
        method: CpuMethodContract,
        input_grouping: usize,
    ) -> Self {
        Self::new_with_input_grouping_and_staging_width(
            current_slice_size,
            output_count,
            worker_count,
            method,
            input_grouping,
            input_grouping,
        )
    }

    /// Builds a plan with a live grouping and its physical staging width.
    /// Folded kernels can pass a width larger than `input_grouping`.
    pub(crate) fn new_with_input_grouping_and_staging_width(
        current_slice_size: usize,
        output_count: usize,
        worker_count: usize,
        method: CpuMethodContract,
        input_grouping: usize,
        allocated_staging_width: usize,
    ) -> Self {
        assert!(input_grouping > 0);
        assert!(allocated_staging_width >= input_grouping);
        let layout = ControllerLayout::new(current_slice_size, output_count, worker_count, method);
        let buffer_accounting = ControllerBufferAccounting::new(
            layout.aligned_len,
            input_grouping,
            allocated_staging_width,
            output_count,
            method,
        );
        Self {
            layout,
            buffer_accounting,
        }
    }

    pub(crate) fn input_grouping(&self) -> usize {
        self.buffer_accounting.input_grouping
    }

    pub(crate) fn layout(&self) -> &ControllerLayout {
        &self.layout
    }

    pub(crate) fn buffer_accounting(&self) -> &ControllerBufferAccounting {
        &self.buffer_accounting
    }

    #[cfg(test)]
    pub(crate) fn trace(&self) -> Vec<ControllerTraceEvent> {
        build_plan_trace(
            self.buffer_accounting.output_count,
            self.layout.worker_count,
            &self.layout,
            &self.buffer_accounting,
            Vec::new(),
        )
    }
}

impl ControllerLayout {
    pub(crate) fn new(
        current_slice_size: usize,
        output_count: usize,
        worker_count: usize,
        method: CpuMethodContract,
    ) -> Self {
        assert!(current_slice_size > 0);
        assert!(output_count > 0);
        let workers = worker_count.max(1);
        let stride = method.stride.max(1);
        let ideal_chunk = align_up(method.ideal_chunk_size.max(stride), stride);
        // Keep one additional packed stride so preparation/finalization can
        // safely carry its checksum/padding block through the controller.
        let aligned_len = align_up(current_slice_size, stride) + stride;

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
            worker_count: workers,
            stride,
        }
    }
}

#[cfg(test)]
fn build_plan_trace(
    output_count: usize,
    worker_count: usize,
    layout: &ControllerLayout,
    accounting: &ControllerBufferAccounting,
    lifecycle_trace: Vec<ControllerTraceEvent>,
) -> Vec<ControllerTraceEvent> {
    let mut trace = vec![ControllerTraceEvent::Initialized {
        staging_area_count: accounting.staging_area_count,
        transfer_buffer_count: accounting.transfer_buffer_count,
        input_grouping: accounting.input_grouping,
        aligned_slice_len: accounting.aligned_slice_len,
        output_count,
        worker_count,
    }];
    trace.push(ControllerTraceEvent::LayoutPlanned {
        aligned_len: layout.aligned_len,
        chunk_len: layout.chunk_len,
        num_chunks: layout.num_chunks,
        assignment_count: layout.assignments.len(),
    });
    trace.extend(layout.assignments.iter().copied().map(|work| {
        ControllerTraceEvent::WorkScheduled {
            worker: work.worker,
            byte_start: work.byte_start,
            byte_len: work.byte_len,
            output_start: work.output_start,
            output_len: work.output_len,
        }
    }));

    trace.extend(lifecycle_trace);
    trace
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

    const METHOD: CpuMethodContract = CpuMethodContract {
        stride: 32,
        alignment: 64,
        ideal_input_multiple: 1,
        staging_multiple: 1,
        ideal_chunk_size: 64 * 1024,
        checksum_width: 32,
        prefetch: CpuPrefetch {
            inputs_per_invoke: 0,
            input_distance_shift: 0,
            output: false,
        },
        strict_wx_available: false,
    };

    fn simulated_batches(input_count: usize, grouping: usize) -> Vec<InputBatch> {
        ControllerLifecycle::simulate(input_count, grouping).batches
    }

    #[test]
    fn input_grouping_rounds_twelve_to_kernel_multiple() {
        assert_eq!(METHOD.input_grouping(), 12);
        assert_eq!(
            CpuMethodContract {
                ideal_input_multiple: 6,
                ..METHOD
            }
            .input_grouping(),
            12
        );
        assert_eq!(
            CpuMethodContract {
                ideal_input_multiple: 8,
                ..METHOD
            }
            .input_grouping(),
            16
        );
    }

    #[test]
    fn input_batches_rotate_staging_and_flush_partial_group() {
        let batches = simulated_batches(25, METHOD.input_grouping());
        assert_eq!(
            batches,
            vec![
                InputBatch {
                    staging_area: 0,
                    input_start: 0,
                    input_len: 12,
                    add: false,
                    reason: BatchSubmitReason::GroupFull,
                },
                InputBatch {
                    staging_area: 1,
                    input_start: 12,
                    input_len: 12,
                    add: true,
                    reason: BatchSubmitReason::GroupFull,
                },
                InputBatch {
                    staging_area: 0,
                    input_start: 24,
                    input_len: 1,
                    add: true,
                    reason: BatchSubmitReason::EndInput,
                },
            ]
        );
    }

    #[test]
    fn input_group_boundaries_flush_complete_and_partial_groups() {
        let cases = [
            (1, vec![1]),
            (11, vec![11]),
            (12, vec![12]),
            (13, vec![12, 1]),
            (23, vec![12, 11]),
            (24, vec![12, 12]),
            (25, vec![12, 12, 1]),
        ];
        for (inputs, expected_lengths) in cases {
            let batches = simulated_batches(inputs, METHOD.input_grouping());
            assert_eq!(
                batches
                    .iter()
                    .map(|batch| batch.input_len)
                    .collect::<Vec<_>>(),
                expected_lengths
            );
            assert_eq!(
                batches
                    .iter()
                    .map(|batch| batch.staging_area)
                    .collect::<Vec<_>>(),
                (0..batches.len())
                    .map(|batch| batch % 2)
                    .collect::<Vec<_>>()
            );
            assert!(!batches[0].add);
            assert!(batches.iter().skip(1).all(|batch| batch.add));
        }
    }

    #[test]
    fn one_chunk_splits_outputs_across_workers() {
        let layout = ControllerLayout::new(64 * 1024, 512, 12, METHOD);
        assert_eq!(layout.num_chunks, 1);
        assert_eq!(layout.assignments.len(), 12);
        assert!(layout.assignments.iter().all(|work| work.byte_start == 0));
        assert!(
            layout
                .assignments
                .iter()
                .all(|work| work.byte_len == 64 * 1024 + METHOD.stride)
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
    fn one_chunk_caps_workers_at_output_count() {
        let layout = ControllerLayout::new(64 * 1024, 3, 12, METHOD);
        assert_eq!(layout.num_chunks, 1);
        assert_eq!(
            layout.assignments,
            vec![
                WorkAssignment {
                    worker: 0,
                    byte_start: 0,
                    byte_len: layout.aligned_len,
                    output_start: 0,
                    output_len: 1,
                },
                WorkAssignment {
                    worker: 1,
                    byte_start: 0,
                    byte_len: layout.aligned_len,
                    output_start: 1,
                    output_len: 1,
                },
                WorkAssignment {
                    worker: 2,
                    byte_start: 0,
                    byte_len: layout.aligned_len,
                    output_start: 2,
                    output_len: 1,
                },
            ]
        );
    }

    #[test]
    fn large_slice_distributes_full_chunks_across_workers() {
        let layout = ControllerLayout::new(1024 * 1024, 8, 12, METHOD);
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
        let method = CpuMethodContract {
            ideal_chunk_size: 96 * 1024,
            ..METHOD
        };
        let layout = ControllerLayout::new(3 * 1024 * 1024, 17, 8, method);
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
        let layout = ControllerLayout::new(65_537, 3, 4, METHOD);
        assert_eq!(layout.aligned_len % METHOD.stride, 0);
        assert_eq!(layout.chunk_len % METHOD.stride, 0);
        assert!(layout.aligned_len >= 65_537);
    }

    #[test]
    fn explicit_grouping_is_the_single_plan_source_of_truth() {
        let default_plan = CpuControllerPlan::new(64 * 1024, 3, 4, METHOD);
        let explicit_plan = CpuControllerPlan::new_with_input_grouping(
            64 * 1024,
            3,
            4,
            METHOD,
            METHOD.input_grouping(),
        );
        assert_eq!(default_plan, explicit_plan);

        let small_source = CpuControllerPlan::new_with_input_grouping(64 * 1024, 3, 4, METHOD, 4);
        assert_eq!(small_source.input_grouping(), 4);
        assert_eq!(
            simulated_batches(9, small_source.input_grouping())
                .iter()
                .map(|batch| (batch.input_len, batch.reason))
                .collect::<Vec<_>>(),
            vec![
                (4, BatchSubmitReason::GroupFull),
                (4, BatchSubmitReason::GroupFull),
                (1, BatchSubmitReason::EndInput),
            ]
        );
        assert_eq!(small_source.buffer_accounting().input_grouping, 4);
        assert_eq!(
            small_source.layout().aligned_len,
            small_source.buffer_accounting().aligned_slice_len
        );
    }

    #[test]
    fn lifecycle_exposes_backpressure_and_area_rotation() {
        let mut lifecycle = ControllerLifecycle::new(2);
        assert_eq!(lifecycle.can_add(), ControllerAddStatus::Ready);
        assert!(matches!(
            lifecycle.add_input(false),
            ControllerAddResult::Accepted {
                submitted: None,
                staging_area: 0,
                slot: 0,
            }
        ));
        let ControllerAddResult::Accepted {
            submitted: Some(first),
            ..
        } = lifecycle.add_input(false)
        else {
            panic!("the first full group should submit");
        };
        assert_eq!(first.staging_area, 0);
        assert_eq!(first.input_start, 0);
        assert_eq!(first.input_len, 2);
        assert!(!first.add);
        assert_eq!(first.reason, BatchSubmitReason::GroupFull);

        assert!(matches!(
            lifecycle.add_input(false),
            ControllerAddResult::Accepted {
                submitted: None,
                staging_area: 1,
                slot: 0,
            }
        ));
        assert!(matches!(
            lifecycle.add_input(false),
            ControllerAddResult::Accepted {
                submitted: Some(InputBatch {
                    staging_area: 1,
                    input_start: 2,
                    input_len: 2,
                    add: true,
                    reason: BatchSubmitReason::GroupFull,
                }),
                ..
            }
        ));
        assert_eq!(lifecycle.can_add(), ControllerAddStatus::Full);
        assert_eq!(lifecycle.observe_backpressure(), ControllerAddStatus::Full);
        lifecycle.wait_for_add();
        assert_eq!(lifecycle.add_input(false), ControllerAddResult::Full);

        lifecycle.complete_batch(0);
        assert_eq!(lifecycle.can_add(), ControllerAddStatus::ReadyBusy);
        assert!(lifecycle.trace().iter().any(|event| matches!(
            event,
            ControllerTraceEvent::Backpressure {
                status: ControllerAddStatus::Full,
                staging_area: 0,
            }
        )));
        assert!(
            lifecycle
                .trace()
                .iter()
                .any(|event| matches!(event, ControllerTraceEvent::WaitForAdd { staging_area: 0 }))
        );
    }

    #[test]
    fn lifecycle_flushes_partial_input_and_finishes_only_after_completion() {
        let mut lifecycle = ControllerLifecycle::new(12).with_min_input_batch_size(12);
        for _ in 0..4 {
            assert!(matches!(
                lifecycle.add_input(false),
                ControllerAddResult::Accepted { .. }
            ));
        }
        let batch = lifecycle.end_input().expect("partial group must flush");
        assert_eq!(batch.input_len, 4);
        assert_eq!(batch.reason, BatchSubmitReason::EndInput);
        assert!(!batch.add);
        assert!(lifecycle.ended);
        lifecycle.complete_batch(batch.staging_area);
        lifecycle.processing_finished();
        assert!(lifecycle.trace().iter().any(|event| matches!(
            event,
            ControllerTraceEvent::InputEnded {
                partial_batch_flushed: true
            }
        )));
        assert!(matches!(
            lifecycle.trace().last(),
            Some(ControllerTraceEvent::ProcessingFinished)
        ));
    }

    #[test]
    fn plan_accounts_for_two_transfer_buffers_double_staging_and_outputs() {
        let plan = CpuControllerPlan::new(65_536, 3, 4, METHOD);
        let accounting = &plan.buffer_accounting;
        assert_eq!(accounting.transfer_buffer_count, 2);
        assert_eq!(accounting.staging_area_count, 2);
        assert_eq!(accounting.aligned_slice_len, 65_568);
        assert_eq!(accounting.physical_row_len, 65_600);
        assert_eq!(accounting.physical_row_len % 64, 0);
        assert_eq!(
            accounting.staging_area_bytes,
            accounting.allocated_staging_width * accounting.physical_row_len
        );
        assert_eq!(
            accounting.transfer_buffer_bytes,
            accounting.physical_row_len
        );
        assert_eq!(
            accounting.output_area_bytes,
            accounting.output_count * accounting.physical_row_len
        );
        assert_eq!(
            accounting.total_bytes,
            accounting.transfer_buffer_count * accounting.transfer_buffer_bytes
                + accounting.staging_area_count * accounting.staging_area_bytes
                + accounting.output_area_bytes
        );
    }

    #[test]
    fn folded_small_group_accounts_physical_staging_width() {
        let plan = CpuControllerPlan::new_with_input_grouping_and_staging_width(
            64 * 1024,
            3,
            4,
            METHOD,
            1,
            6,
        );
        assert_eq!(plan.input_grouping(), 1);
        assert_eq!(plan.buffer_accounting().allocated_staging_width, 6);
        assert_eq!(
            plan.buffer_accounting().staging_area_bytes,
            6 * plan.buffer_accounting().physical_row_len
        );
        assert_eq!(
            simulated_batches(5, plan.input_grouping())
                .iter()
                .map(|batch| batch.input_len)
                .collect::<Vec<_>>(),
            vec![1, 1, 1, 1, 1]
        );
        assert_eq!(
            simulated_batches(5, plan.input_grouping()),
            ControllerLifecycle::simulate(5, 1).batches
        );
    }

    #[test]
    fn plan_trace_contains_only_static_layout_and_runtime_trace_owns_lifecycle() {
        let plan = CpuControllerPlan::new(64 * 1024, 4, 8, METHOD);
        assert!(matches!(
            plan.trace().first(),
            Some(ControllerTraceEvent::Initialized {
                staging_area_count: 2,
                transfer_buffer_count: 2,
                input_grouping: 12,
                ..
            })
        ));
        assert_eq!(
            plan.trace()
                .iter()
                .filter(|event| matches!(event, ControllerTraceEvent::WorkScheduled { .. }))
                .count(),
            plan.layout.assignments.len()
        );
        assert!(plan.trace().iter().all(|event| !matches!(
            event,
            ControllerTraceEvent::BatchSubmitted { .. } | ControllerTraceEvent::Backpressure { .. }
        )));
        let trace = ControllerLifecycle::simulate(25, METHOD.input_grouping()).trace;
        assert!(trace.iter().any(|event| matches!(
            event,
            ControllerTraceEvent::BatchSubmitted {
                input_start: 24,
                input_len: 1,
                add: true,
                reason: BatchSubmitReason::EndInput,
                ..
            }
        )));
    }
}

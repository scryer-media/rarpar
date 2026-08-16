//! GF(2^16) multiply-accumulate for streaming workloads on Apple GPUs
//! (Metal, unified memory).
//!
//! Same product as the CPU kernels: `dst[j] ^= factor[j][s] * src[s]` over
//! GF(2^16) with the PAR2 generator polynomial. The GPU formulation is the
//! 4x16-entry nibble-table one — each output's tables are staged in
//! threadgroup memory, so the inner loop is table lookups against on-chip
//! SRAM while unified memory makes host buffers directly addressable.
//!
//! Dispatch is runtime-probed: this module only exists on macOS builds, and a
//! Metal device is looked up once on first use. Automatic repair selection
//! engages only when a batch is large enough to amortize dispatch latency;
//! explicit policy-driven creation sessions bypass that automatic threshold
//! while still requiring device, environment, shape, and buffer admission.
//! The environment gate (`WEAVER_GF16_METAL=0` disables, `=1` forces for
//! testing) applies to both policies.
//! Sessions surface admission and execution errors to their callers instead
//! of panicking; callers choose any higher-level fallback policy.

use objc2::{
    rc::{Retained, autoreleasepool},
    runtime::ProtocolObject,
};
use objc2_foundation::{NSRange, NSString};
use objc2_metal::{
    MTLBlitCommandEncoder, MTLBuffer, MTLCommandBuffer, MTLCommandBufferStatus, MTLCommandEncoder,
    MTLCommandQueue, MTLCompileOptions, MTLComputeCommandEncoder, MTLComputePipelineState,
    MTLCreateSystemDefaultDevice, MTLDevice, MTLLibrary, MTLResource, MTLResourceOptions, MTLSize,
};
use std::{ffi::c_void, ptr::NonNull, sync::OnceLock};

#[link(name = "CoreGraphics", kind = "framework")]
unsafe extern "C" {}

type Buffer = Retained<ProtocolObject<dyn MTLBuffer>>;
type CommandBuffer = Retained<ProtocolObject<dyn MTLCommandBuffer>>;
type CommandQueue = Retained<ProtocolObject<dyn MTLCommandQueue>>;
type ComputePipelineState = Retained<ProtocolObject<dyn MTLComputePipelineState>>;
type Device = Retained<ProtocolObject<dyn MTLDevice>>;

/// Widest source batch a single dispatch accepts; sized to the streaming
/// workload and to the 8.25 KiB of threadgroup memory its tables
/// need.
pub const MAX_SOURCES: usize = 66;

const TABLE_WORDS_PER_FACTOR: usize = 64; // 4 nibble positions x 16 entries
const TABLE_FACTOR_COUNT: usize = 1usize << 16;
const TABLE_TRACKING_WORDS: usize = TABLE_FACTOR_COUNT / 64;
const IN_FLIGHT_SLOTS: usize = 2;
const PREFERRED_THREADS_PER_GROUP: usize = 256;

/// Auto-engage threshold: outputs x sources x region bytes per workload.
/// Below this the CPU path wins on dispatch + upload overhead.
const MIN_EFFECTIVE_BYTES: u64 = 256 * 1024 * 1024;

/// Reasons a checked Metal memory or shape plan cannot be formed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MetalGf16PlanError {
    ZeroOutputs,
    ZeroSourceCapacity,
    SourceCapacityTooLarge,
    ZeroRegionLength,
    RegionLengthNotEven,
    ArithmeticOverflow,
    ShaderIndexLimit,
}

/// The individual Metal buffers considered during session admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MetalGf16Buffer {
    Source,
    Factors,
    Destination,
    Tables,
}

/// A checked, allocation-free memory and shape plan for a Metal session.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MetalGf16MemoryPlan {
    pub outputs: usize,
    pub source_capacity: usize,
    pub max_region_bytes: usize,
    pub max_region_words: usize,
    pub source_buffer_bytes: usize,
    pub source_slots_bytes: usize,
    pub factor_buffer_bytes: usize,
    pub factor_slots_bytes: usize,
    pub destination_bytes: usize,
    pub table_bytes: usize,
    pub table_tracking_bytes: usize,
    pub total_bytes: usize,
}

/// Check all shape arithmetic and report the memory reserved by a session.
pub fn metal_gf16_memory_plan(
    outputs: usize,
    source_capacity: usize,
    max_region_bytes: usize,
) -> Result<MetalGf16MemoryPlan, MetalGf16PlanError> {
    if outputs == 0 {
        return Err(MetalGf16PlanError::ZeroOutputs);
    }
    if source_capacity == 0 {
        return Err(MetalGf16PlanError::ZeroSourceCapacity);
    }
    if source_capacity > MAX_SOURCES {
        return Err(MetalGf16PlanError::SourceCapacityTooLarge);
    }
    if max_region_bytes == 0 {
        return Err(MetalGf16PlanError::ZeroRegionLength);
    }
    if !max_region_bytes.is_multiple_of(2) {
        return Err(MetalGf16PlanError::RegionLengthNotEven);
    }

    let max_region_words = max_region_bytes / 2;
    let source_index_words = source_capacity
        .checked_mul(max_region_words)
        .ok_or(MetalGf16PlanError::ArithmeticOverflow)?;
    let destination_index_words = outputs
        .checked_mul(max_region_words)
        .ok_or(MetalGf16PlanError::ArithmeticOverflow)?;
    let factor_index_count = outputs
        .checked_mul(source_capacity)
        .ok_or(MetalGf16PlanError::ArithmeticOverflow)?;
    let shader_limit = u32::MAX as usize;
    if outputs > shader_limit
        || source_capacity > shader_limit
        || max_region_words > shader_limit
        || source_index_words > shader_limit
        || destination_index_words > shader_limit
        || factor_index_count > shader_limit
    {
        return Err(MetalGf16PlanError::ShaderIndexLimit);
    }

    let source_buffer_bytes = source_capacity
        .checked_mul(max_region_bytes)
        .ok_or(MetalGf16PlanError::ArithmeticOverflow)?;
    let source_slots_bytes = source_buffer_bytes
        .checked_mul(IN_FLIGHT_SLOTS)
        .ok_or(MetalGf16PlanError::ArithmeticOverflow)?;
    let factor_buffer_bytes = factor_index_count
        .checked_mul(std::mem::size_of::<u16>())
        .ok_or(MetalGf16PlanError::ArithmeticOverflow)?;
    let factor_slots_bytes = factor_buffer_bytes
        .checked_mul(IN_FLIGHT_SLOTS)
        .ok_or(MetalGf16PlanError::ArithmeticOverflow)?;
    let destination_bytes = outputs
        .checked_mul(max_region_bytes)
        .ok_or(MetalGf16PlanError::ArithmeticOverflow)?;
    let table_bytes = TABLE_FACTOR_COUNT
        .checked_mul(TABLE_WORDS_PER_FACTOR)
        .and_then(|entries| entries.checked_mul(std::mem::size_of::<u16>()))
        .ok_or(MetalGf16PlanError::ArithmeticOverflow)?;
    let table_tracking_bytes = TABLE_TRACKING_WORDS
        .checked_mul(std::mem::size_of::<u64>())
        .ok_or(MetalGf16PlanError::ArithmeticOverflow)?;
    let total_bytes = source_slots_bytes
        .checked_add(factor_slots_bytes)
        .and_then(|total| total.checked_add(destination_bytes))
        .and_then(|total| total.checked_add(table_bytes))
        .and_then(|total| total.checked_add(table_tracking_bytes))
        .ok_or(MetalGf16PlanError::ArithmeticOverflow)?;

    Ok(MetalGf16MemoryPlan {
        outputs,
        source_capacity,
        max_region_bytes,
        max_region_words,
        source_buffer_bytes,
        source_slots_bytes,
        factor_buffer_bytes,
        factor_slots_bytes,
        destination_bytes,
        table_bytes,
        table_tracking_bytes,
        total_bytes,
    })
}

fn gf16_mul(mut a: u16, mut b: u16) -> u16 {
    let mut r = 0u16;
    while b != 0 {
        if b & 1 != 0 {
            r ^= a;
        }
        let carry = a & 0x8000 != 0;
        a <<= 1;
        if carry {
            a ^= 0x100B;
        }
        b >>= 1;
    }
    r
}

fn shader_source() -> String {
    format!(
        r#"
#include <metal_stdlib>
using namespace metal;

constant uint MAX_SOURCES = {max_sources}u;

kernel void gf16_mulacc(
    device const ushort* srcs    [[buffer(0)]],   // sources x words
    device ushort* dsts          [[buffer(1)]],   // outputs x words
    device const ushort* tables  [[buffer(2)]],   // factor value x 64
    device const ushort* factors [[buffer(3)]],   // outputs x sources
    constant uint& words         [[buffer(4)]],
    constant uint& sources       [[buffer(5)]],
    uint3 tg_pos                 [[threadgroup_position_in_grid]],
    uint3 tid3                   [[thread_position_in_threadgroup]],
    uint3 tg_dims                [[threads_per_threadgroup]])
{{
    uint tid = tid3.x;
    uint tg_size = tg_dims.x;
    uint out = tg_pos.y;

    // Stage this output's coefficient tables (one 64-entry table per
    // source, addressed by the factor value) into threadgroup memory.
    threadgroup ushort tg_tables[MAX_SOURCES * 64u];
    uint tab_count = sources * 64u;
    for (uint i = tid; i < tab_count; i += tg_size) {{
        uint f = factors[out * sources + (i >> 6u)];
        tg_tables[i] = tables[f * 64u + (i & 63u)];
    }}
    threadgroup_barrier(mem_flags::mem_threadgroup);

    uint w0 = (tg_pos.x * tg_size + tid) * 4u;
    if (w0 >= words) {{
        return;
    }}

    if (w0 + 4u <= words) {{
        // Rows are laid out at `words` granularity; index rows in scalar
        // words and vector-cast within the row.
        uint v = w0 >> 2u;
        ushort4 acc = ushort4(((device const packed_ushort4*)(dsts + out * words))[v]);
        for (uint s = 0; s < sources; s++) {{
            threadgroup const ushort* t = tg_tables + s * 64u;
            ushort4 w = ushort4(((device const packed_ushort4*)(srcs + s * words))[v]);
            acc.x ^= t[w.x & 15u] ^ t[16u + ((w.x >> 4u) & 15u)]
                   ^ t[32u + ((w.x >> 8u) & 15u)] ^ t[48u + (w.x >> 12u)];
            acc.y ^= t[w.y & 15u] ^ t[16u + ((w.y >> 4u) & 15u)]
                   ^ t[32u + ((w.y >> 8u) & 15u)] ^ t[48u + (w.y >> 12u)];
            acc.z ^= t[w.z & 15u] ^ t[16u + ((w.z >> 4u) & 15u)]
                   ^ t[32u + ((w.z >> 8u) & 15u)] ^ t[48u + (w.z >> 12u)];
            acc.w ^= t[w.w & 15u] ^ t[16u + ((w.w >> 4u) & 15u)]
                   ^ t[32u + ((w.w >> 8u) & 15u)] ^ t[48u + (w.w >> 12u)];
        }}
        ((device packed_ushort4*)(dsts + out * words))[v] = packed_ushort4(acc);
    }} else {{
        // Trailing 1-3 words of an odd-length region.
        for (uint w = w0; w < words; w++) {{
            ushort acc = dsts[out * words + w];
            for (uint s = 0; s < sources; s++) {{
                threadgroup const ushort* t = tg_tables + s * 64u;
                ushort x = srcs[s * words + w];
                acc ^= t[x & 15u] ^ t[16u + ((x >> 4u) & 15u)]
                     ^ t[32u + ((x >> 8u) & 15u)] ^ t[48u + (x >> 12u)];
            }}
            dsts[out * words + w] = acc;
        }}
    }}
}}
"#,
        max_sources = MAX_SOURCES
    )
}

/// Device-global Metal state, created once. MTLDevice, MTLCommandQueue and
/// MTLComputePipelineState are documented thread-safe; sessions built on
/// top hold their own buffers and are single-threaded.
struct MetalShared {
    device: Device,
    queue: CommandQueue,
    pipeline: ComputePipelineState,
    threads_per_group: usize,
}

unsafe impl Send for MetalShared {}
unsafe impl Sync for MetalShared {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MetalGate {
    Auto,
    Force,
    Off,
}

/// Why an explicitly requested Metal session was not admitted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MetalGf16AdmissionError {
    DisabledByEnvironment,
    DeviceUnavailable,
    InvalidPlan(MetalGf16PlanError),
    BufferTooLarge {
        buffer: MetalGf16Buffer,
        requested: usize,
        limit: usize,
    },
    AllocationFailed(MetalGf16Buffer),
}

fn metal_gate_for_value(value: Option<&str>) -> MetalGate {
    match value {
        Some(v) if v == "0" || v.eq_ignore_ascii_case("false") => MetalGate::Off,
        Some(v) if v == "1" || v.eq_ignore_ascii_case("true") => MetalGate::Force,
        _ => MetalGate::Auto,
    }
}

fn metal_gate() -> MetalGate {
    let value = std::env::var("WEAVER_GF16_METAL").ok();
    metal_gate_for_value(value.as_deref())
}

fn shared_context() -> Option<&'static MetalShared> {
    static CONTEXT: OnceLock<Option<MetalShared>> = OnceLock::new();
    CONTEXT
        .get_or_init(|| {
            // Every Metal call that can return autoreleased objects runs
            // inside a pool: these threads are plain Rust threads with no
            // ambient pool, so without one the objects leak until thread
            // exit.
            autoreleasepool(|_| {
                let device = MTLCreateSystemDefaultDevice()?;
                let queue = device.newCommandQueue()?;
                let queue_label = NSString::from_str("weaver.gf16");
                queue.setLabel(Some(&queue_label));
                let source = NSString::from_str(&shader_source());
                let options = MTLCompileOptions::new();
                let library = device
                    .newLibraryWithSource_options_error(&source, Some(&options))
                    .ok()?;
                let function_name = NSString::from_str("gf16_mulacc");
                let function = library.newFunctionWithName(&function_name)?;
                let pipeline = device
                    .newComputePipelineStateWithFunction_error(&function)
                    .ok()?;
                let threads_per_group =
                    PREFERRED_THREADS_PER_GROUP.min(pipeline.maxTotalThreadsPerThreadgroup());
                if threads_per_group == 0 {
                    return None;
                }
                Some(MetalShared {
                    device,
                    queue,
                    pipeline,
                    threads_per_group,
                })
            })
        })
        .as_ref()
}

/// Wait for a command buffer and require clean completion; a faulted or
/// cancelled buffer means the destination contents cannot be trusted.
fn wait_completed(cb: &CommandBuffer) -> bool {
    cb.waitUntilCompleted();
    cb.status() == MTLCommandBufferStatus::Completed
}

/// True when a Metal device is present and the tier is not disabled.
pub fn metal_gf16_available() -> bool {
    if matches!(metal_gate(), MetalGate::Off) {
        return false;
    }
    shared_context().is_some()
}

/// One workload's GPU residency: reusable upload buffers (double-buffered so
/// a fill can proceed while the previous dispatch runs), one destination
/// buffer that stays resident across every source batch of a chunk, and a
/// factor-value-indexed table cache filled lazily as coefficients first
/// appear.
pub struct MetalGf16Session {
    shared: &'static MetalShared,
    src_bufs: [Buffer; 2],
    factor_bufs: [Buffer; 2],
    dst_buf: Buffer,
    table_buf: Buffer,
    table_filled: Vec<u64>,
    pending: [Option<CommandBuffer>; 2],
    slot: usize,
    outputs: usize,
    source_capacity: usize,
    max_region_bytes: usize,
    chunk_words: usize,
}

impl MetalGf16Session {
    /// Engage a session using the original automatic admission behavior and
    /// the widest supported source capacity.
    pub fn try_new(outputs: usize, max_region_bytes: usize, effective_bytes: u64) -> Option<Self> {
        Self::try_new_with_source_capacity(outputs, MAX_SOURCES, max_region_bytes, effective_bytes)
    }

    /// Engage an automatically admitted session with a bounded source capacity.
    pub fn try_new_with_source_capacity(
        outputs: usize,
        source_capacity: usize,
        max_region_bytes: usize,
        effective_bytes: u64,
    ) -> Option<Self> {
        if matches!(metal_gate(), MetalGate::Off) {
            return None;
        }
        if matches!(metal_gate(), MetalGate::Auto) && effective_bytes < MIN_EFFECTIVE_BYTES {
            return None;
        }
        let plan = metal_gf16_memory_plan(outputs, source_capacity, max_region_bytes).ok()?;
        Self::try_new_from_plan(plan).ok()
    }

    /// Engage Metal for a caller-requested workload without the automatic
    /// size threshold. Device, environment, shape, and buffer checks still
    /// apply, and admission failures remain inspectable by the caller.
    pub fn try_new_explicit(
        outputs: usize,
        source_capacity: usize,
        max_region_bytes: usize,
    ) -> Result<Self, MetalGf16AdmissionError> {
        if matches!(metal_gate(), MetalGate::Off) {
            return Err(MetalGf16AdmissionError::DisabledByEnvironment);
        }
        let plan = metal_gf16_memory_plan(outputs, source_capacity, max_region_bytes)
            .map_err(MetalGf16AdmissionError::InvalidPlan)?;
        Self::try_new_from_plan(plan)
    }

    fn try_new_from_plan(plan: MetalGf16MemoryPlan) -> Result<Self, MetalGf16AdmissionError> {
        let shared = shared_context().ok_or(MetalGf16AdmissionError::DeviceUnavailable)?;
        let max_len = shared.device.maxBufferLength();
        for (buffer, requested) in [
            (MetalGf16Buffer::Source, plan.source_buffer_bytes),
            (MetalGf16Buffer::Factors, plan.factor_buffer_bytes),
            (MetalGf16Buffer::Destination, plan.destination_bytes),
            (MetalGf16Buffer::Tables, plan.table_bytes),
        ] {
            if requested > max_len {
                return Err(MetalGf16AdmissionError::BufferTooLarge {
                    buffer,
                    requested,
                    limit: max_len,
                });
            }
        }

        let opts = MTLResourceOptions::StorageModeShared;
        autoreleasepool(|_| {
            let new_labeled = |len: usize, label: &str, buffer: MetalGf16Buffer| {
                let buf = shared
                    .device
                    .newBufferWithLength_options(len, opts)
                    .ok_or(MetalGf16AdmissionError::AllocationFailed(buffer))?;
                let label = NSString::from_str(label);
                buf.setLabel(Some(&label));
                Ok(buf)
            };
            Ok(Self {
                shared,
                src_bufs: [
                    new_labeled(
                        plan.source_buffer_bytes,
                        "weaver.gf16.src0",
                        MetalGf16Buffer::Source,
                    )?,
                    new_labeled(
                        plan.source_buffer_bytes,
                        "weaver.gf16.src1",
                        MetalGf16Buffer::Source,
                    )?,
                ],
                factor_bufs: [
                    new_labeled(
                        plan.factor_buffer_bytes,
                        "weaver.gf16.factors0",
                        MetalGf16Buffer::Factors,
                    )?,
                    new_labeled(
                        plan.factor_buffer_bytes,
                        "weaver.gf16.factors1",
                        MetalGf16Buffer::Factors,
                    )?,
                ],
                dst_buf: new_labeled(
                    plan.destination_bytes,
                    "weaver.gf16.dst",
                    MetalGf16Buffer::Destination,
                )?,
                table_buf: new_labeled(
                    plan.table_bytes,
                    "weaver.gf16.tables",
                    MetalGf16Buffer::Tables,
                )?,
                table_filled: vec![0u64; TABLE_TRACKING_WORDS],
                pending: [None, None],
                slot: 0,
                outputs: plan.outputs,
                source_capacity: plan.source_capacity,
                max_region_bytes: plan.max_region_bytes,
                chunk_words: 0,
            })
        })
    }

    fn wait_slot(&mut self, slot: usize) -> Result<(), &'static str> {
        if let Some(cb) = self.pending[slot].take()
            && !wait_completed(&cb)
        {
            self.chunk_words = 0;
            return Err("prior gpu dispatch failed");
        }
        Ok(())
    }

    fn wait_all_pending(&mut self) -> Result<(), &'static str> {
        let mut failed = false;
        for pending in &mut self.pending {
            if let Some(cb) = pending.take()
                && !wait_completed(&cb)
            {
                failed = true;
            }
        }
        if failed {
            self.chunk_words = 0;
            Err("gpu command failed")
        } else {
            Ok(())
        }
    }

    fn ensure_table(&mut self, factor: u16) -> Result<(), &'static str> {
        let idx = usize::from(factor);
        if self.table_filled[idx / 64] & (1 << (idx % 64)) != 0 {
            return Ok(());
        }

        // The shared table is read by every in-flight slot. A table miss is
        // therefore a session-wide synchronization point before its first
        // byte is changed.
        self.wait_all_pending()?;
        let base = self.table_buf.contents().as_ptr() as *mut u16;
        let table_offset = idx
            .checked_mul(TABLE_WORDS_PER_FACTOR)
            .ok_or("table index overflow")?;
        for k in 0..4u32 {
            let shift = k.checked_mul(4).ok_or("table shift overflow")?;
            let nibble_offset = usize::try_from(k)
                .map_err(|_| "table index overflow")?
                .checked_mul(16)
                .ok_or("table index overflow")?;
            for x in 0..16u16 {
                let value = gf16_mul(factor, x << shift);
                let offset = table_offset
                    .checked_add(nibble_offset)
                    .and_then(|offset| offset.checked_add(usize::from(x)))
                    .ok_or("table index overflow")?;
                unsafe {
                    base.add(offset).write(value);
                }
            }
        }
        self.table_filled[idx / 64] |= 1 << (idx % 64);
        Ok(())
    }

    /// Start a chunk: the resident destination region (outputs x
    /// `byte_len`) is zeroed on the GPU. The zeroing command buffer is
    /// tracked like a dispatch so its completion status is checked before
    /// results are trusted.
    pub fn begin_chunk(&mut self, byte_len: usize) -> Result<(), &'static str> {
        if byte_len == 0 || !byte_len.is_multiple_of(2) || byte_len > self.max_region_bytes {
            return Err("chunk length unsupported by the metal session");
        }
        let destination_bytes = self
            .outputs
            .checked_mul(byte_len)
            .ok_or("destination length overflow")?;
        let chunk_words = byte_len / 2;
        self.wait_all_pending()?;
        autoreleasepool(|_| {
            let cb = self
                .shared
                .queue
                .commandBuffer()
                .ok_or("failed to create metal command buffer")?;
            let blit = cb
                .blitCommandEncoder()
                .ok_or("failed to create metal blit encoder")?;
            blit.fillBuffer_range_value(&self.dst_buf, NSRange::new(0, destination_bytes), 0);
            blit.endEncoding();
            cb.commit();
            self.pending[self.slot] = Some(cb);
            self.chunk_words = chunk_words;
            Ok(())
        })
    }

    /// Accumulate one source batch into the resident chunk destinations:
    /// `dst[j] ^= factor(j, s) * srcs[s]` for every output j. Returns after
    /// queueing — the dispatch overlaps the caller's next batch read; the
    /// upload slot being reused is fenced by waiting its prior dispatch.
    pub fn accumulate(
        &mut self,
        srcs: &[&[u8]],
        factor: impl Fn(usize, usize) -> u16,
    ) -> Result<(), &'static str> {
        let sources = srcs.len();
        if sources == 0 {
            return Ok(());
        }
        if sources > self.source_capacity {
            return Err("source batch wider than the metal kernel supports");
        }
        let chunk_words = self.chunk_words;
        if chunk_words == 0 {
            return Err("accumulate before begin_chunk");
        }
        let byte_len = chunk_words.checked_mul(2).ok_or("chunk length overflow")?;
        let source_bytes = sources
            .checked_mul(byte_len)
            .ok_or("source length overflow")?;
        let source_capacity_bytes = self
            .source_capacity
            .checked_mul(self.max_region_bytes)
            .ok_or("source capacity overflow")?;
        if source_bytes > source_capacity_bytes {
            return Err("source batch exceeds the allocated buffer");
        }
        let factor_count = self
            .outputs
            .checked_mul(sources)
            .ok_or("factor length overflow")?;
        let factor_capacity = self
            .outputs
            .checked_mul(self.source_capacity)
            .ok_or("factor capacity overflow")?;
        if factor_count > factor_capacity {
            return Err("factor batch exceeds the allocated buffer");
        }
        let source_index_words = sources
            .checked_mul(chunk_words)
            .ok_or("source index overflow")?;
        let destination_index_words = self
            .outputs
            .checked_mul(chunk_words)
            .ok_or("destination index overflow")?;
        let shader_limit = u32::MAX as usize;
        if self.outputs > shader_limit
            || chunk_words > shader_limit
            || source_index_words > shader_limit
            || destination_index_words > shader_limit
            || factor_count > shader_limit
        {
            return Err("metal shader index limit exceeded");
        }
        for src in srcs {
            if src.len() != byte_len {
                return Err("source region length mismatch");
            }
        }

        let slot = self.slot;
        self.wait_slot(slot)?;

        // Factors first: fills the lazy table cache before the GPU reads it.
        let factor_ptr = self.factor_bufs[slot].contents().as_ptr() as *mut u16;
        for j in 0..self.outputs {
            for s in 0..sources {
                let f = factor(j, s);
                self.ensure_table(f)?;
                let offset = j
                    .checked_mul(sources)
                    .and_then(|offset| offset.checked_add(s))
                    .ok_or("factor index overflow")?;
                unsafe { factor_ptr.add(offset).write(f) };
            }
        }

        let src_ptr = self.src_bufs[slot].contents().as_ptr() as *mut u8;
        for (s, src) in srcs.iter().enumerate() {
            let offset = s.checked_mul(byte_len).ok_or("source offset overflow")?;
            unsafe {
                std::ptr::copy_nonoverlapping(src.as_ptr(), src_ptr.add(offset), byte_len);
            }
        }

        let words = u32::try_from(chunk_words).map_err(|_| "metal word count overflow")?;
        let sources_u32 = u32::try_from(sources).map_err(|_| "metal source count overflow")?;
        let outputs_u32 = u32::try_from(self.outputs).map_err(|_| "metal output count overflow")?;
        let dispatch_height =
            usize::try_from(outputs_u32).map_err(|_| "metal output count overflow")?;
        let threads = self.shared.threads_per_group;
        if threads == 0 {
            return Err("metal threadgroup size unavailable");
        }
        let quads = chunk_words
            .checked_add(3)
            .ok_or("dispatch width overflow")?
            / 4;
        let threadgroups_width = quads
            .checked_add(
                threads
                    .checked_sub(1)
                    .ok_or("metal threadgroup size unavailable")?,
            )
            .ok_or("dispatch width overflow")?
            / threads;
        let cb = autoreleasepool(|_| -> Result<CommandBuffer, &'static str> {
            let cb = self
                .shared
                .queue
                .commandBuffer()
                .ok_or("failed to create metal command buffer")?;
            let enc = cb
                .computeCommandEncoder()
                .ok_or("failed to create metal compute encoder")?;
            enc.setComputePipelineState(&self.shared.pipeline);
            unsafe {
                enc.setBuffer_offset_atIndex(Some(&self.src_bufs[slot]), 0, 0);
                enc.setBuffer_offset_atIndex(Some(&self.dst_buf), 0, 1);
                enc.setBuffer_offset_atIndex(Some(&self.table_buf), 0, 2);
                enc.setBuffer_offset_atIndex(Some(&self.factor_bufs[slot]), 0, 3);
                enc.setBytes_length_atIndex(
                    NonNull::from(&words).cast::<c_void>(),
                    std::mem::size_of_val(&words),
                    4,
                );
                enc.setBytes_length_atIndex(
                    NonNull::from(&sources_u32).cast::<c_void>(),
                    std::mem::size_of_val(&sources_u32),
                    5,
                );
            }
            enc.dispatchThreadgroups_threadsPerThreadgroup(
                MTLSize {
                    width: threadgroups_width,
                    height: dispatch_height,
                    depth: 1,
                },
                MTLSize {
                    width: threads,
                    height: 1,
                    depth: 1,
                },
            );
            enc.endEncoding();
            cb.commit();
            Ok(cb)
        })?;
        self.pending[slot] = Some(cb);
        self.slot = (slot + 1) % IN_FLIGHT_SLOTS;
        Ok(())
    }

    /// Wait for the chunk's dispatches and copy the accumulated
    /// destinations out. `dst_rows[j][..byte_len]` receives output `j`.
    pub fn finish_chunk(&mut self, dst_rows: &mut [Vec<u8>]) -> Result<(), &'static str> {
        if dst_rows.len() != self.outputs {
            return Err("output row count mismatch");
        }
        let byte_len = self.chunk_byte_len()?;
        for row in dst_rows.iter() {
            if row.len() < byte_len {
                return Err("output row shorter than chunk");
            }
        }
        self.wait_all_pending()
            .map_err(|_| "gpu dispatch failed before readback")?;
        let dst_ptr = self.dst_buf.contents().as_ptr() as *const u8;
        for (j, row) in dst_rows.iter_mut().enumerate() {
            let offset = j
                .checked_mul(byte_len)
                .ok_or("destination offset overflow")?;
            unsafe {
                std::ptr::copy_nonoverlapping(dst_ptr.add(offset), row.as_mut_ptr(), byte_len);
            }
        }
        self.chunk_words = 0;
        Ok(())
    }

    /// Wait for the chunk and read it into a caller-owned output-major buffer.
    /// Each output begins at `row_stride`, and exactly `live_byte_len` bytes
    /// are written from each resident destination row.
    pub fn finish_chunk_into(
        &mut self,
        dst: &mut [u8],
        row_stride: usize,
        live_byte_len: usize,
    ) -> Result<(), &'static str> {
        let byte_len = self.chunk_byte_len()?;
        if live_byte_len == 0 {
            return Err("live byte length must be nonzero");
        }
        if live_byte_len > byte_len {
            return Err("live byte length exceeds active chunk");
        }
        if row_stride < live_byte_len {
            return Err("output row stride shorter than live chunk");
        }
        let output_bytes = self
            .outputs
            .checked_mul(row_stride)
            .ok_or("output buffer length overflow")?;
        if dst.len() < output_bytes {
            return Err("flat output buffer shorter than rows");
        }
        self.wait_all_pending()
            .map_err(|_| "gpu dispatch failed before readback")?;
        let dst_ptr = self.dst_buf.contents().as_ptr() as *const u8;
        for j in 0..self.outputs {
            let src_offset = j
                .checked_mul(byte_len)
                .ok_or("destination offset overflow")?;
            let output_offset = j.checked_mul(row_stride).ok_or("output offset overflow")?;
            unsafe {
                std::ptr::copy_nonoverlapping(
                    dst_ptr.add(src_offset),
                    dst.as_mut_ptr().add(output_offset),
                    live_byte_len,
                );
            }
        }
        self.chunk_words = 0;
        Ok(())
    }

    fn chunk_byte_len(&self) -> Result<usize, &'static str> {
        if self.chunk_words == 0 {
            return Err("no active metal chunk");
        }
        self.chunk_words
            .checked_mul(2)
            .ok_or("chunk length overflow")
    }

    /// Device name for engage-time logging.
    pub fn device_name(&self) -> String {
        autoreleasepool(|_| self.shared.device.name().to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gf_simd::mul_acc_region;

    fn deterministic_bytes(len: usize, salt: usize) -> Vec<u8> {
        (0..len)
            .map(|i| ((i * (salt + 7) + 13) % 251) as u8)
            .collect()
    }

    #[test]
    fn metal_gate_value_selection_is_independent_of_context() {
        let cases = [
            (None, MetalGate::Auto),
            (Some(""), MetalGate::Auto),
            (Some("0"), MetalGate::Off),
            (Some("FALSE"), MetalGate::Off),
            (Some("1"), MetalGate::Force),
            (Some("true"), MetalGate::Force),
            (Some("unexpected"), MetalGate::Auto),
        ];

        for (value, expected) in cases {
            assert_eq!(metal_gate_for_value(value), expected);
        }
    }

    #[test]
    fn memory_plan_counts_all_resident_storage() {
        let plan = metal_gf16_memory_plan(3, 5, 10).unwrap();

        assert_eq!(plan.source_buffer_bytes, 50);
        assert_eq!(plan.source_slots_bytes, 100);
        assert_eq!(plan.factor_buffer_bytes, 30);
        assert_eq!(plan.factor_slots_bytes, 60);
        assert_eq!(plan.destination_bytes, 30);
        assert_eq!(
            plan.table_bytes,
            TABLE_FACTOR_COUNT * TABLE_WORDS_PER_FACTOR * 2
        );
        assert_eq!(plan.table_tracking_bytes, TABLE_TRACKING_WORDS * 8);
        assert_eq!(
            plan.total_bytes,
            plan.source_slots_bytes
                + plan.factor_slots_bytes
                + plan.destination_bytes
                + plan.table_bytes
                + plan.table_tracking_bytes
        );
    }

    #[test]
    fn memory_plan_rejects_invalid_and_overflow_shapes() {
        assert_eq!(
            metal_gf16_memory_plan(0, 1, 2),
            Err(MetalGf16PlanError::ZeroOutputs)
        );
        assert_eq!(
            metal_gf16_memory_plan(1, 0, 2),
            Err(MetalGf16PlanError::ZeroSourceCapacity)
        );
        assert_eq!(
            metal_gf16_memory_plan(1, MAX_SOURCES + 1, 2),
            Err(MetalGf16PlanError::SourceCapacityTooLarge)
        );
        assert_eq!(
            metal_gf16_memory_plan(1, 1, 3),
            Err(MetalGf16PlanError::RegionLengthNotEven)
        );
        assert_eq!(
            metal_gf16_memory_plan(usize::MAX, 1, 4),
            Err(MetalGf16PlanError::ArithmeticOverflow)
        );
        if usize::BITS > 32 {
            assert_eq!(
                metal_gf16_memory_plan(u32::MAX as usize + 1, 1, 2),
                Err(MetalGf16PlanError::ShaderIndexLimit)
            );
        }
    }

    #[test]
    #[ignore = "requires a live Metal device; invoke explicitly on native hardware"]
    fn native_metal_dispatch_readback_and_table_growth() {
        let mut session = MetalGf16Session::try_new_explicit(2, 4, 128)
            .unwrap_or_else(|error| panic!("native Metal admission failed: {error:?}"));
        eprintln!("Metal device: {}", session.device_name());

        let source_a = deterministic_bytes(128, 11);
        let source_b = [deterministic_bytes(128, 23), deterministic_bytes(128, 37)];
        let first_factors = [0x1234, 0x2345];
        let second_factors = [[0x3456, 0x4567], [0x5678, 0x6789]];
        let mut expected = vec![vec![0u8; 128]; 2];
        for (j, row) in expected.iter_mut().enumerate() {
            mul_acc_region(first_factors[j], &source_a, row);
            for (s, source) in source_b.iter().enumerate() {
                mul_acc_region(second_factors[j][s], source, row);
            }
        }

        session.begin_chunk(128).unwrap();
        session
            .accumulate(&[source_a.as_slice()], |j, _| first_factors[j])
            .unwrap();
        let source_b_refs: Vec<&[u8]> = source_b.iter().map(Vec::as_slice).collect();
        session
            .accumulate(&source_b_refs, |j, s| second_factors[j][s])
            .unwrap();

        let row_stride = 140;
        let mut flat = vec![0xa5u8; row_stride * 2];
        session
            .finish_chunk_into(&mut flat, row_stride, 128)
            .unwrap();
        for (j, row) in expected.iter().enumerate() {
            let offset = j * row_stride;
            assert_eq!(&flat[offset..offset + 128], row.as_slice());
            assert!(
                flat[offset + 128..offset + row_stride]
                    .iter()
                    .all(|&byte| byte == 0xa5)
            );
        }
    }

    #[test]
    #[ignore = "requires a live Metal device; invoke explicitly on native hardware"]
    fn native_metal_flat_readback_accepts_odd_live_tail() {
        let outputs = 3;
        let dispatch_len = 128;
        let live_len = 127;
        let row_stride = 136;
        let mut session = MetalGf16Session::try_new_explicit(outputs, 2, dispatch_len)
            .unwrap_or_else(|error| panic!("native Metal admission failed: {error:?}"));
        eprintln!("Metal device: {}", session.device_name());

        let sources = [
            deterministic_bytes(dispatch_len, 101),
            deterministic_bytes(dispatch_len, 113),
        ];
        let factors = [[0x1234, 0x2345], [0x3456, 0x4567], [0x5678, 0x6789]];
        let mut expected = vec![vec![0u8; dispatch_len]; outputs];
        for (j, row) in expected.iter_mut().enumerate() {
            for (s, source) in sources.iter().enumerate() {
                mul_acc_region(factors[j][s], source, row);
            }
        }

        session.begin_chunk(dispatch_len).unwrap();
        let source_refs: Vec<&[u8]> = sources.iter().map(Vec::as_slice).collect();
        session
            .accumulate(&source_refs, |j, s| factors[j][s])
            .unwrap();

        let sentinel = 0xa5;
        let mut flat = vec![sentinel; outputs * row_stride];
        assert_eq!(
            session.finish_chunk_into(&mut flat, row_stride, 0),
            Err("live byte length must be nonzero")
        );
        assert_eq!(
            session.finish_chunk_into(&mut flat, row_stride, dispatch_len + 1),
            Err("live byte length exceeds active chunk")
        );
        session
            .finish_chunk_into(&mut flat, row_stride, live_len)
            .unwrap();

        for (j, row) in expected.iter().enumerate() {
            let offset = j * row_stride;
            assert_eq!(&flat[offset..offset + live_len], &row[..live_len]);
            assert!(
                flat[offset + live_len..offset + row_stride]
                    .iter()
                    .all(|&byte| byte == sentinel)
            );
        }
    }

    #[test]
    fn metal_session_matches_cpu_kernels() {
        // Force-engage so the size gate does not skip the test shape; skip
        // entirely on machines without a Metal device.
        let outputs = 5usize;
        let region = 8192usize + 6; // odd tail: exercises the scalar path
        let Some(mut session) = MetalGf16Session::try_new(
            outputs,
            region,
            MIN_EFFECTIVE_BYTES + 1, // pass the auto gate regardless of env
        ) else {
            eprintln!("no Metal device; skipping");
            return;
        };

        let factors: Vec<u16> = (0..outputs * MAX_SOURCES)
            .map(|i| (i as u16).wrapping_mul(0x2F1D).wrapping_add(3) | 1)
            .collect();

        // Two batches accumulate into one chunk, mirroring a streaming workload.
        let batch_a: Vec<Vec<u8>> = (0..MAX_SOURCES)
            .map(|s| deterministic_bytes(region, s))
            .collect();
        let batch_b: Vec<Vec<u8>> = (0..17)
            .map(|s| deterministic_bytes(region, s + 100))
            .collect();

        let mut expected: Vec<Vec<u8>> = vec![vec![0u8; region]; outputs];
        for (j, row) in expected.iter_mut().enumerate() {
            for (s, src) in batch_a.iter().enumerate() {
                mul_acc_region(factors[j * MAX_SOURCES + s], src, row);
            }
            for (s, src) in batch_b.iter().enumerate() {
                mul_acc_region(factors[j * MAX_SOURCES + s].wrapping_add(1) | 1, src, row);
            }
        }

        session.begin_chunk(region).unwrap();
        let refs_a: Vec<&[u8]> = batch_a.iter().map(|s| s.as_slice()).collect();
        session
            .accumulate(&refs_a, |j, s| factors[j * MAX_SOURCES + s])
            .unwrap();
        let refs_b: Vec<&[u8]> = batch_b.iter().map(|s| s.as_slice()).collect();
        session
            .accumulate(&refs_b, |j, s| {
                factors[j * MAX_SOURCES + s].wrapping_add(1) | 1
            })
            .unwrap();
        let mut rows: Vec<Vec<u8>> = vec![vec![0u8; region]; outputs];
        session.finish_chunk(&mut rows).unwrap();

        assert_eq!(rows, expected, "GPU accumulate must match CPU kernels");

        // Second chunk on the same session: dst must re-zero.
        session.begin_chunk(64).unwrap();
        let one = deterministic_bytes(64, 9);
        session.accumulate(&[one.as_slice()], |_, _| 7).unwrap();
        let mut rows2: Vec<Vec<u8>> = vec![vec![0u8; 64]; outputs];
        session.finish_chunk(&mut rows2).unwrap();
        let mut want = vec![0u8; 64];
        mul_acc_region(7, &one, &mut want);
        for row in &rows2 {
            assert_eq!(row, &want, "chunk reset must start from zeroed dst");
        }
    }
}

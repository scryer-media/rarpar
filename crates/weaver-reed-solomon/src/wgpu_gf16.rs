//! GF(2^16) multiply-accumulate on portable GPUs (wgpu: Vulkan/DX12/Metal).
//!
//! The wgpu twin of [`crate::metal_gf16`], for the platforms the native Metal
//! backend does not cover (Windows/Linux discrete GPUs). Same product and the
//! same 4×16-entry nibble-table formulation: each output's coefficient tables
//! are staged into workgroup memory, the inner loop is on-chip table lookups.
//! Not an upstream par2cmdline-turbo port — ParPar's GPU story is OpenCL and
//! is not compiled there; this is rarpar-native engineering like the Metal
//! arm.
//!
//! WGSL has no 16-bit integer type, so words travel in packed pairs: every
//! `u32` holds two LE u16 words, tables store two entries per `u32`
//! (`entry[i] = word[i>>1] >> ((i&1)*16)`), and an odd trailing word masks
//! its unit's high half. Workgroup table storage is `MAX_SOURCES * 32` u32 =
//! 8448 bytes, under the 16 KiB portable minimum.
//!
//! Unlike the Metal session there is no manual double-buffering: wgpu queue
//! operations (`write_buffer`, submits) execute in submission order, so a
//! source upload is ordered after the previous dispatch that reads the same
//! buffer. Readback goes through an explicit MAP_READ staging buffer — no
//! unified-memory shortcut is assumed.
//!
//! Gating mirrors the Metal arm: `WEAVER_GF16_WGPU=0` disables, `=1` forces
//! (skips every gate), otherwise a session engages when the repair is large
//! enough to amortize dispatch + PCIe transfer. The automatic path also
//! refuses `DeviceType::Cpu` adapters — see [`auto_engageable`] — because a
//! Vulkan ICD list on a headless Linux box is often nothing but llvmpipe,
//! and `request_adapter` returns it without complaint.

use std::sync::OnceLock;

/// Widest source batch a single dispatch accepts — matches the Metal arm and
/// the streaming repair batch; its packed tables need 8448 B of workgroup
/// memory.
pub const MAX_SOURCES: usize = 66;

const TABLE_WORDS_PER_FACTOR: usize = 64; // 4 nibble positions × 16 entries
const TABLE_UNITS_PER_FACTOR: usize = TABLE_WORDS_PER_FACTOR / 2; // packed u32
const WORKGROUP_SIZE: usize = 256;

/// Auto-engage threshold: outputs × sources × region bytes per repair.
/// Below this the CPU path wins on dispatch + transfer overhead.
const MIN_EFFECTIVE_BYTES: u64 = 256 * 1024 * 1024;

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
const MAX_SOURCES: u32 = {max_sources}u;
const WG_SIZE: u32 = {wg_size}u;

struct Params {{
    // u16 words per region row.
    words: u32,
    // Packed u32 units per region row (= ceil(words/2)); also the row stride.
    units: u32,
    sources: u32,
    _pad: u32,
}}

@group(0) @binding(0) var<storage, read> srcs: array<u32>;        // sources x units
@group(0) @binding(1) var<storage, read_write> dsts: array<u32>;  // outputs x units
@group(0) @binding(2) var<storage, read> tables: array<u32>;      // factor x 32 packed
@group(0) @binding(3) var<storage, read> factors: array<u32>;     // outputs x sources
@group(0) @binding(4) var<uniform> p: Params;

// One packed 64-entry table per source: 32 u32 units each.
var<workgroup> tg_tables: array<u32, {tg_units}u>;

fn lut(s: u32, idx: u32) -> u32 {{
    let w = tg_tables[s * 32u + (idx >> 1u)];
    return (w >> ((idx & 1u) * 16u)) & 0xFFFFu;
}}

fn mul_word(s: u32, x: u32) -> u32 {{
    return lut(s, x & 15u)
        ^ lut(s, 16u + ((x >> 4u) & 15u))
        ^ lut(s, 32u + ((x >> 8u) & 15u))
        ^ lut(s, 48u + (x >> 12u));
}}

@compute @workgroup_size({wg_size})
fn gf16_mulacc(
    @builtin(workgroup_id) wg: vec3<u32>,
    @builtin(local_invocation_id) lid: vec3<u32>,
) {{
    let tid = lid.x;
    let out = wg.y;

    // Stage this output's packed coefficient tables; each u32 unit has one
    // writer, so no half-word races.
    let tab_units = p.sources * 32u;
    var i = tid;
    while (i < tab_units) {{
        let f = factors[out * p.sources + (i >> 5u)];
        tg_tables[i] = tables[f * 32u + (i & 31u)];
        i += WG_SIZE;
    }}
    workgroupBarrier();

    // One packed unit (two words) per invocation.
    let u = wg.x * WG_SIZE + tid;
    if (u >= p.units) {{
        return;
    }}
    // Odd word count: the last unit's high half is past the region — compute
    // nothing into it and preserve whatever the buffer holds there.
    let partial = ((p.words & 1u) == 1u) && (u == p.units - 1u);

    let acc = dsts[out * p.units + u];
    var lo = acc & 0xFFFFu;
    var hi = acc >> 16u;
    for (var s = 0u; s < p.sources; s++) {{
        let x = srcs[s * p.units + u];
        lo ^= mul_word(s, x & 0xFFFFu);
        if (!partial) {{
            hi ^= mul_word(s, x >> 16u);
        }}
    }}
    dsts[out * p.units + u] = lo | (hi << 16u);
}}
"#,
        max_sources = MAX_SOURCES,
        wg_size = WORKGROUP_SIZE,
        tg_units = MAX_SOURCES * TABLE_UNITS_PER_FACTOR,
    )
}

#[derive(Clone, Copy)]
enum WgpuGate {
    Auto,
    Force,
    Off,
}

fn wgpu_gate() -> WgpuGate {
    match std::env::var("WEAVER_GF16_WGPU") {
        Ok(v) if v == "0" || v.eq_ignore_ascii_case("false") => WgpuGate::Off,
        Ok(v) if v == "1" || v.eq_ignore_ascii_case("true") => WgpuGate::Force,
        _ => WgpuGate::Auto,
    }
}

/// Device-global wgpu state, created once. `Device`/`Queue` are internally
/// synchronized; sessions hold their own buffers and are single-threaded.
struct WgpuShared {
    device: wgpu::Device,
    queue: wgpu::Queue,
    pipeline: wgpu::ComputePipeline,
    adapter_name: String,
    device_type: wgpu::DeviceType,
    max_binding: u64,
}

/// Module-scoped so [`auto_refused_cpu_adapter`] can observe an already-probed
/// adapter without initializing one.
static CONTEXT: OnceLock<Option<WgpuShared>> = OnceLock::new();

/// The shared adapter/device/pipeline, probed once. Deliberately blind to the
/// adapter's device type: the forced path must reach a CPU rasterizer, so the
/// refusal belongs on the automatic arm of [`WgpuGf16Session::try_new_gated`],
/// not here.
fn shared_context() -> Option<&'static WgpuShared> {
    CONTEXT
        .get_or_init(|| {
            if matches!(wgpu_gate(), WgpuGate::Off) {
                return None;
            }
            // Headless compute: no window/display handle needed. `WGPU_BACKEND`
            // (wgpu's own env convention: vulkan/dx12/metal/gl) narrows the
            // backend set — without this the choice between e.g. Vulkan and
            // DX12 on Windows is wgpu's alone and cannot be pinned for A/Bs.
            let mut descriptor = wgpu::InstanceDescriptor::new_without_display_handle();
            descriptor.backends = wgpu::Backends::from_env().unwrap_or(descriptor.backends);
            let instance = wgpu::Instance::new(descriptor);
            let adapter =
                pollster::block_on(instance.request_adapter(&wgpu::RequestAdapterOptions {
                    power_preference: wgpu::PowerPreference::HighPerformance,
                    ..Default::default()
                }))
                .ok()?;
            // Raise the storage-binding/buffer ceilings to what the adapter
            // offers; large repairs need destination bindings past the
            // 128 MiB portable default. Session setup re-checks real sizes.
            let adapter_limits = adapter.limits();
            let limits = wgpu::Limits {
                max_storage_buffer_binding_size: adapter_limits.max_storage_buffer_binding_size,
                max_buffer_size: adapter_limits.max_buffer_size,
                ..Default::default()
            };
            let (device, queue) =
                pollster::block_on(adapter.request_device(&wgpu::DeviceDescriptor {
                    label: Some("weaver.gf16"),
                    required_limits: limits,
                    ..Default::default()
                }))
                .ok()?;
            let module = device.create_shader_module(wgpu::ShaderModuleDescriptor {
                label: Some("weaver.gf16.mulacc"),
                source: wgpu::ShaderSource::Wgsl(shader_source().into()),
            });
            let pipeline = device.create_compute_pipeline(&wgpu::ComputePipelineDescriptor {
                label: Some("weaver.gf16.mulacc"),
                layout: None,
                module: &module,
                entry_point: Some("gf16_mulacc"),
                compilation_options: Default::default(),
                cache: None,
            });
            let max_binding = device.limits().max_storage_buffer_binding_size;
            let info = adapter.get_info();
            Some(WgpuShared {
                device,
                queue,
                pipeline,
                // Backend included: "3080 Ti" alone cannot distinguish a
                // Vulkan run from a DX12 run in logs, and that ambiguity has
                // already cost one wrong benchmark conclusion.
                adapter_name: format!("{} [{:?}]", info.name, info.backend),
                device_type: info.device_type,
                max_binding,
            })
        })
        .as_ref()
}

/// Adapter classes the automatic gate accepts.
///
/// Only `DeviceType::Cpu` is refused, and the reason is structural rather than
/// empirical: a software rasterizer (llvmpipe, lavapipe, SwiftShader) runs this
/// shader on the very cores the CPU tier already owns, reached through a
/// SPIR-V → LLVM JIT and a staging-buffer round trip that the CPU tier does not
/// pay. There is no host on which it can win. Measured on an i5-1240P, work =
/// outputs × sources × region: llvmpipe through this arm ~2.9 GiB/s against
/// ~91 GiB/s for the 16-thread CPU path it would displace.
///
/// `IntegratedGpu` stays engaged, deliberately. The measurement that seems to
/// argue otherwise — an Iris Xe at ~14.9 GiB/s losing to a single GFNI core at
/// ~20.6 GiB/s — was taken on a box where this arm never engages: `engage` in
/// `weaver-par2`'s repair path requires `!cpu_fast_path`, and `cpu_fast_path`
/// is `altmap_supported() || xorjit`, both of which are x86-64-with-AVX2. So
/// the automatic path only ever runs on non-x86 (where the CPU tier is the
/// NEON kernel) and on pre-AVX2 x86, and on neither has an integrated GPU been
/// shown to lose. Refusing the class would instead disable the arm on nearly
/// every host it was written for, since Apple, Adreno and Mali all report
/// `IntegratedGpu` — while `PowerPreference::HighPerformance` already prefers a
/// discrete GPU when the host has both. A host whose integrated GPU really is
/// slower than its CPU tier already has the `WEAVER_GF16_WGPU=0` kill switch;
/// a second knob would be encoding a guess. If that case is ever measured on a
/// host the automatic path can reach, the measurement should drive the policy.
///
/// `Other` and `VirtualGpu` stay engaged too: drivers under-report (virtio-gpu,
/// some Mesa builds), and refusing them would reject real hardware.
///
/// This table governs hosts where nothing else owns accumulation. When an x86
/// fast tier exists, weaver-par2's arbitration asks the stricter
/// [`discrete_auto_candidate`] question instead, and a non-discrete adapter on
/// such a host never reaches this gate at all.
fn auto_engageable(device_type: wgpu::DeviceType) -> bool {
    !matches!(device_type, wgpu::DeviceType::Cpu)
}

/// True when a wgpu adapter is present and the tier is not disabled.
///
/// Says nothing about whether the automatic gate would engage it — a CPU
/// rasterizer is "available" and still refused. Use [`auto_engageable`] for
/// that question.
pub fn wgpu_gf16_available() -> bool {
    shared_context().is_some()
}

/// True when the automatic gate has probed an adapter and would refuse it as a
/// CPU rasterizer, so a caller can log why the GPU arm stayed dark.
///
/// Reports only on an *already*-probed adapter and never initializes one, so
/// asking the question on a repair that the size gate already declined costs
/// nothing.
pub fn auto_refused_cpu_adapter() -> bool {
    matches!(wgpu_gate(), WgpuGate::Auto)
        && CONTEXT
            .get()
            .and_then(|shared| shared.as_ref())
            .is_some_and(|shared| !auto_engageable(shared.device_type))
}

/// True when `WEAVER_GF16_WGPU=1` demands the wgpu arm regardless of CPU
/// fast-path availability. A bench/testing override: the caller must then
/// shape its streaming buffers for the GPU arm (plain fill) and keep the
/// universal CPU tier as the fallback.
pub fn force_requested() -> bool {
    matches!(wgpu_gate(), WgpuGate::Force)
}

/// Pure decision behind [`discrete_auto_candidate`], split out so the table is
/// unit-testable without an adapter or environment state.
fn discrete_auto_candidate_resolved(
    gate: WgpuGate,
    device_type: Option<wgpu::DeviceType>,
    effective_bytes: u64,
) -> bool {
    matches!(gate, WgpuGate::Auto)
        && effective_bytes >= MIN_EFFECTIVE_BYTES
        && matches!(device_type, Some(wgpu::DeviceType::DiscreteGpu))
}

/// True when the AUTOMATIC gate should claim accumulation from an x86 CPU fast
/// tier because a DISCRETE GPU is present and the repair clears the size gate.
///
/// This is a stricter question than [`auto_engageable`], and deliberately so:
/// that gate serves hosts with no fast tier, where anything better than a CPU
/// rasterizer wins by default. Here the GPU must beat a running start —
/// AVX2/GFNI folded or XOR-JIT accumulation across every core — so the burden
/// of proof flips, and only `DiscreteGpu` carries it. Measured (RTX 3080 Ti vs
/// Ryzen 5 3600, AVX2/no-GFNI, `rar5_heavy_damage_250` end-to-end workflow):
/// 2.21 s CPU vs 1.07 s GPU, ~2×. Kernel-isolated the same pairing is only at
/// PARITY — the end-to-end win comes from freeing the whole CPU for the MD5 +
/// I/O the repair runs concurrently, which is also why the decision cannot be
/// made from kernel throughput alone. `IntegratedGpu` is refused here on the
/// same evidence class: an Iris Xe measured 6.4× BEHIND a 16-thread GFNI CPU
/// kernel-isolated, and no end-to-end win has been shown on an AVX2 host.
/// `Other`/`VirtualGpu` are refused as unmeasured against a fast tier (the
/// under-reporting-driver argument in [`auto_engageable`] does not outweigh a
/// measured-fast CPU). `WEAVER_GF16_WGPU=1` remains the override for all of
/// them, and `=0` still kills the arm entirely.
///
/// Cost: on the first affirmative-looking call this initializes the shared
/// adapter/device/pipeline (`OnceLock`, once per process) just to read the
/// device type — the same setup any engagement would pay, wasted only on
/// hosts whose adapter is then refused. The gate and size pre-checks run
/// first so hosts with the tier off, or repairs under the size gate, never
/// pay the probe.
pub fn discrete_auto_candidate(effective_bytes: u64) -> bool {
    if !matches!(wgpu_gate(), WgpuGate::Auto) || effective_bytes < MIN_EFFECTIVE_BYTES {
        return false;
    }
    discrete_auto_candidate_resolved(
        WgpuGate::Auto,
        shared_context().map(|shared| shared.device_type),
        effective_bytes,
    )
}

/// One repair's GPU residency: source/factor upload buffers, one destination
/// buffer resident across every source batch of a chunk, a factor-indexed
/// packed table cache filled lazily, and a MAP_READ staging buffer for
/// readback.
pub struct WgpuGf16Session {
    shared: &'static WgpuShared,
    src_buf: wgpu::Buffer,
    factor_buf: wgpu::Buffer,
    dst_buf: wgpu::Buffer,
    table_buf: wgpu::Buffer,
    params_buf: wgpu::Buffer,
    staging_buf: wgpu::Buffer,
    bind_group: wgpu::BindGroup,
    table_filled: Vec<u64>,
    outputs: usize,
    max_region_bytes: usize,
    /// Row stride in packed u32 units for the current chunk.
    chunk_units: usize,
    chunk_words: usize,
}

impl WgpuGf16Session {
    /// Engage a session when a suitable adapter exists and the whole repair is
    /// big enough to amortize dispatch + transfer (`effective_bytes` = outputs
    /// × sources × region bytes). The automatic path additionally refuses CPU
    /// rasterizers (see [`auto_engageable`]); `WEAVER_GF16_WGPU=1` skips both
    /// gates, `=0` refuses everything.
    pub fn try_new(outputs: usize, max_region_bytes: usize, effective_bytes: u64) -> Option<Self> {
        Self::try_new_gated(wgpu_gate(), outputs, max_region_bytes, effective_bytes)
    }

    /// Engage on whatever adapter the host offers — CPU rasterizers included —
    /// exactly as `WEAVER_GF16_WGPU=1` would, but without writing a
    /// process-global env var.
    ///
    /// For benches and conformance tests that must exercise the shader on the
    /// adapter `VK_DRIVER_FILES` selected. `WEAVER_GF16_WGPU=0` still wins: the
    /// kill switch lives in [`shared_context`], which this cannot bypass.
    pub fn try_new_forced(outputs: usize, max_region_bytes: usize) -> Option<Self> {
        Self::try_new_gated(WgpuGate::Force, outputs, max_region_bytes, 0)
    }

    fn try_new_gated(
        gate: WgpuGate,
        outputs: usize,
        max_region_bytes: usize,
        effective_bytes: u64,
    ) -> Option<Self> {
        // Size gate before `shared_context()`: a repair too small for the GPU
        // must not pay adapter probe, device creation and shader compilation
        // only to be refused.
        match gate {
            WgpuGate::Off => return None,
            WgpuGate::Auto if effective_bytes < MIN_EFFECTIVE_BYTES => return None,
            WgpuGate::Auto | WgpuGate::Force => {}
        }
        let shared = shared_context()?;
        if matches!(gate, WgpuGate::Auto) && !auto_engageable(shared.device_type) {
            return None;
        }
        if outputs == 0 || max_region_bytes == 0 || !max_region_bytes.is_multiple_of(2) {
            return None;
        }
        // The kernel indexes rows as `out * units + u` and `s * units + u` in
        // 32-bit math; refuse shapes that could wrap rather than corrupt. The
        // source side is implicitly bounded by the ≤4 GiB binding ceilings on
        // every backend, but assert it locally so the invariant is
        // self-evident.
        let max_units = (max_region_bytes / 2).div_ceil(2) as u64;
        let max_rows = outputs.max(MAX_SOURCES) as u64;
        if max_rows.saturating_mul(max_units) > u32::MAX as u64 {
            return None;
        }

        let row_bytes = max_units * 4;
        let src_len = MAX_SOURCES as u64 * row_bytes;
        let dst_len = outputs as u64 * row_bytes;
        let factor_len = (outputs * MAX_SOURCES * 4) as u64;
        let table_len = (65536 * TABLE_UNITS_PER_FACTOR * 4) as u64;
        let limit = shared
            .max_binding
            .min(shared.device.limits().max_buffer_size);
        if src_len > limit || dst_len > limit || factor_len > limit || table_len > limit {
            return None;
        }

        let device = &shared.device;
        let mk = |label: &str, size: u64, usage: wgpu::BufferUsages| {
            device.create_buffer(&wgpu::BufferDescriptor {
                label: Some(label),
                size,
                usage,
                mapped_at_creation: false,
            })
        };
        use wgpu::BufferUsages as U;
        let src_buf = mk("weaver.gf16.src", src_len, U::STORAGE | U::COPY_DST);
        let dst_buf = mk(
            "weaver.gf16.dst",
            dst_len,
            U::STORAGE | U::COPY_DST | U::COPY_SRC,
        );
        let factor_buf = mk("weaver.gf16.factors", factor_len, U::STORAGE | U::COPY_DST);
        let table_buf = mk("weaver.gf16.tables", table_len, U::STORAGE | U::COPY_DST);
        let params_buf = mk("weaver.gf16.params", 16, U::UNIFORM | U::COPY_DST);
        let staging_buf = mk("weaver.gf16.staging", dst_len, U::MAP_READ | U::COPY_DST);

        let layout = shared.pipeline.get_bind_group_layout(0);
        let bind_group = device.create_bind_group(&wgpu::BindGroupDescriptor {
            label: Some("weaver.gf16.bind"),
            layout: &layout,
            entries: &[
                wgpu::BindGroupEntry {
                    binding: 0,
                    resource: src_buf.as_entire_binding(),
                },
                wgpu::BindGroupEntry {
                    binding: 1,
                    resource: dst_buf.as_entire_binding(),
                },
                wgpu::BindGroupEntry {
                    binding: 2,
                    resource: table_buf.as_entire_binding(),
                },
                wgpu::BindGroupEntry {
                    binding: 3,
                    resource: factor_buf.as_entire_binding(),
                },
                wgpu::BindGroupEntry {
                    binding: 4,
                    resource: params_buf.as_entire_binding(),
                },
            ],
        });

        Some(Self {
            shared,
            src_buf,
            factor_buf,
            dst_buf,
            table_buf,
            params_buf,
            staging_buf,
            bind_group,
            table_filled: vec![0u64; 65536 / 64],
            outputs,
            max_region_bytes,
            chunk_units: 0,
            chunk_words: 0,
        })
    }

    fn ensure_table(&mut self, factor: u16) {
        let idx = factor as usize;
        if self.table_filled[idx / 64] & (1 << (idx % 64)) != 0 {
            return;
        }
        self.table_filled[idx / 64] |= 1 << (idx % 64);
        let mut packed = [0u8; TABLE_UNITS_PER_FACTOR * 4];
        for k in 0..4u32 {
            for x in 0..16u16 {
                let value = gf16_mul(factor, x << (4 * k));
                let i = (k as usize) * 16 + x as usize;
                let b = value.to_le_bytes();
                packed[i * 2] = b[0];
                packed[i * 2 + 1] = b[1];
            }
        }
        self.shared.queue.write_buffer(
            &self.table_buf,
            (idx * TABLE_UNITS_PER_FACTOR * 4) as u64,
            &packed,
        );
    }

    /// Start a chunk: zero the resident destination rows on the GPU.
    pub fn begin_chunk(&mut self, byte_len: usize) -> Result<(), &'static str> {
        if byte_len == 0 || !byte_len.is_multiple_of(2) || byte_len > self.max_region_bytes {
            return Err("chunk length unsupported by the wgpu session");
        }
        self.chunk_words = byte_len / 2;
        self.chunk_units = self.chunk_words.div_ceil(2);
        let mut encoder =
            self.shared
                .device
                .create_command_encoder(&wgpu::CommandEncoderDescriptor {
                    label: Some("weaver.gf16.begin"),
                });
        let clear_len = (self.outputs * self.chunk_units * 4) as u64;
        encoder.clear_buffer(&self.dst_buf, 0, Some(clear_len));
        self.shared.queue.submit([encoder.finish()]);
        Ok(())
    }

    /// Accumulate one source batch into the resident chunk destinations:
    /// `dst[j] ^= factor(j, s) * srcs[s]`. Queue ordering fences the buffer
    /// reuse; the call returns after submission.
    pub fn accumulate(
        &mut self,
        srcs: &[&[u8]],
        factor: impl Fn(usize, usize) -> u16,
    ) -> Result<(), &'static str> {
        let sources = srcs.len();
        if sources == 0 {
            return Ok(());
        }
        if sources > MAX_SOURCES {
            return Err("source batch wider than the wgpu kernel supports");
        }
        let byte_len = self.chunk_words * 2;
        if byte_len == 0 {
            return Err("accumulate before begin_chunk");
        }

        // Factors first: fills the lazy table cache before the GPU reads it.
        let mut factors = vec![0u8; self.outputs * sources * 4];
        for j in 0..self.outputs {
            for s in 0..sources {
                let f = factor(j, s);
                self.ensure_table(f);
                factors[(j * sources + s) * 4..][..4].copy_from_slice(&(f as u32).to_le_bytes());
            }
        }
        self.shared
            .queue
            .write_buffer(&self.factor_buf, 0, &factors);

        let row_bytes = self.chunk_units * 4;
        let mut row = vec![0u8; row_bytes];
        for (s, src) in srcs.iter().enumerate() {
            if src.len() != byte_len {
                return Err("source region length mismatch");
            }
            row[..byte_len].copy_from_slice(src);
            row[byte_len..].fill(0);
            self.shared
                .queue
                .write_buffer(&self.src_buf, (s * row_bytes) as u64, &row);
        }

        let params: [u32; 4] = [
            self.chunk_words as u32,
            self.chunk_units as u32,
            sources as u32,
            0,
        ];
        self.shared
            .queue
            .write_buffer(&self.params_buf, 0, bytemuck_cast(&params));

        let mut encoder =
            self.shared
                .device
                .create_command_encoder(&wgpu::CommandEncoderDescriptor {
                    label: Some("weaver.gf16.accumulate"),
                });
        {
            let mut pass = encoder.begin_compute_pass(&wgpu::ComputePassDescriptor {
                label: Some("weaver.gf16.mulacc"),
                timestamp_writes: None,
            });
            pass.set_pipeline(&self.shared.pipeline);
            pass.set_bind_group(0, &self.bind_group, &[]);
            let groups_x = self.chunk_units.div_ceil(WORKGROUP_SIZE) as u32;
            pass.dispatch_workgroups(groups_x, self.outputs as u32, 1);
        }
        self.shared.queue.submit([encoder.finish()]);
        Ok(())
    }

    /// Wait for the chunk's dispatches and copy the accumulated destinations
    /// out. `dst_rows[j][..byte_len]` receives output `j`.
    pub fn finish_chunk(&mut self, dst_rows: &mut [Vec<u8>]) -> Result<(), &'static str> {
        if dst_rows.len() != self.outputs {
            return Err("output row count mismatch");
        }
        let byte_len = self.chunk_words * 2;
        let row_bytes = self.chunk_units * 4;
        let copy_len = (self.outputs * row_bytes) as u64;

        let mut encoder =
            self.shared
                .device
                .create_command_encoder(&wgpu::CommandEncoderDescriptor {
                    label: Some("weaver.gf16.readback"),
                });
        encoder.copy_buffer_to_buffer(&self.dst_buf, 0, &self.staging_buf, 0, copy_len);
        self.shared.queue.submit([encoder.finish()]);

        let slice = self.staging_buf.slice(..copy_len);
        let (tx, rx) = std::sync::mpsc::channel();
        slice.map_async(wgpu::MapMode::Read, move |result| {
            let _ = tx.send(result);
        });
        if self
            .shared
            .device
            .poll(wgpu::PollType::wait_indefinitely())
            .is_err()
        {
            return Err("wgpu device poll failed");
        }
        match rx.recv() {
            Ok(Ok(())) => {}
            _ => return Err("wgpu readback mapping failed"),
        }
        {
            let mapped = match slice.get_mapped_range() {
                Ok(mapped) => mapped,
                Err(_) => {
                    // The buffer may still be in the mapped state even when
                    // the range is unavailable; leave it clean for the (dead)
                    // session anyway.
                    self.staging_buf.unmap();
                    return Err("wgpu mapped range unavailable");
                }
            };
            for (j, dst_row) in dst_rows.iter_mut().enumerate() {
                if dst_row.len() < byte_len {
                    drop(mapped);
                    self.staging_buf.unmap();
                    return Err("output row shorter than chunk");
                }
                dst_row[..byte_len].copy_from_slice(&mapped[j * row_bytes..][..byte_len]);
            }
        }
        self.staging_buf.unmap();
        self.chunk_words = 0;
        self.chunk_units = 0;
        Ok(())
    }

    /// Adapter name for engage-time logging.
    pub fn device_name(&self) -> String {
        self.shared.adapter_name.clone()
    }
}

/// `[u32; 4]` → bytes without a bytemuck dependency.
fn bytemuck_cast(v: &[u32; 4]) -> &[u8] {
    unsafe { std::slice::from_raw_parts(v.as_ptr().cast::<u8>(), 16) }
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

    /// The full discrete-auto decision table, adapter- and env-free.
    #[test]
    fn discrete_auto_decision_table() {
        use wgpu::DeviceType;
        let big = MIN_EFFECTIVE_BYTES;
        let small = MIN_EFFECTIVE_BYTES - 1;

        // Only Auto + DiscreteGpu + at-or-above the size gate says yes.
        assert!(discrete_auto_candidate_resolved(
            WgpuGate::Auto,
            Some(DeviceType::DiscreteGpu),
            big
        ));

        // Every other adapter class is refused against a fast tier.
        for device in [
            DeviceType::IntegratedGpu,
            DeviceType::Cpu,
            DeviceType::VirtualGpu,
            DeviceType::Other,
        ] {
            assert!(!discrete_auto_candidate_resolved(
                WgpuGate::Auto,
                Some(device),
                big
            ));
        }
        // No adapter at all.
        assert!(!discrete_auto_candidate_resolved(WgpuGate::Auto, None, big));
        // Under the size gate.
        assert!(!discrete_auto_candidate_resolved(
            WgpuGate::Auto,
            Some(DeviceType::DiscreteGpu),
            small
        ));
        // Off never claims; Force is handled by `force_requested`, not here.
        for gate in [WgpuGate::Off, WgpuGate::Force] {
            assert!(!discrete_auto_candidate_resolved(
                gate,
                Some(DeviceType::DiscreteGpu),
                big
            ));
        }
    }

    /// GPU session against the CPU kernels: odd word counts (packed-unit
    /// tail), factor 0/1 edge cases, a MAX_SOURCES-wide batch, and a second
    /// chunk reusing the session. Skips when no adapter is present (headless
    /// CI without lavapipe).
    ///
    /// Forced, not automatic: this is a shader conformance test and lavapipe is
    /// the only adapter CI has, but the automatic gate refuses CPU rasterizers.
    /// Through `try_new` the whole test would quietly degrade to a skip on
    /// exactly the host it is meant to run on.
    #[test]
    fn wgpu_session_matches_cpu_kernels() {
        for &(outputs, sources, byte_len) in &[
            (3usize, 5usize, 4096usize),
            (3, 5, 4098),
            (2, MAX_SOURCES, 2050),
        ] {
            let Some(mut session) = WgpuGf16Session::try_new_forced(outputs, byte_len) else {
                eprintln!("wgpu adapter unavailable; skipping");
                return;
            };
            // Name the adapter: a pass on a CPU rasterizer (llvmpipe/lavapipe)
            // proves the shader, not the GPU arm. Without this the two are
            // indistinguishable in the test log.
            eprintln!("wgpu adapter: {}", session.device_name());

            let srcs: Vec<Vec<u8>> = (0..sources)
                .map(|s| deterministic_bytes(byte_len, s))
                .collect();
            // Mix in the 0 (no-op) and 1 (plain XOR) edge factors.
            let factor = |j: usize, s: usize| match (j + s) % 5 {
                0 => 0u16,
                1 => 1u16,
                _ => ((j * 7 + s * 131 + 1) % 65536) as u16,
            };

            let mut expected: Vec<Vec<u8>> = vec![vec![0u8; byte_len]; outputs];
            for (j, row) in expected.iter_mut().enumerate() {
                for (s, src) in srcs.iter().enumerate() {
                    mul_acc_region(factor(j, s), src, row);
                }
            }

            for chunk in 0..2 {
                session.begin_chunk(byte_len).expect("begin_chunk");
                let src_refs: Vec<&[u8]> = srcs.iter().map(|s| s.as_slice()).collect();
                // Split the batch in two accumulates to exercise reuse.
                session
                    .accumulate(&src_refs[..2], factor)
                    .expect("accumulate 1");
                session
                    .accumulate(&src_refs[2..], |j, s| factor(j, s + 2))
                    .expect("accumulate 2");
                let mut rows: Vec<Vec<u8>> = vec![vec![0u8; byte_len]; outputs];
                session.finish_chunk(&mut rows).expect("finish_chunk");
                for j in 0..outputs {
                    assert_eq!(
                        rows[j], expected[j],
                        "chunk {chunk} output {j} len {byte_len}"
                    );
                }
            }
        }
    }

    /// The automatic gate refuses a software rasterizer no matter how large the
    /// repair, while the forced path still takes it. Meaningful on both kinds
    /// of host: under `VK_DRIVER_FILES=.../lvp_icd.json` it pins the refusal,
    /// on a real GPU it pins that the arm still engages.
    #[test]
    fn auto_gate_refuses_cpu_adapters() {
        // `WEAVER_GF16_WGPU` would otherwise decide the answer for us.
        if !matches!(wgpu_gate(), WgpuGate::Auto) {
            eprintln!("WEAVER_GF16_WGPU overrides the auto gate; skipping");
            return;
        }
        let Some(shared) = shared_context() else {
            eprintln!("wgpu adapter unavailable; skipping");
            return;
        };
        let (name, device_type) = (&shared.adapter_name, shared.device_type);
        eprintln!("wgpu adapter: {name} ({device_type:?})");
        let is_cpu = matches!(device_type, wgpu::DeviceType::Cpu);

        assert!(
            WgpuGf16Session::try_new_forced(2, 4096).is_some(),
            "forced path must engage any adapter, including {name} ({device_type:?})"
        );
        assert_eq!(
            WgpuGf16Session::try_new(2, 4096, u64::MAX).is_some(),
            !is_cpu,
            "auto gate on {name} ({device_type:?})"
        );
        assert_eq!(auto_refused_cpu_adapter(), is_cpu);
        // The size gate is untouched by the device-type gate.
        assert!(WgpuGf16Session::try_new(2, 4096, MIN_EFFECTIVE_BYTES - 1).is_none());
    }
}

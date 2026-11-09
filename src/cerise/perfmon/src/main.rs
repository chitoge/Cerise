// Cerise perfmon client (PMU path A) — raw hardware performance-counter reads via
// zx_mtrace_control(MTRACE_KIND_PERFMON, ...). It drives the seven mtrace-perfmon
// actions (GET_PROPERTIES / INIT / ASSIGN_BUFFER / STAGE_CONFIG / START / STOP /
// FINI) against the already-vendored kernel PMU stack
// (zircon/kernel/arch/x86/perf_mon.cc), programs the three fixed counters
// (instructions-retired, unhalted-core-cycles, unhalted-reference-cycles) plus one
// programmable architectural event (LLC cache-misses), runs a bounded workload,
// then reads and parses the per-cpu perfmon trace buffers.
//
// It obtains the privileged handle via the narrowly-routed fuchsia.kernel.DebugResource
// builtin (a ZX_RSRC_KIND_SYSTEM child at ZX_RSRC_SYSTEM_DEBUG_BASE); the syscall is
// additionally gated on kernel.enable-debugging-syscalls=true, which ONLY the
// qemu-x64-perfmon profiling product sets. Markers go straight to the kernel debuglog
// (zx_debug_write), so no LogSink is used.
//
// Environment honesty: a VM may not expose a real PMU. Under
// QEMU TCG there is NO PMU, and GET_PROPERTIES returns ZX_ERR_NOT_SUPPORTED. That is a
// LEGITIMATE, asserted outcome — the client emits CERISE-PERFMON-UNSUPPORTED and exits
// cleanly (0). It NEVER fabricates counts. Real numbers come from KVM-with-PMU or bare
// real hardware (architectural PMU v4).
//
// Gate markers (validation/perfmon_boot_test.py):
//   CERISE-PERFMON-START                                    (always, first)
//   CERISE-PERFMON-PROPERTIES version=.. fixed=.. prog=..   (PMU present)
//   CERISE-PERFMON-COUNTS instructions=.. core_cycles=..    (PMU present, after run)
//   CERISE-PERFMON-UNSUPPORTED version=.. reason=..         (no PMU — clean, PASS)
//   CERISE-PERFMON-ERROR ..                                 (routing/flag bug — FAIL)
//   CERISE-PERFMON-DONE                                     (always, last, clean exit)

use fidl_fuchsia_kernel::DebugResourceMarker;
use fuchsia_component::client::connect_to_protocol_sync;
use zx::{MonotonicInstant, Resource, Vmo};

extern "C" {
    // Exported by the vDSO (libzircon.so); not surfaced in the Rust zx-sys bindings,
    // so we declare it directly (as component_runner does for zx_debug_write).
    fn zx_mtrace_control(
        handle: u32,
        kind: u32,
        action: u32,
        options: u32,
        ptr: *mut u8,
        size: usize,
    ) -> i32;
    fn zx_debug_write(buf: *const u8, len: usize) -> i32;
}

fn debug_write(msg: &str) {
    unsafe {
        zx_debug_write(msg.as_ptr(), msg.len());
    }
}

// ── zx status / mtrace ABI (zircon-internal/mtrace.h + errors.h) ──
const ZX_OK: i32 = 0;
const ZX_ERR_NOT_SUPPORTED: i32 = -2;

const MTRACE_KIND_PERFMON: u32 = 1;
const MTRACE_PERFMON_GET_PROPERTIES: u32 = 0;
const MTRACE_PERFMON_INIT: u32 = 1;
const MTRACE_PERFMON_ASSIGN_BUFFER: u32 = 2;
const MTRACE_PERFMON_STAGE_CONFIG: u32 = 3;
const MTRACE_PERFMON_START: u32 = 4;
const MTRACE_PERFMON_STOP: u32 = 5;
const MTRACE_PERFMON_FINI: u32 = 6;

// The minimum PMU version the kernel supports (MTRACE_X86_INTEL_PMU_MIN_SUPPORTED_VERSION).
const MIN_SUPPORTED_VERSION: u16 = 2;

// ── PMU structs, ABI-matched to zircon-internal/device/cpu-trace/{common-pm,intel-pm}.h.
// repr(C) reproduces the C natural-alignment layout; the const asserts below fail the
// build if the size ever drifts (the kernel rejects a wrong `size` with INVALID_ARGS,
// so a mismatch is a clean failure, never memory corruption).

#[repr(C)]
#[derive(Default, Clone, Copy)]
struct PmuCommonProperties {
    pm_version: u16,
    max_num_fixed_events: u16,
    max_fixed_counter_width: u16,
    max_num_programmable_events: u16,
    max_programmable_counter_width: u16,
    max_num_misc_events: u16,
    max_misc_counter_width: u16,
}

#[repr(C)]
#[derive(Default, Clone, Copy)]
struct X86PmuProperties {
    common: PmuCommonProperties,
    padding1: [u8; 2],
    perf_capabilities: u64,
    lbr_stack_size: u32,
    padding2: [u8; 4],
}
const _: () = assert!(std::mem::size_of::<X86PmuProperties>() == 32);

const IPM_MAX_FIXED_COUNTERS: usize = 3;
const IPM_MAX_PROGRAMMABLE_COUNTERS: usize = 8;
const IPM_MAX_MISC_EVENTS: usize = 16;

#[repr(C)]
struct X86PmuConfig {
    global_ctrl: u64,
    fixed_ctrl: u64,
    debug_ctrl: u64,
    timebase_event: u16,
    fixed_events: [u16; IPM_MAX_FIXED_COUNTERS],
    programmable_events: [u16; IPM_MAX_PROGRAMMABLE_COUNTERS],
    misc_events: [u16; IPM_MAX_MISC_EVENTS],
    fixed_initial_value: [u64; IPM_MAX_FIXED_COUNTERS],
    programmable_initial_value: [u64; IPM_MAX_PROGRAMMABLE_COUNTERS],
    fixed_flags: [u32; IPM_MAX_FIXED_COUNTERS],
    programmable_flags: [u32; IPM_MAX_PROGRAMMABLE_COUNTERS],
    misc_flags: [u32; IPM_MAX_MISC_EVENTS],
    padding1: [u8; 4],
    programmable_hw_events: [u64; IPM_MAX_PROGRAMMABLE_COUNTERS],
}
const _: () = assert!(std::mem::size_of::<X86PmuConfig>() == 344);

impl Default for X86PmuConfig {
    fn default() -> Self {
        X86PmuConfig {
            global_ctrl: 0,
            fixed_ctrl: 0,
            debug_ctrl: 0,
            timebase_event: 0,
            fixed_events: [0; IPM_MAX_FIXED_COUNTERS],
            programmable_events: [0; IPM_MAX_PROGRAMMABLE_COUNTERS],
            misc_events: [0; IPM_MAX_MISC_EVENTS],
            fixed_initial_value: [0; IPM_MAX_FIXED_COUNTERS],
            programmable_initial_value: [0; IPM_MAX_PROGRAMMABLE_COUNTERS],
            fixed_flags: [0; IPM_MAX_FIXED_COUNTERS],
            programmable_flags: [0; IPM_MAX_PROGRAMMABLE_COUNTERS],
            misc_flags: [0; IPM_MAX_MISC_EVENTS],
            padding1: [0; 4],
            programmable_hw_events: [0; IPM_MAX_PROGRAMMABLE_COUNTERS],
        }
    }
}

// zx_pmu_buffer_t { zx_handle_t vmo; } — passed to ASSIGN_BUFFER.
#[repr(C)]
struct ZxPmuBuffer {
    vmo: u32,
}
const _: () = assert!(std::mem::size_of::<ZxPmuBuffer>() == 4);

// ── perfmon event ids (perf-mon.h MakeEventId(group, event)) ──
const fn make_event_id(group: u16, event: u16) -> u16 {
    (group << 11) | event
}
const GROUP_ARCH: u16 = 1;
const GROUP_FIXED: u16 = 2;

// Fixed counters (intel-pm-events.inc DEF_FIXED_EVENT ids; hw reg = id-1).
const EV_INSTRUCTIONS_RETIRED: u16 = make_event_id(GROUP_FIXED, 1); // 0x1001, fixed reg 0
const EV_CORE_CYCLES: u16 = make_event_id(GROUP_FIXED, 2); // 0x1002, fixed reg 1
const EV_REF_CYCLES: u16 = make_event_id(GROUP_FIXED, 3); // 0x1003, fixed reg 2

// Programmable architectural event: LLC misses (DEF_ARCH_EVENT id 4, event 0x2e/umask 0x41).
// Architectural event => valid on any host exposing an architectural PMU.
const EV_LLC_MISSES: u16 = make_event_id(GROUP_ARCH, 4); // 0x804

// IA32_PERFEVTSEL bit layout (intel-pm.h): event[7:0] | umask[15:8] | USR(16) | OS(17) | EN(22).
const PERFEVTSEL_LLC_MISSES: u64 =
    0x2e | (0x41 << 8) | (1 << 16) | (1 << 17) | (1 << 22);

// ── perfmon record layout (perf-mon.h) ──
const REC_TIME: u8 = 1; // TimeRecord   : hdr(4) + time(8)   = 12
const REC_TICK: u8 = 2; // TickRecord   : hdr(4)             = 4
const REC_COUNT: u8 = 3; // CountRecord : hdr(4) + count(8)  = 12
const REC_VALUE: u8 = 4; // ValueRecord : hdr(4) + value(8)  = 12
const REC_PC: u8 = 5; //    PcRecord    : hdr(4) + 8 + 8      = 20
const BUFFER_HEADER_SIZE: usize = 24; // version+arch+flags+ticks_per_second+capture_end

fn mtrace(res: &Resource, action: u32, options: u32, ptr: *mut u8, size: usize) -> i32 {
    unsafe { zx_mtrace_control(res.raw_handle(), MTRACE_KIND_PERFMON, action, options, ptr, size) }
}

// A bounded, memory-touching workload: enough retired instructions that the count is
// non-trivial and comfortably exceeds the loop count, with a strided array walk to
// generate real cache traffic (LLC misses).
fn run_workload() -> u64 {
    const ITERS: u64 = 20_000_000;
    let mut buf = vec![0u8; 8 * 1024 * 1024]; // 8 MiB > any core-private cache
    let len = buf.len();
    let mut acc: u64 = 0;
    let mut i: u64 = 0;
    while i < ITERS {
        acc = acc.wrapping_add(i.wrapping_mul(2654435761));
        let idx = (acc as usize) % len;
        buf[idx] = buf[idx].wrapping_add(1);
        acc ^= buf[idx] as u64;
        i += 1;
    }
    std::hint::black_box(&buf);
    std::hint::black_box(acc)
}

// Read u64/u16 little-endian from a byte slice.
fn rd_u16(b: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([b[off], b[off + 1]])
}
fn rd_u64(b: &[u8], off: usize) -> u64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(&b[off..off + 8]);
    u64::from_le_bytes(a)
}

#[derive(Default)]
struct Counts {
    instructions: u64,
    core_cycles: u64,
    ref_cycles: u64,
    llc_misses: u64,
}

// Parse one per-cpu trace buffer, accumulating count records into `counts`.
fn parse_buffer(bytes: &[u8], counts: &mut Counts) {
    if bytes.len() < BUFFER_HEADER_SIZE {
        return;
    }
    let capture_end = rd_u64(bytes, 16) as usize;
    let end = capture_end.min(bytes.len());
    let mut off = BUFFER_HEADER_SIZE;
    while off + 4 <= end {
        let rtype = bytes[off];
        let event = rd_u16(bytes, off + 2);
        let rec_size = match rtype {
            REC_TIME => 12,
            REC_TICK => 4,
            REC_COUNT | REC_VALUE => 12,
            REC_PC => 20,
            _ => break, // unknown/zero — end of valid records
        };
        if off + rec_size > end {
            break;
        }
        if rtype == REC_COUNT || rtype == REC_VALUE {
            let count = rd_u64(bytes, off + 4);
            match event {
                EV_INSTRUCTIONS_RETIRED => counts.instructions += count,
                EV_CORE_CYCLES => counts.core_cycles += count,
                EV_REF_CYCLES => counts.ref_cycles += count,
                EV_LLC_MISSES => counts.llc_misses += count,
                _ => {}
            }
        }
        off += rec_size;
    }
}

// The full supported path: INIT -> ASSIGN_BUFFER(each cpu) -> STAGE_CONFIG -> START ->
// workload -> STOP -> read+parse -> FINI. Returns Ok(counts) or Err(marker-safe reason).
fn run_supported(res: &Resource, num_cpus: u32) -> Result<Counts, String> {
    // INIT
    let st = mtrace(res, MTRACE_PERFMON_INIT, 0, std::ptr::null_mut(), 0);
    if st != ZX_OK {
        return Err(format!("INIT failed status={st}"));
    }

    // ASSIGN_BUFFER: one VMO per cpu, kept alive through STOP.
    let mut vmos: Vec<Vmo> = Vec::with_capacity(num_cpus as usize);
    for cpu in 0..num_cpus {
        let vmo = Vmo::create(4096).map_err(|e| format!("vmo create: {e}"))?;
        let mut buf = ZxPmuBuffer { vmo: vmo.raw_handle() };
        let st = mtrace(
            res,
            MTRACE_PERFMON_ASSIGN_BUFFER,
            cpu,
            &mut buf as *mut _ as *mut u8,
            std::mem::size_of::<ZxPmuBuffer>(),
        );
        if st != ZX_OK {
            let _ = mtrace(res, MTRACE_PERFMON_FINI, 0, std::ptr::null_mut(), 0);
            return Err(format!("ASSIGN_BUFFER cpu={cpu} status={st}"));
        }
        vmos.push(vmo);
    }

    // STAGE_CONFIG: 3 fixed counters + 1 programmable arch event, pure counting mode
    // (no timebase, no PMI, initial values zero).
    let mut cfg = X86PmuConfig::default();
    cfg.fixed_events[0] = EV_INSTRUCTIONS_RETIRED;
    cfg.fixed_events[1] = EV_CORE_CYCLES;
    cfg.fixed_events[2] = EV_REF_CYCLES;
    // IA32_FIXED_CTR_CTRL: enable each fixed counter for OS+USR (0b11 per 4-bit field).
    cfg.fixed_ctrl = 0x3 | (0x3 << 4) | (0x3 << 8);
    cfg.programmable_events[0] = EV_LLC_MISSES;
    cfg.programmable_hw_events[0] = PERFEVTSEL_LLC_MISSES;
    // IA32_PERF_GLOBAL_CTRL: enable PMC0 (bit 0) + fixed 0,1,2 (bits 32,33,34).
    cfg.global_ctrl = (1u64) | (1u64 << 32) | (1u64 << 33) | (1u64 << 34);

    let st = mtrace(
        res,
        MTRACE_PERFMON_STAGE_CONFIG,
        0,
        &mut cfg as *mut _ as *mut u8,
        std::mem::size_of::<X86PmuConfig>(),
    );
    if st != ZX_OK {
        let _ = mtrace(res, MTRACE_PERFMON_FINI, 0, std::ptr::null_mut(), 0);
        return Err(format!("STAGE_CONFIG failed status={st}"));
    }

    // START -> workload -> STOP.
    let st = mtrace(res, MTRACE_PERFMON_START, 0, std::ptr::null_mut(), 0);
    if st != ZX_OK {
        let _ = mtrace(res, MTRACE_PERFMON_FINI, 0, std::ptr::null_mut(), 0);
        return Err(format!("START failed status={st}"));
    }
    let sink = run_workload();
    debug_write(&format!("[perfmon] workload done (sink={:#x})\n", sink));
    let st = mtrace(res, MTRACE_PERFMON_STOP, 0, std::ptr::null_mut(), 0);
    if st != ZX_OK {
        let _ = mtrace(res, MTRACE_PERFMON_FINI, 0, std::ptr::null_mut(), 0);
        return Err(format!("STOP failed status={st}"));
    }

    // Read + parse each per-cpu buffer; counts are summed across cpus.
    let mut counts = Counts::default();
    for (cpu, vmo) in vmos.iter().enumerate() {
        let mut bytes = vec![0u8; 4096];
        if let Err(e) = vmo.read(&mut bytes, 0) {
            debug_write(&format!("[perfmon] cpu {cpu} vmo read err: {e}\n"));
            continue;
        }
        parse_buffer(&bytes, &mut counts);
    }

    // FINI (frees kernel resources; ok to call multiple times).
    let _ = mtrace(res, MTRACE_PERFMON_FINI, 0, std::ptr::null_mut(), 0);
    Ok(counts)
}

fn main() {
    debug_write("CERISE-PERFMON-START\n");

    // Acquire the DebugResource (ZX_RSRC_KIND_SYSTEM @ ZX_RSRC_SYSTEM_DEBUG_BASE).
    let res = match connect_to_protocol_sync::<DebugResourceMarker>() {
        Ok(p) => match p.get(MonotonicInstant::INFINITE) {
            Ok(r) => r,
            Err(e) => {
                debug_write(&format!(
                    "CERISE-PERFMON-ERROR DebugResource.Get failed: {e}\n"
                ));
                debug_write("CERISE-PERFMON-DONE\n");
                std::process::exit(1);
            }
        },
        Err(e) => {
            debug_write(&format!(
                "CERISE-PERFMON-ERROR connect fuchsia.kernel.DebugResource: {e}\n"
            ));
            debug_write("CERISE-PERFMON-DONE\n");
            std::process::exit(1);
        }
    };

    // GET_PROPERTIES — the single biggest unknown: does this CPU/VM expose a PMU?
    let mut props = X86PmuProperties::default();
    let st = mtrace(
        &res,
        MTRACE_PERFMON_GET_PROPERTIES,
        0,
        &mut props as *mut _ as *mut u8,
        std::mem::size_of::<X86PmuProperties>(),
    );

    if st == ZX_ERR_NOT_SUPPORTED {
        // Legitimate: no PMU exposed (QEMU TCG, or a KVM host with vPMU disabled).
        // The flag is set by this product, so NOT_SUPPORTED here means "no silicon
        // counters", not "syscall gated". This is a PASS, never fabricated counts.
        debug_write(
            "CERISE-PERFMON-UNSUPPORTED version=0 reason=zx_mtrace_control-GET_PROPERTIES-returned-NOT_SUPPORTED-no-PMU-exposed\n",
        );
        debug_write("CERISE-PERFMON-DONE\n");
        std::process::exit(0);
    }
    if st != ZX_OK {
        // Any other error == a routing/flag/ABI bug, NOT an environmental no-PMU.
        debug_write(&format!(
            "CERISE-PERFMON-ERROR GET_PROPERTIES status={st}\n"
        ));
        debug_write("CERISE-PERFMON-DONE\n");
        std::process::exit(1);
    }

    let version = props.common.pm_version;
    debug_write(&format!(
        "CERISE-PERFMON-PROPERTIES version={} fixed={} prog={} misc={}\n",
        version,
        props.common.max_num_fixed_events,
        props.common.max_num_programmable_events,
        props.common.max_num_misc_events,
    ));

    if version < MIN_SUPPORTED_VERSION {
        debug_write(&format!(
            "CERISE-PERFMON-UNSUPPORTED version={version} reason=pm_version-below-minimum-supported-2\n"
        ));
        debug_write("CERISE-PERFMON-DONE\n");
        std::process::exit(0);
    }

    let num_cpus = zx::system_get_num_cpus();
    debug_write(&format!("[perfmon] driving {num_cpus} cpu buffer(s)\n"));

    match run_supported(&res, num_cpus) {
        Ok(c) => {
            debug_write(&format!(
                "CERISE-PERFMON-COUNTS instructions={} core_cycles={} ref_cycles={} llc_misses={} cpus={}\n",
                c.instructions, c.core_cycles, c.ref_cycles, c.llc_misses, num_cpus
            ));
            debug_write("CERISE-PERFMON-DONE\n");
            std::process::exit(0);
        }
        Err(reason) => {
            debug_write(&format!("CERISE-PERFMON-ERROR {reason}\n"));
            debug_write("CERISE-PERFMON-DONE\n");
            std::process::exit(1);
        }
    }
}

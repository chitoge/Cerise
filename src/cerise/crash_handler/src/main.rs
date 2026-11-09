//! Cerise crash_handler (userspace post-mortem path): a minimal root-job
//! crash observer built on the task_exceptions primitive.
//!
//! It obtains the ROOT JOB (via the narrowly-routed fuchsia.kernel.RootJob
//! builtin) and binds an exception channel to it. component_manager / elf_runner
//! install NO closer exception handler, so any userspace process crash that is
//! not handled closer propagates to the root job's channel and is delivered
//! here. For each crash it:
//!
//!   * logs the faulting process/thread (name + koid), the exception type and
//!     its arch-specific data, and the general registers;
//!   * emits a SELF-CONTAINED symbolizer-markup block — `{{{reset}}}`, one
//!     `{{{module}}}` + `{{{mmap}}}` per module in the crashing process (module
//!     load base + build-id read from the process's own mapped ELF headers), and
//!     a `{{{bt}}}` backtrace: frame 0 is the fault PC, deeper frames are an
//!     honest frame-pointer walk (return-address chain). //src/cerise/tools/symbolize
//!     resolves this block against the product's .build-id store into named,
//!     line-numbered frames.
//!
//! Then it RELEASES the exception WITHOUT marking it handled (drops the handle),
//! so zircon continues default processing and the process still dies. This is an
//! observer, deliberately NOT a recovery/minidump/crashpad mechanism.

use anyhow::{Context, Result};
use fidl_fuchsia_kernel::RootJobMarker;
use fuchsia_component::client::connect_to_protocol;
use futures::stream::StreamExt;
use task_exceptions::{ExceptionInfo, ExceptionsStream};
use zx::AsHandleRef;

/// Write straight to the kernel debuglog (surfaced on serial) — no LogSink, like
/// shutdown_trigger. Markup + human lines share this one sink so they interleave
/// in a single serial log the symbolize tool then post-processes.
fn emit(msg: &str) {
    // SAFETY: zx_debug_write takes (ptr,len) of readable bytes; msg is a live &str.
    unsafe {
        zx::sys::zx_debug_write(msg.as_ptr(), msg.len());
    }
}

/// Emit one symbolizer-markup element, wrapping the body in `{{{ }}}`. Avoids
/// Rust format-string brace escaping entirely.
fn emit_markup(body: &str) {
    let mut s = String::with_capacity(body.len() + 8);
    s.push_str("{{{");
    s.push_str(body);
    s.push_str("}}}\n");
    emit(&s);
}

/// A zircon object Name (fixed-size, NUL-padded) as a printable string.
fn name_of<T: AsHandleRef>(h: &T) -> String {
    match h.as_handle_ref().get_name() {
        Ok(n) => n.to_string(),
        Err(_) => "<unknown>".to_string(),
    }
}

fn koid_of<T: AsHandleRef>(h: &T) -> u64 {
    h.as_handle_ref().koid().map(|k| k.raw_koid()).unwrap_or(0)
}

/// Read up to `max` bytes of a crashing process's memory at `vaddr`. Returns the
/// bytes actually read (possibly short at a mapping edge), or empty on error.
fn read_mem(process: &zx::Process, vaddr: u64, max: usize) -> Vec<u8> {
    let mut buf = vec![0u8; max];
    match process.read_memory(vaddr as usize, &mut buf) {
        Ok(n) => {
            buf.truncate(n);
            buf
        }
        Err(_) => Vec::new(),
    }
}

/// Parse an in-memory ELF64-LE image header: return (build_id_hex, virtual_span)
/// where `virtual_span` is max(p_vaddr + p_memsz) over PT_LOAD segments (the
/// module's size from its load base, which for a PIE equals link vaddr 0). std
/// ELF poke, mirrors //src/cerise/tools/symbolize::read_build_id but over a
/// process-memory buffer (header + phdrs + notes live in the first page(s)).
fn parse_module(buf: &[u8]) -> Option<(Option<String>, u64)> {
    if buf.len() < 64 || &buf[0..4] != b"\x7fELF" || buf[4] != 2 || buf[5] != 1 {
        return None; // not ELF64-LE
    }
    let u16at = |o: usize| -> Option<usize> {
        Some(u16::from_le_bytes(buf.get(o..o + 2)?.try_into().ok()?) as usize)
    };
    let u32at = |o: usize| -> Option<u32> {
        Some(u32::from_le_bytes(buf.get(o..o + 4)?.try_into().ok()?))
    };
    let u64at = |o: usize| -> Option<u64> {
        Some(u64::from_le_bytes(buf.get(o..o + 8)?.try_into().ok()?))
    };
    let e_phoff = u64at(0x20)? as usize;
    let e_phentsize = u16at(0x36)?;
    let e_phnum = u16at(0x38)?;
    const PT_LOAD: u32 = 1;
    const PT_NOTE: u32 = 4;
    let mut build_id: Option<String> = None;
    let mut span: u64 = 0;
    for i in 0..e_phnum {
        let ph = e_phoff + i * e_phentsize;
        let p_type = match u32at(ph) {
            Some(t) => t,
            None => break,
        };
        match p_type {
            PT_LOAD => {
                if let (Some(p_vaddr), Some(p_memsz)) = (u64at(ph + 0x10), u64at(ph + 0x28)) {
                    span = span.max(p_vaddr.saturating_add(p_memsz));
                }
            }
            PT_NOTE => {
                if build_id.is_none() {
                    if let (Some(p_offset), Some(p_filesz)) = (u64at(ph + 0x08), u64at(ph + 0x20)) {
                        build_id = scan_build_id(buf, p_offset as usize, p_filesz as usize);
                    }
                }
            }
            _ => {}
        }
    }
    Some((build_id, span))
}

/// Scan an ELF note region for NT_GNU_BUILD_ID, returning lowercase hex.
fn scan_build_id(buf: &[u8], mut off: usize, len: usize) -> Option<String> {
    const NT_GNU_BUILD_ID: u32 = 3;
    let end = off.checked_add(len)?.min(buf.len());
    while off + 12 <= end {
        let namesz = u32::from_le_bytes(buf.get(off..off + 4)?.try_into().ok()?) as usize;
        let descsz = u32::from_le_bytes(buf.get(off + 4..off + 8)?.try_into().ok()?) as usize;
        let ntype = u32::from_le_bytes(buf.get(off + 8..off + 12)?.try_into().ok()?);
        let name_off = off + 12;
        let desc_off = name_off + namesz.div_ceil(4) * 4;
        let desc_end = desc_off + descsz;
        if desc_end > end {
            break;
        }
        if ntype == NT_GNU_BUILD_ID && buf.get(name_off..name_off + namesz)? == b"GNU\0" {
            let hex: String = buf[desc_off..desc_end].iter().map(|b| format!("{b:02x}")).collect();
            return Some(hex);
        }
        off = desc_end + (4 - descsz % 4) % 4;
    }
    None
}

/// Emit `{{{reset}}}` + one module/mmap per mapped ELF in the crashing process.
/// A module begins at a mapping with `vmo_offset == 0` whose first bytes are the
/// ELF magic; its build-id + virtual span come from its in-memory ELF headers.
fn emit_modules(process: &zx::Process) {
    emit_markup("reset");
    let maps = match process.info_maps_vec() {
        Ok(m) => m,
        Err(_) => return,
    };
    let mut module_id = 0u32;
    for m in &maps {
        let dets = m.details();
        let Some(details) = dets.as_mapping() else { continue };
        if details.vmo_offset != 0 {
            continue; // not the first page of a module image
        }
        let head = read_mem(process, m.base as u64, 0x2000);
        let Some((Some(build_id), span)) = parse_module(&head) else { continue };
        let span = if span == 0 { m.size as u64 } else { span };
        let name = name_of_map(&m.name, module_id);
        emit_markup(&format!("module:{module_id}:{name}:elf:{build_id}"));
        // static_start 0: for a PIE, module base corresponds to link vaddr 0, so
        // the tool computes module-relative addr = pc - base.
        emit_markup(&format!("mmap:{:#x}:{:#x}:load:{module_id}:rx:0x0", m.base, span));
        module_id += 1;
    }
}

/// A VMO/mapping name as a markup-safe module name (no ':' which would break the
/// element's field split; fall back to a synthetic name if empty).
fn name_of_map(name: &zx::Name, id: u32) -> String {
    let s = name.to_string();
    let s = s.trim_matches('\0').trim();
    if s.is_empty() {
        format!("module{id}")
    } else {
        s.replace(':', "_")
    }
}

/// Emit the `{{{bt}}}` backtrace: frame 0 is the fault PC, then an honest
/// frame-pointer walk of the return-address chain. Requires the crasher to keep
/// frame pointers for depth > 0; frame 0 (the fault PC) is always emitted and is
/// the frame the gate symbolizes. No DWARF unwind (deliberately out of scope).
fn emit_backtrace(process: &zx::Process, rip: u64, rbp: u64) {
    emit_markup(&format!("bt:0:{rip:#x}"));
    let mut fp = rbp;
    let mut frame = 1u32;
    const MAX_FRAMES: u32 = 32;
    while frame < MAX_FRAMES && fp != 0 && fp % 8 == 0 {
        let cell = read_mem(process, fp, 16);
        if cell.len() < 16 {
            break;
        }
        let saved_fp = u64::from_le_bytes(cell[0..8].try_into().unwrap());
        let ret = u64::from_le_bytes(cell[8..16].try_into().unwrap());
        if ret == 0 {
            break;
        }
        emit_markup(&format!("bt:{frame}:{ret:#x}:ra"));
        if saved_fp <= fp {
            break; // frames must ascend (stack grows down); stop on garbage
        }
        fp = saved_fp;
        frame += 1;
    }
}

/// Handle one delivered exception, then drop it (unhandled) so the process dies.
fn handle_exception(info: ExceptionInfo) {
    let ExceptionInfo { process, thread, exception_handle } = info;

    let pname = name_of(&process);
    let tname = name_of(&thread);
    let pkoid = koid_of(&process);
    let tkoid = koid_of(&thread);

    let report = thread.exception_report();
    let type_desc = match &report {
        Ok(r) => format!("{:?}", r.ty),
        Err(s) => format!("<report unavailable: {s}>"),
    };
    let arch_desc = match &report {
        Ok(r) => format!("{:?}", r.arch),
        Err(_) => String::new(),
    };

    emit(&format!(
        "CERISE-CRASH: process {pname:?} (koid {pkoid}) thread {tname:?} (koid {tkoid}) \
         exception {type_desc} {arch_desc}\n"
    ));

    match thread.read_state_general_regs() {
        Ok(regs) => {
            emit(&format!(
                "CERISE-CRASH: regs rip={:#x} rsp={:#x} rbp={:#x} rax={:#x} rdi={:#x} rsi={:#x}\n",
                regs.rip, regs.rsp, regs.rbp, regs.rax, regs.rdi, regs.rsi
            ));
            emit_modules(&process);
            emit_backtrace(&process, regs.rip, regs.rbp);
        }
        Err(s) => {
            emit(&format!("CERISE-CRASH: could not read registers: {s}\n"));
        }
    }
    emit("CERISE-CRASH-END\n");

    // Release WITHOUT setting ZX_EXCEPTION_STATE_HANDLED: dropping the handle
    // lets zircon continue default processing (we are the root-job last-resort
    // handler) so the faulting process is killed. Explicit drop for clarity.
    drop(exception_handle);
}

async fn run() -> Result<()> {
    let root_job_proxy =
        connect_to_protocol::<RootJobMarker>().context("connect fuchsia.kernel.RootJob")?;
    // fuchsia.kernel.RootJob/Get returns a zx.Handle:JOB -> zx::Job, served with
    // SAME_RIGHTS, so it carries the rights create_exception_channel needs.
    let root_job: zx::Job = root_job_proxy.get().await.context("RootJob.Get")?;
    let mut stream = ExceptionsStream::register_with_task(&root_job)
        .map_err(|s| anyhow::anyhow!("register root-job exception channel: {s}"))?;

    // Attached to the root-job exception channel; now safe to let the crasher run.
    emit("CERISE-CRASH-HANDLER-READY\n");
    if let Err(e) = start_crasher() {
        emit(&format!("CERISE-CRASH-HANDLER: could not start crasher: {e:#}\n"));
    }

    while let Some(item) = stream.next().await {
        match item {
            Ok(info) => handle_exception(info),
            Err(status) => emit(&format!("CERISE-CRASH-HANDLER: exception stream error {status}\n")),
        }
    }
    Ok(())
}

/// Start the crasher by connecting to its framework `fuchsia.component.Binder`
/// (routed to us from `#crasher`). This deterministically launches the crasher
/// ONLY AFTER we are attached to the root-job exception channel, so its crash is
/// guaranteed to be observed (an eager sibling would race our attach).
fn start_crasher() -> Result<()> {
    use fidl_fuchsia_component::BinderMarker;
    // Connecting is enough to start it; we hold the proxy so the channel stays open.
    let _binder = connect_to_protocol::<BinderMarker>().context("connect crasher Binder")?;
    // Leak the proxy so the connection (and thus the started crasher) persists.
    std::mem::forget(_binder);
    Ok(())
}

fn main() {
    let mut executor = fuchsia_async::LocalExecutor::default();
    if let Err(e) = executor.run_singlethreaded(run()) {
        emit(&format!("CERISE-CRASH-HANDLER-FAIL: {e:#}\n"));
    }
}

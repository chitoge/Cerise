// cerise-logsink: bridges bootstrap fuchsia.logger.LogSink traffic (API 30
// IOBuffer-based) into the kernel DLOG ring.
//
// At API level 30, LogSink uses a Zircon IOBuffer ring buffer:
//   - Server creates an IobSharedRegion (zx_iob_create_shared_region) for the backing VMO.
//   - Server creates (ep0, ep1) IOBuffer pair over that region with MediatedWriteRingBuffer.
//   - Server sends ep1 to client via the OnInit server event.
//   - Client (diagnostics_log) writes encoded log records via zx_iob_writev on ep1.
//   - Server maps ep0 and polls the ring buffer; decodes with diagnostics_log_encoding.
//   - Decoded records are written through one process-global write-only
//     zx::DebugLog. Production Archivist drains those records through its
//     separately policy-confined fuchsia.boot.ReadOnlyLog capability.
//
// MediatedWriteRingBuffer requires a Shared (not Private) region.
// zx::vdso_next::IobSharedRegion::create() uses dlsym to find the syscall, but on Fuchsia
// the vDSO is NOT in dlsym's search scope. We call zx_iob_create_shared_region directly —
// it's in our cerise sysroot's zircon.ifs (the linker resolves it against the vDSO stub).
//
// zx_debug_write is a direct-serial syscall, not the live DLOG producer. It is
// used only while creating the write-only DebugLog or when a DLOG write fails.
// Archivist is never routed back to this LogSink, so draining DLOG cannot feed a
// record into the same bridge again.
//
// logging = false: we are the bootstrap log sink; initializing our own logger
// would be circular.

use cerise_logsink_core::{
    admission::{ClientLimiter, InterestAction, InterestHangingGet, MAX_LOGSINK_CLIENTS},
    ring::{RECORD_HEADER_LEN, RingError, decode_snapshot, plan_wrapped_copy, validate_window},
};
use fidl::endpoints::ControlHandle;
use std::sync::{Arc, OnceLock};

static DLOG: OnceLock<Option<zx::DebugLog>> = OnceLock::new();

// zx_iob_create_shared_region is a "vdso next" syscall.
// Static extern "C" linkage fails at relocation time when the "next" vDSO is not in musl's
// dynamic-linker search scope. We use dlsym instead and fall back gracefully if not found.
unsafe extern "C" {
    fn dlsym(handle: *const core::ffi::c_void, symbol: *const core::ffi::c_char)
        -> *const core::ffi::c_void;
}
// RTLD_DEFAULT on Fuchsia musl is the null handle (0): search all loaded DSOs.
const RTLD_DEFAULT: *const core::ffi::c_void = core::ptr::null();
#[fuchsia::main(logging = false)]
async fn main() {
    use fidl::endpoints::RequestStream;
    use fidl_fuchsia_logger::LogSinkRequestStream;
    use fuchsia_component::server::ServiceFs;
    use futures::StreamExt;

    init_dlog();
    bootstrap_log("cerise-logsink: starting\n");

    enum Incoming {
        LogSink(LogSinkRequestStream),
    }

    let mut fs = ServiceFs::new();
    fs.dir("svc").add_fidl_service(Incoming::LogSink);
    fs.take_and_serve_directory_handle().expect("serve outgoing dir");

    bootstrap_log("cerise-logsink: serving fuchsia.logger.LogSink\n");

    let clients = Arc::new(ClientLimiter::new(MAX_LOGSINK_CLIENTS));
    fs.for_each_concurrent(None, move |Incoming::LogSink(stream)| {
        let clients = Arc::clone(&clients);
        async move {
            let Some(_permit) = clients.try_acquire() else {
                stream
                    .control_handle()
                    .shutdown_with_epitaph(zx::Status::NO_RESOURCES);
                return;
            };
            serve_logsink(stream).await;
        }
    })
    .await;
}

async fn serve_logsink(stream: fidl_fuchsia_logger::LogSinkRequestStream) {
    use fidl::endpoints::RequestStream;
    use fidl_fuchsia_logger::{LogSinkOnInitRequest, LogSinkRequest};
    use futures::FutureExt;
    use futures::StreamExt;
    use std::sync::atomic::AtomicU64;
    use zx::{
        Handle, Iob, IobAccess, IobDiscipline, IobRegion, IobRegionType,
        Unowned, Vmar, VmarFlags,
        vdso_next::{IobSharedRegion, IobRegionSharedOptions},
    };

    // IOBuffer ring buffer layout (MediatedWriteRingBuffer, Shared region):
    //   mapped[0..PAGE_SIZE]      = header: { head: AtomicU64, tail: AtomicU64 }
    //   mapped[PAGE_SIZE..]       = ring buffer data
    //   Each record envelope:     { tag: u64, length: u64, data: [u8; ceil8(length)] }
    //   head: monotonic count of bytes written (including envelopes)
    //   tail: monotonic count of bytes consumed (we advance this after reading)
    //
    // MediatedWriteRingBuffer discipline REQUIRES a Shared region (Private → INVALID_ARGS).
    // zx_iob_create_shared_region is in the "next" vDSO. We find it via dlsym at runtime to
    // avoid a static relocation dependency (which would fail when the next vDSO isn't in musl's
    // search scope). If dlsym returns null we send OnInit{buffer:None} so the client unblocks.
    const LOG_BUF_SIZE: usize = 256 * 1024;
    let page_size = zx::system_get_page_size() as usize;

    #[repr(C)]
    struct Header {
        head: AtomicU64, // monotonic bytes written (writer advances)
        tail: AtomicU64, // monotonic bytes consumed (reader advances)
    }

    // Look up zx_iob_create_shared_region at runtime via dlsym.
    type IobCreateSharedRegionFn = unsafe extern "C" fn(u64, u64, *mut u32) -> i32;
    let iob_create_fn: Option<IobCreateSharedRegionFn> = unsafe {
        let name = b"zx_iob_create_shared_region\0";
        let ptr = dlsym(RTLD_DEFAULT, name.as_ptr() as *const _);
        if ptr.is_null() { None } else { Some(core::mem::transmute(ptr)) }
    };

    let Some(iob_create_fn) = iob_create_fn else {
        // "next" vDSO not in musl's search scope: send empty OnInit so the client unblocks.
        bootstrap_log("cerise-logsink: zx_iob_create_shared_region not found via dlsym — empty OnInit\n");
        let control = stream.control_handle();
        let _ = control.send_on_init(LogSinkOnInitRequest {
            buffer: None, interest: None, ..Default::default()
        });
        return;
    };

    let mut shared_raw: u32 = 0;
    let sr_status = unsafe { iob_create_fn(0, LOG_BUF_SIZE as u64, &mut shared_raw) };
    if sr_status != 0 {
        bootstrap_log(&format!("cerise-logsink: zx_iob_create_shared_region failed: {sr_status}\n"));
        return;
    }
    let shared_region: IobSharedRegion =
        unsafe { Handle::from_raw(shared_raw) }.expect("valid IobSharedRegion handle").into();

    let (ep0_server, ep1_client) = match Iob::create(
        Default::default(),
        &[IobRegion {
            region_type: IobRegionType::Shared {
                options: IobRegionSharedOptions,
                region: &shared_region,
            },
            // EP0 (server): map for reading and for advancing the tail counter.
            // EP1 (client): mediated write via zx_iob_writev.
            access: IobAccess::EP0_CAN_MAP_READ
                | IobAccess::EP0_CAN_MAP_WRITE
                | IobAccess::EP1_CAN_MEDIATED_WRITE,
            discipline: IobDiscipline::MediatedWriteRingBuffer { tag: 0 },
        }],
    ) {
        Ok(pair) => pair,
        Err(e) => {
            bootstrap_log(&format!("cerise-logsink: Iob::create failed: {e:?}\n"));
            return;
        }
    };

    // Map EP0 for reading and tail updates.
    let root_vmar = unsafe {
        Unowned::<Vmar>::from_raw_handle(fuchsia_runtime::zx_vmar_root_self())
    };
    let mapped_addr = match root_vmar.map_iob(
        VmarFlags::PERM_READ | VmarFlags::PERM_WRITE,
        0,
        &ep0_server,
        0,
        0,
        LOG_BUF_SIZE,
    ) {
        Ok(addr) => addr,
        Err(e) => {
            bootstrap_log(&format!("cerise-logsink: map_iob failed: {e:?}\n"));
            return;
        }
    };

    // Validate every size/address calculation before creating references or
    // dereferencing the mapping. The client does not receive EP1 until after
    // this succeeds, so it cannot write the ring while the layout is checked.
    let layout = (|| {
        if mapped_addr == 0
            || mapped_addr % core::mem::align_of::<Header>() != 0
            || page_size < core::mem::size_of::<Header>()
        {
            return None;
        }
        let data_cap = LOG_BUF_SIZE.checked_sub(page_size)?;
        if data_cap < RECORD_HEADER_LEN {
            return None;
        }
        let map_end = mapped_addr.checked_add(LOG_BUF_SIZE)?;
        let data_addr = mapped_addr.checked_add(page_size)?;
        if data_addr.checked_add(data_cap)? != map_end {
            return None;
        }
        Some((data_addr, data_cap))
    })();
    let Some((data_addr, data_cap)) = layout else {
        bootstrap_log("cerise-logsink: invalid IOBuffer mapping layout\n");
        unsafe { root_vmar.unmap(mapped_addr, LOG_BUF_SIZE).ok() };
        return;
    };

    // SAFETY: map_iob returned a writable mapping of LOG_BUF_SIZE bytes;
    // `layout` proved Header alignment/extent and the data subrange above.
    let header: &Header = unsafe { &*(mapped_addr as *const Header) };
    let data_base = data_addr as *const u8;

    // Send OnInit to the connecting client with the write endpoint (ep1 as zx::Iob).
    // send_on_init takes the table by value (not reference) in this FIDL binding.
    let control = stream.control_handle();
    if let Err(e) = control.send_on_init(LogSinkOnInitRequest {
        buffer: Some(ep1_client),
        interest: None,
        ..Default::default()
    }) {
        bootstrap_log(&format!("cerise-logsink: send_on_init failed: {e:?}\n"));
        unsafe { root_vmar.unmap(mapped_addr, LOG_BUF_SIZE).ok() };
        return;
    }

    let mut my_pos = header.tail.load(std::sync::atomic::Ordering::Acquire);
    let mut stream = stream;
    let mut done = false;
    // WaitForInterestChange is a hanging get: reply ONCE with the initial
    // interest, then park one subsequent responder (interest never changes here)
    // so clients that re-arm on every reply (the C++ syslog backend's
    // PollInterest) don't spin in a busy-loop that saturates this server.
    let mut interest_state = InterestHangingGet::default();
    let mut _parked_interest = None;

    // Poll ring buffer every 50ms; stop when the client disconnects (stream closes).
    // Avoid break-inside-select! by using a done flag.
    loop {
        let timer = fuchsia_async::Timer::new(std::time::Duration::from_millis(50)).fuse();
        let next = stream.next().fuse();
        futures::pin_mut!(timer, next);

        futures::select! {
            _ = timer => {
                // Drain all available records from the ring buffer.
                let head = header.head.load(std::sync::atomic::Ordering::Acquire);
                // SAFETY: data_base/data_cap describe the validated live mapping,
                // which remains mapped until this connection loop ends.
                my_pos = unsafe { drain_mapped_ring(data_base, data_cap, my_pos, head) };
                header.tail.store(my_pos, std::sync::atomic::Ordering::Release);
            }
            item = next => {
                match item {
                    // WaitForInterestChange: respond with default interest (Info+) to keep
                    // the channel alive. Dropping the responder without responding would
                    // call control_handle.shutdown() and close the LogSink channel.
                    Some(Ok(LogSinkRequest::WaitForInterestChange { responder })) => {
                        match interest_state.on_request() {
                            InterestAction::ReplyInitial => {
                                let _ = responder.send(Ok(&Default::default()));
                            }
                            InterestAction::Park => {
                                // Interest never changes, so retain exactly one responder.
                                _parked_interest = Some(responder);
                            }
                            InterestAction::RejectDuplicate => {
                                // FIDL hanging-get methods permit one outstanding request.
                                // Close a client that pipelines another instead of retaining
                                // an attacker-controlled number of responders.
                                control.shutdown_with_epitaph(zx::Status::BAD_STATE);
                                done = true;
                            }
                        }
                    }
                    // Stream closed or errored: signal done.
                    _ => { done = true; }
                }
            }
        }

        if done { break; }
    }

    // Final drain: flush any records written between the last timer tick and channel close.
    {
        let head = header.head.load(std::sync::atomic::Ordering::Acquire);
        // SAFETY: the mapping is still live and has the validated data extent.
        my_pos = unsafe { drain_mapped_ring(data_base, data_cap, my_pos, head) };
        header.tail.store(my_pos, std::sync::atomic::Ordering::Release);
    }

    unsafe { root_vmar.unmap(mapped_addr, LOG_BUF_SIZE).ok() };
}

fn decode_and_klog(payload: &[u8]) {
    use diagnostics_log_encoding::Argument;
    if let Ok((record, _)) = diagnostics_log_encoding::parse::parse_record(payload) {
        let sev = match record.severity {
            s if s >= 0x50 => 'E', // ERROR
            s if s >= 0x40 => 'W', // WARN
            s if s >= 0x30 => 'I', // INFO
            _ => 'D',              // DEBUG / TRACE
        };
        let mut msg = String::new();
        let mut tags: Vec<String> = Vec::new();
        let mut kv: Vec<String> = Vec::new();
        for arg in &record.arguments {
            match arg {
                Argument::Message(m) => msg = m.to_string(),
                Argument::Tag(t) => tags.push(t.to_string()),
                Argument::Other { name, value } => kv.push(format!("{name}={value:?}")),
                _ => {}
            }
        }
        if !kv.is_empty() {
            msg = format!("{} {}", msg, kv.join(" "));
        }
        let line = if tags.is_empty() {
            format!("[{}] {}\n", sev, msg)
        } else {
            format!("[{}][{}] {}\n", sev, tags.join(","), msg)
        };
        bootstrap_log(&line);
    }
}

/// Copy a validated unread window out of the shared mapping in logical order.
///
/// # Safety
///
/// `base..base + capacity` must remain readable for the duration of this call.
unsafe fn snapshot_mapped_ring(
    base: *const u8,
    capacity: usize,
    position: u64,
    length: usize,
) -> Result<Vec<u8>, RingError> {
    let plan = plan_wrapped_copy(capacity, position, length)?;
    let first_end =
        plan.first_start
            .checked_add(plan.first_len)
            .ok_or(RingError::OffsetOverflow {
                offset: plan.first_start,
            })?;
    let mut snapshot = Vec::with_capacity(length);

    // Volatile reads make the shared-memory boundary explicit. The acquired
    // writer head and unreleased reader tail ensure the kernel-mediated writer
    // does not reuse these bytes while this copy is in progress.
    unsafe {
        for index in plan.first_start..first_end {
            snapshot.push(core::ptr::read_volatile(base.add(index)));
        }
        for index in 0..plan.second_len {
            snapshot.push(core::ptr::read_volatile(base.add(index)));
        }
    }
    Ok(snapshot)
}

/// Validate, snapshot, and safely decode one committed reader-to-writer window.
///
/// # Safety
///
/// `base..base + capacity` must describe the live mapped data region.
unsafe fn drain_mapped_ring(base: *const u8, capacity: usize, position: u64, head: u64) -> u64 {
    let available = match validate_window(position, head, capacity) {
        Ok(available) => available,
        Err(error @ RingError::HeadBehindPosition { .. }) => {
            bootstrap_log(&format!(
                "cerise-logsink: refusing invalid ring window: {error}\n"
            ));
            // Never move the monotonic tail backwards.
            return position;
        }
        Err(error) => {
            bootstrap_log(&format!(
                "cerise-logsink: dropping invalid ring window: {error}\n"
            ));
            // The unread bytes were overwritten or cannot be addressed. Advancing
            // to the acquired head is the only bounded recovery point.
            return head;
        }
    };
    if available == 0 {
        return position;
    }

    // SAFETY: validate_window proved available <= capacity, and the caller
    // guarantees the complete mapped extent.
    let snapshot = match unsafe { snapshot_mapped_ring(base, capacity, position, available) } {
        Ok(snapshot) => snapshot,
        Err(error) => {
            bootstrap_log(&format!(
                "cerise-logsink: dropping unread ring window: {error}\n"
            ));
            return head;
        }
    };
    let decoded = match decode_snapshot(&snapshot, capacity) {
        Ok(decoded) => decoded,
        Err(error) => {
            bootstrap_log(&format!(
                "cerise-logsink: dropping malformed ring record: {error}\n"
            ));
            return head;
        }
    };

    for record in decoded.records {
        decode_and_klog(&record.payload);
    }

    let Ok(consumed) = u64::try_from(decoded.consumed) else {
        bootstrap_log("cerise-logsink: decoded byte count does not fit u64\n");
        return head;
    };
    position.checked_add(consumed).unwrap_or(head)
}

fn bootstrap_log(msg: &str) {
    if let Some(log) = DLOG.get().and_then(Option::as_ref) {
        // Preserve long structured records as a sequence of bounded DLOG
        // records. Every split is on a UTF-8 boundary; the kernel's fixed
        // record size therefore cannot truncate text or trigger a panic.
        let mut start = 0;
        while start < msg.len() {
            let mut end = (start + zx::sys::ZX_LOG_RECORD_DATA_MAX).min(msg.len());
            while end > start && !msg.is_char_boundary(end) {
                end -= 1;
            }
            if log.write(&msg.as_bytes()[start..end]).is_err() {
                direct_serial(&msg[start..]);
                return;
            }
            start = end;
        }
        return;
    }

    direct_serial(msg);
}

fn init_dlog() {
    // An invalid resource is intentionally accepted by zx_debuglog_create for
    // a write-only handle (options=0). READABLE would require the privileged
    // resource retained by component_manager and routed only to Archivist.
    let resource = zx::Resource::from(zx::NullableHandle::invalid());
    match zx::DebugLog::create(&resource, zx::DebugLogOpts::empty()) {
        Ok(log) => {
            let _ = DLOG.set(Some(log));
        }
        Err(status) => {
            let _ = DLOG.set(None);
            direct_serial(&format!(
                "cerise-logsink: write-only DLOG creation failed: {status}; using direct serial\n"
            ));
        }
    }
}

fn direct_serial(msg: &str) {
    unsafe {
        zx::sys::zx_debug_write(msg.as_ptr(), msg.len());
    }
}

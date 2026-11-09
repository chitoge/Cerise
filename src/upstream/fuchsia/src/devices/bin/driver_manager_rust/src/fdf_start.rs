// Copyright 2026 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Cerise Component 5: the REAL in-process DFv2 fdf-Driver round-trip.
//!
//! Component 4 built the Rust half (fdf channel pair + complete DriverStartArgs +
//! Driver.Start encode/write) but handed the fdf Driver SERVER end to a SEPARATE
//! driver_host process via `DriverHost.Start`. That can never complete the round
//! trip: **fdf handles are PROCESS-LOCAL runtime handles, not zircon kernel
//! handles**, so the server end cannot cross a process boundary. Component 5
//! CO-LOCATES the loader with the fdf runtime owner (this very process,
//! driver_manager_rust_dfv2) and completes the round trip IN-PROCESS, exactly as
//! the C++ spike (`//src/cerise/dfv2_loader_spike`) proved:
//!
//!   1. Start the fdf runtime env (`fdf_env_start`).
//!   2. Create TWO synchronized fdf dispatchers with DISTINCT owners — a "driver"
//!      dispatcher (the DriverServer binds here) and a "client" dispatcher (drives
//!      Driver.Start). Same-owner ends can trip fdf reentrancy and silently fail
//!      to deliver; the spike used `&owner_driver` vs `&owner_client`.
//!   3. Create the fdf Driver channel pair (client, server).
//!   4. On the DRIVER dispatcher, call the C++ loader FFI
//!      `cerise_load_and_init_driver(so, server_handle)`: it dlopens the driver
//!      .so, resolves `__fuchsia_driver_registration__`, and calls
//!      `v1.initialize(server_handle)` (which reads the CURRENT fdf dispatcher and
//!      binds a `DriverServer<MinimalDriver>` to it). It MUST run on an fdf
//!      dispatcher thread, hence the post onto the driver dispatcher.
//!   5. On the CLIENT dispatcher, build a complete `DriverStartArgs`. The `/svc`
//!      `incoming` namespace is a cross-process CLONE of THIS process's OWN routed
//!      `/svc` (served by component_manager) — DriverBase's `Namespace::Create`
//!      requires a real served `fuchsia.io/Directory`, and its logger ctor then does a
//!      SYNC `ns.Connect<LogSink>()` + `HandleOneEvent` wait for `OnInit` on that very
//!      `/svc`; routing it to cerise_logsink (which pumps in another process)
//!      delivers `OnInit` on the driver's own channel so the ctor completes. Built on
//!      the MAIN executor thread and moved in as the `/svc` Directory client endpoint,
//!      plus an `outgoing_dir` server end; `log_sink` is `None` (the driver connects
//!      `LogSink` itself via the cloned `/svc` — passing an out-of-band `log_sink`
//!      ClientEnd HANGS, its `OnInit` lost across the fdf handle transfer);
//!      `node`/`program` are unused by the minimal driver. Encode `Driver.Start`, and
//!      `Channel::write` it.
//!   6. KEEP BOTH DISPATCHERS ALIVE for the process lifetime (`mem::forget`).
//!      Dropping them initiates ShutdownAsync, which would tear the driver down
//!      before the driver dispatcher processes the Start message. With them alive,
//!      the driver dispatcher asynchronously runs the DriverServer ->
//!      MinimalDriver::Start() -> `CERISE-DFV2-DRIVER-OK` after this returns.
//!
//! A true SEPARATE driver_host process would need a cross-process fdf transport
//! (the runtime does not provide one for the Driver protocol); that is deferred.

use anyhow::{Context, Error, anyhow, bail};
use core::ffi::{c_char, c_void};
use fdf::{Arena, AsyncDispatcher, Channel, Dispatcher, DispatcherBuilder};
use fidl::endpoints::create_endpoints;
use fidl_fuchsia_component_runner as frunner;
use fidl_fuchsia_driver_framework as fdf_fidl;
use fidl_fuchsia_io as fio;
use log::info;
use std::ffi::CString;

// The C++ in-process loader (//src/cerise/dfv2_inproc_loader). Linked into
// driver_manager_rust_dfv2; the binary is linked `-rdynamic` so the dlopen'd
// driver .so binds its UND fdf/libc++/logging refs against this process's one
// statically-linked driver_runtime instance.
unsafe extern "C" {
    fn cerise_load_and_init_driver(so_path: *const c_char, server_handle: u32) -> i32;
}

// Raw fdf runtime env hooks (the safe fdf crate does not re-export these). We start
// the env and bracket dispatcher creation with a synthetic driver "owner" context
// so `fdf_dispatcher_create` (which requires a current driver, not a runtime
// thread) succeeds from driver_manager's executor thread.
unsafe extern "C" {
    fn fdf_env_start(options: u32) -> i32;
    fn fdf_env_register_driver_entry(driver: *const c_void);
    fn fdf_env_register_driver_exit();
}

const ZX_OK: i32 = 0;

fn mark(msg: &[u8]) {
    // SAFETY: zx_debug_write only reads `len` bytes from `ptr`.
    unsafe {
        zx::sys::zx_debug_write(msg.as_ptr(), msg.len());
    }
}

/// Resolve the package-relative driver soname the loader dlopens. The only native
/// DFv2 driver wired for this in-process path is the cerise minimal driver.
fn soname_for_url(_url: &str) -> &'static str {
    "cerise_minimal_driver.so"
}

/// Build the driver's `incoming` `/svc` entry as a cross-process CLONE of THIS
/// process's own routed `/svc` (Component 5 / approach 3).
///
/// `fdf::DriverBase`'s ctor calls `Namespace::Create`, which requires a real
/// served `fuchsia.io/Directory` for `/svc` — an EMPTY `incoming` (`vec![]`)
/// crashes the DriverServer (`EXCEPTION_KILL`) during construction. But it is not
/// enough to be merely served: DriverBase's logger ctor (`Logger::Create` ->
/// `LogConnection::Create`) does `ns.Connect<fuchsia_logger::LogSink>()` on this
/// `/svc` and then SYNC-waits (`HandleOneEvent`) for the LogSink `OnInit` event.
/// Two earlier approaches HUNG: (1) an out-of-band `DriverStartArgs.log_sink`
/// ClientEnd — the OnInit never reaches it after the LogSink zircon handle is
/// transferred through the in-process Rust->C++ fdf `Driver.Start` message; and
/// (2) an empty-but-served local vfs `/svc` — the empty dir holds the Connect
/// channel OPEN (no PEER_CLOSED), so `HandleOneEvent` waits forever.
///
/// Approach 3 hands the driver a connection to driver_manager's OWN `/svc`, which
/// is served cross-process by component_manager (which pumps independently) and has
/// `fuchsia.logger.LogSink` routed to cerise_logsink. So the driver's
/// `ns.Connect<LogSink>()` opens `/svc/fuchsia.logger.LogSink` -> component_manager
/// -> cerise_logsink, which serves THAT connection directly and sends `OnInit` to
/// the driver's OWN channel (NOT a transferred fdf handle) — `HandleOneEvent`
/// receives it, the logger initializes, and the DriverBase ctor completes. This
/// avoids both bugs (no fdf-handle transfer of a LogSink, no dependency on
/// driver_manager's executor pumping a local vfs).
///
/// `open_channel_in_namespace` is a synchronous zircon namespace open: it connects
/// `/svc` to `svc_server` immediately and returns the `/svc` Directory CLIENT
/// endpoint (a Send zircon handle), which is safe to move into the fdf
/// client-dispatcher task. No local serving task to keep alive. `PERM_READABLE`
/// (no EXECUTABLE) suffices to open a protocol within `/svc` (cf.
/// component_manager's realm_builder, which opens `/svc` with the same right).
fn cloned_svc_entry() -> Result<frunner::ComponentNamespaceEntry, Error> {
    let (svc_client, svc_server) = create_endpoints::<fio::DirectoryMarker>();
    fuchsia_fs::directory::open_channel_in_namespace("/svc", fio::PERM_READABLE, svc_server)
        .context("connecting to this process's own /svc for the driver's incoming")?;
    Ok(frunner::ComponentNamespaceEntry {
        path: Some("/svc".to_string()),
        directory: Some(svc_client),
        ..Default::default()
    })
}

/// Create a synchronized fdf dispatcher owned by `owner`, from a non-driver thread.
///
/// `fdf_dispatcher_create` requires a current driver (the dispatcher's owner) but
/// NOT a runtime-managed thread, so we push `owner` as the current driver around
/// the create call. `owner` must be a stable, distinct, process-lived pointer.
/// `allow_thread_blocking` == the spike's `kAllowSyncCalls` option.
fn create_owned_dispatcher(name: &str, owner: *const c_void) -> Result<Dispatcher, Error> {
    // SAFETY: entry/exit are balanced; `owner` outlives the dispatcher (leaked).
    unsafe { fdf_env_register_driver_entry(owner) };
    let result = DispatcherBuilder::new().name(name).allow_thread_blocking().create();
    // SAFETY: matches the entry above.
    unsafe { fdf_env_register_driver_exit() };
    result.map_err(|s| anyhow!("fdf_dispatcher_create({name}) failed: {s:?}"))
}

/// The real in-process DFv2 fdf-Driver start path (Component 5). See module docs.
pub async fn start_root_driver_dfv2(url: String) -> Result<(), Error> {
    // Make any Rust panic visible on serial: the component's stderr is not wired to
    // debuglog (stdout_to_debuglog::init fails in this minimal product), so the
    // default panic message is otherwise lost and a panic-in-an-extern-"C"-callback
    // aborts the process (-1028) with no output.
    std::panic::set_hook(Box::new(|info| {
        let s = format!("CERISE-DFv2-PANIC: {info}\n");
        // SAFETY: zx_debug_write only reads `len` bytes from `ptr`.
        unsafe { zx::sys::zx_debug_write(s.as_ptr(), s.len()) };
    }));
    mark(b"CERISE-DFv2-FDF-START\n");
    info!("Starting root driver via in-process fdf Driver transport: {url}");
    let soname = soname_for_url(&url);

    // 1. Bring up the fdf runtime env (called once, at boot, on this code path).
    // SAFETY: fdf_env_start has no soundness preconditions.
    let env_st = unsafe { fdf_env_start(0) };
    if env_st != ZX_OK {
        bail!("fdf_env_start failed: {env_st}");
    }
    mark(b"CERISE-DFv2-FDF-ENV-STARTED\n");

    // Build the driver's `incoming` `/svc` entry HERE, on the MAIN executor thread
    // (the open is a synchronous zircon namespace op; only the post_task_sync closures
    // run on fdf dispatcher threads). It is a cross-process CLONE of THIS process's own
    // routed `/svc` (served by component_manager). DriverBase's ctor calls
    // `Namespace::Create` (needs a real served `/svc`) AND its logger ctor does a SYNC
    // `ns.Connect<LogSink>()` + `HandleOneEvent` wait for `OnInit`. Cloning our own
    // `/svc` makes that connect reach cerise_logsink (LogSink routed to this
    // component: root_dfv2rt.cm offers it; driver_manager_rust_dfv2.cm uses it) directly
    // over the driver's OWN channel, so `OnInit` arrives and the ctor completes — see
    // `cloned_svc_entry`. The `/svc` Directory CLIENT endpoint is a Send zircon handle,
    // moved into the client dispatcher task below. No local serving task to keep alive
    // (component_manager pumps `/svc`), so there is nothing to leak at the end.
    let svc_entry = cloned_svc_entry()?;

    // Keep `log_sink: None`: the driver connects `fuchsia.logger.LogSink` ITSELF via
    // the cloned `/svc` (above). Supplying an out-of-band `DriverStartArgs.log_sink`
    // ClientEnd HANGS instead — the LogSink `OnInit` never reaches it after the zircon
    // handle is transferred through the in-process Rust->C++ fdf `Driver.Start` message
    // (the zircon-handle-in-fdf-message round-trip bug — see
    // project_runtime_pci_enum_step5). With `log_sink: None` the routed `/svc` clone
    // delivers `OnInit` on the driver's own connection, so the logger initializes for
    // real without any transferred fdf handle.

    // 2. Two dispatchers with DISTINCT, process-lived owners (leaked on purpose).
    let owner_driver = Box::into_raw(Box::new(0u8)) as *const c_void;
    let owner_client = Box::into_raw(Box::new(0u8)) as *const c_void;
    let driver_disp = create_owned_dispatcher("cerise-dfv2-driver", owner_driver)?;
    let client_disp = create_owned_dispatcher("cerise-dfv2-client", owner_client)?;

    // 3. fdf Driver channel pair. `server` -> the loaded driver's DriverServer;
    //    `client` -> we (the driver_manager role) drive Driver.Start.
    let (client, server) = Channel::<[u8]>::create();
    // Extract the raw fdf server-end handle; ownership transfers to the driver via
    // initialize() (it does not double-close).
    let server_raw = server.into_driver_handle().into_raw().get();

    // 4. dlopen + initialize on the DRIVER dispatcher so the DriverServer binds to
    //    it (initialize reads fdf_dispatcher_get_current_dispatcher).
    let so = CString::new(soname).context("driver soname has interior NUL")?;
    let (tx, rx) = std::sync::mpsc::channel();
    driver_disp
        .post_task_sync(move |_status| {
            // SAFETY: `so` is a valid NUL-terminated C string for the call; the C
            // loader takes ownership of the raw fdf server handle via initialize().
            let st = unsafe { cerise_load_and_init_driver(so.as_ptr(), server_raw) };
            let _ = tx.send(st);
        })
        .map_err(|s| anyhow!("posting init task failed: {s:?}"))?;
    let init_st = rx.recv().context("init task channel closed before reply")?;
    if init_st != ZX_OK {
        bail!("cerise_load_and_init_driver failed: {init_st}");
    }
    mark(b"CERISE-DFv2-INPROC-INIT-DONE\n");

    // 5. Build complete DriverStartArgs + drive Driver.Start on the CLIENT
    //    dispatcher (a different thread), so the driver dispatcher is free to
    //    process the server side. Build/encode/write all happen inside the task,
    //    so nothing fdf crosses a thread boundary except the (Send) Channel.
    let (tx2, rx2) = std::sync::mpsc::channel::<Result<(), String>>();
    client_disp
        .post_task_sync(move |_status| {
            mark(b"CERISE-DFv2-CLIENT-TASK-ENTER\n");
            let result = (|| -> Result<(), Error> {
                let arena = Arena::new();
                // Minimal-but-valid args: a real `/svc` `incoming` namespace that is a
                // cross-process CLONE of this process's own routed `/svc` (built on the
                // main executor thread above; DriverBase's `Namespace::Create` requires a
                // real served `/svc`, and its logger connects `LogSink` through this very
                // `/svc`) + a served `outgoing_dir` end. `log_sink` is None: the driver
                // connects `LogSink` itself via the cloned `/svc`, so `OnInit` arrives on
                // its own channel (an out-of-band `log_sink` ClientEnd would HANG — its
                // `OnInit` is lost across the in-process fdf `Driver.Start` handle
                // transfer). `node`/`url`/`program` are unused by the minimal driver. The
                // `/svc` Directory CLIENT endpoint is a Send handle crossing the thread
                // boundary into this task.
                let (_outgoing_client, outgoing_server) =
                    create_endpoints::<fio::DirectoryMarker>();
                let start_args = fdf_fidl::DriverStartArgs {
                    node: None,
                    incoming: Some(vec![svc_entry]),
                    outgoing_dir: Some(outgoing_server),
                    log_sink: None,
                    ..Default::default()
                };
                mark(b"CERISE-DFv2-CLIENT-ARGS-BUILT\n");
                let message =
                    fdf_fidl::DriverRequest::start_as_message(arena, start_args, 1)
                        .context("encoding Driver.Start request")?;
                mark(b"CERISE-DFv2-CLIENT-MSG-ENCODED\n");
                client
                    .write(message)
                    .map_err(|s| anyhow!("fdf Driver.Start write failed: {s:?}"))?;
                mark(b"CERISE-DFv2-CLIENT-WRITTEN\n");
                Ok(())
            })();
            let _ = tx2.send(result.map_err(|e| e.to_string()));
        })
        .map_err(|s| anyhow!("posting Driver.Start task failed: {s:?}"))?;
    rx2.recv()
        .context("Driver.Start task channel closed before reply")?
        .map_err(|e| anyhow!("Driver.Start failed: {e}"))?;
    mark(b"CERISE-DFv2-FDF-START-SENT\n");

    // 6. Keep both dispatchers alive for the process lifetime. The driver
    //    dispatcher will now asynchronously process the Start message ->
    //    DriverServer -> MinimalDriver::Start() -> CERISE-DFV2-DRIVER-OK.
    std::mem::forget(driver_disp);
    std::mem::forget(client_disp);
    // Nothing else to keep alive: the driver's `/svc` is served cross-process by
    // component_manager (we only handed the driver a CLIENT endpoint connected to it),
    // so it keeps responding after this fn returns and the driver (on the driver
    // dispatcher) connects to it asynchronously — no local vfs task to leak.
    info!("In-process DFv2 driver loaded; Start dispatched over fdf transport");
    Ok(())
}

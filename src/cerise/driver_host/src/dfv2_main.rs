// Driver-host bring-up, Step 0: FAITHFUL separate-process DFv2 driver host.
//
// This is the REAL driver_host process for Branch A (a faithful separate
// driver_host process), as opposed to the earlier ACK-only stub (`src/main.rs`) that only ACKs
// `DriverHost.Start` and dlopens nothing.
//
// ARCHITECTURAL BASIS (settled empirically during driver-host bring-up): there is NO cross-process
// fdf transfer in the upstream dm<->driver_host control path. The premise that
// `DriverHost.Start` carries an fdf-transport `Driver` server end is incorrect:
//
//   * `fuchsia.driver.host/Driver` (driver_host.fidl:27) is a *zircon*-transport
//     protocol (no `@transport`) — just `Stop()`. This is the `driver server_end`
//     that `DriverHost.Start` carries across the process boundary.
//   * `fuchsia.driver.framework/Driver` (driver.fidl:16, `@transport("Driver")`) is
//     the *fdf*-transport protocol the driver actually serves (Start/Stop/...). Its
//     connection is established LOCALLY inside this driver host via the
//     `DriverRegistration` ABI (sdk/lib/driver/symbols/symbols.h:35-40:
//     `initialize(fdf_handle_t server_handle)` where `server_handle` is "the server
//     end for the fuchsia.driver.framework/Driver protocol").
//
// So a faithful separate driver host does EXACTLY the same local fdf dance that the
// in-process Component-5 path (driver_manager_rust/src/fdf_start.rs) proved — only
// it runs in THIS separate process. The fdf runtime, dispatchers, and Driver channel
// pair are all process-local to this driver host; nothing fdf crosses to the caller.
//
// On `DriverHost.Start(start_args, driver /*zircon Driver(host)*, host_name)`:
//   1. bring up the fdf runtime env (once),
//   2. create two synchronized fdf dispatchers with distinct owners (driver + client),
//   3. create the fdf `fuchsia.driver.framework/Driver` channel pair LOCALLY,
//   4. on the DRIVER dispatcher, dlopen the driver .so + `initialize(server_handle)`
//      via the proven C++ loader FFI (//src/cerise/dfv2_inproc_loader),
//   5. on the CLIENT dispatcher, re-encode the RECEIVED `DriverStartArgs` (already a
//      `fuchsia.driver.framework/DriverStartArgs`) into an fdf `Driver.Start` message
//      and write it — forwarding the caller-supplied `incoming` namespace (which must
//      carry a working `/svc` with `fuchsia.logger.LogSink`, so the driver's
//      `DriverBase` logger ctor does not hang; the harness clones its own routed
//      `/svc` into it and sets `log_sink: None`),
//   6. decode the flexible Driver.Start result and emit `CERISE-DH-XPROC-FDF-OK` only
//      for its success arm,
//   7. on success, retain the client and both dispatcher-owner identities (the driver dispatcher then runs
//      DriverServer -> MinimalDriver::Start() -> `CERISE-DFV2-DRIVER-OK` IN THIS
//      PROCESS — the definitive cross-process proof); on application error, tear
//      everything down without forwarding Stop,
//   8. serve the zircon `fuchsia.driver.host/Driver` lifecycle, forward Stop exactly once,
//      shut down the exact dispatcher owners, and destroy the exact registration token.

use anyhow::{Context, Error, anyhow, bail};
use core::ffi::{c_char, c_void};
use fdf::{
    Arena, AsyncDispatcher, Channel, CurrentDispatcher, Dispatcher, DispatcherBuilder,
    DispatcherRef, OnDispatcher,
};
use fidl::endpoints::ControlHandle;
use fidl_fuchsia_data as fdata;
use fidl_fuchsia_driver_framework as fdf_fidl;
use fidl_fuchsia_driver_host as fdh;
use fuchsia_component::server::ServiceFs;
use futures::prelude::*;
use libasync::DispatcherTimerExt;
use std::ffi::CString;
use std::sync::Once;

// The C++ in-process loader (//src/cerise/dfv2_inproc_loader): dlopen the driver
// .so, resolve `__fuchsia_driver_registration__`, call `v1.initialize(server)` on the
// CURRENT fdf dispatcher. Identical FFI used by the proven in-process path.
unsafe extern "C" {
    fn cerise_load_and_init_driver_with_token(
        so_path: *const c_char,
        server_handle: u32,
        out_driver: *mut *mut c_void,
    ) -> i32;
    fn cerise_destroy_driver(driver: *mut c_void);
}

// driver-host Step 3 — the compat MODULE loader (//src/cerise/dfv2_inproc_loader): dlopen a
// LEGACY (DFv1) driver .so as an additional module alongside the already-loaded
// compat.so, and return the addresses of its `__zircon_driver_note__` /
// `__zircon_driver_rec__` symbols. MUST be called AFTER cerise_load_and_init_driver
// has dlopen'd compat.so RTLD_GLOBAL (so the legacy .so's UND DFv1 ABI symbols resolve
// against compat.so). The returned addresses are populated into DriverStartArgs.symbols.
unsafe extern "C" {
    fn cerise_load_compat_module(
        legacy_so_path: *const c_char,
        out_note_addr: *mut u64,
        out_rec_addr: *mut u64,
    ) -> i32;
}

// Raw fdf runtime env hooks (the safe fdf crate does not re-export these).
unsafe extern "C" {
    fn fdf_env_start(options: u32) -> i32;
    fn fdf_env_register_driver_entry(driver: *const c_void);
    fn fdf_env_register_driver_exit();
    fn fdf_handle_close(handle: u32);
    fn fdf_env_shutdown_dispatchers_async(
        driver: *const c_void,
        observer: *mut EnvDriverShutdownObserver,
    ) -> i32;
}

const ZX_OK: i32 = 0;
const DRIVER_START_TX_ID: u32 = 1;
const DRIVER_START_ORDINAL: u64 = 0x27be00ae42aa60c2;

type DriverStartWireResult =
    fidl::encoding::FlexibleResultType<fidl::encoding::EmptyStruct, i32>;

#[derive(Debug)]
struct DriverStartApplicationError(i32);

impl std::fmt::Display for DriverStartApplicationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "Driver.Start returned application status {}", self.0)
    }
}

impl std::error::Error for DriverStartApplicationError {}

#[repr(C)]
struct EnvDriverShutdownObserver {
    handler: Option<
        unsafe extern "C" fn(driver: *const c_void, observer: *mut EnvDriverShutdownObserver),
    >,
}

#[repr(C)]
struct DriverShutdownWaiter {
    observer: EnvDriverShutdownObserver,
    done: Option<std::sync::mpsc::Sender<()>>,
}

unsafe extern "C" fn driver_shutdown_complete(
    _driver: *const c_void,
    observer: *mut EnvDriverShutdownObserver,
) {
    // SAFETY: shutdown_driver_dispatchers allocated this exact observer and the
    // runtime invokes its handler once after all dispatchers for the owner have
    // finished their own shutdown callbacks.
    let mut observer = unsafe { Box::from_raw(observer.cast::<DriverShutdownWaiter>()) };
    if let Some(done) = observer.done.take() {
        let _ = done.send(());
    }
}

fn shutdown_driver_dispatchers(owner: *const c_void) -> Result<(), Error> {
    let (done, finished) = std::sync::mpsc::channel();
    let observer = Box::new(DriverShutdownWaiter {
        observer: EnvDriverShutdownObserver {
            handler: Some(driver_shutdown_complete),
        },
        done: Some(done),
    });
    let observer = Box::into_raw(observer);
    // SAFETY: owner uniquely identifies a live dispatcher set, and observer is
    // stable until the one-shot callback reconstructs and drops its Box.
    let status = unsafe {
        fdf_env_shutdown_dispatchers_async(owner, observer.cast::<EnvDriverShutdownObserver>())
    };
    if status != ZX_OK {
        // SAFETY: a failed registration promises not to retain the observer.
        drop(unsafe { Box::from_raw(observer) });
        bail!("fdf_env_shutdown_dispatchers_async failed: {status}");
    }
    finished
        .recv()
        .context("driver dispatcher shutdown callback was dropped")
}

struct DriverIdentity {
    // These unowned references keep the exact dispatchers addressable while
    // running. Their environment shutdown observers destroy the dispatchers.
    _driver_dispatcher: DispatcherRef<'static>,
    client_dispatcher: DispatcherRef<'static>,
    driver_owner: *const c_void,
    client_owner: *const c_void,
    registration: Option<*mut c_void>,
}

impl DriverIdentity {
    fn teardown(self) -> Result<(), Error> {
        let DriverIdentity {
            _driver_dispatcher: _,
            client_dispatcher,
            driver_owner,
            client_owner,
            registration,
        } = self;
        drop(client_dispatcher);
        shutdown_driver_dispatchers(client_owner)?;
        shutdown_driver_dispatchers(driver_owner)?;
        // SAFETY: both owner shutdown callbacks have completed and registration
        // is the exact opaque identity returned for this driver instance.
        if let Some(registration) = registration {
            unsafe { cerise_destroy_driver(registration) };
        }
        // SAFETY: owners were allocated by Box::into_raw and no dispatcher can
        // refer to them after the completed environment shutdown callbacks.
        drop(unsafe { Box::from_raw(client_owner.cast_mut().cast::<u8>()) });
        drop(unsafe { Box::from_raw(driver_owner.cast_mut().cast::<u8>()) });
        Ok(())
    }
}

struct StartedDriver {
    client: Channel<[u8]>,
    identity: DriverIdentity,
}

impl StartedDriver {
    fn teardown(self) -> Result<(), Error> {
        let StartedDriver { client, identity } = self;
        drop(client);
        identity.teardown()
    }

    fn stop(self) -> Result<(), Error> {
        let StartedDriver {
            mut client,
            identity,
        } = self;

        // Send exactly one one-way framework Stop and wait until DriverServer has
        // completed PrepareStop and closed its binding. The client dispatcher is
        // distinct from the driver's owner, so this wait cannot prevent the driver
        // dispatcher from handling Stop.
        let (done, finished) = std::sync::mpsc::channel::<Result<(), String>>();
        let post_result = identity
            .client_dispatcher
            .spawn(async move {
                let result = async {
                    let arena = Arena::new();
                    let message = fdf_fidl::DriverRequest::stop_as_message(arena)
                        .context("encoding Driver.Stop request")?;
                    client
                        .write(message)
                        .map_err(|s| anyhow!("fdf Driver.Stop write failed: {s:?}"))?;
                    let close = client.read_bytes(CurrentDispatcher).fuse();
                    let timeout = CurrentDispatcher
                        .after_deadline(zx::MonotonicInstant::after(
                            zx::MonotonicDuration::from_seconds(30),
                        ))
                        .fuse();
                    futures::pin_mut!(close, timeout);
                    futures::select! {
                        result = close => match result {
                            Err(zx::Status::PEER_CLOSED) => Ok(()),
                            Ok(Some(_)) => Err(anyhow!("unexpected Driver message after Stop")),
                            Ok(None) => Err(anyhow!("Driver channel closed without PEER_CLOSED")),
                            Err(status) => Err(anyhow!("fdf Driver.Stop close wait failed: {status:?}")),
                        },
                        timer = timeout => {
                            timer.context("Driver.Stop timeout task failed")?;
                            Err(anyhow!("fdf Driver peer did not close after Stop"))
                        }
                    }
                }
                .await;
                let _ = done.send(result.map_err(|e| e.to_string()));
            });
        if let Err(status) = post_result {
            let teardown = identity.teardown();
            teardown.context("tearing down after undelivered Driver.Stop")?;
            return Err(anyhow!("posting Driver.Stop task failed: {status:?}"));
        }
        let stop_result = finished
            .recv()
            .context("Driver.Stop task channel closed")
            .and_then(|result| result.map_err(|e| anyhow!(e)));

        // DispatcherRefs are unowned: these environment callbacks perform the one
        // authoritative shutdown. Destroy may run only after the entire driver
        // owner (default plus driver-created dispatchers) has finished shutdown.
        let teardown_result = identity.teardown();
        stop_result?;
        teardown_result
    }
}

fn mark(msg: &[u8]) {
    // SAFETY: zx_debug_write only reads `len` bytes from `ptr`.
    unsafe {
        zx::sys::zx_debug_write(msg.as_ptr(), msg.len());
    }
}

fn exit_after_driver_start_timeout() -> ! {
    // Driver.Start is executing on the driver-owned dispatcher. If it misses
    // the hard reply deadline, waiting for that same dispatcher to shut down
    // can never be a bounded recovery path. This process is the isolation
    // boundary: exiting closes DriverHost immediately and lets the kernel
    // reclaim every dispatcher, registration, channel, and driver resource.
    mark(b"CERISE-DH-XPROC-FDF-TIMEOUT-EXIT\n");
    std::process::exit(1)
}

/// Decode the exact flexible two-way response to fuchsia.driver.framework/Driver.Start.
///
/// The driver-transport bindings expose request encoding but no client proxy, so this is
/// the response-side counterpart of generated `DriverRequest::start_as_message`. A reply
/// is not itself success: the flexible result has distinct success, application-error,
/// and framework-error arms.
fn decode_driver_start_reply(
    mut message: fdf::Message<[u8]>,
) -> Result<Result<(), i32>, Error> {
    let (_arena, Some(body), handles) = message.take_arena_boxes() else {
        bail!("Driver.Start reply has no body");
    };
    if handles.as_ref().is_some_and(|handles| !handles.is_empty()) {
        bail!("Driver.Start reply unexpectedly carried handles");
    }
    let (header, body_bytes) = fidl::encoding::decode_transaction_header(&body)
        .context("decoding Driver.Start reply header")?;
    if header.tx_id != DRIVER_START_TX_ID {
        bail!(
            "Driver.Start reply txid {}, expected {}",
            header.tx_id,
            DRIVER_START_TX_ID
        );
    }
    if header.ordinal != DRIVER_START_ORDINAL {
        bail!(
            "Driver.Start reply ordinal {:#x}, expected {:#x}",
            header.ordinal,
            DRIVER_START_ORDINAL
        );
    }
    if !header
        .dynamic_flags()
        .contains(fidl::encoding::DynamicFlags::FLEXIBLE)
    {
        bail!("Driver.Start reply is missing the flexible-method flag");
    }

    let mut result = fidl::new_empty!(
        DriverStartWireResult,
        fidl::encoding::DefaultFuchsiaResourceDialect
    );
    fidl::encoding::Decoder::<fidl::encoding::DefaultFuchsiaResourceDialect>::decode_into::<
        DriverStartWireResult,
    >(&header, body_bytes, &mut [], &mut result)
    .context("decoding Driver.Start flexible result")?;
    match result {
        fidl::encoding::FlexibleResult::Ok(()) => Ok(Ok(())),
        fidl::encoding::FlexibleResult::DomainErr(status) => Ok(Err(status)),
        fidl::encoding::FlexibleResult::FrameworkErr(error) => Ok(Err(error as i32)),
    }
}

static FDF_ENV: Once = Once::new();
static mut FDF_ENV_OK: bool = false;

/// Bring up the fdf runtime env exactly once for the process.
fn ensure_fdf_env() -> Result<(), Error> {
    FDF_ENV.call_once(|| {
        // SAFETY: fdf_env_start has no soundness preconditions.
        let st = unsafe { fdf_env_start(0) };
        // SAFETY: single-threaded init under Once; no concurrent access.
        unsafe { FDF_ENV_OK = st == ZX_OK };
    });
    // SAFETY: written under Once above; read after call_once completes.
    if unsafe { FDF_ENV_OK } {
        Ok(())
    } else {
        bail!("fdf_env_start failed")
    }
}

/// Create a synchronized fdf dispatcher owned by `owner`, from a non-driver thread.
/// Mirrors driver_manager_rust/src/fdf_start.rs::create_owned_dispatcher.
fn create_owned_dispatcher(name: &str, owner: *const c_void) -> Result<Dispatcher, Error> {
    // SAFETY: entry/exit are balanced; `owner` outlives the dispatcher (leaked).
    unsafe { fdf_env_register_driver_entry(owner) };
    let result = DispatcherBuilder::new()
        .name(name)
        .allow_thread_blocking()
        .create();
    // SAFETY: matches the entry above.
    unsafe { fdf_env_register_driver_exit() };
    result.map_err(|s| anyhow!("fdf_dispatcher_create({name}) failed: {s:?}"))
}

/// Derive the package-relative driver soname to dlopen from the DriverStartArgs this
/// host received over DriverHost.Start. driver_manager builds the FIDL DriverStartArgs
/// with `program: start_info.program` (driver_host crate, driver_host.rs), i.e. it
/// forwards the driver component's `program` dict verbatim — so the .so to load is the
/// basename of program["binary"] (the loader service resolves that soname from THIS
/// host package's /pkg/lib). This is the driver-host Step 2 fix for the previous hardcode: with
/// multiple drivers (parent + child) each driver host must load the .so named in ITS
/// own start_args, not a constant. Falls back to the minimal driver (the x64-dfv2-real
/// root, whose minimal_driver.cm has an empty program) when no binary is named.
fn program_str<'a>(prog: &'a fdata::Dictionary, key: &str) -> Option<&'a str> {
    prog.entries
        .as_ref()?
        .iter()
        .find(|e| e.key == key)
        .and_then(|e| match e.value.as_deref() {
            Some(fdata::DictionaryValue::Str(s)) => Some(s.as_str()),
            _ => None,
        })
}

/// Read a string-valued entry from `start_args.program`, if present.
fn program_value(start_args: &fdf_fidl::DriverStartArgs, key: &str) -> Option<String> {
    start_args
        .program
        .as_ref()
        .and_then(|p| program_str(p, key))
        .map(|s| s.to_string())
}

fn soname_for(start_args: &fdf_fidl::DriverStartArgs) -> String {
    match program_value(start_args, "binary") {
        Some(binary) => binary.rsplit('/').next().unwrap_or(&binary).to_string(),
        None => "cerise_minimal_driver.so".to_string(),
    }
}

/// driver-host Step 3 — load the LEGACY DFv1 .so named by `compat_path` (the program.compat
/// value, e.g. "driver/cerise_compat_legacy.so") as a sibling ELF module of the
/// already-loaded compat.so, and append its `__zircon_driver_note__` /
/// `__zircon_driver_rec__` addresses into `start_args.symbols`. The NodeSymbol
/// `module_name` is the package-relative `compat_path` verbatim, which is exactly what
/// compat computes (driver_path_ == "/pkg/" + compat, looked up minus the "/pkg/"
/// prefix). The .so is dlopen'd by soname (its basename), resolved from the driver
/// host's own /pkg/lib via the framework loader service.
fn load_compat_module(
    start_args: &mut fdf_fidl::DriverStartArgs,
    compat_path: &str,
) -> Result<(), Error> {
    let soname = compat_path.rsplit('/').next().unwrap_or(compat_path);
    let so = CString::new(soname).context("compat module soname has interior NUL")?;
    let mut note_addr: u64 = 0;
    let mut rec_addr: u64 = 0;
    // SAFETY: `so` is a valid NUL-terminated C string; out pointers are valid for the
    // call. compat.so was dlopen'd RTLD_GLOBAL by cerise_load_and_init_driver above,
    // so the legacy .so's UND DFv1 ABI symbols resolve at load.
    let st = unsafe { cerise_load_compat_module(so.as_ptr(), &mut note_addr, &mut rec_addr) };
    if st != ZX_OK {
        bail!("cerise_load_compat_module({soname}) failed: {st}");
    }
    let symbols = start_args.symbols.get_or_insert_with(Vec::new);
    symbols.push(fdf_fidl::NodeSymbol {
        name: Some("__zircon_driver_note__".to_string()),
        address: Some(note_addr),
        module_name: Some(compat_path.to_string()),
        ..Default::default()
    });
    symbols.push(fdf_fidl::NodeSymbol {
        name: Some("__zircon_driver_rec__".to_string()),
        address: Some(rec_addr),
        module_name: Some(compat_path.to_string()),
        ..Default::default()
    });
    Ok(())
}

/// Perform the faithful local fdf Driver round-trip for a single driver in THIS
/// driver host process. The returned owner retains the process-local Driver
/// client and exact dispatcher/registration identities until zircon Driver.Stop.
fn start_driver_locally(mut start_args: fdf_fidl::DriverStartArgs) -> Result<StartedDriver, Error> {
    ensure_fdf_env()?;

    let soname = soname_for(&start_args);
    let so = CString::new(soname).context("driver soname has interior NUL")?;

    // Two dispatchers with distinct per-instance owners. The
    // DriverServer binds to `driver_disp`; we drive Driver.Start on `client_disp`.
    // Same-owner ends can trip fdf reentrancy and silently fail to deliver.
    let owner_driver = Box::into_raw(Box::new(0u8)) as *const c_void;
    let owner_client = Box::into_raw(Box::new(0u8)) as *const c_void;
    let driver_disp = match create_owned_dispatcher("cerise-dh-xproc-driver", owner_driver) {
        Ok(dispatcher) => dispatcher,
        Err(error) => {
            // SAFETY: neither owner is registered with a live dispatcher.
            drop(unsafe { Box::from_raw(owner_client.cast_mut().cast::<u8>()) });
            drop(unsafe { Box::from_raw(owner_driver.cast_mut().cast::<u8>()) });
            return Err(error);
        }
    };
    let client_disp = match create_owned_dispatcher("cerise-dh-xproc-client", owner_client) {
        Ok(dispatcher) => dispatcher,
        Err(error) => {
            let _driver_dispatcher = driver_disp.release();
            shutdown_driver_dispatchers(owner_driver)
                .context("tearing down driver dispatcher after client creation failed")?;
            // SAFETY: client_owner was never registered; driver_owner shutdown completed.
            drop(unsafe { Box::from_raw(owner_client.cast_mut().cast::<u8>()) });
            drop(unsafe { Box::from_raw(owner_driver.cast_mut().cast::<u8>()) });
            return Err(error);
        }
    };
    let mut identity = DriverIdentity {
        _driver_dispatcher: driver_disp.release(),
        client_dispatcher: client_disp.release(),
        driver_owner: owner_driver,
        client_owner: owner_client,
        registration: None,
    };

    // fdf Driver channel pair. `server` -> the loaded driver's DriverServer (via
    // initialize); `client` -> we (the driver-host role) drive Driver.Start.
    let (mut client, server) = Channel::<[u8]>::create();
    let server_raw = server.into_driver_handle().into_raw().get();

    // dlopen + initialize on the DRIVER dispatcher so the DriverServer binds to it
    // (initialize reads fdf_dispatcher_get_current_dispatcher()).
    let (tx, rx) = std::sync::mpsc::channel::<(i32, usize)>();
    let init_post = identity._driver_dispatcher.post_task_sync(move |_status| {
        // SAFETY: `so` is a valid NUL-terminated C string; the C loader takes
        // ownership of the raw fdf server handle via initialize().
        let mut registration = std::ptr::null_mut();
        let st = unsafe {
            cerise_load_and_init_driver_with_token(so.as_ptr(), server_raw, &mut registration)
        };
        let _ = tx.send((st, registration as usize));
    });
    if let Err(status) = init_post {
        // SAFETY: initialize never received the raw server handle.
        unsafe { fdf_handle_close(server_raw) };
        identity
            .teardown()
            .context("tearing down undelivered initialization")?;
        return Err(anyhow!("posting init task failed: {status:?}"));
    }
    let (init_st, registration) = match rx.recv() {
        Ok(result) => result,
        Err(error) => {
            identity
                .teardown()
                .context("tearing down failed initialization")?;
            return Err(error).context("init task channel closed before reply");
        }
    };
    if init_st != ZX_OK {
        identity
            .teardown()
            .context("tearing down failed initialization")?;
        bail!("cerise_load_and_init_driver_with_token failed: {init_st}");
    }
    identity.registration = Some(registration as *mut c_void);

    // driver-host Step 3 — detect whether this is a compat driver BEFORE moving start_args.
    // The actual module load (cerise_load_compat_module / dlopen) runs INSIDE the
    // client_disp FDF task below (on the FDF dispatcher thread) so that the dlopen
    // runs in a context where the FDF runtime is fully initialised.
    //
    // NOTE on the earlier "async_get_default_dispatcher() is NULL on FDF thread" theory:
    // that was incorrect — FDF dispatcher threads DO attach an async loop and therefore
    // DO have a non-null async_get_default_dispatcher(). Moreover, the syslog library
    // is compiled at API level 30 where the api-level-<29 LogState::Connect / missing-
    // dispatcher bypass path doesn't exist.  The real fix for the dlopen hang is that
    // driver_host_dfv2.cm now uses fuchsia.logger.LogSink (offered by driver_manager)
    // so the process FDIO namespace carries /svc/fuchsia.logger.LogSink and the
    // level-30 LogConnection::Create → HandleOneEvent → OnInit round-trip completes
    // instead of blocking on a missing server.  Mirrors upstream driver_host2.cml which
    // includes syslog/client.shard.cml.
    let compat_path_opt: Option<String> = program_value(&start_args, "compat");
    let is_compat = compat_path_opt.is_some();

    // Re-encode the RECEIVED DriverStartArgs into an fdf Driver.Start message, write
    // it, and AWAIT THE REPLY on the CLIENT dispatcher. The args are forwarded
    // verbatim: the caller (harness) supplies a real `/svc` `incoming` (clone of its
    // own routed `/svc`, with LogSink) and `log_sink: None`, so the driver's
    // DriverBase logger ctor connects LogSink over that `/svc` and its `OnInit`
    // arrives on the driver's own channel (the proven approach; an out-of-band
    // `log_sink` ClientEnd would HANG).
    //
    // We emit `CERISE-DH-XPROC-FDF-OK` only AFTER the Driver.Start REPLY lands on
    // the client channel — i.e. after the driver's DriverServer (running on the driver
    // dispatcher in THIS process) actually processed Start and replied. Emitting it
    // merely after `write()` would be a false success: the write succeeds even if the
    // driver's Start later hangs (the known DriverBase-logger-OnInit failure mode).
    // The reply is awaited through the driver-runtime channel future. This leaves
    // the client dispatcher available to service runtime callbacks while Start is
    // pending; a dispatcher-native deadline bounds the wait without sleep polling.
    let (tx2, rx2) =
        std::sync::mpsc::channel::<(Result<Option<Result<(), i32>>, String>, Channel<[u8]>)>();
    let post_result = identity.client_dispatcher.spawn(async move {
        // driver-host Step 3 — compat MODULE load on THIS fdf dispatcher thread.
        // NOTE: the &mut borrow of start_args ends before the IIFE below moves it.
        if let Some(ref compat_path) = compat_path_opt {
            match load_compat_module(&mut start_args, compat_path) {
                Err(e) => {
                    let _ = tx2.send((Err(e.to_string()), client));
                    return;
                }
                Ok(()) => {}
            }
        }
        // start_args is fully owned again (borrow from if-let above has ended).
        let result = async {
            let arena = Arena::new();
            let message = fdf_fidl::DriverRequest::start_as_message(
                arena,
                start_args,
                DRIVER_START_TX_ID,
            )
            .context("encoding Driver.Start request")?;
            client
                .write(message)
                .map_err(|s| anyhow!("fdf Driver.Start write failed: {s:?}"))?;
            let reply = client.read_bytes(CurrentDispatcher).fuse();
            let timeout = CurrentDispatcher
                .after_deadline(zx::MonotonicInstant::after(
                    zx::MonotonicDuration::from_seconds(30),
                ))
                .fuse();
            futures::pin_mut!(reply, timeout);
            futures::select! {
                result = reply => match result {
                    Ok(Some(reply)) => decode_driver_start_reply(reply).map(Some),
                    Ok(None) => Err(anyhow!("Driver.Start channel closed without a reply")),
                    Err(status) => {
                        Err(anyhow!("fdf Driver.Start reply read failed: {status:?}"))
                    }
                },
                timer = timeout => {
                    timer.context("Driver.Start timeout task failed")?;
                    Ok(None)
                }
            }
        }
        .await;
        let _ = tx2.send((result.map_err(|e| e.to_string()), client));
    });
    if let Err(status) = post_result {
        identity
            .teardown()
            .context("tearing down undelivered Driver.Start")?;
        return Err(anyhow!("posting Driver.Start task failed: {status:?}"));
    }
    let (got_reply, client) = match rx2.recv() {
        Ok(result) => result,
        Err(error) => {
            identity
                .teardown()
                .context("tearing down abandoned Driver.Start")?;
            return Err(error).context("Driver.Start task channel closed before reply");
        }
    };
    let start_reply = match got_reply {
        Ok(result) => result,
        Err(error) => {
            drop(client);
            identity
                .teardown()
                .context("tearing down failed Driver.Start")?;
            return Err(anyhow!("Driver.Start failed: {error}"));
        }
    };

    let Some(start_reply) = start_reply else {
        // Start was dispatched but no reply arrived in time (e.g. the driver's Start
        // hung). Do not claim success and do not synchronously wait behind that
        // same stuck dispatcher. Fail-stop this isolated host; driver_manager sees
        // peer closure and the kernel performs bounded process resource cleanup.
        mark(b"CERISE-DH-XPROC-FDF-NO-REPLY\n");
        drop(client);
        exit_after_driver_start_timeout();
    };
    if let Err(status) = start_reply {
        let message = format!("CERISE-DH-XPROC-FDF-APP-ERR: {status}\n");
        mark(message.as_bytes());
        drop(client);
        // Driver.Start failed, so the framework contract forbids forwarding Stop.
        // Shut down the exact dispatcher owners and destroy the registration now.
        // Preserve the driver's exact application status even if best-effort cleanup
        // itself reports a secondary error.
        if let Err(error) = identity.teardown() {
            let message = format!("CERISE-DH-XPROC-START-TEARDOWN-ERR: {error}\n");
            mark(message.as_bytes());
        }
        return Err(DriverStartApplicationError(status).into());
    }
    // Cross-process proof: the driver was dlopen'd + initialized + Start-driven +
    // REPLIED entirely within THIS separate driver host process. The driver's own
    // `CERISE-DFV2-DRIVER-OK` (from MinimalDriver::Start) corroborates.
    mark(b"CERISE-DH-XPROC-FDF-OK\n");
    // Queue a sentinel after decoding the reply. Its execution proves that the
    // driver's dispatcher remains able to run work after Driver.Start completes.
    if let Err(status) = identity._driver_dispatcher.spawn(async {
        mark(b"CERISE-DH-XPROC-POST-REPLY-DRIVER-DISPATCHER\n");
    }) {
        let message =
            format!("CERISE-DH-XPROC-POST-REPLY-DRIVER-DISPATCHER-POST-ERR: {status:?}\n");
        mark(message.as_bytes());
    }
    // driver-host Step 3 — corroborating marker for the compat path: the compat shim's
    // Driver.Start (which loads the legacy module's note/rec from the symbols we
    // populated and runs its bind hook via record_->ops->bind) was driven and replied.
    // NOTE: the AUTHORITATIVE proof that the legacy bind ran THROUGH compat is the
    // legacy driver's own CERISE-COMPAT-LEGACY-OK (emitted from its bind hook);
    // compat replies to Start via an async InitReply path decoupled from bind, so this
    // marker corroborates the round-trip rather than proving device_add surfaced.
    if is_compat {
        mark(b"CERISE-COMPAT-OK\n");
    }
    Ok(StartedDriver { client, identity })
}

#[fuchsia::main(logging = false)]
async fn main() {
    std::panic::set_hook(Box::new(|info| {
        let s = format!("CERISE-DH-XPROC-PANIC: {info}\n");
        // SAFETY: zx_debug_write only reads `len` bytes from `ptr`.
        unsafe { zx::sys::zx_debug_write(s.as_ptr(), s.len()) };
    }));
    mark(b"CERISE-DH-XPROC-HOST-START\n");

    let mut fs = ServiceFs::new_local();
    fs.dir("svc")
        .add_fidl_service(|s: fdh::DriverHostRequestStream| s);
    fs.take_and_serve_directory_handle().unwrap();
    fs.for_each_concurrent(None, |stream| handle_driver_host(stream))
        .await;
}

async fn handle_driver_host(mut stream: fdh::DriverHostRequestStream) {
    while let Ok(Some(req)) = stream.try_next().await {
        match req {
            fdh::DriverHostRequest::Start {
                start_args,
                driver,
                responder,
                ..
            } => {
                mark(b"CERISE-DH-XPROC-START-RECEIVED\n");
                match start_driver_locally(start_args) {
                    Ok(started_driver) => {
                        let _ = responder.send(Ok(()));
                        // Serve the zircon fuchsia.driver.host/Driver lifecycle as an
                        // INDEPENDENT task so the DriverHostRequestStream loop is NOT
                        // blocked. Colocated drivers (e.g. platform-bus-x86 colocated
                        // in platform-bus's driver_host) send a SECOND DriverHost.Start
                        // on this same channel; blocking in the lifecycle loop would
                        // starve that request and leave it unfinished (deadline exceeded).
                        // Each driver gets its own lifecycle task and all coexist in this
                        // process for the process lifetime.
                        fuchsia_async::Task::local(async move {
                            let mut driver_stream = driver.into_stream();
                            match driver_stream.try_next().await {
                                Ok(Some(fdh::DriverRequest::Stop { control_handle })) => {
                                    let status = match started_driver.stop() {
                                        Ok(()) => zx::Status::OK,
                                        Err(error) => {
                                            let message =
                                                format!("CERISE-DH-XPROC-STOP-ERR: {error}\n");
                                            mark(message.as_bytes());
                                            zx::Status::INTERNAL
                                        }
                                    };
                                    control_handle.shutdown_with_epitaph(status);
                                }
                                lifecycle_end => {
                                    let reason = format!(
                                        "CERISE-DH-XPROC-LIFECYCLE-CLOSED: {lifecycle_end:?}\n"
                                    );
                                    mark(reason.as_bytes());
                                    if let Err(error) = started_driver.teardown() {
                                        let message =
                                            format!("CERISE-DH-XPROC-STOP-ERR: {error}\n");
                                        mark(message.as_bytes());
                                    }
                                }
                            }
                        })
                        .detach();
                    }
                    Err(e) => {
                        let s = format!("CERISE-DH-XPROC-START-ERR: {e}\n");
                        mark(s.as_bytes());
                        let status = e
                            .downcast_ref::<DriverStartApplicationError>()
                            .map(|error| error.0)
                            .unwrap_or_else(|| zx::Status::INTERNAL.into_raw());
                        let _ = responder.send(Err(status));
                        // `continue` to the next request; `driver` is dropped here,
                        // closing the server end — the driver was not started.
                        continue;
                    }
                }
            }
            fdh::DriverHostRequest::StartLoadedDriver {
                driver, responder, ..
            } => {
                drop(driver);
                let _ = responder.send(Err(zx::Status::NOT_SUPPORTED.into_raw()));
            }
            fdh::DriverHostRequest::GetProcessInfo { responder } => {
                let _ = responder.send(Err(zx::Status::NOT_SUPPORTED.into_raw()));
            }
            fdh::DriverHostRequest::InstallLoader { .. } => {}
            fdh::DriverHostRequest::TriggerStackTrace { .. } => {}
            fdh::DriverHostRequest::FindDriverCrashInfoByThreadKoid { responder, .. } => {
                let _ = responder.send(Err(zx::Status::NOT_FOUND.into_raw()));
            }
        }
    }
}

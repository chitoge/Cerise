// Driver-host bring-up, Step 0: minimal faithful caller for the separate-process DFv2 driver
// host test. Stands in for driver_manager's create_driver_host + DriverHost.Start,
// without pulling in the full driver_runner topology engine (a "minimal faithful
// equivalent", per the driver-host Step 0 plan).
//
// This process is DISTINCT from the driver host process. It:
//   1. clones its OWN routed `/svc` (which has fuchsia.logger.LogSink routed from
//      cerise_logsink) into a Directory client end,
//   2. opens its static child `driver_host`'s exposed dir and connects to
//      `fuchsia.driver.host/DriverHost`,
//   3. calls `DriverHost.Start(start_args, driver_server, "xproc")` over ZIRCON,
//      where `start_args.incoming` carries the cloned `/svc` (so the driver's
//      DriverBase logger ctor can connect LogSink and its OnInit arrives) and
//      `log_sink: None` (an out-of-band log_sink ClientEnd loses its OnInit across
//      the fdf Driver.Start handle transfer — the proven in-process finding).
//
// The driver_host process then dlopens + initializes + Start-runs the driver IN ITS
// OWN PROCESS. The driver's `CERISE-DFV2-DRIVER-OK` (from MinimalDriver::Start)
// appearing proves cross-process operation; the host emits `CERISE-DH-XPROC-FDF-OK`.

use fidl::endpoints::{ClientEnd, ServerEnd, create_endpoints};
use fidl_cerise_echo as echo;
use fidl_fuchsia_component_runner as frunner;
use fidl_fuchsia_data as fdata;
use fidl_fuchsia_driver_framework as fdf_fidl;
use fidl_fuchsia_driver_host as fdh;
use fidl_fuchsia_io as fio;
use fuchsia_component::client::connect_to_childs_protocol;
use futures::TryStreamExt;

fn mark(msg: &[u8]) {
    // SAFETY: zx_debug_write only reads `len` bytes from `ptr`.
    unsafe {
        zx::sys::zx_debug_write(msg.as_ptr(), msg.len());
    }
}

#[fuchsia::main(logging = false)]
async fn main() {
    std::panic::set_hook(Box::new(|info| {
        let s = format!("CERISE-DH-XPROC-HARNESS-PANIC: {info}\n");
        // SAFETY: zx_debug_write only reads `len` bytes from `ptr`.
        unsafe { zx::sys::zx_debug_write(s.as_ptr(), s.len()) };
    }));
    mark(b"CERISE-DH-XPROC-HARNESS-START\n");

    if let Err(e) = run().await {
        let s = format!("CERISE-DH-XPROC-HARNESS-ERR: {e}\n");
        mark(s.as_bytes());
        return;
    }
}

async fn run() -> Result<(), anyhow::Error> {
    // Connect once, then prove that an application-error Start is cleaned up before two
    // already-queued sibling Starts are served on this same DriverHost connection.
    let driver_host =
        connect_to_childs_protocol::<fdh::DriverHostMarker>("driver_host".to_string(), None)
            .await?;
    mark(b"CERISE-DH-XPROC-HARNESS-CONNECTED\n");

    let failed = start_attempt(true)?;
    let sibling_a = start_attempt(false)?;
    let sibling_b = start_attempt(false)?;
    let failed_start = driver_host.start(failed.start_args, failed.driver_server, "xproc-fail");
    let start_a = driver_host.start(sibling_a.start_args, sibling_a.driver_server, "xproc-a");
    let start_b = driver_host.start(sibling_b.start_args, sibling_b.driver_server, "xproc-b");
    let (failed_result, result_a, result_b) =
        futures::try_join!(failed_start, start_a, start_b)
            .map_err(|e| anyhow::anyhow!("DriverHost.Start FIDL error: {e}"))?;
    match failed_result {
        Err(status) if status == zx::Status::NOT_FOUND.into_raw() => {}
        other => {
            return Err(anyhow::anyhow!(
                "failing DriverHost.Start did not preserve ZX_ERR_NOT_FOUND: {other:?}"
            ));
        }
    }
    drop((failed.driver_client, failed.outgoing_client));
    mark(b"CERISE-DH-XPROC-HARNESS-APP-ERROR-OK\n");

    result_a.map_err(|e| anyhow::anyhow!("first sibling DriverHost.Start error: {e}"))?;
    result_b.map_err(|e| anyhow::anyhow!("second sibling DriverHost.Start error: {e}"))?;
    mark(b"CERISE-DH-XPROC-HARNESS-OK\n");
    mark(b"CERISE-DH-XPROC-HARNESS-SIBLING-OK\n");

    // Cross several executor turns before touching either outgoing directory. This catches
    // both post-Start lifetime loss and cleanup from the failed predecessor leaking into a
    // successfully started sibling.
    for _ in 0..4 {
        fuchsia_async::yield_now().await;
    }
    let echo_a = check_echo(sibling_a.outgoing_client, 0x4352_5345);
    let echo_b = check_echo(sibling_b.outgoing_client, 0x4352_5346);
    futures::try_join!(echo_a, echo_b)?;
    mark(b"CERISE-DH-XPROC-HARNESS-SERVICE-OK\n");

    let stop_a = stop_driver(sibling_a.driver_client);
    let stop_b = stop_driver(sibling_b.driver_client);
    futures::try_join!(stop_a, stop_b)?;
    mark(b"CERISE-DH-XPROC-HARNESS-STOP-OK\n");
    Ok(())
}

struct StartAttempt {
    start_args: fdf_fidl::DriverStartArgs,
    driver_client: ClientEnd<fdh::DriverMarker>,
    driver_server: ServerEnd<fdh::DriverMarker>,
    outgoing_client: ClientEnd<fio::DirectoryMarker>,
}

fn start_attempt(fail_start: bool) -> Result<StartAttempt, anyhow::Error> {
    let (svc_client, svc_server) = create_endpoints::<fio::DirectoryMarker>();
    fuchsia_fs::directory::open_channel_in_namespace("/svc", fio::PERM_READABLE, svc_server)?;
    let (driver_client, driver_server) = create_endpoints::<fdh::DriverMarker>();
    let (outgoing_client, outgoing_server) = create_endpoints::<fio::DirectoryMarker>();
    let program = fail_start.then(|| fdata::Dictionary {
        entries: Some(vec![fdata::DictionaryEntry {
            key: "cerise.test.fail_start".to_string(),
            value: Some(Box::new(fdata::DictionaryValue::Str("true".to_string()))),
        }]),
        ..Default::default()
    });
    Ok(StartAttempt {
        start_args: fdf_fidl::DriverStartArgs {
            node: None,
            incoming: Some(vec![frunner::ComponentNamespaceEntry {
                path: Some("/svc".to_string()),
                directory: Some(svc_client),
                ..Default::default()
            }]),
            outgoing_dir: Some(outgoing_server),
            log_sink: None,
            program,
            ..Default::default()
        },
        driver_client,
        driver_server,
        outgoing_client,
    })
}

async fn check_echo(
    outgoing_client: ClientEnd<fio::DirectoryMarker>,
    expected: u32,
) -> Result<(), anyhow::Error> {
    let outgoing = outgoing_client.into_proxy();
    let echo =
        fuchsia_component::client::connect_to_protocol_at_dir_root::<echo::EchoMarker>(&outgoing)?;
    let value = echo.echo_value(expected).await?;
    if value != expected {
        return Err(anyhow::anyhow!(
            "post-Start Echo returned {value:#x}, expected {expected:#x}"
        ));
    }
    Ok(())
}

async fn stop_driver(driver_client: ClientEnd<fdh::DriverMarker>) -> Result<(), anyhow::Error> {
    let driver = driver_client.into_proxy();
    let mut events = driver.take_event_stream();
    driver.stop()?;
    match events.try_next().await {
        Err(fidl::Error::ClientChannelClosed {
            status,
            epitaph: Some(epitaph),
            ..
        }) if status.into_raw() == zx::Status::OK.into_raw()
            && epitaph == zx::Status::OK.into_raw() as u32 => Ok(()),
        other => Err(anyhow::anyhow!(
            "Driver.Stop did not return a ZX_OK epitaph: {other:?}"
        )),
    }
}

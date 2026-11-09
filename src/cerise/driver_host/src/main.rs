// driver_host: minimal Rust driver host that serves fuchsia.driver.host.DriverHost.
// When Start() is called by driver_manager, prints CERISE-DRIVER-HOST-BOUND and
// CERISE-DRIVER-OK via zx_debug_write to confirm the DFv2 dispatch chain works.
//
// Critical: start_args (which contains node: ClientEnd<Node>) must be kept alive until
// the Driver channel is closed (Stop() received). Dropping node early causes driver_manager
// to see peer-closed on the Node channel and removes the node unexpectedly.

use fidl_fuchsia_driver_host as fdh;
use fuchsia_component::server::ServiceFs;
use futures::prelude::*;

#[fuchsia::main(logging = false)]
async fn main() {
    let mut fs = ServiceFs::new_local();
    fs.dir("svc").add_fidl_service(|s: fdh::DriverHostRequestStream| s);
    fs.take_and_serve_directory_handle().unwrap();

    fs.for_each_concurrent(None, |stream| handle_driver_host(stream)).await;
}

async fn handle_driver_host(mut stream: fdh::DriverHostRequestStream) {
    while let Ok(Some(req)) = stream.try_next().await {
        match req {
            fdh::DriverHostRequest::Start { start_args, driver, responder, .. } => {
                unsafe {
                    let msg = b"CERISE-DRIVER-HOST-BOUND\n";
                    zx::sys::zx_debug_write(msg.as_ptr(), msg.len());
                    let msg = b"CERISE-DRIVER-OK\n";
                    zx::sys::zx_debug_write(msg.as_ptr(), msg.len());
                }
                let _ = responder.send(Ok(()));
                // Keep start_args alive until Stop() — dropping it early closes the
                // node ClientEnd<Node> which causes driver_manager to remove the node.
                let mut driver_stream = driver.into_stream();
                while driver_stream.try_next().await.ok().flatten().is_some() {}
                drop(start_args);
            }
            fdh::DriverHostRequest::StartLoadedDriver { driver, responder, .. } => {
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

// Cerise component-test SUBJECT: a trivial CFv2 component that serves
// cerise.echo.Echo (EchoValue(x) -> x) on its outgoing directory. It is the
// "component under test" launched by the test realm; the verifier (echo_check)
// connects to this protocol through component_manager's capability routing and
// asserts the echoed value.
//
// Modeled on src/cerise/logsink (ServiceFs on the outgoing dir) and
// src/cerise/netstack3_probe (real fdio, statically linked). Markers go straight
// directly to serial via zx_debug_write so the verdict does not depend on the
// LogSink path.
use fidl_cerise_echo::{EchoRequest, EchoRequestStream};
use fuchsia_component::server::ServiceFs;
use futures::prelude::*;

fn klog(s: &str) {
    unsafe extern "C" {
        fn zx_debug_write(buf: *const u8, len: usize) -> i32;
    }
    unsafe {
        zx_debug_write(s.as_ptr(), s.len());
    }
}

enum Incoming {
    Echo(EchoRequestStream),
}

#[fuchsia::main(logging = false)]
async fn main() {
    klog("echo_server: starting\n");

    let mut fs = ServiceFs::new();
    fs.dir("svc").add_fidl_service(Incoming::Echo);
    fs.take_and_serve_directory_handle()
        .expect("echo_server: serve outgoing dir");
    klog("echo_server: serving cerise.echo.Echo\n");

    fs.for_each_concurrent(None, |Incoming::Echo(stream)| serve_echo(stream))
        .await;
}

async fn serve_echo(mut stream: EchoRequestStream) {
    while let Some(request) = stream.next().await {
        match request {
            Ok(EchoRequest::EchoValue { value, responder }) => {
                // Echo the value straight back.
                let _ = responder.send(value);
            }
            Err(_) => break,
        }
    }
}

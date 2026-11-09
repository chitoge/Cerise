// Cerise component-test VERIFIER (the "test root" behavior): connects to
// cerise.echo.Echo from its incoming namespace — a capability component_manager
// routes from the echo_server child per the test realm's `offer` — calls
// EchoValue with a sentinel, and asserts the response equals what was sent.
//
// The verdict marker CERISE-COMPONENT-TEST-OK is emitted by THIS verifier only
// after it confirms the subject behaved correctly (per the review guidance: the
// verdict must come from the verifier, not from the subject self-reporting).
// Any failure emits CERISE-COMPONENT-TEST-FAIL with a reason.
//
// Modeled on src/cerise/netstack3_probe (connect_to_protocol + real fdio).
use fidl_cerise_echo::EchoMarker;
use fuchsia_component::client::connect_to_protocol;

fn klog(s: &str) {
    unsafe extern "C" {
        fn zx_debug_write(buf: *const u8, len: usize) -> i32;
    }
    unsafe {
        zx_debug_write(s.as_ptr(), s.len());
    }
}

const SENTINEL: u32 = 0x00C0_FFEE;

#[fuchsia::main(logging = false)]
async fn main() {
    klog("echo_check: starting\n");

    let echo = match connect_to_protocol::<EchoMarker>() {
        Ok(proxy) => proxy,
        Err(_) => {
            klog("CERISE-COMPONENT-TEST-FAIL: connect_to_protocol(Echo) failed\n");
            return;
        }
    };

    match echo.echo_value(SENTINEL).await {
        Ok(response) if response == SENTINEL => {
            // Real cross-component FIDL round-trip verified through
            // component_manager routing: the subject echoed the sentinel.
            klog("CERISE-COMPONENT-TEST-OK\n");
        }
        Ok(other) => {
            klog("CERISE-COMPONENT-TEST-FAIL: echo mismatch\n");
            let _ = other;
        }
        Err(_) => {
            klog("CERISE-COMPONENT-TEST-FAIL: EchoValue call failed\n");
        }
    }
}

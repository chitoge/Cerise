use core::panic::PanicInfo;

use crate::zx;

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    const MSG: &[u8] = b"cerise-rt: panic\n";
    zx::debug_write(MSG.as_ptr(), MSG.len());
    zx::process_exit(1)
}

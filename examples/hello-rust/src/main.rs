#![no_std]
#![no_main]

extern crate cerise_rt;

const MARKER: &[u8] = b"hello-rust: booted\n";

#[no_mangle]
pub fn cerise_main() {
    cerise_rt::debug_write(MARKER);
}

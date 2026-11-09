// Dynamically-linked Fuchsia binary (PT_INTERP + DT_NEEDED [libzircon.so, libfdio.so, libc.so]).
// Spawned by component_runner via process_builder; prints the component-runner gate marker via zx_debug_write.
extern "C" {
    fn zx_debug_write(buf: *const u8, len: usize) -> i32;
}

fn main() {
    let msg = b"CERISE-COMPONENT-OK\n";
    unsafe { zx_debug_write(msg.as_ptr(), msg.len()) };
}

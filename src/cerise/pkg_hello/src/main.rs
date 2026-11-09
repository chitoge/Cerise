// Cerise packages demonstration component (foundation): pkg_hello — the
// demonstration package's component binary, an external content blob (bin/pkg_hello) inside a real
// Fuchsia package. makes this LAUNCHABLE from disk: pkg_resolver resolves
// fuchsia-pkg://cerise/pkg_hello#meta/pkg_hello.cm and component_manager's elf_runner starts this
// process with its binary + shared libs (lib/{ld.so.1,libm.so,libc++.so.1}) paged out of the fxfs
// blob volume — NOT bootfs. The marker below is emitted on launch, proving the whole
// resolve-and-launch-from-blobs chain; if it appears on serial, the component ran from disk blobs.

fn emit(msg: &str) {
    unsafe {
        zx::sys::zx_debug_write(msg.as_ptr(), msg.len());
    }
}

#[fuchsia::main(logging = false)]
async fn main() {
    emit("CERISE-PKG-RESOLVER-LAUNCHED\n");
}

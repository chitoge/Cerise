// Cerise packages: pkg_hello v1 — the BASE version of the updatable demo package.
// Packaged (meta/package name "pkg_hello") and shipped in the boot image; pkg_fetcher ingests its
// blobs into the fxfs blob volume and the resolver resolves fuchsia-pkg://cerise/pkg_hello to it via
// the BOOTFS BASE index. The marker carries the version string so the boot gate can tell v1 (from
// base) apart from v2 (fetched over the network into the persistent dynamic index).

fn emit(msg: &str) {
    unsafe {
        zx::sys::zx_debug_write(msg.as_ptr(), msg.len());
    }
}

#[fuchsia::main(logging = false)]
async fn main() {
    emit("CERISE-PKG-UPDATE-V1-LAUNCHED\n");
}

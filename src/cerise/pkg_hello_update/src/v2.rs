// Cerise packages: pkg_hello v2 — the UPDATED version of the demo package. Same
// package NAME ("pkg_hello") and manifest as v1, but a different binary => a different content-blob
// merkle => a different meta.far merkle (a genuinely distinct package hash). v2 is NOT staged in the
// boot image: pkg_fetcher downloads its blobs over the network, merkle-verifies them, writes them to
// the fxfs blob volume, and registers "pkg_hello" v2 in the PERSISTENT dynamic index (which shadows
// the base v1 entry). Resolving fuchsia-pkg://cerise/pkg_hello then yields v2 — the update took.
// This marker proves v2's code actually ran (from disk blobs it never shipped with).

fn emit(msg: &str) {
    unsafe {
        zx::sys::zx_debug_write(msg.as_ptr(), msg.len());
    }
}

#[fuchsia::main(logging = false)]
async fn main() {
    emit("CERISE-PKG-UPDATE-V2-LAUNCHED\n");
}

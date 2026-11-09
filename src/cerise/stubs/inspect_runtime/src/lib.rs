// Cerise: real inspect_runtime, re-exported through the historical stub path.
//
// This crate used to be a no-op stub whose `publish()` always returned `None`.
// It is now a thin re-export of the real vendored implementation
// (//src/upstream/fuchsia/src/lib/diagnostics/inspect/runtime/rust:fuchsia-inspect-runtime),
// so consumers depending on //src/cerise/stubs/inspect_runtime:inspect_runtime
// transparently get the real Inspect publishing path with zero consumer edits.
//
// The real crate is brought in under the alias `real_inspect_runtime` (see the
// `aliases` attribute in BUILD.bazel) to avoid a crate-name collision, since
// both this shim and the real crate use `crate_name = "inspect_runtime"`.

pub use real_inspect_runtime::*;

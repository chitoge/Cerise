// Cerise: real Inspect, re-exported through the historical stub path.
//
// This crate used to be a no-op stub. It is now a thin re-export of the real
// vendored Inspect implementation
// (//src/upstream/fuchsia/src/lib/diagnostics/inspect/rust:fuchsia-inspect),
// so every existing consumer that depends on
// //src/cerise/stubs/fuchsia_inspect:fuchsia_inspect transparently gets real,
// VMO-backed Inspect with zero consumer-BUILD edits.
//
// The real crate is brought in under the alias `real_inspect` (see the
// `aliases` attribute in BUILD.bazel) to avoid a crate-name collision, since
// both this shim and the real crate use `crate_name = "fuchsia_inspect"`.
//
// If a consumer ever relies on a stub-only shape that the real API does not
// provide, shadow just that item here (e.g. `pub mod component { pub use
// real_inspect::component::*; /* + shim */ }`) rather than editing the
// consumer. As of the de-stub none is needed: the previous stub's API surface
// was a strict subset of the real crate's.

pub use real_inspect::*;

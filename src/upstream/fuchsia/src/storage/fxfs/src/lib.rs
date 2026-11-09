// Copyright 2021 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Fxfs is a log-structured filesystem for [Fuchsia](https://fuchsia.dev/).
//!
//! For a high-level overview, please refer to the
//! [RFC](/docs/contribute/governance/rfcs/0136_fxfs.md).
//!
//! Where possible, Fxfs code tries to be target agnostic.
//! Fuchsia specific bindings are primarily found under [server].

// TODO(https://fxbug.dev/439053417): Investigate why the recursion limit was bumped
// to unblock the toolchain.
#![recursion_limit = "256"]
// Cerise change: added, not present in unmodified upstream at this pin.
// src/object_store/extent_mapping_iterator.rs uses slice::array_windows() and
// src/zerocopy_serialization.rs uses Vec::into_raw_parts() - both real, long-standing
// unstable std library APIs (rust-lang/rust#75027, #65816) with NO crate-level opt-in
// anywhere in unmodified upstream's lib.rs (confirmed - grepped the whole file). This
// repo's rustc toolchain is genuinely nightly-track (MODULE.bazel's
// rust_linux_x86_64_..._nightly registration), which allows #![feature(...)] directly;
// whatever mechanism Fuchsia's own real build uses to avoid needing this attribute
// (a newer/older nightly where these stabilized differently, or a GN-specific rustc
// invocation flag) wasn't reproducible here. Purely a compiler-permission gate - zero
// behavior change to the vendored logic.
#![feature(array_windows, vec_into_raw_parts)]

pub mod checksum;
pub mod drop_event;

#[macro_use]
mod debug_assert_not_too_long;

pub mod blob_metadata;
pub mod errors;
pub mod filesystem;
pub mod fsck;
pub mod future_with_guard;
pub mod log;
pub mod lsm_tree;
pub mod metrics;
pub mod object_handle;
pub mod object_store;
pub mod range;
pub mod round;
pub mod serialized_types;
mod stable_hash;
#[cfg(any(test, feature = "benchmark", fuzz))]
pub mod testing;
pub mod virtual_device;
pub mod zerocopy_serialization;

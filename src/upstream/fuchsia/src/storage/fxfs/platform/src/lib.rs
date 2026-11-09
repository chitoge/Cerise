// Copyright 2022 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// TODO(https://fxbug.dev/439053417): Investigate why the recursion limit was bumped to unblock the toolchain.
#![recursion_limit = "256"]
// Cerise: this repo's rustc is nightly-track but unmodified upstream carries no
// #![feature(...)] anywhere; array_windows (used in fxblob/blob.rs) needs this on
// our toolchain. Same class of gap as Phase 2's core-lib nightly features.
#![feature(array_windows)]

pub use fxfs_platform_constants as constants;

#[cfg(target_os = "fuchsia")]
pub mod fuchsia;

#[cfg(target_os = "fuchsia")]
pub use self::fuchsia::*;

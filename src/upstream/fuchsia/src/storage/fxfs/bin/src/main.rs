// Copyright 2021 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// TODO(https://fxbug.dev/439053417): Investigate why the recursion limit was bumped to unblock the
// toolchain.
#![recursion_limit = "256"]

use anyhow::{Context, Error};
use fuchsia_runtime::HandleType;
use fxfs::log::*;
use fxfs::serialized_types::LATEST_VERSION;
use fxfs_platform::component::Component;

// DIAGNOSTIC (temporary, fshost validation crash bisection): unconditional trace markers
// to localize a silent EXCEPTION_KILL (return_code=-1028) crash with zero other output.
fn trace(stage: &str) {
    let msg = format!("CERISE-FXFS-BIN-TRACE-{stage}\n");
    unsafe {
        zx::sys::zx_debug_write(msg.as_ptr(), msg.len());
    }
}

// TODO(https://fxbug.dev/402196421) improve scheduler integration
#[fuchsia::main(threads = num_worker_threads(), thread_role = "fuchsia.fs.fxfs")]
async fn main() -> Result<(), Error> {
    trace("MAIN-ENTRY");

    trace("INSPECT-PUBLISH-START");
    let _inspect_server_task = inspect_runtime::publish(
        fuchsia_inspect::component::inspector(),
        inspect_runtime::PublishOptions::default().send_vmo_preference(
            inspect_runtime::TreeServerSendPreference::frozen_or(
                inspect_runtime::TreeServerSendPreference::DeepCopy,
            ),
        ),
    );
    trace("INSPECT-PUBLISH-OK");

    trace("TRACE-PROVIDER-START");
    fuchsia_trace_provider::trace_provider_create_with_fdio();
    trace("TRACE-PROVIDER-OK");

    info!(version:% = LATEST_VERSION; "Started");
    trace("INFO-LOG-OK");

    trace("STARTUP-HANDLE-DIR-START");
    let dir_handle = fuchsia_runtime::take_startup_handle(HandleType::DirectoryRequest.into())
        .context("Missing startup handle")?;
    trace("STARTUP-HANDLE-DIR-OK");

    trace("STARTUP-HANDLE-LIFECYCLE-START");
    let lifecycle_handle =
        fuchsia_runtime::take_startup_handle(HandleType::Lifecycle.into()).map(|h| h.into());
    trace("STARTUP-HANDLE-LIFECYCLE-OK");

    trace("COMPONENT-NEW-START");
    let component = Component::new();
    trace("COMPONENT-NEW-OK");

    trace("COMPONENT-RUN-START");
    let result = component.run(dir_handle.into(), lifecycle_handle).await;
    trace("COMPONENT-RUN-RETURNED");
    result
}

// TODO(https://fxbug.dev/402196413) delegate thread count to product config
fn num_worker_threads() -> u8 {
    (std::cmp::max(zx::system_get_num_cpus(), 2) - 1).try_into().unwrap_or(u8::MAX)
}

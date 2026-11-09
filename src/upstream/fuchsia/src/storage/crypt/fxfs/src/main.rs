// Copyright 2021 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use anyhow::Error;
use fuchsia_async as fasync;
use fuchsia_component::server::ServiceFs;
use futures::TryFutureExt;
use futures::stream::StreamExt;
use fxfs_crypt::log::*;
use fxfs_crypt::{CryptService, Services};

// DIAGNOSTIC (temporary, fshost validation: dynamic fxfs-crypt.N stall bisection).
fn trace(stage: &str) {
    let msg = format!("CERISE-FXFS-CRYPT-TRACE-{stage}\n");
    unsafe {
        zx::sys::zx_debug_write(msg.as_ptr(), msg.len());
    }
}

#[fasync::run(10)]
async fn main() -> Result<(), Error> {
    trace("MAIN-ENTRY");
    diagnostics_log::initialize(diagnostics_log::PublishOptions::default())?;
    trace("DIAGNOSTICS-LOG-INIT-OK");

    let mut fs = ServiceFs::new();
    fs.dir("svc").add_fidl_service(Services::Crypt).add_fidl_service(Services::CryptManagement);
    trace("SERVICEFS-CONFIGURED");
    fs.take_and_serve_directory_handle()?;
    trace("SERVICEFS-SERVING");

    let crypt = CryptService::new();

    const MAX_CONCURRENT: usize = 10_000;
    trace("FOR-EACH-CONCURRENT-START");
    fs.for_each_concurrent(MAX_CONCURRENT, |request| {
        trace("REQUEST-RECEIVED");
        crypt.handle_request(request).unwrap_or_else(|e| error!("{:?}", e))
    })
    .await;
    trace("FOR-EACH-CONCURRENT-RETURNED");

    Ok(())
}

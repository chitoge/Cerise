// Copyright 2026 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use futures::lock::{Mutex, MutexGuard};

/// Serializes the synchronous Driver.Start round trips issued by DriverRunner.
///
/// Bind discovery and component creation stay concurrent. The guard covers only
/// the final driver-host round trip, where a driver may synchronously publish
/// child nodes back through driver_manager before replying to Start.
pub(crate) struct DriverStartGate {
    inner: Mutex<()>,
}

impl DriverStartGate {
    pub(crate) fn new() -> Self {
        Self {
            inner: Mutex::new(()),
        }
    }

    pub(crate) async fn enter(&self) -> MutexGuard<'_, ()> {
        self.inner.lock().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::{FutureExt as _, poll};

    #[test]
    fn admits_only_one_driver_start_round_trip() {
        futures::executor::block_on(async {
            let gate = DriverStartGate::new();
            let first = gate.enter().await;
            let second = gate.enter().fuse();
            futures::pin_mut!(second);

            assert!(poll!(&mut second).is_pending());
            drop(first);
            assert!(poll!(&mut second).is_ready());
        });
    }

    #[test]
    fn production_runner_holds_gate_across_driver_host_start() {
        let source = include_str!("driver_runner.rs");
        assert!(source.contains("start_gate: DriverStartGate"));
        assert!(source.contains("let _start_guard = self.start_gate.enter().await;"));
        assert!(source.contains("node.start_driver(start_info, controller).await"));

        let guard = source
            .find("let _start_guard = self.start_gate.enter().await;")
            .expect("driver start gate acquisition");
        let round_trip = source[guard..]
            .find("node.start_driver(start_info, controller).await")
            .map(|offset| guard + offset)
            .expect("DriverHost.Start round trip after gate acquisition");
        assert!(guard < round_trip);
    }
}

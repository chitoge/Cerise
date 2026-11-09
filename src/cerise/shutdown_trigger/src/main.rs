//! Cerise shutdown_trigger: a tiny ELF component that proves the real orderly
//! shutdown chain end to end.
//!
//! After the system reaches steady state it requests a graceful poweroff through the
//! public API and lets the real chain run:
//!
//!   shutdown_trigger --Admin.Poweroff--> shutdown-shim
//!     shim: records termination state = Poweroff, then
//!     shim --SystemController.Shutdown--> component_manager
//!       component_manager: reverse-dependency-order topology teardown
//!         driver_manager (stopped before the shim, which it depends on for
//!         SystemStateTransition): reads Poweroff, issues zx_system_powerctl(SHUTDOWN)
//!           => QEMU q35 ACPI S5 poweroff => clean guest exit.
//!
//! Readiness gate: before requesting shutdown we `use dev` from driver_manager and read
//! it. A successful readdir round-trips to driver_manager's outgoing directory, proving
//! it is up and serving (its shutdown_manager has published its Lifecycle handler and
//! acquired PowerResource/MexecResource) — so the graceful Stop that follows will reach
//! the real poweroff path rather than the "assuming test" fallback. This also creates a
//! one-directional routing edge (trigger depends on driver_manager), so component_manager
//! stops the trigger before driver_manager during teardown. No arbitrary sleep is used.

use anyhow::{Context, Result};
use fidl::endpoints::ServerEnd;
use fidl_fuchsia_hardware_power_statecontrol::AdminMarker;
use fidl_fuchsia_io as fio;
use fuchsia_component::client::connect_to_protocol;
use fuchsia_fs::directory::{open_channel_in_namespace, readdir};

/// Write a marker straight to the kernel debuglog (surfaced on serial) — no LogSink.
fn emit(msg: &str) {
    // SAFETY: zx_debug_write takes (ptr,len) of readable bytes; msg is a live &str.
    unsafe {
        zx::sys::zx_debug_write(msg.as_ptr(), msg.len());
    }
}

/// A successful readdir of /dev proves driver_manager is up and serving.
async fn driver_manager_ready() -> Result<()> {
    let (dev, server) = fidl::endpoints::create_proxy::<fio::DirectoryMarker>();
    open_channel_in_namespace(
        "/dev",
        fio::PERM_READABLE,
        ServerEnd::new(server.into_channel()),
    )
    .context("open /dev")?;
    readdir(&dev).await.context("readdir /dev")?;
    Ok(())
}

/// Fingerprint the recursive /dev tree (bounded walk). Two equal consecutive
/// fingerprints mean driver enumeration has quiesced.
///
/// WHY: "readdir(/dev) succeeds" only proves driver_manager's outgoing dir is
/// serving — the driver stack may still be BINDING (platform-bus → board →
/// bus-pci → leaves take seconds under TCG). Requesting topology shutdown
/// mid-enumeration catches components in the middle of starting, and a Stop
/// delivered to a still-starting driver component wedges the teardown past
/// component_manager's kill escalation (observed live: `=PS driver_manager_rust`
/// forever, pending: 5 — a stop-during-start deadlock). The gate must therefore fire only after the
/// device tree is QUIESCENT, which is also what a real shutdown initiator
/// (a user, a power button) sees in practice.
async fn devfs_fingerprint() -> Result<u64> {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let (dev, server) = fidl::endpoints::create_proxy::<fio::DirectoryMarker>();
    open_channel_in_namespace(
        "/dev",
        fio::PERM_READABLE,
        ServerEnd::new(server.into_channel()),
    )
    .context("open /dev")?;
    let mut hasher = DefaultHasher::new();
    // DFS with explicit bounds: the base driver stack's devfs is small (tens of
    // nodes); the caps only guard against a runaway tree.
    let mut stack = vec![(String::new(), dev)];
    let mut dirs_visited = 0usize;
    while let Some((prefix, dir)) = stack.pop() {
        dirs_visited += 1;
        if dirs_visited > 256 {
            break;
        }
        // Tolerate subdirs vanishing mid-walk (rebind churn): that just yields a
        // different fingerprint, postponing quiescence — never an error.
        let Ok(entries) = readdir(&dir).await else { continue };
        for e in entries {
            let path = format!("{prefix}/{}", e.name);
            path.hash(&mut hasher);
            if e.kind == fuchsia_fs::directory::DirentKind::Directory {
                if let Ok(sub) =
                    fuchsia_fs::directory::open_directory_async(&dir, &e.name, fio::PERM_READABLE)
                {
                    stack.push((path, sub));
                }
            }
        }
    }
    Ok(hasher.finish())
}

async fn run() {
    emit("CERISE-SHUTDOWN-READY\n");

    // Gate on driver_manager readiness (bounded); do not guess a delay. Generous bound:
    // these products boot under emulation (no KVM), so driver_manager can take minutes.
    const MAX_ATTEMPTS: u32 = 300;
    let mut ready = false;
    for attempt in 0..MAX_ATTEMPTS {
        match driver_manager_ready().await {
            Ok(()) => {
                ready = true;
                break;
            }
            Err(e) => {
                if attempt + 1 == MAX_ATTEMPTS {
                    emit(&format!(
                        "CERISE-SHUTDOWN-FAIL: driver_manager not ready: {e:#}\n"
                    ));
                }
                fuchsia_async::Timer::new(fuchsia_async::MonotonicInstant::after(
                    std::time::Duration::from_secs(1).into(),
                ))
                .await;
            }
        }
    }
    if !ready {
        return;
    }

    // Quiesce gate: require the recursive /dev tree to be UNCHANGED across 3
    // consecutive 1s-spaced polls before requesting shutdown (see
    // devfs_fingerprint's doc comment for the stop-during-start deadlock this
    // prevents). Bounded: after MAX_QUIESCE_POLLS we proceed anyway with a loud
    // marker rather than hanging the gate forever on a pathologically churning
    // tree.
    const STABLE_POLLS_REQUIRED: u32 = 3;
    const MAX_QUIESCE_POLLS: u32 = 120;
    let mut last: Option<u64> = None;
    let mut stable = 0u32;
    for _ in 0..MAX_QUIESCE_POLLS {
        let fp = devfs_fingerprint().await.ok();
        if fp.is_some() && fp == last {
            stable += 1;
            if stable >= STABLE_POLLS_REQUIRED {
                break;
            }
        } else {
            stable = 0;
        }
        last = fp;
        fuchsia_async::Timer::new(fuchsia_async::MonotonicInstant::after(
            std::time::Duration::from_secs(1).into(),
        ))
        .await;
    }
    if stable >= STABLE_POLLS_REQUIRED {
        emit("CERISE-SHUTDOWN-DEVFS-QUIESCED\n");
    } else {
        emit("CERISE-SHUTDOWN-WARN: devfs never quiesced; proceeding anyway\n");
    }

    let admin = match connect_to_protocol::<AdminMarker>() {
        Ok(a) => a,
        Err(e) => {
            emit(&format!(
                "CERISE-SHUTDOWN-FAIL: connect fuchsia.hardware.power.statecontrol.Admin: {e:#}\n"
            ));
            return;
        }
    };

    emit("CERISE-SHUTDOWN-REQUESTED\n");
    match admin.poweroff().await {
        Ok(Ok(())) => emit("CERISE-SHUTDOWN-ACK\n"),
        Ok(Err(s)) => emit(&format!("CERISE-SHUTDOWN-FAIL: Poweroff returned {s}\n")),
        // The Admin channel usually closes as the topology tears down around us; that is
        // the expected, successful path, not a failure.
        Err(_) => emit("CERISE-SHUTDOWN-ACK\n"),
    }

    // Park; the machine powers off out from under us during teardown.
    loop {
        fuchsia_async::Timer::new(fuchsia_async::MonotonicInstant::after(
            std::time::Duration::from_secs(3600).into(),
        ))
        .await;
    }
}

fn main() {
    let mut executor = fuchsia_async::LocalExecutor::default();
    executor.run_singlethreaded(run());
}

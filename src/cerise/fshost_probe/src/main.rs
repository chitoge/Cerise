// Cerise fshost_probe — proves the milestone "a userspace component reads a
// real file from its namespace" where the namespace is populated by real fshost's AUTOMATIC
// device discovery + Fxfs auto-mount, not driven by hand.
//
// fshost's real main.rs serves a pseudo-directory as its own outgoing directory, with an
// entry "fs" => { "blob" => remote_dir(blob_exposed_dir), "data" => remote_dir(data_exposed_dir) }.
// `data_exposed_dir` is the real, live root directory of whatever fshost auto-mounted as the
// "data" filesystem (Fxfs, per Cerise's `fxfs_blob: true` config). The realm exposes this
// "fs" subtree from fshost's .cm as capability "fshost-fs" (source_path "/fs"), routed to
// this component as directory "/fshost-fs". So "/fshost-fs/data/<file>" is a real path into
// fshost's auto-mounted Fxfs data volume; writing then reading a known file there proves the
// full gate.
//
// ORDERING — a real routed capability dependency, not a timing guess (race fix):
// fshost's own component is Lazy — component_manager doesn't start it until something opens
// one of its exposed capabilities, and in the fshost realm ONLY this component opens
// "/fshost-fs". So fshost starts strictly when THIS component first touches "/fshost-fs".
// Before doing that, this component reads "/provisioned/ready" — a directory capability the
// fxfs_provisioner serves ONLY after it has formatted the disk, created the "blob" volume,
// and CLOSED the filesystem (released the disk). That read is a real FIDL round-trip: it
// blocks until the provisioner has served its outgoing directory, i.e. strictly after
// provisioning completed and the disk was released. Only then do we open "/fshost-fs" and
// let fshost claim the disk. Result: provisioner and fshost never touch the disk at the same
// instant — the previous fxfs_probe-vs-fshost device-contention race is dissolved
// deterministically, without any wall-clock delay or content-polling heuristic.

use anyhow::{anyhow, Context, Result};
use fuchsia_fs::file::{read_in_namespace, write_in_namespace};
use zx::sys::zx_debug_write;

// fshost exports "data" as the data filesystem's EXPOSED dir (main.rs
// `remote_dir(env.data_exposed_dir())`), whose writable root is its "root" child
// (fs_management opens "root" with PERM_INHERIT_WRITE). So the real writable path into the
// auto-mounted data volume is ".../data/root/<file>", not ".../data/<file>".
const DATA_FILE: &str = "/fshost-fs/data/root/cerise-fshost-probe.txt";
const KNOWN_CONTENT: &[u8] = b"CERISE-FSHOST-PROBE-CONTENT\n";
// The fxfs_provisioner's readiness handoff: it serves this file only after format+close.
const READY_FILE: &str = "/provisioned/ready";

fn emit(msg: &str) {
    let msg = format!("{msg}\n");
    unsafe {
        zx_debug_write(msg.as_ptr(), msg.len());
    }
}

/// Blocks (via a real read round-trip) until the fxfs_provisioner has finished provisioning
/// and released the disk. Returns once "/provisioned/ready" is readable.
async fn await_provisioned() -> Result<()> {
    // The read only completes once the provisioner serves its outgoing dir (after
    // format+close). A bounded retry covers only the pre-serve window where the channel
    // exists but the request is still queued, plus any transient early-boot hiccup; it is
    // NOT a deadline racing the format — the read itself does the real waiting.
    const MAX_POLLS: u32 = 120; // 120 * 5s = 600s, comfortably past the slowest format
    const POLL_DELAY: std::time::Duration = std::time::Duration::from_secs(5);
    let mut last_err = None;
    for _ in 0..MAX_POLLS {
        match read_in_namespace(READY_FILE).await {
            Ok(_) => return Ok(()),
            Err(e) => {
                last_err = Some(anyhow!("{e:?}"));
                fuchsia_async::Timer::new(fuchsia_async::MonotonicInstant::after(
                    POLL_DELAY.into(),
                ))
                .await;
            }
        }
    }
    Err(last_err.unwrap_or_else(|| anyhow!("no reads attempted")))
}

async fn try_once() -> Result<()> {
    write_in_namespace(DATA_FILE, KNOWN_CONTENT)
        .await
        .context("write_in_namespace failed — fshost hasn't auto-mounted /fshost-fs/data yet")?;
    // The write succeeding proves fshost's real "fs/data" export directory is being served —
    // i.e. fshost automatically discovered the provisioned device and mounted Fxfs on it.
    emit("CERISE-FSHOST-MOUNT-OK");

    let read_back = read_in_namespace(DATA_FILE).await.context("read_in_namespace failed")?;
    if read_back != KNOWN_CONTENT {
        return Err(anyhow!(
            "content mismatch: wrote {} bytes, read back {} bytes",
            KNOWN_CONTENT.len(),
            read_back.len()
        ));
    }
    Ok(())
}

#[fuchsia::main(logging = false)]
async fn main() {
    // Gate on the provisioner FIRST (see the header): do not open "/fshost-fs" (which
    // Lazy-starts fshost and lets it claim the disk) until the provisioner has provisioned
    // the disk and released it.
    if let Err(e) = await_provisioned().await {
        emit(&format!("CERISE-FSHOST-READ-FAIL: never observed provisioner readiness: {e:?}"));
        return;
    }
    emit("CERISE-FSHOST-PROBE-PROVISIONED-OBSERVED");

    // The provisioner being done says nothing about how far fshost's OWN sequence
    // (content-sniff -> spawn a per-volume Crypt child -> create data/unencrypted volumes ->
    // mount) has gotten once it starts. fshost's mount takes real time after its Lazy start,
    // so this retry loop covers that window (the write fails until fshost serves /fs/data).
    const MAX_ATTEMPTS: u32 = 90;
    const RETRY_DELAY: std::time::Duration = std::time::Duration::from_secs(5); // 90*5s = 450s

    let mut last_err: Option<anyhow::Error> = None;
    for _ in 0..MAX_ATTEMPTS {
        match try_once().await {
            Ok(()) => {
                emit("CERISE-FSHOST-READ-OK");
                return;
            }
            Err(e) => {
                // Surface each failure (fshost's mount lags its own start, so early
                // attempts legitimately fail until "/fshost-fs/data/root" is served) so any
                // real, persistent failure is diagnosable immediately, not only at timeout.
                emit(&format!("CERISE-FSHOST-PROBE-ATTEMPT-ERR: {e:#}"));
                last_err = Some(e);
                fuchsia_async::Timer::new(fuchsia_async::MonotonicInstant::after(
                    RETRY_DELAY.into(),
                ))
                .await;
            }
        }
    }
    emit(&format!(
        "CERISE-FSHOST-READ-FAIL: {:?}",
        last_err.unwrap_or_else(|| anyhow!("no attempts ran"))
    ));
}

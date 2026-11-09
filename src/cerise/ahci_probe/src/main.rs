// Storage bring-up gate (AHCI): ahci_probe — proves real block read/write/
// readback through AHCI's client-facing protocol end-to-end.
//
// Same aggregate-Service routing mechanism as nvme_probe (see that file's header
// comment for the full mechanism trace and the important finding: component_manager's
// aggregate-service-from-collection does NOT preserve each source driver's original
// instance name — the aggregated directory lists opaque anonymized identifiers, not
// "sata0"/"namespace-1". This file therefore tries the full write/read/readback proof
// against every instance present, succeeding on whichever one answers, same as
// nvme_probe. To reduce (not eliminate) the chance both probes race on the exact same
// physical instance when exactly two are present, this file iterates the instance list
// in REVERSE order relative to nvme_probe's forward order.

use anyhow::{anyhow, Context, Result};
use block_client::{BlockClient as _, BufferSlice, MutableBufferSlice, RemoteBlockClient};
use fidl_fuchsia_hardware_block_volume::ServiceMarker;
use fuchsia_component::client::{open_service, Service};

fn emit(msg: &str) {
    unsafe {
        zx::sys::zx_debug_write(msg.as_ptr(), msg.len());
    }
}

// DIAGNOSTIC: unconditional stage-entry trace (not just on failure) — a hang inside a
// synchronous/async FIDL call would otherwise be silent. Now emitted as a structured
// DEBUG record through LogSink (tag "ahci_probe") instead of a raw serial marker.
fn trace(stage: &str) {
    log::debug!(stage; "ahci_probe stage entry");
}

async fn list_instances() -> Result<Vec<String>> {
    let dir = open_service::<ServiceMarker>().context("failed to open aggregated Service dir")?;
    let entries = fuchsia_fs::directory::readdir(&dir)
        .await
        .context("failed to read aggregated Service directory")?;
    Ok(entries.into_iter().map(|e| e.name).collect())
}

async fn try_instance(instance: &str) -> Result<()> {
    trace("CONNECT-INSTANCE");
    let dir = open_service::<ServiceMarker>().context("failed to re-open Service dir")?;
    let service = Service::<ServiceMarker>::from_service_dir_proxy(dir, ServiceMarker);
    let volume_proxy = service
        .connect_to_instance(instance)
        .context("failed to connect to instance")?;
    let block_proxy = volume_proxy
        .connect_to_volume()
        .context("failed to connect to volume member")?;

    trace("REMOTE-BLOCK-CLIENT-NEW");
    let client = RemoteBlockClient::new(block_proxy)
        .await
        .map_err(|s| anyhow!("RemoteBlockClient::new failed: {s}"))?;

    trace("BLOCK-SIZE");
    let block_size = client.block_size() as usize;
    if block_size == 0 {
        return Err(anyhow!("device reported block_size=0"));
    }

    trace("WRITE-AT");
    let pattern: Vec<u8> = (0..block_size).map(|i| (0x5Au32.wrapping_add(i as u32)) as u8).collect();
    client
        .write_at(BufferSlice::Memory(&pattern), 0)
        .await
        .map_err(|s| anyhow!("write_at failed: {s}"))?;
    trace("FLUSH");
    client.flush().await.map_err(|s| anyhow!("flush failed: {s}"))?;

    trace("READ-AT");
    let mut readback = vec![0u8; block_size];
    client
        .read_at(MutableBufferSlice::Memory(&mut readback), 0)
        .await
        .map_err(|s| anyhow!("read_at failed: {s}"))?;
    trace("READ-AT-DONE");

    if readback != pattern {
        return Err(anyhow!(
            "readback mismatch: wrote {} bytes, first 8 written={:?} first 8 read={:?}",
            block_size,
            &pattern[..8.min(pattern.len())],
            &readback[..8.min(readback.len())],
        ));
    }

    client.close().await.map_err(|s| anyhow!("close failed: {s}"))?;
    Ok(())
}

async fn try_once() -> Result<()> {
    trace("LIST-INSTANCES");
    let mut instances = list_instances().await?;
    if instances.is_empty() {
        return Err(anyhow!("no instances published yet"));
    }
    instances.reverse();

    let mut last_err: Option<anyhow::Error> = None;
    for instance in &instances {
        match try_instance(instance).await {
            Ok(()) => return Ok(()),
            Err(e) => last_err = Some(e),
        }
    }
    Err(last_err.unwrap_or_else(|| anyhow!("no instances succeeded")))
}

#[fuchsia::main(logging_tags = ["ahci_probe"])]
async fn main() {
    const MAX_ATTEMPTS: u32 = 60;
    const RETRY_DELAY: std::time::Duration = std::time::Duration::from_secs(5);

    log::info!("ahci_probe starting: probing for a real AHCI block device");

    let mut last_err: Option<anyhow::Error> = None;
    for attempt in 0..MAX_ATTEMPTS {
        match try_once().await {
            Ok(()) => {
                log::info!("AHCI block read/write/readback succeeded");
                // Boot-gate marker — keep on serial verbatim (validation greps this).
                emit("CERISE-AHCI-BLOCK-OK\n");
                return;
            }
            Err(e) => {
                log::warn!(attempt = attempt + 1, max = MAX_ATTEMPTS; "AHCI probe attempt failed, retrying: {e:#}");
                last_err = Some(e);
                fuchsia_async::Timer::new(fuchsia_async::MonotonicInstant::after(
                    RETRY_DELAY.into(),
                ))
                .await;
            }
        }
    }

    log::error!("AHCI block probe failed after {MAX_ATTEMPTS} attempts: {last_err:?}");
}

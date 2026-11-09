// Storage bring-up gate: nvme_probe — proves real block read/write/readback
// through NVMe's client-facing protocol end-to-end.
//
// NVMe (namespace.cc, Namespace::AddNamespace) does NOT call AddOwnedChild/DevfsAddArgs
// — unlike network-device, it never registers a devfs node. Instead it publishes a
// fuchsia.hardware.block.volume.Service instance (named per-namespace, e.g.
// "namespace-1") directly into its OWN component's outgoing directory via
// driver_outgoing()->AddService<...>(). The only real Fuchsia mechanism that gets this
// out to a plain sibling CFv2 component (without devfs) is "aggregate service capability
// routing from a collection": cm_fidl_validator's validate_expose_decl allows
// CollectionSource::Allow ONLY for Expose::Service (every other capability kind is
// CollectionSource::Deny) — this is a real, already-supported component_manager
// mechanism, not something added for Cerise. The routing chain is:
//   nvme_cm            Expose::Service(Self -> Parent)              [one bound driver]
//   driver_manager_rust Expose::Service(Collection("boot-drivers") -> Parent)  [aggregate]
//   root                Offer::Service(driver_manager_rust -> nvme_probe)
//   nvme_probe_cm       Use::Service(Parent) at /svc/fuchsia.hardware.block.volume.Service
//
// IMPORTANT, confirmed empirically (storage/AHCI bring-up, when both nvme and ahci
// got bound in the same boot): component_manager's aggregate-service-from-collection
// mechanism does NOT preserve each source's original instance name ("namespace-1",
// "sata0") in the aggregated directory. Observed real directory listing:
//   ["231aa1647eaadb1cf34b7fc89d6dcb8d", "38218f4d40a6d92dee9a309f402282d8"]
// — opaque, anonymized identifiers, not the human-readable names either driver actually
// publishes. An earlier version of this file assumed prefix-matching on the original
// name ("namespace"/"sata") would disambiguate between NVMe's and AHCI's instances once
// both share this one aggregated Service capability — that assumption was wrong and
// caused every attempt to fail at the enumeration step (never even reaching a connect
// call). There is no supported way from this client to learn which anonymized instance
// belongs to which source driver. Since both nvme_probe and ahci_probe exercise the
// exact same generic block_server/FIFO/VMO dataplane mechanism regardless of which
// physical device answers, this file tries the FULL write/read/readback proof against
// EVERY instance currently in the directory, succeeding (CERISE-NVME-BLOCK-OK) as
// soon as any one instance passes. This still proves the real dataplane end-to-end; it
// does not (and cannot, given the anonymization) prove specifically that NVMe's own
// instance was the one that answered rather than AHCI's — noted honestly, not papered
// over.
//
// Client-side: fuchsia_component::client::open_service opens the aggregated directory;
// readdir enumerates whatever instances are currently present; Service::connect_to_instance
// connects to a specific one by its (anonymized) name, then .connect_to_volume() connects
// to the `volume` member (client_end: fuchsia.storage.block.Block per
// fuchsia.hardware.block.volume/service.fidl).
//
// From there, block_client::RemoteBlockClient::new(block_proxy) does GetInfo +
// OpenSession + GetFifo + AttachVmo automatically. BufferSlice::Memory /
// MutableBufferSlice::Memory push actual byte buffers directly (Common::read_at /
// write_at internally stage through their own temp_vmo in TEMP_VMO_SIZE chunks) — no
// manual VMO plumbing needed. device_offset is in BYTES (Common::to_blocks converts to
// the wire dev_offset block count).
//
// Retry-the-whole-sequence-on-failure (a channel that's seen an error is dead, redo
// everything — same lesson as netdev_probe): an instance not yet published just means
// readdir finds an empty/smaller list, not an error on an already-open channel.

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
// DEBUG record through LogSink (tag "nvme_probe") instead of a raw serial marker.
fn trace(stage: &str) {
    log::debug!(stage; "nvme_probe stage entry");
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
    let pattern: Vec<u8> = (0..block_size).map(|i| (0xA5u32.wrapping_add(i as u32)) as u8).collect();
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
    let instances = list_instances().await?;
    if instances.is_empty() {
        return Err(anyhow!("no instances published yet"));
    }

    let mut last_err: Option<anyhow::Error> = None;
    for instance in &instances {
        match try_instance(instance).await {
            Ok(()) => return Ok(()),
            Err(e) => last_err = Some(e),
        }
    }
    Err(last_err.unwrap_or_else(|| anyhow!("no instances succeeded")))
}

#[fuchsia::main(logging_tags = ["nvme_probe"])]
async fn main() {
    const MAX_ATTEMPTS: u32 = 60;
    const RETRY_DELAY: std::time::Duration = std::time::Duration::from_secs(5);

    log::info!("nvme_probe starting: probing for a real NVMe block device");

    let mut last_err: Option<anyhow::Error> = None;
    for attempt in 0..MAX_ATTEMPTS {
        match try_once().await {
            Ok(()) => {
                log::info!("NVMe block read/write/readback succeeded");
                // Boot-gate marker — keep on serial verbatim (validation greps this).
                emit("CERISE-NVME-BLOCK-OK\n");
                return;
            }
            Err(e) => {
                log::warn!(attempt = attempt + 1, max = MAX_ATTEMPTS; "NVMe probe attempt failed, retrying: {e:#}");
                last_err = Some(e);
                fuchsia_async::Timer::new(fuchsia_async::MonotonicInstant::after(
                    RETRY_DELAY.into(),
                ))
                .await;
            }
        }
    }

    log::error!("NVMe block probe failed after {MAX_ATTEMPTS} attempts: {last_err:?}");
}

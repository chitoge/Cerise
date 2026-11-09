// Cerise fxfs_provisioner — the one-time, first-boot Fxfs "genesis" step for the
// x64-fshost product. It replaces fxfs_probe's ad-hoc formatting on the fshost path with
// a real, narrowly-routed component that owns *only* the genesis step, then hands the disk
// off to fshost cleanly.
//
// WHY THIS EXISTS (design choice (b), a Cerise-native provisioner, over (a), the upstream
// FxfsProvisioner path):
//   * There is NO `FxfsProvisioner` server implementation anywhere in the vendored tree —
//     only the FIDL (`fshost/src/fxfsprovisioner.fidl`) and fshost's *client* call
//     (`environment.rs:628`). Enabling `provision_fxfs:true` as-is panics (environment.rs
//     comments say so explicitly). So (a) means writing the server from scratch regardless.
//   * fshost's provision path is gated on a GPT partition labelled
//     SUPER_AND_USERDATA_PARTITION_LABEL (`matcher.rs:252`). Cerise has no GPT driver
//     (config.gpt=false), so that label never appears — and on a *virgin* raw disk with no
//     Fxfs content and no GPT label, fshost's `match_device` returns FALSE
//     (`matcher.rs:263`). fshost therefore cannot self-bootstrap a blank disk at all; it can
//     only *mount* a disk that already content-sniffs as Fxfs. This provisioner exists
//     precisely to make a virgin disk match-able: it lays down the Fxfs container so fshost's
//     content-sniff succeeds and its normal auto-mount path takes over.
//
// WHAT IT PROVISIONS (deliberately minimal — blob only, no crypt):
//   fshost's `FxfsContainer::serve_data` (environment/fxfs_container.rs:45-77) OPENS the
//   "blob" volume (it must pre-exist — `mount_blob_volume` → `open_volume("blob")`,
//   environment.rs:484), but it CREATES the "data" + "unencrypted" volumes itself: when the
//   expected {blob,data,unencrypted} set isn't all present it calls `format_data` →
//   `remove_all_non_blob_volumes()` + `init_data_volume()` (fxfs_container.rs:76-90), which
//   builds the keybag in an "unencrypted" volume and the encrypted "data" volume using
//   fshost's OWN vendored crypt path (`crypt_policy::KeySource::Null` keybag keys via a
//   dynamically-spawned crypt_fxfs child — crypt/fxfs.rs). So this provisioner needs to
//   create ONLY a bare (unencrypted) "blob" volume; anything else it wrote would just be
//   deleted by fshost. No crypt, no WRAPPING_KEY here — key management stays entirely in
//   fshost's untouched keybag path (is deliberately out of scope).
//
// IDEMPOTENT / REBOOT-SAFE: on a disk that already content-sniffs as Fxfs with a "blob"
// volume, it does nothing but re-signal readiness — so a reboot re-runs it harmlessly and
// fshost re-mounts the persisted {blob,data,unencrypted} it created on first boot.
//
// RACE-FREE HANDOFF (the point of the whole task): this component and fshost are the ONLY
// two disk touchers in the fshost realm now (fxfs_probe is retired from that realm). It
// touches the disk ONLY during provisioning, then CLOSES the filesystem and only THEN serves
// a "provisioned" directory capability (a single "ready" file). fshost_probe reads
// "/provisioned/ready" — a real FIDL round-trip that blocks until this component has served
// its outgoing directory, which happens strictly AFTER format+close — before it ever opens
// "/fshost-fs" (the action that Lazy-starts fshost). So the ordering is a real routed
// capability dependency, not a timing guess: provision → close → signal → fshost starts →
// fshost mounts. Exactly one component holds the disk at any instant.
//
// STAYS ALIVE (not "exits"): the task described a provisioner that "then exits", but the
// readiness capability must remain routable for fshost_probe's gate to resolve — if the
// process exited, the channel would close (PEER_CLOSED) instead of serving a clean gate. So
// after provisioning it stays idle, holding NO disk resources (the FxFilesystem and the
// block-device connection are both dropped), serving only the in-memory readiness directory.
//
// STACK: Fxfs's format path (`FxFilesystem::new_empty`) builds deeply-nested generic-heavy
// async state machines that overflow the default thread stack (a real crash isolated in the
// fxfs_probe work — see that file's header). Same fix here: run everything on a dedicated OS
// thread with a 16 MiB stack and its own LocalExecutor.

// WHAT A CLAIM LOOKS LIKE NOW (2026-07-25): claiming a disk used to mean formatting the raw
// block device as Fxfs. That left nowhere for a bootloader to live, so a machine could never
// boot from a disk this provisioner had claimed — the SSD could only ever be secondary storage.
// A claim now WRITES A GPT (an ESP plus an Fxfs partition, see layout.rs) and formats Fxfs
// INSIDE the Fxfs partition. NOTE the limit of that claim: the ESP is RESERVED, not populated.
// No FAT32 filesystem is created in it and no boot shim or ZBI is written to it, here or
// anywhere else on-target. The disk gains somewhere for a bootloader to live; it does not gain
// a bootloader. The claim policy itself is unchanged: cerise still takes the whole
// device, and only when nothing says the device is already ours. See layout.rs for the layout
// and ownership.rs for the decision.
//
// READ THIS BEFORE ENABLING IT ON THE fshost PRODUCTS: fshost content-sniffs the WHOLE raw
// device and has no GPT driver in this tree (config gpt=false, and there is no gpt component —
// only a C++ cc_library at src/upstream/fuchsia/src/storage/gpt with no manifest). An Fxfs
// container that lives inside a partition is therefore invisible to fshost until something
// publishes partitions as block devices. Disks provisioned by the OLD code (Fxfs on the raw
// device) are RETAINED untouched by the ownership check, so nothing already deployed changes;
// but a freshly claimed disk gets the new shape.

mod layout;
mod ownership;

use anyhow::{anyhow, Context, Result};
use block_client::{BlockClient as _, BufferSlice, MutableBufferSlice, RemoteBlockClient};
use fidl_fuchsia_hardware_block_volume::ServiceMarker;
use fidl_fuchsia_storage_block::BlockProxy;
use fs_management::format::{detect_disk_format, DiskFormat};
use fuchsia_component::client::{open_service, Service};
use fuchsia_component::server::ServiceFs;
use futures::StreamExt as _;
use fxfs::filesystem::FxFilesystem;
use fxfs::object_store::volume::root_volume;
use fxfs::object_store::{NewChildStoreOptions, StoreOptions};
use ownership::{Evidence, Plan, Probe, Region, TableEvidence};
use std::sync::Arc;
use storage_device::block_device::BlockDevice;
use storage_device::ranged_device::RangedDevice;
use storage_device::{Device, DeviceHolder};

// fshost's `mount_blob_volume` OPENS (does not create) this volume; it must pre-exist. Bare/
// unencrypted, matching real Fxfs's own blob-volume design (blobs are content-addressed).
const BLOB_VOLUME_NAME: &str = "blob";

// The readiness handoff: a directory capability "provisioned" containing this one file.
// fshost_probe reads it (a round-trip) before touching "/fshost-fs".
const READY_FILE: &str = "ready";
const READY_CONTENT: &[u8] = b"CERISE-PROVISION-READY\n";

fn emit(msg: &str) {
    unsafe {
        zx::sys::zx_debug_write(msg.as_ptr(), msg.len());
    }
}

fn trace(stage: &str) {
    emit(&format!("CERISE-PROVISION-TRACE-{stage}\n"));
}

async fn list_instances() -> Result<Vec<String>> {
    let dir = open_service::<ServiceMarker>().context("failed to open aggregated Service dir")?;
    let entries = fuchsia_fs::directory::readdir(&dir)
        .await
        .context("failed to read aggregated Service directory")?;
    Ok(entries.into_iter().map(|e| e.name).collect())
}

/// A fresh block-device connection to `instance` from the aggregate volume Service pool.
/// Every call re-opens the Service dir (a channel that has seen an error is permanently
/// dead — redo everything, the same philosophy fxfs_probe/nvme_probe use).
async fn connect_block_proxy(instance: &str) -> Result<BlockProxy> {
    let dir = open_service::<ServiceMarker>().context("failed to re-open Service dir")?;
    let service = Service::<ServiceMarker>::from_service_dir_proxy(dir, ServiceMarker);
    let volume_proxy =
        service.connect_to_instance(instance).context("failed to connect to instance")?;
    volume_proxy.connect_to_volume().context("failed to connect to volume member")
}

async fn connect_block_client(instance: &str) -> Result<RemoteBlockClient> {
    let block_proxy = connect_block_proxy(instance).await?;
    RemoteBlockClient::new(block_proxy)
        .await
        .map_err(|s| anyhow!("RemoteBlockClient::new failed: {s}"))
}

/// Builds the `DeviceHolder` Fxfs operates on, clamped to exactly the byte range the ownership
/// decision authorised. For a legacy whole-device store that is the device itself; for a store
/// inside our GPT layout it is a `RangedDevice` window, so every Fxfs read and write is bounded
/// by the storage layer rather than merely by our own good intentions — in particular Fxfs can
/// never reach back over the ESP.
async fn device_for(instance: &str, region: Region) -> Result<DeviceHolder> {
    let remote = connect_block_client(instance).await?;
    let block_size = remote.block_size() as u64;
    if block_size == 0 {
        return Err(anyhow!("device reported block_size=0"));
    }
    let device_size = remote.block_count().saturating_mul(block_size);
    let device = BlockDevice::new(remote, false)
        .await
        .map_err(|e| anyhow!("BlockDevice::new failed: {e}"))?;
    if region.is_whole_device(device_size) {
        return Ok(DeviceHolder::new(device));
    }
    let source: Arc<dyn Device> = Arc::new(device);
    let ranged = RangedDevice::new(source, region.start..region.end()).map_err(|e| {
        anyhow!("RangedDevice::new({}..{}) failed: {e}", region.start, region.end())
    })?;
    Ok(DeviceHolder::new(ranged))
}

/// Opens the Fxfs container in `region` and creates a bare "blob" volume iff it is absent.
/// Returns Ok(true) if this call created it (fresh/half-provisioned), Ok(false) if it was
/// already present (reboot / already provisioned).
async fn ensure_blob_volume_on_existing_fxfs(instance: &str, region: Region) -> Result<bool> {
    let fs = FxFilesystem::open(device_for(instance, region).await?)
        .await
        .map_err(|e| anyhow!("FxFilesystem::open (existing) failed: {e}"))?;
    let created = async {
        let root_vol = root_volume(fs.clone())
            .await
            .map_err(|e| anyhow!("root_volume (existing) failed: {e}"))?;
        let present = root_vol
            .volume_directory()
            .lookup(BLOB_VOLUME_NAME)
            .await
            .map_err(|e| anyhow!("blob volume lookup failed: {e}"))?
            .is_some();
        if present {
            return Ok::<bool, anyhow::Error>(false);
        }
        root_vol
            .new_volume(
                BLOB_VOLUME_NAME,
                NewChildStoreOptions {
                    options: StoreOptions { crypt: None, ..Default::default() },
                    ..Default::default()
                },
            )
            .await
            .map_err(|e| anyhow!("new_volume (blob, recovery) failed: {e}"))?;
        Ok(true)
    }
    .await;
    // Always close the filesystem cleanly so the disk is fully released before we hand off,
    // even if the blob check/creation failed.
    let close = fs.close().await;
    let created = created?;
    close.map_err(|e| anyhow!("close (existing) failed: {e}"))?;
    Ok(created)
}

/// Formats `region` as Fxfs and creates the bare "blob" volume, then closes. `region` is always
/// a range the ownership decision explicitly authorised — never simply "the disk".
async fn format_and_create_blob(instance: &str, region: Region) -> Result<()> {
    let holder = device_for(instance, region).await?;

    trace("FORMAT-START");
    let fs = FxFilesystem::new_empty(holder)
        .await
        .map_err(|e| anyhow!("FxFilesystem::new_empty (format) failed: {e}"))?;
    trace("FORMAT-DONE");
    emit("CERISE-PROVISION-FORMAT-OK\n");

    let create = async {
        let root_vol = root_volume(fs.clone())
            .await
            .map_err(|e| anyhow!("root_volume failed: {e}"))?;
        root_vol
            .new_volume(
                BLOB_VOLUME_NAME,
                NewChildStoreOptions {
                    options: StoreOptions { crypt: None, ..Default::default() },
                    ..Default::default()
                },
            )
            .await
            .map_err(|e| anyhow!("new_volume (blob) failed: {e}"))?;
        Ok::<(), anyhow::Error>(())
    }
    .await;
    let close = fs.close().await;
    create?;
    close.map_err(|e| anyhow!("close (post-format) failed: {e}"))?;
    emit("CERISE-PROVISION-BLOB-VOLUME-OK\n");
    Ok(())
}

/// One probe read, owning its bytes. The three states are NOT interchangeable: `Absent` is a
/// fact about a small device, `Unreadable` is a hole in our evidence, and only the first may
/// ever lead to a destructive decision. See ownership.rs for why that distinction is the fix
/// for a real bug (a transient read error used to reformat a disk that was already ours).
enum RawProbe {
    Read(Vec<u8>),
    Absent,
    Unreadable,
}

impl RawProbe {
    fn as_probe(&self) -> Probe<'_> {
        match self {
            RawProbe::Read(b) => Probe::Read(b),
            RawProbe::Absent => Probe::Absent,
            RawProbe::Unreadable => Probe::Unreadable,
        }
    }
}

/// Reads exactly `len` bytes at device-absolute `offset`, handling block alignment itself.
/// A location past the end of the device is `Absent`; a read that FAILS is `Unreadable`.
async fn read_range(client: &RemoteBlockClient, offset: u64, len: usize) -> RawProbe {
    let block_size = client.block_size() as u64;
    if block_size == 0 || len == 0 {
        return RawProbe::Unreadable;
    }
    let Some(device_size) = client.block_count().checked_mul(block_size) else {
        return RawProbe::Unreadable;
    };
    let Some(end) = offset.checked_add(len as u64) else { return RawProbe::Absent };
    if end > device_size {
        return RawProbe::Absent; // Device too small for this location.
    }
    let aligned_start = (offset / block_size) * block_size;
    let head = (offset - aligned_start) as usize;
    let aligned_len = ((head + len) as u64).div_ceil(block_size) * block_size;
    if aligned_start + aligned_len > device_size {
        return RawProbe::Absent;
    }
    let mut buf = vec![0u8; aligned_len as usize];
    match client.read_at(MutableBufferSlice::Memory(&mut buf), aligned_start).await {
        Ok(()) => RawProbe::Read(buf[head..head + len].to_vec()),
        Err(_) => RawProbe::Unreadable,
    }
}

/// Reads one block for an Fxfs superblock magic probe.
async fn probe_superblock(client: &RemoteBlockClient, offset: u64) -> RawProbe {
    read_range(client, offset, client.block_size() as usize).await
}

/// Looks for a partition table THIS provisioner wrote, and where it put Fxfs.
///
/// Deliberately narrow (see layout.rs): signature + header CRC + entry-array CRC + a partition
/// of our type GUID, or "not ours". No free-space search, no foreign-partition analysis. It
/// exists so a disk we laid out last boot is recognised this boot instead of being re-claimed.
/// The outcome of trying ONE copy of the table.
enum OneCopy {
    /// A valid GPT carrying a partition of our type.
    Ours(Region),
    /// A valid, readable GPT that has no partition of our type (a foreign table, or no table).
    ValidNotOurs,
    /// The header block was readable but is not a valid GPT header — a signature with a bad
    /// CRC, absurd geometry, or an entry array we could not make sense of.
    Damaged,
    /// A read failed.
    Unreadable,
}

async fn read_one_copy(client: &RemoteBlockClient, header_lba: u64) -> OneCopy {
    let block_size = client.block_size() as u64;
    let Some(header_offset) = header_lba.checked_mul(block_size) else { return OneCopy::Damaged };
    let header = match read_range(client, header_offset, block_size as usize).await {
        RawProbe::Read(b) => b,
        // A device too small to hold this copy: a fact, not a hole.
        RawProbe::Absent => return OneCopy::ValidNotOurs,
        RawProbe::Unreadable => return OneCopy::Unreadable,
    };
    if layout::validated_header(&header).is_none() {
        // No signature at all means simply "no GPT here" — an MBR disk, a raw filesystem, or a
        // blank device. A signature with a broken header is something else: a table that IS
        // there and that we cannot interpret.
        return if header.len() >= 8 && header[0..8] == layout::GPT_SIGNATURE {
            OneCopy::Damaged
        } else {
            OneCopy::ValidNotOurs
        };
    }
    let Some((entry_lba, array_len)) = layout::entry_array_location(&header) else {
        return OneCopy::Damaged;
    };
    let Some(entries_offset) = entry_lba.checked_mul(block_size) else { return OneCopy::Damaged };
    let entries = match read_range(client, entries_offset, array_len).await {
        RawProbe::Read(b) => b,
        // The header says there is an entry array and it is not on the device. That is a
        // self-inconsistent table, not a clean "no table".
        RawProbe::Absent => return OneCopy::Damaged,
        RawProbe::Unreadable => return OneCopy::Unreadable,
    };
    match layout::find_fxfs_partition(&header, &entries, block_size) {
        Some(range) => OneCopy::Ours(Region::new(range.start, range.end - range.start)),
        // A valid table without a partition of ours. The entry-array CRC checked out, so this
        // is a real answer, not a guess.
        None => OneCopy::ValidNotOurs,
    }
}

async fn read_our_table(client: &RemoteBlockClient) -> TableEvidence {
    let block_size = client.block_size() as u64;
    let block_count = client.block_count();
    if block_size == 0 || block_count == 0 {
        return TableEvidence::Unreadable;
    }

    // BOTH COPIES, for exactly the reason we probe both Fxfs superblocks: a damaged primary
    // must not demote an owned disk to claimable. GPT keeps a full second copy at the last
    // block precisely so this is answerable, and consulting only the primary would reintroduce
    // — one level up, at the table instead of the superblock — the corruption-demotes-to-
    // claimable failure this module exists to prevent.
    let primary = read_one_copy(client, 1).await;
    if let OneCopy::Ours(region) = primary {
        return TableEvidence::Ours(region);
    }
    let backup = read_one_copy(client, block_count - 1).await;
    if let OneCopy::Ours(region) = backup {
        emit("CERISE-PROVISION-GPT-PRIMARY-BAD: recovered our layout from the backup GPT\n");
        return TableEvidence::Ours(region);
    }

    match (primary, backup) {
        // Any failed read leaves us unable to say the disk is not ours.
        (OneCopy::Unreadable, _) | (_, OneCopy::Unreadable) => TableEvidence::Unreadable,
        // A table is present in at least one copy and neither copy could be interpreted.
        // Missing evidence never authorises a write, and a corrupt table is missing evidence:
        // the partition it described could well have been ours.
        (OneCopy::Damaged, _) | (_, OneCopy::Damaged) => TableEvidence::Damaged,
        // Both copies read cleanly and neither is ours.
        _ => TableEvidence::NotOurs,
    }
}

/// Everything we learned about one disk, owning its buffers so `ownership::Evidence` can borrow.
struct Survey {
    whole_device: Region,
    sniff_says_fxfs: bool,
    table: TableEvidence,
    whole_a: RawProbe,
    whole_b: RawProbe,
    part_a: RawProbe,
    part_b: RawProbe,
}

impl Survey {
    fn evidence(&self) -> Evidence<'_> {
        Evidence {
            whole_device: self.whole_device,
            sniff_says_fxfs: self.sniff_says_fxfs,
            table: self.table,
            whole_a: self.whole_a.as_probe(),
            whole_b: self.whole_b.as_probe(),
            part_a: self.part_a.as_probe(),
            part_b: self.part_b.as_probe(),
        }
    }
}

/// Gathers all the ownership evidence for `instance`, reading nothing twice and writing nothing.
///
/// `detect_disk_format`'s sniff reads ONLY superblock A at device offset 0 and maps every error
/// to `Unknown`, so it is used as positive evidence only; the independent probes below are what
/// keep a corrupt-but-ours disk owned. The probes are taken at BOTH superblock offsets, and —
/// now that a claimed disk keeps its Fxfs inside a partition — both relative to the device and
/// relative to our own partition.
async fn survey(instance: &str) -> Result<Survey> {
    let block_proxy = connect_block_proxy(instance).await?;
    let format = detect_disk_format(&block_proxy).await;
    drop(block_proxy);

    let client = connect_block_client(instance).await?;
    let block_size = client.block_size() as u64;
    if block_size == 0 {
        return Err(anyhow!("device reported block_size=0"));
    }
    let device_size = client
        .block_count()
        .checked_mul(block_size)
        .ok_or_else(|| anyhow!("device reports a nonsensical size"))?;

    let table = read_our_table(&client).await;
    let (part_a, part_b) = match table {
        TableEvidence::Ours(region) => (
            probe_superblock(&client, region.start).await,
            probe_superblock(&client, region.start + ownership::SUPER_BLOCK_B_OFFSET).await,
        ),
        _ => (RawProbe::Absent, RawProbe::Absent),
    };

    Ok(Survey {
        whole_device: Region::new(0, device_size),
        sniff_says_fxfs: format == DiskFormat::Fxfs,
        table,
        whole_a: probe_superblock(&client, 0).await,
        whole_b: probe_superblock(&client, ownership::SUPER_BLOCK_B_OFFSET).await,
        part_a,
        part_b,
    })
}

/// Writes the boot-CAPABLE layout onto `instance` and returns the Fxfs partition's region.
///
/// "Boot-capable", not "bootable", and the distinction is the honest one: this reserves an ESP
/// and leaves it blank. Nothing here creates a FAT32 filesystem in it, and nothing in this tree
/// puts `\EFI\BOOT\BOOTX64.EFI` or a ZBI into it on-target. A disk that has been through this
/// function has somewhere for a bootloader to live and no bootloader.
///
/// Write order is chosen so that a torn write cannot leave a *plausible* table: the backup copy
/// and both entry arrays land first, and the primary header — the thing every tool reads first,
/// and the thing whose CRC blesses the entry array — is written last. Until that final block
/// lands, `read_our_table` sees no valid header and the disk still looks unclaimed, which is the
/// state the retry loop is safe to re-enter.
async fn write_bootable_layout(instance: &str, plan: &layout::LayoutPlan) -> Result<Region> {
    let client = connect_block_client(instance).await?;
    let block_size = client.block_size() as u64;
    let block_count = client.block_count();
    if block_size != plan.block_size || block_count != plan.block_count {
        return Err(anyhow!(
            "device geometry changed under us: planned {} x {}B, now {} x {}B",
            plan.block_count,
            plan.block_size,
            block_count,
            block_size
        ));
    }

    let mut guids = [0u8; 48];
    zx::cprng_draw(&mut guids);
    let mut disk_guid = [0u8; 16];
    let mut esp_guid = [0u8; 16];
    let mut fxfs_guid = [0u8; 16];
    disk_guid.copy_from_slice(&guids[0..16]);
    esp_guid.copy_from_slice(&guids[16..32]);
    fxfs_guid.copy_from_slice(&guids[32..48]);
    // RFC 4122 version 4 / variant bits, in the mixed-endian positions GPT uses.
    for g in [&mut disk_guid, &mut esp_guid, &mut fxfs_guid] {
        g[7] = (g[7] & 0x0F) | 0x40;
        g[8] = (g[8] & 0x3F) | 0x80;
    }

    let img = layout::build_gpt(plan, disk_guid, esp_guid, fxfs_guid);

    emit(&format!(
        "CERISE-PROVISION-LAYOUT: disk {} blocks x {block_size}B; ESP LBA {}..{} ({}); \
         fxfs LBA {}..{} ({})\n",
        block_count,
        plan.esp.first_lba,
        plan.esp.last_lba,
        layout::human(plan.esp.block_count() * block_size),
        plan.fxfs.first_lba,
        plan.fxfs.last_lba,
        layout::human(plan.fxfs.block_count() * block_size),
    ));

    let write = |offset: u64, bytes: &[u8]| {
        let client = &client;
        let bytes = bytes.to_vec();
        async move {
            client
                .write_at(BufferSlice::Memory(&bytes), offset)
                .await
                .map_err(|s| anyhow!("GPT write at byte offset {offset} failed: {s}"))
        }
    };

    trace("GPT-WRITE-START");

    // STEP 1 — scrub the front of the ESP, BEFORE any header is published.
    //
    // Writing a partition table does not touch partition CONTENT, so whatever filesystem used
    // to live at this offset still has its volume boot record sitting there — and we are about
    // to tell the firmware that those bytes are an EFI System Partition. A stale FAT/NTFS/ext
    // superblock inside a region we have declared an ESP is exactly the kind of thing that
    // makes a boot failure hard to read. One megabyte covers any volume boot record plus its
    // backup, and leaves the ESP honestly EMPTY rather than misleadingly occupied.
    //
    // ORDERING MATTERS AND IT IS NOT COSMETIC: this used to run after the primary header, and
    // a crash in that window published a valid table pointing at a stale bootloader — which
    // the resume path (Plan::FormatIn) would never scrub, because it correctly declines to
    // rewrite a table that is already ours. Everything whose stale interpretation matters is
    // now initialised before a header exists to give it meaning.
    // (Nothing here creates a FAT32 filesystem — see the module header: populating the ESP is
    // a separate step that does not exist yet.)
    let scrub_len = layout::ALIGNMENT_BYTES.min(plan.esp.block_count() * block_size);
    let zeros = vec![0u8; scrub_len as usize];
    write(plan.esp.first_lba * block_size, &zeros).await?;

    // STEP 2 — the backup copy and both entry arrays, then the protective MBR.
    write(img.backup_entries_lba * block_size, &img.entries).await?;
    write(img.primary_entries_lba * block_size, &img.entries).await?;
    write(0, &img.protective_mbr).await?;

    // STEP 3 — flush everything the headers will describe BEFORE either header exists. The
    // block protocol makes no ordering promise between un-flushed writes (block_client's
    // write_at takes no barrier), so without this a reordered header could be persisted ahead
    // of the entry array it CRCs.
    client.flush().await.map_err(|s| anyhow!("GPT pre-header flush failed: {s}"))?;

    // STEP 4 — publish. The backup header first, then the primary: the primary is what every
    // tool reads first, so it is the last byte of the transaction to become true.
    write(img.backup_header_lba * block_size, &img.backup_header).await?;
    write(block_size, &img.primary_header).await?;
    client.flush().await.map_err(|s| anyhow!("GPT flush failed: {s}"))?;
    trace("GPT-WRITE-DONE");
    // Say what was and was not done. The ESP is reserved and blank: no FAT32, no boot shim, no
    // ZBI. A reader of this log must not conclude the machine can now boot from this disk.
    emit(
        "CERISE-PROVISION-GPT-OK: layout written; ESP is RESERVED AND EMPTY (no FAT32, no boot \
         shim, no ZBI) — this disk is not yet bootable\n",
    );

    let r = plan.fxfs_bytes();
    Ok(Region::new(r.start, r.end - r.start))
}

/// One full provisioning attempt against `instance`.
///
/// Policy (maintainer decision 2026-07-22, claim shape refined 2026-07-25):
///   * disk IS ours — a legacy whole-device Fxfs store, or a Cerise GPT layout with a store in
///     it — RETAIN: open and verify only. Never reformat, never re-partition. If the container
///     is too corrupt to open, this ERRORS (an owned disk is never demoted; fshost's own
///     corruption handling reformats at most the inner data volumes, never the container).
///   * disk carries OUR table but no store yet (we died mid-provision): format inside the
///     partition the table already reserved. No table rewrite.
///   * disk is NOT ours: whole-disk claim, which now means writing the boot-capable GPT
///     layout (an ESP is RESERVED but left empty) and formatting Fxfs inside its Fxfs
///     partition.
///   * evidence missing (a probe could not be READ): refuse. Never claim on a hole.
///
/// `wrote` is set as soon as this function may have modified a single byte of the disk, so the
/// caller can enforce the one-disk rule (see `try_once`).
/// Idempotent: after a successful claim, the next boot takes the retain path.
async fn provision_instance(instance: &str, wrote: &mut bool) -> Result<()> {
    let survey = survey(instance).await?;
    let plan = ownership::decide(&survey.evidence()).map_err(|e| {
        emit(&format!("CERISE-PROVISION-REFUSED: {e}\n"));
        anyhow!("{e}")
    })?;

    let region = match plan {
        Plan::OpenExisting(region) => {
            // Opening an Fxfs container replays its journal, so this writes.
            *wrote = true;
            match ensure_blob_volume_on_existing_fxfs(instance, region).await? {
                false => emit("CERISE-PROVISION-SKIP\n"),
                true => emit("CERISE-PROVISION-BLOB-VOLUME-OK\n"),
            }
            return Ok(());
        }
        Plan::FormatIn(region) => {
            emit("CERISE-PROVISION-RESUME\n");
            region
        }
        Plan::CreateLayout => {
            emit("CERISE-PROVISION-CLAIM\n");
            // Plan the layout BEFORE writing anything: `plan_layout` is pure and cannot touch
            // the disk, so a refusal here happens with the device still untouched.
            let client = connect_block_client(instance).await?;
            let geometry = (client.block_size() as u64, client.block_count());
            drop(client);
            match layout::plan_layout(geometry.0, geometry.1) {
                Ok(plan) => {
                    *wrote = true;
                    write_bootable_layout(instance, &plan).await?
                }
                // TOO SMALL TO HOLD THE LAYOUT. Say so with the sizes involved — loudly, in the
                // serial log, not as a silent shrug — and then fall back to the layout this
                // provisioner has always written: an Fxfs container occupying the whole device.
                // That is still the same whole-disk claim under the same policy; what it is not
                // is boot-capable, and this is the one place that difference is decided, so it
                // is the one place that has to say it out loud.
                //
                // This is not a nicety. It is what keeps the QEMU storage/pkg gates (256 MiB
                // NVMe images, validation/fshost_boot_test.py:126) on the storage-only shape
                // they were written for, while a real disk gets the boot-capable one.
                //
                // NOTE FOR REVIEW: selecting the layout from the disk SIZE is an interim
                // mechanism, not the end state. The end state is an explicit per-product
                // choice — see the follow-up about fshost being unable to mount a container
                // inside a partition. Only TooSmall falls back; a device that reports a
                // nonsense block size or no blocks at all is a fault, not a small disk, and
                // must never be silently reshaped.
                Err(e @ layout::LayoutError::TooSmall { .. }) => {
                    emit(&format!("CERISE-PROVISION-LAYOUT-REFUSED: {e}\n"));
                    emit(
                        "CERISE-PROVISION-LEGACY-CLAIM: claiming the whole device as a bare Fxfs \
                         container with NO ESP; a machine cannot boot from this disk\n",
                    );
                    *wrote = true;
                    survey.whole_device
                }
                Err(e) => {
                    emit(&format!("CERISE-PROVISION-LAYOUT-REFUSED: {e}\n"));
                    return Err(anyhow!("{e}"));
                }
            }
        }
    };

    *wrote = true;
    format_and_create_blob(instance, region).await
}

async fn try_once(pinned: &mut Option<String>) -> Result<()> {
    trace("LIST-INSTANCES");
    // DETERMINISTIC DEVICE SELECTION:
    // fuchsia_fs::directory::readdir returns entries sorted by name
    // (readdir_inner ends with entries.sort_unstable(); DirEntry orders by
    // name first), so within one enumeration the candidate order is stable and
    // this loop deterministically claims the first (lexicographically
    // smallest) instance that provisions. The names are component_manager-
    // assigned instance ids — stable within a boot, not across boots; cross-
    // boot identity comes from the ownership check (an owned disk is retained
    // whichever position it enumerates at). Metal note: with no USB/eMMC
    // drivers the boot stick and eMMC are invisible — in practice one
    // SATA/NVMe disk is eligible.
    let instances = list_instances().await?;
    if instances.is_empty() {
        return Err(anyhow!("no aggregate-Service instances published yet"));
    }

    // BUG FIX (the error path used to fan out across every disk): this loop used to `continue`
    // on error, so a failure that happened AFTER bytes had already been written to disk A moved
    // straight on and wrote disk B. Only one disk is visible on the laptop today because there
    // are no USB or eMMC drivers — that is driver-coverage luck, not a guarantee, and the boot
    // USB is exactly what appears the day a USB driver lands. Two rules now:
    //   * once any byte has been written to a disk, that disk is PINNED: no other instance is
    //     ever touched, in this attempt or in any later retry;
    //   * a failure after a write aborts the whole enumeration rather than moving on.
    let candidates: Vec<String> = match pinned {
        Some(p) => {
            if !instances.iter().any(|i| i == p) {
                return Err(anyhow!(
                    "pinned disk instance {p} is no longer published; refusing to provision a \
                     different disk after having written to that one"
                ));
            }
            vec![p.clone()]
        }
        None => instances,
    };

    let mut last_err = None;
    for instance in &candidates {
        let mut wrote = false;
        let result = provision_instance(instance, &mut wrote).await;
        if wrote {
            *pinned = Some(instance.clone());
        }
        match result {
            Ok(()) => return Ok(()),
            Err(e) => {
                if wrote {
                    return Err(e.context(format!(
                        "aborting: bytes were already written to disk instance {instance}; \
                         refusing to touch any other disk"
                    )));
                }
                last_err = Some(e);
            }
        }
    }
    Err(last_err.unwrap_or_else(|| anyhow!("no instances tried")))
}

/// Serve the "provisioned" directory capability FOREVER (holding no disk resources). Called
/// only after provisioning has fully completed and the filesystem is closed, so a client
/// reading "/provisioned/ready" is guaranteed the disk was released first.
async fn serve_ready() -> Result<()> {
    let vmo = zx::Vmo::create(READY_CONTENT.len() as u64).context("create ready vmo")?;
    vmo.write(READY_CONTENT, 0).context("write ready vmo")?;
    let mut fs = ServiceFs::new();
    fs.dir("provisioned").add_vmo_file_at(READY_FILE, vmo);
    fs.take_and_serve_directory_handle().context("take_and_serve outgoing dir")?;
    emit("CERISE-PROVISION-READY\n");
    fs.collect::<()>().await;
    Ok(())
}

async fn run() -> Result<()> {
    // The block device (NVMe/AHCI) is not published until its driver binds, ~180-200s into
    // boot on this host; retry discovery until a device appears, then provision it once.
    // Bounded well under the fshost product's QEMU timeout.
    const MAX_ATTEMPTS: u32 = 60;
    const RETRY_DELAY: std::time::Duration = std::time::Duration::from_secs(5);

    let mut last_err = None;
    let mut done = false;
    // Sticky across retries: once we have written to a disk, only that disk is ever touched.
    let mut pinned: Option<String> = None;
    for attempt in 0..MAX_ATTEMPTS {
        match try_once(&mut pinned).await {
            Ok(()) => {
                done = true;
                break;
            }
            Err(e) => {
                last_err = Some(e);
                let _ = attempt;
                fuchsia_async::Timer::new(fuchsia_async::MonotonicInstant::after(
                    RETRY_DELAY.into(),
                ))
                .await;
            }
        }
    }
    if !done {
        return Err(last_err.unwrap_or_else(|| anyhow!("no attempts ran")));
    }
    // Provisioning is complete and the disk is closed; NOW open the readiness gate.
    serve_ready().await
}

fn main() {
    const STACK_SIZE: usize = 16 * 1024 * 1024; // 16 MiB — see header (Fxfs format stack).
    let handle = std::thread::Builder::new()
        .name("fxfs_provisioner-main".to_string())
        .stack_size(STACK_SIZE)
        .spawn(|| {
            let mut executor = fuchsia_async::LocalExecutor::default();
            executor.run_singlethreaded(run())
        })
        .expect("failed to spawn fxfs_provisioner-main thread");
    let result = handle.join().expect("fxfs_provisioner-main thread panicked");
    if let Err(e) = result {
        emit(&format!("CERISE-PROVISION-FAIL: {e:?}\n"));
        std::process::exit(1);
    }
}

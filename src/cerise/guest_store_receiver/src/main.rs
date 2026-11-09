//! guest_store_receiver — the appliance side of pushing a guest image onto the
//! raw guest-image GPT partition, over gRPC.
//!
//! ## What problem this solves, and why the file server could not
//!
//! The VMM reads its guest image out of a **raw GPT partition at byte offsets**,
//! with no filesystem — deliberately, because fshost cannot mount Fxfs inside a
//! partition here and the raw path sidesteps that entirely. The gRPC file
//! server's `Write` puts bytes **into a mounted Fxfs filesystem**. Those are two
//! different destinations, and no amount of routing makes one reach the other. So
//! getting a store onto the partition a machine boots a guest from needs a writer
//! that addresses the partition directly, and this is it.
//!
//! Direction is PUSH: the appliance is the server. A development host stages the
//! store through this component and then asks it to commit. Pull — the appliance
//! fetching pages lazily from a host over gRPC — is a different contract with
//! different failure modes and is not this component.
//!
//! ## The order of operations, which is the whole safety argument
//!
//! 1. **Locate first, write never-yet.** The partition is found by
//!    `guest_store_locate` — settle the aggregated block Service's instance set,
//!    survey EVERY instance, and require exactly one match. Two matches is a
//!    refusal, not a choice. This runs at startup, concurrently with network
//!    bring-up, so its retry budget is spent before any pusher connects.
//! 2. **Stage away from the active image.** Small fixtures use bounded memory.
//!    A disk with the dedicated staging type GUID receives large stores there,
//!    one aligned chunk at a time. Incomplete or rejected bytes never touch the
//!    active guest-image partition.
//! 3. **Decide, once, on the whole payload** (`guest_store_admit`):
//!    a public key must be staged, the manifest's signature must check out
//!    against it, the bytes must be the signed length and hash to the signed
//!    digest, they must decode as a `.cryostore` of exactly that length, and it
//!    must fit the partition.
//! 4. **Only then promote**, copying the checked staged bytes into the active
//!    partition, bounded to its byte range, and flush.
//!
//! A rejection at step 3 issues **no write to the active partition** — not a
//! write that is undone, not a truncated write. Rejected bytes may remain in
//! inactive staging. The refusal gates assert this by inspecting both partition
//! ranges rather than trusting this component's own report.
//!
//! ## What the signature establishes, stated accurately
//!
//! The ed25519 machinery is real and this component only ever *checks*; signing
//! material never ships in the device image. Its authenticity guarantee is only
//! as strong as the key selected by the build. Every marker therefore says
//! **signature-checked against the configured key**, rather than making a
//! stronger claim about key provenance.
//!
//! ## What the routing does and does not contain
//!
//! There is no per-partition capability in this system: no GPT driver, no
//! partition block devices, and the only routable thing is the AGGREGATED
//! `fuchsia.hardware.block.volume.Service`, which hands over every whole disk
//! under anonymized instance names. So the narrowing to one partition happens
//! **in this code**, not in the capability. An out-of-range write is therefore
//! absent rather than impossible, and the containment argument rests on this
//! component being small enough to read.

use anyhow::{anyhow, Context, Result};
use block_client::{BlockClient as _, BufferSlice, MutableBufferSlice, RemoteBlockClient};
use cerise_network_bootstrap::BootstrapPolicy;
use cerise_network_bootstrap_fuchsia::{
    bootstrap, FuchsiaBootstrapConfig, FuchsiaBootstrapResult, Ipv4Configuration,
};
use fidl_fuchsia_hardware_block_volume::ServiceMarker;
use fuchsia_component::client::{open_service, Service};
use fuchsia_fs::directory::readdir;
use guest_store_admit::{accept_store, PushRejection, StoreManifest, PUBKEY_PATH};
use guest_store_locate::{DeviceEvidence, LocateError, PartitionRange};
use sha2::{Digest as _, Sha256};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use cerise_hyper_rt::{FasyncExec, FasyncIo};
use hyper_util::service::TowerToHyperService;

use guest_store_proto::cerise::gueststore::v1 as pb;
use pb::guest_store_server::{GuestStore, GuestStoreServer};

/// A distinct port from the file server's 50051, because the two components can
/// and do share a netstack.
const LISTEN_ADDR: &str = "0.0.0.0:50052";

/// The largest payload this will hold in memory.
///
/// The manifest arrives over the same channel as the bytes and cannot be acted
/// on before its signature checks out, so nothing in it may bound this — the
/// bound has to be a local constant, exactly as `ota_updater::MAX_IMAGE_BYTES`
/// is. 256 MiB is generous next to the stores this path carries today and is
/// still a bound; without one, whoever can reach port 50052 can grow this
/// component's heap until it dies.
const MAX_STORE_BYTES: usize = 256 << 20;

/// How long to keep looking for block devices before refusing.
///
/// Generous, and paid concurrently with network bring-up so it costs a pusher
/// nothing. There is no ordering guarantee that a block driver has bound when a
/// child starts: the file server records the device appearing ~180 s into boot on
/// real hardware.
const ACQUIRE_POLLS: u32 = 400;
const POLL_DELAY: Duration = Duration::from_millis(500);

/// Consecutive polls that must agree before the instance set is surveyed.
///
/// What makes a two-disk ambiguity test mean anything: disks bind one at a time,
/// so a scan run at the wrong moment sees one instance where two will exist a
/// moment later, and "exactly one match" would then be satisfied by an incomplete
/// picture rather than by the machine.
const SETTLE_POLLS: u32 = 4;

/// Raw serial write, reserved for the CERISE-* markers the gates grep for
/// byte-for-byte.
fn emit(msg: &str) {
    let msg = format!("{msg}\n");
    // SAFETY: zx_debug_write takes (ptr, len) of readable bytes.
    unsafe {
        zx::sys::zx_debug_write(msg.as_ptr(), msg.len());
    }
}

async fn sleep(secs: f32) {
    fuchsia_async::Timer::new(fuchsia_async::MonotonicInstant::after(
        std::time::Duration::from_secs_f32(secs).into(),
    ))
    .await;
}

/// Load the ed25519 public key (raw 32 bytes) staged into this component's /pkg.
///
/// FAILS CLOSED, like `ota_updater::load_pubkey` and unlike
/// `pkg_resolver::load_pubkey`. There, a missing key degrades to "honour only the
/// trusted in-image base index" — a strictly smaller, safe set. Here a missing
/// key would degrade to "write whatever arrived on port 50052 onto the partition
/// a guest boots from", so absence must be a refusal. The refusal is
/// `PushRejection::NoPubkey`, produced by `accept_store` rather than here, so the
/// fail-closed behaviour is covered by the host tests.
fn load_pubkey() -> Option<[u8; 32]> {
    match std::fs::read(PUBKEY_PATH) {
        Ok(bytes) => match <[u8; 32]>::try_from(bytes.as_slice()) {
            Ok(key) => {
                emit("CERISE-GUEST-STORE-PUBKEY-OK");
                Some(key)
            }
            Err(_) => {
                emit(&format!(
                    "CERISE-GUEST-STORE-PUBKEY-BAD: {PUBKEY_PATH} is {} bytes, expected 32",
                    bytes.len()
                ));
                None
            }
        },
        Err(e) => {
            emit(&format!("CERISE-GUEST-STORE-NO-PUBKEY: {PUBKEY_PATH}: {e}"));
            None
        }
    }
}

// ------------------------------------------------------------------------------
// The disk side. It lives on its own thread with its own executor, addressed by a
// queue, for the same reason `blockstore.rs` does it that way: the block client's
// futures are not `Send`, and a tonic service's handlers must be. A oneshot reply
// IS `Send`, so the queue is the boundary.
// ------------------------------------------------------------------------------

/// A refusal to locate a partition, with a stable token for the log.
#[derive(Clone, Debug)]
struct Refusal {
    token: String,
    detail: String,
}

/// What the disk thread established before it started serving writes.
#[derive(Clone, Debug)]
struct Located {
    instance: String,
    block_size: u64,
    block_count: u64,
    range: PartitionRange,
    /// Inactive scratch space for stores too large to buffer in RAM.
    staging: Option<PartitionRange>,
}

enum DiskRequest {
    WriteActive {
        bytes: Vec<u8>,
        reply: futures::channel::oneshot::Sender<Result<PromoteResult, String>>,
    },
    Stage {
        offset: u64,
        data: Vec<u8>,
        reply: futures::channel::oneshot::Sender<Result<(), String>>,
    },
    Promote {
        manifest: StoreManifest,
        pubkey: Option<[u8; 32]>,
        staged: u64,
        reply: futures::channel::oneshot::Sender<Result<PromoteResult, String>>,
    },
}

struct PromoteResult {
    written: u64,
    root_hash: String,
}

/// The aggregated Service's instance names, sorted so two polls are comparable.
async fn instance_names() -> Result<Vec<String>> {
    let dir = open_service::<ServiceMarker>().context("opening the aggregated block Service")?;
    let entries = readdir(&dir)
        .await
        .context("reading the aggregated block Service directory")?;
    let mut names: Vec<String> = entries.into_iter().map(|e| e.name).collect();
    names.sort();
    Ok(names)
}

async fn open_instance(name: &str) -> Result<RemoteBlockClient> {
    let dir = open_service::<ServiceMarker>().context("re-opening the block Service")?;
    let service = Service::<ServiceMarker>::from_service_dir_proxy(dir, ServiceMarker);
    let volume = service
        .connect_to_instance(name)
        .with_context(|| format!("connecting to block Service instance {name}"))?;
    let block = volume
        .connect_to_volume()
        .context("connecting to the Service's volume member")?;
    RemoteBlockClient::new(block)
        .await
        .map_err(|st| anyhow!("RemoteBlockClient::new: {st}"))
}

async fn read_blocks(client: &RemoteBlockClient, offset: u64, len: u64) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; len as usize];
    client
        .read_at(MutableBufferSlice::Memory(&mut buf), offset)
        .await
        .map_err(|st| anyhow!("read_at({offset}, {len}): {st}"))?;
    Ok(buf)
}

/// What one device turns out to be, as evidence rather than as an answer.
///
/// The two-step split — plan the entry-array read from the header, then find the
/// partition — is not skippable: the entry array's location comes out of the
/// header, so trusting it before the header's own checksum has passed would size
/// a device read from bytes that failed their integrity check. Same shape the
/// updater's ESP locator and the VMM's block reader use, from the same crate.
async fn evidence_for(client: &RemoteBlockClient, wanted: &[u8; 16]) -> DeviceEvidence {
    let bs = client.block_size() as u64;
    let bc = client.block_count();
    if bs == 0 || bs % 512 != 0 {
        return DeviceEvidence::Damaged(LocateError::BadBlockSize);
    }
    if bc < 2 {
        return DeviceEvidence::Unreadable(format!("the device reports {bc} block(s)"));
    }
    let lba1 = match read_blocks(client, bs, bs).await {
        Ok(b) => b,
        Err(err) => return DeviceEvidence::Unreadable(format!("LBA 1: {err:#}")),
    };
    let (entries_off, array_len) = match guest_store_locate::entry_array_read_plan(&lba1, bs) {
        Ok(v) => v,
        Err(err) => return DeviceEvidence::classify(Err(err)),
    };
    // Bound the entry-array read against the DEVICE, not against the table that
    // asked for it. A header is not evidence about the disk it was read from.
    let device_bytes = match bc.checked_mul(bs) {
        Some(v) => v,
        None => return DeviceEvidence::Damaged(LocateError::BadPartitionRange),
    };
    let aligned = match (array_len as u64).checked_next_multiple_of(bs) {
        Some(v) => v,
        None => return DeviceEvidence::Damaged(LocateError::BadEntryGeometry),
    };
    match entries_off.checked_add(aligned) {
        Some(end) if end <= device_bytes => {}
        _ => {
            return DeviceEvidence::Unreadable(format!(
                "the GPT entry array at {entries_off}..+{aligned} does not lie within this \
                 {device_bytes}-byte device"
            ));
        }
    }
    let entries = match read_blocks(client, entries_off, aligned).await {
        Ok(b) => b,
        Err(err) => return DeviceEvidence::Unreadable(format!("entry array: {err:#}")),
    };
    DeviceEvidence::classify(guest_store_locate::find_partition_by_type(
        &lba1, &entries, bs, bc, wanted,
    ))
}

fn describe(evidence: &DeviceEvidence) -> String {
    match evidence {
        DeviceEvidence::Found(r) => format!(
            "FOUND a guest-image partition at bytes {}..{}",
            r.offset,
            r.end().map(|e| e.to_string()).unwrap_or_else(|| "?".into())
        ),
        DeviceEvidence::Absent(err) => format!("absent ({err})"),
        DeviceEvidence::Damaged(err) => format!("DAMAGED ({err})"),
        DeviceEvidence::Unreadable(msg) => format!("UNREADABLE ({msg})"),
    }
}

/// Waits for the instance set to settle, surveys every member, and chooses at
/// most one — or refuses.
///
/// `select_sole_device`'s rules apply verbatim and are not restated here. Note the
/// one asymmetry they encode, because it is easy to misread as a hole: a single
/// positive match wins even if a SIBLING disk was unreadable, since inconclusive
/// evidence can only undermine a negative conclusion. Two positive matches is
/// always a refusal.
async fn locate(wanted: &[u8; 16]) -> Result<(Located, RemoteBlockClient), Refusal> {
    let mut settled: Vec<String> = Vec::new();
    let mut agree = 0u32;
    let mut last_err: Option<String> = None;
    for poll in 0..ACQUIRE_POLLS {
        let names = match instance_names().await {
            Ok(n) => n,
            Err(err) => {
                last_err = Some(format!("{err:#}"));
                Vec::new()
            }
        };
        if !names.is_empty() && names == settled {
            agree += 1;
        } else {
            agree = 0;
            settled = names;
        }
        if agree >= SETTLE_POLLS {
            break;
        }
        if poll == 0 || poll % 40 == 39 {
            emit(&format!(
                "CERISE-GUEST-STORE-WAIT: poll {} of {ACQUIRE_POLLS}: {} block Service \
                 instance(s) published{}",
                poll + 1,
                settled.len(),
                last_err
                    .as_ref()
                    .map(|e| format!(" (last error: {e})"))
                    .unwrap_or_default(),
            ));
        }
        sleep(POLL_DELAY.as_secs_f32()).await;
    }
    if settled.is_empty() {
        return Err(Refusal {
            token: "no-block-instances".to_owned(),
            detail: format!(
                "no block Service instance was ever published in {ACQUIRE_POLLS} poll(s){}. \
                 The capability may not be routed, or no block driver bound",
                last_err
                    .map(|e| format!("; last error: {e}"))
                    .unwrap_or_default()
            ),
        });
    }

    // The settled instance COUNT, printed before anything is surveyed, so an
    // ambiguity gate can tell "the selector accepted two matches" from "the
    // second disk had not bound when the scan ran".
    emit(&format!(
        "CERISE-GUEST-STORE-SETTLED: instances={} — unchanged for {SETTLE_POLLS} consecutive \
         polls, so this is the set the selection rule is applied to: {settled:?}",
        settled.len(),
    ));

    let mut survey: Vec<(String, DeviceEvidence)> = Vec::new();
    let mut clients: Vec<(String, RemoteBlockClient)> = Vec::new();
    for name in &settled {
        match open_instance(name).await {
            Err(err) => {
                survey.push((name.clone(), DeviceEvidence::Unreadable(format!("{err:#}"))));
            }
            Ok(client) => {
                let evidence = evidence_for(&client, wanted).await;
                emit(&format!(
                    "CERISE-GUEST-STORE-SURVEY: instance {name} — block_size {}, block_count \
                     {}, evidence {}",
                    client.block_size(),
                    client.block_count(),
                    describe(&evidence),
                ));
                survey.push((name.clone(), evidence));
                clients.push((name.clone(), client));
            }
        }
    }

    let selection = match guest_store_locate::select_sole_device(&survey) {
        Ok(s) => s,
        Err(err) => {
            let refusal = Refusal {
                token: err.token().to_owned(),
                detail: format!("{err}"),
            };
            for (_, client) in clients {
                let _ = client.close().await;
            }
            return Err(refusal);
        }
    };

    let mut chosen = None;
    for (name, client) in clients {
        if name == selection.instance && chosen.is_none() {
            chosen = Some(client);
        } else {
            let _ = client.close().await;
        }
    }
    let client = chosen.ok_or_else(|| Refusal {
        token: "selected-instance-vanished".to_owned(),
        detail: format!(
            "instance {} was selected and then not found among the clients this scan opened; \
             refusing rather than re-opening, because a second open is a second chance to get \
             a different device",
            selection.instance
        ),
    })?;

    let staging = match evidence_for(&client, &boot_layout::GUEST_STORE_STAGING_TYPE_GUID).await {
        DeviceEvidence::Found(range) => Some(range),
        DeviceEvidence::Absent(LocateError::NotPresent) => None,
        other => {
            return Err(Refusal {
                token: "bad-staging-partition".to_owned(),
                detail: format!(
                    "the selected disk's staging partition is {}",
                    describe(&other)
                ),
            });
        }
    };
    let located = Located {
        instance: selection.instance,
        block_size: client.block_size() as u64,
        block_count: client.block_count(),
        range: selection.range,
        staging,
    };
    if located.range.offset % located.block_size != 0 {
        return Err(Refusal {
            token: "partition-not-block-aligned".to_owned(),
            detail: format!(
                "the located partition starts at byte {}, which is not a multiple of the \
                 device's {}-byte block size",
                located.range.offset, located.block_size
            ),
        });
    }
    if let Some(staging) = located.staging {
        if staging.offset % located.block_size != 0 {
            return Err(Refusal {
                token: "staging-not-block-aligned".to_owned(),
                detail: format!(
                    "the staging partition starts at byte {}, not a multiple of {}",
                    staging.offset, located.block_size
                ),
            });
        }
        let target_end = located.range.offset + located.range.len;
        let staging_end = staging.offset + staging.len;
        if located.range.offset < staging_end && staging.offset < target_end {
            return Err(Refusal {
                token: "staging-overlaps-target".to_owned(),
                detail: format!(
                    "staging {}..{} overlaps active guest image {}..{}",
                    staging.offset, staging_end, located.range.offset, target_end
                ),
            });
        }
    }
    Ok((located, client))
}

/// The write itself: the store at the start of the partition, block padded.
///
/// Three bounds, all of them re-checked here even though `accept_store` already
/// passed. This is the last line before a device write and it is cheap; a future
/// caller that skipped the admission decision gets an error rather than a
/// scribbled disk.
///
/// The tail padding is deliberate and it is ZEROS rather than a read-modify-write
/// of what is already there. A block device takes whole blocks, so a store whose
/// length is not a block multiple has to be padded with something; zeros are the
/// only choice that does not carry over bytes of a PREVIOUS store into the tail
/// of this one. The reader is bounded by the header's `total_len`, so it never
/// looks at the padding — but "never looked at" is a property of today's reader
/// and "was not left there" is a property of the disk.
async fn write_store(client: &RemoteBlockClient, located: &Located, store: &[u8]) -> Result<u64> {
    let bs = located.block_size;
    let len = store.len() as u64;
    anyhow::ensure!(len > 0, "refusing to write a zero-length store");
    anyhow::ensure!(
        len <= located.range.len,
        "the store is {len} bytes and the partition is {}",
        located.range.len
    );
    let padded = len
        .checked_next_multiple_of(bs)
        .context("rounding the store length up to a block overflows")?;
    // The PADDED length must fit too, not just the store: a store that ends one
    // byte before the partition's end still writes a whole final block.
    anyhow::ensure!(
        padded <= located.range.len,
        "the store is {len} bytes, {padded} once block padded, and the partition is {}",
        located.range.len
    );
    let end = located
        .range
        .offset
        .checked_add(padded)
        .context("the write range overflows u64")?;
    let device_bytes = located
        .block_count
        .checked_mul(bs)
        .context("the device geometry overflows u64")?;
    anyhow::ensure!(
        end <= device_bytes,
        "the write would run to byte {end} of a {device_bytes}-byte device"
    );

    let mut buf = store.to_vec();
    buf.resize(padded as usize, 0);
    client
        .write_at(BufferSlice::Memory(&buf), located.range.offset)
        .await
        .map_err(|st| anyhow!("write_at({}, {padded}): {st}", located.range.offset))?;
    client
        .flush()
        .await
        .map_err(|st| anyhow!("flush after writing {padded} bytes: {st}"))?;
    Ok(padded)
}

async fn stage_chunk(
    client: &RemoteBlockClient,
    located: &Located,
    offset: u64,
    data: &[u8],
) -> Result<()> {
    let range = located
        .staging
        .context("this disk has no guest-store staging partition")?;
    anyhow::ensure!(!data.is_empty(), "an empty staging chunk makes no progress");
    anyhow::ensure!(
        offset % located.block_size == 0 && data.len() as u64 % located.block_size == 0,
        "staging chunks and offsets must be aligned to {} bytes",
        located.block_size
    );
    let end = offset
        .checked_add(data.len() as u64)
        .context("staging range overflow")?;
    anyhow::ensure!(
        end <= range.len,
        "staging write ends at {end}, past the {}-byte staging partition",
        range.len
    );
    let disk_offset = range
        .offset
        .checked_add(offset)
        .context("staging device offset overflow")?;
    client
        .write_at(BufferSlice::Memory(data), disk_offset)
        .await
        .map_err(|st| anyhow!("staging write_at({disk_offset}, {}): {st}", data.len()))?;
    Ok(())
}

async fn promote_staged(
    client: &RemoteBlockClient,
    located: &Located,
    manifest: &StoreManifest,
    pubkey: Option<&[u8; 32]>,
    staged: u64,
) -> Result<PromoteResult> {
    let staging = located
        .staging
        .context("this disk has no guest-store staging partition")?;
    let bs = located.block_size;
    anyhow::ensure!(
        staged > 0 && staged <= staging.len,
        "invalid staged length {staged}"
    );
    anyhow::ensure!(
        staged % bs == 0,
        "the staged store length {staged} is not block-aligned to {bs}"
    );
    guest_store_admit::check_manifest_signature(manifest, pubkey).map_err(|e| anyhow!("{e}"))?;

    const CHUNK: u64 = 4 << 20;
    let mut hasher = Sha256::new();
    let mut offset = 0;
    while offset < staged {
        let len = (staged - offset).min(CHUNK);
        let bytes = read_blocks(client, staging.offset + offset, len).await?;
        hasher.update(&bytes);
        offset += len;
    }
    let digest = cerise_signing::to_hex(&hasher.finalize());

    let head_len = bs.max(cryogen_format::HEADER_LEN as u64);
    let head = read_blocks(client, staging.offset, head_len).await?;
    let header = cryogen_format::Header::decode(&head)
        .map_err(|e| anyhow!("staged payload is not a guest store: {e}"))?;
    let index_len = header.index_len();
    anyhow::ensure!(
        index_len <= staged,
        "store index is {index_len} bytes in {staged} staged"
    );
    let index_read = index_len
        .checked_next_multiple_of(bs)
        .context("rounding staged index length")?;
    let mut index = read_blocks(client, staging.offset, index_read).await?;
    index.truncate(index_len as usize);

    guest_store_admit::accept_staged_store(
        manifest,
        pubkey,
        staged,
        &digest,
        &index,
        located.range.len,
    )
    .map_err(|e| anyhow!("{e}"))?;

    let root_hash = cerise_signing::to_hex(&header.root_hash);
    offset = 0;
    while offset < staged {
        let len = (staged - offset).min(CHUNK);
        let bytes = read_blocks(client, staging.offset + offset, len).await?;
        client
            .write_at(BufferSlice::Memory(&bytes), located.range.offset + offset)
            .await
            .map_err(|st| {
                anyhow!(
                    "active write_at({}, {len}): {st}",
                    located.range.offset + offset
                )
            })?;
        offset += len;
    }
    client
        .flush()
        .await
        .map_err(|st| anyhow!("flush promoted store: {st}"))?;
    Ok(PromoteResult {
        written: staged,
        root_hash,
    })
}

/// The disk thread's body. Everything holding a Zircon object lives inside this
/// future, so all of them are dropped before `run_singlethreaded` returns.
async fn disk_serve(
    wanted: [u8; 16],
    ready: futures::channel::oneshot::Sender<Result<Located, Refusal>>,
    mut requests: futures::channel::mpsc::UnboundedReceiver<DiskRequest>,
) -> Result<()> {
    use futures::StreamExt as _;

    let (located, client) = match locate(&wanted).await {
        Ok(v) => v,
        Err(refusal) => {
            let token = refusal.token.clone();
            let _ = ready.send(Err(refusal));
            // Nothing to serve: without a partition there is no legal write, and
            // a queue that accepted requests it could never satisfy would only
            // delay the same answer.
            return Err(anyhow!("no guest-image partition: {token}"));
        }
    };
    let instance = located.instance.clone();
    if ready.send(Ok(located.clone())).is_err() {
        return Err(anyhow!(
            "nobody is waiting for the guest-image partition's location"
        ));
    }

    while let Some(req) = requests.next().await {
        match req {
            DiskRequest::WriteActive { bytes, reply } => {
                let result = async {
                    let written = write_store(&client, &located, &bytes).await?;
                    let root_hash = guest_store_admit::root_hash_hex(&bytes).unwrap_or_default();
                    Ok(PromoteResult { written, root_hash })
                }
                .await
                .map_err(|e: anyhow::Error| format!("{e:#}"));
                let _ = reply.send(result);
            }
            DiskRequest::Stage {
                offset,
                data,
                reply,
            } => {
                let result = stage_chunk(&client, &located, offset, &data)
                    .await
                    .map_err(|e| format!("{e:#}"));
                let _ = reply.send(result);
            }
            DiskRequest::Promote {
                manifest,
                pubkey,
                staged,
                reply,
            } => {
                let result = promote_staged(&client, &located, &manifest, pubkey.as_ref(), staged)
                    .await
                    .map_err(|e| format!("{e:#}"));
                let _ = reply.send(result);
            }
        }
    }

    let closed = client.close().await;
    emit(&format!(
        "CERISE-GUEST-STORE-DISK-END: released every proxy held for instance {instance} \
         (close: {closed:?})"
    ));
    Ok(())
}

// ------------------------------------------------------------------------------
// The gRPC service.
// ------------------------------------------------------------------------------

/// How long a staging buffer must sit untouched before another push may take it
/// over.
///
/// Both directions of this are real. Without a takeover at all, one interrupted
/// push (a pusher that died between `Stage` and `Commit`) would wedge the
/// appliance until it was rebooted, and there is no session teardown signal to
/// notice that with. Without a delay, a second push would silently reset a first
/// one that was still in flight. So: a fresh push takes over a buffer that has
/// been idle this long, and is refused otherwise.
const STAGE_TAKEOVER_IDLE_NANOS: i64 = 30_000_000_000;

/// The staging buffer.
///
/// TWO CLIENTS PUSHING AT ONCE is the obvious hazard, and it is contained twice
/// over. Correctness first: `Commit` checks a signed digest over the FINAL
/// buffer, so any interleaving that produced a mixture fails the digest and
/// nothing is written — that is what makes concurrency safe, and it does not
/// depend on the rules below. The rules below make it LOUD rather than merely
/// safe: a second push that starts while a first is live is refused outright
/// instead of quietly resetting it, and any `Stage` whose offset does not match
/// what is held is refused without changing anything.
///
/// What is deliberately NOT added is a session identifier. It would not close the
/// hole it appears to — nothing in `(offset, data)` attributes a call to a
/// client, and an id a client chooses is an id another client can send — so it
/// would buy a state machine and the appearance of a guarantee. Real attribution
/// needs an authenticated peer, which is a different piece of work.
#[derive(Default)]
struct Staging {
    bytes: Vec<u8>,
    staged: u64,
    in_flight: bool,
    /// Monotonic nanoseconds at the last accepted `Stage`.
    last_touch_nanos: i64,
}

impl Staging {
    fn is_live(&self, now_nanos: i64) -> bool {
        self.staged != 0
            && now_nanos.saturating_sub(self.last_touch_nanos) < STAGE_TAKEOVER_IDLE_NANOS
    }
}

/// Clears the transient in-flight bit even if tonic cancels a `Stage` future.
///
/// The staged byte count is intentionally left optimistic on cancellation: the
/// disk worker owns the already-queued write and processes later requests after
/// it. If that write ultimately fails, a later Commit's full digest check still
/// prevents promotion.
struct StageFlight {
    staging: Arc<Mutex<Staging>>,
    armed: bool,
}

impl StageFlight {
    fn finish(mut self, reset: bool) -> Result<(), tonic::Status> {
        let mut staging = self
            .staging
            .lock()
            .map_err(|_| tonic::Status::internal("the staging state lock is poisoned"))?;
        staging.in_flight = false;
        if reset {
            staging.staged = 0;
        }
        self.armed = false;
        Ok(())
    }
}

impl Drop for StageFlight {
    fn drop(&mut self) {
        if self.armed {
            if let Ok(mut staging) = self.staging.lock() {
                staging.in_flight = false;
            }
        }
    }
}

#[derive(Clone)]
struct Receiver {
    /// The partition to write, or why there is none. `Err` is served rather than
    /// fatal, so that a pusher is TOLD why instead of finding a closed port —
    /// the same reasoning the file server records for serving without a mount.
    target: Arc<Result<Located, Refusal>>,
    pubkey: Option<[u8; 32]>,
    staging: Arc<Mutex<Staging>>,
    disk: futures::channel::mpsc::UnboundedSender<DiskRequest>,
}

impl Receiver {
    fn located(&self) -> Result<&Located, tonic::Status> {
        match self.target.as_ref() {
            Ok(l) => Ok(l),
            // FAILED_PRECONDITION rather than INTERNAL/UNAVAILABLE: the receiver
            // is working exactly as designed and no retry will help — the system
            // state has to change (a disk carrying exactly one guest-image
            // partition).
            Err(r) => Err(tonic::Status::failed_precondition(format!(
                "this appliance has no guest-image partition to write: {} ({})",
                r.detail, r.token
            ))),
        }
    }
}

#[tonic::async_trait]
impl GuestStore for Receiver {
    async fn stage(
        &self,
        request: tonic::Request<pb::StageRequest>,
    ) -> Result<tonic::Response<pb::StageResponse>, tonic::Status> {
        // Refuse before accumulating anything if there is nowhere to put it: a
        // pusher that has streamed 500 MiB and only then learns there is no
        // partition has been told too late.
        let located = self.located()?.clone();
        let req = request.into_inner();
        let disk_backed = located.staging.is_some();
        let end = req
            .offset
            .checked_add(req.data.len() as u64)
            .ok_or_else(|| tonic::Status::out_of_range("the staged byte range overflows"))?;
        let now = zx::MonotonicInstant::get().into_nanos();
        {
            let mut staging = self
                .staging
                .lock()
                .map_err(|_| tonic::Status::internal("the staging buffer's lock is poisoned"))?;
            if staging.in_flight {
                return Err(tonic::Status::aborted(
                    "a staging write is already in flight",
                ));
            }
            if req.offset == 0 {
                if staging.is_live(now) {
                    return Err(tonic::Status::aborted(format!(
                        "another push is in flight ({} bytes staged); a push may take over only \
                         after {} idle seconds",
                        staging.staged,
                        STAGE_TAKEOVER_IDLE_NANOS / 1_000_000_000,
                    )));
                }
                staging.bytes.clear();
                staging.staged = 0;
            } else if req.offset != staging.staged {
                return Err(tonic::Status::out_of_range(format!(
                    "Stage at offset {} but {} bytes are staged",
                    req.offset, staging.staged,
                )));
            }
            let limit = located
                .staging
                .map(|r| r.len)
                .unwrap_or(MAX_STORE_BYTES as u64);
            if end > limit {
                staging.bytes.clear();
                staging.staged = 0;
                return Err(tonic::Status::resource_exhausted(format!(
                    "the pushed store ends at {end}, past the {limit}-byte staging capacity"
                )));
            }
            if disk_backed {
                if req.offset % located.block_size != 0
                    || req.data.len() as u64 % located.block_size != 0
                {
                    return Err(tonic::Status::invalid_argument(format!(
                        "disk-backed Stage requires offsets and chunks aligned to {} bytes",
                        located.block_size
                    )));
                }
                staging.in_flight = true;
                staging.staged = end;
                staging.last_touch_nanos = now;
            } else {
                staging.bytes.extend_from_slice(&req.data);
                staging.staged = end;
                staging.last_touch_nanos = now;
                return Ok(tonic::Response::new(pb::StageResponse { staged: end }));
            }
        }

        let flight = StageFlight {
            staging: self.staging.clone(),
            armed: true,
        };
        let (reply, rx) = futures::channel::oneshot::channel();
        if self
            .disk
            .unbounded_send(DiskRequest::Stage {
                offset: req.offset,
                data: req.data,
                reply,
            })
            .is_err()
        {
            flight.finish(true)?;
            return Err(tonic::Status::internal("the disk thread's queue is closed"));
        }
        let result = rx
            .await
            .map_err(|_| tonic::Status::internal("the disk thread dropped a staging reply"))?;
        if let Err(err) = result {
            flight.finish(true)?;
            return Err(tonic::Status::internal(err));
        }
        flight.finish(false)?;
        Ok(tonic::Response::new(pb::StageResponse { staged: end }))
    }

    async fn commit(
        &self,
        request: tonic::Request<pb::CommitRequest>,
    ) -> Result<tonic::Response<pb::CommitResponse>, tonic::Status> {
        let located = self.located()?.clone();
        let manifest: StoreManifest = serde_json::from_str(&request.into_inner().manifest_json)
            .map_err(|e| {
                emit("CERISE-GUEST-STORE-REJECT: malformed-manifest");
                tonic::Status::invalid_argument(format!("the manifest is not valid JSON: {e}"))
            })?;

        // Commit CONSUMES the staging state, from here on. A rejected payload
        // therefore does not linger to be committed again under a different
        // manifest, and any memory-backed bytes are released at the moment they
        // stop being needed.
        //
        // Precisely: consumption happens once a manifest has PARSED, so a
        // malformed document above changes no state and leaves the staged bytes
        // for a retry with a corrected one. That asymmetry is deliberate — a
        // typo in a manifest should not cost a pusher the upload — and it is
        // stated because the two orderings are indistinguishable from outside
        // until someone retries.
        let (store, staged) = {
            let mut staging = self
                .staging
                .lock()
                .map_err(|_| tonic::Status::internal("the staging buffer's lock is poisoned"))?;
            if staging.in_flight {
                return Err(tonic::Status::aborted("a staging write is still in flight"));
            }
            let staged = staging.staged;
            staging.staged = 0;
            (std::mem::take(&mut staging.bytes), staged)
        };

        let promoted = if located.staging.is_some() {
            let (reply, rx) = futures::channel::oneshot::channel();
            self.disk
                .unbounded_send(DiskRequest::Promote {
                    manifest: manifest.clone(),
                    pubkey: self.pubkey,
                    staged,
                    reply,
                })
                .map_err(|_| tonic::Status::internal("the disk thread's queue is closed"))?;
            rx.await
                .map_err(|_| tonic::Status::internal("the disk thread dropped promotion"))?
                .map_err(|e| {
                    emit(&format!("CERISE-GUEST-STORE-REJECT: staged-store — {e}"));
                    tonic::Status::invalid_argument(e)
                })?
        } else {
            if let Err(rejection) =
                accept_store(&manifest, self.pubkey.as_ref(), &store, located.range.len)
            {
                // The token FIRST, so a gate's regex has it before any of the prose.
                emit(&format!(
                    "CERISE-GUEST-STORE-REJECT: {} — {rejection}",
                    rejection.token()
                ));
                return Err(match rejection {
                    // A payload that is simply wrong is the client's error...
                    PushRejection::Unsigned
                    | PushRejection::MalformedDigest
                    | PushRejection::BadSignature
                    | PushRejection::SizeMismatch { .. }
                    | PushRejection::HashMismatch { .. }
                    | PushRejection::NotAStore { .. }
                    | PushRejection::StoreLenMismatch { .. } => {
                        tonic::Status::invalid_argument(rejection.to_string())
                    }
                    // ...whereas these two are facts about this appliance that no
                    // retry of the same request can change.
                    PushRejection::NoPubkey | PushRejection::DoesNotFit { .. } => {
                        tonic::Status::failed_precondition(rejection.to_string())
                    }
                });
            }
            let (reply, rx) = futures::channel::oneshot::channel();
            self.disk
                .unbounded_send(DiskRequest::WriteActive {
                    bytes: store,
                    reply,
                })
                .map_err(|_| tonic::Status::internal("the disk thread's queue is closed"))?;
            rx.await
                .map_err(|_| tonic::Status::internal("the disk thread dropped a reply"))?
                .map_err(|e| tonic::Status::internal(e))?
        };

        let root_hash = promoted.root_hash;
        let store_len = manifest.size;
        emit(&format!(
            "CERISE-GUEST-STORE-ADMIT: root_hash={root_hash} bytes={store_len} \
             partition={}..{} — signature-checked against the configured key staged at \
             {PUBKEY_PATH}. That establishes that the signing path works; it does not \
             establish authenticity",
            located.range.offset,
            located.range.offset + located.range.len,
        ));

        let written = promoted.written;

        // Asserted fields first: root_hash, then the byte counts, then prose.
        emit(&format!(
            "CERISE-GUEST-STORE-WROTE: root_hash={root_hash} bytes={written} \
             offset={} instance={} — the store is now the content of the guest-image \
             partition",
            located.range.offset, located.instance,
        ));
        Ok(tonic::Response::new(pb::CommitResponse {
            partition_offset: located.range.offset,
            partition_len: located.range.len,
            bytes_written: written,
            root_hash,
        }))
    }

    async fn probe(
        &self,
        _request: tonic::Request<pb::ProbeRequest>,
    ) -> Result<tonic::Response<pb::ProbeResponse>, tonic::Status> {
        let located = self.located()?;
        let staged = self
            .staging
            .lock()
            .map_err(|_| tonic::Status::internal("the staging buffer's lock is poisoned"))?
            .staged;
        Ok(tonic::Response::new(pb::ProbeResponse {
            partition_offset: located.range.offset,
            partition_len: located.range.len,
            staged,
        }))
    }
}

// ------------------------------------------------------------------------------
// Network bring-up — the same sequence the file server and the updater use.
// ------------------------------------------------------------------------------

async fn bring_up_interface() -> Result<FuchsiaBootstrapResult> {
    bootstrap(
        FuchsiaBootstrapConfig {
            interface_name: "gst-eth0",
            ipv4: Ipv4Configuration::Dhcp {
                timeout_seconds: 45,
            },
            // The caller owns its deliberate 30 × 5s full-bootstrap envelope
            // because it emits the guest-store-specific terminal failure marker.
            policy: BootstrapPolicy {
                discovery_attempts: 1,
                retry_delay_seconds: 0,
                reuse_existing_ipv4: true,
            },
            enable_before_address: true,
            observe_slaac: false,
            install_default_route: false,
            check_socket_provider: false,
        },
        None,
    )
    .await
}

// ------------------------------------------------------------------------------

async fn serve(service: Receiver) -> Result<()> {
    let addr: std::net::SocketAddr = LISTEN_ADDR.parse().unwrap();
    let mut listener = fuchsia_async::net::TcpListener::bind(&addr)
        .context("fuchsia_async::net::TcpListener::bind")?;
    emit("CERISE-GUEST-STORE-LISTENING");

    loop {
        let (returned, stream, _peer) = listener.accept().await.context("accept")?;
        listener = returned;
        let service = service.clone();
        fuchsia_async::Task::local(async move {
            let io = FasyncIo::new(stream);
            // gRPC = h2c prior-knowledge -> hyper HTTP/2 directly (NOT auto).
            let hyper_service = TowerToHyperService::new(GuestStoreServer::new(service));
            let _ = hyper::server::conn::http2::Builder::new(FasyncExec)
                .max_concurrent_streams(64)
                .initial_stream_window_size(1u32 << 20)
                .initial_connection_window_size(1u32 << 21)
                .serve_connection(io, hyper_service)
                .await;
        })
        .detach();
    }
}

async fn run() {
    emit("CERISE-GUEST-STORE-START");

    // The disk thread starts FIRST and runs concurrently with network bring-up,
    // so its (generous) retry budget for a block driver that has not bound yet
    // costs a pusher nothing.
    let (write_tx, write_rx) = futures::channel::mpsc::unbounded();
    let (ready_tx, ready_rx) = futures::channel::oneshot::channel();
    let disk_thread = std::thread::Builder::new()
        .name("guest-store-disk".to_owned())
        .spawn(move || {
            // One LocalExecutor on this thread. Executor state is thread-local
            // and each executor makes its own zx::Port, so it does not collide
            // with the one serving gRPC.
            let mut exec = fuchsia_async::LocalExecutor::default();
            let result = exec.run_singlethreaded(disk_serve(
                boot_layout::GUEST_IMAGE_TYPE_GUID,
                ready_tx,
                write_rx,
            ));
            drop(exec);
            if let Err(e) = result {
                emit(&format!("CERISE-GUEST-STORE-DISK-END: {e:#}"));
            }
        });
    if let Err(e) = disk_thread {
        emit(&format!(
            "CERISE-GUEST-STORE-FAIL: spawning the disk thread: {e}"
        ));
        return;
    }

    let mut last: Option<anyhow::Error> = None;
    let mut network = None;
    for _ in 0..30 {
        match bring_up_interface().await {
            Ok(result) if result.reused_existing_ipv4 => {
                emit("CERISE-GUEST-STORE-NIC-SHARED");
                break;
            }
            Ok(result) => {
                let ipv4 = result
                    .ipv4
                    .context("adapter returned no DHCP configuration");
                if let Ok(ipv4) = ipv4 {
                    emit(&format!(
                        "CERISE-GUEST-STORE-DHCP-LEASE={}.{}.{}.{}/{}",
                        ipv4.address[0],
                        ipv4.address[1],
                        ipv4.address[2],
                        ipv4.address[3],
                        ipv4.prefix_len
                    ));
                }
                network = result.lifetime;
                break;
            }
            Err(error) => {
                last = Some(error);
                sleep(5.0).await;
            }
        }
    }
    if network.is_none() && last.is_some() {
        emit(&format!(
            "CERISE-GUEST-STORE-FAIL: network bringup: {last:?}"
        ));
        return;
    }
    let _network = network;

    // The trust root is loaded BEFORE anything can be pushed, so a product that
    // forgot to stage a key says so at startup rather than after a payload has
    // been accumulated.
    let pubkey = load_pubkey();

    let target = match ready_rx.await {
        Ok(t) => t,
        Err(_) => Err(Refusal {
            token: "disk-thread-died".to_owned(),
            detail: "the disk thread ended before it reported a location".to_owned(),
        }),
    };
    match &target {
        Ok(l) => emit(&format!(
            "CERISE-GUEST-STORE-TARGET: partition bytes {}..{} ({} B) instance={} — the ONLY \
             match across every block Service instance; staging={:?}",
            l.range.offset,
            l.range.offset + l.range.len,
            l.range.len,
            l.instance,
            l.staging,
        )),
        Err(r) => emit(&format!(
            "CERISE-GUEST-STORE-NO-TARGET: {} — {}. Serving anyway, so a pusher is told why \
             rather than finding a closed port; every RPC will return FAILED_PRECONDITION",
            r.token, r.detail,
        )),
    }

    let service = Receiver {
        target: Arc::new(target),
        pubkey,
        staging: Arc::new(Mutex::new(Staging::default())),
        disk: write_tx,
    };
    if let Err(e) = serve(service).await {
        emit(&format!("CERISE-GUEST-STORE-FAIL: serve: {e:#}"));
    }
}

fn main() {
    let mut executor = fuchsia_async::LocalExecutor::default();
    executor.run_singlethreaded(async {
        run().await;
        // Park so the component stays alive and its markers stay attributable to
        // a process that is still there.
        loop {
            sleep(3600.0).await;
        }
    });
}

// storage-backed integration: real filesystem backing. Mounts fxfs RW in-process on a real block
// device (the reliable direct-mount path fxfs_probe proved: FxFilesystem::new_empty
// -> encrypted "default" volume via crypt_fxfs), and implements every file-server RPC
// against the mounted volume's ObjectStore using the fxfs object-store API directly.
//
// Path safety (reject ".."/absolute) is enforced by the caller (path_safety.rs);
// this module receives already-sanitized component slices. Filesystem outcomes map to
// FsError, which main.rs turns into the gRPC Status the proto contract specifies.

use anyhow::{anyhow, Context, Result};
use block_client::{BlockClient as _, MutableBufferSlice, RemoteBlockClient};
use fidl_fuchsia_hardware_block_volume::ServiceMarker;
use fuchsia_component::client::{open_service, Service};
use std::ops::Range;
use std::sync::Arc;

use crate::claim;
#[path = "read_range.rs"]
mod read_range;
use crate::resumable_sha256::ResumableSha256;
use crate::status;

use fxfs::filesystem::{FxFilesystem, SyncOptions};
use fxfs::object_handle::{
    ObjectHandle as _, ObjectProperties, ReadObjectHandle as _, WriteObjectHandle as _,
};
use fxfs::object_store::directory::{
    replace_child, replace_child_with_object, Directory, ReplacedChild,
};
use fxfs::object_store::object_record::Timestamp;
use fxfs::object_store::transaction::{lock_keys, LockKey, Options as TxnOptions};
use fxfs::object_store::volume::root_volume;
use fxfs::object_store::{
    DataObjectHandle, HandleOptions, NewChildStoreOptions, ObjectDescriptor, ObjectStore,
    StoreOptions,
};
use storage_device::block_device::BlockDevice;
use storage_device::ranged_device::RangedDevice;
use storage_device::{Device, DeviceHolder};

use crate::crypt::{connect_crypt, provision_crypt_keys};

const VOLUME_NAME: &str = "default";
const DATA_PARTITION_NAME: &str = "cerise";
// Fxfs bounds transaction journal usage, not just payload bytes. A whole gRPC
// import message can exceed that reservation, so split it at the same 1 MiB
// transaction size used by Fxfs' DirectWriter. The enclosing RPC still
// performs one final handle flush, and explicit import Flush remains the
// filesystem durability barrier.
const FXFS_WRITE_CHUNK_BYTES: usize = 1024 * 1024;
const VERIFY_CHUNK_BYTES: usize = 4 * 1024 * 1024;
/// StoreIndex temporarily retains decoded slot/overlay tables alongside the
/// encoded index. Keep that amplification inside a product-level memory
/// budget. The current 136 GiB Win10 source has an 84 MiB index.
const MAX_CRYOSTORE_INDEX_BYTES: u64 = 128 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct VerifiedCryostore {
    pub sha256: String,
    pub encoded_bytes: u64,
    pub root_hash: String,
    pub guest_disk_bytes: u64,
    pub format_version: u32,
}

// gRPC-status-shaped filesystem errors (see proto/fileserver.proto for the mapping).
#[derive(Debug)]
pub enum FsError {
    NotFound,
    AlreadyExists,
    InvalidArgument(String),
    NotADirectory,
    IsADirectory,
    NotEmpty,
    ResourceExhausted(String),
    Internal(anyhow::Error),
}

fn internal(e: impl Into<anyhow::Error>) -> FsError {
    FsError::Internal(e.into())
}

/// File kind returned to the RPC layer (mirrors the proto FileType).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    File,
    Directory,
    Symlink,
    Unknown,
}

fn kind_of(d: &ObjectDescriptor) -> Kind {
    match d {
        ObjectDescriptor::File => Kind::File,
        ObjectDescriptor::Directory => Kind::Directory,
        ObjectDescriptor::Symlink => Kind::Symlink,
        _ => Kind::Unknown,
    }
}

/// Metadata for one path (Stat) or one directory child (List).
#[derive(Clone, Debug)]
pub struct Meta {
    pub kind: Kind,
    pub size: u64,
    pub mtime_unix_nanos: i64,
}

/// One directory entry from List.
#[derive(Clone, Debug)]
pub struct Entry {
    pub name: String,
    pub kind: Kind,
    pub size: u64,
}

fn ts_nanos(p: &ObjectProperties) -> i64 {
    p.modification_time.as_nanos() as i64
}

// ---------------------------------------------------------------------------
// Mount: the in-process fxfs filesystem rooted at the encrypted "default" volume.
// ---------------------------------------------------------------------------

async fn list_instances() -> Result<Vec<String>> {
    let dir = open_service::<ServiceMarker>().context("open aggregated block Service dir")?;
    let entries = fuchsia_fs::directory::readdir(&dir)
        .await
        .context("readdir block Service dir")?;
    Ok(entries.into_iter().map(|e| e.name).collect())
}

async fn connect_block_client(instance: &str) -> Result<RemoteBlockClient> {
    let dir = open_service::<ServiceMarker>().context("re-open block Service dir")?;
    let service = Service::<ServiceMarker>::from_service_dir_proxy(dir, ServiceMarker);
    let volume_proxy = service
        .connect_to_instance(instance)
        .context("connect to block instance")?;
    let block_proxy = volume_proxy
        .connect_to_volume()
        .context("connect to volume member")?;
    RemoteBlockClient::new(block_proxy)
        .await
        .map_err(|s| anyhow!("RemoteBlockClient::new failed: {s}"))
}

pub struct Mount {
    fs: fxfs::filesystem::OpenFxFilesystem,
    store: Arc<ObjectStore>,
    root_oid: u64,
}

/// One regular file resolved and opened at a published immutable identity.
/// The handle's cached size and object id remain fixed for the bounded stream.
pub struct OpenedRead {
    handle: DataObjectHandle<ObjectStore>,
    size: u64,
}

impl OpenedRead {
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Reads [offset, offset+length) from this opened identity (length 0 == EOF).
    pub async fn read(&self, offset: u64, length: u64) -> Result<Vec<u8>, FsError> {
        if offset >= self.size {
            return Ok(Vec::new());
        }
        let Some(plan) = read_range::plan(
            self.size,
            offset,
            length,
            self.handle.block_size(),
        )
        .map_err(|error| FsError::InvalidArgument(error.to_string()))?
        else {
            return Ok(Vec::new());
        };
        let bytes = read_range::read_exact(plan, |aligned_offset, physical_len| async move {
            let mut buf = self.handle.allocate_buffer(physical_len).await;
            let read = self
                .handle
                .read(aligned_offset, buf.subslice_mut(0..physical_len))
                .await
                .map_err(internal)?;
            Ok(buf.as_slice()[..read].to_vec())
        })
        .await;
        match bytes {
            Ok(bytes) => Ok(bytes),
            Err(read_range::ReadError::Source(error)) => Err(error),
            Err(read_range::ReadError::ShortRead { expected, actual }) => Err(FsError::Internal(
                anyhow!("aligned file read returned {actual} bytes, expected {expected}"),
            )),
            Err(read_range::ReadError::OverRead { maximum, actual }) => Err(FsError::Internal(
                anyhow!("aligned file read returned {actual} bytes, maximum {maximum}"),
            )),
        }
    }
}

async fn make_device(instance: &str, region: Option<Range<u64>>) -> Result<DeviceHolder> {
    let remote = connect_block_client(instance).await?;
    let block_size = remote.block_size() as u64;
    if block_size == 0 {
        return Err(anyhow!("device reported block_size=0"));
    }
    let device_size = remote
        .block_count()
        .checked_mul(block_size)
        .ok_or_else(|| anyhow!("device reports a nonsensical size"))?;
    let device = BlockDevice::new(remote, false)
        .await
        .map_err(|e| anyhow!("BlockDevice::new failed: {e}"))?;
    let Some(region) = region else {
        return Ok(DeviceHolder::new(device));
    };
    if region == (0..device_size) {
        return Ok(DeviceHolder::new(device));
    }
    let source: Arc<dyn Device> = Arc::new(device);
    let ranged = RangedDevice::new(source, region.clone()).map_err(|e| {
        anyhow!(
            "RangedDevice::new({}..{}) failed: {e}",
            region.start,
            region.end
        )
    })?;
    Ok(DeviceHolder::new(ranged))
}

fn emit(msg: &str) {
    unsafe {
        zx::sys::zx_debug_write(msg.as_ptr(), msg.len());
    }
}

// ---------------------------------------------------------------------------
// Disk-claim evidence: the raw block reads behind claim.rs's pure decision.
// ---------------------------------------------------------------------------

/// One probe read, owning its bytes so `claim::Probe` can borrow. The three
/// states are NOT interchangeable — see claim.rs: `Absent` is a fact about a
/// small device, `Unreadable` is a hole in our evidence, and only the first may
/// ever contribute to a decision that writes.
enum RawProbe {
    Read(Vec<u8>),
    Absent,
    Unreadable,
}

impl RawProbe {
    fn as_probe(&self) -> claim::Probe<'_> {
        match self {
            RawProbe::Read(b) => claim::Probe::Read(b),
            RawProbe::Absent => claim::Probe::Absent,
            RawProbe::Unreadable => claim::Probe::Unreadable,
        }
    }
}

/// Reads exactly `len` bytes at device-absolute `offset`, handling block
/// alignment itself. A location past the end of the device is `Absent`; a read
/// that FAILS is `Unreadable`. (Same shape as fxfs_provisioner's read_range —
/// the reads are trivial, the three-state result is the part that matters.)
async fn read_range(client: &RemoteBlockClient, offset: u64, len: usize) -> RawProbe {
    let block_size = client.block_size() as u64;
    if block_size == 0 || len == 0 {
        return RawProbe::Unreadable;
    }
    let Some(device_size) = client.block_count().checked_mul(block_size) else {
        return RawProbe::Unreadable;
    };
    let Some(end) = offset.checked_add(len as u64) else {
        return RawProbe::Absent;
    };
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
    match client
        .read_at(MutableBufferSlice::Memory(&mut buf), aligned_start)
        .await
    {
        Ok(()) => RawProbe::Read(buf[head..head + len].to_vec()),
        Err(_) => RawProbe::Unreadable,
    }
}

/// Reads one span of `claim`'s probe plan.
async fn read_span(client: &RemoteBlockClient, span: claim::Span) -> RawProbe {
    match usize::try_from(span.len) {
        Ok(len) => read_range(client, span.offset, len).await,
        Err(_) => RawProbe::Unreadable,
    }
}

async fn read_span_in(client: &RemoteBlockClient, base: u64, span: claim::Span) -> RawProbe {
    let Some(offset) = base.checked_add(span.offset) else {
        return RawProbe::Unreadable;
    };
    match usize::try_from(span.len) {
        Ok(len) => read_range(client, offset, len).await,
        Err(_) => RawProbe::Unreadable,
    }
}

/// Everything we read off one device, owning its buffers.
struct Survey {
    block_size: u64,
    block_count: u64,
    head: RawProbe,
    gpt_primary: RawProbe,
    gpt_backup: RawProbe,
    ext_super: RawProbe,
    super_b: RawProbe,
    front: RawProbe,
    tail: RawProbe,
}

impl Survey {
    fn device_bytes(&self) -> u64 {
        self.block_count.saturating_mul(self.block_size)
    }

    fn evidence(&self) -> claim::Evidence<'_> {
        claim::Evidence {
            head: self.head.as_probe(),
            gpt_primary: self.gpt_primary.as_probe(),
            gpt_backup: self.gpt_backup.as_probe(),
            ext_super: self.ext_super.as_probe(),
            super_b: self.super_b.as_probe(),
            front: self.front.as_probe(),
            tail: self.tail.as_probe(),
        }
    }

    /// A human-usable identification of the device the decision is about, for
    /// the refusal log. The instance name is a component_manager-assigned id
    /// (stable within a boot, not across boots), so the geometry is included
    /// too — between them an operator can tell which disk was declined.
    fn describe(&self, instance: &str) -> String {
        format!(
            "block.volume instance {instance} ({} blocks x {}B = {} MiB)",
            self.block_count,
            self.block_size,
            self.block_count.saturating_mul(self.block_size) / (1 << 20)
        )
    }
}

/// Gathers the claim evidence for `instance`, writing nothing.
///
/// WHERE to read is `claim::plan_probes`, not arithmetic here: the constants
/// only protect anything if the reads land on them, and a hand-built unit test
/// of `decide` cannot prove that. Keeping the plan in the pure module leaves
/// this function with nothing to get wrong but the I/O.
async fn survey(instance: &str) -> Result<Survey> {
    let client = connect_block_client(instance).await?;
    let block_size = client.block_size() as u64;
    let block_count = client.block_count();
    let plan = claim::plan_probes(block_size, block_count).ok_or_else(|| {
        // Nonsense geometry is a FAULT to report, never a device to reshape.
        anyhow!("device reports unusable geometry: {block_count} blocks x {block_size}B")
    })?;
    Ok(Survey {
        block_size,
        block_count,
        head: read_span(&client, plan.head).await,
        gpt_primary: read_span(&client, plan.gpt_primary).await,
        gpt_backup: read_span(&client, plan.gpt_backup).await,
        ext_super: read_span(&client, plan.ext_super).await,
        super_b: read_span(&client, plan.super_b).await,
        front: read_span(&client, plan.front).await,
        tail: read_span(&client, plan.tail).await,
    })
}

/// Locates the explicitly-owned data partition on one whole disk.
///
/// The deployed type GUID is the historical upstream FVM GUID, so the GUID
/// alone is not ownership evidence. Requiring the exact GPT name narrows the
/// candidate to the partition the deployment/provisioning tools created;
/// `claim::decide` still content-sniffs the bounded region before any mount or
/// format is attempted.
async fn locate_data_partition(instance: &str) -> Result<Option<Range<u64>>> {
    let client = connect_block_client(instance).await?;
    let block_size = client.block_size() as u64;
    let block_count = client.block_count();
    if block_size == 0 {
        return Err(anyhow!("device reported block_size=0"));
    }
    let lba1 = match read_range(&client, block_size, block_size as usize).await {
        RawProbe::Read(bytes) => bytes,
        RawProbe::Absent => return Ok(None),
        RawProbe::Unreadable => return Err(anyhow!("could not read the primary GPT header")),
    };
    let (entries_offset, entries_len) =
        match guest_store_locate::entry_array_read_plan(&lba1, block_size) {
            Ok(plan) => plan,
            Err(guest_store_locate::LocateError::NoSignature) => return Ok(None),
            Err(e) => return Err(anyhow!("cannot trust the primary GPT: {e}")),
        };
    let entries = match read_range(&client, entries_offset, entries_len).await {
        RawProbe::Read(bytes) => bytes,
        RawProbe::Absent => {
            return Err(anyhow!(
                "GPT entry array lies outside the published block device"
            ))
        }
        RawProbe::Unreadable => return Err(anyhow!("could not read the GPT entry array")),
    };
    match guest_store_locate::find_partition_by_type_and_name(
        &lba1,
        &entries,
        block_size,
        block_count,
        &boot_layout::FXFS_TYPE_GUID,
        DATA_PARTITION_NAME,
    ) {
        Ok(range) => {
            let end = range
                .end()
                .ok_or_else(|| anyhow!("data-partition byte range overflowed"))?;
            Ok(Some(range.offset..end))
        }
        Err(guest_store_locate::LocateError::NotPresent) => Ok(None),
        Err(e) => Err(anyhow!("cannot trust the Cerise data-partition entry: {e}")),
    }
}

/// Surveys a partition-relative container while reading through the whole-disk
/// client. The returned geometry and every probe are relative to `region`.
async fn survey_partition(instance: &str, region: &Range<u64>) -> Result<Survey> {
    let client = connect_block_client(instance).await?;
    let block_size = client.block_size() as u64;
    let device_size = client
        .block_count()
        .checked_mul(block_size)
        .ok_or_else(|| anyhow!("device reports a nonsensical size"))?;
    if block_size == 0
        || region.start % block_size != 0
        || region.end % block_size != 0
        || region.end <= region.start
        || region.end > device_size
    {
        return Err(anyhow!(
            "unusable data-partition range {}..{} on a {device_size}-byte device with \
             {block_size}-byte blocks",
            region.start,
            region.end
        ));
    }
    let block_count = (region.end - region.start) / block_size;
    let plan = claim::plan_probes(block_size, block_count).ok_or_else(|| {
        anyhow!("data partition reports unusable geometry: {block_count} blocks x {block_size}B")
    })?;
    Ok(Survey {
        block_size,
        block_count,
        head: read_span_in(&client, region.start, plan.head).await,
        gpt_primary: read_span_in(&client, region.start, plan.gpt_primary).await,
        gpt_backup: read_span_in(&client, region.start, plan.gpt_backup).await,
        ext_super: read_span_in(&client, region.start, plan.ext_super).await,
        super_b: read_span_in(&client, region.start, plan.super_b).await,
        front: read_span_in(&client, region.start, plan.front).await,
        tail: read_span_in(&client, region.start, plan.tail).await,
    })
}

/// Why a mount attempt did not produce a filesystem.
pub enum MountError {
    /// The device is not ours to touch, and no amount of retrying changes that.
    /// The caller must NOT retry and must NOT fall back to formatting.
    Refused(String),
    /// Something went wrong that a later attempt might not hit: no block device
    /// published yet, a transport error, an Fxfs container that would not open.
    Retry(anyhow::Error),
}

impl MountError {
    pub fn message(&self) -> String {
        match self {
            MountError::Refused(m) => m.clone(),
            MountError::Retry(e) => format!("{e:#}"),
        }
    }
}

fn retry(e: impl Into<anyhow::Error>) -> MountError {
    MountError::Retry(e.into())
}

/// Filesystem size and usage as `(total_bytes, used_bytes)`, read straight from the
/// mounted filesystem's own accounting (`OpenFxFilesystem::get_info` -> device size +
/// the allocator's used bytes). Implemented on `Mount` and nowhere else, so there is
/// no path that produces these numbers without a filesystem behind them. In-memory;
/// no I/O, safe to answer on the status console's polling cadence.
impl status::Usage for Mount {
    fn usage(&self) -> (u64, u64) {
        let info = self.fs.get_info();
        (info.total_bytes, info.used_bytes)
    }
}

impl Mount {
    /// Mounts fxfs, formatting a device ONLY when it is positively determined to
    /// be blank.
    ///
    /// THE BUG THIS REPLACES. The old policy was "format-if-needed": take the
    /// FIRST published block instance, try to open an Fxfs container on it and,
    /// if that failed FOR ANY REASON, format the raw device. Because the
    /// component bypassed fshost and treated the service member as a whole raw
    /// disk, on any machine that boots from that disk the fallback overwrote
    /// the partition table —
    /// measured on the CF-SZ5 as happening once per boot. Three changes:
    ///
    ///   * `claim::decide` (pure, host-tested) must POSITIVELY say the device is
    ///     blank before `try_format` is called at all. A GPT in either copy, any
    ///     other recognised signature, a non-zero byte in the first or last
    ///     megabyte, or any probe that could not be read, all refuse.
    ///   * a failure to OPEN an existing container is an error, not a licence to
    ///     format. That path was the actual destroyer: an Fxfs disk whose
    ///     "default" volume was missing, or a transient FIDL error, went
    ///     straight to `new_empty`.
    ///   * DEVICE SELECTION IS NO LONGER `next()`. See below.
    ///
    /// WHY IT LOOKS AT EVERY INSTANCE INSTEAD OF ONLY THE FIRST. On a
    /// multi-disk product the file server does not own instance 0 —
    /// `//products:qemu-x64-console-pkg` gives fshost a package store on one
    /// disk and the file server another, both through the SAME aggregated
    /// service, and the two components sort the same directory and so pick the
    /// same first entry. With "format-if-needed" that was invisible, because
    /// landing on fshost's disk simply reformatted it and carried on; removing
    /// the reformat turned it into a hang, which is how it was found. So:
    ///
    ///   * every instance is SURVEYED first — reads only, no writes;
    ///   * an existing container that OPENS wins, wherever it is (this is what
    ///     makes reboot persistence work);
    ///   * a container that does not open is not ours: log it and move on;
    ///   * only if NOTHING opened is a blank device formatted, and only the
    ///     first one, and only after every instance has been examined. The
    ///     device is PINNED before that write, so no retry and no partial
    ///     format can lead to a second device being claimed.
    ///
    /// WHAT THIS STILL DOES THAT IT SHOULD NOT HAVE TO, STATED PLAINLY:
    ///
    ///   * `try_open` on a container that turns out not to be ours is a
    ///     SPECULATIVE WRITABLE MOUNT. `FxFilesystem::open` here is read-write:
    ///     it replays the journal, initialises the graveyard and starts
    ///     background reaping before anything checks for our volume, and a
    ///     failed open drops the filesystem without closing it. On a container
    ///     another live component has mounted that is genuinely unsafe — two
    ///     writers — and no cross-mount exclusion exists in this tree to
    ///     prevent it. It is a smaller hazard than what it replaced (the old
    ///     code REFORMATTED that same disk) but it is not nothing.
    ///   * "blank" is being used as a proxy for "unowned", and it is not one. A
    ///     blank removable disk that happens to be attached is claimable by this
    ///     rule.
    ///
    /// Both of those are the same missing thing: the file server is handed an
    /// AGGREGATED block service and has to guess which member is its own. The
    /// fix is per-consumer device routing (or a stable ownership identity),
    /// which is a product/realm change, not a content check — content cannot
    /// distinguish two Fxfs containers from the outside. Until that exists this
    /// is the least-destructive behaviour available, and the markers make every
    /// device it touches visible on serial.
    ///
    /// A FRESH block-client/device handle is used per step (open consumes the
    /// DeviceHolder — the same fresh-handle discipline fxfs_probe's remount
    /// uses). The block device appears ~180s into boot, so the caller retries.
    ///
    /// `sink` receives the SAME facts this function already logs — one entry per
    /// device surveyed, with its geometry and what was decided about it — so the
    /// status console can render the decision without re-deriving it. It is written
    /// to, never read from: nothing here branches on what the console can see.
    pub async fn mount_once(
        pinned: &mut Option<String>,
        sink: &status::Sink,
    ) -> Result<Mount, MountError> {
        // The device list describes the LATEST attempt. A device that has gone away
        // between retries must not linger on the panel as though it were still there.
        sink.begin_attempt();
        let instances = list_instances().await.map_err(retry)?;
        if instances.is_empty() {
            return Err(retry(anyhow!(
                "no block.volume Service instance published yet"
            )));
        }

        // ONCE WE HAVE WRITTEN TO A DEVICE, ONLY THAT DEVICE IS EVER TOUCHED
        // AGAIN. `try_format` can succeed at `new_empty` and then fail while
        // creating the volume; without this the caller's retry loop would come
        // back, classify the half-formatted device as "not ours" (it has no
        // "default" volume), and format a DIFFERENT disk — turning one partial
        // claim into two. Same rule, and the same reasoning, as
        // fxfs_provisioner's `try_once` pin.
        let instances: Vec<String> = match pinned {
            Some(p) => {
                if !instances.iter().any(|i| i == p) {
                    return Err(retry(anyhow!(
                        "the block device we already wrote to ({p}) is no longer published;                          refusing to touch a different one"
                    )));
                }
                vec![p.clone()]
            }
            None => instances,
        };

        // Prefer the explicitly-owned GPT data partition. This is the direct
        // machine layout: firmware reads only the ESP, while Fxfs is confined
        // to a sibling partition on the same disk. A positive named-partition
        // match is authoritative; if it is damaged we refuse instead of
        // silently falling back to a different whole-device timeline.
        let mut data_partitions: Vec<(String, Range<u64>)> = Vec::new();
        let mut data_scan_problems = Vec::new();
        for instance in &instances {
            match locate_data_partition(instance).await {
                Ok(Some(region)) => data_partitions.push((instance.clone(), region)),
                Ok(None) => {}
                Err(e) => {
                    let msg = format!("{instance}: data-partition scan failed: {e:#}");
                    sink.observe_problem(instance, msg.clone());
                    data_scan_problems.push(msg);
                }
            }
        }
        if data_partitions.len() > 1 {
            let matches: Vec<&str> = data_partitions
                .iter()
                .map(|(instance, _)| instance.as_str())
                .collect();
            return Err(MountError::Refused(format!(
                "multiple block devices carry a {DATA_PARTITION_NAME:?} data partition \
                 ({matches:?}); refusing to choose"
            )));
        }
        if let Some((instance, region)) = data_partitions.pop() {
            let partition = survey_partition(&instance, &region).await.map_err(|e| {
                retry(e.context(format!(
                    "surveying data partition {}..{} on {instance}",
                    region.start, region.end
                )))
            })?;
            let what = format!(
                "data partition {}..{} on {} ({} MiB)",
                region.start,
                region.end,
                instance,
                partition.device_bytes() / (1 << 20)
            );
            sink.observe(status::Device {
                instance: instance.clone(),
                block_size: partition.block_size,
                block_count: partition.block_count,
                disposition: status::Disposition::Surveyed,
                reason: String::new(),
            });
            match claim::decide(&partition.evidence()) {
                Ok(claim::Claim::OpenExisting) => {
                    let mount = match Self::try_open_region(&instance, Some(region.clone())).await {
                        Ok(mount) => mount,
                        Err(open_error) if pinned.as_deref() == Some(instance.as_str()) => {
                            // This mount attempt itself began from a positively
                            // blank, explicitly owned partition and then wrote
                            // the partial container now visible here. Retrying
                            // the format is confined to that same pinned region;
                            // an older container discovered at process start
                            // never satisfies this branch.
                            Self::try_format_region(&instance, Some(region.clone()))
                                .await
                                .map_err(|format_error| {
                                    retry(anyhow!(
                                        "recovering a partial format of {what} failed; \
                                     open error: {open_error:#}; format error: \
                                     {format_error:#}"
                                    ))
                                })?
                        }
                        Err(error) => {
                            return Err(MountError::Refused(format!(
                                "{what} carries Fxfs but its encrypted \
                                 {VOLUME_NAME:?} volume could not be opened \
                                 ({error:#}); refusing to format or fall back"
                            )));
                        }
                    };
                    log::info!(device:% = what, volume = VOLUME_NAME; "opened partitioned fxfs filesystem");
                    emit("CERISE-FILESERVER-FXFS-OPENED\n");
                    emit("CERISE-FILESERVER-FXFS-PARTITION\n");
                    sink.set_disposition(&instance, status::Disposition::Opened, "");
                    return Ok(mount);
                }
                Ok(claim::Claim::Blank) => {
                    // The exact type+name GPT entry is explicit ownership
                    // evidence, so the whole-device 4 GiB scratch-disk ceiling
                    // does not apply. RangedDevice is the destructive fuse.
                    *pinned = Some(instance.clone());
                    let mount = Self::try_format_region(&instance, Some(region.clone()))
                        .await
                        .map_err(|e| retry(e.context(format!("formatting blank {what} failed"))))?;
                    log::info!(device:% = what, volume = VOLUME_NAME; "formatted partitioned fxfs filesystem");
                    emit("CERISE-FILESERVER-FXFS-FORMATTED\n");
                    emit("CERISE-FILESERVER-FXFS-PARTITION\n");
                    emit(&format!("CERISE-FILESERVER-CLAIMED-BLANK-DISK: {what}\n"));
                    sink.set_disposition(&instance, status::Disposition::Formatted, "");
                    return Ok(mount);
                }
                Err(refusal) => {
                    let msg = format!("{what}: {refusal}");
                    emit(&format!("CERISE-FILESERVER-DISK-REFUSED: {msg}\n"));
                    sink.set_disposition(
                        &instance,
                        status::Disposition::Refused,
                        &refusal.to_string(),
                    );
                    return Err(MountError::Refused(msg));
                }
            }
        }

        // Pass 1: examine everything, open anything that is already ours, and
        // remember (without touching) the first genuinely blank device.
        let mut blank: Option<(String, String)> = None;
        let mut refusals: Vec<String> = Vec::new();
        let mut problems: Vec<String> = data_scan_problems;
        for instance in &instances {
            let survey = match survey(instance).await {
                Ok(s) => s,
                Err(e) => {
                    let msg = format!("{instance}: survey failed: {e:#}");
                    sink.observe_problem(instance, msg.clone());
                    problems.push(msg);
                    continue;
                }
            };
            let what = survey.describe(instance);
            // Record the geometry BEFORE the decision: a device whose size we know is
            // worth showing even if what happens next is a refusal.
            sink.observe(status::Device {
                instance: instance.clone(),
                block_size: survey.block_size,
                block_count: survey.block_count,
                disposition: status::Disposition::Surveyed,
                reason: String::new(),
            });
            match claim::decide(&survey.evidence()) {
                Ok(claim::Claim::OpenExisting) => match Self::try_open_region(instance, None).await
                {
                    Ok(mount) => {
                        log::info!(device:% = what, volume = VOLUME_NAME; "opened existing fxfs filesystem");
                        // Boot-gate marker — keep on serial verbatim (validation greps this).
                        emit("CERISE-FILESERVER-FXFS-OPENED\n");
                        sink.set_disposition(instance, status::Disposition::Opened, "");
                        return Ok(mount);
                    }
                    Err(e) => {
                        // NOT a reason to format. Somebody else's Fxfs looks
                        // exactly like ours from the outside; the volume we need
                        // is the only thing that tells them apart.
                        let msg = format!(
                            "{what} carries an Fxfs container that is not ours to use \
                             ({e:#}); NOT formatting it, moving on"
                        );
                        log::warn!("{msg}");
                        emit(&format!("CERISE-FILESERVER-DISK-NOT-OURS: {msg}\n"));
                        sink.set_disposition(instance, status::Disposition::Problem, &msg);
                        problems.push(msg);
                    }
                },
                Ok(claim::Claim::Blank)
                    if !claim::automatic_format_allowed(survey.device_bytes()) =>
                {
                    let msg = format!(
                        "{what} looked blank, but its {} byte capacity exceeds the {} byte \
                         automatic-format safety ceiling. Large devices require an explicit \
                         ownership/provisioning path; NOT formatting it",
                        survey.device_bytes(),
                        claim::MAX_AUTOMATIC_FORMAT_BYTES,
                    );
                    log::error!("{msg}");
                    emit(&format!("CERISE-FILESERVER-DISK-REFUSED: {msg}\n"));
                    sink.set_disposition(instance, status::Disposition::Refused, &msg);
                    refusals.push(msg);
                }
                Ok(claim::Claim::Blank) => {
                    if blank.is_none() {
                        blank = Some((instance.clone(), what));
                    }
                }
                Err(refusal) => {
                    let msg = format!("{what}: {refusal}");
                    log::error!("{msg}");
                    // Boot-gate marker — names the disk and the reason. Distinct
                    // from CERISE-FILESERVER-FAIL: nothing failed, we declined.
                    emit(&format!("CERISE-FILESERVER-DISK-REFUSED: {msg}\n"));
                    // The panel gets the REASON alone, not the "{what}: " prefix —
                    // it already renders the geometry from the device's own fields,
                    // and repeating it would cost a screen line for nothing.
                    sink.set_disposition(
                        instance,
                        status::Disposition::Refused,
                        &refusal.to_string(),
                    );
                    refusals.push(msg);
                }
            }
        }

        // Pass 2: nothing was already ours. Claim a blank device, at most one.
        if let Some((instance, what)) = blank {
            log::info!(device:% = what; "block device is blank; formatting a fresh fxfs filesystem");
            // Pin BEFORE the write, not after: the point of the pin is to bound
            // the damage of a format that fails half way, and a pin set after
            // the call is not set when the call does not return.
            *pinned = Some(instance.clone());
            let mount = Self::try_format_region(&instance, None)
                .await
                .map_err(|e| retry(e.context(format!("formatting blank {what} failed"))))?;
            log::info!(volume = VOLUME_NAME; "formatted a fresh fxfs filesystem");
            // Boot-gate markers — keep on serial verbatim. The second one names
            // the device: "we formatted something" is not a useful thing to read
            // in a log six months later.
            emit("CERISE-FILESERVER-FXFS-FORMATTED\n");
            emit(&format!("CERISE-FILESERVER-CLAIMED-BLANK-DISK: {what}\n"));
            sink.set_disposition(&instance, status::Disposition::Formatted, "");
            return Ok(mount);
        }

        // Nothing opened and nothing may be claimed. If every candidate was a
        // clean REFUSAL the answer is stable and retrying is pointless; if any
        // of them merely misbehaved, a later attempt might do better.
        if problems.is_empty() && !refusals.is_empty() {
            return Err(MountError::Refused(refusals.join(" | ")));
        }
        Err(retry(anyhow!(
            "no usable block device among {} instance(s): {}",
            instances.len(),
            problems
                .into_iter()
                .chain(refusals)
                .collect::<Vec<_>>()
                .join(" | ")
        )))
    }

    /// Opens the managed volume. New pools are unencrypted; the fallback keeps
    /// pools created by the earlier fixed development-key format readable long
    /// enough to migrate them.
    async fn try_open_region(instance: &str, region: Option<Range<u64>>) -> Result<Mount> {
        let device = make_device(instance, region).await?;
        let fs = FxFilesystem::open(device)
            .await
            .context("FxFilesystem::open failed")?;
        let root_vol = root_volume(fs.clone())
            .await
            .map_err(|e| anyhow!("root_volume (open) failed: {e}"))?;
        let store = match root_vol.volume(VOLUME_NAME, StoreOptions::default()).await {
            Ok(store) => store,
            Err(unencrypted_error) => {
                let crypt = connect_crypt()?;
                root_vol
                    .volume(
                        VOLUME_NAME,
                        StoreOptions {
                            crypt: Some(crypt),
                            ..Default::default()
                        },
                    )
                    .await
                    .map_err(|encrypted_error| {
                        anyhow!(
                            "volume open failed without a key ({unencrypted_error:#}) and with \
                             the legacy development key ({encrypted_error:#})"
                        )
                    })?
            }
        };
        let root_oid = store.root_directory_object_id();
        Ok(Mount {
            fs,
            store,
            root_oid,
        })
    }

    /// Formats a fresh Fxfs pool and creates the managed volume.
    ///
    /// The old fixed development wrapping key provided no confidentiality and
    /// forced every bulk page through a remote crypt service. Fresh managed
    /// pools stay unencrypted until a host-bound key provider is available.
    async fn try_format_region(instance: &str, region: Option<Range<u64>>) -> Result<Mount> {
        let device = make_device(instance, region).await?;
        let fs = FxFilesystem::new_empty(device)
            .await
            .map_err(|e| anyhow!("FxFilesystem::new_empty (format) failed: {e}"))?;
        let root_vol = root_volume(fs.clone())
            .await
            .map_err(|e| anyhow!("root_volume (format) failed: {e}"))?;
        let store = root_vol
            .new_volume(VOLUME_NAME, NewChildStoreOptions::default())
            .await
            .map_err(|e| anyhow!("new_volume failed: {e}"))?;
        let root_oid = store.root_directory_object_id();
        // `new_volume` commits the metadata transaction, but readiness is a
        // durability promise: the machine can lose power immediately after
        // the FORMAT/MOUNT/LISTENING markers.  Checkpoint the journal before
        // returning the mount so the volume's root directory is recoverable
        // on that next boot rather than existing only in the live journal
        // state.
        fs.sync(SyncOptions {
            flush_device: true,
            ..Default::default()
        })
        .await
        .map_err(|e| anyhow!("syncing freshly created volume failed: {e}"))?;
        Ok(Mount {
            fs,
            store,
            root_oid,
        })
    }

    fn store_id(&self) -> u64 {
        self.store.store_object_id()
    }

    /// Flushes the Fxfs journal and its block device so committed mutations
    /// survive immediate power loss.
    async fn sync(&self) -> Result<(), FsError> {
        self.fs
            .sync(SyncOptions {
                flush_device: true,
                ..Default::default()
            })
            .await
            .map_err(internal)
    }

    /// Checkpoints all committed filesystem state.
    ///
    /// Mutating RPCs call `sync` before releasing their admission permit.  The
    /// lifecycle controller calls this once more after those permits drain, so
    /// a successful store freeze is a filesystem-wide durability boundary.
    pub async fn sync_all(&self) -> Result<(), FsError> {
        self.sync().await
    }

    pub fn usage_bytes(&self) -> (u64, u64) {
        let info = self.fs.get_info();
        (info.total_bytes, info.used_bytes)
    }

    async fn open_dir(&self, oid: u64) -> Result<Directory<ObjectStore>, FsError> {
        Directory::open(&self.store, oid).await.map_err(internal)
    }

    /// Resolves a sanitized path to (object_id, kind). Empty path == the root dir.
    async fn resolve(&self, components: &[&str]) -> Result<(u64, Kind), FsError> {
        let mut oid = self.root_oid;
        let mut kind = Kind::Directory;
        for comp in components {
            if kind != Kind::Directory {
                return Err(FsError::NotADirectory);
            }
            let dir = self.open_dir(oid).await?;
            match dir.lookup(comp).await.map_err(internal)? {
                Some((child_oid, desc, _)) => {
                    oid = child_oid;
                    kind = kind_of(&desc);
                }
                None => return Err(FsError::NotFound),
            }
        }
        Ok((oid, kind))
    }

    /// Resolves the parent directory + final name for a create/delete/rename target.
    async fn resolve_parent<'a>(
        &self,
        components: &'a [&'a str],
    ) -> Result<(Directory<ObjectStore>, &'a str), FsError> {
        let (name, parent) = components
            .split_last()
            .ok_or_else(|| FsError::InvalidArgument("empty path".into()))?;
        let (poid, pkind) = self.resolve(parent).await?;
        if pkind != Kind::Directory {
            return Err(FsError::NotADirectory);
        }
        Ok((self.open_dir(poid).await?, *name))
    }

    // --- Stat -------------------------------------------------------------
    pub async fn stat(&self, components: &[&str]) -> Result<Meta, FsError> {
        let (oid, kind) = self.resolve(components).await?;
        match kind {
            Kind::Directory => {
                let d = self.open_dir(oid).await?;
                let p = d.get_properties().await.map_err(internal)?;
                Ok(Meta {
                    kind,
                    size: 0,
                    mtime_unix_nanos: ts_nanos(&p),
                })
            }
            Kind::File | Kind::Symlink | Kind::Unknown => {
                let h = ObjectStore::open_object(&self.store, oid, HandleOptions::default(), None)
                    .await
                    .map_err(internal)?;
                let p = h.get_properties().await.map_err(internal)?;
                Ok(Meta {
                    kind,
                    size: p.data_attribute_size,
                    mtime_unix_nanos: ts_nanos(&p),
                })
            }
        }
    }

    // --- List -------------------------------------------------------------
    pub async fn list(&self, components: &[&str]) -> Result<Vec<Entry>, FsError> {
        self.list_with_limit(components, None).await
    }

    pub async fn list_bounded(
        &self,
        components: &[&str],
        max_entries: usize,
    ) -> Result<Vec<Entry>, FsError> {
        if max_entries == 0 {
            return Err(FsError::InvalidArgument(
                "max_entries must be nonzero for a bounded listing".to_owned(),
            ));
        }
        self.list_with_limit(components, Some(max_entries)).await
    }

    async fn list_with_limit(
        &self,
        components: &[&str],
        max_entries: Option<usize>,
    ) -> Result<Vec<Entry>, FsError> {
        let (oid, kind) = self.resolve(components).await?;
        if kind != Kind::Directory {
            return Err(FsError::NotADirectory);
        }
        let dir = self.open_dir(oid).await?;
        // Collect (name, oid, kind) first so we don't hold the LSM merger borrow across
        // the per-child open_object calls below.
        let mut children: Vec<(String, u64, Kind)> = Vec::new();
        {
            let layer_set = dir.store().tree().layer_set();
            let mut merger = layer_set.merger();
            let mut iter = dir.iter(&mut merger).await.map_err(internal)?;
            while let Some((name, child_oid, desc)) = iter.get() {
                if let Some(limit) = max_entries {
                    if children.len() >= limit {
                        return Err(FsError::ResourceExhausted(format!(
                            "directory contains more than {limit} entries"
                        )));
                    }
                }
                children.push((name.to_string(), child_oid, kind_of(desc)));
                iter.advance().await.map_err(internal)?;
            }
        }
        let mut out = Vec::with_capacity(children.len());
        for (name, child_oid, ckind) in children {
            let size = if ckind == Kind::File {
                let h = ObjectStore::open_object(
                    &self.store,
                    child_oid,
                    HandleOptions::default(),
                    None,
                )
                .await
                .map_err(internal)?;
                h.get_size()
            } else {
                0
            };
            out.push(Entry {
                name,
                kind: ckind,
                size,
            });
        }
        Ok(out)
    }

    // --- Read -------------------------------------------------------------
    /// Resolves and opens one regular file for a bounded immutable read stream.
    pub async fn open_read(&self, components: &[&str]) -> Result<OpenedRead, FsError> {
        let (oid, kind) = self.resolve(components).await?;
        if kind == Kind::Directory {
            return Err(FsError::IsADirectory);
        }
        if kind != Kind::File {
            return Err(FsError::InvalidArgument("not a regular file".into()));
        }
        let handle = ObjectStore::open_object(&self.store, oid, HandleOptions::default(), None)
            .await
            .map_err(internal)?;
        let size = handle.get_size();
        Ok(OpenedRead { handle, size })
    }

    /// Reads [offset, offset+length) (length 0 == to EOF) and returns the bytes.
    pub async fn read(
        &self,
        components: &[&str],
        offset: u64,
        length: u64,
    ) -> Result<Vec<u8>, FsError> {
        self.open_read(components).await?.read(offset, length).await
    }

    /// Parses and validates Cryostore geometry without rereading its pack.
    ///
    /// `sha256` must already have been independently accumulated from the
    /// complete file. Managed imports do that while accepting upload bytes, so
    /// commit only needs to validate the bounded format index.
    pub async fn inspect_cryostore(
        &self,
        components: &[&str],
        sha256: &str,
        expected_size: u64,
    ) -> Result<VerifiedCryostore, FsError> {
        let (oid, kind) = self.resolve(components).await?;
        if kind != Kind::File {
            return Err(FsError::InvalidArgument(
                "Cryostore import is not a regular file".into(),
            ));
        }
        let handle = ObjectStore::open_object(&self.store, oid, HandleOptions::default(), None)
            .await
            .map_err(internal)?;
        let size = handle.get_size();
        if size != expected_size {
            return Err(FsError::InvalidArgument(format!(
                "staged image is {size} bytes; expected {expected_size}"
            )));
        }
        if size < cryogen_format::HEADER_LEN as u64 {
            return Err(FsError::InvalidArgument(
                "staged image is shorter than a Cryostore header".into(),
            ));
        }

        let mut header_buf = handle.allocate_buffer(cryogen_format::HEADER_LEN).await;
        let mut header_read = 0usize;
        while header_read < cryogen_format::HEADER_LEN {
            let read = handle
                .read(
                    header_read as u64,
                    header_buf.subslice_mut(header_read..cryogen_format::HEADER_LEN),
                )
                .await
                .map_err(internal)?;
            if read == 0 {
                return Err(FsError::InvalidArgument(
                    "staged image header was truncated".into(),
                ));
            }
            header_read += read;
        }
        let mut validator = cryogen_format::StoreIndexValidator::new(header_buf.as_slice())
            .map_err(|error| {
                FsError::InvalidArgument(format!("staged image header is invalid: {error}"))
            })?;
        let header = *validator.header();
        if header.total_len() != size {
            return Err(FsError::InvalidArgument(format!(
                "staged image is {size} bytes; its header describes {}",
                header.total_len()
            )));
        }
        if header.index_len() > MAX_CRYOSTORE_INDEX_BYTES {
            return Err(FsError::InvalidArgument(format!(
                "Cryostore index is {} bytes; product limit is {MAX_CRYOSTORE_INDEX_BYTES}",
                header.index_len(),
            )));
        }
        // Fxfs object reads require filesystem-block-aligned offsets. Read the
        // first validation window from zero and omit its already-decoded
        // header when feeding the validator; every following 4 MiB offset is
        // aligned. Starting a read directly at HEADER_LEN (128) is invalid.
        let mut index_offset = 0u64;
        let validator_buffer_len =
            usize::try_from(header.index_len().min(VERIFY_CHUNK_BYTES as u64))
                .expect("bounded validation buffer fits usize");
        let mut validator_buf = handle.allocate_buffer(validator_buffer_len).await;
        while index_offset < header.index_len() {
            let chunk_len =
                usize::try_from((header.index_len() - index_offset).min(VERIFY_CHUNK_BYTES as u64))
                    .expect("bounded validation chunk fits usize");
            let read = handle
                .read(index_offset, validator_buf.subslice_mut(0..chunk_len))
                .await
                .map_err(internal)?;
            if read == 0 {
                return Err(FsError::InvalidArgument(
                    "staged image index was truncated".into(),
                ));
            }
            let feed_start = if index_offset == 0 {
                cryogen_format::HEADER_LEN
            } else {
                0
            };
            if read < feed_start {
                return Err(FsError::InvalidArgument(
                    "staged image index header was truncated".into(),
                ));
            }
            validator
                .update(&validator_buf.as_slice()[feed_start..read])
                .map_err(|error| {
                    FsError::InvalidArgument(format!("staged image index is invalid: {error}"))
                })?;
            index_offset += read as u64;
        }
        let header = validator.finish().map_err(|error| {
            FsError::InvalidArgument(format!("staged image index is invalid: {error}"))
        })?;

        Ok(VerifiedCryostore {
            sha256: sha256.to_owned(),
            encoded_bytes: size,
            root_hash: cryogen_format::HexId(&header.root_hash).to_string(),
            guest_disk_bytes: header.disk_size,
            format_version: cryogen_format::VERSION,
        })
    }

    /// Extends a resumable SHA-256 state over an exact file range in bounded
    /// memory.
    ///
    /// Managed imports start at their durable checkpoint, so restart work is
    /// proportional to the suffix accepted since that checkpoint rather than
    /// to the complete image.
    pub async fn update_hash_range(
        &self,
        components: &[&str],
        start: u64,
        end: u64,
        hasher: &mut ResumableSha256,
    ) -> Result<(), FsError> {
        let (oid, kind) = self.resolve(components).await?;
        if kind != Kind::File {
            return Err(FsError::InvalidArgument(
                "hash source is not a regular file".into(),
            ));
        }
        let handle = ObjectStore::open_object(&self.store, oid, HandleOptions::default(), None)
            .await
            .map_err(internal)?;
        let size = handle.get_size();
        if start > end || end > size {
            return Err(FsError::InvalidArgument(format!(
                "hash range {start}..{end} is invalid for file size {size}"
            )));
        }
        if hasher.bytes_hashed() != start {
            return Err(FsError::InvalidArgument(format!(
                "hash state covers {} bytes, not requested range start {start}",
                hasher.bytes_hashed()
            )));
        }
        let mut offset = start;
        let verify_buffer_len = usize::try_from((end - start).min(VERIFY_CHUNK_BYTES as u64))
            .expect("bounded verification buffer fits usize");
        if verify_buffer_len == 0 {
            return Ok(());
        }
        let mut chunk = handle.allocate_buffer(verify_buffer_len).await;
        while offset < end {
            let chunk_len = usize::try_from((end - offset).min(VERIFY_CHUNK_BYTES as u64))
                .expect("bounded verification chunk fits usize");
            let mut read = 0usize;
            while read < chunk_len {
                let bytes = handle
                    .read(offset + read as u64, chunk.subslice_mut(read..chunk_len))
                    .await
                    .map_err(internal)?;
                if bytes == 0 {
                    return Err(FsError::InvalidArgument(format!(
                        "hash source ended at byte {}, expected range end {end}",
                        offset + read as u64
                    )));
                }
                read += bytes;
            }
            hasher
                .update(&chunk.as_slice()[..chunk_len])
                .map_err(FsError::InvalidArgument)?;
            offset += read as u64;
        }
        Ok(())
    }

    // --- Write ------------------------------------------------------------
    pub async fn write(
        &self,
        components: &[&str],
        offset: u64,
        data: &[u8],
        create: bool,
        truncate: bool,
        durable: bool,
    ) -> Result<u64, FsError> {
        let (parent, name) = self.resolve_parent(components).await?;
        let existing = parent.lookup(name).await.map_err(internal)?;
        if matches!(existing.as_ref(), Some((_, ObjectDescriptor::Directory, _))) {
            return Err(FsError::IsADirectory);
        }
        if matches!(
            existing.as_ref(),
            Some((_, descriptor, _)) if *descriptor != ObjectDescriptor::File
        ) {
            return Err(FsError::InvalidArgument(
                "target is not a regular file".into(),
            ));
        }
        if existing.is_none() && !create {
            return Err(FsError::NotFound);
        }

        let replace_existing = create && truncate && offset == 0 && existing.is_some();
        let handle = if replace_existing {
            // A disposable spill file can contain many independently allocated
            // extents. Truncating such a file in place makes Fxfs describe all
            // of those deallocations on the request's critical path and can
            // exceed its fixed per-transaction metadata reservation. Replace
            // the directory entry with a fresh empty object instead. The old
            // object is durably placed in the graveyard by the same
            // transaction and reclaimed there in Fxfs' bounded background
            // tombstone loop.
            let ctx = parent
                .acquire_context_for_replace(None, name, false)
                .await
                .map_err(internal)?;
            let mut txn = ctx.transaction;
            let fresh = parent
                .create_child_unnamed_temporary_file(&mut txn)
                .await
                .map_err(internal)?;
            self.store
                .remove_from_graveyard(&mut txn, fresh.object_id());
            let replaced = replace_child_with_object(
                &mut txn,
                Some((fresh.object_id(), ObjectDescriptor::File)),
                (&parent, name),
                0,
                Timestamp::now(),
            )
            .await
            .map_err(internal)?;
            txn.commit().await.map_err(internal)?;
            match replaced {
                ReplacedChild::Object(id) => self
                    .fs
                    .graveyard()
                    .queue_tombstone_object(self.store_id(), id),
                ReplacedChild::None | ReplacedChild::ObjectWithRemainingLinks(..) => {}
                ReplacedChild::Directory(_) => {
                    return Err(FsError::Internal(anyhow!(
                        "regular-file replacement unexpectedly displaced a directory"
                    )));
                }
            }
            fresh
        } else {
            match existing {
                Some((child_oid, ObjectDescriptor::File, _)) => {
                    ObjectStore::open_object(&self.store, child_oid, HandleOptions::default(), None)
                        .await
                        .map_err(internal)?
                }
                None => {
                    let mut txn = self
                        .fs
                        .clone()
                        .new_transaction(
                            lock_keys![LockKey::object(self.store_id(), parent.object_id())],
                            TxnOptions::default(),
                        )
                        .await
                        .map_err(internal)?;
                    let h = parent
                        .create_child_file(&mut txn, name)
                        .await
                        .map_err(internal)?;
                    txn.commit().await.map_err(internal)?;
                    h
                }
                Some(_) => unreachable!("non-file entries were rejected above"),
            }
        };
        if truncate && !replace_existing {
            handle.truncate(0).await.map_err(internal)?;
        }
        for (chunk_index, chunk) in data.chunks(FXFS_WRITE_CHUNK_BYTES).enumerate() {
            let chunk_offset = chunk_index
                .checked_mul(FXFS_WRITE_CHUNK_BYTES)
                .and_then(|delta| u64::try_from(delta).ok())
                .and_then(|delta| offset.checked_add(delta))
                .ok_or_else(|| FsError::InvalidArgument("write offset overflowed".into()))?;
            let mut buf = handle.allocate_buffer(chunk.len()).await;
            buf.as_mut_slice().copy_from_slice(chunk);
            handle
                .write_or_append(Some(chunk_offset), buf.as_ref())
                .await
                .map_err(internal)?;
        }
        handle.flush().await.map_err(internal)?;
        if durable {
            self.sync().await?;
        }
        Ok(data.len() as u64)
    }

    /// Replaces a small file without ever exposing its partially written
    /// successor at `components`.
    ///
    /// The temporary name is safe because callers serialize writes to each
    /// control record. A crash can leave that name behind, but the old
    /// published record remains intact until the final rename transaction.
    pub async fn write_atomic(
        &self,
        components: &[&str],
        data: &[u8],
        durable: bool,
    ) -> Result<(), FsError> {
        let (name, parent_components) = components
            .split_last()
            .ok_or_else(|| FsError::InvalidArgument("cannot replace the filesystem root".into()))?;
        let temporary_name = format!(".{name}.cerise-new");
        let mut temporary_components = parent_components.to_vec();
        temporary_components.push(temporary_name.as_str());

        // flush() orders the payload into Fxfs before the directory transaction
        // publishes it. The optional sync after rename is the power-loss
        // boundary for both the payload and the new directory entry.
        self.write(&temporary_components, 0, data, true, true, false)
            .await?;
        self.rename_with_durability(&temporary_components, components, durable)
            .await
    }

    // --- Mkdir ------------------------------------------------------------
    pub async fn mkdir(&self, components: &[&str], parents: bool) -> Result<(), FsError> {
        if components.is_empty() {
            return Err(FsError::AlreadyExists); // root already exists
        }
        if parents {
            let mut oid = self.root_oid;
            for comp in components {
                let dir = self.open_dir(oid).await?;
                match dir.lookup(comp).await.map_err(internal)? {
                    Some((child, ObjectDescriptor::Directory, _)) => oid = child,
                    Some(_) => return Err(FsError::AlreadyExists),
                    None => {
                        let mut txn = self
                            .fs
                            .clone()
                            .new_transaction(
                                lock_keys![LockKey::object(self.store_id(), dir.object_id())],
                                TxnOptions::default(),
                            )
                            .await
                            .map_err(internal)?;
                        let child = dir
                            .create_child_dir(&mut txn, comp)
                            .await
                            .map_err(internal)?;
                        txn.commit().await.map_err(internal)?;
                        oid = child.object_id();
                    }
                }
            }
            self.sync().await?;
            Ok(())
        } else {
            let (parent, name) = self.resolve_parent(components).await?;
            if parent.lookup(name).await.map_err(internal)?.is_some() {
                return Err(FsError::AlreadyExists);
            }
            let mut txn = self
                .fs
                .clone()
                .new_transaction(
                    lock_keys![LockKey::object(self.store_id(), parent.object_id())],
                    TxnOptions::default(),
                )
                .await
                .map_err(internal)?;
            parent
                .create_child_dir(&mut txn, name)
                .await
                .map_err(internal)?;
            txn.commit().await.map_err(internal)?;
            self.sync().await?;
            Ok(())
        }
    }

    // --- Delete -----------------------------------------------------------
    pub async fn delete(&self, components: &[&str], recursive: bool) -> Result<(), FsError> {
        self.delete_with_durability(components, recursive, true)
            .await
    }

    /// Removes an entry without issuing a device barrier. The caller must
    /// establish a later filesystem-wide durability boundary.
    pub async fn delete_lazy(&self, components: &[&str], recursive: bool) -> Result<(), FsError> {
        self.delete_with_durability(components, recursive, false)
            .await
    }

    async fn delete_with_durability(
        &self,
        components: &[&str],
        recursive: bool,
        durable: bool,
    ) -> Result<(), FsError> {
        let (parent, name) = self.resolve_parent(components).await?;
        let (child_oid, desc) = match parent.lookup(name).await.map_err(internal)? {
            Some((o, d, _)) => (o, d),
            None => return Err(FsError::NotFound),
        };
        if desc == ObjectDescriptor::Directory {
            // replace_child refuses a non-empty directory; empty it first if recursive.
            let child_dir = self.open_dir(child_oid).await?;
            let entries = self.list(components).await?;
            if !entries.is_empty() {
                if !recursive {
                    return Err(FsError::NotEmpty);
                }
                for e in entries {
                    let mut sub: Vec<&str> = components.to_vec();
                    sub.push(&e.name);
                    Box::pin(self.delete_with_durability(&sub, true, false)).await?;
                }
            }
            let _ = child_dir;
        }
        let ctx = parent
            .acquire_context_for_replace(None, name, true)
            .await
            .map_err(internal)?;
        let mut txn = ctx.transaction;
        let replaced = replace_child(&mut txn, None, (&parent, name))
            .await
            .map_err(internal)?;
        txn.commit().await.map_err(internal)?;
        match replaced {
            ReplacedChild::None => return Err(FsError::NotFound),
            ReplacedChild::Object(id) | ReplacedChild::Directory(id) => {
                self.store
                    .tombstone_object(id, TxnOptions::default())
                    .await
                    .map_err(internal)?;
            }
            ReplacedChild::ObjectWithRemainingLinks(..) => {}
        }
        if durable {
            self.sync().await?;
        }
        Ok(())
    }

    // --- Rename -----------------------------------------------------------
    pub async fn rename(&self, from: &[&str], to: &[&str]) -> Result<(), FsError> {
        self.rename_with_durability(from, to, true).await
    }

    /// Renames without issuing a device barrier. The caller must establish a
    /// later filesystem-wide durability boundary.
    pub async fn rename_lazy(&self, from: &[&str], to: &[&str]) -> Result<(), FsError> {
        self.rename_with_durability(from, to, false).await
    }

    async fn rename_with_durability(
        &self,
        from: &[&str],
        to: &[&str],
        durable: bool,
    ) -> Result<(), FsError> {
        let (from_parent, from_name) = self.resolve_parent(from).await?;
        let (to_parent, to_name) = self.resolve_parent(to).await?;
        if from_parent
            .lookup(from_name)
            .await
            .map_err(internal)?
            .is_none()
        {
            return Err(FsError::NotFound);
        }
        let ctx = to_parent
            .acquire_context_for_replace(Some((&from_parent, from_name)), to_name, false)
            .await
            .map_err(internal)?;
        let mut txn = ctx.transaction;
        let replaced = replace_child(
            &mut txn,
            Some((&from_parent, from_name)),
            (&to_parent, to_name),
        )
        .await
        .map_err(internal)?;
        txn.commit().await.map_err(internal)?;
        match replaced {
            ReplacedChild::Object(id) | ReplacedChild::Directory(id) => {
                self.store
                    .tombstone_object(id, TxnOptions::default())
                    .await
                    .map_err(internal)?;
            }
            _ => {}
        }
        if durable {
            self.sync().await?;
        }
        Ok(())
    }
}

/// Provisions crypt (once per boot) then mounts, retrying while the block device
/// (published ~180s into boot by the nvme/ahci driver) is not yet available.
///
/// A REFUSAL IS NOT RETRIED. "This disk is somebody else's" is a stable fact
/// about the hardware, not a race with a driver: retrying it would burn five
/// minutes and reach the same answer, and — more importantly — a retry loop that
/// keeps re-asking a destructive question is how the old code got a second
/// chance to do the wrong thing. Refusals return immediately.
pub async fn mount_with_retry(sink: &status::Sink) -> Result<Mount, MountError> {
    // crypt_fxfs is Lazy; the first CryptManagement connect starts it.
    let mut provisioned = false;
    let mut provision_error = None;
    for _ in 0..10u32 {
        match provision_crypt_keys().await {
            Ok(()) => {
                provisioned = true;
                break;
            }
            Err(error) => {
                provision_error = Some(error);
            }
        }
        fuchsia_async::Timer::new(fuchsia_async::MonotonicInstant::after(
            std::time::Duration::from_secs(2).into(),
        ))
        .await;
    }
    if !provisioned {
        return Err(retry(
            provision_error
                .unwrap_or_else(|| anyhow!("crypt key provisioning made no attempt"))
                .context("crypt key provisioning did not become ready"),
        ));
    }
    const MAX_ATTEMPTS: u32 = 60;
    let mut last: Option<MountError> = None;
    // Sticky across retries: once a device has been written to, no other device
    // is ever considered again.
    let mut pinned: Option<String> = None;
    for _ in 0..MAX_ATTEMPTS {
        match Mount::mount_once(&mut pinned, sink).await {
            Ok(m) => return Ok(m),
            Err(refused @ MountError::Refused(_)) => return Err(refused),
            Err(e) => {
                last = Some(e);
                fuchsia_async::Timer::new(fuchsia_async::MonotonicInstant::after(
                    std::time::Duration::from_secs(5).into(),
                ))
                .await;
            }
        }
    }
    Err(last.unwrap_or_else(|| retry(anyhow!("fxfs mount failed with no error"))))
}

//! Cerise A/B host-image stager.
//!
//! On every boot it:
//!   1. reads /pkg/data/ota-config.json = {"version": N, "apply": bool}, emits
//!      CERISE-OS-VERSION=N.
//!   2. finds the sole block device (the ESP/GPT disk) via the aggregated
//!      fuchsia.hardware.block.volume.Service, builds a synchronous block client.
//!   3. parses the GPT by hand to locate the ESP partition offset, mounts its FAT
//!      filesystem with the pure-Rust `fatfs` crate over a block-client adapter.
//!   4. SUCCESS-COMMIT: reads \abr (the 16-byte CABR record the boot shim wrote),
//!      marks the RUNNING slot (abr.active) successful. A legacy single-image ESP
//!      is migrated by copying and verifying bootx64.zbi as slot A, flushing it,
//!      and publishing \abr only as the final mutation. First commit of a slot flips
//!      0->1 => CERISE-OTA-COMMITTED; an already-good slot => CERISE-OTA-PERSISTED.
//!      The commit path NEVER reboots.
//!   5. serves `cerise.update.Stager`. `Prepare` downloads and authenticates the
//!      image while the machine is still running. After its caller has quiesced the
//!      host, `StagePrepared` uniquely locates the physical GPT disk/ESP, writes and
//!      flushes the inactive slot, readback-verifies it, and commits \abr LAST.
//!
//! This component deliberately has no reboot/shutdown capability. The host lifecycle
//! coordinator owns quiesce, calls `StagePrepared`, and separately decides whether to
//! reboot. Keeping that terminal authority out of the raw-disk writer makes the
//! ordering explicit rather than an accident of component teardown.
//!
//! TWO THINGS ON THIS PATH ARE SECURITY DECISIONS, AND BOTH ARE PURE MODULES WITH HOST
//! TESTS RATHER THAN INLINE CODE HERE:
//!
//!   * `esp_locate` — WHERE the ~45 MiB write lands. It is chosen from a GPT this
//!     component did not write, so every field it reads is untrusted input. It
//!     validates the header CRC, the entry-array CRC and all the geometry (reusing
//!     `boot_layout`, the same validator `fxfs_provisioner` and the fileserver hold),
//!     and it REFUSES when there is no ESP instead of falling back to the first
//!     partition it can find. See src/esp.rs.
//!   * `ota_image_manifest` — WHETHER the bytes may be written. The manifest carries an
//!     ed25519 signature made at build time by //src/cerise/ota_updater:ota_signer; the
//!     device holds only the public key, staged at /pkg/keys/ota_image_pub.ed25519.
//!     sha256 alone was never an authenticity check — the same host served both the
//!     image and its digest. With no key staged this refuses to apply. See
//!     src/image_manifest.rs.

use anyhow::{anyhow, Context, Result};
use block_client::{BufferSlice, MutableBufferSlice, RemoteBlockClientSync};
use cerise_network_bootstrap::BootstrapPolicy;
use cerise_network_bootstrap_fuchsia::{
    bootstrap, FuchsiaBootstrapConfig, InterfaceLifetime, Ipv4Configuration,
};
use fidl::endpoints::Proxy as _;
use fidl_cerise_update as fupdate;
use fidl_fuchsia_hardware_block_volume::ServiceMarker;
use fuchsia_component::client::{open_service, Service};
use fuchsia_component::server::ServiceFs;
use fuchsia_fs::directory::readdir;
use futures::io::{AsyncReadExt as _, AsyncWriteExt as _};
use futures::{StreamExt, TryStreamExt};
use ota_http_status::validate_status_line;
use ota_image_manifest::{
    accept_image, accept_running_manifest, sha256_hex, ImageManifest, PUBKEY_PATH,
};
use ota_stage_policy::{
    hash_bounded_slot, parse_update_source, Abr, BeginPrepare, BeginStage, DeviceEvidence,
    ExpectedDevice, OperationState, Phase, PreparedMeta, SelectError, StagedMeta, StateError,
    UpdateSource,
};
use serde::Deserialize;
use std::io::{Read as _, Seek as _, Write as _};
use std::sync::{Arc, Mutex};
use zx::sys::zx_debug_write;

const LEGACY_SOURCE_BASE_URL: &str = "http://10.0.2.2:52099";
const CONFIG_PATH: &str = "/pkg/data/ota-config.json";
const SLOT_ZBI: [&str; 2] = ["zircon_a.zbi", "zircon_b.zbi"];

fn emit(msg: &str) {
    let msg = format!("{msg}\n");
    // SAFETY: zx_debug_write takes (ptr,len) of readable bytes.
    unsafe {
        zx_debug_write(msg.as_ptr(), msg.len());
    }
}

async fn sleep(secs: f32) {
    fuchsia_async::Timer::new(fuchsia_async::MonotonicInstant::after(
        std::time::Duration::from_secs_f32(secs).into(),
    ))
    .await;
}

// --------------------------------------------------------------------------------------
// Config (staged per-product; distinguishes v1/v2 on serial).
// --------------------------------------------------------------------------------------
#[derive(Debug, Deserialize)]
struct OtaConfig {
    version: u32,
    #[serde(default)]
    apply: bool,
    #[serde(default)]
    source_base_url: Option<String>,
}

async fn read_config() -> OtaConfig {
    match fuchsia_fs::file::read_in_namespace(CONFIG_PATH).await {
        Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_else(|e| {
            emit(&format!("CERISE-OTA-WARN: bad ota-config.json: {e}"));
            OtaConfig {
                version: 0,
                apply: false,
                source_base_url: None,
            }
        }),
        Err(e) => {
            emit(&format!("CERISE-OTA-WARN: no ota-config.json: {e}"));
            OtaConfig {
                version: 0,
                apply: false,
                source_base_url: None,
            }
        }
    }
}

/// Load the ed25519 public key (raw 32 bytes) staged into this component's bootfs /pkg.
///
/// FAILS CLOSED, unlike `pkg_resolver::load_pubkey`. There, a missing key degrades to
/// "honour only the trusted in-image base index" — a strictly smaller, safe set. Here a
/// missing key would degrade to "write whatever the network sent to the boot slot", so
/// absence must be a refusal. A product that stages `apply=true` must stage a key; a
/// product with `apply=false` never reaches this.
fn load_pubkey() -> Option<[u8; 32]> {
    match std::fs::read(PUBKEY_PATH) {
        Ok(bytes) => match <[u8; 32]>::try_from(bytes.as_slice()) {
            Ok(key) => {
                emit("CERISE-OTA-PUBKEY-OK");
                Some(key)
            }
            Err(_) => {
                emit(&format!(
                    "CERISE-OTA-PUBKEY-BAD: {PUBKEY_PATH} is {} bytes, expected 32",
                    bytes.len()
                ));
                None
            }
        },
        Err(e) => {
            emit(&format!("CERISE-OTA-NO-PUBKEY: {PUBKEY_PATH}: {e}"));
            None
        }
    }
}

// --------------------------------------------------------------------------------------
// Block-device discovery -> a synchronous block client.
// --------------------------------------------------------------------------------------

type BlockClientEnd = fidl::endpoints::ClientEnd<fidl_fuchsia_storage_block::BlockMarker>;

/// Opens every published whole-disk block instance.
///
/// The aggregate anonymizes instance names and may contain multiple physical disks.
/// Taking `.next()` here used to make the destructive target directory-order
/// dependent. Selection now happens only after every instance has been surveyed.
async fn acquire_block_candidates() -> Result<Vec<(String, BlockClientEnd)>> {
    // Heavy driver stack under TCG (and host contention) can take many minutes to bind
    // AHCI; retry generously so we never give up before the block device appears.
    const MAX_ATTEMPTS: u32 = 300;
    let mut last: Option<anyhow::Error> = None;
    for attempt in 0..MAX_ATTEMPTS {
        match try_acquire_block_candidates().await {
            Ok(candidates) => return Ok(candidates),
            Err(e) => {
                if attempt % 10 == 0 {
                    emit(&format!(
                        "CERISE-OTA-WAIT: no block device yet (attempt {attempt})"
                    ));
                }
                last = Some(e);
                sleep(5.0).await;
            }
        }
    }
    Err(last.unwrap_or_else(|| anyhow!("no block device")))
}

async fn try_acquire_block_candidates() -> Result<Vec<(String, BlockClientEnd)>> {
    let dir = open_service::<ServiceMarker>().context("open aggregated block Service dir")?;
    let mut instances: Vec<String> = readdir(&dir)
        .await
        .context("readdir block Service dir")?
        .into_iter()
        .map(|e| e.name)
        .collect();
    instances.sort();
    if instances.is_empty() {
        return Err(anyhow!("no block Service instances"));
    }
    let mut candidates = Vec::with_capacity(instances.len());
    for instance in instances {
        let dir = open_service::<ServiceMarker>().context("re-open block Service dir")?;
        let service = Service::<ServiceMarker>::from_service_dir_proxy(dir, ServiceMarker);
        let volume_proxy = service
            .connect_to_instance(&instance)
            .with_context(|| format!("connect_to_instance {instance}"))?;
        let block_proxy = volume_proxy
            .connect_to_volume()
            .with_context(|| format!("connect_to_volume {instance}"))?;
        let client_end = block_proxy.into_client_end().map_err(|_| {
            anyhow!("block proxy into_client_end for {instance} (outstanding refs)")
        })?;
        candidates.push((instance, client_end));
    }
    Ok(candidates)
}

// --------------------------------------------------------------------------------------
// Manual GPT parse + fatfs adapter over the synchronous block client. These run on a
// blocking thread (RemoteBlockClientSync drives its own fifo poller and block_on()s).
// --------------------------------------------------------------------------------------

/// A std::io Read+Write+Seek view of one partition of the block device, doing
/// block-aligned read-modify-write. Implements fatfs's IO traits directly.
struct PartitionIo<'a> {
    client: &'a RemoteBlockClientSync,
    base: u64, // partition start, bytes (block-aligned)
    len: u64,  // partition length, bytes
    pos: u64,  // cursor within the partition
    bs: u64,   // block size
}

impl<'a> PartitionIo<'a> {
    fn read_blocks(&self, dev_off: u64, buf: &mut [u8]) -> std::io::Result<()> {
        self.client
            .read_at(MutableBufferSlice::Memory(buf), dev_off)
            .map_err(|s| std::io::Error::other(format!("block read_at {dev_off}: {s}")))
    }
    fn write_blocks(&self, dev_off: u64, buf: &[u8]) -> std::io::Result<()> {
        self.client
            .write_at(BufferSlice::Memory(buf), dev_off)
            .map_err(|s| std::io::Error::other(format!("block write_at {dev_off}: {s}")))
    }
}

impl<'a> std::io::Read for PartitionIo<'a> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let remaining = self.len.saturating_sub(self.pos);
        let want = std::cmp::min(buf.len() as u64, remaining) as usize;
        if want == 0 {
            return Ok(0);
        }
        let start = self.base + self.pos;
        let aligned_start = (start / self.bs) * self.bs;
        let head = (start - aligned_start) as usize;
        let aligned_len = (((head + want) as u64 + self.bs - 1) / self.bs * self.bs) as usize;
        let mut tmp = vec![0u8; aligned_len];
        self.read_blocks(aligned_start, &mut tmp)?;
        buf[..want].copy_from_slice(&tmp[head..head + want]);
        self.pos += want as u64;
        Ok(want)
    }
}

impl<'a> std::io::Write for PartitionIo<'a> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let remaining = self.len.saturating_sub(self.pos);
        let want = std::cmp::min(buf.len() as u64, remaining) as usize;
        if want == 0 {
            return Ok(0);
        }
        let start = self.base + self.pos;
        let aligned_start = (start / self.bs) * self.bs;
        let head = (start - aligned_start) as usize;
        if head == 0 && (want as u64) % self.bs == 0 {
            // Fast path: fully block-aligned, no read-modify-write.
            self.write_blocks(aligned_start, &buf[..want])?;
        } else {
            let aligned_len = (((head + want) as u64 + self.bs - 1) / self.bs * self.bs) as usize;
            let mut tmp = vec![0u8; aligned_len];
            self.read_blocks(aligned_start, &mut tmp)?;
            tmp[head..head + want].copy_from_slice(&buf[..want]);
            self.write_blocks(aligned_start, &tmp)?;
        }
        self.pos += want as u64;
        Ok(want)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.client
            .flush()
            .map_err(|s| std::io::Error::other(format!("block flush: {s}")))
    }
}

impl<'a> std::io::Seek for PartitionIo<'a> {
    fn seek(&mut self, pos: std::io::SeekFrom) -> std::io::Result<u64> {
        let np = match pos {
            std::io::SeekFrom::Start(n) => n as i64,
            std::io::SeekFrom::End(n) => self.len as i64 + n,
            std::io::SeekFrom::Current(n) => self.pos as i64 + n,
        };
        if np < 0 {
            return Err(std::io::Error::other("seek before start"));
        }
        self.pos = np as u64;
        Ok(self.pos)
    }
}

/// Read `len` bytes from device byte offset `off`, doing the block-alignment itself.
///
/// The arithmetic is checked because both arguments now come, indirectly, from a
/// partition table this component did not write. `esp_locate` bounds them before they
/// get here (that is its job); this is the second line, so a future caller that skips
/// the validator gets an error rather than an aborting allocation.
fn read_dev(client: &RemoteBlockClientSync, off: u64, len: usize) -> Result<Vec<u8>> {
    let bs = client.block_size() as u64;
    if bs == 0 {
        return Err(anyhow!("block size is zero"));
    }
    let aligned_start = (off / bs) * bs;
    let head = (off - aligned_start) as usize;
    let span = (head as u64)
        .checked_add(len as u64)
        .ok_or_else(|| anyhow!("read_dev span overflows: off={off} len={len}"))?;
    let aligned_len = span
        .checked_add(bs - 1)
        .ok_or_else(|| anyhow!("read_dev alignment overflows: off={off} len={len}"))?
        / bs
        * bs;
    let mut tmp = vec![0u8; aligned_len as usize];
    client
        .read_at(MutableBufferSlice::Memory(&mut tmp), aligned_start)
        .map_err(|s| anyhow!("read_at {aligned_start}: {s}"))?;
    Ok(tmp[head..head + len].to_vec())
}

/// Locate the ESP: two validated device reads, no decisions of its own.
///
/// ALL of the judgement lives in `esp_locate` (src/esp.rs), which is pure and host-
/// tested against hostile tables no live boot could be made to produce. This function
/// exists only to move bytes: read LBA 1, ask where the entry array is, read exactly
/// that, ask where the ESP is. It cannot skip the validation, because the only thing
/// that tells it what to read second is the validator's own output.
///
/// A refusal here is TERMINAL. It used to be recoverable-by-guessing — with no ESP the
/// old code took the first non-empty partition and wrote a whole OS image into it — and
/// that is precisely the behaviour being removed. See `EspError::NoEsp`.
enum LocateFailure {
    Table(esp_locate::EspError),
    Io(anyhow::Error),
}

fn locate_esp(
    client: &RemoteBlockClientSync,
) -> std::result::Result<esp_locate::EspIdentity, LocateFailure> {
    let bs = client.block_size() as u64;
    let lba1 = read_dev(client, bs, bs as usize)
        .context("read GPT header at LBA1")
        .map_err(LocateFailure::Io)?;
    let (array_off, array_len) =
        esp_locate::entry_array_read_plan(&lba1, bs).map_err(LocateFailure::Table)?;
    let entries = read_dev(client, array_off, array_len)
        .context("read GPT entry array")
        .map_err(LocateFailure::Io)?;
    esp_locate::find_esp_identity_in_table(&lba1, &entries, bs, client.block_count())
        .map_err(LocateFailure::Table)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CommitResult {
    Committed,
    Persisted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DiskFailureKind {
    BlockUnavailable,
    DeviceAmbiguous,
    DeviceMismatch,
    Io,
}

#[derive(Debug)]
struct DiskFailure {
    kind: DiskFailureKind,
    detail: String,
}

impl DiskFailure {
    fn new(kind: DiskFailureKind, detail: impl Into<String>) -> Self {
        Self {
            kind,
            detail: detail.into(),
        }
    }
}

struct OpenCandidate {
    instance: String,
    client: Option<RemoteBlockClientSync>,
}

fn select_block_client(
    candidates: Vec<(String, BlockClientEnd)>,
    expected: ExpectedDevice,
) -> std::result::Result<(String, RemoteBlockClientSync, esp_locate::EspIdentity), DiskFailure> {
    let mut opened = Vec::with_capacity(candidates.len());
    let mut survey = Vec::with_capacity(candidates.len());
    for (instance, client_end) in candidates {
        match RemoteBlockClientSync::new(client_end) {
            Ok(client) => {
                let evidence = match locate_esp(&client) {
                    Ok(identity) => DeviceEvidence::Found(identity),
                    Err(LocateFailure::Table(e)) if e.is_inconclusive() => {
                        emit(&format!(
                            "CERISE-OTA-ESP-INCONCLUSIVE instance={instance} reason={}",
                            e.token()
                        ));
                        DeviceEvidence::Inconclusive(e.to_string())
                    }
                    Err(LocateFailure::Table(e)) => DeviceEvidence::Absent(e.to_string()),
                    Err(LocateFailure::Io(e)) => {
                        emit(&format!(
                            "CERISE-OTA-ESP-INCONCLUSIVE instance={instance} reason={e:#}"
                        ));
                        DeviceEvidence::Inconclusive(format!("{e:#}"))
                    }
                };
                survey.push((instance.clone(), evidence));
                opened.push(OpenCandidate {
                    instance,
                    client: Some(client),
                });
            }
            Err(status) => {
                let detail = format!("open block instance {instance}: {status}");
                survey.push((instance.clone(), DeviceEvidence::Inconclusive(detail)));
                opened.push(OpenCandidate {
                    instance,
                    client: None,
                });
            }
        }
    }
    let selected = ota_stage_policy::select_device(&survey, expected).map_err(|e| match e {
        SelectError::NoInstances | SelectError::NoneFound => {
            DiskFailure::new(DiskFailureKind::BlockUnavailable, format!("{e:?}"))
        }
        SelectError::Ambiguous(instances) => DiskFailure::new(
            DiskFailureKind::DeviceAmbiguous,
            format!("multiple eligible ESPs: {instances:?}"),
        ),
        SelectError::ExpectedMismatch(instances) => DiskFailure::new(
            DiskFailureKind::DeviceMismatch,
            format!("no ESP matched expected GPT identity; other ESPs: {instances:?}"),
        ),
        SelectError::Inconclusive(reasons) => DiskFailure::new(
            DiskFailureKind::BlockUnavailable,
            format!("device survey was inconclusive: {reasons:?}"),
        ),
    })?;
    let client = opened
        .iter_mut()
        .find(|candidate| candidate.instance == selected.instance)
        .and_then(|candidate| candidate.client.take())
        .ok_or_else(|| {
            DiskFailure::new(
                DiskFailureKind::Io,
                "selected block instance no longer has an open client",
            )
        })?;
    emit(&format!(
        "CERISE-OTA-ESP-OK instance={} offset={} bytes={}",
        selected.instance, selected.identity.range.offset, selected.identity.range.len
    ));
    Ok((selected.instance, client, selected.identity))
}

fn mount_esp<'a>(
    client: &'a RemoteBlockClientSync,
    identity: esp_locate::EspIdentity,
) -> Result<fatfs::FileSystem<PartitionIo<'a>>> {
    let io = PartitionIo {
        client,
        base: identity.range.offset,
        len: identity.range.len,
        pos: 0,
        bs: client.block_size() as u64,
    };
    fatfs::FileSystem::new(io, fatfs::FsOptions::new()).context("mount FAT on ESP")
}

/// Convert an ESP that still boots `bootx64.zbi` into the A/B layout.
///
/// The ordering is the durability contract:
///
/// 1. copy the exact legacy image to slot A, unmount, and flush the device;
/// 2. remount and hash slot A back;
/// 3. create `abr` as the final filesystem mutation, then unmount and flush.
///
/// Until step 3 the boot shim ignores slot A and keeps using the legacy path.
/// Once `abr` exists, slot A is a readback-verified successful copy.
fn bootstrap_legacy_layout(
    client: &RemoteBlockClientSync,
    identity: esp_locate::EspIdentity,
) -> std::result::Result<Option<BootCommit>, DiskFailure> {
    let abr_missing = {
        let fs = mount_esp(client, identity)
            .map_err(|e| DiskFailure::new(DiskFailureKind::Io, format!("{e:#}")))?;
        let probe = {
            let root = fs.root_dir();
            match root.open_file("abr") {
                Ok(_) => Ok(false),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(true),
                Err(error) => Err(DiskFailure::new(
                    DiskFailureKind::Io,
                    format!("probe abr: {error}"),
                )),
            }
        };
        let unmount = fs
            .unmount()
            .map_err(|e| DiskFailure::new(DiskFailureKind::Io, format!("unmount FAT: {e}")));
        let missing = probe?;
        unmount?;
        missing
    };
    if !abr_missing {
        return Ok(None);
    }

    let (legacy_digest, legacy_size) = {
        let fs = mount_esp(client, identity)
            .map_err(|e| DiskFailure::new(DiskFailureKind::Io, format!("{e:#}")))?;
        let copied = {
            let root = fs.root_dir();
            (|| {
                let mut legacy = root.open_file("bootx64.zbi").map_err(|e| {
                    DiskFailure::new(DiskFailureKind::Io, format!("open legacy bootx64.zbi: {e}"))
                })?;
                let (digest, size) =
                    hash_bounded_slot(&mut legacy, MAX_IMAGE_BYTES).map_err(|e| {
                        DiskFailure::new(
                            DiskFailureKind::Io,
                            format!("hash legacy bootx64.zbi: {e}"),
                        )
                    })?;
                legacy.seek(std::io::SeekFrom::Start(0)).map_err(|e| {
                    DiskFailure::new(
                        DiskFailureKind::Io,
                        format!("rewind legacy bootx64.zbi: {e}"),
                    )
                })?;
                let mut slot = root.create_file(SLOT_ZBI[0]).map_err(|e| {
                    DiskFailure::new(DiskFailureKind::Io, format!("create bootstrap slot A: {e}"))
                })?;
                slot.truncate().map_err(|e| {
                    DiskFailure::new(
                        DiskFailureKind::Io,
                        format!("truncate bootstrap slot A: {e}"),
                    )
                })?;
                let mut remaining = size;
                let mut chunk = [0u8; 64 * 1024];
                while remaining != 0 {
                    let want = std::cmp::min(remaining, chunk.len() as u64) as usize;
                    legacy.read_exact(&mut chunk[..want]).map_err(|e| {
                        DiskFailure::new(
                            DiskFailureKind::Io,
                            format!("read legacy image during bootstrap: {e}"),
                        )
                    })?;
                    slot.write_all(&chunk[..want]).map_err(|e| {
                        DiskFailure::new(
                            DiskFailureKind::Io,
                            format!("write bootstrap slot A: {e}"),
                        )
                    })?;
                    remaining -= want as u64;
                }
                slot.flush().map_err(|e| {
                    DiskFailure::new(DiskFailureKind::Io, format!("flush bootstrap slot A: {e}"))
                })?;
                Ok::<_, DiskFailure>((digest, size))
            })()
        };
        let unmount = fs.unmount().map_err(|e| {
            DiskFailure::new(
                DiskFailureKind::Io,
                format!("unmount after bootstrap slot write: {e}"),
            )
        });
        let copied = copied?;
        unmount?;
        copied
    };
    client.flush().map_err(|status| {
        DiskFailure::new(
            DiskFailureKind::Io,
            format!("flush bootstrap slot A: {status}"),
        )
    })?;

    {
        let fs = mount_esp(client, identity)
            .map_err(|e| DiskFailure::new(DiskFailureKind::Io, format!("{e:#}")))?;
        let verified = {
            let root = fs.root_dir();
            (|| {
                let mut slot = root.open_file(SLOT_ZBI[0]).map_err(|e| {
                    DiskFailure::new(
                        DiskFailureKind::Io,
                        format!("open bootstrap slot A for readback: {e}"),
                    )
                })?;
                let (readback_digest, readback_size) =
                    hash_bounded_slot(&mut slot, MAX_IMAGE_BYTES).map_err(|e| {
                        DiskFailure::new(
                            DiskFailureKind::Io,
                            format!("hash bootstrap slot A readback: {e}"),
                        )
                    })?;
                if readback_digest != legacy_digest || readback_size != legacy_size {
                    return Err(DiskFailure::new(
                        DiskFailureKind::Io,
                        "bootstrap slot A readback does not match bootx64.zbi",
                    ));
                }

                // Activation metadata is deliberately the final mutation.
                let mut abr_file = root.create_file("abr").map_err(|e| {
                    DiskFailure::new(DiskFailureKind::Io, format!("create bootstrap abr: {e}"))
                })?;
                abr_file.truncate().map_err(|e| {
                    DiskFailure::new(DiskFailureKind::Io, format!("truncate bootstrap abr: {e}"))
                })?;
                abr_file
                    .write_all(&Abr::legacy_bootstrap().to_bytes())
                    .and_then(|_| abr_file.flush())
                    .map_err(|e| {
                        DiskFailure::new(DiskFailureKind::Io, format!("publish bootstrap abr: {e}"))
                    })
            })()
        };
        let unmount = fs.unmount().map_err(|e| {
            DiskFailure::new(
                DiskFailureKind::Io,
                format!("unmount after bootstrap activation: {e}"),
            )
        });
        verified?;
        unmount?;
    }
    client.flush().map_err(|status| {
        DiskFailure::new(
            DiskFailureKind::Io,
            format!("flush bootstrap activation: {status}"),
        )
    })?;
    emit(&format!(
        "CERISE-OTA-LEGACY-BOOTSTRAPPED slot=A sha256={legacy_digest} bytes={legacy_size}"
    ));
    Ok(Some(BootCommit {
        commit: CommitResult::Persisted,
        running_sha256: legacy_digest,
        running_size: legacy_size,
    }))
}

fn commit_running_slot(
    candidates: Vec<(String, BlockClientEnd)>,
) -> std::result::Result<BootCommit, DiskFailure> {
    let (_, client, identity) = select_block_client(candidates, ExpectedDevice::default())?;
    if let Some(commit) = bootstrap_legacy_layout(&client, identity)? {
        let _ = client.close();
        return Ok(commit);
    }
    let fs = mount_esp(&client, identity)
        .map_err(|e| DiskFailure::new(DiskFailureKind::Io, format!("{e:#}")))?;
    let commit;
    let running_sha256;
    let running_size;
    {
        let root = fs.root_dir();
        let mut abr_bytes = [0u8; 16];
        {
            let mut file = root
                .open_file("abr")
                .map_err(|e| DiskFailure::new(DiskFailureKind::Io, format!("open abr: {e}")))?;
            file.read_exact(&mut abr_bytes)
                .map_err(|e| DiskFailure::new(DiskFailureKind::Io, format!("read abr: {e}")))?;
        }
        let mut abr = Abr::parse(&abr_bytes)
            .map_err(|_| DiskFailure::new(DiskFailureKind::Io, "invalid abr record"))?;
        let running = abr.active as usize;
        commit = if abr.mark_running_successful() {
            let mut file = root
                .open_file("abr")
                .map_err(|e| DiskFailure::new(DiskFailureKind::Io, format!("open abr: {e}")))?;
            file.seek(std::io::SeekFrom::Start(0))
                .and_then(|_| file.write_all(&abr.to_bytes()))
                .and_then(|_| file.flush())
                .map_err(|e| {
                    DiskFailure::new(DiskFailureKind::Io, format!("commit running slot: {e}"))
                })?;
            CommitResult::Committed
        } else {
            CommitResult::Persisted
        };
        let mut slot = root.open_file(SLOT_ZBI[running]).map_err(|e| {
            DiskFailure::new(
                DiskFailureKind::Io,
                format!("open running slot for boot-health hash: {e}"),
            )
        })?;
        (running_sha256, running_size) =
            hash_bounded_slot(&mut slot, MAX_IMAGE_BYTES).map_err(|e| {
                DiskFailure::new(
                    DiskFailureKind::Io,
                    format!("hash exact running slot contents: {e}"),
                )
            })?;
    }
    fs.unmount()
        .map_err(|e| DiskFailure::new(DiskFailureKind::Io, format!("unmount FAT: {e}")))?;
    client
        .flush()
        .map_err(|s| DiskFailure::new(DiskFailureKind::Io, format!("block flush: {s}")))?;
    let _ = client.close();
    Ok(BootCommit {
        commit,
        running_sha256,
        running_size,
    })
}

struct BootCommit {
    commit: CommitResult,
    running_sha256: String,
    running_size: u64,
}
struct DiskStage {
    instance: String,
    identity: esp_locate::EspIdentity,
    slot: u8,
}

fn stage_prepared_disk(
    candidates: Vec<(String, BlockClientEnd)>,
    bytes: &[u8],
    expected: ExpectedDevice,
    progress: impl Fn(Phase, &str),
) -> std::result::Result<DiskStage, DiskFailure> {
    let (instance, client, identity) = select_block_client(candidates, expected)?;
    progress(Phase::WritingSlot, "writing and flushing the inactive slot");
    let mut abr_bytes = [0u8; 16];
    let mut abr;
    let inactive;
    {
        let fs = mount_esp(&client, identity)
            .map_err(|e| DiskFailure::new(DiskFailureKind::Io, format!("{e:#}")))?;
        {
            let root = fs.root_dir();
            let mut abr_file = root.open_file("abr").map_err(|e| {
                DiskFailure::new(DiskFailureKind::Io, format!("open abr for read: {e}"))
            })?;
            abr_file
                .read_exact(&mut abr_bytes)
                .map_err(|e| DiskFailure::new(DiskFailureKind::Io, format!("read abr: {e}")))?;
            abr = Abr::parse(&abr_bytes)
                .map_err(|_| DiskFailure::new(DiskFailureKind::Io, "invalid abr record"))?;
            inactive = abr.inactive_slot();
            let mut slot = root.create_file(SLOT_ZBI[inactive]).map_err(|e| {
                DiskFailure::new(DiskFailureKind::Io, format!("create inactive slot: {e}"))
            })?;
            slot.truncate()
                .and_then(|_| slot.write_all(bytes))
                .and_then(|_| slot.flush())
                .map_err(|e| {
                    DiskFailure::new(DiskFailureKind::Io, format!("write inactive slot: {e}"))
                })?;
        }
        fs.unmount().map_err(|e| {
            DiskFailure::new(
                DiskFailureKind::Io,
                format!("unmount after slot write: {e}"),
            )
        })?;
    }
    client
        .flush()
        .map_err(|s| DiskFailure::new(DiskFailureKind::Io, format!("flush inactive slot: {s}")))?;

    progress(
        Phase::VerifyingSlot,
        "remounting the ESP and reading back the inactive slot",
    );
    {
        let fs = mount_esp(&client, identity)
            .map_err(|e| DiskFailure::new(DiskFailureKind::Io, format!("{e:#}")))?;
        {
            let root = fs.root_dir();
            let mut slot = root.open_file(SLOT_ZBI[inactive]).map_err(|e| {
                DiskFailure::new(DiskFailureKind::Io, format!("open slot for readback: {e}"))
            })?;
            let mut offset = 0usize;
            let mut chunk = [0u8; 64 * 1024];
            while offset < bytes.len() {
                let want = std::cmp::min(chunk.len(), bytes.len() - offset);
                slot.read_exact(&mut chunk[..want]).map_err(|e| {
                    DiskFailure::new(
                        DiskFailureKind::Io,
                        format!("readback inactive slot at {offset}: {e}"),
                    )
                })?;
                if chunk[..want] != bytes[offset..offset + want] {
                    return Err(DiskFailure::new(
                        DiskFailureKind::Io,
                        format!("inactive-slot readback mismatch at byte {offset}"),
                    ));
                }
                offset += want;
            }
            let mut extra = [0u8; 1];
            if slot.read(&mut extra).map_err(|e| {
                DiskFailure::new(DiskFailureKind::Io, format!("readback EOF check: {e}"))
            })? != 0
            {
                return Err(DiskFailure::new(
                    DiskFailureKind::Io,
                    "inactive-slot file is longer than the verified image",
                ));
            }

            // Activation metadata is the final FAT mutation.
            progress(
                Phase::CommittingActivation,
                "readback verified; committing A/B activation metadata last",
            );
            let (activation_slot, activated) = abr.activation_for_inactive();
            debug_assert_eq!(activation_slot, inactive);
            abr = activated;
            let mut abr_file = root.open_file("abr").map_err(|e| {
                DiskFailure::new(DiskFailureKind::Io, format!("open abr for activation: {e}"))
            })?;
            abr_file
                .seek(std::io::SeekFrom::Start(0))
                .and_then(|_| abr_file.write_all(&abr.to_bytes()))
                .and_then(|_| abr_file.flush())
                .map_err(|e| {
                    DiskFailure::new(
                        DiskFailureKind::Io,
                        format!("commit activation metadata: {e}"),
                    )
                })?;
        }
        fs.unmount().map_err(|e| {
            DiskFailure::new(
                DiskFailureKind::Io,
                format!("unmount after activation: {e}"),
            )
        })?;
    }
    client.flush().map_err(|s| {
        DiskFailure::new(DiskFailureKind::Io, format!("final activation flush: {s}"))
    })?;
    let _ = client.close();
    Ok(DiskStage {
        instance,
        identity,
        slot: inactive as u8,
    })
}

// --------------------------------------------------------------------------------------
// Network bring-up (cloned from pkg_fetcher) + HTTP/1 fetch + sha256 verify.
// --------------------------------------------------------------------------------------

async fn bring_up_network() -> Result<Option<InterfaceLifetime>> {
    let result = bootstrap(
        FuchsiaBootstrapConfig {
            interface_name: "ota-eth0",
            ipv4: Ipv4Configuration::Dhcp {
                timeout_seconds: 45,
            },
            // Preserve the original 60 attempts with a three-second delay.
            policy: BootstrapPolicy {
                discovery_attempts: 60,
                retry_delay_seconds: 3,
                reuse_existing_ipv4: true,
            },
            enable_before_address: true,
            observe_slaac: false,
            install_default_route: false,
            check_socket_provider: false,
        },
        None,
    )
    .await?;
    if result.reused_existing_ipv4 {
        emit("CERISE-OTA-NETWORK-REUSE");
        return Ok(None);
    }
    let ipv4 = result
        .ipv4
        .context("adapter returned no DHCP configuration")?;
    emit(&format!(
        "CERISE-OTA-DHCP-LEASE={}.{}.{}.{}/{}",
        ipv4.address[0], ipv4.address[1], ipv4.address[2], ipv4.address[3], ipv4.prefix_len
    ));
    Ok(result.lifetime)
}

/// The largest OS image this will accept off the network, and the largest manifest.
///
/// The response is read BEFORE its signature can be checked — the signature is over the
/// manifest, and the manifest arrives over the same unauthenticated channel — so
/// nothing in the signed data can bound this read. A `read_to_end` with no ceiling lets
/// whoever answers at the caller-selected source grow the updater's heap until the
/// component dies.
/// The bound therefore has to be a local constant. Slot ZBIs are ~45 MiB today and the
/// ESP slot is sized for far more, so 256 MiB is generous headroom that is still a
/// bound; the manifest is a few hundred bytes.
const MAX_IMAGE_BYTES: u64 = 256 << 20;
const MAX_MANIFEST_BYTES: u64 = 64 << 10;

fn parse_source(source: fupdate::Source) -> Result<UpdateSource> {
    let base_url = source
        .base_url
        .ok_or_else(|| anyhow!("source.base_url is required"))?;
    parse_update_source(
        &base_url,
        source.manifest_path.as_deref(),
        source.image_path.as_deref(),
    )
    .map_err(|e| anyhow!("{e}"))
}

fn parse_running_manifest_source(source: fupdate::RunningManifestSource) -> Result<UpdateSource> {
    let base_url = source
        .base_url
        .ok_or_else(|| anyhow!("source.base_url is required"))?;
    parse_update_source(&base_url, source.manifest_path.as_deref(), None)
        .map_err(|e| anyhow!("{e}"))
}

/// Plain HTTP/1.0 GET over a blocking std::net::TcpStream (real fdio), reading at most
/// `limit` bytes of body + headers and refusing anything longer.
async fn http_get(source: &UpdateSource, path: &str, limit: u64) -> Result<Vec<u8>> {
    const HTTP_IO_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
    const MAX_HTTP_HEADER_BYTES: u64 = 64 << 10;
    let socket_addr = source
        .socket_addr
        .parse()
        .with_context(|| format!("parse HTTP socket address {}", source.socket_addr))?;
    // std::net::TcpStream::connect_timeout uses a poll/ioctl path that fdio
    // does not implement for these sockets. Keep connect and write bounded with
    // native async-socket deadlines. The response uses the same duration as an
    // IDLE deadline per read, rather than as a whole-transfer deadline: a valid
    // image can take longer than 30 seconds on a busy or negotiated-down link,
    // and continuous bounded progress is not a stall.
    let deadline = fuchsia_async::MonotonicInstant::after(HTTP_IO_TIMEOUT.into());
    let connecting = fuchsia_async::net::TcpStream::connect(socket_addr)
        .with_context(|| format!("begin connect {}", source.socket_addr))?;
    let mut stream =
        fuchsia_async::TimeoutExt::on_timeout(async { Some(connecting.await) }, deadline, || None)
            .await
            .ok_or_else(|| anyhow!("connect {} timed out", source.socket_addr))?
            .with_context(|| format!("connect {}", source.socket_addr))?;
    let req = format!(
        "GET {path} HTTP/1.0\r\nHost: {}\r\nConnection: close\r\n\r\n",
        source.socket_addr
    );
    fuchsia_async::TimeoutExt::on_timeout(
        async { Some(stream.write_all(req.as_bytes()).await) },
        deadline,
        || None,
    )
    .await
    .ok_or_else(|| anyhow!("HTTP GET {path} timed out while writing"))?
    .context("write HTTP request")?;
    let wire_limit = limit
        .checked_add(MAX_HTTP_HEADER_BYTES)
        .ok_or_else(|| anyhow!("HTTP GET {path} byte ceiling overflow"))?;
    let mut buf = Vec::new();
    // This buffer lives across an await. Keep it off the component's bounded
    // thread stack; a 64 KiB array here can exhaust that stack before the first
    // HTTP read even begins.
    let mut chunk = vec![0u8; 64 << 10];
    loop {
        let idle_deadline = fuchsia_async::MonotonicInstant::after(HTTP_IO_TIMEOUT.into());
        let read = fuchsia_async::TimeoutExt::on_timeout(
            async { Some(stream.read(&mut chunk).await) },
            idle_deadline,
            || None,
        )
        .await
        .ok_or_else(|| anyhow!("HTTP GET {path} stalled for 30 seconds while reading"))?
        .context("read HTTP response")?;
        if read == 0 {
            break;
        }
        if (buf.len() as u64).saturating_add(read as u64) > wire_limit {
            return Err(anyhow!(
                "HTTP GET {path} exceeds the {limit}-byte body ceiling"
            ));
        }
        buf.extend_from_slice(&chunk[..read]);
    }
    let sep = b"\r\n\r\n";
    let idx = buf
        .windows(4)
        .position(|w| w == sep)
        .ok_or_else(|| anyhow!("no HTTP header terminator for {path}"))?;
    let status_end = buf
        .windows(2)
        .position(|w| w == b"\r\n")
        .ok_or_else(|| anyhow!("no HTTP status-line terminator for {path}"))?;
    if status_end > idx {
        return Err(anyhow!("HTTP GET {path} has a malformed status line"));
    }
    let status_line = &buf[..status_end];
    validate_status_line(status_line)
        .map_err(|reason| anyhow!("HTTP GET {path} not 200: {reason}"))?;
    let body = &buf[idx + 4..];
    if body.len() as u64 > limit {
        return Err(anyhow!(
            "HTTP GET {path} exceeds the {limit}-byte body ceiling"
        ));
    }
    Ok(body.to_vec())
}

/// Fetch the new ZBI + its signed manifest, and return the bytes ONLY if the whole
/// chain holds: signature, anti-rollback, signed size, signed digest.
///
/// The decision itself is `ota_image_manifest::accept_image` — one call, so the host
/// tests in src/image_manifest.rs cover the real decision and not a paraphrase of it.
/// The `running_version` floor comes from this image's own staged config, which is the
/// only version state the updater has that an attacker on the network cannot touch.
async fn fetch_verified_zbi(
    pubkey: Option<&[u8; 32]>,
    running_version: u32,
    source: &UpdateSource,
) -> Result<(ImageManifest, Vec<u8>)> {
    let manifest_bytes = http_get(source, &source.manifest_path, MAX_MANIFEST_BYTES)
        .await
        .with_context(|| format!("GET {}", source.manifest_path))?;
    let manifest: ImageManifest =
        serde_json::from_slice(&manifest_bytes).context("parse manifest")?;
    let zbi = http_get(source, &source.image_path, MAX_IMAGE_BYTES)
        .await
        .with_context(|| format!("GET {}", source.image_path))?;
    if let Err(r) = accept_image(&manifest, pubkey, running_version, &zbi) {
        // A distinct, greppable marker per class, so the serial log distinguishes "the
        // update was refused" from "the update failed" — and so the tamper gate has
        // something to REQUIRE rather than only an absence to observe.
        emit(&format!("CERISE-OTA-IMAGE-REJECT: {}", r.token()));
        return Err(anyhow!("refusing offered image: {r}"));
    }
    emit(&format!(
        "CERISE-OTA-FETCH-OK version={} sha256={} bytes={}",
        manifest.version,
        manifest.sha256,
        zbi.len()
    ));
    emit("CERISE-OTA-SIG-OK");
    Ok((manifest, zbi))
}

/// Fetch only a signed manifest and bind it to the active-slot evidence from
/// this boot. This performs no update-state or ESP mutation and never fetches
/// the image body named by an ordinary update source.
async fn fetch_verified_running_manifest(
    pubkey: Option<&[u8; 32]>,
    running_version: u32,
    running_sha256: &str,
    running_size: u64,
    source: &UpdateSource,
) -> Result<(ImageManifest, String)> {
    let manifest_bytes = http_get(source, &source.manifest_path, MAX_MANIFEST_BYTES)
        .await
        .with_context(|| format!("GET {}", source.manifest_path))?;
    let manifest_sha256 = sha256_hex(&manifest_bytes);
    let manifest: ImageManifest =
        serde_json::from_slice(&manifest_bytes).context("parse running-image manifest")?;
    if let Err(rejection) = accept_running_manifest(
        &manifest,
        pubkey,
        running_version,
        running_sha256,
        running_size,
    ) {
        emit(&format!(
            "CERISE-OTA-RUNNING-IMAGE-REJECT: {}",
            rejection.token()
        ));
        return Err(anyhow!("refusing running-image evidence: {rejection}"));
    }
    emit(&format!(
        "CERISE-OTA-RUNNING-SIG-OK version={} sha256={} bytes={}",
        manifest.version, manifest.sha256, manifest.size
    ));
    Ok((manifest, manifest_sha256))
}

// --------------------------------------------------------------------------------------

#[derive(Clone)]
struct PreparedImage {
    meta: PreparedMeta,
    bytes: Arc<Vec<u8>>,
}

struct Runtime {
    running_version: u32,
    running_sha256: String,
    running_size: u64,
    state: Mutex<OperationState>,
    image: Mutex<Option<PreparedImage>>,
    last_error: Mutex<Option<fupdate::StageError>>,
    network_ready: Mutex<bool>,
    network: Mutex<Option<InterfaceLifetime>>,
}

impl Runtime {
    fn new(running_version: u32, running_sha256: String, running_size: u64) -> Arc<Self> {
        Arc::new(Self {
            running_version,
            running_sha256,
            running_size,
            state: Mutex::new(OperationState::default()),
            image: Mutex::new(None),
            last_error: Mutex::new(None),
            network_ready: Mutex::new(false),
            network: Mutex::new(None),
        })
    }

    fn fail(&self, error: fupdate::StageError, detail: impl Into<String>) {
        let detail = detail.into();
        self.state.lock().expect("state lock").fail(detail.clone());
        *self.last_error.lock().expect("error lock") = Some(error);
        emit(&format!(
            "CERISE-OTA-STAGE-FAIL phase=failed detail={detail}"
        ));
    }

    fn set_phase(&self, phase: Phase, detail: &str) {
        self.state
            .lock()
            .expect("state lock")
            .set_phase(phase, detail);
        emit(&format!("CERISE-OTA-PHASE {}", phase_token(phase)));
    }
}

fn phase_token(phase: Phase) -> &'static str {
    match phase {
        Phase::Idle => "idle",
        Phase::Downloading => "downloading",
        Phase::Verified => "verified",
        Phase::LocatingDevice => "locating-device",
        Phase::WritingSlot => "writing-slot",
        Phase::VerifyingSlot => "verifying-slot",
        Phase::CommittingActivation => "committing-activation",
        Phase::Staged => "staged",
        Phase::Failed => "failed",
    }
}

fn fidl_phase(phase: Phase) -> fupdate::Phase {
    match phase {
        Phase::Idle => fupdate::Phase::Idle,
        Phase::Downloading => fupdate::Phase::Downloading,
        Phase::Verified => fupdate::Phase::Verified,
        Phase::LocatingDevice => fupdate::Phase::LocatingDevice,
        Phase::WritingSlot => fupdate::Phase::WritingSlot,
        Phase::VerifyingSlot => fupdate::Phase::VerifyingSlot,
        Phase::CommittingActivation => fupdate::Phase::CommittingActivation,
        Phase::Staged => fupdate::Phase::Staged,
        Phase::Failed => fupdate::Phase::Failed,
    }
}

fn fidl_prepared(meta: &PreparedMeta) -> fupdate::Prepared {
    fupdate::Prepared {
        operation_id: Some(meta.operation_id.clone()),
        version: Some(meta.version),
        sha256: Some(meta.sha256.clone()),
        size: Some(meta.size),
        source_base_url: Some(meta.source_base_url.clone()),
        source_manifest_path: Some(meta.source_manifest_path.clone()),
        source_image_path: Some(meta.source_image_path.clone()),
        ..Default::default()
    }
}

fn fidl_staged(meta: &StagedMeta) -> fupdate::Staged {
    fupdate::Staged {
        operation_id: Some(meta.prepared.operation_id.clone()),
        version: Some(meta.prepared.version),
        sha256: Some(meta.prepared.sha256.clone()),
        size: Some(meta.prepared.size),
        block_instance: Some(meta.block_instance.clone()),
        disk_guid: Some(meta.disk_guid),
        esp_guid: Some(meta.esp_guid),
        slot: Some(meta.slot),
        ..Default::default()
    }
}

fn fidl_status(runtime: &Runtime) -> fupdate::Status {
    let state = runtime.state.lock().expect("state lock").clone();
    fupdate::Status {
        phase: Some(fidl_phase(state.phase)),
        operation_id: (!state.operation_id.is_empty()).then_some(state.operation_id),
        detail: (!state.detail.is_empty()).then_some(state.detail),
        prepared: state.prepared.as_ref().map(fidl_prepared),
        staged: state.staged.as_ref().map(fidl_staged),
        error: *runtime.last_error.lock().expect("error lock"),
        running_version: Some(runtime.running_version),
        running_sha256: Some(runtime.running_sha256.clone()),
        running_size: Some(runtime.running_size),
        ..Default::default()
    }
}

fn map_state_error(error: StateError) -> fupdate::StageError {
    match error {
        StateError::InvalidOperationId => fupdate::StageError::InvalidArgument,
        StateError::Busy => fupdate::StageError::Busy,
        StateError::NotPrepared => fupdate::StageError::NotPrepared,
    }
}

fn map_disk_error(kind: DiskFailureKind) -> fupdate::StageError {
    match kind {
        DiskFailureKind::BlockUnavailable => fupdate::StageError::BlockUnavailable,
        DiskFailureKind::DeviceAmbiguous => fupdate::StageError::DeviceAmbiguous,
        DiskFailureKind::DeviceMismatch => fupdate::StageError::DeviceMismatch,
        DiskFailureKind::Io => fupdate::StageError::Io,
    }
}

fn source_matches(meta: &PreparedMeta, source: &UpdateSource) -> bool {
    meta.source_base_url == source.base_url
        && meta.source_manifest_path == source.manifest_path
        && meta.source_image_path == source.image_path
}

async fn prepare(
    runtime: Arc<Runtime>,
    operation_id: String,
    source: fupdate::Source,
) -> std::result::Result<fupdate::Prepared, fupdate::StageError> {
    let source = parse_source(source).map_err(|e| {
        emit(&format!("CERISE-OTA-SOURCE-REJECT: {e:#}"));
        fupdate::StageError::InvalidArgument
    })?;
    let begin = runtime
        .state
        .lock()
        .expect("state lock")
        .begin_prepare(&operation_id)
        .map_err(map_state_error)?;
    match begin {
        BeginPrepare::AlreadyPrepared => {
            let current_image = runtime.image.lock().expect("image lock").clone();
            let meta = if let Some(image) = current_image {
                image.meta
            } else {
                // Stage completion publishes the terminal state before releasing
                // the image bytes. If this retry crossed that boundary, return the
                // staged operation instead of manufacturing an INTERNAL race.
                runtime
                    .state
                    .lock()
                    .expect("state lock")
                    .staged
                    .as_ref()
                    .map(|staged| staged.prepared.clone())
                    .ok_or(fupdate::StageError::Internal)?
            };
            if !source_matches(&meta, &source) {
                return Err(fupdate::StageError::InvalidArgument);
            }
            return Ok(fidl_prepared(&meta));
        }
        BeginPrepare::AlreadyStaged => {
            let state = runtime.state.lock().expect("state lock");
            let staged = state.staged.as_ref().ok_or(fupdate::StageError::Internal)?;
            if !source_matches(&staged.prepared, &source) {
                return Err(fupdate::StageError::InvalidArgument);
            }
            return Ok(fidl_prepared(&staged.prepared));
        }
        BeginPrepare::Started => {}
    }
    *runtime.last_error.lock().expect("error lock") = None;

    let pubkey = load_pubkey();
    let Some(pubkey) = pubkey else {
        runtime.fail(
            fupdate::StageError::ArtifactRejected,
            "no OTA public key is staged",
        );
        return Err(fupdate::StageError::ArtifactRejected);
    };
    let need_network = !*runtime.network_ready.lock().expect("network lock");
    if need_network {
        let network = bring_up_network().await.map_err(|e| {
            runtime.fail(
                fupdate::StageError::BlockUnavailable,
                format!("bring up update network: {e:#}"),
            );
            fupdate::StageError::BlockUnavailable
        })?;
        *runtime.network.lock().expect("network owner lock") = network;
        *runtime.network_ready.lock().expect("network lock") = true;
    }
    let (manifest, bytes) =
        match fetch_verified_zbi(Some(&pubkey), runtime.running_version, &source).await {
            Ok(image) => image,
            Err(e) => {
                runtime.fail(
                    fupdate::StageError::ArtifactRejected,
                    format!("fetch or verify image: {e:#}"),
                );
                return Err(fupdate::StageError::ArtifactRejected);
            }
        };
    let meta = PreparedMeta {
        operation_id,
        version: manifest.version,
        sha256: manifest.sha256,
        size: bytes.len() as u64,
        source_base_url: source.base_url,
        source_manifest_path: source.manifest_path,
        source_image_path: source.image_path,
    };
    {
        let mut state = runtime.state.lock().expect("state lock");
        let mut image = runtime.image.lock().expect("image lock");
        *image = Some(PreparedImage {
            meta: meta.clone(),
            bytes: Arc::new(bytes),
        });
        state.finish_prepare(meta.clone());
    }
    emit(&format!(
        "CERISE-OTA-PREPARED operation={} version={}",
        meta.operation_id, meta.version
    ));
    Ok(fidl_prepared(&meta))
}

async fn verify_running(
    runtime: Arc<Runtime>,
    source: fupdate::RunningManifestSource,
) -> std::result::Result<fupdate::VerifiedRunning, fupdate::StageError> {
    let source = parse_running_manifest_source(source).map_err(|error| {
        emit(&format!("CERISE-OTA-RUNNING-SOURCE-REJECT: {error:#}"));
        fupdate::StageError::InvalidArgument
    })?;
    let Some(pubkey) = load_pubkey() else {
        emit("CERISE-OTA-RUNNING-IMAGE-REJECT: no-pubkey");
        return Err(fupdate::StageError::ArtifactRejected);
    };
    let need_network = !*runtime.network_ready.lock().expect("network lock");
    if need_network {
        let network = bring_up_network().await.map_err(|error| {
            emit(&format!(
                "CERISE-OTA-RUNNING-VERIFY-FAIL: bring up update network: {error:#}"
            ));
            fupdate::StageError::BlockUnavailable
        })?;
        *runtime.network.lock().expect("network owner lock") = network;
        *runtime.network_ready.lock().expect("network lock") = true;
    }
    let public_key_sha256 = sha256_hex(&pubkey);
    let (manifest, manifest_sha256) = fetch_verified_running_manifest(
        Some(&pubkey),
        runtime.running_version,
        &runtime.running_sha256,
        runtime.running_size,
        &source,
    )
    .await
    .map_err(|error| {
        emit(&format!(
            "CERISE-OTA-RUNNING-VERIFY-FAIL: fetch or verify manifest: {error:#}"
        ));
        fupdate::StageError::ArtifactRejected
    })?;
    Ok(fupdate::VerifiedRunning {
        version: Some(manifest.version),
        sha256: Some(manifest.sha256),
        size: Some(manifest.size),
        manifest_sha256: Some(manifest_sha256),
        public_key_sha256: Some(public_key_sha256),
        ..Default::default()
    })
}

async fn stage(
    runtime: Arc<Runtime>,
    request: fupdate::StageRequest,
) -> std::result::Result<fupdate::Staged, fupdate::StageError> {
    let operation_id = request.operation_id.unwrap_or_default();
    let begin = runtime
        .state
        .lock()
        .expect("state lock")
        .begin_stage(&operation_id)
        .map_err(map_state_error)?;
    if let BeginStage::AlreadyStaged(staged) = begin {
        return Ok(fidl_staged(&staged));
    }
    *runtime.last_error.lock().expect("error lock") = None;
    let image = runtime
        .image
        .lock()
        .expect("image lock")
        .clone()
        .ok_or(fupdate::StageError::NotPrepared)?;
    let expected = ExpectedDevice {
        disk_guid: request.expected_disk_guid,
        esp_guid: request.expected_esp_guid,
    };
    let candidates = match acquire_block_candidates().await {
        Ok(candidates) => candidates,
        Err(e) => {
            runtime.fail(
                fupdate::StageError::BlockUnavailable,
                format!("acquire block devices: {e:#}"),
            );
            return Err(fupdate::StageError::BlockUnavailable);
        }
    };
    let progress_runtime = runtime.clone();
    let bytes = image.bytes.clone();
    let result = fuchsia_async::unblock(move || {
        stage_prepared_disk(candidates, bytes.as_slice(), expected, |phase, detail| {
            progress_runtime.set_phase(phase, detail);
        })
    })
    .await;
    let disk = match result {
        Ok(disk) => disk,
        Err(error) => {
            let fidl_error = map_disk_error(error.kind);
            runtime.fail(fidl_error, error.detail);
            return Err(fidl_error);
        }
    };
    let staged = StagedMeta {
        prepared: image.meta,
        block_instance: disk.instance,
        disk_guid: disk.identity.disk_guid,
        esp_guid: disk.identity.partition_guid,
        slot: disk.slot,
    };
    {
        let mut state = runtime.state.lock().expect("state lock");
        let mut image = runtime.image.lock().expect("image lock");
        state.finish_stage(staged.clone());
        *image = None;
    }
    emit(&format!(
        "CERISE-OTA-APPLIED operation={} slot={} version={}",
        staged.prepared.operation_id, staged.slot, staged.prepared.version
    ));
    Ok(fidl_staged(&staged))
}

async fn serve(runtime: Arc<Runtime>, mut stream: fupdate::StagerRequestStream) -> Result<()> {
    while let Some(request) = stream.try_next().await.context("read Stager request")? {
        match request {
            fupdate::StagerRequest::Prepare { payload, responder } => {
                let result = match payload.source {
                    Some(source) => {
                        prepare(
                            runtime.clone(),
                            payload.operation_id.unwrap_or_default(),
                            source,
                        )
                        .await
                    }
                    None => Err(fupdate::StageError::InvalidArgument),
                };
                match result {
                    Ok(prepared) => responder.send(Ok(&prepared))?,
                    Err(error) => responder.send(Err(error))?,
                }
            }
            fupdate::StagerRequest::StagePrepared { payload, responder } => {
                match stage(runtime.clone(), payload).await {
                    Ok(staged) => responder.send(Ok(&staged))?,
                    Err(error) => responder.send(Err(error))?,
                }
            }
            fupdate::StagerRequest::DiscardPrepared {
                operation_id,
                responder,
            } => {
                let result = runtime
                    .state
                    .lock()
                    .expect("state lock")
                    .discard_prepared(&operation_id)
                    .map_err(map_state_error);
                if result.is_ok() {
                    *runtime.image.lock().expect("image lock") = None;
                    *runtime.last_error.lock().expect("error lock") = None;
                }
                responder.send(result)?;
            }
            fupdate::StagerRequest::VerifyRunning { payload, responder } => {
                let result = match payload.source {
                    Some(source) => verify_running(runtime.clone(), source).await,
                    None => Err(fupdate::StageError::InvalidArgument),
                };
                match result {
                    Ok(running) => responder.send(Ok(&running))?,
                    Err(error) => responder.send(Err(error))?,
                }
            }
            fupdate::StagerRequest::GetStatus { responder } => {
                responder.send(&fidl_status(&runtime))?;
            }
        }
    }
    Ok(())
}

async fn run() -> Result<()> {
    emit("CERISE-OTA-START");
    let cfg = read_config().await;
    emit(&format!("CERISE-OS-VERSION={}", cfg.version));

    // A booted slot is acknowledged before accepting a new operation. This does
    // not activate anything; it only prevents the boot shim from rolling back a
    // slot which demonstrably reached this component.
    let candidates = acquire_block_candidates()
        .await
        .context("acquire block devices")?;
    let boot_commit = fuchsia_async::unblock(move || commit_running_slot(candidates))
        .await
        .map_err(|e| anyhow!("commit running slot: {}", e.detail))?;
    match boot_commit.commit {
        CommitResult::Committed => emit("CERISE-OTA-COMMITTED"),
        CommitResult::Persisted => emit("CERISE-OTA-PERSISTED"),
    }
    emit(&format!(
        "CERISE-OTA-RUNNING-SHA256={}",
        boot_commit.running_sha256
    ));

    let runtime = Runtime::new(
        cfg.version,
        boot_commit.running_sha256,
        boot_commit.running_size,
    );
    let mut services = ServiceFs::new_local();
    services
        .dir("svc")
        .add_fidl_service(|stream: fupdate::StagerRequestStream| stream);
    services
        .take_and_serve_directory_handle()
        .context("serve Stager outgoing directory")?;

    // Compatibility for the dedicated OTA validation product: `apply=true` invokes
    // the same two-phase implementation, but still does not reboot. Production
    // HostControl uses the FIDL methods and places host quiesce between them.
    if cfg.apply {
        let auto_runtime = runtime.clone();
        let auto_source = fupdate::Source {
            base_url: Some(
                cfg.source_base_url
                    .clone()
                    .unwrap_or_else(|| LEGACY_SOURCE_BASE_URL.to_owned()),
            ),
            ..Default::default()
        };
        fuchsia_async::Task::local(async move {
            emit("CERISE-OTA-APPLY-BEGIN");
            match prepare(
                auto_runtime.clone(),
                "configured-auto-update".to_owned(),
                auto_source,
            )
            .await
            {
                Ok(_) => {
                    let request = fupdate::StageRequest {
                        operation_id: Some("configured-auto-update".to_owned()),
                        ..Default::default()
                    };
                    if let Err(error) = stage(auto_runtime, request).await {
                        emit(&format!("CERISE-OTA-FAIL: automatic stage: {error:?}"));
                    }
                }
                Err(error) => emit(&format!("CERISE-OTA-FAIL: automatic prepare: {error:?}")),
            }
        })
        .detach();
    }

    services
        .for_each_concurrent(None, move |stream| {
            let runtime = runtime.clone();
            async move {
                if let Err(e) = serve(runtime, stream).await {
                    emit(&format!("CERISE-OTA-FIDL-FAIL: {e:#}"));
                }
            }
        })
        .await;
    Ok(())
}

fn main() {
    let mut executor = fuchsia_async::LocalExecutor::default();
    executor.run_singlethreaded(async {
        if let Err(e) = run().await {
            emit(&format!("CERISE-OTA-FAIL: {e:#}"));
        }
    });
}

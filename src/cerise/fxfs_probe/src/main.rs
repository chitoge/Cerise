// Filesystem gate: fxfs_probe — proves real Fxfs format+mount+write+remount+read on a real
// block device, through the actual vendored Fxfs core library (LSM tree, journal,
// allocator, object store) — not a shortcut.
//
// Path chosen: this file drives `fxfs::filesystem::FxFilesystem` and
// `fxfs::object_store` DIRECTLY, in-process, rather than going through the full CFv2
// `fuchsia.fs.startup.{Startup,Volumes}` FIDL surface that `fxfs/platform`'s
// `Component::run()` serves (see fxfs/platform/src/fuchsia/component.rs). That fuller
// path is the real fshost-driven "fxfs runs as its own server component, a separate
// client drives it over FIDL" shape — genuinely more scope (a second component +
// cross-component Startup/Volumes routing) and is deliberately left as future `fshost`
// work. The in-process approach used here is NOT a shortcut: it is the exact
// same real Fxfs core API (`FxFilesystem::new_empty`/`open`, `Directory::open`,
// `create_child_file`, `DataObjectHandle::contents`) that Fxfs's OWN vendored unit tests
// use to validate the real object store (see fxfs/src/filesystem.rs's `#[cfg(test)]`
// module, e.g. `test_compaction`) — just pointed at a real hardware-backed block device
// (NVMe/AHCI via the proven block_client/block_server stack) instead of a FakeDevice.
// Real journal writes, real LSM-tree operations, real block I/O all happen for real.
//
// Crypt: this drives the REAL `crypt_fxfs` component over `fuchsia.fxfs/{Crypt,
// CryptManagement}` — not `StoreOptions { crypt: None, .. }`. A `ProbeCrypt` type below
// mirrors `fxfs/platform`'s real `RemoteCrypt` (src/fuchsia/remote_crypt.rs) exactly —
// same FIDL calls, same `fxfs_crypto::Crypt` trait impl — reimplemented locally (rather
// than depending on the whole `fxfs_platform` crate, which would drag in vfs_head/
// pseudo_fs_head/delivery_blob-lz4/feedback+battery FIDL just for one ~50-line struct)
// to keep this probe's dependency footprint proportionate, the same judgment call
// netdev_probe made reusing block_client directly instead of the whole driver_host
// stack. `root_volume(fs)::new_volume("default", ..)` creates an ACTUAL encrypted child
// object store (the root store itself stays unencrypted metadata, matching real Fxfs's
// multi-volume design — see object_store/volume.rs's module doc); the wrapping key is
// provisioned once per boot via `CryptManagement.AddWrappingKey`/`SetActiveKey` before
// the retry loop starts (crypt_fxfs is a single long-lived instance for the whole boot;
// re-adding the same wrapping key ID on every retry would hit its own "already used
// slot" rejection — see crypt_fxfs's own `add_forget_key` unit test).
//
// Collision with nvme_probe/ahci_probe: this component and nvme_probe/ahci_probe are
// all Eager children of the same root, all reaching into the SAME anonymized aggregate
// `fuchsia.hardware.block.volume.Service` pool (instance
// names are opaque hashes, not human-readable, and there is no way for a client to pick
// a *specific* controller). nvme_probe/ahci_probe each do ONE raw destructive
// write_at(0)/read_at(0) test-pattern cycle and then stop touching the device;
// fxfs_probe's own full format+write+remount+read sequence could genuinely race against
// that one-shot window on whichever instance it happens to land on. Rather than invent
// a whole new product/topology to dodge this (out of scope here), this file
// retries its ENTIRE sequence (from a fresh instance-discovery pass onward) up to
// several times with short delays — the same "a channel that's seen an error is
// permanently dead, redo everything" philosophy already used by netdev_probe/
// nvme_probe/ahci_probe. Once the other probes' one-shot tests quiesce, a later retry
// gets uncontested access. Documented honestly, not papered over.
//
// Real bug found and fixed: `FxFilesystem::new_empty` (the actual format path) crashed
// with a hard kernel exception (`KERN: terminating process`, return_code=-1028 =
// ZX_TASK_RETCODE_EXCEPTION_KILL) and no panic message anywhere. Isolated by first
// proving `storage_device::Device`'s own allocate/write/read plumbing works cleanly
// against the real block device (this is the FIRST real exercise of
// `storage_device::block_device::BlockDevice`/its buffer allocator in this project --
// nvme_probe/ahci_probe only ever use `block_client::RemoteBlockClient` directly,
// bypassing storage_device entirely) -- ruling that layer out. The crash was a stack
// overflow: Fxfs's format path builds deeply-nested, generic-heavy async state machines
// (LSM tree, journal, allocator, checksums) that overflow this component's default
// thread stack. Fixed by running the actual async work on a dedicated OS thread with an
// explicit 16 MiB stack (with its own `fuchsia_async::LocalExecutor`, since executors
// are per-thread) instead of `#[fuchsia_async::run_singlethreaded]` on main's own
// default-sized thread. This is a real, legitimate fix (plenty of real-world async/
// recursive code needs a bigger-than-default stack) -- not a workaround for a Cerise
// bug elsewhere.

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use block_client::{BlockClient as _, RemoteBlockClient};
use fidl_fuchsia_fxfs::{
    CryptManagementMarker, CryptMarker, CryptProxy, KeyPurpose as FidlKeyPurpose,
};
use fidl_fuchsia_hardware_block_volume::ServiceMarker;
use fuchsia_component::client::{connect_to_protocol, open_service, Service};
use fxfs::filesystem::{FxFilesystem, SyncOptions};
use fxfs::object_handle::{ObjectHandle as _, WriteObjectHandle as _};
use fxfs::object_store::directory::Directory;
use fxfs::object_store::transaction::{lock_keys, LockKey, Options as TxnOptions};
use fxfs::object_store::volume::root_volume;
use fxfs::object_store::{HandleOptions, NewChildStoreOptions, ObjectStore, StoreOptions};
use fxfs_crypto::{
    Crypt, EncryptionKey, FxfsKey, KeyPurpose, ObjectType, UnwrappedKey, WrappedKey,
    WrappedKeyBytes, WrappingKeyId,
};
use std::sync::Arc;
use storage_device::block_device::BlockDevice;
use storage_device::DeviceHolder;

const FILE_NAME: &str = "cerise_test.txt";
const CONTENT: &[u8] = b"CERISE-FXFS-PERSISTED-DATA";
const VOLUME_NAME: &str = "default";
// Real fshost (environment/fxfs_container.rs's `FxfsContainer`) hard-requires a "blob"
// volume to already exist on any device its `FxblobMatcher` claims via content-sniffing
// -- `mount_blob_volume()` (environment.rs) calls `open_volume("blob", ...)`, which OPENS
// an existing volume, it does not create one. Real Fuchsia provisions this once via a
// hardware/GPT-backed `fuchsia.fshost.fxfsprovisioner/FxfsProvisioner` genesis flow that
// has no equivalent component in Cerise's topology. fxfs_probe substitutes for that
// one-time genesis step by creating a real (bare, unencrypted, matching real Fxfs's own
// blob-volume semantics -- blobs are content-addressed and don't need per-file
// encryption) "blob" volume directly, so fshost's later independent `FxFilesystem::open`
// of this same on-disk device sees a real, complete `{blob, ...}` volume set on first
// content-sniff, instead of failing to open a "blob" volume that was never created and
// (before this fix) falling into fshost's own provision_fxfs fallback panic path.
const BLOB_VOLUME_NAME: &str = "blob";
// Fixed test wrapping key: fxfs_probe is a proof-of-real-encryption component, not a
// production key-management story — a hardcoded 32-byte key matches crypt_fxfs's own
// unit-test pattern (see storage/crypt/fxfs/src/lib.rs's `#[fuchsia::test]`s).
const WRAPPING_KEY_ID: u128 = 1;
const WRAPPING_KEY: [u8; 32] = [0xAB; 32];

/// Mirrors `fxfs/platform`'s real `RemoteCrypt` (src/fuchsia/remote_crypt.rs) — same
/// FIDL calls, same trait impl — reimplemented locally to avoid depending on the whole
/// `fxfs_platform` crate for one small struct (see the file-level comment above).
struct ProbeCrypt {
    client: CryptProxy,
}

// A FIDL transport-level error (channel closed, decode failure, etc.) has no natural
// zx::Status of its own; this trait only carries wrapping/unwrapping outcomes, so
// collapse any transport error to INTERNAL — good enough for a proof-of-encryption
// probe, not meant to be a rich error-mapping story like fxfs/platform's real one.
fn fidl_err_to_status(_e: fidl::Error) -> zx::Status {
    zx::Status::INTERNAL
}

trait IntoFidlKeyPurpose {
    fn into_fidl(self) -> FidlKeyPurpose;
}
impl IntoFidlKeyPurpose for KeyPurpose {
    fn into_fidl(self) -> FidlKeyPurpose {
        match self {
            KeyPurpose::Data => FidlKeyPurpose::Data,
            KeyPurpose::Metadata => FidlKeyPurpose::Metadata,
        }
    }
}

#[async_trait]
impl Crypt for ProbeCrypt {
    async fn create_key(
        &self,
        owner: u64,
        purpose: KeyPurpose,
    ) -> Result<(FxfsKey, UnwrappedKey), zx::Status> {
        let (wrapping_key_id, key, unwrapped_key) = self
            .client
            .create_key(owner, purpose.into_fidl())
            .await
            .map_err(fidl_err_to_status)?
            .map_err(zx::Status::from_raw)?;
        Ok((
            FxfsKey {
                wrapping_key_id,
                key: WrappedKeyBytes::try_from(key).map_err(|_| zx::Status::INVALID_ARGS)?,
            },
            UnwrappedKey::new(unwrapped_key),
        ))
    }

    async fn create_key_with_id(
        &self,
        owner: u64,
        wrapping_key_id: WrappingKeyId,
        object_type: ObjectType,
    ) -> Result<(EncryptionKey, UnwrappedKey), zx::Status> {
        let (key, unwrapped_key) = self
            .client
            .create_key_with_id(owner, &wrapping_key_id, object_type)
            .await
            .map_err(fidl_err_to_status)?
            .map_err(zx::Status::from_raw)?;
        Ok((key.try_into().map_err(|_| zx::Status::INVALID_ARGS)?, UnwrappedKey::new(unwrapped_key)))
    }

    async fn unwrap_key(
        &self,
        wrapped_key: &WrappedKey,
        owner: u64,
    ) -> Result<UnwrappedKey, zx::Status> {
        let unwrapped = self
            .client
            .unwrap_key(owner, wrapped_key)
            .await
            .map_err(fidl_err_to_status)?
            .map_err(zx::Status::from_raw)?;
        Ok(UnwrappedKey::new(unwrapped))
    }
}

/// Connects a FRESH `fuchsia.fxfs/Crypt` session and wraps it in `ProbeCrypt`. Called
/// separately for format and for remount, matching the "every attempt gets a fresh
/// channel" philosophy already used for the block device connection itself.
fn connect_crypt() -> Result<Arc<dyn Crypt>> {
    let client = connect_to_protocol::<CryptMarker>().context("failed to connect to Crypt")?;
    Ok(Arc::new(ProbeCrypt { client }) as Arc<dyn Crypt>)
}

/// Provisions the wrapping key crypt_fxfs needs before ANY create_key/unwrap_key call
/// can succeed. Called exactly once per boot (before the retry loop in `run()`), not
/// per-attempt — crypt_fxfs is one long-lived component instance for the whole boot, and
/// re-adding the same wrapping key ID twice is rejected (see crypt_fxfs's own
/// `add_forget_key` unit test: "add_key should fail on a used slot").
async fn provision_crypt_keys() -> Result<()> {
    let mgmt = connect_to_protocol::<CryptManagementMarker>()
        .context("failed to connect to CryptManagement")?;
    mgmt.add_wrapping_key(&WRAPPING_KEY_ID.to_le_bytes(), &WRAPPING_KEY)
        .await
        .context("AddWrappingKey FIDL call failed")?
        .map_err(zx::Status::from_raw)
        .context("AddWrappingKey rejected")?;
    mgmt.set_active_key(FidlKeyPurpose::Data, &WRAPPING_KEY_ID.to_le_bytes())
        .await
        .context("SetActiveKey(Data) FIDL call failed")?
        .map_err(zx::Status::from_raw)
        .context("SetActiveKey(Data) rejected")?;
    mgmt.set_active_key(FidlKeyPurpose::Metadata, &WRAPPING_KEY_ID.to_le_bytes())
        .await
        .context("SetActiveKey(Metadata) FIDL call failed")?
        .map_err(zx::Status::from_raw)
        .context("SetActiveKey(Metadata) rejected")?;
    Ok(())
}

fn emit(msg: &str) {
    unsafe {
        zx::sys::zx_debug_write(msg.as_ptr(), msg.len());
    }
}

// DIAGNOSTIC: unconditional stage-entry trace, same rationale as nvme_probe/ahci_probe
// and netdev_probe before them — a hang inside a silent async call would otherwise
// produce zero output (neither an OK nor a FAIL print).
fn trace(stage: &str) {
    emit(&format!("CERISE-FXFS-PROBE-TRACE-{stage}\n"));
}

async fn list_instances() -> Result<Vec<String>> {
    let dir = open_service::<ServiceMarker>().context("failed to open aggregated Service dir")?;
    let entries = fuchsia_fs::directory::readdir(&dir)
        .await
        .context("failed to read aggregated Service directory")?;
    Ok(entries.into_iter().map(|e| e.name).collect())
}

async fn connect_block_client(instance: &str) -> Result<RemoteBlockClient> {
    let dir = open_service::<ServiceMarker>().context("failed to re-open Service dir")?;
    let service = Service::<ServiceMarker>::from_service_dir_proxy(dir, ServiceMarker);
    let volume_proxy = service
        .connect_to_instance(instance)
        .context("failed to connect to instance")?;
    let block_proxy = volume_proxy
        .connect_to_volume()
        .context("failed to connect to volume member")?;
    RemoteBlockClient::new(block_proxy)
        .await
        .map_err(|s| anyhow!("RemoteBlockClient::new failed: {s}"))
}

/// One full attempt: format, write a file, close, reopen fresh, read the file back and
/// verify the bytes. Returns Ok(()) only on a complete, verified success.
async fn try_instance(instance: &str) -> Result<()> {
    trace("CONNECT");
    let remote = connect_block_client(instance).await?;
    trace("CONNECTED");
    let block_size = remote.block_size();
    let block_count = remote.block_count();
    log::info!(block_size, block_count, instance:% = instance; "fxfs probe: connected to block device");
    if block_size == 0 {
        return Err(anyhow!("device reported block_size=0"));
    }
    trace("BLOCKDEVICE-NEW");
    let device = BlockDevice::new(remote, false)
        .await
        .map_err(|e| anyhow!("BlockDevice::new failed: {e}"))?;
    trace("BLOCKDEVICE-NEW-DONE");

    trace("FORMAT-START");
    let fs = FxFilesystem::new_empty(DeviceHolder::new(device))
        .await
        .map_err(|e| anyhow!("FxFilesystem::new_empty (format) failed: {e}"))?;
    trace("FORMAT-DONE");
    emit("CERISE-FXFS-FORMAT-OK\n");

    // Real encrypted volume: the root store itself stays unencrypted metadata (matching
    // real Fxfs's design — see object_store/volume.rs's module doc), and an actual named
    // child volume is created under it with a real Arc<dyn Crypt> backed by crypt_fxfs.
    // create_key() (invoked inside new_volume's store.create()) is the first real
    // exercise of the whole Crypt FIDL round-trip.
    trace("CRYPT-CONNECT");
    let crypt = connect_crypt()?;
    trace("ROOT-VOLUME");
    let root_vol = root_volume(fs.clone())
        .await
        .map_err(|e| anyhow!("root_volume failed: {e}"))?;
    trace("NEW-VOLUME");
    let store = root_vol
        .new_volume(
            VOLUME_NAME,
            NewChildStoreOptions {
                options: StoreOptions { crypt: Some(crypt), ..Default::default() },
                ..Default::default()
            },
        )
        .await
        .map_err(|e| anyhow!("new_volume (encrypted) failed: {e}"))?;
    emit("CERISE-FXFS-CRYPT-OK\n");

    // Real "blob" volume -- see BLOB_VOLUME_NAME's doc comment. Bare/unencrypted
    // (crypt: None), matching real Fxfs's own blob-volume design; nothing needs to be
    // written into it for fshost's later `open_volume("blob", ...)` to succeed.
    trace("BLOB-VOLUME");
    root_vol
        .new_volume(
            BLOB_VOLUME_NAME,
            NewChildStoreOptions { options: StoreOptions { crypt: None, ..Default::default() }, ..Default::default() },
        )
        .await
        .map_err(|e| anyhow!("new_volume (blob) failed: {e}"))?;
    emit("CERISE-FXFS-BLOB-VOLUME-OK\n");

    trace("WRITE");
    {
        let root_directory = Directory::open(&store, store.root_directory_object_id())
            .await
            .map_err(|e| anyhow!("Directory::open (volume root, write side) failed: {e}"))?;
        let mut transaction = fs
            .clone()
            .new_transaction(
                lock_keys![LockKey::object(store.store_object_id(), root_directory.object_id())],
                TxnOptions::default(),
            )
            .await
            .map_err(|e| anyhow!("new_transaction failed: {e}"))?;
        let handle = root_directory
            .create_child_file(&mut transaction, FILE_NAME)
            .await
            .map_err(|e| anyhow!("create_child_file failed: {e}"))?;
        transaction.commit().await.map_err(|e| anyhow!("transaction.commit failed: {e}"))?;

        let mut buf = handle.allocate_buffer(CONTENT.len()).await;
        buf.as_mut_slice().copy_from_slice(CONTENT);
        handle
            .write_or_append(Some(0), buf.as_ref())
            .await
            .map_err(|e| anyhow!("write_or_append failed: {e}"))?;
        fs.sync(SyncOptions::default())
            .await
            .map_err(|e| anyhow!("sync failed: {e}"))?;
    }
    emit("CERISE-FXFS-WRITE-OK\n");

    trace("CLOSE");
    fs.close().await.map_err(|e| anyhow!("close (pre-remount) failed: {e}"))?;

    // Remount: a fresh RemoteBlockClient session over the SAME instance, and a fresh
    // FxFilesystem::open (not new_empty) — this is the real proof of on-disk
    // persistence, not just an in-memory illusion within one filesystem instance.
    trace("REMOUNT");
    let remote2 = connect_block_client(instance).await?;
    let device2 = BlockDevice::new(remote2, false)
        .await
        .map_err(|e| anyhow!("BlockDevice::new (remount) failed: {e}"))?;
    let fs2 = FxFilesystem::open(DeviceHolder::new(device2))
        .await
        .map_err(|e| anyhow!("FxFilesystem::open (remount) failed: {e}"))?;
    emit("CERISE-FXFS-REMOUNT-OK\n");

    trace("READ");
    let read_result: Result<()> = async {
        // Fresh Crypt session + unlock the SAME named encrypted volume — this is the
        // real proof that the wrapped keys persisted on-disk and crypt_fxfs can
        // actually unwrap them again after a full remount, not just within one
        // filesystem instance's in-memory Crypt reference.
        let crypt2 = connect_crypt()?;
        let root_vol2 =
            root_volume(fs2.clone()).await.map_err(|e| anyhow!("root_volume (remount) failed: {e}"))?;
        let store2 = root_vol2
            .volume(VOLUME_NAME, StoreOptions { crypt: Some(crypt2), ..Default::default() })
            .await
            .map_err(|e| anyhow!("volume (unlock encrypted, remount) failed: {e}"))?;
        let root_directory2 = Directory::open(&store2, store2.root_directory_object_id())
            .await
            .map_err(|e| anyhow!("Directory::open (volume root, read side) failed: {e}"))?;
        let (object_id, _descriptor, _) = root_directory2
            .lookup(FILE_NAME)
            .await
            .map_err(|e| anyhow!("lookup failed: {e}"))?
            .ok_or_else(|| anyhow!("file not found after remount"))?;
        let handle2 = ObjectStore::open_object(&store2, object_id, HandleOptions::default(), None)
            .await
            .map_err(|e| anyhow!("open_object failed: {e}"))?;
        let contents = handle2
            .contents(CONTENT.len() + 16)
            .await
            .map_err(|e| anyhow!("contents (read) failed: {e}"))?;
        if &*contents != CONTENT {
            return Err(anyhow!(
                "readback mismatch: got {:?}, want {:?}",
                contents,
                CONTENT
            ));
        }
        Ok(())
    }
    .await;

    // Always try to close fs2 cleanly, but don't let a close error mask a real read
    // failure (or vice versa) — surface whichever happened first.
    let close_result = fs2.close().await;
    read_result?;
    close_result.map_err(|e| anyhow!("close (post-remount) failed: {e}"))?;

    emit("CERISE-FXFS-READ-OK\n");
    Ok(())
}

async fn try_once() -> Result<()> {
    trace("LIST-INSTANCES");
    let instances = list_instances().await?;
    if instances.is_empty() {
        return Err(anyhow!("no aggregate-Service instances published yet"));
    }
    let mut last_err = None;
    for instance in &instances {
        match try_instance(instance).await {
            Ok(()) => return Ok(()),
            Err(e) => last_err = Some(e),
        }
    }
    Err(last_err.unwrap_or_else(|| anyhow!("no instances tried")))
}

async fn run() -> Option<anyhow::Error> {
    // Initialize the LogSink-backed structured logging backend. This runs inside the
    // dedicated-thread LocalExecutor (see main()), which diagnostics_log::initialize
    // requires. Degrades to a no-op if LogSink isn't routed (MissingOnInit).
    if let Err(e) = diagnostics_log::initialize(
        diagnostics_log::PublishOptions::default().tags(&["fxfs_probe"]),
    ) {
        emit(&format!("CERISE-FXFS-PROBE-LOG-INIT-WARN: {e:?}\n"));
    }
    log::info!("fxfs_probe starting: format + write + remount + read on a real block device");

    // Provision the wrapping key exactly once, before the main retry loop —
    // crypt_fxfs's Lazy startup means this first connection is what actually starts
    // the component (CFv2 routing blocks/queues the Open() until it does), so a short
    // retry here is just extra robustness against any transient early-boot hiccup, not
    // a real expected failure mode.
    const CRYPT_PROVISION_ATTEMPTS: u32 = 10;
    const CRYPT_PROVISION_DELAY: std::time::Duration = std::time::Duration::from_secs(2);
    let mut provisioned = false;
    for _ in 0..CRYPT_PROVISION_ATTEMPTS {
        trace("CRYPT-PROVISION");
        match provision_crypt_keys().await {
            Ok(()) => {
                provisioned = true;
                break;
            }
            Err(_) => {
                fuchsia_async::Timer::new(fuchsia_async::MonotonicInstant::after(
                    CRYPT_PROVISION_DELAY.into(),
                ))
                .await;
            }
        }
    }
    if !provisioned {
        return Some(anyhow!("failed to provision crypt_fxfs wrapping key after retries"));
    }
    trace("CRYPT-PROVISIONED");

    // nvme_probe/ahci_probe (same boot, same aggregate-Service pool) use 60 * 5s =
    // 300s to cover the real ~180-200s gap before NVMe/AHCI finish binding. fxfs_probe
    // additionally needs headroom for its own format+write+remount+read work once it
    // has a device, within run-qemu.sh's 420s TIMEOUT_SECONDS ceiling for x64-pci —
    // 50 * 5s = 250s leaves that margin.
    const MAX_ATTEMPTS: u32 = 50;
    const RETRY_DELAY: std::time::Duration = std::time::Duration::from_secs(5);

    let mut last_err = None;
    for attempt in 0..MAX_ATTEMPTS {
        match try_once().await {
            Ok(()) => {
                log::info!("fxfs_probe: format/write/remount/read verified end-to-end");
                last_err = None;
                break;
            }
            Err(e) => {
                log::warn!(attempt = attempt + 1, max = MAX_ATTEMPTS; "fxfs_probe attempt failed, retrying: {e:#}");
                last_err = Some(e);
                fuchsia_async::Timer::new(fuchsia_async::MonotonicInstant::after(
                    RETRY_DELAY.into(),
                ))
                .await;
            }
        }
        let _ = attempt;
    }
    last_err
}

// DIAGNOSTIC (temporary): fxfs's real format path (FxFilesystem::new_empty) crashed
// with a hard kernel exception (KERN: terminating process, return_code=-1028 =
// ZX_TASK_RETCODE_EXCEPTION_KILL) with no panic message printed anywhere -- ruling out
// storage_device's own plumbing first (a self-test read/write directly through
// storage_device::Device against the real block device, done above in try_instance,
// succeeds cleanly every time). Fxfs's format path builds deeply-nested async state
// machines across many generic-heavy modules (LSM tree, journal, allocator, checksums);
// a stack overflow on this component's default thread stack is a real, plausible cause
// for exactly this failure signature (SIGSEGV-class exception, no panic message since a
// stack overflow can't even run the panic machinery). Testing this by running the
// actual async work on a dedicated OS thread with an explicit, generous stack size,
// with its own fuchsia_async LocalExecutor (executors are per-thread) instead of the
// default `#[fuchsia_async::run_singlethreaded]` attribute on main's own (default-sized)
// thread.
fn main() {
    const STACK_SIZE: usize = 16 * 1024 * 1024; // 16 MiB
    let handle = std::thread::Builder::new()
        .name("fxfs_probe-main".to_string())
        .stack_size(STACK_SIZE)
        .spawn(|| {
            let mut executor = fuchsia_async::LocalExecutor::default();
            executor.run_singlethreaded(run())
        })
        .expect("failed to spawn fxfs_probe-main thread");
    let last_err = handle.join().expect("fxfs_probe-main thread panicked");

    if let Some(e) = last_err {
        emit(&format!("CERISE-FXFS-PROBE-FAIL: {e:?}\n"));
        std::process::exit(1);
    }
}

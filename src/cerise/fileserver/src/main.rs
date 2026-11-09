// Cerise gRPC file server — the FLAGSHIP deliverable.
//
// A real gRPC (h2c prior-knowledge) read-write file server running as a CMv2
// component on modern Fuchsia: it brings up a netstack3 interface itself (reusing
// the proven netstack3_probe InstallDevice path), listens on 0.0.0.0:50051 through
// fuchsia_async::net (the async accept path proven by the initial prototype fasync_tcp_spike),
// and serves gRPC per connection via hyper's HTTP/2 server driven by the
// cerise-hyper-rt adapter (FasyncExec + FasyncIo) over the transport-free @grpc
// tonic-generated FileServerServer.
//
// service integration (this file): transport proof. The service returns a CANNED Stat response
// (real fxfs backing lands in storage-backed integration). GREEN here = gRPC over fuchsia-async over
// netstack3, host-reachable — the novel hard part — is proven.

mod claim;
mod crypt;
mod fs;
mod lifecycle;
mod path_safety;
mod read_stream;
mod resumable_sha256;
mod status;
mod storage_policy;

use std::{
    collections::HashMap,
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context as TaskContext, Poll},
};

use anyhow::{anyhow, Context, Result};
use cerise_hyper_rt::{FasyncExec, FasyncIo};
use cerise_network_bootstrap::BootstrapPolicy;
use cerise_network_bootstrap_fuchsia::{
    bootstrap, FuchsiaBootstrapConfig, FuchsiaBootstrapResult, Ipv4Configuration,
};
use fidl_cerise_network as fnetwork;
use fidl_cerise_storage as fstorage;
use hyper_util::service::TowerToHyperService;
use tonic::codegen::{http, Service as TowerService};
// The @grpc tonic-generated crate. The rust_prost_library's crate name derives from
// the proto_library (`fileserver_proto`); package `cerise.fileserver.v1` -> modules.
use fileserver_proto::cerise::fileserver::v1 as pb;
use pb::file_server_server::{FileServer, FileServerServer};

const LISTEN_ADDR: &str = "0.0.0.0:50051";
/// Generic mutations of controller-owned namespaces are available only on
/// loopback. The externally reachable listener still serves reads and the
/// purpose-built managed image-import state machine.
const CONTROL_LISTEN_ADDR: &str = "127.0.0.1:50053";
/// Import clients use 32 MiB payloads so object lookup/flush transaction costs
/// are amortized without permitting unbounded request allocation.
const MAX_GRPC_DECODING_BYTES: usize = 40 * 1024 * 1024;
const GRPC_FLOW_CONTROL_WINDOW_BYTES: u32 = 16 * 1024 * 1024;
const MAX_GRPC_CONNECTIONS: usize = 16;
const MAX_CONCURRENT_DECODES: usize = 8;

// Raw serial write, reserved for the CERISE-* boot-gate markers the validation boot
// tests grep for (byte-for-byte). All other operational output goes through the
// structured LogSink path (log:: macros, tag "fileserver").
fn emit(msg: &str) {
    unsafe {
        zx::sys::zx_debug_write(msg.as_ptr(), msg.len());
    }
}

// Stage-entry diagnostics now flow as structured DEBUG records through LogSink instead
// of raw CERISE-FILESERVER-TRACE-* serial markers.
fn trace(stage: &str) {
    log::debug!(stage; "fileserver stage entry");
}

// ------------------------------------------------------------------------------
// The gRPC service — storage-backed integration: real, backed by the in-process fxfs mount.
// ------------------------------------------------------------------------------

/// The service. `mount` is an OPTION on purpose — see `run()`: when the disk
/// claim is refused the component still listens, and every RPC then reports the
/// refusal instead of the process silently never coming up.
#[derive(Clone)]
struct CeriseFileServer {
    mount: Option<Arc<fs::Mount>>,
    generic_mutation_authority: GenericMutationAuthority,
    lifecycle: StorageLifecycle,
    /// Serializes durable reservation and publication decisions. Bulk bytes
    /// are still written by separate RPCs, but every request observes the
    /// journals left by its predecessor before changing import state.
    allocation_gate: Arc<futures::lock::Mutex<()>>,
    /// Serializes one immutable import identity without making unrelated
    /// imports, VM spill, or snapshot publication wait for recovery hashing.
    import_locks: Arc<std::sync::Mutex<HashMap<String, std::sync::Weak<futures::lock::Mutex<()>>>>>,
    /// Process-local progressive digests. Per-import locks serialize each
    /// entry; this mutex only makes the map shareable across tonic clones.
    import_sessions: Arc<std::sync::Mutex<ImageImportRuntime>>,
    import_policy: ImageImportPolicy,
    /// Why there is no filesystem, verbatim into every FAILED_PRECONDITION.
    unavailable: Arc<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum GenericMutationAuthority {
    Public,
    Controller,
}

#[derive(Clone, Copy)]
struct ImageImportPolicy {
    max_image_bytes: u64,
    max_active_imports: usize,
    max_hash_sessions: usize,
    max_receipts: usize,
}

impl ImageImportPolicy {
    fn from_process_args() -> Result<Self> {
        let mut policy = Self {
            max_image_bytes: 1 << 40,
            max_active_imports: IMAGE_IMPORT_ACTIVE_LIMIT,
            max_hash_sessions: IMAGE_IMPORT_HASH_SESSION_LIMIT,
            max_receipts: IMAGE_IMPORT_RECEIPT_LIMIT,
        };
        for argument in std::env::args().skip(1) {
            let Some((name, value)) = argument.split_once('=') else {
                continue;
            };
            match name {
                "--max-image-import-bytes" => {
                    policy.max_image_bytes =
                        value.parse().context("parsing --max-image-import-bytes")?;
                }
                "--max-active-image-imports" => {
                    policy.max_active_imports = value
                        .parse()
                        .context("parsing --max-active-image-imports")?;
                }
                "--max-image-import-hash-sessions" => {
                    policy.max_hash_sessions = value
                        .parse()
                        .context("parsing --max-image-import-hash-sessions")?;
                }
                "--max-image-import-receipts" => {
                    policy.max_receipts = value
                        .parse()
                        .context("parsing --max-image-import-receipts")?;
                }
                _ => continue,
            }
        }
        anyhow::ensure!(
            policy.max_image_bytes > 0,
            "image import byte ceiling is zero"
        );
        anyhow::ensure!(
            policy.max_active_imports > 0,
            "active image import ceiling is zero"
        );
        anyhow::ensure!(
            policy.max_hash_sessions > 0,
            "image import hash-session ceiling is zero"
        );
        anyhow::ensure!(
            policy.max_receipts > 0,
            "image import receipt ceiling is zero"
        );
        Ok(policy)
    }
}

impl CeriseFileServer {
    fn reject_dormant_mutation_context(
        &self,
        context: &Option<pb::MutationContext>,
    ) -> Result<(), tonic::Status> {
        if context.is_some() {
            return Err(tonic::Status::unimplemented(
                "durable mutation-source admission is not enabled",
            ));
        }
        Ok(())
    }

    fn import_lock(&self, import_id: &str) -> Arc<futures::lock::Mutex<()>> {
        let mut locks = self
            .import_locks
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        locks.retain(|_, lock| lock.strong_count() != 0);
        if let Some(lock) = locks.get(import_id).and_then(std::sync::Weak::upgrade) {
            return lock;
        }
        let lock = Arc::new(futures::lock::Mutex::new(()));
        locks.insert(import_id.to_owned(), Arc::downgrade(&lock));
        lock
    }

    /// The mounted filesystem, or a FAILED_PRECONDITION that says why there
    /// isn't one. FAILED_PRECONDITION rather than INTERNAL/UNAVAILABLE: the
    /// server is working exactly as designed and no retry will help — the
    /// system state has to change (a disk this component may claim).
    fn fs(&self) -> Result<&fs::Mount, tonic::Status> {
        match &self.mount {
            Some(m) => Ok(m),
            None => Err(tonic::Status::failed_precondition(
                self.unavailable.as_str(),
            )),
        }
    }

    fn fs_arc(&self) -> Result<Arc<fs::Mount>, tonic::Status> {
        self.mount
            .clone()
            .ok_or_else(|| tonic::Status::failed_precondition(self.unavailable.as_str()))
    }

    fn authorize_generic_mutation(&self, components: &[&str]) -> Result<(), tonic::Status> {
        reject_generic_image_mutation(components)?;
        if self.generic_mutation_authority == GenericMutationAuthority::Public
            && path_safety::intersects_controller_namespace(components)
        {
            return Err(tonic::Status::permission_denied(
                "controller-owned namespaces may be mutated only through their owning service",
            ));
        }
        Ok(())
    }

    fn authorize_generic_write(&self, components: &[&str]) -> Result<(), tonic::Status> {
        self.authorize_generic_mutation(components)?;
        if !storage_policy::allows_web_write(components) {
            return Err(tonic::Status::permission_denied(
                "web releases may be written only through their staging publication path",
            ));
        }
        Ok(())
    }

    fn authorize_generic_delete(&self, components: &[&str]) -> Result<(), tonic::Status> {
        self.authorize_generic_mutation(components)?;
        if !storage_policy::allows_web_delete(components) {
            return Err(tonic::Status::permission_denied(
                "active and immutable web releases cannot be deleted through the generic API",
            ));
        }
        Ok(())
    }

    fn authorize_generic_mkdir(&self, components: &[&str]) -> Result<(), tonic::Status> {
        self.authorize_generic_mutation(components)?;
        if !storage_policy::allows_web_mkdir(components) {
            return Err(tonic::Status::permission_denied(
                "web release directories are fixed by the publication protocol",
            ));
        }
        Ok(())
    }

    fn authorize_generic_rename(&self, from: &[&str], to: &[&str]) -> Result<(), tonic::Status> {
        self.authorize_generic_mutation(from)?;
        self.authorize_generic_mutation(to)?;
        if !storage_policy::allows_web_rename(from, to) {
            return Err(tonic::Status::permission_denied(
                "web rename is outside the publication protocol",
            ));
        }
        Ok(())
    }

    fn claim_import_session(
        &self,
        import_id: &str,
    ) -> Result<Option<ImageImportSession>, tonic::Status> {
        let mut runtime = self
            .import_sessions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(slot) = runtime.sessions.get_mut(import_id) {
            return Ok(slot.take());
        }
        let session_limit = self
            .import_policy
            .max_active_imports
            .min(self.import_policy.max_hash_sessions);
        if runtime.sessions.len() >= session_limit {
            return Err(tonic::Status::resource_exhausted(format!(
                "at most {session_limit} image imports may retain progressive hash state"
            )));
        }
        runtime.sessions.insert(import_id.to_owned(), None);
        Ok(None)
    }

    fn put_import_session(&self, session: ImageImportSession) {
        let mut runtime = self
            .import_sessions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let import_id = session.import_id.clone();
        let slot = runtime
            .sessions
            .get_mut(&import_id)
            .expect("an import session is returned only to its claimed slot");
        debug_assert!(
            slot.is_none(),
            "per-import lock permits only one hash state"
        );
        *slot = Some(session);
    }

    fn discard_import_session(&self, import_id: &str) {
        self.import_sessions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .sessions
            .remove(import_id);
    }

    fn active_import_offsets(&self, journal: &ImageImportJournal) -> Option<(u64, u64)> {
        self.import_sessions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .sessions
            .get(&journal.import_id)
            .and_then(Option::as_ref)
            .filter(|session| session.matches(journal))
            .map(|session| (session.accepted_offset(), session.durable_offset))
    }

    async fn acquire_import_session(
        &self,
        mount: &fs::Mount,
        journal: &ImageImportJournal,
        part_path: &str,
    ) -> Result<ImageImportSession, tonic::Status> {
        if let Some(session) = self.claim_import_session(&journal.import_id)? {
            if session.matches(journal) {
                return Ok(session);
            }
            self.put_import_session(session);
            return Err(tonic::Status::data_loss(
                "in-memory import identity differs from its durable journal",
            ));
        }

        let disk_offset = path_size(mount, part_path)
            .await?
            .ok_or_else(|| tonic::Status::failed_precondition("import staging file is missing"))?;
        if journal.durable_offset > disk_offset {
            return Err(tonic::Status::data_loss(
                "image-import durable offset is past its staging payload",
            ));
        }
        let checkpoints = load_import_hash_checkpoints(mount, &journal.import_id).await?;
        let mut matching = Vec::new();
        for (slot, checkpoint) in checkpoints {
            if !checkpoint.matches(journal) {
                log::warn!(
                    import_id:% = journal.import_id,
                    slot = slot;
                    "image-import hash checkpoint identity differs from journal"
                );
                continue;
            }
            matching.push((slot, checkpoint.hash));
        }
        let (recovered, rejected) =
            resumable_sha256::select_newest_checkpoint(matching, disk_offset);
        for (slot, rejection) in rejected {
            match rejection {
                resumable_sha256::CheckpointRejection::AheadOfPayload {
                    checkpoint_bytes,
                    payload_bytes,
                } => log::warn!(
                    import_id:% = journal.import_id,
                    slot,
                    checkpoint_bytes,
                    payload_bytes;
                    "image-import hash checkpoint is ahead of staging"
                ),
                resumable_sha256::CheckpointRejection::Malformed(error) => log::warn!(
                    import_id:% = journal.import_id,
                    slot,
                    error:% = error;
                    "image-import hash checkpoint is malformed"
                ),
            }
        }
        let (mut hasher, checkpoint_slot) = match recovered {
            Some((slot, hasher)) => (hasher, Some(slot)),
            None => (resumable_sha256::ResumableSha256::new(), None),
        };
        let checkpoint_offset = hasher.bytes_hashed();
        let part = path_safety::sanitize_relative(part_path).map_err(bad_path)?;
        mount
            .update_hash_range(&part, checkpoint_offset, disk_offset, &mut hasher)
            .await
            .map_err(to_status)?;
        Ok(ImageImportSession {
            journal_version: journal.version,
            import_id: journal.import_id.clone(),
            expected_sha256: journal.expected_sha256.clone(),
            expected_size: journal.expected_size,
            disk_offset,
            durable_offset: journal.durable_offset,
            hasher,
            checkpoint_offset,
            checkpoint_slot,
        })
    }
}

#[derive(Default)]
struct ImageImportRuntime {
    /// `None` is a claimed slot whose state is currently held by one RPC.
    /// Keeping the placeholder across awaits makes the 64-session bound strict
    /// without evicting another import's progressive hash.
    sessions: HashMap<String, Option<ImageImportSession>>,
}

/// Store-wide host-transition control shared by the gRPC mutation paths and
/// the component-local `cerise.storage.Lifecycle` service.
#[derive(Clone, Default)]
struct StorageLifecycle {
    gate: lifecycle::MutationGate,
    mount: Arc<std::sync::Mutex<Option<Arc<fs::Mount>>>>,
}

impl StorageLifecycle {
    fn attach_mount(&self, mount: Arc<fs::Mount>) {
        *self
            .mount
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(mount);
    }

    fn begin_mutation(&self) -> Result<lifecycle::MutationPermit, tonic::Status> {
        self.gate.begin_mutation().map_err(|_| {
            tonic::Status::failed_precondition(
                "storage mutations are frozen for an orderly host transition",
            )
        })
    }

    fn state(&self) -> fstorage::LifecycleState {
        let snapshot = self.gate.snapshot();
        let phase = match snapshot.phase {
            lifecycle::Phase::Open => fstorage::LifecyclePhase::Open,
            lifecycle::Phase::Freezing => fstorage::LifecyclePhase::Freezing,
            lifecycle::Phase::Frozen => fstorage::LifecyclePhase::Frozen,
            lifecycle::Phase::FrozenUnsynced => fstorage::LifecyclePhase::FrozenUnsynced,
        };
        fstorage::LifecycleState {
            phase: Some(phase),
            generation: Some(snapshot.generation),
            active_mutations: Some(snapshot.active_mutations),
            ..Default::default()
        }
    }

    async fn freeze_and_sync(&self) -> Result<fstorage::FreezeReceipt, fstorage::LifecycleError> {
        let mount = self
            .mount
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
            .ok_or(fstorage::LifecycleError::NotMounted)?;

        match self.gate.begin_freeze() {
            lifecycle::FreezeRole::AlreadyFrozen { generation } => Ok(fstorage::FreezeReceipt {
                generation,
                already_frozen: true,
            }),
            lifecycle::FreezeRole::Wait(wait) => {
                let generation = wait.generation();
                let completed = wait.await;
                if completed.last_synced_generation == generation {
                    Ok(fstorage::FreezeReceipt {
                        generation,
                        already_frozen: true,
                    })
                } else {
                    Err(fstorage::LifecycleError::SyncFailed)
                }
            }
            lifecycle::FreezeRole::Leader(attempt) => {
                let generation = attempt.generation();
                attempt.wait_for_drain().await;
                match mount.sync_all().await {
                    Ok(()) => {
                        attempt.complete_synced();
                        log::info!(generation; "storage mutations frozen and Fxfs synced");
                        Ok(fstorage::FreezeReceipt {
                            generation,
                            already_frozen: false,
                        })
                    }
                    Err(error) => {
                        log::error!(
                            generation,
                            error:?; "final Fxfs sync for storage freeze failed"
                        );
                        attempt.complete_unsynced();
                        Err(fstorage::LifecycleError::SyncFailed)
                    }
                }
            }
        }
    }

    fn thaw(&self, generation: u64) -> Result<(), fstorage::LifecycleError> {
        self.gate.thaw(generation).map_err(|error| match error {
            lifecycle::ThawError::Busy => fstorage::LifecycleError::Busy,
            lifecycle::ThawError::StaleGeneration => fstorage::LifecycleError::StaleGeneration,
        })?;
        log::info!(generation; "storage mutation admission thawed");
        Ok(())
    }

    async fn serve(self, mut stream: fstorage::LifecycleRequestStream) {
        use fx_futures::TryStreamExt;

        loop {
            let request = match stream.try_next().await {
                Ok(Some(request)) => request,
                Ok(None) => return,
                Err(error) => {
                    log::warn!("storage lifecycle channel error: {error:?}");
                    return;
                }
            };
            let sent = match request {
                fstorage::LifecycleRequest::GetState { responder } => responder.send(&self.state()),
                fstorage::LifecycleRequest::FreezeAndSync { responder } => {
                    let result = self.freeze_and_sync().await;
                    responder.send(result.as_ref().map_err(|error| *error))
                }
                fstorage::LifecycleRequest::Thaw {
                    generation,
                    responder,
                } => responder.send(self.thaw(generation)),
            };
            if let Err(error) = sent {
                log::warn!("storage lifecycle reply failed: {error:?}");
                return;
            }
        }
    }
}

type BoxStream<T> =
    std::pin::Pin<Box<dyn futures::Stream<Item = Result<T, tonic::Status>> + Send + 'static>>;

impl read_stream::Backend for Arc<fs::Mount> {
    type Error = fs::FsError;
    type Opened = fs::OpenedRead;

    fn stat_regular<'a>(
        &'a self,
        components: &'a [String],
    ) -> read_stream::ReadFuture<'a, u64, Self::Error> {
        Box::pin(async move {
            let borrowed: Vec<&str> = components.iter().map(String::as_str).collect();
            let metadata = self.stat(&borrowed).await?;
            if metadata.kind == fs::Kind::Directory {
                return Err(fs::FsError::IsADirectory);
            }
            if metadata.kind != fs::Kind::File {
                return Err(fs::FsError::InvalidArgument(
                    "not a regular file".to_owned(),
                ));
            }
            Ok(metadata.size)
        })
    }

    fn open_regular<'a>(
        &'a self,
        components: &'a [String],
    ) -> read_stream::ReadFuture<'a, (Self::Opened, u64), Self::Error> {
        Box::pin(async move {
            let borrowed: Vec<&str> = components.iter().map(String::as_str).collect();
            let opened = self.open_read(&borrowed).await?;
            let size = opened.size();
            Ok((opened, size))
        })
    }

    fn read_opened<'a>(
        &'a self,
        opened: &'a Self::Opened,
        offset: u64,
        length: u64,
    ) -> read_stream::ReadFuture<'a, Vec<u8>, Self::Error> {
        Box::pin(opened.read(offset, length))
    }

    fn read_path<'a>(
        &'a self,
        components: &'a [String],
        offset: u64,
        length: u64,
    ) -> read_stream::ReadFuture<'a, Vec<u8>, Self::Error> {
        Box::pin(async move {
            let borrowed: Vec<&str> = components.iter().map(String::as_str).collect();
            self.read(&borrowed, offset, length).await
        })
    }
}

const READ_CHUNK: usize = 64 * 1024;
/// Bound one generic read independently of its fixed-size response chunks.
/// Callers already consume exact ranges and can issue consecutive requests for
/// larger files.
const MAX_READ_RANGE_BYTES: u64 = 16 * 1024 * 1024;
const IMAGE_IMPORT_PREFIX: &str = "vm-images/v1";
const IMAGE_IMPORT_CONTROL_RESERVE_BYTES: u64 = 1 << 30;
const IMAGE_IMPORT_SAFETY_PERCENT: u64 = 5;
const IMAGE_IMPORT_JOURNAL_VERSION: u32 = 4;
/// Hash state is small, but bound it independently of journals so hostile
/// callers cannot retain process memory forever by starting tiny imports.
const IMAGE_IMPORT_HASH_SESSION_LIMIT: usize = 64;
/// Durable journals are bounded separately from in-memory hash sessions:
/// thousands of one-byte abandoned imports must not consume unbounded metadata
/// or reservation-scan time.
const IMAGE_IMPORT_ACTIVE_LIMIT: usize = 64;
/// Terminal receipts are small and make lost Commit replies idempotent. Keep a
/// generous fixed ceiling so their metadata remains operationally bounded.
const IMAGE_IMPORT_RECEIPT_LIMIT: usize = 4096;
/// A component restart can require rereading at most this much payload after
/// the most recent opportunistic checkpoint. Explicit Flush checkpoints every
/// accepted byte and supplies the stronger power-loss durability guarantee.
const IMAGE_IMPORT_HASH_CHECKPOINT_INTERVAL: u64 = 64 * 1024 * 1024;

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct ImageImportJournal {
    version: u32,
    import_id: String,
    #[serde(default)]
    expected_sha256: String,
    expected_size: u64,
    #[serde(default)]
    durable_offset: u64,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct ImageImportHashCheckpoint {
    version: u32,
    journal_version: u32,
    import_id: String,
    expected_sha256: String,
    expected_size: u64,
    hash: resumable_sha256::Checkpoint,
}

impl ImageImportHashCheckpoint {
    fn from_session(session: &ImageImportSession) -> Self {
        Self {
            version: 1,
            journal_version: session.journal_version,
            import_id: session.import_id.clone(),
            expected_sha256: session.expected_sha256.clone(),
            expected_size: session.expected_size,
            hash: session.hasher.checkpoint(),
        }
    }

    fn matches(&self, journal: &ImageImportJournal) -> bool {
        self.version == 1
            && self.journal_version == journal.version
            && self.import_id == journal.import_id
            && self.expected_sha256 == journal.expected_sha256
            && self.expected_size == journal.expected_size
    }
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct ImageImportReceipt {
    version: u32,
    import_id: String,
    expected_size: u64,
    path: String,
    verified: fs::VerifiedCryostore,
}

impl ImageImportReceipt {
    fn new(import_id: String, path: String, verified: fs::VerifiedCryostore) -> Self {
        Self {
            version: 1,
            import_id,
            expected_size: verified.encoded_bytes,
            path,
            verified,
        }
    }

    fn validate_request(
        &self,
        import_id: &str,
        expected_size: Option<u64>,
        expected_sha256: &str,
    ) -> Result<(), tonic::Status> {
        if self.version != 1
            || self.import_id != import_id
            || self.expected_size != self.verified.encoded_bytes
            || self.path != canonical_image_path(&self.verified.sha256)
        {
            return Err(tonic::Status::data_loss(
                "completed image-import receipt has inconsistent identity",
            ));
        }
        if expected_size.is_some_and(|size| size != self.expected_size)
            || (!expected_sha256.is_empty() && expected_sha256 != self.verified.sha256)
        {
            return Err(tonic::Status::already_exists(
                "import_id is already bound to different immutable content",
            ));
        }
        Ok(())
    }
}

struct ImageImportSession {
    journal_version: u32,
    import_id: String,
    expected_sha256: String,
    expected_size: u64,
    disk_offset: u64,
    durable_offset: u64,
    hasher: resumable_sha256::ResumableSha256,
    checkpoint_offset: u64,
    checkpoint_slot: Option<u8>,
}

impl ImageImportSession {
    fn matches(&self, journal: &ImageImportJournal) -> bool {
        self.import_id == journal.import_id
            && self.journal_version == journal.version
            && self.expected_sha256 == journal.expected_sha256
            && self.expected_size == journal.expected_size
    }

    fn accepted_offset(&self) -> u64 {
        self.disk_offset
    }
}

fn validate_import_id(value: &str) -> Result<(), tonic::Status> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
    {
        return Err(tonic::Status::invalid_argument(
            "import_id must be 1..=128 ASCII letters, digits, dot, dash or underscore",
        ));
    }
    Ok(())
}

fn validate_sha256(value: &str) -> Result<(), tonic::Status> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(tonic::Status::invalid_argument(
            "expected_sha256 must be 64 lowercase hexadecimal characters",
        ));
    }
    Ok(())
}

fn import_paths(import_id: &str) -> (String, String) {
    (
        format!("{IMAGE_IMPORT_PREFIX}/imports/{import_id}.part"),
        format!("{IMAGE_IMPORT_PREFIX}/imports/{import_id}.json"),
    )
}

fn import_receipt_path(import_id: &str) -> String {
    // Deliberately not `.json`: rollback binaries enumerate that suffix as
    // active reservation journals.
    format!("{IMAGE_IMPORT_PREFIX}/imports/{import_id}.complete-state")
}

fn import_hash_checkpoint_path(import_id: &str, slot: u8) -> String {
    debug_assert!(slot < 2);
    // Deliberately does not end in `.json`: rollback binaries enumerate every
    // such suffix as a version-2 reservation journal.
    format!("{IMAGE_IMPORT_PREFIX}/imports/{import_id}.sha256-state.{slot}")
}

fn next_import_hash_checkpoint_path(session: &ImageImportSession) -> (u8, String) {
    let slot = match session.checkpoint_slot {
        Some(0) => 1,
        Some(1) | None => 0,
        Some(_) => unreachable!("checkpoint slots are validated internally"),
    };
    (slot, import_hash_checkpoint_path(&session.import_id, slot))
}

fn canonical_image_path(sha256: &str) -> String {
    format!("{IMAGE_IMPORT_PREFIX}/objects/sha256/{sha256}.cryostore")
}

fn is_managed_image_path(components: &[&str]) -> bool {
    matches!(components, ["vm-images", "v1", ..])
}

fn reject_generic_image_mutation(components: &[&str]) -> Result<(), tonic::Status> {
    if is_managed_image_path(components) {
        return Err(tonic::Status::permission_denied(
            "vm-images/v1 is managed by the image-import RPCs",
        ));
    }
    Ok(())
}

fn consumes_bulk_pool_space(components: &[&str]) -> bool {
    components.starts_with(&["vm-state", "v1"])
        || components.starts_with(&["vm-swap", "v2"])
        || storage_policy::is_web_staging(components)
}

async fn admit_bulk_write(
    mount: &fs::Mount,
    path: &str,
    offset: u64,
    bytes: u64,
    truncate: bool,
) -> Result<(), tonic::Status> {
    let current = path_size(mount, path).await?.unwrap_or(0);
    let end = offset
        .checked_add(bytes)
        .ok_or_else(|| tonic::Status::out_of_range("write end overflowed"))?;
    // Replacing a file may temporarily retain its old object in the Fxfs
    // graveyard, so charge all replacement bytes instead of assuming the old
    // allocation is immediately reusable.
    let growth = if truncate {
        bytes
    } else {
        end.saturating_sub(current)
    };
    if growth == 0 {
        return Ok(());
    }
    // Import writes may proceed without the bulk allocation gate. Sample their
    // remaining reservations before free space so an intervening write can
    // only reduce the apparent availability.
    let reserved = import_reservations(mount).await?;
    let (total, used) = mount.usage_bytes();
    let free = total.saturating_sub(used);
    let protected = IMAGE_IMPORT_CONTROL_RESERVE_BYTES
        .max(total.saturating_mul(IMAGE_IMPORT_SAFETY_PERCENT) / 100);
    let available = free.saturating_sub(protected).saturating_sub(reserved);
    if growth > available {
        return Err(tonic::Status::resource_exhausted(format!(
            "bulk write may allocate {growth} bytes, but only {available} bytes are unreserved \
             above the {protected}-byte control reserve ({reserved} bytes reserved)"
        )));
    }
    Ok(())
}

async fn mkdir_idempotent(mount: &fs::Mount, path: &str) -> Result<(), tonic::Status> {
    let components = path_safety::sanitize_relative(path).map_err(bad_path)?;
    match mount.mkdir(&components, true).await {
        Ok(()) | Err(fs::FsError::AlreadyExists) => Ok(()),
        Err(error) => Err(to_status(error)),
    }
}

async fn load_import_journal(
    mount: &fs::Mount,
    path: &str,
) -> Result<ImageImportJournal, tonic::Status> {
    let components = path_safety::sanitize_relative(path).map_err(bad_path)?;
    let bytes = mount.read(&components, 0, 0).await.map_err(to_status)?;
    serde_json::from_slice(&bytes)
        .map_err(|error| tonic::Status::data_loss(format!("invalid image import journal: {error}")))
}

async fn store_import_journal(
    mount: &fs::Mount,
    path: &str,
    journal: &ImageImportJournal,
) -> Result<(), tonic::Status> {
    let bytes = serde_json::to_vec(journal)
        .map_err(|error| tonic::Status::internal(format!("encoding import journal: {error}")))?;
    let components = path_safety::sanitize_relative(path).map_err(bad_path)?;
    mount
        .write_atomic(&components, &bytes, true)
        .await
        .map_err(to_status)?;
    Ok(())
}

async fn load_import_receipt(
    mount: &fs::Mount,
    import_id: &str,
) -> Result<Option<ImageImportReceipt>, tonic::Status> {
    let path = import_receipt_path(import_id);
    let components = path_safety::sanitize_relative(&path).map_err(bad_path)?;
    let bytes = match mount.read(&components, 0, 0).await {
        Ok(bytes) => bytes,
        Err(fs::FsError::NotFound) => return Ok(None),
        Err(error) => return Err(to_status(error)),
    };
    let receipt = serde_json::from_slice(&bytes).map_err(|error| {
        tonic::Status::data_loss(format!("decoding completed image-import receipt: {error}"))
    })?;
    Ok(Some(receipt))
}

async fn store_import_receipt(
    mount: &fs::Mount,
    receipt: &ImageImportReceipt,
    durable: bool,
) -> Result<(), tonic::Status> {
    let bytes = serde_json::to_vec(receipt).map_err(|error| {
        tonic::Status::internal(format!("encoding completed image-import receipt: {error}"))
    })?;
    let path = import_receipt_path(&receipt.import_id);
    let components = path_safety::sanitize_relative(&path).map_err(bad_path)?;
    mount
        .write_atomic(&components, &bytes, durable)
        .await
        .map_err(to_status)?;
    Ok(())
}

async fn load_import_hash_checkpoints(
    mount: &fs::Mount,
    import_id: &str,
) -> Result<Vec<(u8, ImageImportHashCheckpoint)>, tonic::Status> {
    let mut checkpoints = Vec::new();
    for slot in 0..2 {
        let path = import_hash_checkpoint_path(import_id, slot);
        let components = path_safety::sanitize_relative(&path).map_err(bad_path)?;
        let bytes = match mount.read(&components, 0, 0).await {
            Ok(bytes) => bytes,
            Err(fs::FsError::NotFound) => continue,
            Err(error) => return Err(to_status(error)),
        };
        match serde_json::from_slice(&bytes) {
            Ok(checkpoint) => checkpoints.push((slot, checkpoint)),
            Err(error) => log::warn!(
                path:% = path,
                error:% = error;
                "ignoring invalid image-import hash checkpoint"
            ),
        }
    }
    Ok(checkpoints)
}

async fn remove_import_hash_checkpoints(
    mount: &fs::Mount,
    import_id: &str,
) -> Result<(), tonic::Status> {
    for slot in 0..2 {
        remove_if_present(mount, &import_hash_checkpoint_path(import_id, slot)).await?;
    }
    Ok(())
}

async fn store_import_hash_checkpoint(
    mount: &fs::Mount,
    path: &str,
    checkpoint: &ImageImportHashCheckpoint,
    durable: bool,
) -> Result<(), tonic::Status> {
    let bytes = serde_json::to_vec(checkpoint).map_err(|error| {
        tonic::Status::internal(format!("encoding image-import hash checkpoint: {error}"))
    })?;
    let components = path_safety::sanitize_relative(path).map_err(bad_path)?;
    mount
        .write_atomic(&components, &bytes, durable)
        .await
        .map_err(to_status)?;
    Ok(())
}

async fn path_size(mount: &fs::Mount, path: &str) -> Result<Option<u64>, tonic::Status> {
    let components = path_safety::sanitize_relative(path).map_err(bad_path)?;
    match mount.stat(&components).await {
        Ok(meta) => Ok(Some(meta.size)),
        Err(fs::FsError::NotFound) => Ok(None),
        Err(error) => Err(to_status(error)),
    }
}

async fn remove_if_present(mount: &fs::Mount, path: &str) -> Result<(), tonic::Status> {
    let components = path_safety::sanitize_relative(path).map_err(bad_path)?;
    match mount.delete_lazy(&components, false).await {
        Ok(()) | Err(fs::FsError::NotFound) => Ok(()),
        Err(error) => Err(to_status(error)),
    }
}

fn namespace_bytes<'a>(
    mount: &'a fs::Mount,
    path: &'a str,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<u64, tonic::Status>> + Send + 'a>> {
    Box::pin(async move {
        let components = path_safety::sanitize_relative(path).map_err(bad_path)?;
        let entries = match mount.list(&components).await {
            Ok(entries) => entries,
            Err(fs::FsError::NotFound) => return Ok(0),
            Err(error) => return Err(to_status(error)),
        };
        let mut bytes = 0u64;
        for entry in entries {
            let child = format!("{path}/{}", entry.name);
            bytes = bytes
                .checked_add(match entry.kind {
                    fs::Kind::Directory => namespace_bytes(mount, &child).await?,
                    fs::Kind::File => entry.size,
                    _ => 0,
                })
                .ok_or_else(|| tonic::Status::out_of_range("namespace byte count overflowed"))?;
        }
        Ok(bytes)
    })
}

async fn import_reservations(mount: &fs::Mount) -> Result<u64, tonic::Status> {
    let imports = format!("{IMAGE_IMPORT_PREFIX}/imports");
    let components = path_safety::sanitize_relative(&imports).map_err(bad_path)?;
    let entries = match mount.list(&components).await {
        Ok(entries) => entries,
        Err(fs::FsError::NotFound) => return Ok(0),
        Err(error) => return Err(to_status(error)),
    };
    let mut reserved = 0u64;
    for entry in entries {
        let Some(import_id) = entry.name.strip_suffix(".json") else {
            continue;
        };
        if load_import_receipt(mount, import_id).await?.is_some() {
            continue;
        }
        let journal_path = format!("{imports}/{}", entry.name);
        let journal = load_import_journal(mount, &journal_path).await?;
        let (part_path, _) = import_paths(import_id);
        let accepted = path_size(mount, &part_path).await?.unwrap_or(0);
        reserved = reserved
            .checked_add(journal.expected_size.saturating_sub(accepted))
            .ok_or_else(|| tonic::Status::out_of_range("image reservations overflowed"))?;
    }
    Ok(reserved)
}

async fn import_record_counts(mount: &fs::Mount) -> Result<(usize, usize), tonic::Status> {
    let imports = format!("{IMAGE_IMPORT_PREFIX}/imports");
    let components = path_safety::sanitize_relative(&imports).map_err(bad_path)?;
    let entries = match mount.list(&components).await {
        Ok(entries) => entries,
        Err(fs::FsError::NotFound) => return Ok((0, 0)),
        Err(error) => return Err(to_status(error)),
    };
    let active = entries
        .iter()
        .filter(|entry| entry.name.ends_with(".json"))
        .count();
    let receipts = entries
        .iter()
        .filter(|entry| entry.name.ends_with(".complete-state"))
        .count();
    Ok((active, receipts))
}

fn import_response(path: String, verified: fs::VerifiedCryostore) -> pb::CommitImageImportResponse {
    pb::CommitImageImportResponse {
        path,
        sha256: verified.sha256,
        encoded_bytes: verified.encoded_bytes,
        cryostore_root_hash: verified.root_hash,
        guest_disk_bytes: verified.guest_disk_bytes,
        format_version: verified.format_version,
    }
}

fn receipt_response(receipt: ImageImportReceipt) -> pb::CommitImageImportResponse {
    import_response(receipt.path, receipt.verified)
}

fn current_boot_scope() -> Result<String> {
    let clock = fuchsia_runtime::duplicate_utc_clock_handle(zx::Rights::SAME_RIGHTS)
        .context("duplicating the boot-scoped UTC clock")?;
    let name = clock
        .as_handle_ref()
        .get_name()
        .context("reading the boot-scoped UTC clock identity")?
        .to_string();
    let identity = name
        .strip_prefix("utc_boot_")
        .ok_or_else(|| anyhow!("boot clock has malformed identity {name:?}"))?;
    let boot_id = u64::from_str_radix(identity, 16).context("parsing boot-scoped identity")?;
    anyhow::ensure!(boot_id != 0, "boot-scoped identity is zero");
    Ok(format!("{boot_id:016x}"))
}

async fn purge_stale_spill(mount: &fs::Mount) -> Result<()> {
    const ROOT: &str = "vm-swap/v2";
    mkdir_idempotent(mount, ROOT)
        .await
        .map_err(|status| anyhow!("creating spill root: {status}"))?;
    let current = current_boot_scope()?;
    let root = path_safety::sanitize_relative(ROOT)
        .map_err(|error| anyhow!("invalid internal spill root: {error:?}"))?;
    for entry in mount
        .list(&root)
        .await
        .map_err(|error| anyhow!("{error:?}"))?
    {
        if entry.name == current {
            continue;
        }
        let path = format!("{ROOT}/{}", entry.name);
        let components = path_safety::sanitize_relative(&path)
            .map_err(|error| anyhow!("invalid stale spill path: {error:?}"))?;
        mount
            .delete(&components, true)
            .await
            .map_err(|error| anyhow!("deleting stale spill boot {path:?}: {error:?}"))?;
        log::info!(path:% = path; "removed stale spill boot namespace");
    }
    mkdir_idempotent(mount, &format!("{ROOT}/{current}"))
        .await
        .map_err(|status| anyhow!("creating current spill boot namespace: {status}"))?;
    Ok(())
}

fn to_status(e: fs::FsError) -> tonic::Status {
    match e {
        fs::FsError::NotFound => tonic::Status::not_found("not found"),
        fs::FsError::AlreadyExists => tonic::Status::already_exists("already exists"),
        fs::FsError::InvalidArgument(m) => tonic::Status::invalid_argument(m),
        fs::FsError::NotADirectory => tonic::Status::invalid_argument("not a directory"),
        fs::FsError::IsADirectory => tonic::Status::invalid_argument("is a directory"),
        fs::FsError::NotEmpty => tonic::Status::failed_precondition("directory not empty"),
        fs::FsError::ResourceExhausted(message) => {
            tonic::Status::resource_exhausted(message)
        }
        fs::FsError::Internal(e) => tonic::Status::internal(format!("{e:#}")),
    }
}

fn bad_path(e: path_safety::PathError) -> tonic::Status {
    tonic::Status::invalid_argument(format!("invalid path: {e:?}"))
}

fn kind_to_ft(k: fs::Kind) -> i32 {
    let ft = match k {
        fs::Kind::File => pb::FileType::File,
        fs::Kind::Directory => pb::FileType::Directory,
        fs::Kind::Symlink => pb::FileType::Symlink,
        fs::Kind::Unknown => pb::FileType::Unknown,
    };
    ft as i32
}

fn mode_for(k: fs::Kind) -> u32 {
    match k {
        fs::Kind::Directory => 0o040755,
        _ => 0o100644,
    }
}

#[tonic::async_trait]
impl FileServer for CeriseFileServer {
    async fn stat(
        &self,
        request: tonic::Request<pb::StatRequest>,
    ) -> Result<tonic::Response<pb::StatResponse>, tonic::Status> {
        let path = request.into_inner().path;
        // The success sentinels are emitted only by a server that HAS a
        // filesystem: a degraded server must never be able to print a
        // success marker the boot gates grep for.
        let mount = self.fs()?;
        // Sentinel the host e2e test Stats last (after every assertion passed) so the
        // guest emits a single ordered end-to-end success marker on serial.
        if path == "__cerise_e2e_ok__" {
            emit("CERISE-FILESERVER-E2E-OK\n");
        }
        if path == "__cerise_persist_ok__" {
            emit("CERISE-FILESERVER-PERSIST-OK\n");
        }
        let comps = path_safety::sanitize_relative(&path).map_err(bad_path)?;
        let meta = mount.stat(&comps).await.map_err(to_status)?;
        log::debug!(path:% = path; "RPC Stat served");
        Ok(tonic::Response::new(pb::StatResponse {
            r#type: kind_to_ft(meta.kind),
            size: meta.size,
            mtime_unix_nanos: meta.mtime_unix_nanos,
            mode: mode_for(meta.kind),
        }))
    }

    type ListStream = BoxStream<pb::DirEntry>;

    async fn list(
        &self,
        request: tonic::Request<pb::ListRequest>,
    ) -> Result<tonic::Response<Self::ListStream>, tonic::Status> {
        let request = request.into_inner();
        let path = request.path;
        let comps = path_safety::sanitize_relative(&path).map_err(bad_path)?;
        let mount = self.fs()?;
        let entries = if request.max_entries == 0 {
            mount.list(&comps).await
        } else {
            let max_entries = usize::try_from(request.max_entries).map_err(|_| {
                tonic::Status::invalid_argument("max_entries does not fit this server")
            })?;
            mount.list_bounded(&comps, max_entries).await
        }
        .map_err(to_status)?;
        log::debug!(path:% = path, count = entries.len(); "RPC List served");
        let items: Vec<Result<pb::DirEntry, tonic::Status>> = entries
            .into_iter()
            .map(|e| {
                Ok(pb::DirEntry {
                    name: e.name,
                    r#type: kind_to_ft(e.kind),
                    size: e.size,
                })
            })
            .collect();
        let stream: Self::ListStream = Box::pin(futures::stream::iter(items));
        Ok(tonic::Response::new(stream))
    }

    type ReadStream = BoxStream<pb::ReadChunk>;

    async fn read(
        &self,
        request: tonic::Request<pb::ReadRequest>,
    ) -> Result<tonic::Response<Self::ReadStream>, tonic::Status> {
        let req = request.into_inner();
        let comps = path_safety::sanitize_relative(&req.path).map_err(bad_path)?;
        if req.length == 0 || req.length > MAX_READ_RANGE_BYTES {
            return Err(tonic::Status::invalid_argument(format!(
                "read length must be 1..={MAX_READ_RANGE_BYTES} bytes"
            )));
        }
        let mount = self.fs_arc()?;
        let stability = if path_safety::is_published_content_address(&comps) {
            read_stream::SourceStability::Immutable
        } else {
            read_stream::SourceStability::PathFollowing
        };
        let components: Arc<Vec<String>> = Arc::new(comps.into_iter().map(str::to_owned).collect());
        let state = read_stream::prepare(
            mount,
            components,
            req.offset,
            req.length,
            READ_CHUNK,
            stability,
        )
        .await
        .map_err(|error| match error {
            read_stream::PrepareError::Source(error) => to_status(error),
            read_stream::PrepareError::OffsetOverflow => {
                tonic::Status::out_of_range("read end overflowed")
            }
        })?;
        let planned_bytes = state.planned_bytes();
        let stream = futures::stream::unfold(state, |state| async move {
            read_stream::next(state).await.map(|(result, state)| {
                let result = match result {
                    Ok(chunk) => Ok(pb::ReadChunk {
                        data: chunk.data,
                        offset: chunk.offset,
                    }),
                    Err(read_stream::StreamError::LengthMismatch {
                        offset,
                        expected,
                        actual,
                    }) => Err(tonic::Status::data_loss(format!(
                        "file changed during read at offset {offset}: expected {expected} bytes, got {actual}"
                    ))),
                    Err(read_stream::StreamError::Source(error)) => Err(to_status(error)),
                };
                (result, state)
            })
        });
        log::debug!(
            path:% = req.path,
            offset = req.offset,
            bytes = planned_bytes;
            "RPC Read stream opened"
        );
        let stream: Self::ReadStream = Box::pin(stream);
        Ok(tonic::Response::new(stream))
    }

    async fn write(
        &self,
        request: tonic::Request<pb::WriteRequest>,
    ) -> Result<tonic::Response<pb::WriteResponse>, tonic::Status> {
        let req = request.into_inner();
        self.reject_dormant_mutation_context(&req.mutation_context)?;
        let comps = path_safety::sanitize_relative(&req.path).map_err(bad_path)?;
        self.authorize_generic_write(&comps)?;
        let mount = self.fs()?;
        let _mutation = self.lifecycle.begin_mutation()?;
        let _allocation = if consumes_bulk_pool_space(&comps) {
            Some(self.allocation_gate.lock().await)
        } else {
            None
        };
        let durability = pb::WriteDurability::try_from(req.durability)
            .map_err(|_| tonic::Status::invalid_argument("unknown write durability"))?;
        let durable = durability != pb::WriteDurability::Lazy;
        if !durable && !storage_policy::allows_lazy_write(&comps) {
            return Err(tonic::Status::permission_denied(
                "lazy writes are restricted to atomic staging or boot-scoped spill files",
            ));
        }
        if consumes_bulk_pool_space(&comps) {
            admit_bulk_write(
                mount,
                &req.path,
                req.offset,
                req.data.len() as u64,
                req.truncate,
            )
            .await?;
        }
        let n = mount
            .write(
                &comps,
                req.offset,
                &req.data,
                req.create,
                req.truncate,
                durable,
            )
            .await
            .map_err(to_status)?;
        // Spill-backed VM heads can issue one request per dirty 4 KiB page.
        // Logging each successful write at info level makes the debug transport
        // part of the storage hot path and can dominate a durability barrier.
        log::debug!(path:% = req.path, offset = req.offset, bytes = n; "RPC Write served");
        Ok(tonic::Response::new(pb::WriteResponse { bytes_written: n }))
    }

    async fn flush(
        &self,
        request: tonic::Request<pb::FlushRequest>,
    ) -> Result<tonic::Response<pb::FlushResponse>, tonic::Status> {
        self.reject_dormant_mutation_context(&request.into_inner().mutation_context)?;
        let mount = self.fs()?;
        let _mutation = self.lifecycle.begin_mutation()?;
        mount.sync_all().await.map_err(to_status)?;
        Ok(tonic::Response::new(pb::FlushResponse {}))
    }

    async fn get_usage(
        &self,
        _request: tonic::Request<pb::GetUsageRequest>,
    ) -> Result<tonic::Response<pb::GetUsageResponse>, tonic::Status> {
        let mount = self.fs()?;
        let (total_bytes, used_bytes) = mount.usage_bytes();
        let image_bytes = namespace_bytes(mount, "vm-images/v1/objects").await?;
        let staging_bytes = namespace_bytes(mount, "vm-images/v1/imports").await?;
        let artifact_bytes = namespace_bytes(mount, "vm-state").await?;
        let spill_bytes = namespace_bytes(mount, "vm-swap").await?;
        let control_bytes = namespace_bytes(mount, "vm-manager")
            .await?
            .saturating_add(namespace_bytes(mount, "vm-events").await?)
            .saturating_add(namespace_bytes(mount, "storage").await?);
        let classified = image_bytes
            .saturating_add(staging_bytes)
            .saturating_add(artifact_bytes)
            .saturating_add(spill_bytes)
            .saturating_add(control_bytes);
        let protected_reserve_bytes = IMAGE_IMPORT_CONTROL_RESERVE_BYTES
            .max(total_bytes.saturating_mul(IMAGE_IMPORT_SAFETY_PERCENT) / 100);
        let reserved_bytes = import_reservations(mount).await?;
        let free_bytes = total_bytes.saturating_sub(used_bytes);
        Ok(tonic::Response::new(pb::GetUsageResponse {
            total_bytes,
            used_bytes,
            free_bytes,
            protected_reserve_bytes,
            reserved_bytes,
            image_bytes,
            artifact_bytes,
            spill_bytes,
            control_bytes,
            staging_bytes,
            other_allocated_bytes: used_bytes.saturating_sub(classified),
            image_push_capacity_bytes: free_bytes
                .saturating_sub(protected_reserve_bytes)
                .saturating_sub(reserved_bytes),
        }))
    }

    async fn delete(
        &self,
        request: tonic::Request<pb::DeleteRequest>,
    ) -> Result<tonic::Response<pb::DeleteResponse>, tonic::Status> {
        let req = request.into_inner();
        self.reject_dormant_mutation_context(&req.mutation_context)?;
        let comps = path_safety::sanitize_relative(&req.path).map_err(bad_path)?;
        self.authorize_generic_delete(&comps)?;
        let mount = self.fs()?;
        let _mutation = self.lifecycle.begin_mutation()?;
        mount
            .delete(&comps, req.recursive)
            .await
            .map_err(to_status)?;
        log::info!(path:% = req.path, recursive = req.recursive; "RPC Delete served");
        Ok(tonic::Response::new(pb::DeleteResponse {}))
    }

    async fn mkdir(
        &self,
        request: tonic::Request<pb::MkdirRequest>,
    ) -> Result<tonic::Response<pb::MkdirResponse>, tonic::Status> {
        let req = request.into_inner();
        self.reject_dormant_mutation_context(&req.mutation_context)?;
        let comps = path_safety::sanitize_relative(&req.path).map_err(bad_path)?;
        self.authorize_generic_mkdir(&comps)?;
        let mount = self.fs()?;
        let _mutation = self.lifecycle.begin_mutation()?;
        mount.mkdir(&comps, req.parents).await.map_err(to_status)?;
        log::info!(path:% = req.path, parents = req.parents; "RPC Mkdir served");
        Ok(tonic::Response::new(pb::MkdirResponse {}))
    }

    async fn rename(
        &self,
        request: tonic::Request<pb::RenameRequest>,
    ) -> Result<tonic::Response<pb::RenameResponse>, tonic::Status> {
        let req = request.into_inner();
        self.reject_dormant_mutation_context(&req.mutation_context)?;
        let from = path_safety::sanitize_relative(&req.from).map_err(bad_path)?;
        let to = path_safety::sanitize_relative(&req.to).map_err(bad_path)?;
        self.authorize_generic_rename(&from, &to)?;
        let mount = self.fs()?;
        let _mutation = self.lifecycle.begin_mutation()?;
        let _publication = if storage_policy::is_web_release(&to) {
            Some(self.allocation_gate.lock().await)
        } else {
            None
        };
        if storage_policy::is_web_release(&to) && path_size(mount, &req.to).await?.is_some() {
            return Err(tonic::Status::already_exists(
                "immutable web release already exists",
            ));
        }
        mount.rename(&from, &to).await.map_err(to_status)?;
        log::info!(from:% = req.from, to:% = req.to; "RPC Rename served");
        Ok(tonic::Response::new(pb::RenameResponse {}))
    }

    async fn open_mutation_source(
        &self,
        _request: tonic::Request<pb::OpenMutationSourceRequest>,
    ) -> Result<tonic::Response<pb::OpenMutationSourceResponse>, tonic::Status> {
        Err(tonic::Status::unimplemented(
            "durable mutation-source admission is not enabled",
        ))
    }

    async fn drain_mutation_source(
        &self,
        _request: tonic::Request<pb::DrainMutationSourceRequest>,
    ) -> Result<tonic::Response<pb::DrainMutationSourceResponse>, tonic::Status> {
        Err(tonic::Status::unimplemented(
            "durable mutation-source admission is not enabled",
        ))
    }

    async fn get_mutation_source(
        &self,
        _request: tonic::Request<pb::GetMutationSourceRequest>,
    ) -> Result<tonic::Response<pb::GetMutationSourceResponse>, tonic::Status> {
        Err(tonic::Status::unimplemented(
            "durable mutation-source admission is not enabled",
        ))
    }

    async fn compact_mutation_sources(
        &self,
        _request: tonic::Request<pb::CompactMutationSourcesRequest>,
    ) -> Result<tonic::Response<pb::CompactMutationSourcesResponse>, tonic::Status> {
        Err(tonic::Status::unimplemented(
            "durable mutation-source admission is not enabled",
        ))
    }

    async fn seal_legacy_mutation_admission(
        &self,
        _request: tonic::Request<pb::SealLegacyMutationAdmissionRequest>,
    ) -> Result<tonic::Response<pb::SealLegacyMutationAdmissionResponse>, tonic::Status> {
        Err(tonic::Status::unimplemented(
            "durable mutation-source admission is not enabled",
        ))
    }

    async fn begin_image_import(
        &self,
        request: tonic::Request<pb::BeginImageImportRequest>,
    ) -> Result<tonic::Response<pb::BeginImageImportResponse>, tonic::Status> {
        let req = request.into_inner();
        validate_import_id(&req.import_id)?;
        if !req.expected_sha256.is_empty() {
            validate_sha256(&req.expected_sha256)?;
        }
        if req.expected_size == 0 {
            return Err(tonic::Status::invalid_argument(
                "expected_size must be nonzero",
            ));
        }
        if req.expected_size > self.import_policy.max_image_bytes {
            return Err(tonic::Status::resource_exhausted(format!(
                "image size {} exceeds this host's {}-byte import ceiling",
                req.expected_size, self.import_policy.max_image_bytes
            )));
        }
        let mount = self.fs()?;
        let import_lock = self.import_lock(&req.import_id);
        let _import = import_lock.lock().await;
        let _mutation = self.lifecycle.begin_mutation()?;
        let _allocation = self.allocation_gate.lock().await;
        mkdir_idempotent(mount, &format!("{IMAGE_IMPORT_PREFIX}/imports")).await?;
        mkdir_idempotent(mount, &format!("{IMAGE_IMPORT_PREFIX}/objects/sha256")).await?;
        let (part_path, journal_path) = import_paths(&req.import_id);

        if let Some(receipt) = load_import_receipt(mount, &req.import_id).await? {
            receipt.validate_request(
                &req.import_id,
                Some(req.expected_size),
                &req.expected_sha256,
            )?;
            return Ok(tonic::Response::new(pb::BeginImageImportResponse {
                import_id: req.import_id,
                accepted_offset: receipt.expected_size,
                durable_offset: receipt.expected_size,
            }));
        }

        if path_size(mount, &journal_path).await?.is_some() {
            let mut journal = load_import_journal(mount, &journal_path).await?;
            if journal.import_id != req.import_id
                || journal.expected_size != req.expected_size
                || (!journal.expected_sha256.is_empty()
                    && !req.expected_sha256.is_empty()
                    && journal.expected_sha256 != req.expected_sha256)
            {
                return Err(tonic::Status::already_exists(
                    "import_id is already bound to different immutable content",
                ));
            }
            match journal.version {
                IMAGE_IMPORT_JOURNAL_VERSION => {}
                2 | 3 => {
                    // Version is an existing field, so changing only its value
                    // remains readable by rollback binaries. It gives new hash
                    // sidecars a generation that an old abort+rebegin (which
                    // writes version 2) cannot accidentally reuse.
                    journal.version = IMAGE_IMPORT_JOURNAL_VERSION;
                    self.discard_import_session(&req.import_id);
                    remove_import_hash_checkpoints(mount, &req.import_id).await?;
                    store_import_journal(mount, &journal_path, &journal).await?;
                }
                version => {
                    return Err(tonic::Status::data_loss(format!(
                        "unsupported image import journal version {version}"
                    )))
                }
            }
            if journal.expected_sha256.is_empty() && !req.expected_sha256.is_empty() {
                journal.expected_sha256 = req.expected_sha256.clone();
                self.discard_import_session(&req.import_id);
                remove_import_hash_checkpoints(mount, &req.import_id).await?;
                store_import_journal(mount, &journal_path, &journal).await?;
            }
            let (accepted_offset, durable_offset) = match path_size(mount, &part_path).await? {
                Some(size) => self
                    .active_import_offsets(&journal)
                    .unwrap_or((size, journal.durable_offset)),
                None => {
                    if journal.expected_sha256.is_empty() {
                        return Err(tonic::Status::data_loss(
                            "digest-pending import journal has no staging object",
                        ));
                    }
                    let canonical_path = canonical_image_path(&journal.expected_sha256);
                    let canonical =
                        path_safety::sanitize_relative(&canonical_path).map_err(bad_path)?;
                    if path_size(mount, &canonical_path).await?.is_none() {
                        return Err(tonic::Status::data_loss(
                            "import journal has neither staging nor canonical object",
                        ));
                    }
                    mount
                        .inspect_cryostore(
                            &canonical,
                            &journal.expected_sha256,
                            journal.expected_size,
                        )
                        .await
                        .map_err(to_status)?;
                    (journal.expected_size, journal.expected_size)
                }
            };
            if durable_offset > accepted_offset {
                return Err(tonic::Status::data_loss(
                    "image-import durable offset is past its accepted offset",
                ));
            }
            return Ok(tonic::Response::new(pb::BeginImageImportResponse {
                import_id: req.import_id,
                accepted_offset,
                durable_offset,
            }));
        }

        self.discard_import_session(&req.import_id);
        let (active_imports, receipts) = import_record_counts(mount).await?;
        if active_imports >= self.import_policy.max_active_imports {
            return Err(tonic::Status::resource_exhausted(format!(
                "at most {} durable image imports may be active",
                self.import_policy.max_active_imports
            )));
        }
        if receipts >= self.import_policy.max_receipts {
            return Err(tonic::Status::resource_exhausted(format!(
                "the {}-receipt image-import metadata ceiling was reached",
                self.import_policy.max_receipts
            )));
        }
        let journal = ImageImportJournal {
            version: IMAGE_IMPORT_JOURNAL_VERSION,
            import_id: req.import_id.clone(),
            expected_sha256: req.expected_sha256.clone(),
            expected_size: req.expected_size,
            durable_offset: 0,
        };
        if !req.expected_sha256.is_empty() {
            let canonical_path = canonical_image_path(&req.expected_sha256);
            if path_size(mount, &canonical_path).await?.is_some() {
                let canonical =
                    path_safety::sanitize_relative(&canonical_path).map_err(bad_path)?;
                let verified = mount
                    .inspect_cryostore(&canonical, &req.expected_sha256, req.expected_size)
                    .await
                    .map_err(to_status)?;
                let receipt =
                    ImageImportReceipt::new(req.import_id.clone(), canonical_path, verified);
                store_import_receipt(mount, &receipt, true).await?;
                return Ok(tonic::Response::new(pb::BeginImageImportResponse {
                    import_id: req.import_id,
                    accepted_offset: req.expected_size,
                    durable_offset: req.expected_size,
                }));
            }
        }

        // Writes consume free bytes and reduce their remaining reservation by
        // the same amount. Sampling reservations first and usage second means
        // a concurrent write can only make this admission conservative. The
        // opposite order can overstate availability by the intervening write.
        let reserved = import_reservations(mount).await?;
        let (total, used) = mount.usage_bytes();
        let free = total.saturating_sub(used);
        let protected = IMAGE_IMPORT_CONTROL_RESERVE_BYTES
            .max(total.saturating_mul(IMAGE_IMPORT_SAFETY_PERCENT) / 100);
        let available = free.saturating_sub(protected).saturating_sub(reserved);
        if req.expected_size > available {
            return Err(tonic::Status::resource_exhausted(format!(
                "image needs {} bytes, but only {} bytes are unreserved above the {}-byte \
                 protected reserve ({} bytes are already reserved)",
                req.expected_size, available, protected, reserved,
            )));
        }

        let part = path_safety::sanitize_relative(&part_path).map_err(bad_path)?;
        remove_import_hash_checkpoints(mount, &req.import_id).await?;
        mount
            .write(&part, 0, &[], true, true, false)
            .await
            .map_err(to_status)?;
        store_import_journal(mount, &journal_path, &journal).await?;
        Ok(tonic::Response::new(pb::BeginImageImportResponse {
            import_id: req.import_id,
            accepted_offset: 0,
            durable_offset: 0,
        }))
    }

    async fn write_image_import(
        &self,
        request: tonic::Request<pb::WriteImageImportRequest>,
    ) -> Result<tonic::Response<pb::WriteImageImportResponse>, tonic::Status> {
        let req = request.into_inner();
        validate_import_id(&req.import_id)?;
        if req.data.is_empty() {
            return Err(tonic::Status::invalid_argument(
                "an empty import chunk makes no progress",
            ));
        }
        if req.data.len() as u64 > IMAGE_IMPORT_HASH_CHECKPOINT_INTERVAL {
            return Err(tonic::Status::resource_exhausted(format!(
                "import chunks are limited to {IMAGE_IMPORT_HASH_CHECKPOINT_INTERVAL} bytes"
            )));
        }
        let mount = self.fs()?;
        let import_lock = self.import_lock(&req.import_id);
        let _import = import_lock.lock().await;
        let (part_path, journal_path) = import_paths(&req.import_id);
        let journal = load_import_journal(mount, &journal_path).await?;
        let mut session = self
            .acquire_import_session(mount, &journal, &part_path)
            .await?;
        let current = session.accepted_offset();
        if req.offset != current {
            self.put_import_session(session);
            return Err(tonic::Status::failed_precondition(format!(
                "import offset {} is not the accepted offset {current}",
                req.offset
            )));
        }
        let Some(end) = current.checked_add(req.data.len() as u64) else {
            self.put_import_session(session);
            return Err(tonic::Status::invalid_argument("import offset overflowed"));
        };
        if end > journal.expected_size {
            self.put_import_session(session);
            return Err(tonic::Status::resource_exhausted(format!(
                "import chunk ends at {end}, past reserved size {}",
                journal.expected_size
            )));
        }
        let mut next_hasher = session.hasher.clone();
        if let Err(error) = next_hasher.update(&req.data) {
            self.put_import_session(session);
            return Err(tonic::Status::internal(error));
        }
        let _mutation = match self.lifecycle.begin_mutation() {
            Ok(permit) => permit,
            Err(status) => {
                self.put_import_session(session);
                return Err(status);
            }
        };
        let checkpoint_gap = session
            .disk_offset
            .saturating_sub(session.checkpoint_offset);
        if checkpoint_gap.saturating_add(req.data.len() as u64)
            > IMAGE_IMPORT_HASH_CHECKPOINT_INTERVAL
        {
            // Establish the current state before accepting a chunk that would
            // exceed the recovery bound. Failure is backpressure, not a
            // warning: accepting more payload would make restart work
            // unbounded.
            let checkpoint = ImageImportHashCheckpoint::from_session(&session);
            let (checkpoint_slot, checkpoint_path) = next_import_hash_checkpoint_path(&session);
            if let Err(status) =
                store_import_hash_checkpoint(mount, &checkpoint_path, &checkpoint, false).await
            {
                self.put_import_session(session);
                return Err(status);
            }
            session.checkpoint_offset = session.disk_offset;
            session.checkpoint_slot = Some(checkpoint_slot);
        }
        let part = path_safety::sanitize_relative(&part_path).map_err(bad_path)?;
        if let Err(error) = mount
            .write(&part, session.disk_offset, &req.data, false, false, false)
            .await
        {
            self.put_import_session(session);
            return Err(to_status(error));
        }
        session.hasher = next_hasher;
        session.disk_offset = end;
        self.put_import_session(session);
        Ok(tonic::Response::new(pb::WriteImageImportResponse {
            accepted_offset: end,
        }))
    }

    async fn flush_image_import(
        &self,
        request: tonic::Request<pb::FlushImageImportRequest>,
    ) -> Result<tonic::Response<pb::FlushImageImportResponse>, tonic::Status> {
        let req = request.into_inner();
        validate_import_id(&req.import_id)?;
        let mount = self.fs()?;
        let import_lock = self.import_lock(&req.import_id);
        let _import = import_lock.lock().await;
        let (part_path, journal_path) = import_paths(&req.import_id);
        let mut journal = load_import_journal(mount, &journal_path).await?;
        let mut session = self
            .acquire_import_session(mount, &journal, &part_path)
            .await?;
        let _mutation = match self.lifecycle.begin_mutation() {
            Ok(permit) => permit,
            Err(status) => {
                self.put_import_session(session);
                return Err(status);
            }
        };
        let checkpoint = ImageImportHashCheckpoint::from_session(&session);
        let (checkpoint_slot, checkpoint_path) = next_import_hash_checkpoint_path(&session);
        if let Err(status) =
            store_import_hash_checkpoint(mount, &checkpoint_path, &checkpoint, false).await
        {
            self.put_import_session(session);
            return Err(status);
        }
        let durable_offset = session.disk_offset;
        if let Err(error) = mount.sync_all().await {
            self.put_import_session(session);
            return Err(to_status(error));
        }
        journal.durable_offset = durable_offset;
        if let Err(status) = store_import_journal(mount, &journal_path, &journal).await {
            self.put_import_session(session);
            return Err(status);
        }
        session.durable_offset = durable_offset;
        session.checkpoint_offset = durable_offset;
        session.checkpoint_slot = Some(checkpoint_slot);
        self.put_import_session(session);
        Ok(tonic::Response::new(pb::FlushImageImportResponse {
            durable_offset,
        }))
    }

    async fn commit_image_import(
        &self,
        request: tonic::Request<pb::CommitImageImportRequest>,
    ) -> Result<tonic::Response<pb::CommitImageImportResponse>, tonic::Status> {
        let req = request.into_inner();
        validate_import_id(&req.import_id)?;
        let mount = self.fs()?;
        let import_lock = self.import_lock(&req.import_id);
        let _import = import_lock.lock().await;
        let (part_path, journal_path) = import_paths(&req.import_id);
        if !req.expected_sha256.is_empty() {
            validate_sha256(&req.expected_sha256)?;
        }
        if let Some(receipt) = load_import_receipt(mount, &req.import_id).await? {
            receipt.validate_request(&req.import_id, None, &req.expected_sha256)?;
            let has_debris = path_size(mount, &part_path).await?.is_some()
                || path_size(mount, &journal_path).await?.is_some()
                || path_size(mount, &import_hash_checkpoint_path(&req.import_id, 0))
                    .await?
                    .is_some()
                || path_size(mount, &import_hash_checkpoint_path(&req.import_id, 1))
                    .await?
                    .is_some();
            if has_debris {
                let _mutation = self.lifecycle.begin_mutation()?;
                let _allocation = self.allocation_gate.lock().await;
                self.discard_import_session(&req.import_id);
                remove_if_present(mount, &part_path).await?;
                remove_if_present(mount, &journal_path).await?;
                remove_import_hash_checkpoints(mount, &req.import_id).await?;
                mount.sync_all().await.map_err(to_status)?;
            }
            return Ok(tonic::Response::new(receipt_response(receipt)));
        }
        let mut journal = load_import_journal(mount, &journal_path).await?;
        let expected_sha256 = match (
            journal.expected_sha256.as_str(),
            req.expected_sha256.as_str(),
        ) {
            ("", "") => {
                return Err(tonic::Status::invalid_argument(
                    "expected_sha256 is required at commit when begin omitted it",
                ))
            }
            ("", digest) | (digest, "") => digest.to_owned(),
            (bound, supplied) if bound == supplied => bound.to_owned(),
            _ => {
                return Err(tonic::Status::failed_precondition(
                    "commit digest does not match the digest bound at begin",
                ))
            }
        };
        let canonical_path = canonical_image_path(&expected_sha256);
        let canonical = path_safety::sanitize_relative(&canonical_path).map_err(bad_path)?;

        if path_size(mount, &canonical_path).await?.is_some()
            && path_size(mount, &part_path).await?.is_none()
        {
            let verified = mount
                .inspect_cryostore(&canonical, &expected_sha256, journal.expected_size)
                .await
                .map_err(to_status)?;
            let _mutation = self.lifecycle.begin_mutation()?;
            let _allocation = self.allocation_gate.lock().await;
            let receipt = ImageImportReceipt::new(req.import_id.clone(), canonical_path, verified);
            store_import_receipt(mount, &receipt, false).await?;
            self.discard_import_session(&req.import_id);
            remove_if_present(mount, &journal_path).await?;
            remove_import_hash_checkpoints(mount, &req.import_id).await?;
            mount.sync_all().await.map_err(to_status)?;
            return Ok(tonic::Response::new(receipt_response(receipt)));
        }

        let part = path_safety::sanitize_relative(&part_path).map_err(bad_path)?;
        let mut session = self
            .acquire_import_session(mount, &journal, &part_path)
            .await?;
        if session.accepted_offset() != journal.expected_size {
            let accepted = session.accepted_offset();
            self.put_import_session(session);
            return Err(tonic::Status::failed_precondition(format!(
                "import has accepted {accepted} of {} bytes",
                journal.expected_size
            )));
        }
        let mut digest = session.hasher.clone().finalize_hex();
        if digest != expected_sha256 && session.checkpoint_slot.is_some() {
            // A checkpoint is an acceleration index, not content authority.
            // JSON can remain structurally valid after a storage fault changes
            // one chaining word, so a final mismatch must be checked once
            // against the payload from byte zero before rejecting intact data.
            // This exceptional O(image) read holds only the import lock; normal
            // recovery and publication remain bounded.
            let checkpoint_digest = digest;
            let mut rebuilt = resumable_sha256::ResumableSha256::new();
            if let Err(error) = mount
                .update_hash_range(&part, 0, journal.expected_size, &mut rebuilt)
                .await
            {
                self.put_import_session(session);
                return Err(to_status(error));
            }
            digest = rebuilt.clone().finalize_hex();
            if digest == expected_sha256 {
                log::warn!(
                    import_id:% = req.import_id,
                    checkpoint_digest:% = checkpoint_digest;
                    "discarding an image-import hash checkpoint that disagrees with intact payload"
                );
                session.hasher = rebuilt;
                session.checkpoint_offset = session.disk_offset;
                session.checkpoint_slot = None;
            }
        }
        if digest != expected_sha256 {
            self.put_import_session(session);
            return Err(tonic::Status::data_loss(format!(
                "uploaded image SHA-256 is {digest}; expected {expected_sha256}"
            )));
        }
        let verified = match mount
            .inspect_cryostore(&part, &expected_sha256, journal.expected_size)
            .await
        {
            Ok(verified) => verified,
            Err(error) => {
                self.put_import_session(session);
                return Err(to_status(error));
            }
        };
        let _mutation = match self.lifecycle.begin_mutation() {
            Ok(permit) => permit,
            Err(status) => {
                self.put_import_session(session);
                return Err(status);
            }
        };
        let _allocation = self.allocation_gate.lock().await;
        if journal.expected_sha256.is_empty() {
            journal.expected_sha256 = expected_sha256.clone();
            if let Err(status) = store_import_journal(mount, &journal_path, &journal).await {
                // Atomic publication can report a post-commit sync/tombstone
                // failure after the new journal became visible. Drop this
                // digest-empty cache entry; the retry will rebuild against
                // whichever journal version is authoritative on disk.
                return Err(status);
            }
            // The durable journal remains the identity authority. Update the
            // cached session only after publication succeeds so a failed
            // control-record write cannot poison every retry until reboot.
            session.expected_sha256 = expected_sha256.clone();
        }
        let checkpoint = ImageImportHashCheckpoint::from_session(&session);
        let (_, checkpoint_path) = next_import_hash_checkpoint_path(&session);
        if let Err(status) =
            store_import_hash_checkpoint(mount, &checkpoint_path, &checkpoint, false).await
        {
            self.put_import_session(session);
            return Err(status);
        }
        if let Err(error) = mount.sync_all().await {
            self.put_import_session(session);
            return Err(to_status(error));
        }

        let canonical_exists = match path_size(mount, &canonical_path).await {
            Ok(exists) => exists.is_some(),
            Err(status) => {
                self.put_import_session(session);
                return Err(status);
            }
        };
        if canonical_exists {
            let existing = match mount
                .inspect_cryostore(&canonical, &expected_sha256, journal.expected_size)
                .await
            {
                Ok(existing) => existing,
                Err(error) => {
                    self.put_import_session(session);
                    return Err(to_status(error));
                }
            };
            if existing != verified {
                self.put_import_session(session);
                return Err(tonic::Status::data_loss(
                    "canonical image path contains different verified metadata",
                ));
            }
            if let Err(status) = remove_if_present(mount, &part_path).await {
                self.put_import_session(session);
                return Err(status);
            }
        } else {
            if let Err(error) = mount.rename_lazy(&part, &canonical).await {
                self.put_import_session(session);
                return Err(to_status(error));
            }
        }
        let receipt = ImageImportReceipt::new(req.import_id.clone(), canonical_path, verified);
        if let Err(status) = store_import_receipt(mount, &receipt, false).await {
            self.put_import_session(session);
            return Err(status);
        }
        // Publication succeeded. Drop the claimed cache slot before fallible
        // cleanup so cancellation cannot leave stale in-memory identity behind.
        self.discard_import_session(&req.import_id);
        drop(session);
        remove_if_present(mount, &journal_path).await?;
        remove_import_hash_checkpoints(mount, &req.import_id).await?;
        mount.sync_all().await.map_err(to_status)?;
        Ok(tonic::Response::new(receipt_response(receipt)))
    }

    async fn abort_image_import(
        &self,
        request: tonic::Request<pb::AbortImageImportRequest>,
    ) -> Result<tonic::Response<pb::AbortImageImportResponse>, tonic::Status> {
        let req = request.into_inner();
        validate_import_id(&req.import_id)?;
        let mount = self.fs()?;
        let import_lock = self.import_lock(&req.import_id);
        let _import = import_lock.lock().await;
        if load_import_receipt(mount, &req.import_id).await?.is_some() {
            return Err(tonic::Status::failed_precondition(
                "completed image imports cannot be aborted",
            ));
        }
        let _mutation = self.lifecycle.begin_mutation()?;
        let _allocation = self.allocation_gate.lock().await;
        let (part_path, journal_path) = import_paths(&req.import_id);
        self.discard_import_session(&req.import_id);
        remove_if_present(mount, &part_path).await?;
        remove_if_present(mount, &journal_path).await?;
        remove_import_hash_checkpoints(mount, &req.import_id).await?;
        mount.sync_all().await.map_err(to_status)?;
        Ok(tonic::Response::new(pb::AbortImageImportResponse {}))
    }

    async fn forget_image_import_receipt(
        &self,
        request: tonic::Request<pb::ForgetImageImportReceiptRequest>,
    ) -> Result<tonic::Response<pb::ForgetImageImportReceiptResponse>, tonic::Status> {
        let req = request.into_inner();
        validate_import_id(&req.import_id)?;
        validate_sha256(&req.expected_sha256)?;
        let mount = self.fs()?;
        let import_lock = self.import_lock(&req.import_id);
        let _import = import_lock.lock().await;
        let receipt = load_import_receipt(mount, &req.import_id)
            .await?
            .ok_or_else(|| {
                tonic::Status::not_found("completed image-import receipt was not found")
            })?;
        receipt.validate_request(&req.import_id, None, &req.expected_sha256)?;
        let (part_path, journal_path) = import_paths(&req.import_id);
        if path_size(mount, &part_path).await?.is_some()
            || path_size(mount, &journal_path).await?.is_some()
        {
            return Err(tonic::Status::failed_precondition(
                "complete or reconcile the import cleanup before forgetting its receipt",
            ));
        }
        let _mutation = self.lifecycle.begin_mutation()?;
        let _allocation = self.allocation_gate.lock().await;
        // A Commit reply can be lost after receipt publication but before
        // sidecar cleanup. With both payload and journal absent, these
        // acceleration records have no remaining authority and are safe to
        // collect with the terminal receipt.
        remove_import_hash_checkpoints(mount, &req.import_id).await?;
        remove_if_present(mount, &import_receipt_path(&req.import_id)).await?;
        mount.sync_all().await.map_err(to_status)?;
        Ok(tonic::Response::new(
            pb::ForgetImageImportReceiptResponse {},
        ))
    }
}

// ------------------------------------------------------------------------------
// Network interface bringup — reused verbatim from netstack3_probe/fasync_tcp_spike.
// ------------------------------------------------------------------------------

#[derive(Clone)]
struct HostIpv4Configuration {
    address: [u8; 4],
    prefix_len: u8,
    router: Option<[u8; 4]>,
    dns_servers: Vec<[u8; 4]>,
    default_route_installed: bool,
}

async fn bring_up_interface() -> Result<FuchsiaBootstrapResult> {
    bootstrap(
        FuchsiaBootstrapConfig {
            interface_name: "cerise-eth0",
            ipv4: Ipv4Configuration::Dhcp {
                timeout_seconds: 45,
            },
            policy: BootstrapPolicy {
                discovery_attempts: 90,
                retry_delay_seconds: 5,
                reuse_existing_ipv4: true,
            },
            enable_before_address: true,
            observe_slaac: true,
            install_default_route: true,
            check_socket_provider: true,
        },
        Some(trace),
    )
    .await
}

// ------------------------------------------------------------------------------
// Serve loop: fasync accept -> per-conn hyper HTTP/2 serve over the tonic service.
// ------------------------------------------------------------------------------

#[derive(Clone)]
struct DecodeAdmission<S> {
    inner: S,
    permits: Arc<async_lock::Semaphore>,
}

impl<S, B> TowerService<http::Request<B>> for DecodeAdmission<S>
where
    S: TowerService<http::Request<B>> + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future =
        Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send + 'static>>;

    fn poll_ready(&mut self, context: &mut TaskContext<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(context)
    }

    fn call(&mut self, request: http::Request<B>) -> Self::Future {
        // Calling the tonic service constructs its future but does not poll the
        // request body. Acquire the process-wide permit first so protobuf
        // decoding and its payload allocation are globally bounded across
        // every HTTP/2 connection.
        let response = self.inner.call(request);
        let permits = self.permits.clone();
        Box::pin(async move {
            let _permit = permits.acquire_arc().await;
            response.await
        })
    }
}

async fn serve_on(
    service: CeriseFileServer,
    listen_addr: &'static str,
    connection_permits: Arc<async_lock::Semaphore>,
    decode_permits: Arc<async_lock::Semaphore>,
    publish_ready: bool,
) -> Result<()> {
    let addr: std::net::SocketAddr = listen_addr.parse().unwrap();
    let mut listener = fuchsia_async::net::TcpListener::bind(&addr)
        .context("fuchsia_async::net::TcpListener::bind failed")?;
    log::info!(addr = listen_addr; "fileserver listening for gRPC connections");
    if publish_ready {
        // Boot-gate marker — keep on serial verbatim (validation greps this).
        emit("CERISE-FILESERVER-LISTENING\n");
    }

    loop {
        let (returned, stream, peer) = listener.accept().await.context("accept failed")?;
        listener = returned;
        let Some(connection_permit) = connection_permits.try_acquire_arc() else {
            log::warn!(
                peer:% = peer,
                limit = MAX_GRPC_CONNECTIONS;
                "refusing gRPC connection above the process-wide connection limit"
            );
            continue;
        };
        log::info!(peer:% = peer; "accepted gRPC connection");
        let service = service.clone();
        let decode_permits = decode_permits.clone();
        fuchsia_async::Task::local(async move {
            let _connection_permit = connection_permit;
            let io = FasyncIo::new(stream);
            // gRPC = h2c prior-knowledge -> hyper HTTP/2 server directly (NOT auto).
            let hyper_service = TowerToHyperService::new(DecodeAdmission {
                inner: FileServerServer::new(service)
                    .max_decoding_message_size(MAX_GRPC_DECODING_BYTES),
                permits: decode_permits,
            });
            let result = hyper::server::conn::http2::Builder::new(FasyncExec)
                .max_concurrent_streams(32)
                .initial_stream_window_size(GRPC_FLOW_CONTROL_WINDOW_BYTES)
                .initial_connection_window_size(GRPC_FLOW_CONTROL_WINDOW_BYTES)
                .serve_connection(io, hyper_service)
                .await;
            match result {
                Ok(()) => log::debug!(peer:% = peer; "gRPC connection closed cleanly"),
                Err(e) => log::warn!(peer:% = peer; "gRPC connection ended with error: {e}"),
            }
        })
        .detach();
    }
}

async fn serve(service: CeriseFileServer) -> Result<()> {
    let connection_permits = Arc::new(async_lock::Semaphore::new(MAX_GRPC_CONNECTIONS));
    let decode_permits = Arc::new(async_lock::Semaphore::new(MAX_CONCURRENT_DECODES));
    let mut controller_service = service.clone();
    controller_service.generic_mutation_authority = GenericMutationAuthority::Controller;
    futures::try_join!(
        serve_on(
            service,
            LISTEN_ADDR,
            connection_permits.clone(),
            decode_permits.clone(),
            true,
        ),
        serve_on(
            controller_service,
            CONTROL_LISTEN_ADDR,
            connection_permits,
            decode_permits,
            false,
        ),
    )?;
    Ok(())
}

#[derive(Clone, Default)]
struct HostNetworkConfiguration {
    inner: Arc<std::sync::Mutex<(u64, Option<HostIpv4Configuration>)>>,
}

impl HostNetworkConfiguration {
    fn publish(&self, configuration: HostIpv4Configuration) {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        inner.0 = inner.0.saturating_add(1);
        inner.1 = Some(configuration);
    }

    fn current(&self) -> fnetwork::Configuration {
        let inner = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(configuration) = &inner.1 else {
            return fnetwork::Configuration {
                generation: Some(inner.0),
                ready: Some(false),
                ..Default::default()
            };
        };
        fnetwork::Configuration {
            generation: Some(inner.0),
            ready: Some(true),
            ipv4_address: Some(configuration.address),
            ipv4_prefix_len: Some(configuration.prefix_len),
            ipv4_router: configuration.router,
            dns_servers: Some(configuration.dns_servers.clone()),
            default_route_installed: Some(configuration.default_route_installed),
            ..Default::default()
        }
    }

    async fn serve(self, mut stream: fnetwork::HostConfigurationRequestStream) {
        use fx_futures::TryStreamExt;

        loop {
            let request = match stream.try_next().await {
                Ok(Some(request)) => request,
                Ok(None) => return,
                Err(error) => {
                    log::warn!("host network configuration channel error: {error:?}");
                    return;
                }
            };
            match request {
                fnetwork::HostConfigurationRequest::Get { responder } => {
                    if let Err(error) = responder.send(&self.current()) {
                        log::warn!("host network configuration reply failed: {error:?}");
                        return;
                    }
                }
            }
        }
    }
}

enum ComponentService {
    HostNetwork(fnetwork::HostConfigurationRequestStream),
    Status(fstorage::StatusRequestStream),
    Lifecycle(fstorage::LifecycleRequestStream),
}

/// Publishes `cerise.storage/Status` and `cerise.storage/Lifecycle` on the
/// outgoing directory.
///
/// STARTED BEFORE ANY DECISION IS MADE, deliberately. The block device appears
/// ~180s into boot and a refusal is settled later still; if the protocol only
/// appeared once the mount resolved, a console that connected earlier would see the
/// channel close and would have to render that as something — in practice "no disk",
/// which is false. The record starts at PENDING and this server is up from the first
/// moment of `run()`, so "not decided yet" is a state the console can be TOLD rather
/// than left to infer.
fn spawn_component_services(
    network: HostNetworkConfiguration,
    sink: status::Sink,
    lifecycle: StorageLifecycle,
) {
    use fuchsia_component::server::ServiceFs;
    // See the `aliases` note in BUILD.bazel: `futures` here is @grpc's.
    use fx_futures::StreamExt;

    let mut svc = ServiceFs::new_local();
    svc.dir("svc")
        .add_fidl_service(|stream: fnetwork::HostConfigurationRequestStream| {
            ComponentService::HostNetwork(stream)
        })
        .add_fidl_service(|stream: fstorage::StatusRequestStream| ComponentService::Status(stream))
        .add_fidl_service(|stream: fstorage::LifecycleRequestStream| {
            ComponentService::Lifecycle(stream)
        });
    if let Err(e) = svc.take_and_serve_directory_handle() {
        // Not fatal: a product that does not route this protocol has no outgoing
        // directory request to take, and the file server's actual job is unaffected.
        // LOUD, but not fatal. The component's actual job — serving files — is
        // unaffected, and taking the whole file server down because a telemetry channel
        // could not be published would be a bad trade on a machine whose disk is the
        // thing under investigation. But it is a real failure to honour a declared
        // capability, so it gets a marker of its own rather than a log line nobody
        // reads; the console will independently render Storage as unavailable.
        log::error!("no outgoing directory handle; storage status will not be published: {e:?}");
        emit(&format!("CERISE-FILESERVER-STATUS-UNPUBLISHED: {e:?}\n"));
        return;
    }
    fuchsia_async::Task::local(async move {
        svc.for_each_concurrent(None, move |service| {
            let network = network.clone();
            let sink = sink.clone();
            let lifecycle = lifecycle.clone();
            async move {
                match service {
                    ComponentService::HostNetwork(stream) => network.serve(stream).await,
                    ComponentService::Status(stream) => status::serve(sink, stream).await,
                    ComponentService::Lifecycle(stream) => lifecycle.serve(stream).await,
                }
            }
        })
        .await;
    })
    .detach();
}

async fn run(import_policy: ImageImportPolicy) {
    // Initialize the LogSink-backed structured logging backend. Safe to call here: this
    // runs inside the LocalExecutor (see main()), which diagnostics_log::initialize
    // requires. If LogSink isn't routed it degrades to a no-op (MissingOnInit) rather
    // than failing the boot.
    if let Err(e) = diagnostics_log::initialize(
        diagnostics_log::PublishOptions::default().tags(&["fileserver"]),
    ) {
        emit(&format!("CERISE-FILESERVER-LOG-INIT-WARN: {e:?}\n"));
    }
    log::info!("fileserver starting: bringing up netstack3 interface, then mounting fxfs");

    // The one record of what this component decides about storage, published from
    // here on. See status.rs for why it is up before the answer is known.
    let storage_status = status::Sink::new();
    let storage_lifecycle = StorageLifecycle::default();
    let host_network = HostNetworkConfiguration::default();
    spawn_component_services(
        host_network.clone(),
        storage_status.clone(),
        storage_lifecycle.clone(),
    );

    // App-tier NIC share: if another component (apptier_fetcher) already brought the NIC up, skip our
    // own bringup and use the shared interface (we bind 0.0.0.0, so we accept on it regardless).
    let interface_lifetime = match bring_up_interface().await {
        Ok(result) if result.reused_existing_ipv4 => {
            log::info!(
                "an IPv4 interface already exists; sharing it (skipping fileserver NIC bringup)"
            );
            emit("CERISE-FILESERVER-NIC-SHARED\n");
            None
        }
        Ok(result) => {
            let ipv4 = result
                .ipv4
                .expect("provisioned adapter result has IPv4 configuration");
            let configuration = HostIpv4Configuration {
                address: ipv4.address,
                prefix_len: ipv4.prefix_len,
                router: ipv4.router,
                dns_servers: ipv4.dns_servers,
                default_route_installed: ipv4.default_route_installed,
            };
            // Preserve the live boot contract across the shared bootstrap adapter:
            // this proves the address came from DHCP before the listener is declared
            // ready, rather than merely proving that some IPv4 address exists.
            emit(&format!(
                "CERISE-DHCP-LEASE={}.{}.{}.{}/{}\n",
                ipv4.address[0],
                ipv4.address[1],
                ipv4.address[2],
                ipv4.address[3],
                ipv4.prefix_len
            ));
            if result.slaac_link_local_observed == Some(true) {
                emit("CERISE-SLAAC-ADDR-OK\n");
            }
            host_network.publish(configuration);
            result.lifetime
        }
        Err(error) => {
            log::error!(error:?; "interface bringup failed");
            // Boot-gate marker — keep on serial verbatim (validation greps CERISE-FILESERVER-FAIL).
            emit(&format!("CERISE-FILESERVER-FAIL: bringup: {:?}\n", error));
            // The mount is never attempted on this path, so the record must stop saying
            // PENDING — otherwise the console would wait forever for a decision that is
            // not coming.
            storage_status.settle(status::Settled::Unavailable(format!(
                "the file server never reached the disk: network bringup failed ({error:?})"
            )));
            return;
        }
    };
    log::info!("netstack3 interface up");
    // Retain physical-interface ownership for as long as the serving loop.
    let _interface_lifetime = interface_lifetime;

    // storage-backed integration: mount fxfs RW in-process before serving (reliable direct-mount path;
    // heavy — runs on this 16 MiB-stack thread, see main()).
    //
    // WHY A MOUNT FAILURE NO LONGER ENDS THE PROCESS. This used to `return`, so
    // the component never listened. Combined with fs.rs's new refusal policy that
    // would have been a bad trade on real hardware: a disk the file server must
    // not touch (the CF-SZ5's, which carries the ESP the machine boots from)
    // would take the whole file server down with it, and the operator would see a
    // product with no gRPC and no explanation. The failure is REPORTED, not
    // hidden, and it is reported twice over: a serial marker naming the disk and
    // the reason (emitted by fs.rs), and a FAILED_PRECONDITION carrying the same
    // text on every RPC. The rest of the product — the console, the network — is
    // unaffected, which is the point: a refusal is a deliberate, safe outcome and
    // should not read as a crash.
    //
    // What it must NOT do is look like success. CERISE-FILESERVER-OK and
    // -FXFS-MOUNTED are emitted only on a real mount, the E2E/PERSIST sentinels
    // are unreachable without one (see `stat`), and every gate greps
    // CERISE-FILESERVER-DEGRADED as a failure marker — so a QEMU gate whose blank
    // disk stopped being claimable fails loudly instead of passing vacuously.
    trace("FXFS-MOUNT");
    let allocation_gate = Arc::new(futures::lock::Mutex::new(()));
    let import_locks = Arc::new(std::sync::Mutex::new(HashMap::new()));
    let import_sessions = Arc::new(std::sync::Mutex::new(ImageImportRuntime::default()));
    let service = match fs::mount_with_retry(&storage_status).await {
        Ok(m) => {
            log::info!("fxfs mounted read-write; file server ready");
            // Boot-gate markers — keep on serial verbatim.
            emit("CERISE-FILESERVER-FXFS-MOUNTED\n");
            emit("CERISE-FILESERVER-OK\n");
            // The console reads size and usage off the SAME mount this process
            // serves, live, on each request — not a copy that could drift from it.
            let mount = Arc::new(m);
            if let Err(error) = purge_stale_spill(&mount).await {
                log::error!(error:?; "boot-wide stale spill purge failed");
                storage_status.settle(status::Settled::Unavailable(format!(
                    "stale spill purge failed before worker admission: {error:#}"
                )));
                return;
            }
            storage_lifecycle.attach_mount(mount.clone());
            storage_status.settle(status::Settled::Mounted(
                mount.clone() as Arc<dyn status::Usage>
            ));
            CeriseFileServer {
                mount: Some(mount),
                generic_mutation_authority: GenericMutationAuthority::Public,
                lifecycle: storage_lifecycle.clone(),
                allocation_gate: allocation_gate.clone(),
                import_locks: import_locks.clone(),
                import_sessions: import_sessions.clone(),
                import_policy,
                unavailable: Arc::new(String::new()),
            }
        }
        Err(e) => {
            let why = e.message();
            // A REFUSAL and a mere failure are different facts and the panel says so:
            // "we declined, here is what is on the disk" is an operator-actionable
            // state, "we could not get a filesystem" is a fault.
            storage_status.settle(match e {
                fs::MountError::Refused(_) => status::Settled::Refused(why.clone()),
                fs::MountError::Retry(_) => status::Settled::Unavailable(why.clone()),
            });
            log::error!("no filesystem: {why}");
            // Boot-gate marker — keep on serial verbatim. NOT
            // CERISE-FILESERVER-FAIL: the component has not failed, it has
            // declined, and it is about to serve.
            emit(&format!(
                "CERISE-FILESERVER-DEGRADED: serving with NO filesystem; every RPC will \
                 return FAILED_PRECONDITION. Reason: {why}\n"
            ));
            CeriseFileServer {
                mount: None,
                generic_mutation_authority: GenericMutationAuthority::Public,
                lifecycle: storage_lifecycle.clone(),
                allocation_gate,
                import_locks,
                import_sessions,
                import_policy,
                unavailable: Arc::new(format!(
                    "the file server has no filesystem: {why}. It is serving so that the \
                     failure is visible and the rest of the system is unaffected; it will \
                     not format a disk it cannot prove is blank."
                )),
            }
        }
    };

    if let Err(e) = serve(service).await {
        log::error!("serve loop exited with error: {e:?}");
        // Boot-gate marker — keep on serial verbatim.
        emit(&format!("CERISE-FILESERVER-FAIL: serve: {e:?}\n"));
    }
}

fn main() {
    // A generous stack: storage-backed integration mounts fxfs in-process, whose format/mount path builds
    // deeply-nested async state machines that overflow a default stack (see
    // fxfs_probe). Run the whole serve loop on a dedicated 16 MiB-stack thread with
    // its own LocalExecutor now, so storage-backed integration needs no restructuring.
    const STACK_SIZE: usize = 16 * 1024 * 1024;
    let import_policy =
        ImageImportPolicy::from_process_args().expect("invalid image-import policy argument");
    let handle = std::thread::Builder::new()
        .name("fileserver-main".to_string())
        .stack_size(STACK_SIZE)
        .spawn(move || {
            let mut executor = fuchsia_async::LocalExecutor::default();
            executor.run_singlethreaded(run(import_policy));
        })
        .expect("failed to spawn fileserver-main thread");
    handle.join().expect("fileserver-main thread panicked");
}

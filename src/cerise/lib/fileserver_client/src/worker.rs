//! The gRPC half: a `Send` handle in front of a `!Send` connection driver.
//!
//! # Why this is split, and why it is not an over-engineering
//!
//! `tonic`'s generated client is parameterised over a request body of type
//! `tonic::body::BoxBody`, which is
//! `http_body_util::combinators::UnsyncBoxBody<Bytes, Status>` — **`!Send` by
//! construction**, that being the entire difference between `UnsyncBoxBody` and
//! `BoxBody`. Everything that holds one inherits it: `hyper`'s
//! `SendRequest<BoxBody>` is `!Send`, and so is any future that borrows the
//! generated client to make a call.
//!
//! That collides with the storage-side traits, which require `Send` futures —
//! reasonably, since a disk backend has no idea what executor it will be driven
//! on. The collision is real and it cannot be papered over with a bound: the
//! type is genuinely not `Send`.
//!
//! So the connection lives in one task, which never leaves the executor it was
//! spawned on, and callers reach it through a channel. `Request` is `Send`
//! because its parts are, the handle is `Send + Sync` because a channel sender
//! is, and the `!Send` machinery is confined to [`serve`]. The seam also turns
//! out to be where reconnection and request coalescing will want to live, so it
//! is load-bearing rather than merely permissive.
//!
//! # Ordering
//!
//! [`serve`] answers one request at a time, in the order they were queued. A
//! ranged read is a pure read of immutable content, so concurrency would be
//! safe; it is simply not implemented, because the current consumer issues its
//! reads one at a time anyway and a serial loop makes a request log directly
//! comparable to a client-side counter. Making it concurrent means cloning the
//! client per request — which is why the bounds below keep `T: Clone`
//! reachable — and needs a bound on how many are in flight.

use std::io;
use std::time::{Duration, Instant};

use futures::channel::mpsc;
use futures::channel::oneshot;
use futures::future::Either;
use futures::StreamExt;
use sha2::{Digest as _, Sha256};

use crate::FileMutator;
use crate::RangeAssembler;
use crate::RangeReader;
use crate::FILESERVER_IO_CHUNK_BYTES;

use fileserver_proto::cerise::fileserver::v1 as pb;

/// Bound one ordinary local file-service operation.
///
/// This client runs directly over a raw Hyper HTTP/2 connection, not
/// `tonic::transport::Channel`, so it does not inherit Channel's timeout
/// layer. Without an explicit deadline, one half-open stream can retain a
/// spill-store lock forever and prevent a VM from reaching its durable stop
/// barrier. Two minutes is deliberately much larger than a 2 MiB local range
/// operation while still making that failure finite.
const RPC_TIMEOUT: Duration = Duration::from_secs(120);
/// Image verification may inspect a multi-gigabyte object and is not an
/// ordinary bounded range operation. It is still finite so a dead transport
/// cannot own the request driver forever.
const LONG_RPC_TIMEOUT: Duration = Duration::from_secs(60 * 60);

enum CallFailure {
    Status(tonic::Status),
    Timeout,
}

async fn with_deadline<T>(
    _what: &str,
    timeout: Duration,
    operation: impl std::future::Future<Output = Result<T, tonic::Status>>,
) -> Result<T, CallFailure> {
    let timer = futures_timer::Delay::new(timeout);
    futures::pin_mut!(operation);
    futures::pin_mut!(timer);
    match futures::future::select(operation, timer).await {
        Either::Left((result, _)) => result.map_err(CallFailure::Status),
        Either::Right(((), _)) => Err(CallFailure::Timeout),
    }
}

async fn with_absolute_deadline<T>(
    what: &str,
    deadline: Instant,
    operation: impl std::future::Future<Output = Result<T, tonic::Status>>,
) -> Result<T, CallFailure> {
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .ok_or(CallFailure::Timeout)?;
    with_deadline(what, remaining, operation).await
}

fn call_failure_to_io(what: &str, timeout: Duration, failure: CallFailure) -> io::Error {
    match failure {
        CallFailure::Status(status) => status_to_io(what, status),
        CallFailure::Timeout => io::Error::new(
            io::ErrorKind::TimedOut,
            crate::ClientRpcTimeout::new(format!(
                "{what} did not complete within {} seconds",
                timeout.as_secs()
            )),
        ),
    }
}

/// One unit of work for the connection driver.
///
/// The reply channel carries the *result*, so a failure is delivered to the
/// caller that asked rather than taking down the driver.
#[derive(Debug)]
pub enum Request {
    /// Read `len` bytes of `path` from `offset`, exactly.
    Read {
        /// Path relative to the server's root.
        path: String,
        /// Absolute offset within the file.
        offset: u64,
        /// Number of bytes wanted. Never zero-means-EOF: this client always
        /// names a length, because a caller that does not know the length
        /// cannot check it got what it asked for.
        len: u64,
        /// Where the bytes go.
        reply: oneshot::Sender<io::Result<Vec<u8>>>,
    },
    /// Learn the size of `path`.
    Size {
        /// Path relative to the server's root.
        path: String,
        /// Where the answer goes.
        reply: oneshot::Sender<io::Result<u64>>,
    },
    /// Write an exact byte range.
    Write {
        path: String,
        offset: u64,
        data: Vec<u8>,
        create: bool,
        truncate: bool,
        durable: bool,
        reply: oneshot::Sender<io::Result<()>>,
    },
    SourceWrite {
        source: crate::MutationSourceIdentity,
        path: String,
        offset: u64,
        data: Vec<u8>,
        create: bool,
        truncate: bool,
        durable: bool,
        reply: oneshot::Sender<io::Result<()>>,
    },
    /// Create a directory.
    Mkdir {
        path: String,
        parents: bool,
        reply: oneshot::Sender<io::Result<()>>,
    },
    SourceMkdir {
        source: crate::MutationSourceIdentity,
        path: String,
        parents: bool,
        reply: oneshot::Sender<io::Result<()>>,
    },
    /// Rename a path.
    Rename {
        from: String,
        to: String,
        reply: oneshot::Sender<io::Result<()>>,
    },
    SourceRename {
        source: crate::MutationSourceIdentity,
        from: String,
        to: String,
        reply: oneshot::Sender<io::Result<()>>,
    },
    /// Enumerate one directory without recursion.
    List {
        path: String,
        reply: oneshot::Sender<io::Result<Vec<crate::DirectoryEntry>>>,
    },
    /// Enumerate one directory without recursion, rejecting a larger result.
    ListBounded {
        path: String,
        max_entries: usize,
        reply: oneshot::Sender<io::Result<Vec<crate::DirectoryEntry>>>,
    },
    /// Delete a file or directory.
    Delete {
        path: String,
        recursive: bool,
        reply: oneshot::Sender<io::Result<()>>,
    },
    SourceDelete {
        source: crate::MutationSourceIdentity,
        path: String,
        recursive: bool,
        reply: oneshot::Sender<io::Result<()>>,
    },
    SourceFlush {
        source: crate::MutationSourceIdentity,
        reply: oneshot::Sender<io::Result<()>>,
    },
    OpenMutationSource {
        source: crate::MutationSourceIdentity,
        request_id: String,
        reply: oneshot::Sender<io::Result<crate::MutationSourceReceipt>>,
    },
    DrainMutationSource {
        source: crate::MutationSourceIdentity,
        request_id: String,
        reply: oneshot::Sender<io::Result<crate::MutationSourceReceipt>>,
    },
    GetMutationSource {
        source: crate::MutationSourceIdentity,
        request_id: String,
        reply: oneshot::Sender<io::Result<crate::MutationSourceReceipt>>,
    },
    CompactMutationSources {
        authority_domain_id: String,
        closed_through_generation: u64,
        request_id: String,
        reply: oneshot::Sender<io::Result<crate::MutationSourceCompaction>>,
    },
    SealLegacyMutationAdmission {
        request_id: String,
        reply: oneshot::Sender<io::Result<crate::LegacyMutationSeal>>,
    },
    Usage {
        reply: oneshot::Sender<io::Result<crate::StoreUsage>>,
    },
    BeginImageImport {
        import_id: String,
        expected_sha256: String,
        expected_size: u64,
        reply: oneshot::Sender<io::Result<crate::ImageImportState>>,
    },
    WriteImageImport {
        import_id: String,
        offset: u64,
        data: Vec<u8>,
        reply: oneshot::Sender<io::Result<u64>>,
    },
    FlushImageImport {
        import_id: String,
        reply: oneshot::Sender<io::Result<u64>>,
    },
    CommitImageImport {
        import_id: String,
        expected_sha256: String,
        reply: oneshot::Sender<io::Result<crate::VerifiedImageImport>>,
    },
    AbortImageImport {
        import_id: String,
        reply: oneshot::Sender<io::Result<()>>,
    },
}

/// Whether a request is observational or may change durable server state.
///
/// The exhaustive match is intentionally adjacent to the wire request enum:
/// adding an import phase or filesystem operation cannot compile until its
/// replay class is chosen.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestClass {
    Read,
    Mutation,
}

impl Request {
    pub fn class(&self) -> RequestClass {
        match self {
            Self::Read { .. }
            | Self::Size { .. }
            | Self::List { .. }
            | Self::ListBounded { .. }
            | Self::Usage { .. }
            | Self::GetMutationSource { .. } => RequestClass::Read,
            Self::Write { .. }
            | Self::SourceWrite { .. }
            | Self::Mkdir { .. }
            | Self::SourceMkdir { .. }
            | Self::Rename { .. }
            | Self::SourceRename { .. }
            | Self::Delete { .. }
            | Self::SourceDelete { .. }
            | Self::SourceFlush { .. }
            | Self::OpenMutationSource { .. }
            | Self::DrainMutationSource { .. }
            | Self::CompactMutationSources { .. }
            | Self::SealLegacyMutationAdmission { .. }
            | Self::BeginImageImport { .. }
            | Self::WriteImageImport { .. }
            | Self::FlushImageImport { .. }
            | Self::CommitImageImport { .. }
            | Self::AbortImageImport { .. } => RequestClass::Mutation,
        }
    }
}

/// A `Send + Sync` handle onto a connection driven elsewhere.
#[derive(Clone, Debug)]
pub struct FileServerHandle {
    tx: mpsc::UnboundedSender<Request>,
}

/// A file-server handle whose generic mutations carry one exact source identity.
#[derive(Clone, Debug)]
pub struct MutationSourceFileServerHandle {
    inner: FileServerHandle,
    source: crate::MutationSourceIdentity,
}

/// Creates a handle and the queue its driver must consume.
///
/// Unbounded because the driver is the only consumer and the producer is a disk
/// read path that is already bounded by the number of I/Os in flight; a bound
/// here would add a second place for that backpressure to be expressed and no
/// new information.
pub fn channel() -> (FileServerHandle, mpsc::UnboundedReceiver<Request>) {
    let (tx, rx) = mpsc::unbounded();
    (FileServerHandle { tx }, rx)
}

impl FileServerHandle {
    fn send(&self, req: Request) -> io::Result<()> {
        self.tx.unbounded_send(req).map_err(|_| {
            io::Error::new(
                io::ErrorKind::BrokenPipe,
                crate::TransportLost::new("the file server connection driver has stopped"),
            )
        })
    }

    /// Returns a mutation handle bound to an already-open durable source.
    pub fn with_mutation_source(
        &self,
        source: crate::MutationSourceIdentity,
    ) -> io::Result<MutationSourceFileServerHandle> {
        validate_source_identity(&source)?;
        Ok(MutationSourceFileServerHandle {
            inner: self.clone(),
            source,
        })
    }

    pub async fn open_mutation_source(
        &self,
        source: crate::MutationSourceIdentity,
        request_id: &str,
    ) -> io::Result<crate::MutationSourceReceipt> {
        validate_source_identity(&source)?;
        validate_request_id(request_id)?;
        let (reply, wait) = oneshot::channel();
        self.send(Request::OpenMutationSource {
            source,
            request_id: request_id.to_owned(),
            reply,
        })?;
        wait.await.unwrap_or_else(driver_gone)
    }

    pub async fn drain_mutation_source(
        &self,
        source: crate::MutationSourceIdentity,
        request_id: &str,
    ) -> io::Result<crate::MutationSourceReceipt> {
        validate_source_identity(&source)?;
        validate_request_id(request_id)?;
        let (reply, wait) = oneshot::channel();
        self.send(Request::DrainMutationSource {
            source,
            request_id: request_id.to_owned(),
            reply,
        })?;
        wait.await.unwrap_or_else(driver_gone)
    }

    pub async fn get_mutation_source(
        &self,
        source: crate::MutationSourceIdentity,
        request_id: &str,
    ) -> io::Result<crate::MutationSourceReceipt> {
        validate_source_identity(&source)?;
        validate_request_id(request_id)?;
        let (reply, wait) = oneshot::channel();
        self.send(Request::GetMutationSource {
            source,
            request_id: request_id.to_owned(),
            reply,
        })?;
        wait.await.unwrap_or_else(driver_gone)
    }

    pub async fn compact_mutation_sources(
        &self,
        authority_domain_id: &str,
        closed_through_generation: u64,
        request_id: &str,
    ) -> io::Result<crate::MutationSourceCompaction> {
        validate_authority_domain(authority_domain_id)?;
        validate_request_id(request_id)?;
        let (reply, wait) = oneshot::channel();
        self.send(Request::CompactMutationSources {
            authority_domain_id: authority_domain_id.to_owned(),
            closed_through_generation,
            request_id: request_id.to_owned(),
            reply,
        })?;
        wait.await.unwrap_or_else(driver_gone)
    }

    pub async fn seal_legacy_mutation_admission(
        &self,
        request_id: &str,
    ) -> io::Result<crate::LegacyMutationSeal> {
        validate_request_id(request_id)?;
        let (reply, wait) = oneshot::channel();
        self.send(Request::SealLegacyMutationAdmission {
            request_id: request_id.to_owned(),
            reply,
        })?;
        wait.await.unwrap_or_else(driver_gone)
    }

    pub async fn list(&self, path: &str) -> io::Result<Vec<crate::DirectoryEntry>> {
        let (reply, wait) = oneshot::channel();
        self.send(Request::List {
            path: path.to_owned(),
            reply,
        })?;
        match wait.await {
            Ok(result) => result,
            Err(canceled) => driver_gone(canceled),
        }
    }

    /// Enumerates one directory while independently enforcing a maximum
    /// result count. The client rejects a max-plus-one response even when an
    /// older server ignores the additive wire field.
    pub async fn list_bounded(
        &self,
        path: &str,
        max_entries: usize,
    ) -> io::Result<Vec<crate::DirectoryEntry>> {
        if max_entries == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "max_entries must be nonzero for a bounded listing",
            ));
        }
        u64::try_from(max_entries).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "max_entries does not fit the file-server protocol",
            )
        })?;
        let (reply, wait) = oneshot::channel();
        self.send(Request::ListBounded {
            path: path.to_owned(),
            max_entries,
            reply,
        })?;
        match wait.await {
            Ok(result) => result,
            Err(canceled) => driver_gone(canceled),
        }
    }

    pub async fn delete(&self, path: &str, recursive: bool) -> io::Result<()> {
        let (reply, wait) = oneshot::channel();
        self.send(Request::Delete {
            path: path.to_owned(),
            recursive,
            reply,
        })?;
        match wait.await {
            Ok(result) => result,
            Err(canceled) => driver_gone(canceled),
        }
    }

    pub async fn usage(&self) -> io::Result<crate::StoreUsage> {
        let (reply, wait) = oneshot::channel();
        self.send(Request::Usage { reply })?;
        match wait.await {
            Ok(result) => result,
            Err(canceled) => driver_gone(canceled),
        }
    }

    pub async fn begin_image_import(
        &self,
        import_id: &str,
        expected_size: u64,
        expected_sha256: &str,
    ) -> io::Result<crate::ImageImportState> {
        let (reply, wait) = oneshot::channel();
        self.send(Request::BeginImageImport {
            import_id: import_id.to_owned(),
            expected_sha256: expected_sha256.to_owned(),
            expected_size,
            reply,
        })?;
        wait.await.unwrap_or_else(driver_gone)
    }

    pub async fn write_image_import(
        &self,
        import_id: &str,
        offset: u64,
        data: Vec<u8>,
    ) -> io::Result<u64> {
        let (reply, wait) = oneshot::channel();
        self.send(Request::WriteImageImport {
            import_id: import_id.to_owned(),
            offset,
            data,
            reply,
        })?;
        wait.await.unwrap_or_else(driver_gone)
    }

    pub async fn flush_image_import(&self, import_id: &str) -> io::Result<u64> {
        let (reply, wait) = oneshot::channel();
        self.send(Request::FlushImageImport {
            import_id: import_id.to_owned(),
            reply,
        })?;
        wait.await.unwrap_or_else(driver_gone)
    }

    pub async fn commit_image_import(
        &self,
        import_id: &str,
        expected_sha256: &str,
    ) -> io::Result<crate::VerifiedImageImport> {
        let (reply, wait) = oneshot::channel();
        self.send(Request::CommitImageImport {
            import_id: import_id.to_owned(),
            expected_sha256: expected_sha256.to_owned(),
            reply,
        })?;
        wait.await.unwrap_or_else(driver_gone)
    }

    pub async fn abort_image_import(&self, import_id: &str) -> io::Result<()> {
        let (reply, wait) = oneshot::channel();
        self.send(Request::AbortImageImport {
            import_id: import_id.to_owned(),
            reply,
        })?;
        wait.await.unwrap_or_else(driver_gone)
    }
}

impl MutationSourceFileServerHandle {
    pub async fn delete(&self, path: &str, recursive: bool) -> io::Result<()> {
        let (reply, wait) = oneshot::channel();
        self.inner.send(Request::SourceDelete {
            source: self.source.clone(),
            path: path.to_owned(),
            recursive,
            reply,
        })?;
        wait.await.unwrap_or_else(driver_gone)
    }

    pub async fn flush(&self) -> io::Result<()> {
        let (reply, wait) = oneshot::channel();
        self.inner.send(Request::SourceFlush {
            source: self.source.clone(),
            reply,
        })?;
        wait.await.unwrap_or_else(driver_gone)
    }
}

impl RangeReader for MutationSourceFileServerHandle {
    async fn read_range(&self, path: &str, offset: u64, len: u64) -> io::Result<Vec<u8>> {
        self.inner.read_range(path, offset, len).await
    }

    async fn size_of(&self, path: &str) -> io::Result<u64> {
        self.inner.size_of(path).await
    }
}

impl FileMutator for MutationSourceFileServerHandle {
    async fn write_range(
        &self,
        path: &str,
        offset: u64,
        data: Vec<u8>,
        create: bool,
        truncate: bool,
    ) -> io::Result<()> {
        let (reply, wait) = oneshot::channel();
        self.inner.send(Request::SourceWrite {
            source: self.source.clone(),
            path: path.to_owned(),
            offset,
            data,
            create,
            truncate,
            durable: true,
            reply,
        })?;
        wait.await.unwrap_or_else(driver_gone)
    }

    async fn write_range_lazy(
        &self,
        path: &str,
        offset: u64,
        data: Vec<u8>,
        create: bool,
        truncate: bool,
    ) -> io::Result<()> {
        let (reply, wait) = oneshot::channel();
        self.inner.send(Request::SourceWrite {
            source: self.source.clone(),
            path: path.to_owned(),
            offset,
            data,
            create,
            truncate,
            durable: false,
            reply,
        })?;
        wait.await.unwrap_or_else(driver_gone)
    }

    async fn mkdir(&self, path: &str, parents: bool) -> io::Result<()> {
        let (reply, wait) = oneshot::channel();
        self.inner.send(Request::SourceMkdir {
            source: self.source.clone(),
            path: path.to_owned(),
            parents,
            reply,
        })?;
        wait.await.unwrap_or_else(driver_gone)
    }

    async fn rename(&self, from: &str, to: &str) -> io::Result<()> {
        let (reply, wait) = oneshot::channel();
        self.inner.send(Request::SourceRename {
            source: self.source.clone(),
            from: from.to_owned(),
            to: to.to_owned(),
            reply,
        })?;
        wait.await.unwrap_or_else(driver_gone)
    }
}

fn validate_source_identity(source: &crate::MutationSourceIdentity) -> io::Result<()> {
    validate_authority_domain(&source.authority_domain_id)?;
    if source.boot_id == 0 || source.generation == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "mutation source boot_id and generation must be nonzero",
        ));
    }
    if source.principal_id.is_empty() || source.principal_id.len() > 128 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "mutation source principal_id must contain 1..=128 bytes",
        ));
    }
    Ok(())
}

fn validate_authority_domain(value: &str) -> io::Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "authority_domain_id must be exactly 64 lowercase hexadecimal bytes",
        ));
    }
    Ok(())
}

fn validate_request_id(value: &str) -> io::Result<()> {
    if value.is_empty() || value.len() > 128 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "request_id must contain 1..=128 bytes",
        ));
    }
    Ok(())
}

fn source_to_pb(source: crate::MutationSourceIdentity) -> pb::MutationSourceIdentity {
    pb::MutationSourceIdentity {
        authority_domain_id: source.authority_domain_id,
        boot_id: source.boot_id,
        generation: source.generation,
        principal_id: source.principal_id,
    }
}

fn source_context(source: crate::MutationSourceIdentity) -> pb::MutationContext {
    pb::MutationContext {
        actor: Some(pb::mutation_context::Actor::Source(source_to_pb(source))),
    }
}

fn source_from_pb(source: pb::MutationSourceIdentity) -> io::Result<crate::MutationSourceIdentity> {
    let source = crate::MutationSourceIdentity {
        authority_domain_id: source.authority_domain_id,
        boot_id: source.boot_id,
        generation: source.generation,
        principal_id: source.principal_id,
    };
    validate_source_identity(&source)?;
    Ok(source)
}

#[derive(Clone, Copy)]
pub(crate) enum ReceiptRequestBinding {
    Open,
    Drain,
    Either,
}

pub(crate) fn decode_mutation_source_receipt(
    what: &str,
    response: Option<pb::MutationSourceReceipt>,
    expected_source: &crate::MutationSourceIdentity,
    expected_request_id: &str,
    binding: ReceiptRequestBinding,
) -> io::Result<crate::MutationSourceReceipt> {
    let response = response.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{what} response omitted the source receipt"),
        )
    })?;
    let source = response.source.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{what} response omitted the source identity"),
        )
    })?;
    let source = source_from_pb(source)?;
    if &source != expected_source {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{what} response is bound to a different source"),
        ));
    }
    if response.open_request_id.len() > 128 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{what} response has an over-bound open request identity"),
        ));
    }
    if response.drain_request_id.len() > 128
        || response.receipt_sha256.len() > 64
        || response.request_id.is_empty()
        || response.request_id.len() > 128
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{what} response has an over-bound terminal field"),
        ));
    }
    if response.ledger_revision == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{what} response has revision zero"),
        ));
    }
    if response.request_id != expected_request_id {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{what} response did not echo the exact request identity"),
        ));
    }
    let phase = match pb::MutationSourcePhase::try_from(response.phase) {
        Ok(pb::MutationSourcePhase::Open) => crate::MutationSourcePhase::Open,
        Ok(pb::MutationSourcePhase::Draining) => crate::MutationSourcePhase::Draining,
        Ok(pb::MutationSourcePhase::Drained) => crate::MutationSourcePhase::Drained,
        Ok(pb::MutationSourcePhase::Retired) => crate::MutationSourcePhase::Retired,
        Ok(pb::MutationSourcePhase::Unspecified) | Err(_) => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{what} response has an invalid source phase"),
            ));
        }
    };
    if phase != crate::MutationSourcePhase::Retired
        && (response.open_request_id.is_empty() || response.closed_generation_floor != 0)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{what} live-source response has invalid open/floor fields"),
        ));
    }
    match phase {
        crate::MutationSourcePhase::Open
            if !response.drain_request_id.is_empty() || !response.receipt_sha256.is_empty() =>
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{what} OPEN response retains terminal fields"),
            ));
        }
        crate::MutationSourcePhase::Draining
            if response.drain_request_id.is_empty() || !response.receipt_sha256.is_empty() =>
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{what} DRAINING response has invalid terminal fields"),
            ));
        }
        crate::MutationSourcePhase::Drained if response.drain_request_id.is_empty() => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{what} DRAINED response omits its drain request identity"),
            ));
        }
        crate::MutationSourcePhase::Drained => {
            let expected_digest = drain_receipt_digest(
                &source,
                &response.open_request_id,
                &response.drain_request_id,
            );
            if response.receipt_sha256 != expected_digest {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("{what} DRAINED response has a noncanonical receipt digest"),
                ));
            }
        }
        crate::MutationSourcePhase::Retired
            if !response.open_request_id.is_empty()
                || !response.drain_request_id.is_empty()
                || !response.receipt_sha256.is_empty()
                || response.closed_generation_floor < source.generation =>
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{what} RETIRED response lacks a canonical covering-floor proof"),
            ));
        }
        crate::MutationSourcePhase::Retired => {}
        crate::MutationSourcePhase::Open | crate::MutationSourcePhase::Draining => {}
    }
    let request_matches = phase == crate::MutationSourcePhase::Retired
        || match binding {
            ReceiptRequestBinding::Open => response.open_request_id == expected_request_id,
            ReceiptRequestBinding::Drain => response.drain_request_id == expected_request_id,
            ReceiptRequestBinding::Either => {
                response.open_request_id == expected_request_id
                    || response.drain_request_id == expected_request_id
            }
        };
    if !request_matches {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{what} response is bound to a different request"),
        ));
    }
    Ok(crate::MutationSourceReceipt {
        source,
        open_request_id: response.open_request_id,
        drain_request_id: response.drain_request_id,
        phase,
        receipt_sha256: response.receipt_sha256,
        ledger_revision: response.ledger_revision,
        request_id: response.request_id,
        closed_generation_floor: response.closed_generation_floor,
    })
}

pub(crate) fn drain_receipt_digest(
    source: &crate::MutationSourceIdentity,
    open_request_id: &str,
    drain_request_id: &str,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"cerise.fileserver.mutation-source-drain.v1\0");
    for value in [
        source.authority_domain_id.as_bytes(),
        source.principal_id.as_bytes(),
        open_request_id.as_bytes(),
        drain_request_id.as_bytes(),
    ] {
        hasher.update((value.len() as u64).to_le_bytes());
        hasher.update(value);
    }
    hasher.update(source.boot_id.to_le_bytes());
    hasher.update(source.generation.to_le_bytes());
    let digest = hasher.finalize();
    let mut text = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut text, "{byte:02x}").expect("writing to String cannot fail");
    }
    text
}

pub(crate) fn decode_compaction_response(
    what: &str,
    value: pb::CompactMutationSourcesResponse,
    expected_domain: &str,
    expected_floor: u64,
    expected_request_id: &str,
) -> io::Result<crate::MutationSourceCompaction> {
    if value.closed_through_generation != expected_floor
        || value.ledger_revision == 0
        || value.authority_domain_id != expected_domain
        || value.request_id != expected_request_id
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{what} response does not bind the exact request"),
        ));
    }
    Ok(crate::MutationSourceCompaction {
        authority_domain_id: value.authority_domain_id,
        closed_through_generation: value.closed_through_generation,
        request_id: value.request_id,
        ledger_revision: value.ledger_revision,
    })
}

pub(crate) fn decode_legacy_seal_response(
    value: pb::SealLegacyMutationAdmissionResponse,
    expected_request_id: &str,
) -> io::Result<crate::LegacyMutationSeal> {
    if value.ledger_revision == 0 || value.request_id != expected_request_id {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "SealLegacyMutationAdmission response does not bind the exact request",
        ));
    }
    Ok(crate::LegacyMutationSeal {
        request_id: value.request_id,
        ledger_revision: value.ledger_revision,
    })
}

/// A reply channel dropped without an answer means the driver died mid-request.
/// That is a distinct fact from a server error and is reported as one.
fn driver_gone<T>(_: oneshot::Canceled) -> io::Result<T> {
    Err(io::Error::new(
        io::ErrorKind::BrokenPipe,
        crate::TransportLost::new(
            "the file server connection driver dropped a request without answering",
        ),
    ))
}

impl RangeReader for FileServerHandle {
    async fn read_range(&self, path: &str, offset: u64, len: u64) -> io::Result<Vec<u8>> {
        let (reply, wait) = oneshot::channel();
        self.send(Request::Read {
            path: path.to_owned(),
            offset,
            len,
            reply,
        })?;
        match wait.await {
            Ok(r) => r,
            Err(c) => driver_gone(c),
        }
    }

    async fn size_of(&self, path: &str) -> io::Result<u64> {
        let (reply, wait) = oneshot::channel();
        self.send(Request::Size {
            path: path.to_owned(),
            reply,
        })?;
        match wait.await {
            Ok(r) => r,
            Err(c) => driver_gone(c),
        }
    }
}

impl FileMutator for FileServerHandle {
    async fn write_range(
        &self,
        path: &str,
        offset: u64,
        data: Vec<u8>,
        create: bool,
        truncate: bool,
    ) -> io::Result<()> {
        let (reply, wait) = oneshot::channel();
        self.send(Request::Write {
            path: path.to_owned(),
            offset,
            data,
            create,
            truncate,
            durable: true,
            reply,
        })?;
        match wait.await {
            Ok(r) => r,
            Err(c) => driver_gone(c),
        }
    }

    async fn write_range_lazy(
        &self,
        path: &str,
        offset: u64,
        data: Vec<u8>,
        create: bool,
        truncate: bool,
    ) -> io::Result<()> {
        let (reply, wait) = oneshot::channel();
        self.send(Request::Write {
            path: path.to_owned(),
            offset,
            data,
            create,
            truncate,
            durable: false,
            reply,
        })?;
        match wait.await {
            Ok(r) => r,
            Err(c) => driver_gone(c),
        }
    }

    async fn mkdir(&self, path: &str, parents: bool) -> io::Result<()> {
        let (reply, wait) = oneshot::channel();
        self.send(Request::Mkdir {
            path: path.to_owned(),
            parents,
            reply,
        })?;
        match wait.await {
            Ok(r) => r,
            Err(c) => driver_gone(c),
        }
    }

    async fn rename(&self, from: &str, to: &str) -> io::Result<()> {
        let (reply, wait) = oneshot::channel();
        self.send(Request::Rename {
            from: from.to_owned(),
            to: to.to_owned(),
            reply,
        })?;
        match wait.await {
            Ok(r) => r,
            Err(c) => driver_gone(c),
        }
    }
}

/// Turns a gRPC status into an `io::Error` that still names the code.
///
/// The code is kept in the message rather than mapped onto an `ErrorKind`,
/// because the mapping is lossy in the direction that matters: `NOT_FOUND` and
/// `PERMISSION_DENIED` have kinds, but `RESOURCE_EXHAUSTED` and `INTERNAL` do
/// not, and a reader looking at "the store is missing" versus "the server is
/// broken" needs to be able to tell.
fn status_to_io(what: &str, s: tonic::Status) -> io::Error {
    // A status decoded from response trailers has no error source. Tonic adds
    // a source when it synthesizes a status from the HTTP/2 transport. Keep
    // those cases typed so the generation supervisor can reconnect, while an
    // application status (including a server-returned UNAVAILABLE) remains an
    // authoritative reply and must not be retried as a transport failure.
    if std::error::Error::source(&s).is_some() {
        return io::Error::new(
            io::ErrorKind::BrokenPipe,
            crate::TransportLost::new(format!("{what}: file server transport failed: {s}")),
        );
    }
    let kind = match s.code() {
        tonic::Code::NotFound => io::ErrorKind::NotFound,
        tonic::Code::AlreadyExists => io::ErrorKind::AlreadyExists,
        tonic::Code::PermissionDenied => io::ErrorKind::PermissionDenied,
        tonic::Code::InvalidArgument => io::ErrorKind::InvalidInput,
        tonic::Code::Unimplemented => io::ErrorKind::Unsupported,
        tonic::Code::DeadlineExceeded => io::ErrorKind::TimedOut,
        _ => io::ErrorKind::Other,
    };
    io::Error::new(
        kind,
        format!("{what}: gRPC {:?}: {}", s.code(), s.message()),
    )
}

/// Drives one connection until its queue closes.
///
/// Runs forever from the caller's point of view: spawn it, keep the handle.
/// It returns when every [`FileServerHandle`] onto its queue has been dropped.
pub async fn serve<T>(
    client: pb::file_server_client::FileServerClient<T>,
    rx: mpsc::UnboundedReceiver<Request>,
) where
    T: tonic::client::GrpcService<tonic::body::BoxBody>,
    T::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    T::ResponseBody: http_body::Body<Data = bytes::Bytes> + Send + 'static,
    <T::ResponseBody as http_body::Body>::Error:
        Into<Box<dyn std::error::Error + Send + Sync>> + Send,
{
    serve_with_timeouts(client, rx, RPC_TIMEOUT, LONG_RPC_TIMEOUT).await
}

pub(crate) async fn serve_with_timeouts<T>(
    mut client: pb::file_server_client::FileServerClient<T>,
    mut rx: mpsc::UnboundedReceiver<Request>,
    rpc_timeout: Duration,
    long_rpc_timeout: Duration,
) where
    T: tonic::client::GrpcService<tonic::body::BoxBody>,
    T::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    T::ResponseBody: http_body::Body<Data = bytes::Bytes> + Send + 'static,
    <T::ResponseBody as http_body::Body>::Error:
        Into<Box<dyn std::error::Error + Send + Sync>> + Send,
{
    while let Some(req) = rx.next().await {
        match req {
            Request::Read {
                path,
                offset,
                len,
                reply,
            } => {
                let r = read_exact(&mut client, &path, offset, len, rpc_timeout).await;
                // A caller that gave up before the answer arrived is not an
                // error; drop the result.
                let _ = reply.send(r);
            }
            Request::Size { path, reply } => {
                let operation = client.stat(pb::StatRequest { path: path.clone() });
                let r = match with_deadline(&format!("Stat {path}"), rpc_timeout, operation).await {
                    Ok(resp) => Ok(resp.into_inner().size),
                    Err(failure) => Err(call_failure_to_io(
                        &format!("Stat {path}"),
                        rpc_timeout,
                        failure,
                    )),
                };
                let _ = reply.send(r);
            }
            request @ (Request::Write { .. } | Request::SourceWrite { .. }) => {
                let (source, path, offset, data, create, truncate, durable, reply) = match request {
                    Request::Write {
                        path,
                        offset,
                        data,
                        create,
                        truncate,
                        durable,
                        reply,
                    } => (None, path, offset, data, create, truncate, durable, reply),
                    Request::SourceWrite {
                        source,
                        path,
                        offset,
                        data,
                        create,
                        truncate,
                        durable,
                        reply,
                    } => (
                        Some(source),
                        path,
                        offset,
                        data,
                        create,
                        truncate,
                        durable,
                        reply,
                    ),
                    _ => unreachable!("write request was matched above"),
                };
                let expected = data.len() as u64;
                let what = format!("Write {path}[{offset}..+{expected}]");
                let operation = client.write(pb::WriteRequest {
                    path: path.clone(),
                    offset,
                    data,
                    create,
                    truncate,
                    durability: if durable {
                        pb::WriteDurability::Unspecified as i32
                    } else {
                        pb::WriteDurability::Lazy as i32
                    },
                    mutation_context: source.map(source_context),
                });
                let r = match with_deadline(&what, rpc_timeout, operation).await {
                    Ok(resp) if resp.get_ref().bytes_written == expected => Ok(()),
                    Ok(resp) => Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        format!(
                            "Write {path}[{offset}..+{expected}] reported {} byte(s)",
                            resp.get_ref().bytes_written
                        ),
                    )),
                    Err(failure) => Err(call_failure_to_io(&what, rpc_timeout, failure)),
                };
                let _ = reply.send(r);
            }
            request @ (Request::Mkdir { .. } | Request::SourceMkdir { .. }) => {
                let (source, path, parents, reply) = match request {
                    Request::Mkdir {
                        path,
                        parents,
                        reply,
                    } => (None, path, parents, reply),
                    Request::SourceMkdir {
                        source,
                        path,
                        parents,
                        reply,
                    } => (Some(source), path, parents, reply),
                    _ => unreachable!("mkdir request was matched above"),
                };
                let what = format!("Mkdir {path}");
                let operation = client.mkdir(pb::MkdirRequest {
                    path: path.clone(),
                    parents,
                    mutation_context: source.map(source_context),
                });
                let r = with_deadline(&what, rpc_timeout, operation)
                    .await
                    .map(|_| ())
                    .map_err(|failure| call_failure_to_io(&what, rpc_timeout, failure));
                let _ = reply.send(r);
            }
            request @ (Request::Rename { .. } | Request::SourceRename { .. }) => {
                let (source, from, to, reply) = match request {
                    Request::Rename { from, to, reply } => (None, from, to, reply),
                    Request::SourceRename {
                        source,
                        from,
                        to,
                        reply,
                    } => (Some(source), from, to, reply),
                    _ => unreachable!("rename request was matched above"),
                };
                let what = format!("Rename {from} -> {to}");
                let operation = client.rename(pb::RenameRequest {
                    from: from.clone(),
                    to: to.clone(),
                    mutation_context: source.map(source_context),
                });
                let r = with_deadline(&what, rpc_timeout, operation)
                    .await
                    .map(|_| ())
                    .map_err(|failure| call_failure_to_io(&what, rpc_timeout, failure));
                let _ = reply.send(r);
            }
            request @ (Request::List { .. } | Request::ListBounded { .. }) => {
                let (path, max_entries, reply) = match request {
                    Request::List { path, reply } => (path, None, reply),
                    Request::ListBounded {
                        path,
                        max_entries,
                        reply,
                    } => (path, Some(max_entries), reply),
                    _ => unreachable!("list request was matched above"),
                };
                let what = format!("List {path}");
                // A List is one operation even though tonic exposes its
                // response as a stream. Reusing one absolute deadline keeps a
                // slow peer from multiplying this budget by the entry count.
                let deadline = Instant::now() + rpc_timeout;
                let operation = client.list(pb::ListRequest {
                    path: path.clone(),
                    max_entries: max_entries
                        .map(|limit| {
                            u64::try_from(limit)
                                .expect("FileServerHandle validated the listing limit")
                        })
                        .unwrap_or(0),
                });
                let r = match with_absolute_deadline(&what, deadline, operation).await {
                    Ok(response) => {
                        let mut stream = response.into_inner();
                        let mut entries = Vec::new();
                        loop {
                            match with_absolute_deadline(&what, deadline, stream.message()).await {
                                Ok(Some(entry)) => {
                                    if let Some(limit) = max_entries {
                                        if entries.len() >= limit {
                                            break Err(io::Error::new(
                                                io::ErrorKind::InvalidData,
                                                format!(
                                                    "List {path} returned more than the requested {limit} entries"
                                                ),
                                            ));
                                        }
                                    }
                                    entries.push(crate::DirectoryEntry {
                                        name: entry.name,
                                        kind: entry.r#type,
                                        size: entry.size,
                                    });
                                }
                                Ok(None) => break Ok(entries),
                                Err(failure) => {
                                    break Err(call_failure_to_io(
                                        &format!("List {path}"),
                                        rpc_timeout,
                                        failure,
                                    ))
                                }
                            }
                        }
                    }
                    Err(failure) => Err(call_failure_to_io(
                        &format!("List {path}"),
                        rpc_timeout,
                        failure,
                    )),
                };
                let _ = reply.send(r);
            }
            request @ (Request::Delete { .. } | Request::SourceDelete { .. }) => {
                let (source, path, recursive, reply) = match request {
                    Request::Delete {
                        path,
                        recursive,
                        reply,
                    } => (None, path, recursive, reply),
                    Request::SourceDelete {
                        source,
                        path,
                        recursive,
                        reply,
                    } => (Some(source), path, recursive, reply),
                    _ => unreachable!("delete request was matched above"),
                };
                let what = format!("Delete {path}");
                let operation = client.delete(pb::DeleteRequest {
                    path: path.clone(),
                    recursive,
                    mutation_context: source.map(source_context),
                });
                let r = with_deadline(&what, rpc_timeout, operation)
                    .await
                    .map(|_| ())
                    .map_err(|failure| call_failure_to_io(&what, rpc_timeout, failure));
                let _ = reply.send(r);
            }
            Request::SourceFlush { source, reply } => {
                let what = format!("Flush mutation source {}", source.generation);
                let operation = client.flush(pb::FlushRequest {
                    mutation_context: Some(source_context(source)),
                });
                let r = with_deadline(&what, rpc_timeout, operation)
                    .await
                    .map(|_| ())
                    .map_err(|failure| call_failure_to_io(&what, rpc_timeout, failure));
                let _ = reply.send(r);
            }
            Request::OpenMutationSource {
                source,
                request_id,
                reply,
            } => {
                let what = format!("OpenMutationSource {}", source.generation);
                let expected_source = source.clone();
                let expected_request_id = request_id.clone();
                let operation = client.open_mutation_source(pb::OpenMutationSourceRequest {
                    source: Some(source_to_pb(source)),
                    request_id,
                });
                let result = with_deadline(&what, rpc_timeout, operation)
                    .await
                    .map_err(|failure| call_failure_to_io(&what, rpc_timeout, failure))
                    .and_then(|response| {
                        decode_mutation_source_receipt(
                            &what,
                            response.into_inner().receipt,
                            &expected_source,
                            &expected_request_id,
                            ReceiptRequestBinding::Open,
                        )
                    });
                let _ = reply.send(result);
            }
            Request::DrainMutationSource {
                source,
                request_id,
                reply,
            } => {
                let what = format!("DrainMutationSource {}", source.generation);
                let expected_source = source.clone();
                let expected_request_id = request_id.clone();
                let operation = client.drain_mutation_source(pb::DrainMutationSourceRequest {
                    source: Some(source_to_pb(source)),
                    request_id,
                });
                let result = with_deadline(&what, long_rpc_timeout, operation)
                    .await
                    .map_err(|failure| call_failure_to_io(&what, long_rpc_timeout, failure))
                    .and_then(|response| {
                        decode_mutation_source_receipt(
                            &what,
                            response.into_inner().receipt,
                            &expected_source,
                            &expected_request_id,
                            ReceiptRequestBinding::Drain,
                        )
                    });
                let _ = reply.send(result);
            }
            Request::GetMutationSource {
                source,
                request_id,
                reply,
            } => {
                let what = format!("GetMutationSource {}", source.generation);
                let expected_source = source.clone();
                let expected_request_id = request_id.clone();
                let operation = client.get_mutation_source(pb::GetMutationSourceRequest {
                    source: Some(source_to_pb(source)),
                    request_id,
                });
                let result = with_deadline(&what, rpc_timeout, operation)
                    .await
                    .map_err(|failure| call_failure_to_io(&what, rpc_timeout, failure))
                    .and_then(|response| {
                        decode_mutation_source_receipt(
                            &what,
                            response.into_inner().receipt,
                            &expected_source,
                            &expected_request_id,
                            ReceiptRequestBinding::Either,
                        )
                    });
                let _ = reply.send(result);
            }
            Request::CompactMutationSources {
                authority_domain_id,
                closed_through_generation,
                request_id,
                reply,
            } => {
                let what = format!("CompactMutationSources through {closed_through_generation}");
                let expected_domain = authority_domain_id.clone();
                let expected_request_id = request_id.clone();
                let operation =
                    client.compact_mutation_sources(pb::CompactMutationSourcesRequest {
                        authority_domain_id,
                        closed_through_generation,
                        request_id,
                    });
                let result = with_deadline(&what, rpc_timeout, operation)
                    .await
                    .map_err(|failure| call_failure_to_io(&what, rpc_timeout, failure))
                    .and_then(|response| {
                        decode_compaction_response(
                            &what,
                            response.into_inner(),
                            &expected_domain,
                            closed_through_generation,
                            &expected_request_id,
                        )
                    });
                let _ = reply.send(result);
            }
            Request::SealLegacyMutationAdmission { request_id, reply } => {
                let what = "SealLegacyMutationAdmission";
                let expected_request_id = request_id.clone();
                let operation =
                    client.seal_legacy_mutation_admission(pb::SealLegacyMutationAdmissionRequest {
                        request_id,
                    });
                let result = with_deadline(what, rpc_timeout, operation)
                    .await
                    .map_err(|failure| call_failure_to_io(what, rpc_timeout, failure))
                    .and_then(|response| {
                        decode_legacy_seal_response(response.into_inner(), &expected_request_id)
                    });
                let _ = reply.send(result);
            }
            Request::Usage { reply } => {
                let r = with_deadline(
                    "GetUsage",
                    rpc_timeout,
                    client.get_usage(pb::GetUsageRequest {}),
                )
                .await
                .map(|response| {
                    let usage = response.into_inner();
                    crate::StoreUsage {
                        total_bytes: usage.total_bytes,
                        used_bytes: usage.used_bytes,
                        free_bytes: usage.free_bytes,
                        protected_reserve_bytes: usage.protected_reserve_bytes,
                        reserved_bytes: usage.reserved_bytes,
                        image_bytes: usage.image_bytes,
                        artifact_bytes: usage.artifact_bytes,
                        spill_bytes: usage.spill_bytes,
                        control_bytes: usage.control_bytes,
                        staging_bytes: usage.staging_bytes,
                        other_allocated_bytes: usage.other_allocated_bytes,
                        image_push_capacity_bytes: usage.image_push_capacity_bytes,
                    }
                })
                .map_err(|failure| call_failure_to_io("GetUsage", rpc_timeout, failure));
                let _ = reply.send(r);
            }
            Request::BeginImageImport {
                import_id,
                expected_sha256,
                expected_size,
                reply,
            } => {
                let what = format!("BeginImageImport {import_id}");
                let operation = client.begin_image_import(pb::BeginImageImportRequest {
                    import_id: import_id.clone(),
                    expected_sha256,
                    expected_size,
                });
                let r = with_deadline(&what, rpc_timeout, operation)
                    .await
                    .map(|response| {
                        let value = response.into_inner();
                        crate::ImageImportState {
                            import_id: value.import_id,
                            accepted_offset: value.accepted_offset,
                            durable_offset: value.durable_offset,
                        }
                    })
                    .map_err(|failure| call_failure_to_io(&what, rpc_timeout, failure));
                let _ = reply.send(r);
            }
            Request::WriteImageImport {
                import_id,
                offset,
                data,
                reply,
            } => {
                let what = format!("WriteImageImport {import_id}");
                let operation = client.write_image_import(pb::WriteImageImportRequest {
                    import_id: import_id.clone(),
                    offset,
                    data,
                });
                let r = with_deadline(&what, rpc_timeout, operation)
                    .await
                    .map(|response| response.into_inner().accepted_offset)
                    .map_err(|failure| call_failure_to_io(&what, rpc_timeout, failure));
                let _ = reply.send(r);
            }
            Request::FlushImageImport { import_id, reply } => {
                let what = format!("FlushImageImport {import_id}");
                let operation = client.flush_image_import(pb::FlushImageImportRequest {
                    import_id: import_id.clone(),
                });
                let r = with_deadline(&what, long_rpc_timeout, operation)
                    .await
                    .map(|response| response.into_inner().durable_offset)
                    .map_err(|failure| call_failure_to_io(&what, long_rpc_timeout, failure));
                let _ = reply.send(r);
            }
            Request::CommitImageImport {
                import_id,
                expected_sha256,
                reply,
            } => {
                let what = format!("CommitImageImport {import_id}");
                let operation = client.commit_image_import(pb::CommitImageImportRequest {
                    import_id: import_id.clone(),
                    expected_sha256,
                });
                let r = with_deadline(&what, long_rpc_timeout, operation)
                    .await
                    .map(|response| {
                        let value = response.into_inner();
                        crate::VerifiedImageImport {
                            path: value.path,
                            sha256: value.sha256,
                            encoded_bytes: value.encoded_bytes,
                            cryostore_root_hash: value.cryostore_root_hash,
                            guest_disk_bytes: value.guest_disk_bytes,
                            format_version: value.format_version,
                        }
                    })
                    .map_err(|failure| call_failure_to_io(&what, long_rpc_timeout, failure));
                let _ = reply.send(r);
            }
            Request::AbortImageImport { import_id, reply } => {
                let what = format!("AbortImageImport {import_id}");
                let operation = client.abort_image_import(pb::AbortImageImportRequest {
                    import_id: import_id.clone(),
                });
                let r = with_deadline(&what, rpc_timeout, operation)
                    .await
                    .map(|_| ())
                    .map_err(|failure| call_failure_to_io(&what, rpc_timeout, failure));
                let _ = reply.send(r);
            }
        }
    }
}

/// One logical ranged read, split into bounded RPCs and length-checked.
///
/// `RangeReader` deliberately has no transport-sized ceiling: an 88 MiB
/// Cryostore index is still one logical range.  The file service does have a
/// per-RPC ceiling, so this driver owns the adaptation and callers do not have
/// to duplicate it. Each RPC is independently exact through
/// [`read_one_exact`]; a later failure discards the partial aggregate.
async fn read_exact<T>(
    client: &mut pb::file_server_client::FileServerClient<T>,
    path: &str,
    offset: u64,
    len: u64,
    rpc_timeout: Duration,
) -> io::Result<Vec<u8>>
where
    T: tonic::client::GrpcService<tonic::body::BoxBody>,
    T::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    T::ResponseBody: http_body::Body<Data = bytes::Bytes> + Send + 'static,
    <T::ResponseBody as http_body::Body>::Error:
        Into<Box<dyn std::error::Error + Send + Sync>> + Send,
{
    if len == 0 {
        // `length = 0` means "to EOF" on the wire, so an empty request must
        // never be sent: it would ask for the whole file.
        return Ok(Vec::new());
    }
    let end = offset.checked_add(len).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("Read {path}[{offset}..+{len}] overflows the file offset space"),
        )
    })?;
    let capacity = usize::try_from(len).map_err(|_| {
        io::Error::new(
            io::ErrorKind::OutOfMemory,
            format!("Read {path}[{offset}..+{len}] does not fit this address space"),
        )
    })?;
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(capacity).map_err(|_| {
        io::Error::new(
            io::ErrorKind::OutOfMemory,
            format!("Read {path}[{offset}..+{len}] could not reserve its result buffer"),
        )
    })?;
    let mut at = offset;
    while at < end {
        let chunk_len = (end - at).min(FILESERVER_IO_CHUNK_BYTES as u64);
        let chunk = read_one_exact(client, path, at, chunk_len, rpc_timeout).await?;
        bytes.extend_from_slice(&chunk);
        at += chunk_len;
    }
    Ok(bytes)
}

/// One file-service `Read` RPC, assembled from its streamed chunks.
async fn read_one_exact<T>(
    client: &mut pb::file_server_client::FileServerClient<T>,
    path: &str,
    offset: u64,
    len: u64,
    rpc_timeout: Duration,
) -> io::Result<Vec<u8>>
where
    T: tonic::client::GrpcService<tonic::body::BoxBody>,
    T::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    T::ResponseBody: http_body::Body<Data = bytes::Bytes> + Send + 'static,
    <T::ResponseBody as http_body::Body>::Error:
        Into<Box<dyn std::error::Error + Send + Sync>> + Send,
{
    debug_assert!(len > 0 && len <= FILESERVER_IO_CHUNK_BYTES as u64);
    let what = format!("Read {path}[{offset}..+{len}]");
    let operation = client.read(pb::ReadRequest {
        path: path.to_owned(),
        offset,
        length: len,
    });
    let mut stream = with_deadline(&what, rpc_timeout, operation)
        .await
        .map_err(|failure| call_failure_to_io(&what, rpc_timeout, failure))?
        .into_inner();

    let mut asm = RangeAssembler::new(offset, len);
    loop {
        let chunk = with_deadline(&what, rpc_timeout, stream.message())
            .await
            .map_err(|failure| {
                call_failure_to_io(&format!("{what} stream"), rpc_timeout, failure)
            })?;
        match chunk {
            Some(c) => asm.push(c.offset, &c.data)?,
            None => break,
        }
    }
    asm.finish()
}

// Cerise packages: fxblob_storage — the shared `package_directory::NonMetaStorage`
// backed by fxfs's `fuchsia.fxfs/BlobReader` (fxblob), promoted out of pkg_probe so BOTH the
// on-target proof (pkg_probe) and the fuchsia-pkg:// resolver (pkg_resolver) reuse ONE blob source.
//
// fxblob does NOT expose blobs as a flat `fuchsia.io` directory of hash-named files (open-by-hash
// returns NOT_SUPPORTED), so the vendored `NonMetaStorage for fio::DirectoryProxy` impl does not
// apply. Reads go through `BlobReader.GetVmo(hash)` — a pager-backed, per-page merkle-VERIFIED VMO
// (a corrupt blob faults on page-in). This is exactly what the real upstream `blobfs::Client` does.
//
// de-stub of `open`: left `FxblobStorage::open` fail-loud (NOT_SUPPORTED) because
// serving a CONTENT blob as a live openable file needs a `BlobReader`->`vmo_blob` connection. That
// path is implemented here, mirroring `blobfs::open_blob_with_reader`: on `open`, spawn a task on
// the caller's `ExecutionScope` that fetches the blob VMO and serves it as a `vmo_blob::VmoBlob`
// (a vfs `File`) via a `StreamIoConnection`. So `package_directory::serve(...)` over this storage
// now serves content files (`bin/...`, `lib/...`), not just meta files from the meta.far VMO.
//
// EXECUTABILITY: `vmo_blob::VmoBlob::get_backing_memory(EXECUTE)` calls `replace_as_executable`
// against a process-global VMEX resource. A process that must serve EXECUTABLE package blobs (the
// resolver, whose served /pkg backs a launched component's binary + libs) calls `init_vmex` once at
// startup with a vmex obtained from `fuchsia.kernel.VmexResource`. A read-only consumer (pkg_probe,
// which only READS content blobs through the served dir) never calls it — EXECUTE then returns
// NOT_SUPPORTED, READ works. This is the same split as upstream `blobfs::Client::new` (vmex) vs
// `new_readonly`.

use fidl_fuchsia_fxfs::BlobReaderProxy;
use fidl_fuchsia_io as fio;
use fuchsia_hash::Hash;
use package_directory::{NonMetaStorage, NonMetaStorageError};
use vfs::execution_scope::ExecutionScope;
use vfs::file::StreamIoConnection;
use vfs::{ObjectRequest, ObjectRequestRef, ProtocolsExt};

/// Initialize the process-global VMEX resource used to grant EXECUTE rights to served blobs.
/// Call ONCE at startup in any process that serves EXECUTABLE package directories (the resolver).
/// Idempotent-erroring: a second call returns `ALREADY_BOUND` (surfaced by the underlying
/// `vmo_blob::init_vmex_resource`). Read-only consumers never call this.
pub fn init_vmex(vmex: zx::Resource) -> Result<(), anyhow::Error> {
    vmo_blob::init_vmex_resource(vmex)
}

/// A `package_directory::NonMetaStorage` whose content blobs live in the fxfs `blob` volume and are
/// read via `fuchsia.fxfs/BlobReader` (merkle-verified on page-in).
pub struct FxblobStorage {
    reader: BlobReaderProxy,
}

impl FxblobStorage {
    pub fn new(reader: BlobReaderProxy) -> Self {
        Self { reader }
    }
}

/// Spawn a task on `scope` that opens `blob` via `reader` and serves it as a live `fuchsia.io/File`
/// backed by `vmo_blob::VmoBlob`. Errors are delivered asynchronously on the `object_request`
/// channel. Mirrors upstream `blobfs::open_blob_with_reader`.
fn open_blob_with_reader(
    reader: BlobReaderProxy,
    blob_hash: Hash,
    scope: ExecutionScope,
    flags: fio::Flags,
    object_request: ObjectRequest,
) {
    scope.clone().spawn(object_request.handle_async(async move |object_request| {
        let get_vmo_result = reader.get_vmo(&blob_hash.into()).await.map_err(|fidl_error| {
            if let fidl::Error::ClientChannelClosed { status, .. } = fidl_error {
                status
            } else {
                zx::Status::INTERNAL
            }
        })?;
        let vmo = get_vmo_result.map_err(zx::Status::from_raw)?;
        let vmo_blob = vmo_blob::VmoBlob::new(vmo);
        object_request
            .create_connection::<StreamIoConnection<_>, _>(scope, vmo_blob, flags)
            .await
    }));
}

impl NonMetaStorage for FxblobStorage {
    /// Live directory-serving of a CONTENT blob — invoked by `package_directory::serve` when a
    /// client opens a non-meta file (`bin/...`, `lib/...`) through a served package directory.
    fn open(
        &self,
        blob: &Hash,
        flags: fio::Flags,
        scope: ExecutionScope,
        object_request: ObjectRequestRef<'_>,
    ) -> Result<(), zx::Status> {
        // Blobs are immutable and read/exec only: reject any write or creation intent loudly.
        if flags.rights().is_some_and(|rights| rights.contains(fio::Operations::WRITE_BYTES)) {
            return Err(zx::Status::ACCESS_DENIED);
        }
        if flags.creation_mode() != vfs::CreationMode::Never {
            return Err(zx::Status::NOT_SUPPORTED);
        }
        // Errors below are communicated via the `object_request` channel.
        let object_request = object_request.take();
        open_blob_with_reader(self.reader.clone(), *blob, scope, flags, object_request);
        Ok(())
    }

    async fn get_blob_vmo(&self, hash: &Hash) -> Result<zx::Vmo, NonMetaStorageError> {
        self.reader
            .get_vmo(hash)
            .await
            .map_err(NonMetaStorageError::Fidl)?
            .map_err(|s| NonMetaStorageError::GetVmo(zx::Status::from_raw(s)))
    }

    async fn read_blob(&self, hash: &Hash) -> Result<Vec<u8>, NonMetaStorageError> {
        let vmo = self.get_blob_vmo(hash).await?;
        let content_size = vmo.get_content_size().map_err(|e| {
            NonMetaStorageError::ReadBlob(fuchsia_fs::file::ReadError::ReadError(e))
        })?;
        vmo.read_to_vec::<u8>(0, content_size)
            .map_err(|e| NonMetaStorageError::ReadBlob(fuchsia_fs::file::ReadError::ReadError(e)))
    }
}

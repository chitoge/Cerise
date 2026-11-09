// Cerise stub: provides blobfs::Client as a no-op type so that package-directory
// and system-image compile for component-manager bring-up (bootfs resolver path).
// Real blobfs depends on fuchsia.fxfs; we never call Client methods in the
// bootfs path (FuchsiaBootPackageResolver is only active when /boot/blob exists).

use fidl_fuchsia_io as fio;
use fuchsia_hash::Hash;
use vfs::ObjectRequestRef;
use vfs::execution_scope::ExecutionScope;

/// Errors returned by get_blob_vmo.
#[derive(Debug)]
pub enum GetBlobVmoError {
    OpenBlob(fuchsia_fs::node::OpenError),
    GetVmo(zx::Status),
    Fidl(fidl::Error),
}

impl std::fmt::Display for GetBlobVmoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "blobfs stub: GetBlobVmoError")
    }
}
impl std::error::Error for GetBlobVmoError {}

/// No-op blobfs client. All methods return NOT_SUPPORTED.
#[derive(Clone, Debug)]
pub struct Client;

impl Client {
    pub fn open_blob_for_read(
        &self,
        _blob: &Hash,
        _flags: fio::Flags,
        _scope: ExecutionScope,
        _object_request: ObjectRequestRef<'_>,
    ) -> Result<(), zx::Status> {
        Err(zx::Status::NOT_SUPPORTED)
    }

    pub async fn get_blob_vmo(&self, _hash: &Hash) -> Result<zx::Vmo, GetBlobVmoError> {
        Err(GetBlobVmoError::GetVmo(zx::Status::NOT_SUPPORTED))
    }
}

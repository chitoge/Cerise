// RemoteCrypt bridge for the file server's in-process fxfs mount — a verbatim
// reuse of fxfs_probe's proven ProbeCrypt (which itself mirrors fxfs/platform's
// RemoteCrypt): implements fxfs_crypto::Crypt over the fuchsia.fxfs/Crypt FIDL
// service (crypt_fxfs), plus one-per-boot wrapping-key provisioning via
// CryptManagement. See src/cerise/fxfs_probe/src/main.rs for the full rationale.

use anyhow::{Context, Result};
use async_trait::async_trait;
use fidl_fuchsia_fxfs::{
    CryptManagementMarker, CryptMarker, CryptProxy, KeyPurpose as FidlKeyPurpose,
};
use fuchsia_component::client::connect_to_protocol;
use fxfs_crypto::{
    Crypt, EncryptionKey, FxfsKey, KeyPurpose, ObjectType, UnwrappedKey, WrappedKey,
    WrappedKeyBytes, WrappingKeyId,
};
use std::sync::Arc;

// Fixed test wrapping key — matches crypt_fxfs's own unit-test pattern and
// fxfs_probe's. A proof-of-real-encryption server, not a key-management story.
pub const WRAPPING_KEY_ID: u128 = 1;
pub const WRAPPING_KEY: [u8; 32] = [0xAB; 32];

struct RemoteCrypt {
    client: CryptProxy,
}

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
impl Crypt for RemoteCrypt {
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
        Ok((
            key.try_into().map_err(|_| zx::Status::INVALID_ARGS)?,
            UnwrappedKey::new(unwrapped_key),
        ))
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

/// Connects a fresh fuchsia.fxfs/Crypt session wrapped as a `Crypt` impl.
pub fn connect_crypt() -> Result<Arc<dyn Crypt>> {
    let client = connect_to_protocol::<CryptMarker>().context("failed to connect to Crypt")?;
    Ok(Arc::new(RemoteCrypt { client }) as Arc<dyn Crypt>)
}

/// Provisions the wrapping key crypt_fxfs needs before any create_key/unwrap_key.
/// Called exactly once per boot (crypt_fxfs rejects re-adding the same key id).
pub async fn provision_crypt_keys() -> Result<()> {
    let mgmt = connect_to_protocol::<CryptManagementMarker>()
        .context("failed to connect to CryptManagement")?;
    let add = mgmt
        .add_wrapping_key(&WRAPPING_KEY_ID.to_le_bytes(), &WRAPPING_KEY)
        .await
        .context("AddWrappingKey FIDL call failed")?;
    match add {
        Ok(()) => {}
        Err(raw) if zx::Status::from_raw(raw) == zx::Status::ALREADY_EXISTS => {}
        Err(raw) => {
            return Err(zx::Status::from_raw(raw)).context("AddWrappingKey rejected");
        }
    }
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

// Copyright 2022 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Manages encryption for Fxfs' data volume.
//!
//! The keys for the data volume are stored in the "unencrypted" volume in a keybag.  The contents
//! of "unencrypted" differ, depending on the crypt policy used:
//!
//! # Legacy policies (null / tee):
//!
//! keys/
//!   fxfs-data  # Wrapped keys for the data volume are serialized to this file; see
//!              # [`KeyBagManager`]
//!
//! # Keymint policy (hardware-sealed keys)
//!
//! keys/
//!   keymint.0 # The sealing key ID and sealed keys for each volume are stored in this file; see
//!             # [`KeyManager`]

use crate::device::constants::{DATA_VOLUME_LABEL, UNENCRYPTED_VOLUME_LABEL};
use anyhow::{Context, Error, anyhow};
// Cerise change: only `KeySource::Null` exists in this build (see
// crypt_policy's own top-of-file note) — the keymint-specific unseal/format machinery below
// is trimmed to match (no TEE/TrustZone hardware on any Cerise target).
use crypt_policy::{KeyConsumer, KeySource, format_sources, get_policy, unseal_sources};
use fidl::endpoints::{ClientEnd, Proxy};
use fidl_fuchsia_component::{self as fcomponent, RealmMarker};
use fidl_fuchsia_component_decl as fdecl;
use fidl_fuchsia_fs_startup::{CheckOptions, CreateOptions, MountOptions};
use fidl_fuchsia_fxfs::{CryptManagementMarker, CryptMarker, KeyPurpose};
use fidl_fuchsia_io as fio;
use fs_management::filesystem::{ServingMultiVolumeFilesystem, ServingVolume};
use fuchsia_component::client::{
    connect_to_protocol, connect_to_protocol_at_dir_root, open_childs_exposed_directory,
};
use key_bag::{AES128_KEY_SIZE, AES256_KEY_SIZE, Aes256Key, KeyBagManager, WrappingKey};
use std::ops::Deref;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

struct KeyManager {
    dir: fio::DirectoryProxy,
}

const KEYBAG_DIR_NAME: &'static str = "keys";

const KEYBAG_FILE_NAME: &str = "fxfs-data";

impl KeyManager {
    // Returns `None` if the keybag was absent when attempting to unwrap.  (`None` is never returned
    // when `create` is set).
    async fn unwrap_or_create_keys(
        &mut self,
        create: bool,
    ) -> Result<Option<(Aes256Key, Aes256Key)>, Error> {
        let policy = get_policy().await?;
        log::info!("unwrap_or_create_keys create: {create} policy: {policy:?}");
        let sources = if create { format_sources(policy) } else { unseal_sources(policy) };

        let mut keybag = None;
        let mut last_err = anyhow!("no keys?");
        for source in sources {
            let key = match source {
                KeySource::Null(null) => null.get_key(KeyConsumer::Fxfs),
            };
            let wrapping_key = match key.len() {
                // unwrap is safe because we know the length of the requested array is the same
                // length as the Vec in both branches.
                AES128_KEY_SIZE => WrappingKey::Aes128(key.try_into().unwrap()),
                AES256_KEY_SIZE => WrappingKey::Aes256(key.try_into().unwrap()),
                _ => {
                    last_err = anyhow!("invalid key size");
                    continue;
                }
            };
            if keybag.is_none() {
                let keybag_dir =
                    fuchsia_fs::directory::clone(&self.dir).context("Failed to clone dir")?;
                let keybag_dir_fd =
                    fdio::create_fd(keybag_dir.into_channel().unwrap().into_zx_channel().into())?;
                keybag = Some(if create {
                    KeyBagManager::create(keybag_dir_fd, Path::new(KEYBAG_FILE_NAME))?
                } else {
                    let Some(bag) =
                        KeyBagManager::open(keybag_dir_fd, Path::new(KEYBAG_FILE_NAME))?
                    else {
                        return Ok(None);
                    };
                    bag
                });
            }

            let mut unwrap_fn = |slot| {
                if create {
                    keybag.as_mut().unwrap().new_key(slot, &wrapping_key).context("new key")
                } else {
                    keybag
                        .as_mut()
                        .unwrap()
                        .unwrap_key(slot, &wrapping_key)
                        .context("unwrapping key")
                }
            };

            let data_unwrapped = match unwrap_fn(0) {
                Ok(data_unwrapped) => data_unwrapped,
                Err(e) => {
                    last_err = e.context("data key");
                    continue;
                }
            };
            let metadata_unwrapped = match unwrap_fn(1) {
                Ok(metadata_unwrapped) => metadata_unwrapped,
                Err(e) => {
                    last_err = e.context("metadata key");
                    continue;
                }
            };
            return Ok(Some((data_unwrapped, metadata_unwrapped)));
        }
        Err(last_err)
    }
}

/// Unwraps the data volume in `fs`.  Any failures should be treated as fatal and the filesystem
/// should be reformatted and re-initialized.  If Ok(None) is returned, it means the keybag was
/// shredded, so a reformat is required.
/// Returns the name of the data volume as well as a reference to it.
pub async fn unlock_data_volume(
    fs: &mut ServingMultiVolumeFilesystem,
    config: &fshost_config::Config,
) -> Result<Option<(CryptService, String, ServingVolume)>, Error> {
    if config.check_filesystems {
        fs.check_volume(UNENCRYPTED_VOLUME_LABEL, CheckOptions::default())
            .await
            .context("Failed to verify unencrypted")?;
    }
    with_unencrypted_volume(
        fs.open_volume(UNENCRYPTED_VOLUME_LABEL, MountOptions::default())
            .await
            .context("Failed to open unencrypted")?,
        async |unencrypted_volume: &mut ServingVolume| {
            let dir = match fuchsia_fs::directory::open_directory(
                unencrypted_volume.root(),
                KEYBAG_DIR_NAME,
                fio::PERM_READABLE | fio::PERM_WRITABLE,
            )
            .await
            {
                Err(err) if err.is_not_found_error() => return Ok(None),
                res => res?,
            };
            let mut key_manager = KeyManager { dir };
            let Some((data_unwrapped, metadata_unwrapped)) =
                key_manager.unwrap_or_create_keys(false).await?
            else {
                return Ok(None);
            };

            let crypt_service =
                CryptService::new(data_unwrapped, metadata_unwrapped, &config.fxfs_crypt_url)
                    .await
                    .context("init_crypt_service")?;
            if config.check_filesystems {
                fs.check_volume(
                    DATA_VOLUME_LABEL,
                    CheckOptions { crypt: Some(crypt_service.connect()), ..Default::default() },
                )
                .await
                .context("Failed to verify data")?;
            }
            let crypt = Some(crypt_service.connect());

            let volume = fs
                .open_volume(DATA_VOLUME_LABEL, MountOptions { crypt, ..MountOptions::default() })
                .await
                .context("Failed to open data")?;

            Ok(Some((crypt_service, DATA_VOLUME_LABEL.to_string(), volume)))
        },
    )
    .await
}

// We must make sure that the unencrypted volume is properly unmounted for all error paths so that
// it can safely be removed if necessary.
async fn with_unencrypted_volume<R>(
    mut unencrypted_volume: ServingVolume,
    callback: impl AsyncFnOnce(&mut ServingVolume) -> Result<R, Error>,
) -> Result<R, Error> {
    let result = callback(&mut unencrypted_volume).await;
    let _ = unencrypted_volume.shutdown().await;
    result
}

/// Initializes the data volume in `fs`, which should be freshly reformatted.
/// Returns the name of the data volume as well as a reference to it.
pub async fn init_data_volume<'a>(
    fs: &'a mut ServingMultiVolumeFilesystem,
    config: &'a fshost_config::Config,
) -> Result<(CryptService, String, ServingVolume), Error> {
    // Open up the unencrypted volume so that we can access the key-bag for data.
    crate::debug_log("INIT-DATA-VOLUME-CREATE-UNENCRYPTED-START");
    let unencrypted_created = fs
        .create_volume(UNENCRYPTED_VOLUME_LABEL, CreateOptions::default(), MountOptions::default())
        .await
        .context("Failed to create unencrypted")?;
    crate::debug_log("INIT-DATA-VOLUME-CREATE-UNENCRYPTED-OK");
    with_unencrypted_volume(
        unencrypted_created,
        async |unencrypted_volume| {
            crate::debug_log("INIT-DATA-VOLUME-CREATE-KEYS-DIR-START");
            let dir = fuchsia_fs::directory::create_directory(
                unencrypted_volume.root(),
                KEYBAG_DIR_NAME,
                fio::PERM_READABLE | fio::PERM_WRITABLE,
            )
            .await
            .context("Failed to create keys dir")?;
            crate::debug_log("INIT-DATA-VOLUME-CREATE-KEYS-DIR-OK");
            let mut key_manager = KeyManager { dir };
            let (data_unwrapped, metadata_unwrapped) =
                key_manager.unwrap_or_create_keys(true).await?.unwrap();
            crate::debug_log("INIT-DATA-VOLUME-KEYS-READY");

            let crypt_service =
                CryptService::new(data_unwrapped, metadata_unwrapped, &config.fxfs_crypt_url)
                    .await
                    .context("init_crypt_service")?;
            crate::debug_log("INIT-DATA-VOLUME-CRYPT-SERVICE-READY");
            let crypt = Some(crypt_service.connect());

            crate::debug_log("INIT-DATA-VOLUME-CREATE-DATA-VOLUME-START");
            let volume = fs
                .create_volume(
                    DATA_VOLUME_LABEL,
                    CreateOptions::default(),
                    MountOptions { crypt, ..MountOptions::default() },
                )
                .await
                .context("Failed to create data")?;
            crate::debug_log("INIT-DATA-VOLUME-CREATE-DATA-VOLUME-OK");

            Ok((crypt_service, DATA_VOLUME_LABEL.to_string(), volume))
        },
    )
    .await
}

static FXFS_CRYPT_COLLECTION_NAME: &str = "fxfs-crypt";

pub struct CryptService {
    component_name: String,
    exposed_dir: fio::DirectoryProxy,
}

impl CryptService {
    async fn new(
        data_key: Aes256Key,
        metadata_key: Aes256Key,
        fxfs_crypt_url: &str,
    ) -> Result<Self, Error> {
        static INSTANCE: AtomicU64 = AtomicU64::new(1);

        let collection_ref = fdecl::CollectionRef { name: FXFS_CRYPT_COLLECTION_NAME.to_string() };

        let component_name = format!("fxfs-crypt.{}", INSTANCE.fetch_add(1, Ordering::SeqCst));

        let child_decl = fdecl::Child {
            name: Some(component_name.clone()),
            url: Some(fxfs_crypt_url.to_string()),
            startup: Some(fdecl::StartupMode::Lazy),
            ..Default::default()
        };

        crate::debug_log("CRYPT-SERVICE-NEW-START");
        let realm_proxy = connect_to_protocol::<RealmMarker>()?;
        crate::debug_log("CRYPT-SERVICE-REALM-CONNECTED");

        realm_proxy
            .create_child(&collection_ref, &child_decl, fcomponent::CreateChildArgs::default())
            .await?
            .map_err(|e| anyhow!("create_child failed: {:?}", e))?;
        crate::debug_log("CRYPT-SERVICE-CREATE-CHILD-OK");

        let exposed_dir = open_childs_exposed_directory(
            component_name.clone(),
            Some(FXFS_CRYPT_COLLECTION_NAME.to_string()),
        )
        .await?;
        crate::debug_log("CRYPT-SERVICE-EXPOSED-DIR-OPEN-OK");

        let crypt_management =
            connect_to_protocol_at_dir_root::<CryptManagementMarker>(&exposed_dir)?;
        crate::debug_log("CRYPT-SERVICE-CRYPT-MANAGEMENT-CONNECTED");
        let wrapping_key_id_0 = [0; 16];
        let mut wrapping_key_id_1 = [0; 16];
        wrapping_key_id_1[0] = 1;
        crate::debug_log("CRYPT-SERVICE-ADD-WRAPPING-KEY-0-START");
        crypt_management
            .add_wrapping_key(&wrapping_key_id_0, data_key.deref())
            .await?
            .map_err(zx::Status::from_raw)?;
        crate::debug_log("CRYPT-SERVICE-ADD-WRAPPING-KEY-0-OK");
        crypt_management
            .add_wrapping_key(&wrapping_key_id_1, metadata_key.deref())
            .await?
            .map_err(zx::Status::from_raw)?;
        crate::debug_log("CRYPT-SERVICE-ADD-WRAPPING-KEY-1-OK");
        crypt_management
            .set_active_key(KeyPurpose::Data, &wrapping_key_id_0)
            .await?
            .map_err(zx::Status::from_raw)?;
        crate::debug_log("CRYPT-SERVICE-SET-ACTIVE-KEY-DATA-OK");
        crypt_management
            .set_active_key(KeyPurpose::Metadata, &wrapping_key_id_1)
            .await?
            .map_err(zx::Status::from_raw)?;
        crate::debug_log("CRYPT-SERVICE-SET-ACTIVE-KEY-METADATA-OK");

        Ok(CryptService { component_name, exposed_dir })
    }

    fn connect(&self) -> ClientEnd<CryptMarker> {
        // The assumption is if the crypt service child exists at all, the exposed directory will
        // have the crypt protocol, so we `expect` it.
        connect_to_protocol_at_dir_root::<CryptMarker>(&self.exposed_dir)
            .expect("Unable to connect to Crypt service")
            .into_channel()
            .unwrap()
            .into_zx_channel()
            .into()
    }
}

impl Drop for CryptService {
    fn drop(&mut self) {
        if let Ok(realm_proxy) = connect_to_protocol::<RealmMarker>() {
            let _ = realm_proxy.destroy_child(&fdecl::ChildRef {
                name: self.component_name.clone(),
                collection: Some(FXFS_CRYPT_COLLECTION_NAME.to_string()),
            });
        }
    }
}

// Cerise change: keymint keys are never created on Cerise (`format_sources`
// returns an empty list for `Policy::Keymint`, so `unwrap_or_create_keys` never reaches a
// keymint-key-creation path in the first place) — nothing to delete, always a no-op.
async fn delete_keymint_keys() -> Result<(), Error> {
    Ok(())
}

/// Attempts to shred the key bag stored in the unencrypted volume of `fs`, if it exists.
/// If we fail to find the key bag, we log a warning and return success, since the keys may have
/// already been shredded.
pub async fn shred_key_bag(fs: &ServingMultiVolumeFilesystem) -> Result<(), Error> {
    if let Err(err) = delete_keymint_keys().await {
        log::warn!(err:?; "Failed to delete keymint keys.  Proceeding with best-effort FDR.");
    }

    if !fs.has_volume(UNENCRYPTED_VOLUME_LABEL).await.context("checking for unencrypted volume")? {
        // If the unencrypted volume is missing, the keys are already gone.
        log::warn!("Unencrypted volume not present");
        return Ok(());
    }

    with_unencrypted_volume(
        fs.open_volume(UNENCRYPTED_VOLUME_LABEL, MountOptions::default())
            .await
            .context("Failed to open unencrypted volume")?,
        async |vol| {
            if !fuchsia_fs::directory::dir_contains(vol.root(), KEYBAG_DIR_NAME).await? {
                log::info!("Directory {KEYBAG_DIR_NAME} not present; not shredding");
                return Ok(());
            }
            fuchsia_fs::directory::remove_dir_recursive(vol.root(), KEYBAG_DIR_NAME)
                .await
                .context("Faild to shred keys")?;
            Ok(())
        },
    )
    .await
}

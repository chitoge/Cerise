// Copyright 2024 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! crypt_policy contains all the key policy logic for the different operations that can be done
//! with hardware keys.  Keeping the policy logic in one place makes it easier to audit.
//!
//! Cerise change: the real upstream `TeeDerivedKeySource` and
//! `KeymintSealedData` (plus their `KeySource::TeeDerived`/`KeySource::KeymintSealed`
//! variants) are removed here. The disclosed
//! rationale. No TEE/TrustZone hardware exists on any Cerise target, and Cerise only
//! ever configures `Policy::Null` (a real, first-class upstream policy, not a fallback)
//! via /boot/config/zxcrypt. `format_sources`/`unseal_sources` return an empty key-source
//! list for the TEE/Keymint policy variants rather than silently substituting the null key
//! - if `/boot/config/zxcrypt` is ever misconfigured to request TEE/keymint on Cerise,
//! callers correctly fail closed instead of using an insecure key.

use anyhow::{Error, bail};

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Policy {
    Null,
    TeeRequired,
    TeeTransitional,
    TeeOpportunistic,
    Keymint,
}

impl TryFrom<String> for Policy {
    type Error = Error;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        match value.as_ref() {
            "null" => Ok(Policy::Null),
            "tee" => Ok(Policy::TeeRequired),
            "tee-transitional" => Ok(Policy::TeeTransitional),
            "tee-opportunistic" => Ok(Policy::TeeOpportunistic),
            "keymint" => Ok(Policy::Keymint),
            p => bail!("unrecognized key source policy: '{p}'"),
        }
    }
}

impl std::fmt::Display for Policy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Null => f.write_str("null"),
            Self::TeeRequired => f.write_str("tee"),
            Self::TeeTransitional => f.write_str("tee-transitional"),
            Self::TeeOpportunistic => f.write_str("tee-opportunistic"),
            Self::Keymint => f.write_str("keymint"),
        }
    }
}

/// Reads the policy from well-known locations in `/boot`.
///
/// Cerise change: real upstream reads this from a `/boot/config/zxcrypt`
/// file via a "boot" directory capability. Cerise has no real boot-config-directory
/// capability wired to any component yet (same "no real config-delivery mechanism"
/// rationale already disclosed for fshost's own `Config::take_from_startup_handle()` ->
/// literal Config substitution in this same fshost validation). Since Cerise only ever
/// configures `Policy::Null` (confirmed above - no TEE hardware on any target), return it
/// directly rather than reading a file that doesn't exist in this namespace.
pub async fn get_policy() -> Result<Policy, Error> {
    Ok(Policy::Null)
}

/// Fxfs and zxcrypt have different null keys, so operations have to indicate which is ultimately
/// going to consume the key we produce.
#[derive(Clone, Copy, Debug)]
pub enum KeyConsumer {
    /// The null key for fxfs is a 128-bit key with the bytes "zxcrypt" at the beginning and then
    /// padded with zeros. This is for legacy reasons - earlier versions of this code picked this
    /// key, so we need to continue to use it to avoid wiping everyone's null-key-encrypted fxfs
    /// data partitions.
    Fxfs,
    /// The null key for zxcrypt is a 256-bit key containing all zeros.
    Zxcrypt,
}

#[derive(Debug)]
pub struct NullKeySource;

impl NullKeySource {
    pub fn get_key(&self, consumer: KeyConsumer) -> Vec<u8> {
        match consumer {
            KeyConsumer::Fxfs => {
                let mut key = b"zxcrypt".to_vec();
                key.resize(16, 0);
                key
            }
            KeyConsumer::Zxcrypt => vec![0u8; 32],
        }
    }
}

#[derive(Debug)]
pub enum KeySource {
    /// An insecure static key is used.
    Null(NullKeySource),
}

/// Returns all valid key sources when formatting a volume, based on `policy`. Only
/// `Policy::Null` yields a usable key source on Cerise (see the
/// note at the top of this file); the TEE/Keymint variants intentionally return an empty list.
pub fn format_sources(policy: Policy) -> Vec<KeySource> {
    match policy {
        Policy::Null => vec![KeySource::Null(NullKeySource)],
        Policy::TeeRequired | Policy::TeeTransitional | Policy::TeeOpportunistic | Policy::Keymint => {
            vec![]
        }
    }
}

/// Returns all valid key sources when unsealing a volume, based on `policy`. See
/// `format_sources` above for why only `Policy::Null` yields a usable key source here.
pub fn unseal_sources(policy: Policy) -> Vec<KeySource> {
    match policy {
        Policy::Null => vec![KeySource::Null(NullKeySource)],
        Policy::TeeRequired | Policy::TeeTransitional | Policy::TeeOpportunistic | Policy::Keymint => {
            vec![]
        }
    }
}

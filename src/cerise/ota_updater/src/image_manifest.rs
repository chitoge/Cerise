//! The OS-image update manifest and the decision to accept an image, as pure logic.
//!
//! WHAT WAS WRONG. Before this module the OTA path's only integrity check was a sha256
//! that the *same host* served alongside the image. `main.rs` said so in as many words
//! ("sha256 here is the pre-write integrity gate; an ed25519 signature check slots in
//! at the same point"), and `validation/ota_update_boot_test.py` computed that sha256
//! from the very bytes it was about to serve as the image. One function produced both,
//! so a substituted image and its substituted manifest passed exactly as a genuine pair
//! did. That is not a weak authenticity check; it is the absence of one, and the gate
//! could not have a tampered-image negative test because no tampered input was
//! *constructible* — anything the harness served became, by construction, correct.
//!
//! WHAT THIS ADDS. The manifest now carries an ed25519 signature produced at BUILD time
//! by `//src/cerise/ota_updater:ota_signer` from the seed under `//build/keys`, over
//! domain-separated canonical bytes. The device holds only the public key, staged into
//! its own package at `/pkg/keys/ota_image_pub.ed25519`. The private seed never ships.
//! This is the same trust shape `pkg_index` / `pkg_signer` / `pkg_resolver` already use
//! for the signed package index, deliberately reusing `cerise_signing` rather than
//! introducing a second signature scheme — and the domain tag below is different from
//! the package index's, so a signature over an index entry can never be replayed as a
//! signature over an OS image.
//!
//! WHAT IT DOES NOT ADD. The public key is embedded in the running image, so the trust
//! root is "the image you are already running". That is the same honest limit
//! `pkg_signer`'s header records: this stops a network or host-side substitution, it
//! does not survive an attacker who can rewrite the running image's bootfs, and there
//! is no verified boot or hardware monotonic counter under QEMU to anchor it to.
//! Rollback protection here is likewise partial: [`check_version_forward`] uses the
//! RUNNING image's own version as the floor, which blocks re-serving an older validly
//! signed image over the network, but not physically restoring an old disk.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// The domain tag for OS-image manifests. MUST differ from every other consumer of
/// `cerise_signing` (`pkg_index` uses its own) so signatures cannot cross contexts.
pub const OTA_IMAGE_SIGN_DOMAIN: &str = "cerise-ota-image-v2";

/// The path the public key is staged at inside the updater's own package. Mirrors
/// `pkg_resolver`'s `/pkg/keys/pkg_index_pub.ed25519`.
pub const PUBKEY_PATH: &str = "/pkg/keys/ota_image_pub.ed25519";

/// The manifest served alongside a new OS image.
///
/// `signature` defaults so an old unsigned manifest still *parses* — and is then
/// rejected by [`verify_manifest`], because an empty signature verifies against
/// nothing. Parsing and honouring are kept separate on purpose: a malformed document
/// and an unsigned one should produce different messages in the log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImageManifest {
    pub version: u32,
    /// Lowercase hex sha256 of the image bytes.
    pub sha256: String,
    pub size: u64,
    /// ed25519 signature (128 hex chars) over [`signing_message`]. Empty when unsigned.
    #[serde(default)]
    pub signature: String,
}

/// The CANONICAL bytes the signature covers: domain-separated `{version, sha256, size}`.
/// The build-time signer and the on-device verifier MUST agree byte for byte, so this
/// is the single source of truth for both. The `signature` field is not part of them.
///
/// `size` is signed as well as `sha256` so the length the manifest claims cannot be
/// moved independently of the digest. It does NOT bound the network read: the manifest
/// arrives over the same unauthenticated channel as the image, so nothing in it can be
/// trusted before the signature verifies. `main.rs` bounds the read with a local
/// constant (`MAX_IMAGE_BYTES`); this field is checked afterwards, against bytes
/// already in hand.
pub fn signing_message(version: u32, sha256: &str, size: u64) -> Vec<u8> {
    let version = version.to_string();
    let size = size.to_string();
    cerise_signing::domain_message(OTA_IMAGE_SIGN_DOMAIN, &[&version, sha256, &size])
}

/// Produce a signed manifest. BUILD/HOST-time only — the seed never reaches a device.
pub fn sign_manifest(seed: &[u8; 32], version: u32, image: &[u8]) -> ImageManifest {
    let sha256 = sha256_hex(image);
    let size = image.len() as u64;
    let sig = cerise_signing::sign(seed, &signing_message(version, &sha256, size));
    ImageManifest { version, sha256, size, signature: cerise_signing::to_hex(&sig) }
}

/// Verify a manifest's signature against `pubkey`. False on an empty, malformed or
/// tampered signature, on a tampered field, or on the wrong key. This is the trust
/// boundary the device holds.
pub fn verify_manifest(m: &ImageManifest, pubkey: &[u8; 32]) -> bool {
    let Some(sig) = cerise_signing::from_hex::<64>(&m.signature) else {
        return false;
    };
    cerise_signing::verify(pubkey, &signing_message(m.version, &m.sha256, m.size), &sig)
}

/// Lowercase hex sha256.
pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    cerise_signing::to_hex(&h.finalize())
}

/// Why an offered image was refused. Each carries the numbers, so a refused OTA gives
/// an operator the facts rather than a shrug.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImageRejection {
    /// No public key is staged, so nothing can be verified. FAIL CLOSED: unlike
    /// `pkg_resolver`, where a missing key degrades to the trusted in-image base index
    /// (a safe subset), a missing key here would degrade to "write whatever arrived".
    NoPubkey,
    /// The manifest carries no signature at all.
    Unsigned,
    /// The signature does not verify: tampered manifest, tampered signature, wrong key.
    BadSignature,
    /// The manifest's digest is not lowercase hex of the right length.
    MalformedDigest,
    /// A validly signed but not-newer image. Blocks replay-downgrade over the fetch
    /// path; does not protect against physically restoring an old disk.
    Rollback { offered: u32, running: u32 },
    /// A signed manifest offered as current-boot evidence named a version
    /// different from the version embedded in the running image.
    VersionMismatch { manifest: u32, running: u32 },
    /// The image is not the length the signed manifest claims.
    SizeMismatch { manifest: u64, got: u64 },
    /// The image does not hash to the signed digest — a substituted image under a
    /// genuine manifest.
    HashMismatch { manifest: String, got: String },
}

impl ImageRejection {
    /// A short, stable token for the serial log.
    pub fn token(&self) -> &'static str {
        match self {
            ImageRejection::NoPubkey => "no-pubkey",
            ImageRejection::Unsigned => "unsigned",
            ImageRejection::BadSignature => "bad-signature",
            ImageRejection::MalformedDigest => "malformed-digest",
            ImageRejection::Rollback { .. } => "rollback",
            ImageRejection::VersionMismatch { .. } => "version-mismatch",
            ImageRejection::SizeMismatch { .. } => "size-mismatch",
            ImageRejection::HashMismatch { .. } => "hash-mismatch",
        }
    }
}

impl std::fmt::Display for ImageRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ImageRejection::NoPubkey => write!(f, "no OTA public key staged at {PUBKEY_PATH}"),
            ImageRejection::Unsigned => write!(f, "manifest carries no signature"),
            ImageRejection::BadSignature => write!(f, "manifest signature does not verify"),
            ImageRejection::MalformedDigest => write!(f, "manifest sha256 is not 64 lowercase hex"),
            ImageRejection::Rollback { offered, running } => {
                write!(f, "rollback: offered version {offered} is not newer than running {running}")
            }
            ImageRejection::VersionMismatch { manifest, running } => {
                write!(
                    f,
                    "running version mismatch: signed manifest {manifest}, running image {running}"
                )
            }
            ImageRejection::SizeMismatch { manifest, got } => {
                write!(f, "size mismatch: manifest {manifest}, image {got}")
            }
            ImageRejection::HashMismatch { manifest, got } => {
                write!(f, "sha256 mismatch: manifest {manifest}, computed {got}")
            }
        }
        .and_then(|()| write!(f, " ({})", self.token()))
    }
}

/// Anti-rollback: an offered image must be strictly newer than the one running.
pub fn check_version_forward(offered: u32, running: u32) -> Result<(), ImageRejection> {
    if offered <= running {
        return Err(ImageRejection::Rollback { offered, running });
    }
    Ok(())
}

fn is_lower_hex_digest(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Authenticate the manifest fields before any of them are used as evidence.
fn authenticate_manifest(
    manifest: &ImageManifest,
    pubkey: Option<&[u8; 32]>,
) -> Result<(), ImageRejection> {
    let pubkey = pubkey.ok_or(ImageRejection::NoPubkey)?;
    if manifest.signature.is_empty() {
        return Err(ImageRejection::Unsigned);
    }
    if !is_lower_hex_digest(&manifest.sha256) {
        return Err(ImageRejection::MalformedDigest);
    }
    if !verify_manifest(manifest, pubkey) {
        return Err(ImageRejection::BadSignature);
    }
    Ok(())
}

/// THE decision: may these bytes be written to the inactive slot?
///
/// The on-device caller makes exactly this one call, so these host tests cover the
/// real decision rather than a paraphrase of it. Order is load-bearing:
///
///   1. a public key must exist (fail closed);
///   2. the manifest's digest must be well-formed *before* it is used as a message;
///   3. the SIGNATURE must verify — everything after this point is trusted only
///      because it does. Checking the hash first and the signature second would let a
///      substituted image+manifest pair get all the way to "digest matches" and would
///      make the signature look redundant;
///   4. anti-rollback on the signed version;
///   5. the signed size, then the signed digest, against the actual bytes.
pub fn accept_image(
    manifest: &ImageManifest,
    pubkey: Option<&[u8; 32]>,
    running_version: u32,
    image: &[u8],
) -> Result<(), ImageRejection> {
    authenticate_manifest(manifest, pubkey)?;
    check_version_forward(manifest.version, running_version)?;
    if manifest.size != image.len() as u64 {
        return Err(ImageRejection::SizeMismatch { manifest: manifest.size, got: image.len() as u64 });
    }
    let got = sha256_hex(image);
    if got != manifest.sha256 {
        return Err(ImageRejection::HashMismatch { manifest: manifest.sha256.clone(), got });
    }
    Ok(())
}

/// Verify that a signed manifest describes the exact image already running.
///
/// Unlike [`accept_image`], equality is required rather than rejected: this
/// path attests active-slot evidence and never authorizes a slot write. The
/// caller supplies version from the running bootfs and digest/size from the
/// active-slot file hashed during this boot's success-commit session.
pub fn accept_running_manifest(
    manifest: &ImageManifest,
    pubkey: Option<&[u8; 32]>,
    running_version: u32,
    running_sha256: &str,
    running_size: u64,
) -> Result<(), ImageRejection> {
    authenticate_manifest(manifest, pubkey)?;
    if manifest.version != running_version {
        return Err(ImageRejection::VersionMismatch {
            manifest: manifest.version,
            running: running_version,
        });
    }
    if manifest.size != running_size {
        return Err(ImageRejection::SizeMismatch {
            manifest: manifest.size,
            got: running_size,
        });
    }
    if manifest.sha256 != running_sha256 {
        return Err(ImageRejection::HashMismatch {
            manifest: manifest.sha256.clone(),
            got: running_sha256.to_owned(),
        });
    }
    Ok(())
}

// ==========================================================================================
#[cfg(test)]
mod tests {
    use super::*;

    const SEED: [u8; 32] = [42u8; 32];
    const IMAGE: &[u8] = b"a pretend ZBI, but the bytes are real enough to hash";

    fn pk() -> [u8; 32] {
        cerise_signing::public_from_seed(&SEED)
    }

    fn signed() -> ImageManifest {
        sign_manifest(&SEED, 2, IMAGE)
    }

    // --- the instrument can go green ------------------------------------------------

    #[test]
    fn a_genuine_image_is_accepted() {
        assert_eq!(accept_image(&signed(), Some(&pk()), 1, IMAGE), Ok(()));
    }

    #[test]
    fn a_signed_manifest_can_attest_the_exact_running_slot() {
        let manifest = signed();
        assert_eq!(
            accept_running_manifest(
                &manifest,
                Some(&pk()),
                manifest.version,
                &manifest.sha256,
                manifest.size,
            ),
            Ok(()),
        );
    }

    #[test]
    fn proof_artifact_digests_are_exact_lowercase_sha256() {
        let digest = sha256_hex(b"");
        assert_eq!(
            digest,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(digest.len(), 64);
        assert!(
            digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        );
    }

    #[test]
    fn running_slot_attestation_requires_every_exact_signed_field() {
        let manifest = signed();
        assert_eq!(
            accept_running_manifest(
                &manifest,
                Some(&pk()),
                manifest.version + 1,
                &manifest.sha256,
                manifest.size,
            ),
            Err(ImageRejection::VersionMismatch {
                manifest: manifest.version,
                running: manifest.version + 1,
            }),
        );
        assert_eq!(
            accept_running_manifest(
                &manifest,
                Some(&pk()),
                manifest.version,
                &manifest.sha256,
                manifest.size + 1,
            ),
            Err(ImageRejection::SizeMismatch {
                manifest: manifest.size,
                got: manifest.size + 1,
            }),
        );
        assert_eq!(
            accept_running_manifest(
                &manifest,
                Some(&pk()),
                manifest.version,
                &sha256_hex(b"another running slot"),
                manifest.size,
            ),
            Err(ImageRejection::HashMismatch {
                manifest: manifest.sha256.clone(),
                got: sha256_hex(b"another running slot"),
            }),
        );
    }

    #[test]
    fn running_slot_attestation_still_requires_the_trusted_signature() {
        let manifest = signed();
        assert_eq!(
            accept_running_manifest(
                &manifest,
                None,
                manifest.version,
                &manifest.sha256,
                manifest.size,
            ),
            Err(ImageRejection::NoPubkey),
        );
        let mut tampered = manifest.clone();
        tampered.signature.replace_range(0..1, "0");
        if tampered.signature == manifest.signature {
            tampered.signature.replace_range(0..1, "1");
        }
        assert_eq!(
            accept_running_manifest(
                &tampered,
                Some(&pk()),
                manifest.version,
                &manifest.sha256,
                manifest.size,
            ),
            Err(ImageRejection::BadSignature),
        );
    }

    #[test]
    fn the_manifest_round_trips_through_json() {
        // The device parses JSON off the wire, so the signed bytes must survive that.
        let m = signed();
        let json = serde_json::to_vec(&m).unwrap();
        let back: ImageManifest = serde_json::from_slice(&json).unwrap();
        assert_eq!(back, m);
        assert_eq!(accept_image(&back, Some(&pk()), 1, IMAGE), Ok(()));
    }

    // --- and it can go red, on every axis it claims ----------------------------------

    #[test]
    fn a_substituted_image_under_a_genuine_manifest_is_refused() {
        // The exact attack the old gate could not express: the manifest is authentic
        // and correctly signed; the BYTES are someone else's.
        let evil = b"a completely different ZBI of the same-ish shape".to_vec();
        assert_ne!(evil.len() as u64, IMAGE.len() as u64);
        let r = accept_image(&signed(), Some(&pk()), 1, &evil).unwrap_err();
        assert_eq!(r.token(), "size-mismatch");

        // And when the substitute is padded to the exact signed length, so the size
        // check cannot be what catches it, the signed digest is.
        let mut evil = evil;
        evil.resize(IMAGE.len(), b'.');
        let r = accept_image(&signed(), Some(&pk()), 1, &evil).unwrap_err();
        assert_eq!(r.token(), "hash-mismatch", "the signed digest must catch a same-length swap");
    }

    #[test]
    fn a_substituted_image_with_its_own_recomputed_manifest_is_refused() {
        // This is the one that matters. The old design's failure mode was that an
        // attacker who could serve the image could also serve its manifest, so both
        // moved together and the digest check was vacuous. Here the attacker does
        // exactly that — recomputes a perfectly consistent manifest for their own
        // image — and it fails, because they cannot produce the signature.
        let evil = b"an attacker's ZBI, with a manifest they built themselves".to_vec();
        let attacker_manifest = ImageManifest {
            version: 2,
            sha256: sha256_hex(&evil),
            size: evil.len() as u64,
            signature: String::new(),
        };
        assert_eq!(
            accept_image(&attacker_manifest, Some(&pk()), 1, &evil),
            Err(ImageRejection::Unsigned),
        );

        // Even with a well-formed but attacker-generated signature (their own keypair).
        let attacker_seed = [9u8; 32];
        let forged = sign_manifest(&attacker_seed, 2, &evil);
        assert_eq!(forged.sha256, sha256_hex(&evil), "the forgery is internally consistent");
        assert_eq!(
            accept_image(&forged, Some(&pk()), 1, &evil),
            Err(ImageRejection::BadSignature),
            "an internally consistent manifest signed by the wrong key must not pass",
        );
    }

    #[test]
    fn a_tampered_signature_is_refused() {
        // What //validation:ota-update-tamper-boot serves, produced the same way.
        let mut m = signed();
        let mut sig = m.signature.clone().into_bytes();
        sig[0] = if sig[0] == b'0' { b'1' } else { b'0' };
        m.signature = String::from_utf8(sig).unwrap();
        assert_eq!(accept_image(&m, Some(&pk()), 1, IMAGE), Err(ImageRejection::BadSignature));
    }

    #[test]
    fn every_signed_field_is_actually_covered() {
        // A signature that covered only some fields would still pass the tests above.
        // Move each field in turn and require the signature to stop verifying.
        for mutate in [
            (|m: &mut ImageManifest| m.version = 3) as fn(&mut ImageManifest),
            |m: &mut ImageManifest| m.size += 1,
            |m: &mut ImageManifest| m.sha256 = sha256_hex(b"different"),
        ] {
            let mut m = signed();
            mutate(&mut m);
            assert!(!verify_manifest(&m, &pk()), "a mutated field must break the signature: {m:?}");
        }
    }

    #[test]
    fn a_missing_key_fails_closed() {
        // Deliberately UNLIKE pkg_resolver's graceful absence: there, no key means
        // "honour only the trusted in-image base index", a safe subset. Here, no key
        // would mean "write whatever arrived", so absence must refuse.
        assert_eq!(accept_image(&signed(), None, 1, IMAGE), Err(ImageRejection::NoPubkey));
    }

    #[test]
    fn a_wrong_key_is_refused() {
        let other = cerise_signing::public_from_seed(&[7u8; 32]);
        assert_eq!(accept_image(&signed(), Some(&other), 1, IMAGE), Err(ImageRejection::BadSignature));
    }

    #[test]
    fn a_validly_signed_older_image_is_refused() {
        // Replay-downgrade over the fetch path: the attacker re-serves a genuine,
        // genuinely signed OLD image to reintroduce a fixed bug.
        let old = sign_manifest(&SEED, 1, IMAGE);
        assert!(verify_manifest(&old, &pk()), "the old manifest really is genuine");
        assert_eq!(
            accept_image(&old, Some(&pk()), 2, IMAGE),
            Err(ImageRejection::Rollback { offered: 1, running: 2 }),
        );
        // Equal is also a replay.
        assert_eq!(check_version_forward(2, 2), Err(ImageRejection::Rollback { offered: 2, running: 2 }));
        assert_eq!(check_version_forward(3, 2), Ok(()));
    }

    #[test]
    fn a_malformed_digest_is_refused_before_it_is_used() {
        for bad in ["", "ZZ", &"A".repeat(64), &"a".repeat(63)] {
            let mut m = signed();
            m.sha256 = bad.to_string();
            // Re-sign so the signature is NOT what rejects it — the digest shape is.
            let sig = cerise_signing::sign(&SEED, &signing_message(m.version, &m.sha256, m.size));
            m.signature = cerise_signing::to_hex(&sig);
            assert_eq!(
                accept_image(&m, Some(&pk()), 1, IMAGE),
                Err(ImageRejection::MalformedDigest),
                "digest {bad:?} must be refused on shape",
            );
        }
    }

    #[test]
    fn the_ota_domain_cannot_be_replayed_from_the_package_index() {
        // Domain separation, concretely: the same field values under the package
        // index's domain must not verify here.
        let version = "2";
        let sha = sha256_hex(IMAGE);
        let size = IMAGE.len().to_string();
        let ours = signing_message(2, &sha, IMAGE.len() as u64);
        let theirs = cerise_signing::domain_message("cerise-pkg-index-v2", &[version, &sha, &size]);
        assert_ne!(ours, theirs);
        let cross = cerise_signing::sign(&SEED, &theirs);
        assert!(
            !cerise_signing::verify(&pk(), &ours, &cross),
            "a signature made under another domain must not verify as an OS image",
        );
    }

    #[test]
    fn an_unsigned_legacy_manifest_parses_but_is_never_honoured() {
        // Exactly the document the gate used to serve: version/sha256/size, no
        // signature field at all. It must still parse (so the log says "unsigned"
        // rather than "malformed JSON") and must never be accepted.
        let legacy = br#"{"version":2,"sha256":"00","size":7}"#;
        let m: ImageManifest = serde_json::from_slice(legacy).expect("legacy manifest must parse");
        assert_eq!(m.signature, "");
        assert_eq!(accept_image(&m, Some(&pk()), 1, IMAGE), Err(ImageRejection::Unsigned));
    }

    #[test]
    fn every_rejection_has_a_distinct_token() {
        let all = [
            ImageRejection::NoPubkey,
            ImageRejection::Unsigned,
            ImageRejection::BadSignature,
            ImageRejection::MalformedDigest,
            ImageRejection::Rollback { offered: 1, running: 2 },
            ImageRejection::VersionMismatch { manifest: 1, running: 2 },
            ImageRejection::SizeMismatch { manifest: 1, got: 2 },
            ImageRejection::HashMismatch { manifest: "a".into(), got: "b".into() },
        ];
        let mut seen: Vec<&str> = all.iter().map(|e| e.token()).collect();
        seen.sort_unstable();
        let n = seen.len();
        seen.dedup();
        assert_eq!(seen.len(), n);
    }
}

//! WHETHER a pushed guest store may be written to the guest-image partition.
//!
//! The *decision* half of the push path, split out as a pure library so it can be
//! unit-tested on the host against payloads a live push could never conveniently
//! be made to produce. The same split `fxfs_provisioner` uses for
//! `layout.rs`/`ownership.rs`, the file server for `claim.rs`, the updater for
//! `esp.rs`/`image_manifest.rs` and the block reader for `guest_store_locate`; the
//! component depends on this crate rather than re-`mod`ing the source, so there is
//! exactly one compilation of the logic and no drift between what the tests check
//! and what ships.
//!
//! ## Why unchecked bytes never reach the active partition
//!
//! The signature covers the store, not a chunk of it, so a receiver that streamed
//! chunks straight to the active partition would be writing on an unverified
//! basis and would only find out at the end. Small payloads are accumulated in
//! bounded RAM. Large payloads are streamed to a distinct inactive staging
//! partition, hashed and parsed there, and copied to the active partition only
//! after this module accepts the signed facts and complete index.
//!
//! ## What the signature does and does not establish
//!
//! The machinery is real ed25519 and the on-device side only ever verifies.
//! Signing material never ships in the device image, but the authenticity
//! guarantee is only as strong as the key selected by the build. Accordingly,
//! markers use the precise phrase **signature-checked against the configured
//! key** rather than making a stronger provenance claim.
//!
//! ## What is deliberately NOT here
//!
//! **No anti-rollback.** `ota_image_manifest::check_version_forward` exists
//! because re-serving an older validly-signed OS image over the network
//! reintroduces fixed bugs, and the running image's own version is a floor an
//! attacker on the wire cannot move. A guest store has no such floor — the
//! appliance holds no version state about the guest image, and replacing a guest
//! image with an older one is an ordinary operator action rather than an attack
//! on the appliance. Inventing a version field here would produce a check that
//! looked like rollback protection and was not one.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// The domain tag for pushed guest stores. MUST differ from every other consumer
/// of `cerise_signing` (`cerise-pkg-index-v2`, `cerise-ota-image-v2`) so that a
/// signature made over a package-index entry or an OS image can never be replayed
/// as a signature over a guest store.
pub const GUEST_STORE_SIGN_DOMAIN: &str = "cerise-guest-store-v2";

/// The path the public key is staged at inside the receiver's own package.
/// Mirrors `pkg_resolver`'s `/pkg/keys/pkg_index_pub.ed25519` and the updater's
/// `/pkg/keys/ota_image_pub.ed25519`.
pub const PUBKEY_PATH: &str = "/pkg/keys/guest_store_pub.ed25519";

/// The manifest a pusher sends alongside the store bytes.
///
/// `signature` defaults so an unsigned document still *parses* and is then
/// rejected as [`PushRejection::Unsigned`]. Parsing and honouring are kept
/// separate on purpose: a malformed document and an unsigned one should produce
/// different messages in the log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoreManifest {
    /// Lowercase hex sha256 of the store bytes.
    pub sha256: String,
    /// Length of the store in bytes.
    pub size: u64,
    /// ed25519 signature (128 hex chars) over [`signing_message`]. Empty when
    /// unsigned.
    #[serde(default)]
    pub signature: String,
}

/// The CANONICAL bytes the signature covers: domain-separated `{sha256, size}`.
///
/// The build-time signer and the on-device checker MUST agree byte for byte, so
/// this is the single source of truth for both, and the `signature` field is not
/// part of them. `size` is signed as well as `sha256` so the length the manifest
/// claims cannot be moved independently of the digest. It does NOT bound the
/// network read — the manifest arrives over the same channel as the store, so
/// nothing in it can be acted on before the signature checks out; the receiver
/// bounds its buffer with a local constant.
pub fn signing_message(sha256: &str, size: u64) -> Vec<u8> {
    let size = size.to_string();
    cerise_signing::domain_message(GUEST_STORE_SIGN_DOMAIN, &[sha256, &size])
}

/// Produce a signed manifest. BUILD/HOST-time only — the seed never reaches a
/// device.
pub fn sign_manifest(seed: &[u8; 32], store: &[u8]) -> StoreManifest {
    sign_manifest_digest(seed, sha256_hex(store), store.len() as u64)
}

/// Sign a digest produced by a streaming file reader.
pub fn sign_manifest_digest(seed: &[u8; 32], sha256: String, size: u64) -> StoreManifest {
    let sig = cerise_signing::sign(seed, &signing_message(&sha256, size));
    StoreManifest { sha256, size, signature: cerise_signing::to_hex(&sig) }
}

/// Check a manifest's signature against `pubkey`. False on an empty, malformed or
/// tampered signature, on a moved field, or on the wrong key.
pub fn signature_checks_out(m: &StoreManifest, pubkey: &[u8; 32]) -> bool {
    let Some(sig) = cerise_signing::from_hex::<64>(&m.signature) else {
        return false;
    };
    cerise_signing::verify(pubkey, &signing_message(&m.sha256, m.size), &sig)
}

/// Fail closed on manifest authenticity before reading or parsing staged bytes.
///
/// [`accept_staged_store`] repeats this check as part of the complete admission
/// decision. The receiver also calls it before any staging-partition read so an
/// unsigned or attacker-signed manifest cannot cause untrusted disk contents to
/// reach the store parser.
pub fn check_manifest_signature(
    manifest: &StoreManifest,
    pubkey: Option<&[u8; 32]>,
) -> Result<(), PushRejection> {
    let pubkey = pubkey.ok_or(PushRejection::NoPubkey)?;
    if manifest.signature.is_empty() {
        return Err(PushRejection::Unsigned);
    }
    if !is_lower_hex_digest(&manifest.sha256) {
        return Err(PushRejection::MalformedDigest);
    }
    if !signature_checks_out(manifest, pubkey) {
        return Err(PushRejection::BadSignature);
    }
    Ok(())
}

/// Lowercase hex sha256.
pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    cerise_signing::to_hex(&h.finalize())
}

/// Why a pushed store was refused. Every variant carries the numbers, so a
/// refusal gives an operator the facts rather than a shrug.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PushRejection {
    /// No public key is staged, so no signature can be checked. FAIL CLOSED:
    /// unlike `pkg_resolver`, where a missing key degrades to the trusted
    /// in-image base index (a strictly smaller, safe set), a missing key here
    /// would degrade to "write whatever arrived onto the disk the VMM boots from".
    NoPubkey,
    /// The manifest carries no signature at all.
    Unsigned,
    /// The manifest's digest is not 64 lowercase hex characters.
    MalformedDigest,
    /// The signature does not check out: moved manifest, corrupt signature, or a
    /// different key.
    BadSignature,
    /// The pushed bytes are not the length the signed manifest claims.
    SizeMismatch { manifest: u64, got: u64 },
    /// The pushed bytes do not hash to the signed digest — a substituted payload
    /// under a genuine manifest.
    HashMismatch { manifest: String, got: String },
    /// The bytes are correctly signed and are not a `.cryostore`. Carries the
    /// format crate's own reason.
    NotAStore { why: String },
    /// The store header describes a store of a different length than was pushed.
    /// A short push and a padded push are both this.
    StoreLenMismatch { header: u64, got: u64 },
    /// The store is longer than the partition it would be written to.
    DoesNotFit { store: u64, partition: u64 },
}

impl PushRejection {
    /// A short, stable token for the serial log. Callers prefix it with their own
    /// marker.
    pub fn token(&self) -> &'static str {
        match self {
            PushRejection::NoPubkey => "no-pubkey",
            PushRejection::Unsigned => "unsigned",
            PushRejection::MalformedDigest => "malformed-digest",
            PushRejection::BadSignature => "bad-signature",
            PushRejection::SizeMismatch { .. } => "size-mismatch",
            PushRejection::HashMismatch { .. } => "hash-mismatch",
            PushRejection::NotAStore { .. } => "not-a-store",
            PushRejection::StoreLenMismatch { .. } => "store-length-mismatch",
            PushRejection::DoesNotFit { .. } => "store-does-not-fit",
        }
    }
}

impl std::fmt::Display for PushRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PushRejection::NoPubkey => {
                write!(f, "no guest-store public key staged at {PUBKEY_PATH}")
            }
            PushRejection::Unsigned => write!(f, "the manifest carries no signature"),
            PushRejection::MalformedDigest => {
                write!(f, "the manifest sha256 is not 64 lowercase hex characters")
            }
            PushRejection::BadSignature => write!(
                f,
                "the manifest signature does not check out against the configured key"
            ),
            PushRejection::SizeMismatch { manifest, got } => {
                write!(f, "size mismatch: manifest {manifest}, pushed {got}")
            }
            PushRejection::HashMismatch { manifest, got } => {
                write!(f, "sha256 mismatch: manifest {manifest}, computed {got}")
            }
            PushRejection::NotAStore { why } => {
                write!(f, "the pushed bytes are not a guest store: {why}")
            }
            PushRejection::StoreLenMismatch { header, got } => write!(
                f,
                "the store header describes {header} bytes and {got} were pushed"
            ),
            PushRejection::DoesNotFit { store, partition } => write!(
                f,
                "the store is {store} bytes and the guest-image partition is {partition}"
            ),
        }
        .and_then(|()| write!(f, " ({})", self.token()))
    }
}

fn is_lower_hex_digest(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// THE decision: may these bytes be written to that partition?
///
/// The on-device caller makes exactly this one call, so the host tests below
/// cover the real decision rather than a paraphrase of it. Order is load-bearing:
///
///   1. a public key must exist (fail closed);
///   2. the manifest must be signed at all, and its digest well-formed *before*
///      the digest is used as part of a signed message;
///   3. the SIGNATURE must check out — everything after this point is acted on
///      only because it did. Checking the digest first would let a substituted
///      payload and its own recomputed manifest reach "digest matches", and would
///      make the signature look redundant;
///   4. the signed size, then the signed digest, against the bytes actually in
///      hand;
///   5. only now is the payload parsed AS A STORE, and parsed to the point where
///      the store's own `root_hash` has been checked — not merely to a header
///      that decodes. The bytes are attacker-shaped input right up until step 3
///      passes, and a parser is a poor first line of defence; running it last
///      means `not-a-store` in a log always means "someone signed the wrong or a
///      damaged file", never "someone sent us garbage";
///   6. the store's own declared length must equal what was pushed — a truncated
///      or padded push whose manifest was re-signed for the truncated bytes gets
///      through steps 1-4 by construction, and this is what catches it;
///   7. and it must fit the partition. Last, because it is the only step that
///      depends on the machine rather than on the payload, and a payload that is
///      wrong everywhere should be described by what is wrong with the payload.
///
/// `partition_len` is the located partition's real byte length, bounded against
/// the device's own `block_count` by `guest_store_locate` before it gets here.
pub fn accept_store(
    manifest: &StoreManifest,
    pubkey: Option<&[u8; 32]>,
    store: &[u8],
    partition_len: u64,
) -> Result<(), PushRejection> {
    accept_staged_store(
        manifest,
        pubkey,
        store.len() as u64,
        &sha256_hex(store),
        store,
        partition_len,
    )
}

/// Admit a store whose large body was streamed through inactive staging.
///
/// `index` is the complete index prefix read back from staging. The whole-file
/// digest and byte count are computed while streaming that partition, so this
/// performs the same decision as [`accept_store`] without holding the pack in
/// memory.
pub fn accept_staged_store(
    manifest: &StoreManifest,
    pubkey: Option<&[u8; 32]>,
    got_size: u64,
    got_sha256: &str,
    index: &[u8],
    partition_len: u64,
) -> Result<(), PushRejection> {
    check_manifest_signature(manifest, pubkey)?;
    if manifest.size != got_size {
        return Err(PushRejection::SizeMismatch {
            manifest: manifest.size,
            got: got_size,
        });
    }
    if got_sha256 != manifest.sha256 {
        return Err(PushRejection::HashMismatch {
            manifest: manifest.sha256.clone(),
            got: got_sha256.to_owned(),
        });
    }
    // `StoreIndex::parse`, NOT `Header::decode`, and the difference is a hole this
    // code had. `Header::decode` checks magic, version, page size and geometry and
    // says so in its own doc comment: "This does not verify `root_hash` — it
    // cannot, since the bytes the root covers have not been read yet. A header
    // that decodes is a header that is well-formed, not one that is trusted;
    // `StoreIndex::parse` is where trust starts." Here the whole store IS in hand,
    // so there is no excuse for stopping at the header — and stopping there meant
    // a store with a corrupted index, signed with a key this appliance accepts,
    // would have been written to the partition. The VMM would then have refused a
    // partition THIS component damaged, which is the exact "half a store is worse
    // than no store" failure the buffer-then-decide ordering exists to prevent.
    let index = cryogen_format::StoreIndex::parse(index)
        .map_err(|e| PushRejection::NotAStore { why: format!("{e}") })?;
    let total = index.header().total_len();
    if total != got_size {
        return Err(PushRejection::StoreLenMismatch { header: total, got: got_size });
    }
    // The same rule the READER applies, from the same crate, rather than a second
    // "does it fit" written here: the component that puts a store in a partition
    // and the component that reads it out must not be able to disagree about what
    // fits.
    guest_store_locate::store_len_within_partition(total, partition_len)
        .map_err(|_| PushRejection::DoesNotFit { store: total, partition: partition_len })?;
    Ok(())
}

/// The store's `root_hash` as lowercase hex, for the acceptance marker.
///
/// Reported rather than the sha256 of the bytes, because `root_hash` is what the
/// READER prints when it later opens this partition
/// (`UEFI-CERISE-CRYO-1: ... root_hash=...`). Two components naming the same
/// content by the same name is what lets one run's push and a later run's boot be
/// tied together by something neither of them chose.
pub fn root_hash_hex(store: &[u8]) -> Option<String> {
    cryogen_format::Header::decode(store)
        .ok()
        .map(|h| cerise_signing::to_hex(&h.root_hash))
}

// ==========================================================================================
#[cfg(test)]
mod tests {
    use super::*;

    const SEED: [u8; 32] = [42u8; 32];

    fn pk() -> [u8; 32] {
        cerise_signing::public_from_seed(&SEED)
    }

    /// A REAL `.cryostore`, produced by the format crate's own packer rather than
    /// hand-rolled here.
    ///
    /// A fixture only this file agrees with proves nothing, and a store is exactly
    /// the kind of structure that is easy to fake into passing one's own parser.
    /// `pack` is the same code path the host `cryostore` tool uses.
    fn a_store() -> Vec<u8> {
        const PS: usize = cryogen_format::PAGE_SIZE;
        let page = |b: u8| vec![b; PS];
        let mut packer = cryogen_format::Packer::new(16 * PS as u64);
        // Two distinct non-zero pages plus a repeat, so the pack deduplicates and
        // the store is not a copy of the disk it came from. `finish()` yields only
        // the index prefix; the novel pages are appended after it, exactly the way
        // the `cryostore` CLI assembles a store.
        let mut body = Vec::new();
        for (index, bytes) in [(0u64, page(0xAA)), (1, page(0xBB)), (2, page(0xAA))] {
            if let cryogen_format::Disposition::Novel(_) =
                packer.add_page(index, &bytes).expect("pack a page")
            {
                body.extend_from_slice(&bytes);
            }
        }
        let mut out = packer.finish();
        out.extend_from_slice(&body);
        out
    }

    fn signed(store: &[u8]) -> StoreManifest {
        sign_manifest(&SEED, store)
    }

    // --- the instrument can go green --------------------------------------------------

    #[test]
    fn a_genuine_store_is_accepted() {
        let store = a_store();
        assert_eq!(accept_store(&signed(&store), Some(&pk()), &store, 16 << 20), Ok(()));
    }

    #[test]
    fn the_manifest_round_trips_through_json() {
        // The receiver parses JSON off the wire, so the signed bytes must survive
        // that.
        let store = a_store();
        let m = signed(&store);
        let back: StoreManifest = serde_json::from_slice(&serde_json::to_vec(&m).unwrap()).unwrap();
        assert_eq!(back, m);
        assert_eq!(accept_store(&back, Some(&pk()), &store, 16 << 20), Ok(()));
    }

    #[test]
    fn a_store_smaller_than_its_partition_is_accepted_and_equal_is_too() {
        // The partition is sized by whoever partitioned the disk, never by the
        // store later written into it, so "smaller" is the normal case. Exact
        // equality would reject every correctly-sized partition.
        let store = a_store();
        let m = signed(&store);
        assert_eq!(accept_store(&m, Some(&pk()), &store, 16 << 20), Ok(()));
        assert_eq!(accept_store(&m, Some(&pk()), &store, store.len() as u64), Ok(()));
    }

    // --- and it can go red, on every axis it claims ------------------------------------

    #[test]
    fn a_missing_key_fails_closed() {
        // Deliberately UNLIKE pkg_resolver's graceful absence: there, no key means
        // "honour only the trusted in-image base index", a safe subset. Here it
        // would mean "write whatever arrived to the disk a guest boots from".
        let store = a_store();
        assert_eq!(
            accept_store(&signed(&store), None, &store, 16 << 20),
            Err(PushRejection::NoPubkey)
        );
    }

    #[test]
    fn an_unsigned_manifest_parses_but_is_never_honoured() {
        let store = a_store();
        let legacy = format!(r#"{{"sha256":"{}","size":{}}}"#, sha256_hex(&store), store.len());
        let m: StoreManifest = serde_json::from_str(&legacy).expect("must parse");
        assert_eq!(m.signature, "");
        assert_eq!(accept_store(&m, Some(&pk()), &store, 16 << 20), Err(PushRejection::Unsigned));
    }

    #[test]
    fn a_pusher_with_their_own_key_is_refused() {
        // THE case the whole signature exists for. The pusher recomputes a
        // perfectly internally-consistent manifest for their own payload and signs
        // it with a keypair they generated. Every field agrees with every other
        // field; only the key is different.
        let store = a_store();
        let forged = sign_manifest(&[9u8; 32], &store);
        assert_eq!(forged.sha256, sha256_hex(&store), "the forgery is internally consistent");
        assert_eq!(
            accept_store(&forged, Some(&pk()), &store, 16 << 20),
            Err(PushRejection::BadSignature),
        );
    }

    #[test]
    fn a_tampered_signature_is_refused() {
        // The exact payload the tamper gate pushes, produced the same way
        // `guest_store_signer --tamper` produces it: one hex character moved.
        let store = a_store();
        let mut m = signed(&store);
        let mut sig = m.signature.into_bytes();
        sig[0] = if sig[0] == b'0' { b'1' } else { b'0' };
        m.signature = String::from_utf8(sig).unwrap();
        assert_eq!(
            accept_store(&m, Some(&pk()), &store, 16 << 20),
            Err(PushRejection::BadSignature)
        );
    }

    #[test]
    fn every_signed_field_is_actually_covered() {
        // A signature that covered only some fields would still pass every test
        // above. Move each in turn and require the check to stop passing.
        let store = a_store();
        for mutate in [
            (|m: &mut StoreManifest| m.size += 1) as fn(&mut StoreManifest),
            |m: &mut StoreManifest| m.sha256 = sha256_hex(b"different"),
        ] {
            let mut m = signed(&store);
            mutate(&mut m);
            assert!(!signature_checks_out(&m, &pk()), "a moved field must break it: {m:?}");
        }
    }

    #[test]
    fn a_substituted_payload_under_a_genuine_manifest_is_refused_on_size_then_on_digest() {
        let store = a_store();
        let m = signed(&store);
        let mut evil = vec![0xEEu8; store.len() + 1];
        assert_eq!(
            accept_store(&m, Some(&pk()), &evil, 16 << 20),
            Err(PushRejection::SizeMismatch { manifest: m.size, got: evil.len() as u64 }),
        );
        // Padded to the exact signed length, so the size check cannot be what
        // catches it, and the signed digest is.
        evil.truncate(store.len());
        assert_eq!(
            accept_store(&m, Some(&pk()), &evil, 16 << 20).unwrap_err().token(),
            "hash-mismatch",
        );
    }

    #[test]
    fn bytes_that_are_not_a_store_are_refused_by_the_header_and_not_by_the_signature() {
        // The signature is GENUINE and is over these very bytes, so it cannot be
        // what rejects them. This is the case that proves the header check is a
        // check and not decoration — and it is what the "wrong file was signed"
        // gate pushes.
        let junk = vec![0xA5u8; 36_864];
        let m = signed(&junk);
        assert!(signature_checks_out(&m, &pk()), "the manifest really is genuine");
        let r = accept_store(&m, Some(&pk()), &junk, 16 << 20).unwrap_err();
        assert_eq!(r.token(), "not-a-store", "{r}");
    }

    #[test]
    fn a_signed_store_with_a_corrupted_index_is_refused() {
        // THE case a header-only check let through, and the one that matters
        // most: this is a real store, of the right length, signed with the right
        // key over exactly these bytes. Only its `root_hash` disagrees with the
        // index under it.
        //
        // `Header::decode` accepts it — its own doc comment says it cannot check
        // `root_hash` — so a receiver that stopped there would have written a
        // damaged store to the partition a guest boots from, and the VMM would
        // then have refused a partition this component damaged.
        let store = a_store();
        let mut corrupt = store.clone();
        let slots_off = cryogen_format::Header::decode(&store).unwrap().slots_off as usize;
        corrupt[slots_off] ^= 1; // one bit of one slot id
        assert_eq!(corrupt.len(), store.len(), "the corruption changes no length");
        assert!(
            cryogen_format::Header::decode(&corrupt).is_ok(),
            "the header still decodes, which is exactly why the header is not enough",
        );
        let m = signed(&corrupt);
        assert!(signature_checks_out(&m, &pk()), "the manifest really is genuine");
        let r = accept_store(&m, Some(&pk()), &corrupt, 16 << 20).unwrap_err();
        assert_eq!(r.token(), "not-a-store", "{r}");
        assert!(format!("{r}").contains("root_hash"), "the reason must name it: {r}");
    }

    #[test]
    fn a_zero_length_push_is_refused() {
        let m = signed(b"");
        assert_eq!(accept_store(&m, Some(&pk()), b"", 16 << 20).unwrap_err().token(), "not-a-store");
    }

    #[test]
    fn a_truncated_store_re_signed_for_its_truncation_is_still_refused() {
        // Steps 1-4 pass BY CONSTRUCTION here: the pusher truncated the store and
        // then signed the truncated bytes, so the digest and the size agree with
        // what arrived. Only the store's own declared length catches it, which is
        // why that check is not redundant with the signed size.
        let store = a_store();
        let short = store[..store.len() - cryogen_format::PAGE_SIZE].to_vec();
        let m = signed(&short);
        assert!(signature_checks_out(&m, &pk()));
        match accept_store(&m, Some(&pk()), &short, 16 << 20).unwrap_err() {
            PushRejection::StoreLenMismatch { header, got } => {
                assert_eq!(header, store.len() as u64);
                assert_eq!(got, short.len() as u64);
            }
            other => panic!("expected StoreLenMismatch, got {other}"),
        }
    }

    #[test]
    fn a_padded_store_re_signed_for_its_padding_is_still_refused() {
        // The other direction: a store followed by extra bytes. Without the
        // length equality this would be accepted and the partition would end up
        // holding a store plus a tail of someone else's choosing.
        let store = a_store();
        let mut padded = store.clone();
        padded.extend_from_slice(&[0u8; 4096]);
        let m = signed(&padded);
        assert!(signature_checks_out(&m, &pk()));
        assert_eq!(
            accept_store(&m, Some(&pk()), &padded, 16 << 20).unwrap_err().token(),
            "store-length-mismatch",
        );
    }

    #[test]
    fn a_store_larger_than_the_partition_is_refused() {
        let store = a_store();
        let m = signed(&store);
        let too_small = (store.len() - 1) as u64;
        match accept_store(&m, Some(&pk()), &store, too_small).unwrap_err() {
            PushRejection::DoesNotFit { store: s, partition } => {
                assert_eq!(s, store.len() as u64);
                assert_eq!(partition, too_small);
            }
            other => panic!("expected DoesNotFit, got {other}"),
        }
    }

    #[test]
    fn a_malformed_digest_is_refused_before_it_is_used() {
        let store = a_store();
        for bad in ["", "ZZ", &"A".repeat(64), &"a".repeat(63)] {
            let mut m = signed(&store);
            m.sha256 = bad.to_string();
            // Re-signed, so the SIGNATURE is not what rejects it — the shape is.
            let sig = cerise_signing::sign(&SEED, &signing_message(&m.sha256, m.size));
            m.signature = cerise_signing::to_hex(&sig);
            assert_eq!(
                accept_store(&m, Some(&pk()), &store, 16 << 20),
                Err(PushRejection::MalformedDigest),
                "digest {bad:?} must be refused on shape",
            );
        }
    }

    #[test]
    fn a_guest_store_signature_cannot_be_replayed_from_another_domain() {
        // Domain separation, concretely: the same field values signed under the
        // OS-image or package-index domain must not check out here.
        let store = a_store();
        let sha = sha256_hex(&store);
        let size = store.len().to_string();
        let ours = signing_message(&sha, store.len() as u64);
        for foreign in ["cerise-ota-image-v2", "cerise-pkg-index-v2"] {
            let theirs = cerise_signing::domain_message(foreign, &[&sha, &size]);
            assert_ne!(ours, theirs);
            let cross = cerise_signing::sign(&SEED, &theirs);
            assert!(
                !cerise_signing::verify(&pk(), &ours, &cross),
                "a signature made under {foreign} must not check out as a guest store",
            );
        }
    }

    #[test]
    fn every_rejection_has_a_distinct_token() {
        let all = [
            PushRejection::NoPubkey,
            PushRejection::Unsigned,
            PushRejection::MalformedDigest,
            PushRejection::BadSignature,
            PushRejection::SizeMismatch { manifest: 1, got: 2 },
            PushRejection::HashMismatch { manifest: "a".into(), got: "b".into() },
            PushRejection::NotAStore { why: "x".into() },
            PushRejection::StoreLenMismatch { header: 1, got: 2 },
            PushRejection::DoesNotFit { store: 1, partition: 2 },
        ];
        let mut seen: Vec<&str> = all.iter().map(|e| e.token()).collect();
        seen.sort_unstable();
        let n = seen.len();
        seen.dedup();
        assert_eq!(seen.len(), n);
    }

    #[test]
    fn the_reported_root_hash_is_the_headers_own() {
        let store = a_store();
        let hex = root_hash_hex(&store).expect("a real store has one");
        assert_eq!(hex.len(), 64);
        let header = cryogen_format::Header::decode(&store).unwrap();
        assert_eq!(hex, cerise_signing::to_hex(&header.root_hash));
        // And a payload that is not a store has none to report.
        assert_eq!(root_hash_hex(&[0u8; 36_864]), None);
    }
}

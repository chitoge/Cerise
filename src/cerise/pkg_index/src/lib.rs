// Cerise packages: pkg_index — the pure, host-testable logic shared by the
// package resolver (read side) and the network fetcher (write side) for a PERSISTENT, UPDATABLE
// package index.
//
// shipped a read-only, build-time name->merkle index staged in bootfs. makes packages
// updatable by layering a PERSISTENT dynamic index (a small JSON file the fetcher writes atomically
// onto the fxfs `data` volume) OVER that bootfs base index. Resolution consults the dynamic index
// first and falls back to the base index — so a newly-fetched package "shadows" its base entry and
// survives reboot without re-fetching.
//
// This crate is deliberately free of Fuchsia-target dependencies (no zx / fuchsia-async / fdio) so
// the layering, identity, and merkle-verification rules are unit-tested on the HOST. The on-target
// I/O (BlobReader reads, atomic-rename writes) lives in pkg_resolver / pkg_fetcher.

use fuchsia_hash::Hash;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::str::FromStr as _;

/// Domain tag for the ed25519 signature over a dynamic-index entry (see `signing_message`). Unique to
/// this context so a package-entry signature can never be replayed as any other signed object.
pub const INDEX_SIGN_DOMAIN: &str = "cerise-pkg-index-v2";

/// One entry in the persistent dynamic index: a package NAME bound to the meta.far merkle (the
/// package hash) of a specific VERSION. The merkle is stored as its 64-hex string (the on-disk,
/// human-auditable form); it is parsed to a `Hash` on resolution so a malformed entry fails loud.
///
/// (signed index): the entry additionally carries a monotonic `counter` and an ed25519
/// `signature` (hex) produced by the trusted build-time signer over the entry's CANONICAL bytes
/// (`signing_message`). The resolver honors ONLY entries whose signature verifies against the
/// embedded public key — so a compromised on-device writer (pkg_fetcher) cannot introduce a package.
/// Both fields default (an unsigned/legacy entry parses but is never honored — its signature does not
/// verify), so the on-disk format is forward/backward tolerant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexEntry {
    pub name: String,
    pub version: String,
    pub merkle: String,
    /// Monotonic anti-rollback counter, set by the signer and COVERED by the signature. The fetcher
    /// rejects a fetched entry whose counter is <= the currently-installed entry's counter.
    #[serde(default)]
    pub counter: u64,
    /// ed25519 signature (128-hex) over `signing_message`, produced by the build-time private key.
    /// Empty for an unsigned/legacy entry (which the resolver will not honor).
    #[serde(default)]
    pub signature: String,
}

/// The CANONICAL bytes an index entry's signature covers: domain-separated `{name, version, merkle,
/// counter}`. The signer (host tool) and the verifier (resolver/fetcher) MUST agree byte-for-byte, so
/// this is the single source of truth. The `signature` field itself is NOT part of the signed bytes.
pub fn signing_message(name: &str, version: &str, merkle: &str, counter: u64) -> Vec<u8> {
    let counter = counter.to_string();
    cerise_signing::domain_message(INDEX_SIGN_DOMAIN, &[name, version, merkle, &counter])
}

/// Sign an entry's canonical bytes with the build-time seed, returning a fully-populated, honorable
/// `IndexEntry`. Build/host-time only (the private seed never ships to a device).
pub fn sign_entry(seed: &[u8; 32], name: &str, version: &str, merkle: &str, counter: u64) -> IndexEntry {
    let msg = signing_message(name, version, merkle, counter);
    let sig = cerise_signing::sign(seed, &msg);
    IndexEntry {
        name: name.to_string(),
        version: version.to_string(),
        merkle: merkle.to_string(),
        counter,
        signature: cerise_signing::to_hex(&sig),
    }
}

/// Verify one entry's signature against `pubkey`. Returns false on a malformed/empty signature or any
/// tamper. This is the trust boundary the resolver holds: an entry that does not verify is dropped.
pub fn verify_entry(entry: &IndexEntry, pubkey: &[u8; 32]) -> bool {
    let Some(sig) = cerise_signing::from_hex::<64>(&entry.signature) else {
        return false;
    };
    let msg = signing_message(&entry.name, &entry.version, &entry.merkle, entry.counter);
    cerise_signing::verify(pubkey, &msg, &sig)
}

/// Anti-rollback: a newly-FETCHED entry may only replace an on-disk one if its counter is strictly
/// greater. Blocks replay-downgrade over the fetch path (an attacker re-serving an old, validly-signed
/// entry to reintroduce a fixed package). It does NOT protect against offline disk rollback (physically
/// resetting the on-disk index) — there is no hardware monotonic counter under QEMU; that gap is
/// documented, not closed.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("rollback rejected: fetched counter {fetched} is not greater than installed counter {installed}")]
pub struct RollbackError {
    pub fetched: u64,
    pub installed: u64,
}

pub fn check_counter_monotonic(fetched: u64, installed: Option<u64>) -> Result<(), RollbackError> {
    match installed {
        Some(installed) if fetched <= installed => Err(RollbackError { fetched, installed }),
        _ => Ok(()),
    }
}

/// The persistent dynamic package index — a flat, name-keyed JSON document written atomically onto
/// the fxfs `data` volume. At most one entry per name (an upsert replaces any prior binding), so a
/// re-registration is an UPDATE, not an append. Ordering is stable (sorted by name) so the on-disk
/// bytes are deterministic for a given logical state.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DynamicIndex {
    #[serde(default)]
    pub entries: Vec<IndexEntry>,
}

#[derive(Debug, thiserror::Error)]
pub enum DynamicIndexParseError {
    #[error("invalid dynamic-index JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("dynamic index contains duplicate package name {0:?}")]
    DuplicateName(String),
}

/// Where a resolved meta.far merkle came from — used by the resolver to report which layer served a
/// package (dynamic shadowing base is the observable proof that the update took effect).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Source {
    /// Served from the persistent dynamic index (a fetched/updated package).
    Dynamic { version: String },
    /// Served from the build-time bootfs base index (the shipped-in-image package).
    Base,
}

/// A resolved package: the meta.far merkle plus which layer it came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolved {
    pub merkle: Hash,
    pub source: Source,
}

/// Errors that make resolution fail LOUD rather than silently degrade.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ResolveError {
    #[error("dynamic index entry for {name:?} has a malformed merkle {merkle:?}")]
    MalformedDynamicMerkle { name: String, merkle: String },
}

/// Errors that make identity verification (verified-exec) fail LOUD.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("package identity mismatch: index binds name {requested:?} but the meta.far declares meta/package name {actual:?}")]
pub struct IdentityError {
    pub requested: String,
    pub actual: String,
}

/// The fetch-path pre-install integrity error: downloaded bytes did not hash to the claimed merkle.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("blob integrity mismatch: downloaded bytes hash to {got}, claimed {claimed}")]
pub struct MerkleMismatch {
    pub claimed: Hash,
    pub got: Hash,
}

/// The fetch-path registration integrity error: a signed index entry names a different meta.far
/// than the one just installed. This check must happen before mutating or persisting the dynamic
/// index, otherwise a failed update can leave a durable entry pointing somewhere unexpected.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error(
    "signed index entry merkle {entry_merkle:?} does not match installed meta.far {installed_meta_far}"
)]
pub struct EntryMerkleMismatch {
    pub entry_merkle: String,
    pub installed_meta_far: Hash,
}

impl DynamicIndex {
    /// Parse the on-disk JSON. An empty/missing file is the caller's concern (treat as `default()`).
    pub fn parse(bytes: &[u8]) -> Result<Self, DynamicIndexParseError> {
        let index: Self = serde_json::from_slice(bytes)?;
        let mut names = HashSet::new();
        for entry in &index.entries {
            if !names.insert(entry.name.as_str()) {
                return Err(DynamicIndexParseError::DuplicateName(entry.name.clone()));
            }
        }
        Ok(index)
    }

    /// Serialize to the canonical on-disk bytes (sorted by name, pretty). Deterministic for a given
    /// logical state so an atomic replace is byte-reproducible.
    pub fn to_json(&self) -> Vec<u8> {
        let mut sorted = self.clone();
        sorted.entries.sort_by(|a, b| a.name.cmp(&b.name));
        let mut v = serde_json::to_vec_pretty(&sorted).expect("DynamicIndex serialize");
        v.push(b'\n');
        v
    }

    /// Look up a name's entry, if present.
    pub fn get(&self, name: &str) -> Option<&IndexEntry> {
        self.entries.iter().find(|e| e.name == name)
    }

    /// UPSERT by name: a new registration for an existing name REPLACES it (an update), otherwise it
    /// is added. This is what makes a package "updatable" — the newest registration wins.
    pub fn upsert(&mut self, entry: IndexEntry) {
        if let Some(slot) = self.entries.iter_mut().find(|e| e.name == entry.name) {
            *slot = entry;
        } else {
            self.entries.push(entry);
        }
    }
}

/// Atomically with respect to the in-memory index, check that `entry` names the meta.far just
/// installed and then upsert it. A mismatch returns before touching `dynamic`, so callers can
/// safely persist the index only after this succeeds. Callers that intentionally exercise an
/// invalid identity binding must use the lower-level `upsert` API explicitly; this integrity API
/// never has a bypass mode.
pub fn upsert_if_matches_installed_meta_far(
    dynamic: &mut DynamicIndex,
    entry: IndexEntry,
    installed_meta_far: &Hash,
) -> Result<(), EntryMerkleMismatch> {
    if entry.merkle != installed_meta_far.to_string() {
        return Err(EntryMerkleMismatch {
            entry_merkle: entry.merkle,
            installed_meta_far: *installed_meta_far,
        });
    }
    dynamic.upsert(entry);
    Ok(())
}

/// Layered resolution: the dynamic index SHADOWS the bootfs base index. Returns the meta.far merkle
/// and its source, dynamic-first then base, or `None` if neither layer knows the name. A dynamic
/// entry with a malformed merkle is a LOUD error (never a silent fall-through to base).
pub fn resolve(
    name: &str,
    dynamic: &DynamicIndex,
    base: &HashMap<String, Hash>,
) -> Result<Option<Resolved>, ResolveError> {
    if let Some(entry) = dynamic.get(name) {
        let merkle = Hash::from_str(&entry.merkle).map_err(|_| ResolveError::MalformedDynamicMerkle {
            name: name.to_string(),
            merkle: entry.merkle.clone(),
        })?;
        return Ok(Some(Resolved { merkle, source: Source::Dynamic { version: entry.version.clone() } }));
    }
    Ok(base.get(name).copied().map(|merkle| Resolved { merkle, source: Source::Base }))
}

/// Return the subset of a dynamic index whose entries carry a VALID signature under `pubkey`, plus
/// the list of names whose (present) entry was DROPPED for an invalid/absent signature. The resolver
/// applies this BEFORE layering: only signature-honored entries shadow base; a dropped entry is as if
/// it were not there (falls through to base, or to not-found). This makes the RESOLVER the trust
/// boundary — a compromised writer that appends an unsigned entry gains nothing.
pub fn filter_signed(dynamic: &DynamicIndex, pubkey: &[u8; 32]) -> (DynamicIndex, Vec<String>) {
    let mut kept = DynamicIndex::default();
    let mut dropped = Vec::new();
    for entry in &dynamic.entries {
        if verify_entry(entry, pubkey) {
            kept.entries.push(entry.clone());
        } else {
            dropped.push(entry.name.clone());
        }
    }
    (kept, dropped)
}

/// Package GARBAGE-COLLECTION live set — the EFFECTIVE meta.far merkle per package name, mirroring
/// exactly what the resolver would serve: the (signature-filtered) dynamic index SHADOWS base. This is
/// the crux of a correct GC: the naive union {base ∪ dynamic} would keep v1's blobs alive forever
/// (base still names v1), so a post-update sweep would never reclaim anything. Instead, for each name
/// we take the dynamic (signed) merkle if present, else the base merkle — so an updated package's OLD
/// (shadowed) meta.far becomes unreferenced and collectible, while a NON-updated base package stays
/// live. Returns name -> effective meta.far hash. Malformed dynamic merkle fails loud (never silently
/// keeps stale blobs).
///
/// The caller then walks each effective meta.far's content-blob closure (package_directory's
/// `external_file_hashes`) to expand this into the full live BLOB set; everything else in the store is
/// unreferenced and may be unlinked.
pub fn effective_meta_fars(
    signed_dynamic: &DynamicIndex,
    base: &HashMap<String, Hash>,
) -> Result<HashMap<String, Hash>, ResolveError> {
    let mut live = HashMap::new();
    let names: HashSet<&str> =
        base.keys().map(String::as_str).chain(signed_dynamic.entries.iter().map(|e| e.name.as_str())).collect();
    for name in names {
        if let Some(resolved) = resolve(name, signed_dynamic, base)? {
            live.insert(name.to_string(), resolved.merkle);
        }
    }
    Ok(live)
}

/// Verified-exec IDENTITY binding: the meta.far a name resolves to MUST declare that same name in
/// its own meta/package. Content-addressing already guarantees the served blob IS the merkle the
/// index names (fxfs page-in verifies it), so a merkle re-compare is a tautology — the real thing an
/// index can lie about is IDENTITY: pointing a name at a DIFFERENT package's (valid) meta.far. This
/// rejects that.
pub fn verify_identity(requested_name: &str, far_package_name: &str) -> Result<(), IdentityError> {
    if requested_name == far_package_name {
        Ok(())
    } else {
        Err(IdentityError { requested: requested_name.to_string(), actual: far_package_name.to_string() })
    }
}

/// Fetch-path PRE-INSTALL integrity: bytes downloaded over the network MUST hash to the merkle the
/// index/manifest claims before they are written to the blob volume. (fxfs re-verifies on the write
/// path too, but verifying here fails fast and keeps tampered bytes out of the store entirely.)
pub fn verify_downloaded_blob(bytes: &[u8], claimed: &Hash) -> Result<(), MerkleMismatch> {
    let got = fuchsia_merkle::root_from_slice(bytes);
    if &got == claimed {
        Ok(())
    } else {
        Err(MerkleMismatch { claimed: *claimed, got })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(byte: u8) -> Hash {
        Hash::from([byte; 32])
    }

    fn base_index() -> HashMap<String, Hash> {
        let mut m = HashMap::new();
        m.insert("pkg_hello".to_string(), h(0x11));
        m
    }

    // A fixed test signing seed (NOT the build key) for the signed-index tests.
    const TEST_SEED: [u8; 32] = [42u8; 32];

    // An UNSIGNED entry (counter 0, empty signature) — parses but is never honored by the resolver.
    fn ent(name: &str, version: &str, merkle: &str) -> IndexEntry {
        IndexEntry {
            name: name.into(),
            version: version.into(),
            merkle: merkle.into(),
            counter: 0,
            signature: String::new(),
        }
    }

    #[test]
    fn base_only_resolves_from_base() {
        let base = base_index();
        let dynamic = DynamicIndex::default();
        let r = resolve("pkg_hello", &dynamic, &base).unwrap().unwrap();
        assert_eq!(r.merkle, h(0x11));
        assert_eq!(r.source, Source::Base);
        // Unknown name resolves nowhere.
        assert!(resolve("nope", &dynamic, &base).unwrap().is_none());
    }

    #[test]
    fn dynamic_shadows_base_for_same_name() {
        // The core updatability rule: a dynamic entry for a name WINS over the base entry.
        let base = base_index();
        let mut dynamic = DynamicIndex::default();
        dynamic.upsert(ent("pkg_hello", "2", &h(0x22).to_string()));
        let r = resolve("pkg_hello", &dynamic, &base).unwrap().unwrap();
        assert_eq!(r.merkle, h(0x22), "dynamic v2 must shadow base v1");
        assert_eq!(r.source, Source::Dynamic { version: "2".to_string() });
    }

    #[test]
    fn upsert_is_update_not_append() {
        let mut dynamic = DynamicIndex::default();
        dynamic.upsert(ent("p", "1", &h(0x01).to_string()));
        dynamic.upsert(ent("p", "2", &h(0x02).to_string()));
        assert_eq!(dynamic.entries.len(), 1, "re-registering a name replaces, not appends");
        assert_eq!(dynamic.get("p").unwrap().version, "2");
    }

    #[test]
    fn dynamic_index_json_roundtrips_and_is_deterministic() {
        let mut a = DynamicIndex::default();
        a.upsert(ent("b", "1", &h(0x0b).to_string()));
        a.upsert(ent("a", "1", &h(0x0a).to_string()));
        let bytes = a.to_json();
        let back = DynamicIndex::parse(&bytes).unwrap();
        // Parsed-back set equals the logical state.
        assert_eq!(back.get("a").unwrap().merkle, h(0x0a).to_string());
        assert_eq!(back.get("b").unwrap().merkle, h(0x0b).to_string());
        // Canonical ordering: same logical state built in a different insert order => same bytes.
        let mut c = DynamicIndex::default();
        c.upsert(ent("a", "1", &h(0x0a).to_string()));
        c.upsert(ent("b", "1", &h(0x0b).to_string()));
        assert_eq!(a.to_json(), c.to_json(), "on-disk bytes are deterministic for a logical state");
    }

    #[test]
    fn empty_index_parses() {
        assert_eq!(DynamicIndex::parse(b"{}").unwrap(), DynamicIndex::default());
        assert_eq!(DynamicIndex::parse(br#"{"entries":[]}"#).unwrap(), DynamicIndex::default());
    }

    #[test]
    fn duplicate_names_are_rejected_while_parsing() {
        let json = format!(
            r#"{{"entries":[{{"name":"p","version":"1","merkle":"{}"}},{{"name":"p","version":"2","merkle":"{}"}}]}}"#,
            h(0x01),
            h(0x02),
        );
        let error = DynamicIndex::parse(json.as_bytes()).unwrap_err();
        assert!(matches!(error, DynamicIndexParseError::DuplicateName(name) if name == "p"));
    }

    #[test]
    fn malformed_dynamic_merkle_is_loud() {
        let base = base_index();
        let mut dynamic = DynamicIndex::default();
        dynamic.upsert(ent("pkg_hello", "2", "not-a-hash"));
        let err = resolve("pkg_hello", &dynamic, &base).unwrap_err();
        assert!(matches!(err, ResolveError::MalformedDynamicMerkle { .. }));
    }

    #[test]
    fn identity_binding_accepts_match_rejects_mismatch() {
        // The genuine verified-exec check: a name must resolve to a meta.far that declares that name.
        assert!(verify_identity("pkg_hello", "pkg_hello").is_ok());
        let err = verify_identity("pkg_hello_evil", "pkg_hello").unwrap_err();
        assert_eq!(err.requested, "pkg_hello_evil");
        assert_eq!(err.actual, "pkg_hello");
    }

    #[test]
    fn fetch_path_rejects_tampered_bytes() {
        // Non-redundant network-tamper check: bytes whose merkle != claimed are rejected BEFORE install.
        let good = b"the-real-package-bytes";
        let merkle = fuchsia_merkle::root_from_slice(good);
        assert!(verify_downloaded_blob(good, &merkle).is_ok());

        let mut tampered = good.to_vec();
        tampered[0] ^= 0xff; // flip a byte in transit
        let err = verify_downloaded_blob(&tampered, &merkle).unwrap_err();
        assert_eq!(err.claimed, merkle);
        assert_ne!(err.got, merkle);
    }

    #[test]
    fn entry_merkle_mismatch_does_not_mutate_dynamic_index() {
        let mut dynamic = DynamicIndex::default();
        dynamic.upsert(ent("existing", "1", &h(0x01).to_string()));
        let before = dynamic.clone();
        let entry = sign_entry(&TEST_SEED, "pkg_hello", "2", &h(0x22).to_string(), 1);

        let err =
            upsert_if_matches_installed_meta_far(&mut dynamic, entry, &h(0x33)).unwrap_err();

        assert_eq!(err.entry_merkle, h(0x22).to_string());
        assert_eq!(err.installed_meta_far, h(0x33));
        assert_eq!(dynamic, before, "a merkle mismatch must leave the dynamic index unchanged");
    }

    #[test]
    fn entry_merkle_match_upserts() {
        let mut dynamic = DynamicIndex::default();
        let good = sign_entry(&TEST_SEED, "pkg_hello", "2", &h(0x22).to_string(), 1);
        upsert_if_matches_installed_meta_far(&mut dynamic, good, &h(0x22)).unwrap();
        assert_eq!(dynamic.get("pkg_hello").unwrap().merkle, h(0x22).to_string());
    }

    // ----: signed index ----

    #[test]
    fn signed_entry_verifies_and_tamper_is_rejected() {
        let pubkey = cerise_signing::public_from_seed(&TEST_SEED);
        let signed = sign_entry(&TEST_SEED, "pkg_hello", "2", &h(0x22).to_string(), 5);
        assert!(verify_entry(&signed, &pubkey), "a genuine signed entry verifies");

        // Tamper each covered field in turn — every one must break the signature.
        let mut t = signed.clone();
        t.merkle = h(0x33).to_string();
        assert!(!verify_entry(&t, &pubkey), "tampered merkle must not verify");
        let mut t = signed.clone();
        t.version = "3".into();
        assert!(!verify_entry(&t, &pubkey), "tampered version must not verify");
        let mut t = signed.clone();
        t.name = "pkg_evil".into();
        assert!(!verify_entry(&t, &pubkey), "tampered name must not verify");
        let mut t = signed.clone();
        t.counter = 6;
        assert!(!verify_entry(&t, &pubkey), "tampered counter must not verify");

        // An unsigned/legacy entry never verifies.
        assert!(!verify_entry(&ent("pkg_hello", "2", &h(0x22).to_string()), &pubkey));
        // A different key never verifies.
        let other = cerise_signing::public_from_seed(&[1u8; 32]);
        assert!(!verify_entry(&signed, &other));
    }

    #[test]
    fn filter_signed_keeps_only_valid_and_reports_dropped() {
        let pubkey = cerise_signing::public_from_seed(&TEST_SEED);
        let mut dynamic = DynamicIndex::default();
        dynamic.upsert(sign_entry(&TEST_SEED, "good", "1", &h(0x01).to_string(), 1));
        dynamic.upsert(ent("unsigned", "1", &h(0x02).to_string())); // no signature
        // A validly-shaped signature but for the WRONG bytes (signed then field-tampered).
        let mut forged = sign_entry(&TEST_SEED, "forged", "1", &h(0x03).to_string(), 1);
        forged.merkle = h(0x99).to_string();
        dynamic.upsert(forged);

        let (kept, dropped) = filter_signed(&dynamic, &pubkey);
        assert_eq!(kept.entries.len(), 1);
        assert_eq!(kept.entries[0].name, "good");
        assert!(dropped.contains(&"unsigned".to_string()));
        assert!(dropped.contains(&"forged".to_string()));
    }

    #[test]
    fn resolver_boundary_only_signed_dynamic_shadows_base() {
        // The security property: an UNSIGNED dynamic entry for a base name must NOT shadow base — the
        // resolver falls through to the (trusted, in-image) base merkle. A SIGNED one shadows.
        let pubkey = cerise_signing::public_from_seed(&TEST_SEED);
        let base = base_index(); // pkg_hello -> h(0x11)

        let mut dyn_unsigned = DynamicIndex::default();
        dyn_unsigned.upsert(ent("pkg_hello", "2", &h(0x22).to_string()));
        let (kept, _) = filter_signed(&dyn_unsigned, &pubkey);
        let r = resolve("pkg_hello", &kept, &base).unwrap().unwrap();
        assert_eq!(r.merkle, h(0x11), "unsigned dynamic entry must NOT shadow base");
        assert_eq!(r.source, Source::Base);

        let mut dyn_signed = DynamicIndex::default();
        dyn_signed.upsert(sign_entry(&TEST_SEED, "pkg_hello", "2", &h(0x22).to_string(), 1));
        let (kept, _) = filter_signed(&dyn_signed, &pubkey);
        let r = resolve("pkg_hello", &kept, &base).unwrap().unwrap();
        assert_eq!(r.merkle, h(0x22), "signed dynamic entry shadows base");
    }

    #[test]
    fn counter_blocks_rollback_over_fetch_path() {
        assert!(check_counter_monotonic(2, None).is_ok(), "first install: any counter accepted");
        assert!(check_counter_monotonic(3, Some(2)).is_ok(), "strictly greater accepted");
        assert!(check_counter_monotonic(2, Some(2)).is_err(), "equal counter is a replay: rejected");
        let err = check_counter_monotonic(1, Some(2)).unwrap_err();
        assert_eq!(err.fetched, 1);
        assert_eq!(err.installed, 2);
    }

    // ----: GC live-set (shadowing) ----

    #[test]
    fn effective_meta_fars_shadows_base_so_old_is_collectible() {
        // The GC crux: base still names pkg_hello -> v1, but the SIGNED dynamic index names v2. The
        // effective (live) meta.far is v2 ONLY — so v1's meta.far becomes unreferenced/collectible.
        let pubkey = cerise_signing::public_from_seed(&TEST_SEED);
        let mut base = HashMap::new();
        base.insert("pkg_hello".to_string(), h(0x11)); // v1
        base.insert("other_pkg".to_string(), h(0xaa)); // never updated -> must stay live

        let mut dynamic = DynamicIndex::default();
        dynamic.upsert(sign_entry(&TEST_SEED, "pkg_hello", "2", &h(0x22).to_string(), 1)); // v2
        let (signed, _) = filter_signed(&dynamic, &pubkey);

        let live = effective_meta_fars(&signed, &base).unwrap();
        assert_eq!(live.get("pkg_hello"), Some(&h(0x22)), "live meta.far is v2, not v1");
        assert_eq!(live.get("other_pkg"), Some(&h(0xaa)), "non-updated base package stays live");
        // v1's meta.far h(0x11) is NOT in the live set -> collectible.
        let live_hashes: HashSet<Hash> = live.values().copied().collect();
        assert!(!live_hashes.contains(&h(0x11)), "shadowed v1 meta.far must be collectible");
    }

    #[test]
    fn effective_meta_fars_unsigned_does_not_keep_v2_alive() {
        // If the dynamic entry is UNSIGNED, the resolver serves base (v1). GC must therefore keep v1
        // live — computed from the SAME signature-filtered view the resolver uses.
        let pubkey = cerise_signing::public_from_seed(&TEST_SEED);
        let mut base = HashMap::new();
        base.insert("pkg_hello".to_string(), h(0x11));
        let mut dynamic = DynamicIndex::default();
        dynamic.upsert(ent("pkg_hello", "2", &h(0x22).to_string())); // unsigned
        let (signed, _) = filter_signed(&dynamic, &pubkey);
        let live = effective_meta_fars(&signed, &base).unwrap();
        assert_eq!(live.get("pkg_hello"), Some(&h(0x11)), "unsigned entry: base v1 stays live");
    }
}

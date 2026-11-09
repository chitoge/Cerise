// Cerise packages: pkg_fetcher — the on-target driver that makes packages
// UPDATABLE over the network. It extends pkg_probe's role (provision-gate + fshost mount + blob
// ingest + launch trigger) with the update flow:
//
//   BOOT 1 (blank disk / empty dynamic index):
//     1. gate on the fxfs_provisioner, connect fshost's BlobCreator.
//     2. INGEST the BASE package (v1) blobs from its own /pkg (like pkg_probe).
//     3. bind pkg_hello_v1's Binder => component_manager resolves fuchsia-pkg://cerise/pkg_hello via
//        #pkg_resolver, which (dynamic index empty) serves the BASE index -> v1 launches from disk
//        blobs => CERISE-PKG-UPDATE-V1-LAUNCHED.
//     4. bring up netstack3 (discover NIC, DHCP DORA) and FETCH v2 over the network from the host
//        (10.0.2.2:<port>, plain HTTP/1 over std::net): v2's ingest manifest + every delivery-blob
//        payload. MERKLE-VERIFY each blob BEFORE install (network-tamper gate), then BlobCreator-write.
//     5. REGISTER "pkg_hello" v2 -> v2 meta.far merkle in the PERSISTENT dynamic index on the fxfs
//        data volume (atomic temp+rename). The dynamic entry now SHADOWS the base v1 entry.
//     6. bind pkg_hello_v2's Binder (a second instance of the SAME URL) => the resolver now serves
//        v2 from the dynamic index => CERISE-PKG-UPDATE-V2-LAUNCHED. The update took effect IN-BOOT.
//     7. verified-exec NEGATIVE: register a LYING entry (pkg_hello_evil -> v1's meta.far) and ask the
//        resolver to resolve it; the identity binding (meta/package name != requested name) rejects
//        it loudly => CERISE-PKG-UPDATE-IDENTITY-REJECT.
//
//   BOOT 2 (same disk, dynamic index already has pkg_hello v2):
//     - blobs + dynamic index persisted. SKIP the network entirely (CERISE-PKG-UPDATE-SKIP-FETCH), bind
//       pkg_hello_v2 => resolver serves v2 from the PERSISTENT dynamic index => CERISE-PKG-UPDATE-V2-LAUNCHED.
//       The host server observes ZERO connections on boot 2 — the not-refetched proof.
//
// Markers (serial): CERISE-PKG-UPDATE-FETCHER-READY, -V1-LAUNCHED (from v1), -FETCH-OK, -REGISTERED,
// -V2-LAUNCHED (from v2), -IDENTITY-REJECT (from resolver), -SKIP-FETCH, and CERISE-PKG-UPDATE-OK.
// Failure: CERISE-PKG-UPDATE-FETCHER-FAIL: <ctx>.

use anyhow::{anyhow, Context, Result};
use cerise_http_download::Limits as HttpLimits;
use cerise_network_bootstrap::BootstrapPolicy;
use cerise_network_bootstrap_fuchsia::{
    bootstrap, FuchsiaBootstrapConfig, InterfaceLifetime, Ipv4Configuration,
};
use fidl::endpoints::Proxy as _;
use fidl_fuchsia_component::{BinderMarker, BinderProxy};
use fidl_fuchsia_component_resolution as fresolution;
use fidl_fuchsia_fxfs::{BlobCreatorMarker, BlobCreatorProxy, BlobReaderMarker, BlobReaderProxy};
use fidl_fuchsia_io as fio;
use fuchsia_component::client::{
    connect_to_protocol, connect_to_protocol_at_dir_svc, connect_to_protocol_at_path,
};
use fuchsia_fs::directory::readdir;
use fuchsia_hash::Hash;
use futures::FutureExt as _;
use fxblob_storage::FxblobStorage;
use package_directory::RootDir;
use pkg_index::{
    check_counter_monotonic, effective_meta_fars, filter_signed,
    upsert_if_matches_installed_meta_far, verify_entry, DynamicIndex, IndexEntry,
};
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::io::Write as _;
use std::path::Path;
use std::str::FromStr as _;
use zx::sys::zx_debug_write;

const READY_FILE: &str = "/provisioned/ready";
const BLOB_DIR: &str = "/fshost-fs/blob";
// (GC): the fxfs blob volume's FLAT hash-named directory (svc siblings under /fshost-fs/blob/svc).
// fxfs serves it as a MUTABLE fuchsia.io directory; deleting an unreferenced blob is Directory.Unlink
// on its 64-hex name (the exact mechanism blobfs::Client::delete_blob uses). fshost re-exports it
// writable, so opening it PERM_WRITABLE grants the unlink.
const BLOB_ROOT: &str = "/fshost-fs/blob/root";
const DATA_DIR: &str = "/fshost-fs/data/root";
const DYNAMIC_INDEX: &str = "/fshost-fs/data/root/pkg_dynamic_index.json";
const DYNAMIC_INDEX_TMP: &str = "/fshost-fs/data/root/pkg_dynamic_index.json.tmp";
const BASE_MANIFEST: &str = "/pkg/blobs/manifest.json";
const PKG_ROOT: &str = "/pkg";
const PKG_NAME: &str = "pkg_hello";
// (signed index): the ed25519 PUBLIC key, staged into this component's bootfs /pkg. The
// fetcher verifies a downloaded signed entry BEFORE merging it (fail-fast); the resolver re-verifies
// at load (the real trust boundary). Both hold only the public key — never the private seed.
const PUBKEY_PATH: &str = "/pkg/keys/pkg_index_pub.ed25519";
// Host download endpoint. 10.0.2.2 is QEMU SLIRP's alias for the host loopback; the gate binds a
// plain-HTTP server on 127.0.0.1 at this fixed port (guest->host needs no hostfwd/guestfwd).
const HOST_ADDR: &str = "10.0.2.2:52099";
const MAX_MANIFEST_BYTES: usize = 1 << 20;
const MAX_INDEX_ENTRY_BYTES: usize = 64 << 10;
const MAX_BLOB_BYTES: usize = 64 << 20;
const DOWNLOAD_DIR: &str = "/fshost-fs/data/root/.pkg-fetcher-downloads";

fn emit(msg: &str) {
    let msg = format!("{msg}\n");
    unsafe {
        zx_debug_write(msg.as_ptr(), msg.len());
    }
}

async fn sleep(secs: f32) {
    fuchsia_async::Timer::new(fuchsia_async::MonotonicInstant::after(
        std::time::Duration::from_secs_f32(secs).into(),
    ))
    .await;
}

// The build-time ingest manifest (shared shape with pkg_builder / pkg_probe).
#[derive(Debug, Deserialize)]
struct IngestManifest {
    package: String,
    meta_far: BlobEntry,
    blobs: Vec<BlobEntry>,
}

#[derive(Debug, Deserialize, Clone)]
struct BlobEntry {
    pkg_path: String,
    #[serde(default)]
    runtime_path: String,
    merkle: String,
}

// ---------------------------------------------------------------------------------------------
// Provision gate + blob volume (adapted from pkg_probe).
// ---------------------------------------------------------------------------------------------

async fn await_provisioned() -> Result<()> {
    for _ in 0..120 {
        if fuchsia_fs::file::read_in_namespace(READY_FILE)
            .await
            .is_ok()
        {
            return Ok(());
        }
        sleep(5.0).await;
    }
    Err(anyhow!("provisioner readiness never observed"))
}

async fn connect_blob_creator() -> Result<BlobCreatorProxy> {
    let mut last = None;
    for _ in 0..120 {
        match fuchsia_fs::directory::open_in_namespace(BLOB_DIR, fio::PERM_READABLE) {
            Ok(blob_dir) => match connect_to_protocol_at_dir_svc::<BlobCreatorMarker>(&blob_dir) {
                Ok(creator) => match creator.needs_overwrite(&[0u8; 32]).await {
                    Ok(_) => return Ok(creator),
                    Err(e) => last = Some(anyhow!("BlobCreator probe failed: {e:?}")),
                },
                Err(e) => last = Some(anyhow!("connect BlobCreator: {e:?}")),
            },
            Err(e) => last = Some(anyhow!("open {BLOB_DIR}: {e:?}")),
        }
        sleep(5.0).await;
    }
    Err(last.unwrap_or_else(|| anyhow!("no BlobCreator attempts")))
}

/// Ingest the BASE package (v1) from this component's own /pkg — same as pkg_probe. Idempotent.
async fn ingest_base(creator: &BlobCreatorProxy) -> Result<IngestManifest> {
    let bytes = fuchsia_fs::file::read_in_namespace(BASE_MANIFEST)
        .await
        .map_err(|e| anyhow!("read base manifest {BASE_MANIFEST}: {e:?}"))?;
    let manifest: IngestManifest = serde_json::from_slice(&bytes).context("parse base manifest")?;
    let mut all: Vec<&BlobEntry> = vec![&manifest.meta_far];
    all.extend(manifest.blobs.iter());
    for entry in all {
        let hash = Hash::from_str(&entry.merkle)
            .map_err(|e| anyhow!("bad merkle {}: {e:?}", entry.merkle))?;
        let path = format!("{PKG_ROOT}/{}", entry.runtime_path);
        let data = fuchsia_fs::file::read_in_namespace(&path)
            .await
            .map_err(|e| anyhow!("read {path}: {e:?}"))?;
        cerise_fxblob_install::write_uncompressed(
            creator,
            hash.as_bytes()
                .try_into()
                .expect("fuchsia hash is 32 bytes"),
            std::io::Cursor::new(&data),
            data.len() as u64,
        )
        .await
        .with_context(|| format!("ingest base blob {}", entry.pkg_path))?;
    }
    Ok(manifest)
}

// ---------------------------------------------------------------------------------------------
// Dynamic index (persistent, on the fxfs data volume). Atomic replace: temp + rename.
// ---------------------------------------------------------------------------------------------

fn read_dynamic_index() -> Result<DynamicIndex> {
    match std::fs::read(DYNAMIC_INDEX) {
        Ok(bytes) => DynamicIndex::parse(&bytes)
            .with_context(|| format!("parse dynamic index {DYNAMIC_INDEX}")),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(DynamicIndex::default()),
        Err(error) => Err(error).with_context(|| format!("read dynamic index {DYNAMIC_INDEX}")),
    }
}

/// Persist the already-validated dynamic index with a crash-consistent atomic replace: write a temp
/// file, then rename it over the real path (fxfs implements fuchsia.io rename transactionally). A
/// crash leaves either the old or the new index, never a torn one.
///
/// Its entries were merged verbatim only after the signature, counter, and installed-meta.far
/// checks. The resolver re-verifies signatures at load; the fetcher never signs.
fn register_entry(index: &DynamicIndex) -> Result<()> {
    // Ensure the data root exists (fshost auto-mounts it; a first write just lands there).
    std::fs::create_dir_all(DATA_DIR).with_context(|| format!("create {DATA_DIR}"))?;
    let bytes = index.to_json();

    // Rename gives atomic publication, but it does not make either the temporary file's contents
    // or the directory entry durable. The live boot gate stops QEMU as soon as the success marker is
    // observed, so explicitly flush both layers before claiming registration succeeded.
    let mut temporary = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(DYNAMIC_INDEX_TMP)
        .with_context(|| format!("create temp dynamic index {DYNAMIC_INDEX_TMP}"))?;
    temporary
        .write_all(&bytes)
        .with_context(|| format!("write temp dynamic index {DYNAMIC_INDEX_TMP}"))?;
    temporary
        .sync_all()
        .with_context(|| format!("sync temp dynamic index {DYNAMIC_INDEX_TMP}"))?;
    drop(temporary);
    std::fs::rename(DYNAMIC_INDEX_TMP, DYNAMIC_INDEX)
        .with_context(|| format!("atomic rename {DYNAMIC_INDEX_TMP} -> {DYNAMIC_INDEX}"))?;
    std::fs::File::open(DATA_DIR)
        .and_then(|directory| directory.sync_all())
        .with_context(|| format!("sync dynamic index directory {DATA_DIR}"))?;
    Ok(())
}

/// Load the ed25519 public key (raw 32 bytes) staged into this component's bootfs /pkg.
fn load_pubkey() -> Result<[u8; 32]> {
    let bytes = std::fs::read(PUBKEY_PATH).with_context(|| format!("read pubkey {PUBKEY_PATH}"))?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("pubkey {PUBKEY_PATH} is {} bytes, expected 32", bytes.len()))
}

/// Download a signed dynamic-index entry from the host, verify its signature and counter, check it
/// against the just-installed meta.far when supplied, then persist it. The merkle check runs before
/// any dynamic-index mutation or write. `installed_meta_far: None` is only for the deliberate
/// verified-exec identity-negative entry. Returns the registered entry.
async fn fetch_verify_register_entry(
    path: &str,
    pubkey: &[u8; 32],
    installed_meta_far: Option<&Hash>,
) -> Result<IndexEntry> {
    let bytes = http_get(path, MAX_INDEX_ENTRY_BYTES)
        .await
        .with_context(|| format!("GET signed entry {path}"))?;
    let entry: IndexEntry = serde_json::from_slice(&bytes).context("parse signed entry")?;
    if !verify_entry(&entry, pubkey) {
        return Err(anyhow!("signed entry {path} failed signature verification"));
    }
    let mut index = read_dynamic_index()?;
    let installed = index.get(&entry.name).map(|e| e.counter);
    check_counter_monotonic(entry.counter, installed).context("anti-rollback counter check")?;
    if let Some(installed_meta_far) = installed_meta_far {
        upsert_if_matches_installed_meta_far(&mut index, entry.clone(), installed_meta_far)
            .context("signed entry merkle check against installed meta.far")?;
    } else {
        // Only the explicit verified-exec negative reaches this branch: it must
        // register a deliberately false name binding so the resolver can reject it.
        index.upsert(entry.clone());
    }
    register_entry(&index).context("register signed entry")?;
    Ok(entry)
}

// ---------------------------------------------------------------------------------------------
// Network bringup + bounded HTTP/1 download.
// ---------------------------------------------------------------------------------------------

async fn bring_up_network() -> Result<InterfaceLifetime> {
    let result = bootstrap(
        FuchsiaBootstrapConfig {
            interface_name: "pkg-eth0",
            ipv4: Ipv4Configuration::Dhcp {
                timeout_seconds: 45,
            },
            policy: BootstrapPolicy::once(),
            enable_before_address: true,
            observe_slaac: false,
            install_default_route: false,
            check_socket_provider: false,
        },
        None,
    )
    .await?;
    let ipv4 = result
        .ipv4
        .context("adapter returned no DHCP configuration")?;
    emit(&format!(
        "CERISE-PKG-UPDATE-DHCP-LEASE={}.{}.{}.{}/{}",
        ipv4.address[0], ipv4.address[1], ipv4.address[2], ipv4.address[3], ipv4.prefix_len
    ));
    result
        .lifetime
        .context("adapter unexpectedly reused an interface")
}

/// Bounded HTTP GET with connect/write, idle-read, and overall deadlines.
async fn http_get(path: &str, max_body_bytes: usize) -> Result<Vec<u8>> {
    cerise_http_download::get(HOST_ADDR, path, HttpLimits::new(max_body_bytes)).await
}

/// Download v2 over the network, MERKLE-VERIFY each blob before install, and write it into the blob
/// volume. Returns v2's meta.far merkle string (to register in the dynamic index).
async fn fetch_and_install_v2(creator: &BlobCreatorProxy) -> Result<String> {
    let manifest_bytes = http_get("/manifest.json", MAX_MANIFEST_BYTES)
        .await
        .context("GET /manifest.json")?;
    let manifest: IngestManifest =
        serde_json::from_slice(&manifest_bytes).context("parse fetched v2 manifest")?;
    if manifest.package != PKG_NAME {
        return Err(anyhow!(
            "fetched manifest package {:?} != {PKG_NAME:?}",
            manifest.package
        ));
    }
    let mut all: Vec<&BlobEntry> = vec![&manifest.meta_far];
    all.extend(manifest.blobs.iter());
    for entry in all {
        let claimed = Hash::from_str(&entry.merkle)
            .map_err(|e| anyhow!("bad v2 merkle {}: {e:?}", entry.merkle))?;
        let spool_path = Path::new(DOWNLOAD_DIR).join(format!("{}.part", entry.merkle));
        let mut blob = cerise_blob_download::download_verified(
            HOST_ADDR,
            &format!("/blob/{}", entry.merkle),
            HttpLimits::new(MAX_BLOB_BYTES),
            &spool_path,
            &claimed,
        )
        .await
        .with_context(|| format!("GET blob {}", entry.merkle))?;
        let blob_len = blob.len();
        // The spool is Merkle-verified before BlobCreator sees any payload bytes. Fxfs then
        // independently verifies the streamed Type-1 delivery on its write path.
        cerise_fxblob_install::write_uncompressed(
            creator,
            claimed
                .as_bytes()
                .try_into()
                .expect("fuchsia hash is 32 bytes"),
            blob.reader(),
            blob_len,
        )
        .await
        .with_context(|| format!("install v2 blob {}", entry.pkg_path))?;
    }
    Ok(manifest.meta_far.merkle)
}

// ---------------------------------------------------------------------------------------------
// Launch triggers + verified-exec negative.
// ---------------------------------------------------------------------------------------------

/// Bind a pkg_hello instance's framework Binder to Lazy-start it, and WAIT for it to run+exit
/// (the Binder channel closes when the component stops). Deterministic ordering: after this returns,
/// the instance has resolved (against the index state AT bind time) and emitted its marker.
async fn launch_and_wait(binder: BinderProxy, what: &str) -> Result<()> {
    // The Binder connection is already open (connect implicitly started resolution). Wait for the
    // instance to stop (marker emitted, main returned => channel PEER_CLOSED), bounded so a stuck
    // resolve can't hang boot.
    futures::select! {
        _ = binder.on_closed().fuse() => {},
        _ = sleep(30.0).fuse() => {
            return Err(anyhow!("{what} launch did not stop within 30 seconds"));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Package GARBAGE COLLECTION: an explicit, post-update unreferenced-blob sweep.
//
// LIVE SET = mirror of what the resolver serves: the signature-filtered dynamic index SHADOWS base
// (pkg_index::effective_meta_fars), and for each effective meta.far we walk its content-blob closure
// (package_directory::RootDir::external_file_hashes). Everything else in the fxfs blob volume is
// unreferenced and unlinked. This is the CORRECT live set — a naive base∪dynamic union would keep an
// updated package's OLD (shadowed) blobs alive forever and reclaim nothing.
//
// SAFETY / blob-in-use: fxfs blob deletion is POSIX unlink-while-open — the directory entry vanishes
// and the blob becomes un-openable immediately (new BlobReader.GetVmo -> NOT_FOUND), but the backing
// storage is retained until every open handle AND every pager-backed child VMO (from a prior GetVmo)
// is dropped, then it is tombstoned. elf_runner pages a launched component's binary+libs out of the
// blob VMO for the component's WHOLE LIFETIME, so the safety rule is "never GC blobs a still-running
// component resolved." We run GC only on the post-update path AFTER v1 and v2 have each run-to-exit
// (launch_and_wait joined their Binder close), so their VMOs are already dropped.
// ---------------------------------------------------------------------------------------------

/// Connect a BlobReader to fshost's mounted blob volume (used both to walk meta.fars and to prove a
/// swept blob is gone).
fn connect_blob_reader() -> Result<BlobReaderProxy> {
    let blob_dir = fuchsia_fs::directory::open_in_namespace(BLOB_DIR, fio::PERM_READABLE)
        .with_context(|| format!("open {BLOB_DIR}"))?;
    connect_to_protocol_at_dir_svc::<BlobReaderMarker>(&blob_dir).context("connect BlobReader")
}

/// Is a blob currently readable (openable)? After an unlink this goes false (NOT_FOUND) even before
/// the storage is physically reclaimed — the affirmative "it's gone" test the gate asserts.
async fn blob_present(reader: &BlobReaderProxy, hash: &Hash) -> bool {
    matches!(reader.get_vmo(&(*hash).into()).await, Ok(Ok(_)))
}

/// Enumerate every blob currently in the store (hash-named entries in the flat blob-volume dir).
async fn enumerate_store() -> Result<Vec<Hash>> {
    let dir = fuchsia_fs::directory::open_in_namespace(BLOB_ROOT, fio::PERM_READABLE)
        .with_context(|| format!("open {BLOB_ROOT}"))?;
    let entries = readdir(&dir)
        .await
        .with_context(|| format!("readdir {BLOB_ROOT}"))?;
    Ok(entries
        .into_iter()
        .filter_map(|e| Hash::from_str(&e.name).ok())
        .collect())
}

/// Compute the LIVE blob set: for each package's EFFECTIVE meta.far (signed-dynamic shadows base),
/// the meta.far merkle plus its content-blob closure (read from the meta.far via BlobReader).
async fn compute_live_set(
    reader: &BlobReaderProxy,
    signed_dynamic: &DynamicIndex,
    base: &HashMap<String, Hash>,
) -> Result<HashSet<Hash>> {
    let effective = effective_meta_fars(signed_dynamic, base).context("effective meta.far set")?;
    let mut live = HashSet::new();
    for (name, meta) in effective {
        live.insert(meta);
        let storage = FxblobStorage::new(reader.clone());
        let root = RootDir::new(storage, meta)
            .await
            .map_err(|e| anyhow!("walk meta.far {meta} for {name}: {e:?}"))?;
        for h in root.external_file_hashes() {
            live.insert(*h);
        }
    }
    Ok(live)
}

/// The explicit post-update GC sweep + evidence. `base_manifest` is the fetcher's own base package
/// (v1); `v2_merkle` is the just-registered v2 meta.far. Deletes unreferenced blobs and asserts v1's
/// UNIQUE blobs are gone while v2 + shared libs survive (GC didn't eat live data).
async fn gc_sweep(
    pubkey: &[u8; 32],
    base_manifest: &IngestManifest,
    v2_merkle: &str,
) -> Result<()> {
    emit("CERISE-PKG-GC-START");
    let reader = connect_blob_reader()?;

    // base index (name -> v1 meta.far) + the SIGNATURE-FILTERED dynamic index (== resolver's view).
    let mut base = HashMap::new();
    base.insert(
        base_manifest.package.clone(),
        Hash::from_str(&base_manifest.meta_far.merkle)?,
    );
    let raw_dynamic = read_dynamic_index()?;
    let (signed_dynamic, _) = filter_signed(&raw_dynamic, pubkey);

    let live = compute_live_set(&reader, &signed_dynamic, &base)
        .await
        .context("compute live set")?;
    let all = enumerate_store().await.context("enumerate store")?;
    let dead: Vec<Hash> = all.iter().filter(|h| !live.contains(h)).copied().collect();
    emit(&format!(
        "CERISE-PKG-GC-LIVE: {} live / {} in store / {} unreferenced",
        live.len(),
        all.len(),
        dead.len()
    ));

    // Unlink each unreferenced blob (Directory.Unlink on the writable blob-volume root dir).
    let blob_root = fuchsia_fs::directory::open_in_namespace(
        BLOB_ROOT,
        fio::PERM_READABLE | fio::PERM_WRITABLE,
    )
    .with_context(|| format!("open {BLOB_ROOT} writable"))?;
    let mut deleted = 0u32;
    for h in &dead {
        match blob_root
            .unlink(&h.to_string(), &fio::UnlinkOptions::default())
            .await
        {
            Ok(Ok(())) => deleted += 1,
            other => emit(&format!(
                "CERISE-PKG-GC-ERROR: unlink {h} failed: {other:?}"
            )),
        }
    }
    emit(&format!(
        "CERISE-PKG-GC-DELETED: {deleted} unreferenced blobs reclaimed"
    ));

    // ---- EVIDENCE: v1's UNIQUE blobs GONE, v2 + shared libs KEPT ----
    let v1_meta = Hash::from_str(&base_manifest.meta_far.merkle)?;
    let v2_meta = Hash::from_str(v2_merkle)?;
    // v1's meta.far is shadowed by v2 and has no other referent -> must have been swept.
    if blob_present(&reader, &v1_meta).await {
        return Err(anyhow!(
            "GC FAILED: shadowed v1 meta.far {v1_meta} still readable after sweep"
        ));
    }
    emit(&format!(
        "CERISE-PKG-GC-VERIFIED: v1 meta.far {v1_meta} is GONE (BlobReader NOT_FOUND)"
    ));

    // v2 (live) must survive — GC did not eat live data.
    if !blob_present(&reader, &v2_meta).await {
        return Err(anyhow!(
            "GC ATE LIVE DATA: v2 meta.far {v2_meta} missing after sweep"
        ));
    }
    // A shared lib (present in BOTH v1 and v2, content-deduped) must survive as v2's referent.
    if let Some(shared) = base_manifest
        .blobs
        .iter()
        .find(|b| b.pkg_path == "lib/ld.so.1")
    {
        let h = Hash::from_str(&shared.merkle)?;
        if !blob_present(&reader, &h).await {
            return Err(anyhow!(
                "GC ATE SHARED BLOB: {} ({h}) missing after sweep",
                shared.pkg_path
            ));
        }
    }
    emit(&format!(
        "CERISE-PKG-GC-KEPT: v2 meta.far {v2_meta} + shared libs survive (live data intact)"
    ));
    Ok(())
}

async fn main_inner() -> Result<()> {
    await_provisioned().await.context("await provisioner")?;
    let creator = connect_blob_creator()
        .await
        .context("connect BlobCreator")?;
    let base_manifest = ingest_base(&creator)
        .await
        .context("ingest base package (v1)")?;
    let pubkey = load_pubkey().context("load signing public key")?;
    emit("CERISE-PKG-UPDATE-FETCHER-READY");

    let dynamic = read_dynamic_index()?;
    let already = dynamic.get(PKG_NAME).map(|e| e.version.clone());

    if already.as_deref() == Some("2") {
        // ---- BOOT 2: the dynamic index + v2 blobs persisted. No network. ----
        emit("CERISE-PKG-UPDATE-SKIP-FETCH");
        let binder = connect_to_protocol_at_path::<BinderMarker>("/svc/pkg_hello_v2.Binder")
            .context("connect pkg_hello_v2 Binder")?;
        launch_and_wait(binder, "v2 (persistent)").await?;
        emit("CERISE-PKG-UPDATE-OK");
        return Ok(());
    }

    // ---- BOOT 1: base launch, then fetch + register + updated launch. ----
    // v1 from the BASE index (dynamic index is still empty at this bind).
    let v1_binder = connect_to_protocol_at_path::<BinderMarker>("/svc/pkg_hello_v1.Binder")
        .context("connect pkg_hello_v1 Binder")?;
    launch_and_wait(v1_binder, "v1 (base)").await?;

    // Bring up the network and DOWNLOAD v2 from the host.
    let _network = bring_up_network()
        .await
        .context("bring up netstack3 + DHCP")?;
    let v2_merkle = fetch_and_install_v2(&creator)
        .await
        .context("fetch + install v2 over network")?;
    let v2_meta_far = Hash::from_str(&v2_merkle).context("parse installed v2 meta.far merkle")?;
    emit(&format!(
        "CERISE-PKG-UPDATE-FETCH-OK: v2 meta.far {v2_merkle}"
    ));

    // download the SIGNED entry, VERIFY its ed25519 signature + anti-rollback counter, and
    // register it VERBATIM (the signature travels into the persistent index for the resolver to
    // re-verify). The fetcher holds no private key, so it can only introduce a signer-blessed entry.
    let entry = fetch_verify_register_entry("/entry.json", &pubkey, Some(&v2_meta_far))
        .await
        .context("fetch + verify + register v2 signed entry")?;
    emit(&format!(
        "CERISE-PKG-SIGNATURE-OK: v2 signed entry verified (counter {})",
        entry.counter
    ));
    emit(&format!(
        "CERISE-PKG-UPDATE-REGISTERED: {PKG_NAME} v2 -> {v2_merkle}"
    ));

    // v2 from the DYNAMIC index (a second instance of the SAME URL, resolved AFTER register).
    let v2_binder = connect_to_protocol_at_path::<BinderMarker>("/svc/pkg_hello_v2.Binder")
        .context("connect pkg_hello_v2 Binder")?;
    launch_and_wait(v2_binder, "v2 (updated)").await?;

    // ---- GC: post-update sweep of unreferenced blobs (v1's now-shadowed unique blobs). ----
    // The natural post-update trigger: v1 + v2 have each run-to-exit (their VMOs dropped), the update
    // is registered+launched, and the negatives below have not yet polluted the index. NB: this
    // deletes blobs the BASE index still names (v1) — non-bricking because ingest_base re-creates them
    // from bootfs on every boot; so the boot-2 durability assertion is scoped to "v2 resolves," not
    // "v1 stays gone."
    gc_sweep(&pubkey, &base_manifest, &v2_merkle)
        .await
        .context("post-update GC sweep")?;

    // ---- SIGNATURE NEGATIVE: a TAMPERED signed entry must be rejected BEFORE install. ----
    signature_negative_test(&pubkey).await;

    // ---- verified-exec IDENTITY NEGATIVE: a validly-SIGNED but LYING-identity entry must fail. ----
    // pkg_hello_evil -> v2's meta.far (a LIVE, present blob, genuinely signed, WRONG identity: its
    // meta/package name is "pkg_hello", not "pkg_hello_evil"). The signature gate passes; the
    // resolver's identity binding rejects it.
    negative_identity_test(&pubkey).await;

    emit("CERISE-PKG-UPDATE-OK");
    Ok(())
}

/// signature negative: fetch a TAMPERED signed entry (corrupted signature) and assert the
/// fetcher rejects it before any install/register. Non-fatal to the fetcher's success.
async fn signature_negative_test(pubkey: &[u8; 32]) {
    match fetch_verify_register_entry("/entry_bad.json", pubkey, None).await {
        Err(_) => emit("CERISE-PKG-SIGNATURE-REJECT: tampered signed entry rejected, no install"),
        Ok(_) => emit(
            "CERISE-PKG-UPDATE-FETCHER-FAIL: SIG NEGATIVE LEAK — a tampered entry was accepted",
        ),
    }
}

/// Fetch a validly-SIGNED but LYING-identity entry (pkg_hello_evil -> v1's meta.far), register it, and
/// ask the resolver to resolve it; assert it is REJECTED by the identity binding. the entry is
/// genuinely signed (so it passes the resolver's signature gate) but its meta/package name mismatches,
/// so the identity binding must still reject it. Non-fatal to the fetcher's success.
async fn negative_identity_test(pubkey: &[u8; 32]) {
    // The signed evil entry is served by the host at /entry_evil.json (signed by the build key, name
    // "pkg_hello_evil", merkle = v1's real meta.far). Fetching + registering it exercises the full
    // signature path, then the resolver's identity binding.
    if let Err(e) = fetch_verify_register_entry("/entry_evil.json", pubkey, None).await {
        emit(&format!("CERISE-PKG-UPDATE-FETCHER: negative-test evil entry fetch/verify failed (skipping): {e:#}"));
        return;
    }
    let resolver = match connect_to_protocol::<fresolution::ResolverMarker>() {
        Ok(r) => r,
        Err(e) => {
            emit(&format!("CERISE-PKG-UPDATE-FETCHER: negative-test connect Resolver failed (skipping): {e:#}"));
            return;
        }
    };
    match resolver
        .resolve("fuchsia-pkg://cerise/pkg_hello_evil#meta/pkg_hello.cm")
        .await
    {
        Ok(Err(_)) => { /* rejected — the resolver already emitted CERISE-PKG-UPDATE-IDENTITY-REJECT */
        }
        Ok(Ok(_)) => {
            emit("CERISE-PKG-UPDATE-FETCHER-FAIL: NEGATIVE TEST LEAK — lying entry resolved OK")
        }
        Err(e) => emit(&format!(
            "CERISE-PKG-UPDATE-FETCHER: negative-test transport error (inconclusive): {e:?}"
        )),
    }
}

#[fuchsia::main(logging = false)]
async fn main() {
    if let Err(e) = main_inner().await {
        emit(&format!("CERISE-PKG-UPDATE-FETCHER-FAIL: {e:#}"));
    }
}

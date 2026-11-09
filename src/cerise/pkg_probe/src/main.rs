// Cerise packages foundation: pkg_probe — the on-target proof that a real Fuchsia
// package lives in the fxfs `blob` volume and resolves end to end.
//
// It runs in the x64-pkg product (root_dfv2acpi_pkg realm = the fshost realm + this component).
// It plays the fshost_probe role (gate on the provisioner, then trigger fshost's Lazy mount)
// AND then does the package work:
//
//   1. Gate on the fxfs_provisioner: read /provisioned/ready (a real FIDL round-trip; blocks
//      until the provisioner formatted the disk, created the empty "blob" volume, and RELEASED
//      it). Only then touch fshost.
//   2. Open /fshost-fs/blob (Lazy-starts fshost, which mounts the "blob" volume as_blob and
//      exposes fuchsia.fxfs/BlobCreator + BlobReader under svc/, and the hash-named blobs under
//      root/). Retry until BlobCreator is connectable.
//   3. INGEST: read the build-time ingest manifest from this component's own /pkg
//      (/pkg/blobs/manifest.json) and, for the meta.far and every content blob, read the raw
//      bytes from /pkg, re-encode as an uncompressed Type-1 delivery blob, and write it via
//      BlobCreator.Create(merkle) -> BlobWriter (ring buffer). fxfs recomputes the merkle on the
//      write path, so the blobs are content-addressed and write-verified. => CERISE-PKG-INGEST-OK
//   4. RESOLVE: open /fshost-fs/blob/root as a fuchsia.io directory of hash-named blobs and drive
//      the vendored package_directory crate over it (fio::DirectoryProxy NonMetaStorage impl —
//      no blobfs de-stub needed). RootDir::new pulls the meta.far by its merkle and parses it;
//      then read meta/package, meta/pkg_hello.cm, and the bin/pkg_hello content blob back
//      (merkle-verified by fxfs on the read/page-in path). Also serve() the package as a live
//      fuchsia.io directory and read a file through the served connection.
//
// Markers (serial): CERISE-PKG-PROBE-PROVISIONED-OBSERVED, CERISE-PKG-INGEST-OK,
// CERISE-PKG-MANIFEST-OK, CERISE-PKG-CM-OK, CERISE-PKG-BLOB-OK, CERISE-PKG-DIR-SERVED, and the
// success marker CERISE-PKG-OK. Failure: CERISE-PKG-FAIL: <ctx>.
//
// DELIBERATELY ABSENT (foundation scope): resolving a fuchsia-pkg:// URL through a resolver
// daemon and LAUNCHING pkg_hello (needs pkg-resolver/pkg-cache), OTA, verified-exec policy, and
// blob compression (uncompressed Type-1 only).

use anyhow::{anyhow, Context, Result};
use fidl_fuchsia_fxfs::{BlobCreatorMarker, BlobCreatorProxy, BlobReaderMarker};
use fidl_fuchsia_io as fio;
use fuchsia_component::client::{connect_to_protocol, connect_to_protocol_at_dir_svc};
use fuchsia_hash::Hash;
use fxblob_storage::FxblobStorage;
use package_directory::RootDir;
use serde::Deserialize;
use std::str::FromStr as _;
use vfs::execution_scope::ExecutionScope;
use zx::sys::zx_debug_write;

const READY_FILE: &str = "/provisioned/ready";
const BLOB_DIR: &str = "/fshost-fs/blob";
const MANIFEST_PATH: &str = "/pkg/blobs/manifest.json";
const PKG_ROOT: &str = "/pkg";

fn emit(msg: &str) {
    let msg = format!("{msg}\n");
    unsafe {
        zx_debug_write(msg.as_ptr(), msg.len());
    }
}

#[derive(Debug, Deserialize)]
struct IngestManifest {
    meta_far: BlobEntry,
    blobs: Vec<BlobEntry>,
}

#[derive(Debug, Deserialize)]
struct BlobEntry {
    pkg_path: String,
    runtime_path: String,
    merkle: String,
}

async fn sleep(secs: u64) {
    fuchsia_async::Timer::new(fuchsia_async::MonotonicInstant::after(
        std::time::Duration::from_secs(secs).into(),
    ))
    .await;
}

/// Block (real read round-trip) until the fxfs_provisioner has released the disk.
async fn await_provisioned() -> Result<()> {
    for _ in 0..120 {
        if fuchsia_fs::file::read_in_namespace(READY_FILE).await.is_ok() {
            return Ok(());
        }
        sleep(5).await;
    }
    Err(anyhow!("provisioner readiness never observed"))
}

/// Open /fshost-fs/blob (Lazy-starts fshost) and connect to BlobCreator, retrying until fshost
/// has mounted the blob volume and is serving the protocol.
async fn connect_blob_creator() -> Result<BlobCreatorProxy> {
    let mut last = None;
    for _ in 0..120 {
        match fuchsia_fs::directory::open_in_namespace(BLOB_DIR, fio::PERM_READABLE) {
            Ok(blob_dir) => match connect_to_protocol_at_dir_svc::<BlobCreatorMarker>(&blob_dir) {
                Ok(creator) => {
                    // Probe with a NeedsOverwrite call to confirm the server is actually up.
                    match creator.needs_overwrite(&[0u8; 32]).await {
                        Ok(_) => return Ok(creator),
                        Err(e) => last = Some(anyhow!("BlobCreator probe failed: {e:?}")),
                    }
                }
                Err(e) => last = Some(anyhow!("connect BlobCreator: {e:?}")),
            },
            Err(e) => last = Some(anyhow!("open {BLOB_DIR}: {e:?}")),
        }
        sleep(5).await;
    }
    Err(last.unwrap_or_else(|| anyhow!("no BlobCreator attempts")))
}

/// Write one blob (raw uncompressed bytes `data`, merkle `hash`) into the blob volume via the
/// ring-buffer BlobWriter protocol. Serialized (await each BytesReady before reusing ring space),
/// which is simple and correct for any ring size.
async fn write_blob(creator: &BlobCreatorProxy, hash: &Hash, data: &[u8]) -> Result<()> {
    let delivery = delivery_blob::generate_uncompressed_type1(data);
    let writer = creator
        .create(hash.as_bytes().try_into().unwrap(), /*allow_existing=*/ true)
        .await
        .context("BlobCreator.Create transport")?
        .map_err(|e| anyhow!("BlobCreator.Create error: {e:?}"))?;
    let writer = writer.into_proxy();

    let vmo = writer
        .get_vmo(delivery.len() as u64)
        .await
        .context("BlobWriter.GetVmo transport")?
        .map_err(|s| anyhow!("BlobWriter.GetVmo error: {s}"))?;
    let ring = vmo.get_size().context("ring vmo size")?;
    if ring == 0 {
        return Err(anyhow!("server returned zero-size ring vmo"));
    }

    let total = delivery.len() as u64;
    let mut written: u64 = 0;
    while written < total {
        let off = written % ring;
        let contiguous = ring - off; // don't wrap within a single vmo.write
        let chunk = std::cmp::min(contiguous, total - written) as usize;
        vmo.write(&delivery[written as usize..written as usize + chunk], off)
            .context("write into ring vmo")?;
        writer
            .bytes_ready(chunk as u64)
            .await
            .context("BlobWriter.BytesReady transport")?
            .map_err(|s| anyhow!("BlobWriter.BytesReady error: {s}"))?;
        written += chunk as u64;
    }
    Ok(())
}

/// Read a staged file from this component's /pkg namespace.
async fn read_pkg_file(runtime_path: &str) -> Result<Vec<u8>> {
    let path = format!("{PKG_ROOT}/{runtime_path}");
    fuchsia_fs::file::read_in_namespace(&path)
        .await
        .map_err(|e| anyhow!("read {path}: {e:?}"))
}

async fn ingest(creator: &BlobCreatorProxy, manifest: &IngestManifest) -> Result<()> {
    // meta.far first, then every content blob.
    let mut all: Vec<&BlobEntry> = vec![&manifest.meta_far];
    all.extend(manifest.blobs.iter());
    for entry in all {
        let hash = Hash::from_str(&entry.merkle)
            .map_err(|e| anyhow!("bad merkle {}: {e:?}", entry.merkle))?;
        let data = read_pkg_file(&entry.runtime_path).await?;
        write_blob(creator, &hash, &data)
            .await
            .with_context(|| format!("ingest blob {} ({})", entry.pkg_path, entry.merkle))?;
    }
    Ok(())
}

async fn resolve_and_verify(manifest: &IngestManifest) -> Result<()> {
    let meta_far_hash = Hash::from_str(&manifest.meta_far.merkle)?;

    // The blob source: fshost's blob volume BlobReader (fxblob). Reads are merkle-verified.
    let blob_dir = fuchsia_fs::directory::open_in_namespace(BLOB_DIR, fio::PERM_READABLE)
        .context("open blob dir for reader")?;
    let reader = connect_to_protocol_at_dir_svc::<BlobReaderMarker>(&blob_dir)
        .context("connect BlobReader")?;
    // A second reader for the live-serve proof below (RootDir consumes the first).
    let reader2 = connect_to_protocol_at_dir_svc::<BlobReaderMarker>(&blob_dir)
        .context("connect BlobReader (serve)")?;
    let storage = FxblobStorage::new(reader);

    // Drive the vendored package_directory crate over the blob volume. RootDir::new pulls the
    // meta.far by its merkle (via BlobReader.GetVmo) and parses the FAR (meta/package,
    // meta/contents, meta/*.cm) — real meta.far parsing on the actual on-disk blob.
    let root_dir = RootDir::new(storage, meta_far_hash)
        .await
        .map_err(|e| anyhow!("RootDir::new (parse meta.far): {e:?}"))?;

    // meta/package — proves the FAR's package identity is readable.
    let pkg_path = root_dir.path().await.map_err(|e| anyhow!("read meta/package: {e:?}"))?;
    if pkg_path.name().as_ref() != "pkg_hello" {
        return Err(anyhow!("meta/package name mismatch: {}", pkg_path.name()));
    }
    emit("CERISE-PKG-MANIFEST-OK");

    // meta/pkg_hello.cm — decode as a real fuchsia.component.decl/Component to prove it is a
    // genuine compiled manifest, not opaque bytes.
    let cm_bytes = root_dir
        .read_file("meta/pkg_hello.cm")
        .await
        .map_err(|e| anyhow!("read meta/pkg_hello.cm: {e:?}"))?;
    let component: fidl_fuchsia_component_decl::Component =
        fidl::unpersist(&cm_bytes).map_err(|e| anyhow!("decode .cm: {e:?}"))?;
    let program = component.program.ok_or_else(|| anyhow!(".cm has no program"))?;
    if program.runner.as_deref() != Some("elf") {
        return Err(anyhow!(".cm runner != elf: {:?}", program.runner));
    }
    emit("CERISE-PKG-CM-OK");

    // bin/pkg_hello content blob — read it back through the blob volume (each page merkle-VERIFIED
    // by fxfs on page-in) and confirm its bytes hash to the manifest merkle.
    let bin_entry = manifest
        .blobs
        .iter()
        .find(|b| b.pkg_path == "bin/pkg_hello")
        .ok_or_else(|| anyhow!("manifest missing bin/pkg_hello"))?;
    let bin_bytes = root_dir
        .read_file("bin/pkg_hello")
        .await
        .map_err(|e| anyhow!("read bin/pkg_hello content blob: {e:?}"))?;
    let got = fuchsia_merkle::root_from_slice(&bin_bytes).to_string();
    if got != bin_entry.merkle {
        return Err(anyhow!("content-blob merkle mismatch: got {got}, want {}", bin_entry.merkle));
    }
    emit("CERISE-PKG-BLOB-OK");

    // Serve the package as a LIVE fuchsia.io directory (package_directory::serve over the fxfs
    // blob volume) and read files THROUGH the served connection — proving the serving path, not
    // just RootDir reads. `serve` returns after establishing the connection; the actual VFS
    // serving continues on `scope` (held to end of fn), so subsequent reads run against the live
    // directory.
    let storage2 = FxblobStorage::new(reader2);
    let (pkg_dir, server_end) = fidl::endpoints::create_proxy::<fio::DirectoryMarker>();
    let scope = ExecutionScope::new();
    package_directory::serve(scope.clone(), storage2, meta_far_hash, fio::PERM_READABLE, server_end)
        .await
        .map_err(|e| anyhow!("package_directory::serve: {e:?}"))?;

    // meta/package is a META file (served from the meta.far VMO via the vfs connection); this does
    // NOT invoke NonMetaStorage::open.
    let served_meta = fuchsia_fs::directory::read_file(&pkg_dir, "meta/package")
        .await
        .map_err(|e| anyhow!("read meta/package via served dir: {e:?}"))?;
    if served_meta.is_empty() {
        return Err(anyhow!("served meta/package was empty"));
    }
    emit("CERISE-PKG-DIR-SERVED");

    // bin/pkg_hello is a CONTENT blob — reading it THROUGH the served directory invokes
    // FxblobStorage::open (the de-stub: BlobReader -> vmo_blob::VmoBlob -> StreamIoConnection),
    // NOT the RootDir read path. Verify the bytes recovered through the served connection hash to
    // the manifest merkle: proves a content blob is genuinely READ THROUGH THE SERVED DIRECTORY.
    let served_bin = fuchsia_fs::directory::read_file(&pkg_dir, "bin/pkg_hello")
        .await
        .map_err(|e| anyhow!("read bin/pkg_hello via served dir (open path): {e:?}"))?;
    let served_merkle = fuchsia_merkle::root_from_slice(&served_bin).to_string();
    if served_merkle != bin_entry.merkle {
        return Err(anyhow!(
            "served content-blob merkle mismatch: got {served_merkle}, want {}",
            bin_entry.merkle
        ));
    }
    emit("CERISE-PKG-RESOLVER-CONTENT-SERVED");

    // Keep the serving scope explicitly alive across the reads above.
    drop(scope);
    Ok(())
}

/// launch trigger: bind pkg_hello's framework Binder to Lazy-start it. component_manager
/// resolves fuchsia-pkg://cerise/pkg_hello via #pkg_resolver — which serves pkg_hello's package
/// directory (bin + lib/*) from the fxfs "blob" volume, EXECUTABLE — and elf_runner loads the
/// binary + shared libs from those disk blobs and runs it (=> CERISE-PKG-RESOLVER-LAUNCHED on serial).
/// This must run AFTER ingest: the resolver reads pkg_hello's blobs from the volume pkg_probe just
/// populated.
async fn trigger_launch() -> Result<()> {
    use fidl_fuchsia_component::BinderMarker;
    // Hold the Binder connection open while pkg_hello resolves-from-disk, launches, emits its
    // marker, and exits. Generous bound (blob-backed lib loads + several FIDL hops through the
    // resolver); the boot gate asserts CERISE-PKG-RESOLVER-LAUNCHED actually appeared.
    let _binder = connect_to_protocol::<BinderMarker>().context("connect pkg_hello Binder")?;
    sleep(30).await;
    Ok(())
}

async fn run() -> Result<()> {
    await_provisioned().await.context("await provisioner")?;
    emit("CERISE-PKG-PROBE-PROVISIONED-OBSERVED");

    let creator = connect_blob_creator().await.context("connect BlobCreator")?;

    let manifest_bytes =
        fuchsia_fs::file::read_in_namespace(MANIFEST_PATH).await.map_err(|e| {
            anyhow!("read ingest manifest {MANIFEST_PATH}: {e:?}")
        })?;
    let manifest: IngestManifest =
        serde_json::from_slice(&manifest_bytes).context("parse ingest manifest")?;

    ingest(&creator, &manifest).await.context("ingest package blobs")?;
    emit("CERISE-PKG-INGEST-OK");

    resolve_and_verify(&manifest).await.context("resolve package")?;

    // drive the resolve-and-launch-from-disk chain (pkg_hello runs from blob-volume blobs).
    trigger_launch().await.context("trigger pkg_hello launch")?;

    emit("CERISE-PKG-OK");
    Ok(())
}

#[fuchsia::main(logging = false)]
async fn main() {
    if let Err(e) = run().await {
        emit(&format!("CERISE-PKG-FAIL: {e:#}"));
    }
}

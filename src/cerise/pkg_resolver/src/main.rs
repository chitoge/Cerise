// Cerise packages (increment 2): pkg_resolver — a minimal
// fuchsia.component.resolution.Resolver for `fuchsia-pkg://cerise/<name>` URLs, backed by the
// fxfs `blob` volume. This is the piece deliberately left absent: it lets
// component_manager RESOLVE a fuchsia-pkg:// URL and LAUNCH the packaged component from
// disk blobs (its binary + shared libs paged out of the fxfs blob volume), not from bootfs.
//
// HOW IT FITS THE REALM (root_dfv2acpi_pkg): pkg_resolver is a Lazy child registered in a
// `pkg-env` environment as the resolver for the `fuchsia-pkg` scheme. component_manager connects
// to it (Lazy-starting it) the first time it resolves a `fuchsia-pkg://` child — which happens
// only AFTER pkg_probe has ingested the demo package's blobs and Lazy-started fshost (pkg_probe
// binds pkg_hello's fuchsia.component.Binder to trigger the launch). So by the time a resolve
// arrives, the blobs are in the fxfs `blob` volume and fshost serves BlobReader. No
// Eager-before-storage ordering hazard.
//
// STATIC INDEX (honest scope): the name->meta.far-merkle map is the SAME build-time ingest
// manifest pkg_probe consumes, staged into this component's /pkg (/pkg/index/manifest.json). It
// carries `package` (name) and `meta_far.merkle` (== the package hash the root
// package_directory::serve resolves from). One package today; the format is genuinely name-keyed,
// so adding packages is adding manifest entries, not code. NO dynamic index, NO pkg-cache, NO OTA.
//
// EXECUTABILITY: the resolved package directory is served with PERM_READABLE|PERM_EXECUTABLE so
// component_manager's elf_runner can load the binary + libs (get_backing_memory(EXECUTE)) from it.
// That requires a VMEX resource in THIS process: we fetch fuchsia.kernel.VmexResource once at
// startup and hand it to fxblob_storage::init_vmex (-> vmo_blob::init_vmex_resource). This is the
// exact executability trust boundary pkg-cache holds in upstream Fuchsia. VmexResource is a
// privileged capability; route_check permits precisely this one (pkg_resolver + VmexResource) and
// nothing else

use anyhow::{Context, Result};
use fidl::endpoints::{ClientEnd, Proxy as _};
use fidl_fuchsia_component_resolution as fresolution;
use fidl_fuchsia_fxfs::BlobReaderMarker;
use fidl_fuchsia_io as fio;
use fidl_fuchsia_kernel::VmexResourceMarker;
use fuchsia_component::client::{connect_to_protocol, connect_to_protocol_at_dir_svc};
use fuchsia_component::server::ServiceFs;
use fuchsia_hash::Hash;
use fxblob_storage::FxblobStorage;
use futures::prelude::*;
use pkg_index::{DynamicIndex, Source};
use serde::Deserialize;
use std::collections::HashMap;
use std::str::FromStr as _;
use std::sync::Arc;
use version_history::AbiRevision;
use vfs::execution_scope::ExecutionScope;
use zx::sys::zx_debug_write;

const BLOB_DIR: &str = "/fshost-fs/blob";
const INDEX_MANIFEST: &str = "/pkg/index/manifest.json";
// (signed index): the ed25519 PUBLIC key, staged into this component's bootfs /pkg. The
// resolver honors ONLY dynamic-index entries whose signature verifies against this key — so a
// compromised on-device writer (pkg_fetcher) cannot introduce a package. The key ships in the signed
// OS image; that is the trust root.
const PUBKEY_PATH: &str = "/pkg/keys/pkg_index_pub.ed25519";
// the PERSISTENT dynamic index lives on the fxfs `data` volume (fshost serves it
// under /fshost-fs/data/root, writable + reboot-durable). pkg_fetcher writes it atomically; the
// resolver reads it FRESH on every Resolve and layers it OVER the bootfs base index. An absent file
// (for example, the base qemu-x64-pkg product, which never fetches) means base index only. Other I/O
// failures and malformed contents fail closed so corruption cannot silently disable rollback state.
const DYNAMIC_INDEX: &str = "/fshost-fs/data/root/pkg_dynamic_index.json";
const URL_SCHEME: &str = "fuchsia-pkg://";
const EXPECTED_HOST: &str = "cerise";

fn emit(msg: &str) {
    let msg = format!("{msg}\n");
    unsafe {
        zx_debug_write(msg.as_ptr(), msg.len());
    }
}

// The build-time ingest manifest (shared with pkg_probe). We only need the package name and the
// meta.far merkle; extra fields (blobs, sizes) are ignored by serde.
#[derive(Debug, Deserialize)]
struct IngestManifest {
    package: String,
    meta_far: MetaFarEntry,
}

#[derive(Debug, Deserialize)]
struct MetaFarEntry {
    merkle: String,
}

/// meta/package (MetaPackage v0): the package's OWN declared identity, embedded in its meta.far by
/// cerise_package. We read this back to enforce the verified-exec identity binding (the name the
/// index resolved MUST equal the name the package declares) — see resolve().
#[derive(Debug, Deserialize)]
struct MetaPackage {
    name: String,
}

struct ResolverInner {
    /// Persistent VFS scope: every resolved package directory is served on it and MUST outlive the
    /// Resolve call (elf_runner reads the binary + libs from it after Resolve returns). Dropping
    /// this cancels all served directories, so it lives for the whole process.
    scope: ExecutionScope,
    /// The build-time bootfs BASE index: name -> meta.far merkle (the package hash). The persistent
    /// dynamic index (read fresh per-Resolve from the data volume) layers OVER this.
    base: HashMap<String, Hash>,
    /// the ed25519 public key that dynamic-index entries must be signed under to be honored.
    pubkey: [u8; 32],
}

/// Read the PERSISTENT dynamic index fresh from the fxfs `data` volume. An absent file means no
/// registrations yet. Any other read or parse failure is returned so callers cannot silently
/// discard the installed anti-rollback floor and fall back to an older base package.
fn read_dynamic_index() -> Result<DynamicIndex> {
    match std::fs::read(DYNAMIC_INDEX) {
        Ok(bytes) => DynamicIndex::parse(&bytes)
            .with_context(|| format!("parse dynamic index {DYNAMIC_INDEX}")),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            Ok(DynamicIndex::default())
        }
        Err(error) => Err(error).with_context(|| format!("read dynamic index {DYNAMIC_INDEX}")),
    }
}

fn parse_pkg_url(url: &str) -> Option<(&str, &str, &str)> {
    // fuchsia-pkg://<host>/<name>#<resource>, e.g. fuchsia-pkg://cerise/pkg_hello#meta/pkg_hello.cm
    let rest = url.strip_prefix(URL_SCHEME)?;
    let (path, resource) = rest.split_once('#')?;
    let (host, name) = path.split_once('/')?;
    if host.is_empty() || name.is_empty() || name.contains('/') || resource.is_empty() {
        return None;
    }
    Some((host, name, resource))
}

/// Serve ONE resolved package directory over the fxfs blob volume and build the resolution result.
/// Returns a well-formed fresolution::Component (decl + executable package directory + abi).
async fn resolve(inner: &ResolverInner, url: &str) -> Result<fresolution::Component, fresolution::ResolverError> {
    let (host, name, resource) = parse_pkg_url(url).ok_or_else(|| {
        emit(&format!("CERISE-PKG-RESOLVER-RESOLVE-FAIL: bad url {url}"));
        fresolution::ResolverError::InvalidArgs
    })?;
    if host != EXPECTED_HOST {
        emit(&format!("CERISE-PKG-RESOLVER-RESOLVE-FAIL: unknown host {host}"));
        return Err(fresolution::ResolverError::NotSupported);
    }

    // LAYERED resolution: the persistent dynamic index (read fresh from the data volume)
    // SHADOWS the bootfs base index. A dynamic entry with a malformed merkle fails loud.
    //
    // SIGNED INDEX: the resolver is the trust boundary. Before layering, drop every dynamic
    // entry whose ed25519 signature does not verify against the embedded public key — an unsigned or
    // tampered entry (e.g. from a compromised writer) is treated as if absent (falls through to the
    // trusted-in-image base). If the REQUESTED name's dynamic entry was dropped, say so loudly.
    let raw_dynamic = read_dynamic_index().map_err(|error| {
        emit(&format!("CERISE-PKG-UPDATE-DYNINDEX-BAD: {error:#}"));
        fresolution::ResolverError::Internal
    })?;
    let (dynamic, dropped) = pkg_index::filter_signed(&raw_dynamic, &inner.pubkey);
    if dropped.iter().any(|n| n == name) {
        emit(&format!("CERISE-PKG-SIGNATURE-REJECT: dropped unsigned/invalid dynamic entry for {name}"));
    }
    let resolved = pkg_index::resolve(name, &dynamic, &inner.base).map_err(|e| {
        emit(&format!("CERISE-PKG-RESOLVER-RESOLVE-FAIL: {e}"));
        fresolution::ResolverError::Internal
    })?;
    let resolved = resolved.ok_or_else(|| {
        emit(&format!("CERISE-PKG-RESOLVER-RESOLVE-FAIL: package not in index: {name}"));
        fresolution::ResolverError::PackageNotFound
    })?;
    let meta_far_hash = resolved.merkle;
    match &resolved.source {
        Source::Dynamic { version } => {
            emit(&format!("CERISE-PKG-UPDATE-SOURCE-DYNAMIC: {name} v{version} -> {meta_far_hash}"))
        }
        Source::Base => emit(&format!("CERISE-PKG-UPDATE-SOURCE-BASE: {name} -> {meta_far_hash}")),
    }

    // Connect a fresh BlobReader to fshost's mounted blob volume. FxblobStorage owns it, so it
    // lives as long as the served directory (on the persistent scope).
    let blob_dir = fuchsia_fs::directory::open_in_namespace(BLOB_DIR, fio::PERM_READABLE)
        .map_err(|e| {
            emit(&format!("CERISE-PKG-RESOLVER-RESOLVE-FAIL: open {BLOB_DIR}: {e:?}"));
            fresolution::ResolverError::Io
        })?;
    let reader = connect_to_protocol_at_dir_svc::<BlobReaderMarker>(&blob_dir).map_err(|e| {
        emit(&format!("CERISE-PKG-RESOLVER-RESOLVE-FAIL: connect BlobReader: {e:?}"));
        fresolution::ResolverError::Io
    })?;
    let storage = FxblobStorage::new(reader);

    // Serve the package as an EXECUTABLE fuchsia.io directory over the blob volume. `serve` returns
    // after establishing the connection; the VFS serving continues on `inner.scope` (held for the
    // process lifetime) — we DO NOT await it further. The proxy is handed to component_manager as
    // Package.directory below.
    let (pkg_dir, server_end) = fidl::endpoints::create_proxy::<fio::DirectoryMarker>();
    package_directory::serve(
        inner.scope.clone(),
        storage,
        meta_far_hash,
        fio::PERM_READABLE | fio::PERM_EXECUTABLE,
        server_end,
    )
    .await
    .map_err(|e| {
        emit(&format!("CERISE-PKG-RESOLVER-RESOLVE-FAIL: serve meta.far {meta_far_hash}: {e:?}"));
        fresolution::ResolverError::PackageNotFound
    })?;

    // VERIFIED-EXEC IDENTITY BINDING: the meta.far this name resolved to MUST declare that
    // same name in its OWN meta/package. Content-addressing already guarantees the served blob IS
    // meta_far_hash (fxfs verifies it on page-in), so re-hashing it would be a tautology; the real
    // thing an index can lie about is IDENTITY — pointing `name` at a DIFFERENT (valid) package's
    // meta.far. Reject that loudly: a lying index entry must not launch someone else's code.
    let meta_pkg_bytes = fuchsia_fs::directory::read_file(&pkg_dir, "meta/package").await.map_err(|e| {
        emit(&format!("CERISE-PKG-RESOLVER-RESOLVE-FAIL: read meta/package for {name}: {e:?}"));
        fresolution::ResolverError::Io
    })?;
    let meta_pkg: MetaPackage = serde_json::from_slice(&meta_pkg_bytes).map_err(|e| {
        emit(&format!("CERISE-PKG-RESOLVER-RESOLVE-FAIL: parse meta/package for {name}: {e}"));
        fresolution::ResolverError::Internal
    })?;
    if let Err(e) = pkg_index::verify_identity(name, &meta_pkg.name) {
        emit(&format!("CERISE-PKG-UPDATE-IDENTITY-REJECT: {e}"));
        return Err(fresolution::ResolverError::PackageNotFound);
    }
    emit(&format!("CERISE-PKG-UPDATE-IDENTITY-OK: {name} == meta/package {}", meta_pkg.name));

    // ABI revision from meta/fuchsia.abi/abi-revision (embedded in the meta.far by cerise_package).
    let abi_revision =
        fidl_fuchsia_component_abi_ext::read_abi_revision_optional(&pkg_dir, AbiRevision::PATH)
            .await
            .map_err(fresolution::ResolverError::from)?;

    // The component manifest (.cm) — served from the meta.far VMO; returned as fuchsia.mem.Data.
    let decl = mem_util::open_file_data(&pkg_dir, resource).await.map_err(|e| {
        emit(&format!("CERISE-PKG-RESOLVER-RESOLVE-FAIL: read {resource}: {e:?}"));
        fresolution::ResolverError::ManifestNotFound
    })?;

    let package_url = format!("{URL_SCHEME}{host}/{name}");
    // Hand the SAME served connection to component_manager as the package directory (mapped to
    // /pkg in the launched component's namespace, R+X). Reads above already completed on it.
    let directory = ClientEnd::new(
        pkg_dir
            .into_channel()
            .map_err(|_| fresolution::ResolverError::Internal)?
            .into_zx_channel(),
    );

    emit(&format!("CERISE-PKG-RESOLVER-RESOLVED: {package_url}"));
    Ok(fresolution::Component {
        decl: Some(decl),
        package: Some(fresolution::Package {
            url: Some(package_url),
            directory: Some(directory),
            ..Default::default()
        }),
        abi_revision: abi_revision.map(Into::into),
        ..Default::default()
    })
}

async fn serve_resolver(inner: Arc<ResolverInner>, mut stream: fresolution::ResolverRequestStream) {
    while let Ok(Some(request)) = stream.try_next().await {
        match request {
            fresolution::ResolverRequest::Resolve { component_url, responder } => {
                let result = resolve(&inner, &component_url).await;
                let _ = responder.send(result);
            }
            fresolution::ResolverRequest::ResolveWithContext { responder, .. } => {
                // scope: absolute fuchsia-pkg:// URLs only (no subpackages/relative URLs).
                let _ = responder.send(Err(fresolution::ResolverError::NotSupported));
            }
            fresolution::ResolverRequest::_UnknownMethod { .. } => {}
        }
    }
}

/// Load the build-time bootfs BASE index (name->merkle) from the staged ingest manifest. This is the
/// shipped-in-image fallback layer; the persistent dynamic index shadows it at resolve time.
fn load_base_index() -> Result<HashMap<String, Hash>> {
    let bytes = std::fs::read(INDEX_MANIFEST)
        .with_context(|| format!("read index manifest {INDEX_MANIFEST}"))?;
    let manifest: IngestManifest =
        serde_json::from_slice(&bytes).context("parse index manifest")?;
    let hash = Hash::from_str(&manifest.meta_far.merkle)
        .with_context(|| format!("bad meta.far merkle {}", manifest.meta_far.merkle))?;
    let mut index = HashMap::new();
    index.insert(manifest.package.clone(), hash);
    emit(&format!("CERISE-PKG-RESOLVER-INDEX: {} -> {}", manifest.package, hash));
    Ok(index)
}

/// Load the ed25519 public key (raw 32 bytes) staged into this component's bootfs /pkg.
///
/// GRACEFUL ABSENCE: a product that never uses the signed dynamic index (e.g. the
/// `qemu-x64-pkg`, which resolves only from the trusted-in-image BASE index) need not stage a key.
/// With no key, `filter_signed` uses an all-zero sentinel that NO real signature verifies against, so
/// EVERY dynamic entry is dropped (base-only resolution) — which is exactly the safe behavior.
/// A present-but-malformed key is still fatal (a signing product with a broken key must fail loud).
fn load_pubkey() -> Result<[u8; 32]> {
    match std::fs::read(PUBKEY_PATH) {
        Ok(bytes) => {
            let key: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
                anyhow::anyhow!("pubkey {PUBKEY_PATH} is {} bytes, expected 32", bytes.len())
            })?;
            emit("CERISE-PKG-RESOLVER-PUBKEY-OK");
            Ok(key)
        }
        Err(_) => {
            // No key staged => no signed dynamic entries can be honored (base-only). Safe + honest.
            emit("CERISE-PKG-RESOLVER-NO-PUBKEY: base-index-only (no signed dynamic entries honored)");
            Ok([0u8; 32])
        }
    }
}

async fn run() -> Result<()> {
    // Fetch the VMEX resource and arm the process-global executability gate BEFORE serving any
    // resolve — the served package directory must be able to answer get_backing_memory(EXECUTE).
    let vmex_proxy = connect_to_protocol::<VmexResourceMarker>().context("connect VmexResource")?;
    let vmex_handle = vmex_proxy.get().await.context("VmexResource.Get")?;
    fxblob_storage::init_vmex(zx::Resource::from(vmex_handle)).context("init_vmex")?;
    emit("CERISE-PKG-RESOLVER-VMEX-OK");

    let pubkey = load_pubkey()?;
    let inner =
        Arc::new(ResolverInner { scope: ExecutionScope::new(), base: load_base_index()?, pubkey });

    let mut fs = ServiceFs::new();
    fs.dir("svc").add_fidl_service(|stream: fresolution::ResolverRequestStream| stream);
    fs.take_and_serve_directory_handle().context("take_and_serve outgoing dir")?;
    emit("CERISE-PKG-RESOLVER-READY");

    fs.for_each_concurrent(None, |stream| {
        let inner = Arc::clone(&inner);
        async move { serve_resolver(inner, stream).await }
    })
    .await;
    Ok(())
}

#[fuchsia::main(logging = false)]
async fn main() {
    if let Err(e) = run().await {
        emit(&format!("CERISE-PKG-RESOLVER-FAIL: {e:#}"));
    }
}

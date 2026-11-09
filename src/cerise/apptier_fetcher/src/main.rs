// Cerise packages (post-storage app tier): apptier_fetcher — the on-target driver that
// realizes the bootfs-offload PAYOFF. It delivers a REAL production application (the gRPC fileserver,
// 8.5 MB + libs) from a fuchsia-pkg PACKAGE over the network instead of from bootfs.
//
// FLOW (single-package, first-boot network fetch; simpler than pkg_fetcher's v1/v2 update dance):
//   1. gate on the fxfs_provisioner, connect fshost's BlobCreator + BlobReader.
//   2. bring up netstack3 (discover NIC, DHCP DORA) and KEEP the interface up for the whole boot —
//      apptier_fetcher OWNS the NIC; the fileserver SHARES it (it binds 0.0.0.0:50051 on the same
//      netstack3 and skips its own bringup via an interface-exists guard). So this component must
//      NOT exit while the fileserver runs (process exit would close the interface handles).
//   3. read the fileserver's BASE ingest manifest (staged in /pkg — the resolver's trusted-in-image
//      base index) to learn the meta.far merkle. If that blob is ALREADY in the blob volume (reboot:
//      persisted), SKIP the network. Otherwise DOWNLOAD the meta.far + every content blob from the
//      host, merkle-VERIFY each before install, and write them via BlobCreator.
//   4. bind the fileserver's framework Binder -> component_manager resolves fuchsia-pkg://cerise/
//      fileserver via #pkg_resolver (from the BASE index) and elf_runner launches it from DISK blobs.
//   5. PARK forever, holding the NIC up for the fileserver's lifetime.
//
// Markers: CERISE-APPTIER-FETCHER-READY, -DHCP (lease), -FETCH-OK / -SKIP-FETCH, -LAUNCHED.
// Failure: CERISE-APPTIER-FAIL: <ctx>. The fileserver emits CERISE-FILESERVER-LISTENING itself.

use anyhow::{anyhow, Context, Result};
use cerise_http_download::Limits as HttpLimits;
use cerise_network_bootstrap::BootstrapPolicy;
use cerise_network_bootstrap_fuchsia::{
    bootstrap, FuchsiaBootstrapConfig, InterfaceLifetime, Ipv4Configuration,
};
use fidl_fuchsia_component::{BinderMarker, BinderProxy};
use fidl_fuchsia_fxfs::{BlobCreatorMarker, BlobCreatorProxy, BlobReaderMarker, BlobReaderProxy};
use fidl_fuchsia_io as fio;
use fuchsia_component::client::{connect_to_protocol_at_dir_svc, connect_to_protocol_at_path};
use fuchsia_hash::Hash;
use serde::Deserialize;
use std::path::Path;
use std::str::FromStr as _;
use zx::sys::zx_debug_write;

const READY_FILE: &str = "/provisioned/ready";
const BLOB_DIR: &str = "/fshost-fs/blob";
const BASE_MANIFEST: &str = "/pkg/index/manifest.json";
const PKG_NAME: &str = "fileserver";
// Host download endpoint (QEMU SLIRP host-loopback alias). Distinct port from pkg_fetcher's 52099.
const HOST_ADDR: &str = "10.0.2.2:52098";
const MAX_MANIFEST_BYTES: usize = 1 << 20;
const MAX_BLOB_BYTES: usize = 64 << 20;
const DOWNLOAD_DIR: &str = "/fshost-fs/data/root/.apptier-fetcher-downloads";

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

#[derive(Debug, Deserialize)]
struct IngestManifest {
    package: String,
    meta_far: BlobEntry,
    blobs: Vec<BlobEntry>,
}

#[derive(Debug, Deserialize)]
struct BlobEntry {
    pkg_path: String,
    merkle: String,
}

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

fn connect_blob_reader() -> Result<BlobReaderProxy> {
    let blob_dir = fuchsia_fs::directory::open_in_namespace(BLOB_DIR, fio::PERM_READABLE)
        .with_context(|| format!("open {BLOB_DIR}"))?;
    connect_to_protocol_at_dir_svc::<BlobReaderMarker>(&blob_dir).context("connect BlobReader")
}

async fn blob_present(reader: &BlobReaderProxy, hash: &Hash) -> bool {
    matches!(reader.get_vmo(&(*hash).into()).await, Ok(Ok(_)))
}

// ---- network bringup ---------------------------------------------------------

async fn bring_up_network() -> Result<InterfaceLifetime> {
    let result = bootstrap(
        FuchsiaBootstrapConfig {
            interface_name: "apptier-eth0",
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
        "CERISE-APPTIER-DHCP-LEASE={}.{}.{}.{}/{}",
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

/// Download the fileserver package (manifest + meta.far + content blobs) from the host, merkle-verify
/// each blob before install, and write it into the blob volume.
async fn fetch_and_install(creator: &BlobCreatorProxy) -> Result<()> {
    let manifest_bytes = http_get("/manifest.json", MAX_MANIFEST_BYTES)
        .await
        .context("GET /manifest.json")?;
    let manifest: IngestManifest =
        serde_json::from_slice(&manifest_bytes).context("parse fetched manifest")?;
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
            .map_err(|e| anyhow!("bad merkle {}: {e:?}", entry.merkle))?;
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
        .with_context(|| format!("install blob {}", entry.pkg_path))?;
    }
    Ok(())
}

/// Read the base ingest manifest staged in /pkg to learn the fileserver's meta.far merkle.
fn read_base_meta_far() -> Result<Hash> {
    let bytes = std::fs::read(BASE_MANIFEST)
        .with_context(|| format!("read base manifest {BASE_MANIFEST}"))?;
    let manifest: IngestManifest = serde_json::from_slice(&bytes).context("parse base manifest")?;
    Hash::from_str(&manifest.meta_far.merkle)
        .map_err(|e| anyhow!("bad base meta.far merkle: {e:?}"))
}

async fn main_inner() -> Result<()> {
    await_provisioned().await.context("await provisioner")?;
    let creator = connect_blob_creator()
        .await
        .context("connect BlobCreator")?;
    let reader = connect_blob_reader().context("connect BlobReader")?;
    emit("CERISE-APPTIER-FETCHER-READY");

    // Bring up the network FIRST (unconditionally) — the fileserver shares this interface whether or
    // not we re-fetch, so it must be up on every boot.
    let _network = bring_up_network()
        .await
        .context("bring up netstack3 + DHCP")?;

    // Fetch the fileserver package only if its blobs are not already resident (reboot => persisted).
    let meta_far = read_base_meta_far().context("read base meta.far merkle")?;
    if blob_present(&reader, &meta_far).await {
        emit("CERISE-APPTIER-SKIP-FETCH");
    } else {
        fetch_and_install(&creator)
            .await
            .context("fetch + install fileserver package")?;
        emit(&format!(
            "CERISE-APPTIER-FETCH-OK: fileserver meta.far {meta_far}"
        ));
    }

    // Bind the fileserver's framework Binder -> component_manager resolves fuchsia-pkg://cerise/
    // fileserver via #pkg_resolver (base index) and launches it from disk blobs.
    let _binder: BinderProxy =
        connect_to_protocol_at_path::<BinderMarker>("/svc/fileserver.Binder")
            .context("connect fileserver Binder")?;
    emit("CERISE-APPTIER-LAUNCHED: fileserver resolved from package (disk blobs, not bootfs)");

    // PARK forever, holding the NIC up for the fileserver's lifetime. (The fileserver serves gRPC on
    // the shared interface; if this process exited, the interface would tear down.)
    loop {
        sleep(3600.0).await;
    }
}

#[fuchsia::main(logging = false)]
async fn main() {
    if let Err(e) = main_inner().await {
        emit(&format!("CERISE-APPTIER-FAIL: {e:#}"));
    }
}

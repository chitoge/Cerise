// Cerise packages foundation: pkg_builder — a HOST tool that builds a real
// Fuchsia package (meta.far) from the vendored fuchsia-pkg library, plus a Cerise-native
// "ingest manifest" the on-target pkg_probe reads to write the package's blobs into the
// fxfs `blob` volume (content-addressed, merkle-verified).
//
// It is deliberately thin: all the real work — meta/package, meta/contents, meta/fuchsia.abi,
// FAR serialization, and merkle-root computation of every blob AND of the meta.far itself —
// is done by the vendored `fuchsia_pkg::PackageBuilder` (which pulls fuchsia-archive +
// fuchsia-merkle + fuchsia-hash, all un-stubbed). This tool only: (1) drives PackageBuilder
// from a JSON spec, (2) copies each content blob to a Bazel-declared output path (so the
// staged bytes and the manifest come from ONE source of truth), and (3) emits the ingest
// manifest mapping each blob's runtime staging path -> its merkle.
//
// No checked-in generated artifacts: meta.far is produced by this tool at build time.

use anyhow::{Context, Result};
use fuchsia_pkg::{PackageBuilder, PackageManifest};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Build spec, written by the cerise_package Bazel rule.
#[derive(Debug, Deserialize)]
struct Spec {
    /// Package name (goes into meta/package).
    name: String,
    /// Files embedded INSIDE meta.far (e.g. a compiled component manifest meta/<name>.cm).
    far_files: Vec<FarFile>,
    /// External content blobs (the component binary, shared libs, ...).
    blobs: Vec<BlobSpec>,
    /// Where to write the produced meta.far (Bazel-declared output).
    meta_far_out: PathBuf,
    /// Where to write the ingest manifest JSON (Bazel-declared output).
    manifest_out: PathBuf,
    /// A scratch dir PackageBuilder may use for intermediates.
    gendir: PathBuf,
    /// Runtime path (in pkg_probe's /pkg namespace) the meta.far is staged at.
    meta_far_runtime_path: String,
}

#[derive(Debug, Deserialize)]
struct FarFile {
    /// Path inside the package/meta.far, e.g. "meta/pkg_hello.cm".
    pkg_path: String,
    /// Host source file.
    source: PathBuf,
}

#[derive(Debug, Deserialize)]
struct BlobSpec {
    /// Path inside the package, e.g. "bin/pkg_hello".
    pkg_path: String,
    /// Host source file.
    source: PathBuf,
    /// Bazel-declared output the raw blob bytes are copied to (single source of truth
    /// for both the staged bootfs bytes and the merkle in the ingest manifest).
    out_copy: PathBuf,
    /// Path (in pkg_probe's /pkg namespace) this blob is staged at at runtime.
    runtime_path: String,
}

/// The ingest manifest pkg_probe consumes at runtime. Every entry is content-addressed:
/// pkg_probe reads `runtime_path`'s bytes, re-encodes them as an uncompressed Type-1
/// delivery blob, and calls BlobCreator.Create(merkle) — fxfs recomputes the merkle on the
/// write path and rejects a mismatch, so a corrupted staged blob cannot be ingested.
#[derive(Debug, Serialize)]
struct IngestManifest {
    package: String,
    /// meta.far merkle == the package hash; the root package_directory::serve resolves from.
    meta_far: BlobEntry,
    blobs: Vec<BlobEntry>,
}

#[derive(Debug, Serialize)]
struct BlobEntry {
    /// Path inside the package (informational; "meta/" for the meta.far itself).
    pkg_path: String,
    /// Path in pkg_probe's /pkg namespace where the raw bytes are staged.
    runtime_path: String,
    /// Hex fuchsia-merkle root of the ORIGINAL (uncompressed) bytes.
    merkle: String,
    size: u64,
}

fn main() -> Result<()> {
    let spec_path = std::env::args().nth(1).context("usage: pkg_builder <spec.json>")?;
    let spec: Spec = serde_json::from_reader(
        std::fs::File::open(&spec_path).with_context(|| format!("open spec {spec_path}"))?,
    )
    .context("parse spec json")?;

    std::fs::create_dir_all(&spec.gendir).context("create gendir")?;

    // Build the real meta.far via the vendored library.
    let mut builder = PackageBuilder::new_platform_internal_package(&spec.name);
    for ff in &spec.far_files {
        builder
            .add_file_to_far(&ff.pkg_path, ff.source.to_str().context("far source utf8")?)
            .with_context(|| format!("add_file_to_far {}", ff.pkg_path))?;
    }
    for b in &spec.blobs {
        builder
            .add_file_as_blob(&b.pkg_path, b.source.to_str().context("blob source utf8")?)
            .with_context(|| format!("add_file_as_blob {}", b.pkg_path))?;
    }
    let manifest: PackageManifest =
        builder.build(&spec.gendir, &spec.meta_far_out).context("PackageBuilder::build")?;

    // Index the produced blob merkles by package path.
    let mut merkle_by_path = std::collections::BTreeMap::new();
    let mut size_by_path = std::collections::BTreeMap::new();
    for blob in manifest.blobs() {
        merkle_by_path.insert(blob.path.clone(), blob.merkle.to_string());
        size_by_path.insert(blob.path.clone(), blob.size);
    }

    // meta.far merkle == package hash.
    let meta_far_merkle = manifest.hash().to_string();
    let meta_far_size = *size_by_path
        .get(PackageManifest::META_FAR_BLOB_PATH)
        .context("manifest missing meta.far blob entry")?;

    // Copy each content blob to its declared output and record its merkle.
    let mut blob_entries = Vec::new();
    for b in &spec.blobs {
        std::fs::copy(&b.source, &b.out_copy)
            .with_context(|| format!("copy blob {} -> {}", b.source.display(), b.out_copy.display()))?;
        let merkle = merkle_by_path
            .get(&b.pkg_path)
            .with_context(|| format!("no merkle for blob {}", b.pkg_path))?
            .clone();
        let size = *size_by_path.get(&b.pkg_path).unwrap_or(&0);
        blob_entries.push(BlobEntry {
            pkg_path: b.pkg_path.clone(),
            runtime_path: b.runtime_path.clone(),
            merkle,
            size,
        });
    }

    let ingest = IngestManifest {
        package: spec.name.clone(),
        meta_far: BlobEntry {
            pkg_path: PackageManifest::META_FAR_BLOB_PATH.to_string(),
            runtime_path: spec.meta_far_runtime_path.clone(),
            merkle: meta_far_merkle,
            size: meta_far_size,
        },
        blobs: blob_entries,
    };
    let json = serde_json::to_string_pretty(&ingest).context("serialize ingest manifest")?;
    std::fs::write(&spec.manifest_out, json).context("write ingest manifest")?;
    Ok(())
}

// Cerise OTA: ota_signer — the HOST/BUILD-time signer for OS-image update manifests.
//
// It reads an OS image (a ZBI), hashes it, and writes the manifest the update host serves
// alongside it, signed with the selected Ed25519 build seed (//build/keys:signing_seed).
// The private seed exists ONLY on the build side; the device is staged with the derived
// PUBLIC key at /pkg/keys/ota_image_pub.ed25519 and can only verify.
//
// This is the sibling of //src/cerise/tools/pkg_signer, deliberately the same shape (same
// cerise_signing primitive, same signing and public-key derivation, same key provenance
// caveat) so the OS-image trust chain and the package-index trust chain are one design and
// not two. The canonical bytes it signs are ota_image_manifest::signing_message, under a
// DIFFERENT domain tag, so neither kind of signature can be replayed as the other.
//
// WHY --tamper EXISTS. It is the point of the whole change. Before signatures, the OTA gate
// could not construct a bad image: it computed the manifest's sha256 from the very bytes it
// served, so any substitution it made was, by construction, self-consistent and accepted.
// --tamper emits a manifest that is byte-identical to the genuine one except that its
// signature is corrupt, which //validation:ota-update-tamper-boot serves in place of the
// real one to prove the device REFUSES and does not write. A guard that cannot be made to
// fire is not a guard.
//
// KEY PROVENANCE / ROTATION (and the same limit pkg_signer records): source builds use
// either the source-only example seed or the public development fallback. Production must
// inject a seed from an HSM or signing service and anchor the public key in a
// verified-boot-measured location; rotation means shipping a new public key in a new image
// and re-signing. None of that changes the on-device verify path.
//
// THE CONDITION UNDER WHICH THESE SIGNATURES ARE WORTH NOTHING, stated plainly because it is
// not obvious from this file. `//build/keys:signing_seed` is an alias: it resolves to the
// non-production example at `build/keys/pkg_index_signing_seed.bin` when present, and otherwise
// to `:dev_signing_seed`, a fixed public string in `build/keys/BUILD.bazel`. Neither source-build
// value establishes authenticity; anyone with the corresponding source tree can mint a manifest
// this updater will accept. The signature then protects against accidental corruption and
// against a host that merely substitutes bytes, and NOT against an adversary. That is a
// property of the shared key infrastructure, not of the OTA path, and it is shared verbatim
// with the signed package index; closing it means a real key and a verified-boot anchor, which
// is the same work item for both. A build that intends the signature to be a security boundary
// must ensure an externally held release seed is supplied.
//
//   ota_signer pubkey --seed <seed.bin> --out <pubkey.bin>
//   ota_signer sign   --seed <seed.bin> --image <image.zbi> --version <N> --out <m.json>
//                     [--tamper]
//   ota_signer verify --pubkey <pubkey.bin> --image <image.zbi> --manifest <m.json>

use anyhow::{anyhow, bail, Context, Result};
use ota_image_manifest::{sha256_hex, sign_manifest, verify_manifest, ImageManifest};
use std::collections::HashMap;

fn arg(map: &HashMap<String, String>, k: &str) -> Result<String> {
    map.get(k).cloned().ok_or_else(|| anyhow!("missing required --{k}"))
}

fn parse_flags(args: &[String]) -> (HashMap<String, String>, Vec<String>) {
    let mut map = HashMap::new();
    let mut flags = Vec::new();
    let mut i = 0;
    while i < args.len() {
        if let Some(key) = args[i].strip_prefix("--") {
            // Boolean flag when the next token is another --flag or absent.
            if i + 1 < args.len() && !args[i + 1].starts_with("--") {
                map.insert(key.to_string(), args[i + 1].clone());
                i += 2;
            } else {
                flags.push(key.to_string());
                i += 1;
            }
        } else {
            i += 1;
        }
    }
    (map, flags)
}

fn read_seed(path: &str) -> Result<[u8; 32]> {
    let bytes = std::fs::read(path).with_context(|| format!("read seed {path}"))?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("seed {path} is {} bytes, expected 32", bytes.len()))
}

fn read_public_key(path: &str) -> Result<[u8; 32]> {
    let bytes = std::fs::read(path).with_context(|| format!("read public key {path}"))?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("public key {path} is {} bytes, expected 32", bytes.len()))
}

fn main() -> Result<()> {
    let argv: Vec<String> = std::env::args().collect();
    if argv.len() < 2 {
        bail!("usage: ota_signer <pubkey|sign|verify> [flags]");
    }
    let (opts, flags) = parse_flags(&argv[2..]);

    match argv[1].as_str() {
        "pubkey" => {
            let seed = read_seed(&arg(&opts, "seed")?)?;
            let pk = cerise_signing::public_from_seed(&seed);
            std::fs::write(arg(&opts, "out")?, pk).context("write pubkey")?;
        }
        "sign" => {
            let seed = read_seed(&arg(&opts, "seed")?)?;
            let image_path = arg(&opts, "image")?;
            let image = std::fs::read(&image_path).with_context(|| format!("read {image_path}"))?;
            let version: u32 = arg(&opts, "version")?.parse().context("parse --version")?;
            let mut manifest = sign_manifest(&seed, version, &image);
            if flags.iter().any(|f| f == "tamper") {
                // Corrupt ONE hex character of the signature and nothing else, so the
                // negative payload differs from the genuine one in exactly the field
                // under test. Same technique as pkg_signer --tamper.
                let mut sig = manifest.signature.into_bytes();
                sig[0] = if sig[0] == b'0' { b'1' } else { b'0' };
                manifest.signature = String::from_utf8(sig).unwrap();
            }
            let json = serde_json::to_vec_pretty(&manifest).context("serialize manifest")?;
            std::fs::write(arg(&opts, "out")?, json).context("write manifest")?;
        }
        "verify" => {
            let public_key = read_public_key(&arg(&opts, "pubkey")?)?;
            let image_path = arg(&opts, "image")?;
            let image = std::fs::read(&image_path).with_context(|| format!("read {image_path}"))?;
            let manifest_path = arg(&opts, "manifest")?;
            let manifest_bytes = std::fs::read(&manifest_path)
                .with_context(|| format!("read manifest {manifest_path}"))?;
            let manifest: ImageManifest =
                serde_json::from_slice(&manifest_bytes).context("parse manifest")?;
            if !verify_manifest(&manifest, &public_key) {
                bail!("manifest signature verification failed");
            }
            let image_size = u64::try_from(image.len()).context("image size exceeds u64")?;
            let image_sha256 = sha256_hex(&image);
            if manifest.size != image_size || manifest.sha256 != image_sha256 {
                bail!("signed manifest does not describe the supplied image");
            }
            println!(
                "status=verified version={} sha256={} bytes={}",
                manifest.version, image_sha256, image_size
            );
        }
        other => bail!("unknown subcommand {other:?} (expected pubkey|sign|verify)"),
    }
    Ok(())
}

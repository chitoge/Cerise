// guest_store_signer — the HOST/BUILD-time signer for guest-store push manifests.
//
// It reads a `.cryostore`, hashes it, and writes the manifest a pusher sends alongside
// it, signed with the selected Ed25519 build seed (//build/keys:signing_seed). The
// private seed exists ONLY on the build side; the appliance is staged with the derived
// PUBLIC key at /pkg/keys/guest_store_pub.ed25519 and can only check.
//
// This is the sibling of //src/cerise/ota_updater:ota_signer and
// //src/cerise/tools/pkg_signer, deliberately the same shape (same cerise_signing
// primitive, same "pubkey | sign | --tamper" surface, same key provenance caveat) so the
// three trust chains are one design and not three. The canonical bytes it signs are
// guest_store_admit::signing_message, under a DIFFERENT domain tag, so no signature can
// be replayed across them.
//
// WHY --tamper EXISTS. The refusal gate has to push a payload the appliance REFUSES, and
// it has to differ from the genuine one in exactly the field under test. --tamper emits a
// manifest byte-identical to the genuine one except that one hex character of its
// signature has moved. A guard that cannot be made to fire is not a guard.
//
// WHAT THESE SIGNATURES ESTABLISH, stated plainly because the machinery does not look any
// different either way. `//build/keys:signing_seed` resolves to the source-only example
// seed when present. Otherwise it uses `:dev_signing_seed`, another fixed test value.
// Signatures made with either prove only that the signing path works and do not establish
// authenticity. A trusted release needs an externally held key and an anchor for the public
// one; that requirement is shared by all three chains and changes nothing about the
// on-device check path.
//
//   guest_store_signer pubkey --seed <seed.bin> --out <pubkey.bin>
//   guest_store_signer sign   --seed <seed.bin> --store <image.cryostore> --out <m.json>
//                             [--tamper]

use anyhow::{anyhow, bail, Context, Result};
use guest_store_admit::sign_manifest_digest;
use sha2::{Digest as _, Sha256};
use std::collections::HashMap;
use std::io::Read as _;

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

fn main() -> Result<()> {
    let argv: Vec<String> = std::env::args().collect();
    if argv.len() < 2 {
        bail!("usage: guest_store_signer <pubkey|sign> [flags]");
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
            let store_path = arg(&opts, "store")?;
            let mut store =
                std::fs::File::open(&store_path).with_context(|| format!("open {store_path}"))?;
            let mut hasher = Sha256::new();
            let mut size = 0u64;
            let mut chunk = vec![0u8; 4 << 20];
            loop {
                let read = store.read(&mut chunk).with_context(|| format!("read {store_path}"))?;
                if read == 0 {
                    break;
                }
                hasher.update(&chunk[..read]);
                size += read as u64;
            }
            let digest = cerise_signing::to_hex(&hasher.finalize());
            let mut manifest = sign_manifest_digest(&seed, digest, size);
            if flags.iter().any(|f| f == "tamper") {
                // Move ONE hex character of the signature and nothing else, so the
                // negative payload differs from the genuine one in exactly the field
                // under test. Same technique as ota_signer --tamper.
                let mut sig = manifest.signature.into_bytes();
                sig[0] = if sig[0] == b'0' { b'1' } else { b'0' };
                manifest.signature = String::from_utf8(sig).unwrap();
            }
            let json = serde_json::to_vec_pretty(&manifest).context("serialize manifest")?;
            std::fs::write(arg(&opts, "out")?, json).context("write manifest")?;
        }
        other => bail!("unknown subcommand {other:?} (expected pubkey|sign)"),
    }
    Ok(())
}

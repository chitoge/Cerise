// Cerise packages: pkg_signer — the HOST/build-time tool that signs a dynamic-index entry
// with the selected Ed25519 build key and derives the PUBLIC key that gets embedded
// (staged into bootfs /pkg) in pkg_resolver + pkg_fetcher.
//
// This is the trusted signer that closes the "trusted-writer gap": the on-device pkg_fetcher
// is NO LONGER trusted to introduce packages — it can only merge entries this tool signed, and the
// resolver honors only signature-valid entries. The private seed lives ONLY here (build side); the
// device holds the public key.
//
// KEY PROVENANCE / ROTATION: source builds use the source-only example seed when
// present or the public development fallback. A trusted release must inject a
// deployment credential from an HSM or signing service and embed its public key in
// a verified-boot-measured location. Rotation means shipping a new public key in a
// new signed image and re-signing entries. None of that changes the on-device path.
//
// Subcommands:
//   pubkey  --seed <seed.bin> --out <pubkey.bin>
//       derive the 32-byte raw ed25519 public key from the seed (staged into resolver+fetcher /pkg).
//   sign    --seed <seed.bin> --manifest <manifest.json> --version <V> --counter <N> --out <entry.json>
//            [--tamper]
//       read the package name + meta.far merkle from an ingest manifest, sign {name,version,merkle,
//       counter}, and write the signed IndexEntry JSON the fetcher downloads and merges verbatim.
//       --tamper corrupts the signature after signing (produces the NEGATIVE-test payload).

use anyhow::{anyhow, bail, Context, Result};
use pkg_index::{sign_entry, IndexEntry};
use serde::Deserialize;
use std::collections::HashMap;

#[derive(Debug, Deserialize)]
struct IngestManifest {
    package: String,
    meta_far: MetaFar,
}
#[derive(Debug, Deserialize)]
struct MetaFar {
    merkle: String,
}

fn arg(map: &HashMap<String, String>, k: &str) -> Result<String> {
    map.get(k).cloned().ok_or_else(|| anyhow!("missing required --{k}"))
}

fn parse_flags(args: &[String]) -> (HashMap<String, String>, Vec<String>) {
    let mut map = HashMap::new();
    let mut flags = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if let Some(key) = a.strip_prefix("--") {
            // Boolean flag if the next token is another --flag or absent.
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
    bytes.as_slice().try_into().map_err(|_| anyhow!("seed {path} is {} bytes, expected 32", bytes.len()))
}

fn main() -> Result<()> {
    let argv: Vec<String> = std::env::args().collect();
    if argv.len() < 2 {
        bail!("usage: pkg_signer <pubkey|sign> [flags]");
    }
    let cmd = argv[1].clone();
    let (opts, flags) = parse_flags(&argv[2..]);

    match cmd.as_str() {
        "pubkey" => {
            let seed = read_seed(&arg(&opts, "seed")?)?;
            let pk = cerise_signing::public_from_seed(&seed);
            std::fs::write(arg(&opts, "out")?, pk).context("write pubkey")?;
        }
        "sign" => {
            let seed = read_seed(&arg(&opts, "seed")?)?;
            let manifest_bytes = std::fs::read(arg(&opts, "manifest")?).context("read manifest")?;
            let manifest: IngestManifest =
                serde_json::from_slice(&manifest_bytes).context("parse manifest")?;
            let version = arg(&opts, "version")?;
            let counter: u64 = arg(&opts, "counter")?.parse().context("parse --counter")?;
            // --name overrides the manifest's package name (used to sign a LYING-IDENTITY entry: a
            // name pointing at a DIFFERENT package's valid meta.far — the identity negative,
            // which must be validly SIGNED to reach the resolver's identity check past the sig gate).
            let name = opts.get("name").cloned().unwrap_or_else(|| manifest.package.clone());
            let mut entry: IndexEntry =
                sign_entry(&seed, &name, &version, &manifest.meta_far.merkle, counter);
            if flags.iter().any(|f| f == "tamper") {
                // Corrupt the signature so verify_entry() rejects it — the NEGATIVE-test payload.
                let mut sig = entry.signature.into_bytes();
                sig[0] = if sig[0] == b'0' { b'1' } else { b'0' };
                entry.signature = String::from_utf8(sig).unwrap();
            }
            let json = serde_json::to_vec_pretty(&entry).context("serialize signed entry")?;
            std::fs::write(arg(&opts, "out")?, json).context("write signed entry")?;
        }
        other => bail!("unknown subcommand {other:?} (expected pubkey|sign)"),
    }
    Ok(())
}

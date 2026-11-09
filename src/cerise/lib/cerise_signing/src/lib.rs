// cerise_signing (packages): a tiny, reusable ed25519 sign/verify primitive over canonical
// message bytes, backed by the in-tree BoringSSL Rust bindings (bssl-crypto). Factored out of
// pkg_index so it can be SHARED — the package-index signed-entry path (pkg_index / pkg_resolver /
// pkg_fetcher / the pkg_signer host tool) is the first consumer; the OS-image OTA trust chain is
// expected to reuse the same sign/verify over its own canonical image-manifest bytes.
//
// SCOPE: this crate is deliberately message-agnostic. It signs/verifies RAW bytes — each consumer
// defines its own DOMAIN-SEPARATED canonical encoding (see `domain_message`) so a signature over a
// package-index entry can never be replayed as a signature over an OS image, or vice versa. Ed25519
// hashes the message internally (SHA-512, RFC 8032), so callers pass the canonical bytes directly.
//
// It builds on BOTH host and the Fuchsia target (bssl-crypto is already on the load-bearing path via
// fuchsia-merkle), so the pure logic is host-unit-tested here and reused verbatim on-target.

use bssl_crypto::ed25519;

/// Length of an ed25519 seed / private key (the 32 secret bytes).
pub const SEED_LEN: usize = 32;
/// Length of an ed25519 public key.
pub const PUBLIC_KEY_LEN: usize = 32;
/// Length of an ed25519 signature.
pub const SIGNATURE_LEN: usize = 64;

/// Sign `msg` with the 32-byte `seed` (private key), returning the 64-byte signature. HOST/build-time
/// only in practice (the private key never ships to a device); on-target code only ever verifies.
pub fn sign(seed: &[u8; SEED_LEN], msg: &[u8]) -> [u8; SIGNATURE_LEN] {
    ed25519::PrivateKey::from_seed(seed).sign(msg)
}

/// Derive the 32-byte public key from a 32-byte seed (private key). Used by the host tool to emit the
/// public key that gets embedded (bootfs) in the resolver + fetcher.
pub fn public_from_seed(seed: &[u8; SEED_LEN]) -> [u8; PUBLIC_KEY_LEN] {
    *ed25519::PrivateKey::from_seed(seed).to_public().as_bytes()
}

/// Verify a 64-byte `sig` over `msg` against the 32-byte `pubkey`. Returns false on any mismatch —
/// tampered message, wrong key, or malformed signature. This is the trust boundary the resolver and
/// fetcher hold (public key only, no secret material).
pub fn verify(pubkey: &[u8; PUBLIC_KEY_LEN], msg: &[u8], sig: &[u8; SIGNATURE_LEN]) -> bool {
    ed25519::PublicKey::from_bytes(pubkey).verify(msg, sig).is_ok()
}

/// Build a DOMAIN-SEPARATED canonical message from a domain tag and ordered fields.
///
/// Every component is length-prefixed and the field count is encoded explicitly,
/// so caller-controlled delimiters cannot make two field lists collide. Consumers
/// MUST pick a unique, versioned `domain` (for example `cerise-pkg-index-v2`) so
/// signatures cannot cross contexts or encoding revisions.
pub fn domain_message(domain: &str, fields: &[&str]) -> Vec<u8> {
    const FORMAT: &[u8] = b"cerise-signing-message-v1\0";

    fn append_component(out: &mut Vec<u8>, value: &[u8]) {
        let length = u64::try_from(value.len()).expect("message component length fits u64");
        out.extend_from_slice(&length.to_be_bytes());
        out.extend_from_slice(value);
    }

    let mut out = Vec::with_capacity(
        FORMAT.len() + domain.len() + fields.iter().map(|field| field.len() + 8).sum::<usize>() + 16,
    );
    out.extend_from_slice(FORMAT);
    append_component(&mut out, domain.as_bytes());
    out.extend_from_slice(
        &u64::try_from(fields.len()).expect("message field count fits u64").to_be_bytes(),
    );
    for field in fields {
        append_component(&mut out, field.as_bytes());
    }
    out
}

/// Lowercase-hex encode bytes (for embedding a signature/key in JSON). Deterministic.
pub fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Decode lowercase/uppercase hex into a fixed-size array. `None` on wrong length or non-hex.
pub fn from_hex<const N: usize>(s: &str) -> Option<[u8; N]> {
    let s = s.trim();
    if s.len() != N * 2 {
        return None;
    }
    let mut out = [0u8; N];
    for i in 0..N {
        out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    // A fixed test seed (NOT the build key). Deterministic keypair for reproducible unit tests.
    const SEED: [u8; 32] = [7u8; 32];

    #[test]
    fn sign_then_verify_roundtrips() {
        let pk = public_from_seed(&SEED);
        let msg = domain_message("cerise-test", &["alpha", "beta"]);
        let sig = sign(&SEED, &msg);
        assert!(verify(&pk, &msg, &sig), "a genuine signature must verify");
    }

    #[test]
    fn tampered_message_is_rejected() {
        let pk = public_from_seed(&SEED);
        let msg = domain_message("cerise-test", &["alpha", "beta"]);
        let sig = sign(&SEED, &msg);
        let tampered = domain_message("cerise-test", &["alpha", "BETA"]);
        assert!(!verify(&pk, &tampered, &sig), "a tampered message must NOT verify");
    }

    #[test]
    fn tampered_signature_is_rejected() {
        let pk = public_from_seed(&SEED);
        let msg = domain_message("cerise-test", &["x"]);
        let mut sig = sign(&SEED, &msg);
        sig[0] ^= 0xff;
        assert!(!verify(&pk, &msg, &sig), "a corrupted signature must NOT verify");
    }

    #[test]
    fn wrong_key_is_rejected() {
        let msg = domain_message("cerise-test", &["x"]);
        let sig = sign(&SEED, &msg);
        let other_pk = public_from_seed(&[9u8; 32]);
        assert!(!verify(&other_pk, &msg, &sig), "a different public key must NOT verify");
    }

    #[test]
    fn domain_separation_matters() {
        // The SAME fields under a DIFFERENT domain must produce a signature that does not cross over.
        let pk = public_from_seed(&SEED);
        let a = domain_message("domain-a", &["same"]);
        let sig_a = sign(&SEED, &a);
        let b = domain_message("domain-b", &["same"]);
        assert!(!verify(&pk, &b, &sig_a), "domain separation must prevent cross-context replay");
    }

    #[test]
    fn field_boundaries_are_unambiguous() {
        let left = domain_message("cerise-test", &["a\nb", "c"]);
        let right = domain_message("cerise-test", &["a", "b\nc"]);
        assert_ne!(left, right, "caller-controlled delimiters must not collide");
    }

    #[test]
    fn hex_roundtrips() {
        let sig = sign(&SEED, b"hello");
        let hex = to_hex(&sig);
        assert_eq!(hex.len(), SIGNATURE_LEN * 2);
        let back: [u8; SIGNATURE_LEN] = from_hex(&hex).unwrap();
        assert_eq!(back, sig);
        assert!(from_hex::<64>("nothex").is_none());
        assert!(from_hex::<64>("00").is_none(), "wrong length rejected");
    }
}

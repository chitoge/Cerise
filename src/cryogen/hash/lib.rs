//! SHA-256 content hashing for cryogen.
//!
//! The page store is content-addressed: a page's identity *is* the hash of its
//! bytes, so two pages collide in the store only if they hash equally. That makes
//! the hash a correctness dependency, not just a lookup key — a non-cryptographic
//! hash would let an attacker-chosen (or merely unlucky) pair of distinct pages
//! alias, silently corrupting a restored guest. SHA-256 is used for its collision
//! resistance and because its digest is exactly the store's 32-byte `BlobId`.
//!
//! This is a self-contained implementation over `core` only: the store and its
//! consumers build for a freestanding target with no libc and no C toolchain, so
//! a C-backed digest is not an option here.
//!
//! Reference: FIPS 180-4.

#![cfg_attr(not(test), no_std)]

/// A SHA-256 digest — also the store's page identifier.
pub type Digest = [u8; 32];

/// Bytes absorbed per compression round.
const BLOCK_LEN: usize = 64;

/// FIPS 180-4 §4.2.2 round constants: the first 32 bits of the fractional parts
/// of the cube roots of the first 64 primes.
const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// FIPS 180-4 §5.3.3 initial hash value: the first 32 bits of the fractional
/// parts of the square roots of the first 8 primes.
const H0: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// Streaming SHA-256 state.
///
/// Streaming matters here because a caller may hash a page it is reading in
/// pieces, without staging the whole input.
pub struct Sha256 {
    h: [u32; 8],
    /// Partial block awaiting a full 64 bytes.
    buf: [u8; BLOCK_LEN],
    buf_len: usize,
    /// Total message length in bytes; the padding encodes it as bits.
    total: u64,
}

impl Sha256 {
    pub fn new() -> Self {
        Sha256 { h: H0, buf: [0; BLOCK_LEN], buf_len: 0, total: 0 }
    }

    /// Absorbs `data`, buffering any tail that does not fill a block.
    pub fn update(&mut self, mut data: &[u8]) {
        self.total = self.total.wrapping_add(data.len() as u64);

        // Top up a partial block first.
        if self.buf_len > 0 {
            let take = core::cmp::min(BLOCK_LEN - self.buf_len, data.len());
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
            self.buf_len += take;
            data = &data[take..];
            if self.buf_len == BLOCK_LEN {
                let block = self.buf;
                self.compress(&block);
                self.buf_len = 0;
            }
        }

        // Consume whole blocks straight from the input.
        while data.len() >= BLOCK_LEN {
            let (block, rest) = data.split_at(BLOCK_LEN);
            let mut b = [0u8; BLOCK_LEN];
            b.copy_from_slice(block);
            self.compress(&b);
            data = rest;
        }

        // Stash the remainder.
        if !data.is_empty() {
            self.buf[..data.len()].copy_from_slice(data);
            self.buf_len = data.len();
        }
    }

    /// Appends the FIPS padding (a 0x80 byte, zeros, then the 64-bit big-endian
    /// bit length) and returns the digest.
    pub fn finalize(mut self) -> Digest {
        let bit_len = self.total.wrapping_mul(8);

        // 0x80 then zero-pad so that exactly 8 bytes remain for the length.
        self.buf[self.buf_len] = 0x80;
        self.buf_len += 1;
        if self.buf_len > BLOCK_LEN - 8 {
            for b in &mut self.buf[self.buf_len..] {
                *b = 0;
            }
            let block = self.buf;
            self.compress(&block);
            self.buf_len = 0;
        }
        for b in &mut self.buf[self.buf_len..BLOCK_LEN - 8] {
            *b = 0;
        }
        self.buf[BLOCK_LEN - 8..].copy_from_slice(&bit_len.to_be_bytes());
        let block = self.buf;
        self.compress(&block);

        let mut out = [0u8; 32];
        for (i, word) in self.h.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
        }
        out
    }

    /// FIPS 180-4 §6.2.2 compression over one 64-byte block.
    fn compress(&mut self, block: &[u8; BLOCK_LEN]) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                block[i * 4],
                block[i * 4 + 1],
                block[i * 4 + 2],
                block[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let (mut a, mut b, mut c, mut d) = (self.h[0], self.h[1], self.h[2], self.h[3]);
        let (mut e, mut f, mut g, mut hh) = (self.h[4], self.h[5], self.h[6], self.h[7]);

        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ (!e & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);

            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }

        self.h[0] = self.h[0].wrapping_add(a);
        self.h[1] = self.h[1].wrapping_add(b);
        self.h[2] = self.h[2].wrapping_add(c);
        self.h[3] = self.h[3].wrapping_add(d);
        self.h[4] = self.h[4].wrapping_add(e);
        self.h[5] = self.h[5].wrapping_add(f);
        self.h[6] = self.h[6].wrapping_add(g);
        self.h[7] = self.h[7].wrapping_add(hh);
    }
}

impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}

/// One-shot SHA-256 of `data` — the usual way to derive a page's store id.
pub fn sha256(data: &[u8]) -> Digest {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(d: &Digest) -> String {
        let mut s = String::new();
        for b in d {
            s.push_str(&format!("{:02x}", b));
        }
        s
    }

    // Published FIPS 180-4 / NIST CAVP vectors — these check the implementation
    // against the standard, not against itself.
    #[test]
    fn nist_vector_empty() {
        assert_eq!(
            hex(&sha256(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn nist_vector_abc() {
        assert_eq!(
            hex(&sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    // 56 bytes: exercises the padding path where the length does not fit in the
    // final block and a second compression round is required.
    #[test]
    fn nist_vector_two_block() {
        assert_eq!(
            hex(&sha256(
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
            )),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
    }

    // One million 'a' — the classic long-message vector, and the only one here
    // that exercises the 64-bit length counter meaningfully.
    #[test]
    fn nist_vector_million_a() {
        let mut h = Sha256::new();
        let chunk = [b'a'; 1000];
        for _ in 0..1000 {
            h.update(&chunk);
        }
        assert_eq!(
            hex(&h.finalize()),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
        );
    }

    // The all-zero 4 KiB page: by far the most common page in a sparse disk
    // image, so its digest is the store's single most-reused key.
    #[test]
    fn zero_page_digest() {
        assert_eq!(
            hex(&sha256(&[0u8; 4096])),
            "ad7facb2586fc6e966c004d7d1d16b024f5805ff7cb47c7a85dabd8b48892ca7"
        );
    }

    // Streaming in arbitrary pieces must equal the one-shot digest; the ingest
    // path relies on this when a page arrives split across reads.
    #[test]
    fn streaming_matches_one_shot() {
        let data: Vec<u8> = (0..1000u32).map(|i| (i % 251) as u8).collect();
        for split in [1usize, 63, 64, 65, 127, 128, 500] {
            let mut h = Sha256::new();
            h.update(&data[..split]);
            h.update(&data[split..]);
            assert_eq!(h.finalize(), sha256(&data), "split at {}", split);
        }
    }
}

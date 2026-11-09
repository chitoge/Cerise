//! SHA-256 with a small, portable checkpoint.
//!
//! RustCrypto remains the implementation of the compression primitive.  This
//! wrapper only owns the chaining words, byte count, and sub-block tail that
//! must cross a process restart.  It is not suitable for authenticating a
//! checkpoint supplied by an untrusted peer; callers must keep checkpoints in
//! a protected namespace and bind them to the object identity.

use sha2::{
    compress256,
    digest::{generic_array::GenericArray, typenum::U64},
};

const BLOCK_BYTES: usize = 64;
const INITIAL_STATE: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct Checkpoint {
    pub bytes_hashed: u64,
    pub state: [u32; 8],
    /// Lowercase hexadecimal encoding of the uncompressed final partial block.
    pub tail_hex: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResumableSha256 {
    bytes_hashed: u64,
    state: [u32; 8],
    tail: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CheckpointRejection {
    AheadOfPayload {
        checkpoint_bytes: u64,
        payload_bytes: u64,
    },
    Malformed(String),
}

/// Selects the furthest valid checkpoint that does not run past the payload.
///
/// Callers perform their own identity/generation checks before passing
/// checkpoints here. Keeping offset and structural selection in this module
/// makes the two-slot crash behavior testable without a filesystem.
pub fn select_newest_checkpoint(
    checkpoints: impl IntoIterator<Item = (u8, Checkpoint)>,
    payload_bytes: u64,
) -> (
    Option<(u8, ResumableSha256)>,
    Vec<(u8, CheckpointRejection)>,
) {
    let mut selected: Option<(u8, ResumableSha256)> = None;
    let mut rejected = Vec::new();
    for (slot, checkpoint) in checkpoints {
        match ResumableSha256::from_checkpoint(&checkpoint) {
            Ok(hasher) if hasher.bytes_hashed() <= payload_bytes => {
                let replace = selected
                    .as_ref()
                    .map(|(_, current)| hasher.bytes_hashed() > current.bytes_hashed())
                    .unwrap_or(true);
                if replace {
                    selected = Some((slot, hasher));
                }
            }
            Ok(hasher) => rejected.push((
                slot,
                CheckpointRejection::AheadOfPayload {
                    checkpoint_bytes: hasher.bytes_hashed(),
                    payload_bytes,
                },
            )),
            Err(error) => {
                rejected.push((slot, CheckpointRejection::Malformed(error)));
            }
        }
    }
    (selected, rejected)
}

impl Default for ResumableSha256 {
    fn default() -> Self {
        Self::new()
    }
}

impl ResumableSha256 {
    pub fn new() -> Self {
        Self {
            bytes_hashed: 0,
            state: INITIAL_STATE,
            tail: Vec::new(),
        }
    }

    pub fn from_checkpoint(checkpoint: &Checkpoint) -> Result<Self, String> {
        let tail = decode_hex(&checkpoint.tail_hex)?;
        if tail.len() >= BLOCK_BYTES {
            return Err("SHA-256 checkpoint tail is not shorter than one block".into());
        }
        if checkpoint.bytes_hashed % BLOCK_BYTES as u64 != tail.len() as u64 {
            return Err(
                "SHA-256 checkpoint byte count does not agree with its partial block".into(),
            );
        }
        Ok(Self {
            bytes_hashed: checkpoint.bytes_hashed,
            state: checkpoint.state,
            tail,
        })
    }

    pub fn checkpoint(&self) -> Checkpoint {
        Checkpoint {
            bytes_hashed: self.bytes_hashed,
            state: self.state,
            tail_hex: encode_hex(&self.tail),
        }
    }

    pub fn bytes_hashed(&self) -> u64 {
        self.bytes_hashed
    }

    pub fn update(&mut self, mut data: &[u8]) -> Result<(), String> {
        self.bytes_hashed = self
            .bytes_hashed
            .checked_add(
                u64::try_from(data.len()).map_err(|_| "SHA-256 input length does not fit u64")?,
            )
            .ok_or_else(|| "SHA-256 input length overflowed u64".to_string())?;

        if !self.tail.is_empty() {
            let take = (BLOCK_BYTES - self.tail.len()).min(data.len());
            self.tail.extend_from_slice(&data[..take]);
            data = &data[take..];
            if self.tail.len() == BLOCK_BYTES {
                compress_bytes(&mut self.state, &self.tail);
                self.tail.clear();
            }
        }

        let whole = data.len() - data.len() % BLOCK_BYTES;
        if whole != 0 {
            compress_bytes(&mut self.state, &data[..whole]);
            data = &data[whole..];
        }
        self.tail.extend_from_slice(data);
        Ok(())
    }

    pub fn finalize(mut self) -> [u8; 32] {
        let bit_len = self.bytes_hashed.wrapping_mul(8);
        let mut padding = [0u8; BLOCK_BYTES * 2];
        padding[0] = 0x80;
        let zeroes_and_marker = if self.tail.len() < 56 {
            56 - self.tail.len()
        } else {
            BLOCK_BYTES + 56 - self.tail.len()
        };
        padding[zeroes_and_marker..zeroes_and_marker + 8].copy_from_slice(&bit_len.to_be_bytes());

        self.tail
            .extend_from_slice(&padding[..zeroes_and_marker + 8]);
        debug_assert_eq!(self.tail.len() % BLOCK_BYTES, 0);
        compress_bytes(&mut self.state, &self.tail);

        let mut digest = [0u8; 32];
        for (encoded, word) in digest.chunks_exact_mut(4).zip(self.state) {
            encoded.copy_from_slice(&word.to_be_bytes());
        }
        digest
    }

    pub fn finalize_hex(self) -> String {
        encode_hex(&self.finalize())
    }
}

fn compress_bytes(state: &mut [u32; 8], bytes: &[u8]) {
    debug_assert_eq!(bytes.len() % BLOCK_BYTES, 0);
    if bytes.is_empty() {
        return;
    }
    // GenericArray<u8, U64> has the same layout and alignment as [u8; 64].
    // This is the representation guarantee used by sha2::compress256 itself.
    // Every u8 bit pattern is valid, and `bytes` is an exact number of blocks.
    let blocks = unsafe {
        std::slice::from_raw_parts(
            bytes.as_ptr().cast::<GenericArray<u8, U64>>(),
            bytes.len() / BLOCK_BYTES,
        )
    };
    compress256(state, blocks);
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

fn decode_hex(encoded: &str) -> Result<Vec<u8>, String> {
    if encoded.len() % 2 != 0 {
        return Err("SHA-256 checkpoint tail has odd-length hexadecimal".into());
    }
    encoded
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = hex_nibble(pair[0])?;
            let low = hex_nibble(pair[1])?;
            Ok((high << 4) | low)
        })
        .collect()
}

fn hex_nibble(byte: u8) -> Result<u8, String> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err("SHA-256 checkpoint tail is not lowercase hexadecimal".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest as _, Sha256};

    fn reference(input: &[u8]) -> String {
        format!("{:x}", Sha256::digest(input))
    }

    #[test]
    fn standard_vectors_match_rustcrypto() {
        for input in [
            &b""[..],
            &b"abc"[..],
            &b"The quick brown fox jumps over the lazy dog"[..],
            &b"The quick brown fox jumps over the lazy dog."[..],
        ] {
            let mut actual = ResumableSha256::new();
            actual.update(input).unwrap();
            assert_eq!(actual.finalize_hex(), reference(input));
        }
    }

    #[test]
    fn every_boundary_and_segmentation_matches_rustcrypto() {
        let input: Vec<u8> = (0usize..4097)
            .map(|index| (index.wrapping_mul(131) ^ (index >> 3)) as u8)
            .collect();
        for len in 0..=257 {
            for segment in [1, 3, 7, 63, 64, 65, 127] {
                let mut actual = ResumableSha256::new();
                for chunk in input[..len].chunks(segment) {
                    actual.update(chunk).unwrap();
                }
                assert_eq!(actual.finalize_hex(), reference(&input[..len]));
            }
        }
    }

    #[test]
    fn checkpoint_round_trip_resumes_at_partial_blocks() {
        let input: Vec<u8> = (0usize..8193)
            .map(|index| (index.wrapping_mul(17) ^ (index >> 2)) as u8)
            .collect();
        for split in [0, 1, 55, 56, 63, 64, 65, 127, 4096, 8192] {
            let mut before = ResumableSha256::new();
            before.update(&input[..split]).unwrap();
            let checkpoint = before.checkpoint();
            let json = serde_json::to_vec(&checkpoint).unwrap();
            let decoded: Checkpoint = serde_json::from_slice(&json).unwrap();
            let mut resumed = ResumableSha256::from_checkpoint(&decoded).unwrap();
            resumed.update(&input[split..]).unwrap();
            assert_eq!(resumed.finalize_hex(), reference(&input));
        }
    }

    #[test]
    fn malformed_checkpoint_is_rejected() {
        let valid = Checkpoint {
            bytes_hashed: 1,
            state: INITIAL_STATE,
            tail_hex: "00".into(),
        };
        assert!(ResumableSha256::from_checkpoint(&valid).is_ok());
        for tail_hex in ["0", "GG", &"00".repeat(64)] {
            let invalid = Checkpoint {
                tail_hex: tail_hex.into(),
                ..valid.clone()
            };
            assert!(ResumableSha256::from_checkpoint(&invalid).is_err());
        }
        let wrong_length = Checkpoint {
            bytes_hashed: 2,
            ..valid
        };
        assert!(ResumableSha256::from_checkpoint(&wrong_length).is_err());
    }

    #[test]
    fn alternating_slot_recovery_survives_torn_or_ahead_new_state() {
        let input = vec![0x5a; 257];
        let mut older = ResumableSha256::new();
        older.update(&input[..64]).unwrap();
        let mut newer = older.clone();
        newer.update(&input[64..129]).unwrap();

        // A torn slot is absent because its JSON could not be decoded. The
        // prior slot remains a complete recovery point.
        let (selected, rejected) =
            select_newest_checkpoint([(0, older.checkpoint())], input.len() as u64);
        assert!(rejected.is_empty());
        assert_eq!(selected.unwrap().1.bytes_hashed(), 64);

        // Once the inactive slot is complete, it wins regardless of enumeration
        // order.
        let (selected, rejected) = select_newest_checkpoint(
            [(1, newer.checkpoint()), (0, older.checkpoint())],
            input.len() as u64,
        );
        assert!(rejected.is_empty());
        assert_eq!(selected.unwrap().1.bytes_hashed(), 129);

        // If metadata reaches disk ahead of its payload, recovery rejects it
        // and retains the older slot.
        let (selected, rejected) =
            select_newest_checkpoint([(0, older.checkpoint()), (1, newer.checkpoint())], 96);
        assert_eq!(selected.unwrap().1.bytes_hashed(), 64);
        assert_eq!(
            rejected,
            vec![(
                1,
                CheckpointRejection::AheadOfPayload {
                    checkpoint_bytes: 129,
                    payload_bytes: 96,
                }
            )]
        );
    }

    #[test]
    fn malformed_new_slot_does_not_mask_previous_slot() {
        let mut older = ResumableSha256::new();
        older.update(&[7; 64]).unwrap();
        let malformed = Checkpoint {
            bytes_hashed: 65,
            state: INITIAL_STATE,
            tail_hex: String::new(),
        };
        let (selected, rejected) =
            select_newest_checkpoint([(0, older.checkpoint()), (1, malformed)], 65);
        assert_eq!(selected.unwrap().1.bytes_hashed(), 64);
        assert!(matches!(
            rejected.as_slice(),
            [(1, CheckpointRejection::Malformed(_))]
        ));
    }
}

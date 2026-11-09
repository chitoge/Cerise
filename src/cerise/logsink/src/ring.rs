//! Pure validation and decoding for mediated-write ring-buffer snapshots.

use std::fmt;

pub const RECORD_HEADER_LEN: usize = 16;
const RECORD_ALIGNMENT: usize = 8;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RingError {
    ZeroCapacity,
    HeadBehindPosition {
        position: u64,
        head: u64,
    },
    WindowDoesNotFitUsize {
        available: u64,
    },
    WindowExceedsCapacity {
        available: usize,
        capacity: usize,
    },
    CopyExceedsCapacity {
        length: usize,
        capacity: usize,
    },
    SnapshotExceedsCapacity {
        length: usize,
        capacity: usize,
    },
    LengthDoesNotFitUsize {
        offset: usize,
        length: u64,
    },
    LengthPaddingOverflow {
        offset: usize,
        length: usize,
    },
    EnvelopeOverflow {
        offset: usize,
        padded_length: usize,
    },
    EnvelopeExceedsCapacity {
        offset: usize,
        envelope: usize,
        capacity: usize,
    },
    OffsetOverflow {
        offset: usize,
    },
}

impl fmt::Display for RingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroCapacity => write!(f, "ring capacity is zero"),
            Self::HeadBehindPosition { position, head } => {
                write!(f, "ring head {head} is behind reader position {position}")
            }
            Self::WindowDoesNotFitUsize { available } => {
                write!(f, "ring window of {available} bytes does not fit usize")
            }
            Self::WindowExceedsCapacity {
                available,
                capacity,
            } => write!(
                f,
                "ring window of {available} bytes exceeds capacity {capacity}",
            ),
            Self::CopyExceedsCapacity { length, capacity } => {
                write!(f, "ring copy of {length} bytes exceeds capacity {capacity}")
            }
            Self::SnapshotExceedsCapacity { length, capacity } => {
                write!(
                    f,
                    "snapshot of {length} bytes exceeds ring capacity {capacity}"
                )
            }
            Self::LengthDoesNotFitUsize { offset, length } => write!(
                f,
                "record at byte {offset} declares length {length}, which does not fit usize",
            ),
            Self::LengthPaddingOverflow { offset, length } => write!(
                f,
                "record at byte {offset} length {length} overflows alignment padding",
            ),
            Self::EnvelopeOverflow {
                offset,
                padded_length,
            } => write!(
                f,
                "record at byte {offset} padded length {padded_length} overflows its envelope",
            ),
            Self::EnvelopeExceedsCapacity {
                offset,
                envelope,
                capacity,
            } => write!(
                f,
                "record at byte {offset} envelope {envelope} exceeds ring capacity {capacity}",
            ),
            Self::OffsetOverflow { offset } => {
                write!(f, "record at byte {offset} overflows snapshot offsets")
            }
        }
    }
}

impl std::error::Error for RingError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CopyPlan {
    pub first_start: usize,
    pub first_len: usize,
    pub second_len: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RingRecord {
    pub tag: u64,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedBatch {
    pub records: Vec<RingRecord>,
    /// Bytes occupied by complete records at the start of the snapshot.
    pub consumed: usize,
    /// The snapshot ended partway through a header or record.
    pub incomplete: bool,
}

/// Validate the monotonic reader-to-writer window before touching mapped data.
pub fn validate_window(position: u64, head: u64, capacity: usize) -> Result<usize, RingError> {
    if capacity == 0 {
        return Err(RingError::ZeroCapacity);
    }
    let available = head
        .checked_sub(position)
        .ok_or(RingError::HeadBehindPosition { position, head })?;
    let available =
        usize::try_from(available).map_err(|_| RingError::WindowDoesNotFitUsize { available })?;
    if available > capacity {
        return Err(RingError::WindowExceedsCapacity {
            available,
            capacity,
        });
    }
    Ok(available)
}

/// Plan a bounded copy from a wrapping ring into a linear snapshot.
pub fn plan_wrapped_copy(
    capacity: usize,
    position: u64,
    length: usize,
) -> Result<CopyPlan, RingError> {
    if capacity == 0 {
        return Err(RingError::ZeroCapacity);
    }
    if length > capacity {
        return Err(RingError::CopyExceedsCapacity { length, capacity });
    }
    let capacity_u64 = u64::try_from(capacity).map_err(|_| RingError::WindowDoesNotFitUsize {
        available: u64::MAX,
    })?;
    let first_start =
        usize::try_from(position % capacity_u64).map_err(|_| RingError::WindowDoesNotFitUsize {
            available: position,
        })?;
    let first_len = length.min(capacity - first_start);
    Ok(CopyPlan {
        first_start,
        first_len,
        second_len: length - first_len,
    })
}

/// Decode complete record envelopes from a linear snapshot of the unread ring window.
///
/// The caller supplies the full ring capacity separately so a forged length cannot be
/// accepted merely because a short snapshot happens to end before the claimed record.
pub fn decode_snapshot(snapshot: &[u8], capacity: usize) -> Result<DecodedBatch, RingError> {
    if capacity == 0 {
        return Err(RingError::ZeroCapacity);
    }
    if snapshot.len() > capacity {
        return Err(RingError::SnapshotExceedsCapacity {
            length: snapshot.len(),
            capacity,
        });
    }

    let mut records = Vec::new();
    let mut cursor = 0usize;
    let mut incomplete = false;

    while cursor < snapshot.len() {
        let remaining = snapshot
            .len()
            .checked_sub(cursor)
            .ok_or(RingError::OffsetOverflow { offset: cursor })?;
        if remaining < RECORD_HEADER_LEN {
            incomplete = true;
            break;
        }

        let tag_end = cursor
            .checked_add(8)
            .ok_or(RingError::OffsetOverflow { offset: cursor })?;
        let length_end = cursor
            .checked_add(RECORD_HEADER_LEN)
            .ok_or(RingError::OffsetOverflow { offset: cursor })?;
        let tag = u64::from_le_bytes(
            snapshot
                .get(cursor..tag_end)
                .ok_or(RingError::OffsetOverflow { offset: cursor })?
                .try_into()
                .map_err(|_| RingError::OffsetOverflow { offset: cursor })?,
        );
        let payload_len_u64 = u64::from_le_bytes(
            snapshot
                .get(tag_end..length_end)
                .ok_or(RingError::OffsetOverflow { offset: cursor })?
                .try_into()
                .map_err(|_| RingError::OffsetOverflow { offset: cursor })?,
        );
        let payload_len =
            usize::try_from(payload_len_u64).map_err(|_| RingError::LengthDoesNotFitUsize {
                offset: cursor,
                length: payload_len_u64,
            })?;
        let padded_len = payload_len.checked_add(RECORD_ALIGNMENT - 1).ok_or(
            RingError::LengthPaddingOverflow {
                offset: cursor,
                length: payload_len,
            },
        )? & !(RECORD_ALIGNMENT - 1);
        let envelope =
            RECORD_HEADER_LEN
                .checked_add(padded_len)
                .ok_or(RingError::EnvelopeOverflow {
                    offset: cursor,
                    padded_length: padded_len,
                })?;
        if envelope > capacity {
            return Err(RingError::EnvelopeExceedsCapacity {
                offset: cursor,
                envelope,
                capacity,
            });
        }
        if remaining < envelope {
            incomplete = true;
            break;
        }

        let payload_end = length_end
            .checked_add(payload_len)
            .ok_or(RingError::OffsetOverflow { offset: cursor })?;
        let payload = snapshot
            .get(length_end..payload_end)
            .ok_or(RingError::OffsetOverflow { offset: cursor })?
            .to_vec();
        records.push(RingRecord { tag, payload });
        cursor = cursor
            .checked_add(envelope)
            .ok_or(RingError::OffsetOverflow { offset: cursor })?;
    }

    Ok(DecodedBatch {
        records,
        consumed: cursor,
        incomplete,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn envelope(tag: u64, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&tag.to_le_bytes());
        out.extend_from_slice(&(payload.len() as u64).to_le_bytes());
        out.extend_from_slice(payload);
        while out.len() % RECORD_ALIGNMENT != 0 {
            out.push(0);
        }
        out
    }

    fn apply_plan(ring: &[u8], plan: CopyPlan) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&ring[plan.first_start..plan.first_start + plan.first_len]);
        out.extend_from_slice(&ring[..plan.second_len]);
        out
    }

    #[test]
    fn window_validation_rejects_reversal_and_overrun() {
        assert_eq!(validate_window(9, 9, 32), Ok(0));
        assert_eq!(validate_window(9, 17, 32), Ok(8));
        assert!(matches!(
            validate_window(10, 9, 32),
            Err(RingError::HeadBehindPosition { .. })
        ));
        assert!(matches!(
            validate_window(0, 33, 32),
            Err(RingError::WindowExceedsCapacity { .. })
        ));
        assert_eq!(validate_window(0, 0, 0), Err(RingError::ZeroCapacity));
    }

    #[test]
    fn wrapped_copy_plan_never_reads_past_capacity() {
        let ring: Vec<u8> = (0..8).collect();
        let plan = plan_wrapped_copy(ring.len(), 6, 5).unwrap();
        assert_eq!(
            plan,
            CopyPlan {
                first_start: 6,
                first_len: 2,
                second_len: 3
            }
        );
        assert_eq!(apply_plan(&ring, plan), vec![6, 7, 0, 1, 2]);
        assert!(matches!(
            plan_wrapped_copy(8, 0, 9),
            Err(RingError::CopyExceedsCapacity { .. })
        ));
    }

    #[test]
    fn decodes_multiple_records_and_discards_padding() {
        let mut bytes = envelope(7, b"abc");
        bytes.extend_from_slice(&envelope(9, b"eight888"));
        let batch = decode_snapshot(&bytes, 128).unwrap();
        assert!(!batch.incomplete);
        assert_eq!(batch.consumed, bytes.len());
        assert_eq!(
            batch.records,
            vec![
                RingRecord {
                    tag: 7,
                    payload: b"abc".to_vec()
                },
                RingRecord {
                    tag: 9,
                    payload: b"eight888".to_vec()
                },
            ]
        );
    }

    #[test]
    fn incomplete_header_or_body_is_left_unconsumed() {
        let full = envelope(1, b"payload");
        let short_header = decode_snapshot(&full[..8], 64).unwrap();
        assert!(short_header.incomplete);
        assert_eq!(short_header.consumed, 0);

        let short_body = decode_snapshot(&full[..RECORD_HEADER_LEN + 2], 64).unwrap();
        assert!(short_body.incomplete);
        assert_eq!(short_body.consumed, 0);

        let mut first_then_partial = envelope(2, b"ok");
        let consumed = first_then_partial.len();
        first_then_partial.extend_from_slice(&full[..10]);
        let batch = decode_snapshot(&first_then_partial, 128).unwrap();
        assert!(batch.incomplete);
        assert_eq!(batch.consumed, consumed);
        assert_eq!(batch.records.len(), 1);
    }

    #[test]
    fn rejects_lengths_that_overflow_or_cannot_fit_the_ring() {
        let mut overflow = Vec::new();
        overflow.extend_from_slice(&0u64.to_le_bytes());
        overflow.extend_from_slice(&u64::MAX.to_le_bytes());
        assert!(matches!(
            decode_snapshot(&overflow, 64),
            Err(RingError::LengthDoesNotFitUsize { .. })
                | Err(RingError::LengthPaddingOverflow { .. })
        ));

        let mut too_large = Vec::new();
        too_large.extend_from_slice(&0u64.to_le_bytes());
        too_large.extend_from_slice(&49u64.to_le_bytes());
        assert!(matches!(
            decode_snapshot(&too_large, 64),
            Err(RingError::EnvelopeExceedsCapacity { .. })
        ));
    }

    #[test]
    fn rejects_snapshot_larger_than_ring() {
        assert!(matches!(
            decode_snapshot(&[0; 17], 16),
            Err(RingError::SnapshotExceedsCapacity { .. })
        ));
    }
}

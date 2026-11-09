//! Planning and exact slicing for byte ranges over block-aligned sources.
//!
//! The file-server API is byte-addressed, while the underlying object handle
//! requires an aligned read offset.  Keep that adaptation small and separate
//! from the storage mount so it can be tested without a device.

use std::future::Future;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ReadPlan {
    pub(crate) aligned_offset: u64,
    pub(crate) head: usize,
    pub(crate) requested_len: usize,
    pub(crate) physical_len: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PlanError {
    ZeroBlockSize,
    OffsetOverflow,
    LengthOverflow,
}

impl std::fmt::Display for PlanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ZeroBlockSize => f.write_str("file block size is zero"),
            Self::OffsetOverflow => f.write_str("read offset + length overflowed"),
            Self::LengthOverflow => f.write_str("requested read does not fit this process"),
        }
    }
}

/// Plans one bounded physical read for a logical byte range.
pub(crate) fn plan(
    size: u64,
    offset: u64,
    length: u64,
    block_size: u64,
) -> Result<Option<ReadPlan>, PlanError> {
    if block_size == 0 {
        return Err(PlanError::ZeroBlockSize);
    }
    if offset >= size {
        return Ok(None);
    }
    let end = if length == 0 {
        size
    } else {
        offset
            .checked_add(length)
            .ok_or(PlanError::OffsetOverflow)?
            .min(size)
    };
    let requested_len = usize::try_from(end - offset).map_err(|_| PlanError::LengthOverflow)?;
    let aligned_offset = offset - offset % block_size;
    let head = usize::try_from(offset - aligned_offset).map_err(|_| PlanError::LengthOverflow)?;
    let requested_physical_len = head
        .checked_add(requested_len)
        .ok_or(PlanError::LengthOverflow)?;
    let block = usize::try_from(block_size).map_err(|_| PlanError::LengthOverflow)?;
    let physical_len = requested_physical_len
        .checked_add(block - 1)
        .and_then(|length| length.checked_div(block))
        .and_then(|blocks| blocks.checked_mul(block))
        .ok_or(PlanError::LengthOverflow)?;
    Ok(Some(ReadPlan {
        aligned_offset,
        head,
        requested_len,
        physical_len,
    }))
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ReadError<E> {
    Source(E),
    ShortRead { expected: usize, actual: usize },
    OverRead { maximum: usize, actual: usize },
}

/// Runs the source read and returns exactly the requested logical range.
///
/// The source is called once at an aligned offset.  A result may be shorter
/// than the physical buffer only when it still covers the requested logical
/// suffix at EOF.  A shorter result is rejected instead of retrying at a now-
/// unaligned continuation offset.
pub(crate) async fn read_exact<F, Fut, E>(
    plan: ReadPlan,
    source: F,
) -> Result<Vec<u8>, ReadError<E>>
where
    F: FnOnce(u64, usize) -> Fut,
    Fut: Future<Output = Result<Vec<u8>, E>>,
{
    let mut bytes = source(plan.aligned_offset, plan.physical_len)
        .await
        .map_err(ReadError::Source)?;
    let required_len = plan.head + plan.requested_len;
    if bytes.len() < required_len {
        return Err(ReadError::ShortRead {
            expected: required_len,
            actual: bytes.len(),
        });
    }
    if bytes.len() > plan.physical_len {
        return Err(ReadError::OverRead {
            maximum: plan.physical_len,
            actual: bytes.len(),
        });
    }
    if plan.head != 0 {
        bytes.copy_within(plan.head..required_len, 0);
    }
    bytes.truncate(plan.requested_len);
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source(offset: u64, len: usize) -> Vec<u8> {
        (0..len)
            .map(|index| {
                let value = (offset + index as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15);
                (value >> 56) as u8
            })
            .collect()
    }

    fn source_in_server_chunks(offset: u64, len: usize) -> Vec<u8> {
        const SERVER_CHUNK: usize = 64 * 1024;
        let mut bytes = Vec::with_capacity(len);
        let mut at = 0;
        while at < len {
            let chunk_len = (len - at).min(SERVER_CHUNK);
            bytes.extend_from_slice(&source(offset + at as u64, chunk_len));
            at += chunk_len;
        }
        bytes
    }

    #[test]
    fn unaligned_large_range_uses_one_aligned_source_read() {
        let block = 4096;
        let offset = 2_031_532;
        let length = 2_031_532;
        let plan = plan(99_145_356, offset, length, block).unwrap().unwrap();
        assert_eq!(plan.aligned_offset, 2_027_520);
        assert_eq!(plan.head, 4_012);
        assert_eq!(plan.requested_len, length as usize);
        assert_eq!(plan.physical_len, 2_035_712);

        let mut seen = None;
        let got = futures::executor::block_on(read_exact(plan, |source_offset, source_len| {
            seen = Some((source_offset, source_len));
            async move { Ok::<_, ()>(source_in_server_chunks(source_offset, source_len)) }
        }))
        .unwrap();
        assert_eq!(seen, Some((2_027_520, 2_035_712)));
        assert_eq!(got, source(offset, length as usize));
    }

    #[test]
    fn offset_one_and_aligned_ranges_are_exact() {
        for (offset, length) in [(1, 1000), (2 * 1024 * 1024, 2 * 1024 * 1024)] {
            let plan = plan(8 * 1024 * 1024, offset, length, 4096)
                .unwrap()
                .unwrap();
            let got = futures::executor::block_on(read_exact(plan, |source_offset, source_len| {
                async move { Ok::<_, ()>(source(source_offset, source_len)) }
            }))
            .unwrap();
            assert_eq!(got, source(offset, length as usize));
        }
    }

    #[test]
    fn exact_extraction_reuses_the_source_vec_allocation() {
        let plan = plan(8192, 17, 1000, 4096).unwrap().unwrap();
        let bytes = source(plan.aligned_offset, plan.physical_len);
        let pointer = bytes.as_ptr();
        let capacity = bytes.capacity();
        let got = futures::executor::block_on(read_exact(plan, |_, _| async move {
            Ok::<_, ()>(bytes)
        }))
        .unwrap();
        assert_eq!(got, source(17, 1000));
        assert_eq!(got.as_ptr(), pointer);
        assert_eq!(got.capacity(), capacity);
    }

    #[test]
    fn logical_server_chunks_keep_source_reads_aligned() {
        const SERVER_CHUNK: u64 = 64 * 1024;
        let logical_offset = 2_031_532;
        let logical_len = SERVER_CHUNK * 3 + 17;
        let file_size = 8 * 1024 * 1024;
        let mut got = Vec::new();
        let mut at = 0;
        while at < logical_len {
            let chunk_len = (logical_len - at).min(SERVER_CHUNK);
            let chunk_offset = logical_offset + at;
            let plan = plan(file_size, chunk_offset, chunk_len, 4096)
                .unwrap()
                .unwrap();
            let chunk = futures::executor::block_on(read_exact(
                plan,
                |source_offset, source_len| async move {
                    assert_eq!(source_offset % 4096, 0);
                    assert_eq!(source_len % 4096, 0);
                    Ok::<_, ()>(source(source_offset, source_len))
                },
            ))
            .unwrap();
            got.extend_from_slice(&chunk);
            at += chunk_len;
        }
        assert_eq!(got, source(logical_offset, logical_len as usize));
    }

    #[test]
    fn eof_is_clamped_and_truncation_is_rejected() {
        let plan = plan(100, 99, 10, 4096).unwrap().unwrap();
        let got = futures::executor::block_on(read_exact(plan, |source_offset, _| {
            let required_len = plan.head + plan.requested_len;
            async move { Ok::<_, ()>(source(source_offset, required_len)) }
        }))
        .unwrap();
        assert_eq!(got, source(99, 1));

        let error = futures::executor::block_on(read_exact(plan, |_, _| async {
            Ok::<_, ()>(vec![0; 99])
        }))
        .unwrap_err();
        assert_eq!(
            error,
            ReadError::ShortRead {
                expected: plan.head + plan.requested_len,
                actual: 99,
            }
        );
        assert_eq!(super::plan(100, 100, 1, 4096).unwrap(), None);
        let to_eof = super::plan(100, 1, 0, 4096).unwrap().unwrap();
        let got = futures::executor::block_on(read_exact(to_eof, |source_offset, source_len| {
            async move { Ok::<_, ()>(source(source_offset, source_len)) }
        }))
        .unwrap();
        assert_eq!(got, source(1, 99));
        assert_eq!(
            super::plan(u64::MAX, u64::MAX - 1, 4, 4096),
            Err(PlanError::OffsetOverflow)
        );
    }

    #[test]
    fn source_errors_are_preserved() {
        let plan = plan(4096, 1, 2, 4096).unwrap().unwrap();
        let error = futures::executor::block_on(read_exact(plan, |_, _| async {
            Err::<Vec<u8>, _>("source failed")
        }))
        .unwrap_err();
        assert_eq!(error, ReadError::Source("source failed"));
    }
}

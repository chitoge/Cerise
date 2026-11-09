//! Streaming writes of verified payloads into an Fxfs blob volume.

#![forbid(unsafe_code)]

use anyhow::{Context as _, Result, anyhow};
use fidl_fuchsia_fxfs::BlobCreatorProxy;
use std::io::Read;

const COPY_CHUNK_BYTES: usize = 64 << 10;

/// Write an uncompressed Type-1 delivery stream without materializing it.
pub async fn write_uncompressed<R: Read>(
    creator: &BlobCreatorProxy,
    hash: &[u8; 32],
    payload: R,
    payload_length: u64,
) -> Result<()> {
    let mut delivery = delivery_blob::UncompressedType1Reader::new(payload, payload_length);
    let total = delivery
        .delivery_length()
        .ok_or_else(|| anyhow!("delivery-blob length overflow"))?;
    let writer = creator
        .create(hash, /* allow_existing = */ true)
        .await
        .context("BlobCreator.Create transport")?
        .map_err(|error| anyhow!("BlobCreator.Create error: {error:?}"))?
        .into_proxy();
    let vmo = writer
        .get_vmo(total)
        .await
        .context("BlobWriter.GetVmo transport")?
        .map_err(|status| anyhow!("BlobWriter.GetVmo error: {status}"))?;
    let ring = vmo.get_size().context("ring VMO size")?;
    if ring == 0 {
        return Err(anyhow!("server returned zero-size ring VMO"));
    }

    let mut scratch = [0u8; COPY_CHUNK_BYTES];
    let mut written = 0u64;
    while written < total {
        let offset = written % ring;
        let contiguous = ring - offset;
        let wanted = usize::try_from(contiguous.min(total - written))
            .unwrap_or(usize::MAX)
            .min(scratch.len());
        let read = delivery
            .read(&mut scratch[..wanted])
            .context("read Type-1 delivery stream")?;
        if read == 0 {
            return Err(anyhow!(
                "delivery stream ended after {written} of {total} bytes"
            ));
        }
        vmo.write(&scratch[..read], offset)
            .context("write into BlobWriter ring VMO")?;
        writer
            .bytes_ready(read as u64)
            .await
            .context("BlobWriter.BytesReady transport")?
            .map_err(|status| anyhow!("BlobWriter.BytesReady error: {status}"))?;
        written = written
            .checked_add(read as u64)
            .ok_or_else(|| anyhow!("delivery write length overflow"))?;
    }
    Ok(())
}

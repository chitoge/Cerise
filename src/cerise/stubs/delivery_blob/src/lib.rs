// Cerise: delivery_blob types + a REAL uncompressed Type-1 generator.
//
// History: this started as a pure type-stub so fuchsia-pkg's error/manifest modules
// compile without pulling the full upstream compression stack (rayon/zstd). It later
// added a genuine, byte-accurate RFC-0207 Type-1 *uncompressed*
// delivery-blob generator — the exact bytes fxfs's `BlobCreator`/`BlobWriter` accept —
// so the on-target package-ingestion path (pkg_probe -> fuchsia.fxfs.BlobCreator) can
// write real blobs into the fxfs `blob` volume WITHOUT dragging the zstd C-lib into a
// fuchsia-target binary.
//
// STILL FAIL-LOUD (deliberately absent, no consumer on the new path needs them):
//   * `decompress` / `decompressed_size_from_reader` — fxfs decompresses on its OWN read
//     path; we only ever WRITE uncompressed (CompressionMode::Never equivalent), so the
//     read side never runs through this crate. Left returning DecompressError.
//   * zstd/lz4 COMPRESSION — `generate_uncompressed_type1` is uncompressed-only. Compression
//     is a future milestone; no Cerise consumer needs it yet.
//
// The uncompressed Type-1 wire format (mirrors the vendored
// src/upstream/fuchsia/src/storage/lib/delivery_blob/src/{lib.rs,format.rs}
// `SerializedType1Blob` + `Type1Blob::generate(_, CompressionMode::Never)`), 28-byte
// metadata header then the raw payload, all little-endian:
//   magic[4] = 0xfc 0x1a 0xb1 0x0b | delivery_type u32 =1 | header_length u32 =28
//   payload_length u64 | checksum u32 (CRC-32/ISO-HDLC over the 28 bytes w/ checksum=0)
//   flags u32 =0 (bit0 IS_COMPRESSED clear) | <raw payload bytes...>

/// Type of delivery blob encoding (stub: only type 1 exists in practice).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[repr(u32)]
pub enum DeliveryBlobType {
    Type1 = 1,
}

impl From<DeliveryBlobType> for u32 {
    fn from(t: DeliveryBlobType) -> u32 {
        t as u32
    }
}

/// Error returned when decompressing a delivery blob.
#[derive(Debug, thiserror::Error)]
#[error("delivery_blob stub: DecompressError")]
pub struct DecompressError;

/// Decompress a delivery blob (stub: always fails with NOT_SUPPORTED).
pub fn decompress(_data: &[u8]) -> Result<Vec<u8>, DecompressError> {
    Err(DecompressError)
}

/// Return the decompressed size from a reader (stub: always fails).
pub fn decompressed_size_from_reader<R: std::io::Read>(_reader: R) -> Result<u64, DecompressError> {
    Err(DecompressError)
}

/// Write a delivery blob to a writer (stub: always fails — compression path unimplemented).
pub fn generate_to<W: std::io::Write>(
    _blob_type: DeliveryBlobType,
    _data: &[u8],
    _dest: &W,
) -> Result<(), DecompressError> {
    Err(DecompressError)
}

// ── REAL: uncompressed RFC-0207 Type-1 delivery-blob generator ──────────────

/// Delivery-blob magic number ("Fuchsia Blob", big-endian), from format.rs.
const DELIVERY_BLOB_MAGIC: [u8; 4] = [0xfc, 0x1a, 0xb1, 0x0b];
/// Serialized Type-1 metadata header length in bytes (size_of::<SerializedType1Blob>()).
const TYPE1_HEADER_LEN: u32 = 28;

/// Construct the metadata header for an uncompressed Type-1 delivery stream.
///
/// Callers that already hold a bounded reader can write this header followed
/// by payload chunks, avoiding a second payload-sized allocation.
pub fn uncompressed_type1_header(payload_length: u64) -> [u8; TYPE1_HEADER_LEN as usize] {
    let mut meta = [0u8; TYPE1_HEADER_LEN as usize];
    meta[0..4].copy_from_slice(&DELIVERY_BLOB_MAGIC);
    meta[4..8].copy_from_slice(&u32::from(DeliveryBlobType::Type1).to_le_bytes());
    meta[8..12].copy_from_slice(&TYPE1_HEADER_LEN.to_le_bytes());
    meta[12..20].copy_from_slice(&payload_length.to_le_bytes());
    // bytes 20..24 remain zero while the checksum is calculated; bytes
    // 24..28 are zero flags (uncompressed).
    let crc = crc::Crc::<u32>::new(&crc::CRC_32_ISO_HDLC);
    let checksum = crc.checksum(&meta);
    meta[20..24].copy_from_slice(&checksum.to_le_bytes());
    meta
}

/// A bounded reader for one uncompressed Type-1 delivery stream.
///
/// The reader emits the metadata header first and then exactly
/// `payload_length` bytes from `payload`. An early payload EOF is an error, and
/// bytes beyond the declared payload length are never consumed. This lets an
/// async Fxfs writer use an ordinary fixed-size scratch buffer without first
/// materializing the complete delivery blob.
pub struct UncompressedType1Reader<R> {
    header: std::io::Cursor<[u8; TYPE1_HEADER_LEN as usize]>,
    payload: std::io::Take<R>,
    payload_length: u64,
}

impl<R: std::io::Read> UncompressedType1Reader<R> {
    pub fn new(payload: R, payload_length: u64) -> Self {
        Self {
            header: std::io::Cursor::new(uncompressed_type1_header(payload_length)),
            payload: payload.take(payload_length),
            payload_length,
        }
    }

    /// Total delivery-stream length supplied to `BlobCreator.Create`.
    pub fn delivery_length(&self) -> Option<u64> {
        u64::from(TYPE1_HEADER_LEN).checked_add(self.payload_length)
    }
}

impl<R: std::io::Read> std::io::Read for UncompressedType1Reader<R> {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        if self.header.position() < u64::from(TYPE1_HEADER_LEN) {
            return self.header.read(out);
        }
        if self.payload.limit() == 0 {
            return Ok(0);
        }
        let read = self.payload.read(out)?;
        if read == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "delivery-blob payload ended before its declared length",
            ));
        }
        Ok(read)
    }
}

/// Generate a byte-accurate **uncompressed** Type-1 delivery blob for `data` — the exact
/// bytes fxfs's `BlobWriter` expects (equivalent to the vendored
/// `Type1Blob::generate(data, CompressionMode::Never)`). The returned Vec is the full
/// delivery-blob stream: 28-byte metadata header (with a real CRC-32/ISO-HDLC checksum)
/// followed by the raw payload. `is_compressed` is always false.
///
/// The merkle root that identifies the blob (passed to `BlobCreator.Create`) is computed
/// over the ORIGINAL `data`, not over this stream — the delivery blob is only the transport
/// encoding; see fuchsia_merkle::root_from_slice at the call site.
pub fn generate_uncompressed_type1(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(TYPE1_HEADER_LEN as usize + data.len());
    out.extend_from_slice(&uncompressed_type1_header(data.len() as u64));
    out.extend_from_slice(data);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uncompressed_type1_layout_and_checksum() {
        let data: &[u8] = &[1, 2, 3, 4];
        let blob = generate_uncompressed_type1(data);
        // 28-byte header + payload.
        assert_eq!(blob.len(), TYPE1_HEADER_LEN as usize + data.len());
        assert_eq!(&blob[0..4], &DELIVERY_BLOB_MAGIC);
        assert_eq!(u32::from_le_bytes(blob[4..8].try_into().unwrap()), 1); // Type1
        assert_eq!(
            u32::from_le_bytes(blob[8..12].try_into().unwrap()),
            TYPE1_HEADER_LEN
        );
        assert_eq!(
            u64::from_le_bytes(blob[12..20].try_into().unwrap()),
            data.len() as u64
        );
        assert_eq!(u32::from_le_bytes(blob[24..28].try_into().unwrap()), 0); // flags: uncompressed
        assert_eq!(&blob[28..], data); // raw payload appended verbatim
        // Recompute the checksum over the header with its checksum field zeroed and confirm.
        let mut header = blob[0..28].to_vec();
        header[20..24].copy_from_slice(&0u32.to_le_bytes());
        let crc = crc::Crc::<u32>::new(&crc::CRC_32_ISO_HDLC);
        assert_eq!(
            u32::from_le_bytes(blob[20..24].try_into().unwrap()),
            crc.checksum(&header)
        );
    }

    #[test]
    fn empty_blob_is_header_only() {
        let blob = generate_uncompressed_type1(&[]);
        assert_eq!(blob.len(), TYPE1_HEADER_LEN as usize);
        assert_eq!(u64::from_le_bytes(blob[12..20].try_into().unwrap()), 0);
    }

    #[test]
    fn streaming_header_matches_the_buffered_generator() {
        let payload = b"payload split into independent chunks";
        let buffered = generate_uncompressed_type1(payload);
        assert_eq!(
            &buffered[..TYPE1_HEADER_LEN as usize],
            &uncompressed_type1_header(payload.len() as u64)
        );
        assert_eq!(&buffered[TYPE1_HEADER_LEN as usize..], payload);
    }

    #[test]
    fn streaming_reader_matches_buffered_bytes_and_stops_at_declared_length() {
        use std::io::Read;

        let payload = b"payload plus ignored suffix";
        let declared = 7;
        let mut stream = UncompressedType1Reader::new(&payload[..], declared);
        assert_eq!(
            stream.delivery_length(),
            Some(u64::from(TYPE1_HEADER_LEN) + declared)
        );
        let mut streamed = Vec::new();
        stream.read_to_end(&mut streamed).unwrap();
        assert_eq!(
            stream.delivery_length(),
            Some(u64::from(TYPE1_HEADER_LEN) + declared)
        );
        assert_eq!(
            streamed,
            generate_uncompressed_type1(&payload[..declared as usize])
        );
    }

    #[test]
    fn streaming_reader_rejects_truncated_payload() {
        use std::io::Read;

        let mut stream = UncompressedType1Reader::new(&b"short"[..], 6);
        let mut streamed = Vec::new();
        let error = stream.read_to_end(&mut streamed).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::UnexpectedEof);
    }
}

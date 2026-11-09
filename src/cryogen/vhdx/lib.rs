//! VHDX disk-image reader: resolves a virtual disk's *logical* contents without
//! materializing it.
//!
//! A dynamic VHDX stores only the regions a guest has actually written. A 64 GiB
//! disk holding a few hundred MiB of data is a few hundred MiB on disk, and the
//! rest is described — not stored — by a block allocation table (BAT) that marks
//! those regions absent. Reading such an image logically therefore means
//! consulting the BAT and *synthesizing* zeros for absent blocks, which is what
//! lets an ingest pass over a 64 GiB disk touch only its allocated bytes.
//!
//! This reader exposes that logical view: [`Vhdx::read_block`] fills a caller's
//! buffer with a block's contents, reading the file only where the BAT says data
//! exists. It is `no_std` (needs `alloc` for the BAT) and does its I/O through the
//! [`ImageReader`] trait, so the same parser serves a host tool and an on-target
//! consumer.
//!
//! Reference: [MS-VHDX], the VHDX file format specification.

#![cfg_attr(not(test), no_std)]

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;

/// Byte offset of the file type identifier.
const FILE_ID_OFFSET: u64 = 0;
const FILE_ID_SIGNATURE: &[u8; 8] = b"vhdxfile";

/// The two header slots. The live header is the one that is well-formed and
/// carries the greater sequence number; the other is the previous generation,
/// kept so an interrupted update cannot leave the file without a valid header.
const HEADER_1_OFFSET: u64 = 0x1_0000;
const HEADER_2_OFFSET: u64 = 0x2_0000;
const HEADER_SIGNATURE: &[u8; 4] = b"head";
/// A header structure occupies a whole 4 KiB, and its checksum covers all of it.
const HEADER_LEN: usize = 4096;

/// The two region-table slots (the second mirrors the first).
const REGION_TABLE_1_OFFSET: u64 = 0x3_0000;
const REGION_TABLE_2_OFFSET: u64 = 0x4_0000;
const REGION_SIGNATURE: &[u8; 4] = b"regi";
/// The region table's checksum covers a full 64 KiB.
const REGION_TABLE_LEN: usize = 64 * 1024;

const METADATA_SIGNATURE: &[u8; 8] = b"metadata";

/// Region and metadata item identifiers, in their on-disk byte order (the first
/// three GUID fields are little-endian, the rest big-endian).
const GUID_BAT: [u8; 16] = [
    0x66, 0x77, 0xc2, 0x2d, 0x23, 0xf6, 0x00, 0x42, 0x9d, 0x64, 0x11, 0x5e, 0x9b, 0xfd, 0x4a, 0x08,
];
const GUID_METADATA_REGION: [u8; 16] = [
    0x06, 0xa2, 0x7c, 0x8b, 0x90, 0x47, 0x9a, 0x4b, 0xb8, 0xfe, 0x57, 0x5f, 0x05, 0x0f, 0x88, 0x6e,
];
const GUID_FILE_PARAMETERS: [u8; 16] = [
    0x37, 0x67, 0xa1, 0xca, 0x36, 0xfa, 0x43, 0x4d, 0xb3, 0xb6, 0x33, 0xf0, 0xaa, 0x44, 0xe7, 0x6b,
];
const GUID_VIRTUAL_DISK_SIZE: [u8; 16] = [
    0x24, 0x42, 0xa5, 0x2f, 0x1b, 0xcd, 0x76, 0x48, 0xb2, 0x11, 0x5d, 0xbe, 0xd8, 0x3b, 0xf4, 0xb8,
];
const GUID_LOGICAL_SECTOR_SIZE: [u8; 16] = [
    0x1d, 0xbf, 0x41, 0x81, 0x6f, 0xa9, 0x09, 0x47, 0xba, 0x47, 0xf2, 0x33, 0xa8, 0xfa, 0xab, 0x5f,
];

/// A BAT entry's state lives in its low 3 bits; the file offset, in 1 MiB units,
/// lives in bits 20..63.
const BAT_STATE_MASK: u64 = 0x7;
const BAT_OFFSET_SHIFT: u32 = 20;

/// What the BAT says about a payload block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockState {
    /// No data stored. For a disk without a parent this reads as zeros.
    NotPresent,
    /// Allocated but never written; contents are undefined, read as zeros.
    Undefined,
    /// Explicitly zero.
    Zero,
    /// Unmapped (e.g. trimmed); reads as zeros.
    Unmapped,
    /// Every sector of this block is stored in the file.
    FullyPresent,
    /// Some sectors are stored; a sector bitmap says which. The rest are zeros
    /// (for a disk without a parent).
    PartiallyPresent,
    /// A state the specification does not define.
    Unknown(u8),
}

impl BlockState {
    fn from_bits(bits: u8) -> Self {
        match bits {
            0 => BlockState::NotPresent,
            1 => BlockState::Undefined,
            2 => BlockState::Zero,
            3 => BlockState::Unmapped,
            6 => BlockState::FullyPresent,
            7 => BlockState::PartiallyPresent,
            other => BlockState::Unknown(other),
        }
    }

    /// Whether any of this block's bytes are stored in the file.
    pub fn has_stored_data(self) -> bool {
        matches!(self, BlockState::FullyPresent | BlockState::PartiallyPresent)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// The underlying reader failed.
    Io,
    /// Not a VHDX file.
    BadSignature,
    /// Neither header slot is usable.
    NoValidHeader,
    /// A required region (BAT or metadata) is absent.
    MissingRegion,
    /// A required metadata item is absent.
    MissingMetadata,
    /// Block size is not a supported power of two, or does not divide evenly.
    BadGeometry,
    /// Differencing disks resolve reads through a parent image, which this
    /// reader does not follow.
    HasParent,
    /// A caller's buffer is the wrong size.
    BadBufferLen,
}

/// Byte-addressable access to the image file.
pub trait ImageReader {
    /// Fills `buf` from `offset`. Must fill it completely or fail.
    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<(), Error>;
}

/// The disk's shape, from the image metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Geometry {
    /// Payload block size in bytes.
    pub block_size: u64,
    /// The disk's logical size as the guest sees it.
    pub virtual_disk_size: u64,
    /// Logical sector size (the unit a sector bitmap bit covers).
    pub logical_sector_size: u32,
    /// Number of payload blocks covering the disk.
    pub data_blocks: u64,
    /// Payload blocks per sector-bitmap block. The BAT interleaves one
    /// sector-bitmap entry after every `chunk_ratio` payload entries, so this
    /// is what makes a payload block's BAT index differ from its block number.
    pub chunk_ratio: u64,
}

/// A VHDX image opened for logical reads.
pub struct Vhdx<R: ImageReader> {
    reader: R,
    geometry: Geometry,
    /// The raw BAT, including the interleaved sector-bitmap entries.
    bat: Vec<u64>,
}

fn le_u16(b: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([b[off], b[off + 1]])
}
fn le_u32(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}
fn le_u64(b: &[u8], off: usize) -> u64 {
    let mut v = [0u8; 8];
    v.copy_from_slice(&b[off..off + 8]);
    u64::from_le_bytes(v)
}

/// CRC-32C (Castagnoli), the checksum VHDX uses for its headers and region
/// table. Bitwise rather than table-driven: it runs a handful of times when an
/// image is opened, never on a data path.
fn crc32c(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            // Branch-free conditional xor of the reversed polynomial.
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0x82F6_3B78 & mask);
        }
    }
    !crc
}

/// Verifies a structure whose 4-byte checksum sits at `checksum_off` and covers
/// the whole structure with that field zeroed.
fn checksum_ok(buf: &[u8], checksum_off: usize) -> bool {
    let stored = le_u32(buf, checksum_off);
    let mut zeroed = buf.to_vec();
    zeroed[checksum_off..checksum_off + 4].fill(0);
    crc32c(&zeroed) == stored
}

impl<R: ImageReader> Vhdx<R> {
    /// Parses the image's headers, regions, metadata and BAT.
    pub fn open(mut reader: R) -> Result<Self, Error> {
        let mut id = [0u8; 8];
        reader.read_at(FILE_ID_OFFSET, &mut id)?;
        if &id != FILE_ID_SIGNATURE {
            return Err(Error::BadSignature);
        }

        Self::select_header(&mut reader)?;
        let (bat_offset, bat_length, metadata_offset) = Self::read_regions(&mut reader)?;
        let geometry = Self::read_metadata(&mut reader, metadata_offset)?;

        // Load the BAT whole: it is a few hundred KiB even for a large disk, and
        // ingest consults it once per block.
        let entries = (bat_length as usize) / 8;
        let mut raw = vec![0u8; entries * 8];
        reader.read_at(bat_offset, &mut raw)?;
        let bat = (0..entries).map(|i| le_u64(&raw, i * 8)).collect();

        Ok(Vhdx { reader, geometry, bat })
    }

    /// Picks the live header: well-formed, checksum-valid, greatest sequence
    /// number. A torn header fails its checksum and is skipped, which is the
    /// point of keeping two.
    fn select_header(reader: &mut R) -> Result<u64, Error> {
        let mut best: Option<u64> = None;
        for offset in [HEADER_1_OFFSET, HEADER_2_OFFSET] {
            let mut buf = vec![0u8; HEADER_LEN];
            if reader.read_at(offset, &mut buf).is_err() {
                continue;
            }
            if &buf[0..4] != HEADER_SIGNATURE {
                continue;
            }
            if !checksum_ok(&buf, 4) {
                continue;
            }
            let seq = le_u64(&buf, 8);
            best = Some(match best {
                Some(cur) if cur >= seq => cur,
                _ => seq,
            });
        }
        best.ok_or(Error::NoValidHeader)
    }

    /// Returns (BAT offset, BAT length, metadata region offset).
    fn read_regions(reader: &mut R) -> Result<(u64, u32, u64), Error> {
        for offset in [REGION_TABLE_1_OFFSET, REGION_TABLE_2_OFFSET] {
            let mut buf = vec![0u8; REGION_TABLE_LEN];
            if reader.read_at(offset, &mut buf).is_err() {
                continue;
            }
            if &buf[0..4] != REGION_SIGNATURE || !checksum_ok(&buf, 4) {
                continue;
            }
            let count = le_u32(&buf, 8) as usize;
            let (mut bat, mut meta) = (None, None);
            for i in 0..count {
                let e = 16 + i * 32;
                if e + 32 > buf.len() {
                    break;
                }
                let guid = &buf[e..e + 16];
                let file_offset = le_u64(&buf, e + 16);
                let length = le_u32(&buf, e + 24);
                if guid == GUID_BAT {
                    bat = Some((file_offset, length));
                } else if guid == GUID_METADATA_REGION {
                    meta = Some(file_offset);
                }
            }
            if let (Some((bo, bl)), Some(mo)) = (bat, meta) {
                return Ok((bo, bl, mo));
            }
        }
        Err(Error::MissingRegion)
    }

    /// Reads the metadata items that define the disk's shape.
    fn read_metadata(reader: &mut R, region: u64) -> Result<Geometry, Error> {
        let mut head = [0u8; 32];
        reader.read_at(region, &mut head)?;
        if &head[0..8] != METADATA_SIGNATURE {
            return Err(Error::MissingMetadata);
        }
        let count = le_u16(&head, 10) as usize;

        let (mut block_size, mut disk_size, mut sector_size, mut has_parent) =
            (None, None, None, false);
        for i in 0..count {
            let mut e = [0u8; 32];
            reader.read_at(region + 32 + (i as u64) * 32, &mut e)?;
            let offset = le_u32(&e, 16) as u64;
            let length = le_u32(&e, 20) as usize;
            let guid = &e[0..16];

            if guid == GUID_FILE_PARAMETERS && length >= 8 {
                let mut v = [0u8; 8];
                reader.read_at(region + offset, &mut v)?;
                block_size = Some(le_u32(&v, 0) as u64);
                // Bit 1 marks a differencing disk, whose absent blocks resolve
                // against a parent image rather than reading as zeros.
                has_parent = le_u32(&v, 4) & 0x2 != 0;
            } else if guid == GUID_VIRTUAL_DISK_SIZE && length >= 8 {
                let mut v = [0u8; 8];
                reader.read_at(region + offset, &mut v)?;
                disk_size = Some(le_u64(&v, 0));
            } else if guid == GUID_LOGICAL_SECTOR_SIZE && length >= 4 {
                let mut v = [0u8; 4];
                reader.read_at(region + offset, &mut v)?;
                sector_size = Some(le_u32(&v, 0));
            }
        }

        if has_parent {
            return Err(Error::HasParent);
        }
        let block_size = block_size.ok_or(Error::MissingMetadata)?;
        let virtual_disk_size = disk_size.ok_or(Error::MissingMetadata)?;
        let logical_sector_size = sector_size.ok_or(Error::MissingMetadata)?;
        if block_size == 0
            || !block_size.is_power_of_two()
            || logical_sector_size == 0
            || virtual_disk_size % block_size != 0
        {
            return Err(Error::BadGeometry);
        }

        let data_blocks = virtual_disk_size / block_size;
        // A sector-bitmap block covers 2^23 sectors' worth of payload.
        let chunk_ratio = ((1u64 << 23) * logical_sector_size as u64) / block_size;
        if chunk_ratio == 0 {
            return Err(Error::BadGeometry);
        }

        Ok(Geometry {
            block_size,
            virtual_disk_size,
            logical_sector_size,
            data_blocks,
            chunk_ratio,
        })
    }

    pub fn geometry(&self) -> Geometry {
        self.geometry
    }

    /// The BAT index of payload block `block`, skipping the sector-bitmap entry
    /// that follows every `chunk_ratio` payload entries.
    fn payload_index(&self, block: u64) -> usize {
        (block + block / self.geometry.chunk_ratio) as usize
    }

    /// The BAT index of the sector-bitmap entry covering payload block `block`.
    fn bitmap_index(&self, block: u64) -> usize {
        let chunk = block / self.geometry.chunk_ratio;
        (chunk * (self.geometry.chunk_ratio + 1) + self.geometry.chunk_ratio) as usize
    }

    /// What the BAT says about `block`.
    pub fn block_state(&self, block: u64) -> BlockState {
        match self.bat.get(self.payload_index(block)) {
            Some(entry) => BlockState::from_bits((entry & BAT_STATE_MASK) as u8),
            None => BlockState::NotPresent,
        }
    }

    /// Fills `out` (exactly one block) with block `block`'s logical contents.
    ///
    /// Absent blocks are synthesized as zeros without touching the file, which is
    /// what keeps a pass over a sparse disk proportional to its allocated size
    /// rather than its virtual size.
    pub fn read_block(&mut self, block: u64, out: &mut [u8]) -> Result<(), Error> {
        let block_size = self.geometry.block_size as usize;
        if out.len() != block_size {
            return Err(Error::BadBufferLen);
        }
        let entry = match self.bat.get(self.payload_index(block)) {
            Some(e) => *e,
            None => {
                out.fill(0);
                return Ok(());
            }
        };
        let state = BlockState::from_bits((entry & BAT_STATE_MASK) as u8);
        let file_offset = (entry >> BAT_OFFSET_SHIFT) << BAT_OFFSET_SHIFT;

        match state {
            BlockState::FullyPresent => self.reader.read_at(file_offset, out),
            BlockState::PartiallyPresent => {
                // Only the sectors flagged in the chunk's bitmap are stored; the
                // rest read as zeros (no parent to defer to).
                self.reader.read_at(file_offset, out)?;
                let bitmap_entry = self.bat.get(self.bitmap_index(block)).copied().unwrap_or(0);
                let bitmap_state = BlockState::from_bits((bitmap_entry & BAT_STATE_MASK) as u8);
                if !bitmap_state.has_stored_data() {
                    // No bitmap stored: nothing is valid.
                    out.fill(0);
                    return Ok(());
                }
                let bitmap_offset = (bitmap_entry >> BAT_OFFSET_SHIFT) << BAT_OFFSET_SHIFT;

                let sector = self.geometry.logical_sector_size as usize;
                let sectors_per_block = block_size / sector;
                // The chunk's bitmap covers chunk_ratio blocks back to back, one
                // bit per sector.
                let first_bit =
                    (block % self.geometry.chunk_ratio) as usize * sectors_per_block;

                for s in 0..sectors_per_block {
                    let bit = first_bit + s;
                    let mut byte = [0u8; 1];
                    self.reader
                        .read_at(bitmap_offset + (bit / 8) as u64, &mut byte)?;
                    let present = byte[0] & (1 << (bit % 8)) != 0;
                    if !present {
                        out[s * sector..(s + 1) * sector].fill(0);
                    }
                }
                Ok(())
            }
            // NotPresent / Undefined / Zero / Unmapped / unknown: zeros.
            _ => {
                out.fill(0);
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An in-memory image, so the parser is tested without any real file.
    struct MemImage(Vec<u8>);

    impl ImageReader for MemImage {
        fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<(), Error> {
            let start = offset as usize;
            let end = start + buf.len();
            if end > self.0.len() {
                return Err(Error::Io);
            }
            buf.copy_from_slice(&self.0[start..end]);
            Ok(())
        }
    }

    const BLOCK: u64 = 1 << 20;
    const SECTOR: u32 = 512;

    fn put(img: &mut Vec<u8>, offset: usize, bytes: &[u8]) {
        if img.len() < offset + bytes.len() {
            img.resize(offset + bytes.len(), 0);
        }
        img[offset..offset + bytes.len()].copy_from_slice(bytes);
    }

    /// Stamps a checksum whose field sits at `checksum_off` within `[start, start+len)`.
    fn stamp_checksum(img: &mut Vec<u8>, start: usize, len: usize, checksum_off: usize) {
        let mut region = img[start..start + len].to_vec();
        region[checksum_off..checksum_off + 4].fill(0);
        let crc = crc32c(&region);
        img[start + checksum_off..start + checksum_off + 4].copy_from_slice(&crc.to_le_bytes());
    }

    /// Builds a small but structurally faithful VHDX: 4 blocks, one of each
    /// interesting state, with real headers, region table, metadata and BAT.
    fn synth_image(states: &[(u8, Option<Vec<u8>>)]) -> MemImage {
        let disk_size = BLOCK * states.len() as u64;
        let mut img = vec![0u8; 0x40_0000];

        put(&mut img, 0, b"vhdxfile");

        // Two headers; header 2 wins on sequence number.
        for (i, off) in [(1u64, 0x1_0000usize), (2, 0x2_0000)] {
            put(&mut img, off, b"head");
            put(&mut img, off + 8, &i.to_le_bytes());
            stamp_checksum(&mut img, off, HEADER_LEN, 4);
        }

        // Region table: BAT at 0x30_0000, metadata at 0x20_0000.
        let bat_off: u64 = 0x30_0000;
        let meta_off: u64 = 0x20_0000;
        for table in [0x3_0000usize, 0x4_0000] {
            put(&mut img, table, b"regi");
            put(&mut img, table + 8, &2u32.to_le_bytes());
            put(&mut img, table + 16, &GUID_BAT);
            put(&mut img, table + 32, &bat_off.to_le_bytes());
            put(&mut img, table + 40, &(0x10_0000u32).to_le_bytes());
            put(&mut img, table + 48, &GUID_METADATA_REGION);
            put(&mut img, table + 64, &meta_off.to_le_bytes());
            put(&mut img, table + 72, &(0x10_0000u32).to_le_bytes());
            stamp_checksum(&mut img, table, REGION_TABLE_LEN, 4);
        }

        // Metadata region: three items describing the geometry.
        let m = meta_off as usize;
        put(&mut img, m, b"metadata");
        put(&mut img, m + 10, &3u16.to_le_bytes());
        let items: [([u8; 16], u32, u32); 3] = [
            (GUID_FILE_PARAMETERS, 0x1_0000, 8),
            (GUID_VIRTUAL_DISK_SIZE, 0x1_0008, 8),
            (GUID_LOGICAL_SECTOR_SIZE, 0x1_0010, 4),
        ];
        for (i, (guid, off, len)) in items.iter().enumerate() {
            let e = m + 32 + i * 32;
            put(&mut img, e, guid);
            put(&mut img, e + 16, &off.to_le_bytes());
            put(&mut img, e + 20, &len.to_le_bytes());
        }
        put(&mut img, m + 0x1_0000, &(BLOCK as u32).to_le_bytes());
        put(&mut img, m + 0x1_0004, &0u32.to_le_bytes()); // no parent
        put(&mut img, m + 0x1_0008, &disk_size.to_le_bytes());
        put(&mut img, m + 0x1_0010, &SECTOR.to_le_bytes());

        // Payload blocks live past the BAT; give each stored block its own 1 MiB.
        let mut next_payload: u64 = 0x31_0000;
        let chunk_ratio = ((1u64 << 23) * SECTOR as u64) / BLOCK;
        for (i, (state, data)) in states.iter().enumerate() {
            let block = i as u64;
            let bat_index = block + block / chunk_ratio;
            let mut entry = *state as u64;
            if let Some(bytes) = data {
                // BAT offsets are in 1 MiB units, so payloads must be 1 MiB aligned.
                let aligned = (next_payload + BLOCK - 1) & !(BLOCK - 1);
                put(&mut img, aligned as usize, bytes);
                entry |= aligned;
                next_payload = aligned + BLOCK;
            }
            put(
                &mut img,
                (bat_off + bat_index * 8) as usize,
                &entry.to_le_bytes(),
            );
        }
        MemImage(img)
    }

    #[test]
    fn parses_geometry() {
        let img = synth_image(&[(0, None), (0, None)]);
        let v = Vhdx::open(img).expect("open");
        let g = v.geometry();
        assert_eq!(g.block_size, BLOCK);
        assert_eq!(g.virtual_disk_size, 2 * BLOCK);
        assert_eq!(g.logical_sector_size, SECTOR);
        assert_eq!(g.data_blocks, 2);
        // (2^23 * 512) / 1 MiB
        assert_eq!(g.chunk_ratio, 4096);
    }

    #[test]
    fn rejects_non_vhdx() {
        let mut img = synth_image(&[(0, None)]);
        img.0[0] = b'X';
        // `Vhdx` is not `Debug`, so match rather than `unwrap_err`.
        match Vhdx::open(img) {
            Err(e) => assert_eq!(e, Error::BadSignature),
            Ok(_) => panic!("expected BadSignature"),
        }
    }

    #[test]
    fn absent_blocks_read_as_zeros_without_stored_data() {
        // NOT_PRESENT, UNDEFINED, ZERO, UNMAPPED all read as zeros.
        let img = synth_image(&[(0, None), (1, None), (2, None), (3, None)]);
        let mut v = Vhdx::open(img).expect("open");
        let mut buf = vec![0xFFu8; BLOCK as usize];
        for b in 0..4u64 {
            assert!(!v.block_state(b).has_stored_data(), "block {}", b);
            v.read_block(b, &mut buf).expect("read");
            assert!(buf.iter().all(|&x| x == 0), "block {} not zero", b);
        }
    }

    #[test]
    fn fully_present_block_returns_stored_bytes() {
        let mut data = vec![0u8; BLOCK as usize];
        data[0] = 0xAB;
        data[BLOCK as usize - 1] = 0xCD;
        let img = synth_image(&[(6, Some(data.clone())), (0, None)]);
        let mut v = Vhdx::open(img).expect("open");
        assert_eq!(v.block_state(0), BlockState::FullyPresent);

        let mut buf = vec![0u8; BLOCK as usize];
        v.read_block(0, &mut buf).expect("read");
        assert_eq!(buf, data);

        // The neighbouring absent block is still zeros.
        v.read_block(1, &mut buf).expect("read");
        assert!(buf.iter().all(|&x| x == 0));
    }

    #[test]
    fn wrong_buffer_length_is_rejected() {
        let img = synth_image(&[(0, None)]);
        let mut v = Vhdx::open(img).expect("open");
        let mut small = [0u8; 16];
        assert_eq!(v.read_block(0, &mut small).unwrap_err(), Error::BadBufferLen);
    }

    #[test]
    fn crc32c_matches_known_vector() {
        // Castagnoli check value for the ASCII digits.
        assert_eq!(crc32c(b"123456789"), 0xE306_9283);
    }
}

//! Where the OTA updater's destructive write goes: the pure GPT->ESP decision.
//!
//! WHY THIS IS ITS OWN MODULE. `ota_updater` writes a whole OS image (~45 MiB) into
//! the partition this code selects. Everything that decides *which* partition that is
//! therefore sits on a destructive path, and it is driven entirely by bytes read off a
//! disk we did not write. So it is factored out here with **no I/O, no block client and
//! no FIDL**, exactly the way `fxfs_provisioner`'s `layout.rs` / `ownership.rs` and the
//! fileserver's `claim.rs` are, so the decision can be unit-tested on the host against
//! hostile inputs that no live boot could ever be made to produce.
//!
//! WHAT IS REUSED RATHER THAN REWRITTEN. The header validator is
//! `boot_layout::validated_header` and the entry geometry is
//! `boot_layout::entry_array_location` — the same functions `fxfs_provisioner` uses to
//! recognise tables and the fileserver uses to decide whether a disk is claimable. A
//! second GPT validator in the tree would drift from the first, and the two components
//! that must never disagree about "is this a valid partition table" are precisely the
//! one that writes tables and the ones that destroy partitions. What is *not* shared is
//! the entry walk: `boot_layout::find_fxfs_partition` looks for `FXFS_TYPE_GUID`, this
//! looks for `ESP_TYPE_GUID`, and generalising that would mean editing a module three
//! other components link. The validation — signature, header size, header CRC, entry
//! geometry — is shared; only the lookup is local.
//!
//! WHAT THIS IS NOT. CRC-32 is a corruption check, not authentication: an adversary who
//! can rewrite the disk can recompute both CRCs and put the ESP type GUID on any
//! partition they like. What the checks here buy is that a DAMAGED or ARITHMETICALLY
//! HOSTILE table cannot steer a 45 MiB write — no wrapped offsets, no absurd
//! allocations, no partition outside the device, and no guessing when the table does
//! not say where the ESP is. Defending against a disk an attacker can already rewrite
//! is a verified-boot problem, and this module does not solve it.
//!
//! THE TWO-PHASE SHAPE. The entry array's location comes out of the header, so the
//! caller cannot read it until the header has been validated. Hence
//! `entry_array_read_plan` (header -> where and how much to read) and then
//! `find_esp_in_table` (header + those bytes -> the ESP). A caller cannot skip the
//! validation, because the only thing that tells it what to read is the validator's
//! own output.
//!
//! WHAT THIS REFUSES THAT THE PREVIOUS PARSE ACCEPTED. Each of the following has a
//! test in `tests` below that ALSO runs a release-semantics model of the old parse on
//! the same fixture and asserts the old code got it wrong — a guard whose absence
//! changed nothing would not be a guard:
//!   * a header whose CRC does not check out (the old parse validated the 8-byte
//!     `"EFI PART"` signature and nothing else);
//!   * a header whose `header_size` field is absurd;
//!   * an entry array whose CRC does not match the header's `entries_crc`;
//!   * `entry_count * entry_size` overflowing, or merely being large enough that the
//!     old `vec![0u8; num * esz]` aborts the process;
//!   * `entry_lba * block_size` overflowing into a small, wrong device offset;
//!   * a partition entry whose `last_lba < first_lba`, or whose byte range overflows;
//!   * **a table with no ESP entry at all.** The old parse fell back to the first
//!     non-empty partition and wrote the OS image there. See `NoEsp` below.
//!
//! And these are NEW guards, not fixes — the old parse was not defeated by them, and
//! the tests for them carry no old-code control. Recorded separately so the list above
//! is not read as claiming more than it proves:
//!   * a short entry array (the old code sized its own read, so it could not see one);
//!   * a missing signature and a too-short header (the old code refused these too,
//!     less precisely);
//!   * `last - first + 1` overflowing for a whole-address-space entry, and the
//!     exclusive end `offset + len` overflowing;
//!   * an ESP that is not on this device (`block_count` was never consulted);
//!   * more than one ESP entry.

use boot_layout::{crc32, entry_array_location, validated_header, ESP_TYPE_GUID};

/// The largest entry array this will read. A header is attacker-controlled, so the
/// allocation it implies needs a ceiling that does not come from the header itself.
/// `boot_layout::entry_array_location` already caps the *count* at 4096, but the entry
/// *size* is only required to be a non-zero multiple of 128, so their product is still
/// ~17 TB in the worst case. Real tables are 128 x 128 = 16 KiB; UEFI 2.10 requires the
/// array to fit in the space before the first usable LBA. 1 MiB is ~64x the real value
/// and far below anything that could exhaust memory.
pub const MAX_ENTRY_ARRAY_BYTES: usize = 1 << 20;

/// The largest single partition entry this will accept. GPT requires a multiple of 128;
/// every implementation in practice uses exactly 128.
pub const MAX_ENTRY_SIZE: usize = 4096;

/// Why the ESP could not be located. Every variant is a *refusal*: there is no variant
/// that means "we guessed". The write path treats all of them identically — it does not
/// write — so the distinction exists for the serial log and for the tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EspError {
    /// `block_size` was zero or not a multiple of 512.
    BadBlockSize,
    /// Fewer bytes than a GPT header were handed in.
    ShortHeader,
    /// No `"EFI PART"` at LBA 1. There is no GPT here at all.
    NoSignature,
    /// The signature is present but the header does not validate: an out-of-range
    /// `header_size`, or a header CRC that does not match. Something IS there and we
    /// cannot trust a single field of it.
    DamagedHeader,
    /// The header's entry geometry is absurd: a zero or >4096 entry count, an entry
    /// size that is not a non-zero multiple of 128, an entry size over
    /// `MAX_ENTRY_SIZE`, or a total array over `MAX_ENTRY_ARRAY_BYTES`.
    BadEntryGeometry,
    /// `entry_lba * block_size` does not fit in a `u64`. The old parse wrapped this
    /// into a small offset and read a wrong, in-range part of the disk.
    EntryArrayOffsetOverflow,
    /// The caller supplied fewer entry-array bytes than the header asked for.
    ShortEntryArray,
    /// The entry array's CRC-32 does not match the header's `entries_crc`. The header
    /// is authentic-looking and the table under it is not.
    DamagedEntryArray,
    /// A partition entry's `last_lba < first_lba`, or its byte range overflows —
    /// including the inclusive-range `last - first + 1` when an entry claims the whole
    /// address space, and the exclusive end `offset + len`.
    BadPartitionRange,
    /// The ESP's range is arithmetically fine and is not on this device. A partition
    /// table is not evidence about the disk it was read from.
    PartitionOffDevice,
    /// Two entries claim the EFI System Partition type. Resolving that by taking the
    /// first is the same guess as the removed fallback; refuse instead.
    MultipleEsp,
    /// The table is entirely valid and contains no EFI System Partition.
    ///
    /// THIS IS DELIBERATELY AN ERROR AND NOT A FALLBACK. The previous parse, on this
    /// exact input, emitted a warning and used the first non-empty partition — so the
    /// consequence of an unexpected partition table was *writing a whole OS image over
    /// whichever partition happened to be listed first*, not declining to update. The
    /// justification given was an "endianness surprise on some tool", which is a
    /// hypothesis about a bug we have never seen, weighed against a certain and
    /// unrecoverable outcome when it is wrong. An OTA that does not happen is a
    /// machine that stays on its current image; an OTA written to the wrong partition
    /// is a destroyed one. See the module test `a_table_with_no_esp_is_refused`.
    NoEsp,
}

impl EspError {
    /// A short, stable token for the serial log. Callers prefix it with their own
    /// marker; these are matched by `validation/ota_update_boot_test.py`.
    pub fn token(self) -> &'static str {
        match self {
            EspError::BadBlockSize => "bad-block-size",
            EspError::ShortHeader => "short-header",
            EspError::NoSignature => "no-gpt-signature",
            EspError::DamagedHeader => "damaged-header",
            EspError::BadEntryGeometry => "bad-entry-geometry",
            EspError::EntryArrayOffsetOverflow => "entry-array-offset-overflow",
            EspError::ShortEntryArray => "short-entry-array",
            EspError::DamagedEntryArray => "damaged-entry-array",
            EspError::BadPartitionRange => "bad-partition-range",
            EspError::PartitionOffDevice => "partition-off-device",
            EspError::MultipleEsp => "multiple-esp-partitions",
            EspError::NoEsp => "no-esp-partition",
        }
    }

    /// Whether this device could not be conclusively classified as lacking an ESP.
    ///
    /// A valid table with no ESP and a disk with no GPT are ordinary non-matches.
    /// Every other failure means an expected boot disk may be present but damaged or
    /// unreadable, which must not silently redirect the write to a sibling device.
    pub fn is_inconclusive(self) -> bool {
        !matches!(self, EspError::NoSignature | EspError::NoEsp)
    }
}

impl std::fmt::Display for EspError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let detail = match self {
            EspError::BadBlockSize => "block size is zero or not a multiple of 512",
            EspError::ShortHeader => "fewer bytes supplied than a GPT header occupies",
            EspError::NoSignature => "no \"EFI PART\" signature at LBA 1",
            EspError::DamagedHeader => "GPT header failed its size/CRC check",
            EspError::BadEntryGeometry => "GPT entry count/size out of range",
            EspError::EntryArrayOffsetOverflow => "entry-array LBA x block size overflows u64",
            EspError::ShortEntryArray => "entry array shorter than the header requires",
            EspError::DamagedEntryArray => "entry array failed its CRC check",
            EspError::BadPartitionRange => "partition entry has an inverted or overflowing range",
            EspError::PartitionOffDevice => "the ESP does not lie within this device",
            EspError::MultipleEsp => {
                "more than one EFI System Partition in this table (refusing: which one \
                 receives the OS image is not ours to guess)"
            }
            EspError::NoEsp => {
                "no EFI System Partition in this table (refusing: a whole OS image is \
                 about to be written, and there is no safe partition to guess)"
            }
        };
        write!(f, "{} ({})", detail, self.token())
    }
}

/// A partition's location on the device, in bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EspRange {
    /// Byte offset of the partition's first block.
    pub offset: u64,
    /// Partition length in bytes.
    pub len: u64,
}

/// Persistent identity and range of an ESP on one physical GPT disk.
///
/// Aggregated block Service instance names are anonymized and change at boot,
/// so they are useful provenance but not an identity a lifecycle coordinator can
/// safely persist. These GUIDs come from the validated GPT header/entry instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EspIdentity {
    pub range: EspRange,
    pub disk_guid: [u8; 16],
    pub partition_guid: [u8; 16],
}

fn check_block_size(block_size: u64) -> Result<(), EspError> {
    if block_size == 0 || block_size % 512 != 0 {
        return Err(EspError::BadBlockSize);
    }
    Ok(())
}

fn le_u32(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
}

fn le_u64(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().unwrap())
}

/// Validate `lba1` and say where the entry array is: `(byte offset, byte length)`.
///
/// The caller reads exactly that and passes it to [`find_esp_in_table`]. Both the
/// offset and the length are the product of two header fields, and both products are
/// checked here — the old parse did neither.
pub fn entry_array_read_plan(lba1: &[u8], block_size: u64) -> Result<(u64, usize), EspError> {
    check_block_size(block_size)?;
    // Distinguish "no GPT" from "damaged GPT" before validating, so the log can say
    // which. `validated_header` collapses both into None.
    if lba1.len() < 92 {
        return Err(EspError::ShortHeader);
    }
    if lba1[0..8] != boot_layout::GPT_SIGNATURE {
        return Err(EspError::NoSignature);
    }
    // Signature, header_size range, and header CRC-32 (with the CRC field zeroed) —
    // the shared validator. Nothing below may read a header field before this passes:
    // the entry array's location comes out of the header, so trusting it first means
    // sizing an allocation and a device read from bytes that failed their own checksum.
    validated_header(lba1).ok_or(EspError::DamagedHeader)?;

    // Entry geometry, also shared: entry_size a non-zero multiple of 128, entry_count
    // in 1..=4096, and count * size computed with checked_mul.
    let (entry_lba, array_len) = entry_array_location(lba1).ok_or(EspError::BadEntryGeometry)?;
    let entry_size = le_u32(lba1, 84) as usize;
    if entry_size > MAX_ENTRY_SIZE || array_len > MAX_ENTRY_ARRAY_BYTES {
        return Err(EspError::BadEntryGeometry);
    }

    // The offset the old parse computed as `entry_lba * bs`, in a plain multiply on a
    // u64 read straight out of the header. In release that wraps to a small, perfectly
    // readable device offset and the read silently succeeds against the wrong bytes.
    let offset = entry_lba
        .checked_mul(block_size)
        .ok_or(EspError::EntryArrayOffsetOverflow)?;
    Ok((offset, array_len))
}

/// Locate the EFI System Partition in a validated table.
///
/// `lba1` is the block at LBA 1; `entries` is at least the byte length
/// [`entry_array_read_plan`] returned, read from the offset it returned; `block_count`
/// is the DEVICE's block count, which is what bounds the result — the table itself is
/// not evidence about the disk it came from. Returns the ESP's byte range, or refuses.
/// **There is no fallback partition.**
pub fn find_esp_in_table(
    lba1: &[u8],
    entries: &[u8],
    block_size: u64,
    block_count: u64,
) -> Result<EspRange, EspError> {
    Ok(find_esp_identity_in_table(lba1, entries, block_size, block_count)?.range)
}

/// Locate the ESP and retain the persistent disk and partition GUIDs which
/// identify the exact physical boot target across aggregated-Service renaming.
pub fn find_esp_identity_in_table(
    lba1: &[u8],
    entries: &[u8],
    block_size: u64,
    block_count: u64,
) -> Result<EspIdentity, EspError> {
    let (_, array_len) = entry_array_read_plan(lba1, block_size)?;
    let entry_size = le_u32(lba1, 84) as usize;
    let entry_count = le_u32(lba1, 80) as usize;

    if entries.len() < array_len {
        return Err(EspError::ShortEntryArray);
    }
    // UEFI 2.10 table 5-5: the CRC covers exactly entry_count * entry_size bytes, not
    // any block padding around them. Without this, a header can be authentic (its own
    // CRC checks out) while every partition entry under it is attacker-chosen.
    if crc32(&entries[..array_len]) != le_u32(lba1, 88) {
        return Err(EspError::DamagedEntryArray);
    }

    let mut found: Option<EspIdentity> = None;
    for i in 0..entry_count {
        let e = &entries[i * entry_size..(i + 1) * entry_size];
        if e[0..16] == [0u8; 16] {
            continue; // unused entry
        }
        if e[0..16] != ESP_TYPE_GUID {
            continue;
        }
        // A second ESP is an ambiguity, and resolving an ambiguity by taking the first
        // is the same kind of guess this module exists to remove. Refuse.
        if found.is_some() {
            return Err(EspError::MultipleEsp);
        }
        let first = le_u64(e, 32);
        let last = le_u64(e, 40);
        if last < first {
            return Err(EspError::BadPartitionRange);
        }
        // GPT ranges are INCLUSIVE, so the block count is `last - first + 1`, and that
        // `+ 1` is itself an overflow when the entry claims the whole address space
        // (first=0, last=u64::MAX) — a case that passes both the ordering check and the
        // `first * block_size` check above. Every step is checked; there is no
        // "obviously fine" arithmetic on a field that came off the disk.
        let blocks = last
            .checked_sub(first)
            .and_then(|n| n.checked_add(1))
            .ok_or(EspError::BadPartitionRange)?;
        let offset = first
            .checked_mul(block_size)
            .ok_or(EspError::BadPartitionRange)?;
        let len = blocks
            .checked_mul(block_size)
            .ok_or(EspError::BadPartitionRange)?;
        // The exclusive end must exist too: `PartitionIo` adds its cursor to `offset`,
        // so a range whose end wraps would let the FAT driver address arbitrary device
        // offsets by seeking.
        let end = offset.checked_add(len).ok_or(EspError::BadPartitionRange)?;

        // ...and it must be on THIS disk. The arithmetic above only proves the numbers
        // are representable. Nothing in a partition table is evidence about the device
        // it was read from, so the device's own geometry is what bounds it.
        let device_bytes = block_count
            .checked_mul(block_size)
            .ok_or(EspError::BadBlockSize)?;
        if last >= block_count || end > device_bytes {
            return Err(EspError::PartitionOffDevice);
        }
        found = Some(EspIdentity {
            range: EspRange { offset, len },
            disk_guid: lba1[56..72]
                .try_into()
                .expect("validated GPT header contains disk GUID"),
            partition_guid: e[16..32]
                .try_into()
                .expect("GPT entry contains partition GUID"),
        });
    }
    found.ok_or(EspError::NoEsp)
}

// ==========================================================================================
#[cfg(test)]
mod tests {
    use super::*;

    const BS: u64 = 512;
    /// The fixtures describe a small notional device: usable LBAs 34..=99, backup
    /// header at 100. `BLOCKS` is its block count, which is what bounds every range.
    const BLOCKS: u64 = 101;

    // --------------------------------------------------------------------------------
    // Fixture builder.
    //
    // Every hostile case below needs ONE field corrupted with both CRCs otherwise
    // correct, which no real GPT writer will produce, so the fixtures are built here.
    // A fixture builder only this file agrees with would let every test pass for the
    // wrong reason, so two things anchor it:
    //
    //   * `esp_is_found_in_a_table_the_provisioner_actually_builds` parses the output
    //     of the REAL `boot_layout::build_gpt` (driven by the real `plan_layout`) — the
    //     bytes `fxfs_provisioner` writes to hardware, whose spec-conformance is
    //     independently checked against sgdisk/parted by that component's
    //     `gpt_image_tool` — and requires the ESP range to equal the plan's own;
    //   * `the_fixture_builder_produces_a_header_the_shared_validator_accepts` requires
    //     the clean fixture to pass `boot_layout::validated_header`, i.e. the same
    //     function `fxfs_provisioner` and the fileserver hold, not a local opinion.
    // --------------------------------------------------------------------------------

    struct Gpt {
        lba1: Vec<u8>,
        entries: Vec<u8>,
    }

    /// `(type_guid, first_lba, last_lba)` per entry slot.
    fn build(
        entry_count: u32,
        entry_size: u32,
        entry_lba: u64,
        parts: &[([u8; 16], u64, u64)],
    ) -> Gpt {
        let array_len = (entry_count as usize) * (entry_size as usize);
        let mut entries = vec![0u8; array_len];
        for (i, (guid, first, last)) in parts.iter().enumerate() {
            let e = &mut entries[i * entry_size as usize..(i + 1) * entry_size as usize];
            e[0..16].copy_from_slice(guid);
            e[16..32].copy_from_slice(&[0xAB; 16]); // unique GUID, unused by the parse
            e[32..40].copy_from_slice(&first.to_le_bytes());
            e[40..48].copy_from_slice(&last.to_le_bytes());
        }
        let mut lba1 = vec![0u8; BS as usize];
        lba1[0..8].copy_from_slice(b"EFI PART");
        lba1[8..12].copy_from_slice(&0x0001_0000u32.to_le_bytes()); // revision
        lba1[12..16].copy_from_slice(&92u32.to_le_bytes()); // header_size
        lba1[24..32].copy_from_slice(&1u64.to_le_bytes()); // my_lba
        lba1[32..40].copy_from_slice(&100u64.to_le_bytes()); // alternate_lba
        lba1[40..48].copy_from_slice(&34u64.to_le_bytes()); // first_usable
        lba1[48..56].copy_from_slice(&99u64.to_le_bytes()); // last_usable
        lba1[72..80].copy_from_slice(&entry_lba.to_le_bytes());
        lba1[80..84].copy_from_slice(&entry_count.to_le_bytes());
        lba1[84..88].copy_from_slice(&entry_size.to_le_bytes());
        lba1[88..92].copy_from_slice(&crc32(&entries[..array_len]).to_le_bytes());
        reseal(&mut lba1);
        Gpt { lba1, entries }
    }

    /// Recompute the header CRC so a corrupted field is the ONLY thing wrong. Without
    /// this, every "hostile field" test would be caught by the header CRC and would
    /// prove nothing about the field it names.
    fn reseal(lba1: &mut [u8]) {
        lba1[16..20].copy_from_slice(&[0, 0, 0, 0]);
        let crc = crc32(&lba1[..92]);
        lba1[16..20].copy_from_slice(&crc.to_le_bytes());
    }

    /// A header alone, for geometry so absurd that materialising the entry array it
    /// describes would itself abort the test process — which is the property under
    /// test. `entries_crc` is set to the CRC of nothing, since nothing is read.
    fn build_header_only(entry_count: u32, entry_size: u32, entry_lba: u64) -> Vec<u8> {
        let mut lba1 = vec![0u8; BS as usize];
        lba1[0..8].copy_from_slice(b"EFI PART");
        lba1[8..12].copy_from_slice(&0x0001_0000u32.to_le_bytes());
        lba1[12..16].copy_from_slice(&92u32.to_le_bytes());
        lba1[24..32].copy_from_slice(&1u64.to_le_bytes());
        lba1[32..40].copy_from_slice(&100u64.to_le_bytes());
        lba1[40..48].copy_from_slice(&34u64.to_le_bytes());
        lba1[48..56].copy_from_slice(&99u64.to_le_bytes());
        lba1[72..80].copy_from_slice(&entry_lba.to_le_bytes());
        lba1[80..84].copy_from_slice(&entry_count.to_le_bytes());
        lba1[84..88].copy_from_slice(&entry_size.to_le_bytes());
        lba1[88..92].copy_from_slice(&crc32(&[]).to_le_bytes());
        reseal(&mut lba1);
        lba1
    }

    /// One ESP at LBA 34..=99, the normal shape: 128 entries of 128 bytes at LBA 2.
    fn clean() -> Gpt {
        build(128, 128, 2, &[(ESP_TYPE_GUID, 34, 99)])
    }

    const OTHER_GUID: [u8; 16] = boot_layout::FXFS_TYPE_GUID;

    // --------------------------------------------------------------------------------
    // The old parse, transcribed. THIS IS THE NEGATIVE CONTROL.
    //
    // Every refusal added above is only worth having if the input it refuses actually
    // defeated the code it replaced. `legacy_find_esp` is `find_esp` from
    // src/main.rs:272-305 as it stood before this change, with the two `read_dev` calls
    // replaced by slicing an in-memory disk, and with the two unchecked multiplies
    // spelled `wrapping_mul` because a plain `*` panics in a debug-assertions test
    // build and wraps in the release build that ships. Both of those are the bug; the
    // wrapping spelling is the one that reaches a device.
    //
    // It reports an oversized allocation rather than performing it: `vec![0u8; 1<<63]`
    // aborts the process, and a test that aborts the process reports nothing. The size
    // it reports is the exact expression the old code passed to `vec!`.
    // --------------------------------------------------------------------------------

    #[derive(Debug, PartialEq, Eq)]
    enum Legacy {
        /// The old code would have called `vec![0u8; n]` with this `n`.
        WouldAllocate(u64),
        /// The old code read the entry array from this device byte offset.
        ReadAt { offset: u64, result: LegacyPick },
    }

    #[derive(Debug, PartialEq, Eq)]
    enum LegacyPick {
        /// Matched the ESP type GUID.
        Esp(u64, u64),
        /// No ESP; used the first non-empty partition anyway (the fallback).
        FellBackToFirstPartition(u64, u64),
        NoPartitions,
        /// Slicing the entry array went out of bounds — the old code would panic here.
        WouldPanic,
    }

    /// `disk` is a map from device byte offset to bytes, good enough for these fixtures:
    /// `entries_at` is where the entry array actually lives on the notional device.
    fn legacy_find_esp(lba1: &[u8], entries: &[u8], entries_at: u64, bs: u64) -> Legacy {
        // Old: `let header = read_dev(client, bs, 92)?;` then only a signature check.
        assert_eq!(&lba1[0..8], b"EFI PART", "fixture must carry the signature");
        let entry_lba = u64::from_le_bytes(lba1[0x48..0x50].try_into().unwrap());
        let num = u32::from_le_bytes(lba1[0x50..0x54].try_into().unwrap()) as u64;
        let esz = u32::from_le_bytes(lba1[0x54..0x58].try_into().unwrap()) as u64;
        // Old: `read_dev(client, entry_lba * bs, (num * esz) as usize)?`
        let want = num.wrapping_mul(esz);
        if want > (1 << 32) {
            return Legacy::WouldAllocate(want);
        }
        let offset = entry_lba.wrapping_mul(bs);
        let table: Vec<u8> = if offset == entries_at && (want as usize) <= entries.len() {
            entries[..want as usize].to_vec()
        } else {
            // Read landed somewhere else on the device: zeros for these fixtures.
            vec![0u8; want as usize]
        };
        let mut first_nonempty: Option<(u64, u64)> = None;
        for i in 0..num {
            let lo = (i * esz) as usize;
            let hi = ((i + 1) * esz) as usize;
            if hi > table.len() {
                return Legacy::ReadAt {
                    offset,
                    result: LegacyPick::WouldPanic,
                };
            }
            let e = &table[lo..hi];
            if e[0..16] == [0u8; 16] {
                continue;
            }
            let first = u64::from_le_bytes(e[32..40].try_into().unwrap());
            let last = u64::from_le_bytes(e[40..48].try_into().unwrap());
            // Old: `(last + 1 - first) * bs`, spelled wrapping for the same reason as
            // the multiplies above — a plain `-` panics under the test build's debug
            // assertions and silently underflows in the release build that ships.
            let bytes = last.wrapping_add(1).wrapping_sub(first).wrapping_mul(bs);
            if e[0..16] == ESP_TYPE_GUID {
                return Legacy::ReadAt {
                    offset,
                    result: LegacyPick::Esp(first.wrapping_mul(bs), bytes),
                };
            }
            first_nonempty.get_or_insert((first.wrapping_mul(bs), bytes));
        }
        Legacy::ReadAt {
            offset,
            result: match first_nonempty {
                // The fallback: a warning, and then the OS image goes here.
                Some((o, l)) => LegacyPick::FellBackToFirstPartition(o, l),
                None => LegacyPick::NoPartitions,
            },
        }
    }

    // --------------------------------------------------------------------------------
    // 1. The instrument works at all: a good table parses, and it is a table this tree
    //    really writes.
    // --------------------------------------------------------------------------------

    #[test]
    fn a_clean_table_yields_the_esp() {
        let g = clean();
        assert_eq!(
            find_esp_in_table(&g.lba1, &g.entries, BS, BLOCKS),
            Ok(EspRange {
                offset: 34 * BS,
                len: 66 * BS
            }),
        );
        assert_eq!(
            find_esp_identity_in_table(&g.lba1, &g.entries, BS, BLOCKS),
            Ok(EspIdentity {
                range: EspRange {
                    offset: 34 * BS,
                    len: 66 * BS
                },
                disk_guid: [0; 16],
                partition_guid: [0xAB; 16],
            }),
        );
        // And the plan agrees about where the array was.
        assert_eq!(entry_array_read_plan(&g.lba1, BS), Ok((2 * BS, 128 * 128)));
    }

    #[test]
    fn the_fixture_builder_produces_a_header_the_shared_validator_accepts() {
        // If this fails, every hostile case below is testing a header that was already
        // invalid for an unrelated reason and proves nothing.
        let g = clean();
        assert!(
            validated_header(&g.lba1).is_some(),
            "the fixture builder must produce a header fxfs_provisioner's own validator accepts"
        );
    }

    #[test]
    fn esp_is_found_in_a_table_the_provisioner_actually_builds() {
        // The anti-self-agreement anchor: real plan_layout + real build_gpt, i.e. the
        // bytes fxfs_provisioner puts on a real disk, not bytes this file invented.
        let block_size = 512u64;
        let block_count = (8u64 << 30) / block_size; // 8 GiB: comfortably above the minimum
        let plan = boot_layout::plan_layout(block_size, block_count).expect("plan an 8 GiB disk");
        let img = boot_layout::build_gpt(&plan, [1u8; 16], [2u8; 16], [3u8; 16]);

        let (off, len) = entry_array_read_plan(&img.primary_header, block_size)
            .expect("a table the provisioner built must validate");
        assert_eq!(off, img.primary_entries_lba * block_size);
        assert!(len <= img.entries.len());

        let got = find_esp_in_table(&img.primary_header, &img.entries, block_size, block_count)
            .expect("the provisioner's own ESP must be found");
        assert_eq!(got.offset, plan.esp.first_lba * block_size);
        assert_eq!(
            got.len,
            (plan.esp.last_lba - plan.esp.first_lba + 1) * block_size
        );
    }

    // --------------------------------------------------------------------------------
    // 2. Header size and header CRC.
    // --------------------------------------------------------------------------------

    #[test]
    fn a_header_with_a_bad_crc_is_refused_where_the_old_parse_trusted_it() {
        let mut g = clean();
        g.lba1[16] ^= 0xff; // corrupt the stored header CRC, nothing else
        assert_eq!(
            find_esp_in_table(&g.lba1, &g.entries, BS, BLOCKS),
            Err(EspError::DamagedHeader)
        );

        // The old parse never looked: signature present => every field trusted.
        assert_eq!(
            legacy_find_esp(&g.lba1, &g.entries, 2 * BS, BS),
            Legacy::ReadAt {
                offset: 2 * BS,
                result: LegacyPick::Esp(34 * BS, 66 * BS)
            },
            "the old parse accepted a header whose own checksum said it was corrupt"
        );
    }

    #[test]
    fn an_absurd_header_size_is_refused() {
        let mut g = clean();
        // header_size larger than the block handed in: the CRC would be computed over
        // bytes that were never read.
        g.lba1[12..16].copy_from_slice(&4096u32.to_le_bytes());
        reseal(&mut g.lba1);
        assert_eq!(
            find_esp_in_table(&g.lba1, &g.entries, BS, BLOCKS),
            Err(EspError::DamagedHeader)
        );

        let mut h = clean();
        h.lba1[12..16].copy_from_slice(&8u32.to_le_bytes()); // below the 92-byte minimum
        reseal(&mut h.lba1);
        assert_eq!(
            find_esp_in_table(&h.lba1, &h.entries, BS, BLOCKS),
            Err(EspError::DamagedHeader)
        );

        // Neither shape troubled the old parse.
        assert!(matches!(
            legacy_find_esp(&g.lba1, &g.entries, 2 * BS, BS),
            Legacy::ReadAt {
                result: LegacyPick::Esp(..),
                ..
            }
        ));
    }

    #[test]
    fn no_signature_and_a_short_header_are_distinguished() {
        let mut g = clean();
        g.lba1[0..8].copy_from_slice(b"NOTAPART");
        assert_eq!(
            find_esp_in_table(&g.lba1, &g.entries, BS, BLOCKS),
            Err(EspError::NoSignature)
        );
        assert_eq!(
            find_esp_in_table(&[0u8; 16], &g.entries, BS, BLOCKS),
            Err(EspError::ShortHeader)
        );
        assert_eq!(
            find_esp_in_table(&clean().lba1, &g.entries, 0, BLOCKS),
            Err(EspError::BadBlockSize)
        );
        assert_eq!(
            find_esp_in_table(&clean().lba1, &g.entries, 999, BLOCKS),
            Err(EspError::BadBlockSize)
        );
    }

    // --------------------------------------------------------------------------------
    // 3. Entry-array CRC.
    // --------------------------------------------------------------------------------

    #[test]
    fn a_tampered_entry_array_is_refused_where_the_old_parse_used_it() {
        // The sharpest case: the header is byte-perfect and passes its own CRC. Only
        // the entries under it were rewritten — an ESP pointed at someone else's data.
        let mut g = clean();
        g.entries[32..40].copy_from_slice(&500_000u64.to_le_bytes()); // first_lba
        g.entries[40..48].copy_from_slice(&600_000u64.to_le_bytes()); // last_lba
        assert!(
            validated_header(&g.lba1).is_some(),
            "header must still be valid"
        );
        assert_eq!(
            find_esp_in_table(&g.lba1, &g.entries, BS, BLOCKS),
            Err(EspError::DamagedEntryArray),
            "the header's entries_crc must be what catches this"
        );

        // The old parse checked no CRC at all and would have written the OS image at
        // byte 256,000,000 — wherever that lands.
        assert_eq!(
            legacy_find_esp(&g.lba1, &g.entries, 2 * BS, BS),
            Legacy::ReadAt {
                offset: 2 * BS,
                result: LegacyPick::Esp(500_000 * BS, 100_001 * BS),
            },
            "the old parse followed a partition entry nothing had authenticated"
        );
    }

    #[test]
    fn a_short_entry_array_is_refused_not_indexed_past() {
        // HONEST SCOPE. Unlike every other case here, this one is NOT a demonstrated
        // defect in the old parse. The old code sized its own read
        // (`read_dev(..., num * esz)`), and `read_dev` returns exactly the requested
        // length or errors, so the table it walked was always exactly `num * esz`
        // bytes and its `table[i*esz..(i+1)*esz]` slicing could not run off the end.
        //
        // What this guards is the NEW module's API contract: `find_esp_in_table` takes
        // the entry bytes from its caller, so a caller that under-reads — a short
        // device, a partial read, a future caller that does not use
        // `entry_array_read_plan` — must get a refusal rather than a panic in a
        // component whose next action is a 45 MiB write. Recorded as a new guard, not
        // as a fix.
        let g = clean();
        let truncated = &g.entries[..100];
        assert_eq!(
            find_esp_in_table(&g.lba1, truncated, BS, BLOCKS),
            Err(EspError::ShortEntryArray)
        );
        assert_eq!(
            find_esp_in_table(&g.lba1, &[], BS, BLOCKS),
            Err(EspError::ShortEntryArray)
        );
    }

    // --------------------------------------------------------------------------------
    // 4. The two unchecked multiplies.
    // --------------------------------------------------------------------------------

    #[test]
    fn an_absurd_entry_count_times_size_cannot_drive_the_allocation() {
        // num * esz as the old parse computed it: 0xFFFF_FF80 * 0xFFFF_FF80. The entry
        // array is not materialised even by this test — building it would abort the
        // test process, which is the whole point.
        let lba1 = build_header_only(0xFFFF_FF80, 0xFFFF_FF80, 2);
        assert!(
            validated_header(&lba1).is_some(),
            "the header itself must be valid"
        );
        assert_eq!(
            entry_array_read_plan(&lba1, BS),
            Err(EspError::BadEntryGeometry),
            "entry geometry must be range-checked before it sizes anything"
        );

        // What the old code would have handed to `vec![0u8; _]`. ~1.8e19 bytes = 18 EB.
        let Legacy::WouldAllocate(n) = legacy_find_esp(&lba1, &[], 2 * BS, BS) else {
            panic!("the old parse should have tried to allocate");
        };
        assert!(
            n > (1u64 << 63),
            "the old parse sized a Vec at {n} bytes (abort)"
        );
    }

    #[test]
    fn a_merely_large_entry_count_is_also_refused() {
        // Not an overflow — just 4096 x 4096 = 16 MiB, which allocates fine and is
        // still nothing a real GPT ever contains. `boot_layout` caps the count at
        // 4096; MAX_ENTRY_ARRAY_BYTES is what caps the product.
        let lba1 = build_header_only(4096, 4096, 2);
        assert_eq!(
            entry_array_read_plan(&lba1, BS),
            Err(EspError::BadEntryGeometry)
        );
        // And the old parse would have read and walked all 16 MiB of it.
        assert!(matches!(
            legacy_find_esp(&lba1, &[], 2 * BS, BS),
            Legacy::ReadAt { .. }
        ));

        // 8192 entries: over boot_layout's own count cap, i.e. the shared check fires.
        let h = build_header_only(8192, 128, 2);
        assert_eq!(
            entry_array_read_plan(&h, BS),
            Err(EspError::BadEntryGeometry)
        );

        // An entry size that is not a multiple of 128 is not a GPT at all.
        let k = build_header_only(128, 129, 2);
        assert_eq!(
            entry_array_read_plan(&k, BS),
            Err(EspError::BadEntryGeometry)
        );

        // Zero entries: `boot_layout` refuses this too, and a zero-length read that
        // then walks zero entries would otherwise reach the NoEsp path by accident.
        let z = build_header_only(0, 128, 2);
        assert_eq!(
            entry_array_read_plan(&z, BS),
            Err(EspError::BadEntryGeometry)
        );
    }

    #[test]
    fn entry_lba_times_block_size_cannot_wrap_into_a_wrong_offset() {
        // entry_lba chosen so entry_lba * 512 wraps to exactly 4096: a small, valid,
        // perfectly readable device offset. The read SUCCEEDS and returns the wrong
        // bytes, which is worse than failing.
        let entry_lba = (1u64 << 55) + 8; // * 512 == 2^64 + 4096 == 4096 (mod 2^64)
        let mut g = build(128, 128, entry_lba, &[(ESP_TYPE_GUID, 34, 99)]);
        reseal(&mut g.lba1);
        assert_eq!(
            entry_array_read_plan(&g.lba1, BS),
            Err(EspError::EntryArrayOffsetOverflow),
        );

        // Demonstrate the wrap really is silent, and really is a plausible offset.
        // (`entry_lba * BS` cannot even be written here: rustc rejects the constant
        // multiply outright, which is precisely the operation the old parse performed
        // at runtime on a value it had read off the disk.)
        assert_eq!(entry_lba.wrapping_mul(BS), 4096);
        // Say the entry array really does live at LBA 2, as in the clean fixture. The
        // old parse reads byte 4096 instead and never notices.
        let Legacy::ReadAt { offset, result } = legacy_find_esp(&g.lba1, &g.entries, 2 * BS, BS)
        else {
            panic!("the old parse should have performed a read");
        };
        assert_eq!(
            offset, 4096,
            "the old parse read the entry array from the wrong place"
        );
        assert_eq!(
            result,
            LegacyPick::NoPartitions,
            "and it then made a decision about a partition table it never actually read",
        );
    }

    #[test]
    fn a_partition_spanning_the_whole_address_space_is_refused() {
        // REGRESSION. The first version of this module computed the length as
        // `last - first + 1` with a plain `+`, having checked only `last >= first` and
        // `first * block_size`. first=0, last=u64::MAX passes both of those and then
        // overflows the length: a panic in a debug build, and in the release build that
        // ships, a wrap to zero — a zero-length ESP that `PartitionIo` would then treat
        // as a partition it may write into at any offset. The case was found by review,
        // not by the tests above, which is why it is called out separately: the
        // boundary a range check misses is the one where the range is the whole space.
        let g = build(128, 128, 2, &[(ESP_TYPE_GUID, 0, u64::MAX)]);
        assert_eq!(
            find_esp_in_table(&g.lba1, &g.entries, BS, BLOCKS),
            Err(EspError::BadPartitionRange),
        );
        // Also the one-block-short variant, so the fix is not an off-by-one that only
        // catches the exact maximum.
        let h = build(128, 128, 2, &[(ESP_TYPE_GUID, 1, u64::MAX)]);
        assert_eq!(
            find_esp_in_table(&h.lba1, &h.entries, BS, BLOCKS),
            Err(EspError::BadPartitionRange),
        );
    }

    #[test]
    fn a_partition_that_runs_off_the_end_of_the_device_is_refused() {
        // In range arithmetically, and not on this disk. Without a device bound the
        // parse would nominate a region past the end and the write would either fail
        // late (after the FAT mount had already begun) or land somewhere unintended.
        let g = build(128, 128, 2, &[(ESP_TYPE_GUID, BLOCKS - 10, BLOCKS + 10)]);
        assert_eq!(
            find_esp_in_table(&g.lba1, &g.entries, BS, BLOCKS),
            Err(EspError::PartitionOffDevice),
        );
        // Exactly filling the device is fine (last block index == BLOCKS - 1).
        let h = build(128, 128, 2, &[(ESP_TYPE_GUID, 34, BLOCKS - 1)]);
        assert!(find_esp_in_table(&h.lba1, &h.entries, BS, BLOCKS).is_ok());
        // One past is not.
        let k = build(128, 128, 2, &[(ESP_TYPE_GUID, 34, BLOCKS)]);
        assert_eq!(
            find_esp_in_table(&k.lba1, &k.entries, BS, BLOCKS),
            Err(EspError::PartitionOffDevice),
        );
    }

    #[test]
    fn two_entries_claiming_the_esp_type_are_refused_not_silently_resolved() {
        // A table with two EFI System Partitions is not a table we understand, and
        // "take the first" is the same species of guess as the fallback this module
        // removed: it picks a destination for a whole OS image out of an ambiguity.
        let g = build(
            128,
            128,
            2,
            &[(ESP_TYPE_GUID, 34, 60), (ESP_TYPE_GUID, 61, 99)],
        );
        assert_eq!(
            find_esp_in_table(&g.lba1, &g.entries, BS, BLOCKS),
            Err(EspError::MultipleEsp),
        );
    }

    #[test]
    fn an_inverted_or_overflowing_partition_range_is_refused() {
        // last < first.
        let g = build(128, 128, 2, &[(ESP_TYPE_GUID, 99, 34)]);
        assert_eq!(
            find_esp_in_table(&g.lba1, &g.entries, BS, BLOCKS),
            Err(EspError::BadPartitionRange),
        );

        // first * block_size overflows.
        let h = build(128, 128, 2, &[(ESP_TYPE_GUID, u64::MAX - 1, u64::MAX)]);
        assert_eq!(
            find_esp_in_table(&h.lba1, &h.entries, BS, BLOCKS),
            Err(EspError::BadPartitionRange),
        );

        // The old parse computed `(last + 1 - first) * bs` with neither check: on the
        // inverted range that is an underflow, and it would have reported a partition
        // ~2^64 bytes long starting at byte 50688.
        let Legacy::ReadAt {
            result: LegacyPick::Esp(off, len),
            ..
        } = legacy_find_esp(&g.lba1, &g.entries, 2 * BS, BS)
        else {
            panic!("the old parse should have returned a partition");
        };
        assert_eq!(off, 99 * BS);
        assert!(
            len > (1u64 << 60),
            "the old parse reported a {len}-byte partition"
        );
    }

    // --------------------------------------------------------------------------------
    // 5. The fallback, and the reason `NoEsp` exists.
    // --------------------------------------------------------------------------------

    #[test]
    fn a_table_with_no_esp_is_refused() {
        // A completely valid GPT — correct signature, correct header CRC, correct
        // entry-array CRC — that simply contains no EFI System Partition. This is not
        // a hostile input; it is what you get by pointing the updater at any disk that
        // is not the one it expected.
        let g = build(128, 128, 2, &[(OTHER_GUID, 34, 99)]);
        assert!(
            validated_header(&g.lba1).is_some(),
            "this table is valid, just not ours"
        );
        assert_eq!(
            find_esp_in_table(&g.lba1, &g.entries, BS, BLOCKS),
            Err(EspError::NoEsp),
            "with no ESP there is no safe partition to guess: refuse"
        );

        // What the old parse did instead: took the first non-empty partition — here
        // the Fxfs container holding the package store and user data — and returned it
        // as the place to write a whole OS image.
        assert_eq!(
            legacy_find_esp(&g.lba1, &g.entries, 2 * BS, BS),
            Legacy::ReadAt {
                offset: 2 * BS,
                result: LegacyPick::FellBackToFirstPartition(34 * BS, 66 * BS),
            },
            "the old parse redirected the write rather than stopping it"
        );
    }

    #[test]
    fn an_esp_after_other_partitions_is_still_found() {
        // The fallback's removal must not become "only entry 0 counts": a real
        // multi-partition disk lists the ESP wherever it lists it.
        let g = build(
            128,
            128,
            2,
            &[
                (OTHER_GUID, 34, 40),
                (OTHER_GUID, 41, 50),
                (ESP_TYPE_GUID, 51, 99),
            ],
        );
        assert_eq!(
            find_esp_in_table(&g.lba1, &g.entries, BS, BLOCKS),
            Ok(EspRange {
                offset: 51 * BS,
                len: 49 * BS
            }),
        );
    }

    #[test]
    fn an_empty_table_is_refused_and_never_returns_a_zero_range() {
        let g = build(128, 128, 2, &[]);
        assert_eq!(
            find_esp_in_table(&g.lba1, &g.entries, BS, BLOCKS),
            Err(EspError::NoEsp)
        );
        assert_eq!(
            legacy_find_esp(&g.lba1, &g.entries, 2 * BS, BS),
            Legacy::ReadAt {
                offset: 2 * BS,
                result: LegacyPick::NoPartitions
            },
            "the empty case is the one thing the old parse also refused"
        );
    }

    #[test]
    fn every_error_has_a_distinct_token() {
        // The serial log is how a failed OTA is diagnosed; two refusals that print the
        // same token are one refusal for anyone reading the log.
        let all = [
            EspError::BadBlockSize,
            EspError::ShortHeader,
            EspError::NoSignature,
            EspError::DamagedHeader,
            EspError::BadEntryGeometry,
            EspError::EntryArrayOffsetOverflow,
            EspError::ShortEntryArray,
            EspError::DamagedEntryArray,
            EspError::BadPartitionRange,
            EspError::PartitionOffDevice,
            EspError::MultipleEsp,
            EspError::NoEsp,
        ];
        let mut seen: Vec<&str> = all.iter().map(|e| e.token()).collect();
        seen.sort_unstable();
        let n = seen.len();
        seen.dedup();
        assert_eq!(seen.len(), n, "EspError tokens must be distinct");
    }
}

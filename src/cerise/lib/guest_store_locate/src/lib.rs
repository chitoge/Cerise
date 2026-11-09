//! Which partition, on which disk, holds the guest image — and whether to
//! believe it.
//!
//! This is the *decision* half of reading a guest image off a block device, split
//! out as a pure library so it can be unit-tested on the host against inputs a
//! live boot could never be made to produce. The same split the file server uses
//! for `claim.rs`, the provisioner for `layout.rs`/`ownership.rs` and the updater
//! for `esp.rs`; the consuming binary depends on this crate rather than
//! re-`mod`ing the source, so there is exactly one compilation of the logic and no
//! drift between what the tests check and what ships.
//!
//! ## Why this exists at all, when block I/O is already proven
//!
//! `ahci_probe` proves **I/O** and not **selection**. It opens the aggregated
//! `fuchsia.hardware.block.volume.Service`, tries every instance until one
//! answers, and writes a pattern at offset 0 of whichever one did. Its own
//! comment says it iterates in reverse relative to `nvme_probe` to *reduce, not
//! eliminate*, the chance the two probes race onto the same physical device. That
//! is not device selection; it is a coin flip with a comment.
//!
//! Four facts make selection genuinely hard here, and none of them is fixed by
//! more I/O:
//!
//! 1. **The aggregated Service does not preserve driver instance names.** The
//!    directory lists opaque anonymized identifiers, stable only within a boot —
//!    not `sata0` or `namespace-1`.
//! 2. **There is no per-consumer device routing.** The file server records this
//!    as the open problem in the tree's own words: it "is handed an AGGREGATED
//!    block service and has to guess which member is its own".
//! 3. **There are no partition block devices.** Cerise has no GPT driver, so
//!    there is one Service instance per *whole physical disk*. Hence this crate:
//!    the consumer parses the GPT itself and offsets into a whole disk.
//! 4. **Partition identity over FIDL is a placeholder.** `GetTypeGuid` returns
//!    `ZX_OK` with an all-zero GUID on both AHCI and NVMe. A successful call
//!    returning meaningless data is the `0xff`-impersonation failure mode in a
//!    different costume, so the GUID has to come from the table on the disk.
//!
//! ## The rules, and why each one is a refusal rather than a fallback
//!
//! * **Scan every instance; do not stop at the first match.** A type GUID
//!   identifies a *content type*, not which physical disk was meant.
//! * **Require exactly one match across all instances.** Two matches is a
//!   refusal. This is the rule whose absence cost the file server a debugging
//!   session.
//! * **Three distinct evidence states, never collapsed:** no GPT, damaged GPT,
//!   unreadable. Damaged or unreadable must never fall through to "no partition"
//!   — that is how an I/O error becomes a blank disk.
//! * **Bound every range against the device's real `block_count`.** A partition
//!   table is not evidence about the disk it was read from.
//! * **A store shorter than its partition is normal.** See
//!   [`store_len_within_partition`].
//!
//! What this crate deliberately does NOT do: recover from the backup GPT. A
//! recovery path that has never been exercised is worse than a refusal that has,
//! so a primary header that does not validate is [`LocateError::DamagedHeader`]
//! and the caller stops.

use std::ops::Range;

/// The largest entry array this will read.
///
/// A header is attacker-controlled, so the allocation it implies needs a ceiling
/// that does not come from the header itself. `boot_layout::entry_array_location`
/// already caps the *count* at 4096, but the entry *size* is only required to be a
/// non-zero multiple of 128, so their product is still ~17 TB in the worst case.
/// Real tables are 128 x 128 = 16 KiB.
pub const MAX_ENTRY_ARRAY_BYTES: usize = 1 << 20;

/// The largest single partition entry this will accept. GPT requires a multiple
/// of 128; every implementation in practice uses exactly 128.
pub const MAX_ENTRY_SIZE: usize = 4096;

/// Why a guest-image partition could not be located on ONE device.
///
/// Every variant is a refusal; there is no variant meaning "we guessed". The
/// three-way distinction the module docs insist on is carried by
/// [`LocateError::NoSignature`] (no GPT), [`LocateError::DamagedHeader`] /
/// [`LocateError::DamagedEntryArray`] (damaged GPT), and — because an I/O failure
/// is the caller's to observe, not this crate's — by the caller mapping a read
/// error to [`DeviceEvidence::Unreadable`] rather than to `Absent`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocateError {
    /// `block_size` was zero or not a multiple of 512.
    BadBlockSize,
    /// Fewer bytes than a GPT header were handed in.
    ShortHeader,
    /// No `"EFI PART"` at LBA 1. There is no GPT here at all — a legitimate
    /// answer for a disk that is not ours, and NOT the same as a damaged one.
    NoSignature,
    /// The signature is present but the header does not validate: an
    /// out-of-range `header_size`, or a header CRC that does not match.
    /// Something IS there and not one field of it can be trusted.
    DamagedHeader,
    /// The header's entry geometry is absurd.
    BadEntryGeometry,
    /// `entry_lba * block_size` does not fit in a `u64`.
    EntryArrayOffsetOverflow,
    /// The caller supplied fewer entry-array bytes than the header asked for.
    ShortEntryArray,
    /// The entry array's CRC-32 does not match. The header is authentic-looking
    /// and the table under it is not.
    DamagedEntryArray,
    /// A partition entry's `last_lba < first_lba`, or its byte range overflows.
    BadPartitionRange,
    /// The range is arithmetically fine and is not on this device.
    PartitionOffDevice,
    /// Two entries on this device claim the guest-image type.
    MultipleOnDevice,
    /// The table is entirely valid and contains no guest-image partition.
    NotPresent,
}

impl LocateError {
    /// A short, stable token for the serial log. Callers prefix it with their own
    /// marker.
    pub fn token(self) -> &'static str {
        match self {
            LocateError::BadBlockSize => "bad-block-size",
            LocateError::ShortHeader => "short-header",
            LocateError::NoSignature => "no-gpt-signature",
            LocateError::DamagedHeader => "damaged-header",
            LocateError::BadEntryGeometry => "bad-entry-geometry",
            LocateError::EntryArrayOffsetOverflow => "entry-array-offset-overflow",
            LocateError::ShortEntryArray => "short-entry-array",
            LocateError::DamagedEntryArray => "damaged-entry-array",
            LocateError::BadPartitionRange => "bad-partition-range",
            LocateError::PartitionOffDevice => "partition-off-device",
            LocateError::MultipleOnDevice => "multiple-guest-partitions-on-device",
            LocateError::NotPresent => "no-guest-partition",
        }
    }

    /// True for the states that must NEVER be treated as "this disk simply does
    /// not have one".
    ///
    /// The distinction is the whole point of the taxonomy: `NoSignature` and
    /// `NotPresent` are *evidence* that a disk is not ours, and every other
    /// variant is evidence that we could not tell. Collapsing the second group
    /// into the first is how a damaged table, or a table we failed to parse,
    /// becomes a silent "no store here" and then a blank guest disk.
    pub fn is_inconclusive(self) -> bool {
        !matches!(self, LocateError::NoSignature | LocateError::NotPresent)
    }
}

impl std::fmt::Display for LocateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let detail = match self {
            LocateError::BadBlockSize => "block size is zero or not a multiple of 512",
            LocateError::ShortHeader => "fewer bytes supplied than a GPT header occupies",
            LocateError::NoSignature => "no \"EFI PART\" signature at LBA 1",
            LocateError::DamagedHeader => "GPT header failed its size/CRC check",
            LocateError::BadEntryGeometry => "GPT entry count/size out of range",
            LocateError::EntryArrayOffsetOverflow => "entry-array LBA x block size overflows u64",
            LocateError::ShortEntryArray => "entry array shorter than the header requires",
            LocateError::DamagedEntryArray => "entry array failed its CRC check",
            LocateError::BadPartitionRange => {
                "partition entry has an inverted or overflowing range"
            }
            LocateError::PartitionOffDevice => "the partition does not lie within this device",
            LocateError::MultipleOnDevice => {
                "more than one guest-image partition on this device (refusing: which one \
                 holds the guest is not ours to guess)"
            }
            LocateError::NotPresent => "no guest-image partition in this table",
        };
        write!(f, "{} ({})", detail, self.token())
    }
}

/// A partition's location on one device, in bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PartitionRange {
    /// Byte offset of the partition's first block.
    pub offset: u64,
    /// Partition length in bytes.
    pub len: u64,
}

impl PartitionRange {
    pub fn end(&self) -> Option<u64> {
        self.offset.checked_add(self.len)
    }

    pub fn as_range(&self) -> Option<Range<u64>> {
        Some(self.offset..self.end()?)
    }
}

fn check_block_size(block_size: u64) -> Result<(), LocateError> {
    if block_size == 0 || block_size % 512 != 0 {
        return Err(LocateError::BadBlockSize);
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
/// The caller reads exactly that and passes it to [`find_partition_by_type`]. A
/// two-step split the caller cannot skip, for the reason the updater's ESP locator
/// gives: the entry array's location comes out of the header, so trusting it
/// before the header's own checksum has passed means sizing an allocation *and* a
/// device read from bytes that failed their own integrity check.
///
/// The header/geometry validators are `boot_layout`'s, shared with the component
/// that WRITES partition tables and the one that must not destroy them. A second
/// GPT validator in this tree would drift from the first, and the components that
/// must never disagree about "is this a valid table" are exactly those.
pub fn entry_array_read_plan(lba1: &[u8], block_size: u64) -> Result<(u64, usize), LocateError> {
    check_block_size(block_size)?;
    // Distinguish "no GPT" from "damaged GPT" BEFORE validating, so the log can
    // say which. `validated_header` collapses both into None, and collapsing them
    // is precisely what turns a damaged table into "not ours".
    if lba1.len() < 92 {
        return Err(LocateError::ShortHeader);
    }
    if lba1[0..8] != boot_layout::GPT_SIGNATURE {
        return Err(LocateError::NoSignature);
    }
    boot_layout::validated_header(lba1).ok_or(LocateError::DamagedHeader)?;

    let (entry_lba, array_len) =
        boot_layout::entry_array_location(lba1).ok_or(LocateError::BadEntryGeometry)?;
    let entry_size = le_u32(lba1, 84) as usize;
    if entry_size > MAX_ENTRY_SIZE || array_len > MAX_ENTRY_ARRAY_BYTES {
        return Err(LocateError::BadEntryGeometry);
    }
    let offset = entry_lba
        .checked_mul(block_size)
        .ok_or(LocateError::EntryArrayOffsetOverflow)?;
    Ok((offset, array_len))
}

/// Locate the sole partition of `wanted_type` in a validated table on ONE device.
///
/// `block_count` is the DEVICE's block count, and it is what bounds the result —
/// the table itself is not evidence about the disk it came from. **There is no
/// fallback partition.**
pub fn find_partition_by_type(
    lba1: &[u8],
    entries: &[u8],
    block_size: u64,
    block_count: u64,
    wanted_type: &[u8; 16],
) -> Result<PartitionRange, LocateError> {
    find_partition(lba1, entries, block_size, block_count, wanted_type, None)
}

/// Locate the sole partition whose type GUID and GPT name both match.
///
/// The name is matched as the GPT entry's fixed, NUL-padded UTF-16LE field.
/// This is useful when a legacy/shared type GUID is not sufficient ownership
/// evidence by itself. It deliberately retains all of
/// [`find_partition_by_type`]'s CRC, geometry, device-bound and ambiguity
/// checks.
pub fn find_partition_by_type_and_name(
    lba1: &[u8],
    entries: &[u8],
    block_size: u64,
    block_count: u64,
    wanted_type: &[u8; 16],
    wanted_name: &str,
) -> Result<PartitionRange, LocateError> {
    find_partition(
        lba1,
        entries,
        block_size,
        block_count,
        wanted_type,
        Some(wanted_name),
    )
}

fn find_partition(
    lba1: &[u8],
    entries: &[u8],
    block_size: u64,
    block_count: u64,
    wanted_type: &[u8; 16],
    wanted_name: Option<&str>,
) -> Result<PartitionRange, LocateError> {
    let (_, array_len) = entry_array_read_plan(lba1, block_size)?;
    let entry_size = le_u32(lba1, 84) as usize;
    let entry_count = le_u32(lba1, 80) as usize;

    if entries.len() < array_len {
        return Err(LocateError::ShortEntryArray);
    }
    // UEFI 2.10 table 5-5: the CRC covers exactly entry_count * entry_size bytes,
    // not any block padding around them. Without this a header can be authentic —
    // its own CRC checks out — while every partition entry under it is chosen by
    // whoever wrote the disk.
    if boot_layout::crc32(&entries[..array_len]) != le_u32(lba1, 88) {
        return Err(LocateError::DamagedEntryArray);
    }

    let device_bytes = block_count
        .checked_mul(block_size)
        .ok_or(LocateError::BadPartitionRange)?;

    let mut found: Option<PartitionRange> = None;
    for i in 0..entry_count {
        let e = &entries[i * entry_size..(i + 1) * entry_size];
        if e[0..16] == [0u8; 16] {
            continue; // unused entry
        }
        if &e[0..16] != wanted_type.as_slice() {
            continue;
        }
        if let Some(wanted_name) = wanted_name {
            let mut encoded = [0u8; 72];
            for (i, unit) in wanted_name
                .encode_utf16()
                .take(encoded.len() / 2 - 1)
                .enumerate()
            {
                encoded[i * 2..i * 2 + 2].copy_from_slice(&unit.to_le_bytes());
            }
            if e.get(56..128) != Some(encoded.as_slice()) {
                continue;
            }
        }
        // A second match is an ambiguity, and resolving an ambiguity by taking
        // the first is the same guess this crate exists to remove.
        if found.is_some() {
            return Err(LocateError::MultipleOnDevice);
        }
        let first = le_u64(e, 32);
        let last = le_u64(e, 40);
        if last < first {
            return Err(LocateError::BadPartitionRange);
        }
        // GPT ranges are INCLUSIVE, so the block count is `last - first + 1`, and
        // that `+ 1` is itself an overflow when an entry claims the whole address
        // space (first=0, last=u64::MAX) — a case that passes the ordering check.
        // Every step is checked; there is no "obviously fine" arithmetic on a
        // field that came off a disk.
        let blocks = last
            .checked_sub(first)
            .and_then(|n| n.checked_add(1))
            .ok_or(LocateError::BadPartitionRange)?;
        let offset = first
            .checked_mul(block_size)
            .ok_or(LocateError::BadPartitionRange)?;
        let len = blocks
            .checked_mul(block_size)
            .ok_or(LocateError::BadPartitionRange)?;
        // The exclusive end must exist too: a reader adds its cursor to `offset`,
        // so a range whose end wraps would let a caller address arbitrary device
        // offsets by seeking.
        let end = offset
            .checked_add(len)
            .ok_or(LocateError::BadPartitionRange)?;
        if end > device_bytes {
            return Err(LocateError::PartitionOffDevice);
        }
        found = Some(PartitionRange { offset, len });
    }
    found.ok_or(LocateError::NotPresent)
}

/// What one aggregated-Service instance turned out to be.
///
/// The three states the module docs require, as a type, so that a caller cannot
/// accidentally treat the third as the first. `Unreadable` exists because an I/O
/// failure is observed by the caller (this crate never touches a device) and must
/// still be carried into the decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeviceEvidence {
    /// A guest-image partition was found here, at this byte range.
    Found(PartitionRange),
    /// This device is legitimately not ours: no GPT, or a valid table with no
    /// guest-image partition.
    Absent(LocateError),
    /// Something is here and we could not tell what: a damaged table, absurd
    /// geometry, a range off the device.
    Damaged(LocateError),
    /// The device could not be read at all. Carries the caller's message.
    Unreadable(String),
}

impl DeviceEvidence {
    /// Classifies a [`find_partition_by_type`] result into `Found`/`Absent`/`Damaged`.
    ///
    /// The mapping is [`LocateError::is_inconclusive`] and nothing else, so there
    /// is one place where "does this count as absent?" is decided.
    pub fn classify(result: Result<PartitionRange, LocateError>) -> Self {
        match result {
            Ok(range) => DeviceEvidence::Found(range),
            Err(err) if err.is_inconclusive() => DeviceEvidence::Damaged(err),
            Err(err) => DeviceEvidence::Absent(err),
        }
    }
}

/// Why a scan across every instance did not yield exactly one guest image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SelectError {
    /// No instances were published at all.
    NoInstances,
    /// Every instance was legitimately not ours.
    ///
    /// The ONLY refusal that means "there is genuinely no guest image here", and
    /// therefore the only one a caller could ever consider survivable.
    NoneFound,
    /// More than one instance carries a guest-image partition. **Two matches is a
    /// refusal, not a choice.** The aggregate anonymizes instance names, so there
    /// is no basis on which to prefer one — and the file server's selection bug
    /// was found exactly by attaching a second disk.
    Ambiguous { matches: Vec<String> },
    /// At least one instance was damaged or unreadable, so "none found" cannot be
    /// concluded.
    ///
    /// Separate from `NoneFound` on purpose. If a disk we could not read might
    /// have held the store, then "no store" is not something this scan
    /// established — it is something it failed to establish.
    Inconclusive { reasons: Vec<(String, String)> },
}

impl SelectError {
    pub fn token(&self) -> &'static str {
        match self {
            SelectError::NoInstances => "no-block-instances",
            SelectError::NoneFound => "no-guest-partition-on-any-device",
            SelectError::Ambiguous { .. } => "ambiguous-guest-partition",
            SelectError::Inconclusive { .. } => "inconclusive-device-evidence",
        }
    }
}

impl std::fmt::Display for SelectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SelectError::NoInstances => {
                write!(
                    f,
                    "no block Service instances were published ({})",
                    self.token()
                )
            }
            SelectError::NoneFound => write!(
                f,
                "no device carries a guest-image partition, and every device was \
                 conclusively surveyed ({})",
                self.token()
            ),
            SelectError::Ambiguous { matches } => write!(
                f,
                "{} devices carry a guest-image partition ({:?}); refusing to choose, \
                 because the aggregated Service anonymizes instance names and there is \
                 no basis to prefer one ({})",
                matches.len(),
                matches,
                self.token()
            ),
            SelectError::Inconclusive { reasons } => write!(
                f,
                "{} device(s) could not be conclusively surveyed ({:?}); \"no guest image\" \
                 is therefore not established, and a damaged or unreadable disk must never \
                 be reported as simply not having one ({})",
                reasons.len(),
                reasons,
                self.token()
            ),
        }
    }
}

/// The instance chosen, and its partition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Selection {
    /// The aggregated-Service instance name. Opaque and stable only within a
    /// boot, which is exactly why it is reported: it is provenance for the run,
    /// not an identity to persist.
    pub instance: String,
    pub range: PartitionRange,
}

/// Choose the sole device carrying a guest image, or refuse.
///
/// Takes the WHOLE survey rather than being called per device, because every rule
/// that matters is a property of the set: exactly one match, and no inconclusive
/// evidence anywhere. A per-device API would let a caller stop at the first match
/// and never learn about the second.
///
/// Ordering of refusals is deliberate. Ambiguity is reported before
/// inconclusiveness, because two positively-identified stores is a configuration
/// error the operator must fix, whereas an unreadable third disk is noise next to
/// it. Inconclusiveness is reported before `NoneFound`, because that is the whole
/// point of tracking it.
pub fn select_sole_device(survey: &[(String, DeviceEvidence)]) -> Result<Selection, SelectError> {
    if survey.is_empty() {
        return Err(SelectError::NoInstances);
    }
    let mut found: Vec<Selection> = Vec::new();
    let mut inconclusive: Vec<(String, String)> = Vec::new();
    for (instance, evidence) in survey {
        match evidence {
            DeviceEvidence::Found(range) => found.push(Selection {
                instance: instance.clone(),
                range: *range,
            }),
            DeviceEvidence::Damaged(err) => {
                inconclusive.push((instance.clone(), err.token().to_owned()))
            }
            DeviceEvidence::Unreadable(msg) => {
                inconclusive.push((instance.clone(), format!("unreadable: {msg}")))
            }
            DeviceEvidence::Absent(_) => {}
        }
    }
    if found.len() > 1 {
        return Err(SelectError::Ambiguous {
            matches: found.into_iter().map(|s| s.instance).collect(),
        });
    }
    if let Some(sole) = found.pop() {
        // A single match wins even if another disk was unreadable: the store was
        // positively identified, and the unreadable disk cannot make that less
        // true. This is the one place inconclusive evidence is NOT fatal, and it
        // is deliberate — the asymmetry is that inconclusive evidence can only
        // undermine a NEGATIVE conclusion.
        return Ok(sole);
    }
    if !inconclusive.is_empty() {
        return Err(SelectError::Inconclusive {
            reasons: inconclusive,
        });
    }
    Err(SelectError::NoneFound)
}

/// Is a store of `total_len` bytes consistent with a partition of `partition_len`?
///
/// **This is the check that used to be exact equality, and exact equality was
/// wrong.** The BOOTFS path asserted `header.total_len() == store_len`, which is
/// correct there — a BOOTFS entry's length *is* the store's length. A partition is
/// normally *larger* than the store it holds: it is sized by whoever partitioned
/// the disk, not by the pack that was later written into it. Carrying the equality
/// across would have rejected every correctly-sized partition, and the failure
/// would have looked like a corrupt store rather than a mis-specified check.
///
/// So: the header's `total_len` is the authority on how long the store is, the
/// partition merely has to be big enough to contain it, and the store length the
/// caller then uses is `total_len` — not the partition length, which would let
/// reads run off the end of the pack into whatever the partition's tail happens to
/// hold.
pub fn store_len_within_partition(total_len: u64, partition_len: u64) -> Result<u64, String> {
    if total_len == 0 {
        return Err("the store header describes a zero-length store".to_owned());
    }
    if total_len > partition_len {
        return Err(format!(
            "the store header describes {total_len} bytes but its partition is only \
             {partition_len} bytes; the store does not fit the partition it was found in"
        ));
    }
    Ok(total_len)
}

#[cfg(test)]
mod tests {
    use super::*;

    const BS: u64 = 512;

    /// Builds a GPT whose entry array holds the given `(type_guid, first_lba,
    /// last_lba)` entries, with correct header and entry-array CRCs.
    ///
    /// Correct CRCs by construction, so that a test asserting a REFUSAL is
    /// refusing for the reason it names rather than because the fixture was
    /// malformed in some other way.
    fn table(entries_in: &[([u8; 16], u64, u64)], block_count: u64) -> (Vec<u8>, Vec<u8>) {
        let entry_count: u32 = 128;
        let entry_size: u32 = 128;
        let mut entries = vec![0u8; (entry_count * entry_size) as usize];
        for (i, (guid, first, last)) in entries_in.iter().enumerate() {
            let at = i * entry_size as usize;
            entries[at..at + 16].copy_from_slice(guid);
            // A unique instance GUID, so entries are not byte-identical.
            entries[at + 16] = (i as u8) + 1;
            entries[at + 32..at + 40].copy_from_slice(&first.to_le_bytes());
            entries[at + 40..at + 48].copy_from_slice(&last.to_le_bytes());
        }
        let mut lba1 = vec![0u8; BS as usize];
        lba1[0..8].copy_from_slice(&boot_layout::GPT_SIGNATURE);
        lba1[8..12].copy_from_slice(&0x0001_0000u32.to_le_bytes()); // revision
        lba1[12..16].copy_from_slice(&92u32.to_le_bytes()); // header_size
        lba1[24..32].copy_from_slice(&1u64.to_le_bytes()); // my_lba
        lba1[32..40].copy_from_slice(&(block_count - 1).to_le_bytes()); // alternate_lba
        lba1[40..48].copy_from_slice(&34u64.to_le_bytes()); // first_usable
        lba1[48..56].copy_from_slice(&(block_count - 34).to_le_bytes()); // last_usable
        lba1[72..80].copy_from_slice(&2u64.to_le_bytes()); // entry_lba
        lba1[80..84].copy_from_slice(&entry_count.to_le_bytes());
        lba1[84..88].copy_from_slice(&entry_size.to_le_bytes());
        let entries_crc = boot_layout::crc32(&entries[..(entry_count * entry_size) as usize]);
        lba1[88..92].copy_from_slice(&entries_crc.to_le_bytes());
        // Header CRC last, over the header with its own CRC field zeroed.
        lba1[16..20].copy_from_slice(&0u32.to_le_bytes());
        let hdr_crc = boot_layout::crc32(&lba1[..92]);
        lba1[16..20].copy_from_slice(&hdr_crc.to_le_bytes());
        (lba1, entries)
    }

    fn set_name(lba1: &mut [u8], entries: &mut [u8], index: usize, name: &str) {
        let at = index * 128 + 56;
        entries[at..at + 72].fill(0);
        for (i, unit) in name.encode_utf16().take(35).enumerate() {
            entries[at + i * 2..at + i * 2 + 2].copy_from_slice(&unit.to_le_bytes());
        }
        let entries_crc = boot_layout::crc32(&entries[..128 * 128]);
        lba1[88..92].copy_from_slice(&entries_crc.to_le_bytes());
        lba1[16..20].fill(0);
        let header_crc = boot_layout::crc32(&lba1[..92]);
        lba1[16..20].copy_from_slice(&header_crc.to_le_bytes());
    }

    const GUEST: [u8; 16] = boot_layout::GUEST_IMAGE_TYPE_GUID;
    const ESP: [u8; 16] = boot_layout::ESP_TYPE_GUID;

    // ── Fixture sanity. A fixture only this file agrees with proves nothing. ──

    #[test]
    fn a_clean_table_locates_the_guest_partition() {
        let bc = 200_000u64;
        let (lba1, entries) = table(&[(ESP, 2048, 6143), (GUEST, 6144, 20479)], bc);
        let r = find_partition_by_type(&lba1, &entries, BS, bc, &GUEST).expect("must locate");
        assert_eq!(r.offset, 6144 * BS);
        assert_eq!(r.len, (20479 - 6144 + 1) * BS);
        assert_eq!(r.end(), Some(20480 * BS));
    }

    #[test]
    fn the_esp_and_the_guest_partition_do_not_collide() {
        // The same table, asked for the other type, must give the other range.
        // Without this, "found the guest partition" could just mean "found the
        // first partition".
        let bc = 200_000u64;
        let (lba1, entries) = table(&[(ESP, 2048, 6143), (GUEST, 6144, 20479)], bc);
        let esp = find_partition_by_type(&lba1, &entries, BS, bc, &ESP).expect("must locate ESP");
        assert_eq!(esp.offset, 2048 * BS);
        assert_ne!(
            esp.offset,
            find_partition_by_type(&lba1, &entries, BS, bc, &GUEST)
                .unwrap()
                .offset
        );
    }

    #[test]
    fn a_shared_type_can_be_disambiguated_by_exact_gpt_name() {
        let bc = 200_000u64;
        let (mut lba1, mut entries) = table(&[(GUEST, 6144, 20479), (GUEST, 20480, 32767)], bc);
        set_name(&mut lba1, &mut entries, 0, "somebody-else");
        set_name(&mut lba1, &mut entries, 1, "cerise");

        let found = find_partition_by_type_and_name(&lba1, &entries, BS, bc, &GUEST, "cerise")
            .expect("the exact named partition must be selected");
        assert_eq!(found.offset, 20480 * BS);

        assert_eq!(
            find_partition_by_type_and_name(&lba1, &entries, BS, bc, &GUEST, "not-present",),
            Err(LocateError::NotPresent),
        );
    }

    #[test]
    fn two_exact_named_matches_are_still_ambiguous() {
        let bc = 200_000u64;
        let (mut lba1, mut entries) = table(&[(GUEST, 6144, 20479), (GUEST, 20480, 32767)], bc);
        set_name(&mut lba1, &mut entries, 0, "cerise");
        set_name(&mut lba1, &mut entries, 1, "cerise");
        assert_eq!(
            find_partition_by_type_and_name(&lba1, &entries, BS, bc, &GUEST, "cerise"),
            Err(LocateError::MultipleOnDevice),
        );
    }

    // ── Per-device refusals ──

    #[test]
    fn a_table_without_a_guest_partition_is_absent_not_damaged() {
        let bc = 200_000u64;
        let (lba1, entries) = table(&[(ESP, 2048, 6143)], bc);
        let err = find_partition_by_type(&lba1, &entries, BS, bc, &GUEST).unwrap_err();
        assert_eq!(err, LocateError::NotPresent);
        assert!(
            !err.is_inconclusive(),
            "a valid table with no match is conclusive"
        );
        assert!(matches!(
            DeviceEvidence::classify(Err(err)),
            DeviceEvidence::Absent(_)
        ));
    }

    #[test]
    fn no_signature_is_absent_and_a_damaged_header_is_not() {
        // The distinction this crate exists to preserve. A disk with no GPT is
        // legitimately not ours; a disk whose GPT is corrupt is a disk we cannot
        // read, and reporting the second as the first is how an I/O-level problem
        // becomes a silent blank guest disk.
        let blank = vec![0u8; BS as usize];
        let err = entry_array_read_plan(&blank, BS).unwrap_err();
        assert_eq!(err, LocateError::NoSignature);
        assert!(!err.is_inconclusive());
        assert!(matches!(
            DeviceEvidence::classify(Err(err)),
            DeviceEvidence::Absent(_)
        ));

        let bc = 200_000u64;
        let (mut lba1, _) = table(&[(GUEST, 6144, 20479)], bc);
        lba1[16] ^= 0xff; // corrupt the header CRC
        let err = entry_array_read_plan(&lba1, BS).unwrap_err();
        assert_eq!(err, LocateError::DamagedHeader);
        assert!(
            err.is_inconclusive(),
            "a damaged header must never read as absent"
        );
        assert!(matches!(
            DeviceEvidence::classify(Err(err)),
            DeviceEvidence::Damaged(_)
        ));
    }

    #[test]
    fn a_damaged_entry_array_is_refused_even_with_an_authentic_header() {
        // The header's own CRC still checks out here; only the entries are
        // altered. Without the separate entry-array CRC check, every partition
        // entry under an authentic header would be whatever the disk says.
        let bc = 200_000u64;
        let (lba1, mut entries) = table(&[(GUEST, 6144, 20479)], bc);
        entries[32] ^= 0xff; // move the partition's first_lba
        let err = find_partition_by_type(&lba1, &entries, BS, bc, &GUEST).unwrap_err();
        assert_eq!(err, LocateError::DamagedEntryArray);
        assert!(err.is_inconclusive());
    }

    #[test]
    fn two_guest_partitions_on_one_device_are_refused() {
        let bc = 200_000u64;
        let (lba1, entries) = table(&[(GUEST, 6144, 20479), (GUEST, 20480, 40959)], bc);
        assert_eq!(
            find_partition_by_type(&lba1, &entries, BS, bc, &GUEST).unwrap_err(),
            LocateError::MultipleOnDevice
        );
    }

    #[test]
    fn a_partition_past_the_end_of_the_device_is_refused() {
        // The table is internally valid; it is simply not a table about THIS
        // disk. Nothing in a partition table is evidence about the device it was
        // read from, which is why block_count is a separate argument.
        let (lba1, entries) = table(&[(GUEST, 6144, 20479)], 200_000);
        let err = find_partition_by_type(&lba1, &entries, BS, 10_000, &GUEST).unwrap_err();
        assert_eq!(err, LocateError::PartitionOffDevice);
        assert!(err.is_inconclusive());
    }

    #[test]
    fn an_inverted_range_is_refused() {
        let bc = 200_000u64;
        let (lba1, entries) = table(&[(GUEST, 20479, 6144)], bc);
        assert_eq!(
            find_partition_by_type(&lba1, &entries, BS, bc, &GUEST).unwrap_err(),
            LocateError::BadPartitionRange
        );
    }

    #[test]
    fn a_whole_address_space_range_is_refused_rather_than_overflowing() {
        // first=0, last=u64::MAX passes the ordering check, and `last - first + 1`
        // is the overflow. In release a wrapping `+ 1` would give a zero-length
        // partition at offset 0 — an in-range, perfectly readable, completely
        // wrong answer.
        let bc = 200_000u64;
        let (lba1, entries) = table(&[(GUEST, 0, u64::MAX)], bc);
        assert_eq!(
            find_partition_by_type(&lba1, &entries, BS, bc, &GUEST).unwrap_err(),
            LocateError::BadPartitionRange
        );
    }

    #[test]
    fn a_bad_block_size_is_refused_before_anything_is_parsed() {
        let bc = 200_000u64;
        let (lba1, entries) = table(&[(GUEST, 6144, 20479)], bc);
        for bad in [0u64, 500, 513] {
            assert_eq!(
                find_partition_by_type(&lba1, &entries, bad, bc, &GUEST).unwrap_err(),
                LocateError::BadBlockSize
            );
        }
    }

    #[test]
    fn a_short_entry_array_is_refused_rather_than_read_past() {
        let bc = 200_000u64;
        let (lba1, entries) = table(&[(GUEST, 6144, 20479)], bc);
        let truncated = &entries[..entries.len() / 2];
        assert_eq!(
            find_partition_by_type(&lba1, truncated, BS, bc, &GUEST).unwrap_err(),
            LocateError::ShortEntryArray
        );
    }

    // ── The cross-device selection rules ──

    fn found(off: u64) -> DeviceEvidence {
        DeviceEvidence::Found(PartitionRange {
            offset: off,
            len: 4096,
        })
    }

    #[test]
    fn exactly_one_match_across_instances_is_selected() {
        let survey = vec![
            (
                "aaa".to_owned(),
                DeviceEvidence::Absent(LocateError::NoSignature),
            ),
            ("bbb".to_owned(), found(6144 * BS)),
            (
                "ccc".to_owned(),
                DeviceEvidence::Absent(LocateError::NotPresent),
            ),
        ];
        let sel = select_sole_device(&survey).expect("exactly one match");
        assert_eq!(sel.instance, "bbb");
        assert_eq!(sel.range.offset, 6144 * BS);
    }

    #[test]
    fn two_matching_devices_are_refused_not_chosen_between() {
        // THE decoy case. The aggregate anonymizes instance names, so there is no
        // basis on which to prefer one; the file server's selection bug was found
        // exactly by attaching a second disk. A scan that stopped at the first
        // match would pass this and be wrong.
        let survey = vec![
            ("aaa".to_owned(), found(6144 * BS)),
            ("bbb".to_owned(), found(99999 * BS)),
        ];
        match select_sole_device(&survey).unwrap_err() {
            SelectError::Ambiguous { matches } => {
                assert_eq!(matches.len(), 2);
                assert!(matches.contains(&"aaa".to_owned()));
                assert!(matches.contains(&"bbb".to_owned()));
            }
            other => panic!("expected Ambiguous, got {other:?}"),
        }
    }

    #[test]
    fn ambiguity_is_reported_even_when_another_device_is_unreadable() {
        // Ordering matters: two positively-identified stores is an operator error
        // that must be named, and an unreadable third disk must not be allowed to
        // relabel it as merely inconclusive.
        let survey = vec![
            ("aaa".to_owned(), found(1)),
            ("bbb".to_owned(), found(2)),
            (
                "ccc".to_owned(),
                DeviceEvidence::Unreadable("io".to_owned()),
            ),
        ];
        assert!(matches!(
            select_sole_device(&survey).unwrap_err(),
            SelectError::Ambiguous { .. }
        ));
    }

    #[test]
    fn a_damaged_device_makes_none_found_inconclusive_rather_than_negative() {
        // The rule that keeps a damaged disk from being reported as a disk without
        // a guest image. If we could not read a disk, then "there is no guest
        // image" is not something this scan established.
        let survey = vec![
            (
                "aaa".to_owned(),
                DeviceEvidence::Absent(LocateError::NoSignature),
            ),
            (
                "bbb".to_owned(),
                DeviceEvidence::Damaged(LocateError::DamagedHeader),
            ),
        ];
        match select_sole_device(&survey).unwrap_err() {
            SelectError::Inconclusive { reasons } => {
                assert_eq!(reasons.len(), 1);
                assert_eq!(reasons[0].0, "bbb");
                assert_eq!(reasons[0].1, "damaged-header");
            }
            other => panic!("expected Inconclusive, got {other:?}"),
        }
    }

    #[test]
    fn an_unreadable_device_is_also_inconclusive() {
        let survey = vec![(
            "aaa".to_owned(),
            DeviceEvidence::Unreadable("ZX_ERR_IO".to_owned()),
        )];
        assert!(matches!(
            select_sole_device(&survey).unwrap_err(),
            SelectError::Inconclusive { .. }
        ));
    }

    #[test]
    fn a_single_match_wins_despite_an_unreadable_sibling() {
        // The deliberate asymmetry: inconclusive evidence can only undermine a
        // NEGATIVE conclusion. A positively-identified store stays identified.
        let survey = vec![
            ("aaa".to_owned(), found(6144 * BS)),
            (
                "bbb".to_owned(),
                DeviceEvidence::Unreadable("io".to_owned()),
            ),
        ];
        assert_eq!(select_sole_device(&survey).unwrap().instance, "aaa");
    }

    #[test]
    fn all_absent_is_the_only_genuinely_negative_answer() {
        let survey = vec![
            (
                "aaa".to_owned(),
                DeviceEvidence::Absent(LocateError::NoSignature),
            ),
            (
                "bbb".to_owned(),
                DeviceEvidence::Absent(LocateError::NotPresent),
            ),
        ];
        assert_eq!(
            select_sole_device(&survey).unwrap_err(),
            SelectError::NoneFound
        );
    }

    #[test]
    fn an_empty_survey_is_not_the_same_as_nothing_found() {
        // "No disks were published yet" is a retry condition; "no disk has one" is
        // a verdict. Conflating them would make a component that started before
        // the block driver bound conclude there is no guest image.
        assert_eq!(
            select_sole_device(&[]).unwrap_err(),
            SelectError::NoInstances
        );
    }

    // ── The store-length rule that used to be exact equality ──

    #[test]
    fn a_store_smaller_than_its_partition_is_accepted() {
        // THE regression this function exists for. The BOOTFS path asserts
        // `header.total_len() == store_len`, which is right there and would reject
        // every correctly-sized partition here, because a partition is sized by
        // whoever partitioned the disk and not by the pack later written into it.
        assert_eq!(
            store_len_within_partition(36_864, 8 * 1024 * 1024),
            Ok(36_864)
        );
        // Equality is still fine — a partition sized exactly to its store.
        assert_eq!(store_len_within_partition(4096, 4096), Ok(4096));
    }

    #[test]
    fn a_store_larger_than_its_partition_is_refused() {
        let err = store_len_within_partition(8 * 1024 * 1024, 36_864).unwrap_err();
        assert!(err.contains("does not fit"), "{err}");
    }

    #[test]
    fn a_zero_length_store_is_refused() {
        assert!(store_len_within_partition(0, 4096).is_err());
    }

    #[test]
    fn the_accepted_length_is_the_headers_and_never_the_partitions() {
        // Returning the partition length would let reads run off the end of the
        // pack into whatever the partition's tail happens to hold — which, on a
        // freshly partitioned disk, is zeros that would decode as valid-looking
        // empty pages.
        assert_eq!(
            store_len_within_partition(36_864, 64 * 1024 * 1024),
            Ok(36_864)
        );
    }
}

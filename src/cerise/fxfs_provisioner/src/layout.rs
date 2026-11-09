//! The bootable whole-disk layout the provisioner writes when it claims a disk.
//!
//! POLICY CONTEXT (maintainer decision 2026-07-22, refined 2026-07-25): Cerise
//! claims the WHOLE device when the device is not already ours. What changed is
//! the *shape* of the claim: instead of formatting the raw block device as Fxfs
//! — which leaves no room for an ESP and therefore no way for the machine to
//! boot from the disk it just provisioned — the claim now lays down a GPT with
//! an EFI System Partition and an Fxfs partition.
//!
//! This module CREATES a layout on a disk we own by policy. It does NOT
//! negotiate with an existing one: there is deliberately no free-space search,
//! no foreign-partition detection and no emptiness heuristic here (a general
//! partition-aware provisioner was considered and cancelled as too much
//! machinery). The one piece of *reading* that survives is
//! [`find_fxfs_partition`], which exists solely for IDEMPOTENCE — recognising a
//! layout this very code wrote, so a reboot reuses it instead of re-writing it.
//!
//! Like `ownership.rs` this module is pure: no zx, no FIDL, no async, no I/O.
//! It turns numbers into bytes; `main.rs` puts the bytes on the disk. That is
//! what makes the table construction host-unit-testable, and the tests validate
//! the produced image with `sgdisk`/`parted` rather than only with our own
//! parser (a table only we agree with is not a GPT).

use core::fmt;
use core::ops::Range;

// ---------------------------------------------------------------------------
// Type GUIDs — mirrored from the tree's own definitions
// ---------------------------------------------------------------------------

/// EFI System Partition type GUID, C12A7328-F81F-11D2-BA4B-00A0C93EC93B, in the
/// on-disk mixed-endian encoding.
///
/// Byte-for-byte `GUID_EFI_VALUE` from
/// `zircon/system/public/zircon/hw/gpt.h:203-208`. `GUID_EFI_VALUE` is the
/// tree's canonical constant for this GUID.
pub const ESP_TYPE_GUID: [u8; 16] = [
    0x28, 0x73, 0x2a, 0xc1, 0x1f, 0xf8, 0xd2, 0x11, 0xba, 0x4b, 0x00, 0xa0, 0xc9, 0x3e, 0xc9, 0x3b,
];

/// The partition type GUID Cerise's Fxfs container lives under,
/// 49FD7CB8-DF15-4E73-B9D9-992070127F0F, in the on-disk mixed-endian encoding.
///
/// This is `GPT_FVM_TYPE_GUID` (`zircon/system/public/zircon/hw/gpt.h:144`,
/// spelled there through the `GPT_GUID(...)` mixed-endian macro). Upstream
/// kept the historical "fvm" spelling for the type that now carries the Fxfs
/// container; `fs_management`'s partition matching keys off this same value
/// (`src/upstream/fuchsia/src/storage/lib/fs_management/rust/src/lib.rs`,
/// `.../format/constants.rs`). Expanding `GPT_GUID(0x49fd7cb8, 0xdf15,
/// 0x4e73, 0xb9d9, 0x992070127f0f)` gives exactly the bytes below; the
/// `guid_bytes_match_gpt_h` test re-derives them from the macro's rules so a
/// transcription slip cannot pass.
pub const FXFS_TYPE_GUID: [u8; 16] = [
    0xb8, 0x7c, 0xfd, 0x49, 0x15, 0xdf, 0x73, 0x4e, 0xb9, 0xd9, 0x99, 0x20, 0x70, 0x12, 0x7f, 0x0f,
];

/// The partition type GUID a guest-image store lives under,
/// 43A1F4C2-7B5E-4D18-9E3A-6F0C21D8B7A5, in the on-disk mixed-endian encoding.
///
/// **A NEW GUID, minted here, and deliberately not any existing one.** The other
/// two type GUIDs in this file are mirrors of upstream constants, because
/// something else in the system keys off them: `fs_management`'s partition
/// matching looks for [`FXFS_TYPE_GUID`], and firmware looks for
/// [`ESP_TYPE_GUID`]. Nothing outside this tree has any opinion about a
/// content-addressed guest-image pack, so reusing a borrowed type here would buy
/// nothing and cost the one thing a type GUID is for: telling two kinds of
/// content apart.
///
/// Why that matters concretely. [`FXFS_TYPE_GUID`] *is* upstream's
/// `GPT_FVM_TYPE_GUID`, and the consequence is already guarded at runtime —
/// `ownership.rs` has to refuse a partition of "our" type whose contents turn out
/// to be an upstream FVM container, with a named test for it. That guard exists
/// because a shared type GUID makes "is this mine?" a content question instead of
/// a table question. A distinct GUID for guest images keeps the answer in the
/// table, where it is cheap and unambiguous.
///
/// Encoding, since it is easy to get wrong: GPT stores the first three fields
/// little-endian and the last two as written, so
/// `GPT_GUID(0x43a1f4c2, 0x7b5e, 0x4d18, 0x9e3a, 0x6f0c21d8b7a5)` expands to the
/// bytes below. `guest_image_guid_round_trips` re-derives them from the macro's
/// rules rather than trusting this transcription.
pub const GUEST_IMAGE_TYPE_GUID: [u8; 16] = [
    0xc2, 0xf4, 0xa1, 0x43, 0x5e, 0x7b, 0x18, 0x4d, 0x9e, 0x3a, 0x6f, 0x0c, 0x21, 0xd8, 0xb7, 0xa5,
];

/// The partition type GUID used as untrusted scratch space while receiving a
/// guest store, 7A5E4C11-2D8B-4F90-A6C3-91E72B5D4038.
///
/// This is deliberately distinct from [`GUEST_IMAGE_TYPE_GUID`]. A receiver
/// may write incomplete or rejected bytes here, but it must not write the
/// active guest-image partition until the signed payload has passed admission.
pub const GUEST_STORE_STAGING_TYPE_GUID: [u8; 16] = [
    0x11, 0x4c, 0x5e, 0x7a, 0x8b, 0x2d, 0x90, 0x4f, 0xa6, 0xc3, 0x91, 0xe7, 0x2b, 0x5d, 0x40, 0x38,
];

/// Partition label written on a guest-image partition. Documentation for whoever
/// opens a partition editor; the TYPE GUID is what policy keys off.
pub const GUEST_IMAGE_LABEL: &str = "cerise-guest";

/// Partition label for the receiver's inactive staging area.
pub const GUEST_STORE_STAGING_LABEL: &str = "cerise-guest-stage";

/// Partition label written on the ESP: `GUID_EFI_NAME`, gpt.h:209.
pub const ESP_LABEL: &str = "fuchsia-esp";

/// Partition label written on the Fxfs partition. The label is documentation
/// for whoever next opens a partition editor; the TYPE GUID is what policy
/// actually keys off.
pub const FXFS_LABEL: &str = "cerise";

// ---------------------------------------------------------------------------
// Sizing
// ---------------------------------------------------------------------------

/// Partition start alignment. 1 MiB is the conventional choice and matches the
/// CF-SZ5's existing table (partition 1 at sector 2048 on a 512-byte-sector
/// disk); it also keeps every partition aligned to any plausible SSD erase
/// block and to 4 Kn physical sectors.
pub const ALIGNMENT_BYTES: u64 = 1 << 20;

/// ESP size: 2 GiB.
///
/// SIZED DELIBERATELY, because the previous ESP images in this tree were not:
/// the firstlight ESPs were built with essentially no headroom and overflowed
/// at roughly 1% of ZBI growth, failing at FAT32 assembly with a raw cluster
/// count. The arithmetic here:
///
///   * The A/B OTA layout keeps BOTH slots as files in the ESP —
///     `\zircon_a.zbi` and `\zircon_b.zbi` — plus `\abr` and the
///     `\EFI\BOOT\BOOTX64.EFI` shim. So the ESP must hold 2x a whole ZBI, not
///     1x, and must hold them SIMULTANEOUSLY during an update (the new slot is
///     written before the old one is released).
///   * The ZBIs that actually boot on metal through UEFI today are ~64 MB
///     (the firstlight / CF-SZ5 images). Two slots = ~128 MB. 2 GiB is ~16x
///     that: the ZBI can grow by an order of magnitude before the ESP is the
///     thing that breaks.
///   * The tree's largest ZBIs are much bigger (~1.65 GB for
///     qemu-x64-console), but those cannot be UEFI
///     booted at all — the shim loads the whole ZBI into memory and the
///     operative limit is RAM, not the ESP. Sizing the ESP for two 1.65 GB
///     slots (3.3 GiB+) would be sizing for an image that cannot boot. 2 GiB
///     single-slots even that image, and comfortably double-slots anything in
///     the metal-bootable class.
///   * Cost: 2 GiB of a 128 GB+ laptop SSD is ~1.5%. Cheap insurance against
///     the exact failure this tree already hit once.
///   * FAT32 sanity at this size: 2 GiB with 4 KiB clusters is 524,288
///     clusters — well above FAT32's 65,525-cluster minimum and far below its
///     maximum, and every individual file stays under the 4 GiB FAT32 file
///     size limit.
pub const ESP_BYTES: u64 = 2 << 30;

/// Smallest Fxfs partition worth creating. Below this the disk is not a system
/// disk and we would rather say so loudly than lay down something useless.
pub const MIN_FXFS_BYTES: u64 = 1 << 30;

/// GPT entry array geometry: the near-universal 128 entries x 128 bytes
/// (16 KiB), which is what `GPT_ENTRY_SIZE` (gpt.h:15) describes per entry and
/// what every partition tool expects to find.
pub const ENTRY_COUNT: u32 = 128;
pub const ENTRY_SIZE: u32 = 128;

/// GPT header signature, "EFI PART" (`GPT_MAGIC`, gpt.h:13).
pub const GPT_SIGNATURE: [u8; 8] = *b"EFI PART";

/// GPT header revision 1.0 and header size (`GPT_HEADER_SIZE`, gpt.h:14).
const GPT_REVISION: u32 = 0x0001_0000;
const GPT_HEADER_SIZE: u32 = 92;

// ---------------------------------------------------------------------------
// Plan
// ---------------------------------------------------------------------------

/// One partition of the layout, in inclusive LBAs (GPT's own convention).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PartitionPlan {
    pub first_lba: u64,
    pub last_lba: u64,
    pub type_guid: [u8; 16],
    pub label: &'static str,
}

impl PartitionPlan {
    pub fn block_count(&self) -> u64 {
        self.last_lba - self.first_lba + 1
    }
    pub fn byte_range(&self, block_size: u64) -> Range<u64> {
        self.first_lba * block_size..(self.last_lba + 1) * block_size
    }
}

/// The complete layout for one disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LayoutPlan {
    pub block_size: u64,
    pub block_count: u64,
    pub first_usable_lba: u64,
    pub last_usable_lba: u64,
    pub entry_count: u32,
    pub entry_size: u32,
    pub esp: PartitionPlan,
    pub fxfs: PartitionPlan,
}

impl LayoutPlan {
    pub fn esp_bytes(&self) -> Range<u64> {
        self.esp.byte_range(self.block_size)
    }
    pub fn fxfs_bytes(&self) -> Range<u64> {
        self.fxfs.byte_range(self.block_size)
    }
    /// LBA of the backup GPT header: always the last block of the device.
    pub fn backup_header_lba(&self) -> u64 {
        self.block_count - 1
    }
    fn entry_array_blocks(&self) -> u64 {
        ((self.entry_count as u64) * (self.entry_size as u64)).div_ceil(self.block_size)
    }
    pub fn primary_entries_lba(&self) -> u64 {
        2
    }
    pub fn backup_entries_lba(&self) -> u64 {
        self.backup_header_lba() - self.entry_array_blocks()
    }
}

/// Why a disk could not be given the layout. Every variant carries the sizes
/// involved: if we refuse to provision a disk, the operator gets the numbers,
/// not a shrug.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LayoutError {
    /// Block size is zero, not a power of two, or larger than the alignment we
    /// align partitions to.
    BadBlockSize { block_size: u64 },
    /// The device reports no blocks at all.
    EmptyDevice,
    /// The disk cannot hold ESP + minimum Fxfs + the GPT structures.
    TooSmall {
        disk_bytes: u64,
        needed_bytes: u64,
        esp_bytes: u64,
        min_fxfs_bytes: u64,
        gpt_overhead_bytes: u64,
    },
}

impl fmt::Display for LayoutError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LayoutError::BadBlockSize { block_size } => write!(
                f,
                "device reports an unusable block size {block_size} \
                 (must be a power of two, >= 512, and <= {ALIGNMENT_BYTES} \
                 so partitions can be {}-aligned)",
                human(ALIGNMENT_BYTES)
            ),
            LayoutError::EmptyDevice => write!(f, "device reports zero blocks"),
            LayoutError::TooSmall {
                disk_bytes,
                needed_bytes,
                esp_bytes,
                min_fxfs_bytes,
                gpt_overhead_bytes,
            } => write!(
                f,
                "disk is too small for the Cerise bootable layout: disk is {} ({disk_bytes} bytes), \
                 layout needs at least {} ({needed_bytes} bytes) = {} ESP + {} minimum Fxfs \
                 + {} GPT structures and 1 MiB alignment. Refusing to write a partition table.",
                human(*disk_bytes),
                human(*needed_bytes),
                human(*esp_bytes),
                human(*min_fxfs_bytes),
                human(*gpt_overhead_bytes),
            ),
        }
    }
}

/// Compute the layout for a device of `block_count` blocks of `block_size`
/// bytes. Fails loudly, with sizes, rather than producing something subtly
/// broken.
pub fn plan_layout(block_size: u64, block_count: u64) -> Result<LayoutPlan, LayoutError> {
    if block_size < 512 || !block_size.is_power_of_two() || block_size > ALIGNMENT_BYTES {
        return Err(LayoutError::BadBlockSize { block_size });
    }
    if block_count == 0 {
        return Err(LayoutError::EmptyDevice);
    }

    let align_lbas = ALIGNMENT_BYTES / block_size;
    let entry_array_blocks = ((ENTRY_COUNT as u64) * (ENTRY_SIZE as u64)).div_ceil(block_size);

    // Primary: LBA0 protective MBR, LBA1 header, LBA2.. entry array. First
    // usable LBA is the first block after the entry array (34 on a 512-byte
    // -sector disk) — the same value sgdisk/parted write. Partitions are
    // aligned separately, below; putting the alignment into FirstUsableLBA
    // instead would be legal but makes sgdisk warn about an unusual gap.
    let first_usable_lba = 2 + entry_array_blocks;
    // Backup: entry array immediately below the final block, header in it.
    let backup_header_lba = block_count - 1;

    // Overhead, in bytes, that is not available to partitions at all: the
    // primary structures, the backup structures, and the alignment slack in
    // front of partition 1.
    let gpt_overhead_bytes =
        (first_usable_lba + entry_array_blocks + 1) * block_size + ALIGNMENT_BYTES;
    let disk_bytes = block_count * block_size;
    let needed_bytes = ESP_BYTES + MIN_FXFS_BYTES + gpt_overhead_bytes;

    if backup_header_lba < entry_array_blocks + 1 || disk_bytes < needed_bytes {
        return Err(LayoutError::TooSmall {
            disk_bytes,
            needed_bytes,
            esp_bytes: ESP_BYTES,
            min_fxfs_bytes: MIN_FXFS_BYTES,
            gpt_overhead_bytes,
        });
    }

    let last_usable_lba = backup_header_lba - entry_array_blocks - 1;

    // ESP: first aligned LBA at or after the first usable one (2048 on a
    // 512-byte-sector disk, exactly like the CF-SZ5's existing table), exactly
    // ESP_BYTES long.
    let esp_first = first_usable_lba.div_ceil(align_lbas) * align_lbas;
    let esp_last = esp_first + ESP_BYTES / block_size - 1;

    // Fxfs: next aligned LBA after the ESP, running to the last usable LBA.
    // The end is aligned DOWN so the partition's length is a whole number of
    // alignment units too; the few leftover sectors before the backup GPT stay
    // unallocated, which is exactly what every partitioning tool does.
    let fxfs_first = (esp_last + 1).div_ceil(align_lbas) * align_lbas;
    let fxfs_last = ((last_usable_lba + 1) / align_lbas) * align_lbas - 1;

    // plan_layout's size gate above guarantees these, but an off-by-one here
    // would silently produce an overlapping or inverted table, so assert the
    // invariants instead of trusting the arithmetic.
    if fxfs_first > fxfs_last
        || fxfs_last > last_usable_lba
        || esp_first < first_usable_lba
        || esp_last >= fxfs_first
        || (fxfs_last - fxfs_first + 1) * block_size < MIN_FXFS_BYTES
    {
        return Err(LayoutError::TooSmall {
            disk_bytes,
            needed_bytes,
            esp_bytes: ESP_BYTES,
            min_fxfs_bytes: MIN_FXFS_BYTES,
            gpt_overhead_bytes,
        });
    }

    Ok(LayoutPlan {
        block_size,
        block_count,
        first_usable_lba,
        last_usable_lba,
        entry_count: ENTRY_COUNT,
        entry_size: ENTRY_SIZE,
        esp: PartitionPlan {
            first_lba: esp_first,
            last_lba: esp_last,
            type_guid: ESP_TYPE_GUID,
            label: ESP_LABEL,
        },
        fxfs: PartitionPlan {
            first_lba: fxfs_first,
            last_lba: fxfs_last,
            type_guid: FXFS_TYPE_GUID,
            label: FXFS_LABEL,
        },
    })
}

// ---------------------------------------------------------------------------
// Table construction
// ---------------------------------------------------------------------------

/// The bytes of a complete GPT, ready to be written at the given LBAs. Nothing
/// in here has touched a disk; `main.rs` does the I/O.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GptImage {
    /// One block: the protective MBR, written at LBA 0.
    pub protective_mbr: Vec<u8>,
    /// One block: the primary header, written at LBA 1.
    pub primary_header: Vec<u8>,
    /// The entry array, padded to a whole number of blocks. Written at both
    /// `primary_entries_lba` and `backup_entries_lba`.
    pub entries: Vec<u8>,
    /// One block: the backup header, written at `backup_header_lba`.
    pub backup_header: Vec<u8>,
    pub primary_entries_lba: u64,
    pub backup_entries_lba: u64,
    pub backup_header_lba: u64,
}

/// Build the on-disk GPT for `plan`.
///
/// The three GUIDs are supplied by the caller because this module has no
/// randomness (that is what keeps it pure and its tests deterministic);
/// `main.rs` draws them from the kernel CPRNG.
pub fn build_gpt(
    plan: &LayoutPlan,
    disk_guid: [u8; 16],
    esp_guid: [u8; 16],
    fxfs_guid: [u8; 16],
) -> GptImage {
    let bs = plan.block_size as usize;

    // --- entry array -------------------------------------------------------
    let entry_size = plan.entry_size as usize;
    let array_len = entry_size * plan.entry_count as usize;
    let padded_len = (array_len as u64).div_ceil(plan.block_size) as usize * bs;
    let mut entries = vec![0u8; padded_len];
    write_entry(&mut entries[0..entry_size], &plan.esp, esp_guid);
    write_entry(&mut entries[entry_size..2 * entry_size], &plan.fxfs, fxfs_guid);
    // The CRC covers exactly entry_count * entry_size bytes, not the block
    // padding (UEFI 2.10 table 5-5: SizeOfPartitionEntry * NumberOfPartitionEntries).
    let entries_crc = crc32(&entries[..array_len]);

    // --- headers -----------------------------------------------------------
    let primary_header = build_header(
        plan,
        disk_guid,
        entries_crc,
        1,
        plan.backup_header_lba(),
        plan.primary_entries_lba(),
    );
    let backup_header = build_header(
        plan,
        disk_guid,
        entries_crc,
        plan.backup_header_lba(),
        1,
        plan.backup_entries_lba(),
    );

    GptImage {
        protective_mbr: build_protective_mbr(plan),
        primary_header,
        entries,
        backup_header,
        primary_entries_lba: plan.primary_entries_lba(),
        backup_entries_lba: plan.backup_entries_lba(),
        backup_header_lba: plan.backup_header_lba(),
    }
}

fn write_entry(slot: &mut [u8], p: &PartitionPlan, unique_guid: [u8; 16]) {
    slot[0..16].copy_from_slice(&p.type_guid);
    slot[16..32].copy_from_slice(&unique_guid);
    slot[32..40].copy_from_slice(&p.first_lba.to_le_bytes());
    slot[40..48].copy_from_slice(&p.last_lba.to_le_bytes());
    slot[48..56].copy_from_slice(&0u64.to_le_bytes()); // attributes
    // Name: UTF-16LE, GPT_NAME_LEN (72) bytes = 36 units, NUL-padded.
    let name_bytes = slot.len() - 56;
    for (i, unit) in p.label.encode_utf16().take(name_bytes / 2 - 1).enumerate() {
        slot[56 + i * 2..58 + i * 2].copy_from_slice(&unit.to_le_bytes());
    }
}

fn build_header(
    plan: &LayoutPlan,
    disk_guid: [u8; 16],
    entries_crc: u32,
    my_lba: u64,
    alternate_lba: u64,
    entries_lba: u64,
) -> Vec<u8> {
    let mut h = vec![0u8; plan.block_size as usize];
    h[0..8].copy_from_slice(&GPT_SIGNATURE);
    h[8..12].copy_from_slice(&GPT_REVISION.to_le_bytes());
    h[12..16].copy_from_slice(&GPT_HEADER_SIZE.to_le_bytes());
    // h[16..20] header CRC — computed last, over the first header_size bytes
    // with this field zeroed.
    h[20..24].copy_from_slice(&0u32.to_le_bytes()); // reserved
    h[24..32].copy_from_slice(&my_lba.to_le_bytes());
    h[32..40].copy_from_slice(&alternate_lba.to_le_bytes());
    h[40..48].copy_from_slice(&plan.first_usable_lba.to_le_bytes());
    h[48..56].copy_from_slice(&plan.last_usable_lba.to_le_bytes());
    h[56..72].copy_from_slice(&disk_guid);
    h[72..80].copy_from_slice(&entries_lba.to_le_bytes());
    h[80..84].copy_from_slice(&plan.entry_count.to_le_bytes());
    h[84..88].copy_from_slice(&plan.entry_size.to_le_bytes());
    h[88..92].copy_from_slice(&entries_crc.to_le_bytes());
    let crc = crc32(&h[..GPT_HEADER_SIZE as usize]);
    h[16..20].copy_from_slice(&crc.to_le_bytes());
    h
}

/// A canonical protective MBR (UEFI 2.10 table 5-3): one partition entry of
/// type 0xEE covering the whole disk (clamped to 0xFFFFFFFF sectors), boot
/// signature 0xAA55, everything else zero. Its entire job is to stop legacy
/// tools from believing the disk is unpartitioned.
fn build_protective_mbr(plan: &LayoutPlan) -> Vec<u8> {
    let mut mbr = vec![0u8; plan.block_size as usize];
    let e = &mut mbr[446..462];
    e[0] = 0x00; // not bootable
    // CHS start 0x000200 (head 0, sector 2, cylinder 0) — the value the spec
    // prescribes for the protective entry.
    e[1] = 0x00;
    e[2] = 0x02;
    e[3] = 0x00;
    e[4] = 0xEE; // GPT protective
    // CHS end: the spec's "0xFFFFFF if the size is too large" case.
    e[5] = 0xFF;
    e[6] = 0xFF;
    e[7] = 0xFF;
    e[8..12].copy_from_slice(&1u32.to_le_bytes()); // starting LBA
    let size = u32::try_from(plan.block_count - 1).unwrap_or(0xFFFF_FFFF);
    e[12..16].copy_from_slice(&size.to_le_bytes());
    mbr[510] = 0x55;
    mbr[511] = 0xAA;
    mbr
}

// ---------------------------------------------------------------------------
// Recognition (idempotence only)
// ---------------------------------------------------------------------------

/// Find the Fxfs partition in a GPT we wrote. Returns its byte range.
///
/// THIS IS NOT A GPT PARSER in the sense that was cancelled: it does not search
/// for free space, does not look at foreign partitions, does not judge
/// emptiness, and does not validate the backup copy. It answers exactly one
/// question — "is this a table of ours, and where does our Fxfs live?" — which
/// is what idempotence requires now that our Fxfs superblocks are no longer at
/// device offset 0.
///
/// It is deliberately conservative: signature, self-consistent geometry, a
/// correct header CRC, and a correct entry-array CRC must all hold, or it
/// returns None. A garbled table is "not ours", and the caller's own ownership
/// probes then decide (they, not this function, are what stands between a
/// damaged disk and a reformat).
///
/// `lba1` is the block at LBA 1; `entries` is at least
/// `entry_count * entry_size` bytes read from the header's entry LBA.
pub fn find_fxfs_partition(lba1: &[u8], entries: &[u8], block_size: u64) -> Option<Range<u64>> {
    if block_size == 0 {
        return None;
    }
    validated_header(lba1)?;
    let (_, array_len) = entry_array_location(lba1)?;
    let entry_size = le_u32(lba1, 84) as usize;
    let entry_count = le_u32(lba1, 80) as usize;
    if entries.len() < array_len {
        return None;
    }
    if crc32(&entries[..array_len]) != le_u32(lba1, 88) {
        return None;
    }

    for i in 0..entry_count {
        let e = &entries[i * entry_size..(i + 1) * entry_size];
        if e[0..16] != FXFS_TYPE_GUID {
            continue;
        }
        let first = le_u64(e, 32);
        let last = le_u64(e, 40);
        if last < first {
            return None;
        }
        let start = first.checked_mul(block_size)?;
        let end = last.checked_add(1)?.checked_mul(block_size)?;
        return Some(start..end);
    }
    None
}

/// A GPT header that passes its own signature, size and CRC checks, or None.
/// Every field read out of a header must go through this first: the entry-array
/// location comes out of the header itself, so trusting it before the CRC
/// checks out means sizing a read from corrupt bytes.
pub fn validated_header(lba1: &[u8]) -> Option<&[u8]> {
    if lba1.len() < GPT_HEADER_SIZE as usize || lba1[0..8] != GPT_SIGNATURE {
        return None;
    }
    let header_size = le_u32(lba1, 12) as usize;
    if !(GPT_HEADER_SIZE as usize..=lba1.len()).contains(&header_size) {
        return None;
    }
    let stored_crc = le_u32(lba1, 16);
    let mut scratch = lba1[..header_size].to_vec();
    scratch[16..20].copy_from_slice(&[0, 0, 0, 0]);
    if crc32(&scratch) != stored_crc {
        return None;
    }
    Some(&lba1[..header_size])
}

/// `(entry array LBA, entry array length in bytes)` for a valid header, so the
/// caller knows exactly what to read. None when the header is not valid or its
/// entry geometry is absurd.
pub fn entry_array_location(lba1: &[u8]) -> Option<(u64, usize)> {
    validated_header(lba1)?;
    let entry_lba = le_u64(lba1, 72);
    let entry_count = le_u32(lba1, 80) as usize;
    let entry_size = le_u32(lba1, 84) as usize;
    // GPT requires entry_size to be a multiple of 128; refuse absurd counts
    // rather than sizing an allocation from a corrupt field.
    if entry_size < 128 || entry_size % 128 != 0 || entry_count == 0 || entry_count > 4096 {
        return None;
    }
    Some((entry_lba, entry_count.checked_mul(entry_size)?))
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

fn le_u32(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
}

fn le_u64(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().unwrap())
}

/// CRC-32/ISO-HDLC (the "IEEE" polynomial), which is what GPT specifies for
/// both the header and the entry array (UEFI 2.10 section 5.3).
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            crc = if crc & 1 != 0 { (crc >> 1) ^ 0xEDB8_8320 } else { crc >> 1 };
        }
    }
    !crc
}

/// Byte counts in error messages are for a human deciding what to do about
/// their disk, so they get human units.
pub fn human(bytes: u64) -> String {
    const UNITS: [(&str, u64); 4] =
        [("TiB", 1 << 40), ("GiB", 1 << 30), ("MiB", 1 << 20), ("KiB", 1 << 10)];
    for (name, scale) in UNITS {
        if bytes >= scale {
            return format!("{:.2} {name}", bytes as f64 / scale as f64);
        }
    }
    format!("{bytes} bytes")
}

#[cfg(test)]
mod tests {
    use super::*;

    const GIB: u64 = 1 << 30;

    /// Re-derive both type GUIDs from the rules gpt.h states, so a
    /// transcription slip in the byte arrays above cannot pass.
    /// gpt.h:54-72 `GPT_GUID(g0,g1,g2,g3,g4)`: g0 4 bytes little-endian,
    /// g1 2 bytes LE, g2 2 bytes LE, g3 2 bytes BIG-endian, g4 6 bytes BE.
    fn gpt_guid(g0: u32, g1: u16, g2: u16, g3: u16, g4: u64) -> [u8; 16] {
        let mut out = [0u8; 16];
        out[0..4].copy_from_slice(&g0.to_le_bytes());
        out[4..6].copy_from_slice(&g1.to_le_bytes());
        out[6..8].copy_from_slice(&g2.to_le_bytes());
        out[8..10].copy_from_slice(&g3.to_be_bytes());
        out[10..16].copy_from_slice(&g4.to_be_bytes()[2..8]);
        out
    }

    #[test]
    fn guid_bytes_match_gpt_h() {
        // GPT_FVM_TYPE_GUID, zircon/system/public/zircon/hw/gpt.h:144.
        assert_eq!(
            FXFS_TYPE_GUID,
            gpt_guid(0x49fd_7cb8, 0xdf15, 0x4e73, 0xb9d9, 0x9920_7012_7f0f)
        );
        // GUID_EFI_VALUE, gpt.h:203-208, spelled as literal bytes there; this
        // is the same GUID written the GPT_GUID way.
        assert_eq!(
            ESP_TYPE_GUID,
            gpt_guid(0xc12a_7328, 0xf81f, 0x11d2, 0xba4b, 0x00a0_c93e_c93b)
        );
    }

    /// The guest-image type GUID, re-derived from the GPT_GUID mixed-endian rules
    /// rather than trusting the transcription in the constant.
    #[test]
    fn guest_image_guid_round_trips() {
        assert_eq!(
            GUEST_IMAGE_TYPE_GUID,
            gpt_guid(0x43a1_f4c2, 0x7b5e, 0x4d18, 0x9e3a, 0x6f0c_21d8_b7a5)
        );
    }

    /// The three type GUIDs must be mutually distinct.
    ///
    /// Not a tautology about three literals: the whole reason the guest-image type
    /// is a NEW GUID rather than a borrowed one is that a shared type turns "is
    /// this partition mine?" from a table question into a content question — which
    /// is exactly the situation `ownership.rs` has to carry a runtime guard for,
    /// because `FXFS_TYPE_GUID` is upstream's FVM type. If someone later
    /// "simplifies" this by pointing the guest-image type at one of the others,
    /// that decision should break a test rather than quietly recreate the problem.
    #[test]
    fn the_three_type_guids_are_distinct() {
        assert_ne!(GUEST_IMAGE_TYPE_GUID, FXFS_TYPE_GUID);
        assert_ne!(GUEST_IMAGE_TYPE_GUID, ESP_TYPE_GUID);
        assert_ne!(GUEST_STORE_STAGING_TYPE_GUID, GUEST_IMAGE_TYPE_GUID);
        assert_ne!(GUEST_STORE_STAGING_TYPE_GUID, FXFS_TYPE_GUID);
        assert_ne!(GUEST_STORE_STAGING_TYPE_GUID, ESP_TYPE_GUID);
        assert_ne!(FXFS_TYPE_GUID, ESP_TYPE_GUID);
    }

    #[test]
    fn crc32_matches_the_standard_check_vector() {
        // The universally quoted CRC-32/ISO-HDLC check value.
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
        assert_eq!(crc32(b""), 0);
    }

    #[test]
    fn a_64gib_disk_gets_an_aligned_two_partition_layout() {
        let bs = 512;
        let plan = plan_layout(bs, 64 * GIB / bs).expect("64 GiB disk must be layout-able");
        // 1 MiB alignment: partition 1 at sector 2048, exactly like the
        // laptop's existing table.
        assert_eq!(plan.esp.first_lba, 2048);
        assert_eq!(plan.esp.byte_range(bs).end - plan.esp.byte_range(bs).start, ESP_BYTES);
        assert_eq!(plan.esp.first_lba * bs % ALIGNMENT_BYTES, 0);
        assert_eq!(plan.fxfs.first_lba * bs % ALIGNMENT_BYTES, 0);
        assert!(plan.fxfs.first_lba > plan.esp.last_lba, "partitions must not overlap");
        assert!(plan.fxfs.last_lba <= plan.last_usable_lba);
        assert_eq!(plan.esp.type_guid, ESP_TYPE_GUID);
        assert_eq!(plan.fxfs.type_guid, FXFS_TYPE_GUID);
        // The Fxfs partition gets essentially the whole rest of the disk.
        let fxfs_len = plan.fxfs.block_count() * bs;
        assert!(fxfs_len > 61 * GIB, "fxfs got only {}", human(fxfs_len));
    }

    #[test]
    fn a_4kn_disk_is_laid_out_too() {
        let bs = 4096;
        let plan = plan_layout(bs, 64 * GIB / bs).expect("4Kn disk must be layout-able");
        assert_eq!(plan.esp.first_lba, 256); // 1 MiB / 4096
        assert_eq!(plan.esp.byte_range(bs).end - plan.esp.byte_range(bs).start, ESP_BYTES);
        assert_eq!(plan.fxfs.first_lba * bs % ALIGNMENT_BYTES, 0);
    }

    #[test]
    fn a_disk_too_small_fails_loudly_with_the_sizes() {
        let bs = 512;
        let err = plan_layout(bs, 2 * GIB / bs).expect_err("2 GiB cannot hold 2 GiB ESP + 1 GiB");
        let msg = err.to_string();
        assert!(matches!(err, LayoutError::TooSmall { .. }), "{err:?}");
        assert!(msg.contains("2.00 GiB"), "message must carry the disk size: {msg}");
        assert!(msg.contains("too small"), "{msg}");
        assert!(msg.contains("Refusing to write a partition table"), "{msg}");
    }

    #[test]
    fn a_nonsense_block_size_is_refused() {
        assert!(matches!(plan_layout(0, 100), Err(LayoutError::BadBlockSize { .. })));
        assert!(matches!(plan_layout(511, 100), Err(LayoutError::BadBlockSize { .. })));
        assert!(matches!(plan_layout(1000, 100), Err(LayoutError::BadBlockSize { .. })));
        assert!(matches!(plan_layout(512, 0), Err(LayoutError::EmptyDevice)));
    }

    fn image_for(bs: u64, blocks: u64) -> (LayoutPlan, GptImage) {
        let plan = plan_layout(bs, blocks).unwrap();
        let img = build_gpt(&plan, [0x11; 16], [0x22; 16], [0x33; 16]);
        (plan, img)
    }

    #[test]
    fn the_header_is_a_valid_gpt_header() {
        let (plan, img) = image_for(512, 64 * GIB / 512);
        let h = &img.primary_header;
        assert_eq!(&h[0..8], b"EFI PART");
        assert_eq!(le_u32(h, 8), 0x0001_0000);
        assert_eq!(le_u32(h, 12), 92);
        assert_eq!(le_u64(h, 24), 1);
        assert_eq!(le_u64(h, 32), plan.backup_header_lba());
        assert_eq!(le_u64(h, 72), 2);
        assert_eq!(le_u32(h, 80), 128);
        assert_eq!(le_u32(h, 84), 128);
        // Header CRC verifies with the field zeroed.
        let mut scratch = h[..92].to_vec();
        let stored = le_u32(h, 16);
        scratch[16..20].copy_from_slice(&[0, 0, 0, 0]);
        assert_eq!(crc32(&scratch), stored);
        // Entry array CRC covers entry_count * entry_size, not the padding.
        assert_eq!(le_u32(h, 88), crc32(&img.entries[..128 * 128]));
    }

    #[test]
    fn the_backup_header_mirrors_the_primary() {
        let (plan, img) = image_for(512, 64 * GIB / 512);
        let b = &img.backup_header;
        assert_eq!(&b[0..8], b"EFI PART");
        assert_eq!(le_u64(b, 24), plan.backup_header_lba());
        assert_eq!(le_u64(b, 32), 1);
        assert_eq!(le_u64(b, 72), plan.backup_entries_lba());
        // Same usable range, same disk GUID, same entry CRC as the primary.
        assert_eq!(&b[40..56], &img.primary_header[40..56]);
        assert_eq!(&b[56..72], &img.primary_header[56..72]);
        assert_eq!(le_u32(b, 88), le_u32(&img.primary_header, 88));
        let mut scratch = b[..92].to_vec();
        let stored = le_u32(b, 16);
        scratch[16..20].copy_from_slice(&[0, 0, 0, 0]);
        assert_eq!(crc32(&scratch), stored);
    }

    #[test]
    fn the_protective_mbr_is_canonical() {
        let (_, img) = image_for(512, 64 * GIB / 512);
        let m = &img.protective_mbr;
        assert_eq!(m[510], 0x55);
        assert_eq!(m[511], 0xAA);
        assert_eq!(m[446 + 4], 0xEE, "partition type must be 0xEE (GPT protective)");
        assert_eq!(le_u32(m, 446 + 8), 1, "protective entry starts at LBA 1");
        assert_eq!(le_u32(m, 446 + 12), (64 * GIB / 512 - 1) as u32);
        // Only one MBR entry is used.
        assert_eq!(&m[462..510], &[0u8; 48]);
    }

    #[test]
    fn the_entries_carry_the_two_partitions_and_nothing_else() {
        let (plan, img) = image_for(512, 64 * GIB / 512);
        assert_eq!(&img.entries[0..16], &ESP_TYPE_GUID);
        assert_eq!(le_u64(&img.entries, 32), plan.esp.first_lba);
        assert_eq!(le_u64(&img.entries, 40), plan.esp.last_lba);
        assert_eq!(&img.entries[128..144], &FXFS_TYPE_GUID);
        assert_eq!(le_u64(&img.entries, 128 + 32), plan.fxfs.first_lba);
        assert_eq!(le_u64(&img.entries, 128 + 40), plan.fxfs.last_lba);
        // Labels, UTF-16LE.
        let esp_name: Vec<u16> = (0..11).map(|i| u16::from_le_bytes([img.entries[56 + i * 2], img.entries[57 + i * 2]])).collect();
        assert_eq!(String::from_utf16(&esp_name).unwrap(), "fuchsia-esp");
        // Every remaining slot is zero.
        assert_eq!(&img.entries[256..128 * 128], &vec![0u8; 128 * 126][..]);
    }

    /// The idempotence hinge: a table we just built must be recognised as ours.
    #[test]
    fn our_own_table_is_recognised() {
        let (plan, img) = image_for(512, 64 * GIB / 512);
        let found = find_fxfs_partition(&img.primary_header, &img.entries, 512)
            .expect("we must recognise the table we just wrote");
        assert_eq!(found, plan.fxfs_bytes());
    }

    #[test]
    fn a_foreign_or_damaged_table_is_not_recognised_as_ours() {
        let (_, img) = image_for(512, 64 * GIB / 512);
        // No signature.
        assert!(find_fxfs_partition(&vec![0u8; 512], &img.entries, 512).is_none());
        // Signature present, header CRC wrong.
        let mut bad = img.primary_header.clone();
        bad[40] ^= 0xFF;
        assert!(find_fxfs_partition(&bad, &img.entries, 512).is_none());
        // Header fine, entry array tampered with (CRC mismatch).
        let mut bad_entries = img.entries.clone();
        bad_entries[128 + 32] ^= 0xFF;
        assert!(find_fxfs_partition(&img.primary_header, &bad_entries, 512).is_none());
        // A valid GPT with no partition of our type is not ours.
        let mut other = img.entries.clone();
        other[128..144].copy_from_slice(&[0xAB; 16]);
        let plan = plan_layout(512, 64 * GIB / 512).unwrap();
        let reheaded = build_header(
            &plan,
            [0x11; 16],
            crc32(&other[..128 * 128]),
            1,
            plan.backup_header_lba(),
            2,
        );
        assert!(find_fxfs_partition(&reheaded, &other, 512).is_none());
    }

    #[test]
    fn recognition_works_from_the_backup_header_too() {
        let (plan, img) = image_for(512, 64 * GIB / 512);
        let found = find_fxfs_partition(&img.backup_header, &img.entries, 512).unwrap();
        assert_eq!(found, plan.fxfs_bytes());
    }

    #[test]
    fn structures_do_not_overlap_the_partitions() {
        for (bs, blocks) in [(512u64, 64 * GIB / 512), (4096, 64 * GIB / 4096), (512, 8 * GIB / 512)] {
            let (plan, img) = image_for(bs, blocks);
            let entry_blocks = (128u64 * 128).div_ceil(bs);
            assert!(plan.first_usable_lba >= 2 + entry_blocks, "bs={bs}");
            assert!(plan.esp.first_lba >= plan.first_usable_lba, "bs={bs}");
            assert!(
                img.backup_entries_lba > plan.last_usable_lba,
                "backup entry array must sit above last usable, bs={bs}"
            );
            assert_eq!(img.backup_header_lba, blocks - 1, "bs={bs}");
            assert!(plan.fxfs.last_lba < img.backup_entries_lba, "bs={bs}");
        }
    }
}

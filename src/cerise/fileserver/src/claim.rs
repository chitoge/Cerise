//! Whether the file server may claim the storage region it was handed.
//!
//! WHY THIS EXISTS. `fs.rs`'s mount used to be "format-if-needed": try to open
//! an Fxfs container at device offset 0 and, if that failed FOR ANY REASON,
//! call `FxFilesystem::new_empty` on the raw device. The file server bypasses
//! fshost and historically took the FIRST published
//! `fuchsia.hardware.block.volume.Service` instance as a whole raw disk, so on
//! a machine that boots
//! from that disk the policy overwrote LBA 0..2047: the protective MBR, the
//! primary GPT header and the entry array. Measured on the CF-SZ5 laptop as
//! happening ONCE PER BOOT (three rescue boots, each finding a fresh
//! `FxfsSupr7` superblock with a different UUID after exactly one Cerise boot),
//! with the ESP's file content intact behind a partition table that no longer
//! described it. The console realm starts the file server eager and routes it
//! the block service, so every console product ate the disk it booted from.
//!
//! THE RULE. Formatting is authorised only by a POSITIVE determination that the
//! device is blank. Three things follow, and they are the whole module:
//!
//!   1. A device carrying a foreign layout is never formatted. "Foreign" is
//!      led by a valid GPT — and BOTH copies are consulted, because GPT keeps a
//!      full second copy at the last block precisely so that a damaged primary
//!      is answerable. Reading only the primary would let a disk whose primary
//!      header we ourselves destroyed read as "blank" and be eaten again, which
//!      is exactly the observed once-per-boot loop. Named non-Fxfs signatures
//!      (FVM, an MBR/boot-sector signature, ext2/3/4) refuse too.
//!
//!   2. THE NAMED SIGNATURES ARE NOT THE SAFETY PROPERTY — they are the
//!      diagnostics, so the refusal log can say what is on the disk. The safety
//!      property is that [`FRONT_SCAN_BYTES`] at the front and
//!      [`TAIL_SCAN_BYTES`] at the end must be ENTIRELY ZERO. A signature list
//!      is a list of the things we thought of; a region scan also catches the
//!      ones we did not (an mdraid superblock at 4096, a ZFS label whose first
//!      8 KiB is blank by design, a btrfs superblock at 65536). See
//!      [`Claim::Blank`] for the exact strength of the resulting claim, which is
//!      NOT "the whole device is zero".
//!
//!   3. "Unformatted" and "unreadable" are different answers. A read that FAILS
//!      is a hole in the evidence, not a licence to reformat; it is treated as
//!      "this could have been the byte that said the disk was occupied". Only
//!      probes that were actually READ can produce [`Claim::Blank`].
//!
//! ORDER MATTERS, AND NOT ONLY FOR THE FORMAT PATH — see [`decide`]. Every
//! definite foreign signal is consulted BEFORE the Fxfs check, which is the
//! opposite of what `fxfs_provisioner`'s `ownership.rs` does, because there the
//! fallback ("open it") is non-destructive and here opening is itself a write.
//! A disk in exactly the CF-SZ5's damaged state (an Fxfs superblock at LBA 0,
//! primary GPT gone, backup GPT intact) is therefore REFUSED, not opened, and
//! stops being rewritten.
//!
//! LINEAGE. This is `src/cerise/fxfs_provisioner/src/ownership.rs`'s reasoning
//! applied to the file server's different question, and the shared parts are
//! shared rather than copied: GPT header validation comes from that component's
//! `boot_layout` library, so "what counts as a valid GPT" cannot drift between
//! the component that writes tables and the component that must not destroy
//! them. What is NOT shared is the decision itself: the provisioner decides
//! whether to lay out a disk, this decides whether a whole-device container may
//! be created, and the outcome spaces do not correspond.
//!
//! Deliberately pure (no zx / FIDL / async / IO) so the policy is host
//! unit-testable; `fs.rs` supplies the raw block reads.

use core::fmt;

/// First 8 bytes of every Fxfs superblock: b"FxfsSupr" (fxfs super_block.rs
/// `SUPER_BLOCK_MAGIC`). Mirrored as policy data — the claim decision must be
/// answerable from raw bytes even when the Fxfs stack refuses the volume.
pub const FXFS_MAGIC: [u8; 8] = *b"FxfsSupr";

/// Byte offset of Fxfs superblock copy B (fxfs super_block.rs
/// `SuperBlockInstance::B.first_extent()`, both current and legacy layouts).
/// Copy A is at offset 0. Both offsets are relative to the start of the
/// container; `fs.rs` translates them through a bounded region when the
/// container is in a GPT partition.
pub const SUPER_BLOCK_B_OFFSET: u64 = 524_288;

/// First 8 bytes of a Fuchsia Volume Manager superblock (fs_management
/// `FVM_MAGIC`). An FVM at offset 0 is an upstream Fuchsia installation.
pub const FVM_MAGIC: [u8; 8] = *b"FVM PART";

/// Byte offset of the ext2/3/4 superblock. Its magic is a little-endian
/// `0xEF53` 56 bytes in (i.e. at device offset 1080).
pub const EXT_SUPER_BLOCK_OFFSET: u64 = 1024;

/// Offset of the ext magic within the ext superblock block.
const EXT_MAGIC_AT: usize = 56;
const EXT_MAGIC: [u8; 2] = [0x53, 0xEF];

/// Offset of the boot-sector signature within LBA 0, and its value. Present on
/// an MBR partition table, on a GPT's protective MBR, and on a FAT/NTFS volume
/// boot record — all of them layouts we must not overwrite.
const BOOT_SIGNATURE_AT: usize = 510;
const BOOT_SIGNATURE: [u8; 2] = [0x55, 0xAA];

/// How much of the FRONT of the device must be zero before it counts as blank.
///
/// WHY A REGION AND NOT JUST THE POINT PROBES. The named signatures above are
/// for DIAGNOSTICS — so the log can say "ext4" instead of "something". They are
/// not the safety property, because a signature table is a list of the things we
/// happened to think of, and a container whose only marker sits at an offset we
/// never look at would read as all-zero and be formatted. Concretely, at 512-byte
/// blocks, the five point probes (0, 512, 1024, 524288, last LBA) miss: an mdraid
/// 1.2 superblock at 4096, a ZFS vdev label (whose first 8 KiB is deliberately
/// BLANK, with the boot header at 8192), a btrfs superblock at 65536, and a swap
/// signature at 4086. One megabyte at the front covers every one of them, plus
/// every partition table and volume boot record in ordinary use, and it is the
/// same 1 MiB alignment gap that partitioning tools leave empty on a disk that
/// really is fresh.
pub const FRONT_SCAN_BYTES: u64 = 1 << 20;

/// How much of the END of the device must be zero. Covers the backup GPT (header
/// plus its entry array), mdraid 0.90/1.0 superblocks, and ZFS labels L2/L3 —
/// all of which live at the end precisely so that the front of the disk can be
/// overwritten without losing them.
pub const TAIL_SCAN_BYTES: u64 = 1 << 20;

/// Largest whole device the file server may automatically turn into a scratch
/// filesystem.
///
/// Content probing answers "does this look blank?", not "does this device
/// belong to me?". In particular, a just-published physical disk can
/// transiently return zero-filled reads before its real partition table is
/// visible. Small VM test disks are intentionally disposable and stay below
/// this ceiling. A larger device requires an explicit provisioning/ownership
/// path; it is never formatted merely because one survey looked empty.
pub const MAX_AUTOMATIC_FORMAT_BYTES: u64 = 4 << 30;

/// The capacity fuse on the one destructive claim outcome.
pub fn automatic_format_allowed(device_bytes: u64) -> bool {
    device_bytes <= MAX_AUTOMATIC_FORMAT_BYTES
}

/// The result of one raw probe read. The three states are NOT interchangeable:
/// `Absent` is a fact about a small device, `Unreadable` is a hole in our
/// evidence, and only the first may ever contribute to a destructive decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Probe<'a> {
    /// The bytes at that location.
    Read(&'a [u8]),
    /// The location does not exist on this device (e.g. superblock B on a
    /// device smaller than 524288 bytes). Nothing is there to find.
    Absent,
    /// The read failed. We do not know what is there.
    Unreadable,
}

impl Probe<'_> {
    fn is_unreadable(&self) -> bool {
        matches!(self, Probe::Unreadable)
    }
    fn starts_with(&self, magic: &[u8]) -> bool {
        matches!(self, Probe::Read(b) if b.len() >= magic.len() && &b[..magic.len()] == magic)
    }
    fn has_at(&self, at: usize, want: &[u8]) -> bool {
        matches!(self, Probe::Read(b) if b.len() >= at + want.len() && &b[at..at + want.len()] == want)
    }
    /// True when the probe was read and every byte of it is zero. `Absent` is
    /// NOT blank-by-default: nothing was read, so it contributes nothing here
    /// (and it contributes nothing to occupancy either — see [`decide`]).
    fn is_all_zero(&self) -> bool {
        matches!(self, Probe::Read(b) if b.iter().all(|&x| x == 0))
    }
    /// True when the probe was read and carries at least one non-zero byte.
    fn has_content(&self) -> bool {
        matches!(self, Probe::Read(b) if b.iter().any(|&x| x != 0))
    }
}

/// What one copy of the partition table says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GptCopy {
    /// A GPT header that passes its own signature/size/CRC checks.
    Valid,
    /// Read cleanly, and there is no GPT header here.
    Absent,
    /// The GPT signature is present but the header does not validate — a bad
    /// CRC, an absurd header size. Something IS there and we cannot read it.
    Damaged,
    /// The read failed.
    Unreadable,
}

/// Classifies one block that should hold a GPT header.
///
/// The validation is `boot_layout::validated_header`, the same function
/// `fxfs_provisioner` uses to recognise tables — shared on purpose, so the
/// component that writes partition tables and the component that must not
/// destroy them cannot disagree about what a valid one is.
pub fn classify_gpt_copy(p: Probe<'_>) -> GptCopy {
    match p {
        Probe::Unreadable => GptCopy::Unreadable,
        // A device too small to hold this copy is a fact, not a hole: there is
        // no table there because there is no there there.
        Probe::Absent => GptCopy::Absent,
        Probe::Read(block) => {
            if boot_layout::validated_header(block).is_some() {
                GptCopy::Valid
            } else if block.len() >= 8 && block[0..8] == boot_layout::GPT_SIGNATURE {
                GptCopy::Damaged
            } else {
                GptCopy::Absent
            }
        }
    }
}

/// What the partition table as a whole says, having consulted both copies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TableEvidence {
    /// At least one copy is a valid GPT.
    Present,
    /// Both copies read cleanly and neither is a GPT.
    Absent,
    /// A GPT is present but valid in neither copy.
    Damaged,
    /// A read failed.
    Unreadable,
}

/// Combines the two table copies. A VALID copy anywhere wins — that is the
/// entire point of the backup, and consulting only the primary would let a disk
/// whose primary header we destroyed last boot read as blank this boot.
pub fn combine_table(primary: GptCopy, backup: GptCopy) -> TableEvidence {
    if primary == GptCopy::Valid || backup == GptCopy::Valid {
        return TableEvidence::Present;
    }
    match (primary, backup) {
        // A failed read leaves us unable to say there is no table.
        (GptCopy::Unreadable, _) | (_, GptCopy::Unreadable) => TableEvidence::Unreadable,
        (GptCopy::Damaged, _) | (_, GptCopy::Damaged) => TableEvidence::Damaged,
        _ => TableEvidence::Absent,
    }
}

/// Everything `fs.rs` read from one candidate container, in raw form. Offsets
/// are relative to that container; `fs.rs` maps them to whole-device offsets
/// before issuing I/O.
#[derive(Debug)]
pub struct Evidence<'a> {
    /// Block at offset 0: Fxfs superblock A, the FVM magic, and the boot-sector
    /// signature at byte 510 all live here.
    pub head: Probe<'a>,
    /// Block at LBA 1 — the primary GPT header.
    pub gpt_primary: Probe<'a>,
    /// Block at the last LBA — the backup GPT header.
    pub gpt_backup: Probe<'a>,
    /// Block at offset 1024 — the ext2/3/4 superblock.
    pub ext_super: Probe<'a>,
    /// Block at offset 524288 — Fxfs superblock copy B.
    pub super_b: Probe<'a>,
    /// The first [`FRONT_SCAN_BYTES`] of the device (or the whole device, if it
    /// is smaller). Not inspected for any signature — only for whether it is
    /// entirely zero. See [`FRONT_SCAN_BYTES`] for why this, and not the
    /// signature list, is the actual safety property.
    pub front: Probe<'a>,
    /// The last [`TAIL_SCAN_BYTES`] of the device, same rule.
    pub tail: Probe<'a>,
}

/// One device-absolute byte range to read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Span {
    pub offset: u64,
    pub len: u64,
}

/// WHERE to read, computed from the device geometry alone.
///
/// WHY THIS IS HERE AND NOT INLINE IN `fs.rs`. The constants above only protect
/// anything if the reads actually land on them, and a test that builds
/// [`Evidence`] by hand proves nothing about that: change
/// [`SUPER_BLOCK_B_OFFSET`] to the wrong value and every hand-built test still
/// passes while production probes empty space and calls a live filesystem blank.
/// (That was a real surviving mutant, found in review.) Putting the plan in the
/// pure module lets the tests assert the absolute byte offsets for both 512- and
/// 4096-byte geometries, and leaves `fs.rs` with nothing to get wrong but the
/// I/O.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProbePlan {
    pub head: Span,
    pub gpt_primary: Span,
    pub gpt_backup: Span,
    pub ext_super: Span,
    pub super_b: Span,
    pub front: Span,
    pub tail: Span,
}

/// The probe plan for a device of this geometry, or `None` if the geometry is
/// nonsense (which is a fault to report, never a small disk to reshape).
pub fn plan_probes(block_size: u64, block_count: u64) -> Option<ProbePlan> {
    if block_size == 0 || block_count == 0 {
        return None;
    }
    let device_size = block_count.checked_mul(block_size)?;
    let front_len = FRONT_SCAN_BYTES.min(device_size);
    let tail_len = TAIL_SCAN_BYTES.min(device_size);
    Some(ProbePlan {
        head: Span {
            offset: 0,
            len: block_size,
        },
        // LBA 1 and the last LBA: where UEFI 2.10 section 5.3 puts the primary
        // and backup headers, in units of the device's OWN logical block.
        gpt_primary: Span {
            offset: block_size,
            len: block_size,
        },
        gpt_backup: Span {
            offset: (block_count - 1) * block_size,
            len: block_size,
        },
        ext_super: Span {
            offset: EXT_SUPER_BLOCK_OFFSET,
            len: block_size,
        },
        super_b: Span {
            offset: SUPER_BLOCK_B_OFFSET,
            len: block_size,
        },
        front: Span {
            offset: 0,
            len: front_len,
        },
        tail: Span {
            offset: device_size - tail_len,
            len: tail_len,
        },
    })
}

/// What the file server may do with the device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Claim {
    /// There is an Fxfs container here already. Open it. If opening fails, that
    /// is an ERROR — never a reason to format.
    ///
    /// WHAT THIS DOES NOT PROVE, AND IT MATTERS: that the container is OURS.
    /// Eight bytes of superblock magic identify Fxfs, not its owner, and this
    /// component has no way to tell its own container from another component's
    /// without opening it — which writes. On a single-disk product that is fine
    /// (there is only one candidate and the file server is the only claimant).
    /// On a MULTI-DISK product it is not: `//products:qemu-x64-console-pkg`
    /// gives fshost a package store on disk1 and the file server disk2, both
    /// through the same aggregated `fuchsia.hardware.block.volume.Service`, and
    /// `fs.rs` picks the FIRST instance. If that first instance is fshost's, the
    /// file server will open a container fshost owns.
    ///
    /// That hazard is older than this module and is not made worse by it — the
    /// code this replaced would have FORMATTED that same disk, because opening
    /// it fails (fshost's container has no "default" volume) and failure used to
    /// mean format. Refusing to format is the part this module can fix from
    /// content alone; deciding WHICH disk belongs to whom cannot be done from
    /// content and needs per-consumer device routing. See the note on
    /// `//validation:pkg-apptier-boot` in validation/BUILD.bazel.
    OpenExisting,
    /// No evidence of any layout, anywhere we looked. This is the ONLY outcome
    /// that authorises `FxFilesystem::new_empty` on the raw device.
    ///
    /// BE PRECISE ABOUT THE STRENGTH OF THIS CLAIM. It is not "the device is
    /// all zeros" — proving that would mean reading every byte of a 250 GB disk
    /// on every boot. It is "the first [`FRONT_SCAN_BYTES`] and the last
    /// [`TAIL_SCAN_BYTES`] were read and are entirely zero, and no named
    /// signature matched". Every partition table, volume boot record and
    /// container superblock in ordinary use lives inside those two regions, by
    /// design — they are put there so that tools can find them. A layout that
    /// deliberately keeps its only metadata elsewhere (a hand-relocated GPT, a
    /// filesystem whose front has already been wiped but whose data survives)
    /// would still be missed. That residual is a sampling limit, not an
    /// oversight, and it is the reason the refusal side of this module is
    /// deliberately trigger-happy: everything ambiguous refuses.
    Blank,
}

/// Why the file server refuses to touch the device. Refusing is always safe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// A probe that could have shown the device is occupied could not be read.
    EvidenceUnavailable { what: &'static str },
    /// The device carries somebody else's layout.
    ForeignLayout { what: &'static str },
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Refusal::EvidenceUnavailable { what } => write!(
                f,
                "refusing to claim this block device: could not read {what}. \
                 A read failure is missing evidence, not proof the device is blank — \
                 formatting here could destroy a filesystem or a partition table that \
                 the failed read would have shown us."
            ),
            Refusal::ForeignLayout { what } => write!(
                f,
                "refusing to claim this block device: it carries {what}. \
                 The file server takes the WHOLE raw device, so formatting it would \
                 overwrite that layout — including the partition table of a disk this \
                 machine may boot from."
            ),
        }
    }
}

/// The whole claim decision, as a pure function of the evidence.
///
/// THE ORDER IS THE POLICY. Every DEFINITE sign of a foreign layout is consulted
/// before the "is this our own Fxfs?" question, and that is the opposite of what
/// `fxfs_provisioner`'s `ownership.rs` does. The reason is that for the
/// provisioner the fallback outcome ("open it") is non-destructive, whereas here
/// opening is itself a write: `FxFilesystem::open` replays the journal at device
/// offset 0 and would flatten LBA 1. So a device that says "I am partitioned" or
/// "I am an ext4" must be left alone ENTIRELY, even when an Fxfs superblock is
/// also sitting at offset 0 — which is precisely the state the old bug leaves a
/// disk in, and precisely the combination (`FxfsSupr` at 0 plus `55 AA` at 510)
/// that an Fxfs-magic-first ordering would have opened.
pub fn decide(e: &Evidence<'_>) -> Result<Claim, Refusal> {
    // 1. THE PARTITION TABLE, BOTH COPIES.
    match combine_table(
        classify_gpt_copy(e.gpt_primary),
        classify_gpt_copy(e.gpt_backup),
    ) {
        TableEvidence::Unreadable => {
            return Err(Refusal::EvidenceUnavailable {
                what: "the primary or backup GPT header",
            })
        }
        TableEvidence::Damaged => {
            return Err(Refusal::EvidenceUnavailable {
                what: "a partition table that is present but valid in neither copy",
            })
        }
        TableEvidence::Present => {
            return Err(Refusal::ForeignLayout {
                what: "a valid GPT partition table",
            })
        }
        TableEvidence::Absent => {}
    }

    // 2. The other named foreign signatures. Still ahead of the Fxfs check: each
    //    is a POSITIVE identification of a layout that is not ours, and a stray
    //    Fxfs magic must not be able to talk us past it. Naming them (rather
    //    than leaving them to the catch-all in step 5) is what lets the refusal
    //    log say WHAT is on the disk instead of only that something is.
    //
    //    FVM is unconditional: its magic is 8 bytes at offset 0, the same bytes
    //    the Fxfs magic would occupy, so the two cannot both be there.
    if e.head.starts_with(&FVM_MAGIC) {
        return Err(Refusal::ForeignLayout {
            what: "a Fuchsia Volume Manager container",
        });
    }

    //    THE WEAK SIGNATURES ARE CONDITIONAL, AND THIS IS NOT A LOOPHOLE.
    //    The boot signature (2 bytes at 510) and the ext magic (2 bytes at 1080)
    //    both live INSIDE the 4 KiB that Fxfs superblock A occupies. On a device
    //    that really is an Fxfs container those bytes are Fxfs's own serialized
    //    record stream, not an MBR and not an ext superblock — Fxfs writes the
    //    magic, then a serialized header, then records, straight through them
    //    (fxfs journal/super_block.rs). Nothing stops that stream from
    //    containing 0x55 0xAA at exactly byte 510; it is a two-byte coincidence,
    //    so it is a 1-in-65536 event per disk, not a never. Applying these
    //    checks to a block that starts with the Fxfs magic would therefore
    //    permanently lock a legitimate Cerise disk out of its own file server,
    //    with no way back short of an external rewrite. (Measured on two real
    //    Cerise stores from the QEMU gates: bytes 504..516 and 1072..1092 are
    //    zero today. "Today" is the point — as a store grows, the record stream
    //    reaches further, and there is no invariant that keeps it away.)
    //
    //    So the weak signatures are consulted only when the first block is NOT
    //    an Fxfs superblock — which is exactly when their bytes mean what they
    //    say. The dangerous case is preserved: an MBR at offset 0 with an Fxfs
    //    container starting later (so that superblock B, not A, is what our
    //    524288 probe sees) still has a non-Fxfs first block, so the MBR still
    //    refuses. The GPT checks above stay unconditional because "EFI PART"
    //    plus a matching CRC-32 is not something a record stream produces by
    //    accident.
    let head_is_fxfs_superblock = e.head.starts_with(&FXFS_MAGIC);
    if !head_is_fxfs_superblock {
        if e.head.has_at(BOOT_SIGNATURE_AT, &BOOT_SIGNATURE) {
            return Err(Refusal::ForeignLayout {
                what: "a boot-sector signature at byte 510 (an MBR partition table, \
                       or a FAT/NTFS volume boot record)",
            });
        }
        if e.ext_super.has_at(EXT_MAGIC_AT, &EXT_MAGIC) {
            return Err(Refusal::ForeignLayout {
                what: "an ext2/ext3/ext4 filesystem",
            });
        }
    }

    // 3. An Fxfs container. EITHER superblock copy is enough: a damaged copy A
    //    with an intact copy B is still a filesystem, and demoting it to "blank"
    //    is the corruption-eats-the-disk failure.
    //
    //    READ [`Claim::OpenExisting`] BEFORE TRUSTING THIS. Eight bytes of magic
    //    say "an Fxfs container is here"; they do not say it is OURS.
    if e.head.starts_with(&FXFS_MAGIC) || e.super_b.starts_with(&FXFS_MAGIC) {
        return Ok(Claim::OpenExisting);
    }

    // 4. Missing evidence never authorises a write. Every remaining probe could
    //    have been the one that said "occupied"; an unread one stops the
    //    decision dead rather than falling through to the format branch.
    if e.head.is_unreadable() {
        return Err(Refusal::EvidenceUnavailable {
            what: "the first block of the device",
        });
    }
    if e.super_b.is_unreadable() {
        return Err(Refusal::EvidenceUnavailable {
            what: "Fxfs superblock B",
        });
    }
    if e.ext_super.is_unreadable() {
        return Err(Refusal::EvidenceUnavailable {
            what: "the ext2/3/4 superblock location",
        });
    }
    if e.front.is_unreadable() {
        return Err(Refusal::EvidenceUnavailable {
            what: "the first megabyte of the device",
        });
    }
    if e.tail.is_unreadable() {
        return Err(Refusal::EvidenceUnavailable {
            what: "the last megabyte of the device",
        });
    }

    // 5. THE CATCH-ALL, AND THE ACTUAL SAFETY PROPERTY. Everything was read and
    //    nothing named it, so the only remaining question is whether the device
    //    is actually empty — and that question is asked of whole REGIONS, not of
    //    the handful of offsets the signature list happens to cover. A layout we
    //    cannot name is still somebody's layout, and this component's claim is
    //    the whole device, so "I do not recognise it" must not read as "I may
    //    have it". Only all-zero probes get through.
    if e.front.has_content()
        || e.tail.has_content()
        || e.head.has_content()
        || e.gpt_primary.has_content()
        || e.gpt_backup.has_content()
        || e.ext_super.has_content()
        || e.super_b.has_content()
    {
        return Err(Refusal::ForeignLayout {
            what: "data we do not recognise (no Fxfs, no partition table, but not empty either)",
        });
    }

    // 6. THE REGION SCANS MUST HAVE HAPPENED. Steps 4 and 5 reject an
    //    `Unreadable` region and a non-zero one, but on their own they would let
    //    an `Absent` region through — and `Absent` means "nothing was read
    //    here", which is not evidence of emptiness, it is the absence of
    //    evidence. `plan_probes` clamps both windows to the device, so in
    //    production they are never `Absent`; requiring it here is what stops a
    //    future caller (or a test fixture) from reaching the one destructive
    //    outcome without having done the scan at all.
    if !e.front.is_all_zero() {
        return Err(Refusal::EvidenceUnavailable {
            what: "the first megabyte of the device (it was never scanned)",
        });
    }
    if !e.tail.is_all_zero() {
        return Err(Refusal::EvidenceUnavailable {
            what: "the last megabyte of the device (it was never scanned)",
        });
    }
    Ok(Claim::Blank)
}

#[cfg(test)]
mod tests {
    use super::*;

    const BLOCK: usize = 512;

    fn zeros() -> Vec<u8> {
        vec![0u8; BLOCK]
    }

    fn block_with(prefix: &[u8]) -> Vec<u8> {
        let mut b = zeros();
        b[..prefix.len()].copy_from_slice(prefix);
        b
    }

    fn block_at(at: usize, bytes: &[u8]) -> Vec<u8> {
        let mut b = zeros();
        b[at..at + bytes.len()].copy_from_slice(bytes);
        b
    }

    fn garbage() -> Vec<u8> {
        // Deterministic non-magic noise (an overwritten superblock). Byte 510
        // must not accidentally be 0x55 — assert that below so the fixture
        // cannot silently start testing the boot-signature branch instead.
        (0..BLOCK).map(|i| (i * 7 + 13) as u8).collect()
    }

    /// A real, CRC-correct GPT header, built by the same library the
    /// provisioner writes tables with — so this test cannot pass against a
    /// table only we would agree with.
    fn real_gpt_primary_header() -> Vec<u8> {
        let plan = boot_layout::plan_layout(512, 64 << 21).expect("plan a 64 GiB-ish disk");
        boot_layout::build_gpt(&plan, [1u8; 16], [2u8; 16], [3u8; 16]).primary_header
    }

    fn real_gpt_backup_header() -> Vec<u8> {
        let plan = boot_layout::plan_layout(512, 64 << 21).expect("plan a 64 GiB-ish disk");
        boot_layout::build_gpt(&plan, [1u8; 16], [2u8; 16], [3u8; 16]).backup_header
    }

    /// A zeroed 1 MiB region scan, the shape `plan_probes` always produces.
    fn clean_region() -> Vec<u8> {
        vec![0u8; 1 << 20]
    }

    /// Evidence for a device with the given first block, clean region scans, and
    /// nothing else. The region scans must be REAL reads: `decide` refuses to
    /// call anything blank without them (they are the safety property), so a
    /// fixture that left them `Absent` could never reach `Claim::Blank` and
    /// every test below would pass for the wrong reason.
    fn dev<'a>(head: Probe<'a>, regions: &'a [u8]) -> Evidence<'a> {
        Evidence {
            head,
            gpt_primary: Probe::Absent,
            gpt_backup: Probe::Absent,
            ext_super: Probe::Absent,
            super_b: Probe::Absent,
            front: Probe::Read(regions),
            tail: Probe::Read(regions),
        }
    }

    // ---- the blank case, which the QEMU gates depend on --------------------

    /// The gates' disks are `truncate(256 MiB)` sparse files: every probe reads
    /// clean zeros. That, and only that, is claimable.
    #[test]
    fn a_genuinely_blank_device_is_claimable() {
        let z = zeros();
        let region = vec![0u8; 1 << 20];
        let e = Evidence {
            head: Probe::Read(&z),
            gpt_primary: Probe::Read(&z),
            gpt_backup: Probe::Read(&z),
            ext_super: Probe::Read(&z),
            super_b: Probe::Read(&z),
            front: Probe::Read(&region),
            tail: Probe::Read(&region),
        };
        assert_eq!(decide(&e), Ok(Claim::Blank));
    }

    /// A device too small to hold superblock B / the ext superblock is still
    /// claimable when what does exist is blank: `Absent` is a fact, not a hole.
    #[test]
    fn a_tiny_blank_device_is_claimable() {
        let z = zeros();
        let tiny = vec![0u8; 4096];
        let e = Evidence {
            head: Probe::Read(&z),
            gpt_primary: Probe::Read(&z),
            gpt_backup: Probe::Read(&z),
            ext_super: Probe::Absent,
            super_b: Probe::Absent,
            front: Probe::Read(&tiny),
            tail: Probe::Read(&tiny),
        };
        assert_eq!(decide(&e), Ok(Claim::Blank));
    }

    // ---- an existing Fxfs container is opened, never formatted -------------

    #[test]
    fn an_fxfs_superblock_a_means_open_not_format() {
        let r = clean_region();
        let a = block_with(b"FxfsSupr");
        assert_eq!(decide(&dev(Probe::Read(&a), &r)), Ok(Claim::OpenExisting));
    }

    /// THE CORRUPTION CASE: superblock A destroyed, superblock B intact. Still
    /// a filesystem. Demoting it to "blank" would reformat live data.
    #[test]
    fn a_damaged_superblock_a_with_an_intact_b_is_still_a_filesystem() {
        let r = clean_region();
        let g = garbage();
        let b = block_with(b"FxfsSupr");
        let e = Evidence {
            super_b: Probe::Read(&b),
            ..dev(Probe::Read(&g), &r)
        };
        assert_eq!(decide(&e), Ok(Claim::OpenExisting));
    }

    // ---- BOTH GPT COPIES ---------------------------------------------------

    /// A valid primary GPT refuses.
    #[test]
    fn a_valid_primary_gpt_refuses() {
        let r = clean_region();
        let z = zeros();
        let hdr = real_gpt_primary_header();
        let e = Evidence {
            gpt_primary: Probe::Read(&hdr),
            ..dev(Probe::Read(&z), &r)
        };
        assert_eq!(
            decide(&e),
            Err(Refusal::ForeignLayout {
                what: "a valid GPT partition table"
            })
        );
    }

    /// THE REGRESSION TEST FOR THE OBSERVED ONCE-PER-BOOT LOOP. The CF-SZ5
    /// after one Cerise boot: primary GPT header ZEROED, an Fxfs superblock
    /// sitting at LBA 0, backup GPT intact at the last LBA. A rule that read
    /// only the primary would call this "ours" (or worse, "blank") and eat it
    /// again. It must REFUSE — and refuse rather than open, because opening
    /// replays a journal over LBA 1.
    #[test]
    fn a_damaged_primary_with_an_intact_backup_is_not_blank_and_not_ours() {
        let z = zeros();
        let fxfs_at_lba0 = block_with(b"FxfsSupr");
        let backup = real_gpt_backup_header();
        let e = Evidence {
            head: Probe::Read(&fxfs_at_lba0),
            gpt_primary: Probe::Read(&z), // we zeroed it ourselves last boot
            gpt_backup: Probe::Read(&backup),
            ext_super: Probe::Read(&z),
            super_b: Probe::Read(&z),
            front: Probe::Absent,
            tail: Probe::Absent,
        };
        assert_eq!(
            decide(&e),
            Err(Refusal::ForeignLayout {
                what: "a valid GPT partition table"
            })
        );
    }

    /// A GPT signature whose header does not validate is a table that IS there
    /// and that we cannot interpret: missing evidence, not a clean "no table".
    #[test]
    fn a_gpt_signature_with_a_bad_crc_refuses_as_missing_evidence() {
        let r = clean_region();
        let z = zeros();
        let mut hdr = real_gpt_primary_header();
        hdr[20] ^= 0xFF; // corrupt a CRC-covered byte, keep the signature
        let e = Evidence {
            gpt_primary: Probe::Read(&hdr),
            ..dev(Probe::Read(&z), &r)
        };
        assert_eq!(
            decide(&e),
            Err(Refusal::EvidenceUnavailable {
                what: "a partition table that is present but valid in neither copy"
            })
        );
    }

    /// An unreadable table copy refuses: we cannot say there is no table.
    #[test]
    fn an_unreadable_gpt_copy_refuses() {
        let r = clean_region();
        let z = zeros();
        let e = Evidence {
            gpt_backup: Probe::Unreadable,
            ..dev(Probe::Read(&z), &r)
        };
        assert_eq!(
            decide(&e),
            Err(Refusal::EvidenceUnavailable {
                what: "the primary or backup GPT header"
            })
        );
        assert!(decide(&e)
            .unwrap_err()
            .to_string()
            .contains("not proof the device is blank"));
    }

    /// ...but a valid table anywhere still wins over an unreadable other copy:
    /// positive evidence of occupancy is never downgraded.
    #[test]
    fn a_valid_backup_beats_an_unreadable_primary() {
        let r = clean_region();
        let z = zeros();
        let backup = real_gpt_backup_header();
        let e = Evidence {
            gpt_primary: Probe::Unreadable,
            gpt_backup: Probe::Read(&backup),
            ..dev(Probe::Read(&z), &r)
        };
        assert_eq!(
            decide(&e),
            Err(Refusal::ForeignLayout {
                what: "a valid GPT partition table"
            })
        );
    }

    // ---- unreadable probes never authorise a format ------------------------

    #[test]
    fn an_unreadable_first_block_refuses() {
        let r = clean_region();
        let z = zeros();
        let e = Evidence {
            gpt_primary: Probe::Read(&z),
            ..dev(Probe::Unreadable, &r)
        };
        assert_eq!(
            decide(&e),
            Err(Refusal::EvidenceUnavailable {
                what: "the first block of the device"
            })
        );
    }

    #[test]
    fn an_unreadable_superblock_b_refuses() {
        let r = clean_region();
        let z = zeros();
        let e = Evidence {
            super_b: Probe::Unreadable,
            ..dev(Probe::Read(&z), &r)
        };
        assert_eq!(
            decide(&e),
            Err(Refusal::EvidenceUnavailable {
                what: "Fxfs superblock B"
            })
        );
    }

    #[test]
    fn an_unreadable_ext_superblock_refuses() {
        let r = clean_region();
        let z = zeros();
        let e = Evidence {
            ext_super: Probe::Unreadable,
            ..dev(Probe::Read(&z), &r)
        };
        assert_eq!(
            decide(&e),
            Err(Refusal::EvidenceUnavailable {
                what: "the ext2/3/4 superblock location"
            })
        );
    }

    /// An unreadable probe must not FABRICATE occupancy either: a device whose
    /// Fxfs superblock we can see is opened, not refused, even if another probe
    /// failed.
    #[test]
    fn positive_fxfs_evidence_beats_an_unreadable_probe() {
        let r = clean_region();
        let a = block_with(b"FxfsSupr");
        let e = Evidence {
            ext_super: Probe::Unreadable,
            ..dev(Probe::Read(&a), &r)
        };
        assert_eq!(decide(&e), Ok(Claim::OpenExisting));
    }

    // ---- named foreign signatures -----------------------------------------

    #[test]
    fn an_fvm_container_refuses() {
        let r = clean_region();
        let fvm = block_with(b"FVM PART");
        assert_eq!(
            decide(&dev(Probe::Read(&fvm), &r)),
            Err(Refusal::ForeignLayout {
                what: "a Fuchsia Volume Manager container"
            })
        );
    }

    /// An MBR-partitioned disk, or a FAT/NTFS volume, or a GPT's protective MBR
    /// on a disk whose headers we could not read as valid: byte 510 says stop.
    #[test]
    fn a_boot_sector_signature_refuses() {
        let r = clean_region();
        let mbr = block_at(BOOT_SIGNATURE_AT, &BOOT_SIGNATURE);
        let got = decide(&dev(Probe::Read(&mbr), &r));
        assert!(
            matches!(got, Err(Refusal::ForeignLayout { what }) if what.contains("byte 510")),
            "{got:?}"
        );
    }

    #[test]
    fn an_ext4_filesystem_refuses() {
        let r = clean_region();
        let z = zeros();
        let ext = block_at(EXT_MAGIC_AT, &EXT_MAGIC);
        let e = Evidence {
            ext_super: Probe::Read(&ext),
            ..dev(Probe::Read(&z), &r)
        };
        assert_eq!(
            decide(&e),
            Err(Refusal::ForeignLayout {
                what: "an ext2/ext3/ext4 filesystem"
            })
        );
    }

    // ---- the catch-all -----------------------------------------------------

    /// Unrecognised content is still content. A device with bytes we cannot
    /// name is not claimable — the claim is the WHOLE device, so "I don't know
    /// what this is" must not mean "I may have it".
    #[test]
    fn unrecognised_non_zero_content_refuses() {
        let r = clean_region();
        let g = garbage();
        // Guard the fixture: it must not be tripping the boot-signature branch.
        assert_ne!(g[BOOT_SIGNATURE_AT..BOOT_SIGNATURE_AT + 2], BOOT_SIGNATURE);
        let got = decide(&dev(Probe::Read(&g), &r));
        assert!(
            matches!(got, Err(Refusal::ForeignLayout { what }) if what.contains("do not recognise")),
            "{got:?}"
        );
    }

    /// ...and it is enough for the content to be ANYWHERE we looked, not only
    /// in the first block: a single non-zero byte at the last LBA refuses.
    #[test]
    fn non_zero_content_in_any_probe_refuses() {
        let r = clean_region();
        let z = zeros();
        let mut tail = zeros();
        tail[7] = 1;
        let e = Evidence {
            gpt_backup: Probe::Read(&tail),
            ..dev(Probe::Read(&z), &r)
        };
        assert!(
            matches!(decide(&e), Err(Refusal::ForeignLayout { .. })),
            "{:?}",
            decide(&e)
        );
    }

    // ---- the region scans: the actual safety property ----------------------

    /// A container whose only metadata sits at an offset NO point probe covers
    /// (an mdraid 1.2 superblock at byte 4096) must still refuse. This is the
    /// case the signature list cannot catch and the region scan exists for.
    #[test]
    fn a_signature_no_point_probe_covers_is_caught_by_the_front_scan() {
        let z = zeros();
        let mut front = vec![0u8; 1 << 20];
        front[4096..4100].copy_from_slice(b"\xfc\x4e\x2b\xa9"); // mdraid magic
        let clean = vec![0u8; 1 << 20];
        let e = Evidence {
            head: Probe::Read(&z),
            gpt_primary: Probe::Read(&z),
            gpt_backup: Probe::Read(&z),
            ext_super: Probe::Read(&z),
            super_b: Probe::Read(&z),
            front: Probe::Read(&front),
            tail: Probe::Read(&clean),
        };
        assert!(
            matches!(decide(&e), Err(Refusal::ForeignLayout { .. })),
            "{:?}",
            decide(&e)
        );
    }

    /// ...and the same at the END of the device (an mdraid 1.0 superblock, a ZFS
    /// L2/L3 label): the tail scan is not decoration.
    #[test]
    fn metadata_at_the_end_of_the_device_is_caught_by_the_tail_scan() {
        let z = zeros();
        let clean = vec![0u8; 1 << 20];
        let mut tail = vec![0u8; 1 << 20];
        tail[(1 << 20) - 4096] = 0x01;
        let e = Evidence {
            head: Probe::Read(&z),
            gpt_primary: Probe::Read(&z),
            gpt_backup: Probe::Read(&z),
            ext_super: Probe::Read(&z),
            super_b: Probe::Read(&z),
            front: Probe::Read(&clean),
            tail: Probe::Read(&tail),
        };
        assert!(
            matches!(decide(&e), Err(Refusal::ForeignLayout { .. })),
            "{:?}",
            decide(&e)
        );
    }

    /// An unreadable region scan is a hole, not a blank.
    #[test]
    fn an_unreadable_region_scan_refuses() {
        let z = zeros();
        let clean = vec![0u8; 1 << 20];
        let base = Evidence {
            head: Probe::Read(&z),
            gpt_primary: Probe::Read(&z),
            gpt_backup: Probe::Read(&z),
            ext_super: Probe::Read(&z),
            super_b: Probe::Read(&z),
            front: Probe::Read(&clean),
            tail: Probe::Read(&clean),
        };
        assert_eq!(
            decide(&Evidence {
                front: Probe::Unreadable,
                ..base
            }),
            Err(Refusal::EvidenceUnavailable {
                what: "the first megabyte of the device"
            })
        );
        assert_eq!(
            decide(&Evidence {
                tail: Probe::Unreadable,
                ..base
            }),
            Err(Refusal::EvidenceUnavailable {
                what: "the last megabyte of the device"
            })
        );
    }

    /// A region scan that was never TAKEN is not a clean bill of health either.
    /// `Absent` means "nothing was read here"; every other probe can be legitimately
    /// absent on a small device, but these two are clamped to the device by
    /// `plan_probes` and so are never absent in production. Requiring them
    /// positively is what stops the one destructive outcome from being reachable
    /// without the scan that authorises it.
    #[test]
    fn an_unscanned_region_is_not_blank() {
        let z = zeros();
        let clean = clean_region();
        let base = Evidence {
            head: Probe::Read(&z),
            gpt_primary: Probe::Read(&z),
            gpt_backup: Probe::Read(&z),
            ext_super: Probe::Read(&z),
            super_b: Probe::Read(&z),
            front: Probe::Read(&clean),
            tail: Probe::Read(&clean),
        };
        // The control: with both scans present and zero, this IS blank.
        assert_eq!(decide(&base), Ok(Claim::Blank));
        assert_eq!(
            decide(&Evidence {
                front: Probe::Absent,
                ..base
            }),
            Err(Refusal::EvidenceUnavailable {
                what: "the first megabyte of the device (it was never scanned)"
            })
        );
        assert_eq!(
            decide(&Evidence {
                tail: Probe::Absent,
                ..base
            }),
            Err(Refusal::EvidenceUnavailable {
                what: "the last megabyte of the device (it was never scanned)"
            })
        );
    }

    // ---- ordering: which signals may override which --------------------

    /// A VALID GPT BEATS AN FXFS MAGIC — unconditionally. "EFI PART" plus a
    /// matching CRC-32 is not something Fxfs's record stream produces by
    /// accident, so this really is a partitioned disk with a stray magic, and
    /// opening it would replay a journal over LBA 1.
    /// (Covered by `a_damaged_primary_with_an_intact_backup_...` above; this
    /// pins the primary-copy case too.)
    #[test]
    fn a_valid_gpt_beats_an_fxfs_magic() {
        let r = clean_region();
        let hdr = real_gpt_primary_header();
        let fxfs = block_with(b"FxfsSupr");
        let e = Evidence {
            gpt_primary: Probe::Read(&hdr),
            ..dev(Probe::Read(&fxfs), &r)
        };
        assert_eq!(
            decide(&e),
            Err(Refusal::ForeignLayout {
                what: "a valid GPT partition table"
            })
        );
    }

    /// ...BUT THE TWO-BYTE SIGNATURES DO NOT, and this is the correction to a
    /// rule that was briefly the other way round. Bytes 510 and 1080 are inside
    /// Fxfs superblock A's own serialized record stream. `55 AA` landing at 510
    /// is a 1-in-65536 coincidence, and refusing on it would permanently lock a
    /// legitimate Cerise disk out of its own file server. When the first block
    /// IS an Fxfs superblock, those bytes are Fxfs's, not an MBR's.
    #[test]
    fn a_two_byte_signature_inside_an_fxfs_superblock_is_not_a_foreign_layout() {
        let r = clean_region();
        let mut b = block_with(b"FxfsSupr");
        b[BOOT_SIGNATURE_AT..BOOT_SIGNATURE_AT + 2].copy_from_slice(&BOOT_SIGNATURE);
        assert_eq!(decide(&dev(Probe::Read(&b), &r)), Ok(Claim::OpenExisting));

        let a = block_with(b"FxfsSupr");
        let ext = block_at(EXT_MAGIC_AT, &EXT_MAGIC);
        let e = Evidence {
            ext_super: Probe::Read(&ext),
            ..dev(Probe::Read(&a), &r)
        };
        assert_eq!(decide(&e), Ok(Claim::OpenExisting));
    }

    /// THE CASE THAT MUST NOT BE LOST TO THAT RELAXATION: a real MBR at offset 0
    /// with an Fxfs container starting later on the disk, so that our fixed
    /// 524288 probe lands on ITS superblock. The first block is not an Fxfs
    /// superblock, so `55 AA` there means exactly what it says, and the disk is
    /// refused rather than opened.
    #[test]
    fn an_mbr_with_an_fxfs_container_further_in_still_refuses() {
        let r = clean_region();
        let mbr = block_at(BOOT_SIGNATURE_AT, &BOOT_SIGNATURE);
        let inner = block_with(b"FxfsSupr");
        let e = Evidence {
            super_b: Probe::Read(&inner),
            ..dev(Probe::Read(&mbr), &r)
        };
        let got = decide(&e);
        assert!(
            matches!(got, Err(Refusal::ForeignLayout { what }) if what.contains("byte 510")),
            "{got:?}"
        );
    }

    // ---- the probe plan: WHERE we read, not just what we conclude ----------

    /// THE MUTANT THIS EXISTS TO KILL (found in review): every test above builds
    /// `Evidence` by hand, so changing `SUPER_BLOCK_B_OFFSET` to a wrong value
    /// leaves them all passing while production probes empty space and calls a
    /// live filesystem blank. Assert the ABSOLUTE byte offsets.
    #[test]
    fn the_probe_plan_lands_on_the_documented_offsets_512() {
        let p = plan_probes(512, 488_397_168).expect("the CF-SZ5's WDC SSD geometry");
        assert_eq!(
            p.head,
            Span {
                offset: 0,
                len: 512
            }
        );
        assert_eq!(
            p.gpt_primary,
            Span {
                offset: 512,
                len: 512
            },
            "GPT primary is LBA 1"
        );
        assert_eq!(
            p.gpt_backup,
            Span {
                offset: 488_397_167 * 512,
                len: 512
            },
            "GPT backup is the LAST LBA"
        );
        assert_eq!(
            p.ext_super,
            Span {
                offset: 1024,
                len: 512
            },
            "ext magic lands at 1080"
        );
        assert_eq!(
            p.super_b,
            Span {
                offset: 524_288,
                len: 512
            },
            "Fxfs superblock B"
        );
        assert_eq!(
            p.front,
            Span {
                offset: 0,
                len: 1 << 20
            }
        );
        assert_eq!(
            p.tail,
            Span {
                offset: 488_397_168 * 512 - (1 << 20),
                len: 1 << 20
            }
        );
    }

    /// The same offsets are BYTE offsets, not block counts: on a 4Kn disk the
    /// GPT moves with the block size and the fixed-byte locations do not.
    #[test]
    fn the_probe_plan_lands_on_the_documented_offsets_4096() {
        let p = plan_probes(4096, 1_000_000).expect("a 4Kn disk");
        assert_eq!(
            p.head,
            Span {
                offset: 0,
                len: 4096
            }
        );
        assert_eq!(
            p.gpt_primary,
            Span {
                offset: 4096,
                len: 4096
            },
            "LBA 1 is 4096 here"
        );
        assert_eq!(
            p.gpt_backup,
            Span {
                offset: 999_999 * 4096,
                len: 4096
            }
        );
        assert_eq!(
            p.ext_super,
            Span {
                offset: 1024,
                len: 4096
            },
            "fixed byte offset"
        );
        assert_eq!(
            p.super_b,
            Span {
                offset: 524_288,
                len: 4096
            },
            "fixed byte offset"
        );
        assert_eq!(
            p.tail,
            Span {
                offset: 1_000_000u64 * 4096 - (1 << 20),
                len: 1 << 20
            }
        );
    }

    /// A device smaller than the scan windows gets clamped windows, not an
    /// overflowing or empty plan.
    #[test]
    fn the_probe_plan_clamps_on_a_tiny_device() {
        let p = plan_probes(512, 8).expect("a 4 KiB device");
        assert_eq!(
            p.front,
            Span {
                offset: 0,
                len: 4096
            }
        );
        assert_eq!(
            p.tail,
            Span {
                offset: 0,
                len: 4096
            }
        );
        assert_eq!(
            p.gpt_backup,
            Span {
                offset: 7 * 512,
                len: 512
            }
        );
    }

    /// Nonsense geometry is a fault to report, never a device to reshape.
    #[test]
    fn the_probe_plan_refuses_nonsense_geometry() {
        assert_eq!(plan_probes(0, 100), None);
        assert_eq!(plan_probes(512, 0), None);
        assert_eq!(plan_probes(u64::MAX, u64::MAX), None);
    }

    /// A transient all-zero survey of a physical disk must not authorize a
    /// whole-device format. Disposable VM scratch disks remain supported.
    #[test]
    fn automatic_format_is_capacity_bounded() {
        assert!(automatic_format_allowed(300 << 20));
        assert!(automatic_format_allowed(MAX_AUTOMATIC_FORMAT_BYTES));
        assert!(!automatic_format_allowed(MAX_AUTOMATIC_FORMAT_BYTES + 1));
        assert!(!automatic_format_allowed(250_059_350_016));
    }

    // ---- the classifier itself --------------------------------------------

    #[test]
    fn gpt_copy_classification() {
        let z = zeros();
        let hdr = real_gpt_primary_header();
        assert_eq!(classify_gpt_copy(Probe::Read(&hdr)), GptCopy::Valid);
        assert_eq!(classify_gpt_copy(Probe::Read(&z)), GptCopy::Absent);
        assert_eq!(classify_gpt_copy(Probe::Absent), GptCopy::Absent);
        assert_eq!(classify_gpt_copy(Probe::Unreadable), GptCopy::Unreadable);
        let mut bad = hdr.clone();
        bad[20] ^= 0xFF;
        assert_eq!(classify_gpt_copy(Probe::Read(&bad)), GptCopy::Damaged);
        // A truncated read never panics and never validates.
        assert_eq!(classify_gpt_copy(Probe::Read(b"EFI")), GptCopy::Absent);
        assert_eq!(classify_gpt_copy(Probe::Read(&[])), GptCopy::Absent);
    }

    #[test]
    fn table_combination_prefers_a_valid_copy_then_the_worst_hole() {
        use GptCopy::*;
        assert_eq!(combine_table(Valid, Unreadable), TableEvidence::Present);
        assert_eq!(combine_table(Unreadable, Valid), TableEvidence::Present);
        assert_eq!(combine_table(Absent, Absent), TableEvidence::Absent);
        assert_eq!(combine_table(Damaged, Absent), TableEvidence::Damaged);
        assert_eq!(
            combine_table(Unreadable, Damaged),
            TableEvidence::Unreadable
        );
    }

    /// A short read must never panic, and a truncated magic must never match.
    #[test]
    fn short_reads_are_safe() {
        let r = clean_region();
        // A prefix of the magic is NOT the magic, and it is not zero either, so
        // it lands in the catch-all rather than being opened or formatted.
        assert!(
            matches!(
                decide(&dev(Probe::Read(b"Fxfs"), &r)),
                Err(Refusal::ForeignLayout { .. })
            ),
            "a truncated Fxfs magic must not read as a filesystem"
        );
        // A zero-length read carries no content and no magic.
        assert_eq!(decide(&dev(Probe::Read(&[]), &r)), Ok(Claim::Blank));
        assert_eq!(
            decide(&dev(Probe::Read(b"FxfsSupr"), &r)),
            Ok(Claim::OpenExisting)
        );
        // Too short to hold byte 510 -> the boot-signature check cannot panic.
        let mut half = vec![0u8; 64];
        half[63] = 0xAA;
        assert!(matches!(
            decide(&dev(Probe::Read(&half), &r)),
            Err(Refusal::ForeignLayout { .. })
        ));
    }
}

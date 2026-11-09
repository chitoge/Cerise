//! Disk-ownership detection for the provisioner's whole-disk claim policy.
//!
//! STORAGE POLICY (maintainer decision 2026-07-22, shape refined 2026-07-25):
//! whole-disk claim is SANCTIONED when the disk is not Cerise-owned. If the
//! disk IS ours, it must be RETAINED — and corruption must NEVER demote an
//! owned disk to claimable.
//!
//! WHAT THE CLAIM NOW LOOKS LIKE: claiming a disk no longer means formatting
//! the raw block device as Fxfs. It means writing a GPT with an ESP and an
//! Fxfs partition (see `layout.rs`) and formatting Fxfs *inside* that
//! partition, so a disk Cerise claims has somewhere for a bootloader to live.
//! That moves the Fxfs superblocks off device offset 0, which is why ownership
//! detection below has to look in two places.
//!
//! WHY `detect_disk_format` ALONE IS NOT ENOUGH: fs_management's sniff reads
//! ONLY superblock A at device offset 0 (format.rs: one `read_at(buf, 0)` +
//! `data.starts_with(FXFS_MAGIC)`), and maps every error to `Unknown`. Fxfs
//! keeps TWO superblock copies, A at offset 0 and B at offset 524288 (fxfs
//! super_block.rs: both instances begin with the magic in both current and
//! legacy layouts). So an Fxfs disk whose first bytes are damaged — but whose
//! superblock B is intact — sniffs as `Unknown` and would fall into the
//! claim/format branch: exactly the corruption-demotes-to-claimable failure
//! the policy forbids. The hardening: independently probe the magic at BOTH
//! superblock locations; if EITHER matches, the disk is ours.
//!
//! THE ASYMMETRY BUG THIS MODULE NOW FIXES (bug 1): the probes used to be
//! `Option<&[u8]>`, with `None` meaning both "this location does not exist on
//! this device" and "the read failed". Treating a failed read as no-evidence
//! is right in isolation — a read failure must never *fabricate* ownership —
//! but the consequence of no-evidence was destructive: `disk_is_owned(false,
//! None, None)` is false, and the not-owned branch formats. A transient read
//! error at the wrong instant therefore reformatted a disk that was already
//! ours, and the retry loop did not help because the reformat returned `Ok`
//! immediately. [`Probe`] now separates `Absent` (a real fact about a small
//! device) from `Unreadable` (missing evidence), and [`decide`] REFUSES rather
//! than claiming when evidence that could have said "ours" is missing. Missing
//! evidence never authorises a write.
//!
//! This module is deliberately pure (no zx / FIDL / async) so the ownership
//! decision is host-unit-testable; main.rs supplies the raw block reads.

use core::fmt;

/// First 8 bytes of every Fxfs superblock: b"FxfsSupr" (fxfs
/// super_block.rs `SUPER_BLOCK_MAGIC`, mirrored by fs_management's
/// `FXFS_MAGIC`). Mirrored here as policy data: ownership must be decidable
/// from raw bytes even when the full Fxfs stack refuses the volume.
pub const FXFS_MAGIC: [u8; 8] = *b"FxfsSupr";

/// Byte offset of Fxfs superblock copy B (fxfs super_block.rs
/// `SuperBlockInstance::B.first_extent()` = 524288 in both the current and
/// legacy extent layouts; copy A is at offset 0 in both). Relative to the
/// START OF THE FXFS CONTAINER, which is device offset 0 for a legacy
/// whole-device store and the partition offset for a store in our GPT layout.
pub const SUPER_BLOCK_B_OFFSET: u64 = 524_288;

/// A byte range of a device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Region {
    pub start: u64,
    pub len: u64,
}

impl Region {
    pub fn new(start: u64, len: u64) -> Self {
        Self { start, len }
    }
    pub fn end(&self) -> u64 {
        self.start + self.len
    }
    pub fn is_whole_device(&self, device_len: u64) -> bool {
        self.start == 0 && self.len == device_len
    }
}

/// The result of one raw probe read. The distinction between the last two
/// variants is the whole point (see the module header): `Absent` is a fact,
/// `Unreadable` is a hole in our knowledge, and only the first may lead to a
/// destructive decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Probe<'a> {
    /// The bytes at that location.
    Read(&'a [u8]),
    /// The location does not exist on this device (e.g. superblock B on a
    /// device smaller than 524288+block bytes). Nothing is there to find.
    Absent,
    /// The read failed. We do not know what is there.
    Unreadable,
}

impl Probe<'_> {
    fn carries_magic(&self) -> bool {
        matches!(self, Probe::Read(b) if block_has_fxfs_magic(b))
    }
    fn is_unreadable(&self) -> bool {
        matches!(self, Probe::Unreadable)
    }
    fn carries_foreign_container(&self) -> bool {
        matches!(self, Probe::Read(b) if block_has_fvm_magic(b))
    }
}

/// What the provisioner should do with a disk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Plan {
    /// There is an Fxfs container here already. Open it, ensure the blob
    /// volume, and touch nothing else. Never reformat, never re-partition.
    OpenExisting(Region),
    /// The disk carries a Cerise layout whose Fxfs partition has no container
    /// in it yet (we crashed between writing the table and formatting).
    /// Format inside the partition. Does NOT rewrite the table.
    FormatIn(Region),
    /// No evidence that this disk is ours: claim the whole device by writing
    /// the bootable layout and formatting Fxfs inside its Fxfs partition.
    /// This is the only destructive outcome, and it is reachable only when
    /// every probe was actually read.
    CreateLayout,
}

/// Why the provisioner refuses to decide. Refusing is always safe; claiming on
/// incomplete evidence is not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OwnershipError {
    /// A probe that could have proved the disk is ours could not be read.
    EvidenceUnavailable { what: &'static str },
    /// A partition of Cerise's type holds somebody else's container. Our type
    /// GUID is shared with upstream Fuchsia, so type alone does not prove we
    /// wrote it.
    ForeignContainer { region: Region, what: &'static str },
}

impl fmt::Display for OwnershipError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OwnershipError::EvidenceUnavailable { what } => write!(
                f,
                "refusing to decide disk ownership: could not read {what}. \
                 A read failure is missing evidence, not proof the disk is free — \
                 claiming it here would reformat a disk that may already be ours."
            ),
            OwnershipError::ForeignContainer { region, what } => write!(
                f,
                "refusing to format {what} at offset {} (length {}): the partition carries \
                 Cerise's Fxfs type GUID, but that GUID is upstream Fuchsia's FVM type too, \
                 and the contents say this partition is somebody else's. Formatting here would \
                 destroy a live installation.",
                region.start, region.len
            ),
        }
    }
}

/// Everything `main.rs` learned about one disk, in raw form.
#[derive(Debug)]
pub struct Evidence<'a> {
    /// The whole device, as a region.
    pub whole_device: Region,
    /// fs_management's whole-device content sniff said Fxfs. Positive evidence
    /// only — it maps every error to "not Fxfs", so a false here proves
    /// nothing (which is exactly why the probes below exist).
    pub sniff_says_fxfs: bool,
    /// Where a GPT of ours puts its Fxfs partition, if the table on this disk
    /// is one of ours.
    pub table: TableEvidence,
    /// Superblock A / B probes taken at DEVICE offsets 0 and 524288 — the
    /// legacy whole-device Fxfs layout this provisioner used to create.
    pub whole_a: Probe<'a>,
    pub whole_b: Probe<'a>,
    /// Superblock A / B probes taken relative to `table`'s Fxfs partition.
    /// Meaningless (and ignored) unless `table` is `Ours`.
    pub part_a: Probe<'a>,
    pub part_b: Probe<'a>,
}

/// What reading the partition table (both copies) told us.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TableEvidence {
    /// A well-formed GPT carrying a partition of Cerise's Fxfs type, here.
    Ours(Region),
    /// Both copies read cleanly and neither carries a Cerise Fxfs partition:
    /// no table at all, or a foreign one.
    NotOurs,
    /// A GPT is present but could not be interpreted in either copy (a
    /// signature with a bad CRC, self-inconsistent geometry). The partition it
    /// described could have been ours, so this is missing evidence, not a
    /// clean "no".
    Damaged,
    /// A read failed.
    Unreadable,
}

/// First 8 bytes of a Fuchsia Volume Manager superblock, b"FVM PART"
/// (fs_management `FVM_MAGIC`,
/// `src/upstream/fuchsia/src/storage/lib/fs_management/rust/src/format/constants.rs:20`).
/// Mirrored here for one narrow purpose: our Fxfs partition type IS upstream's
/// FVM partition type, so this is the magic that tells an upstream Fuchsia
/// install apart from a half-provisioned Cerise one. See [`decide`].
pub const FVM_MAGIC: [u8; 8] = *b"FVM PART";

/// Returns true when a raw block read (from superblock offset A or B) carries
/// the Fxfs superblock magic.
pub fn block_has_fxfs_magic(block: &[u8]) -> bool {
    block.len() >= FXFS_MAGIC.len() && block[..FXFS_MAGIC.len()] == FXFS_MAGIC
}

/// Returns true when a raw block read carries the FVM superblock magic.
pub fn block_has_fvm_magic(block: &[u8]) -> bool {
    block.len() >= FVM_MAGIC.len() && block[..FVM_MAGIC.len()] == FVM_MAGIC
}

/// The ownership predicate: a container is Cerise's iff ANY evidence of Fxfs
/// remains — the content sniff said Fxfs, or either superblock copy still
/// carries the magic. Probes that are `Absent` or `Unreadable` contribute no
/// evidence here; the *consequence* of missing evidence is [`decide`]'s job,
/// not this predicate's.
pub fn disk_is_owned(sniff_says_fxfs: bool, superblock_a: Probe<'_>, superblock_b: Probe<'_>) -> bool {
    sniff_says_fxfs || superblock_a.carries_magic() || superblock_b.carries_magic()
}

/// The whole provisioning decision, as a pure function of the evidence.
///
/// Ordering is the load-bearing part: "is this already ours?" is answered in
/// full — legacy whole-device store, our own GPT layout, and every probe that
/// could show either — BEFORE any path reaches [`Plan::CreateLayout`]. And a
/// probe that could have said "ours" but could not be read stops the decision
/// dead instead of falling through to the destructive branch.
pub fn decide(e: &Evidence<'_>) -> Result<Plan, OwnershipError> {
    // 1. Positive whole-device evidence, cheapest and strongest.
    if e.sniff_says_fxfs {
        return Ok(Plan::OpenExisting(e.whole_device));
    }

    // 2. Our own GPT layout. If we could not read the table at all we cannot
    //    tell a virgin disk from one we provisioned last boot.
    match e.table {
        TableEvidence::Unreadable => {
            return Err(OwnershipError::EvidenceUnavailable { what: "the GPT header or entry array" });
        }
        TableEvidence::Damaged => {
            return Err(OwnershipError::EvidenceUnavailable {
                what: "a partition table that is present but valid in neither copy",
            });
        }
        TableEvidence::Ours(region) => {
            if disk_is_owned(false, e.part_a, e.part_b) {
                return Ok(Plan::OpenExisting(region));
            }
            if e.part_a.is_unreadable() || e.part_b.is_unreadable() {
                return Err(OwnershipError::EvidenceUnavailable {
                    what: "an Fxfs superblock inside our own partition",
                });
            }
            // THE TYPE GUID IS NOT PROOF OF AUTHORSHIP. Cerise's Fxfs partition
            // type is `GPT_FVM_TYPE_GUID` (gpt.h:144) because that is the
            // constant this tree defines and fs_management keys off — but
            // upstream Fuchsia uses that same type for a real Fuchsia Volume
            // Manager container. A partition of "our" type that holds an FVM is
            // an upstream Fuchsia installation, not a half-finished Cerise one,
            // and formatting Fxfs over it would silently destroy it. Refuse.
            // (This is a single named-magic guard, not the general
            // foreign-partition analysis that was cancelled: it fires only on
            // the one collision our own type GUID actually creates.)
            if e.part_a.carries_foreign_container() {
                return Err(OwnershipError::ForeignContainer {
                    region,
                    what: "a Fuchsia Volume Manager container",
                });
            }
            // Our table, our partition, no container inside it: a previous run
            // wrote the table and died before formatting. Finish the job. This
            // writes only inside the partition the table already reserved.
            return Ok(Plan::FormatIn(region));
        }
        TableEvidence::NotOurs => {}
    }

    // 3. The legacy layout: an Fxfs container occupying the raw device, which
    //    is what every disk provisioned before this change looks like. Such a
    //    disk is RETAINED as-is and never re-partitioned.
    if disk_is_owned(false, e.whole_a, e.whole_b) {
        return Ok(Plan::OpenExisting(e.whole_device));
    }
    if e.whole_a.is_unreadable() || e.whole_b.is_unreadable() {
        return Err(OwnershipError::EvidenceUnavailable {
            what: "an Fxfs superblock at the start of the device",
        });
    }

    // 4. Every probe was read and none of them says this disk is ours.
    Ok(Plan::CreateLayout)
}

#[cfg(test)]
mod tests {
    use super::*;

    const BLOCK: usize = 4096;
    const DEV_LEN: u64 = 64 << 30;

    fn block_with(prefix: &[u8]) -> Vec<u8> {
        let mut b = vec![0u8; BLOCK];
        b[..prefix.len()].copy_from_slice(prefix);
        b
    }

    fn garbage_block() -> Vec<u8> {
        // Deterministic non-magic noise (a corrupt/overwritten superblock).
        (0..BLOCK).map(|i| (i * 7 + 13) as u8).collect()
    }

    fn whole() -> Region {
        Region::new(0, DEV_LEN)
    }

    /// Evidence for a disk with no GPT of ours and the given whole-device probes.
    fn raw<'a>(sniff: bool, a: Probe<'a>, b: Probe<'a>) -> Evidence<'a> {
        Evidence {
            whole_device: whole(),
            sniff_says_fxfs: sniff,
            table: TableEvidence::NotOurs,
            whole_a: a,
            whole_b: b,
            part_a: Probe::Absent,
            part_b: Probe::Absent,
        }
    }

    // ---- the ownership predicate ------------------------------------------

    #[test]
    fn virgin_disk_is_claimable() {
        let zeros = vec![0u8; BLOCK];
        assert!(!disk_is_owned(false, Probe::Read(&zeros), Probe::Read(&zeros)));
    }

    #[test]
    fn garbage_disk_is_claimable() {
        let g = garbage_block();
        assert!(!disk_is_owned(false, Probe::Read(&g), Probe::Read(&g)));
    }

    #[test]
    fn healthy_fxfs_is_owned() {
        let a = block_with(b"FxfsSupr");
        let b = block_with(b"FxfsSupr");
        assert!(disk_is_owned(true, Probe::Read(&a), Probe::Read(&b)));
    }

    /// THE POLICY-CRITICAL CASE: superblock A corrupted (sniff sees Unknown),
    /// superblock B intact -> still OWNED. Corruption never demotes to claimable.
    #[test]
    fn corrupt_superblock_a_intact_b_is_still_owned() {
        let corrupt_a = garbage_block();
        let intact_b = block_with(b"FxfsSupr");
        assert!(disk_is_owned(false, Probe::Read(&corrupt_a), Probe::Read(&intact_b)));
        assert_eq!(
            decide(&raw(false, Probe::Read(&corrupt_a), Probe::Read(&intact_b))),
            Ok(Plan::OpenExisting(whole()))
        );
    }

    /// Magic-at-A present but the sniff failed (e.g. transport error mapped to
    /// Unknown by detect_disk_format): the independent probe still protects it.
    #[test]
    fn sniff_error_with_intact_a_is_owned() {
        let intact_a = block_with(b"FxfsSupr");
        let corrupt_b = garbage_block();
        assert!(disk_is_owned(false, Probe::Read(&intact_a), Probe::Read(&corrupt_b)));
    }

    /// A device too small for superblock B (probe genuinely Absent): A decides.
    #[test]
    fn small_device_decided_by_superblock_a() {
        let intact_a = block_with(b"FxfsSupr");
        assert!(disk_is_owned(false, Probe::Read(&intact_a), Probe::Absent));
        let g = garbage_block();
        assert!(!disk_is_owned(false, Probe::Read(&g), Probe::Absent));
        // ...and it decides the whole plan, without erroring on the absence.
        assert_eq!(decide(&raw(false, Probe::Read(&g), Probe::Absent)), Ok(Plan::CreateLayout));
    }

    /// A truncated/short read never panics and never matches.
    #[test]
    fn short_block_is_not_magic() {
        assert!(!block_has_fxfs_magic(b"Fxfs"));
        assert!(!block_has_fxfs_magic(&[]));
        // Prefix alone in a full block IS the magic (the on-disk check).
        assert!(block_has_fxfs_magic(&block_with(b"FxfsSupr")));
    }

    // ---- BUG 1: an unreadable probe must never lead to a reformat ----------

    /// THE REGRESSION TEST FOR BUG 1. This is the case that used to reformat a
    /// disk that was already ours: both probes fail to read, the sniff maps its
    /// own error to "not Fxfs", and the old code fell through to the format
    /// branch. It must now REFUSE.
    #[test]
    fn unreadable_probes_refuse_instead_of_claiming() {
        let e = raw(false, Probe::Unreadable, Probe::Unreadable);
        assert_eq!(
            decide(&e),
            Err(OwnershipError::EvidenceUnavailable {
                what: "an Fxfs superblock at the start of the device"
            })
        );
        // ...and the message says why, so an operator can tell this apart from
        // a disk we simply declined to touch.
        assert!(decide(&e).unwrap_err().to_string().contains("not proof the disk is free"));
    }

    /// One unreadable probe is enough to stop the destructive branch, even when
    /// the other probe read cleanly as not-ours: the unread one could have been
    /// the intact superblock.
    #[test]
    fn one_unreadable_probe_still_refuses() {
        let g = garbage_block();
        assert!(decide(&raw(false, Probe::Read(&g), Probe::Unreadable)).is_err());
        assert!(decide(&raw(false, Probe::Unreadable, Probe::Read(&g))).is_err());
    }

    /// But an unreadable probe must not *fabricate* ownership either: positive
    /// evidence elsewhere still wins, and is not downgraded to an error.
    #[test]
    fn positive_evidence_beats_an_unreadable_probe() {
        let intact = block_with(b"FxfsSupr");
        assert_eq!(
            decide(&raw(false, Probe::Read(&intact), Probe::Unreadable)),
            Ok(Plan::OpenExisting(whole()))
        );
        assert_eq!(
            decide(&raw(true, Probe::Unreadable, Probe::Unreadable)),
            Ok(Plan::OpenExisting(whole()))
        );
    }

    /// An unreadable partition table is the same class of hole: we cannot tell
    /// a virgin disk from one we laid out last boot.
    #[test]
    fn an_unreadable_table_refuses() {
        let zeros = vec![0u8; BLOCK];
        let e = Evidence {
            table: TableEvidence::Unreadable,
            ..raw(false, Probe::Read(&zeros), Probe::Read(&zeros))
        };
        assert_eq!(
            decide(&e),
            Err(OwnershipError::EvidenceUnavailable { what: "the GPT header or entry array" })
        );
    }

    // ---- the new layout: recognition and idempotence -----------------------

    fn with_our_table<'a>(region: Region, a: Probe<'a>, b: Probe<'a>) -> Evidence<'a> {
        Evidence {
            whole_device: whole(),
            sniff_says_fxfs: false,
            table: TableEvidence::Ours(region),
            whole_a: Probe::Read(&[]),
            whole_b: Probe::Read(&[]),
            part_a: a,
            part_b: b,
        }
    }

    /// IDEMPOTENCE: a disk already carrying a Cerise layout with a formatted
    /// Fxfs partition is reused, not re-partitioned.
    #[test]
    fn a_disk_already_carrying_our_layout_is_reused() {
        let region = Region::new(2 * (1 << 30) + (1 << 20), 60 << 30);
        let intact = block_with(b"FxfsSupr");
        assert_eq!(
            decide(&with_our_table(region, Probe::Read(&intact), Probe::Read(&intact))),
            Ok(Plan::OpenExisting(region))
        );
    }

    /// ...and the both-superblocks reasoning carries forward into the
    /// partition: a damaged superblock A inside our partition, with B intact,
    /// is still ours. Corruption must not demote it to "re-partition me".
    #[test]
    fn damaged_superblock_a_inside_our_partition_is_still_ours() {
        let region = Region::new(1 << 21, 60 << 30);
        let corrupt = garbage_block();
        let intact = block_with(b"FxfsSupr");
        assert_eq!(
            decide(&with_our_table(region, Probe::Read(&corrupt), Probe::Read(&intact))),
            Ok(Plan::OpenExisting(region))
        );
    }

    /// Crash between writing the table and formatting: the table is ours, the
    /// partition is empty. Finish inside the partition; do NOT rewrite the
    /// table, and above all do not fall back to claiming the whole device.
    #[test]
    fn our_table_with_an_unformatted_partition_is_formatted_in_place() {
        let region = Region::new(1 << 21, 60 << 30);
        let zeros = vec![0u8; BLOCK];
        assert_eq!(
            decide(&with_our_table(region, Probe::Read(&zeros), Probe::Read(&zeros))),
            Ok(Plan::FormatIn(region))
        );
    }

    /// An unreadable probe INSIDE our own partition refuses too — same rule,
    /// and here the destructive alternative would have been a reformat of a
    /// partition that may well hold a live filesystem.
    #[test]
    fn an_unreadable_probe_inside_our_partition_refuses() {
        let region = Region::new(1 << 21, 60 << 30);
        let zeros = vec![0u8; BLOCK];
        assert_eq!(
            decide(&with_our_table(region, Probe::Read(&zeros), Probe::Unreadable)),
            Err(OwnershipError::EvidenceUnavailable {
                what: "an Fxfs superblock inside our own partition"
            })
        );
    }

    /// A disk provisioned by the OLD code — Fxfs straight on the raw device,
    /// no partition table — must be retained exactly as it is. This is the
    /// upgrade path, and re-partitioning it would destroy a live filesystem.
    #[test]
    fn a_legacy_whole_device_fxfs_disk_is_never_repartitioned() {
        let intact = block_with(b"FxfsSupr");
        let g = garbage_block();
        assert_eq!(
            decide(&raw(false, Probe::Read(&intact), Probe::Read(&g))),
            Ok(Plan::OpenExisting(whole()))
        );
        assert_eq!(decide(&raw(true, Probe::Absent, Probe::Absent)), Ok(Plan::OpenExisting(whole())));
    }

    /// A genuinely blank disk is the one and only case that gets a new layout.
    #[test]
    fn only_a_disk_with_no_evidence_at_all_gets_a_new_layout() {
        let zeros = vec![0u8; BLOCK];
        assert_eq!(decide(&raw(false, Probe::Read(&zeros), Probe::Read(&zeros))), Ok(Plan::CreateLayout));
    }

    /// THE TYPE-GUID COLLISION. Cerise's Fxfs partition type is
    /// `GPT_FVM_TYPE_GUID`, which upstream Fuchsia uses for a real FVM
    /// container. A partition of that type holding an FVM is an upstream
    /// Fuchsia install, and formatting Fxfs over it would destroy it. The type
    /// GUID alone must never authorise the write.
    #[test]
    fn an_upstream_fuchsia_fvm_in_a_partition_of_our_type_is_refused() {
        let region = Region::new(1 << 21, 60 << 30);
        let fvm = block_with(b"FVM PART");
        let zeros = vec![0u8; BLOCK];
        assert_eq!(
            decide(&with_our_table(region, Probe::Read(&fvm), Probe::Read(&zeros))),
            Err(OwnershipError::ForeignContainer {
                region,
                what: "a Fuchsia Volume Manager container"
            })
        );
        let msg = decide(&with_our_table(region, Probe::Read(&fvm), Probe::Read(&zeros)))
            .unwrap_err()
            .to_string();
        assert!(msg.contains("destroy a live installation"), "{msg}");
    }

    /// ...but an Fxfs container of ours in a partition of our type is still
    /// simply ours, FVM guard or not.
    #[test]
    fn the_foreign_container_guard_does_not_block_our_own_store() {
        let region = Region::new(1 << 21, 60 << 30);
        let fxfs = block_with(b"FxfsSupr");
        assert_eq!(
            decide(&with_our_table(region, Probe::Read(&fxfs), Probe::Read(&fxfs))),
            Ok(Plan::OpenExisting(region))
        );
    }

    /// A partition table that is PRESENT but valid in neither copy is missing
    /// evidence, not a clean "not ours": the partition it described could well
    /// have been ours. Refuse rather than re-claim the disk.
    #[test]
    fn a_table_damaged_in_both_copies_refuses() {
        let zeros = vec![0u8; BLOCK];
        let e = Evidence {
            table: TableEvidence::Damaged,
            ..raw(false, Probe::Read(&zeros), Probe::Read(&zeros))
        };
        assert_eq!(
            decide(&e),
            Err(OwnershipError::EvidenceUnavailable {
                what: "a partition table that is present but valid in neither copy"
            })
        );
    }
}

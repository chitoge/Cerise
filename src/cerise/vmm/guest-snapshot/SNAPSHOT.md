# Guest RAM snapshot / restore

Fast restore of guest physical RAM is the primitive a snapshot-driven VMM is
built on: run the guest, then return its memory to an earlier baseline in time
proportional to what changed — not to the size of RAM. This crate provides that
capability on Cerise, and defines the semantics precisely enough that an
in-kernel fast path can later be swapped in without any guest-visible change.

## Model

Guest RAM is a VMO mapped into the guest address-space VMAR. The capability
keeps two VMOs:

- **golden** — the immutable baseline (the snapshot). Mapped into the host so
  the VMM loads the initial guest image directly into it; never mapped into the
  guest.
- **working** — a copy-on-write child of `golden`, mapped into the guest VMAR
  (and into the host VMAR for VMM access). The guest runs here; its writes
  copy-on-write away from `golden`, leaving the baseline intact.

Operations:

| op            | effect                                                        | cost | status |
|---------------|---------------------------------------------------------------|------|--------|
| `new` + `baseline_ptr` | allocate golden, load the baseline image into it     | O(image) | built |
| `start()`     | spawn `working` (CoW clone of golden), map into guest + host   | O(1) + lazy page-in | built |
| `restore()`   | in-kernel revert of `working` to `golden` in place            | O(pages dirtied), no remap | built |
| `dirty_bitmap()` | report pages dirtied since `start`/`restore` (guest + host) | O(dirty) | built |
| `fork()`      | second independent branch sharing the baseline                | O(1) | built |
| `checkpoint()`| promote current `working` to a new baseline (full snapshot)   | O(1) create, lazy copy | built |

`restore()` issues a single `zx_vmo_op_range(working, ZX_VMO_OP_REVERT_TO_SNAPSHOT)`.
The kernel reverts only the pages the guest forked (wrote) back to the parent
baseline in place, and — because the guest RAM mapping is an ordinary kernel
VMO mapping — the revert invalidates the guest's second-level translation
through the normal unmap path, so the guest and host mappings stay valid (no
unmap/remap) and the reverted pages re-fault from the baseline on next access.
Cost is O(pages dirtied since `start`) with no per-page userspace copy. The
baseline is loaded into `golden` up front, so `restore()` is demonstrable on its
own, independent of `checkpoint()`.

### `fork()` and `checkpoint()`

`fork()` returns a second `GuestRamSnapshot` that shares the same golden
baseline (via a duplicated handle) with its own working clone mapped into a
second guest address space; the two branches diverge and `restore()`
independently. `checkpoint()` captures the running `working` as a new golden (a
full `ZX_VMO_CHILD_SNAPSHOT`) and rebases a fresh working onto it, so subsequent
`restore()`s return to the checkpoint rather than the image loaded at `new`.

Both are validated at the kernel level (`vmo_snapshot_fork_test`,
`vmo_snapshot_checkpoint_test`): `restore()`'s share-count surgery stays correct
with sibling clones present, and after a re-baseline it returns to the
checkpoint in the deeper hierarchy — not the original baseline.

**Incremental checkpoint: kernel-ready.** The current userspace `checkpoint()`
takes a *full* snapshot. An O(pages-changed) incremental checkpoint uses
`ZX_VMO_CHILD_SNAPSHOT_MODIFIED`, which Zircon permits only on a pager-backed
parent — yielding a *unidirectional* clone. The kernel supports this end to end:
`ZX_VMO_OP_REVERT_TO_SNAPSHOT` handles both the anonymous (bidirectional) and
pager-backed (unidirectional) clone shapes, and `SNAPSHOT_MODIFIED` re-baseline
+ restore-to-checkpoint is in-kernel unit-tested
(`vmo_snapshot_checkpoint_incremental_test`). The one remaining piece is in the
*VMM*, not the kernel: backing guest RAM with a pager (a userspace pager serving
`golden`) so `checkpoint()` can use `SNAPSHOT_MODIFIED`. Until then the
full-snapshot form above is used.

Known limitation of the full-snapshot form: each `checkpoint()` inserts a new
hidden node in the VMO hierarchy and never collapses the old one, so a workload
that checkpoints repeatedly grows its ancestry (and memory) unbounded. This is
precisely what the incremental/pager-backed form above resolves; until then,
frequent re-baselining should be avoided.

## Two realizations of one semantics

The crate is split so the *semantics* are testable without a hypervisor:

- **Portable model** (`AccessTracker` + `restore_dirty`) — a `no_std`,
  allocation-free page-dirty set and a restore that copies only dirty pages
  from a baseline buffer. It produces exactly the guest-visible state a CoW
  re-clone does, at O(dirty) cost. This is the software fallback for a backend
  without native CoW memory, and the reference the CoW path must match. It is
  unit-tested on the build host — no emulator, no live boot.
- **CoW mechanism** (`cerise::GuestRamSnapshot`) — the Zircon realization on
  `zx_vmo_create_child` (`SNAPSHOT_AT_LEAST_ON_WRITE` for the working clone) and
  the in-kernel `ZX_VMO_OP_REVERT_TO_SNAPSHOT` for restore. Built for the Cerise
  target. (`SNAPSHOT_MODIFIED` for incremental checkpoints is deferred; see
  "Why `checkpoint()` is deferred".)

## Access tracking

Restore does not need the dirty set, but two adjacent capabilities do:
incremental checkpoint (snapshot only what changed) and dirty-region export.
`dirty_bitmap()` returns it directly from the kernel via a single
`zx_vmo_op_range(working, ZX_VMO_OP_QUERY_DIRTY)`: the kernel walks the working
clone's own page list and reports every page it has forked (written) since the
last `restore()`, one bit per page.

The elegant part: on a CoW clone this set is the **union** of both write
sources for free —

- **guest-CPU writes** fork the shared page through the guest's second-level
  translation, and
- **host writes** (the VMM emulating a device into guest RAM through the
  working host mapping) fork the *same* shared page —

so both land in the clone's private page list and both show up in the bitmap.
A conventional guest-only dirty log sees only the guest-CPU source and needs a
second mechanism bolted on for host writes; here the CoW structure captures both
in one query, with no per-write fault.

`AccessTracker` (the portable model) remains the `no_std` software realization
of the same set — and the fallback for a backend without native CoW memory,
where the two sources must be unioned by hand (`mark_range_dirty` for host
writes).

## In-kernel fast restore (implemented)

`restore()` is a single in-kernel operation,
`zx_vmo_op_range(working, ZX_VMO_OP_REVERT_TO_SNAPSHOT, 0, size)`. The kernel
(`VmCowPages::SnapshotRestoreRange`) reverts only the pages the guest forked
back to the parent baseline in place: for each forked page it re-shares the
parent content, frees the private copy, and restores the copy-on-write marker.
No userspace unmap/remap and no per-page copy; the guest mapping's affected
translation entries are invalidated through the normal range-change path, so
the guest re-faults from the baseline on next access.

The kernel primitive is unit-tested in-kernel (`vmo_snapshot_restore_test` under
`//tests/zircon:kernel-utest-boot`): restore returns the baseline, the sibling
holding the baseline is undisturbed, private attribution returns to zero,
copy-on-write is re-armed, and it is repeatable — validated with the
debug-assert kernel (continuous-attribution validation passes).

The revert is additionally validated **through a live guest** (a kernel
hypervisor-enter test): a guest runs on a copy-on-write clone, writes a page of
its own RAM, and the host then queries the dirty set, reverts the clone in
place, and re-enters — whereupon the guest re-reads the same address and
observes the baseline. This exercises the part the VMO-only test cannot: that
the revert invalidates the guest's second-level (EPT) translation so the guest
itself re-faults from the baseline. It runs only on a host that exposes
hardware virtualization to the guest; on a plain emulated boot it self-skips.

The portable model above remains the reference semantics and the fallback for
backends/platforms without the in-kernel op.

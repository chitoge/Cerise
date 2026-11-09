// Copyright 2026 The Fuchsia Authors
//
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT

// Kernel unit tests for the guest-RAM snapshot/restore primitive (VMO
// copy-on-write child revert-to-parent).  Kept in its own suite/testcase so it
// can be linked into the utest kernel independently of the rest of
// vm_unittests (see BUILD.bazel).

#include <lib/fit/defer.h>
#include <lib/page/size.h>
#include <lib/user_copy/user_ptr.h>

#include <object/handle.h>
#include <object/vm_object_dispatcher.h>
#include <vm/vm_cow_pages.h>
#include <vm/vm_object_paged.h>

#include "test_helper.h"

namespace vm_unittest {

namespace {

// Smoke test: confirms this suite is linked into the utest kernel and executed
// by `ut`.  Landing marker for the snapshot-restore work.
bool vmo_snapshot_smoke_test() {
  BEGIN_TEST;
  EXPECT_TRUE(true);
  END_TEST;
}

// Write a single distinguishing byte at the start of page `page` of `vmo`.
zx_status_t poke(const fbl::RefPtr<VmObject>& vmo, size_t page, uint8_t value) {
  return vmo->Write(&value, page * kPageSize, sizeof(value));
}

// Read the distinguishing byte at the start of page `page` of `vmo`.
zx_status_t peek(const fbl::RefPtr<VmObject>& vmo, size_t page, uint8_t* value) {
  return vmo->Read(value, page * kPageSize, sizeof(*value));
}

// Characterize the CoW behaviour this feature relies on, so the revert
// implementation is designed against verified facts rather than inference:
//   * an anonymous golden + OnWrite (SNAPSHOT_AT_LEAST_ON_WRITE) clone shares
//     the baseline until the clone writes,
//   * a clone write forks privately and leaves the golden untouched,
//   * attribution moves to the clone for exactly the forked page, and
//   * DecommitRange on the clone is rejected (no existing revert path).
bool vmo_snapshot_characterize_test() {
  BEGIN_TEST;

  AutoVmScannerDisable scanner_disable;

  constexpr size_t kNumPages = 4;
  constexpr size_t kAllocSize = kPageSize * kNumPages;

  // Anonymous golden VMO, committed and stamped with a per-page baseline.
  fbl::RefPtr<VmObjectPaged> golden;
  ASSERT_EQ(ZX_OK, VmObjectPaged::Create(PMM_ALLOC_FLAG_ANY, 0, kAllocSize, &golden));
  golden->set_user_id(ZX_KOID_KERNEL);
  ASSERT_EQ(ZX_OK, golden->CommitRange(0, kAllocSize));
  for (size_t i = 0; i < kNumPages; i++) {
    ASSERT_EQ(ZX_OK, poke(golden, i, static_cast<uint8_t>(0x10 + i)));
  }

  // OnWrite clone == SNAPSHOT_AT_LEAST_ON_WRITE.
  fbl::RefPtr<VmObject> working;
  ASSERT_EQ(ZX_OK, golden->CreateClone(Resizability::NonResizable, SnapshotType::OnWrite, 0,
                                       kAllocSize, false, &working));
  ASSERT_TRUE(working);
  working->set_user_id(ZX_KOID_KERNEL);

  // Fresh clone: sees golden's baseline, owns no private pages yet.  (Anonymous
  // golden yields a *bidirectional* clone with a hidden parent, so the clone
  // carries a nonzero shared/scaled attribution — hence we assert only the
  // private-byte component, which is the quantity a revert must return to zero.)
  for (size_t i = 0; i < kNumPages; i++) {
    uint8_t v = 0;
    ASSERT_EQ(ZX_OK, peek(working, i, &v));
    EXPECT_EQ(static_cast<uint8_t>(0x10 + i), v);
  }
  EXPECT_EQ(0u, working->GetAttributedMemory().total_private_bytes());

  // Write page 1 of the clone -> forks a private copy.
  ASSERT_EQ(ZX_OK, poke(working, 1, 0xAA));

  // Clone sees its write; golden is untouched.
  uint8_t v = 0;
  ASSERT_EQ(ZX_OK, peek(working, 1, &v));
  EXPECT_EQ(0xAA, v);
  ASSERT_EQ(ZX_OK, peek(golden, 1, &v));
  EXPECT_EQ(0x11, v);

  // Exactly one page is now privately owned by the clone (the fork).
  EXPECT_EQ(kPageSize, working->GetAttributedMemory().total_private_bytes());

  // No existing op reverts a child to its parent: decommit is refused because
  // the clone has a parent.
  EXPECT_EQ(ZX_ERR_NOT_SUPPORTED, working->DecommitRange(0, kAllocSize));

  END_TEST;
}

// Exercise the restore primitive: dirty a clone, restore it to the baseline,
// re-dirty, and restore again — verifying content, that the golden is never
// disturbed, that private attribution returns to zero, and that copy-on-write
// is re-armed after each restore.
bool vmo_snapshot_restore_test() {
  BEGIN_TEST;

  AutoVmScannerDisable scanner_disable;

  constexpr size_t kNumPages = 4;
  constexpr size_t kAllocSize = kPageSize * kNumPages;

  fbl::RefPtr<VmObjectPaged> golden;
  ASSERT_EQ(ZX_OK, VmObjectPaged::Create(PMM_ALLOC_FLAG_ANY, 0, kAllocSize, &golden));
  golden->set_user_id(ZX_KOID_KERNEL);
  ASSERT_EQ(ZX_OK, golden->CommitRange(0, kAllocSize));
  for (size_t i = 0; i < kNumPages; i++) {
    ASSERT_EQ(ZX_OK, poke(golden, i, static_cast<uint8_t>(0x10 + i)));
  }

  fbl::RefPtr<VmObject> working;
  ASSERT_EQ(ZX_OK, golden->CreateClone(Resizability::NonResizable, SnapshotType::OnWrite, 0,
                                       kAllocSize, false, &working));
  working->set_user_id(ZX_KOID_KERNEL);

  // Restore on a VMO with no parent (not a clone) is unsupported.
  {
    fbl::RefPtr<VmObjectPaged> standalone;
    ASSERT_EQ(ZX_OK, VmObjectPaged::Create(PMM_ALLOC_FLAG_ANY, 0, kPageSize, &standalone));
    EXPECT_EQ(ZX_ERR_NOT_SUPPORTED, standalone->SnapshotRestoreRange(0, kPageSize));
  }

  // Dirty pages 1 and 3 of the clone.
  ASSERT_EQ(ZX_OK, poke(working, 1, 0xAA));
  ASSERT_EQ(ZX_OK, poke(working, 3, 0xBB));
  EXPECT_EQ(2u * kPageSize, working->GetAttributedMemory().total_private_bytes());

  // Restore the whole clone.
  ASSERT_EQ(ZX_OK, working->SnapshotRestoreRange(0, kAllocSize));

  // Every page reads the baseline again, the clone owns no private pages, and
  // the golden is untouched.
  uint8_t v = 0;
  for (size_t i = 0; i < kNumPages; i++) {
    ASSERT_EQ(ZX_OK, peek(working, i, &v));
    EXPECT_EQ(static_cast<uint8_t>(0x10 + i), v);
    ASSERT_EQ(ZX_OK, peek(golden, i, &v));
    EXPECT_EQ(static_cast<uint8_t>(0x10 + i), v);
  }
  EXPECT_EQ(0u, working->GetAttributedMemory().total_private_bytes());

  // Copy-on-write is re-armed: a fresh write forks again without disturbing the
  // golden.
  ASSERT_EQ(ZX_OK, poke(working, 2, 0xCC));
  ASSERT_EQ(ZX_OK, peek(working, 2, &v));
  EXPECT_EQ(0xCC, v);
  ASSERT_EQ(ZX_OK, peek(golden, 2, &v));
  EXPECT_EQ(0x12, v);
  EXPECT_EQ(kPageSize, working->GetAttributedMemory().total_private_bytes());

  // Restore is repeatable.
  ASSERT_EQ(ZX_OK, working->SnapshotRestoreRange(0, kAllocSize));
  ASSERT_EQ(ZX_OK, peek(working, 2, &v));
  EXPECT_EQ(0x12, v);
  EXPECT_EQ(0u, working->GetAttributedMemory().total_private_bytes());

  END_TEST;
}

// Restore a sub-range: only the pages in the range revert; forks outside it are
// left untouched.
bool vmo_snapshot_restore_partial_test() {
  BEGIN_TEST;

  AutoVmScannerDisable scanner_disable;

  constexpr size_t kNumPages = 4;
  constexpr size_t kAllocSize = kPageSize * kNumPages;

  fbl::RefPtr<VmObjectPaged> golden;
  ASSERT_EQ(ZX_OK, VmObjectPaged::Create(PMM_ALLOC_FLAG_ANY, 0, kAllocSize, &golden));
  golden->set_user_id(ZX_KOID_KERNEL);
  ASSERT_EQ(ZX_OK, golden->CommitRange(0, kAllocSize));
  for (size_t i = 0; i < kNumPages; i++) {
    ASSERT_EQ(ZX_OK, poke(golden, i, static_cast<uint8_t>(0x10 + i)));
  }

  fbl::RefPtr<VmObject> working;
  ASSERT_EQ(ZX_OK, golden->CreateClone(Resizability::NonResizable, SnapshotType::OnWrite, 0,
                                       kAllocSize, false, &working));
  working->set_user_id(ZX_KOID_KERNEL);

  // Dirty all four pages.
  for (size_t i = 0; i < kNumPages; i++) {
    ASSERT_EQ(ZX_OK, poke(working, i, 0xF0));
  }
  EXPECT_EQ(4u * kPageSize, working->GetAttributedMemory().total_private_bytes());

  // Restore only the middle two pages [1, 3).
  ASSERT_EQ(ZX_OK, working->SnapshotRestoreRange(kPageSize, 2 * kPageSize));

  // Pages 1 and 2 are back to baseline; pages 0 and 3 keep their dirty value.
  uint8_t v = 0;
  ASSERT_EQ(ZX_OK, peek(working, 0, &v));
  EXPECT_EQ(0xF0, v);
  ASSERT_EQ(ZX_OK, peek(working, 1, &v));
  EXPECT_EQ(0x11, v);
  ASSERT_EQ(ZX_OK, peek(working, 2, &v));
  EXPECT_EQ(0x12, v);
  ASSERT_EQ(ZX_OK, peek(working, 3, &v));
  EXPECT_EQ(0xF0, v);

  // Only pages 0 and 3 remain privately owned.
  EXPECT_EQ(2u * kPageSize, working->GetAttributedMemory().total_private_bytes());

  END_TEST;
}

// A pinned page in the restore range makes the operation fail with BAD_STATE
// (the kernel may hold a stable pointer into it); it succeeds once unpinned.
bool vmo_snapshot_restore_pinned_test() {
  BEGIN_TEST;

  AutoVmScannerDisable scanner_disable;

  constexpr size_t kNumPages = 2;
  constexpr size_t kAllocSize = kPageSize * kNumPages;

  fbl::RefPtr<VmObjectPaged> golden;
  ASSERT_EQ(ZX_OK, VmObjectPaged::Create(PMM_ALLOC_FLAG_ANY, 0, kAllocSize, &golden));
  golden->set_user_id(ZX_KOID_KERNEL);
  ASSERT_EQ(ZX_OK, golden->CommitRange(0, kAllocSize));
  ASSERT_EQ(ZX_OK, poke(golden, 0, 0x10));

  fbl::RefPtr<VmObject> working;
  ASSERT_EQ(ZX_OK, golden->CreateClone(Resizability::NonResizable, SnapshotType::OnWrite, 0,
                                       kAllocSize, false, &working));
  working->set_user_id(ZX_KOID_KERNEL);

  // Fork and pin page 0.
  ASSERT_EQ(ZX_OK, poke(working, 0, 0xAA));
  ASSERT_EQ(ZX_OK, working->CommitRangePinned(0, kPageSize, false));

  // Restore over the pinned page is refused.
  EXPECT_EQ(ZX_ERR_BAD_STATE, working->SnapshotRestoreRange(0, kPageSize));

  // Once unpinned, restore succeeds and reverts the page.
  working->Unpin(0, kPageSize);
  ASSERT_EQ(ZX_OK, working->SnapshotRestoreRange(0, kPageSize));
  uint8_t v = 0;
  ASSERT_EQ(ZX_OK, peek(working, 0, &v));
  EXPECT_EQ(0x10, v);

  END_TEST;
}

// Drive the operation through the dispatcher the way zx_vmo_op_range does:
// exercises the ZX_VMO_OP_REVERT_TO_SNAPSHOT op-code dispatch and the
// ZX_RIGHT_WRITE gate, which the method-level tests bypass.
bool vmo_snapshot_restore_op_dispatch_test() {
  BEGIN_TEST;

  AutoVmScannerDisable scanner_disable;

  constexpr size_t kAllocSize = kPageSize;

  fbl::RefPtr<VmObjectPaged> golden;
  ASSERT_EQ(ZX_OK, VmObjectPaged::Create(PMM_ALLOC_FLAG_ANY, 0, kAllocSize, &golden));
  golden->set_user_id(ZX_KOID_KERNEL);
  ASSERT_EQ(ZX_OK, golden->CommitRange(0, kAllocSize));
  ASSERT_EQ(ZX_OK, poke(golden, 0, 0x10));

  fbl::RefPtr<VmObject> working;
  ASSERT_EQ(ZX_OK, golden->CreateClone(Resizability::NonResizable, SnapshotType::OnWrite, 0,
                                       kAllocSize, false, &working));

  // VmObjectDispatcher::Create assigns the VMO's user_id (asserting it was 0),
  // so wrap the clone before setting an id or writing to it.
  KernelHandle<VmObjectDispatcher> handle;
  zx_rights_t rights;
  ASSERT_EQ(ZX_OK, VmObjectDispatcher::Create(
                       working, 0, VmObjectDispatcher::InitialMutability::kMutable, &handle,
                       &rights));

  // Fork page 0 of the clone.
  ASSERT_EQ(ZX_OK, poke(working, 0, 0xAA));

  auto null_buf = make_user_inout_ptr(static_cast<void*>(nullptr));

  // Without the WRITE right the op is refused before touching the VMO.
  EXPECT_EQ(ZX_ERR_ACCESS_DENIED,
            handle.dispatcher()->RangeOp(ZX_VMO_OP_REVERT_TO_SNAPSHOT, 0, kAllocSize, null_buf, 0,
                                         0));

  // With the WRITE right the op runs and reverts the fork.
  EXPECT_EQ(ZX_OK, handle.dispatcher()->RangeOp(ZX_VMO_OP_REVERT_TO_SNAPSHOT, 0, kAllocSize,
                                                null_buf, 0, ZX_RIGHT_WRITE));
  uint8_t v = 0;
  ASSERT_EQ(ZX_OK, peek(working, 0, &v));
  EXPECT_EQ(0x10, v);

  END_TEST;
}

// Fork: two independent clones off one baseline. Reverting one leaves the other
// (and the baseline) untouched — the share-count surgery is correct with
// sibling clones present.
bool vmo_snapshot_fork_test() {
  BEGIN_TEST;

  AutoVmScannerDisable scanner_disable;

  constexpr size_t kNumPages = 4;
  constexpr size_t kAllocSize = kPageSize * kNumPages;

  fbl::RefPtr<VmObjectPaged> golden;
  ASSERT_EQ(ZX_OK, VmObjectPaged::Create(PMM_ALLOC_FLAG_ANY, 0, kAllocSize, &golden));
  golden->set_user_id(ZX_KOID_KERNEL);
  ASSERT_EQ(ZX_OK, golden->CommitRange(0, kAllocSize));
  for (size_t i = 0; i < kNumPages; i++) {
    ASSERT_EQ(ZX_OK, poke(golden, i, static_cast<uint8_t>(0x10 + i)));
  }

  fbl::RefPtr<VmObject> a, b;
  ASSERT_EQ(ZX_OK, golden->CreateClone(Resizability::NonResizable, SnapshotType::OnWrite, 0,
                                       kAllocSize, false, &a));
  a->set_user_id(ZX_KOID_KERNEL);
  ASSERT_EQ(ZX_OK, golden->CreateClone(Resizability::NonResizable, SnapshotType::OnWrite, 0,
                                       kAllocSize, false, &b));
  b->set_user_id(ZX_KOID_KERNEL);

  // Diverge the two branches at different pages.
  ASSERT_EQ(ZX_OK, poke(a, 0, 0xAA));
  ASSERT_EQ(ZX_OK, poke(b, 1, 0xBB));

  // Restore branch a only.
  ASSERT_EQ(ZX_OK, a->SnapshotRestoreRange(0, kAllocSize));

  uint8_t v = 0;
  // a is fully back to baseline and owns nothing private.
  for (size_t i = 0; i < kNumPages; i++) {
    ASSERT_EQ(ZX_OK, peek(a, i, &v));
    EXPECT_EQ(static_cast<uint8_t>(0x10 + i), v);
  }
  EXPECT_EQ(0u, a->GetAttributedMemory().total_private_bytes());
  // b is undisturbed: its page 1 write survives, everything else is baseline.
  ASSERT_EQ(ZX_OK, peek(b, 0, &v));
  EXPECT_EQ(0x10, v);
  ASSERT_EQ(ZX_OK, peek(b, 1, &v));
  EXPECT_EQ(0xBB, v);
  ASSERT_EQ(ZX_OK, peek(b, 2, &v));
  EXPECT_EQ(0x12, v);
  EXPECT_EQ(kPageSize, b->GetAttributedMemory().total_private_bytes());
  // The baseline is untouched.
  for (size_t i = 0; i < kNumPages; i++) {
    ASSERT_EQ(ZX_OK, peek(golden, i, &v));
    EXPECT_EQ(static_cast<uint8_t>(0x10 + i), v);
  }

  // Restoring b too returns it to baseline.
  ASSERT_EQ(ZX_OK, b->SnapshotRestoreRange(0, kAllocSize));
  ASSERT_EQ(ZX_OK, peek(b, 1, &v));
  EXPECT_EQ(0x11, v);
  EXPECT_EQ(0u, b->GetAttributedMemory().total_private_bytes());

  END_TEST;
}

// Checkpoint: capture a running clone's current content as a new baseline (a
// full snapshot), run a fresh clone off it, and confirm restore returns to the
// *checkpoint* rather than the original baseline — exercising revert in the
// deeper hierarchy a re-baseline produces.
bool vmo_snapshot_checkpoint_test() {
  BEGIN_TEST;

  AutoVmScannerDisable scanner_disable;

  constexpr size_t kNumPages = 2;
  constexpr size_t kAllocSize = kPageSize * kNumPages;

  fbl::RefPtr<VmObjectPaged> golden;
  ASSERT_EQ(ZX_OK, VmObjectPaged::Create(PMM_ALLOC_FLAG_ANY, 0, kAllocSize, &golden));
  golden->set_user_id(ZX_KOID_KERNEL);
  ASSERT_EQ(ZX_OK, golden->CommitRange(0, kAllocSize));
  ASSERT_EQ(ZX_OK, poke(golden, 0, 0x10));
  ASSERT_EQ(ZX_OK, poke(golden, 1, 0x11));

  fbl::RefPtr<VmObject> working;
  ASSERT_EQ(ZX_OK, golden->CreateClone(Resizability::NonResizable, SnapshotType::OnWrite, 0,
                                       kAllocSize, false, &working));
  working->set_user_id(ZX_KOID_KERNEL);

  // Guest runs and dirties page 0.
  ASSERT_EQ(ZX_OK, poke(working, 0, 0xAA));

  // Checkpoint: new baseline captures the current state (0xAA, 0x11); a fresh
  // clone runs off it.
  fbl::RefPtr<VmObject> checkpoint;
  ASSERT_EQ(ZX_OK, working->CreateClone(Resizability::NonResizable, SnapshotType::Full, 0,
                                        kAllocSize, false, &checkpoint));
  checkpoint->set_user_id(ZX_KOID_KERNEL);
  fbl::RefPtr<VmObject> working2;
  ASSERT_EQ(ZX_OK, checkpoint->CreateClone(Resizability::NonResizable, SnapshotType::OnWrite, 0,
                                           kAllocSize, false, &working2));
  working2->set_user_id(ZX_KOID_KERNEL);

  uint8_t v = 0;
  ASSERT_EQ(ZX_OK, peek(working2, 0, &v));
  EXPECT_EQ(0xAA, v);
  ASSERT_EQ(ZX_OK, peek(working2, 1, &v));
  EXPECT_EQ(0x11, v);

  // Guest dirties page 1 past the checkpoint.
  ASSERT_EQ(ZX_OK, poke(working2, 1, 0xBB));

  // Restore returns to the checkpoint (0xAA, 0x11), not the original baseline.
  ASSERT_EQ(ZX_OK, working2->SnapshotRestoreRange(0, kAllocSize));
  ASSERT_EQ(ZX_OK, peek(working2, 0, &v));
  EXPECT_EQ(0xAA, v);
  ASSERT_EQ(ZX_OK, peek(working2, 1, &v));
  EXPECT_EQ(0x11, v);
  EXPECT_EQ(0u, working2->GetAttributedMemory().total_private_bytes());

  END_TEST;
}

// Restore also works on a clone of a *pager-backed* root — the unidirectional
// clone shape (no hidden node, no parent-content markers). This is the shape an
// incremental (SNAPSHOT_MODIFIED) checkpoint would produce.
bool vmo_snapshot_restore_pager_test() {
  BEGIN_TEST;

  AutoVmScannerDisable scanner_disable;

  constexpr uint64_t kNumPages = 2;
  constexpr uint64_t kAllocSize = kNumPages * kPageSize;
  vm_page_t* pages[kNumPages];
  fbl::RefPtr<VmObjectPaged> golden;
  ASSERT_EQ(ZX_OK, make_committed_pager_vmo(kNumPages, false, false, pages, &golden));
  golden->set_user_id(ZX_KOID_KERNEL);
  ASSERT_EQ(ZX_OK, poke(golden, 0, 0x10));
  ASSERT_EQ(ZX_OK, poke(golden, 1, 0x11));

  fbl::RefPtr<VmObject> working;
  ASSERT_EQ(ZX_OK, golden->CreateClone(Resizability::NonResizable, SnapshotType::OnWrite, 0,
                                       kAllocSize, false, &working));
  working->set_user_id(ZX_KOID_KERNEL);

  // Fresh clone sees the root baseline.
  uint8_t v = 0;
  ASSERT_EQ(ZX_OK, peek(working, 0, &v));
  EXPECT_EQ(0x10, v);

  // Fork page 0.
  ASSERT_EQ(ZX_OK, poke(working, 0, 0xAA));
  ASSERT_EQ(ZX_OK, peek(working, 0, &v));
  EXPECT_EQ(0xAA, v);
  EXPECT_EQ(kPageSize, working->GetAttributedMemory().total_private_bytes());

  // Restore reverts page 0 to the root baseline; the root is untouched.
  ASSERT_EQ(ZX_OK, working->SnapshotRestoreRange(0, kAllocSize));
  ASSERT_EQ(ZX_OK, peek(working, 0, &v));
  EXPECT_EQ(0x10, v);
  ASSERT_EQ(ZX_OK, peek(golden, 0, &v));
  EXPECT_EQ(0x10, v);
  EXPECT_EQ(0u, working->GetAttributedMemory().total_private_bytes());

  END_TEST;
}

// Incremental checkpoint: with a pager-backed golden, a SNAPSHOT_MODIFIED clone
// captures a new baseline sharing unmodified pages (O(pages changed)), and
// restore of a fresh clone off it returns to the checkpoint. This is the full
// incremental re-baseline path, kernel side.
bool vmo_snapshot_checkpoint_incremental_test() {
  BEGIN_TEST;

  AutoVmScannerDisable scanner_disable;

  constexpr uint64_t kNumPages = 2;
  constexpr uint64_t kAllocSize = kNumPages * kPageSize;
  vm_page_t* pages[kNumPages];
  fbl::RefPtr<VmObjectPaged> golden;
  ASSERT_EQ(ZX_OK, make_committed_pager_vmo(kNumPages, false, false, pages, &golden));
  golden->set_user_id(ZX_KOID_KERNEL);
  ASSERT_EQ(ZX_OK, poke(golden, 0, 0x10));
  ASSERT_EQ(ZX_OK, poke(golden, 1, 0x11));

  fbl::RefPtr<VmObject> working;
  ASSERT_EQ(ZX_OK, golden->CreateClone(Resizability::NonResizable, SnapshotType::OnWrite, 0,
                                       kAllocSize, false, &working));
  working->set_user_id(ZX_KOID_KERNEL);

  // Guest dirties page 0.
  ASSERT_EQ(ZX_OK, poke(working, 0, 0xAA));

  // Incremental checkpoint: SNAPSHOT_MODIFIED captures the modified pages while
  // sharing the rest, and a fresh clone runs off it.
  fbl::RefPtr<VmObject> checkpoint;
  ASSERT_EQ(ZX_OK, working->CreateClone(Resizability::NonResizable, SnapshotType::Modified, 0,
                                        kAllocSize, false, &checkpoint));
  checkpoint->set_user_id(ZX_KOID_KERNEL);
  fbl::RefPtr<VmObject> working2;
  ASSERT_EQ(ZX_OK, checkpoint->CreateClone(Resizability::NonResizable, SnapshotType::OnWrite, 0,
                                           kAllocSize, false, &working2));
  working2->set_user_id(ZX_KOID_KERNEL);

  uint8_t v = 0;
  ASSERT_EQ(ZX_OK, peek(working2, 0, &v));
  EXPECT_EQ(0xAA, v);
  ASSERT_EQ(ZX_OK, peek(working2, 1, &v));
  EXPECT_EQ(0x11, v);

  // Dirty page 1 past the checkpoint, then restore back to the checkpoint.
  ASSERT_EQ(ZX_OK, poke(working2, 1, 0xBB));
  ASSERT_EQ(ZX_OK, working2->SnapshotRestoreRange(0, kAllocSize));
  ASSERT_EQ(ZX_OK, peek(working2, 0, &v));
  EXPECT_EQ(0xAA, v);
  ASSERT_EQ(ZX_OK, peek(working2, 1, &v));
  EXPECT_EQ(0x11, v);
  EXPECT_EQ(0u, working2->GetAttributedMemory().total_private_bytes());

  END_TEST;
}

// The dangerous incremental case: after a SNAPSHOT_MODIFIED checkpoint (which
// inserts a hidden node capturing the modified page), a fresh clone RE-forks
// exactly that captured page and then restores. The reverted fork shadows a
// hidden-node page that carries a share count — the pager-backed revert branch
// must handle that, not just pages that fall through to the pager root.
bool vmo_snapshot_checkpoint_incremental_refork_test() {
  BEGIN_TEST;

  AutoVmScannerDisable scanner_disable;

  constexpr uint64_t kNumPages = 2;
  constexpr uint64_t kAllocSize = kNumPages * kPageSize;
  vm_page_t* pages[kNumPages];
  fbl::RefPtr<VmObjectPaged> golden;
  ASSERT_EQ(ZX_OK, make_committed_pager_vmo(kNumPages, false, false, pages, &golden));
  golden->set_user_id(ZX_KOID_KERNEL);
  ASSERT_EQ(ZX_OK, poke(golden, 0, 0x10));
  ASSERT_EQ(ZX_OK, poke(golden, 1, 0x11));

  fbl::RefPtr<VmObject> working;
  ASSERT_EQ(ZX_OK, golden->CreateClone(Resizability::NonResizable, SnapshotType::OnWrite, 0,
                                       kAllocSize, false, &working));
  working->set_user_id(ZX_KOID_KERNEL);

  // working modifies page 0 — this is the page the checkpoint will capture.
  ASSERT_EQ(ZX_OK, poke(working, 0, 0xAA));

  fbl::RefPtr<VmObject> checkpoint;
  ASSERT_EQ(ZX_OK, working->CreateClone(Resizability::NonResizable, SnapshotType::Modified, 0,
                                        kAllocSize, false, &checkpoint));
  checkpoint->set_user_id(ZX_KOID_KERNEL);
  // Incremental sharing: the checkpoint captures only the modified page, so it
  // privately owns at most that one page (page 1 stays shared with the root).
  EXPECT_LE(checkpoint->GetAttributedMemory().total_private_bytes(), kPageSize);

  fbl::RefPtr<VmObject> working2;
  ASSERT_EQ(ZX_OK, checkpoint->CreateClone(Resizability::NonResizable, SnapshotType::OnWrite, 0,
                                           kAllocSize, false, &working2));
  working2->set_user_id(ZX_KOID_KERNEL);

  uint8_t v = 0;
  ASSERT_EQ(ZX_OK, peek(working2, 0, &v));
  EXPECT_EQ(0xAA, v);

  // Re-fork the captured page (owned by the hidden node), then restore.
  ASSERT_EQ(ZX_OK, poke(working2, 0, 0xCC));
  ASSERT_EQ(ZX_OK, peek(working2, 0, &v));
  EXPECT_EQ(0xCC, v);
  ASSERT_EQ(ZX_OK, working2->SnapshotRestoreRange(0, kAllocSize));
  ASSERT_EQ(ZX_OK, peek(working2, 0, &v));
  EXPECT_EQ(0xAA, v);
  EXPECT_EQ(0u, working2->GetAttributedMemory().total_private_bytes());

  END_TEST;
}

// The share-count case: two sibling clones of a SNAPSHOT_MODIFIED checkpoint
// both see the captured page; one re-forks and reverts it while the other still
// shares it. If the pager-backed revert branch mishandled the hidden-node share
// count, this leaks (caught by teardown / continuous-attribution validation)
// and/or corrupts the sibling.
bool vmo_snapshot_checkpoint_incremental_siblings_test() {
  BEGIN_TEST;

  AutoVmScannerDisable scanner_disable;

  constexpr uint64_t kNumPages = 2;
  constexpr uint64_t kAllocSize = kNumPages * kPageSize;
  vm_page_t* pages[kNumPages];
  fbl::RefPtr<VmObjectPaged> golden;
  ASSERT_EQ(ZX_OK, make_committed_pager_vmo(kNumPages, false, false, pages, &golden));
  golden->set_user_id(ZX_KOID_KERNEL);
  ASSERT_EQ(ZX_OK, poke(golden, 0, 0x10));

  fbl::RefPtr<VmObject> working;
  ASSERT_EQ(ZX_OK, golden->CreateClone(Resizability::NonResizable, SnapshotType::OnWrite, 0,
                                       kAllocSize, false, &working));
  working->set_user_id(ZX_KOID_KERNEL);
  ASSERT_EQ(ZX_OK, poke(working, 0, 0xAA));

  fbl::RefPtr<VmObject> checkpoint;
  ASSERT_EQ(ZX_OK, working->CreateClone(Resizability::NonResizable, SnapshotType::Modified, 0,
                                        kAllocSize, false, &checkpoint));
  checkpoint->set_user_id(ZX_KOID_KERNEL);

  // Two sibling branches off the checkpoint, both seeing the captured page 0.
  fbl::RefPtr<VmObject> a, b;
  ASSERT_EQ(ZX_OK, checkpoint->CreateClone(Resizability::NonResizable, SnapshotType::OnWrite, 0,
                                           kAllocSize, false, &a));
  a->set_user_id(ZX_KOID_KERNEL);
  ASSERT_EQ(ZX_OK, checkpoint->CreateClone(Resizability::NonResizable, SnapshotType::OnWrite, 0,
                                           kAllocSize, false, &b));
  b->set_user_id(ZX_KOID_KERNEL);

  // a re-forks the captured page and reverts it; b keeps sharing it.
  ASSERT_EQ(ZX_OK, poke(a, 0, 0xCC));
  ASSERT_EQ(ZX_OK, a->SnapshotRestoreRange(0, kAllocSize));

  uint8_t v = 0;
  ASSERT_EQ(ZX_OK, peek(a, 0, &v));
  EXPECT_EQ(0xAA, v);  // a back to the checkpoint
  ASSERT_EQ(ZX_OK, peek(b, 0, &v));
  EXPECT_EQ(0xAA, v);  // b undisturbed
  EXPECT_EQ(0u, a->GetAttributedMemory().total_private_bytes());

  END_TEST;
}

// Dirty tracking: QueryDirtyPages reports exactly the pages the clone forked,
// and restore clears the set.
bool vmo_snapshot_dirty_query_test() {
  BEGIN_TEST;

  AutoVmScannerDisable scanner_disable;

  constexpr size_t kNumPages = 8;
  constexpr size_t kAllocSize = kPageSize * kNumPages;

  fbl::RefPtr<VmObjectPaged> golden;
  ASSERT_EQ(ZX_OK, VmObjectPaged::Create(PMM_ALLOC_FLAG_ANY, 0, kAllocSize, &golden));
  golden->set_user_id(ZX_KOID_KERNEL);
  ASSERT_EQ(ZX_OK, golden->CommitRange(0, kAllocSize));

  fbl::RefPtr<VmObject> working;
  ASSERT_EQ(ZX_OK, golden->CreateClone(Resizability::NonResizable, SnapshotType::OnWrite, 0,
                                       kAllocSize, false, &working));
  working->set_user_id(ZX_KOID_KERNEL);

  uint8_t bits = 0xFF;
  // Fresh clone: nothing dirty.
  ASSERT_EQ(ZX_OK, working->QueryDirtyPages(0, kAllocSize, &bits, sizeof(bits)));
  EXPECT_EQ(0u, bits);

  // Dirty pages 1, 3, and 7.
  ASSERT_EQ(ZX_OK, poke(working, 1, 0xA1));
  ASSERT_EQ(ZX_OK, poke(working, 3, 0xA3));
  ASSERT_EQ(ZX_OK, poke(working, 7, 0xA7));
  ASSERT_EQ(ZX_OK, working->QueryDirtyPages(0, kAllocSize, &bits, sizeof(bits)));
  EXPECT_EQ(static_cast<uint8_t>((1u << 1) | (1u << 3) | (1u << 7)), bits);

  // A too-small buffer is rejected.
  EXPECT_EQ(ZX_ERR_BUFFER_TOO_SMALL, working->QueryDirtyPages(0, kAllocSize, &bits, 0));

  // After restore, the dirty set is empty again.
  ASSERT_EQ(ZX_OK, working->SnapshotRestoreRange(0, kAllocSize));
  bits = 0xFF;
  ASSERT_EQ(ZX_OK, working->QueryDirtyPages(0, kAllocSize, &bits, sizeof(bits)));
  EXPECT_EQ(0u, bits);

  // A VMO with no parent (not a clone) is unsupported.
  fbl::RefPtr<VmObjectPaged> standalone;
  ASSERT_EQ(ZX_OK, VmObjectPaged::Create(PMM_ALLOC_FLAG_ANY, 0, kPageSize, &standalone));
  EXPECT_EQ(ZX_ERR_NOT_SUPPORTED, standalone->QueryDirtyPages(0, kPageSize, &bits, sizeof(bits)));

  END_TEST;
}

UNITTEST_START_TESTCASE(vmo_snapshot_tests)
VM_UNITTEST(vmo_snapshot_smoke_test)
VM_UNITTEST(vmo_snapshot_characterize_test)
VM_UNITTEST(vmo_snapshot_restore_test)
VM_UNITTEST(vmo_snapshot_restore_partial_test)
VM_UNITTEST(vmo_snapshot_restore_pinned_test)
VM_UNITTEST(vmo_snapshot_restore_op_dispatch_test)
VM_UNITTEST(vmo_snapshot_fork_test)
VM_UNITTEST(vmo_snapshot_checkpoint_test)
VM_UNITTEST(vmo_snapshot_restore_pager_test)
VM_UNITTEST(vmo_snapshot_checkpoint_incremental_test)
VM_UNITTEST(vmo_snapshot_checkpoint_incremental_refork_test)
VM_UNITTEST(vmo_snapshot_checkpoint_incremental_siblings_test)
VM_UNITTEST(vmo_snapshot_dirty_query_test)
UNITTEST_END_TESTCASE(vmo_snapshot_tests, "vmo_snapshot", "VMO snapshot/restore tests")

}  // namespace

}  // namespace vm_unittest

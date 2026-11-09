// Copyright 2026 The Fuchsia Authors
//
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT

// Decisive positive guest-entry test.
//
// The rest of the in-kernel hypervisor suite (hypervisor_unittest.cc) exercises
// only the second-level address-space *structures* (GuestPhysicalAspace / EPT
// page tables); nothing there performs a VMLAUNCH. This test does: it builds a
// minimal 64-bit guest, enters it with `Vcpu::Enter`, and asserts that a value
// written by a guest instruction round-trips back out through a trapped I/O
// exit. Its pass/fail is the empirical answer to "can this host actually run a
// guest under the Zircon hypervisor" — which, when the host is itself a
// virtualized guest, is a question of whether nested VMLAUNCH works one level
// deeper.
//
// The guest:
//   * runs in 64-bit long mode (the BSP entry mode set by vmcs_init), CR3 == 0,
//   * uses an identity page-table hierarchy rooted at guest-physical address 0
//     (PML4 -> PDPT -> PD, a single 2 MiB page mapping [0, 2 MiB)),
//   * executes `mov al, 0x42; out 0x10, al` at guest-physical 0x3000.
// A synchronous I/O trap on port 0x10 turns the OUT into a ZX_PKT_TYPE_GUEST_IO
// packet delivered straight back through Enter().

#include <lib/fit/defer.h>
#include <lib/page/size.h>
#include <lib/unittest/unittest.h>
#include <zircon/errors.h>
#include <zircon/syscalls/hypervisor.h>
#include <zircon/syscalls/port.h>
#include <zircon/types.h>

#include <arch/hypervisor.h>
#include <fbl/ref_ptr.h>
#include <hypervisor/aspace.h>
#include <kernel/cpu.h>
#include <kernel/thread.h>
#include <ktl/atomic.h>
#include <ktl/unique_ptr.h>
#include <ktl/utility.h>
#include <object/guest_dispatcher.h>
#include <object/handle.h>
#include <object/vcpu_dispatcher.h>
#include <lib/backtrace/global_cpu_context_exchange.h>
#include <object/vm_address_region_dispatcher.h>
#include <platform/timer.h>
#include <vm/pmm.h>
#include <vm/vm_address_region.h>
#include <vm/vm_object.h>
#include <vm/vm_object_paged.h>

#include "test_helper.h"

#ifdef __x86_64__
#include <arch/x86.h>
#include <arch/x86/apic.h>
#include <arch/x86/feature.h>
#include <arch/x86/perf_mon.h>
#include <arch/x86/registers.h>

// For ValidateGuestXcr0Rules / ValidateXsaveImageRules: the table-driven cases
// below drive the validators directly, against a synthetic machine, because on
// any one part only a fraction of their rules is reachable through the CPU.
#include "vcpu_priv.h"
#include "vmexit_priv.h"
#endif

namespace {

#ifdef __x86_64__

constexpr arch_mmu_flags_t kMmuFlags =
    ARCH_MMU_FLAG_PERM_READ | ARCH_MMU_FLAG_PERM_WRITE | ARCH_MMU_FLAG_PERM_EXECUTE;

// Guest-physical layout within the backing VMO.
constexpr uint64_t kPml4Gpa = 0x0000;
constexpr uint64_t kPdptGpa = 0x1000;
constexpr uint64_t kPdGpa = 0x2000;
constexpr uint64_t kCodeGpa = 0x3000;
constexpr uint64_t kCode2Gpa = 0x3800;      // A second code entry point (for a 2nd guest phase).
constexpr uint64_t kDataGpa = 0x4000;       // A data page the guest dirties then re-reads.
constexpr size_t kGuestRamSize = 0x10000;   // 64 KiB is ample for tables + code + data.
constexpr size_t kBitmapLen = (kGuestRamSize / 4096 + 7) / 8;

// Paging flags.
constexpr uint64_t kPresent = 1u << 0;
constexpr uint64_t kWritable = 1u << 1;
constexpr uint64_t kPageSize2M = 1u << 7;  // PS bit: PDE maps a 2 MiB page.

constexpr uint16_t kTrapPort = 0x10;
constexpr uint8_t kSentinel = 0x42;

#endif  // __x86_64__

bool vcpu_enter_traps_io_write() {
  BEGIN_TEST;

#ifdef __x86_64__
  // Create the guest. Guest::Create() both probes for VMX support and, if
  // present, performs VMXON and configures VMX operation on this CPU. On a host
  // that exposes no (nested) VT-x this returns ZX_ERR_NOT_SUPPORTED, in which
  // case the honest result is to skip rather than to fail.
  auto guest_result = Guest::Create();
  if (guest_result.is_error() && guest_result.status_value() == ZX_ERR_NOT_SUPPORTED) {
    printf("VMX not supported here (no exposed VT-x); skipping guest-entry test.\n");
    return true;
  }
  ASSERT_EQ(ZX_OK, guest_result.status_value(), "Guest::Create failed (VMXON)\n");
  ktl::unique_ptr<Guest> guest = ktl::move(guest_result.value());

  // Allocate and populate guest RAM.
  fbl::RefPtr<VmObjectPaged> vmo;
  ASSERT_EQ(ZX_OK, VmObjectPaged::Create(PMM_ALLOC_FLAG_ANY, 0u, kGuestRamSize, &vmo),
            "create guest RAM VMO\n");

  // Identity-mapped 64-bit page tables. Each table's first entry is enough to
  // cover [0, 2 MiB), which contains both the tables and the code.
  const uint64_t pml4e = kPdptGpa | kPresent | kWritable;
  const uint64_t pdpte = kPdGpa | kPresent | kWritable;
  const uint64_t pde = 0x0 | kPresent | kWritable | kPageSize2M;  // 2 MiB page @ phys 0.
  ASSERT_EQ(ZX_OK, vmo->Write(&pml4e, kPml4Gpa, sizeof(pml4e)), "write PML4\n");
  ASSERT_EQ(ZX_OK, vmo->Write(&pdpte, kPdptGpa, sizeof(pdpte)), "write PDPT\n");
  ASSERT_EQ(ZX_OK, vmo->Write(&pde, kPdGpa, sizeof(pde)), "write PD\n");

  // Guest code at 0x3000:
  //   B0 42     mov al, 0x42
  //   E6 10     out 0x10, al   -> VM exit (unconditional I/O exiting)
  //   F4        hlt            -> unreached; safety net
  const uint8_t code[] = {0xB0, kSentinel, 0xE6, static_cast<uint8_t>(kTrapPort), 0xF4};
  ASSERT_EQ(ZX_OK, vmo->Write(code, kCodeGpa, sizeof(code)), "write guest code\n");

  ASSERT_EQ(ZX_OK, vmo->CommitRange(0, kGuestRamSize), "commit guest RAM\n");

  // Map the RAM at guest-physical 0 in the guest's second-level address space.
  fbl::RefPtr<VmAddressRegion> root_vmar = guest->RootVmar();
  auto mapping = root_vmar->CreateVmMapping(0 /* offset */, kGuestRamSize, 0 /* align_pow2 */,
                                            VMAR_FLAG_SPECIFIC, vmo, 0 /* vmo_offset */, kMmuFlags,
                                            "guest-ram");
  ASSERT_EQ(ZX_OK, mapping.status_value(), "map guest RAM into GPAS\n");

  // Synchronous I/O trap: no port dispatcher, so the exit is delivered straight
  // back through Enter() instead of being queued.
  auto trap = guest->SetTrap(ZX_GUEST_TRAP_IO, kTrapPort, 1 /* len */, nullptr /* port */,
                             0x1234 /* key */);
  ASSERT_EQ(ZX_OK, trap.status_value(), "install I/O trap\n");

  // Create the VCPU with RIP = code entry, then enter the guest.
  auto vcpu_result = Vcpu::Create(*guest, kCodeGpa);
  ASSERT_EQ(ZX_OK, vcpu_result.status_value(), "Vcpu::Create failed\n");
  ktl::unique_ptr<Vcpu> vcpu = ktl::move(vcpu_result.value());

  zx_port_packet_t packet = {};
  auto enter = vcpu->Enter(packet);

  // The headline assertion: entry succeeded and the guest actually executed.
  ASSERT_EQ(ZX_OK, enter.status_value(), "Vcpu::Enter failed (VMLAUNCH / nested entry)\n");
  EXPECT_EQ(static_cast<uint8_t>(ZX_PKT_TYPE_GUEST_IO), static_cast<uint8_t>(packet.type),
            "expected a guest I/O exit\n");
  EXPECT_EQ(kTrapPort, packet.guest_io.port, "wrong trapped port\n");
  EXPECT_EQ(1u, packet.guest_io.access_size, "wrong I/O access size\n");
  EXPECT_FALSE(packet.guest_io.input, "expected an OUT (write), not an IN\n");
  // The sentinel the guest wrote must round-trip back out.
  EXPECT_EQ(kSentinel, packet.guest_io.data[0], "guest-written sentinel did not round-trip\n");

  // Emit visible evidence: this line prints only if VMLAUNCH actually ran guest
  // instructions and the OUT round-tripped, so the pass is observable in the
  // serial log rather than merely asserted.
  printf("guest-entry OK: nested VMLAUNCH ran a 64-bit guest; I/O exit port=%#x value=%#x\n",
         packet.guest_io.port, packet.guest_io.data[0]);
#else
  printf("Not x86_64; skipping guest-entry test.\n");
#endif  // __x86_64__

  END_TEST;
}

// End-to-end validation of the snapshot mechanisms *through a running guest*.
//
// The VMO-layer suite (snapshot_unittest.cc) proves ZX_VMO_OP_REVERT_TO_SNAPSHOT
// and ZX_VMO_OP_QUERY_DIRTY on a plain VMAR mapping. It cannot prove the
// load-bearing guest claim: that reverting the working clone invalidates the
// guest's *second-level* (EPT) translation so the guest itself re-faults from
// the baseline. That requires a live guest, which this test now supplies.
//
// The guest runs on a copy-on-write clone of a golden baseline. It writes a
// sentinel to a data page (forking it), reports the value it sees, exits; the
// host queries the dirty set, reverts the clone in place, and re-enters; the
// guest re-reads the same address and must now observe the baseline.
bool vcpu_guest_ram_snapshot_restore() {
  BEGIN_TEST;

#ifdef __x86_64__
  auto guest_result = Guest::Create();
  if (guest_result.is_error() && guest_result.status_value() == ZX_ERR_NOT_SUPPORTED) {
    printf("VMX not supported here; skipping guest-RAM snapshot/restore test.\n");
    return true;
  }
  ASSERT_EQ(ZX_OK, guest_result.status_value(), "Guest::Create failed\n");
  ktl::unique_ptr<Guest> guest = ktl::move(guest_result.value());

  // Golden baseline: page tables, code, and one data byte.
  fbl::RefPtr<VmObjectPaged> golden;
  ASSERT_EQ(ZX_OK, VmObjectPaged::Create(PMM_ALLOC_FLAG_ANY, 0u, kGuestRamSize, &golden),
            "create golden VMO\n");
  const uint64_t pml4e = kPdptGpa | kPresent | kWritable;
  const uint64_t pdpte = kPdGpa | kPresent | kWritable;
  const uint64_t pde = 0x0 | kPresent | kWritable | kPageSize2M;
  ASSERT_EQ(ZX_OK, golden->Write(&pml4e, kPml4Gpa, sizeof(pml4e)), "write PML4\n");
  ASSERT_EQ(ZX_OK, golden->Write(&pdpte, kPdptGpa, sizeof(pdpte)), "write PDPT\n");
  ASSERT_EQ(ZX_OK, golden->Write(&pde, kPdGpa, sizeof(pde)), "write PD\n");

  // Guest code at 0x3000:
  //   48 BB <0x4000>  mov  rbx, 0x4000
  //   C6 03 BB        mov  byte [rbx], 0xBB   ; write -> CoW fork of the data page
  //   8A 03           mov  al, [rbx]          ; al = value the guest sees
  //   E6 10           out  0x10, al           ; exit #1: report post-write value
  //   8A 03           mov  al, [rbx]          ; (resumed here after host revert)
  //   E6 11           out  0x11, al           ; exit #2: report post-revert value
  //   F4              hlt
  const uint8_t code[] = {
      0x48, 0xBB, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // mov rbx, 0x4000
      0xC6, 0x03, 0xBB,                                            // mov byte [rbx], 0xBB
      0x8A, 0x03,                                                  // mov al, [rbx]
      0xE6, 0x10,                                                  // out 0x10, al
      0x8A, 0x03,                                                  // mov al, [rbx]
      0xE6, 0x11,                                                  // out 0x11, al
      0xF4,                                                        // hlt
  };
  ASSERT_EQ(ZX_OK, golden->Write(code, kCodeGpa, sizeof(code)), "write guest code\n");

  constexpr uint8_t kBaseline = 0xAA;
  constexpr uint8_t kDirtied = 0xBB;
  ASSERT_EQ(ZX_OK, golden->Write(&kBaseline, kDataGpa, sizeof(kBaseline)), "write baseline\n");
  ASSERT_EQ(ZX_OK, golden->CommitRange(0, kGuestRamSize), "commit golden\n");

  // working = copy-on-write clone; the guest runs here, its writes fork away.
  fbl::RefPtr<VmObject> working;
  ASSERT_EQ(ZX_OK,
            golden->CreateClone(Resizability::NonResizable, SnapshotType::OnWrite, 0, kGuestRamSize,
                                false, &working),
            "create working clone\n");
  working->set_user_id(ZX_KOID_KERNEL);

  fbl::RefPtr<VmAddressRegion> root_vmar = guest->RootVmar();
  auto mapping = root_vmar->CreateVmMapping(0, kGuestRamSize, 0, VMAR_FLAG_SPECIFIC, working, 0,
                                            kMmuFlags, "guest-ram");
  ASSERT_EQ(ZX_OK, mapping.status_value(), "map working clone into GPAS\n");

  auto trap1 = guest->SetTrap(ZX_GUEST_TRAP_IO, 0x10, 1, nullptr, 0x10);
  ASSERT_EQ(ZX_OK, trap1.status_value(), "install trap 0x10\n");
  auto trap2 = guest->SetTrap(ZX_GUEST_TRAP_IO, 0x11, 1, nullptr, 0x11);
  ASSERT_EQ(ZX_OK, trap2.status_value(), "install trap 0x11\n");

  auto vcpu_result = Vcpu::Create(*guest, kCodeGpa);
  ASSERT_EQ(ZX_OK, vcpu_result.status_value(), "Vcpu::Create failed\n");
  ktl::unique_ptr<Vcpu> vcpu = ktl::move(vcpu_result.value());

  // Entry #1: the guest writes the sentinel and reports what it reads back.
  zx_port_packet_t p1 = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(p1).status_value(), "Enter #1 failed\n");
  ASSERT_EQ(static_cast<uint8_t>(ZX_PKT_TYPE_GUEST_IO), static_cast<uint8_t>(p1.type),
            "expected I/O exit #1\n");
  EXPECT_EQ(0x10u, p1.guest_io.port, "wrong port on exit #1\n");
  EXPECT_EQ(static_cast<uint32_t>(kDirtied), static_cast<uint32_t>(p1.guest_io.data[0]),
            "guest should read back its own write\n");

  // The guest's write must appear in the kernel dirty query on the clone.
  const uint32_t data_page = static_cast<uint32_t>(kDataGpa / 4096);
  uint8_t dirty[kBitmapLen] = {};
  ASSERT_EQ(ZX_OK, working->QueryDirtyPages(0, kGuestRamSize, dirty, sizeof(dirty)),
            "query dirty (post-write) failed\n");
  EXPECT_TRUE((dirty[data_page / 8] & (1u << (data_page % 8))) != 0,
              "data page must read dirty after the guest wrote it\n");

  // Revert the clone to the golden baseline in place. This must both drop the
  // forked page AND invalidate the guest's EPT for it.
  ASSERT_EQ(ZX_OK, working->SnapshotRestoreRange(0, kGuestRamSize), "SnapshotRestoreRange failed\n");

  // The data page must now read clean.
  uint8_t clean[kBitmapLen] = {};
  ASSERT_EQ(ZX_OK, working->QueryDirtyPages(0, kGuestRamSize, clean, sizeof(clean)),
            "query dirty (post-revert) failed\n");
  EXPECT_TRUE((clean[data_page / 8] & (1u << (data_page % 8))) == 0,
              "data page must read clean after revert\n");

  // Entry #2: the guest re-reads the same address and must now see the baseline
  // — proving the revert reached all the way through the guest's EPT.
  zx_port_packet_t p2 = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(p2).status_value(), "Enter #2 failed\n");
  ASSERT_EQ(static_cast<uint8_t>(ZX_PKT_TYPE_GUEST_IO), static_cast<uint8_t>(p2.type),
            "expected I/O exit #2\n");
  EXPECT_EQ(0x11u, p2.guest_io.port, "wrong port on exit #2\n");
  EXPECT_EQ(static_cast<uint32_t>(kBaseline), static_cast<uint32_t>(p2.guest_io.data[0]),
            "guest must observe the baseline after in-kernel revert\n");

  printf("guest-RAM snapshot/restore OK: guest wrote %#x and read it back; after in-kernel "
         "revert the guest re-read %#x (baseline)\n",
         kDirtied, p2.guest_io.data[0]);
#else
  printf("Not x86_64; skipping.\n");
#endif  // __x86_64__

  END_TEST;
}

// Writes the identity 64-bit page-table hierarchy (PML4 -> PDPT -> 2 MiB PD)
// into `vmo` at GPA 0.
zx_status_t WriteIdentityTables(const fbl::RefPtr<VmObjectPaged>& vmo) {
  const uint64_t pml4e = kPdptGpa | kPresent | kWritable;
  const uint64_t pdpte = kPdGpa | kPresent | kWritable;
  const uint64_t pde = 0x0 | kPresent | kWritable | kPageSize2M;
  if (zx_status_t s = vmo->Write(&pml4e, kPml4Gpa, sizeof(pml4e)); s != ZX_OK) {
    return s;
  }
  if (zx_status_t s = vmo->Write(&pdpte, kPdptGpa, sizeof(pdpte)); s != ZX_OK) {
    return s;
  }
  return vmo->Write(&pde, kPdGpa, sizeof(pde));
}

// Spins up a fresh guest on `ram` mapped at GPA 0, enters at `entry`, and runs
// until the first I/O exit; returns that packet. The guest and vcpu are torn
// down before returning (single-shot). Ports 0x10 and 0x11 are trapped.
zx::result<zx_port_packet_t> RunGuestToFirstIo(const fbl::RefPtr<VmObject>& ram, uint64_t entry) {
  auto guest_result = Guest::Create();
  if (guest_result.is_error()) {
    return guest_result.take_error();
  }
  ktl::unique_ptr<Guest> guest = ktl::move(guest_result.value());
  auto mapping = guest->RootVmar()->CreateVmMapping(0, kGuestRamSize, 0, VMAR_FLAG_SPECIFIC, ram, 0,
                                                    kMmuFlags, "guest-ram");
  if (mapping.is_error()) {
    return mapping.take_error();
  }
  if (auto t = guest->SetTrap(ZX_GUEST_TRAP_IO, 0x10, 1, nullptr, 0x10); t.is_error()) {
    return t.take_error();
  }
  if (auto t = guest->SetTrap(ZX_GUEST_TRAP_IO, 0x11, 1, nullptr, 0x11); t.is_error()) {
    return t.take_error();
  }
  auto vcpu_result = Vcpu::Create(*guest, entry);
  if (vcpu_result.is_error()) {
    return vcpu_result.take_error();
  }
  ktl::unique_ptr<Vcpu> vcpu = ktl::move(vcpu_result.value());
  zx_port_packet_t packet = {};
  if (auto e = vcpu->Enter(packet); e.is_error()) {
    return e.take_error();
  }
  return zx::ok(packet);
}

// fork(): two sibling CoW clones of one golden baseline are independent — a
// write made by a guest running on one clone is invisible to a guest running on
// the sibling. This is the fork isolation property, validated through EPT.
bool vcpu_fork_sibling_isolation() {
  BEGIN_TEST;

#ifdef __x86_64__
  {
    auto probe = Guest::Create();
    if (probe.is_error() && probe.status_value() == ZX_ERR_NOT_SUPPORTED) {
      printf("VMX not supported here; skipping fork test.\n");
      return true;
    }
    ASSERT_EQ(ZX_OK, probe.status_value(), "Guest::Create failed\n");
  }

  fbl::RefPtr<VmObjectPaged> golden;
  ASSERT_EQ(ZX_OK, VmObjectPaged::Create(PMM_ALLOC_FLAG_ANY, 0u, kGuestRamSize, &golden),
            "create golden\n");
  ASSERT_EQ(ZX_OK, WriteIdentityTables(golden), "write tables\n");
  // Code A @0x3000: write 0xB0 to the data page and report it.
  const uint8_t code_write[] = {0x48, 0xBB, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                0xC6, 0x03, 0xB0, 0x8A, 0x03, 0xE6, 0x10, 0xF4};
  // Code B @0x3800: read-only — just report whatever the data page holds.
  const uint8_t code_read[] = {0x48, 0xBB, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                               0x8A, 0x03, 0xE6, 0x10, 0xF4};
  ASSERT_EQ(ZX_OK, golden->Write(code_write, kCodeGpa, sizeof(code_write)), "write codeA\n");
  ASSERT_EQ(ZX_OK, golden->Write(code_read, kCode2Gpa, sizeof(code_read)), "write codeB\n");
  constexpr uint8_t kBaseline = 0xAA;
  ASSERT_EQ(ZX_OK, golden->Write(&kBaseline, kDataGpa, sizeof(kBaseline)), "write baseline\n");
  ASSERT_EQ(ZX_OK, golden->CommitRange(0, kGuestRamSize), "commit golden\n");

  fbl::RefPtr<VmObject> working_a, working_b;
  ASSERT_EQ(ZX_OK,
            golden->CreateClone(Resizability::NonResizable, SnapshotType::OnWrite, 0, kGuestRamSize,
                                false, &working_a),
            "clone A\n");
  working_a->set_user_id(ZX_KOID_KERNEL);
  ASSERT_EQ(ZX_OK,
            golden->CreateClone(Resizability::NonResizable, SnapshotType::OnWrite, 0, kGuestRamSize,
                                false, &working_b),
            "clone B\n");
  working_b->set_user_id(ZX_KOID_KERNEL);

  // Guest A writes 0xB0 to its own clone.
  auto ra = RunGuestToFirstIo(working_a, kCodeGpa);
  ASSERT_EQ(ZX_OK, ra.status_value(), "run guest A\n");
  EXPECT_EQ(0xB0u, static_cast<uint32_t>(ra.value().guest_io.data[0]), "guest A sees its write\n");

  // Guest B, on the sibling clone, must still observe the untouched baseline.
  auto rb = RunGuestToFirstIo(working_b, kCode2Gpa);
  ASSERT_EQ(ZX_OK, rb.status_value(), "run guest B\n");
  EXPECT_EQ(0xAAu, static_cast<uint32_t>(rb.value().guest_io.data[0]),
            "sibling clone must be unaffected by guest A's write\n");

  printf("fork OK: guest A wrote 0xb0 to its clone; sibling guest B still read 0xaa (baseline)\n");
#else
  printf("Not x86_64; skipping.\n");
#endif  // __x86_64__

  END_TEST;
}

// checkpoint(): after re-baselining a running clone (a full snapshot of its
// current state), a later revert returns to the *checkpoint*, not to the
// original image. Validated through guests: guest 1 dirties to 0xCC, we
// checkpoint, guest 2 dirties to 0xDD then reverts and must read 0xCC (the
// checkpoint) — never 0xAA (the original baseline).
bool vcpu_checkpoint_rebaseline() {
  BEGIN_TEST;

#ifdef __x86_64__
  {
    auto probe = Guest::Create();
    if (probe.is_error() && probe.status_value() == ZX_ERR_NOT_SUPPORTED) {
      printf("VMX not supported here; skipping checkpoint test.\n");
      return true;
    }
    ASSERT_EQ(ZX_OK, probe.status_value(), "Guest::Create failed\n");
  }

  fbl::RefPtr<VmObjectPaged> golden;
  ASSERT_EQ(ZX_OK, VmObjectPaged::Create(PMM_ALLOC_FLAG_ANY, 0u, kGuestRamSize, &golden),
            "create golden\n");
  ASSERT_EQ(ZX_OK, WriteIdentityTables(golden), "write tables\n");
  // Phase-1 code @0x3000: write 0xCC and report it (this becomes the checkpoint).
  const uint8_t code_p1[] = {0x48, 0xBB, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                             0xC6, 0x03, 0xCC, 0x8A, 0x03, 0xE6, 0x10, 0xF4};
  // Phase-2 code @0x3800: write 0xDD (out 0x10), then re-read (out 0x11).
  const uint8_t code_p2[] = {0x48, 0xBB, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                             0xC6, 0x03, 0xDD, 0x8A, 0x03, 0xE6, 0x10,
                             0x8A, 0x03, 0xE6, 0x11, 0xF4};
  ASSERT_EQ(ZX_OK, golden->Write(code_p1, kCodeGpa, sizeof(code_p1)), "write phase1 code\n");
  ASSERT_EQ(ZX_OK, golden->Write(code_p2, kCode2Gpa, sizeof(code_p2)), "write phase2 code\n");
  constexpr uint8_t kOriginal = 0xAA;
  ASSERT_EQ(ZX_OK, golden->Write(&kOriginal, kDataGpa, sizeof(kOriginal)), "write baseline\n");
  ASSERT_EQ(ZX_OK, golden->CommitRange(0, kGuestRamSize), "commit golden\n");

  fbl::RefPtr<VmObject> working;
  ASSERT_EQ(ZX_OK,
            golden->CreateClone(Resizability::NonResizable, SnapshotType::OnWrite, 0, kGuestRamSize,
                                false, &working),
            "clone working\n");
  working->set_user_id(ZX_KOID_KERNEL);

  // Phase 1: a guest dirties the working clone to 0xCC.
  auto r1 = RunGuestToFirstIo(working, kCodeGpa);
  ASSERT_EQ(ZX_OK, r1.status_value(), "run phase-1 guest\n");
  EXPECT_EQ(0xCCu, static_cast<uint32_t>(r1.value().guest_io.data[0]), "phase-1 write\n");

  // Checkpoint: full snapshot of the working clone's current state becomes the
  // new baseline; a fresh working clone rides on top of it.
  fbl::RefPtr<VmObject> checkpoint;
  ASSERT_EQ(ZX_OK,
            working->CreateClone(Resizability::NonResizable, SnapshotType::Full, 0, kGuestRamSize,
                                 false, &checkpoint),
            "create checkpoint (full snapshot)\n");
  checkpoint->set_user_id(ZX_KOID_KERNEL);
  fbl::RefPtr<VmObject> working2;
  ASSERT_EQ(ZX_OK,
            checkpoint->CreateClone(Resizability::NonResizable, SnapshotType::OnWrite, 0,
                                    kGuestRamSize, false, &working2),
            "clone post-checkpoint working\n");
  working2->set_user_id(ZX_KOID_KERNEL);

  // Phase 2: a guest on the post-checkpoint clone writes 0xDD, then we revert
  // and re-enter — it must read the checkpoint (0xCC), not the original (0xAA).
  auto guest_result = Guest::Create();
  ASSERT_EQ(ZX_OK, guest_result.status_value(), "create phase-2 guest\n");
  ktl::unique_ptr<Guest> guest = ktl::move(guest_result.value());
  auto mapping = guest->RootVmar()->CreateVmMapping(0, kGuestRamSize, 0, VMAR_FLAG_SPECIFIC,
                                                    working2, 0, kMmuFlags, "guest-ram");
  ASSERT_EQ(ZX_OK, mapping.status_value(), "map working2\n");
  auto t1 = guest->SetTrap(ZX_GUEST_TRAP_IO, 0x10, 1, nullptr, 0x10);
  ASSERT_EQ(ZX_OK, t1.status_value(), "trap 0x10\n");
  auto t2 = guest->SetTrap(ZX_GUEST_TRAP_IO, 0x11, 1, nullptr, 0x11);
  ASSERT_EQ(ZX_OK, t2.status_value(), "trap 0x11\n");
  auto vcpu_result = Vcpu::Create(*guest, kCode2Gpa);
  ASSERT_EQ(ZX_OK, vcpu_result.status_value(), "Vcpu::Create phase-2\n");
  ktl::unique_ptr<Vcpu> vcpu = ktl::move(vcpu_result.value());

  zx_port_packet_t pd = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(pd).status_value(), "phase-2 Enter #1\n");
  EXPECT_EQ(0x10u, pd.guest_io.port, "phase-2 port #1\n");
  EXPECT_EQ(0xDDu, static_cast<uint32_t>(pd.guest_io.data[0]), "phase-2 write\n");

  ASSERT_EQ(ZX_OK, working2->SnapshotRestoreRange(0, kGuestRamSize), "revert to checkpoint\n");

  zx_port_packet_t pc = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(pc).status_value(), "phase-2 Enter #2\n");
  EXPECT_EQ(0x11u, pc.guest_io.port, "phase-2 port #2\n");
  EXPECT_EQ(0xCCu, static_cast<uint32_t>(pc.guest_io.data[0]),
            "revert must return to the checkpoint (0xCC), not the original (0xAA)\n");

  printf("checkpoint OK: re-baselined at 0xcc; after guest wrote 0xdd + revert, guest re-read "
         "0x%x (checkpoint, not original 0xaa)\n",
         pc.guest_io.data[0]);
#else
  printf("Not x86_64; skipping.\n");
#endif  // __x86_64__

  END_TEST;
}

// Discriminating experiment for incremental checkpoint: does a guest CoW-write,
// through EPT, fork an OnWrite clone whose *root is pager-backed* (the
// unidirectional clone shape SNAPSHOT_MODIFIED requires)? This intersection —
// second-level-translation CoW fork on a pager-rooted clone — is the one thing
// the anonymous-clone tests above never exercise, and the reason incremental
// checkpoint through a guest was previously deferred. If this passes, the full
// SNAPSHOT_MODIFIED incremental test below is mechanical.
bool vcpu_pager_backed_clone_forks() {
  BEGIN_TEST;

#ifdef __x86_64__
  {
    auto probe = Guest::Create();
    if (probe.is_error() && probe.status_value() == ZX_ERR_NOT_SUPPORTED) {
      printf("VMX not supported here; skipping pager-backed clone test.\n");
      return true;
    }
    ASSERT_EQ(ZX_OK, probe.status_value(), "Guest::Create failed\n");
  }

  // Pager-backed golden: this makes the OnWrite clone *unidirectional*.
  constexpr size_t kNumPages = kGuestRamSize / 4096;
  fbl::RefPtr<VmObjectPaged> golden;
  ASSERT_EQ(ZX_OK,
            vm_unittest::make_committed_pager_vmo(kNumPages, /*trap_dirty=*/false,
                                                  /*resizable=*/false, nullptr, &golden),
            "create pager-backed golden\n");
  golden->set_user_id(ZX_KOID_KERNEL);
  ASSERT_EQ(ZX_OK, WriteIdentityTables(golden), "write tables\n");
  // Code @0x3000: write 0xBB to the data page and report it.
  const uint8_t code[] = {0x48, 0xBB, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                          0xC6, 0x03, 0xBB, 0x8A, 0x03, 0xE6, 0x10, 0xF4};
  ASSERT_EQ(ZX_OK, golden->Write(code, kCodeGpa, sizeof(code)), "write code\n");
  constexpr uint8_t kBaseline = 0xAA;
  ASSERT_EQ(ZX_OK, golden->Write(&kBaseline, kDataGpa, sizeof(kBaseline)), "write baseline\n");

  fbl::RefPtr<VmObject> working;
  ASSERT_EQ(ZX_OK,
            golden->CreateClone(Resizability::NonResizable, SnapshotType::OnWrite, 0, kGuestRamSize,
                                false, &working),
            "create unidirectional working clone\n");
  working->set_user_id(ZX_KOID_KERNEL);

  // Run a guest on the pager-rooted clone. This exercises *both* read fault-in
  // (code fetch + page-table walk served from the pager-backed parent through
  // the clone) and the write CoW fork we are actually interrogating.
  auto r = RunGuestToFirstIo(working, kCodeGpa);
  ASSERT_EQ(ZX_OK, r.status_value(), "guest on pager-rooted clone failed to run\n");
  EXPECT_EQ(0xBBu, static_cast<uint32_t>(r.value().guest_io.data[0]),
            "guest should read back its own write\n");

  // The discriminating assertion: the write must have forked the clone.
  const uint32_t data_page = static_cast<uint32_t>(kDataGpa / 4096);
  uint8_t dirty[kBitmapLen] = {};
  ASSERT_EQ(ZX_OK, working->QueryDirtyPages(0, kGuestRamSize, dirty, sizeof(dirty)),
            "query dirty on pager-rooted clone\n");
  EXPECT_TRUE((dirty[data_page / 8] & (1u << (data_page % 8))) != 0,
              "guest write must fork the pager-backed-rooted clone through EPT\n");

  printf("pager-backed clone fork OK: guest CoW-write through EPT forked the unidirectional "
         "(pager-rooted) clone\n");
#else
  printf("Not x86_64; skipping.\n");
#endif  // __x86_64__

  END_TEST;
}

// Incremental checkpoint through a guest: the O(pages-changed) form. Same shape
// as the full-checkpoint test, but the golden is pager-backed and the re-baseline
// uses SnapshotType::Modified (which Zircon permits only on a pager-rooted, i.e.
// unidirectional, clone). Guest 1 dirties to 0xCC; we take a SNAPSHOT_MODIFIED
// checkpoint; guest 2 dirties to 0xDD, reverts, and must read the checkpoint
// (0xCC), never the original (0xAA). Closes the last snapshot mechanism that had
// only VMO-layer coverage.
bool vcpu_incremental_checkpoint_rebaseline() {
  BEGIN_TEST;

#ifdef __x86_64__
  {
    auto probe = Guest::Create();
    if (probe.is_error() && probe.status_value() == ZX_ERR_NOT_SUPPORTED) {
      printf("VMX not supported here; skipping incremental checkpoint test.\n");
      return true;
    }
    ASSERT_EQ(ZX_OK, probe.status_value(), "Guest::Create failed\n");
  }

  // Pager-backed golden -> the clones below are unidirectional, the shape
  // SNAPSHOT_MODIFIED requires.
  constexpr size_t kNumPages = kGuestRamSize / 4096;
  fbl::RefPtr<VmObjectPaged> golden;
  ASSERT_EQ(ZX_OK,
            vm_unittest::make_committed_pager_vmo(kNumPages, /*trap_dirty=*/false,
                                                  /*resizable=*/false, nullptr, &golden),
            "create pager-backed golden\n");
  golden->set_user_id(ZX_KOID_KERNEL);
  ASSERT_EQ(ZX_OK, WriteIdentityTables(golden), "write tables\n");
  const uint8_t code_p1[] = {0x48, 0xBB, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                             0xC6, 0x03, 0xCC, 0x8A, 0x03, 0xE6, 0x10, 0xF4};
  const uint8_t code_p2[] = {0x48, 0xBB, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                             0xC6, 0x03, 0xDD, 0x8A, 0x03, 0xE6, 0x10,
                             0x8A, 0x03, 0xE6, 0x11, 0xF4};
  ASSERT_EQ(ZX_OK, golden->Write(code_p1, kCodeGpa, sizeof(code_p1)), "write phase1 code\n");
  ASSERT_EQ(ZX_OK, golden->Write(code_p2, kCode2Gpa, sizeof(code_p2)), "write phase2 code\n");
  constexpr uint8_t kOriginal = 0xAA;
  ASSERT_EQ(ZX_OK, golden->Write(&kOriginal, kDataGpa, sizeof(kOriginal)), "write baseline\n");

  fbl::RefPtr<VmObject> working;
  ASSERT_EQ(ZX_OK,
            golden->CreateClone(Resizability::NonResizable, SnapshotType::OnWrite, 0, kGuestRamSize,
                                false, &working),
            "clone working\n");
  working->set_user_id(ZX_KOID_KERNEL);

  // Phase 1: guest dirties to 0xCC.
  auto r1 = RunGuestToFirstIo(working, kCodeGpa);
  ASSERT_EQ(ZX_OK, r1.status_value(), "run phase-1 guest\n");
  EXPECT_EQ(0xCCu, static_cast<uint32_t>(r1.value().guest_io.data[0]), "phase-1 write\n");

  // Incremental checkpoint: SNAPSHOT_MODIFIED captures only the changed pages.
  fbl::RefPtr<VmObject> checkpoint;
  ASSERT_EQ(ZX_OK,
            working->CreateClone(Resizability::NonResizable, SnapshotType::Modified, 0,
                                 kGuestRamSize, false, &checkpoint),
            "create incremental (SNAPSHOT_MODIFIED) checkpoint\n");
  checkpoint->set_user_id(ZX_KOID_KERNEL);
  fbl::RefPtr<VmObject> working2;
  ASSERT_EQ(ZX_OK,
            checkpoint->CreateClone(Resizability::NonResizable, SnapshotType::OnWrite, 0,
                                    kGuestRamSize, false, &working2),
            "clone post-checkpoint working\n");
  working2->set_user_id(ZX_KOID_KERNEL);

  // Phase 2: guest writes 0xDD, host reverts, guest must read 0xCC (checkpoint).
  auto guest_result = Guest::Create();
  ASSERT_EQ(ZX_OK, guest_result.status_value(), "create phase-2 guest\n");
  ktl::unique_ptr<Guest> guest = ktl::move(guest_result.value());
  auto mapping = guest->RootVmar()->CreateVmMapping(0, kGuestRamSize, 0, VMAR_FLAG_SPECIFIC,
                                                    working2, 0, kMmuFlags, "guest-ram");
  ASSERT_EQ(ZX_OK, mapping.status_value(), "map working2\n");
  auto t1 = guest->SetTrap(ZX_GUEST_TRAP_IO, 0x10, 1, nullptr, 0x10);
  ASSERT_EQ(ZX_OK, t1.status_value(), "trap 0x10\n");
  auto t2 = guest->SetTrap(ZX_GUEST_TRAP_IO, 0x11, 1, nullptr, 0x11);
  ASSERT_EQ(ZX_OK, t2.status_value(), "trap 0x11\n");
  auto vcpu_result = Vcpu::Create(*guest, kCode2Gpa);
  ASSERT_EQ(ZX_OK, vcpu_result.status_value(), "Vcpu::Create phase-2\n");
  ktl::unique_ptr<Vcpu> vcpu = ktl::move(vcpu_result.value());

  zx_port_packet_t pd = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(pd).status_value(), "phase-2 Enter #1\n");
  EXPECT_EQ(0xDDu, static_cast<uint32_t>(pd.guest_io.data[0]), "phase-2 write\n");

  ASSERT_EQ(ZX_OK, working2->SnapshotRestoreRange(0, kGuestRamSize), "revert to checkpoint\n");

  zx_port_packet_t pc = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(pc).status_value(), "phase-2 Enter #2\n");
  EXPECT_EQ(0xCCu, static_cast<uint32_t>(pc.guest_io.data[0]),
            "revert must return to the incremental checkpoint (0xCC), not the original (0xAA)\n");

  printf("incremental checkpoint OK: SNAPSHOT_MODIFIED re-baseline on a pager-rooted clone; after "
         "guest wrote 0xdd + revert, guest re-read 0x%x (checkpoint, not original 0xaa)\n",
         pc.guest_io.data[0]);
#else
  printf("Not x86_64; skipping.\n");
#endif  // __x86_64__

  END_TEST;
}

// vCPU-state save/restore, proven by execution determinism. The property that
// matters is not "the guest ran after I wrote some registers" but "a captured
// state fully determines subsequent execution": run to a point, snapshot, run
// on to produce output B, restore the snapshot, run again, and observe the
// identical B. This specifically exercises RIP save/restore — without it, the
// replayed run would resume at the wrong instruction and not reproduce B.
bool vcpu_state_snapshot_determinism() {
  BEGIN_TEST;

#ifdef __x86_64__
  auto guest_result = Guest::Create();
  if (guest_result.is_error() && guest_result.status_value() == ZX_ERR_NOT_SUPPORTED) {
    printf("VMX not supported here; skipping vcpu-state determinism test.\n");
    return true;
  }
  ASSERT_EQ(ZX_OK, guest_result.status_value(), "Guest::Create failed\n");
  ktl::unique_ptr<Guest> guest = ktl::move(guest_result.value());

  fbl::RefPtr<VmObjectPaged> golden;
  ASSERT_EQ(ZX_OK, VmObjectPaged::Create(PMM_ALLOC_FLAG_ANY, 0u, kGuestRamSize, &golden),
            "create golden\n");
  ASSERT_EQ(ZX_OK, WriteIdentityTables(golden), "write tables\n");
  // Code @0x3000:
  //   88 D8      mov al, bl        ; report rbx low byte
  //   E6 10      out 0x10, al      ; exit A (rbx as loaded)
  //   48 FF C3   inc rbx           ; deterministic mutation
  //   88 D8      mov al, bl
  //   E6 11      out 0x11, al      ; exit B (rbx+1)
  //   F4         hlt
  const uint8_t code[] = {0x88, 0xD8, 0xE6, 0x10, 0x48, 0xFF, 0xC3,
                          0x88, 0xD8, 0xE6, 0x11, 0xF4};
  ASSERT_EQ(ZX_OK, golden->Write(code, kCodeGpa, sizeof(code)), "write code\n");
  ASSERT_EQ(ZX_OK, golden->CommitRange(0, kGuestRamSize), "commit golden\n");

  fbl::RefPtr<VmObject> working;
  ASSERT_EQ(ZX_OK,
            golden->CreateClone(Resizability::NonResizable, SnapshotType::OnWrite, 0, kGuestRamSize,
                                false, &working),
            "clone working\n");
  working->set_user_id(ZX_KOID_KERNEL);
  auto mapping = guest->RootVmar()->CreateVmMapping(0, kGuestRamSize, 0, VMAR_FLAG_SPECIFIC,
                                                    working, 0, kMmuFlags, "guest-ram");
  ASSERT_EQ(ZX_OK, mapping.status_value(), "map guest RAM\n");
  auto t1 = guest->SetTrap(ZX_GUEST_TRAP_IO, 0x10, 1, nullptr, 0x10);
  ASSERT_EQ(ZX_OK, t1.status_value(), "trap 0x10\n");
  auto t2 = guest->SetTrap(ZX_GUEST_TRAP_IO, 0x11, 1, nullptr, 0x11);
  ASSERT_EQ(ZX_OK, t2.status_value(), "trap 0x11\n");

  auto vcpu_result = Vcpu::Create(*guest, kCodeGpa);
  ASSERT_EQ(ZX_OK, vcpu_result.status_value(), "Vcpu::Create failed\n");
  ktl::unique_ptr<Vcpu> vcpu = ktl::move(vcpu_result.value());

  // Seed rbx = 0x40 via the general-register write path.
  zx_vcpu_state_t init = {};
  init.rbx = 0x40;
  ASSERT_EQ(ZX_OK, vcpu->WriteState(init).status_value(), "seed rbx\n");

  // Run to exit A: guest reports rbx (0x40); RIP now sits at `inc rbx`.
  zx_port_packet_t a = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(a).status_value(), "Enter to A\n");
  ASSERT_EQ(0x10u, a.guest_io.port, "exit A port\n");
  EXPECT_EQ(0x40u, static_cast<uint32_t>(a.guest_io.data[0]), "exit A value\n");

  // Snapshot the full architectural state here (the point just before `inc`).
  VcpuArchState snap = {};
  ASSERT_EQ(ZX_OK, vcpu->SaveArchState(snap).status_value(), "SaveArchState\n");
  EXPECT_EQ(0x40u, static_cast<uint32_t>(snap.regs.rbx), "snapshot captured rbx\n");

  // Run on to exit B: inc -> 0x41, reported at port 0x11.
  zx_port_packet_t b = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(b).status_value(), "Enter to B\n");
  ASSERT_EQ(0x11u, b.guest_io.port, "exit B port\n");
  EXPECT_EQ(0x41u, static_cast<uint32_t>(b.guest_io.data[0]), "exit B value\n");

  // Restore the snapshot: RIP goes back to `inc`, rbx back to 0x40.
  ASSERT_EQ(ZX_OK, vcpu->RestoreArchState(snap).status_value(), "RestoreArchState\n");

  // Replay from the restored state: it must deterministically reproduce exit B.
  // If RIP were not restored, the guest would resume at `hlt` and never reach
  // this exit.
  zx_port_packet_t b2 = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(b2).status_value(), "Enter to B' (replay)\n");
  ASSERT_EQ(0x11u, b2.guest_io.port, "replay port\n");
  EXPECT_EQ(0x41u, static_cast<uint32_t>(b2.guest_io.data[0]),
            "replay must reproduce exit B (0x41) from the restored state\n");

  printf("vcpu-state snapshot OK: captured before inc (rbx=0x40); first run produced 0x%x, and "
         "after RIP+GPR restore the replay reproduced 0x%x at port 0x11\n",
         b.guest_io.data[0], b2.guest_io.data[0]);
#else
  printf("Not x86_64; skipping.\n");
#endif  // __x86_64__

  END_TEST;
}

// Control-register + segment-base save/restore. Two checks, both non-vacuous:
//   1. SaveArchState captures live 64-bit-mode control state — paging on
//      (CR0.PG), PAE on (CR4.PAE), long mode active (EFER.LMA).
//   2. RestoreArchState *injects* a GS base the guest then reads through: the
//      host sets gs_base to a data page holding a sentinel, and the guest's
//      `mov al, gs:[0]` returns that sentinel — proving the segment-base write
//      reaches the guest, not just the struct.
bool vcpu_state_control_and_segment_base() {
  BEGIN_TEST;

#ifdef __x86_64__
  auto guest_result = Guest::Create();
  if (guest_result.is_error() && guest_result.status_value() == ZX_ERR_NOT_SUPPORTED) {
    printf("VMX not supported here; skipping control/segment-state test.\n");
    return true;
  }
  ASSERT_EQ(ZX_OK, guest_result.status_value(), "Guest::Create failed\n");
  ktl::unique_ptr<Guest> guest = ktl::move(guest_result.value());

  constexpr uint64_t kGsDataGpa = 0x5000;  // A data page reachable via an injected GS base.
  constexpr uint8_t kSentinel = 0x77;

  fbl::RefPtr<VmObjectPaged> golden;
  ASSERT_EQ(ZX_OK, VmObjectPaged::Create(PMM_ALLOC_FLAG_ANY, 0u, kGuestRamSize, &golden),
            "create golden\n");
  ASSERT_EQ(ZX_OK, WriteIdentityTables(golden), "write tables\n");
  // Code @0x3000:
  //   B0 01                        mov al, 1
  //   E6 10                        out 0x10, al      ; marker exit
  //   65 A0 00 00 00 00 00 00 00 00  mov al, gs:[0]  ; al = [gs_base + 0]
  //   E6 11                        out 0x11, al      ; report byte read via GS
  //   F4                           hlt
  const uint8_t code[] = {0xB0, 0x01, 0xE6, 0x10,
                          0x65, 0xA0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                          0xE6, 0x11, 0xF4};
  ASSERT_EQ(ZX_OK, golden->Write(code, kCodeGpa, sizeof(code)), "write code\n");
  ASSERT_EQ(ZX_OK, golden->Write(&kSentinel, kGsDataGpa, sizeof(kSentinel)), "write sentinel\n");
  ASSERT_EQ(ZX_OK, golden->CommitRange(0, kGuestRamSize), "commit golden\n");

  fbl::RefPtr<VmObject> working;
  ASSERT_EQ(ZX_OK,
            golden->CreateClone(Resizability::NonResizable, SnapshotType::OnWrite, 0, kGuestRamSize,
                                false, &working),
            "clone working\n");
  working->set_user_id(ZX_KOID_KERNEL);
  auto mapping = guest->RootVmar()->CreateVmMapping(0, kGuestRamSize, 0, VMAR_FLAG_SPECIFIC,
                                                    working, 0, kMmuFlags, "guest-ram");
  ASSERT_EQ(ZX_OK, mapping.status_value(), "map guest RAM\n");
  auto t1 = guest->SetTrap(ZX_GUEST_TRAP_IO, 0x10, 1, nullptr, 0x10);
  ASSERT_EQ(ZX_OK, t1.status_value(), "trap 0x10\n");
  auto t2 = guest->SetTrap(ZX_GUEST_TRAP_IO, 0x11, 1, nullptr, 0x11);
  ASSERT_EQ(ZX_OK, t2.status_value(), "trap 0x11\n");
  auto vcpu_result = Vcpu::Create(*guest, kCodeGpa);
  ASSERT_EQ(ZX_OK, vcpu_result.status_value(), "Vcpu::Create failed\n");
  ktl::unique_ptr<Vcpu> vcpu = ktl::move(vcpu_result.value());

  // Run to the marker exit; RIP now sits at `mov al, gs:[0]`.
  zx_port_packet_t marker = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(marker).status_value(), "Enter to marker\n");
  ASSERT_EQ(0x10u, marker.guest_io.port, "marker port\n");

  // 1. Capture, and confirm the control state is the live 64-bit-mode state.
  VcpuArchState s = {};
  ASSERT_EQ(ZX_OK, vcpu->SaveArchState(s).status_value(), "SaveArchState\n");
  constexpr uint64_t kCr0Pg = 1ull << 31;
  constexpr uint64_t kCr4Pae = 1ull << 5;
  constexpr uint64_t kEferLma = 1ull << 10;
  EXPECT_TRUE((s.cr0 & kCr0Pg) != 0, "CR0.PG must be captured set (paging on)\n");
  EXPECT_TRUE((s.cr4 & kCr4Pae) != 0, "CR4.PAE must be captured set\n");
  EXPECT_TRUE((s.efer & kEferLma) != 0, "EFER.LMA must be captured set (long mode)\n");

  // 2. Inject a GS base and prove the guest reads through it.
  s.gs.base = kGsDataGpa;
  ASSERT_EQ(ZX_OK, vcpu->RestoreArchState(s).status_value(), "RestoreArchState\n");

  zx_port_packet_t read = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(read).status_value(), "Enter to GS read\n");
  ASSERT_EQ(0x11u, read.guest_io.port, "GS-read port\n");
  EXPECT_EQ(static_cast<uint32_t>(kSentinel), static_cast<uint32_t>(read.guest_io.data[0]),
            "guest must read the sentinel through the injected GS base\n");

  printf("vcpu control/segment-state OK: captured CR0.PG/CR4.PAE/EFER.LMA; injected gs_base and "
         "the guest read 0x%x through gs:[0]\n",
         read.guest_io.data[0]);
#else
  printf("Not x86_64; skipping.\n");
#endif  // __x86_64__

  END_TEST;
}

// Complete VCPU serialization: capture the full architectural state, serialize
// it to a flat byte buffer, deserialize a fresh copy, and prove (a) the buffer
// round-trips byte-for-byte and (b) restoring from the deserialized copy resumes
// the guest deterministically. This is the save-a-snapshot-to-a-blob path.
bool vcpu_full_state_serialization_roundtrip() {
  BEGIN_TEST;

#ifdef __x86_64__
  auto guest_result = Guest::Create();
  if (guest_result.is_error() && guest_result.status_value() == ZX_ERR_NOT_SUPPORTED) {
    printf("VMX not supported here; skipping vcpu serialization test.\n");
    return true;
  }
  ASSERT_EQ(ZX_OK, guest_result.status_value(), "Guest::Create failed\n");
  ktl::unique_ptr<Guest> guest = ktl::move(guest_result.value());

  fbl::RefPtr<VmObjectPaged> golden;
  ASSERT_EQ(ZX_OK, VmObjectPaged::Create(PMM_ALLOC_FLAG_ANY, 0u, kGuestRamSize, &golden),
            "create golden\n");
  ASSERT_EQ(ZX_OK, WriteIdentityTables(golden), "write tables\n");
  // Same deterministic guest as the RIP+GPR test: report rbx, inc, report again.
  const uint8_t code[] = {0x88, 0xD8, 0xE6, 0x10, 0x48, 0xFF, 0xC3,
                          0x88, 0xD8, 0xE6, 0x11, 0xF4};
  ASSERT_EQ(ZX_OK, golden->Write(code, kCodeGpa, sizeof(code)), "write code\n");
  ASSERT_EQ(ZX_OK, golden->CommitRange(0, kGuestRamSize), "commit golden\n");

  fbl::RefPtr<VmObject> working;
  ASSERT_EQ(ZX_OK,
            golden->CreateClone(Resizability::NonResizable, SnapshotType::OnWrite, 0, kGuestRamSize,
                                false, &working),
            "clone working\n");
  working->set_user_id(ZX_KOID_KERNEL);
  auto mapping = guest->RootVmar()->CreateVmMapping(0, kGuestRamSize, 0, VMAR_FLAG_SPECIFIC,
                                                    working, 0, kMmuFlags, "guest-ram");
  ASSERT_EQ(ZX_OK, mapping.status_value(), "map guest RAM\n");
  auto t1 = guest->SetTrap(ZX_GUEST_TRAP_IO, 0x10, 1, nullptr, 0x10);
  ASSERT_EQ(ZX_OK, t1.status_value(), "trap 0x10\n");
  auto t2 = guest->SetTrap(ZX_GUEST_TRAP_IO, 0x11, 1, nullptr, 0x11);
  ASSERT_EQ(ZX_OK, t2.status_value(), "trap 0x11\n");
  auto vcpu_result = Vcpu::Create(*guest, kCodeGpa);
  ASSERT_EQ(ZX_OK, vcpu_result.status_value(), "Vcpu::Create failed\n");
  ktl::unique_ptr<Vcpu> vcpu = ktl::move(vcpu_result.value());

  zx_vcpu_state_t init = {};
  init.rbx = 0x50;
  ASSERT_EQ(ZX_OK, vcpu->WriteState(init).status_value(), "seed rbx\n");

  // Run to the first exit; RIP now sits at `inc rbx`.
  zx_port_packet_t a = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(a).status_value(), "Enter to A\n");
  EXPECT_EQ(0x50u, static_cast<uint32_t>(a.guest_io.data[0]), "exit A value\n");

  // Capture the full state.
  VcpuArchState s1 = {};
  ASSERT_EQ(ZX_OK, vcpu->SaveArchState(s1).status_value(), "SaveArchState\n");
  // Non-vacuous: the capture holds real 64-bit-mode state.
  EXPECT_TRUE((s1.cr0 & (1ull << 31)) != 0, "CR0.PG captured\n");
  EXPECT_TRUE((s1.efer & (1ull << 10)) != 0, "EFER.LMA captured\n");
  EXPECT_TRUE(s1.cs.access_rights != 0, "CS access-rights captured\n");
  EXPECT_TRUE(s1.gdtr_limit != 0 || s1.idtr_limit != 0, "a descriptor-table limit captured\n");
  EXPECT_EQ(0x50u, static_cast<uint32_t>(s1.regs.rbx), "rbx captured\n");

  // Serialize -> flat buffer -> deserialize into a fresh struct.
  const size_t buf_len = SerializedVcpuStateSize();
  fbl::AllocChecker ac;
  ktl::unique_ptr<uint8_t[]> buffer(new (&ac) uint8_t[buf_len]);
  ASSERT_TRUE(ac.check(), "alloc serialization buffer\n");
  ASSERT_EQ(ZX_OK, SerializeVcpuState(s1, buffer.get(), buf_len).status_value(), "serialize\n");

  // A too-small buffer must be rejected.
  EXPECT_EQ(ZX_ERR_BUFFER_TOO_SMALL, SerializeVcpuState(s1, buffer.get(), buf_len - 1).status_value(),
            "short buffer must be rejected\n");

  VcpuArchState s2 = {};
  ASSERT_EQ(ZX_OK, DeserializeVcpuState(s2, buffer.get(), buf_len).status_value(), "deserialize\n");

  // The round-trip must be byte-for-byte lossless.
  EXPECT_EQ(0, memcmp(&s1, &s2, sizeof(VcpuArchState)), "serialize/deserialize must be lossless\n");

  // Diverge the VCPU *past* the captured point: run on to exit B (inc -> 0x51),
  // which advances RIP to `hlt` and leaves rbx at 0x51. If restore were a no-op,
  // the next Enter would resume at `hlt` and never reach exit B again.
  zx_port_packet_t b1 = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(b1).status_value(), "Enter to B\n");
  ASSERT_EQ(0x11u, b1.guest_io.port, "exit B port\n");
  EXPECT_EQ(0x51u, static_cast<uint32_t>(b1.guest_io.data[0]), "exit B value\n");

  // Restore from the *deserialized* blob and replay: the guest must resume at
  // the captured RIP with the captured rbx and reproduce exit B — proving the
  // restore actually drives execution from the serialized state (RIP + GPRs).
  ASSERT_EQ(ZX_OK, vcpu->RestoreArchState(s2).status_value(), "RestoreArchState\n");
  zx_port_packet_t b2 = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(b2).status_value(), "Enter to B' (replay)\n");
  ASSERT_EQ(0x11u, b2.guest_io.port, "replay port\n");
  EXPECT_EQ(0x51u, static_cast<uint32_t>(b2.guest_io.data[0]),
            "replay from the deserialized blob must reproduce exit B\n");

  printf("vcpu serialization OK: %zu-byte snapshot round-tripped losslessly; after diverging the "
         "vcpu, restore from the deserialized blob replayed exit B (0x%x)\n",
         buf_len, b2.guest_io.data[0]);
#else
  printf("Not x86_64; skipping.\n");
#endif  // __x86_64__

  END_TEST;
}

// VMM-planted software breakpoint (INT3) coverage support. Mirrors what a
// userspace VMM/VMI does for coverage-guided tracing: plant 0xCC over a block's
// first instruction, run, take the #BP exit, record the hit, restore the byte,
// reposition RIP, and resume — the guest then executes the original instruction.
// This exercises the two blocking kernel pieces: (1) opt-in #BP trapping +
// delivery as a ZX_PKT_TYPE_GUEST_EXCEPTION exit, and (2) RIP reposition (via the
// arch-state restore). It also proves guest-RAM writes propagate to the guest's
// EPT (the restored byte must be what re-executes, not the stale 0xCC).
bool vcpu_breakpoint_int3_coverage() {
  BEGIN_TEST;

#ifdef __x86_64__
  auto guest_result = Guest::Create();
  if (guest_result.is_error() && guest_result.status_value() == ZX_ERR_NOT_SUPPORTED) {
    printf("VMX not supported here; skipping breakpoint-coverage test.\n");
    return true;
  }
  ASSERT_EQ(ZX_OK, guest_result.status_value(), "Guest::Create failed\n");
  ktl::unique_ptr<Guest> guest = ktl::move(guest_result.value());

  fbl::RefPtr<VmObjectPaged> golden;
  ASSERT_EQ(ZX_OK, VmObjectPaged::Create(PMM_ALLOC_FLAG_ANY, 0u, kGuestRamSize, &golden),
            "create golden\n");
  ASSERT_EQ(ZX_OK, WriteIdentityTables(golden), "write tables\n");
  // Code @0x3000:
  //   B0 41   mov al, 0x41   <- block start; we plant 0xCC over the 0xB0 byte
  //   E6 20   out 0x20, al   <- reports 0x41 iff the restored instruction ran
  //   F4      hlt
  const uint8_t code[] = {0xB0, 0x41, 0xE6, 0x20, 0xF4};
  const uint8_t kOrigByte = 0xB0;  // first byte of the block, overwritten by INT3
  ASSERT_EQ(ZX_OK, golden->Write(code, kCodeGpa, sizeof(code)), "write code\n");
  ASSERT_EQ(ZX_OK, golden->CommitRange(0, kGuestRamSize), "commit golden\n");

  fbl::RefPtr<VmObject> working;
  ASSERT_EQ(ZX_OK,
            golden->CreateClone(Resizability::NonResizable, SnapshotType::OnWrite, 0, kGuestRamSize,
                                false, &working),
            "clone working\n");
  working->set_user_id(ZX_KOID_KERNEL);

  // Plant the breakpoint: 0xCC over the block's first byte, before entry.
  const uint8_t kInt3 = 0xCC;
  ASSERT_EQ(ZX_OK, working->Write(&kInt3, kCodeGpa, 1), "plant INT3\n");

  auto mapping = guest->RootVmar()->CreateVmMapping(0, kGuestRamSize, 0, VMAR_FLAG_SPECIFIC,
                                                    working, 0, kMmuFlags, "guest-ram");
  ASSERT_EQ(ZX_OK, mapping.status_value(), "map guest RAM\n");
  auto trap = guest->SetTrap(ZX_GUEST_TRAP_IO, 0x20, 1, nullptr, 0x20);
  ASSERT_EQ(ZX_OK, trap.status_value(), "trap 0x20\n");

  auto vcpu_result = Vcpu::Create(*guest, kCodeGpa);
  ASSERT_EQ(ZX_OK, vcpu_result.status_value(), "Vcpu::Create failed\n");
  ktl::unique_ptr<Vcpu> vcpu = ktl::move(vcpu_result.value());

  // Opt into #BP trapping.
  ASSERT_EQ(ZX_OK, vcpu->SetBreakpointTrapping(true).status_value(), "enable #BP trapping\n");

  // Run: the guest hits the planted INT3 and exits to us as a guest exception.
  zx_port_packet_t bp = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(bp).status_value(), "Enter to breakpoint\n");
  ASSERT_EQ(static_cast<uint8_t>(ZX_PKT_TYPE_GUEST_EXCEPTION), static_cast<uint8_t>(bp.type),
            "expected a guest-exception exit\n");
  EXPECT_EQ(3u, bp.guest_exception.vector, "expected #BP (vector 3)\n");
  // For an intercepted #BP the VM exit leaves guest RIP *at* the INT3 (the block
  // start), with the instruction length in the exit-info field — so no RIP
  // reposition is needed to re-execute the original instruction after restoring
  // the byte. (RIP write is still available via the arch-state path for VMMs
  // that skip or relocate.)
  const uint64_t bp_addr = bp.guest_exception.rip;
  EXPECT_EQ(kCodeGpa, bp_addr, "breakpoint should be at the block start\n");

  // "Coverage recorded" = the guest reached bp_addr. Restore the original byte;
  // the guest will re-execute from the (unchanged) RIP at the block start.
  ASSERT_EQ(ZX_OK, working->Write(&kOrigByte, kCodeGpa, 1), "restore original byte\n");

  // Resume: the guest must now execute the restored `mov al,0x41; out 0x20,al`.
  // If the restored byte did not reach the guest's EPT, it would re-hit 0xCC
  // instead (another guest-exception, not an I/O exit).
  zx_port_packet_t io = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(io).status_value(), "Enter after breakpoint\n");
  ASSERT_EQ(static_cast<uint8_t>(ZX_PKT_TYPE_GUEST_IO), static_cast<uint8_t>(io.type),
            "expected an I/O exit after resuming past the breakpoint\n");
  EXPECT_EQ(0x20u, io.guest_io.port, "wrong port\n");
  EXPECT_EQ(0x41u, static_cast<uint32_t>(io.guest_io.data[0]),
            "guest must run the restored instruction after the breakpoint\n");

  printf("breakpoint coverage OK: planted INT3 -> #BP exit at block %#lx; after restoring the "
         "byte the guest re-executed the original instruction (0x%x)\n",
         bp_addr, io.guest_io.data[0]);
#else
  printf("Not x86_64; skipping.\n");
#endif  // __x86_64__

  END_TEST;
}

// The other half of VMM breakpoint handling: when a trapped #BP is NOT one of
// the VMM's instrumentation points (it's the guest's *own* INT3, e.g. an
// in-guest debugger), the VMM re-injects it so the guest's own IDT handler runs.
// This builds a minimal but real 64-bit guest (GDT with a code segment, an IDT
// whose #BP gate points at a handler, and a stack), takes the guest's INT3 as a
// host exit, re-injects #BP, and proves the guest's handler executed.
bool vcpu_breakpoint_inject_to_guest() {
  BEGIN_TEST;

#ifdef __x86_64__
  auto guest_result = Guest::Create();
  if (guest_result.is_error() && guest_result.status_value() == ZX_ERR_NOT_SUPPORTED) {
    printf("VMX not supported here; skipping breakpoint-injection test.\n");
    return true;
  }
  ASSERT_EQ(ZX_OK, guest_result.status_value(), "Guest::Create failed\n");
  ktl::unique_ptr<Guest> guest = ktl::move(guest_result.value());

  constexpr uint64_t kGdtGpa = 0x6000;
  constexpr uint64_t kIdtGpa = 0x6800;
  constexpr uint64_t kHandlerGpa = 0x8000;
  constexpr uint64_t kStackTop = 0x9000;

  fbl::RefPtr<VmObjectPaged> golden;
  ASSERT_EQ(ZX_OK, VmObjectPaged::Create(PMM_ALLOC_FLAG_ANY, 0u, kGuestRamSize, &golden),
            "create golden\n");
  ASSERT_EQ(ZX_OK, WriteIdentityTables(golden), "write tables\n");

  // The guest's own breakpoint: a bare INT3 at the entry point.
  const uint8_t kInt3 = 0xCC;
  ASSERT_EQ(ZX_OK, golden->Write(&kInt3, kCodeGpa, 1), "guest INT3\n");

  // GDT: [0] = null (already zero), [1] = flat 64-bit code segment (selector 0x08).
  const uint8_t gdt_code[8] = {0xFF, 0xFF, 0x00, 0x00, 0x00, 0x9B, 0xAF, 0x00};
  ASSERT_EQ(ZX_OK, golden->Write(gdt_code, kGdtGpa + 8, sizeof(gdt_code)), "GDT code desc\n");

  // IDT gate for vector 3 (#BP): 64-bit interrupt gate, selector 0x08, offset =
  // handler.
  const uint8_t idt_bp_gate[16] = {
      static_cast<uint8_t>(kHandlerGpa & 0xFF), static_cast<uint8_t>((kHandlerGpa >> 8) & 0xFF),
      0x08, 0x00,  // selector = 0x0008
      0x00,        // IST
      0x8E,        // present, DPL 0, 64-bit interrupt gate
      0x00, 0x00,  // offset[31:16]
      0x00, 0x00, 0x00, 0x00,  // offset[63:32]
      0x00, 0x00, 0x00, 0x00,  // reserved
  };
  ASSERT_EQ(ZX_OK, golden->Write(idt_bp_gate, kIdtGpa + 3 * 16, sizeof(idt_bp_gate)),
            "IDT #BP gate\n");

  // Handler: mov al,0x55; out 0x30,al; hlt.
  const uint8_t handler[] = {0xB0, 0x55, 0xE6, 0x30, 0xF4};
  ASSERT_EQ(ZX_OK, golden->Write(handler, kHandlerGpa, sizeof(handler)), "handler\n");
  ASSERT_EQ(ZX_OK, golden->CommitRange(0, kGuestRamSize), "commit golden\n");

  fbl::RefPtr<VmObject> working;
  ASSERT_EQ(ZX_OK,
            golden->CreateClone(Resizability::NonResizable, SnapshotType::OnWrite, 0, kGuestRamSize,
                                false, &working),
            "clone working\n");
  working->set_user_id(ZX_KOID_KERNEL);
  auto mapping = guest->RootVmar()->CreateVmMapping(0, kGuestRamSize, 0, VMAR_FLAG_SPECIFIC,
                                                    working, 0, kMmuFlags, "guest-ram");
  ASSERT_EQ(ZX_OK, mapping.status_value(), "map guest RAM\n");
  auto trap = guest->SetTrap(ZX_GUEST_TRAP_IO, 0x30, 1, nullptr, 0x30);
  ASSERT_EQ(ZX_OK, trap.status_value(), "trap 0x30\n");

  auto vcpu_result = Vcpu::Create(*guest, kCodeGpa);
  ASSERT_EQ(ZX_OK, vcpu_result.status_value(), "Vcpu::Create failed\n");
  ktl::unique_ptr<Vcpu> vcpu = ktl::move(vcpu_result.value());
  ASSERT_EQ(ZX_OK, vcpu->SetBreakpointTrapping(true).status_value(), "enable #BP trapping\n");

  // Point the guest at its descriptor tables and a stack (via the arch-state
  // path), so it can actually take an interrupt.
  VcpuArchState s = {};
  ASSERT_EQ(ZX_OK, vcpu->SaveArchState(s).status_value(), "SaveArchState\n");
  s.gdtr_base = kGdtGpa;
  s.gdtr_limit = 0x0F;
  s.idtr_base = kIdtGpa;
  s.idtr_limit = 0xFFF;
  s.regs.rsp = kStackTop;
  ASSERT_EQ(ZX_OK, vcpu->RestoreArchState(s).status_value(), "load GDTR/IDTR/RSP\n");

  // The guest hits its own INT3; we take it as a host exit.
  zx_port_packet_t bp = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(bp).status_value(), "Enter to guest INT3\n");
  ASSERT_EQ(static_cast<uint8_t>(ZX_PKT_TYPE_GUEST_EXCEPTION), static_cast<uint8_t>(bp.type),
            "expected a guest-exception exit\n");
  EXPECT_EQ(kCodeGpa, bp.guest_exception.rip, "wrong #BP address\n");

  // "Not one of ours" -> re-inject the #BP so the guest's own handler runs.
  // Trapping is disabled for the delivering entry so the injected #BP reaches
  // the guest IDT rather than re-trapping to the host (a real VMM re-enables it
  // afterwards; here one delivery suffices).
  ASSERT_EQ(ZX_OK, vcpu->SetBreakpointTrapping(false).status_value(), "disable #BP trapping\n");
  ASSERT_EQ(ZX_OK, vcpu->InjectException(3, /*instruction_length=*/1).status_value(),
            "InjectException(#BP)\n");

  // The guest's #BP handler must now execute and report via port 0x30.
  zx_port_packet_t handled = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(handled).status_value(), "Enter to guest handler\n");
  ASSERT_EQ(static_cast<uint8_t>(ZX_PKT_TYPE_GUEST_IO), static_cast<uint8_t>(handled.type),
            "expected the guest #BP handler to run and do I/O\n");
  EXPECT_EQ(0x30u, handled.guest_io.port, "wrong handler port\n");
  EXPECT_EQ(0x55u, static_cast<uint32_t>(handled.guest_io.data[0]),
            "guest's own #BP handler must have run\n");

  printf("breakpoint injection OK: guest INT3 taken as host exit, re-injected #BP vectored "
         "through the guest IDT and its handler ran (0x%x)\n",
         handled.guest_io.data[0]);
#else
  printf("Not x86_64; skipping.\n");
#endif  // __x86_64__

  END_TEST;
}

// A guest + vcpu that outlive a single Enter(), so a test can drive several
// entries and mutate state between them (unlike single-shot RunGuestToFirstIo).
struct LiveGuest {
  ktl::unique_ptr<Guest> guest;
  ktl::unique_ptr<Vcpu> vcpu;
};

// Maps `ram` at GPA 0, traps ports 0x10/0x11, and creates a vcpu at `entry`.
// The RAM mapping is retained by the guest's VMAR, so dropping the local handle
// here does not unmap it.
zx::result<LiveGuest> CreateLiveGuest(const fbl::RefPtr<VmObject>& ram, uint64_t entry) {
  auto guest_result = Guest::Create();
  if (guest_result.is_error()) {
    return guest_result.take_error();
  }
  ktl::unique_ptr<Guest> guest = ktl::move(guest_result.value());
  auto mapping = guest->RootVmar()->CreateVmMapping(0, kGuestRamSize, 0, VMAR_FLAG_SPECIFIC, ram, 0,
                                                    kMmuFlags, "guest-ram");
  if (mapping.is_error()) {
    return mapping.take_error();
  }
  if (auto t = guest->SetTrap(ZX_GUEST_TRAP_IO, 0x10, 1, nullptr, 0x10); t.is_error()) {
    return t.take_error();
  }
  if (auto t = guest->SetTrap(ZX_GUEST_TRAP_IO, 0x11, 1, nullptr, 0x11); t.is_error()) {
    return t.take_error();
  }
  auto vcpu_result = Vcpu::Create(*guest, entry);
  if (vcpu_result.is_error()) {
    return vcpu_result.take_error();
  }
  LiveGuest lg;
  lg.guest = ktl::move(guest);
  lg.vcpu = ktl::move(vcpu_result.value());
  return zx::ok(ktl::move(lg));
}

// WI-1.6 (kick): Vcpu::Kick() cancels an in-flight run cleanly. We enter once to
// bind the vcpu to this thread and take a first I/O exit, then Kick() and re-
// enter: that entry must return ZX_ERR_CANCELED *before* running any guest
// instruction. A subsequent entry resumes the guest exactly where it was — so
// the cancel neither advanced nor corrupted guest state.
bool vcpu_kick_cancels_run() {
  BEGIN_TEST;

#ifdef __x86_64__
  fbl::RefPtr<VmObjectPaged> ram;
  ASSERT_EQ(ZX_OK, VmObjectPaged::Create(PMM_ALLOC_FLAG_ANY, 0u, kGuestRamSize, &ram), "ram\n");
  ASSERT_EQ(ZX_OK, WriteIdentityTables(ram), "tables\n");
  // mov al,0x42; out 0x10,al; mov al,0x43; out 0x11,al; hlt
  const uint8_t code[] = {0xB0, 0x42, 0xE6, 0x10, 0xB0, 0x43, 0xE6, 0x11, 0xF4};
  ASSERT_EQ(ZX_OK, ram->Write(code, kCodeGpa, sizeof(code)), "code\n");
  ASSERT_EQ(ZX_OK, ram->CommitRange(0, kGuestRamSize), "commit\n");

  auto lg = CreateLiveGuest(ram, kCodeGpa);
  if (lg.is_error() && lg.status_value() == ZX_ERR_NOT_SUPPORTED) {
    printf("VMX not supported here; skipping kick-cancel test.\n");
    return true;
  }
  ASSERT_EQ(ZX_OK, lg.status_value(), "create live guest\n");
  Vcpu* vcpu = lg->vcpu.get();

  // First entry: run to exit #1 (port 0x10 = 0x42). This binds the vcpu.
  zx_port_packet_t p = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(p).status_value(), "enter #1\n");
  ASSERT_EQ(static_cast<uint8_t>(ZX_PKT_TYPE_GUEST_IO), static_cast<uint8_t>(p.type), "io #1\n");
  ASSERT_EQ(0x42u, static_cast<uint32_t>(p.guest_io.data[0]), "exit #1 value\n");

  // Kick, then re-enter: the run must cancel without executing the guest.
  vcpu->Kick();
  auto canceled = vcpu->Enter(p);
  ASSERT_EQ(ZX_ERR_CANCELED, canceled.status_value(), "kicked entry must cancel\n");

  // The kick is transient; the next entry resumes at the *same* point the guest
  // was suspended, reaching exit #2 (0x43). Had the canceled entry run the
  // guest, exit #2 would have been consumed already.
  ASSERT_EQ(ZX_OK, vcpu->Enter(p).status_value(), "enter after cancel\n");
  ASSERT_EQ(static_cast<uint8_t>(ZX_PKT_TYPE_GUEST_IO), static_cast<uint8_t>(p.type), "io #2\n");
  EXPECT_EQ(0x43u, static_cast<uint32_t>(p.guest_io.data[0]),
            "guest must resume at the point the cancel suspended it\n");
  printf("kick-cancel OK: Enter returned CANCELED with no guest advance; resume reached %#x\n",
         p.guest_io.data[0]);
#else
  printf("Not x86_64; skipping.\n");
#endif  // __x86_64__

  END_TEST;
}

// WI-1.6 (state): the public zx_vcpu_state_t read/write path (ReadState /
// WriteState) round-trips guest GPRs and a written register drives subsequent
// guest execution. This is the syscall-surface path (GPRs+RSP+RFLAGS, no RIP),
// distinct from the kernel-internal SaveArchState/RestoreArchState exercised
// elsewhere. Non-vacuous: the value the guest reports on exit #2 exists only
// because the host injected it via WriteState between the two entries.
bool vcpu_public_state_readwrite_roundtrip() {
  BEGIN_TEST;

#ifdef __x86_64__
  fbl::RefPtr<VmObjectPaged> ram;
  ASSERT_EQ(ZX_OK, VmObjectPaged::Create(PMM_ALLOC_FLAG_ANY, 0u, kGuestRamSize, &ram), "ram\n");
  ASSERT_EQ(ZX_OK, WriteIdentityTables(ram), "tables\n");
  // mov al,0x42; out 0x10,al; mov al,bl; out 0x11,al; hlt
  //   exit #1 reports 0x42; after the host writes bl via WriteState, exit #2
  //   reports that host-injected value.
  const uint8_t code[] = {0xB0, 0x42, 0xE6, 0x10, 0x88, 0xD8, 0xE6, 0x11, 0xF4};
  ASSERT_EQ(ZX_OK, ram->Write(code, kCodeGpa, sizeof(code)), "code\n");
  ASSERT_EQ(ZX_OK, ram->CommitRange(0, kGuestRamSize), "commit\n");

  auto lg = CreateLiveGuest(ram, kCodeGpa);
  if (lg.is_error() && lg.status_value() == ZX_ERR_NOT_SUPPORTED) {
    printf("VMX not supported here; skipping public-state round-trip test.\n");
    return true;
  }
  ASSERT_EQ(ZX_OK, lg.status_value(), "create live guest\n");
  Vcpu* vcpu = lg->vcpu.get();

  zx_port_packet_t p = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(p).status_value(), "enter #1\n");
  ASSERT_EQ(0x42u, static_cast<uint32_t>(p.guest_io.data[0]), "exit #1 value\n");

  // ReadState must reflect the guest GPRs at the exit (al=0x42 => rax low byte).
  zx_vcpu_state_t state = {};
  ASSERT_EQ(ZX_OK, vcpu->ReadState(state).status_value(), "ReadState\n");
  EXPECT_EQ(0x42u, static_cast<uint32_t>(state.rax & 0xff), "ReadState did not see guest rax\n");

  // Inject a value the guest cannot otherwise produce, then let it read bl out.
  constexpr uint64_t kInjected = 0x99;
  state.rbx = kInjected;
  ASSERT_EQ(ZX_OK, vcpu->WriteState(state).status_value(), "WriteState\n");

  ASSERT_EQ(ZX_OK, vcpu->Enter(p).status_value(), "enter #2\n");
  ASSERT_EQ(static_cast<uint8_t>(ZX_PKT_TYPE_GUEST_IO), static_cast<uint8_t>(p.type), "io #2\n");
  EXPECT_EQ(static_cast<uint32_t>(kInjected), static_cast<uint32_t>(p.guest_io.data[0]),
            "WriteState-injected rbx did not reach the guest\n");
  printf("public-state OK: ReadState saw rax=%#x; WriteState(rbx=%#x) drove guest exit #2=%#x\n",
         static_cast<uint32_t>(state.rax & 0xff), static_cast<uint32_t>(kInjected),
         p.guest_io.data[0]);
#else
  printf("Not x86_64; skipping.\n");
#endif  // __x86_64__

  END_TEST;
}

// WI-1.6 (overlay): a GPA range can be re-backed with a different VMO mid-guest-
// lifetime, and the guest observes the new backing. The guest reads the same
// address twice; between the two reads the host overwrites that page's mapping
// with a fresh VMO (VMAR_FLAG_SPECIFIC_OVERWRITE). The second read must return
// the overlay's byte — proving the overwrite tore down and invalidated the
// guest's second-level (EPT) translation for that page. Non-vacuous: the overlay
// byte exists only in the replacement VMO.
bool vcpu_overlay_rebacks_gpa() {
  BEGIN_TEST;

#ifdef __x86_64__
  constexpr uint8_t kBaseline = 0xAA;
  constexpr uint8_t kOverlay = 0xCC;

  fbl::RefPtr<VmObjectPaged> golden;
  ASSERT_EQ(ZX_OK, VmObjectPaged::Create(PMM_ALLOC_FLAG_ANY, 0u, kGuestRamSize, &golden), "ram\n");
  ASSERT_EQ(ZX_OK, WriteIdentityTables(golden), "tables\n");
  // mov rbx,0x4000; mov al,[rbx]; out 0x10,al; mov al,[rbx]; out 0x11,al; hlt
  const uint8_t code[] = {0x48, 0xBB, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // rbx=0x4000
                          0x8A, 0x03, 0xE6, 0x10,  // al=[rbx]; out 0x10 (exit #1)
                          0x8A, 0x03, 0xE6, 0x11,  // al=[rbx]; out 0x11 (exit #2)
                          0xF4};
  ASSERT_EQ(ZX_OK, golden->Write(code, kCodeGpa, sizeof(code)), "code\n");
  ASSERT_EQ(ZX_OK, golden->Write(&kBaseline, kDataGpa, sizeof(kBaseline)), "baseline byte\n");
  ASSERT_EQ(ZX_OK, golden->CommitRange(0, kGuestRamSize), "commit\n");

  auto lg = CreateLiveGuest(golden, kCodeGpa);
  if (lg.is_error() && lg.status_value() == ZX_ERR_NOT_SUPPORTED) {
    printf("VMX not supported here; skipping overlay test.\n");
    return true;
  }
  ASSERT_EQ(ZX_OK, lg.status_value(), "create live guest\n");
  Vcpu* vcpu = lg->vcpu.get();

  zx_port_packet_t p = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(p).status_value(), "enter #1\n");
  ASSERT_EQ(static_cast<uint32_t>(kBaseline), static_cast<uint32_t>(p.guest_io.data[0]),
            "exit #1 must read the baseline byte\n");

  // Overlay a fresh page over GPA [0x4000, 0x5000) with the replacement byte.
  fbl::RefPtr<VmObjectPaged> overlay;
  ASSERT_EQ(ZX_OK, VmObjectPaged::Create(PMM_ALLOC_FLAG_ANY, 0u, 4096, &overlay), "overlay\n");
  ASSERT_EQ(ZX_OK, overlay->Write(&kOverlay, 0, sizeof(kOverlay)), "overlay byte\n");
  ASSERT_EQ(ZX_OK, overlay->CommitRange(0, 4096), "commit overlay\n");
  auto remap = lg->guest->RootVmar()->CreateVmMapping(kDataGpa, 4096, 0,
                                                      VMAR_FLAG_SPECIFIC_OVERWRITE, overlay, 0,
                                                      kMmuFlags, "overlay");
  ASSERT_EQ(ZX_OK, remap.status_value(), "overwrite-map overlay at GPA 0x4000\n");

  ASSERT_EQ(ZX_OK, vcpu->Enter(p).status_value(), "enter #2\n");
  ASSERT_EQ(static_cast<uint8_t>(ZX_PKT_TYPE_GUEST_IO), static_cast<uint8_t>(p.type), "io #2\n");
  EXPECT_EQ(static_cast<uint32_t>(kOverlay), static_cast<uint32_t>(p.guest_io.data[0]),
            "guest must observe the overlay backing after the re-map\n");
  printf("overlay OK: exit #1 read baseline %#x; after GPA re-map, exit #2 read overlay %#x\n",
         kBaseline, p.guest_io.data[0]);
#else
  printf("Not x86_64; skipping.\n");
#endif  // __x86_64__

  END_TEST;
}

// WI-2.1 (capture): the local-APIC block — LVT-timer config and the pending-
// interrupt set — is captured into VcpuArchState, survives serialize/deserialize
// canonically, and RestoreArchState rebuilds the *exact* set (dropping any
// interrupt the live tracker accumulated after capture). Delivery of a restored
// pending interrupt is a separate, hardware-timing-sensitive property gated to
// bare metal; this proves the capture/restore plumbing only.
bool vcpu_lapic_pending_state_roundtrip() {
  BEGIN_TEST;

#ifdef __x86_64__
  fbl::RefPtr<VmObjectPaged> ram;
  ASSERT_EQ(ZX_OK, VmObjectPaged::Create(PMM_ALLOC_FLAG_ANY, 0u, kGuestRamSize, &ram), "ram\n");
  ASSERT_EQ(ZX_OK, WriteIdentityTables(ram), "tables\n");
  const uint8_t code[] = {0xB0, 0x42, 0xE6, 0x10, 0xF4};  // mov al,0x42; out 0x10,al; hlt
  ASSERT_EQ(ZX_OK, ram->Write(code, kCodeGpa, sizeof(code)), "code\n");
  ASSERT_EQ(ZX_OK, ram->CommitRange(0, kGuestRamSize), "commit\n");

  auto lg = CreateLiveGuest(ram, kCodeGpa);
  if (lg.is_error() && lg.status_value() == ZX_ERR_NOT_SUPPORTED) {
    // Fail-on-skip guard: this print is DISTINCT from the "LAPIC-state OK"
    // success marker below, which is emitted only after the whole body runs. A
    // boot contract that requires "LAPIC-state OK" therefore treats a VMX skip
    // as absence-of-proof, not a silent green. Live ISR restore is exercised
    // only where CreateLiveGuest works (a bare-metal VT-x host).
    printf("LAPIC-state SKIPPED: VMX/CreateLiveGuest unavailable, control NOT exercised\n");
    return true;
  }
  ASSERT_EQ(ZX_OK, lg.status_value(), "create live guest\n");
  Vcpu* vcpu = lg->vcpu.get();

  // Bind + run once so the capture reflects real running state.
  zx_port_packet_t p = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(p).status_value(), "enter\n");

  constexpr uint32_t kV1 = 0x21, kV2 = 0x81, kV3 = 0x40;
  auto bit = [](uint32_t v, const VcpuAsyncState& s) {
    return (s.pending_interrupts[v / 8] & (1u << (v % 8))) != 0;
  };

  // Inject two interrupts; they land pending (we do not re-enter, so they are
  // captured rather than delivered).
  ASSERT_EQ(ZX_OK, vcpu->Interrupt(kV1).status_value(), "inject v1\n");
  ASSERT_EQ(ZX_OK, vcpu->Interrupt(kV2).status_value(), "inject v2\n");

  VcpuAsyncState captured = {};
  ASSERT_EQ(ZX_OK, vcpu->SaveAsyncState(captured).status_value(), "SaveAsyncState\n");
  EXPECT_TRUE(bit(kV1, captured), "v1 captured pending\n");
  EXPECT_TRUE(bit(kV2, captured), "v2 captured pending\n");
  EXPECT_FALSE(bit(kV3, captured), "v3 not yet injected\n");

  // Host-chosen LVT-timer config (values the guest never programmed) so the LVT
  // round-trip is non-vacuous.
  captured.lvt_timer = 0x1234;
  captured.lvt_initial_count = 0x5678;
  captured.lvt_divide_config = 0xB;

  // Host-chosen in-service-register bits, so the ISR round-trip is non-vacuous.
  // Two high-word vectors (0x41, 0xff) plus, deliberately, vectors 21 and 31 in
  // word 0: those are the bare interrupt vectors this implementation legitimately
  // places in service (guest ICR/device vectors), and a guest with vector 31 in service
  // must round-trip. They are NOT the impossible low vectors (0..20) that
  // RestoreAsyncState rejects.
  captured.isr[0x41 / 32] |= uint32_t{1} << (0x41 % 32);
  captured.isr[0xff / 32] |= uint32_t{1} << (0xff % 32);
  captured.isr[21 / 32] |= uint32_t{1} << (21 % 32);
  captured.isr[31 / 32] |= uint32_t{1} << (31 % 32);
  EXPECT_EQ((uint32_t{1} << 21) | (uint32_t{1} << 31), captured.isr[0],
            "word 0 carries only the legitimate vectors 21 and 31\n");

  // Serialize -> deserialize must preserve the local-APIC block exactly.
  const size_t buf_len = SerializedVcpuAsyncStateSize();
  fbl::AllocChecker ac;
  ktl::unique_ptr<uint8_t[]> buffer(new (&ac) uint8_t[buf_len]);
  ASSERT_TRUE(ac.check(), "alloc buffer\n");
  ASSERT_EQ(ZX_OK, SerializeVcpuAsyncState(captured, buffer.get(), buf_len).status_value(),
            "serialize\n");
  VcpuAsyncState restored = {};
  ASSERT_EQ(ZX_OK, DeserializeVcpuAsyncState(restored, buffer.get(), buf_len).status_value(),
            "deserialize\n");
  EXPECT_EQ(0x1234u, restored.lvt_timer, "lvt_timer survived serialize\n");
  EXPECT_EQ(0x5678u, restored.lvt_initial_count, "lvt_initial_count survived serialize\n");
  EXPECT_EQ(0xBu, restored.lvt_divide_config, "lvt_divide survived serialize\n");
  EXPECT_TRUE(bit(kV1, restored) && bit(kV2, restored), "pending set survived serialize\n");
  // The ISR bitmap is distinct from the pending set and must survive serialize
  // field-for-field, including the legitimate word-0 vectors 21 and 31.
  for (size_t i = 0; i < (sizeof(captured.isr) / sizeof(captured.isr[0])); i++) {
    EXPECT_EQ(captured.isr[i], restored.isr[i], "isr word survived serialize\n");
  }

  // Diverge the live tracker with a third interrupt, then restore. Restore must
  // reinstate exactly {v1, v2}, drop the divergent v3, and re-establish LVT.
  ASSERT_EQ(ZX_OK, vcpu->Interrupt(kV3).status_value(), "inject divergent v3\n");
  ASSERT_EQ(ZX_OK, vcpu->RestoreAsyncState(restored).status_value(), "RestoreAsyncState\n");

  VcpuAsyncState after = {};
  ASSERT_EQ(ZX_OK, vcpu->SaveAsyncState(after).status_value(), "re-capture\n");
  EXPECT_EQ(0x1234u, after.lvt_timer, "lvt_timer restored into live state\n");
  EXPECT_TRUE(bit(kV1, after), "v1 restored\n");
  EXPECT_TRUE(bit(kV2, after), "v2 restored\n");
  EXPECT_FALSE(bit(kV3, after), "divergent v3 dropped by restore\n");
  // ISR was written authoritatively into live state by RestoreAsyncState and
  // reads back through a fresh SaveAsyncState.
  for (size_t i = 0; i < (sizeof(captured.isr) / sizeof(captured.isr[0])); i++) {
    EXPECT_EQ(captured.isr[i], after.isr[i], "isr word restored into live state\n");
  }

  // Impossible low-vector ISR bits (vectors 0..20 are never in service) are
  // rejected, and the live ISR is left unchanged by the rejected restore. Both
  // vector 0 and vector 20 -- the top of the impossible range, one below the
  // first legitimate vector 21 -- must be refused; the boundary is exact.
  for (uint32_t impossible : {uint32_t{0}, uint32_t{20}}) {
    VcpuAsyncState bad = restored;
    bad.isr[0] = uint32_t{1} << impossible;
    EXPECT_EQ(ZX_ERR_INVALID_ARGS, vcpu->RestoreAsyncState(bad).status_value(),
              "impossible low-vector ISR bit rejected\n");
    VcpuAsyncState after_reject = {};
    ASSERT_EQ(ZX_OK, vcpu->SaveAsyncState(after_reject).status_value(),
              "re-capture after reject\n");
    // The live ISR still holds exactly what the last accepted restore installed
    // -- including the legitimate word-0 vectors 21 and 31 -- and nothing from
    // the rejected blob leaked in.
    for (size_t i = 0; i < (sizeof(captured.isr) / sizeof(captured.isr[0])); i++) {
      EXPECT_EQ(captured.isr[i], after_reject.isr[i], "rejected restore left ISR unchanged\n");
    }
  }

  // Transactional restore across the PV-clock path: a blob whose ISR is VALID
  // (so it passes the ISR check) but whose paravirtual-clock GPA is unmapped must
  // be rejected during the phase-1 mapping preflight, leaving the WHOLE LAPIC --
  // LVT, pending set, and ISR -- exactly as the last accepted restore left it.
  // The blob carries divergent LVT/pending/ISR values, so any partial mutation
  // would show up here.
  VcpuAsyncState pre_pv = {};
  ASSERT_EQ(ZX_OK, vcpu->SaveAsyncState(pre_pv).status_value(), "capture before bad-PV restore\n");
  VcpuAsyncState bad_pv = pre_pv;
  bad_pv.lvt_timer = 0xDEAD;        // diverge LVT
  bad_pv.lvt_initial_count = 0xBEEF;
  bad_pv.lvt_divide_config = 0x1;
  memset(bad_pv.pending_interrupts, 0, sizeof(bad_pv.pending_interrupts));
  bad_pv.pending_interrupts[kV3 / 8] |= static_cast<uint8_t>(1u << (kV3 % 8));  // diverge pending
  memset(bad_pv.isr, 0, sizeof(bad_pv.isr));
  bad_pv.isr[0x55 / 32] |= uint32_t{1} << (0x55 % 32);  // diverge ISR (still a valid vector)
  bad_pv.pv_clock_enabled = 1;
  bad_pv.pv_clock_guest_paddr = 0x8000'0000u;  // far outside the 64 KiB guest RAM: unmapped
  EXPECT_NE(ZX_OK, vcpu->RestoreAsyncState(bad_pv).status_value(),
            "restore with an unmapped PV-clock GPA is rejected\n");
  VcpuAsyncState after_pv = {};
  ASSERT_EQ(ZX_OK, vcpu->SaveAsyncState(after_pv).status_value(), "re-capture after bad-PV reject\n");
  EXPECT_EQ(pre_pv.lvt_timer, after_pv.lvt_timer, "bad-PV restore left LVT timer unchanged\n");
  EXPECT_EQ(pre_pv.lvt_initial_count, after_pv.lvt_initial_count,
            "bad-PV restore left LVT initial-count unchanged\n");
  EXPECT_EQ(pre_pv.lvt_divide_config, after_pv.lvt_divide_config,
            "bad-PV restore left LVT divide unchanged\n");
  EXPECT_TRUE(bit(kV1, after_pv) && bit(kV2, after_pv),
              "bad-PV restore left pending set unchanged\n");
  EXPECT_FALSE(bit(kV3, after_pv), "bad-PV restore did not admit its divergent pending vector\n");
  for (size_t i = 0; i < (sizeof(pre_pv.isr) / sizeof(pre_pv.isr[0])); i++) {
    EXPECT_EQ(pre_pv.isr[i], after_pv.isr[i], "bad-PV restore left ISR unchanged\n");
  }

  printf("LAPIC-state OK: pending {%#x,%#x} + LVT captured, serialized, restored; "
         "divergent %#x dropped; unmapped-PV restore rejected with no partial mutation\n",
         kV1, kV2, kV3);
#else
  printf("Not x86_64; skipping.\n");
#endif  // __x86_64__

  END_TEST;
}

// WriteVectoringEvent must refuse every shape the capture path cannot produce (a
// corrupt or cross-built durable artifact could carry a valid identity triple
// but a bad payload), and a rejected write must not partially mutate the live
// vectoring event. Table-driven: establish one known-good value, then for each
// bad shape assert the write is rejected AND ReadVectoringEvent still returns the
// good value unchanged FIELD FOR FIELD. Also proves the two shape-dependent
// positive cases: a #CP hardware exception carrying its error code is accepted in
// protected mode, and the same event is refused once the guest is in real mode
// (CR0.PE clear), where VM entry cannot deliver an error code.
bool vcpu_vectoring_event_write_validation() {
  BEGIN_TEST;

#ifdef __x86_64__
  // CR0.PE (protected-mode enable). Spelled locally so the test does not depend
  // on a register-macro header being transitively included.
  constexpr uint64_t kCr0Pe = 0x1;
  fbl::RefPtr<VmObjectPaged> ram;
  ASSERT_EQ(ZX_OK, VmObjectPaged::Create(PMM_ALLOC_FLAG_ANY, 0u, kGuestRamSize, &ram), "ram\n");
  ASSERT_EQ(ZX_OK, WriteIdentityTables(ram), "tables\n");
  const uint8_t code[] = {0xB0, 0x42, 0xE6, 0x10, 0xF4};  // mov al,0x42; out 0x10,al; hlt
  ASSERT_EQ(ZX_OK, ram->Write(code, kCodeGpa, sizeof(code)), "code\n");
  ASSERT_EQ(ZX_OK, ram->CommitRange(0, kGuestRamSize), "commit\n");

  auto lg = CreateLiveGuest(ram, kCodeGpa);
  if (lg.is_error() && lg.status_value() == ZX_ERR_NOT_SUPPORTED) {
    // Fail-on-skip guard: DISTINCT from the "vectoring-event validation OK"
    // success marker below, which prints only after the whole body runs. A boot
    // contract that requires that marker treats a VMX skip as absence-of-proof,
    // not a silent green. Live validation is exercised only where CreateLiveGuest
    // works (a bare-metal VT-x host).
    printf("vectoring-event validation SKIPPED: VMX/CreateLiveGuest unavailable, "
           "control NOT exercised\n");
    return true;
  }
  ASSERT_EQ(ZX_OK, lg.status_value(), "create live guest\n");
  Vcpu* vcpu = lg->vcpu.get();
  zx_port_packet_t p = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(p).status_value(), "enter\n");

  // Raw VMX interruption types (bits 10:8) -- the anonymous-namespace constants
  // in vcpu.cc are not visible here, so spell them out.
  constexpr uint32_t kExternal = 0u << 8;
  constexpr uint32_t kReserved = 1u << 8;
  constexpr uint32_t kNmi = 2u << 8;
  constexpr uint32_t kHwExc = 3u << 8;
  constexpr uint32_t kSwInt = 4u << 8;
  constexpr uint32_t kPrivSwExc = 5u << 8;
  constexpr uint32_t kSwExc = 6u << 8;
  constexpr uint32_t kOther = 7u << 8;

  auto make = [](uint32_t valid, uint32_t type, uint32_t vector, uint32_t has_err, uint32_t err,
                 uint32_t ilen) {
    zx_vcpu_vectoring_event_t e = {};
    e.magic = ZX_VCPU_VECTORING_EVENT_MAGIC;
    e.version = ZX_VCPU_VECTORING_EVENT_VERSION;
    e.size = sizeof(zx_vcpu_vectoring_event_t);
    e.valid = valid;
    e.type = type;
    e.vector = vector;
    e.has_error_code = has_err;
    e.error_code = err;
    e.instruction_length = ilen;
    return e;
  };

  // Compares two events field for field, so a rejected write that mutated ANY
  // field is caught -- not just type/vector.
  auto same_event = [](const zx_vcpu_vectoring_event_t& a, const zx_vcpu_vectoring_event_t& b) {
    return a.magic == b.magic && a.version == b.version && a.size == b.size &&
           a.valid == b.valid && a.type == b.type && a.vector == b.vector &&
           a.has_error_code == b.has_error_code && a.error_code == b.error_code &&
           a.instruction_length == b.instruction_length;
  };

  // Known-good baseline: an external interrupt at a valid vector, no error code.
  // Read it back once; this exact value is what every rejected write below must
  // leave untouched.
  const zx_vcpu_vectoring_event_t good = make(1, kExternal, 0x30, 0, 0, 0);
  ASSERT_EQ(ZX_OK, vcpu->WriteVectoringEvent(good).status_value(), "good write\n");
  zx_vcpu_vectoring_event_t baseline = {};
  ASSERT_EQ(ZX_OK, vcpu->ReadVectoringEvent(baseline).status_value(), "read good\n");
  EXPECT_EQ(kExternal, baseline.type, "good type\n");
  EXPECT_EQ(0x30u, baseline.vector, "good vector\n");

  struct BadCase {
    const char* name;
    zx_vcpu_vectoring_event_t event;
  };
  BadCase bad[] = {
      {"bad magic", [&] { auto e = make(1, kExternal, 0x30, 0, 0, 0); e.magic ^= 0xFF; return e; }()},
      {"valid > 1", make(2, kExternal, 0x30, 0, 0, 0)},
      {"reserved type", make(1, kReserved, 0x30, 0, 0, 0)},
      {"other-event type", make(1, kOther, 0x30, 0, 0, 0)},
      {"vector above 8 bits", make(1, kExternal, 0x1FF, 0, 0, 0)},
      {"external low vector (reclassified)", make(1, kExternal, 0x14, 0, 0, 0)},
      {"external vector 0", make(1, kExternal, 0, 0, 0, 0)},
      {"nmi wrong vector", make(1, kNmi, 3, 0, 0, 0)},
      {"hw exception vector > 31", make(1, kHwExc, 0x20, 0, 0, 0)},
      {"priv-sw-exc wrong vector", make(1, kPrivSwExc, 2, 0, 0, 0)},
      {"sw-exc wrong vector", make(1, kSwExc, 5, 0, 0, 0)},
      {"error-code flag on external", make(1, kExternal, 0x30, 1, 0, 0)},
      {"missing error-code flag on #GP", make(1, kHwExc, 13, 0, 0, 0)},
      {"error-code flag on #UD (no err)", make(1, kHwExc, 6, 1, 0, 0)},
      {"error-code high bits set on #GP", make(1, kHwExc, 13, 1, 0x1'0000, 0)},
      {"instruction_length on external", make(1, kExternal, 0x30, 0, 0, 4)},
      {"instruction_length 0 on sw-int", make(1, kSwInt, 0x80, 0, 0, 0)},
      {"instruction_length 16 on sw-int", make(1, kSwInt, 0x80, 0, 0, 16)},
      {"clear with a stray field", [&] { auto e = make(0, 0, 0, 0, 0, 0); e.vector = 1; return e; }()},
  };

  for (auto& c : bad) {
    EXPECT_NE(ZX_OK, vcpu->WriteVectoringEvent(c.event).status_value(), c.name);
    zx_vcpu_vectoring_event_t unchanged = {};
    ASSERT_EQ(ZX_OK, vcpu->ReadVectoringEvent(unchanged).status_value(), "read after reject\n");
    // The WHOLE event must be untouched, proving no partial mutation of any
    // field before the rejection.
    EXPECT_TRUE(same_event(baseline, unchanged), c.name);
  }

  // Positive shape-dependent case: a #CP (vector 21) hardware exception carries
  // an architectural error code. In protected mode -- where this guest is after
  // Enter -- WriteVectoringEvent must ACCEPT it: the error-code flag agrees with
  // the has_error_code() predicate and CR0.PE is set.
  const zx_vcpu_vectoring_event_t cp_event = make(1, kHwExc, 21, 1, 0, 0);
  ASSERT_EQ(ZX_OK, vcpu->WriteVectoringEvent(cp_event).status_value(),
            "#CP with error code accepted in protected mode\n");
  zx_vcpu_vectoring_event_t cp_back = {};
  ASSERT_EQ(ZX_OK, vcpu->ReadVectoringEvent(cp_back).status_value(), "read #CP\n");
  EXPECT_EQ(kHwExc, cp_back.type, "#CP type\n");
  EXPECT_EQ(21u, cp_back.vector, "#CP vector\n");
  EXPECT_EQ(1u, cp_back.has_error_code, "#CP carries error code\n");

  // Real-mode case: drop the guest to CR0.PE == 0, then attempt the SAME #CP
  // event. VM entry cannot deliver an error code outside protected mode (SDM
  // Vol. 3, 26.2.1.3), so WriteVectoringEvent must refuse it with BAD_STATE --
  // and, being a rejected write, must leave the accepted #CP value untouched.
  // The arch-state topic is written before this one during a real restore, so
  // reading the just-written GUEST_CR0 here mirrors that ordering.
  VcpuArchState arch = {};
  ASSERT_EQ(ZX_OK, vcpu->SaveArchState(arch).status_value(), "save arch\n");
  arch.cr0 &= ~kCr0Pe;  // clear protected-mode enable
  ASSERT_EQ(ZX_OK, vcpu->RestoreArchState(arch).status_value(), "restore real-mode CR0\n");
  EXPECT_EQ(ZX_ERR_BAD_STATE, vcpu->WriteVectoringEvent(cp_event).status_value(),
            "error-code event refused in real mode\n");
  zx_vcpu_vectoring_event_t after_realmode = {};
  ASSERT_EQ(ZX_OK, vcpu->ReadVectoringEvent(after_realmode).status_value(), "read after real-mode\n");
  EXPECT_TRUE(same_event(cp_back, after_realmode),
              "real-mode-rejected write left the #CP event untouched\n");

  // A valid clear is accepted and leaves nothing owed.
  ASSERT_EQ(ZX_OK, vcpu->WriteVectoringEvent(make(0, 0, 0, 0, 0, 0)).status_value(), "clear\n");
  zx_vcpu_vectoring_event_t cleared = {};
  ASSERT_EQ(ZX_OK, vcpu->ReadVectoringEvent(cleared).status_value(), "read cleared\n");
  EXPECT_EQ(0u, cleared.valid, "cleared\n");
  printf("vectoring-event validation OK: %zu bad shapes rejected (full event unchanged each "
         "time), #CP+errcode accepted in protected mode and refused in real mode\n",
         sizeof(bad) / sizeof(bad[0]));
#else
  printf("Not x86_64; skipping.\n");
#endif  // __x86_64__

  END_TEST;
}

// The LVT timer vector the TSC-deadline-mode test programs, so the WriteTscState
// re-arm/disarm branch (which fires only in that mode) is exercised.
constexpr uint32_t kTscTimerVector = 0x40;

// The guest-TSC checkpoint topic (ZX_VCPU_STATE_TSC): a live control proving the
// WriteTscState contract. WriteTscState installs the caller's pre-computed signed
// offset VERBATIM (never re-derived from a fresh per-VCPU RDTSC), re-derives the
// armed IA32_TSC_DEADLINE through it, DISARMS on a zero deadline in TSC-deadline
// mode, and rejects malformed writes without mutating live state. Needs a live
// guest (real VMX) because the offset only exists in a real VMCS; self-skips
// loudly under TCG.
bool vcpu_tsc_state_roundtrip() {
  BEGIN_TEST;
#if __x86_64__
  fbl::RefPtr<VmObjectPaged> ram;
  ASSERT_EQ(ZX_OK, VmObjectPaged::Create(PMM_ALLOC_FLAG_ANY, 0u, kGuestRamSize, &ram), "ram\n");
  ASSERT_EQ(ZX_OK, WriteIdentityTables(ram), "tables\n");
  const uint8_t code[] = {0xB0, 0x42, 0xE6, 0x10, 0xF4};  // mov al,0x42; out 0x10,al; hlt
  ASSERT_EQ(ZX_OK, ram->Write(code, kCodeGpa, sizeof(code)), "code\n");
  ASSERT_EQ(ZX_OK, ram->CommitRange(0, kGuestRamSize), "commit\n");

  auto lg = CreateLiveGuest(ram, kCodeGpa);
  if (lg.is_error() && lg.status_value() == ZX_ERR_NOT_SUPPORTED) {
    // Fail-on-skip guard: DISTINCT from the "tsc-anchor OK" success marker
    // below, so a boot contract requiring that marker treats a VMX skip as
    // absence-of-proof, not a silent green.
    printf("tsc-anchor SKIPPED: VMX/CreateLiveGuest unavailable, control NOT exercised\n");
    return true;
  }
  ASSERT_EQ(ZX_OK, lg.status_value(), "create live guest\n");
  Vcpu* vcpu = lg->vcpu.get();

  zx_port_packet_t p = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(p).status_value(), "enter\n");

  // Capture: a live read is PRESENT and, on a real VMX guest, OFFSETTING, and
  // reports the signed offset itself (not just guest_tsc).
  zx_vcpu_tsc_state_t captured = {};
  ASSERT_EQ(ZX_OK, vcpu->ReadTscState(captured).status_value(), "ReadTscState\n");
  ASSERT_EQ(ZX_VCPU_TSC_STATE_MAGIC, captured.magic, "read magic\n");
  ASSERT_NE(0u, captured.flags & ZX_VCPU_TSC_STATE_PRESENT, "a live read is PRESENT\n");
  ASSERT_NE(0u, captured.flags & ZX_VCPU_TSC_STATE_OFFSETTING,
            "TSC offsetting must be available on a live VMX guest\n");

  // Program the LVT timer into TSC-deadline mode via the async-state topic, so
  // the WriteTscState re-arm/disarm branch (LVT == TSC-deadline mode) is taken.
  VcpuAsyncState async = {};
  ASSERT_EQ(ZX_OK, vcpu->SaveAsyncState(async).status_value(), "SaveAsyncState\n");
  async.lvt_timer = LVT_TIMER_MODE_TSC_DEADLINE | kTscTimerVector;
  async.timer_armed = 0;  // start disarmed; the TSC topic is what arms it below.
  ASSERT_EQ(ZX_OK, vcpu->RestoreAsyncState(async).status_value(), "RestoreAsyncState (deadline mode)\n");

  // The offset is installed VERBATIM. Choose an offset that makes the
  // guest read back a distinctive far-future anchor, compute it the way a
  // partition restore does (anchor - host RDTSC now), and install it directly.
  constexpr uint64_t kAnchor = 0x0000'4200'0000'0000ull;
  const int64_t offset = static_cast<int64_t>(kAnchor - _rdtsc());
  // An armed deadline FAR past the anchor (2^40 guest TSC ticks, minutes away at
  // any real frequency), so the host timer it re-derives to stays armed long
  // enough for the SaveAsyncState observation below -- a near deadline would
  // fire in the sub-millisecond gap and read back disarmed, which is a property
  // of the deadline chosen, not of the re-arm.
  const uint64_t kDeadline = kAnchor + (uint64_t{1} << 40);
  zx_vcpu_tsc_state_t reanchor = {};
  reanchor.magic = ZX_VCPU_TSC_STATE_MAGIC;
  reanchor.version = ZX_VCPU_TSC_STATE_VERSION;
  reanchor.size = sizeof(zx_vcpu_tsc_state_t);
  reanchor.flags = ZX_VCPU_TSC_STATE_PRESENT | ZX_VCPU_TSC_STATE_OFFSETTING;
  reanchor.guest_tsc = kAnchor;  // informational; the kernel installs tsc_offset.
  reanchor.tsc_offset = offset;
  reanchor.tsc_deadline = kDeadline;
  ASSERT_EQ(ZX_OK, vcpu->WriteTscState(reanchor).status_value(), "WriteTscState re-anchor\n");

  zx_vcpu_tsc_state_t after = {};
  ASSERT_EQ(ZX_OK, vcpu->ReadTscState(after).status_value(), "ReadTscState after\n");
  // The offset read back must be EXACTLY what we wrote: verbatim install, not a
  // fresh RDTSC-derived value. This is the property that keeps a partition
  // coherent, and the one that would fail if the kernel re-derived the offset.
  EXPECT_EQ(offset, after.tsc_offset, "offset installed verbatim (not RDTSC-re-derived)\n");
  EXPECT_GE(after.guest_tsc, kAnchor, "guest TSC re-anchored to at least the anchor\n");
  // A generous ceiling: the read is the anchor plus the host cycles between the
  // write and this read. It fails only if the offset was not installed at all.
  EXPECT_LT(after.guest_tsc - kAnchor, uint64_t{1} << 30, "guest TSC re-anchored precisely\n");
  EXPECT_EQ(kDeadline, after.tsc_deadline, "armed TSC-deadline round-trips\n");
  // OBSERVE the re-arm: with a nonzero deadline in TSC-deadline mode the timer
  // is now armed (RearmApicTimer ran), visible through the async snapshot.
  VcpuAsyncState armed = {};
  ASSERT_EQ(ZX_OK, vcpu->SaveAsyncState(armed).status_value(), "SaveAsyncState after arm\n");
  EXPECT_EQ(1u, armed.timer_armed, "a nonzero deadline in TSC-deadline mode armed the timer\n");

  // Zero deadline DISARMS. A live TSC-deadline timer is armed above;
  // writing a zero deadline (field present, deadline 0) must cancel it, not
  // leave it running against the authoritative TSC state.
  zx_vcpu_tsc_state_t disarm = reanchor;
  disarm.tsc_deadline = 0;
  ASSERT_EQ(ZX_OK, vcpu->WriteTscState(disarm).status_value(), "WriteTscState disarm\n");
  VcpuAsyncState after_disarm = {};
  ASSERT_EQ(ZX_OK, vcpu->SaveAsyncState(after_disarm).status_value(), "SaveAsyncState after disarm\n");
  EXPECT_EQ(0u, after_disarm.timer_armed, "a zero deadline in TSC-deadline mode disarmed the timer\n");
  zx_vcpu_tsc_state_t after_disarm_tsc = {};
  ASSERT_EQ(ZX_OK, vcpu->ReadTscState(after_disarm_tsc).status_value(), "ReadTscState after disarm\n");
  EXPECT_EQ(0u, after_disarm_tsc.tsc_deadline, "disarmed deadline reads back 0\n");

  // --- host-TSC-epoch-jump: re-anchor to a SECOND, different anchor and confirm
  // the guest clock follows the newly installed offset (a partition restored on
  // a machine whose host TSC epoch differs from the capture's).
  constexpr uint64_t kAnchor2 = 0x0000'8800'0000'0000ull;
  const int64_t offset2 = static_cast<int64_t>(kAnchor2 - _rdtsc());
  zx_vcpu_tsc_state_t reanchor2 = reanchor;
  reanchor2.guest_tsc = kAnchor2;
  reanchor2.tsc_offset = offset2;
  reanchor2.tsc_deadline = 0;
  ASSERT_EQ(ZX_OK, vcpu->WriteTscState(reanchor2).status_value(), "WriteTscState epoch jump\n");
  zx_vcpu_tsc_state_t after2 = {};
  ASSERT_EQ(ZX_OK, vcpu->ReadTscState(after2).status_value(), "ReadTscState after epoch jump\n");
  EXPECT_EQ(offset2, after2.tsc_offset, "second offset installed verbatim\n");
  EXPECT_GE(after2.guest_tsc, kAnchor2, "guest TSC followed the new epoch\n");
  EXPECT_LT(after2.guest_tsc - kAnchor2, uint64_t{1} << 30, "guest TSC re-anchored to the new epoch\n");

  // Rejection: a bad identity triple is refused and does NOT mutate the offset.
  zx_vcpu_tsc_state_t bad_magic = reanchor2;
  bad_magic.magic ^= 0xDEADBEEF;
  EXPECT_EQ(ZX_ERR_INVALID_ARGS, vcpu->WriteTscState(bad_magic).status_value(),
            "bad magic rejected\n");
  // Rejection: field-absent (PRESENT clear) with a nonzero payload is malformed.
  zx_vcpu_tsc_state_t bad_absent = reanchor2;
  bad_absent.flags = 0;  // clears PRESENT and OFFSETTING but keeps the payload.
  EXPECT_EQ(ZX_ERR_INVALID_ARGS, vcpu->WriteTscState(bad_absent).status_value(),
            "field-absent-with-payload rejected\n");
  // Neither rejection moved the clock: it still reads back the second offset.
  zx_vcpu_tsc_state_t after_reject = {};
  ASSERT_EQ(ZX_OK, vcpu->ReadTscState(after_reject).status_value(), "ReadTscState after reject\n");
  EXPECT_EQ(offset2, after_reject.tsc_offset, "rejected writes left the offset intact\n");

  // A well-formed FIELD-ABSENT write (flags == 0, zero payload) is accepted and
  // leaves the offset alone (carries a pre-TSC-topic artifact through restore).
  zx_vcpu_tsc_state_t absent = {};
  absent.magic = ZX_VCPU_TSC_STATE_MAGIC;
  absent.version = ZX_VCPU_TSC_STATE_VERSION;
  absent.size = sizeof(zx_vcpu_tsc_state_t);
  EXPECT_EQ(ZX_OK, vcpu->WriteTscState(absent).status_value(), "well-formed field-absent accepted\n");
  zx_vcpu_tsc_state_t after_absent = {};
  ASSERT_EQ(ZX_OK, vcpu->ReadTscState(after_absent).status_value(), "ReadTscState after absent\n");
  EXPECT_EQ(offset2, after_absent.tsc_offset, "field-absent left the offset untouched\n");

  // The production ordering: the ASYNC restore arms the timer from its
  // remaining-time snapshot, and the PRESENT TSC state applied AFTER it (the
  // TSC topic restores last) is authoritative in TSC-deadline mode. A captured
  // tsc_deadline of 0 there means "disarmed", so it must actively cancel the
  // timer the async path just armed rather than leave a live timer contradicting
  // the authoritative TSC state. The earlier disarm case wrote two TSC states to
  // arm-then-disarm; this reproduces the real sequence where a DIFFERENT topic
  // (async) did the arming.
  VcpuAsyncState async_arm = {};
  ASSERT_EQ(ZX_OK, vcpu->SaveAsyncState(async_arm).status_value(), "SaveAsyncState pre-arm\n");
  async_arm.lvt_timer = LVT_TIMER_MODE_TSC_DEADLINE | kTscTimerVector;
  async_arm.timer_armed = 1;
  async_arm.timer_remaining_ns = uint64_t{60} * 1000 * 1000 * 1000;  // 60s: will not fire in-test.
  ASSERT_EQ(ZX_OK, vcpu->RestoreAsyncState(async_arm).status_value(),
            "RestoreAsyncState arms the timer\n");
  VcpuAsyncState async_armed_seen = {};
  ASSERT_EQ(ZX_OK, vcpu->SaveAsyncState(async_armed_seen).status_value(),
            "SaveAsyncState after async arm\n");
  ASSERT_EQ(1u, async_armed_seen.timer_armed,
            "the async restore, not a TSC write, armed the timer\n");
  // Now the authoritative PRESENT TSC state with a zero deadline, in deadline
  // mode: it must cancel the async-armed timer.
  zx_vcpu_tsc_state_t tsc_disarm_after_async = {};
  tsc_disarm_after_async.magic = ZX_VCPU_TSC_STATE_MAGIC;
  tsc_disarm_after_async.version = ZX_VCPU_TSC_STATE_VERSION;
  tsc_disarm_after_async.size = sizeof(zx_vcpu_tsc_state_t);
  tsc_disarm_after_async.flags = ZX_VCPU_TSC_STATE_PRESENT | ZX_VCPU_TSC_STATE_OFFSETTING;
  tsc_disarm_after_async.tsc_offset = offset2;  // leave the clock where it is.
  tsc_disarm_after_async.tsc_deadline = 0;      // authoritative: disarmed.
  ASSERT_EQ(ZX_OK, vcpu->WriteTscState(tsc_disarm_after_async).status_value(),
            "WriteTscState disarm-after-async-arm\n");
  VcpuAsyncState async_after_tsc = {};
  ASSERT_EQ(ZX_OK, vcpu->SaveAsyncState(async_after_tsc).status_value(),
            "SaveAsyncState after TSC disarm\n");
  EXPECT_EQ(0u, async_after_tsc.timer_armed,
            "a PRESENT TSC state with deadline==0 cancelled the async-armed timer\n");

  printf("tsc-anchor OK: offset %#lx installed verbatim (guest TSC read back %#lx), armed "
         "deadline %#lx round-trips, zero deadline disarms, epoch jump followed, malformed "
         "writes rejected with the clock unchanged\n",
         static_cast<uint64_t>(offset), after.guest_tsc, kDeadline);
#else
  printf("Not x86_64; skipping.\n");
#endif  // __x86_64__

  END_TEST;
}

#if __x86_64__
// Carries the AP VCPU's two-phase no-skew run to a dedicated kernel thread. A
// VCPU binds one-per-thread, so the second partition VP must live on its own
// thread; these fields cross the boundary. Phase 1 captures; the AP then blocks
// on |go_restore| until the BSP thread has computed the ONE partition offset,
// installs THAT SAME offset, and reports the installed value back.
struct TscSkewContext {
  Guest* guest = nullptr;
  // Phase-1 result: the offset this VP captured (must equal the BSP's).
  int64_t captured_offset = 0;
  uint32_t captured_flags = 0;
  zx_status_t status = ZX_ERR_INTERNAL;
  // BSP -> AP: the single partition offset to install, and the gate that
  // releases the AP to install it (set only after the BSP has computed it).
  int64_t partition_offset = 0;
  ktl::atomic<bool> captured_ready{false};
  ktl::atomic<bool> go_restore{false};
  // Phase-2 result: the offset actually installed, read back from the VMCS.
  int64_t restored_offset = 0;
};

// A partition-wide restore must leave every VP on ONE coherent guest clock. The
// coherent, sampling-instant-independent quantity is the VMCS TSC offset: two
// VPs share one clock IFF they carry the identical offset (the host TSC is
// synchronized across CPUs). This is the red-first control for the verbatim
// offset install: it installs the SAME pre-computed offset on two VPs whose
// installs are DELIBERATELY spaced apart in time, and asserts both read that
// exact offset back. A per-VP-RDTSC approach -- each VP deriving
// offset = guest_tsc - its_own_rdtsc at its own
// restore instant -- would make the two installed offsets differ by the spacing
// (the sequential-restore skew), failing the equality assertion.
bool vcpu_tsc_partition_no_skew() {
  BEGIN_TEST;

  auto guest_result = Guest::Create();
  if (guest_result.is_error() && guest_result.status_value() == ZX_ERR_NOT_SUPPORTED) {
    printf("tsc-no-skew SKIPPED: VMX/Guest::Create unavailable, control NOT exercised\n");
    return true;
  }
  ASSERT_EQ(ZX_OK, guest_result.status_value(), "Guest::Create failed\n");
  ktl::unique_ptr<Guest> guest = ktl::move(guest_result.value());

  fbl::RefPtr<VmObjectPaged> ram;
  ASSERT_EQ(ZX_OK, VmObjectPaged::Create(PMM_ALLOC_FLAG_ANY, 0u, kGuestRamSize, &ram), "ram\n");
  ASSERT_EQ(ZX_OK, WriteIdentityTables(ram), "tables\n");
  const uint8_t code[] = {0xB0, 0x42, 0xE6, 0x10, 0xF4};  // mov al,0x42; out 0x10,al; hlt
  ASSERT_EQ(ZX_OK, ram->Write(code, kCodeGpa, sizeof(code)), "code\n");
  ASSERT_EQ(ZX_OK, ram->CommitRange(0, kGuestRamSize), "commit\n");
  auto mapping = guest->RootVmar()->CreateVmMapping(0, kGuestRamSize, 0, VMAR_FLAG_SPECIFIC, ram, 0,
                                                    kMmuFlags, "guest-ram");
  ASSERT_EQ(ZX_OK, mapping.status_value(), "map\n");
  auto trap = guest->SetTrap(ZX_GUEST_TRAP_IO, 0x10, 1, nullptr, 0x10);
  ASSERT_EQ(ZX_OK, trap.status_value(), "trap 0x10\n");

  // BSP VP on this thread.
  auto bsp_result = Vcpu::Create(*guest, kCodeGpa);
  ASSERT_EQ(ZX_OK, bsp_result.status_value(), "create BSP vcpu\n");
  ktl::unique_ptr<Vcpu> bsp = ktl::move(bsp_result.value());
  zx_port_packet_t p = {};
  ASSERT_EQ(ZX_OK, bsp->Enter(p).status_value(), "enter BSP\n");

  TscSkewContext ctx;
  ctx.guest = guest.get();

  // The AP VP runs its whole two-phase life on its own thread.
  auto ap_body = [](void* arg) -> int {
    auto* c = static_cast<TscSkewContext*>(arg);
    auto ap_result = Vcpu::Create(*c->guest, kCodeGpa);
    if (ap_result.is_error()) {
      c->status = ap_result.status_value();
      c->captured_ready.store(true);
      return 0;
    }
    ktl::unique_ptr<Vcpu> ap = ktl::move(ap_result.value());
    zx_port_packet_t pk = {};
    if (auto e = ap->Enter(pk); e.is_error()) {
      c->status = e.status_value();
      c->captured_ready.store(true);
      return 0;
    }
    // Phase 1: capture this VP's offset.
    zx_vcpu_tsc_state_t cap = {};
    if (auto r = ap->ReadTscState(cap); r.is_error()) {
      c->status = r.status_value();
      c->captured_ready.store(true);
      return 0;
    }
    c->captured_offset = cap.tsc_offset;
    c->captured_flags = cap.flags;
    c->captured_ready.store(true);
    // Wait for the BSP to compute the ONE partition offset.
    while (!c->go_restore.load()) {
      Thread::Current::Yield();
    }
    // Phase 2: install THAT SAME offset (verbatim) and read it back.
    zx_vcpu_tsc_state_t restore = {};
    restore.magic = ZX_VCPU_TSC_STATE_MAGIC;
    restore.version = ZX_VCPU_TSC_STATE_VERSION;
    restore.size = sizeof(zx_vcpu_tsc_state_t);
    restore.flags = ZX_VCPU_TSC_STATE_PRESENT | ZX_VCPU_TSC_STATE_OFFSETTING;
    restore.tsc_offset = c->partition_offset;
    if (auto w = ap->WriteTscState(restore); w.is_error()) {
      c->status = w.status_value();
      return 0;
    }
    zx_vcpu_tsc_state_t back = {};
    if (auto r = ap->ReadTscState(back); r.is_error()) {
      c->status = r.status_value();
      return 0;
    }
    c->restored_offset = back.tsc_offset;
    c->status = ZX_OK;
    return 0;
  };
  Thread* ap_thread = Thread::Create("hv-ap-tsc-skew", ap_body, &ctx, DEFAULT_PRIORITY);
  ASSERT_TRUE(ap_thread != nullptr, "create AP thread\n");
  ap_thread->Resume();

  // Wait for the AP's phase-1 capture.
  while (!ctx.captured_ready.load()) {
    Thread::Current::Yield();
  }

  // Capture the BSP's own offset. On a coherent partition the two captured
  // offsets are EQUAL -- the same guest clock behind two VPs, minus nothing,
  // because the offset does not depend on the (per-VP) sampling instant.
  zx_vcpu_tsc_state_t bsp_cap = {};
  ASSERT_EQ(ZX_OK, bsp->ReadTscState(bsp_cap).status_value(), "BSP ReadTscState\n");
  ASSERT_NE(0u, bsp_cap.flags & ZX_VCPU_TSC_STATE_OFFSETTING, "BSP OFFSETTING\n");
  ASSERT_NE(0u, ctx.captured_flags & ZX_VCPU_TSC_STATE_OFFSETTING, "AP OFFSETTING\n");
  EXPECT_EQ(bsp_cap.tsc_offset, ctx.captured_offset,
            "a coherent capture gives both VPs the same offset\n");

  // Partition restore: sample the host TSC ONCE, compute ONE offset from the BSP
  // anchor, and hand it to the AP.
  constexpr uint64_t kAnchor = 0x0000'4200'0000'0000ull;
  const int64_t partition_offset = static_cast<int64_t>(kAnchor - _rdtsc());
  ctx.partition_offset = partition_offset;
  // Install on the BSP immediately; release the AP AFTER a deliberate delay, so
  // the two installs happen at meaningfully different host instants. Under a
  // per-VP-RDTSC approach that spacing IS the skew; here it is inert.
  zx_vcpu_tsc_state_t bsp_restore = {};
  bsp_restore.magic = ZX_VCPU_TSC_STATE_MAGIC;
  bsp_restore.version = ZX_VCPU_TSC_STATE_VERSION;
  bsp_restore.size = sizeof(zx_vcpu_tsc_state_t);
  bsp_restore.flags = ZX_VCPU_TSC_STATE_PRESENT | ZX_VCPU_TSC_STATE_OFFSETTING;
  bsp_restore.tsc_offset = partition_offset;
  ASSERT_EQ(ZX_OK, bsp->WriteTscState(bsp_restore).status_value(), "BSP WriteTscState\n");
  const uint64_t spin_until = _rdtsc() + (uint64_t{1} << 22);  // ~4M cycles of separation.
  while (_rdtsc() < spin_until) {
    Thread::Current::Yield();
  }
  ctx.go_restore.store(true);

  int retcode = 0;
  ASSERT_EQ(ZX_OK, ap_thread->Join(&retcode, ZX_TIME_INFINITE), "join AP thread\n");
  ASSERT_EQ(ZX_OK, ctx.status, "AP two-phase run\n");

  // Read the BSP's installed offset back.
  zx_vcpu_tsc_state_t bsp_back = {};
  ASSERT_EQ(ZX_OK, bsp->ReadTscState(bsp_back).status_value(), "BSP ReadTscState back\n");

  // THE no-skew assertion: despite the spacing between the two installs, both
  // VPs carry the EXACT partition offset, so they read one coherent clock.
  EXPECT_EQ(partition_offset, bsp_back.tsc_offset, "BSP offset installed verbatim\n");
  EXPECT_EQ(partition_offset, ctx.restored_offset, "AP offset installed verbatim\n");
  EXPECT_EQ(bsp_back.tsc_offset, ctx.restored_offset,
            "both VPs share ONE offset -> no sequential-restore skew\n");

  printf("tsc-no-skew OK: 2 VPs, installs spaced ~%#lx cycles apart, both carry offset %#lx "
         "verbatim (diff=0) -> one coherent partition clock\n",
         uint64_t{1} << 22, static_cast<uint64_t>(partition_offset));

  END_TEST;
}
#else
bool vcpu_tsc_partition_no_skew() {
  BEGIN_TEST;
  printf("Not x86_64; skipping.\n");
  END_TEST;
}
#endif  // __x86_64__

// The asynchronous-state wire format is versioned independently of the
// architectural blob. This proves, WITHOUT a live guest (so it runs on every
// host, not only a VT-x one), that: (1) the current v7 layout round-trips
// including the ISR bitmap; (2) a released v6 buffer -- which predates the ISR
// field -- decodes into a well-formed current struct with an EMPTY ISR and every
// other field preserved, from BOTH an exact-size buffer and the released
// 4096-byte retained buffer; and (3) a v6 buffer with the wrong payload size, and
// an unknown version, are refused.
bool vcpu_async_state_codec_versions() {
  BEGIN_TEST;

  // Mirrors the anonymous-namespace constant kVcpuAsyncStateMagic in vcpu.cc,
  // which is not visible here. 'VASY'.
  constexpr uint32_t kAsyncMagic = 0x56415359;
  const size_t header_size = SerializedVcpuAsyncStateSize() - sizeof(VcpuAsyncState);

  // A source value with distinguishing fields AND ISR bits set (including the
  // legitimate word-0 vector 21).
  VcpuAsyncState src = {};
  src.lvt_timer = 0xABCD;
  src.lvt_initial_count = 0x1111;
  src.lvt_divide_config = 0x3;
  src.timer_armed = 1;
  src.timer_remaining_ns = 0x1234'5678u;
  src.pending_interrupts[0x33 / 8] |= static_cast<uint8_t>(1u << (0x33 % 8));
  src.isr[21 / 32] |= uint32_t{1} << (21 % 32);
  src.isr[0xff / 32] |= uint32_t{1} << (0xff % 32);
  src.pv_clock_enabled = 1;
  src.pv_clock_is_stable = 1;
  src.pv_clock_version = 9;
  src.pv_clock_guest_paddr = 0xF000u;

  // (1) v7 round-trip: SerializeVcpuAsyncState emits v7; deserialize restores it
  // exactly, ISR included.
  const size_t buf_len = SerializedVcpuAsyncStateSize();
  fbl::AllocChecker ac;
  ktl::unique_ptr<uint8_t[]> buf(new (&ac) uint8_t[buf_len]);
  ASSERT_TRUE(ac.check(), "alloc\n");
  ASSERT_EQ(ZX_OK, SerializeVcpuAsyncState(src, buf.get(), buf_len).status_value(),
            "serialize v7\n");
  // Header must carry version 7.
  uint32_t emitted_version = 0;
  memcpy(&emitted_version, buf.get() + sizeof(uint32_t), sizeof(emitted_version));
  EXPECT_EQ(7u, emitted_version, "async blob emitted as v7\n");
  VcpuAsyncState back = {};
  ASSERT_EQ(ZX_OK, DeserializeVcpuAsyncState(back, buf.get(), buf_len).status_value(),
            "deserialize v7\n");
  EXPECT_EQ(src.lvt_timer, back.lvt_timer, "v7 lvt_timer\n");
  EXPECT_EQ(src.timer_remaining_ns, back.timer_remaining_ns, "v7 timer_remaining\n");
  for (size_t i = 0; i < (sizeof(src.isr) / sizeof(src.isr[0])); i++) {
    EXPECT_EQ(src.isr[i], back.isr[i], "v7 isr word round-trips\n");
  }
  EXPECT_EQ(src.pv_clock_guest_paddr, back.pv_clock_guest_paddr, "v7 pv_clock_guest_paddr\n");

  // Build a v6 legacy payload from `src` by dropping the isr[] region: the bytes
  // before isr and the bytes from pv_clock_enabled to the end are laid out
  // identically in the v6 struct, so concatenating them reproduces the exact v6
  // payload the released producer emitted. offsetof on the CURRENT struct locates
  // the seam, so this stays correct if padding ever shifts.
  const size_t front_len = offsetof(VcpuAsyncState, isr);
  const size_t tail_begin = offsetof(VcpuAsyncState, pv_clock_enabled);
  const size_t tail_len = sizeof(VcpuAsyncState) - tail_begin;
  const size_t v6_payload_size = front_len + tail_len;

  auto build_v6 = [&](uint8_t* out, uint32_t payload_size_field) {
    memcpy(out, &kAsyncMagic, sizeof(kAsyncMagic));
    const uint32_t v6_version = 6;
    memcpy(out + sizeof(uint32_t), &v6_version, sizeof(v6_version));
    memcpy(out + 2 * sizeof(uint32_t), &payload_size_field, sizeof(payload_size_field));
    memcpy(out + header_size, &src, front_len);
    memcpy(out + header_size + front_len, reinterpret_cast<const uint8_t*>(&src) + tail_begin,
           tail_len);
  };

  // (2a) Exact-size v6 buffer decodes: fields preserved, ISR empty.
  const size_t v6_exact_len = header_size + v6_payload_size;
  ktl::unique_ptr<uint8_t[]> v6buf(new (&ac) uint8_t[v6_exact_len]);
  ASSERT_TRUE(ac.check(), "alloc v6\n");
  build_v6(v6buf.get(), static_cast<uint32_t>(v6_payload_size));
  VcpuAsyncState from_v6 = {};
  ASSERT_EQ(ZX_OK, DeserializeVcpuAsyncState(from_v6, v6buf.get(), v6_exact_len).status_value(),
            "decode exact-size v6\n");
  EXPECT_EQ(src.lvt_timer, from_v6.lvt_timer, "v6 lvt_timer preserved\n");
  EXPECT_EQ(src.timer_remaining_ns, from_v6.timer_remaining_ns, "v6 timer preserved\n");
  EXPECT_TRUE((from_v6.pending_interrupts[0x33 / 8] & (1u << (0x33 % 8))) != 0,
              "v6 pending bit preserved\n");
  EXPECT_EQ(src.pv_clock_guest_paddr, from_v6.pv_clock_guest_paddr, "v6 pv_clock preserved\n");
  for (size_t i = 0; i < (sizeof(from_v6.isr) / sizeof(from_v6.isr[0])); i++) {
    EXPECT_EQ(0u, from_v6.isr[i], "v6 decode leaves ISR empty\n");
  }

  // (2b) The released 4096-byte retained buffer (v6 header + payload, zero-padded
  // to 4096) decodes identically; only the leading payload bytes are read.
  constexpr size_t kRetained = 4096;
  ASSERT_TRUE(kRetained >= v6_exact_len, "retained buffer covers payload\n");
  ktl::unique_ptr<uint8_t[]> v6pad(new (&ac) uint8_t[kRetained]);
  ASSERT_TRUE(ac.check(), "alloc v6 padded\n");
  memset(v6pad.get(), 0, kRetained);
  build_v6(v6pad.get(), static_cast<uint32_t>(v6_payload_size));
  VcpuAsyncState from_v6pad = {};
  ASSERT_EQ(ZX_OK, DeserializeVcpuAsyncState(from_v6pad, v6pad.get(), kRetained).status_value(),
            "decode 4096-byte retained v6\n");
  EXPECT_EQ(src.lvt_timer, from_v6pad.lvt_timer, "retained v6 lvt_timer preserved\n");
  EXPECT_EQ(src.pv_clock_guest_paddr, from_v6pad.pv_clock_guest_paddr,
            "retained v6 pv_clock preserved\n");

  // (3) A v6 buffer whose payload_size field is wrong is refused, and an unknown
  // version is refused.
  ktl::unique_ptr<uint8_t[]> v6bad(new (&ac) uint8_t[v6_exact_len]);
  ASSERT_TRUE(ac.check(), "alloc v6 bad\n");
  build_v6(v6bad.get(), static_cast<uint32_t>(v6_payload_size + 1));
  VcpuAsyncState reject_a = {};
  EXPECT_EQ(ZX_ERR_INVALID_ARGS,
            DeserializeVcpuAsyncState(reject_a, v6bad.get(), v6_exact_len).status_value(),
            "v6 wrong payload_size refused\n");
  const uint32_t bad_version = 5;
  memcpy(v6bad.get() + sizeof(uint32_t), &bad_version, sizeof(bad_version));
  memcpy(v6bad.get() + 2 * sizeof(uint32_t), &v6_payload_size, sizeof(uint32_t));
  VcpuAsyncState reject_b = {};
  EXPECT_EQ(ZX_ERR_INVALID_ARGS,
            DeserializeVcpuAsyncState(reject_b, v6bad.get(), v6_exact_len).status_value(),
            "unknown async version refused\n");

  printf("async-state codec OK: v7 ISR round-trips; v6 legacy decodes (exact + 4096B) with "
         "empty ISR; bad payload_size and unknown version refused\n");

  END_TEST;
}

// WI-1.2 (injection reachability): a maskable external interrupt injected via
// Vcpu::Interrupt() is delivered to the guest's IDT handler once the guest is
// interruptible (IF=1). This is the LAPIC vector-delivery primitive a userspace
// VMM layers MSI/IOAPIC routing on top of — that routing is decoded in
// userspace, not the kernel. Delivery *reliability* under load and any APIC-
// virtualization path are hardware-timing-sensitive and gated to bare metal;
// this proves single-shot reachability of the injection path.
bool vcpu_maskable_interrupt_reaches_handler() {
  BEGIN_TEST;

#ifdef __x86_64__
  auto guest_result = Guest::Create();
  if (guest_result.is_error() && guest_result.status_value() == ZX_ERR_NOT_SUPPORTED) {
    printf("VMX not supported here; skipping interrupt-injection test.\n");
    return true;
  }
  ASSERT_EQ(ZX_OK, guest_result.status_value(), "Guest::Create failed\n");
  ktl::unique_ptr<Guest> guest = ktl::move(guest_result.value());

  constexpr uint64_t kGdtGpa = 0x6000;
  constexpr uint64_t kIdtGpa = 0x6800;
  constexpr uint64_t kHandlerGpa = 0x8000;
  constexpr uint64_t kStackTop = 0x9000;
  constexpr uint32_t kVector = 0x50;  // in [0x20, 0xef], an injectable platform vector.

  fbl::RefPtr<VmObjectPaged> golden;
  ASSERT_EQ(ZX_OK, VmObjectPaged::Create(PMM_ALLOC_FLAG_ANY, 0u, kGuestRamSize, &golden), "golden\n");
  ASSERT_EQ(ZX_OK, WriteIdentityTables(golden), "tables\n");

  // Guest: enable interrupts, exit once (so the host injects while the guest is
  // interruptible), then spin — the injected interrupt vectors out of the spin.
  //   FB     sti
  //   90     nop            ; clear the 1-instruction STI shadow
  //   E6 10  out 0x10, al   ; exit #1
  //   EB FE  jmp $          ; spin until interrupted
  const uint8_t code[] = {0xFB, 0x90, 0xE6, 0x10, 0xEB, 0xFE};
  ASSERT_EQ(ZX_OK, golden->Write(code, kCodeGpa, sizeof(code)), "code\n");

  // GDT[1] = flat 64-bit code segment (selector 0x08).
  const uint8_t gdt_code[8] = {0xFF, 0xFF, 0x00, 0x00, 0x00, 0x9B, 0xAF, 0x00};
  ASSERT_EQ(ZX_OK, golden->Write(gdt_code, kGdtGpa + 8, sizeof(gdt_code)), "GDT code desc\n");

  // IDT gate for kVector: 64-bit interrupt gate, selector 0x08, offset=handler.
  const uint8_t idt_gate[16] = {
      static_cast<uint8_t>(kHandlerGpa & 0xFF), static_cast<uint8_t>((kHandlerGpa >> 8) & 0xFF),
      0x08, 0x00, 0x00, 0x8E, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
  ASSERT_EQ(ZX_OK, golden->Write(idt_gate, kIdtGpa + kVector * 16, sizeof(idt_gate)), "IDT gate\n");

  // Handler: mov al,0x66; out 0x30,al; hlt.
  const uint8_t handler[] = {0xB0, 0x66, 0xE6, 0x30, 0xF4};
  ASSERT_EQ(ZX_OK, golden->Write(handler, kHandlerGpa, sizeof(handler)), "handler\n");
  ASSERT_EQ(ZX_OK, golden->CommitRange(0, kGuestRamSize), "commit\n");

  auto mapping = guest->RootVmar()->CreateVmMapping(0, kGuestRamSize, 0, VMAR_FLAG_SPECIFIC, golden,
                                                    0, kMmuFlags, "guest-ram");
  ASSERT_EQ(ZX_OK, mapping.status_value(), "map\n");
  auto t1 = guest->SetTrap(ZX_GUEST_TRAP_IO, 0x10, 1, nullptr, 0x10);
  ASSERT_EQ(ZX_OK, t1.status_value(), "trap 0x10\n");
  auto t2 = guest->SetTrap(ZX_GUEST_TRAP_IO, 0x30, 1, nullptr, 0x30);
  ASSERT_EQ(ZX_OK, t2.status_value(), "trap 0x30\n");

  auto vcpu_result = Vcpu::Create(*guest, kCodeGpa);
  ASSERT_EQ(ZX_OK, vcpu_result.status_value(), "Vcpu::Create\n");
  ktl::unique_ptr<Vcpu> vcpu = ktl::move(vcpu_result.value());

  VcpuArchState s = {};
  ASSERT_EQ(ZX_OK, vcpu->SaveArchState(s).status_value(), "SaveArchState\n");
  s.gdtr_base = kGdtGpa;
  s.gdtr_limit = 0x0F;
  s.idtr_base = kIdtGpa;
  s.idtr_limit = 0xFFF;
  s.regs.rsp = kStackTop;
  ASSERT_EQ(ZX_OK, vcpu->RestoreArchState(s).status_value(), "load GDTR/IDTR/RSP\n");

  // Run until the guest has enabled interrupts and is spinning.
  zx_port_packet_t p = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(p).status_value(), "enter #1\n");
  ASSERT_EQ(0x10u, p.guest_io.port, "expected the pre-spin exit on 0x10\n");

  // Inject the maskable interrupt; the next entry must deliver it to the handler.
  ASSERT_EQ(ZX_OK, vcpu->Interrupt(kVector).status_value(), "inject vector\n");
  zx_port_packet_t handled = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(handled).status_value(), "enter #2 (deliver)\n");
  ASSERT_EQ(static_cast<uint8_t>(ZX_PKT_TYPE_GUEST_IO), static_cast<uint8_t>(handled.type), "io\n");
  EXPECT_EQ(0x30u, handled.guest_io.port, "handler port\n");
  EXPECT_EQ(0x66u, static_cast<uint32_t>(handled.guest_io.data[0]),
            "guest IDT handler for the injected vector must have run\n");
  printf("interrupt-injection OK: Vcpu::Interrupt(%#x) vectored through the guest IDT; "
         "handler ran (0x%x)\n",
         kVector, handled.guest_io.data[0]);
#else
  printf("Not x86_64; skipping.\n");
#endif  // __x86_64__

  END_TEST;
}

// -----------------------------------------------------------------------------
// HLT-WAKE ATTRIBUTION INSTRUMENT (serializer investigation, 2026-08).
//
// Question under measurement: when a VCPU is *parked* in `handle_hlt`'s
// `InterruptTracker::Wait(ZX_TIME_INFINITE)` and another thread calls
// `Vcpu::Interrupt()` -- the exact shape of a VMBus SINT delivery from the
// worker's completion path -- does the VCPU wake promptly, or does the vector
// only sit pending until something else (a timer kick) happens to end the wait?
//
// The static trace says `InterruptTracker::Interrupt` signals the same event
// the HLT wait blocks on (interrupt_tracker.h), so the wake should be prompt
// and tick-independent. This test turns that from inference into a number, and
// its negative control turns "there is no tick in the kernel HLT wait" into an
// assertion: a parked, un-interrupted VP must still be parked 120 ms later.
//
// Red-first shape: if the wake path were pending-only (the hypothesized bug),
// the parking entry would never return; the helper's watchdog Kick() unwedges
// the thread and the test FAILS on `watchdog_fired` -- so the instrument can
// go red, and what it measures is exactly the thing under suspicion.
// -----------------------------------------------------------------------------

constexpr uint32_t kHltWakeIters = 64;
// Which iteration doubles as the negative control (120 ms of deliberate
// silence before the injection, asserting the parked VP did not wake by
// itself). Not the first or last, so it sits between ordinary iterations.
constexpr uint32_t kHltWakeControlIter = 3;
constexpr uint32_t kHltWakeVector = 0x50;

struct HltWakeShared {
  Vcpu* vcpu = nullptr;
  // 0: idle. 2*i+1: main has taken iteration i's "about to halt" exit and the
  // next entry parks in HLT. 2*i+2: iteration i's handler exit came back.
  ktl::atomic<uint32_t> phase{0};
  // When the helper called Vcpu::Interrupt(), on the monotonic clock the main
  // thread also reads. Written before the injection, so the measured latency
  // includes the injection syscall itself -- the shape a SINT delivery has.
  ktl::atomic<zx_instant_mono_t> inject_time{0};
  ktl::atomic<bool> inject_failed{false};
  ktl::atomic<bool> watchdog_fired{false};
  ktl::atomic<bool> control_stayed_parked{false};
};

int HltWakeHelperBody(void* arg) {
  auto* sh = static_cast<HltWakeShared*>(arg);
  for (uint32_t i = 0; i < kHltWakeIters; i++) {
    const uint32_t ready = 2 * i + 1;
    const uint32_t woke = 2 * i + 2;
    zx_instant_mono_t deadline = current_mono_time() + ZX_SEC(10);
    while (sh->phase.load(ktl::memory_order_acquire) < ready) {
      if (current_mono_time() > deadline) {
        sh->watchdog_fired.store(true, ktl::memory_order_release);
        sh->vcpu->Kick();
        return -1;
      }
      Thread::Current::SleepRelative(ZX_USEC(100));
    }
    // Let the VP actually reach and execute HLT: the announcing exit returns
    // to the main thread *before* the parking entry, and the injection must
    // land on a parked VP, not race the entry. Microseconds would do; 5 ms
    // keeps scheduling noise out of the claim without slowing the suite.
    Thread::Current::SleepRelative(ZX_MSEC(5));
    if (i == kHltWakeControlIter) {
      // NEGATIVE CONTROL. An idle parked VP gets no interrupt for 120 ms --
      // roughly eight of the 15.6 ms ticks the investigated workload shows.
      // If the kernel HLT wait had any tick of its own, or HLT fell through
      // spuriously, the guest would reach the handler exit (or the next
      // "about to halt" exit) and phase would have advanced.
      Thread::Current::SleepRelative(ZX_MSEC(120));
      sh->control_stayed_parked.store(sh->phase.load(ktl::memory_order_acquire) == ready,
                                      ktl::memory_order_release);
    }
    sh->inject_time.store(current_mono_time(), ktl::memory_order_release);
    if (sh->vcpu->Interrupt(kHltWakeVector).is_error()) {
      sh->inject_failed.store(true, ktl::memory_order_release);
      sh->vcpu->Kick();
      return -1;
    }
    // Watchdog: the red arm. A wake that never comes leaves the main thread
    // parked inside Enter forever; Kick() unwedges it so the suite can fail
    // loudly instead of hanging.
    deadline = current_mono_time() + ZX_SEC(3);
    while (sh->phase.load(ktl::memory_order_acquire) < woke) {
      if (current_mono_time() > deadline) {
        sh->watchdog_fired.store(true, ktl::memory_order_release);
        sh->vcpu->Kick();
        return -1;
      }
      Thread::Current::SleepRelative(ZX_USEC(100));
    }
  }
  return 0;
}

bool vcpu_interrupt_wakes_halted_vcpu() {
  BEGIN_TEST;

#ifdef __x86_64__
  auto guest_result = Guest::Create();
  if (guest_result.is_error() && guest_result.status_value() == ZX_ERR_NOT_SUPPORTED) {
    printf("VMX not supported here; skipping HLT-wake latency test.\n");
    return true;
  }
  ASSERT_EQ(ZX_OK, guest_result.status_value(), "Guest::Create failed\n");
  ktl::unique_ptr<Guest> guest = ktl::move(guest_result.value());

  constexpr uint64_t kGdtGpa = 0x6000;
  constexpr uint64_t kIdtGpa = 0x6800;
  constexpr uint64_t kHandlerGpa = 0x8000;
  constexpr uint64_t kStackTop = 0x9000;

  fbl::RefPtr<VmObjectPaged> ram;
  ASSERT_EQ(ZX_OK, VmObjectPaged::Create(PMM_ALLOC_FLAG_ANY, 0u, kGuestRamSize, &ram), "ram\n");
  ASSERT_EQ(ZX_OK, WriteIdentityTables(ram), "tables\n");

  // Guest loop: announce, halt, repeat. Each round trip is one parked wake.
  //   FB           sti
  //   90           nop            ; clear the STI shadow
  // loop_top (kCodeGpa+2):
  //   B0 A1        mov al, 0xA1
  //   E6 10        out 0x10, al   ; "about to halt"
  //   F4           hlt            ; park in handle_hlt's infinite Wait
  //   EB F9        jmp loop_top   ; reached via the handler's jmp, next round
  const uint8_t code[] = {0xFB, 0x90, 0xB0, 0xA1, 0xE6, 0x10, 0xF4, 0xEB, 0xF9};
  ASSERT_EQ(ZX_OK, ram->Write(code, kCodeGpa, sizeof(code)), "code\n");

  // GDT[1] = flat 64-bit code segment (selector 0x08).
  const uint8_t gdt_code[8] = {0xFF, 0xFF, 0x00, 0x00, 0x00, 0x9B, 0xAF, 0x00};
  ASSERT_EQ(ZX_OK, ram->Write(gdt_code, kGdtGpa + 8, sizeof(gdt_code)), "GDT code desc\n");

  // IDT gate for kHltWakeVector: 64-bit interrupt gate, selector 0x08,
  // offset = kHandlerGpa (0x8000: low byte 0x00, second byte 0x80).
  const uint8_t idt_gate[16] = {0x00, 0x80, 0x08, 0x00, 0x00, 0x8E, 0x00, 0x00,
                                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
  ASSERT_EQ(ZX_OK, ram->Write(idt_gate, kIdtGpa + kHltWakeVector * 16, sizeof(idt_gate)),
            "IDT gate\n");

  // Handler: report the wake, EOI (the in-service register would otherwise
  // hold the *next* injection of this same vector back forever), re-enable
  // delivery, and resume the loop. `jmp` rather than `iretq`: the two-entry
  // GDT has nothing to reload SS from (see RewriteHandlersToResumeLoop's
  // comment further down this file for the #GP that teaches).
  //   B0 66             mov al, 0x66
  //   E6 30             out 0x30, al   ; "woke via the handler"
  //   B9 0B 08 00 00    mov ecx, 0x80B ; x2APIC EOI
  //   31 C0             xor eax, eax
  //   31 D2             xor edx, edx
  //   0F 30             wrmsr
  //   FB                sti            ; the interrupt gate cleared IF
  //   E9 ED AF FF FF    jmp loop_top   ; 0x3002 - (0x8010 + 5) = -0x5013
  const uint8_t handler[] = {0xB0, 0x66, 0xE6, 0x30, 0xB9, 0x0B, 0x08, 0x00, 0x00, 0x31, 0xC0,
                             0x31, 0xD2, 0x0F, 0x30, 0xFB, 0xE9, 0xED, 0xAF, 0xFF, 0xFF};
  ASSERT_EQ(ZX_OK, ram->Write(handler, kHandlerGpa, sizeof(handler)), "handler\n");
  ASSERT_EQ(ZX_OK, ram->CommitRange(0, kGuestRamSize), "commit\n");

  auto mapping = guest->RootVmar()->CreateVmMapping(0, kGuestRamSize, 0, VMAR_FLAG_SPECIFIC, ram,
                                                    0, kMmuFlags, "guest-ram");
  ASSERT_EQ(ZX_OK, mapping.status_value(), "map\n");
  auto t1 = guest->SetTrap(ZX_GUEST_TRAP_IO, 0x10, 1, nullptr, 0x10);
  ASSERT_EQ(ZX_OK, t1.status_value(), "trap 0x10\n");
  auto t2 = guest->SetTrap(ZX_GUEST_TRAP_IO, 0x30, 1, nullptr, 0x30);
  ASSERT_EQ(ZX_OK, t2.status_value(), "trap 0x30\n");

  auto vcpu_result = Vcpu::Create(*guest, kCodeGpa);
  ASSERT_EQ(ZX_OK, vcpu_result.status_value(), "Vcpu::Create\n");
  ktl::unique_ptr<Vcpu> vcpu = ktl::move(vcpu_result.value());

  VcpuArchState s = {};
  ASSERT_EQ(ZX_OK, vcpu->SaveArchState(s).status_value(), "SaveArchState\n");
  s.gdtr_base = kGdtGpa;
  s.gdtr_limit = 0x0F;
  s.idtr_base = kIdtGpa;
  s.idtr_limit = 0xFFF;
  s.regs.rsp = kStackTop;
  ASSERT_EQ(ZX_OK, vcpu->RestoreArchState(s).status_value(), "load GDTR/IDTR/RSP\n");

  HltWakeShared shared;
  shared.vcpu = vcpu.get();
  Thread* helper = Thread::Create("hv-hlt-wake-inject", HltWakeHelperBody, &shared,
                                  DEFAULT_PRIORITY);
  ASSERT_TRUE(helper != nullptr, "create helper thread\n");
  helper->Resume();

  zx_duration_t lat_min = ZX_TIME_INFINITE;
  zx_duration_t lat_max = 0;
  zx_duration_t lat_sum = 0;
  uint32_t over_1ms = 0;
  uint32_t over_10ms = 0;
  bool run_ok = true;

  for (uint32_t i = 0; i < kHltWakeIters && run_ok; i++) {
    // The announcing exit: the guest is about to halt.
    zx_port_packet_t announce = {};
    auto enter_a = vcpu->Enter(announce);
    if (enter_a.is_error() || announce.guest_io.port != 0x10) {
      // A CANCELED here means the helper's watchdog already gave up.
      run_ok = false;
      break;
    }
    shared.phase.store(2 * i + 1, ktl::memory_order_release);

    // The parking entry. This blocks in handle_hlt's Wait until the helper's
    // Interrupt() -- or its watchdog Kick(), which is the failure arm.
    zx_port_packet_t woke = {};
    auto enter_b = vcpu->Enter(woke);
    const zx_instant_mono_t t_wake = current_mono_time();
    if (enter_b.is_error() || woke.guest_io.port != 0x30 ||
        static_cast<uint32_t>(woke.guest_io.data[0]) != 0x66u) {
      run_ok = false;
      break;
    }
    const zx_duration_t lat =
        zx_time_sub_time(t_wake, shared.inject_time.load(ktl::memory_order_acquire));
    if (lat < lat_min) {
      lat_min = lat;
    }
    if (lat > lat_max) {
      lat_max = lat;
    }
    lat_sum = zx_duration_add_duration(lat_sum, lat);
    if (lat > ZX_MSEC(1)) {
      over_1ms++;
    }
    if (lat > ZX_MSEC(10)) {
      over_10ms++;
    }
    shared.phase.store(2 * i + 2, ktl::memory_order_release);
  }

  int helper_ret = -1;
  ASSERT_EQ(ZX_OK, helper->Join(&helper_ret, ZX_TIME_INFINITE), "join helper\n");

  ASSERT_TRUE(!shared.inject_failed.load(), "Vcpu::Interrupt refused a wake vector\n");
  ASSERT_TRUE(!shared.watchdog_fired.load(),
              "THE HYPOTHESIZED BUG: a parked VCPU did not wake on Vcpu::Interrupt() within 3 s; "
              "the vector sat pending until the watchdog Kick\n");
  ASSERT_TRUE(run_ok, "every iteration must come back through the guest's own handler\n");
  ASSERT_EQ(0, helper_ret, "helper thread reported a failure\n");
  ASSERT_TRUE(shared.control_stayed_parked.load(),
              "negative control: a parked VP with no interrupt woke by itself within 120 ms -- "
              "the kernel HLT wait is NOT tickless, or HLT fell through\n");
  // Correctness bound, deliberately loose: nested-KVM scheduling can add
  // milliseconds of noise, and the numbers printed below are the measurement.
  // What this asserts is the *mechanism*: a parked wake is event-driven, not
  // quantized to any tick.
  EXPECT_TRUE(lat_max < ZX_SEC(1), "a parked wake took over a second\n");

  printf("CERISE-HLT-WAKE: iters=%u min=%ld ns avg=%ld ns max=%ld ns over_1ms=%u over_10ms=%u "
         "control_120ms=still-parked\n",
         kHltWakeIters, lat_min, lat_sum / kHltWakeIters, lat_max, over_1ms, over_10ms);
#else
  printf("Not x86_64; skipping.\n");
#endif  // __x86_64__

  END_TEST;
}

// The tracker-level half of the same attribution, runnable with no VMX at all.
//
// `InterruptTracker::Wait` blocks on its event *before* it tests `Pending()`
// (interrupt_tracker.h), so the two ways a vector can arrive differ in exactly
// one observable: `Interrupt()` (Track + Signal) ends a wait immediately, while
// a bare `Track()` -- the window-blocked requeue path in vcpu.cc, and the tail
// of the documented Cancel-clobbers-Signal race -- leaves a *pending, wanted*
// vector invisible to a wait that starts afterwards.
//
// The first block asserts the healthy flavor. The second PINS the defective
// flavor as it behaves today, so this suite stays green while the defect is
// tracked; the planned kernel fix (test Pending() before the first block, per
// the comment at vcpu.cc's deferral path) flips the pinned assertion, and THAT
// flip is the fix's red-first gate.
bool interrupt_tracker_signal_vs_track_wake() {
  BEGIN_TEST;

  constexpr uint32_t kVector = 0x51;

  // Signalled flavor: a Wait that starts after Interrupt() must not sleep.
  {
    hypervisor::InterruptTracker<X86_INT_COUNT> tracker;
    ASSERT_EQ(ZX_OK, tracker.Interrupt(kVector).status_value(), "Interrupt\n");
    const zx_instant_mono_t t0 = current_mono_time();
    ASSERT_EQ(ZX_OK, tracker.Wait(zx_time_add_duration(t0, ZX_SEC(5)), nullptr).status_value(),
              "signalled wait\n");
    const zx_duration_t elapsed = zx_time_sub_time(current_mono_time(), t0);
    EXPECT_TRUE(elapsed < ZX_MSEC(500),
                "a vector deposited with its signal must end the wait promptly\n");
    printf("CERISE-TRACKER-WAKE: Interrupt()-flavor wait returned in %ld ns\n", elapsed);
  }

  // Track-only flavor: the same pending vector, minus the signal. Today the
  // wait sleeps through its whole deadline with the vector already in the
  // bitmap -- the "pending bit set" vs "blocked thread woken" distinction.
  {
    hypervisor::InterruptTracker<X86_INT_COUNT> tracker;
    ASSERT_EQ(ZX_OK, tracker.Track(kVector).status_value(), "Track\n");
    ASSERT_TRUE(tracker.Pending(), "the vector is pending before the wait begins\n");
    constexpr zx_duration_t kDeadline = ZX_MSEC(200);
    const zx_instant_mono_t t0 = current_mono_time();
    ASSERT_EQ(ZX_OK,
              tracker.Wait(zx_time_add_duration(t0, kDeadline), nullptr).status_value(),
              "track-only wait\n");
    const zx_duration_t elapsed = zx_time_sub_time(current_mono_time(), t0);
    printf("CERISE-TRACKER-WAKE: Track()-only wait slept %ld ns of its %ld ns deadline with the "
           "vector pending the whole time (DEFECT PINNED; the Wait-tests-Pending-first fix flips "
           "this assertion)\n",
           elapsed, kDeadline);
    // PINNED DEFECT -- flip to `elapsed < kDeadline / 2` with the kernel fix.
    EXPECT_TRUE(elapsed >= kDeadline, "current Wait blocks before testing Pending()\n");
    EXPECT_TRUE(tracker.Pending(), "the slept-through vector is still there\n");
  }

  END_TEST;
}

// Carries an AP vcpu run across to a dedicated kernel thread and back: the
// thread creates + enters the AP vcpu and records the outcome here.
struct ApRunContext {
  Guest* guest;
  uint64_t entry;
  zx_status_t create_status;
  zx_status_t enter_status;
  zx_port_packet_t packet;
};

// WI-1.3 (AP startup): the kernel's half of bringing up an application
// processor. The guest BSP writes a STARTUP IPI to the x2APIC ICR; the
// hypervisor traps it and surfaces a ZX_PKT_TYPE_GUEST_VCPU/STARTUP packet
// carrying the AP id and entry point (INIT IPIs are absorbed — only STARTUP
// brings a VCPU up). Acting on that packet is userspace orchestration: a Vcpu
// binds one-per-thread (Vcpu::Create returns ZX_ERR_BAD_STATE if the calling
// thread already owns a vcpu), so the AP is created and run on its *own* thread.
// This test drives the whole path: the BSP's SIPI is decoded to the correct id
// and entry, and the AP vcpu is then created + entered on a dedicated kernel
// thread and runs its guest code (reporting via I/O).
bool vcpu_ap_startup_sipi() {
  BEGIN_TEST;

#ifdef __x86_64__
  auto guest_result = Guest::Create();
  if (guest_result.is_error() && guest_result.status_value() == ZX_ERR_NOT_SUPPORTED) {
    printf("VMX not supported here; skipping AP-startup test.\n");
    return true;
  }
  ASSERT_EQ(ZX_OK, guest_result.status_value(), "Guest::Create failed\n");
  ktl::unique_ptr<Guest> guest = ktl::move(guest_result.value());

  constexpr uint64_t kApEntryGpa = 0x7000;  // vector 0x07 << 12.
  constexpr uint32_t kApId = 1;

  fbl::RefPtr<VmObjectPaged> ram;
  ASSERT_EQ(ZX_OK, VmObjectPaged::Create(PMM_ALLOC_FLAG_ANY, 0u, kGuestRamSize, &ram), "ram\n");
  ASSERT_EQ(ZX_OK, WriteIdentityTables(ram), "tables\n");
  // BSP: send a STARTUP IPI to AP id 1, entry 0x7000, via the x2APIC ICR.
  //   B9 30 08 00 00  mov ecx, 0x830  ; ICR MSR
  //   B8 07 06 00 00  mov eax, 0x607  ; vector=7 (0x7000>>12) | STARTUP(6)<<8, physical
  //   BA 01 00 00 00  mov edx, 1      ; destination APIC id 1
  //   0F 30           wrmsr           ; trapped -> GUEST_VCPU STARTUP exit
  //   F4              hlt
  const uint8_t bsp[] = {0xB9, 0x30, 0x08, 0x00, 0x00, 0xB8, 0x07, 0x06, 0x00,
                         0x00, 0xBA, 0x01, 0x00, 0x00, 0x00, 0x0F, 0x30, 0xF4};
  ASSERT_EQ(ZX_OK, ram->Write(bsp, kCodeGpa, sizeof(bsp)), "bsp code\n");
  // AP: mov al,0x77; out 0x31,al; hlt.
  const uint8_t ap[] = {0xB0, 0x77, 0xE6, 0x31, 0xF4};
  ASSERT_EQ(ZX_OK, ram->Write(ap, kApEntryGpa, sizeof(ap)), "ap code\n");
  ASSERT_EQ(ZX_OK, ram->CommitRange(0, kGuestRamSize), "commit\n");

  auto mapping = guest->RootVmar()->CreateVmMapping(0, kGuestRamSize, 0, VMAR_FLAG_SPECIFIC, ram, 0,
                                                    kMmuFlags, "guest-ram");
  ASSERT_EQ(ZX_OK, mapping.status_value(), "map\n");
  auto ap_trap = guest->SetTrap(ZX_GUEST_TRAP_IO, 0x31, 1, nullptr, 0x31);
  ASSERT_EQ(ZX_OK, ap_trap.status_value(), "trap 0x31\n");

  // BSP vcpu: run until it issues the STARTUP IPI.
  auto bsp_result = Vcpu::Create(*guest, kCodeGpa);
  ASSERT_EQ(ZX_OK, bsp_result.status_value(), "create BSP vcpu\n");
  ktl::unique_ptr<Vcpu> bsp_vcpu = ktl::move(bsp_result.value());
  zx_port_packet_t sipi = {};
  ASSERT_EQ(ZX_OK, bsp_vcpu->Enter(sipi).status_value(), "enter BSP\n");
  ASSERT_EQ(static_cast<uint8_t>(ZX_PKT_TYPE_GUEST_VCPU), static_cast<uint8_t>(sipi.type),
            "expected a GUEST_VCPU exit\n");
  EXPECT_EQ(static_cast<uint32_t>(ZX_PKT_GUEST_VCPU_STARTUP), sipi.guest_vcpu.type,
            "expected a STARTUP packet\n");
  EXPECT_EQ(static_cast<uint64_t>(kApId), sipi.guest_vcpu.startup.id, "AP id decoded\n");
  EXPECT_EQ(static_cast<uint64_t>(kApEntryGpa), sipi.guest_vcpu.startup.entry, "AP entry decoded\n");

  // A vcpu binds one-per-thread: creating the AP on this thread (which already
  // owns the BSP vcpu) is refused. This is why the AP runs on its own thread.
  auto ap_same_thread = Vcpu::Create(*guest, sipi.guest_vcpu.startup.entry);
  EXPECT_EQ(ZX_ERR_BAD_STATE, ap_same_thread.status_value(),
            "a thread already owning a vcpu must not create a second\n");

  // Play the userspace role: run the AP vcpu on its own kernel thread, entering
  // at the decoded startup entry. The thread creates the AP vcpu (binding it to
  // that thread), runs it to its first I/O exit, and records the result; the AP
  // vcpu is torn down on its own thread when the closure returns.
  ApRunContext ctx = {guest.get(), sipi.guest_vcpu.startup.entry, ZX_ERR_INTERNAL, ZX_ERR_INTERNAL,
                      {}};
  auto ap_body = [](void* arg) -> int {
    auto* c = reinterpret_cast<ApRunContext*>(arg);
    auto ap_result = Vcpu::Create(*c->guest, c->entry);
    c->create_status = ap_result.status_value();
    if (ap_result.is_error()) {
      return 0;
    }
    ktl::unique_ptr<Vcpu> ap_vcpu = ktl::move(ap_result.value());
    c->enter_status = ap_vcpu->Enter(c->packet).status_value();
    return 0;
  };
  Thread* ap_thread = Thread::Create("hv-ap-vcpu", ap_body, &ctx, DEFAULT_PRIORITY);
  ASSERT_TRUE(ap_thread != nullptr, "create AP thread\n");
  ap_thread->Resume();
  int retcode = 0;
  ASSERT_EQ(ZX_OK, ap_thread->Join(&retcode, ZX_TIME_INFINITE), "join AP thread\n");

  ASSERT_EQ(ZX_OK, ctx.create_status, "AP Vcpu::Create on its own thread\n");
  ASSERT_EQ(ZX_OK, ctx.enter_status, "AP Enter\n");
  ASSERT_EQ(static_cast<uint8_t>(ZX_PKT_TYPE_GUEST_IO), static_cast<uint8_t>(ctx.packet.type),
            "AP I/O exit\n");
  EXPECT_EQ(0x31u, ctx.packet.guest_io.port, "AP port\n");
  EXPECT_EQ(0x77u, static_cast<uint32_t>(ctx.packet.guest_io.data[0]),
            "the AP vcpu must have run its guest code\n");
  printf("AP-startup OK: BSP SIPI decoded to STARTUP(id=%lu, entry=%#lx); AP vcpu ran on its own "
         "thread and reported 0x%x\n",
         sipi.guest_vcpu.startup.id, sipi.guest_vcpu.startup.entry, ctx.packet.guest_io.data[0]);
#else
  printf("Not x86_64; skipping.\n");
#endif  // __x86_64__

  END_TEST;
}

// --- An AP that boots itself from real mode into long mode -------------------
//
// THE SMP GATE. `vcpu_ap_startup_sipi` above proves a second VP starts and runs
// guest code, but the code it runs is 16-bit real-mode code that never changes
// processor mode -- so nothing in this suite has ever driven the one path that
// only a second VP can reach: the real -> protected -> long mode transition an
// AP performs after its SIPI. That path fails if paging changes are not trapped,
// and a single-vCPU test cannot see it because `vmcs_init` hands the BSP long
// mode ready-made (`kEntryCtls64bitMode`, `vcpu.cc`).
//
// The failure mechanism, restated so the assertions below can be read against
// it. `CR0_GUEST_HOST_MASK` used to hold only ET|NE|NW|CD, so a guest write to
// `CR0.PG` did not exit. `handle_cr0_write` -- the only code that sets
// `EFER.LMA` and the IA-32e-mode-guest VM-entry control -- therefore never ran.
// The processor sets LMA itself when the guest turns on paging with LME set, the
// save-IA32_EFER exit control copies it into `GUEST_IA32_EFER` at the next exit,
// and the NEXT VM entry fails Volume 3 Section 26.3.1.1's "LMA must equal the
// IA-32e-mode-guest VM-entry control" check. That is a VM-entry failure due to
// invalid guest state: exit reason 33, which this kernel reports as a
// ZX_PKT_TYPE_GUEST_HALT.
//
// So this AP does what a real AP trampoline does -- LGDT, CR4.PAE, EFER.LME,
// CR3, then PE|PG in one `mov cr0`, then a far jump to a 64-bit code segment of
// its own making -- and reports four things through I/O ports, each measured BY
// THE GUEST rather than read back out of the VMCS by the host:
//
//   0x30  reached compatibility mode: the `mov cr0` with PE|PG retired.
//   0x32  0xA5, obtained by `movabs $0xA5<<40; shr $40` -- a 64-bit operand
//         width, which no other mode can produce.
//   0x33  8, the number of bytes one `push` moved RSP -- the architectural
//         stack width, again only 8 in 64-bit mode.
//   0x34  the top byte of the AP's OWN IA32_PAT, which it wrote BEFORE the
//         transition, so the VCPU's MSR state is checked to have survived the
//         mode change. MEASURED NOT TO DISCRIMINATE ON THIS HOST -- see the
//         ENTRY_CTLS-preservation assertion further down, which does.
//
// Why 0x32/0x33 are not decorative even though 0x30 alone would be a strong
// hint: with the untrapped-paging defect the AP does execute long-mode instructions once --
// the defect is that it can never be re-entered -- so a test that stopped at the
// first post-transition marker would pass on the broken kernel. The exits after
// the transition are what force a second VM entry in long mode.
//
// None of the above is the assertion that actually catches the defect here. Measured
// on this host, the unfixed and fixed kernels produce byte-identical values for
// every one of those four markers AND for the AP's GUEST_CR0, GUEST_IA32_EFER
// and ENTRY_CTLS, because the layer below repairs the VM-entry control the
// missing exit failed to update. The only observable that moves is
// `Vcpu::Cr0WriteExits()`, which is 0 without the fix and 1 with it. That
// counter was added for this test and is the discriminating assertion; without
// it this whole case is decorative on a nested host.
#ifdef __x86_64__

constexpr uint64_t kApTrampolineGpa = 0x7000;  // SIPI vector 0x07 << 12.
constexpr uint64_t kApLongModeGpa = 0x7100;    // Same page, past the 16-bit part.
constexpr uint64_t kApGdtGpa = 0x8000;
constexpr uint64_t kApGdtPtrGpa = 0x8100;
constexpr uint32_t kApSipiId = 1;
constexpr uint16_t kApCompatPort = 0x30;
constexpr uint16_t kApWidthPort = 0x32;
constexpr uint16_t kApStackPort = 0x33;
constexpr uint16_t kApPatPort = 0x34;
// The PA7 entry the AP writes into its own IA32_PAT before switching mode.
// CHOSEN AT RUN TIME from the architecturally legal encodings (Volume 3, Table
// 12-10: 0 UC, 1 WC, 4 WT, 5 WP, 6 WB, 7 UC-), as the first one that differs
// from the HOST's PA7, and then patched into the trampoline's immediate. A fixed
// constant was tried first and the very first run rejected it: this kernel's own
// PA7 is 0x01, so a marker of 0x01 would have read back correctly whether or not
// the AP kept its own PAT. The guest's page tables select PAT entry 0
// (PAT/PCD/PWT all clear in `WriteIdentityTables`), so whichever value is picked
// changes no memory type the AP actually uses -- it is a marker, not a policy.
constexpr uint8_t kApPatLegal[] = {0x00, 0x01, 0x04, 0x05, 0x06, 0x07};
// Index of the high byte of the `or $0x0?000000, %edx` immediate in |ap16|.
constexpr size_t kApPatImmIndex = 28;

// Carries a multi-step AP vcpu run to a dedicated kernel thread and back.
struct ApModeContext {
  static constexpr size_t kMaxSteps = 6;
  Guest* guest;
  uint64_t entry;
  zx_status_t create_status;
  zx_status_t last_status;
  size_t count;
  zx_port_packet_t packets[kMaxSteps];
  // Recorded at each exit: the guest mode the AP is in (CR0, IA32_EFER) and the
  // VM-entry control that has to agree with it. Kept as raw values rather than
  // asserted inside the thread so a red run prints the whole sequence.
  uint64_t cr0[kMaxSteps];
  uint64_t efer[kMaxSteps];
  uint32_t entry_ctls[kMaxSteps];
  // The same control as `vmcs_init` left it, before the AP has run an
  // instruction. Separating "what creation programmed" from "what the mode
  // transition left" is the whole question this test asks.
  uint32_t entry_ctls_at_create;
  uint32_t pinbased_at_create;
  uint64_t cr0_write_exits;
};

#endif  // __x86_64__

bool vcpu_ap_boots_itself_into_long_mode() {
  BEGIN_TEST;

#ifdef __x86_64__
  auto guest_result = Guest::Create();
  if (guest_result.is_error() && guest_result.status_value() == ZX_ERR_NOT_SUPPORTED) {
    printf("VMX not supported here; skipping AP long-mode bring-up test.\n");
    return true;
  }
  ASSERT_EQ(ZX_OK, guest_result.status_value(), "Guest::Create failed\n");
  ktl::unique_ptr<Guest> guest = ktl::move(guest_result.value());

  // Pick a PAT marker that can discriminate. If it equalled the host's own PA7,
  // the port-0x34 assertion would pass whether or not the AP's PAT survived the
  // transition -- which is not hypothetical: 0x01 does equal it on this kernel.
  const uint64_t host_pat = read_msr(X86_MSR_IA32_PAT);
  const uint8_t host_pa7 = static_cast<uint8_t>(host_pat >> 56);
  uint8_t pat_marker = 0xff;
  for (uint8_t candidate : kApPatLegal) {
    if (candidate != host_pa7) {
      pat_marker = candidate;
      break;
    }
  }
  ASSERT_NE(0xffu, static_cast<uint32_t>(pat_marker), "no legal PAT encoding differs from the host's\n");

  fbl::RefPtr<VmObjectPaged> ram;
  ASSERT_EQ(ZX_OK, VmObjectPaged::Create(PMM_ALLOC_FLAG_ANY, 0u, kGuestRamSize, &ram), "ram\n");
  ASSERT_EQ(ZX_OK, WriteIdentityTables(ram), "tables\n");

  // BSP: STARTUP IPI to AP id 1, entry 0x7000, through the x2APIC ICR. Same
  // shape as vcpu_ap_startup_sipi -- the AP is brought up the way a VMM's guest
  // brings one up, not by conjuring a second vcpu behind the guest's back.
  //   B9 30 08 00 00  mov ecx, 0x830
  //   B8 07 06 00 00  mov eax, 0x607   ; vector 7 | STARTUP(6) << 8
  //   BA 01 00 00 00  mov edx, 1
  //   0F 30           wrmsr
  //   F4              hlt
  const uint8_t bsp[] = {0xB9, 0x30, 0x08, 0x00, 0x00, 0xB8, 0x07, 0x06, 0x00,
                         0x00, 0xBA, 0x01, 0x00, 0x00, 0x00, 0x0F, 0x30, 0xF4};
  ASSERT_EQ(ZX_OK, ram->Write(bsp, kCodeGpa, sizeof(bsp)), "bsp code\n");

  // The AP's 16-bit real-mode trampoline, at CS base 0x7000 / IP 0. Assembled
  // with GNU as (`as --32`, `.code16`) and pasted here rather than hand-encoded.
  //
  //   fa                    cli
  //   66 0f 01 16 00 81     lgdtl 0x8100
  //   66 b9 77 02 00 00     mov  $0x277, %ecx      ; IA32_PAT (pass-through MSR)
  //   0f 32                 rdmsr
  //   66 81 e2 ff ff ff 00  and  $0x00ffffff, %edx ; clear PA7
  //   66 81 ca 00 00 00 01  or   $0x01000000, %edx ; PA7; the 0x01 is PATCHED below
  //   0f 30                 wrmsr
  //   0f 20 e0              mov  %cr4, %eax
  //   66 83 c8 20           or   $0x20, %eax       ; CR4.PAE
  //   0f 22 e0              mov  %eax, %cr4
  //   66 b9 80 00 00 c0     mov  $0xc0000080, %ecx ; IA32_EFER (pass-through)
  //   0f 32                 rdmsr
  //   66 0d 00 01 00 00     or   $0x100, %eax      ; EFER.LME
  //   0f 30                 wrmsr
  //   66 31 c0              xor  %eax, %eax
  //   0f 22 d8              mov  %eax, %cr3        ; page tables at GPA 0
  //   0f 20 c0              mov  %cr0, %eax
  //   66 0d 01 00 00 80     or   $0x80000001, %eax ; PG|PE -- the write under test
  //   0f 22 c0              mov  %eax, %cr0
  //   b0 3c                 mov  $0x3c, %al
  //   e6 30                 out  %al, $0x30        ; forces a VM entry in compat mode
  //   66 ea 00 71 00 00 08 00  ljmpl $0x08, $0x7100
  uint8_t ap16[] = {
      0xfa, 0x66, 0x0f, 0x01, 0x16, 0x00, 0x81, 0x66, 0xb9, 0x77, 0x02, 0x00, 0x00, 0x0f,
      0x32, 0x66, 0x81, 0xe2, 0xff, 0xff, 0xff, 0x00, 0x66, 0x81, 0xca, 0x00, 0x00, 0x00,
      0x01, 0x0f, 0x30, 0x0f, 0x20, 0xe0, 0x66, 0x83, 0xc8, 0x20, 0x0f, 0x22, 0xe0, 0x66,
      0xb9, 0x80, 0x00, 0x00, 0xc0, 0x0f, 0x32, 0x66, 0x0d, 0x00, 0x01, 0x00, 0x00, 0x0f,
      0x30, 0x66, 0x31, 0xc0, 0x0f, 0x22, 0xd8, 0x0f, 0x20, 0xc0, 0x66, 0x0d, 0x01, 0x00,
      0x00, 0x80, 0x0f, 0x22, 0xc0, 0xb0, 0x3c, 0xe6, 0x30, 0x66, 0xea, 0x00, 0x71, 0x00,
      0x00, 0x08, 0x00};
  static_assert(sizeof(ap16) <= kApLongModeGpa - kApTrampolineGpa,
                "the 16-bit trampoline must not run into the 64-bit continuation");
  // Patch the PAT marker in, and check the byte being overwritten is the one the
  // listing above says it is -- otherwise an edit elsewhere in the trampoline
  // would silently corrupt an instruction instead of failing here.
  ASSERT_EQ(0x01u, static_cast<uint32_t>(ap16[kApPatImmIndex]),
            "kApPatImmIndex no longer names the PAT immediate\n");
  ap16[kApPatImmIndex] = pat_marker;
  ASSERT_EQ(ZX_OK, ram->Write(ap16, kApTrampolineGpa, sizeof(ap16)), "ap 16-bit\n");

  // The AP's 64-bit continuation, at GPA 0x7100, reached only through the far
  // jump above. `as --64`, `.code64`.
  //
  //   48 b8 00 00 00 00 00 a5 00 00  movabs $0x0000a50000000000, %rax
  //   48 c1 e8 28                    shr   $40, %rax        ; -> 0xa5
  //   e6 32                          out   %al, $0x32
  //   48 c7 c4 00 a0 00 00           mov   $0xa000, %rsp
  //   48 89 e3                       mov   %rsp, %rbx
  //   53                             push  %rbx             ; 8 bytes in 64-bit mode
  //   48 89 e0                       mov   %rsp, %rax
  //   48 29 d8                       sub   %rbx, %rax
  //   48 f7 d8                       neg   %rax             ; -> 8
  //   e6 33                          out   %al, $0x33
  //   b9 77 02 00 00                 mov   $0x277, %ecx
  //   0f 32                          rdmsr
  //   c1 ea 18                       shr   $24, %edx        ; PA7
  //   89 d0                          mov   %edx, %eax
  //   e6 34                          out   %al, $0x34
  //   f4                             hlt
  const uint8_t ap64[] = {0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa5, 0x00, 0x00, 0x48,
                          0xc1, 0xe8, 0x28, 0xe6, 0x32, 0x48, 0xc7, 0xc4, 0x00, 0xa0, 0x00,
                          0x00, 0x48, 0x89, 0xe3, 0x53, 0x48, 0x89, 0xe0, 0x48, 0x29, 0xd8,
                          0x48, 0xf7, 0xd8, 0xe6, 0x33, 0xb9, 0x77, 0x02, 0x00, 0x00, 0x0f,
                          0x32, 0xc1, 0xea, 0x18, 0x89, 0xd0, 0xe6, 0x34, 0xf4};
  ASSERT_EQ(ZX_OK, ram->Write(ap64, kApLongModeGpa, sizeof(ap64)), "ap 64-bit\n");

  // The AP's own GDT: null, a 64-bit code segment (L=1, D=0) at selector 0x08,
  // and a flat data segment at 0x10. Built by the guest's firmware in reality;
  // written here because there is no firmware.
  const uint8_t gdt[] = {
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // 0x00 null
      0xff, 0xff, 0x00, 0x00, 0x00, 0x9a, 0xaf, 0x00,  // 0x08 code64: P|S|code|R, G|L
      0xff, 0xff, 0x00, 0x00, 0x00, 0x92, 0xcf, 0x00,  // 0x10 data:   P|S|data|W, G|D
  };
  ASSERT_EQ(ZX_OK, ram->Write(gdt, kApGdtGpa, sizeof(gdt)), "gdt\n");
  const uint8_t gdt_ptr[] = {sizeof(gdt) - 1, 0x00, 0x00, 0x80, 0x00, 0x00};  // limit 23, base 0x8000
  ASSERT_EQ(ZX_OK, ram->Write(gdt_ptr, kApGdtPtrGpa, sizeof(gdt_ptr)), "gdt ptr\n");
  ASSERT_EQ(ZX_OK, ram->CommitRange(0, kGuestRamSize), "commit\n");

  auto mapping = guest->RootVmar()->CreateVmMapping(0, kGuestRamSize, 0, VMAR_FLAG_SPECIFIC, ram, 0,
                                                    kMmuFlags, "guest-ram");
  ASSERT_EQ(ZX_OK, mapping.status_value(), "map\n");
  for (uint16_t port : {kApCompatPort, kApWidthPort, kApStackPort, kApPatPort}) {
    auto t = guest->SetTrap(ZX_GUEST_TRAP_IO, port, 1, nullptr, port);
    ASSERT_EQ(ZX_OK, t.status_value(), "trap\n");
  }

  auto bsp_result = Vcpu::Create(*guest, kCodeGpa);
  ASSERT_EQ(ZX_OK, bsp_result.status_value(), "create BSP vcpu\n");
  ktl::unique_ptr<Vcpu> bsp_vcpu = ktl::move(bsp_result.value());
  zx_port_packet_t sipi = {};
  ASSERT_EQ(ZX_OK, bsp_vcpu->Enter(sipi).status_value(), "enter BSP\n");
  ASSERT_EQ(static_cast<uint8_t>(ZX_PKT_TYPE_GUEST_VCPU), static_cast<uint8_t>(sipi.type),
            "expected a GUEST_VCPU exit\n");
  ASSERT_EQ(static_cast<uint64_t>(kApSipiId), sipi.guest_vcpu.startup.id, "AP id\n");
  ASSERT_EQ(kApTrampolineGpa, sipi.guest_vcpu.startup.entry, "AP entry\n");

  ApModeContext ctx = {guest.get(), sipi.guest_vcpu.startup.entry, ZX_ERR_INTERNAL, ZX_ERR_INTERNAL,
                       0,           {}};
  auto ap_body = [](void* arg) -> int {
    auto* c = static_cast<ApModeContext*>(arg);
    auto ap_result = Vcpu::Create(*c->guest, c->entry);
    c->create_status = ap_result.status_value();
    if (ap_result.is_error()) {
      return 0;
    }
    ktl::unique_ptr<Vcpu> ap_vcpu = ktl::move(ap_result.value());
    if (auto e = ap_vcpu->EntryControls(); e.is_ok()) {
      c->entry_ctls_at_create = *e;
    }
    if (auto p = ap_vcpu->PinbasedControls(); p.is_ok()) {
      c->pinbased_at_create = *p;
    }
    for (size_t i = 0; i < ApModeContext::kMaxSteps; i++) {
      zx_port_packet_t packet = {};
      auto entered = ap_vcpu->Enter(packet);
      c->last_status = entered.status_value();
      if (entered.is_error()) {
        return 0;
      }
      VcpuArchState state = {};
      if (ap_vcpu->SaveArchState(state).is_ok()) {
        c->cr0[c->count] = state.cr0;
        c->efer[c->count] = state.efer;
      }
      if (auto e_ctls = ap_vcpu->EntryControls(); e_ctls.is_ok()) {
        c->entry_ctls[c->count] = *e_ctls;
      }
      c->cr0_write_exits = ap_vcpu->Cr0WriteExits();
      c->packets[c->count++] = packet;
      // Anything other than an I/O exit ends the run: a GUEST_HALT is what a
      // VM-entry failure surfaces as, and there is nothing to resume.
      if (packet.type != ZX_PKT_TYPE_GUEST_IO) {
        return 0;
      }
      // Stop BEFORE the trampoline's HLT. `handle_hlt` waits on the interrupt
      // tracker with no deadline, so a further Enter here would block this
      // thread forever and the Join() below would never return.
      if (packet.guest_io.port == kApPatPort) {
        return 0;
      }
    }
    return 0;
  };
  Thread* ap_thread = Thread::Create("hv-ap-longmode", ap_body, &ctx, DEFAULT_PRIORITY);
  ASSERT_TRUE(ap_thread != nullptr, "create AP thread\n");
  ap_thread->Resume();
  int retcode = 0;
  ASSERT_EQ(ZX_OK, ap_thread->Join(&retcode, ZX_TIME_INFINITE), "join AP thread\n");

  ASSERT_EQ(ZX_OK, ctx.create_status, "AP Vcpu::Create on its own thread\n");

  // Report what the AP actually did before asserting, so a red run names the
  // step it died at instead of only the assertion that noticed.
  printf("AP long-mode bring-up: %zu exit(s), last Enter status %d; at creation (real mode, no "
         "paging) ENTRY_CTLS %#x -> IA-32e-mode-guest %d, PINBASED_CTLS %#x; exiting CR0 writes "
         "seen %lu\n",
         ctx.count, ctx.last_status, ctx.entry_ctls_at_create,
         (ctx.entry_ctls_at_create & (1u << 9)) != 0, ctx.pinbased_at_create,
         ctx.cr0_write_exits);
  for (size_t i = 0; i < ctx.count; i++) {
    const zx_port_packet_t& p = ctx.packets[i];
    if (p.type == ZX_PKT_TYPE_GUEST_IO) {
      printf("    [%zu] I/O port %#x = %#x   [GUEST_CR0 %#lx GUEST_IA32_EFER %#lx ENTRY_CTLS %#x "
             "(IA-32e-mode-guest %d, LMA %d)]\n",
             i, p.guest_io.port, static_cast<uint32_t>(p.guest_io.data[0]), ctx.cr0[i],
             ctx.efer[i], ctx.entry_ctls[i], (ctx.entry_ctls[i] & (1u << 9)) != 0,
             (ctx.efer[i] & (1ull << 10)) != 0);
    } else if (p.type == ZX_PKT_TYPE_GUEST_HALT) {
      printf("    [%zu] GUEST HALT reason %u exit_reason %u rip %#lx"
             " (exit_reason 33 == VM-entry failure due to invalid guest state, which is"
             " what happens when an AP turns on paging unobserved)\n",
             i, p.guest_halt.reason, p.guest_halt.exit_reason, p.guest_halt.rip);
    } else {
      printf("    [%zu] packet type %u\n", i, static_cast<uint32_t>(p.type));
    }
  }

  // The discriminating assertion, and the only one that can go red on
  // this host. Everything else about the AP's mode -- its registers, its stack
  // width, its VM-entry controls -- comes out identical whether or not
  // CR0_GUEST_HOST_MASK holds PG, because the mode transition happens either
  // way and the layer below repairs the control we failed to update. What is
  // NOT identical is whether the hypervisor was told: with PG unmasked the
  // guest's `mov cr0` never leaves the guest, `handle_cr0_write` never runs, and
  // this counter stays at zero. Measured at zero on the unfixed tree.
  EXPECT_GT(ctx.cr0_write_exits, 0u,
            "the AP's PE|PG write must have exited to handle_cr0_write; a zero here means CR0.PG "
            "is not in CR0_GUEST_HOST_MASK and the hypervisor did not see the mode change\n");

  // Assert the entry-control invariant next because it names the consequence; the marker
  // assertions below only notice that the VP stopped. See the note at them.
  for (size_t i = 0; i < ctx.count; i++) {
    const uint32_t ia32e_mode_guest = (ctx.entry_ctls[i] & (1u << 9)) != 0 ? 1u : 0u;
    const uint32_t efer_lma = (ctx.efer[i] & (1ull << 10)) != 0 ? 1u : 0u;
    ASSERT_EQ(ia32e_mode_guest, efer_lma,
              "GUEST_IA32_EFER.LMA and the IA-32e-mode-guest VM-entry control must agree at every "
              "exit; when they do not, the next VM entry fails its guest-state checks\n");
  }

  // NO VM-ENTRY CONTROL MAY BE LOST TO A MODE TRANSITION.
  //
  // `handle_cr0_write` reaches ENTRY_CTLS through `SetControl`, which does not
  // set bits -- it REBUILDS the whole field as `allowed_0 | defaults | set`,
  // where `defaults` is taken from its `old_msr` argument. Handed the capability
  // MSR there, every control that is neither required-1 nor named in `set` is
  // dropped. Measured on exactly that mutation: ENTRY_CTLS 0xd3ff -> 0x13ff at
  // the AP's first mode transition, losing load-IA32_PAT (bit 14) and
  // load-IA32_EFER (bit 15), i.e. from that point on the guest would run with
  // whatever PAT and EFER the host last had.
  //
  // This is the assertion that catches it. The port-0x34 PAT marker below does
  // NOT: it read back correctly under that mutation, because on this host the
  // layer below preserves the guest's PAT for us. One more instrument that
  // nesting quietly repairs -- which is why the control field is asserted here
  // directly rather than only through its effect.
  for (size_t i = 0; i < ctx.count; i++) {
    EXPECT_EQ(ctx.entry_ctls_at_create, ctx.entry_ctls[i] & ctx.entry_ctls_at_create,
              "a VM-entry control the VCPU was created with was dropped by the mode transition\n");
  }

  ASSERT_EQ(ZX_OK, ctx.last_status, "every AP Enter must succeed\n");
  ASSERT_EQ(4u, ctx.count, "the AP must reach all four of its markers\n");
  for (size_t i = 0; i < ctx.count; i++) {
    ASSERT_EQ(static_cast<uint8_t>(ZX_PKT_TYPE_GUEST_IO), static_cast<uint8_t>(ctx.packets[i].type),
              "every AP exit must be an I/O exit; a halt means the VP could not be re-entered\n");
  }
  // The entry-control invariant, asserted directly instead of inferred from a crash.
  //
  // Volume 3, Section 26.3.1.1: with the load-IA32_EFER VM-entry control set --
  // which `vmcs_init` always sets -- GUEST_IA32_EFER.LMA must equal the
  // IA-32e-mode-guest VM-entry control, or VM entry fails with exit reason 33. A
  // VP whose guest changed mode without the hypervisor noticing violates exactly
  // this, and it is the only part invisible from inside the guest:
  // long mode itself is reached either way.
  //
  // READ THIS BEFORE TRUSTING A GREEN HERE. On a host where Cerise is itself a
  // guest, the layer below can repair this field behind us, and on this
  // development host it does: measured on the UNFIXED tree, the AP's ENTRY_CTLS
  // went from 0xd1ff at creation (IA-32e-mode-guest 0, correct for a real-mode
  // AP) to 0xd3ff after the trampoline turned on paging -- bit 9 appearing with
  // no Cerise code having written it, because `handle_cr0_write` never ran. So
  // this invariant cannot go red here for the untrapped-paging failure. It is written for
  // a bare-metal machine where Cerise is L0, where nothing repairs the field;
  // and it was proved able to go red by
  // clearing the bit by hand after the transition, which produced exactly the
  // predicted failure -- ENTRY_CTLS 0xd1ff (IA-32e-mode-guest 0) with LMA 1, and
  // the next Enter returning a GUEST HALT with exit_reason 33. That also settles
  // that the check IS enforced on this host, so the green above really is the
  // field being repaired underneath us rather than the rule going unchecked.
  //
  // Consistency alone would also be satisfied by a VP that never left real mode,
  // so require the end state to be long mode as well.
  ASSERT_NE(0u, static_cast<uint32_t>((ctx.cr0[ctx.count - 1] & X86_CR0_PG) != 0),
            "the AP must end with paging on\n");
  ASSERT_NE(0u, ctx.entry_ctls[ctx.count - 1] & (1u << 9),
            "the AP must end with the IA-32e-mode-guest VM-entry control set\n");

  EXPECT_EQ(static_cast<uint32_t>(kApCompatPort), ctx.packets[0].guest_io.port,
            "the AP must retire its PE|PG write\n");
  EXPECT_EQ(static_cast<uint32_t>(kApWidthPort), ctx.packets[1].guest_io.port, "width marker\n");
  EXPECT_EQ(0xa5u, static_cast<uint32_t>(ctx.packets[1].guest_io.data[0]),
            "0xa5 can only come out of a 64-bit shift of a 64-bit immediate\n");
  EXPECT_EQ(static_cast<uint32_t>(kApStackPort), ctx.packets[2].guest_io.port, "stack marker\n");
  EXPECT_EQ(8u, static_cast<uint32_t>(ctx.packets[2].guest_io.data[0]),
            "one push must move RSP by 8, the 64-bit stack width\n");
  EXPECT_EQ(static_cast<uint32_t>(kApPatPort), ctx.packets[3].guest_io.port, "PAT marker\n");
  EXPECT_EQ(static_cast<uint32_t>(pat_marker), static_cast<uint32_t>(ctx.packets[3].guest_io.data[0]),
            "the AP must still hold its own IA32_PAT after the mode transition; reading the"
            " host's PA7 here means the mode change dropped the load-IA32_PAT entry control\n");

  printf("AP long-mode OK: a second VP started by SIPI at %#lx ran its own real->protected->long "
         "trampoline, and in 64-bit mode measured operand width 0x%x, stack width %u and its own "
         "IA32_PAT PA7 0x%x (host's is 0x%x)\n",
         kApTrampolineGpa, static_cast<uint32_t>(ctx.packets[1].guest_io.data[0]),
         static_cast<uint32_t>(ctx.packets[2].guest_io.data[0]),
         static_cast<uint32_t>(ctx.packets[3].guest_io.data[0]), host_pa7);
#else
  printf("Not x86_64; skipping.\n");
#endif  // __x86_64__

  END_TEST;
}

// A whole-state restore may install a mode unlike the one in which a VCPU was
// created. This is routine for secondary processors: creation initializes an
// AP in real mode, but a snapshot normally captures it after the operating
// system has brought it into long mode. The VM-entry IA-32e-mode control is
// host state rather than part of VcpuArchState, so RestoreArchState must derive
// it from the restored EFER instead of retaining the fresh AP's value.
bool vcpu_long_mode_snapshot_restores_into_fresh_ap() {
  BEGIN_TEST;

#ifdef __x86_64__
  auto guest_result = Guest::Create();
  if (guest_result.is_error() && guest_result.status_value() == ZX_ERR_NOT_SUPPORTED) {
    printf("VMX not supported here; skipping fresh-AP restore test.\n");
    return true;
  }
  ASSERT_EQ(ZX_OK, guest_result.status_value(), "Guest::Create failed\n");
  ktl::unique_ptr<Guest> guest = ktl::move(guest_result.value());

  fbl::RefPtr<VmObjectPaged> ram;
  ASSERT_EQ(ZX_OK, VmObjectPaged::Create(PMM_ALLOC_FLAG_ANY, 0u, kGuestRamSize, &ram), "ram\n");
  ASSERT_EQ(ZX_OK, WriteIdentityTables(ram), "tables\n");
  const uint8_t code[] = {0xB0, kSentinel, 0xE6, static_cast<uint8_t>(kTrapPort), 0xF4};
  ASSERT_EQ(ZX_OK, ram->Write(code, kCodeGpa, sizeof(code)), "code\n");
  ASSERT_EQ(ZX_OK, ram->CommitRange(0, kGuestRamSize), "commit\n");
  auto mapping = guest->RootVmar()->CreateVmMapping(0, kGuestRamSize, 0, VMAR_FLAG_SPECIFIC, ram, 0,
                                                    kMmuFlags, "guest-ram");
  ASSERT_EQ(ZX_OK, mapping.status_value(), "map\n");
  auto trap = guest->SetTrap(ZX_GUEST_TRAP_IO, kTrapPort, 1, nullptr, kTrapPort);
  ASSERT_EQ(ZX_OK, trap.status_value(), "trap\n");

  // The BSP's creation state is a ready-made valid long-mode snapshot.
  auto bsp_result = Vcpu::Create(*guest, kCodeGpa);
  ASSERT_EQ(ZX_OK, bsp_result.status_value(), "create BSP\n");
  ktl::unique_ptr<Vcpu> bsp = ktl::move(bsp_result.value());
  fbl::AllocChecker ac;
  ktl::unique_ptr<VcpuArchState> snapshot(new (&ac) VcpuArchState{});
  ASSERT_TRUE(ac.check(), "allocate snapshot\n");
  ASSERT_EQ(ZX_OK, bsp->SaveArchState(*snapshot).status_value(), "save BSP long-mode state\n");
  ASSERT_NE(0u, static_cast<uint32_t>(snapshot->efer & X86_EFER_LMA),
            "source snapshot must be in long mode\n");

  struct RestoreContext {
    Guest* guest;
    const VcpuArchState* snapshot;
    zx_status_t create_status = ZX_ERR_INTERNAL;
    zx_status_t restore_status = ZX_ERR_INTERNAL;
    zx_status_t enter_status = ZX_ERR_INTERNAL;
    uint32_t controls_before = 0;
    uint32_t controls_after = 0;
    zx_port_packet_t packet = {};
  } ctx = {guest.get(), snapshot.get()};

  auto ap_body = [](void* arg) -> int {
    auto* c = static_cast<RestoreContext*>(arg);
    auto ap_result = Vcpu::Create(*c->guest, kCodeGpa);
    c->create_status = ap_result.status_value();
    if (ap_result.is_error()) {
      return 0;
    }
    ktl::unique_ptr<Vcpu> ap = ktl::move(ap_result.value());
    if (auto controls = ap->EntryControls(); controls.is_ok()) {
      c->controls_before = *controls;
    }
    auto restored = ap->RestoreArchState(*c->snapshot);
    c->restore_status = restored.status_value();
    if (restored.is_error()) {
      return 0;
    }
    if (auto controls = ap->EntryControls(); controls.is_ok()) {
      c->controls_after = *controls;
    }
    auto entered = ap->Enter(c->packet);
    c->enter_status = entered.status_value();
    return 0;
  };
  Thread* ap_thread = Thread::Create("hv-ap-restore", ap_body, &ctx, DEFAULT_PRIORITY);
  ASSERT_TRUE(ap_thread != nullptr, "create AP thread\n");
  ap_thread->Resume();
  int retcode = 0;
  ASSERT_EQ(ZX_OK, ap_thread->Join(&retcode, ZX_TIME_INFINITE), "join AP thread\n");

  ASSERT_EQ(ZX_OK, ctx.create_status, "create fresh AP\n");
  ASSERT_EQ(0u, ctx.controls_before & kEntryCtls64bitMode,
            "a fresh AP must start with IA-32e-mode guest clear\n");
  ASSERT_EQ(ZX_OK, ctx.restore_status, "restore long-mode snapshot into AP\n");
  ASSERT_NE(0u, ctx.controls_after & kEntryCtls64bitMode,
            "restore must derive IA-32e-mode guest from EFER.LMA\n");
  ASSERT_EQ(ctx.controls_before & ~kEntryCtls64bitMode,
            ctx.controls_after & ~kEntryCtls64bitMode,
            "restore must preserve every unrelated VM-entry control\n");
  ASSERT_EQ(ZX_OK, ctx.enter_status, "enter restored AP\n");
  ASSERT_EQ(static_cast<uint8_t>(ZX_PKT_TYPE_GUEST_IO), static_cast<uint8_t>(ctx.packet.type),
            "restored AP must execute guest code, not fail VM entry\n");
  EXPECT_EQ(kTrapPort, ctx.packet.guest_io.port, "I/O port\n");
  EXPECT_EQ(kSentinel, ctx.packet.guest_io.data[0], "guest sentinel\n");

  printf("fresh-AP restore OK: ENTRY_CTLS %#x -> %#x and the restored long-mode VP executed\n",
         ctx.controls_before, ctx.controls_after);
#else
  printf("Not x86_64; skipping.\n");
#endif  // __x86_64__

  END_TEST;
}

// --- A blocked NMI is released by the thing that blocked it ------------------
//
// An NMI is blocked while the guest is inside its own NMI handler, and NOTHING
// this hypervisor used to arm could tell it when that ended. Interrupt-window
// exiting -- the instrument every blocked-NMI site used, with a comment saying
// it was the wrong one -- fires when RFLAGS.IF is set and no STI/MOV-SS blocking
// is in force. An NMI handler is entered through an interrupt gate, which
// CLEARS IF. So for the entire duration of the block, the instrument watching
// for its end is watching a condition that is false and that the block itself
// guarantees will stay false. The queued NMI then waits not for the handler to
// finish but for some unrelated VM exit to happen along.
//
// THE ORDER OF THE PACKETS IS NOT THE ANSWER, THOUGH IT WAS DESIGNED TO BE, AND
// THE MEASUREMENT IS WHY THIS PARAGRAPH EXISTS. The intent was to make "unrelated
// VM exit" impossible by removing them -- after the handler returns the guest
// runs a long stretch of code with no I/O in it -- so that a fixed kernel would
// report handler, handler, done and a broken one handler, done, handler.
//
// Run against a kernel arming the OLD instrument, the order came back
// handler, handler, done: IDENTICAL. A stretch with no I/O in it is not a
// stretch with no VM exits in it -- external interrupts exit unconditionally
// (`kPinbasedCtlsExtIntExiting`), and on a busy host there are plenty, each one
// returning to the injection path which then finds the NMI deliverable. So all
// three ordering assertions below pass on the unfixed kernel. They are kept
// because they pin the guest's behaviour, but they are NOT the evidence.
//
// What discriminates is `Vcpu::NmiWindowExits()`: 1 with the fix, 0 without.
// The control that produces that exit is armed by exactly one code path -- the
// one that found an NMI blocked -- so it cannot be produced by a host interrupt
// arriving at a convenient moment, which is precisely what the order can be.
//
// This case needs virtual NMIs, which the pin-based capability MSR read FROM
// INSIDE THIS HYPERVISOR must offer -- see `print_vmx_capabilities_once`, whose
// line this test also checks by reading PINBASED_CTLS back off the VMCS. Where
// they are absent the hypervisor keeps the old fallback and this case reports
// that rather than failing, because that is a missing capability and not a
// missing runner flag.
bool vcpu_blocked_nmi_is_released_by_the_nmi_window() {
  BEGIN_TEST;

#ifdef __x86_64__
  auto guest_result = Guest::Create();
  if (guest_result.is_error() && guest_result.status_value() == ZX_ERR_NOT_SUPPORTED) {
    printf("VMX not supported here; skipping NMI-window test.\n");
    return true;
  }
  ASSERT_EQ(ZX_OK, guest_result.status_value(), "Guest::Create failed\n");
  ktl::unique_ptr<Guest> guest = ktl::move(guest_result.value());

  constexpr uint64_t kGdtGpa = 0x6000;
  constexpr uint64_t kIdtGpa = 0x6800;
  constexpr uint64_t kNmiHandlerGpa = 0x8000;
  constexpr uint64_t kStackTop = 0x9000;
  constexpr uint16_t kArmPort = 0x10;
  constexpr uint16_t kHandlerPort = 0x30;
  constexpr uint16_t kDonePort = 0x31;

  fbl::RefPtr<VmObjectPaged> ram;
  ASSERT_EQ(ZX_OK, VmObjectPaged::Create(PMM_ALLOC_FLAG_ANY, 0u, kGuestRamSize, &ram), "ram\n");
  ASSERT_EQ(ZX_OK, WriteIdentityTables(ram), "tables\n");

  // Main line. Interrupts are NEVER enabled: vmcs_init leaves RFLAGS.IF clear
  // and nothing here sets it, which is the whole point -- an interrupt window
  // can never open, so anything that arrives must have been released by the NMI
  // window.
  //   B0 5A          mov al, 0x5a
  //   E6 10          out 0x10, al     ; exit #1: "armed", host injects NMI #1
  //   B9 00 00 00 08 mov ecx, 0x08000000
  //   E2 FE          loop $           ; a long NON-EXITING stretch
  //   B0 44          mov al, 0x44
  //   E6 31          out 0x31, al     ; "done"
  //   F4             hlt
  const uint8_t code[] = {0xB0, 0x5A, 0xE6, kArmPort, 0xB9, 0x00, 0x00, 0x00, 0x08,
                          0xE2, 0xFE, 0xB0, 0x44, 0xE6, kDonePort, 0xF4};
  ASSERT_EQ(ZX_OK, ram->Write(code, kCodeGpa, sizeof(code)), "code\n");

  // GDT[1] = flat 64-bit code segment (selector 0x08).
  const uint8_t gdt_code[8] = {0xFF, 0xFF, 0x00, 0x00, 0x00, 0x9B, 0xAF, 0x00};
  ASSERT_EQ(ZX_OK, ram->Write(gdt_code, kGdtGpa + 8, sizeof(gdt_code)), "GDT code desc\n");

  // IDT gate for vector 2 (NMI): 64-bit interrupt gate, selector 0x08.
  const uint8_t idt_gate[16] = {
      static_cast<uint8_t>(kNmiHandlerGpa & 0xFF),
      static_cast<uint8_t>((kNmiHandlerGpa >> 8) & 0xFF),
      0x08, 0x00, 0x00, 0x8E, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
  ASSERT_EQ(ZX_OK, ram->Write(idt_gate, kIdtGpa + X86_INT_NMI * 16, sizeof(idt_gate)), "IDT\n");

  // NMI handler: report, then IRET. The IRET is what clears NMI blocking, and
  // with virtual NMIs it is what the NMI window is waiting for.
  //   B0 77   mov al, 0x77
  //   E6 30   out 0x30, al
  //   48 CF   iretq
  const uint8_t handler[] = {0xB0, 0x77, 0xE6, kHandlerPort, 0x48, 0xCF};
  ASSERT_EQ(ZX_OK, ram->Write(handler, kNmiHandlerGpa, sizeof(handler)), "handler\n");
  ASSERT_EQ(ZX_OK, ram->CommitRange(0, kGuestRamSize), "commit\n");

  auto mapping = guest->RootVmar()->CreateVmMapping(0, kGuestRamSize, 0, VMAR_FLAG_SPECIFIC, ram, 0,
                                                    kMmuFlags, "guest-ram");
  ASSERT_EQ(ZX_OK, mapping.status_value(), "map\n");
  for (uint16_t port : {kArmPort, kHandlerPort, kDonePort}) {
    auto t = guest->SetTrap(ZX_GUEST_TRAP_IO, port, 1, nullptr, port);
    ASSERT_EQ(ZX_OK, t.status_value(), "trap\n");
  }

  auto vcpu_result = Vcpu::Create(*guest, kCodeGpa);
  ASSERT_EQ(ZX_OK, vcpu_result.status_value(), "Vcpu::Create\n");
  ktl::unique_ptr<Vcpu> vcpu = ktl::move(vcpu_result.value());

  // Read the control back off this VCPU's own VMCS rather than trusting a
  // capability MSR: what matters is what `vmcs_init` was able to program here.
  auto pin = vcpu->PinbasedControls();
  ASSERT_EQ(ZX_OK, pin.status_value(), "read PINBASED_CTLS\n");
  constexpr uint32_t kVirtualNmis = 1u << 5;
  if ((*pin & kVirtualNmis) == 0) {
    printf("virtual NMIs are not offered to this hypervisor (PINBASED_CTLS %#x); the blocked-NMI "
           "fallback is interrupt-window exiting and this case cannot distinguish it. Skipping.\n",
           *pin);
    return true;
  }

  VcpuArchState s = {};
  ASSERT_EQ(ZX_OK, vcpu->SaveArchState(s).status_value(), "SaveArchState\n");
  s.gdtr_base = kGdtGpa;
  s.gdtr_limit = 0x0F;
  s.idtr_base = kIdtGpa;
  s.idtr_limit = 0xFFF;
  s.regs.rsp = kStackTop;
  // Selector 0x08 so the handler's IRET can reload a non-null CS -- vmcs_init
  // leaves the BSP's CS selector null, and iretq refuses a null CS with #GP(0).
  s.cs.selector = 0x08;
  ASSERT_EQ(ZX_OK, vcpu->RestoreArchState(s).status_value(), "load GDTR/IDTR/RSP/CS\n");

  zx_port_packet_t armed = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(armed).status_value(), "enter to the armed marker\n");
  ASSERT_EQ(static_cast<uint32_t>(kArmPort), armed.guest_io.port, "armed marker\n");
  ASSERT_EQ(0u, vcpu->NmiWindowExits(), "no NMI has been blocked yet\n");

  // NMI #1: delivered on the next entry, and its delivery sets NMI blocking.
  ASSERT_EQ(ZX_OK, vcpu->Interrupt(X86_INT_NMI).status_value(), "queue NMI #1\n");

  // Collect what the guest does from here. Bounded, and stopping before the
  // guest's HLT, which `handle_hlt` would wait on with no deadline.
  constexpr size_t kMaxSteps = 5;
  uint16_t ports[kMaxSteps] = {};
  size_t count = 0;
  bool queued_second = false;
  for (size_t i = 0; i < kMaxSteps; i++) {
    zx_port_packet_t p = {};
    auto entered = vcpu->Enter(p);
    ASSERT_EQ(ZX_OK, entered.status_value(), "enter\n");
    ASSERT_EQ(static_cast<uint8_t>(ZX_PKT_TYPE_GUEST_IO), static_cast<uint8_t>(p.type),
              "every exit here must be an I/O exit\n");
    ports[count++] = static_cast<uint16_t>(p.guest_io.port);
    // On the FIRST handler entry -- i.e. while the guest is demonstrably inside
    // its NMI handler and NMI blocking is in force -- queue the second one. It
    // cannot be injected now; what is being measured is when it is.
    if (!queued_second && p.guest_io.port == kHandlerPort) {
      queued_second = true;
      ASSERT_EQ(ZX_OK, vcpu->Interrupt(X86_INT_NMI).status_value(), "queue NMI #2\n");
      continue;
    }
    if (p.guest_io.port == kDonePort) {
      break;
    }
  }

  printf("blocked-NMI release: PINBASED_CTLS %#x (virtual NMIs on), %zu exit(s), NMI-window exits "
         "%lu, port order:",
         *pin, count, vcpu->NmiWindowExits());
  for (size_t i = 0; i < count; i++) {
    printf(" %#x", ports[i]);
  }
  printf("\n");

  // THE DISCRIMINATING ASSERTION, and measured to be the only one: arming the
  // old instrument instead leaves this at 0 while every assertion below still
  // passes, because a host external interrupt exits the guest during the long
  // stretch and the NMI is delivered on the way back in.
  EXPECT_GT(vcpu->NmiWindowExits(), 0u,
            "the second NMI must have been released by an NMI-window exit, not by whatever exit "
            "happened along next\n");

  // Behavioural pins. Not evidence for host NMI delivery -- see the note above -- but they keep
  // the guest doing what the counter is being read about.
  ASSERT_GE(count, 3u, "expected handler, handler, done\n");
  EXPECT_EQ(static_cast<uint32_t>(kHandlerPort), static_cast<uint32_t>(ports[0]),
            "the first NMI must reach the guest's own handler\n");
  EXPECT_EQ(static_cast<uint32_t>(kHandlerPort), static_cast<uint32_t>(ports[1]),
            "the second NMI must be delivered before the guest's next I/O\n");
  EXPECT_EQ(static_cast<uint32_t>(kDonePort), static_cast<uint32_t>(ports[2]), "done marker\n");
#else
  printf("Not x86_64; skipping.\n");
#endif  // __x86_64__

  END_TEST;
}

// --- Logical-destination interrupt routing -----------------------------------
//
// Two halves of the same x2APIC feature, both exercised through a real guest:
//   * the LDR a VP reads back (encode side), and
//   * the VP mask a logical ICR destination decodes to (decode side).
//
// Intel Volume 3, Section 10.12.10.2: in x2APIC mode the LDR is read-only and
// derived from the x2APIC ID as
//   LDR[31:16] = cluster ID = ID[19:4],  LDR[15:0] = 1 << (ID[3:0]).

#ifdef __x86_64__

constexpr uint32_t kX2ApicIdMsr = 0x802;
constexpr uint32_t kX2ApicLdrMsr = 0x80d;
constexpr uint32_t kX2ApicIcrMsr = 0x830;
constexpr uint16_t kWideTrapPort = 0x11;  // Reported with a 4-byte OUT.

// The value the architecture requires the LDR to hold for |apic_id|, written out
// independently of the kernel's own helper so the test is not a tautology.
constexpr uint32_t ExpectedLdr(uint32_t apic_id) {
  return ((apic_id / 16u) << 16) | (1u << (apic_id % 16u));
}

// Runs a single-shot guest that does `rdmsr <msr>; out 0x11, eax; hlt` and
// returns the 32 bits the guest read. |burn_vpids| VPIDs are allocated from the
// guest's allocator (and never freed) before the vcpu is created, which forces
// the vcpu's VPID to burn_vpids+1 and hence its x2APIC ID (VPID - 1) to
// |burn_vpids|. That is the only way to observe a VP with a nonzero cluster
// without standing up 17 live vcpus.
zx::result<uint32_t> RunGuestReadMsr32(uint32_t msr, uint16_t burn_vpids) {
  auto guest_result = Guest::Create();
  if (guest_result.is_error()) {
    return guest_result.take_error();
  }
  ktl::unique_ptr<Guest> guest = ktl::move(guest_result.value());
  for (uint16_t i = 0; i < burn_vpids; i++) {
    auto id = guest->TryAllocVpid();
    if (id.is_error()) {
      return id.take_error();
    }
  }

  fbl::RefPtr<VmObjectPaged> ram;
  if (zx_status_t s = VmObjectPaged::Create(PMM_ALLOC_FLAG_ANY, 0u, kGuestRamSize, &ram);
      s != ZX_OK) {
    return zx::error(s);
  }
  if (zx_status_t s = WriteIdentityTables(ram); s != ZX_OK) {
    return zx::error(s);
  }
  //   B9 <msr>   mov ecx, msr
  //   0F 32      rdmsr          -> trapped x2APIC MSR read
  //   E7 11      out 0x11, eax  -> 4-byte I/O exit carrying the value
  //   F4         hlt
  //
  // vmcs_init only entertains long mode for the BSP (VPID 1); every other VCPU
  // starts as an AP would after a SIPI, in 16-bit real mode at CS:0. Burning
  // VPIDs therefore also picks the mode, so the same instructions have to be
  // emitted with 0x66 operand-size prefixes to stay 32-bit there.
  const bool is_ap = burn_vpids != 0;
  uint8_t code[12];
  size_t n = 0;
  if (is_ap) {
    code[n++] = 0x66;
  }
  code[n++] = 0xB9;
  code[n++] = static_cast<uint8_t>(msr);
  code[n++] = static_cast<uint8_t>(msr >> 8);
  code[n++] = static_cast<uint8_t>(msr >> 16);
  code[n++] = static_cast<uint8_t>(msr >> 24);
  code[n++] = 0x0F;
  code[n++] = 0x32;
  if (is_ap) {
    code[n++] = 0x66;
  }
  code[n++] = 0xE7;
  code[n++] = static_cast<uint8_t>(kWideTrapPort);
  code[n++] = 0xF4;
  if (zx_status_t s = ram->Write(code, kCodeGpa, n); s != ZX_OK) {
    return zx::error(s);
  }
  if (zx_status_t s = ram->CommitRange(0, kGuestRamSize); s != ZX_OK) {
    return zx::error(s);
  }
  auto mapping = guest->RootVmar()->CreateVmMapping(0, kGuestRamSize, 0, VMAR_FLAG_SPECIFIC, ram, 0,
                                                    kMmuFlags, "guest-ram");
  if (mapping.is_error()) {
    return mapping.take_error();
  }
  if (auto t = guest->SetTrap(ZX_GUEST_TRAP_IO, kWideTrapPort, 4, nullptr, kWideTrapPort);
      t.is_error()) {
    return t.take_error();
  }
  auto vcpu_result = Vcpu::Create(*guest, kCodeGpa);
  if (vcpu_result.is_error()) {
    return vcpu_result.take_error();
  }
  ktl::unique_ptr<Vcpu> vcpu = ktl::move(vcpu_result.value());
  zx_port_packet_t packet = {};
  if (auto e = vcpu->Enter(packet); e.is_error()) {
    return e.take_error();
  }
  if (packet.type != ZX_PKT_TYPE_GUEST_IO || packet.guest_io.port != kWideTrapPort ||
      packet.guest_io.access_size != 4) {
    printf("RunGuestReadMsr32(msr=%#x, burn=%u): unexpected exit type=%#x port=%#x size=%u\n", msr,
           burn_vpids, packet.type, packet.guest_io.port, packet.guest_io.access_size);
    return zx::error(ZX_ERR_BAD_STATE);
  }
  uint32_t value = 0;
  memcpy(&value, packet.guest_io.data, sizeof(value));
  return zx::ok(value);
}

#endif  // __x86_64__

// Logical routing, encode side: a guest reading the x2APIC LDR must observe the
// architecturally derived value for *its own* APIC ID — the right cluster in
// bits 31:16 and the right one-hot bit in 15:0 — not the zero it used to read.
// Checked at three APIC IDs: 0 (cluster 0, bit 0), 16 (cluster 1, bit 0 — the
// first ID where the cluster field is nonzero), and 34 (cluster 2, bit 2, so
// both fields are nonzero and different from each other). Each run also reads
// the APIC ID register, so the LDR is checked against the ID the same VP
// reports rather than against an assumption about VPID allocation.
bool vcpu_x2apic_ldr_derived_from_apic_id() {
  BEGIN_TEST;

#ifdef __x86_64__
  auto probe = Guest::Create();
  if (probe.is_error() && probe.status_value() == ZX_ERR_NOT_SUPPORTED) {
    printf("VMX not supported here; skipping x2APIC LDR test.\n");
    return true;
  }
  ASSERT_EQ(ZX_OK, probe.status_value(), "Guest::Create failed\n");
  probe.value().reset();

  struct LdrCase {
    uint16_t burn_vpids;
    uint32_t expected_apic_id;
    uint32_t expected_ldr;
  };
  const LdrCase cases[] = {
      {0, 0, 0x0000'0001},    // cluster 0, logical id bit 0.
      {16, 16, 0x0001'0001},  // cluster 1, logical id bit 0.
      {34, 34, 0x0002'0004},  // cluster 2, logical id bit 2.
  };
  for (const LdrCase& c : cases) {
    // Cross-check the expectation table against the architectural formula.
    ASSERT_EQ(c.expected_ldr, ExpectedLdr(c.expected_apic_id),
              "case table disagrees with the Section 10.12.10 formula\n");

    auto id = RunGuestReadMsr32(kX2ApicIdMsr, c.burn_vpids);
    ASSERT_EQ(ZX_OK, id.status_value(), "run guest for APIC ID\n");
    ASSERT_EQ(c.expected_apic_id, id.value(), "VP did not get the intended APIC ID\n");

    auto ldr = RunGuestReadMsr32(kX2ApicLdrMsr, c.burn_vpids);
    ASSERT_EQ(ZX_OK, ldr.status_value(), "run guest for LDR\n");
    EXPECT_EQ(c.expected_ldr, ldr.value(), "LDR is not the derived value for this APIC ID\n");
    EXPECT_EQ(c.expected_apic_id / 16u, ldr.value() >> 16, "wrong cluster in LDR[31:16]\n");
    EXPECT_EQ(1u << (c.expected_apic_id % 16u), ldr.value() & 0xffffu,
              "wrong one-hot logical id in LDR[15:0]\n");
    printf("x2APIC LDR OK: apic_id=%u reads LDR=%#x (cluster %u, bit %u)\n", id.value(),
           ldr.value(), ldr.value() >> 16, c.expected_apic_id % 16u);
  }
#else
  printf("Not x86_64; skipping.\n");
#endif  // __x86_64__

  END_TEST;
}

// Logical routing, decode side: an IPI sent in logical destination mode must
// produce a VCPU mask holding exactly the VPs the destination names — the
// intended VP *and no others*. A test that only asserted "the intended VP is
// present" would be satisfied by the broadcast mask, so every case pins the
// whole 64-bit mask, and the table deliberately includes a destination naming a
// cluster that holds no VP (empty mask is the correct answer) alongside the
// physical and broadcast forms, which must keep behaving exactly as before.
//
// Scaffolding is the same shape as the AP-startup test: the guest writes the
// x2APIC ICR, the write traps, and the resulting GUEST_VCPU/INTERRUPT packet is
// read back through Enter(). One guest issues every case in sequence.
bool vcpu_logical_ipi_target_mask() {
  BEGIN_TEST;

#ifdef __x86_64__
  auto guest_result = Guest::Create();
  if (guest_result.is_error() && guest_result.status_value() == ZX_ERR_NOT_SUPPORTED) {
    printf("VMX not supported here; skipping logical-IPI test.\n");
    return true;
  }
  ASSERT_EQ(ZX_OK, guest_result.status_value(), "Guest::Create failed\n");
  ktl::unique_ptr<Guest> guest = ktl::move(guest_result.value());

  struct IpiCase {
    const char* name;
    uint32_t destination;  // ICR[63:32].
    bool logical;
    uint8_t vector;
    uint64_t expected_mask;
  };
  const IpiCase cases[] = {
      // Physical mode is untouched by this change; it is here so a regression in
      // the shared path is caught by the same test.
      {"physical, VP 3", 0x0000'0003, false, 0x21, uint64_t{1} << 3},
      // Cluster 0, logical id bit 1 -> VP 1 only. This is the case that would
      // pass under a broadcast bug if the mask were not pinned exactly.
      {"logical, cluster 0 bit 1", 0x0000'0002, true, 0x22, uint64_t{1} << 1},
      // Two VPs in one cluster.
      {"logical, cluster 0 bits 0+2", 0x0000'0005, true, 0x23, 0x5},
      // First cluster whose VPs live in the upper half of the mask.
      {"logical, cluster 1 bit 0", 0x0001'0001, true, 0x24, uint64_t{1} << 16},
      // Cluster 2, a multi-bit logical id: VPs 32-35 and 44-47.
      {"logical, cluster 2 bits f00f", 0x0002'f00f, true, 0x25, uint64_t{0xf00f} << 32},
      // Top of the 64-VP mask.
      {"logical, cluster 3 bit 15", 0x0003'8000, true, 0x26, uint64_t{1} << 63},
      // Cluster 4 is past kMaxGuestVcpus/16: no VP matches, so the mask is empty.
      {"logical, empty cluster 4", 0x0004'0001, true, 0x27, 0},
      // A far-out cluster must not wrap or shift back into the mask.
      {"logical, empty cluster fffe", 0xfffe'0001, true, 0x28, 0},
      // 0xffffffff is broadcast in *both* destination modes (Vol 3, 10.12.9).
      {"logical broadcast", 0xffff'ffff, true, 0x29, UINT64_MAX},
      {"physical broadcast", 0xffff'ffff, false, 0x2a, UINT64_MAX},
  };
  constexpr size_t kCaseCount = sizeof(cases) / sizeof(cases[0]);

  fbl::RefPtr<VmObjectPaged> ram;
  ASSERT_EQ(ZX_OK, VmObjectPaged::Create(PMM_ALLOC_FLAG_ANY, 0u, kGuestRamSize, &ram), "ram\n");
  ASSERT_EQ(ZX_OK, WriteIdentityTables(ram), "tables\n");

  // Per case: mov ecx, 0x830; mov eax, <icr lo>; mov edx, <destination>; wrmsr.
  // Delivery mode FIXED (0) and shorthand NO_SHORTHAND (0) are both encoded as
  // zero bits; the destination mode is ICR bit 11.
  uint8_t code[kCaseCount * 17 + 1] = {};
  size_t n = 0;
  auto emit_imm32 = [&code, &n](uint32_t v) {
    code[n++] = static_cast<uint8_t>(v);
    code[n++] = static_cast<uint8_t>(v >> 8);
    code[n++] = static_cast<uint8_t>(v >> 16);
    code[n++] = static_cast<uint8_t>(v >> 24);
  };
  for (const IpiCase& c : cases) {
    const uint32_t icr_lo = c.vector | (c.logical ? (1u << 11) : 0u);
    code[n++] = 0xB9;  // mov ecx, imm32
    emit_imm32(kX2ApicIcrMsr);
    code[n++] = 0xB8;  // mov eax, imm32
    emit_imm32(icr_lo);
    code[n++] = 0xBA;  // mov edx, imm32
    emit_imm32(c.destination);
    code[n++] = 0x0F;  // wrmsr
    code[n++] = 0x30;
  }
  code[n++] = 0xF4;  // hlt
  ASSERT_EQ(ZX_OK, ram->Write(code, kCodeGpa, n), "write guest code\n");
  ASSERT_EQ(ZX_OK, ram->CommitRange(0, kGuestRamSize), "commit\n");

  auto mapping = guest->RootVmar()->CreateVmMapping(0, kGuestRamSize, 0, VMAR_FLAG_SPECIFIC, ram, 0,
                                                    kMmuFlags, "guest-ram");
  ASSERT_EQ(ZX_OK, mapping.status_value(), "map\n");

  auto vcpu_result = Vcpu::Create(*guest, kCodeGpa);
  ASSERT_EQ(ZX_OK, vcpu_result.status_value(), "create vcpu\n");
  ktl::unique_ptr<Vcpu> vcpu = ktl::move(vcpu_result.value());

  for (const IpiCase& c : cases) {
    zx_port_packet_t packet = {};
    ASSERT_EQ(ZX_OK, vcpu->Enter(packet).status_value(), "enter\n");
    ASSERT_EQ(static_cast<uint8_t>(ZX_PKT_TYPE_GUEST_VCPU), static_cast<uint8_t>(packet.type),
              "expected a GUEST_VCPU exit\n");
    ASSERT_EQ(static_cast<uint32_t>(ZX_PKT_GUEST_VCPU_INTERRUPT), packet.guest_vcpu.type,
              "expected an INTERRUPT packet\n");
    // The vector identifies which case this packet belongs to, so a dropped or
    // reordered exit cannot be mistaken for a matching mask.
    ASSERT_EQ(static_cast<uint32_t>(c.vector),
              static_cast<uint32_t>(packet.guest_vcpu.interrupt.vector),
              "packet is not the case under test\n");
    EXPECT_EQ(c.expected_mask, packet.guest_vcpu.interrupt.mask, "wrong target mask\n");
    printf("logical-IPI OK: %s dest=%#x -> mask=%#lx (expected %#lx)\n", c.name, c.destination,
           packet.guest_vcpu.interrupt.mask, c.expected_mask);
  }
#else
  printf("Not x86_64; skipping.\n");
#endif  // __x86_64__

  END_TEST;
}

// WI-1.1 (MMIO read + completion, one instruction form): an MMIO read exits to
// the VMM as a ZX_PKT_TYPE_GUEST_MEM packet, and the VMM completes it by
// supplying the read value. On x86 the packet carries the GPA, cr3, rip,
// instruction size, and default operand size, but NOT the decoded operand — so
// completion requires the VMM to decode the faulting instruction. This test
// covers the fixed form `mov al, [mem]` (opcode 8A /r); a general MMIO path
// needs a full x86 decoder (kernel completion ABI vs userspace emulator — the
// open design fork). The kernel has already advanced RIP past the faulting
// instruction before delivering the packet (handle_trap -> next_rip), so a read
// completion only has to place the value in the destination register — done here
// through the public ReadState/WriteState path.
bool vcpu_mmio_read_completion() {
  BEGIN_TEST;

#ifdef __x86_64__
  constexpr uint64_t kMmioGpa = 0x5000;  // a page inside RAM, carved out by the MEM trap.
  constexpr uint8_t kDeviceValue = 0x5A;

  auto guest_result = Guest::Create();
  if (guest_result.is_error() && guest_result.status_value() == ZX_ERR_NOT_SUPPORTED) {
    printf("VMX not supported here; skipping MMIO-completion test.\n");
    return true;
  }
  ASSERT_EQ(ZX_OK, guest_result.status_value(), "Guest::Create failed\n");
  ktl::unique_ptr<Guest> guest = ktl::move(guest_result.value());

  fbl::RefPtr<VmObjectPaged> ram;
  ASSERT_EQ(ZX_OK, VmObjectPaged::Create(PMM_ALLOC_FLAG_ANY, 0u, kGuestRamSize, &ram), "ram\n");
  ASSERT_EQ(ZX_OK, WriteIdentityTables(ram), "tables\n");
  //   48 BB 00 50 .. mov rbx, 0x5000
  //   8A 03          mov al, [rbx]   ; MMIO read -> GUEST_MEM exit
  //   E6 10          out 0x10, al    ; report the VMM-completed value
  //   F4             hlt
  const uint8_t code[] = {0x48, 0xBB, 0x00, 0x50, 0x00, 0x00, 0x00, 0x00,
                          0x00, 0x00, 0x8A, 0x03, 0xE6, 0x10, 0xF4};
  ASSERT_EQ(ZX_OK, ram->Write(code, kCodeGpa, sizeof(code)), "code\n");
  ASSERT_EQ(ZX_OK, ram->CommitRange(0, kGuestRamSize), "commit\n");

  auto mapping = guest->RootVmar()->CreateVmMapping(0, kGuestRamSize, 0, VMAR_FLAG_SPECIFIC, ram, 0,
                                                    kMmuFlags, "guest-ram");
  ASSERT_EQ(ZX_OK, mapping.status_value(), "map\n");
  auto io_trap = guest->SetTrap(ZX_GUEST_TRAP_IO, 0x10, 1, nullptr, 0x10);
  ASSERT_EQ(ZX_OK, io_trap.status_value(), "trap 0x10\n");
  // A synchronous MEM trap unmaps the page from the guest EPT so an access faults.
  auto mem_trap = guest->SetTrap(ZX_GUEST_TRAP_MEM, kMmioGpa, 0x1000, nullptr, 0x5000);
  ASSERT_EQ(ZX_OK, mem_trap.status_value(), "MEM trap\n");

  auto vcpu_result = Vcpu::Create(*guest, kCodeGpa);
  ASSERT_EQ(ZX_OK, vcpu_result.status_value(), "Vcpu::Create\n");
  ktl::unique_ptr<Vcpu> vcpu = ktl::move(vcpu_result.value());

  zx_port_packet_t mem = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(mem).status_value(), "enter to MMIO\n");
  ASSERT_EQ(static_cast<uint8_t>(ZX_PKT_TYPE_GUEST_MEM), static_cast<uint8_t>(mem.type),
            "expected an MMIO/mem exit\n");
  EXPECT_EQ(kMmioGpa, mem.guest_mem.addr, "MMIO GPA\n");
  EXPECT_EQ(2u, static_cast<uint32_t>(mem.guest_mem.instruction_size), "instruction size (8A 03)\n");
  EXPECT_EQ(kCodeGpa + 10, mem.guest_mem.rip, "faulting-instruction RIP\n");

  // VMM decode: confirm the fixed form `mov al,[rbx]` (8A 03) at the reported RIP.
  uint8_t insn[2] = {};
  ASSERT_EQ(ZX_OK, ram->Read(insn, mem.guest_mem.rip, sizeof(insn)), "read faulting insn\n");
  EXPECT_EQ(0x8Au, static_cast<uint32_t>(insn[0]), "opcode 8A\n");
  EXPECT_EQ(0x03u, static_cast<uint32_t>(insn[1]), "modrm al,[rbx]\n");

  // VMM completion: place the device value in AL (RIP is already past the insn).
  zx_vcpu_state_t s = {};
  ASSERT_EQ(ZX_OK, vcpu->ReadState(s).status_value(), "ReadState\n");
  s.rax = (s.rax & ~0xffull) | kDeviceValue;
  ASSERT_EQ(ZX_OK, vcpu->WriteState(s).status_value(), "WriteState (complete read)\n");

  // Guest resumes and reports the completed value.
  zx_port_packet_t io = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(io).status_value(), "enter to report\n");
  ASSERT_EQ(static_cast<uint8_t>(ZX_PKT_TYPE_GUEST_IO), static_cast<uint8_t>(io.type), "io\n");
  EXPECT_EQ(0x10u, io.guest_io.port, "port\n");
  EXPECT_EQ(static_cast<uint32_t>(kDeviceValue), static_cast<uint32_t>(io.guest_io.data[0]),
            "guest must observe the VMM-completed MMIO read value\n");
  printf("MMIO-completion OK: mov al,[%#lx] exited as GUEST_MEM; VMM completed al=%#x; guest "
         "reported %#x\n",
         kMmioGpa, kDeviceValue, io.guest_io.data[0]);
#else
  printf("Not x86_64; skipping.\n");
#endif  // __x86_64__

  END_TEST;
}

// K1 (enlightenment identity): with Hyper-V identity enabled, CPUID leaf
// 0x40000000 presents "Microsoft Hv" (ebx:ecx:edx) instead of the default
// "KVMKVMKVM" — the first thing a Hyper-V-enlightened guest (e.g. Windows)
// checks to take its Hyper-V path. Non-vacuous: the reported byte is 'M' only on
// the Hyper-V path; the default KVM identity would report 'K'.
bool vcpu_hyperv_cpuid_identity() {
  BEGIN_TEST;

#ifdef __x86_64__
  fbl::RefPtr<VmObjectPaged> ram;
  ASSERT_EQ(ZX_OK, VmObjectPaged::Create(PMM_ALLOC_FLAG_ANY, 0u, kGuestRamSize, &ram), "ram\n");
  ASSERT_EQ(ZX_OK, WriteIdentityTables(ram), "tables\n");
  //   B8 00 00 00 40  mov eax, 0x40000000  ; hypervisor vendor leaf
  //   0F A2           cpuid                ; ebx:ecx:edx = vendor string
  //   89 D8           mov eax, ebx         ; low byte of ebx -> al
  //   E6 10           out 0x10, al
  //   F4              hlt
  const uint8_t code[] = {0xB8, 0x00, 0x00, 0x00, 0x40, 0x0F, 0xA2, 0x89, 0xD8, 0xE6, 0x10, 0xF4};
  ASSERT_EQ(ZX_OK, ram->Write(code, kCodeGpa, sizeof(code)), "code\n");
  ASSERT_EQ(ZX_OK, ram->CommitRange(0, kGuestRamSize), "commit\n");

  auto lg = CreateLiveGuest(ram, kCodeGpa);
  if (lg.is_error() && lg.status_value() == ZX_ERR_NOT_SUPPORTED) {
    printf("VMX not supported here; skipping Hyper-V CPUID identity test.\n");
    return true;
  }
  ASSERT_EQ(ZX_OK, lg.status_value(), "create live guest\n");
  Vcpu* vcpu = lg->vcpu.get();

  // MSR delegation first: a Hyper-V identity without it is refused outright.
  // That configuration tells Windows "I am Hv#1" and then #GPs the first
  // synthetic-MSR write it makes.
  ASSERT_EQ(ZX_OK, vcpu->SetMsrDelegation(true).status_value(), "delegate synthetic MSRs\n");
  ASSERT_EQ(ZX_OK, vcpu->SetHypervIdentity(true).status_value(), "enable Hyper-V identity\n");

  zx_port_packet_t p = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(p).status_value(), "enter\n");
  ASSERT_EQ(static_cast<uint8_t>(ZX_PKT_TYPE_GUEST_IO), static_cast<uint8_t>(p.type), "io\n");
  EXPECT_EQ(0x4Du, static_cast<uint32_t>(p.guest_io.data[0]),
            "guest must see the Hyper-V vendor ('M' = 0x4D), not KVM ('K' = 0x4B)\n");
  printf("hyperv-cpuid OK: leaf 0x40000000 ebx low byte = %#x ('%c')\n", p.guest_io.data[0],
         p.guest_io.data[0]);
#else
  printf("Not x86_64; skipping.\n");
#endif  // __x86_64__

  END_TEST;
}

// K2 (synthetic-MSR read): a guest read of a claimed synthetic MSR surfaces to
// the VMM as a ZX_PKT_TYPE_GUEST_MSR packet rather than faulting, and the VMM
// completes it by supplying the value the guest observes. Non-vacuous: the
// reported byte exists only because the test wrote it between the two entries —
// nothing in the guest or the kernel can produce it.
bool vcpu_synthetic_msr_read_delegates() {
  BEGIN_TEST;

#ifdef __x86_64__
  constexpr uint32_t kSynthMsr = 0x40000021;
  constexpr uint8_t kVmmValue = 0x5A;

  fbl::RefPtr<VmObjectPaged> ram;
  ASSERT_EQ(ZX_OK, VmObjectPaged::Create(PMM_ALLOC_FLAG_ANY, 0u, kGuestRamSize, &ram), "ram\n");
  ASSERT_EQ(ZX_OK, WriteIdentityTables(ram), "tables\n");
  //   B9 21 00 00 40  mov ecx, 0x40000021
  //   0F 32           rdmsr          ; delegated exit; the VMM supplies rax
  //   E6 10           out 0x10, al   ; report what the VMM supplied
  //   F4              hlt
  const uint8_t code[] = {0xB9, 0x21, 0x00, 0x00, 0x40, 0x0F, 0x32, 0xE6, 0x10, 0xF4};
  ASSERT_EQ(ZX_OK, ram->Write(code, kCodeGpa, sizeof(code)), "code\n");
  ASSERT_EQ(ZX_OK, ram->CommitRange(0, kGuestRamSize), "commit\n");

  auto lg = CreateLiveGuest(ram, kCodeGpa);
  if (lg.is_error() && lg.status_value() == ZX_ERR_NOT_SUPPORTED) {
    printf("VMX not supported here; skipping synthetic-MSR read test.\n");
    return true;
  }
  ASSERT_EQ(ZX_OK, lg.status_value(), "create live guest\n");
  Vcpu* vcpu = lg->vcpu.get();
  ASSERT_EQ(ZX_OK, vcpu->SetMsrDelegation(true).status_value(), "enable MSR delegation\n");

  zx_port_packet_t p = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(p).status_value(), "enter to MSR read\n");
  ASSERT_EQ(static_cast<uint8_t>(ZX_PKT_TYPE_GUEST_MSR), static_cast<uint8_t>(p.type),
            "expected a delegated MSR exit\n");
  EXPECT_EQ(static_cast<uint64_t>(kSynthMsr), p.guest_msr.msr, "MSR index\n");
  EXPECT_FALSE(p.guest_msr.is_write, "expected a read\n");

  // Complete the read: the kernel has already advanced past the RDMSR, so the
  // VMM only has to leave the value in rax.
  zx_vcpu_state_t s = {};
  ASSERT_EQ(ZX_OK, vcpu->ReadState(s).status_value(), "ReadState\n");
  s.rax = (s.rax & ~0xffull) | kVmmValue;
  ASSERT_EQ(ZX_OK, vcpu->WriteState(s).status_value(), "WriteState (complete read)\n");

  zx_port_packet_t io = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(io).status_value(), "enter to report\n");
  ASSERT_EQ(static_cast<uint8_t>(ZX_PKT_TYPE_GUEST_IO), static_cast<uint8_t>(io.type), "io\n");
  EXPECT_EQ(static_cast<uint32_t>(kVmmValue), static_cast<uint32_t>(io.guest_io.data[0]),
            "guest must observe the VMM-supplied MSR value\n");
  printf("synthetic-MSR read OK: guest rdmsr(%#x) exited to the VMM; guest read back %#x\n",
         kSynthMsr, io.guest_io.data[0]);
#else
  printf("Not x86_64; skipping.\n");
#endif  // __x86_64__

  END_TEST;
}

// K2 (synthetic-MSR write): a guest write to a claimed synthetic MSR surfaces
// the register and the value the guest supplied, instead of faulting.
bool vcpu_synthetic_msr_write_delegates() {
  BEGIN_TEST;

#ifdef __x86_64__
  constexpr uint32_t kSynthMsr = 0x40000022;
  // edx:eax, i.e. the value the guest composes below.
  constexpr uint64_t kGuestValue = (static_cast<uint64_t>(0xF00D) << 32) | 0xBEEF;

  fbl::RefPtr<VmObjectPaged> ram;
  ASSERT_EQ(ZX_OK, VmObjectPaged::Create(PMM_ALLOC_FLAG_ANY, 0u, kGuestRamSize, &ram), "ram\n");
  ASSERT_EQ(ZX_OK, WriteIdentityTables(ram), "tables\n");
  //   B9 22 00 00 40  mov ecx, 0x40000022
  //   B8 EF BE 00 00  mov eax, 0xbeef
  //   BA 0D F0 00 00  mov edx, 0xf00d
  //   0F 30           wrmsr          ; delegated exit carrying edx:eax
  //   F4              hlt
  const uint8_t code[] = {0xB9, 0x22, 0x00, 0x00, 0x40, 0xB8, 0xEF, 0xBE, 0x00, 0x00,
                          0xBA, 0x0D, 0xF0, 0x00, 0x00, 0x0F, 0x30, 0xF4};
  ASSERT_EQ(ZX_OK, ram->Write(code, kCodeGpa, sizeof(code)), "code\n");
  ASSERT_EQ(ZX_OK, ram->CommitRange(0, kGuestRamSize), "commit\n");

  auto lg = CreateLiveGuest(ram, kCodeGpa);
  if (lg.is_error() && lg.status_value() == ZX_ERR_NOT_SUPPORTED) {
    printf("VMX not supported here; skipping synthetic-MSR write test.\n");
    return true;
  }
  ASSERT_EQ(ZX_OK, lg.status_value(), "create live guest\n");
  Vcpu* vcpu = lg->vcpu.get();
  ASSERT_EQ(ZX_OK, vcpu->SetMsrDelegation(true).status_value(), "enable MSR delegation\n");

  zx_port_packet_t p = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(p).status_value(), "enter to MSR write\n");
  ASSERT_EQ(static_cast<uint8_t>(ZX_PKT_TYPE_GUEST_MSR), static_cast<uint8_t>(p.type),
            "expected a delegated MSR exit\n");
  EXPECT_EQ(static_cast<uint64_t>(kSynthMsr), p.guest_msr.msr, "MSR index\n");
  EXPECT_TRUE(p.guest_msr.is_write, "expected a write\n");
  EXPECT_EQ(kGuestValue, p.guest_msr.value, "the value the guest wrote must be surfaced\n");
  printf("synthetic-MSR write OK: guest wrmsr(%#x) surfaced value %#lx\n", kSynthMsr,
         p.guest_msr.value);
#else
  printf("Not x86_64; skipping.\n");
#endif  // __x86_64__

  END_TEST;
}

// K3 (hypercall): a guest hypercall surfaces its operands to the VMM, and the
// VMM's result reaches the guest. Non-vacuous in both directions — the operands
// are guest-chosen sentinels, and the returned byte is VMM-chosen.
bool vcpu_hypercall_delegates() {
  BEGIN_TEST;

#ifdef __x86_64__
  constexpr uint64_t kInput = 0x1234;
  constexpr uint64_t kArg0 = 0x5678;
  constexpr uint64_t kArg1 = 0xABCD;
  constexpr uint8_t kVmmResult = 0x7E;

  fbl::RefPtr<VmObjectPaged> ram;
  ASSERT_EQ(ZX_OK, VmObjectPaged::Create(PMM_ALLOC_FLAG_ANY, 0u, kGuestRamSize, &ram), "ram\n");
  ASSERT_EQ(ZX_OK, WriteIdentityTables(ram), "tables\n");
  //   B9 34 12 00 00     mov ecx, 0x1234   ; hypercall input
  //   BA 78 56 00 00     mov edx, 0x5678   ; arg0
  //   41 B8 CD AB 00 00  mov r8d, 0xabcd   ; arg1
  //   0F 01 C1           vmcall            ; delegated exit; the VMM sets rax
  //   E6 10              out 0x10, al      ; report the VMM's result
  //   F4                 hlt
  const uint8_t code[] = {0xB9, 0x34, 0x12, 0x00, 0x00, 0xBA, 0x78, 0x56, 0x00,
                          0x00, 0x41, 0xB8, 0xCD, 0xAB, 0x00, 0x00, 0x0F, 0x01,
                          0xC1, 0xE6, 0x10, 0xF4};
  ASSERT_EQ(ZX_OK, ram->Write(code, kCodeGpa, sizeof(code)), "code\n");
  ASSERT_EQ(ZX_OK, ram->CommitRange(0, kGuestRamSize), "commit\n");

  auto lg = CreateLiveGuest(ram, kCodeGpa);
  if (lg.is_error() && lg.status_value() == ZX_ERR_NOT_SUPPORTED) {
    printf("VMX not supported here; skipping hypercall test.\n");
    return true;
  }
  ASSERT_EQ(ZX_OK, lg.status_value(), "create live guest\n");
  Vcpu* vcpu = lg->vcpu.get();
  ASSERT_EQ(ZX_OK, vcpu->SetHypercallDelegation(true).status_value(), "enable hypercall delegation\n");

  zx_port_packet_t p = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(p).status_value(), "enter to hypercall\n");
  ASSERT_EQ(static_cast<uint8_t>(ZX_PKT_TYPE_GUEST_HYPERCALL), static_cast<uint8_t>(p.type),
            "expected a delegated hypercall exit\n");
  EXPECT_EQ(kInput, p.guest_hypercall.input, "hypercall input (rcx)\n");
  EXPECT_EQ(kArg0, p.guest_hypercall.arg0, "hypercall arg0 (rdx)\n");
  EXPECT_EQ(kArg1, p.guest_hypercall.arg1, "hypercall arg1 (r8)\n");

  // Return a result the same way a delegated MSR read is completed.
  zx_vcpu_state_t s = {};
  ASSERT_EQ(ZX_OK, vcpu->ReadState(s).status_value(), "ReadState\n");
  s.rax = (s.rax & ~0xffull) | kVmmResult;
  ASSERT_EQ(ZX_OK, vcpu->WriteState(s).status_value(), "WriteState (hypercall result)\n");

  zx_port_packet_t io = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(io).status_value(), "enter to report\n");
  ASSERT_EQ(static_cast<uint8_t>(ZX_PKT_TYPE_GUEST_IO), static_cast<uint8_t>(io.type), "io\n");
  EXPECT_EQ(static_cast<uint32_t>(kVmmResult), static_cast<uint32_t>(io.guest_io.data[0]),
            "guest must observe the VMM's hypercall result\n");
  printf("hypercall OK: guest vmcall surfaced (input=%#lx, arg0=%#lx, arg1=%#lx); guest read "
         "result %#x\n",
         p.guest_hypercall.input, p.guest_hypercall.arg0, p.guest_hypercall.arg1,
         io.guest_io.data[0]);
#else
  printf("Not x86_64; skipping.\n");
#endif  // __x86_64__

  END_TEST;
}

// The default path must be untouched: with delegation off, a synthetic-MSR read
// still raises #GP in the guest exactly as before, rather than exiting to the
// VMM. Proven through the guest's own #GP handler, so this cannot pass by the
// exit merely being absent.
bool vcpu_synthetic_msr_faults_without_delegation() {
  BEGIN_TEST;

#ifdef __x86_64__
  auto guest_result = Guest::Create();
  if (guest_result.is_error() && guest_result.status_value() == ZX_ERR_NOT_SUPPORTED) {
    printf("VMX not supported here; skipping MSR no-delegation test.\n");
    return true;
  }
  ASSERT_EQ(ZX_OK, guest_result.status_value(), "Guest::Create failed\n");
  ktl::unique_ptr<Guest> guest = ktl::move(guest_result.value());

  constexpr uint64_t kGdtGpa = 0x6000;
  constexpr uint64_t kIdtGpa = 0x6800;
  constexpr uint64_t kHandlerGpa = 0x8000;
  constexpr uint64_t kStackTop = 0x9000;
  constexpr uint32_t kGpVector = 13;

  fbl::RefPtr<VmObjectPaged> golden;
  ASSERT_EQ(ZX_OK, VmObjectPaged::Create(PMM_ALLOC_FLAG_ANY, 0u, kGuestRamSize, &golden), "ram\n");
  ASSERT_EQ(ZX_OK, WriteIdentityTables(golden), "tables\n");
  //   B9 21 00 00 40  mov ecx, 0x40000021
  //   0F 32           rdmsr   ; no delegation -> #GP vectors through the guest IDT
  //   F4              hlt
  const uint8_t code[] = {0xB9, 0x21, 0x00, 0x00, 0x40, 0x0F, 0x32, 0xF4};
  ASSERT_EQ(ZX_OK, golden->Write(code, kCodeGpa, sizeof(code)), "code\n");

  const uint8_t gdt_code[8] = {0xFF, 0xFF, 0x00, 0x00, 0x00, 0x9B, 0xAF, 0x00};
  ASSERT_EQ(ZX_OK, golden->Write(gdt_code, kGdtGpa + 8, sizeof(gdt_code)), "GDT code desc\n");

  const uint8_t idt_gate[16] = {
      static_cast<uint8_t>(kHandlerGpa & 0xFF), static_cast<uint8_t>((kHandlerGpa >> 8) & 0xFF),
      0x08, 0x00, 0x00, 0x8E, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
  ASSERT_EQ(ZX_OK, golden->Write(idt_gate, kIdtGpa + kGpVector * 16, sizeof(idt_gate)),
            "IDT #GP gate\n");

  // Handler: mov al,0x6D; out 0x30,al; hlt.
  const uint8_t handler[] = {0xB0, 0x6D, 0xE6, 0x30, 0xF4};
  ASSERT_EQ(ZX_OK, golden->Write(handler, kHandlerGpa, sizeof(handler)), "handler\n");
  ASSERT_EQ(ZX_OK, golden->CommitRange(0, kGuestRamSize), "commit\n");

  auto mapping = guest->RootVmar()->CreateVmMapping(0, kGuestRamSize, 0, VMAR_FLAG_SPECIFIC, golden,
                                                    0, kMmuFlags, "guest-ram");
  ASSERT_EQ(ZX_OK, mapping.status_value(), "map\n");
  auto trap = guest->SetTrap(ZX_GUEST_TRAP_IO, 0x30, 1, nullptr, 0x30);
  ASSERT_EQ(ZX_OK, trap.status_value(), "trap 0x30\n");

  auto vcpu_result = Vcpu::Create(*guest, kCodeGpa);
  ASSERT_EQ(ZX_OK, vcpu_result.status_value(), "Vcpu::Create\n");
  ktl::unique_ptr<Vcpu> vcpu = ktl::move(vcpu_result.value());

  VcpuArchState s = {};
  ASSERT_EQ(ZX_OK, vcpu->SaveArchState(s).status_value(), "SaveArchState\n");
  s.gdtr_base = kGdtGpa;
  s.gdtr_limit = 0x0F;
  s.idtr_base = kIdtGpa;
  s.idtr_limit = 0xFFF;
  s.regs.rsp = kStackTop;
  ASSERT_EQ(ZX_OK, vcpu->RestoreArchState(s).status_value(), "load GDTR/IDTR/RSP\n");

  // Deliberately no SetMsrDelegation call: this is the default configuration.
  zx_port_packet_t p = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(p).status_value(), "enter\n");
  ASSERT_EQ(static_cast<uint8_t>(ZX_PKT_TYPE_GUEST_IO), static_cast<uint8_t>(p.type),
            "expected the guest's #GP handler to run, not an MSR exit\n");
  EXPECT_EQ(0x30u, p.guest_io.port, "handler port\n");
  EXPECT_EQ(0x6Du, static_cast<uint32_t>(p.guest_io.data[0]),
            "the guest's own #GP handler must have run\n");
  printf("no-delegation OK: synthetic-MSR read still faulted to the guest's #GP handler (%#x)\n",
         p.guest_io.data[0]);
#else
  printf("Not x86_64; skipping.\n");
#endif  // __x86_64__

  END_TEST;
}

// Writes a guest that executes CPUID on `leaf` and reports all four result
// registers as 32-bit OUTs to port 0x10, in eax/ebx/ecx/edx order. CPUID
// clobbers every one of those registers, so the results are parked in r8-r11 —
// which CPUID leaves alone — before edx is repurposed as the port number.
zx_status_t WriteCpuidProbe(const fbl::RefPtr<VmObjectPaged>& ram, uint64_t gpa, uint32_t leaf) {
  const uint8_t code[] = {
      0xB8, static_cast<uint8_t>(leaf), static_cast<uint8_t>(leaf >> 8),
      static_cast<uint8_t>(leaf >> 16), static_cast<uint8_t>(leaf >> 24),  // mov eax, leaf
      0x0F, 0xA2,                                                         // cpuid
      0x41, 0x89, 0xC0,                                                   // mov r8d, eax
      0x41, 0x89, 0xD9,                                                   // mov r9d, ebx
      0x41, 0x89, 0xCA,                                                   // mov r10d, ecx
      0x41, 0x89, 0xD3,                                                   // mov r11d, edx
      0xBA, 0x10, 0x00, 0x00, 0x00,                                       // mov edx, 0x10 (port)
      0x44, 0x89, 0xC0, 0xEF,                                             // mov eax,r8d ; out dx,eax
      0x44, 0x89, 0xC8, 0xEF,                                             // mov eax,r9d ; out dx,eax
      0x44, 0x89, 0xD0, 0xEF,                                             // mov eax,r10d; out dx,eax
      0x44, 0x89, 0xD8, 0xEF,                                             // mov eax,r11d; out dx,eax
      0xF4,                                                               // hlt
  };
  return ram->Write(code, gpa, sizeof(code));
}

// Runs the probe guest to its four I/O exits, collecting eax/ebx/ecx/edx.
zx::result<> ReadCpuidProbe(Vcpu* vcpu, uint32_t (&out)[4]) {
  for (uint32_t& reg : out) {
    zx_port_packet_t p = {};
    if (auto e = vcpu->Enter(p); e.is_error()) {
      return e.take_error();
    }
    if (p.type != ZX_PKT_TYPE_GUEST_IO || p.guest_io.access_size != 4) {
      return zx::error(ZX_ERR_BAD_STATE);
    }
    reg = p.guest_io.u32;
  }
  return zx::ok();
}

// K4: the Hyper-V feature/limit CPUID leaves are answered from values the VMM
// supplies, not from the host's CPUID. Non-vacuous: every value asserted here is
// one the VMM chose, and the host's CPUID could not produce it for these leaves
// (before this, they fell through and returned the highest base leaf's data).
bool vcpu_hyperv_cpuid_supplied_leaves() {
  BEGIN_TEST;

#ifdef __x86_64__
  // The minimum viable set: synthetic-MSR access (partition reference counter,
  // SynIC, synthetic timers, hypercall MSRs, VP index), the two hypercall
  // privileges VMBus needs, a long-spin-wait count that retires that hypercall,
  // and a partition sized to this test's guest.
  constexpr uint32_t kVersionEax = 0x1BADCAFE;
  constexpr uint32_t kFeatureEax = (1u << 1) | (1u << 2) | (1u << 3) | (1u << 5) | (1u << 6);
  constexpr uint32_t kFeatureEbx = (1u << 4) | (1u << 5);  // post_messages, signal_events
  constexpr uint32_t kRecommendEax = 1u << 9;              // deprecate_auto_eoi
  constexpr uint32_t kRecommendEbx = 0xffffffff;           // never notify on long spin waits
  constexpr uint32_t kMaxVps = 4;

  fbl::RefPtr<VmObjectPaged> ram;
  ASSERT_EQ(ZX_OK, VmObjectPaged::Create(PMM_ALLOC_FLAG_ANY, 0u, kGuestRamSize, &ram), "ram\n");
  ASSERT_EQ(ZX_OK, WriteIdentityTables(ram), "tables\n");
  ASSERT_EQ(ZX_OK, WriteCpuidProbe(ram, kCodeGpa, 0x40000003), "probe\n");
  ASSERT_EQ(ZX_OK, ram->CommitRange(0, kGuestRamSize), "commit\n");

  auto lg = CreateLiveGuest(ram, kCodeGpa);
  if (lg.is_error() && lg.status_value() == ZX_ERR_NOT_SUPPORTED) {
    printf("VMX not supported here; skipping Hyper-V CPUID leaf test.\n");
    return true;
  }
  ASSERT_EQ(ZX_OK, lg.status_value(), "create live guest\n");
  Vcpu* vcpu = lg->vcpu.get();

  // MSR delegation first: a Hyper-V identity without it is refused outright.
  // That configuration tells Windows "I am Hv#1" and then #GPs the first
  // synthetic-MSR write it makes.
  ASSERT_EQ(ZX_OK, vcpu->SetMsrDelegation(true).status_value(), "delegate synthetic MSRs\n");
  ASSERT_EQ(ZX_OK, vcpu->SetHypervIdentity(true).status_value(), "enable Hyper-V identity\n");
  ASSERT_EQ(ZX_OK, vcpu->SetHypervCpuidLeaf(0x40000002, {kVersionEax, 0, 0, 0}).status_value(),
            "set version leaf\n");
  ASSERT_EQ(ZX_OK,
            vcpu->SetHypervCpuidLeaf(0x40000003, {kFeatureEax, kFeatureEbx, 0, 0}).status_value(),
            "set feature leaf\n");
  ASSERT_EQ(
      ZX_OK,
      vcpu->SetHypervCpuidLeaf(0x40000004, {kRecommendEax, kRecommendEbx, 0, 0}).status_value(),
      "set recommendation leaf\n");
  ASSERT_EQ(ZX_OK, vcpu->SetHypervCpuidLeaf(0x40000005, {kMaxVps, kMaxVps, 0, 0}).status_value(),
            "set limits leaf\n");

  // Leaves outside the VMM-supplied range are the kernel's own, so they must be
  // refused rather than silently landing somewhere.
  EXPECT_EQ(ZX_ERR_INVALID_ARGS, vcpu->SetHypervCpuidLeaf(0x40000001, {}).status_value(),
            "identity leaf is not VMM-supplied\n");
  EXPECT_EQ(ZX_ERR_INVALID_ARGS, vcpu->SetHypervCpuidLeaf(0x40000006, {}).status_value(),
            "leaf past the advertised maximum is not VMM-supplied\n");

  uint32_t regs[4] = {};
  ASSERT_EQ(ZX_OK, ReadCpuidProbe(vcpu, regs).status_value(), "run feature-leaf probe\n");
  EXPECT_EQ(kFeatureEax, regs[0], "feature leaf eax\n");
  EXPECT_EQ(kFeatureEbx, regs[1], "feature leaf ebx\n");
  EXPECT_EQ(0u, regs[2], "feature leaf ecx\n");
  EXPECT_EQ(0u, regs[3], "feature leaf edx\n");
  printf("hyperv-leaf OK: 0x40000003 = %#x %#x %#x %#x\n", regs[0], regs[1], regs[2], regs[3]);
#else
  printf("Not x86_64; skipping.\n");
#endif  // __x86_64__

  END_TEST;
}

// A leaf inside the hypervisor-reserved range that we do not implement must read
// as zero — "not implemented" — rather than falling through to the host's CPUID.
// We advertise 0x40000005 as the maximum, so 0x40000006 is such a leaf.
bool vcpu_hyperv_cpuid_unimplemented_leaf_is_zero() {
  BEGIN_TEST;

#ifdef __x86_64__
  fbl::RefPtr<VmObjectPaged> ram;
  ASSERT_EQ(ZX_OK, VmObjectPaged::Create(PMM_ALLOC_FLAG_ANY, 0u, kGuestRamSize, &ram), "ram\n");
  ASSERT_EQ(ZX_OK, WriteIdentityTables(ram), "tables\n");
  ASSERT_EQ(ZX_OK, WriteCpuidProbe(ram, kCodeGpa, 0x40000006), "probe\n");
  ASSERT_EQ(ZX_OK, ram->CommitRange(0, kGuestRamSize), "commit\n");

  auto lg = CreateLiveGuest(ram, kCodeGpa);
  if (lg.is_error() && lg.status_value() == ZX_ERR_NOT_SUPPORTED) {
    printf("VMX not supported here; skipping unimplemented-leaf test.\n");
    return true;
  }
  ASSERT_EQ(ZX_OK, lg.status_value(), "create live guest\n");
  Vcpu* vcpu = lg->vcpu.get();
  // MSR delegation first: a Hyper-V identity without it is refused outright.
  // That configuration tells Windows "I am Hv#1" and then #GPs the first
  // synthetic-MSR write it makes.
  ASSERT_EQ(ZX_OK, vcpu->SetMsrDelegation(true).status_value(), "delegate synthetic MSRs\n");
  ASSERT_EQ(ZX_OK, vcpu->SetHypervIdentity(true).status_value(), "enable Hyper-V identity\n");

  uint32_t regs[4] = {};
  ASSERT_EQ(ZX_OK, ReadCpuidProbe(vcpu, regs).status_value(), "run probe\n");
  EXPECT_EQ(0u, regs[0], "eax\n");
  EXPECT_EQ(0u, regs[1], "ebx\n");
  EXPECT_EQ(0u, regs[2], "ecx\n");
  EXPECT_EQ(0u, regs[3], "edx\n");
  printf("hyperv-leaf OK: unimplemented leaf 0x40000006 reads as zero\n");
#else
  printf("Not x86_64; skipping.\n");
#endif  // __x86_64__

  END_TEST;
}

// Without the Hyper-V identity the supplied values must be inert: the guest is
// being shown the KVM identity, for which these leaves mean nothing, and it must
// see exactly what it saw before this feature existed.
bool vcpu_hyperv_cpuid_leaves_inert_without_identity() {
  BEGIN_TEST;

#ifdef __x86_64__
  constexpr uint32_t kFeatureEax = (1u << 1) | (1u << 2) | (1u << 3) | (1u << 5) | (1u << 6);

  fbl::RefPtr<VmObjectPaged> ram;
  ASSERT_EQ(ZX_OK, VmObjectPaged::Create(PMM_ALLOC_FLAG_ANY, 0u, kGuestRamSize, &ram), "ram\n");
  ASSERT_EQ(ZX_OK, WriteIdentityTables(ram), "tables\n");
  ASSERT_EQ(ZX_OK, WriteCpuidProbe(ram, kCodeGpa, 0x40000003), "probe\n");
  ASSERT_EQ(ZX_OK, ram->CommitRange(0, kGuestRamSize), "commit\n");

  auto lg = CreateLiveGuest(ram, kCodeGpa);
  if (lg.is_error() && lg.status_value() == ZX_ERR_NOT_SUPPORTED) {
    printf("VMX not supported here; skipping identity-off leaf test.\n");
    return true;
  }
  ASSERT_EQ(ZX_OK, lg.status_value(), "create live guest\n");
  Vcpu* vcpu = lg->vcpu.get();

  // Supply the values but leave the identity off (its default).
  ASSERT_EQ(ZX_OK, vcpu->SetHypervCpuidLeaf(0x40000003, {kFeatureEax, 0, 0, 0}).status_value(),
            "set feature leaf\n");

  uint32_t regs[4] = {};
  ASSERT_EQ(ZX_OK, ReadCpuidProbe(vcpu, regs).status_value(), "run probe\n");
  EXPECT_NE(kFeatureEax, regs[0],
            "supplied leaf must not be visible while the guest sees the KVM identity\n");
  printf("hyperv-leaf OK: identity off leaves 0x40000003 unsynthesized (eax=%#x)\n", regs[0]);
#else
  printf("Not x86_64; skipping.\n");
#endif  // __x86_64__

  END_TEST;
}

#ifdef __x86_64__
// Polls (up to ~5s) for |vector| to become pending in the vcpu's local-APIC
// interrupt tracker, sleeping between checks so timer IRQs can run. Returns
// whether it became pending. Used to observe an APIC timer actually firing
// without needing a guest IDT/GDT for full interrupt delivery.
bool WaitForInterruptPending(Vcpu* vcpu, uint32_t vector) {
  for (int i = 0; i < 5000; i++) {
    if (vcpu->InterruptPending(vector)) {
      return true;
    }
    Thread::Current::SleepRelative(ZX_MSEC(1));
  }
  return vcpu->InterruptPending(vector);
}

// x2APIC MSR indices and the paravirtual pv-clock MSR the guests below program directly.
constexpr uint32_t kX2ApicLvtTimer = 0x832;
constexpr uint32_t kX2ApicInitialCount = 0x838;
constexpr uint32_t kX2ApicDcr = 0x83e;
constexpr uint32_t kX2ApicSelfIpi = 0x83f;
#endif  // __x86_64__

// Async-state (local-APIC timer) reconstruction, validated non-vacuously: the
// guest arms a one-shot APIC timer; we capture the async state, serialize and
// deserialize it, wait for the *original* timer to fire, then restore from the
// deserialized blob and prove the *reconstructed* timer fires too. Restore first
// clears the (now-pending) vector, so its reappearance can only come from the
// re-armed timer — not a stale pending bit. This exercises the load-bearing
// claim that the live Timer is reconstructed (re-anchored to the clock), not
// blindly copied.
bool vcpu_async_state_apic_timer_reconstruct() {
  BEGIN_TEST;

#ifdef __x86_64__
  auto guest_result = Guest::Create();
  if (guest_result.is_error() && guest_result.status_value() == ZX_ERR_NOT_SUPPORTED) {
    printf("VMX not supported here; skipping async-state APIC-timer test.\n");
    return true;
  }
  ASSERT_EQ(ZX_OK, guest_result.status_value(), "Guest::Create failed\n");
  ktl::unique_ptr<Guest> guest = ktl::move(guest_result.value());

  fbl::RefPtr<VmObjectPaged> golden;
  ASSERT_EQ(ZX_OK, VmObjectPaged::Create(PMM_ALLOC_FLAG_ANY, 0u, kGuestRamSize, &golden),
            "create golden\n");
  ASSERT_EQ(ZX_OK, WriteIdentityTables(golden), "write tables\n");
  // Guest @0x3000, all in long mode:
  //   wrmsr LVT_TIMER   = 0x30    (vector 0x30, one-shot, unmasked)
  //   wrmsr DCR         = 0x0b    (divide-by-1)
  //   wrmsr INITIAL_CNT = 0x02000000  (arms the one-shot timer, ~tens of ms)
  //   out 0x10, 1       (signal "armed"); hlt
  const uint8_t code[] = {
      0xB9, 0x32, 0x08, 0x00, 0x00,        // mov ecx, 0x832  (LVT_TIMER)
      0xB8, 0x30, 0x00, 0x00, 0x00,        // mov eax, 0x30
      0x31, 0xD2,                          // xor edx, edx
      0x0F, 0x30,                          // wrmsr
      0xB9, 0x3E, 0x08, 0x00, 0x00,        // mov ecx, 0x83e  (DCR)
      0xB8, 0x0B, 0x00, 0x00, 0x00,        // mov eax, 0x0b
      0x0F, 0x30,                          // wrmsr
      0xB9, 0x38, 0x08, 0x00, 0x00,        // mov ecx, 0x838  (INITIAL_COUNT)
      0xB8, 0x00, 0x00, 0x00, 0x02,        // mov eax, 0x02000000
      0x0F, 0x30,                          // wrmsr  (arms timer)
      0xB0, 0x01,                          // mov al, 1
      0xE6, 0x10,                          // out 0x10, al
      0xF4,                                // hlt
  };
  ASSERT_EQ(ZX_OK, golden->Write(code, kCodeGpa, sizeof(code)), "write code\n");
  ASSERT_EQ(ZX_OK, golden->CommitRange(0, kGuestRamSize), "commit golden\n");

  fbl::RefPtr<VmObject> working;
  ASSERT_EQ(ZX_OK,
            golden->CreateClone(Resizability::NonResizable, SnapshotType::OnWrite, 0, kGuestRamSize,
                                false, &working),
            "clone working\n");
  working->set_user_id(ZX_KOID_KERNEL);
  auto mapping = guest->RootVmar()->CreateVmMapping(0, kGuestRamSize, 0, VMAR_FLAG_SPECIFIC,
                                                    working, 0, kMmuFlags, "guest-ram");
  ASSERT_EQ(ZX_OK, mapping.status_value(), "map guest RAM\n");
  auto t1 = guest->SetTrap(ZX_GUEST_TRAP_IO, 0x10, 1, nullptr, 0x10);
  ASSERT_EQ(ZX_OK, t1.status_value(), "trap 0x10\n");
  auto vcpu_result = Vcpu::Create(*guest, kCodeGpa);
  ASSERT_EQ(ZX_OK, vcpu_result.status_value(), "Vcpu::Create failed\n");
  ktl::unique_ptr<Vcpu> vcpu = ktl::move(vcpu_result.value());

  // Run until the guest reports it has armed the timer.
  zx_port_packet_t armed = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(armed).status_value(), "Enter to armed\n");
  ASSERT_EQ(0x10u, armed.guest_io.port, "armed port\n");

  // Capture the async state. The timer must read back armed, one-shot, vector
  // 0x30, with real remaining time.
  VcpuAsyncState a = {};
  ASSERT_EQ(ZX_OK, vcpu->SaveAsyncState(a).status_value(), "SaveAsyncState\n");
  EXPECT_EQ(1u, static_cast<uint32_t>(a.timer_armed), "timer must be captured as armed\n");
  EXPECT_EQ(0x30u, a.lvt_timer & 0xffu, "captured LVT timer vector\n");
  EXPECT_TRUE(a.timer_remaining_ns > 0, "captured remaining time must be positive\n");

  // Serialize -> flat buffer -> deserialize; the round-trip must be lossless.
  const size_t buf_len = SerializedVcpuAsyncStateSize();
  fbl::AllocChecker ac;
  ktl::unique_ptr<uint8_t[]> buffer(new (&ac) uint8_t[buf_len]);
  ASSERT_TRUE(ac.check(), "alloc buffer\n");
  ASSERT_EQ(ZX_OK, SerializeVcpuAsyncState(a, buffer.get(), buf_len).status_value(), "serialize\n");
  EXPECT_EQ(ZX_ERR_BUFFER_TOO_SMALL,
            SerializeVcpuAsyncState(a, buffer.get(), buf_len - 1).status_value(),
            "short buffer must be rejected\n");
  VcpuAsyncState a2 = {};
  ASSERT_EQ(ZX_OK, DeserializeVcpuAsyncState(a2, buffer.get(), buf_len).status_value(),
            "deserialize\n");
  EXPECT_EQ(0, memcmp(&a, &a2, sizeof(VcpuAsyncState)), "async serialize/deserialize lossless\n");

  // Prove restore reconstructs the timer, non-vacuously and without a timing
  // race. First restore a DISARMED variant of the captured state: this cancels
  // the timer and clears the pending set, so the vector is *stably* not pending
  // (there is no armed deadline to race against). Then restore the captured
  // ARMED state: the reconstructed one-shot timer must fire and post the vector.
  // Because the disarmed step left it clear with no timer, that fire can only
  // come from the timer the armed restore reconstructed.
  VcpuAsyncState disarmed = a2;
  disarmed.timer_armed = 0;
  disarmed.timer_remaining_ns = 0;
  memset(disarmed.pending_interrupts, 0, sizeof(disarmed.pending_interrupts));
  ASSERT_EQ(ZX_OK, vcpu->RestoreAsyncState(disarmed).status_value(), "RestoreAsyncState(disarmed)\n");
  EXPECT_FALSE(vcpu->InterruptPending(0x30),
               "with the timer restored disarmed, the vector must not be pending\n");

  // Reconstruct the armed timer from the captured snapshot — it must fire.
  ASSERT_EQ(ZX_OK, vcpu->RestoreAsyncState(a2).status_value(), "RestoreAsyncState(armed)\n");
  ASSERT_TRUE(WaitForInterruptPending(vcpu.get(), 0x30),
              "reconstructed APIC timer must fire after restore\n");

  printf("async-state APIC-timer OK: captured armed one-shot (vector 0x30, %lu ns remaining); "
         "after serialize/restore the reconstructed timer fired again\n",
         static_cast<unsigned long>(a.timer_remaining_ns));
#else
  printf("Not x86_64; skipping.\n");
#endif  // __x86_64__

  END_TEST;
}

// Async-state pending-interrupt authority + pv-clock reconstruction. The guest
// enables the paravirtual pv-clock and self-IPIs two vectors; we capture, prove the
// capture holds them, round-trip through serialization, then prove restore is
// *authoritative* over the pending set (it clears a pending vector and installs
// one that was not pending) and that it tears down and reconstructs the pv-clock
// mapping against real guest memory.
bool vcpu_async_state_pending_and_pvclock_roundtrip() {
  BEGIN_TEST;

#ifdef __x86_64__
  constexpr uint64_t kPvClockGpa = 0x6000;  // A free page for the pv-clock struct.

  auto guest_result = Guest::Create();
  if (guest_result.is_error() && guest_result.status_value() == ZX_ERR_NOT_SUPPORTED) {
    printf("VMX not supported here; skipping async-state pending/pv-clock test.\n");
    return true;
  }
  ASSERT_EQ(ZX_OK, guest_result.status_value(), "Guest::Create failed\n");
  ktl::unique_ptr<Guest> guest = ktl::move(guest_result.value());

  fbl::RefPtr<VmObjectPaged> golden;
  ASSERT_EQ(ZX_OK, VmObjectPaged::Create(PMM_ALLOC_FLAG_ANY, 0u, kGuestRamSize, &golden),
            "create golden\n");
  ASSERT_EQ(ZX_OK, WriteIdentityTables(golden), "write tables\n");
  // Guest @0x3000:
  //   wrmsr KVM_SYSTEM_TIME = kPvClockGpa | 1   (enable pv-clock)
  //   wrmsr SELF_IPI = 0x40 ; wrmsr SELF_IPI = 0x50   (make two vectors pending)
  //   out 0x10, 1 ; hlt
  const uint8_t code[] = {
      0xB9, 0x01, 0x4D, 0x56, 0x4B,        // mov ecx, 0x4b564d01 (KVM_SYSTEM_TIME)
      0xB8, 0x01, 0x60, 0x00, 0x00,        // mov eax, 0x6001  (kPvClockGpa | 1)
      0x31, 0xD2,                          // xor edx, edx
      0x0F, 0x30,                          // wrmsr
      0xB9, 0x3F, 0x08, 0x00, 0x00,        // mov ecx, 0x83f (SELF_IPI)
      0xB8, 0x40, 0x00, 0x00, 0x00,        // mov eax, 0x40
      0x0F, 0x30,                          // wrmsr
      0xB9, 0x3F, 0x08, 0x00, 0x00,        // mov ecx, 0x83f (SELF_IPI)
      0xB8, 0x50, 0x00, 0x00, 0x00,        // mov eax, 0x50
      0x0F, 0x30,                          // wrmsr
      0xB0, 0x01,                          // mov al, 1
      0xE6, 0x10,                          // out 0x10, al
      0xF4,                                // hlt
  };
  ASSERT_EQ(ZX_OK, golden->Write(code, kCodeGpa, sizeof(code)), "write code\n");
  ASSERT_EQ(ZX_OK, golden->CommitRange(0, kGuestRamSize), "commit golden\n");

  fbl::RefPtr<VmObject> working;
  ASSERT_EQ(ZX_OK,
            golden->CreateClone(Resizability::NonResizable, SnapshotType::OnWrite, 0, kGuestRamSize,
                                false, &working),
            "clone working\n");
  working->set_user_id(ZX_KOID_KERNEL);
  auto mapping = guest->RootVmar()->CreateVmMapping(0, kGuestRamSize, 0, VMAR_FLAG_SPECIFIC,
                                                    working, 0, kMmuFlags, "guest-ram");
  ASSERT_EQ(ZX_OK, mapping.status_value(), "map guest RAM\n");
  auto t1 = guest->SetTrap(ZX_GUEST_TRAP_IO, 0x10, 1, nullptr, 0x10);
  ASSERT_EQ(ZX_OK, t1.status_value(), "trap 0x10\n");
  auto vcpu_result = Vcpu::Create(*guest, kCodeGpa);
  ASSERT_EQ(ZX_OK, vcpu_result.status_value(), "Vcpu::Create failed\n");
  ktl::unique_ptr<Vcpu> vcpu = ktl::move(vcpu_result.value());

  zx_port_packet_t p = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(p).status_value(), "Enter\n");
  ASSERT_EQ(0x10u, p.guest_io.port, "signal port\n");

  // Capture: pv-clock enabled at the right gpa; vectors 0x40 and 0x50 pending.
  VcpuAsyncState a = {};
  ASSERT_EQ(ZX_OK, vcpu->SaveAsyncState(a).status_value(), "SaveAsyncState\n");
  EXPECT_EQ(1u, static_cast<uint32_t>(a.pv_clock_enabled), "pv-clock must be captured enabled\n");
  EXPECT_EQ(kPvClockGpa, a.pv_clock_guest_paddr, "pv-clock guest paddr captured\n");
  EXPECT_TRUE((a.pending_interrupts[0x40 / 8] & (1u << (0x40 % 8))) != 0, "vector 0x40 captured\n");
  EXPECT_TRUE((a.pending_interrupts[0x50 / 8] & (1u << (0x50 % 8))) != 0, "vector 0x50 captured\n");

  // Serialize round-trip.
  const size_t buf_len = SerializedVcpuAsyncStateSize();
  fbl::AllocChecker ac;
  ktl::unique_ptr<uint8_t[]> buffer(new (&ac) uint8_t[buf_len]);
  ASSERT_TRUE(ac.check(), "alloc buffer\n");
  ASSERT_EQ(ZX_OK, SerializeVcpuAsyncState(a, buffer.get(), buf_len).status_value(), "serialize\n");
  VcpuAsyncState a2 = {};
  ASSERT_EQ(ZX_OK, DeserializeVcpuAsyncState(a2, buffer.get(), buf_len).status_value(),
            "deserialize\n");
  EXPECT_EQ(0, memcmp(&a, &a2, sizeof(VcpuAsyncState)), "async serialize/deserialize lossless\n");

  // Restore authority over the pending set: from the deserialized copy, drop
  // 0x40 and add 0x60, then restore. The tracker must reflect *exactly* the
  // restored bitmap: 0x40 gone (was pending), 0x50 kept, 0x60 present (was not).
  VcpuAsyncState mod = a2;
  mod.pending_interrupts[0x40 / 8] &= static_cast<uint8_t>(~(1u << (0x40 % 8)));
  mod.pending_interrupts[0x60 / 8] |= static_cast<uint8_t>(1u << (0x60 % 8));
  ASSERT_EQ(ZX_OK, vcpu->RestoreAsyncState(mod).status_value(), "RestoreAsyncState (pending)\n");
  EXPECT_FALSE(vcpu->InterruptPending(0x40), "restore must clear the previously-pending 0x40\n");
  EXPECT_TRUE(vcpu->InterruptPending(0x50), "restore must keep 0x50\n");
  EXPECT_TRUE(vcpu->InterruptPending(0x60), "restore must install 0x60\n");

  // pv-clock teardown then reconstruction. Restoring a disabled clock stops it;
  // restoring the captured clock re-maps it against real guest memory (a bogus
  // gpa would fail), which we confirm by re-capturing.
  VcpuAsyncState down = a2;
  down.pv_clock_enabled = 0;
  ASSERT_EQ(ZX_OK, vcpu->RestoreAsyncState(down).status_value(), "RestoreAsyncState (clock down)\n");
  VcpuAsyncState chk = {};
  ASSERT_EQ(ZX_OK, vcpu->SaveAsyncState(chk).status_value(), "re-capture (down)\n");
  EXPECT_EQ(0u, static_cast<uint32_t>(chk.pv_clock_enabled), "pv-clock must be torn down\n");

  ASSERT_EQ(ZX_OK, vcpu->RestoreAsyncState(a2).status_value(), "RestoreAsyncState (clock up)\n");
  VcpuAsyncState chk2 = {};
  ASSERT_EQ(ZX_OK, vcpu->SaveAsyncState(chk2).status_value(), "re-capture (up)\n");
  EXPECT_EQ(1u, static_cast<uint32_t>(chk2.pv_clock_enabled), "pv-clock must be reconstructed\n");
  EXPECT_EQ(kPvClockGpa, chk2.pv_clock_guest_paddr, "reconstructed pv-clock gpa\n");

  printf("async-state pending/pv-clock OK: captured pending {0x40,0x50} + pv-clock @%#lx; restore "
         "was authoritative over pending and reconstructed the pv-clock mapping\n",
         static_cast<unsigned long>(kPvClockGpa));
#else
  printf("Not x86_64; skipping.\n");
#endif  // __x86_64__

  END_TEST;
}

// The end-to-end claim the async-state work exists to support: a timer armed by
// a guest, captured, serialized and restored, must go on to interrupt *that
// guest* — not merely re-appear in a host-side bitmap. The two tests above stop
// at the interrupt tracker, which proves reconstruction but not delivery; this
// one carries it the last step, through the guest's own IDT.
//
// The guest enables interrupts, arms a one-shot APIC timer on vector 0x30, and
// spins. We capture the async state, round-trip it, then restore a DISARMED copy
// and sleep past the deadline: the vector stays clear, which proves the live
// Timer was genuinely cancelled and that nothing already in flight can account
// for what follows. Only then do we restore an ARMED state. The reconstructed
// timer fires, and re-entering the guest vectors it through the guest IDT into a
// handler that reports over I/O. The reported byte can only have been written by
// guest code that the restored timer's interrupt reached.
//
// WHY THE GUEST ARMS A ~30-SECOND TIMER AND THE TEST SUPPLIES ITS OWN
// DEADLINE. This case used to be load-flaky: it failed once and passed on a
// re-run of the same binary. The guest armed a ~16 ms one-shot two instructions
// before the `out 0x10` that hands control back, and those two instructions are
// separated by a VM exit, a host round trip and a VM entry. On a box with four
// concurrent workloads, a scheduling delay longer than 16 ms in that window is
// ordinary, not exotic -- and then the timer had already fired by the time
// `SaveAsyncState` ran, so it captured as DISARMED and the test failed on an
// assertion about the capture rather than about anything it exists to prove.
//
// The fix is structural, not a widened tolerance. Two roles were being played by
// one timer -- "the artifact being captured" and "the thing that must fire soon"
// -- and they have opposite requirements. They are now separate:
//
//   * the GUEST arms a deliberately enormous one-shot (initial count
//     0xFFFFFFFF, divide-by-16: tens of seconds). Nothing that can happen in a
//     VM-exit round trip beats it, so the capture is deterministic. The test
//     asserts the captured remaining time is over a second, which is the
//     property that makes the rest sound rather than a slack allowance;
//   * the TEST then supplies the short deadline itself, by editing
//     `timer_remaining_ns` in the captured blob before restoring it. Every
//     interval anything is asserted about is now one this thread installed and
//     then measured, with no guest instruction in between.
//
// And the delay that used to be the flake is now DELIBERATE: the test sleeps
// well past the old 16 ms window before capturing. A scheduling hazard that only
// appears under load is not a thing to hope against; making it happen on every
// run is what turns the assumption into an asserted property.
bool vcpu_async_state_restored_timer_reaches_guest_idt() {
  BEGIN_TEST;

#ifdef __x86_64__
  auto guest_result = Guest::Create();
  if (guest_result.is_error() && guest_result.status_value() == ZX_ERR_NOT_SUPPORTED) {
    printf("VMX not supported here; skipping restored-timer delivery test.\n");
    return true;
  }
  ASSERT_EQ(ZX_OK, guest_result.status_value(), "Guest::Create failed\n");
  ktl::unique_ptr<Guest> guest = ktl::move(guest_result.value());

  constexpr uint64_t kGdtGpa = 0x6000;
  constexpr uint64_t kIdtGpa = 0x6800;
  constexpr uint64_t kHandlerGpa = 0x8000;
  constexpr uint64_t kStackTop = 0x9000;
  constexpr uint32_t kVector = 0x30;  // must match the LVT vector the guest programs.
  constexpr uint8_t kHandlerToken = 0x5A;

  fbl::RefPtr<VmObjectPaged> ram;
  ASSERT_EQ(ZX_OK, VmObjectPaged::Create(PMM_ALLOC_FLAG_ANY, 0u, kGuestRamSize, &ram), "ram\n");
  ASSERT_EQ(ZX_OK, WriteIdentityTables(ram), "tables\n");

  // Guest @0x3000, long mode:
  //   sti; nop            ; interruptible (nop clears the 1-instruction shadow)
  //   wrmsr LVT_TIMER   = 0x30        (vector 0x30, one-shot, unmasked)
  //   wrmsr DCR         = 0x03        (divide-by-16)
  //   wrmsr INITIAL_CNT = 0xFFFFFFFF  (arms the one-shot timer, tens of SECONDS)
  //   out 0x10, al        ; signal "armed" -> exit to us
  //   jmp $               ; spin until the timer interrupt vectors out
  //
  // The count and divisor are chosen to put the guest's own deadline far beyond
  // any scheduling delay this thread can suffer between the arming WRMSR exit
  // and the capture below, AND beyond the whole window this test waits in -- see
  // the note above the function. The test never waits for this deadline; it
  // replaces it.
  //
  // The divisor is not 1 on purpose. `lvt_deadline` used to compute
  // `lvt_initial_count << divisor_shift` in 32-bit arithmetic, so a maximal
  // count lost its high bits and every non-unity divide configuration produced a
  // deadline far earlier than the guest asked for. This test asked for tens of
  // seconds, got 1.77 s, and that is how the truncation was found; the
  // "more than ten seconds" assertion below is now its gate.
  const uint8_t code[] = {
      0xFB,                                 // sti
      0x90,                                 // nop
      0xB9, 0x32, 0x08, 0x00, 0x00,         // mov ecx, 0x832  (LVT_TIMER)
      0xB8, 0x30, 0x00, 0x00, 0x00,         // mov eax, 0x30
      0x31, 0xD2,                           // xor edx, edx
      0x0F, 0x30,                           // wrmsr
      0xB9, 0x3E, 0x08, 0x00, 0x00,         // mov ecx, 0x83e  (DCR)
      0xB8, 0x03, 0x00, 0x00, 0x00,         // mov eax, 0x03   (divide-by-16)
      0x0F, 0x30,                           // wrmsr
      0xB9, 0x38, 0x08, 0x00, 0x00,         // mov ecx, 0x838  (INITIAL_COUNT)
      0xB8, 0xFF, 0xFF, 0xFF, 0xFF,         // mov eax, 0xFFFFFFFF
      0x0F, 0x30,                           // wrmsr  (arms the timer)
      0xB0, 0x01,                           // mov al, 1
      0xE6, 0x10,                           // out 0x10, al
      0xEB, 0xFE,                           // jmp $
  };
  ASSERT_EQ(ZX_OK, ram->Write(code, kCodeGpa, sizeof(code)), "code\n");

  // GDT[1] = flat 64-bit code segment (selector 0x08), for the interrupt gate.
  const uint8_t gdt_code[8] = {0xFF, 0xFF, 0x00, 0x00, 0x00, 0x9B, 0xAF, 0x00};
  ASSERT_EQ(ZX_OK, ram->Write(gdt_code, kGdtGpa + 8, sizeof(gdt_code)), "GDT code desc\n");

  // IDT gate for kVector: 64-bit interrupt gate, selector 0x08, offset=handler.
  const uint8_t idt_gate[16] = {
      static_cast<uint8_t>(kHandlerGpa & 0xFF), static_cast<uint8_t>((kHandlerGpa >> 8) & 0xFF),
      0x08, 0x00, 0x00, 0x8E, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
  ASSERT_EQ(ZX_OK, ram->Write(idt_gate, kIdtGpa + kVector * 16, sizeof(idt_gate)), "IDT gate\n");

  // Handler: mov al,0x5A; out 0x31,al; hlt.
  const uint8_t handler[] = {0xB0, kHandlerToken, 0xE6, 0x31, 0xF4};
  ASSERT_EQ(ZX_OK, ram->Write(handler, kHandlerGpa, sizeof(handler)), "handler\n");
  ASSERT_EQ(ZX_OK, ram->CommitRange(0, kGuestRamSize), "commit\n");

  auto mapping = guest->RootVmar()->CreateVmMapping(0, kGuestRamSize, 0, VMAR_FLAG_SPECIFIC, ram, 0,
                                                    kMmuFlags, "guest-ram");
  ASSERT_EQ(ZX_OK, mapping.status_value(), "map guest RAM\n");
  auto t1 = guest->SetTrap(ZX_GUEST_TRAP_IO, 0x10, 1, nullptr, 0x10);
  ASSERT_EQ(ZX_OK, t1.status_value(), "trap 0x10\n");
  auto t2 = guest->SetTrap(ZX_GUEST_TRAP_IO, 0x31, 1, nullptr, 0x31);
  ASSERT_EQ(ZX_OK, t2.status_value(), "trap 0x31\n");

  auto vcpu_result = Vcpu::Create(*guest, kCodeGpa);
  ASSERT_EQ(ZX_OK, vcpu_result.status_value(), "Vcpu::Create failed\n");
  ktl::unique_ptr<Vcpu> vcpu = ktl::move(vcpu_result.value());

  // Give the guest a GDT, an IDT and a stack, so an interrupt can actually be
  // vectored rather than escalating to a shutdown.
  VcpuArchState s = {};
  ASSERT_EQ(ZX_OK, vcpu->SaveArchState(s).status_value(), "SaveArchState\n");
  s.gdtr_base = kGdtGpa;
  s.gdtr_limit = 0x0F;
  s.idtr_base = kIdtGpa;
  s.idtr_limit = 0xFFF;
  s.regs.rsp = kStackTop;
  ASSERT_EQ(ZX_OK, vcpu->RestoreArchState(s).status_value(), "load GDTR/IDTR/RSP\n");

  // Run until the guest reports it has armed the timer; it is now spinning.
  zx_port_packet_t armed = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(armed).status_value(), "Enter to armed\n");
  ASSERT_EQ(0x10u, armed.guest_io.port, "armed port\n");

  // THE DELAY THAT USED TO BE THE FLAKE, MADE DELIBERATE. This is longer than
  // the ~16 ms one-shot the guest used to arm, so a run of this test always
  // contains the scheduling delay that used to break it once in a while. If a
  // future edit shortens the guest's timer back into this range, this sleep
  // turns that into a deterministic failure instead of an occasional one.
  constexpr zx_duration_t kInjectedCaptureDelay = ZX_MSEC(100);
  Thread::Current::SleepRelative(kInjectedCaptureDelay);

  // Capture and round-trip the async state.
  VcpuAsyncState a = {};
  ASSERT_EQ(ZX_OK, vcpu->SaveAsyncState(a).status_value(), "SaveAsyncState\n");
  ASSERT_EQ(1u, static_cast<uint32_t>(a.timer_armed),
            "the timer must still be armed when it is captured. It is deliberately a tens-of-"
            "seconds one-shot so that this cannot depend on how quickly this thread got here\n");
  EXPECT_EQ(kVector, a.lvt_timer & 0xffu, "captured LVT timer vector\n");
  // The load-bearing property, asserted rather than assumed: the guest's own
  // deadline is far enough away that nothing below can be confused for it.
  // More than the whole budget WaitForInterruptPending will spend below (5 s),
  // with margin. A second was not enough: an implementation that ignored both
  // restores entirely could then have the guest's ORIGINAL timer fire inside the
  // waiter's window and be mistaken for the restored one.
  ASSERT_TRUE(a.timer_remaining_ns > static_cast<uint64_t>(ZX_SEC(10)),
              "the guest's deadline must be beyond the whole window this test waits in, so that "
              "every interval it measures is one it installed itself and the guest's own timer can "
              "never be what is observed firing\n");
  EXPECT_FALSE(vcpu->InterruptPending(kVector),
               "and nothing can have fired yet, even after the injected delay above\n");

  const size_t buf_len = SerializedVcpuAsyncStateSize();
  fbl::AllocChecker ac;
  ktl::unique_ptr<uint8_t[]> buffer(new (&ac) uint8_t[buf_len]);
  ASSERT_TRUE(ac.check(), "alloc buffer\n");
  ASSERT_EQ(ZX_OK, SerializeVcpuAsyncState(a, buffer.get(), buf_len).status_value(), "serialize\n");
  VcpuAsyncState a2 = {};
  ASSERT_EQ(ZX_OK, DeserializeVcpuAsyncState(a2, buffer.get(), buf_len).status_value(),
            "deserialize\n");
  ASSERT_EQ(0, memcmp(&a, &a2, sizeof(VcpuAsyncState)), "async round-trip lossless\n");

  // The header must actually be load-bearing. A blob produced by a kernel whose
  // async layout differs — or one that is not an async blob at all — has to be
  // refused, because misreading it would silently install a wrong timer.
  // [magic][version][payload size], three uint32s.
  VcpuAsyncState rejected = {};
  uint32_t saved_word = 0;
  memcpy(&saved_word, buffer.get() + 4, sizeof(saved_word));  // version
  const uint32_t stale_version = saved_word - 1;
  memcpy(buffer.get() + 4, &stale_version, sizeof(stale_version));
  EXPECT_EQ(ZX_ERR_INVALID_ARGS,
            DeserializeVcpuAsyncState(rejected, buffer.get(), buf_len).status_value(),
            "a blob from a kernel at an older async version must be refused\n");
  memcpy(buffer.get() + 4, &saved_word, sizeof(saved_word));

  memcpy(&saved_word, buffer.get(), sizeof(saved_word));  // magic
  const uint32_t arch_magic = 0x56435055;                 // 'VCPU' — the register blob's magic
  memcpy(buffer.get(), &arch_magic, sizeof(arch_magic));
  EXPECT_EQ(ZX_ERR_INVALID_ARGS,
            DeserializeVcpuAsyncState(rejected, buffer.get(), buf_len).status_value(),
            "a register-state blob must not be read as async state\n");
  memcpy(buffer.get(), &saved_word, sizeof(saved_word));

  // The short deadline is the TEST's, not the guest's: re-anchoring is exactly
  // what RestoreAsyncState does with this field, so writing it here is using the
  // interface, not bypassing it.
  constexpr zx_duration_t kShortDeadline = ZX_MSEC(20);
  VcpuAsyncState short_armed = a2;
  short_armed.timer_remaining_ns = static_cast<uint64_t>(kShortDeadline);
  memset(short_armed.pending_interrupts, 0, sizeof(short_armed.pending_interrupts));
  ASSERT_EQ(ZX_OK, vcpu->RestoreAsyncState(short_armed).status_value(),
            "RestoreAsyncState(short)\n");

  // Now cancel it and wait past that deadline. If the vector is still clear
  // afterwards, a disarmed restore provably kills a LIVE timer, so any later
  // firing is attributable only to restore.
  //
  // Race-free in the direction that matters: a disarmed restore also clears the
  // pending set, so even if this thread were descheduled past the 20 ms and the
  // short timer fired first, its bit is erased here and the assertion below
  // still only sees a firing that happened AFTER the cancel -- which is the
  // thing being ruled out. The failing direction (restore does not cancel)
  // cannot be hidden by any delay.
  VcpuAsyncState disarmed = a2;
  disarmed.timer_armed = 0;
  disarmed.timer_remaining_ns = 0;
  memset(disarmed.pending_interrupts, 0, sizeof(disarmed.pending_interrupts));
  ASSERT_EQ(ZX_OK, vcpu->RestoreAsyncState(disarmed).status_value(),
            "RestoreAsyncState(disarmed)\n");
  Thread::Current::SleepRelative(zx_duration_add_duration(kShortDeadline, ZX_MSEC(50)));
  ASSERT_FALSE(vcpu->InterruptPending(kVector),
               "a live APIC timer must be cancelled by a disarmed restore\n");

  // Restore the armed state: the reconstructed timer must fire...
  const zx_instant_mono_t rearmed_at = current_mono_time();
  ASSERT_EQ(ZX_OK, vcpu->RestoreAsyncState(short_armed).status_value(),
            "RestoreAsyncState(armed)\n");
  // NOT YET. An implementation that answered "armed" by simply setting the LVT
  // vector pending -- no Timer, no deadline -- would satisfy every other
  // assertion here, including the disarmed phase, whose restore would clear that
  // synchronous bit and leave nothing to fire. This is the assertion it fails.
  ASSERT_FALSE(vcpu->InterruptPending(kVector),
               "restoring an armed timer must SCHEDULE it, not deliver it: the vector must still "
               "be clear immediately after the restore\n");
  ASSERT_TRUE(WaitForInterruptPending(vcpu.get(), kVector),
              "reconstructed APIC timer must fire after restore\n");
  // ...and it must be the RESTORED timer, not the guest's. The guest's own
  // deadline was asserted above to be over a second out and this fires in tens
  // of milliseconds, so the two cannot be confused. An implementation that
  // ignored the restored remaining time and kept the guest's deadline fails
  // here (and would already have exhausted WaitForInterruptPending's budget).
  const zx_duration_t fired_after = zx_time_sub_time(current_mono_time(), rearmed_at);
  EXPECT_LT(fired_after, static_cast<zx_duration_t>(a.timer_remaining_ns),
            "the firing must be the restored deadline, which is far shorter than the guest's\n");
  // Bounded from BELOW as well, so the observed firing has to have waited. Half
  // the restored deadline, because the poll granularity is coarser than the
  // deadline is precise; the point is only that it is not instantaneous.
  EXPECT_GT(fired_after, kShortDeadline / 2,
            "and it must have taken roughly the restored deadline to arrive -- an implementation "
            "that sets the vector pending at restore time fires in zero\n");

  // ...and, on re-entry, be delivered into the guest through its own IDT.
  zx_port_packet_t handled = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(handled).status_value(), "Enter to deliver\n");
  ASSERT_EQ(static_cast<uint8_t>(ZX_PKT_TYPE_GUEST_IO), static_cast<uint8_t>(handled.type),
            "expected the handler's I/O exit\n");
  EXPECT_EQ(0x31u, handled.guest_io.port, "handler port\n");
  EXPECT_EQ(static_cast<uint32_t>(kHandlerToken), static_cast<uint32_t>(handled.guest_io.data[0]),
            "the guest's own IDT handler for the timer vector must have run\n");

  // A one-shot that has fired is spent. Capturing it again must not describe it
  // as armed — a snapshot that did would fire the same interrupt a second time
  // every time it was restored.
  VcpuAsyncState spent = {};
  ASSERT_EQ(ZX_OK, vcpu->SaveAsyncState(spent).status_value(), "SaveAsyncState (spent)\n");
  EXPECT_EQ(0u, static_cast<uint32_t>(spent.timer_armed),
            "a one-shot that already fired must capture as disarmed\n");

  printf("async-state timer-delivery OK: guest armed one-shot vector %#x, captured %lu ns out "
         "(after a deliberate %lu ms delay, so the capture does not race the guest's own "
         "deadline); a %lu ms restored deadline was cancelled by a disarmed restore and stayed "
         "clear, then re-armed and fired %lu ns later -- far short of the guest's own -- and "
         "vectored through the guest IDT (handler wrote %#x)\n",
         kVector, static_cast<unsigned long>(a.timer_remaining_ns),
         static_cast<unsigned long>(kInjectedCaptureDelay / ZX_MSEC(1)),
         static_cast<unsigned long>(kShortDeadline / ZX_MSEC(1)),
         static_cast<unsigned long>(fired_after), handled.guest_io.data[0]);
#else
  printf("Not x86_64; skipping.\n");
#endif  // __x86_64__

  END_TEST;
}

// A guest that faults with no handler installed shuts itself down, and the VMM
// must be told — a guest that cannot be resumed and a guest that is merely slow
// look identical otherwise. This runs a guest with no interrupt descriptor table
// and an instruction that always faults: the fault has nowhere to go, so the
// processor gives up. Before this was surfaced the VCPU re-entered and faulted
// again indefinitely, reporting nothing to the VMM.
bool vcpu_triple_fault_surfaces_halt() {
  BEGIN_TEST;

#ifdef __x86_64__
  fbl::RefPtr<VmObjectPaged> ram;
  ASSERT_EQ(ZX_OK, VmObjectPaged::Create(PMM_ALLOC_FLAG_ANY, 0u, kGuestRamSize, &ram), "ram\n");
  ASSERT_EQ(ZX_OK, WriteIdentityTables(ram), "tables\n");
  // ud2 — always raises an invalid-opcode fault. The guest has no IDT, so the
  // fault escalates until the processor shuts the guest down.
  const uint8_t code[] = {0x0F, 0x0B};
  ASSERT_EQ(ZX_OK, ram->Write(code, kCodeGpa, sizeof(code)), "code\n");
  ASSERT_EQ(ZX_OK, ram->CommitRange(0, kGuestRamSize), "commit\n");

  auto lg = CreateLiveGuest(ram, kCodeGpa);
  if (lg.is_error() && lg.status_value() == ZX_ERR_NOT_SUPPORTED) {
    printf("VMX not supported here; skipping triple-fault test.\n");
    return true;
  }
  ASSERT_EQ(ZX_OK, lg.status_value(), "create live guest\n");

  zx_port_packet_t p = {};
  ASSERT_EQ(ZX_OK, lg->vcpu->Enter(p).status_value(), "enter\n");
  ASSERT_EQ(static_cast<uint8_t>(ZX_PKT_TYPE_GUEST_HALT), static_cast<uint8_t>(p.type),
            "a guest that shuts down must surface a halt, not resume\n");
  EXPECT_EQ(static_cast<uint32_t>(ZX_PKT_GUEST_HALT_TRIPLE_FAULT), p.guest_halt.reason,
            "wrong halt reason\n");
  EXPECT_EQ(kCodeGpa, p.guest_halt.rip, "halt must report where the guest stopped\n");
  printf("triple-fault OK: guest shutdown surfaced as a halt at rip %#lx\n", p.guest_halt.rip);
#else
  printf("Not x86_64; skipping.\n");
#endif  // __x86_64__

  END_TEST;
}

#ifdef __x86_64__
// ---------------------------------------------------------------------------
// ZX_VCPU_STATE_ENLIGHTENMENT: the userspace-facing path to the paravirtual
// configuration.
//
// The tests above drive the in-kernel setters directly. These drive
// VcpuDispatcher — the object a syscall resolves a handle to, and the layer
// zx_vcpu_read_state()/zx_vcpu_write_state() call straight into. Only the handle
// lookup and the user copy sit above it, so what a VMM will actually reach is
// covered here rather than assumed.
// ---------------------------------------------------------------------------

// A guest + vcpu owned through the dispatcher layer, mapped and trapped the same
// way CreateLiveGuest does.
struct LiveGuestDispatcher {
  fbl::RefPtr<GuestDispatcher> guest;
  fbl::RefPtr<VcpuDispatcher> vcpu;
};

zx::result<LiveGuestDispatcher> CreateLiveGuestDispatcher(const fbl::RefPtr<VmObject>& ram,
                                                          uint64_t entry) {
  KernelHandle<GuestDispatcher> guest_handle;
  KernelHandle<VmAddressRegionDispatcher> vmar_handle;
  zx_rights_t guest_rights = 0, vmar_rights = 0;
  if (zx_status_t status =
          GuestDispatcher::Create(0, &guest_handle, &guest_rights, &vmar_handle, &vmar_rights);
      status != ZX_OK) {
    return zx::error(status);
  }
  // release() hands over the reference without running the dispatcher's
  // zero-handles path, which is what a real handle table would keep alive.
  fbl::RefPtr<GuestDispatcher> guest = guest_handle.release();
  // The VMAR dispatcher is just a handle onto the guest's root VMAR, which the
  // GuestDispatcher owns; map through the VMAR itself as CreateLiveGuest does.
  vmar_handle.release();

  auto mapping = guest->guest().RootVmar()->CreateVmMapping(0, kGuestRamSize, 0, VMAR_FLAG_SPECIFIC,
                                                            ram, 0, kMmuFlags, "guest-ram");
  if (mapping.is_error()) {
    return mapping.take_error();
  }
  if (zx_status_t status = guest->SetTrap(ZX_GUEST_TRAP_IO, 0x10, 1, nullptr, 0x10);
      status != ZX_OK) {
    return zx::error(status);
  }
  if (zx_status_t status = guest->SetTrap(ZX_GUEST_TRAP_IO, 0x11, 1, nullptr, 0x11);
      status != ZX_OK) {
    return zx::error(status);
  }

  KernelHandle<VcpuDispatcher> vcpu_handle;
  zx_rights_t vcpu_rights = 0;
  if (zx_status_t status =
          VcpuDispatcher::Create(guest, /*options=*/0, entry, &vcpu_handle, &vcpu_rights);
      status != ZX_OK) {
    return zx::error(status);
  }
  LiveGuestDispatcher lg;
  lg.guest = ktl::move(guest);
  lg.vcpu = vcpu_handle.release();
  return zx::ok(ktl::move(lg));
}

// The structure a VMM fills in for ZX_VCPU_STATE_ENLIGHTENMENT, with the
// self-describing header already correct.
zx_vcpu_enlightenment_t MakeEnlightenment(uint32_t flags) {
  zx_vcpu_enlightenment_t e = {};
  e.magic = ZX_VCPU_ENLIGHTENMENT_MAGIC;
  e.version = ZX_VCPU_ENLIGHTENMENT_VERSION;
  e.size = sizeof(e);
  e.flags = flags;
  return e;
}

zx_vcpu_debug_state_t MakeDebugState(uint64_t active_flags) {
  zx_vcpu_debug_state_t state = {};
  state.magic = ZX_VCPU_DEBUG_STATE_MAGIC;
  state.version = ZX_VCPU_DEBUG_STATE_VERSION;
  state.size = sizeof(state);
  state.active_flags = active_flags;
  return state;
}

zx_vcpu_run_control_t MakeRunControl(uint64_t active_flags, uint32_t timer_ticks) {
  zx_vcpu_run_control_t state = {};
  state.magic = ZX_VCPU_RUN_CONTROL_MAGIC;
  state.version = ZX_VCPU_RUN_CONTROL_VERSION;
  state.size = sizeof(state);
  state.active_flags = active_flags;
  state.preemption_timer_ticks = timer_ticks;
  return state;
}

zx_vcpu_exit_control_t MakeExitControl(uint64_t active_flags, uint64_t reasons0,
                                       uint64_t reasons1, uint64_t exit_budget,
                                       uint64_t ack_sequence = 0) {
  zx_vcpu_exit_control_t state = {};
  state.magic = ZX_VCPU_EXIT_CONTROL_MAGIC;
  state.version = ZX_VCPU_EXIT_CONTROL_VERSION;
  state.size = sizeof(state);
  state.active_flags = active_flags;
  state.selected_reasons[0] = reasons0;
  state.selected_reasons[1] = reasons1;
  state.exit_budget = exit_budget;
  state.ack_sequence = ack_sequence;
  return state;
}

zx_vcpu_instruction_control_t MakeInstructionControl(uint64_t active_flags,
                                                     uint64_t budget,
                                                     uint64_t ack_sequence = 0) {
  zx_vcpu_instruction_control_t state = {};
  state.magic = ZX_VCPU_INSTRUCTION_CONTROL_MAGIC;
  state.version = ZX_VCPU_INSTRUCTION_CONTROL_VERSION;
  state.size = sizeof(state);
  state.active_flags = active_flags;
  state.budget = budget;
  state.ack_sequence = ack_sequence;
  return state;
}

zx_vcpu_memory_access_control_t MakeMemoryAccessControl(uint64_t active_flags,
                                                        uint64_t ack_sequence = 0) {
  zx_vcpu_memory_access_control_t state = {};
  state.magic = ZX_VCPU_MEMORY_ACCESS_CONTROL_MAGIC;
  state.version = ZX_VCPU_MEMORY_ACCESS_CONTROL_VERSION;
  state.size = sizeof(state);
  state.active_flags = active_flags;
  state.ack_sequence = ack_sequence;
  return state;
}

zx_vcpu_hardware_breakpoint_control_t MakeHardwareBreakpointControl(
    uint64_t active_flags, uint64_t address = 0,
    zx_vcpu_hardware_breakpoint_access_t access = 0,
    zx_vcpu_hardware_breakpoint_length_t length = 0,
    uint32_t condition_index = 0, uint64_t ack_sequence = 0) {
  zx_vcpu_hardware_breakpoint_control_t state = {};
  state.magic = ZX_VCPU_HARDWARE_BREAKPOINT_CONTROL_MAGIC;
  state.version = ZX_VCPU_HARDWARE_BREAKPOINT_CONTROL_VERSION;
  state.size = sizeof(state);
  state.active_flags = active_flags;
  state.ack_sequence = ack_sequence;
  if ((active_flags & ZX_VCPU_HARDWARE_BREAKPOINT_ARM) != 0) {
    state.request_count = 1;
    state.requests[0].address = address;
    state.requests[0].access = access;
    state.requests[0].length = length;
    state.requests[0].condition_index = condition_index;
  }
  return state;
}

bool SameEnlightenment(const zx_vcpu_enlightenment_t& a, const zx_vcpu_enlightenment_t& b) {
  if (a.magic != b.magic || a.version != b.version || a.size != b.size || a.flags != b.flags ||
      a.cpuid_count != b.cpuid_count || a.reserved != b.reserved) {
    return false;
  }
  for (uint32_t i = 0; i < ZX_VCPU_HYPERV_CPUID_MAX; i++) {
    if (a.cpuid[i].leaf != b.cpuid[i].leaf || a.cpuid[i].eax != b.cpuid[i].eax ||
        a.cpuid[i].ebx != b.cpuid[i].ebx || a.cpuid[i].ecx != b.cpuid[i].ecx ||
        a.cpuid[i].edx != b.cpuid[i].edx) {
      return false;
    }
  }
  return true;
}
#endif  // __x86_64__

// Drive the debug-register control through a real VM entry. The three phases
// distinguish a non-hit from an execute stop and a data stop, and the data
// phase has the guest claim DR0 while the host request is armed. The host must
// transparently move its request to a free slot rather than confiscating DR0.
bool vcpu_hardware_breakpoint_execute_data_and_guest_coexistence() {
  BEGIN_TEST;

#ifdef __x86_64__
  // Phase 1: an unrelated request must not create an exit.
  // Phase 2: the instruction at +4 must stop before execution.
  // Phase 3: guest MOV-DR instructions claim DR0, then a four-byte store stops
  // after the access. The final two reports prove the guest still owns DR0 and
  // DR7 after the host stop is acknowledged.
  const uint8_t code[] = {
      0xB0, 0x31, 0xE6, 0x10,                    // +0: first report
      0xB0, 0x32, 0xE6, 0x10,                    // +4: execute stop, second report
      0x48, 0xC7, 0xC3, 0x55, 0x55, 0x00, 0x00,  // +8: rbx = 0x5555
      0x0F, 0x23, 0xC3,                          // +15: mov dr0,rbx
      0x48, 0xC7, 0xC3, 0x01, 0x00, 0x00, 0x00,  // +18: rbx = L0
      0x0F, 0x23, 0xFB,                          // +25: mov dr7,rbx
      0x48, 0xC7, 0xC0, 0x00, 0x40, 0x00, 0x00,  // +28: rax = data
      0xC7, 0x00, 0x12, 0x34, 0x56, 0x78,        // +35: watched store
      0x0F, 0x21, 0xC0, 0xE6, 0x10,              // +41: report DR0 low byte
      0x0F, 0x21, 0xF8, 0xE6, 0x10,              // +46: report DR7 low byte
      0xF4,
  };
  static_assert(sizeof(code) == 52);

  fbl::RefPtr<VmObjectPaged> ram;
  ASSERT_EQ(ZX_OK, VmObjectPaged::Create(PMM_ALLOC_FLAG_ANY, 0u, kGuestRamSize, &ram), "ram\n");
  ASSERT_EQ(ZX_OK, WriteIdentityTables(ram), "tables\n");
  ASSERT_EQ(ZX_OK, ram->Write(code, kCodeGpa, sizeof(code)), "code\n");
  ASSERT_EQ(ZX_OK, ram->CommitRange(0, kGuestRamSize), "commit\n");

  auto lg = CreateLiveGuestDispatcher(ram, kCodeGpa);
  if (lg.is_error() && lg.status_value() == ZX_ERR_NOT_SUPPORTED) {
    printf("VMX not supported here; skipping hardware-breakpoint entry test.\n");
    return true;
  }
  ASSERT_EQ(ZX_OK, lg.status_value(), "create live guest\n");
  VcpuDispatcher* vcpu = lg->vcpu.get();

  zx_vcpu_hardware_breakpoint_control_t capability = {};
  ASSERT_EQ(ZX_OK, vcpu->ReadState(capability), "read capability\n");
  EXPECT_EQ(ZX_VCPU_HARDWARE_BREAKPOINT_CONTROL_MAGIC, capability.magic, "magic\n");
  EXPECT_EQ(ZX_VCPU_HARDWARE_BREAKPOINT_CONTROL_VERSION, capability.version, "version\n");
  EXPECT_EQ(sizeof(capability), capability.size, "size\n");
  EXPECT_EQ(ZX_VCPU_HARDWARE_BREAKPOINT_MAX_REQUESTS,
            static_cast<uint32_t>(capability.max_requests), "request limit\n");
  EXPECT_EQ(4u, static_cast<uint32_t>(capability.max_slots), "architectural slot limit\n");
  if (capability.availability == ZX_VCPU_HARDWARE_BREAKPOINT_UNSUPPORTED) {
    auto refused = MakeHardwareBreakpointControl(
        ZX_VCPU_HARDWARE_BREAKPOINT_ARM, kCodeGpa,
        ZX_VCPU_HARDWARE_BREAKPOINT_EXECUTE,
        ZX_VCPU_HARDWARE_BREAKPOINT_LENGTH_1, 1);
    EXPECT_EQ(ZX_ERR_NOT_SUPPORTED, vcpu->WriteState(refused),
              "unavailable control must fail closed\n");
    zx_vcpu_hardware_breakpoint_control_t after = {};
    ASSERT_EQ(ZX_OK, vcpu->ReadState(after), "read after refusal\n");
    EXPECT_EQ(0u, after.active_flags, "refusal must not arm anything\n");
    printf("hardware-breakpoint entry control unavailable on this VMX host; fail-closed path OK.\n");
    return true;
  }

  // Whole-state replacement cancels host run controls. Exercise it while the
  // heap-backed breakpoint session is live: the session must be destroyed only
  // after the VMCS guard restores normal blocking.
  const size_t full_size = SerializedVcpuStateSize();
  fbl::AllocChecker full_ac;
  ktl::unique_ptr<uint8_t[]> full(new (&full_ac) uint8_t[full_size]);
  ASSERT_TRUE(full_ac.check(), "allocate whole-state buffer\n");
  size_t full_actual = 0;
  ASSERT_EQ(ZX_OK, vcpu->ReadStateFull(full.get(), full_size, &full_actual),
            "capture whole state before breakpoint restore cleanup\n");
  ASSERT_EQ(full_size, full_actual, "whole-state size\n");
  auto restore_cleanup = MakeHardwareBreakpointControl(
      ZX_VCPU_HARDWARE_BREAKPOINT_ARM, kCode2Gpa,
      ZX_VCPU_HARDWARE_BREAKPOINT_EXECUTE,
      ZX_VCPU_HARDWARE_BREAKPOINT_LENGTH_1, 1);
  ASSERT_EQ(ZX_OK, vcpu->WriteState(restore_cleanup),
            "arm before whole-state replacement\n");
  ASSERT_EQ(ZX_OK, vcpu->WriteStateFull(full.get(), full_actual),
            "whole-state replacement cancels breakpoint control\n");
  zx_vcpu_hardware_breakpoint_control_t after_restore = {};
  ASSERT_EQ(ZX_OK, vcpu->ReadState(after_restore),
            "read breakpoint control after whole-state replacement\n");
  EXPECT_EQ(0u, after_restore.active_flags,
            "whole-state replacement disarms breakpoint control\n");
  EXPECT_EQ(0u, after_restore.pending_sequence,
            "whole-state replacement drops pending breakpoint state\n");
  EXPECT_EQ(0u, after_restore.request_count,
            "whole-state replacement drops breakpoint requests\n");

  // No matching RIP: ordinary execution reaches the first report and the
  // request remains armed with no pending record.
  auto negative = MakeHardwareBreakpointControl(
      ZX_VCPU_HARDWARE_BREAKPOINT_ARM, kCode2Gpa,
      ZX_VCPU_HARDWARE_BREAKPOINT_EXECUTE,
      ZX_VCPU_HARDWARE_BREAKPOINT_LENGTH_1, 2);
  ASSERT_EQ(ZX_OK, vcpu->WriteState(negative), "arm negative execute request\n");
  zx_port_packet_t packet = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(packet), "run negative phase\n");
  ASSERT_EQ(static_cast<uint8_t>(ZX_PKT_TYPE_GUEST_IO), static_cast<uint8_t>(packet.type),
            "negative request must not invent a debug stop\n");
  EXPECT_EQ(0x31u, static_cast<uint32_t>(packet.guest_io.data[0]), "first report\n");
  zx_vcpu_hardware_breakpoint_control_t still_armed = {};
  ASSERT_EQ(ZX_OK, vcpu->ReadState(still_armed), "read negative request\n");
  EXPECT_EQ(ZX_VCPU_HARDWARE_BREAKPOINT_ARM, still_armed.active_flags,
            "non-hit remains armed\n");
  EXPECT_EQ(0u, still_armed.pending_sequence, "non-hit has no pending result\n");
  ASSERT_EQ(ZX_OK, vcpu->WriteState(MakeHardwareBreakpointControl(0)),
            "disarm negative request\n");

  // The next instruction is at +4. Execute breakpoints report that RIP before
  // the instruction changes AL.
  constexpr uint32_t kExecuteCondition = 7;
  auto execute = MakeHardwareBreakpointControl(
      ZX_VCPU_HARDWARE_BREAKPOINT_ARM, kCodeGpa + 4,
      ZX_VCPU_HARDWARE_BREAKPOINT_EXECUTE,
      ZX_VCPU_HARDWARE_BREAKPOINT_LENGTH_1, kExecuteCondition);
  ASSERT_EQ(ZX_OK, vcpu->WriteState(execute), "arm execute request\n");
  packet = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(packet), "run to execute stop\n");
  ASSERT_EQ(static_cast<uint8_t>(ZX_PKT_TYPE_GUEST_HARDWARE_BREAKPOINT),
            static_cast<uint8_t>(packet.type), "typed execute packet\n");
  EXPECT_EQ(kCodeGpa + 4, packet.guest_hardware_breakpoint.rip, "pre-instruction RIP\n");
  EXPECT_EQ(uint64_t{1} << kExecuteCondition,
            packet.guest_hardware_breakpoint.condition_mask, "execute condition\n");
  EXPECT_EQ(ZX_VCPU_HARDWARE_BREAKPOINT_PRE_INSTRUCTION,
            static_cast<uint32_t>(packet.guest_hardware_breakpoint.boundary),
            "execute boundary\n");

  zx_vcpu_hardware_breakpoint_control_t execute_pending = {};
  ASSERT_EQ(ZX_OK, vcpu->ReadState(execute_pending), "read execute result\n");
  EXPECT_EQ(packet.guest_hardware_breakpoint.sequence, execute_pending.pending_sequence,
            "packet and state sequence agree\n");
  EXPECT_EQ(0u, execute_pending.pending_guest_dr6 & execute_pending.pending_slot_mask,
            "host-owned DR6 causes are hidden from the guest\n");
  size_t pending_full_actual = 0;
  ASSERT_EQ(ZX_OK,
            vcpu->ReadStateFull(full.get(), full_size, &pending_full_actual),
            "capture whole state while breakpoint result remains pending\n");
  ASSERT_EQ(full_size, pending_full_actual, "pending whole-state size\n");
  zx_vcpu_hardware_breakpoint_control_t pending_after_capture = {};
  ASSERT_EQ(ZX_OK, vcpu->ReadState(pending_after_capture),
            "read pending breakpoint after whole-state capture\n");
  EXPECT_EQ(execute_pending.pending_sequence,
            pending_after_capture.pending_sequence,
            "whole-state capture leaves pending breakpoint immutable\n");
  EXPECT_EQ(ZX_ERR_BAD_STATE,
            vcpu->WriteState(MakeHardwareBreakpointControl(
                0, 0, 0, 0, 0, execute_pending.pending_sequence + 1)),
            "stale acknowledgement rejected\n");
  zx_vcpu_hardware_breakpoint_control_t after_stale = {};
  ASSERT_EQ(ZX_OK, vcpu->ReadState(after_stale), "read after stale acknowledgement\n");
  EXPECT_EQ(execute_pending.pending_sequence, after_stale.pending_sequence,
            "stale acknowledgement leaves stop immutable\n");
  ASSERT_EQ(ZX_OK,
            vcpu->WriteState(MakeHardwareBreakpointControl(
                0, 0, 0, 0, 0, execute_pending.pending_sequence)),
            "acknowledge execute stop\n");

  packet = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(packet), "resume execute phase\n");
  ASSERT_EQ(static_cast<uint8_t>(ZX_PKT_TYPE_GUEST_IO), static_cast<uint8_t>(packet.type),
            "ack resumes the stopped instruction\n");
  EXPECT_EQ(0x32u, static_cast<uint32_t>(packet.guest_io.data[0]), "second report\n");

  // The guest claims DR0 before touching data. A transparent host control must
  // move to DR1 and report that physical slot, while preserving the guest file.
  constexpr uint32_t kDataCondition = 11;
  auto data = MakeHardwareBreakpointControl(
      ZX_VCPU_HARDWARE_BREAKPOINT_ARM, kDataGpa,
      ZX_VCPU_HARDWARE_BREAKPOINT_WRITE,
      ZX_VCPU_HARDWARE_BREAKPOINT_LENGTH_4, kDataCondition);
  ASSERT_EQ(ZX_OK, vcpu->WriteState(data), "arm data request\n");
  packet = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(packet), "run to data stop\n");
  ASSERT_EQ(static_cast<uint8_t>(ZX_PKT_TYPE_GUEST_HARDWARE_BREAKPOINT),
            static_cast<uint8_t>(packet.type), "typed data packet\n");
  EXPECT_EQ(kCodeGpa + 41, packet.guest_hardware_breakpoint.rip,
            "data stop is after the six-byte store\n");
  EXPECT_EQ(uint64_t{1} << kDataCondition,
            packet.guest_hardware_breakpoint.condition_mask, "data condition\n");
  EXPECT_EQ(0x2u, static_cast<uint32_t>(packet.guest_hardware_breakpoint.slot_mask),
            "host request remapped to DR1 around guest DR0\n");
  EXPECT_EQ(ZX_VCPU_HARDWARE_BREAKPOINT_POST_ACCESS,
            static_cast<uint32_t>(packet.guest_hardware_breakpoint.boundary),
            "data boundary\n");
  uint32_t stored = 0;
  ASSERT_EQ(ZX_OK, ram->Read(&stored, kDataGpa, sizeof(stored)), "read watched data\n");
  EXPECT_EQ(0x78563412u, stored, "data access completed before its stop\n");

  zx_vcpu_hardware_breakpoint_control_t data_pending = {};
  ASSERT_EQ(ZX_OK, vcpu->ReadState(data_pending), "read data result\n");
  ASSERT_EQ(ZX_OK,
            vcpu->WriteState(MakeHardwareBreakpointControl(
                0, 0, 0, 0, 0, data_pending.pending_sequence)),
            "acknowledge data stop\n");

  packet = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(packet), "read guest DR0\n");
  ASSERT_EQ(static_cast<uint8_t>(ZX_PKT_TYPE_GUEST_IO), static_cast<uint8_t>(packet.type),
            "DR0 report\n");
  EXPECT_EQ(0x55u, static_cast<uint32_t>(packet.guest_io.data[0]),
            "guest DR0 survives host remap and stop\n");
  packet = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(packet), "read guest DR7\n");
  ASSERT_EQ(static_cast<uint8_t>(ZX_PKT_TYPE_GUEST_IO), static_cast<uint8_t>(packet.type),
            "DR7 report\n");
  EXPECT_EQ(0x01u, static_cast<uint32_t>(packet.guest_io.data[0]),
            "guest DR7 enable survives host remap and stop\n");

  printf("hardware-breakpoint entry OK: negative run, execute/pre stop, exact ack, "
         "guest-owned DR0 remap, and write/post stop all completed.\n");
#else
  printf("Not x86_64; skipping hardware-breakpoint entry test.\n");
#endif

  END_TEST;
}

// The debug topic is both the capability query and the atomic control point.
// This test drives it through VcpuDispatcher, then makes the stepped instruction
// take an I/O exit. The exit handler's completion must preserve the pending
// debugger boundary across that userspace round trip; the following entry must
// return the typed debug exit before another instruction executes, consuming
// only the one-shot flag while persistent #BP interception remains armed. The
// hardware-completed sibling of this case is VM-exit reason bit 28 and feeds
// the same pending latch in Vcpu::Enter.
bool vcpu_debug_state_topic_single_step_is_one_shot() {
  BEGIN_TEST;

#ifdef __x86_64__
  fbl::RefPtr<VmObjectPaged> ram;
  ASSERT_EQ(ZX_OK, VmObjectPaged::Create(PMM_ALLOC_FLAG_ANY, 0u, kGuestRamSize, &ram), "ram\n");
  ASSERT_EQ(ZX_OK, WriteIdentityTables(ram), "tables\n");
  // out 0x10,al; mov al,0x43; out 0x10,al; hlt
  const uint8_t code[] = {0xE6, 0x10, 0xB0, 0x43, 0xE6, 0x10, 0xF4};
  ASSERT_EQ(ZX_OK, ram->Write(code, kCodeGpa, sizeof(code)), "code\n");
  ASSERT_EQ(ZX_OK, ram->CommitRange(0, kGuestRamSize), "commit\n");

  auto lg = CreateLiveGuestDispatcher(ram, kCodeGpa);
  if (lg.is_error() && lg.status_value() == ZX_ERR_NOT_SUPPORTED) {
    printf("VMX not supported here; skipping debug-state topic test.\n");
    return true;
  }
  ASSERT_EQ(ZX_OK, lg.status_value(), "create live guest (dispatchers)\n");
  VcpuDispatcher* vcpu = lg->vcpu.get();
  zx_vcpu_state_t regs = {};
  ASSERT_EQ(ZX_OK, vcpu->ReadState(regs), "read initial registers\n");
  regs.rax = 0x42;
  ASSERT_EQ(ZX_OK, vcpu->WriteState(regs), "seed stepped I/O value\n");

  zx_vcpu_debug_state_t initial = {};
  ASSERT_EQ(ZX_OK, vcpu->ReadState(initial), "read initial debug state\n");
  EXPECT_EQ(ZX_VCPU_DEBUG_STATE_MAGIC, initial.magic, "magic\n");
  EXPECT_EQ(ZX_VCPU_DEBUG_STATE_VERSION, initial.version, "version\n");
  EXPECT_EQ(sizeof(initial), initial.size, "size\n");
  EXPECT_TRUE((initial.supported_flags & ZX_VCPU_DEBUG_TRAP_SOFTWARE_BREAKPOINT) != 0,
              "#BP interception is part of every x86 VMX VCPU\n");
  EXPECT_EQ(0u, initial.active_flags, "fresh VCPU has no debug controls armed\n");

  const uint64_t requested =
      ZX_VCPU_DEBUG_TRAP_SOFTWARE_BREAKPOINT | ZX_VCPU_DEBUG_SINGLE_STEP;
  zx_vcpu_debug_state_t arm = MakeDebugState(requested);
  const bool can_single_step = (initial.supported_flags & ZX_VCPU_DEBUG_SINGLE_STEP) != 0;
  const zx_status_t arm_status = vcpu->WriteState(arm);
  if (!can_single_step) {
    EXPECT_EQ(ZX_ERR_NOT_SUPPORTED, arm_status, "unsupported MTF request must fail plainly\n");
    zx_vcpu_debug_state_t after = {};
    ASSERT_EQ(ZX_OK, vcpu->ReadState(after), "read after refused request\n");
    EXPECT_EQ(initial.active_flags, after.active_flags,
              "refused combined request must not partially arm #BP\n");
    printf("debug-state topic OK: host reports no toggleable MTF; combined request was refused "
           "atomically\n");
    return true;
  }
  ASSERT_EQ(ZX_OK, arm_status, "arm #BP + one-shot MTF\n");

  zx_vcpu_debug_state_t armed = {};
  ASSERT_EQ(ZX_OK, vcpu->ReadState(armed), "read armed debug state\n");
  EXPECT_EQ(requested, armed.active_flags, "both requested controls must be active\n");

  // The stepped instruction itself exits for I/O before hardware executes it;
  // the kernel completes it by advancing RIP and must account for the debugger
  // boundary MTF cannot observe directly.
  zx_port_packet_t io = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(io), "enter to stepped I/O instruction\n");
  ASSERT_EQ(static_cast<uint8_t>(ZX_PKT_TYPE_GUEST_IO), static_cast<uint8_t>(io.type),
            "the instruction's own exit takes priority\n");
  EXPECT_EQ(0x42u, static_cast<uint32_t>(io.guest_io.data[0]), "stepped I/O value\n");

  zx_vcpu_debug_state_t pending = {};
  ASSERT_EQ(ZX_OK, vcpu->ReadState(pending), "read while MTF exit is pending\n");
  EXPECT_EQ(requested, pending.active_flags,
            "an unrelated exit must not consume the one-shot control\n");

  zx_port_packet_t step = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(step), "re-enter for pending MTF exit\n");
  ASSERT_EQ(static_cast<uint8_t>(ZX_PKT_TYPE_GUEST_EXCEPTION), static_cast<uint8_t>(step.type),
            "MTF must surface as the typed guest debug/exception exit\n");
  EXPECT_EQ(X86_INT_DEBUG, step.guest_exception.vector, "single step is a #DB-shaped exit\n");
  EXPECT_EQ(kCodeGpa + 2, step.guest_exception.rip,
            "pending MTF must surface before the instruction after the I/O exit\n");

  zx_vcpu_debug_state_t consumed = {};
  ASSERT_EQ(ZX_OK, vcpu->ReadState(consumed), "read after single-step exit\n");
  EXPECT_EQ(ZX_VCPU_DEBUG_TRAP_SOFTWARE_BREAKPOINT, consumed.active_flags,
            "MTF must disarm itself while persistent #BP interception remains\n");

  zx_port_packet_t resumed = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(resumed), "resume after one-shot\n");
  ASSERT_EQ(static_cast<uint8_t>(ZX_PKT_TYPE_GUEST_IO), static_cast<uint8_t>(resumed.type),
            "resume must run freely to the I/O exit\n");
  EXPECT_EQ(0x43u, static_cast<uint32_t>(resumed.guest_io.data[0]),
            "the instruction after the step must execute only after the debug exit\n");

  zx_vcpu_debug_state_t malformed = MakeDebugState(0);
  malformed.supported_flags = initial.supported_flags;
  EXPECT_EQ(ZX_ERR_INVALID_ARGS, vcpu->WriteState(malformed),
            "output-only support bits must be rejected on write\n");
  ASSERT_EQ(ZX_OK, vcpu->ReadState(consumed), "read after malformed request\n");
  EXPECT_EQ(ZX_VCPU_DEBUG_TRAP_SOFTWARE_BREAKPOINT, consumed.active_flags,
            "malformed request must leave active controls unchanged\n");

  ASSERT_EQ(ZX_OK, vcpu->WriteState(MakeDebugState(0)), "clear debug controls\n");
  ASSERT_EQ(ZX_OK, vcpu->ReadState(consumed), "read cleared debug state\n");
  EXPECT_EQ(0u, consumed.active_flags, "all controls cleared\n");
  printf("debug-state topic OK: a pending step survived an I/O exit, surfaced at RIP %#lx, "
         "self-cleared, and preserved persistent #BP interception\n",
         step.guest_exception.rip);
#else
  printf("Not x86_64; skipping.\n");
#endif  // __x86_64__

  END_TEST;
}

bool vcpu_run_control_preemption_timer_is_one_shot() {
  BEGIN_TEST;

#ifdef __x86_64__
  fbl::RefPtr<VmObjectPaged> ram;
  ASSERT_EQ(ZX_OK, VmObjectPaged::Create(PMM_ALLOC_FLAG_ANY, 0u, kGuestRamSize, &ram), "ram\n");
  ASSERT_EQ(ZX_OK, WriteIdentityTables(ram), "tables\n");
  // A self-loop cannot complete before even the smallest usable VMX
  // preemption timer, so the expected exit is unambiguous.
  const uint8_t code[] = {0xEB, 0xFE};
  ASSERT_EQ(ZX_OK, ram->Write(code, kCodeGpa, sizeof(code)), "code\n");
  ASSERT_EQ(ZX_OK, ram->CommitRange(0, kGuestRamSize), "commit\n");

  auto lg = CreateLiveGuestDispatcher(ram, kCodeGpa);
  if (lg.is_error() && lg.status_value() == ZX_ERR_NOT_SUPPORTED) {
    printf("VMX not supported here; skipping run-control topic test.\n");
    return true;
  }
  ASSERT_EQ(ZX_OK, lg.status_value(), "create live guest (dispatchers)\n");
  VcpuDispatcher* vcpu = lg->vcpu.get();

  zx_vcpu_run_control_t initial = {};
  ASSERT_EQ(ZX_OK, vcpu->ReadState(initial), "read initial run control\n");
  EXPECT_EQ(ZX_VCPU_RUN_CONTROL_MAGIC, initial.magic, "magic\n");
  EXPECT_EQ(ZX_VCPU_RUN_CONTROL_VERSION, initial.version, "version\n");
  EXPECT_EQ(sizeof(initial), initial.size, "size\n");
  EXPECT_EQ(0u, initial.active_flags, "fresh VCPU has no run control armed\n");
  EXPECT_LE(initial.preemption_timer_rate_shift, 31u, "architectural timer shift\n");

  auto arm = MakeRunControl(ZX_VCPU_RUN_PREEMPTION_TIMER, 1000);
  const bool supported =
      (initial.supported_flags & ZX_VCPU_RUN_PREEMPTION_TIMER) != 0;
  const zx_status_t arm_status = vcpu->WriteState(arm);
  if (!supported) {
    EXPECT_EQ(ZX_ERR_NOT_SUPPORTED, arm_status, "unsupported timer must fail plainly\n");
    zx_vcpu_run_control_t after = {};
    ASSERT_EQ(ZX_OK, vcpu->ReadState(after), "read after refused timer\n");
    EXPECT_EQ(0u, after.active_flags, "refused timer must not arm anything\n");
    return true;
  }
  ASSERT_EQ(ZX_OK, arm_status, "arm VMX preemption timer\n");

  zx_vcpu_run_control_t armed = {};
  ASSERT_EQ(ZX_OK, vcpu->ReadState(armed), "read armed run control\n");
  EXPECT_EQ(ZX_VCPU_RUN_PREEMPTION_TIMER, armed.active_flags, "timer active\n");
  EXPECT_EQ(1000u, armed.preemption_timer_ticks, "timer count round-trips\n");

  auto malformed = MakeRunControl(0, 1);
  EXPECT_EQ(ZX_ERR_INVALID_ARGS, vcpu->WriteState(malformed),
            "inactive timer cannot carry a count\n");
  zx_vcpu_run_control_t after_malformed = {};
  ASSERT_EQ(ZX_OK, vcpu->ReadState(after_malformed), "read after malformed request\n");
  EXPECT_EQ(ZX_VCPU_RUN_PREEMPTION_TIMER, after_malformed.active_flags,
            "malformed request leaves the armed control unchanged\n");
  EXPECT_EQ(1000u, after_malformed.preemption_timer_ticks,
            "malformed request leaves the timer count unchanged\n");

  zx_port_packet_t packet = {};
  EXPECT_EQ(ZX_ERR_TIMED_OUT, vcpu->Enter(packet), "timer expiry is a bounded-run result\n");

  zx_vcpu_run_control_t expired = {};
  ASSERT_EQ(ZX_OK, vcpu->ReadState(expired), "read after timer expiry\n");
  EXPECT_EQ(0u, expired.active_flags, "timer expiry disarms the one-shot control\n");
  EXPECT_EQ(0u, expired.preemption_timer_ticks, "expired count is cleared\n");

  printf("run-control topic OK: VMX preemption timer expired and self-cleared (rate shift %u)\n",
         initial.preemption_timer_rate_shift);
#else
  printf("Not x86_64; skipping.\n");
#endif

  END_TEST;
}

bool vcpu_run_control_preemption_timer_survives_unrelated_exit() {
  BEGIN_TEST;

#ifdef __x86_64__
  fbl::RefPtr<VmObjectPaged> ram;
  ASSERT_EQ(ZX_OK, VmObjectPaged::Create(PMM_ALLOC_FLAG_ANY, 0u, kGuestRamSize, &ram), "ram\n");
  ASSERT_EQ(ZX_OK, WriteIdentityTables(ram), "tables\n");
  // Spend enough time in non-root mode for the timer to advance, then cause a
  // userspace-visible I/O exit before entering a terminal self-loop.
  const uint8_t code[] = {
      0xB9, 0x00, 0x00, 0x01, 0x00,  // mov ecx, 65536
      0xF3, 0x90,                    // pause
      0xE2, 0xFC,                    // loop -4
      0xE6, 0x10,                    // out 0x10, al
      0xEB, 0xFE,                    // jmp .
  };
  ASSERT_EQ(ZX_OK, ram->Write(code, kCodeGpa, sizeof(code)), "code\n");
  ASSERT_EQ(ZX_OK, ram->CommitRange(0, kGuestRamSize), "commit\n");

  auto lg = CreateLiveGuestDispatcher(ram, kCodeGpa);
  if (lg.is_error() && lg.status_value() == ZX_ERR_NOT_SUPPORTED) {
    printf("VMX not supported here; skipping run-control persistence test.\n");
    return true;
  }
  ASSERT_EQ(ZX_OK, lg.status_value(), "create live guest (dispatchers)\n");
  VcpuDispatcher* vcpu = lg->vcpu.get();

  zx_vcpu_run_control_t initial = {};
  ASSERT_EQ(ZX_OK, vcpu->ReadState(initial), "read initial run control\n");
  if ((initial.supported_flags & ZX_VCPU_RUN_PREEMPTION_TIMER) == 0) {
    printf("VMX preemption timer persistence is unavailable here; skipping.\n");
    return true;
  }

  constexpr uint32_t kInitialTicks = 0xffffffffu;
  ASSERT_EQ(ZX_OK,
            vcpu->WriteState(MakeRunControl(ZX_VCPU_RUN_PREEMPTION_TIMER, kInitialTicks)),
            "arm long VMX preemption timer\n");
  zx_port_packet_t packet = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(packet), "unrelated I/O exit\n");
  ASSERT_EQ(static_cast<uint8_t>(ZX_PKT_TYPE_GUEST_IO), static_cast<uint8_t>(packet.type),
            "expected I/O before timer expiration\n");

  zx_vcpu_run_control_t after_io = {};
  ASSERT_EQ(ZX_OK, vcpu->ReadState(after_io), "read timer after unrelated exit\n");
  EXPECT_EQ(ZX_VCPU_RUN_PREEMPTION_TIMER, after_io.active_flags, "timer remains armed\n");
  EXPECT_GT(after_io.preemption_timer_ticks, 0u, "timer did not expire\n");
  EXPECT_LT(after_io.preemption_timer_ticks, kInitialTicks,
            "unrelated exit saved the decremented timer count\n");

  ASSERT_EQ(ZX_OK, vcpu->WriteState(MakeRunControl(0, 0)), "disarm timer\n");
  zx_vcpu_run_control_t cleared = {};
  ASSERT_EQ(ZX_OK, vcpu->ReadState(cleared), "read cleared timer\n");
  EXPECT_EQ(0u, cleared.active_flags, "timer is inactive\n");
  EXPECT_EQ(0u, cleared.preemption_timer_ticks, "timer count is clear\n");
#else
  printf("Not x86_64; skipping.\n");
#endif

  END_TEST;
}

bool vcpu_exit_observation_is_post_handler_one_shot_and_acknowledged() {
  BEGIN_TEST;

#ifdef __x86_64__
  fbl::RefPtr<VmObjectPaged> ram;
  ASSERT_EQ(ZX_OK, VmObjectPaged::Create(PMM_ALLOC_FLAG_ANY, 0u, kGuestRamSize, &ram), "ram\n");
  ASSERT_EQ(ZX_OK, WriteIdentityTables(ram), "tables\n");
  // mov al,0x42; out 0x10,al; mov al,0x43; out 0x10,al; hlt
  const uint8_t code[] = {0xB0, 0x42, 0xE6, 0x10, 0xB0, 0x43, 0xE6, 0x10, 0xF4};
  ASSERT_EQ(ZX_OK, ram->Write(code, kCodeGpa, sizeof(code)), "code\n");
  ASSERT_EQ(ZX_OK, ram->CommitRange(0, kGuestRamSize), "commit\n");

  auto lg = CreateLiveGuestDispatcher(ram, kCodeGpa);
  if (lg.is_error() && lg.status_value() == ZX_ERR_NOT_SUPPORTED) {
    printf("VMX not supported here; skipping exit-observation test.\n");
    return true;
  }
  ASSERT_EQ(ZX_OK, lg.status_value(), "create nested live guest\n");
  VcpuDispatcher* vcpu = lg->vcpu.get();

  zx_vcpu_exit_control_t initial = {};
  ASSERT_EQ(ZX_OK, vcpu->ReadState(initial), "read exit-control capabilities\n");
  EXPECT_EQ(ZX_VCPU_EXIT_CONTROL_MAGIC, initial.magic, "magic\n");
  EXPECT_EQ(ZX_VCPU_EXIT_CONTROL_VERSION, initial.version, "version\n");
  EXPECT_EQ(sizeof(initial), initial.size, "size\n");
  EXPECT_EQ(ZX_VCPU_EXIT_CONTROL_ALL_FLAGS, initial.supported_flags, "software controls\n");
  constexpr uint32_t kIoExitReason = 30;
  const uint64_t io_reason = uint64_t{1} << kIoExitReason;
  ASSERT_TRUE((initial.supported_reasons[0] & io_reason) != 0,
              "I/O must be in the runtime observation set\n");
  EXPECT_EQ(0u, initial.active_flags, "unarmed initially\n");
  EXPECT_EQ(0u, initial.pending_sequence, "no pending result initially\n");

  // Runtime discovery is authoritative. A reason outside the exact supported
  // set fails atomically and does not create an active session.
  auto unsupported =
      MakeExitControl(ZX_VCPU_EXIT_CONTROL_OBSERVE, 0, uint64_t{1} << 5, 0);
  EXPECT_EQ(ZX_ERR_NOT_SUPPORTED, vcpu->WriteState(unsupported),
            "an unreported reason must fail closed\n");
  zx_vcpu_exit_control_t after_refusal = {};
  ASSERT_EQ(ZX_OK, vcpu->ReadState(after_refusal), "read after refused arm\n");
  EXPECT_EQ(0u, after_refusal.active_flags, "refused arm changes nothing\n");

  ASSERT_EQ(ZX_OK,
            vcpu->WriteState(
                MakeExitControl(ZX_VCPU_EXIT_CONTROL_OBSERVE, io_reason, 0, 0)),
            "arm one-shot I/O observation\n");

  // The original packet wins. Its output side effect is handled by userspace;
  // the observation is held until the next Enter, before another VM entry.
  zx_port_packet_t first_io = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(first_io), "enter to first I/O\n");
  ASSERT_EQ(static_cast<uint8_t>(ZX_PKT_TYPE_GUEST_IO), static_cast<uint8_t>(first_io.type),
            "the normal I/O packet is delivered first\n");
  EXPECT_EQ(0x42u, static_cast<uint32_t>(first_io.guest_io.data[0]), "first output value\n");

  zx_vcpu_exit_control_t pending = {};
  ASSERT_EQ(ZX_OK, vcpu->ReadState(pending), "read pending observation\n");
  EXPECT_EQ(0u, pending.active_flags, "trigger disarms the one-shot\n");
  // Nested KVM can interpose an external-interrupt exit before the selected
  // I/O exit. The selected reason still defines the boundary; exits_seen is
  // deliberately the exact count of every completed exit since arming.
  EXPECT_GE(pending.exits_seen, 1u, "the selected exit was counted\n");
  ASSERT_NE(0u, pending.pending_sequence, "result needs acknowledgement\n");
  EXPECT_EQ(kIoExitReason, pending.pending_exit_reason, "I/O reason\n");
  EXPECT_EQ(ZX_PKT_GUEST_EXIT_OBSERVATION_REASON, pending.pending_flags, "reason trigger\n");
  EXPECT_EQ(kCodeGpa + 2, pending.pending_exit_rip, "faulting OUT RIP\n");
  EXPECT_EQ(kCodeGpa + 4, pending.pending_resume_rip,
            "normal I/O handling advanced RIP before the stop\n");

  zx_port_packet_t observation = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(observation), "deliver deferred observation before VM entry\n");
  ASSERT_EQ(static_cast<uint8_t>(ZX_PKT_TYPE_GUEST_EXIT_OBSERVATION),
            static_cast<uint8_t>(observation.type), "typed observation packet\n");
  EXPECT_EQ(pending.pending_sequence, observation.guest_exit_observation.sequence, "sequence\n");
  EXPECT_EQ(kIoExitReason, observation.guest_exit_observation.exit_reason, "exit reason\n");
  EXPECT_EQ(kCodeGpa + 2, observation.guest_exit_observation.exit_rip, "exit RIP\n");
  EXPECT_EQ(kCodeGpa + 4, observation.guest_exit_observation.resume_rip, "handled RIP\n");

  zx_port_packet_t blocked = {};
  EXPECT_EQ(ZX_ERR_BAD_STATE, vcpu->Enter(blocked),
            "delivered observation must be acknowledged before resume\n");
  auto stale_ack = MakeExitControl(0, 0, 0, 0, pending.pending_sequence + 1);
  EXPECT_EQ(ZX_ERR_BAD_STATE, vcpu->WriteState(stale_ack),
            "a stale acknowledgement cannot release the VCPU\n");

  ASSERT_EQ(ZX_OK, vcpu->WriteState(MakeExitControl(0, 0, 0, 0, pending.pending_sequence)),
            "acknowledge the exact one-shot\n");
  zx_vcpu_exit_control_t acknowledged = {};
  ASSERT_EQ(ZX_OK, vcpu->ReadState(acknowledged), "read acknowledged state\n");
  EXPECT_EQ(0u, acknowledged.pending_sequence, "ack releases pending result\n");
  EXPECT_EQ(0u, acknowledged.exits_seen, "inactive control does not retain a live counter\n");

  zx_port_packet_t second_io = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(second_io), "resume after acknowledgement\n");
  ASSERT_EQ(static_cast<uint8_t>(ZX_PKT_TYPE_GUEST_IO), static_cast<uint8_t>(second_io.type),
            "guest reaches the second output\n");
  EXPECT_EQ(0x43u, static_cast<uint32_t>(second_io.guest_io.data[0]),
            "resume did not replay the first output\n");
#else
  printf("Not x86_64; skipping.\n");
#endif

  END_TEST;
}

bool vcpu_exit_budget_stops_after_exact_completed_exit() {
  BEGIN_TEST;

#ifdef __x86_64__
  fbl::RefPtr<VmObjectPaged> ram;
  ASSERT_EQ(ZX_OK, VmObjectPaged::Create(PMM_ALLOC_FLAG_ANY, 0u, kGuestRamSize, &ram), "ram\n");
  ASSERT_EQ(ZX_OK, WriteIdentityTables(ram), "tables\n");
  // mov eax,0; cpuid; cpuid; mov al,0x55; out 0x10,al; hlt
  const uint8_t code[] = {
      0xB8, 0x00, 0x00, 0x00, 0x00, 0x0F, 0xA2, 0x0F,
      0xA2, 0xB0, 0x55, 0xE6, 0x10, 0xF4,
  };
  ASSERT_EQ(ZX_OK, ram->Write(code, kCodeGpa, sizeof(code)), "code\n");
  ASSERT_EQ(ZX_OK, ram->CommitRange(0, kGuestRamSize), "commit\n");

  auto lg = CreateLiveGuestDispatcher(ram, kCodeGpa);
  if (lg.is_error() && lg.status_value() == ZX_ERR_NOT_SUPPORTED) {
    printf("VMX not supported here; skipping exit-budget test.\n");
    return true;
  }
  ASSERT_EQ(ZX_OK, lg.status_value(), "create nested live guest\n");
  VcpuDispatcher* vcpu = lg->vcpu.get();

  ASSERT_EQ(ZX_OK,
            vcpu->WriteState(MakeExitControl(ZX_VCPU_EXIT_CONTROL_BUDGET, 0, 0, 2)),
            "arm an exact two-exit budget\n");
  zx_port_packet_t observation = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(observation), "run until the second completed exit\n");
  ASSERT_EQ(static_cast<uint8_t>(ZX_PKT_TYPE_GUEST_EXIT_OBSERVATION),
            static_cast<uint8_t>(observation.type), "budget observation\n");
  EXPECT_EQ(ZX_PKT_GUEST_EXIT_OBSERVATION_BUDGET,
            observation.guest_exit_observation.flags, "budget trigger\n");
  // Host interrupts are valid completed VM exits too, and are intentionally
  // part of the budget. If a CPUID is the second exit, its handler must have
  // advanced RIP before the stop; an asynchronous exit keeps the same RIP.
  if (observation.guest_exit_observation.exit_reason == 10u) {
    EXPECT_EQ(observation.guest_exit_observation.exit_rip + 2,
              observation.guest_exit_observation.resume_rip,
              "CPUID was handled before the budget stop\n");
  } else {
    EXPECT_EQ(observation.guest_exit_observation.exit_rip,
              observation.guest_exit_observation.resume_rip,
              "asynchronous exit leaves the instruction pointer unchanged\n");
  }

  zx_vcpu_exit_control_t pending = {};
  ASSERT_EQ(ZX_OK, vcpu->ReadState(pending), "read completed budget\n");
  EXPECT_EQ(2u, pending.exits_seen, "exact completed-exit count\n");
  EXPECT_EQ(observation.guest_exit_observation.sequence, pending.pending_sequence, "sequence\n");
  ASSERT_EQ(ZX_OK, vcpu->WriteState(MakeExitControl(0, 0, 0, 0, pending.pending_sequence)),
            "acknowledge budget boundary\n");

  zx_port_packet_t io = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(io), "resume after exact budget\n");
  ASSERT_EQ(static_cast<uint8_t>(ZX_PKT_TYPE_GUEST_IO), static_cast<uint8_t>(io.type), "I/O\n");
  EXPECT_EQ(0x55u, static_cast<uint32_t>(io.guest_io.data[0]),
            "resume reaches the output without replaying the budget boundary\n");
#else
  printf("Not x86_64; skipping.\n");
#endif

  END_TEST;
}

bool vcpu_unarmed_exit_control_adds_no_return_or_counter() {
  BEGIN_TEST;

#ifdef __x86_64__
  fbl::RefPtr<VmObjectPaged> ram;
  ASSERT_EQ(ZX_OK, VmObjectPaged::Create(PMM_ALLOC_FLAG_ANY, 0u, kGuestRamSize, &ram), "ram\n");
  ASSERT_EQ(ZX_OK, WriteIdentityTables(ram), "tables\n");
  // Two kernel-handled CPUID exits followed by the one ordinary userspace exit.
  const uint8_t code[] = {
      0xB8, 0x00, 0x00, 0x00, 0x00, 0x0F, 0xA2, 0x0F,
      0xA2, 0xB0, 0x66, 0xE6, 0x10, 0xF4,
  };
  ASSERT_EQ(ZX_OK, ram->Write(code, kCodeGpa, sizeof(code)), "code\n");
  ASSERT_EQ(ZX_OK, ram->CommitRange(0, kGuestRamSize), "commit\n");

  auto lg = CreateLiveGuestDispatcher(ram, kCodeGpa);
  if (lg.is_error() && lg.status_value() == ZX_ERR_NOT_SUPPORTED) {
    printf("VMX not supported here; skipping unarmed exit-control test.\n");
    return true;
  }
  ASSERT_EQ(ZX_OK, lg.status_value(), "create nested live guest\n");
  VcpuDispatcher* vcpu = lg->vcpu.get();

  zx_port_packet_t io = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(io), "unarmed entry reaches ordinary I/O directly\n");
  ASSERT_EQ(static_cast<uint8_t>(ZX_PKT_TYPE_GUEST_IO), static_cast<uint8_t>(io.type),
            "no additional observation return\n");
  EXPECT_EQ(0x66u, static_cast<uint32_t>(io.guest_io.data[0]), "guest completed both CPUIDs\n");

  zx_vcpu_exit_control_t state = {};
  ASSERT_EQ(ZX_OK, vcpu->ReadState(state), "read unarmed control\n");
  EXPECT_EQ(0u, state.active_flags, "still unarmed\n");
  EXPECT_EQ(0u, state.exits_seen, "unarmed path did not touch the session counter\n");
  EXPECT_EQ(0u, state.pending_sequence, "unarmed path created no pending return\n");
#else
  printf("Not x86_64; skipping.\n");
#endif

  END_TEST;
}

// Topic 12 discovery is deliberately weaker than Configure: it snapshots only
// the architectural PT/CPUID.14 and ToPA prerequisites. In particular, reading
// it must not touch an RTIT MSR, scan or reserve the PMI resource, or create a
// trace generation. This contract is identical on supported and unsupported
// CPUs; the latter must still return a typed fail-closed capability record.
bool vcpu_intel_pt_capability_read_is_cpuid_only_and_unreserved() {
  BEGIN_TEST;

#ifdef __x86_64__
  fbl::RefPtr<VmObjectPaged> ram;
  ASSERT_EQ(ZX_OK, VmObjectPaged::Create(PMM_ALLOC_FLAG_ANY, 0u, kGuestRamSize, &ram), "ram\n");
  ASSERT_EQ(ZX_OK, WriteIdentityTables(ram), "tables\n");
  ASSERT_EQ(ZX_OK, ram->CommitRange(0, kGuestRamSize), "commit\n");

  auto lg = CreateLiveGuestDispatcher(ram, kCodeGpa);
  if (lg.is_error() && lg.status_value() == ZX_ERR_NOT_SUPPORTED) {
    printf("VMX not supported here; skipping Intel PT capability-read test.\n");
    return true;
  }
  ASSERT_EQ(ZX_OK, lg.status_value(), "create nested live guest\n");
  VcpuDispatcher* vcpu = lg->vcpu.get();

  const uint64_t accesses_before = x86_perfmon_vcpu_pt_msr_accesses();
  zx_vcpu_intel_pt_control_t first = {};
  ASSERT_EQ(ZX_OK, vcpu->ReadState(first), "read Intel PT capabilities\n");
  EXPECT_EQ(ZX_VCPU_INTEL_PT_CONTROL_MAGIC, first.magic, "magic\n");
  EXPECT_EQ(ZX_VCPU_INTEL_PT_CONTROL_VERSION, first.version, "version\n");
  EXPECT_EQ(sizeof(first), first.size, "size\n");
  EXPECT_TRUE(first.availability == ZX_VCPU_INTEL_PT_UNSUPPORTED ||
                  first.availability == ZX_VCPU_INTEL_PT_AVAILABLE,
              "CPUID discovery reports only supported or unsupported, never resource busy\n");
  EXPECT_EQ(0u, first.trace_generation, "capability read creates no trace generation\n");
  EXPECT_EQ(ZX_VCPU_INTEL_PT_TERMINAL_INACTIVE, first.terminal,
            "capability read creates no active session\n");
  EXPECT_EQ(0u, first.buffer_bytes, "capability read allocates no trace buffer\n");
  EXPECT_EQ(0u, first.producer_cursor, "capability read produces no trace bytes\n");
  EXPECT_EQ(accesses_before, x86_perfmon_vcpu_pt_msr_accesses(),
            "capability read touches no RTIT MSR\n");

  zx_vcpu_intel_pt_control_t second = {};
  ASSERT_EQ(ZX_OK, vcpu->ReadState(second), "repeat Intel PT capability read\n");
  EXPECT_EQ(first.availability, second.availability, "capability result is stable\n");
  EXPECT_EQ(first.unavailable_reason, second.unavailable_reason, "failure reason is stable\n");
  EXPECT_EQ(0u, second.trace_generation, "repeat read still owns no session\n");
  EXPECT_EQ(ZX_VCPU_INTEL_PT_TERMINAL_INACTIVE, second.terminal,
            "repeat read remains inactive\n");
  EXPECT_EQ(accesses_before, x86_perfmon_vcpu_pt_msr_accesses(),
            "repeated capability reads touch no RTIT MSR\n");

  if (first.availability == ZX_VCPU_INTEL_PT_AVAILABLE) {
    EXPECT_EQ(ZX_VCPU_INTEL_PT_REASON_NONE, first.unavailable_reason,
              "supported CPUID has no unavailable reason\n");
    EXPECT_GE(first.cpuid_14[0].eax, 1u, "leaf 14 exposes subleaf one\n");
    EXPECT_EQ(0x3u, first.cpuid_14[0].ecx & 0x3u,
              "leaf 14 exposes ToPA and multiple entries\n");
  } else {
    EXPECT_TRUE(first.unavailable_reason == ZX_VCPU_INTEL_PT_REASON_ABSENT ||
                    first.unavailable_reason == ZX_VCPU_INTEL_PT_REASON_CPUID_MALFORMED ||
                    first.unavailable_reason == ZX_VCPU_INTEL_PT_REASON_TOPA_UNAVAILABLE ||
                    first.unavailable_reason ==
                        ZX_VCPU_INTEL_PT_REASON_MULTI_ENTRY_TOPA_UNAVAILABLE,
                "unsupported discovery is explained only by CPUID/ToPA prerequisites\n");
  }

  printf("Intel PT capability read OK: CPUID-only availability %u, zero trace generation, "
         "zero RTIT MSR accesses\n",
         first.availability);
#else
  printf("Not x86_64; skipping.\n");
#endif

  END_TEST;
}

// Configure is the explicit qualification boundary for the prerequisites that
// a capability read intentionally does not probe. A static failure becomes a
// typed, stable capability result; a transient resource conflict does not
// poison later discovery. A supported host releases the unused session without
// entering the guest, so this test never needs to decode trace data.
bool vcpu_intel_pt_configure_qualifies_static_host_prerequisites() {
  BEGIN_TEST;

#ifdef __x86_64__
  fbl::RefPtr<VmObjectPaged> ram;
  ASSERT_EQ(ZX_OK, VmObjectPaged::Create(PMM_ALLOC_FLAG_ANY, 0u, kGuestRamSize, &ram), "ram\n");
  ASSERT_EQ(ZX_OK, WriteIdentityTables(ram), "tables\n");
  ASSERT_EQ(ZX_OK, ram->CommitRange(0, kGuestRamSize), "commit\n");

  auto lg = CreateLiveGuestDispatcher(ram, kCodeGpa);
  if (lg.is_error() && lg.status_value() == ZX_ERR_NOT_SUPPORTED) {
    printf("VMX not supported here; skipping Intel PT qualification test.\n");
    return true;
  }
  ASSERT_EQ(ZX_OK, lg.status_value(), "create nested live guest\n");
  VcpuDispatcher* vcpu = lg->vcpu.get();

  // The public record includes a 4 KiB data window. One heap-backed scratch
  // record keeps every Configure branch well below the 16 KiB kernel stack.
  fbl::AllocChecker ac;
  ktl::unique_ptr<zx_vcpu_intel_pt_control_t> control_storage(
      new (&ac) zx_vcpu_intel_pt_control_t{});
  ASSERT_TRUE(ac.check(), "allocate Intel PT qualification record\n");
  auto& control = *control_storage;

  ASSERT_EQ(ZX_OK, vcpu->ReadState(control), "read initial Intel PT capability\n");
  if (control.availability == ZX_VCPU_INTEL_PT_UNSUPPORTED) {
    printf("Intel PT is absent architecturally; static qualification is unnecessary.\n");
    return true;
  }

  uint32_t psb_frequency = 0;
  while (psb_frequency < 32 &&
         (control.supported_psb_frequencies & (uint32_t{1} << psb_frequency)) == 0) {
    ++psb_frequency;
  }
  if (psb_frequency == 32) {
    printf("Intel PT exposes no supported PSB encoding; skipping Configure qualification.\n");
    return true;
  }

  memset(&control, 0, sizeof(control));
  control.magic = ZX_VCPU_INTEL_PT_CONTROL_MAGIC;
  control.version = ZX_VCPU_INTEL_PT_CONTROL_VERSION;
  control.size = sizeof(control);
  control.action = ZX_VCPU_INTEL_PT_ACTION_CONFIGURE;
  control.delivery = ZX_VCPU_INTEL_PT_DELIVERY_COMPLETE_OR_FAIL;
  control.config_flags = ZX_VCPU_INTEL_PT_TRACE_SUPERVISOR;
  control.buffer_bytes = 3 * kPageSize;
  control.psb_frequency = psb_frequency;
  const zx_status_t configure_status = vcpu->WriteState(control);

  if (configure_status == ZX_OK) {
    memset(&control, 0, sizeof(control));
    ASSERT_EQ(ZX_OK, vcpu->ReadState(control), "read active Intel PT session\n");
    const uint64_t generation = control.trace_generation;
    ASSERT_NE(0u, generation, "configured session has a generation\n");

    memset(&control, 0, sizeof(control));
    control.magic = ZX_VCPU_INTEL_PT_CONTROL_MAGIC;
    control.version = ZX_VCPU_INTEL_PT_CONTROL_VERSION;
    control.size = sizeof(control);
    control.action = ZX_VCPU_INTEL_PT_ACTION_RELEASE;
    control.trace_generation = generation;
    ASSERT_EQ(ZX_OK, vcpu->WriteState(control), "release unused Intel PT session\n");
  } else if (configure_status == ZX_ERR_NOT_SUPPORTED) {
    memset(&control, 0, sizeof(control));
    ASSERT_EQ(ZX_OK, vcpu->ReadState(control), "read qualified Intel PT capability\n");
    EXPECT_EQ(ZX_VCPU_INTEL_PT_UNSUPPORTED, control.availability,
              "static Configure failure changes the capability result\n");
    EXPECT_TRUE(
        control.unavailable_reason == ZX_VCPU_INTEL_PT_REASON_NESTED_HOST ||
            control.unavailable_reason == ZX_VCPU_INTEL_PT_REASON_RTIT_MSR_UNAVAILABLE ||
            control.unavailable_reason == ZX_VCPU_INTEL_PT_REASON_VMX_CONTROL_UNAVAILABLE,
        "static Configure failure has an exact host-prerequisite reason\n");
  } else {
    EXPECT_EQ(ZX_ERR_SHOULD_WAIT, configure_status,
              "Configure either succeeds, proves static unavailability, or reports contention\n");
    memset(&control, 0, sizeof(control));
    ASSERT_EQ(ZX_OK, vcpu->ReadState(control), "read capability after contention\n");
    EXPECT_EQ(ZX_VCPU_INTEL_PT_AVAILABLE, control.availability,
              "transient contention does not poison capability discovery\n");
  }
#else
  printf("Not x86_64; skipping.\n");
#endif

  END_TEST;
}

// A finite, branch-heavy guest proves the complete hardware data path without
// relying on trace decoding. Its safety I/O exit is far beyond one 4 KiB ToPA
// region: a supported bare-metal host must first return the typed watermark
// raised by the ToPA interrupt. Nested hosts that expose PT in CPUID but cannot
// give L1 the RTIT MSRs are expected to qualify as unsupported and skip.
//
// Beyond overflow delivery, this exercises the Cerise-facing contract:
// immutable bounded reads are retryable, ACK is an exact monotonic cursor,
// STOP leaves a complete terminal record, and RELEASE returns the resource.
bool vcpu_intel_pt_topa_watermark_is_complete_and_drainable() {
  BEGIN_TEST;

#ifdef __x86_64__
  fbl::RefPtr<VmObjectPaged> ram;
  ASSERT_EQ(ZX_OK, VmObjectPaged::Create(PMM_ALLOC_FLAG_ANY, 0u, kGuestRamSize, &ram), "ram\n");
  ASSERT_EQ(ZX_OK, WriteIdentityTables(ram), "tables\n");

  // mov ecx,10000000
  // loop: test cl,1; jz next; next: dec ecx; jnz loop
  // mov al,0x7a; out 0x10,al; hlt
  //
  // Both conditional branches contribute TNT outcomes. If the ToPA PMI path
  // is broken the bounded loop eventually reaches the I/O trap and the test
  // fails deterministically instead of leaving Enter() blocked forever.
  const uint8_t code[] = {
      0xB9, 0x80, 0x96, 0x98, 0x00, 0xF6, 0xC1, 0x01, 0x74, 0x00,
      0xFF, 0xC9, 0x75, 0xF7, 0xB0, 0x7A, 0xE6, 0x10, 0xF4,
  };
  ASSERT_EQ(ZX_OK, ram->Write(code, kCodeGpa, sizeof(code)), "code\n");
  ASSERT_EQ(ZX_OK, ram->CommitRange(0, kGuestRamSize), "commit\n");

  auto lg = CreateLiveGuestDispatcher(ram, kCodeGpa);
  if (lg.is_error() && lg.status_value() == ZX_ERR_NOT_SUPPORTED) {
    printf("VMX not supported here; skipping Intel PT watermark run.\n");
    return true;
  }
  ASSERT_EQ(ZX_OK, lg.status_value(), "create nested live guest\n");
  VcpuDispatcher* vcpu = lg->vcpu.get();

  // The public PT record carries a 4 KiB raw-data window. Keep it and the retry
  // copy off the 16 KiB kernel stack even on the early unsupported-host path.
  fbl::AllocChecker ac;
  ktl::unique_ptr<zx_vcpu_intel_pt_control_t> control_storage(
      new (&ac) zx_vcpu_intel_pt_control_t{});
  ASSERT_TRUE(ac.check(), "allocate Intel PT control record\n");
  auto& control = *control_storage;
  ASSERT_EQ(ZX_OK, vcpu->ReadState(control), "read Intel PT capability\n");
  if (control.availability == ZX_VCPU_INTEL_PT_UNSUPPORTED) {
    printf("Intel PT is absent here; skipping hardware watermark run.\n");
    return true;
  }

  uint32_t psb_frequency = 0;
  while (psb_frequency < 32 &&
         (control.supported_psb_frequencies & (uint32_t{1} << psb_frequency)) == 0) {
    ++psb_frequency;
  }
  if (psb_frequency == 32) {
    printf("Intel PT exposes no usable PSB frequency; skipping hardware watermark run.\n");
    return true;
  }

  memset(&control, 0, sizeof(control));
  control.magic = ZX_VCPU_INTEL_PT_CONTROL_MAGIC;
  control.version = ZX_VCPU_INTEL_PT_CONTROL_VERSION;
  control.size = sizeof(control);
  control.action = ZX_VCPU_INTEL_PT_ACTION_CONFIGURE;
  control.delivery = ZX_VCPU_INTEL_PT_DELIVERY_COMPLETE_OR_FAIL;
  control.config_flags =
      ZX_VCPU_INTEL_PT_TRACE_SUPERVISOR | ZX_VCPU_INTEL_PT_BRANCH_TRACE;
  // Three independently reclaimable pairs, each with one main page and one
  // STOP guard page. The main-page INT is the expected boundary.
  control.buffer_bytes = 3 * kPageSize;
  control.psb_frequency = psb_frequency;
  zx_status_t status = vcpu->WriteState(control);
  if (status == ZX_ERR_NOT_SUPPORTED) {
    memset(&control, 0, sizeof(control));
    ASSERT_EQ(ZX_OK, vcpu->ReadState(control), "read qualified Intel PT capability\n");
    if (control.unavailable_reason == ZX_VCPU_INTEL_PT_REASON_NESTED_HOST ||
        control.unavailable_reason == ZX_VCPU_INTEL_PT_REASON_RTIT_MSR_UNAVAILABLE) {
      printf("Nested host cannot delegate the PT execution path; skipping hardware watermark "
             "run.\n");
      return true;
    }
  }
  ASSERT_EQ(ZX_OK, status, "configure Intel PT hardware watermark session\n");

  memset(&control, 0, sizeof(control));
  ASSERT_EQ(ZX_OK, vcpu->ReadState(control), "read configured Intel PT session\n");
  const uint64_t generation = control.trace_generation;
  ASSERT_NE(0u, generation, "configured session has a generation\n");

  zx_port_packet_t watermark = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(watermark), "run to ToPA watermark\n");
  ASSERT_EQ(static_cast<uint8_t>(ZX_PKT_TYPE_GUEST_INTEL_PT),
            static_cast<uint8_t>(watermark.type),
            "ToPA interrupt must arrive before the finite guest's safety I/O exit\n");
  EXPECT_EQ(generation, watermark.guest_intel_pt.trace_generation,
            "watermark belongs to the configured generation\n");
  EXPECT_NE(0u, watermark.guest_intel_pt.segment_sequence,
            "watermark identifies an immutable segment\n");
  const uint64_t producer_cursor = watermark.guest_intel_pt.producer_cursor;
  EXPECT_GE(producer_cursor, kPageSize,
            "first one-page ToPA main region is complete\n");
  EXPECT_LE(producer_cursor, 2 * kPageSize,
            "interrupt-delivery skid remains inside the STOP guard\n");
  EXPECT_EQ(ZX_VCPU_INTEL_PT_STATUS_SEGMENT_COMPLETE,
            watermark.guest_intel_pt.status_flags,
            "watermark is complete with no gap, hardware error, or stop\n");

  memset(&control, 0, sizeof(control));
  ASSERT_EQ(ZX_OK, vcpu->ReadState(control), "read watermark state\n");
  EXPECT_EQ(producer_cursor, control.producer_cursor,
            "producer published the complete main region and guard tail\n");
  EXPECT_EQ(1u, control.watermark_count, "exactly one watermark was published\n");
  EXPECT_EQ(0u, control.lost_bytes, "complete-or-fail path reports no loss\n");
  EXPECT_EQ(ZX_VCPU_INTEL_PT_TERMINAL_ACTIVE, control.terminal,
            "a replacement pair is active after rotation\n");

  memset(&control, 0, sizeof(control));
  control.magic = ZX_VCPU_INTEL_PT_CONTROL_MAGIC;
  control.version = ZX_VCPU_INTEL_PT_CONTROL_VERSION;
  control.size = sizeof(control);
  control.action = ZX_VCPU_INTEL_PT_ACTION_SELECT_READ;
  control.trace_generation = generation;
  control.read_cursor = 0;
  control.read_max_bytes = ZX_VCPU_INTEL_PT_MAX_CHUNK_BYTES;
  ASSERT_EQ(ZX_OK, vcpu->WriteState(control), "select first bounded trace read\n");

  memset(&control, 0, sizeof(control));
  ASSERT_EQ(ZX_OK, vcpu->ReadState(control), "read first bounded trace chunk\n");
  ASSERT_EQ(kPageSize, control.data_size, "one bounded read returns the complete page\n");
  ASSERT_EQ(kPageSize, control.next_cursor, "bounded read advances by one maximum chunk\n");
  const uint64_t first_segment_sequence = control.segment_sequence;
  const uint64_t first_segment_offset = control.segment_offset;
  ktl::unique_ptr<uint8_t[]> first_data(
      new (&ac) uint8_t[ZX_VCPU_INTEL_PT_MAX_CHUNK_BYTES]);
  ASSERT_TRUE(ac.check(), "allocate Intel PT retry buffer\n");
  memcpy(first_data.get(), control.data, control.data_size);

  memset(&control, 0, sizeof(control));
  control.magic = ZX_VCPU_INTEL_PT_CONTROL_MAGIC;
  control.version = ZX_VCPU_INTEL_PT_CONTROL_VERSION;
  control.size = sizeof(control);
  control.action = ZX_VCPU_INTEL_PT_ACTION_SELECT_READ;
  control.trace_generation = generation;
  control.read_cursor = 0;
  control.read_max_bytes = ZX_VCPU_INTEL_PT_MAX_CHUNK_BYTES;
  ASSERT_EQ(ZX_OK, vcpu->WriteState(control), "repeat identical trace selection\n");
  memset(&control, 0, sizeof(control));
  ASSERT_EQ(ZX_OK, vcpu->ReadState(control), "repeat identical trace read\n");
  EXPECT_EQ(kPageSize, control.data_size, "retry preserves the bounded size\n");
  EXPECT_EQ(kPageSize, control.next_cursor, "retry preserves the next cursor\n");
  EXPECT_EQ(first_segment_sequence, control.segment_sequence,
            "retry preserves the segment identity\n");
  EXPECT_EQ(first_segment_offset, control.segment_offset,
            "retry preserves the segment offset\n");
  EXPECT_EQ(0, memcmp(first_data.get(), control.data, control.data_size),
            "retry returns byte-identical raw trace data\n");

  memset(&control, 0, sizeof(control));
  control.magic = ZX_VCPU_INTEL_PT_CONTROL_MAGIC;
  control.version = ZX_VCPU_INTEL_PT_CONTROL_VERSION;
  control.size = sizeof(control);
  control.action = ZX_VCPU_INTEL_PT_ACTION_ACK;
  control.trace_generation = generation;
  control.acknowledged_cursor = kPageSize;
  ASSERT_EQ(ZX_OK, vcpu->WriteState(control), "acknowledge the exact drained cursor\n");
  memset(&control, 0, sizeof(control));
  ASSERT_EQ(ZX_OK, vcpu->ReadState(control), "read drained Intel PT session\n");
  EXPECT_EQ(kPageSize, control.acknowledged_cursor, "ACK advances exactly to the drained page\n");
  EXPECT_EQ(producer_cursor, control.producer_cursor,
            "first ACK does not discard the interrupt-skid tail\n");

  memset(&control, 0, sizeof(control));
  control.magic = ZX_VCPU_INTEL_PT_CONTROL_MAGIC;
  control.version = ZX_VCPU_INTEL_PT_CONTROL_VERSION;
  control.size = sizeof(control);
  control.action = ZX_VCPU_INTEL_PT_ACTION_SELECT_READ;
  control.trace_generation = generation;
  control.read_cursor = kPageSize;
  control.read_max_bytes = ZX_VCPU_INTEL_PT_MAX_CHUNK_BYTES;
  ASSERT_EQ(ZX_OK, vcpu->WriteState(control), "select interrupt-skid trace tail\n");
  memset(&control, 0, sizeof(control));
  ASSERT_EQ(ZX_OK, vcpu->ReadState(control), "read interrupt-skid trace tail\n");
  EXPECT_EQ(producer_cursor - kPageSize, control.data_size,
            "second bounded read contains the complete guard tail\n");
  EXPECT_EQ(producer_cursor, control.next_cursor,
            "guard-tail read reaches the published cursor\n");
  EXPECT_EQ(first_segment_sequence, control.segment_sequence,
            "main region and guard tail retain one segment identity\n");
  EXPECT_EQ(kPageSize, control.segment_offset, "guard tail follows the main region exactly\n");

  memset(&control, 0, sizeof(control));
  control.magic = ZX_VCPU_INTEL_PT_CONTROL_MAGIC;
  control.version = ZX_VCPU_INTEL_PT_CONTROL_VERSION;
  control.size = sizeof(control);
  control.action = ZX_VCPU_INTEL_PT_ACTION_ACK;
  control.trace_generation = generation;
  control.acknowledged_cursor = producer_cursor;
  ASSERT_EQ(ZX_OK, vcpu->WriteState(control), "acknowledge complete trace segment\n");
  memset(&control, 0, sizeof(control));
  ASSERT_EQ(ZX_OK, vcpu->ReadState(control), "read fully drained Intel PT session\n");
  EXPECT_EQ(producer_cursor, control.acknowledged_cursor,
            "all published main and guard bytes are drained exactly\n");

  memset(&control, 0, sizeof(control));
  control.magic = ZX_VCPU_INTEL_PT_CONTROL_MAGIC;
  control.version = ZX_VCPU_INTEL_PT_CONTROL_VERSION;
  control.size = sizeof(control);
  control.action = ZX_VCPU_INTEL_PT_ACTION_STOP;
  control.trace_generation = generation;
  ASSERT_EQ(ZX_OK, vcpu->WriteState(control), "stop Intel PT session\n");
  memset(&control, 0, sizeof(control));
  ASSERT_EQ(ZX_OK, vcpu->ReadState(control), "read stopped Intel PT session\n");
  EXPECT_EQ(ZX_VCPU_INTEL_PT_TERMINAL_COMPLETE, control.terminal,
            "clean Stop produces a complete terminal state\n");
  EXPECT_EQ(0u, control.lost_bytes, "clean terminal state retains no-loss result\n");

  memset(&control, 0, sizeof(control));
  control.magic = ZX_VCPU_INTEL_PT_CONTROL_MAGIC;
  control.version = ZX_VCPU_INTEL_PT_CONTROL_VERSION;
  control.size = sizeof(control);
  control.action = ZX_VCPU_INTEL_PT_ACTION_RELEASE;
  control.trace_generation = generation;
  ASSERT_EQ(ZX_OK, vcpu->WriteState(control), "release Intel PT session\n");

  printf("Intel PT hardware watermark OK: one complete %lu-byte ToPA segment (4 KiB main plus "
         "%lu-byte interrupt-skid guard), byte-identical bounded retry, exact two-chunk ACK, "
         "no loss, clean Stop, and Release\n",
         producer_cursor, producer_cursor - kPageSize);
#else
  printf("Not x86_64; skipping.\n");
#endif

  END_TEST;
}

#ifdef __x86_64__

struct IntelPtKickContext {
  VcpuDispatcher* vcpu;
  ktl::atomic<bool> armed;
  ktl::atomic<bool> kicked;
};

int IntelPtKickBody(void* arg) {
  auto* context = static_cast<IntelPtKickContext*>(arg);
  while (!context->armed.load()) {
    Thread::Current::SleepRelative(ZX_MSEC(1));
  }
  // The caller has just returned from an I/O handshake immediately before the
  // guest's HLT. Give it enough time to re-enter and block in handle_hlt, so
  // this covers the real cross-thread Kick path rather than a pre-entry latch.
  Thread::Current::SleepRelative(ZX_MSEC(200));
  context->vcpu->Kick();
  context->kicked.store(true);
  return 0;
}

#endif

// Intel PT and the generic cross-thread stop path must compose. In particular,
// an in-flight Kick may interrupt a guest while an active trace session owns
// the PMI route, without consuming or corrupting that route. The guest first
// handshakes immediately before HLT, is kicked out of the real blocking wait,
// and then resumes into a finite branch-heavy loop. Reaching the typed ToPA
// watermark after the cancellation proves the PT route survived; Stop,
// Release, and a second Configure prove cleanup returned the global resource.
bool vcpu_intel_pt_cross_thread_kick_preserves_route_and_cleanup() {
  BEGIN_TEST;

#ifdef __x86_64__
  fbl::RefPtr<VmObjectPaged> ram;
  ASSERT_EQ(ZX_OK, VmObjectPaged::Create(PMM_ALLOC_FLAG_ANY, 0u, kGuestRamSize, &ram), "ram\n");
  ASSERT_EQ(ZX_OK, WriteIdentityTables(ram), "tables\n");

  // mov al,0x41; out 0x10,al; hlt
  // mov ecx,10000000
  // loop: test cl,1; jz next; next: dec ecx; jnz loop
  // mov al,0x7a; out 0x11,al; hlt
  //
  // The first OUT places the following HLT at a deterministic boundary. The
  // finite loop is a safety bound if the ToPA route is lost: port 0x11 then
  // returns instead of leaving the test blocked forever.
  const uint8_t code[] = {
      0xB0, 0x41, 0xE6, 0x10, 0xF4, 0xB9, 0x80, 0x96, 0x98, 0x00, 0xF6, 0xC1,
      0x01, 0x74, 0x00, 0xFF, 0xC9, 0x75, 0xF7, 0xB0, 0x7A, 0xE6, 0x11, 0xF4,
  };
  ASSERT_EQ(ZX_OK, ram->Write(code, kCodeGpa, sizeof(code)), "code\n");
  ASSERT_EQ(ZX_OK, ram->CommitRange(0, kGuestRamSize), "commit\n");

  auto lg = CreateLiveGuestDispatcher(ram, kCodeGpa);
  if (lg.is_error() && lg.status_value() == ZX_ERR_NOT_SUPPORTED) {
    printf("VMX not supported here; skipping Intel PT + Kick composition test.\n");
    return true;
  }
  ASSERT_EQ(ZX_OK, lg.status_value(), "create nested live guest\n");
  VcpuDispatcher* vcpu = lg->vcpu.get();

  fbl::AllocChecker ac;
  ktl::unique_ptr<zx_vcpu_intel_pt_control_t> control_storage(
      new (&ac) zx_vcpu_intel_pt_control_t{});
  ASSERT_TRUE(ac.check(), "allocate Intel PT control record\n");
  auto& control = *control_storage;
  ASSERT_EQ(ZX_OK, vcpu->ReadState(control), "read Intel PT capability\n");
  if (control.availability == ZX_VCPU_INTEL_PT_UNSUPPORTED) {
    printf("Intel PT is absent here; skipping Intel PT + Kick composition test.\n");
    return true;
  }

  uint32_t psb_frequency = 0;
  while (psb_frequency < 32 &&
         (control.supported_psb_frequencies & (uint32_t{1} << psb_frequency)) == 0) {
    ++psb_frequency;
  }
  if (psb_frequency == 32) {
    printf("Intel PT exposes no usable PSB frequency; skipping Intel PT + Kick composition "
           "test.\n");
    return true;
  }

  auto configure = [&]() {
    memset(&control, 0, sizeof(control));
    control.magic = ZX_VCPU_INTEL_PT_CONTROL_MAGIC;
    control.version = ZX_VCPU_INTEL_PT_CONTROL_VERSION;
    control.size = sizeof(control);
    control.action = ZX_VCPU_INTEL_PT_ACTION_CONFIGURE;
    control.delivery = ZX_VCPU_INTEL_PT_DELIVERY_COMPLETE_OR_FAIL;
    control.config_flags =
        ZX_VCPU_INTEL_PT_TRACE_SUPERVISOR | ZX_VCPU_INTEL_PT_BRANCH_TRACE;
    control.buffer_bytes = 3 * kPageSize;
    control.psb_frequency = psb_frequency;
    return vcpu->WriteState(control);
  };
  auto release = [&](uint64_t generation) {
    memset(&control, 0, sizeof(control));
    control.magic = ZX_VCPU_INTEL_PT_CONTROL_MAGIC;
    control.version = ZX_VCPU_INTEL_PT_CONTROL_VERSION;
    control.size = sizeof(control);
    control.action = ZX_VCPU_INTEL_PT_ACTION_RELEASE;
    control.trace_generation = generation;
    return vcpu->WriteState(control);
  };

  zx_status_t status = configure();
  if (status == ZX_ERR_NOT_SUPPORTED) {
    memset(&control, 0, sizeof(control));
    ASSERT_EQ(ZX_OK, vcpu->ReadState(control), "read qualified Intel PT capability\n");
    if (control.unavailable_reason == ZX_VCPU_INTEL_PT_REASON_NESTED_HOST ||
        control.unavailable_reason == ZX_VCPU_INTEL_PT_REASON_RTIT_MSR_UNAVAILABLE ||
        control.unavailable_reason == ZX_VCPU_INTEL_PT_REASON_VMX_CONTROL_UNAVAILABLE) {
      printf("Host cannot delegate the Intel PT execution path; skipping Intel PT + Kick "
             "composition test.\n");
      return true;
    }
  }
  ASSERT_EQ(ZX_OK, status, "configure Intel PT session for Kick composition\n");

  memset(&control, 0, sizeof(control));
  ASSERT_EQ(ZX_OK, vcpu->ReadState(control), "read configured Intel PT session\n");
  const uint64_t generation = control.trace_generation;
  ASSERT_NE(0u, generation, "configured session has a generation\n");

  zx_port_packet_t handshake = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(handshake), "run to pre-HLT handshake\n");
  ASSERT_EQ(static_cast<uint8_t>(ZX_PKT_TYPE_GUEST_IO),
            static_cast<uint8_t>(handshake.type), "pre-HLT handshake packet\n");
  ASSERT_EQ(0x10u, handshake.guest_io.port, "pre-HLT handshake port\n");
  ASSERT_EQ(0x41u, static_cast<uint32_t>(handshake.guest_io.data[0]),
            "pre-HLT handshake value\n");

  IntelPtKickContext kick = {};
  kick.vcpu = vcpu;
  Thread* kicker =
      Thread::Create("hv-intel-pt-kick", IntelPtKickBody, &kick, DEFAULT_PRIORITY);
  ASSERT_TRUE(kicker != nullptr, "create Intel PT kicker thread\n");
  kicker->Resume();
  kick.armed.store(true);

  zx_port_packet_t interrupted = {};
  const zx_status_t enter_status = vcpu->Enter(interrupted);
  int kicker_retcode = 0;
  const zx_status_t join_status = kicker->Join(&kicker_retcode, ZX_TIME_INFINITE);
  ASSERT_EQ(ZX_OK, join_status, "join Intel PT kicker thread\n");
  ASSERT_TRUE(kick.kicked.load(), "cross-thread Kick ran\n");
  ASSERT_EQ(ZX_ERR_INTERNAL_INTR_RETRY, enter_status,
            "Kick must interrupt the in-flight HLT wait\n");

  zx_port_packet_t canceled = {};
  ASSERT_EQ(ZX_ERR_CANCELED, vcpu->Enter(canceled),
            "the in-flight Kick remains latched for the next entry\n");

  memset(&control, 0, sizeof(control));
  ASSERT_EQ(ZX_OK, vcpu->ReadState(control), "read Intel PT state after Kick\n");
  ASSERT_EQ(generation, control.trace_generation, "Kick preserves the trace generation\n");
  ASSERT_EQ(ZX_VCPU_INTEL_PT_TERMINAL_ACTIVE, control.terminal,
            "Kick leaves the PT route active\n");
  ASSERT_EQ(0u, control.lost_bytes, "Kick introduces no trace loss\n");

  zx_port_packet_t watermark = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(watermark), "resume after Kick to ToPA watermark\n");
  ASSERT_EQ(static_cast<uint8_t>(ZX_PKT_TYPE_GUEST_INTEL_PT),
            static_cast<uint8_t>(watermark.type),
            "the preserved PT route returns its typed watermark\n");
  EXPECT_EQ(generation, watermark.guest_intel_pt.trace_generation,
            "watermark belongs to the pre-Kick generation\n");
  EXPECT_NE(0u, watermark.guest_intel_pt.segment_sequence,
            "watermark identifies a sealed segment\n");
  EXPECT_EQ(ZX_VCPU_INTEL_PT_STATUS_SEGMENT_COMPLETE,
            watermark.guest_intel_pt.status_flags,
            "post-Kick watermark is complete and lossless\n");

  memset(&control, 0, sizeof(control));
  control.magic = ZX_VCPU_INTEL_PT_CONTROL_MAGIC;
  control.version = ZX_VCPU_INTEL_PT_CONTROL_VERSION;
  control.size = sizeof(control);
  control.action = ZX_VCPU_INTEL_PT_ACTION_STOP;
  control.trace_generation = generation;
  ASSERT_EQ(ZX_OK, vcpu->WriteState(control), "stop post-Kick Intel PT session\n");
  memset(&control, 0, sizeof(control));
  ASSERT_EQ(ZX_OK, vcpu->ReadState(control), "read stopped post-Kick Intel PT session\n");
  EXPECT_EQ(ZX_VCPU_INTEL_PT_TERMINAL_COMPLETE, control.terminal,
            "post-Kick Stop produces a complete terminal state\n");
  EXPECT_EQ(0u, control.lost_bytes, "post-Kick Stop remains lossless\n");
  ASSERT_EQ(ZX_OK, release(generation), "release post-Kick Intel PT session\n");

  memset(&control, 0, sizeof(control));
  ASSERT_EQ(ZX_OK, vcpu->ReadState(control), "read Intel PT capability after Release\n");
  ASSERT_EQ(ZX_VCPU_INTEL_PT_AVAILABLE, control.availability,
            "Release returns Intel PT to available\n");
  ASSERT_EQ(ZX_VCPU_INTEL_PT_TERMINAL_INACTIVE, control.terminal,
            "Release clears the terminal session\n");
  ASSERT_EQ(0u, control.trace_generation, "Release clears the trace generation\n");

  ASSERT_EQ(ZX_OK, configure(), "reconfigure Intel PT after post-Kick Release\n");
  memset(&control, 0, sizeof(control));
  ASSERT_EQ(ZX_OK, vcpu->ReadState(control), "read reconfigured Intel PT session\n");
  const uint64_t second_generation = control.trace_generation;
  ASSERT_NE(0u, second_generation, "reconfigured session has a generation\n");
  EXPECT_NE(generation, second_generation, "reconfiguration creates a fresh generation\n");
  ASSERT_EQ(ZX_OK, release(second_generation), "release reconfigured Intel PT session\n");

  printf("Intel PT + Kick composition OK: in-flight HLT interrupted, cancellation latched, "
         "generation %lu produced a lossless watermark after resume, and Stop/Release allowed "
         "generation %lu\n",
         generation, second_generation);
#else
  printf("Not x86_64; skipping.\n");
#endif

  END_TEST;
}

// The instruction-control topic is a runtime capability query and a global PMU
// reservation point. This test covers both truthful fail-closed discovery and
// the no-cost default path. It is useful on nested KVM even when no usable PMU
// is exposed: that case must return UNSUPPORTED/NOT_SUPPORTED without touching
// state, rather than advertising a control that fails only after mutation.
bool vmx_allowed_one_accepts_flexible_and_forced_controls() {
  BEGIN_TEST;

#ifdef __x86_64__
  constexpr uint32_t bit = 1u << 13;
  EXPECT_TRUE(vmx_control_allows_one(uint64_t{bit} << 32, bit),
              "flexible control may be enabled\n");
  EXPECT_TRUE(vmx_control_allows_one((uint64_t{bit} << 32) | bit, bit),
              "forced-one control is already enabled\n");
  EXPECT_FALSE(vmx_control_allows_one(0, bit),
               "control without an allowed-one bit cannot be enabled\n");
#else
  printf("Not x86_64; skipping.\n");
#endif

  END_TEST;
}

bool vcpu_instruction_control_capability_validation_and_unarmed_path() {
  BEGIN_TEST;

#ifdef __x86_64__
  fbl::RefPtr<VmObjectPaged> ram;
  ASSERT_EQ(ZX_OK, VmObjectPaged::Create(PMM_ALLOC_FLAG_ANY, 0u, kGuestRamSize, &ram), "ram\n");
  ASSERT_EQ(ZX_OK, WriteIdentityTables(ram), "tables\n");
  // mov al,0x5a; out 0x10,al; hlt
  const uint8_t code[] = {0xB0, 0x5A, 0xE6, 0x10, 0xF4};
  ASSERT_EQ(ZX_OK, ram->Write(code, kCodeGpa, sizeof(code)), "code\n");
  ASSERT_EQ(ZX_OK, ram->CommitRange(0, kGuestRamSize), "commit\n");

  auto lg = CreateLiveGuestDispatcher(ram, kCodeGpa);
  if (lg.is_error() && lg.status_value() == ZX_ERR_NOT_SUPPORTED) {
    printf("VMX not supported here; skipping instruction-control capability test.\n");
    return true;
  }
  ASSERT_EQ(ZX_OK, lg.status_value(), "create nested live guest\n");
  VcpuDispatcher* vcpu = lg->vcpu.get();

  zx_vcpu_instruction_control_t initial = {};
  ASSERT_EQ(ZX_OK, vcpu->ReadState(initial), "read instruction-control capabilities\n");
  EXPECT_EQ(ZX_VCPU_INSTRUCTION_CONTROL_MAGIC, initial.magic, "magic\n");
  EXPECT_EQ(ZX_VCPU_INSTRUCTION_CONTROL_VERSION, initial.version, "version\n");
  EXPECT_EQ(sizeof(initial), initial.size, "size\n");
  EXPECT_LE(initial.availability, ZX_VCPU_INSTRUCTION_BUSY, "known availability value\n");
  EXPECT_EQ(0u, initial.active_flags, "fresh VCPU is unarmed\n");
  EXPECT_EQ(0u, initial.pending_sequence, "fresh VCPU has no result\n");
  if (initial.availability == ZX_VCPU_INSTRUCTION_UNSUPPORTED) {
    EXPECT_EQ(0u, initial.supported_flags, "unsupported means no advertised flag\n");
    EXPECT_EQ(0u, initial.counter_width, "unsupported means no counter width\n");
    EXPECT_EQ(0u, initial.precision, "unsupported means no precision claim\n");
    EXPECT_EQ(0u, initial.max_budget, "unsupported means no maximum\n");
  } else {
    EXPECT_EQ(ZX_VCPU_INSTRUCTION_ALL_FLAGS, initial.supported_flags,
              "available or busy hardware reports the implemented control\n");
    EXPECT_GE(initial.counter_width, 16u, "minimum accepted fixed-counter width\n");
    EXPECT_EQ(ZX_VCPU_INSTRUCTION_PRECISION_OVERFLOW_INTERRUPT, initial.precision,
              "the stop uses an overflow interrupt and may skid\n");
    EXPECT_NE(0u, initial.max_budget, "supported hardware has a non-zero range\n");
  }

  const uint64_t accesses_before = x86_perfmon_vcpu_counter_msr_accesses();
  zx_port_packet_t io = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(io), "unarmed entry\n");
  ASSERT_EQ(static_cast<uint8_t>(ZX_PKT_TYPE_GUEST_IO), static_cast<uint8_t>(io.type),
            "unarmed execution returns only its ordinary I/O packet\n");
  EXPECT_EQ(0x5Au, static_cast<uint32_t>(io.guest_io.data[0]), "guest output\n");
  EXPECT_EQ(accesses_before, x86_perfmon_vcpu_counter_msr_accesses(),
            "unarmed execution must not access PMU MSRs\n");

  // Unknown layouts, flags, and output fields are rejected before any session
  // state or reservation changes.
  auto malformed_size = MakeInstructionControl(0, 0);
  malformed_size.size--;
  EXPECT_EQ(ZX_ERR_INVALID_ARGS, vcpu->WriteState(malformed_size), "unknown size\n");
  auto unknown_flag = MakeInstructionControl(uint64_t{1} << 63, 1);
  EXPECT_EQ(ZX_ERR_INVALID_ARGS, vcpu->WriteState(unknown_flag), "unknown flag\n");
  auto output_on_write = MakeInstructionControl(0, 0);
  output_on_write.retired_instructions = 1;
  EXPECT_EQ(ZX_ERR_INVALID_ARGS, vcpu->WriteState(output_on_write),
            "output-only result on write\n");
  zx_vcpu_instruction_control_t after_rejections = {};
  ASSERT_EQ(ZX_OK, vcpu->ReadState(after_rejections), "read after malformed requests\n");
  EXPECT_EQ(0u, after_rejections.active_flags, "malformed requests leave the VCPU unarmed\n");
  EXPECT_EQ(0u, after_rejections.pending_sequence, "malformed requests create no result\n");

  const uint64_t budget =
      initial.max_budget == 0 ? 1 : ktl::min<uint64_t>(initial.max_budget, 1024);
  auto arm = MakeInstructionControl(ZX_VCPU_INSTRUCTION_RETIRED_BUDGET, budget);
  const zx_status_t arm_status = vcpu->WriteState(arm);
  if (initial.availability == ZX_VCPU_INSTRUCTION_UNSUPPORTED) {
    EXPECT_EQ(ZX_ERR_NOT_SUPPORTED, arm_status,
              "a valid arm on unsupported hardware fails before mutation\n");
    zx_vcpu_instruction_control_t after = {};
    ASSERT_EQ(ZX_OK, vcpu->ReadState(after), "read after unsupported arm\n");
    EXPECT_EQ(0u, after.active_flags, "unsupported arm stays inactive\n");
    EXPECT_EQ(0u, after.pending_sequence, "unsupported arm creates no result\n");
    printf("instruction-control capability OK: nested host exposes no attributable fixed "
           "retired counter; the valid request failed closed and unarmed execution touched no "
           "PMU MSR\n");
    return true;
  }
  if (arm_status == ZX_ERR_SHOULD_WAIT) {
    zx_vcpu_instruction_control_t after = {};
    ASSERT_EQ(ZX_OK, vcpu->ReadState(after), "read after busy arm\n");
    EXPECT_EQ(0u, after.active_flags, "resource conflict fails before mutation\n");
    EXPECT_EQ(0u, after.pending_sequence, "resource conflict creates no result\n");
    printf("instruction-control capability OK: hardware is supported but the PMU/PMI resource "
           "is busy; the request failed before mutation and unarmed execution touched no PMU "
           "MSR\n");
    return true;
  }
  ASSERT_EQ(ZX_OK, arm_status, "arm retired-instruction budget\n");

  zx_vcpu_instruction_control_t armed = {};
  ASSERT_EQ(ZX_OK, vcpu->ReadState(armed), "read armed state\n");
  EXPECT_EQ(ZX_VCPU_INSTRUCTION_RETIRED_BUDGET, armed.active_flags, "budget armed\n");
  EXPECT_EQ(budget, armed.budget, "budget round-trips\n");

  auto malformed_while_armed = MakeInstructionControl(0, 0);
  malformed_while_armed.max_budget = 1;
  EXPECT_EQ(ZX_ERR_INVALID_ARGS, vcpu->WriteState(malformed_while_armed),
            "malformed cancellation is atomic\n");
  zx_vcpu_instruction_control_t still_armed = {};
  ASSERT_EQ(ZX_OK, vcpu->ReadState(still_armed), "read after malformed cancellation\n");
  EXPECT_EQ(ZX_VCPU_INSTRUCTION_RETIRED_BUDGET, still_armed.active_flags,
            "malformed cancellation leaves the session armed\n");
  EXPECT_EQ(budget, still_armed.budget, "malformed cancellation preserves the budget\n");

  X86VcpuPmuProperties conflict = {};
  EXPECT_EQ(ZX_ERR_SHOULD_WAIT, x86_perfmon_reserve_vcpu_counter(&conflict),
            "a second owner must fail while this VCPU holds the global PMU resource\n");

  ASSERT_EQ(ZX_OK, vcpu->WriteState(MakeInstructionControl(0, 0)),
            "cancel before overflow\n");
  zx_vcpu_instruction_control_t canceled = {};
  ASSERT_EQ(ZX_OK, vcpu->ReadState(canceled), "read canceled state\n");
  EXPECT_EQ(0u, canceled.active_flags, "cancel disarms\n");
  EXPECT_EQ(0u, canceled.budget, "cancel clears the budget\n");

  // Prove cleanup made the resource genuinely reusable, first at the PMU layer
  // and then through the public VCPU control.
  ASSERT_EQ(ZX_OK, x86_perfmon_reserve_vcpu_counter(&conflict),
            "resource reacquires after cancellation\n");
  x86_perfmon_release_vcpu_counter();
  ASSERT_EQ(ZX_OK, vcpu->WriteState(arm), "VCPU reacquires after cleanup\n");
  ASSERT_EQ(ZX_OK, vcpu->WriteState(MakeInstructionControl(0, 0)), "final disarm\n");

  printf("instruction-control capability OK: %u-bit fixed counter, max budget %#lx; malformed "
         "requests were atomic, a competing reservation saw SHOULD_WAIT, cancellation released "
         "the resource, and unarmed execution touched no PMU MSR\n",
         initial.counter_width, initial.max_budget);
#else
  printf("Not x86_64; skipping.\n");
#endif

  END_TEST;
}

// A positive hardware run uses a long exit-free guest loop so the only reason
// to return early is the fixed-counter PMI. The observed count is deliberately
// compared as >= requested rather than == requested: PMIs skid. The packet and
// read-back both carry the exact sampled guest-only count and the requested
// threshold separately.
bool vcpu_instruction_budget_reports_exact_observed_count_and_requires_ack() {
  BEGIN_TEST;

#ifdef __x86_64__
  fbl::RefPtr<VmObjectPaged> ram;
  ASSERT_EQ(ZX_OK, VmObjectPaged::Create(PMM_ALLOC_FLAG_ANY, 0u, kGuestRamSize, &ram), "ram\n");
  ASSERT_EQ(ZX_OK, WriteIdentityTables(ram), "tables\n");
  // mov ecx,100000; dec ecx; jnz -4; mov al,0x6b; out 0x10,al; hlt
  const uint8_t code[] = {
      0xB9, 0xA0, 0x86, 0x01, 0x00, 0xFF, 0xC9,
      0x75, 0xFC, 0xB0, 0x6B, 0xE6, 0x10, 0xF4,
  };
  ASSERT_EQ(ZX_OK, ram->Write(code, kCodeGpa, sizeof(code)), "code\n");
  ASSERT_EQ(ZX_OK, ram->CommitRange(0, kGuestRamSize), "commit\n");

  auto lg = CreateLiveGuestDispatcher(ram, kCodeGpa);
  if (lg.is_error() && lg.status_value() == ZX_ERR_NOT_SUPPORTED) {
    printf("VMX not supported here; skipping instruction-budget run.\n");
    return true;
  }
  ASSERT_EQ(ZX_OK, lg.status_value(), "create nested live guest\n");
  VcpuDispatcher* vcpu = lg->vcpu.get();

  zx_vcpu_instruction_control_t capability = {};
  ASSERT_EQ(ZX_OK, vcpu->ReadState(capability), "read instruction capability\n");
  if (capability.availability != ZX_VCPU_INSTRUCTION_AVAILABLE) {
    printf("instruction-budget positive run unavailable here (%s); fail-closed behavior is "
           "covered by the capability test\n",
           capability.availability == ZX_VCPU_INSTRUCTION_BUSY ? "resource busy"
                                                               : "hardware unsupported");
    return true;
  }

  const uint64_t budget = ktl::min<uint64_t>(capability.max_budget, 4096);
  ASSERT_NE(0u, budget, "supported counter has a usable budget\n");
  ASSERT_EQ(
      ZX_OK,
      vcpu->WriteState(MakeInstructionControl(ZX_VCPU_INSTRUCTION_RETIRED_BUDGET, budget)),
      "arm instruction budget\n");

  zx_port_packet_t stopped = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(stopped), "run to fixed-counter overflow\n");
  ASSERT_EQ(static_cast<uint8_t>(ZX_PKT_TYPE_GUEST_INSTRUCTION_BUDGET),
            static_cast<uint8_t>(stopped.type), "typed instruction-budget packet\n");
  ASSERT_NE(0u, stopped.guest_instruction_budget.sequence, "non-zero sequence\n");
  EXPECT_EQ(budget, stopped.guest_instruction_budget.requested_budget,
            "packet keeps the requested target separate\n");
  EXPECT_GE(stopped.guest_instruction_budget.retired_instructions, budget,
            "exact observed count reaches or exceeds the target because PMI delivery may skid\n");
  EXPECT_GE(stopped.guest_instruction_budget.rip, kCodeGpa + 5,
            "stop is in or after the counted loop\n");
  EXPECT_LT(stopped.guest_instruction_budget.rip, kCodeGpa + 11,
            "small budget stops before the final output instruction\n");

  zx_vcpu_instruction_control_t pending = {};
  ASSERT_EQ(ZX_OK, vcpu->ReadState(pending), "read pending result\n");
  EXPECT_EQ(0u, pending.active_flags, "overflow disarms the one-shot\n");
  EXPECT_EQ(stopped.guest_instruction_budget.sequence, pending.pending_sequence,
            "same acknowledgement sequence\n");
  EXPECT_EQ(stopped.guest_instruction_budget.retired_instructions,
            pending.retired_instructions, "read-back preserves exact observed count\n");
  EXPECT_EQ(stopped.guest_instruction_budget.rip, pending.pending_rip,
            "read-back preserves stopped RIP\n");

  zx_port_packet_t blocked = {};
  EXPECT_EQ(ZX_ERR_BAD_STATE, vcpu->Enter(blocked),
            "delivered result blocks resume until exact acknowledgement\n");
  EXPECT_EQ(
      ZX_ERR_BAD_STATE,
      vcpu->WriteState(MakeInstructionControl(0, 0, pending.pending_sequence + 1)),
      "stale acknowledgement is refused\n");
  ASSERT_EQ(ZX_OK,
            vcpu->WriteState(MakeInstructionControl(0, 0, pending.pending_sequence)),
            "acknowledge exact result\n");

  zx_port_packet_t completed = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(completed), "resume after acknowledgement\n");
  ASSERT_EQ(static_cast<uint8_t>(ZX_PKT_TYPE_GUEST_IO),
            static_cast<uint8_t>(completed.type), "guest reaches ordinary output\n");
  EXPECT_EQ(0x6Bu, static_cast<uint32_t>(completed.guest_io.data[0]),
            "resume continues the loop without replaying the stop\n");

  printf("instruction-budget run OK: requested %#lx retired guest instructions; exact observed "
         "count %#lx at RIP %#lx (overflow-interrupt precision), then exact acknowledgement "
         "resumed to the guest marker\n",
         budget, stopped.guest_instruction_budget.retired_instructions,
         stopped.guest_instruction_budget.rip);
#else
  printf("Not x86_64; skipping.\n");
#endif

  END_TEST;
}

// Whole-state replacement and terminal guest halt both end an armed control,
// and dispatcher destruction must do the same. Each transition is followed by
// a real reacquisition, so a test cannot pass merely because the visible VCPU
// fields were cleared while the global reservation leaked.
bool vcpu_instruction_control_cleanup_on_restore_halt_and_destruction() {
  BEGIN_TEST;

#ifdef __x86_64__
  fbl::RefPtr<VmObjectPaged> ram;
  ASSERT_EQ(ZX_OK, VmObjectPaged::Create(PMM_ALLOC_FLAG_ANY, 0u, kGuestRamSize, &ram), "ram\n");
  ASSERT_EQ(ZX_OK, WriteIdentityTables(ram), "tables\n");
  // ud2: with no usable IDT this terminates the guest through triple fault.
  const uint8_t code[] = {0x0F, 0x0B};
  ASSERT_EQ(ZX_OK, ram->Write(code, kCodeGpa, sizeof(code)), "code\n");
  ASSERT_EQ(ZX_OK, ram->CommitRange(0, kGuestRamSize), "commit\n");

  auto lg = CreateLiveGuestDispatcher(ram, kCodeGpa);
  if (lg.is_error() && lg.status_value() == ZX_ERR_NOT_SUPPORTED) {
    printf("VMX not supported here; skipping instruction-control cleanup test.\n");
    return true;
  }
  ASSERT_EQ(ZX_OK, lg.status_value(), "create nested live guest\n");
  VcpuDispatcher* vcpu = lg->vcpu.get();

  zx_vcpu_instruction_control_t capability = {};
  ASSERT_EQ(ZX_OK, vcpu->ReadState(capability), "read instruction capability\n");
  if (capability.availability != ZX_VCPU_INSTRUCTION_AVAILABLE) {
    printf("instruction-control cleanup run unavailable here (%s); lifecycle code remains "
           "compile-covered and unsupported/busy behavior is covered separately\n",
           capability.availability == ZX_VCPU_INSTRUCTION_BUSY ? "resource busy"
                                                               : "hardware unsupported");
    return true;
  }
  const uint64_t budget = ktl::min<uint64_t>(capability.max_budget, 65536);
  const auto arm =
      MakeInstructionControl(ZX_VCPU_INSTRUCTION_RETIRED_BUDGET, budget);

  const size_t full_size = SerializedVcpuStateSize();
  fbl::AllocChecker ac;
  ktl::unique_ptr<uint8_t[]> full(new (&ac) uint8_t[full_size]);
  ASSERT_TRUE(ac.check(), "allocate whole-state buffer\n");
  size_t actual = 0;
  ASSERT_EQ(ZX_OK, vcpu->ReadStateFull(full.get(), full_size, &actual), "capture whole state\n");
  ASSERT_EQ(full_size, actual, "whole-state size\n");

  ASSERT_EQ(ZX_OK, vcpu->WriteState(arm), "arm before restore\n");
  const uint8_t saved_header_byte = full[0];
  full[0] ^= 0xff;
  EXPECT_EQ(ZX_ERR_INVALID_ARGS, vcpu->WriteStateFull(full.get(), actual),
            "malformed whole-state replacement is refused\n");
  full[0] = saved_header_byte;
  zx_vcpu_instruction_control_t after_refused_restore = {};
  ASSERT_EQ(ZX_OK, vcpu->ReadState(after_refused_restore),
            "read after refused whole-state replacement\n");
  EXPECT_EQ(ZX_VCPU_INSTRUCTION_RETIRED_BUDGET,
            after_refused_restore.active_flags,
            "failed restore leaves the armed control unchanged\n");
  EXPECT_EQ(budget, after_refused_restore.budget,
            "failed restore leaves the requested budget unchanged\n");
  ASSERT_EQ(ZX_OK, vcpu->WriteStateFull(full.get(), actual),
            "successful whole-state replacement\n");
  zx_vcpu_instruction_control_t restored = {};
  ASSERT_EQ(ZX_OK, vcpu->ReadState(restored), "read after restore\n");
  EXPECT_EQ(0u, restored.active_flags, "restore cancels active budget\n");
  EXPECT_EQ(0u, restored.pending_sequence, "restore drops pending control state\n");
  ASSERT_EQ(ZX_OK, vcpu->WriteState(arm), "resource reacquires after restore\n");
  ASSERT_EQ(ZX_OK, vcpu->WriteState(MakeInstructionControl(0, 0)),
            "disarm after restore reacquisition\n");

  ASSERT_EQ(ZX_OK, vcpu->WriteState(arm), "arm before terminal guest halt\n");
  zx_port_packet_t halted = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(halted), "enter terminal guest\n");
  ASSERT_EQ(static_cast<uint8_t>(ZX_PKT_TYPE_GUEST_HALT),
            static_cast<uint8_t>(halted.type), "terminal halt wins\n");
  zx_vcpu_instruction_control_t after_halt = {};
  ASSERT_EQ(ZX_OK, vcpu->ReadState(after_halt), "read after terminal halt\n");
  EXPECT_EQ(0u, after_halt.active_flags, "terminal halt cancels active budget\n");
  EXPECT_EQ(0u, after_halt.pending_sequence, "terminal halt keeps no budget result\n");
  ASSERT_EQ(ZX_OK, vcpu->WriteState(arm), "resource reacquires after terminal halt\n");
  ASSERT_EQ(ZX_OK, vcpu->WriteState(MakeInstructionControl(0, 0)),
            "disarm after halt reacquisition\n");

  ASSERT_EQ(ZX_OK, vcpu->WriteState(arm), "arm before dispatcher destruction\n");
  lg->vcpu.reset();
  lg->guest.reset();

  auto replacement = CreateLiveGuestDispatcher(ram, kCodeGpa);
  ASSERT_EQ(ZX_OK, replacement.status_value(), "create replacement VCPU\n");
  zx_vcpu_instruction_control_t replacement_capability = {};
  ASSERT_EQ(ZX_OK, replacement->vcpu->ReadState(replacement_capability),
            "read replacement capability\n");
  EXPECT_EQ(ZX_VCPU_INSTRUCTION_AVAILABLE, replacement_capability.availability,
            "destruction releases the old reservation\n");
  ASSERT_EQ(ZX_OK, replacement->vcpu->WriteState(arm),
            "replacement VCPU acquires after destruction\n");
  ASSERT_EQ(ZX_OK,
            replacement->vcpu->WriteState(MakeInstructionControl(0, 0)),
            "replacement disarm\n");

  printf("instruction-control cleanup OK: successful whole-state restore, terminal guest halt, "
         "and dispatcher destruction each released the global PMU reservation; a subsequent "
         "owner reacquired it after every transition\n");
#else
  printf("Not x86_64; skipping.\n");
#endif

  END_TEST;
}

// The memory-access topic is a runtime capability query and a guest-global,
// transactional EPT permission control. This covers malformed requests,
// page-boundary checks, overlapping ranges, every access kind, and atomic
// rejection while an existing range set is installed.
bool vcpu_memory_access_control_validation_overlap_and_cross_page() {
  BEGIN_TEST;

#ifdef __x86_64__
  fbl::RefPtr<VmObjectPaged> ram;
  ASSERT_EQ(ZX_OK, VmObjectPaged::Create(PMM_ALLOC_FLAG_ANY, 0u, kGuestRamSize, &ram), "ram\n");
  ASSERT_EQ(ZX_OK, WriteIdentityTables(ram), "tables\n");
  const uint8_t code[] = {0xB0, 0x5A, 0xE6, 0x10, 0xF4};
  ASSERT_EQ(ZX_OK, ram->Write(code, kCodeGpa, sizeof(code)), "code\n");
  ASSERT_EQ(ZX_OK, ram->CommitRange(0, kGuestRamSize), "commit\n");

  auto lg = CreateLiveGuestDispatcher(ram, kCodeGpa);
  if (lg.is_error() && lg.status_value() == ZX_ERR_NOT_SUPPORTED) {
    printf("VMX/EPT unavailable; memory-access control correctly cannot be instantiated here.\n");
    return true;
  }
  ASSERT_EQ(ZX_OK, lg.status_value(), "create nested live guest\n");
  VcpuDispatcher* vcpu = lg->vcpu.get();

  zx_vcpu_memory_access_control_t initial = {};
  ASSERT_EQ(ZX_OK, vcpu->ReadState(initial), "read capabilities\n");
  EXPECT_EQ(ZX_VCPU_MEMORY_ACCESS_CONTROL_MAGIC, initial.magic, "magic\n");
  EXPECT_EQ(ZX_VCPU_MEMORY_ACCESS_CONTROL_VERSION, initial.version, "version\n");
  EXPECT_EQ(sizeof(initial), initial.size, "size\n");
  EXPECT_EQ(ZX_VCPU_MEMORY_ACCESS_AVAILABLE, initial.availability, "EPT-backed control available\n");
  EXPECT_EQ(ZX_VCPU_MEMORY_ACCESS_MAX_RANGES, initial.max_ranges, "range bound\n");
  EXPECT_EQ(ZX_VCPU_MEMORY_ACCESS_MAX_PAGES, initial.max_pages, "page bound\n");
  EXPECT_EQ(ZX_VCPU_MEMORY_ACCESS_ALL_FLAGS, initial.supported_flags, "supported control\n");
  EXPECT_EQ(ZX_VCPU_MEMORY_ACCESS_WRITE | ZX_VCPU_MEMORY_ACCESS_EXECUTE,
            initial.supported_access,
            "x86 advertises only independently representable access kinds\n");
  EXPECT_EQ(0u, initial.active_flags, "fresh guest unarmed\n");

  auto malformed_size = MakeMemoryAccessControl(0);
  malformed_size.size--;
  EXPECT_EQ(ZX_ERR_INVALID_ARGS, vcpu->WriteState(malformed_size), "unknown size\n");
  auto unknown_flag = MakeMemoryAccessControl(uint64_t{1} << 63);
  EXPECT_EQ(ZX_ERR_INVALID_ARGS, vcpu->WriteState(unknown_flag), "unknown flag\n");
  auto empty_arm = MakeMemoryAccessControl(ZX_VCPU_MEMORY_ACCESS_ARM);
  EXPECT_EQ(ZX_ERR_INVALID_ARGS, vcpu->WriteState(empty_arm), "armed set must be non-empty\n");
  auto output_on_write = MakeMemoryAccessControl(0);
  output_on_write.supported_access = ZX_VCPU_MEMORY_ACCESS_WRITE;
  EXPECT_EQ(ZX_ERR_INVALID_ARGS, vcpu->WriteState(output_on_write),
            "supported access is output-only\n");

  auto unaligned = MakeMemoryAccessControl(ZX_VCPU_MEMORY_ACCESS_ARM);
  unaligned.range_count = 1;
  unaligned.ranges[0] = {kDataGpa + 1, kPageSize, ZX_VCPU_MEMORY_ACCESS_WRITE, 0};
  EXPECT_EQ(ZX_ERR_INVALID_ARGS, vcpu->WriteState(unaligned), "unaligned start\n");
  unaligned.ranges[0] = {kDataGpa, kPageSize + 1, ZX_VCPU_MEMORY_ACCESS_WRITE, 0};
  EXPECT_EQ(ZX_ERR_INVALID_ARGS, vcpu->WriteState(unaligned), "non-page-multiple length\n");
  unaligned.ranges[0] = {kGuestRamSize - kPageSize, 2 * kPageSize,
                         ZX_VCPU_MEMORY_ACCESS_WRITE, 0};
  EXPECT_EQ(ZX_ERR_INVALID_ARGS, vcpu->WriteState(unaligned), "range crossing GPA-space end\n");
  unaligned.ranges[0] = {kDataGpa, kPageSize, 0, 0};
  EXPECT_EQ(ZX_ERR_INVALID_ARGS, vcpu->WriteState(unaligned), "empty access mask\n");
  unaligned.ranges[0] = {kDataGpa, kPageSize, uint32_t{1} << 31, 0};
  EXPECT_EQ(ZX_ERR_INVALID_ARGS, vcpu->WriteState(unaligned), "unknown access bit\n");
  auto unsupported_read = MakeMemoryAccessControl(ZX_VCPU_MEMORY_ACCESS_ARM);
  unsupported_read.range_count = 1;
  unsupported_read.ranges[0] = {
      kDataGpa, kPageSize, ZX_VCPU_MEMORY_ACCESS_READ, 0};
  EXPECT_EQ(ZX_ERR_NOT_SUPPORTED, vcpu->WriteState(unsupported_read),
            "EPT cannot independently stop reads while preserving writes\n");

  auto arm = MakeMemoryAccessControl(ZX_VCPU_MEMORY_ACCESS_ARM);
  arm.range_count = 3;
  // A genuine two-page range plus a coincident subrange. The execute range
  // proves both independently supported permissions are accepted in one
  // atomic replacement.
  arm.ranges[0] = {kDataGpa, 2 * kPageSize, ZX_VCPU_MEMORY_ACCESS_WRITE, 0};
  arm.ranges[1] = {kDataGpa, kPageSize,
                   ZX_VCPU_MEMORY_ACCESS_WRITE | ZX_VCPU_MEMORY_ACCESS_EXECUTE, 0};
  arm.ranges[2] = {kCodeGpa, kPageSize, ZX_VCPU_MEMORY_ACCESS_EXECUTE, 0};
  ASSERT_EQ(ZX_OK, vcpu->WriteState(arm), "arm overlapping cross-page ranges\n");

  zx_vcpu_memory_access_control_t armed = {};
  ASSERT_EQ(ZX_OK, vcpu->ReadState(armed), "read armed range set\n");
  EXPECT_EQ(ZX_VCPU_MEMORY_ACCESS_ARM, armed.active_flags, "armed\n");
  EXPECT_EQ(3u, armed.range_count, "all ranges retained\n");
  EXPECT_EQ(2 * kPageSize, armed.ranges[0].length, "cross-page length retained\n");
  EXPECT_EQ(ZX_VCPU_MEMORY_ACCESS_WRITE | ZX_VCPU_MEMORY_ACCESS_EXECUTE,
            armed.ranges[1].access | armed.ranges[2].access,
            "write/execute access masks retained\n");

  EXPECT_EQ(ZX_ERR_NOT_SUPPORTED, vcpu->WriteState(unsupported_read),
            "unsupported replacement is rejected atomically\n");
  zx_vcpu_memory_access_control_t after_unsupported = {};
  ASSERT_EQ(ZX_OK, vcpu->ReadState(after_unsupported),
            "read after unsupported replacement\n");
  EXPECT_EQ(ZX_VCPU_MEMORY_ACCESS_ARM, after_unsupported.active_flags,
            "unsupported replacement preserves old EPT control\n");
  EXPECT_EQ(3u, after_unsupported.range_count,
            "unsupported replacement preserves old ranges\n");

  auto malformed_cancel = MakeMemoryAccessControl(0);
  malformed_cancel.pending_flags = 1;
  EXPECT_EQ(ZX_ERR_INVALID_ARGS, vcpu->WriteState(malformed_cancel),
            "output field makes replacement malformed\n");
  zx_vcpu_memory_access_control_t still_armed = {};
  ASSERT_EQ(ZX_OK, vcpu->ReadState(still_armed), "read after rejected replacement\n");
  EXPECT_EQ(ZX_VCPU_MEMORY_ACCESS_ARM, still_armed.active_flags,
            "rejected replacement preserves old EPT control\n");
  EXPECT_EQ(3u, still_armed.range_count, "rejected replacement preserves ranges\n");

  ASSERT_EQ(ZX_OK, vcpu->WriteState(MakeMemoryAccessControl(0)), "disarm\n");
  arch_mmu_flags_t restored_flags = 0;
  ASSERT_EQ(ZX_OK,
            lg->guest->guest().PhysicalAspace().arch_aspace().Query(kDataGpa, nullptr,
                                                                   &restored_flags),
            "query restored EPT flags\n");
  EXPECT_EQ(kMmuFlags, restored_flags, "disarm restores exact effective permissions\n");
#else
  printf("Not x86_64; unsupported architecture fails closed through the dispatcher.\n");
#endif

  END_TEST;
}

// A real nested EPT write violation establishes the public stop semantics:
// the RMW instruction has not executed, exact rearm re-stops it, ack-only
// restores permissions, and the unchanged instruction then increments memory
// exactly once before reaching the ordinary I/O exit.
bool vcpu_memory_access_write_is_pre_access_and_ack_retries_once() {
  BEGIN_TEST;

#ifdef __x86_64__
  fbl::RefPtr<VmObjectPaged> ram;
  ASSERT_EQ(ZX_OK, VmObjectPaged::Create(PMM_ALLOC_FLAG_ANY, 0u, kGuestRamSize, &ram), "ram\n");
  ASSERT_EQ(ZX_OK, WriteIdentityTables(ram), "tables\n");
  // inc byte ptr [0x4000]; mov al,0x7c; out 0x10,al; hlt
  const uint8_t code[] = {
      0xFE, 0x04, 0x25, 0x00, 0x40, 0x00, 0x00,
      0xB0, 0x7C, 0xE6, 0x10, 0xF4,
  };
  const uint8_t baseline = 0x10;
  ASSERT_EQ(ZX_OK, ram->Write(code, kCodeGpa, sizeof(code)), "code\n");
  ASSERT_EQ(ZX_OK, ram->Write(&baseline, kDataGpa, sizeof(baseline)), "baseline\n");
  ASSERT_EQ(ZX_OK, ram->CommitRange(0, kGuestRamSize), "commit\n");

  auto lg = CreateLiveGuestDispatcher(ram, kCodeGpa);
  if (lg.is_error() && lg.status_value() == ZX_ERR_NOT_SUPPORTED) {
    printf("VMX/EPT unavailable; positive nested memory-access run cannot execute here.\n");
    return true;
  }
  ASSERT_EQ(ZX_OK, lg.status_value(), "create nested live guest\n");
  VcpuDispatcher* vcpu = lg->vcpu.get();

  auto arm = MakeMemoryAccessControl(ZX_VCPU_MEMORY_ACCESS_ARM);
  arm.range_count = 2;
  arm.ranges[0] = {kDataGpa, kPageSize, ZX_VCPU_MEMORY_ACCESS_WRITE, 0};
  arm.ranges[1] = {kDataGpa, 2 * kPageSize,
                   ZX_VCPU_MEMORY_ACCESS_WRITE | ZX_VCPU_MEMORY_ACCESS_EXECUTE, 0};
  ASSERT_EQ(ZX_OK, vcpu->WriteState(arm), "arm write stop\n");

  zx_port_packet_t first = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(first), "run to first EPT write stop\n");
  ASSERT_EQ(static_cast<uint8_t>(ZX_PKT_TYPE_GUEST_MEMORY_ACCESS),
            static_cast<uint8_t>(first.type), "typed memory-access packet\n");
  ASSERT_NE(0u, first.guest_memory_access.sequence, "nonzero sequence\n");
  EXPECT_EQ(kDataGpa, first.guest_memory_access.guest_paddr, "exact triggering GPA\n");
  EXPECT_EQ(kCodeGpa, first.guest_memory_access.rip, "RIP remains on RMW instruction\n");

  uint8_t observed = 0;
  ASSERT_EQ(ZX_OK, ram->Read(&observed, kDataGpa, sizeof(observed)), "read before ack\n");
  EXPECT_EQ(baseline, observed, "pre-access stop must not execute the increment\n");

  zx_vcpu_memory_access_control_t pending = {};
  ASSERT_EQ(ZX_OK, vcpu->ReadState(pending), "read pending classification\n");
  EXPECT_EQ(0u, pending.active_flags, "one-shot is inactive while EPT restriction stays pending\n");
  EXPECT_EQ(first.guest_memory_access.sequence, pending.pending_sequence, "same sequence\n");
  EXPECT_EQ(kDataGpa, pending.pending_guest_paddr, "pending GPA\n");
  EXPECT_EQ(kCodeGpa, pending.pending_rip, "pending RIP\n");
  EXPECT_NE(0u, pending.pending_access & ZX_VCPU_MEMORY_ACCESS_WRITE, "write classified\n");
  EXPECT_EQ(0x3u, pending.pending_range_mask, "both coincident range indices reported\n");
  EXPECT_EQ(pending.pending_qualification & ZX_VCPU_MEMORY_ACCESS_ALL,
            pending.pending_access, "raw qualification agrees with typed access\n");

  zx_port_packet_t blocked = {};
  EXPECT_EQ(ZX_ERR_BAD_STATE, vcpu->Enter(blocked), "pending stop blocks every re-entry\n");
  auto stale = arm;
  stale.ack_sequence = pending.pending_sequence + 1;
  EXPECT_EQ(ZX_ERR_BAD_STATE, vcpu->WriteState(stale), "stale acknowledgement rejected\n");

  // Exact acknowledgement and identical replacement is atomic. Because the
  // faulting access remains covered, it must stop again rather than briefly
  // slipping through between the old and new EPT permission sets.
  auto rearm = arm;
  rearm.ack_sequence = pending.pending_sequence;
  ASSERT_EQ(ZX_OK, vcpu->WriteState(rearm), "exact ack plus identical rearm\n");
  zx_port_packet_t second = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(second), "same instruction re-stops\n");
  ASSERT_EQ(static_cast<uint8_t>(ZX_PKT_TYPE_GUEST_MEMORY_ACCESS),
            static_cast<uint8_t>(second.type), "typed second stop\n");
  EXPECT_NE(first.guest_memory_access.sequence, second.guest_memory_access.sequence,
            "rearm creates a new exact sequence\n");
  ASSERT_EQ(ZX_OK, ram->Read(&observed, kDataGpa, sizeof(observed)), "read after re-stop\n");
  EXPECT_EQ(baseline, observed, "rearm did not let the access execute\n");

  ASSERT_EQ(ZX_OK,
            vcpu->WriteState(MakeMemoryAccessControl(
                0, second.guest_memory_access.sequence)),
            "ack-only restores saved permissions\n");
  zx_port_packet_t completed = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(completed), "retry original instruction\n");
  ASSERT_EQ(static_cast<uint8_t>(ZX_PKT_TYPE_GUEST_IO),
            static_cast<uint8_t>(completed.type), "guest reaches ordinary marker\n");
  EXPECT_EQ(0x7Cu, static_cast<uint32_t>(completed.guest_io.data[0]), "marker value\n");
  ASSERT_EQ(ZX_OK, ram->Read(&observed, kDataGpa, sizeof(observed)), "read after resume\n");
  EXPECT_EQ(static_cast<uint8_t>(baseline + 1), observed,
            "unchanged RMW instruction executes exactly once after ack\n");
#else
  printf("Not x86_64; unsupported architecture fails closed through the dispatcher.\n");
#endif

  END_TEST;
}

// A single ZX_VCPU_STATE_ENLIGHTENMENT write is enough for a VMM to arm the
// whole Hyper-V surface: the identity, a VMM-supplied feature leaf, and the two
// delegated exits (ZX_PKT_TYPE_GUEST_MSR / ZX_PKT_TYPE_GUEST_HYPERCALL) that
// were previously unreachable from userspace. Non-vacuous throughout: each value
// the guest reports can only have come from this configuration — 'M' rather than
// the default 'K', a feature leaf the kernel has no way to invent, and two
// values the test supplies between entries.
bool vcpu_enlightenment_topic_arms_delegated_exits() {
  BEGIN_TEST;

#ifdef __x86_64__
  constexpr uint32_t kFeatureEax = (1u << 1) | (1u << 2) | (1u << 3) | (1u << 5) | (1u << 6);
  constexpr uint32_t kFeatureEbx = (1u << 4) | (1u << 5);
  constexpr uint32_t kSynthMsr = 0x40000024;
  constexpr uint8_t kVmmMsrValue = 0x3C;
  constexpr uint64_t kInput = 0x1234;
  constexpr uint64_t kArg0 = 0x5678;
  constexpr uint64_t kArg1 = 0xABCD;
  constexpr uint8_t kVmmResult = 0x6D;

  fbl::RefPtr<VmObjectPaged> ram;
  ASSERT_EQ(ZX_OK, VmObjectPaged::Create(PMM_ALLOC_FLAG_ANY, 0u, kGuestRamSize, &ram), "ram\n");
  ASSERT_EQ(ZX_OK, WriteIdentityTables(ram), "tables\n");
  const uint8_t code[] = {
      0xB8, 0x00, 0x00, 0x00, 0x40,        // mov eax, 0x40000000 (vendor leaf)
      0x0F, 0xA2,                          // cpuid
      0x89, 0xD8,                          // mov eax, ebx
      0xE6, 0x10,                          // out 0x10, al   -> identity byte
      0xB8, 0x03, 0x00, 0x00, 0x40,        // mov eax, 0x40000003 (feature leaf)
      0x0F, 0xA2,                          // cpuid
      0xBA, 0x10, 0x00, 0x00, 0x00,        // mov edx, 0x10
      0xEF,                                // out dx, eax    -> feature leaf eax
      0xB9, 0x24, 0x00, 0x00, 0x40,        // mov ecx, 0x40000024
      0x0F, 0x32,                          // rdmsr          -> delegated MSR exit
      0xE6, 0x11,                          // out 0x11, al   -> what the VMM supplied
      0xB9, 0x34, 0x12, 0x00, 0x00,        // mov ecx, 0x1234
      0xBA, 0x78, 0x56, 0x00, 0x00,        // mov edx, 0x5678
      0x41, 0xB8, 0xCD, 0xAB, 0x00, 0x00,  // mov r8d, 0xabcd
      0x0F, 0x01, 0xC1,                    // vmcall         -> delegated hypercall exit
      0xE6, 0x11,                          // out 0x11, al   -> the VMM's result
      0xF4,                                // hlt
  };
  ASSERT_EQ(ZX_OK, ram->Write(code, kCodeGpa, sizeof(code)), "code\n");
  ASSERT_EQ(ZX_OK, ram->CommitRange(0, kGuestRamSize), "commit\n");

  auto lg = CreateLiveGuestDispatcher(ram, kCodeGpa);
  if (lg.is_error() && lg.status_value() == ZX_ERR_NOT_SUPPORTED) {
    printf("VMX not supported here; skipping enlightenment-topic arming test.\n");
    return true;
  }
  ASSERT_EQ(ZX_OK, lg.status_value(), "create live guest (dispatchers)\n");
  VcpuDispatcher* vcpu = lg->vcpu.get();

  // This is the whole thing a VMM has to do: one write of the topic.
  zx_vcpu_enlightenment_t config =
      MakeEnlightenment(ZX_VCPU_ENLIGHTENMENT_HYPERV_IDENTITY | ZX_VCPU_ENLIGHTENMENT_DELEGATE_MSRS |
                        ZX_VCPU_ENLIGHTENMENT_DELEGATE_HYPERCALLS);
  config.cpuid_count = 1;
  config.cpuid[0] = {0x40000003, kFeatureEax, kFeatureEbx, 0, 0};
  ASSERT_EQ(ZX_OK, vcpu->WriteState(config), "write ZX_VCPU_STATE_ENLIGHTENMENT\n");

  // 1: the guest takes its Hyper-V path.
  zx_port_packet_t p = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(p), "enter to identity report\n");
  ASSERT_EQ(static_cast<uint8_t>(ZX_PKT_TYPE_GUEST_IO), static_cast<uint8_t>(p.type), "io\n");
  EXPECT_EQ(0x4Du, static_cast<uint32_t>(p.guest_io.data[0]),
            "guest must see 'M' (Microsoft Hv), not 'K' (KVM)\n");
  const uint8_t identity_byte = p.guest_io.data[0];

  // 2: the feature leaf the VMM supplied through the same write.
  zx_port_packet_t leaf = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(leaf), "enter to feature-leaf report\n");
  ASSERT_EQ(static_cast<uint8_t>(ZX_PKT_TYPE_GUEST_IO), static_cast<uint8_t>(leaf.type), "io\n");
  EXPECT_EQ(kFeatureEax, leaf.guest_io.u32, "feature leaf eax must come from the VMM\n");

  // 3: the delegated synthetic-MSR read, completed by the "VMM".
  zx_port_packet_t msr = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(msr), "enter to delegated MSR read\n");
  ASSERT_EQ(static_cast<uint8_t>(ZX_PKT_TYPE_GUEST_MSR), static_cast<uint8_t>(msr.type),
            "delegated MSR exit must be reachable once the topic is written\n");
  EXPECT_EQ(static_cast<uint64_t>(kSynthMsr), msr.guest_msr.msr, "MSR index\n");
  EXPECT_FALSE(msr.guest_msr.is_write, "expected a read\n");
  zx_vcpu_state_t s = {};
  ASSERT_EQ(ZX_OK, vcpu->ReadState(s), "ReadState\n");
  s.rax = (s.rax & ~0xffull) | kVmmMsrValue;
  ASSERT_EQ(ZX_OK, vcpu->WriteState(s), "WriteState (complete MSR read)\n");

  zx_port_packet_t msr_io = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(msr_io), "enter to MSR report\n");
  ASSERT_EQ(static_cast<uint8_t>(ZX_PKT_TYPE_GUEST_IO), static_cast<uint8_t>(msr_io.type), "io\n");
  EXPECT_EQ(static_cast<uint32_t>(kVmmMsrValue), static_cast<uint32_t>(msr_io.guest_io.data[0]),
            "guest must observe the VMM-supplied MSR value\n");

  // 4: the delegated hypercall, likewise.
  zx_port_packet_t hc = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(hc), "enter to delegated hypercall\n");
  ASSERT_EQ(static_cast<uint8_t>(ZX_PKT_TYPE_GUEST_HYPERCALL), static_cast<uint8_t>(hc.type),
            "delegated hypercall exit must be reachable once the topic is written\n");
  EXPECT_EQ(kInput, hc.guest_hypercall.input, "hypercall input (rcx)\n");
  EXPECT_EQ(kArg0, hc.guest_hypercall.arg0, "hypercall arg0 (rdx)\n");
  EXPECT_EQ(kArg1, hc.guest_hypercall.arg1, "hypercall arg1 (r8)\n");
  ASSERT_EQ(ZX_OK, vcpu->ReadState(s), "ReadState\n");
  s.rax = (s.rax & ~0xffull) | kVmmResult;
  ASSERT_EQ(ZX_OK, vcpu->WriteState(s), "WriteState (hypercall result)\n");

  zx_port_packet_t hc_io = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(hc_io), "enter to hypercall report\n");
  ASSERT_EQ(static_cast<uint8_t>(ZX_PKT_TYPE_GUEST_IO), static_cast<uint8_t>(hc_io.type), "io\n");
  EXPECT_EQ(static_cast<uint32_t>(kVmmResult), static_cast<uint32_t>(hc_io.guest_io.data[0]),
            "guest must observe the VMM's hypercall result\n");

  printf(
      "enlightenment-topic OK: one ZX_VCPU_STATE_ENLIGHTENMENT write armed identity='%c', "
      "leaf 0x40000003 eax=%#x, delegated MSR value=%#x, delegated hypercall result=%#x\n",
      identity_byte, leaf.guest_io.u32, msr_io.guest_io.data[0], hc_io.guest_io.data[0]);
#else
  printf("Not x86_64; skipping.\n");
#endif  // __x86_64__

  END_TEST;
}

// The topic round-trips: a fresh VCPU reports the default (nothing delegated, no
// supplied leaves), a written configuration reads back exactly, writing that
// same structure back is accepted, and a write is a wholesale replacement rather
// than an accumulation — so a VMM can save and restore this alongside
// ZX_VCPU_STATE_FULL.
bool vcpu_enlightenment_topic_round_trips() {
  BEGIN_TEST;

#ifdef __x86_64__
  fbl::RefPtr<VmObjectPaged> ram;
  ASSERT_EQ(ZX_OK, VmObjectPaged::Create(PMM_ALLOC_FLAG_ANY, 0u, kGuestRamSize, &ram), "ram\n");
  ASSERT_EQ(ZX_OK, WriteIdentityTables(ram), "tables\n");
  const uint8_t code[] = {0xF4};  // hlt; this test never needs to run the guest.
  ASSERT_EQ(ZX_OK, ram->Write(code, kCodeGpa, sizeof(code)), "code\n");
  ASSERT_EQ(ZX_OK, ram->CommitRange(0, kGuestRamSize), "commit\n");

  auto lg = CreateLiveGuestDispatcher(ram, kCodeGpa);
  if (lg.is_error() && lg.status_value() == ZX_ERR_NOT_SUPPORTED) {
    printf("VMX not supported here; skipping enlightenment-topic round-trip test.\n");
    return true;
  }
  ASSERT_EQ(ZX_OK, lg.status_value(), "create live guest (dispatchers)\n");
  VcpuDispatcher* vcpu = lg->vcpu.get();

  // The default: a VCPU nobody configured keeps the kernel's own surface.
  zx_vcpu_enlightenment_t initial = {};
  ASSERT_EQ(ZX_OK, vcpu->ReadState(initial), "read default enlightenment\n");
  EXPECT_EQ(ZX_VCPU_ENLIGHTENMENT_MAGIC, initial.magic, "magic\n");
  EXPECT_EQ(ZX_VCPU_ENLIGHTENMENT_VERSION, initial.version, "version\n");
  EXPECT_EQ(static_cast<uint32_t>(sizeof(zx_vcpu_enlightenment_t)), initial.size, "size\n");
  EXPECT_EQ(0u, initial.flags, "a fresh VCPU must delegate nothing\n");
  EXPECT_EQ(ZX_VCPU_HYPERV_CPUID_MAX, initial.cpuid_count, "all leaves are reported\n");
  for (uint32_t i = 0; i < ZX_VCPU_HYPERV_CPUID_MAX; i++) {
    EXPECT_EQ(ZX_VCPU_HYPERV_CPUID_LEAF_FIRST + i, initial.cpuid[i].leaf, "leaf number\n");
    EXPECT_EQ(0u, initial.cpuid[i].eax, "leaf eax\n");
    EXPECT_EQ(0u, initial.cpuid[i].ebx, "leaf ebx\n");
    EXPECT_EQ(0u, initial.cpuid[i].ecx, "leaf ecx\n");
    EXPECT_EQ(0u, initial.cpuid[i].edx, "leaf edx\n");
  }

  zx_vcpu_enlightenment_t written =
      MakeEnlightenment(ZX_VCPU_ENLIGHTENMENT_HYPERV_IDENTITY | ZX_VCPU_ENLIGHTENMENT_DELEGATE_MSRS |
                        ZX_VCPU_ENLIGHTENMENT_DELEGATE_HYPERCALLS);
  written.cpuid_count = ZX_VCPU_HYPERV_CPUID_MAX;
  written.cpuid[0] = {0x40000002, 0x1bbc, 0x0004, 0, 0};
  written.cpuid[1] = {0x40000003, 0x0000006e, 0x00000030, 0, 0};
  written.cpuid[2] = {0x40000004, 0x00000200, 0xffffffff, 0, 0};
  written.cpuid[3] = {0x40000005, 4, 4, 0, 0};
  ASSERT_EQ(ZX_OK, vcpu->WriteState(written), "write full configuration\n");

  zx_vcpu_enlightenment_t read_back = {};
  ASSERT_EQ(ZX_OK, vcpu->ReadState(read_back), "read back\n");
  EXPECT_TRUE(SameEnlightenment(written, read_back),
              "a written configuration must read back unchanged\n");

  // What was read is itself a valid write, which is what makes save/restore work.
  ASSERT_EQ(ZX_OK, vcpu->WriteState(read_back), "write back what was read\n");
  zx_vcpu_enlightenment_t again = {};
  ASSERT_EQ(ZX_OK, vcpu->ReadState(again), "read after write-back\n");
  EXPECT_TRUE(SameEnlightenment(written, again), "write-back must be idempotent\n");

  // A write replaces: clearing the flags and naming no leaves returns the VCPU
  // to the default, rather than leaving the old leaves behind.
  zx_vcpu_enlightenment_t cleared = MakeEnlightenment(0);
  ASSERT_EQ(ZX_OK, vcpu->WriteState(cleared), "write empty configuration\n");
  zx_vcpu_enlightenment_t after_clear = {};
  ASSERT_EQ(ZX_OK, vcpu->ReadState(after_clear), "read after clear\n");
  EXPECT_TRUE(SameEnlightenment(initial, after_clear),
              "an empty write must restore the default configuration\n");

  printf(
      "enlightenment-topic OK: default reads as flags=%#x/%u leaves; full configuration "
      "round-tripped and an empty write restored the default\n",
      initial.flags, initial.cpuid_count);
#else
  printf("Not x86_64; skipping.\n");
#endif  // __x86_64__

  END_TEST;
}

// Input validation: the kernel refuses a structure it does not understand, and a
// CPUID leaf outside the block a VMM may supply, rather than trusting the
// caller. And a refused write changes nothing — the configuration set before the
// bad writes is still the one the guest sees afterwards, so rejection is not
// merely "returned an error".
bool vcpu_enlightenment_topic_rejects_invalid() {
  BEGIN_TEST;

#ifdef __x86_64__
  fbl::RefPtr<VmObjectPaged> ram;
  ASSERT_EQ(ZX_OK, VmObjectPaged::Create(PMM_ALLOC_FLAG_ANY, 0u, kGuestRamSize, &ram), "ram\n");
  ASSERT_EQ(ZX_OK, WriteIdentityTables(ram), "tables\n");
  //   mov eax, 0x40000000 ; cpuid ; mov eax, ebx ; out 0x10, al ; hlt
  const uint8_t code[] = {0xB8, 0x00, 0x00, 0x00, 0x40, 0x0F, 0xA2, 0x89, 0xD8, 0xE6, 0x10, 0xF4};
  ASSERT_EQ(ZX_OK, ram->Write(code, kCodeGpa, sizeof(code)), "code\n");
  ASSERT_EQ(ZX_OK, ram->CommitRange(0, kGuestRamSize), "commit\n");

  auto lg = CreateLiveGuestDispatcher(ram, kCodeGpa);
  if (lg.is_error() && lg.status_value() == ZX_ERR_NOT_SUPPORTED) {
    printf("VMX not supported here; skipping enlightenment-topic rejection test.\n");
    return true;
  }
  ASSERT_EQ(ZX_OK, lg.status_value(), "create live guest (dispatchers)\n");
  VcpuDispatcher* vcpu = lg->vcpu.get();

  // A configuration the VCPU must still be in after every rejection below.
  //
  // Identity is paired with MSR delegation because identity alone is itself a
  // rejected configuration: it tells Windows "I am Hv#1" and then #GPs the
  // first synthetic-MSR write it makes. It is asserted on as such further down.
  zx_vcpu_enlightenment_t good = MakeEnlightenment(ZX_VCPU_ENLIGHTENMENT_HYPERV_IDENTITY |
                                                   ZX_VCPU_ENLIGHTENMENT_DELEGATE_MSRS);
  good.cpuid_count = 1;
  good.cpuid[0] = {0x40000004, 0xAABBCCDD, 0x11223344, 0, 0};
  ASSERT_EQ(ZX_OK, vcpu->WriteState(good), "write baseline configuration\n");

  // A stale or foreign producer: the header is checked on entry.
  zx_vcpu_enlightenment_t bad = MakeEnlightenment(0);
  bad.magic = ZX_VCPU_ENLIGHTENMENT_MAGIC + 1;
  EXPECT_EQ(ZX_ERR_INVALID_ARGS, vcpu->WriteState(bad), "wrong magic must be refused\n");
  bad = MakeEnlightenment(0);
  bad.version = ZX_VCPU_ENLIGHTENMENT_VERSION + 1;
  EXPECT_EQ(ZX_ERR_INVALID_ARGS, vcpu->WriteState(bad), "wrong version must be refused\n");
  bad = MakeEnlightenment(0);
  bad.size = sizeof(zx_vcpu_enlightenment_t) - 4;
  EXPECT_EQ(ZX_ERR_INVALID_ARGS, vcpu->WriteState(bad), "wrong size must be refused\n");

  // A Hyper-V identity without MSR delegation is refused. An `Unhandled guest
  // RDMSR 0x40000021` line identifies a VCPU in exactly this state, since the kernel
  // cannot print it in any other. The kernel implements no synthetic register,
  // so there is nobody to answer them if the VMM has not claimed them.
  bad = MakeEnlightenment(ZX_VCPU_ENLIGHTENMENT_HYPERV_IDENTITY);
  EXPECT_EQ(ZX_ERR_INVALID_ARGS, vcpu->WriteState(bad),
            "a Hyper-V identity without MSR delegation must be refused, not merely documented\n");
  // ...and the two together are accepted, so the rule above is a pairing
  // requirement and not a blanket ban on the identity flag.
  zx_vcpu_enlightenment_t paired = MakeEnlightenment(ZX_VCPU_ENLIGHTENMENT_HYPERV_IDENTITY |
                                                     ZX_VCPU_ENLIGHTENMENT_DELEGATE_MSRS);
  EXPECT_EQ(ZX_OK, vcpu->WriteState(paired),
            "identity paired with MSR delegation must be accepted\n");
  ASSERT_EQ(ZX_OK, vcpu->WriteState(good), "restore the baseline\n");

  // A capability this kernel does not implement, and a reserved field that must
  // stay zero so it can be given a meaning later.
  bad = MakeEnlightenment(ZX_VCPU_ENLIGHTENMENT_DELEGATE_HYPERCALLS | (1u << 3));
  EXPECT_EQ(ZX_ERR_INVALID_ARGS, vcpu->WriteState(bad), "unknown flag must be refused\n");
  bad = MakeEnlightenment(0);
  bad.reserved = 1;
  EXPECT_EQ(ZX_ERR_INVALID_ARGS, vcpu->WriteState(bad), "non-zero reserved must be refused\n");

  // More leaves than the structure holds.
  bad = MakeEnlightenment(0);
  bad.cpuid_count = ZX_VCPU_HYPERV_CPUID_MAX + 1;
  EXPECT_EQ(ZX_ERR_OUT_OF_RANGE, vcpu->WriteState(bad), "over-long leaf list must be refused\n");

  // Leaves outside the block a VMM may supply. 0x40000001 is the kernel's own
  // identity leaf, 0x40000006 is past the advertised maximum, and 0x00000001 is
  // not synthetic at all — none of them has a slot the exit handler could use.
  const uint32_t bad_leaves[] = {0x00000001, 0x40000000, 0x40000001, 0x40000006, 0xffffffff};
  for (uint32_t leaf : bad_leaves) {
    bad = MakeEnlightenment(ZX_VCPU_ENLIGHTENMENT_HYPERV_IDENTITY);
    bad.cpuid_count = 1;
    bad.cpuid[0] = {leaf, 0xDEADBEEF, 0, 0, 0};
    EXPECT_EQ(ZX_ERR_OUT_OF_RANGE, vcpu->WriteState(bad),
              "a CPUID leaf outside the synthetic range must be refused\n");
  }

  // Nothing above was applied.
  zx_vcpu_enlightenment_t after = {};
  ASSERT_EQ(ZX_OK, vcpu->ReadState(after), "read after rejections\n");
  EXPECT_EQ(ZX_VCPU_ENLIGHTENMENT_HYPERV_IDENTITY | ZX_VCPU_ENLIGHTENMENT_DELEGATE_MSRS,
            after.flags,
            "a refused write must not change the flags -- the baseline pairs identity with MSR "
            "delegation because identity alone is itself refused now\n");
  EXPECT_EQ(0xAABBCCDDu, after.cpuid[2].eax, "a refused write must not change leaf 0x40000004\n");
  EXPECT_EQ(0x11223344u, after.cpuid[2].ebx, "a refused write must not change leaf 0x40000004\n");
  for (uint32_t i = 0; i < ZX_VCPU_HYPERV_CPUID_MAX; i++) {
    if (i != 2) {
      EXPECT_EQ(0u, after.cpuid[i].eax, "a refused write must not populate another leaf\n");
    }
  }

  // And the guest still sees exactly the configuration that was accepted.
  zx_port_packet_t p = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(p), "enter\n");
  ASSERT_EQ(static_cast<uint8_t>(ZX_PKT_TYPE_GUEST_IO), static_cast<uint8_t>(p.type), "io\n");
  EXPECT_EQ(0x4Du, static_cast<uint32_t>(p.guest_io.data[0]),
            "the baseline configuration must have survived the rejected writes\n");

  printf(
      "enlightenment-topic OK: rejected bad magic/version/size, unknown flag, non-zero reserved, "
      "over-long leaf list and 5 out-of-range CPUID leaves; VCPU unchanged (flags=%#x, guest saw "
      "'%c')\n",
      after.flags, p.guest_io.data[0]);
#else
  printf("Not x86_64; skipping.\n");
#endif  // __x86_64__

  END_TEST;
}

#ifdef __x86_64__
// ---------------------------------------------------------------------------
// ZX_VCPU_STATE_PENDING_EVENT: injecting an exception with its real payload.
//
// `zx_vcpu_interrupt()` carries a vector and nothing else, so an exception that
// architecturally has an error code (#DF, #TS, #NP, #SS, #GP, #PF, #AC) reaches
// the guest with a zero one, and #PF reaches it with a stale CR2. These tests
// drive the topic through VcpuDispatcher — the object a handle resolves to, with
// only the handle lookup and the user copy above it — and prove the guest's own
// handler reads back the error code (and, for #PF, the CR2) the VMM supplied. A
// test that merely observed "an exception arrived" would pass with the error
// code still zero, which is the entire bug.
// ---------------------------------------------------------------------------

// Guest-physical layout shared by the pending-event tests.
constexpr uint64_t kEvtGdtGpa = 0x6000;
constexpr uint64_t kEvtIdtGpa = 0x6800;
constexpr uint64_t kEvtHandlerGpa = 0x8000;
constexpr uint64_t kEvtStackTop = 0x9000;

// The structure a VMM fills in for ZX_VCPU_STATE_PENDING_EVENT, with the
// self-describing header already correct.
zx_vcpu_pending_event_t MakePendingEvent(uint32_t type, uint32_t vector) {
  zx_vcpu_pending_event_t e = {};
  e.magic = ZX_VCPU_PENDING_EVENT_MAGIC;
  e.version = ZX_VCPU_PENDING_EVENT_VERSION;
  e.size = sizeof(e);
  e.type = type;
  e.vector = vector;
  return e;
}

// A 64-bit interrupt gate for `vector`, selector 0x08, pointing at `handler`.
void WriteIdtGate(uint8_t (&gate)[16], uint64_t handler) {
  memset(gate, 0, sizeof(gate));
  gate[0] = static_cast<uint8_t>(handler & 0xFF);
  gate[1] = static_cast<uint8_t>((handler >> 8) & 0xFF);
  gate[2] = 0x08;  // selector
  gate[5] = 0x8E;  // present, DPL 0, 64-bit interrupt gate
}

// Point a dispatcher-owned VCPU at its descriptor tables and a stack, through
// the public ZX_VCPU_STATE_FULL path (the raw-Vcpu tests above use
// SaveArchState/RestoreArchState directly; these go the way a VMM does).
zx_status_t SetGuestTables(VcpuDispatcher* vcpu, uint64_t gdt, uint64_t idt, uint64_t rsp) {
  const size_t len = SerializedVcpuStateSize();
  fbl::AllocChecker ac;
  ktl::unique_ptr<uint8_t[]> buf(new (&ac) uint8_t[len]);
  if (!ac.check()) {
    return ZX_ERR_NO_MEMORY;
  }
  size_t actual = 0;
  if (zx_status_t status = vcpu->ReadStateFull(buf.get(), len, &actual); status != ZX_OK) {
    return status;
  }
  VcpuArchState state = {};
  if (auto result = DeserializeVcpuState(state, buf.get(), actual); result.is_error()) {
    return result.status_value();
  }
  state.gdtr_base = gdt;
  state.gdtr_limit = 0x0F;
  state.idtr_base = idt;
  state.idtr_limit = 0xFFF;
  state.regs.rsp = rsp;
  if (auto result = SerializeVcpuState(state, buf.get(), len); result.is_error()) {
    return result.status_value();
  }
  return vcpu->WriteStateFull(buf.get(), len);
}
#endif  // __x86_64__

// The headline case: a VMM that emulated an instruction and decided the guest
// earned a #GP injects it *with the error code it computed*, and the guest's own
// #GP handler pops that error code off its exception frame and reports it back.
// Two bytes of it are reported, so a delivered-but-zero error code (the old
// behaviour) fails loudly rather than looking like a pass.
bool vcpu_pending_event_gp_error_code_reaches_handler() {
  BEGIN_TEST;

#ifdef __x86_64__
  constexpr uint32_t kErrorCode = 0xBEEF;

  fbl::RefPtr<VmObjectPaged> ram;
  ASSERT_EQ(ZX_OK, VmObjectPaged::Create(PMM_ALLOC_FLAG_ANY, 0u, kGuestRamSize, &ram), "ram\n");
  ASSERT_EQ(ZX_OK, WriteIdentityTables(ram), "tables\n");

  // Guest: announce readiness, then run on. If the injection never arrives the
  // guest reports 0x77 on port 0x11 — a clean failure rather than a hang.
  //   B0 00    mov al, 0
  //   E6 10    out 0x10, al   ; exit #1 (VMM injects between entries)
  //   B0 77    mov al, 0x77
  //   E6 11    out 0x11, al   ; only reached if no exception was delivered
  //   F4       hlt
  const uint8_t code[] = {0xB0, 0x00, 0xE6, 0x10, 0xB0, 0x77, 0xE6, 0x11, 0xF4};
  ASSERT_EQ(ZX_OK, ram->Write(code, kCodeGpa, sizeof(code)), "code\n");

  // GDT[1] = flat 64-bit code segment (selector 0x08).
  const uint8_t gdt_code[8] = {0xFF, 0xFF, 0x00, 0x00, 0x00, 0x9B, 0xAF, 0x00};
  ASSERT_EQ(ZX_OK, ram->Write(gdt_code, kEvtGdtGpa + 8, sizeof(gdt_code)), "GDT\n");

  uint8_t gate[16];
  WriteIdtGate(gate, kEvtHandlerGpa);
  ASSERT_EQ(ZX_OK, ram->Write(gate, kEvtIdtGpa + X86_INT_GP_FAULT * 16, sizeof(gate)), "IDT\n");

  // #GP handler. A 64-bit interrupt gate for a vector with an error code pushes
  // it below the return frame, so it is the first thing on the handler's stack.
  //   58          pop rax        ; the error code the VMM supplied
  //   E6 30       out 0x30, al   ; low byte
  //   C1 E8 08    shr eax, 8
  //   E6 31       out 0x31, al   ; second byte
  //   F4          hlt
  const uint8_t handler[] = {0x58, 0xE6, 0x30, 0xC1, 0xE8, 0x08, 0xE6, 0x31, 0xF4};
  ASSERT_EQ(ZX_OK, ram->Write(handler, kEvtHandlerGpa, sizeof(handler)), "handler\n");
  ASSERT_EQ(ZX_OK, ram->CommitRange(0, kGuestRamSize), "commit\n");

  auto lg = CreateLiveGuestDispatcher(ram, kCodeGpa);
  if (lg.is_error() && lg.status_value() == ZX_ERR_NOT_SUPPORTED) {
    printf("VMX not supported here; skipping pending-event #GP test.\n");
    return true;
  }
  ASSERT_EQ(ZX_OK, lg.status_value(), "create live guest (dispatchers)\n");
  VcpuDispatcher* vcpu = lg->vcpu.get();
  ASSERT_EQ(ZX_OK, lg->guest->SetTrap(ZX_GUEST_TRAP_IO, 0x30, 1, nullptr, 0x30), "trap 0x30\n");
  ASSERT_EQ(ZX_OK, lg->guest->SetTrap(ZX_GUEST_TRAP_IO, 0x31, 1, nullptr, 0x31), "trap 0x31\n");
  ASSERT_EQ(ZX_OK, SetGuestTables(vcpu, kEvtGdtGpa, kEvtIdtGpa, kEvtStackTop), "GDTR/IDTR/RSP\n");

  // Nothing is queued on a fresh VCPU.
  zx_vcpu_pending_event_t before = {};
  ASSERT_EQ(ZX_OK, vcpu->ReadState(before), "read pending event\n");
  EXPECT_EQ(ZX_VCPU_EVENT_NONE, before.type, "a fresh VCPU must have nothing queued\n");

  zx_port_packet_t p = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(p), "enter #1\n");
  ASSERT_EQ(0x10u, p.guest_io.port, "expected the readiness exit on 0x10\n");

  // This is the whole thing a VMM has to do.
  zx_vcpu_pending_event_t gp =
      MakePendingEvent(ZX_VCPU_EVENT_HARDWARE_EXCEPTION, X86_INT_GP_FAULT);
  gp.flags = ZX_VCPU_EVENT_ERROR_CODE_VALID;
  gp.error_code = kErrorCode;
  ASSERT_EQ(ZX_OK, vcpu->WriteState(gp), "queue #GP with an error code\n");

  // It reads back as queued, so the topic really is state until entry eats it.
  zx_vcpu_pending_event_t queued = {};
  ASSERT_EQ(ZX_OK, vcpu->ReadState(queued), "read back queued event\n");
  EXPECT_EQ(ZX_VCPU_EVENT_HARDWARE_EXCEPTION, queued.type, "queued type\n");
  EXPECT_EQ(static_cast<uint32_t>(X86_INT_GP_FAULT), queued.vector, "queued vector\n");
  EXPECT_EQ(ZX_VCPU_EVENT_ERROR_CODE_VALID, queued.flags, "queued flags\n");
  EXPECT_EQ(kErrorCode, queued.error_code, "queued error code\n");

  zx_port_packet_t lo = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(lo), "enter #2 (deliver #GP)\n");
  ASSERT_EQ(static_cast<uint8_t>(ZX_PKT_TYPE_GUEST_IO), static_cast<uint8_t>(lo.type), "io\n");
  ASSERT_EQ(0x30u, lo.guest_io.port,
            "the guest's #GP handler must have run (0x11 here means no exception was "
            "delivered at all)\n");
  EXPECT_EQ(kErrorCode & 0xFF, static_cast<uint32_t>(lo.guest_io.data[0]),
            "the handler must read back the error code the VMM supplied, not zero\n");

  zx_port_packet_t hi = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(hi), "enter #3 (handler continues)\n");
  ASSERT_EQ(0x31u, hi.guest_io.port, "second error-code byte\n");
  EXPECT_EQ((kErrorCode >> 8) & 0xFF, static_cast<uint32_t>(hi.guest_io.data[0]),
            "the error code must be delivered in full, not truncated\n");

  // Delivery consumed the queue: this is a one-shot, not a standing property.
  zx_vcpu_pending_event_t after = {};
  ASSERT_EQ(ZX_OK, vcpu->ReadState(after), "read after delivery\n");
  EXPECT_EQ(ZX_VCPU_EVENT_NONE, after.type, "delivery must consume the queued event\n");

  printf("pending-event #GP OK: ZX_VCPU_STATE_PENDING_EVENT queued #GP(error_code=%#x); the "
         "guest's own IDT handler read it back as %#x and the queue is now empty\n",
         kErrorCode,
         static_cast<uint32_t>(hi.guest_io.data[0]) << 8 | lo.guest_io.data[0]);
#else
  printf("Not x86_64; skipping.\n");
#endif  // __x86_64__

  END_TEST;
}

// #PF is the case that needs two things at once: the error code *and* CR2, which
// is not a VMCS field at all (it is swapped around VM entry through VmxState).
// The guest's #PF handler reads both back.
bool vcpu_pending_event_page_fault_delivers_cr2() {
  BEGIN_TEST;

#ifdef __x86_64__
  constexpr uint32_t kErrorCode = 0x07;      // present | write | user
  constexpr uint64_t kFaultAddr = 0x12345000;

  fbl::RefPtr<VmObjectPaged> ram;
  ASSERT_EQ(ZX_OK, VmObjectPaged::Create(PMM_ALLOC_FLAG_ANY, 0u, kGuestRamSize, &ram), "ram\n");
  ASSERT_EQ(ZX_OK, WriteIdentityTables(ram), "tables\n");

  const uint8_t code[] = {0xB0, 0x00, 0xE6, 0x10, 0xB0, 0x77, 0xE6, 0x11, 0xF4};
  ASSERT_EQ(ZX_OK, ram->Write(code, kCodeGpa, sizeof(code)), "code\n");
  const uint8_t gdt_code[8] = {0xFF, 0xFF, 0x00, 0x00, 0x00, 0x9B, 0xAF, 0x00};
  ASSERT_EQ(ZX_OK, ram->Write(gdt_code, kEvtGdtGpa + 8, sizeof(gdt_code)), "GDT\n");

  uint8_t gate[16];
  WriteIdtGate(gate, kEvtHandlerGpa);
  ASSERT_EQ(ZX_OK, ram->Write(gate, kEvtIdtGpa + X86_INT_PAGE_FAULT * 16, sizeof(gate)), "IDT\n");

  // #PF handler:
  //   58          pop rax        ; error code
  //   E6 30       out 0x30, al
  //   0F 20 D0    mov rax, cr2   ; the faulting address the VMM supplied
  //   C1 E8 0C    shr eax, 12
  //   E6 31       out 0x31, al   ; (CR2 >> 12) & 0xff
  //   C1 E8 08    shr eax, 8
  //   E6 32       out 0x32, al   ; (CR2 >> 20) & 0xff
  //   F4          hlt
  const uint8_t handler[] = {0x58, 0xE6, 0x30, 0x0F, 0x20, 0xD0, 0xC1, 0xE8,
                             0x0C, 0xE6, 0x31, 0xC1, 0xE8, 0x08, 0xE6, 0x32, 0xF4};
  ASSERT_EQ(ZX_OK, ram->Write(handler, kEvtHandlerGpa, sizeof(handler)), "handler\n");
  ASSERT_EQ(ZX_OK, ram->CommitRange(0, kGuestRamSize), "commit\n");

  auto lg = CreateLiveGuestDispatcher(ram, kCodeGpa);
  if (lg.is_error() && lg.status_value() == ZX_ERR_NOT_SUPPORTED) {
    printf("VMX not supported here; skipping pending-event #PF test.\n");
    return true;
  }
  ASSERT_EQ(ZX_OK, lg.status_value(), "create live guest (dispatchers)\n");
  VcpuDispatcher* vcpu = lg->vcpu.get();
  ASSERT_EQ(ZX_OK, lg->guest->SetTrap(ZX_GUEST_TRAP_IO, 0x30, 1, nullptr, 0x30), "trap 0x30\n");
  ASSERT_EQ(ZX_OK, lg->guest->SetTrap(ZX_GUEST_TRAP_IO, 0x31, 1, nullptr, 0x31), "trap 0x31\n");
  ASSERT_EQ(ZX_OK, lg->guest->SetTrap(ZX_GUEST_TRAP_IO, 0x32, 1, nullptr, 0x32), "trap 0x32\n");
  ASSERT_EQ(ZX_OK, SetGuestTables(vcpu, kEvtGdtGpa, kEvtIdtGpa, kEvtStackTop), "GDTR/IDTR/RSP\n");

  zx_port_packet_t p = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(p), "enter #1\n");
  ASSERT_EQ(0x10u, p.guest_io.port, "readiness exit\n");

  zx_vcpu_pending_event_t pf =
      MakePendingEvent(ZX_VCPU_EVENT_HARDWARE_EXCEPTION, X86_INT_PAGE_FAULT);
  pf.flags = ZX_VCPU_EVENT_ERROR_CODE_VALID | ZX_VCPU_EVENT_CR2_VALID;
  pf.error_code = kErrorCode;
  pf.cr2 = kFaultAddr;
  ASSERT_EQ(ZX_OK, vcpu->WriteState(pf), "queue #PF with error code + CR2\n");

  zx_port_packet_t ec = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(ec), "enter #2 (deliver #PF)\n");
  ASSERT_EQ(static_cast<uint8_t>(ZX_PKT_TYPE_GUEST_IO), static_cast<uint8_t>(ec.type), "io\n");
  ASSERT_EQ(0x30u, ec.guest_io.port,
            "the guest's #PF handler must have run (0x11 here means nothing was delivered)\n");
  EXPECT_EQ(kErrorCode, static_cast<uint32_t>(ec.guest_io.data[0]),
            "#PF error code must be the one the VMM supplied\n");

  zx_port_packet_t c1 = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(c1), "enter #3 (CR2 low)\n");
  ASSERT_EQ(0x31u, c1.guest_io.port, "CR2 low byte port\n");
  EXPECT_EQ(static_cast<uint32_t>((kFaultAddr >> 12) & 0xFF),
            static_cast<uint32_t>(c1.guest_io.data[0]),
            "the guest must read the faulting address the VMM supplied out of CR2\n");

  zx_port_packet_t c2 = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(c2), "enter #4 (CR2 high)\n");
  ASSERT_EQ(0x32u, c2.guest_io.port, "CR2 high byte port\n");
  EXPECT_EQ(static_cast<uint32_t>((kFaultAddr >> 20) & 0xFF),
            static_cast<uint32_t>(c2.guest_io.data[0]), "CR2 must be delivered in full\n");

  // The handler can only report a byte per port write, so it reports the two
  // bytes of CR2 that identify the page (bits 12-27); both are checked above.
  printf("pending-event #PF OK: queued #PF(error_code=%#x, cr2=%#lx); the guest's handler read "
         "back error code %#x and CR2 bits[27:12] = %#x (expected %#x)\n",
         kErrorCode, kFaultAddr, static_cast<uint32_t>(ec.guest_io.data[0]),
         static_cast<uint32_t>(c2.guest_io.data[0]) << 8 | c1.guest_io.data[0],
         static_cast<uint32_t>((kFaultAddr >> 12) & 0xFFFF));
#else
  printf("Not x86_64; skipping.\n");
#endif  // __x86_64__

  END_TEST;
}

// The topic behaves as state, not as a fire-and-forget action: what is queued
// reads back, writing ZX_VCPU_EVENT_NONE un-queues it, and a cleared event is
// then genuinely not delivered — the guest runs straight on instead.
bool vcpu_pending_event_topic_round_trips() {
  BEGIN_TEST;

#ifdef __x86_64__
  fbl::RefPtr<VmObjectPaged> ram;
  ASSERT_EQ(ZX_OK, VmObjectPaged::Create(PMM_ALLOC_FLAG_ANY, 0u, kGuestRamSize, &ram), "ram\n");
  ASSERT_EQ(ZX_OK, WriteIdentityTables(ram), "tables\n");

  //   B0 00    mov al, 0
  //   E6 10    out 0x10, al   ; exit #1
  //   B0 22    mov al, 0x22
  //   E6 11    out 0x11, al   ; exit #2 -- only if nothing was delivered
  //   F4       hlt
  const uint8_t code[] = {0xB0, 0x00, 0xE6, 0x10, 0xB0, 0x22, 0xE6, 0x11, 0xF4};
  ASSERT_EQ(ZX_OK, ram->Write(code, kCodeGpa, sizeof(code)), "code\n");
  const uint8_t gdt_code[8] = {0xFF, 0xFF, 0x00, 0x00, 0x00, 0x9B, 0xAF, 0x00};
  ASSERT_EQ(ZX_OK, ram->Write(gdt_code, kEvtGdtGpa + 8, sizeof(gdt_code)), "GDT\n");
  uint8_t gate[16];
  WriteIdtGate(gate, kEvtHandlerGpa);
  ASSERT_EQ(ZX_OK, ram->Write(gate, kEvtIdtGpa + X86_INT_GP_FAULT * 16, sizeof(gate)), "IDT\n");
  // #GP handler: pop rax; mov al,0xEE; out 0x11,al; hlt -- a value the straight
  // line through the guest can never produce.
  const uint8_t handler[] = {0x58, 0xB0, 0xEE, 0xE6, 0x11, 0xF4};
  ASSERT_EQ(ZX_OK, ram->Write(handler, kEvtHandlerGpa, sizeof(handler)), "handler\n");
  ASSERT_EQ(ZX_OK, ram->CommitRange(0, kGuestRamSize), "commit\n");

  auto lg = CreateLiveGuestDispatcher(ram, kCodeGpa);
  if (lg.is_error() && lg.status_value() == ZX_ERR_NOT_SUPPORTED) {
    printf("VMX not supported here; skipping pending-event round-trip test.\n");
    return true;
  }
  ASSERT_EQ(ZX_OK, lg.status_value(), "create live guest (dispatchers)\n");
  VcpuDispatcher* vcpu = lg->vcpu.get();
  ASSERT_EQ(ZX_OK, SetGuestTables(vcpu, kEvtGdtGpa, kEvtIdtGpa, kEvtStackTop), "GDTR/IDTR/RSP\n");

  zx_port_packet_t p = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(p), "enter #1\n");
  ASSERT_EQ(0x10u, p.guest_io.port, "readiness exit\n");

  // Every field of every shape round-trips.
  zx_vcpu_pending_event_t pf =
      MakePendingEvent(ZX_VCPU_EVENT_HARDWARE_EXCEPTION, X86_INT_PAGE_FAULT);
  pf.flags = ZX_VCPU_EVENT_ERROR_CODE_VALID | ZX_VCPU_EVENT_CR2_VALID;
  pf.error_code = 0xCAFE;
  pf.cr2 = 0xFFFF800012345678;
  ASSERT_EQ(ZX_OK, vcpu->WriteState(pf), "queue #PF\n");
  zx_vcpu_pending_event_t got = {};
  ASSERT_EQ(ZX_OK, vcpu->ReadState(got), "read back #PF\n");
  EXPECT_EQ(ZX_VCPU_PENDING_EVENT_MAGIC, got.magic, "magic\n");
  EXPECT_EQ(ZX_VCPU_PENDING_EVENT_VERSION, got.version, "version\n");
  EXPECT_EQ(static_cast<uint32_t>(sizeof(zx_vcpu_pending_event_t)), got.size, "size\n");
  EXPECT_EQ(pf.type, got.type, "type\n");
  EXPECT_EQ(pf.vector, got.vector, "vector\n");
  EXPECT_EQ(pf.flags, got.flags, "flags\n");
  EXPECT_EQ(pf.error_code, got.error_code, "error code\n");
  EXPECT_EQ(pf.cr2, got.cr2, "cr2\n");

  // A software exception carries an instruction length instead.
  zx_vcpu_pending_event_t bp =
      MakePendingEvent(ZX_VCPU_EVENT_SOFTWARE_EXCEPTION, X86_INT_BREAKPOINT);
  bp.instruction_length = 1;
  ASSERT_EQ(ZX_OK, vcpu->WriteState(bp), "queue #BP\n");
  ASSERT_EQ(ZX_OK, vcpu->ReadState(got), "read back #BP\n");
  EXPECT_EQ(ZX_VCPU_EVENT_SOFTWARE_EXCEPTION, got.type, "#BP replaced #PF wholesale\n");
  EXPECT_EQ(1u, got.instruction_length, "instruction length\n");
  EXPECT_EQ(0u, got.flags, "the replaced event's error code + CR2 must be gone\n");
  EXPECT_EQ(0u, got.error_code, "error code cleared\n");
  EXPECT_EQ(0u, got.cr2, "cr2 cleared\n");

  // Now queue a #GP the guest could observe, and un-queue it again.
  zx_vcpu_pending_event_t gp =
      MakePendingEvent(ZX_VCPU_EVENT_HARDWARE_EXCEPTION, X86_INT_GP_FAULT);
  gp.flags = ZX_VCPU_EVENT_ERROR_CODE_VALID;
  gp.error_code = 0x11;
  ASSERT_EQ(ZX_OK, vcpu->WriteState(gp), "queue #GP\n");
  ASSERT_EQ(ZX_OK, vcpu->WriteState(MakePendingEvent(ZX_VCPU_EVENT_NONE, 0)), "clear the queue\n");
  ASSERT_EQ(ZX_OK, vcpu->ReadState(got), "read after clear\n");
  EXPECT_EQ(ZX_VCPU_EVENT_NONE, got.type, "ZX_VCPU_EVENT_NONE must un-queue\n");
  EXPECT_EQ(0u, got.vector, "cleared vector\n");
  EXPECT_EQ(0u, got.flags, "cleared flags\n");

  // And the clear is real: the guest runs straight on rather than vectoring
  // through its #GP handler.
  zx_port_packet_t after = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(after), "enter #2\n");
  ASSERT_EQ(static_cast<uint8_t>(ZX_PKT_TYPE_GUEST_IO), static_cast<uint8_t>(after.type), "io\n");
  ASSERT_EQ(0x11u, after.guest_io.port, "second exit port\n");
  EXPECT_EQ(0x22u, static_cast<uint32_t>(after.guest_io.data[0]),
            "a cleared event must not be delivered (0xEE here means it was)\n");

  printf("pending-event topic round-trip OK: #PF(ec+cr2) and #BP(len) read back field-for-field, "
         "a replacement dropped the previous payload, and after ZX_VCPU_EVENT_NONE the guest ran "
         "straight through (0x%x)\n",
         after.guest_io.data[0]);
#else
  printf("Not x86_64; skipping.\n");
#endif  // __x86_64__

  END_TEST;
}

// Input validation: userspace must not be able to compose an
// interruption-information field that VM entry would reject — a malformed
// injection surfaces as an opaque VM-entry failure with no path back to the call
// that caused it. Every rejection below is refused *before* anything is queued,
// so the event that was legitimately queued first is still the one the guest
// takes afterwards.
bool vcpu_pending_event_rejects_invalid() {
  BEGIN_TEST;

#ifdef __x86_64__
  constexpr uint32_t kBaselineErrorCode = 0x5A;

  fbl::RefPtr<VmObjectPaged> ram;
  ASSERT_EQ(ZX_OK, VmObjectPaged::Create(PMM_ALLOC_FLAG_ANY, 0u, kGuestRamSize, &ram), "ram\n");
  ASSERT_EQ(ZX_OK, WriteIdentityTables(ram), "tables\n");
  const uint8_t code[] = {0xB0, 0x00, 0xE6, 0x10, 0xB0, 0x77, 0xE6, 0x11, 0xF4};
  ASSERT_EQ(ZX_OK, ram->Write(code, kCodeGpa, sizeof(code)), "code\n");
  const uint8_t gdt_code[8] = {0xFF, 0xFF, 0x00, 0x00, 0x00, 0x9B, 0xAF, 0x00};
  ASSERT_EQ(ZX_OK, ram->Write(gdt_code, kEvtGdtGpa + 8, sizeof(gdt_code)), "GDT\n");
  uint8_t gate[16];
  WriteIdtGate(gate, kEvtHandlerGpa);
  ASSERT_EQ(ZX_OK, ram->Write(gate, kEvtIdtGpa + X86_INT_GP_FAULT * 16, sizeof(gate)), "IDT\n");
  // #GP handler: pop rax; out 0x11, al; hlt.
  const uint8_t handler[] = {0x58, 0xE6, 0x11, 0xF4};
  ASSERT_EQ(ZX_OK, ram->Write(handler, kEvtHandlerGpa, sizeof(handler)), "handler\n");
  ASSERT_EQ(ZX_OK, ram->CommitRange(0, kGuestRamSize), "commit\n");

  auto lg = CreateLiveGuestDispatcher(ram, kCodeGpa);
  if (lg.is_error() && lg.status_value() == ZX_ERR_NOT_SUPPORTED) {
    printf("VMX not supported here; skipping pending-event rejection test.\n");
    return true;
  }
  ASSERT_EQ(ZX_OK, lg.status_value(), "create live guest (dispatchers)\n");
  VcpuDispatcher* vcpu = lg->vcpu.get();
  ASSERT_EQ(ZX_OK, SetGuestTables(vcpu, kEvtGdtGpa, kEvtIdtGpa, kEvtStackTop), "GDTR/IDTR/RSP\n");

  zx_port_packet_t p = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(p), "enter #1\n");
  ASSERT_EQ(0x10u, p.guest_io.port, "readiness exit\n");

  // The event that must survive every rejection below.
  zx_vcpu_pending_event_t good =
      MakePendingEvent(ZX_VCPU_EVENT_HARDWARE_EXCEPTION, X86_INT_GP_FAULT);
  good.flags = ZX_VCPU_EVENT_ERROR_CODE_VALID;
  good.error_code = kBaselineErrorCode;
  ASSERT_EQ(ZX_OK, vcpu->WriteState(good), "queue the baseline event\n");

  uint32_t rejected = 0;
  auto reject = [&](const char* what, zx_status_t expected,
                    const zx_vcpu_pending_event_t& e) -> bool {
    zx_status_t status = vcpu->WriteState(e);
    if (status != expected) {
      printf("FAIL: %s -> %d, expected %d\n", what, status, expected);
      return false;
    }
    rejected++;
    return true;
  };
  zx_vcpu_pending_event_t bad;

  // A stale or foreign producer: the header is checked on entry.
  bad = MakePendingEvent(ZX_VCPU_EVENT_HARDWARE_EXCEPTION, X86_INT_INVALID_OP);
  bad.magic = ZX_VCPU_PENDING_EVENT_MAGIC + 1;
  ASSERT_TRUE(reject("wrong magic", ZX_ERR_INVALID_ARGS, bad), "\n");
  bad = MakePendingEvent(ZX_VCPU_EVENT_HARDWARE_EXCEPTION, X86_INT_INVALID_OP);
  bad.version = ZX_VCPU_PENDING_EVENT_VERSION + 1;
  ASSERT_TRUE(reject("wrong version", ZX_ERR_INVALID_ARGS, bad), "\n");
  bad = MakePendingEvent(ZX_VCPU_EVENT_HARDWARE_EXCEPTION, X86_INT_INVALID_OP);
  bad.size = sizeof(zx_vcpu_pending_event_t) - 4;
  ASSERT_TRUE(reject("wrong size", ZX_ERR_INVALID_ARGS, bad), "\n");

  // An interruption type this kernel does not deliver. Type 5 would be VMX's
  // "privileged software exception"; leaving it out of the ABI is deliberate,
  // and a caller that guesses at it is told so.
  bad = MakePendingEvent(5, X86_INT_GP_FAULT);
  ASSERT_TRUE(reject("unknown type", ZX_ERR_INVALID_ARGS, bad), "\n");
  bad = MakePendingEvent(0xFFFFFFFF, X86_INT_GP_FAULT);
  ASSERT_TRUE(reject("garbage type", ZX_ERR_INVALID_ARGS, bad), "\n");
  bad = MakePendingEvent(ZX_VCPU_EVENT_HARDWARE_EXCEPTION, X86_INT_GP_FAULT);
  bad.flags = ZX_VCPU_EVENT_ERROR_CODE_VALID | (1u << 5);
  ASSERT_TRUE(reject("unknown flag", ZX_ERR_INVALID_ARGS, bad), "\n");

  // The bug this path exists to fix, in both directions: an exception whose
  // vector has an error code must carry one, and a vector that has none must
  // not claim one (VM entry rejects the deliver-error-code bit there).
  bad = MakePendingEvent(ZX_VCPU_EVENT_HARDWARE_EXCEPTION, X86_INT_GP_FAULT);
  ASSERT_TRUE(reject("#GP without an error code", ZX_ERR_INVALID_ARGS, bad), "\n");
  bad = MakePendingEvent(ZX_VCPU_EVENT_HARDWARE_EXCEPTION, X86_INT_INVALID_OP);
  bad.flags = ZX_VCPU_EVENT_ERROR_CODE_VALID;
  bad.error_code = 1;
  ASSERT_TRUE(reject("#UD with an error code", ZX_ERR_INVALID_ARGS, bad), "\n");

  // CR2 belongs to #PF and nothing else, in both directions.
  bad = MakePendingEvent(ZX_VCPU_EVENT_HARDWARE_EXCEPTION, X86_INT_PAGE_FAULT);
  bad.flags = ZX_VCPU_EVENT_ERROR_CODE_VALID;
  bad.error_code = 3;
  ASSERT_TRUE(reject("#PF without CR2", ZX_ERR_INVALID_ARGS, bad), "\n");
  bad = MakePendingEvent(ZX_VCPU_EVENT_HARDWARE_EXCEPTION, X86_INT_GP_FAULT);
  bad.flags = ZX_VCPU_EVENT_ERROR_CODE_VALID | ZX_VCPU_EVENT_CR2_VALID;
  bad.error_code = 3;
  bad.cr2 = 0x1000;
  ASSERT_TRUE(reject("#GP with CR2", ZX_ERR_INVALID_ARGS, bad), "\n");

  // Vectors outside the range each type allows.
  bad = MakePendingEvent(ZX_VCPU_EVENT_HARDWARE_EXCEPTION, 0x20);
  ASSERT_TRUE(reject("hardware exception vector 0x20", ZX_ERR_OUT_OF_RANGE, bad), "\n");
  bad = MakePendingEvent(ZX_VCPU_EVENT_EXTERNAL_INTERRUPT, X86_INT_GP_FAULT);
  ASSERT_TRUE(reject("external interrupt in the exception range", ZX_ERR_OUT_OF_RANGE, bad), "\n");
  bad = MakePendingEvent(ZX_VCPU_EVENT_EXTERNAL_INTERRUPT, 0x100);
  ASSERT_TRUE(reject("external interrupt vector 0x100", ZX_ERR_OUT_OF_RANGE, bad), "\n");
  bad = MakePendingEvent(ZX_VCPU_EVENT_NMI, X86_INT_BREAKPOINT);
  ASSERT_TRUE(reject("NMI on a vector other than 2", ZX_ERR_INVALID_ARGS, bad), "\n");
  bad = MakePendingEvent(ZX_VCPU_EVENT_SOFTWARE_EXCEPTION, X86_INT_GP_FAULT);
  bad.instruction_length = 1;
  ASSERT_TRUE(reject("software exception that is not #BP/#OF", ZX_ERR_INVALID_ARGS, bad), "\n");

  // Instruction length belongs to software exceptions, and must be a real
  // instruction length there.
  bad = MakePendingEvent(ZX_VCPU_EVENT_SOFTWARE_EXCEPTION, X86_INT_BREAKPOINT);
  ASSERT_TRUE(reject("software exception with length 0", ZX_ERR_OUT_OF_RANGE, bad), "\n");
  bad = MakePendingEvent(ZX_VCPU_EVENT_SOFTWARE_EXCEPTION, X86_INT_BREAKPOINT);
  bad.instruction_length = 16;
  ASSERT_TRUE(reject("software exception with length 16", ZX_ERR_OUT_OF_RANGE, bad), "\n");
  bad = MakePendingEvent(ZX_VCPU_EVENT_HARDWARE_EXCEPTION, X86_INT_GP_FAULT);
  bad.flags = ZX_VCPU_EVENT_ERROR_CODE_VALID;
  bad.instruction_length = 1;
  ASSERT_TRUE(reject("hardware exception with an instruction length", ZX_ERR_INVALID_ARGS, bad),
              "\n");
  bad = MakePendingEvent(ZX_VCPU_EVENT_EXTERNAL_INTERRUPT, 0x50);
  bad.flags = ZX_VCPU_EVENT_ERROR_CODE_VALID;
  bad.error_code = 1;
  ASSERT_TRUE(reject("external interrupt with an error code", ZX_ERR_INVALID_ARGS, bad), "\n");

  // A payload set without its flag would otherwise be silently dropped.
  bad = MakePendingEvent(ZX_VCPU_EVENT_HARDWARE_EXCEPTION, X86_INT_INVALID_OP);
  bad.error_code = 1;
  ASSERT_TRUE(reject("error code without its flag", ZX_ERR_INVALID_ARGS, bad), "\n");
  bad = MakePendingEvent(ZX_VCPU_EVENT_HARDWARE_EXCEPTION, X86_INT_INVALID_OP);
  bad.cr2 = 0x1000;
  ASSERT_TRUE(reject("cr2 without its flag", ZX_ERR_INVALID_ARGS, bad), "\n");

  // Clearing the queue means clearing it, not clearing it *and* something else.
  bad = MakePendingEvent(ZX_VCPU_EVENT_NONE, X86_INT_GP_FAULT);
  ASSERT_TRUE(reject("ZX_VCPU_EVENT_NONE with a vector", ZX_ERR_INVALID_ARGS, bad), "\n");

  // Nothing above was applied: the baseline event is still the queued one.
  zx_vcpu_pending_event_t still = {};
  ASSERT_EQ(ZX_OK, vcpu->ReadState(still), "read after rejections\n");
  EXPECT_EQ(ZX_VCPU_EVENT_HARDWARE_EXCEPTION, still.type, "a refused write must not change type\n");
  EXPECT_EQ(static_cast<uint32_t>(X86_INT_GP_FAULT), still.vector,
            "a refused write must not change the vector\n");
  EXPECT_EQ(kBaselineErrorCode, still.error_code,
            "a refused write must not change the error code\n");

  // And it is the baseline the guest actually takes.
  zx_port_packet_t handled = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(handled), "enter #2\n");
  ASSERT_EQ(static_cast<uint8_t>(ZX_PKT_TYPE_GUEST_IO), static_cast<uint8_t>(handled.type), "io\n");
  ASSERT_EQ(0x11u, handled.guest_io.port, "handler port\n");
  EXPECT_EQ(kBaselineErrorCode, static_cast<uint32_t>(handled.guest_io.data[0]),
            "the baseline error code must have survived the rejected writes\n");

  printf("pending-event rejection OK: refused %u malformed injections (bad header, unknown "
         "type/flag, missing or forbidden error code, misplaced CR2, out-of-range vectors, bad "
         "instruction length); the VCPU still delivered the baseline #GP(%#x)\n",
         rejected, handled.guest_io.data[0]);
#else
  printf("Not x86_64; skipping.\n");
#endif  // __x86_64__

  END_TEST;
}

#ifdef __x86_64__
// ---------------------------------------------------------------------------
// Events interrupted mid-delivery: the VMCS IDT-vectoring information field.
//
// When a VM exit happens *while* the processor is vectoring an event through
// the guest IDT — the classic trigger being that the push of the interrupt
// frame is the first write the guest has ever made to its stack page, so it
// takes an EPT violation — the processor abandons the delivery, rolls the guest
// back to before it, and records what it was delivering in the IDT-vectoring
// information field. The exit reason is the fault's, not the event's. Unless the
// hypervisor reads that field and puts the event back, the event is gone: its
// vector was already popped out of the interrupt tracker (or its pending-event
// slot already cleared) by the entry that injected it.
//
// A real OS rarely notices, because its stack has been in use for a long time
// before it enables interrupts. A freshly-SIPI'd AP is exactly the shape that
// does notice, and that is how Windows brings up every processor after the first.
//
// Making this reproduce in a test takes some care: VmMapping::PageFaultLocked
// opportunistically faults up to kPageFaultMaxOptimisticPages (16) *committed*
// pages ahead of the one that faulted, so the very first EPT violation in these
// 64 KiB guests — the walk of the PML4 at GPA 0 — maps the entire guest RAM,
// stack page included. Simply "never writing" the stack is therefore not enough:
// these tests re-map a fresh page over the stack GPA with
// VMAR_FLAG_SPECIFIC_OVERWRITE after the guest is already running, which drops
// the old mapping's page-table entries and leaves the GPA genuinely unbacked.
//
// The pass condition is not just "the handler ran" — a fix that pre-faulted or
// pinned the stack page, or that blindly replayed the last interrupt, would pass
// that. Vcpu::Vectoring() reports what the processor actually said: how many
// events were recovered from the IDT-vectoring field, and, for the most recent
// one, the raw field, the exit reason that carried it and the guest-physical
// address the aborted delivery was touching. So each test states exactly what it
// expects to have happened, down to the vector and interruption type the
// hardware recorded.
// ---------------------------------------------------------------------------

// Exit reasons, Volume 3, Appendix C. The exit that carries a delivery-time
// fault reports the *fault*, which is the whole difficulty.
constexpr uint32_t kExitReasonEptViolation = 48;
// Interruption types as they appear in bits 10:8 of the vectoring field.
constexpr uint32_t kIdtvTypeExternalInterrupt = 0;
constexpr uint32_t kIdtvTypeHardwareException = 3;

// Decodes what the processor recorded, so an assertion can name it.
uint32_t VectoringVector(const Vcpu* vcpu) { return vcpu->Vectoring().last_info & 0xFFu; }
uint32_t VectoringType(const Vcpu* vcpu) { return (vcpu->Vectoring().last_info >> 8) & 0x7u; }
bool VectoringValid(const Vcpu* vcpu) { return (vcpu->Vectoring().last_info & (1u << 31)) != 0; }
bool VectoringHasErrorCode(const Vcpu* vcpu) {
  return (vcpu->Vectoring().last_info & (1u << 11)) != 0;
}

// Guest-physical layout shared by the IDT-vectoring tests. The stack lives on a
// page of its own, below the descriptor tables, so the interrupt frame's push
// cannot spill into a page that something else has already touched.
constexpr uint64_t kIdtvStackGpa = 0x5000;
constexpr uint64_t kIdtvStackTop = 0x6000;
constexpr uint64_t kIdtvGdtGpa = 0x6000;
constexpr uint64_t kIdtvIdtGpa = 0x6800;
constexpr uint64_t kIdtvHandlerGpa = 0x8000;
// Bytes per handler. 16 was enough when a handler only reported its vector;
// these handlers also write an EOI, which is four instructions.
constexpr uint64_t kIdtvHandlerStride = 32;
constexpr uint64_t kIdtvPfHandlerGpa = 0xA000;
constexpr uint16_t kIdtvReportPort = 0x30;
constexpr uint16_t kIdtvCr2Port = 0x31;
// The vector under test, and the neighbours/faults that get their own reporting
// handlers so that "something else arrived" fails loudly instead of silently.
constexpr uint32_t kIdtvVector = 0x52;
constexpr uint32_t kIdtvWatchedVectors[] = {0x02, 0x08, 0x0D, 0x0E, 0x1F, 0x51, 0x52, 0x53};
constexpr size_t kIdtvWatchedCount = sizeof(kIdtvWatchedVectors) / sizeof(kIdtvWatchedVectors[0]);

// A guest body shared by the tests that need to take more than one interrupt:
// it exits once to say it is ready, then spins in a bounded loop long enough for
// everything queued to arrive, then reports completion. The counter is set up
// BEFORE the readiness exit because an interrupt can be injected at the very
// next entry, and the handlers below resume at the loop rather than at the
// instruction they interrupted — initialising it afterwards leaves RCX at zero
// and `loop` runs 2^64 times.
//   FB          sti
//   90          nop
//   B9 .. 00 10 mov ecx, 0x100000
//   B0 A1       mov al, 0xA1
//   E6 10       out 0x10, al        ; "ready"
//   E2 FE       loop $              ; offset 11
//   B0 A3       mov al, 0xA3
//   E6 12       out 0x12, al        ; "finished, and nothing more arrived"
//   F4          hlt
constexpr uint8_t kIdtvLoopCode[] = {0xFB, 0x90, 0xB9, 0x00, 0x00, 0x10, 0x00, 0xB0, 0xA1,
                                     0xE6, 0x10, 0xE2, 0xFE, 0xB0, 0xA3, 0xE6, 0x12, 0xF4};
constexpr uint64_t kIdtvLoopGpa = kCodeGpa + 11;
constexpr uint16_t kIdtvDonePort = 0x12;
constexpr uint8_t kIdtvDoneToken = 0xA3;

// Lays down the tables, a flat 64-bit code segment, and one IDT entry per
// watched vector pointing at a handler that reports *its own vector number* on
// kIdtvReportPort. Reporting the vector rather than a fixed sentinel is what
// makes "and received the right vector" an assertion rather than a hope: a
// spurious interrupt, or a #PF/#DF thrown by a half-delivered event, arrives at
// a different handler and reports a different byte.
zx_status_t WriteVectoringGuest(const fbl::RefPtr<VmObjectPaged>& ram, const uint8_t* code,
                                size_t code_len) {
  if (zx_status_t s = WriteIdentityTables(ram); s != ZX_OK) {
    return s;
  }
  if (zx_status_t s = ram->Write(code, kCodeGpa, code_len); s != ZX_OK) {
    return s;
  }
  const uint8_t gdt_code[8] = {0xFF, 0xFF, 0x00, 0x00, 0x00, 0x9B, 0xAF, 0x00};
  if (zx_status_t s = ram->Write(gdt_code, kIdtvGdtGpa + 8, sizeof(gdt_code)); s != ZX_OK) {
    return s;
  }
  for (size_t i = 0; i < kIdtvWatchedCount; i++) {
    const uint32_t vector = kIdtvWatchedVectors[i];
    const uint64_t handler = kIdtvHandlerGpa + i * kIdtvHandlerStride;
    uint8_t gate[16];
    WriteIdtGate(gate, handler);
    if (zx_status_t s = ram->Write(gate, kIdtvIdtGpa + vector * 16, sizeof(gate)); s != ZX_OK) {
      return s;
    }
    // mov al, <vector>; out kIdtvReportPort, al; <EOI>; hlt  — touches no stack.
    //
    // The EOI is what a real interrupt service routine ends with, and since the
    // hypervisor gained an in-service register it is load-bearing rather than
    // decorative: without it the vector stays in service after the handler runs,
    // and the next interrupt of the same priority class is held back forever --
    // which is the architecturally correct answer to a guest that never
    // acknowledges its interrupts. It sits after the report so the report exit
    // still observes the interrupt in service. On a handler entered for an
    // exception or an NMI, neither of which enters the ISR, it is a no-op.
    const uint8_t body[] = {0xB0,
                            static_cast<uint8_t>(vector),
                            0xE6,
                            static_cast<uint8_t>(kIdtvReportPort),
                            0xB9, 0x0B, 0x08, 0x00, 0x00,  // mov ecx, 0x80b (EOI)
                            0x31, 0xC0,                    // xor eax, eax
                            0x31, 0xD2,                    // xor edx, edx
                            0x0F, 0x30,                    // wrmsr
                            0xF4};
    if (zx_status_t s = ram->Write(body, handler, sizeof(body)); s != ZX_OK) {
      return s;
    }
  }
  return ram->CommitRange(0, kGuestRamSize);
}

// Drops a fresh, never-touched page over the stack GPA. VMAR_FLAG_SPECIFIC_
// OVERWRITE tears down the previous mapping — and with it the EPT entries the
// opportunistic fault-ahead installed — so the next access to that page really
// is its first, and a write to it really does exit.
zx_status_t OverwriteStackWithPristinePage(Guest* guest) {
  fbl::RefPtr<VmObjectPaged> fresh;
  if (zx_status_t s = VmObjectPaged::Create(PMM_ALLOC_FLAG_ANY, 0u, 4096, &fresh); s != ZX_OK) {
    return s;
  }
  if (zx_status_t s = fresh->CommitRange(0, 4096); s != ZX_OK) {
    return s;
  }
  auto remap = guest->RootVmar()->CreateVmMapping(kIdtvStackGpa, 4096, 0,
                                                  VMAR_FLAG_SPECIFIC_OVERWRITE, fresh, 0, kMmuFlags,
                                                  "pristine-stack");
  return remap.status_value();
}

// Rewrites every watched handler to report its vector, end the interrupt, and
// then resume the shared loop, so more than one interrupt can be observed in a
// single run:
//   mov al, <vector>; out kIdtvReportPort, al; wrmsr EOI; sti; jmp kIdtvLoopGpa
//
// The EOI is not decoration. Since the hypervisor gained an in-service register,
// an unacknowledged interrupt keeps the processor priority at its own class, and
// the tests that queue two vectors of the same class -- which is most of the
// ones using this helper -- would see the second held indefinitely. That is the
// correct answer to a guest that never EOIs; the fix is for the guest to EOI,
// which is what a real handler does. It is placed after the report so the report
// exit still observes the interrupt in service, and it is a no-op in the
// handlers reached by an exception or an NMI, neither of which enters the ISR.
//
// Deliberately not `iretq`. IRET reloads SS from the selector the processor
// pushed, which for these guests is the null selector the hypervisor leaves in
// GUEST_SS_SELECTOR, and the two-entry GDT has nothing to reload it from — the
// first version of the exact-once test took a #GP there, and the #GP handler's
// own report is what gave it away. `sti` re-enables delivery (the interrupt gate
// cleared IF) and the jump abandons the frame, which costs 40 bytes of stack per
// interrupt and touches no descriptor. It also, deliberately, never ends NMI
// blocking — only IRET does that, which is what the NMI-window test needs.
zx_status_t RewriteHandlersToResumeLoop(const fbl::RefPtr<VmObjectPaged>& ram) {
  for (size_t i = 0; i < kIdtvWatchedCount; i++) {
    const uint64_t handler = kIdtvHandlerGpa + i * kIdtvHandlerStride;
    // The jump displacement is measured from the end of the 21-byte body.
    const int32_t disp = static_cast<int32_t>(kIdtvLoopGpa) - static_cast<int32_t>(handler + 21);
    const uint32_t d = static_cast<uint32_t>(disp);
    const uint8_t body[] = {0xB0,
                            static_cast<uint8_t>(kIdtvWatchedVectors[i]),
                            0xE6,
                            static_cast<uint8_t>(kIdtvReportPort),
                            0xB9, 0x0B, 0x08, 0x00, 0x00,  // mov ecx, 0x80b (EOI)
                            0x31, 0xC0,                    // xor eax, eax
                            0x31, 0xD2,                    // xor edx, edx
                            0x0F, 0x30,                    // wrmsr
                            0xFB,
                            0xE9,
                            static_cast<uint8_t>(d & 0xFF),
                            static_cast<uint8_t>((d >> 8) & 0xFF),
                            static_cast<uint8_t>((d >> 16) & 0xFF),
                            static_cast<uint8_t>((d >> 24) & 0xFF)};
    static_assert(sizeof(body) == 21, "jump displacement is measured from the body's end");
    if (zx_status_t s = ram->Write(body, handler, sizeof(body)); s != ZX_OK) {
      return s;
    }
  }
  return ram->CommitRange(0, kGuestRamSize);
}

// Points a raw Vcpu at the vectoring layout's tables and stack.
zx_status_t SetVectoringTables(Vcpu* vcpu) {
  VcpuArchState s = {};
  if (auto r = vcpu->SaveArchState(s); r.is_error()) {
    return r.status_value();
  }
  s.gdtr_base = kIdtvGdtGpa;
  s.gdtr_limit = 0x0F;
  s.idtr_base = kIdtvIdtGpa;
  s.idtr_limit = 0xFFF;
  s.regs.rsp = kIdtvStackTop;
  return vcpu->RestoreArchState(s).status_value();
}
#endif  // __x86_64__

// THE REPRODUCTION. An injected interrupt whose interrupt-frame push is the
// first write the guest ever makes to its stack page. The push takes an EPT
// violation *during delivery*; the processor abandons the event and records it
// in the IDT-vectoring information field. Before that field was read, the vector
// was simply gone — it had already been popped out of the interrupt tracker and
// written into the entry-interruption field, so nothing re-queued it, and the
// guest span on in `jmp $` forever.
bool vcpu_event_faulting_mid_delivery_is_reinjected() {
  BEGIN_TEST;

#ifdef __x86_64__
  fbl::RefPtr<VmObjectPaged> ram;
  ASSERT_EQ(ZX_OK, VmObjectPaged::Create(PMM_ALLOC_FLAG_ANY, 0u, kGuestRamSize, &ram), "ram\n");

  // FB       sti
  // 90       nop            ; retire the one-instruction STI shadow
  // B0 A1    mov al, 0xA1
  // E6 10    out 0x10, al   ; exit #1: interruptible, and the stack still pristine
  // EB FE    jmp $          ; spin until the injected interrupt vectors out of it
  const uint8_t code[] = {0xFB, 0x90, 0xB0, 0xA1, 0xE6, 0x10, 0xEB, 0xFE};
  ASSERT_EQ(ZX_OK, WriteVectoringGuest(ram, code, sizeof(code)), "build guest\n");

  auto lg = CreateLiveGuest(ram, kCodeGpa);
  if (lg.is_error() && lg.status_value() == ZX_ERR_NOT_SUPPORTED) {
    printf("VMX not supported here; skipping IDT-vectoring re-injection test.\n");
    return true;
  }
  ASSERT_EQ(ZX_OK, lg.status_value(), "create live guest\n");
  Vcpu* vcpu = lg->vcpu.get();
  ASSERT_EQ(ZX_OK, lg->guest->SetTrap(ZX_GUEST_TRAP_IO, kIdtvReportPort, 1, nullptr,
                                      kIdtvReportPort)
                       .status_value(),
            "trap report port\n");
  ASSERT_EQ(ZX_OK, SetVectoringTables(vcpu), "GDTR/IDTR/RSP\n");

  zx_port_packet_t p = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(p).status_value(), "enter #1\n");
  ASSERT_EQ(0x10u, p.guest_io.port, "readiness exit\n");
  ASSERT_EQ(0xA1u, static_cast<uint32_t>(p.guest_io.data[0]), "readiness sentinel\n");
  EXPECT_EQ(0u, vcpu->Vectoring().reinjections, "nothing has been interrupted mid-delivery yet\n");

  // Make the stack page genuinely unbacked. Up to this point the guest has run
  // only out of its code page and read its tables; it has never written a byte
  // of stack, and now the EPT has no entry for the page at all.
  ASSERT_EQ(ZX_OK, OverwriteStackWithPristinePage(lg->guest.get()), "pristine stack page\n");

  ASSERT_EQ(ZX_OK, vcpu->Interrupt(kIdtvVector).status_value(), "inject vector\n");

  zx_port_packet_t handled = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(handled).status_value(), "enter #2 (deliver)\n");
  ASSERT_EQ(static_cast<uint8_t>(ZX_PKT_TYPE_GUEST_IO), static_cast<uint8_t>(handled.type), "io\n");
  ASSERT_EQ(static_cast<uint32_t>(kIdtvReportPort), static_cast<uint32_t>(handled.guest_io.port),
            "the guest's own IDT handler must have run\n");
  EXPECT_EQ(kIdtvVector, static_cast<uint32_t>(handled.guest_io.data[0]),
            "and it must be the handler for the vector that was injected\n");

  // Non-vacuity, stated as hardware evidence rather than as inference. The
  // handler running is only interesting if the delivery really was aborted and
  // recovered; a fix that pre-faulted the stack, or that replayed the last
  // vector unconditionally, would satisfy the assertions above and fail these.
  EXPECT_EQ(1u, vcpu->Vectoring().reinjections,
            "exactly one event must have been recovered from the IDT-vectoring field\n");
  EXPECT_TRUE(VectoringValid(vcpu), "the processor must have marked the field valid\n");
  EXPECT_EQ(kIdtvVector, VectoringVector(vcpu),
            "and recorded the vector whose delivery it abandoned\n");
  EXPECT_EQ(kIdtvTypeExternalInterrupt, VectoringType(vcpu),
            "as an external interrupt, not an exception\n");
  EXPECT_FALSE(VectoringHasErrorCode(vcpu), "an external interrupt carries no error code\n");
  EXPECT_EQ(kExitReasonEptViolation, vcpu->Vectoring().last_exit_reason,
            "the exit that carried it must be the *fault's*, not the event's\n");
  EXPECT_EQ(kIdtvStackGpa, vcpu->Vectoring().last_exit_gpa & ~UINT64_C(0xFFF),
            "and the address it faulted on must be the stack page the frame was being "
            "pushed to\n");

  printf("IDT-vectoring re-injection OK: vector %#x was interrupted mid-delivery by the first "
         "write to a pristine stack page — the processor reported idt_vectoring=%#x (valid, "
         "type %u, vector %#x) on an EPT violation at gpa %#lx — and was recovered (%lu "
         "re-injection(s)) and delivered to the guest's own handler, which reported %#x\n",
         kIdtvVector, vcpu->Vectoring().last_info, VectoringType(vcpu), VectoringVector(vcpu),
         vcpu->Vectoring().last_exit_gpa, vcpu->Vectoring().reinjections,
         handled.guest_io.data[0]);
#else
  printf("Not x86_64; skipping.\n");
#endif  // __x86_64__

  END_TEST;
}

// THE NEGATIVE CONTROL, and the one that keeps the fix honest. Same guest, same
// freshly-overwritten stack page, one variable changed: the guest performs a
// stack write of its own (`push rax; pop rax`) before the injection, so the EPT
// entry is present by the time the interrupt frame is pushed and the delivery
// completes in one go. This is the distinction the original diagnosis rested on
// — the VP that pushed received its vector, the VP that did not, did not — and
// it must keep passing, with *no* re-injection: a fix that recovered events it
// had not lost, or that disturbed ordinary delivery, fails here.
bool vcpu_event_with_written_stack_needs_no_reinjection() {
  BEGIN_TEST;

#ifdef __x86_64__
  fbl::RefPtr<VmObjectPaged> ram;
  ASSERT_EQ(ZX_OK, VmObjectPaged::Create(PMM_ALLOC_FLAG_ANY, 0u, kGuestRamSize, &ram), "ram\n");

  // FB       sti
  // 90       nop
  // B0 A1    mov al, 0xA1
  // E6 10    out 0x10, al   ; exit #1: the host makes the stack page pristine here
  // 50       push rax       ; <- the single variable: an ordinary write to it
  // 58       pop rax
  // B0 A2    mov al, 0xA2
  // E6 11    out 0x11, al   ; exit #2: stack page now backed
  // EB FE    jmp $
  const uint8_t code[] = {0xFB, 0x90, 0xB0, 0xA1, 0xE6, 0x10, 0x50,
                          0x58, 0xB0, 0xA2, 0xE6, 0x11, 0xEB, 0xFE};
  ASSERT_EQ(ZX_OK, WriteVectoringGuest(ram, code, sizeof(code)), "build guest\n");

  auto lg = CreateLiveGuest(ram, kCodeGpa);
  if (lg.is_error() && lg.status_value() == ZX_ERR_NOT_SUPPORTED) {
    printf("VMX not supported here; skipping written-stack control.\n");
    return true;
  }
  ASSERT_EQ(ZX_OK, lg.status_value(), "create live guest\n");
  Vcpu* vcpu = lg->vcpu.get();
  ASSERT_EQ(ZX_OK, lg->guest->SetTrap(ZX_GUEST_TRAP_IO, kIdtvReportPort, 1, nullptr,
                                      kIdtvReportPort)
                       .status_value(),
            "trap report port\n");
  ASSERT_EQ(ZX_OK, SetVectoringTables(vcpu), "GDTR/IDTR/RSP\n");

  zx_port_packet_t p = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(p).status_value(), "enter #1\n");
  ASSERT_EQ(0x10u, p.guest_io.port, "readiness exit\n");

  // Identical setup to the reproduction: the stack page is made pristine at the
  // same point in the run.
  ASSERT_EQ(ZX_OK, OverwriteStackWithPristinePage(lg->guest.get()), "pristine stack page\n");

  // ...and then the guest, not an injected event, is the one to touch it first.
  zx_port_packet_t touched = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(touched).status_value(), "enter #2 (guest writes its stack)\n");
  ASSERT_EQ(0x11u, touched.guest_io.port, "post-push exit\n");
  ASSERT_EQ(0xA2u, static_cast<uint32_t>(touched.guest_io.data[0]), "post-push sentinel\n");
  EXPECT_EQ(0u, vcpu->Vectoring().reinjections,
            "the guest's own EPT violation happened outside event delivery, so there was "
            "nothing to recover\n");

  ASSERT_EQ(ZX_OK, vcpu->Interrupt(kIdtvVector).status_value(), "inject vector\n");

  zx_port_packet_t handled = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(handled).status_value(), "enter #3 (deliver)\n");
  ASSERT_EQ(static_cast<uint8_t>(ZX_PKT_TYPE_GUEST_IO), static_cast<uint8_t>(handled.type), "io\n");
  ASSERT_EQ(static_cast<uint32_t>(kIdtvReportPort), static_cast<uint32_t>(handled.guest_io.port),
            "ordinary delivery must still reach the guest's IDT handler\n");
  EXPECT_EQ(kIdtvVector, static_cast<uint32_t>(handled.guest_io.data[0]),
            "and with the right vector\n");
  EXPECT_EQ(0u, vcpu->Vectoring().reinjections,
            "a delivery that never faulted must not be re-injected — recovering an event that "
            "was not interrupted would deliver it twice\n");

  printf("written-stack control OK: the guest wrote its own stack first, so vector %#x was "
         "delivered in one go (handler reported %#x) with 0 IDT-vectoring re-injections\n",
         kIdtvVector, handled.guest_io.data[0]);
#else
  printf("Not x86_64; skipping.\n");
#endif  // __x86_64__

  END_TEST;
}

// The payload has to survive the round trip too, not just the vector. A #PF
// queued through ZX_VCPU_STATE_PENDING_EVENT carries an error code and a CR2;
// its delivery is interrupted by the very same pristine-stack EPT violation, and
// the guest's own #PF handler must still read back both. The error code comes
// out of the IDT-vectoring error-code field; CR2 is not a VMCS field at all and
// survives because vmx.S swaps it around every entry and the aborted delivery
// never overwrote it.
bool vcpu_faulting_delivery_preserves_error_code_and_cr2() {
  BEGIN_TEST;

#ifdef __x86_64__
  constexpr uint32_t kErrorCode = 0x07;  // present | write | user
  constexpr uint64_t kFaultAddr = 0x12345000;

  fbl::RefPtr<VmObjectPaged> ram;
  ASSERT_EQ(ZX_OK, VmObjectPaged::Create(PMM_ALLOC_FLAG_ANY, 0u, kGuestRamSize, &ram), "ram\n");
  const uint8_t code[] = {0xFB, 0x90, 0xB0, 0xA1, 0xE6, 0x10, 0xEB, 0xFE};
  ASSERT_EQ(ZX_OK, WriteVectoringGuest(ram, code, sizeof(code)), "build guest\n");

  // Re-point the #PF gate at a handler that reports the error code and CR2.
  //   58        pop rax        ; the error code the processor pushed
  //   E6 30     out 0x30, al
  //   0F 20 D0  mov rax, cr2
  //   C1 E8 0C  shr eax, 12
  //   E6 31     out 0x31, al   ; (CR2 >> 12) & 0xff
  //   F4        hlt
  uint8_t gate[16];
  WriteIdtGate(gate, kIdtvPfHandlerGpa);
  ASSERT_EQ(ZX_OK, ram->Write(gate, kIdtvIdtGpa + X86_INT_PAGE_FAULT * 16, sizeof(gate)), "gate\n");
  const uint8_t pf_handler[] = {0x58, 0xE6, 0x30, 0x0F, 0x20, 0xD0, 0xC1, 0xE8, 0x0C, 0xE6, 0x31,
                                0xF4};
  ASSERT_EQ(ZX_OK, ram->Write(pf_handler, kIdtvPfHandlerGpa, sizeof(pf_handler)), "pf handler\n");
  ASSERT_EQ(ZX_OK, ram->CommitRange(0, kGuestRamSize), "commit\n");

  auto lg = CreateLiveGuest(ram, kCodeGpa);
  if (lg.is_error() && lg.status_value() == ZX_ERR_NOT_SUPPORTED) {
    printf("VMX not supported here; skipping faulting-delivery payload test.\n");
    return true;
  }
  ASSERT_EQ(ZX_OK, lg.status_value(), "create live guest\n");
  Vcpu* vcpu = lg->vcpu.get();
  ASSERT_EQ(ZX_OK, lg->guest->SetTrap(ZX_GUEST_TRAP_IO, kIdtvReportPort, 1, nullptr,
                                      kIdtvReportPort)
                       .status_value(),
            "trap report port\n");
  ASSERT_EQ(ZX_OK,
            lg->guest->SetTrap(ZX_GUEST_TRAP_IO, kIdtvCr2Port, 1, nullptr, kIdtvCr2Port)
                .status_value(),
            "trap cr2 port\n");
  ASSERT_EQ(ZX_OK, SetVectoringTables(vcpu), "GDTR/IDTR/RSP\n");

  zx_port_packet_t p = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(p).status_value(), "enter #1\n");
  ASSERT_EQ(0x10u, p.guest_io.port, "readiness exit\n");
  ASSERT_EQ(ZX_OK, OverwriteStackWithPristinePage(lg->guest.get()), "pristine stack page\n");

  zx_vcpu_pending_event_t pf =
      MakePendingEvent(ZX_VCPU_EVENT_HARDWARE_EXCEPTION, X86_INT_PAGE_FAULT);
  pf.flags = ZX_VCPU_EVENT_ERROR_CODE_VALID | ZX_VCPU_EVENT_CR2_VALID;
  pf.error_code = kErrorCode;
  pf.cr2 = kFaultAddr;
  ASSERT_EQ(ZX_OK, vcpu->WritePendingEvent(pf).status_value(), "queue #PF\n");

  zx_port_packet_t ec = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(ec).status_value(), "enter #2 (deliver #PF)\n");
  ASSERT_EQ(static_cast<uint8_t>(ZX_PKT_TYPE_GUEST_IO), static_cast<uint8_t>(ec.type), "io\n");
  ASSERT_EQ(static_cast<uint32_t>(kIdtvReportPort), static_cast<uint32_t>(ec.guest_io.port),
            "the guest's #PF handler must have run\n");
  EXPECT_EQ(kErrorCode, static_cast<uint32_t>(ec.guest_io.data[0]),
            "the error code must survive being carried through the IDT-vectoring fields\n");
  EXPECT_EQ(1u, vcpu->Vectoring().reinjections,
            "the #PF's own frame push must have faulted mid-delivery, exactly once\n");
  EXPECT_EQ(static_cast<uint32_t>(X86_INT_PAGE_FAULT), VectoringVector(vcpu),
            "the recorded vector must be the #PF, not the EPT violation\n");
  EXPECT_EQ(kIdtvTypeHardwareException, VectoringType(vcpu),
            "recorded as a hardware exception\n");
  EXPECT_TRUE(VectoringHasErrorCode(vcpu),
            "with the error-code bit set, which is where the error code came back from\n");

  zx_port_packet_t c = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(c).status_value(), "enter #3 (CR2)\n");
  ASSERT_EQ(static_cast<uint32_t>(kIdtvCr2Port), static_cast<uint32_t>(c.guest_io.port),
            "CR2 report port\n");
  EXPECT_EQ(static_cast<uint32_t>((kFaultAddr >> 12) & 0xFF),
            static_cast<uint32_t>(c.guest_io.data[0]),
            "CR2 must survive the aborted delivery as well as the error code\n");

  printf("faulting-delivery payload OK: #PF(error_code=%#x, cr2=%#lx) was interrupted mid-delivery "
         "on a pristine stack, re-injected (%lu), and the guest handler read back error code %#x "
         "and CR2 bits[19:12] %#x\n",
         kErrorCode, kFaultAddr, vcpu->Vectoring().reinjections,
         static_cast<uint32_t>(ec.guest_io.data[0]), static_cast<uint32_t>(c.guest_io.data[0]));
#else
  printf("Not x86_64; skipping.\n");
#endif  // __x86_64__

  END_TEST;
}

// THE DECISIVE ONE. Everything above could still be satisfied by a fix that
// replayed the last event unconditionally, or that quietly dropped whatever else
// was queued while it dealt with the interrupted delivery. So: two distinct
// vectors are queued before the faulting delivery, and the guest reports every
// entry into every handler. The one that gets interrupted mid-delivery must
// arrive exactly once, the one that was merely waiting must arrive exactly once
// after it, and then the guest must run on to completion with nothing else
// arriving at all.
//
// That single construction catches three different wrong fixes: duplicate
// delivery (a third handler report), a queued vector consumed and lost while the
// interrupted one was being put back (only one report), and re-injection of an
// event that had not been interrupted (a report after the guest finished).
bool vcpu_reinjected_event_and_queued_event_each_arrive_once() {
  BEGIN_TEST;

#ifdef __x86_64__
  // The lower vector is queued too; InterruptTracker::Pop scans highest-first,
  // so kIdtvVector (0x52) is the one whose delivery gets interrupted and 0x51
  // is the one left waiting.
  constexpr uint32_t kQueuedVector = 0x51;

  fbl::RefPtr<VmObjectPaged> ram;
  ASSERT_EQ(ZX_OK, VmObjectPaged::Create(PMM_ALLOC_FLAG_ANY, 0u, kGuestRamSize, &ram), "ram\n");

  ASSERT_EQ(ZX_OK, WriteVectoringGuest(ram, kIdtvLoopCode, sizeof(kIdtvLoopCode)), "build guest\n");
  ASSERT_EQ(ZX_OK, RewriteHandlersToResumeLoop(ram), "resuming handlers\n");

  auto lg = CreateLiveGuest(ram, kCodeGpa);
  if (lg.is_error() && lg.status_value() == ZX_ERR_NOT_SUPPORTED) {
    printf("VMX not supported here; skipping exact-once test.\n");
    return true;
  }
  ASSERT_EQ(ZX_OK, lg.status_value(), "create live guest\n");
  Vcpu* vcpu = lg->vcpu.get();
  ASSERT_EQ(ZX_OK, lg->guest->SetTrap(ZX_GUEST_TRAP_IO, kIdtvReportPort, 1, nullptr,
                                      kIdtvReportPort)
                       .status_value(),
            "trap report port\n");
  ASSERT_EQ(ZX_OK, lg->guest->SetTrap(ZX_GUEST_TRAP_IO, 0x12, 1, nullptr, 0x12).status_value(),
            "trap done port\n");
  ASSERT_EQ(ZX_OK, SetVectoringTables(vcpu), "GDTR/IDTR/RSP\n");

  zx_port_packet_t p = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(p).status_value(), "enter #1\n");
  ASSERT_EQ(0x10u, p.guest_io.port, "readiness exit\n");
  ASSERT_EQ(ZX_OK, OverwriteStackWithPristinePage(lg->guest.get()), "pristine stack page\n");

  // Both queued before a single entry: the tracker hands out the higher vector
  // first, its delivery faults on the pristine stack, and the lower one must
  // still be there afterwards.
  ASSERT_EQ(ZX_OK, vcpu->Interrupt(kQueuedVector).status_value(), "queue the waiting vector\n");
  ASSERT_EQ(ZX_OK, vcpu->Interrupt(kIdtvVector).status_value(), "queue the vector to interrupt\n");

  zx_port_packet_t first = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(first).status_value(), "enter #2\n");
  ASSERT_EQ(static_cast<uint32_t>(kIdtvReportPort), static_cast<uint32_t>(first.guest_io.port),
            "the interrupted delivery must have been put back and taken\n");
  EXPECT_EQ(kIdtvVector, static_cast<uint32_t>(first.guest_io.data[0]),
            "highest-priority vector arrives first\n");
  EXPECT_EQ(1u, vcpu->Vectoring().reinjections, "exactly one recovery so far\n");
  EXPECT_EQ(kIdtvVector, VectoringVector(vcpu), "and it was that vector that was interrupted\n");

  // The vector that was merely waiting was not consumed by the entry that got
  // used up on the re-injection. It arrives next, once.
  zx_port_packet_t second = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(second).status_value(), "enter #3\n");
  ASSERT_EQ(static_cast<uint32_t>(kIdtvReportPort), static_cast<uint32_t>(second.guest_io.port),
            "the queued vector must not have been lost while the other was put back\n");
  EXPECT_EQ(kQueuedVector, static_cast<uint32_t>(second.guest_io.data[0]),
            "and it must be the one that was queued, not a repeat\n");
  EXPECT_EQ(1u, vcpu->Vectoring().reinjections,
            "an ordinary delivery must not be counted as a recovery\n");

  // And nothing else. If either vector were delivered twice this would be a
  // third report on the handler port instead of the guest's completion.
  zx_port_packet_t done = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(done).status_value(), "enter #4\n");
  ASSERT_EQ(static_cast<uint8_t>(ZX_PKT_TYPE_GUEST_IO), static_cast<uint8_t>(done.type), "io\n");
  EXPECT_EQ(0x12u, static_cast<uint32_t>(done.guest_io.port),
            "the guest must run to completion: a third handler report here means an event was "
            "delivered twice\n");
  EXPECT_EQ(0xA3u, static_cast<uint32_t>(done.guest_io.data[0]), "completion sentinel\n");
  EXPECT_EQ(1u, vcpu->Vectoring().reinjections, "and no spurious re-injection afterwards\n");

  printf("exact-once OK: with %#x and %#x both queued, %#x was interrupted mid-delivery and "
         "recovered (1 re-injection), %#x followed, each exactly once, and the guest then ran "
         "to completion (%#x)\n",
         kIdtvVector, kQueuedVector, static_cast<uint32_t>(first.guest_io.data[0]),
         static_cast<uint32_t>(second.guest_io.data[0]), done.guest_io.data[0]);
#else
  printf("Not x86_64; skipping.\n");
#endif  // __x86_64__

  END_TEST;
}

// NMIs go first. `local_apic_maybe_interrupt` says so in a comment — "1) NMIs,
// 2) interrupts, 3) generated exceptions" — and implements it by asking the
// tracker for the NMI before scanning for anything else. That ask could never
// succeed: `InterruptTracker::TryPop`'s bounds test was inverted, so it rejected
// every vector a caller could legitimately pass. The NMI then fell through to
// the general scan, which runs highest-vector-first, and vector 2 lost to every
// ordinary interrupt.
//
// Asserting that an NMI arrives is not enough to see that — it arrives either
// way, just late. This queues an ordinary vector and an NMI before the same
// entry and asserts the ORDER.
bool vcpu_nmi_takes_priority_over_a_queued_interrupt() {
  BEGIN_TEST;

#ifdef __x86_64__
  constexpr uint32_t kLowPriority = 0x51;  // higher *vector*, lower priority.

  fbl::RefPtr<VmObjectPaged> ram;
  ASSERT_EQ(ZX_OK, VmObjectPaged::Create(PMM_ALLOC_FLAG_ANY, 0u, kGuestRamSize, &ram), "ram\n");
  ASSERT_EQ(ZX_OK, WriteVectoringGuest(ram, kIdtvLoopCode, sizeof(kIdtvLoopCode)), "build guest\n");
  ASSERT_EQ(ZX_OK, RewriteHandlersToResumeLoop(ram), "resuming handlers\n");

  auto lg = CreateLiveGuest(ram, kCodeGpa);
  if (lg.is_error() && lg.status_value() == ZX_ERR_NOT_SUPPORTED) {
    printf("VMX not supported here; skipping NMI-priority test.\n");
    return true;
  }
  ASSERT_EQ(ZX_OK, lg.status_value(), "create live guest\n");
  Vcpu* vcpu = lg->vcpu.get();
  ASSERT_EQ(ZX_OK, lg->guest->SetTrap(ZX_GUEST_TRAP_IO, kIdtvReportPort, 1, nullptr,
                                      kIdtvReportPort)
                       .status_value(),
            "trap report port\n");
  ASSERT_EQ(ZX_OK, lg->guest
                       ->SetTrap(ZX_GUEST_TRAP_IO, kIdtvDonePort, 1, nullptr, kIdtvDonePort)
                       .status_value(),
            "trap done port\n");
  ASSERT_EQ(ZX_OK, SetVectoringTables(vcpu), "GDTR/IDTR/RSP\n");

  zx_port_packet_t p = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(p).status_value(), "enter #1\n");
  ASSERT_EQ(0x10u, p.guest_io.port, "readiness exit\n");

  // Queued before the same entry, ordinary vector first so that "the NMI won"
  // cannot be an artefact of the order they were requested in.
  ASSERT_EQ(ZX_OK, vcpu->Interrupt(kLowPriority).status_value(), "queue the ordinary vector\n");
  ASSERT_EQ(ZX_OK, vcpu->Interrupt(X86_INT_NMI).status_value(), "queue the NMI\n");

  zx_port_packet_t first = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(first).status_value(), "enter #2\n");
  ASSERT_EQ(static_cast<uint32_t>(kIdtvReportPort), static_cast<uint32_t>(first.guest_io.port),
            "a handler must have run\n");
  EXPECT_EQ(static_cast<uint32_t>(X86_INT_NMI), static_cast<uint32_t>(first.guest_io.data[0]),
            "the NMI must be delivered before the ordinary interrupt queued alongside it\n");

  zx_port_packet_t second = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(second).status_value(), "enter #3\n");
  ASSERT_EQ(static_cast<uint32_t>(kIdtvReportPort), static_cast<uint32_t>(second.guest_io.port),
            "the ordinary vector must still be delivered, just second\n");
  EXPECT_EQ(kLowPriority, static_cast<uint32_t>(second.guest_io.data[0]), "and it must be it\n");

  printf("NMI-priority OK: with vector %#x and the NMI queued before the same entry, the NMI "
         "(%#x) arrived first and %#x followed\n",
         kLowPriority, first.guest_io.data[0], second.guest_io.data[0]);
#else
  printf("Not x86_64; skipping.\n");
#endif  // __x86_64__

  END_TEST;
}

// The two meanings of vector 21 and the reserved range above it must remain
// distinguishable. The bare, cross-thread ABI is for asynchronous device/IPI
// interrupts; Windows uses vector 31 in an ICR. Architectural #CP at vector 21
// is an exception with an error code and uses the typed pending-event ABI.
bool vcpu_injection_abi_matches_what_can_be_delivered() {
  BEGIN_TEST;

#ifdef __x86_64__
  fbl::RefPtr<VmObjectPaged> ram;
  ASSERT_EQ(ZX_OK, VmObjectPaged::Create(PMM_ALLOC_FLAG_ANY, 0u, kGuestRamSize, &ram), "ram\n");
  // sti; nop; mov al,0x5E; out 0x10,al; hlt. If the queued external vector is
  // initially held by IF, the interrupt-window exit after STI releases it.
  const uint8_t code[] = {0xFB, 0x90, 0xB0, 0x5E, 0xE6, 0x10, 0xF4};
  ASSERT_EQ(ZX_OK, WriteVectoringGuest(ram, code, sizeof(code)), "build guest\n");

  auto lg = CreateLiveGuest(ram, kCodeGpa);
  if (lg.is_error() && lg.status_value() == ZX_ERR_NOT_SUPPORTED) {
    printf("VMX not supported here; skipping injection-ABI test.\n");
    return true;
  }
  ASSERT_EQ(ZX_OK, lg.status_value(), "create live guest\n");
  Vcpu* vcpu = lg->vcpu.get();
  // Trap the vector handler's report port. Without this the handler's
  // `out kIdtvReportPort, al` (WriteVectoringGuest) is discarded rather than
  // exiting, so the Enter below never returns the report packet the assertions
  // expect: the handler falls through to its EOI and `hlt`, and the VCPU parks
  // in handle_hlt's infinite Wait. CreateLiveGuest only traps 0x10/0x11, so
  // (unlike the other vectoring tests, which install this trap themselves) this
  // test hung under real VMX and only self-skipped under TCG. Only 0x30 is
  // needed here: the single delivered vector reports there; 0x31/kIdtvCr2Port
  // is used only by the #PF/CR2 tests, and the #CP path here is a
  // WritePendingEvent validation that is never delivered to the guest.
  ASSERT_EQ(ZX_OK, lg->guest
                       ->SetTrap(ZX_GUEST_TRAP_IO, kIdtvReportPort, 1, nullptr, kIdtvReportPort)
                       .status_value(),
            "trap report port\n");
  ASSERT_EQ(ZX_OK, SetVectoringTables(vcpu), "GDTR/IDTR/RSP\n");

  // #CP carries an error code, so the topic must want one — and must refuse the
  // form that VM entry would reject.
  zx_vcpu_pending_event_t cp =
      MakePendingEvent(ZX_VCPU_EVENT_HARDWARE_EXCEPTION, X86_INT_CONTROL_PROTECTION);
  cp.flags = ZX_VCPU_EVENT_ERROR_CODE_VALID;
  cp.error_code = 0x1234;
  EXPECT_EQ(ZX_OK, vcpu->WritePendingEvent(cp).status_value(),
            "a #CP with its error code must be accepted\n");
  zx_vcpu_pending_event_t cp_bad =
      MakePendingEvent(ZX_VCPU_EVENT_HARDWARE_EXCEPTION, X86_INT_CONTROL_PROTECTION);
  EXPECT_EQ(ZX_ERR_INVALID_ARGS, vcpu->WritePendingEvent(cp_bad).status_value(),
            "a #CP without one must be refused\n");

  // Un-queue it, then exercise the exact low external vector Windows uses.
  zx_vcpu_pending_event_t none = MakePendingEvent(ZX_VCPU_EVENT_NONE, 0);
  ASSERT_EQ(ZX_OK, vcpu->WritePendingEvent(none).status_value(), "clear\n");
  constexpr uint32_t kWindowsIpiVector = 0x1f;
  ASSERT_EQ(ZX_OK, vcpu->Interrupt(kWindowsIpiVector).status_value(),
            "queue low external IPI vector\n");
  ASSERT_TRUE(vcpu->InterruptPending(kWindowsIpiVector), "the IPI must be pending\n");
  zx_port_packet_t p = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(p).status_value(), "deliver low external IPI vector\n");
  ASSERT_EQ(static_cast<uint8_t>(ZX_PKT_TYPE_GUEST_IO), static_cast<uint8_t>(p.type), "io\n");
  EXPECT_EQ(static_cast<uint32_t>(kIdtvReportPort), static_cast<uint32_t>(p.guest_io.port),
            "the vector handler must report\n");
  EXPECT_EQ(kWindowsIpiVector, static_cast<uint32_t>(p.guest_io.data[0]),
            "the guest must receive vector 31 as an external interrupt\n");
  EXPECT_TRUE(vcpu->InService(kWindowsIpiVector), "the external IPI must enter the ISR\n");
  EXPECT_FALSE(vcpu->InterruptPending(kWindowsIpiVector), "delivery must consume the request\n");

  // The neighbouring established meanings remain accepted.
  EXPECT_EQ(ZX_OK, vcpu->Interrupt(X86_INT_VIRT).status_value(), "#VE remains injectable\n");
  EXPECT_EQ(ZX_OK, vcpu->Interrupt(X86_INT_PLATFORM_BASE).status_value(),
            "the first platform vector is still injectable\n");

  printf("injection-ABI OK: bare IPI vector %#x delivered as an external interrupt and entered "
         "the ISR; typed #CP accepted with its error code and refused without\n",
         kWindowsIpiVector);
#else
  printf("Not x86_64; skipping.\n");
#endif  // __x86_64__

  END_TEST;
}

// THE OTHER WAY AN INTERRUPTED DELIVERY CAN BE LOST: not by being dropped, but
// by being forced into a VM entry the processor refuses.
//
// The re-injection above put the event back unconditionally. That was sound
// while the guest state it went back into was necessarily the state it came out
// of. It no longer is: a VMM can call Vcpu::RestoreArchState between the exit
// that aborted the delivery and the entry that puts the event back, and now that
// RFLAGS.IF is genuinely restorable (see vcpu_state_interrupt_flag_roundtrip),
// it can come back CLEAR. Volume 3, Section 26.3.1.4 then refuses the entry
// outright: if the VM-entry interruption-information field is valid and its type
// is external interrupt, RFLAGS.IF must be 1. The refusal is a VM-entry failure
// (exit reason 0x21), which ends the run with ZX_ERR_BAD_STATE and names
// nothing — the shape of failure that is hardest to diagnose from userspace.
//
// So this is a two-sided assertion, and both sides matter:
//   * the entry must NOT fail — the event may not be forced in; and
//   * the event must NOT be dropped either. Simply skipping the injection would
//     satisfy the first half and silently lose an interrupt, which is the very
//     bug re-injection exists to fix, because this event has no queue behind it
//     (asserted below: the tracker no longer holds the vector at the point the
//     exit is handed to us). The vector has to be put back into the interrupt
//     tracker and delivered when the guest is injectable again.
//
// Getting the exit into the test's hands is the only piece of machinery here:
// the usual reproduction faults on an unbacked stack page, which Enter() fixes
// up internally and never returns from. A ZX_GUEST_TRAP_MEM over a decoy stack
// page unmaps it *and* routes the resulting fault to the VMM, so the aborted
// delivery is observable from outside Enter() — which is exactly the window in
// which a snapshot-restoring VMM acts.
bool vcpu_interrupted_delivery_deferred_when_if_clear() {
  BEGIN_TEST;

#ifdef __x86_64__
  // A stack page of its own, covered by a MEM trap, used only for the delivery
  // that is meant to abort. The real stack (kIdtvStackGpa) stays untrapped so
  // the later, successful delivery can complete.
  constexpr uint64_t kTrapStackGpa = 0xC000;
  constexpr uint64_t kTrapStackTop = 0xD000;
  // A stub the guest runs while its interrupts are off, so the entry under test
  // has somewhere to land and something to report. `jmp $`, not `hlt`: a halt
  // with interrupts disabled is a different exit and a different story.
  constexpr uint64_t kIfOffStubGpa = 0xE000;
  constexpr uint16_t kIfOffPort = 0x13;
  constexpr uint8_t kIfOffToken = 0xA5;

  fbl::RefPtr<VmObjectPaged> ram;
  ASSERT_EQ(ZX_OK, VmObjectPaged::Create(PMM_ALLOC_FLAG_ANY, 0u, kGuestRamSize, &ram), "ram\n");

  // FB       sti
  // 90       nop            ; retire the one-instruction STI shadow
  // B0 A1    mov al, 0xA1
  // E6 10    out 0x10, al   ; exit #1: interruptible, stack untouched
  // EB FE    jmp $          ; offset 6 — spin until the interrupt vectors out
  const uint8_t code[] = {0xFB, 0x90, 0xB0, 0xA1, 0xE6, 0x10, 0xEB, 0xFE};
  ASSERT_EQ(ZX_OK, WriteVectoringGuest(ram, code, sizeof(code)), "build guest\n");
  // B0 A5    mov al, 0xA5
  // E6 13    out 0x13, al
  // EB FE    jmp $
  const uint8_t stub[] = {0xB0, kIfOffToken, 0xE6, static_cast<uint8_t>(kIfOffPort), 0xEB, 0xFE};
  ASSERT_EQ(ZX_OK, ram->Write(stub, kIfOffStubGpa, sizeof(stub)), "if-off stub\n");
  ASSERT_EQ(ZX_OK, ram->CommitRange(0, kGuestRamSize), "commit\n");

  auto lg = CreateLiveGuest(ram, kCodeGpa);
  if (lg.is_error() && lg.status_value() == ZX_ERR_NOT_SUPPORTED) {
    printf("VMX not supported here; skipping deferred-re-injection test.\n");
    return true;
  }
  ASSERT_EQ(ZX_OK, lg.status_value(), "create live guest\n");
  Vcpu* vcpu = lg->vcpu.get();
  ASSERT_EQ(
      ZX_OK,
      lg->guest->SetTrap(ZX_GUEST_TRAP_IO, kIdtvReportPort, 1, nullptr, kIdtvReportPort)
          .status_value(),
      "trap report port\n");
  ASSERT_EQ(ZX_OK,
            lg->guest->SetTrap(ZX_GUEST_TRAP_IO, kIfOffPort, 1, nullptr, kIfOffPort).status_value(),
            "trap if-off port\n");
  // Unmaps the decoy stack page and routes its faults to us instead of to
  // GuestPhysicalAspace::PageFault.
  ASSERT_EQ(ZX_OK,
            lg->guest->SetTrap(ZX_GUEST_TRAP_MEM, kTrapStackGpa, 0x1000, nullptr, kTrapStackGpa)
                .status_value(),
            "trap decoy stack page\n");
  ASSERT_EQ(ZX_OK, SetVectoringTables(vcpu), "GDTR/IDTR/RSP\n");

  // VcpuArchState carries a 1 KiB XSAVE area; keep it off the kernel stack.
  fbl::AllocChecker ac;
  ktl::unique_ptr<VcpuArchState> s(new (&ac) VcpuArchState{});
  ASSERT_TRUE(ac.check(), "alloc arch state\n");

  // Point the stack at the trapped page for the delivery that must abort.
  ASSERT_EQ(ZX_OK, vcpu->SaveArchState(*s).status_value(), "save #0\n");
  s->regs.rsp = kTrapStackTop;
  ASSERT_EQ(ZX_OK, vcpu->RestoreArchState(*s).status_value(), "point rsp at the decoy stack\n");

  zx_port_packet_t p = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(p).status_value(), "enter #1\n");
  ASSERT_EQ(static_cast<uint8_t>(ZX_PKT_TYPE_GUEST_IO), static_cast<uint8_t>(p.type),
            "readiness exit must be an I/O packet before its fields are read\n");
  ASSERT_EQ(0x10u, p.guest_io.port, "readiness exit\n");
  ASSERT_EQ(0xA1u, static_cast<uint32_t>(p.guest_io.data[0]), "readiness sentinel\n");
  EXPECT_EQ(0u, vcpu->Vectoring().reinjections, "nothing re-injected yet\n");
  EXPECT_EQ(0u, vcpu->Vectoring().deferrals, "nothing deferred yet\n");

  ASSERT_EQ(ZX_OK, vcpu->Interrupt(kIdtvVector).status_value(), "inject vector\n");
  ASSERT_TRUE(vcpu->InterruptPending(kIdtvVector), "queued in the tracker\n");

  // The interrupt frame's push takes the MEM trap, so the delivery is abandoned
  // and the exit is handed to us rather than fixed up inside Enter().
  zx_port_packet_t mem = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(mem).status_value(), "enter #2 (delivery aborts)\n");
  ASSERT_EQ(static_cast<uint8_t>(ZX_PKT_TYPE_GUEST_MEM), static_cast<uint8_t>(mem.type),
            "the aborted delivery must surface as a memory exit\n");
  ASSERT_EQ(kTrapStackGpa, mem.guest_mem.addr & ~UINT64_C(0xFFF),
            "on the decoy stack page the frame was being pushed to\n");
  // The processor's own account of what it abandoned.
  ASSERT_TRUE(VectoringValid(vcpu), "IDT-vectoring field must be valid\n");
  ASSERT_EQ(kIdtvVector, VectoringVector(vcpu), "and name the injected vector\n");
  ASSERT_EQ(kIdtvTypeExternalInterrupt, VectoringType(vcpu), "as an external interrupt\n");
  EXPECT_EQ(0u, vcpu->Vectoring().reinjections, "not put back yet — we are holding the exit\n");
  // The load-bearing premise of the whole re-injection mechanism, asserted rather
  // than assumed: at this instant the VMCS field is the ONLY copy of the event.
  ASSERT_FALSE(vcpu->InterruptPending(kIdtvVector),
               "the entry that injected it popped it; the tracker no longer holds it\n");

  // The VMM now restores a snapshot taken with interrupts disabled — and parks
  // the guest on the if-off stub with an ordinary, untrapped stack.
  ASSERT_EQ(ZX_OK, vcpu->SaveArchState(*s).status_value(), "save mid-flight\n");
  ASSERT_TRUE((s->regs.rflags & X86_FLAGS_IF) != 0, "the guest's own sti is still in force\n");
  s->regs.rflags &= ~static_cast<uint64_t>(X86_FLAGS_IF);
  s->rip = kIfOffStubGpa;
  s->regs.rsp = kIdtvStackTop;
  ASSERT_EQ(ZX_OK, vcpu->RestoreArchState(*s).status_value(), "restore with IF clear\n");

  // THE ENTRY UNDER TEST. Before the fix this re-issued the external interrupt
  // over RFLAGS.IF=0 and the processor refused the entry. Measured, so that the
  // failure this guards against is on record rather than described: the kernel
  // log carried
  //     hypervisor: VM exit handler for ENTRY_FAILURE_GUEST_STATE (33) returned -20
  //     ... RIP: 0xe000 ... entry failure: 1
  // and the VMM was handed ZX_PKT_TYPE_GUEST_HALT with reason
  // ZX_PKT_GUEST_HALT_UNHANDLED — the run over, the guest killed, at an entry it
  // had nothing to do with and at a RIP that names nothing relevant.
  zx_port_packet_t off = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(off).status_value(),
            "an interrupted delivery must not be forced into an entry RFLAGS.IF=0 forbids\n");
  ASSERT_NE(static_cast<uint8_t>(ZX_PKT_TYPE_GUEST_HALT), static_cast<uint8_t>(off.type),
            "the entry must not have been refused (pre-fix: halt, ZX_PKT_GUEST_HALT_UNHANDLED, "
            "exit_reason 33 = ENTRY_FAILURE_GUEST_STATE)\n");
  ASSERT_EQ(static_cast<uint8_t>(ZX_PKT_TYPE_GUEST_IO), static_cast<uint8_t>(off.type), "io\n");
  ASSERT_EQ(static_cast<uint32_t>(kIfOffPort), static_cast<uint32_t>(off.guest_io.port),
            "the guest must have run with its interrupts off\n");
  EXPECT_EQ(static_cast<uint32_t>(kIfOffToken), static_cast<uint32_t>(off.guest_io.data[0]),
            "if-off sentinel\n");
  // Deferred, not injected — and specifically deferred into the tracker, which is
  // what gives the event the queue it did not have. An implementation that merely
  // held the event in `vectoring_event_` fails this line; one that dropped it
  // fails the delivery below.
  EXPECT_EQ(1u, vcpu->Vectoring().deferrals, "deferred exactly once\n");
  EXPECT_EQ(0u, vcpu->Vectoring().reinjections, "and never force-injected\n");
  ASSERT_TRUE(vcpu->InterruptPending(kIdtvVector),
              "the deferred vector must be back in the interrupt tracker\n");

  // And it must still arrive. Re-enable interrupts, park the guest back on its
  // spin, and the vector has to vector through the guest's own IDT.
  ASSERT_EQ(ZX_OK, vcpu->SaveArchState(*s).status_value(), "save (if-off)\n");
  s->regs.rflags |= X86_FLAGS_IF;
  s->rip = kCodeGpa + 6;  // the `jmp $`
  s->regs.rsp = kIdtvStackTop;
  ASSERT_EQ(ZX_OK, vcpu->RestoreArchState(*s).status_value(), "restore with IF set\n");

  zx_port_packet_t handled = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(handled).status_value(), "enter #4 (deliver)\n");
  ASSERT_EQ(static_cast<uint8_t>(ZX_PKT_TYPE_GUEST_IO), static_cast<uint8_t>(handled.type),
            "the delivery must end in an I/O packet before its fields are read\n");
  ASSERT_EQ(static_cast<uint32_t>(kIdtvReportPort), static_cast<uint32_t>(handled.guest_io.port),
            "the guest's own IDT handler must have run\n");
  EXPECT_EQ(kIdtvVector, static_cast<uint32_t>(handled.guest_io.data[0]),
            "and it must be the handler for the deferred vector\n");
  EXPECT_FALSE(vcpu->InterruptPending(kIdtvVector), "which consumed it from the tracker\n");

  printf("deferred re-injection OK: vector %#x was abandoned mid-delivery (idt_vectoring=%#x), the "
         "VMM then restored RFLAGS.IF=0; the entry that followed did not fail — the event was "
         "re-queued (%lu deferral(s), %lu forced re-injection(s)) and delivered to the guest's own "
         "handler, which reported %#x, once interrupts came back on\n",
         kIdtvVector, vcpu->Vectoring().last_info, vcpu->Vectoring().deferrals,
         vcpu->Vectoring().reinjections, handled.guest_io.data[0]);
#else
  printf("Not x86_64; skipping.\n");
#endif  // __x86_64__

  END_TEST;
}

// THE SAME FIX, ON THE OTHER TYPE IT REACHES: an interrupted NMI delivery.
//
// The external-interrupt test above leaves the NMI half of the injectability
// test unexercised, so an implementation that handled only external interrupts
// would pass everything there. This is that gap, and it is not a hypothetical
// one — the pre-fix failure mode is the same shape and just as fatal, for a
// different reason in a different sentence of the SDM. Volume 3's checks on
// guest non-register state refuse a VM entry that injects an external interrupt
// OR an NMI while blocking-by-MOV-SS is set; can_inject_nmi() says as much in
// its own comment ("it turns a deliverable NMI into an opaque VM-entry failure
// that kills the run"), and the unconditional re-issue walked straight into it.
//
// Two things about the NMI path have no analogue on the external-interrupt side
// and are checked here:
//   * blocking-by-NMI is cleared BEFORE injectability is tested, not after the
//     injection as it used to be. An aborted NMI delivery sets that bit itself,
//     so testing first would defer every re-injected NMI on the strength of the
//     block it created — turning the normal case into the deferred case forever.
//     If that clear were moved back, or dropped, this test hangs or fails rather
//     than passing quietly.
//   * the deferred vector goes back as vector 2, which InterruptTracker pops by
//     name ahead of everything else, so the NMI keeps its priority across the
//     deferral.
//
// RFLAGS.IF is deliberately left SET here. IF does not gate NMIs, so it is not
// the interesting variable; leaving it set also means interrupt-window exiting
// — the only window instrument available without virtual NMIs — actually fires
// once the guest retires one instruction and MOV-SS blocking lapses. A deferred
// NMI under IF=0 has no such guarantee and would sit until the next unrelated
// exit; that is a known limitation of not enabling virtual NMIs, called out in
// local_apic_maybe_interrupt, and is not what this test is about.
//
// The blocked entry is stopped at an exit of its own rather than being allowed
// to run on to the delivery, so that every wrong implementation fails an
// assertion instead of hanging in a guest that never reports. See the
// one-instruction stub below.
bool vcpu_interrupted_nmi_deferred_when_blocked() {
  BEGIN_TEST;

#ifdef __x86_64__
  constexpr uint64_t kTrapStackGpa = 0xC000;
  constexpr uint64_t kTrapStackTop = 0xD000;
  // GUEST_INTERRUPTIBILITY_STATE bit 1, "blocking by MOV SS". The hypervisor's
  // own constant lives in its private header, so it is spelled out here.
  constexpr uint32_t kMovSsBlocking = 1u << 1;
  // GUEST_INTERRUPTIBILITY_STATE bit 3, "blocking by NMI".
  constexpr uint32_t kNmiBlocking = 1u << 3;
  // Interruption type 2 in bits 10:8 of the IDT-vectoring field: NMI.
  constexpr uint32_t kIdtvTypeNmi = 2;
  // A ONE-INSTRUCTION stub, and the length is the point. The blocked entry has
  // to be observable on its own — otherwise "deferred" and "delivered" happen
  // inside a single Enter() and every wrong implementation that eventually
  // delivers the NMI looks identical to the right one, while every one that
  // loses it hangs instead of failing an assertion. `out` retires, which lapses
  // MOV-SS blocking, and exits in the same breath: the exit is taken for the I/O
  // instruction rather than for the interrupt window, so the test gets the VCPU
  // back with the NMI still queued and can inspect it.
  constexpr uint64_t kNmiStubGpa = 0xE000;
  constexpr uint16_t kNmiStubPort = 0x13;

  fbl::RefPtr<VmObjectPaged> ram;
  ASSERT_EQ(ZX_OK, VmObjectPaged::Create(PMM_ALLOC_FLAG_ANY, 0u, kGuestRamSize, &ram), "ram\n");

  // FB 90    sti; nop        — IF set, so the window instrument can work later
  // B0 A1    mov al, 0xA1
  // E6 10    out 0x10, al    ; readiness
  // EB FE    jmp $           ; offset 6
  const uint8_t code[] = {0xFB, 0x90, 0xB0, 0xA1, 0xE6, 0x10, 0xEB, 0xFE};
  ASSERT_EQ(ZX_OK, WriteVectoringGuest(ram, code, sizeof(code)), "build guest\n");
  // E6 13    out 0x13, al   ; the single instruction of the blocked entry
  // EB FE    jmp $          ; where the NMI finds the guest on the entry after
  const uint8_t stub[] = {0xE6, static_cast<uint8_t>(kNmiStubPort), 0xEB, 0xFE};
  ASSERT_EQ(ZX_OK, ram->Write(stub, kNmiStubGpa, sizeof(stub)), "one-instruction stub\n");
  ASSERT_EQ(ZX_OK, ram->CommitRange(0, kGuestRamSize), "commit\n");

  auto lg = CreateLiveGuest(ram, kCodeGpa);
  if (lg.is_error() && lg.status_value() == ZX_ERR_NOT_SUPPORTED) {
    printf("VMX not supported here; skipping deferred-NMI test.\n");
    return true;
  }
  ASSERT_EQ(ZX_OK, lg.status_value(), "create live guest\n");
  Vcpu* vcpu = lg->vcpu.get();
  ASSERT_EQ(
      ZX_OK,
      lg->guest->SetTrap(ZX_GUEST_TRAP_IO, kIdtvReportPort, 1, nullptr, kIdtvReportPort)
          .status_value(),
      "trap report port\n");
  ASSERT_EQ(
      ZX_OK,
      lg->guest->SetTrap(ZX_GUEST_TRAP_IO, kNmiStubPort, 1, nullptr, kNmiStubPort).status_value(),
      "trap stub port\n");
  ASSERT_EQ(ZX_OK,
            lg->guest->SetTrap(ZX_GUEST_TRAP_MEM, kTrapStackGpa, 0x1000, nullptr, kTrapStackGpa)
                .status_value(),
            "trap decoy stack page\n");
  ASSERT_EQ(ZX_OK, SetVectoringTables(vcpu), "GDTR/IDTR/RSP\n");

  fbl::AllocChecker ac;
  ktl::unique_ptr<VcpuArchState> s(new (&ac) VcpuArchState{});
  ASSERT_TRUE(ac.check(), "alloc arch state\n");
  ktl::unique_ptr<VcpuArchState> after(new (&ac) VcpuArchState{});
  ASSERT_TRUE(ac.check(), "alloc arch state (2)\n");

  ASSERT_EQ(ZX_OK, vcpu->SaveArchState(*s).status_value(), "save #0\n");
  s->regs.rsp = kTrapStackTop;
  ASSERT_EQ(ZX_OK, vcpu->RestoreArchState(*s).status_value(), "point rsp at the decoy stack\n");

  zx_port_packet_t p = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(p).status_value(), "enter #1\n");
  ASSERT_EQ(static_cast<uint8_t>(ZX_PKT_TYPE_GUEST_IO), static_cast<uint8_t>(p.type), "io\n");
  ASSERT_EQ(0x10u, p.guest_io.port, "readiness exit\n");
  EXPECT_EQ(0u, vcpu->Vectoring().deferrals, "nothing deferred yet\n");

  ASSERT_EQ(ZX_OK, vcpu->Interrupt(X86_INT_NMI).status_value(), "queue an NMI\n");
  ASSERT_TRUE(vcpu->InterruptPending(X86_INT_NMI), "queued in the tracker\n");

  // The NMI's own frame push takes the MEM trap, so the delivery is abandoned
  // and handed to us mid-flight.
  zx_port_packet_t mem = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(mem).status_value(), "enter #2 (NMI delivery aborts)\n");
  ASSERT_EQ(static_cast<uint8_t>(ZX_PKT_TYPE_GUEST_MEM), static_cast<uint8_t>(mem.type),
            "the aborted delivery must surface as a memory exit\n");
  ASSERT_EQ(kTrapStackGpa, mem.guest_mem.addr & ~UINT64_C(0xFFF), "on the decoy stack page\n");
  ASSERT_TRUE(VectoringValid(vcpu), "IDT-vectoring field must be valid\n");
  ASSERT_EQ(static_cast<uint32_t>(X86_INT_NMI), VectoringVector(vcpu), "vector 2\n");
  ASSERT_EQ(kIdtvTypeNmi, VectoringType(vcpu), "recorded as an NMI, not an exception\n");
  ASSERT_FALSE(vcpu->InterruptPending(X86_INT_NMI),
               "the entry that injected it popped it; the tracker no longer holds it\n");

  // The VMM restores a state in which the NMI cannot be taken: blocking by
  // MOV-SS. IF stays set — it does not gate NMIs, and it is what lets the window
  // instrument fire. Also move the stack off the trapped page so the delivery
  // that follows can complete.
  ASSERT_EQ(ZX_OK, vcpu->SaveArchState(*s).status_value(), "save mid-flight\n");
  ASSERT_TRUE((s->regs.rflags & X86_FLAGS_IF) != 0, "IF is still set\n");
  // Whether the aborted delivery left blocking-by-NMI set is the processor's
  // choice, not ours ("may have left" is what the SDM supports), so it is
  // recorded rather than assumed — the "and it was cleared" assertion below is
  // only meaningful if it was set, and the printf says which case ran.
  const bool nmi_blocking_was_set = (s->interruptibility_state & kNmiBlocking) != 0;
  s->interruptibility_state |= kMovSsBlocking;
  s->rip = kNmiStubGpa;
  s->regs.rsp = kIdtvStackTop;
  ASSERT_EQ(ZX_OK, vcpu->RestoreArchState(*s).status_value(), "restore with MOV-SS blocking\n");

  // THE ENTRY UNDER TEST. Before the fix this re-issued the NMI over
  // blocking-by-MOV-SS and the processor refused the entry, exactly as in the
  // external-interrupt case: ENTRY_FAILURE_GUEST_STATE, surfaced to the VMM as
  // ZX_PKT_TYPE_GUEST_HALT / ZX_PKT_GUEST_HALT_UNHANDLED, run over.
  //
  // After it: deferred to the tracker, and the guest's single instruction exits.
  // Stopping here — rather than letting the same Enter() run on to the delivery
  // — is what makes the wrong implementations distinguishable instead of merely
  // slow: dropping the NMI, or keeping it in `vectoring_event_` instead of
  // re-queuing it, or never clearing the blocking-by-NMI the aborted delivery
  // set, each fails one of the four assertions below rather than hanging in a
  // guest that never reports.
  zx_port_packet_t blocked = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(blocked).status_value(),
            "an interrupted NMI must not be forced into an entry MOV-SS blocking forbids\n");
  ASSERT_NE(static_cast<uint8_t>(ZX_PKT_TYPE_GUEST_HALT), static_cast<uint8_t>(blocked.type),
            "the entry must not have been refused (pre-fix: halt, ZX_PKT_GUEST_HALT_UNHANDLED, "
            "exit_reason 33 = ENTRY_FAILURE_GUEST_STATE)\n");
  ASSERT_EQ(static_cast<uint8_t>(ZX_PKT_TYPE_GUEST_IO), static_cast<uint8_t>(blocked.type), "io\n");
  ASSERT_EQ(static_cast<uint32_t>(kNmiStubPort), static_cast<uint32_t>(blocked.guest_io.port),
            "the guest's one instruction must have run, and the NMI must NOT have been "
            "delivered on that entry\n");
  EXPECT_EQ(1u, vcpu->Vectoring().deferrals, "deferred exactly once\n");
  EXPECT_EQ(0u, vcpu->Vectoring().reinjections, "and never force-injected\n");
  // Dropped, or kept in `vectoring_event_`: either way the tracker is empty here.
  ASSERT_TRUE(vcpu->InterruptPending(X86_INT_NMI),
              "the deferred NMI must be back in the interrupt tracker, as vector 2\n");
  // And the block the aborted delivery created must be gone, or the NMI would be
  // the last one this guest ever sees.
  ASSERT_EQ(ZX_OK, vcpu->SaveArchState(*after).status_value(), "save after the blocked entry\n");
  if (nmi_blocking_was_set) {
    ASSERT_EQ(0u, after->interruptibility_state & kNmiBlocking,
              "blocking-by-NMI, set by the delivery that never completed, must have been "
              "cleared\n");
  }

  // And it must still arrive. Nothing blocks it now: the next entry pops vector 2
  // by name and delivers it into the guest's own handler.
  zx_port_packet_t handled = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(handled).status_value(), "enter (deliver)\n");
  ASSERT_EQ(static_cast<uint8_t>(ZX_PKT_TYPE_GUEST_IO), static_cast<uint8_t>(handled.type), "io\n");
  ASSERT_EQ(static_cast<uint32_t>(kIdtvReportPort), static_cast<uint32_t>(handled.guest_io.port),
            "the guest's own IDT handler must have run\n");
  EXPECT_EQ(static_cast<uint32_t>(X86_INT_NMI), static_cast<uint32_t>(handled.guest_io.data[0]),
            "and it must be the NMI handler, not some neighbouring vector\n");
  EXPECT_FALSE(vcpu->InterruptPending(X86_INT_NMI), "which consumed it from the tracker\n");

  printf("deferred NMI OK: an NMI was abandoned mid-delivery (idt_vectoring=%#x, type %u; the "
         "aborted delivery %s blocking-by-NMI), the VMM restored blocking-by-MOV-SS; the entry "
         "that followed did not fail and did not deliver — the NMI was re-queued (%lu deferral(s), "
         "%lu forced re-injection(s)) and observed pending in the tracker, then reached the "
         "guest's own handler, which reported %#x\n",
         vcpu->Vectoring().last_info, VectoringType(vcpu),
         nmi_blocking_was_set ? "left" : "did not leave", vcpu->Vectoring().deferrals,
         vcpu->Vectoring().reinjections, handled.guest_io.data[0]);
#else
  printf("Not x86_64; skipping.\n");
#endif  // __x86_64__

  END_TEST;
}

// Why handle_xsetbv has no CPL check, settled against the hardware.
//
// XSETBV is a CPL-0 instruction — Volume 2's XSETBV page lists "#GP(0) If the
// current privilege level is not 0" — and handle_xsetbv never asks. Alongside
// it, handle_vmcall *does* call is_cpl0(), which makes the omission read like an
// oversight and a guest-isolation hole: a ring-3 guest process asking the
// hypervisor to do what its own hardware refuses to do for it.
//
// It is not one, and the reason cannot be settled by reading the SDM alone:
// Volume 3, Section 26.1.2, lists XSETBV among the instructions that cause a VM
// exit unconditionally, while Section 26.1.1 gives certain faults — including
// faults based on privilege level — priority over such exits. Which of the two
// wins for this instruction decides whether the missing check is a bug or is
// correct, and the two sections read against each other either way.
//
// So this test asks the processor. The guest genuinely executes at CPL 3:
// ring-3 CS/SS descriptors, user-accessible page tables at every level, IOPL 3
// so its own OUT is not a fault, and an IDT whose #GP gate names a ring-3 code
// segment so the fault is delivered without a privilege change (a CPL-0 handler
// would need a TSS with RSP0, and without one the #GP escalates to a triple
// fault that explains nothing). It reports its own CPL out of the guest, then
// executes XSETBV. Three outcomes are distinguishable, and the test names which
// one it saw:
//
//   * the guest's own #GP handler runs, vector 13, no exit — the privilege fault
//     wins, handle_xsetbv is unreachable at CPL 3, and a check there would be
//     dead code. THIS IS WHAT THIS HOST DOES.
//   * an exit reaches handle_xsetbv and it is emulated — the check is missing
//     and the isolation hole is real.
//   * an exit reaches handle_xsetbv and is refused — a check is present.
//
// The CPL-0 half is the control that makes the CPL-3 half mean anything: the
// byte-for-byte identical instruction, in the same guest, at ring 0, must exit
// and be emulated. Without it, "no XSETBV exit at ring 3" would be equally
// consistent with the guest never having got that far.
//
// This is a characterization test, not a regression test: nothing was changed to
// make it pass. It is here so that the "there is deliberately no is_cpl0() check"
// comment in vmexit.cc rests on a measurement, and so that a machine or a
// configuration on which the exit *does* win fails loudly instead of quietly
// emulating a privileged instruction for ring 3.
bool vcpu_xsetbv_cpl3_faults_before_the_exit() {
  BEGIN_TEST;

#ifdef __x86_64__
  constexpr uint64_t kUser = 1u << 2;  // page-table U/S bit
  constexpr uint64_t kUserStackTop = 0x9000;
  constexpr uint16_t kCplPort = 0x14;
  constexpr uint16_t kXsetbvDonePort = 0x15;
  constexpr uint8_t kXsetbvDoneToken = 0xA7;
  // VMX segment access-rights DPL field, bits 6:5 (Volume 3, Section 24.4.1).
  constexpr uint32_t kDpl3 = 3u << 5;
  // RFLAGS.IOPL, bits 13:12. At CPL <= IOPL an OUT is permitted without
  // consulting the TSS I/O permission bitmap, which these guests do not have.
  constexpr uint64_t kIopl3 = 3u << 12;
  // A #GP handler, so that "the processor faulted before the VM exit" is an
  // observable third outcome rather than an unexplained packet. Its gate names a
  // ring-3 code segment, so the fault is delivered without a privilege change:
  // a CPL 0 handler would need a TSS with RSP0, and without one the #GP would
  // escalate to a triple fault and say nothing about why.
  constexpr uint64_t kXGdtGpa = 0x6000;
  constexpr uint64_t kXIdtGpa = 0x6800;
  constexpr uint64_t kGpHandlerGpa = 0xB000;
  constexpr uint16_t kGpPort = 0x16;

  fbl::RefPtr<VmObjectPaged> ram;
  ASSERT_EQ(ZX_OK, VmObjectPaged::Create(PMM_ALLOC_FLAG_ANY, 0u, kGuestRamSize, &ram), "ram\n");
  // Identity tables as elsewhere, but user-accessible at every level: at CPL 3
  // an instruction fetch from a supervisor page is a #PF before anything else
  // can happen.
  const uint64_t pml4e = kPdptGpa | kPresent | kWritable | kUser;
  const uint64_t pdpte = kPdGpa | kPresent | kWritable | kUser;
  const uint64_t pde = 0x0 | kPresent | kWritable | kUser | kPageSize2M;
  ASSERT_EQ(ZX_OK, ram->Write(&pml4e, kPml4Gpa, sizeof(pml4e)), "pml4\n");
  ASSERT_EQ(ZX_OK, ram->Write(&pdpte, kPdptGpa, sizeof(pdpte)), "pdpt\n");
  ASSERT_EQ(ZX_OK, ram->Write(&pde, kPdGpa, sizeof(pde)), "pd\n");

  // 8C C8             mov eax, cs
  // 24 03             and al, 3          ; CPL, from the CS selector's RPL
  // E6 14             out 0x14, al       ; report it out of the guest
  // 31 C9             xor ecx, ecx       ; XCR0
  // 31 D2             xor edx, edx
  // B8 03 00 00 00    mov eax, 3         ; x87|SSE — the one XCR0 always legal
  // 0F 01 D1          xsetbv
  // B0 A7             mov al, 0xA7
  // E6 15             out 0x15, al       ; reached only if XSETBV was emulated
  // F4                hlt
  const uint8_t code[] = {0x8C, 0xC8, 0x24, 0x03, 0xE6, static_cast<uint8_t>(kCplPort),
                          0x31, 0xC9, 0x31, 0xD2, 0xB8, 0x03,
                          0x00, 0x00, 0x00, 0x0F, 0x01, 0xD1,
                          0xB0, kXsetbvDoneToken,  0xE6, static_cast<uint8_t>(kXsetbvDonePort),
                          0xF4};
  ASSERT_EQ(ZX_OK, ram->Write(code, kCodeGpa, sizeof(code)), "code\n");

  // GDT: entry 1 a ring-0 64-bit code segment, entry 3 the ring-3 one the #GP
  // gate names. Nothing in the guest loads a segment; these exist only so the
  // processor has a descriptor to read when it vectors the fault.
  const uint8_t gdt_code0[8] = {0xFF, 0xFF, 0x00, 0x00, 0x00, 0x9B, 0xAF, 0x00};
  const uint8_t gdt_code3[8] = {0xFF, 0xFF, 0x00, 0x00, 0x00, 0xFB, 0xAF, 0x00};
  ASSERT_EQ(ZX_OK, ram->Write(gdt_code0, kXGdtGpa + 8, sizeof(gdt_code0)), "gdt ring0\n");
  ASSERT_EQ(ZX_OK, ram->Write(gdt_code3, kXGdtGpa + 24, sizeof(gdt_code3)), "gdt ring3\n");
  // #GP gate -> kGpHandlerGpa, through selector 0x1B (GDT entry 3, RPL 3), DPL 3.
  uint8_t gate[16];
  memset(gate, 0, sizeof(gate));
  gate[0] = static_cast<uint8_t>(kGpHandlerGpa & 0xFF);
  gate[1] = static_cast<uint8_t>((kGpHandlerGpa >> 8) & 0xFF);
  gate[2] = 0x1B;
  gate[5] = 0xEE;  // present, DPL 3, 64-bit interrupt gate
  ASSERT_EQ(ZX_OK, ram->Write(gate, kXIdtGpa + X86_INT_GP_FAULT * 16, sizeof(gate)), "gp gate\n");
  // B0 0D  mov al, 13 ; E6 16  out 0x16, al ; EB FE  jmp $   (no hlt: CPL 3)
  const uint8_t gp_handler[] = {0xB0, 0x0D, 0xE6, static_cast<uint8_t>(kGpPort), 0xEB, 0xFE};
  ASSERT_EQ(ZX_OK, ram->Write(gp_handler, kGpHandlerGpa, sizeof(gp_handler)), "gp handler\n");
  ASSERT_EQ(ZX_OK, ram->CommitRange(0, kGuestRamSize), "commit\n");

  auto lg = CreateLiveGuest(ram, kCodeGpa);
  if (lg.is_error() && lg.status_value() == ZX_ERR_NOT_SUPPORTED) {
    printf("VMX not supported here; skipping ring-3 XSETBV test.\n");
    return true;
  }
  ASSERT_EQ(ZX_OK, lg.status_value(), "create live guest\n");
  Vcpu* vcpu = lg->vcpu.get();
  ASSERT_EQ(ZX_OK,
            lg->guest->SetTrap(ZX_GUEST_TRAP_IO, kCplPort, 1, nullptr, kCplPort).status_value(),
            "trap cpl port\n");
  ASSERT_EQ(
      ZX_OK,
      lg->guest->SetTrap(ZX_GUEST_TRAP_IO, kXsetbvDonePort, 1, nullptr, kXsetbvDonePort)
          .status_value(),
      "trap xsetbv-done port\n");
  ASSERT_EQ(ZX_OK,
            lg->guest->SetTrap(ZX_GUEST_TRAP_IO, kGpPort, 1, nullptr, kGpPort).status_value(),
            "trap gp port\n");

  fbl::AllocChecker ac;
  ktl::unique_ptr<VcpuArchState> s(new (&ac) VcpuArchState{});
  ASSERT_TRUE(ac.check(), "alloc arch state\n");

  // Drop the guest to ring 3. VMX takes the segment descriptors straight out of
  // the VMCS, so no GDT entry has to exist for these selectors — nothing here
  // ever executes a segment load. CS.DPL == SS.DPL == SS.RPL == CS.RPL == 3 is
  // what Volume 3's guest-segment entry checks require of a consistent ring-3
  // state.
  ASSERT_EQ(ZX_OK, vcpu->SaveArchState(*s).status_value(), "save\n");
  s->cs.selector = 0x1B;
  s->cs.access_rights |= kDpl3;
  s->ss.selector = 0x23;
  s->ss.access_rights |= kDpl3;
  s->gdtr_base = kXGdtGpa;
  s->gdtr_limit = 0x1F;
  s->idtr_base = kXIdtGpa;
  s->idtr_limit = 0xFFF;
  s->regs.rsp = kUserStackTop;
  s->regs.rflags |= kIopl3;
  s->rip = kCodeGpa;
  ASSERT_EQ(ZX_OK, vcpu->RestoreArchState(*s).status_value(), "drop to ring 3\n");

  zx_port_packet_t cpl = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(cpl).status_value(), "enter (ring 3)\n");
  ASSERT_EQ(static_cast<uint8_t>(ZX_PKT_TYPE_GUEST_IO), static_cast<uint8_t>(cpl.type),
            "an I/O packet, before its fields are read\n");
  ASSERT_EQ(static_cast<uint32_t>(kCplPort), static_cast<uint32_t>(cpl.guest_io.port),
            "the ring-3 guest must reach its first OUT\n");
  ASSERT_EQ(3u, static_cast<uint32_t>(cpl.guest_io.data[0]),
            "and must really be running at CPL 3, by its own reckoning\n");

  // THE MEASUREMENT.
  zx_port_packet_t x = {};
  const zx_status_t ring3 = vcpu->Enter(x).status_value();
  printf("ring-3 XSETBV outcome: status=%d packet.type=%u io.port=%#x io.data0=%#x\n", ring3,
         static_cast<uint32_t>(x.type), static_cast<uint32_t>(x.guest_io.port),
         static_cast<uint32_t>(x.guest_io.data[0]));
  ASSERT_EQ(ZX_OK, ring3, "the run must not have failed for some third reason\n");
  ASSERT_EQ(static_cast<uint8_t>(ZX_PKT_TYPE_GUEST_IO), static_cast<uint8_t>(x.type),
            "the guest must have reached an OUT, not shut itself down\n");
  ASSERT_NE(static_cast<uint32_t>(kXsetbvDonePort), static_cast<uint32_t>(x.guest_io.port),
            "a ring-3 XSETBV must NOT have been exited, emulated and retired\n");
  ASSERT_EQ(static_cast<uint32_t>(kGpPort), static_cast<uint32_t>(x.guest_io.port),
            "it must instead have been faulted by the processor, inside the guest\n");
  EXPECT_EQ(static_cast<uint32_t>(X86_INT_GP_FAULT), static_cast<uint32_t>(x.guest_io.data[0]),
            "and the fault must be #GP(0), vector 13 — the privilege fault, not #UD\n");

  // THE CONTROL, and it is what makes the line above mean anything. Same guest,
  // same bytes, ring 0: the exit must happen and the instruction must retire. If
  // this failed, "no XSETBV exit at ring 3" would prove nothing — the guest could
  // simply never have reached the instruction.
  ASSERT_EQ(ZX_OK, vcpu->SaveArchState(*s).status_value(), "save (ring 3)\n");
  s->cs.selector = 0x08;
  s->cs.access_rights &= ~kDpl3;
  s->ss.selector = 0x10;
  s->ss.access_rights &= ~kDpl3;
  s->regs.rsp = kUserStackTop;
  s->rip = kCodeGpa;
  ASSERT_EQ(ZX_OK, vcpu->RestoreArchState(*s).status_value(), "back to ring 0\n");

  zx_port_packet_t cpl0 = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(cpl0).status_value(), "enter (ring 0)\n");
  ASSERT_EQ(static_cast<uint8_t>(ZX_PKT_TYPE_GUEST_IO), static_cast<uint8_t>(cpl0.type),
            "an I/O packet, before its fields are read\n");
  ASSERT_EQ(static_cast<uint32_t>(kCplPort), static_cast<uint32_t>(cpl0.guest_io.port),
            "cpl port (ring 0)\n");
  ASSERT_EQ(0u, static_cast<uint32_t>(cpl0.guest_io.data[0]), "now running at CPL 0\n");

  zx_port_packet_t done = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(done).status_value(),
            "the identical XSETBV at ring 0 must still be accepted\n");
  ASSERT_EQ(static_cast<uint8_t>(ZX_PKT_TYPE_GUEST_IO), static_cast<uint8_t>(done.type),
            "an I/O packet, before its fields are read\n");
  ASSERT_EQ(static_cast<uint32_t>(kXsetbvDonePort), static_cast<uint32_t>(done.guest_io.port),
            "and the guest must run on past it\n");
  EXPECT_EQ(static_cast<uint32_t>(kXsetbvDoneToken), static_cast<uint32_t>(done.guest_io.data[0]),
            "xsetbv-done sentinel\n");

  printf("ring-3 XSETBV OK: a guest running at CPL %u (by its own reckoning) executed XSETBV and "
         "took #GP vector %u in its own handler — no XSETBV VM exit reached the hypervisor, so the "
         "privilege fault has priority over the exit; the byte-for-byte identical instruction at "
         "CPL %u did exit, was emulated, and retired (sentinel %#x)\n",
         static_cast<uint32_t>(cpl.guest_io.data[0]), static_cast<uint32_t>(x.guest_io.data[0]),
         static_cast<uint32_t>(cpl0.guest_io.data[0]), static_cast<uint32_t>(done.guest_io.data[0]));
#else
  printf("Not x86_64; skipping.\n");
#endif  // __x86_64__

  END_TEST;
}

// A hypercall attempted at CPL 3 must be answered the way the guest's own
// hypervisor ABI says, and the two ABIs this kernel can present say different
// things.
//
// The Hyper-V TLFS requires an exception here rather than an error status. Its
// "Legal Hypercall Environments" clause reads:
//
//     "Hypercalls can be invoked only from the most privileged guest processor
//      mode. On x64 platforms, this means protected mode with a current privilege
//      level (CPL) of zero. Although real-mode code runs with an effective CPL of
//      zero, hypercalls are not allowed in real mode. An attempt to invoke a
//      hypercall within an illegal processor mode will generate a #UD (undefined
//      operation) exception on x64 [...]"
//
// So there is no status code at all on this path: the conformant answer is an
// exception, RAX is not written, and RIP stays on the faulting instruction. A
// status code would be the *non*-conformant answer.
//
// The `-1` the kernel used to return is meaningful under the kernel's other
// identity -- KVM, which is the default --
// `-1` is exactly `-KVM_EPERM`, which is what KVM's own `kvm_emulate_hypercall`
// returns for a CPL != 0 caller. One value, two ABIs, and it was right for the
// one it was written for and wrong for the one that was bolted on later.
//
// Hence three arms, in one guest, over the identical three instruction bytes:
//
//   * ring 3, Hyper-V identity  -> #UD in the guest's own handler, RIP unadvanced
//   * ring 3, KVM identity      -> RAX = -1, RIP advanced (TLFS does not apply)
//   * ring 0, Hyper-V identity  -> the hypercall is delegated to the VMM
//
// Each arm is the control for the others, which is what makes this more than
// decorative. An implementation that always injects #UD fails arm 2. One that
// never does fails arm 1. One that #UDs everything including CPL 0 fails arm 3.
// And the RIP assertion is the one that discriminates a correct #UD from a #UD
// injected after `next_rip` has already advanced past the VMCALL: a fault whose
// pushed return address is three bytes too high cannot be retried or reported by
// the guest, and every other assertion here passes with that bug present.
bool vcpu_hypercall_at_cpl3_faults_per_identity() {
  BEGIN_TEST;

#ifdef __x86_64__
  constexpr uint64_t kUser = 1u << 2;  // page-table U/S bit
  constexpr uint64_t kUserStackTop = 0x9000;
  constexpr uint32_t kDpl3 = 3u << 5;
  constexpr uint64_t kIopl3 = 3u << 12;
  constexpr uint64_t kVGdtGpa = 0x6000;
  constexpr uint64_t kVIdtGpa = 0x6800;
  constexpr uint64_t kUdHandlerGpa = 0xB000;
  constexpr uint64_t kGpHandlerGpa = 0xB100;
  constexpr uint16_t kCplPort = 0x14;
  constexpr uint16_t kRaxPort = 0x15;
  constexpr uint16_t kVectorPort = 0x16;
  constexpr uint16_t kRipPort = 0x17;
  constexpr uint8_t kVmmResult = 0x6D;

  fbl::RefPtr<VmObjectPaged> ram;
  ASSERT_EQ(ZX_OK, VmObjectPaged::Create(PMM_ALLOC_FLAG_ANY, 0u, kGuestRamSize, &ram), "ram\n");
  // User-accessible identity tables at every level: at CPL 3 an instruction
  // fetch from a supervisor page faults before anything else can happen.
  const uint64_t pml4e = kPdptGpa | kPresent | kWritable | kUser;
  const uint64_t pdpte = kPdGpa | kPresent | kWritable | kUser;
  const uint64_t pde = 0x0 | kPresent | kWritable | kUser | kPageSize2M;
  ASSERT_EQ(ZX_OK, ram->Write(&pml4e, kPml4Gpa, sizeof(pml4e)), "pml4\n");
  ASSERT_EQ(ZX_OK, ram->Write(&pdpte, kPdptGpa, sizeof(pdpte)), "pdpt\n");
  ASSERT_EQ(ZX_OK, ram->Write(&pde, kPdGpa, sizeof(pde)), "pd\n");

  // 8C C8             mov eax, cs
  // 24 03             and al, 3
  // E6 14             out 0x14, al   ; the guest's own reading of its CPL
  // 31 C9             xor ecx, ecx   ; hypercall input value 0
  // 31 D2             xor edx, edx
  // 0F 01 C1          vmcall         ; <- at kCodeGpa + kVmcallOffset
  // E6 15             out 0x15, al   ; reached only if the VMCALL retired
  // F4                hlt
  constexpr uint64_t kVmcallOffset = 10;
  const uint8_t code[] = {0x8C, 0xC8, 0x24, 0x03, 0xE6, static_cast<uint8_t>(kCplPort),
                          0x31, 0xC9, 0x31, 0xD2, 0x0F, 0x01,
                          0xC1, 0xE6, static_cast<uint8_t>(kRaxPort), 0xF4};
  static_assert(sizeof(code) == 16);
  ASSERT_EQ(ZX_OK, ram->Write(code, kCodeGpa, sizeof(code)), "code\n");
  // The low byte of the VMCALL's own address, and of the address three bytes
  // past it. These must differ or the RIP assertion below proves nothing.
  const uint8_t kVmcallRipLow = static_cast<uint8_t>(kCodeGpa + kVmcallOffset);
  const uint8_t kAdvancedRipLow = static_cast<uint8_t>(kCodeGpa + kVmcallOffset + 3);
  static_assert(static_cast<uint8_t>(kCodeGpa + kVmcallOffset) !=
                static_cast<uint8_t>(kCodeGpa + kVmcallOffset + 3));

  // GDT entry 1 a ring-0 64-bit code segment, entry 3 the ring-3 one the fault
  // gates name. Nothing here executes a segment load; these exist only so the
  // processor has a descriptor to read when it vectors a fault.
  const uint8_t gdt_code0[8] = {0xFF, 0xFF, 0x00, 0x00, 0x00, 0x9B, 0xAF, 0x00};
  const uint8_t gdt_code3[8] = {0xFF, 0xFF, 0x00, 0x00, 0x00, 0xFB, 0xAF, 0x00};
  ASSERT_EQ(ZX_OK, ram->Write(gdt_code0, kVGdtGpa + 8, sizeof(gdt_code0)), "gdt ring0\n");
  ASSERT_EQ(ZX_OK, ram->Write(gdt_code3, kVGdtGpa + 24, sizeof(gdt_code3)), "gdt ring3\n");
  // Gates for #UD and #GP, both through selector 0x1B (GDT entry 3, RPL 3) with
  // DPL 3, so the fault is delivered without a privilege change: a CPL-0 handler
  // would need a TSS with RSP0, and without one the fault escalates to a triple
  // fault that explains nothing. #GP has a gate of its own so that "the wrong
  // fault arrived" is an observable outcome rather than a triple fault.
  auto write_gate = [&](uint8_t vector, uint64_t handler) {
    uint8_t gate[16];
    memset(gate, 0, sizeof(gate));
    gate[0] = static_cast<uint8_t>(handler & 0xFF);
    gate[1] = static_cast<uint8_t>((handler >> 8) & 0xFF);
    gate[2] = 0x1B;
    gate[5] = 0xEE;  // present, DPL 3, 64-bit interrupt gate
    return ram->Write(gate, kVIdtGpa + vector * 16, sizeof(gate));
  };
  ASSERT_EQ(ZX_OK, write_gate(X86_INT_INVALID_OP, kUdHandlerGpa), "ud gate\n");
  ASSERT_EQ(ZX_OK, write_gate(X86_INT_GP_FAULT, kGpHandlerGpa), "gp gate\n");
  // #UD handler: report the vector, then the low byte of the RETURN ADDRESS the
  // processor pushed. With a DPL-3 gate entered from CPL 3 there is no stack
  // switch, so [rsp] is that address -- and for a fault (as opposed to a trap)
  // it is the address OF the faulting instruction, not the one after it.
  //
  //  B0 06        mov al, 6
  //  E6 16        out 0x16, al
  //  8A 04 24     mov al, [rsp]
  //  E6 17        out 0x17, al
  //  EB FE        jmp $            (no hlt: CPL 3)
  const uint8_t ud_handler[] = {0xB0, X86_INT_INVALID_OP, 0xE6,
                               static_cast<uint8_t>(kVectorPort), 0x8A, 0x04,
                               0x24, 0xE6, static_cast<uint8_t>(kRipPort), 0xEB, 0xFE};
  ASSERT_EQ(ZX_OK, ram->Write(ud_handler, kUdHandlerGpa, sizeof(ud_handler)), "ud handler\n");
  const uint8_t gp_handler[] = {0xB0, X86_INT_GP_FAULT, 0xE6,
                                static_cast<uint8_t>(kVectorPort), 0xEB, 0xFE};
  ASSERT_EQ(ZX_OK, ram->Write(gp_handler, kGpHandlerGpa, sizeof(gp_handler)), "gp handler\n");
  ASSERT_EQ(ZX_OK, ram->CommitRange(0, kGuestRamSize), "commit\n");

  auto lg = CreateLiveGuest(ram, kCodeGpa);
  if (lg.is_error() && lg.status_value() == ZX_ERR_NOT_SUPPORTED) {
    printf("VMX not supported here; skipping ring-3 hypercall test.\n");
    return true;
  }
  ASSERT_EQ(ZX_OK, lg.status_value(), "create live guest\n");
  Vcpu* vcpu = lg->vcpu.get();
  for (uint16_t port : {kCplPort, kRaxPort, kVectorPort, kRipPort}) {
    ASSERT_EQ(ZX_OK, lg->guest->SetTrap(ZX_GUEST_TRAP_IO, port, 1, nullptr, port).status_value(),
              "trap io port\n");
  }

  fbl::AllocChecker ac;
  ktl::unique_ptr<VcpuArchState> s(new (&ac) VcpuArchState{});
  ASSERT_TRUE(ac.check(), "alloc arch state\n");

  // Drop to ring 3. CS.DPL == SS.DPL == SS.RPL == CS.RPL == 3 is what Volume 3's
  // guest-segment entry checks require of a consistent ring-3 state.
  auto set_ring = [&](uint32_t cpl) {
    if (auto r = vcpu->SaveArchState(*s); r.is_error()) {
      return r.status_value();
    }
    s->cs.selector = cpl == 3 ? 0x1B : 0x08;
    s->ss.selector = cpl == 3 ? 0x23 : 0x10;
    if (cpl == 3) {
      s->cs.access_rights |= kDpl3;
      s->ss.access_rights |= kDpl3;
    } else {
      s->cs.access_rights &= ~kDpl3;
      s->ss.access_rights &= ~kDpl3;
    }
    s->gdtr_base = kVGdtGpa;
    s->gdtr_limit = 0x1F;
    s->idtr_base = kVIdtGpa;
    s->idtr_limit = 0xFFF;
    s->regs.rsp = kUserStackTop;
    s->regs.rflags |= kIopl3;
    s->rip = kCodeGpa;
    return vcpu->RestoreArchState(*s).status_value();
  };

  // ARM 1: ring 3 under a Hyper-V identity. TLFS says #UD.
  zx_vcpu_enlightenment_t hyperv =
      MakeEnlightenment(ZX_VCPU_ENLIGHTENMENT_HYPERV_IDENTITY | ZX_VCPU_ENLIGHTENMENT_DELEGATE_MSRS |
                        ZX_VCPU_ENLIGHTENMENT_DELEGATE_HYPERCALLS);
  ASSERT_EQ(ZX_OK, vcpu->WriteEnlightenment(hyperv).status_value(), "arm Hyper-V identity\n");
  ASSERT_EQ(ZX_OK, set_ring(3), "drop to ring 3\n");

  zx_port_packet_t p = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(p).status_value(), "enter (ring 3, Hv)\n");
  ASSERT_EQ(static_cast<uint8_t>(ZX_PKT_TYPE_GUEST_IO), static_cast<uint8_t>(p.type), "io\n");
  ASSERT_EQ(static_cast<uint32_t>(kCplPort), static_cast<uint32_t>(p.guest_io.port), "cpl port\n");
  ASSERT_EQ(3u, static_cast<uint32_t>(p.guest_io.data[0]),
            "the guest must really be at CPL 3, by its own reckoning\n");

  zx_port_packet_t f = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(f).status_value(), "enter (the VMCALL)\n");
  printf("ring-3 Hv VMCALL outcome: packet.type=%u io.port=%#x io.data0=%#x\n",
         static_cast<uint32_t>(f.type), static_cast<uint32_t>(f.guest_io.port),
         static_cast<uint32_t>(f.guest_io.data[0]));
  ASSERT_NE(static_cast<uint8_t>(ZX_PKT_TYPE_GUEST_HYPERCALL), static_cast<uint8_t>(f.type),
            "a CPL-3 hypercall must NOT be delegated to the VMM\n");
  ASSERT_EQ(static_cast<uint8_t>(ZX_PKT_TYPE_GUEST_IO), static_cast<uint8_t>(f.type),
            "the guest must have taken a fault it can report, not shut itself down\n");
  ASSERT_NE(static_cast<uint32_t>(kRaxPort), static_cast<uint32_t>(f.guest_io.port),
            "the VMCALL must not have retired with a status in RAX -- TLFS wants an exception\n");
  ASSERT_EQ(static_cast<uint32_t>(kVectorPort), static_cast<uint32_t>(f.guest_io.port),
            "one of the guest's own fault handlers must have run\n");
  EXPECT_EQ(static_cast<uint32_t>(X86_INT_INVALID_OP), static_cast<uint32_t>(f.guest_io.data[0]),
            "and it must be #UD (vector 6), the fault TLFS names -- not #GP\n");

  zx_port_packet_t r = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(r).status_value(), "enter (the pushed RIP)\n");
  ASSERT_EQ(static_cast<uint8_t>(ZX_PKT_TYPE_GUEST_IO), static_cast<uint8_t>(r.type), "io\n");
  ASSERT_EQ(static_cast<uint32_t>(kRipPort), static_cast<uint32_t>(r.guest_io.port), "rip port\n");
  // THE DISCRIMINATING ASSERTION. `next_rip` runs unconditionally at the top of
  // handle_vmcall, so the natural way to write this fix leaves RIP three bytes
  // past the VMCALL and every other assertion above still passes.
  EXPECT_EQ(static_cast<uint32_t>(kVmcallRipLow), static_cast<uint32_t>(r.guest_io.data[0]),
            "the #UD frame must point AT the VMCALL, not past it: a fault reports the faulting "
            "instruction's own address\n");
  if (r.guest_io.data[0] == kAdvancedRipLow) {
    printf("    ^ the pushed RIP is exactly three bytes past the VMCALL: the fault was injected "
           "after next_rip had already advanced it\n");
  }

  // ARM 2, the control that stops an unconditional #UD from passing. Same three
  // bytes, same ring, KVM identity: KVM's ABI answers -KVM_EPERM in RAX and the
  // instruction retires, and TLFS has nothing to say about a guest that was
  // never told it is talking to Hyper-V.
  ASSERT_EQ(ZX_OK, vcpu->WriteEnlightenment(MakeEnlightenment(0)).status_value(),
            "back to the KVM identity\n");
  ASSERT_EQ(ZX_OK, set_ring(3), "ring 3 again\n");
  zx_port_packet_t kcpl = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(kcpl).status_value(), "enter (ring 3, KVM)\n");
  ASSERT_EQ(static_cast<uint32_t>(kCplPort), static_cast<uint32_t>(kcpl.guest_io.port), "cpl\n");
  ASSERT_EQ(3u, static_cast<uint32_t>(kcpl.guest_io.data[0]), "still CPL 3\n");
  zx_port_packet_t k = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(k).status_value(), "enter (the VMCALL, KVM identity)\n");
  ASSERT_EQ(static_cast<uint8_t>(ZX_PKT_TYPE_GUEST_IO), static_cast<uint8_t>(k.type), "io\n");
  ASSERT_EQ(static_cast<uint32_t>(kRaxPort), static_cast<uint32_t>(k.guest_io.port),
            "under the KVM identity the VMCALL must retire and the guest run on\n");
  EXPECT_EQ(0xFFu, static_cast<uint32_t>(k.guest_io.data[0]),
            "with -KVM_EPERM (-1) in RAX, which is that ABI's answer\n");

  // ARM 3, the control that stops "#UD everything" from passing. Ring 0, Hyper-V
  // identity: the hypercall must reach the VMM.
  ASSERT_EQ(ZX_OK, vcpu->WriteEnlightenment(hyperv).status_value(), "Hyper-V identity again\n");
  ASSERT_EQ(ZX_OK, set_ring(0), "back to ring 0\n");
  zx_port_packet_t zcpl = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(zcpl).status_value(), "enter (ring 0, Hv)\n");
  ASSERT_EQ(static_cast<uint32_t>(kCplPort), static_cast<uint32_t>(zcpl.guest_io.port), "cpl\n");
  ASSERT_EQ(0u, static_cast<uint32_t>(zcpl.guest_io.data[0]), "now at CPL 0\n");
  zx_port_packet_t hc = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(hc).status_value(), "enter (the VMCALL, ring 0)\n");
  ASSERT_EQ(static_cast<uint8_t>(ZX_PKT_TYPE_GUEST_HYPERCALL), static_cast<uint8_t>(hc.type),
            "at CPL 0 the identical instruction must still be delegated to the VMM -- without this "
            "the #UD above would be equally consistent with the guest never reaching the VMCALL\n");
  zx_vcpu_state_t st = {};
  ASSERT_EQ(ZX_OK, vcpu->ReadState(st).status_value(), "ReadState\n");
  st.rax = kVmmResult;
  ASSERT_EQ(ZX_OK, vcpu->WriteState(st).status_value(), "WriteState (hypercall result)\n");
  zx_port_packet_t done = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(done).status_value(), "enter (result report)\n");
  ASSERT_EQ(static_cast<uint32_t>(kRaxPort), static_cast<uint32_t>(done.guest_io.port),
            "and it must retire\n");
  EXPECT_EQ(static_cast<uint32_t>(kVmmResult), static_cast<uint32_t>(done.guest_io.data[0]),
            "carrying the VMM's own result\n");

  printf("CPL-3 hypercall OK: ring 3 + Hyper-V identity took #UD vector %u in the guest's own "
         "handler with the frame pointing at the VMCALL itself (%#x, not %#x); ring 3 + KVM "
         "identity retired with RAX low byte %#x (-KVM_EPERM); ring 0 + Hyper-V identity was "
         "delegated to the VMM and retired with %#x\n",
         static_cast<uint32_t>(f.guest_io.data[0]), static_cast<uint32_t>(r.guest_io.data[0]),
         static_cast<uint32_t>(kAdvancedRipLow), static_cast<uint32_t>(k.guest_io.data[0]),
         static_cast<uint32_t>(done.guest_io.data[0]));
#else
  printf("Not x86_64; skipping.\n");
#endif  // __x86_64__

  END_TEST;
}

// Guest RFLAGS.IF must survive save/restore, in both polarities.
//
// A snapshot taken inside a guest's interrupts-disabled critical section has to
// resume with interrupts still disabled, and one taken with them enabled has to
// resume enabled. The masks used by SaveArchState/RestoreArchState previously
// omitted IF (bit 9) entirely, so the flag was neither captured nor written
// back: a restore silently left whatever IF the destination VCPU happened to
// have. That is exactly the state a checkpoint is supposed to pin down.
//
// Non-vacuous in a way the bug itself cannot fake:
//   * the assertions on the *saved* struct catch a save that drops IF;
//   * the restore is checked by the guest reading its own RFLAGS with `pushfq`,
//     i.e. against the hardware, not against the same mask that was wrong;
//   * both polarities are exercised, each after the live IF has been driven to
//     the *opposite* value by real guest instructions (sti/cli), so a "fix"
//     that hardcodes IF either way fails one of the two.
bool vcpu_state_interrupt_flag_roundtrip() {
  BEGIN_TEST;

#ifdef __x86_64__
  constexpr uint64_t kStiGpa = 0x3000;    // sti;  nop; out 0x11,al; hlt
  constexpr uint64_t kCliGpa = 0x3800;    // cli;  nop; out 0x11,al; hlt
  constexpr uint64_t kProbeGpa = 0x5000;  // report the guest's own RFLAGS.IF on port 0x10
  constexpr uint64_t kStackTop = 0x9000;  // pushfq needs a stack; identity-mapped RW RAM
  // GUEST_INTERRUPTIBILITY_STATE bit 0 ("blocking by STI"). The hypervisor's own
  // constant lives in its private header, so it is spelled out here.
  constexpr uint32_t kStiBlocking = 1u << 0;

  fbl::RefPtr<VmObjectPaged> ram;
  ASSERT_EQ(ZX_OK, VmObjectPaged::Create(PMM_ALLOC_FLAG_ANY, 0u, kGuestRamSize, &ram), "ram\n");
  ASSERT_EQ(ZX_OK, WriteIdentityTables(ram), "tables\n");
  //   FB     sti            ; (FA cli in the other copy)
  //   90     nop            ; retire the one-instruction STI shadow
  //   E6 11  out 0x11, al
  //   F4     hlt
  const uint8_t sti_code[] = {0xFB, 0x90, 0xE6, 0x11, 0xF4};
  const uint8_t cli_code[] = {0xFA, 0x90, 0xE6, 0x11, 0xF4};
  //   9C           pushfq
  //   58           pop rax
  //   48 C1 E8 09  shr rax, 9
  //   24 01        and al, 1
  //   E6 10        out 0x10, al   ; 1 iff the guest's own IF is set
  //   F4           hlt
  const uint8_t probe_code[] = {0x9C, 0x58, 0x48, 0xC1, 0xE8, 0x09, 0x24, 0x01, 0xE6, 0x10, 0xF4};
  ASSERT_EQ(ZX_OK, ram->Write(sti_code, kStiGpa, sizeof(sti_code)), "sti code\n");
  ASSERT_EQ(ZX_OK, ram->Write(cli_code, kCliGpa, sizeof(cli_code)), "cli code\n");
  ASSERT_EQ(ZX_OK, ram->Write(probe_code, kProbeGpa, sizeof(probe_code)), "probe code\n");
  ASSERT_EQ(ZX_OK, ram->CommitRange(0, kGuestRamSize), "commit\n");

  auto lg = CreateLiveGuest(ram, kStiGpa);
  if (lg.is_error() && lg.status_value() == ZX_ERR_NOT_SUPPORTED) {
    printf("VMX not supported here; skipping RFLAGS.IF save/restore test.\n");
    return true;
  }
  ASSERT_EQ(ZX_OK, lg.status_value(), "create live guest\n");
  Vcpu* vcpu = lg->vcpu.get();

  // VcpuArchState carries a 1 KiB XSAVE area; keep the several copies this test
  // needs off the kernel stack.
  fbl::AllocChecker ac;
  ktl::unique_ptr<VcpuArchState> on(new (&ac) VcpuArchState{});
  ASSERT_TRUE(ac.check(), "alloc IF-set snapshot\n");
  ktl::unique_ptr<VcpuArchState> off(new (&ac) VcpuArchState{});
  ASSERT_TRUE(ac.check(), "alloc IF-clear snapshot\n");
  ktl::unique_ptr<VcpuArchState> scratch(new (&ac) VcpuArchState{});
  ASSERT_TRUE(ac.check(), "alloc scratch\n");

  // Restore `base` with RIP repointed at `rip` (and a usable stack), then run to
  // the next exit. `extra_interruptibility` is OR'd into the restored
  // interruptibility state, for the malformed-input check at the end.
  zx_port_packet_t pkt = {};
  auto restore_and_run = [&](const VcpuArchState& base, uint64_t rip,
                             uint32_t extra_interruptibility = 0) -> zx_status_t {
    *scratch = base;
    scratch->rip = rip;
    scratch->regs.rsp = kStackTop;
    scratch->interruptibility_state |= extra_interruptibility;
    if (auto r = vcpu->RestoreArchState(*scratch); r.is_error()) {
      return r.status_value();
    }
    pkt = {};
    return vcpu->Enter(pkt).status_value();
  };

  // 1. The guest executes `sti`, so the live VMCS has IF set. Capture it.
  ASSERT_EQ(ZX_OK, vcpu->Enter(pkt).status_value(), "enter (sti path)\n");
  ASSERT_EQ(0x11u, pkt.guest_io.port, "sti-path exit port\n");
  ASSERT_EQ(ZX_OK, vcpu->SaveArchState(*on).status_value(), "save with IF set\n");
  ASSERT_TRUE((on->regs.rflags & X86_FLAGS_IF) != 0,
              "a snapshot taken after the guest's sti must record RFLAGS.IF as SET\n");

  // 2. The guest executes `cli`, so the live VMCS has IF clear. Capture that too.
  ASSERT_EQ(ZX_OK, restore_and_run(*on, kCliGpa), "enter (cli path)\n");
  ASSERT_EQ(0x11u, pkt.guest_io.port, "cli-path exit port\n");
  ASSERT_EQ(ZX_OK, vcpu->SaveArchState(*off).status_value(), "save with IF clear\n");
  ASSERT_TRUE((off->regs.rflags & X86_FLAGS_IF) == 0,
              "a snapshot taken after the guest's cli must record RFLAGS.IF as CLEAR\n");

  // 3. Live IF is currently 0. Restoring the IF-set snapshot must turn it back
  //    on, as observed by the guest itself.
  ASSERT_EQ(ZX_OK, restore_and_run(*on, kProbeGpa), "enter (probe after IF-set restore)\n");
  ASSERT_EQ(0x10u, pkt.guest_io.port, "probe exit port\n");
  EXPECT_EQ(1u, static_cast<uint32_t>(pkt.guest_io.data[0]),
            "restoring a snapshot captured with interrupts ENABLED must resume with IF set\n");

  // 4. Drive the live IF back to 1 with real guest code, so the next check
  //    cannot pass merely because IF was already where it wanted it.
  ASSERT_EQ(ZX_OK, restore_and_run(*on, kStiGpa), "enter (sti path again)\n");
  ASSERT_EQ(0x11u, pkt.guest_io.port, "sti-path exit port (2)\n");

  // 5. Restoring the IF-clear snapshot must turn interrupts back off. This is
  //    the case that matters: a guest snapshotted inside an interrupts-disabled
  //    critical section must not resume with interrupts on.
  ASSERT_EQ(ZX_OK, restore_and_run(*off, kProbeGpa), "enter (probe after IF-clear restore)\n");
  ASSERT_EQ(0x10u, pkt.guest_io.port, "probe exit port (2)\n");
  EXPECT_EQ(0u, static_cast<uint32_t>(pkt.guest_io.data[0]),
            "restoring a snapshot captured with interrupts DISABLED must resume with IF clear\n");

  // 6. Now that IF=0 is a reachable restored state, the interruptibility state
  //    that rides along with it has to stay legal: VM entry rejects "blocking by
  //    STI" together with RFLAGS.IF=0. The restore path must clamp that rather
  //    than turn a caller-supplied combination into an opaque entry failure.
  ASSERT_EQ(ZX_OK, restore_and_run(*on, kStiGpa), "enter (sti path, third)\n");
  ASSERT_EQ(ZX_OK, restore_and_run(*off, kProbeGpa, kStiBlocking),
            "IF=0 plus blocking-by-STI must be clamped, not fail VM entry\n");
  // Without the clamp this is where it shows: the entry is refused with
  // ENTRY_FAILURE_GUEST_STATE (33) and Enter hands back something that is not
  // the guest's I/O exit.
  ASSERT_EQ(static_cast<uint8_t>(ZX_PKT_TYPE_GUEST_IO), static_cast<uint8_t>(pkt.type),
            "IF=0 plus blocking-by-STI must not turn into a VM-entry failure\n");
  ASSERT_EQ(0x10u, pkt.guest_io.port, "probe exit port (3)\n");
  EXPECT_EQ(0u, static_cast<uint32_t>(pkt.guest_io.data[0]),
            "the clamped restore must still resume with IF clear\n");

  printf("RFLAGS.IF save/restore OK: snapshots recorded IF=1 and IF=0; each restore drove the "
         "guest's own pushfq to report the captured value after the live flag had been set to the "
         "opposite one; IF=0 with blocking-by-STI entered cleanly\n");
#else
  printf("Not x86_64; skipping.\n");
#endif  // __x86_64__

  END_TEST;
}

// CSTAR is an architectural per-VCPU MSR even on a guest that never executes a
// compatibility-mode SYSCALL. Windows saves it with the rest of the syscall
// MSRs during early boot. This exercises the real guest instructions in both
// directions, then proves the full-state blob can replace the value and have a
// subsequent RDMSR observe the restored state.
bool vcpu_cstar_read_write_and_restore_roundtrip() {
  BEGIN_TEST;

#ifdef __x86_64__
  fbl::RefPtr<VmObjectPaged> ram;
  ASSERT_EQ(ZX_OK, VmObjectPaged::Create(PMM_ALLOC_FLAG_ANY, 0u, kGuestRamSize, &ram), "ram\n");
  ASSERT_EQ(ZX_OK, WriteIdentityTables(ram), "tables\n");

  constexpr uint32_t kFirstCstar = 0x12345678;
  constexpr uint32_t kRestoredCstar = 0x23456789;
  // mov ecx,IA32_CSTAR; mov eax,kFirstCstar; xor edx,edx; wrmsr;
  // xor eax,eax; xor edx,edx; rdmsr; out 0x10,eax; hlt
  const uint8_t write_read[] = {
      0xB9, 0x83, 0x00, 0x00, 0xC0, 0xB8, 0x78, 0x56, 0x34, 0x12, 0x31,
      0xD2, 0x0F, 0x30, 0x31, 0xC0, 0x31, 0xD2, 0x0F, 0x32, 0xE7, 0x10, 0xF4,
  };
  // mov ecx,IA32_CSTAR; xor eax,eax; xor edx,edx; rdmsr; out 0x10,eax; hlt
  const uint8_t read_only[] = {
      0xB9, 0x83, 0x00, 0x00, 0xC0, 0x31, 0xC0, 0x31,
      0xD2, 0x0F, 0x32, 0xE7, 0x10, 0xF4,
  };
  ASSERT_EQ(ZX_OK, ram->Write(write_read, kCodeGpa, sizeof(write_read)), "write/read code\n");
  ASSERT_EQ(ZX_OK, ram->Write(read_only, kCode2Gpa, sizeof(read_only)), "read-only code\n");
  ASSERT_EQ(ZX_OK, ram->CommitRange(0, kGuestRamSize), "commit\n");

  auto lg = CreateLiveGuestDispatcher(ram, kCodeGpa);
  if (lg.is_error() && lg.status_value() == ZX_ERR_NOT_SUPPORTED) {
    printf("VMX not supported here; skipping CSTAR round-trip test.\n");
    return true;
  }
  ASSERT_EQ(ZX_OK, lg.status_value(), "create live guest\n");
  VcpuDispatcher* vcpu = lg->vcpu.get();

  zx_port_packet_t packet = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(packet), "enter write/read guest\n");
  ASSERT_EQ(static_cast<uint8_t>(ZX_PKT_TYPE_GUEST_IO), static_cast<uint8_t>(packet.type),
            "write/read report\n");
  ASSERT_EQ(4u, static_cast<uint32_t>(packet.guest_io.access_size), "dword report\n");
  uint32_t reported = 0;
  memcpy(&reported, packet.guest_io.data, sizeof(reported));
  EXPECT_EQ(kFirstCstar, reported, "guest WRMSR must be returned by guest RDMSR\n");

  const size_t len = SerializedVcpuStateSize();
  fbl::AllocChecker ac;
  ktl::unique_ptr<uint8_t[]> buf(new (&ac) uint8_t[len]);
  ASSERT_TRUE(ac.check(), "alloc state blob\n");
  ktl::unique_ptr<VcpuArchState> state(new (&ac) VcpuArchState{});
  ASSERT_TRUE(ac.check(), "alloc state\n");
  size_t actual = 0;
  ASSERT_EQ(ZX_OK, vcpu->ReadStateFull(buf.get(), len, &actual), "read full state\n");
  ASSERT_EQ(ZX_OK, DeserializeVcpuState(*state, buf.get(), actual).status_value(),
            "deserialize full state\n");
  EXPECT_EQ(static_cast<uint64_t>(kFirstCstar), state->cstar,
            "full state must capture guest CSTAR\n");

  state->cstar = kRestoredCstar;
  state->rip = kCode2Gpa;
  ASSERT_EQ(ZX_OK, SerializeVcpuState(*state, buf.get(), len).status_value(), "serialize\n");
  ASSERT_EQ(ZX_OK, vcpu->WriteStateFull(buf.get(), len), "restore CSTAR\n");
  packet = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(packet), "enter read-only guest\n");
  ASSERT_EQ(static_cast<uint8_t>(ZX_PKT_TYPE_GUEST_IO), static_cast<uint8_t>(packet.type),
            "restored report\n");
  memcpy(&reported, packet.guest_io.data, sizeof(reported));
  EXPECT_EQ(kRestoredCstar, reported, "guest RDMSR must observe restored CSTAR\n");

  printf("CSTAR round-trip OK: guest wrote/read %#x; full state captured it and restored %#x\n",
         kFirstCstar, kRestoredCstar);
#else
  printf("Not x86_64; skipping.\n");
#endif

  END_TEST;
}

// ZX_VCPU_STATE_FULL carries fields that are not guest state at all.
//
// Most of the structure is written to the VMCS, so a bad value is the guest's
// problem. XCR0 is different -- it is loaded into the *physical* XCR0 by
// swap_extended_registers() on the way into the guest, which runs in host
// context. XSETBV #GPs on an illegal operand, so before this was validated, a
// VMM handle plus one write of a nonsense XCR0 faulted the kernel: a
// machine-wide denial of service, not a guest fault. Nothing gates the load but
// x86_xsave_supported() -- it once also depended on guest CR4.OSXSAVE, which
// arrives through this very same structure and so gated nothing; see the comment
// in Vcpu::LoadExtendedRegisters for why that term is gone entirely. The syscall
// MSRs (covered below) are the same shape: a bare WRMSR in host context.
//
// The `xsave` image is the third field of this shape; it has its own test,
// vcpu_restore_rejects_hostile_xsave, below.
//
// This test drives VcpuDispatcher -- the object a zx_vcpu_write_state() handle
// resolves to, with only the handle lookup and the user copy above it -- and
// asserts (a) each hostile value is refused with an error, (b) nothing was
// applied, and (c) the machine is still alive afterwards, proved by running the
// guest again. The last step is a positive control: the identical restore with a
// *legal* XCR0 is accepted and does reach XSETBV on the next entry, so a
// validator that simply refused everything would fail here.
bool vcpu_restore_rejects_hostile_xcr0() {
  BEGIN_TEST;

#ifdef __x86_64__
  fbl::RefPtr<VmObjectPaged> ram;
  ASSERT_EQ(ZX_OK, VmObjectPaged::Create(PMM_ALLOC_FLAG_ANY, 0u, kGuestRamSize, &ram), "ram\n");
  ASSERT_EQ(ZX_OK, WriteIdentityTables(ram), "tables\n");
  // mov al,0x42; out 0x10,al; hlt
  const uint8_t code[] = {0xB0, kSentinel, 0xE6, 0x10, 0xF4};
  ASSERT_EQ(ZX_OK, ram->Write(code, kCodeGpa, sizeof(code)), "code\n");
  ASSERT_EQ(ZX_OK, ram->CommitRange(0, kGuestRamSize), "commit\n");

  auto lg = CreateLiveGuestDispatcher(ram, kCodeGpa);
  if (lg.is_error() && lg.status_value() == ZX_ERR_NOT_SUPPORTED) {
    printf("VMX not supported here; skipping hostile-XCR0 restore test.\n");
    return true;
  }
  ASSERT_EQ(ZX_OK, lg.status_value(), "create live guest (dispatchers)\n");
  VcpuDispatcher* vcpu = lg->vcpu.get();

  // 1. Baseline: the guest runs. Whatever follows, this is what "the machine
  //    survived" has to look like again at the end.
  zx_port_packet_t p = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(p), "baseline enter\n");
  ASSERT_EQ(static_cast<uint8_t>(ZX_PKT_TYPE_GUEST_IO), static_cast<uint8_t>(p.type),
            "baseline io\n");
  ASSERT_EQ(static_cast<uint32_t>(kSentinel), static_cast<uint32_t>(p.guest_io.data[0]),
            "baseline sentinel\n");

  const size_t len = SerializedVcpuStateSize();
  fbl::AllocChecker ac;
  ktl::unique_ptr<uint8_t[]> buf(new (&ac) uint8_t[len]);
  ASSERT_TRUE(ac.check(), "alloc serialized state\n");
  ktl::unique_ptr<VcpuArchState> state(new (&ac) VcpuArchState{});
  ASSERT_TRUE(ac.check(), "alloc arch state\n");

  size_t actual = 0;
  ASSERT_EQ(ZX_OK, vcpu->ReadStateFull(buf.get(), len, &actual), "ReadStateFull\n");
  ASSERT_EQ(ZX_OK, DeserializeVcpuState(*state, buf.get(), actual).status_value(),
            "deserialize\n");
  const uint64_t good_xcr0 = state->xcr0;

  // Restore `state` with `xcr0` substituted, always with guest CR4.OSXSAVE set
  // so the value would genuinely be loaded, and RIP back at the top of the code.
  auto write_with_xcr0 = [&](uint64_t xcr0) -> zx_status_t {
    state->xcr0 = xcr0;
    state->cr4 |= X86_CR4_OSXSAVE;
    state->rip = kCodeGpa;
    if (auto r = SerializeVcpuState(*state, buf.get(), len); r.is_error()) {
      return r.status_value();
    }
    return vcpu->WriteStateFull(buf.get(), len);
  };

  // Each of these is a value XSETBV answers with #GP. They are chosen to be
  // hostile on any CPU: where a bit happens to be unsupported here, the
  // supported-set test refuses it; where it is supported, a dependency rule
  // does. (The XSAVE-area size bound cannot be provoked portably -- it needs an
  // AVX-512 host, where the 5/6/7 case below becomes the size case instead.)
  struct HostileXcr0 {
    uint64_t value;
    const char* why;
  };
  const HostileXcr0 hostile[] = {
      {0, "XCR0 with x87 (bit 0) cleared -- XSETBV always #GPs on this\n"},
      {X86_XSAVE_STATE_BIT_X87 | X86_XSAVE_STATE_BIT_AVX, "AVX (bit 2) without SSE (bit 1)\n"},
      {1ull << 63, "reserved bit 63 set (and x87 clear)\n"},
      {good_xcr0 | (1ull << 62), "a component bit no CPU reports as supported\n"},
      {~0ull, "every bit set\n"},
      {good_xcr0 | X86_XSAVE_STATE_BIT_MPX_BNDREG, "MPX BNDREG (3) without BNDCSR (4)\n"},
      {good_xcr0 | X86_XSAVE_STATE_BIT_MPX_BNDCSR, "MPX BNDCSR (4) without BNDREG (3)\n"},
      {good_xcr0 | X86_XSAVE_STATE_BIT_AVX512_OPMASK, "AVX-512 opmask (5) alone\n"},
      // All three AVX-512 bits together, but with AVX (2) removed -- the
      // dependency, not the all-or-none rule.
      {(good_xcr0 & ~static_cast<uint64_t>(X86_XSAVE_STATE_BIT_AVX)) |
           X86_XSAVE_STATE_BIT_AVX512_OPMASK | X86_XSAVE_STATE_BIT_AVX512_LOWERZMM_HIGH |
           X86_XSAVE_STATE_BIT_AVX512_HIGHERZMM,
       "AVX-512 (5,6,7) without AVX (2)\n"},
      {good_xcr0 | (1ull << 18), "AMX XTILEDATA (18) without XTILECFG (17)\n"},
      {good_xcr0 | X86_XSAVE_STATE_BIT_PT, "a supervisor-only (IA32_XSS) component in XCR0\n"},
  };
  for (const HostileXcr0& h : hostile) {
    ASSERT_EQ(ZX_ERR_INVALID_ARGS, write_with_xcr0(h.value), h.why);
  }

  // 1b. XCR0 is not the only field of this structure that lands in host context.
  //     The syscall MSRs are written into the real MSRs by Vcpu::ContextSwitch()
  //     with a bare `wrmsr` before VM entry, and WRMSR #GPs on a non-canonical
  //     IA32_LSTAR / IA32_KERNEL_GS_BASE or a reserved-bit IA32_TSC_AUX. Same
  //     ABI, same host fault, so the same refusal is required.
  const uint64_t good_lstar = state->lstar;
  const uint64_t good_cstar = state->cstar;
  const uint64_t good_kernel_gs_base = state->kernel_gs_base;
  const uint64_t good_tsc_aux = state->tsc_aux;
  auto write_with_msrs = [&](uint64_t lstar, uint64_t cstar, uint64_t kernel_gs_base,
                             uint64_t tsc_aux) -> zx_status_t {
    state->xcr0 = good_xcr0;
    state->lstar = lstar;
    state->cstar = cstar;
    state->kernel_gs_base = kernel_gs_base;
    state->tsc_aux = tsc_aux;
    state->rip = kCodeGpa;
    if (auto r = SerializeVcpuState(*state, buf.get(), len); r.is_error()) {
      return r.status_value();
    }
    return vcpu->WriteStateFull(buf.get(), len);
  };
  // The lowest non-canonical address on a 48-bit-VA machine, and a bit set above
  // the 32 IA32_TSC_AUX actually has.
  constexpr uint64_t kNonCanonical = 0x0000800000000000ull;
  constexpr uint64_t kTscAuxReserved = 1ull << 32;
  ASSERT_EQ(ZX_ERR_INVALID_ARGS,
            write_with_msrs(kNonCanonical, good_cstar, good_kernel_gs_base, good_tsc_aux),
            "a non-canonical IA32_LSTAR must be refused, not written by the host\n");
  ASSERT_EQ(ZX_ERR_INVALID_ARGS,
            write_with_msrs(good_lstar, kNonCanonical, good_kernel_gs_base, good_tsc_aux),
            "a non-canonical IA32_CSTAR must be refused\n");
  ASSERT_EQ(ZX_ERR_INVALID_ARGS,
            write_with_msrs(good_lstar, good_cstar, kNonCanonical | 0xdead0000, good_tsc_aux),
            "a non-canonical IA32_KERNEL_GS_BASE must be refused\n");
  ASSERT_EQ(ZX_ERR_INVALID_ARGS,
            write_with_msrs(good_lstar, good_cstar, good_kernel_gs_base,
                            kTscAuxReserved | good_tsc_aux),
            "a reserved bit in IA32_TSC_AUX must be refused\n");
  // Restore the caller-supplied fields to legal values so the checks below see
  // the VCPU as the rejections left it.
  state->lstar = good_lstar;
  state->cstar = good_cstar;
  state->kernel_gs_base = good_kernel_gs_base;
  state->tsc_aux = good_tsc_aux;

  // 2. Nothing was applied. A restore refused halfway would be its own bug.
  ktl::unique_ptr<VcpuArchState> after(new (&ac) VcpuArchState{});
  ASSERT_TRUE(ac.check(), "alloc post-rejection state\n");
  ASSERT_EQ(ZX_OK, vcpu->ReadStateFull(buf.get(), len, &actual), "ReadStateFull after\n");
  ASSERT_EQ(ZX_OK, DeserializeVcpuState(*after, buf.get(), actual).status_value(),
            "deserialize after\n");
  EXPECT_EQ(good_xcr0, after->xcr0, "a refused restore must leave XCR0 untouched\n");
  EXPECT_EQ(good_lstar, after->lstar, "a refused restore must leave IA32_LSTAR untouched\n");
  EXPECT_EQ(good_cstar, after->cstar, "a refused restore must leave IA32_CSTAR untouched\n");
  EXPECT_EQ(good_kernel_gs_base, after->kernel_gs_base,
            "a refused restore must leave IA32_KERNEL_GS_BASE untouched\n");
  EXPECT_EQ(good_tsc_aux, after->tsc_aux, "a refused restore must leave IA32_TSC_AUX untouched\n");

  // 3. The positive control, and the proof the machine survived: the same
  //    restore with a legal XCR0 is accepted, the entry loads it into the
  //    physical XCR0, and the guest runs to its I/O exit.
  ASSERT_EQ(ZX_OK, write_with_xcr0(good_xcr0), "a legal XCR0 must still be accepted\n");
  zx_port_packet_t after_pkt = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(after_pkt), "enter after the rejected restores\n");
  ASSERT_EQ(static_cast<uint8_t>(ZX_PKT_TYPE_GUEST_IO), static_cast<uint8_t>(after_pkt.type),
            "io after\n");
  EXPECT_EQ(static_cast<uint32_t>(kSentinel), static_cast<uint32_t>(after_pkt.guest_io.data[0]),
            "the guest must still run after the hostile restores were refused\n");

  printf(
      "hostile-XCR0 restore OK: %zu illegal XCR0 values plus 4 host-faulting syscall-MSR values "
      "were refused with ZX_ERR_INVALID_ARGS through ZX_VCPU_STATE_FULL, the VCPU's own XCR0 "
      "stayed %#lx, and the guest re-entered (so XSETBV really was reached) and reported %#x\n",
      sizeof(hostile) / sizeof(hostile[0]), good_xcr0,
      static_cast<uint32_t>(after_pkt.guest_io.data[0]));
#else
  printf("Not x86_64; skipping.\n");
#endif  // __x86_64__

  END_TEST;
}

#ifdef __x86_64__

// Offsets into an XSAVE area (Volume 1, Section 13.4).
constexpr size_t kMxcsrOffset = 24;
constexpr size_t kXstateBvOffset = 512;
constexpr size_t kXcompBvOffset = 520;
constexpr size_t kHeaderReservedOffset = 528;
constexpr uint64_t kXcompBvCompacted = 1ull << 63;

uint64_t ReadU64(const uint8_t* image, size_t offset) {
  uint64_t v;
  memcpy(&v, image + offset, sizeof(v));
  return v;
}
void WriteU64(uint8_t* image, size_t offset, uint64_t v) { memcpy(image + offset, &v, sizeof(v)); }
uint32_t ReadU32(const uint8_t* image, size_t offset) {
  uint32_t v;
  memcpy(&v, image + offset, sizeof(v));
  return v;
}
void WriteU32(uint8_t* image, size_t offset, uint32_t v) { memcpy(image + offset, &v, sizeof(v)); }

const char* RestoreInstructionName(enum x86_extended_register_restore_kind kind) {
  switch (kind) {
    case X86_EXTENDED_REGISTER_RESTORE_XRSTORS:
      return "XRSTORS";
    case X86_EXTENDED_REGISTER_RESTORE_XRSTOR:
      return "XRSTOR";
    case X86_EXTENDED_REGISTER_RESTORE_FXRSTOR:
      return "FXRSTOR";
    case X86_EXTENDED_REGISTER_RESTORE_NONE:
      return "none";
  }
  return "?";
}

// Synthetic standard-format XSAVE area sizes, for driving ValidateGuestXcr0Rules
// against parts this one is not. Two of them, differing only in what AVX-512
// costs, so the 1 KiB buffer bound can be isolated: the same XCR0 that the
// "small" machine accepts is refused on the "big" one for size and nothing else.
zx::result<uint32_t> FakeXsaveSizeSmall(uint64_t xcr0) {
  uint32_t size = 576;
  if (xcr0 & X86_XSAVE_STATE_BIT_AVX) {
    size = 576 + 256;
  }
  return zx::ok(size);
}
// A third machine, differing from FakeXsaveSizeSmall only in that PKRU extends
// the area. Exists so the synthetic leaf-0xD assertions below expect two
// DIFFERENT sizes: against one machine alone, "return 832" satisfies them.
zx::result<uint32_t> FakeXsaveSizePkru(uint64_t xcr0) {
  uint32_t size = 576;
  if (xcr0 & X86_XSAVE_STATE_BIT_AVX) {
    size = 576 + 256;
  }
  if (xcr0 & X86_XSAVE_STATE_BIT_PKRU) {
    size = 576 + 256 + 8;
  }
  return zx::ok(size);
}
zx::result<uint32_t> FakeXsaveSizeBig(uint64_t xcr0) {
  uint32_t size = 576;
  if (xcr0 & X86_XSAVE_STATE_BIT_AVX) {
    size = 576 + 256;
  }
  // Roughly a real AVX-512 machine: opmask + ZMM_Hi256 + Hi16_ZMM take the area
  // to ~2.5 KiB, well past X86_MAX_EXTENDED_REGISTER_SIZE.
  if (xcr0 & (X86_XSAVE_STATE_BIT_AVX512_OPMASK | X86_XSAVE_STATE_BIT_AVX512_LOWERZMM_HIGH |
              X86_XSAVE_STATE_BIT_AVX512_HIGHERZMM)) {
    size = 2688;
  }
  return zx::ok(size);
}

#endif  // __x86_64__

// The `xsave` member of ZX_VCPU_STATE_FULL is the last field of this structure
// that is applied to the physical machine in host context.
//
// Vcpu::RestoreArchState memcpy's those 1024 caller-supplied bytes into
// Vcpu::extended_register_state_, and swap_extended_registers() then hands that
// buffer to XRSTORS / XRSTOR / FXRSTOR with the host running. Every #GP
// condition of those instructions is reachable from any caller holding a VCPU
// handle: a reserved MXCSR bit, an XSTATE_BV or XCOMP_BV the restore instruction
// refuses, a nonzero reserved byte in the XSAVE header. None of that is a guest
// fault; it is a kernel fault, i.e. a machine-wide denial of service.
//
// Before ValidateGuestXsaveImage() existed, every case below faulted the kernel
// outright rather than returning an error, so the failure mode of this test on
// the unfixed tree is a panic, not a failed assertion.
//
// Structure mirrors the hostile-XCR0 test: drive VcpuDispatcher (the object a
// zx_vcpu_write_state() handle resolves to), assert each hostile image is
// refused, assert nothing was applied, and prove the machine is still alive by
// running the guest again. The positive control is deliberately NOT just the
// captured image: a legally *different* image is also accepted, so a validator
// that whitelisted the one value a round trip produces would fail here.
bool vcpu_restore_rejects_hostile_xsave() {
  BEGIN_TEST;

#ifdef __x86_64__
  fbl::RefPtr<VmObjectPaged> ram;
  ASSERT_EQ(ZX_OK, VmObjectPaged::Create(PMM_ALLOC_FLAG_ANY, 0u, kGuestRamSize, &ram), "ram\n");
  ASSERT_EQ(ZX_OK, WriteIdentityTables(ram), "tables\n");
  // mov al,0x42; out 0x10,al; hlt
  const uint8_t code[] = {0xB0, kSentinel, 0xE6, 0x10, 0xF4};
  ASSERT_EQ(ZX_OK, ram->Write(code, kCodeGpa, sizeof(code)), "code\n");
  ASSERT_EQ(ZX_OK, ram->CommitRange(0, kGuestRamSize), "commit\n");

  auto lg = CreateLiveGuestDispatcher(ram, kCodeGpa);
  if (lg.is_error() && lg.status_value() == ZX_ERR_NOT_SUPPORTED) {
    printf("VMX not supported here; skipping hostile-XSAVE restore test.\n");
    return true;
  }
  ASSERT_EQ(ZX_OK, lg.status_value(), "create live guest (dispatchers)\n");
  VcpuDispatcher* vcpu = lg->vcpu.get();

  // Which instruction this host really issues decides which of the rules below
  // are the operative ones. Reported rather than assumed -- the whole point of
  // x86_extended_register_restore_instruction().
  const enum x86_extended_register_restore_kind kind =
      x86_extended_register_restore_instruction();
  printf("this host restores extended registers with %s; MXCSR_MASK is %#x\n",
         RestoreInstructionName(kind), x86_mxcsr_mask());

  // 1. Baseline: the guest runs.
  zx_port_packet_t p = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(p), "baseline enter\n");
  ASSERT_EQ(static_cast<uint8_t>(ZX_PKT_TYPE_GUEST_IO), static_cast<uint8_t>(p.type),
            "baseline io\n");
  ASSERT_EQ(static_cast<uint32_t>(kSentinel), static_cast<uint32_t>(p.guest_io.data[0]),
            "baseline sentinel\n");

  const size_t len = SerializedVcpuStateSize();
  fbl::AllocChecker ac;
  ktl::unique_ptr<uint8_t[]> buf(new (&ac) uint8_t[len]);
  ASSERT_TRUE(ac.check(), "alloc serialized state\n");
  ktl::unique_ptr<VcpuArchState> state(new (&ac) VcpuArchState{});
  ASSERT_TRUE(ac.check(), "alloc arch state\n");

  size_t actual = 0;
  ASSERT_EQ(ZX_OK, vcpu->ReadStateFull(buf.get(), len, &actual), "ReadStateFull\n");
  ASSERT_EQ(ZX_OK, DeserializeVcpuState(*state, buf.get(), actual).status_value(),
            "deserialize\n");

  // The image the machine itself produced, kept pristine to rebuild each case
  // from. Everything below mutates exactly one thing about it.
  ktl::unique_ptr<uint8_t[]> good(new (&ac) uint8_t[X86_MAX_EXTENDED_REGISTER_SIZE]);
  ASSERT_TRUE(ac.check(), "alloc good image\n");
  memcpy(good.get(), state->xsave, X86_MAX_EXTENDED_REGISTER_SIZE);
  const uint64_t good_xcr0 = state->xcr0;
  const uint64_t good_xstate_bv = ReadU64(good.get(), kXstateBvOffset);
  const uint64_t good_xcomp_bv = ReadU64(good.get(), kXcompBvOffset);
  const uint32_t good_mxcsr = ReadU32(good.get(), kMxcsrOffset);

  // Restore `state` with the XSAVE image replaced and RIP back at the top of the
  // code. CR4.OSXSAVE is set as well: it no longer decides whether the image is
  // restored (see Vcpu::LoadExtendedRegisters), but leaving it set keeps this a
  // realistic guest rather than one whose extended state is inert.
  auto write_with_image = [&](const uint8_t* image) -> zx_status_t {
    memcpy(state->xsave, image, X86_MAX_EXTENDED_REGISTER_SIZE);
    state->xcr0 = good_xcr0;
    state->cr4 |= X86_CR4_OSXSAVE;
    state->rip = kCodeGpa;
    if (auto r = SerializeVcpuState(*state, buf.get(), len); r.is_error()) {
      return r.status_value();
    }
    return vcpu->WriteStateFull(buf.get(), len);
  };

  ktl::unique_ptr<uint8_t[]> img(new (&ac) uint8_t[X86_MAX_EXTENDED_REGISTER_SIZE]);
  ASSERT_TRUE(ac.check(), "alloc scratch image\n");
  auto reset = [&]() { memcpy(img.get(), good.get(), X86_MAX_EXTENDED_REGISTER_SIZE); };

  // (a) MXCSR bits outside this part's MXCSR_MASK. Bits 31:16 are reserved on
  //     every part that has ever existed, so this is hostile everywhere -- and
  //     it is the one case that faults all three restore instructions.
  reset();
  WriteU32(img.get(), kMxcsrOffset, good_mxcsr | (1u << 31));
  ASSERT_EQ(ZX_ERR_INVALID_ARGS, write_with_image(img.get()),
            "MXCSR bit 31 is reserved on every part; loading it #GPs the host\n");
  reset();
  WriteU32(img.get(), kMxcsrOffset, good_mxcsr | (1u << 16));
  ASSERT_EQ(ZX_ERR_INVALID_ARGS, write_with_image(img.get()),
            "MXCSR bit 16 is reserved on every part\n");
  // And every bit outside the *measured* mask, whatever it is here.
  reset();
  WriteU32(img.get(), kMxcsrOffset, good_mxcsr | ~x86_mxcsr_mask());
  ASSERT_EQ(ZX_ERR_INVALID_ARGS, write_with_image(img.get()),
            "no bit outside this host's real MXCSR_MASK may be restored\n");

  // The remaining cases are XSAVE-header cases, which only exist when the host
  // restores with XRSTOR or XRSTORS. On an FXRSTOR-only part the header is never
  // read and refusing these would be refusing what hardware accepts.
  if (kind == X86_EXTENDED_REGISTER_RESTORE_XRSTOR ||
      kind == X86_EXTENDED_REGISTER_RESTORE_XRSTORS) {
    // (b) Nonzero reserved bytes in the XSAVE header (offsets 528..575).
    //     #GP for both XRSTOR and XRSTORS.
    reset();
    img[kHeaderReservedOffset] = 1;
    ASSERT_EQ(ZX_ERR_INVALID_ARGS, write_with_image(img.get()),
              "the first reserved header byte must be zero\n");
    reset();
    img[kHeaderReservedOffset + 47] = 0xff;
    ASSERT_EQ(ZX_ERR_INVALID_ARGS, write_with_image(img.get()),
              "the last reserved header byte must be zero\n");

    // (c) XSTATE_BV naming a component that is not enabled. Bit 62 is a
    //     component no part implements, so it is in no XCR0 and in no XCOMP_BV:
    //     under XRSTOR it violates "XSTATE_BV subset of XCR0", under XRSTORS
    //     "XSTATE_BV subset of XCOMP_BV". Hostile either way.
    reset();
    WriteU64(img.get(), kXstateBvOffset, good_xstate_bv | (1ull << 62));
    ASSERT_EQ(ZX_ERR_INVALID_ARGS, write_with_image(img.get()),
              "XSTATE_BV must not name a component outside the enabled set\n");
    reset();
    WriteU64(img.get(), kXstateBvOffset, ~kXcompBvCompacted);
    ASSERT_EQ(ZX_ERR_INVALID_ARGS, write_with_image(img.get()),
              "an XSTATE_BV of every component must be refused\n");

    // A component this CPU may well implement but that is not in the guest's
    // XCR0 -- the realistic version of the same fault, rather than a bit no
    // silicon has.
    uint64_t absent = 0;
    for (uint32_t i = 2; i <= 62; ++i) {
      if (!(good_xcr0 & (1ull << i))) {
        absent = 1ull << i;
        break;
      }
    }
    ASSERT_NE(0u, absent, "the guest XCR0 cannot name every component\n");
    reset();
    WriteU64(img.get(), kXstateBvOffset, good_xstate_bv | absent);
    ASSERT_EQ(ZX_ERR_INVALID_ARGS, write_with_image(img.get()),
              "XSTATE_BV must not name a component absent from the guest's XCR0\n");

    // (d) XCOMP_BV format. Flipping bit 63 is hostile in both directions: this
    //     host's save path produces exactly one of the two formats, and the
    //     restore instruction that goes with it #GPs on the other.
    reset();
    WriteU64(img.get(), kXcompBvOffset, good_xcomp_bv ^ kXcompBvCompacted);
    ASSERT_EQ(ZX_ERR_INVALID_ARGS, write_with_image(img.get()),
              "the compacted-format bit must match the restore instruction\n");
    //     A component bit in XCOMP_BV that is not in XCR0: under XRSTORS that is
    //     the "XCOMP_BV subset of XCR0" rule, under XRSTOR it is a nonzero
    //     XCOMP_BV in the standard format.
    reset();
    WriteU64(img.get(), kXcompBvOffset, good_xcomp_bv | (1ull << 62));
    ASSERT_EQ(ZX_ERR_INVALID_ARGS, write_with_image(img.get()),
              "XCOMP_BV must not name a component outside the enabled set\n");
  }

  // 2. Nothing was applied: the VCPU's own image is still the one it saved.
  ktl::unique_ptr<VcpuArchState> after(new (&ac) VcpuArchState{});
  ASSERT_TRUE(ac.check(), "alloc post-rejection state\n");
  ASSERT_EQ(ZX_OK, vcpu->ReadStateFull(buf.get(), len, &actual), "ReadStateFull after\n");
  ASSERT_EQ(ZX_OK, DeserializeVcpuState(*after, buf.get(), actual).status_value(),
            "deserialize after\n");
  EXPECT_EQ(0, memcmp(good.get(), after->xsave, X86_MAX_EXTENDED_REGISTER_SIZE),
            "a refused restore must leave the XSAVE area untouched\n");
  EXPECT_EQ(good_xcr0, after->xcr0, "a refused restore must leave XCR0 untouched\n");

  // 3. Positive controls. First the captured image, then a legally *different*
  //    one -- MXCSR moved to another value the mask permits and a pattern planted
  //    in XMM0 -- which a whitelist-of-one validator would refuse. Both are
  //    followed by a real entry, so the host actually executes the restore
  //    instruction on them.
  ASSERT_EQ(ZX_OK, write_with_image(good.get()), "the captured image must be accepted\n");
  zx_port_packet_t after_pkt = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(after_pkt), "enter after the rejected restores\n");
  ASSERT_EQ(static_cast<uint8_t>(ZX_PKT_TYPE_GUEST_IO), static_cast<uint8_t>(after_pkt.type),
            "io after\n");
  EXPECT_EQ(static_cast<uint32_t>(kSentinel), static_cast<uint32_t>(after_pkt.guest_io.data[0]),
            "the guest must still run after the hostile restores were refused\n");

  reset();
  // Toggle MXCSR.RC bit 1 (bit 13). It is inside 0xFFBF, so it is inside every
  // real MXCSR_MASK, and flipping it is guaranteed to change the value -- unlike
  // writing a constant such as the init 0x1f80, which is very likely to be
  // exactly what was captured, since this guest never executes an FP or SIMD
  // instruction. Also plant a pattern in the XMM0 slot (legacy offset 160).
  const uint32_t other_mxcsr = good_mxcsr ^ (1u << 13);
  WriteU32(img.get(), kMxcsrOffset, other_mxcsr);
  memset(img.get() + 160, 0x5a, 16);
  // Enforced, not assumed: if this image were byte-identical to the captured one,
  // accepting it would say nothing about a whitelist-of-one implementation.
  ASSERT_NE(0, memcmp(img.get(), good.get(), X86_MAX_EXTENDED_REGISTER_SIZE),
            "the second positive control must not be the captured image\n");
  ASSERT_EQ(ZX_OK, write_with_image(img.get()),
            "a legal image that is not the captured one must also be accepted\n");
  zx_port_packet_t other_pkt = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(other_pkt), "enter with a different legal image\n");
  ASSERT_EQ(static_cast<uint8_t>(ZX_PKT_TYPE_GUEST_IO), static_cast<uint8_t>(other_pkt.type),
            "io after the second legal image\n");
  EXPECT_EQ(static_cast<uint32_t>(kSentinel), static_cast<uint32_t>(other_pkt.guest_io.data[0]),
            "the guest must run after a legal but different XSAVE image\n");
  // And it survived a full entry: the restore took it, the entry XRSTOR'd it, the
  // exit XSAVE'd over the same buffer, and the value is still the one supplied.
  //
  // Deliberately not claimed as proof that MXCSR reached the physical register:
  // XSAVEOPT/XSAVES may leave an unmodified field untouched, in which case this
  // reads back the byte the restore itself wrote. Proving physical application
  // would take guest code executing `stmxcsr` into guest memory and reading that
  // memory back out, which this guest is not built to do.
  ASSERT_EQ(ZX_OK, vcpu->ReadStateFull(buf.get(), len, &actual), "ReadStateFull final\n");
  ASSERT_EQ(ZX_OK, DeserializeVcpuState(*after, buf.get(), actual).status_value(),
            "deserialize final\n");
  EXPECT_EQ(other_mxcsr, ReadU32(after->xsave, kMxcsrOffset),
            "the accepted image must survive the entry's restore and the exit's save\n");

  printf(
      "hostile-XSAVE restore OK: reserved MXCSR bits, nonzero header reserved bytes, and "
      "out-of-set XSTATE_BV/XCOMP_BV were all refused with ZX_ERR_INVALID_ARGS through "
      "ZX_VCPU_STATE_FULL; the VCPU's own image was untouched; and two *different* legal images "
      "were each accepted and carried through a real entry without faulting the host (the guest "
      "reported %#x, then %#x)\n",
      static_cast<uint32_t>(after_pkt.guest_io.data[0]),
      static_cast<uint32_t>(other_pkt.guest_io.data[0]));
#else
  printf("Not x86_64; skipping.\n");
#endif  // __x86_64__

  END_TEST;
}

// The two validators, driven directly against synthetic machines.
//
// Read from the real CPU, both are only ever exercised for what this part
// happens to implement. On a host without AVX-512 or AMX the XCR0 size bound is
// unreachable and several dependency rules are dead; and since only one of
// XRSTORS / XRSTOR / FXRSTOR is ever issued here, two thirds of the image rules
// are dead too. Worse, a live test's positive control can only re-offer the
// value the machine itself produced, so an implementation that whitelisted
// exactly that value would pass it.
//
// These cases fix both: the environment is a parameter, so every rule is
// reachable and every table has positive cases that no whitelist-of-one could
// satisfy.
bool vcpu_restore_validator_rules() {
  BEGIN_TEST;

#ifdef __x86_64__
  // ---- ValidateGuestXcr0Rules ----
  //
  // A machine richer than any we have: x87, SSE, AVX, MPX (3,4), AVX-512
  // (5,6,7), PKRU (9) and AMX (17,18).
  constexpr uint64_t kAmxCfg = 1ull << 17;
  constexpr uint64_t kAmxData = 1ull << 18;
  constexpr uint64_t kAvx512 = X86_XSAVE_STATE_BIT_AVX512_OPMASK |
                               X86_XSAVE_STATE_BIT_AVX512_LOWERZMM_HIGH |
                               X86_XSAVE_STATE_BIT_AVX512_HIGHERZMM;
  constexpr uint64_t kMpx = X86_XSAVE_STATE_BIT_MPX_BNDREG | X86_XSAVE_STATE_BIT_MPX_BNDCSR;
  constexpr uint64_t kSynthSupported = X86_XSAVE_STATE_BIT_X87 | X86_XSAVE_STATE_BIT_SSE |
                                       X86_XSAVE_STATE_BIT_AVX | kMpx | kAvx512 |
                                       X86_XSAVE_STATE_BIT_PKRU | kAmxCfg | kAmxData;

  struct Xcr0Case {
    uint64_t xcr0;
    bool xsave_supported;
    uint64_t supported;
    XsaveSizeFn size_fn;
    bool expect_ok;
    const char* why;
  };
  const Xcr0Case xcr0_cases[] = {
      // Positive cases, several distinct values -- no whitelist of one passes.
      {X86_XSAVE_STATE_BIT_X87, true, kSynthSupported, FakeXsaveSizeSmall, true, "x87 alone\n"},
      {X86_XSAVE_STATE_BIT_X87 | X86_XSAVE_STATE_BIT_SSE, true, kSynthSupported, FakeXsaveSizeSmall,
       true, "x87+SSE\n"},
      {0x7, true, kSynthSupported, FakeXsaveSizeSmall, true, "x87+SSE+AVX\n"},
      {0x7 | kMpx, true, kSynthSupported, FakeXsaveSizeSmall, true, "MPX pair together\n"},
      {0x7 | X86_XSAVE_STATE_BIT_PKRU, true, kSynthSupported, FakeXsaveSizeSmall, true, "PKRU\n"},
      {0x7 | kAmxCfg, true, kSynthSupported, FakeXsaveSizeSmall, true,
       "AMX XTILECFG alone is architecturally allowed\n"},
      {0x7 | kAvx512, true, kSynthSupported, FakeXsaveSizeSmall, true,
       "AVX-512 complete, on a machine where it fits\n"},
      {0, false, 0, FakeXsaveSizeSmall, true, "XCR0 zero on a machine without XSAVE\n"},

      // The size bound, isolated: identical XCR0, identical supported set, one
      // machine where the state fits in X86_MAX_EXTENDED_REGISTER_SIZE and one
      // where it does not. This is the rule no host we own can reach.
      {0x7 | kAvx512, true, kSynthSupported, FakeXsaveSizeBig, false,
       "AVX-512 whose XSAVE area overruns the kernel's 1 KiB buffer\n"},

      // Architectural rejections.
      {0, true, kSynthSupported, FakeXsaveSizeSmall, false, "x87 (bit 0) cleared\n"},
      {X86_XSAVE_STATE_BIT_X87 | X86_XSAVE_STATE_BIT_AVX, true, kSynthSupported, FakeXsaveSizeSmall,
       false, "AVX without SSE\n"},
      {0x7 | X86_XSAVE_STATE_BIT_MPX_BNDREG, true, kSynthSupported, FakeXsaveSizeSmall, false,
       "MPX BNDREG without BNDCSR\n"},
      {0x7 | X86_XSAVE_STATE_BIT_MPX_BNDCSR, true, kSynthSupported, FakeXsaveSizeSmall, false,
       "MPX BNDCSR without BNDREG\n"},
      {0x7 | X86_XSAVE_STATE_BIT_AVX512_OPMASK, true, kSynthSupported, FakeXsaveSizeSmall, false,
       "AVX-512 opmask alone\n"},
      {0x3 | kAvx512, true, kSynthSupported, FakeXsaveSizeSmall, false,
       "AVX-512 without AVX\n"},
      {0x7 | kAmxData, true, kSynthSupported, FakeXsaveSizeSmall, false,
       "AMX XTILEDATA without XTILECFG\n"},
      {0x7 | X86_XSAVE_STATE_BIT_PT, true, kSynthSupported, FakeXsaveSizeSmall, false,
       "a supervisor-only (IA32_XSS) component\n"},
      {0x7 | (1ull << 62), true, kSynthSupported, FakeXsaveSizeSmall, false,
       "a component this machine does not support\n"},
      {~0ull, true, kSynthSupported, FakeXsaveSizeSmall, false, "every bit set\n"},
      {X86_XSAVE_STATE_BIT_X87, false, 0, FakeXsaveSizeSmall, false,
       "any nonzero XCR0 on a machine without XSAVE\n"},
  };
  for (const Xcr0Case& c : xcr0_cases) {
    const zx_status_t got =
        ValidateGuestXcr0Rules(c.xcr0, c.xsave_supported, c.supported, c.size_fn).status_value();
    ASSERT_EQ(c.expect_ok ? ZX_OK : ZX_ERR_INVALID_ARGS, got, c.why);
  }

  // ---- What a guest may name on a synthetic AVX-512 machine ------------
  //
  // The table above answers "does the validator apply the architectural rules";
  // this answers the different question of what
  // set the validator is handed in the first place. CPUID leaf 0xD advertised the
  // host's component bitmap unmasked while ValidateGuestXcr0 refused AVX-512 on
  // every host (its ~2.5 KiB area cannot fit X86_MAX_EXTENDED_REGISTER_SIZE), so
  // an AVX-512 part advertised components whose XSETBV was certain to be refused.
  // Neither machine here has AVX-512, so `kSynthSupported` is the only way to ask.
  const uint64_t advertised = GuestXsaveComponents(kSynthSupported);
  EXPECT_EQ(0u, advertised & kAvx512,
            "AVX-512's XCR0 components must not be advertised to a guest: ValidateGuestXcr0 "
            "refuses them on every host, and handle_cpuid already clears the AVX-512 feature "
            "bits from leaf 7\n");
  EXPECT_EQ(0u, advertised & kMpx, "nor MPX's, which this kernel does not back either\n");
  EXPECT_EQ(0u, advertised & (kAmxCfg | kAmxData),
            "nor AMX's: XTILEDATA alone is 8 KiB, so the 1 KiB buffer bound refuses it on every "
            "part that has it -- exactly the AVX-512 lie in a second place\n");
  // ...and the mask is a denylist, not a wholesale refusal, or the lines above
  // would pass with `advertised == 0`.
  EXPECT_EQ(X86_XSAVE_STATE_BIT_X87 | X86_XSAVE_STATE_BIT_SSE | X86_XSAVE_STATE_BIT_AVX |
                X86_XSAVE_STATE_BIT_PKRU,
            advertised,
            "everything this kernel does back must survive the mask, exactly\n");

  // ---- Leaf-0xD sizes on the same synthetic AVX-512 machine ------------
  //
  // Masking the bitmap and leaving ECX -- "the size required by all supported
  // state components", Volume 2, Table 3-8 -- as the host's was a lie whose
  // magnitude this hardware cannot show. A measured Coffee Lake processor
  // withholds MPX and nothing else, so the difference between the host's ECX
  // and the honest one is 256
  // bytes; on a part with AVX-512 and AMX, which neither machine here is, the
  // guest would be handed a 2688-byte requirement for a component set whose
  // whole layout is 832 bytes. That is the case worth asserting, and
  // GuestXsaveMainLeaf takes the bitmap and the size function as parameters so
  // it can be asked here rather than only on whatever part is running.
  {
    auto leaf = GuestXsaveMainLeaf(kSynthSupported, /*guest_xcr0=*/0x3, FakeXsaveSizeBig);
    ASSERT_EQ(ZX_OK, leaf.status_value(), "synthetic leaf 0xD\n");
    EXPECT_EQ(static_cast<uint32_t>(advertised), leaf->eax,
              "the bitmap is the advertised set\n");
    EXPECT_EQ(0u, leaf->edx, "and nothing above component 31 survives on this machine\n");
    // THE ASSERTION THAT DISCRIMINATES. FakeXsaveSizeBig answers 2688 for
    // kSynthSupported and 832 for `advertised`, so a pass-through ECX and an
    // honest one are 1856 bytes apart here -- and 832 is also what the
    // per-component subleaves of an AVX-512-less bitmap would imply.
    EXPECT_EQ(FakeXsaveSizeBig(advertised).value(), leaf->ecx,
              "ECX must be the size of the set the guest MAY enable, not the size of the set the "
              "machine happens to implement\n");
    EXPECT_NE(FakeXsaveSizeBig(kSynthSupported).value(), leaf->ecx,
              "and on this machine those two differ, so the assertion above is not vacuous\n");
    // EBX is the other question, and the two must not be answered with one
    // number: XCR0 here is x87+SSE, whose area is the 576-byte floor.
    EXPECT_EQ(576u, leaf->ebx, "EBX is the size for the ENABLED components\n");
    EXPECT_LE(leaf->ebx, leaf->ecx, "the enabled set can never need more than the supported set\n");
    printf("synthetic leaf 0xD: bitmap %#x, ECX %u (the host set would have said %u), EBX %u\n",
           leaf->eax, leaf->ecx, FakeXsaveSizeBig(kSynthSupported).value(), leaf->ebx);

    // THE SAME BITMAP, A DIFFERENT LAYOUT. Both machines advertise 0x207, and
    // on this one PKRU pushes the supported-set size to 840 -- so an
    // implementation that returned the constant 832 would satisfy every
    // assertion above and fail here. One synthetic machine cannot distinguish
    // that cheapest incorrect implementation.
    auto other = GuestXsaveMainLeaf(kSynthSupported, /*guest_xcr0=*/0x3, FakeXsaveSizePkru);
    ASSERT_EQ(ZX_OK, other.status_value(), "second synthetic leaf 0xD\n");
    EXPECT_EQ(static_cast<uint32_t>(advertised), other->eax, "same bitmap\n");
    EXPECT_EQ(840u, other->ecx,
              "ECX must follow the machine's layout, not a constant that happens to be right on "
              "one of them\n");
    EXPECT_EQ(576u, other->ebx, "and EBX must still be the enabled set's size\n");
    ASSERT_NE(leaf->ecx, other->ecx,
              "the two synthetic machines must disagree about ECX, or the pair proves nothing\n");
  }

  // THE RESIDUAL THE DENYLIST CANNOT EXPRESS, asserted against the REAL host
  // rather than a synthetic one, because it is a property of this part's
  // standard-layout offsets and not of the constant.
  //
  // A component's XSAVE offset depends on which components precede it, so PKRU --
  // eight bytes -- sits past X86_MAX_EXTENDED_REGISTER_SIZE on a part that also
  // has AVX-512 and comfortably inside it on a part that does not. No list of bits
  // can say that. What can is this: whatever set CPUID advertises here, this host
  // must accept it. It passes trivially on the measured Coffee Lake processor
  // (x87|SSE|AVX) and is the gate
  // that fires the day this kernel runs on a part where the two disagree.
  {
    cpuid_leaf l;
    if (x86_get_cpuid_subleaf(X86_CPUID_XSAVE, 0, &l)) {
      const uint64_t host_components = (static_cast<uint64_t>(l.d) << 32) | l.a;
      const uint64_t here = GuestXsaveComponents(host_components);
      EXPECT_EQ(ZX_OK, ValidateGuestXcr0(here).status_value(),
                "the component set guest CPUID advertises on THIS host must be one this host's "
                "own XCR0 validator accepts -- advertisement and acceptance are supposed to come "
                "from one set\n");
      printf("advertised-vs-accepted OK: host CPUID.D.0 EDX:EAX = %#lx, advertised %#lx\n",
             host_components, here);
    }
  }

  // THE DISCRIMINATING PAIR, and the reason `FakeXsaveSizeSmall` is used for both:
  // on a machine where AVX-512 state FITS, the 1 KiB bound cannot be what refuses
  // it, so only the advertised set can be. Run against `FakeXsaveSizeBig` this
  // assertion would pass with no mask at all -- exactly the broken state in which
  // the size bound was doing all the work and CPUID was lying.
  EXPECT_EQ(ZX_ERR_INVALID_ARGS,
            ValidateGuestXcr0Rules(0x7 | kAvx512, /*xsave_supported=*/true, advertised,
                                   FakeXsaveSizeSmall)
                .status_value(),
            "a guest XCR0 naming AVX-512 must be refused for NOT BEING ADVERTISED, on a machine "
            "where its state would have fitted\n");
  EXPECT_EQ(
      ZX_OK,
      ValidateGuestXcr0Rules(0x7, /*xsave_supported=*/true, advertised, FakeXsaveSizeSmall)
          .status_value(),
      "and x87+SSE+AVX must still be accepted against that same narrowed set\n");

  // ---- ValidateXsaveImageRules ----
  fbl::AllocChecker ac;
  ktl::unique_ptr<uint8_t[]> image(new (&ac) uint8_t[X86_MAX_EXTENDED_REGISTER_SIZE]);
  ASSERT_TRUE(ac.check(), "alloc synthetic image\n");

  // A synthetic host: x87+SSE+AVX enabled, and a part that implements DAZ (so
  // MXCSR bit 6 is legal there and illegal on the 0xFFBF part below).
  constexpr uint64_t kLiveXcr0 = 0x7;
  constexpr uint32_t kMaskWithDaz = 0xffff;
  constexpr uint32_t kMaskWithoutDaz = 0xffbf;
  constexpr uint32_t kDaz = 1u << 6;
  constexpr uint32_t kMaskedExceptions = 0x3f << 7;

  struct ImageCase {
    enum x86_extended_register_restore_kind instruction;
    uint64_t live_xcr0;
    uint32_t mxcsr_mask;
    uint32_t mxcsr;
    uint64_t xstate_bv;
    uint64_t xcomp_bv;
    bool poison_reserved;
    bool expect_ok;
    const char* why;
  };
  const ImageCase image_cases[] = {
      // --- MXCSR, against the mask rather than a constant. The same image is
      //     legal on a part that implements DAZ and illegal on one that does
      //     not, which is precisely why x86_mxcsr_mask() had to be measured.
      {X86_EXTENDED_REGISTER_RESTORE_XRSTOR, kLiveXcr0, kMaskWithDaz, kMaskedExceptions | kDaz,
       kLiveXcr0, 0, false, true, "DAZ is legal on a part whose MXCSR_MASK has bit 6\n"},
      {X86_EXTENDED_REGISTER_RESTORE_XRSTOR, kLiveXcr0, kMaskWithoutDaz, kMaskedExceptions | kDaz,
       kLiveXcr0, 0, false, false, "DAZ is reserved on a part whose MXCSR_MASK does not\n"},
      {X86_EXTENDED_REGISTER_RESTORE_XRSTOR, kLiveXcr0, kMaskWithDaz, 0xffffffff, kLiveXcr0, 0,
       false, false, "MXCSR bits 31:16 are reserved on every part\n"},
      {X86_EXTENDED_REGISTER_RESTORE_FXRSTOR, kLiveXcr0, kMaskWithoutDaz, kMaskedExceptions | kDaz,
       0, 0, false, false, "FXRSTOR faults on a reserved MXCSR bit too\n"},
      {X86_EXTENDED_REGISTER_RESTORE_XRSTORS, kLiveXcr0, kMaskWithoutDaz, kMaskedExceptions | kDaz,
       kLiveXcr0, kLiveXcr0 | kXcompBvCompacted, false, false,
       "so does XRSTORS\n"},
      // ...but only because the live XCR0 selects SSE. XRSTOR and XRSTORS load
      // MXCSR only when the restore mask names SSE or AVX state, so under an
      // x87-only XCR0 those four bytes are dead and an image carrying reserved
      // bits there is one hardware accepts. Refusing it would be over-refusal, so
      // these two are positive cases, not negative ones.
      {X86_EXTENDED_REGISTER_RESTORE_XRSTOR, X86_XSAVE_STATE_BIT_X87, kMaskWithoutDaz, 0xffffffff,
       X86_XSAVE_STATE_BIT_X87, 0, false, true,
       "XRSTOR does not load MXCSR under an x87-only XCR0\n"},
      {X86_EXTENDED_REGISTER_RESTORE_XRSTORS, X86_XSAVE_STATE_BIT_X87, kMaskWithoutDaz, 0xffffffff,
       X86_XSAVE_STATE_BIT_X87, X86_XSAVE_STATE_BIT_X87 | kXcompBvCompacted, false, true,
       "nor does XRSTORS\n"},
      // AVX alone in the live XCR0 is enough to make it live again. (Not a legal
      // XCR0 for XSETBV -- AVX requires SSE -- but this function is about what
      // the restore instruction does with the mask it is given, and the pairing
      // rule belongs to ValidateGuestXcr0.)
      {X86_EXTENDED_REGISTER_RESTORE_XRSTOR, X86_XSAVE_STATE_BIT_X87 | X86_XSAVE_STATE_BIT_AVX,
       kMaskWithoutDaz, 0xffffffff, X86_XSAVE_STATE_BIT_X87, 0, false, false,
       "AVX in the restore mask loads MXCSR just as SSE does\n"},
      // FXRSTOR has no restore mask at all: it always loads MXCSR.
      {X86_EXTENDED_REGISTER_RESTORE_FXRSTOR, X86_XSAVE_STATE_BIT_X87, kMaskWithoutDaz, 0xffffffff,
       0, 0, false, false, "FXRSTOR loads MXCSR whatever XCR0 says\n"},

      // --- FXRSTOR reads no XSAVE header, so nothing in one can fault it.
      //     Refusing these would be refusing what hardware accepts.
      {X86_EXTENDED_REGISTER_RESTORE_FXRSTOR, kLiveXcr0, kMaskWithDaz, kMaskedExceptions, ~0ull,
       ~0ull, true, true, "FXRSTOR ignores XSTATE_BV, XCOMP_BV and the reserved bytes\n"},
      {X86_EXTENDED_REGISTER_RESTORE_NONE, kLiveXcr0, kMaskWithoutDaz, 0xffffffff, ~0ull, ~0ull,
       true, true, "a host that restores nothing cannot be faulted by anything\n"},

      // --- XRSTOR. Architecturally it can consume the compacted format too, on
      //     a part reporting XSAVEC; admitting only the standard one is this
      //     validator's policy, matching the save path that pairs with it.
      {X86_EXTENDED_REGISTER_RESTORE_XRSTOR, kLiveXcr0, kMaskWithDaz, kMaskedExceptions, 0, 0,
       false, true, "an all-initial standard-format image\n"},
      {X86_EXTENDED_REGISTER_RESTORE_XRSTOR, kLiveXcr0, kMaskWithDaz, kMaskedExceptions, 0x3, 0,
       false, true, "a proper subset of the live XCR0\n"},
      {X86_EXTENDED_REGISTER_RESTORE_XRSTOR, kLiveXcr0, kMaskWithDaz, kMaskedExceptions, kLiveXcr0,
       0, false, true, "exactly the live XCR0\n"},
      {X86_EXTENDED_REGISTER_RESTORE_XRSTOR, kLiveXcr0, kMaskWithDaz, kMaskedExceptions, 0xf, 0,
       false, false, "XSTATE_BV naming a component outside the live XCR0\n"},
      {X86_EXTENDED_REGISTER_RESTORE_XRSTOR, kLiveXcr0, kMaskWithDaz, kMaskedExceptions, ~0ull, 0,
       false, false, "XSTATE_BV of everything\n"},
      {X86_EXTENDED_REGISTER_RESTORE_XRSTOR, kLiveXcr0, kMaskWithDaz, kMaskedExceptions, kLiveXcr0,
       kLiveXcr0 | kXcompBvCompacted, false, false,
       "a compacted image, which this validator admits only for XRSTORS\n"},
      {X86_EXTENDED_REGISTER_RESTORE_XRSTOR, kLiveXcr0, kMaskWithDaz, kMaskedExceptions, kLiveXcr0,
       kLiveXcr0, false, false, "bits 62:0 of XCOMP_BV must be zero in the standard format\n"},
      {X86_EXTENDED_REGISTER_RESTORE_XRSTOR, kLiveXcr0, kMaskWithDaz, kMaskedExceptions, kLiveXcr0,
       0, true, false, "nonzero reserved bytes in the XSAVE header\n"},

      // --- XRSTORS: compacted format only.
      {X86_EXTENDED_REGISTER_RESTORE_XRSTORS, kLiveXcr0, kMaskWithDaz, kMaskedExceptions, kLiveXcr0,
       kLiveXcr0 | kXcompBvCompacted, false, true, "a well-formed compacted image\n"},
      {X86_EXTENDED_REGISTER_RESTORE_XRSTORS, kLiveXcr0, kMaskWithDaz, kMaskedExceptions, 0x1,
       0x3 | kXcompBvCompacted, false, true, "XSTATE_BV a proper subset of XCOMP_BV\n"},
      {X86_EXTENDED_REGISTER_RESTORE_XRSTORS, kLiveXcr0, kMaskWithDaz, kMaskedExceptions, 0,
       kXcompBvCompacted, false, true, "an empty but compacted image\n"},
      {X86_EXTENDED_REGISTER_RESTORE_XRSTORS, kLiveXcr0, kMaskWithDaz, kMaskedExceptions, kLiveXcr0,
       kLiveXcr0, false, false, "the standard format handed to XRSTORS\n"},
      {X86_EXTENDED_REGISTER_RESTORE_XRSTORS, kLiveXcr0, kMaskWithDaz, kMaskedExceptions, 0, 0,
       false, false, "an all-zero header is standard format, which XRSTORS refuses\n"},
      {X86_EXTENDED_REGISTER_RESTORE_XRSTORS, kLiveXcr0, kMaskWithDaz, kMaskedExceptions, 0x7,
       0x3 | kXcompBvCompacted, false, false, "XSTATE_BV not a subset of XCOMP_BV\n"},
      {X86_EXTENDED_REGISTER_RESTORE_XRSTORS, kLiveXcr0, kMaskWithDaz, kMaskedExceptions, 0x7,
       0xf | kXcompBvCompacted, false, false, "XCOMP_BV naming a component outside the live XCR0\n"},
      {X86_EXTENDED_REGISTER_RESTORE_XRSTORS, kLiveXcr0, kMaskWithDaz, kMaskedExceptions,
       X86_XSAVE_STATE_BIT_PT, X86_XSAVE_STATE_BIT_PT | kXcompBvCompacted, false, false,
       "a supervisor (IA32_XSS) component, which the 1 KiB bound never covered\n"},
      {X86_EXTENDED_REGISTER_RESTORE_XRSTORS, kLiveXcr0, kMaskWithDaz, kMaskedExceptions, kLiveXcr0,
       kLiveXcr0 | kXcompBvCompacted, true, false,
       "nonzero reserved header bytes fault XRSTORS as well\n"},

      // --- The live XCR0 is a parameter, not a constant: the same image is
      //     legal on a machine with AVX-512 enabled and illegal on one without.
      {X86_EXTENDED_REGISTER_RESTORE_XRSTORS, 0x7 | kAvx512, kMaskWithDaz, kMaskedExceptions,
       0x7 | kAvx512, 0x7 | kAvx512 | kXcompBvCompacted, false, true,
       "AVX-512 state on a machine with AVX-512 enabled\n"},
      {X86_EXTENDED_REGISTER_RESTORE_XRSTORS, 0x7, kMaskWithDaz, kMaskedExceptions, 0x7 | kAvx512,
       0x7 | kAvx512 | kXcompBvCompacted, false, false,
       "the same image on a machine without it\n"},
  };
  for (const ImageCase& c : image_cases) {
    memset(image.get(), 0, X86_MAX_EXTENDED_REGISTER_SIZE);
    WriteU32(image.get(), kMxcsrOffset, c.mxcsr);
    WriteU64(image.get(), kXstateBvOffset, c.xstate_bv);
    WriteU64(image.get(), kXcompBvOffset, c.xcomp_bv);
    if (c.poison_reserved) {
      image[kHeaderReservedOffset + 3] = 0xa5;
    }
    const XsaveRestoreEnv env = {
        .instruction = c.instruction,
        .live_xcr0 = c.live_xcr0,
        .mxcsr_mask = c.mxcsr_mask,
    };
    const zx_status_t got = ValidateXsaveImageRules(image.get(), env).status_value();
    ASSERT_EQ(c.expect_ok ? ZX_OK : ZX_ERR_INVALID_ARGS, got, c.why);
  }

  printf(
      "validator rules OK: %zu synthetic XCR0 cases (including the >1 KiB size bound, which needs "
      "AVX-512 hardware to reach through CPUID) and %zu synthetic XSAVE-image cases covering all "
      "of XRSTORS/XRSTOR/FXRSTOR and both MXCSR_MASK shapes\n",
      sizeof(xcr0_cases) / sizeof(xcr0_cases[0]),
      sizeof(image_cases) / sizeof(image_cases[0]));
#else
  printf("Not x86_64; skipping.\n");
#endif  // __x86_64__

  END_TEST;
}

#ifdef __x86_64__

// The probe thread of vcpu_blocking_exit_does_not_leak_guest_xstate, below.
//
// It is pinned to the same logical CPU as the VCPU thread, because XCR0 is a
// per-logical-processor register: reading it anywhere else would say nothing
// about the CPU the VCPU parked on.
struct XstateProbeContext {
  VcpuDispatcher* vcpu;
  ktl::atomic<bool> armed;
  ktl::atomic<bool> ran;
  ktl::atomic<uint64_t> observed_xcr0;
  ktl::atomic<uint32_t> observed_cpu;
};

int XstateProbeBody(void* arg) {
  auto* c = static_cast<XstateProbeContext*>(arg);
  while (!c->armed.load()) {
    Thread::Current::SleepRelative(ZX_MSEC(1));
  }
  // Let the VCPU thread reach its HLT and block. Sleeping here is also what
  // makes this thread a *realistic* victim: a thread that has been context-
  // switched out at least once has had its extended-register buffer written by
  // XSAVES under the host's XCR0, so the buffer's XCOMP_BV names every host
  // component. Restoring that buffer under a narrower XCR0 is a #GP.
  Thread::Current::SleepRelative(ZX_MSEC(200));
  c->observed_cpu.store(arch_curr_cpu_num());
  c->observed_xcr0.store(x86_xgetbv(0));
  c->ran.store(true);
  // Release the VCPU from its HLT so Enter() returns rather than hanging.
  c->vcpu->Kick();
  return 0;
}

#endif  // __x86_64__

// Guest state must not outlive the VCPU's ownership of the CPU.
//
// Vcpu::Enter() installs the guest's XCR0 and the guest's extended-register file
// once, before the first VM entry, and swaps them back only in the fit::defer at
// the very end. In between, several exit handlers deliberately re-enable
// blocking and preemption -- AutoVmcs::Invalidate(), reached from handle_hlt via
// InterruptTracker::Wait, but also from handle_ept_violation, handle_vmcall,
// handle_kvm_wrmsr, handle_external_interrupt and Trap::Queue -- and the
// AutoVmcs destructor does the same at the end of every loop iteration. So the
// VCPU thread can be descheduled with the *guest's* XCR0 still in the physical
// register and the guest's FPU state still in the register file.
//
// The scheduler then runs x86_extended_register_context_switch(), which XSAVEs
// the outgoing thread's buffer and XRSTORs the incoming thread's -- both under
// whatever XCR0 is live. Two things follow, and this test is about the first:
//
//   * Any thread whose saved buffer was written under the host's XCR0 carries an
//     XCOMP_BV (compacted form, XRSTORS) or XSTATE_BV (standard form, XRSTOR)
//     naming components the guest's XCR0 does not have. Restoring it is a #GP on
//     a kernel instruction -- a host panic that any VMM can provoke with one
//     legal restore (`xcr0 = 1` is accepted by ValidateGuestXcr0, as it must be)
//     plus a guest that executes HLT.
//   * The VCPU thread's own extended-register buffer is overwritten with the
//     guest's FPU state.
//
// The test drives VcpuDispatcher, the object a zx_vcpu_* handle resolves to. It
// narrows the guest's XCR0 to x87 only through the whole-state restore topic,
// runs a guest that halts, and has a second thread pinned to the same CPU read
// the physical XCR0 while the VCPU is parked. Before the fix that read is never
// reached: switching to the probe thread faults the kernel.
bool vcpu_blocking_exit_does_not_leak_guest_xstate() {
  BEGIN_TEST;

#ifdef __x86_64__
  if (!x86_xsave_supported()) {
    printf("XSAVE not supported here; XCR0 does not exist. Skipping.\n");
    return true;
  }

  fbl::RefPtr<VmObjectPaged> ram;
  ASSERT_EQ(ZX_OK, VmObjectPaged::Create(PMM_ALLOC_FLAG_ANY, 0u, kGuestRamSize, &ram), "ram\n");
  ASSERT_EQ(ZX_OK, WriteIdentityTables(ram), "tables\n");
  // mov al,0x42; out 0x10,al; hlt
  //
  // The OUT is the handshake: when it returns, the guest's very next instruction
  // is the HLT, so the following Enter() blocks essentially immediately.
  const uint8_t code[] = {0xB0, kSentinel, 0xE6, 0x10, 0xF4};
  ASSERT_EQ(ZX_OK, ram->Write(code, kCodeGpa, sizeof(code)), "code\n");
  ASSERT_EQ(ZX_OK, ram->CommitRange(0, kGuestRamSize), "commit\n");

  auto lg = CreateLiveGuestDispatcher(ram, kCodeGpa);
  if (lg.is_error() && lg.status_value() == ZX_ERR_NOT_SUPPORTED) {
    printf("VMX not supported here; skipping guest-xstate leak test.\n");
    return true;
  }
  ASSERT_EQ(ZX_OK, lg.status_value(), "create live guest (dispatchers)\n");
  VcpuDispatcher* vcpu = lg->vcpu.get();

  // Pin this thread, and the probe, to one logical CPU. XCR0 is per-CPU, so an
  // unpinned probe could read a CPU the guest never ran on and pass vacuously.
  const cpu_num_t cpu = arch_curr_cpu_num();
  const cpu_mask_t saved_affinity = Thread::Current::Get()->SetCpuAffinity(cpu_num_to_mask(cpu));
  auto restore_affinity =
      fit::defer([saved_affinity] { Thread::Current::Get()->SetCpuAffinity(saved_affinity); });

  // The host's XCR0, read on the pinned CPU. This is what the CPU must be left
  // holding whenever the VCPU thread is not running.
  const uint64_t host_xcr0 = x86_xgetbv(0);

  // Phase 1: run to the OUT. The guest is now parked one instruction before HLT.
  zx_port_packet_t p = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(p), "baseline enter\n");
  ASSERT_EQ(static_cast<uint8_t>(ZX_PKT_TYPE_GUEST_IO), static_cast<uint8_t>(p.type),
            "baseline io\n");
  ASSERT_EQ(static_cast<uint32_t>(kSentinel), static_cast<uint32_t>(p.guest_io.data[0]),
            "baseline sentinel\n");

  // Narrow the guest's XCR0 to x87 only, through the public restore ABI.
  //
  // x87-only is the strongest choice available and it is deliberately legal:
  // ValidateGuestXcr0 accepts it (bit 0 set, no dependency violated, and it can
  // only shrink the XSAVE area), so no amount of validation on the restore path
  // can refuse it. Every other thread in the system has at least SSE state, so
  // both the XRSTORS rule (XCOMP_BV outside XCR0) and the XRSTOR rule (XSTATE_BV
  // outside XCR0) are violated by every victim buffer, on any host.
  const size_t len = SerializedVcpuStateSize();
  fbl::AllocChecker ac;
  ktl::unique_ptr<uint8_t[]> buf(new (&ac) uint8_t[len]);
  ASSERT_TRUE(ac.check(), "alloc serialized state\n");
  ktl::unique_ptr<VcpuArchState> state(new (&ac) VcpuArchState{});
  ASSERT_TRUE(ac.check(), "alloc arch state\n");
  size_t actual = 0;
  ASSERT_EQ(ZX_OK, vcpu->ReadStateFull(buf.get(), len, &actual), "ReadStateFull\n");
  ASSERT_EQ(ZX_OK, DeserializeVcpuState(*state, buf.get(), actual).status_value(), "deserialize\n");

  constexpr uint64_t kNarrowXcr0 = X86_XSAVE_STATE_BIT_X87;
  ASSERT_TRUE(host_xcr0 != kNarrowXcr0,
              "this host's XCR0 is x87-only, so it cannot be narrowed; the leak is real but "
              "unobservable here\n");
  state->xcr0 = kNarrowXcr0;
  // The image must be legal for the XCR0 it will be restored under, or the
  // restore is (correctly) refused by ValidateGuestXsaveImage before it can
  // prove anything about blocking.
  x86_extended_register_init_state_from_bv(state->xsave, kNarrowXcr0);
  ASSERT_EQ(ZX_OK, SerializeVcpuState(*state, buf.get(), len).status_value(), "serialize\n");
  ASSERT_EQ(ZX_OK, vcpu->WriteStateFull(buf.get(), len),
            "an x87-only XCR0 is legal and must be accepted\n");

  // Phase 2: start the probe, then enter and let the guest halt.
  XstateProbeContext ctx = {};
  ctx.vcpu = vcpu;
  Thread* probe = Thread::Create("hv-xstate-probe", XstateProbeBody, &ctx, DEFAULT_PRIORITY);
  ASSERT_TRUE(probe != nullptr, "create probe thread\n");
  probe->SetCpuAffinity(cpu_num_to_mask(cpu));
  probe->Resume();

  ctx.armed.store(true);

  // Plant a distinctive x87 control word in *this* thread's live FPU state
  // before the blocking entry.
  //
  // This is the second half of the hole, and it is what stops a fix that
  // restores only the XCR0 from passing this test. The guest's XSAVE image was
  // just reset to the architectural initial state, whose control word is
  // 0x037f, and x87 is the one component an x87-only XCR0 does select -- so
  // while the guest runs, the physical control word is the guest's. If the
  // guest's register file is still live when this thread is descheduled, the
  // scheduler XSAVEs *it* into this thread's buffer, and the value below is
  // gone for good.
  //
  // 0x0f7f is 0x037f with the rounding-control field set to "toward zero": a
  // legal control word that no initial state produces. Kernel threads have
  // their extended registers context-switched like any other, so writing one
  // here is safe.
  constexpr uint16_t kHostFcw = 0x0f7f;
  constexpr uint16_t kInitialFcw = 0x037f;
  uint16_t fcw = kHostFcw;
  __asm__ volatile("fldcw %0" ::"m"(fcw));

  zx_port_packet_t halted = {};
  const zx_status_t enter_status = vcpu->Enter(halted);

  uint16_t observed_fcw = 0;
  __asm__ volatile("fnstcw %0" : "=m"(observed_fcw));
  // Put the ordinary control word back before anything else in this thread runs.
  fcw = kInitialFcw;
  __asm__ volatile("fldcw %0" ::"m"(fcw));

  int retcode = 0;
  ASSERT_EQ(ZX_OK, probe->Join(&retcode, ZX_TIME_INFINITE), "join probe thread\n");

  ASSERT_TRUE(ctx.ran.load(), "the probe thread must have run\n");
  ASSERT_EQ(cpu, static_cast<cpu_num_t>(ctx.observed_cpu.load()),
            "the probe must have run on the VCPU's CPU\n");
  // ZX_ERR_INTERNAL_INTR_RETRY is the Kick-while-blocked path (the tracker's
  // wait was cancelled). ZX_ERR_CANCELED would mean the kick was seen at the top
  // of the entry loop instead, i.e. the VCPU never actually blocked -- which
  // would make the XCR0 reading below meaningless.
  ASSERT_EQ(ZX_ERR_INTERNAL_INTR_RETRY, enter_status,
            "the VCPU must have been kicked out of a real block, not before entry\n");

  EXPECT_EQ(host_xcr0, ctx.observed_xcr0.load(),
            "a descheduled VCPU must leave the HOST's XCR0 in the physical register; the guest's "
            "was still live, which is a #GP waiting for the next thread whose XSAVE buffer names a "
            "component the guest's XCR0 does not\n");

  EXPECT_EQ(kHostFcw, observed_fcw,
            "a descheduled VCPU must leave the HOST's extended registers in the CPU too, not only "
            "the host's XCR0; reading back the guest's initial control word (0x037f) means the "
            "scheduler saved the guest's FPU state into this thread's own buffer\n");

  // The guest's XCR0 must nevertheless survive the block: restoring the host's
  // around a blocking point is only correct if the guest's comes back.
  ASSERT_EQ(ZX_OK, vcpu->ReadStateFull(buf.get(), len, &actual), "ReadStateFull after\n");
  ktl::unique_ptr<VcpuArchState> after(new (&ac) VcpuArchState{});
  ASSERT_TRUE(ac.check(), "alloc post state\n");
  ASSERT_EQ(ZX_OK, DeserializeVcpuState(*after, buf.get(), actual).status_value(),
            "deserialize after\n");
  EXPECT_EQ(kNarrowXcr0, after->xcr0,
            "the guest's XCR0 must be preserved across a blocking exit\n");

  // A kick latches. It cancelled the tracker's wait (which is why the entry
  // above returned ZX_ERR_INTERNAL_INTR_RETRY), and `kicked_` is still set, so
  // the next entry reports ZX_ERR_CANCELED before entering the guest. Consume
  // that here, so the positive control below is a real entry.
  zx_port_packet_t drained = {};
  ASSERT_EQ(ZX_ERR_CANCELED, vcpu->Enter(drained), "the latched kick is consumed once\n");

  // The machine is still alive, and the VCPU still runs: put it back at the top
  // of the code with its original XCR0 and drive it to the I/O exit again.
  state->xcr0 = after->xcr0;
  state->rip = kCodeGpa;
  ASSERT_EQ(ZX_OK, SerializeVcpuState(*state, buf.get(), len).status_value(), "re-serialize\n");
  ASSERT_EQ(ZX_OK, vcpu->WriteStateFull(buf.get(), len), "restore for the positive control\n");
  zx_port_packet_t again = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(again), "enter after the blocking exit\n");
  ASSERT_EQ(static_cast<uint8_t>(ZX_PKT_TYPE_GUEST_IO), static_cast<uint8_t>(again.type),
            "io after\n");
  EXPECT_EQ(static_cast<uint32_t>(kSentinel), static_cast<uint32_t>(again.guest_io.data[0]),
            "the guest must still run after the blocking exit\n");

  printf("blocking-exit xstate OK: guest XCR0 narrowed to %#lx through the restore ABI; while the "
         "VCPU was parked in HLT on CPU %u a second thread read the physical XCR0 as %#lx (host "
         "%#lx); this thread's x87 control word survived the block as %#x (guest's initial state "
         "is %#x); and the guest's XCR0 came back for the next entry\n",
         kNarrowXcr0, cpu, ctx.observed_xcr0.load(), host_xcr0, observed_fcw, kInitialFcw);
#else
  printf("Not x86_64; skipping.\n");
#endif  // __x86_64__

  END_TEST;
}

// The guest's CR8 is its own, and lives in a page this VCPU owns.
//
// This VMCS sets the "use TPR shadow" VM-execution control and clears CR8-load
// and CR8-store exiting, which means the processor services a guest's `MOV
// to/from CR8` entirely on its own, against VTPR at offset 0x80 of the
// virtual-APIC page. That page's address (VMCS field 0x2012) was never
// programmed. An unwritten VMCS field is architecturally *undefined*; in
// practice the VMCS region is allocated zero-filled and it read back as 0,
// which VM entry accepts (its only checks are 4-KiB alignment and the
// physical-address width). So every VCPU on the machine used host-physical page
// 0 as its virtual-APIC page: `MOV to CR8` wrote host memory no one owns, and
// two VCPUs shared one task-priority register.
//
// Three things are asserted, and the first alone is not enough:
//
//  1. the guest reads back through CR8 what it wrote. This is the obvious test
//     and it PASSES WITHOUT THE FIX -- host-physical page 0 is memory like any
//     other, so the round trip works while writing somewhere it must not. It is
//     kept because it is the property a guest depends on, but it discriminates
//     nothing on its own;
//  2. host-physical page 0 is *not* modified by the guest's write. This is the
//     host-safety claim, stated directly;
//  3. a second VCPU, running while the first is still alive, reads 0 from CR8
//     rather than the first VCPU's value -- and the first VCPU's task priority
//     is unchanged afterwards. This separates "a page was programmed" from "a
//     page *per VCPU* was programmed", and it is what the two cheap wrong
//     fixes fail: one shared page fails the reader's assertion, and one shared
//     page re-zeroed at each `Vcpu::Create` fails the re-check of the first
//     VCPU's priority.
//
// A VCPU binds one per thread (`Vcpu::Create` refuses a second on a thread that
// already owns one), so the second runs on a thread of its own. It is a second
// *guest's* BSP rather than an AP of the first, because an AP starts in real
// mode and CR8 exists only in 64-bit mode.
struct Cr8ReaderContext {
  Guest* guest;
  uint64_t entry;
  zx_status_t create_status;
  zx_status_t enter_status;
  zx_paddr_t virtual_apic;
  zx_port_packet_t packet;
};

bool vcpu_cr8_is_per_vcpu_state() {
  BEGIN_TEST;

#ifdef __x86_64__
  constexpr uint8_t kTaskPriority = 0x0B;

  // 48 C7 C0 0B 00 00 00  mov rax, 0x0B
  // 44 0F 22 C0           mov cr8, rax
  // 48 31 C0              xor rax, rax    ; so the read below cannot pass on a stale rax
  // 44 0F 20 C0           mov rax, cr8
  // E6 10                 out 0x10, al
  // F4                    hlt
  const uint8_t writer[] = {0x48, 0xC7, 0xC0, kTaskPriority, 0x00, 0x00, 0x00, 0x44, 0x0F,
                            0x22, 0xC0, 0x48, 0x31, 0xC0, 0x44, 0x0F, 0x20, 0xC0, 0xE6,
                            0x10, 0xF4};
  // 44 0F 20 C0  mov rax, cr8
  // 48 31 C9 ... (not needed; rax is fully written by the read)
  // E6 10        out 0x10, al
  // F4           hlt
  const uint8_t reader[] = {0x44, 0x0F, 0x20, 0xC0, 0xE6, 0x10, 0xF4};

  // Physical page 0's VTPR slot, read through the physmap. Nothing in the
  // kernel owns or writes this location; before the virtual-APIC page existed,
  // the guest's `MOV to CR8` below did.
  volatile uint32_t* const host_page0_vtpr = reinterpret_cast<volatile uint32_t*>(
      reinterpret_cast<uintptr_t>(paddr_to_physmap(0)) + 0x80);
  const uint32_t host_page0_before = *host_page0_vtpr;

  fbl::RefPtr<VmObjectPaged> ram;
  ASSERT_EQ(ZX_OK, VmObjectPaged::Create(PMM_ALLOC_FLAG_ANY, 0u, kGuestRamSize, &ram), "ram\n");
  ASSERT_EQ(ZX_OK, WriteIdentityTables(ram), "tables\n");
  ASSERT_EQ(ZX_OK, ram->Write(writer, kCodeGpa, sizeof(writer)), "code\n");
  ASSERT_EQ(ZX_OK, ram->CommitRange(0, kGuestRamSize), "commit\n");

  auto lg = CreateLiveGuest(ram, kCodeGpa);
  if (lg.is_error() && lg.status_value() == ZX_ERR_NOT_SUPPORTED) {
    printf("VMX not supported here; skipping CR8 virtual-APIC-page test.\n");
    return true;
  }
  ASSERT_EQ(ZX_OK, lg.status_value(), "create live guest\n");
  Vcpu* vcpu = lg->vcpu.get();

  const zx_paddr_t first_apic_page = vcpu->VirtualApicAddress();
  EXPECT_NE(0u, first_apic_page,
            "VIRTUAL_APIC_ADDRESS must name a page this VCPU owns; 0 is host-physical page 0\n");
  EXPECT_EQ(0u, first_apic_page & 0xfffu, "the virtual-APIC page must be 4 KiB aligned\n");

  zx_port_packet_t p = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(p).status_value(), "enter writer\n");
  ASSERT_EQ(static_cast<uint8_t>(ZX_PKT_TYPE_GUEST_IO), static_cast<uint8_t>(p.type), "io\n");
  // (1) The guest observes its own write. True before the fix as well.
  EXPECT_EQ(static_cast<uint32_t>(kTaskPriority), static_cast<uint32_t>(p.guest_io.data[0]),
            "the guest must read back through CR8 the value it wrote\n");
  // The host can see the guest's task priority, which is what the interrupt gate
  // reads and, on Windows, is the guest's IRQL. `MOV to CR8` writes bits 7:4 of
  // VTPR and clears bits 3:0.
  EXPECT_EQ(static_cast<uint32_t>(kTaskPriority) << 4, vcpu->TaskPriority(),
            "the VCPU's VTPR must hold what the guest put in CR8\n");

  // (2) Host safety: the guest's CR8 write went to its own page, not page 0.
  EXPECT_EQ(host_page0_before, *host_page0_vtpr,
            "a guest `mov cr8` must not write host-physical page 0\n");

  // (3) A second VCPU, alive at the same time as the first, has its own CR8.
  fbl::RefPtr<VmObjectPaged> ram2;
  ASSERT_EQ(ZX_OK, VmObjectPaged::Create(PMM_ALLOC_FLAG_ANY, 0u, kGuestRamSize, &ram2), "ram2\n");
  ASSERT_EQ(ZX_OK, WriteIdentityTables(ram2), "tables2\n");
  ASSERT_EQ(ZX_OK, ram2->Write(reader, kCodeGpa, sizeof(reader)), "code2\n");
  ASSERT_EQ(ZX_OK, ram2->CommitRange(0, kGuestRamSize), "commit2\n");

  auto guest2_result = Guest::Create();
  ASSERT_EQ(ZX_OK, guest2_result.status_value(), "Guest::Create #2\n");
  ktl::unique_ptr<Guest> guest2 = ktl::move(guest2_result.value());
  auto mapping2 = guest2->RootVmar()->CreateVmMapping(0, kGuestRamSize, 0, VMAR_FLAG_SPECIFIC, ram2,
                                                      0, kMmuFlags, "guest-ram-2");
  ASSERT_EQ(ZX_OK, mapping2.status_value(), "map #2\n");
  auto trap2 = guest2->SetTrap(ZX_GUEST_TRAP_IO, 0x10, 1, nullptr, 0x10);
  ASSERT_EQ(ZX_OK, trap2.status_value(), "trap #2\n");

  // The VCPU is created and entered on its own thread: this thread already owns
  // one. The first VCPU is never destroyed, so its virtual-APIC page cannot have
  // been recycled into the second's.
  Cr8ReaderContext ctx = {guest2.get(), kCodeGpa, ZX_ERR_INTERNAL, ZX_ERR_INTERNAL, 0, {}};
  auto reader_body = [](void* arg) -> int {
    auto* c = reinterpret_cast<Cr8ReaderContext*>(arg);
    auto r = Vcpu::Create(*c->guest, c->entry);
    c->create_status = r.status_value();
    if (r.is_error()) {
      return 0;
    }
    ktl::unique_ptr<Vcpu> v = ktl::move(r.value());
    c->virtual_apic = v->VirtualApicAddress();
    c->enter_status = v->Enter(c->packet).status_value();
    return 0;
  };
  Thread* reader_thread = Thread::Create("hv-cr8-reader", reader_body, &ctx, DEFAULT_PRIORITY);
  ASSERT_TRUE(reader_thread != nullptr, "create reader thread\n");
  reader_thread->Resume();
  int retcode = 0;
  ASSERT_EQ(ZX_OK, reader_thread->Join(&retcode, ZX_TIME_INFINITE), "join reader thread\n");

  ASSERT_EQ(ZX_OK, ctx.create_status, "second Vcpu::Create on its own thread\n");
  ASSERT_EQ(ZX_OK, ctx.enter_status, "second Enter\n");
  ASSERT_EQ(static_cast<uint8_t>(ZX_PKT_TYPE_GUEST_IO), static_cast<uint8_t>(ctx.packet.type),
            "io2\n");
  EXPECT_EQ(0u, static_cast<uint32_t>(ctx.packet.guest_io.data[0]),
            "a second VCPU must read 0 from CR8, not the first VCPU's task priority\n");
  EXPECT_NE(first_apic_page, ctx.virtual_apic,
            "two live VCPUs must not share one virtual-APIC page\n");
  // And the second VCPU's existence must not have disturbed the first's -- which
  // is what a single shared page re-zeroed at each Vcpu::Create would do.
  EXPECT_EQ(static_cast<uint32_t>(kTaskPriority) << 4, vcpu->TaskPriority(),
            "the first VCPU's task priority must survive a second VCPU being created\n");

  printf("CR8 virtual-APIC OK: guest wrote %#x and read it back; VTPR %#x on its own page %#lx; "
         "host-physical page 0 unchanged (%#x); a concurrent second VCPU on page %#lx read %#x "
         "and left the first's VTPR at %#x\n",
         kTaskPriority, static_cast<uint32_t>(kTaskPriority) << 4, first_apic_page,
         host_page0_before, ctx.virtual_apic, static_cast<uint32_t>(ctx.packet.guest_io.data[0]),
         vcpu->TaskPriority());
#else
  printf("Not x86_64; skipping.\n");
#endif  // __x86_64__

  END_TEST;
}

// The guest's CR8 actually gates interrupt delivery, and lowering it releases
// exactly the interrupt that was waiting.
//
// Injecting through the VM-entry interruption-information field bypasses the
// APIC's priority arbitration entirely -- VM entry performs no priority check --
// so a hypervisor that does not consult the guest's task priority delivers
// vectors the guest has masked. On x64 Windows CR8 *is* IRQL, so that means an
// ISR running inside a region whose whole purpose was to exclude it.
//
// The guest raises CR8 to priority class 8, exits, and the host injects vector
// 0x50 (class 5, below it). The discriminating assertion is the *port of the
// next exit*: it must be the guest's own `out 0x11`, reached by running past the
// injection, not the interrupt handler's `out 0x30`. Then the guest lowers CR8
// to 0 and the same vector must arrive -- which is what separates holding the
// interrupt from dropping it. An implementation that ignores TPR fails the
// first half; one that discards a blocked vector fails the second.
//
// Run twice, over the two ways a vector can be injected, because they are two
// different code paths and only one of them goes through the interrupt tracker:
//
//   * `Vcpu::Interrupt` deposits into the local-APIC interrupt tracker, which
//     `local_apic_maybe_interrupt` arbitrates;
//   * `Vcpu::WritePendingEvent` (the ZX_VCPU_STATE_PENDING_EVENT topic) stages
//     the VM-entry interruption-information field directly, bypassing the
//     tracker -- and so needs the same gate applied separately.
bool Cr8GatingScenario(bool via_pending_event) {
  BEGIN_TEST;

#ifdef __x86_64__
  auto guest_result = Guest::Create();
  if (guest_result.is_error() && guest_result.status_value() == ZX_ERR_NOT_SUPPORTED) {
    printf("VMX not supported here; skipping CR8 interrupt-gating test.\n");
    return true;
  }
  ASSERT_EQ(ZX_OK, guest_result.status_value(), "Guest::Create failed\n");
  ktl::unique_ptr<Guest> guest = ktl::move(guest_result.value());

  constexpr uint64_t kGdtGpa = 0x6000;
  constexpr uint64_t kIdtGpa = 0x6800;
  constexpr uint64_t kHandlerGpa = 0x8000;
  constexpr uint64_t kStackTop = 0x9000;
  // Vector 0x50 is priority class 5; the guest raises its task priority to
  // class 8, which is above it, so a correct APIC holds this vector back.
  constexpr uint32_t kVector = 0x50;
  constexpr uint8_t kRaisedClass = 0x08;
  // The guest steps down in two stages, 8 -> 5 -> 4, and both stages are
  // asserted on.
  //
  // Class 5 is the vector's *own* class, and the architecture is specific about
  // it: Volume 3, Section 11.8.4 delivers an interrupt only when its priority
  // class is *greater* than the processor's, so at class 5 vector 0x50 must
  // still be held. That is the equal-class case, and it is the only thing in
  // this test that discriminates `<` from `<=` in the comparison the whole
  // priority model is built on. Without it the test was satisfied by either.
  //
  // Class 4 is one step below, the least the guest can lower to and still be
  // owed the interrupt -- and it is what makes the TPR-below-threshold assertion
  // discriminating. Lowering all the way to 0 is satisfied by a threshold armed
  // at *any* class from 1 up: a hypervisor that ignored the vector entirely and
  // hard-coded a threshold of 1 would still exit when VTPR reached 0, and would
  // still pass. With the guest stopping at 4, only a threshold armed at 5 --
  // this vector's own priority class, which is the thing being claimed --
  // produces an exit, and the 8 -> 5 step additionally proves it was not armed
  // any *higher* than 5 either, because that step must produce no exit at all.
  constexpr uint8_t kEqualClass = 0x05;
  constexpr uint8_t kLoweredClass = 0x04;

  fbl::RefPtr<VmObjectPaged> ram;
  ASSERT_EQ(ZX_OK, VmObjectPaged::Create(PMM_ALLOC_FLAG_ANY, 0u, kGuestRamSize, &ram), "ram\n");
  ASSERT_EQ(ZX_OK, WriteIdentityTables(ram), "tables\n");

  //  FB                    sti
  //  90                    nop                 ; retire the one-instruction STI shadow
  //  48 C7 C0 08 00 00 00  mov rax, 8
  //  44 0F 22 C0           mov cr8, rax        ; task priority class 8
  //  B0 01                 mov al, 1
  //  E6 10                 out 0x10, al        ; exit #1; the host injects here
  //  90 x8                 nop                 ; a window a wrongly-delivered vector lands in
  //  B0 AA                 mov al, 0xAA
  //  E6 11                 out 0x11, al        ; exit #2 -- must be reached
  //  48 C7 C0 05 00 00 00  mov rax, 5          ; the vector's OWN class
  //  44 0F 22 C0           mov cr8, rax        ; equal, not above: still held
  //  90 x8                 nop                 ; another landing window
  //  B0 BB                 mov al, 0xBB
  //  E6 12                 out 0x12, al        ; exit #3 -- must be reached too
  //  90 x8                 nop
  //  B0 CC                 mov al, 0xCC
  //  E6 15                 out 0x15, al        ; exit #4 -- the ENTRY before it is
  //                                            ; the one made with VTPR already at
  //                                            ; class 5, so this is where the
  //                                            ; equal-class comparison is taken
  //  48 C7 C0 04 00 00 00  mov rax, 4          ; NOT 0: one class below the vector's
  //  44 0F 22 C0           mov cr8, rax        ; lower it; the held vector must now arrive
  //  EB FE                 jmp $               ; spin until it does
  const uint8_t code[] = {
      0xFB, 0x90, 0x48, 0xC7, 0xC0, kRaisedClass, 0x00, 0x00, 0x00, 0x44, 0x0F, 0x22, 0xC0,
      0xB0, 0x01, 0xE6, 0x10, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
      0xB0, 0xAA, 0xE6, 0x11, 0x48, 0xC7, 0xC0, kEqualClass, 0x00, 0x00, 0x00,
      0x44, 0x0F, 0x22, 0xC0, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
      0xB0, 0xBB, 0xE6, 0x12, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
      0xB0, 0xCC, 0xE6, 0x15, 0x48, 0xC7, 0xC0, kLoweredClass, 0x00, 0x00, 0x00,
      0x44, 0x0F, 0x22, 0xC0, 0xEB, 0xFE};
  ASSERT_EQ(ZX_OK, ram->Write(code, kCodeGpa, sizeof(code)), "code\n");

  // GDT[1] = flat 64-bit code segment (selector 0x08).
  const uint8_t gdt_code[8] = {0xFF, 0xFF, 0x00, 0x00, 0x00, 0x9B, 0xAF, 0x00};
  ASSERT_EQ(ZX_OK, ram->Write(gdt_code, kGdtGpa + 8, sizeof(gdt_code)), "GDT code desc\n");

  // IDT gate for kVector: 64-bit interrupt gate, selector 0x08, offset=handler.
  const uint8_t idt_gate[16] = {
      static_cast<uint8_t>(kHandlerGpa & 0xFF), static_cast<uint8_t>((kHandlerGpa >> 8) & 0xFF),
      0x08, 0x00, 0x00, 0x8E, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
  ASSERT_EQ(ZX_OK, ram->Write(idt_gate, kIdtGpa + kVector * 16, sizeof(idt_gate)), "IDT gate\n");

  // Handler: mov al,0x66; out 0x30,al; hlt.
  const uint8_t handler[] = {0xB0, 0x66, 0xE6, 0x30, 0xF4};
  ASSERT_EQ(ZX_OK, ram->Write(handler, kHandlerGpa, sizeof(handler)), "handler\n");
  ASSERT_EQ(ZX_OK, ram->CommitRange(0, kGuestRamSize), "commit\n");

  auto mapping = guest->RootVmar()->CreateVmMapping(0, kGuestRamSize, 0, VMAR_FLAG_SPECIFIC, ram, 0,
                                                    kMmuFlags, "guest-ram");
  ASSERT_EQ(ZX_OK, mapping.status_value(), "map\n");
  for (uint16_t port :
       {uint16_t{0x10}, uint16_t{0x11}, uint16_t{0x12}, uint16_t{0x15}, uint16_t{0x30}}) {
    auto t = guest->SetTrap(ZX_GUEST_TRAP_IO, port, 1, nullptr, port);
    ASSERT_EQ(ZX_OK, t.status_value(), "install I/O trap\n");
  }

  auto vcpu_result = Vcpu::Create(*guest, kCodeGpa);
  ASSERT_EQ(ZX_OK, vcpu_result.status_value(), "Vcpu::Create\n");
  ktl::unique_ptr<Vcpu> vcpu = ktl::move(vcpu_result.value());

  VcpuArchState s = {};
  ASSERT_EQ(ZX_OK, vcpu->SaveArchState(s).status_value(), "SaveArchState\n");
  s.gdtr_base = kGdtGpa;
  s.gdtr_limit = 0x0F;
  s.idtr_base = kIdtGpa;
  s.idtr_limit = 0xFFF;
  s.regs.rsp = kStackTop;
  ASSERT_EQ(ZX_OK, vcpu->RestoreArchState(s).status_value(), "load GDTR/IDTR/RSP\n");

  // Exit #1: the guest has enabled interrupts and raised its task priority.
  zx_port_packet_t p = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(p).status_value(), "enter #1\n");
  ASSERT_EQ(0x10u, p.guest_io.port, "expected the pre-injection exit on 0x10\n");
  ASSERT_EQ(static_cast<uint32_t>(kRaisedClass) << 4, vcpu->TaskPriority(),
            "the guest's `mov cr8` must be visible to the host as VTPR\n");

  // Inject a vector below the guest's task priority, by whichever route.
  if (via_pending_event) {
    const zx_vcpu_pending_event_t ev =
        MakePendingEvent(ZX_VCPU_EVENT_EXTERNAL_INTERRUPT, kVector);
    ASSERT_EQ(ZX_OK, vcpu->WritePendingEvent(ev).status_value(), "queue pending event\n");
  } else {
    ASSERT_EQ(ZX_OK, vcpu->Interrupt(kVector).status_value(), "inject vector\n");
  }

  // Exit #2 is the discriminator. RFLAGS.IF is set and the guest is spinning
  // through nops, so nothing but its own task priority is holding this vector
  // back: if the port here is 0x30, the handler ran and CR8 did not gate it.
  zx_port_packet_t blocked = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(blocked).status_value(), "enter #2\n");
  ASSERT_EQ(static_cast<uint8_t>(ZX_PKT_TYPE_GUEST_IO), static_cast<uint8_t>(blocked.type), "io\n");
  EXPECT_EQ(0x11u, blocked.guest_io.port,
            "the guest raised CR8 above this vector's priority class, so it must have run past "
            "the injection to its own out 0x11 -- port 0x30 means the handler ran anyway\n");
  EXPECT_EQ(0xAAu, static_cast<uint32_t>(blocked.guest_io.data[0]), "exit #2 value\n");
  // Held, not dropped -- checked where that route actually parks it.
  auto still_held = [&](const char* when) {
    if (via_pending_event) {
      zx_vcpu_pending_event_t still = {};
      if (vcpu->ReadPendingEvent(still).is_error()) {
        return false;
      }
      return still.type == static_cast<uint32_t>(ZX_VCPU_EVENT_EXTERNAL_INTERRUPT) &&
             still.vector == kVector;
    }
    (void)when;
    return vcpu->InterruptPending(kVector);
  };
  EXPECT_TRUE(still_held("above"),
              "a priority-blocked vector must stay queued, not be discarded\n");

  // Exit #3 is the equal-class discriminator, and it is the assertion this test
  // did not have.
  //
  // The guest has lowered CR8 from class 8 to class 5 -- the vector's own class.
  // Volume 3, Section 11.8.4 delivers only when the vector's class is *greater*
  // than the processor's, so 0x50 is still held, and the guest must reach its
  // own `out 0x12`. An implementation that wrote `<` where the architecture says
  // `<=` -- an off-by-one that nothing else here can see -- delivers the vector
  // at this step and reports port 0x30 instead.
  //
  // The TPR-below-threshold counter must NOT move across this step either, and
  // that is a second, independent claim: the processor exits when VTPR[7:4] falls
  // below the threshold, so a threshold armed at this vector's class 5 does not
  // fire on 8 -> 5, while one armed at anything above 5 -- for instance at the
  // guest's own task-priority class, which is a plausible wrong reading of what
  // to arm -- does.
  const uint64_t tpr_exits_before_equal = vcpu->TprBelowThresholdExits();
  zx_port_packet_t equal = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(equal).status_value(), "enter #3\n");
  ASSERT_EQ(static_cast<uint8_t>(ZX_PKT_TYPE_GUEST_IO), static_cast<uint8_t>(equal.type), "io\n");
  EXPECT_EQ(0x12u, equal.guest_io.port,
            "the guest lowered CR8 to this vector's OWN priority class, which is not ABOVE it, so "
            "the vector must still be held and the guest must reach its own out 0x12 -- port 0x30 "
            "means the comparison used `<` where the architecture says `<=`\n");
  EXPECT_EQ(0xBBu, static_cast<uint32_t>(equal.guest_io.data[0]), "exit #3 value\n");
  EXPECT_EQ(static_cast<uint32_t>(kEqualClass) << 4, vcpu->TaskPriority(),
            "the guest must actually be sitting at class 5 here, or this step proved nothing\n");
  EXPECT_EQ(tpr_exits_before_equal, vcpu->TprBelowThresholdExits(),
            "no TPR-below-threshold exit may occur on the 8 -> 5 step: a threshold armed at this "
            "vector's class 5 does not fire until VTPR goes BELOW 5, and one that fired here was "
            "armed too high\n");
  EXPECT_TRUE(still_held("equal"),
              "and the vector must still be queued after the equal-class step\n");

  // Exit #4 is where the equal-class comparison is actually *taken*.
  //
  // Exit #3 above proves the guest reached class 5 with the vector still queued,
  // but the entry that preceded it was made while VTPR still read class 8 -- the
  // guest lowers CR8 in the middle of that entry, and no exit follows, because a
  // threshold armed at 5 fires only below 5. So the comparison at class 5 has
  // not happened yet. This entry is the one that makes it: VTPR reads class 5
  // when `local_apic_maybe_interrupt` runs, the vector's class is 5, and the
  // guest must still run past to its own `out 0x15`.
  //
  // This is the assertion an implementation written with `<` instead of `<=`
  // fails, and it fails it directly -- it delivers here.
  zx_port_packet_t equal_entry = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(equal_entry).status_value(), "enter #4\n");
  ASSERT_EQ(static_cast<uint8_t>(ZX_PKT_TYPE_GUEST_IO), static_cast<uint8_t>(equal_entry.type),
            "io\n");
  EXPECT_EQ(0x15u, equal_entry.guest_io.port,
            "this entry was made with the guest ALREADY at the vector's own priority class, so "
            "the arbitration ran at class 5 against a class-5 vector and must have refused it; "
            "port 0x30 means the comparison admitted an equal class\n");
  EXPECT_EQ(0xCCu, static_cast<uint32_t>(equal_entry.guest_io.data[0]), "exit #4 value\n");
  EXPECT_EQ(static_cast<uint32_t>(kEqualClass) << 4, vcpu->TaskPriority(),
            "and the guest must still be at class 5 for that to be what was tested\n");
  EXPECT_TRUE(still_held("equal entry"), "the vector must still be queued\n");

  // The guest lowers CR8 to class 4 -- below this vector's class 5, above zero.
  // The vector must now be delivered, through a TPR-below-threshold exit the run
  // loop handles internally, so it arrives within this same Enter().
  //
  // That exit is asserted on directly, and it is not redundant with the delivery
  // assertions below. Nothing else in this test discriminates it: the guest's
  // last instruction is `jmp $`, so even a hypervisor that arms no threshold at
  // all gets the vector delivered on the next entry after any unrelated exit --
  // and a host timer tick supplies one within milliseconds. The delivery
  // assertions therefore pass either way. What separates "released because the
  // hypervisor was watching for the guest to lower CR8" from "released because
  // something else happened to exit" is that a TPR-below-threshold exit occurred
  // at all, which happens only if the threshold was armed for this vector's
  // priority class on the previous entry.
  //
  // And the guest stops at class 4 rather than 0, which is what makes "armed for
  // *this vector's* class" the claim rather than "armed at all". The processor
  // exits when bits 7:4 of VTPR fall below bits 3:0 of the threshold, so a
  // threshold of 5 exits on the 5 -> 4 transition and a constant threshold of 1,
  // 2, 3 or 4 does not. See kLoweredClass.
  const uint64_t tpr_exits_before = vcpu->TprBelowThresholdExits();
  zx_port_packet_t released = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(released).status_value(), "enter #5\n");
  ASSERT_EQ(static_cast<uint8_t>(ZX_PKT_TYPE_GUEST_IO), static_cast<uint8_t>(released.type), "io\n");
  EXPECT_EQ(0x30u, released.guest_io.port,
            "lowering CR8 to one class below the vector's must release the held vector into the "
            "guest's IDT handler\n");
  EXPECT_EQ(0x66u, static_cast<uint32_t>(released.guest_io.data[0]), "handler value\n");
  EXPECT_EQ(static_cast<uint32_t>(kLoweredClass) << 4, vcpu->TaskPriority(),
            "the guest lowered its task priority to class 4, not to 0 -- if this reads 0 the "
            "guest did not run the code this test is about\n");
  EXPECT_GT(vcpu->TprBelowThresholdExits(), tpr_exits_before,
            "the held vector must be released by a TPR-below-threshold exit -- i.e. the threshold "
            "was armed for THIS VECTOR'S priority class, since the guest only lowered CR8 to one "
            "class below it -- not by whatever unrelated exit happens next\n");

  // Delivered means in service. The vector went through the APIC's arbitration,
  // so the APIC has to know it is running: until the guest's EOI, the processor
  // priority is this vector's class regardless of what the task priority says --
  // which here is class 4, lower. Reading the same value out of TaskPriority()
  // and ProcessorPriority() would mean the ISR term was contributing nothing.
  EXPECT_TRUE(vcpu->InService(kVector),
              "a delivered vector must be in service until the guest EOIs it\n");
  EXPECT_EQ(kVector, vcpu->InServiceVector(), "and it must be the highest one in service\n");
  EXPECT_EQ(static_cast<uint32_t>(kVector) & 0xf0u, vcpu->ProcessorPriority(),
            "with a class-5 vector in service and the task priority at class 4, the PROCESSOR "
            "priority must be the in-service vector's class, not the task priority\n");
  EXPECT_NE(vcpu->TaskPriority(), vcpu->ProcessorPriority(),
            "the in-service term must be contributing something the task priority does not\n");

  printf("CR8 interrupt gating OK (%s): with CR8 class %#x the guest ran past injected vector %#x "
         "to its own out 0x11; at the vector's OWN class %#x it was still held and reached out "
         "0x12 with no threshold exit; lowering CR8 to class %#x raised %lu TPR-below-threshold "
         "exit(s) and delivered it to the guest IDT handler with VTPR still %#x, PPR %#x\n",
         via_pending_event ? "pending-event ABI" : "Vcpu::Interrupt", kRaisedClass, kVector,
         kEqualClass, kLoweredClass, vcpu->TprBelowThresholdExits() - tpr_exits_before,
         vcpu->TaskPriority(), vcpu->ProcessorPriority());
#else
  (void)via_pending_event;
  printf("Not x86_64; skipping.\n");
#endif  // __x86_64__

  END_TEST;
}

bool vcpu_cr8_gates_interrupt_delivery() {
  BEGIN_TEST;
  EXPECT_TRUE(Cr8GatingScenario(/*via_pending_event=*/false), "tracker-injected vector\n");
  END_TEST;
}

bool vcpu_cr8_gates_pending_event_delivery() {
  BEGIN_TEST;
  EXPECT_TRUE(Cr8GatingScenario(/*via_pending_event=*/true), "pending-event-injected vector\n");
  END_TEST;
}

// An interrupt that is running is *in service*, and an interrupt of its own
// priority class must wait for the EOI that ends it.
//
// This is the half of the priority model the task priority cannot supply, and
// the half that was entirely absent: there was no in-service register, so
// `EOI` -- which a guest writes at the end of every single interrupt it takes --
// was accepted and thrown away, and the processor priority could never be
// anything but the task priority. A guest running an ISR at IRQL 5 with CR8
// still at 0, which is the normal state inside a Windows interrupt service
// routine, could be re-entered by another class-5 interrupt on the next
// instruction.
//
// Three separate claims, and none of the three is provable from the others:
//
//  1. delivery puts the vector in service, and the *guest* can see that: it
//     reads its own PPR (x2APIC MSR 0x80a) and its own ISR word (0x812) from
//     inside the handler, through its own `rdmsr`, not through the host-side
//     accessor that the injection path wrote. Both registers used to be
//     unreadable -- PPR was not in the MSR enum at all and took a #GP, and the
//     ISR words read a hard 0;
//  2. a second vector of the same class is *held* while the first is in service.
//     The guest's task priority is 0 throughout, so nothing else in this
//     hypervisor could be holding it -- and `IsrBlocked()` counts the block by
//     the reason, so "held by the in-service interrupt" is distinguished from
//     "held by CR8" rather than inferred;
//  3. the guest's EOI is what releases it. The guest runs `wrmsr 0x80b` and the
//     held vector arrives before the guest's own next instruction retires.
//
// The negative marker is deliberate and separate at each step: the guest has an
// `out 0x11` it can only reach if the second vector was *not* delivered, and an
// `out 0x12` after the EOI that it can only reach if the vector was not
// delivered even then. A dropped interrupt and a wrongly-delivered one land on
// different ports, so neither can be mistaken for the mechanism working.
bool vcpu_apic_in_service_blocks_until_eoi() {
  BEGIN_TEST;

#ifdef __x86_64__
  auto guest_result = Guest::Create();
  if (guest_result.is_error() && guest_result.status_value() == ZX_ERR_NOT_SUPPORTED) {
    printf("VMX not supported here; skipping in-service/EOI test.\n");
    return true;
  }
  ASSERT_EQ(ZX_OK, guest_result.status_value(), "Guest::Create failed\n");
  ktl::unique_ptr<Guest> guest = ktl::move(guest_result.value());

  constexpr uint64_t kGdtGpa = 0x6000;
  constexpr uint64_t kIdtGpa = 0x6800;
  constexpr uint64_t kFirstHandlerGpa = 0x8000;
  constexpr uint64_t kNestHandlerGpa = 0x8080;
  constexpr uint64_t kSecondHandlerGpa = 0x8100;
  constexpr uint64_t kProbeGpa = 0x8180;
  constexpr uint64_t kStackTop = 0x9000;

  // Three vectors, chosen so that each of the three relations the arbitration
  // has to get right is exercised by a different pair:
  //   0x50 and 0x51 are the SAME class (5). Equal is not greater, so the second
  //     must wait for the first to be acknowledged. 0x51 is also the numerically
  //     *higher* vector, so "the higher number wins" -- which is what the
  //     interrupt tracker's reverse scan does on its own -- gives the wrong
  //     answer here, and only the in-service bit gives the right one.
  //   0x60 is a HIGHER class (6). It must pre-empt 0x50 while 0x50 is running,
  //     because that is what an interrupt priority *class* means; an
  //     implementation that simply refused every interrupt while any other was
  //     in service would block it.
  constexpr uint32_t kFirstVector = 0x50;
  constexpr uint32_t kSecondVector = 0x51;
  constexpr uint32_t kNestVector = 0x60;
  // 0x50 and 0x51 are bits 16 and 17 of word 2 (x2APIC ISR MSR 0x812, IRR 0x822);
  // 0x60 is bit 0 of word 3.
  constexpr uint32_t kIsrWordMsr = 0x812;
  constexpr uint32_t kIrrWordMsr = 0x822;
  constexpr uint32_t kExpectedIsrWord = 1u << (kFirstVector % 32);
  constexpr uint32_t kExpectedIrrWord = 1u << (kSecondVector % 32);
  constexpr uint32_t kPprMsr = 0x80a;
  constexpr uint32_t kEoiMsr = 0x80b;
  // Loaded into EAX and EDX before every `rdmsr` below. Without it these reads
  // are not assertions at all: the value each one is required to produce is
  // already sitting in EAX from the instruction before -- `mov al, 0x50`
  // immediately precedes the PPR read, and 0x50 is exactly what the PPR must be
  // -- so a handler that advanced RIP and touched no register would satisfy
  // them. Poisoning first means the reported value can only have come from the
  // hypervisor.
  constexpr uint32_t kPoison = 0xDEAD'BEEF;
  constexpr uint8_t kWidePort = 0x13;

  fbl::RefPtr<VmObjectPaged> ram;
  ASSERT_EQ(ZX_OK, VmObjectPaged::Create(PMM_ALLOC_FLAG_ANY, 0u, kGuestRamSize, &ram), "ram\n");
  ASSERT_EQ(ZX_OK, WriteIdentityTables(ram), "tables\n");

  uint8_t buf[256];
  size_t n = 0;
  auto emit = [&](std::initializer_list<uint8_t> bytes) {
    for (uint8_t b : bytes) {
      buf[n++] = b;
    }
  };
  auto emit32 = [&](uint32_t v) {
    emit({static_cast<uint8_t>(v), static_cast<uint8_t>(v >> 8), static_cast<uint8_t>(v >> 16),
          static_cast<uint8_t>(v >> 24)});
  };
  // mov al, value ; out port, al
  auto report_byte = [&](uint8_t value, uint8_t port) { emit({0xB0, value, 0xE6, port}); };
  // mov eax, poison ; mov edx, poison ; mov ecx, msr ; rdmsr ; out kWidePort, eax
  auto read_report = [&](uint32_t msr) {
    emit({0xB8});
    emit32(kPoison);
    emit({0xBA});
    emit32(kPoison);
    emit({0xB9});
    emit32(msr);
    emit({0x0F, 0x32, 0xE7, kWidePort});
  };
  // mov ecx, 0x80b ; xor eax, eax ; xor edx, edx ; wrmsr
  auto eoi = [&]() {
    emit({0xB9});
    emit32(kEoiMsr);
    emit({0x31, 0xC0, 0x31, 0xD2, 0x0F, 0x30});
  };
  // jmp rel32, from a body that starts at |base|.
  //
  // Deliberately not `iretq`: IRET reloads SS from the selector the processor
  // pushed, which for these guests is the null selector the hypervisor leaves in
  // GUEST_SS_SELECTOR, and the two-entry GDT has nothing to reload it from.
  auto jmp_to = [&](uint64_t base, uint64_t target) {
    const int32_t disp = static_cast<int32_t>(target) - static_cast<int32_t>(base + n + 5);
    emit({0xE9});
    emit32(static_cast<uint32_t>(disp));
  };

  // The guest body: say it is ready, then read its own IRR before anything has
  // been requested, then park. The host drives everything from there.
  n = 0;
  emit({0xFB, 0x90});  // sti ; nop -- retire the STI shadow
  report_byte(0xA1, 0x10);
  read_report(kIrrWordMsr);
  emit({0xEB, 0xFE});  // jmp $
  ASSERT_EQ(ZX_OK, ram->Write(buf, kCodeGpa, n), "code\n");

  // GDT[1] = flat 64-bit code segment (selector 0x08).
  const uint8_t gdt_code[8] = {0xFF, 0xFF, 0x00, 0x00, 0x00, 0x9B, 0xAF, 0x00};
  ASSERT_EQ(ZX_OK, ram->Write(gdt_code, kGdtGpa + 8, sizeof(gdt_code)), "GDT code desc\n");

  struct Gate {
    uint32_t vector;
    uint64_t handler;
  };
  const Gate gates[] = {{kFirstVector, kFirstHandlerGpa},
                        {kSecondVector, kSecondHandlerGpa},
                        {kNestVector, kNestHandlerGpa}};
  for (const Gate& g : gates) {
    uint8_t gate[16];
    WriteIdtGate(gate, g.handler);
    ASSERT_EQ(ZX_OK, ram->Write(gate, kIdtGpa + g.vector * 16, sizeof(gate)), "IDT gate\n");
  }

  // Handler for 0x50: report that it ran, read its own PPR and ISR word back
  // through its own `rdmsr`, then re-enable interrupts and resume at the probe.
  // It deliberately does NOT EOI -- it is the interrupt that stays in service
  // while everything else is tried against it.
  n = 0;
  report_byte(static_cast<uint8_t>(kFirstVector), 0x30);
  read_report(kPprMsr);
  read_report(kIsrWordMsr);
  emit({0xFB});
  jmp_to(kFirstHandlerGpa, kProbeGpa);
  ASSERT_LE(n, 128u, "first handler overruns its slot\n");
  ASSERT_EQ(ZX_OK, ram->Write(buf, kFirstHandlerGpa, n), "handler 0x50\n");

  // Handler for 0x60, the higher class. It runs *inside* 0x50's handler, so its
  // reads are taken with two interrupts in service at once: the PPR must be its
  // own class, and the ISR word must still show 0x50 underneath it. Then it
  // EOIs, which unwinds one level and puts the processor priority back to 0x50's
  // class rather than to zero.
  n = 0;
  report_byte(static_cast<uint8_t>(kNestVector), 0x30);
  read_report(kPprMsr);
  read_report(kIsrWordMsr);
  eoi();
  emit({0xFB});
  jmp_to(kNestHandlerGpa, kProbeGpa);
  ASSERT_LE(n, 128u, "nested handler overruns its slot\n");
  ASSERT_EQ(ZX_OK, ram->Write(buf, kNestHandlerGpa, n), "handler 0x60\n");

  // Handler for 0x51: reaching it at all is the whole assertion.
  n = 0;
  report_byte(static_cast<uint8_t>(kSecondVector), 0x30);
  emit({0xF4});
  ASSERT_EQ(ZX_OK, ram->Write(buf, kSecondHandlerGpa, n), "handler 0x51\n");

  // The probe, which every handler resumes into. Its two markers are negative:
  // `out 0x11` is reachable only if 0x51 was NOT delivered, and `out 0x12` only
  // if 0x51 was not delivered even after the EOI. A dropped interrupt and a
  // wrongly-delivered one therefore land on different ports.
  n = 0;
  report_byte(0xA2, 0x11);
  read_report(kIrrWordMsr);
  eoi();
  report_byte(0xA3, 0x12);
  emit({0xF4});
  ASSERT_EQ(ZX_OK, ram->Write(buf, kProbeGpa, n), "probe\n");
  ASSERT_EQ(ZX_OK, ram->CommitRange(0, kGuestRamSize), "commit\n");

  auto mapping = guest->RootVmar()->CreateVmMapping(0, kGuestRamSize, 0, VMAR_FLAG_SPECIFIC, ram, 0,
                                                    kMmuFlags, "guest-ram");
  ASSERT_EQ(ZX_OK, mapping.status_value(), "map\n");
  for (uint16_t port : {uint16_t{0x10}, uint16_t{0x11}, uint16_t{0x12}, uint16_t{0x30}}) {
    auto t = guest->SetTrap(ZX_GUEST_TRAP_IO, port, 1, nullptr, port);
    ASSERT_EQ(ZX_OK, t.status_value(), "install byte I/O trap\n");
  }
  // One wide port carries every register read, in order. A 4-byte I/O trap
  // reserves four consecutive ports, so a second one at 0x14 would overlap it.
  {
    auto t = guest->SetTrap(ZX_GUEST_TRAP_IO, kWidePort, 4, nullptr, kWidePort);
    ASSERT_EQ(ZX_OK, t.status_value(), "install wide I/O trap\n");
  }

  auto vcpu_result = Vcpu::Create(*guest, kCodeGpa);
  ASSERT_EQ(ZX_OK, vcpu_result.status_value(), "Vcpu::Create\n");
  ktl::unique_ptr<Vcpu> vcpu = ktl::move(vcpu_result.value());

  VcpuArchState s = {};
  ASSERT_EQ(ZX_OK, vcpu->SaveArchState(s).status_value(), "SaveArchState\n");
  s.gdtr_base = kGdtGpa;
  s.gdtr_limit = 0x0F;
  s.idtr_base = kIdtGpa;
  s.idtr_limit = 0xFFF;
  s.regs.rsp = kStackTop;
  ASSERT_EQ(ZX_OK, vcpu->RestoreArchState(s).status_value(), "load GDTR/IDTR/RSP\n");

  auto wide = [](const zx_port_packet_t& p) {
    uint32_t v = 0;
    memcpy(&v, p.guest_io.data, sizeof(v));
    return v;
  };

  zx_port_packet_t p = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(p).status_value(), "enter #1\n");
  ASSERT_EQ(0x10u, p.guest_io.port, "expected the readiness exit on 0x10\n");
  ASSERT_EQ(0u, vcpu->InServiceVector(), "nothing is in service before anything is delivered\n");
  ASSERT_EQ(0u, vcpu->ProcessorPriority(), "and the processor priority starts at 0\n");
  ASSERT_EQ(0u, vcpu->TaskPriority(),
            "the guest never touches CR8 in this test -- if it is nonzero, the task priority "
            "rather than the in-service register could be what holds a vector back\n");

  // The guest's own view of what has been requested, before anything has been.
  // The IRR words read a hard 0 before there was one to read, so what
  // discriminates is not this zero on its own -- it is this zero together with
  // the nonzero one the probe reads later, from the same register, same run.
  zx_port_packet_t irr_idle = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(irr_idle).status_value(), "enter #2\n");
  ASSERT_EQ(static_cast<uint32_t>(kWidePort), irr_idle.guest_io.port, "idle IRR report\n");
  EXPECT_EQ(0u, wide(irr_idle), "nothing has been requested yet\n");

  // (1) The first vector is delivered and goes into service.
  ASSERT_EQ(ZX_OK, vcpu->Interrupt(kFirstVector).status_value(), "inject the first vector\n");
  zx_port_packet_t ran = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(ran).status_value(), "enter #3\n");
  ASSERT_EQ(0x30u, ran.guest_io.port, "the first vector must vector through the guest IDT\n");
  ASSERT_EQ(kFirstVector, static_cast<uint32_t>(ran.guest_io.data[0]), "and be that vector\n");
  EXPECT_TRUE(vcpu->InService(kFirstVector), "a delivered vector must be in service\n");
  EXPECT_EQ(kFirstVector, vcpu->InServiceVector(), "and be the highest in service\n");
  EXPECT_EQ(kFirstVector & 0xf0u, vcpu->ProcessorPriority(),
            "with a class-5 vector in service and CR8 at 0, the processor priority is the "
            "in-service vector's class -- not the task priority, which is still 0\n");

  zx_port_packet_t ppr_report = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(ppr_report).status_value(), "enter #4\n");
  ASSERT_EQ(static_cast<uint32_t>(kWidePort), ppr_report.guest_io.port, "PPR report\n");
  ASSERT_EQ(4u, ppr_report.guest_io.access_size, "PPR report must be the 4-byte OUT\n");
  EXPECT_EQ(kFirstVector & 0xf0u, wide(ppr_report),
            "the guest's own `rdmsr 0x80a` must report the priority it is running at; this "
            "register used to be absent from the MSR switch entirely and #GP the guest\n");

  zx_port_packet_t isr_report = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(isr_report).status_value(), "enter #5\n");
  ASSERT_EQ(static_cast<uint32_t>(kWidePort), isr_report.guest_io.port, "ISR report\n");
  EXPECT_EQ(kExpectedIsrWord, wide(isr_report),
            "the guest's own `rdmsr 0x812` must show its vector's bit in the in-service register; "
            "the ISR words read a hard 0 before there was one\n");

  // (2) A HIGHER priority class pre-empts the running handler. This is the half
  // of the model that a blanket "refuse everything while anything is in service"
  // would get wrong, and the ISR ends up holding two bits at once.
  ASSERT_EQ(ZX_OK, vcpu->Interrupt(kNestVector).status_value(), "inject the higher class\n");
  zx_port_packet_t nested = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(nested).status_value(), "enter #6\n");
  EXPECT_EQ(0x30u, nested.guest_io.port,
            "a vector of a HIGHER priority class must pre-empt the running handler; reaching the "
            "probe's out 0x11 instead would mean interrupts are being refused wholesale rather "
            "than arbitrated by class\n");
  EXPECT_EQ(kNestVector, static_cast<uint32_t>(nested.guest_io.data[0]),
            "and it must be the higher-class vector that ran\n");
  EXPECT_TRUE(vcpu->InService(kFirstVector) && vcpu->InService(kNestVector),
              "both must now be in service at once -- one slot is not an in-service register\n");
  EXPECT_EQ(kNestVector, vcpu->InServiceVector(), "the higher one is on top\n");
  EXPECT_EQ(kNestVector & 0xf0u, vcpu->ProcessorPriority(), "and sets the processor priority\n");

  zx_port_packet_t nested_ppr = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(nested_ppr).status_value(), "enter #7\n");
  ASSERT_EQ(static_cast<uint32_t>(kWidePort), nested_ppr.guest_io.port, "nested PPR report\n");
  EXPECT_EQ(kNestVector & 0xf0u, wide(nested_ppr),
            "the guest, nested two deep, must read the inner interrupt's class as its PPR\n");

  zx_port_packet_t nested_isr = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(nested_isr).status_value(), "enter #8\n");
  ASSERT_EQ(static_cast<uint32_t>(kWidePort), nested_isr.guest_io.port, "nested ISR report\n");
  EXPECT_EQ(kExpectedIsrWord, wide(nested_isr),
            "and must still see the OUTER interrupt in service beneath it\n");

  // (3) A second vector of the first one's class is held. The nested handler
  // EOIs on its way out, which unwinds to 0x50 -- not to zero -- so this is
  // blocked by what is left in service, with CR8 still 0 throughout.
  const uint64_t isr_blocked_before = vcpu->IsrBlocked();
  ASSERT_EQ(ZX_OK, vcpu->Interrupt(kSecondVector).status_value(), "inject the second vector\n");
  zx_port_packet_t held = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(held).status_value(), "enter #9\n");
  EXPECT_EQ(0x11u, held.guest_io.port,
            "a vector of the still-running interrupt's own priority class must be held until its "
            "EOI, so the guest must reach its own out 0x11 -- port 0x30 means the second handler "
            "ran inside the first, which is exactly the pre-emption the architecture forbids\n");
  EXPECT_EQ(0xA2u, static_cast<uint32_t>(held.guest_io.data[0]), "probe value\n");
  EXPECT_EQ(1u, vcpu->EoiCompletions(),
            "the nested handler's EOI must have ended exactly one interrupt\n");
  EXPECT_FALSE(vcpu->InService(kNestVector), "the nested vector is done\n");
  EXPECT_TRUE(vcpu->InService(kFirstVector), "the outer one is not\n");
  EXPECT_EQ(kFirstVector & 0xf0u, vcpu->ProcessorPriority(),
            "so one EOI unwinds to the outer interrupt's class, not to zero\n");
  EXPECT_TRUE(vcpu->InterruptPending(kSecondVector), "and the held vector is held, not dropped\n");
  EXPECT_GT(vcpu->IsrBlocked(), isr_blocked_before,
            "the block must be attributed to the in-service interrupt; the guest's task priority "
            "is 0 here, so a block counted against the task priority instead would mean the two "
            "terms are not being told apart\n");
  EXPECT_EQ(0u, vcpu->TaskPriority(), "CR8 is still 0 -- nothing else could be holding it\n");

  // The same IRR the guest read as 0 before anything was injected must now show
  // the held vector. One register, two reads, two different required values: a
  // handler answering from a constant cannot satisfy both.
  zx_port_packet_t irr_held = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(irr_held).status_value(), "enter #10\n");
  ASSERT_EQ(static_cast<uint32_t>(kWidePort), irr_held.guest_io.port, "held IRR report\n");
  EXPECT_EQ(kExpectedIrrWord, wide(irr_held),
            "a vector that is held rather than delivered is *requested*, and the guest must be "
            "able to see it in its own interrupt-request register\n");

  // (4) The guest's own EOI releases it, before its next instruction retires.
  zx_port_packet_t released = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(released).status_value(), "enter #11\n");
  EXPECT_EQ(0x30u, released.guest_io.port,
            "the guest's EOI must end the in-service interrupt and let the held vector in; port "
            "0x12 means the EOI was accepted and discarded, which is what happened before there "
            "was an in-service register for it to clear\n");
  EXPECT_EQ(kSecondVector, static_cast<uint32_t>(released.guest_io.data[0]),
            "and the vector that arrives must be the one that was held\n");
  EXPECT_EQ(2u, vcpu->EoiCompletions(),
            "two EOIs, each ending a real in-service interrupt rather than merely accepted\n");
  EXPECT_FALSE(vcpu->InService(kFirstVector), "the first vector is no longer in service\n");
  EXPECT_TRUE(vcpu->InService(kSecondVector), "and the second one now is\n");
  EXPECT_EQ(kSecondVector & 0xf0u, vcpu->ProcessorPriority(),
            "the processor priority follows the new in-service vector\n");

  printf("in-service/EOI OK: %#x delivered and in service (guest read PPR %#x, ISR %#x, IRR %#x "
         "-> %#x through its own poisoned rdmsr); higher-class %#x pre-empted it with BOTH in "
         "service (guest read PPR %#x, ISR %#x); same-class %#x was held (%lu ISR-attributed "
         "block(s), CR8 still %#x) and reached out 0x11; two EOIs unwound %#x then %#x and "
         "delivered %#x, PPR now %#x\n",
         kFirstVector, wide(ppr_report), wide(isr_report), wide(irr_idle), wide(irr_held),
         kNestVector, wide(nested_ppr), wide(nested_isr), kSecondVector,
         vcpu->IsrBlocked() - isr_blocked_before, vcpu->TaskPriority(), kNestVector, kFirstVector,
         kSecondVector, vcpu->ProcessorPriority());
#else
  printf("Not x86_64; skipping.\n");
#endif  // __x86_64__

  END_TEST;
}

// ---------------------------------------------------------------------------
// Exception starvation and the delivery precedence it turns on.
// ---------------------------------------------------------------------------
//
// Shared scaffolding for the three cases below. Every one of them needs the same
// machine: a 64-bit guest with a real GDT/IDT, a #GP gate and an external-vector
// gate that land on DIFFERENT ports, and a stack. What differs between them is
// only the guest's instruction stream and what the host queues at the first
// exit, so those are the parameters.
//
// The two handlers report on different ports on purpose. "The exception was
// starved", "the exception arrived" and "the interrupt arrived instead" are
// three distinct outcomes, and a test that could not tell the second from the
// third would be satisfied by a hypervisor that had simply stopped gating
// interrupts on priority -- which is the W3 model this change must not undo.
#ifdef __x86_64__

// Priority class 5. The guest raises its task priority to class 8 in the two
// cases where the block is meant to be the task priority, so a correct APIC
// holds this vector back.
constexpr uint32_t kStarveIntVector = 0x50;
constexpr uint8_t kStarveRaisedClass = 0x08;
constexpr uint32_t kGpVectorNo = 13;
constexpr uint64_t kStarveGdtGpa = 0x6000;
constexpr uint64_t kStarveIdtGpa = 0x6800;
constexpr uint64_t kStarveGpHandlerGpa = 0x8000;
constexpr uint64_t kStarveIntHandlerGpa = 0x8080;
// A SECOND, non-#GP exception vector. This distinguishes a fall-through
// hard-coded to
// `TryPop(X86_INT_GP_FAULT)` rather than a scan of the exception range passes
// every other assertion here, because #GP is the only exception this hypervisor
// generates often enough to be the obvious one to special-case.
constexpr uint32_t kUdVectorNo = 6;
constexpr uint64_t kStarveUdHandlerGpa = 0x8100;
constexpr uint64_t kStarveStackTop = 0x9000;
// mov al, 0x6D ; out 0x30, al ; hlt  -- reached only by the #GP gate.
constexpr uint8_t kGpHandlerPort = 0x30;
constexpr uint8_t kGpHandlerByte = 0x6D;
// mov al, 0x55 ; out 0x31, al ; hlt  -- reached only by the external vector.
constexpr uint8_t kIntHandlerPort = 0x31;
constexpr uint8_t kIntHandlerByte = 0x55;
// mov al, 0x99 ; out 0x32, al ; hlt  -- reached only by the #UD gate.
constexpr uint8_t kUdHandlerPort = 0x32;
constexpr uint8_t kUdHandlerByte = 0x99;
// The guest's own "nothing was delivered to me" report.
constexpr uint8_t kStarveNothingPort = 0x11;
constexpr uint8_t kStarveNothingByte = 0xAA;

// Builds the RAM image: identity tables, GDT, both IDT gates, both handlers, and
// `code` at kCodeGpa.
zx_status_t WriteStarvationImage(const fbl::RefPtr<VmObjectPaged>& ram, const uint8_t* code,
                                 size_t code_len) {
  if (zx_status_t s = WriteIdentityTables(ram); s != ZX_OK) {
    return s;
  }
  if (zx_status_t s = ram->Write(code, kCodeGpa, code_len); s != ZX_OK) {
    return s;
  }
  // GDT[1] = flat 64-bit code segment (selector 0x08).
  const uint8_t gdt_code[8] = {0xFF, 0xFF, 0x00, 0x00, 0x00, 0x9B, 0xAF, 0x00};
  if (zx_status_t s = ram->Write(gdt_code, kStarveGdtGpa + 8, sizeof(gdt_code)); s != ZX_OK) {
    return s;
  }
  auto gate = [&](uint32_t vector, uint64_t handler) {
    const uint8_t idt_gate[16] = {static_cast<uint8_t>(handler & 0xFF),
                                  static_cast<uint8_t>((handler >> 8) & 0xFF),
                                  0x08,
                                  0x00,
                                  0x00,
                                  0x8E,
                                  0x00,
                                  0x00,
                                  0x00,
                                  0x00,
                                  0x00,
                                  0x00,
                                  0x00,
                                  0x00,
                                  0x00,
                                  0x00};
    return ram->Write(idt_gate, kStarveIdtGpa + vector * 16, sizeof(idt_gate));
  };
  if (zx_status_t s = gate(kGpVectorNo, kStarveGpHandlerGpa); s != ZX_OK) {
    return s;
  }
  if (zx_status_t s = gate(kStarveIntVector, kStarveIntHandlerGpa); s != ZX_OK) {
    return s;
  }
  if (zx_status_t s = gate(kUdVectorNo, kStarveUdHandlerGpa); s != ZX_OK) {
    return s;
  }
  const uint8_t gp_handler[] = {0xB0, kGpHandlerByte, 0xE6, kGpHandlerPort, 0xF4};
  if (zx_status_t s = ram->Write(gp_handler, kStarveGpHandlerGpa, sizeof(gp_handler)); s != ZX_OK) {
    return s;
  }
  const uint8_t int_handler[] = {0xB0, kIntHandlerByte, 0xE6, kIntHandlerPort, 0xF4};
  if (zx_status_t s = ram->Write(int_handler, kStarveIntHandlerGpa, sizeof(int_handler));
      s != ZX_OK) {
    return s;
  }
  const uint8_t ud_handler[] = {0xB0, kUdHandlerByte, 0xE6, kUdHandlerPort, 0xF4};
  if (zx_status_t s = ram->Write(ud_handler, kStarveUdHandlerGpa, sizeof(ud_handler)); s != ZX_OK) {
    return s;
  }
  return ram->CommitRange(0, kGuestRamSize);
}

// Maps the image, installs the four I/O traps the cases use, creates the VCPU
// and loads its GDTR/IDTR/RSP.
zx::result<ktl::unique_ptr<Vcpu>> MakeStarvationVcpu(Guest& guest,
                                                     const fbl::RefPtr<VmObjectPaged>& ram) {
  auto mapping = guest.RootVmar()->CreateVmMapping(0, kGuestRamSize, 0, VMAR_FLAG_SPECIFIC, ram, 0,
                                                   kMmuFlags, "guest-ram");
  if (mapping.is_error()) {
    return mapping.take_error();
  }
  for (uint16_t port : {uint16_t{0x10}, uint16_t{kStarveNothingPort}, uint16_t{kGpHandlerPort},
                        uint16_t{kIntHandlerPort}, uint16_t{kUdHandlerPort}}) {
    auto t = guest.SetTrap(ZX_GUEST_TRAP_IO, port, 1, nullptr, port);
    if (t.is_error()) {
      return t.take_error();
    }
  }
  auto vcpu_result = Vcpu::Create(guest, kCodeGpa);
  if (vcpu_result.is_error()) {
    return vcpu_result.take_error();
  }
  ktl::unique_ptr<Vcpu> vcpu = ktl::move(vcpu_result.value());
  VcpuArchState s = {};
  if (auto e = vcpu->SaveArchState(s); e.is_error()) {
    return e.take_error();
  }
  s.gdtr_base = kStarveGdtGpa;
  s.gdtr_limit = 0x0F;
  s.idtr_base = kStarveIdtGpa;
  s.idtr_limit = 0xFFF;
  s.regs.rsp = kStarveStackTop;
  if (auto e = vcpu->RestoreArchState(s); e.is_error()) {
    return e.take_error();
  }
  return zx::ok(ktl::move(vcpu));
}

#endif  // __x86_64__

// A queued exception must not be starved by a priority-blocked interrupt.
//
// `local_apic_maybe_interrupt` pops the highest pending vector. When that vector
// is an external interrupt the guest's processor priority is holding back, the
// vector is put back -- correctly -- and the function RETURNED. A queued
// exception sitting lower in the same bitmap was therefore never even looked at.
//
// Why that is a livelock and not merely a delay. The exceptions in that bitmap
// are the ones this hypervisor's own exit handlers generate -- a #GP for an
// unhandled MSR handling relies on this -- and they are generated without advancing
// the guest RIP, because that is what a fault requires. So the guest re-executes
// the faulting instruction, exits again, queues the same #GP again, and is
// refused again. Nothing in the loop lowers the task priority, because the guest
// never retires an instruction. See `vcpu_faulting_instruction_is_not_starved_by
// _a_blocked_interrupt` below for that shape driven end-to-end; this case is the
// bounded one, and it is deliberately registered FIRST so that a regression
// aborts the suite here rather than hanging in that one.
//
// THE PRECEDENCE CLAIM, stated because the fix is not "exceptions first".
// Volume 3, Table 6-2 ranks a maskable hardware interrupt ABOVE a fault from
// executing an instruction, and that ordering is preserved -- see
// `vcpu_deliverable_interrupt_precedes_a_queued_exception`, which is the guard
// on it. The ordering only ranks events that can actually be delivered. An
// interrupt held below the processor priority is not delivered by the APIC at
// all; it stays requested. A fault, meanwhile, is not subject to TPR/PPR in any
// form -- it is a property of the instruction being executed, not of the
// interrupt-priority space -- so on real silicon the raised task priority holds
// the interrupt in the IRR while the instruction executes and its fault is
// taken. Delivering the exception here is what that looks like from inside a
// hypervisor that injects through the VM-entry interruption-information field.
//
// What each assertion discriminates:
//   * port 0x11 means the exception was starved -- the bug;
//   * port 0x31 means the interrupt was delivered anyway -- the W3 priority
//     model undone, which is the cheapest way to "fix" a starvation report;
//   * the interrupt still being PENDING afterwards means it was held, not
//     dropped, and not delivered;
//   * the task priority still reading class 8 at the moment the fault was taken
//     is the positive form of "an exception is not TPR-gated"; if the fault had
//     only arrived because something lowered CR8, this would not read 0x80;
//   * PriorityBlocked() moving proves the interrupt was refused *on priority
//     grounds* on this entry, rather than never having been considered.
bool vcpu_queued_exception_is_not_starved_by_a_blocked_interrupt() {
  BEGIN_TEST;

#ifdef __x86_64__
  auto guest_result = Guest::Create();
  if (guest_result.is_error() && guest_result.status_value() == ZX_ERR_NOT_SUPPORTED) {
    printf("VMX not supported here; skipping exception-starvation test.\n");
    return true;
  }
  ASSERT_EQ(ZX_OK, guest_result.status_value(), "Guest::Create failed\n");
  ktl::unique_ptr<Guest> guest = ktl::move(guest_result.value());

  //  FB                    sti
  //  90                    nop                 ; retire the one-instruction STI shadow
  //  48 C7 C0 08 00 00 00  mov rax, 8
  //  44 0F 22 C0           mov cr8, rax        ; task priority class 8
  //  B0 01                 mov al, 1
  //  E6 10                 out 0x10, al        ; exit #1; the host queues both events here
  //  90 x8                 nop                 ; a window a delivered event lands in
  //  B0 AA                 mov al, 0xAA
  //  E6 11                 out 0x11, al        ; reached ONLY if nothing was delivered
  //  F4                    hlt
  const uint8_t code[] = {0xFB, 0x90, 0x48, 0xC7, 0xC0, kStarveRaisedClass, 0x00,
                          0x00, 0x00, 0x44, 0x0F, 0x22, 0xC0, 0xB0,
                          0x01, 0xE6, 0x10, 0x90, 0x90, 0x90, 0x90,
                          0x90, 0x90, 0x90, 0x90, 0xB0, kStarveNothingByte,
                          0xE6, kStarveNothingPort, 0xF4};
  // Phase 2's landing area, at kCode2Gpa: a window for a delivered exception and
  // a report the guest can only reach if nothing was delivered.
  //  90 x8     nop
  //  B0 CC     mov al, 0xCC
  //  E6 11     out 0x11, al
  //  F4        hlt
  const uint8_t resume[] = {0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
                            0xB0, 0xCC, 0xE6, kStarveNothingPort, 0xF4};

  fbl::RefPtr<VmObjectPaged> ram;
  ASSERT_EQ(ZX_OK, VmObjectPaged::Create(PMM_ALLOC_FLAG_ANY, 0u, kGuestRamSize, &ram), "ram\n");
  ASSERT_EQ(ZX_OK, WriteStarvationImage(ram, code, sizeof(code)), "image\n");
  ASSERT_EQ(ZX_OK, ram->Write(resume, kCode2Gpa, sizeof(resume)), "resume stub\n");
  auto vcpu_result = MakeStarvationVcpu(*guest, ram);
  ASSERT_EQ(ZX_OK, vcpu_result.status_value(), "vcpu\n");
  ktl::unique_ptr<Vcpu> vcpu = ktl::move(vcpu_result.value());

  zx_port_packet_t p = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(p).status_value(), "enter #1\n");
  ASSERT_EQ(0x10u, p.guest_io.port, "expected the pre-injection exit on 0x10\n");
  ASSERT_EQ(static_cast<uint32_t>(kStarveRaisedClass) << 4, vcpu->TaskPriority(),
            "the guest's `mov cr8` must be visible to the host as VTPR\n");

  // Both, at the same time, into the same bitmap. The interrupt is the
  // numerically higher vector, so it is the one the tracker's reverse scan pops.
  ASSERT_EQ(ZX_OK, vcpu->Interrupt(kStarveIntVector).status_value(), "queue interrupt\n");
  ASSERT_EQ(ZX_OK, vcpu->Interrupt(kGpVectorNo).status_value(), "queue #GP\n");

  const uint64_t blocked_before = vcpu->PriorityBlocked();
  zx_port_packet_t got = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(got).status_value(), "enter #2\n");
  ASSERT_EQ(static_cast<uint8_t>(ZX_PKT_TYPE_GUEST_IO), static_cast<uint8_t>(got.type), "io\n");
  EXPECT_EQ(static_cast<uint32_t>(kGpHandlerPort), got.guest_io.port,
            "the queued #GP must reach the guest's own #GP handler even though a lower-priority "
            "external vector is blocked ahead of it in the same bitmap -- port 0x11 means the "
            "exception was STARVED (the guest ran on with its fault undelivered), port 0x31 means "
            "the blocked interrupt was delivered instead and the priority model was undone\n");
  EXPECT_EQ(static_cast<uint32_t>(kGpHandlerByte), static_cast<uint32_t>(got.guest_io.data[0]),
            "and it must be the #GP handler that ran\n");
  EXPECT_TRUE(vcpu->InterruptPending(kStarveIntVector),
              "the priority-blocked interrupt must still be queued: delivering the exception must "
              "not consume, drop or deliver it\n");
  EXPECT_FALSE(vcpu->InService(kStarveIntVector),
               "and it must not be in service -- nothing delivered it\n");
  EXPECT_EQ(static_cast<uint32_t>(kStarveRaisedClass) << 4, vcpu->TaskPriority(),
            "the fault was taken with the guest's task priority STILL at class 8: an exception is "
            "not gated by TPR/PPR at all, which is the whole reason it may go first here\n");
  EXPECT_GT(vcpu->PriorityBlocked(), blocked_before,
            "the interrupt must have been REFUSED on priority grounds on this entry -- if this "
            "counter did not move, the interrupt was never arbitrated and the exception did not "
            "get in past a block, it got in past nothing\n");

  // Phase 2: the same thing with an exception that is NOT #GP.
  //
  // The fall-through is specified as a scan of the exception range, not as a
  // special case for the one vector this hypervisor happens to generate most.
  // A fix written as `TryPop(X86_INT_GP_FAULT)` satisfies every assertion above
  // while avoiding the required scan, and fails here.
  //
  // The interrupt from phase 1 is still queued and CR8 is still class 8, so the
  // block is the same one; RFLAGS.IF is put back because the #GP was delivered
  // through an interrupt gate, which cleared it, and without that this phase
  // would silently be testing the interruptibility path instead of the priority
  // path it is registered under.
  fbl::AllocChecker ac;
  ktl::unique_ptr<VcpuArchState> s(new (&ac) VcpuArchState{});
  ASSERT_TRUE(ac.check(), "alloc arch state\n");
  ASSERT_EQ(ZX_OK, vcpu->SaveArchState(*s).status_value(), "capture between phases\n");
  s->rip = kCode2Gpa;
  s->regs.rflags |= X86_FLAGS_IF;
  ASSERT_EQ(ZX_OK, vcpu->RestoreArchState(*s).status_value(), "reposition to the resume stub\n");
  ASSERT_TRUE(vcpu->InterruptPending(kStarveIntVector),
              "phase 2 needs the interrupt still held from phase 1\n");
  ASSERT_EQ(static_cast<uint32_t>(kStarveRaisedClass) << 4, vcpu->TaskPriority(),
            "and the task priority still raised, or it is not the same block\n");
  ASSERT_EQ(ZX_OK, vcpu->Interrupt(kUdVectorNo).status_value(), "queue #UD\n");

  const uint64_t blocked_before_ud = vcpu->PriorityBlocked();
  zx_port_packet_t ud = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(ud).status_value(), "enter #3\n");
  ASSERT_EQ(static_cast<uint8_t>(ZX_PKT_TYPE_GUEST_IO), static_cast<uint8_t>(ud.type), "io\n");
  EXPECT_EQ(static_cast<uint32_t>(kUdHandlerPort), ud.guest_io.port,
            "a queued #UD must get through the same block a #GP got through -- port 0x11 here "
            "means the fall-through was hard-coded to the #GP vector rather than scanning the "
            "exception range\n");
  EXPECT_EQ(static_cast<uint32_t>(kUdHandlerByte), static_cast<uint32_t>(ud.guest_io.data[0]),
            "and it must be the #UD handler that ran\n");
  EXPECT_GT(vcpu->PriorityBlocked(), blocked_before_ud,
            "this phase must have gone through the priority branch too\n");
  EXPECT_TRUE(vcpu->InterruptPending(kStarveIntVector),
              "and the interrupt is STILL held after a second exception went past it\n");

  printf("exception starvation OK: with CR8 at class %#x holding vector %#x, the queued #GP "
         "reached the guest's own handler (port %#x, %#x) and a queued #UD reached its own (port "
         "%#x, %#x); the interrupt is still pending, not in service, VTPR still %#x, %lu "
         "priority-block(s) recorded\n",
         kStarveRaisedClass, kStarveIntVector, got.guest_io.port, got.guest_io.data[0],
         ud.guest_io.port, ud.guest_io.data[0], vcpu->TaskPriority(),
         vcpu->PriorityBlocked() - blocked_before);
#else
  printf("Not x86_64; skipping.\n");
#endif  // __x86_64__

  END_TEST;
}

// The SECOND starvation path, and the older one.
//
// `local_apic_maybe_interrupt` refuses a popped external vector in two separate
// places, and both used to `return`:
//
//   * the guest is not INTERRUPTIBLE -- RFLAGS.IF is clear, or STI/MOV-SS
//     blocking is in force. This one predates the interrupt-priority model
//     entirely;
//   * the guest's PROCESSOR PRIORITY is at or above the vector's class, which is
//     the path the priority model introduced and the case above covers.
//
// A fix applied to only the second leaves the first open, and would still look
// like a fix -- the case above would go green. This case is what makes that
// partial fix red, and the assertion that does it is `PriorityBlocked()`:
// it must NOT move here. The interrupt is refused because the guest cannot take
// an interrupt at all, not because of its priority, and the two counters exist
// precisely so those reasons can be told apart rather than inferred. The guest's
// task priority is 0 throughout, so nothing in the priority model is even in
// play.
//
// Phase 2 is not decoration. It proves the refused vector was HELD and that the
// instrument armed for it still works after an exception was injected on the
// same entry: the guest is repositioned to a stub that runs `sti`, and the
// interrupt-window exit that follows must deliver the vector to its own handler
// within that same `Enter()`. Without it, "the exception got through" would be
// consistent with the interrupt having been quietly dropped on the floor, which
// is a worse bug than the one being fixed.
bool vcpu_queued_exception_is_not_starved_by_an_uninjectable_interrupt() {
  BEGIN_TEST;

#ifdef __x86_64__
  auto guest_result = Guest::Create();
  if (guest_result.is_error() && guest_result.status_value() == ZX_ERR_NOT_SUPPORTED) {
    printf("VMX not supported here; skipping uninjectable-interrupt starvation test.\n");
    return true;
  }
  ASSERT_EQ(ZX_OK, guest_result.status_value(), "Guest::Create failed\n");
  ktl::unique_ptr<Guest> guest = ktl::move(guest_result.value());

  // Phase 1, at kCodeGpa. CR8 is left at 0: the ONLY thing that can hold the
  // interrupt here is RFLAGS.IF.
  //  FA        cli
  //  B0 01     mov al, 1
  //  E6 10     out 0x10, al     ; exit #1; the host queues both events here
  //  90 x8     nop
  //  B0 AA     mov al, 0xAA
  //  E6 11     out 0x11, al     ; reached ONLY if the exception was starved
  //  F4        hlt
  const uint8_t code[] = {0xFA, 0xB0, 0x01, 0xE6, 0x10, 0x90, 0x90, 0x90, 0x90, 0x90,
                          0x90, 0x90, 0x90, 0xB0, kStarveNothingByte,
                          0xE6, kStarveNothingPort, 0xF4};
  // Phase 2, at kCode2Gpa: re-enable interrupts and give the held vector
  // somewhere to arrive.
  //  FB        sti
  //  90        nop              ; retire the one-instruction STI shadow
  //  90 x8     nop
  //  B0 CC     mov al, 0xCC
  //  E6 11     out 0x11, al     ; reached ONLY if the held vector was lost
  //  F4        hlt
  const uint8_t resume[] = {0xFB, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
                            0xB0, 0xCC, 0xE6, kStarveNothingPort, 0xF4};

  fbl::RefPtr<VmObjectPaged> ram;
  ASSERT_EQ(ZX_OK, VmObjectPaged::Create(PMM_ALLOC_FLAG_ANY, 0u, kGuestRamSize, &ram), "ram\n");
  ASSERT_EQ(ZX_OK, WriteStarvationImage(ram, code, sizeof(code)), "image\n");
  ASSERT_EQ(ZX_OK, ram->Write(resume, kCode2Gpa, sizeof(resume)), "resume stub\n");
  auto vcpu_result = MakeStarvationVcpu(*guest, ram);
  ASSERT_EQ(ZX_OK, vcpu_result.status_value(), "vcpu\n");
  ktl::unique_ptr<Vcpu> vcpu = ktl::move(vcpu_result.value());

  zx_port_packet_t p = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(p).status_value(), "enter #1\n");
  ASSERT_EQ(0x10u, p.guest_io.port, "expected the pre-injection exit on 0x10\n");

  // The guest really is un-interruptible, checked rather than assumed. If
  // RFLAGS.IF were set here the `cli` did not take and this case would be a
  // duplicate of the priority one.
  fbl::AllocChecker ac;
  ktl::unique_ptr<VcpuArchState> s(new (&ac) VcpuArchState{});
  ASSERT_TRUE(ac.check(), "alloc arch state\n");
  ASSERT_EQ(ZX_OK, vcpu->SaveArchState(*s).status_value(), "capture after cli\n");
  ASSERT_EQ(0u, s->regs.rflags & X86_FLAGS_IF,
            "the guest must have interrupts DISABLED at the injection point -- that is the block "
            "this case is about\n");
  ASSERT_EQ(0u, vcpu->TaskPriority(),
            "and its task priority must be 0, so the priority model cannot be what holds the "
            "vector\n");

  ASSERT_EQ(ZX_OK, vcpu->Interrupt(kStarveIntVector).status_value(), "queue interrupt\n");
  ASSERT_EQ(ZX_OK, vcpu->Interrupt(kGpVectorNo).status_value(), "queue #GP\n");

  const uint64_t blocked_before = vcpu->PriorityBlocked();
  zx_port_packet_t got = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(got).status_value(), "enter #2\n");
  ASSERT_EQ(static_cast<uint8_t>(ZX_PKT_TYPE_GUEST_IO), static_cast<uint8_t>(got.type), "io\n");
  EXPECT_EQ(static_cast<uint32_t>(kGpHandlerPort), got.guest_io.port,
            "the queued #GP must reach the guest's own handler even though an UN-INJECTABLE "
            "external vector was popped ahead of it -- RFLAGS.IF does not gate exceptions. Port "
            "0x11 here means only the priority branch was fixed and this older path still "
            "returns; port 0x31 means an interrupt was injected into a guest with IF clear\n");
  EXPECT_EQ(static_cast<uint32_t>(kGpHandlerByte), static_cast<uint32_t>(got.guest_io.data[0]),
            "and it must be the #GP handler that ran\n");
  EXPECT_EQ(blocked_before, vcpu->PriorityBlocked(),
            "the priority-block counter must NOT move: this vector was refused because the guest "
            "was not interruptible, not because of its priority. A fix that routed this case "
            "through the priority branch would move it, and would be arming the TPR threshold "
            "for a condition the threshold cannot observe\n");
  EXPECT_TRUE(vcpu->InterruptPending(kStarveIntVector),
              "the un-injectable interrupt must still be queued\n");
  EXPECT_FALSE(vcpu->InService(kStarveIntVector), "and it must not be in service\n");

  // Phase 2: the held vector must still be deliverable once the guest can take
  // it. The #GP handler does not return, so the host repositions the guest --
  // which is what a VMM does anyway. RFLAGS.IF is still clear (the #GP went
  // through an interrupt gate), so the stub's own `sti` is what unblocks it.
  ASSERT_EQ(ZX_OK, vcpu->SaveArchState(*s).status_value(), "capture between phases\n");
  ASSERT_EQ(0u, s->regs.rflags & X86_FLAGS_IF,
            "the #GP gate must have left interrupts disabled, or the stub's sti proves nothing\n");
  s->rip = kCode2Gpa;
  ASSERT_EQ(ZX_OK, vcpu->RestoreArchState(*s).status_value(), "reposition to the resume stub\n");

  zx_port_packet_t released = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(released).status_value(), "enter #3\n");
  ASSERT_EQ(static_cast<uint8_t>(ZX_PKT_TYPE_GUEST_IO), static_cast<uint8_t>(released.type), "io\n");
  EXPECT_EQ(static_cast<uint32_t>(kIntHandlerPort), released.guest_io.port,
            "the held vector must be delivered once the guest re-enables interrupts -- port 0x11 "
            "means it was dropped when the exception went in ahead of it, which would be a worse "
            "bug than the starvation this case is about\n");
  EXPECT_EQ(static_cast<uint32_t>(kIntHandlerByte),
            static_cast<uint32_t>(released.guest_io.data[0]), "the external vector's handler\n");
  EXPECT_TRUE(vcpu->InService(kStarveIntVector),
              "and now, having actually been delivered, it is in service\n");

  printf("uninjectable-interrupt starvation OK: with RFLAGS.IF clear and vector %#x un-injectable, "
         "the queued #GP still reached the guest's handler (port %#x, %#x) with the priority-block "
         "counter unmoved at %lu; the guest's own sti then released the held vector into its "
         "handler (port %#x, %#x)\n",
         kStarveIntVector, got.guest_io.port, got.guest_io.data[0], vcpu->PriorityBlocked(),
         released.guest_io.port, released.guest_io.data[0]);
#else
  printf("Not x86_64; skipping.\n");
#endif  // __x86_64__

  END_TEST;
}

// The other half of the precedence rule, and the guard that keeps the fix above
// from being "exceptions first".
//
// Same two events queued together, but the guest's task priority is 0, so the
// external interrupt IS deliverable. Volume 3, Table 6-2 ranks a maskable
// hardware interrupt above a fault from executing an instruction, so the
// interrupt must go first -- and the exception must be DISCARDED, per Volume 3,
// Section 6.9 ("lower priority exceptions are discarded... re-generated when the
// interrupt handler returns"), which is sound precisely because the RIP was
// never advanced past the faulting instruction.
//
// This case also passes before the precedence correction; it exists because the
// simplest wrong implementation -- pop exceptions before interrupts
// unconditionally -- passes the case above and fails this one.
bool vcpu_deliverable_interrupt_precedes_a_queued_exception() {
  BEGIN_TEST;

#ifdef __x86_64__
  auto guest_result = Guest::Create();
  if (guest_result.is_error() && guest_result.status_value() == ZX_ERR_NOT_SUPPORTED) {
    printf("VMX not supported here; skipping delivery-precedence test.\n");
    return true;
  }
  ASSERT_EQ(ZX_OK, guest_result.status_value(), "Guest::Create failed\n");
  ktl::unique_ptr<Guest> guest = ktl::move(guest_result.value());

  //  FB        sti
  //  90        nop
  //  B0 01     mov al, 1
  //  E6 10     out 0x10, al     ; exit #1; both events queued here, CR8 still 0
  //  90 x8     nop
  //  B0 AA     mov al, 0xAA
  //  E6 11     out 0x11, al     ; reached only if NEITHER was delivered
  //  F4        hlt
  const uint8_t code[] = {0xFB, 0x90, 0xB0, 0x01, 0xE6, 0x10, 0x90, 0x90, 0x90,
                          0x90, 0x90, 0x90, 0x90, 0x90, 0xB0, kStarveNothingByte,
                          0xE6, kStarveNothingPort, 0xF4};

  fbl::RefPtr<VmObjectPaged> ram;
  ASSERT_EQ(ZX_OK, VmObjectPaged::Create(PMM_ALLOC_FLAG_ANY, 0u, kGuestRamSize, &ram), "ram\n");
  ASSERT_EQ(ZX_OK, WriteStarvationImage(ram, code, sizeof(code)), "image\n");
  auto vcpu_result = MakeStarvationVcpu(*guest, ram);
  ASSERT_EQ(ZX_OK, vcpu_result.status_value(), "vcpu\n");
  ktl::unique_ptr<Vcpu> vcpu = ktl::move(vcpu_result.value());

  zx_port_packet_t p = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(p).status_value(), "enter #1\n");
  ASSERT_EQ(0x10u, p.guest_io.port, "expected the pre-injection exit on 0x10\n");
  ASSERT_EQ(0u, vcpu->TaskPriority(),
            "this case needs the task priority at 0, or the interrupt is not deliverable and it "
            "is testing the other case\n");

  ASSERT_EQ(ZX_OK, vcpu->Interrupt(kStarveIntVector).status_value(), "queue interrupt\n");
  ASSERT_EQ(ZX_OK, vcpu->Interrupt(kGpVectorNo).status_value(), "queue #GP\n");

  zx_port_packet_t got = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(got).status_value(), "enter #2\n");
  ASSERT_EQ(static_cast<uint8_t>(ZX_PKT_TYPE_GUEST_IO), static_cast<uint8_t>(got.type), "io\n");
  EXPECT_EQ(static_cast<uint32_t>(kIntHandlerPort), got.guest_io.port,
            "with nothing blocking it, the external interrupt outranks a queued fault (Volume 3, "
            "Table 6-2) and must be delivered first -- port 0x30 means exceptions were given "
            "blanket precedence, which is the cheapest wrong fix for the starvation case\n");
  EXPECT_EQ(static_cast<uint32_t>(kIntHandlerByte), static_cast<uint32_t>(got.guest_io.data[0]),
            "and it must be the external vector's handler that ran\n");
  EXPECT_TRUE(vcpu->InService(kStarveIntVector),
              "a delivered external vector is in service until the guest EOIs it\n");
  EXPECT_FALSE(vcpu->InterruptPending(kGpVectorNo),
               "the lower-priority exception is DISCARDED, not held (Volume 3, Section 6.9): the "
               "guest RIP was never advanced past the faulting instruction, so it is regenerated "
               "when the handler returns\n");

  printf("delivery precedence OK: a deliverable vector %#x went ahead of a queued #GP (port %#x, "
         "%#x), is in service, and the exception was discarded\n",
         kStarveIntVector, got.guest_io.port, got.guest_io.data[0]);
#else
  printf("Not x86_64; skipping.\n");
#endif  // __x86_64__

  END_TEST;
}

// The same defect end-to-end, driven by a real guest instruction rather than by
// a host-queued vector -- the shape the unhandled-MSR path depends on.
//
// The guest raises CR8, the host queues a class-5 interrupt it therefore cannot
// take, and the guest then executes `rdmsr 0x1233`. Nothing implements that
// register and nothing ever should, so `handle_rdmsr`'s default arm answers it
// the way the architecture requires: queue a #GP into the interrupt tracker and
// do NOT advance the guest RIP. (It is the same register class
// `vcpu_unhandled_msr_announces_itself` uses for the same reason.)
//
// WHY AN *ANNOUNCED* MSR AND NOT A RESERVED x2APIC ONE. With `rdmsr 0x801`,
// nothing in the test distinguished
// "the hypervisor queued a #GP into the tracker" from "the CPU took a native
// #GP without ever exiting". Both put the guest in its #GP handler, both leave
// the interrupt pending, and every assertion passed either way -- so the case
// could have exercised none of the starvation path. An announced register fixes
// that, because `UnhandledMsrs()` is written only by the software handler. The
// log assertions below are therefore not decoration: they are what proves this
// test touches the mechanism at all. The recorded RIP additionally pins the
// no-`next_rip` property the livelock argument depends on.
//
// A NOTE ON WHAT FAILURE LOOKS LIKE HERE, because it is not a failed assertion.
// With the starvation bug present this test does not return a wrong value -- it
// does not return at all. `Vcpu::Enter` re-enters, the guest re-executes the
// RDMSR, the handler re-queues the #GP, the entry path refuses to look at it,
// and nothing in that loop ever exits to the VMM. That silent hang is exactly
// the failure mode that would otherwise convert a visible halt into a hang, and it
// is why this case is registered AFTER the bounded one above: Zircon's unittest
// framework aborts a testcase at its first failure, so the bounded case fails
// first and this one is never reached.
bool vcpu_faulting_instruction_is_not_starved_by_a_blocked_interrupt() {
  BEGIN_TEST;

#ifdef __x86_64__
  auto guest_result = Guest::Create();
  if (guest_result.is_error() && guest_result.status_value() == ZX_ERR_NOT_SUPPORTED) {
    printf("VMX not supported here; skipping faulting-instruction starvation test.\n");
    return true;
  }
  ASSERT_EQ(ZX_OK, guest_result.status_value(), "Guest::Create failed\n");
  ktl::unique_ptr<Guest> guest = ktl::move(guest_result.value());

  //  FB                    sti
  //  90                    nop
  //  48 C7 C0 08 00 00 00  mov rax, 8
  //  44 0F 22 C0           mov cr8, rax        ; task priority class 8
  //  B0 01                 mov al, 1
  //  E6 10                 out 0x10, al        ; exit #1; the host queues the interrupt here
  //  B9 33 12 00 00        mov ecx, 0x1233     ; implemented by nobody
  //  0F 32                 rdmsr               ; -> #GP queued, guest RIP NOT advanced
  //  B0 AA                 mov al, 0xAA
  //  E6 11                 out 0x11, al        ; reached only if the fault never arrived
  //  F4                    hlt
  constexpr uint32_t kUnhandledMsr = 0x1233;
  // Byte offset of the RDMSR within the block above, so the recorded fault RIP
  // can be asserted exactly rather than merely "something was logged".
  constexpr uint64_t kRdmsrOffset = 22;
  const uint8_t code[] = {0xFB, 0x90, 0x48, 0xC7, 0xC0, kStarveRaisedClass, 0x00,
                          0x00, 0x00, 0x44, 0x0F, 0x22, 0xC0, 0xB0,
                          0x01, 0xE6, 0x10, 0xB9, 0x33, 0x12, 0x00,
                          0x00, 0x0F, 0x32, 0xB0, kStarveNothingByte,
                          0xE6, kStarveNothingPort, 0xF4};
  static_assert(kRdmsrOffset == 22, "keep in step with the encoding above");

  fbl::RefPtr<VmObjectPaged> ram;
  ASSERT_EQ(ZX_OK, VmObjectPaged::Create(PMM_ALLOC_FLAG_ANY, 0u, kGuestRamSize, &ram), "ram\n");
  ASSERT_EQ(ZX_OK, WriteStarvationImage(ram, code, sizeof(code)), "image\n");
  auto vcpu_result = MakeStarvationVcpu(*guest, ram);
  ASSERT_EQ(ZX_OK, vcpu_result.status_value(), "vcpu\n");
  ktl::unique_ptr<Vcpu> vcpu = ktl::move(vcpu_result.value());

  zx_port_packet_t p = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(p).status_value(), "enter #1\n");
  ASSERT_EQ(0x10u, p.guest_io.port, "expected the pre-injection exit on 0x10\n");
  ASSERT_EQ(static_cast<uint32_t>(kStarveRaisedClass) << 4, vcpu->TaskPriority(), "CR8 raised\n");
  ASSERT_EQ(ZX_OK, vcpu->Interrupt(kStarveIntVector).status_value(), "queue interrupt\n");
  ASSERT_EQ(0u, vcpu->UnhandledMsrs().total,
            "nothing has faulted yet, so the count below is this guest's alone\n");

  zx_port_packet_t got = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(got).status_value(), "enter #2\n");
  ASSERT_EQ(static_cast<uint8_t>(ZX_PKT_TYPE_GUEST_IO), static_cast<uint8_t>(got.type), "io\n");
  EXPECT_EQ(static_cast<uint32_t>(kGpHandlerPort), got.guest_io.port,
            "the #GP the hypervisor generated for the guest's own faulting instruction must reach "
            "the guest, and it must do so while a lower-priority interrupt is blocked -- port "
            "0x11 means the guest ran past its own fault, port 0x31 means the blocked interrupt "
            "was delivered\n");
  EXPECT_EQ(static_cast<uint32_t>(kGpHandlerByte), static_cast<uint32_t>(got.guest_io.data[0]),
            "the guest's #GP handler\n");
  EXPECT_TRUE(vcpu->InterruptPending(kStarveIntVector), "the interrupt is still held\n");
  EXPECT_EQ(static_cast<uint32_t>(kStarveRaisedClass) << 4, vcpu->TaskPriority(),
            "and the task priority never moved\n");

  // This is what proves the fault came from the hypervisor's own handler rather
  // than from the CPU, i.e. that this case exercised the tracker at all.
  {
    const UnhandledMsrLog& log = vcpu->UnhandledMsrs();
    EXPECT_EQ(1u, log.total,
              "the RDMSR must have taken a VM exit and been answered in software exactly once -- "
              "0 here means the CPU faulted the guest natively and this case never touched the "
              "starvation path it claims to test\n");
    EXPECT_EQ(kUnhandledMsr, log.last_msr, "and the record must name the register\n");
    EXPECT_TRUE(log.last_gp_injected, "the #GP must have been queued, not merely logged\n");
    EXPECT_EQ(kCodeGpa + kRdmsrOffset, log.last_rip,
              "the recorded RIP must be the RDMSR's OWN address: the livelock argument depends on "
              "the fault handler not advancing past the faulting instruction, and if it did "
              "advance, this test would pass while the shape it stands for had changed\n");
  }

  printf("faulting-instruction progress OK: `rdmsr %#x` at RIP %#lx under CR8 class %#x with "
         "vector %#x blocked was answered in software (%lu announcement) and delivered its #GP to "
         "the guest (port %#x, %#x) instead of re-executing forever\n",
         kUnhandledMsr, kCodeGpa + kRdmsrOffset, kStarveRaisedClass, kStarveIntVector,
         vcpu->UnhandledMsrs().total, got.guest_io.port, got.guest_io.data[0]);
#else
  printf("Not x86_64; skipping.\n");
#endif  // __x86_64__

  END_TEST;
}

// The x2APIC registers that a guest may legally read, and the LVT entries it may
// legally write and read back.
//
// Two defects, in one guest, because they share a mechanism:
//
//  * seven registers faulted on an architecturally legal access. `ICR`,
//    `LVT_ERROR`, `INITIAL_COUNT` and `DCR` were writable and *not readable*,
//    so the read half of a read-modify-write -- which is how an LVT entry is
//    masked or unmasked, and how an IPI is composed -- took a #GP. `PPR`, `APR`
//    and `CURRENT_COUNT` were absent from the register enum entirely, so both
//    directions faulted; `CURRENT_COUNT` is read by every local-timer
//    calibration loop and `PPR` by APIC bring-up.
//  * the LVT writes that were accepted were then thrown away, and the matching
//    reads answered with the architectural *reset* value. A guest that masked
//    an LVT entry and read it back was told it had not.
//
// Everything here is driven from inside the guest with real `wrmsr`/`rdmsr`
// instructions, and every value is reported back out with a 4-byte OUT, so what
// is asserted is what the guest sees. That matters twice over. First, it is the
// only way to check the fault: a #GP here is injected into a guest with a
// 16-byte IDT, which triple-faults, so a register that still faults does not
// produce a wrong value -- it produces no exit at all and the test fails on the
// missing packet rather than on a comparison. Second, it settles by measurement
// whether "virtualize x2APIC mode" is enabled, under
// which the processor may service some of the 0x800-0x8ff range from the
// virtual-APIC page without exiting, and whether these accesses actually reach
// the hypervisor's handlers was a reading of the interaction rather than an
// observation. A value only the handler could have produced -- the guest's own
// write, read back -- is that observation.
//
// The values written are deliberately not the reset values and not each other,
// so a handler that answered every read from one shared field, or from the reset
// constant it used to return, fails.
bool vcpu_x2apic_register_set_is_readable() {
  BEGIN_TEST;

#ifdef __x86_64__
  auto guest_result = Guest::Create();
  if (guest_result.is_error() && guest_result.status_value() == ZX_ERR_NOT_SUPPORTED) {
    printf("VMX not supported here; skipping x2APIC register-set test.\n");
    return true;
  }
  ASSERT_EQ(ZX_OK, guest_result.status_value(), "Guest::Create failed\n");
  ktl::unique_ptr<Guest> guest = ktl::move(guest_result.value());

  constexpr uint16_t kReportPort = 0x13;  // 4-byte OUT.

  // A tiny emitter, so the program below reads as the sequence it is.
  uint8_t code[1024];
  size_t n = 0;
  auto emit = [&](std::initializer_list<uint8_t> bytes) {
    for (uint8_t b : bytes) {
      code[n++] = b;
    }
  };
  auto emit32 = [&](uint32_t v) {
    emit({static_cast<uint8_t>(v), static_cast<uint8_t>(v >> 8), static_cast<uint8_t>(v >> 16),
          static_cast<uint8_t>(v >> 24)});
  };
  // mov ecx, msr ; mov edx, hi ; mov eax, lo ; wrmsr
  auto wrmsr = [&](uint32_t msr, uint32_t hi, uint32_t lo) {
    emit({0xB9});
    emit32(msr);
    emit({0xBA});
    emit32(hi);
    emit({0xB8});
    emit32(lo);
    emit({0x0F, 0x30});
  };
  // mov eax, poison ; mov edx, poison ; mov ecx, msr ; rdmsr ; out kReportPort, eax
  //
  // The poison is not decoration. Each write above loads EAX with exactly the
  // value the read is then required to produce, so without it an RDMSR handler
  // that merely advanced RIP and touched no register would leave the expected
  // answer sitting in EAX from the write, and every assertion here would pass
  // against a hypervisor that implements none of these registers. With EAX and
  // EDX poisoned first, the value can only have come from the handler.
  constexpr uint32_t kPoison = 0xDEAD'BEEF;
  auto rdmsr_report = [&](uint32_t msr) {
    emit({0xB8});
    emit32(kPoison);
    emit({0xBA});
    emit32(kPoison);
    emit({0xB9});
    emit32(msr);
    emit({0x0F, 0x32, 0xE7, static_cast<uint8_t>(kReportPort)});
  };
  // mov eax, edx ; out kReportPort, eax  -- the top half of a 64-bit register.
  // EDX was poisoned by the rdmsr_report immediately before this, so a handler
  // that leaves EDX alone reports the poison rather than the ICR's destination.
  auto report_edx = [&]() { emit({0x89, 0xD0, 0xE7, static_cast<uint8_t>(kReportPort)}); };

  // The registers, the values, and what the guest must read back. Each entry is
  // a write followed immediately by a read of the same register.
  struct RwCase {
    const char* name;
    uint32_t msr;
    uint32_t written;
    uint32_t expected;
  };
  const RwCase rw[] = {
      // LVT entries. Reset value is 0x10000 (masked) for all of them, and none of
      // these values is that, so "the read returned the reset constant" fails.
      {"LVT_ERROR", 0x837, 0x0000'00F3, 0x0000'00F3},
      {"LVT_LINT0", 0x835, 0x0000'8700, 0x0000'8700},
      {"LVT_LINT1", 0x836, 0x0000'0400, 0x0000'0400},
      {"LVT_CMCI", 0x82f, 0x0000'00F0, 0x0000'00F0},
      {"LVT_THERMAL", 0x833, 0x0000'00E0, 0x0000'00E0},
      {"LVT_MONITOR", 0x834, 0x0000'00D0, 0x0000'00D0},
      // The spurious-vector register: reset 0xff, and bit 8 is the software
      // enable a guest sets during bring-up.
      {"SVR", 0x80f, 0x0000'01FF, 0x0000'01FF},
      // Divide configuration, and the initial count. Both were write-only.
      {"DCR", 0x83e, 0x0000'000B, 0x0000'000B},
  };
  constexpr size_t kRwCount = sizeof(rw) / sizeof(rw[0]);
  for (const RwCase& c : rw) {
    wrmsr(c.msr, 0, c.written);
    rdmsr_report(c.msr);
  }

  // The ICR: a single 64-bit read/write register in x2APIC mode. Delivery mode
  // INIT (5) is chosen deliberately -- it is serviced entirely in the kernel, so
  // this write does not surface a VCPU packet the way a FIXED IPI would, and the
  // test stays a sequence of reports.
  constexpr uint32_t kIcrHi = 0x0000'1234;
  constexpr uint32_t kIcrLo = 0x0000'0500;
  wrmsr(0x830, kIcrHi, kIcrLo);
  rdmsr_report(0x830);
  report_edx();

  // Read-only registers that were absent from the enum entirely. On a guest that
  // has touched neither CR8 nor any interrupt, both must read 0 -- but the
  // discriminating fact is that they read *at all*: before, either one took a
  // #GP into an IDT this guest does not have.
  rdmsr_report(0x80a);  // PPR
  rdmsr_report(0x809);  // APR

  // The timer. Arm a one-shot far enough out that it cannot fire during the
  // test, then read the initial count back (previously write-only) and the
  // current count twice (previously absent).
  constexpr uint32_t kInitialCount = 0x4000'0000;
  wrmsr(0x832, 0, 0x0000'0030);  // LVT_TIMER: vector 0x30, one-shot, unmasked.
  wrmsr(0x838, 0, kInitialCount);
  rdmsr_report(0x838);  // INITIAL_COUNT
  rdmsr_report(0x839);  // CURRENT_COUNT, first read
  rdmsr_report(0x839);  // CURRENT_COUNT, second read
  emit({0xF4});         // hlt
  ASSERT_LT(n, sizeof(code), "guest program overflowed its buffer\n");

  fbl::RefPtr<VmObjectPaged> ram;
  ASSERT_EQ(ZX_OK, VmObjectPaged::Create(PMM_ALLOC_FLAG_ANY, 0u, kGuestRamSize, &ram), "ram\n");
  ASSERT_EQ(ZX_OK, WriteIdentityTables(ram), "tables\n");
  ASSERT_EQ(ZX_OK, ram->Write(code, kCodeGpa, n), "code\n");
  ASSERT_EQ(ZX_OK, ram->CommitRange(0, kGuestRamSize), "commit\n");
  auto mapping = guest->RootVmar()->CreateVmMapping(0, kGuestRamSize, 0, VMAR_FLAG_SPECIFIC, ram, 0,
                                                    kMmuFlags, "guest-ram");
  ASSERT_EQ(ZX_OK, mapping.status_value(), "map\n");
  auto trap = guest->SetTrap(ZX_GUEST_TRAP_IO, kReportPort, 4, nullptr, kReportPort);
  ASSERT_EQ(ZX_OK, trap.status_value(), "trap\n");

  auto vcpu_result = Vcpu::Create(*guest, kCodeGpa);
  ASSERT_EQ(ZX_OK, vcpu_result.status_value(), "Vcpu::Create\n");
  ktl::unique_ptr<Vcpu> vcpu = ktl::move(vcpu_result.value());

  auto next_report = [&](uint32_t* out, const char* what) {
    zx_port_packet_t p = {};
    if (vcpu->Enter(p).is_error()) {
      printf("x2APIC register test: Enter() failed reading %s -- a register that still faults "
             "takes the guest down instead of returning a wrong value\n",
             what);
      return false;
    }
    if (p.type != ZX_PKT_TYPE_GUEST_IO || p.guest_io.port != kReportPort ||
        p.guest_io.access_size != 4) {
      printf("x2APIC register test: reading %s produced exit type %#x port %#x size %u instead of "
             "the report -- the read did not complete in the guest\n",
             what, p.type, p.guest_io.port, p.guest_io.access_size);
      return false;
    }
    memcpy(out, p.guest_io.data, sizeof(*out));
    return true;
  };

  for (size_t i = 0; i < kRwCount; i++) {
    uint32_t value = 0;
    ASSERT_TRUE(next_report(&value, rw[i].name), "read back a written register\n");
    EXPECT_EQ(rw[i].expected, value, rw[i].name);
    printf("x2APIC %s: wrote %#x, guest read back %#x\n", rw[i].name, rw[i].written, value);
  }

  uint32_t icr_lo = 0, icr_hi = 0;
  ASSERT_TRUE(next_report(&icr_lo, "ICR[31:0]"), "ICR low\n");
  ASSERT_TRUE(next_report(&icr_hi, "ICR[63:32]"), "ICR high\n");
  EXPECT_EQ(kIcrLo, icr_lo, "the ICR must read back the command that was written\n");
  EXPECT_EQ(kIcrHi, icr_hi, "including its destination field, which lives in the top half\n");

  uint32_t ppr = 0, apr = 0;
  ASSERT_TRUE(next_report(&ppr, "PPR"), "PPR\n");
  ASSERT_TRUE(next_report(&apr, "APR"), "APR\n");
  EXPECT_EQ(0u, ppr, "a guest that has raised no priority and taken no interrupt reads PPR 0\n");
  EXPECT_EQ(0u, apr, "and APR 0\n");

  uint32_t initial = 0, count1 = 0, count2 = 0;
  ASSERT_TRUE(next_report(&initial, "INITIAL_COUNT"), "INITIAL_COUNT\n");
  ASSERT_TRUE(next_report(&count1, "CURRENT_COUNT #1"), "CURRENT_COUNT #1\n");
  ASSERT_TRUE(next_report(&count2, "CURRENT_COUNT #2"), "CURRENT_COUNT #2\n");
  EXPECT_EQ(kInitialCount, initial, "the initial count must read back what was written\n");
  // The current count is the one value here that is not a stored constant, so it
  // gets the assertions that a stored constant would fail: it must be inside the
  // armed interval, must have moved off the initial count (each read is separated
  // from the arming write by at least one VM exit, which is microseconds against
  // an interval of hundreds of milliseconds), and must be counting *down*.
  EXPECT_GT(count1, 0u, "the armed timer's current count must not be 0\n");
  EXPECT_LT(count1, kInitialCount,
            "and must have advanced past the initial count -- a handler that answered this read "
            "with the initial count would be indistinguishable from a stopped timer\n");
  EXPECT_LE(count2, count1, "the current count must count down, not up\n");
  printf("x2APIC timer: initial %#x, current count read %#x then %#x (down by %u)\n", initial,
         count1, count2, count1 - count2);

  printf("x2APIC register set OK: %zu read/write registers round-tripped through the guest's own "
         "wrmsr/rdmsr, the 64-bit ICR read back as %#x:%#x, and PPR/APR/CURRENT_COUNT -- all three "
         "absent from the register enum before, so a read of any of them took a #GP -- answered "
         "the guest instead of faulting it\n",
         kRwCount, icr_hi, icr_lo);
#else
  printf("Not x86_64; skipping.\n");
#endif  // __x86_64__

  END_TEST;
}

bool vcpu_xapic_reset_mmio_and_x2apic_transition() {
  BEGIN_TEST;

#ifdef __x86_64__
  auto guest_result = Guest::Create();
  if (guest_result.is_error() && guest_result.status_value() == ZX_ERR_NOT_SUPPORTED) {
    printf("VMX not supported here; skipping xAPIC interface test.\n");
    return true;
  }
  ASSERT_EQ(ZX_OK, guest_result.status_value(), "Guest::Create\n");
  ktl::unique_ptr<Guest> guest = ktl::move(guest_result.value());

  constexpr uint16_t kReportPort = 0x14;
  uint8_t code[256];
  size_t n = 0;
  auto emit = [&](std::initializer_list<uint8_t> bytes) {
    for (uint8_t byte : bytes) {
      code[n++] = byte;
    }
  };
  auto emit32 = [&](uint32_t value) {
    emit({static_cast<uint8_t>(value), static_cast<uint8_t>(value >> 8),
          static_cast<uint8_t>(value >> 16), static_cast<uint8_t>(value >> 24)});
  };
  auto emit64 = [&](uint64_t value) {
    emit32(static_cast<uint32_t>(value));
    emit32(static_cast<uint32_t>(value >> 32));
  };
  auto report_eax = [&]() { emit({0xE7, static_cast<uint8_t>(kReportPort)}); };
  auto rdmsr_report = [&](uint32_t msr) {
    emit({0xB9});
    emit32(msr);
    emit({0x0F, 0x32});
    report_eax();
  };
  auto mmio_read_report = [&](uint64_t address) {
    emit({0xA1});  // mov eax, moffs64
    emit64(address);
    report_eax();
  };

  rdmsr_report(X86_MSR_IA32_APIC_BASE);
  mmio_read_report(APIC_PHYS_BASE + 0x20);  // xAPIC ID
  mmio_read_report(APIC_PHYS_BASE + 0x30);  // version

  // mov eax, 0x1ff ; mov moffs64, eax ; read it back.
  emit({0xB8});
  emit32(0x1ff);
  emit({0xA3});
  emit64(APIC_PHYS_BASE + 0x0f0);
  mmio_read_report(APIC_PHYS_BASE + 0x0f0);

  // Enter x2APIC mode through the architectural IA32_APIC_BASE transition.
  emit({0xB9});
  emit32(X86_MSR_IA32_APIC_BASE);
  emit({0x31, 0xD2, 0xB8});
  emit32(APIC_PHYS_BASE | IA32_APIC_BASE_XAPIC_ENABLE | IA32_APIC_BASE_X2APIC_ENABLE);
  emit({0x0F, 0x30});
  rdmsr_report(X86_MSR_IA32_APIC_BASE);
  rdmsr_report(X86_MSR_IA32_X2APIC_APICID);
  emit({0xF4});

  fbl::RefPtr<VmObjectPaged> ram;
  ASSERT_EQ(ZX_OK, VmObjectPaged::Create(PMM_ALLOC_FLAG_ANY, 0u, kGuestRamSize, &ram), "ram\n");
  ASSERT_EQ(ZX_OK, WriteIdentityTables(ram), "tables\n");
  ASSERT_EQ(ZX_OK, ram->Write(code, kCodeGpa, n), "code\n");
  ASSERT_EQ(ZX_OK, ram->CommitRange(0, kGuestRamSize), "commit\n");
  auto mapping = guest->RootVmar()->CreateVmMapping(0, kGuestRamSize, 0, VMAR_FLAG_SPECIFIC, ram, 0,
                                                    kMmuFlags, "guest-ram");
  ASSERT_EQ(ZX_OK, mapping.status_value(), "map\n");
  ASSERT_EQ(ZX_OK,
            guest->SetTrap(ZX_GUEST_TRAP_IO, kReportPort, 4, nullptr, kReportPort).status_value(),
            "trap\n");
  // A chipset commonly installs one trap over the complete high-MMIO window.
  // It includes FEE00000, but an xAPIC VCPU must remap that one page for VMX's
  // APIC-access virtualization instead of routing LAPIC accesses to userspace.
  ASSERT_EQ(ZX_OK,
            guest->SetTrap(ZX_GUEST_TRAP_MEM, 0xf800'0000, 0x0800'0000, nullptr, 0)
                .status_value(),
            "broad high-MMIO trap\n");

  auto vcpu_result = Vcpu::Create(*guest, kCodeGpa, ZX_VCPU_CREATE_XAPIC);
  if (vcpu_result.is_error() && vcpu_result.status_value() == ZX_ERR_NOT_SUPPORTED) {
    printf("VMX APIC-register virtualization not supported here; skipping xAPIC test.\n");
    return true;
  }
  ASSERT_EQ(ZX_OK, vcpu_result.status_value(), "Vcpu::Create xAPIC\n");
  ktl::unique_ptr<Vcpu> vcpu = ktl::move(vcpu_result.value());

  zx_status_t access_status = ZX_OK;
  auto access = [&](uint32_t action, uint32_t offset,
                    uint32_t value = 0) -> zx_vcpu_xapic_access_t {
    if (access_status != ZX_OK) {
      return {};
    }
    zx_vcpu_xapic_access_t request = {
        .magic = ZX_VCPU_XAPIC_ACCESS_MAGIC,
        .version = ZX_VCPU_XAPIC_ACCESS_VERSION,
        .size = sizeof(zx_vcpu_xapic_access_t),
        .action = action,
        .offset = offset,
        .value = value,
    };
    access_status = vcpu->WriteXapicAccess(request).status_value();
    if (access_status != ZX_OK) {
      return {};
    }
    zx_vcpu_xapic_access_t result = {};
    access_status = vcpu->ReadXapicAccess(result).status_value();
    return result;
  };

  // The state-topic path is the software fallback on a nested host without
  // APIC-register virtualization, and remains the same canonical register
  // access on a host that can accelerate the MMIO instruction itself.
  zx_vcpu_xapic_access_t id = access(ZX_VCPU_XAPIC_ACTION_READ, 0x020);
  EXPECT_EQ(ZX_VCPU_XAPIC_RESULT_VALUE_VALID, id.result_flags, "ID read value valid\n");
  EXPECT_EQ(0u, id.value, "BSP xAPIC ID through state topic\n");
  zx_vcpu_xapic_access_t version = access(ZX_VCPU_XAPIC_ACTION_READ, 0x030);
  EXPECT_EQ(0x15u | (0x6u << 16), version.value, "xAPIC version through state topic\n");
  zx_vcpu_xapic_access_t write_svr =
      access(ZX_VCPU_XAPIC_ACTION_WRITE, 0x0f0, 0x1ff);
  EXPECT_EQ(ZX_VCPU_XAPIC_RESULT_NONE, write_svr.result_kind, "SVR has no host side effect\n");
  EXPECT_EQ(0x1ffu, access(ZX_VCPU_XAPIC_ACTION_READ, 0x0f0).value,
            "SVR state-topic write/read\n");
  zx_vcpu_xapic_access_t empty_eoi =
      access(ZX_VCPU_XAPIC_ACTION_WRITE, 0x0b0, 0);
  EXPECT_EQ(ZX_VCPU_XAPIC_RESULT_NONE, empty_eoi.result_kind,
            "EOI with no in-service vector has no side effect\n");

  // xAPIC's split ICR stages the destination in the high register and sends on
  // the low write. The result uses the same mask/vector and startup id/entry as
  // ZX_PKT_TYPE_GUEST_VCPU.
  constexpr uint32_t kIpiDestination = 2;
  constexpr uint32_t kIpiVector = 0x51;
  access(ZX_VCPU_XAPIC_ACTION_WRITE, 0x310, kIpiDestination << 24);
  zx_vcpu_xapic_access_t ipi = access(ZX_VCPU_XAPIC_ACTION_WRITE, 0x300, kIpiVector);
  EXPECT_EQ(ZX_VCPU_XAPIC_RESULT_INTERRUPT, ipi.result_kind, "fixed IPI result\n");
  EXPECT_EQ(uint64_t{1} << kIpiDestination, ipi.target, "physical IPI target mask\n");
  EXPECT_EQ(kIpiVector, ipi.vector, "fixed IPI vector\n");

  constexpr uint32_t kStartupDestination = 3;
  constexpr uint32_t kStartupVector = 8;
  access(ZX_VCPU_XAPIC_ACTION_WRITE, 0x310, kStartupDestination << 24);
  zx_vcpu_xapic_access_t startup =
      access(ZX_VCPU_XAPIC_ACTION_WRITE, 0x300,
             (static_cast<uint32_t>(InterruptDeliveryMode::STARTUP) << 8) | kStartupVector);
  EXPECT_EQ(ZX_VCPU_XAPIC_RESULT_STARTUP, startup.result_kind, "STARTUP result\n");
  EXPECT_EQ(kStartupDestination, startup.target, "STARTUP APIC ID\n");
  EXPECT_EQ(static_cast<uint64_t>(kStartupVector) << 12, startup.entry, "STARTUP entry\n");

  access(ZX_VCPU_XAPIC_ACTION_WRITE, 0x310, kIpiDestination << 24);
  zx_vcpu_xapic_access_t init =
      access(ZX_VCPU_XAPIC_ACTION_WRITE, 0x300,
             static_cast<uint32_t>(InterruptDeliveryMode::INIT) << 8);
  EXPECT_EQ(ZX_VCPU_XAPIC_RESULT_NONE, init.result_kind, "INIT is absorbed\n");
  EXPECT_EQ(ZX_OK, access_status, "submit and read xAPIC state-topic accesses\n");

  zx_vcpu_xapic_access_t malformed = {
      .magic = ZX_VCPU_XAPIC_ACCESS_MAGIC,
      .version = ZX_VCPU_XAPIC_ACCESS_VERSION,
      .size = sizeof(zx_vcpu_xapic_access_t),
      .action = ZX_VCPU_XAPIC_ACTION_READ,
      .offset = 0x024,
  };
  EXPECT_EQ(ZX_ERR_INVALID_ARGS, vcpu->WriteXapicAccess(malformed).status_value(),
            "misaligned xAPIC register offset\n");

  constexpr uint32_t kVmxProcbasedCtls2Msr = 0x48b;
  constexpr uint32_t kApicAccelerationControls = (1u << 0) | (1u << 8);
  const uint32_t offered =
      static_cast<uint32_t>(read_msr(kVmxProcbasedCtls2Msr) >> 32);
  const bool accelerated =
      (offered & kApicAccelerationControls) == kApicAccelerationControls;
  EXPECT_EQ(accelerated, guest->PhysicalAspace().IsMapped(APIC_PHYS_BASE),
            "FEE00000 is mapped only for the VMX-accelerated xAPIC path\n");
  if (!accelerated) {
    printf("xAPIC software fallback OK: register reads/writes and fixed/INIT/STARTUP IPI side "
           "effects completed through topic 5 while the broad FEE00000 MMIO trap remained "
           "unmapped for userspace decoding.\n");
    return true;
  }

  uint32_t reports[6] = {};
  for (uint32_t& report : reports) {
    zx_port_packet_t packet = {};
    ASSERT_EQ(ZX_OK, vcpu->Enter(packet).status_value(), "report exit\n");
    ASSERT_EQ(static_cast<uint32_t>(ZX_PKT_TYPE_GUEST_IO), packet.type, "report type\n");
    ASSERT_EQ(kReportPort, packet.guest_io.port, "report port\n");
    memcpy(&report, packet.guest_io.data, sizeof(report));
  }

  EXPECT_EQ(APIC_PHYS_BASE | IA32_APIC_BASE_XAPIC_ENABLE | IA32_APIC_BASE_BSP, reports[0],
            "xAPIC reset mode\n");
  EXPECT_EQ(0u, reports[1], "BSP xAPIC ID\n");
  EXPECT_EQ(0x15u | (0x6u << 16), reports[2], "xAPIC version\n");
  EXPECT_EQ(0x1ffu, reports[3], "SVR MMIO write/read\n");
  EXPECT_EQ(APIC_PHYS_BASE | IA32_APIC_BASE_XAPIC_ENABLE | IA32_APIC_BASE_X2APIC_ENABLE |
                IA32_APIC_BASE_BSP,
            reports[4], "x2APIC transition\n");
  EXPECT_EQ(0u, reports[5], "x2APIC ID after transition\n");
#else
  printf("Not x86_64; skipping.\n");
#endif

  END_TEST;
}

// A restored VCPU comes back with the task priority it was captured at, and not
// with whatever the live virtual-APIC page happens to hold.
//
// VTPR was absent from the snapshot ABI. Neither VcpuArchState nor
// VcpuAsyncState carried it and neither Save/Restore pair touched it, so a
// restore left the guest's task priority at whatever was in the page -- 0 on a
// fresh VCPU. On x64 Windows CR8 *is* IRQL, so a guest snapshotted at IRQL 8 and
// restored came back at IRQL 0 and would take an ISR inside exactly the region
// the raise exists to exclude. This is a snapshot-centric hypervisor: every
// restore was affected, not only a guest that reads CR8 back.
//
// The decisive assertion is the last one, and it is deliberately not made
// through the same page the restore writes. `Vcpu::TaskPriority()` reads the
// virtual-APIC page, which is where `guest_tpr_write` puts the restored value --
// asserting on it alone would only prove that a store happened. So the guest
// itself executes `mov rax, cr8` after the restore and reports the result out an
// I/O port: the value comes back through the processor's own CR8 read, against
// the page named by the VCPU's own VMCS.
//
// The clobber in the middle is what makes the last assertion mean anything. If
// restore ignored `tpr` (the behaviour being fixed), the clobber would not land
// either, the page would still hold the original value, and the guest would read
// it back -- passing for the wrong reason. Hence the explicit check that the
// clobber took effect, and that a fresh capture *sees* the clobbered value: that
// pair fails for a no-op restore and for a save that returns a constant.
bool vcpu_vtpr_survives_snapshot_restore() {
  BEGIN_TEST;

#ifdef __x86_64__
  // Priority class 0x0B, i.e. VTPR 0xB0. Nonzero in bits 7:4 so it cannot be
  // confused with the zero a fresh page holds, and not 0x0F so a value that got
  // saturated somewhere would show.
  constexpr uint8_t kTaskPriority = 0x0B;
  constexpr uint32_t kVtpr = static_cast<uint32_t>(kTaskPriority) << 4;

  // 48 C7 C0 0B 00 00 00  mov rax, 0x0B
  // 44 0F 22 C0           mov cr8, rax     ; VTPR = 0xB0
  // B0 5A                 mov al, 0x5A
  // E6 10                 out 0x10, al     ; exit A -- the host snapshots here
  // 48 31 C0              xor rax, rax     ; so the read below cannot pass on a stale rax
  // 44 0F 20 C0           mov rax, cr8     ; the guest reads its OWN task priority
  // E6 11                 out 0x11, al     ; exit B -- must report 0x0B
  // F4                    hlt
  const uint8_t code[] = {0x48, 0xC7, 0xC0, kTaskPriority, 0x00, 0x00, 0x00, 0x44, 0x0F,
                          0x22, 0xC0, 0xB0, 0x5A, 0xE6, 0x10, 0x48, 0x31, 0xC0,
                          0x44, 0x0F, 0x20, 0xC0, 0xE6, 0x11, 0xF4};

  fbl::RefPtr<VmObjectPaged> ram;
  ASSERT_EQ(ZX_OK, VmObjectPaged::Create(PMM_ALLOC_FLAG_ANY, 0u, kGuestRamSize, &ram), "ram\n");
  ASSERT_EQ(ZX_OK, WriteIdentityTables(ram), "tables\n");
  ASSERT_EQ(ZX_OK, ram->Write(code, kCodeGpa, sizeof(code)), "code\n");
  ASSERT_EQ(ZX_OK, ram->CommitRange(0, kGuestRamSize), "commit\n");

  auto lg = CreateLiveGuest(ram, kCodeGpa);
  if (lg.is_error() && lg.status_value() == ZX_ERR_NOT_SUPPORTED) {
    printf("VMX not supported here; skipping VTPR snapshot test.\n");
    return true;
  }
  ASSERT_EQ(ZX_OK, lg.status_value(), "create live guest\n");
  Vcpu* vcpu = lg->vcpu.get();

  // The guest raises its task priority and stops.
  zx_port_packet_t a = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(a).status_value(), "enter to A\n");
  ASSERT_EQ(0x10u, a.guest_io.port, "expected the pre-snapshot exit on 0x10\n");
  EXPECT_EQ(0x5Au, static_cast<uint32_t>(a.guest_io.data[0]), "exit A value\n");
  ASSERT_EQ(kVtpr, vcpu->TaskPriority(), "the guest's `mov cr8` must have reached VTPR\n");

  // Every VcpuArchState here is on the heap, and that is not style.
  //
  // It is ~1.4 KiB -- it carries a 1 KiB XSAVE image -- and a kernel machine
  // stack is 16 KiB. The four this test needs are 5.6 KiB of one frame, on top
  // of whatever the harness above it is using. An earlier draft held six as
  // locals and overflowed the stack, which does not announce itself as a failed
  // assertion: it corrupts the Thread structure, so the panic that follows
  // prints "<linebuffer corruption>" instead of its own message and the run dies
  // several tests away from the cause. Worth the four lines.
  fbl::AllocChecker ac;
  ktl::unique_ptr<VcpuArchState[]> states(new (&ac) VcpuArchState[4]);
  ASSERT_TRUE(ac.check(), "alloc arch states\n");
  memset(states.get(), 0, 4 * sizeof(VcpuArchState));
  VcpuArchState& s1 = states[0];       // the capture
  VcpuArchState& s2 = states[1];       // the same, round-tripped through the wire format
  VcpuArchState& scratch = states[2];  // clobbered / hostile variants
  VcpuArchState& s3 = states[3];       // a re-capture after the clobber

  // Capture. The task priority must be *in* the capture -- this is the field
  // that was missing.
  ASSERT_EQ(ZX_OK, vcpu->SaveArchState(s1).status_value(), "SaveArchState\n");
  EXPECT_EQ(kVtpr, s1.tpr, "the snapshot must carry the guest's task priority\n");

  // And it must survive the wire format, which is what actually goes to disk.
  const size_t buf_len = SerializedVcpuStateSize();
  ktl::unique_ptr<uint8_t[]> buffer(new (&ac) uint8_t[buf_len]);
  ASSERT_TRUE(ac.check(), "alloc serialization buffer\n");
  ASSERT_EQ(ZX_OK, SerializeVcpuState(s1, buffer.get(), buf_len).status_value(), "serialize\n");
  ASSERT_EQ(ZX_OK, DeserializeVcpuState(s2, buffer.get(), buf_len).status_value(), "deserialize\n");
  EXPECT_EQ(kVtpr, s2.tpr, "the serialized blob must carry the task priority\n");

  // A blob from before this field existed is refused rather than applied. That
  // is the point of the version bump: a v3 blob has no task priority in it at
  // all, so applying one would leave the live VTPR untouched -- silently
  // reintroducing exactly this bug from an old snapshot.
  {
    ktl::unique_ptr<uint8_t[]> old_blob(new (&ac) uint8_t[buf_len]);
    ASSERT_TRUE(ac.check(), "alloc old blob\n");
    memcpy(old_blob.get(), buffer.get(), buf_len);
    const uint32_t previous_version = 3;
    memcpy(old_blob.get() + sizeof(uint32_t), &previous_version, sizeof(previous_version));
    EXPECT_EQ(ZX_ERR_INVALID_ARGS,
              DeserializeVcpuState(scratch, old_blob.get(), buf_len).status_value(),
              "a pre-VTPR (v3) snapshot must be refused, not applied with no task priority\n");
  }

  // Clobber the live task priority, exactly as restoring into a fresh VCPU
  // would: a VCPU that never ran this guest has VTPR 0.
  scratch = s2;
  scratch.tpr = 0;
  ASSERT_EQ(ZX_OK, vcpu->RestoreArchState(scratch).status_value(), "restore the clobbered state\n");
  ASSERT_EQ(0u, vcpu->TaskPriority(),
            "the clobber must actually land -- if restore ignores `tpr` then nothing below "
            "discriminates anything, because the original value would never have been disturbed\n");
  // ...and a fresh capture must see the clobbered value, not a remembered one.
  ASSERT_EQ(ZX_OK, vcpu->SaveArchState(s3).status_value(), "re-capture after the clobber\n");
  EXPECT_EQ(0u, s3.tpr,
            "the capture must read the live virtual-APIC page, so a save that returns a constant "
            "fails here\n");

  // A task priority with reserved bits set is refused outright, and the refusal
  // leaves the VCPU untouched. VTPR is 8 bits; bits 31:8 of the field are
  // reserved, and the processor -- not this kernel -- reads it at VM entry.
  {
    scratch = s2;
    scratch.tpr = 0x100;
    EXPECT_EQ(ZX_ERR_INVALID_ARGS, vcpu->RestoreArchState(scratch).status_value(),
              "a VTPR with reserved bits set must be refused, not masked\n");
    EXPECT_EQ(0u, vcpu->TaskPriority(),
              "a refused restore must leave the VCPU exactly as it was\n");
  }

  // All eight bits, not just the priority class.
  //
  // `MOV to CR8` writes bits 7:4 and zeroes bits 3:0, so every value this test
  // produces through the guest has a zero sub-class -- which means a restore
  // that carried only `tpr & 0xf0` would satisfy every other assertion here.
  // The x2APIC TPR MSR (0x808) can set the sub-class, and the kernel routes it
  // to the same VTPR, so the field has to survive in full. Driven through the
  // restore path directly because the sub-class has no `MOV to CR8` spelling.
  {
    constexpr uint32_t kSubClassTpr = 0xB7;
    scratch = s2;
    scratch.tpr = kSubClassTpr;
    ASSERT_EQ(ZX_OK, vcpu->RestoreArchState(scratch).status_value(), "restore a sub-class TPR\n");
    EXPECT_EQ(kSubClassTpr, vcpu->TaskPriority(),
              "the whole 8-bit VTPR must survive, sub-class included -- a save/restore that "
              "carried only bits 7:4 would pass every other assertion in this test\n");
    ASSERT_EQ(ZX_OK, vcpu->SaveArchState(s3).status_value(), "re-capture the sub-class TPR\n");
    EXPECT_EQ(kSubClassTpr, s3.tpr, "and the capture must read all eight bits back\n");
  }

  // Restore the real capture.
  ASSERT_EQ(ZX_OK, vcpu->RestoreArchState(s2).status_value(), "RestoreArchState\n");
  EXPECT_EQ(kVtpr, vcpu->TaskPriority(), "restore must put the captured task priority back\n");

  // The decisive assertion: the guest reads CR8 itself and gets its own value.
  zx_port_packet_t b = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(b).status_value(), "enter to B\n");
  ASSERT_EQ(static_cast<uint8_t>(ZX_PKT_TYPE_GUEST_IO), static_cast<uint8_t>(b.type), "io\n");
  ASSERT_EQ(0x11u, b.guest_io.port, "expected the post-restore exit on 0x11\n");
  EXPECT_EQ(static_cast<uint32_t>(kTaskPriority), static_cast<uint32_t>(b.guest_io.data[0]),
            "after the restore the guest's own `mov rax, cr8` must read back the task priority it "
            "set before the snapshot -- 0 here is a guest resuming at IRQL 0 inside a region it "
            "raised IRQL to protect\n");

  printf("VTPR snapshot OK: guest set CR8 class %#x (VTPR %#x); the capture carried it through a "
         "%zu-byte blob; a v3 blob was refused; clobbering the live value to 0 and restoring "
         "brought it back, and the guest read %#x out of CR8 itself\n",
         kTaskPriority, kVtpr, buf_len, static_cast<uint32_t>(b.guest_io.data[0]));
#else
  printf("Not x86_64; skipping.\n");
#endif  // __x86_64__

  END_TEST;
}

// An unhandled guest RDMSR/WRMSR announces itself, in enough detail to act on.
//
// An MSR this hypervisor does not implement is answered with an injected #GP,
// and a guest that did not expect one almost never dies at the faulting
// instruction: it dies later, somewhere unrelated. Two fatal gaps of exactly
// this shape have already been found in this tree the expensive way -- by
// crashing into them and reconstructing the cause afterwards -- RDMSR 0x10
// (IA32_TSC) and WRMSR 0x1a0 (IA32_MISC_ENABLE), each of which took a whole
// Windows boot down.
//
// So the record has to carry the three things that turn a crash into a fix:
// *which* register, at *which* guest RIP, and in which direction (plus, for a
// write, the value the guest wanted). The RIP assertion is exact -- the address
// of the faulting instruction, not the one after it -- because "we logged
// something" is the failure mode here: an announcement with no location is what
// the previous `Unhandled guest RDMSR %#lx` line already was.
//
// The fault itself is proved independently of the record. The guest's own #GP
// handler runs and reports on a port; that is what makes `last_gp_injected`
// meaningful rather than a flag the code sets about itself.
//
// Both registers are ones nothing implements and nothing ever should. The read
// used to be IA32_FEATURE_CONTROL (0x3A) "because it is the next candidate on
// a likely future implementation target -- and implementing it would make this case
// silently stop testing an unhandled read at all. A register chosen because we
// are about to support it is the wrong choice for a gate that asserts we do not.
bool vcpu_unhandled_msr_announces_itself() {
  BEGIN_TEST;

#ifdef __x86_64__
  constexpr uint32_t kReadMsr = 0x1233;   // implemented by nobody
  constexpr uint32_t kWriteMsr = 0x1234;  // likewise
  constexpr uint64_t kWriteValue = 0x00009ABC00005678ull;
  // Offsets of the faulting instructions within their code blocks.
  constexpr uint64_t kRdmsrOffset = 5;   // after `mov ecx, imm32`
  constexpr uint64_t kWrmsrOffset = 15;  // after three `mov r32, imm32`

  // Phase 1, at kCodeGpa:
  //   B9 33 12 00 00  mov ecx, 0x1233
  //   0F 32           rdmsr           ; unimplemented -> #GP -> handler
  //   B0 77           mov al, 0x77
  //   E6 11           out 0x11, al    ; only reached if no #GP was delivered
  //   F4              hlt
  const uint8_t phase1[] = {0xB9, 0x33, 0x12, 0x00, 0x00, 0x0F, 0x32,
                            0xB0, 0x77, 0xE6, 0x11, 0xF4};
  // Phase 2, at kCode2Gpa:
  //   B9 34 12 00 00  mov ecx, 0x1234
  //   B8 78 56 00 00  mov eax, 0x5678
  //   BA BC 9A 00 00  mov edx, 0x9ABC
  //   0F 30           wrmsr           ; unimplemented -> #GP -> handler
  //   B0 77           mov al, 0x77
  //   E6 11           out 0x11, al    ; only reached if no #GP was delivered
  //   F4              hlt
  const uint8_t phase2[] = {0xB9, 0x34, 0x12, 0x00, 0x00, 0xB8, 0x78, 0x56, 0x00,
                            0x00, 0xBA, 0xBC, 0x9A, 0x00, 0x00, 0x0F, 0x30,
                            0xB0, 0x77, 0xE6, 0x11, 0xF4};
  // #GP handler: announce and stop. It does not return, so each phase is driven
  // by its own Enter() and repositioned by the host in between.
  //   B0 6D  mov al, 0x6D
  //   E6 30  out 0x30, al
  //   F4     hlt
  const uint8_t handler[] = {0xB0, 0x6D, 0xE6, 0x30, 0xF4};

  fbl::RefPtr<VmObjectPaged> ram;
  ASSERT_EQ(ZX_OK, VmObjectPaged::Create(PMM_ALLOC_FLAG_ANY, 0u, kGuestRamSize, &ram), "ram\n");
  ASSERT_EQ(ZX_OK, WriteIdentityTables(ram), "tables\n");
  ASSERT_EQ(ZX_OK, ram->Write(phase1, kCodeGpa, sizeof(phase1)), "phase 1\n");
  ASSERT_EQ(ZX_OK, ram->Write(phase2, kCode2Gpa, sizeof(phase2)), "phase 2\n");
  ASSERT_EQ(ZX_OK, ram->Write(handler, kEvtHandlerGpa, sizeof(handler)), "handler\n");

  // GDT[1] = flat 64-bit code segment (selector 0x08), and a #GP gate.
  const uint8_t gdt_code[8] = {0xFF, 0xFF, 0x00, 0x00, 0x00, 0x9B, 0xAF, 0x00};
  ASSERT_EQ(ZX_OK, ram->Write(gdt_code, kEvtGdtGpa + 8, sizeof(gdt_code)), "GDT\n");
  uint8_t gate[16];
  WriteIdtGate(gate, kEvtHandlerGpa);
  ASSERT_EQ(ZX_OK, ram->Write(gate, kEvtIdtGpa + X86_INT_GP_FAULT * 16, sizeof(gate)), "IDT\n");
  ASSERT_EQ(ZX_OK, ram->CommitRange(0, kGuestRamSize), "commit\n");

  auto lg = CreateLiveGuest(ram, kCodeGpa);
  if (lg.is_error() && lg.status_value() == ZX_ERR_NOT_SUPPORTED) {
    printf("VMX not supported here; skipping unhandled-MSR test.\n");
    return true;
  }
  ASSERT_EQ(ZX_OK, lg.status_value(), "create live guest\n");
  Vcpu* vcpu = lg->vcpu.get();
  ASSERT_EQ(ZX_OK, lg->guest->SetTrap(ZX_GUEST_TRAP_IO, 0x30, 1, nullptr, 0x30).status_value(),
            "trap 0x30\n");

  // On the heap: see the note in vcpu_vtpr_survives_snapshot_restore. Each of
  // these is ~1.4 KiB and the kernel stack is 16 KiB.
  fbl::AllocChecker ac;
  ktl::unique_ptr<VcpuArchState> s(new (&ac) VcpuArchState{});
  ASSERT_TRUE(ac.check(), "alloc arch state\n");
  ASSERT_EQ(ZX_OK, vcpu->SaveArchState(*s).status_value(), "SaveArchState\n");
  s->gdtr_base = kEvtGdtGpa;
  s->gdtr_limit = 0x0F;
  s->idtr_base = kEvtIdtGpa;
  s->idtr_limit = 0xFFF;
  s->regs.rsp = kEvtStackTop;
  ASSERT_EQ(ZX_OK, vcpu->RestoreArchState(*s).status_value(), "load GDTR/IDTR/RSP\n");

  // Nothing has been seen yet, so the counts below are this guest's alone.
  ASSERT_EQ(0u, vcpu->UnhandledMsrs().total, "a fresh VCPU has seen no unhandled MSR\n");

  // Phase 1: the unimplemented read.
  zx_port_packet_t p1 = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(p1).status_value(), "enter phase 1\n");
  ASSERT_EQ(static_cast<uint8_t>(ZX_PKT_TYPE_GUEST_IO), static_cast<uint8_t>(p1.type), "io\n");
  ASSERT_EQ(0x30u, p1.guest_io.port,
            "the guest's own #GP handler must have run (0x11 here means the unimplemented RDMSR "
            "did not fault the guest at all)\n");
  EXPECT_EQ(0x6Du, static_cast<uint32_t>(p1.guest_io.data[0]), "handler value\n");

  {
    const UnhandledMsrLog& log = vcpu->UnhandledMsrs();
    EXPECT_EQ(1u, log.total, "exactly one unhandled access so far\n");
    EXPECT_EQ(kReadMsr, log.last_msr, "the record must name the register\n");
    EXPECT_EQ(kCodeGpa + kRdmsrOffset, log.last_rip,
              "the record must carry the guest RIP of the faulting instruction itself -- a "
              "record with no location is the diagnostic that already existed\n");
    EXPECT_FALSE(log.last_is_write, "a RDMSR must be recorded as a read\n");
    EXPECT_TRUE(log.last_gp_injected,
                "the #GP must be recorded as injected, and the handler above ran, so this is "
                "not the code merely asserting about itself\n");
    EXPECT_EQ(1u, log.tracked, "one distinct register tracked\n");
    EXPECT_EQ(kReadMsr, log.entries[0].msr, "tracked register\n");
    EXPECT_EQ(1u, log.entries[0].count, "first occurrence\n");
  }

  // Phase 2: the unimplemented write. The handler does not return, so the host
  // repositions the guest -- which is what a VMM does anyway.
  ASSERT_EQ(ZX_OK, vcpu->SaveArchState(*s).status_value(), "capture between phases\n");
  s->rip = kCode2Gpa;
  ASSERT_EQ(ZX_OK, vcpu->RestoreArchState(*s).status_value(), "reposition to phase 2\n");

  zx_port_packet_t p2 = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(p2).status_value(), "enter phase 2\n");
  ASSERT_EQ(static_cast<uint8_t>(ZX_PKT_TYPE_GUEST_IO), static_cast<uint8_t>(p2.type), "io\n");
  ASSERT_EQ(0x30u, p2.guest_io.port,
            "the guest's own #GP handler must have run for the unimplemented WRMSR too\n");

  {
    const UnhandledMsrLog& log = vcpu->UnhandledMsrs();
    EXPECT_EQ(2u, log.total, "two unhandled accesses now\n");
    EXPECT_EQ(kWriteMsr, log.last_msr, "the record must name the written register\n");
    EXPECT_EQ(kCode2Gpa + kWrmsrOffset, log.last_rip,
              "the WRMSR's own guest RIP\n");
    EXPECT_TRUE(log.last_is_write, "a WRMSR must be recorded as a write\n");
    EXPECT_EQ(kWriteValue, log.last_value,
              "the value the guest tried to write (edx:eax) must be recorded -- without it a "
              "write gap cannot be told from a read gap at the same register\n");
    EXPECT_TRUE(log.last_gp_injected, "the #GP must be recorded as injected\n");
    EXPECT_EQ(2u, log.tracked, "two distinct registers tracked, counted separately\n");
    EXPECT_EQ(kWriteMsr, log.entries[1].msr, "second tracked register\n");
    EXPECT_EQ(1u, log.entries[1].count,
              "each register keeps its own count, so one register being hammered cannot rate-"
              "limit the first sighting of another\n");
  }

  printf("unhandled-MSR announcement OK: RDMSR %#x at RIP %#lx and WRMSR %#x = %#lx at RIP %#lx "
         "were each recorded with their own guest RIP and direction, each injected a #GP the "
         "guest's own handler ran, and the two registers are counted separately\n",
         kReadMsr, kCodeGpa + kRdmsrOffset, kWriteMsr, kWriteValue, kCode2Gpa + kWrmsrOffset);
#else
  printf("Not x86_64; skipping.\n");
#endif  // __x86_64__

  END_TEST;
}

// The MSRs a working Windows boot is documented to touch are all answered,
// and the gate is that the guest completes with ZERO unhandled-MSR
// announcements.
//
// WHY "ZERO ANNOUNCEMENTS" IS NOT VACUOUS. An absence proves nothing on its own:
// a guest that never executed the instructions, or that died early, also
// announces nothing. Three things close that:
//   * every read is asserted against its expected VALUE, and each read is
//     preceded by poisoning eax/edx, so the value reported can only have come
//     from the hypervisor's handler;
//   * the guest must reach its own end marker, so it demonstrably executed the
//     whole list;
//   * PHASE 2 is a positive control on the fault path itself. It writes a locked
//     IA32_FEATURE_CONTROL, which is architecturally #GP, and requires the
//     guest's own #GP handler to run. That proves faults CAN still be generated
//     and observed here -- so "zero announcements" in phase 1 is a measurement
//     rather than a broken instrument. It also requires that fault NOT to be
//     announced: a register we know about and deliberately fault is a different
//     thing from one we have never heard of, and the gate depends on the two
//     staying distinct.
//
// A missing register in phase 1 therefore shows up three independent ways: the
// guest lands in the #GP handler and exits on the fault port instead of the
// expected wide report (the next_report diagnostic names which register it was
// about to read), the announcement log becomes non-empty, and the log names the
// register and the guest RIP.
//
// Red control: delete one `case` label from handle_rdmsr and rebuild.
bool vcpu_msr_coverage_leaves_nothing_unhandled() {
  BEGIN_TEST;

#ifdef __x86_64__
  constexpr uint32_t kPoison = 0xDEAD'BEEF;
  constexpr uint8_t kWidePort = 0x13;
  constexpr uint8_t kDonePort = 0x30;
  constexpr uint8_t kDoneByte = 0x5A;
  // The guest's #GP handler reports here and halts -- the established idiom in
  // this file. An earlier draft used a handler that dropped the error code,
  // advanced the saved RIP past the two-byte faulting instruction and `iret`ed,
  // so one run could name every gap at once; it drove the guest to a triple
  // fault at RIP == kStackTop (i.e. `iret` consumed the wrong stack slot) and is
  // not worth the fragility here. See the report note on `iret` from an injected
  // exception frame, which no case in this suite currently covers.
  constexpr uint8_t kFaultPort = 0x31;
  constexpr uint8_t kFaultByte = 0x6D;
  constexpr uint64_t kHandlerGpa = 0x8000;
  constexpr uint64_t kGdtGpa = 0x6000;
  constexpr uint64_t kIdtGpa = 0x6800;
  constexpr uint64_t kStackTop = 0x9000;
  // TSC-deadline mode, masked (so the deadline we plant cannot actually inject
  // anything), vector 0xb0.
  constexpr uint32_t kLvtTimerDeadline = LVT_TIMER_MODE_TSC_DEADLINE | LVT_MASKED | 0xb0;
  constexpr uint32_t kDeadlineValue = 0x1234;
  // Written to IA32_DEBUGCTL: LBR|BTF are honoured, BTS (bit 7) must be dropped.
  constexpr uint32_t kDebugctlWritten = 0x83;
  constexpr uint32_t kDebugctlExpected = 0x03;

  fbl::AllocChecker bac;
  ktl::unique_ptr<uint8_t[]> buf(new (&bac) uint8_t[1024]);
  ASSERT_TRUE(bac.check(), "alloc code buffer\n");
  size_t n = 0;
  auto emit = [&](std::initializer_list<uint8_t> bytes) {
    for (uint8_t b : bytes) {
      buf[n++] = b;
    }
  };
  auto emit32 = [&](uint32_t v) {
    emit({static_cast<uint8_t>(v), static_cast<uint8_t>(v >> 8), static_cast<uint8_t>(v >> 16),
          static_cast<uint8_t>(v >> 24)});
  };
  // mov eax,poison ; mov edx,poison ; mov ecx,msr ; rdmsr ; out kWidePort,eax
  auto read_report = [&](uint32_t msr) {
    emit({0xB8});
    emit32(kPoison);
    emit({0xBA});
    emit32(kPoison);
    emit({0xB9});
    emit32(msr);
    emit({0x0F, 0x32, 0xE7, kWidePort});
  };
  // mov ecx,msr ; mov eax,val ; xor edx,edx ; wrmsr
  auto write_msr = [&](uint32_t msr, uint32_t val) {
    emit({0xB9});
    emit32(msr);
    emit({0xB8});
    emit32(val);
    emit({0x31, 0xD2, 0x0F, 0x30});
  };

  // The registers, in the order the guest reads them, with what each must
  // answer. Everything here is a register a working Windows boot is known to touch.
  struct Expect {
    uint32_t msr;
    uint32_t value;
    const char* what;
  };
  const Expect kReads[] = {
      // The legacy P6 BBL_CR_* family: all nine, read as 0.
      {0x88, 0, "BBL_CR_D0"},
      {0x89, 0, "BBL_CR_D1"},
      {0x8a, 0, "BBL_CR_D2"},
      {0x116, 0, "BBL_CR_ADDR"},
      {0x118, 0, "BBL_CR_DECC"},
      {0x119, 0, "BBL_CR_CTL"},
      {0x11a, 0, "BBL_CR_TRIG"},
      {0x11b, 0, "BBL_CR_BUSY"},
      {0x11e, 0, "BBL_CR_CTL3"},
      // The virtual PMU is disabled, including this model-specific uncore
      // C-box bank. Exercise every register so neither endpoint nor an interior
      // counter can silently fall back to #GP.
      {0xdb0, 0, "MSR_UNC_CBO_5_PERFEVTSEL0"},
      {0xdb1, 0, "MSR_UNC_CBO_5_PERFCTR0"},
      {0xdb2, 0, "MSR_UNC_CBO_5_PERFEVTSEL1"},
      {0xdb3, 0, "MSR_UNC_CBO_5_PERFCTR1"},
      {0xdb4, 0, "MSR_UNC_CBO_5_PERFEVTSEL2"},
      {0xdb5, 0, "MSR_UNC_CBO_5_PERFCTR2"},
      {0xdb6, 0, "MSR_UNC_CBO_5_PERFEVTSEL3"},
      {0xdb7, 0, "MSR_UNC_CBO_5_PERFCTR3"},
      {0xdb8, 0, "MSR_UNC_CBO_5_PERFEVTSEL4"},
      {0xdb9, 0, "MSR_UNC_CBO_5_PERFCTR4"},
      {0xdba, 0, "MSR_UNC_CBO_5_PERFEVTSEL5"},
      {0xdbb, 0, "MSR_UNC_CBO_5_PERFCTR5"},
      // Locked, VMX-outside-SMX clear (CPUID clears the VMX bit too).
      {0x3a, 0x1, "IA32_FEATURE_CONTROL"},
      // The derived value; see kGuestMiscEnable. NOT the reference's 0x851809.
      {0x1a0, 0x801801, "IA32_MISC_ENABLE"},
      // Writes are ignored, so 0 is the consistent answer.
      {0x48, 0, "IA32_SPEC_CTRL"},
      // Architecturally inert outside TSC-deadline mode, and read as 0 there.
      {0x6e0, 0, "IA32_TSC_DEADLINE (one-shot mode)"},
  };
  for (const Expect& e : kReads) {
    read_report(e.msr);
  }
  // DEBUGCTL: write LBR|BTF|BTS, read back LBR|BTF. The BTS bit must have been
  // dropped -- it would point the CPU at the host's IA32_DS_AREA.
  write_msr(0x1d9, kDebugctlWritten);
  read_report(0x1d9);
  // TSC_DEADLINE: put the LVT timer in deadline mode (masked), write a deadline,
  // read it back. A handler that answered this register with a constant 0 --
  // which is the correct answer in the OTHER mode, and therefore the cheap wrong
  // implementation -- fails here.
  write_msr(0x832, kLvtTimerDeadline);
  write_msr(0x6e0, kDeadlineValue);
  read_report(0x6e0);
  // Writes that must be swallowed rather than faulted.
  write_msr(0x88, 0xDEADBEEF);
  write_msr(0x11e, 0x12345678);
  write_msr(0xdb0, 0x00400000);
  write_msr(0xdb2, 0x00400000);
  write_msr(0xdbb, 0x0000ffff);
  write_msr(0x1a0, 0);
  // End marker: reaching this proves the guest executed the whole list without
  // being diverted into its #GP handler.
  emit({0xB0, kDoneByte, 0xE6, kDonePort, 0xF4});
  ASSERT_TRUE(n < 1024, "code buffer overflow\n");

  fbl::RefPtr<VmObjectPaged> ram;
  ASSERT_EQ(ZX_OK, VmObjectPaged::Create(PMM_ALLOC_FLAG_ANY, 0u, kGuestRamSize, &ram), "ram\n");
  ASSERT_EQ(ZX_OK, WriteIdentityTables(ram), "tables\n");
  ASSERT_EQ(ZX_OK, ram->Write(buf.get(), kCodeGpa, n), "code\n");
  // Phase 2, at kCode2Gpa: write a locked IA32_FEATURE_CONTROL, which is
  // architecturally #GP, and require the guest's own handler to run.
  //   B9 3A 00 00 00  mov ecx, 0x3a
  //   B8 01 00 00 00  mov eax, 1
  //   31 D2           xor edx, edx
  //   0F 30           wrmsr        ; -> #GP -> handler
  //   B0 77           mov al, 0x77
  //   E6 30           out 0x30, al ; reached ONLY if the write did not fault
  //   F4              hlt
  const uint8_t phase2[] = {0xB9, 0x3A, 0x00, 0x00, 0x00, 0xB8, 0x01, 0x00, 0x00, 0x00,
                            0x31, 0xD2, 0x0F, 0x30, 0xB0, 0x77, 0xE6, kDonePort, 0xF4};
  ASSERT_EQ(ZX_OK, ram->Write(phase2, kCode2Gpa, sizeof(phase2)), "phase 2\n");

  const uint8_t gdt_code[8] = {0xFF, 0xFF, 0x00, 0x00, 0x00, 0x9B, 0xAF, 0x00};
  ASSERT_EQ(ZX_OK, ram->Write(gdt_code, kGdtGpa + 8, sizeof(gdt_code)), "GDT\n");
  const uint8_t idt_gate[16] = {
      static_cast<uint8_t>(kHandlerGpa & 0xFF), static_cast<uint8_t>((kHandlerGpa >> 8) & 0xFF),
      0x08, 0x00, 0x00, 0x8E, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
  ASSERT_EQ(ZX_OK, ram->Write(idt_gate, kIdtGpa + X86_INT_GP_FAULT * 16, sizeof(idt_gate)), "IDT\n");
  // mov al,0x6D ; out 0x31,al ; hlt
  const uint8_t handler[] = {0xB0, kFaultByte, 0xE6, kFaultPort, 0xF4};
  ASSERT_EQ(ZX_OK, ram->Write(handler, kHandlerGpa, sizeof(handler)), "handler\n");
  ASSERT_EQ(ZX_OK, ram->CommitRange(0, kGuestRamSize), "commit\n");

  auto lg = CreateLiveGuest(ram, kCodeGpa);
  if (lg.is_error() && lg.status_value() == ZX_ERR_NOT_SUPPORTED) {
    printf("VMX not supported here; skipping MSR coverage test.\n");
    return true;
  }
  ASSERT_EQ(ZX_OK, lg.status_value(), "create live guest\n");
  Vcpu* vcpu = lg->vcpu.get();
  ASSERT_EQ(ZX_OK, lg->guest->SetTrap(ZX_GUEST_TRAP_IO, kWidePort, 1, nullptr, kWidePort)
                       .status_value(),
            "trap wide port\n");
  ASSERT_EQ(ZX_OK,
            lg->guest->SetTrap(ZX_GUEST_TRAP_IO, kDonePort, 1, nullptr, kDonePort).status_value(),
            "trap done port\n");
  ASSERT_EQ(ZX_OK,
            lg->guest->SetTrap(ZX_GUEST_TRAP_IO, kFaultPort, 1, nullptr, kFaultPort).status_value(),
            "trap fault port\n");

  fbl::AllocChecker ac;
  ktl::unique_ptr<VcpuArchState> s(new (&ac) VcpuArchState{});
  ASSERT_TRUE(ac.check(), "alloc arch state\n");
  ASSERT_EQ(ZX_OK, vcpu->SaveArchState(*s).status_value(), "SaveArchState\n");
  s->gdtr_base = kGdtGpa;
  s->gdtr_limit = 0x0F;
  s->idtr_base = kIdtGpa;
  s->idtr_limit = 0xFFF;
  s->regs.rsp = kStackTop;
  ASSERT_EQ(ZX_OK, vcpu->RestoreArchState(*s).status_value(), "load GDTR/IDTR/RSP\n");
  ASSERT_EQ(0u, vcpu->UnhandledMsrs().total, "a fresh VCPU has announced nothing\n");

  auto wide = [](const zx_port_packet_t& p) { return p.guest_io.u32; };
  // Returns false only after saying what actually arrived. "next_report is
  // false" on its own names no register, no port and no packet type, which is
  // the same failure mode announce_unhandled_msr exists to avoid.
  auto next_report = [&](zx_port_packet_t& p, const char* what) {
    if (auto e = vcpu->Enter(p); e.is_error()) {
      printf("    ^ %s: Enter() failed with %d\n", what, e.status_value());
      return false;
    }
    if (p.type != ZX_PKT_TYPE_GUEST_IO) {
      printf("    ^ %s: expected an I/O exit, got packet type %u", what,
             static_cast<uint32_t>(p.type));
      if (p.type == ZX_PKT_TYPE_GUEST_HALT) {
        // The guest died. Its RIP names the instruction, and code starts at
        // kCodeGpa, so the offset is what to look for in the emitted stream.
        printf(" -- GUEST HALT, reason %u, rip %#lx (kCodeGpa+%#lx)", p.guest_halt.reason,
               p.guest_halt.rip, p.guest_halt.rip - kCodeGpa);
      }
      printf("\n");
      return false;
    }
    if (p.guest_io.port != kWidePort || p.guest_io.access_size != 4) {
      printf("    ^ %s: expected a 4-byte OUT on port %#x, got a %u-byte OUT on port %#x "
             "(data %#x)\n",
             what, kWidePort, static_cast<uint32_t>(p.guest_io.access_size), p.guest_io.port,
             p.guest_io.u32);
      return false;
    }
    return true;
  };

  for (const Expect& e : kReads) {
    zx_port_packet_t p = {};
    ASSERT_TRUE(next_report(p, e.what), "expected a 4-byte report for each register read\n");
    EXPECT_EQ(e.value, wide(p), e.what);
    if (e.value != wide(p)) {
      printf("    ^ register %#x (%s) answered %#x, expected %#x\n", e.msr, e.what, wide(p),
             e.value);
    }
  }
  {
    zx_port_packet_t p = {};
    ASSERT_TRUE(next_report(p, "IA32_DEBUGCTL readback"), "DEBUGCTL readback report\n");
    EXPECT_EQ(kDebugctlExpected, wide(p),
              "IA32_DEBUGCTL must read back LBR|BTF and NOT the BTS bit: BTS would arm the "
              "processor to write branch records through the HOST's IA32_DS_AREA, which is not a "
              "VMCS field and is not swapped around VM entry\n");
  }
  {
    zx_port_packet_t p = {};
    ASSERT_TRUE(next_report(p, "IA32_TSC_DEADLINE readback"), "TSC_DEADLINE readback report\n");
    EXPECT_EQ(kDeadlineValue, wide(p),
              "in TSC-deadline mode the register must hand back what the guest wrote -- a handler "
              "hard-coded to 0 satisfies the earlier one-shot-mode read and fails here\n");
  }
  zx_port_packet_t done = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(done).status_value(), "enter to done\n");
  ASSERT_EQ(static_cast<uint32_t>(ZX_PKT_TYPE_GUEST_IO), static_cast<uint8_t>(done.type),
            "expected the end marker\n");
  ASSERT_EQ(static_cast<uint32_t>(kDonePort), done.guest_io.port,
            "the guest must have run the whole list to its end marker -- port 0x31 here means it "
            "was diverted into its #GP handler by a register that is still unimplemented\n");
  EXPECT_EQ(static_cast<uint32_t>(kDoneByte), static_cast<uint32_t>(done.guest_io.data[0]),
            "done marker\n");

  // The gate.
  {
    const UnhandledMsrLog& log = vcpu->UnhandledMsrs();
    EXPECT_EQ(0u, log.total,
              "ZERO unhandled-MSR announcements. A non-zero count names the register that is "
              "still missing; see the line printed below it\n");
    if (log.total != 0) {
      printf("    ^ still unhandled: %#x at guest RIP %#lx, %s\n", log.entries[0].msr,
             log.last_rip, log.last_is_write ? "write" : "read");
    }
    EXPECT_EQ(0u, log.tracked, "and no register tracked at all\n");
  }

  // Phase 2: the positive control on the fault path. Writing a locked
  // IA32_FEATURE_CONTROL is architecturally #GP, so the guest's own handler must
  // run -- which is what makes phase 1's empty log a measurement rather than a
  // dead instrument -- and that #GP must NOT be announced, because it is a
  // register we know about and deliberately fault rather than one we have never
  // heard of.
  ASSERT_EQ(ZX_OK, vcpu->SaveArchState(*s).status_value(), "capture between phases\n");
  s->rip = kCode2Gpa;
  ASSERT_EQ(ZX_OK, vcpu->RestoreArchState(*s).status_value(), "reposition to phase 2\n");

  zx_port_packet_t faulted = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(faulted).status_value(), "enter phase 2\n");
  ASSERT_EQ(static_cast<uint32_t>(ZX_PKT_TYPE_GUEST_IO), static_cast<uint8_t>(faulted.type),
            "expected the #GP handler\n");
  EXPECT_EQ(static_cast<uint32_t>(kFaultPort), faulted.guest_io.port,
            "writing a LOCKED IA32_FEATURE_CONTROL must fault the guest -- port 0x30 with 0x77 "
            "here means the write was accepted, which would contradict the read reporting the "
            "lock bit set\n");
  EXPECT_EQ(static_cast<uint32_t>(kFaultByte), static_cast<uint32_t>(faulted.guest_io.data[0]),
            "the guest's own #GP handler must have run\n");
  EXPECT_EQ(0u, vcpu->UnhandledMsrs().total,
            "and that #GP must NOT have been announced: an announcement means \"we do not know "
            "this register\", and this one we know about and fault on purpose. If this ever "
            "counts, the zero-announcement gate above has stopped distinguishing the two\n");

  printf("MSR coverage OK: %zu registers read with their expected values (MISC_ENABLE %#x, "
         "FEATURE_CONTROL locked, DEBUGCTL masked to %#x, TSC_DEADLINE round-tripped %#x), the "
         "swallowed writes did not fault, the guest reached its end marker, the deliberate #GP on "
         "a locked register was taken by the guest and NOT announced, and the unhandled-MSR log "
         "is empty\n",
         sizeof(kReads) / sizeof(kReads[0]), 0x801801u, kDebugctlExpected, kDeadlineValue);
#else
  printf("Not x86_64; skipping.\n");
#endif  // __x86_64__

  END_TEST;
}

// `iretq` from an injected exception frame.
//
// Every other #GP case in this suite reports and halts, so injection is covered
// and *resumption after injection* was not. The unhandled-MSR behavior made that path load-bearing: an
// unhandled MSR now #GPs the guest instead of halting the VM, so the guest's own
// handler is expected to fix up and return -- which is an `iretq` off a frame the
// hypervisor caused the processor to push.
//
// WHAT MAKES THIS DISCRIMINATING, rather than "an exception arrived". The guest
// takes the SAME shape of fault twice from two different sources:
//
//   PHASE 1 -- a NATIVE guest #GP (`mov ds, ax` with a selector past the GDT
//     limit). The exception bitmap is 0, so this never leaves the guest; the
//     PROCESSOR builds the frame. This is the control.
//   PHASE 2 -- a HYPERVISOR-INJECTED #GP (RDMSR of a register the handler has
//     never heard of), delivered through ENTRY_INTERRUPTION_INFORMATION.
//
// One handler serves both. It reports all six frame slots -- error code, RIP,
// CS, RFLAGS, RSP, SS -- before touching anything, then advances the saved RIP
// past the two-byte faulting instruction, discards the error code and `iretq`s.
// The test then requires the two frames to be IDENTICAL in shape. That is the
// assertion that answers "is the injected frame malformed": a malformed
// injection cannot match what the silicon itself pushes two instructions
// earlier, on the same stack, in the same guest. A test that only checked "the
// guest resumed" would pass with, say, the saved RIP already advanced -- the
// guest would resume two bytes into the next instruction and, for most byte
// sequences, keep running.
//
// PHASE 3 is the trap this test exists to pin down, and it is a property of the
// FRAME, not of the hypervisor: `iretq` reloads CS from the frame, and the frame
// carries whatever CS the guest had when it faulted. `vmcs_init` starts a BSP
// with GUEST_CS_SELECTOR == 0 (`vcpu.cc`: "Use GUEST_RIP to set the entry point
// on the BSP") -- a NULL selector, which IRET refuses with #GP(0). So a guest
// that never loaded a real CS can be injected into perfectly and still cannot
// return. Phase 3 re-runs the same fault with the selector put back to 0 and
// shows the `iretq` itself faulting: the handler is entered a second time, and
// the second frame's saved RIP is the address of the `iretq`. It is bounded --
// every handler entry is an I/O exit, so the test decides how many times the
// guest runs -- so it cannot hang the way a free-running fault storm would.
//
// The MSR used for phase 2 is 0xDEADBEEF ON PURPOSE. A gate keyed on something
// being unimplemented dies silently when someone implements it (that is exactly
// what nearly happened to `vcpu_unhandled_msr_announces_itself`, keyed on MSR
// 0x3A until support for 0x3A was implemented). 0xDEADBEEF is not an MSR index in any
// architectural or vendor range and never will be, so no future MSR work can
// quietly turn this phase into a no-op.
bool vcpu_iretq_from_an_injected_frame_resumes_the_guest() {
  BEGIN_TEST;

#ifdef __x86_64__
  constexpr uint8_t kFramePort = 0x28;  // 4-byte: the six exception-frame slots
  constexpr uint8_t kMarkPort = 0x20;   // 1-byte: "execution resumed here"
  constexpr uint8_t kWidePort = 0x21;   // 4-byte: RSP / RFLAGS observed after iretq
  constexpr uint8_t kCtlPort = 0x33;    // 4-byte: the null-CS control's saved RIP
  constexpr uint64_t kGdtGpa = 0x6000;
  constexpr uint64_t kIdtGpa = 0x6800;
  constexpr uint64_t kHandlerGpa = 0x8000;
  constexpr uint64_t kHandler2Gpa = 0x8200;
  constexpr uint64_t kStackTop = 0x9000;
  constexpr uint16_t kCodeSel = 0x08;  // GDT[1], a 64-bit code segment
  constexpr uint16_t kDataSel = 0x10;  // GDT[2], a flat data segment
  // Past the GDT limit set below (0x17), so loading it is #GP(selector).
  constexpr uint16_t kBadSel = 0x20;
  constexpr uint32_t kNeverMsr = 0xDEAD'BEEF;
  constexpr uint8_t kMarkNative = 0xA1;
  constexpr uint8_t kMarkInjected = 0xA2;

  fbl::AllocChecker bac;
  ktl::unique_ptr<uint8_t[]> buf(new (&bac) uint8_t[256]);
  ASSERT_TRUE(bac.check(), "alloc code buffer\n");
  size_t n = 0;
  auto emit = [&](std::initializer_list<uint8_t> bytes) {
    for (uint8_t b : bytes) {
      buf[n++] = b;
    }
  };
  auto emit32 = [&](uint32_t v) {
    emit({static_cast<uint8_t>(v), static_cast<uint8_t>(v >> 8), static_cast<uint8_t>(v >> 16),
          static_cast<uint8_t>(v >> 24)});
  };
  // mov al,mark ; out kMarkPort,al ; mov rax,rsp ; out kWidePort,eax ;
  // pushfq ; pop rax ; out kWidePort,eax
  //
  // Nothing between the fault and the `pushfq` writes RFLAGS (MOV and OUT do
  // not), so the flags reported here are the ones `iretq` restored from the
  // frame, and can be compared with the frame's own RFLAGS slot.
  auto report_resumption = [&](uint8_t mark) {
    emit({0xB0, mark, 0xE6, kMarkPort});
    emit({0x48, 0x89, 0xE0, 0xE7, kWidePort});
    emit({0x9C, 0x58, 0xE7, kWidePort});
  };

  // PHASE 1: a fault the processor takes entirely on its own.
  emit({0xB8});
  emit32(kBadSel);
  const uint64_t kNativeFaultRip = kCodeGpa + n;
  emit({0x8E, 0xD8});  // mov ds, ax  -> #GP(kBadSel); exception bitmap is 0
  report_resumption(kMarkNative);
  // PHASE 2: a fault the hypervisor injects.
  emit({0xB9});
  emit32(kNeverMsr);
  const uint64_t kInjectedFaultRip = kCodeGpa + n;
  emit({0x0F, 0x32});  // rdmsr    -> unhandled -> #GP injected through the VMCS
  report_resumption(kMarkInjected);
  emit({0xF4});
  ASSERT_TRUE(n < 256, "code buffer overflow\n");
  const size_t kCodeLen = n;

  // PHASE 3, at kCode2Gpa: the same native fault and nothing else. What differs
  // is the CS selector the test puts back before entering.
  //   B8 20 00 00 00  mov eax, kBadSel
  //   8E D8           mov ds, ax
  //   F4              hlt
  const uint8_t phase3[] = {0xB8, static_cast<uint8_t>(kBadSel), 0x00, 0x00, 0x00, 0x8E, 0xD8, 0xF4};
  const uint64_t kPhase3FaultRip = kCode2Gpa + 5;

  // The handler. Both faulting instructions are two bytes (`mov ds,ax` is 8E D8;
  // `rdmsr` is 0F 32), so one fixed advance serves both.
  //   8B 04 24            mov eax, [rsp]        ; error code
  //   E7 28               out kFramePort, eax
  //   8B 44 24 08         mov eax, [rsp+8]      ; saved RIP
  //   E7 28
  //   8B 44 24 10         mov eax, [rsp+16]     ; saved CS
  //   E7 28
  //   8B 44 24 18         mov eax, [rsp+24]     ; saved RFLAGS
  //   E7 28
  //   8B 44 24 20         mov eax, [rsp+32]     ; saved RSP
  //   E7 28
  //   8B 44 24 28         mov eax, [rsp+40]     ; saved SS
  //   E7 28
  //   48 83 44 24 08 02   add qword [rsp+8], 2  ; step over the faulting instruction
  //   48 83 C4 08         add rsp, 8            ; discard the error code
  //   48 CF               iretq
  size_t hn = 0;
  ktl::unique_ptr<uint8_t[]> hbuf(new (&bac) uint8_t[64]);
  ASSERT_TRUE(bac.check(), "alloc handler buffer\n");
  auto hemit = [&](std::initializer_list<uint8_t> bytes) {
    for (uint8_t b : bytes) {
      hbuf[hn++] = b;
    }
  };
  hemit({0x8B, 0x04, 0x24, 0xE7, kFramePort});              // [rsp]      error code
  hemit({0x8B, 0x44, 0x24, 0x08, 0xE7, kFramePort});        // [rsp+0x08] RIP
  hemit({0x8B, 0x44, 0x24, 0x10, 0xE7, kFramePort});        // [rsp+0x10] CS
  hemit({0x8B, 0x44, 0x24, 0x18, 0xE7, kFramePort});        // [rsp+0x18] RFLAGS
  hemit({0x8B, 0x44, 0x24, 0x20, 0xE7, kFramePort});        // [rsp+0x20] RSP
  hemit({0x8B, 0x44, 0x24, 0x28, 0xE7, kFramePort});        // [rsp+0x28] SS
  hemit({0x48, 0x83, 0x44, 0x24, 0x08, 0x02});              // add qword [rsp+8], 2
  hemit({0x48, 0x83, 0xC4, 0x08});                          // add rsp, 8
  hemit({0x48, 0xCF});                                      // iretq
  ASSERT_TRUE(hn <= 64, "handler buffer overflow\n");
  // The phase-3 handler: report the saved RIP, then attempt the same return.
  //   8B 44 24 08   mov eax, [rsp+8]
  //   E7 33         out kCtlPort, eax
  //   48 83 C4 08   add rsp, 8
  //   48 CF         iretq                <- at kHandler2Gpa + 10
  const uint8_t handler2[] = {0x8B, 0x44, 0x24, 0x08, 0xE7, kCtlPort,
                              0x48, 0x83, 0xC4, 0x08, 0x48, 0xCF};
  const uint64_t kHandler2IretRip = kHandler2Gpa + 10;

  fbl::RefPtr<VmObjectPaged> ram;
  ASSERT_EQ(ZX_OK, VmObjectPaged::Create(PMM_ALLOC_FLAG_ANY, 0u, kGuestRamSize, &ram), "ram\n");
  ASSERT_EQ(ZX_OK, WriteIdentityTables(ram), "tables\n");
  ASSERT_EQ(ZX_OK, ram->Write(buf.get(), kCodeGpa, kCodeLen), "code\n");
  ASSERT_EQ(ZX_OK, ram->Write(phase3, kCode2Gpa, sizeof(phase3)), "phase 3 code\n");
  ASSERT_EQ(ZX_OK, ram->Write(hbuf.get(), kHandlerGpa, hn), "handler\n");
  ASSERT_EQ(ZX_OK, ram->Write(handler2, kHandler2Gpa, sizeof(handler2)), "control handler\n");

  // GDT[1] = flat 64-bit code (0x08), GDT[2] = flat data (0x10). Both are needed
  // for real: `iretq` reloads CS from GDT[1] and SS from GDT[2], and refuses a
  // null selector for CS.
  const uint8_t gdt_code[8] = {0xFF, 0xFF, 0x00, 0x00, 0x00, 0x9B, 0xAF, 0x00};
  const uint8_t gdt_data[8] = {0xFF, 0xFF, 0x00, 0x00, 0x00, 0x93, 0xCF, 0x00};
  ASSERT_EQ(ZX_OK, ram->Write(gdt_code, kGdtGpa + 8, sizeof(gdt_code)), "GDT code\n");
  ASSERT_EQ(ZX_OK, ram->Write(gdt_data, kGdtGpa + 16, sizeof(gdt_data)), "GDT data\n");
  uint8_t gate[16];
  WriteIdtGate(gate, kHandlerGpa);
  ASSERT_EQ(ZX_OK, ram->Write(gate, kIdtGpa + X86_INT_GP_FAULT * 16, sizeof(gate)), "IDT\n");
  ASSERT_EQ(ZX_OK, ram->CommitRange(0, kGuestRamSize), "commit\n");

  auto lg = CreateLiveGuest(ram, kCodeGpa);
  if (lg.is_error() && lg.status_value() == ZX_ERR_NOT_SUPPORTED) {
    printf("VMX not supported here; skipping iretq-resumption test.\n");
    return true;
  }
  ASSERT_EQ(ZX_OK, lg.status_value(), "create live guest\n");
  Vcpu* vcpu = lg->vcpu.get();
  for (uint8_t port : {kFramePort, kMarkPort, kWidePort, kCtlPort}) {
    ASSERT_EQ(ZX_OK, lg->guest->SetTrap(ZX_GUEST_TRAP_IO, port, 1, nullptr, port).status_value(),
              "trap a report port\n");
  }

  fbl::AllocChecker ac;
  ktl::unique_ptr<VcpuArchState> s(new (&ac) VcpuArchState{});
  ASSERT_TRUE(ac.check(), "alloc arch state\n");
  ASSERT_EQ(ZX_OK, vcpu->SaveArchState(*s).status_value(), "SaveArchState\n");
  // Recorded, not asserted: phase 3 sets this itself, so the test does not
  // depend on the default -- but the default is the reason phase 3 exists.
  printf("a fresh BSP's CS selector is %#x (vmcs_init leaves it null on the BSP)\n",
         static_cast<uint32_t>(s->cs.selector));
  s->gdtr_base = kGdtGpa;
  s->gdtr_limit = 0x17;  // three descriptors
  s->idtr_base = kIdtGpa;
  s->idtr_limit = 0xFFF;
  s->regs.rsp = kStackTop;
  // What a real VMM does and this harness never had to: give the guest a code
  // and stack selector that name real descriptors, so a return through the GDT
  // is possible at all.
  s->cs.selector = kCodeSel;
  s->ss.selector = kDataSel;
  ASSERT_EQ(ZX_OK, vcpu->RestoreArchState(*s).status_value(), "load GDTR/IDTR/RSP/CS/SS\n");

  // A frame, as the handler reported it.
  struct Frame {
    uint32_t error_code, rip, cs, rflags, rsp, ss;
  };
  auto read_frame = [&](Frame& f, const char* what) {
    uint32_t* slots[] = {&f.error_code, &f.rip, &f.cs, &f.rflags, &f.rsp, &f.ss};
    for (size_t i = 0; i < 6; i++) {
      zx_port_packet_t p = {};
      if (auto e = vcpu->Enter(p); e.is_error()) {
        printf("    ^ %s frame slot %zu: Enter() failed with %d\n", what, i, e.status_value());
        return false;
      }
      if (p.type != ZX_PKT_TYPE_GUEST_IO || p.guest_io.port != kFramePort) {
        printf("    ^ %s frame slot %zu: expected a report on port %#x, got packet type %u",
               what, i, kFramePort, static_cast<uint32_t>(p.type));
        if (p.type == ZX_PKT_TYPE_GUEST_HALT) {
          printf(" -- GUEST HALT, reason %u, exit_reason %u, rip %#lx", p.guest_halt.reason,
                 p.guest_halt.exit_reason, p.guest_halt.rip);
        } else if (p.type == ZX_PKT_TYPE_GUEST_IO) {
          printf(" on port %#x", p.guest_io.port);
        }
        printf("\n");
        return false;
      }
      *slots[i] = p.guest_io.u32;
    }
    return true;
  };
  // The marker + RSP + RFLAGS a resumed guest reports.
  auto read_resumption = [&](uint8_t mark, uint32_t& rsp_out, uint32_t& rflags_out,
                             const char* what) {
    zx_port_packet_t p = {};
    if (auto e = vcpu->Enter(p); e.is_error()) {
      printf("    ^ %s: Enter() failed with %d\n", what, e.status_value());
      return false;
    }
    if (p.type != ZX_PKT_TYPE_GUEST_IO || p.guest_io.port != kMarkPort ||
        p.guest_io.data[0] != mark) {
      printf("    ^ %s: the guest did not resume at the instruction after the fault. Expected "
             "%#x on port %#x; got packet type %u",
             what, mark, kMarkPort, static_cast<uint32_t>(p.type));
      if (p.type == ZX_PKT_TYPE_GUEST_HALT) {
        printf(" -- GUEST HALT, reason %u (0=triple fault, 1=unhandled), exit_reason %u, rip %#lx",
               p.guest_halt.reason, p.guest_halt.exit_reason, p.guest_halt.rip);
      } else if (p.type == ZX_PKT_TYPE_GUEST_IO) {
        printf(" on port %#x, data %#x", p.guest_io.port, p.guest_io.u32);
      }
      printf("\n");
      return false;
    }
    zx_port_packet_t r = {};
    if (auto e = vcpu->Enter(r); e.is_error() || r.guest_io.port != kWidePort) {
      printf("    ^ %s: expected the RSP report\n", what);
      return false;
    }
    rsp_out = r.guest_io.u32;
    zx_port_packet_t fl = {};
    if (auto e = vcpu->Enter(fl); e.is_error() || fl.guest_io.port != kWidePort) {
      printf("    ^ %s: expected the RFLAGS report\n", what);
      return false;
    }
    rflags_out = fl.guest_io.u32;
    return true;
  };

  // ---- PHASE 1: the processor's own frame. ----
  Frame native = {};
  ASSERT_TRUE(read_frame(native, "native #GP"), "the guest's #GP handler must have run\n");
  EXPECT_EQ(static_cast<uint32_t>(kBadSel), native.error_code,
            "a #GP from a bad segment selector carries that selector as its error code\n");
  EXPECT_EQ(static_cast<uint32_t>(kNativeFaultRip), native.rip,
            "the frame must name the FAULTING instruction, not the one after it\n");
  EXPECT_EQ(static_cast<uint32_t>(kCodeSel), native.cs, "saved CS\n");
  EXPECT_EQ(static_cast<uint32_t>(X86_FLAGS_RESERVED_ONES), native.rflags & 0xFFFF,
            "saved RFLAGS (low 16; RF above them is set by the processor for a fault)\n");
  EXPECT_EQ(static_cast<uint32_t>(kStackTop), native.rsp, "saved RSP\n");
  EXPECT_EQ(static_cast<uint32_t>(kDataSel), native.ss, "saved SS\n");

  uint32_t rsp1 = 0, rflags1 = 0;
  ASSERT_TRUE(read_resumption(kMarkNative, rsp1, rflags1, "after the native #GP"),
              "iretq from a processor-built frame must resume the guest\n");
  EXPECT_EQ(static_cast<uint32_t>(kStackTop), rsp1,
            "iretq must restore RSP from the frame; anything else means it consumed the wrong "
            "number of slots\n");
  EXPECT_EQ(native.rflags & 0xFFFF, rflags1 & 0xFFFF, "iretq must restore RFLAGS from the frame\n");

  // ---- PHASE 2: the hypervisor's injected frame. ----
  Frame injected = {};
  ASSERT_TRUE(read_frame(injected, "injected #GP"),
              "an unhandled MSR must reach the guest's own #GP handler\n");
  EXPECT_EQ(0u, injected.error_code,
            "the hypervisor injects #GP with a zero error code -- but it must be PUSHED: if "
            "ENTRY_INTERRUPTION_INFORMATION ever loses its deliver-error-code bit this slot "
            "becomes the saved RIP and every slot below it shifts by eight\n");
  EXPECT_EQ(static_cast<uint32_t>(kInjectedFaultRip), injected.rip,
            "the injected frame must name the RDMSR itself. If it names RDMSR+2 the handler's "
            "fix-up steps two bytes too far and the guest resumes mid-instruction\n");
  // THE ANNOUNCEMENT AND THE FRAME MUST BE THE SAME NUMBER.
  //
  // `announce_unhandled_msr` prints `exit_info.guest_rip`, captured at the exit;
  // the frame carries GUEST_RIP as it stood at VM entry. Anything that advances
  // GUEST_RIP between the two -- a stray `next_rip` in the faulting arm is the
  // obvious way -- moves the frame and leaves the log line unchanged, so the
  // announcement would still read correctly while the guest was handed a frame
  // pointing past the instruction. A guest's extable fixup (Linux's
  // `rdmsrl_safe`) matches on the faulting address, so that turns every
  // RECOVERABLE MSR probe into a fatal fault, and the kernel log would say
  // nothing was wrong. Asserting the two are equal is what stops the log from
  // being evidence about something other than what the guest saw.
  EXPECT_EQ(static_cast<uint64_t>(injected.rip), vcpu->UnhandledMsrs().last_rip,
            "the RIP in the unhandled-MSR announcement must be the RIP in the frame the guest's "
            "handler actually read\n");
  // The point of the whole test: same shape, two sources.
  EXPECT_EQ(native.cs, injected.cs, "injected CS must match what the processor pushes\n");
  EXPECT_EQ(native.rflags & 0xFFFF, injected.rflags & 0xFFFF, "injected RFLAGS must match\n");
  EXPECT_EQ(native.rsp, injected.rsp, "injected RSP must match\n");
  EXPECT_EQ(native.ss, injected.ss, "injected SS must match\n");

  uint32_t rsp2 = 0, rflags2 = 0;
  ASSERT_TRUE(read_resumption(kMarkInjected, rsp2, rflags2, "after the injected #GP"),
              "iretq from an INJECTED frame must resume the guest -- this is the case no test in "
              "this suite covered, and the one unhandled-MSR injection made routine\n");
  EXPECT_EQ(static_cast<uint32_t>(kStackTop), rsp2,
            "and the stack must be exactly where it was, so a guest can take this fault "
            "repeatedly without drifting\n");
  EXPECT_EQ(injected.rflags & 0xFFFF, rflags2 & 0xFFFF, "RFLAGS restored from the injected frame\n");

  // ---- PHASE 3: the null-CS trap, bounded. ----
  ASSERT_EQ(ZX_OK, vcpu->SaveArchState(*s).status_value(), "capture before phase 3\n");
  s->rip = kCode2Gpa;
  s->regs.rsp = kStackTop;
  s->cs.selector = 0;  // back to what vmcs_init leaves a BSP with
  ASSERT_EQ(ZX_OK, vcpu->RestoreArchState(*s).status_value(), "reposition to phase 3\n");
  {
    uint8_t gate2[16];
    WriteIdtGate(gate2, kHandler2Gpa);
    ASSERT_EQ(ZX_OK, ram->Write(gate2, kIdtGpa + X86_INT_GP_FAULT * 16, sizeof(gate2)),
              "point #GP at the control handler\n");
  }

  zx_port_packet_t c1 = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(c1).status_value(), "enter phase 3\n");
  ASSERT_EQ(static_cast<uint32_t>(ZX_PKT_TYPE_GUEST_IO), static_cast<uint8_t>(c1.type),
            "phase 3's first fault must reach the control handler\n");
  EXPECT_EQ(static_cast<uint32_t>(kPhase3FaultRip), c1.guest_io.u32,
            "first entry: the frame names the guest's faulting instruction\n");

  zx_port_packet_t c2 = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(c2).status_value(), "enter phase 3 again\n");
  ASSERT_EQ(static_cast<uint32_t>(ZX_PKT_TYPE_GUEST_IO), static_cast<uint8_t>(c2.type),
            "the iretq must have faulted straight back into the handler\n");
  EXPECT_EQ(static_cast<uint32_t>(kHandler2IretRip), c2.guest_io.u32,
            "SECOND entry, and its frame names the IRETQ ITSELF -- that is the whole finding: "
            "with a null CS in the frame the return instruction is what faults, not the guest. A "
            "guest whose VMM never gave it a code selector can be injected into and cannot "
            "return. If this ever reports the guest's RIP again, the null-CS return started "
            "working and this control is no longer measuring anything\n");

  printf("iretq-resumption OK: a native #GP(%#x) at rip %#lx and an INJECTED #GP (unhandled MSR "
         "%#x) at rip %#lx pushed frames identical in CS %#x / RFLAGS %#x / RSP %#x / SS %#x; the "
         "guest's handler stepped over each faulting instruction, iretq'd, and resumed with RSP "
         "back at %#x both times. Control: with CS put back to the null selector vmcs_init leaves "
         "a BSP with, the iretq at %#lx faults into the handler itself\n",
         kBadSel, kNativeFaultRip, kNeverMsr, kInjectedFaultRip, native.cs, native.rflags,
         native.rsp, native.ss, rsp2, kHandler2IretRip);
#else
  printf("Not x86_64; skipping.\n");
#endif  // __x86_64__

  END_TEST;
}

// A guest touching a port no VMM registered gets the answer real hardware
// gives, and keeps running -- and the hypervisor says so out loud.
//
// I/O exiting here is unconditional (there are no I/O bitmaps), so EVERY port
// access takes a VM exit and any port the VMM did not claim used to return
// ZX_ERR_NOT_FOUND, which the epilogue turns into a halt. Firmware and Windows
// both touch ports outside the Gen2 set; port 0x80, used as a one-microsecond
// delay, is the one everything hits. So this was reachable on an ordinary boot
// and the consequence was a dead guest.
//
// THE TRAP THIS TEST IS BUILT AROUND. The correct answer for an unclaimed port
// is all-ones -- nothing drives the bus -- and all-ones is also the single most
// misleading value in this codebase, because every "ready", "present" and "done"
// bit in it reads as SET. Absent hardware then looks like working hardware, and
// this project has been bitten by exactly that three times. So "the guest got
// 0xff" is only half the property; the other half is that the hypervisor
// ANNOUNCED it, and the announcement is what the counters below assert. A
// version that silently defaulted every port would satisfy every value
// assertion here and fail only on `total`/`tracked`.
//
// The registered ports the guest reports through are the control for those
// counters: they take the same unconditional exit and must not be counted.
//
// WHAT THIS DOES NOT PROVE, said rather than implied: that the unclaimed WRITE
// was "discarded". There is no sink to observe, so the only observable is that
// the guest carried on; the write's disappearance is a property of there being
// nowhere for it to go, not something asserted here. What IS asserted about the
// write is that it did not kill the guest and that it was recorded with the
// right port, direction, value and RIP.
bool vcpu_unregistered_io_port_defaults_instead_of_killing_the_guest() {
  BEGIN_TEST;

#ifdef __x86_64__
  constexpr uint8_t kMarkPort = 0x20;  // registered
  constexpr uint8_t kWidePort = 0x21;  // registered
  // Unregistered on purpose. 0x80 is the real-world case (the POST/delay port);
  // the other three exist to cover all three access widths.
  constexpr uint8_t kDeadWrite = 0x80;
  constexpr uint8_t kDeadRead1 = 0x81;
  constexpr uint8_t kDeadRead4 = 0x82;
  constexpr uint8_t kDeadRead2 = 0x83;
  constexpr uint8_t kEndMarker = 0xA5;
  constexpr uint32_t kWriteValue = 0x5A;

  //  E4 81           in  al, 0x81       ; unclaimed 1-byte read
  //  0F B6 C0        movzx eax, al
  //  E7 21           out 0x21, eax
  //  66 E5 83        in  ax, 0x83       ; unclaimed 2-byte read
  //  0F B7 C0        movzx eax, ax
  //  E7 21           out 0x21, eax
  //  E5 82           in  eax, 0x82      ; unclaimed 4-byte read
  //  E7 21           out 0x21, eax
  //  B8 5A 00 BB AA  mov eax, 0xAABB005A
  //  E6 80           out 0x80, al       ; unclaimed 1-byte write; only AL is written,
  //                                     ; so the log must record 0x5A and not RAX
  //  B0 A5           mov al, 0xA5
  //  E6 20           out 0x20, al       ; reached only if none of the above was fatal
  //  F4              hlt
  const uint8_t code[] = {
      0xE4, kDeadRead1, 0x0F, 0xB6, 0xC0, 0xE7, kWidePort,
      0x66, 0xE5, kDeadRead2, 0x0F, 0xB7, 0xC0, 0xE7, kWidePort,
      0xE5, kDeadRead4, 0xE7, kWidePort,
      0xB8, 0x5A, 0x00, 0xBB, 0xAA, 0xE6, kDeadWrite,
      0xB0, kEndMarker, 0xE6, kMarkPort, 0xF4};
  // Computed, so "the RIP was recorded" means the right RIP and not any RIP.
  constexpr uint64_t kRead1Rip = kCodeGpa + 0;
  constexpr uint64_t kWriteRip = kCodeGpa + 24;

  fbl::RefPtr<VmObjectPaged> ram;
  ASSERT_EQ(ZX_OK, VmObjectPaged::Create(PMM_ALLOC_FLAG_ANY, 0u, kGuestRamSize, &ram), "ram\n");
  ASSERT_EQ(ZX_OK, WriteIdentityTables(ram), "tables\n");
  ASSERT_EQ(ZX_OK, ram->Write(code, kCodeGpa, sizeof(code)), "code\n");
  ASSERT_EQ(ZX_OK, ram->CommitRange(0, kGuestRamSize), "commit\n");

  auto lg = CreateLiveGuest(ram, kCodeGpa);
  if (lg.is_error() && lg.status_value() == ZX_ERR_NOT_SUPPORTED) {
    printf("VMX not supported here; skipping unregistered-I/O test.\n");
    return true;
  }
  ASSERT_EQ(ZX_OK, lg.status_value(), "create live guest\n");
  Vcpu* vcpu = lg->vcpu.get();
  for (uint8_t port : {kMarkPort, kWidePort}) {
    ASSERT_EQ(ZX_OK, lg->guest->SetTrap(ZX_GUEST_TRAP_IO, port, 1, nullptr, port).status_value(),
              "trap a report port\n");
  }
  ASSERT_EQ(0u, vcpu->UnhandledIo().total, "a fresh VCPU has defaulted nothing\n");

  struct Expect {
    uint32_t value;
    const char* what;
  };
  const Expect kExpected[] = {
      {0xffu, "1-byte IN from an unclaimed port"},
      {0xffffu, "2-byte IN from an unclaimed port"},
      {0xffffffffu, "4-byte IN from an unclaimed port"},
  };
  for (const Expect& e : kExpected) {
    zx_port_packet_t p = {};
    ASSERT_EQ(ZX_OK, vcpu->Enter(p).status_value(),
              "an unclaimed port must not kill the guest\n");
    if (p.type != ZX_PKT_TYPE_GUEST_IO) {
      printf("    ^ %s: the guest died instead of being answered", e.what);
      if (p.type == ZX_PKT_TYPE_GUEST_HALT) {
        printf(" -- GUEST HALT, reason %u, exit_reason %u, rip %#lx", p.guest_halt.reason,
               p.guest_halt.exit_reason, p.guest_halt.rip);
      }
      printf("\n");
    }
    ASSERT_EQ(static_cast<uint32_t>(ZX_PKT_TYPE_GUEST_IO), static_cast<uint8_t>(p.type),
              "expected the guest to report what it read\n");
    ASSERT_EQ(static_cast<uint32_t>(kWidePort), p.guest_io.port, "report port\n");
    EXPECT_EQ(e.value, p.guest_io.u32, e.what);
  }

  zx_port_packet_t done = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(done).status_value(), "enter to the end marker\n");
  ASSERT_EQ(static_cast<uint32_t>(ZX_PKT_TYPE_GUEST_IO), static_cast<uint8_t>(done.type),
            "the unclaimed OUT must be discarded, not fatal\n");
  ASSERT_EQ(static_cast<uint32_t>(kMarkPort), done.guest_io.port, "end marker port\n");
  EXPECT_EQ(static_cast<uint32_t>(kEndMarker), static_cast<uint32_t>(done.guest_io.data[0]),
            "end marker\n");

  // The half a silent default would fail.
  {
    const UnhandledIoLog& log = vcpu->UnhandledIo();
    EXPECT_EQ(4u, log.total, "all four unclaimed accesses must be recorded\n");
    EXPECT_EQ(3u, log.reads, "three of them reads\n");
    EXPECT_EQ(1u, log.writes, "and one a write\n");
    EXPECT_EQ(4u, log.tracked,
              "four DISTINCT ports, each with its own counter -- and the two REGISTERED ports the "
              "guest reported through took the same unconditional I/O exit and must NOT appear "
              "here, or the log would drown in traffic that is being serviced correctly\n");
    EXPECT_EQ(static_cast<uint32_t>(kDeadWrite), static_cast<uint32_t>(log.last_port),
              "the last defaulted access was the write\n");
    EXPECT_FALSE(log.last_is_read, "recorded as a write\n");
    EXPECT_EQ(static_cast<uint64_t>(kWriteValue), log.last_value,
              "the value the guest tried to write must be recorded, MASKED TO THE ACCESS WIDTH: a "
              "1-byte OUT writes AL only, so recording all of RAX (0xAABB005A here) would put bits "
              "in the log the guest never sent, and a log that reports something that did not "
              "happen is worse than one that reports less\n");
    EXPECT_EQ(kWriteRip, log.last_rip, "the write's own guest RIP\n");
    EXPECT_EQ(static_cast<uint32_t>(kDeadRead1), static_cast<uint32_t>(log.entries[0].port),
              "ports are tracked in first-sighting order, starting at the guest's first "
              "instruction (rip %#lx)\n");
    EXPECT_EQ(1u, log.entries[0].count, "each port keeps its own count\n");
  }

  printf("unregistered-I/O OK: 1/2/4-byte INs from unclaimed ports answered %#x/%#x/%#x (the "
         "all-ones an undriven bus returns), an unclaimed OUT of %#x at rip %#lx was discarded, "
         "the guest reached its end marker from rip %#lx, and all four were announced across four "
         "tracked ports while the two registered ports were not\n",
         0xffu, 0xffffu, 0xffffffffu, kWriteValue, kWriteRip, kRead1Rip);
#else
  printf("Not x86_64; skipping.\n");
#endif  // __x86_64__

  END_TEST;
}

// An unserviceable EPT exit tells the VMM which address.
//
// The halt packet used to carry the exit reason and the guest RIP and nothing
// else, so a VMM was told "an EPT violation went unserviced" and could not say
// where. The offending guest-physical address existed only in a kernel `dprintf`
// -- which the VMM cannot read, and which on a headless run is gone by the time
// anyone looks. For a snapshot-centric project that is the difference between
// "the restored image is missing a mapping at 0x20000" and "memory broke".
//
// The guest reads a guest-physical address that is inside its own paging
// structures' reach but outside the RAM the VMM mapped, so the read is a clean
// EPT violation with nothing to service it. The RIP and the exit reason were
// already reported; the assertion that discriminates this change from the old
// behaviour is `physical_address`, which was structurally unable to be anything
// but zero before.
//
// THE ADDRESS MUST BE THE GUEST-PHYSICAL ONE, and every other guest in this file
// is identity-mapped, which would make GUEST_LINEAR_ADDRESS and
// GUEST_PHYSICAL_ADDRESS the same number and the assertion unable to tell them
// apart. So this guest gets a SECOND, non-identity window: a extra PDPT entry
// maps guest-virtual [1 GiB, 1 GiB + 2 MiB) onto guest-physical [0, 2 MiB), and
// the guest makes its access through that. The linear address is 0x40020000 and
// the physical address is 0x20000, so an implementation that reported the linear
// address fails.
//
// EPT MISCONFIGURATION (exit 49) shares that field and is now handled by its own
// arm rather than falling into `default`, but it is not exercised here: producing
// one requires deliberately malforming an EPT paging-structure entry, which is
// not reachable through any interface this test has. Said rather than implied.
//
// The second phase asserts the field is ZERO for an unhandled exit that has no
// address (`INVD`, exit 13), because "always report the last GPA you saw" is the
// cheapest way to satisfy the first phase.
bool vcpu_unserviceable_ept_exit_reports_the_guest_physical_address() {
  BEGIN_TEST;

#ifdef __x86_64__
  // Past kGuestRamSize, so the second-level translation has nothing behind it,
  // and inside the 2 MiB the tables cover, so the access is not a guest #PF.
  constexpr uint64_t kUnbackedGpa = 0x20000;
  constexpr uint64_t kAliasBase = 0x40000000;  // PDPT entry 1 == 1 GiB of GVA
  constexpr uint64_t kAliasGva = kAliasBase + kUnbackedGpa;
  constexpr uint64_t kAliasPdGpa = 0x5000;  // a spare page inside the guest RAM
  static_assert(kUnbackedGpa >= kGuestRamSize, "must be outside the mapped RAM");
  static_assert(kUnbackedGpa < (2u << 20), "must be inside the 2 MiB the PD entry covers");
  static_assert(kAliasPdGpa + 0x1000 <= kGuestRamSize, "the alias PD must be inside the RAM");

  //  48 B8 <imm64>   movabs rax, 0x40020000
  //  8A 00           mov al, [rax]     ; EPT violation on GPA 0x20000, GVA 0x40020000
  //  F4              hlt
  const uint8_t code[] = {0x48, 0xB8, 0x00, 0x00, 0x02, 0x40, 0x00, 0x00, 0x00, 0x00,
                          0x8A, 0x00, 0xF4};
  constexpr uint64_t kFaultingRip = kCodeGpa + 10;

  //  0F 08           invd              ; exit 13, unhandled, and has no address
  //  F4              hlt
  const uint8_t phase2[] = {0x0F, 0x08, 0xF4};

  fbl::RefPtr<VmObjectPaged> ram;
  ASSERT_EQ(ZX_OK, VmObjectPaged::Create(PMM_ALLOC_FLAG_ANY, 0u, kGuestRamSize, &ram), "ram\n");
  ASSERT_EQ(ZX_OK, WriteIdentityTables(ram), "tables\n");
  // The non-identity alias: PDPT[1] -> a PD whose entry 0 is a 2 MiB page at
  // guest-physical 0. WriteIdentityTables wrote PDPT[0]; this adds PDPT[1].
  {
    const uint64_t alias_pdpte = kAliasPdGpa | kPresent | kWritable;
    const uint64_t alias_pde = 0x0 | kPresent | kWritable | kPageSize2M;
    ASSERT_EQ(ZX_OK, ram->Write(&alias_pdpte, kPdptGpa + 8, sizeof(alias_pdpte)), "alias PDPTE\n");
    ASSERT_EQ(ZX_OK, ram->Write(&alias_pde, kAliasPdGpa, sizeof(alias_pde)), "alias PDE\n");
  }
  ASSERT_EQ(ZX_OK, ram->Write(code, kCodeGpa, sizeof(code)), "code\n");
  ASSERT_EQ(ZX_OK, ram->Write(phase2, kCode2Gpa, sizeof(phase2)), "phase 2 code\n");
  ASSERT_EQ(ZX_OK, ram->CommitRange(0, kGuestRamSize), "commit\n");

  auto lg = CreateLiveGuest(ram, kCodeGpa);
  if (lg.is_error() && lg.status_value() == ZX_ERR_NOT_SUPPORTED) {
    printf("VMX not supported here; skipping EPT-diagnostics test.\n");
    return true;
  }
  ASSERT_EQ(ZX_OK, lg.status_value(), "create live guest\n");

  zx_port_packet_t p = {};
  ASSERT_EQ(ZX_OK, lg->vcpu->Enter(p).status_value(), "enter\n");
  ASSERT_EQ(static_cast<uint32_t>(ZX_PKT_TYPE_GUEST_HALT), static_cast<uint8_t>(p.type),
            "an EPT violation with no backing must halt the guest, not resume it into the same "
            "faulting instruction forever\n");
  EXPECT_EQ(static_cast<uint32_t>(ZX_PKT_GUEST_HALT_UNHANDLED), p.guest_halt.reason,
            "reported as an unserviced exit rather than a guest shutdown\n");
  EXPECT_EQ(48u, p.guest_halt.exit_reason, "exit reason 48 is EPT_VIOLATION\n");
  EXPECT_EQ(kFaultingRip, p.guest_halt.rip, "the instruction that made the access\n");
  // The assertion this change exists for -- and, because the access went through
  // the non-identity alias, it also discriminates the GUEST-PHYSICAL address from
  // the guest-LINEAR one.
  EXPECT_EQ(kUnbackedGpa, p.guest_halt.physical_address,
            "the halt packet must name the guest-physical address the exit was about. Zero here "
            "means the VMM is told an EPT exit happened somewhere, which is what it was told "
            "before, and the address survives only in a kernel log line the VMM cannot read\n");
  EXPECT_NE(kAliasGva, p.guest_halt.physical_address,
            "and it must be the GUEST-PHYSICAL address, not the linear one the instruction used. "
            "The two are equal for every identity-mapped guest in this file, which is why this one "
            "has a second non-identity window\n");

  // Phase 2: an unhandled exit with no address must report zero, or "report the
  // last GPA you happened to see" would satisfy phase 1 forever.
  {
    fbl::AllocChecker ac;
    ktl::unique_ptr<VcpuArchState> st(new (&ac) VcpuArchState{});
    ASSERT_TRUE(ac.check(), "alloc arch state\n");
    ASSERT_EQ(ZX_OK, lg->vcpu->SaveArchState(*st).status_value(), "capture between phases\n");
    st->rip = kCode2Gpa;
    ASSERT_EQ(ZX_OK, lg->vcpu->RestoreArchState(*st).status_value(), "reposition to phase 2\n");

    zx_port_packet_t q = {};
    ASSERT_EQ(ZX_OK, lg->vcpu->Enter(q).status_value(), "enter phase 2\n");
    ASSERT_EQ(static_cast<uint32_t>(ZX_PKT_TYPE_GUEST_HALT), static_cast<uint8_t>(q.type),
              "INVD is an unconditional exit this hypervisor does not handle\n");
    EXPECT_EQ(13u, q.guest_halt.exit_reason, "exit reason 13 is INVD\n");
    EXPECT_EQ(0u, q.guest_halt.physical_address,
              "an exit with no guest-physical address must report zero. A non-zero value here -- "
              "0x20000 in particular -- means the field is stale from the previous exit rather "
              "than read from the one being reported\n");
  }

  printf("EPT-diagnostics OK: an unbacked read of guest-VIRTUAL %#lx (guest-physical %#lx, via a "
         "non-identity alias so the two differ) from rip %#lx halted with exit reason %u and the "
         "PHYSICAL address %#lx in the packet; an unhandled INVD reported zero\n",
         kAliasGva, kUnbackedGpa, kFaultingRip, p.guest_halt.exit_reason,
         p.guest_halt.physical_address);
#else
  printf("Not x86_64; skipping.\n");
#endif  // __x86_64__

  END_TEST;
}

// DR0-DR3 belong to the guest, and the host's survive the guest.
//
// MOV-DR exiting is off and VMX context-switches only DR7 and IA32_DEBUGCTL, via
// the save/load-debug-controls entry and exit controls. Everything else in the
// debug-register file -- the four address registers and the status register --
// was simply shared: a guest `mov dr0, rax` overwrote whatever address the
// HOST's hardware breakpoint pointed at, and a guest `mov rax, dr0` read it.
// x64 Windows writes the debug registers on every context switch, so a Windows
// guest rewrites the host kernel's breakpoints continuously.
//
// TWO PROPERTIES, AND ONLY ONE OF THEM DISCRIMINATES. "The guest reads back what
// it wrote" passes on the BROKEN kernel too -- with one shared register file the
// value is still sitting there. The assertions that can only pass with a real
// swap are:
//   * the host's DR0-DR3 are unchanged after the guest ran (host safety), and
//   * the guest does not see the host's values when it looks (isolation).
// The read-back is kept anyway, because it fails a DIFFERENT wrong
// implementation: one that loads the guest's registers on entry and forgets to
// save them on exit.
//
// The thread is pinned because the debug registers are per-CPU: an unpinned
// check could read a CPU the guest never ran on and pass vacuously.
//
// ALL FOUR ADDRESS REGISTERS, not just DR0. A shim that swapped DR0 alone would
// satisfy a DR0-only test while leaving DR1-DR3 shared, so the guest writes and
// reads back all four and the host checks all four.
//
// DR6 is exercised too, but asserted loosely on purpose: x86_read_debug_status
// ORs in X86_DR6_MASK and x86_write_debug_status drops the upper half, so an
// exact equality would be asserting the masking rather than the swap. What is
// asserted is the one bit the guest set, and that the host's DR6 did not acquire
// it.
//
// DR7 is NOT swapped by this change -- the VMCS owns it through the
// save/load-debug-controls entry and exit controls -- so the host's DR7 must come
// back exactly as it was. That is asserted, because the swap writes DR7 as part
// of `x86_write_hw_debug_regs` and getting its ordering wrong is the defect
// review found in the first draft of the implementation.
bool vcpu_guest_debug_registers_are_not_the_hosts() {
  BEGIN_TEST;

#ifdef __x86_64__
  constexpr uint8_t kMarkPort = 0x20;
  constexpr uint8_t kWidePort = 0x21;
  constexpr uint8_t kPausePort = 0x22;
  constexpr uint8_t kEndMarker = 0xA7;
  // One per address register, distinct so a mix-up names itself.
  const uint32_t kGuestDr[4] = {0x1234'5678u, 0x1234'5679u, 0x1234'567Au, 0x1234'567Bu};
  // Small, canonical, and nothing like the guest's.
  const uint64_t kHostDr[4] = {0xCAFE'F00Du, 0xCAFE'F00Eu, 0xCAFE'F00Fu, 0xCAFE'F010u};
  // Bit 0 of DR6 is B0, "breakpoint 0 condition detected" -- inside
  // X86_DR6_USER_MASK, so it is a bit the guest can really set.
  constexpr uint32_t kGuestDr6Bit = 0x1;

  size_t n = 0;
  fbl::AllocChecker bac;
  ktl::unique_ptr<uint8_t[]> buf(new (&bac) uint8_t[128]);
  ASSERT_TRUE(bac.check(), "alloc code buffer\n");
  auto emit = [&](std::initializer_list<uint8_t> bytes) {
    for (uint8_t b : bytes) {
      buf[n++] = b;
    }
  };
  auto emit32 = [&](uint32_t v) {
    emit({static_cast<uint8_t>(v), static_cast<uint8_t>(v >> 8), static_cast<uint8_t>(v >> 16),
          static_cast<uint8_t>(v >> 24)});
  };
  // Phase A: report all four DRs as the guest finds them, before writing any.
  for (uint8_t dr = 0; dr < 4; dr++) {
    emit({0x0F, 0x21, static_cast<uint8_t>(0xC0 | (dr << 3))});  // mov rax, drN
    emit({0xE7, kWidePort});
  }
  // Phase B: write all four, set a DR6 bit, then exit.
  for (uint8_t dr = 0; dr < 4; dr++) {
    emit({0xB8});
    emit32(kGuestDr[dr]);
    emit({0x0F, 0x23, static_cast<uint8_t>(0xC0 | (dr << 3))});  // mov drN, rax
  }
  emit({0xB8});
  emit32(kGuestDr6Bit);
  emit({0x0F, 0x23, 0xC0 | (6 << 3)});  // mov dr6, rax
  emit({0xB0, 0x01, 0xE6, kPausePort});
  // Phase C: read all four back after the VM exit, then DR6, then the marker.
  for (uint8_t dr = 0; dr < 4; dr++) {
    emit({0x0F, 0x21, static_cast<uint8_t>(0xC0 | (dr << 3))});
    emit({0xE7, kWidePort});
  }
  emit({0x0F, 0x21, 0xC0 | (6 << 3)});  // mov rax, dr6
  emit({0xE7, kWidePort});
  emit({0xB0, kEndMarker, 0xE6, kMarkPort, 0xF4});
  ASSERT_TRUE(n < 128, "code buffer overflow\n");

  fbl::RefPtr<VmObjectPaged> ram;
  ASSERT_EQ(ZX_OK, VmObjectPaged::Create(PMM_ALLOC_FLAG_ANY, 0u, kGuestRamSize, &ram), "ram\n");
  ASSERT_EQ(ZX_OK, WriteIdentityTables(ram), "tables\n");
  ASSERT_EQ(ZX_OK, ram->Write(buf.get(), kCodeGpa, n), "code\n");
  ASSERT_EQ(ZX_OK, ram->CommitRange(0, kGuestRamSize), "commit\n");

  auto lg = CreateLiveGuest(ram, kCodeGpa);
  if (lg.is_error() && lg.status_value() == ZX_ERR_NOT_SUPPORTED) {
    printf("VMX not supported here; skipping debug-register test.\n");
    return true;
  }
  ASSERT_EQ(ZX_OK, lg.status_value(), "create live guest\n");
  Vcpu* vcpu = lg->vcpu.get();
  for (uint8_t port : {kMarkPort, kWidePort, kPausePort}) {
    ASSERT_EQ(ZX_OK, lg->guest->SetTrap(ZX_GUEST_TRAP_IO, port, 1, nullptr, port).status_value(),
              "trap a report port\n");
  }

  const cpu_num_t cpu = arch_curr_cpu_num();
  const cpu_mask_t saved_affinity = Thread::Current::Get()->SetCpuAffinity(cpu_num_to_mask(cpu));
  auto restore_affinity =
      fit::defer([saved_affinity] { Thread::Current::Get()->SetCpuAffinity(saved_affinity); });

  // Plant host breakpoint ADDRESSES. DR7 is left exactly as it was, so nothing
  // is armed and no host breakpoint can actually fire -- the addresses alone are
  // what the guest could clobber, and what this test is about.
  x86_debug_state_t original;
  x86_read_hw_debug_regs(&original);
  auto restore_debug = fit::defer([&original] { x86_write_hw_debug_regs(&original); });
  {
    x86_debug_state_t planted = original;
    for (size_t i = 0; i < 4; i++) {
      planted.dr[i] = kHostDr[i];
    }
    x86_write_hw_debug_regs(&planted);
  }
  {
    x86_debug_state_t check;
    x86_read_hw_debug_regs(&check);
    ASSERT_EQ(kHostDr[0], check.dr[0], "the host's own DR0 must read back what was planted\n");
  }

  auto next_wide = [&](uint32_t& out, const char* what) {
    zx_port_packet_t p = {};
    if (auto e = vcpu->Enter(p); e.is_error()) {
      printf("    ^ %s: Enter() failed with %d\n", what, e.status_value());
      return false;
    }
    if (p.type != ZX_PKT_TYPE_GUEST_IO || p.guest_io.port != kWidePort) {
      printf("    ^ %s: expected a report on port %#x, got packet type %u", what, kWidePort,
             static_cast<uint32_t>(p.type));
      if (p.type == ZX_PKT_TYPE_GUEST_HALT) {
        printf(" -- GUEST HALT, reason %u, exit_reason %u, rip %#lx", p.guest_halt.reason,
               p.guest_halt.exit_reason, p.guest_halt.rip);
      }
      printf("\n");
      return false;
    }
    out = p.guest_io.u32;
    return true;
  };

  // Phase A: what the guest sees before it has written anything.
  for (uint8_t dr = 0; dr < 4; dr++) {
    uint32_t seen = 0;
    ASSERT_TRUE(next_wide(seen, "the guest's view of its own DR before writing"),
                "the guest must report each DR\n");
    EXPECT_EQ(0u, seen,
              "a guest reading a debug register before it has written one must see its own zero, "
              "not the host's breakpoint address\n");
    if (seen != 0) {
      printf("    ^ guest DR%u read %#x; the host planted %#lx there\n", dr, seen, kHostDr[dr]);
    }
  }

  zx_port_packet_t pause = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(pause).status_value(), "enter past the guest's DR writes\n");
  ASSERT_EQ(static_cast<uint32_t>(ZX_PKT_TYPE_GUEST_IO), static_cast<uint8_t>(pause.type),
            "the guest's DR writes must not fault\n");
  ASSERT_EQ(static_cast<uint32_t>(kPausePort), pause.guest_io.port, "pause port\n");

  // The host's registers, examined while the guest is parked mid-run with its own
  // values loaded.
  {
    x86_debug_state_t after;
    x86_read_hw_debug_regs(&after);
    for (size_t i = 0; i < 4; i++) {
      EXPECT_EQ(kHostDr[i], after.dr[i],
                "the host's debug-register addresses must survive a guest that writes its own. A "
                "guest value here means the two share one register file, and a host hardware "
                "breakpoint would now be pointing wherever the guest put it\n");
      if (after.dr[i] != kHostDr[i]) {
        printf("    ^ host DR%zu is now %#lx; it was %#lx and the guest wrote %#x\n", i,
               after.dr[i], kHostDr[i], kGuestDr[i]);
      }
    }
    EXPECT_EQ(original.dr7, after.dr7,
              "and the host's DR7 must be exactly as it was. This change does not swap DR7 -- the "
              "VMCS owns it -- so a difference here means the swap is writing it\n");
    EXPECT_EQ(0u, after.dr6 & kGuestDr6Bit,
              "the host's DR6 must not have acquired the condition bit the guest set\n");
  }

  // Phase C: the guest's own values must have survived the VM exit.
  for (uint8_t dr = 0; dr < 4; dr++) {
    uint32_t seen = 0;
    ASSERT_TRUE(next_wide(seen, "the guest's DR read back after a VM exit"),
                "the guest must report each DR again\n");
    EXPECT_EQ(kGuestDr[dr], seen,
              "the guest's own debug register must survive the VM exit in between -- this is the "
              "assertion a load-on-entry-without-save-on-exit implementation fails, and the one "
              "the ORIGINAL shared-register-file behaviour also passed, which is why it is not the "
              "assertion this test rests on\n");
  }
  uint32_t guest_dr6 = 0;
  ASSERT_TRUE(next_wide(guest_dr6, "the guest's DR6"), "the guest must report DR6\n");
  EXPECT_EQ(kGuestDr6Bit, guest_dr6 & kGuestDr6Bit,
            "and the DR6 condition bit the guest set must still be set for the guest\n");

  zx_port_packet_t done = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(done).status_value(), "enter to the end marker\n");
  ASSERT_EQ(static_cast<uint32_t>(ZX_PKT_TYPE_GUEST_IO), static_cast<uint8_t>(done.type),
            "the guest must reach its end marker\n");
  ASSERT_EQ(static_cast<uint32_t>(kMarkPort), done.guest_io.port, "end marker port\n");
  EXPECT_EQ(static_cast<uint32_t>(kEndMarker), static_cast<uint32_t>(done.guest_io.data[0]),
            "end marker\n");

  printf("debug-register OK: host DR0-DR3 planted as %#lx..%#lx on CPU-%u survived a guest that "
         "wrote %#x..%#x into all four plus DR6 bit %#x; the guest saw zero in all four before its "
         "writes and read every one of them back after a VM exit, and the host's DR7 and DR6 were "
         "untouched\n",
         kHostDr[0], kHostDr[3], cpu, kGuestDr[0], kGuestDr[3], kGuestDr6Bit);
#else
  printf("Not x86_64; skipping.\n");
#endif  // __x86_64__

  END_TEST;
}

// A host NMI taken while this CPU is running a guest reaches the host's
// own NMI handler, and the guest survives it.
//
// `kPinbasedCtlsNmiExiting` is set, so a host NMI during VMX non-root operation
// does not go through the host IDT at all -- it becomes exit reason 0 with
// interruption type 2. That arm used to return ZX_ERR_NOT_SUPPORTED, which kills
// the guest, and the NMI itself was dropped.
//
// The reason this outranks its rarity: the only NMI source in this kernel is
// SendNmiIpi behind CpuContextExchange, whose only production caller is the `k
// cpu context` debug command. So it fires exactly when someone is trying to find
// out why a CPU looks hung -- and CpuContextExchange's lock can only be released
// by a target that ANSWERS, so a single lost NMI wedges the tool for the rest of
// the boot as well as killing the guest under investigation.
//
// The instrument is the production path itself: another CPU calls
// RequestContext, which is what `k cpu context` calls, and a ZX_OK from it means
// the target really did run x86_nmi_handler and reply. The DISCRIMINATING
// assertion is the counter, not the reply: an NMI that lands while the VCPU
// thread is between entries is answered by the ordinary IDT path and proves
// nothing about this fix, so the helper keeps asking until
// HostNmisRedispatched() moves. Without that counter the test would pass on the
// unfixed kernel every time the timing happened to be kind.
//
// TWO CPUS ARE REQUIRED and there is no way around it: the only way to put an
// NMI into a CPU that is running a guest is to send it from a different one.
// Everything this thread could do to itself is delivered before the VM entry.
//
// This now fails rather than skips. It used to self-skip on a
// one-CPU boot, and `//tests/zircon:kernel-utest-boot` passed no `--smp` at all,
// so the default lane ran this case's skip path and reported it as a PASS. A
// skip is a pass to this framework, so the only gate that could ever have run
// this case was one nobody was running. The gate now boots with `--smp=2`.
//
// The distinction being drawn, because it decides what every other precondition
// in this file should do: a MISSING HARDWARE CAPABILITY is a legitimate skip --
// no VT-x under TCG, no XSAVE on a part without it -- because the machine
// genuinely cannot answer the question and failing would only make the portable
// gate unrunnable. A MISSING RUNNER FLAG is not: the machine could have answered
// it and was asked not to, and silence there is how a case stops testing
// anything without anyone noticing. Hence the ordering below: the VMX probe,
// which may skip, is deliberately AFTER this check, which may not.
bool vcpu_host_nmi_during_guest_is_redispatched_not_lost() {
  BEGIN_TEST;

#ifdef __x86_64__
  const cpu_mask_t online = mp_get_online_mask();
  const cpu_num_t self = arch_curr_cpu_num();
  cpu_num_t helper_cpu = INVALID_CPU;
  for (cpu_num_t c = 0; c < percpu::processor_count(); c++) {
    if (c != self && (online & cpu_num_to_mask(c)) != 0) {
      helper_cpu = c;
      break;
    }
  }
  if (helper_cpu == INVALID_CPU) {
    printf("only one CPU is online (processor_count %zu); an NMI can only reach a running guest "
           "from another CPU, so this case cannot run. THIS IS A RUNNER MISCONFIGURATION, NOT A "
           "MISSING CAPABILITY: boot with -smp 2 or more.\n",
           percpu::processor_count());
  }
  ASSERT_NE(INVALID_CPU, helper_cpu,
            "the host-NMI case needs a second online CPU; boot with -smp 2 or more\n");

  constexpr uint8_t kArmedPort = 0x10;
  constexpr uint8_t kDonePort = 0x11;
  //  B0 01           mov al, 1
  //  E6 10           out 0x10, al        ; "I am about to spin" -> exit to us
  //  B9 00 00 00 20  mov ecx, 0x20000000
  //  E2 FE           loop $              ; a long stretch of NON-EXITING guest.
  //                                      ; Sized to outlast the sender's whole
  //                                      ; budget, so "no NMI landed in the
  //                                      ; guest" cannot mean "the guest had
  //                                      ; already finished".
  //  B0 42           mov al, 0x42
  //  E6 11           out 0x11, al        ; only reached if the NMI was not fatal
  //  F4              hlt
  const uint8_t code[] = {0xB0, 0x01, 0xE6, kArmedPort,
                          0xB9, 0x00, 0x00, 0x00, 0x20, 0xE2, 0xFE,
                          0xB0, 0x42, 0xE6, kDonePort, 0xF4};

  fbl::RefPtr<VmObjectPaged> ram;
  ASSERT_EQ(ZX_OK, VmObjectPaged::Create(PMM_ALLOC_FLAG_ANY, 0u, kGuestRamSize, &ram), "ram\n");
  ASSERT_EQ(ZX_OK, WriteIdentityTables(ram), "tables\n");
  ASSERT_EQ(ZX_OK, ram->Write(code, kCodeGpa, sizeof(code)), "code\n");
  ASSERT_EQ(ZX_OK, ram->CommitRange(0, kGuestRamSize), "commit\n");

  auto lg = CreateLiveGuest(ram, kCodeGpa);
  if (lg.is_error() && lg.status_value() == ZX_ERR_NOT_SUPPORTED) {
    printf("VMX not supported here; skipping host-NMI redispatch test.\n");
    return true;
  }
  ASSERT_EQ(ZX_OK, lg.status_value(), "create live guest\n");
  Vcpu* vcpu = lg->vcpu.get();

  // Pin the VCPU thread, so the helper knows which CPU to aim at.
  const cpu_mask_t saved_affinity = Thread::Current::Get()->SetCpuAffinity(cpu_num_to_mask(self));
  auto restore_affinity =
      fit::defer([saved_affinity] { Thread::Current::Get()->SetCpuAffinity(saved_affinity); });

  zx_port_packet_t armed = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(armed).status_value(), "enter to the armed marker\n");
  ASSERT_EQ(static_cast<uint32_t>(kArmedPort), armed.guest_io.port, "armed marker\n");
  ASSERT_EQ(0u, vcpu->HostNmisRedispatched(), "nothing has NMI'd this VCPU yet\n");

  struct NmiCtx {
    Vcpu* vcpu;
    cpu_num_t target;
    ktl::atomic<bool> go{false};
    ktl::atomic<uint32_t> replies{0};
    ktl::atomic<uint32_t> attempts{0};
    ktl::atomic<zx_status_t> last_status{ZX_OK};
  };
  NmiCtx ctx{vcpu, self};
  auto nmi_body = [](void* arg) -> int {
    NmiCtx* c = static_cast<NmiCtx*>(arg);
    while (!c->go.load(ktl::memory_order_acquire)) {
      Thread::Current::Yield();
    }
    // A FIXED number of attempts, and deliberately not "until the counter
    // moves": `host_nmis_redispatched_` is a plain uint64_t written on the VCPU's
    // own thread, so polling it from this CPU would be a data race on a
    // non-atomic object. The main thread reads it after Join(), where the
    // happens-before edge is real. Sized so the whole run fits inside the
    // guest's non-exiting stretch.
    for (uint32_t i = 0; i < 64; i++) {
      CpuContext context;
      zx_status_t status;
      {
        InterruptDisableGuard irqd;
        status = g_cpu_context_exchange.RequestContext(c->target, ZX_MSEC(200), context);
      }
      c->attempts.fetch_add(1, ktl::memory_order_relaxed);
      c->last_status.store(status, ktl::memory_order_relaxed);
      if (status == ZX_OK) {
        c->replies.fetch_add(1, ktl::memory_order_relaxed);
      } else {
        // The exchange is left held by a target that never answered; there is
        // nothing useful to do after that and retrying only spins.
        break;
      }
    }
    return 0;
  };
  Thread* nmi_thread = Thread::Create("hv-nmi-sender", nmi_body, &ctx, DEFAULT_PRIORITY);
  ASSERT_TRUE(nmi_thread != nullptr, "create NMI sender thread\n");
  nmi_thread->SetCpuAffinity(cpu_num_to_mask(helper_cpu));
  nmi_thread->Resume();
  ctx.go.store(true, ktl::memory_order_release);

  // The guest spins here with no exits, so this is where the NMIs land.
  zx_port_packet_t done = {};
  auto entered = vcpu->Enter(done);

  int retcode = 0;
  ASSERT_EQ(ZX_OK, nmi_thread->Join(&retcode, ZX_TIME_INFINITE), "join NMI sender\n");

  ASSERT_EQ(ZX_OK, entered.status_value(),
            "a host NMI during guest execution must not fail the run\n");
  if (done.type != ZX_PKT_TYPE_GUEST_IO) {
    printf("    ^ the guest did not survive the NMI: packet type %u",
           static_cast<uint32_t>(done.type));
    if (done.type == ZX_PKT_TYPE_GUEST_HALT) {
      printf(" -- GUEST HALT, reason %u, exit_reason %u (0 == EXCEPTION_OR_NMI), rip %#lx",
             done.guest_halt.reason, done.guest_halt.exit_reason, done.guest_halt.rip);
    }
    printf("\n");
  }
  ASSERT_EQ(static_cast<uint32_t>(ZX_PKT_TYPE_GUEST_IO), static_cast<uint8_t>(done.type),
            "the guest must run on past the NMI to its own end marker\n");
  ASSERT_EQ(static_cast<uint32_t>(kDonePort), done.guest_io.port, "end marker port\n");
  EXPECT_EQ(0x42u, static_cast<uint32_t>(done.guest_io.data[0]), "end marker\n");

  // The discriminating assertion. A reply alone would also be produced by an NMI
  // that arrived while this thread was between entries, on a kernel with no fix
  // at all.
  EXPECT_GT(vcpu->HostNmisRedispatched(), 0u,
            "at least one NMI must have been taken as a VM exit from inside the guest and "
            "re-dispatched. Zero with a reply present means every NMI landed in host context and "
            "this test measured nothing\n");
  EXPECT_GT(ctx.replies.load(ktl::memory_order_relaxed), 0u,
            "and the host's own NMI handler must have answered the exchange -- that is the `k cpu "
            "context` path, and a lost NMI leaves it held forever\n");
  EXPECT_EQ(ZX_OK, ctx.last_status.load(ktl::memory_order_relaxed),
            "the last RequestContext must have completed rather than timed out\n");

  printf("host-NMI OK: %u RequestContext round trips from CPU-%u to CPU-%u over %u attempts; %lu "
         "of them were taken as VM exits from inside the guest and re-dispatched to vector 2, and "
         "the guest ran on to its own end marker\n",
         ctx.replies.load(ktl::memory_order_relaxed), helper_cpu, self,
         ctx.attempts.load(ktl::memory_order_relaxed), vcpu->HostNmisRedispatched());
#else
  printf("Not x86_64; skipping.\n");
#endif  // __x86_64__

  END_TEST;
}

// The guest is not told about an XSAVE component this hypervisor cannot back.
//
// Zircon does not support MPX -- x86_extended_register_enable_feature() answers
// X86_EXTENDED_REGISTER_MPX with "Currently unsupported" -- but guest CPUID used
// to pass the host's MPX bits straight through: the feature bit at
// CPUID.(EAX=07H,ECX=0):EBX[14], the XCR0-component bits at
// CPUID.(EAX=0DH,ECX=0):EAX[4:3], and the D/3 and D/4 subleaves describing their
// size and offset. Meanwhile ValidateGuestXcr0 took its `supported` mask from
// host CPUID, so a guest XSETBV enabling MPX was accepted -- and a guest XSETBV
// is inert, so the physical XCR0 never gained the bits anyway. A guest that
// believed all three ended up with MPX "on" and no hardware behind it.
//
// All four assertions are made *through the guest*, by a guest that executes
// CPUID itself and reports what it was told, because what matters is what the
// guest sees and not what the hypervisor believes it wrote. The fifth is made
// against ValidateGuestXcr0 directly: advertisement and acceptance are supposed
// to come from one set, so a guest XCR0 naming MPX must be refused on the same
// host where CPUID has just denied it.
//
// Discriminating only where the silicon has MPX, so the host's own CPUID is
// printed alongside: on a part without MPX this passes vacuously and the log
// says so rather than letting a green tick imply more than it proves.
bool vcpu_guest_is_not_told_about_mpx() {
  BEGIN_TEST;

#ifdef __x86_64__
  //  B8 07 00 00 00  mov eax, 7
  //  31 C9           xor ecx, ecx
  //  0F A2           cpuid
  //  C1 EB 0E        shr ebx, 14
  //  83 E3 01        and ebx, 1
  //  88 D8           mov al, bl
  //  E6 10           out 0x10, al      ; exit 1: CPUID.7.0:EBX[14], the MPX feature bit
  //
  //  B8 0D 00 00 00  mov eax, 0x0D
  //  31 C9           xor ecx, ecx
  //  0F A2           cpuid
  //  C1 E8 03        shr eax, 3
  //  83 E0 03        and eax, 3
  //  E6 11           out 0x11, al      ; exit 2: CPUID.D.0:EAX[4:3], the BNDREGS/BNDCSR bits
  //
  //  B8 0D 00 00 00  mov eax, 0x0D
  //  B9 03 00 00 00  mov ecx, 3
  //  0F A2           cpuid
  //  09 D8           or eax, ebx
  //  09 C8           or eax, ecx
  //  09 D0           or eax, edx
  //  85 C0           test eax, eax
  //  0F 95 C0        setne al
  //  E6 30           out 0x30, al      ; exit 3: is subleaf D/3 non-zero anywhere?
  //
  //  ... the same for subleaf 4 ...
  //  E6 31           out 0x31, al      ; exit 4: is subleaf D/4 non-zero anywhere?
  //  F4              hlt
  const uint8_t code[] = {
      0xB8, 0x07, 0x00, 0x00, 0x00, 0x31, 0xC9, 0x0F, 0xA2,
      0xC1, 0xEB, 0x0E, 0x83, 0xE3, 0x01, 0x88, 0xD8, 0xE6, 0x10,
      0xB8, 0x0D, 0x00, 0x00, 0x00, 0x31, 0xC9, 0x0F, 0xA2,
      0xC1, 0xE8, 0x03, 0x83, 0xE0, 0x03, 0xE6, 0x11,
      0xB8, 0x0D, 0x00, 0x00, 0x00, 0xB9, 0x03, 0x00, 0x00, 0x00, 0x0F, 0xA2,
      0x09, 0xD8, 0x09, 0xC8, 0x09, 0xD0, 0x85, 0xC0, 0x0F, 0x95, 0xC0, 0xE6, 0x30,
      0xB8, 0x0D, 0x00, 0x00, 0x00, 0xB9, 0x04, 0x00, 0x00, 0x00, 0x0F, 0xA2,
      0x09, 0xD8, 0x09, 0xC8, 0x09, 0xD0, 0x85, 0xC0, 0x0F, 0x95, 0xC0, 0xE6, 0x31,
      0xF4};

  fbl::RefPtr<VmObjectPaged> ram;
  ASSERT_EQ(ZX_OK, VmObjectPaged::Create(PMM_ALLOC_FLAG_ANY, 0u, kGuestRamSize, &ram), "ram\n");
  ASSERT_EQ(ZX_OK, WriteIdentityTables(ram), "tables\n");
  ASSERT_EQ(ZX_OK, ram->Write(code, kCodeGpa, sizeof(code)), "code\n");
  ASSERT_EQ(ZX_OK, ram->CommitRange(0, kGuestRamSize), "commit\n");

  auto lg = CreateLiveGuest(ram, kCodeGpa);
  if (lg.is_error() && lg.status_value() == ZX_ERR_NOT_SUPPORTED) {
    printf("VMX not supported here; skipping MPX-masking test.\n");
    return true;
  }
  ASSERT_EQ(ZX_OK, lg.status_value(), "create live guest\n");
  Vcpu* vcpu = lg->vcpu.get();
  ASSERT_EQ(ZX_OK, lg->guest->SetTrap(ZX_GUEST_TRAP_IO, 0x30, 1, nullptr, 0x30).status_value(),
            "trap 0x30\n");
  ASSERT_EQ(ZX_OK, lg->guest->SetTrap(ZX_GUEST_TRAP_IO, 0x31, 1, nullptr, 0x31).status_value(),
            "trap 0x31\n");

  // What the host itself reports, so the log states whether these assertions had
  // anything to discriminate.
  uint32_t host_leaf7_ebx = 0, host_xsave_eax = 0;
  {
    cpuid_leaf l;
    if (x86_get_cpuid_subleaf(X86_CPUID_EXTENDED_FEATURE_FLAGS, 0, &l)) {
      host_leaf7_ebx = l.b;
    }
    if (x86_get_cpuid_subleaf(X86_CPUID_XSAVE, 0, &l)) {
      host_xsave_eax = l.a;
    }
  }
  const bool host_has_mpx = (host_leaf7_ebx & (1u << X86_FEATURE_MPX.bit)) != 0;

  struct {
    uint16_t port;
    const char* what;
  } const stages[] = {
      {0x10, "CPUID.(EAX=07H,ECX=0):EBX[14] -- the MPX feature bit"},
      {0x11, "CPUID.(EAX=0DH,ECX=0):EAX[4:3] -- the BNDREGS/BNDCSR XCR0 bits"},
      {0x30, "CPUID.(EAX=0DH,ECX=3) -- the BNDREGS state subleaf"},
      {0x31, "CPUID.(EAX=0DH,ECX=4) -- the BNDCSR state subleaf"},
  };
  for (const auto& stage : stages) {
    zx_port_packet_t p = {};
    ASSERT_EQ(ZX_OK, vcpu->Enter(p).status_value(), "enter\n");
    ASSERT_EQ(static_cast<uint8_t>(ZX_PKT_TYPE_GUEST_IO), static_cast<uint8_t>(p.type), "io\n");
    ASSERT_EQ(static_cast<uint32_t>(stage.port), static_cast<uint32_t>(p.guest_io.port),
              "expected the guest's next CPUID report\n");
    EXPECT_EQ(0u, static_cast<uint32_t>(p.guest_io.data[0]), stage.what);
  }

  // Advertisement and acceptance come from one set: having just denied MPX to
  // the guest, this host must also refuse an XCR0 that names it. Holds on every
  // host -- on one without MPX it was already refused -- so the print below says
  // whether it discriminated.
  const uint64_t mpx_xcr0 = X86_XSAVE_STATE_BIT_X87 | X86_XSAVE_STATE_BIT_SSE |
                            X86_XSAVE_STATE_BIT_MPX_BNDREG | X86_XSAVE_STATE_BIT_MPX_BNDCSR;
  EXPECT_EQ(ZX_ERR_INVALID_ARGS, ValidateGuestXcr0(mpx_xcr0).status_value(),
            "a guest XCR0 naming MPX must be refused, since CPUID does not offer it\n");
  // And the check is not simply refusing everything: the components this kernel
  // does back are still accepted.
  EXPECT_EQ(ZX_OK,
            ValidateGuestXcr0(X86_XSAVE_STATE_BIT_X87 | X86_XSAVE_STATE_BIT_SSE).status_value(),
            "x87+SSE must still be accepted -- otherwise the refusal above proves nothing\n");

  printf("MPX masking OK: the guest read 0 from the MPX feature bit, from CPUID.D.0:EAX[4:3] and "
         "from both D/3 and D/4, and an XCR0 naming MPX was refused. Host CPUID.7.0:EBX=%#x "
         "(MPX %s), CPUID.D.0:EAX=%#x -- so this run %s\n",
         host_leaf7_ebx, host_has_mpx ? "PRESENT" : "absent", host_xsave_eax,
         host_has_mpx ? "discriminated: without the mask the guest would have seen MPX"
                      : "was VACUOUS: this part has no MPX to hide");
#else
  printf("Not x86_64; skipping.\n");
#endif  // __x86_64__

  END_TEST;
}

// The leaf-1 / leaf-7 feature pass-through, stated as a table rather
// than as an argument.
//
// handle_cpuid answers leaf 1 and leaf 7 by running CPUID on the host and
// clearing a hand-written list of bits. Everything not on that list is a claim
// this hypervisor makes on silicon's behalf, and the recurring defect in this
// file is a claim with nothing behind it. Two things are asserted here and a
// third is printed:
//
//   1. REGRESSION LOCK. Every bit the file deliberately clears or sets is
//      checked THROUGH THE GUEST. These are cheap and they are the reason a
//      later "simplification" of the mask list cannot pass quietly. They are not
//      new coverage; they are a fence around coverage that already exists only
//      as code.
//
//   2. THE CLAIM-VS-DO ASSERTION, and the one that is new: a feature whose
//      enable bit lives in CR4 must have a CR4 bit this guest can actually set.
//      CR4_GUEST_HOST_MASK holds only VMXE (vcpu.cc), so a guest `mov cr4` that
//      touches any OTHER bit does not exit and there is no opportunity to
//      emulate anything -- the value goes to the guest's architectural CR4 with
//      no hypervisor in the path. (Only a write that disagrees with the VMXE
//      read shadow exits.) IA32_VMX_CR4_FIXED1 is the ALLOWED-ONE mask for
//      that register in VMX operation, so a bit missing from it is one the
//      guest can never hold. A feature advertised in CPUID whose CR4 bit is missing
//      from FIXED1 is one the guest is invited to turn on and cannot: the `mov
//      cr4` #GPs, at an instruction encoded `0F 22`, in whatever module first
//      tries. That is exactly the shape of fault this lead was opened for.
//
//   3. The full table is PRINTED, advertised-or-not next to what this
//      hypervisor does about each bit, because "what do we hand a guest on this
//      host" is a question the answer to which keeps being reconstructed by
//      hand from source.
//
// Deliberately NOT asserted: that a feature with no CR4 bit and no MSR handler
// is un-advertised. Withdrawing a bit has cost this project two boots, and for
// most of the list below "capable but not enabled" is a legal platform state
// this hypervisor already reports coherently (see kGuestMiscEnable in
// vmexit.cc). The table names them so the judgement is visible instead of
// implicit.
bool vcpu_leaf1_leaf7_claims_match_what_is_backed() {
  BEGIN_TEST;

#ifdef __x86_64__
  constexpr uint16_t kReportPort = 0x14;
  constexpr uint8_t kPort = static_cast<uint8_t>(kReportPort);
  // From vmx_cpu_state_priv.h, which this test does not include. The list of
  // CR4 bits that are allowed to be 1 in VMX operation.
  constexpr uint32_t kMsrIa32VmxCr4Fixed1 = 0x489;
  // CR4 bits with no X86_CR4_* name in this tree.
  constexpr uint64_t kCr4Smxe = 1ull << 14;
  constexpr uint64_t kCr4La57 = 1ull << 12;
  constexpr uint64_t kCr4Kl = 1ull << 19;
  constexpr uint64_t kCr4Cet = 1ull << 23;

  //  B8 01 00 00 00     mov eax,1
  //  31 C9              xor ecx,ecx
  //  0F A2              cpuid
  //  41 89 CA           mov r10d,ecx
  //  41 89 D3           mov r11d,edx
  //  BA 14 00 00 00 / 44 89 D0 / EF     ; report 0: leaf 1 ECX
  //  BA 14 00 00 00 / 44 89 D8 / EF     ; report 1: leaf 1 EDX
  //  B8 07 00 00 00     mov eax,7
  //  31 C9              xor ecx,ecx
  //  0F A2              cpuid
  //  41 89 D9           mov r9d,ebx
  //  41 89 CA           mov r10d,ecx
  //  41 89 D3           mov r11d,edx
  //  BA 14 00 00 00 / 44 89 C8 / EF     ; report 2: leaf 7.0 EBX
  //  BA 14 00 00 00 / 44 89 D0 / EF     ; report 3: leaf 7.0 ECX
  //  BA 14 00 00 00 / 44 89 D8 / EF     ; report 4: leaf 7.0 EDX
  //  F4                 hlt
  const uint8_t code[] = {
      0xB8, 0x01, 0x00, 0x00, 0x00, 0x31, 0xC9, 0x0F, 0xA2,
      0x41, 0x89, 0xCA, 0x41, 0x89, 0xD3,
      0xBA, kPort, 0x00, 0x00, 0x00, 0x44, 0x89, 0xD0, 0xEF,
      0xBA, kPort, 0x00, 0x00, 0x00, 0x44, 0x89, 0xD8, 0xEF,
      0xB8, 0x07, 0x00, 0x00, 0x00, 0x31, 0xC9, 0x0F, 0xA2,
      0x41, 0x89, 0xD9, 0x41, 0x89, 0xCA, 0x41, 0x89, 0xD3,
      0xBA, kPort, 0x00, 0x00, 0x00, 0x44, 0x89, 0xC8, 0xEF,
      0xBA, kPort, 0x00, 0x00, 0x00, 0x44, 0x89, 0xD0, 0xEF,
      0xBA, kPort, 0x00, 0x00, 0x00, 0x44, 0x89, 0xD8, 0xEF,
      0xF4};

  // What handle_cpuid promises about each bit. kPassThrough means "whatever the
  // host says", which is a claim too -- it is just not one this test can turn
  // into an equality.
  enum Claim { kPassThrough, kMustBeClear, kMustBeSet };
  // Index into the five registers the guest reports, in report order.
  enum Reg { k1Ecx, k1Edx, k7Ebx, k7Ecx, k7Edx };
  struct Feature {
    const char* name;
    uint8_t reg;
    uint8_t bit;
    // The CR4 bit that enables this feature, or 0. Non-zero is what makes this
    // entry assertable rather than merely printable.
    uint64_t cr4;
    Claim claim;
    // What this hypervisor actually does. Printed, never asserted on -- it is
    // the human-readable half of the table.
    const char* backing;
  };
  static const Feature kFeatures[] = {
      // ---- leaf 1, ECX ----
      {"DTES64", k1Ecx, 2, 0, kPassThrough,
       "IA32_DS_AREA (0x600) unhandled -> #GP; MISC_ENABLE says BTS+PEBS unavailable"},
      {"MONITOR", k1Ecx, 3, 0, kMustBeClear, "cleared; leaf 5 zeroed; MISC_ENABLE bit 18 clear"},
      {"DS-CPL", k1Ecx, 4, 0, kPassThrough, "same as DTES64"},
      {"SMX", k1Ecx, 6, kCr4Smxe, kPassThrough,
       "GETSEC (0F 37) unimplemented; FEATURE_CONTROL reports locked, SENTER-enable clear"},
      {"EIST", k1Ecx, 7, 0, kPassThrough,
       "IA32_PERF_CTL (0x199) unhandled -> #GP; MISC_ENABLE bit 16 (EIST enable) clear"},
      {"TM2", k1Ecx, 8, 0, kMustBeClear, "cleared"},
      {"xTPR update", k1Ecx, 14, 0, kPassThrough,
       "MISC_ENABLE bit 23 (xTPR message disable) reported SET"},
      {"PDCM", k1Ecx, 15, 0, kMustBeClear, "cleared"},
      {"PCID", k1Ecx, 17, X86_CR4_PCIDE, kPassThrough, "INVPCID gated on the VMCS control"},
      {"DCA", k1Ecx, 18, 0, kPassThrough, "IA32_DCA_CAP (0x1f8) unhandled -> #GP"},
      {"x2APIC", k1Ecx, 21, 0, kMustBeSet, "set; the local APIC is emulated"},
      {"TSC deadline", k1Ecx, 24, 0, kMustBeSet, "set unconditionally; the APIC timer is emulated"},
      {"XSAVE", k1Ecx, 26, X86_CR4_OSXSAVE, kPassThrough,
       "XSETBV emulated and validated; leaf 0xD masked to GuestXsaveComponents()"},
      {"hypervisor", k1Ecx, 31, 0, kMustBeSet, "set"},
      // ---- leaf 1, EDX ----
      {"SEP", k1Edx, 11, 0, kMustBeSet, "set; SYSENTER MSRs are VMCS guest fields"},
      {"DS", k1Edx, 21, 0, kPassThrough, "same as DTES64"},
      {"ACPI", k1Edx, 22, 0, kMustBeClear, "cleared (THERM_CONTROL MSR)"},
      {"TM", k1Edx, 29, 0, kMustBeClear, "cleared"},
      // ---- leaf 7 subleaf 0, EBX ----
      {"FSGSBASE", k7Ebx, 0, X86_CR4_FSGSBASE, kPassThrough,
       "CR4.FSGSBASE set at VCPU init; FS/GS/KERNEL_GS_BASE never exit and are swapped in "
       "ContextSwitch"},
      {"TSC_ADJUST", k7Ebx, 1, 0, kMustBeClear, "cleared"},
      {"SGX", k7Ebx, 2, 0, kPassThrough,
       "ENCLS/ENCLU (0F 01 CF / 0F 01 D7) unimplemented; SGXLEPUBKEYHASH unhandled; "
       "FEATURE_CONTROL reports SGX-enable clear"},
      {"HLE", k7Ebx, 4, 0, kPassThrough, "IA32_TSX_CTRL (0x122) unhandled -> #GP"},
      {"SMEP", k7Ebx, 7, X86_CR4_SMEP, kPassThrough, "paging feature, nothing to emulate"},
      {"RTM", k7Ebx, 11, 0, kPassThrough, "same as HLE"},
      {"RDT-M", k7Ebx, 12, 0, kPassThrough, "IA32_QM_* (0xc8d-0xc8f) unhandled -> #GP"},
      {"MPX", k7Ebx, 14, 0, kMustBeClear,
       "cleared, and its XCR0 components are withheld from leaf 0xD"},
      {"RDT-A", k7Ebx, 15, 0, kPassThrough, "IA32_L3_MASK (0xc90+) unhandled -> #GP"},
      {"AVX512F", k7Ebx, 16, 0, kMustBeClear, "cleared; XCR0 components 5-7 withheld"},
      {"SMAP", k7Ebx, 20, X86_CR4_SMAP, kPassThrough, "paging feature, nothing to emulate"},
      {"Intel PT", k7Ebx, 25, 0, kMustBeClear, "cleared"},
      {"SHA-NI", k7Ebx, 29, 0, kPassThrough, "plain instructions, no state beyond XMM"},
      // ---- leaf 7 subleaf 0, ECX ----
      {"UMIP", k7Ecx, 2, X86_CR4_UMIP, kPassThrough,
       "no descriptor-table exiting is configured; CR4.UMIP is unmediated"},
      {"PKU", k7Ecx, 3, X86_CR4_PKE, kPassThrough,
       "WRPKRU/RDPKRU (0F 01 EE/EF) do not exit; PKRU is XCR0 bit 9, which is NOT withheld"},
      {"WAITPKG", k7Ecx, 5, 0, kPassThrough, "IA32_UMWAIT_CONTROL (0xe1) unhandled -> #GP"},
      {"CET_SS", k7Ecx, 7, kCr4Cet, kPassThrough, "MSRs 0x6a0-0x6a8 unhandled -> #GP"},
      {"GFNI", k7Ecx, 8, 0, kPassThrough, "plain instructions"},
      {"AVX512_VBMI", k7Ecx, 1, 0, kMustBeClear, "cleared"},
      {"LA57", k7Ecx, 16, kCr4La57, kPassThrough, "paging feature; EPT is 4-level here"},
      {"RDPID", k7Ecx, 22, 0, kPassThrough,
       "BACKED: IA32_TSC_AUX never exits and is swapped per-VCPU in ContextSwitch"},
      {"KL", k7Ecx, 23, kCr4Kl, kPassThrough, "IA32_COPY_* unhandled -> #GP"},
      {"MOVDIRI", k7Ecx, 27, 0, kPassThrough, "plain instructions"},
      {"MOVDIR64B", k7Ecx, 28, 0, kPassThrough, "plain instructions"},
      // ---- leaf 7 subleaf 0, EDX ----
      {"SERIALIZE", k7Edx, 14, 0, kPassThrough, "plain instruction, no architectural state"},
      {"CET_IBT", k7Edx, 20, kCr4Cet, kPassThrough, "same as CET_SS"},
      {"IBRS/IBPB", k7Edx, 26, 0, kMustBeClear, "cleared; IA32_SPEC_CTRL reads 0, writes ignored"},
      {"STIBP", k7Edx, 27, 0, kMustBeClear, "cleared"},
      {"L1D_FLUSH", k7Edx, 28, 0, kMustBeClear, "cleared; IA32_FLUSH_CMD unhandled"},
      {"ARCH_CAPABILITIES", k7Edx, 29, 0, kMustBeClear, "cleared; the MSR is unhandled"},
      {"SSBD", k7Edx, 31, 0, kMustBeClear, "cleared"},
  };

  fbl::RefPtr<VmObjectPaged> ram;
  ASSERT_EQ(ZX_OK, VmObjectPaged::Create(PMM_ALLOC_FLAG_ANY, 0u, kGuestRamSize, &ram), "ram\n");
  ASSERT_EQ(ZX_OK, WriteIdentityTables(ram), "tables\n");
  ASSERT_EQ(ZX_OK, ram->Write(code, kCodeGpa, sizeof(code)), "code\n");
  ASSERT_EQ(ZX_OK, ram->CommitRange(0, kGuestRamSize), "commit\n");

  auto lg = CreateLiveGuest(ram, kCodeGpa);
  if (lg.is_error() && lg.status_value() == ZX_ERR_NOT_SUPPORTED) {
    printf("VMX not supported here; skipping leaf-1/leaf-7 claim table.\n");
    return true;
  }
  ASSERT_EQ(ZX_OK, lg.status_value(), "create live guest\n");
  Vcpu* vcpu = lg->vcpu.get();
  ASSERT_EQ(
      ZX_OK,
      lg->guest->SetTrap(ZX_GUEST_TRAP_IO, kReportPort, 1, nullptr, kReportPort).status_value(),
      "trap the feature-report port\n");

  uint32_t guest_regs[5] = {};
  for (uint32_t i = 0; i < 5; ++i) {
    zx_port_packet_t p = {};
    ASSERT_EQ(ZX_OK, vcpu->Enter(p).status_value(), "enter\n");
    ASSERT_EQ(static_cast<uint8_t>(ZX_PKT_TYPE_GUEST_IO), static_cast<uint8_t>(p.type), "io\n");
    ASSERT_EQ(static_cast<uint32_t>(kReportPort), static_cast<uint32_t>(p.guest_io.port),
              "feature-report port\n");
    guest_regs[i] = p.guest_io.u32;
  }

  // What the host reports, for the printed table only -- the assertions below
  // are all on what the GUEST was told.
  uint32_t host_regs[5] = {};
  {
    cpuid_leaf l;
    ASSERT_TRUE(x86_get_cpuid_subleaf(X86_CPUID_MODEL_FEATURES, 0, &l), "host leaf 1\n");
    host_regs[k1Ecx] = l.c;
    host_regs[k1Edx] = l.d;
    ASSERT_TRUE(x86_get_cpuid_subleaf(X86_CPUID_EXTENDED_FEATURE_FLAGS, 0, &l), "host leaf 7\n");
    host_regs[k7Ebx] = l.b;
    host_regs[k7Ecx] = l.c;
    host_regs[k7Edx] = l.d;
  }
  // Safe to read: CreateLiveGuest succeeded, so this CPU is in VMX operation.
  const uint64_t cr4_fixed1 = read_msr(kMsrIa32VmxCr4Fixed1);

  static const char* const kRegNames[5] = {"CPUID.1:ECX    ", "CPUID.1:EDX    ",
                                           "CPUID.7.0:EBX  ", "CPUID.7.0:ECX  ",
                                           "CPUID.7.0:EDX  "};
  printf("leaf-1 / leaf-7 claim table, as handed to a guest on THIS host:\n");
  printf("  guest: 1:ECX=0x%08x 1:EDX=0x%08x 7.0:EBX=0x%08x 7.0:ECX=0x%08x 7.0:EDX=0x%08x\n",
         guest_regs[k1Ecx], guest_regs[k1Edx], guest_regs[k7Ebx], guest_regs[k7Ecx],
         guest_regs[k7Edx]);
  printf("  host : 1:ECX=0x%08x 1:EDX=0x%08x 7.0:EBX=0x%08x 7.0:ECX=0x%08x 7.0:EDX=0x%08x\n",
         host_regs[k1Ecx], host_regs[k1Edx], host_regs[k7Ebx], host_regs[k7Ecx], host_regs[k7Edx]);
  printf("  IA32_VMX_CR4_FIXED1=%#lx\n", cr4_fixed1);

  uint32_t cr4_checked = 0;
  for (const Feature& f : kFeatures) {
    const bool told = (guest_regs[f.reg] & (1u << f.bit)) != 0;
    const bool host_has = (host_regs[f.reg] & (1u << f.bit)) != 0;
    printf("  %-18s %s bit %-2u  host=%d guest=%d  %s\n", f.name, kRegNames[f.reg],
           static_cast<uint32_t>(f.bit), host_has ? 1 : 0, told ? 1 : 0, f.backing);
    switch (f.claim) {
      case kMustBeClear:
        EXPECT_FALSE(told, f.name);
        break;
      case kMustBeSet:
        EXPECT_TRUE(told, f.name);
        break;
      case kPassThrough:
        break;
    }
    // THE CLAIM-VS-DO ASSERTION. Only meaningful where the bit is actually
    // advertised, so on any one part most entries are inert -- the printed
    // count below says how many were live rather than letting a green tick
    // imply the whole table was exercised.
    if (f.cr4 != 0 && told) {
      cr4_checked++;
      EXPECT_TRUE((cr4_fixed1 & f.cr4) != 0,
                "this feature is advertised to the guest, but its CR4 enable bit is not one "
                "IA32_VMX_CR4_FIXED1 permits -- CR4_GUEST_HOST_MASK holds only VMXE, so the "
                "guest's `mov cr4` reaches the real register and #GPs\n");
    }
  }
  // Or the whole column is vacuous and its green tick means nothing: a
  // presentation that advertised none of these features would satisfy every
  // CR4 assertion by never making one.
  EXPECT_NE(0u, cr4_checked,
            "no CR4-backed feature was advertised at all, so the FIXED1 column asserted "
            "nothing on this host\n");
  printf("  -> %u of the CR4-backed features were advertised on this host and checked against "
         "IA32_VMX_CR4_FIXED1; the rest of that column was inert here.\n",
         cr4_checked);
#else
  printf("Not x86_64; skipping.\n");
#endif  // __x86_64__

  END_TEST;
}

// CPUID leaf 0xD must be internally consistent: the component bitmap,
// the two SIZES beside it, and the per-component subleaves are four statements
// about one layout, and the guest can compare them without help.
//
// Masking the bitmap (EDX:EAX) to GuestXsaveComponents() fixed one register and
// left the next one lying. ECX -- "the size required by all state components
// supported", Volume 2, Table 3-8 -- was still the host's, so on a part with MPX
// the guest was told, in one CPUID, that the components it may enable are
// x87|SSE|AVX (0x7) and that they need 1088 bytes: a number describing a layout
// that ends in the two components the very same leaf had just denied, and which
// no combination of the offsets and sizes the guest is shown can produce.
//
// EVERY NUMBER HERE COMES FROM THE GUEST. The expectation for ECX is recomputed
// from the bitmap and the per-component subleaves *as the guest read them*, not
// from compute_xsave_size(), so this is a consistency check on what was handed
// over rather than the implementation agreeing with itself.
//
// THE GUEST NARROWS ITS OWN XCR0 FIRST, and that is the point of the XSETBV at
// the top rather than an incidental setup step. EBX (the size for the components
// *enabled* in XCR0) and ECX (the size for the components *supported*) are
// different questions, and on this machine the initial XCR0 is exactly the
// supported set -- so the cheapest wrong implementation, `ECX = EBX`, would pass
// every assertion below unless something makes the two differ. Narrowing to
// x87|SSE pins EBX at 576 while ECX must stay at the full advertised size.
bool vcpu_cpuid_leaf_d_is_self_consistent() {
  BEGIN_TEST;

#ifdef __x86_64__
  constexpr uint16_t kReportPort = 0x13;
  constexpr uint8_t kPort = static_cast<uint8_t>(kReportPort);
  // The legacy region (512) plus the XSAVE header (64). The floor of any
  // standard-format XSAVE area, and written out here rather than taken from
  // vmexit.cc's constants so the expectation is independent of them.
  constexpr uint32_t kXsaveAreaFloor = 576;
  // Components 2..19: AVX, MPX (3,4), AVX-512 (5,6,7), Intel-PT (8), PKRU (9),
  // PASID (10), CET (11,12), HDC (13), UINTR (14), LBR (15), HWP (16), AMX
  // (17,18), APX (19). That is EVERY state component Volume 1 defines today, so
  // the ECX recomputation below is not merely "correct on the part in front of
  // us" -- it was, and the guard that made it conditional is what said so.
  constexpr uint32_t kFirstSubleaf = 2;
  constexpr uint32_t kLastSubleaf = 19;
  constexpr uint32_t kNumSubleaves = kLastSubleaf - kFirstSubleaf + 1;

  //  31 C9              xor ecx,ecx
  //  31 D2              xor edx,edx
  //  B8 03 00 00 00     mov eax,3
  //  0F 01 D1           xsetbv                 ; XCR0 = x87|SSE, so EBX != ECX
  //  B8 0D 00 00 00     mov eax,0x0D
  //  31 C9              xor ecx,ecx
  //  0F A2              cpuid
  //  41 89 C0           mov r8d,eax            ; bitmap low
  //  41 89 D9           mov r9d,ebx            ; size for the ENABLED set
  //  41 89 CA           mov r10d,ecx           ; size for the SUPPORTED set
  //  41 89 D3           mov r11d,edx           ; bitmap high
  //  BA 13 00 00 00 / 44 89 C0 / EF            ; report 0: EAX
  //  BA 13 00 00 00 / 44 89 C8 / EF            ; report 1: EBX
  //  BA 13 00 00 00 / 44 89 D0 / EF            ; report 2: ECX
  //  BA 13 00 00 00 / 44 89 D8 / EF            ; report 3: EDX
  const uint8_t prologue[] = {
      0x31, 0xC9, 0x31, 0xD2, 0xB8, 0x03, 0x00, 0x00, 0x00, 0x0F, 0x01, 0xD1,
      0xB8, 0x0D, 0x00, 0x00, 0x00, 0x31, 0xC9, 0x0F, 0xA2,
      0x41, 0x89, 0xC0, 0x41, 0x89, 0xD9, 0x41, 0x89, 0xCA, 0x41, 0x89, 0xD3,
      0xBA, kPort, 0x00, 0x00, 0x00, 0x44, 0x89, 0xC0, 0xEF,
      0xBA, kPort, 0x00, 0x00, 0x00, 0x44, 0x89, 0xC8, 0xEF,
      0xBA, kPort, 0x00, 0x00, 0x00, 0x44, 0x89, 0xD0, 0xEF,
      0xBA, kPort, 0x00, 0x00, 0x00, 0x44, 0x89, 0xD8, 0xEF,
      // The same again for subleaf 1 -- the XSAVEOPT/XSAVEC/XSAVES flags. Not a
      // component subleaf, so it takes no part in the size arithmetic below; it
      // is here so the printed leaf is the WHOLE leaf a guest reads on this
      // host, which is the question this lead was opened to answer.
      //  B8 0D 00 00 00 / B9 01 00 00 00 / 0F A2   cpuid(0xd, 1)
      0xB8, 0x0D, 0x00, 0x00, 0x00, 0xB9, 0x01, 0x00, 0x00, 0x00, 0x0F, 0xA2,
      0x41, 0x89, 0xC0, 0x41, 0x89, 0xD9, 0x41, 0x89, 0xCA, 0x41, 0x89, 0xD3,
      0xBA, kPort, 0x00, 0x00, 0x00, 0x44, 0x89, 0xC0, 0xEF,
      0xBA, kPort, 0x00, 0x00, 0x00, 0x44, 0x89, 0xC8, 0xEF,
      0xBA, kPort, 0x00, 0x00, 0x00, 0x44, 0x89, 0xD0, 0xEF,
      0xBA, kPort, 0x00, 0x00, 0x00, 0x44, 0x89, 0xD8, 0xEF};

  uint8_t code[1280] = {};
  static_assert(sizeof(code) <= kCode2Gpa - kCodeGpa, "the blob must not reach the next entry\n");
  size_t n = sizeof(prologue);
  memcpy(code, prologue, sizeof(prologue));
  for (uint32_t s = kFirstSubleaf; s <= kLastSubleaf; ++s) {
    //  B8 0D 00 00 00     mov eax,0x0D
    //  B9 ss 00 00 00     mov ecx,s
    //  0F A2              cpuid
    //  41 89 C0           mov r8d,eax          ; this component's SIZE
    //  41 89 D9           mov r9d,ebx          ; this component's OFFSET
    //  09 D1              or ecx,edx           ; the two registers Table 3-8
    //  41 89 CA           mov r10d,ecx         ; says must ALSO read as zero
    //  BA 13 00 00 00 / 44 89 C0 / EF          ; report the size
    //  BA 13 00 00 00 / 44 89 C8 / EF          ; report the offset
    //  BA 13 00 00 00 / 44 89 D0 / EF          ; report ECX|EDX
    const uint8_t block[] = {
        0xB8, 0x0D, 0x00, 0x00, 0x00,
        0xB9, static_cast<uint8_t>(s), 0x00, 0x00, 0x00,
        0x0F, 0xA2,
        0x41, 0x89, 0xC0, 0x41, 0x89, 0xD9, 0x09, 0xD1, 0x41, 0x89, 0xCA,
        0xBA, kPort, 0x00, 0x00, 0x00, 0x44, 0x89, 0xC0, 0xEF,
        0xBA, kPort, 0x00, 0x00, 0x00, 0x44, 0x89, 0xC8, 0xEF,
        0xBA, kPort, 0x00, 0x00, 0x00, 0x44, 0x89, 0xD0, 0xEF};
    ASSERT_LE(n + sizeof(block) + 1, sizeof(code), "guest code buffer\n");
    memcpy(code + n, block, sizeof(block));
    n += sizeof(block);
  }
  code[n++] = 0xF4;  // hlt

  fbl::RefPtr<VmObjectPaged> ram;
  ASSERT_EQ(ZX_OK, VmObjectPaged::Create(PMM_ALLOC_FLAG_ANY, 0u, kGuestRamSize, &ram), "ram\n");
  ASSERT_EQ(ZX_OK, WriteIdentityTables(ram), "tables\n");
  ASSERT_EQ(ZX_OK, ram->Write(code, kCodeGpa, n), "code\n");
  ASSERT_EQ(ZX_OK, ram->CommitRange(0, kGuestRamSize), "commit\n");

  if (!x86_xsave_supported()) {
    printf("This part has no XSAVE, so leaf 0xD describes nothing; skipping.\n");
    return true;
  }

  auto lg = CreateLiveGuest(ram, kCodeGpa);
  if (lg.is_error() && lg.status_value() == ZX_ERR_NOT_SUPPORTED) {
    printf("VMX not supported here; skipping leaf-0xD consistency test.\n");
    return true;
  }
  ASSERT_EQ(ZX_OK, lg.status_value(), "create live guest\n");
  Vcpu* vcpu = lg->vcpu.get();
  ASSERT_EQ(
      ZX_OK,
      lg->guest->SetTrap(ZX_GUEST_TRAP_IO, kReportPort, 1, nullptr, kReportPort).status_value(),
      "trap leaf-0xD report port\n");

  // [0..3] = subleaf 0's EAX,EBX,ECX,EDX; [4..7] = subleaf 1's.
  uint32_t main_leaf[8] = {};
  uint32_t comp_size[kNumSubleaves] = {};
  uint32_t comp_offset[kNumSubleaves] = {};
  uint32_t comp_rest[kNumSubleaves] = {};
  for (uint32_t i = 0; i < 8 + 3 * kNumSubleaves; ++i) {
    zx_port_packet_t p = {};
    ASSERT_EQ(ZX_OK, vcpu->Enter(p).status_value(), "enter\n");
    ASSERT_EQ(static_cast<uint8_t>(ZX_PKT_TYPE_GUEST_IO), static_cast<uint8_t>(p.type), "io\n");
    ASSERT_EQ(static_cast<uint32_t>(kReportPort), static_cast<uint32_t>(p.guest_io.port),
              "leaf-0xD report port\n");
    if (i < 8) {
      main_leaf[i] = p.guest_io.u32;
    } else if ((i - 8) % 3 == 0) {
      comp_size[(i - 8) / 3] = p.guest_io.u32;
    } else if ((i - 8) % 3 == 1) {
      comp_offset[(i - 8) / 3] = p.guest_io.u32;
    } else {
      comp_rest[(i - 8) / 3] = p.guest_io.u32;
    }
  }
  const uint32_t guest_eax = main_leaf[0];
  const uint32_t guest_ebx = main_leaf[1];
  const uint32_t guest_ecx = main_leaf[2];
  const uint32_t guest_edx = main_leaf[3];

  // What this part really supports, read here rather than through the same path
  // the kernel uses, so the bitmap expectation is not the implementation
  // agreeing with itself.
  uint32_t host_eax = 0, host_ecx = 0, host_edx = 0;
  {
    cpuid_leaf l;
    ASSERT_TRUE(x86_get_cpuid_subleaf(X86_CPUID_XSAVE, 0, &l), "host leaf 0xD\n");
    host_eax = l.a;
    host_ecx = l.c;
    host_edx = l.d;
  }
  const uint64_t advertised = GuestXsaveComponents((static_cast<uint64_t>(host_edx) << 32) |
                                                   host_eax);

  EXPECT_EQ(static_cast<uint32_t>(advertised), guest_eax,
            "CPUID.(EAX=0DH,ECX=0):EAX must be the host's component set minus the ones this "
            "hypervisor withholds\n");
  EXPECT_EQ(static_cast<uint32_t>(advertised >> 32), guest_edx,
            "and the same for the high half of the bitmap\n");

  // Every component the guest is told about must describe itself, and every
  // component it is NOT told about must describe nothing. Without the second
  // half a guest that reads the subleaves instead of the bitmap would lay out an
  // XSAVE area around a component that is not there.
  for (uint32_t s = kFirstSubleaf; s <= kLastSubleaf; ++s) {
    const uint32_t i = s - kFirstSubleaf;
    const bool told = (guest_eax & (1u << s)) != 0;
    if (told) {
      EXPECT_NE(0u, comp_size[i],
                "a component advertised in the bitmap must have a non-zero size in its own "
                "subleaf\n");
    } else {
      EXPECT_EQ(0u, comp_size[i],
                "a component absent from the bitmap must read as all zeros in its own subleaf "
                "(Volume 2, Table 3-8)\n");
      EXPECT_EQ(0u, comp_offset[i],
                "a component absent from the bitmap must read as all zeros in its own subleaf "
                "(Volume 2, Table 3-8)\n");
      // ALL FOUR registers, not just the two the size arithmetic uses. An
      // implementation that zeroed EAX and EBX and left the host's ECX/EDX
      // there would satisfy every other assertion here.
      EXPECT_EQ(0u, comp_rest[i],
                "and that means ECX and EDX too, not only the size and offset\n");
    }
  }

  // THE ASSERTION THAT DISCRIMINATES. ECX recomputed from nothing but the
  // bitmap and the offsets/sizes the guest was just handed.
  uint32_t implied = kXsaveAreaFloor;
  for (uint32_t s = kFirstSubleaf; s <= kLastSubleaf; ++s) {
    const uint32_t i = s - kFirstSubleaf;
    if ((guest_eax & (1u << s)) != 0) {
      const uint32_t end = comp_offset[i] + comp_size[i];
      if (end > implied) {
        implied = end;
      }
    }
  }
  // The walk above stops at component 9. If a part ever advertises one above
  // that, `implied` would under-count and this assertion would be wrong rather
  // than merely weak -- so it is made conditional and the condition is printed.
  const bool bitmap_within_walk = (guest_eax >> (kLastSubleaf + 1)) == 0 && guest_edx == 0;
  if (bitmap_within_walk) {
    EXPECT_EQ(implied, guest_ecx,
              "CPUID.(EAX=0DH,ECX=0):ECX is the size needed by every component the guest is told "
              "it MAY enable. Passing the host's through leaves it describing a layout that ends "
              "in components the bitmap beside it has denied\n");
  }
  EXPECT_LE(guest_ebx, guest_ecx,
            "the size for the enabled set can never exceed the size for the supported set\n");
  // Pins EBX, and with it the difference between the two registers. This is what
  // stops `ECX = EBX` -- which needs no per-component reasoning at all -- from
  // satisfying everything above on a machine whose initial XCR0 happens to be
  // the whole supported set.
  EXPECT_EQ(kXsaveAreaFloor, guest_ebx,
            "after the guest narrowed XCR0 to x87|SSE its XSAVE area is the legacy region plus "
            "the header and nothing else\n");
  EXPECT_NE(guest_ebx, guest_ecx,
            "and it must differ from ECX, or the assertion on ECX proves nothing\n");

  // SUBLEAF 1, which handle_cpuid rewrites and this test used only to print.
  // XSAVEC (EAX[1]) and XSAVES (EAX[3]) are cleared because this hypervisor does
  // not support the compacted format or IA32_XSS, and Table 3-8 then requires
  // EBX to enumerate zero; ECX/EDX describe the IA32_XSS component set, which
  // with XSAVES denied must be empty. Asserted, because a regression here is a
  // guest laying out a compacted XSAVE area we cannot save into; merely reading
  // this leaf would not check that contract.
  EXPECT_EQ(0u, main_leaf[4] & (1u << 1), "XSAVEC must not be advertised\n");
  EXPECT_EQ(0u, main_leaf[4] & (1u << 3), "XSAVES/XRSTORS must not be advertised\n");
  EXPECT_EQ(0u, main_leaf[5],
            "with EAX[1] and EAX[3] both zero, Table 3-8 requires EBX to enumerate zero\n");
  EXPECT_EQ(0u, main_leaf[6], "and the IA32_XSS component set must be empty\n");
  EXPECT_EQ(0u, main_leaf[7], "and the IA32_XSS component set must be empty\n");

  // THE WHOLE LEAF, as a guest reads it on this host. Printed rather than
  // asserted: the assertions above are the contract, this is the answer to
  // "what do we actually hand a guest here", which keeps being reconstructed
  // by hand from source.
  printf("CPUID leaf 0xD as handed to a guest on THIS host (guest XCR0 = x87|SSE):\n");
  printf("  D/0  EAX=0x%08x EBX=0x%08x ECX=0x%08x EDX=0x%08x\n", main_leaf[0], main_leaf[1],
         main_leaf[2], main_leaf[3]);
  printf("  D/1  EAX=0x%08x EBX=0x%08x ECX=0x%08x EDX=0x%08x\n", main_leaf[4], main_leaf[5],
         main_leaf[6], main_leaf[7]);
  for (uint32_t s = kFirstSubleaf; s <= kLastSubleaf; ++s) {
    const uint32_t i = s - kFirstSubleaf;
    printf("  D/%u  size=%-6u offset=%-6u ecx|edx=%-6u (advertised in the bitmap: %s)\n", s,
           comp_size[i], comp_offset[i], comp_rest[i],
           (guest_eax & (1u << s)) != 0 ? "yes" : "no");
  }
  printf("leaf 0xD consistency OK: guest sees EAX=%#x EBX=%u ECX=%u EDX=%#x; the bitmap and the "
         "per-component subleaves imply ECX=%u%s. Host CPUID.D.0 EAX=%#x ECX=%u -- so this run "
         "%s\n",
         guest_eax, guest_ebx, guest_ecx, guest_edx, implied,
         bitmap_within_walk ? "" : " (NOT CHECKED: a component above 9 is advertised)", host_eax,
         host_ecx,
         // Against the IMPLIED value, not against the guest's: when the bug is
         // present those two are what differ, and comparing the guest's ECX
         // with the host's would have called the red run "vacuous".
         host_ecx != implied
             ? "DISCRIMINATED: the host's ECX differs from the honest one, so a pass-through "
               "would have been caught"
             : "was VACUOUS for the ECX mask: this part withholds no component that affects the "
               "size, so the host's ECX was already right");
#else
  printf("Not x86_64; skipping.\n");
#endif  // __x86_64__

  END_TEST;
}

// Guest CPUID leaf 0 must not advertise basic leaves this hypervisor does
// not answer.
//
// Leaf 0 is passed straight through from the host, so the guest is told the host's
// real maximum basic leaf -- but the pass-through range stops at
// MAX_SUPPORTED_CPUID (0x17), and anything above that falls to handle_cpuid's
// `default` arm. On a part whose maximum basic leaf is above 0x17, the guest is
// therefore told leaf 0x1f (v2 extended topology) exists and is handed the
// contents of some other leaf when it asks. That also defeats the file's own
// stated intent two cases higher up -- "reporting [leaf 0x1f] breaks Linux
// guests, we can get away with reporting only the older topology" -- because on
// such a part the guest is told 0x1f is there whatever the topology case does.
//
// WHAT THIS HOST CAN AND CANNOT SHOW, measured rather than assumed.
// A measured i5-8500T reports a maximum basic leaf of 0x16, which is
// BELOW MAX_SUPPORTED_CPUID. So every leaf above 0x16 is out of range for the
// guest too, and returning the highest basic leaf's data for it is exactly what
// Volume 2's CPUID page mandates -- the defect is not reachable here at all. The
// the sharper measured statement is that the defect is
// UNREACHABLE on this silicon, and the way to reach it is
// `qemu -cpu host,level=0x1f`, which raises the maximum basic leaf the Cerise
// kernel itself sees without touching anything else. That is how the red run for
// this assertion was taken.
//
// The first assertion is therefore VACUOUS in the default configuration and the
// print below says so, in the shape the MPX test established. The second checks the
// claim this fix rests on -- that once leaf 0 is clamped, `default`'s
// `cpuid_c(MAX_SUPPORTED_CPUID)` and "the highest leaf the guest is told about" are
// the same answer, because the processor applies the very same out-of-range clamp.
// It is a check on the REASONING and is regression-vacuous for the clamp itself:
// on a part whose ceiling is at or below MAX_SUPPORTED_CPUID the processor makes
// both sides equal whatever this kernel does.
//
// The extended ceiling is asserted the same way. It is vacuous on every part this
// kernel has run on -- a measured i5-8500T reports 0x80000008, far below
// MAX_SUPPORTED_CPUID_EXT (0x80000021) -- and `qemu -cpu host,xlevel=...` is the
// lever that reaches it.
bool vcpu_cpuid_leaf_zero_matches_what_is_answered() {
  BEGIN_TEST;

#ifdef __x86_64__
  constexpr uint16_t kMaxLeafPort = 0x10;
  constexpr uint16_t kAgreePort = 0x11;
  constexpr uint16_t kV2TopologyPort = 0x12;
  // A leaf above every basic leaf and below the hypervisor-reserved range, so it
  // is out of range in any configuration.
  constexpr uint32_t kOutOfRangeLeaf = 0x30000000;

  //  31 C0             xor eax,eax
  //  31 C9             xor ecx,ecx
  //  0F A2             cpuid
  //  89 C7             mov edi,eax          ; the max basic leaf we are told
  //  BA 10 00 00 00    mov edx,0x10
  //  EF                out dx,eax           ; report it, 32 bits
  //  89 F8             mov eax,edi
  //  31 C9             xor ecx,ecx
  //  0F A2             cpuid                ; CPUID(max basic leaf)
  //  41 89 C0          mov r8d,eax
  //  41 89 D9          mov r9d,ebx
  //  41 89 CA          mov r10d,ecx
  //  41 89 D3          mov r11d,edx
  //  B8 00 00 00 30    mov eax,0x30000000
  //  31 C9             xor ecx,ecx
  //  0F A2             cpuid                ; CPUID(out of range)
  //  44 31 C0          xor eax,r8d
  //  44 31 CB          xor ebx,r9d
  //  44 31 D1          xor ecx,r10d
  //  44 31 DA          xor edx,r11d
  //  09 D8             or eax,ebx
  //  09 C8             or eax,ecx
  //  09 D0             or eax,edx           ; ZF iff all four registers agreed
  //  0F 94 C0          sete al
  //  E6 11             out 0x11, al
  //  B8 1F 00 00 00    mov eax,0x1f
  //  31 C9             xor ecx,ecx
  //  0F A2             cpuid
  //  BA 12 00 00 00    mov edx,0x12
  //  EF                out dx,eax           ; leaf 0x1f eax, for the log
  //  F4                hlt
  const uint8_t code[] = {
      0x31, 0xC0, 0x31, 0xC9, 0x0F, 0xA2, 0x89, 0xC7,
      0xBA, static_cast<uint8_t>(kMaxLeafPort), 0x00, 0x00, 0x00, 0xEF,
      0x89, 0xF8, 0x31, 0xC9, 0x0F, 0xA2,
      0x41, 0x89, 0xC0, 0x41, 0x89, 0xD9, 0x41, 0x89, 0xCA, 0x41, 0x89, 0xD3,
      0xB8, 0x00, 0x00, 0x00, 0x30, 0x31, 0xC9, 0x0F, 0xA2,
      0x44, 0x31, 0xC0, 0x44, 0x31, 0xCB, 0x44, 0x31, 0xD1, 0x44, 0x31, 0xDA,
      0x09, 0xD8, 0x09, 0xC8, 0x09, 0xD0, 0x0F, 0x94, 0xC0,
      0xE6, static_cast<uint8_t>(kAgreePort),
      0xB8, 0x1F, 0x00, 0x00, 0x00, 0x31, 0xC9, 0x0F, 0xA2,
      0xBA, static_cast<uint8_t>(kV2TopologyPort), 0x00, 0x00, 0x00, 0xEF,
      //  B8 00 00 00 80  mov eax,0x80000000
      //  31 C9           xor ecx,ecx
      //  0F A2           cpuid
      //  BA 12 00 00 00  mov edx,0x12
      //  EF              out dx,eax          ; the extended ceiling
      0xB8, 0x00, 0x00, 0x00, 0x80, 0x31, 0xC9, 0x0F, 0xA2,
      0xBA, static_cast<uint8_t>(kV2TopologyPort), 0x00, 0x00, 0x00, 0xEF,
      0xF4};
  static_assert(kOutOfRangeLeaf == 0x30000000, "the immediate above encodes this leaf");

  fbl::RefPtr<VmObjectPaged> ram;
  ASSERT_EQ(ZX_OK, VmObjectPaged::Create(PMM_ALLOC_FLAG_ANY, 0u, kGuestRamSize, &ram), "ram\n");
  ASSERT_EQ(ZX_OK, WriteIdentityTables(ram), "tables\n");
  ASSERT_EQ(ZX_OK, ram->Write(code, kCodeGpa, sizeof(code)), "code\n");
  ASSERT_EQ(ZX_OK, ram->CommitRange(0, kGuestRamSize), "commit\n");

  auto lg = CreateLiveGuest(ram, kCodeGpa);
  if (lg.is_error() && lg.status_value() == ZX_ERR_NOT_SUPPORTED) {
    printf("VMX not supported here; skipping CPUID max-leaf test.\n");
    return true;
  }
  ASSERT_EQ(ZX_OK, lg.status_value(), "create live guest\n");
  Vcpu* vcpu = lg->vcpu.get();
  // 0x10 and 0x11 are already trapped by CreateLiveGuest; only 0x12 is new.
  ASSERT_EQ(ZX_OK,
            lg->guest->SetTrap(ZX_GUEST_TRAP_IO, kV2TopologyPort, 1, nullptr, kV2TopologyPort)
                .status_value(),
            "trap leaf-0x1f report port\n");

  // The host's own maximum basic leaf, read here rather than through the same
  // helper the kernel uses, so this expectation is not the implementation
  // agreeing with itself.
  uint32_t host_max_basic = 0;
  {
    cpuid_leaf l;
    ASSERT_TRUE(x86_get_cpuid_subleaf(X86_CPUID_BASE, 0, &l), "host leaf 0\n");
    host_max_basic = l.a;
  }
  const uint32_t expected_max =
      host_max_basic < MAX_SUPPORTED_CPUID ? host_max_basic : uint32_t{MAX_SUPPORTED_CPUID};

  zx_port_packet_t maxleaf = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(maxleaf).status_value(), "enter (max leaf)\n");
  ASSERT_EQ(static_cast<uint8_t>(ZX_PKT_TYPE_GUEST_IO), static_cast<uint8_t>(maxleaf.type), "io\n");
  ASSERT_EQ(static_cast<uint32_t>(kMaxLeafPort), static_cast<uint32_t>(maxleaf.guest_io.port),
            "max-leaf port\n");
  EXPECT_EQ(expected_max, maxleaf.guest_io.u32,
            "guest CPUID leaf 0 must advertise no basic leaf above the highest one this "
            "hypervisor answers (MAX_SUPPORTED_CPUID), and no lower than the host's own max\n");

  zx_port_packet_t agree = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(agree).status_value(), "enter (out-of-range agreement)\n");
  ASSERT_EQ(static_cast<uint32_t>(kAgreePort), static_cast<uint32_t>(agree.guest_io.port),
            "agreement port\n");
  EXPECT_EQ(1u, static_cast<uint32_t>(agree.guest_io.data[0]),
            "an out-of-range leaf must return the data of the highest basic leaf the guest is told "
            "about (Volume 2, CPUID) -- if these differ, handle_cpuid's `default` arm and leaf 0 "
            "disagree about what the ceiling is\n");

  zx_port_packet_t v2 = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(v2).status_value(), "enter (leaf 0x1f)\n");
  ASSERT_EQ(static_cast<uint32_t>(kV2TopologyPort), static_cast<uint32_t>(v2.guest_io.port),
            "leaf 0x1f port\n");

  uint32_t host_max_ext = 0;
  {
    cpuid_leaf l;
    ASSERT_TRUE(x86_get_cpuid_subleaf(X86_CPUID_EXT_BASE, 0, &l), "host leaf 0x80000000\n");
    host_max_ext = l.a;
  }
  const uint32_t expected_max_ext = host_max_ext < MAX_SUPPORTED_CPUID_EXT
                                        ? host_max_ext
                                        : uint32_t{MAX_SUPPORTED_CPUID_EXT};
  zx_port_packet_t ext = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(ext).status_value(), "enter (extended ceiling)\n");
  ASSERT_EQ(static_cast<uint32_t>(kV2TopologyPort), static_cast<uint32_t>(ext.guest_io.port),
            "extended ceiling port\n");
  EXPECT_EQ(expected_max_ext, ext.guest_io.u32,
            "guest CPUID leaf 0x80000000 must advertise no extended leaf above the highest one "
            "this hypervisor answers\n");

  printf("CPUID max-leaf OK: host max basic leaf %#x, MAX_SUPPORTED_CPUID %#x, guest told %#x; an "
         "out-of-range leaf agrees with it; leaf 0x1f eax = %#x; host max extended leaf %#x, "
         "guest told %#x. This run %s\n",
         host_max_basic, static_cast<uint32_t>(MAX_SUPPORTED_CPUID), maxleaf.guest_io.u32,
         v2.guest_io.u32, host_max_ext, ext.guest_io.u32,
         host_max_basic > MAX_SUPPORTED_CPUID
             ? "DISCRIMINATED: without the clamp the guest would have been told about leaves "
               "0x18-onwards that fall to `default`"
             : "was VACUOUS for the clamp: this part's max basic leaf is already at or below "
               "MAX_SUPPORTED_CPUID, so there is nothing to clamp (use `qemu -cpu "
               "host,level=0x1f` to reach it)");
#else
  printf("Not x86_64; skipping.\n");
#endif  // __x86_64__

  END_TEST;
}

// A guest XSETBV must take effect.
//
// The handler validated the value and stored it in `guest_state.xcr0`, and that
// was the end of it: the physical XCR0 was written only by
// LoadExtendedRegisters(), and SaveExtendedRegisters() overwrote the field from
// XGETBV -- so every reload read back the value the previous load had installed
// and the guest's write was clobbered before it could ever be loaded. XSETBV
// exits unconditionally from VMX non-root operation (Volume 3, Section 25.1.2),
// so the guest could not reach the register itself either. A guest that enabled or
// disabled any component silently did not get what it asked for; on a measured
// Coffee Lake processor the initial value happens to be what Windows would ask
// for, which is the only reason this has not bitten.
//
// EVERY ASSERTION IS THE GUEST READING THE HARDWARE, with XGETBV, and not the
// hypervisor reporting what it believes it wrote. `guest_state.xcr0` was already
// correct before this fix -- asserting on it through ReadState would have passed
// against the bug.
//
// The three reports are each other's controls:
//
//   * narrowing (drop AVX) must be observed. This is the assertion that fails
//     against the old behaviour, where report 2 reads back report 1.
//   * widening back to the initial value must ALSO be observed, so a "fix" that
//     only ever masks components off fails. Widening is also the direction with
//     the host-safety coupling, so it is the one worth exercising.
//   * report 1 is printed and checked for x87+SSE, and if the machine's initial
//     XCR0 is already x87+SSE then narrowing to x87+SSE proves nothing and the
//     output says so instead of a green tick implying otherwise.
bool vcpu_guest_xsetbv_takes_effect() {
  BEGIN_TEST;

#ifdef __x86_64__
  constexpr uint16_t kXcr0Port = 0x12;
  constexpr uint32_t kNarrowed = X86_XSAVE_STATE_BIT_X87 | X86_XSAVE_STATE_BIT_SSE;

  //  31 C9              xor ecx,ecx
  //  0F 01 D0           xgetbv                ; eax = XCR0[31:0]
  //  41 89 C4           mov r12d,eax          ; keep it; nothing below clobbers r12
  //  BA 12 00 00 00     mov edx,0x12
  //  EF                 out dx,eax            ; report 1: the initial XCR0
  //  31 C9              xor ecx,ecx
  //  31 D2              xor edx,edx
  //  B8 03 00 00 00     mov eax,3
  //  0F 01 D1           xsetbv                ; narrow to x87|SSE
  //  31 C9              xor ecx,ecx
  //  0F 01 D0           xgetbv
  //  BA 12 00 00 00     mov edx,0x12          ; edx held XCR0[63:32], which is unused
  //  EF                 out dx,eax            ; report 2: after narrowing
  //  31 C9              xor ecx,ecx
  //  31 D2              xor edx,edx
  //  44 89 E0           mov eax,r12d
  //  0F 01 D1           xsetbv                ; widen back to the initial value
  //  31 C9              xor ecx,ecx
  //  0F 01 D0           xgetbv
  //  BA 12 00 00 00     mov edx,0x12
  //  EF                 out dx,eax            ; report 3: after widening
  //  F4                 hlt
  const uint8_t code[] = {
      0x31, 0xC9, 0x0F, 0x01, 0xD0, 0x41, 0x89, 0xC4,
      0xBA, static_cast<uint8_t>(kXcr0Port), 0x00, 0x00, 0x00, 0xEF,
      0x31, 0xC9, 0x31, 0xD2, 0xB8, 0x03, 0x00, 0x00, 0x00, 0x0F, 0x01, 0xD1,
      0x31, 0xC9, 0x0F, 0x01, 0xD0,
      0xBA, static_cast<uint8_t>(kXcr0Port), 0x00, 0x00, 0x00, 0xEF,
      0x31, 0xC9, 0x31, 0xD2, 0x44, 0x89, 0xE0, 0x0F, 0x01, 0xD1,
      0x31, 0xC9, 0x0F, 0x01, 0xD0,
      0xBA, static_cast<uint8_t>(kXcr0Port), 0x00, 0x00, 0x00, 0xEF,
      0xF4};

  // A SECOND blob, run only where the guest's initial XCR0 is exactly x87|SSE|AVX,
  // which asks the question the three XGETBV reports above cannot: what is IN a
  // component the guest has just re-enabled?
  //
  // XSAVE and XRSTOR select components by the LIVE XCR0, so while AVX is off the
  // upper halves of the YMM registers are neither saved into the guest's buffer nor
  // restored from it -- they keep whatever the physical registers hold, which after
  // any deschedule is the HOST's. Widening XCR0 with a bare x86_xsetbv would hand
  // those to the guest. The XGETBV reports pass either way. The fix cycles the
  // register file through the guest's own buffer, so a
  // newly selected component comes back INITIALIZED -- Volume 1, Section 13.8.
  //
  //  C5 FD 76 C0        vpcmpeqd ymm0,ymm0,ymm0   ; all ones, both halves
  //  31 C9 31 D2        xor ecx,ecx ; xor edx,edx
  //  B8 03 00 00 00     mov eax,3
  //  0F 01 D1           xsetbv                    ; AVX off
  //  31 C9 31 D2        xor ecx,ecx ; xor edx,edx
  //  B8 07 00 00 00     mov eax,7
  //  0F 01 D1           xsetbv                    ; AVX back on
  //  C4 E3 7D 19 C1 01  vextractf128 xmm1,ymm0,1  ; the AVX component
  //  C5 F9 7E C8        vmovd eax,xmm1
  //  BA 12 00 00 00     mov edx,0x12
  //  EF                 out dx,eax                ; report 4
  //  C5 F9 7E C0        vmovd eax,xmm0            ; the SSE component
  //  BA 12 00 00 00     mov edx,0x12
  //  EF                 out dx,eax                ; report 5
  //  F4                 hlt
  constexpr uint64_t kAvxCodeGpa = kCodeGpa + 0x100;
  const uint8_t avx_code[] = {
      0xC5, 0xFD, 0x76, 0xC0,
      0x31, 0xC9, 0x31, 0xD2, 0xB8, 0x03, 0x00, 0x00, 0x00, 0x0F, 0x01, 0xD1,
      0x31, 0xC9, 0x31, 0xD2, 0xB8, 0x07, 0x00, 0x00, 0x00, 0x0F, 0x01, 0xD1,
      0xC4, 0xE3, 0x7D, 0x19, 0xC1, 0x01,
      0xC5, 0xF9, 0x7E, 0xC8,
      0xBA, static_cast<uint8_t>(kXcr0Port), 0x00, 0x00, 0x00, 0xEF,
      0xC5, 0xF9, 0x7E, 0xC0,
      0xBA, static_cast<uint8_t>(kXcr0Port), 0x00, 0x00, 0x00, 0xEF,
      0xF4};

  fbl::RefPtr<VmObjectPaged> ram;
  ASSERT_EQ(ZX_OK, VmObjectPaged::Create(PMM_ALLOC_FLAG_ANY, 0u, kGuestRamSize, &ram), "ram\n");
  ASSERT_EQ(ZX_OK, WriteIdentityTables(ram), "tables\n");
  ASSERT_EQ(ZX_OK, ram->Write(code, kCodeGpa, sizeof(code)), "code\n");
  ASSERT_EQ(ZX_OK, ram->Write(avx_code, kAvxCodeGpa, sizeof(avx_code)), "avx code\n");
  ASSERT_EQ(ZX_OK, ram->CommitRange(0, kGuestRamSize), "commit\n");

  auto lg = CreateLiveGuest(ram, kCodeGpa);
  if (lg.is_error() && lg.status_value() == ZX_ERR_NOT_SUPPORTED) {
    printf("VMX not supported here; skipping XSETBV-effectiveness test.\n");
    return true;
  }
  ASSERT_EQ(ZX_OK, lg.status_value(), "create live guest\n");
  Vcpu* vcpu = lg->vcpu.get();
  ASSERT_EQ(ZX_OK,
            lg->guest->SetTrap(ZX_GUEST_TRAP_IO, kXcr0Port, 1, nullptr, kXcr0Port).status_value(),
            "trap XCR0 report port\n");

  uint32_t reports[3] = {};
  for (uint32_t i = 0; i < 3; i++) {
    zx_port_packet_t p = {};
    ASSERT_EQ(ZX_OK, vcpu->Enter(p).status_value(), "enter\n");
    ASSERT_EQ(static_cast<uint8_t>(ZX_PKT_TYPE_GUEST_IO), static_cast<uint8_t>(p.type), "io\n");
    ASSERT_EQ(static_cast<uint32_t>(kXcr0Port), static_cast<uint32_t>(p.guest_io.port),
              "XCR0 report port\n");
    reports[i] = p.guest_io.u32;
  }

  ASSERT_EQ(kNarrowed, reports[0] & kNarrowed,
            "the guest's initial XCR0 must at least have x87 and SSE, or nothing below makes "
            "sense\n");
  EXPECT_EQ(kNarrowed, reports[1],
            "after XSETBV to x87|SSE the guest's own XGETBV must read back x87|SSE. Reading back "
            "the INITIAL value means the write never reached the physical XCR0\n");
  EXPECT_EQ(reports[0], reports[2],
            "and XSETBV back to the initial value must be observed too -- widening is the "
            "direction a mask-only implementation gets wrong\n");

  // The component-content half, where the guest's initial XCR0 makes it askable.
  constexpr uint32_t kX87SseAvx = 0x7;
  if (reports[0] == kX87SseAvx) {
    fbl::AllocChecker ac;
    ktl::unique_ptr<VcpuArchState> s(new (&ac) VcpuArchState{});
    ASSERT_TRUE(ac.check(), "alloc arch state\n");
    ASSERT_EQ(ZX_OK, vcpu->SaveArchState(*s).status_value(), "save\n");
    s->rip = kAvxCodeGpa;
    ASSERT_EQ(ZX_OK, vcpu->RestoreArchState(*s).status_value(), "jump to the AVX blob\n");

    uint32_t avx_reports[2] = {};
    for (uint32_t i = 0; i < 2; i++) {
      zx_port_packet_t p = {};
      ASSERT_EQ(ZX_OK, vcpu->Enter(p).status_value(), "enter (AVX blob)\n");
      ASSERT_EQ(static_cast<uint8_t>(ZX_PKT_TYPE_GUEST_IO), static_cast<uint8_t>(p.type), "io\n");
      ASSERT_EQ(static_cast<uint32_t>(kXcr0Port), static_cast<uint32_t>(p.guest_io.port),
                "XCR0 report port\n");
      avx_reports[i] = p.guest_io.u32;
    }
    EXPECT_EQ(0u, avx_reports[0],
              "a component the guest has just re-enabled must come back INITIALIZED. Reading "
              "back the pre-narrowing pattern means the physical registers were never cycled, "
              "and after a deschedule those registers hold the HOST's data, not the guest's\n");
    // The control, and without it "zero everything on any XCR0 change" would pass.
    EXPECT_EQ(0xFFFFFFFFu, avx_reports[1],
              "while a component that stayed enabled throughout must be PRESERVED\n");
    printf("XSETBV component-state OK: after narrow+widen the AVX half of ymm0 read %#x (init) "
           "and the SSE half read %#x (preserved)\n",
           avx_reports[0], avx_reports[1]);
  } else {
    printf("XSETBV component-state: SKIPPED, the guest's initial XCR0 is %#x rather than %#x\n",
           reports[0], kX87SseAvx);
  }

  printf("XSETBV effectiveness OK: guest XGETBV read %#x initially, %#x after narrowing to "
         "x87|SSE, %#x after widening back. This run %s\n",
         reports[0], reports[1], reports[2],
         reports[0] == kNarrowed
             ? "was VACUOUS: this machine's initial guest XCR0 is already x87|SSE, so there was "
               "nothing to narrow"
             : "DISCRIMINATED: the initial XCR0 differs from the narrowed one, so an inert XSETBV "
               "would have reported the initial value twice");
#else
  printf("Not x86_64; skipping.\n");
#endif  // __x86_64__

  END_TEST;
}

// The guest's TSC is the hypervisor's to choose, and both ways the guest
// can read it must agree with the choice.
//
// VMCS TSC_OFFSET (0x2010) was not defined in vcpu_priv.h and nothing wrote it, so
// a guest read the host's raw counter -- whose epoch is the machine's power-on --
// through RDTSC and through RDMSR of IA32_TIME_STAMP_COUNTER alike. Tolerable for
// a boot (Windows calibrates against CPUID leaf 0x15 rather than assuming the TSC
// starts near zero) and a correctness defect for snapshot restore, where a restored
// snapshot's guest time jumps forward by the whole save-to-restore wall-clock gap
// with nothing able to correct it.
//
// THE TWO ASSERTIONS ARE EACH OTHER'S CONTROL, and this is the part worth reading
// before changing either:
//
//   * RDTSC is applied by the PROCESSOR. Nothing in this kernel can fake it, so a
//     shift in what RDTSC returns proves the VMCS field and the "use TSC
//     offsetting" control are really programmed. An implementation that emulated
//     the MSR in software and never touched the VMCS fails this one.
//   * RDMSR 0x10 is EMULATED by handle_rdmsr, and the processor does nothing for
//     it. An implementation that programs the VMCS and forgets this read fails
//     that one -- and would leave a guest whose two views of one counter differ by
//     the offset, which is the sharper version of the same bug.
//
// Neither alone is sufficient, and the third assertion -- that the two agree with
// each other after the shift -- is the one a guest would actually notice.
//
// The offset is chosen far larger than any plausible elapsed time between the two
// passes so that "the offset took effect" and "time passed" cannot be confused: at
// ~2.1 GHz, 2^40 ticks is about eight minutes and the tolerance below is about two
// seconds.
bool vcpu_guest_tsc_honours_the_vmcs_offset() {
  BEGIN_TEST;

#ifdef __x86_64__
  constexpr uint16_t kTscPort = 0x12;
  constexpr int64_t kOffset = int64_t{1} << 40;
  constexpr uint64_t kTolerance = uint64_t{1} << 32;

  //  0F 31              rdtsc                 ; edx:eax
  //  41 89 C4           mov r12d,eax
  //  41 89 D5           mov r13d,edx
  //  B9 10 00 00 00     mov ecx,0x10          ; IA32_TIME_STAMP_COUNTER
  //  0F 32              rdmsr
  //  41 89 C6           mov r14d,eax
  //  41 89 D7           mov r15d,edx
  //  BA 12 00 00 00     mov edx,0x12
  //  44 89 E0           mov eax,r12d
  //  EF                 out dx,eax            ; RDTSC low
  //  44 89 E8           mov eax,r13d
  //  EF                 out dx,eax            ; RDTSC high
  //  44 89 F0           mov eax,r14d
  //  EF                 out dx,eax            ; RDMSR low
  //  44 89 F8           mov eax,r15d
  //  EF                 out dx,eax            ; RDMSR high
  //  F4                 hlt
  const uint8_t code[] = {
      0x0F, 0x31, 0x41, 0x89, 0xC4, 0x41, 0x89, 0xD5,
      0xB9, 0x10, 0x00, 0x00, 0x00, 0x0F, 0x32, 0x41, 0x89, 0xC6, 0x41, 0x89, 0xD7,
      0xBA, static_cast<uint8_t>(kTscPort), 0x00, 0x00, 0x00,
      0x44, 0x89, 0xE0, 0xEF,
      0x44, 0x89, 0xE8, 0xEF,
      0x44, 0x89, 0xF0, 0xEF,
      0x44, 0x89, 0xF8, 0xEF,
      0xF4};

  fbl::RefPtr<VmObjectPaged> ram;
  ASSERT_EQ(ZX_OK, VmObjectPaged::Create(PMM_ALLOC_FLAG_ANY, 0u, kGuestRamSize, &ram), "ram\n");
  ASSERT_EQ(ZX_OK, WriteIdentityTables(ram), "tables\n");
  ASSERT_EQ(ZX_OK, ram->Write(code, kCodeGpa, sizeof(code)), "code\n");
  ASSERT_EQ(ZX_OK, ram->CommitRange(0, kGuestRamSize), "commit\n");

  auto lg = CreateLiveGuest(ram, kCodeGpa);
  if (lg.is_error() && lg.status_value() == ZX_ERR_NOT_SUPPORTED) {
    printf("VMX not supported here; skipping TSC-offset test.\n");
    return true;
  }
  ASSERT_EQ(ZX_OK, lg.status_value(), "create live guest\n");
  Vcpu* vcpu = lg->vcpu.get();
  ASSERT_EQ(ZX_OK,
            lg->guest->SetTrap(ZX_GUEST_TRAP_IO, kTscPort, 1, nullptr, kTscPort).status_value(),
            "trap TSC report port\n");

  fbl::AllocChecker ac;
  ktl::unique_ptr<VcpuArchState> s(new (&ac) VcpuArchState{});
  ASSERT_TRUE(ac.check(), "alloc arch state\n");

  // Reads the guest's four reports back as two 64-bit values.
  struct Pass {
    uint64_t rdtsc;
    uint64_t rdmsr;
  };
  auto run = [&](Pass& out) {
    uint32_t dwords[4] = {};
    for (uint32_t i = 0; i < 4; i++) {
      zx_port_packet_t p = {};
      if (auto r = vcpu->Enter(p); r.is_error()) {
        return r.status_value();
      }
      if (p.type != ZX_PKT_TYPE_GUEST_IO || p.guest_io.port != kTscPort) {
        return ZX_ERR_BAD_STATE;
      }
      dwords[i] = p.guest_io.u32;
    }
    out.rdtsc = (static_cast<uint64_t>(dwords[1]) << 32) | dwords[0];
    out.rdmsr = (static_cast<uint64_t>(dwords[3]) << 32) | dwords[2];
    return ZX_OK;
  };
  // Unsigned difference, so a wrap of the 64-bit counter is not a huge number.
  auto near = [](uint64_t a, uint64_t b, uint64_t tolerance) {
    const uint64_t d = a - b;
    return d <= tolerance || (0 - d) <= tolerance;
  };

  ASSERT_EQ(0, vcpu->TscOffset(), "a fresh VCPU must start with no TSC offset\n");
  Pass zero = {};
  ASSERT_EQ(ZX_OK, run(zero), "first pass (offset 0)\n");
  EXPECT_TRUE(near(zero.rdmsr, zero.rdtsc, kTolerance),
              "with no offset, RDTSC and RDMSR 0x10 must already be the same counter\n");

  const zx_status_t set = vcpu->SetTscOffset(kOffset).status_value();
  if (set == ZX_ERR_NOT_SUPPORTED) {
    printf("TSC offset: this machine does not offer TSC offsetting (the primary processor-based "
           "control is not settable), so only the offset-0 half of this test ran. Guest RDTSC "
           "%#lx, RDMSR 0x10 %#lx.\n",
           zero.rdtsc, zero.rdmsr);
    END_TEST;
  }
  ASSERT_EQ(ZX_OK, set, "SetTscOffset\n");
  ASSERT_EQ(kOffset, vcpu->TscOffset(), "and it must be reported back\n");

  ASSERT_EQ(ZX_OK, vcpu->SaveArchState(*s).status_value(), "save\n");
  s->rip = kCodeGpa;
  ASSERT_EQ(ZX_OK, vcpu->RestoreArchState(*s).status_value(), "rewind to the start\n");

  Pass offset = {};
  ASSERT_EQ(ZX_OK, run(offset), "second pass (offset programmed)\n");

  // 1: the processor applied the field. This cannot be faked from software.
  EXPECT_TRUE(near(offset.rdtsc - zero.rdtsc, static_cast<uint64_t>(kOffset), kTolerance),
              "the guest's RDTSC must have moved by exactly the programmed offset -- the processor "
              "adds VMCS TSC_OFFSET itself, so this failing means the field or the `use TSC "
              "offsetting` control is not really programmed\n");
  // 2: and the emulated MSR read agrees. This is the one a VMCS-only fix misses.
  EXPECT_TRUE(near(offset.rdmsr - zero.rdmsr, static_cast<uint64_t>(kOffset), kTolerance),
              "RDMSR 0x10 must have moved by the same offset. It is emulated by handle_rdmsr, so "
              "the processor does nothing for it -- this failing means the guest's two views of "
              "one counter differ by the offset\n");
  // 3: which is the property a guest would actually notice.
  EXPECT_TRUE(near(offset.rdmsr, offset.rdtsc, kTolerance),
              "and the two must still be the same counter as each other\n");

  printf("TSC offset OK: offset 0 gave guest RDTSC %#lx / RDMSR 0x10 %#lx; offset %#lx gave %#lx / "
         "%#lx -- both moved by %#lx (tolerance %#lx). TSC offsetting IS available on this "
         "machine.\n",
         zero.rdtsc, zero.rdmsr, static_cast<uint64_t>(kOffset), offset.rdtsc, offset.rdmsr,
         offset.rdtsc - zero.rdtsc, kTolerance);
#else
  printf("Not x86_64; skipping.\n");
#endif  // __x86_64__

  END_TEST;
}

// CPUID.1:ECX.OSXSAVE follows the GUEST's CR4, not the host's.
//
// Volume 2, Table 3-8 makes bit 27 a mirror of CR4.OSXSAVE rather than a
// capability: it says "the OS has enabled XSETBV/XGETBV", and software is told
// to test it before executing XGETBV, which #UDs unless CR4.OSXSAVE is set.
// This hypervisor passed the host's bit straight through, so a guest that
// cleared its own CR4.OSXSAVE was still told the instruction was available.
//
// The guest here does exactly that, and the assertion is on what it reads:
//
//   1. read CPUID.1:ECX with CR4.OSXSAVE set   -> bit 27 must be 1
//   2. clear CR4.OSXSAVE
//   3. read CPUID.1:ECX again                  -> bit 27 must be 0
//   4. execute XGETBV                          -> must #UD, and the guest's own
//                                                 #UD handler must report it
//
// Step 1 is what stops step 3 from passing for the wrong reason: a hypervisor
// that simply cleared bit 27 always would satisfy step 3 and fail step 1, and a
// guest that could never run XGETBV at all would fail step 1 too. Step 4 is the
// consequence the bit exists to predict -- it is the fault a real guest took,
// and asserting the CPUID bit without it would leave "we report it correctly and
// the instruction works anyway" indistinguishable from a fix.
//
// Observed red on the unfixed tree: step 3 read bit 27 as 1 (the host's), which
// is precisely the lie that made a Windows boot module execute XGETBV and die.
bool vcpu_cpuid_osxsave_follows_guest_cr4() {
  BEGIN_TEST;

#ifdef __x86_64__
  auto guest_result = Guest::Create();
  if (guest_result.is_error() && guest_result.status_value() == ZX_ERR_NOT_SUPPORTED) {
    printf("VMX not supported here; skipping OSXSAVE mirror test.\n");
    return true;
  }
  ASSERT_EQ(ZX_OK, guest_result.status_value(), "Guest::Create failed\n");
  ktl::unique_ptr<Guest> guest = ktl::move(guest_result.value());

  constexpr uint64_t kGdtGpa = 0x6000;
  constexpr uint64_t kIdtGpa = 0x6800;
  constexpr uint64_t kUdHandlerGpa = 0x8000;
  constexpr uint64_t kStackTop = 0x9000;
  constexpr uint8_t kWidePort = 0x13;
  // 0x17, not 0x14: a 4-byte I/O trap reserves four consecutive ports, so
  // kWidePort already owns 0x13-0x16 and a trap at 0x14 is refused with
  // ZX_ERR_ALREADY_EXISTS. (Measured -- this test was written with 0x14 and the
  // trap installation, not an assertion, is what failed.)
  constexpr uint8_t kUdPort = 0x17;
  // CR4.OSXSAVE. Not in CR4_GUEST_HOST_MASK (which holds only VMXE), so the
  // guest's `mov cr4` below lands in GUEST_CR4 without exiting -- which is
  // exactly why reading GUEST_CR4 in handle_cpuid is correct.
  constexpr uint32_t kCr4Osxsave = 1u << 18;

  fbl::RefPtr<VmObjectPaged> ram;
  ASSERT_EQ(ZX_OK, VmObjectPaged::Create(PMM_ALLOC_FLAG_ANY, 0u, kGuestRamSize, &ram), "ram\n");
  ASSERT_EQ(ZX_OK, WriteIdentityTables(ram), "tables\n");

  uint8_t buf[256];
  size_t n = 0;
  auto emit = [&](std::initializer_list<uint8_t> bytes) {
    for (uint8_t b : bytes) {
      buf[n++] = b;
    }
  };
  auto emit32 = [&](uint32_t v) {
    emit({static_cast<uint8_t>(v), static_cast<uint8_t>(v >> 8), static_cast<uint8_t>(v >> 16),
          static_cast<uint8_t>(v >> 24)});
  };
  // mov eax, 1 ; xor ecx, ecx ; cpuid ; out kWidePort, eax  -- reports ECX
  auto report_cpuid_ecx = [&]() {
    emit({0xB8});
    emit32(1);
    emit({0x31, 0xC9});              // xor ecx, ecx
    emit({0x0F, 0xA2});              // cpuid
    emit({0x89, 0xC8});              // mov eax, ecx
    emit({0xE7, kWidePort});         // out kWidePort, eax
  };

  n = 0;
  // (1) Report ECX with CR4.OSXSAVE as the hypervisor left it (set: Setup()
  //     writes X86_CR4_OSXSAVE into GUEST_CR4).
  report_cpuid_ecx();
  // (2) Clear CR4.OSXSAVE. No exit: the bit is not in CR4_GUEST_HOST_MASK.
  emit({0x0F, 0x20, 0xE0});  // mov rax, cr4
  emit({0x25});              // and eax, imm32
  emit32(~kCr4Osxsave);
  emit({0x0F, 0x22, 0xE0});  // mov cr4, rax
  // (3) Report ECX again. The same instruction, the same register, a different
  //     required answer -- so a handler answering from a constant fails one.
  report_cpuid_ecx();
  // (4) XGETBV (0F 01 D0) with ECX=0. Must #UD now that CR4.OSXSAVE is clear.
  emit({0x31, 0xC9});              // xor ecx, ecx
  emit({0x0F, 0x01, 0xD0});        // xgetbv
  // Only reached if XGETBV did NOT fault.
  emit({0xB0, 0xBB, 0xE6, kUdPort});  // mov al, 0xBB ; out kUdPort, al
  emit({0xF4});                       // hlt
  ASSERT_EQ(ZX_OK, ram->Write(buf, kCodeGpa, n), "code\n");

  // The #UD handler: report that it ran, then stop.
  n = 0;
  emit({0xB0, 0x06, 0xE6, kUdPort});  // mov al, 6 (#UD vector) ; out kUdPort, al
  emit({0xF4});                       // hlt
  ASSERT_EQ(ZX_OK, ram->Write(buf, kUdHandlerGpa, n), "#UD handler\n");

  const uint8_t gdt_code[8] = {0xFF, 0xFF, 0x00, 0x00, 0x00, 0x9B, 0xAF, 0x00};
  ASSERT_EQ(ZX_OK, ram->Write(gdt_code, kGdtGpa + 8, sizeof(gdt_code)), "GDT code desc\n");
  {
    uint8_t gate[16];
    WriteIdtGate(gate, kUdHandlerGpa);
    ASSERT_EQ(ZX_OK, ram->Write(gate, kIdtGpa + 6 * 16, sizeof(gate)), "#UD gate\n");
  }
  ASSERT_EQ(ZX_OK, ram->CommitRange(0, kGuestRamSize), "commit\n");

  auto mapping = guest->RootVmar()->CreateVmMapping(0, kGuestRamSize, 0, VMAR_FLAG_SPECIFIC, ram, 0,
                                                    kMmuFlags, "guest-ram");
  ASSERT_EQ(ZX_OK, mapping.status_value(), "map\n");
  {
    auto t = guest->SetTrap(ZX_GUEST_TRAP_IO, kWidePort, 4, nullptr, kWidePort);
    ASSERT_EQ(ZX_OK, t.status_value(), "wide I/O trap\n");
  }
  {
    auto t = guest->SetTrap(ZX_GUEST_TRAP_IO, kUdPort, 1, nullptr, kUdPort);
    ASSERT_EQ(ZX_OK, t.status_value(), "#UD report trap\n");
  }

  auto vcpu_result = Vcpu::Create(*guest, kCodeGpa);
  ASSERT_EQ(ZX_OK, vcpu_result.status_value(), "Vcpu::Create\n");
  ktl::unique_ptr<Vcpu> vcpu = ktl::move(vcpu_result.value());

  VcpuArchState s = {};
  ASSERT_EQ(ZX_OK, vcpu->SaveArchState(s).status_value(), "SaveArchState\n");
  s.gdtr_base = kGdtGpa;
  s.gdtr_limit = 0x0F;
  s.idtr_base = kIdtGpa;
  s.idtr_limit = 0xFFF;
  s.regs.rsp = kStackTop;
  ASSERT_EQ(ZX_OK, vcpu->RestoreArchState(s).status_value(), "load GDTR/IDTR/RSP\n");

  auto wide = [](const zx_port_packet_t& p) {
    uint32_t v = 0;
    memcpy(&v, p.guest_io.data, sizeof(v));
    return v;
  };
  constexpr uint32_t kOsxsaveBit = 1u << 27;

  zx_port_packet_t before = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(before).status_value(), "enter #1\n");
  ASSERT_EQ(static_cast<uint32_t>(kWidePort), before.guest_io.port, "the first CPUID report\n");
  EXPECT_NE(0u, wide(before) & kOsxsaveBit,
            "with CR4.OSXSAVE set -- which is how this hypervisor starts a VCPU -- the guest must "
            "read OSXSAVE as 1; a hypervisor that simply always cleared bit 27 would pass the "
            "assertion below and fail this one\n");

  zx_port_packet_t after = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(after).status_value(), "enter #2\n");
  ASSERT_EQ(static_cast<uint32_t>(kWidePort), after.guest_io.port, "the second CPUID report\n");
  EXPECT_EQ(0u, wide(after) & kOsxsaveBit,
            "after the guest clears its own CR4.OSXSAVE, CPUID.1:ECX bit 27 must read 0. Reading "
            "1 here is the host's bit passed through, and it is a licence to execute XGETBV that "
            "the guest does not have\n");

  zx_port_packet_t ud = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(ud).status_value(), "enter #3\n");
  ASSERT_EQ(static_cast<uint32_t>(kUdPort), ud.guest_io.port, "the XGETBV outcome report\n");
  EXPECT_EQ(6u, static_cast<uint32_t>(ud.guest_io.data[0]),
            "XGETBV with CR4.OSXSAVE clear must raise #UD and reach the guest's own handler; "
            "0xBB here means it executed anyway, and the CPUID bit above would then be reporting "
            "a restriction the processor is not applying\n");

  // The set/clear wording is DERIVED, not asserted in the format string. An
  // earlier draft hardcoded "(bit 27 clear)" and duly printed it during a red
  // run -- EXPECT_ does not abort -- so the log said the opposite of what the
  // failure above had just reported.
  printf("OSXSAVE mirror: guest read CPUID.1:ECX %#x (bit 27 %s) with CR4.OSXSAVE on, %#x (bit 27 "
         "%s) after clearing it; XGETBV then reported vector %u (6 = #UD).\n",
         wide(before), (wide(before) & kOsxsaveBit) ? "set" : "clear", wide(after),
         (wide(after) & kOsxsaveBit) ? "set" : "clear",
         static_cast<uint32_t>(ud.guest_io.data[0]));
#else
  printf("Not x86_64; skipping.\n");
#endif  // __x86_64__

  END_TEST;
}

// A guest's EOI reaches the VMM for a registered vector, and ONLY for one.
//
// The kernel's local APIC consumes the guest's `wrmsr 0x80b` in-kernel: the
// in-service bit is cleared here and the guest resumes with no exit. That is
// right for every consumer but one -- an IO-APIC emulated in userspace, whose
// level-triggered lines set `remote IRR` on delivery and refuse to deliver again
// until an EOI clears it. Such a line fires exactly once for the life of the
// guest, because the EOI that would clear it never leaves this kernel.
//
// So the EOI is surfaced -- but only for vectors the VMM asked about, and the
// gate is the whole design rather than an optimisation. An EOI is the last
// instruction of every interrupt handler a guest runs; making it exit
// unconditionally would trade one stuck line for a userspace round trip on every
// interrupt in the system. Both halves are asserted here, and the second is the
// one that would otherwise regress silently, since an over-eager exit still
// produces a *correct* guest.
//
// What makes each assertion falsifiable is the ORDER of exits, not their
// presence. The handler reports itself, EOIs, and then reports again on a second
// port, so:
//
//   * a registered vector must produce  out 0x30 -> EOI packet -> out 0x11
//   * an unregistered one must produce  out 0x30 ->              out 0x11
//
// A missing exit therefore shows up as the wrong packet arriving rather than as
// a hang, and a spurious one displaces the marker that follows it. Observed red
// both ways by forcing `EoiBitmap::Test` to a constant: false makes the
// registered case exit to 0x11 where the EOI packet was required; true makes
// step (3) -- the unregistered vector alongside a registered one -- produce an
// EOI packet where 0x11 was required.
bool vcpu_registered_eoi_exits_to_the_vmm() {
  BEGIN_TEST;

#ifdef __x86_64__
  auto guest_result = Guest::Create();
  if (guest_result.is_error() && guest_result.status_value() == ZX_ERR_NOT_SUPPORTED) {
    printf("VMX not supported here; skipping registered-EOI test.\n");
    return true;
  }
  ASSERT_EQ(ZX_OK, guest_result.status_value(), "Guest::Create failed\n");
  ktl::unique_ptr<Guest> guest = ktl::move(guest_result.value());

  // The registration ABI, before anything is entered. `len` is the registration
  // itself, so a length this call cannot mean has to be refused rather than
  // rounded to the nearest thing it could have meant.
  {
    auto bad_vector = guest->SetTrap(ZX_GUEST_TRAP_EOI, 256, 1, nullptr, 0);
    EXPECT_EQ(ZX_ERR_OUT_OF_RANGE, bad_vector.status_value(),
              "a vector past the 256 the architecture has must be refused\n");
    auto bad_len = guest->SetTrap(ZX_GUEST_TRAP_EOI, 0x50, 2, nullptr, 0);
    EXPECT_EQ(ZX_ERR_INVALID_ARGS, bad_len.status_value(),
              "len is the registration (1 on, 0 off); anything else is a caller who has "
              "misread this as an address range\n");
  }

  constexpr uint64_t kGdtGpa = 0x6000;
  constexpr uint64_t kIdtGpa = 0x6800;
  constexpr uint64_t kWatchedHandlerGpa = 0x8000;
  constexpr uint64_t kQuietHandlerGpa = 0x8080;
  constexpr uint64_t kParkGpa = 0x8100;
  constexpr uint64_t kStackTop = 0x9000;

  // Two vectors of DIFFERENT priority classes, so that neither can hold the
  // other back and every delivery below is unconditional. `kWatched` is the one
  // registered; `kQuiet` is the control that must produce no exit.
  constexpr uint32_t kWatchedVector = 0x50;
  constexpr uint32_t kQuietVector = 0x60;
  constexpr uint32_t kEoiMsr = 0x80b;
  // Reported by every handler before its EOI, and again after it.
  constexpr uint8_t kRanPort = 0x30;
  constexpr uint8_t kPastEoiPort = 0x11;

  fbl::RefPtr<VmObjectPaged> ram;
  ASSERT_EQ(ZX_OK, VmObjectPaged::Create(PMM_ALLOC_FLAG_ANY, 0u, kGuestRamSize, &ram), "ram\n");
  ASSERT_EQ(ZX_OK, WriteIdentityTables(ram), "tables\n");

  uint8_t buf[128];
  size_t n = 0;
  auto emit = [&](std::initializer_list<uint8_t> bytes) {
    for (uint8_t b : bytes) {
      buf[n++] = b;
    }
  };
  auto emit32 = [&](uint32_t v) {
    emit({static_cast<uint8_t>(v), static_cast<uint8_t>(v >> 8), static_cast<uint8_t>(v >> 16),
          static_cast<uint8_t>(v >> 24)});
  };
  auto report_byte = [&](uint8_t value, uint8_t port) { emit({0xB0, value, 0xE6, port}); };
  // mov ecx, 0x80b ; xor eax, eax ; xor edx, edx ; wrmsr
  auto eoi = [&]() {
    emit({0xB9});
    emit32(kEoiMsr);
    emit({0x31, 0xC0, 0x31, 0xD2, 0x0F, 0x30});
  };
  auto jmp_to = [&](uint64_t base, uint64_t target) {
    const int32_t disp = static_cast<int32_t>(target) - static_cast<int32_t>(base + n + 5);
    emit({0xE9});
    emit32(static_cast<uint32_t>(disp));
  };

  // The body: announce readiness, then park with interrupts on. The host drives
  // everything after that by injecting.
  n = 0;
  emit({0xFB, 0x90});  // sti ; nop -- retire the STI shadow
  report_byte(0xA1, 0x10);
  emit({0xEB, 0xFE});  // jmp $
  ASSERT_EQ(ZX_OK, ram->Write(buf, kCodeGpa, n), "code\n");

  const uint8_t gdt_code[8] = {0xFF, 0xFF, 0x00, 0x00, 0x00, 0x9B, 0xAF, 0x00};
  ASSERT_EQ(ZX_OK, ram->Write(gdt_code, kGdtGpa + 8, sizeof(gdt_code)), "GDT code desc\n");

  struct Gate {
    uint32_t vector;
    uint64_t handler;
  };
  const Gate gates[] = {{kWatchedVector, kWatchedHandlerGpa}, {kQuietVector, kQuietHandlerGpa}};
  for (const Gate& g : gates) {
    uint8_t gate[16];
    WriteIdtGate(gate, g.handler);
    ASSERT_EQ(ZX_OK, ram->Write(gate, kIdtGpa + g.vector * 16, sizeof(gate)), "IDT gate\n");
  }

  // Both handlers are the same shape, and that is the point: the only thing that
  // differs between the registered and unregistered runs is the registration.
  const Gate bodies[] = {{kWatchedVector, kWatchedHandlerGpa}, {kQuietVector, kQuietHandlerGpa}};
  for (const Gate& b : bodies) {
    n = 0;
    report_byte(static_cast<uint8_t>(b.vector), kRanPort);
    eoi();
    report_byte(0xA2, kPastEoiPort);
    emit({0xFB});  // sti
    jmp_to(b.handler, kParkGpa);
    ASSERT_LE(n, 128u, "handler overruns its slot\n");
    ASSERT_EQ(ZX_OK, ram->Write(buf, b.handler, n), "handler\n");
  }

  // Where every handler resumes to, and waits for the next injection.
  n = 0;
  emit({0xEB, 0xFE});  // jmp $
  ASSERT_EQ(ZX_OK, ram->Write(buf, kParkGpa, n), "park\n");
  ASSERT_EQ(ZX_OK, ram->CommitRange(0, kGuestRamSize), "commit\n");

  auto mapping = guest->RootVmar()->CreateVmMapping(0, kGuestRamSize, 0, VMAR_FLAG_SPECIFIC, ram, 0,
                                                    kMmuFlags, "guest-ram");
  ASSERT_EQ(ZX_OK, mapping.status_value(), "map\n");
  for (uint16_t port : {uint16_t{0x10}, uint16_t{kPastEoiPort}, uint16_t{kRanPort}}) {
    auto t = guest->SetTrap(ZX_GUEST_TRAP_IO, port, 1, nullptr, port);
    ASSERT_EQ(ZX_OK, t.status_value(), "install byte I/O trap\n");
  }

  auto vcpu_result = Vcpu::Create(*guest, kCodeGpa);
  ASSERT_EQ(ZX_OK, vcpu_result.status_value(), "Vcpu::Create\n");
  ktl::unique_ptr<Vcpu> vcpu = ktl::move(vcpu_result.value());

  VcpuArchState s = {};
  ASSERT_EQ(ZX_OK, vcpu->SaveArchState(s).status_value(), "SaveArchState\n");
  s.gdtr_base = kGdtGpa;
  s.gdtr_limit = 0x0F;
  s.idtr_base = kIdtGpa;
  s.idtr_limit = 0xFFF;
  s.regs.rsp = kStackTop;
  ASSERT_EQ(ZX_OK, vcpu->RestoreArchState(s).status_value(), "load GDTR/IDTR/RSP\n");

  zx_port_packet_t p = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(p).status_value(), "enter #1\n");
  ASSERT_EQ(0x10u, p.guest_io.port, "expected the readiness exit on 0x10\n");
  EXPECT_EQ(0u, vcpu->EoiExits(), "nothing is registered and nothing has been EOI'd\n");

  // (1) The control, taken FIRST so that "no exit" cannot be an artefact of a
  // registration made earlier and never cleared. Nothing is registered yet.
  ASSERT_EQ(ZX_OK, vcpu->Interrupt(kQuietVector).status_value(), "inject the quiet vector\n");
  zx_port_packet_t quiet_ran = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(quiet_ran).status_value(), "enter #2\n");
  ASSERT_EQ(static_cast<uint32_t>(kRanPort), quiet_ran.guest_io.port, "the quiet handler ran\n");
  ASSERT_EQ(kQuietVector, static_cast<uint32_t>(quiet_ran.guest_io.data[0]), "and is that one\n");

  zx_port_packet_t quiet_past = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(quiet_past).status_value(), "enter #3\n");
  EXPECT_EQ(static_cast<uint32_t>(kPastEoiPort), quiet_past.guest_io.port,
            "an EOI on an UNREGISTERED vector must not exit: the next thing the VMM sees has to "
            "be the marker after the EOI, not the EOI. A ZX_PKT_TYPE_GUEST_EOI here is a "
            "userspace round trip on every interrupt in the system\n");
  EXPECT_EQ(1u, vcpu->EoiCompletions(), "the EOI still ended a real in-service interrupt\n");
  EXPECT_EQ(0u, vcpu->EoiExits(), "it just did not cost an exit\n");

  // (2) Now register one vector, and only that one.
  {
    auto t = guest->SetTrap(ZX_GUEST_TRAP_EOI, kWatchedVector, 1, nullptr, 0);
    ASSERT_EQ(ZX_OK, t.status_value(), "register the watched vector\n");
  }
  ASSERT_EQ(ZX_OK, vcpu->Interrupt(kWatchedVector).status_value(), "inject the watched vector\n");
  zx_port_packet_t watched_ran = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(watched_ran).status_value(), "enter #4\n");
  ASSERT_EQ(static_cast<uint32_t>(kRanPort), watched_ran.guest_io.port, "the handler ran\n");
  ASSERT_EQ(kWatchedVector, static_cast<uint32_t>(watched_ran.guest_io.data[0]), "as itself\n");

  zx_port_packet_t eoi_packet = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(eoi_packet).status_value(), "enter #5\n");
  ASSERT_EQ(ZX_PKT_TYPE_GUEST_EOI, eoi_packet.type,
            "the guest's EOI on a REGISTERED vector must reach the VMM; the marker port after the "
            "EOI arriving here instead means the kernel swallowed it, which is the whole defect "
            "-- an emulated IO-APIC's level line then never clears its remote IRR\n");
  EXPECT_EQ(static_cast<uint64_t>(kWatchedVector), eoi_packet.guest_eoi.vector,
            "and must name the vector that ended, since that is what selects the redirection "
            "entry to clear\n");
  EXPECT_EQ(2u, vcpu->EoiCompletions(), "two EOIs so far\n");
  EXPECT_EQ(1u, vcpu->EoiExits(), "exactly one of which was surfaced\n");
  EXPECT_FALSE(vcpu->InService(kWatchedVector),
               "the in-service bit is already cleared when the packet is delivered: this reports "
               "what happened, it does not ask the VMM to complete anything\n");

  zx_port_packet_t watched_past = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(watched_past).status_value(), "enter #6\n");
  EXPECT_EQ(static_cast<uint32_t>(kPastEoiPort), watched_past.guest_io.port,
            "and the guest resumes with nothing written back -- RIP was already past the WRMSR\n");

  // (3) The quiet vector again, this time WITH the other one still registered.
  //
  // This is the case that actually tests the per-vector bit, and step (1) was
  // not a substitute for it. Measured: the EOI path used to carry an "is
  // anything registered at all?" precheck in front of the per-vector test, and
  // forcing that per-vector test to a constant `true` left step (1) GREEN --
  // the bitmap was empty there, so the constant was never reached. A gate that
  // made every vector exit would have shipped. The precheck is gone now (see
  // `EoiBitmap`), and this step is what would catch it coming back.
  ASSERT_EQ(ZX_OK, vcpu->Interrupt(kQuietVector).status_value(),
            "inject the quiet vector alongside a registered one\n");
  zx_port_packet_t mixed_ran = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(mixed_ran).status_value(), "enter #7\n");
  ASSERT_EQ(static_cast<uint32_t>(kRanPort), mixed_ran.guest_io.port, "the quiet handler ran\n");
  ASSERT_EQ(kQuietVector, static_cast<uint32_t>(mixed_ran.guest_io.data[0]), "as itself\n");

  zx_port_packet_t mixed_past = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(mixed_past).status_value(), "enter #8\n");
  EXPECT_EQ(static_cast<uint32_t>(kPastEoiPort), mixed_past.guest_io.port,
            "registering one vector must not register every vector -- an EOI packet here means "
            "the gate is 'has the VMM registered anything' rather than 'has it registered THIS'\n");
  EXPECT_EQ(3u, vcpu->EoiCompletions(), "three EOIs\n");
  EXPECT_EQ(1u, vcpu->EoiExits(), "still one exit, from the one registered vector\n");

  // (4) Unregistering is not a no-op the caller has to work around. Without it a
  // VMM cannot follow a guest that reprograms a redirection entry to a new
  // vector, and the old one would keep exiting forever.
  {
    auto t = guest->SetTrap(ZX_GUEST_TRAP_EOI, kWatchedVector, 0, nullptr, 0);
    ASSERT_EQ(ZX_OK, t.status_value(), "unregister the watched vector\n");
  }
  ASSERT_EQ(ZX_OK, vcpu->Interrupt(kWatchedVector).status_value(), "inject it once more\n");
  zx_port_packet_t again_ran = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(again_ran).status_value(), "enter #9\n");
  ASSERT_EQ(static_cast<uint32_t>(kRanPort), again_ran.guest_io.port, "the handler ran again\n");

  zx_port_packet_t again_past = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(again_past).status_value(), "enter #10\n");
  EXPECT_EQ(static_cast<uint32_t>(kPastEoiPort), again_past.guest_io.port,
            "an unregistered vector must stop exiting -- the SAME vector that exited above\n");
  EXPECT_EQ(4u, vcpu->EoiCompletions(), "four EOIs in total\n");
  EXPECT_EQ(1u, vcpu->EoiExits(),
            "and still exactly one exit: the registration, not the vector, is what decides\n");

  printf("registered-EOI OK: %lu guest EOIs completed, %lu surfaced. Unregistered %#x cost no "
         "exit before or after; registered %#x delivered ZX_PKT_TYPE_GUEST_EOI naming vector "
         "%#lx, and stopped costing an exit once unregistered.\n",
         vcpu->EoiCompletions(), vcpu->EoiExits(), kQuietVector, kWatchedVector,
         eoi_packet.guest_eoi.vector);
#else
  printf("Not x86_64; skipping.\n");
#endif  // __x86_64__

  END_TEST;
}

// ---------------------------------------------------------------------------
// ZX_VCPU_STATE_LAZY_EOI: registration validates, and a write is always safe
// to apply on top of any previous state (live reprogram or restore alike).
// ---------------------------------------------------------------------------
bool vcpu_lazy_eoi_state_topic_validates_registration() {
  BEGIN_TEST;

#ifdef __x86_64__
  auto guest_result = Guest::Create();
  if (guest_result.is_error() && guest_result.status_value() == ZX_ERR_NOT_SUPPORTED) {
    printf("VMX not supported here; skipping lazy-EOI registration test.\n");
    return true;
  }
  ASSERT_EQ(ZX_OK, guest_result.status_value(), "Guest::Create failed\n");
  ktl::unique_ptr<Guest> guest = ktl::move(guest_result.value());

  fbl::RefPtr<VmObjectPaged> ram;
  ASSERT_EQ(ZX_OK, VmObjectPaged::Create(PMM_ALLOC_FLAG_ANY, 0u, kGuestRamSize, &ram), "ram\n");
  ASSERT_EQ(ZX_OK, WriteIdentityTables(ram), "tables\n");
  const uint8_t code[] = {0xF4};  // hlt; never actually run in this test.
  ASSERT_EQ(ZX_OK, ram->Write(code, kCodeGpa, sizeof(code)), "code\n");
  ASSERT_EQ(ZX_OK, ram->CommitRange(0, kGuestRamSize), "commit\n");
  auto mapping = guest->RootVmar()->CreateVmMapping(0, kGuestRamSize, 0, VMAR_FLAG_SPECIFIC, ram, 0,
                                                    kMmuFlags, "guest-ram");
  ASSERT_EQ(ZX_OK, mapping.status_value(), "map\n");

  auto vcpu_result = Vcpu::Create(*guest, kCodeGpa);
  ASSERT_EQ(ZX_OK, vcpu_result.status_value(), "Vcpu::Create\n");
  ktl::unique_ptr<Vcpu> vcpu = ktl::move(vcpu_result.value());
  vcpu->ForceLazyEoiGrantForTest();  // Inert (no VID gate ships); retained for compatibility.

  constexpr uint64_t kAssistGpa = 0x9000;
  constexpr uint64_t kSecondAssistGpa = 0xA000;

  zx_vcpu_lazy_eoi_state_t bad = {};
  bad.magic = 0xdeadbeef;
  bad.version = ZX_VCPU_LAZY_EOI_STATE_VERSION;
  bad.size = sizeof(bad);
  EXPECT_EQ(ZX_ERR_INVALID_ARGS, vcpu->WriteLazyEoiState(bad).status_value(), "bad magic\n");
  bad.magic = ZX_VCPU_LAZY_EOI_STATE_MAGIC;
  bad.version = 0;
  EXPECT_EQ(ZX_ERR_INVALID_ARGS, vcpu->WriteLazyEoiState(bad).status_value(), "bad version\n");
  bad.version = ZX_VCPU_LAZY_EOI_STATE_VERSION;
  bad.size = sizeof(bad) - 1;
  EXPECT_EQ(ZX_ERR_INVALID_ARGS, vcpu->WriteLazyEoiState(bad).status_value(), "bad size\n");
  bad.size = sizeof(bad);

  // enabled=1 with assist_gpa == 0 is refused: nothing to map.
  bad.enabled = 1;
  bad.assist_gpa = 0;
  EXPECT_EQ(ZX_ERR_INVALID_ARGS, vcpu->WriteLazyEoiState(bad).status_value(),
            "enabled with no address\n");

  // A misaligned assist_gpa is refused -- the word is accessed through
  // ktl::atomic_ref, which requires natural (4-byte) alignment for its
  // atomicity guarantee.
  bad.assist_gpa = kAssistGpa + 1;
  EXPECT_EQ(ZX_ERR_INVALID_ARGS, vcpu->WriteLazyEoiState(bad).status_value(),
            "misaligned address\n");
  bad.assist_gpa = kAssistGpa + 2;
  EXPECT_EQ(ZX_ERR_INVALID_ARGS, vcpu->WriteLazyEoiState(bad).status_value(),
            "misaligned address (2)\n");

  // enabled=0 with a nonzero assist_gpa is refused: the field is output-only
  // when disabled, not silently ignored.
  bad.enabled = 0;
  bad.assist_gpa = kAssistGpa;
  EXPECT_EQ(ZX_ERR_INVALID_ARGS, vcpu->WriteLazyEoiState(bad).status_value(),
            "disabled with a stray address\n");

  // A valid registration succeeds and reads back exactly what was written.
  zx_vcpu_lazy_eoi_state_t good = {};
  good.magic = ZX_VCPU_LAZY_EOI_STATE_MAGIC;
  good.version = ZX_VCPU_LAZY_EOI_STATE_VERSION;
  good.size = sizeof(good);
  good.enabled = 1;
  good.assist_gpa = kAssistGpa;
  ASSERT_EQ(ZX_OK, vcpu->WriteLazyEoiState(good).status_value(), "register\n");

  zx_vcpu_lazy_eoi_state_t readback = {};
  ASSERT_EQ(ZX_OK, vcpu->ReadLazyEoiState(readback).status_value(), "read back\n");
  EXPECT_EQ(1u, readback.enabled, "reports enabled\n");
  EXPECT_EQ(kAssistGpa, readback.assist_gpa, "reports the registered address\n");

  // A second registration to a DIFFERENT address replaces the first wholesale
  // -- and this is also how a VMM restores a snapshot, so nothing about it may
  // depend on the previous registration's mapping still being valid.
  good.assist_gpa = kSecondAssistGpa;
  ASSERT_EQ(ZX_OK, vcpu->WriteLazyEoiState(good).status_value(), "re-register\n");
  ASSERT_EQ(ZX_OK, vcpu->ReadLazyEoiState(readback).status_value(), "read back again\n");
  EXPECT_EQ(kSecondAssistGpa, readback.assist_gpa, "reports the NEW address\n");

  // Disabling drops the mapping and reports enabled=0/assist_gpa=0.
  zx_vcpu_lazy_eoi_state_t off = {};
  off.magic = ZX_VCPU_LAZY_EOI_STATE_MAGIC;
  off.version = ZX_VCPU_LAZY_EOI_STATE_VERSION;
  off.size = sizeof(off);
  ASSERT_EQ(ZX_OK, vcpu->WriteLazyEoiState(off).status_value(), "disable\n");
  ASSERT_EQ(ZX_OK, vcpu->ReadLazyEoiState(readback).status_value(), "read back disabled\n");
  EXPECT_EQ(0u, readback.enabled, "reports disabled\n");
  EXPECT_EQ(0u, readback.assist_gpa, "reports no address\n");

  printf("lazy-EOI registration OK: bad magic/version/size/field-combinations refused; a valid "
         "registration, a re-registration to a new address, and a disable all read back exactly "
         "what was written\n");
#else
  printf("Not x86_64; skipping.\n");
#endif  // __x86_64__

  END_TEST;
}

// ---------------------------------------------------------------------------
// ZX_VCPU_STATE_LAZY_EOI: an armed grant lets the guest skip its real EOI with
// no exit, and this kernel reconciles it -- retiring the SPECIFIC vector via
// guest_isr_clear, not "whatever is on top of ISR" -- on the next VM entry's
// admission, before that entry's own admission decision runs.
//
// RED-VERIFIED 2026-08-01: commenting out the
// `guest_lazy_eoi_reconcile(*local_apic_state);` call at the top of
// `local_apic_maybe_interrupt` (vcpu.cc) makes this test fail exactly as
// predicted -- enter #4 lands on the heartbeat port instead of kRanPort (the
// re-injected vector is refused forever, held back by its own never-retired
// ISR bit), `vcpu->IsrBlocked()` climbs, `LazyEoiCompletions()` stays 0 and
// `InService(kVector)` stays true. Reverted after confirming.
// ---------------------------------------------------------------------------
bool vcpu_lazy_eoi_armed_interrupt_produces_no_exit() {
  BEGIN_TEST;

#ifdef __x86_64__
  auto guest_result = Guest::Create();
  if (guest_result.is_error() && guest_result.status_value() == ZX_ERR_NOT_SUPPORTED) {
    printf("VMX not supported here; skipping lazy-EOI no-exit test.\n");
    return true;
  }
  ASSERT_EQ(ZX_OK, guest_result.status_value(), "Guest::Create failed\n");
  ktl::unique_ptr<Guest> guest = ktl::move(guest_result.value());

  constexpr uint64_t kGdtGpa = 0x6000;
  constexpr uint64_t kIdtGpa = 0x6800;
  constexpr uint64_t kHandlerGpa = 0x8000;
  constexpr uint64_t kAssistGpa = 0x9000;
  constexpr uint64_t kStackTop = 0xA000;
  constexpr uint32_t kVector = 0x50;
  constexpr uint8_t kRanPort = 0x30;
  constexpr uint8_t kEpiloguePort = 0x31;
  // The guest's "idle" state is a loop that always produces an exit on its
  // own, whether or not the pending interrupt is deliverable -- so a vector
  // that never gets delivered shows up as "only ever this port", never as a
  // hang.
  constexpr uint8_t kHeartbeatPort = 0x32;

  fbl::RefPtr<VmObjectPaged> ram;
  ASSERT_EQ(ZX_OK, VmObjectPaged::Create(PMM_ALLOC_FLAG_ANY, 0u, kGuestRamSize, &ram), "ram\n");
  ASSERT_EQ(ZX_OK, WriteIdentityTables(ram), "tables\n");

  uint8_t buf[128];
  size_t n = 0;
  auto emit = [&](std::initializer_list<uint8_t> bytes) {
    for (uint8_t b : bytes) {
      buf[n++] = b;
    }
  };
  auto emit32 = [&](uint32_t v) {
    emit({static_cast<uint8_t>(v), static_cast<uint8_t>(v >> 8), static_cast<uint8_t>(v >> 16),
          static_cast<uint8_t>(v >> 24)});
  };
  auto emit64 = [&](uint64_t v) {
    for (int i = 0; i < 8; i++) {
      emit({static_cast<uint8_t>(v >> (8 * i))});
    }
  };
  auto report_byte = [&](uint8_t value, uint8_t port) { emit({0xB0, value, 0xE6, port}); };
  // The entire lazy-EOI epilogue this hypervisor is supposed to let through
  // for free: mov rax, kAssistGpa ; mov dword [rax], 0. An ordinary
  // guest-memory write -- no MSR, no MMIO, nothing this hypervisor traps on.
  auto clear_assist_word = [&]() {
    emit({0x48, 0xB8});
    emit64(kAssistGpa);
    emit({0xC7, 0x00, 0x00, 0x00, 0x00, 0x00});
  };
  auto jmp_to = [&](uint64_t base, uint64_t target) {
    const int32_t disp = static_cast<int32_t>(target) - static_cast<int32_t>(base + n + 5);
    emit({0xE9});
    emit32(static_cast<uint32_t>(disp));
  };

  // The guest's whole idle loop: report a heartbeat, then do it again. This is
  // also the code at kCodeGpa, so the guest starts here. RFLAGS.IF resets to 0
  // (vmcs_init writes only the reserved-ones bits), so an external interrupt
  // is not deliverable until the guest enables interrupts itself.
  n = 0;
  emit({0xFB, 0x90});  // sti ; nop -- retire the STI shadow
  report_byte(0xBB, kHeartbeatPort);
  jmp_to(kCodeGpa, kCodeGpa);
  ASSERT_EQ(ZX_OK, ram->Write(buf, kCodeGpa, n), "code\n");

  const uint8_t gdt_code[8] = {0xFF, 0xFF, 0x00, 0x00, 0x00, 0x9B, 0xAF, 0x00};
  ASSERT_EQ(ZX_OK, ram->Write(gdt_code, kGdtGpa + 8, sizeof(gdt_code)), "GDT code desc\n");

  uint8_t gate[16];
  WriteIdtGate(gate, kHandlerGpa);
  ASSERT_EQ(ZX_OK, ram->Write(gate, kIdtGpa + kVector * 16, sizeof(gate)), "IDT gate\n");

  // Handler: report that it ran, unconditionally take the lazy path (a
  // TLFS-compliant guest only ever reaches this write because it found the
  // assist word set; the assertions below confirm this kernel actually armed
  // it), re-enable interrupts, then resume the heartbeat loop. Deliberately
  // never issues the real EOI (WRMSR 0x80b) at all.
  n = 0;
  report_byte(static_cast<uint8_t>(kVector), kRanPort);
  clear_assist_word();
  report_byte(0xAA, kEpiloguePort);
  emit({0xFB, 0x90});  // sti ; nop -- retire the STI shadow before resuming.
  jmp_to(kHandlerGpa, kCodeGpa);
  ASSERT_EQ(ZX_OK, ram->Write(buf, kHandlerGpa, n), "handler\n");
  ASSERT_EQ(ZX_OK, ram->CommitRange(0, kGuestRamSize), "commit\n");

  auto mapping = guest->RootVmar()->CreateVmMapping(0, kGuestRamSize, 0, VMAR_FLAG_SPECIFIC, ram, 0,
                                                    kMmuFlags, "guest-ram");
  ASSERT_EQ(ZX_OK, mapping.status_value(), "map\n");
  for (uint16_t port : {uint16_t{kRanPort}, uint16_t{kEpiloguePort}, uint16_t{kHeartbeatPort}}) {
    auto t = guest->SetTrap(ZX_GUEST_TRAP_IO, port, 1, nullptr, port);
    ASSERT_EQ(ZX_OK, t.status_value(), "install byte I/O trap\n");
  }

  auto vcpu_result = Vcpu::Create(*guest, kCodeGpa);
  ASSERT_EQ(ZX_OK, vcpu_result.status_value(), "Vcpu::Create\n");
  ktl::unique_ptr<Vcpu> vcpu = ktl::move(vcpu_result.value());
  vcpu->ForceLazyEoiGrantForTest();  // Inert (no VID gate ships); retained for compatibility.

  VcpuArchState s = {};
  ASSERT_EQ(ZX_OK, vcpu->SaveArchState(s).status_value(), "SaveArchState\n");
  s.gdtr_base = kGdtGpa;
  s.gdtr_limit = 0x0F;
  s.idtr_base = kIdtGpa;
  s.idtr_limit = 0xFFF;
  s.regs.rsp = kStackTop;
  ASSERT_EQ(ZX_OK, vcpu->RestoreArchState(s).status_value(), "load GDTR/IDTR/RSP\n");

  zx_vcpu_lazy_eoi_state_t lazy = {};
  lazy.magic = ZX_VCPU_LAZY_EOI_STATE_MAGIC;
  lazy.version = ZX_VCPU_LAZY_EOI_STATE_VERSION;
  lazy.size = sizeof(lazy);
  lazy.enabled = 1;
  lazy.assist_gpa = kAssistGpa;
  ASSERT_EQ(ZX_OK, vcpu->WriteLazyEoiState(lazy).status_value(), "register lazy EOI\n");

  zx_port_packet_t idle = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(idle).status_value(), "enter #1 (idle heartbeat)\n");
  ASSERT_EQ(static_cast<uint32_t>(kHeartbeatPort), idle.guest_io.port, "starts idle\n");
  ASSERT_EQ(0u, vcpu->EoiCompletions(), "nothing has EOI'd yet\n");

  ASSERT_EQ(ZX_OK, vcpu->Interrupt(kVector).status_value(), "inject\n");
  zx_port_packet_t ran = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(ran).status_value(), "enter #2\n");
  ASSERT_EQ(static_cast<uint32_t>(kRanPort), ran.guest_io.port, "handler must run\n");

  zx_port_packet_t epilogue = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(epilogue).status_value(), "enter #3\n");
  ASSERT_EQ(static_cast<uint32_t>(kEpiloguePort), epilogue.guest_io.port,
            "the epilogue's own memory write must not exit: the next thing seen must be the "
            "marker right after it, not anything describing the write itself\n");

  // The grant was consumed (word now 0) but this kernel has not yet had a
  // chance to reconcile it -- that only happens at the top of the NEXT VM
  // entry's admission. This is "no exit for the EOI, and it is genuinely
  // still pending reconciliation", not "nothing happened".
  EXPECT_TRUE(vcpu->LazyEoiArmed(), "grant still recorded as outstanding\n");
  EXPECT_EQ(kVector, vcpu->LazyEoiVector(), "recorded for the vector that was actually granted\n");
  EXPECT_TRUE(vcpu->InService(kVector), "ISR bit not yet retired -- reconciliation has not run\n");
  EXPECT_EQ(0u, vcpu->EoiCompletions(), "no real (register-path) EOI ever happened\n");
  EXPECT_EQ(0u, vcpu->LazyEoiCompletions(), "and reconciliation has not run yet either\n");

  // Inject the SAME vector again. Correct behaviour: this entry's admission
  // reconciles the first grant (retiring kVector specifically) before
  // deciding whether to admit the second one, so the guest is interrupted
  // again immediately rather than idling first.
  ASSERT_EQ(ZX_OK, vcpu->Interrupt(kVector).status_value(), "inject again\n");
  zx_port_packet_t ran2 = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(ran2).status_value(), "enter #4\n");
  EXPECT_EQ(static_cast<uint32_t>(kRanPort), ran2.guest_io.port,
            "the SAME vector must be deliverable again -- landing on the heartbeat port instead "
            "means it is refused forever, held back by its own never-retired in-service bit\n");
  EXPECT_EQ(1u, vcpu->LazyEoiCompletions(),
            "reconciliation of the FIRST grant must have happened by now, specifically\n");
  EXPECT_TRUE(vcpu->InService(kVector), "freshly (re-)armed for the second delivery\n");
  EXPECT_EQ(kVector, vcpu->LazyEoiVector(), "recorded again for this delivery\n");

  printf("lazy-EOI no-exit OK: armed grant's own memory clear produced no exit; reconciliation "
         "retired vector %#x specifically (%lu grant(s) reconciled), which stayed deliverable a "
         "second time (blocked count would climb instead if it did not)\n",
         kVector, vcpu->LazyEoiCompletions());
#else
  printf("Not x86_64; skipping.\n");
#endif  // __x86_64__

  END_TEST;
}

// ---------------------------------------------------------------------------
// ZX_VCPU_STATE_LAZY_EOI vs ZX_GUEST_TRAP_EOI: a vector the VMM registered for
// EOI notification must NEVER be granted the lazy path, even when it is the
// sole in-service vector (the case that otherwise always qualifies).
//
// A grant's entire purpose is that the guest's EOI costs no VM exit -- but that
// exit is the ONLY thing that produces ZX_PKT_TYPE_GUEST_EOI, and
// `guest_lazy_eoi_reconcile` retires the ISR bit silently, without consulting
// the EOI-interest bitmap. So a granted+registered vector loses its
// notification outright: the emulated IO-APIC never clears remote IRR for that
// level-triggered line, the device can never re-assert, and the line wedges --
// the same class of failure as the strand, arriving through the VMM instead of
// the guest. The sole-in-service case is the COMMON case, so this would fire
// routinely on any level-triggered route, not rarely.
//
// The fix declines the grant in `guest_lazy_eoi_arm`, so the guest falls
// through to the ordinary exit-costing EOI and the packet is delivered. This
// test is red under an arm that ignores the bitmap: with the grant issued the
// guest's epilogue takes the lazy skip, no EOI packet is ever produced, and the
// next thing the VMM sees is the guest's own marker port.
// ---------------------------------------------------------------------------
bool vcpu_lazy_eoi_registered_eoi_vector_is_never_granted() {
  BEGIN_TEST;

#ifdef __x86_64__
  auto guest_result = Guest::Create();
  if (guest_result.is_error() && guest_result.status_value() == ZX_ERR_NOT_SUPPORTED) {
    printf("VMX not supported here; skipping lazy-EOI vs EOI-trap test.\n");
    return true;
  }
  ASSERT_EQ(ZX_OK, guest_result.status_value(), "Guest::Create failed\n");
  ktl::unique_ptr<Guest> guest = ktl::move(guest_result.value());

  constexpr uint64_t kGdtGpa = 0x6000;
  constexpr uint64_t kIdtGpa = 0x6800;
  constexpr uint64_t kHandlerGpa = 0x8000;
  constexpr uint64_t kRealEoiGpa = 0x8080;
  constexpr uint64_t kAssistGpa = 0x9000;
  constexpr uint64_t kStackTop = 0xA000;
  // The vector the VMM watches -- stands in for a level-triggered IO-APIC route.
  constexpr uint32_t kWatchedVector = 0x50;
  constexpr uint32_t kEoiMsr = 0x80b;
  constexpr uint8_t kRanPort = 0x30;
  constexpr uint8_t kLazySkipPort = 0x31;
  constexpr uint8_t kHeartbeatPort = 0x32;
  constexpr uint8_t kRealEoiPort = 0x33;

  fbl::RefPtr<VmObjectPaged> ram;
  ASSERT_EQ(ZX_OK, VmObjectPaged::Create(PMM_ALLOC_FLAG_ANY, 0u, kGuestRamSize, &ram), "ram\n");
  ASSERT_EQ(ZX_OK, WriteIdentityTables(ram), "tables\n");

  uint8_t buf[128];
  size_t n = 0;
  auto emit = [&](std::initializer_list<uint8_t> bytes) {
    for (uint8_t b : bytes) {
      buf[n++] = b;
    }
  };
  auto emit32 = [&](uint32_t v) {
    emit({static_cast<uint8_t>(v), static_cast<uint8_t>(v >> 8), static_cast<uint8_t>(v >> 16),
          static_cast<uint8_t>(v >> 24)});
  };
  auto emit64 = [&](uint64_t v) {
    for (int i = 0; i < 8; i++) {
      emit({static_cast<uint8_t>(v >> (8 * i))});
    }
  };
  auto report_byte = [&](uint8_t value, uint8_t port) { emit({0xB0, value, 0xE6, port}); };
  auto eoi = [&]() {
    emit({0xB9});
    emit32(kEoiMsr);
    emit({0x31, 0xC0, 0x31, 0xD2, 0x0F, 0x30});
  };
  auto jmp_to = [&](uint64_t base, uint64_t target) {
    const int32_t disp = static_cast<int32_t>(target) - static_cast<int32_t>(base + n + 5);
    emit({0xE9});
    emit32(static_cast<uint32_t>(disp));
  };
  auto jz_to = [&](uint64_t base, uint64_t target) {
    const int32_t disp = static_cast<int32_t>(target) - static_cast<int32_t>(base + n + 2);
    emit({0x74, static_cast<uint8_t>(disp)});
  };

  n = 0;
  emit({0xFB, 0x90});  // sti ; nop
  report_byte(0xBB, kHeartbeatPort);
  jmp_to(kCodeGpa, kCodeGpa);
  ASSERT_EQ(ZX_OK, ram->Write(buf, kCodeGpa, n), "code\n");

  const uint8_t gdt_code[8] = {0xFF, 0xFF, 0x00, 0x00, 0x00, 0x9B, 0xAF, 0x00};
  ASSERT_EQ(ZX_OK, ram->Write(gdt_code, kGdtGpa + 8, sizeof(gdt_code)), "GDT code desc\n");

  uint8_t gate[16];
  WriteIdtGate(gate, kHandlerGpa);
  ASSERT_EQ(ZX_OK, ram->Write(gate, kIdtGpa + kWatchedVector * 16, sizeof(gate)), "IDT gate\n");

  // A TLFS-faithful epilogue, so the GUEST's own protocol decides the path:
  // read the assist word, and take the free skip only if this kernel offered
  // one. With the grant correctly declined the word reads 0 and the guest falls
  // through to the real EOI -- which is what produces the VMM's packet.
  n = 0;
  report_byte(static_cast<uint8_t>(kWatchedVector), kRanPort);
  emit({0x48, 0xBB});
  emit64(kAssistGpa);
  emit({0x8B, 0x03});  // mov eax, [rbx]
  emit({0x85, 0xC0});  // test eax, eax
  jz_to(kHandlerGpa, kRealEoiGpa);
  emit({0xC7, 0x03, 0x00, 0x00, 0x00, 0x00});  // (word was 1) lazy skip: clear it, NO exit
  report_byte(0xDD, kLazySkipPort);
  emit({0xFB, 0x90});
  jmp_to(kHandlerGpa, kCodeGpa);
  ASSERT_LE(n, static_cast<size_t>(kRealEoiGpa - kHandlerGpa), "handler overruns its EOI stub\n");
  ASSERT_EQ(ZX_OK, ram->Write(buf, kHandlerGpa, n), "handler\n");

  n = 0;
  eoi();
  report_byte(0xEE, kRealEoiPort);
  emit({0xFB, 0x90});
  jmp_to(kRealEoiGpa, kCodeGpa);
  ASSERT_EQ(ZX_OK, ram->Write(buf, kRealEoiGpa, n), "real-EOI stub\n");
  ASSERT_EQ(ZX_OK, ram->CommitRange(0, kGuestRamSize), "commit\n");

  auto mapping = guest->RootVmar()->CreateVmMapping(0, kGuestRamSize, 0, VMAR_FLAG_SPECIFIC, ram, 0,
                                                    kMmuFlags, "guest-ram");
  ASSERT_EQ(ZX_OK, mapping.status_value(), "map\n");
  for (uint16_t port : {uint16_t{kRanPort}, uint16_t{kLazySkipPort}, uint16_t{kHeartbeatPort},
                        uint16_t{kRealEoiPort}}) {
    auto t = guest->SetTrap(ZX_GUEST_TRAP_IO, port, 1, nullptr, port);
    ASSERT_EQ(ZX_OK, t.status_value(), "install byte I/O trap\n");
  }

  auto vcpu_result = Vcpu::Create(*guest, kCodeGpa);
  ASSERT_EQ(ZX_OK, vcpu_result.status_value(), "Vcpu::Create\n");
  ktl::unique_ptr<Vcpu> vcpu = ktl::move(vcpu_result.value());
  vcpu->ForceLazyEoiGrantForTest();  // Inert (no VID gate ships); retained for compatibility.

  VcpuArchState s = {};
  ASSERT_EQ(ZX_OK, vcpu->SaveArchState(s).status_value(), "SaveArchState\n");
  s.gdtr_base = kGdtGpa;
  s.gdtr_limit = 0x0F;
  s.idtr_base = kIdtGpa;
  s.idtr_limit = 0xFFF;
  s.regs.rsp = kStackTop;
  ASSERT_EQ(ZX_OK, vcpu->RestoreArchState(s).status_value(), "load GDTR/IDTR/RSP\n");

  // BOTH enlightenments live at once -- the combination that was untested.
  zx_vcpu_lazy_eoi_state_t lazy = {};
  lazy.magic = ZX_VCPU_LAZY_EOI_STATE_MAGIC;
  lazy.version = ZX_VCPU_LAZY_EOI_STATE_VERSION;
  lazy.size = sizeof(lazy);
  lazy.enabled = 1;
  lazy.assist_gpa = kAssistGpa;
  ASSERT_EQ(ZX_OK, vcpu->WriteLazyEoiState(lazy).status_value(), "register lazy EOI\n");
  {
    auto t = guest->SetTrap(ZX_GUEST_TRAP_EOI, kWatchedVector, 1, nullptr, 0);
    ASSERT_EQ(ZX_OK, t.status_value(), "register the watched vector for EOI notification\n");
  }

  zx_port_packet_t idle = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(idle).status_value(), "enter #1 (idle)\n");
  ASSERT_EQ(static_cast<uint32_t>(kHeartbeatPort), idle.guest_io.port, "starts idle\n");

  // Sole in service, so the ONLY thing that can decline the grant is the
  // EOI-interest registration.
  ASSERT_EQ(ZX_OK, vcpu->Interrupt(kWatchedVector).status_value(), "inject the watched vector\n");
  zx_port_packet_t ran = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(ran).status_value(), "enter #2\n");
  ASSERT_EQ(static_cast<uint32_t>(kRanPort), ran.guest_io.port, "handler ran\n");
  ASSERT_TRUE(vcpu->InService(kWatchedVector), "and it is in service\n");

  // Non-fatal, so a RED run proceeds to the headline packet assertion below.
  EXPECT_FALSE(vcpu->LazyEoiArmed(),
               "a vector registered for EOI notification must NOT be granted, even though it is "
               "the sole in-service vector (RED: the grant is armed here)\n");
  uint32_t word = 0xffffffff;
  ASSERT_EQ(ZX_OK, ram->Read(&word, kAssistGpa, sizeof(word)), "read assist word\n");
  EXPECT_EQ(0u, word,
            "and the refusal must be visible in guest memory -- the word must offer no skip "
            "(RED: it reads 1)\n");

  // THE HEADLINE: the guest's EOI must reach the VMM.
  zx_port_packet_t eoi_packet = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(eoi_packet).status_value(), "enter #3\n");
  EXPECT_EQ(ZX_PKT_TYPE_GUEST_EOI, eoi_packet.type,
            "the EOI of a REGISTERED vector must exit to the VMM; landing on the guest's lazy-skip "
            "marker port instead means the grant swallowed the notification, and an emulated "
            "IO-APIC's level line would never clear its remote IRR\n");
  EXPECT_EQ(static_cast<uint64_t>(kWatchedVector), eoi_packet.guest_eoi.vector,
            "and must name the vector that ended\n");
  EXPECT_EQ(0u, vcpu->LazyEoiCompletions(),
            "nothing was retired lazily -- the grant was never issued\n");
  EXPECT_FALSE(vcpu->InService(kWatchedVector), "the vector retired through its real EOI\n");

  if (eoi_packet.type == ZX_PKT_TYPE_GUEST_EOI && !vcpu->LazyEoiArmed()) {
    printf("lazy-EOI vs EOI-trap OK: vector %#x was sole in service yet declined a grant because "
           "the VMM registered ZX_GUEST_TRAP_EOI; the guest took the real EOI and the packet was "
           "delivered (%lu lazy completion(s))\n",
           kWatchedVector, vcpu->LazyEoiCompletions());
  } else {
    printf("lazy-EOI vs EOI-trap SWALLOWED: armed=%d, packet type %u (expected %u) -- the grant "
           "consumed the EOI notification for vector %#x\n",
           vcpu->LazyEoiArmed(), eoi_packet.type, ZX_PKT_TYPE_GUEST_EOI, kWatchedVector);
  }
#else
  printf("Not x86_64; skipping.\n");
#endif  // __x86_64__

  END_TEST;
}

// ---------------------------------------------------------------------------
// ZX_VCPU_STATE_LAZY_EOI sole-in-service rule: when a higher-priority vector
// is admitted on top of an already-in-service vector that holds a grant, the
// nested admission must REVOKE that grant in guest memory (word forced to 0,
// this kernel's `armed` bookkeeping cleared) rather than overwrite the word's
// holder. A single shared assist word cannot safely stand in for two distinct
// in-service ISR bits: whichever epilogue reaches the word first consumes it
// for itself, and the other vector is then retired by a real EOI aimed at
// top-of-ISR -- the wrong bit -- stranding a vector forever (the winnano
// VMBus-SINT wedge; see guest_lazy_eoi_arm's doc). This test pins the
// mechanism: at the instant of nested admission the grant is gone, and with
// no grant outstanding every vector in the stack retires through its own
// ordinary (register-path) EOI, so nothing is ever reconciled-away.
// ---------------------------------------------------------------------------
bool vcpu_lazy_eoi_nested_admission_revokes_grant() {
  BEGIN_TEST;

#ifdef __x86_64__
  auto guest_result = Guest::Create();
  if (guest_result.is_error() && guest_result.status_value() == ZX_ERR_NOT_SUPPORTED) {
    printf("VMX not supported here; skipping lazy-EOI revoke test.\n");
    return true;
  }
  ASSERT_EQ(ZX_OK, guest_result.status_value(), "Guest::Create failed\n");
  ktl::unique_ptr<Guest> guest = ktl::move(guest_result.value());

  constexpr uint64_t kGdtGpa = 0x6000;
  constexpr uint64_t kIdtGpa = 0x6800;
  constexpr uint64_t kFirstHandlerGpa = 0x8000;
  constexpr uint64_t kNestHandlerGpa = 0x8080;
  constexpr uint64_t kSharedEpilogueGpa = 0x8100;
  constexpr uint64_t kRealEoiSubGpa = 0x8140;
  constexpr uint64_t kAssistGpa = 0x9000;
  constexpr uint64_t kStackTop = 0xA000;
  // Different priority CLASSES (bits 7:4), so B genuinely pre-empts A.
  constexpr uint32_t kFirstVector = 0x50;
  constexpr uint32_t kNestVector = 0x60;
  constexpr uint32_t kEoiMsr = 0x80b;
  constexpr uint8_t kRanPort = 0x30;
  constexpr uint8_t kFirstEpiloguePort = 0x31;
  constexpr uint8_t kHeartbeatPort = 0x32;
  constexpr uint8_t kBEoiPort = 0x33;
  constexpr uint8_t kAEoiPort = 0x34;

  fbl::RefPtr<VmObjectPaged> ram;
  ASSERT_EQ(ZX_OK, VmObjectPaged::Create(PMM_ALLOC_FLAG_ANY, 0u, kGuestRamSize, &ram), "ram\n");
  ASSERT_EQ(ZX_OK, WriteIdentityTables(ram), "tables\n");

  uint8_t buf[128];
  size_t n = 0;
  auto emit = [&](std::initializer_list<uint8_t> bytes) {
    for (uint8_t b : bytes) {
      buf[n++] = b;
    }
  };
  auto emit32 = [&](uint32_t v) {
    emit({static_cast<uint8_t>(v), static_cast<uint8_t>(v >> 8), static_cast<uint8_t>(v >> 16),
          static_cast<uint8_t>(v >> 24)});
  };
  auto emit64 = [&](uint64_t v) {
    for (int i = 0; i < 8; i++) {
      emit({static_cast<uint8_t>(v >> (8 * i))});
    }
  };
  auto report_byte = [&](uint8_t value, uint8_t port) { emit({0xB0, value, 0xE6, port}); };
  auto eoi = [&]() {
    emit({0xB9});
    emit32(kEoiMsr);
    emit({0x31, 0xC0, 0x31, 0xD2, 0x0F, 0x30});
  };
  auto jmp_to = [&](uint64_t base, uint64_t target) {
    const int32_t disp = static_cast<int32_t>(target) - static_cast<int32_t>(base + n + 5);
    emit({0xE9});
    emit32(static_cast<uint32_t>(disp));
  };
  auto jz_to = [&](uint64_t base, uint64_t target) {
    const int32_t disp = static_cast<int32_t>(target) - static_cast<int32_t>(base + n + 2);
    emit({0x74, static_cast<uint8_t>(disp)});
  };

  n = 0;
  emit({0xFB, 0x90});  // sti ; nop
  report_byte(0xBB, kHeartbeatPort);
  jmp_to(kCodeGpa, kCodeGpa);
  ASSERT_EQ(ZX_OK, ram->Write(buf, kCodeGpa, n), "code\n");

  const uint8_t gdt_code[8] = {0xFF, 0xFF, 0x00, 0x00, 0x00, 0x9B, 0xAF, 0x00};
  ASSERT_EQ(ZX_OK, ram->Write(gdt_code, kGdtGpa + 8, sizeof(gdt_code)), "GDT code desc\n");

  struct Gate {
    uint32_t vector;
    uint64_t handler;
  };
  const Gate gates[] = {{kFirstVector, kFirstHandlerGpa}, {kNestVector, kNestHandlerGpa}};
  for (const Gate& g : gates) {
    uint8_t gate[16];
    WriteIdtGate(gate, g.handler);
    ASSERT_EQ(ZX_OK, ram->Write(gate, kIdtGpa + g.vector * 16, sizeof(gate)), "IDT gate\n");
  }

  // A: report, re-enable interrupts, report its epilogue marker, park at the
  // idle loop -- deliberately WITHOUT touching the word, so it still holds a
  // live grant when B pre-empts.
  n = 0;
  report_byte(static_cast<uint8_t>(kFirstVector), kRanPort);
  emit({0xFB, 0x90});
  report_byte(0xAA, kFirstEpiloguePort);
  jmp_to(kFirstHandlerGpa, kCodeGpa);
  ASSERT_EQ(ZX_OK, ram->Write(buf, kFirstHandlerGpa, n), "first handler\n");

  // B: report, then a TLFS-faithful epilogue -- read the word, and only skip
  // the EOI if the word offered it (nonzero). Under the sole-vector rule the
  // nested admission has already forced the word to 0, so B falls through to
  // the real EOI, retiring itself by vector, then hands off to A's epilogue.
  n = 0;
  report_byte(static_cast<uint8_t>(kNestVector), kRanPort);
  emit({0x48, 0xBB});
  emit64(kAssistGpa);
  emit({0x8B, 0x03});  // mov eax, [rbx]
  emit({0x85, 0xC0});  // test eax, eax
  jz_to(kNestHandlerGpa, kNestHandlerGpa + 0x30);  // jz -> B real-EOI stub below
  emit({0xC7, 0x03, 0x00, 0x00, 0x00, 0x00});      // (word was 1) lazy skip: clear, no exit
  jmp_to(kNestHandlerGpa, kSharedEpilogueGpa);
  // B real-EOI stub at +0x30:
  ASSERT_LE(n, size_t{0x30}, "B handler prologue overruns its real-EOI stub\n");
  while (n < 0x30) {
    emit({0x90});
  }
  eoi();
  report_byte(0xCC, kBEoiPort);
  jmp_to(kNestHandlerGpa + 0x30, kSharedEpilogueGpa);
  ASSERT_EQ(ZX_OK, ram->Write(buf, kNestHandlerGpa, n), "nest handler\n");

  // Shared stand-in for A's own epilogue (this suite never uses IRET): read
  // the word; if already 0, take the real EOI (retiring A by vector).
  n = 0;
  emit({0x48, 0xBB});
  emit64(kAssistGpa);
  emit({0x8B, 0x03});
  emit({0x85, 0xC0});
  jz_to(kSharedEpilogueGpa, kRealEoiSubGpa);
  emit({0xC7, 0x03, 0x00, 0x00, 0x00, 0x00});
  jmp_to(kSharedEpilogueGpa, kCodeGpa);
  ASSERT_LE(n, static_cast<size_t>(kRealEoiSubGpa - kSharedEpilogueGpa), "epilogue overruns\n");
  ASSERT_EQ(ZX_OK, ram->Write(buf, kSharedEpilogueGpa, n), "shared epilogue\n");

  n = 0;
  eoi();
  report_byte(0xEE, kAEoiPort);
  jmp_to(kRealEoiSubGpa, kCodeGpa);
  ASSERT_EQ(ZX_OK, ram->Write(buf, kRealEoiSubGpa, n), "real-EOI sub\n");
  ASSERT_EQ(ZX_OK, ram->CommitRange(0, kGuestRamSize), "commit\n");

  auto mapping = guest->RootVmar()->CreateVmMapping(0, kGuestRamSize, 0, VMAR_FLAG_SPECIFIC, ram, 0,
                                                    kMmuFlags, "guest-ram");
  ASSERT_EQ(ZX_OK, mapping.status_value(), "map\n");
  for (uint16_t port : {uint16_t{kRanPort}, uint16_t{kFirstEpiloguePort}, uint16_t{kHeartbeatPort},
                        uint16_t{kBEoiPort}, uint16_t{kAEoiPort}}) {
    auto t = guest->SetTrap(ZX_GUEST_TRAP_IO, port, 1, nullptr, port);
    ASSERT_EQ(ZX_OK, t.status_value(), "install byte I/O trap\n");
  }

  auto vcpu_result = Vcpu::Create(*guest, kCodeGpa);
  ASSERT_EQ(ZX_OK, vcpu_result.status_value(), "Vcpu::Create\n");
  ktl::unique_ptr<Vcpu> vcpu = ktl::move(vcpu_result.value());
  vcpu->ForceLazyEoiGrantForTest();  // Inert (no VID gate ships); retained for compatibility.

  VcpuArchState s = {};
  ASSERT_EQ(ZX_OK, vcpu->SaveArchState(s).status_value(), "SaveArchState\n");
  s.gdtr_base = kGdtGpa;
  s.gdtr_limit = 0x0F;
  s.idtr_base = kIdtGpa;
  s.idtr_limit = 0xFFF;
  s.regs.rsp = kStackTop;
  ASSERT_EQ(ZX_OK, vcpu->RestoreArchState(s).status_value(), "load GDTR/IDTR/RSP\n");

  zx_vcpu_lazy_eoi_state_t lazy = {};
  lazy.magic = ZX_VCPU_LAZY_EOI_STATE_MAGIC;
  lazy.version = ZX_VCPU_LAZY_EOI_STATE_VERSION;
  lazy.size = sizeof(lazy);
  lazy.enabled = 1;
  lazy.assist_gpa = kAssistGpa;
  ASSERT_EQ(ZX_OK, vcpu->WriteLazyEoiState(lazy).status_value(), "register lazy EOI\n");

  zx_port_packet_t idle = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(idle).status_value(), "enter #1 (idle)\n");
  ASSERT_EQ(static_cast<uint32_t>(kHeartbeatPort), idle.guest_io.port, "starts idle\n");

  // A admitted alone -> sole in service -> granted.
  ASSERT_EQ(ZX_OK, vcpu->Interrupt(kFirstVector).status_value(), "inject A\n");
  zx_port_packet_t a_ran = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(a_ran).status_value(), "enter #2\n");
  ASSERT_EQ(static_cast<uint32_t>(kRanPort), a_ran.guest_io.port, "A handler ran\n");
  zx_port_packet_t a_epi = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(a_epi).status_value(), "enter #3\n");
  ASSERT_EQ(static_cast<uint32_t>(kFirstEpiloguePort), a_epi.guest_io.port, "A epilogue marker\n");
  ASSERT_TRUE(vcpu->LazyEoiArmed(), "A granted (sole in service)\n");
  ASSERT_EQ(kFirstVector, vcpu->LazyEoiVector(), "grant names A\n");
  uint32_t word = 0;
  ASSERT_EQ(ZX_OK, ram->Read(&word, kAssistGpa, sizeof(word)), "read word\n");
  ASSERT_EQ(1u, word, "grant offered (word=1)\n");

  // B pre-empts. THE assertion this test exists for: the nested admission
  // REVOKED A's grant -- in guest memory, not just bookkeeping -- rather than
  // overwriting the word's holder.
  ASSERT_EQ(ZX_OK, vcpu->Interrupt(kNestVector).status_value(), "inject B\n");
  zx_port_packet_t b_ran = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(b_ran).status_value(), "enter #4\n");
  ASSERT_EQ(static_cast<uint32_t>(kRanPort), b_ran.guest_io.port, "B pre-empts A\n");
  EXPECT_FALSE(vcpu->LazyEoiArmed(),
               "the nested admission must REVOKE the grant, not overwrite its holder\n");
  EXPECT_TRUE(vcpu->InService(kFirstVector) && vcpu->InService(kNestVector), "both in service\n");
  ASSERT_EQ(ZX_OK, ram->Read(&word, kAssistGpa, sizeof(word)), "read word\n");
  EXPECT_EQ(0u, word, "revocation must reach guest memory (word forced to 0)\n");
  EXPECT_EQ(0u, vcpu->EoiCompletions(), "no real EOI yet\n");
  EXPECT_EQ(0u, vcpu->LazyEoiCompletions(), "nothing reconciled -- a revoke is not a completion\n");

  // With no grant, B finds the word already 0 and takes its own real EOI.
  zx_port_packet_t b_eoi = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(b_eoi).status_value(), "enter #5\n");
  EXPECT_EQ(static_cast<uint32_t>(kBEoiPort), b_eoi.guest_io.port,
            "B must take the real-EOI branch (the word offered no skip), not the lazy skip\n");
  EXPECT_FALSE(vcpu->InService(kNestVector), "B retired by vector through its real EOI\n");
  EXPECT_TRUE(vcpu->InService(kFirstVector), "A still genuinely in service\n");
  EXPECT_EQ(1u, vcpu->EoiCompletions(), "one real EOI\n");

  // A's stand-in epilogue likewise real-EOIs; A retires -- NOT stranded.
  zx_port_packet_t a_eoi = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(a_eoi).status_value(), "enter #6\n");
  EXPECT_EQ(static_cast<uint32_t>(kAEoiPort), a_eoi.guest_io.port, "A took its own real EOI\n");
  EXPECT_FALSE(vcpu->InService(kFirstVector), "A retired -- the strand is impossible\n");
  EXPECT_EQ(2u, vcpu->EoiCompletions(), "two real EOIs total\n");
  EXPECT_EQ(0u, vcpu->LazyEoiCompletions(),
            "the nested pair produced no lazy completion: the grant was revoked, not consumed\n");

  // Report OBSERVED state, and only claim the rule held when it actually did.
  // An unconditional "OK" trailer prints identically on a RED run (these are
  // non-fatal EXPECTs, so control reaches here either way) and reads as a pass
  // in the serial log next to the framework's own FAILED lines.
  if (!vcpu->LazyEoiArmed() && !vcpu->InService(kFirstVector) && vcpu->EoiCompletions() == 2u) {
    printf("lazy-EOI revoke OK: nested admission of %#x forced A(%#x)'s grant word to 0 and "
           "cleared armed; both vectors then retired via real EOI (%lu total), 0 lazy "
           "completions -- no shared-word misattribution possible\n",
           kNestVector, kFirstVector, vcpu->EoiCompletions());
  } else {
    printf("lazy-EOI revoke MISMATCH: armed=%d A(%#x) still in service=%d real EOIs=%lu "
           "(expected armed=0, in-service=0, 2) -- the grant was overwritten, not revoked\n",
           vcpu->LazyEoiArmed(), kFirstVector, vcpu->InService(kFirstVector),
           vcpu->EoiCompletions());
  }
#else
  printf("Not x86_64; skipping.\n");
#endif  // __x86_64__

  END_TEST;
}

// ---------------------------------------------------------------------------
// ZX_VCPU_STATE_LAZY_EOI negative: with the mechanism never registered, an
// EOI still costs the ordinary, exit-generating path -- proving the new
// mechanism is opt-in and does not silently swallow exits it should not.
// ---------------------------------------------------------------------------
bool vcpu_lazy_eoi_negative_unarmed_still_exits() {
  BEGIN_TEST;

#ifdef __x86_64__
  auto guest_result = Guest::Create();
  if (guest_result.is_error() && guest_result.status_value() == ZX_ERR_NOT_SUPPORTED) {
    printf("VMX not supported here; skipping lazy-EOI negative test.\n");
    return true;
  }
  ASSERT_EQ(ZX_OK, guest_result.status_value(), "Guest::Create failed\n");
  ktl::unique_ptr<Guest> guest = ktl::move(guest_result.value());

  constexpr uint64_t kGdtGpa = 0x6000;
  constexpr uint64_t kIdtGpa = 0x6800;
  constexpr uint64_t kHandlerGpa = 0x8000;
  constexpr uint64_t kStackTop = 0xA000;
  constexpr uint32_t kVector = 0x50;
  constexpr uint32_t kEoiMsr = 0x80b;
  constexpr uint8_t kRanPort = 0x30;
  constexpr uint8_t kPastEoiPort = 0x11;

  fbl::RefPtr<VmObjectPaged> ram;
  ASSERT_EQ(ZX_OK, VmObjectPaged::Create(PMM_ALLOC_FLAG_ANY, 0u, kGuestRamSize, &ram), "ram\n");
  ASSERT_EQ(ZX_OK, WriteIdentityTables(ram), "tables\n");

  uint8_t buf[128];
  size_t n = 0;
  auto emit = [&](std::initializer_list<uint8_t> bytes) {
    for (uint8_t b : bytes) {
      buf[n++] = b;
    }
  };
  auto emit32 = [&](uint32_t v) {
    emit({static_cast<uint8_t>(v), static_cast<uint8_t>(v >> 8), static_cast<uint8_t>(v >> 16),
          static_cast<uint8_t>(v >> 24)});
  };
  auto report_byte = [&](uint8_t value, uint8_t port) { emit({0xB0, value, 0xE6, port}); };
  auto eoi = [&]() {
    emit({0xB9});
    emit32(kEoiMsr);
    emit({0x31, 0xC0, 0x31, 0xD2, 0x0F, 0x30});
  };
  auto jmp_to = [&](uint64_t base, uint64_t target) {
    const int32_t disp = static_cast<int32_t>(target) - static_cast<int32_t>(base + n + 5);
    emit({0xE9});
    emit32(static_cast<uint32_t>(disp));
  };

  n = 0;
  emit({0xFB, 0x90});  // sti ; nop -- RFLAGS.IF resets to 0.
  emit({0xEB, 0xFE});  // jmp $ -- idle until interrupted; no assist word exists to check.
  ASSERT_EQ(ZX_OK, ram->Write(buf, kCodeGpa, n), "code\n");

  const uint8_t gdt_code[8] = {0xFF, 0xFF, 0x00, 0x00, 0x00, 0x9B, 0xAF, 0x00};
  ASSERT_EQ(ZX_OK, ram->Write(gdt_code, kGdtGpa + 8, sizeof(gdt_code)), "GDT code desc\n");

  uint8_t gate[16];
  WriteIdtGate(gate, kHandlerGpa);
  ASSERT_EQ(ZX_OK, ram->Write(gate, kIdtGpa + kVector * 16, sizeof(gate)), "IDT gate\n");

  // A completely ordinary handler: report, real EOI, report again, halt.
  n = 0;
  report_byte(static_cast<uint8_t>(kVector), kRanPort);
  eoi();
  report_byte(0xA1, kPastEoiPort);
  emit({0xF4});  // hlt
  ASSERT_EQ(ZX_OK, ram->Write(buf, kHandlerGpa, n), "handler\n");
  ASSERT_EQ(ZX_OK, ram->CommitRange(0, kGuestRamSize), "commit\n");

  auto mapping = guest->RootVmar()->CreateVmMapping(0, kGuestRamSize, 0, VMAR_FLAG_SPECIFIC, ram, 0,
                                                    kMmuFlags, "guest-ram");
  ASSERT_EQ(ZX_OK, mapping.status_value(), "map\n");
  for (uint16_t port : {uint16_t{kRanPort}, uint16_t{kPastEoiPort}}) {
    auto t = guest->SetTrap(ZX_GUEST_TRAP_IO, port, 1, nullptr, port);
    ASSERT_EQ(ZX_OK, t.status_value(), "install byte I/O trap\n");
  }

  auto vcpu_result = Vcpu::Create(*guest, kCodeGpa);
  ASSERT_EQ(ZX_OK, vcpu_result.status_value(), "Vcpu::Create\n");
  ktl::unique_ptr<Vcpu> vcpu = ktl::move(vcpu_result.value());

  VcpuArchState s = {};
  ASSERT_EQ(ZX_OK, vcpu->SaveArchState(s).status_value(), "SaveArchState\n");
  s.gdtr_base = kGdtGpa;
  s.gdtr_limit = 0x0F;
  s.idtr_base = kIdtGpa;
  s.idtr_limit = 0xFFF;
  s.regs.rsp = kStackTop;
  ASSERT_EQ(ZX_OK, vcpu->RestoreArchState(s).status_value(), "load GDTR/IDTR/RSP\n");

  // Deliberately NOT registering ZX_VCPU_STATE_LAZY_EOI at all: the default,
  // never-touched-it VCPU that every non-Hyper-V, and every not-yet-upgraded
  // Hyper-V, guest is.

  ASSERT_EQ(ZX_OK, vcpu->Interrupt(kVector).status_value(), "inject\n");
  zx_port_packet_t ran = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(ran).status_value(), "enter #1\n");
  ASSERT_EQ(static_cast<uint32_t>(kRanPort), ran.guest_io.port, "handler ran\n");

  zx_port_packet_t past_eoi = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(past_eoi).status_value(), "enter #2\n");
  ASSERT_EQ(static_cast<uint32_t>(kPastEoiPort), past_eoi.guest_io.port,
            "the guest's real EOI must complete and let it reach its own next instruction\n");
  EXPECT_EQ(1u, vcpu->EoiCompletions(), "the EOI ended a real in-service interrupt\n");
  EXPECT_FALSE(vcpu->InService(kVector), "retired through the ordinary path\n");
  EXPECT_EQ(0u, vcpu->LazyEoiCompletions(),
            "the lazy-EOI mechanism took no part in this at all -- it is opt-in\n");
  EXPECT_FALSE(vcpu->LazyEoiArmed(), "never armed: nothing was ever registered\n");

  printf("lazy-EOI negative OK: with ZX_VCPU_STATE_LAZY_EOI never written, vector %#x took the "
         "ordinary real-EOI path (%lu completion(s)); the lazy mechanism never engaged\n",
         kVector, vcpu->EoiCompletions());
#else
  printf("Not x86_64; skipping.\n");
#endif  // __x86_64__

  END_TEST;
}

// ---------------------------------------------------------------------------
// ZX_VCPU_STATE_LAPIC read from a thread that does NOT own the VCPU must refuse
// to sample the assist word, and say so with its own sentinel.
//
// The word is the one field whose read dereferences the kernel's mapping of the
// guest's VP assist page -- and the OWNING thread can drop and replace that
// mapping at any moment, because the guest drives it (a write of
// HV_X64_MSR_VP_ASSIST_PAGE with the enable bit clear makes the VMM disable the
// topic, which move-assigns a default GuestPtr). GuestPtr::as() loads mapping_
// several times unlocked, so an off-thread reader can pass the null test with
// the old pointer and then reload it as null: a kernel-mode null dereference,
// guest-paced, i.e. a guest->host DoS -- and a data race on an fbl::RefPtr even
// when it does not fault.
//
// This pins the gate DETERMINISTICALLY rather than trying to win that race: an
// off-thread read must report ZX_VCPU_LAPIC_ASSIST_WORD_OFF_THREAD -- never 0,
// 1, or the unmapped sentinel, each of which would be a fabricated grant state
// for the very diagnostic used to pin an interrupt wedge -- while STILL filling
// in every other field, and the same read on the owning thread must return the
// real word.
// ---------------------------------------------------------------------------
struct LapicOffThreadContext {
  Vcpu* vcpu;
  zx_status_t status;
  zx_vcpu_lapic_state_t state;
};

bool vcpu_lapic_read_off_thread_refuses_the_assist_word() {
  BEGIN_TEST;

#ifdef __x86_64__
  auto guest_result = Guest::Create();
  if (guest_result.is_error() && guest_result.status_value() == ZX_ERR_NOT_SUPPORTED) {
    printf("VMX not supported here; skipping off-thread LAPIC read test.\n");
    return true;
  }
  ASSERT_EQ(ZX_OK, guest_result.status_value(), "Guest::Create failed\n");
  ktl::unique_ptr<Guest> guest = ktl::move(guest_result.value());

  constexpr uint64_t kGdtGpa = 0x6000;
  constexpr uint64_t kIdtGpa = 0x6800;
  constexpr uint64_t kHandlerGpa = 0x8000;
  constexpr uint64_t kAssistGpa = 0x9000;
  constexpr uint64_t kStackTop = 0xA000;
  constexpr uint32_t kVector = 0x50;
  constexpr uint8_t kRanPort = 0x30;
  constexpr uint8_t kHeartbeatPort = 0x32;

  fbl::RefPtr<VmObjectPaged> ram;
  ASSERT_EQ(ZX_OK, VmObjectPaged::Create(PMM_ALLOC_FLAG_ANY, 0u, kGuestRamSize, &ram), "ram\n");
  ASSERT_EQ(ZX_OK, WriteIdentityTables(ram), "tables\n");

  uint8_t buf[64];
  size_t n = 0;
  auto emit = [&](std::initializer_list<uint8_t> bytes) {
    for (uint8_t b : bytes) {
      buf[n++] = b;
    }
  };
  auto emit32 = [&](uint32_t v) {
    emit({static_cast<uint8_t>(v), static_cast<uint8_t>(v >> 8), static_cast<uint8_t>(v >> 16),
          static_cast<uint8_t>(v >> 24)});
  };
  auto report_byte = [&](uint8_t value, uint8_t port) { emit({0xB0, value, 0xE6, port}); };
  auto jmp_to = [&](uint64_t base, uint64_t target) {
    const int32_t disp = static_cast<int32_t>(target) - static_cast<int32_t>(base + n + 5);
    emit({0xE9});
    emit32(static_cast<uint32_t>(disp));
  };

  n = 0;
  emit({0xFB, 0x90});  // sti ; nop
  report_byte(0xBB, kHeartbeatPort);
  jmp_to(kCodeGpa, kCodeGpa);
  ASSERT_EQ(ZX_OK, ram->Write(buf, kCodeGpa, n), "code\n");

  const uint8_t gdt_code[8] = {0xFF, 0xFF, 0x00, 0x00, 0x00, 0x9B, 0xAF, 0x00};
  ASSERT_EQ(ZX_OK, ram->Write(gdt_code, kGdtGpa + 8, sizeof(gdt_code)), "GDT code desc\n");
  uint8_t gate[16];
  WriteIdtGate(gate, kHandlerGpa);
  ASSERT_EQ(ZX_OK, ram->Write(gate, kIdtGpa + kVector * 16, sizeof(gate)), "IDT gate\n");

  // Handler parks without touching the word, so a grant is still outstanding
  // (armed, word == 1) when the two reads below run -- i.e. there IS a real
  // value to report, and the off-thread sentinel is a refusal, not an artefact
  // of there being nothing to see.
  n = 0;
  report_byte(static_cast<uint8_t>(kVector), kRanPort);
  jmp_to(kHandlerGpa, kCodeGpa);
  ASSERT_EQ(ZX_OK, ram->Write(buf, kHandlerGpa, n), "handler\n");
  ASSERT_EQ(ZX_OK, ram->CommitRange(0, kGuestRamSize), "commit\n");

  auto mapping = guest->RootVmar()->CreateVmMapping(0, kGuestRamSize, 0, VMAR_FLAG_SPECIFIC, ram, 0,
                                                    kMmuFlags, "guest-ram");
  ASSERT_EQ(ZX_OK, mapping.status_value(), "map\n");
  for (uint16_t port : {uint16_t{kRanPort}, uint16_t{kHeartbeatPort}}) {
    auto t = guest->SetTrap(ZX_GUEST_TRAP_IO, port, 1, nullptr, port);
    ASSERT_EQ(ZX_OK, t.status_value(), "install byte I/O trap\n");
  }

  auto vcpu_result = Vcpu::Create(*guest, kCodeGpa);
  ASSERT_EQ(ZX_OK, vcpu_result.status_value(), "Vcpu::Create\n");
  ktl::unique_ptr<Vcpu> vcpu = ktl::move(vcpu_result.value());
  vcpu->ForceLazyEoiGrantForTest();  // Inert (no VID gate ships); retained for compatibility.

  VcpuArchState s = {};
  ASSERT_EQ(ZX_OK, vcpu->SaveArchState(s).status_value(), "SaveArchState\n");
  s.gdtr_base = kGdtGpa;
  s.gdtr_limit = 0x0F;
  s.idtr_base = kIdtGpa;
  s.idtr_limit = 0xFFF;
  s.regs.rsp = kStackTop;
  ASSERT_EQ(ZX_OK, vcpu->RestoreArchState(s).status_value(), "load GDTR/IDTR/RSP\n");

  zx_vcpu_lazy_eoi_state_t lazy = {};
  lazy.magic = ZX_VCPU_LAZY_EOI_STATE_MAGIC;
  lazy.version = ZX_VCPU_LAZY_EOI_STATE_VERSION;
  lazy.size = sizeof(lazy);
  lazy.enabled = 1;
  lazy.assist_gpa = kAssistGpa;
  ASSERT_EQ(ZX_OK, vcpu->WriteLazyEoiState(lazy).status_value(), "register lazy EOI\n");

  zx_port_packet_t idle = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(idle).status_value(), "enter #1 (idle)\n");
  ASSERT_EQ(static_cast<uint32_t>(kHeartbeatPort), idle.guest_io.port, "starts idle\n");
  ASSERT_EQ(ZX_OK, vcpu->Interrupt(kVector).status_value(), "inject\n");
  zx_port_packet_t ran = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(ran).status_value(), "enter #2\n");
  ASSERT_EQ(static_cast<uint32_t>(kRanPort), ran.guest_io.port, "handler ran\n");
  ASSERT_TRUE(vcpu->LazyEoiArmed(), "a grant is outstanding, so the word really is 1\n");

  // On the owning thread: the real word.
  zx_vcpu_lapic_state_t own = {};
  ASSERT_EQ(ZX_OK, vcpu->ReadLapicState(own).status_value(), "on-thread LAPIC read\n");
  EXPECT_EQ(1u, own.lazy_eoi_assist_word,
            "the owning thread reads the actual word, which an unconsumed grant leaves at 1\n");

  // Off-thread: refused, with the whole rest of the snapshot still served.
  LapicOffThreadContext ctx = {vcpu.get(), ZX_ERR_INTERNAL, {}};
  auto reader_body = [](void* arg) -> int {
    auto* c = reinterpret_cast<LapicOffThreadContext*>(arg);
    c->status = c->vcpu->ReadLapicState(c->state).status_value();
    return 0;
  };
  Thread* reader = Thread::Create("hv-lapic-off-thread", reader_body, &ctx, DEFAULT_PRIORITY);
  ASSERT_TRUE(reader != nullptr, "create reader thread\n");
  reader->Resume();
  int retcode = 0;
  ASSERT_EQ(ZX_OK, reader->Join(&retcode, ZX_TIME_INFINITE), "join reader thread\n");

  ASSERT_EQ(ZX_OK, ctx.status, "an off-thread diagnostics read must still SUCCEED\n");
  EXPECT_EQ(ZX_VCPU_LAPIC_ASSIST_WORD_OFF_THREAD, ctx.state.lazy_eoi_assist_word,
            "an off-thread read must refuse the word with its own sentinel: dereferencing the "
            "assist-page mapping from a thread that does not own this VCPU is what faults the "
            "host kernel when the owning thread replaces it\n");
  EXPECT_NE(1u, ctx.state.lazy_eoi_assist_word, "and must not fabricate a grant state\n");
  EXPECT_NE(ZX_VCPU_LAPIC_ASSIST_WORD_UNMAPPED, ctx.state.lazy_eoi_assist_word,
            "nor claim the page is unmapped, which it is not\n");
  // Everything else is still genuinely served off-thread -- the gate is scoped
  // to the one field that dereferences a mapping, not to the whole topic.
  EXPECT_EQ(kVector, ctx.state.isrv, "isrv is still reported off-thread\n");
  EXPECT_EQ(1u, ctx.state.lazy_eoi_armed, "as is the grant bookkeeping\n");
  EXPECT_EQ(kVector, ctx.state.lazy_eoi_vector, "and the vector it names\n");
  EXPECT_EQ(own.ppr, ctx.state.ppr, "and the processor priority agrees with the on-thread read\n");

  if (ctx.state.lazy_eoi_assist_word == ZX_VCPU_LAPIC_ASSIST_WORD_OFF_THREAD) {
    printf("off-thread LAPIC read OK: the word was refused with the off-thread sentinel (%#x) "
           "while isrv=%#x / armed=%u / vector=%#x were still served; the owning thread read the "
           "real word (%u)\n",
           ctx.state.lazy_eoi_assist_word, ctx.state.isrv, ctx.state.lazy_eoi_armed,
           ctx.state.lazy_eoi_vector, own.lazy_eoi_assist_word);
  } else {
    printf("off-thread LAPIC read UNGATED: word=%#x -- an off-thread caller dereferenced the "
           "assist-page mapping\n",
           ctx.state.lazy_eoi_assist_word);
  }
#else
  printf("Not x86_64; skipping.\n");
#endif  // __x86_64__

  END_TEST;
}

// ---------------------------------------------------------------------------
// GuestPtr::as() on a never-mapped GuestPtr must read as EMPTY, not fault.
// Regression test for a host-killing kernel NULL dereference: the diagnostics
// LAPIC read (ZX_VCPU_STATE_LAPIC) reaches `lazy_eoi_guest_ptr.as<uint32_t>()`
// on a VCPU that never registered a lazy-EOI assist page, and `as()` used to
// dereference its null mapping (mapping_->size()) before the bounds check --
// so an ordinary userspace zx_vcpu_read_state page-faulted the kernel
// (CR2 = a VmMapping field offset) and rebooted a live host on the first
// off-thread diagnostics read after a guest started. With the fix, the empty
// GuestPtr reads as nullptr and the topic reports the no-mapping sentinel.
// Without it, this test does not fail -- it panics the kernel, which is the
// point: RED is a panic, GREEN is the sentinel.
// ---------------------------------------------------------------------------
bool vcpu_lapic_read_without_assist_page_is_safe() {
  BEGIN_TEST;

#ifdef __x86_64__
  auto guest_result = Guest::Create();
  if (guest_result.is_error() && guest_result.status_value() == ZX_ERR_NOT_SUPPORTED) {
    printf("VMX not supported here; skipping LAPIC-read safety test.\n");
    return true;
  }
  ASSERT_EQ(ZX_OK, guest_result.status_value(), "Guest::Create failed\n");
  ktl::unique_ptr<Guest> guest = ktl::move(guest_result.value());

  fbl::RefPtr<VmObjectPaged> ram;
  ASSERT_EQ(ZX_OK, VmObjectPaged::Create(PMM_ALLOC_FLAG_ANY, 0u, kGuestRamSize, &ram), "ram\n");
  ASSERT_EQ(ZX_OK, WriteIdentityTables(ram), "tables\n");
  auto mapping = guest->RootVmar()->CreateVmMapping(0, kGuestRamSize, 0, VMAR_FLAG_SPECIFIC, ram, 0,
                                                    kMmuFlags, "guest-ram");
  ASSERT_EQ(ZX_OK, mapping.status_value(), "map\n");

  auto vcpu_result = Vcpu::Create(*guest, kCodeGpa);
  ASSERT_EQ(ZX_OK, vcpu_result.status_value(), "Vcpu::Create\n");
  ktl::unique_ptr<Vcpu> vcpu = ktl::move(vcpu_result.value());

  // Deliberately NO ZX_VCPU_STATE_LAZY_EOI registration: the lazy-EOI GuestPtr
  // is the default, never-mapped one -- the exact state that used to fault.
  zx_vcpu_lapic_state_t lapic = {};
  ASSERT_EQ(ZX_OK, vcpu->ReadLapicState(lapic).status_value(),
            "the diagnostics read must succeed against an unregistered VCPU\n");
  EXPECT_EQ(0xffffffffu, lapic.lazy_eoi_assist_word,
            "no assist page registered -> the no-mapping sentinel, not a fault\n");
  EXPECT_EQ(0u, lapic.lazy_eoi_registered, "not registered\n");

  printf("LAPIC-read safety OK: topic read against a VCPU with no assist page returned the "
         "no-mapping sentinel (%#x) instead of faulting the kernel\n",
         lapic.lazy_eoi_assist_word);
#else
  printf("Not x86_64; skipping.\n");
#endif  // __x86_64__

  END_TEST;
}

// ---------------------------------------------------------------------------
// ZX_VCPU_STATE_LAZY_EOI restore posture: writing the topic -- including a
// snapshot restore's write, which is indistinguishable from a live reprogram
// at this layer -- always arms the FRESH mapping to "no grant outstanding",
// regardless of anything read back from an earlier snapshot. This is the
// conservative choice ZX_VCPU_STATE_LAZY_EOI's doc comment specifies: at most
// one vector takes an ordinary EOI it could have skipped; nothing is ever
// silently left permanently in service by a restore.
// ---------------------------------------------------------------------------
bool vcpu_lazy_eoi_restore_forces_real_eoi() {
  BEGIN_TEST;

#ifdef __x86_64__
  auto guest_result = Guest::Create();
  if (guest_result.is_error() && guest_result.status_value() == ZX_ERR_NOT_SUPPORTED) {
    printf("VMX not supported here; skipping lazy-EOI restore test.\n");
    return true;
  }
  ASSERT_EQ(ZX_OK, guest_result.status_value(), "Guest::Create failed\n");
  ktl::unique_ptr<Guest> guest = ktl::move(guest_result.value());

  constexpr uint64_t kGdtGpa = 0x6000;
  constexpr uint64_t kIdtGpa = 0x6800;
  constexpr uint64_t kHandlerGpa = 0x8000;
  constexpr uint64_t kAssistGpa = 0x9000;
  constexpr uint64_t kStackTop = 0xA000;
  constexpr uint32_t kVector = 0x50;
  constexpr uint8_t kRanPort = 0x30;
  constexpr uint8_t kEpiloguePort = 0x31;

  fbl::RefPtr<VmObjectPaged> ram;
  ASSERT_EQ(ZX_OK, VmObjectPaged::Create(PMM_ALLOC_FLAG_ANY, 0u, kGuestRamSize, &ram), "ram\n");
  ASSERT_EQ(ZX_OK, WriteIdentityTables(ram), "tables\n");

  uint8_t buf[128];
  size_t n = 0;
  auto emit = [&](std::initializer_list<uint8_t> bytes) {
    for (uint8_t b : bytes) {
      buf[n++] = b;
    }
  };
  auto emit32 = [&](uint32_t v) {
    emit({static_cast<uint8_t>(v), static_cast<uint8_t>(v >> 8), static_cast<uint8_t>(v >> 16),
          static_cast<uint8_t>(v >> 24)});
  };
  auto emit64 = [&](uint64_t v) {
    for (int i = 0; i < 8; i++) {
      emit({static_cast<uint8_t>(v >> (8 * i))});
    }
  };
  auto report_byte = [&](uint8_t value, uint8_t port) { emit({0xB0, value, 0xE6, port}); };
  auto clear_assist_word = [&]() {
    emit({0x48, 0xB8});
    emit64(kAssistGpa);
    emit({0xC7, 0x00, 0x00, 0x00, 0x00, 0x00});
  };
  auto jmp_to = [&](uint64_t base, uint64_t target) {
    const int32_t disp = static_cast<int32_t>(target) - static_cast<int32_t>(base + n + 5);
    emit({0xE9});
    emit32(static_cast<uint32_t>(disp));
  };

  n = 0;
  emit({0xFB, 0x90});  // sti ; nop -- RFLAGS.IF resets to 0.
  emit({0xEB, 0xFE});  // jmp $
  ASSERT_EQ(ZX_OK, ram->Write(buf, kCodeGpa, n), "code\n");

  const uint8_t gdt_code[8] = {0xFF, 0xFF, 0x00, 0x00, 0x00, 0x9B, 0xAF, 0x00};
  ASSERT_EQ(ZX_OK, ram->Write(gdt_code, kGdtGpa + 8, sizeof(gdt_code)), "GDT code desc\n");

  uint8_t gate[16];
  WriteIdtGate(gate, kHandlerGpa);
  ASSERT_EQ(ZX_OK, ram->Write(gate, kIdtGpa + kVector * 16, sizeof(gate)), "IDT gate\n");

  n = 0;
  report_byte(static_cast<uint8_t>(kVector), kRanPort);
  clear_assist_word();
  report_byte(0xAA, kEpiloguePort);
  jmp_to(kHandlerGpa, kCodeGpa);
  ASSERT_EQ(ZX_OK, ram->Write(buf, kHandlerGpa, n), "handler\n");
  ASSERT_EQ(ZX_OK, ram->CommitRange(0, kGuestRamSize), "commit\n");

  auto mapping = guest->RootVmar()->CreateVmMapping(0, kGuestRamSize, 0, VMAR_FLAG_SPECIFIC, ram, 0,
                                                    kMmuFlags, "guest-ram");
  ASSERT_EQ(ZX_OK, mapping.status_value(), "map\n");
  for (uint16_t port : {uint16_t{kRanPort}, uint16_t{kEpiloguePort}}) {
    auto t = guest->SetTrap(ZX_GUEST_TRAP_IO, port, 1, nullptr, port);
    ASSERT_EQ(ZX_OK, t.status_value(), "install byte I/O trap\n");
  }

  auto vcpu_result = Vcpu::Create(*guest, kCodeGpa);
  ASSERT_EQ(ZX_OK, vcpu_result.status_value(), "Vcpu::Create\n");
  ktl::unique_ptr<Vcpu> vcpu = ktl::move(vcpu_result.value());
  vcpu->ForceLazyEoiGrantForTest();  // Inert (no VID gate ships); retained for compatibility.

  VcpuArchState s = {};
  ASSERT_EQ(ZX_OK, vcpu->SaveArchState(s).status_value(), "SaveArchState\n");
  s.gdtr_base = kGdtGpa;
  s.gdtr_limit = 0x0F;
  s.idtr_base = kIdtGpa;
  s.idtr_limit = 0xFFF;
  s.regs.rsp = kStackTop;
  ASSERT_EQ(ZX_OK, vcpu->RestoreArchState(s).status_value(), "load GDTR/IDTR/RSP\n");

  zx_vcpu_lazy_eoi_state_t lazy = {};
  lazy.magic = ZX_VCPU_LAZY_EOI_STATE_MAGIC;
  lazy.version = ZX_VCPU_LAZY_EOI_STATE_VERSION;
  lazy.size = sizeof(lazy);
  lazy.enabled = 1;
  lazy.assist_gpa = kAssistGpa;
  ASSERT_EQ(ZX_OK, vcpu->WriteLazyEoiState(lazy).status_value(), "register lazy EOI\n");

  // Injected before the first Enter(): the guest has not executed its `sti`
  // yet, so this entry's admission finds RFLAGS.IF clear, defers the vector,
  // and arms interrupt-window exiting -- an internal exit Enter() handles on
  // its own, re-trying admission the instant the guest's `sti` retires.
  ASSERT_EQ(ZX_OK, vcpu->Interrupt(kVector).status_value(), "inject\n");
  zx_port_packet_t ran = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(ran).status_value(), "enter #1\n");
  ASSERT_EQ(static_cast<uint32_t>(kRanPort), ran.guest_io.port, "handler ran\n");

  zx_port_packet_t epilogue = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(epilogue).status_value(), "enter #2\n");
  ASSERT_EQ(static_cast<uint32_t>(kEpiloguePort), epilogue.guest_io.port,
            "the epilogue's memory write must not exit\n");
  // A grant is now outstanding, unreconciled: exactly the mid-flight state a
  // checkpoint taken at this instant would capture.
  ASSERT_TRUE(vcpu->LazyEoiArmed(), "a grant is outstanding at the simulated snapshot point\n");
  ASSERT_TRUE(vcpu->InService(kVector), "and the vector is genuinely still in service\n");

  // Simulate a VMM restoring this exact configuration into a snapshot-restored
  // VCPU: it reads the topic (getting back enabled=1, the same assist_gpa)
  // and writes it again post-restore, exactly as it would for
  // ZX_VCPU_STATE_ENLIGHTENMENT. Nothing about the outstanding grant is, or
  // could be, carried in this payload.
  zx_vcpu_lazy_eoi_state_t readback = {};
  ASSERT_EQ(ZX_OK, vcpu->ReadLazyEoiState(readback).status_value(), "read for restore\n");
  ASSERT_EQ(ZX_OK, vcpu->WriteLazyEoiState(readback).status_value(), "restore\n");

  // The conservative posture: the write itself reconciles the outstanding
  // grant immediately (the guest had already consumed it -- the word reads 0
  // -- so this retires kVector specifically, through the same path an
  // ordinary entry would have), rather than merely discarding the
  // bookkeeping and leaving the ISR bit to strand.
  EXPECT_FALSE(vcpu->LazyEoiArmed(), "restore forces no-grant-outstanding immediately\n");
  EXPECT_FALSE(vcpu->InService(kVector),
               "and actually retired the ISR bit -- not just the bookkeeping -- because the "
               "guest had already consumed the grant; the write itself must reconcile it, since "
               "the mapping this VCPU needs to observe that later is about to be replaced\n");

  // The guest-visible consequence: the vector is deliverable again, not
  // permanently stuck.
  ASSERT_EQ(ZX_OK, vcpu->Interrupt(kVector).status_value(), "inject again post-restore\n");
  zx_port_packet_t ran_again = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(ran_again).status_value(), "enter #3\n");
  EXPECT_EQ(static_cast<uint32_t>(kRanPort), ran_again.guest_io.port,
            "deliverable again after the restore -- not stuck\n");

  printf("lazy-EOI restore OK: a write of this topic -- indistinguishable here from a snapshot "
         "restore -- unconditionally cleared the outstanding grant, and vector %#x remained "
         "deliverable afterward\n",
         kVector);
#else
  printf("Not x86_64; skipping.\n");
#endif  // __x86_64__

  END_TEST;
}

// ---------------------------------------------------------------------------
// ZX_VCPU_STATE_TLB_FLUSH: registration validates (identity, and that the
// output-only fields are not misused as input), and a request is idempotent.
// Uses the raw Vcpu accessor directly, on the VCPU's own thread; the
// cross-thread property itself is exercised by the mechanism's shape --
// WriteTlbFlushState deliberately has no ThreadIsOurThread guard, mirroring
// Vcpu::Interrupt -- not by spinning up a second thread here.
// ---------------------------------------------------------------------------
bool vcpu_tlb_flush_state_topic_validates_and_is_idempotent() {
  BEGIN_TEST;

#ifdef __x86_64__
  auto guest_result = Guest::Create();
  if (guest_result.is_error() && guest_result.status_value() == ZX_ERR_NOT_SUPPORTED) {
    printf("VMX not supported here; skipping TLB-flush registration test.\n");
    return true;
  }
  ASSERT_EQ(ZX_OK, guest_result.status_value(), "Guest::Create failed\n");
  ktl::unique_ptr<Guest> guest = ktl::move(guest_result.value());

  fbl::RefPtr<VmObjectPaged> ram;
  ASSERT_EQ(ZX_OK, VmObjectPaged::Create(PMM_ALLOC_FLAG_ANY, 0u, kGuestRamSize, &ram), "ram\n");
  ASSERT_EQ(ZX_OK, WriteIdentityTables(ram), "tables\n");
  const uint8_t code[] = {0xF4};  // hlt; never actually run in this test.
  ASSERT_EQ(ZX_OK, ram->Write(code, kCodeGpa, sizeof(code)), "code\n");
  ASSERT_EQ(ZX_OK, ram->CommitRange(0, kGuestRamSize), "commit\n");
  auto mapping = guest->RootVmar()->CreateVmMapping(0, kGuestRamSize, 0, VMAR_FLAG_SPECIFIC, ram, 0,
                                                    kMmuFlags, "guest-ram");
  ASSERT_EQ(ZX_OK, mapping.status_value(), "map\n");

  auto vcpu_result = Vcpu::Create(*guest, kCodeGpa);
  ASSERT_EQ(ZX_OK, vcpu_result.status_value(), "Vcpu::Create\n");
  ktl::unique_ptr<Vcpu> vcpu = ktl::move(vcpu_result.value());

  zx_vcpu_tlb_flush_state_t bad = {};
  bad.magic = 0xdeadbeef;
  bad.version = ZX_VCPU_TLB_FLUSH_STATE_VERSION;
  bad.size = sizeof(bad);
  EXPECT_EQ(ZX_ERR_INVALID_ARGS, vcpu->WriteTlbFlushState(bad).status_value(), "bad magic\n");
  bad.magic = ZX_VCPU_TLB_FLUSH_STATE_MAGIC;
  bad.version = 0;
  EXPECT_EQ(ZX_ERR_INVALID_ARGS, vcpu->WriteTlbFlushState(bad).status_value(), "bad version\n");
  bad.version = ZX_VCPU_TLB_FLUSH_STATE_VERSION;
  bad.size = sizeof(bad) - 1;
  EXPECT_EQ(ZX_ERR_INVALID_ARGS, vcpu->WriteTlbFlushState(bad).status_value(), "bad size\n");
  bad.size = sizeof(bad);
  bad.pending = 1;
  EXPECT_EQ(ZX_ERR_INVALID_ARGS, vcpu->WriteTlbFlushState(bad).status_value(),
            "pending is output-only\n");
  bad.pending = 0;
  bad.flushes_consumed = 1;
  EXPECT_EQ(ZX_ERR_INVALID_ARGS, vcpu->WriteTlbFlushState(bad).status_value(),
            "flushes_consumed is output-only\n");

  zx_vcpu_tlb_flush_state_t before = {};
  ASSERT_EQ(ZX_OK, vcpu->ReadTlbFlushState(before).status_value(), "read before\n");
  EXPECT_EQ(0u, before.pending, "nothing requested yet\n");
  EXPECT_EQ(0u, before.flushes_consumed, "nothing consumed yet\n");

  zx_vcpu_tlb_flush_state_t good = {};
  good.magic = ZX_VCPU_TLB_FLUSH_STATE_MAGIC;
  good.version = ZX_VCPU_TLB_FLUSH_STATE_VERSION;
  good.size = sizeof(good);
  ASSERT_EQ(ZX_OK, vcpu->WriteTlbFlushState(good).status_value(), "request\n");
  zx_vcpu_tlb_flush_state_t after_one = {};
  ASSERT_EQ(ZX_OK, vcpu->ReadTlbFlushState(after_one).status_value(), "read after one request\n");
  EXPECT_EQ(1u, after_one.pending, "now pending\n");

  // Idempotent: requesting again while already pending changes nothing
  // observable.
  ASSERT_EQ(ZX_OK, vcpu->WriteTlbFlushState(good).status_value(), "request again\n");
  zx_vcpu_tlb_flush_state_t after_two = {};
  ASSERT_EQ(ZX_OK, vcpu->ReadTlbFlushState(after_two).status_value(), "read after two requests\n");
  EXPECT_EQ(1u, after_two.pending, "still just pending\n");
  EXPECT_EQ(0u, after_two.flushes_consumed, "still not consumed -- nothing has entered yet\n");

  printf("TLB-flush registration OK: bad magic/version/size/output-only-field writes refused; a "
         "request is idempotent while pending\n");
#else
  printf("Not x86_64; skipping.\n");
#endif  // __x86_64__

  END_TEST;
}

// ---------------------------------------------------------------------------
// ZX_VCPU_STATE_TLB_FLUSH: a requested flush is consumed (INVVPID executed,
// `flushes_consumed` incremented, `pending` cleared) strictly at the next VM
// entry, before any guest instruction -- and a translation the guest cached
// before the flush is not used afterward.
//
// Two kinds of evidence, deliberately: the memory-content assertion is the
// real-world claim, but TLB eviction can mask a missing flush by accident
// (the entry might not have survived anyway), so it is not on its own proof
// of anything. The `ReadTlbFlushState` counter assertions are the
// deterministic ones: they show the pending-set -> kick -> consumed-at-entry
// ordering directly, independent of whether the stale translation happened to
// still be cached.
// ---------------------------------------------------------------------------
bool vcpu_tlb_flush_request_flushes_stale_translation() {
  BEGIN_TEST;

#ifdef __x86_64__
  auto guest_result = Guest::Create();
  if (guest_result.is_error() && guest_result.status_value() == ZX_ERR_NOT_SUPPORTED) {
    printf("VMX not supported here; skipping TLB-flush test.\n");
    return true;
  }
  ASSERT_EQ(ZX_OK, guest_result.status_value(), "Guest::Create failed\n");
  ktl::unique_ptr<Guest> guest = ktl::move(guest_result.value());

  // A second PD slot (VA [2 MiB, 4 MiB)), deliberately NOT the huge page
  // WriteIdentityTables installs at PD[0]: this needs a real, edit-able
  // 4 KiB PTE, not a 2 MiB page.
  constexpr uint64_t kPtGpa = 0x7000;
  constexpr uint64_t kPage1Gpa = 0x8000;
  constexpr uint64_t kPage2Gpa = 0x9000;
  constexpr uint64_t kStackTop = 0xA000;
  constexpr uint64_t kFlushVa = 0x0000000000200000;  // PD index 1.
  constexpr uint8_t kReadPort = 0x30;
  constexpr uint32_t kPattern1 = 0x11111111;
  constexpr uint32_t kPattern2 = 0x22222222;

  fbl::RefPtr<VmObjectPaged> ram;
  ASSERT_EQ(ZX_OK, VmObjectPaged::Create(PMM_ALLOC_FLAG_ANY, 0u, kGuestRamSize, &ram), "ram\n");
  ASSERT_EQ(ZX_OK, WriteIdentityTables(ram), "tables\n");

  const uint64_t pd1e = kPtGpa | kPresent | kWritable;  // no PS bit: a real PT, not a huge page.
  ASSERT_EQ(ZX_OK, ram->Write(&pd1e, kPdGpa + 1 * sizeof(pd1e), sizeof(pd1e)), "PD[1]\n");
  const uint64_t pte = kPage1Gpa | kPresent | kWritable;
  ASSERT_EQ(ZX_OK, ram->Write(&pte, kPtGpa, sizeof(pte)), "PTE -> page 1\n");
  ASSERT_EQ(ZX_OK, ram->Write(&kPattern1, kPage1Gpa, sizeof(kPattern1)), "page 1 contents\n");
  ASSERT_EQ(ZX_OK, ram->Write(&kPattern2, kPage2Gpa, sizeof(kPattern2)), "page 2 contents\n");

  uint8_t buf[64];
  size_t n = 0;
  auto emit = [&](std::initializer_list<uint8_t> bytes) {
    for (uint8_t b : bytes) {
      buf[n++] = b;
    }
  };
  auto emit64 = [&](uint64_t v) {
    for (int i = 0; i < 8; i++) {
      emit({static_cast<uint8_t>(v >> (8 * i))});
    }
  };
  auto read_va_and_report = [&]() {
    emit({0x48, 0xB8});  // mov rax, kFlushVa
    emit64(kFlushVa);
    emit({0x8B, 0x00});                    // mov eax, [rax]
    emit({0xE7, kReadPort});                // out kReadPort, eax (wide)
  };

  n = 0;
  read_va_and_report();  // first read, through the cacheable translation.
  read_va_and_report();  // second read, after the host retargets the PTE.
  emit({0xF4});           // hlt
  ASSERT_EQ(ZX_OK, ram->Write(buf, kCodeGpa, n), "code\n");
  ASSERT_EQ(ZX_OK, ram->CommitRange(0, kGuestRamSize), "commit\n");

  auto mapping = guest->RootVmar()->CreateVmMapping(0, kGuestRamSize, 0, VMAR_FLAG_SPECIFIC, ram, 0,
                                                    kMmuFlags, "guest-ram");
  ASSERT_EQ(ZX_OK, mapping.status_value(), "map\n");
  {
    auto t = guest->SetTrap(ZX_GUEST_TRAP_IO, kReadPort, 4, nullptr, kReadPort);
    ASSERT_EQ(ZX_OK, t.status_value(), "install wide I/O trap\n");
  }

  auto vcpu_result = Vcpu::Create(*guest, kCodeGpa);
  ASSERT_EQ(ZX_OK, vcpu_result.status_value(), "Vcpu::Create\n");
  ktl::unique_ptr<Vcpu> vcpu = ktl::move(vcpu_result.value());

  VcpuArchState s = {};
  ASSERT_EQ(ZX_OK, vcpu->SaveArchState(s).status_value(), "SaveArchState\n");
  s.regs.rsp = kStackTop;
  ASSERT_EQ(ZX_OK, vcpu->RestoreArchState(s).status_value(), "load RSP\n");

  auto wide = [](const zx_port_packet_t& p) {
    uint32_t v = 0;
    memcpy(&v, p.guest_io.data, sizeof(v));
    return v;
  };

  zx_port_packet_t first = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(first).status_value(), "enter #1\n");
  ASSERT_EQ(static_cast<uint32_t>(kReadPort), first.guest_io.port, "first read\n");
  EXPECT_EQ(kPattern1, wide(first), "reads page 1's contents through the cacheable mapping\n");

  zx_vcpu_tlb_flush_state_t before = {};
  ASSERT_EQ(ZX_OK, vcpu->ReadTlbFlushState(before).status_value(), "read before\n");
  ASSERT_EQ(0u, before.pending, "nothing requested yet\n");
  ASSERT_EQ(0u, before.flushes_consumed, "nothing consumed yet\n");

  // Retarget the PTE to page 2, entirely behind the guest's back -- a plain
  // host write to guest memory, exactly what a VMM does after deciding a
  // mapping changed.
  const uint64_t pte2 = kPage2Gpa | kPresent | kWritable;
  ASSERT_EQ(ZX_OK, ram->Write(&pte2, kPtGpa, sizeof(pte2)), "PTE -> page 2\n");

  zx_vcpu_tlb_flush_state_t request = {};
  request.magic = ZX_VCPU_TLB_FLUSH_STATE_MAGIC;
  request.version = ZX_VCPU_TLB_FLUSH_STATE_VERSION;
  request.size = sizeof(request);
  ASSERT_EQ(ZX_OK, vcpu->WriteTlbFlushState(request).status_value(), "request flush\n");
  zx_vcpu_tlb_flush_state_t after_request = {};
  ASSERT_EQ(ZX_OK, vcpu->ReadTlbFlushState(after_request).status_value(), "read after request\n");
  EXPECT_EQ(1u, after_request.pending, "pending immediately after the request\n");
  EXPECT_EQ(0u, after_request.flushes_consumed, "not consumed yet -- no entry has happened\n");

  zx_port_packet_t second = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(second).status_value(), "enter #2\n");
  ASSERT_EQ(static_cast<uint32_t>(kReadPort), second.guest_io.port, "second read\n");

  // The deterministic evidence: this Enter() call consumed the flush before
  // running any guest instruction, whether or not the stale translation
  // happened to still be cached.
  zx_vcpu_tlb_flush_state_t after_entry = {};
  ASSERT_EQ(ZX_OK, vcpu->ReadTlbFlushState(after_entry).status_value(), "read after entry\n");
  EXPECT_EQ(0u, after_entry.pending, "consumed: no longer pending\n");
  EXPECT_EQ(1u, after_entry.flushes_consumed,
            "consumed: this VCPU executed exactly one INVVPID for this request\n");

  // The probabilistic evidence: the guest's second read, through the SAME
  // virtual address, must now see page 2's contents -- not a stale cached
  // translation of page 1.
  EXPECT_EQ(kPattern2, wide(second),
            "the retargeted PTE must be visible on the very next guest read -- a stale TLB entry "
            "would still show page 1's contents\n");

  printf("TLB-flush OK: first read %#x (page 1); PTE retargeted, flush requested (pending=%u), "
         "consumed at the next entry (flushes_consumed=%lu); second read %#x (page 2)\n",
         wide(first), after_request.pending, after_entry.flushes_consumed, wide(second));
#else
  printf("Not x86_64; skipping.\n");
#endif  // __x86_64__

  END_TEST;
}

// ---------------------------------------------------------------------------
// ZX_VCPU_STATE_TLB_FLUSH: a request racing this VCPU's own consumption of an
// earlier one must not be silently erased.
//
// Consumption used to be load(pending) -> INVVPID -> store(pending, false).
// WriteTlbFlushState runs on ANY thread, not serialized against the
// consuming VCPU's own thread beyond the kick -- so a request whose
// store(true) landed between that load and that store would be overwritten
// back to false by the trailing store, with nothing left to notice: no
// crash, no assertion, just a flush that silently never happens. Fixed by
// consuming through a single atomic exchange(false) BEFORE the INVVPID (see
// vcpu.cc's own comment there for the full argument).
//
// What this test actually is: a soak test, not a precisely-triggered single
// interleaving. A boolean pending flag cannot, by construction, distinguish
// "one request, delivered" from "several requests, coalesced" from the
// outside -- so a black-box test cannot directly count how many individual
// erasures did or did not happen, and MEASURED (2026-08-01): reverting this
// code to the old load/INVVPID/store pattern and running this exact test
// still passes 111/111 -- the assertions below did not empirically catch the
// window on that run, even across several million racer iterations (each
// `WriteTlbFlushState` call sends this VCPU's own thread a real IPI, which
// forces additional internal VM-exit/re-entry cycles this consumption code
// runs on too, so the true number of race attempts per test run is far
// higher than the `kIterations` outer-loop count suggests -- and it still
// was not enough to flip a black-box assertion). That is not evidence the
// bug is benign; it is evidence this KIND of black-box test cannot bound the
// false-negative rate for a single-bit erasure race, which is exactly why
// the fix does not rest on this test. What it CAN, and does, show: the
// mechanism survives millions of overlapping request/entry pairs -- real
// concurrent load against the real code path, including the IPI-induced
// internal re-entries -- without hanging, faulting, deadlocking, or leaving
// the flag stuck in a state a drained, no-longer-racing final entry cannot
// resolve. The correctness argument for the fix itself is the atomicity of
// `exchange` (a single indivisible read-and-clear has no window for a
// concurrent store to land invisibly in), argued in vcpu.cc's own comment;
// this test is concurrency-safety coverage, not a substitute for that
// argument, and its own doc comment says so rather than overclaiming a red
// result that was not observed.
// ---------------------------------------------------------------------------
bool vcpu_tlb_flush_concurrent_requests_are_not_erased() {
  BEGIN_TEST;

#ifdef __x86_64__
  auto guest_result = Guest::Create();
  if (guest_result.is_error() && guest_result.status_value() == ZX_ERR_NOT_SUPPORTED) {
    printf("VMX not supported here; skipping TLB-flush concurrency test.\n");
    return true;
  }
  ASSERT_EQ(ZX_OK, guest_result.status_value(), "Guest::Create failed\n");
  ktl::unique_ptr<Guest> guest = ktl::move(guest_result.value());

  constexpr uint64_t kStackTop = 0xA000;
  constexpr uint8_t kHeartbeatPort = 0x30;
  constexpr uint32_t kIterations = 20;

  fbl::RefPtr<VmObjectPaged> ram;
  ASSERT_EQ(ZX_OK, VmObjectPaged::Create(PMM_ALLOC_FLAG_ANY, 0u, kGuestRamSize, &ram), "ram\n");
  ASSERT_EQ(ZX_OK, WriteIdentityTables(ram), "tables\n");

  // mov al, 0xBB ; out kHeartbeatPort, al ; jmp <back to the start>. A tight
  // loop that always exits immediately, so thousands of entries can be
  // driven back-to-back with no guest-side delay.
  const uint8_t code[] = {0xB0, 0xBB, 0xE6, kHeartbeatPort, 0xEB, 0xFC};
  ASSERT_EQ(ZX_OK, ram->Write(code, kCodeGpa, sizeof(code)), "code\n");
  ASSERT_EQ(ZX_OK, ram->CommitRange(0, kGuestRamSize), "commit\n");

  auto mapping = guest->RootVmar()->CreateVmMapping(0, kGuestRamSize, 0, VMAR_FLAG_SPECIFIC, ram, 0,
                                                    kMmuFlags, "guest-ram");
  ASSERT_EQ(ZX_OK, mapping.status_value(), "map\n");
  {
    auto t = guest->SetTrap(ZX_GUEST_TRAP_IO, kHeartbeatPort, 1, nullptr, kHeartbeatPort);
    ASSERT_EQ(ZX_OK, t.status_value(), "install heartbeat trap\n");
  }

  auto vcpu_result = Vcpu::Create(*guest, kCodeGpa);
  ASSERT_EQ(ZX_OK, vcpu_result.status_value(), "Vcpu::Create\n");
  ktl::unique_ptr<Vcpu> vcpu = ktl::move(vcpu_result.value());

  VcpuArchState s = {};
  ASSERT_EQ(ZX_OK, vcpu->SaveArchState(s).status_value(), "SaveArchState\n");
  s.regs.rsp = kStackTop;
  ASSERT_EQ(ZX_OK, vcpu->RestoreArchState(s).status_value(), "load RSP\n");

  struct RacerCtx {
    Vcpu* vcpu;
    ktl::atomic<bool> go{false};
    ktl::atomic<bool> stop{false};
    ktl::atomic<uint64_t> requests_issued{0};
  };
  RacerCtx ctx{vcpu.get()};
  auto racer_body = [](void* arg) -> int {
    auto* c = static_cast<RacerCtx*>(arg);
    while (!c->go.load(ktl::memory_order_acquire)) {
      Thread::Current::Yield();
    }
    zx_vcpu_tlb_flush_state_t request = {};
    request.magic = ZX_VCPU_TLB_FLUSH_STATE_MAGIC;
    request.version = ZX_VCPU_TLB_FLUSH_STATE_VERSION;
    request.size = sizeof(request);
    // Yield every iteration. This is a real host CPU, potentially shared with
    // other work (including other CPUs waiting on this one) -- an unbounded,
    // uncooperative spin here was measured to starve a sibling CPU badly
    // enough to trip the lockup detector and stretch this one test past five
    // minutes. Yielding still lets this thread and the main loop below
    // interleave across many iterations (that overlap, not per-iteration
    // density, is what gives the exchange window its chances); it is simply
    // not allowed to monopolize a core to do it.
    while (!c->stop.load(ktl::memory_order_relaxed)) {
      if (c->vcpu->WriteTlbFlushState(request).is_ok()) {
        c->requests_issued.fetch_add(1, ktl::memory_order_relaxed);
      }
      Thread::Current::Yield();
    }
    return 0;
  };
  Thread* racer = Thread::Create("hv-tlb-flush-racer", racer_body, &ctx, DEFAULT_PRIORITY);
  ASSERT_TRUE(racer != nullptr, "create racer thread\n");
  racer->Resume();
  ctx.go.store(true, ktl::memory_order_release);

  // Make the concurrency precondition EXPLICIT and bounded rather than assumed.
  // The old loop ran a fixed kIterations entries and then asserted the racer had
  // issued at least one request -- which is a false red whenever the racer
  // thread simply never got scheduled inside that window (a starved sibling on a
  // contended 2-vCPU host, exactly what a nested-KVM CI runner is). Instead,
  // drive at least kIterations entries AND keep going until the racer has
  // demonstrably issued kMinConcurrentRequests requests, up to a wall-clock
  // deadline so a genuinely starved racer can never hang the test. `raced`
  // records whether real overlap actually occurred; the flushes_consumed
  // assertion below is made only when it did.
  constexpr uint64_t kMinConcurrentRequests = 4;
  const zx_instant_mono_t concurrency_deadline = current_mono_time() + ZX_SEC(10);
  uint32_t entries = 0;
  bool raced = false;
  for (;;) {
    zx_port_packet_t p = {};
    ASSERT_EQ(ZX_OK, vcpu->Enter(p).status_value(),
              "entry must not fail under concurrent flush requests\n");
    entries++;
    const uint64_t issued = ctx.requests_issued.load(ktl::memory_order_relaxed);
    if (entries >= kIterations && issued >= kMinConcurrentRequests) {
      raced = true;
      break;
    }
    if (current_mono_time() >= concurrency_deadline) {
      // Bounded exit: the racer did not reach the target overlap in time. If it
      // issued anything at all the run still raced (any request the drain entry
      // has not yet consumed is genuine overlap); if it issued nothing it
      // starved and there is no concurrency to assert on.
      raced = issued > 0;
      break;
    }
  }

  ctx.stop.store(true, ktl::memory_order_relaxed);
  int retcode = 0;
  ASSERT_EQ(ZX_OK, racer->Join(&retcode, ZX_TIME_INFINITE), "join racer\n");

  // With the racer joined, its last possible write has already happened
  // (Join is a happens-before edge): no further concurrent writer exists, so
  // one more entry is guaranteed to resolve whatever it left pending. This
  // is a convergence/no-hang check, not evidence about whether an erasure
  // happened earlier in the run -- see the test's own doc comment.
  zx_port_packet_t drain = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(drain).status_value(), "drain entry\n");

  zx_vcpu_tlb_flush_state_t final_state = {};
  ASSERT_EQ(ZX_OK, vcpu->ReadTlbFlushState(final_state).status_value(), "read final state\n");
  EXPECT_EQ(0u, final_state.pending,
            "must converge to not-pending once the racer has stopped and one more entry has "
            "run\n");
  const uint64_t issued = ctx.requests_issued.load(ktl::memory_order_relaxed);
  if (raced) {
    // Real overlap occurred (the racer issued requests while entries ran), so a
    // consume is guaranteed: every entry that observes pending clears it through
    // exchange(false) and counts it, and the drain entry above consumes any
    // request still outstanding at join. flushes_consumed==0 with issued>0 would
    // mean a request was silently erased -- exactly the regression under test.
    EXPECT_GT(final_state.flushes_consumed, 0u,
              "the racer issued requests concurrently, so at least one must have been consumed -- "
              "zero means a request was silently erased\n");
    printf("TLB-flush concurrency OK: %lu requests issued by the racer against %u entries; %lu "
           "flush(es) consumed; converged to not-pending after the racer stopped and one drain "
           "entry\n",
           issued, entries, final_state.flushes_consumed);
  } else {
    // The racer starved (issued nothing within the deadline): this run exercised
    // no overlap, so there is nothing to assert about consumption. This is not a
    // product failure -- it is a scheduling outcome on a contended host -- so the
    // run reports the missed precondition rather than reddening the suite. The
    // convergence check above (pending==0, no hang) is still enforced.
    printf("TLB-flush concurrency: racer starved (0 requests in %u entries before the deadline); "
           "no overlap exercised this run -- convergence still verified, concurrency assertion "
           "skipped rather than falsely failed\n",
           entries);
  }
#else
  printf("Not x86_64; skipping.\n");
#endif  // __x86_64__

  END_TEST;
}

// ---------------------------------------------------------------------------
// ZX_VCPU_STATE_LAZY_EOI strand regression (the winnano wedge, modeled
// directly): a low-class vector A is granted; a high-class vector B nests; B
// consumes the single shared word and skips its EOI; A's epilogue then finds
// the word 0 and takes a real EOI -- which retires TOP-of-ISR (B), not A.
// Under the old overwrite protocol A's in-service bit is never retired, so A's
// whole priority class is blocked on this VCPU forever: a subsequent
// same-class vector C is refused (RED -- C never runs; the guest stays idle).
// Under the sole-vector rule B's nested admission revokes the grant, so the
// word offers B no skip, B retires itself by a real EOI, A retires by its own,
// and C is delivered (GREEN).
//
// RED capture (2026-08-07): with the sole-vector guard in guest_lazy_eoi_arm
// temporarily reverted to the overwrite protocol, this test fails exactly as
// described -- the nested-admission EXPECTs (armed still set, word still 1)
// trip, and the headline C-delivery EXPECT lands on the idle heartbeat port
// instead of C's handler, i.e. C blocked by the stranded A. Restored after.
// ---------------------------------------------------------------------------
bool vcpu_lazy_eoi_strand_regression_lower_vector_delivers() {
  BEGIN_TEST;

#ifdef __x86_64__
  auto guest_result = Guest::Create();
  if (guest_result.is_error() && guest_result.status_value() == ZX_ERR_NOT_SUPPORTED) {
    printf("VMX not supported here; skipping lazy-EOI strand regression.\n");
    return true;
  }
  ASSERT_EQ(ZX_OK, guest_result.status_value(), "Guest::Create failed\n");
  ktl::unique_ptr<Guest> guest = ktl::move(guest_result.value());

  constexpr uint64_t kGdtGpa = 0x6000;
  constexpr uint64_t kIdtGpa = 0x6800;
  constexpr uint64_t kAHandlerGpa = 0x8000;
  constexpr uint64_t kBHandlerGpa = 0x8080;
  constexpr uint64_t kBRealEoiGpa = 0x80B0;  // fixed stub offset within B's handler
  constexpr uint64_t kSharedEpilogueGpa = 0x8100;
  constexpr uint64_t kARealEoiGpa = 0x8140;
  constexpr uint64_t kCHandlerGpa = 0x8180;
  constexpr uint64_t kAssistGpa = 0x9000;
  constexpr uint64_t kStackTop = 0xA000;
  // A and C share a priority CLASS (5); B is a higher class (6) so it nests.
  // C at A's own class is delivered only if A's in-service bit was retired.
  constexpr uint32_t kAVector = 0x50;
  constexpr uint32_t kBVector = 0x60;
  constexpr uint32_t kCVector = 0x51;
  constexpr uint32_t kEoiMsr = 0x80b;
  constexpr uint8_t kRanPort = 0x30;
  constexpr uint8_t kAEpiloguePort = 0x31;
  constexpr uint8_t kHeartbeatPort = 0x32;
  constexpr uint8_t kBEoiPort = 0x33;
  constexpr uint8_t kAEoiPort = 0x34;
  constexpr uint8_t kCRanPort = 0x36;

  fbl::RefPtr<VmObjectPaged> ram;
  ASSERT_EQ(ZX_OK, VmObjectPaged::Create(PMM_ALLOC_FLAG_ANY, 0u, kGuestRamSize, &ram), "ram\n");
  ASSERT_EQ(ZX_OK, WriteIdentityTables(ram), "tables\n");

  uint8_t buf[128];
  size_t n = 0;
  auto emit = [&](std::initializer_list<uint8_t> bytes) {
    for (uint8_t b : bytes) {
      buf[n++] = b;
    }
  };
  auto emit32 = [&](uint32_t v) {
    emit({static_cast<uint8_t>(v), static_cast<uint8_t>(v >> 8), static_cast<uint8_t>(v >> 16),
          static_cast<uint8_t>(v >> 24)});
  };
  auto emit64 = [&](uint64_t v) {
    for (int i = 0; i < 8; i++) {
      emit({static_cast<uint8_t>(v >> (8 * i))});
    }
  };
  auto report_byte = [&](uint8_t value, uint8_t port) { emit({0xB0, value, 0xE6, port}); };
  auto eoi = [&]() {
    emit({0xB9});
    emit32(kEoiMsr);
    emit({0x31, 0xC0, 0x31, 0xD2, 0x0F, 0x30});
  };
  auto jmp_to = [&](uint64_t base, uint64_t target) {
    const int32_t disp = static_cast<int32_t>(target) - static_cast<int32_t>(base + n + 5);
    emit({0xE9});
    emit32(static_cast<uint32_t>(disp));
  };
  auto jz_to = [&](uint64_t base, uint64_t target) {
    const int32_t disp = static_cast<int32_t>(target) - static_cast<int32_t>(base + n + 2);
    emit({0x74, static_cast<uint8_t>(disp)});
  };

  n = 0;
  emit({0xFB, 0x90});  // sti ; nop
  report_byte(0xBB, kHeartbeatPort);
  jmp_to(kCodeGpa, kCodeGpa);
  ASSERT_EQ(ZX_OK, ram->Write(buf, kCodeGpa, n), "code\n");

  const uint8_t gdt_code[8] = {0xFF, 0xFF, 0x00, 0x00, 0x00, 0x9B, 0xAF, 0x00};
  ASSERT_EQ(ZX_OK, ram->Write(gdt_code, kGdtGpa + 8, sizeof(gdt_code)), "GDT code desc\n");

  struct Gate {
    uint32_t vector;
    uint64_t handler;
  };
  const Gate gates[] = {
      {kAVector, kAHandlerGpa}, {kBVector, kBHandlerGpa}, {kCVector, kCHandlerGpa}};
  for (const Gate& g : gates) {
    uint8_t gate[16];
    WriteIdtGate(gate, g.handler);
    ASSERT_EQ(ZX_OK, ram->Write(gate, kIdtGpa + g.vector * 16, sizeof(gate)), "IDT gate\n");
  }

  // A: report, re-enable interrupts, report its epilogue marker, park -- never
  // touching the word, so it holds a live grant when B pre-empts.
  n = 0;
  report_byte(static_cast<uint8_t>(kAVector), kRanPort);
  emit({0xFB, 0x90});
  report_byte(0xAA, kAEpiloguePort);
  jmp_to(kAHandlerGpa, kCodeGpa);
  ASSERT_EQ(ZX_OK, ram->Write(buf, kAHandlerGpa, n), "A handler\n");

  // B: report; then check the word. Lazy branch (word offered a skip): clear
  // it and jump straight to A's epilogue WITHOUT any intervening exit -- so
  // under the overwrite protocol A's real EOI lands before any reconciliation
  // can run, which is precisely how it retires B's bit and strands A. Real
  // branch (word already 0 under the sole-vector rule): a real EOI retires B.
  n = 0;
  report_byte(static_cast<uint8_t>(kBVector), kRanPort);
  emit({0x48, 0xBB});
  emit64(kAssistGpa);
  emit({0x8B, 0x03});  // mov eax, [rbx]
  emit({0x85, 0xC0});  // test eax, eax
  jz_to(kBHandlerGpa, kBRealEoiGpa);
  emit({0xC7, 0x03, 0x00, 0x00, 0x00, 0x00});  // (word was 1) lazy skip, NO exit
  jmp_to(kBHandlerGpa, kSharedEpilogueGpa);
  ASSERT_LE(n, static_cast<size_t>(kBRealEoiGpa - kBHandlerGpa), "B prologue overruns stub\n");
  while (n < static_cast<size_t>(kBRealEoiGpa - kBHandlerGpa)) {
    emit({0x90});
  }
  eoi();
  report_byte(0xCC, kBEoiPort);
  jmp_to(kBRealEoiGpa, kSharedEpilogueGpa);
  ASSERT_EQ(ZX_OK, ram->Write(buf, kBHandlerGpa, n), "B handler\n");

  // Shared stand-in for A's epilogue: read word; if 0, real EOI (retires
  // whatever is top-of-ISR now -- the strand's crux).
  n = 0;
  emit({0x48, 0xBB});
  emit64(kAssistGpa);
  emit({0x8B, 0x03});
  emit({0x85, 0xC0});
  jz_to(kSharedEpilogueGpa, kARealEoiGpa);
  emit({0xC7, 0x03, 0x00, 0x00, 0x00, 0x00});
  jmp_to(kSharedEpilogueGpa, kCodeGpa);
  ASSERT_LE(n, static_cast<size_t>(kARealEoiGpa - kSharedEpilogueGpa), "epilogue overruns\n");
  ASSERT_EQ(ZX_OK, ram->Write(buf, kSharedEpilogueGpa, n), "shared epilogue\n");

  n = 0;
  eoi();
  report_byte(0xEE, kAEoiPort);
  jmp_to(kARealEoiGpa, kCodeGpa);
  ASSERT_LE(n, static_cast<size_t>(kCHandlerGpa - kARealEoiGpa), "real-EOI sub overruns\n");
  ASSERT_EQ(ZX_OK, ram->Write(buf, kARealEoiGpa, n), "A real-EOI sub\n");

  // C: report its own vector, then park. Reached only if A's class is free.
  n = 0;
  report_byte(static_cast<uint8_t>(kCVector), kCRanPort);
  emit({0xFB, 0x90});
  jmp_to(kCHandlerGpa, kCodeGpa);
  ASSERT_EQ(ZX_OK, ram->Write(buf, kCHandlerGpa, n), "C handler\n");
  ASSERT_EQ(ZX_OK, ram->CommitRange(0, kGuestRamSize), "commit\n");

  auto mapping = guest->RootVmar()->CreateVmMapping(0, kGuestRamSize, 0, VMAR_FLAG_SPECIFIC, ram, 0,
                                                    kMmuFlags, "guest-ram");
  ASSERT_EQ(ZX_OK, mapping.status_value(), "map\n");
  for (uint16_t port : {uint16_t{kRanPort}, uint16_t{kAEpiloguePort}, uint16_t{kHeartbeatPort},
                        uint16_t{kBEoiPort}, uint16_t{kAEoiPort}, uint16_t{kCRanPort}}) {
    auto t = guest->SetTrap(ZX_GUEST_TRAP_IO, port, 1, nullptr, port);
    ASSERT_EQ(ZX_OK, t.status_value(), "install byte I/O trap\n");
  }

  auto vcpu_result = Vcpu::Create(*guest, kCodeGpa);
  ASSERT_EQ(ZX_OK, vcpu_result.status_value(), "Vcpu::Create\n");
  ktl::unique_ptr<Vcpu> vcpu = ktl::move(vcpu_result.value());
  vcpu->ForceLazyEoiGrantForTest();  // Inert (no VID gate ships); retained for compatibility.

  VcpuArchState s = {};
  ASSERT_EQ(ZX_OK, vcpu->SaveArchState(s).status_value(), "SaveArchState\n");
  s.gdtr_base = kGdtGpa;
  s.gdtr_limit = 0x0F;
  s.idtr_base = kIdtGpa;
  s.idtr_limit = 0xFFF;
  s.regs.rsp = kStackTop;
  ASSERT_EQ(ZX_OK, vcpu->RestoreArchState(s).status_value(), "load GDTR/IDTR/RSP\n");

  zx_vcpu_lazy_eoi_state_t lazy = {};
  lazy.magic = ZX_VCPU_LAZY_EOI_STATE_MAGIC;
  lazy.version = ZX_VCPU_LAZY_EOI_STATE_VERSION;
  lazy.size = sizeof(lazy);
  lazy.enabled = 1;
  lazy.assist_gpa = kAssistGpa;
  ASSERT_EQ(ZX_OK, vcpu->WriteLazyEoiState(lazy).status_value(), "register lazy EOI\n");

  zx_port_packet_t idle = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(idle).status_value(), "enter #1 (idle)\n");
  ASSERT_EQ(static_cast<uint32_t>(kHeartbeatPort), idle.guest_io.port, "starts idle\n");

  ASSERT_EQ(ZX_OK, vcpu->Interrupt(kAVector).status_value(), "inject A\n");
  zx_port_packet_t a_ran = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(a_ran).status_value(), "enter #2\n");
  ASSERT_EQ(static_cast<uint32_t>(kRanPort), a_ran.guest_io.port, "A handler ran\n");
  zx_port_packet_t a_epi = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(a_epi).status_value(), "enter #3\n");
  ASSERT_EQ(static_cast<uint32_t>(kAEpiloguePort), a_epi.guest_io.port, "A epilogue marker\n");
  EXPECT_TRUE(vcpu->LazyEoiArmed(), "A granted (sole in service)\n");
  EXPECT_EQ(kAVector, vcpu->LazyEoiVector(), "grant names A\n");

  ASSERT_EQ(ZX_OK, vcpu->Interrupt(kBVector).status_value(), "inject B\n");
  zx_port_packet_t b_ran = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(b_ran).status_value(), "enter #4\n");
  ASSERT_EQ(static_cast<uint32_t>(kRanPort), b_ran.guest_io.port, "B pre-empts A\n");
  // The revoke -- non-fatal EXPECTs so a RED run proceeds to the C headline.
  EXPECT_FALSE(vcpu->LazyEoiArmed(),
               "nested admission must revoke A's grant (RED: overwrite leaves it armed)\n");
  uint32_t word = 0xffffffff;
  ASSERT_EQ(ZX_OK, ram->Read(&word, kAssistGpa, sizeof(word)), "read word\n");
  EXPECT_EQ(0u, word, "revoke must force the word to 0 (RED: overwrite leaves it 1)\n");

  zx_port_packet_t after_b = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(after_b).status_value(), "enter #5\n");
  EXPECT_EQ(static_cast<uint32_t>(kBEoiPort), after_b.guest_io.port,
            "B must take its own real EOI (RED: B lazy-skips and A's EOI surfaces here instead)\n");

  zx_port_packet_t after_a = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(after_a).status_value(), "enter #6\n");
  EXPECT_EQ(static_cast<uint32_t>(kAEoiPort), after_a.guest_io.port, "A takes its own real EOI\n");
  EXPECT_FALSE(vcpu->InService(kBVector), "B retired\n");
  EXPECT_FALSE(vcpu->InService(kAVector),
               "A retired -- NOT stranded (RED: A's bit is still set here)\n");
  EXPECT_EQ(0u, vcpu->LazyEoiCompletions(), "no lazy completion for the nested pair\n");

  // THE headline: with A's class free, a same-class C is delivered. Under the
  // strand it is refused forever and the guest stays idle.
  ASSERT_EQ(ZX_OK, vcpu->Interrupt(kCVector).status_value(), "inject C\n");
  zx_port_packet_t c_ran = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(c_ran).status_value(), "enter #7\n");
  EXPECT_EQ(static_cast<uint32_t>(kCRanPort), c_ran.guest_io.port,
            "C (same class as A) must be delivered once A retired -- landing on the heartbeat "
            "port instead is the strand: A's never-retired in-service bit blocks its whole "
            "class forever\n");
  EXPECT_EQ(kCVector, static_cast<uint32_t>(c_ran.guest_io.data[0]), "and it is C itself\n");

  // Same rule as the revoke test above: never print an "OK" trailer the RED
  // leg would print verbatim. The strand's signature is C landing on the
  // heartbeat port (the guest idled because A's class stayed blocked), so say
  // exactly that instead.
  if (c_ran.guest_io.port == static_cast<uint32_t>(kCRanPort) && !vcpu->InService(kAVector)) {
    printf("lazy-EOI strand regression OK: B nested on A revoked the grant; B and A each retired "
           "through their own real EOI; a subsequent same-class vector %#x was delivered (port "
           "%#x) -- the winnano strand cannot form under the sole-vector rule\n",
           kCVector, c_ran.guest_io.port);
  } else {
    printf("lazy-EOI strand regression STRANDED: A(%#x) in service=%d; C(%#x) surfaced on port "
           "%#x (expected %#x) -- A's never-retired bit is blocking its whole class\n",
           kAVector, vcpu->InService(kAVector), kCVector, c_ran.guest_io.port,
           static_cast<uint32_t>(kCRanPort));
  }
#else
  printf("Not x86_64; skipping.\n");
#endif  // __x86_64__

  END_TEST;
}

// ---------------------------------------------------------------------------
// ZX_VCPU_STATE_LAZY_EOI: moving (or disabling) the assist page while a
// grant is armed but NOT yet consumed must revoke it in guest memory before
// the old mapping is dropped -- not merely forget this kernel's bookkeeping
// for it. A real guest's dispatch trampoline typically caches the assist
// page's address rather than re-reading the enlightenment MSR on every
// epilogue, so an interrupt already in flight when the move/disable lands
// can still dereference the SAME old physical page afterward.
//
// RED-VERIFIED 2026-08-01: with the old-word revocation removed from
// WriteLazyEoiState (leaving only the already-consumed-grant reconcile),
// this test fails exactly as predicted. Reverted after confirming.
// ---------------------------------------------------------------------------
bool vcpu_lazy_eoi_move_while_unconsumed_revokes_old_word() {
  BEGIN_TEST;

#ifdef __x86_64__
  auto guest_result = Guest::Create();
  if (guest_result.is_error() && guest_result.status_value() == ZX_ERR_NOT_SUPPORTED) {
    printf("VMX not supported here; skipping lazy-EOI move-while-unconsumed test.\n");
    return true;
  }
  ASSERT_EQ(ZX_OK, guest_result.status_value(), "Guest::Create failed\n");
  ktl::unique_ptr<Guest> guest = ktl::move(guest_result.value());

  constexpr uint64_t kGdtGpa = 0x6000;
  constexpr uint64_t kIdtGpa = 0x6800;
  constexpr uint64_t kHandlerGpa = 0x8000;
  constexpr uint64_t kOldAssistGpa = 0x9000;
  constexpr uint64_t kNewAssistGpa = 0xB000;
  constexpr uint64_t kStackTop = 0xA000;
  constexpr uint32_t kVector = 0x50;
  constexpr uint8_t kRanPort = 0x30;
  constexpr uint8_t kEpiloguePort = 0x31;

  fbl::RefPtr<VmObjectPaged> ram;
  ASSERT_EQ(ZX_OK, VmObjectPaged::Create(PMM_ALLOC_FLAG_ANY, 0u, kGuestRamSize, &ram), "ram\n");
  ASSERT_EQ(ZX_OK, WriteIdentityTables(ram), "tables\n");

  uint8_t buf[32];
  size_t n = 0;
  auto emit = [&](std::initializer_list<uint8_t> bytes) {
    for (uint8_t b : bytes) {
      buf[n++] = b;
    }
  };
  auto emit32 = [&](uint32_t v) {
    emit({static_cast<uint8_t>(v), static_cast<uint8_t>(v >> 8), static_cast<uint8_t>(v >> 16),
          static_cast<uint8_t>(v >> 24)});
  };
  auto report_byte = [&](uint8_t value, uint8_t port) { emit({0xB0, value, 0xE6, port}); };
  auto jmp_to = [&](uint64_t base, uint64_t target) {
    const int32_t disp = static_cast<int32_t>(target) - static_cast<int32_t>(base + n + 5);
    emit({0xE9});
    emit32(static_cast<uint32_t>(disp));
  };

  n = 0;
  emit({0xFB, 0x90});
  emit({0xEB, 0xFE});  // jmp $
  ASSERT_EQ(ZX_OK, ram->Write(buf, kCodeGpa, n), "code\n");

  const uint8_t gdt_code[8] = {0xFF, 0xFF, 0x00, 0x00, 0x00, 0x9B, 0xAF, 0x00};
  ASSERT_EQ(ZX_OK, ram->Write(gdt_code, kGdtGpa + 8, sizeof(gdt_code)), "GDT code desc\n");

  uint8_t gate[16];
  WriteIdtGate(gate, kHandlerGpa);
  ASSERT_EQ(ZX_OK, ram->Write(gate, kIdtGpa + kVector * 16, sizeof(gate)), "IDT gate\n");

  // Reports and parks WITHOUT touching the word -- the grant stays
  // unconsumed for as long as the test needs it to.
  n = 0;
  report_byte(static_cast<uint8_t>(kVector), kRanPort);
  report_byte(0xAA, kEpiloguePort);
  jmp_to(kHandlerGpa, kCodeGpa);
  ASSERT_EQ(ZX_OK, ram->Write(buf, kHandlerGpa, n), "handler\n");
  ASSERT_EQ(ZX_OK, ram->CommitRange(0, kGuestRamSize), "commit\n");

  auto mapping = guest->RootVmar()->CreateVmMapping(0, kGuestRamSize, 0, VMAR_FLAG_SPECIFIC, ram, 0,
                                                    kMmuFlags, "guest-ram");
  ASSERT_EQ(ZX_OK, mapping.status_value(), "map\n");
  for (uint16_t port : {uint16_t{kRanPort}, uint16_t{kEpiloguePort}}) {
    auto t = guest->SetTrap(ZX_GUEST_TRAP_IO, port, 1, nullptr, port);
    ASSERT_EQ(ZX_OK, t.status_value(), "install byte I/O trap\n");
  }

  auto vcpu_result = Vcpu::Create(*guest, kCodeGpa);
  ASSERT_EQ(ZX_OK, vcpu_result.status_value(), "Vcpu::Create\n");
  ktl::unique_ptr<Vcpu> vcpu = ktl::move(vcpu_result.value());
  vcpu->ForceLazyEoiGrantForTest();  // Inert (no VID gate ships); retained for compatibility.

  VcpuArchState s = {};
  ASSERT_EQ(ZX_OK, vcpu->SaveArchState(s).status_value(), "SaveArchState\n");
  s.gdtr_base = kGdtGpa;
  s.gdtr_limit = 0x0F;
  s.idtr_base = kIdtGpa;
  s.idtr_limit = 0xFFF;
  s.regs.rsp = kStackTop;
  ASSERT_EQ(ZX_OK, vcpu->RestoreArchState(s).status_value(), "load GDTR/IDTR/RSP\n");

  zx_vcpu_lazy_eoi_state_t lazy = {};
  lazy.magic = ZX_VCPU_LAZY_EOI_STATE_MAGIC;
  lazy.version = ZX_VCPU_LAZY_EOI_STATE_VERSION;
  lazy.size = sizeof(lazy);
  lazy.enabled = 1;
  lazy.assist_gpa = kOldAssistGpa;
  ASSERT_EQ(ZX_OK, vcpu->WriteLazyEoiState(lazy).status_value(), "register at the OLD address\n");

  ASSERT_EQ(ZX_OK, vcpu->Interrupt(kVector).status_value(), "inject\n");
  zx_port_packet_t ran = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(ran).status_value(), "enter #1\n");
  ASSERT_EQ(static_cast<uint32_t>(kRanPort), ran.guest_io.port, "handler ran\n");

  zx_port_packet_t epilogue = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(epilogue).status_value(), "enter #2\n");
  ASSERT_EQ(static_cast<uint32_t>(kEpiloguePort), epilogue.guest_io.port, "reached epilogue\n");

  uint32_t old_word_before = 0;
  ASSERT_EQ(ZX_OK, ram->Read(&old_word_before, kOldAssistGpa, sizeof(old_word_before)),
            "read old word before move\n");
  ASSERT_EQ(1u, old_word_before, "the grant is genuinely unconsumed before the move\n");
  ASSERT_TRUE(vcpu->LazyEoiArmed(), "armed\n");

  // The move: reprogram to a NEW address while the grant above is still
  // outstanding. A real VMM issues this in response to the GUEST's own
  // enlightenment-MSR write -- the guest itself decided to relocate the
  // page, independent of whether A's interrupt has finished.
  lazy.assist_gpa = kNewAssistGpa;
  ASSERT_EQ(ZX_OK, vcpu->WriteLazyEoiState(lazy).status_value(), "move to the NEW address\n");

  uint32_t old_word_after = 0xffffffff;
  ASSERT_EQ(ZX_OK, ram->Read(&old_word_after, kOldAssistGpa, sizeof(old_word_after)),
            "read old word after move\n");
  EXPECT_EQ(0u, old_word_after,
            "the OLD word must be revoked (forced to 0) in actual guest memory before the "
            "mapping is dropped -- a guest whose interrupt-epilogue trampoline caches the "
            "address rather than re-reading the MSR would otherwise still see a live-looking 1 "
            "there and skip an EOI it owes, with nothing left to retire it\n");
  EXPECT_FALSE(vcpu->LazyEoiArmed(), "no grant left outstanding after the move\n");

  printf("lazy-EOI move-while-unconsumed OK: old word at %#lx forced to 0 (was %#x) before the "
         "mapping moved to %#lx\n",
         kOldAssistGpa, old_word_before, kNewAssistGpa);
#else
  printf("Not x86_64; skipping.\n");
#endif  // __x86_64__

  END_TEST;
}

// ---------------------------------------------------------------------------
// ZX_VCPU_STATE_LAZY_EOI: a grant the guest already consumed (word 0, ISR bit
// not yet retired by this kernel) must be reconciled BEFORE a VMM-queued
// ZX_VCPU_STATE_PENDING_EVENT external interrupt's priority is evaluated for
// admission -- not only inside local_apic_maybe_interrupt's own (tracker)
// admission a few lines later in the same Vcpu::Enter iteration.
//
// Why this matters beyond "one entry late": the pending_event_ admission
// block that computes this decision, when it finds the event blocked purely
// by an in-service vector, deliberately arms neither interrupt-window
// exiting nor the TPR threshold -- by design, since an ORDINARY EOI always
// exits and the loop re-examines the queue on its own next time around. A
// lazy grant's consumption does not exit at all, so without reconciling
// first, this specific admission decision can be made against a stale ISR
// bit with nothing left to ever re-evaluate it: a guest that HLTs waiting
// for exactly this event (HLT waits only on interrupt_tracker, which a
// pending_event_-only block never touches) would wait forever. This test
// stops short of actually invoking HLT -- an unbounded wait has no place in
// an automated suite -- and instead observes the SAME-ENTRY admission
// outcome directly: the guest's own next instruction, deliverable or not,
// tells the story without any risk of hanging the test itself.
//
// RED-VERIFIED 2026-08-01: with the early reconcile call removed from
// Vcpu::Enter (leaving only the one inside local_apic_maybe_interrupt, which
// runs too late for this specific decision), this test fails exactly as
// predicted. Reverted after confirming.
// ---------------------------------------------------------------------------
bool vcpu_lazy_eoi_reconcile_precedes_pending_event_admission() {
  BEGIN_TEST;

#ifdef __x86_64__
  auto guest_result = Guest::Create();
  if (guest_result.is_error() && guest_result.status_value() == ZX_ERR_NOT_SUPPORTED) {
    printf("VMX not supported here; skipping lazy-EOI pending_event_ ordering test.\n");
    return true;
  }
  ASSERT_EQ(ZX_OK, guest_result.status_value(), "Guest::Create failed\n");
  ktl::unique_ptr<Guest> guest = ktl::move(guest_result.value());

  constexpr uint64_t kGdtGpa = 0x6000;
  constexpr uint64_t kIdtGpa = 0x6800;
  constexpr uint64_t kFirstHandlerGpa = 0x8000;
  constexpr uint64_t kPendingHandlerGpa = 0x8080;
  constexpr uint64_t kAssistGpa = 0x9000;
  constexpr uint64_t kStackTop = 0xA000;
  // SAME class (5) as kFirstVector: admission of kPendingVector hinges
  // purely on whether kFirstVector's ISR bit has been reconciled away, not
  // on any other priority relationship.
  constexpr uint32_t kFirstVector = 0x50;
  constexpr uint32_t kPendingVector = 0x51;
  constexpr uint8_t kRanPort = 0x30;
  constexpr uint8_t kFirstEpiloguePort = 0x31;
  constexpr uint8_t kHeartbeatPort = 0x32;
  constexpr uint8_t kPendingRanPort = 0x33;

  fbl::RefPtr<VmObjectPaged> ram;
  ASSERT_EQ(ZX_OK, VmObjectPaged::Create(PMM_ALLOC_FLAG_ANY, 0u, kGuestRamSize, &ram), "ram\n");
  ASSERT_EQ(ZX_OK, WriteIdentityTables(ram), "tables\n");

  uint8_t buf[32];
  size_t n = 0;
  auto emit = [&](std::initializer_list<uint8_t> bytes) {
    for (uint8_t b : bytes) {
      buf[n++] = b;
    }
  };
  auto emit32 = [&](uint32_t v) {
    emit({static_cast<uint8_t>(v), static_cast<uint8_t>(v >> 8), static_cast<uint8_t>(v >> 16),
          static_cast<uint8_t>(v >> 24)});
  };
  auto emit64 = [&](uint64_t v) {
    for (int i = 0; i < 8; i++) {
      emit({static_cast<uint8_t>(v >> (8 * i))});
    }
  };
  auto report_byte = [&](uint8_t value, uint8_t port) { emit({0xB0, value, 0xE6, port}); };
  auto clear_assist_word = [&]() {
    emit({0x48, 0xB8});
    emit64(kAssistGpa);
    emit({0xC7, 0x00, 0x00, 0x00, 0x00, 0x00});
  };
  auto jmp_to = [&](uint64_t base, uint64_t target) {
    const int32_t disp = static_cast<int32_t>(target) - static_cast<int32_t>(base + n + 5);
    emit({0xE9});
    emit32(static_cast<uint32_t>(disp));
  };

  n = 0;
  emit({0xFB, 0x90});
  report_byte(0xBB, kHeartbeatPort);
  jmp_to(kCodeGpa, kCodeGpa);
  ASSERT_EQ(ZX_OK, ram->Write(buf, kCodeGpa, n), "code\n");

  const uint8_t gdt_code[8] = {0xFF, 0xFF, 0x00, 0x00, 0x00, 0x9B, 0xAF, 0x00};
  ASSERT_EQ(ZX_OK, ram->Write(gdt_code, kGdtGpa + 8, sizeof(gdt_code)), "GDT code desc\n");

  struct Gate {
    uint32_t vector;
    uint64_t handler;
  };
  const Gate gates[] = {{kFirstVector, kFirstHandlerGpa}, {kPendingVector, kPendingHandlerGpa}};
  for (const Gate& g : gates) {
    uint8_t gate[16];
    WriteIdtGate(gate, g.handler);
    ASSERT_EQ(ZX_OK, ram->Write(gate, kIdtGpa + g.vector * 16, sizeof(gate)), "IDT gate\n");
  }

  // A: report, take the lazy skip (consumed, but this kernel has not yet had
  // an admission attempt since to notice), re-enable interrupts, report an
  // epilogue marker, park.
  n = 0;
  report_byte(static_cast<uint8_t>(kFirstVector), kRanPort);
  clear_assist_word();
  emit({0xFB, 0x90});
  report_byte(0xAA, kFirstEpiloguePort);
  jmp_to(kFirstHandlerGpa, kCodeGpa);
  ASSERT_EQ(ZX_OK, ram->Write(buf, kFirstHandlerGpa, n), "first handler\n");

  // The pending_event_-sourced vector's handler: reaching it at all is the
  // whole assertion.
  n = 0;
  report_byte(static_cast<uint8_t>(kPendingVector), kPendingRanPort);
  jmp_to(kPendingHandlerGpa, kCodeGpa);
  ASSERT_EQ(ZX_OK, ram->Write(buf, kPendingHandlerGpa, n), "pending-vector handler\n");
  ASSERT_EQ(ZX_OK, ram->CommitRange(0, kGuestRamSize), "commit\n");

  auto mapping = guest->RootVmar()->CreateVmMapping(0, kGuestRamSize, 0, VMAR_FLAG_SPECIFIC, ram, 0,
                                                    kMmuFlags, "guest-ram");
  ASSERT_EQ(ZX_OK, mapping.status_value(), "map\n");
  for (uint16_t port : {uint16_t{kRanPort}, uint16_t{kFirstEpiloguePort}, uint16_t{kHeartbeatPort},
                        uint16_t{kPendingRanPort}}) {
    auto t = guest->SetTrap(ZX_GUEST_TRAP_IO, port, 1, nullptr, port);
    ASSERT_EQ(ZX_OK, t.status_value(), "install byte I/O trap\n");
  }

  auto vcpu_result = Vcpu::Create(*guest, kCodeGpa);
  ASSERT_EQ(ZX_OK, vcpu_result.status_value(), "Vcpu::Create\n");
  ktl::unique_ptr<Vcpu> vcpu = ktl::move(vcpu_result.value());
  vcpu->ForceLazyEoiGrantForTest();  // Inert (no VID gate ships); retained for compatibility.

  VcpuArchState s = {};
  ASSERT_EQ(ZX_OK, vcpu->SaveArchState(s).status_value(), "SaveArchState\n");
  s.gdtr_base = kGdtGpa;
  s.gdtr_limit = 0x0F;
  s.idtr_base = kIdtGpa;
  s.idtr_limit = 0xFFF;
  s.regs.rsp = kStackTop;
  ASSERT_EQ(ZX_OK, vcpu->RestoreArchState(s).status_value(), "load GDTR/IDTR/RSP\n");

  zx_vcpu_lazy_eoi_state_t lazy = {};
  lazy.magic = ZX_VCPU_LAZY_EOI_STATE_MAGIC;
  lazy.version = ZX_VCPU_LAZY_EOI_STATE_VERSION;
  lazy.size = sizeof(lazy);
  lazy.enabled = 1;
  lazy.assist_gpa = kAssistGpa;
  ASSERT_EQ(ZX_OK, vcpu->WriteLazyEoiState(lazy).status_value(), "register lazy EOI\n");

  zx_port_packet_t idle = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(idle).status_value(), "enter #1 (idle)\n");
  ASSERT_EQ(static_cast<uint32_t>(kHeartbeatPort), idle.guest_io.port, "starts idle\n");

  ASSERT_EQ(ZX_OK, vcpu->Interrupt(kFirstVector).status_value(), "inject A\n");
  zx_port_packet_t ran = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(ran).status_value(), "enter #2\n");
  ASSERT_EQ(static_cast<uint32_t>(kRanPort), ran.guest_io.port, "A's handler ran\n");

  zx_port_packet_t epilogue = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(epilogue).status_value(), "enter #3\n");
  ASSERT_EQ(static_cast<uint32_t>(kFirstEpiloguePort), epilogue.guest_io.port,
            "A's own memory write must not exit\n");
  // Precondition: consumed in guest memory, but not yet reconciled by this
  // kernel -- nothing has called local_apic_maybe_interrupt since the guest
  // cleared the word.
  ASSERT_TRUE(vcpu->InService(kFirstVector), "still (stale) in service\n");
  ASSERT_TRUE(vcpu->LazyEoiArmed(), "not yet reconciled\n");

  // Queue a VMM-staged external interrupt of the SAME priority class,
  // through the pending_event_ ABI -- not the tracker `Interrupt()` used
  // above -- so this exercises the OTHER admission path.
  zx_vcpu_pending_event_t event =
      MakePendingEvent(ZX_VCPU_EVENT_EXTERNAL_INTERRUPT, kPendingVector);
  ASSERT_EQ(ZX_OK, vcpu->WritePendingEvent(event).status_value(), "queue pending event\n");

  zx_port_packet_t outcome = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(outcome).status_value(), "enter #4\n");
  EXPECT_EQ(static_cast<uint32_t>(kPendingRanPort), outcome.guest_io.port,
            "the pending_event_ vector must be admitted on THIS entry -- landing on the "
            "heartbeat port instead means it was blocked by A's stale, not-yet-reconciled ISR "
            "bit, and nothing in that code path would ever re-examine it\n");
  EXPECT_FALSE(vcpu->InService(kFirstVector), "reconciled: A's ISR bit is gone\n");
  EXPECT_EQ(1u, vcpu->LazyEoiCompletions(), "A's grant was reconciled exactly once\n");

  printf("lazy-EOI pending_event_ ordering OK: A's stale grant was reconciled before the "
         "pending_event_ admission decision, so vector %#x (same class as %#x) was admitted on "
         "the very entry it was queued\n",
         kPendingVector, kFirstVector);
#else
  printf("Not x86_64; skipping.\n");
#endif  // __x86_64__

  END_TEST;
}

// ---------------------------------------------------------------------------
// ZX_VCPU_STATE_LAZY_EOI, HLT BLOCK-PATH DEADLOCK (the bare-metal wedge).
//
// A guest takes a high interrupt A, lazy-EOIs it (a silent guest-memory write,
// assist word -> 0, no exit), and then HLTs awaiting a LOWER interrupt B. A's
// in-service bit has not been reconciled, so it still elevates the processor
// priority and blocks B; B is pending in the tracker with no signal left of its
// own. With the plain wait (the lazy-DISABLED baseline's block path) handle_hlt
// parks forever -- the deadlock. The fix reconciles A's consumed grant on the
// block path, which drops the priority and makes B deliverable, then re-enters
// so it is injected: NOT by force-injecting a fixed vector, but by observing
// that reconciling made a pending vector newly deliverable (class > the lowered
// processor priority, guest interruptible). This is the exact test that would
// have caught the wedge on bare metal, where nested KVM's virtual-APIC hides it.
//
// The build under test flips it: on the plain-wait baseline the fatal entry
// never returns and the watchdog Kick()s it loose after 3 s (RED, on
// watchdog_fired); with the reconcile-and-deliver-if-newly-deliverable fix the
// entry returns through B's handler in microseconds (GREEN). Lazy-EOI is active
// throughout -- the fix works by TAKING the lazy EOI, confirmed by
// LazyEoiCompletions() advancing.
//
// Ports: 0x10 announce, 0x20 A ran, 0x30 B ran (the resume/green signal).
// Vectors: A = 0xE0 (class 0xE), B = 0x50 (class 0x5); B's class <= A's, so B
// is held by A's in-service bit and by nothing else once interrupts are on.
// ---------------------------------------------------------------------------

struct LazyEoiHltShared {
  Vcpu* vcpu = nullptr;
  // Main sets this immediately before the fatal Enter, so the watchdog only
  // starts its 3 s clock once the entry that must not hang is in flight.
  ktl::atomic<bool> arm{false};
  // Main sets this once the fatal Enter has returned (on the fixed kernel), so
  // a correct run never trips the watchdog.
  ktl::atomic<bool> done{false};
  // The red arm: set true iff the fatal entry had to be Kick()ed loose.
  ktl::atomic<bool> watchdog_fired{false};
};

int LazyEoiHltWatchdogBody(void* arg) {
  auto* sh = static_cast<LazyEoiHltShared*>(arg);
  zx_instant_mono_t deadline = current_mono_time() + ZX_SEC(10);
  while (!sh->arm.load(ktl::memory_order_acquire)) {
    if (current_mono_time() > deadline) {
      // Setup never reached the fatal entry; let the main thread's own
      // assertions report the failure.
      return -1;
    }
    Thread::Current::SleepRelative(ZX_USEC(100));
  }
  deadline = current_mono_time() + ZX_SEC(3);
  while (!sh->done.load(ktl::memory_order_acquire)) {
    if (current_mono_time() > deadline) {
      sh->watchdog_fired.store(true, ktl::memory_order_release);
      sh->vcpu->Kick();
      return 0;
    }
    Thread::Current::SleepRelative(ZX_USEC(100));
  }
  return 0;
}

bool vcpu_lazy_eoi_then_hlt_delivers_the_awaited_lower_vector() {
  BEGIN_TEST;

#ifdef __x86_64__
  auto guest_result = Guest::Create();
  if (guest_result.is_error() && guest_result.status_value() == ZX_ERR_NOT_SUPPORTED) {
    printf("VMX not supported here; skipping lazy-EOI HLT wedge test.\n");
    return true;
  }
  ASSERT_EQ(ZX_OK, guest_result.status_value(), "Guest::Create failed\n");
  ktl::unique_ptr<Guest> guest = ktl::move(guest_result.value());

  constexpr uint64_t kGdtGpa = 0x6000;
  constexpr uint64_t kIdtGpa = 0x6800;
  constexpr uint64_t kHandlerAGpa = 0x8000;
  constexpr uint64_t kHandlerBGpa = 0x8800;
  constexpr uint64_t kAssistGpa = 0x9000;
  constexpr uint64_t kStackTop = 0xA000;
  constexpr uint32_t kVectorA = 0xE0;  // high class 0xE
  constexpr uint32_t kVectorB = 0x50;  // low class 0x5, <= A's class
  constexpr uint8_t kAnnouncePort = 0x10;
  constexpr uint8_t kRanAPort = 0x20;
  constexpr uint8_t kRanBPort = 0x30;

  fbl::RefPtr<VmObjectPaged> ram;
  ASSERT_EQ(ZX_OK, VmObjectPaged::Create(PMM_ALLOC_FLAG_ANY, 0u, kGuestRamSize, &ram), "ram\n");
  ASSERT_EQ(ZX_OK, WriteIdentityTables(ram), "tables\n");

  // Main: enable interrupts, announce, then park awaiting A. A is delivered on
  // the entry that follows the announce exit, so the guest vectors straight
  // into A's handler and never actually retires this HLT.
  //   FB 90  B0 A1 E6 10  F4  EB FE
  //   sti;nop; mov al,0xA1; out 0x10,al; hlt; jmp $
  const uint8_t code[] = {0xFB, 0x90, 0xB0, 0xA1, 0xE6, 0x10, 0xF4, 0xEB, 0xFE};
  ASSERT_EQ(ZX_OK, ram->Write(code, kCodeGpa, sizeof(code)), "code\n");

  const uint8_t gdt_code[8] = {0xFF, 0xFF, 0x00, 0x00, 0x00, 0x9B, 0xAF, 0x00};
  ASSERT_EQ(ZX_OK, ram->Write(gdt_code, kGdtGpa + 8, sizeof(gdt_code)), "GDT code desc\n");

  uint8_t gate_a[16];
  WriteIdtGate(gate_a, kHandlerAGpa);
  ASSERT_EQ(ZX_OK, ram->Write(gate_a, kIdtGpa + kVectorA * 16, sizeof(gate_a)), "IDT gate A\n");
  uint8_t gate_b[16];
  WriteIdtGate(gate_b, kHandlerBGpa);
  ASSERT_EQ(ZX_OK, ram->Write(gate_b, kIdtGpa + kVectorB * 16, sizeof(gate_b)), "IDT gate B\n");

  // A's handler: enable interrupts, report, HALT with the grant still
  // outstanding (HLT #2 -- consumes B's stored signal without retiring
  // anything), then on resume take the LAZY EOI (bare `mov [assist],0`, no
  // exit) and HALT again (HLT #3, the fatal one). Never issues a real EOI, so
  // A's in-service bit persists until something reconciles the consumed grant.
  //   FB 90  B0 AA E6 20  F4  48 B8 <kAssistGpa:8>  C7 00 00 00 00 00  F4  EB FE
  const uint8_t handler_a[] = {0xFB, 0x90, 0xB0, 0xAA, 0xE6, 0x20, 0xF4,
                               0x48, 0xB8, 0x00, 0x90, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                               0xC7, 0x00, 0x00, 0x00, 0x00, 0x00,
                               0xF4, 0xEB, 0xFE};
  ASSERT_EQ(ZX_OK, ram->Write(handler_a, kHandlerAGpa, sizeof(handler_a)), "handler A\n");

  // B's handler: report B was delivered (the guest RESUMED), then halt.
  //   B0 BB E6 30 F4 EB FE
  const uint8_t handler_b[] = {0xB0, 0xBB, 0xE6, 0x30, 0xF4, 0xEB, 0xFE};
  ASSERT_EQ(ZX_OK, ram->Write(handler_b, kHandlerBGpa, sizeof(handler_b)), "handler B\n");
  ASSERT_EQ(ZX_OK, ram->CommitRange(0, kGuestRamSize), "commit\n");

  auto mapping = guest->RootVmar()->CreateVmMapping(0, kGuestRamSize, 0, VMAR_FLAG_SPECIFIC, ram, 0,
                                                    kMmuFlags, "guest-ram");
  ASSERT_EQ(ZX_OK, mapping.status_value(), "map\n");
  for (uint16_t port : {uint16_t{kAnnouncePort}, uint16_t{kRanAPort}, uint16_t{kRanBPort}}) {
    auto t = guest->SetTrap(ZX_GUEST_TRAP_IO, port, 1, nullptr, port);
    ASSERT_EQ(ZX_OK, t.status_value(), "install byte I/O trap\n");
  }

  auto vcpu_result = Vcpu::Create(*guest, kCodeGpa);
  ASSERT_EQ(ZX_OK, vcpu_result.status_value(), "Vcpu::Create\n");
  ktl::unique_ptr<Vcpu> vcpu = ktl::move(vcpu_result.value());

  VcpuArchState s = {};
  ASSERT_EQ(ZX_OK, vcpu->SaveArchState(s).status_value(), "SaveArchState\n");
  s.gdtr_base = kGdtGpa;
  s.gdtr_limit = 0x0F;
  s.idtr_base = kIdtGpa;
  s.idtr_limit = 0xFFF;
  s.regs.rsp = kStackTop;
  ASSERT_EQ(ZX_OK, vcpu->RestoreArchState(s).status_value(), "load GDTR/IDTR/RSP\n");

  // Lazy-EOI is ACTIVE (no gate); the grant is established by this write.
  zx_vcpu_lazy_eoi_state_t lazy = {};
  lazy.magic = ZX_VCPU_LAZY_EOI_STATE_MAGIC;
  lazy.version = ZX_VCPU_LAZY_EOI_STATE_VERSION;
  lazy.size = sizeof(lazy);
  lazy.enabled = 1;
  lazy.assist_gpa = kAssistGpa;
  ASSERT_EQ(ZX_OK, vcpu->WriteLazyEoiState(lazy).status_value(), "register lazy EOI\n");

  zx_port_packet_t announce = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(announce).status_value(), "enter #1 (announce)\n");
  ASSERT_EQ(static_cast<uint32_t>(kAnnouncePort), announce.guest_io.port, "starts by announcing\n");

  ASSERT_EQ(ZX_OK, vcpu->Interrupt(kVectorA).status_value(), "inject A\n");
  zx_port_packet_t ran_a = {};
  ASSERT_EQ(ZX_OK, vcpu->Enter(ran_a).status_value(), "enter #2 (A's handler)\n");
  ASSERT_EQ(static_cast<uint32_t>(kRanAPort), ran_a.guest_io.port, "A's handler must run\n");

  // Wedged precondition: A is in service with an outstanding lazy grant, nothing
  // reconciled yet.
  ASSERT_TRUE(vcpu->InService(kVectorA), "A is in service\n");
  ASSERT_TRUE(vcpu->LazyEoiArmed(), "A's lazy grant is outstanding\n");
  ASSERT_EQ(kVectorA, vcpu->LazyEoiVector(), "the grant names A\n");
  ASSERT_FALSE(vcpu->InService(kVectorB), "B is not in service\n");
  ASSERT_EQ(0u, vcpu->LazyEoiCompletions(), "nothing reconciled yet\n");

  // Deposit B while A is in service. Its one-deep signal is consumed by HLT #2
  // before the fatal HLT #3, leaving B pending in the bitmap, held by A's stale
  // in-service bit, with no signal left -- the lost-signal deadlock.
  ASSERT_EQ(ZX_OK, vcpu->Interrupt(kVectorB).status_value(), "inject B (lower priority)\n");

  LazyEoiHltShared shared;
  shared.vcpu = vcpu.get();
  Thread* watchdog =
      Thread::Create("hv-lazy-eoi-hlt-watchdog", LazyEoiHltWatchdogBody, &shared, DEFAULT_PRIORITY);
  ASSERT_TRUE(watchdog != nullptr, "create watchdog thread\n");
  watchdog->Resume();

  // The fatal entry: HLT #2 (consumes B's signal), lazy EOI, HLT #3. On the
  // plain-wait baseline this parks forever; with the fix, reconciling A on the
  // block path makes B newly deliverable and this returns through B's handler.
  shared.arm.store(true, ktl::memory_order_release);
  zx_port_packet_t resumed = {};
  auto fatal = vcpu->Enter(resumed);
  shared.done.store(true, ktl::memory_order_release);

  int watchdog_ret = -1;
  ASSERT_EQ(ZX_OK, watchdog->Join(&watchdog_ret, ZX_TIME_INFINITE), "join watchdog\n");

  ASSERT_FALSE(
      shared.watchdog_fired.load(ktl::memory_order_acquire),
      "THE WEDGE: after a lazy EOI the halted guest never woke -- the lower interrupt B was "
      "pending but held by A's un-reconciled in-service bit, and handle_hlt blocked without "
      "reconciling it. The fix reconciles on the block path and delivers B; the plain wait "
      "deadlocks here\n");
  ASSERT_EQ(ZX_OK, fatal.status_value(), "the fatal entry returned an error rather than resuming\n");
  ASSERT_EQ(static_cast<uint32_t>(kRanBPort), resumed.guest_io.port,
            "the guest must resume into B's handler -- B was injected once A's stale grant was "
            "reconciled on the block path\n");
  ASSERT_EQ(0xBBu, static_cast<uint32_t>(resumed.guest_io.data[0]), "B's handler marker\n");

  EXPECT_FALSE(vcpu->InService(kVectorA), "A's stale in-service bit was reconciled away\n");
  EXPECT_TRUE(vcpu->InService(kVectorB), "B is now the in-service interrupt\n");
  EXPECT_GE(vcpu->LazyEoiCompletions(), 1u,
            "the lazy EOI was actually taken and reconciled -- lazy-EOI stayed active, the wedge "
            "was not papered over by forcing real EOIs\n");

  printf("lazy-EOI HLT wedge OK: a lazy EOI followed by HLT delivered the awaited lower vector -- "
         "A's consumed grant was reconciled on the block path (%lu completion(s)), B became "
         "deliverable and was injected, and the guest resumed into its handler\n",
         vcpu->LazyEoiCompletions());
#else
  printf("Not x86_64; skipping.\n");
#endif  // __x86_64__

  END_TEST;
}

}  // namespace

UNITTEST_START_TESTCASE(hypervisor_enter)
UNITTEST("vcpu enters a 64-bit guest and traps an I/O write", vcpu_enter_traps_io_write)
UNITTEST("guest dirties RAM, host reverts, guest re-reads baseline",
         vcpu_guest_ram_snapshot_restore)
UNITTEST("sibling CoW clones are isolated across two guests (fork)",
         vcpu_fork_sibling_isolation)
UNITTEST("revert returns to a checkpoint re-baseline, not the original",
         vcpu_checkpoint_rebaseline)
UNITTEST("guest CoW-write forks a pager-backed-rooted clone through EPT",
         vcpu_pager_backed_clone_forks)
UNITTEST("incremental (SNAPSHOT_MODIFIED) checkpoint through a guest",
         vcpu_incremental_checkpoint_rebaseline)
UNITTEST("vcpu arch-state save/restore is execution-deterministic (RIP+GPRs)",
         vcpu_state_snapshot_determinism)
UNITTEST("vcpu control-register capture + segment-base injection",
         vcpu_state_control_and_segment_base)
UNITTEST("complete vcpu state serializes and restores losslessly",
         vcpu_full_state_serialization_roundtrip)
UNITTEST("an interrupted delivery is deferred, not forced, when the VMM restores IF=0",
         vcpu_interrupted_delivery_deferred_when_if_clear)
UNITTEST("an interrupted NMI is deferred, not forced, when the VMM restores MOV-SS blocking",
         vcpu_interrupted_nmi_deferred_when_blocked)
UNITTEST("a ring-3 XSETBV faults in the guest before any VM exit (ring 0 still exits)",
         vcpu_xsetbv_cpl3_faults_before_the_exit)
UNITTEST("a ring-3 hypercall #UDs under Hyper-V and returns -KVM_EPERM under KVM",
         vcpu_hypercall_at_cpl3_faults_per_identity)
UNITTEST("guest RFLAGS.IF survives save/restore in both polarities",
         vcpu_state_interrupt_flag_roundtrip)
UNITTEST("VMM-planted INT3 breakpoint traps to host and resumes",
         vcpu_breakpoint_int3_coverage)
UNITTEST("re-injected #BP vectors through the guest's own IDT handler",
         vcpu_breakpoint_inject_to_guest)
UNITTEST("debug-state topic advertises support and one-shot single-step",
         vcpu_debug_state_topic_single_step_is_one_shot)
UNITTEST("hardware breakpoint is transparent across execute, data, and guest-owned DR0",
         vcpu_hardware_breakpoint_execute_data_and_guest_coexistence)
UNITTEST("run-control topic advertises a one-shot VMX preemption timer",
         vcpu_run_control_preemption_timer_is_one_shot)
UNITTEST("run-control timer count survives unrelated VM exits",
         vcpu_run_control_preemption_timer_survives_unrelated_exit)
UNITTEST("VM-exit observation is post-handler, one-shot, and explicitly acknowledged",
         vcpu_exit_observation_is_post_handler_one_shot_and_acknowledged)
UNITTEST("VM-exit budget stops after the exact completed exit",
         vcpu_exit_budget_stops_after_exact_completed_exit)
UNITTEST("unarmed VM-exit control adds no return and touches no session counter",
         vcpu_unarmed_exit_control_adds_no_return_or_counter)
UNITTEST("Intel PT capability read is CPUID-only and reserves no session",
         vcpu_intel_pt_capability_read_is_cpuid_only_and_unreserved)
UNITTEST("Intel PT Configure qualifies static host prerequisites",
         vcpu_intel_pt_configure_qualifies_static_host_prerequisites)
UNITTEST("Intel PT ToPA watermark is complete and drainable",
         vcpu_intel_pt_topa_watermark_is_complete_and_drainable)
UNITTEST("Intel PT composes with an in-flight cross-thread Kick and clean release",
         vcpu_intel_pt_cross_thread_kick_preserves_route_and_cleanup)
UNITTEST("VMX allowed-one accepts both flexible and forced-one controls",
         vmx_allowed_one_accepts_flexible_and_forced_controls)
UNITTEST("instruction-control discovery, validation, contention, and unarmed path",
         vcpu_instruction_control_capability_validation_and_unarmed_path)
UNITTEST("instruction budget reports exact observed count and requires acknowledgement",
         vcpu_instruction_budget_reports_exact_observed_count_and_requires_ack)
UNITTEST("instruction-control cleanup releases on restore, halt, and destruction",
         vcpu_instruction_control_cleanup_on_restore_halt_and_destruction)
UNITTEST("memory-access control validates overlap, cross-page, and typed masks atomically",
         vcpu_memory_access_control_validation_overlap_and_cross_page)
UNITTEST("memory write stop is pre-access and ack retries the instruction exactly once",
         vcpu_memory_access_write_is_pre_access_and_ack_retries_once)
UNITTEST("kick cancels an in-flight run without advancing the guest",
         vcpu_kick_cancels_run)
UNITTEST("public zx_vcpu_state read/write round-trips and drives the guest",
         vcpu_public_state_readwrite_roundtrip)
UNITTEST("overlay re-backs a GPA range and the guest sees the new page",
         vcpu_overlay_rebacks_gpa)
UNITTEST("local-APIC LVT + pending-interrupt set serialize and restore",
         vcpu_lapic_pending_state_roundtrip)
UNITTEST("WriteVectoringEvent rejects every non-capturable shape and does not partially mutate",
         vcpu_vectoring_event_write_validation)
UNITTEST("async-state codec round-trips v7 ISR and decodes released v6 blobs",
         vcpu_async_state_codec_versions)
UNITTEST("guest TSC offset installed verbatim, deadline re-arms/disarms, bad writes rejected",
         vcpu_tsc_state_roundtrip)
UNITTEST("partition TSC restore installs one offset on every VP with no sequential-restore skew",
         vcpu_tsc_partition_no_skew)
UNITTEST("maskable interrupt injected via Interrupt() reaches the guest IDT",
         vcpu_maskable_interrupt_reaches_handler)
UNITTEST("Vcpu::Interrupt wakes a HLT-parked VCPU promptly, and idleness is tickless",
         vcpu_interrupt_wakes_halted_vcpu)
UNITTEST("a tracker vector without its signal is invisible to a later wait (defect pin)",
         interrupt_tracker_signal_vs_track_wake)
UNITTEST("BSP STARTUP IPI surfaces an AP startup packet and the AP vcpu runs",
         vcpu_ap_startup_sipi)
UNITTEST("an AP boots itself from real mode into long mode and stays runnable",
         vcpu_ap_boots_itself_into_long_mode)
UNITTEST("a long-mode snapshot restores into a freshly-created AP",
         vcpu_long_mode_snapshot_restores_into_fresh_ap)
UNITTEST("a blocked NMI is released by the NMI window, not by an unrelated exit",
         vcpu_blocked_nmi_is_released_by_the_nmi_window)
UNITTEST("x2APIC LDR reads back the value derived from the VP's own APIC ID",
         vcpu_x2apic_ldr_derived_from_apic_id)
UNITTEST("logical-destination IPIs route to exactly the named VPs",
         vcpu_logical_ipi_target_mask)
UNITTEST("MMIO read exits and the VMM completes it (mov al,[mem] form)",
         vcpu_mmio_read_completion)
UNITTEST("Hyper-V CPUID identity presents 'Microsoft Hv' to the guest",
         vcpu_hyperv_cpuid_identity)
UNITTEST("Hyper-V feature/limit CPUID leaves come from the VMM",
         vcpu_hyperv_cpuid_supplied_leaves)
UNITTEST("an unimplemented Hyper-V CPUID leaf reads as zero",
         vcpu_hyperv_cpuid_unimplemented_leaf_is_zero)
UNITTEST("supplied Hyper-V CPUID leaves are inert without the identity",
         vcpu_hyperv_cpuid_leaves_inert_without_identity)
UNITTEST("delegated synthetic-MSR read exits to the VMM and completes",
         vcpu_synthetic_msr_read_delegates)
UNITTEST("delegated synthetic-MSR write surfaces the register and value",
         vcpu_synthetic_msr_write_delegates)
UNITTEST("delegated hypercall surfaces operands and returns a result",
         vcpu_hypercall_delegates)
UNITTEST("enlightenment topic arms identity + CPUID + delegated MSR/hypercall exits",
         vcpu_enlightenment_topic_arms_delegated_exits)
UNITTEST("enlightenment topic round-trips and an empty write restores the default",
         vcpu_enlightenment_topic_round_trips)
UNITTEST("enlightenment topic rejects malformed input and out-of-range CPUID leaves",
         vcpu_enlightenment_topic_rejects_invalid)
UNITTEST("without delegation a synthetic-MSR read still faults the guest",
         vcpu_synthetic_msr_faults_without_delegation)
UNITTEST("async-state APIC timer is captured and reconstructed (re-fires)",
         vcpu_async_state_apic_timer_reconstruct)
UNITTEST("async-state pending interrupts + pv-clock round-trip and restore authoritatively",
         vcpu_async_state_pending_and_pvclock_roundtrip)
UNITTEST("a restored APIC timer fires and vectors through the guest's own IDT",
         vcpu_async_state_restored_timer_reaches_guest_idt)
UNITTEST("a guest that shuts itself down surfaces a halt instead of spinning",
         vcpu_triple_fault_surfaces_halt)
UNITTEST("injected #GP carries the VMM's error code into the guest's own handler",
         vcpu_pending_event_gp_error_code_reaches_handler)
UNITTEST("injected #PF delivers both the error code and CR2 to the guest",
         vcpu_pending_event_page_fault_delivers_cr2)
UNITTEST("pending-event topic round-trips and ZX_VCPU_EVENT_NONE un-queues",
         vcpu_pending_event_topic_round_trips)
UNITTEST("an event interrupted mid-delivery by a pristine-stack fault is re-injected",
         vcpu_event_faulting_mid_delivery_is_reinjected)
UNITTEST("with the stack already written the same vector needs no re-injection",
         vcpu_event_with_written_stack_needs_no_reinjection)
UNITTEST("a faulting delivery preserves its error code and CR2",
         vcpu_faulting_delivery_preserves_error_code_and_cr2)
UNITTEST("a re-injected event and an already-queued one each arrive exactly once",
         vcpu_reinjected_event_and_queued_event_each_arrive_once)
UNITTEST("the injection ABI refuses exactly what the entry sequence cannot deliver",
         vcpu_injection_abi_matches_what_can_be_delivered)
UNITTEST("an NMI is delivered before an ordinary vector queued alongside it",
         vcpu_nmi_takes_priority_over_a_queued_interrupt)
UNITTEST("pending-event topic refuses malformed injections and stays unchanged",
         vcpu_pending_event_rejects_invalid)
UNITTEST("CSTAR guest read/write and full-state restore are coherent",
         vcpu_cstar_read_write_and_restore_roundtrip)
UNITTEST("a hostile XCR0 in ZX_VCPU_STATE_FULL is refused instead of faulting the host",
         vcpu_restore_rejects_hostile_xcr0)
UNITTEST("a hostile XSAVE image in ZX_VCPU_STATE_FULL is refused instead of faulting the host",
         vcpu_restore_rejects_hostile_xsave)
UNITTEST("a blocked VCPU leaves the host's XCR0 on the CPU, not the guest's",
         vcpu_blocking_exit_does_not_leak_guest_xstate)
UNITTEST("a guest's CR8 is its own VCPU's, not host-physical page 0", vcpu_cr8_is_per_vcpu_state)
UNITTEST("the guest's CR8 holds back a lower-priority interrupt until it is lowered",
         vcpu_cr8_gates_interrupt_delivery)
UNITTEST("an in-service interrupt holds back one of its own class until the guest's EOI",
         vcpu_apic_in_service_blocks_until_eoi)
// Registered in this order deliberately. `run_unittest` breaks out of the
// testcase at the first failing case (lib/unittest/console.cc), so the three
// bounded cases come first and the end-to-end one -- which HANGS rather than
// failing if the starvation bug is present -- comes last, where a regression in
// any of the others aborts before it is reached. The two starvation cases cover
// the two independent refusal paths in `local_apic_maybe_interrupt`: priority
// and interruptibility. Neither implies the other; a fix to one alone leaves the
// other red.
UNITTEST("a queued exception is not starved by a priority-blocked interrupt",
         vcpu_queued_exception_is_not_starved_by_a_blocked_interrupt)
UNITTEST("a queued exception is not starved by an un-injectable interrupt",
         vcpu_queued_exception_is_not_starved_by_an_uninjectable_interrupt)
UNITTEST("a deliverable interrupt still precedes a queued exception",
         vcpu_deliverable_interrupt_precedes_a_queued_exception)
UNITTEST("a guest's own faulting instruction makes progress under a blocked interrupt",
         vcpu_faulting_instruction_is_not_starved_by_a_blocked_interrupt)
UNITTEST("x2APIC PPR/APR/ICR/LVT/counter registers read back what the guest wrote",
         vcpu_x2apic_register_set_is_readable)
UNITTEST("xAPIC reset MMIO state transitions architecturally to x2APIC",
         vcpu_xapic_reset_mmio_and_x2apic_transition)
UNITTEST("the guest's CR8 holds back a VMM-queued pending event too",
         vcpu_cr8_gates_pending_event_delivery)
UNITTEST("a restored VCPU comes back with its own task priority (CR8/VTPR), read by the guest",
         vcpu_vtpr_survives_snapshot_restore)
UNITTEST("an unhandled RDMSR/WRMSR names the register, the guest RIP and the fault",
         vcpu_unhandled_msr_announces_itself)
UNITTEST("the MSRs a Windows boot touches are all answered, with zero announcements",
         vcpu_msr_coverage_leaves_nothing_unhandled)
UNITTEST("iretq from an injected exception frame resumes the guest",
         vcpu_iretq_from_an_injected_frame_resumes_the_guest)
UNITTEST("an unregistered I/O port is defaulted and announced, not fatal",
         vcpu_unregistered_io_port_defaults_instead_of_killing_the_guest)
UNITTEST("an unserviceable EPT exit reports the guest-physical address",
         vcpu_unserviceable_ept_exit_reports_the_guest_physical_address)
UNITTEST("the guest's debug registers are its own, not the host's",
         vcpu_guest_debug_registers_are_not_the_hosts)
UNITTEST("a host NMI during guest execution reaches the host and spares the guest",
         vcpu_host_nmi_during_guest_is_redispatched_not_lost)
UNITTEST("the guest is not told about MPX, which this kernel cannot back",
         vcpu_guest_is_not_told_about_mpx)
UNITTEST("guest CPUID leaf 0xD's bitmap, sizes and subleaves agree with each other",
         vcpu_cpuid_leaf_d_is_self_consistent)
UNITTEST("every leaf-1/leaf-7 feature the guest is told about is one it can enable",
         vcpu_leaf1_leaf7_claims_match_what_is_backed)
UNITTEST("guest CPUID leaf 0 advertises no basic leaf the hypervisor does not answer",
         vcpu_cpuid_leaf_zero_matches_what_is_answered)
UNITTEST("a guest XSETBV takes effect, narrowing and widening, read back with XGETBV",
         vcpu_guest_xsetbv_takes_effect)
UNITTEST("the guest's RDTSC and RDMSR 0x10 both honour the VMCS TSC offset",
         vcpu_guest_tsc_honours_the_vmcs_offset)
UNITTEST("the XCR0 and XSAVE-image validators obey their rules on synthetic machines",
         vcpu_restore_validator_rules)
UNITTEST("CPUID.1:ECX.OSXSAVE follows the guest's CR4, and XGETBV then faults",
         vcpu_cpuid_osxsave_follows_guest_cr4)
UNITTEST("a guest EOI reaches the VMM for a registered vector, and only for one",
         vcpu_registered_eoi_exits_to_the_vmm)
UNITTEST("ZX_VCPU_STATE_LAZY_EOI registration validates and replaces wholesale",
         vcpu_lazy_eoi_state_topic_validates_registration)
UNITTEST("an armed lazy-EOI grant costs no exit and is reconciled specifically",
         vcpu_lazy_eoi_armed_interrupt_produces_no_exit)
UNITTEST("a vector registered for EOI notification is never granted the lazy path",
         vcpu_lazy_eoi_registered_eoi_vector_is_never_granted)
UNITTEST("a nested lazy-EOI admission revokes the outstanding grant (sole-in-service rule)",
         vcpu_lazy_eoi_nested_admission_revokes_grant)
UNITTEST("with lazy EOI never registered, an EOI still costs the ordinary exit",
         vcpu_lazy_eoi_negative_unarmed_still_exits)
UNITTEST("a LAPIC diagnostics read against a VCPU with no assist page is safe (empty GuestPtr)",
         vcpu_lapic_read_without_assist_page_is_safe)
UNITTEST("an off-thread LAPIC read refuses the assist word instead of racing the mapping",
         vcpu_lapic_read_off_thread_refuses_the_assist_word)
UNITTEST("a lazy-EOI topic write -- including a restore -- forces no grant outstanding",
         vcpu_lazy_eoi_restore_forces_real_eoi)
UNITTEST("ZX_VCPU_STATE_TLB_FLUSH registration validates and a request is idempotent",
         vcpu_tlb_flush_state_topic_validates_and_is_idempotent)
UNITTEST("a requested TLB flush is consumed at the next entry and drops a stale translation",
         vcpu_tlb_flush_request_flushes_stale_translation)
UNITTEST("concurrent TLB-flush requests racing this VCPU's own consumption are not erased",
         vcpu_tlb_flush_concurrent_requests_are_not_erased)
UNITTEST("a nested high-class vector cannot strand the low-class vector beneath it",
         vcpu_lazy_eoi_strand_regression_lower_vector_delivers)
UNITTEST("moving the assist page while a grant is unconsumed revokes the old word",
         vcpu_lazy_eoi_move_while_unconsumed_revokes_old_word)
UNITTEST("lazy-EOI reconciliation precedes pending_event_ admission, not just the tracker's",
         vcpu_lazy_eoi_reconcile_precedes_pending_event_admission)
UNITTEST("a lazy EOI then HLT delivers the awaited lower vector (block-path reconcile, no wedge)",
         vcpu_lazy_eoi_then_hlt_delivers_the_awaited_lower_vector)
UNITTEST_END_TESTCASE(hypervisor_enter, "hypervisor-enter",
                      "positive guest-entry (VMLAUNCH) + snapshot/fork/checkpoint through a guest")

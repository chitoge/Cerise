// Copyright 2017 The Fuchsia Authors
//
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT

#include <align.h>
#include <zircon/syscalls/hypervisor.h>

#include <arch/x86/apic.h>
#include <arch/x86/feature.h>
#include <arch/x86/hypervisor/invalidate.h>

#include "vmx_cpu_state_priv.h"

namespace {

void IgnoreMsr(const VmxPage& msr_bitmaps_page, uint32_t msr) {
  // From Volume 3, Section 24.6.9.
  uint8_t* msr_bitmaps = msr_bitmaps_page.VirtualAddress<uint8_t>();
  if (msr >= 0xc0000000) {
    msr_bitmaps += 1 << 10;
  }

  uint16_t msr_low = msr & 0x1fff;
  uint16_t msr_byte = msr_low / 8;
  uint8_t msr_bit = msr_low % 8;

  // Ignore reads to the MSR.
  msr_bitmaps[msr_byte] &= static_cast<uint8_t>(~(1u << msr_bit));

  // Ignore writes to the MSR.
  msr_bitmaps += 2 << 10;
  msr_bitmaps[msr_byte] &= static_cast<uint8_t>(~(1u << msr_bit));
}

}  // namespace

// static
zx::result<ktl::unique_ptr<Guest>> Guest::Create() {
  // Check that the CPU supports VMX.
  if (!x86_feature_test(X86_FEATURE_VMX)) {
    return zx::error(ZX_ERR_NOT_SUPPORTED);
  }

  auto gpa = hypervisor::GuestPhysicalAspace::Create();
  if (gpa.is_error()) {
    return gpa.take_error();
  }

  // Invalidate the EPT across all CPUs.
  uint64_t eptp = ept_pointer_from_pml4(gpa->arch_aspace().arch_table_phys());
  broadcast_invept(eptp);

  if (auto result = alloc_vmx_state(); result.is_error()) {
    return result.take_error();
  }

  fbl::AllocChecker ac;
  ktl::unique_ptr<Guest> guest(new (&ac) Guest(std::move(*gpa)));
  if (!ac.check()) {
    free_vmx_state();
    return zx::error(ZX_ERR_NO_MEMORY);
  }

  // Setup common MSR bitmaps.
  VmxInfo vmx_info;
  if (auto result = guest->msr_bitmaps_page_.Alloc(vmx_info, UINT8_MAX); result.is_error()) {
    return result.take_error();
  }

  // The APIC-access page is shared by all xAPIC VCPUs, while the virtual-APIC
  // page containing register state remains per-VCPU. It is mapped only when
  // the first xAPIC VCPU is created: an x2APIC-only guest must leave this GPA
  // available to an ordinary MMIO trap.
  if (auto result = guest->apic_access_page_.Alloc(0); result.is_error()) {
    return result.take_error();
  }

  // These are saved/restored by VMCS controls.
  IgnoreMsr(guest->msr_bitmaps_page_, X86_MSR_IA32_SYSENTER_CS);
  IgnoreMsr(guest->msr_bitmaps_page_, X86_MSR_IA32_SYSENTER_ESP);
  IgnoreMsr(guest->msr_bitmaps_page_, X86_MSR_IA32_SYSENTER_EIP);
  IgnoreMsr(guest->msr_bitmaps_page_, X86_MSR_IA32_PAT);
  IgnoreMsr(guest->msr_bitmaps_page_, X86_MSR_IA32_EFER);
  IgnoreMsr(guest->msr_bitmaps_page_, X86_MSR_IA32_FS_BASE);
  IgnoreMsr(guest->msr_bitmaps_page_, X86_MSR_IA32_GS_BASE);

  // These are saved/restored manually.
  IgnoreMsr(guest->msr_bitmaps_page_, X86_MSR_IA32_STAR);
  IgnoreMsr(guest->msr_bitmaps_page_, X86_MSR_IA32_LSTAR);
  IgnoreMsr(guest->msr_bitmaps_page_, X86_MSR_IA32_CSTAR);
  IgnoreMsr(guest->msr_bitmaps_page_, X86_MSR_IA32_FMASK);
  IgnoreMsr(guest->msr_bitmaps_page_, X86_MSR_IA32_KERNEL_GS_BASE);
  IgnoreMsr(guest->msr_bitmaps_page_, X86_MSR_IA32_TSC_AUX);

  return zx::ok(ktl::move(guest));
}

Guest::Guest(hypervisor::GuestPhysicalAspace gpa) : gpa_(std::move(gpa)) {}

Guest::~Guest() {
  // Tear down the EPT mapping before apic_access_page_'s backing physical page
  // is returned to the allocator.
  {
    Guard<Mutex> guard{&apic_access_lock_};
    if (apic_access_mapped_) {
      std::ignore = gpa_.UnmapRange(APIC_PHYS_BASE, kPageSize);
    }
  }
  free_vmx_state();
}

zx::result<> Guest::MapApicAccessPage() {
  Guard<Mutex> guard{&apic_access_lock_};
  if (apic_access_mapped_) {
    return zx::ok();
  }
  if (auto result = gpa_.MapInterruptController(APIC_PHYS_BASE,
                                                apic_access_page_.PhysicalAddress(), kPageSize);
      result.is_error()) {
    return result;
  }
  apic_access_mapped_ = true;
  return zx::ok();
}

zx::result<> Guest::SetTrap(uint32_t kind, zx_vaddr_t addr, size_t len,
                            fbl::RefPtr<PortDispatcher> port, uint64_t key) {
  switch (kind) {
    case ZX_GUEST_TRAP_MEM:
      if (port) {
        return zx::error(ZX_ERR_INVALID_ARGS);
      }
      break;
    case ZX_GUEST_TRAP_BELL:
      if (!port) {
        return zx::error(ZX_ERR_INVALID_ARGS);
      }
      break;
    case ZX_GUEST_TRAP_IO:
      if (port) {
        return zx::error(ZX_ERR_INVALID_ARGS);
      }
      return traps_.InsertTrap(kind, addr, len, nullptr, key);
    // Registers one interrupt *vector*, not an address range, so this is
    // deliberately not a TrapMap entry: the EOI exit path runs on every guest
    // EOI and cannot afford a range lookup, and a vector has no length to
    // reserve. `len` is the registration itself -- 1 to register, 0 to
    // unregister -- which is why anything else is refused rather than rounded.
    //
    // The packet is delivered through zx_vcpu_enter() rather than to a port,
    // like every other guest exit that the VCPU's own thread must service, so a
    // port handle here is a caller who has misunderstood the mechanism.
    case ZX_GUEST_TRAP_EOI:
      if (port || key != 0) {
        return zx::error(ZX_ERR_INVALID_ARGS);
      }
      if (addr >= EoiBitmap::kNumVectors) {
        return zx::error(ZX_ERR_OUT_OF_RANGE);
      }
      if (len > 1) {
        return zx::error(ZX_ERR_INVALID_ARGS);
      }
      eoi_interest_.Set(static_cast<uint32_t>(addr), len == 1);
      return zx::ok();
    default:
      return zx::error(ZX_ERR_INVALID_ARGS);
  }

  // Common logic for memory-based traps.
  if (!IsPageRounded(addr) || !IsPageRounded(len)) {
    return zx::error(ZX_ERR_INVALID_ARGS);
  }
  zx_vaddr_t end = 0;
  if (__builtin_add_overflow(addr, len, &end)) {
    return zx::error(ZX_ERR_OUT_OF_RANGE);
  }

  {
    Guard<Mutex> guard{&apic_access_lock_};
    const zx_vaddr_t apic_end = APIC_PHYS_BASE + kPageSize;
    if (apic_access_mapped_ && addr < apic_end && end > APIC_PHYS_BASE) {
      // VMX recognizes an xAPIC access only while EPT translates this GPA to
      // the APIC-access page. Broad chipset traps commonly cover the entire
      // high-MMIO window, including FEE00000; preserve the one architectural
      // page while unmapping the ranges on either side.
      if (addr < APIC_PHYS_BASE) {
        if (auto result = gpa_.UnmapRange(addr, APIC_PHYS_BASE - addr); result.is_error()) {
          return result;
        }
      }
      if (end > apic_end) {
        if (auto result = gpa_.UnmapRange(apic_end, end - apic_end); result.is_error()) {
          return result;
        }
      }
    } else if (auto result = gpa_.UnmapRange(addr, len); result.is_error()) {
      return result;
    }
  }
  return traps_.InsertTrap(kind, addr, len, ktl::move(port), key);
}

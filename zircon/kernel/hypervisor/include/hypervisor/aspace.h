// Copyright 2017 The Fuchsia Authors
//
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT

#ifndef ZIRCON_KERNEL_HYPERVISOR_INCLUDE_HYPERVISOR_ASPACE_H_
#define ZIRCON_KERNEL_HYPERVISOR_INCLUDE_HYPERVISOR_ASPACE_H_

#include <lib/zx/result.h>

#include <ktl/unique_ptr.h>
#include <ktl/utility.h>
#include <vm/pinned_vm_object.h>
#include <vm/vm_address_region.h>
#include <vm/vm_aspace.h>
#include <vm/vm_object.h>

namespace hypervisor {

// RAII object that holds a mapping of guest physical address space to the host
// kernel virtual address space. Can be used to map a frequently accessed
// portion of guest physical memory for faster access.
class GuestPtr {
 public:
  GuestPtr(fbl::RefPtr<VmMapping> mapping, PinnedVmObject&& pinned_vmo, zx_vaddr_t offset)
      : mapping_(ktl::move(mapping)), pinned_vmo_(ktl::move(pinned_vmo)), offset_(offset) {}
  ~GuestPtr() { reset(); }

  GuestPtr() = default;
  GuestPtr(GuestPtr&&) noexcept = default;
  GuestPtr(const GuestPtr&) = delete;
  GuestPtr& operator=(const GuestPtr&) = delete;

  // NOT `= default`. A memberwise move-assign releases `mapping_` (an
  // fbl::RefPtr) WITHOUT calling Destroy(), so the kernel root VMAR keeps its
  // own reference and the old mapping stays live and mapped forever -- while
  // PinnedVmObject::operator= immediately resets and UNPINS the pages under it.
  // That is precisely the pairing CreateGuestPtr's error path exists to avoid
  // (a pinned VMO unpinned with a live kernel mapping still referencing it).
  //
  // It is guest-driven, not theoretical: every guest write of
  // HV_X64_MSR_VP_ASSIST_PAGE move-assigns the lazy-EOI GuestPtr, and pv.cc
  // does the same for the pvclock page. A ring-0 loop on that MSR would leak
  // one 4K kernel mapping + VmMapping + page tables per iteration until the
  // host exhausts kernel VA. Tearing the old mapping down first makes
  // move-assign mean the same thing as destruction-then-construction.
  GuestPtr& operator=(GuestPtr&& other) noexcept {
    if (this != &other) {
      reset();
      mapping_ = ktl::move(other.mapping_);
      pinned_vmo_ = ktl::move(other.pinned_vmo_);
      offset_ = other.offset_;
      other.offset_ = 0;
    }
    return *this;
  }

  void reset() {
    if (mapping_) {
      mapping_->Destroy();
      mapping_.reset();
    }
    pinned_vmo_.reset();
  }

  template <typename T>
  T* as() const {
    // The null check is load-bearing, not defensive style: a default
    // (never-mapped or reset) GuestPtr has no mapping, and dereferencing
    // `mapping_` here made an empty GuestPtr FAULT instead of reading as
    // empty. Every caller was written against "empty returns nullptr" -- they
    // null-check the result -- so the one caller that could legally see the
    // never-mapped state (a diagnostics read against a VCPU that never
    // registered a lazy-EOI assist page) turned a userspace
    // zx_vcpu_read_state into a deterministic kernel-mode null dereference
    // (CR2 = a VmMapping field offset) that took down a live host.
    if (!mapping_ || offset_ + sizeof(T) > mapping_->size()) {
      return nullptr;
    }
    return reinterpret_cast<T*>(mapping_->base() + offset_);
  }

 private:
  fbl::RefPtr<VmMapping> mapping_;
  PinnedVmObject pinned_vmo_;
  // Default-initialized: a default-constructed GuestPtr otherwise carries an
  // INDETERMINATE offset, and `as()` only avoids reading it because `!mapping_`
  // short-circuits first. Relying on that short-circuit is a trap for the next
  // edit of `as()`.
  zx_vaddr_t offset_ = 0;
};

class GuestPhysicalAspace {
 public:
  static zx::result<GuestPhysicalAspace> Create();
  ~GuestPhysicalAspace();

  GuestPhysicalAspace() = default;
  GuestPhysicalAspace(GuestPhysicalAspace&&) = default;
  GuestPhysicalAspace& operator=(GuestPhysicalAspace&&) = default;

  GuestPhysicalAspace(const GuestPhysicalAspace&) = delete;
  GuestPhysicalAspace& operator=(const GuestPhysicalAspace&) = delete;

  size_t size() const { return physical_aspace_->size(); }
  ArchVmAspace& arch_aspace() { return physical_aspace_->arch_aspace(); }
  fbl::RefPtr<VmAddressRegion> RootVmar() const { return physical_aspace_->RootVmar(); }

  bool IsMapped(zx_gpaddr_t guest_paddr) const;
  // Returns the maximum permissions declared by the mapping containing
  // |guest_paddr| without faulting or changing its page-table state.
  zx::result<arch_mmu_flags_t> MappingMmuFlags(zx_gpaddr_t guest_paddr) const;
  zx::result<> MapInterruptController(zx_gpaddr_t guest_paddr, zx_paddr_t host_paddr, size_t len);
  zx::result<> UnmapRange(zx_gpaddr_t guest_paddr, size_t len);
  zx::result<> PageFault(zx_gpaddr_t guest_paddr);
  zx::result<GuestPtr> CreateGuestPtr(zx_gpaddr_t guest_paddr, size_t len, const char* name);

 private:
  fbl::RefPtr<VmMapping> FindMapping(zx_gpaddr_t guest_paddr) const
      TA_REQ(physical_aspace_->lock());

  fbl::RefPtr<VmAspace> physical_aspace_;
};

}  // namespace hypervisor

#endif  // ZIRCON_KERNEL_HYPERVISOR_INCLUDE_HYPERVISOR_ASPACE_H_

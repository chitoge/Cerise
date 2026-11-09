// Copyright 2026 The Fuchsia Authors
//
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT

#include <lib/page/size.h>
#include <lib/fit/defer.h>
#include <string.h>

#include <arch/hypervisor.h>
#include <fbl/alloc_checker.h>
#include <kernel/thread.h>
#include <ktl/unique_ptr.h>

namespace {

constexpr zx_vcpu_memory_access_mask_t kSupportedAccess =
    ZX_VCPU_MEMORY_ACCESS_WRITE | ZX_VCPU_MEMORY_ACCESS_EXECUTE;

constexpr arch_mmu_flags_t AccessMmuFlags(zx_vcpu_memory_access_mask_t access) {
  arch_mmu_flags_t flags = 0;
  if ((access & ZX_VCPU_MEMORY_ACCESS_READ) != 0) {
    flags |= ARCH_MMU_FLAG_PERM_READ;
  }
  if ((access & ZX_VCPU_MEMORY_ACCESS_WRITE) != 0) {
    flags |= ARCH_MMU_FLAG_PERM_WRITE;
  }
  if ((access & ZX_VCPU_MEMORY_ACCESS_EXECUTE) != 0) {
    flags |= ARCH_MMU_FLAG_PERM_EXECUTE;
  }
  return flags;
}

constexpr zx_vcpu_memory_access_mask_t QualificationAccess(uint64_t qualification) {
  zx_vcpu_memory_access_mask_t access = 0;
  if ((qualification & (uint64_t{1} << 0)) != 0) {
    access |= ZX_VCPU_MEMORY_ACCESS_READ;
  }
  if ((qualification & (uint64_t{1} << 1)) != 0) {
    access |= ZX_VCPU_MEMORY_ACCESS_WRITE;
  }
  if ((qualification & (uint64_t{1} << 2)) != 0) {
    access |= ZX_VCPU_MEMORY_ACCESS_EXECUTE;
  }
  return access;
}

bool RangeIsZero(const zx_vcpu_memory_access_range_t& range) {
  return range.guest_paddr == 0 && range.length == 0 && range.access == 0 &&
         range.reserved == 0;
}

}  // namespace

void Guest::RegisterVcpu(Vcpu& vcpu, uint16_t vpid) {
  DEBUG_ASSERT(vpid > 0 && vpid <= kMaxGuestVcpus);
  Guard<Mutex> guard{&vcpu_registry_lock_};
  DEBUG_ASSERT(vcpus_[vpid - 1] == nullptr);
  vcpus_[vpid - 1] = &vcpu;
}

void Guest::UnregisterVcpu(Vcpu& vcpu, uint16_t vpid) {
  DEBUG_ASSERT(vpid > 0 && vpid <= kMaxGuestVcpus);
  Guard<Mutex> guard{&vcpu_registry_lock_};
  DEBUG_ASSERT(vcpus_[vpid - 1] == &vcpu);
  vcpus_[vpid - 1] = nullptr;
}

void Guest::QuiesceVcpus(Vcpu* caller) {
  // Holding this lock stabilizes VCPU lifetimes as well as the set being
  // stopped. Vcpu::~Vcpu unregisters before taking the global thread-list lock,
  // so Kick's thread-list lookup cannot invert this ordering.
  Guard<Mutex> guard{&vcpu_registry_lock_};
  for (Vcpu* vcpu : vcpus_) {
    if (vcpu != nullptr && vcpu != caller) {
      vcpu->Kick();
    }
  }
  for (;;) {
    bool all_stopped = true;
    for (Vcpu* vcpu : vcpus_) {
      if (vcpu != nullptr && vcpu != caller &&
          vcpu->entered_.load(ktl::memory_order_acquire)) {
        all_stopped = false;
        break;
      }
    }
    if (all_stopped) {
      return;
    }
    Thread::Current::SleepRelative(ZX_USEC(10));
  }
}

void Guest::QuiesceMemoryAccessStop(Vcpu& trigger) {
  if (!IsMemoryAccessTrigger(trigger.vpid_)) {
    return;
  }
  QuiesceVcpus(&trigger);
}

zx::result<> Guest::ReadMemoryAccessControl(zx_vcpu_memory_access_control_t& out) const {
  out = {};
  out.magic = ZX_VCPU_MEMORY_ACCESS_CONTROL_MAGIC;
  out.version = ZX_VCPU_MEMORY_ACCESS_CONTROL_VERSION;
  out.size = sizeof(out);
  out.availability = ZX_VCPU_MEMORY_ACCESS_AVAILABLE;
  out.max_ranges = ZX_VCPU_MEMORY_ACCESS_MAX_RANGES;
  out.max_pages = ZX_VCPU_MEMORY_ACCESS_MAX_PAGES;
  out.supported_flags = ZX_VCPU_MEMORY_ACCESS_ALL_FLAGS;
  out.supported_access = kSupportedAccess;

  Guard<SpinLock, IrqSave> guard{&memory_access_lock_};
  const bool pending = memory_access_pending_.load(ktl::memory_order_relaxed);
  if (memory_access_installed_.load(ktl::memory_order_relaxed) && !pending) {
    out.active_flags = ZX_VCPU_MEMORY_ACCESS_ARM;
  }
  out.range_count = memory_access_range_count_;
  memcpy(out.ranges, memory_access_ranges_, sizeof(out.ranges));
  if (pending) {
    out.pending_sequence = memory_access_result_.sequence;
    out.pending_guest_paddr = memory_access_result_.guest_paddr;
    out.pending_guest_vaddr = memory_access_result_.guest_vaddr;
    out.pending_rip = memory_access_result_.rip;
    out.pending_qualification = memory_access_result_.qualification;
    out.pending_range_mask = memory_access_result_.range_mask;
    out.pending_access = memory_access_result_.access;
    out.pending_flags = memory_access_result_.flags;
    out.pending_vpid = memory_access_result_.vpid;
  }
  return zx::ok();
}

zx::result<> Guest::WriteMemoryAccessControl(const zx_vcpu_memory_access_control_t& in,
                                             Vcpu& caller) {
  if (in.magic != ZX_VCPU_MEMORY_ACCESS_CONTROL_MAGIC ||
      in.version != ZX_VCPU_MEMORY_ACCESS_CONTROL_VERSION || in.size != sizeof(in) ||
      in.reserved != 0 || in.availability != 0 || in.max_ranges != 0 || in.max_pages != 0 ||
      in.supported_flags != 0 ||
      (in.active_flags & ~ZX_VCPU_MEMORY_ACCESS_ALL_FLAGS) != 0 || in.reserved2 != 0 ||
      in.pending_sequence != 0 || in.pending_guest_paddr != 0 ||
      in.pending_guest_vaddr != 0 || in.pending_rip != 0 || in.pending_qualification != 0 ||
      in.pending_range_mask != 0 || in.pending_access != 0 || in.pending_flags != 0 ||
      in.pending_vpid != 0 || in.supported_access != 0 ||
      in.range_count > ZX_VCPU_MEMORY_ACCESS_MAX_RANGES) {
    return zx::error(ZX_ERR_INVALID_ARGS);
  }

  const bool arm = (in.active_flags & ZX_VCPU_MEMORY_ACCESS_ARM) != 0;
  if (arm != (in.range_count != 0)) {
    return zx::error(ZX_ERR_INVALID_ARGS);
  }

  struct RequestedPage {
    zx_gpaddr_t guest_paddr = 0;
    zx_vcpu_memory_access_mask_t trapped_access = 0;
  };
  struct TransitionPage {
    zx_gpaddr_t guest_paddr = 0;
    arch_mmu_flags_t before_flags = 0;
    arch_mmu_flags_t desired_flags = 0;
  };
  struct TransitionScratch {
    RequestedPage requested_pages[ZX_VCPU_MEMORY_ACCESS_MAX_PAGES] = {};
    MemoryAccessPage old_pages[ZX_VCPU_MEMORY_ACCESS_MAX_PAGES] = {};
    TransitionPage transition[ZX_VCPU_MEMORY_ACCESS_MAX_PAGES * 2] = {};
    MemoryAccessPage replacement[ZX_VCPU_MEMORY_ACCESS_MAX_PAGES] = {};
  };

  // PageFault and Protect may descend through the VM and PMM stacks. Keeping
  // these bounded arrays (about 7 KiB at the current ABI limits) on a 16 KiB
  // kernel stack leaves too little headroom for those calls. Configuration is
  // already a blocking control path, so allocate all transition scratch before
  // quiescing peers or mutating EPT permissions.
  fbl::AllocChecker ac;
  ktl::unique_ptr<TransitionScratch> scratch(
      new (&ac) TransitionScratch());
  if (!ac.check()) {
    return zx::error(ZX_ERR_NO_MEMORY);
  }
  auto& requested_pages = scratch->requested_pages;
  auto& old_pages = scratch->old_pages;
  auto& transition = scratch->transition;
  auto& replacement = scratch->replacement;
  uint32_t requested_page_count = 0;

  for (uint32_t i = 0; i < ZX_VCPU_MEMORY_ACCESS_MAX_RANGES; ++i) {
    const auto& range = in.ranges[i];
    if (i >= in.range_count) {
      if (!RangeIsZero(range)) {
        return zx::error(ZX_ERR_INVALID_ARGS);
      }
      continue;
    }
    if (range.reserved != 0 || range.length == 0 ||
        (range.guest_paddr & (kPageSize - 1)) != 0 || (range.length & (kPageSize - 1)) != 0 ||
        range.access == 0 || (range.access & ~ZX_VCPU_MEMORY_ACCESS_ALL) != 0 ||
        range.guest_paddr >= gpa_.size() || range.length > gpa_.size() - range.guest_paddr) {
      return zx::error(ZX_ERR_INVALID_ARGS);
    }
    if ((range.access & ~kSupportedAccess) != 0) {
      // EPT forbids write without read. Selecting READ over ordinary RW guest
      // memory would therefore also revoke write and repeatedly fault an
      // unselected access, violating the independently-selectable,
      // transparent pre-access contract.
      return zx::error(ZX_ERR_NOT_SUPPORTED);
    }
    for (uint64_t offset = 0; offset < range.length; offset += kPageSize) {
      const zx_gpaddr_t guest_paddr = range.guest_paddr + offset;
      uint32_t page_index = 0;
      for (; page_index < requested_page_count; ++page_index) {
        if (requested_pages[page_index].guest_paddr == guest_paddr) {
          break;
        }
      }
      if (page_index == requested_page_count) {
        if (requested_page_count == ZX_VCPU_MEMORY_ACCESS_MAX_PAGES) {
          return zx::error(ZX_ERR_OUT_OF_RANGE);
        }
        requested_pages[requested_page_count++].guest_paddr = guest_paddr;
      }
      requested_pages[page_index].trapped_access |= range.access;
    }
  }

  // Validate every mapping and requested permission without touching the EPT.
  // This happens before peers are kicked, page faults are resolved, or any
  // instrumentation state changes.
  for (uint32_t i = 0; i < requested_page_count; ++i) {
    auto flags = gpa_.MappingMmuFlags(requested_pages[i].guest_paddr);
    if (flags.is_error()) {
      if (flags.status_value() == ZX_ERR_NOT_FOUND) {
        return zx::error(ZX_ERR_INVALID_ARGS);
      }
      return flags.take_error();
    }
    const arch_mmu_flags_t requested = AccessMmuFlags(requested_pages[i].trapped_access);
    if ((*flags & requested) != requested) {
      return zx::error(ZX_ERR_ACCESS_DENIED);
    }
  }

  Guard<Mutex> config_guard{&memory_access_config_lock_};

  uint64_t pending_sequence = 0;
  {
    Guard<SpinLock, IrqSave> guard{&memory_access_lock_};
    if (memory_access_pending_.load(ktl::memory_order_relaxed)) {
      pending_sequence = memory_access_result_.sequence;
    }
  }
  if (pending_sequence != 0) {
    if (in.ack_sequence != pending_sequence) {
      return zx::error(ZX_ERR_BAD_STATE);
    }
  } else if (in.ack_sequence != 0) {
    return zx::error(ZX_ERR_NOT_FOUND);
  }

  // Close the create/enter race before kicking peers. New Enter calls now fail
  // closed, while a VCPU already past its entry check is caught by Kick below.
  // On a failed transition restore the real prior pending state.
  const bool had_pending = pending_sequence != 0;
  memory_access_pending_.store(true, ktl::memory_order_release);
  bool transition_committed = false;
  auto restore_transition_gate = fit::defer([this, had_pending, &transition_committed] {
    if (!transition_committed) {
      memory_access_pending_.store(had_pending, ktl::memory_order_release);
    }
  });

  // No VCPU may observe the transition between the old and replacement EPT
  // permission sets.
  QuiesceVcpus(&caller);

  uint32_t old_page_count = 0;
  {
    Guard<SpinLock, IrqSave> guard{&memory_access_lock_};
    old_page_count = memory_access_page_count_;
    memcpy(old_pages, memory_access_pages_, sizeof(old_pages));
  }

  // Materialize only pages not already held by the old control. Existing pages
  // must not be faulted here: PageFault deliberately restores their mapping's
  // maximum permissions, which would discard the exact trapped state before a
  // rollback record exists.
  for (uint32_t i = 0; i < requested_page_count; ++i) {
    bool was_installed = false;
    for (uint32_t j = 0; j < old_page_count; ++j) {
      if (old_pages[j].guest_paddr == requested_pages[i].guest_paddr) {
        was_installed = true;
        break;
      }
    }
    if (!was_installed) {
      if (auto result = gpa_.PageFault(requested_pages[i].guest_paddr); result.is_error()) {
        return result.take_error();
      }
    }
  }

  uint32_t transition_count = 0;

  for (uint32_t i = 0; i < old_page_count; ++i) {
    transition[transition_count].guest_paddr = old_pages[i].guest_paddr;
    transition[transition_count].before_flags =
        old_pages[i].original_flags & ~AccessMmuFlags(old_pages[i].trapped_access);
    transition[transition_count].desired_flags = old_pages[i].original_flags;
    transition_count++;
  }

  for (uint32_t i = 0; i < requested_page_count; ++i) {
    MemoryAccessPage page = {};
    page.guest_paddr = requested_pages[i].guest_paddr;
    page.trapped_access = requested_pages[i].trapped_access;

    uint32_t transition_index = 0;
    for (; transition_index < transition_count; ++transition_index) {
      if (transition[transition_index].guest_paddr == page.guest_paddr) {
        break;
      }
    }
    if (transition_index < transition_count) {
      for (uint32_t j = 0; j < old_page_count; ++j) {
        if (old_pages[j].guest_paddr == page.guest_paddr) {
          page.original_flags = old_pages[j].original_flags;
          break;
        }
      }
    } else {
      arch_mmu_flags_t flags = 0;
      zx_status_t status = gpa_.arch_aspace().Query(page.guest_paddr, nullptr, &flags);
      if (status != ZX_OK) {
        return zx::error(status);
      }
      page.original_flags = flags;
      transition[transition_count].guest_paddr = page.guest_paddr;
      transition[transition_count].before_flags = flags;
      transition[transition_count].desired_flags = flags;
      transition_index = transition_count++;
    }
    transition[transition_index].desired_flags =
        page.original_flags & ~AccessMmuFlags(page.trapped_access);
    replacement[i] = page;
  }

  uint32_t changed = 0;
  for (; changed < transition_count; ++changed) {
    zx_status_t status = gpa_.arch_aspace().Protect(
        transition[changed].guest_paddr, 1, transition[changed].desired_flags,
        ArchVmAspace::ArchUnmapOptions::None);
    if (status != ZX_OK) {
      // Include the failing page: Protect documents that a large-page split may
      // leave a mixed result on allocation failure.
      for (uint32_t rollback = changed + 1; rollback > 0; --rollback) {
        const TransitionPage& page = transition[rollback - 1];
        zx_status_t restore = gpa_.arch_aspace().Protect(
            page.guest_paddr, 1, page.before_flags, ArchVmAspace::ArchUnmapOptions::None);
        if (restore != ZX_OK) {
          dprintf(CRITICAL,
                  "hypervisor: failed to roll back EPT permission at guest-physical %#lx: %d\n",
                  page.guest_paddr, restore);
        }
      }
      return zx::error(status);
    }
  }

  {
    Guard<SpinLock, IrqSave> guard{&memory_access_lock_};
    memset(memory_access_ranges_, 0, sizeof(memory_access_ranges_));
    memset(memory_access_pages_, 0, sizeof(memory_access_pages_));
    if (arm) {
      memcpy(memory_access_ranges_, in.ranges, sizeof(memory_access_ranges_));
      memcpy(memory_access_pages_, replacement, sizeof(replacement));
    }
    memory_access_range_count_ = arm ? in.range_count : 0;
    memory_access_page_count_ = arm ? requested_page_count : 0;
    memory_access_owner_vpid_ = arm ? caller.vpid_ : 0;
    memory_access_result_ = {};
    memory_access_trigger_vpid_.store(0, ktl::memory_order_relaxed);
    memory_access_pending_.store(false, ktl::memory_order_release);
    memory_access_installed_.store(arm, ktl::memory_order_release);
    memory_access_transitioning_.store(false, ktl::memory_order_release);
  }
  transition_committed = true;
  return zx::ok();
}

bool Guest::MaybeStopMemoryAccess(uint64_t qualification, zx_gpaddr_t guest_paddr,
                                  zx_vaddr_t guest_vaddr, zx_vaddr_t rip, uint16_t vpid,
                                  zx_port_packet_t& packet) {
  if (memory_access_transitioning_.load(ktl::memory_order_acquire)) {
    // A peer was already in non-root mode when a backing-page transition
    // started. Its kick can race an EPT exit, but it must not observe or relax
    // the transient mapping. Return an empty cancellation packet.
    memset(&packet, 0, sizeof(packet));
    return true;
  }
  if (!memory_access_installed_.load(ktl::memory_order_acquire)) {
    return false;
  }

  MemoryAccessPendingRecord result = {};
  {
    Guard<SpinLock, IrqSave> guard{&memory_access_lock_};
    if (memory_access_pending_.load(ktl::memory_order_relaxed)) {
      // A peer may take an EPT exit in the short interval before the first
      // trigger's deferred kick reaches it. Never pass that exit to PageFault:
      // doing so would restore the very EPT permission preserving the stop.
      result = memory_access_result_;
    } else {
      const zx_vcpu_memory_access_mask_t access = QualificationAccess(qualification);
      uint64_t range_mask = 0;
      for (uint32_t i = 0; i < memory_access_range_count_; ++i) {
        const auto& range = memory_access_ranges_[i];
        if (guest_paddr >= range.guest_paddr &&
            guest_paddr - range.guest_paddr < range.length &&
            (range.access & access) != 0) {
          range_mask |= uint64_t{1} << i;
        }
      }
      if (range_mask == 0) {
        return false;
      }

      result.sequence = memory_access_next_sequence_++;
      if (memory_access_next_sequence_ == 0) {
        memory_access_next_sequence_ = 1;
      }
      result.guest_paddr = guest_paddr;
      result.guest_vaddr = (qualification & (uint64_t{1} << 7)) != 0 ? guest_vaddr : 0;
      result.rip = rip;
      result.qualification = qualification;
      result.range_mask = range_mask;
      result.access = access;
      result.flags = (qualification & (uint64_t{1} << 7)) != 0
                         ? ZX_VCPU_MEMORY_ACCESS_RESULT_GVA_VALID
                         : 0;
      result.vpid = vpid;
      memory_access_result_ = result;
      memory_access_trigger_vpid_.store(vpid, ktl::memory_order_release);
      memory_access_pending_.store(true, ktl::memory_order_release);
    }
  }

  memset(&packet, 0, sizeof(packet));
  if (result.vpid != vpid) {
    // A peer raced the first trigger's deferred kick. It must leave Enter
    // without publishing a duplicate result: userspace could otherwise
    // acknowledge that duplicate while the real trigger is still joining the
    // peer, creating a circular wait. The VM-exit caller maps this empty packet
    // to ZX_ERR_CANCELED.
    return true;
  }
  packet.type = ZX_PKT_TYPE_GUEST_MEMORY_ACCESS;
  packet.guest_memory_access.sequence = result.sequence;
  packet.guest_memory_access.guest_paddr = result.guest_paddr;
  packet.guest_memory_access.guest_vaddr = result.guest_vaddr;
  packet.guest_memory_access.rip = result.rip;
  return true;
}

zx::result<> Guest::PageFaultPreservingMemoryAccess(zx_gpaddr_t guest_paddr,
                                                     uint16_t caller_vpid) {
  if (!memory_access_installed_.load(ktl::memory_order_acquire)) {
    return gpa_.PageFault(guest_paddr);
  }

  Guard<Mutex> config_guard{&memory_access_config_lock_};
  if (!memory_access_installed_.load(ktl::memory_order_acquire)) {
    return gpa_.PageFault(guest_paddr);
  }

  fbl::AllocChecker ac;
  ktl::unique_ptr<MemoryAccessPage[]> protected_pages(
      new (&ac) MemoryAccessPage[ZX_VCPU_MEMORY_ACCESS_MAX_PAGES]);
  if (!ac.check()) {
    return zx::error(ZX_ERR_NO_MEMORY);
  }

  uint32_t protected_page_count = 0;
  {
    Guard<SpinLock, IrqSave> guard{&memory_access_lock_};
    protected_page_count = memory_access_page_count_;
    memcpy(protected_pages.get(), memory_access_pages_,
           sizeof(MemoryAccessPage) * protected_page_count);
  }

  Vcpu* caller = nullptr;
  {
    Guard<Mutex> guard{&vcpu_registry_lock_};
    if (caller_vpid == 0 || caller_vpid > kMaxGuestVcpus ||
        vcpus_[caller_vpid - 1] == nullptr) {
      return zx::error(ZX_ERR_BAD_STATE);
    }
    caller = vcpus_[caller_vpid - 1];
  }

  // PageFault maps an opportunistic adjacent batch with "upgrade existing"
  // semantics. Without this gate, such a batch can transiently restore a
  // protected EPT entry and a peer can execute through the observation range.
  // Block new entries, stop peers, then restore the complete fixed protection
  // set before releasing the gate.
  memory_access_transitioning_.store(true, ktl::memory_order_release);
  bool release_transition = true;
  auto transition_guard = fit::defer([this, &release_transition] {
    if (release_transition) {
      memory_access_transitioning_.store(false, ktl::memory_order_release);
    }
  });
  QuiesceVcpus(caller);

  zx::result<> fault = gpa_.PageFault(guest_paddr);
  zx_status_t protection_error = ZX_OK;
  for (uint32_t i = 0; i < protected_page_count; ++i) {
    const MemoryAccessPage& page = protected_pages[i];
    const arch_mmu_flags_t desired_flags =
        page.original_flags & ~AccessMmuFlags(page.trapped_access);
    const zx_status_t status = gpa_.arch_aspace().Protect(
        page.guest_paddr, 1, desired_flags,
        ArchVmAspace::ArchUnmapOptions::None);
    if (status != ZX_OK && protection_error == ZX_OK) {
      protection_error = status;
    }
  }
  if (protection_error != ZX_OK) {
    // Fail closed. A later explicit disarm uses the durable original flags and
    // clears the transition gate after restoring the whole set.
    release_transition = false;
    return zx::error(protection_error);
  }
  return fault;
}

void Guest::ReleaseMemoryAccessOwner(Vcpu& owner, uint16_t vpid) {
  bool owns_control = false;
  {
    Guard<SpinLock, IrqSave> guard{&memory_access_lock_};
    owns_control = memory_access_owner_vpid_ == vpid;
  }
  if (!owns_control) {
    return;
  }

  zx_vcpu_memory_access_control_t disarm = {};
  disarm.magic = ZX_VCPU_MEMORY_ACCESS_CONTROL_MAGIC;
  disarm.version = ZX_VCPU_MEMORY_ACCESS_CONTROL_VERSION;
  disarm.size = sizeof(disarm);
  {
    Guard<SpinLock, IrqSave> guard{&memory_access_lock_};
    if (memory_access_pending_.load(ktl::memory_order_relaxed)) {
      disarm.ack_sequence = memory_access_result_.sequence;
    }
  }
  if (auto result = WriteMemoryAccessControl(disarm, owner); result.is_error()) {
    dprintf(CRITICAL, "hypervisor: failed to release guest memory-access control: %d\n",
            result.status_value());
  }
}

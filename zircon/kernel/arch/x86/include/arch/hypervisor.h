// Copyright 2017 The Fuchsia Authors
//
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT

#ifndef ZIRCON_KERNEL_ARCH_X86_INCLUDE_ARCH_HYPERVISOR_H_
#define ZIRCON_KERNEL_ARCH_X86_INCLUDE_ARCH_HYPERVISOR_H_

#include <lib/id_allocator.h>
#include <zircon/compiler.h>
#include <zircon/syscalls/hypervisor.h>
#include <zircon/types.h>

#include <arch/x86/apic.h>
#include <arch/x86/hypervisor/vmx_state.h>
#include <arch/x86/interrupts.h>
#include <fbl/ref_ptr.h>
#include <hypervisor/aspace.h>
#include <hypervisor/interrupt_tracker.h>
#include <hypervisor/page.h>
#include <hypervisor/trap_map.h>
#include <kernel/event.h>
#include <kernel/mutex.h>
#include <kernel/spinlock.h>
#include <kernel/timer.h>
#include <ktl/atomic.h>
#include <ktl/unique_ptr.h>

class AutoVmcs;
class HardwareBreakpointSession;
class IntelPtState;
struct VmxInfo;
class Vcpu;

// Which interrupt vectors a VMM has asked to be told about when the guest ends
// them, one bit per vector.
//
// The gate on ZX_PKT_TYPE_GUEST_EOI, and the reason that exit is affordable. An
// EOI is the last instruction of every interrupt handler a guest runs, so
// surfacing all of them would put a userspace round trip on every interrupt; the
// only consumer is a userspace IO-APIC's level-triggered lines, of which a
// typical guest has one (the ACPI SCI). This is the same shape KVM uses for
// KVM_EXIT_IOAPIC_EOI (`ioapic_handled_vectors`), for the same reason.
//
// Written from a VMM thread through zx_guest_set_trap() and read on the VCPU's
// own exit path, so the words are atomic. Relaxed is the right order: each bit
// stands alone, and a registration racing an in-flight EOI legitimately lands on
// either side of it -- the VMM cannot have been depending on an EOI that had
// already been executed when it asked.
class EoiBitmap {
 public:
  static constexpr uint32_t kNumVectors = 256;

  bool Test(uint32_t vector) const {
    if (vector >= kNumVectors) {
      return false;
    }
    return (bits_[vector / 64].load(ktl::memory_order_relaxed) & Bit(vector)) != 0;
  }

  void Set(uint32_t vector, bool interested) {
    if (vector >= kNumVectors) {
      return;
    }
    ktl::atomic<uint64_t>& word = bits_[vector / 64];
    if (interested) {
      word.fetch_or(Bit(vector), ktl::memory_order_relaxed);
    } else {
      word.fetch_and(~Bit(vector), ktl::memory_order_relaxed);
    }
  }

  // Deliberately no Empty() / "is anything registered" accessor. There was one,
  // used as a precheck in front of Test() on the EOI path, and it was removed
  // rather than kept: it made a test of "an unregistered vector does not exit"
  // pass without Test() ever being reached, which is how a gate that registered
  // every vector could have shipped green. It was also four loads standing in
  // front of one. Callers test the vector.

 private:
  static constexpr uint64_t Bit(uint32_t vector) { return uint64_t{1} << (vector % 64); }

  ktl::atomic<uint64_t> bits_[kNumVectors / 64] = {};
};

class VmxPage : public hypervisor::Page {
 public:
  zx::result<> Alloc(const VmxInfo& info, uint8_t fill);

 private:
  using hypervisor::Page::Alloc;
};

// Represents a guest within the hypervisor.
class Guest {
 public:
  // Maximum VCPUs per guest.
  static constexpr size_t kMaxGuestVcpus = 64;

  static zx::result<ktl::unique_ptr<Guest>> Create();

  Guest(const Guest&) = delete;
  Guest(Guest&&) = delete;
  Guest& operator=(const Guest&) = delete;
  Guest& operator=(Guest&&) = delete;

  virtual ~Guest();

  zx::result<> SetTrap(uint32_t kind, zx_vaddr_t addr, size_t len, fbl::RefPtr<PortDispatcher> port,
                       uint64_t key);

  hypervisor::GuestPhysicalAspace& PhysicalAspace() { return gpa_; }
  fbl::RefPtr<VmAddressRegion> RootVmar() const { return gpa_.RootVmar(); }
  hypervisor::TrapMap& Traps() { return traps_; }
  // The vectors whose EOIs this guest's VMM has asked to see. Read on every
  // guest EOI, so it is handed to the exit handler rather than looked up.
  const EoiBitmap& EoiInterest() const { return eoi_interest_; }
  zx_paddr_t MsrBitmapsAddress() const { return msr_bitmaps_page_.PhysicalAddress(); }
  zx_paddr_t ApicAccessAddress() const { return apic_access_page_.PhysicalAddress(); }
  zx::result<> MapApicAccessPage();

  zx::result<uint16_t> TryAllocVpid() { return vpid_allocator_.TryAlloc(); }
  zx::result<> FreeVpid(uint16_t vpid) { return vpid_allocator_.Free(vpid); }

  // Guest-global, EPT-backed pre-access stops. Configuration is carried
  // through a VCPU handle but applies to every VCPU sharing this EPT.
  zx::result<> ReadMemoryAccessControl(zx_vcpu_memory_access_control_t& out) const;
  zx::result<> WriteMemoryAccessControl(const zx_vcpu_memory_access_control_t& in, Vcpu& caller);
  bool MaybeStopMemoryAccess(uint64_t qualification, zx_gpaddr_t guest_paddr,
                             zx_vaddr_t guest_vaddr, zx_vaddr_t rip, uint16_t vpid,
                             zx_port_packet_t& packet);
  zx::result<> PageFaultPreservingMemoryAccess(zx_gpaddr_t guest_paddr,
                                               uint16_t caller_vpid);
  bool MemoryAccessBlocked() const {
    return memory_access_pending_.load(ktl::memory_order_acquire) ||
           memory_access_transitioning_.load(ktl::memory_order_acquire);
  }
  bool IsMemoryAccessTrigger(uint16_t vpid) const {
    return memory_access_trigger_vpid_.load(ktl::memory_order_acquire) == vpid;
  }
  void QuiesceMemoryAccessStop(Vcpu& trigger);

  // A hardware-breakpoint result is per-VCPU, but its stopped boundary is
  // guest-wide: peers must not re-enter until the trigger acknowledges it.
  bool ClaimHardwareBreakpointStop(uint16_t vpid);
  void ReleaseHardwareBreakpointStop(uint16_t vpid);
  bool HardwareBreakpointPending() const {
    return hardware_breakpoint_trigger_vpid_.load(ktl::memory_order_acquire) != 0;
  }
  bool IsHardwareBreakpointTrigger(uint16_t vpid) const {
    return hardware_breakpoint_trigger_vpid_.load(ktl::memory_order_acquire) == vpid;
  }
  void QuiesceHardwareBreakpointStop(Vcpu& trigger);

  // VCPU lifetime registry used only to establish a guest-wide stopped
  // boundary before EPT permissions are transitioned.
  void RegisterVcpu(Vcpu& vcpu, uint16_t vpid);
  void UnregisterVcpu(Vcpu& vcpu, uint16_t vpid);
  void ReleaseMemoryAccessOwner(Vcpu& owner, uint16_t vpid);

 private:
  struct MemoryAccessPage {
    zx_gpaddr_t guest_paddr = 0;
    arch_mmu_flags_t original_flags = 0;
    zx_vcpu_memory_access_mask_t trapped_access = 0;
  };

  struct MemoryAccessPendingRecord {
    uint64_t sequence = 0;
    zx_gpaddr_t guest_paddr = 0;
    zx_vaddr_t guest_vaddr = 0;
    zx_vaddr_t rip = 0;
    uint64_t qualification = 0;
    uint64_t range_mask = 0;
    zx_vcpu_memory_access_mask_t access = 0;
    uint32_t flags = 0;
    uint32_t vpid = 0;
  };

  explicit Guest(hypervisor::GuestPhysicalAspace gpa);
  void QuiesceVcpus(Vcpu* caller);

  hypervisor::GuestPhysicalAspace gpa_;
  hypervisor::TrapMap traps_;
  id_allocator::IdAllocator<uint16_t, kMaxGuestVcpus> vpid_allocator_;
  VmxPage msr_bitmaps_page_;
  // Shared by the guest's VCPUs as the VMX APIC-access page. EPT maps the
  // architectural local-APIC GPA to this host page; each VCPU still has its own
  // virtual-APIC page containing that processor's register state.
  hypervisor::Page apic_access_page_;
  DECLARE_MUTEX(Guest) apic_access_lock_;
  bool apic_access_mapped_ TA_GUARDED(apic_access_lock_) = false;
  EoiBitmap eoi_interest_;

  DECLARE_MUTEX(Guest) vcpu_registry_lock_;
  Vcpu* vcpus_[kMaxGuestVcpus] TA_GUARDED(vcpu_registry_lock_) = {};

  // Configuration changes may fault pages in and split EPT leaves, so they use
  // a blocking mutex. The exit path only touches the fixed, published record
  // under the spin lock and never allocates or blocks.
  DECLARE_MUTEX(Guest) memory_access_config_lock_;
  mutable DECLARE_SPINLOCK(Guest) memory_access_lock_;
  zx_vcpu_memory_access_range_t
      memory_access_ranges_[ZX_VCPU_MEMORY_ACCESS_MAX_RANGES]
          TA_GUARDED(memory_access_lock_) = {};
  MemoryAccessPage memory_access_pages_[ZX_VCPU_MEMORY_ACCESS_MAX_PAGES]
      TA_GUARDED(memory_access_lock_) = {};
  uint32_t memory_access_range_count_ TA_GUARDED(memory_access_lock_) = 0;
  uint32_t memory_access_page_count_ TA_GUARDED(memory_access_lock_) = 0;
  uint16_t memory_access_owner_vpid_ TA_GUARDED(memory_access_lock_) = 0;
  uint64_t memory_access_next_sequence_ TA_GUARDED(memory_access_lock_) = 1;
  MemoryAccessPendingRecord memory_access_result_ TA_GUARDED(memory_access_lock_) = {};
  ktl::atomic<bool> memory_access_installed_ = false;
  ktl::atomic<bool> memory_access_pending_ = false;
  ktl::atomic<bool> memory_access_transitioning_ = false;
  ktl::atomic<uint16_t> memory_access_trigger_vpid_ = 0;
  ktl::atomic<uint16_t> hardware_breakpoint_trigger_vpid_ = 0;
};

// Stores part of the MSR state for a virtual CPU.
struct MsrState {
  uint64_t star;
  uint64_t lstar;
  uint64_t cstar;
  uint64_t fmask;
  uint64_t tsc_aux;
  uint64_t kernel_gs_base;
};

// Stores the local APIC state for a virtual CPU.
struct LocalApicState {
  // The architectural local-APIC interface currently selected by
  // IA32_APIC_BASE. Legacy VCPUs start true for compatibility; an xAPIC VCPU
  // starts false and may make the one-way architectural transition to x2APIC.
  bool x2apic_enabled = true;
  // Timer for APIC timer.
  Timer timer;
  // Tracks pending interrupts.
  hypervisor::InterruptTracker<X86_INT_COUNT> interrupt_tracker;
  // LVT timer configuration
  uint32_t lvt_timer = LVT_MASKED;  // Initial state is masked (Vol 3 Section 10.12.5.1).
  uint32_t lvt_initial_count = 0;
  uint32_t lvt_divide_config = 0;
  // Absolute monotonic deadline the APIC timer is currently armed to fire at, or
  // 0 when it is disarmed. This shadows the live |timer| object (which owns no
  // readable deadline) so a snapshot can capture the *remaining* time and
  // reconstruct — rather than blind-rearm — the timer on restore. Written only
  // by update_timer(); the Timer object remains the source of truth for firing.
  zx_instant_mono_t timer_deadline = 0;
  // The same deadline expressed in raw TSC ticks, or 0 when it is not known.
  //
  // `timer_deadline` cannot be used to answer the guest's CURRENT_COUNT read:
  // the monotonic clock it is expressed in has **millisecond** granularity on
  // this platform (measured -- two reads of `current_mono_time()` tens of
  // microseconds apart returned the identical value, so a count derived from it
  // does not move at all between two guest instructions). The APIC timer is
  // scaled from the TSC in the first place, so the raw tick counter is both
  // finer and the natural unit: the remaining tick count, shifted down by the
  // divide configuration, *is* the current count.
  //
  // Written by `lvt_deadline`, which is the only place the tick duration is
  // known. Zero after a snapshot restore, which reconstructs a monotonic
  // deadline and has no tick deadline to go with it; the count then falls back
  // to the coarse derivation, which is imprecise but not wrong.
  uint64_t timer_tsc_deadline = 0;
  // The raw value the guest last wrote to IA32_TSC_DEADLINE (0x6e0), kept purely
  // so the READ of that register can hand it back. We advertise TSC-deadline in
  // CPUID unconditionally and have always handled the write, so refusing the
  // read was a self-inflicted asymmetry that faulted any guest performing a
  // read-modify-write of its own deadline.
  //
  // Distinct from `timer_tsc_deadline` above, which is the ONE-SHOT/PERIODIC
  // timer's deadline in ticks and feeds CURRENT_COUNT; the two modes are
  // mutually exclusive and conflating them would make CURRENT_COUNT answer from
  // a deadline that mode does not have.
  //
  // Not carried by the async-state snapshot: the armed timer is restored from
  // `timer_deadline`, so a restored VCPU keeps firing correctly but reads this
  // register back as 0 until the guest rewrites it. Extending the snapshot is
  // W4's, and its ABI version is shared with the VMM.
  uint64_t tsc_deadline = 0;
  // The VCPU's virtual-APIC page, mapped in the kernel's physmap, or nullptr on
  // a VCPU that has not finished being created. Owned by `Vcpu::
  // virtual_apic_page_`; this is a borrowed pointer so the exit handlers, which
  // are handed only a LocalApicState, can reach it.
  //
  // The one field this hypervisor uses is VTPR at `kVirtualApicTprOffset`. The
  // processor writes it directly, without a VM exit, on every guest `MOV to
  // CR8` -- so it is guest-writable memory whose value can change between any
  // two instructions of ours, and must be read afresh each time rather than
  // cached across a VM entry.
  volatile uint32_t* virtual_apic = nullptr;
  // The TPR threshold currently programmed in the VMCS, shadowed so the common
  // path can skip a VMWRITE when nothing has changed. See
  // `local_apic_maybe_interrupt`.
  uint32_t tpr_threshold = 0;
  // How many TPR-below-threshold VM exits this VCPU has taken. The processor
  // raises one only because `local_apic_maybe_interrupt` armed the threshold, so
  // this counts the times the *hypervisor's own* instrument -- rather than an
  // incidental host interrupt -- is what noticed the guest lowering its task
  // priority. Without it, a test cannot tell a held interrupt that was released
  // by the TPR threshold apart from one released by the next timer tick, which
  // is the difference between an interrupt held for nanoseconds and one held
  // until something unrelated happens to exit.
  uint64_t tpr_below_threshold_exits = 0;
  // How many guest `MOV to CR0` writes have exited to `handle_cr0_write`.
  //
  // This counter discriminates the paging-write trap fix from its absence,
  // and it exists because nothing else does. Adding PG to CR0_GUEST_HOST_MASK is
  // invisible in every other observable: the guest reaches long mode with or
  // without it, and on a host where Cerise is itself a guest the layer below
  // repairs the VM-entry control that the missing exit failed to update -- so the
  // VMCS ends up in the same state by a different route, and every assertion
  // about the guest's mode passes either way. Measured: with the mask unfixed the
  // AP's mode-transition write does not exit and this stays 0.
  uint64_t cr0_write_exits = 0;
  // NMI-window VM exits taken by this VCPU. Zero unless a blocked NMI was
  // waiting, and zero on any part that does not offer virtual NMIs (the control
  // that produces this exit cannot be set without them, so the old
  // interrupt-window fallback is used there instead). This is what separates an
  // NMI delivered BECAUSE the guest's NMI blocking cleared from one delivered
  // because an unrelated exit happened along -- which is precisely what the
  // fallback produces, and precisely what a test cannot otherwise tell apart.
  uint64_t nmi_window_exits = 0;

  // ---- In-service register (ISR) ----
  //
  // One bit per vector: set when this APIC hands a vector to the guest, cleared
  // by the guest's EOI. This is the half of the priority model that TPR alone
  // cannot supply. Volume 3, Section 11.8.3.1 derives the processor priority
  // from *both* the task priority and the highest in-service vector, so without
  // an ISR the processor priority is only ever the task priority, and a guest
  // already inside an interrupt handler can be pre-empted by another interrupt
  // of the same priority class -- the case the architecture exists to prevent
  // and the one a Windows ISR relies on.
  //
  // Bit `v` lives in `isr[v / 32]` at bit `v % 32`, which is also the layout the
  // x2APIC ISR MSRs (0x810-0x817) expose. Tracker vectors through X86_INT_VIRT
  // are never set: exceptions and NMIs do not go through the APIC and are not
  // acknowledged with an EOI, so a bit there would never be cleared. Bare
  // interrupt vectors 21..31 are external guest ICR/device requests and do.
  uint32_t isr[8] = {};

  // ---- Registers the guest reads back ----
  //
  // Before these existed the writes were accepted and discarded and the reads
  // answered with the architectural *reset* value, so a guest that programmed
  // an LVT entry and read it back -- the read-modify-write that APIC bring-up
  // and every mask/unmask pair performs -- saw its own write vanish.
  //
  // Reset values are from Volume 3, Section 11.12.5.1: LVT entries reset masked,
  // the spurious-interrupt vector register resets to 0xff (vector 0xff, APIC
  // software-disabled).
  uint32_t svr = 0xff;
  // Writable only through the xAPIC MMIO interface. Kept outside the
  // virtual-APIC page so synchronizing dynamic registers before VM entry does
  // not overwrite values the guest programmed.
  uint32_t xapic_ldr = 0;
  uint32_t xapic_dfr = 0xffff'ffff;
  uint32_t lvt_error = LVT_MASKED;
  uint32_t lvt_lint0 = LVT_MASKED;
  uint32_t lvt_lint1 = LVT_MASKED;
  uint32_t lvt_thermal = LVT_MASKED;
  uint32_t lvt_cmci = LVT_MASKED;
  uint32_t lvt_monitor = LVT_MASKED;
  // The last value written to the 64-bit x2APIC ICR. The write is acted on when
  // it happens (see handle_ipi); this is kept only so the read-modify-write a
  // guest may perform on it does not fault. Delivery status (bit 12) is always
  // read back as 0 -- an IPI issued here has already been handed to the VMM by
  // the time the guest can read it, so it is never "send pending".
  uint64_t icr = 0;

  // ---- Instruments ----
  //
  // How many EOIs actually completed an interrupt (i.e. found a bit set in the
  // ISR and cleared it). Counted separately from EOIs that arrived with an empty
  // ISR, because "the guest EOI'd" and "the EOI ended a real in-service
  // interrupt" are what a test has to tell apart: before the ISR existed, every
  // EOI was accepted and discarded, so a test asserting only that the guest's
  // WRMSR succeeded would have passed against the broken implementation.
  uint64_t eoi_completions = 0;
  // Of those, how many were surfaced to the VMM as ZX_PKT_TYPE_GUEST_EOI because
  // the guest's VMM had registered that vector with ZX_GUEST_TRAP_EOI.
  //
  // The cost of the gate, measured rather than argued: this against
  // `eoi_completions` is the exit rate the feature actually adds, and a test can
  // assert that an unregistered vector leaves it at zero -- which is the whole
  // claim that the common path did not regress.
  uint64_t eoi_exits = 0;
  // How many times an external interrupt was held back because its priority
  // class was not above the guest's *processor* priority, and of those, how many
  // were held by an in-service interrupt rather than by the task priority alone.
  // The second counter is the one that distinguishes this model from the
  // TPR-only gate that preceded it.
  uint64_t priority_blocked = 0;
  uint64_t isr_blocked = 0;

  // ---- Lazy EOI (Hyper-V TLFS "no EOI required" VP-assist-page bit) ----
  //
  // See ZX_VCPU_STATE_LAZY_EOI's doc comment for the mechanism. State here is
  // kept to exactly what admission (`local_apic_maybe_interrupt`,
  // `Vcpu::Enter`'s pending-event block) and reconciliation
  // (`local_apic_maybe_interrupt`'s own entry) need; the guest-visible word
  // itself lives in guest memory via `lazy_eoi_guest_ptr`, not here.

  // Kernel mapping of the guest-physical word, or unset when lazy EOI is not
  // registered for this VCPU (`ZX_VCPU_STATE_LAZY_EOI` with `enabled` false,
  // or never written). Mirrors `PvClockState::guest_ptr`.
  hypervisor::GuestPtr lazy_eoi_guest_ptr;
  // The guest-physical address the word is mapped from, so
  // `Vcpu::ReadLazyEoiState` can report the configuration currently in effect
  // and so the mapping can be reconstructed if ever needed. Zero when lazy EOI
  // is not registered. Mirrors `PvClockState::guest_paddr`.
  zx_gpaddr_t lazy_eoi_guest_paddr = 0;
  // Whether a grant is currently outstanding — i.e. the word was last written
  // 1 by this kernel and has not yet been observed read back as 0 — and, if
  // so, which vector it was issued for. Reconciliation retires exactly this
  // vector (`guest_isr_clear`), never "whatever is on top of ISR now": a
  // higher-priority vector admitted before this grant is reconciled
  // overwrites `lazy_eoi_vector` (and rewrites the word to 1), which is sound
  // only because ISR nesting guarantees the guest cannot have reached the
  // superseded vector's epilogue in the meantime — see the admission sites.
  bool lazy_eoi_armed = false;
  uint32_t lazy_eoi_vector = 0;
  // How many grants this kernel issued were actually consumed by the guest
  // (word observed read back 0) and retired specifically via
  // `guest_isr_clear`, as opposed to `eoi_completions`, which counts EOIs
  // that arrived through the ordinary register-write path.
  uint64_t lazy_eoi_completions = 0;
};

// Which parts of the paravirtual surface a guest sees, and which of them the
// userspace VMM owns rather than the kernel.
//
// Everything here is off by default, so an ordinary guest keeps the kernel's own
// paravirtual surface — notably the KVM identity and the in-kernel clock that is
// discovered through it. A guest built around a different enlightenment contract
// opts in, and the VMM then answers for the parts it has claimed.
// The four output registers of a single CPUID leaf.
struct HypervCpuidLeaf {
  uint32_t eax = 0;
  uint32_t ebx = 0;
  uint32_t ecx = 0;
  uint32_t edx = 0;
};

// The Hyper-V CPUID leaves the VMM supplies, rather than the kernel: the version
// leaf, the feature and recommendation bits — which describe the synthetic
// surface the VMM has actually implemented — and the implementation limits,
// which follow from the guest's topology. None of that is knowable here. The
// identity leaves below this range are fixed and stay in the kernel.
constexpr uint32_t kHypervSuppliedLeafFirst = 0x40000002;
constexpr uint32_t kHypervSuppliedLeafLast = 0x40000005;
constexpr size_t kHypervSuppliedLeafCount =
    kHypervSuppliedLeafLast - kHypervSuppliedLeafFirst + 1;

struct VcpuEnlightenment {
  // Report the hypervisor through the 0x4000_0000 CPUID leaves as Hyper-V rather
  // than as KVM.
  bool hyperv_identity = false;
  // Contents of the VMM-supplied Hyper-V CPUID leaves, indexed by
  // (leaf - kHypervSuppliedLeafFirst). Consulted only when hyperv_identity is
  // set. All-zero is a meaningful answer — it says the VMM implements nothing
  // beyond the identity — so there is no separate "was it set" flag.
  HypervCpuidLeaf hyperv_cpuid[kHypervSuppliedLeafCount];
  // Surface accesses to the synthetic MSR block to the VMM instead of faulting
  // them, so it can implement the synthetic registers the guest expects.
  bool delegate_synthetic_msrs = false;
  // Surface hypercalls to the VMM instead of servicing them in the kernel.
  bool delegate_hypercalls = false;
};

// What this VCPU has seen of guest RDMSR/WRMSR accesses this hypervisor does not
// implement.
//
// An unhandled access is answered with an injected #GP, and a guest that did not
// expect one rarely dies at the RDMSR: it dies later, somewhere unrelated, with
// the cause already off the stack. Two fatal gaps of exactly this shape have
// been found in this tree by crashing into them and reconstructing the cause
// afterwards — RDMSR 0x10 (IA32_TSC) and WRMSR 0x1a0 (IA32_MISC_ENABLE), both of
// which took a whole Windows boot down. So each unhandled access now announces
// itself, and says the three things needed to act on it: which register, at
// which guest RIP, in which direction — plus whether the #GP was really queued,
// because "we faulted the guest" and "we tried to and could not" are different
// bugs.
//
// Rate safety is deliberate in both directions, because both failures have cost
// this project time. The *first* access to any given register is always logged,
// at a print level no build configuration can compile out: a limiter that drops
// the first occurrence hides exactly the line worth having. Repeats of a
// register already announced are logged on a power-of-two backoff, so a guest
// polling one register in a loop costs a logarithmic number of lines rather than
// drowning the boot — and the count in each line says how many were skipped, so
// nothing is silently discarded.
struct UnhandledMsrLog {
  // How many distinct registers get their own backoff counter. Past this, a
  // register that has never been seen is counted in `overflow` instead; a guest
  // touching more than this many unimplemented registers has a bigger problem
  // than log fidelity.
  static constexpr size_t kMaxTracked = 16;
  struct Entry {
    uint32_t msr = 0;
    uint64_t count = 0;
  };
  Entry entries[kMaxTracked] = {};
  size_t tracked = 0;
  // Accesses to registers that first appeared after `entries` filled up.
  uint64_t overflow = 0;

  // Every unhandled access, and the most recent one in full. Exposed (via
  // Vcpu::UnhandledMsrs) so a test can assert that the announcement carries the
  // register, the guest RIP and the fault — an instrument whose only output is a
  // log line cannot be shown to be measuring anything.
  uint64_t total = 0;
  uint32_t last_msr = 0;
  uint64_t last_rip = 0;
  // The value a WRMSR was trying to write (edx:eax); 0 for a read.
  uint64_t last_value = 0;
  bool last_is_write = false;
  // Whether the #GP was actually queued for delivery. False means the guest was
  // not even told its access failed.
  bool last_gp_injected = false;
};

// What this VCPU has seen of guest I/O to ports no VMM claimed.
//
// I/O exiting here is unconditional (`kProcbasedCtlsIoExiting`) rather than
// bitmap-driven, so EVERY port access the guest makes takes a VM exit and any
// port the VMM did not register used to return ZX_ERR_NOT_FOUND and kill the
// guest. Firmware and Windows both touch ports outside the Gen2 set -- 0x80, the
// classic post/delay port, is the one everybody hits -- so this was reachable on
// an ordinary boot.
//
// The default is now what an unclaimed port does on a PC: the bus is not driven,
// a read floats to all-ones, a write goes nowhere. THAT DEFAULT IS DANGEROUS ON
// ITS OWN, and the danger is specific and has bitten this project three times: a
// read of all-ones has every "ready", "present" and "done" bit SET, so a device
// that is not there looks like a device that is working perfectly. The whole
// point of this structure is that the default is never silent. Every distinct
// port announces itself the first time, at a print level no build can compile
// out, and repeats back off by powers of two -- the same shape as
// UnhandledMsrLog, for the same reason.
struct UnhandledIoLog {
  // Distinct ports that get their own backoff counter; past this, a port that
  // has never been seen is counted in `overflow`.
  static constexpr size_t kMaxTracked = 16;
  struct Entry {
    uint16_t port = 0;
    uint64_t count = 0;
  };
  Entry entries[kMaxTracked] = {};
  size_t tracked = 0;
  uint64_t overflow = 0;

  // Every defaulted access, split by direction. Reads are the ones that can
  // mislead a guest (see above); writes are merely dropped.
  uint64_t total = 0;
  uint64_t reads = 0;
  uint64_t writes = 0;
  uint16_t last_port = 0;
  uint64_t last_rip = 0;
  uint8_t last_access_size = 0;
  bool last_is_read = false;
  // What the guest was handed for the last defaulted read (all-ones, sized), or
  // what it tried to write. Exposed so a test can assert the value really is the
  // float-high answer rather than a zero that happens to look harmless.
  uint64_t last_value = 0;
};

// Stores the para-virtualized clock for a virtual CPU.
//
// System time is time since boot time, and boot time is some fixed point in the
// past.
struct pv_clock_system_time;
struct PvClockState {
  bool is_stable = false;
  uint32_t version = 0;
  pv_clock_system_time* system_time = nullptr;
  hypervisor::GuestPtr guest_ptr;
  // Guest-physical address the pv-clock system-time structure is mapped from
  // (the value the guest wrote to the paravirtual system-time MSR, without the enable
  // bit). Retained so the mapping can be reconstructed on snapshot restore.
  // Zero when the clock is stopped.
  zx_paddr_t guest_paddr = 0;
};

// Architectural execution state of a VCPU, captured for save/restore (the
// foundation for VM snapshotting). This is the state needed to resume a guest
// deterministically from a captured point. It currently covers the general
// registers, RSP, RFLAGS, and — unlike the public zx_vcpu_state_t surface — the
// instruction pointer, without which a VCPU cannot be restored to where it was
// executing. Control/segment/MSR state is layered on as guests that mutate them
// are exercised.
// One segment/descriptor register's cached state.
struct VcpuSegmentState {
  uint16_t selector;
  uint64_t base;
  uint32_t limit;
  uint32_t access_rights;
};

// The complete architectural state of a VCPU, in a flat POD form suitable for
// serialization (save/restore, e.g. a VM snapshot to disk). It draws from every
// place the hypervisor keeps guest state: the VMCS, the VCPU's saved general
// and MSR state, and its extended (XSAVE) register area.
//
// This is the complete guest-state area the hypervisor's (expanded) VMCS field
// set exposes, plus the general/MSR/extended state kept alongside it.
struct VcpuArchState {
  // General registers (+ RSP and user RFLAGS) and the instruction pointer.
  zx_vcpu_state_t regs;
  uint64_t rip;

  // Control / mode / debug state.
  uint64_t cr0;
  uint64_t cr2;
  uint64_t cr3;
  uint64_t cr4;
  uint64_t efer;
  uint64_t xcr0;
  uint64_t pat;
  uint64_t dr[4];
  uint64_t dr6;
  uint64_t dr7;
  uint64_t debugctl;
  uint64_t pending_debug_exceptions;

  // The guest's task-priority register: VTPR bits 7:0, taken from this VCPU's
  // virtual-APIC page. This is the register `MOV to CR8` writes and `MOV from
  // CR8` reads -- with "use TPR shadow" set and CR8-load/store exiting clear the
  // processor services both entirely on its own, so this page is the only place
  // the guest's task priority exists. On x64 Windows that register is IRQL.
  //
  // It belongs here, with RIP, rather than in VcpuAsyncState: it is a quiescent
  // register written straight back on restore, not a live kernel object to be
  // reconstructed. And it has to travel with RIP or a snapshot is not a
  // snapshot. A guest captured inside a raised-IRQL region and restored without
  // this field resumes at the captured instruction with its interrupt gate wide
  // open, and takes an ISR inside precisely the region the raise exists to
  // exclude. Every restore is affected, not only a guest that reads CR8 back.
  //
  // Bits 31:8 of the VTPR field are reserved. A restore that sets them is
  // refused rather than masked -- see Vcpu::RestoreArchState, which also states
  // what the *processor* does with this value on the way into the guest.
  uint32_t tpr;

  // Segment and descriptor-table registers (selector/base/limit/access).
  VcpuSegmentState es, cs, ss, ds, fs, gs, tr, ldtr;
  uint64_t gdtr_base;
  uint32_t gdtr_limit;
  uint64_t idtr_base;
  uint32_t idtr_limit;

  // SYSENTER and delivery state.
  uint32_t sysenter_cs;
  uint64_t sysenter_esp;
  uint64_t sysenter_eip;
  uint32_t interruptibility_state;
  uint32_t activity_state;

  // Note: the in-kernel local APIC (LVT-timer configuration, the pending-
  // interrupt set) and the paravirtualized clock are deliberately NOT here.
  // They are not quiescent registers to be written back but live kernel objects
  // that must be *reconstructed*, so they live in VcpuAsyncState below. Holding
  // them in both places would give restore two sources of truth that could
  // disagree.

  // Syscall and related MSRs (from the VCPU's saved MSR state).
  uint64_t star;
  uint64_t lstar;
  uint64_t cstar;
  uint64_t fmask;
  uint64_t tsc_aux;
  uint64_t kernel_gs_base;

  // Extended (FPU / SSE / AVX / ...) register state: the XSAVE area.
  uint8_t xsave[X86_MAX_EXTENDED_REGISTER_SIZE];
};

// Serialization of a captured VcpuArchState to/from a flat, self-describing byte
// buffer: a small header ([magic][version][payload size]) followed by the state
// bytes. SerializedVcpuStateSize() is the exact buffer length required.
// Deserialize validates the header and rejects a mismatched magic/version/size.
size_t SerializedVcpuStateSize();
zx::result<> SerializeVcpuState(const VcpuArchState& state, uint8_t* buffer, size_t len);
zx::result<> DeserializeVcpuState(VcpuArchState& state, const uint8_t* buffer, size_t len);

// Asynchronous / device-facing execution state of a VCPU, captured for
// save/restore alongside VcpuArchState. Where VcpuArchState is the quiescent
// architectural register file, this is the state the hypervisor holds in live
// helper objects — the in-kernel local APIC (its timer and pending-interrupt
// set) and the paravirtualized clock — reduced to a flat POD form. The live
// objects (Timer, GuestPtr, InterruptTracker) are never serialized directly;
// their *configuration* is captured here and they are reconstructed on restore.
struct VcpuAsyncState {
  // Local-APIC timer configuration (see LocalApicState).
  uint32_t lvt_timer;
  uint32_t lvt_initial_count;
  uint32_t lvt_divide_config;
  // Whether the APIC timer was armed at capture and, if so, how long until it
  // fires. Captured as a *remaining duration* rather than an absolute deadline,
  // so restore re-anchors it to the clock at restore time instead of firing on
  // a stale — possibly long-past — absolute deadline.
  uint8_t timer_armed;
  uint64_t timer_remaining_ns;

  // Pending-interrupt bitmap: one bit per interrupt vector, LSB-first within
  // each byte. Mirrors the local-APIC InterruptTracker's pending set.
  uint8_t pending_interrupts[(X86_INT_COUNT + 7) / 8];

  // In-service-register (ISR) bitmap: the local-APIC ISR, one bit per vector
  // (word `v/32`, bit `v%32`), mirroring LocalApicState::isr. This is NOT the
  // pending set above: pending is what is waiting to be delivered, ISR is what
  // has been delivered and not yet EOIed. It is load-bearing for priority — a
  // guest ISR runs at the processor priority its ISR bit implies (see
  // guest_ppr / guest_isrv) and blocks same/lower-class interrupts until it
  // EOIs. It matters especially for an interrupted external-interrupt
  // vectoring event: delivery aborted with the ISR bit already set, and direct
  // reinjection assumes the bit survived. Without capturing it, a restored
  // guest loses in-service state — admitting interrupts it should be masking
  // (priority inversion) and, from a discarded timeline, leaving stale ISR bits
  // that wedge later interrupts. Vectors 0..X86_INT_VIRT are never set
  // (exceptions and NMIs are not APIC-acknowledged), but bare interrupt vectors
  // 21..31 (X86_INT_VIRT+1 .. X86_INT_MAX_INTEL_DEFINED) legitimately enter
  // service as guest ICR/device vectors, so word 0 may carry those bits.
  uint32_t isr[(X86_INT_COUNT + 31) / 32];

  // Paravirtualized clock.
  uint8_t pv_clock_enabled;    // clock currently mapped into guest memory
  uint8_t pv_clock_is_stable;  // guest sees the clock as monotonic-stable
  uint32_t pv_clock_version;
  uint64_t pv_clock_guest_paddr;
};

// Serialization of a captured VcpuAsyncState, using the same self-describing
// [magic][version][payload size] framing as VcpuState above (with a distinct
// magic). SerializedVcpuAsyncStateSize() is the exact buffer length required.
size_t SerializedVcpuAsyncStateSize();
zx::result<> SerializeVcpuAsyncState(const VcpuAsyncState& state, uint8_t* buffer, size_t len);
zx::result<> DeserializeVcpuAsyncState(VcpuAsyncState& state, const uint8_t* buffer, size_t len);

// Represents a virtual CPU within a guest.
class Vcpu {
 public:
  static zx::result<ktl::unique_ptr<Vcpu>> Create(Guest& guest, zx_vaddr_t entry,
                                                  uint32_t options = 0);

  Vcpu(const Vcpu&) = delete;
  Vcpu(Vcpu&&) = delete;
  Vcpu& operator=(const Vcpu&) = delete;
  Vcpu& operator=(Vcpu&&) = delete;

  virtual ~Vcpu();

  zx::result<> Enter(zx_port_packet_t& packet);
  void Kick();
  zx::result<> Interrupt(uint32_t vector);
  zx::result<> ReadState(zx_vcpu_state_t& vcpu_state);
  zx::result<> WriteState(const zx_vcpu_state_t& vcpu_state);
  zx::result<> WriteState(const zx_vcpu_io_t& io_state);

  // Snapshot / restore the architectural execution state (VcpuArchState),
  // including RIP, so a guest can be resumed deterministically from a captured
  // point. Both must run on the VCPU's own thread.
  zx::result<> SaveArchState(VcpuArchState& out);
  zx::result<> RestoreArchState(const VcpuArchState& in);

  // Snapshot / restore the asynchronous state (VcpuAsyncState): the in-kernel
  // local-APIC timer + pending interrupts and the paravirtualized clock. The
  // live Timer / GuestPtr are reconstructed from captured configuration rather
  // than copied. Both must run on the VCPU's own thread.
  zx::result<> SaveAsyncState(VcpuAsyncState& out);
  zx::result<> RestoreAsyncState(const VcpuAsyncState& in);

  // The guest's TSC, as the guest reads it, is the host's TSC plus this offset
  // (VMCS TSC_OFFSET, 0x2010, with the "use TSC offsetting" primary control).
  // Zero by default, which is exactly the pre-existing behaviour: the guest reads
  // the host's raw counter.
  //
  // Every guest-visible reading of the TSC honours it -- hardware RDTSC/RDTSCP
  // because the processor applies the field, and RDMSR of
  // IA32_TIME_STAMP_COUNTER, IA32_TSC_DEADLINE and the paravirtual clock's
  // timestamps because the kernel adds or subtracts it there. Host-internal uses
  // of the TSC (the APIC timer's tick deadline, for instance) are host-TSC
  // deltas and are deliberately untouched.
  //
  // NOT IN THE SNAPSHOT ABI. VcpuArchState does not carry it, so a restored VCPU
  // starts at zero whatever the saved one was using; see the note in
  // Vcpu::Setup for why the default is zero until it does. Must run on the
  // VCPU's own thread. Returns ZX_ERR_NOT_SUPPORTED where the part does not
  // offer TSC offsetting, which is a real possibility under nested VMX.
  int64_t TscOffset() const { return tsc_offset_; }
  zx::result<> SetTscOffset(int64_t offset);

  // Non-destructively reports whether |vector| is pending in the local-APIC
  // interrupt tracker. Exposed to let snapshot save/restore be validated (and
  // for a future userspace VMM to observe pending state).
  bool InterruptPending(uint32_t vector);

  // Enable/disable trapping of guest breakpoint exceptions (#BP / INT3) to the
  // host. When enabled, a guest INT3 causes a VM exit that Enter() surfaces as a
  // ZX_PKT_TYPE_GUEST_EXCEPTION packet instead of being delivered to the guest
  // IDT — the substrate for VMM-planted software breakpoints (e.g. coverage).
  zx::result<> SetBreakpointTrapping(bool enable);

  // Read or atomically replace host-assisted debug controls. Host support is
  // derived from the VMX control MSRs for this processor; a known but
  // unavailable flag is refused without changing either the exception bitmap
  // or the primary execution controls. SINGLE_STEP is implemented with the
  // monitor-trap flag and is cleared by the VM-exit handler before its
  // guest-exception packet is returned.
  zx::result<> ReadDebugState(zx_vcpu_debug_state_t& out);
  zx::result<> WriteDebugState(const zx_vcpu_debug_state_t& in);

  // Read or atomically replace host-assisted bounded-run controls. The VMX
  // preemption timer is one-shot and reports its host-derived TSC-rate shift.
  zx::result<> ReadRunControl(zx_vcpu_run_control_t& out);
  zx::result<> WriteRunControl(const zx_vcpu_run_control_t& in);

  // Read or atomically acknowledge/replace one-shot post-handler VM-exit
  // controls. This is a software-only boundary: it does not alter VMCS
  // controls, and when unarmed the entry loop only takes a cached false branch.
  zx::result<> ReadExitControl(zx_vcpu_exit_control_t& out);
  zx::result<> WriteExitControl(const zx_vcpu_exit_control_t& in);

  // Read, acknowledge, or arm a runtime-reserved guest-only fixed
  // retired-instruction budget.
  zx::result<> ReadInstructionControl(zx_vcpu_instruction_control_t& out);
  zx::result<> WriteInstructionControl(const zx_vcpu_instruction_control_t& in);

  // Read or atomically acknowledge/replace guest-global EPT-backed
  // guest-physical memory-access stops.
  zx::result<> ReadMemoryAccessControl(zx_vcpu_memory_access_control_t& out);
  zx::result<> WriteMemoryAccessControl(const zx_vcpu_memory_access_control_t& in);

  // Typed raw Intel PT configuration and bounded immutable cursor reads.
  zx::result<> ReadIntelPtControl(zx_vcpu_intel_pt_control_t& out);
  zx::result<> WriteIntelPtControl(const zx_vcpu_intel_pt_control_t& in);

  // Transparent DR0-DR3 instruction/data breakpoints with exact one-shot
  // acknowledgement.
  zx::result<> ReadHardwareBreakpointControl(
      zx_vcpu_hardware_breakpoint_control_t& out);
  zx::result<> WriteHardwareBreakpointControl(
      const zx_vcpu_hardware_breakpoint_control_t& in);

  // Present the hypervisor to this guest as Hyper-V ("Microsoft Hv") instead of
  // the default KVM identity, via the 0x4000_0000 CPUID leaves. Off by default,
  // so ordinary guests keep the KVM identity (and its in-kernel pvclock). A
  // Hyper-V-enlightened guest (e.g. Windows) sets this so it takes its Hyper-V
  // path. What that identity then advertises is supplied through
  // SetHypervCpuidLeaf; the MSR and hypercall surface it describes is delegated
  // separately.
  zx::result<> SetHypervIdentity(bool enable);

  // Supply the contents of one Hyper-V CPUID leaf, which must be in
  // [kHypervSuppliedLeafFirst, kHypervSuppliedLeafLast]. These leaves state
  // which synthetic facilities exist and how large the partition is, so only the
  // VMM implementing that surface can answer them; the kernel would otherwise
  // have to guess. They are static for a given VM, so the VMM sets them once at
  // setup rather than answering an exit on every CPUID — which a guest executes
  // often while booting.
  //
  // The values take effect only under SetHypervIdentity: without it the guest is
  // being shown the KVM identity, for which these leaves mean nothing.
  zx::result<> SetHypervCpuidLeaf(uint32_t leaf, const HypervCpuidLeaf& values);

  // Hand the synthetic MSR block (0x4000_0000-0x4000_ffff) to the VMM: an access
  // there surfaces as a ZX_PKT_TYPE_GUEST_MSR packet instead of faulting the
  // guest, which is how the VMM implements the synthetic registers an
  // enlightened guest expects. Off by default, and deliberately scoped to that
  // block so the registers the kernel already models — the local APIC, the
  // in-kernel clock, the timer deadline — keep their existing behavior.
  zx::result<> SetMsrDelegation(bool enable);

  // Hand hypercalls to the VMM: a guest hypercall surfaces as a
  // ZX_PKT_TYPE_GUEST_HYPERCALL packet carrying the guest's operands, rather
  // than being serviced against the kernel's own hypercall set. Off by default.
  zx::result<> SetHypercallDelegation(bool enable);

  // The userspace-facing form of the four setters above: apply (or report) the
  // whole paravirtual configuration in one self-describing structure, which is
  // what the ZX_VCPU_STATE_ENLIGHTENMENT topic of zx_vcpu_write_state() /
  // zx_vcpu_read_state() carries.
  //
  // WriteEnlightenment validates the entire structure — identity, version and
  // size; that no unknown flag or reserved field is set; and that every
  // synthetic CPUID leaf named is one this kernel lets a VMM supply — *before*
  // applying any of it, so a rejected write leaves the VCPU untouched rather
  // than half-configured. It replaces the configuration wholesale: a capability
  // whose flag is absent is turned off, and a leaf that is not listed is
  // cleared. Both must run on the VCPU's own thread, like the setters they wrap.
  zx::result<> WriteEnlightenment(const zx_vcpu_enlightenment_t& in);
  zx::result<> ReadEnlightenment(zx_vcpu_enlightenment_t& out);

  // Queue an exception for delivery to the guest on the next Enter(), vectoring
  // through the guest IDT. Used to pass a guest's *own* breakpoint back to it
  // after the VMM decides a trapped #BP is not one of its instrumentation
  // points. `instruction_length` (1 for INT3) sets the software-exception return
  // RIP (GUEST_RIP + length). Fails if an event injection is already pending.
  zx::result<> InjectException(uint32_t vector, uint32_t instruction_length);

  // The userspace-facing form of the above: queue (or report) a fully specified
  // event — VMX interruption type, vector, error code and, for #PF, CR2 — which
  // is what the ZX_VCPU_STATE_PENDING_EVENT topic of zx_vcpu_write_state() /
  // zx_vcpu_read_state() carries. This is what lets a VMM that emulated a
  // faulting instruction tell the guest what actually went wrong, rather than
  // handing it a #GP or #PF with a zero error code.
  //
  // WritePendingEvent validates the whole structure — identity, version and
  // size; that the type is one this kernel delivers; that the vector is in the
  // range that type allows; that an error code is present exactly when the
  // vector architecturally has one, and CR2 exactly for #PF; that an
  // instruction length is present exactly for a software exception; and that
  // the guest is in a mode that can take the event at all — *before* queueing
  // any of it. A rejected write leaves nothing queued, so userspace cannot
  // build an interruption-information field that VM entry would refuse (which
  // surfaces as an opaque entry failure, not as an error the caller can act
  // on). It replaces the queue wholesale; ZX_VCPU_EVENT_NONE clears it. Both
  // must run on the VCPU's own thread, like every other state accessor.
  zx::result<> WritePendingEvent(const zx_vcpu_pending_event_t& in);
  zx::result<> ReadPendingEvent(zx_vcpu_pending_event_t& out);

  // The interrupted-delivery (VMCS IDT-vectoring) event owed re-injection on the
  // next entry. Distinct from the pending event: both can be outstanding at
  // once. Write validates the whole structure before applying any of it and
  // rejects anything the capture path would never produce; `valid == 0` clears
  // it. Both run on the VCPU's own thread, like every other state accessor.
  zx::result<> WriteVectoringEvent(const zx_vcpu_vectoring_event_t& in);
  zx::result<> ReadVectoringEvent(zx_vcpu_vectoring_event_t& out);

  // Captures the guest TSC anchor and armed IA32_TSC_DEADLINE, and on write
  // re-anchors the VMCS TSC_OFFSET so the guest reads back the supplied guest
  // TSC and re-derives the armed deadline through the new offset. See
  // ZX_VCPU_STATE_TSC. Both run on the VCPU's own thread.
  zx::result<> WriteTscState(const zx_vcpu_tsc_state_t& in);
  zx::result<> ReadTscState(zx_vcpu_tsc_state_t& out);

  // Completes one userspace-decoded xAPIC MMIO access against this VCPU's
  // in-kernel local-APIC state. Write submits and executes the access; read
  // retrieves its value and any EOI/IPI side effect.
  zx::result<> WriteXapicAccess(const zx_vcpu_xapic_access_t& in);
  zx::result<> ReadXapicAccess(zx_vcpu_xapic_access_t& out);

  // The userspace-facing form of the lazy-EOI mechanism, carried by the
  // ZX_VCPU_STATE_LAZY_EOI topic. See that topic's doc comment for the
  // mechanism and this kernel's exact obligations.
  //
  // WriteLazyEoiState validates identity, version and size, and that every
  // field not meaningful for the given `enabled` is zero, before applying
  // anything. It (re)creates or releases the guest-physical mapping and
  // always leaves the word, and this VCPU's own bookkeeping, in the
  // "no grant outstanding" state -- including when the write is a snapshot
  // restore, which is the conservative posture ZX_VCPU_STATE_LAZY_EOI
  // documents. Must run on the VCPU's own thread.
  zx::result<> WriteLazyEoiState(const zx_vcpu_lazy_eoi_state_t& in);
  zx::result<> ReadLazyEoiState(zx_vcpu_lazy_eoi_state_t& out);

  // The userspace-facing form of the TLB-flush primitive, carried by the
  // ZX_VCPU_STATE_TLB_FLUSH topic. See that topic's doc comment for the
  // mechanism. UNLIKE every other state accessor on this class, both of these
  // are deliberately safe to call from any thread -- the same exception
  // `Interrupt()` and `InterruptPending()` below already carry -- so a
  // hypercall handler running on a different VCPU's thread can mark this one
  // pending without a thread hop.
  zx::result<> WriteTlbFlushState(const zx_vcpu_tlb_flush_state_t& in);
  zx::result<> ReadTlbFlushState(zx_vcpu_tlb_flush_state_t& out);

  // Read-only per-VCPU EOI accounting, carried by ZX_VCPU_STATE_EXIT_COUNTERS.
  // Also safe from any thread (it copies two cumulative diagnostic counters);
  // a cross-thread read may be a tick stale, which is fine for a heartbeat.
  zx::result<> ReadExitCounters(zx_vcpu_exit_counters_t& out);

  // Read-only per-VCPU software-LAPIC snapshot, carried by ZX_VCPU_STATE_LAPIC.
  // Diagnostics; safe from any thread (a cross-thread read may be a tick stale).
  zx::result<> ReadLapicState(zx_vcpu_lapic_state_t& out);

  zx_info_vcpu_t GetInfo() const;

  // What this VCPU has seen of events aborted mid-delivery: how many it has put
  // back, and the raw evidence for the most recent one. Exposed so a test can
  // tell "the event survived because it was re-injected" apart from "the event
  // was never lost in this setup" — without it, a delivery test passes either
  // way — and so it can assert on the processor's own account of what happened
  // rather than inferring it.
  struct VectoringStats {
    // Events recovered from the IDT-vectoring information field and re-injected.
    uint64_t reinjections = 0;
    // Events recovered from that field which the guest could not take on the
    // entry that followed -- RFLAGS.IF clear, or blocking by STI/MOV-SS/NMI --
    // and which were therefore re-queued into the interrupt tracker instead of
    // being forced into a VM entry that would have failed. Counted separately
    // from `reinjections` so a test can tell "deferred, and delivered later"
    // apart from both "injected straight away" and "dropped".
    uint64_t deferrals = 0;
    // Raw IDT-vectoring information field of the most recent exit that carried
    // one: bit 31 valid, bits 10:8 type, bits 7:0 vector, bit 11 error code.
    uint32_t last_info = 0;
    // Basic exit reason of that exit — the *fault's* reason, not the event's.
    uint32_t last_exit_reason = 0;
    // GUEST_PHYSICAL_ADDRESS at that exit; the address the interrupted delivery
    // was touching, when the exit was an EPT violation.
    uint64_t last_exit_gpa = 0;
  };
  const VectoringStats& Vectoring() const { return vectoring_; }

  // The host-physical address of this VCPU's virtual-APIC page — the page the
  // processor reads and writes for `MOV to/from CR8` while "use TPR shadow" is
  // set. Exposed so a test can assert that it is programmed at all, and that no
  // two VCPUs share one; before this page existed the VMCS field was never
  // written, read back as zero, and every VCPU on the machine therefore used
  // host-physical page 0 as its virtual-APIC page.
  zx_paddr_t VirtualApicAddress() const {
    return virtual_apic_page_.IsAllocated() ? virtual_apic_page_.PhysicalAddress() : 0;
  }

  // The guest's task-priority register (VTPR bits 7:0) as the processor last
  // left it. This is the register `MOV to CR8` writes, so it is the guest's own
  // account of its interrupt priority — on Windows, its IRQL. Read from the
  // virtual-APIC page, not from any hypervisor-side shadow.
  uint32_t TaskPriority() const;

  // How many TPR-below-threshold VM exits this VCPU has taken. See
  // LocalApicState::tpr_below_threshold_exits: this is the count of times the
  // hypervisor's own instrument for "the guest lowered its task priority" fired,
  // which is what separates an interrupt released promptly by that instrument
  // from one that merely happened to be re-examined on the next unrelated exit.
  uint64_t TprBelowThresholdExits() const;

  // The guest's processor priority (PPR), derived from its task priority and its
  // highest in-service vector exactly as Volume 3, Section 11.8.3.1 defines it.
  // This -- not the task priority -- is what gates an external interrupt.
  uint32_t ProcessorPriority() const;

  // The highest vector currently in service, or 0 if none is. Generated
  // exceptions and the NMI never enter the ISR, so 0 is unambiguous.
  uint32_t InServiceVector() const;

  // Whether |vector| is in service: handed to the guest by this APIC and not yet
  // acknowledged with an EOI.
  bool InService(uint32_t vector) const;

  // How many EOIs completed a real in-service interrupt. See
  // LocalApicState::eoi_completions -- an EOI that is accepted and discarded,
  // which is what this hypervisor used to do with every one of them, does not
  // count here.
  uint64_t EoiCompletions() const;

  // How many of those were surfaced to the VMM as ZX_PKT_TYPE_GUEST_EOI. See
  // LocalApicState::eoi_exits.
  uint64_t EoiExits() const;

  // How many external interrupts were held back by the guest's processor
  // priority, and how many of those were held by an in-service interrupt rather
  // than by the task priority alone.
  uint64_t PriorityBlocked() const;
  uint64_t IsrBlocked() const;

  // Test/inspection accessors for lazy EOI. See LocalApicState's lazy_eoi_*
  // fields.
  bool LazyEoiArmed() const;
  uint32_t LazyEoiVector() const;
  uint64_t LazyEoiCompletions() const;

  // INERT. This existed to defeat a "virtual-interrupt delivery" gate in
  // `WriteLazyEoiState` that made the grant path unreachable in a unit test.
  // That gate is GONE -- lazy EOI ships active, the grant is established
  // unconditionally, and `WriteLazyEoiState` only `(void)`-casts the flag this
  // sets. It is retained solely so the existing tests that call it keep
  // compiling; setting it changes NOTHING about this VCPU's behaviour, and a
  // test that calls it is exercising the ordinary production path.
  void ForceLazyEoiGrantForTest() { lazy_eoi_test_force_grant_ = true; }

  // What this VCPU has seen of guest MSR accesses it does not implement. See
  // UnhandledMsrLog: an unhandled access is a #GP the guest did not ask for, and
  // is usually fatal somewhere else entirely, so each one is announced. This is
  // the machine-readable half of that announcement.
  const UnhandledMsrLog& UnhandledMsrs() const { return unhandled_msr_log_; }

  // What this VCPU has seen of guest I/O to ports no VMM registered. See
  // UnhandledIoLog: those accesses no longer kill the guest, and the answer they
  // get back is the one that makes absent hardware look healthy, so the
  // announcement is the only thing standing between a defaulted port and a
  // silent misdiagnosis.
  const UnhandledIoLog& UnhandledIo() const { return unhandled_io_log_; }

  // Host NMIs that arrived while this VCPU was in VMX non-root operation,
  // and were re-dispatched to the host's own handler instead of killing the
  // guest. Zero is the normal value; it moves only when something NMIs this CPU
  // during guest execution, which in this kernel means `k cpu context`.
  uint64_t HostNmisRedispatched() const { return host_nmis_redispatched_; }

  // Guest `MOV to CR0` writes that exited to the hypervisor. See
  // LocalApicState::cr0_write_exits for why this is the only observable that
  // separates a mode transition the hypervisor saw from one it did not.
  uint64_t Cr0WriteExits() const { return local_apic_state_.cr0_write_exits; }

  // NMI-window VM exits. See LocalApicState::nmi_window_exits.
  uint64_t NmiWindowExits() const { return local_apic_state_.nmi_window_exits; }

  // The VM-entry and pin-based controls currently programmed in this
  // VCPU's VMCS, read back from the VMCS itself.
  //
  // This exists because the mode a VCPU is in and the controls that describe
  // that mode are two different facts, and only the second one can be wrong
  // without the guest noticing immediately. A guest that turns on paging
  // unobserved reaches long mode either way; what differs is whether the
  // IA-32e-mode-guest VM-entry control was brought along with it, and nothing
  // the guest can execute reveals that. Loads this VCPU's VMCS, so it must be
  // called on the VCPU's own thread -- ZX_ERR_BAD_STATE otherwise.
  zx::result<uint32_t> EntryControls();
  zx::result<uint32_t> PinbasedControls();

 private:
  friend class Guest;

  // Reads the IDT-vectoring information field, which records an event that was
  // being delivered through the guest IDT when the VM exit occurred, and stashes
  // it for re-injection. Must run before the exit handler, which may invalidate
  // the AutoVmcs (handle_ept_violation does, so that it can block).
  void CaptureVectoringEvent(AutoVmcs& vmcs);
  Vcpu(Guest& guest, uint16_t vpid, Thread* thread);

  void Migrate(Thread* thread, Thread::MigrateStage stage)
      TA_REQ(chainlock_transaction_token, thread->get_lock());
  void ContextSwitch(bool include_gs);
  // No AutoVmcs parameter: which XCR0 and which buffer are swapped is now
  // decided entirely by x86_xsave_supported(), with nothing read from the VMCS.
  // See the comment in Vcpu::LoadExtendedRegisters.
  void LoadExtendedRegisters();
  void SaveExtendedRegisters();

  // Puts the host's XCR0 and extended-register file back before this VCPU's
  // thread loses the CPU.
  //
  // Called from the thread's context-switch callback, which `Scheduler::
  // RescheduleCommon` invokes for both the outgoing and the incoming thread.
  // `xstate_loaded_` makes it self-disambiguating: it is set only while this
  // thread is running with the guest's state installed, so when this VCPU's
  // thread is the *incoming* one the flag is already clear and this is a no-op.
  //
  // Deliberately one-directional. The syscall MSRs next to it in that callback
  // are swapped symmetrically because nothing else touches them; the extended
  // registers cannot be, because `arch_context_switch()` XSAVE/XRSTORs them
  // itself, *after* the callback runs. Restoring the guest's here on the way in
  // would save the outgoing thread's registers into this thread's buffer and
  // then be overwritten anyway. The guest's state is reloaded instead at the
  // next VM entry, in `Enter()`, where interrupts and preemption are off.
  void SwapExtendedRegistersOut();

  // Installs the guest's XCR0 on the physical register when a guest XSETBV has
  // changed it since its extended state was loaded, cycling the register file
  // through the guest's own buffer so newly enabled components are initialized
  // rather than inherited from whoever ran last. Must be called with the guest's
  // extended state loaded, from inside the AutoVmcs that brackets VM entry.
  void ReconcileGuestXcr0();

  // Some explanation is required for why we disable static lock analysis here.
  // `thread_` is initially set during our construction in a context where the
  // caller guarantees that `thread_`'s instance cannot exit.  After this, there
  // will only ever be one more assignment made to this variable, when the thread
  // exits and calls the registered migration function.  This happens with the
  // global Thread list_lock held, and is what is used to make sure that the
  // thread cannot exit out from under us during operations like Kick and
  // Interrupt.
  //
  // There are many other places in the code, however, where the code simply
  // wants to check to see the calling thread is the same as `thread_`.  There
  // are only two options here.
  //
  // 1) The calling thread (A) is not the same as thread as our thread.  If our
  //    initial thread was B, then thread_ can only ever have two values; either B
  //    or nullptr.  A will never match, regardless of whether or not B has
  //    exited or not yet.  We need the `thread_` member to be atomic in order
  //    to avoid a formal C++ data race, but nothing more.
  // 2) The calling thread (A) *is* the same as our thread.  This means that our
  //    thread is currently running, and cannot exit out from under us.  We
  //    don't even need the atomic load in this case, since it is A who will
  //    eventually perform the mutation setting thread_ to nullptr, so no
  //    concurrent write is possible.
  //
  // In either case, we don't actually need to hold the Thread::list_lock_ in
  // order to simply check to see if a calling thread is our thread.  All we
  // need is a relaxed atomic load to deal with case 1 (above).
  //
  bool ThreadIsOurThread(Thread* thread) const TA_NO_THREAD_SAFETY_ANALYSIS {
    // TODO(https://fxbug.dev/355287217): Remove workaround for const/volatile qualified atomic_ref.
    return thread ==
           ktl::atomic_ref{const_cast<Vcpu*>(this)->thread_}.load(ktl::memory_order_relaxed);
  }

  // Drops all one-shot instruction-budget state. PMU ownership is released
  // immediately unless an already-raised PMI still needs its EOI, in which
  // case the PMU layer completes the release from the interrupt handler.
  void ResetInstructionControl();
  void ResetIntelPtControl();
  zx::result<> ActivateHardwareBreakpointControl(AutoVmcs& vmcs);
  zx::result<> DeactivateHardwareBreakpointControl(AutoVmcs& vmcs);
  zx::result<> HandleHardwareBreakpointMovDr(AutoVmcs& vmcs);
  zx::result<bool> HandleHardwareBreakpointDebugExit(
      AutoVmcs& vmcs, uint64_t raw_dr6, zx_port_packet_t& packet);
  void InterruptCpu();

  Guest& guest_;
  const uint16_t vpid_;
  // |last_cpu_| contains the CPU dedicated to holding the guest's VMCS state,
  // or INVALID_CPU if there is no such VCPU. If this Vcpu is actively running,
  // then |last_cpu_| will point to that CPU.
  //
  // The VMCS state of this Vcpu must not be loaded prior to |last_cpu_| being
  // set, nor must |last_cpu_| be modified prior to the VMCS state being cleared.
  cpu_num_t last_cpu_ TA_GUARDED(thread_->get_lock());

  // |thread_| will be set to nullptr when the thread exits during the Exiting
  // stage of our migration function callback.
  Thread* thread_ TA_GUARDED(Thread::get_list_lock());
  ktl::atomic<bool> kicked_ = false;
  ktl::atomic<bool> entered_ = false;
  // ZX_VCPU_STATE_TLB_FLUSH: whether a flush is pending (bit 0) and how many
  // have been consumed in total (bits 1-63, i.e. the consumed count is
  // stored pre-shifted left by one). Packed into ONE atomic word, rather
  // than a separate `bool` and `uint64_t`, so ReadTlbFlushState's (pending,
  // flushes_consumed) pair is always a single coherent snapshot: two
  // independent atomics could not give that guarantee without a caller
  // ever being able to observe pending==0 alongside a flushes_consumed that
  // has not yet been incremented for the very consumption that cleared it.
  // WriteTlbFlushState sets bit 0 with `fetch_or` (from any thread, and
  // idempotent, so a second request while one is already pending is a
  // no-op); this VCPU's own thread is the only writer of the consumed bits,
  // at the very end of Enter()'s per-iteration setup, immediately before
  // the hardware VM-entry instruction -- see the non-looping
  // compare_exchange there for why a concurrent WriteTlbFlushState landing
  // during that update is still never erased.
  ktl::atomic<uint64_t> tlb_flush_state_ = 0;
  static constexpr uint64_t kTlbFlushPendingBit = 1;
  static constexpr uint64_t kTlbFlushConsumedIncrement = 2;
  bool registered_with_guest_ = false;
  // Whether the guest's XCR0 and extended-register file are installed in the
  // physical CPU right now. True only between `LoadExtendedRegisters()` and the
  // matching save, and therefore only ever while this VCPU's thread is running.
  // Read and written by that thread, and by the context-switch callback that
  // runs on that thread's behalf as it is descheduled; never by another CPU
  // while it is true.
  ktl::atomic<bool> xstate_loaded_ = false;
  // The XCR0 `extended_register_state_` was last WRITTEN under, which is
  // not the same thing as the guest's architectural XCR0
  // (`vmx_state_.guest_state.xcr0`) between a guest XSETBV and the next VM entry.
  // Save and Load both use this one, so a restore of that buffer always happens
  // under the XCR0 it was saved under -- which XRSTORS requires, since it #GP(0)s
  // when the image's XCOMP_BV names a component absent from XCR0. See
  // Vcpu::ReconcileGuestXcr0, which is the only thing that moves the two together.
  // Touched only on the VCPU's own thread with preemption disabled.
  uint64_t xstate_buffer_xcr0_ = 0;
  VmxPage vmcs_page_;
  // The virtual-APIC page (Volume 3, Section 30.1). Required by, and only by,
  // the "use TPR shadow" primary VM-execution control, which this VMCS sets so
  // that a guest's `MOV to/from CR8` — how x64 Windows reads and writes IRQL —
  // runs without a VM exit. The processor services those instructions against
  // VTPR at offset 0x80 of this page.
  //
  // Per-VCPU, and that is not an implementation detail: VTPR is per-logical-
  // processor architectural state, so a shared page would make one VP's IRQL
  // visible to another.
  hypervisor::Page virtual_apic_page_;
  VmxState vmx_state_;
  MsrState msr_state_;
  LocalApicState local_apic_state_;
  // Test-only override for the VID gate in WriteLazyEoiState. Always false in
  // production; see ForceLazyEoiGrantForTest.
  bool lazy_eoi_test_force_grant_ = false;
  PvClockState pv_clock_state_;
  // Per-VCPU rather than global so a log line names the VP that took the fault,
  // and so one VP hammering a register cannot silence the first occurrence on
  // another.
  UnhandledMsrLog unhandled_msr_log_;
  // Same reasoning as unhandled_msr_log_: per-VCPU so a line names the VP, and
  // so one VP polling a dead port cannot silence the first sighting on another.
  UnhandledIoLog unhandled_io_log_;
  // Counted on the VCPU's own thread, immediately after the VM exit, so it needs
  // no synchronization.
  uint64_t host_nmis_redispatched_ = 0;
  // The VMCS TSC_OFFSET this VCPU is running with, mirrored here so the
  // exit handlers that have to add or subtract it do not have to read the VMCS.
  // Written only by SetTscOffset, which requires the VCPU's own thread, and read
  // only from that thread, so it needs no synchronization for the same reason
  // host_nmis_redispatched_ does not.
  int64_t tsc_offset_ = 0;
  // The guest's complete debug-register file. DR0-DR3 and DR6 are swapped
  // around VM entry because VMX does not do so. DR7 normally lives in the VMCS;
  // its shadow is authoritative only while host-owned hardware breakpoints are
  // overlaid into the VMCS value.
  // VMX swaps DR7 and IA32_DEBUGCTL through the entry/exit controls and nothing
  // else, so without these the guest and the host share the address and status
  // registers outright.
  //
  uint64_t guest_debug_regs_[4] = {};
  // X86_DR6_MASK, not 0: DR6's reserved bits read as one, and that value is what
  // the rest of this kernel treats as the register's reset state (see
  // x86_read_debug_status and arch/x86/thread.cc). Starting at zero would hand a
  // fresh guest a DR6 no processor ever produces.
  uint64_t guest_dr6_ = 0xffff0ff0;
  uint64_t guest_dr7_ = 0x400;
  // Null is the zero-cost ordinary path: no allocation, MOV-DR exit, #DB exit,
  // or extra debug-register VMCS/MSR work exists until a validated arm.
  ktl::unique_ptr<HardwareBreakpointSession> hardware_breakpoint_;
  // The four controls below are changed as one logical transaction when the
  // first host breakpoint is armed and restored exactly when it is removed.
  // Remembering their prior values avoids confiscating controls another VCPU
  // facility or a nested VMX implementation already required.
  bool hardware_breakpoint_vmcs_active_ = false;
  bool hardware_breakpoint_had_mov_dr_exiting_ = false;
  bool hardware_breakpoint_had_debug_exception_exit_ = false;
  bool hardware_breakpoint_had_entry_debug_controls_ = false;
  bool hardware_breakpoint_had_exit_debug_controls_ = false;
  // VM-exit reason bit 28 says an MTF exit became pending at the same boundary
  // as a different, higher-priority exit. That indication lives only in the
  // exit-reason field, so remember it until Enter can return the debugger exit.
  // The same latch is set when the kernel or VMM completes an instruction that
  // exited before execution (for example port I/O): in both cases the next
  // guest instruction must not run before the one-shot is reported.
  bool pending_monitor_trap_ = false;
  // Shadow of the host-owned MTF control. This is deliberately separate from
  // guest RFLAGS.TF and lets the normal run path skip every debug-only VMREAD:
  // when false, Enter pays one predictable branch and nothing else.
  bool monitor_trap_armed_ = false;
  // Opt-in post-handler VM-exit observation and completed-exit budget. All
  // storage is embedded in the VCPU; arming allocates nothing and changes no
  // hardware controls. The cached armed bit keeps the ordinary path from
  // touching counters or VMCS fields beyond those normal handling already
  // uses.
  bool exit_control_armed_ = false;
  uint64_t exit_control_active_flags_ = 0;
  uint64_t exit_control_selected_reasons_[2] = {};
  uint64_t exit_control_budget_ = 0;
  uint64_t exit_control_exits_seen_ = 0;
  uint64_t next_exit_observation_sequence_ = 1;
  zx_packet_guest_exit_observation_t pending_exit_observation_ = {};
  bool pending_exit_observation_valid_ = false;
  bool pending_exit_observation_delivered_ = false;
  // Guest-only retired-instruction PMU session. Reservation is global and is
  // acquired only by a validated arm request; the normal entry path never
  // touches PMU state while this cached bit is false.
  bool instruction_counter_reserved_ = false;
  bool instruction_control_armed_ = false;
  uint64_t instruction_budget_ = 0;
  uint64_t retired_instructions_ = 0;
  uint64_t next_instruction_sequence_ = 1;
  zx_packet_guest_instruction_budget_t pending_instruction_budget_ = {};
  bool pending_instruction_budget_valid_ = false;
  bool pending_instruction_budget_delivered_ = false;
  // Allocated only after a complete typed Intel PT configure request reserves
  // the host resource. A null pointer is the ordinary path: no RTIT MSR access,
  // VMCS control change, polling, or allocation occurs in Enter.
  ktl::unique_ptr<IntelPtState> intel_pt_;
  // A capability read is deliberately CPUID-only. If a later Configure proves
  // a static host prerequisite absent, remember its public reason so subsequent
  // reads can report the qualified result without repeating invasive probes.
  zx_vcpu_intel_pt_unavailable_reason_t intel_pt_static_unavailable_reason_ =
      ZX_VCPU_INTEL_PT_REASON_NONE;
  // A VMM-requested event to inject on the next VM entry (e.g. a re-injected
  // guest breakpoint, or a fault an instruction emulator decided the guest
  // earned). Held here rather than written into the VMCS at request time
  // because the interruption-information field only takes effect on the VMCS
  // that is loaded at VM entry; Enter() applies it. Already validated by the
  // time it lands here, so Enter() does not re-check it.
  struct PendingEvent {
    // ZX_VCPU_EVENT_*; ZX_VCPU_EVENT_NONE means nothing is queued.
    uint32_t type = 0;
    uint32_t vector = 0;
    uint32_t error_code = 0;
    uint32_t instruction_length = 0;
    uint64_t cr2 = 0;
    bool has_error_code = false;
    bool has_cr2 = false;
  };
  // Touched only on the VCPU's own thread (InjectException/WritePendingEvent
  // and Enter), so it needs no synchronization.
  PendingEvent pending_event_;
  // Most recently completed software xAPIC access. Like every VCPU state topic,
  // submission and retrieval happen on this VCPU's owning thread, in order
  // between the MMIO exit and the next entry.
  zx_vcpu_xapic_access_t xapic_access_result_ = {};
  bool xapic_access_result_valid_ = false;
  // An event that was already being delivered through the guest IDT when the
  // last VM exit occurred, recovered from the VMCS IDT-vectoring information
  // field. The processor aborts such a delivery, rolls the guest back to before
  // it, and reports the interrupted event here; re-injecting it is the
  // hypervisor's job, and skipping that step loses the event outright.
  //
  // Kept separate from `pending_event_` rather than folded into it: a VMM
  // request and an interrupted delivery can be outstanding at the same time,
  // and either overwriting the other drops an event just as thoroughly as
  // ignoring this field did. The VMX interruption type is kept raw rather than
  // translated to a ZX_VCPU_EVENT_* because the field can name types the public
  // enum has no word for -- a software interrupt (INT n) or a privileged
  // software exception (INT1) whose delivery faulted.
  struct VectoringEvent {
    bool valid = false;
    // Raw VMX interruption type, already shifted into bits 10:8.
    uint32_t type = 0;
    uint32_t vector = 0;
    uint32_t error_code = 0;
    uint32_t instruction_length = 0;
    bool has_error_code = false;
  };
  VectoringEvent vectoring_event_;
  VectoringStats vectoring_;
  // The paravirtual surface this guest sees. Touched only on the VCPU's own
  // thread (the setters and the Enter exit handler), so it needs no
  // synchronization.
  VcpuEnlightenment enlightenment_;
  // The guest may enable any state, so the XSAVE area is the maximum size.
  alignas(64) uint8_t extended_register_state_[X86_MAX_EXTENDED_REGISTER_SIZE];
};

#endif  // ZIRCON_KERNEL_ARCH_X86_INCLUDE_ARCH_HYPERVISOR_H_

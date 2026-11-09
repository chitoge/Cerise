// Copyright 2017 The Fuchsia Authors
//
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT

#include <bits.h>
#include <inttypes.h>
#include <lib/ktrace.h>
#include <platform.h>
#include <string.h>
#include <trace.h>
#include <zircon/syscalls/hypervisor.h>
#include <zircon/time.h>
#include <zircon/types.h>

#include <arch/hypervisor.h>
#include <arch/x86/apic.h>
#include <arch/x86/feature.h>
#include <arch/x86/hypervisor/invalidate.h>
#include <arch/x86/interrupts.h>
#include <arch/x86/mmu.h>
#include <arch/x86/pv.h>
#include <hypervisor/interrupt_tracker.h>
#include <hypervisor/ktrace.h>
#include <kernel/percpu.h>
#include <kernel/stats.h>
#include <ktl/algorithm.h>
#include <platform/pc/timer.h>
#include <vm/fault.h>
#include <vm/physmap.h>
#include <vm/pmm.h>

#include "pv_priv.h"
#include "vcpu_priv.h"
#include "vmexit_priv.h"

#include <ktl/enforce.h>

#define LOCAL_TRACE 0

extern "C" void x86_call_external_interrupt_handler(uint64_t vector);

namespace {

constexpr uint64_t kLocalApicXapicBase = APIC_PHYS_BASE | IA32_APIC_BASE_XAPIC_ENABLE;
constexpr uint64_t kLocalApicX2apicBase = kLocalApicXapicBase | IA32_APIC_BASE_X2APIC_ENABLE;

constexpr uint64_t kX2ApicMsrBase = 0x800;
constexpr uint64_t kX2ApicMsrMax = 0x83f;

constexpr uint64_t kMiscEnableFastStrings = 1u << 0;

// ---------------------------------------------------------------------------
// Registers this hypervisor answers that arch/x86/registers.h does not name.
// ---------------------------------------------------------------------------

// Read-only here: the read reports the lock bit set, so a write is a write to a
// locked register and takes the #GP the architecture prescribes.
constexpr uint32_t kMsrIa32FeatureControl = 0x3a;
constexpr uint64_t kFeatureControlLock = 1u << 0;

constexpr uint32_t kMsrIa32Debugctl = 0x1d9;
// The only two bits a guest may set. Everything else is dropped; see the write
// handler for why silence is safer than a fault here.
constexpr uint64_t kDebugctlLbr = 1u << 0;
constexpr uint64_t kDebugctlBtf = 1u << 1;
constexpr uint64_t kDebugctlGuestWritable = kDebugctlLbr | kDebugctlBtf;

// The legacy P6 BBL_CR_* family. Not architectural on any part we run on and
// absent from current SDMs; they survive as registers a Windows kernel still
// touches on its way up. A backend that does boot this guest carries the same
// hard-coded list. Reads answer 0, writes are swallowed.
constexpr uint32_t kMsrBblCrD0 = 0x88;
constexpr uint32_t kMsrBblCrD1 = 0x89;
constexpr uint32_t kMsrBblCrD2 = 0x8a;
constexpr uint32_t kMsrBblCrAddr = 0x116;
constexpr uint32_t kMsrBblCrDecc = 0x118;
constexpr uint32_t kMsrBblCrCtl = 0x119;
constexpr uint32_t kMsrBblCrTrig = 0x11a;
constexpr uint32_t kMsrBblCrBusy = 0x11b;
constexpr uint32_t kMsrBblCrCtl3 = 0x11e;
// An Intel uncore C-box performance-monitor bank used by older model-specific
// monitoring code.  The virtual PMU is disabled (CPUID leaf 0xA is zero), so
// the only coherent virtual value for its event selectors and counters is the
// reset/disabled value.  Some Windows kernels still save registers from this
// bank on particular family/model combinations; faulting those probes turns
// the resulting #GP into
// STATUS_PRIVILEGED_INSTRUCTION during boot.
constexpr uint32_t kMsrUncoreCbox5First = 0xdb0;
constexpr uint32_t kMsrUncoreCbox5Last = 0xdbb;

// ---------------------------------------------------------------------------
// IA32_MISC_ENABLE, as the guest reads it.
// ---------------------------------------------------------------------------
//
// A reference backend that boots this guest hard-codes 0x851809. We report
// 0x801801, and the difference is deliberate -- DO NOT "correct" this back to
// the reference constant. The rule applied here is that every bit must agree
// with what THIS hypervisor's own CPUID masking tells the guest, because an
// incoherent pair (capability advertised, enable bit denying it, or the reverse)
// is exactly the class of defect this register was already implicated in: we
// passed CPUID.1:ECX bit 14 (xTPR update control) through from the host while
// reporting xTPR messages *enabled*, in the TPR neighbourhood, on a hypervisor
// whose TPR lives in a virtual-APIC page.
//
//   bit 0  Fast-Strings Enable ................................ 1
//          True and harmless; also what the previous implementation reported by
//          masking the host's value, so no guest loses anything.
//   bit 3  Automatic Thermal Control Circuit Enable ............ 0  (ref: 1)
//          Pairs with CPUID.1:EDX.TM, which handle_cpuid explicitly CLEARS.
//   bit 11 Branch Trace Storage UNAVAILABLE .................... 1
//          Honest and load-bearing: there is no debug store here. IA32_DS_AREA
//          is unimplemented and the DEBUGCTL BTS bits are masked off, so a guest
//          that consults this bit will not try to arm branch tracing.
//   bit 12 Processor Event Based Sampling UNAVAILABLE .......... 1
//          CPUID leaf 0xA is zeroed ("disable all performance monitoring"), so
//          there is no PMU to sample with.
//   bit 16 Enhanced SpeedStep Enable ........................... 0  (ref: 1)
//          CPUID.1:ECX.EIST passes through from the host, so a guest may see the
//          capability -- but "capable and not enabled" is a legal, well-defined
//          platform state and it is the true one: IA32_PERF_CTL (0x199) is not
//          implemented. Claiming enabled invites a write we would fault.
//   bit 18 ENABLE MONITOR FSM ................................. 0  (ref: 1)
//          handle_cpuid explicitly clears CPUID.1:ECX.MONITOR and zeroes leaf 5.
//          This bit is the one that says MONITOR/MWAIT do not #UD, so claiming
//          it while denying the feature is incoherent in the direction that
//          matters.
//   bit 22 Limit CPUID Maxval ................................. 0
//          MUST be 0; setting it clamps CPUID to leaf 3. Pinned below.
//   bit 23 xTPR Message Disable ............................... 1  (ref: 1)
//          Closes the incoherence above. There is no chipset here to send xTPR
//          messages, so "disabled" is the true answer.
constexpr uint64_t kMiscEnableBtsUnavailable = 1ull << 11;
constexpr uint64_t kMiscEnablePebsUnavailable = 1ull << 12;
constexpr uint64_t kMiscEnableLimitCpuidMaxval = 1ull << 22;
constexpr uint64_t kMiscEnableXtprMessageDisable = 1ull << 23;
// AND IT IS A CONSTANT, not `read_msr(IA32_MISC_ENABLE)` masked -- which is what
// this used to be, and what it will get "simplified" back to unless the reason
// is sitting here. This is a snapshot-centric hypervisor: a guest that reads
// this register, is checkpointed, and resumes on a different machine must not
// see it change underneath it. Masking the host's value makes the guest's view
// of its own CPU a property of whichever host happens to be running it, which is
// a migration hazard even when every bit of the mask is individually defensible.
// Every bit below is decided by OUR CPUID masking, which is the same on every
// host, so the value is too.
constexpr uint64_t kGuestMiscEnable = kMiscEnableFastStrings | kMiscEnableBtsUnavailable |
                                      kMiscEnablePebsUnavailable | kMiscEnableXtprMessageDisable;
static_assert(kGuestMiscEnable == 0x801801ull, "the value is derived above; update the table too");
static_assert((kGuestMiscEnable & kMiscEnableLimitCpuidMaxval) == 0,
              "Limit CPUID Maxval would clamp guest CPUID to leaf 3");

constexpr uint32_t kFirstExtendedStateComponent = 2;
// Volume 1, Section 13.1 enumerates state components 0..62. This used to stop at
// 9 (PKRU), which silently under-counted the XSAVE area on any CPU that reports
// a component above it (AMX's XTILECFG/XTILEDATA are 17 and 18). The area size
// is now used to bound XCR0 -- see ValidateGuestXcr0 -- so an under-count would
// be a hole, not merely an inaccurate CPUID answer.
constexpr uint32_t kLastExtendedStateComponent = 62;
// From Volume 1, Section 13.4.
constexpr uint32_t kXsaveLegacyRegionSize = 512;
constexpr uint32_t kXsaveHeaderSize = 64;

// NOTE: x86 instructions are guaranteed to be 15 bytes or fewer.
constexpr uint8_t kMaxInstructionSize = 15;

alignas(uint32_t) constexpr char kHypVendorId[] = "KVMKVMKVM\0\0\0";
static_assert(sizeof(kHypVendorId) - 1 == 12, "Vendor ID must be 12 characters long");

// Hyper-V (TLFS) CPUID identity, returned per-guest when Hyper-V-identity mode is
// enabled (a Hyper-V-enlightened guest, e.g. Windows, keys off these). ebx:ecx:edx
// of leaf 0x40000000 spell "Microsoft Hv"; leaf 0x40000001 eax is the "Hv#1"
// interface signature. The feature/recommendation leaves (0x40000002+) are a
// separate, later step (they must track what the userspace VMM actually offers).
constexpr uint32_t kHypervVendorEbx = 0x7263694D;  // "Micr"
constexpr uint32_t kHypervVendorEcx = 0x666F736F;  // "osof"
constexpr uint32_t kHypervVendorEdx = 0x76482074;  // "t Hv"
constexpr uint32_t kHypervInterfaceSignature = 0x31237648;  // "Hv#1"
constexpr uint32_t kHypervMaxLeaf = 0x40000005;
static_assert(kHypervMaxLeaf == kHypervSuppliedLeafLast,
              "The advertised max leaf must be the last one we actually answer");
// CPUID leaves 0x4000_0000-0x4fff_ffff are reserved for hypervisor use, so under
// a Hyper-V identity none of them may fall through to the host's CPUID.
constexpr uint32_t kHypervCpuidRangeLast = 0x4fffffff;

// The synthetic MSR block a VMM may claim (see Vcpu::SetMsrDelegation). This is
// where an enlightened guest expects its synthetic registers — the hypercall
// page, the VP index, the interrupt controller and timers — none of which the
// kernel models. The window stops short of 0x4000_ffff on purpose: the kernel's
// own paravirtual clock registers live higher in the hypervisor-reserved space
// (0x4b56_4d00), so scoping the delegation this way leaves them, and every
// architectural MSR, on their existing in-kernel paths even when it is on.
constexpr uint32_t kSyntheticMsrBase = 0x40000000;
constexpr uint32_t kSyntheticMsrMax = 0x4000ffff;
static_assert(kKvmSystemTimeMsr > kSyntheticMsrMax && kKvmBootTime > kSyntheticMsrMax,
              "Delegating the synthetic MSR block must not capture the in-kernel clock");


constexpr uint64_t kKvmFeatureNoIoDelay = 1u << 1;

void dump_guest_state(const GuestState& guest_state, const ExitInfo& exit_info) {
  dprintf(INFO, " RAX: %#18lx  RCX: %#18lx  RDX: %#18lx  RBX: %#18lx\n", guest_state.rax,
          guest_state.rcx, guest_state.rdx, guest_state.rbx);
  dprintf(INFO, " RSP:  xxxxxxxx xxxxxxxx  RBP: %#18lx  RSI: %#18lx  RDI: %#18lx\n",
          guest_state.rbp, guest_state.rsi, guest_state.rdi);
  dprintf(INFO, "  R8: %#18lx   R9: %#18lx  R10: %#18lx  R11: %#18lx\n", guest_state.r8,
          guest_state.r9, guest_state.r10, guest_state.r11);
  dprintf(INFO, " R12: %#18lx  R13: %#18lx  R14: %#18lx  R15: %#18lx\n", guest_state.r12,
          guest_state.r13, guest_state.r14, guest_state.r15);
  dprintf(INFO, " RIP: %#18lx  CR2: %#18lx XCR0: %#18lx\n", exit_info.guest_rip, guest_state.cr2,
          guest_state.xcr0);

  dprintf(INFO, "entry failure: %d\n", exit_info.entry_failure);
  dprintf(INFO, "exit instruction length: %u\n", exit_info.exit_instruction_length);
}

void next_rip(const ExitInfo& exit_info, AutoVmcs& vmcs) {
  vmcs.Write(VmcsFieldXX::GUEST_RIP, exit_info.guest_rip + exit_info.exit_instruction_length);

  // Clear any flags blocking interrupt injection for a single instruction.
  uint32_t guest_interruptibility = vmcs.Read(VmcsField32::GUEST_INTERRUPTIBILITY_STATE);
  uint32_t new_interruptibility =
      guest_interruptibility & ~(kInterruptibilityStiBlocking | kInterruptibilityMovSsBlocking);
  if (new_interruptibility != guest_interruptibility) {
    vmcs.Write(VmcsField32::GUEST_INTERRUPTIBILITY_STATE, new_interruptibility);
  }
}

void handle_external_interrupt(AutoVmcs& vmcs) {
  const ExitInterruptionInfo int_info(vmcs);
  DEBUG_ASSERT(int_info.valid);
  DEBUG_ASSERT(int_info.interruption_type == InterruptionType::EXTERNAL_INTERRUPT);
  vmcs.Invalidate();
  x86_call_external_interrupt_handler(int_info.vector);
}

void handle_interrupt_window(AutoVmcs& vmcs) { vmcs.InterruptWindowExiting(false); }

// The guest has just become able to take an NMI: virtual-NMI blocking
// cleared (the guest's NMI handler executed IRET) and MOV-SS blocking is clear.
// Nothing to do but disarm the window -- the injection decision is made on the
// way back into the guest, by `local_apic_maybe_interrupt`, which will now find
// `can_inject_nmi` true and deliver the vector it put back.
//
// Counted, because the counter is the only thing that distinguishes an NMI
// delivered BECAUSE this window fired from one delivered because some unrelated
// exit happened to come along -- and the second is what the old
// interrupt-window fallback actually produced.
void handle_nmi_window(AutoVmcs& vmcs, LocalApicState& local_apic_state) {
  local_apic_state.nmi_window_exits++;
  vmcs.NmiWindowExiting(false);
}

// The guest lowered its task priority below the threshold armed for a vector
// that was waiting on exactly that.
//
// There is nothing to do here, and that is the whole design: the exit's only
// job is to end the VM entry so the run loop reaches
// `local_apic_maybe_interrupt` again, which re-reads VTPR, finds the vector now
// deliverable, and injects it. The threshold is re-armed or cleared there too,
// so this handler owns no state.
//
// Deliberately no `next_rip`. Volume 3, Section 27.2.2: a TPR-below-threshold
// VM exit is a trap that occurs *after* the instruction that lowered VTPR has
// completed (or immediately after a VM entry that found it already below), so
// the guest RIP the processor saved is the next instruction and advancing it
// would skip one.
void handle_tpr_below_threshold() {}

// From Volume 2, Section 3.2, Table 3-8  "Processor Extended State Enumeration
// Main Leaf (EAX = 0DH, ECX = 0)".
//
// Bits 31-00: Maximum size (bytes, from the beginning of the XSAVE/XRSTOR save
// area) required by enabled features in XCR0. May be different than ECX if some
// features at the end of the XSAVE save area are not enabled.
zx::result<uint32_t> compute_xsave_size(uint64_t guest_xcr0) {
  uint32_t xsave_size = kXsaveLegacyRegionSize + kXsaveHeaderSize;
  for (uint32_t i = kFirstExtendedStateComponent; i <= kLastExtendedStateComponent; ++i) {
    cpuid_leaf leaf;
    // 1ull, not 1: components run to 62 and `1 << i` is undefined past 31.
    if (!(guest_xcr0 & (1ull << i))) {
      continue;
    }
    if (!x86_get_cpuid_subleaf(X86_CPUID_XSAVE, i, &leaf)) {
      return zx::error(ZX_ERR_INTERNAL);
    }
    if (leaf.a == 0 && leaf.b == 0 && leaf.c == 0 && leaf.d == 0) {
      continue;
    }
    const uint32_t component_offset = leaf.b;
    const uint32_t component_size = leaf.a;
    // The MAXIMUM end, not the last one computed. Assigning here instead was
    // safe only while component index order matched standard-layout offset
    // order, which is no longer an architectural guarantee: APX (XCR0 bit 19)
    // is placed in the standard layout at the offset MPX used to occupy, so a
    // higher-numbered component can end earlier than a lower-numbered one. With
    // a plain assignment that under-counts -- which, now that this feeds the
    // buffer bound in ValidateGuestXcr0(), would be a hole rather than merely a
    // wrong CPUID answer. (Volume 2, Table 3-8 defines EBX as the maximum size,
    // so this is also the more correct answer for the guest's CPUID.)
    xsave_size = ktl::max(xsave_size, component_offset + component_size);
  }
  return zx::ok(xsave_size);
}

zx::result<> handle_cpuid(const ExitInfo& exit_info, AutoVmcs& vmcs, GuestState& guest_state,
                          const VcpuEnlightenment& enlightenment) {
  const uint32_t leaf = guest_state.eax();
  const uint32_t subleaf = guest_state.ecx();
  const bool hyperv_identity = enlightenment.hyperv_identity;

  next_rip(exit_info, vmcs);

  // Under a Hyper-V identity the whole hypervisor-reserved CPUID range belongs to
  // that surface. The VMM answers the leaves describing what it implements; every
  // other leaf in the range reads as zero, meaning "not implemented". Falling
  // through to the default below would instead hand the guest the highest base
  // leaf's contents, which is unrelated data that a probing guest could act on.
  if (hyperv_identity && leaf >= kHypervSuppliedLeafFirst && leaf <= kHypervCpuidRangeLast) {
    const HypervCpuidLeaf values = leaf <= kHypervSuppliedLeafLast
                                       ? enlightenment.hyperv_cpuid[leaf - kHypervSuppliedLeafFirst]
                                       : HypervCpuidLeaf{};
    guest_state.rax = values.eax;
    guest_state.rbx = values.ebx;
    guest_state.rcx = values.ecx;
    guest_state.rdx = values.edx;
    return zx::ok();
  }

  switch (leaf) {
    case X86_CPUID_BASE:
    case X86_CPUID_EXT_BASE:
      cpuid(leaf, reinterpret_cast<uint32_t*>(&guest_state.rax),
            reinterpret_cast<uint32_t*>(&guest_state.rbx),
            reinterpret_cast<uint32_t*>(&guest_state.rcx),
            reinterpret_cast<uint32_t*>(&guest_state.rdx));
      // EAX in these two leaves is the guest's ceiling -- the highest
      // basic (leaf 0) or extended (leaf 0x80000000) leaf it is told exists --
      // and the host's answer is not this hypervisor's to advertise. The
      // pass-through cases below stop at MAX_SUPPORTED_CPUID /
      // MAX_SUPPORTED_CPUID_EXT, and everything above falls to `default`, so on a
      // part whose ceiling is higher the guest was being told about leaves that
      // are answered with some other leaf's contents. Volume 2's CPUID page makes
      // "out of range" a well-defined request; "in range and answered with
      // unrelated data" is not a state a guest has any way to detect.
      //
      // This also restores the intent of the X86_CPUID_TOPOLOGY case below, which
      // says reporting leaf 0x1f breaks Linux guests and that only the older leaf
      // 0xB is offered. That was true only while the host's ceiling happened to be
      // under 0x1f: on a 2019-or-later part leaf 0 advertised 0x1f regardless, and
      // a guest that took leaf 0 at its word asked for it.
      //
      // Narrowing only. A ceiling at or below ours is passed through untouched,
      // which includes older processors whose ceiling is 0x16, so this is a
      // no-op there -- see
      // vcpu_cpuid_leaf_zero_matches_what_is_answered, which says so in its own
      // output rather than letting a green tick imply otherwise.
      //
      // `default` deliberately still uses the MAX_SUPPORTED_CPUID constant rather
      // than the clamped ceiling, and the two cannot disagree: if the host ceiling
      // is above ours the clamped value IS MAX_SUPPORTED_CPUID, and if it is below,
      // the processor applies the identical out-of-range clamp to
      // cpuid_c(MAX_SUPPORTED_CPUID) itself. The test checks that equality through
      // the guest rather than leaving it as an argument.
      {
        const uint32_t ceiling = leaf == X86_CPUID_BASE ? uint32_t{MAX_SUPPORTED_CPUID}
                                                        : uint32_t{MAX_SUPPORTED_CPUID_EXT};
        if (static_cast<uint32_t>(guest_state.rax) > ceiling) {
          guest_state.rax = ceiling;
        }
      }
      return zx::ok();
    case X86_CPUID_BASE + 1 ... MAX_SUPPORTED_CPUID:
    case X86_CPUID_EXT_BASE + 1 ... MAX_SUPPORTED_CPUID_EXT:
      cpuid_c(leaf, subleaf, reinterpret_cast<uint32_t*>(&guest_state.rax),
              reinterpret_cast<uint32_t*>(&guest_state.rbx),
              reinterpret_cast<uint32_t*>(&guest_state.rcx),
              reinterpret_cast<uint32_t*>(&guest_state.rdx));
      switch (leaf) {
        case X86_CPUID_MODEL_FEATURES:
          // Override the initial local APIC ID. From Vol 2, Table 3-8.
          guest_state.rbx &= ~(0xff << 24);
          guest_state.rbx |= (vmcs.Read(VmcsField16::VPID) - 1) << 24;
          // Enable the hypervisor bit.
          guest_state.rcx |= 1u << X86_FEATURE_HYPERVISOR.bit;
          // Enable the x2APIC bit.
          guest_state.rcx |= 1u << X86_FEATURE_X2APIC.bit;
          // Always enable TSC deadline (this doesn't depend on the host feature).
          guest_state.rcx |= 1u << X86_FEATURE_TSC_DEADLINE.bit;
          // OSXSAVE MIRRORS THE GUEST'S CR4, and is not a capability bit.
          //
          // Volume 2, Table 3-8: CPUID.1:ECX.OSXSAVE[bit 27] reports whether
          // *the OS* has set CR4.OSXSAVE, and the processor keeps the two in
          // step. It is the bit software is told to test before executing
          // XGETBV -- which #UDs unless CR4.OSXSAVE is set. Passing the host's
          // value through therefore hands the guest a licence it does not have:
          // a guest that clears its own CR4.OSXSAVE still reads 1 here, executes
          // XGETBV, and takes a #UD it has no reason to expect. That is not
          // hypothetical -- it is how a Windows boot module died, with the #UD
          // surfacing much later as a corrupted initial thread and a
          // FAST_FAIL_INCORRECT_STACK bugcheck.
          //
          // GUEST_CR4 is the right field to read, and CR4_READ_SHADOW is not.
          // The shadow supplies only the bits in CR4_GUEST_HOST_MASK, and Setup()
          // puts exactly one bit there: X86_CR4_VMXE. Every other CR4 bit --
          // OSXSAVE among them -- is owned by the guest, written straight into
          // GUEST_CR4 by a `mov cr4` that does not even exit, and read back from
          // GUEST_CR4. Reading the shadow here would report a hardcoded 0 and
          // break every guest that legitimately enables XSAVE. (handle_xsetbv
          // below already reads GUEST_CR4 for this same bit, for this same
          // reason.)
          if (vmcs.Read(VmcsFieldXX::GUEST_CR4) & X86_CR4_OSXSAVE) {
            guest_state.rcx |= 1u << X86_FEATURE_OSXSAVE.bit;
          } else {
            guest_state.rcx &= ~(1u << X86_FEATURE_OSXSAVE.bit);
          }
          // Disable the VMX bit.
          guest_state.rcx &= ~(1u << X86_FEATURE_VMX.bit);
          // Disable the PDCM bit.
          guest_state.rcx &= ~(1u << X86_FEATURE_PDCM.bit);
          // Disable MONITOR/MWAIT.
          guest_state.rcx &= ~(1u << X86_FEATURE_MON.bit);
          // Disable THERM_INTERRUPT and THERM_STATUS MSRs
          guest_state.rcx &= ~(1u << X86_FEATURE_TM2.bit);
          // Enable the SEP (SYSENTER support).
          guest_state.rdx |= 1u << X86_FEATURE_SEP.bit;
          // Disable the Thermal Monitor bit.
          guest_state.rdx &= ~(1u << X86_FEATURE_TM.bit);
          // Disable the THERM_CONTROL_MSR bit.
          guest_state.rdx &= ~(1u << X86_FEATURE_ACPI.bit);
          break;
        // Modern CPUs (2018+) support a newer extended topology leaf (leaf 0x1f). However,
        // reporting it breaks Linux guests. We can get away with reporting only the older topology,
        // since software should fallback to it. From Intel Volume 1, Section 21.3: "CPUID.1FH is a
        // preferred superset to leaf 0BH. Intel recommends first checking for the existence of
        // leaf 1FH before using leaf 0BH."
        case X86_CPUID_TOPOLOGY:
          if (subleaf == 0) {
            guest_state.rax = 0;
            guest_state.rbx = X86_FEATURE_TOPOLOGY_SINGLE_PROCESSOR.bit;
            // Bits [07-00] are the index (0), bits [15-08] are the subleaf identifier.
            guest_state.rcx = 0u | (1u << X86_FEATURE_TOPOLOGY_LOGICAL_PROCESSOR.bit);
            guest_state.rdx = vmcs.Read(VmcsField16::VPID) - 1;
          } else {
            // No need to report further subleafs.
            guest_state.rax = 0;
            guest_state.rbx = 0;
            guest_state.rcx = 0;
            guest_state.rdx = 0;
          }
          break;
        // XSAVE registers are enumerated in Intel Vol. 2A, Table 3-8.
        case X86_CPUID_XSAVE:
          if (subleaf == 0) {
            // All four registers come from one expression; see
            // GuestXsaveMainLeaf.
            const uint64_t host_components =
                (static_cast<uint64_t>(static_cast<uint32_t>(guest_state.rdx)) << 32) |
                static_cast<uint32_t>(guest_state.rax);
            auto main_leaf =
                GuestXsaveMainLeaf(host_components, guest_state.xcr0, compute_xsave_size);
            if (main_leaf.is_error()) {
              return main_leaf.take_error();
            }
            guest_state.rax = main_leaf->eax;
            guest_state.rbx = main_leaf->ebx;
            guest_state.rcx = main_leaf->ecx;
            guest_state.rdx = main_leaf->edx;
          } else if (subleaf == 1) {
            // TODO(https://fxbug.dev/506251881): Properly support XSAVEC, which is currently
            // not feasible due to missing support for extended state components such as AVX-512.
            // In the meantime, we'll clear bit 01, which indicates that we don't support XSAVEC.
            guest_state.rax &= ~(1u << 1);
            // Clear bit 03, which indicates that we don't support XSAVES/XRSTORS and IA32_XSS.
            guest_state.rax &= ~(1u << 3);
            // From the Intel manual (Vol. 2A, Table 3-8): "If EAX[1] and EAX[3] are both
            // enumerated as 0, EBX enumerates zero."
            guest_state.rbx = 0;
            // ECX and EDX are for enumerating the IA32_XSS MSR size, which is a feature we've
            // explicitly disabled above.
            guest_state.rcx = 0;
            guest_state.rdx = 0;
          } else if (subleaf < 64) {
            cpuid_leaf main_leaf;
            if (!x86_get_cpuid_subleaf(X86_CPUID_XSAVE, 0, &main_leaf)) {
              return zx::error(ZX_ERR_INTERNAL);
            }
            const uint64_t advertised =
                GuestXsaveComponents((static_cast<uint64_t>(main_leaf.d) << 32) | main_leaf.a);
            if ((advertised & (uint64_t{1} << subleaf)) == 0) {
              // Volume 2, Table 3-8 requires every register to read as zero
              // when the component is absent from subleaf 0's XCR0 bitmap.
              // This includes both explicitly withheld state and IA32_XSS-only
              // components such as processor trace. Passing through an
              // XSS-only host subleaf while XSAVES is disabled above would
              // expose a size and layout for state the guest cannot enable.
              guest_state.rax = 0;
              guest_state.rbx = 0;
              guest_state.rcx = 0;
              guest_state.rdx = 0;
            }
          }
          break;
        case X86_CPUID_THERMAL_AND_POWER:
          // Disable the performance energy bias bit.
          guest_state.rcx &= ~(1u << X86_FEATURE_PERF_BIAS.bit);
          // Disable the hardware coordination feedback bit.
          guest_state.rcx &= ~(1u << X86_FEATURE_HW_FEEDBACK.bit);
          guest_state.rax &= ~(
              // Disable Digital Thermal Sensor
              1u << X86_FEATURE_DTS.bit |
              // Disable Package Thermal Status MSR.
              1u << X86_FEATURE_PTM.bit |
              // Disable THERM_STATUS MSR bits 10/11 & THERM_INTERRUPT MSR bit 24
              1u << X86_FEATURE_PLN.bit |
              // Disable HWP MSRs.
              1u << X86_FEATURE_HWP.bit | 1u << X86_FEATURE_HWP_NOT.bit |
              1u << X86_FEATURE_HWP_ACT.bit | 1u << X86_FEATURE_HWP_PREF.bit |
              // Don't advertise Turbo.
              1u << X86_FEATURE_TURBO.bit | 1u << X86_FEATURE_TURBO_MAX.bit);
          break;
        case X86_CPUID_PERFORMANCE_MONITORING: {
          // Disable all performance monitoring.
          // 31-07 = Reserved 0, 06-00 = 1 if event is not available.
          const uint32_t performance_monitoring_no_events = 0b1111111;
          guest_state.rax = 0;
          guest_state.rbx = performance_monitoring_no_events;
          guest_state.rcx = 0;
          guest_state.rdx = 0;
          break;
        }
        case X86_CPUID_MON:
          // MONITOR/MWAIT are not implemented.
          guest_state.rax = 0;
          guest_state.rbx = 0;
          guest_state.rcx = 0;
          guest_state.rdx = 0;
          break;
        case X86_CPUID_EXTENDED_FEATURE_FLAGS:
          // It's possible when running under KVM in nVMX mode, that host
          // CPUID indicates that invpcid is supported but VMX doesn't allow
          // to enable INVPCID bit in secondary processor based controls.
          // Therefore explicitly clear INVPCID bit in CPUID if the VMX flag
          // wasn't set.
          if ((vmcs.Read(VmcsField32::PROCBASED_CTLS2) & kProcbasedCtls2Invpcid) == 0) {
            guest_state.rbx &= ~(1u << X86_FEATURE_INVPCID.bit);
          }
          // Disable:
          //  * Processor Trace bit
          //  * TSC Adjust bit
          guest_state.rbx &= ~(1u << X86_FEATURE_PT.bit | 1u << X86_FEATURE_TSC_ADJUST.bit);
          // Disable MPX. This kernel does not back it (registers.cc answers
          // X86_EXTENDED_REGISTER_MPX with "Currently unsupported"), and its
          // XCR0 components are withheld from CPUID leaf 0xD and from
          // ValidateGuestXcr0 -- so a guest told MPX exists here would find
          // BNDCFGS absent, its XSETBV refused, and its first BNDMK/BNDCL faulting
          // for no reason it can see. The feature bit and the state components
          // have to go together or the guest gets half a feature.
          //
          // Gated on subleaf 0: leaf 7 is subleaf-indexed and EBX[14] means MPX
          // only there. (The masks above are not so gated; that is pre-existing
          // and not touched here.)
          if (subleaf == 0) {
            guest_state.rbx &= ~(1u << X86_FEATURE_MPX.bit);
            // OSPKE mirrors the guest's CR4.PKE, exactly as leaf 1's OSXSAVE
            // mirrors CR4.OSXSAVE; see there for why GUEST_CR4 rather than
            // CR4_READ_SHADOW is the field that holds the guest's view.
            //
            // The failure here is the mirror image of OSXSAVE's and milder: the
            // host almost certainly has CR4.PKE clear, so a guest that enables
            // protection keys reads OSPKE=0 and concludes PKRU is unusable --
            // a feature silently unavailable rather than a fault. Fixed
            // together because it is the same SDM rule and the same one-line
            // shape; leaving one of a matched pair wrong is how the next
            // reader concludes the rule does not apply here.
            if (vmcs.Read(VmcsFieldXX::GUEST_CR4) & X86_CR4_PKE) {
              guest_state.rcx |= 1u << X86_FEATURE_OSPKE.bit;
            } else {
              guest_state.rcx &= ~(1u << X86_FEATURE_OSPKE.bit);
            }
          }
          // Disable:
          //  * Indirect Branch Prediction Barrier bit
          //  * Single Thread Indirect Branch Predictors bit
          //  * Speculative Store Bypass Disable bit
          // These imply support for the IA32_SPEC_CTRL and IA32_PRED_CMD
          // MSRs, which are not implemented.
          guest_state.rdx &= ~(1u << X86_FEATURE_IBRS_IBPB.bit | 1u << X86_FEATURE_STIBP.bit |
                               1u << X86_FEATURE_SSBD.bit);
          // Disable support for the IA32_ARCH_CAPABILITIES MSR.
          guest_state.rdx &= ~(1u << X86_FEATURE_ARCH_CAPABILITIES.bit);
          // Disable support for the IA32_FLUSH_CMD MSR.
          guest_state.rdx &= ~(1u << X86_FEATURE_L1D_FLUSH.bit);

          // TODO(https://fxbug.dev/42060002): Enable AVX-512 if supported.
          //
          // Disabling this to work around invalid opcode errors trying to execute these
          // instructions.
          guest_state.rbx &= ~(1u << X86_FEATURE_AVX512F.bit | 1u << X86_FEATURE_AVX512DQ.bit |
                               1u << X86_FEATURE_AVX512IFMA.bit | 1u << X86_FEATURE_AVX512PF.bit |
                               1u << X86_FEATURE_AVX512ER.bit | 1u << X86_FEATURE_AVX512CD.bit |
                               1u << X86_FEATURE_AVX512BW.bit | 1u << X86_FEATURE_AVX512VL.bit);
          guest_state.rcx &=
              ~(1u << X86_FEATURE_AVX512VBMI.bit | 1u << X86_FEATURE_AVX512VBMI2.bit |
                1u << X86_FEATURE_AVX512VNNI.bit | 1u << X86_FEATURE_AVX512BITALG.bit |
                1u << X86_FEATURE_AVX512VPDQ.bit);
          guest_state.rdx &=
              ~(1u << X86_FEATURE_AVX512QVNNIW.bit | 1u << X86_FEATURE_AVX512QFMA.bit);

          break;
      }
      return zx::ok();
    case X86_CPUID_HYP_VENDOR: {
      // This leaf is commonly used to identify a hypervisor via ebx:ecx:edx.
      if (hyperv_identity) {
        // Present as Hyper-V ("Microsoft Hv") so an enlightened guest takes its
        // Hyper-V path instead of the KVM one.
        guest_state.rax = kHypervMaxLeaf;
        guest_state.rbx = kHypervVendorEbx;
        guest_state.rcx = kHypervVendorEcx;
        guest_state.rdx = kHypervVendorEdx;
        return zx::ok();
      }
      auto regs = reinterpret_cast<const uint32_t*>(kHypVendorId);
      // Since Zircon hypervisor disguises itself as KVM, it needs to return
      // in EAX max CPUID function supported by hypervisor. Zero in EAX
      // should be interpreted as 0x40000001. Details are available in the
      // Linux kernel documentation (Documentation/virtual/kvm/cpuid.txt).
      guest_state.rax = X86_CPUID_KVM_FEATURES;
      guest_state.rbx = regs[0];
      guest_state.rcx = regs[1];
      guest_state.rdx = regs[2];
      return zx::ok();
    }
    case X86_CPUID_KVM_FEATURES:
      if (hyperv_identity) {
        // Hyper-V interface signature leaf ("Hv#1").
        guest_state.rax = kHypervInterfaceSignature;
        guest_state.rbx = 0;
        guest_state.rcx = 0;
        guest_state.rdx = 0;
        return zx::ok();
      }
      // We support KVM clock.
      guest_state.rax = kKvmFeatureClockSourceOld | kKvmFeatureClockSource | kKvmFeatureNoIoDelay;
      guest_state.rbx = 0;
      guest_state.rcx = 0;
      guest_state.rdx = 0;
      return zx::ok();
    // From Volume 2A, CPUID instruction reference. If the EAX value is outside
    // the range recognized by CPUID then the information for the highest
    // supported base information leaf is returned. Any value in ECX is
    // honored.
    default:
      cpuid_c(MAX_SUPPORTED_CPUID, subleaf, reinterpret_cast<uint32_t*>(&guest_state.rax),
              reinterpret_cast<uint32_t*>(&guest_state.rbx),
              reinterpret_cast<uint32_t*>(&guest_state.rcx),
              reinterpret_cast<uint32_t*>(&guest_state.rdx));
      return zx::ok();
  }
}

zx::result<> handle_hlt(const ExitInfo& exit_info, AutoVmcs& vmcs,
                        LocalApicState& local_apic_state) {
  next_rip(exit_info, vmcs);

  // Complete a lazy EOI the guest took but this kernel has not yet reconciled,
  // BEFORE deciding to block. A lazy EOI is a silent guest-memory write (assist
  // word -> 0) with no VM exit, so the higher vector's in-service bit is still
  // set here and is still elevating the processor priority -- which blocks the
  // LOWER vector the guest halted to await. Reconciling clears that stale ISR
  // bit and drops the processor priority.
  guest_lazy_eoi_reconcile(local_apic_state);

  // Then, and only then, decide whether to block. Re-enter the guest WITHOUT
  // blocking iff reconciling just made a pending vector NEWLY DELIVERABLE: its
  // priority class now exceeds the (lowered) processor priority AND the guest is
  // interruptible. That single predicate covers both failure modes this fix
  // targets:
  //   * DEADLOCK (a halting guest): it lazy-EOI'd a high vector and awaits a
  //     lower one that has no pending signal of its own -- Wait would sleep on
  //     it forever. Reconcile drops the priority, the awaited vector is now
  //     deliverable, and re-entering lets local_apic_maybe_interrupt inject it.
  //   * LIVELOCK (a spinning/re-halting guest): the guest wakes, handles, lazy-
  //     EOIs and re-halts with an interrupt always pending. The predicate is
  //     deliverability, NOT mere presence, so a vector still blocked by ANOTHER
  //     in-service bit -- or the just-completed vector re-arriving while the
  //     priority is unchanged -- does NOT skip the block. Returning on bare
  //     Pending() (the earlier revision) is exactly what spun the Enter loop
  //     re-injecting an undeliverable/re-firing vector and made no forward
  //     progress; blocking here instead parks the VCPU until a signal actually
  //     changes something.
  // The class-vs-processor-priority test mirrors local_apic_maybe_interrupt's
  // own admission gate, so a return here is injected on the very next entry, and
  // a non-return is a vector that entry would have refused anyway.
  // The SHARED gate (vcpu_priv.h), not a second copy: see its comment for what
  // divergence between the two would cost.
  const bool interruptible = can_inject_external_int(vmcs);
  uint32_t pending_vector = 0;
  if (interruptible && local_apic_state.interrupt_tracker.Peek(&pending_vector) &&
      (pending_vector >> 4) > guest_ppr_class(local_apic_state)) {
    return zx::ok();
  }

  return local_apic_state.interrupt_tracker.Wait(ZX_TIME_INFINITE, &vmcs);
}

zx::result<> handle_cr0_write(AutoVmcs& vmcs, uint64_t val, LocalApicState& local_apic_state) {
  // Outside IA-32e mode a `MOV to CR0` carries a 32-bit operand, so the upper
  // half of the guest's RAX is not part of the value -- it is whatever the guest
  // last left there. This is load-bearing because the write this function
  // now sees first is an AP's, made in 16-bit real mode, and passing stale high
  // bits through to `cr0_is_invalid` would reject a legal mode transition and
  // halt the VP.
  if ((vmcs.Read(VmcsField64::GUEST_IA32_EFER) & X86_EFER_LMA) == 0) {
    val &= UINT32_MAX;
  }
  local_apic_state.cr0_write_exits++;

  // X86_CR0_NE is masked so that guests may write to it, but depending on
  // IA32_VMX_CR0_FIXED0 it might be unsupported in VMX operation to set it to
  // zero. Allow the guest to control its value in CR0_READ_SHADOW but not in
  // GUEST_CR0 so that GUEST_CR0 stays valid.
  uint64_t cr0 = val | X86_CR0_NE;
  if (cr0_is_invalid(vmcs, cr0)) {
    return zx::error(ZX_ERR_INVALID_ARGS);
  }

  // From Volume 3, Table 11-5: CD=0 and NW=1 is an invalid setting and should
  // generate a GP fault.
  if (!(val & X86_CR0_CD) && (val & X86_CR0_NW)) {
    local_apic_state.interrupt_tracker.Interrupt<X86_INT_GP_FAULT>();
    return zx::ok();
  }

  // If CR0.PG is being changed, then invalidate the VPID.
  uint64_t cr0_changed = val ^ vmcs.Read(VmcsFieldXX::GUEST_CR0);
  if (cr0_changed & X86_CR0_PG) {
    uint16_t vpid = vmcs.Read(VmcsField16::VPID);
    invvpid(InvVpid::SINGLE_CONTEXT, vpid, 0);
  }

  // From Volume 3, Section 26.3.2.1: CR0 is loaded from the CR0 field with the
  // exception of the following bits, which are never modified on VM entry: ET
  // (bit 4); reserved bits ...; NW (bit 29) and CD (bit 30). The values of
  // these bits in the CR0 field are ignored.
  //
  // Even though these bits will be ignored on VM entry, to ensure that
  // GUEST_CR0 matches the actual value of CR0 while the guest is running set
  // those bits to match the host values. This is done only to make debugging
  // simpler.
  cr0 &= ~(X86_CR0_NW | X86_CR0_CD);
  cr0 |= X86_CR0_ET;
  vmcs.Write(VmcsFieldXX::GUEST_CR0, cr0);

  // From Volume 3, Section 25.3: For each position corresponding to a bit clear
  // in the CR0 guest/host mask, the destination operand is loaded with the
  // value of the corresponding bit in CR0. For each position corresponding to a
  // bit set in the CR0 guest/host mask, the destination operand is loaded with
  // the value of the corresponding bit in the CR0 read shadow.
  //
  // Allow the guest to control the shadow.
  vmcs.Write(VmcsFieldXX::CR0_READ_SHADOW, val);

  // From Volume 3, Section 26.3.1.1: If CR0.PG and EFER.LME are set then
  // EFER.LMA and the IA-32e mode guest entry control must also be set.
  //
  // `CR0_GUEST_HOST_MASK` includes PG, so an AP
  // that turns on paging gets here instead of doing it behind the hypervisor's
  // back. Two things had to change with it.
  //
  // 1. THE TRANSITION IS SYMMETRIC. Clearing PG (or LME) while LMA is still set
  //    leaves exactly the same inconsistency in the other direction, and the
  //    next VM entry fails the same check. The early return used to walk away
  //    from that case.
  // 2. `SetControl` REBUILDS THE WHOLE FIELD -- it writes
  //    `allowed_0 | defaults | set`, where `defaults` comes from its `old_msr`
  //    argument. Passing the capability MSR there, as this did, means every
  //    control the VMCS was configured with that is neither required-1 nor named
  //    in `set` is DROPPED: on the entry controls that is load-IA32_PAT and
  //    load-IA32_EFER, so the first mode transition would have silently handed
  //    the guest the HOST's PAT and EFER from then on. Passing the field's
  //    CURRENT value instead preserves what is already set, which is the idiom
  //    `vmcs_init` already uses for its incremental PROCBASED_CTLS2 writes.
  //    Latent until now only because this function never ran.
  const uint64_t efer = vmcs.Read(VmcsField64::GUEST_IA32_EFER);
  const bool long_mode = (efer & X86_EFER_LME) != 0 && (cr0 & X86_CR0_PG) != 0;
  vmcs.Write(VmcsField64::GUEST_IA32_EFER,
             long_mode ? (efer | X86_EFER_LMA) : (efer & ~X86_EFER_LMA));
  return vmcs.SetControl(VmcsField32::ENTRY_CTLS, read_msr(X86_MSR_IA32_VMX_TRUE_ENTRY_CTLS),
                         vmcs.Read(VmcsField32::ENTRY_CTLS),
                         long_mode ? kEntryCtls64bitMode : 0, long_mode ? 0 : kEntryCtls64bitMode);
}

zx::result<uint64_t> register_value(AutoVmcs& vmcs, const GuestState& guest_state,
                                    uint8_t register_id) {
  switch (register_id) {
    // From Intel Volume 3, Table 27-3.
    case 0:
      return zx::ok(guest_state.rax);
    case 1:
      return zx::ok(guest_state.rcx);
    case 2:
      return zx::ok(guest_state.rdx);
    case 3:
      return zx::ok(guest_state.rbx);
    case 4:
      return zx::ok(vmcs.Read(VmcsFieldXX::GUEST_RSP));
    case 5:
      return zx::ok(guest_state.rbp);
    case 6:
      return zx::ok(guest_state.rsi);
    case 7:
      return zx::ok(guest_state.rdi);
    case 8:
      return zx::ok(guest_state.r8);
    case 9:
      return zx::ok(guest_state.r9);
    case 10:
      return zx::ok(guest_state.r10);
    case 11:
      return zx::ok(guest_state.r11);
    case 12:
      return zx::ok(guest_state.r12);
    case 13:
      return zx::ok(guest_state.r13);
    case 14:
      return zx::ok(guest_state.r14);
    case 15:
      return zx::ok(guest_state.r15);
    default:
      return zx::error(ZX_ERR_INVALID_ARGS);
  }
}

zx::result<> handle_control_register_access(const ExitInfo& exit_info, AutoVmcs& vmcs,
                                            const GuestState& guest_state,
                                            LocalApicState& local_apic_state) {
  const CrAccessInfo cr_access_info(vmcs.Read(VmcsFieldXX::EXIT_QUALIFICATION));
  switch (cr_access_info.access_type) {
    case CrAccessType::MOV_TO_CR: {
      // Handle CR0 only.
      if (cr_access_info.cr_number != 0) {
        return zx::error(ZX_ERR_NOT_SUPPORTED);
      }
      auto val = register_value(vmcs, guest_state, cr_access_info.reg);
      if (val.is_error()) {
        return val.take_error();
      }
      auto result = handle_cr0_write(vmcs, *val, local_apic_state);
      if (result.is_error()) {
        return result.take_error();
      }
      next_rip(exit_info, vmcs);
      return zx::ok();
    }
    default:
      return zx::error(ZX_ERR_NOT_SUPPORTED);
  }
}

zx::result<> handle_io_instruction(const ExitInfo& exit_info, AutoVmcs& vmcs,
                                   GuestState& guest_state, hypervisor::TrapMap& traps,
                                   zx_port_packet_t& packet, UnhandledIoLog& unhandled_io) {
  const IoInfo io_info(vmcs.Read(VmcsFieldXX::EXIT_QUALIFICATION));
  if (io_info.string || io_info.repeat) {
    dprintf(INFO, "hypervisor: Unsupported guest IO instruction\n");
    return zx::error(ZX_ERR_NOT_SUPPORTED);
  }

  zx::result<hypervisor::Trap*> trap = traps.FindTrap(ZX_GUEST_TRAP_IO, io_info.port);
  if (trap.is_error()) {
    // I/O exiting here is unconditional -- there are no I/O bitmaps -- so
    // this arm is reached for EVERY port the VMM did not register, and it used
    // to return ZX_ERR_NOT_FOUND, which the epilogue turns into a halt. A guest
    // that touched port 0x80 to burn a microsecond died for it.
    //
    // The default is what an unclaimed port does on the physical bus: nothing
    // drives it, so a read floats to all-ones and a write is lost. Note what
    // that means and why the announcement below is not optional -- all-ones has
    // every status bit SET, so absent hardware reads back as hardware that is
    // present, ready and finished. Handing the guest that value silently would
    // trade a loud failure for a quiet lie.
    //
    // Deliberately NOT a #GP: `IN`/`OUT` to an unclaimed port is not an
    // architectural fault on x86 (the guest is at IOPL, and the I/O permission
    // bitmap is the only thing that faults), so injecting one would invent a
    // fault real hardware never delivers.
    // Masked to the access width in BOTH directions. An OUT only writes the low
    // 1/2/4 bytes of RAX, so recording the whole register would put bits in the
    // log that were never part of the access -- a log that reports something the
    // guest did not do is worse than one that reports less.
    const uint64_t width_mask = unclaimed_io_read_value(io_info.access_size);
    const uint64_t value =
        io_info.input ? width_mask : (guest_state.rax & width_mask);
    announce_unhandled_io(unhandled_io, io_info.port, exit_info.guest_rip, io_info.input,
                          io_info.access_size, value);
    next_rip(exit_info, vmcs);
    if (io_info.input) {
      // Same width rule as the trapped path below: a 32-bit IN zero-extends to
      // the full 64-bit register, a narrower one leaves the upper bytes alone.
      if (io_info.access_size == 4) {
        guest_state.rax = value;
      } else {
        memcpy(&guest_state.rax, &value, io_info.access_size);
      }

    }
    return zx::ok();
  }
  next_rip(exit_info, vmcs);

  memset(&packet, 0, sizeof(packet));
  packet.key = (*trap)->key();
  packet.type = ZX_PKT_TYPE_GUEST_IO;
  packet.guest_io.port = io_info.port;
  packet.guest_io.access_size = io_info.access_size;
  packet.guest_io.input = io_info.input;
  if (io_info.input) {
    // From Volume 1, Section 3.4.1.1: 32-bit operands generate a 32-bit
    // result, zero-extended to a 64-bit result in the destination general-
    // purpose register.
    if (io_info.access_size == 4) {
      guest_state.rax = 0;
    }
  } else {
    memcpy(packet.guest_io.data, &guest_state.rax, io_info.access_size);
    if ((*trap)->HasPort()) {
      return (*trap)->Queue(packet, &vmcs);
    }
    // If there was no port for the range, then return to user-space.
  }

  return zx::error(ZX_ERR_NEXT);
}

// Defined next to the rest of the APIC-timer arithmetic, below.
uint32_t current_count(LocalApicState& local_apic_state);

// The 32 pending vectors starting at |base|, with generated exceptions removed
// -- the x2APIC IRR's view of the interrupt tracker.
//
// The tracker doubles as the queue for exceptions the VMM generates (a #GP from
// an unhandled MSR, say), and those did not come from the APIC; reporting them
// as APIC interrupt requests would be a fabrication, and vectors 0-15 are
// architecturally illegal as requests in any case.
//
// The bare interrupt ABI treats vectors above X86_INT_VIRT as asynchronous
// interrupts, including guest ICR vectors 21..31. Typed exceptions such as #CP
// live in the pending-event queue rather than this bitmap.
uint32_t requestable(LocalApicState& local_apic_state, uint32_t base) {
  constexpr uint32_t kFirstRequestable = X86_INT_VIRT + 1;
  if (base + 32u <= kFirstRequestable) {
    return 0;
  }
  const uint32_t bits = local_apic_state.interrupt_tracker.PendingWord(base);
  if (base >= kFirstRequestable) {
    return bits;
  }
  return bits & ~((uint32_t{1} << (kFirstRequestable - base)) - 1);
}

void handle_apic_rdmsr(const ExitInfo& exit_info, AutoVmcs& vmcs, GuestState& guest_state,
                       LocalApicState& local_apic_state) {
  switch (static_cast<X2ApicMsr>(guest_state.ecx())) {
    case X2ApicMsr::ID:
      next_rip(exit_info, vmcs);
      // Every arm of this switch uses `SetEdxEax` rather than assigning `rax`.
      // RDMSR architecturally defines *both* halves of EDX:EAX, and the x2APIC
      // registers other than the ICR are 32-bit, so EDX must read back as zero
      // rather than as whatever the guest happened to leave in it. Assigning
      // `rax` alone leaves a stale EDX, which a guest assembling a 64-bit value
      // out of EDX:EAX -- the normal shape of an RDMSR wrapper -- reads as
      // garbage in the top half.
      guest_state.SetEdxEax(vmcs.Read(VmcsField16::VPID) - 1);
      break;
    case X2ApicMsr::VERSION: {
      next_rip(exit_info, vmcs);
      // We choose 15H as it causes us to be seen as a modern APIC by Linux,
      // and is the highest non-reserved value. See Volume 3 Section 10.4.8.
      const uint32_t version = 0x15;
      const uint32_t max_lvt_entry = 0x6;  // LVT entries minus 1.
      const uint32_t eoi_suppression = 0;  // Disable support for EOI-broadcast suppression.
      guest_state.SetEdxEax(version | (max_lvt_entry << 16) | (eoi_suppression << 24));
      break;
    }
    case X2ApicMsr::SVR:
      // The value the guest last wrote, not the reset value. Answering with the
      // reset constant made every write to this register invisible, so a guest
      // that software-enabled its APIC (SVR bit 8) and read the register back to
      // confirm it was told the APIC was still disabled.
      next_rip(exit_info, vmcs);
      guest_state.SetEdxEax(local_apic_state.svr);
      break;
    case X2ApicMsr::LDR:
      // Unlike xAPIC, the x2APIC LDR is read-only and is derived from the APIC
      // ID rather than reset to 0. See Volume 3 Section 10.12.10.2. Writes stay
      // unhandled below, which is what makes them #GP.
      next_rip(exit_info, vmcs);
      guest_state.SetEdxEax(x2apic_logical_id(vmcs.Read(VmcsField16::VPID) - 1u));
      break;
    case X2ApicMsr::TPR:
      // The task-priority register is not hypervisor-side state: with "use TPR
      // shadow" set, the processor services the guest's `MOV to/from CR8`
      // against VTPR in the virtual-APIC page without ever exiting. CR8 and this
      // MSR are two views of the same architectural register (CR8 is TPR bits
      // 7:4), so answering this read with a constant 0 — which is what happened
      // before the virtual-APIC page existed — told a guest that had raised its
      // priority through CR8 that it had not.
      next_rip(exit_info, vmcs);
      guest_state.SetEdxEax(guest_tpr_read(local_apic_state));
      break;
    case X2ApicMsr::PPR:
      // The processor priority: the guest's own view of the priority its
      // interrupts are being arbitrated against. This register was absent from
      // the X2ApicMsr enum entirely, so reading it took a #GP -- the register
      // whose whole purpose is interrupt priority, on a hypervisor that had no
      // interrupt priority to report.
      next_rip(exit_info, vmcs);
      guest_state.SetEdxEax(guest_ppr(local_apic_state));
      break;
    case X2ApicMsr::APR: {
      next_rip(exit_info, vmcs);
      // The arbitration priority needs the highest *requested* vector, which
      // lives in the interrupt tracker rather than in LocalApicState's own
      // fields; scan it here and hand it to the derivation.
      uint32_t irrv = 0;
      for (int word = 7; word >= 0; word--) {
        const uint32_t base = static_cast<uint32_t>(word) * 32u;
        const uint32_t bits = requestable(local_apic_state, base);
        if (bits != 0) {
          irrv = base + 31u - static_cast<uint32_t>(__builtin_clz(bits));
          break;
        }
      }
      guest_state.SetEdxEax(guest_apr(local_apic_state, irrv));
      break;
    }
    case X2ApicMsr::ISR_31_0... X2ApicMsr::ISR_255_224: {
      // Real in-service bits, which is what makes an EOI mean something. These
      // read 0 unconditionally before, so a guest could not tell whether it was
      // inside an interrupt at all.
      next_rip(exit_info, vmcs);
      const uint32_t index =
          guest_state.ecx() - static_cast<uint32_t>(X2ApicMsr::ISR_31_0);
      guest_state.SetEdxEax(local_apic_state.isr[index]);
      break;
    }
    case X2ApicMsr::IRR_31_0... X2ApicMsr::IRR_255_224: {
      // The interrupt-request register is "requested and not yet accepted",
      // which for this hypervisor is exactly the interrupt tracker's bitmap.
      //
      // Generated exceptions (through X86_INT_VIRT) are masked: they did not
      // come from the APIC, so reporting them as APIC requests would be a
      // fabrication. Bare vectors 21..31 are retained because they are guest
      // ICR/device requests; typed #CP does not use this bitmap.
      next_rip(exit_info, vmcs);
      const uint32_t index =
          guest_state.ecx() - static_cast<uint32_t>(X2ApicMsr::IRR_31_0);
      const uint32_t base = index * 32u;
      guest_state.SetEdxEax(requestable(local_apic_state, base));
      break;
    }
    case X2ApicMsr::TMR_31_0... X2ApicMsr::TMR_255_224:
    case X2ApicMsr::ESR:
      // The trigger-mode register records, per vector, whether the interrupt
      // that was accepted was level-triggered. Every interrupt this hypervisor
      // delivers is edge-triggered -- there is no IOAPIC behind it and the
      // sources are the ICR, the self-IPI register, the LVT timer and the VMM's
      // own injection ABI, all of which are edge -- so 0 is the honest answer
      // rather than a stub. The error-status register likewise reports the
      // errors this APIC can raise, which is none.
      next_rip(exit_info, vmcs);
      guest_state.SetEdxEax(0);
      break;
    case X2ApicMsr::LVT_MONITOR:
      next_rip(exit_info, vmcs);
      guest_state.SetEdxEax(local_apic_state.lvt_monitor);
      break;
    case X2ApicMsr::LVT_LINT0:
      next_rip(exit_info, vmcs);
      guest_state.SetEdxEax(local_apic_state.lvt_lint0);
      break;
    case X2ApicMsr::LVT_LINT1:
      next_rip(exit_info, vmcs);
      guest_state.SetEdxEax(local_apic_state.lvt_lint1);
      break;
    case X2ApicMsr::LVT_THERMAL_SENSOR:
      next_rip(exit_info, vmcs);
      guest_state.SetEdxEax(local_apic_state.lvt_thermal);
      break;
    case X2ApicMsr::LVT_CMCI:
      next_rip(exit_info, vmcs);
      guest_state.SetEdxEax(local_apic_state.lvt_cmci);
      break;
    case X2ApicMsr::LVT_ERROR:
      // Architecturally read/write. It was writable and not readable, so a
      // read-modify-write of it -- the shape of every mask/unmask -- faulted on
      // the read.
      next_rip(exit_info, vmcs);
      guest_state.SetEdxEax(local_apic_state.lvt_error);
      break;
    case X2ApicMsr::LVT_TIMER:
      next_rip(exit_info, vmcs);
      guest_state.SetEdxEax(local_apic_state.lvt_timer);
      break;
    case X2ApicMsr::INITIAL_COUNT:
      // Also read/write, also previously write-only.
      next_rip(exit_info, vmcs);
      guest_state.SetEdxEax(local_apic_state.lvt_initial_count);
      break;
    case X2ApicMsr::DCR:
      next_rip(exit_info, vmcs);
      guest_state.SetEdxEax(local_apic_state.lvt_divide_config);
      break;
    case X2ApicMsr::CURRENT_COUNT:
      // Read-only, and previously absent: a guest calibrating its local timer
      // reads this, and took a #GP for it. Derived from the deadline the timer
      // is actually armed to, run back through the same divide the initial count
      // was scaled by, so the two agree.
      next_rip(exit_info, vmcs);
      guest_state.SetEdxEax(current_count(local_apic_state));
      break;
    case X2ApicMsr::ICR:
      // In x2APIC the ICR is a single 64-bit read/write register (Volume 3,
      // Section 10.12.9), not the xAPIC pair. The write is acted on when it
      // happens; this hands back what was written so that a read-modify-write
      // does not fault. Bit 12, delivery status, always reads 0: by the time the
      // guest can read this register the IPI has already been handed on, so it
      // is never "send pending".
      next_rip(exit_info, vmcs);
      guest_state.SetEdxEax(local_apic_state.icr & ~(uint64_t{1} << 12));
      break;
    default:
      // Issue a general protection fault for write only and unimplemented
      // registers.
      dprintf(INFO, "hypervisor: Unhandled guest x2APIC RDMSR %#lx\n", guest_state.rcx);
      local_apic_state.interrupt_tracker.Interrupt<X86_INT_GP_FAULT>();
      break;
  }
}

// Surfaces an MSR access to the VMM. The instruction pointer is advanced first,
// so a read is completed by writing the value the guest should see into rax/rdx
// before the next entry — the same completion shape as an I/O read.
zx::result<> delegate_msr(const ExitInfo& exit_info, AutoVmcs& vmcs, const GuestState& guest_state,
                          bool is_write, zx_port_packet_t& packet) {
  next_rip(exit_info, vmcs);
  memset(&packet, 0, sizeof(packet));
  packet.type = ZX_PKT_TYPE_GUEST_MSR;
  packet.guest_msr.msr = guest_state.ecx();
  packet.guest_msr.value = is_write ? guest_state.EdxEax() : 0;
  packet.guest_msr.is_write = is_write;
  return zx::error(ZX_ERR_NEXT);
}

zx::result<> handle_rdmsr(const ExitInfo& exit_info, AutoVmcs& vmcs, GuestState& guest_state,
                          LocalApicState& local_apic_state, bool delegate_synthetic_msrs,
                          int64_t tsc_offset, zx_port_packet_t& packet,
                          UnhandledMsrLog& unhandled_msrs) {
  // A claimed synthetic register belongs to the VMM, so it is surfaced before
  // the kernel's own handling; the block is disjoint from every register handled
  // below, so this only ever diverts accesses that would otherwise fault.
  if (delegate_synthetic_msrs && guest_state.ecx() >= kSyntheticMsrBase &&
      guest_state.ecx() <= kSyntheticMsrMax) {
    return delegate_msr(exit_info, vmcs, guest_state, /*is_write=*/false, packet);
  }
  // On execution of rdmsr, ecx specifies the MSR and the result is stored in edx:eax.
  switch (guest_state.ecx()) {
    case X86_MSR_IA32_APIC_BASE: {
      next_rip(exit_info, vmcs);
      uint64_t result =
          local_apic_state.x2apic_enabled ? kLocalApicX2apicBase : kLocalApicXapicBase;
      if (vmcs.Read(VmcsField16::VPID) == 1) {
        result |= IA32_APIC_BASE_BSP;
      }
      guest_state.SetEdxEax(result);
      break;
    }
    // From Volume 3, Section 18.17: IA32_TIME_STAMP_COUNTER is the same counter
    // RDTSC reads, and RDTSC is *not* configured to exit here — no VMCS control
    // in this file sets "RDTSC exiting", and no TSC offset is programmed, so a
    // guest already reads the host's TSC directly and freely. Refusing the
    // architectural MSR form of a read the guest can perform anyway with one
    // instruction is a gap, not a policy: it leaks nothing and denies nothing,
    // it only turns a legal instruction into a #GP.
    //
    // This was not hypothetical. The `mu_msvm` UEFI firmware executes RDMSR
    // 0x10 while booting a Windows guest; the injected #GP reached its fatal
    // path, which reset the machine by loading a null IDT and executing UD2 —
    // so the whole boot ended in a triple fault whose only visible cause was one
    // `Unhandled guest RDMSR 0x10` line.
    //
    // Writes deliberately stay unhandled and therefore still #GP: a guest that
    // could WRMSR this register would move the *host's* time base.
    //
    // Adding `tsc_offset` keeps this register agreeing with the RDTSC
    // the paragraph above says the guest can execute anyway. The processor adds
    // VMCS TSC_OFFSET to RDTSC/RDTSCP itself; this read is emulated, so it has to
    // do the same by hand. Without it the two forms of the same counter would
    // differ by the offset -- a guest that calibrated with one and timed with the
    // other would be wrong by however far apart the epochs are.
    case X86_MSR_IA32_TSC:
      next_rip(exit_info, vmcs);
      guest_state.SetEdxEax(_rdtsc() + static_cast<uint64_t>(tsc_offset));
      break;
    // See kGuestMiscEnable for the value and, more importantly, for why it is
    // not the reference backend's 0x851809.
    case X86_MSR_IA32_MISC_ENABLE:
      next_rip(exit_info, vmcs);
      guest_state.SetEdxEax(kGuestMiscEnable);
      break;
    // Windows reads this early for VMX/SMX/SGX capability, and a VMM that leaves
    // it at 0 is telling the guest the register was never locked by firmware --
    // which on real hardware means the platform is still configurable. Report it
    // locked, with the VMX-outside-SMX enable CLEAR, because handle_cpuid also
    // clears CPUID.1:ECX.VMX: claiming VMX here while denying it there is the
    // same incoherence kGuestMiscEnable exists to avoid.
    case kMsrIa32FeatureControl:
      next_rip(exit_info, vmcs);
      guest_state.SetEdxEax(kFeatureControlLock);
      break;
    // The value already lives in the VMCS and is hardware-swapped around VM
    // entry, so this reads back exactly what took effect -- including the bits
    // the write handler declined to honour.
    case kMsrIa32Debugctl:
      next_rip(exit_info, vmcs);
      guest_state.SetEdxEax(vmcs.Read(VmcsField64::GUEST_IA32_DEBUGCTL));
      break;
    // We advertise TSC-deadline in CPUID unconditionally and have always handled
    // the WRITE, so refusing the READ was a self-inflicted asymmetry: a guest
    // that reads its own deadline back -- or read-modify-writes it -- took a
    // #GP. Outside TSC-deadline mode the register is architecturally inert and
    // reads zero (this is also what KVM's kvm_get_lapic_tscdeadline_msr does).
    case X86_MSR_IA32_TSC_DEADLINE:
      next_rip(exit_info, vmcs);
      guest_state.SetEdxEax(
          (local_apic_state.lvt_timer & LVT_TIMER_MODE_MASK) == LVT_TIMER_MODE_TSC_DEADLINE
              ? local_apic_state.tsc_deadline
              : 0);
      break;
    // Writes here are already ignored (see handle_wrmsr), so 0 -- "nothing took
    // effect" -- is the answer consistent with that, and CPUID clears
    // IBRS/STIBP/SSBD so a well-behaved guest will not ask.
    case X86_MSR_IA32_SPEC_CTRL:
    // The legacy P6 BBL_CR_* family; see the constants.
    case kMsrBblCrD0:
    case kMsrBblCrD1:
    case kMsrBblCrD2:
    case kMsrBblCrAddr:
    case kMsrBblCrDecc:
    case kMsrBblCrCtl:
    case kMsrBblCrTrig:
    case kMsrBblCrBusy:
    case kMsrBblCrCtl3:
    // No virtual uncore PMU is exposed.  Report its event selector disabled,
    // independent of whether the physical CPU happens to implement this
    // model-specific register.  That also keeps snapshots migratable.
    case kMsrUncoreCbox5First ... kMsrUncoreCbox5Last:
      next_rip(exit_info, vmcs);
      guest_state.SetEdxEax(0);
      break;
    case X86_MSR_DRAM_ENERGY_STATUS:
    case X86_MSR_DRAM_POWER_LIMIT:
    // From Volume 3, Section 28.2.6.2: The MTRRs have no effect on the memory
    // type used for an access to a guest-physical address.
    case X86_MSR_IA32_MTRRCAP:
    case X86_MSR_IA32_MTRR_DEF_TYPE:
    case X86_MSR_IA32_MTRR_FIX64K_00000:
    case X86_MSR_IA32_MTRR_FIX16K_80000 ... X86_MSR_IA32_MTRR_FIX16K_A0000:
    case X86_MSR_IA32_MTRR_FIX4K_C0000 ... X86_MSR_IA32_MTRR_FIX4K_F8000:
    case X86_MSR_IA32_MTRR_PHYSBASE0 ... X86_MSR_IA32_MTRR_PHYSMASK9:
    // From Volume 3, Section 9.11.4: For now, 0.
    case X86_MSR_IA32_PLATFORM_ID:
    // From Volume 3, Section 9.11.7: 0 indicates no microcode update is loaded.
    case X86_MSR_IA32_BIOS_SIGN_ID:
    // From Volume 3, Section 15.3.1: 0 indicates that our machine has no
    // checking capabilities.
    case X86_MSR_IA32_MCG_CAP:
    case X86_MSR_IA32_MCG_STATUS:
    case X86_MSR_IA32_TEMPERATURE_TARGET:
    case X86_MSR_PKG_ENERGY_STATUS:
    case X86_MSR_PLATFORM_ENERGY_COUNTER:
    case X86_MSR_PLATFORM_POWER_LIMIT:
    case X86_MSR_PP0_ENERGY_STATUS:
    case X86_MSR_PP0_POWER_LIMIT:
    case X86_MSR_PP1_ENERGY_STATUS:
    case X86_MSR_PP1_POWER_LIMIT:
    case X86_MSR_RAPL_POWER_UNIT:
    // From Volume 3, Section 14.2: We've configured CPUID to report no MPERF/APERF
    // support, but Linux attempts to read stats anyhow. Just ignore it.
    case X86_MSR_PPERF:
    // From Volume 4, Table 2-15: Number of SMI interrupts since boot.
    // We report 0 interrupts.
    case X86_MSR_SMI_COUNT:
      next_rip(exit_info, vmcs);
      guest_state.SetEdxEax(0);
      break;
    case kX2ApicMsrBase ... kX2ApicMsrMax:
      if (!local_apic_state.x2apic_enabled) {
        local_apic_state.interrupt_tracker.Interrupt<X86_INT_GP_FAULT>();
      } else {
        handle_apic_rdmsr(exit_info, vmcs, guest_state, local_apic_state);
      }
      break;
    default: {
      // Deliberately not `next_rip`: the guest RIP stays on the RDMSR, which is
      // both what a #GP requires and what makes the RIP in the line below the
      // address of the faulting instruction rather than the one after it.
      const bool injected =
          local_apic_state.interrupt_tracker.Interrupt(X86_INT_GP_FAULT).is_ok();
      announce_unhandled_msr(unhandled_msrs, guest_state.ecx(), exit_info.guest_rip,
                             /*is_write=*/false, /*value=*/0, injected);
      break;
    }
  }
  return zx::ok();
}

zx_instant_mono_t lvt_deadline(LocalApicState& local_apic_state) {
  if ((local_apic_state.lvt_timer & LVT_TIMER_MODE_MASK) != LVT_TIMER_MODE_ONESHOT &&
      (local_apic_state.lvt_timer & LVT_TIMER_MODE_MASK) != LVT_TIMER_MODE_PERIODIC) {
    return 0;
  }
  // Volume 3, Section 11.5.4: "A write of 0 to the initial-count register
  // effectively stops the local APIC timer, in both one-shot and periodic mode."
  // Without this the arithmetic below produces a duration of zero, i.e. a
  // deadline of *now*, and the timer fires at once — so a guest that programs
  // LVT_TIMER (choosing a vector and one-shot mode) before it programs the
  // initial count, which is the natural order and what Linux does, is handed a
  // spurious interrupt on that vector immediately, before it has armed
  // anything. That is a race against the guest's next few instructions: it is
  // lost more often the slower the guest runs, which is why it shows up on real
  // silicon and not under KVM.
  if (local_apic_state.lvt_initial_count == 0) {
    return 0;
  }
  uint32_t shift = BITS_SHIFT(local_apic_state.lvt_divide_config, 1, 0) |
                   (BIT_SHIFT(local_apic_state.lvt_divide_config, 3) << 2);
  uint32_t divisor_shift = (shift + 1) & 7;
  // The cast is BEFORE the shift, and that is the whole point. `lvt_initial_count`
  // is a uint32_t, so shifting it first does the arithmetic in 32 bits and throws
  // the high bits away: an initial count of 0xFFFFFFFF with divide-by-16 became
  // 0xFFFFFFF0 rather than 0xFFFFFFFF0, and every divide configuration other
  // than 1 silently produced a deadline up to `divisor` times too EARLY. A guest
  // calibrating against divide-by-128 got its interrupt 128x sooner than it
  // asked for, which is indistinguishable from a mis-measured APIC frequency and
  // is exactly the kind of thing that looks like a guest bug.
  //
  // Found by vcpu_async_state_restored_timer_reaches_guest_idt, which asks for a
  // deadline tens of seconds out and got 1.77 s.
  int64_t duration_tsc_ticks =
      static_cast<int64_t>(local_apic_state.lvt_initial_count) << divisor_shift;
  zx_duration_t duration = convert_raw_tsc_duration_to_nanoseconds(duration_tsc_ticks);
  // Record the same deadline in raw ticks. This is the only place the tick
  // duration exists, and it is what the guest's CURRENT_COUNT read is answered
  // from -- the monotonic deadline returned below is far too coarse for that.
  // See LocalApicState::timer_tsc_deadline.
  local_apic_state.timer_tsc_deadline = _rdtsc() + static_cast<uint64_t>(duration_tsc_ticks);
  return zx_time_add_duration(current_mono_time(), duration);
}

// The APIC timer's current count (x2APIC MSR 0x839, read-only).
//
// This hypervisor does not model an APIC-frequency counter; it arms a host timer
// at a deadline computed from the initial count and the divide configuration. So
// the current count is reconstructed from that deadline rather than counted
// down. Doing it that way means the value a guest reads always agrees with the
// interrupt it is going to get, which is what a calibration loop is actually
// measuring -- a free-running counter derived independently would drift against
// the timer that fires.
//
// It is reconstructed from the *tick* deadline, not the monotonic one. The
// monotonic clock has millisecond granularity here (measured), and the count
// derived from it did not change at all between two guest reads tens of
// microseconds apart -- a register that never moves is indistinguishable from a
// stopped timer, which is the failure the read was added to avoid. The APIC
// timer is a scaled TSC anyway: the remaining raw tick count shifted down by the
// divide configuration *is* the current count, exactly inverting the arithmetic
// `lvt_deadline` used to arm it.
//
// The monotonic fallback below is reached only after a snapshot restore, which
// reconstructs a deadline without a tick counterpart. It is coarse -- and says
// so -- but a coarse count is better than none, and the alternative on that path
// is to claim the timer is stopped.
//
// Zero when the timer is disarmed, which Volume 3, Section 11.5.4 also gives as
// the value after a one-shot has expired.
uint32_t current_count(LocalApicState& local_apic_state) {
  if (local_apic_state.timer_deadline == 0 || local_apic_state.lvt_initial_count == 0) {
    return 0;
  }
  const uint32_t shift = BITS_SHIFT(local_apic_state.lvt_divide_config, 1, 0) |
                         (BIT_SHIFT(local_apic_state.lvt_divide_config, 3) << 2);
  const uint32_t divisor_shift = (shift + 1) & 7;

  if (local_apic_state.timer_tsc_deadline != 0) {
    const uint64_t now_ticks = _rdtsc();
    if (now_ticks >= local_apic_state.timer_tsc_deadline) {
      return 0;
    }
    const uint64_t count =
        (local_apic_state.timer_tsc_deadline - now_ticks) >> divisor_shift;
    return count > local_apic_state.lvt_initial_count
               ? local_apic_state.lvt_initial_count
               : static_cast<uint32_t>(count);
  }

  const zx_instant_mono_t now = current_mono_time();
  if (now >= local_apic_state.timer_deadline) {
    return 0;
  }
  const zx_duration_t total = convert_raw_tsc_duration_to_nanoseconds(
      static_cast<int64_t>(local_apic_state.lvt_initial_count) << divisor_shift);
  if (total <= 0) {
    return 0;
  }
  const uint64_t remaining = static_cast<uint64_t>(local_apic_state.timer_deadline - now);
  const uint64_t count =
      (static_cast<uint64_t>(local_apic_state.lvt_initial_count) * remaining) /
      static_cast<uint64_t>(total);
  return count > local_apic_state.lvt_initial_count
             ? local_apic_state.lvt_initial_count
             : static_cast<uint32_t>(count);
}

void update_timer(LocalApicState& local_apic_state, zx_instant_mono_t deadline);

void deadline_callback(Timer* timer, zx_instant_mono_t now, void* arg) {
  auto& local_apic_state = *static_cast<LocalApicState*>(arg);
  // The armed deadline has now passed, so the timer is no longer armed. Clear
  // the shadow (see LocalApicState::timer_deadline) before deciding whether to
  // rearm: only the periodic path below puts a new deadline back. Without this a
  // snapshot taken after a one-shot fired would capture it as still armed with
  // zero time remaining, and restore would fire it a second time.
  local_apic_state.timer_deadline = 0;
  if (local_apic_state.lvt_timer & LVT_MASKED) {
    return;
  }
  if ((local_apic_state.lvt_timer & LVT_TIMER_MODE_MASK) == LVT_TIMER_MODE_PERIODIC) {
    update_timer(local_apic_state, lvt_deadline(local_apic_state));
  }
  uint8_t vector = local_apic_state.lvt_timer & LVT_TIMER_VECTOR_MASK;
  zx::result<> result = local_apic_state.interrupt_tracker.Interrupt(vector);
  ZX_ASSERT(result.is_ok());
}

void update_timer(LocalApicState& local_apic_state, zx_instant_mono_t deadline) {
  local_apic_state.timer.Cancel();
  // Shadow the armed deadline so a snapshot can capture the remaining time (see
  // LocalApicState::timer_deadline). 0 means disarmed.
  local_apic_state.timer_deadline = deadline > 0 ? deadline : 0;
  if (deadline > 0) {
    local_apic_state.timer.SetOneshot(deadline, deadline_callback, &local_apic_state);
  } else {
    // Disarmed, so the tick deadline `lvt_deadline` may have just written is
    // stale. Cleared here rather than there because this is the function that
    // owns "is the timer armed".
    local_apic_state.timer_tsc_deadline = 0;
  }
}

uint64_t ipi_target_mask(const InterruptCommandRegister& icr, uint16_t self,
                         bool x2apic_enabled) {
  DEBUG_ASSERT(self < Guest::kMaxGuestVcpus);

  switch (icr.destination_shorthand) {
    case InterruptDestinationShorthand::NO_SHORTHAND: {
      // Intel Volume 3, Section 10.12.9: A destination ID value of FFFF_FFFFH
      // is used for broadcast of interrupts in both logical destination and
      // physical destination modes.
      const uint32_t broadcast =
          x2apic_enabled ? kIpiBroadcastDestination : static_cast<uint32_t>(UINT8_MAX);
      if (icr.destination == broadcast) {
        return UINT64_MAX;
      }

      // In logical destination mode the destination is a cluster ID plus a
      // per-VCPU bitmask, not a VCPU index.
      if (icr.destination_mode == InterruptDestinationMode::LOGICAL) {
        // The xAPIC flat model uses its 8-bit destination directly as a
        // per-processor mask. x2APIC uses the cluster encoding.
        return x2apic_enabled ? x2apic_logical_target_mask(icr.destination)
                              : static_cast<uint64_t>(icr.destination & UINT8_MAX);
      }

      // If an invalid destination was provided, just return the empty mask.
      if (unlikely(icr.destination >= Guest::kMaxGuestVcpus)) {
        return 0;
      }

      // Otherwise, generate a mask for the target VCPU.
      return uint64_t{1} << icr.destination;
    }
    case InterruptDestinationShorthand::SELF:
      return uint64_t{1} << self;
    case InterruptDestinationShorthand::ALL_INCLUDING_SELF:
      return UINT64_MAX;
    case InterruptDestinationShorthand::ALL_EXCLUDING_SELF:
      return ~(uint64_t{1} << self);
  }

  return 0;
}

void complete_apic_access(const ExitInfo& exit_info, AutoVmcs& vmcs, bool advance_rip) {
  if (advance_rip) {
    next_rip(exit_info, vmcs);
  }
}

zx::result<> handle_ipi(const ExitInfo& exit_info, AutoVmcs& vmcs, const GuestState& guest_state,
                        zx_port_packet& packet, bool advance_rip, bool x2apic_enabled) {
  InterruptCommandRegister icr(guest_state.edx(), guest_state.eax());
  switch (icr.delivery_mode) {
    case InterruptDeliveryMode::FIXED: {
      uint16_t self = vmcs.Read(VmcsField16::VPID) - 1;
      memset(&packet, 0, sizeof(packet));
      packet.type = ZX_PKT_TYPE_GUEST_VCPU;
      packet.guest_vcpu.type = ZX_PKT_GUEST_VCPU_INTERRUPT;
      packet.guest_vcpu.interrupt.mask = ipi_target_mask(icr, self, x2apic_enabled);
      packet.guest_vcpu.interrupt.vector = icr.vector;
      complete_apic_access(exit_info, vmcs, advance_rip);
      return zx::error(ZX_ERR_NEXT);
    }
    case InterruptDeliveryMode::NMI: {
      uint16_t self = vmcs.Read(VmcsField16::VPID) - 1;
      memset(&packet, 0, sizeof(packet));
      packet.type = ZX_PKT_TYPE_GUEST_VCPU;
      packet.guest_vcpu.type = ZX_PKT_GUEST_VCPU_INTERRUPT;
      // Intel Volume 3a, Table 10-4 specifies that NMI to self is an invalid configuration and
      // behavior is undefined for invalid configurations.
      //
      // For simplicity we'll just clear the self-bit in the mask.
      packet.guest_vcpu.interrupt.mask =
          ipi_target_mask(icr, self, x2apic_enabled) & ~(uint64_t{1} << self);

      // Intel Volume 3a, Section 10.6.1 Interrupt Command Register.
      //
      // For NMI the target information is ignored since the NMI vector is already defined.
      packet.guest_vcpu.interrupt.vector = X86_INT_NMI;
      complete_apic_access(exit_info, vmcs, advance_rip);
      return zx::error(ZX_ERR_NEXT);
    }
    case InterruptDeliveryMode::INIT:
      // Ignore INIT IPIs, we only need STARTUP to bring up a VCPU.
      complete_apic_access(exit_info, vmcs, advance_rip);
      return zx::ok();
    case InterruptDeliveryMode::STARTUP:
      // The MP initialisation protocol (Volume 3, Section 8.4) addresses APs by
      // physical APIC ID, and `startup.id` is that ID. A logical destination has
      // no such ID, so refuse rather than hand the VMM a bogus VCPU index.
      if (icr.destination_mode == InterruptDestinationMode::LOGICAL) {
        dprintf(INFO, "hypervisor: STARTUP IPI with a logical destination is not supported\n");
        return zx::error(ZX_ERR_NOT_SUPPORTED);
      }
      memset(&packet, 0, sizeof(packet));
      packet.type = ZX_PKT_TYPE_GUEST_VCPU;
      packet.guest_vcpu.type = ZX_PKT_GUEST_VCPU_STARTUP;
      packet.guest_vcpu.startup.id = icr.destination;
      packet.guest_vcpu.startup.entry = icr.vector << 12;
      complete_apic_access(exit_info, vmcs, advance_rip);
      return zx::error(ZX_ERR_NEXT);
    default:
      dprintf(INFO, "hypervisor: Unsupported guest IPI delivery mode %#x\n",
              static_cast<uint8_t>(icr.delivery_mode));
      return zx::error(ZX_ERR_NOT_SUPPORTED);
  }
}

zx::result<> handle_apic_wrmsr(const ExitInfo& exit_info, AutoVmcs& vmcs,
                               const GuestState& guest_state, LocalApicState& local_apic_state,
                               const EoiBitmap& eoi_interest, zx_port_packet& packet,
                               bool advance_rip = true) {
  // Check for writes to reserved bits.
  //
  // From Volume 3, Section 10.12.1.2: "The upper 32-bits of all x2APIC MSRs
  // (except for the ICR) are reserved."
  X2ApicMsr reg = static_cast<X2ApicMsr>(guest_state.ecx());
  if (unlikely(guest_state.edx() != 0 && reg != X2ApicMsr::ICR)) {
    local_apic_state.interrupt_tracker.Interrupt<X86_INT_GP_FAULT>();
    return zx::ok();
  }

  switch (reg) {
    case X2ApicMsr::EOI:
      // From Volume 3, Section 10.12.1.2: "WRMSR of a non-zero value causes #GP(0)."
      if (guest_state.eax() != 0) {
        local_apic_state.interrupt_tracker.Interrupt<X86_INT_GP_FAULT>();
        return zx::ok();
      }
      complete_apic_access(exit_info, vmcs, advance_rip);
      // An EOI ends the highest-priority interrupt currently in service. This
      // used to be accepted and discarded -- there was no in-service register
      // for it to clear -- which meant that from the guest's side an interrupt
      // never ended, and from the hypervisor's side one had never begun.
      //
      // Nothing else is needed to get a vector that was waiting on this
      // delivered: WRMSR is a VM exit, so returning ZX_OK here re-enters through
      // Vcpu::Enter, and `local_apic_maybe_interrupt` re-derives the processor
      // priority -- now lower -- and injects on that very entry.
      //
      // The completed vector is also the one fact a userspace IO-APIC needs and
      // cannot otherwise learn: a level-triggered line sets `remote IRR` on
      // delivery and refuses to deliver again until an EOI clears it, and the
      // EOI is consumed here, in the kernel, where that device cannot see it.
      // Surfacing it is what ZX_PKT_TYPE_GUEST_EOI is for.
      //
      // Gated, and this gate is load-bearing rather than tidy: an EOI is the
      // last instruction of every interrupt handler a guest runs, so an
      // unconditional exit here would trade a correctness bug for a userspace
      // round trip on every single interrupt. A VMM registers the handful of
      // vectors it has programmed a level-triggered line with, and every other
      // EOI stays the no-exit path it is today.
      //
      // One bit test, and deliberately NOT an "is anything registered at all"
      // precheck in front of it. Such a precheck was here and was removed for
      // two reasons, in that order of importance: it let a test assert "an
      // unregistered vector does not exit" and pass without the per-vector bit
      // ever being consulted -- so a gate that registered EVERY vector would
      // have shipped green -- and it is four loads where this is one. A guest
      // that has registered nothing pays a single relaxed load of a word that is
      // zero, which is the cheapest this can be.
      //
      // `next_rip` has already run, so the packet reports a completed action:
      // the VMM has nothing to write back and resumes the VCPU as it is.
      {
        uint32_t completed = 0;
        if (guest_isr_eoi(local_apic_state, &completed)) {
          local_apic_state.eoi_completions++;
          if (unlikely(eoi_interest.Test(completed))) {
            local_apic_state.eoi_exits++;
            memset(&packet, 0, sizeof(packet));
            packet.type = ZX_PKT_TYPE_GUEST_EOI;
            packet.guest_eoi.vector = completed;
            return zx::error(ZX_ERR_NEXT);
          }
        }
      }
      return zx::ok();
    case X2ApicMsr::ESR:
      if (guest_state.eax() != 0) {
        local_apic_state.interrupt_tracker.Interrupt<X86_INT_GP_FAULT>();
        return zx::ok();
      }
      complete_apic_access(exit_info, vmcs, advance_rip);
      return zx::ok();
    case X2ApicMsr::TPR:
      // From Volume 3, Section 10.12.1.2 and Figure 10-18: only bits 7:0 of the
      // TPR are defined; the rest are reserved, and writing them causes #GP(0).
      // (The upper 32 bits are already refused above, for every register but
      // the ICR.)
      if ((guest_state.eax() & ~0xffu) != 0) {
        local_apic_state.interrupt_tracker.Interrupt<X86_INT_GP_FAULT>();
        return zx::ok();
      }
      complete_apic_access(exit_info, vmcs, advance_rip);
      // Into the virtual-APIC page, which is where `MOV to CR8` also writes and
      // where `local_apic_maybe_interrupt` reads the guest's priority from. A
      // write dropped here — as it was before that page existed — would let a
      // guest raise its task priority through this register and still be
      // interrupted below it.
      guest_tpr_write(local_apic_state, guest_state.eax());
      return zx::ok();
    // These six writes were accepted and thrown away, and the matching reads
    // answered with the architectural reset value -- so a guest that masked an
    // LVT entry, or software-enabled its APIC through the spurious-vector
    // register, and then read the register back was told its write had not
    // happened. That is not a stub that is merely incomplete: a read-modify-
    // write, which is how an LVT entry is masked and unmasked, silently reverts
    // every other field in the register.
    //
    // None of these six sources can raise an interrupt in this hypervisor --
    // there is no LINT pin, no thermal sensor, no CMCI and no performance
    // counter behind them -- so storing the value is the whole of the
    // behaviour. What the guest gets is a register that remembers.
    case X2ApicMsr::SVR:
      complete_apic_access(exit_info, vmcs, advance_rip);
      local_apic_state.svr = guest_state.eax();
      return zx::ok();
    case X2ApicMsr::LVT_MONITOR:
      complete_apic_access(exit_info, vmcs, advance_rip);
      local_apic_state.lvt_monitor = guest_state.eax();
      return zx::ok();
    case X2ApicMsr::LVT_ERROR:
      complete_apic_access(exit_info, vmcs, advance_rip);
      local_apic_state.lvt_error = guest_state.eax();
      return zx::ok();
    case X2ApicMsr::LVT_LINT0:
      complete_apic_access(exit_info, vmcs, advance_rip);
      local_apic_state.lvt_lint0 = guest_state.eax();
      return zx::ok();
    case X2ApicMsr::LVT_LINT1:
      complete_apic_access(exit_info, vmcs, advance_rip);
      local_apic_state.lvt_lint1 = guest_state.eax();
      return zx::ok();
    case X2ApicMsr::LVT_THERMAL_SENSOR:
      complete_apic_access(exit_info, vmcs, advance_rip);
      local_apic_state.lvt_thermal = guest_state.eax();
      return zx::ok();
    case X2ApicMsr::LVT_CMCI:
      complete_apic_access(exit_info, vmcs, advance_rip);
      local_apic_state.lvt_cmci = guest_state.eax();
      return zx::ok();
    case X2ApicMsr::LVT_TIMER:
      if ((guest_state.eax() & LVT_TIMER_MODE_MASK) == LVT_TIMER_MODE_RESERVED) {
        // E3: the guest wrote the reserved timer mode. Its action, its fault --
        // and it joins the rest of this handler, where every other malformed
        // APIC write already takes a #GP rather than ending the VM.
        local_apic_state.interrupt_tracker.Interrupt<X86_INT_GP_FAULT>();
        return zx::ok();
      }
      complete_apic_access(exit_info, vmcs, advance_rip);
      local_apic_state.lvt_timer = guest_state.eax();
      update_timer(local_apic_state, lvt_deadline(local_apic_state));
      return zx::ok();
    case X2ApicMsr::INITIAL_COUNT:
      complete_apic_access(exit_info, vmcs, advance_rip);
      local_apic_state.lvt_initial_count = guest_state.eax();
      update_timer(local_apic_state, lvt_deadline(local_apic_state));
      return zx::ok();
    case X2ApicMsr::DCR:
      complete_apic_access(exit_info, vmcs, advance_rip);
      local_apic_state.lvt_divide_config = guest_state.eax();
      update_timer(local_apic_state, lvt_deadline(local_apic_state));
      return zx::ok();
    case X2ApicMsr::SELF_IPI: {
      complete_apic_access(exit_info, vmcs, advance_rip);
      uint32_t vector = guest_state.eax() & UINT8_MAX;
      return local_apic_state.interrupt_tracker.Interrupt(vector);
    }
    case X2ApicMsr::ICR:
      // Remembered for the read side (see handle_apic_rdmsr): in x2APIC the ICR
      // is a single 64-bit read/write register, so a guest that composes an IPI
      // by reading it, changing the vector and writing it back used to fault on
      // the read. Stored before the write is acted on, because handle_ipi does
      // not return on every path.
      local_apic_state.icr = guest_state.EdxEax();
      return handle_ipi(exit_info, vmcs, guest_state, packet, advance_rip,
                        local_apic_state.x2apic_enabled);
    default:
      // Issue a general protection fault for read only and unimplemented
      // registers.
      dprintf(INFO, "hypervisor: Unhandled guest x2APIC WRMSR %#" PRIx32 "\n", guest_state.ecx());
      local_apic_state.interrupt_tracker.Interrupt<X86_INT_GP_FAULT>();
      return zx::ok();
  }
}

zx::result<> handle_apic_write_at_offset(const ExitInfo& exit_info, AutoVmcs& vmcs,
                                         LocalApicState& local_apic_state,
                                         const EoiBitmap& eoi_interest, zx_port_packet& packet,
                                         uint32_t offset, uint32_t value,
                                         bool advance_rip = false) {
  if (local_apic_state.x2apic_enabled || local_apic_state.virtual_apic == nullptr) {
    return zx::error(ZX_ERR_BAD_STATE);
  }

  local_apic_state.virtual_apic[offset / sizeof(uint32_t)] = value;

  // LDR and DFR exist only in the xAPIC MMIO interface. Hardware has already
  // copied the write into the virtual-APIC page; retain it as canonical state
  // for the next synchronization pass.
  if (offset == 0x0d0) {
    local_apic_state.xapic_ldr = value;
    complete_apic_access(exit_info, vmcs, advance_rip);
    return zx::ok();
  }
  if (offset == 0x0e0) {
    local_apic_state.xapic_dfr = value;
    complete_apic_access(exit_info, vmcs, advance_rip);
    return zx::ok();
  }
  // The high half of xAPIC's split ICR is staging state. Sending occurs only
  // when the low half is written.
  if (offset == 0x310) {
    local_apic_state.icr =
        (local_apic_state.icr & UINT32_MAX) | (static_cast<uint64_t>(value >> 24) << 32);
    complete_apic_access(exit_info, vmcs, advance_rip);
    return zx::ok();
  }

  GuestState write = {};
  write.rcx = kX2ApicMsrBase + offset / 0x10u;
  write.rax = value;
  if (offset == 0x300) {
    write.rdx = local_apic_state.virtual_apic[0x310 / sizeof(uint32_t)] >> 24;
  }

  // An APIC-write exit is trap-like: VMX has completed the memory write and
  // saved the following RIP. Reuse the x2APIC register semantics without
  // advancing it a second time.
  return handle_apic_wrmsr(exit_info, vmcs, write, local_apic_state, eoi_interest, packet,
                           advance_rip);
}

zx::result<> handle_apic_write(const ExitInfo& exit_info, AutoVmcs& vmcs,
                               LocalApicState& local_apic_state,
                               const EoiBitmap& eoi_interest, zx_port_packet& packet,
                               bool advance_rip = false) {
  const uint32_t offset =
      static_cast<uint32_t>(vmcs.Read(VmcsFieldXX::EXIT_QUALIFICATION)) & 0xff0u;
  const uint32_t value = local_apic_state.virtual_apic[offset / sizeof(uint32_t)];
  return handle_apic_write_at_offset(exit_info, vmcs, local_apic_state, eoi_interest, packet,
                                     offset, value, advance_rip);
}

zx::result<> handle_apic_access() {
  // VMX APIC-register virtualization handles ordinary xAPIC accesses without
  // this exit. On hosts lacking that control, FEE00000 remains unmapped and the
  // access is decoded by userspace before being completed through VCPU state.
  return zx::error(ZX_ERR_NOT_SUPPORTED);
}

zx::result<> handle_kvm_wrmsr(const ExitInfo& exit_info, AutoVmcs& vmcs,
                              const GuestState& guest_state, LocalApicState& local_apic_state,
                              PvClockState& pv_clock, hypervisor::GuestPhysicalAspace& gpa) {
  zx_paddr_t guest_paddr = guest_state.EdxEax();

  next_rip(exit_info, vmcs);
  switch (guest_state.ecx()) {
    case kKvmSystemTimeMsrOld:
    case kKvmSystemTimeMsr:
      vmcs.Invalidate();
      if ((guest_paddr & 1) != 0) {
        return pv_clock_reset_clock(&pv_clock, &gpa, guest_paddr & ~static_cast<zx_paddr_t>(1));
      } else {
        pv_clock_stop_clock(&pv_clock);
      }
      return zx::ok();
    case kKvmBootTimeOld:
    case kKvmBootTime:
      vmcs.Invalidate();
      return pv_clock_update_boot_time(&gpa, guest_paddr);
    default:
      local_apic_state.interrupt_tracker.Interrupt<X86_INT_GP_FAULT>();
      return zx::ok();
  }
}

zx::result<> handle_wrmsr(const ExitInfo& exit_info, AutoVmcs& vmcs, const GuestState& guest_state,
                          LocalApicState& local_apic_state, PvClockState& pv_clock,
                          hypervisor::GuestPhysicalAspace& gpa, zx_port_packet& packet,
                          bool delegate_synthetic_msrs, bool hyperv_identity, int64_t tsc_offset,
                          const EoiBitmap& eoi_interest, UnhandledMsrLog& unhandled_msrs) {
  // See the matching note in handle_rdmsr.
  if (delegate_synthetic_msrs && guest_state.ecx() >= kSyntheticMsrBase &&
      guest_state.ecx() <= kSyntheticMsrMax) {
    return delegate_msr(exit_info, vmcs, guest_state, /*is_write=*/true, packet);
  }
  // On execution of wrmsr, rcx specifies the MSR and edx:eax contains the value to be written.
  switch (guest_state.ecx()) {
    case X86_MSR_IA32_APIC_BASE:
      {
        const uint64_t requested = guest_state.EdxEax() & ~IA32_APIC_BASE_BSP;
        const uint64_t current =
            local_apic_state.x2apic_enabled ? kLocalApicX2apicBase : kLocalApicXapicBase;
        if (requested == current) {
          next_rip(exit_info, vmcs);
          return zx::ok();
        }
        if (!local_apic_state.x2apic_enabled && requested == kLocalApicX2apicBase) {
          // VM entry forbids xAPIC- and x2APIC-virtualization controls from
          // being active together. Switch the interface at the same
          // architectural boundary at which IA32_APIC_BASE changes.
          uint32_t controls = vmcs.Read(VmcsField32::PROCBASED_CTLS2);
          controls &= ~(kProcbasedCtls2ApicAccess | kProcbasedCtls2ApicRegister);
          controls |= kProcbasedCtls2x2Apic;
          vmcs.Write(VmcsField32::PROCBASED_CTLS2, controls);
          local_apic_state.x2apic_enabled = true;
          next_rip(exit_info, vmcs);
          return zx::ok();
        }
        // E3: a guest relocating or disabling its own APIC is doing something
        // this hypervisor declines to emulate. That is the GUEST's action, so it
        // earns a #GP -- which is also what writing a reserved value to this
        // register does architecturally. It used to return an error, which the
        // epilogue turned into a dead VM: an illegal guest action became a
        // fatal halt with no fault the guest could have handled or reported.
        local_apic_state.interrupt_tracker.Interrupt<X86_INT_GP_FAULT>();
        return zx::ok();
      }
    // Locked, per the read side. Writing a locked IA32_FEATURE_CONTROL is
    // architecturally #GP, so this is a KNOWN register answered the way the
    // architecture says -- deliberately NOT routed through
    // announce_unhandled_msr, which means "we do not know this register". The
    // zero-announcement gate is only meaningful if those two stay distinct.
    case kMsrIa32FeatureControl:
      local_apic_state.interrupt_tracker.Interrupt<X86_INT_GP_FAULT>();
      return zx::ok();
    // Accepted, but only the two bits this hypervisor can actually stand behind.
    //
    // The rest are DROPPED rather than faulted, and the reason is host safety
    // rather than tidiness: DEBUGCTL bits 6-10 (TR/BTS/BTINT/BTS_OFF_*) arm the
    // processor to write branch records through IA32_DS_AREA, which is NOT a
    // VMCS field and is NOT swapped around VM entry -- so a guest that set them
    // would be pointing the CPU at the HOST's debug-store area with guest-chosen
    // contents. Dropping is the only answer that cannot do that. The freeze-on-
    // PMI bits are meaningless with no PMU (CPUID leaf 0xA is zeroed).
    //
    // Stated plainly because it is a real limitation, as it already is for
    // IA32_MISC_ENABLE: a guest that writes this register and reads it back does
    // not necessarily see what it wrote. It does see what took effect -- the
    // read returns the VMCS field -- which is the honest half of the trade.
    case kMsrIa32Debugctl:
      next_rip(exit_info, vmcs);
      vmcs.Write(VmcsField64::GUEST_IA32_DEBUGCTL, guest_state.EdxEax() & kDebugctlGuestWritable);
      return zx::ok();
    // The legacy P6 BBL_CR_* family: swallowed, as the reference backend does.
    case kMsrBblCrD0:
    case kMsrBblCrD1:
    case kMsrBblCrD2:
    case kMsrBblCrAddr:
    case kMsrBblCrDecc:
    case kMsrBblCrCtl:
    case kMsrBblCrTrig:
    case kMsrBblCrBusy:
    case kMsrBblCrCtl3:
    // Paired with the zero-valued read above: there is no uncore counter to
    // program, and a guest write must not escape to a host-specific MSR.
    case kMsrUncoreCbox5First ... kMsrUncoreCbox5Last:
      next_rip(exit_info, vmcs);
      return zx::ok();
    // See note in handle_rdmsr.
    case X86_MSR_IA32_MTRRCAP:
    case X86_MSR_IA32_MTRR_DEF_TYPE:
    case X86_MSR_IA32_MTRR_FIX64K_00000:
    case X86_MSR_IA32_MTRR_FIX16K_80000 ... X86_MSR_IA32_MTRR_FIX16K_A0000:
    case X86_MSR_IA32_MTRR_FIX4K_C0000 ... X86_MSR_IA32_MTRR_FIX4K_F8000:
    case X86_MSR_IA32_MTRR_PHYSBASE0 ... X86_MSR_IA32_MTRR_PHYSMASK9:
    case X86_MSR_IA32_BIOS_SIGN_ID:
    case X86_MSR_DRAM_POWER_LIMIT:
    case X86_MSR_PP0_POWER_LIMIT:
    case X86_MSR_PP1_POWER_LIMIT:
    case X86_MSR_PLATFORM_POWER_LIMIT:
    // We disable the associated CPUID bits, but Linux still writes to these
    // MSRs. Just ignore it.
    case X86_MSR_IA32_SPEC_CTRL:
    case X86_MSR_IA32_PRED_CMD:
    // From Volume 4, Table 2-2: IA32_MISC_ENABLE. `handle_rdmsr` already
    // answers reads of this register with a synthesised value (fast strings
    // only) rather than the host's, so the guest's view of it is this
    // hypervisor's invention in both directions; making a *write* fatal while a
    // read is fabricated is the inconsistent half of that choice, not the safe
    // one. Every bit a guest would set here — fast strings, monitor/mwait, XD
    // disable, speed-step — is a property of the physical core it does not own,
    // so the write must not reach hardware; ignoring it is the only remaining
    // option that is not a #GP.
    //
    // Stated plainly because it is a real limitation: a guest that writes this
    // register and reads it back does **not** see what it wrote. The `mu_msvm`
    // firmware writes it while starting a Windows guest, and the #GP that used
    // to answer that write took the whole boot down.
    case X86_MSR_IA32_MISC_ENABLE:
      next_rip(exit_info, vmcs);
      return zx::ok();
    case X86_MSR_IA32_TSC_DEADLINE: {
      if ((local_apic_state.lvt_timer & LVT_TIMER_MODE_MASK) != LVT_TIMER_MODE_TSC_DEADLINE) {
        // E3, and this one is NOT a #GP. Outside TSC-deadline mode the register
        // is architecturally inert: the SDM makes writes to it meaningless in
        // one-shot/periodic mode, and KVM's kvm_set_lapic_tscdeadline_msr
        // returns without acting. Ignoring is what hardware does; faulting would
        // invent a fault, and killing the VM -- which is what this used to do --
        // turned a legal-if-pointless guest write into a dead machine.
        next_rip(exit_info, vmcs);
        return zx::ok();
      }
      next_rip(exit_info, vmcs);
      // Kept so the read side can hand it back; see the RDMSR case. This is
      // hypervisor-side state that the async-state snapshot does not carry
      // today, so a restored VCPU reads back 0 until the guest rewrites it --
      // the armed timer itself is restored from timer_deadline. Noted rather
      // than fixed here: extending the snapshot and its ABI version is
      // shared with code this change must not disturb.
      local_apic_state.tsc_deadline = guest_state.EdxEax();
      // The guest writes a deadline in its own TSC, so the offset comes
      // back off before the value is handed to a converter that speaks host TSC.
      // Stored above unmodified, because a read of this register must return what
      // the guest wrote.
      int64_t tsc_deadline =
          static_cast<int64_t>(guest_state.EdxEax() - static_cast<uint64_t>(tsc_offset));
      zx_instant_mono_t mono_deadline = convert_raw_tsc_timestamp_to_clock_monotonic(tsc_deadline);
      update_timer(local_apic_state, mono_deadline);
      return zx::ok();
    }
    case kX2ApicMsrBase ... kX2ApicMsrMax:
      if (!local_apic_state.x2apic_enabled) {
        local_apic_state.interrupt_tracker.Interrupt<X86_INT_GP_FAULT>();
        return zx::ok();
      }
      return handle_apic_wrmsr(exit_info, vmcs, guest_state, local_apic_state, eoi_interest,
                               packet);
    case kKvmSystemTimeMsrOld:
    case kKvmSystemTimeMsr:
    case kKvmBootTimeOld:
    case kKvmBootTime:
      // Under a Hyper-V identity the guest was never told this hypervisor
      // speaks KVM (no KVM CPUID signature is advertised in the
      // 0x4000_0000 range — see handle_cpuid), so a write to the KVM
      // paravirtual-clock MSRs is a blind probe, not a negotiated feature.
      // Honoring it anyway would let ANY guest create a long-lived
      // kernel-held pin on its own RAM (pv_clock_reset_clock →
      // CreateGuestPtr → PinnedVmObject), and a pinned page makes guest RAM
      // un-snapshottable: zx_vmo_create_child(SNAPSHOT_AT_LEAST_ON_WRITE)
      // refuses a pinned VMO with ZX_ERR_BAD_STATE
      // (VmCowPages::CreateCloneLocked) — a guest-triggerable veto over the
      // host's checkpoint/restore. Treat the access exactly like any other
      // MSR this hypervisor does not implement for this guest: announce it
      // and inject #GP. Non-Hyper-V (KVM-identity) guests keep the working
      // pvclock path below.
      if (hyperv_identity) {
        const bool injected =
            local_apic_state.interrupt_tracker.Interrupt(X86_INT_GP_FAULT).is_ok();
        announce_unhandled_msr(unhandled_msrs, guest_state.ecx(), exit_info.guest_rip,
                               /*is_write=*/true, guest_state.EdxEax(), injected);
        return zx::ok();
      }
      return handle_kvm_wrmsr(exit_info, vmcs, guest_state, local_apic_state, pv_clock, gpa);
    default: {
      // See the matching note in handle_rdmsr: no `next_rip`, so `guest_rip` is
      // the address of the WRMSR itself.
      const bool injected =
          local_apic_state.interrupt_tracker.Interrupt(X86_INT_GP_FAULT).is_ok();
      announce_unhandled_msr(unhandled_msrs, guest_state.ecx(), exit_info.guest_rip,
                             /*is_write=*/true, guest_state.EdxEax(), injected);
      return zx::ok();
    }
  }
}

uint8_t default_operand_size(uint64_t efer, uint32_t cs_access_rights) {
  // See Volume 3, Section 5.2.1.
  if ((efer & X86_EFER_LMA) && (cs_access_rights & kGuestXxAccessRightsL)) {
    // IA32-e 64 bit mode.
    return 4;
  } else if (cs_access_rights & kGuestXxAccessRightsD) {
    // CS.D set (and not 64 bit mode).
    return 4;
  } else {
    // CS.D clear (and not 64 bit mode).
    return 2;
  }
}

zx::result<> handle_trap(const ExitInfo& exit_info, AutoVmcs& vmcs, bool read,
                         zx_vaddr_t guest_paddr, hypervisor::TrapMap& traps,
                         zx_port_packet_t& packet) {
  zx::result<hypervisor::Trap*> trap = traps.FindTrap(ZX_GUEST_TRAP_BELL, guest_paddr);
  if (trap.is_error()) {
    return trap.take_error();
  }
  next_rip(exit_info, vmcs);

  switch ((*trap)->kind()) {
    case ZX_GUEST_TRAP_BELL:
      if (read) {
        return zx::error(ZX_ERR_NOT_SUPPORTED);
      }
      packet.key = (*trap)->key();
      packet.type = ZX_PKT_TYPE_GUEST_BELL;
      packet.guest_bell.addr = guest_paddr;
      if (!(*trap)->HasPort()) {
        return zx::error(ZX_ERR_BAD_STATE);
      }
      return (*trap)->Queue(packet, &vmcs);
    case ZX_GUEST_TRAP_MEM:
      if (exit_info.exit_instruction_length > kMaxInstructionSize) {
        return zx::error(ZX_ERR_INTERNAL);
      }
      packet.key = (*trap)->key();
      packet.type = ZX_PKT_TYPE_GUEST_MEM;
      packet.guest_mem.addr = guest_paddr;
      packet.guest_mem.cr3 = vmcs.Read(VmcsFieldXX::GUEST_CR3);
      packet.guest_mem.rip = exit_info.guest_rip;
      packet.guest_mem.instruction_size = static_cast<uint8_t>(exit_info.exit_instruction_length);
      packet.guest_mem.default_operand_size = default_operand_size(
          vmcs.Read(VmcsField64::GUEST_IA32_EFER), vmcs.Read(VmcsField32::GUEST_CS_ACCESS_RIGHTS));
      return zx::error(ZX_ERR_NEXT);
    default:
      return zx::error(ZX_ERR_BAD_STATE);
  }
}

zx::result<> handle_exception_or_nmi(const ExitInfo& exit_info, AutoVmcs& vmcs,
                                     zx_port_packet_t& packet,
                                     uint64_t& host_nmis_redispatched) {
  const ExitInterruptionInfo int_info(vmcs);
  // A trapped guest breakpoint (#BP / INT3) is surfaced to userspace so a VMM
  // can implement software breakpoints — e.g. VMM-planted coverage
  // instrumentation. The VMM records the hit, restores the original byte, and
  // repositions the guest RIP before resuming. Breakpoint trapping is opt-in
  // (Vcpu::SetBreakpointTrapping); other exceptions and NMIs are unaffected.
  if (int_info.valid && int_info.vector == X86_INT_BREAKPOINT) {
    memset(&packet, 0, sizeof(packet));
    packet.type = ZX_PKT_TYPE_GUEST_EXCEPTION;
    packet.guest_exception.vector = int_info.vector;
    packet.guest_exception.rip = exit_info.guest_rip;
    return zx::error(ZX_ERR_NEXT);
  }

  // `kPinbasedCtlsNmiExiting` is set, so a host NMI taken while this CPU
  // is in VMX non-root operation does NOT go through the host IDT -- it becomes
  // this VM exit, reason 0 with interruption type 2. The comment at the call
  // site used to claim the opposite ("NMIs are handled by the host via the
  // IDT"), and the code did the two worst things available: it returned
  // ZX_ERR_NOT_SUPPORTED, which the epilogue turns into a halt that kills the
  // guest, and it dropped the NMI on the floor.
  //
  // WHY THAT MATTERED MORE THAN ITS RARITY SUGGESTS. The only NMI source in this
  // kernel is `SendNmiIpi` behind CpuContextExchange, whose only production
  // caller is the `k cpu context` debug command. So this fires precisely when an
  // engineer is trying to find out why a CPU looks hung -- and the requester
  // spins until it times out AND leaves the exchange permanently held, because
  // the lock can only be released by a target that answered. One NMI into a
  // guest therefore destroyed the guest and disabled the tool for the rest of
  // the boot, at the exact moment both were wanted.
  //
  // Re-dispatch through the real IDT vector rather than by calling the handler.
  // `x86_call_external_interrupt_handler` is NOT usable here: its synthesized
  // frame sits on the current kernel stack, and `interrupt_common`'s NMI arm
  // recovers %gs.base by computing the percpu pointer from %rsp on the
  // assumption that the frame is on the NMI IST stack (see exceptions.S,
  // .Lnmi). Software `int $2` goes through IDT vector 2, which has an IST index
  // installed (mp.cc: idt_set_ist_index(&_idt, X86_INT_NMI, NMI_IST_INDEX)), so
  // the processor makes that assumption true.
  //
  // Interrupts are disabled here -- this runs before the run loop re-enables
  // them -- which is what x86_nmi_handler asserts.
  if (int_info.valid && int_info.interruption_type == InterruptionType::NON_MASKABLE_INTERRUPT &&
      int_info.vector == X86_INT_NMI) {
    host_nmis_redispatched++;
    // The handler may take arbitrary time and must not hold a VMCS open.
    vmcs.Invalidate();
    __asm__ __volatile__("int $2" ::: "memory");
    // Nothing about the guest changed: it never saw this, its RIP is unmoved,
    // and it resumes where it was.
    return zx::ok();
  }
  return zx::error(ZX_ERR_NOT_SUPPORTED);
}

zx::result<> handle_ept_violation(const ExitInfo& exit_info, AutoVmcs& vmcs,
                                  Guest& guest, uint16_t vpid,
                                  hypervisor::GuestPhysicalAspace& gpa, hypervisor::TrapMap& traps,
                                  zx_port_packet_t& packet) {
  const uint64_t qualification = vmcs.Read(VmcsFieldXX::EXIT_QUALIFICATION);
  const EptViolationInfo ept_violation_info(qualification);
  zx_gpaddr_t guest_paddr = vmcs.Read(VmcsField64::GUEST_PHYSICAL_ADDRESS);
  if (guest.MaybeStopMemoryAccess(qualification, guest_paddr,
                                  vmcs.Read(VmcsFieldXX::GUEST_LINEAR_ADDRESS),
                                  exit_info.guest_rip, vpid, packet)) {
    // EPT violations are pre-access. Deliberately do not advance RIP, fault the
    // page in, or emulate: the exact instruction is retried only after an
    // acknowledgement has transitioned the permissions.
    return zx::error(packet.type == ZX_PKT_TYPE_GUEST_MEMORY_ACCESS ? ZX_ERR_NEXT
                                                                    : ZX_ERR_CANCELED);
  }
  auto result = handle_trap(exit_info, vmcs, ept_violation_info.read, guest_paddr, traps, packet);
  if (result.status_value() != ZX_ERR_NOT_FOUND) {
    return result;
  }

  // We may have to block when handling the page fault.
  vmcs.Invalidate();

  // If there was no trap associated with this address and it is outside of
  // guest physical address space, return failure.
  if (guest_paddr >= gpa.size()) {
    return zx::error(ZX_ERR_OUT_OF_RANGE);
  }

  result = guest.PageFaultPreservingMemoryAccess(guest_paddr, vpid);
  if (result.is_error()) {
    // This used to be the only place the offending address appeared:
    // the halt packet the epilogue builds carried the exit reason and the guest
    // RIP and nothing else, so a VMM was told "an EPT violation went unserviced"
    // with no way to say WHERE, and the one artifact that knew was a kernel log
    // line the VMM cannot read. The address now travels in the packet -- see
    // ZX_PKT_GUEST_HALT_ADDRESS_VALID below -- and this line stays because a
    // kernel log is often all a bare-metal run leaves behind.
    dprintf(CRITICAL,
            "hypervisor: unhandled EPT violation at guest-physical %#lx (guest RIP %#lx, %s%s%s)\n",
            guest_paddr, exit_info.guest_rip, ept_violation_info.read ? "read " : "",
            ept_violation_info.write ? "write " : "", ept_violation_info.instruction ? "exec" : "");
  }
  return result;
}

zx::result<> handle_xsetbv(const ExitInfo& exit_info, AutoVmcs& vmcs, GuestState& guest_state,
                           LocalApicState& local_apic_state) {
  // E3, and the clearest case of it in the file: every refusal below is
  // architecturally #GP(0) on real silicon, so answering any of them by killing
  // the VM replaced a fault the guest's own handler would have taken with a
  // machine that simply stopped. Volume 2's XSETBV page lists all three.
  uint64_t guest_cr4 = vmcs.Read(VmcsFieldXX::GUEST_CR4);
  if (!(guest_cr4 & X86_CR4_OSXSAVE)) {
    local_apic_state.interrupt_tracker.Interrupt<X86_INT_GP_FAULT>();
    return zx::ok();
  }

  // There is deliberately no is_cpl0() check here, and the asymmetry with
  // handle_vmcall (which has one) is correct rather than an oversight.
  //
  // XSETBV is a CPL-0 instruction -- Volume 2's XSETBV page lists "#GP(0) If the
  // current privilege level is not 0" -- so it looks as though this handler
  // ought to test the guest's CPL the way handle_vmcall does. It does not need
  // to, because that fault has priority over the VM exit: Volume 3, Section
  // 26.1.1, gives privilege-level faults priority over the VM exits caused by
  // instruction execution, so a ring-3 guest's XSETBV never gets here at all --
  // the processor #GP(0)s it inside the guest. VMCALL is the opposite case (the
  // exit happens first and the hypervisor owns the privilege check), which is
  // why is_cpl0 exists and why it is called there and not here.
  //
  // Measured, not inferred: vcpu_xsetbv_cpl3_faults_before_the_exit in
  // unittests/guest_enter_test.cc runs a guest at CPL 3 -- ring-3 CS/SS, user
  // page tables, IOPL 3 -- which reports its own CPL out of the guest and then
  // executes this instruction. Its own #GP handler runs, with vector 13, and no
  // XSETBV exit is taken; the identical instruction at CPL 0 exits and is
  // emulated here. A CPL test added to this function would therefore be dead
  // code, and its predicate would be wrong besides: is_cpl0() reads SS.DPL,
  // which is a proxy for CPL, not CPL itself.

  // We only support XCR0. Naming any other XCR is #GP(0) architecturally.
  if (guest_state.rcx != 0) {
    local_apic_state.interrupt_tracker.Interrupt<X86_INT_GP_FAULT>();
    return zx::ok();
  }

  // Check that XCR0 is valid. The checks live in ValidateGuestXcr0() because
  // this is not the only way a value reaches guest_state.xcr0 -- VCPU snapshot
  // restore (Vcpu::RestoreArchState) sets it straight from a caller-supplied
  // structure -- and both paths end at the same host-context x86_xsetbv().
  // Keeping one validator is what stops the two from drifting apart, which is
  // exactly how the restore path came to have none at all.
  // A guest XSETBV naming a value this hypervisor cannot back is the guest's
  // own illegal instruction, and #GP(0) is what hardware answers with. NOTE the
  // asymmetry with the SNAPSHOT-restore path, which shares this validator and
  // must keep returning an error: there the value came from the VMM through
  // Vcpu::RestoreArchState, it is not a guest action, and it reaches a host
  // x86_xsetbv() -- so refusing it is a host-safety rejection to the caller,
  // not a fault to inject. Same check, two callers, two correct answers.
  const uint64_t xcr0 = guest_state.EdxEax();
  if (auto result = ValidateGuestXcr0(xcr0); result.is_error()) {
    local_apic_state.interrupt_tracker.Interrupt<X86_INT_GP_FAULT>();
    return zx::ok();
  }

  // This write is the whole effect of a guest XSETBV, and it is now
  // effective; it used to be inert, and the note that used to be here explained
  // why. What changed is one step in Vcpu::Enter: the entry path re-installs this
  // value on the physical XCR0 when it differs from what is currently loaded (see
  // the `xstate_loaded_` block there), so the guest's next instruction runs under
  // the XCR0 it asked for. The write is not made from here for a host-safety
  // reason worth keeping: this function has no way to know whether the guest's
  // extended state is the one currently in the CPU, and an `x86_xsetbv` issued
  // while the HOST's state is loaded would corrupt the host's XCR0. Vcpu::Enter
  // does know, because that is the flag it owns.
  //
  // WHY THE IMAGE DOES NOT NEED RE-VALIDATING, which the note that used to be here
  // said it would. ValidateXsaveImageRules() decides whether MXCSR is loaded from
  // the live XCR0's SSE/AVX bits, so a guest that enlarges XCR0 after an image was
  // accepted looks as though it could make an unvalidated MXCSR reachable. It
  // cannot, and the reason is the load/save protocol rather than this function:
  //
  //   * enlarging XCR0 does not restore anything. The register file already in the
  //     CPU is the guest's, and hardware MXCSR is legal by construction -- it was
  //     either loaded from an image validated against an XCR0 that selected it, or
  //     never loaded at all and so is still the host's.
  //   * `xstate_loaded_` goes false only immediately after SaveExtendedRegisters()
  //     and Vcpu::Enter loads only when it is false, so EVERY restore of the
  //     guest's buffer is preceded by a save of it. The first save after the XSETBV
  //     runs under the new, larger XCR0 and therefore rewrites the buffer's MXCSR
  //     from the legal value in hardware, before any restore can read it.
  //
  // The other half of the guard is in CPUID: kGuestWithheldXsaveComponents now
  // withholds AVX-512, so no guest XCR0 that reaches here can select more state
  // than the kernel's fixed 1 KiB buffers hold. Without that, an effective XSETBV
  // would have made the size bound in ValidateGuestXcr0Rules the only thing
  // standing between a guest and an overrun of the Vcpu object -- one check
  // instead of two, on a value the guest chooses.
  guest_state.xcr0 = xcr0;
  next_rip(exit_info, vmcs);
  return zx::ok();
}

void handle_pause(const ExitInfo& exit_info, AutoVmcs& vmcs) { next_rip(exit_info, vmcs); }

bool is_cpl0(AutoVmcs& vmcs) {
  const uint32_t access_rights = vmcs.Read(VmcsField32::GUEST_SS_ACCESS_RIGHTS);
  // We only accept a VMCALL if CPL is 0.
  return (access_rights & kGuestXxAccessRightsDplUser) == 0;
}

// TLFS, "Legal Hypercall Environments", verbatim: "Hypercalls can be invoked only
// from the most privileged guest processor mode. On x64 platforms, this means
// protected mode with a current privilege level (CPL) of zero. Although real-mode
// code runs with an effective CPL of zero, hypercalls are not allowed in real
// mode."
//
// Both halves of that sentence are checked, and the second one is why is_cpl0()
// alone is not the predicate: is_cpl0() reads SS.DPL, which a real-mode guest has
// as 0, so it would admit exactly the case the spec calls out. Virtual-8086 mode
// is the same case from the other direction -- RFLAGS.VM is set while CS.RPL
// reads 3 in the segment registers but the mode is not protected mode either.
//
// GUEST_CR0.PE is the guest's own bit: CR0_GUEST_HOST_MASK holds only
// ET|NE|NW|CD (vcpu.cc), so PE is not shadowed and this read is not answering
// from CR0_READ_SHADOW.
bool is_legal_hypercall_environment(AutoVmcs& vmcs) {
  if ((vmcs.Read(VmcsFieldXX::GUEST_CR0) & X86_CR0_PE) == 0) {
    return false;
  }
  if ((vmcs.Read(VmcsFieldXX::GUEST_RFLAGS) & X86_FLAGS_VM) != 0) {
    return false;
  }
  return is_cpl0(vmcs);
}

zx::result<> handle_vmcall(const ExitInfo& exit_info, AutoVmcs& vmcs, GuestState& guest_state,
                           hypervisor::GuestPhysicalAspace& gpa,
                           const VcpuEnlightenment& enlightenment,
                           LocalApicState& local_apic_state, int64_t tsc_offset,
                           zx_port_packet_t& packet) {
  // The two identities this kernel can present define this failure
  // differently, and each is right for its own ABI, so the answer is picked from
  // the identity rather than being one value for both.
  //
  // Hyper-V: the TLFS quotes above give no status code at all -- "An attempt to
  // invoke a hypercall within an illegal processor mode will generate a #UD
  // (undefined operation) exception on x64". So RAX is left alone and #UD is
  // injected. A status code here would be the non-conformant answer, which is why
  // Returning an HV_STATUS is not what this implements; see the
  // long note on vcpu_hypercall_at_cpl3_faults_per_identity in
  // unittests/guest_enter_test.cc for the verbatim clause.
  //
  // KVM: `kvm_emulate_hypercall` answers a CPL != 0 caller with -KVM_EPERM in
  // RAX and retires the instruction. `NOT_PERMITTED` is -1, which is exactly
  // -KVM_EPERM -- so the pre-existing behaviour was correct for the identity it
  // was written for, and stays.
  //
  // NOTE the `next_rip` placement, which is load-bearing and is the whole reason
  // this check moved above it. A #UD is a FAULT: the frame the processor pushes
  // must hold the address of the VMCALL itself, so RIP must not have been
  // advanced when the event is injected. The KVM arm still advances it, because
  // there the instruction retires.
  //
  // What this does NOT fix, and cannot from here: `next_rip` still runs before
  // the *delegated* hypercall is handed to the VMM, so a VMM cannot rewind RIP to
  // re-execute a call. That blocks rep hypercalls and retry-by-re-execution and
  // is an ABI change because RIP has already advanced; out of scope here.
  //
  // The two identities get two PREDICATES as well as two answers, which is not
  // fussiness: the real-mode and virtual-8086 clauses are TLFS's, and KVM's ABI
  // has no equivalent -- `kvm_emulate_hypercall` tests CPL and nothing else. Using
  // the wider predicate for both would have changed the KVM path's behaviour for a
  // real-mode caller as a side effect of a Hyper-V conformance fix. (Caught by
  // The test exercises only protected-mode CPL 3, so it would not
  // have noticed.)
  if (enlightenment.hyperv_identity) {
    if (!is_legal_hypercall_environment(vmcs)) {
      local_apic_state.interrupt_tracker.Interrupt<X86_INT_INVALID_OP>();
      return zx::ok();
    }
  } else if (!is_cpl0(vmcs)) {
    next_rip(exit_info, vmcs);
    guest_state.rax = VmCallStatus::NOT_PERMITTED;
    return zx::ok();
  }
  next_rip(exit_info, vmcs);
  // A VMM that has claimed hypercalls owns the whole call set, so the operands
  // go to it untouched rather than being matched against the kernel's own. As
  // with a delegated MSR read, the result is returned by writing rax before the
  // next entry.
  if (enlightenment.delegate_hypercalls) {
    memset(&packet, 0, sizeof(packet));
    packet.type = ZX_PKT_TYPE_GUEST_HYPERCALL;
    packet.guest_hypercall.input = guest_state.rcx;
    packet.guest_hypercall.arg0 = guest_state.rdx;
    packet.guest_hypercall.arg1 = guest_state.r8;
    return zx::error(ZX_ERR_NEXT);
  }
  vmcs.Invalidate();

  // We never fail in case of hypercalls, we just return/propagate errors to the caller.
  const VmCallInfo info(guest_state);
  switch (info.type) {
    case VmCallType::CLOCK_PAIRING: {
      if (info.arg[1] != 0) {
        dprintf(INFO, "hypervisor: CLOCK_PAIRING hypercall doesn't support clock type %lu\n",
                info.arg[1]);
        guest_state.rax = VmCallStatus::NOT_SUPPORTED;
        break;
      }
      if (auto result = pv_clock_populate_offset(&gpa, info.arg[0], tsc_offset);
          result.is_error()) {
        dprintf(INFO, "hypervisor: Failed to populate lock offset with error %d\n",
                result.status_value());
        guest_state.rax = VmCallStatus::FAULT;
        break;
      }
      guest_state.rax = VmCallStatus::OK;
      break;
    }
    default:
      dprintf(INFO,
              "hypervisor: Unknown hypercall %lu (arg0=%#lx, arg1=%#lx, arg2=%#lx, arg3=%#lx)\n",
              static_cast<uint64_t>(info.type), info.arg[0], info.arg[1], info.arg[2], info.arg[3]);
      guest_state.rax = VmCallStatus::UNKNOWN_HYPERCALL;
      break;
  }
  return zx::ok();
}

}  // namespace

zx::result<uint32_t> ReadXapicRegister(LocalApicState& local_apic_state, uint32_t apic_id,
                                       uint32_t offset) {
  if (local_apic_state.x2apic_enabled || local_apic_state.virtual_apic == nullptr) {
    return zx::error(ZX_ERR_BAD_STATE);
  }
  if ((offset & 0xfu) != 0 || offset >= kPageSize) {
    return zx::error(ZX_ERR_INVALID_ARGS);
  }
  const bool bitmap_register =
      (offset >= 0x100 && offset <= 0x270 && ((offset - 0x100) % 0x10) == 0);
  switch (offset) {
    case 0x020:  // ID
    case 0x030:  // version
    case 0x080:  // TPR
    case 0x090:  // APR
    case 0x0a0:  // PPR
    case 0x0d0:  // LDR
    case 0x0e0:  // DFR
    case 0x0f0:  // SVR
    case 0x280:  // ESR
    case 0x2f0:  // CMCI
    case 0x300:  // ICR low
    case 0x310:  // ICR high
    case 0x320:  // LVT timer
    case 0x330:  // LVT thermal
    case 0x340:  // LVT performance monitor
    case 0x350:  // LVT LINT0
    case 0x360:  // LVT LINT1
    case 0x370:  // LVT error
    case 0x380:  // initial count
    case 0x390:  // current count
    case 0x3e0:  // divide configuration
      break;
    default:
      if (!bitmap_register) {
        return zx::error(ZX_ERR_NOT_SUPPORTED);
      }
      break;
  }
  SyncVirtualApicPage(local_apic_state, apic_id);
  return zx::ok(local_apic_state.virtual_apic[offset / sizeof(uint32_t)]);
}

zx::result<> WriteXapicRegister(AutoVmcs& vmcs, LocalApicState& local_apic_state,
                                const EoiBitmap& eoi_interest, uint32_t offset, uint32_t value,
                                zx_port_packet_t& packet) {
  if (local_apic_state.x2apic_enabled || local_apic_state.virtual_apic == nullptr) {
    return zx::error(ZX_ERR_BAD_STATE);
  }
  if ((offset & 0xfu) != 0 || offset >= kPageSize) {
    return zx::error(ZX_ERR_INVALID_ARGS);
  }
  switch (offset) {
    case 0x080:  // TPR
      if ((value & ~0xffu) != 0) {
        return zx::error(ZX_ERR_INVALID_ARGS);
      }
      break;
    case 0x0b0:  // EOI
    case 0x280:  // ESR
      if (value != 0) {
        return zx::error(ZX_ERR_INVALID_ARGS);
      }
      break;
    case 0x0d0:  // LDR
    case 0x0e0:  // DFR
    case 0x0f0:  // SVR
    case 0x2f0:  // CMCI
    case 0x300:  // ICR low
    case 0x310:  // ICR high
    case 0x330:  // LVT thermal
    case 0x340:  // LVT performance monitor
    case 0x350:  // LVT LINT0
    case 0x360:  // LVT LINT1
    case 0x370:  // LVT error
    case 0x380:  // initial count
    case 0x3e0:  // divide configuration
      break;
    case 0x320:  // LVT timer
      if ((value & LVT_TIMER_MODE_MASK) == LVT_TIMER_MODE_RESERVED) {
        return zx::error(ZX_ERR_INVALID_ARGS);
      }
      break;
    default:
      return zx::error(ZX_ERR_NOT_SUPPORTED);
  }

  // The shared write machinery takes ExitInfo only to advance a trapped
  // instruction. A state-topic access has already been decoded by userspace,
  // so advance_rip is false below and no exit field is consumed.
  ExitInfo exit_info(vmcs);
  zx::result<> result =
      handle_apic_write_at_offset(exit_info, vmcs, local_apic_state, eoi_interest, packet, offset,
                                  value, /*advance_rip=*/false);
  return result.status_value() == ZX_ERR_NEXT ? zx::ok() : result;
}

void announce_unhandled_msr(UnhandledMsrLog& log, uint32_t msr, uint64_t guest_rip, bool is_write,
                            uint64_t value, bool gp_injected) {
  log.total++;
  log.last_msr = msr;
  log.last_rip = guest_rip;
  log.last_value = is_write ? value : 0;
  log.last_is_write = is_write;
  log.last_gp_injected = gp_injected;

  // How many times *this register* has been seen, so the backoff below is
  // per-register: a guest hammering one unimplemented MSR must not be able to
  // suppress the first line about a different one, which is the line that
  // identifies a new gap.
  uint64_t count = 0;
  bool overflowed = false;
  for (size_t i = 0; i < log.tracked; i++) {
    if (log.entries[i].msr == msr) {
      count = ++log.entries[i].count;
      break;
    }
  }
  if (count == 0) {
    if (log.tracked < UnhandledMsrLog::kMaxTracked) {
      log.entries[log.tracked].msr = msr;
      log.entries[log.tracked].count = 1;
      log.tracked++;
      count = 1;
    } else {
      count = ++log.overflow;
      overflowed = true;
    }
  }

  // Print the 1st, 2nd, 4th, 8th ... occurrence and nothing in between. The
  // count is in the line, so a reader can see how many were skipped rather than
  // being quietly shown a fraction of the truth.
  if ((count & (count - 1)) != 0) {
    return;
  }
  // The first occurrence of a register goes out at ALWAYS: it is the one line
  // that identifies a new gap, and no build's DEBUG_PRINT_LEVEL should be able
  // to remove it. Repeats are INFO, where a quiet build can drop them.
  const bool first = count == 1 && !overflowed;
  if (!first && !DPRINTF_ENABLED_FOR_LEVEL(INFO)) {
    return;
  }
  if (is_write) {
    printf(
        "hypervisor: unhandled guest WRMSR %#x = %#" PRIx64 " at guest RIP %#" PRIx64
        " -- %s (occurrence %" PRIu64 "%s)\n",
        msr, value, guest_rip, gp_injected ? "#GP injected" : "#GP COULD NOT BE INJECTED", count,
        overflowed ? " of registers past the tracking table" : " for this register");
  } else {
    printf("hypervisor: unhandled guest RDMSR %#x at guest RIP %#" PRIx64
           " -- %s (occurrence %" PRIu64 "%s)\n",
           msr, guest_rip, gp_injected ? "#GP injected" : "#GP COULD NOT BE INJECTED", count,
           overflowed ? " of registers past the tracking table" : " for this register");
  }
}

void announce_unhandled_io(UnhandledIoLog& log, uint16_t port, uint64_t guest_rip, bool is_read,
                           uint8_t access_size, uint64_t value) {
  log.total++;
  if (is_read) {
    log.reads++;
  } else {
    log.writes++;
  }
  log.last_port = port;
  log.last_rip = guest_rip;
  log.last_access_size = access_size;
  log.last_is_read = is_read;
  log.last_value = value;

  // Per-PORT backoff, for the same reason the MSR log's is per-register: a guest
  // spinning on one dead port must not be able to suppress the first sighting of
  // a different one, which is the line that identifies a new gap.
  uint64_t count = 0;
  bool overflowed = false;
  for (size_t i = 0; i < log.tracked; i++) {
    if (log.entries[i].port == port) {
      count = ++log.entries[i].count;
      break;
    }
  }
  if (count == 0) {
    if (log.tracked < UnhandledIoLog::kMaxTracked) {
      log.entries[log.tracked].port = port;
      log.entries[log.tracked].count = 1;
      log.tracked++;
      count = 1;
    } else {
      count = ++log.overflow;
      overflowed = true;
    }
  }

  if ((count & (count - 1)) != 0) {
    return;
  }
  // The first sighting of a port goes out at ALWAYS. A defaulted READ is the
  // dangerous half -- all-ones reads as "ready" -- so the line says what the
  // guest was handed, not merely that something happened.
  const bool first = count == 1 && !overflowed;
  if (!first && !DPRINTF_ENABLED_FOR_LEVEL(INFO)) {
    return;
  }
  if (is_read) {
    printf("hypervisor: guest IN from unregistered I/O port %#x (%u bytes) at guest RIP %#" PRIx64
           " -- answered %#" PRIx64 ", the all-ones value an undriven bus returns, in which every "
           "status bit reads as SET (occurrence %" PRIu64 "%s)\n",
           port, access_size, guest_rip, value, count,
           overflowed ? " of ports past the tracking table" : " for this port");
  } else {
    printf("hypervisor: guest OUT to unregistered I/O port %#x (%u bytes) = %#" PRIx64
           " at guest RIP %#" PRIx64 " -- discarded (occurrence %" PRIu64 "%s)\n",
           port, access_size, value, guest_rip, count,
           overflowed ? " of ports past the tracking table" : " for this port");
  }
}

zx::result<XsaveMainLeaf> GuestXsaveMainLeaf(uint64_t host_supported, uint64_t guest_xcr0,
                                             XsaveSizeFn xsave_size_fn) {
  // EDX:EAX is the set of state components a guest may put in XCR0. Withhold
  // the ones this hypervisor cannot back, so the guest is not told about a
  // component whose XSETBV ValidateGuestXcr0 would then refuse. Passing
  // silicon's answer through is what let a guest enable MPX it could not have;
  // see kGuestWithheldXsaveComponents.
  const uint64_t advertised = GuestXsaveComponents(host_supported);

  // EBX is the size the components CURRENTLY in XCR0 need; ECX the size the
  // whole SUPPORTED set would need. Both are measured against `advertised`
  // rather than against silicon, because a bitmap and a size that disagree is
  // the same defect the bitmap mask was made to fix, one register along: ECX
  // used to be the host's, so on a part with MPX the guest was told "the
  // components you may enable are x87|SSE|AVX" and, immediately after, "and
  // they need 1088 bytes" -- a number describing a layout that ends in the two
  // components the same leaf had just denied, and that no combination of the
  // offsets and sizes the guest is shown can produce. Volume 2, Table 3-8
  // defines ECX over "all the state components supported", and after the mask
  // the supported set IS `advertised`.
  //
  // NARROWING ECX IS SAFE BY CONSTRUCTION, not by argument. Every path that
  // writes guest_state.xcr0 -- handle_xsetbv and Vcpu::RestoreArchState -- goes
  // through ValidateGuestXcr0, whose `supported` mask is this same
  // GuestXsaveComponents(); so the guest's XCR0 is always a subset of
  // `advertised`, and the size function is a maximum over the components in its
  // argument, so EBX <= ECX always. A guest that sizes a buffer from ECX still
  // gets one large enough for any XSAVE it can legally issue.
  auto enabled_size = xsave_size_fn(guest_xcr0);
  if (enabled_size.is_error()) {
    return enabled_size.take_error();
  }
  auto supported_size = xsave_size_fn(advertised);
  if (supported_size.is_error()) {
    return supported_size.take_error();
  }
  return zx::ok(XsaveMainLeaf{
      .eax = static_cast<uint32_t>(advertised),
      .ebx = *enabled_size,
      .ecx = *supported_size,
      .edx = static_cast<uint32_t>(advertised >> 32),
  });
}

zx::result<> ValidateGuestXcr0Rules(uint64_t xcr0, bool xsave_supported, uint64_t supported,
                                    XsaveSizeFn xsave_size_fn) {
  // Why this is a *host* safety check and not merely guest hygiene.
  //
  // `guest_state.xcr0` is not a shadow the guest reads back: it is handed
  // verbatim to `x86_xsetbv(0, ...)` by swap_extended_registers() (vcpu.cc),
  // which runs on the way into and out of the guest -- that is, in HOST context,
  // with host CR4/CR3 and no VM to absorb the fault. XSETBV #GPs on an illegal
  // operand (Volume 2, "XSETBV"), so an unchecked value here is a kernel fault,
  // not a guest fault. Everything below is therefore a precondition of the
  // kernel not #GP'ing on its own instruction.

  // XSETBV is #UD without XSAVE. The kernel only ever executes it when it has
  // enabled XSAVE for itself, so on such a machine no guest may carry a nonzero
  // XCR0 at all. (Vcpu::Setup leaves it zero there, so this rejects nothing a
  // save/restore round trip can produce.)
  if (!xsave_supported) {
    if (xcr0 != 0) {
      return zx::error(ZX_ERR_INVALID_ARGS);
    }
    return zx::ok();
  }

  // `supported` is CPUID.(EAX=0Dh,ECX=0).EDX:EAX -- the set of state components
  // this CPU allows in XCR0. Reserved bits and supervisor-only components
  // (IA32_XSS states such as PT, CET_U/CET_S, LBR) read as 0 there, so the
  // single subset test below covers "reserved bits must be zero" and "no
  // XSS-only bit" as well as "no unsupported feature".
  if (xcr0 & ~supported) {
    return zx::error(ZX_ERR_INVALID_ARGS);
  }

  // Volume 2, "XSETBV": #GP(0) if an attempt is made to clear XCR0[0].
  if (!(xcr0 & X86_XSAVE_STATE_BIT_X87)) {
    return zx::error(ZX_ERR_INVALID_ARGS);
  }

  // Volume 1, Section 13.3 / Volume 2, "XSETBV": components that are only
  // meaningful together must be enabled together, and XSETBV enforces it with a
  // #GP. Each pairing below is one of those rules.

  // AVX (2) is the upper half of the SSE registers, so it requires SSE (1).
  if ((xcr0 & X86_XSAVE_STATE_BIT_AVX) && !(xcr0 & X86_XSAVE_STATE_BIT_SSE)) {
    return zx::error(ZX_ERR_INVALID_ARGS);
  }

  // MPX: BNDREGS (3) and BNDCSR (4) are set or cleared together, never split.
  constexpr uint64_t kMpx = X86_XSAVE_STATE_BIT_MPX_BNDREG | X86_XSAVE_STATE_BIT_MPX_BNDCSR;
  if ((xcr0 & kMpx) != 0 && (xcr0 & kMpx) != kMpx) {
    return zx::error(ZX_ERR_INVALID_ARGS);
  }

  // AVX-512: opmask (5), ZMM_Hi256 (6) and Hi16_ZMM (7) are all set or all
  // clear, and enabling them requires AVX (and hence, by the rule above, SSE).
  constexpr uint64_t kAvx512 = X86_XSAVE_STATE_BIT_AVX512_OPMASK |
                               X86_XSAVE_STATE_BIT_AVX512_LOWERZMM_HIGH |
                               X86_XSAVE_STATE_BIT_AVX512_HIGHERZMM;
  if ((xcr0 & kAvx512) != 0) {
    if ((xcr0 & kAvx512) != kAvx512 || !(xcr0 & X86_XSAVE_STATE_BIT_AVX)) {
      return zx::error(ZX_ERR_INVALID_ARGS);
    }
  }

  // AMX: XTILEDATA (18) is meaningless without the XTILECFG (17) that describes
  // its shape, and XSETBV refuses that combination. The converse -- XTILECFG
  // alone -- is architecturally allowed, so it is not rejected here. These bits
  // have no X86_XSAVE_STATE_BIT_* names in this tree because nothing else refers
  // to them; name them locally rather than invent kernel-wide constants.
  constexpr uint64_t kXtilecfg = 1ull << 17;
  constexpr uint64_t kXtiledata = 1ull << 18;
  if ((xcr0 & kXtiledata) && !(xcr0 & kXtilecfg)) {
    return zx::error(ZX_ERR_INVALID_ARGS);
  }

  // Not an SDM rule -- a rule about this kernel's buffers, and the reason the
  // architectural checks alone are not enough.
  //
  // Both XSAVE areas involved are fixed-size: Vcpu::extended_register_state_ and
  // arch_thread::extended_register_buffer are X86_MAX_EXTENDED_REGISTER_SIZE
  // bytes. XSAVE/XRSTOR write and read components selected by the *live* XCR0,
  // which between LoadExtendedRegisters() and SaveExtendedRegisters() is the
  // guest's. So an XCR0 that is entirely legal to XSETBV but selects more state
  // than 1 KiB -- AVX-512 needs roughly 2.5 KiB -- makes the host's own
  // x86_extended_register_save_state() overrun the Vcpu object. That is memory
  // corruption rather than a fault, so it is checked here, where the value is
  // still refusable.
  // compute_xsave_size() measures the STANDARD layout. When the host uses
  // XSAVES it writes the compacted layout, which is never larger, so this bound
  // is conservative: it can refuse a component set that would in fact have fit
  // compacted, but it can never admit one that overruns. Deliberate -- this
  // function cannot see which instruction registers.cc will issue, and the
  // safe direction of that ignorance is to over-refuse.
  auto xsave_size = xsave_size_fn(xcr0);
  if (xsave_size.is_error()) {
    return xsave_size.take_error();
  }
  if (*xsave_size > X86_MAX_EXTENDED_REGISTER_SIZE) {
    return zx::error(ZX_ERR_INVALID_ARGS);
  }

  return zx::ok();
}

zx::result<> ValidateGuestXcr0(uint64_t xcr0) {
  if (!x86_xsave_supported()) {
    return ValidateGuestXcr0Rules(xcr0, /*xsave_supported=*/false, /*supported=*/0,
                                  compute_xsave_size);
  }
  cpuid_leaf leaf;
  if (!x86_get_cpuid_subleaf(X86_CPUID_XSAVE, 0, &leaf)) {
    return zx::error(ZX_ERR_INTERNAL);
  }
  // Silicon's answer, minus the components this hypervisor withholds from
  // guests. Narrowing only ever refuses more, so this cannot admit a value the
  // host's own XSETBV would fault on -- and it is the same mask handle_cpuid
  // uses to decide what to advertise, which is the point: a component the guest
  // is never told about must not be one a guest XCR0 may name. See
  // kGuestWithheldXsaveComponents.
  const uint64_t supported =
      GuestXsaveComponents((static_cast<uint64_t>(leaf.d) << 32) | leaf.a);
  return ValidateGuestXcr0Rules(xcr0, /*xsave_supported=*/true, supported, compute_xsave_size);
}

zx::result<> ValidateXsaveImageRules(const uint8_t* image, const XsaveRestoreEnv& env) {
  // Why this is a *host* safety check, exactly as ValidateGuestXcr0 above is.
  //
  // These 1024 bytes are entirely caller-supplied (the `xsave` member of
  // VcpuArchState, which arrives through zx_vcpu_write_state's whole-state
  // topic). Vcpu::RestoreArchState copies them into extended_register_state_,
  // and swap_extended_registers() then feeds that buffer to
  // x86_extended_register_restore_state() -- XRSTORS, XRSTOR or FXRSTOR -- while
  // the HOST is running. Every #GP condition of those instructions is therefore
  // a kernel fault reachable from any caller holding a VCPU handle, not a guest
  // fault. Each rule below is one of those conditions.
  //
  // The environment is a parameter rather than read from the CPU here so that
  // these rules can be driven directly against a synthetic machine -- a host
  // that issues an instruction this one does not, an MXCSR_MASK this part does
  // not have, an XCR0 with components no CPU here implements. Nothing in this
  // function may consult the real CPU.

  // A host that restores no extended register state at all executes none of the
  // three instructions, so nothing in this image can fault it.
  if (env.instruction == X86_EXTENDED_REGISTER_RESTORE_NONE) {
    return zx::ok();
  }

  // MXCSR lives in the legacy area at offset 24, and is the one field all three
  // instructions can fault on. Volume 1, Section 11.6.6: bits outside MXCSR_MASK
  // are reserved and loading one is a #GP.
  //
  // Checked exactly when the instruction would load it, and not otherwise.
  // FXRSTOR always loads it. XRSTOR loads it when the restore mask selects SSE or
  // AVX state, and here RFBM is `~0 & XCR0` (see
  // x86_extended_register_restore_state), so that condition is
  // `live_xcr0 & (SSE | AVX)`. XRSTORS keys it on SSE alone; testing AVX as well
  // costs nothing, because ValidateGuestXcr0Rules() refuses an XCR0 with AVX and
  // not SSE, so no XCR0 that reaches here can have one without the other.
  // Under an x87-only XCR0 those four bytes are dead
  // and the hardware never inspects them -- and they really can be arbitrary in a
  // legitimate image, because an XSAVE whose mask lacks SSE and AVX does not
  // write the field either, leaving whatever the destination held. Refusing such
  // an image would be refusing a value hardware accepts.
  //
  // This is exact only because the XCR0 an image is validated against is the one
  // in force at every restore of it: Vcpu::RestoreArchState installs `in.xcr0`
  // and `in.xsave` together, having validated the pair.
  //
  // A guest XSETBV is effective, so this paragraph used to end with
  // "if guest XSETBV is ever made to take effect, it must re-validate the image
  // against the new value". It does not, and the argument is in handle_xsetbv:
  // enlarging XCR0 restores nothing, and the load/save protocol guarantees the
  // buffer is re-saved -- under the new XCR0, from a legal hardware MXCSR --
  // before it can be restored again. So the XCR0 in force at any restore of this
  // buffer is still one that the image in it was written under.
  const bool mxcsr_is_loaded =
      env.instruction == X86_EXTENDED_REGISTER_RESTORE_FXRSTOR ||
      (env.live_xcr0 & (X86_XSAVE_STATE_BIT_SSE | X86_XSAVE_STATE_BIT_AVX)) != 0;
  if (mxcsr_is_loaded) {
    uint32_t mxcsr;
    memcpy(&mxcsr, image + 24, sizeof(mxcsr));
    if ((mxcsr & ~env.mxcsr_mask) != 0) {
      return zx::error(ZX_ERR_INVALID_ARGS);
    }
  }

  // FXRSTOR reads only the 512-byte legacy area: it has no XSAVE header, so
  // nothing past MXCSR can fault it.
  if (env.instruction == X86_EXTENDED_REGISTER_RESTORE_FXRSTOR) {
    return zx::ok();
  }

  // The 64-byte XSAVE header at offset 512: XSTATE_BV, then XCOMP_BV, then 48
  // reserved bytes.
  uint64_t xstate_bv, xcomp_bv;
  memcpy(&xstate_bv, image + kXsaveLegacyRegionSize, sizeof(xstate_bv));
  memcpy(&xcomp_bv, image + kXsaveLegacyRegionSize + sizeof(xstate_bv), sizeof(xcomp_bv));

  // Volume 2, "XRSTOR"/"XRSTORS": #GP(0) if bytes 63:16 of the XSAVE header are
  // not all zero.
  constexpr size_t kHeaderReservedOffset = kXsaveLegacyRegionSize + 16;
  constexpr size_t kHeaderReservedSize = kXsaveHeaderSize - 16;
  for (size_t i = 0; i < kHeaderReservedSize; ++i) {
    if (image[kHeaderReservedOffset + i] != 0) {
      return zx::error(ZX_ERR_INVALID_ARGS);
    }
  }

  constexpr uint64_t kXcompBvCompacted = 1ull << 63;
  const bool compacted = (xcomp_bv & kXcompBvCompacted) != 0;
  const uint64_t xcomp_components = xcomp_bv & ~kXcompBvCompacted;

  if (env.instruction == X86_EXTENDED_REGISTER_RESTORE_XRSTORS) {
    // XRSTORS restores the compacted format and only the compacted format:
    // Volume 2, "XRSTORS", #GP(0) if bit 63 of XCOMP_BV is 0.
    if (!compacted) {
      return zx::error(ZX_ERR_INVALID_ARGS);
    }
    // #GP(0) if XCOMP_BV sets a bit that is not set in XCR0 | IA32_XSS.
    //
    // Tested against the live XCR0 alone, which is stricter than the
    // architectural rule by exactly the supervisor (IA32_XSS) components. That
    // is deliberate and does two jobs: this kernel's save path never places an
    // XSS component in this buffer, and the 1 KiB bound the XCR0 validator
    // proved (compute_xsave_size(xcr0) <= X86_MAX_EXTENDED_REGISTER_SIZE) only
    // covers components in XCR0. An XSS component admitted here would be one the
    // buffer was never sized for.
    if ((xcomp_components & ~env.live_xcr0) != 0) {
      return zx::error(ZX_ERR_INVALID_ARGS);
    }
    // #GP(0) if XSTATE_BV sets a bit that is not set in XCOMP_BV. (Together with
    // the rule above this also gives XSTATE_BV a subset of the live XCR0.)
    if ((xstate_bv & ~xcomp_components) != 0) {
      return zx::error(ZX_ERR_INVALID_ARGS);
    }
    return zx::ok();
  }

  // XRSTOR.
  //
  // Architecturally XRSTOR can consume the compacted format too, on a part that
  // reports XSAVEC; it is not a standard-format-only instruction. Rejecting every
  // compacted image here is therefore deliberately stricter than hardware, and
  // costs nothing: this host only reaches XRSTOR when it is not using XSAVES, and
  // then x86_extended_register_save_state() falls back to XSAVEOPT or XSAVE, both
  // of which write XCOMP_BV as zero. No legitimate round trip on such a host
  // produces a compacted image, so refusing one keeps this check off a CPUID
  // capability the restore path does not otherwise use. Volume 2, "XRSTOR":
  // #GP(0) if bit 63 of XCOMP_BV is 0 and bits 62:0 are not all zero, and #GP(0)
  // if bit 63 is 1 and XSAVEC is not supported.
  if (xcomp_bv != 0) {
    return zx::error(ZX_ERR_INVALID_ARGS);
  }
  // Volume 2, "XRSTOR": #GP(0) if XSTATE_BV sets a bit that is not set in XCR0.
  if ((xstate_bv & ~env.live_xcr0) != 0) {
    return zx::error(ZX_ERR_INVALID_ARGS);
  }
  return zx::ok();
}

zx::result<> ValidateGuestXsaveImage(const uint8_t* image, uint64_t guest_xcr0) {
  const XsaveRestoreEnv env = {
      .instruction = x86_extended_register_restore_instruction(),
      // The XCR0 that will be live at every XRSTOR of this image.
      //
      // swap_extended_registers() sets the physical XCR0 to the guest's before
      // restoring the guest's buffer and back to the host's before restoring the
      // host's, and Vcpu::LoadExtendedRegisters/SaveExtendedRegisters gate both
      // halves on the single predicate x86_xsave_supported() -- see the comment
      // there, which exists to keep that predicate from acquiring a second term.
      // So the image is loaded under the guest's XCR0 and saved under the
      // guest's XCR0, always the same one, and `guest_xcr0` here is that value.
      .live_xcr0 = guest_xcr0,
      .mxcsr_mask = x86_mxcsr_mask(),
  };
  return ValidateXsaveImageRules(image, env);
}

// Number of VCPUs addressed by one x2APIC logical cluster. Fixed by the LDR
// encoding: the logical ID is a 16-bit one-hot field.
static constexpr uint32_t kVcpusPerCluster = 16;
static_assert(Guest::kMaxGuestVcpus % kVcpusPerCluster == 0,
              "the VCPU mask must hold a whole number of x2APIC clusters");

uint32_t x2apic_logical_id(uint32_t apic_id) {
  // Cluster ID is ID[19:4] -- 16 bits, so it is masked rather than merely
  // shifted -- and the logical ID is a one-hot bit selected by ID[3:0].
  return (((apic_id >> 4) & 0xffff) << 16) | (1u << (apic_id & 0xf));
}

uint64_t x2apic_logical_target_mask(uint32_t destination) {
  constexpr uint32_t kClusters = Guest::kMaxGuestVcpus / kVcpusPerCluster;
  const uint32_t cluster = destination >> 16;
  // No VCPU lives in this cluster, so nothing is a target. Note this also covers
  // every cluster ID that would shift the logical IDs out of the mask entirely.
  if (cluster >= kClusters) {
    return 0;
  }
  const uint64_t logical_ids = destination & 0xffff;
  return logical_ids << (cluster * kVcpusPerCluster);
}

void SyncVirtualApicPage(LocalApicState& state, uint32_t apic_id) {
  if (state.x2apic_enabled || state.virtual_apic == nullptr) {
    return;
  }

  auto write = [&state](uint32_t offset, uint32_t value) {
    state.virtual_apic[offset / sizeof(uint32_t)] = value;
  };

  // xAPIC exposes the 8-bit ID in bits 31:24; the x2APIC MSR exposes the same
  // ID unshifted. The version value matches handle_apic_rdmsr.
  write(0x020, (apic_id & 0xffu) << 24);
  write(0x030, 0x15u | (0x6u << 16));
  write(0x090, 0);
  write(0x0a0, guest_ppr(state));
  write(0x0d0, state.xapic_ldr);
  write(0x0e0, state.xapic_dfr);
  write(0x0f0, state.svr);

  uint32_t highest_requested = 0;
  for (uint32_t i = 0; i < 8; ++i) {
    const uint32_t base = i * 32u;
    const uint32_t irr = requestable(state, base);
    write(0x100 + i * 0x10, state.isr[i]);
    write(0x180 + i * 0x10, 0);
    write(0x200 + i * 0x10, irr);
    if (irr != 0) {
      highest_requested = base + 31u - static_cast<uint32_t>(__builtin_clz(irr));
    }
  }
  write(0x090, guest_apr(state, highest_requested));

  write(0x280, 0);
  write(0x2f0, state.lvt_cmci);
  write(0x300, static_cast<uint32_t>(state.icr));
  write(0x310, static_cast<uint32_t>(state.icr >> 32) << 24);
  write(0x320, state.lvt_timer);
  write(0x330, state.lvt_thermal);
  write(0x340, state.lvt_monitor);
  write(0x350, state.lvt_lint0);
  write(0x360, state.lvt_lint1);
  write(0x370, state.lvt_error);
  write(0x380, state.lvt_initial_count);
  write(0x390, current_count(state));
  write(0x3e0, state.lvt_divide_config);
}

void RearmApicTimer(LocalApicState& local_apic_state, zx_instant_mono_t deadline) {
  // Thin external entry point onto the file-local update_timer(), so snapshot
  // restore (in vcpu.cc) can reconstruct the guest's one-shot APIC timer through
  // the same arming path a live guest exit uses.
  update_timer(local_apic_state, deadline);
  // A restored deadline is monotonic and has no raw-tick counterpart; whatever
  // tick deadline this VCPU's state happens to carry belongs to a different
  // arming and must not be used. Clearing it puts CURRENT_COUNT on the coarse
  // derivation until the guest programs the timer again, which is the honest
  // answer rather than a precise wrong one.
  local_apic_state.timer_tsc_deadline = 0;
}

ExitInfo::ExitInfo(const AutoVmcs& vmcs) {
  // From Volume 3, Section 26.7.
  uint32_t full_exit_reason = vmcs.Read(VmcsField32::EXIT_REASON);
  entry_failure = BIT(full_exit_reason, 31);
  exit_reason = static_cast<ExitReason>(BITS(full_exit_reason, 15, 0));

  exit_instruction_length = vmcs.Read(VmcsField32::EXIT_INSTRUCTION_LENGTH);
  guest_rip = vmcs.Read(VmcsFieldXX::GUEST_RIP);

  if (exit_reason == ExitReason::EXTERNAL_INTERRUPT || exit_reason == ExitReason::IO_INSTRUCTION) {
    return;
  }

  LTRACEF("entry failure: %d\n", entry_failure);
  LTRACEF("exit reason: %#x (%s)\n", static_cast<uint32_t>(exit_reason),
          exit_reason_name(exit_reason));
  LTRACEF("exit instruction length: %#x\n", exit_instruction_length);
  LTRACEF("guest activity state: %#x\n", vmcs.Read(VmcsField32::GUEST_ACTIVITY_STATE));
  LTRACEF("guest interruptibility state: %#x\n",
          vmcs.Read(VmcsField32::GUEST_INTERRUPTIBILITY_STATE));
  LTRACEF("guest linear address: %#lx\n", vmcs.Read(VmcsFieldXX::GUEST_LINEAR_ADDRESS));
  LTRACEF("guest rip: %#lx\n", guest_rip);
}

ExitInterruptionInfo::ExitInterruptionInfo(const AutoVmcs& vmcs) {
  uint32_t int_info = vmcs.Read(VmcsField32::EXIT_INTERRUPTION_INFORMATION);
  vector = static_cast<uint8_t>(BITS(int_info, 7, 0));
  interruption_type = static_cast<InterruptionType>(BITS_SHIFT(int_info, 10, 8));
  error_code_valid = BIT(int_info, 11);
  valid = BIT(int_info, 31);
}

PageFaultInfo::PageFaultInfo(uint32_t error_code) {
  // From Volume 3A, Figure 4-12.
  flags = 0;
  flags |= (error_code & PFEX_W) ? VMM_PF_FLAG_WRITE : 0;
  flags |= (error_code & PFEX_U) ? VMM_PF_FLAG_USER : 0;
  flags |= (error_code & PFEX_I) ? VMM_PF_FLAG_INSTRUCTION : 0;
  flags |= (error_code & PFEX_P) ? 0 : VMM_PF_FLAG_NOT_PRESENT;
}

EptViolationInfo::EptViolationInfo(uint64_t qualification) {
  // From Volume 3C, Table 27-7.
  read = BIT(qualification, 0);
  write = BIT(qualification, 1);
  instruction = BIT(qualification, 2);
}

CrAccessInfo::CrAccessInfo(uint64_t qualification) {
  // From Volume 3, Table 27-3.
  cr_number = static_cast<uint8_t>(BITS(qualification, 3, 0));
  access_type = static_cast<CrAccessType>(BITS_SHIFT(qualification, 5, 4));
  reg = static_cast<uint8_t>(BITS_SHIFT(qualification, 11, 8));
}

IoInfo::IoInfo(uint64_t qualification) {
  access_size = static_cast<uint8_t>(BITS(qualification, 2, 0) + 1);
  input = BIT_SHIFT(qualification, 3);
  string = BIT_SHIFT(qualification, 4);
  repeat = BIT_SHIFT(qualification, 5);
  port = static_cast<uint16_t>(BITS_SHIFT(qualification, 31, 16));
}

InterruptCommandRegister::InterruptCommandRegister(uint32_t hi, uint32_t lo) {
  destination = hi;
  destination_mode = static_cast<InterruptDestinationMode>(BIT_SHIFT(lo, 11));
  delivery_mode = static_cast<InterruptDeliveryMode>(BITS_SHIFT(lo, 10, 8));
  destination_shorthand = static_cast<InterruptDestinationShorthand>(BITS_SHIFT(lo, 19, 18));
  vector = static_cast<uint8_t>(BITS(lo, 7, 0));
}

VmCallInfo::VmCallInfo(const GuestState& guest_state) {
  // ABI is documented in Linux kernel documentation, see
  // Documents/virtual/kvm/hypercalls.txt
  type = static_cast<VmCallType>(guest_state.rax);
  arg[0] = guest_state.rbx;
  arg[1] = guest_state.rcx;
  arg[2] = guest_state.rdx;
  arg[3] = guest_state.rsi;
}

zx::result<> vmexit_handler(AutoVmcs& vmcs, GuestState& guest_state,
                            LocalApicState& local_apic_state, PvClockState& pv_clock,
                            Guest& guest, hypervisor::GuestPhysicalAspace& gpa,
                            hypervisor::TrapMap& traps,
                            zx_port_packet_t& packet, const VcpuEnlightenment& enlightenment,
                            uint16_t vpid, int64_t tsc_offset, const EoiBitmap& eoi_interest,
                            UnhandledMsrLog& unhandled_msrs, UnhandledIoLog& unhandled_io,
                            uint64_t& host_nmis_redispatched) {
  zx::result<> result = zx::ok();
  const ExitInfo exit_info(vmcs);
  // Set by the two exits that have a guest-physical address to report,
  // and put into the halt packet by the epilogue. Read from the VMCS while it is
  // still current: handle_ept_violation invalidates it so that it can block.
  zx_gpaddr_t halt_physical_address = 0;
  switch (exit_info.exit_reason) {
    case ExitReason::EXTERNAL_INTERRUPT:
      ktrace_vcpu_exit(VCPU_EXTERNAL_INTERRUPT, exit_info.guest_rip);
      GUEST_STATS_INC(interrupts);
      handle_external_interrupt(vmcs);
      break;
    case ExitReason::INTERRUPT_WINDOW:
      ktrace_vcpu_exit(VCPU_INTERRUPT_WINDOW, exit_info.guest_rip);
      GUEST_STATS_INC(interrupt_windows);
      handle_interrupt_window(vmcs);
      break;
    case ExitReason::NMI_WINDOW:
      // Unreachable before virtual NMIs were adopted -- the control that
      // produces this exit cannot be set without them -- and, being absent from
      // this switch, it would have fallen to `default` and halted the guest.
      ktrace_vcpu_exit(VCPU_INTERRUPT_WINDOW, exit_info.guest_rip);
      handle_nmi_window(vmcs, local_apic_state);
      break;
    case ExitReason::TPR_BELOW_THRESHOLD:
      ktrace_vcpu_exit(VCPU_TPR_BELOW_THRESHOLD, exit_info.guest_rip);
      local_apic_state.tpr_below_threshold_exits++;
      handle_tpr_below_threshold();
      break;
    case ExitReason::APIC_ACCESS:
      ktrace_vcpu_exit(VCPU_NOT_SUPPORTED, exit_info.guest_rip);
      result = handle_apic_access();
      break;
    case ExitReason::APIC_WRITE:
      ktrace_vcpu_exit(VCPU_WRMSR, exit_info.guest_rip);
      result = handle_apic_write(exit_info, vmcs, local_apic_state, eoi_interest, packet);
      break;
    case ExitReason::CPUID:
      ktrace_vcpu_exit(VCPU_CPUID, exit_info.guest_rip);
      GUEST_STATS_INC(cpuid_instructions);
      result = handle_cpuid(exit_info, vmcs, guest_state, enlightenment);
      break;
    case ExitReason::HLT:
      ktrace_vcpu_exit(VCPU_HLT, exit_info.guest_rip);
      GUEST_STATS_INC(hlt_instructions);
      result = handle_hlt(exit_info, vmcs, local_apic_state);
      break;
    case ExitReason::CONTROL_REGISTER_ACCESS:
      ktrace_vcpu_exit(VCPU_CONTROL_REGISTER_ACCESS, exit_info.guest_rip);
      GUEST_STATS_INC(control_register_accesses);
      result = handle_control_register_access(exit_info, vmcs, guest_state, local_apic_state);
      break;
    case ExitReason::IO_INSTRUCTION:
      ktrace_vcpu_exit(VCPU_IO_INSTRUCTION, exit_info.guest_rip);
      GUEST_STATS_INC(io_instructions);
      result = handle_io_instruction(exit_info, vmcs, guest_state, traps, packet, unhandled_io);
      break;
    case ExitReason::RDMSR:
      ktrace_vcpu_exit(VCPU_RDMSR, exit_info.guest_rip);
      GUEST_STATS_INC(rdmsr_instructions);
      result = handle_rdmsr(exit_info, vmcs, guest_state, local_apic_state,
                            enlightenment.delegate_synthetic_msrs, tsc_offset, packet,
                            unhandled_msrs);
      break;
    case ExitReason::WRMSR:
      ktrace_vcpu_exit(VCPU_WRMSR, exit_info.guest_rip);
      GUEST_STATS_INC(wrmsr_instructions);
      result = handle_wrmsr(exit_info, vmcs, guest_state, local_apic_state, pv_clock, gpa, packet,
                            enlightenment.delegate_synthetic_msrs, enlightenment.hyperv_identity,
                            tsc_offset, eoi_interest, unhandled_msrs);
      break;
    case ExitReason::ENTRY_FAILURE_GUEST_STATE:
    case ExitReason::ENTRY_FAILURE_MSR_LOADING:
    case ExitReason::ENTRY_FAILURE_MACHINE_CHECK:
      ktrace_vcpu_exit(VCPU_VM_ENTRY_FAILURE, exit_info.guest_rip);
      result = zx::error(ZX_ERR_BAD_STATE);
      break;
    case ExitReason::EPT_VIOLATION:
      ktrace_vcpu_exit(VCPU_EPT_VIOLATION, exit_info.guest_rip);
      GUEST_STATS_INC(ept_violations);
      halt_physical_address = vmcs.Read(VmcsField64::GUEST_PHYSICAL_ADDRESS);
      result = handle_ept_violation(exit_info, vmcs, guest, vpid, gpa, traps, packet);
      break;
    case ExitReason::EPT_MISCONFIGURATION:
      // Still fatal, and correctly so: a misconfigured EPT entry is a
      // hypervisor bug, and resuming only takes the same exit again. What
      // changes is that it is now diagnosable -- the address whose EPT entry is
      // malformed is the single most useful fact about it, and it used to reach
      // neither the log nor the VMM. Handled explicitly rather than through
      // `default` so this cannot regress into an anonymous halt.
      ktrace_vcpu_exit(VCPU_NOT_SUPPORTED, exit_info.guest_rip);
      halt_physical_address = vmcs.Read(VmcsField64::GUEST_PHYSICAL_ADDRESS);
      dprintf(CRITICAL,
              "hypervisor: EPT MISCONFIGURATION at guest-physical %#lx (guest RIP %#lx) -- an EPT "
              "paging-structure entry for this address is malformed\n",
              halt_physical_address, exit_info.guest_rip);
      result = zx::error(ZX_ERR_NOT_SUPPORTED);
      break;
    case ExitReason::XSETBV:
      ktrace_vcpu_exit(VCPU_XSETBV, exit_info.guest_rip);
      GUEST_STATS_INC(xsetbv_instructions);
      result = handle_xsetbv(exit_info, vmcs, guest_state, local_apic_state);
      break;
    case ExitReason::PAUSE:
      ktrace_vcpu_exit(VCPU_PAUSE, exit_info.guest_rip);
      GUEST_STATS_INC(pause_instructions);
      handle_pause(exit_info, vmcs);
      break;
    case ExitReason::VMCALL:
      ktrace_vcpu_exit(VCPU_VMCALL, exit_info.guest_rip);
      GUEST_STATS_INC(vmcall_instructions);
      result = handle_vmcall(exit_info, vmcs, guest_state, gpa, enlightenment, local_apic_state,
                             tsc_offset, packet);
      break;
    case ExitReason::MONITOR_TRAP_FLAG: {
      // Host-assisted single-step is one-shot. Clear MTF before returning the
      // typed debug exit so a caller can resume without an extra write and run
      // freely. An unrelated VM exit does not pass through this arm, so it does
      // not consume a step that was still pending before an instruction
      // completed.
      //
      // VMX also reserves interruption type 7 ("other event") for a pending
      // monitor-trap event in the VM-entry field. CaptureVectoringEvent
      // deliberately never treats that type as a guest IDT event: re-injecting
      // it as an exception would corrupt guest state. The architectural signal
      // consumed here is exit reason 37 itself.
      ktrace_vcpu_exit(VCPU_EXCEPTION_OR_NMI, exit_info.guest_rip);
      const uint32_t primary = vmcs.Read(VmcsField32::PROCBASED_CTLS);
      const uint32_t desired = primary & ~kProcbasedCtlsMonitorTrapFlag;
      result =
          vmcs.SetControl(VmcsField32::PROCBASED_CTLS,
                          read_msr(X86_MSR_IA32_VMX_TRUE_PROCBASED_CTLS),
                          read_msr(X86_MSR_IA32_VMX_PROCBASED_CTLS), desired, ~desired);
      if (result.is_ok()) {
        memset(&packet, 0, sizeof(packet));
        packet.type = ZX_PKT_TYPE_GUEST_EXCEPTION;
        packet.guest_exception.vector = X86_INT_DEBUG;
        packet.guest_exception.rip = exit_info.guest_rip;
        result = zx::error(ZX_ERR_NEXT);
      }
      break;
    }
    case ExitReason::VMX_PREEMPT_TIMER_EXPIRED: {
      // The bounded run completed. Make the timer one-shot before returning
      // so an ordinary resume cannot inherit a stale zero-valued timer.
      const uint32_t pinbased = vmcs.Read(VmcsField32::PINBASED_CTLS);
      const uint32_t desired_pinbased = pinbased & ~kPinbasedCtlsPreemptionTimer;
      result =
          vmcs.SetControl(VmcsField32::PINBASED_CTLS,
                          read_msr(X86_MSR_IA32_VMX_TRUE_PINBASED_CTLS),
                          read_msr(X86_MSR_IA32_VMX_PINBASED_CTLS), desired_pinbased,
                          ~desired_pinbased);
      if (result.is_ok()) {
        const uint32_t exit = vmcs.Read(VmcsField32::EXIT_CTLS);
        const uint32_t desired_exit = exit & ~kExitCtlsSaveVmxPreemptionTimer;
        result =
            vmcs.SetControl(VmcsField32::EXIT_CTLS,
                            read_msr(X86_MSR_IA32_VMX_TRUE_EXIT_CTLS),
                            read_msr(X86_MSR_IA32_VMX_EXIT_CTLS), desired_exit,
                            ~desired_exit);
      }
      if (result.is_ok()) {
        vmcs.Write(VmcsField32::VMX_PREEMPTION_TIMER_VALUE, 0);
        result = zx::error(ZX_ERR_TIMED_OUT);
      }
      break;
    }
    case ExitReason::EXCEPTION_OR_NMI:
      // A trapped #BP (opt-in via Vcpu::SetBreakpointTrapping) is surfaced to
      // userspace. A host NMI is re-dispatched to the host's own vector 2 and
      // the guest resumes -- see handle_exception_or_nmi for why this exit is
      // where a host NMI lands at all, which is the opposite of what this
      // comment used to assert. Other exceptions are delivered directly to
      // guests (the exception bitmap is 0) and so are not expected here.
      ktrace_vcpu_exit(VCPU_EXCEPTION_OR_NMI, exit_info.guest_rip);
      result = handle_exception_or_nmi(exit_info, vmcs, packet, host_nmis_redispatched);
      break;
    case ExitReason::TRIPLE_FAULT:
      ktrace_vcpu_exit(VCPU_FAILURE, exit_info.guest_rip);
      // A guest that faults with no usable handler shuts itself down, and cannot
      // be resumed: re-entering only reproduces the fault. Report it so the VMM
      // can say what happened and where, instead of the guest appearing to hang
      // while the kernel log fills.
      memset(&packet, 0, sizeof(packet));
      packet.type = ZX_PKT_TYPE_GUEST_HALT;
      packet.guest_halt.reason = ZX_PKT_GUEST_HALT_TRIPLE_FAULT;
      packet.guest_halt.rip = exit_info.guest_rip;
      result = zx::error(ZX_ERR_NEXT);
      break;
    default:
      ktrace_vcpu_exit(VCPU_NOT_SUPPORTED, exit_info.guest_rip);
      result = zx::error(ZX_ERR_NOT_SUPPORTED);
      break;
  }
  switch (result.status_value()) {
    case ZX_OK:
    case ZX_ERR_NEXT:
    // A host-armed execution timer is a successful bounded-run boundary,
    // surfaced as the syscall status rather than an unhandled guest exit.
    case ZX_ERR_TIMED_OUT:
    case ZX_ERR_INTERNAL_INTR_RETRY:
    case ZX_ERR_INTERNAL_INTR_KILLED:
    case ZX_ERR_CANCELED:
      break;
    default:
      dprintf(CRITICAL, "hypervisor: VM exit handler for %s (%u) returned %d\n",
              exit_reason_name(exit_info.exit_reason), static_cast<uint32_t>(exit_info.exit_reason),
              result.status_value());
      dump_guest_state(guest_state, exit_info);
      // Report the unserviced exit rather than resuming. The guest has made no
      // progress past whatever caused it, so resuming takes the same exit again;
      // previously this returned success and the VCPU span, visible only as
      // repeated complaints in the kernel log.
      memset(&packet, 0, sizeof(packet));
      packet.type = ZX_PKT_TYPE_GUEST_HALT;
      packet.guest_halt.reason = ZX_PKT_GUEST_HALT_UNHANDLED;
      packet.guest_halt.exit_reason = static_cast<uint32_t>(exit_info.exit_reason);
      packet.guest_halt.rip = exit_info.guest_rip;
      // Zero for every other exit reason, which is what the field documents.
      packet.guest_halt.physical_address = halt_physical_address;
      result = zx::error(ZX_ERR_NEXT);
      break;
  }
  return result;
}

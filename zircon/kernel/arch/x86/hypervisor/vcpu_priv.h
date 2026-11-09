// Copyright 2017 The Fuchsia Authors
//
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT

#ifndef ZIRCON_KERNEL_ARCH_X86_HYPERVISOR_VCPU_PRIV_H_
#define ZIRCON_KERNEL_ARCH_X86_HYPERVISOR_VCPU_PRIV_H_

#include <arch/arch_interrupt.h>
#include <arch/hypervisor.h>
#include <hypervisor/state_invalidator.h>
#include <kernel/auto_preempt_disabler.h>
#include <ktl/atomic.h>

// clang-format off

#define X86_MSR_IA32_VMX_PINBASED_CTLS                  0x0481
#define X86_MSR_IA32_VMX_PROCBASED_CTLS                 0x0482
#define X86_MSR_IA32_VMX_EXIT_CTLS                      0x0483
#define X86_MSR_IA32_VMX_ENTRY_CTLS                     0x0484
#define X86_MSR_IA32_VMX_PROCBASED_CTLS2                0x048b
#define X86_MSR_IA32_VMX_TRUE_PINBASED_CTLS             0x048d
#define X86_MSR_IA32_VMX_TRUE_PROCBASED_CTLS            0x048e
#define X86_MSR_IA32_VMX_TRUE_EXIT_CTLS                 0x048f
#define X86_MSR_IA32_VMX_TRUE_ENTRY_CTLS                0x0490

// PROCBASED_CTLS2 flags.
static const uint32_t kProcbasedCtls2ApicAccess         = 1u << 0;
static const uint32_t kProcbasedCtls2Ept                = 1u << 1;
static const uint32_t kProcbasedCtls2Rdtscp             = 1u << 3;
static const uint32_t kProcbasedCtls2x2Apic             = 1u << 4;
static const uint32_t kProcbasedCtls2Vpid               = 1u << 5;
static const uint32_t kProcbasedCtls2UnrestrictedGuest  = 1u << 7;
static const uint32_t kProcbasedCtls2ApicRegister       = 1u << 8;
// "Virtual-interrupt delivery" (Volume 3, Section 24.6.2). When set, the
// processor's virtual-APIC evaluates and delivers virtual interrupts and, in
// particular, completes a Hyper-V lazy EOI in hardware. This tree NEVER sets it
// (see vmcs_init's PROCBASED_CTLS2 write), so every lazy EOI IS completed by
// this kernel's software reconcile.
//
// THE OLD COMMENT HERE SAID `WriteLazyEoiState` GATES THE GRANT ON THIS BIT.
// It does not, and has not since lazy EOI shipped active: the grant is
// established regardless of this control, and the sole-in-service rule in
// `guest_lazy_eoi_arm` plus the software reconcile are what make it correct.
// This constant is referenced only by capability reporting.
static const uint32_t kProcbasedCtls2VirtualInterruptDelivery = 1u << 9;
static const uint32_t kProcbasedCtls2PauseLoopExiting   = 1u << 10;
static const uint32_t kProcbasedCtls2Invpcid            = 1u << 12;

// PROCBASED_CTLS flags.
static const uint32_t kProcbasedCtlsIntWindowExiting    = 1u << 2;
// Adds VMCS TSC_OFFSET to every guest TSC read (RDTSC, RDTSCP, RDMSR of
// IA32_TIME_STAMP_COUNTER). It is not paired with TSC scaling when the processor
// does not expose IA32_VMX_PROCBASED_CTLS2 secondary bit 25.
static const uint32_t kProcbasedCtlsUseTscOffsetting    = 1u << 3;
static const uint32_t kProcbasedCtlsHltExiting          = 1u << 7;
// The right instrument for a blocked NMI, and usable only when the "virtual
// NMIs" pin-based control below is also 1 -- VM entry rejects the pair
// (NMI-window exiting = 1, virtual NMIs = 0) with VM-instruction error 7. Named
// here so `print_vmx_capabilities_once` can report whether we are offered it.
static const uint32_t kProcbasedCtlsNmiWindowExiting    = 1u << 22;
static const uint32_t kProcbasedCtlsCr3LoadExiting      = 1u << 15;
static const uint32_t kProcbasedCtlsCr3StoreExiting     = 1u << 16;
static const uint32_t kProcbasedCtlsCr8LoadExiting      = 1u << 19;
static const uint32_t kProcbasedCtlsCr8StoreExiting     = 1u << 20;
static const uint32_t kProcbasedCtlsTprShadow           = 1u << 21;
// Intercept guest MOV to/from DR0-DR7 only while transparent host-owned slots
// are armed. Clear on the ordinary path.
static const uint32_t kProcbasedCtlsMovDrExiting        = 1u << 23;
static const uint32_t kProcbasedCtlsIoExiting           = 1u << 24;
// Exit after the next guest instruction without modifying guest RFLAGS.TF.
// Unlike guest single-step, this is a host-owned, one-shot debug instrument.
static const uint32_t kProcbasedCtlsMonitorTrapFlag     = 1u << 27;
static const uint32_t kProcbasedCtlsMsrBitmaps          = 1u << 28;
static const uint32_t kProcbasedCtlsProcbasedCtls2      = 1u << 31;

// PINBASED_CTLS flags.
static const uint32_t kPinbasedCtlsExtIntExiting        = 1u << 0;
static const uint32_t kPinbasedCtlsNmiExiting           = 1u << 3;
// Changes how NMI blocking is represented (the guest interruptibility
// state's NMI-blocking bit becomes "virtual NMI blocking", set by delivery and
// cleared by the guest's IRET) and is the prerequisite for NMI-window exiting.
static const uint32_t kPinbasedCtlsVirtualNmis          = 1u << 5;
// Decrement the VMX preemption timer while the CPU is in VMX non-root
// operation and exit when it reaches zero.
static const uint32_t kPinbasedCtlsPreemptionTimer      = 1u << 6;

// EXIT_CTLS flags.
static const uint32_t kExitCtlsSaveDebugControls        = 1u << 2;
static const uint32_t kExitCtls64bitMode                = 1u << 9;
// Load IA32_PERF_GLOBAL_CTRL from the host-state field on VM exit. Paired with
// the entry control below to make a VCPU instruction counter guest-only.
static const uint32_t kExitCtlsLoadIa32PerfGlobalCtrl   = 1u << 12;
static const uint32_t kExitCtlsAckIntOnExit             = 1u << 15;
static const uint32_t kExitCtlsSaveIa32Pat              = 1u << 18;
static const uint32_t kExitCtlsLoadIa32Pat              = 1u << 19;
static const uint32_t kExitCtlsSaveIa32Efer             = 1u << 20;
static const uint32_t kExitCtlsLoadIa32Efer             = 1u << 21;
// Preserve the remaining VMX preemption-timer count across unrelated VM
// exits. Without this, each handled exit re-enters with the original count and
// a sufficiently exit-heavy guest can postpone a bounded run indefinitely.
static const uint32_t kExitCtlsSaveVmxPreemptionTimer   = 1u << 22;
static const uint32_t kExitCtlsClearIa32RtitControl     = 1u << 25;

// ENTRY_CTLS flags.
static const uint32_t kEntryCtlsLoadDebugControls       = 1u << 2;
static const uint32_t kEntryCtls64bitMode               = 1u << 9;
static const uint32_t kEntryCtlsLoadIa32PerfGlobalCtrl  = 1u << 13;
static const uint32_t kEntryCtlsLoadIa32Pat             = 1u << 14;
static const uint32_t kEntryCtlsLoadIa32Efer            = 1u << 15;
static const uint32_t kEntryCtlsLoadIa32RtitControl     = 1u << 18;

// LINK_POINTER values.
static const uint64_t kLinkPointerInvalidate            = UINT64_MAX;

// Virtual-APIC page layout. From Volume 3, Section 30.1 ("Virtual-APIC State"):
// the virtual task-priority register (VTPR) is the 32-bit field at offset 0x80
// of the virtual-APIC page -- the same offset the TPR occupies in a real xAPIC
// page. With "use TPR shadow" set, `MOV to CR8` writes bits 7:4 of VTPR and
// `MOV from CR8` reads them, with no VM exit; VTPR is therefore where the
// guest's task priority actually lives, and the only place a hypervisor can
// read it from.
static const uint32_t kVirtualApicTprOffset             = 0x80;

// clang-format on

// A VMX control can be programmed to one whenever its capability MSR's
// allowed-one bit is set. The lower must-be-one bit does not need to be clear:
// if it is set, the control is forced to one, which already satisfies a caller
// that needs the control enabled.
constexpr bool vmx_control_allows_one(uint64_t capability, uint32_t bit) {
  const uint32_t may_be_one = static_cast<uint32_t>(capability >> 32);
  return (may_be_one & bit) != 0;
}

// The guest's task priority, as bits 7:4 of VTPR -- the interrupt priority class
// the guest has raised to. Zero on a VCPU whose virtual-APIC page has not been
// installed yet.
//
// This is one of the two terms of the *processor* priority; see `guest_ppr`
// below, which is what actually gates delivery. TPR alone is still needed on its
// own for one thing: deciding whether the TPR-threshold VM exit is an instrument
// that can release a held vector at all. The processor compares the threshold
// against VTPR and nothing else, so a vector held by an in-service interrupt
// rather than by the task priority cannot be released by it.
//
// The processor writes VTPR without a VM exit on every guest `MOV to CR8`, so
// this must be read afresh rather than cached across a VM entry.
inline uint8_t guest_tpr_class(const LocalApicState& state) {
  if (state.virtual_apic == nullptr) {
    return 0;
  }
  const uint32_t vtpr = state.virtual_apic[kVirtualApicTprOffset / sizeof(uint32_t)];
  return static_cast<uint8_t>((vtpr >> 4) & 0xf);
}

// Reads/writes the whole 8-bit VTPR, which is what the x2APIC TPR MSR (0x808)
// exposes. Bits 3:0 are the task-priority sub-class; `MOV to CR8` zeroes them,
// a TPR MSR write can set them.
inline uint32_t guest_tpr_read(const LocalApicState& state) {
  if (state.virtual_apic == nullptr) {
    return 0;
  }
  return state.virtual_apic[kVirtualApicTprOffset / sizeof(uint32_t)] & 0xff;
}

inline void guest_tpr_write(LocalApicState& state, uint32_t value) {
  if (state.virtual_apic == nullptr) {
    return;
  }
  state.virtual_apic[kVirtualApicTprOffset / sizeof(uint32_t)] = value & 0xff;
}

// ---- The in-service register, and the priority derived from it ----
//
// From Volume 3, Section 11.8.4, the local APIC delivers an interrupt only when
// its priority class -- bits 7:4 of its vector -- is *greater* than the
// processor's priority class. The processor priority is not the task priority:
// Section 11.8.3.1 defines it as
//
//     if TPR[7:4] >= ISRV[7:4]:  PPR = TPR
//     else:                      PPR = ISRV & 0xf0
//
// where ISRV is the highest vector currently in service. The second arm is what
// keeps an interrupt handler from being pre-empted by another interrupt of its
// own class, which is the property a Windows ISR is written against and the one
// no amount of TPR modelling can supply on its own.

inline void guest_isr_set(LocalApicState& state, uint32_t vector) {
  if (vector >= 256) {
    return;
  }
  state.isr[vector / 32] |= uint32_t{1} << (vector % 32);
}

inline void guest_isr_clear(LocalApicState& state, uint32_t vector) {
  if (vector >= 256) {
    return;
  }
  state.isr[vector / 32] &= ~(uint32_t{1} << (vector % 32));
}

inline bool guest_isr_get(const LocalApicState& state, uint32_t vector) {
  if (vector >= 256) {
    return false;
  }
  return (state.isr[vector / 32] & (uint32_t{1} << (vector % 32))) != 0;
}

// The highest vector in service, or 0 when the ISR is empty. Zero is not
// ambiguous: `guest_isr_set` is only ever called for platform vectors (at or
// above X86_INT_PLATFORM_BASE) and for the bare interrupt vectors 21..31 that
// enter service as guest ICR/device vectors. Vectors 0..X86_INT_VIRT are never
// set, so the lowest vector ever in service is 21 and a return of 0 can only
// mean the ISR is empty.
inline uint32_t guest_isrv(const LocalApicState& state) {
  for (int word = 7; word >= 0; word--) {
    const uint32_t bits = state.isr[word];
    if (bits != 0) {
      const uint32_t bit = 31u - static_cast<uint32_t>(__builtin_clz(bits));
      return static_cast<uint32_t>(word) * 32u + bit;
    }
  }
  return 0;
}

// The processor priority register, Volume 3, Section 11.8.3.1.
inline uint32_t guest_ppr(const LocalApicState& state) {
  const uint32_t tpr = guest_tpr_read(state);
  const uint32_t isrv = guest_isrv(state);
  return ((tpr >> 4) >= (isrv >> 4)) ? tpr : (isrv & 0xf0u);
}

// The processor's priority *class* -- the thing a candidate vector's own class
// must exceed for the vector to be delivered.
inline uint8_t guest_ppr_class(const LocalApicState& state) {
  return static_cast<uint8_t>((guest_ppr(state) >> 4) & 0xf);
}

// The arbitration priority register, Volume 3, Section 11.8.4. Read-only, and
// meaningful only alongside the highest requested vector, which the caller
// supplies because it lives in the interrupt tracker rather than here.
inline uint32_t guest_apr(const LocalApicState& state, uint32_t irrv) {
  const uint32_t tpr = guest_tpr_read(state);
  const uint32_t isrv = guest_isrv(state);
  if ((tpr >> 4) >= (irrv >> 4) && (tpr >> 4) > (isrv >> 4)) {
    return tpr;
  }
  const uint32_t a = isrv & 0xf0u;
  const uint32_t b = irrv & 0xf0u;
  return a > b ? a : b;
}

// End-of-interrupt: clear the highest in-service bit, which is the one the guest
// is acknowledging. Returns false, and changes nothing, when nothing is in
// service -- a real APIC ignores such an EOI too, and the distinction is what
// `LocalApicState::eoi_completions` counts.
//
// This is the single funnel every architectural EOI reaches this kernel
// through -- xAPIC MMIO (`handle_apic_write` -> `handle_apic_write_at_offset`
// -> `handle_apic_wrmsr`), x2APIC WRMSR (`handle_wrmsr` -> `handle_apic_wrmsr`
// directly), and the synthetic-alias xapic-access path a VMM uses for the
// Hyper-V EOI/ICR/TPR MSRs (`Vcpu::WriteXapicAccess` -> `WriteXapicRegister`
// -> `handle_apic_write_at_offset` -> `handle_apic_wrmsr`) all end up here,
// and nowhere else clears an ISR bit via an EOI (`vcpu.cc`'s two `guest_isr_
// clear` call sites undo an injection that never reached the guest, which is
// a different event).
//
// Cancels any outstanding lazy-EOI grant as a side effect, unconditionally,
// whenever this call actually retires a vector. A TLFS-compliant guest is not
// expected to reach here while its own bit is armed -- it is supposed to
// check the word first and take the memory-write skip instead -- but nothing
// stops it (a guest that ignores the word, or simply issues an EOI from a
// code path that never consulted it). Without this cancellation that guest
// can strand the grant holder forever: vector A armed, higher-priority B
// admitted and overwrites the grant to B (the word stays 1 -- see
// guest_lazy_eoi_arm), B issues a real EOI THROUGH THIS FUNCTION instead of
// the lazy path (retiring B correctly, by vector number, since B is top of
// ISR), but leaves the word at 1 and this kernel's bookkeeping still saying
// "armed for B". Control eventually reaches A's own epilogue, which finds
// the word still 1, consumes it (thinking it is A's own grant), and skips
// A's real EOI. Reconciliation then vector-clears B -- already retired, a
// no-op -- and A's ISR bit is never touched again: stuck forever. Cancelling
// here means the word reads 0 by the time A's epilogue runs, so A takes the
// honest EOI path instead and retires normally through this same function.
inline bool guest_isr_eoi(LocalApicState& state, uint32_t* vector) {
  const uint32_t isrv = guest_isrv(state);
  if (isrv == 0) {
    return false;
  }
  guest_isr_clear(state, isrv);
  *vector = isrv;

  if (state.lazy_eoi_armed) {
    uint32_t* word = state.lazy_eoi_guest_ptr.as<uint32_t>();
    if (word != nullptr) {
      ktl::atomic_ref<uint32_t>(*word).store(0, ktl::memory_order_relaxed);
    }
    // Bookkeeping only -- NOT lazy_eoi_completions. That counter is
    // specifically "the guest took the lazy skip and this kernel retired the
    // vector on its behalf"; this is the opposite case, an honest EOI that
    // happened to make an outstanding grant moot. The caller's own
    // eoi_completions already counts this as the real EOI it is.
    state.lazy_eoi_armed = false;
  }

  return true;
}

// ---- Lazy EOI (Hyper-V TLFS "no EOI required" VP-assist-page bit) ----
//
// See ZX_VCPU_STATE_LAZY_EOI's doc comment (zircon/system/public/zircon/
// syscalls/hypervisor.h) for the full mechanism. The guest-physical word lives
// in `state.lazy_eoi_guest_ptr`; these three functions are the only code that
// touches it, so every rule about when it is safe to arm or must be
// reconciled lives here rather than being re-derived at each call site.

// Whether lazy EOI is registered for this VCPU at all. A guest that never
// asked for it takes the `false` side of this check every time it is
// evaluated -- and, on the hottest path (every admitted external interrupt,
// on every VCPU, whether or not it is Hyper-V-enlightened), it is evaluated
// TWICE per Vcpu::Enter iteration: once by `guest_lazy_eoi_reconcile`'s own
// `lazy_eoi_armed` check called early in Vcpu::Enter (before the
// pending_event_ priority computation), and again by the same function's
// call at the top of `local_apic_maybe_interrupt`. Two predicted-not-taken
// branches, not one -- callers should mark both call sites accordingly (see
// each), and this function itself is written so its own condition is the
// rare one.
inline bool guest_lazy_eoi_registered(const LocalApicState& state) {
  return state.lazy_eoi_guest_paddr != 0;
}

// Arms a grant for `vector` -- but ONLY when `vector` is the SOLE in-service
// vector. Both call sites (`local_apic_maybe_interrupt`, and `Vcpu::Enter`'s
// pending-event block) call this immediately after `guest_isr_set` for exactly
// the vector they just admitted, so "sole" here means the ISR contains that
// one bit and nothing else.
//
// THE SOLE-VECTOR RULE IS THE WHOLE CORRECTNESS ARGUMENT, and it was learned
// the hard way. An earlier revision armed on the caller's admission gate alone
// (no same-or-higher class in service) and OVERWROTE an outstanding grant on
// nested admission, reasoning that ISR nesting made the overwrite sound. It
// does not, because the assist word is ONE flag shared by every epilogue while
// the ISR bits it stands in for are per-vector, and a nested vector's lazy
// skip produces NO VM exit. The stranding interleave, observed live (winnano
// on the G3/reactor, VMBus SINT 0x33 + IPI 0xd2):
//
//   1. A (0x33, class 3) admitted, sole -> ISR={A}, word=1, grant=A.
//   2. B (0xd2, class 0xd) nests -> ISR={A,B}, grant overwritten to B.
//   3. B's epilogue consumes the word (word->0), SKIPS its EOI -- a plain
//      guest-memory write, no exit, so B's ISR bit is still set and the
//      kernel has had no chance to reconcile.
//   4. A's epilogue reads word==0 -> takes the HONEST, exit-costing EOI.
//      `guest_isr_eoi` retires the highest in-service bit -- which is B's,
//      not A's -- and cancels the armed grant on the way.
//   5. Net: A's one EOI was spent on B's bit. Nothing will ever retire A:
//      the guest believes A is done, the grant is gone, and A's class is
//      blocked on this VCPU forever. For winnano that was the VMBus SINT
//      class -- messages stopped, I/O froze, vp0 spun re-sending IPIs.
//
// With the sole-vector rule the fraud is unconstructible: a grant can only
// name a vector with nothing beneath it, so a lazy skip can never leave an
// un-reconciled bit ABOVE a vector that still owes a real EOI. This also
// matches the TLFS posture for the "no EOI required" assist bit -- Hyper-V
// sets it only when the EOI being skipped could not affect any other
// in-service interrupt.
//
// The nested-admission branch must also REVOKE an outstanding grant, not
// merely decline to arm: the word still reads 1 for the vector beneath, and
// the vector being injected now would consume it at its own epilogue --
// skipping an EOI this kernel would then mis-attribute to the vector below
// (the same fraud, inverted). Revocation is safe here: this runs on the
// VCPU's own thread between reconcile (both admission paths reconcile before
// arming, and the guest has not executed since) and entry, so an armed grant
// still has word==1 -- there is no consumed grant to lose.
// PRECONDITION ON THE GUEST, and it cannot be enforced from this side: the
// sole-vector rule is sound only if the guest CONSUMES the assist word
// ATOMICALLY (a single read-modify-write -- Windows' HAL enlightenment uses
// `lock btr`). A guest whose epilogue instead does a separate load, test, then
// store can still strand itself, and no hypervisor-side change can close it,
// because the decision is made inside the guest between two instructions we do
// not sit between:
//
//   1. A admitted sole -> ISR={A}, word=1, armed=A.
//   2. A's epilogue LOADS the word, reads 1, decides to skip its EOI.
//   3. Before it stores 0, B nests: non-sole, so the revoke below stores
//      word=0 and clears armed.
//   4. B's epilogue loads 0 -> honest EOI -> retires top-of-ISR = B. Correct.
//   5. A's epilogue resumes on its now-STALE decision, stores 0 and skips its
//      EOI. A's bit is set, armed=false, word=0: nothing will ever retire A.
//
// With an atomic consume the hole closes from both sides -- the RMW either
// lands before B's admission (and the pre-arm reconcile retires A) or after
// the revoke (and returns 0, forcing the honest EOI). This is inherent to the
// one-flag TLFS design, not to this implementation.
inline void guest_lazy_eoi_arm(LocalApicState& state, uint32_t vector,
                               const EoiBitmap& eoi_interest) {
  // Most VCPUs, most of the time this is reached (an interrupt is actually
  // being admitted), are not Hyper-V lazy-EOI-enlightened: "not registered"
  // is the likely outcome here, not the rare one.
  if (likely(!guest_lazy_eoi_registered(state))) {
    return;
  }
  // Bound-check like guest_isr_set/clear/get do. Unreachable today, and that is
  // the point: without it, a vector >= 256 makes every `expect` below 0, so an
  // EMPTY ISR would look "sole" and arm a grant for a vector `guest_isr_set`
  // refused to record -- which reconcile would later count as a phantom lazy
  // completion against a bit that was never set.
  if (vector >= EoiBitmap::kNumVectors) {
    return;
  }
  uint32_t* word = state.lazy_eoi_guest_ptr.as<uint32_t>();
  if (word == nullptr) {
    // Registered but the mapping is gone (the topic was disabled since the
    // grant was issued). Nothing can be armed, and the stale bookkeeping is
    // dropped rather than left claiming a grant against a mapping that no
    // longer exists -- the same posture guest_lazy_eoi_reconcile takes.
    state.lazy_eoi_armed = false;
    return;
  }
  // TWO reasons to decline a grant, handled identically below so they cannot
  // drift apart:
  //
  // (1) EOI-TRAPPED. A vector the VMM asked to be notified about
  //     (ZX_GUEST_TRAP_EOI) must NEVER get a grant. The whole point of a grant
  //     is that the guest's EOI causes no VM exit -- but that exit is the only
  //     thing that produces the ZX_PKT_TYPE_GUEST_EOI packet, and
  //     `guest_lazy_eoi_reconcile` retires the ISR bit silently, with no
  //     reference to this bitmap. Granting would swallow the notification: an
  //     emulated IO-APIC's level-triggered line would never clear its remote
  //     IRR, so the device could never re-assert and the line wedges. The
  //     sole-in-service case is the COMMON case, so such a vector would lose
  //     its EOI routinely, not rarely. Declining just means it always takes the
  //     ordinary exit-costing EOI -- what the registration is asking for.
  //
  // (2) NESTED. `vector` is not the sole in-service vector, so a grant naming
  //     it could be consumed by an epilogue belonging to a different vector.
  //
  // In BOTH cases any outstanding grant must also be REVOKED, not merely left
  // un-refreshed: the word still reads 1 for the vector beneath, and the vector
  // being admitted now would consume it at its own epilogue -- skipping an EOI
  // this kernel would then mis-attribute to the vector below. Everyone in the
  // stack then takes the ordinary EOI, which retires strictly top-of-ISR: the
  // one ordering that cannot strand a bit.
  bool sole = true;
  for (uint32_t i = 0; i < 8; i++) {
    const uint32_t expect = (vector / 32 == i) ? (uint32_t{1} << (vector % 32)) : 0;
    if (state.isr[i] != expect) {
      sole = false;
      break;
    }
  }
  if (eoi_interest.Test(vector) || !sole) {
    if (state.lazy_eoi_armed) {
      ktl::atomic_ref<uint32_t>(*word).store(0, ktl::memory_order_relaxed);
      state.lazy_eoi_armed = false;
    }
    return;
  }
  ktl::atomic_ref<uint32_t>(*word).store(1, ktl::memory_order_relaxed);
  state.lazy_eoi_armed = true;
  state.lazy_eoi_vector = vector;
}


// Reconciles any outstanding grant against the guest-physical word. If the
// guest consumed it (skipped its real EOI, so the word now reads 0 without
// this kernel having cleared it), retires exactly `lazy_eoi_vector` -- via
// `guest_isr_clear`, deliberately NOT `guest_isr_eoi` -- because by the time
// reconciliation runs, "whatever is on top of ISR now" may be a different,
// more nested vector that was admitted (and itself granted the word) after
// this one; see `guest_lazy_eoi_arm`. Retiring the wrong one would leave this
// grant's real vector permanently in service (blocking its whole priority
// class forever) while incorrectly clearing a vector still legitimately
// running.
//
// Idempotent, and one predicted branch on `lazy_eoi_armed` when nothing is
// outstanding -- the common case for a guest that never enabled lazy EOI,
// and the case immediately after any reconciliation. Called from TWO sites
// per Vcpu::Enter iteration on the admission hot path -- early in Enter
// itself, before the pending_event_ priority computation, and again at the
// very top of `local_apic_maybe_interrupt`, before THAT function reads
// processor priority for its own (tracker) admission decision -- so a grant
// retired here is visible to whichever decision runs next on the very same
// VM entry, not one entry later. See Vcpu::Enter's own comment at its call
// site for why both are necessary, not redundant.
inline void guest_lazy_eoi_reconcile(LocalApicState& state) {
  // Likely, not unlikely: most VCPUs, most entries, have nothing armed.
  if (likely(!state.lazy_eoi_armed)) {
    return;
  }
  uint32_t* word = state.lazy_eoi_guest_ptr.as<uint32_t>();
  if (word == nullptr) {
    // Disabled (ZX_VCPU_STATE_LAZY_EOI written with enabled=false) since the
    // grant was issued. Nothing left to observe; drop the stale bookkeeping
    // rather than touch a mapping that no longer exists.
    state.lazy_eoi_armed = false;
    return;
  }
  if (ktl::atomic_ref<uint32_t>(*word).load(ktl::memory_order_relaxed) != 0) {
    // The guest has not reached this vector's epilogue yet.
    return;
  }
  guest_isr_clear(state, state.lazy_eoi_vector);
  state.lazy_eoi_completions++;
  state.lazy_eoi_armed = false;
}

// Revokes an outstanding grant if it names `vector`, forcing the guest-visible
// word to 0 so no epilogue can consume it.
//
// For the two places that UNDO an injection by clearing its ISR bit rather than
// by an EOI (a deferred vectoring event, and a VM-entry failure). Without this
// they leave `armed == true, word == 1, nothing in service`, which breaks the
// "armed => that vector is the SOLE in-service vector" invariant the whole
// sole-vector rule rests on. No strand results today, only because the next
// admission re-points or revokes the grant -- but "an invariant that happens to
// be repaired by whatever runs next" is not an invariant, and the grant would
// meanwhile authorize a skip for a vector the guest never entered a handler for.
//
// PRECONDITION, and why the reconcile below is here: this must not discard a
// grant the guest has ALREADY consumed, because that consumption owes an ISR
// retire that only `guest_lazy_eoi_reconcile` performs -- dropping it would
// strand the very bit the revoke is trying to keep honest. Reconciling first
// makes the helper safe to call at any point, rather than only where the caller
// has independently established that the guest has not run since the grant was
// armed. At both current call sites the guest has not executed since the last
// reconcile, so this is a no-op there; it is here so the third caller does not
// have to know that.
inline void guest_lazy_eoi_revoke_if_vector(LocalApicState& state, uint32_t vector) {
  guest_lazy_eoi_reconcile(state);
  if (likely(!state.lazy_eoi_armed) || state.lazy_eoi_vector != vector) {
    return;
  }
  if (uint32_t* word = state.lazy_eoi_guest_ptr.as<uint32_t>(); word != nullptr) {
    ktl::atomic_ref<uint32_t>(*word).store(0, ktl::memory_order_relaxed);
  }
  state.lazy_eoi_armed = false;
}

// clang-format off

// GUEST_XX_ACCESS_RIGHTS flags.
static const uint32_t kGuestXxAccessRightsUnusable      = 1u << 16;
// See Volume 3, Section 24.4.1 for access rights format.
static const uint32_t kGuestXxAccessRightsTypeA         = 1u << 0;
static const uint32_t kGuestXxAccessRightsTypeW         = 1u << 1;
static const uint32_t kGuestXxAccessRightsTypeE         = 1u << 2;
static const uint32_t kGuestXxAccessRightsTypeCode      = 1u << 3;
// See Volume 3, Section 3.4.5.1 for valid non-system selector types.
static const uint32_t kGuestXxAccessRightsS             = 1u << 4;
static const uint32_t kGuestXxAccessRightsDplUser       = 3u << 5;
static const uint32_t kGuestXxAccessRightsP             = 1u << 7;
static const uint32_t kGuestXxAccessRightsL             = 1u << 13;
static const uint32_t kGuestXxAccessRightsD             = 1u << 14;
// See Volume 3, Section 3.5 for valid system selectors types.
static const uint32_t kGuestTrAccessRightsTssBusy16Bit  = 3u << 0;
static const uint32_t kGuestTrAccessRightsTssBusy       = 11u << 0;

static const uint32_t kGuestXxAccessRightsDefault       = kGuestXxAccessRightsTypeA |
                                                          kGuestXxAccessRightsTypeW |
                                                          kGuestXxAccessRightsS |
                                                          kGuestXxAccessRightsP;

// GUEST_INTERRUPTIBILITY_STATE flags.
static const uint32_t kInterruptibilityStiBlocking      = 1u << 0;
static const uint32_t kInterruptibilityMovSsBlocking    = 1u << 1;
static const uint32_t kInterruptibilityNmiBlocking      = 1u << 3;

// VMCS fields.
enum class VmcsField16 : uint64_t {
    VPID                                                = 0x0000,
    GUEST_ES_SELECTOR                                   = 0x0800,
    GUEST_CS_SELECTOR                                   = 0x0802,
    GUEST_SS_SELECTOR                                   = 0x0804,
    GUEST_DS_SELECTOR                                   = 0x0806,
    GUEST_FS_SELECTOR                                   = 0x0808,
    GUEST_GS_SELECTOR                                   = 0x080a,
    GUEST_LDTR_SELECTOR                                 = 0x080c,
    GUEST_TR_SELECTOR                                   = 0x080e,
    HOST_ES_SELECTOR                                    = 0x0c00,
    HOST_CS_SELECTOR                                    = 0x0c02,
    HOST_SS_SELECTOR                                    = 0x0c04,
    HOST_DS_SELECTOR                                    = 0x0c06,
    HOST_FS_SELECTOR                                    = 0x0c08,
    HOST_GS_SELECTOR                                    = 0x0c0a,
    HOST_TR_SELECTOR                                    = 0x0c0c,
};

enum class VmcsField64 : uint64_t {
    MSR_BITMAPS_ADDRESS                                 = 0x2004,
    TSC_OFFSET                                          = 0x2010,
    VIRTUAL_APIC_ADDRESS                                = 0x2012,
    APIC_ACCESS_ADDRESS                                 = 0x2014,
    EXIT_MSR_STORE_ADDRESS                              = 0x2006,
    EXIT_MSR_LOAD_ADDRESS                               = 0x2008,
    ENTRY_MSR_LOAD_ADDRESS                              = 0x200a,
    EPT_POINTER                                         = 0x201a,
    GUEST_PHYSICAL_ADDRESS                              = 0x2400,
    LINK_POINTER                                        = 0x2800,
    GUEST_IA32_DEBUGCTL                                 = 0x2802,
    GUEST_IA32_PAT                                      = 0x2804,
    GUEST_IA32_EFER                                     = 0x2806,
    GUEST_IA32_PERF_GLOBAL_CTRL                         = 0x2808,
    GUEST_IA32_RTIT_CTL                                 = 0x2814,
    HOST_IA32_PAT                                       = 0x2c00,
    HOST_IA32_EFER                                      = 0x2c02,
    HOST_IA32_PERF_GLOBAL_CTRL                          = 0x2c04,
};

enum class VmcsField32 : uint64_t {
    PINBASED_CTLS                                       = 0x4000,
    PROCBASED_CTLS                                      = 0x4002,
    EXCEPTION_BITMAP                                    = 0x4004,
    PAGEFAULT_ERRORCODE_MASK                            = 0x4006,
    PAGEFAULT_ERRORCODE_MATCH                           = 0x4008,
    EXIT_CTLS                                           = 0x400c,
    EXIT_MSR_STORE_COUNT                                = 0x400e,
    EXIT_MSR_LOAD_COUNT                                 = 0x4010,
    ENTRY_CTLS                                          = 0x4012,
    ENTRY_MSR_LOAD_COUNT                                = 0x4014,
    ENTRY_INTERRUPTION_INFORMATION                      = 0x4016,
    ENTRY_EXCEPTION_ERROR_CODE                          = 0x4018,
    ENTRY_INSTRUCTION_LENGTH                            = 0x401a,
    TPR_THRESHOLD                                       = 0x401c,
    PROCBASED_CTLS2                                     = 0x401e,
    PLE_GAP                                             = 0x4020,
    PLE_WINDOW                                          = 0x4022,
    INSTRUCTION_ERROR                                   = 0x4400,
    EXIT_REASON                                         = 0x4402,
    EXIT_INTERRUPTION_INFORMATION                       = 0x4404,
    EXIT_INTERRUPTION_ERROR_CODE                        = 0x4406,
    // The event that was *being delivered* when the VM exit occurred, as
    // opposed to EXIT_INTERRUPTION_INFORMATION, which describes the event that
    // *caused* it. Both may be valid on the same exit. See Volume 3, the
    // VM-exit information fields: "Information for VM Exits During Event
    // Delivery" (§27.2.3 in current revisions; the subsection has moved).
    IDT_VECTORING_INFORMATION                           = 0x4408,
    IDT_VECTORING_ERROR_CODE                            = 0x440a,
    EXIT_INSTRUCTION_LENGTH                             = 0x440c,
    EXIT_INSTRUCTION_INFORMATION                        = 0x440e,
    HOST_IA32_SYSENTER_CS                               = 0x4c00,

    GUEST_ES_LIMIT                                      = 0x4800,
    GUEST_CS_LIMIT                                      = 0x4802,
    GUEST_SS_LIMIT                                      = 0x4804,
    GUEST_DS_LIMIT                                      = 0x4806,
    GUEST_FS_LIMIT                                      = 0x4808,
    GUEST_GS_LIMIT                                      = 0x480a,
    GUEST_LDTR_LIMIT                                    = 0x480c,
    GUEST_TR_LIMIT                                      = 0x480e,

    GUEST_GDTR_LIMIT                                    = 0x4810,
    GUEST_IDTR_LIMIT                                    = 0x4812,
    GUEST_CS_ACCESS_RIGHTS                              = 0x4816,
    GUEST_ES_ACCESS_RIGHTS                              = 0x4814,
    GUEST_SS_ACCESS_RIGHTS                              = 0x4818,
    GUEST_DS_ACCESS_RIGHTS                              = 0x481a,
    GUEST_FS_ACCESS_RIGHTS                              = 0x481c,
    GUEST_GS_ACCESS_RIGHTS                              = 0x481e,
    GUEST_LDTR_ACCESS_RIGHTS                            = 0x4820,
    GUEST_TR_ACCESS_RIGHTS                              = 0x4822,
    GUEST_INTERRUPTIBILITY_STATE                        = 0x4824,
    GUEST_ACTIVITY_STATE                                = 0x4826,
    GUEST_IA32_SYSENTER_CS                              = 0x482a,
    VMX_PREEMPTION_TIMER_VALUE                          = 0x482e,
};

enum class VmcsFieldXX : uint64_t {
    CR0_GUEST_HOST_MASK                                 = 0x6000,
    CR4_GUEST_HOST_MASK                                 = 0x6002,
    CR0_READ_SHADOW                                     = 0x6004,
    CR4_READ_SHADOW                                     = 0x6006,
    EXIT_QUALIFICATION                                  = 0x6400,
    GUEST_LINEAR_ADDRESS                                = 0x640a,
    GUEST_CR0                                           = 0x6800,
    GUEST_CR3                                           = 0x6802,
    GUEST_CR4                                           = 0x6804,

    GUEST_ES_BASE                                       = 0x6806,
    GUEST_CS_BASE                                       = 0x6808,
    GUEST_SS_BASE                                       = 0x680A,
    GUEST_DS_BASE                                       = 0x680C,
    GUEST_FS_BASE                                       = 0x680E,
    GUEST_GS_BASE                                       = 0x6810,
    GUEST_LDTR_BASE                                     = 0x6812,
    GUEST_TR_BASE                                       = 0x6814,

    GUEST_GDTR_BASE                                     = 0x6816,
    GUEST_IDTR_BASE                                     = 0x6818,
    GUEST_DR7                                           = 0x681a,
    GUEST_RSP                                           = 0x681c,
    GUEST_RIP                                           = 0x681e,
    GUEST_RFLAGS                                        = 0x6820,
    GUEST_PENDING_DEBUG_EXCEPTIONS                      = 0x6822,
    GUEST_IA32_SYSENTER_ESP                             = 0x6824,
    GUEST_IA32_SYSENTER_EIP                             = 0x6826,
    HOST_CR0                                            = 0x6c00,
    HOST_CR3                                            = 0x6c02,
    HOST_CR4                                            = 0x6c04,
    HOST_FS_BASE                                        = 0x6c06,
    HOST_GS_BASE                                        = 0x6c08,
    HOST_TR_BASE                                        = 0x6c0a,
    HOST_GDTR_BASE                                      = 0x6c0c,
    HOST_IDTR_BASE                                      = 0x6c0e,
    HOST_IA32_SYSENTER_ESP                              = 0x6c10,
    HOST_IA32_SYSENTER_EIP                              = 0x6c12,
    HOST_RSP                                            = 0x6c14,
    HOST_RIP                                            = 0x6c16,
};

// clang-format on

// A guard-like object that loads a VMCS within a given scope.
class AutoVmcs : public hypervisor::StateInvalidator {
 public:
  // Constructing an AutoVmcs disables interrupts, disables preemption, and
  // marks the calling thread as not being allowed to block (in order to catch
  // programming errors).  Destroying or |Invalidate|ing restores those previous
  // states.
  explicit AutoVmcs(paddr_t vmcs_address_, bool clear = false);
  ~AutoVmcs();

  void Invalidate() override;
  void InterruptWindowExiting(bool enable);
  // Only settable while `kPinbasedCtlsVirtualNmis` is also set -- VM entry
  // rejects the pair otherwise with VM-instruction error 7.
  void NmiWindowExiting(bool enable);
  void IssueInterrupt(uint32_t vector);

  // Writes a fully specified VM-entry interruption-information field: the
  // caller chooses the interruption type (Volume 3, Section 24.8.3) and whether
  // an error code accompanies the event, rather than having both inferred from
  // the vector. `type` is the raw VMX encoding already shifted into bits 10:8
  // (kInterruptType*). The caller is responsible for having validated the
  // combination — a malformed field is rejected by VM entry, not here.
  void IssueEvent(uint32_t type, uint32_t vector, bool deliver_error_code, uint32_t error_code);

  uint16_t Read(VmcsField16 field) const;
  uint32_t Read(VmcsField32 field) const;
  uint64_t Read(VmcsField64 field) const;
  uint64_t Read(VmcsFieldXX field) const;
  void Write(VmcsField16 field, uint16_t val);
  void Write(VmcsField32 field, uint32_t val);
  void Write(VmcsField64 field, uint64_t val);
  void Write(VmcsFieldXX field, uint64_t val);

  bool valid() const { return vmcs_address_ != 0; }

  zx::result<> SetControl(VmcsField32 controls, uint64_t true_msr, uint64_t old_msr, uint32_t set,
                          uint32_t clear);

 private:
  AutoPreemptDisabler apd_;
  paddr_t vmcs_address_;
  interrupt_saved_state_t int_state_;
};

bool cr0_is_invalid(AutoVmcs& vmcs, uint64_t cr0_value);

// External interrupts can be blocked due to STI, move SS or the IF flag.
//
// SHARED ON PURPOSE. `handle_hlt` used to open-code a second copy of this test
// because the original lived file-locally in vcpu.cc. Two copies of the gate
// that decides whether an external interrupt can be delivered MUST agree: if
// they ever diverge, the HLT path can decide the guest is interruptible and
// return without blocking while `Vcpu::Enter` then refuses to inject, so the
// guest immediately re-HLTs -- the exact spin this series set out to kill.
// One definition makes that divergence unrepresentable.
inline bool can_inject_external_int(AutoVmcs& vmcs) {
  return (vmcs.Read(VmcsFieldXX::GUEST_RFLAGS) & X86_FLAGS_IF) &&
         (vmcs.Read(VmcsField32::GUEST_INTERRUPTIBILITY_STATE) &
          (kInterruptibilityStiBlocking | kInterruptibilityMovSsBlocking)) == 0;
}

#endif  // ZIRCON_KERNEL_ARCH_X86_HYPERVISOR_VCPU_PRIV_H_

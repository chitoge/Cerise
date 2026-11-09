// Copyright 2017 The Fuchsia Authors
//
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT

#include <bits.h>
#include <lib/arch/x86/boot-cpuid.h>
#include <lib/arch/x86/speculation.h>
#include <lib/boot-options/boot-options.h>
#include <lib/fit/defer.h>
#include <lib/kconcurrent/chainlock_transaction.h>
#include <lib/ktrace.h>
#include <platform.h>
#include <zircon/syscalls/hypervisor.h>

#include <arch/x86/descriptor.h>
#include <arch/x86/feature.h>
#include <arch/x86/apic.h>
#include <arch/x86/hypervisor/invalidate.h>
#include <arch/x86/mmu.h>
#include <arch/x86/perf_mon.h>
#include <arch/x86/platform_access.h>
#include <arch/x86/pv.h>
#include <hwreg/x86msr.h>
#include <platform/pc/timer.h>
#include <hypervisor/cpu.h>
#include <hypervisor/ktrace.h>
#include <kernel/percpu.h>
#include <kernel/stats.h>
#include <ktl/algorithm.h>
#include <ktl/atomic.h>
#include <vm/fault.h>
#include <vm/pmm.h>
#include <vm/vm_object.h>

#include "hardware_breakpoint.h"
#include "intel_pt.h"
#include "pv_priv.h"
#include "vcpu_priv.h"
#include "vmexit_priv.h"
#include "vmx_cpu_state_priv.h"

namespace {

constexpr uint32_t kInterruptInfoValid = 1u << 31;
constexpr uint32_t kInterruptInfoDeliverErrorCode = 1u << 11;
// Bit 12 is *not* part of the vector or the type. In the VM-exit interruption-
// information field it means "NMI unblocking due to IRET"; in the IDT-vectoring
// information field it is undefined. Either way it is a reserved bit of the
// VM-entry interruption-information field (bits 30:12 must be zero there), so
// copying a raw exit-side value across without masking would fail VM entry.
constexpr uint32_t kInterruptInfoNmiUnblocking = 1u << 12;
constexpr uint32_t kInterruptInfoVectorMask = 0xffu;    // bits 7:0
constexpr uint32_t kInterruptInfoTypeMask = 0x700u;     // bits 10:8
// Volume 3, Section 24.8.3 (Table 24-14) interruption types, pre-shifted into
// bits 10:8 so they can be OR'd straight into an interruption-information field.
constexpr uint32_t kInterruptTypeExternalInterrupt = 0u << 8;
constexpr uint32_t kInterruptTypeReserved = 1u << 8;
constexpr uint32_t kInterruptTypeNmi = 2u << 8;
constexpr uint32_t kInterruptTypeHardwareException = 3u << 8;
constexpr uint32_t kInterruptTypeSoftwareInterrupt = 4u << 8;
constexpr uint32_t kInterruptTypePrivilegedSoftwareException = 5u << 8;
constexpr uint32_t kInterruptTypeSoftwareException = 6u << 8;
constexpr uint32_t kInterruptTypeOtherEvent = 7u << 8;

// Whether an interruption type takes its return RIP from the VM-entry
// instruction-length field rather than from the trapped RIP: software
// interrupts (INT n), privileged software exceptions (INT1) and software
// exceptions (INT3, INTO). Volume 3's account of the VM-exit
// instruction-length field makes the VM-exit
// instruction-length field carry the length of the originating instruction when
// a VM exit interrupts the delivery of one of these, which is exactly the value
// VM entry needs to re-deliver it.
bool type_needs_instruction_length(uint32_t type) {
  return type == kInterruptTypeSoftwareInterrupt ||
         type == kInterruptTypePrivilegedSoftwareException ||
         type == kInterruptTypeSoftwareException;
}

constexpr uint16_t kBaseProcessorVpid = 1;
constexpr uint64_t kDr6Reset = 0xffff0ff0;
constexpr uint64_t kDr6GuestCauseMask = 0xe00f;
constexpr uint64_t kGuestCr4DebugExtensions = uint64_t{1} << 3;
constexpr uint64_t kGuestCr4La57 = uint64_t{1} << 12;

zx::result<uint64_t> read_guest_gpr(AutoVmcs& vmcs, const GuestState& state,
                                    uint8_t index, bool long_mode) {
  uint64_t value = 0;
  switch (index) {
    case 0:
      value = state.rax;
      break;
    case 1:
      value = state.rcx;
      break;
    case 2:
      value = state.rdx;
      break;
    case 3:
      value = state.rbx;
      break;
    case 4:
      value = vmcs.Read(VmcsFieldXX::GUEST_RSP);
      break;
    case 5:
      value = state.rbp;
      break;
    case 6:
      value = state.rsi;
      break;
    case 7:
      value = state.rdi;
      break;
    case 8:
      value = state.r8;
      break;
    case 9:
      value = state.r9;
      break;
    case 10:
      value = state.r10;
      break;
    case 11:
      value = state.r11;
      break;
    case 12:
      value = state.r12;
      break;
    case 13:
      value = state.r13;
      break;
    case 14:
      value = state.r14;
      break;
    case 15:
      value = state.r15;
      break;
    default:
      return zx::error(ZX_ERR_INVALID_ARGS);
  }
  return zx::ok(long_mode ? value : static_cast<uint64_t>(static_cast<uint32_t>(value)));
}

zx::result<> write_guest_gpr(AutoVmcs& vmcs, GuestState& state, uint8_t index,
                             uint64_t value, bool long_mode) {
  value = long_mode ? value : static_cast<uint64_t>(static_cast<uint32_t>(value));
  switch (index) {
    case 0:
      state.rax = value;
      break;
    case 1:
      state.rcx = value;
      break;
    case 2:
      state.rdx = value;
      break;
    case 3:
      state.rbx = value;
      break;
    case 4:
      vmcs.Write(VmcsFieldXX::GUEST_RSP, value);
      break;
    case 5:
      state.rbp = value;
      break;
    case 6:
      state.rsi = value;
      break;
    case 7:
      state.rdi = value;
      break;
    case 8:
      state.r8 = value;
      break;
    case 9:
      state.r9 = value;
      break;
    case 10:
      state.r10 = value;
      break;
    case 11:
      state.r11 = value;
      break;
    case 12:
      state.r12 = value;
      break;
    case 13:
      state.r13 = value;
      break;
    case 14:
      state.r14 = value;
      break;
    case 15:
      state.r15 = value;
      break;
    default:
      return zx::error(ZX_ERR_INVALID_ARGS);
  }
  return zx::ok();
}

void advance_guest_rip(AutoVmcs& vmcs) {
  vmcs.Write(VmcsFieldXX::GUEST_RIP,
             vmcs.Read(VmcsFieldXX::GUEST_RIP) +
                 vmcs.Read(VmcsField32::EXIT_INSTRUCTION_LENGTH));
  const uint32_t interruptibility =
      vmcs.Read(VmcsField32::GUEST_INTERRUPTIBILITY_STATE);
  vmcs.Write(VmcsField32::GUEST_INTERRUPTIBILITY_STATE,
             interruptibility &
                 ~(kInterruptibilityStiBlocking | kInterruptibilityMovSsBlocking));
}

// The RFLAGS bits a whole-VCPU snapshot owns.
//
// Deliberately *not* X86_FLAGS_USER. That mask describes what unprivileged code
// on the host may control, and restricted.cc rightly excludes IF from it: a
// restricted-mode thread must never touch the host's interrupt flag. Guest
// RFLAGS is a different object. It is the guest's own architectural state,
// isolated from the host by the VMCS, so "what the guest may have" is a strictly
// wider set than "what host user code may have". Reusing X86_FLAGS_USER here
// dropped IF (bit 9) from both capture and restore, which meant a snapshot did
// not record whether the guest had interrupts enabled and a restore resumed with
// whatever IF the destination VCPU happened to be carrying.
//
// Bit by bit, against the VM-entry checks on GUEST_RFLAGS (Volume 3, "Checks on
// Guest RIP, RFLAGS, and SSP" and "Checks on Guest Non-Register State"):
//
//   CF/PF/AF/ZF/SF/OF (0,2,4,6,7,11)  arithmetic results — pure guest state.
//   TF (8)     guest single-step. Traps to the guest's own #DB, not the host.
//   IF (9)     the bug. Whether the guest has interrupts enabled is exactly what
//              a checkpoint must pin down. Entry-safe in both polarities:
//              IF=0 only *blocks* injection (can_inject_external_int() already
//              gates on it), and the one entry check that names IF -- external
//              interrupts require IF=1 -- is enforced by that same gate.
//   DF (10)    string direction — pure guest state.
//   IOPL (12-13) guest-internal privilege. It gates I/O and CLI/STI for guest
//              CPL>0 code only; port access still exits through our I/O bitmap
//              regardless, so a guest cannot reach real hardware with it. No
//              entry check.
//   NT (14)    guest task nesting. No entry check.
//   RF (16)    suppresses one instruction breakpoint. Genuine guest state; it is
//              loaded from this field on entry and has no entry check.
//   AC (18)    alignment check — pure guest state.
//   VIF/VIP (19,20) virtual-interrupt flag/pending, meaningful with CR4.VME or
//              PVI, both of which we also restore. Guest-visible only, no entry
//              check.
//   ID (21)    CPUID-supported indicator — pure guest state.
//
// Excluded, on purpose:
//   VM (17)    virtual-8086 mode. This is the one bit a caller could use to
//              break VM entry: entry requires VM=0 whenever the "IA-32e mode
//              guest" entry control is set, and that control is *not* part of
//              VcpuArchState, so a snapshot cannot describe a consistent VM86
//              guest anyway. Left outside the mask, so restore keeps whatever
//              the live VMCS has (0 for every long-mode guest) instead of
//              accepting a value that would fail entry.
//   bits 1,3,5,15,22-63  reserved. Bit 1 must be 1 and the rest must be 0 at
//              entry, so they are forced rather than carried.
constexpr uint64_t kGuestRflagsMask = X86_FLAGS_USER | X86_FLAGS_IF | X86_FLAGS_IOPL_MASK |
                                      X86_FLAGS_RF | X86_FLAGS_VIF | X86_FLAGS_VIP;
static_assert((kGuestRflagsMask & X86_FLAGS_VM) == 0, "VM86 must not be restorable");
static_assert((kGuestRflagsMask & X86_FLAGS_RESERVED) == 0,
              "reserved bits are forced, not carried");

void vmptrld(paddr_t pa) {
  uint8_t err;

  __asm__ __volatile__("vmptrld %[pa]"
                       : "=@ccna"(err)  // Set `err` on error (C or Z flag set)
                       : [pa] "m"(pa)
                       : "cc", "memory");

  ASSERT(!err);
}

void vmclear(paddr_t pa) {
  uint8_t err;

  __asm__ __volatile__("vmclear %[pa]"
                       : "=@ccna"(err)  // Set `err` on error (C or Z flag set)
                       : [pa] "m"(pa)
                       : "cc", "memory");

  ASSERT(!err);
}

uint64_t vmread(uint64_t field) {
  uint8_t err;
  uint64_t val;

  __asm__ __volatile__("vmread %[field], %[val]"
                       : [val] "=r"(val),
                         "=@ccna"(err)  // Set `err` on error (C or Z flag set)
                       : [field] "r"(field)
                       : "cc");
  ASSERT(!err);
  return val;
}

void vmwrite(uint64_t field, uint64_t val) {
  uint8_t err;

  __asm__ __volatile__("vmwrite %[val], %[field]"
                       : "=@ccna"(err)  // Set `err` on error (C or Z flag set)
                       : [val] "r"(val), [field] "r"(field)
                       : "cc");
  ASSERT(!err);
}

bool has_error_code(uint32_t vector) {
  switch (vector) {
    case X86_INT_DOUBLE_FAULT:
    case X86_INT_INVALID_TSS:
    case X86_INT_SEGMENT_NOT_PRESENT:
    case X86_INT_STACK_FAULT:
    case X86_INT_GP_FAULT:
    case X86_INT_PAGE_FAULT:
    case X86_INT_ALIGNMENT_CHECK:
    // #CP is the newest of the error-code-pushing exceptions and was missing
    // here. Its absence was not harmless: `WritePendingEvent` requires the
    // caller's error-code flag to agree with this predicate exactly, so a
    // correctly formed #CP injection was refused and a malformed one — no error
    // code, which VM entry itself would then reject — was accepted.
    case X86_INT_CONTROL_PROTECTION:
      return true;
    default:
      return false;
  }
}

void swap_extended_registers(uint8_t* save_extended_registers, uint64_t& save_xcr0, bool save,
                             uint8_t* load_extended_registers, uint64_t& load_xcr0, bool load) {
  x86_extended_register_save_state(save_extended_registers);
  if (save) {
    save_xcr0 = x86_xgetbv(0);
  }
  if (load) {
    x86_xsetbv(0, load_xcr0);
  }
  x86_extended_register_restore_state(load_extended_registers);
}

template <typename Out, typename In>
void register_copy(Out& out, const In& in) {
  out.rax = in.rax;
  out.rcx = in.rcx;
  out.rdx = in.rdx;
  out.rbx = in.rbx;
  out.rbp = in.rbp;
  out.rsi = in.rsi;
  out.rdi = in.rdi;
  out.r8 = in.r8;
  out.r9 = in.r9;
  out.r10 = in.r10;
  out.r11 = in.r11;
  out.r12 = in.r12;
  out.r13 = in.r13;
  out.r14 = in.r14;
  out.r15 = in.r15;
}

// The five VM-execution control capability MSRs, decoded and printed once per
// boot, as read FROM INSIDE THE HYPERVISOR.
//
// This exists because a capability MSR read from the host -- `/dev/cpu/N/msr`,
// `cpuid`, `/proc/cpuinfo`, `lscpu` -- is an UPPER BOUND on what the silicon
// could offer, not what this hypervisor is handed. When Cerise runs under
// another VMM it sees that VMM's nested-VMX subset, which is strictly smaller
// and differs by host kernel version. Reasoning from the outer number has
// can produce a wrong conclusion when the host
// reported `PROCBASED_CTLS2` allowed_1 = 0x5ffcff, from which it was concluded
// that no control clamp could occur, while every boot of this kernel on that
// same machine prints ten "Failed to set VMCS controls 0x401e" lines because
// what reaches here is 0x1378ff and PAUSE-loop exiting (bit 10) is not in it.
//
// So: before building anything on "control X is available", read this line.
// allowed_1 is the mask of controls that MAY be 1; a control absent from it
// cannot be set at all, and `SetControl` will refuse it.
void print_vmx_capabilities_once() {
  static ktl::atomic<bool> printed{false};
  if (printed.exchange(true, ktl::memory_order_relaxed)) {
    return;
  }
  const uint64_t pin = read_msr(X86_MSR_IA32_VMX_TRUE_PINBASED_CTLS);
  const uint64_t proc = read_msr(X86_MSR_IA32_VMX_TRUE_PROCBASED_CTLS);
  const uint64_t proc2 = read_msr(X86_MSR_IA32_VMX_PROCBASED_CTLS2);
  const uint64_t exit_ctls = read_msr(X86_MSR_IA32_VMX_TRUE_EXIT_CTLS);
  const uint64_t entry = read_msr(X86_MSR_IA32_VMX_TRUE_ENTRY_CTLS);
  auto allowed_1 = [](uint64_t msr) { return static_cast<uint32_t>(BITS_SHIFT(msr, 63, 32)); };
  auto allowed_0 = [](uint64_t msr) { return static_cast<uint32_t>(BITS(msr, 31, 0)); };
  dprintf(INFO,
          "hypervisor: VMX controls offered TO THIS HYPERVISOR (allowed_1/allowed_0): "
          "pin %#x/%#x proc %#x/%#x proc2 %#x/%#x exit %#x/%#x entry %#x/%#x\n",
          allowed_1(pin), allowed_0(pin), allowed_1(proc), allowed_0(proc), allowed_1(proc2),
          allowed_0(proc2), allowed_1(exit_ctls), allowed_0(exit_ctls), allowed_1(entry),
          allowed_0(entry));
  dprintf(INFO,
          "hypervisor: of the controls this tree reasons about: virtual-NMIs %d "
          "NMI-window-exiting %d preemption-timer %d TSC-offsetting %d MOV-DR-exiting %d "
          "APIC-register-virtualization %d virtual-interrupt-delivery %d PAUSE-loop-exiting %d\n",
          (allowed_1(pin) & kPinbasedCtlsVirtualNmis) != 0,
          (allowed_1(proc) & kProcbasedCtlsNmiWindowExiting) != 0,
          (allowed_1(pin) & (1u << 6)) != 0,
          (allowed_1(proc) & kProcbasedCtlsUseTscOffsetting) != 0,
          (allowed_1(proc) & (1u << 23)) != 0, (allowed_1(proc2) & (1u << 8)) != 0,
          (allowed_1(proc2) & (1u << 9)) != 0,
          (allowed_1(proc2) & kProcbasedCtls2PauseLoopExiting) != 0);
}

zx::result<> vmcs_init(AutoVmcs& vmcs, uint16_t vpid, uintptr_t entry, paddr_t msr_bitmaps_address,
                       paddr_t virtual_apic_address, paddr_t apic_access_address, paddr_t ept_pml4,
                       bool x2apic_enabled, VmxState* vmx_state, uint8_t* extended_register_state,
                       uint64_t& xstate_buffer_xcr0) {
  print_vmx_capabilities_once();

  // Setup secondary processor-based VMCS controls.
  const uint64_t procbased_ctls2 = read_msr(X86_MSR_IA32_VMX_PROCBASED_CTLS2);
  const uint32_t offered_procbased_ctls2 = static_cast<uint32_t>(procbased_ctls2 >> 32);
  const uint32_t required_apic_controls = kProcbasedCtls2x2Apic;
  if ((offered_procbased_ctls2 & required_apic_controls) != required_apic_controls) {
    // CPUID advertises x2APIC support to an xAPIC-reset guest, so the
    // architectural transition must be implementable before the VCPU exists.
    return zx::error(ZX_ERR_NOT_SUPPORTED);
  }
  const uint32_t xapic_acceleration =
      kProcbasedCtls2ApicAccess | kProcbasedCtls2ApicRegister;
  const bool accelerate_xapic =
      (offered_procbased_ctls2 & xapic_acceleration) == xapic_acceleration;
  const uint32_t apic_controls =
      x2apic_enabled ? kProcbasedCtls2x2Apic : (accelerate_xapic ? xapic_acceleration : 0);
  const uint32_t inactive_apic_controls =
      x2apic_enabled ? xapic_acceleration
                     : (kProcbasedCtls2x2Apic |
                        (accelerate_xapic ? 0 : xapic_acceleration));
  auto result =
      vmcs.SetControl(VmcsField32::PROCBASED_CTLS2, procbased_ctls2, 0,
                      // Enable use of extended page tables.
                      kProcbasedCtls2Ept |
                          // Enable use of RDTSCP instruction.
                          kProcbasedCtls2Rdtscp |
                          // Select the APIC interface this VCPU resets in.
                          apic_controls |
                          // Associate cached translations of linear
                          // addresses with a virtual processor ID.
                          kProcbasedCtls2Vpid |
                          // Enable unrestricted guest.
                          kProcbasedCtls2UnrestrictedGuest,
                      inactive_apic_controls);
  if (result.is_error()) {
    return result;
  }

  // Enable use of INVPCID instruction if available.
  std::ignore =
      vmcs.SetControl(VmcsField32::PROCBASED_CTLS2, read_msr(X86_MSR_IA32_VMX_PROCBASED_CTLS2),
                      vmcs.Read(VmcsField32::PROCBASED_CTLS2), kProcbasedCtls2Invpcid, 0);

  // Setup pin-based VMCS controls.
  result =
      vmcs.SetControl(VmcsField32::PINBASED_CTLS, read_msr(X86_MSR_IA32_VMX_TRUE_PINBASED_CTLS),
                      read_msr(X86_MSR_IA32_VMX_PINBASED_CTLS),
                      // External interrupts cause a VM exit.
                      kPinbasedCtlsExtIntExiting |
                          // Non-maskable interrupts cause a VM exit.
                          kPinbasedCtlsNmiExiting,
                      0);
  if (result.is_error()) {
    return result;
  }

  // Use virtual NMIs when this hypervisor is offered them.
  //
  // Without this, a blocked NMI has no correct instrument. Interrupt-window
  // exiting -- what the injection paths fall back to -- watches RFLAGS.IF and
  // STI/MOV-SS blocking, none of which gate an NMI; a guest sitting in its own
  // NMI handler with interrupts disabled (which is every NMI handler, since the
  // gate clears IF) never opens an interrupt window at all, so the queued NMI
  // waits for some unrelated exit. NMI-window exiting watches virtual-NMI
  // blocking, which is the thing that is actually blocking it, and VM entry
  // refuses that control unless this one is set.
  //
  // Requested rather than required, and asked for AFTER the mandatory controls
  // above, so a part or a nested layer that does not offer it still gets a
  // working VCPU with the old fallback. Measured on this host: pin-based
  // allowed_1 is 0x7f, which includes bit 5, so it is offered here -- see
  // `print_vmx_capabilities_once`, and read that line rather than a capability
  // MSR sampled from outside this hypervisor before assuming it elsewhere.
  //
  // NMI exiting is its prerequisite (Volume 3, Section 26.2.1.1) and is set
  // above unconditionally; that is why this is a separate, later call rather
  // than another bit in the set above -- if it is refused, the mandatory
  // controls must survive.
  std::ignore =
      vmcs.SetControl(VmcsField32::PINBASED_CTLS, read_msr(X86_MSR_IA32_VMX_TRUE_PINBASED_CTLS),
                      vmcs.Read(VmcsField32::PINBASED_CTLS), kPinbasedCtlsVirtualNmis, 0);

  // Setup primary processor-based VMCS controls.
  result =
      vmcs.SetControl(VmcsField32::PROCBASED_CTLS, read_msr(X86_MSR_IA32_VMX_TRUE_PROCBASED_CTLS),
                      read_msr(X86_MSR_IA32_VMX_PROCBASED_CTLS),
                      // Enable VM exit when interrupts are enabled.
                      kProcbasedCtlsIntWindowExiting |
                          // Enable VM exit on HLT instruction.
                          kProcbasedCtlsHltExiting |
                          // Enable TPR virtualization. This is what lets the
                          // guest run `MOV to/from CR8` without a VM exit; it
                          // is only meaningful because VIRTUAL_APIC_ADDRESS is
                          // programmed below, and setting it without that page
                          // is what made the guest's task priority meaningless
                          // (see there).
                          kProcbasedCtlsTprShadow |
                          // Enable VM exit on IO instructions.
                          kProcbasedCtlsIoExiting |
                          // Enable use of MSR bitmaps.
                          kProcbasedCtlsMsrBitmaps |
                          // Enable secondary processor-based controls.
                          kProcbasedCtlsProcbasedCtls2,
                      // Disable VM exit on CR3 load.
                      kProcbasedCtlsCr3LoadExiting |
                          // Disable VM exit on CR3 store.
                          kProcbasedCtlsCr3StoreExiting |
                          // Disable VM exit on CR8 load.
                          kProcbasedCtlsCr8LoadExiting |
                          // Disable VM exit on CR8 store.
                          kProcbasedCtlsCr8StoreExiting);
  if (result.is_error()) {
    return result;
  }

  // We only enable interrupt-window exiting above to ensure that the
  // processor supports it for later use. So disable it for now.
  vmcs.InterruptWindowExiting(false);

  // The guest's TSC becomes ours to choose rather than the host's raw
  // counter. TSC_OFFSET (0x2010) was not even defined in this file before, and
  // nothing wrote it, so a guest read the host's TSC -- whose epoch is the
  // machine's power-on -- through both RDTSC and RDMSR 0x10.
  //
  // THE OFFSET IS PROGRAMMED TO ZERO HERE, DELIBERATELY, so this is not yet a
  // behaviour change for any guest: what lands is the mechanism, the control, and
  // the three guest-visible reads that have to agree with it. Two things have to
  // happen elsewhere before a nonzero default is correct, and both are outside
  // this directory:
  //
  //   1. `virt_cerise/src/reftsc.rs` derives the Hyper-V reference-TSC page's
  //      `TscOffset` from the *VMM's own* `rdtsc`, and verifies it with the VMM's
  //      `rdtsc` too. The page's arithmetic is evaluated by the GUEST, with the
  //      guest's TSC. Programming a nonzero offset here therefore shifts the
  //      guest's reference clock by exactly that offset while the VMM's
  //      self-check still passes -- a wrong clock behind a green instrument, the
  //      same shape as the earlier 1000 Hz bug.
  //   2. VcpuArchState cannot carry the offset, so a restored VCPU cannot be
  //      given the one it was saved with. With the offset at zero a restore is no
  //      worse than today (guest time jumps forward by the save-to-restore gap);
  //      with a per-VCPU offset chosen at creation it would be worse, because a
  //      restored guest's TSC would jump BACKWARDS to near zero, and a
  //      non-monotonic TSC hangs both Windows and Linux. That field is a
  //      kVcpuStateVersion bump shared with the VMM.
  //
  // The control is enabled if the part offers it rather than being required,
  // because a VCPU that cannot be created is worse than a guest whose TSC is the
  // host's. Nested VMX does clamp what it offers here -- see the 0x401e lines this
  // suite prints for PAUSE-loop exiting -- so "the capability MSR says yes" is not
  // the same question as "the MSR the hypervisor can read says yes".
  {
    const uint64_t true_procbased = read_msr(X86_MSR_IA32_VMX_TRUE_PROCBASED_CTLS);
    const uint32_t procbased_allowed_1 = static_cast<uint32_t>(BITS_SHIFT(true_procbased, 63, 32));
    if ((procbased_allowed_1 & kProcbasedCtlsUseTscOffsetting) != 0) {
      vmcs.Write(VmcsField64::TSC_OFFSET, 0);
      vmcs.Write(VmcsField32::PROCBASED_CTLS,
                 vmcs.Read(VmcsField32::PROCBASED_CTLS) | kProcbasedCtlsUseTscOffsetting);
    }
  }

  // Setup VM-exit VMCS controls.
  result = vmcs.SetControl(VmcsField32::EXIT_CTLS, read_msr(X86_MSR_IA32_VMX_TRUE_EXIT_CTLS),
                           read_msr(X86_MSR_IA32_VMX_EXIT_CTLS),
                           // Logical processor is in 64-bit mode after VM
                           // exit. On VM exit CS.L, IA32_EFER.LME, and
                           // IA32_EFER.LMA is set to true.
                           kExitCtls64bitMode |
                               // Acknowledge external interrupt on exit.
                               kExitCtlsAckIntOnExit |
                               // Save the guest IA32_PAT MSR on exit.
                               kExitCtlsSaveIa32Pat |
                               // Load the host IA32_PAT MSR on exit.
                               kExitCtlsLoadIa32Pat |
                               // Save the guest IA32_EFER MSR on exit.
                               kExitCtlsSaveIa32Efer |
                               // Load the host IA32_EFER MSR on exit.
                               kExitCtlsLoadIa32Efer,
                           0);
  if (result.is_error()) {
    return result;
  }

  // Whether we are configuring the base processor. The base processor starts in
  // 64-bit mode with all features enabled. For secondary processors, they must
  // be bootstrapped by the operating system.
  const bool is_base_processor = vpid == kBaseProcessorVpid;

  // Setup VM-entry VMCS controls.
  // Load the guest IA32_PAT MSR and IA32_EFER MSR on entry.
  uint32_t entry_ctls = kEntryCtlsLoadIa32Pat | kEntryCtlsLoadIa32Efer;
  if (is_base_processor) {
    // On the BSP, go straight to 64-bit mode on entry.
    entry_ctls |= kEntryCtls64bitMode;
  }
  result = vmcs.SetControl(VmcsField32::ENTRY_CTLS, read_msr(X86_MSR_IA32_VMX_TRUE_ENTRY_CTLS),
                           read_msr(X86_MSR_IA32_VMX_ENTRY_CTLS), entry_ctls, 0);
  if (result.is_error()) {
    return result;
  }

  // Enable use of PAUSE-loop exiting if available.
  result =
      vmcs.SetControl(VmcsField32::PROCBASED_CTLS2, read_msr(X86_MSR_IA32_VMX_PROCBASED_CTLS2),
                      vmcs.Read(VmcsField32::PROCBASED_CTLS2), kProcbasedCtls2PauseLoopExiting, 0);
  if (result.is_ok()) {
    // From Volume 3, Section 25.1.3: The processor determines the amount of
    // time between this execution of PAUSE and the previous execution of PAUSE
    // at CPL 0. If this amount of time exceeds the value of the VM-execution
    // control field PLE_Gap, the processor considers this execution to be the
    // first execution of PAUSE in a loop. (It also does so for the first
    // execution of PAUSE at CPL 0 after VM entry.)
    //
    // Otherwise, the processor determines the amount of time since the most
    // recent execution of PAUSE that was considered to be the first in a loop.
    // If this amount of time exceeds the value of the VM-execution control
    // field PLE_Window, a VM exit occurs.
    //
    // For purposes of these computations, time is measured based on a counter
    // that runs at the same rate as the timestamp counter (TSC).
    //
    // NOTE: These values are based on KVM, which was based on empirical
    // analysis.
    vmcs.Write(VmcsField32::PLE_GAP, 1u << 7);
    vmcs.Write(VmcsField32::PLE_WINDOW, 1u << 12);
  }

  // From Volume 3, Section 24.6.3: The exception bitmap is a 32-bit field
  // that contains one bit for each exception. When an exception occurs,
  // its vector is used to select a bit in this field. If the bit is 1,
  // the exception causes a VM exit. If the bit is 0, the exception is
  // delivered normally through the IDT, using the descriptor
  // corresponding to the exception’s vector.
  //
  // From Volume 3, Section 25.2: If software desires VM exits on all page
  // faults, it can set bit 14 in the exception bitmap to 1 and set the
  // page-fault error-code mask and match fields each to 00000000H.
  vmcs.Write(VmcsField32::EXCEPTION_BITMAP, 0);
  vmcs.Write(VmcsField32::PAGEFAULT_ERRORCODE_MASK, 0);
  vmcs.Write(VmcsField32::PAGEFAULT_ERRORCODE_MATCH, 0);

  // From Volume 3, Section 28.1: Virtual-processor identifiers (VPIDs)
  // introduce to VMX operation a facility by which a logical processor may
  // cache information for multiple linear-address spaces. When VPIDs are
  // used, VMX transitions may retain cached information and the logical
  // processor switches to a different linear-address space.
  //
  // From Volume 3, Section 26.2.1.1: If the “enable VPID” VM-execution
  // control is 1, the value of the VPID VM-execution control field must not
  // be 0000H.
  //
  // From Volume 3, Section 28.3.3.3: If EPT is in use, the logical processor
  // associates all mappings it creates with the value of bits 51:12 of
  // current EPTP. If a VMM uses different EPTP values for different guests,
  // it may use the same VPID for those guests.
  //
  // From Volume 3, Section 28.3.3.1: Operations that architecturally
  // invalidate entries in the TLBs or paging-structure caches independent of
  // VMX operation (e.g., the INVLPG and INVPCID instructions) invalidate
  // linear mappings and combined mappings. They are required to do so only
  // for the current VPID (but, for combined mappings, all EP4TAs). Linear
  // mappings for the current VPID are invalidated even if EPT is in use.
  // Combined mappings for the current VPID are invalidated even if EPT is
  // not in use.
  vmcs.Write(VmcsField16::VPID, vpid);
  invvpid(InvVpid::SINGLE_CONTEXT, vpid, 0);

  // From Volume 3, Section 28.2: The extended page-table mechanism (EPT) is a
  // feature that can be used to support the virtualization of physical
  // memory. When EPT is in use, certain addresses that would normally be
  // treated as physical addresses (and used to access memory) are instead
  // treated as guest-physical addresses. Guest-physical addresses are
  // translated by traversing a set of EPT paging structures to produce
  // physical addresses that are used to access memory.
  const auto eptp = ept_pointer_from_pml4(ept_pml4);
  vmcs.Write(VmcsField64::EPT_POINTER, eptp);

  // Setup MSR handling.
  vmcs.Write(VmcsField64::MSR_BITMAPS_ADDRESS, msr_bitmaps_address);
  // No transition-time MSRs are installed initially. These fields are
  // architecturally ignored while their count is zero, but writing both count
  // and address gives optional facilities such as Intel PT a defined list to
  // extend and later restore rather than relying on VMCS allocation residue.
  vmcs.Write(VmcsField64::ENTRY_MSR_LOAD_ADDRESS, 0);
  vmcs.Write(VmcsField64::EXIT_MSR_LOAD_ADDRESS, 0);
  vmcs.Write(VmcsField32::ENTRY_MSR_LOAD_COUNT, 0);
  vmcs.Write(VmcsField32::EXIT_MSR_LOAD_COUNT, 0);

  // The virtual-APIC page, required by the "use TPR shadow" control set above.
  //
  // From Volume 3, Section 25.6.8: "If the 'use TPR shadow' VM-execution
  // control is 1, the virtual-APIC address is the 4-KByte-aligned physical
  // address of the virtual-APIC page", and Section 30.1.1: `MOV to CR8` stores
  // its source into bits 7:4 of VTPR (offset 0x80 of that page) with bits 3:0
  // cleared, and `MOV from CR8` returns it -- neither causing a VM exit, since
  // CR8-load and CR8-store exiting are both cleared above.
  //
  // This field had never been written. An unwritten VMCS field is
  // architecturally *undefined*, not zero -- so what it actually held was
  // measured rather than assumed: a temporary `vmread(0x2012)` placed here,
  // before this write, read back 0 on all 65 VCPU creations of a full
  // hypervisor-suite boot (i5-8500T, this kernel running under KVM), with no
  // other value ever observed. 0 passes VM entry's only checks on this field
  // (4-KiB aligned, within the physical-address width). So VM
  // entry always succeeded, and every VCPU on the machine used host-physical
  // page 0 as its virtual-APIC page: a guest `MOV to CR8` wrote host memory no
  // one owns, `MOV from CR8` read it back, and two VCPUs -- in the same guest
  // or in different guests -- shared one task-priority register. x64 Windows
  // keeps IRQL in CR8, so this was the guest's IRQL.
  vmcs.Write(VmcsField64::VIRTUAL_APIC_ADDRESS, virtual_apic_address);
  vmcs.Write(VmcsField64::APIC_ACCESS_ADDRESS, apic_access_address);

  // No TPR-below-threshold exits until something is waiting on one. From
  // Volume 3, Section 26.2.1.1, VM entry requires bits 31:4 of this field to be
  // 0 whenever "use TPR shadow" is set and "virtual-interrupt delivery" is not,
  // which is this configuration; `local_apic_maybe_interrupt` maintains it
  // within that range.
  vmcs.Write(VmcsField32::TPR_THRESHOLD, 0);

  // Setup VMCS host state.
  //
  // NOTE: We are pinned to a thread when executing this function, therefore
  // it is acceptable to use per-CPU state.
  x86_percpu* percpu = x86_get_percpu();
  vmcs.Write(VmcsField32::HOST_IA32_SYSENTER_CS, 0);
  vmcs.Write(VmcsFieldXX::HOST_IA32_SYSENTER_ESP, 0);
  vmcs.Write(VmcsFieldXX::HOST_IA32_SYSENTER_EIP, 0);
  vmcs.Write(VmcsField64::HOST_IA32_PAT, read_msr(X86_MSR_IA32_PAT));
  vmcs.Write(VmcsField64::HOST_IA32_EFER, read_msr(X86_MSR_IA32_EFER));
  vmcs.Write(VmcsFieldXX::HOST_CR0, x86_get_cr0());
  vmcs.Write(VmcsFieldXX::HOST_CR3, x86_get_cr3());
  vmcs.Write(VmcsFieldXX::HOST_CR4, x86_get_cr4());
  vmcs.Write(VmcsField16::HOST_ES_SELECTOR, 0);
  vmcs.Write(VmcsField16::HOST_CS_SELECTOR, CODE_64_SELECTOR);
  vmcs.Write(VmcsField16::HOST_SS_SELECTOR, DATA_SELECTOR);
  vmcs.Write(VmcsField16::HOST_DS_SELECTOR, 0);
  vmcs.Write(VmcsField16::HOST_FS_SELECTOR, 0);
  vmcs.Write(VmcsField16::HOST_GS_SELECTOR, 0);
  vmcs.Write(VmcsField16::HOST_TR_SELECTOR, TSS_SELECTOR(percpu->cpu_num));
  vmcs.Write(VmcsFieldXX::HOST_FS_BASE, read_msr(X86_MSR_IA32_FS_BASE));
  vmcs.Write(VmcsFieldXX::HOST_GS_BASE, read_msr(X86_MSR_IA32_GS_BASE));
  vmcs.Write(VmcsFieldXX::HOST_TR_BASE, reinterpret_cast<uint64_t>(&percpu->default_tss));
  vmcs.Write(VmcsFieldXX::HOST_GDTR_BASE, reinterpret_cast<uint64_t>(gdt_get()));
  vmcs.Write(VmcsFieldXX::HOST_IDTR_BASE, reinterpret_cast<uint64_t>(idt_get_readonly()));
  vmcs.Write(VmcsFieldXX::HOST_RSP, reinterpret_cast<uint64_t>(vmx_state));
  vmcs.Write(VmcsFieldXX::HOST_RIP, reinterpret_cast<uint64_t>(vmx_exit_asm));

  // Setup VMCS guest state.
  uint64_t cr0 = X86_CR0_ET |  // Enable extension type
                 X86_CR0_NE |  // Enable internal x87 exception handling
                 X86_CR0_WP;   // Enable supervisor write protect
  if (is_base_processor) {
    // Enable protected mode and paging on the primary VCPU.
    cr0 |= X86_CR0_PE |  // Enable protected mode
           X86_CR0_PG;   // Enable paging
  }
  if (cr0_is_invalid(vmcs, cr0)) {
    return zx::error(ZX_ERR_BAD_STATE);
  }
  vmcs.Write(VmcsFieldXX::GUEST_CR0, cr0);

  // From Volume 3, Section 27.5.1: The following bits are not modified: For
  // CR0, ET, CD, NW; [the reserved bits], and any bits that are fixed in VMX
  // operation.
  //
  // Any bit that is not restored must be masked, or the guest will be able to
  // affect the host's cr0. However, we do not need to mask:
  //   * The reserved bits, which will generate GP faults;
  //   * ET, which is fixed to 1 (Volume 3 Section 2.5);
  //   * The bits that are fixed in VMX operation aside from PE and PG for
  //     unrestricted guests, which will generate GP faults (Volume 3 Section
  //     25.3);
  //
  // Additionally, NE is fixed in VMX operation but some guests will attempt to
  // clear it without handling the GP fault. So it should also be masked.
  //
  // **PG** is included, and it is not a host-safety bit like the rest of this
  // list -- it is the one bit whose change the hypervisor cannot afford to miss.
  // `handle_cr0_write` is the only code that sets `GUEST_IA32_EFER.LMA` and the
  // IA-32e-mode-guest VM-entry control, and it runs only on an EXITING CR0
  // write. With PG unmasked, an AP performing the ordinary real -> protected ->
  // long trampoline (LGDT, CR4.PAE, EFER.LME, CR3, then PE|PG in one `mov cr0`)
  // turns on paging without a single exit. The processor sets EFER.LMA itself,
  // the save-IA32_EFER exit control copies it into GUEST_IA32_EFER at the next
  // exit, and the entry control is still 0 -- which Volume 3, Section 26.3.1.1
  // forbids, so the NEXT VM entry fails with exit reason 33 and the AP is dead.
  // Unreachable at one vCPU, because `vmcs_init` hands the BSP long mode
  // ready-made below.
  //
  // The cost is nothing for a running guest. Volume 3, Section 25.1.3: a `MOV to
  // CR0` exits only if the source differs from the CR0 read shadow in a masked
  // position, and the shadow is maintained to match, so a 64-bit guest that
  // rewrites CR0 without changing PG still does not exit. Only the mode
  // transition itself does.
  vmcs.Write(VmcsFieldXX::CR0_GUEST_HOST_MASK,
             X86_CR0_ET | X86_CR0_NE | X86_CR0_NW | X86_CR0_CD | X86_CR0_PG);

  // From Volume 3, Section 9.1.1: Following power-up, The state of control
  // register CR0 is 60000010H (CD and ET are set.)
  //
  // PG must be in here for the BSP for the same reason it is now in the mask:
  // the guest reads masked bits from this shadow, so a BSP that is running with
  // paging on and reads PG back as 0 would be lied to -- and a guest that does
  // `mov eax, cr0; or ...; mov cr0, eax` would then write that lie back and
  // believe it had turned paging off. `handle_cr0_write` keeps it in step from
  // here on.
  vmcs.Write(VmcsFieldXX::CR0_READ_SHADOW,
             X86_CR0_ET | (is_base_processor ? X86_CR0_PG : 0u));

  // Enable FXSAVE, VMX, FSGSBASE, and XSAVE.
  uint64_t cr4 = X86_CR4_OSFXSR | X86_CR4_VMXE | X86_CR4_FSGSBASE | X86_CR4_OSXSAVE;
  if (is_base_processor) {
    // Enable PAE and PGE on the BSP.
    cr4 |= X86_CR4_PAE | X86_CR4_PGE;
  }
  if (cr_is_invalid(cr4, X86_MSR_IA32_VMX_CR4_FIXED0, X86_MSR_IA32_VMX_CR4_FIXED1)) {
    return zx::error(ZX_ERR_BAD_STATE);
  }
  vmcs.Write(VmcsFieldXX::GUEST_CR4, cr4);

  // Mask access to CR4.
  vmcs.Write(VmcsFieldXX::CR4_GUEST_HOST_MASK, X86_CR4_VMXE);
  vmcs.Write(VmcsFieldXX::CR4_READ_SHADOW, 0);

  vmcs.Write(VmcsField64::GUEST_IA32_PAT, read_msr(X86_MSR_IA32_PAT));

  uint64_t guest_efer = read_msr(X86_MSR_IA32_EFER);
  if (!is_base_processor) {
    // Disable LME and LMA on all but the BSP.
    guest_efer &= ~(X86_EFER_LME | X86_EFER_LMA);
  }
  vmcs.Write(VmcsField64::GUEST_IA32_EFER, guest_efer);

  uint32_t cs_access_rights =
      kGuestXxAccessRightsDefault | kGuestXxAccessRightsTypeE | kGuestXxAccessRightsTypeCode;
  if (is_base_processor) {
    // Ensure that the BSP starts with a 64-bit code segment.
    cs_access_rights |= kGuestXxAccessRightsL;
  }
  vmcs.Write(VmcsField32::GUEST_CS_ACCESS_RIGHTS, cs_access_rights);

  vmcs.Write(VmcsField32::GUEST_TR_ACCESS_RIGHTS,
             kGuestTrAccessRightsTssBusy | kGuestXxAccessRightsP);

  vmcs.Write(VmcsField32::GUEST_SS_ACCESS_RIGHTS, kGuestXxAccessRightsDefault);
  vmcs.Write(VmcsField32::GUEST_DS_ACCESS_RIGHTS, kGuestXxAccessRightsDefault);
  vmcs.Write(VmcsField32::GUEST_ES_ACCESS_RIGHTS, kGuestXxAccessRightsDefault);
  vmcs.Write(VmcsField32::GUEST_FS_ACCESS_RIGHTS, kGuestXxAccessRightsDefault);
  vmcs.Write(VmcsField32::GUEST_GS_ACCESS_RIGHTS, kGuestXxAccessRightsDefault);

  vmcs.Write(VmcsField32::GUEST_LDTR_ACCESS_RIGHTS,
             kGuestXxAccessRightsTypeW | kGuestXxAccessRightsP);

  if (is_base_processor) {
    // Use GUEST_RIP to set the entry point on the BSP.
    vmcs.Write(VmcsFieldXX::GUEST_CS_BASE, 0);
    vmcs.Write(VmcsField16::GUEST_CS_SELECTOR, 0);
    vmcs.Write(VmcsFieldXX::GUEST_RIP, entry);
  } else {
    // Use CS to set the entry point on APs.
    vmcs.Write(VmcsFieldXX::GUEST_CS_BASE, entry);
    vmcs.Write(VmcsField16::GUEST_CS_SELECTOR, static_cast<uint16_t>(entry >> 4));
    vmcs.Write(VmcsFieldXX::GUEST_RIP, 0);
  }
  vmcs.Write(VmcsField32::GUEST_CS_LIMIT, 0xffff);
  vmcs.Write(VmcsFieldXX::GUEST_TR_BASE, 0);
  vmcs.Write(VmcsField16::GUEST_TR_SELECTOR, 0);
  vmcs.Write(VmcsField32::GUEST_TR_LIMIT, 0xffff);
  vmcs.Write(VmcsFieldXX::GUEST_DS_BASE, 0);
  vmcs.Write(VmcsField32::GUEST_DS_LIMIT, 0xffff);
  vmcs.Write(VmcsFieldXX::GUEST_SS_BASE, 0);
  vmcs.Write(VmcsField32::GUEST_SS_LIMIT, 0xffff);
  vmcs.Write(VmcsFieldXX::GUEST_ES_BASE, 0);
  vmcs.Write(VmcsField32::GUEST_ES_LIMIT, 0xffff);
  vmcs.Write(VmcsFieldXX::GUEST_FS_BASE, 0);
  vmcs.Write(VmcsField32::GUEST_FS_LIMIT, 0xffff);
  vmcs.Write(VmcsFieldXX::GUEST_GS_BASE, 0);
  vmcs.Write(VmcsField32::GUEST_GS_LIMIT, 0xffff);
  vmcs.Write(VmcsField32::GUEST_LDTR_LIMIT, 0xffff);
  vmcs.Write(VmcsFieldXX::GUEST_GDTR_BASE, 0);
  vmcs.Write(VmcsField32::GUEST_GDTR_LIMIT, 0xffff);
  vmcs.Write(VmcsFieldXX::GUEST_IDTR_BASE, 0);
  vmcs.Write(VmcsField32::GUEST_IDTR_LIMIT, 0xffff);

  // Set all reserved RFLAGS bits to their correct values
  vmcs.Write(VmcsFieldXX::GUEST_RFLAGS, X86_FLAGS_RESERVED_ONES);

  vmcs.Write(VmcsField32::GUEST_ACTIVITY_STATE, 0);
  vmcs.Write(VmcsField32::GUEST_INTERRUPTIBILITY_STATE, 0);
  vmcs.Write(VmcsFieldXX::GUEST_PENDING_DEBUG_EXCEPTIONS, 0);

  // From Volume 3, Section 26.3.1.1: The IA32_SYSENTER_ESP field and the
  // IA32_SYSENTER_EIP field must each contain a canonical address.
  vmcs.Write(VmcsFieldXX::GUEST_IA32_SYSENTER_ESP, 0);
  vmcs.Write(VmcsFieldXX::GUEST_IA32_SYSENTER_EIP, 0);
  vmcs.Write(VmcsField32::GUEST_IA32_SYSENTER_CS, 0);

  vmcs.Write(VmcsFieldXX::GUEST_CR3, 0);
  vmcs.Write(VmcsFieldXX::GUEST_RSP, 0);

  // From Volume 3, Section 24.4.2: If the “VMCS shadowing” VM-execution
  // control is 1, the VMREAD and VMWRITE instructions access the VMCS
  // referenced by this pointer (see Section 24.10). Otherwise, software
  // should set this field to FFFFFFFF_FFFFFFFFH to avoid VM-entry
  // failures (see Section 26.3.1.5).
  vmcs.Write(VmcsField64::LINK_POINTER, kLinkPointerInvalidate);

  if (x86_xsave_supported()) {
    // Set initial guest XCR0 to host XCR0.
    vmx_state->host_state.xcr0 = x86_xgetbv(0);
    // Intersected with the host's set, not asserted independently of it. The
    // constant alone named AVX unconditionally, and this value is loaded into
    // the physical XCR0 by swap_extended_registers() while the *host* runs -- so
    // on a CPU that does not report AVX in CPUID.(EAX=0Dh,ECX=0), the very first
    // VM entry would XSETBV an unsupported bit and #GP in the kernel. Masking by
    // the host's XCR0 also guarantees the guest's XSAVE area is no larger than
    // the host's, which is what X86_MAX_EXTENDED_REGISTER_SIZE is sized for.
    vmx_state->guest_state.xcr0 =
        vmx_state->host_state.xcr0 &
        (X86_XSAVE_STATE_BIT_X87 | X86_XSAVE_STATE_BIT_SSE | X86_XSAVE_STATE_BIT_AVX);
    x86_extended_register_init_state_from_bv(extended_register_state, vmx_state->guest_state.xcr0);
    xstate_buffer_xcr0 = vmx_state->guest_state.xcr0;
  }

  return zx::ok();
}

// NMI injection is blocked if an NMI is already being serviced (Volume 3,
// Section 24.4.2, Table 24-3), and mov ss blocks *all* interrupts (Volume 2
// Section 4.3 MOV-Move instruction). Note that the IF flag does not affect
// NMIs (Volume 3, Section 6.8.1).
bool can_inject_nmi(AutoVmcs& vmcs) {
  // STI blocking belongs here too, even though the IF flag does not gate NMIs.
  // This is a VM-entry requirement rather than an architectural delivery rule:
  // VM entry checks the guest interruptibility state against the event being
  // injected, and injecting an NMI while blocking-by-STI is set is refused.
  // Ignoring it does not lose the NMI in the abstract, but it turns a deliverable
  // NMI into an opaque VM-entry failure that kills the run.
  return (vmcs.Read(VmcsField32::GUEST_INTERRUPTIBILITY_STATE) &
          (kInterruptibilityNmiBlocking | kInterruptibilityMovSsBlocking |
           kInterruptibilityStiBlocking)) == 0;
}

// Arms the instrument that says when a blocked NMI becomes deliverable.
//
// NMI-window exiting is the architecturally right one: it watches virtual-NMI
// blocking, which is what actually gates an NMI. Interrupt-window exiting --
// what every one of these sites used before, knowingly and with a comment saying
// so -- watches RFLAGS.IF and STI/MOV-SS blocking, none of which gate an NMI, so
// for a guest inside its own NMI handler (IF clear, because the gate cleared it)
// it never fires and the NMI waits for an unrelated exit.
//
// It falls back to the old instrument where "virtual NMIs" is not offered, so
// this is a strict improvement rather than a new hardware requirement.
//
// ONE CARVE-OUT, and it is not cosmetic. Volume 3, Section 25.3: an NMI-window
// VM exit occurs at the beginning of an instruction when there is no virtual-NMI
// blocking and no MOV-SS blocking -- **blocking by STI is not in that list**,
// but `can_inject_nmi` above does refuse an injection under it, because VM entry
// does. Arming the NMI window for an NMI blocked only by STI would exit at the
// beginning of the shadowed instruction, fail to inject, re-arm, re-enter, and
// exit again at the same RIP: the guest never retires the instruction that would
// clear the shadow. That is a livelock, not a delay. Interrupt-window exiting is
// the right instrument for exactly that condition -- it is gated on STI blocking
// clearing -- and STI implies RFLAGS.IF is set, so it will fire. MOV-SS blocking
// needs no such carve-out: it suppresses the NMI window as well, so the guest
// retires an instruction before anything can exit.
void arm_nmi_wakeup(AutoVmcs* vmcs) {
  const uint32_t interruptibility = vmcs->Read(VmcsField32::GUEST_INTERRUPTIBILITY_STATE);
  const bool blocked_only_by_sti =
      (interruptibility & (kInterruptibilityNmiBlocking | kInterruptibilityMovSsBlocking)) == 0 &&
      (interruptibility & kInterruptibilityStiBlocking) != 0;
  if (!blocked_only_by_sti &&
      (vmcs->Read(VmcsField32::PINBASED_CTLS) & kPinbasedCtlsVirtualNmis) != 0) {
    vmcs->NmiWindowExiting(true);
    return;
  }
  vmcs->InterruptWindowExiting(true);
}

// Puts back virtual-NMI blocking that a faulting IRET cleared.
//
// Volume 3, Section 25.7.1.2: with virtual NMIs in force the processor clears
// virtual-NMI blocking as soon as it *begins* executing IRET, not when the IRET
// completes. If the IRET then faults -- here, most plausibly an EPT violation
// taken while popping its own return frame -- the guest is resumed at that same
// IRET with the blocking already gone, and the next NMI is delivered on top of a
// handler that has not finished. The processor reports the situation by setting
// bit 12 of the VM-exit interruption-information field, or of the exit
// qualification for an EPT violation, and putting the blocking back is the
// VMM's job.
//
// This obligation is *created* by adopting virtual NMIs -- without them the
// processor maintains real NMI blocking itself and there is nothing to restore
// -- so it is not optional decoration on the change above.
//
// A double fault is excluded (as KVM excludes it): the guest is not going back
// to the IRET, so there is no handler left to protect.
void recover_nmi_blocking(AutoVmcs& vmcs) {
  if ((vmcs.Read(VmcsField32::PINBASED_CTLS) & kPinbasedCtlsVirtualNmis) == 0) {
    return;
  }
  const uint32_t exit_reason = vmcs.Read(VmcsField32::EXIT_REASON);
  // A VM-entry failure takes the exit path without running the guest, so no IRET
  // was begun and the fields say nothing. Volume 3, Section 26.7: bit 31 marks it.
  if ((exit_reason & (1u << 31)) != 0) {
    return;
  }
  bool unblocked = false;
  switch (exit_reason & 0xffffu) {
    case static_cast<uint32_t>(ExitReason::EXCEPTION_OR_NMI): {
      const uint32_t info = vmcs.Read(VmcsField32::EXIT_INTERRUPTION_INFORMATION);
      unblocked = (info & kInterruptInfoValid) != 0 && (info & kInterruptInfoNmiUnblocking) != 0 &&
                  (info & kInterruptInfoVectorMask) != X86_INT_DOUBLE_FAULT;
      break;
    }
    case static_cast<uint32_t>(ExitReason::EPT_VIOLATION):
      unblocked = (vmcs.Read(VmcsFieldXX::EXIT_QUALIFICATION) & kInterruptInfoNmiUnblocking) != 0;
      break;
    default:
      break;
  }
  if (unblocked) {
    vmcs.Write(VmcsField32::GUEST_INTERRUPTIBILITY_STATE,
               vmcs.Read(VmcsField32::GUEST_INTERRUPTIBILITY_STATE) | kInterruptibilityNmiBlocking);
  }
}

// Programs the TPR threshold, skipping the VMWRITE when it has not changed.
//
// From Volume 3, Section 30.1.2: while "use TPR shadow" is set and
// "virtual-interrupt delivery" is not, a TPR-below-threshold VM exit occurs
// whenever bits 7:4 of VTPR fall below bits 3:0 of this field -- both after a
// `MOV to CR8` that lowers it and, per Section 27.6.7, immediately after any VM
// entry that finds it already below. That second case is what makes this
// race-free: there is no window in which the guest lowers its task priority
// unobserved and then runs on with an interrupt stranded.
void set_tpr_threshold(AutoVmcs* vmcs, LocalApicState* local_apic_state, uint32_t threshold) {
  DEBUG_ASSERT(threshold <= 0xf);
  if (local_apic_state->tpr_threshold == threshold) {
    return;
  }
  local_apic_state->tpr_threshold = threshold;
  vmcs->Write(VmcsField32::TPR_THRESHOLD, threshold);
}

// Pops the highest-numbered pending *exception*: a vector in [0, X86_INT_VIRT]
// other than the NMI, which the caller has already asked for by name and may
// have just put back.
//
// The interrupt tracker has no range-limited pop, and this walks the range
// rather than adding one. That is deliberate: the tracker header is shared with
// arm64, and this is not a hot path -- it runs only on an entry where a
// higher-priority interrupt has already been found undeliverable.
//
// Excluding the NMI is load-bearing, not tidiness. The caller reaches here after
// tracking a *blocked* NMI back into the bitmap; re-popping it here would inject
// an NMI the guest cannot take, which VM entry rejects outright.
bool pop_pending_exception(LocalApicState* local_apic_state, uint32_t* vector) {
  for (uint32_t v = X86_INT_VIRT + 1; v-- > 0;) {
    if (v == X86_INT_NMI) {
      continue;
    }
    if (local_apic_state->interrupt_tracker.TryPop(v)) {
      *vector = v;
      return true;
    }
  }
  return false;
}

constexpr uint64_t exit_reason_bit(ExitReason reason) {
  return uint64_t{1} << static_cast<uint32_t>(reason);
}

// Exact runtime-discovery set for post-handler observation. Every reason here
// has a normal handler in vmexit_handler. Reasons whose primary meaning is
// already another host control boundary (MTF and the VMX preemption timer), and
// terminal/unhandled reasons, are deliberately omitted.
constexpr uint64_t kObservableExitReasons0 =
    exit_reason_bit(ExitReason::EXCEPTION_OR_NMI) |
    exit_reason_bit(ExitReason::EXTERNAL_INTERRUPT) |
    exit_reason_bit(ExitReason::INTERRUPT_WINDOW) | exit_reason_bit(ExitReason::NMI_WINDOW) |
    exit_reason_bit(ExitReason::CPUID) | exit_reason_bit(ExitReason::VMCALL) |
    exit_reason_bit(ExitReason::CONTROL_REGISTER_ACCESS) |
    exit_reason_bit(ExitReason::IO_INSTRUCTION) | exit_reason_bit(ExitReason::RDMSR) |
    exit_reason_bit(ExitReason::WRMSR) | exit_reason_bit(ExitReason::PAUSE) |
    exit_reason_bit(ExitReason::TPR_BELOW_THRESHOLD) | exit_reason_bit(ExitReason::EPT_VIOLATION) |
    exit_reason_bit(ExitReason::XSETBV) | exit_reason_bit(ExitReason::APIC_WRITE);
constexpr uint64_t kObservableExitReasons1 = 0;

bool instruction_counter_vmx_controls_supported() {
  return vmx_control_allows_one(read_msr(X86_MSR_IA32_VMX_TRUE_ENTRY_CTLS),
                                kEntryCtlsLoadIa32PerfGlobalCtrl) &&
         vmx_control_allows_one(read_msr(X86_MSR_IA32_VMX_TRUE_EXIT_CTLS),
                                kExitCtlsLoadIa32PerfGlobalCtrl);
}

bool intel_pt_vmx_controls_supported() {
  auto flexible = [](uint64_t capability, uint32_t bit) {
    const uint32_t must_be_one = static_cast<uint32_t>(capability);
    const uint32_t may_be_one = static_cast<uint32_t>(capability >> 32);
    return (may_be_one & bit) != 0 && (must_be_one & bit) == 0;
  };
  return flexible(read_msr(X86_MSR_IA32_VMX_TRUE_ENTRY_CTLS),
                  kEntryCtlsLoadIa32RtitControl) &&
         flexible(read_msr(X86_MSR_IA32_VMX_TRUE_EXIT_CTLS),
                  kExitCtlsClearIa32RtitControl);
}

bool intel_pt_vmx_operation_supported() {
  // IA32_VMX_MISC[14] says Intel PT may remain enabled while the processor is
  // in VMX operation. Older parts can provide this without the later dedicated
  // VM-entry-load / VM-exit-clear IA32_RTIT_CTL controls; on those parts the
  // ordinary VM-entry/VM-exit MSR-load lists provide the exact transition.
  return (read_msr(X86_MSR_IA32_VMX_MISC) & (uint64_t{1} << 14)) != 0;
}

bool intel_pt_bytes_are_zero(const uint8_t* bytes, size_t size) {
  for (size_t i = 0; i < size; ++i) {
    if (bytes[i] != 0) {
      return false;
    }
  }
  return true;
}

bool intel_pt_output_fields_are_zero(const zx_vcpu_intel_pt_control_t& in) {
  if (in.availability != 0 || in.unavailable_reason != 0 || in.cpu_family != 0 ||
      in.cpu_model != 0 || in.cpu_stepping != 0 || in.max_address_ranges != 0 ||
      in.supported_psb_frequencies != 0 || in.supported_mtc_frequencies != 0 ||
      in.supported_cycle_thresholds != 0 || in.reserved0 != 0 ||
      in.supported_flags != 0 || in.data_size != 0 || in.next_cursor != 0 ||
      in.producer_cursor != 0 || in.segment_sequence != 0 || in.segment_offset != 0 ||
      in.hardware_status != 0 || in.lost_bytes != 0 || in.watermark_count != 0 ||
      in.terminal != 0 || in.status_flags != 0 ||
      !intel_pt_bytes_are_zero(in.data, sizeof(in.data))) {
    return false;
  }
  for (const auto& leaf : in.cpuid_14) {
    if (leaf.subleaf != 0 || leaf.eax != 0 || leaf.ebx != 0 || leaf.ecx != 0 ||
        leaf.edx != 0 || leaf.reserved != 0) {
      return false;
    }
  }
  return true;
}

bool intel_pt_config_fields_are_zero(const zx_vcpu_intel_pt_control_t& in) {
  if (in.delivery != 0 || in.address_range_count != 0 || in.config_flags != 0 ||
      in.buffer_bytes != 0 || in.cr3_match != 0 || in.psb_frequency != 0 ||
      in.mtc_frequency != 0 || in.cycle_threshold != 0 || in.reserved1 != 0) {
    return false;
  }
  for (const auto& range : in.address_ranges) {
    if (range.start != 0 || range.length != 0) {
      return false;
    }
  }
  return true;
}

// Injects an interrupt into the guest, if there is one pending.
//
// `tpr_wait_class` is the priority class of a VMM-requested external interrupt
// that `Vcpu::Enter` has already found the guest's task priority to be blocking,
// or 0 if there is none. This function owns the TPR threshold -- it is the last
// thing to touch the VMCS before entry -- so that event's requirement has to
// come through here or it would be cleared on the way past. Two waiters take the
// *higher* class: as the guest's task priority falls, the higher-class vector
// becomes deliverable first, and that is the wakeup to ask for.
zx::result<> local_apic_maybe_interrupt(AutoVmcs* vmcs, LocalApicState* local_apic_state,
                                        uint32_t tpr_wait_class, const EoiBitmap& eoi_interest) {
  // Reconcile any outstanding lazy-EOI grant before anything below reads
  // processor priority: a grant the guest consumed (skipped its real EOI) must
  // retire its vector's ISR bit before this same entry decides whether a new
  // vector is admissible, or a guest that lowered its own effective priority
  // via the lazy path would still be seen as blocking one more entry than it
  // actually does. One branch, predicted not-taken, for a guest that never
  // registered ZX_VCPU_STATE_LAZY_EOI -- see guest_lazy_eoi_reconcile.
  guest_lazy_eoi_reconcile(*local_apic_state);

  // Something has already been staged for this entry -- in practice an event
  // that was aborted mid-delivery and is being re-injected from the
  // IDT-vectoring information field. Only one event can be injected per entry,
  // and a vector popped here would have nowhere to go back to: `Pop` consumes
  // it and `IssueInterrupt` would then overwrite the staged event. So leave the
  // tracker alone and ask to be told when the guest is interruptible again.
  if ((vmcs->Read(VmcsField32::ENTRY_INTERRUPTION_INFORMATION) & kInterruptInfoValid) != 0) {
    if (local_apic_state->interrupt_tracker.Pending()) {
      vmcs->InterruptWindowExiting(true);
    }
    // Nothing is waiting on the guest to lower its task priority *this* entry:
    // whatever is in the tracker is being held back by the staged event, not by
    // TPR, and the interrupt window above is the instrument for that. Leaving a
    // stale threshold armed would exit immediately after this entry for a
    // condition no one is watching for.
    set_tpr_threshold(vmcs, local_apic_state, tpr_wait_class);
    return zx::ok();
  }

  // Since hardware generated exceptions are delivered to the guest directly,
  // the only exceptions we see here are those we generate in the VMM, e.g. GP
  // faults in vmexit handlers. Therefore we simplify interrupt priority to 1)
  // NMIs, 2) interrupts, and 3) generated exceptions. See Volume 3, Section
  // 6.9, Table 6-2.
  uint32_t vector = X86_INT_COUNT;
  bool pending = local_apic_state->interrupt_tracker.TryPop(X86_INT_NMI);
  if (pending) {
    vector = X86_INT_NMI;
  } else {
    // Pop scans vectors from highest to lowest, which correctly pops interrupts
    // before exceptions. The bare, cross-thread VCPU interrupt ABI is used for
    // device interrupts and guest IPIs, including the reserved vectors 21..31
    // that Windows can place in an ICR. All tracker vectors <= X86_INT_VIRT
    // except the NMI vector are exceptions.
    pending = local_apic_state->interrupt_tracker.Pop(&vector);
    if (!pending) {
      set_tpr_threshold(vmcs, local_apic_state, tpr_wait_class);
      return zx::ok();
    }
    // If type isn't inactive, then Pop should have initialized vector to a
    // valid value.
    DEBUG_ASSERT(vector != X86_INT_COUNT);
  }

  // ---- Can the guest take THIS vector on THIS entry? ----
  //
  // Two questions are tangled together in this function and used to be answered
  // as one. The first is PRIORITY: which of several deliverable events goes
  // first. The second is DELIVERABILITY: whether a given event can go at all.
  //
  // Volume 3, Table 6-2 answers only the first, and it ranks NMIs and maskable
  // hardware interrupts above faults from executing an instruction -- which is
  // exactly what the tracker's highest-vector-first scan reproduces, since every
  // vector above X86_INT_VIRT is an interrupt and every tracker vector below it
  // bar the NMI is an exception. A typed #CP (vector 21) uses pending_event_
  // instead, so it cannot be confused with a bare asynchronous interrupt here.
  //
  // The second question this function must answer for itself, because injecting
  // through the VM-entry interruption-information field bypasses both the APIC
  // and the processor's own interruptibility logic. And the answer differs by
  // kind:
  //
  //   * an external interrupt is gated by RFLAGS.IF, by STI/MOV-SS blocking and
  //     by the guest's processor priority; an NMI by NMI blocking;
  //   * an EXCEPTION is gated by none of that. It is a fault of the instruction
  //     the guest is executing, not an interrupt request, and it does not live
  //     in the interrupt-priority space at all. On real silicon a raised task
  //     priority leaves the interrupt sitting in the IRR while the instruction
  //     executes and its fault is taken.
  //
  // So when the highest-priority vector turns out to be an interrupt the guest
  // cannot take, it is put back and the queue is RE-SCANNED for an exception,
  // which is not subject to whatever blocked it. Returning at that point -- what
  // this used to do, on both refusal paths -- starves the exception, and
  // "starves" is not an exaggeration. The exceptions in this bitmap are the ones
  // this hypervisor's own exit handlers generate, and they are generated WITHOUT
  // advancing the guest RIP, because that is what a fault requires. The guest
  // re-executes the faulting instruction, the handler re-queues the same
  // exception, and nothing in that loop ever lowers the task priority or sets
  // RFLAGS.IF, because the guest never retires an instruction. It is a livelock,
  // not a delay -- and one with no exit to the VMM, so it presents as a silent
  // hang rather than as anything diagnosable.
  //
  // This costs a deliverable interrupt nothing: an exception is reached below
  // only on an entry where a higher-priority interrupt was already established
  // to be undeliverable.
  bool blocked = false;
  bool arm_interrupt_window = false;
  bool arm_nmi_window = false;
  if (vector == X86_INT_NMI) {
    blocked = !can_inject_nmi(*vmcs);
    // This used to arm interrupt-window exiting here, knowingly and with
    // a comment saying it was the wrong instrument, because NMI-window exiting
    // requires the "virtual NMIs" pin-based control and this VMCS did not enable
    // it. `vmcs_init` now requests virtual NMIs where they are offered, and
    // `arm_nmi_wakeup` picks whichever instrument is actually usable -- so on a
    // part that offers them a blocked NMI is now woken by the thing that gates
    // it, and on one that does not, the old fallback is unchanged.
    arm_nmi_window = blocked;
  } else if (vector > X86_INT_VIRT) {
    if (!can_inject_external_int(*vmcs)) {
      // Not interruptible: RFLAGS.IF is clear, or STI/MOV-SS blocking is in
      // force. Interrupt-window exiting is the instrument that says when that
      // stops being true.
      blocked = true;
      arm_interrupt_window = true;
    } else {
      // Interruptible, so what is left is the guest's own *processor* priority,
      // and nothing else.
      //
      // From Volume 3, Section 11.8.4: the local APIC delivers an interrupt only
      // when its priority class -- bits 7:4 of the vector -- is *greater* than
      // the processor's. NMIs and exceptions are not subject to it, which is why
      // this test is inside the external-interrupt branch.
      //
      // The processor priority has two terms (Section 11.8.3.1): the task
      // priority the guest set with `MOV to CR8`, and the highest vector already
      // in service. Gating on the first alone -- which is what this did before
      // there was an ISR -- lets an interrupt of the same class pre-empt a
      // handler that is still running, because nothing recorded that it was
      // running. Gating on neither, which is where this started, ignored the
      // guest's IRQL entirely.
      //
      // What is armed to get the vector moving again depends on WHICH term is
      // blocking it:
      //
      //   * blocked by the task priority: arm the TPR threshold, and the
      //     processor exits the moment the guest lowers CR8 far enough.
      //     Interrupt-window exiting would be the wrong instrument -- RFLAGS.IF
      //     is already set here, so it would exit immediately and on every entry
      //     after, and still not say when TPR moved;
      //   * blocked only by an in-service interrupt: arm nothing. The TPR
      //     threshold watches VTPR and nothing else, so a threshold armed for
      //     this vector's class would fire on the very next entry -- VTPR is
      //     already below it -- for a condition that has not changed, once per
      //     entry, forever. The event that ends this block is the guest's EOI,
      //     which is a WRMSR VM exit and therefore returns to this loop by
      //     itself.
      const uint32_t vector_class = vector >> 4;
      if (vector_class <= guest_ppr_class(*local_apic_state)) {
        blocked = true;
        local_apic_state->priority_blocked++;
        if (vector_class <= guest_tpr_class(*local_apic_state)) {
          // Assigned INTO `tpr_wait_class` rather than kept in a local of its
          // own, and that is not incidental: the single `set_tpr_threshold` call
          // below is the only one on the delivery path, so a separate local
          // would be silently overwritten by it and this vector's threshold
          // would never be programmed. Cr8GatingScenario's
          // TprBelowThresholdExits() assertion is what catches that if it is
          // ever "simplified" back.
          tpr_wait_class = ktl::max(vector_class, tpr_wait_class);
        } else {
          local_apic_state->isr_blocked++;
        }
      }
    }
  }

  if (blocked) {
    // The vector is put back rather than dropped.
    if (zx::result<> result = local_apic_state->interrupt_tracker.Track(vector);
        result.is_error()) {
      return result;
    }
    if (arm_nmi_window) {
      arm_nmi_wakeup(vmcs);
    } else if (arm_interrupt_window) {
      vmcs->InterruptWindowExiting(true);
    }
    // ...and then, deliberately, NO return: see the note above. If an exception
    // is waiting behind this interrupt it is not subject to the block that just
    // refused it, and it is the only thing that can let the guest make progress.
    if (!pop_pending_exception(local_apic_state, &vector)) {
      set_tpr_threshold(vmcs, local_apic_state, tpr_wait_class);
      return zx::ok();
    }
  }

  // This vector is going in. Anything still waiting on the guest's task priority
  // -- a VMM-requested event deferred this entry, or a lower-priority vector
  // left in the tracker -- keeps or re-arms the threshold; a lower-priority
  // tracker vector does so on a later entry, once it is the one being popped.
  set_tpr_threshold(vmcs, local_apic_state, tpr_wait_class);

  // If the vector is non-maskable or interrupts are enabled, inject interrupt.
  vmcs->IssueInterrupt(vector);

  // It is in service from here until the guest's EOI. Only vectors that went
  // through the APIC's priority arbitration above enter the ISR: an NMI or an
  // exception is not acknowledged with an EOI, so a bit set for one would never
  // be cleared and would raise the processor priority forever.
  if (vector > X86_INT_VIRT) {
    guest_isr_set(*local_apic_state, vector);
    // Reaching here already proves vector_class > guest_ppr_class(state) from
    // the check above -- i.e. nothing of this vector's priority or higher was
    // in service the instant it was admitted -- which is exactly the
    // qualification TLFS requires for lazy EOI. See guest_lazy_eoi_arm.
    guest_lazy_eoi_arm(*local_apic_state, vector, eoi_interest);
  }

  // Volume 3, Section 6.9: Lower priority exceptions are discarded; lower
  // priority interrupts are held pending. Discarded exceptions are re-generated
  // when the interrupt handler returns execution to the point in the program or
  // task where the exceptions and/or interrupts occurred.
  local_apic_state->interrupt_tracker.Clear(0, X86_INT_NMI);
  local_apic_state->interrupt_tracker.Clear(X86_INT_NMI + 1, X86_INT_VIRT + 1);

  return zx::ok();
}

}  // namespace

AutoVmcs::AutoVmcs(paddr_t vmcs_address, bool clear) : vmcs_address_(vmcs_address) {
  DEBUG_ASSERT(!arch_ints_disabled());
  DEBUG_ASSERT(!arch_blocking_disallowed());
  int_state_ = arch_interrupt_save();
  arch_set_blocking_disallowed(true);
  if (clear) {
    vmclear(vmcs_address_);
  }
  vmptrld(vmcs_address_);
}

AutoVmcs::~AutoVmcs() {
  DEBUG_ASSERT(arch_ints_disabled());
  if (vmcs_address_ != 0) {
    DEBUG_ASSERT(arch_blocking_disallowed());
    arch_set_blocking_disallowed(false);
  }
  arch_interrupt_restore(int_state_);
}

void AutoVmcs::Invalidate() {
  if (vmcs_address_ != 0) {
    vmcs_address_ = 0;
    arch_set_blocking_disallowed(false);
    apd_.Enable();
  }
}

void AutoVmcs::InterruptWindowExiting(bool enable) {
  DEBUG_ASSERT(vmcs_address_ != 0);
  uint32_t controls = Read(VmcsField32::PROCBASED_CTLS);
  if (enable) {
    controls |= kProcbasedCtlsIntWindowExiting;
  } else {
    controls &= ~kProcbasedCtlsIntWindowExiting;
  }
  Write(VmcsField32::PROCBASED_CTLS, controls);
}

void AutoVmcs::NmiWindowExiting(bool enable) {
  DEBUG_ASSERT(vmcs_address_ != 0);
  // Volume 3, Section 26.2.1.1: VM entry requires "virtual NMIs" to be 1
  // whenever "NMI-window exiting" is. Setting this without it does not produce a
  // wrong guest, it produces an opaque VM-instruction error 7 at the next entry.
  DEBUG_ASSERT(!enable || (Read(VmcsField32::PINBASED_CTLS) & kPinbasedCtlsVirtualNmis) != 0);
  uint32_t controls = Read(VmcsField32::PROCBASED_CTLS);
  if (enable) {
    controls |= kProcbasedCtlsNmiWindowExiting;
  } else {
    controls &= ~kProcbasedCtlsNmiWindowExiting;
  }
  Write(VmcsField32::PROCBASED_CTLS, controls);
}

void AutoVmcs::IssueInterrupt(uint32_t vector) {
  uint32_t type = kInterruptTypeExternalInterrupt;
  if (vector == X86_INT_BREAKPOINT || vector == X86_INT_OVERFLOW) {
    // From Volume 3, Section 24.8.3. A VMM should use type hardware exception for all
    // exceptions other than breakpoints and overflows, which should be software exceptions.
    type = kInterruptTypeSoftwareException;
  } else if (vector == X86_INT_NMI) {
    type = kInterruptTypeNmi;
  } else if (vector <= X86_INT_VIRT) {
    // From Volume 3, Section 6.15. All other vectors from 0 to X86_INT_VIRT are exceptions.
    type = kInterruptTypeHardwareException;
  }
  if (type == kInterruptTypeSoftwareException) {
    // A software exception takes its return RIP from the VM-entry instruction-
    // length field, and this path has no length to offer. Left unwritten the
    // field keeps whatever a previous injection put there, so the guest would
    // resume at RIP plus a stale number of bytes — silent, and different every
    // time. Both vectors that reach here are one byte long (INT3; INTO, which
    // is not encodable in 64-bit mode at all), so state that rather than
    // inherit something.
    Write(VmcsField32::ENTRY_INSTRUCTION_LENGTH, 1);
  }
  // This path has only a vector to work with, so an exception that
  // architecturally carries an error code is delivered with a zero one. That is
  // what `zx_vcpu_interrupt()` has always done and what its callers expect; a
  // VMM with a real error code to deliver uses the pending-event path
  // (Vcpu::WritePendingEvent) instead.
  IssueEvent(type, vector, type == kInterruptTypeHardwareException && has_error_code(vector), 0);
}

void AutoVmcs::IssueEvent(uint32_t type, uint32_t vector, bool deliver_error_code,
                          uint32_t error_code) {
  DEBUG_ASSERT(vmcs_address_ != 0);
  uint32_t interrupt_info = kInterruptInfoValid | type | (vector & UINT8_MAX);
  if (deliver_error_code) {
    interrupt_info |= kInterruptInfoDeliverErrorCode;
    Write(VmcsField32::ENTRY_EXCEPTION_ERROR_CODE, error_code);
  }

  DEBUG_ASSERT((Read(VmcsField32::ENTRY_INTERRUPTION_INFORMATION) & kInterruptInfoValid) == 0);
  Write(VmcsField32::ENTRY_INTERRUPTION_INFORMATION, interrupt_info);
}

uint16_t AutoVmcs::Read(VmcsField16 field) const {
  DEBUG_ASSERT(vmcs_address_ != 0);
  return static_cast<uint16_t>(vmread(static_cast<uint64_t>(field)));
}

uint32_t AutoVmcs::Read(VmcsField32 field) const {
  DEBUG_ASSERT(vmcs_address_ != 0);
  return static_cast<uint32_t>(vmread(static_cast<uint64_t>(field)));
}

uint64_t AutoVmcs::Read(VmcsField64 field) const {
  DEBUG_ASSERT(vmcs_address_ != 0);
  return vmread(static_cast<uint64_t>(field));
}

uint64_t AutoVmcs::Read(VmcsFieldXX field) const {
  DEBUG_ASSERT(vmcs_address_ != 0);
  return vmread(static_cast<uint64_t>(field));
}

void AutoVmcs::Write(VmcsField16 field, uint16_t val) {
  DEBUG_ASSERT(vmcs_address_ != 0);
  vmwrite(static_cast<uint64_t>(field), val);
}

void AutoVmcs::Write(VmcsField32 field, uint32_t val) {
  DEBUG_ASSERT(vmcs_address_ != 0);
  vmwrite(static_cast<uint64_t>(field), val);
}

void AutoVmcs::Write(VmcsField64 field, uint64_t val) {
  DEBUG_ASSERT(vmcs_address_ != 0);
  vmwrite(static_cast<uint64_t>(field), val);
}

void AutoVmcs::Write(VmcsFieldXX field, uint64_t val) {
  DEBUG_ASSERT(vmcs_address_ != 0);
  vmwrite(static_cast<uint64_t>(field), val);
}

zx::result<> AutoVmcs::SetControl(VmcsField32 controls, uint64_t true_msr, uint64_t old_msr,
                                  uint32_t set, uint32_t clear) {
  DEBUG_ASSERT(vmcs_address_ != 0);
  uint32_t allowed_0 = static_cast<uint32_t>(BITS(true_msr, 31, 0));
  uint32_t allowed_1 = static_cast<uint32_t>(BITS_SHIFT(true_msr, 63, 32));
  if ((allowed_1 & set) != set) {
    dprintf(INFO, "Failed to set VMCS controls %#x, %#x != %#x\n", static_cast<uint>(controls),
            allowed_1, set);
    return zx::error(ZX_ERR_NOT_SUPPORTED);
  }
  if ((~allowed_0 & clear) != clear) {
    dprintf(INFO, "Failed to clear VMCS controls %#x, %#x != %#x\n", static_cast<uint>(controls),
            ~allowed_0, clear);
    return zx::error(ZX_ERR_NOT_SUPPORTED);
  }
  if ((set & clear) != 0) {
    dprintf(INFO, "Attempted to set and clear the same VMCS controls %#x\n",
            static_cast<uint>(controls));
    return zx::error(ZX_ERR_INVALID_ARGS);
  }

  // See Volume 3, Section 31.5.1, Algorithm 3, Part C. If the control can be
  // either 0 or 1 (flexible), and the control is unknown, then refer to the
  // old MSR to find the default value.
  uint32_t flexible = allowed_0 ^ allowed_1;
  uint32_t unknown = flexible & ~(set | clear);
  uint32_t defaults = unknown & BITS(old_msr, 31, 0);
  Write(controls, allowed_0 | defaults | set);
  return zx::ok();
}

bool cr0_is_invalid(AutoVmcs& vmcs, uint64_t cr0_value) {
  uint64_t check_value = cr0_value;
  // From Volume 3, Section 26.3.1.1: PE and PG bits of CR0 are not checked when unrestricted
  // guest is enabled. Set both here to avoid clashing with X86_MSR_IA32_VMX_CR0_FIXED1.
  if (vmcs.Read(VmcsField32::PROCBASED_CTLS2) & kProcbasedCtls2UnrestrictedGuest) {
    check_value |= X86_CR0_PE | X86_CR0_PG;
  }
  return cr_is_invalid(check_value, X86_MSR_IA32_VMX_CR0_FIXED0, X86_MSR_IA32_VMX_CR0_FIXED1);
}

// static
zx::result<ktl::unique_ptr<Vcpu>> Vcpu::Create(Guest& guest, zx_vaddr_t entry, uint32_t options) {
  if ((options & ~ZX_VCPU_CREATE_XAPIC) != 0) {
    return zx::error(ZX_ERR_INVALID_ARGS);
  }
  if (fbl::RefPtr<VmAddressRegion> root_vmar = guest.RootVmar();
      entry < root_vmar->base() || entry >= root_vmar->base() + root_vmar->size()) {
    return zx::error(ZX_ERR_INVALID_ARGS);
  }

  Thread* thread = Thread::Current::Get();
  if (thread->vcpu()) {
    return zx::error(ZX_ERR_BAD_STATE);
  }

  auto vpid = guest.TryAllocVpid();
  if (vpid.is_error()) {
    return vpid.take_error();
  }

  fbl::AllocChecker ac;
  ktl::unique_ptr<Vcpu> vcpu(new (&ac) Vcpu(guest, *vpid, thread));
  if (!ac.check()) {
    auto result = guest.FreeVpid(*vpid);
    DEBUG_ASSERT(result.is_ok());
    return zx::error(ZX_ERR_NO_MEMORY);
  }
  vcpu->local_apic_state_.x2apic_enabled = (options & ZX_VCPU_CREATE_XAPIC) == 0;

  VmxInfo vmx_info;
  auto result = vcpu->vmcs_page_.Alloc(vmx_info, 0);
  if (result.is_error()) {
    return result.take_error();
  }

  VmxRegion* region = vcpu->vmcs_page_.template VirtualAddress<VmxRegion>();
  region->revision_id = vmx_info.revision_id;

  // The virtual-APIC page. Zero-filled, which is the architectural reset value
  // of the one field in it this hypervisor uses: Volume 3, Section 11.8.4 --
  // "the task-priority register is set to 0 on reset", i.e. the guest starts
  // blocking nothing. Must exist before `vmcs_init`, which programs its address.
  if (auto result = vcpu->virtual_apic_page_.Alloc(0); result.is_error()) {
    return result.take_error();
  }
  vcpu->local_apic_state_.virtual_apic =
      vcpu->virtual_apic_page_.template VirtualAddress<volatile uint32_t>();

  // Mapping the shared APIC-access page can take blocking VM locks, so it must
  // happen before AutoVmcs disables interrupts and blocking below.
  if (!vcpu->local_apic_state_.x2apic_enabled) {
    const uint32_t offered =
        static_cast<uint32_t>(read_msr(X86_MSR_IA32_VMX_PROCBASED_CTLS2) >> 32);
    const uint32_t acceleration =
        kProcbasedCtls2ApicAccess | kProcbasedCtls2ApicRegister;
    if ((offered & acceleration) == acceleration) {
      if (result = guest.MapApicAccessPage(); result.is_error()) {
        return result.take_error();
      }
    }
  }

  zx_paddr_t ept_pml4 = guest.PhysicalAspace().arch_aspace().arch_table_phys();
  zx_paddr_t vmcs_address = vcpu->vmcs_page_.PhysicalAddress();
  // We create the `AutoVmcs` object here, so that we ensure that interrupts are
  // disabled from `vmcs_init` until `SetMigrateFn`. This is important to ensure
  // that we do not migrate CPUs while setting up the VCPU.
  {
    AutoVmcs vmcs(vmcs_address, /*clear=*/true);
    result = vmcs_init(vmcs, *vpid, entry, guest.MsrBitmapsAddress(),
                       vcpu->virtual_apic_page_.PhysicalAddress(), guest.ApicAccessAddress(),
                       ept_pml4, vcpu->local_apic_state_.x2apic_enabled, &vcpu->vmx_state_,
                       vcpu->extended_register_state_, vcpu->xstate_buffer_xcr0_);
    if (result.is_error()) {
      return result.take_error();
    }

    {
      Guard<SpinLock, IrqSave> list_guard{&Thread::get_list_lock()};
      SingleChainLockGuard thread_guard{IrqSaveOption, thread->get_lock(), CLT_TAG("Vcpu::Create")};

      // Only set the thread migrate function after we have initialised the VMCS.
      // Otherwise, the migrate function may interact with an uninitialised VMCS.
      thread->SetMigrateFnLocked([vcpu = vcpu.get()](Thread* thread, auto stage) {
        ChainLockTransaction::AssertActive();
        thread->get_lock().AssertHeld();
        vcpu->Migrate(thread, stage);
      });
      thread->SetContextSwitchFnLocked([vcpu = vcpu.get()]() {
        if (vcpu->entered_.load()) {
          // `arch_context_switch()` saves and restores GS, so we can skip it.
          vcpu->ContextSwitch(/*include_gs=*/false);
        }
        // The guest's XCR0 and extended-register file must not survive this
        // thread losing the CPU. See Vcpu::SwapExtendedRegistersOut.
        vcpu->SwapExtendedRegistersOut();
      });
    }
    // Destroy AutoVmcs before taking Guest's normal VCPU registry mutex below.
    // AutoVmcs deliberately marks blocking as disallowed while a VMCS is
    // current on this CPU.
  }

  DEBUG_ASSERT(!arch_ints_disabled());
  DEBUG_ASSERT(!arch_blocking_disallowed());

  // Setup PV clock state.
  vcpu->pv_clock_state_.is_stable = x86_hypervisor_has_pv_clock()
                                        ? pv_clock_is_stable()
                                        : x86_feature_test(X86_FEATURE_INVAR_TSC);

  guest.RegisterVcpu(*vcpu, *vpid);
  vcpu->registered_with_guest_ = true;
  return zx::ok(ktl::move(vcpu));
}

Vcpu::Vcpu(Guest& guest, uint16_t vpid, Thread* thread)
    : guest_(guest),
      vpid_(vpid),
      last_cpu_(thread->LastCpu()),
      thread_(thread),
      vmx_state_(/* zero-init */),
      msr_state_(/* zero-init */) {
  thread->set_vcpu(true);
}

void Vcpu::ResetInstructionControl() {
  if (instruction_counter_reserved_) {
    x86_perfmon_release_vcpu_counter();
    instruction_counter_reserved_ = false;
  }
  instruction_control_armed_ = false;
  instruction_budget_ = 0;
  retired_instructions_ = 0;
  pending_instruction_budget_ = {};
  pending_instruction_budget_valid_ = false;
  pending_instruction_budget_delivered_ = false;
}

void Vcpu::ResetIntelPtControl() {
  intel_pt_.reset();
}

zx::result<> Vcpu::ActivateHardwareBreakpointControl(AutoVmcs& vmcs) {
  if (hardware_breakpoint_ == nullptr || !hardware_breakpoint_->armed()) {
    return zx::error(ZX_ERR_BAD_STATE);
  }

  HardwareBreakpointController::GuestState guest = {};
  for (size_t i = 0; i < 4; ++i) {
    guest.address[i] = guest_debug_regs_[i];
  }
  guest.dr6 = guest_dr6_;
  guest.dr7 = guest_dr7_;
  guest.linear_address_width =
      (vmcs.Read(VmcsFieldXX::GUEST_CR4) & kGuestCr4La57) != 0 ? 57 : 48;
  const auto physical =
      hardware_breakpoint_->controller().BuildPhysicalState(guest);

  if (hardware_breakpoint_vmcs_active_) {
    vmcs.Write(VmcsFieldXX::GUEST_DR7, physical.dr7);
    return zx::ok();
  }

  const uint64_t primary_controls =
      read_msr(X86_MSR_IA32_VMX_TRUE_PROCBASED_CTLS);
  const uint64_t entry_controls =
      read_msr(X86_MSR_IA32_VMX_TRUE_ENTRY_CTLS);
  const uint64_t exit_controls =
      read_msr(X86_MSR_IA32_VMX_TRUE_EXIT_CTLS);
  const uint32_t primary = vmcs.Read(VmcsField32::PROCBASED_CTLS);
  const uint32_t entry = vmcs.Read(VmcsField32::ENTRY_CTLS);
  const uint32_t exit = vmcs.Read(VmcsField32::EXIT_CTLS);
  const uint32_t bitmap = vmcs.Read(VmcsField32::EXCEPTION_BITMAP);
  const uint32_t desired_primary = primary | kProcbasedCtlsMovDrExiting;
  const uint32_t desired_entry = entry | kEntryCtlsLoadDebugControls;
  const uint32_t desired_exit = exit | kExitCtlsSaveDebugControls;
  if (desired_primary != primary) {
    if (auto result =
            vmcs.SetControl(VmcsField32::PROCBASED_CTLS, primary_controls,
                            read_msr(X86_MSR_IA32_VMX_PROCBASED_CTLS),
                            desired_primary, ~desired_primary);
        result.is_error()) {
      return result.take_error();
    }
  }
  if (desired_entry != entry) {
    if (auto result =
            vmcs.SetControl(VmcsField32::ENTRY_CTLS, entry_controls,
                            read_msr(X86_MSR_IA32_VMX_ENTRY_CTLS),
                            desired_entry, ~desired_entry);
        result.is_error()) {
      vmcs.Write(VmcsField32::PROCBASED_CTLS, primary);
      return result.take_error();
    }
  }
  if (desired_exit != exit) {
    if (auto result =
            vmcs.SetControl(VmcsField32::EXIT_CTLS, exit_controls,
                            read_msr(X86_MSR_IA32_VMX_EXIT_CTLS),
                            desired_exit, ~desired_exit);
        result.is_error()) {
      vmcs.Write(VmcsField32::ENTRY_CTLS, entry);
      vmcs.Write(VmcsField32::PROCBASED_CTLS, primary);
      return result.take_error();
    }
  }
  vmcs.Write(VmcsField32::EXCEPTION_BITMAP,
             bitmap | (uint32_t{1} << X86_INT_DEBUG));
  vmcs.Write(VmcsFieldXX::GUEST_DR7, physical.dr7);
  hardware_breakpoint_had_mov_dr_exiting_ =
      (primary & kProcbasedCtlsMovDrExiting) != 0;
  hardware_breakpoint_had_debug_exception_exit_ =
      (bitmap & (uint32_t{1} << X86_INT_DEBUG)) != 0;
  hardware_breakpoint_had_entry_debug_controls_ =
      (entry & kEntryCtlsLoadDebugControls) != 0;
  hardware_breakpoint_had_exit_debug_controls_ =
      (exit & kExitCtlsSaveDebugControls) != 0;
  hardware_breakpoint_vmcs_active_ = true;
  return zx::ok();
}

zx::result<> Vcpu::DeactivateHardwareBreakpointControl(AutoVmcs& vmcs) {
  if (!hardware_breakpoint_vmcs_active_) {
    vmcs.Write(VmcsFieldXX::GUEST_DR7, guest_dr7_);
    return zx::ok();
  }

  const uint32_t primary = vmcs.Read(VmcsField32::PROCBASED_CTLS);
  const uint32_t entry = vmcs.Read(VmcsField32::ENTRY_CTLS);
  const uint32_t exit = vmcs.Read(VmcsField32::EXIT_CTLS);
  const uint32_t bitmap = vmcs.Read(VmcsField32::EXCEPTION_BITMAP);
  const uint32_t desired_primary =
      hardware_breakpoint_had_mov_dr_exiting_
          ? (primary | kProcbasedCtlsMovDrExiting)
          : (primary & ~kProcbasedCtlsMovDrExiting);
  const uint32_t desired_entry =
      hardware_breakpoint_had_entry_debug_controls_
          ? (entry | kEntryCtlsLoadDebugControls)
          : (entry & ~kEntryCtlsLoadDebugControls);
  const uint32_t desired_exit =
      hardware_breakpoint_had_exit_debug_controls_
          ? (exit | kExitCtlsSaveDebugControls)
          : (exit & ~kExitCtlsSaveDebugControls);
  if (desired_primary != primary) {
    if (auto result =
            vmcs.SetControl(VmcsField32::PROCBASED_CTLS,
                            read_msr(X86_MSR_IA32_VMX_TRUE_PROCBASED_CTLS),
                            read_msr(X86_MSR_IA32_VMX_PROCBASED_CTLS),
                            desired_primary, ~desired_primary);
        result.is_error()) {
      return result.take_error();
    }
  }
  if (desired_entry != entry) {
    if (auto result =
            vmcs.SetControl(VmcsField32::ENTRY_CTLS,
                            read_msr(X86_MSR_IA32_VMX_TRUE_ENTRY_CTLS),
                            read_msr(X86_MSR_IA32_VMX_ENTRY_CTLS),
                            desired_entry, ~desired_entry);
        result.is_error()) {
      vmcs.Write(VmcsField32::PROCBASED_CTLS, primary);
      return result.take_error();
    }
  }
  if (desired_exit != exit) {
    if (auto result =
            vmcs.SetControl(VmcsField32::EXIT_CTLS,
                            read_msr(X86_MSR_IA32_VMX_TRUE_EXIT_CTLS),
                            read_msr(X86_MSR_IA32_VMX_EXIT_CTLS),
                            desired_exit, ~desired_exit);
        result.is_error()) {
      vmcs.Write(VmcsField32::ENTRY_CTLS, entry);
      vmcs.Write(VmcsField32::PROCBASED_CTLS, primary);
      return result.take_error();
    }
  }
  vmcs.Write(VmcsField32::EXCEPTION_BITMAP,
             hardware_breakpoint_had_debug_exception_exit_
                 ? (bitmap | (uint32_t{1} << X86_INT_DEBUG))
                 : (bitmap & ~(uint32_t{1} << X86_INT_DEBUG)));
  vmcs.Write(VmcsFieldXX::GUEST_DR7, guest_dr7_);
  hardware_breakpoint_vmcs_active_ = false;
  hardware_breakpoint_had_mov_dr_exiting_ = false;
  hardware_breakpoint_had_debug_exception_exit_ = false;
  hardware_breakpoint_had_entry_debug_controls_ = false;
  hardware_breakpoint_had_exit_debug_controls_ = false;
  return zx::ok();
}

zx::result<> Vcpu::HandleHardwareBreakpointMovDr(AutoVmcs& vmcs) {
  DEBUG_ASSERT(hardware_breakpoint_ != nullptr);
  DEBUG_ASSERT(hardware_breakpoint_->armed());

  const uint64_t qualification = vmcs.Read(VmcsFieldXX::EXIT_QUALIFICATION);
  uint32_t debug_register = static_cast<uint32_t>(qualification & 7);
  const bool from_debug_register = (qualification & (uint64_t{1} << 4)) != 0;
  const uint8_t general_register =
      static_cast<uint8_t>((qualification >> 8) & 0xf);
  const bool long_mode =
      (vmcs.Read(VmcsField32::ENTRY_CTLS) & kEntryCtls64bitMode) != 0;

  HardwareBreakpointController::GuestState guest = {};
  for (size_t i = 0; i < 4; ++i) {
    guest.address[i] = guest_debug_regs_[i];
  }
  guest.dr6 = guest_dr6_;
  guest.dr7 = guest_dr7_;
  guest.linear_address_width =
      (vmcs.Read(VmcsFieldXX::GUEST_CR4) & kGuestCr4La57) != 0 ? 57 : 48;

  auto queue_exception = [this](uint32_t vector) -> zx::result<> {
    if (pending_event_.type != ZX_VCPU_EVENT_NONE) {
      return zx::error(ZX_ERR_BAD_STATE);
    }
    pending_event_ = {};
    pending_event_.type = ZX_VCPU_EVENT_HARDWARE_EXCEPTION;
    pending_event_.vector = vector;
    pending_event_.has_error_code = has_error_code(vector);
    return zx::ok();
  };

  // General detect faults before every MOV-DR, clears GD, and leaves RIP on the
  // instruction. The following entry delivers the guest's own #DB.
  if ((guest.dr7 & X86_DR7_GD) != 0) {
    hardware_breakpoint_->controller().WriteGuestDr7(
        guest.dr7 & ~static_cast<uint64_t>(X86_DR7_GD), guest);
    hardware_breakpoint_->controller().WriteGuestDr6(
        guest.dr6 | static_cast<uint64_t>(X86_DR6_BD), guest);
    guest_dr6_ = guest.dr6;
    guest_dr7_ = guest.dr7;
    if (auto result = queue_exception(X86_INT_DEBUG); result.is_error()) {
      return result.take_error();
    }
    return ActivateHardwareBreakpointControl(vmcs);
  }

  // With CR4.DE clear, DR4/DR5 are the architectural aliases of DR6/DR7.
  // With it set they are undefined instructions.
  if (debug_register == 4 || debug_register == 5) {
    if ((vmcs.Read(VmcsFieldXX::GUEST_CR4) &
         kGuestCr4DebugExtensions) != 0) {
      return queue_exception(X86_INT_INVALID_OP);
    }
    debug_register += 2;
  }

  if (from_debug_register) {
    uint64_t value = 0;
    switch (debug_register) {
      case 0:
      case 1:
      case 2:
      case 3:
        value = hardware_breakpoint_->controller().ReadGuestAddress(
            debug_register, guest);
        break;
      case 6:
        value = hardware_breakpoint_->controller().ReadGuestDr6(guest);
        break;
      case 7:
        value = hardware_breakpoint_->controller().ReadGuestDr7(guest);
        break;
      default:
        return zx::error(ZX_ERR_BAD_STATE);
    }
    if (auto result = write_guest_gpr(vmcs, vmx_state_.guest_state,
                                      general_register, value, long_mode);
        result.is_error()) {
      return result.take_error();
    }
  } else {
    auto value = read_guest_gpr(vmcs, vmx_state_.guest_state,
                                general_register, long_mode);
    if (value.is_error()) {
      return value.take_error();
    }
    // In 64-bit mode, MOV to DR6/DR7 with any high bit set faults instead of
    // silently truncating.
    if (long_mode && debug_register >= 6 && (*value >> 32) != 0) {
      return queue_exception(X86_INT_GP_FAULT);
    }
    switch (debug_register) {
      case 0:
      case 1:
      case 2:
      case 3:
        if (auto result = hardware_breakpoint_->controller().WriteGuestAddress(
                debug_register, *value, guest);
            result.is_error()) {
          return result.take_error();
        }
        break;
      case 6:
        hardware_breakpoint_->controller().WriteGuestDr6(*value, guest);
        break;
      case 7:
        hardware_breakpoint_->controller().WriteGuestDr7(*value, guest);
        break;
      default:
        return zx::error(ZX_ERR_BAD_STATE);
    }
  }

  for (size_t i = 0; i < 4; ++i) {
    guest_debug_regs_[i] = guest.address[i];
  }
  guest_dr6_ = guest.dr6;
  guest_dr7_ = guest.dr7;
  advance_guest_rip(vmcs);

  if (hardware_breakpoint_->armed()) {
    return ActivateHardwareBreakpointControl(vmcs);
  }
  // The guest enabled more slots than the host plan can transparently fit.
  // Preserve its write exactly and cancel the host control.
  return DeactivateHardwareBreakpointControl(vmcs);
}

zx::result<bool> Vcpu::HandleHardwareBreakpointDebugExit(
    AutoVmcs& vmcs, uint64_t raw_dr6, zx_port_packet_t& packet) {
  const uint32_t interruption =
      vmcs.Read(VmcsField32::EXIT_INTERRUPTION_INFORMATION);
  if ((interruption & kInterruptInfoValid) == 0 ||
      (interruption & kInterruptInfoTypeMask) !=
          kInterruptTypeHardwareException ||
      (interruption & kInterruptInfoVectorMask) != X86_INT_DEBUG) {
    return zx::ok(false);
  }

  HardwareBreakpointSession::PendingStop pending = {};
  hardware_breakpoint_->MaybeLatchDebugExit(
      raw_dr6, vmcs.Read(VmcsFieldXX::GUEST_RIP), vpid_, pending);

  if (!hardware_breakpoint_->pending()) {
    // Guest-only #DB: update its architectural status and queue the exception
    // back to the guest without surfacing a host stop.
    HardwareBreakpointController::GuestState guest = {};
    guest.dr6 = guest_dr6_;
    guest.dr7 = guest_dr7_;
    hardware_breakpoint_->controller().WriteGuestDr6(raw_dr6, guest);
    if ((raw_dr6 & X86_DR6_BD) != 0) {
      hardware_breakpoint_->controller().WriteGuestDr7(
          guest.dr7 & ~static_cast<uint64_t>(X86_DR7_GD), guest);
    }
    guest_dr6_ = guest.dr6;
    guest_dr7_ = guest.dr7;
    if (pending_event_.type != ZX_VCPU_EVENT_NONE) {
      return zx::error(ZX_ERR_BAD_STATE);
    }
    pending_event_ = {};
    pending_event_.type = ZX_VCPU_EVENT_HARDWARE_EXCEPTION;
    pending_event_.vector = X86_INT_DEBUG;
    if (auto result = ActivateHardwareBreakpointControl(vmcs);
        result.is_error()) {
      return result.take_error();
    }
    return zx::ok(true);
  }

  // The controller consumed the host one-shot. Preserve only coincident guest
  // causes in the guest-visible DR6, then remove every host-owned VMCS control.
  HardwareBreakpointController::GuestState guest = {};
  guest.dr6 = guest_dr6_;
  guest.dr7 = guest_dr7_;
  hardware_breakpoint_->controller().WriteGuestDr6(
      pending.stop.guest_dr6, guest);
  if ((pending.stop.guest_dr6 & X86_DR6_BD) != 0) {
    hardware_breakpoint_->controller().WriteGuestDr7(
        guest.dr7 & ~static_cast<uint64_t>(X86_DR7_GD), guest);
  }
  guest_dr6_ = guest.dr6;
  guest_dr7_ = guest.dr7;
  if (auto result = DeactivateHardwareBreakpointControl(vmcs);
      result.is_error()) {
    hardware_breakpoint_->Reset();
    return result.take_error();
  }

  if (!guest_.ClaimHardwareBreakpointStop(vpid_)) {
    // Another VP reached a stop first. Keep this immutable local result; once
    // the first is acknowledged, a later Enter publishes this one without
    // re-entering the guest.
    return zx::error(ZX_ERR_CANCELED);
  }

  memset(&packet, 0, sizeof(packet));
  packet.type = ZX_PKT_TYPE_GUEST_HARDWARE_BREAKPOINT;
  packet.guest_hardware_breakpoint.sequence = pending.sequence;
  packet.guest_hardware_breakpoint.rip = pending.stop.rip;
  packet.guest_hardware_breakpoint.condition_mask =
      pending.stop.condition_mask;
  packet.guest_hardware_breakpoint.vpid = pending.stop.vpid;
  packet.guest_hardware_breakpoint.slot_mask = pending.stop.slot_mask;
  packet.guest_hardware_breakpoint.boundary =
      static_cast<uint8_t>(pending.stop.boundary);
  return zx::ok(true);
}

Vcpu::~Vcpu() {
  if (registered_with_guest_) {
    if (guest_.IsHardwareBreakpointTrigger(vpid_)) {
      guest_.ReleaseHardwareBreakpointStop(vpid_);
    }
    hardware_breakpoint_.reset();
    guest_.ReleaseMemoryAccessOwner(*this, vpid_);
    guest_.UnregisterVcpu(*this, vpid_);
    registered_with_guest_ = false;
  }
  ResetInstructionControl();
  ResetIntelPtControl();
  {
    // Taking the Thread list lock guarantees that our thread cannot be in the
    // Exiting stage of our migration function as Thread::Exit holds the list
    // lock during the migration callback.  `thread_` is only ever mutated
    // during this callback as the thread exits, so we are guaranteed to see
    // either our thread, or nullptr if the thread has already exited.
    Guard<SpinLock, IrqSave> guard{&Thread::get_list_lock()};
    if (thread_ != nullptr) {
      SingleChainLockGuard thread_guard{NoIrqSaveOption, thread_->get_lock(),
                                        CLT_TAG("Vcpu::~Vcpu")};
      thread_->set_vcpu(false);
      // Clear the migration function, so that |thread_| does not reference
      // |this| after destruction of the VCPU.
      thread_->SetMigrateFnLocked(nullptr);
      thread_->SetContextSwitchFnLocked(nullptr);
    }
  }
  // last_cpu_ would normally be guarded by thread_->get_lock(), but in the case where thread_ has
  // already exited and become nullptr we still need to clear the vmcs off the last cpu the thread
  // ran on. As we are in the destructor, and have already cleared out any potential thread_
  // migration function, we are safe to just read last_cpu_ directly here. Note that it is being in
  // the destructor that causes the lock annotations to be okay with this load, but it is being
  // specifically after removal of any migrate method that actually makes this safe.
  const cpu_num_t cpu = last_cpu_;

  if (vmcs_page_.IsAllocated() && cpu != INVALID_CPU) {
    // Clear VMCS state from the CPU.
    //
    // The destructor may be called from a different thread, therefore we must
    // IPI the CPU that last run the thread.
    paddr_t paddr = vmcs_page_.PhysicalAddress();
    mp_sync_exec(
        mp_ipi_target::MASK, cpu_num_to_mask(cpu),
        [](void* paddr) { vmclear(reinterpret_cast<paddr_t>(paddr)); },
        ktl::bit_cast<void*>(paddr));
  }

  local_apic_state_.timer.Cancel();
  auto result = guest_.FreeVpid(vpid_);
  DEBUG_ASSERT(result.is_ok());
}

void Vcpu::Migrate(Thread* thread, Thread::MigrateStage stage) {
  // The thread being passed to us must be _our_ thread, and its lock must
  // currently be held (a requirement for calling a Migration function).  Assert
  // this to make the lock analysis happy.
  DEBUG_ASSERT(ThreadIsOurThread(thread));
  [this]() TA_NO_THREAD_SAFETY_ANALYSIS TA_RET_CAP(
      thread_->get_lock()) -> auto& { return thread_->get_lock(); }().AssertHeld();

  // Volume 3, Section 31.8.2: An MP-aware VMM is free to assign any logical
  // processor to a VM. But for performance considerations, moving a guest VMCS
  // to another logical processor is slower than resuming that guest VMCS on the
  // same logical processor. Certain VMX performance features (such as caching
  // of portions of the VMCS in the processor) are optimized for a guest VMCS
  // that runs on the same logical processor.
  //
  // If the VMCS regions are identical (same revision ID) the following sequence
  // can be used to move or copy the VMCS from one logical processor to another:
  switch (stage) {
    // * Perform a VMCLEAR operation on the source logical processor. This
    //   ensures that all VMCS data that may be cached by the processor are
    //   flushed to memory.
    case Thread::MigrateStage::Save: {
      vmclear(vmcs_page_.PhysicalAddress());
      // After VMCLEAR, `last_cpu_` can be cleared to indicate this VCPU is both
      // not presently running, and its state is not loaded anywhere.
      last_cpu_ = INVALID_CPU;
      break;
    }
    // * Copy the VMCS region from one memory location to another location. This
    //   is an optional step assuming the VMM wishes to relocate the VMCS or
    //   move the VMCS to another system.
    // * Perform a VMPTRLD of the physical address of VMCS region on the
    //   destination processor to establish its current VMCS pointer.
    case Thread::MigrateStage::Restore: {
      // Volume 3, Section 31.8.2: To migrate a VMCS to another logical
      // processor, a VMM must use the sequence of VMCLEAR, VMPTRLD and
      // VMLAUNCH.
      //
      // We set `resume` to false so that `vmx_enter` will call VMLAUNCH when
      // entering the the guest, instead of VMRESUME.
      vmx_state_.resume = false;

      // Before performing the VMPTRLD, update the `last_cpu_` for
      // `Vcpu::Interrupt()` and `vmcs_page_` state tracking. It is assumed that
      // the `Thread::MigrateStage::Save` stage already happened and that a
      // VMCLEAR has been performed on `last_cpu_`, hence the previous value of
      DEBUG_ASSERT(last_cpu_ == INVALID_CPU);
      last_cpu_ = thread->LastCpuLocked();

      // Load the VMCS on the destination processor.
      vmptrld(vmcs_page_.PhysicalAddress());

      // Update the VMCS with the per-CPU variables of the destination
      // processor.
      x86_percpu* percpu = x86_get_percpu();
      vmwrite(static_cast<uint64_t>(VmcsField16::HOST_TR_SELECTOR), TSS_SELECTOR(percpu->cpu_num));
      vmwrite(static_cast<uint64_t>(VmcsFieldXX::HOST_FS_BASE), thread->arch().fs_base);
      vmwrite(static_cast<uint64_t>(VmcsFieldXX::HOST_GS_BASE), read_msr(X86_MSR_IA32_GS_BASE));
      vmwrite(static_cast<uint64_t>(VmcsFieldXX::HOST_TR_BASE),
              reinterpret_cast<uint64_t>(&percpu->default_tss));

      // Invalidate TLB mappings for the VPID.
      invvpid(InvVpid::SINGLE_CONTEXT, vpid_, 0);
      break;
    }
    case Thread::MigrateStage::Exiting: {
      // The `thread_` is exiting and so we must clear our reference to it.
      Thread::get_list_lock().lock().AssertHeld();
      ktl::atomic_ref{thread_}.store(nullptr, ktl::memory_order_relaxed);
      break;
    }
  }
}

void Vcpu::ContextSwitch(bool include_gs) {
  uint64_t star = read_msr(X86_MSR_IA32_STAR);
  uint64_t lstar = read_msr(X86_MSR_IA32_LSTAR);
  uint64_t cstar = read_msr(X86_MSR_IA32_CSTAR);
  uint64_t fmask = read_msr(X86_MSR_IA32_FMASK);
  uint64_t tsc_aux = read_msr(X86_MSR_IA32_TSC_AUX);

  write_msr(X86_MSR_IA32_STAR, msr_state_.star);
  write_msr(X86_MSR_IA32_LSTAR, msr_state_.lstar);
  write_msr(X86_MSR_IA32_CSTAR, msr_state_.cstar);
  write_msr(X86_MSR_IA32_FMASK, msr_state_.fmask);
  write_msr(X86_MSR_IA32_TSC_AUX, msr_state_.tsc_aux);

  msr_state_.star = star;
  msr_state_.lstar = lstar;
  msr_state_.cstar = cstar;
  msr_state_.fmask = fmask;
  msr_state_.tsc_aux = tsc_aux;

  if (include_gs) {
    uint64_t kernel_gs_base = read_msr(X86_MSR_IA32_KERNEL_GS_BASE);
    write_msr(X86_MSR_IA32_KERNEL_GS_BASE, msr_state_.kernel_gs_base);
    msr_state_.kernel_gs_base = kernel_gs_base;
  }
}

// Both halves of the swap run with interrupts and preemption disabled and
// blocking disallowed -- LoadExtendedRegisters() from inside the `AutoVmcs` that
// brackets a VM entry, SaveExtendedRegisters() from the context-switch callback
// or from the same kind of bracketed region in Enter()'s defer. That is what
// makes "the guest's XCR0 is live exactly while this thread owns the CPU"
// enforceable rather than aspirational; see Vcpu::SwapExtendedRegistersOut.
void Vcpu::LoadExtendedRegisters() {
  arch_thread& thread = Thread::Current::Get()->arch();
  bool save_host = x86_xsave_supported();
  // x86_xsave_supported() says this CPU has the XSETBV instruction at all, and
  // that is the ONLY term this predicate may have. Do not re-add guest
  // CR4.OSXSAVE to it.
  //
  // It used to read `x86_xsave_supported() && (GUEST_CR4 & X86_CR4_OSXSAVE)`,
  // and that made the XCR0 in force when the guest's XSAVE image is restored
  // depend on a bit the guest can flip without exiting (CR4_GUEST_HOST_MASK
  // holds only VMXE, so a guest `mov cr4` never traps). Load and save are
  // separated by at least one VM entry: the guest could be entered with OSXSAVE set --
  // image restored under the guest's XCR0, image saved under the guest's XCR0 --
  // then clear OSXSAVE, and the next entry would XRSTOR that same image under
  // the *host's* XCR0 instead. If the guest's XCR0 named a component the host's
  // does not, that XRSTOR is a #GP on a kernel instruction. Keeping the
  // predicate free of guest state makes the guest's XCR0 the XCR0 in force at
  // every save and every restore of this buffer, which is the invariant
  // ValidateGuestXsaveImage() validates against (see vmexit.cc).
  //
  // Nothing guest-visible is lost. During guest execution the physical CR4 is
  // the guest's, so with OSXSAVE clear the guest cannot execute XGETBV, XSAVE or
  // any AVX instruction whatever the physical XCR0 holds. And the value loaded
  // is always one ValidateGuestXcr0() has passed, so the XSETBV itself cannot
  // fault.
  bool load_guest = x86_xsave_supported();
  swap_extended_registers(thread.extended_register_buffer, vmx_state_.host_state.xcr0, save_host,
                          extended_register_state_, xstate_buffer_xcr0_, load_guest);
}

void Vcpu::SaveExtendedRegisters() {
  arch_thread& thread = Thread::Current::Get()->arch();
  // Mirrors LoadExtendedRegisters, and must keep mirroring it: the two
  // predicates have to stay identical or the XCR0 an image is saved under stops
  // being the XCR0 it is restored under. See the comment there.
  //
  // The guest's slot here is `xstate_buffer_xcr0_`, not
  // guest_state.xcr0, and the swap is what maintains it -- this records the XCR0
  // the buffer has just been written under. It used to read the physical XCR0
  // back into guest_state.xcr0, which was harmless only while a guest XSETBV was
  // inert. Now that handle_xsetbv writes guest_state.xcr0 and
  // ReconcileGuestXcr0() installs it at the next entry, there is a window between
  // the two -- the AutoVmcs destructor at the bottom of Enter()'s loop re-enables
  // preemption -- in which a deschedule would run this function and OVERWRITE the
  // guest's new value with the old physical one. The guest would see its XSETBV
  // retire (RIP has already advanced) and have no effect, occasionally and
  // unreproducibly. Keeping the two apart makes that window harmless instead:
  // this records where the BUFFER is, Reconcile moves it to where the GUEST asked
  // to be, and neither overwrites the other.
  //
  // The XSETBV test cannot see this race because it never deschedules in the
  // window.
  bool save_guest = x86_xsave_supported();
  bool load_host = x86_xsave_supported();
  swap_extended_registers(extended_register_state_, xstate_buffer_xcr0_, save_guest,
                          thread.extended_register_buffer, vmx_state_.host_state.xcr0, load_host);
}

// Makes a guest XSETBV take effect without letting the guest see state
// it did not put there and without faulting the host.
//
// Called from Vcpu::Enter on every iteration, after any LoadExtendedRegisters(),
// inside the AutoVmcs that brackets the entry -- so interrupts and preemption are
// off, `xstate_loaded_` is true, and the physical XCR0 is definitely this guest's.
// handle_xsetbv deliberately does not touch the register itself: it cannot tell
// whose extended state is in the CPU, and an x86_xsetbv issued while the HOST's is
// loaded would corrupt the host's XCR0.
//
// TWO XCR0s, and the distinction is what makes this safe:
//
//   * `guest_state.xcr0` is the guest's ARCHITECTURAL XCR0 -- what XGETBV must
//     report and what SaveArchState carries. Written by Vcpu::Setup,
//     handle_xsetbv and Vcpu::RestoreArchState.
//   * `xstate_buffer_xcr0_` is the XCR0 `extended_register_state_` was last
//     WRITTEN under. Load and Save both use it, so a restore of that buffer always
//     happens under the XCR0 it was saved under.
//
// They diverge exactly between a guest XSETBV and the next entry, and this
// function is what closes the gap.
//
// WHY THE REGISTER FILE HAS TO MOVE, and why a bare x86_xsetbv is the version that
// leaks. XSAVE and XRSTOR select components by the LIVE XCR0, so while the guest's
// XCR0 is narrow, a component outside it is neither saved into the guest's buffer
// nor restored from it -- it keeps whatever the physical registers hold, which
// after any deschedule is the HOST's. Simply widening XCR0 would hand the guest
// those registers: a guest that XSETBVs down to x87|SSE, is descheduled, and then
// XSETBVs AVX back on would read the host's YMM upper halves. Cycling the file
// through the guest's own buffer instead means a newly selected component comes
// back INITIALIZED (Volume 1, Section 13.8: a component in RFBM whose XSTATE_BV bit
// is clear is initialized, not left alone), which is also what the guest should see.
//
// WHY DROPS AND ADDITIONS ARE DONE SEPARATELY, and this one is a host fault rather
// than a leak. This kernel restores with XRSTORS where the part has XSAVES, i.e.
// the COMPACTED format, and XRSTORS #GP(0)s if the image's XCOMP_BV names a
// component absent from XCR0 (Volume 2, "XRSTORS"). A save under the old XCR0
// followed by a restore under a NARROWER one violates exactly that -- and #GP on
// XRSTORS in host context is a kernel panic, which is how this was found: the
// first version of this function did the save/restore unconditionally and killed
// the boot with "vector 13" inside x86_extended_register_restore_state.
//
// So: drop first, with no state movement at all (nothing new becomes visible, so
// there is nothing to leak), and only then add, with the buffer written under the
// intersection and therefore always a subset of the XCR0 it is restored under.
// `live & want` is itself always a legal XCR0 -- every dependency this validator
// enforces is all-or-nothing in both operands, so an intersection cannot split a
// pair -- which is why it can be installed on its own.
//
void Vcpu::ReconcileGuestXcr0() {
  if (!x86_xsave_supported()) {
    return;
  }
  const uint64_t want = vmx_state_.guest_state.xcr0;
  const uint64_t live = xstate_buffer_xcr0_;
  if (live == want) {
    // The overwhelmingly common path: the guest has not executed XSETBV since its
    // state was loaded.
    return;
  }

  const uint64_t common = live & want;
  if (common != live) {
    // Components leaving. Nothing moves: they simply stop being selected, and the
    // guest cannot see them any more. Their stale contents stay in the physical
    // registers, which is harmless precisely because the next re-enable goes
    // through the branch below and initializes them.
    x86_xsetbv(0, common);
  }
  if (common != want) {
    // Components arriving.
    x86_extended_register_save_state(extended_register_state_);

    // MXCSR is the one field of the legacy area whose presence depends on the
    // component mask, and the only one either instruction can fault on. XSAVE
    // writes it when the live XCR0 selects SSE or AVX; XRSTOR loads it under the
    // same condition. Enabling SSE from an XCR0 that had neither is therefore the
    // single case where the restore below would load four bytes the save above did
    // not write -- bytes that, after a snapshot restore, are exactly the ones
    // ValidateXsaveImageRules declined to check, because under that XCR0 no
    // instruction could reach them.
    //
    // 0x1F80 is the architectural power-on value (all six exception masks set,
    // everything else clear) and is legal under every MXCSR_MASK, so this needs
    // neither validation nor a read of the live register. It is also the right
    // answer for the guest: it has just enabled SSE, and a freshly enabled
    // component's state is defined to be the initial one.
    constexpr uint64_t kMxcsrIsLive = X86_XSAVE_STATE_BIT_SSE | X86_XSAVE_STATE_BIT_AVX;
    constexpr size_t kMxcsrOffset = 24;
    constexpr uint32_t kMxcsrInitialValue = 0x1f80;
    if ((want & kMxcsrIsLive) != 0 && (common & kMxcsrIsLive) == 0) {
      memcpy(extended_register_state_ + kMxcsrOffset, &kMxcsrInitialValue,
             sizeof(kMxcsrInitialValue));
    }

    // Cannot fault: every path that writes guest_state.xcr0 -- handle_xsetbv and
    // Vcpu::RestoreArchState -- put the value through ValidateGuestXcr0() first,
    // which applies the host XSETBV's own #GP conditions plus the bound on this
    // kernel's fixed 1 KiB buffers.
    x86_xsetbv(0, want);
    x86_extended_register_restore_state(extended_register_state_);
  }
  xstate_buffer_xcr0_ = want;
}

void Vcpu::SwapExtendedRegistersOut() {
  if (!xstate_loaded_.load()) {
    return;
  }
  // If the flag is set, this VCPU's thread is the one being descheduled, so the
  // physical XCR0 and register file are this guest's and `Thread::Current` is
  // the thread whose buffer holds the host state to put back. Were this the
  // *incoming* thread the flag would be clear (it is cleared right here, on the
  // way out), and we would otherwise be about to save the outgoing thread's
  // registers into the wrong buffer.
  DEBUG_ASSERT(ThreadIsOurThread(Thread::Current::Get()));
  SaveExtendedRegisters();
  xstate_loaded_.store(false);
}

zx::result<> vmx_enter(VmxState* vmx_state) {
  // Perform the low-level vmlaunch or vmresume, entering the guest,
  // and returning when the guest exits.
  zx_status_t status = vmx_enter_asm(vmx_state);

  DEBUG_ASSERT(arch_ints_disabled());

  // Reload the task segment in order to restore its limit. VMX always
  // restores it with a limit of 0x67, which excludes the IO bitmap.
  seg_sel_t selector = TSS_SELECTOR(arch_curr_cpu_num());
  x86_clear_tss_busy(selector);
  x86_ltr(selector);

  return zx::make_result(status);
}

void Vcpu::CaptureVectoringEvent(AutoVmcs& vmcs) {
  const uint32_t info = vmcs.Read(VmcsField32::IDT_VECTORING_INFORMATION);
  if ((info & kInterruptInfoValid) == 0) {
    return;
  }
  // A VM-entry failure takes the VM-exit path but never ran the guest, so
  // nothing was in delivery and the field says nothing useful. Volume 3,
  // Section 26.7: bit 31 of the exit reason marks it.
  const uint32_t exit_reason = vmcs.Read(VmcsField32::EXIT_REASON);
  if ((exit_reason & (1u << 31)) != 0) {
    return;
  }
  vectoring_.last_info = info;
  vectoring_.last_exit_reason = exit_reason & 0xffffu;
  vectoring_.last_exit_gpa = vmcs.Read(VmcsField64::GUEST_PHYSICAL_ADDRESS);

  const uint32_t type = info & kInterruptInfoTypeMask;
  // Type 1 is not used, and type 7 ("other event") does not name a guest-visible
  // event at all -- VM entry uses it to request a pending MTF exit, and this
  // field never reports one. Neither is something that was being delivered
  // through the guest IDT, so neither is something to put back.
  if (type == kInterruptTypeReserved || type == kInterruptTypeOtherEvent) {
    return;
  }

  vectoring_event_ = {};
  vectoring_event_.valid = true;
  vectoring_event_.type = type;
  // Bits 7:0 only. Bit 12 (kInterruptInfoNmiUnblocking) is a separate flag, not
  // part of the vector, and must not survive into the entry field.
  vectoring_event_.vector = info & kInterruptInfoVectorMask;
  vectoring_event_.has_error_code = (info & kInterruptInfoDeliverErrorCode) != 0;
  if (vectoring_event_.has_error_code) {
    vectoring_event_.error_code = vmcs.Read(VmcsField32::IDT_VECTORING_ERROR_CODE);
  }
  if (type_needs_instruction_length(type)) {
    vectoring_event_.instruction_length = vmcs.Read(VmcsField32::EXIT_INSTRUCTION_LENGTH);
  }

  // Everything above takes only the three subfields the VM-entry interruption-
  // information field also defines. Bit 12 is deliberately not among them.
  constexpr uint32_t kReinjectable =
      kInterruptInfoVectorMask | kInterruptInfoTypeMask | kInterruptInfoDeliverErrorCode;
  static_assert((kReinjectable & kInterruptInfoNmiUnblocking) == 0,
                "bit 12 is not part of the vector, the type, or the error-code flag");
}

zx::result<> Vcpu::Enter(zx_port_packet_t& packet) {
  Thread* const current_thread = Thread::Current::Get();
  if (!ThreadIsOurThread(current_thread)) {
    return zx::error(ZX_ERR_BAD_STATE);
  }
  if (guest_.MemoryAccessBlocked()) {
    return zx::error(ZX_ERR_BAD_STATE);
  }

  bool extended_registers_loaded = false;
  auto defer = fit::defer([this, &extended_registers_loaded] {
    if (extended_registers_loaded) {
      AutoVmcs vmcs(vmcs_page_.PhysicalAddress());
      // The context-switch callback may already have put the host's XCR0 and
      // extended registers back — every deschedule since the last VM entry does
      // — in which case there is nothing of the guest's left in the CPU to save.
      // Saving unconditionally here would XSAVE the *host's* register file into
      // the guest's buffer and set guest_state.xcr0 to the host's.
      if (xstate_loaded_.load()) {
        SaveExtendedRegisters();
        xstate_loaded_.store(false);
      }
      ContextSwitch(/*include_gs=*/true);
      entered_.store(false);
    }
    // Spectre V2: Ensure that code executed in the VM guest cannot influence
    // indirect branch prediction in the host.
    //
    // TODO(https://fxbug.dev/42108888): We may be able to avoid the IBPB here; the kernel
    // is either built with a retpoline or has Enhanced IBRS enabled. We
    // currently execute an IBPB on context-switch to a new aspace. The IBPB is
    // currently only here to protect hypervisor user threads.
    if (!BootOptions::Get()->x86_disable_spec_mitigations && x86_cpu_has_ibpb()) {
      arch::IssueIbpb(arch::BootCpuidIo{}, hwreg::X86MsrIo{});
    }
  });

  zx::result<> result = zx::ok();
  bool reset_instruction_control_on_return = false;
  do {
    // If the thread was killed or suspended, then we should exit with an error.
    if (zx_status_t status = current_thread->CheckKillOrSuspendSignal(); status != ZX_OK) {
      return zx::error(status);
    }

    if (unlikely(hardware_breakpoint_ != nullptr &&
                 hardware_breakpoint_->pending())) {
      if (guest_.HardwareBreakpointPending()) {
        return zx::error(guest_.IsHardwareBreakpointTrigger(vpid_)
                             ? ZX_ERR_BAD_STATE
                             : ZX_ERR_CANCELED);
      }
      if (!guest_.ClaimHardwareBreakpointStop(vpid_)) {
        return zx::error(ZX_ERR_CANCELED);
      }
      const auto& pending = hardware_breakpoint_->pending_stop();
      memset(&packet, 0, sizeof(packet));
      packet.type = ZX_PKT_TYPE_GUEST_HARDWARE_BREAKPOINT;
      packet.guest_hardware_breakpoint.sequence = pending.sequence;
      packet.guest_hardware_breakpoint.rip = pending.stop.rip;
      packet.guest_hardware_breakpoint.condition_mask =
          pending.stop.condition_mask;
      packet.guest_hardware_breakpoint.vpid = pending.stop.vpid;
      packet.guest_hardware_breakpoint.slot_mask = pending.stop.slot_mask;
      packet.guest_hardware_breakpoint.boundary =
          static_cast<uint8_t>(pending.stop.boundary);
      guest_.QuiesceHardwareBreakpointStop(*this);
      return zx::ok();
    }
    if (unlikely(guest_.HardwareBreakpointPending())) {
      return zx::error(ZX_ERR_CANCELED);
    }

    AutoVmcs vmcs(vmcs_page_.PhysicalAddress());

    // The interrupt priority class of a VMM-requested external interrupt that
    // the guest's task priority is holding back on this entry, or 0 for none.
    // Handed to `local_apic_maybe_interrupt`, which owns the TPR threshold, so
    // that a pending event blocked here re-arms rather than being forgotten.
    uint32_t tpr_wait_class = 0;

    // We check whether a kick was requested before entering the guest so that:
    // 1. When we enter the syscall, we can return immediately without entering
    //    the guest.
    // 2. If we have already exited the guest to handle a packet, it allows us
    //    to return and gives user-space a chance to handle that packet, without
    //    the request to kick interfering with the packet in-flight.
    //
    // We also do this after we have disabled interrupts, so if an interrupt was
    // fired before we disabled interrupts, we have the opportunity to check
    // whether a kick was requested, but the interrupt was lost. If an interrupt
    // is fired after we have disabled interrupts, when we enter the guest we
    // will exit due to the interrupt, and run this check again.
    if (kicked_.exchange(false)) {
      return zx::error(ZX_ERR_CANCELED);
    }

    if (unlikely(pending_exit_observation_valid_)) {
      if (pending_exit_observation_delivered_) {
        // Delivery is one-shot and acknowledgement is explicit. Returning the
        // same record again would make a reconnect indistinguishable from a
        // second boundary; entering the guest would violate the stop.
        return zx::error(ZX_ERR_BAD_STATE);
      }
      // A normal handler can surface work to userspace (for example a memory
      // access) before this stop. The following Enter is the completion
      // boundary, so sample the resume point only now, after userspace has
      // supplied that result and before another VM entry can replay anything.
      pending_exit_observation_.resume_rip = vmcs.Read(VmcsFieldXX::GUEST_RIP);
      memset(&packet, 0, sizeof(packet));
      packet.type = ZX_PKT_TYPE_GUEST_EXIT_OBSERVATION;
      packet.guest_exit_observation = pending_exit_observation_;
      pending_exit_observation_delivered_ = true;
      return zx::ok();
    }

    if (unlikely(pending_instruction_budget_valid_)) {
      if (pending_instruction_budget_delivered_) {
        return zx::error(ZX_ERR_BAD_STATE);
      }
      // A normal exit packet may have needed userspace completion before this
      // one-shot could be reported. Sample the actual paused resume point now,
      // after that completion and before another VM entry.
      pending_instruction_budget_.rip = vmcs.Read(VmcsFieldXX::GUEST_RIP);
      memset(&packet, 0, sizeof(packet));
      packet.type = ZX_PKT_TYPE_GUEST_INSTRUCTION_BUDGET;
      packet.guest_instruction_budget = pending_instruction_budget_;
      pending_instruction_budget_delivered_ = true;
      return zx::ok();
    }

    if (unlikely(intel_pt_ != nullptr)) {
      zx_packet_guest_intel_pt_t trace_packet = {};
      if (intel_pt_->TakePacket(trace_packet)) {
        memset(&packet, 0, sizeof(packet));
        packet.type = ZX_PKT_TYPE_GUEST_INTEL_PT;
        packet.guest_intel_pt = trace_packet;
        return zx::ok();
      }
      if (!intel_pt_->MayEnter()) {
        // Complete-or-fail never wraps onto unread pages. ACK may release a
        // wholly consumed pair and make a later entry eligible.
        return zx::error(ZX_ERR_BAD_STATE);
      }
    }

    if (unlikely(pending_monitor_trap_)) {
      // The stepped instruction already completed (either in hardware, as
      // reported by VM-exit reason bit 28, or through an exit handler). Return
      // the debug boundary without entering the guest again: VM-entry type
      // "other event" would itself wait for another instruction boundary on
      // some nested implementations, which is one instruction too late.
      const uint32_t primary = vmcs.Read(VmcsField32::PROCBASED_CTLS);
      const uint32_t desired = primary & ~kProcbasedCtlsMonitorTrapFlag;
      if (auto clear =
              vmcs.SetControl(VmcsField32::PROCBASED_CTLS,
                              read_msr(X86_MSR_IA32_VMX_TRUE_PROCBASED_CTLS),
                              read_msr(X86_MSR_IA32_VMX_PROCBASED_CTLS), desired, ~desired);
          clear.is_error()) {
        return clear.take_error();
      }
      pending_monitor_trap_ = false;
      monitor_trap_armed_ = false;
      memset(&packet, 0, sizeof(packet));
      packet.type = ZX_PKT_TYPE_GUEST_EXCEPTION;
      packet.guest_exception.vector = X86_INT_DEBUG;
      packet.guest_exception.rip = vmcs.Read(VmcsFieldXX::GUEST_RIP);
      return zx::ok();
    }

    // An event that was already vectoring through the guest IDT when the last
    // VM exit happened goes back first, ahead of anything else waiting.
    //
    // Precedence, and why it is this way round: this event has no queue to fall
    // back to. Its vector was popped out of the interrupt tracker (and the
    // tracker's lower-priority entries cleared) on the entry that injected it,
    // or `pending_event_` was zeroed when it was staged -- the VMCS field the
    // processor recorded it in is the only remaining copy, and it is overwritten
    // by the next exit. A tracker vector or a queued `pending_event_`, by
    // contrast, survives an entry it does not get: deferring one costs a VM
    // entry, dropping this one loses an interrupt. Architecturally it is also
    // the right order -- the processor rolled the guest back to before the
    // event, so from the guest's point of view this is the next thing that must
    // happen, and anything the host queued since logically arrives after it.
    //
    // That precedence holds for the event this entry actually injects. An event
    // the guest cannot take is given a queue instead (below), and from that
    // point it is an ordinary queued vector at ordinary priority.
    if (vectoring_event_.valid) {
      if (vectoring_event_.type == kInterruptTypeNmi) {
        // The aborted delivery may have left blocking-by-NMI set, which would
        // make the re-injected NMI the last one the guest ever sees. Volume 3's
        // VMX programming considerations call this out; clear it, as the
        // delivery that would have ended with an IRET never happened.
        //
        // This has to happen BEFORE the injectability test below, not after the
        // injection as it used to: blocking-by-NMI is the block this very event
        // created, so testing first would defer every re-injected NMI on the
        // strength of its own aborted delivery -- which is the normal case, not
        // an edge case.
        uint32_t interruptibility = vmcs.Read(VmcsField32::GUEST_INTERRUPTIBILITY_STATE);
        vmcs.Write(VmcsField32::GUEST_INTERRUPTIBILITY_STATE,
                   interruptibility & ~kInterruptibilityNmiBlocking);
      }

      // Whether the guest can take it *now*. This event was re-issued
      // unconditionally until it was noticed that the guest state it goes back
      // into is no longer the state it came out of: a VMM can call
      // Vcpu::RestoreArchState between the exit that aborted the delivery and
      // this entry, and now that RFLAGS.IF is genuinely restorable it can come
      // back clear. VM entry refuses that pair -- Volume 3, Section 26.3.1.4,
      // "Checks on Guest RFLAGS": if the VM-entry interruption-information field
      // is valid and its type is external interrupt, RFLAGS.IF must be 1 -- and
      // the refusal is a VM-entry failure (exit reason 0x21) that ends the run,
      // not something the guest or the VMM can act on. The same section's
      // non-register-state checks refuse an external interrupt or an NMI
      // injected over blocking-by-STI or blocking-by-MOV-SS.
      //
      // Exceptions and software interrupts are not blocked by any of this and
      // are re-issued unconditionally, exactly as before.
      bool deliverable = true;
      if (vectoring_event_.type == kInterruptTypeExternalInterrupt) {
        deliverable = can_inject_external_int(vmcs);
      } else if (vectoring_event_.type == kInterruptTypeNmi) {
        deliverable = can_inject_nmi(vmcs);
      }

      if (!deliverable) {
        // NOT a skip. The comment above explains that this event has no queue to
        // fall back to, so dropping it loses an interrupt outright -- which is
        // the very bug re-injection exists to fix. Give it one: put the vector
        // back into the interrupt tracker, which is where an external interrupt
        // waits when it cannot be delivered, and ask for an exit as soon as the
        // guest becomes injectable again. `local_apic_maybe_interrupt` below
        // will find it there on this and every subsequent entry and deliver it
        // the moment the guest can take it.
        //
        // The round trip is exact for both types this reaches. An external
        // interrupt carries no error code and no instruction length, and every
        // path that can inject one (Vcpu::Interrupt and WritePendingEvent) has
        // already refused vectors the tracker cannot re-issue with the same
        // type, so `IssueInterrupt` reproduces this event bit for bit. An NMI is
        // vector 2, which the tracker pops first, by name, for that reason.
        //
        // What it does NOT keep is this event's head-of-line position: once it is
        // in the bitmap it takes ordinary priority, so an NMI, or a higher
        // external vector queued meanwhile, can go first. That is the
        // architectural order for those cases, and the precedence argued for
        // above was only ever a consequence of this event having no queue --
        // which, from here, it does.
        //
        // `Interrupt`, not `Track`: the two differ only in that `Interrupt`
        // signals the tracker's event, and the difference is load-bearing on
        // exactly one path. `InterruptTracker::Wait` -- which is what handle_hlt
        // parks the VCPU in -- blocks on that event *before* it tests Pending(),
        // so a vector deposited without a signal is invisible to a guest that
        // halts immediately afterwards, and the VCPU sleeps to the deadline with
        // the interrupt already in the bitmap. Nothing else re-signals it: the
        // event that queued this vector originally was consumed by the wait that
        // delivered it, and a `pending_event_` NMI never touched the tracker at
        // all.
        //
        // This narrows that hazard; it does not close it. `Event::Signal` is
        // one-deep, so a Vcpu::Kick() whose Cancel() lands between the `kicked_`
        // check above and this line leaves the cancellation stored and discards
        // this ZX_OK signal: the vector sits in the bitmap unsignalled, and a
        // later HLT taken while it is still un-injectable sleeps through it.
        // Neither the kick nor the vector is lost -- `kicked_` is latched
        // separately, and every subsequent entry finds the vector in the tracker
        // -- only the wakeup is. Closing it properly means making
        // InterruptTracker::Wait test Pending() before its first blocking wait,
        // which is a change to shared code with a trade-off of its own (a guest
        // that halts with a permanently un-injectable vector would then spin
        // rather than sleep) and wants a test of its own. The same hazard
        // already exists on local_apic_maybe_interrupt's Track() path.
        const uint32_t vector =
            vectoring_event_.type == kInterruptTypeNmi ? X86_INT_NMI : vectoring_event_.vector;
        // Back out of service as well as back into the tracker, or it blocks
        // itself. Its ISR bit was set when it was first injected; from the
        // tracker it must pass `local_apic_maybe_interrupt`'s priority
        // arbitration again, and that test asks whether the vector's class
        // exceeds the processor priority -- which its own in-service bit would
        // hold at its own class. The vector would be requeued and refused on
        // every entry from then on, with nothing left to clear it: the guest
        // never entered the handler, so it will never EOI. This is the one place
        // an injection is undone, and it is the only place the ISR is cleared
        // other than by an EOI.
        if (vectoring_event_.type == kInterruptTypeExternalInterrupt) {
          guest_isr_clear(local_apic_state_, vector);
          // The injection is being undone, so a grant naming this vector no
          // longer has an in-service bit behind it. Revoke it here to keep
          // "armed => sole in service" total rather than relying on the next
          // admission to re-point it.
          guest_lazy_eoi_revoke_if_vector(local_apic_state_, vector);
        }
        if (result = local_apic_state_.interrupt_tracker.Interrupt(vector); result.is_error()) {
          return result;
        }
        vectoring_event_ = {};
        vectoring_.deferrals++;
        // `arm_nmi_wakeup` for an NMI, which is now woken by NMI-window
        // exiting where the part offers virtual NMIs; interrupt-window exiting
        // for everything else, and as the fallback where it does not.
        if (vector == X86_INT_NMI) {
          arm_nmi_wakeup(&vmcs);
        } else {
          vmcs.InterruptWindowExiting(true);
        }
      } else {
        vmcs.IssueEvent(vectoring_event_.type, vectoring_event_.vector,
                        vectoring_event_.has_error_code, vectoring_event_.error_code);
        vmcs.Write(VmcsField32::ENTRY_INSTRUCTION_LENGTH, vectoring_event_.instruction_length);
        vectoring_event_ = {};
        vectoring_.reinjections++;
        // Whatever we just displaced still needs an entry of its own. Ask for an
        // exit as soon as the guest can take one so it does not sit indefinitely.
        if (pending_event_.type != ZX_VCPU_EVENT_NONE) {
          vmcs.InterruptWindowExiting(true);
        }
      }
    }

    // Is a VMM-queued external interrupt being held back by the guest's own task
    // priority on this entry?
    //
    // Decided HERE, above `local_apic_maybe_interrupt`, and not in the block
    // below that acts on it. That function owns the TPR threshold and is the
    // last thing to touch the VMCS before entry, so a requirement discovered
    // after it has run is a requirement it has already cleared on the way past.
    // Computing it below and assigning to `tpr_wait_class` there compiles, reads
    // correctly, and arms nothing: the store is dead. That was measured, not
    // reasoned about -- with the store dead the guest still got its interrupt,
    // because `Enter` re-examines the queue on every exit and a host timer tick
    // supplies one within milliseconds. What it did not get was an exit *for
    // this reason*, so the interrupt sat in the queue for a tick instead of for
    // the instruction that unblocked it. `LocalApicState::
    // tpr_below_threshold_exits` is the instrument that tells those apart.
    //
    // `can_inject_external_int` is part of the condition rather than left to the
    // block below, because the two blocks are not interchangeable. If RFLAGS.IF
    // is clear then interruptibility, not task priority, is what is holding the
    // event, and interrupt-window exiting is the instrument that will fire; the
    // TPR threshold would not, and claiming it would suppress the window.
    //
    // The comparison is against the *processor* priority, not the task priority
    // alone -- an in-service interrupt blocks a VMM-staged vector exactly as it
    // blocks one from the tracker. But only the task-priority half of that block
    // can be watched for with the TPR threshold, which compares against VTPR and
    // nothing else; a vector held purely by an in-service interrupt is released
    // by the guest's EOI, which *ordinarily* exits by itself -- but a lazy-EOI
    // grant's consumption does not: it is a plain guest-memory write, with no
    // exit at all. Reconciling it is exactly what turns that silent write back
    // into an ISR retirement this kernel can see; see the call immediately
    // below.
    //
    // That reconciliation MUST happen here, before `guest_ppr_class` is read for
    // this decision, not only inside `local_apic_maybe_interrupt` a few lines
    // down. This function's own admission (the interrupt_tracker path) is
    // reconciled correctly by that later call, but `pending_int_blocked_by_
    // priority` below is computed from `local_apic_state_` BEFORE
    // `local_apic_maybe_interrupt` ever runs -- so without this call, a grant
    // the guest already consumed (word 0, ISR bit not yet retired) can still
    // wrongly block a VMM-queued external interrupt on THIS entry, on the
    // strength of an ISR bit that is about to be cleared a few statements too
    // late to matter. That block lands in the "held purely by an in-service
    // interrupt" case two blocks down, which deliberately arms neither
    // interrupt-window exiting nor the TPR threshold -- by design, since an
    // ordinary EOI always exits and re-examines the queue on its own. A lazy
    // one does not, and HLT waits only on `interrupt_tracker`
    // (`vmexit.cc`'s `handle_hlt`), which a pending_event_-only block never
    // touches either: the guest can wedge in HLT forever, waiting on a vector
    // that reconciliation would have released one call later. Calling it here
    // closes that window by making sure it never opens: by the time
    // `pending_int_blocked_by_priority` is computed, this VCPU's ISR already
    // reflects every grant the guest has consumed so far.
    //
    guest_lazy_eoi_reconcile(local_apic_state_);

    const uint32_t pending_int_class = pending_event_.vector >> 4;
    const bool pending_int_blocked_by_priority =
        pending_event_.type == ZX_VCPU_EVENT_EXTERNAL_INTERRUPT &&
        pending_event_.vector >= X86_INT_PLATFORM_BASE &&
        pending_int_class <= guest_ppr_class(local_apic_state_) &&
        can_inject_external_int(vmcs);
    if (pending_int_blocked_by_priority) {
      local_apic_state_.priority_blocked++;
      if (pending_int_class <= guest_tpr_class(local_apic_state_)) {
        tpr_wait_class = pending_int_class;
      } else {
        local_apic_state_.isr_blocked++;
      }
    }

    if (result = local_apic_maybe_interrupt(&vmcs, &local_apic_state_, tpr_wait_class,
                                           guest_.EoiInterest());
        result.is_error()) {
      return result;
    }

    // Apply a VMM-requested event injection (a re-injected guest breakpoint, or
    // a fault an emulator decided the guest earned), unless the LAPIC path
    // already queued an event this entry. The payload was fully validated when
    // it was queued, so the only thing decided here is whether the guest can
    // take it *now*: an exception cannot be blocked, but an external interrupt
    // or an NMI can, in which case it stays queued and we ask to be told when
    // the guest becomes interruptible.
    if (pending_event_.type != ZX_VCPU_EVENT_NONE &&
        (vmcs.Read(VmcsField32::ENTRY_INTERRUPTION_INFORMATION) & kInterruptInfoValid) == 0) {
      bool deliverable = true;
      uint32_t type = kInterruptTypeHardwareException;
      switch (pending_event_.type) {
        case ZX_VCPU_EVENT_EXTERNAL_INTERRUPT:
          type = kInterruptTypeExternalInterrupt;
          deliverable = can_inject_external_int(vmcs);
          // A VMM-requested external interrupt is still an external interrupt,
          // and the guest's processor priority gates it exactly as it gates one
          // that arrived through the interrupt tracker. This path stages the
          // VM-entry interruption-information field directly, which bypasses
          // the APIC entirely, so without this test a VMM could deliver below
          // the guest's IRQL -- or into a running handler of the same class --
          // through the very ABI that exists to let it be precise about what
          // the guest is told.
          //
          // The comparison itself is made above, before the TPR threshold is
          // programmed rather than after; see there for why it cannot be made
          // here.
          deliverable = deliverable && !pending_int_blocked_by_priority;
          break;
        case ZX_VCPU_EVENT_NMI:
          type = kInterruptTypeNmi;
          deliverable = can_inject_nmi(vmcs);
          break;
        case ZX_VCPU_EVENT_SOFTWARE_EXCEPTION:
          type = kInterruptTypeSoftwareException;
          break;
        default:
          DEBUG_ASSERT(pending_event_.type == ZX_VCPU_EVENT_HARDWARE_EXCEPTION);
          break;
      }
      if (!deliverable) {
        // Interrupt-window exiting is the instrument for a guest that is not
        // interruptible; for one that is interruptible but has raised its task
        // priority it is the wrong one, and actively harmful -- RFLAGS.IF is set
        // in that case, so it would exit immediately on this and every
        // subsequent entry. The TPR threshold is the instrument for that, and
        // `local_apic_maybe_interrupt` has already armed it from
        // `tpr_wait_class`. For one blocked by an in-service interrupt it is
        // equally wrong for the same reason, and the guest's EOI is what will
        // end the block; neither instrument is armed in that case.
        if (!pending_int_blocked_by_priority) {
          // A VMM-queued NMI is blocked by NMI blocking, which only
          // NMI-window exiting watches. `arm_nmi_wakeup` uses it where virtual
          // NMIs are enabled and falls back to the interrupt window where they
          // are not.
          if (pending_event_.type == ZX_VCPU_EVENT_NMI) {
            arm_nmi_wakeup(&vmcs);
          } else {
            vmcs.InterruptWindowExiting(true);
          }
        }
      } else {
        if (pending_event_.has_cr2) {
          // CR2 is not a VMCS field: it is swapped around VM entry through
          // VmxState (see vmx.S), so the faulting address for an injected #PF
          // is staged there rather than written to the VMCS.
          vmx_state_.guest_state.cr2 = pending_event_.cr2;
        }
        vmcs.IssueEvent(type, pending_event_.vector, pending_event_.has_error_code,
                        pending_event_.error_code);
        vmcs.Write(VmcsField32::ENTRY_INSTRUCTION_LENGTH, pending_event_.instruction_length);
        // An external interrupt is in service from here until the guest's EOI,
        // whichever ABI staged it. Only external interrupts: an exception or an
        // NMI is not acknowledged with an EOI, so a bit set for one would never
        // be cleared.
        if (type == kInterruptTypeExternalInterrupt) {
          guest_isr_set(local_apic_state_, pending_event_.vector);
          // Same qualification argument as local_apic_maybe_interrupt's own
          // admission site: `deliverable` above already required
          // !pending_int_blocked_by_priority, i.e.
          // pending_int_class > guest_ppr_class(state) at the point that was
          // evaluated, so nothing of this vector's priority or higher was in
          // service when it was admitted.
          guest_lazy_eoi_arm(local_apic_state_, pending_event_.vector, guest_.EoiInterest());
        }
        pending_event_ = {};
      }
    }

    SyncVirtualApicPage(local_apic_state_, vpid_ - 1u);

    // Updates guest system time if the guest subscribed to updates.
    pv_clock_update_system_time(&pv_clock_state_, &guest_.PhysicalAspace(), tsc_offset_);

    if (!extended_registers_loaded) {
      entered_.store(true);
      ContextSwitch(/*include_gs=*/true);
      extended_registers_loaded = true;
    }

    // The guest's XCR0 and extended-register file are installed here, and only
    // here: the last thing before the entry, inside `vmcs`, which has interrupts
    // disabled, preemption disabled and blocking disallowed. That is the whole
    // reason this is a separate, re-run step rather than part of the block
    // above. Exit handlers deliberately give the CPU back — AutoVmcs::
    // Invalidate() from handle_hlt, handle_ept_violation, handle_vmcall,
    // handle_kvm_wrmsr, handle_external_interrupt and Trap::Queue, plus the
    // AutoVmcs destructor at the end of every iteration of this loop and the
    // CheckKillOrSuspendSignal() at the top of it — and each of those is a point
    // at which this thread can be descheduled. When it is, the context-switch
    // callback puts the host's state back and clears `xstate_loaded_`, so the
    // guest's has to be reloaded before the next entry.
    if (!xstate_loaded_.load()) {
      LoadExtendedRegisters();
      xstate_loaded_.store(true);
    }
    ReconcileGuestXcr0();

    if (x86_cpu_should_l1d_flush_on_vmentry()) {
      // L1TF: Flush L1D$ before entering vCPU. If the CPU is affected by MDS,
      // also flush microarchitectural buffers.
      write_msr(X86_MSR_IA32_FLUSH_CMD, 1);
    } else if (x86_cpu_should_md_clear_on_user_return()) {
      // MDS: If the processor is not affected by L1TF but is affected by MDS or
      // TAA, flush microarchitectural buffers.
      mds_buff_overwrite();
    }

    const bool intel_pt_entry = intel_pt_ != nullptr;
    if (unlikely(intel_pt_entry)) {
      DEBUG_ASSERT(!instruction_control_armed_);
      if (auto prepare = intel_pt_->PrepareEntry(vmcs); prepare.is_error()) {
        return prepare.take_error();
      }
    }

    KTRACE_DURATION_BEGIN("kernel:arch", "vcpu");

    const bool hardware_breakpoint_entry =
        hardware_breakpoint_ != nullptr && hardware_breakpoint_->armed();

    // DR0-DR3 and DR6 are the guest's, not the host's.
    //
    // MOV-DR exiting is off on the ordinary path and VMX does NOT context-switch these four
    // address registers or the status register. Only DR7 and IA32_DEBUGCTL are
    // swapped, by the save/load-debug-controls entry and exit controls. So
    // without this the guest and the host SHARE DR0-DR3 and DR6: a guest write
    // clobbers whatever hardware breakpoint the host had armed, and a guest read
    // observes the host's addresses. x64 Windows writes the debug registers on
    // every context switch and reads DR6 in its exception path, so this is not a
    // corner case for the guest this hypervisor exists to run.
    //
    // Unconditional rather than lazy. The lazy form (MOV-DR exiting, swap only
    // once the guest has touched one) is what a mature implementation does, and
    // it is strictly more code on the exit path plus a new exit reason to
    // handle; five register moves each way is the honest starting point and it
    // is correct for every guest rather than for the ones we thought of.
    //
    // DR7 is deliberately NOT touched here -- the VMCS owns it, and writing it
    // in host context would fight the entry/exit controls. Neither is the host's
    // DR7 disturbed, so a host breakpoint stays armed across the entry; what
    // changes is that the guest can no longer move the address it points at.
    //
    // While a host-owned plan is active, the controller overlays only slots
    // the guest has disabled. The guest file stays in the shadows above;
    // physical DR6 starts with no cause bits so an old guest-visible B/BD/BS/BT
    // bit cannot be mistaken for a new stop.
    x86_debug_state_t host_debug_state;
    x86_read_hw_debug_regs(&host_debug_state);
    {
      // DISARM FIRST, and it has to be a separate write. `x86_write_hw_debug_regs`
      // writes DR0-DR3 and then DR7 LAST (registers.cc), so handing it a
      // disabled DR7 in the same call still leaves the host's enable bits active
      // while the guest's addresses are being installed. In that window an armed
      // host breakpoint points wherever the GUEST chose, and the very next thing
      // this code does is touch host memory on the way into VM entry -- so a
      // guest could aim a host #DB at the entry path. Zeroing DR7 up front
      // closes the window; VM entry then loads GUEST_DR7 from the VMCS through
      // the load-debug-controls entry control, so the guest still gets its own.
      //
      // Found by review, not by the test below, which plants host breakpoint
      // ADDRESSES with DR7 untouched and so never had one armed.
      x86_disable_debug_state();
      x86_debug_state_t entry_state = host_debug_state;
      if (unlikely(hardware_breakpoint_entry)) {
        HardwareBreakpointController::GuestState guest = {};
        for (size_t i = 0; i < 4; ++i) {
          guest.address[i] = guest_debug_regs_[i];
        }
        guest.dr6 = guest_dr6_;
        guest.dr7 = guest_dr7_;
        guest.linear_address_width =
            (vmcs.Read(VmcsFieldXX::GUEST_CR4) & kGuestCr4La57) != 0
                ? 57
                : 48;
        const auto physical =
            hardware_breakpoint_->controller().BuildPhysicalState(guest);
        for (size_t i = 0; i < 4; ++i) {
          entry_state.dr[i] = physical.address[i];
        }
        entry_state.dr6 = kDr6Reset;
      } else {
        for (size_t i = 0; i < 4; ++i) {
          entry_state.dr[i] = guest_debug_regs_[i];
        }
        entry_state.dr6 = guest_dr6_;
      }
      entry_state.dr7 = 0;  // stays disarmed until VM entry installs the guest's
      x86_write_hw_debug_regs(&entry_state);
    }

    const bool instruction_counted_entry = instruction_control_armed_;
    X86VcpuPmuContext instruction_pmu_context = {};
    X86VcpuPmuSample instruction_pmu_sample = {};
    uint32_t saved_entry_controls = 0;
    uint32_t saved_exit_controls = 0;
    uint64_t saved_guest_perf_global_ctrl = 0;
    uint64_t saved_host_perf_global_ctrl = 0;
    uint64_t saved_guest_debugctl = 0;
    if (unlikely(instruction_counted_entry)) {
      DEBUG_ASSERT(instruction_counter_reserved_);
      DEBUG_ASSERT(retired_instructions_ < instruction_budget_);
      const uint64_t remaining = instruction_budget_ - retired_instructions_;

      saved_entry_controls = vmcs.Read(VmcsField32::ENTRY_CTLS);
      saved_exit_controls = vmcs.Read(VmcsField32::EXIT_CTLS);
      saved_guest_perf_global_ctrl =
          vmcs.Read(VmcsField64::GUEST_IA32_PERF_GLOBAL_CTRL);
      saved_host_perf_global_ctrl =
          vmcs.Read(VmcsField64::HOST_IA32_PERF_GLOBAL_CTRL);
      saved_guest_debugctl = vmcs.Read(VmcsField64::GUEST_IA32_DEBUGCTL);

      x86_perfmon_prepare_vcpu_counter(remaining, &instruction_pmu_context);
      constexpr uint64_t kFixedCounter0Enable = uint64_t{1} << 32;
      constexpr uint64_t kFreezePerfmonWhileSmm = uint64_t{1} << 14;
      // VM entry is the first point at which fixed counter zero is enabled;
      // VM exit disables it before the first host instruction executes.
      vmcs.Write(VmcsField64::GUEST_IA32_PERF_GLOBAL_CTRL, kFixedCounter0Enable);
      vmcs.Write(VmcsField64::HOST_IA32_PERF_GLOBAL_CTRL,
                 instruction_pmu_context.host_global_ctrl & ~kFixedCounter0Enable);
      vmcs.Write(VmcsField64::GUEST_IA32_DEBUGCTL,
                 saved_guest_debugctl | kFreezePerfmonWhileSmm);
      vmcs.Write(VmcsField32::ENTRY_CTLS,
                 saved_entry_controls | kEntryCtlsLoadIa32PerfGlobalCtrl);
      vmcs.Write(VmcsField32::EXIT_CTLS,
                 saved_exit_controls | kExitCtlsLoadIa32PerfGlobalCtrl);
    }

    // ZX_VCPU_STATE_TLB_FLUSH consumption: the last thing before the hardware
    // VM-entry instruction, so no guest instruction can run on this pCPU
    // without first taking a pending flush. `InvVpid::SINGLE_CONTEXT` targets
    // every TLB entry tagged with this VCPU's VPID (this kernel has no
    // narrower granularity to offer -- see the topic's doc comment on why
    // that is within what TLFS permits) on the CURRENT pCPU; migration to a
    // different one is handled separately, unconditionally, in this VCPU's
    // migrate function (`Thread::MigrateStage::Restore`, above). One
    // predicted-not-taken branch for a guest that never requests a flush.
    //
    // Consumed with a single atomic compare_exchange, BEFORE the INVVPID --
    // not a load, then INVVPID, then a separate store(false). The two-step
    // form has a real erasure window: WriteTlbFlushState runs on another
    // VCPU's thread and is not otherwise serialized against this one (see
    // its own comment), so a request landing after this thread's load but
    // before its store would be silently overwritten back to false by that
    // store, and nothing would ever run its INVVPID.
    //
    // A plain load-check followed by this compare_exchange (rather than an
    // unconditional exchange(false)) is what lets `tlb_flush_state_` also
    // carry `flushes_consumed` coherently (see the field's own comment):
    // WriteTlbFlushState only ever sets bit 0 with `fetch_or`, so the ONLY
    // way `state` (captured by the load) can go stale before the CAS below
    // runs is exactly that -- another request's bit 0 landing in between.
    // On success, pending is cleared and the counter incremented as ONE
    // atomic step, so a concurrent ReadTlbFlushState can never observe the
    // two out of sync. On failure (that concurrent request raced in), `state`
    // is updated to the actual current value by compare_exchange_strong and
    // NOTHING further is done: no retry, no forced clear. This deliberately
    // does NOT try to fold that request into the INVVPID that already ran
    // above -- it covers whatever was true when it ran, not a page-table
    // edit whose corresponding request did not exist yet -- so folding it in
    // would UNDER-flush while over-reporting completion. Leaving the bit set
    // costs at most one entry's delay (picked up, with its own INVVPID, on
    // this VCPU's very next admission attempt, exactly like any freshly
    // arrived request) and undercounts `flushes_consumed` by at most one in
    // this exact race -- a bookkeeping approximation, never a coverage gap.
    //
    // Nor is a request ever starved waiting for that next attempt:
    // WriteTlbFlushState's kick (Vcpu::InterruptCpu, the same mechanism
    // Kick() uses) fires unconditionally on every request, including one
    // that lands while this thread is between the CAS and vmx_enter below --
    // if the target is already off CPU at that instant (which it is,
    // mid-host-code, exactly as when Kick() races a VCPU that has already
    // exited to host code on its own) the IPI is simply not delivered to a
    // running guest, but the bit it set stays regardless of the kick's
    // outcome, so the NEXT local_apic_maybe_interrupt call -- which happens
    // on every loop iteration of Enter(), including one forced by an
    // unrelated exit -- will still see it and consume it then.
    uint64_t tlb_flush_state = tlb_flush_state_.load(ktl::memory_order_acquire);
    if (unlikely((tlb_flush_state & kTlbFlushPendingBit) != 0)) {
      invvpid(InvVpid::SINGLE_CONTEXT, vpid_, 0);
      const uint64_t next =
          (tlb_flush_state & ~kTlbFlushPendingBit) + kTlbFlushConsumedIncrement;
      tlb_flush_state_.compare_exchange_strong(tlb_flush_state, next,
                                               ktl::memory_order_acq_rel,
                                               ktl::memory_order_acquire);
    }

    GUEST_STATS_INC(vm_entries);
    result = vmx_enter(&vmx_state_);
    if (unlikely(intel_pt_entry)) {
      // The hardware VM transition cleared TraceEn before the first host
      // instruction, either through the dedicated control or the ordinary
      // VM-exit MSR-load list. Latch output/status and restore host RTIT state
      // before debug-state restoration or normal exit handling can add
      // unaccounted work.
      intel_pt_->FinishExit(vmcs, result.is_ok());
    }
    if (unlikely(instruction_counted_entry)) {
      instruction_pmu_sample =
          x86_perfmon_finish_vcpu_counter(instruction_pmu_context);
      // The instrumentation is not guest architectural PMU state. Put every
      // displaced VMCS field back before any normal exit handling can inspect
      // or expose it.
      vmcs.Write(VmcsField32::ENTRY_CTLS, saved_entry_controls);
      vmcs.Write(VmcsField32::EXIT_CTLS, saved_exit_controls);
      vmcs.Write(VmcsField64::GUEST_IA32_PERF_GLOBAL_CTRL,
                 saved_guest_perf_global_ctrl);
      vmcs.Write(VmcsField64::HOST_IA32_PERF_GLOBAL_CTRL,
                 saved_host_perf_global_ctrl);
      vmcs.Write(VmcsField64::GUEST_IA32_DEBUGCTL, saved_guest_debugctl);
    }
    GUEST_STATS_INC(vm_exits);

    {
      x86_debug_state_t exit_state;
      x86_read_hw_debug_regs(&exit_state);
      if (likely(!hardware_breakpoint_entry)) {
        for (size_t i = 0; i < 4; i++) {
          guest_debug_regs_[i] = exit_state.dr[i];
        }
        guest_dr6_ = exit_state.dr6;
      }
      // Addresses first, DR7 last -- which is the order that matters here for
      // the same reason it mattered above, in the other direction: the host's
      // enables must not come back while the guest's addresses are still loaded.
      // `x86_write_hw_debug_regs` already writes them in that order.
      x86_write_hw_debug_regs(&host_debug_state);
    }

    if (!BootOptions::Get()->x86_disable_spec_mitigations) {
      // Spectre V2: Ensure that code executed in the VM guest cannot influence
      // return address prediction in the host.
      x86_ras_fill();
    }

    if (result.is_ok()) {
      bool instruction_budget_reached = false;
      if (unlikely(instruction_counted_entry)) {
        if (UINT64_MAX - retired_instructions_ < instruction_pmu_sample.retired) {
          retired_instructions_ = UINT64_MAX;
        } else {
          retired_instructions_ += instruction_pmu_sample.retired;
        }
        instruction_budget_reached =
            instruction_pmu_sample.overflow ||
            retired_instructions_ >= instruction_budget_;
      }
      vmx_state_.resume = true;
      // Before the exit handler, which may invalidate `vmcs` in order to block:
      // the IDT-vectoring information field is meaningful on any exit that can
      // happen mid-delivery -- an EPT violation from the interrupt frame's push
      // is the common one, but an intercepted exception, an EPT
      // misconfiguration, an APIC-access exit or a task switch in the same
      // window carries it too -- so it is read on every exit rather than inside
      // one handler.
      CaptureVectoringEvent(vmcs);
      // Before the exit handler, for the same reason -- handle_ept_violation
      // invalidates the VMCS so that it can block, and the exit qualification bit
      // this reads is one of the two places the processor reports that a faulting
      // IRET already cleared virtual-NMI blocking.
      recover_nmi_blocking(vmcs);
      bool hardware_exit_handled = false;
      zx_status_t hardware_exit_status = ZX_OK;
      if (unlikely(hardware_breakpoint_entry)) {
        const uint32_t reason =
            vmcs.Read(VmcsField32::EXIT_REASON) & 0xffffu;
        if (reason == static_cast<uint32_t>(ExitReason::MOV_DR)) {
          hardware_exit_handled = true;
          hardware_exit_status =
              HandleHardwareBreakpointMovDr(vmcs).status_value();
        } else if (reason ==
                   static_cast<uint32_t>(ExitReason::EXCEPTION_OR_NMI)) {
          // A #DB VM exit reports the architectural DR6 causes in the exit
          // qualification. It does not deliver the exception to the host, so
          // the host's physical DR6 is not a record of the guest event (and a
          // nested hypervisor is specifically required to keep its host debug
          // state separate). Reconstitute the guest-visible reserved bits
          // around the qualification's B0-B3/BD/BS/BT cause bits.
          const uint64_t raw_dr6 =
              kDr6Reset |
              (vmcs.Read(VmcsFieldXX::EXIT_QUALIFICATION) &
               kDr6GuestCauseMask);
          auto handled = HandleHardwareBreakpointDebugExit(
              vmcs, raw_dr6, packet);
          if (handled.is_error()) {
            hardware_exit_handled = true;
            hardware_exit_status = handled.status_value();
          } else if (*handled) {
            hardware_exit_handled = true;
            hardware_exit_status =
                packet.type == ZX_PKT_TYPE_GUEST_HARDWARE_BREAKPOINT
                    ? ZX_ERR_NEXT
                    : ZX_OK;
          }
        }
      }
      auto handle_exit = [&]() -> zx::result<> {
        if (hardware_exit_handled) {
          if (hardware_exit_status == ZX_OK) {
            return zx::ok();
          }
          return zx::error(hardware_exit_status);
        }
        return vmexit_handler(vmcs, vmx_state_.guest_state, local_apic_state_, pv_clock_state_,
                              guest_, guest_.PhysicalAspace(), guest_.Traps(), packet, enlightenment_,
                              vpid_, tsc_offset_, guest_.EoiInterest(), unhandled_msr_log_,
                              unhandled_io_log_, host_nmis_redispatched_);
      };
      const bool monitor_trap_armed = monitor_trap_armed_;
      const bool exit_control_armed = exit_control_armed_;
      if (likely(!monitor_trap_armed && !exit_control_armed &&
                 !instruction_counted_entry)) {
        // The ordinary run path: no control-only VMREADs, counters, PMU MSR
        // reads, allocations, hardware changes, or additional returns. All
        // opt-in facilities collapse to cached-state branches.
        result = handle_exit();
      } else {
        const uint32_t full_exit_reason = vmcs.Read(VmcsField32::EXIT_REASON);
        const uint32_t basic_exit_reason = full_exit_reason & 0xffffu;
        const uint64_t exit_rip = vmcs.Read(VmcsFieldXX::GUEST_RIP);
        // Volume 3, VM-exit reason bit 28: MTF became pending but another exit
        // took priority. Exit reason 37 is the MTF exit itself and needs no
        // deferred debugger packet.
        if (monitor_trap_armed && (full_exit_reason & (1u << 28)) != 0 &&
            basic_exit_reason != static_cast<uint32_t>(ExitReason::MONITOR_TRAP_FLAG)) {
          pending_monitor_trap_ = true;
        }

        result = handle_exit();
        if (monitor_trap_armed) {
          if (basic_exit_reason == static_cast<uint32_t>(ExitReason::MONITOR_TRAP_FLAG)) {
            monitor_trap_armed_ = false;
          } else {
            // An instruction exit is raised before that instruction executes.
            // The exit handler completes it by advancing RIP, or userspace
            // completes a surfaced memory access before its next Enter. MTF
            // cannot observe that emulation in hardware, so turn the completion
            // into the pending debugger boundary ourselves. Bit 28 above handles
            // the complementary hardware-completed case.
            const bool handler_advanced_instruction =
                vmcs.valid() && vmcs.Read(VmcsFieldXX::GUEST_RIP) != exit_rip;
            const bool userspace_will_complete_memory =
                result.status_value() == ZX_ERR_NEXT && packet.type == ZX_PKT_TYPE_GUEST_MEM;
            if (handler_advanced_instruction || userspace_will_complete_memory) {
              pending_monitor_trap_ = true;
            }
          }
        }

        if (exit_control_armed) {
          const zx_status_t status = result.status_value();
          const bool normally_handled =
              (status == ZX_OK || status == ZX_ERR_NEXT || status == ZX_ERR_TIMED_OUT) &&
              !(status == ZX_ERR_NEXT && packet.type == ZX_PKT_TYPE_GUEST_HALT);
          if (normally_handled) {
            if (exit_control_exits_seen_ != UINT64_MAX) {
              exit_control_exits_seen_++;
            }
            const uint32_t word = basic_exit_reason / 64;
            const uint32_t bit = basic_exit_reason % 64;
            const bool reason_match =
                (exit_control_active_flags_ & ZX_VCPU_EXIT_CONTROL_OBSERVE) != 0 && word < 2 &&
                (exit_control_selected_reasons_[word] & (uint64_t{1} << bit)) != 0;
            const bool budget_match =
                (exit_control_active_flags_ & ZX_VCPU_EXIT_CONTROL_BUDGET) != 0 &&
                exit_control_exits_seen_ >= exit_control_budget_;
            if (reason_match || budget_match) {
              const uint64_t resume_rip =
                  vmcs.valid() ? vmcs.Read(VmcsFieldXX::GUEST_RIP) : exit_rip;
              uint32_t flags = 0;
              if (reason_match) {
                flags |= ZX_PKT_GUEST_EXIT_OBSERVATION_REASON;
              }
              if (budget_match) {
                flags |= ZX_PKT_GUEST_EXIT_OBSERVATION_BUDGET;
              }
              pending_exit_observation_ = {};
              pending_exit_observation_.sequence = next_exit_observation_sequence_;
              pending_exit_observation_.exit_rip = exit_rip;
              pending_exit_observation_.resume_rip = resume_rip;
              pending_exit_observation_.exit_reason = basic_exit_reason;
              pending_exit_observation_.flags = flags;
              next_exit_observation_sequence_++;
              if (next_exit_observation_sequence_ == 0) {
                next_exit_observation_sequence_ = 1;
              }
              pending_exit_observation_valid_ = true;
              pending_exit_observation_delivered_ = false;
              exit_control_armed_ = false;
              exit_control_active_flags_ = 0;
              exit_control_selected_reasons_[0] = 0;
              exit_control_selected_reasons_[1] = 0;
              exit_control_budget_ = 0;

              if (status == ZX_OK) {
                // No other userspace work is pending. Deliver this boundary
                // directly; for an existing packet/status, preserve it and
                // deliver before the following VM entry instead.
                memset(&packet, 0, sizeof(packet));
                packet.type = ZX_PKT_TYPE_GUEST_EXIT_OBSERVATION;
                packet.guest_exit_observation = pending_exit_observation_;
                pending_exit_observation_delivered_ = true;
                result = zx::error(ZX_ERR_NEXT);
              }
            }
          }
        }

        if (instruction_counted_entry && instruction_budget_reached) {
          pending_instruction_budget_ = {};
          pending_instruction_budget_.sequence = next_instruction_sequence_;
          pending_instruction_budget_.requested_budget = instruction_budget_;
          pending_instruction_budget_.retired_instructions = retired_instructions_;
          pending_instruction_budget_.rip =
              vmcs.valid() ? vmcs.Read(VmcsFieldXX::GUEST_RIP) : exit_rip;
          next_instruction_sequence_++;
          if (next_instruction_sequence_ == 0) {
            next_instruction_sequence_ = 1;
          }
          pending_instruction_budget_valid_ = true;
          pending_instruction_budget_delivered_ = false;
          instruction_control_armed_ = false;
          instruction_budget_ = 0;

          // Preserve an ordinary packet (or another armed control's packet).
          // Otherwise this typed stop can be delivered immediately.
          if (result.status_value() == ZX_OK) {
            memset(&packet, 0, sizeof(packet));
            packet.type = ZX_PKT_TYPE_GUEST_INSTRUCTION_BUDGET;
            packet.guest_instruction_budget = pending_instruction_budget_;
            pending_instruction_budget_delivered_ = true;
            result = zx::error(ZX_ERR_NEXT);
          }
        }

        if (result.status_value() == ZX_ERR_NEXT &&
            packet.type == ZX_PKT_TYPE_GUEST_HALT) {
          // A terminal guest cannot consume another run-control request. Drop
          // both an active budget and a same-exit pending result. If its PMI is
          // already raised, the PMU layer keeps global ownership only until the
          // interrupt handler acknowledges that vector. Defer the mutex-taking
          // release until AutoVmcs has restored interrupts and blocking.
          reset_instruction_control_on_return = true;
        }
      }
    } else {
      if (unlikely(hardware_breakpoint_entry)) {
        if (auto cleanup = DeactivateHardwareBreakpointControl(vmcs);
            cleanup.is_error()) {
          dprintf(CRITICAL,
                  "hypervisor: failed to clear hardware-breakpoint controls "
                  "after VM-entry failure: %d\n",
                  cleanup.status_value());
        }
        hardware_breakpoint_->Reset();
      }
      ktrace_vcpu_exit(VCPU_FAILURE, vmcs.Read(VmcsFieldXX::GUEST_RIP));
      uint64_t error = vmcs.Read(VmcsField32::INSTRUCTION_ERROR);
      dprintf(INFO, "VCPU enter failed: Instruction error %lu\n", error);
      // The entry never ran the guest, so an external interrupt staged for it
      // was not delivered and is not in service. Take the bit back out.
      //
      // Without this, an entry failure leaves the ISR holding a vector no
      // handler will ever EOI, and every interrupt of that priority class is
      // refused from then on -- for the life of the VCPU, since nothing else
      // clears an ISR bit. The failure is already fatal to this run, but the
      // VCPU object survives it and a VMM may restore state and re-enter, and
      // a deadlocked priority class is a far more confusing symptom than the
      // entry failure that caused it.
      const uint32_t staged = vmcs.Read(VmcsField32::ENTRY_INTERRUPTION_INFORMATION);
      if ((staged & kInterruptInfoValid) != 0 &&
          (staged & kInterruptInfoTypeMask) == kInterruptTypeExternalInterrupt) {
        const uint32_t staged_vector = staged & kInterruptInfoVectorMask;
        guest_isr_clear(local_apic_state_, staged_vector);
        // Same reasoning as the vectoring-event deferral above: the entry
        // failed, so the guest never took this vector and owes it no EOI.
        guest_lazy_eoi_revoke_if_vector(local_apic_state_, staged_vector);
      }
    }
  } while (result.is_ok());
  if (result.status_value() == ZX_ERR_NEXT && packet.type == ZX_PKT_TYPE_GUEST_HALT) {
    // A terminal guest cannot consume a pending pre-access result or another
    // armed range set. Tear it down after AutoVmcs has restored blocking, while
    // preserving the halt packet and status that explain why execution ended.
    zx_vcpu_memory_access_control_t memory_control = {};
    if (auto read = guest_.ReadMemoryAccessControl(memory_control); read.is_ok() &&
        (memory_control.active_flags != 0 || memory_control.pending_sequence != 0)) {
      zx_vcpu_memory_access_control_t disarm = {};
      disarm.magic = ZX_VCPU_MEMORY_ACCESS_CONTROL_MAGIC;
      disarm.version = ZX_VCPU_MEMORY_ACCESS_CONTROL_VERSION;
      disarm.size = sizeof(disarm);
      disarm.ack_sequence = memory_control.pending_sequence;
      if (auto cleanup = guest_.WriteMemoryAccessControl(disarm, *this);
          cleanup.is_error()) {
        dprintf(CRITICAL, "hypervisor: failed to clear terminal memory-access control: %d\n",
                cleanup.status_value());
      }
    }
    if (intel_pt_ != nullptr) {
      // Keep sealed bytes readable for StopTraceSession, but never re-enter a
      // terminal guest. Stop seals any partial active output and releases no
      // cursor storage; RELEASE or VCPU teardown drops the reservation.
      if (auto stop = intel_pt_->Stop(intel_pt_->generation()); stop.is_error()) {
        dprintf(CRITICAL, "hypervisor: failed to stop terminal Intel PT session: %d\n",
                stop.status_value());
      }
    }
    if (hardware_breakpoint_ != nullptr) {
      AutoVmcs cleanup_vmcs(vmcs_page_.PhysicalAddress());
      if (auto cleanup =
              DeactivateHardwareBreakpointControl(cleanup_vmcs);
          cleanup.is_error()) {
        dprintf(CRITICAL,
                "hypervisor: failed to clear terminal hardware-breakpoint "
                "controls: %d\n",
                cleanup.status_value());
      }
      if (guest_.IsHardwareBreakpointTrigger(vpid_)) {
        guest_.ReleaseHardwareBreakpointStop(vpid_);
      }
      hardware_breakpoint_->Reset();
    }
  }
  if (result.status_value() == ZX_ERR_NEXT &&
      packet.type == ZX_PKT_TYPE_GUEST_MEMORY_ACCESS &&
      guest_.IsMemoryAccessTrigger(vpid_)) {
    // The handler runs with interrupts disabled and a current VMCS, neither of
    // which may be held while peer threads are kicked and joined. Establish the
    // guest-wide stopped boundary here, after the loop's AutoVmcs is gone but
    // before the triggering packet can reach userspace.
    guest_.QuiesceMemoryAccessStop(*this);
  }
  if (result.status_value() == ZX_ERR_NEXT &&
      packet.type == ZX_PKT_TYPE_GUEST_HARDWARE_BREAKPOINT &&
      guest_.IsHardwareBreakpointTrigger(vpid_)) {
    guest_.QuiesceHardwareBreakpointStop(*this);
  }
  if (reset_instruction_control_on_return) {
    ResetInstructionControl();
  }
  return result.status_value() == ZX_ERR_NEXT ? zx::ok() : result;
}

void Vcpu::Kick() {
  kicked_.store(true);
  // Cancel any pending or upcoming wait-for-interrupts.
  local_apic_state_.interrupt_tracker.Cancel();
  InterruptCpu();
}

void Vcpu::InterruptCpu() {
  // Enter the global thread list lock, allowing us to see if our thread still exists.
  Guard<SpinLock, IrqSave> guard{&Thread::get_list_lock()};
  if (thread_ != nullptr) {
    // If our thread is still around, grab its lock to prevent our last_cpu_
    // bookkeeping from changing.
    //
    // TODO(johngro): Do we need any of this?  Can we just use the Thread's
    // last_cpu member instead?
    SingleChainLockGuard thread_guard{NoIrqSaveOption, thread_->get_lock(),
                                      CLT_TAG("Vcpu::InterruptCpu")};

    // If the VCPU thread is still running, and we have a valid last_cpu_, send
    // the thread's CPU an IPI.
    if (thread_->state() == THREAD_RUNNING && last_cpu_ != INVALID_CPU) {
      mp_interrupt(mp_ipi_target::MASK, cpu_num_to_mask(last_cpu_));
    }
  }
}

zx::result<> Vcpu::WriteXapicAccess(const zx_vcpu_xapic_access_t& in) {
  if (!ThreadIsOurThread(Thread::Current::Get())) {
    return zx::error(ZX_ERR_BAD_STATE);
  }
  if (local_apic_state_.x2apic_enabled) {
    return zx::error(ZX_ERR_BAD_STATE);
  }

  zx_vcpu_xapic_access_t out = in;
  if (in.action == ZX_VCPU_XAPIC_ACTION_READ) {
    auto value = ReadXapicRegister(local_apic_state_, vpid_ - 1u, in.offset);
    if (value.is_error()) {
      return value.take_error();
    }
    out.value = *value;
    out.result_flags = ZX_VCPU_XAPIC_RESULT_VALUE_VALID;
  } else if (in.action == ZX_VCPU_XAPIC_ACTION_WRITE) {
    zx_port_packet_t packet = {};
    AutoVmcs vmcs(vmcs_page_.PhysicalAddress());
    if (auto result = WriteXapicRegister(vmcs, local_apic_state_, guest_.EoiInterest(), in.offset,
                                         in.value, packet);
        result.is_error()) {
      return result;
    }

    switch (packet.type) {
      case 0:
        break;
      case ZX_PKT_TYPE_GUEST_EOI:
        out.result_kind = ZX_VCPU_XAPIC_RESULT_EOI;
        out.vector = packet.guest_eoi.vector;
        break;
      case ZX_PKT_TYPE_GUEST_VCPU:
        if (packet.guest_vcpu.type == ZX_PKT_GUEST_VCPU_INTERRUPT) {
          out.result_kind = ZX_VCPU_XAPIC_RESULT_INTERRUPT;
          out.vector = packet.guest_vcpu.interrupt.vector;
          out.target = packet.guest_vcpu.interrupt.mask;
        } else if (packet.guest_vcpu.type == ZX_PKT_GUEST_VCPU_STARTUP) {
          out.result_kind = ZX_VCPU_XAPIC_RESULT_STARTUP;
          out.target = packet.guest_vcpu.startup.id;
          out.entry = packet.guest_vcpu.startup.entry;
        } else {
          return zx::error(ZX_ERR_INTERNAL);
        }
        break;
      default:
        return zx::error(ZX_ERR_INTERNAL);
    }
  } else {
    return zx::error(ZX_ERR_INVALID_ARGS);
  }

  xapic_access_result_ = out;
  xapic_access_result_valid_ = true;
  return zx::ok();
}

zx::result<> Vcpu::ReadXapicAccess(zx_vcpu_xapic_access_t& out) {
  if (!ThreadIsOurThread(Thread::Current::Get())) {
    return zx::error(ZX_ERR_BAD_STATE);
  }
  if (!xapic_access_result_valid_) {
    return zx::error(ZX_ERR_BAD_STATE);
  }
  out = xapic_access_result_;
  return zx::ok();
}

zx::result<> Vcpu::WriteLazyEoiState(const zx_vcpu_lazy_eoi_state_t& in) {
  if (!ThreadIsOurThread(Thread::Current::Get())) {
    return zx::error(ZX_ERR_BAD_STATE);
  }
  // Identity first: a caller that does not agree with this kernel about the
  // layout is refused rather than reinterpreted.
  if (in.magic != ZX_VCPU_LAZY_EOI_STATE_MAGIC || in.version != ZX_VCPU_LAZY_EOI_STATE_VERSION ||
      in.size != sizeof(zx_vcpu_lazy_eoi_state_t) || in.reserved != 0 || in.enabled > 1) {
    return zx::error(ZX_ERR_INVALID_ARGS);
  }

  // Give any grant against the OLD mapping one last chance to be reconciled
  // through the ordinary path -- reading the word this kernel itself was
  // still tracking, before that mapping is replaced or released -- rather
  // than unconditionally discarding the bookkeeping.
  //
  // This resolves the case where the guest had ALREADY consumed the grant
  // (word is 0) but this kernel had not yet had an entry to notice: dropping
  // the bookkeeping at that instant, unreconciled, would abandon the ISR bit
  // itself with nothing left able to retire it -- permanently, since the
  // mapping that would have let a later entry observe the 0 is gone. That is
  // precisely the "stuck forever" failure this whole mechanism exists to
  // avoid, and it is reachable exactly here: a live reprogram or restore
  // landing between the guest's memory write and this VCPU's next admission
  // attempt.
  guest_lazy_eoi_reconcile(local_apic_state_);

  // If a grant is STILL outstanding here, the guest had not yet reached its
  // epilogue (word still 1) when the reconcile above ran. This is NOT an
  // attempt to preserve that grant across the write -- the vector it names
  // still takes an ordinary, exit-costing EOI it could otherwise have
  // skipped, per ZX_VCPU_STATE_LAZY_EOI's documented conservative posture --
  // but the grant must be explicitly REVOKED in guest memory before the OLD
  // mapping is dropped or replaced, not merely forgotten by this kernel.
  //
  // Forgetting it here (the original version of this code) left the OLD
  // word at 1 in actual guest RAM, which this kernel no longer tracks but
  // the GUEST still owns and can still read. A real guest's interrupt-
  // dispatch trampoline typically caches the assist page's address once
  // rather than re-reading the enlightenment MSR on every epilogue, so an
  // interrupt that was already in flight when this write landed -- most
  // concretely, a disable (enabled=0) the guest issued for reasons
  // unrelated to that specific in-flight interrupt -- can still reach its
  // epilogue afterward and dereference the SAME physical page through that
  // cached pointer. Finding a stale 1 there, with no way to tell it apart
  // from a live grant, it would skip its own EOI -- and with every piece of
  // this kernel's bookkeeping for it already dropped, nothing would ever
  // retire that vector's ISR bit again.
  //
  // Writing 0 through the OLD mapping, while it is still valid, closes that
  // window: whichever physical page the guest's cached pointer names, by the
  // time this call returns it reads 0, so that epilogue -- whenever it
  // finally runs -- takes the honest, self-accounting EOI path instead.
  if (local_apic_state_.lazy_eoi_armed) {
    uint32_t* old_word = local_apic_state_.lazy_eoi_guest_ptr.as<uint32_t>();
    if (old_word != nullptr) {
      ktl::atomic_ref<uint32_t>(*old_word).store(0, ktl::memory_order_relaxed);
    }
    local_apic_state_.lazy_eoi_armed = false;
  }

  if (in.enabled == 0) {
    // A field only carries meaning under `enabled`; requiring the rest to be
    // zero means a caller that thought it was setting an address is told so,
    // instead of having it silently dropped.
    if (in.assist_gpa != 0) {
      return zx::error(ZX_ERR_INVALID_ARGS);
    }
    // The word this kernel tracked, if any, was already reconciled or
    // revoked above. Drop the mapping (GuestPtr::reset(), via move-assigning
    // a default one) and the vector it named.
    local_apic_state_.lazy_eoi_guest_ptr = hypervisor::GuestPtr();
    local_apic_state_.lazy_eoi_guest_paddr = 0;
    local_apic_state_.lazy_eoi_vector = 0;
    return zx::ok();
  }

  if (in.assist_gpa == 0) {
    return zx::error(ZX_ERR_INVALID_ARGS);
  }

  // NOTE (owner decision, 2026-08): lazy-EOI ships ACTIVE on this no-APIC-v
  // hardware -- the grant is established unconditionally below. An earlier
  // revision gated it off when the VMCS lacks "virtual-interrupt delivery"
  // (kProcbasedCtls2VirtualInterruptDelivery, never set in this tree); that gate
  // is NOT shipped, because disabling lazy-EOI forgoes the exit-reduction the
  // guest expects. The correct software reconcile is what makes it right. The
  // `lazy_eoi_test_force_grant_` knob and the VID constant are retained only as
  // scaffolding / a possible future safety switch; neither changes this path
  // now.
  (void)lazy_eoi_test_force_grant_;

  // The word is accessed through `ktl::atomic_ref<uint32_t>` (see
  // guest_lazy_eoi_arm/reconcile and guest_isr_eoi's cancellation), which
  // requires natural alignment for its atomicity guarantee -- an unaligned
  // access is not just slower, it is not actually atomic on this
  // architecture. `CreateGuestPtr` below independently refuses a GPA whose
  // 4 bytes would straddle two guest pages (ZX_ERR_OUT_OF_RANGE), but that
  // is a mapping-granularity check, not an alignment one: a GPA that is
  // 4-byte-misaligned but still fits within one page would pass it and
  // still be unsafe. Reject it explicitly, here, before either check runs.
  if ((in.assist_gpa % sizeof(uint32_t)) != 0) {
    return zx::error(ZX_ERR_INVALID_ARGS);
  }

  // Remembers nothing else about the OLD mapping: a live reprogram (the guest
  // moved the VP assist page, or the VMM is restoring a snapshot) replaces it
  // wholesale, exactly like ZX_VCPU_STATE_ENLIGHTENMENT.
  auto guest_ptr = guest_.PhysicalAspace().CreateGuestPtr(
      in.assist_gpa, sizeof(uint32_t), "vp-assist-lazy-eoi-guest-mapping");
  if (guest_ptr.is_error()) {
    return guest_ptr.take_error();
  }
  uint32_t* word = guest_ptr->as<uint32_t>();
  if (word == nullptr) {
    return zx::error(ZX_ERR_INVALID_ARGS);
  }

  // Conservative posture, unconditional on live-reprogram or restore alike:
  // arm the word to "no grant outstanding" and drop any vector this kernel
  // might still believe was armed (only possible if the reconcile above left
  // it alone because the guest had not yet consumed it). See
  // ZX_VCPU_STATE_LAZY_EOI's doc comment for why this is the right default
  // rather than an attempt to preserve a not-yet-consumed grant across the
  // write.
  ktl::atomic_ref<uint32_t>(*word).store(0, ktl::memory_order_relaxed);
  local_apic_state_.lazy_eoi_guest_ptr = ktl::move(*guest_ptr);
  local_apic_state_.lazy_eoi_guest_paddr = in.assist_gpa;
  local_apic_state_.lazy_eoi_armed = false;
  local_apic_state_.lazy_eoi_vector = 0;
  return zx::ok();
}

zx::result<> Vcpu::ReadLazyEoiState(zx_vcpu_lazy_eoi_state_t& out) {
  if (!ThreadIsOurThread(Thread::Current::Get())) {
    return zx::error(ZX_ERR_BAD_STATE);
  }
  out = {};
  out.magic = ZX_VCPU_LAZY_EOI_STATE_MAGIC;
  out.version = ZX_VCPU_LAZY_EOI_STATE_VERSION;
  out.size = sizeof(zx_vcpu_lazy_eoi_state_t);
  if (local_apic_state_.lazy_eoi_guest_paddr != 0) {
    out.enabled = 1;
    out.assist_gpa = local_apic_state_.lazy_eoi_guest_paddr;
  }
  return zx::ok();
}

zx::result<> Vcpu::Interrupt(uint32_t vector) {
  // This is the bare, cross-thread ABI for asynchronous device interrupts and
  // guest IPIs. Vectors 21..31 are reserved by the architecture but are still
  // valid ICR vectors, and Windows uses vector 31 for an IPI. In the tracker
  // they therefore mean external interrupts. A VMM injecting the architectural
  // #CP at vector 21 uses the explicitly typed pending-event state instead.
  zx::result<> result = local_apic_state_.interrupt_tracker.Interrupt(vector);
  if (result.is_ok()) {
    InterruptCpu();
  }
  return result;
}

bool Vcpu::InterruptPending(uint32_t vector) {
  return local_apic_state_.interrupt_tracker.Get(vector);
}

zx::result<> Vcpu::WriteTlbFlushState(const zx_vcpu_tlb_flush_state_t& in) {
  // Deliberately NOT gated by ThreadIsOurThread: see ZX_VCPU_STATE_TLB_FLUSH's
  // doc comment. A hypercall handler running on a DIFFERENT VCPU's thread is
  // exactly the intended caller.
  if (in.magic != ZX_VCPU_TLB_FLUSH_STATE_MAGIC || in.version != ZX_VCPU_TLB_FLUSH_STATE_VERSION ||
      in.size != sizeof(zx_vcpu_tlb_flush_state_t)) {
    return zx::error(ZX_ERR_INVALID_ARGS);
  }
  // Both fields are output-only: a write always means "request one flush",
  // and there is nothing else to configure. A caller that thought it was
  // setting one of these is told so, instead of having it silently ignored.
  if (in.pending != 0 || in.flushes_consumed != 0) {
    return zx::error(ZX_ERR_INVALID_ARGS);
  }
  // Idempotent: setting an already-pending bit is a no-op past this
  // fetch_or, and fetch_or touches only bit 0 -- it can never disturb the
  // consumed-count bits the packed word also carries (see the field's own
  // comment for why they share it), no matter how it interleaves with the
  // consuming side's compare_exchange. Release order pairs with the
  // acquire load/CAS at the consumption site, so a flush requested
  // strictly-before this call is visible strictly-before that consumption
  // observes the bit -- not required for correctness here (the request
  // itself carries no data the target reads out of guest memory through
  // this path), but it costs nothing and keeps the pair unsurprising.
  tlb_flush_state_.fetch_or(kTlbFlushPendingBit, ktl::memory_order_release);
  // Force the target out of guest mode, exactly as zx_vcpu_kick() does, so it
  // cannot be mid- or past-VM-entry on the stale mapping when this call
  // returns to the hypercall handler that issued it. See
  // ZX_VCPU_STATE_TLB_FLUSH's doc comment for why this is what makes the
  // "effects observable when the hypercall returns" guarantee hold: this
  // store plus this kick together mean the target's NEXT VM entry -- and
  // every one after, until it consumes the flag -- cannot proceed without
  // first taking the flush.
  InterruptCpu();
  return zx::ok();
}

zx::result<> Vcpu::ReadExitCounters(zx_vcpu_exit_counters_t& out) {
  // Deliberately NOT gated by ThreadIsOurThread: these two counters are written
  // only on this VCPU's own thread (guest_lazy_eoi_reconcile and the real-EOI
  // site), so a cross-thread reader -- the VMM's off-thread heartbeat -- sees at
  // worst a value one increment stale, which is acceptable for diagnostics.
  out = {};
  out.lazy_eoi_completions = local_apic_state_.lazy_eoi_completions;
  out.real_eoi_completions = local_apic_state_.eoi_completions;
  return zx::ok();
}

zx::result<> Vcpu::ReadLapicState(zx_vcpu_lapic_state_t& out) {
  // Diagnostics snapshot, NOT gated by ThreadIsOurThread (a cross-thread read
  // may be a tick stale). All the software-LAPIC state a VMI tool needs to pin
  // an interrupt wedge from outside the box.
  out = {};
  for (uint32_t i = 0; i < 8; i++) {
    out.isr[i] = local_apic_state_.isr[i];
    // The interrupt tracker is this kernel's IRR: vectors requested and not yet
    // accepted. PendingWord takes the base vector of each 32-vector window.
    out.irr[i] = local_apic_state_.interrupt_tracker.PendingWord(i * 32u);
  }
  out.isrv = guest_isrv(local_apic_state_);
  out.ppr = guest_ppr(local_apic_state_);
  out.tpr = guest_tpr_read(local_apic_state_);
  out.lazy_eoi_registered = guest_lazy_eoi_registered(local_apic_state_) ? 1u : 0u;
  out.lazy_eoi_armed = local_apic_state_.lazy_eoi_armed ? 1u : 0u;
  out.lazy_eoi_vector = local_apic_state_.lazy_eoi_vector;
  // The assist word as this kernel sees it in guest memory: 0 = consumed (owed a
  // retire), 1 = not consumed, 0xffffffff = no mapping. This is THE datum that
  // distinguishes a lazy-EOI the guest took but we have not reconciled (0) from
  // an ISR bit the guest will never EOI at all -- e.g. an auto-EOI vector (1).
  //
  // THE WORD READ -- AND ONLY IT -- IS GATED ON BEING THIS VCPU'S OWN THREAD.
  // Everything above is a plain scalar load out of LocalApicState: racy against
  // the VCPU thread, but a torn/stale diagnostic integer is harmless. The word
  // is categorically different, because reading it dereferences
  // `lazy_eoi_guest_ptr`, and the VCPU thread REPLACES that GuestPtr on the
  // guest's schedule -- `WriteLazyEoiState` move-assigns a default one whenever
  // the guest writes HV_X64_MSR_VP_ASSIST_PAGE with the enable bit clear.
  // `GuestPtr::as()` loads `mapping_` more than once (the null test, then
  // `size()`, then `base()`), unlocked, so an off-thread reader can pass the
  // null test with the old pointer and then reload it as null -- a kernel-mode
  // null dereference, i.e. exactly the host-killing fault the empty-GuestPtr
  // fix earlier in this series repaired, re-created from the other side. Worse,
  // it is a data race on an fbl::RefPtr (UB) even when it does not fault, and
  // the guest paces it: a ring-0 loop toggling that MSR while the VMM's
  // heartbeat polls this topic is a guest->host DoS.
  //
  // The null check alone cannot fix this and neither can loading `mapping_`
  // once -- both still race the RefPtr release. Only the owning thread can
  // safely dereference it, so an off-thread caller gets a DISTINCT sentinel
  // that says "not sampled here", never a fabricated 0 or 1 (either of which
  // would read as a real grant state and mislead exactly the wedge diagnosis
  // this topic exists for).
  if (ThreadIsOurThread(Thread::Current::Get())) {
    uint32_t* word = local_apic_state_.lazy_eoi_guest_ptr.as<uint32_t>();
    out.lazy_eoi_assist_word = word == nullptr
                                   ? ZX_VCPU_LAPIC_ASSIST_WORD_UNMAPPED
                                   : ktl::atomic_ref<uint32_t>(*word).load(ktl::memory_order_relaxed);
  } else {
    out.lazy_eoi_assist_word = ZX_VCPU_LAPIC_ASSIST_WORD_OFF_THREAD;
  }
  out.lazy_eoi_completions = local_apic_state_.lazy_eoi_completions;
  out.real_eoi_completions = local_apic_state_.eoi_completions;
  return zx::ok();
}

zx::result<> Vcpu::ReadTlbFlushState(zx_vcpu_tlb_flush_state_t& out) {
  // Deliberately NOT gated by ThreadIsOurThread: see ZX_VCPU_STATE_TLB_FLUSH's
  // doc comment.
  out = {};
  out.magic = ZX_VCPU_TLB_FLUSH_STATE_MAGIC;
  out.version = ZX_VCPU_TLB_FLUSH_STATE_VERSION;
  out.size = sizeof(zx_vcpu_tlb_flush_state_t);
  // ONE atomic load: pending and flushes_consumed come from the same packed
  // word (see its own field comment), so this is always a coherent
  // snapshot -- never pending==0 paired with a flushes_consumed that has
  // not yet counted the very consumption that cleared it.
  const uint64_t state = tlb_flush_state_.load(ktl::memory_order_acquire);
  out.pending = (state & kTlbFlushPendingBit) != 0 ? 1 : 0;
  out.flushes_consumed = state / kTlbFlushConsumedIncrement;
  return zx::ok();
}

uint32_t Vcpu::TaskPriority() const { return guest_tpr_read(local_apic_state_); }

uint64_t Vcpu::TprBelowThresholdExits() const {
  return local_apic_state_.tpr_below_threshold_exits;
}

uint32_t Vcpu::ProcessorPriority() const { return guest_ppr(local_apic_state_); }

uint32_t Vcpu::InServiceVector() const { return guest_isrv(local_apic_state_); }

bool Vcpu::InService(uint32_t vector) const { return guest_isr_get(local_apic_state_, vector); }

uint64_t Vcpu::EoiCompletions() const { return local_apic_state_.eoi_completions; }

uint64_t Vcpu::EoiExits() const { return local_apic_state_.eoi_exits; }

uint64_t Vcpu::PriorityBlocked() const { return local_apic_state_.priority_blocked; }

uint64_t Vcpu::IsrBlocked() const { return local_apic_state_.isr_blocked; }

bool Vcpu::LazyEoiArmed() const { return local_apic_state_.lazy_eoi_armed; }

uint32_t Vcpu::LazyEoiVector() const { return local_apic_state_.lazy_eoi_vector; }

uint64_t Vcpu::LazyEoiCompletions() const { return local_apic_state_.lazy_eoi_completions; }

zx::result<> Vcpu::ReadState(zx_vcpu_state_t& vcpu_state) {
  if (!ThreadIsOurThread(Thread::Current::Get())) {
    return zx::error(ZX_ERR_BAD_STATE);
  }
  register_copy(vcpu_state, vmx_state_.guest_state);
  AutoVmcs vmcs(vmcs_page_.PhysicalAddress());
  vcpu_state.rsp = vmcs.Read(VmcsFieldXX::GUEST_RSP);
  vcpu_state.rflags = vmcs.Read(VmcsFieldXX::GUEST_RFLAGS) & X86_FLAGS_USER;
  return zx::ok();
}

zx::result<> Vcpu::WriteState(const zx_vcpu_state_t& vcpu_state) {
  if (!ThreadIsOurThread(Thread::Current::Get())) {
    return zx::error(ZX_ERR_BAD_STATE);
  }
  register_copy(vmx_state_.guest_state, vcpu_state);
  AutoVmcs vmcs(vmcs_page_.PhysicalAddress());
  vmcs.Write(VmcsFieldXX::GUEST_RSP, vcpu_state.rsp);
  if (vcpu_state.rflags & X86_FLAGS_RESERVED_ONES) {
    const uint64_t rflags = vmcs.Read(VmcsFieldXX::GUEST_RFLAGS);
    const uint64_t user_flags = (rflags & ~X86_FLAGS_USER) | (vcpu_state.rflags & X86_FLAGS_USER);
    vmcs.Write(VmcsFieldXX::GUEST_RFLAGS, user_flags);
  }
  return zx::ok();
}

zx::result<> Vcpu::WriteState(const zx_vcpu_io_t& io_state) {
  if (!ThreadIsOurThread(Thread::Current::Get())) {
    return zx::error(ZX_ERR_BAD_STATE);
  }
  if ((io_state.access_size != 1) && (io_state.access_size != 2) && (io_state.access_size != 4)) {
    return zx::error(ZX_ERR_INVALID_ARGS);
  }
  static_assert(sizeof(vmx_state_.guest_state.rax) >= 4);
  memcpy(&vmx_state_.guest_state.rax, io_state.data, io_state.access_size);
  return zx::ok();
}

zx::result<uint32_t> Vcpu::EntryControls() {
  if (!ThreadIsOurThread(Thread::Current::Get())) {
    return zx::error(ZX_ERR_BAD_STATE);
  }
  AutoVmcs vmcs(vmcs_page_.PhysicalAddress());
  return zx::ok(vmcs.Read(VmcsField32::ENTRY_CTLS));
}

zx::result<uint32_t> Vcpu::PinbasedControls() {
  if (!ThreadIsOurThread(Thread::Current::Get())) {
    return zx::error(ZX_ERR_BAD_STATE);
  }
  AutoVmcs vmcs(vmcs_page_.PhysicalAddress());
  return zx::ok(vmcs.Read(VmcsField32::PINBASED_CTLS));
}

zx::result<> Vcpu::SaveArchState(VcpuArchState& out) {
  if (!ThreadIsOurThread(Thread::Current::Get())) {
    return zx::error(ZX_ERR_BAD_STATE);
  }
  register_copy(out.regs, vmx_state_.guest_state);
  out.cr2 = vmx_state_.guest_state.cr2;
  out.xcr0 = vmx_state_.guest_state.xcr0;

  AutoVmcs vmcs(vmcs_page_.PhysicalAddress());
  out.regs.rsp = vmcs.Read(VmcsFieldXX::GUEST_RSP);
  // Capture every guest-owned RFLAGS bit -- IF above all, see kGuestRflagsMask.
  // Bit 1 is added back so the captured value is a well-formed RFLAGS rather
  // than something only this code can interpret.
  out.regs.rflags =
      (vmcs.Read(VmcsFieldXX::GUEST_RFLAGS) & kGuestRflagsMask) | X86_FLAGS_RESERVED_ONES;
  // The instruction pointer is not part of zx_vcpu_state_t, but restoring a VCPU
  // to a captured point requires it.
  out.rip = vmcs.Read(VmcsFieldXX::GUEST_RIP);

  // Control / mode / debug state.
  out.cr0 = vmcs.Read(VmcsFieldXX::GUEST_CR0);
  out.cr3 = vmcs.Read(VmcsFieldXX::GUEST_CR3);
  out.cr4 = vmcs.Read(VmcsFieldXX::GUEST_CR4);
  out.efer = vmcs.Read(VmcsField64::GUEST_IA32_EFER);
  out.pat = vmcs.Read(VmcsField64::GUEST_IA32_PAT);
  for (size_t i = 0; i < 4; ++i) {
    out.dr[i] = guest_debug_regs_[i];
  }
  out.dr6 = guest_dr6_;
  out.dr7 = hardware_breakpoint_ != nullptr &&
                    (hardware_breakpoint_->armed() ||
                     hardware_breakpoint_->pending())
                ? guest_dr7_
                : vmcs.Read(VmcsFieldXX::GUEST_DR7);
  out.debugctl = vmcs.Read(VmcsField64::GUEST_IA32_DEBUGCTL);
  out.pending_debug_exceptions = vmcs.Read(VmcsFieldXX::GUEST_PENDING_DEBUG_EXCEPTIONS);

  // The guest's task priority (CR8), read from the virtual-APIC page rather than
  // from any hypervisor-side shadow -- there is none, and there cannot be one:
  // the processor writes VTPR on a guest `MOV to CR8` without taking a VM exit,
  // so the page is the only account of it that is not already stale.
  out.tpr = guest_tpr_read(local_apic_state_);

  auto read_segment = [&vmcs](VcpuSegmentState& seg, VmcsField16 selector, VmcsFieldXX base,
                              VmcsField32 limit, VmcsField32 access) {
    seg.selector = vmcs.Read(selector);
    seg.base = vmcs.Read(base);
    seg.limit = vmcs.Read(limit);
    seg.access_rights = vmcs.Read(access);
  };
  read_segment(out.es, VmcsField16::GUEST_ES_SELECTOR, VmcsFieldXX::GUEST_ES_BASE,
               VmcsField32::GUEST_ES_LIMIT, VmcsField32::GUEST_ES_ACCESS_RIGHTS);
  read_segment(out.cs, VmcsField16::GUEST_CS_SELECTOR, VmcsFieldXX::GUEST_CS_BASE,
               VmcsField32::GUEST_CS_LIMIT, VmcsField32::GUEST_CS_ACCESS_RIGHTS);
  read_segment(out.ss, VmcsField16::GUEST_SS_SELECTOR, VmcsFieldXX::GUEST_SS_BASE,
               VmcsField32::GUEST_SS_LIMIT, VmcsField32::GUEST_SS_ACCESS_RIGHTS);
  read_segment(out.ds, VmcsField16::GUEST_DS_SELECTOR, VmcsFieldXX::GUEST_DS_BASE,
               VmcsField32::GUEST_DS_LIMIT, VmcsField32::GUEST_DS_ACCESS_RIGHTS);
  read_segment(out.fs, VmcsField16::GUEST_FS_SELECTOR, VmcsFieldXX::GUEST_FS_BASE,
               VmcsField32::GUEST_FS_LIMIT, VmcsField32::GUEST_FS_ACCESS_RIGHTS);
  read_segment(out.gs, VmcsField16::GUEST_GS_SELECTOR, VmcsFieldXX::GUEST_GS_BASE,
               VmcsField32::GUEST_GS_LIMIT, VmcsField32::GUEST_GS_ACCESS_RIGHTS);
  read_segment(out.tr, VmcsField16::GUEST_TR_SELECTOR, VmcsFieldXX::GUEST_TR_BASE,
               VmcsField32::GUEST_TR_LIMIT, VmcsField32::GUEST_TR_ACCESS_RIGHTS);
  read_segment(out.ldtr, VmcsField16::GUEST_LDTR_SELECTOR, VmcsFieldXX::GUEST_LDTR_BASE,
               VmcsField32::GUEST_LDTR_LIMIT, VmcsField32::GUEST_LDTR_ACCESS_RIGHTS);

  out.gdtr_base = vmcs.Read(VmcsFieldXX::GUEST_GDTR_BASE);
  out.gdtr_limit = vmcs.Read(VmcsField32::GUEST_GDTR_LIMIT);
  out.idtr_base = vmcs.Read(VmcsFieldXX::GUEST_IDTR_BASE);
  out.idtr_limit = vmcs.Read(VmcsField32::GUEST_IDTR_LIMIT);

  out.sysenter_cs = vmcs.Read(VmcsField32::GUEST_IA32_SYSENTER_CS);
  out.sysenter_esp = vmcs.Read(VmcsFieldXX::GUEST_IA32_SYSENTER_ESP);
  out.sysenter_eip = vmcs.Read(VmcsFieldXX::GUEST_IA32_SYSENTER_EIP);
  out.interruptibility_state = vmcs.Read(VmcsField32::GUEST_INTERRUPTIBILITY_STATE);
  out.activity_state = vmcs.Read(VmcsField32::GUEST_ACTIVITY_STATE);

  // Syscall / related MSRs (kept in the VCPU's saved MSR state, not the VMCS).
  out.star = msr_state_.star;
  out.lstar = msr_state_.lstar;
  out.cstar = msr_state_.cstar;
  out.fmask = msr_state_.fmask;
  out.tsc_aux = msr_state_.tsc_aux;
  out.kernel_gs_base = msr_state_.kernel_gs_base;

  // Extended (XSAVE) register area.
  memcpy(out.xsave, extended_register_state_, X86_MAX_EXTENDED_REGISTER_SIZE);

  return zx::ok();
}

zx::result<> Vcpu::RestoreArchState(const VcpuArchState& in) {
  if (!ThreadIsOurThread(Thread::Current::Get())) {
    return zx::error(ZX_ERR_BAD_STATE);
  }
  // XCR0 is checked BEFORE anything is applied, so a refused restore leaves the
  // VCPU exactly as it was rather than half-written.
  //
  // XCR0 is one of three parts of this structure that are not simply guest
  // state. Most fields are written to the VMCS, and a bad value there is the
  // guest's problem (or at worst a VM-entry failure, which is reported). The
  // exceptions are XCR0 (here), the syscall MSRs (below), and the `xsave` image
  // (below) -- each of which is applied to the physical machine in host context,
  // and each of which is therefore checked here, before anything is written.
  //
  // XCR0 is loaded into the *physical* XCR0 by
  // swap_extended_registers() on the way into the guest -- while the host is
  // running -- so an illegal value is a #GP on a kernel instruction, i.e. a
  // machine-wide denial of service from any caller holding a VCPU handle. The
  // gate on it (guest CR4.OSXSAVE) is restored from this same structure, so it
  // is no protection at all.
  //
  // ValidateGuestXcr0() is the same check the guest's own XSETBV goes through;
  // see vmexit.cc.
  if (auto result = ValidateGuestXcr0(in.xcr0); result.is_error()) {
    return result.take_error();
  }

  // The syscall MSRs are the same shape of problem as XCR0: inspect the
  // rest of this structure for it.
  //
  // They are not VMCS fields. ContextSwitch() (above) writes them into the *real*
  // MSRs with a bare `wrmsr` before VM entry and swaps the host's back afterwards,
  // so they too are applied in host context. WRMSR #GPs on a non-canonical write
  // to IA32_LSTAR, IA32_CSTAR, or IA32_KERNEL_GS_BASE, and on a reserved-bit write to
  // IA32_TSC_AUX -- each of which is, again, a kernel fault from a caller holding
  // a VCPU handle.
  //
  // IA32_STAR is only segment selectors and constrains nothing, so it is not
  // checked. IA32_FMASK is left alone deliberately: its upper half is documented
  // as reserved but the SDM does not state that WRMSR faults on it, and refusing a
  // value hardware would accept is its own bug.
  //
  // x86_is_vaddr_canonical() tests against kX86VAddrBits (48). That is the same
  // width the rest of the kernel assumes, and it errs safe on a 5-level-paging
  // machine: an address canonical at 48 bits is canonical at 57 as well, so this
  // can refuse a value the CPU would take but never accept one it would not.
  if (!x86_is_vaddr_canonical(in.lstar) || !x86_is_vaddr_canonical(in.cstar) ||
      !x86_is_vaddr_canonical(in.kernel_gs_base)) {
    return zx::error(ZX_ERR_INVALID_ARGS);
  }
  // IA32_TSC_AUX is a 32-bit register; bits 63:32 are reserved.
  if ((in.tsc_aux >> 32) != 0) {
    return zx::error(ZX_ERR_INVALID_ARGS);
  }

  // The task-priority register is the fourth field of this structure that is not
  // simply written into the VMCS and left to the guest.
  //
  // Ask the standing question -- which instruction does the host execute with
  // this value? The answer is VMLAUNCH/VMRESUME itself. VTPR is not a VMCS
  // field; it is a location in a page whose address is in the VMCS, and the
  // processor reads it as part of VM entry: with "use TPR shadow" set and
  // "virtual-interrupt delivery" clear -- this VMCS's configuration -- entry
  // compares bits 3:0 of the TPR-threshold VM-execution control against bits 7:4
  // of VTPR, and Section 27.6.7 has it raise a TPR-below-threshold exit
  // immediately after any entry that finds VTPR already below the threshold.
  // `local_apic_maybe_interrupt` arms that threshold from the same value on
  // every entry. So a caller-supplied VTPR is consumed by the host's entry
  // instruction, not by guest code.
  //
  // VTPR is 8 bits (Volume 3, Section 30.1.1); bits 31:8 of the 32-bit field are
  // reserved. Refuse a value that sets them rather than masking it: the rule for
  // this ABI is that the caller is told its input was wrong, not silently handed
  // a different register than the one it asked for.
  if ((in.tpr & ~0xffu) != 0) {
    return zx::error(ZX_ERR_INVALID_ARGS);
  }

  // The `xsave` image is the third. It is copied into extended_register_state_
  // at the bottom of this function, and swap_extended_registers() then hands
  // that buffer to the host's XRSTORS / XRSTOR / FXRSTOR -- in host context,
  // with no VM to absorb the fault. A reserved MXCSR bit alone is enough to #GP
  // there; so is an XSTATE_BV or XCOMP_BV the restore instruction rejects, or a
  // nonzero reserved byte in the XSAVE header.
  //
  // Validated against `in.xcr0`, which is the value the same restore installs as
  // the guest's XCR0 and which the check above has just proved legal and no
  // larger than this kernel's 1 KiB buffers. Order matters twice over: the XCR0
  // check has to come first because it is what bounds the components this image
  // may name, and this check has to come before any write because a refused
  // restore must leave the VCPU exactly as it was.
  //
  // ValidateGuestXsaveImage() knows which of the three instructions this host
  // actually issues (x86_extended_register_restore_instruction()) and this
  // part's real MXCSR_MASK (x86_mxcsr_mask()); see vmexit.cc.
  if (auto result = ValidateGuestXsaveImage(in.xsave, in.xcr0); result.is_error()) {
    return result.take_error();
  }

  // EPT-backed access stops describe the machine that is being replaced, not
  // the restored one. Remove them only after all restore input has validated,
  // and before opening this VCPU's VMCS (permission transitions can block and
  // must quiesce peer VCPUs). A pending pre-access record is acknowledged with
  // its exact sequence as part of the same disarm transition.
  zx_vcpu_memory_access_control_t memory_control = {};
  if (auto result = guest_.ReadMemoryAccessControl(memory_control); result.is_error()) {
    return result.take_error();
  }
  if (memory_control.active_flags != 0 || memory_control.pending_sequence != 0) {
    zx_vcpu_memory_access_control_t disarm = {};
    disarm.magic = ZX_VCPU_MEMORY_ACCESS_CONTROL_MAGIC;
    disarm.version = ZX_VCPU_MEMORY_ACCESS_CONTROL_VERSION;
    disarm.size = sizeof(disarm);
    disarm.ack_sequence = memory_control.pending_sequence;
    if (auto result = guest_.WriteMemoryAccessControl(disarm, *this); result.is_error()) {
      return result.take_error();
    }
  }

  // A successful whole-state replacement also replaces host run controls. Do
  // this only after every input field has validated so a rejected restore is
  // completely atomic. A pending overflow interrupt keeps global PMU ownership
  // only until its handler acknowledges it; the restored VCPU remains paused.
  ResetInstructionControl();
  // Processor trace output belongs to the execution timeline being replaced.
  // Drop its pinned pages and exclusive PMI reservation before installing the
  // restored registers. The worker invalidates the old trace generation and
  // keeps the restored VM paused while clients reconnect.
  ResetIntelPtControl();
  if (guest_.IsHardwareBreakpointTrigger(vpid_)) {
    guest_.ReleaseHardwareBreakpointStop(vpid_);
  }

  register_copy(vmx_state_.guest_state, in.regs);
  vmx_state_.guest_state.cr2 = in.cr2;
  vmx_state_.guest_state.xcr0 = in.xcr0;
  // The image copied in below was validated against exactly this XCR0, so it is
  // also the XCR0 the buffer is "in". See xstate_buffer_xcr0_.
  xstate_buffer_xcr0_ = in.xcr0;

  // Keep the retired session alive until after AutoVmcs restores normal
  // blocking. Destroying its heap allocation while a VMCS is current trips the
  // allocator's arch_blocking_disallowed() invariant. This ownership holder is
  // deliberately declared before |vmcs| so C++ destroys |vmcs| first on every
  // return path below.
  ktl::unique_ptr<HardwareBreakpointSession> retired_hardware_breakpoint;
  AutoVmcs vmcs(vmcs_page_.PhysicalAddress());
  if (hardware_breakpoint_ != nullptr) {
    if (auto result = DeactivateHardwareBreakpointControl(vmcs);
        result.is_error()) {
      return result.take_error();
    }
    retired_hardware_breakpoint = ktl::move(hardware_breakpoint_);
  }

  // VM_ENTRY_IA32E_MODE is host control state, so it is deliberately not part
  // of VcpuArchState. It is nevertheless coupled to architectural guest state:
  // when IA32_EFER is loaded on entry, Volume 3 requires this control to agree
  // with GUEST_IA32_EFER.LMA. A freshly-created AP starts in real mode with the
  // control clear, while a snapshot commonly restores that AP in long mode.
  // Leaving the creation-time value in place makes the first entry after
  // restore fail with "invalid guest state" before the guest executes anything.
  //
  // Preserve the complete live control field and change only its derived mode
  // bit. Passing the capability MSR as the defaults argument would silently
  // drop optional controls already enabled in this VMCS, notably loading the
  // guest PAT and EFER on entry.
  const bool long_mode = (in.efer & X86_EFER_LMA) != 0;
  if (auto result =
          vmcs.SetControl(VmcsField32::ENTRY_CTLS,
                          read_msr(X86_MSR_IA32_VMX_TRUE_ENTRY_CTLS),
                          vmcs.Read(VmcsField32::ENTRY_CTLS),
                          long_mode ? kEntryCtls64bitMode : 0,
                          long_mode ? 0 : kEntryCtls64bitMode);
      result.is_error()) {
    return result.take_error();
  }
  vmcs.Write(VmcsFieldXX::GUEST_RSP, in.regs.rsp);
  // Restore the guest-owned RFLAGS bits (see kGuestRflagsMask). Everything else
  // is either forced to its architecturally required value or, for VM, kept from
  // the live VMCS -- so no caller-supplied bit pattern can produce an RFLAGS that
  // VM entry would reject.
  const uint64_t live_rflags = vmcs.Read(VmcsFieldXX::GUEST_RFLAGS);
  const uint64_t restored_rflags = (in.regs.rflags & kGuestRflagsMask) |
                                   (live_rflags & X86_FLAGS_VM) | X86_FLAGS_RESERVED_ONES;
  vmcs.Write(VmcsFieldXX::GUEST_RFLAGS, restored_rflags);
  // Restore RIP so the guest resumes exactly where it was captured.
  vmcs.Write(VmcsFieldXX::GUEST_RIP, in.rip);

  vmcs.Write(VmcsFieldXX::GUEST_CR0, in.cr0);
  // PG is in CR0_GUEST_HOST_MASK, so the guest reads it from the read
  // shadow rather than from GUEST_CR0. A restore that moved GUEST_CR0.PG without
  // moving the shadow would leave a VCPU whose paging state and whose reported
  // paging state disagree -- and, worse, a `mov eax, cr0; mov cr0, eax` in the
  // restored guest would then write the shadow's stale PG back as if the guest
  // had asked for it. The other masked bits (ET/NE/NW/CD) are host-owned and
  // deliberately not restored from the guest's view of CR0; PG is the guest's
  // own, so it alone is carried across.
  vmcs.Write(VmcsFieldXX::CR0_READ_SHADOW,
             (vmcs.Read(VmcsFieldXX::CR0_READ_SHADOW) & ~static_cast<uint64_t>(X86_CR0_PG)) |
                 (in.cr0 & X86_CR0_PG));
  vmcs.Write(VmcsFieldXX::GUEST_CR3, in.cr3);
  // CR4.VMXE is ours, not the guest's, and must survive a restore.
  //
  // Setup() sets it in GUEST_CR4 and then puts it in CR4_GUEST_HOST_MASK, so
  // the guest never observes it -- a guest read of CR4 is answered from
  // CR4_READ_SHADOW, where the bit is clear. That means no caller can supply it
  // back to us: `in.cr4` comes from a guest-visible view of CR4, in which VMXE
  // is legitimately absent.
  //
  // Writing `in.cr4` verbatim therefore clears a bit that IA32_VMX_CR4_FIXED0
  // requires to be set in VMX operation, and the next VM entry fails with
  // "VM-entry failure due to invalid guest state" (exit reason 0x21) at the
  // guest's first instruction, naming no field. Re-assert it here, exactly as
  // Setup() does.
  vmcs.Write(VmcsFieldXX::GUEST_CR4, in.cr4 | X86_CR4_VMXE);
  vmcs.Write(VmcsField64::GUEST_IA32_EFER, in.efer);
  vmcs.Write(VmcsField64::GUEST_IA32_PAT, in.pat);
  for (size_t i = 0; i < 4; ++i) {
    guest_debug_regs_[i] = in.dr[i];
  }
  guest_dr6_ = in.dr6;
  guest_dr7_ = in.dr7;
  vmcs.Write(VmcsFieldXX::GUEST_DR7, in.dr7);
  vmcs.Write(VmcsField64::GUEST_IA32_DEBUGCTL, in.debugctl);
  vmcs.Write(VmcsFieldXX::GUEST_PENDING_DEBUG_EXCEPTIONS, in.pending_debug_exceptions);

  auto write_segment = [&vmcs](const VcpuSegmentState& seg, VmcsField16 selector, VmcsFieldXX base,
                               VmcsField32 limit, VmcsField32 access) {
    vmcs.Write(selector, seg.selector);
    vmcs.Write(base, seg.base);
    vmcs.Write(limit, seg.limit);
    vmcs.Write(access, seg.access_rights);
  };
  write_segment(in.es, VmcsField16::GUEST_ES_SELECTOR, VmcsFieldXX::GUEST_ES_BASE,
                VmcsField32::GUEST_ES_LIMIT, VmcsField32::GUEST_ES_ACCESS_RIGHTS);
  write_segment(in.cs, VmcsField16::GUEST_CS_SELECTOR, VmcsFieldXX::GUEST_CS_BASE,
                VmcsField32::GUEST_CS_LIMIT, VmcsField32::GUEST_CS_ACCESS_RIGHTS);
  write_segment(in.ss, VmcsField16::GUEST_SS_SELECTOR, VmcsFieldXX::GUEST_SS_BASE,
                VmcsField32::GUEST_SS_LIMIT, VmcsField32::GUEST_SS_ACCESS_RIGHTS);
  write_segment(in.ds, VmcsField16::GUEST_DS_SELECTOR, VmcsFieldXX::GUEST_DS_BASE,
                VmcsField32::GUEST_DS_LIMIT, VmcsField32::GUEST_DS_ACCESS_RIGHTS);
  write_segment(in.fs, VmcsField16::GUEST_FS_SELECTOR, VmcsFieldXX::GUEST_FS_BASE,
                VmcsField32::GUEST_FS_LIMIT, VmcsField32::GUEST_FS_ACCESS_RIGHTS);
  write_segment(in.gs, VmcsField16::GUEST_GS_SELECTOR, VmcsFieldXX::GUEST_GS_BASE,
                VmcsField32::GUEST_GS_LIMIT, VmcsField32::GUEST_GS_ACCESS_RIGHTS);
  write_segment(in.tr, VmcsField16::GUEST_TR_SELECTOR, VmcsFieldXX::GUEST_TR_BASE,
                VmcsField32::GUEST_TR_LIMIT, VmcsField32::GUEST_TR_ACCESS_RIGHTS);
  write_segment(in.ldtr, VmcsField16::GUEST_LDTR_SELECTOR, VmcsFieldXX::GUEST_LDTR_BASE,
                VmcsField32::GUEST_LDTR_LIMIT, VmcsField32::GUEST_LDTR_ACCESS_RIGHTS);

  vmcs.Write(VmcsFieldXX::GUEST_GDTR_BASE, in.gdtr_base);
  vmcs.Write(VmcsField32::GUEST_GDTR_LIMIT, in.gdtr_limit);
  vmcs.Write(VmcsFieldXX::GUEST_IDTR_BASE, in.idtr_base);
  vmcs.Write(VmcsField32::GUEST_IDTR_LIMIT, in.idtr_limit);

  vmcs.Write(VmcsField32::GUEST_IA32_SYSENTER_CS, in.sysenter_cs);
  vmcs.Write(VmcsFieldXX::GUEST_IA32_SYSENTER_ESP, in.sysenter_esp);
  vmcs.Write(VmcsFieldXX::GUEST_IA32_SYSENTER_EIP, in.sysenter_eip);
  // The interruptibility state is coupled to RFLAGS.IF: Volume 3's checks on
  // guest non-register state require blocking-by-STI to be 0 when IF is 0. Now
  // that IF is genuinely restorable (and reaches here from userspace via
  // zx_vcpu_write_state's whole-state topic), the two can be handed to us
  // inconsistently. Hardware cannot produce that pair -- STI-blocking only
  // exists in the shadow of an STI that set IF -- so clamping loses nothing real
  // and keeps a malformed input from becoming an opaque VM-entry failure.
  uint32_t interruptibility = in.interruptibility_state;
  if ((restored_rflags & X86_FLAGS_IF) == 0) {
    interruptibility &= ~kInterruptibilityStiBlocking;
  }
  vmcs.Write(VmcsField32::GUEST_INTERRUPTIBILITY_STATE, interruptibility);
  vmcs.Write(VmcsField32::GUEST_ACTIVITY_STATE, in.activity_state);

  // Put the guest's task priority back, and drop the TPR threshold that was
  // armed against the value being replaced.
  //
  // The threshold is a wakeup request, not guest state: `local_apic_maybe_
  // interrupt` arms it for the priority class of a vector it is holding back, so
  // that the processor exits the moment VTPR falls below it. Once VTPR has been
  // replaced wholesale that request describes a comparison against a register
  // that no longer exists -- and a threshold left above the restored VTPR makes
  // the very next entry exit immediately, and every entry after it, for a
  // condition nobody is waiting on. Clearing it costs nothing in the other
  // direction: `local_apic_maybe_interrupt` re-derives and re-arms the threshold
  // before every entry, so a vector that still needs a wakeup gets one.
  guest_tpr_write(local_apic_state_, in.tpr);
  set_tpr_threshold(&vmcs, &local_apic_state_, 0);

  msr_state_.star = in.star;
  msr_state_.lstar = in.lstar;
  msr_state_.cstar = in.cstar;
  msr_state_.fmask = in.fmask;
  msr_state_.tsc_aux = in.tsc_aux;
  msr_state_.kernel_gs_base = in.kernel_gs_base;

  // Validated at the top of this function by ValidateGuestXsaveImage(), against
  // the restore instruction this host really issues and against `in.xcr0` --
  // which, because LoadExtendedRegisters/SaveExtendedRegisters swap this buffer
  // under the guest's XCR0 unconditionally, is the XCR0 in force at every
  // XRSTOR and every XSAVE of it from here on.
  memcpy(extended_register_state_, in.xsave, X86_MAX_EXTENDED_REGISTER_SIZE);

  return zx::ok();
}

zx::result<> Vcpu::SetBreakpointTrapping(bool enable) {
  if (!ThreadIsOurThread(Thread::Current::Get())) {
    return zx::error(ZX_ERR_BAD_STATE);
  }
  AutoVmcs vmcs(vmcs_page_.PhysicalAddress());
  uint32_t bitmap = vmcs.Read(VmcsField32::EXCEPTION_BITMAP);
  const uint32_t bp_bit = 1u << X86_INT_BREAKPOINT;
  if (enable) {
    bitmap |= bp_bit;
  } else {
    bitmap &= ~bp_bit;
  }
  vmcs.Write(VmcsField32::EXCEPTION_BITMAP, bitmap);
  return zx::ok();
}

zx::result<> Vcpu::ReadDebugState(zx_vcpu_debug_state_t& out) {
  if (!ThreadIsOurThread(Thread::Current::Get())) {
    return zx::error(ZX_ERR_BAD_STATE);
  }

  // A control is useful for a one-shot only if the active VMX implementation
  // permits both values. The high MSR half says it may be one; a zero in the
  // low half says it may be zero. CPU family/model is deliberately irrelevant:
  // nested VMX can expose a different control set on the same physical CPU.
  const uint64_t controls = read_msr(X86_MSR_IA32_VMX_TRUE_PROCBASED_CTLS);
  const uint32_t must_be_one = static_cast<uint32_t>(controls);
  const uint32_t may_be_one = static_cast<uint32_t>(controls >> 32);

  uint64_t supported = ZX_VCPU_DEBUG_TRAP_SOFTWARE_BREAKPOINT;
  if ((may_be_one & kProcbasedCtlsMonitorTrapFlag) != 0 &&
      (must_be_one & kProcbasedCtlsMonitorTrapFlag) == 0) {
    supported |= ZX_VCPU_DEBUG_SINGLE_STEP;
  }

  AutoVmcs vmcs(vmcs_page_.PhysicalAddress());
  uint64_t active = 0;
  if ((vmcs.Read(VmcsField32::EXCEPTION_BITMAP) & (1u << X86_INT_BREAKPOINT)) != 0) {
    active |= ZX_VCPU_DEBUG_TRAP_SOFTWARE_BREAKPOINT;
  }
  if ((vmcs.Read(VmcsField32::PROCBASED_CTLS) & kProcbasedCtlsMonitorTrapFlag) != 0) {
    active |= ZX_VCPU_DEBUG_SINGLE_STEP;
  }

  out = {};
  out.magic = ZX_VCPU_DEBUG_STATE_MAGIC;
  out.version = ZX_VCPU_DEBUG_STATE_VERSION;
  out.size = sizeof(out);
  out.supported_flags = supported;
  out.active_flags = active;
  return zx::ok();
}

zx::result<> Vcpu::WriteDebugState(const zx_vcpu_debug_state_t& in) {
  if (!ThreadIsOurThread(Thread::Current::Get())) {
    return zx::error(ZX_ERR_BAD_STATE);
  }
  if (in.magic != ZX_VCPU_DEBUG_STATE_MAGIC || in.version != ZX_VCPU_DEBUG_STATE_VERSION ||
      in.size != sizeof(in) || in.reserved != 0 || in.supported_flags != 0 ||
      (in.active_flags & ~ZX_VCPU_DEBUG_ALL_FLAGS) != 0) {
    return zx::error(ZX_ERR_INVALID_ARGS);
  }

  // Validate every requested host-specific control before touching either VMCS
  // field. This preserves all-or-nothing behavior for a request that combines
  // persistent #BP interception with one-shot monitor trapping.
  const uint64_t controls = read_msr(X86_MSR_IA32_VMX_TRUE_PROCBASED_CTLS);
  const uint32_t must_be_one = static_cast<uint32_t>(controls);
  const uint32_t may_be_one = static_cast<uint32_t>(controls >> 32);
  const bool monitor_trap_supported =
      (may_be_one & kProcbasedCtlsMonitorTrapFlag) != 0 &&
      (must_be_one & kProcbasedCtlsMonitorTrapFlag) == 0;
  if ((in.active_flags & ZX_VCPU_DEBUG_SINGLE_STEP) != 0 && !monitor_trap_supported) {
    return zx::error(ZX_ERR_NOT_SUPPORTED);
  }

  AutoVmcs vmcs(vmcs_page_.PhysicalAddress());
  uint32_t primary = vmcs.Read(VmcsField32::PROCBASED_CTLS);
  const bool arm_single_step = (in.active_flags & ZX_VCPU_DEBUG_SINGLE_STEP) != 0;
  const uint32_t desired_primary =
      arm_single_step ? (primary | kProcbasedCtlsMonitorTrapFlag)
                      : (primary & ~kProcbasedCtlsMonitorTrapFlag);
  if (desired_primary != primary) {
    // SetControl validates the requested value against the VMX capability MSRs
    // before its VMWRITE. Passing the complete current field as set/clear masks
    // preserves every unrelated dynamic control exactly.
    if (auto result =
            vmcs.SetControl(VmcsField32::PROCBASED_CTLS, controls,
                            read_msr(X86_MSR_IA32_VMX_PROCBASED_CTLS), desired_primary,
                            ~desired_primary);
        result.is_error()) {
      return result.take_error();
    }
  }
  if (!arm_single_step) {
    pending_monitor_trap_ = false;
  }
  monitor_trap_armed_ = arm_single_step;

  uint32_t bitmap = vmcs.Read(VmcsField32::EXCEPTION_BITMAP);
  const uint32_t bp_bit = 1u << X86_INT_BREAKPOINT;
  if ((in.active_flags & ZX_VCPU_DEBUG_TRAP_SOFTWARE_BREAKPOINT) != 0) {
    bitmap |= bp_bit;
  } else {
    bitmap &= ~bp_bit;
  }
  vmcs.Write(VmcsField32::EXCEPTION_BITMAP, bitmap);
  return zx::ok();
}

zx::result<> Vcpu::ReadRunControl(zx_vcpu_run_control_t& out) {
  if (!ThreadIsOurThread(Thread::Current::Get())) {
    return zx::error(ZX_ERR_BAD_STATE);
  }

  const uint64_t pin_controls = read_msr(X86_MSR_IA32_VMX_TRUE_PINBASED_CTLS);
  const uint32_t pin_must_be_one = static_cast<uint32_t>(pin_controls);
  const uint32_t pin_may_be_one = static_cast<uint32_t>(pin_controls >> 32);
  const uint64_t exit_controls = read_msr(X86_MSR_IA32_VMX_TRUE_EXIT_CTLS);
  const uint32_t exit_must_be_one = static_cast<uint32_t>(exit_controls);
  const uint32_t exit_may_be_one = static_cast<uint32_t>(exit_controls >> 32);
  const bool timer_supported =
      (pin_may_be_one & kPinbasedCtlsPreemptionTimer) != 0 &&
      (pin_must_be_one & kPinbasedCtlsPreemptionTimer) == 0 &&
      (exit_may_be_one & kExitCtlsSaveVmxPreemptionTimer) != 0 &&
      (exit_must_be_one & kExitCtlsSaveVmxPreemptionTimer) == 0;

  AutoVmcs vmcs(vmcs_page_.PhysicalAddress());
  const uint32_t pinbased = vmcs.Read(VmcsField32::PINBASED_CTLS);
  out = {};
  out.magic = ZX_VCPU_RUN_CONTROL_MAGIC;
  out.version = ZX_VCPU_RUN_CONTROL_VERSION;
  out.size = sizeof(out);
  out.supported_flags = timer_supported ? ZX_VCPU_RUN_PREEMPTION_TIMER : 0;
  if ((pinbased & kPinbasedCtlsPreemptionTimer) != 0) {
    out.active_flags = ZX_VCPU_RUN_PREEMPTION_TIMER;
    out.preemption_timer_ticks = vmcs.Read(VmcsField32::VMX_PREEMPTION_TIMER_VALUE);
  }
  out.preemption_timer_rate_shift =
      static_cast<uint8_t>(read_msr(X86_MSR_IA32_VMX_MISC) & 0x1f);
  return zx::ok();
}

zx::result<> Vcpu::WriteRunControl(const zx_vcpu_run_control_t& in) {
  if (!ThreadIsOurThread(Thread::Current::Get())) {
    return zx::error(ZX_ERR_BAD_STATE);
  }
  if (in.magic != ZX_VCPU_RUN_CONTROL_MAGIC || in.version != ZX_VCPU_RUN_CONTROL_VERSION ||
      in.size != sizeof(in) || in.reserved != 0 || in.supported_flags != 0 ||
      (in.active_flags & ~ZX_VCPU_RUN_ALL_FLAGS) != 0 ||
      in.preemption_timer_rate_shift != 0 || in.reserved2[0] != 0 || in.reserved2[1] != 0 ||
      in.reserved2[2] != 0) {
    return zx::error(ZX_ERR_INVALID_ARGS);
  }

  const bool arm_timer = (in.active_flags & ZX_VCPU_RUN_PREEMPTION_TIMER) != 0;
  if (arm_timer != (in.preemption_timer_ticks != 0)) {
    return zx::error(ZX_ERR_INVALID_ARGS);
  }

  const uint64_t pin_controls = read_msr(X86_MSR_IA32_VMX_TRUE_PINBASED_CTLS);
  const uint32_t pin_must_be_one = static_cast<uint32_t>(pin_controls);
  const uint32_t pin_may_be_one = static_cast<uint32_t>(pin_controls >> 32);
  const uint64_t exit_controls = read_msr(X86_MSR_IA32_VMX_TRUE_EXIT_CTLS);
  const uint32_t exit_must_be_one = static_cast<uint32_t>(exit_controls);
  const uint32_t exit_may_be_one = static_cast<uint32_t>(exit_controls >> 32);
  const bool timer_supported =
      (pin_may_be_one & kPinbasedCtlsPreemptionTimer) != 0 &&
      (pin_must_be_one & kPinbasedCtlsPreemptionTimer) == 0 &&
      (exit_may_be_one & kExitCtlsSaveVmxPreemptionTimer) != 0 &&
      (exit_must_be_one & kExitCtlsSaveVmxPreemptionTimer) == 0;
  if (arm_timer && !timer_supported) {
    return zx::error(ZX_ERR_NOT_SUPPORTED);
  }

  AutoVmcs vmcs(vmcs_page_.PhysicalAddress());
  const uint32_t pinbased = vmcs.Read(VmcsField32::PINBASED_CTLS);
  const uint32_t exit = vmcs.Read(VmcsField32::EXIT_CTLS);
  const uint32_t desired_pinbased =
      arm_timer ? (pinbased | kPinbasedCtlsPreemptionTimer)
                : (pinbased & ~kPinbasedCtlsPreemptionTimer);
  const uint32_t desired_exit =
      arm_timer ? (exit | kExitCtlsSaveVmxPreemptionTimer)
                : (exit & ~kExitCtlsSaveVmxPreemptionTimer);
  if (arm_timer) {
    if (desired_exit != exit) {
      if (auto result =
              vmcs.SetControl(VmcsField32::EXIT_CTLS, exit_controls,
                              read_msr(X86_MSR_IA32_VMX_EXIT_CTLS), desired_exit,
                              ~desired_exit);
          result.is_error()) {
        return result.take_error();
      }
    }
    if (desired_pinbased != pinbased) {
      if (auto result =
              vmcs.SetControl(VmcsField32::PINBASED_CTLS, pin_controls,
                              read_msr(X86_MSR_IA32_VMX_PINBASED_CTLS), desired_pinbased,
                              ~desired_pinbased);
          result.is_error()) {
        vmcs.Write(VmcsField32::EXIT_CTLS, exit);
        return result.take_error();
      }
    }
  } else {
    if (desired_pinbased != pinbased) {
      if (auto result =
              vmcs.SetControl(VmcsField32::PINBASED_CTLS, pin_controls,
                              read_msr(X86_MSR_IA32_VMX_PINBASED_CTLS), desired_pinbased,
                              ~desired_pinbased);
          result.is_error()) {
        return result.take_error();
      }
    }
    if (desired_exit != exit) {
      if (auto result =
              vmcs.SetControl(VmcsField32::EXIT_CTLS, exit_controls,
                              read_msr(X86_MSR_IA32_VMX_EXIT_CTLS), desired_exit,
                              ~desired_exit);
          result.is_error()) {
        vmcs.Write(VmcsField32::PINBASED_CTLS, pinbased);
        return result.take_error();
      }
    }
  }
  // The control cannot affect execution until the next VM entry, which
  // occurs only after this thread leaves the state syscall. Writing the count
  // after both controls also leaves the old timer intact if either control
  // change is unexpectedly rejected.
  vmcs.Write(VmcsField32::VMX_PREEMPTION_TIMER_VALUE,
             arm_timer ? in.preemption_timer_ticks : 0);
  return zx::ok();
}

zx::result<> Vcpu::ReadExitControl(zx_vcpu_exit_control_t& out) {
  if (!ThreadIsOurThread(Thread::Current::Get())) {
    return zx::error(ZX_ERR_BAD_STATE);
  }

  out = {};
  out.magic = ZX_VCPU_EXIT_CONTROL_MAGIC;
  out.version = ZX_VCPU_EXIT_CONTROL_VERSION;
  out.size = sizeof(out);
  out.supported_flags = ZX_VCPU_EXIT_CONTROL_ALL_FLAGS;
  out.active_flags = exit_control_active_flags_;
  out.supported_reasons[0] = kObservableExitReasons0;
  out.supported_reasons[1] = kObservableExitReasons1;
  out.selected_reasons[0] = exit_control_selected_reasons_[0];
  out.selected_reasons[1] = exit_control_selected_reasons_[1];
  out.exit_budget = exit_control_budget_;
  out.exits_seen = exit_control_exits_seen_;
  if (pending_exit_observation_valid_) {
    out.pending_sequence = pending_exit_observation_.sequence;
    out.pending_exit_reason = pending_exit_observation_.exit_reason;
    out.pending_flags = pending_exit_observation_.flags;
    out.pending_exit_rip = pending_exit_observation_.exit_rip;
    out.pending_resume_rip = pending_exit_observation_.resume_rip;
  }
  return zx::ok();
}

zx::result<> Vcpu::WriteExitControl(const zx_vcpu_exit_control_t& in) {
  if (!ThreadIsOurThread(Thread::Current::Get())) {
    return zx::error(ZX_ERR_BAD_STATE);
  }
  if (in.magic != ZX_VCPU_EXIT_CONTROL_MAGIC || in.version != ZX_VCPU_EXIT_CONTROL_VERSION ||
      in.size != sizeof(in) || in.reserved != 0 || in.supported_flags != 0 ||
      in.supported_reasons[0] != 0 || in.supported_reasons[1] != 0 ||
      (in.active_flags & ~ZX_VCPU_EXIT_CONTROL_ALL_FLAGS) != 0 ||
      in.pending_sequence != 0 || in.exits_seen != 0 || in.pending_exit_reason != 0 ||
      in.pending_flags != 0 || in.pending_exit_rip != 0 || in.pending_resume_rip != 0) {
    return zx::error(ZX_ERR_INVALID_ARGS);
  }

  const bool observe = (in.active_flags & ZX_VCPU_EXIT_CONTROL_OBSERVE) != 0;
  const bool budget = (in.active_flags & ZX_VCPU_EXIT_CONTROL_BUDGET) != 0;
  const bool has_reasons = in.selected_reasons[0] != 0 || in.selected_reasons[1] != 0;
  if (observe != has_reasons || budget != (in.exit_budget != 0)) {
    return zx::error(ZX_ERR_INVALID_ARGS);
  }
  if ((in.selected_reasons[0] & ~kObservableExitReasons0) != 0 ||
      (in.selected_reasons[1] & ~kObservableExitReasons1) != 0) {
    return zx::error(ZX_ERR_NOT_SUPPORTED);
  }

  if (pending_exit_observation_valid_) {
    if (in.ack_sequence != pending_exit_observation_.sequence) {
      return zx::error(ZX_ERR_BAD_STATE);
    }
  } else if (in.ack_sequence != 0) {
    return zx::error(ZX_ERR_NOT_FOUND);
  }

  // Validation above is complete. Acknowledge and re-arm as one atomic state
  // transition, with no allocation and no hardware programming.
  pending_exit_observation_ = {};
  pending_exit_observation_valid_ = false;
  pending_exit_observation_delivered_ = false;
  exit_control_active_flags_ = in.active_flags;
  exit_control_selected_reasons_[0] = in.selected_reasons[0];
  exit_control_selected_reasons_[1] = in.selected_reasons[1];
  exit_control_budget_ = in.exit_budget;
  exit_control_exits_seen_ = 0;
  exit_control_armed_ = in.active_flags != 0;
  return zx::ok();
}

zx::result<> Vcpu::ReadInstructionControl(zx_vcpu_instruction_control_t& out) {
  if (!ThreadIsOurThread(Thread::Current::Get())) {
    return zx::error(ZX_ERR_BAD_STATE);
  }

  out = {};
  out.magic = ZX_VCPU_INSTRUCTION_CONTROL_MAGIC;
  out.version = ZX_VCPU_INSTRUCTION_CONTROL_VERSION;
  out.size = sizeof(out);

  X86VcpuPmuProperties properties = {};
  zx_status_t availability = ZX_ERR_NOT_SUPPORTED;
  if (instruction_counter_vmx_controls_supported()) {
    availability =
        x86_perfmon_vcpu_counter_status(instruction_counter_reserved_, &properties);
  }
  if (availability == ZX_OK || availability == ZX_ERR_SHOULD_WAIT) {
    out.supported_flags = ZX_VCPU_INSTRUCTION_ALL_FLAGS;
    out.counter_width = properties.counter_width;
    out.max_budget = properties.max_budget;
    out.precision = ZX_VCPU_INSTRUCTION_PRECISION_OVERFLOW_INTERRUPT;
    out.availability = availability == ZX_OK ? ZX_VCPU_INSTRUCTION_AVAILABLE
                                             : ZX_VCPU_INSTRUCTION_BUSY;
  } else {
    out.availability = ZX_VCPU_INSTRUCTION_UNSUPPORTED;
  }

  out.active_flags =
      instruction_control_armed_ ? ZX_VCPU_INSTRUCTION_RETIRED_BUDGET : 0;
  out.budget = instruction_budget_;
  out.retired_instructions = retired_instructions_;
  if (pending_instruction_budget_valid_) {
    out.pending_sequence = pending_instruction_budget_.sequence;
    out.retired_instructions = pending_instruction_budget_.retired_instructions;
    out.pending_rip = pending_instruction_budget_.rip;
  }
  return zx::ok();
}

zx::result<> Vcpu::WriteInstructionControl(const zx_vcpu_instruction_control_t& in) {
  if (!ThreadIsOurThread(Thread::Current::Get())) {
    return zx::error(ZX_ERR_BAD_STATE);
  }
  if (in.magic != ZX_VCPU_INSTRUCTION_CONTROL_MAGIC ||
      in.version != ZX_VCPU_INSTRUCTION_CONTROL_VERSION || in.size != sizeof(in) ||
      in.reserved != 0 || in.availability != 0 || in.counter_width != 0 ||
      in.precision != 0 || in.reserved2 != 0 || in.supported_flags != 0 ||
      (in.active_flags & ~ZX_VCPU_INSTRUCTION_ALL_FLAGS) != 0 || in.max_budget != 0 ||
      in.pending_sequence != 0 || in.retired_instructions != 0 || in.pending_rip != 0) {
    return zx::error(ZX_ERR_INVALID_ARGS);
  }

  const bool arm =
      (in.active_flags & ZX_VCPU_INSTRUCTION_RETIRED_BUDGET) != 0;
  if (arm != (in.budget != 0)) {
    return zx::error(ZX_ERR_INVALID_ARGS);
  }
  if (pending_instruction_budget_valid_) {
    if (in.ack_sequence != pending_instruction_budget_.sequence) {
      return zx::error(ZX_ERR_BAD_STATE);
    }
  } else if (in.ack_sequence != 0) {
    return zx::error(ZX_ERR_NOT_FOUND);
  }

  X86VcpuPmuProperties properties = {};
  bool acquired = false;
  if (arm) {
    if (!instruction_counter_vmx_controls_supported()) {
      return zx::error(ZX_ERR_NOT_SUPPORTED);
    }
    zx_status_t status =
        x86_perfmon_vcpu_counter_status(instruction_counter_reserved_, &properties);
    if (status == ZX_ERR_NOT_SUPPORTED) {
      return zx::error(status);
    }
    if (in.budget > properties.max_budget) {
      return zx::error(ZX_ERR_OUT_OF_RANGE);
    }
    if (status != ZX_OK) {
      return zx::error(status);
    }
    if (!instruction_counter_reserved_) {
      status = x86_perfmon_reserve_vcpu_counter(&properties);
      if (status != ZX_OK) {
        return zx::error(status);
      }
      acquired = true;
    }
  }

  // Validation and any required reservation are complete. From here the
  // acknowledgement and next arm are one state transition.
  if (!arm && instruction_counter_reserved_) {
    x86_perfmon_release_vcpu_counter();
    instruction_counter_reserved_ = false;
  } else if (acquired) {
    instruction_counter_reserved_ = true;
  }
  pending_instruction_budget_ = {};
  pending_instruction_budget_valid_ = false;
  pending_instruction_budget_delivered_ = false;
  instruction_control_armed_ = arm;
  instruction_budget_ = arm ? in.budget : 0;
  retired_instructions_ = 0;
  return zx::ok();
}

zx::result<> Vcpu::ReadMemoryAccessControl(zx_vcpu_memory_access_control_t& out) {
  if (!ThreadIsOurThread(Thread::Current::Get())) {
    return zx::error(ZX_ERR_BAD_STATE);
  }
  return guest_.ReadMemoryAccessControl(out);
}

zx::result<> Vcpu::WriteMemoryAccessControl(const zx_vcpu_memory_access_control_t& in) {
  if (!ThreadIsOurThread(Thread::Current::Get())) {
    return zx::error(ZX_ERR_BAD_STATE);
  }
  return guest_.WriteMemoryAccessControl(in, *this);
}

zx::result<> Vcpu::ReadIntelPtControl(zx_vcpu_intel_pt_control_t& out) {
  if (!ThreadIsOurThread(Thread::Current::Get())) {
    return zx::error(ZX_ERR_BAD_STATE);
  }
  if (intel_pt_ != nullptr) {
    return intel_pt_->ReadControl(out);
  }

  X86VcpuPtProperties properties = {};
  const zx_status_t status = x86_perfmon_vcpu_pt_status(false, &properties);
  if (status == ZX_ERR_NOT_SUPPORTED) {
    IntelPtState::ReadCapabilities(out, properties, ZX_VCPU_INTEL_PT_UNSUPPORTED,
                                   ZX_VCPU_INTEL_PT_REASON_NONE);
    return zx::ok();
  }
  if (status != ZX_OK) {
    return zx::error(status);
  }
  if (intel_pt_static_unavailable_reason_ != ZX_VCPU_INTEL_PT_REASON_NONE) {
    IntelPtState::ReadCapabilities(out, properties, ZX_VCPU_INTEL_PT_UNSUPPORTED,
                                   intel_pt_static_unavailable_reason_);
    return zx::ok();
  }
  IntelPtState::ReadCapabilities(out, properties, ZX_VCPU_INTEL_PT_AVAILABLE,
                                 ZX_VCPU_INTEL_PT_REASON_NONE);
  return zx::ok();
}

zx::result<> Vcpu::WriteIntelPtControl(const zx_vcpu_intel_pt_control_t& in) {
  if (!ThreadIsOurThread(Thread::Current::Get())) {
    return zx::error(ZX_ERR_BAD_STATE);
  }
  if (in.magic != ZX_VCPU_INTEL_PT_CONTROL_MAGIC ||
      in.version != ZX_VCPU_INTEL_PT_CONTROL_VERSION || in.size != sizeof(in) ||
      in.action == ZX_VCPU_INTEL_PT_ACTION_NONE ||
      in.action > ZX_VCPU_INTEL_PT_ACTION_RELEASE ||
      !intel_pt_output_fields_are_zero(in)) {
    return zx::error(ZX_ERR_INVALID_ARGS);
  }

  if (in.action == ZX_VCPU_INTEL_PT_ACTION_CONFIGURE) {
    if (intel_pt_ != nullptr || in.trace_generation != 0 ||
        in.acknowledged_cursor != 0 || in.read_cursor != 0 ||
        in.read_max_bytes != 0 || in.reserved1 != 0) {
      return zx::error(ZX_ERR_BAD_STATE);
    }
    X86VcpuPtProperties properties = {};
    zx_status_t status = x86_perfmon_vcpu_pt_status(false, &properties);
    if (status != ZX_OK) {
      return zx::error(status);
    }
    IntelPtSwitchingMode switching_mode =
        IntelPtSwitchingMode::kDedicatedVmxControls;
    if (!intel_pt_vmx_controls_supported()) {
      if (!intel_pt_vmx_operation_supported()) {
        intel_pt_static_unavailable_reason_ =
            ZX_VCPU_INTEL_PT_REASON_VMX_CONTROL_UNAVAILABLE;
        return zx::error(ZX_ERR_NOT_SUPPORTED);
      }
      switching_mode = IntelPtSwitchingMode::kVmxMsrLoadLists;
    }
    status = x86_perfmon_reserve_vcpu_pt(&properties);
    if (status != ZX_OK) {
      if (status == ZX_ERR_NOT_SUPPORTED) {
        intel_pt_static_unavailable_reason_ =
            IntelPtState::PublicUnavailableReason(properties.unavailable_reason);
      }
      return zx::error(status);
    }
    auto state = IntelPtState::Create(in, properties, switching_mode);
    if (state.is_error()) {
      return state.take_error();
    }
    intel_pt_ = ktl::move(state.value());
    intel_pt_static_unavailable_reason_ = ZX_VCPU_INTEL_PT_REASON_NONE;
    return zx::ok();
  }

  if (intel_pt_ == nullptr || in.trace_generation == 0 ||
      !intel_pt_config_fields_are_zero(in)) {
    return zx::error(ZX_ERR_BAD_STATE);
  }
  switch (in.action) {
    case ZX_VCPU_INTEL_PT_ACTION_SELECT_READ:
      if (in.acknowledged_cursor != 0) {
        return zx::error(ZX_ERR_INVALID_ARGS);
      }
      return intel_pt_->SelectRead(in.trace_generation, in.read_cursor, in.read_max_bytes);
    case ZX_VCPU_INTEL_PT_ACTION_ACK:
      if (in.read_cursor != 0 || in.read_max_bytes != 0) {
        return zx::error(ZX_ERR_INVALID_ARGS);
      }
      return intel_pt_->Ack(in.trace_generation, in.acknowledged_cursor);
    case ZX_VCPU_INTEL_PT_ACTION_STOP:
      if (in.acknowledged_cursor != 0 || in.read_cursor != 0 ||
          in.read_max_bytes != 0) {
        return zx::error(ZX_ERR_INVALID_ARGS);
      }
      return intel_pt_->Stop(in.trace_generation);
    case ZX_VCPU_INTEL_PT_ACTION_RELEASE:
      if (in.acknowledged_cursor != 0 || in.read_cursor != 0 ||
          in.read_max_bytes != 0) {
        return zx::error(ZX_ERR_INVALID_ARGS);
      }
      if (in.trace_generation != intel_pt_->generation()) {
        return zx::error(ZX_ERR_NOT_FOUND);
      }
      ResetIntelPtControl();
      return zx::ok();
    default:
      return zx::error(ZX_ERR_INVALID_ARGS);
  }
}

zx::result<> Vcpu::ReadHardwareBreakpointControl(
    zx_vcpu_hardware_breakpoint_control_t& out) {
  if (!ThreadIsOurThread(Thread::Current::Get())) {
    return zx::error(ZX_ERR_BAD_STATE);
  }

  const bool supported = HardwareBreakpointController::RuntimeSupported(
      read_msr(X86_MSR_IA32_VMX_TRUE_PROCBASED_CTLS),
      read_msr(X86_MSR_IA32_VMX_TRUE_ENTRY_CTLS),
      read_msr(X86_MSR_IA32_VMX_TRUE_EXIT_CTLS));
  out = {};
  out.magic = ZX_VCPU_HARDWARE_BREAKPOINT_CONTROL_MAGIC;
  out.version = ZX_VCPU_HARDWARE_BREAKPOINT_CONTROL_VERSION;
  out.size = sizeof(out);
  out.availability = supported ? ZX_VCPU_HARDWARE_BREAKPOINT_AVAILABLE
                               : ZX_VCPU_HARDWARE_BREAKPOINT_UNSUPPORTED;
  out.max_slots = HardwareBreakpointController::kSlotCount;
  out.max_requests = ZX_VCPU_HARDWARE_BREAKPOINT_MAX_REQUESTS;
  out.supported_flags =
      supported ? ZX_VCPU_HARDWARE_BREAKPOINT_ALL_FLAGS : 0;
  if (hardware_breakpoint_ == nullptr) {
    return zx::ok();
  }

  const auto& controller = hardware_breakpoint_->controller();
  if (hardware_breakpoint_->armed()) {
    out.active_flags = ZX_VCPU_HARDWARE_BREAKPOINT_ARM;
  }
  out.request_count = controller.request_count();
  for (uint32_t i = 0; i < out.request_count; ++i) {
    const auto& request = controller.request(i);
    out.requests[i].address = request.address;
    out.requests[i].access =
        static_cast<zx_vcpu_hardware_breakpoint_access_t>(request.access);
    out.requests[i].length =
        static_cast<zx_vcpu_hardware_breakpoint_length_t>(request.length);
    out.requests[i].condition_index = request.condition_index;
  }
  if (hardware_breakpoint_->pending()) {
    const auto& pending = hardware_breakpoint_->pending_stop();
    out.pending_sequence = pending.sequence;
    out.pending_condition_mask = pending.stop.condition_mask;
    out.pending_rip = pending.stop.rip;
    out.pending_raw_dr6 = pending.stop.raw_dr6;
    out.pending_guest_dr6 = pending.stop.guest_dr6;
    out.pending_vpid = pending.stop.vpid;
    out.pending_slot_mask = pending.stop.slot_mask;
    out.pending_boundary = static_cast<uint8_t>(pending.stop.boundary);
  }
  return zx::ok();
}

zx::result<> Vcpu::WriteHardwareBreakpointControl(
    const zx_vcpu_hardware_breakpoint_control_t& in) {
  if (!ThreadIsOurThread(Thread::Current::Get())) {
    return zx::error(ZX_ERR_BAD_STATE);
  }
  if (in.magic != ZX_VCPU_HARDWARE_BREAKPOINT_CONTROL_MAGIC ||
      in.version != ZX_VCPU_HARDWARE_BREAKPOINT_CONTROL_VERSION ||
      in.size != sizeof(in) || in.reserved != 0 || in.availability != 0 ||
      in.max_slots != 0 || in.max_requests != 0 || in.supported_flags != 0 ||
      (in.active_flags & ~ZX_VCPU_HARDWARE_BREAKPOINT_ALL_FLAGS) != 0 ||
      in.reserved2 != 0 ||
      in.request_count > ZX_VCPU_HARDWARE_BREAKPOINT_MAX_REQUESTS ||
      in.pending_sequence != 0 || in.pending_condition_mask != 0 ||
      in.pending_rip != 0 || in.pending_raw_dr6 != 0 ||
      in.pending_guest_dr6 != 0 || in.pending_vpid != 0 ||
      in.pending_slot_mask != 0 || in.pending_boundary != 0 ||
      in.reserved3 != 0) {
    return zx::error(ZX_ERR_INVALID_ARGS);
  }

  const bool arm =
      (in.active_flags & ZX_VCPU_HARDWARE_BREAKPOINT_ARM) != 0;
  if (arm != (in.request_count != 0)) {
    return zx::error(ZX_ERR_INVALID_ARGS);
  }
  HardwareBreakpointController::Request
      requests[ZX_VCPU_HARDWARE_BREAKPOINT_MAX_REQUESTS] = {};
  for (uint32_t i = 0; i < ZX_VCPU_HARDWARE_BREAKPOINT_MAX_REQUESTS; ++i) {
    const auto& source = in.requests[i];
    if (i >= in.request_count) {
      if (source.address != 0 || source.access != 0 || source.length != 0 ||
          source.condition_index != 0 || source.reserved != 0) {
        return zx::error(ZX_ERR_INVALID_ARGS);
      }
      continue;
    }
    if (source.reserved != 0) {
      return zx::error(ZX_ERR_INVALID_ARGS);
    }
    if ((source.access != ZX_VCPU_HARDWARE_BREAKPOINT_EXECUTE &&
         source.access != ZX_VCPU_HARDWARE_BREAKPOINT_WRITE &&
         source.access != ZX_VCPU_HARDWARE_BREAKPOINT_READ_WRITE) ||
        (source.length != ZX_VCPU_HARDWARE_BREAKPOINT_LENGTH_1 &&
         source.length != ZX_VCPU_HARDWARE_BREAKPOINT_LENGTH_2 &&
         source.length != ZX_VCPU_HARDWARE_BREAKPOINT_LENGTH_4 &&
         source.length != ZX_VCPU_HARDWARE_BREAKPOINT_LENGTH_8)) {
      return zx::error(ZX_ERR_INVALID_ARGS);
    }
    requests[i].address = source.address;
    requests[i].access =
        static_cast<HardwareBreakpointController::Access>(source.access);
    requests[i].length =
        static_cast<HardwareBreakpointController::Length>(source.length);
    requests[i].condition_index = source.condition_index;
  }

  if (!HardwareBreakpointController::RuntimeSupported(
          read_msr(X86_MSR_IA32_VMX_TRUE_PROCBASED_CTLS),
          read_msr(X86_MSR_IA32_VMX_TRUE_ENTRY_CTLS),
          read_msr(X86_MSR_IA32_VMX_TRUE_EXIT_CTLS))) {
    return zx::error(ZX_ERR_NOT_SUPPORTED);
  }

  if (!arm && hardware_breakpoint_ == nullptr && in.ack_sequence == 0) {
    return zx::ok();
  }

  if (hardware_breakpoint_ != nullptr && hardware_breakpoint_->pending() &&
      !guest_.IsHardwareBreakpointTrigger(vpid_)) {
    // A second VP's local stop is queued behind the guest-global stop that won
    // the race. It must first be published through Enter, not acknowledged
    // out of order through a state read.
    return zx::error(ZX_ERR_BAD_STATE);
  }

  // Allocate before AutoVmcs marks blocking as disallowed. Everything after
  // the VMCS is loaded must be fixed-storage state validation and register
  // programming only.
  fbl::AllocChecker ac;
  ktl::unique_ptr<HardwareBreakpointSession> replacement(
      new (&ac) HardwareBreakpointSession());
  if (!ac.check()) {
    return zx::error(ZX_ERR_NO_MEMORY);
  }
  if (hardware_breakpoint_ != nullptr) {
    *replacement = *hardware_breakpoint_;
  }

  const bool acknowledging =
      hardware_breakpoint_ != nullptr && hardware_breakpoint_->pending();
  HardwareBreakpointSession::PendingStop acknowledged_stop = {};
  if (acknowledging) {
    acknowledged_stop = hardware_breakpoint_->pending_stop();
    if ((acknowledged_stop.stop.guest_dr6 & kDr6GuestCauseMask) != 0 &&
        pending_event_.type != ZX_VCPU_EVENT_NONE) {
      return zx::error(ZX_ERR_BAD_STATE);
    }
  }

  uint64_t old_guest_dr7 = guest_dr7_;
  ktl::unique_ptr<HardwareBreakpointSession> previous;
  zx::result<> transition = zx::ok();
  {
    AutoVmcs vmcs(vmcs_page_.PhysicalAddress());
    HardwareBreakpointController::GuestState guest = {};
    for (size_t i = 0; i < 4; ++i) {
      guest.address[i] = guest_debug_regs_[i];
    }
    guest.dr6 = guest_dr6_;
    guest.dr7 =
        hardware_breakpoint_ != nullptr ? guest_dr7_ : vmcs.Read(VmcsFieldXX::GUEST_DR7);
    guest.linear_address_width =
        (vmcs.Read(VmcsFieldXX::GUEST_CR4) & kGuestCr4La57) != 0 ? 57 : 48;

    if (auto result = replacement->Replace(
            in.ack_sequence, arm ? requests : nullptr, in.request_count, guest);
        result.is_error()) {
      return result.take_error();
    }

    if (hardware_breakpoint_ == nullptr) {
      guest_dr7_ = guest.dr7;
    }
    previous = ktl::move(hardware_breakpoint_);
    hardware_breakpoint_ = ktl::move(replacement);
    transition =
        hardware_breakpoint_->armed()
            ? ActivateHardwareBreakpointControl(vmcs)
            : DeactivateHardwareBreakpointControl(vmcs);
  }
  if (transition.is_error()) {
    // Restore ownership only after AutoVmcs has restored normal blocking.
    // Assigning the unique_ptr may free the rejected replacement session.
    hardware_breakpoint_ = ktl::move(previous);
    guest_dr7_ = old_guest_dr7;
    return transition.take_error();
  }

  if (acknowledging) {
    guest_.ReleaseHardwareBreakpointStop(vpid_);
    if ((acknowledged_stop.stop.guest_dr6 & kDr6GuestCauseMask) != 0) {
      pending_event_ = {};
      pending_event_.type = ZX_VCPU_EVENT_HARDWARE_EXCEPTION;
      pending_event_.vector = X86_INT_DEBUG;
    }
  }
  return zx::ok();
}

zx::result<> Vcpu::SetTscOffset(int64_t offset) {
  if (!ThreadIsOurThread(Thread::Current::Get())) {
    return zx::error(ZX_ERR_BAD_STATE);
  }
  AutoVmcs vmcs(vmcs_page_.PhysicalAddress());
  // Setup enables the control when the part offers it, so a cleared bit here means
  // this machine does not do TSC offsetting -- report that rather than writing a
  // field the processor will ignore, which would leave `tsc_offset_` claiming an
  // offset the guest's RDTSC does not have. That silent disagreement is the whole
  // failure mode of the version of this the kernel used to have, where the field
  // did not exist at all.
  if ((vmcs.Read(VmcsField32::PROCBASED_CTLS) & kProcbasedCtlsUseTscOffsetting) == 0) {
    return zx::error(ZX_ERR_NOT_SUPPORTED);
  }
  // NOT rebased here: an already-armed IA32_TSC_DEADLINE was translated to a host
  // deadline with the offset in force when the guest wrote it, and changing the
  // offset now leaves that translation behind. Harmless while the only caller is a
  // test that sets the offset before the guest arms anything, and a real hazard the
  // moment a VMM can set it mid-run. Named rather than fixed because the fix
  // (re-deriving local_apic_state.tsc_deadline through the new offset) belongs with
  // the code that makes the offset settable from userspace.
  vmcs.Write(VmcsField64::TSC_OFFSET, static_cast<uint64_t>(offset));
  tsc_offset_ = offset;
  return zx::ok();
}

zx::result<> Vcpu::SetHypervIdentity(bool enable) {
  if (!ThreadIsOurThread(Thread::Current::Get())) {
    return zx::error(ZX_ERR_BAD_STATE);
  }
  // Identity without MSR delegation is a configuration that cannot work.
  // An `Unhandled guest RDMSR 0x40000021` report identifies precisely this
  // state, because the kernel cannot print it in any other. Telling Windows
  // "I am Hv#1" and then #GP-ing the first
  // `WRMSR 0x40000000` -- which is the first thing an enlightened Windows does
  // -- is not a degraded mode, it is a broken one, and nothing in the kernel
  // implements the synthetic registers itself. Refuse the pairing rather than
  // document it.
  if (enable && !enlightenment_.delegate_synthetic_msrs) {
    return zx::error(ZX_ERR_INVALID_ARGS);
  }
  // Touched only on the VCPU's own thread (here and in the Enter exit handler),
  // so it needs no synchronization.
  enlightenment_.hyperv_identity = enable;
  return zx::ok();
}

zx::result<> Vcpu::SetHypervCpuidLeaf(uint32_t leaf, const HypervCpuidLeaf& values) {
  if (!ThreadIsOurThread(Thread::Current::Get())) {
    return zx::error(ZX_ERR_BAD_STATE);
  }
  if (leaf < kHypervSuppliedLeafFirst || leaf > kHypervSuppliedLeafLast) {
    return zx::error(ZX_ERR_INVALID_ARGS);
  }
  enlightenment_.hyperv_cpuid[leaf - kHypervSuppliedLeafFirst] = values;
  return zx::ok();
}

zx::result<> Vcpu::SetMsrDelegation(bool enable) {
  if (!ThreadIsOurThread(Thread::Current::Get())) {
    return zx::error(ZX_ERR_BAD_STATE);
  }
  // The other direction of the same invariant: withdrawing delegation from a
  // VCPU that is presenting a Hyper-V identity would leave it in exactly the
  // state SetHypervIdentity refuses to create. Enforcing only one direction
  // would make the invariant depend on the order the setters happen to be
  // called in, which is not an invariant.
  if (!enable && enlightenment_.hyperv_identity) {
    return zx::error(ZX_ERR_INVALID_ARGS);
  }
  enlightenment_.delegate_synthetic_msrs = enable;
  return zx::ok();
}

zx::result<> Vcpu::SetHypercallDelegation(bool enable) {
  if (!ThreadIsOurThread(Thread::Current::Get())) {
    return zx::error(ZX_ERR_BAD_STATE);
  }
  enlightenment_.delegate_hypercalls = enable;
  return zx::ok();
}

namespace {

// The flags zx_vcpu_enlightenment_t::flags may carry in this version. Anything
// else is a caller built against a surface this kernel does not implement, and
// is refused rather than silently ignored.
constexpr uint32_t kKnownEnlightenmentFlags = ZX_VCPU_ENLIGHTENMENT_HYPERV_IDENTITY |
                                              ZX_VCPU_ENLIGHTENMENT_DELEGATE_MSRS |
                                              ZX_VCPU_ENLIGHTENMENT_DELEGATE_HYPERCALLS;

// Enforce the identity/delegation pairing structurally.
//
// Every known flag appears here with the set of flags it REQUIRES, and the
// static_assert below fails to compile if a flag is added to
// kKnownEnlightenmentFlags without an entry. That is the point: the identity /
// MSR-delegation mismatch existed because the three capabilities were
// independent booleans with nothing tying them, so the next capability added
// would have arrived the same way. Modelled on the compile-time assert that
// pins the VMM's SUPPORTED_FEATURES to the crash-MSR table.
struct EnlightenmentDependency {
  uint32_t flag;
  uint32_t requires_flags;
};
constexpr EnlightenmentDependency kEnlightenmentDependencies[] = {
    // Presenting a Hyper-V identity commits us to answering the synthetic MSRs,
    // and only the VMM can: the kernel implements none of them.
    {ZX_VCPU_ENLIGHTENMENT_HYPERV_IDENTITY, ZX_VCPU_ENLIGHTENMENT_DELEGATE_MSRS},
    {ZX_VCPU_ENLIGHTENMENT_DELEGATE_MSRS, 0},
    // Hypercall delegation stands alone: a VMM may claim VMCALL without
    // presenting a Hyper-V identity (the KVM-flavoured paravirtual surface).
    {ZX_VCPU_ENLIGHTENMENT_DELEGATE_HYPERCALLS, 0},
};

constexpr uint32_t EnlightenmentFlagsCovered() {
  uint32_t covered = 0;
  for (const EnlightenmentDependency& d : kEnlightenmentDependencies) {
    covered |= d.flag;
  }
  return covered;
}
static_assert(EnlightenmentFlagsCovered() == kKnownEnlightenmentFlags,
              "every enlightenment flag must declare what it requires; a new flag needs an entry "
              "in kEnlightenmentDependencies, not just a bit in kKnownEnlightenmentFlags");

// Whether `flags` satisfies every dependency it names. Order-independent by
// construction, which is why WriteEnlightenment checks the whole requested set
// here rather than relying on the setters, which are applied one at a time.
constexpr bool EnlightenmentFlagsAreConsistent(uint32_t flags) {
  for (const EnlightenmentDependency& d : kEnlightenmentDependencies) {
    if ((flags & d.flag) != 0 && (flags & d.requires_flags) != d.requires_flags) {
      return false;
    }
  }
  return true;
}
static_assert(!EnlightenmentFlagsAreConsistent(ZX_VCPU_ENLIGHTENMENT_HYPERV_IDENTITY),
              "identity alone must be refused");
static_assert(EnlightenmentFlagsAreConsistent(ZX_VCPU_ENLIGHTENMENT_HYPERV_IDENTITY |
                                              ZX_VCPU_ENLIGHTENMENT_DELEGATE_MSRS),
              "identity paired with MSR delegation must be accepted");
static_assert(EnlightenmentFlagsAreConsistent(0), "the empty configuration is legal");

// The public leaf window and the kernel's must be the same window; if one is
// ever widened the other has to move with it, or userspace could name a leaf the
// exit handler has no slot for.
static_assert(ZX_VCPU_HYPERV_CPUID_LEAF_FIRST == kHypervSuppliedLeafFirst);
static_assert(ZX_VCPU_HYPERV_CPUID_LEAF_LAST == kHypervSuppliedLeafLast);
static_assert(ZX_VCPU_HYPERV_CPUID_MAX == kHypervSuppliedLeafCount);

}  // namespace

zx::result<> Vcpu::WriteEnlightenment(const zx_vcpu_enlightenment_t& in) {
  if (!ThreadIsOurThread(Thread::Current::Get())) {
    return zx::error(ZX_ERR_BAD_STATE);
  }
  // Validate everything before touching the VCPU. The exit handlers read
  // enlightenment_ without re-checking it, so anything that reaches it must
  // already be a configuration they expect; and a caller whose structure is
  // rejected is entitled to find the VCPU exactly as it left it.
  if (in.magic != ZX_VCPU_ENLIGHTENMENT_MAGIC || in.version != ZX_VCPU_ENLIGHTENMENT_VERSION ||
      in.size != sizeof(zx_vcpu_enlightenment_t)) {
    return zx::error(ZX_ERR_INVALID_ARGS);
  }
  if ((in.flags & ~kKnownEnlightenmentFlags) != 0 || in.reserved != 0) {
    return zx::error(ZX_ERR_INVALID_ARGS);
  }
  if (in.cpuid_count > ZX_VCPU_HYPERV_CPUID_MAX) {
    return zx::error(ZX_ERR_OUT_OF_RANGE);
  }
  // A write replaces the whole set of supplied leaves, so build the new set
  // first: leaves the caller did not name read back as zero, which is the
  // "implements nothing" answer and matches a freshly created VCPU.
  HypervCpuidLeaf leaves[kHypervSuppliedLeafCount] = {};
  for (uint32_t i = 0; i < in.cpuid_count; i++) {
    const uint32_t leaf = in.cpuid[i].leaf;
    if (leaf < kHypervSuppliedLeafFirst || leaf > kHypervSuppliedLeafLast) {
      return zx::error(ZX_ERR_OUT_OF_RANGE);
    }
    leaves[leaf - kHypervSuppliedLeafFirst] = {in.cpuid[i].eax, in.cpuid[i].ebx, in.cpuid[i].ecx,
                                               in.cpuid[i].edx};
  }

  // Checked against the WHOLE requested set, before anything is applied. The
  // setters below enforce the same invariant, but they run one at a time against
  // the VCPU's current state, so a perfectly valid combined write would be
  // refused halfway through purely because of the order they are called in.
  //
  // Deliberately LAST of the validations. It was originally placed with the
  // other flag checks, which changed the error a caller sees for a request that
  // is both inconsistent AND has an out-of-range CPUID leaf: the established
  // contract for that is ZX_ERR_OUT_OF_RANGE, and a new invariant should not
  // quietly renumber an existing one. Both orders refuse the write; only this
  // one keeps the more specific answer.
  if (!EnlightenmentFlagsAreConsistent(in.flags)) {
    return zx::error(ZX_ERR_INVALID_ARGS);
  }

  // Apply through the same setters the in-kernel callers use, so there is one
  // definition of what each capability means. None of these can fail now: the
  // thread check above is the only condition they impose beyond the leaf range,
  // which has already been checked.
  for (uint32_t i = 0; i < kHypervSuppliedLeafCount; i++) {
    if (auto result = SetHypervCpuidLeaf(kHypervSuppliedLeafFirst + i, leaves[i]);
        result.is_error()) {
      return result;
    }
  }
  const bool want_identity = (in.flags & ZX_VCPU_ENLIGHTENMENT_HYPERV_IDENTITY) != 0;
  const bool want_msrs = (in.flags & ZX_VCPU_ENLIGHTENMENT_DELEGATE_MSRS) != 0;
  // Applied in an order that never transits a state the setters refuse. Each
  // setter enforces the identity/delegation invariant against the VCPU as it is
  // at that moment, so raising delegation must precede raising identity, and
  // dropping identity must precede dropping delegation. The whole requested set
  // was already validated above; this is only about the path taken to reach it.
  if (want_identity) {
    if (auto result = SetMsrDelegation(want_msrs); result.is_error()) {
      return result;
    }
    if (auto result = SetHypervIdentity(true); result.is_error()) {
      return result;
    }
  } else {
    if (auto result = SetHypervIdentity(false); result.is_error()) {
      return result;
    }
    if (auto result = SetMsrDelegation(want_msrs); result.is_error()) {
      return result;
    }
  }
  return SetHypercallDelegation((in.flags & ZX_VCPU_ENLIGHTENMENT_DELEGATE_HYPERCALLS) != 0);
}

zx::result<> Vcpu::ReadEnlightenment(zx_vcpu_enlightenment_t& out) {
  if (!ThreadIsOurThread(Thread::Current::Get())) {
    return zx::error(ZX_ERR_BAD_STATE);
  }
  out = {};
  out.magic = ZX_VCPU_ENLIGHTENMENT_MAGIC;
  out.version = ZX_VCPU_ENLIGHTENMENT_VERSION;
  out.size = sizeof(zx_vcpu_enlightenment_t);
  if (enlightenment_.hyperv_identity) {
    out.flags |= ZX_VCPU_ENLIGHTENMENT_HYPERV_IDENTITY;
  }
  if (enlightenment_.delegate_synthetic_msrs) {
    out.flags |= ZX_VCPU_ENLIGHTENMENT_DELEGATE_MSRS;
  }
  if (enlightenment_.delegate_hypercalls) {
    out.flags |= ZX_VCPU_ENLIGHTENMENT_DELEGATE_HYPERCALLS;
  }
  // Report every leaf, including the all-zero ones: the result is a complete
  // description, so writing it back reproduces this configuration exactly.
  out.cpuid_count = ZX_VCPU_HYPERV_CPUID_MAX;
  for (uint32_t i = 0; i < kHypervSuppliedLeafCount; i++) {
    const HypervCpuidLeaf& leaf = enlightenment_.hyperv_cpuid[i];
    out.cpuid[i] = {kHypervSuppliedLeafFirst + i, leaf.eax, leaf.ebx, leaf.ecx, leaf.edx};
  }
  return zx::ok();
}

zx::result<> Vcpu::InjectException(uint32_t vector, uint32_t instruction_length) {
  if (!ThreadIsOurThread(Thread::Current::Get())) {
    return zx::error(ZX_ERR_BAD_STATE);
  }
  if (pending_event_.type != ZX_VCPU_EVENT_NONE) {
    return zx::error(ZX_ERR_BAD_STATE);
  }
  // The injection must be applied on the loaded VMCS immediately before VM entry;
  // Enter() consumes this on its next iteration. (A VMCS write here, on a
  // separate AutoVmcs, would not survive to entry.)
  //
  // This is the vector-only shape `zx_vcpu_interrupt()` has: the type is
  // inferred from the vector and an exception that carries an error code gets a
  // zero one, matching what AutoVmcs::IssueInterrupt did before the
  // pending-event path existed. Callers with a real payload use
  // WritePendingEvent.
  pending_event_ = {};
  pending_event_.vector = vector;
  pending_event_.instruction_length = instruction_length;
  if (vector == X86_INT_BREAKPOINT || vector == X86_INT_OVERFLOW) {
    pending_event_.type = ZX_VCPU_EVENT_SOFTWARE_EXCEPTION;
  } else if (vector == X86_INT_NMI) {
    pending_event_.type = ZX_VCPU_EVENT_NMI;
  } else if (vector <= X86_INT_VIRT) {
    pending_event_.type = ZX_VCPU_EVENT_HARDWARE_EXCEPTION;
    pending_event_.has_error_code = has_error_code(vector);
  } else {
    pending_event_.type = ZX_VCPU_EVENT_EXTERNAL_INTERRUPT;
  }
  return zx::ok();
}

zx::result<> Vcpu::WritePendingEvent(const zx_vcpu_pending_event_t& in) {
  if (!ThreadIsOurThread(Thread::Current::Get())) {
    return zx::error(ZX_ERR_BAD_STATE);
  }
  // Identity first: a caller that does not agree with this kernel about the
  // layout is refused rather than reinterpreted.
  if (in.magic != ZX_VCPU_PENDING_EVENT_MAGIC || in.version != ZX_VCPU_PENDING_EVENT_VERSION ||
      in.size != sizeof(zx_vcpu_pending_event_t)) {
    return zx::error(ZX_ERR_INVALID_ARGS);
  }
  constexpr uint32_t kKnownFlags = ZX_VCPU_EVENT_ERROR_CODE_VALID | ZX_VCPU_EVENT_CR2_VALID;
  if ((in.flags & ~kKnownFlags) != 0) {
    return zx::error(ZX_ERR_INVALID_ARGS);
  }
  const bool has_error_code_flag = (in.flags & ZX_VCPU_EVENT_ERROR_CODE_VALID) != 0;
  const bool has_cr2_flag = (in.flags & ZX_VCPU_EVENT_CR2_VALID) != 0;
  // A payload field only carries meaning under its flag; requiring the rest to
  // be zero means a caller that thought it was setting something is told so,
  // instead of having it silently dropped.
  if (!has_error_code_flag && in.error_code != 0) {
    return zx::error(ZX_ERR_INVALID_ARGS);
  }
  if (!has_cr2_flag && in.cr2 != 0) {
    return zx::error(ZX_ERR_INVALID_ARGS);
  }

  switch (in.type) {
    case ZX_VCPU_EVENT_NONE:
      // Clearing the queue: nothing else may be set, or the caller means
      // something this does not do.
      if (in.vector != 0 || in.flags != 0 || in.instruction_length != 0) {
        return zx::error(ZX_ERR_INVALID_ARGS);
      }
      pending_event_ = {};
      return zx::ok();

    case ZX_VCPU_EVENT_EXTERNAL_INTERRUPT:
      // Vectors below X86_INT_PLATFORM_BASE are the architecturally defined
      // exception range: delivering one as an external interrupt would vector
      // through the guest's exception gate with interrupt semantics.
      if (in.vector < X86_INT_PLATFORM_BASE || in.vector > X86_INT_MAX) {
        return zx::error(ZX_ERR_OUT_OF_RANGE);
      }
      if (has_error_code_flag || has_cr2_flag || in.instruction_length != 0) {
        return zx::error(ZX_ERR_INVALID_ARGS);
      }
      break;

    case ZX_VCPU_EVENT_NMI:
      if (in.vector != X86_INT_NMI) {
        return zx::error(ZX_ERR_INVALID_ARGS);
      }
      if (has_error_code_flag || has_cr2_flag || in.instruction_length != 0) {
        return zx::error(ZX_ERR_INVALID_ARGS);
      }
      break;

    case ZX_VCPU_EVENT_HARDWARE_EXCEPTION:
      if (in.vector > X86_INT_MAX_INTEL_DEFINED) {
        return zx::error(ZX_ERR_OUT_OF_RANGE);
      }
      // The error code is not optional in either direction: VM entry refuses a
      // deliver-error-code bit on a vector that has none (Volume 3, Section
      // 26.2.1.3), and omitting it on a vector that has one is exactly the
      // silent-zero bug this path exists to fix.
      if (has_error_code_flag != has_error_code(in.vector)) {
        return zx::error(ZX_ERR_INVALID_ARGS);
      }
      // CR2 means the faulting linear address, which only #PF has.
      if (has_cr2_flag != (in.vector == X86_INT_PAGE_FAULT)) {
        return zx::error(ZX_ERR_INVALID_ARGS);
      }
      if (in.instruction_length != 0) {
        return zx::error(ZX_ERR_INVALID_ARGS);
      }
      break;

    case ZX_VCPU_EVENT_SOFTWARE_EXCEPTION:
      // Volume 3, Section 24.8.3: only #BP and #OF are software exceptions.
      if (in.vector != X86_INT_BREAKPOINT && in.vector != X86_INT_OVERFLOW) {
        return zx::error(ZX_ERR_INVALID_ARGS);
      }
      if (has_error_code_flag || has_cr2_flag) {
        return zx::error(ZX_ERR_INVALID_ARGS);
      }
      // The guest resumes at RIP + length, so a zero length would re-execute
      // the raising instruction forever. VM entry bounds it at 15 bytes.
      if (in.instruction_length == 0 || in.instruction_length > 15) {
        return zx::error(ZX_ERR_OUT_OF_RANGE);
      }
      break;

    default:
      return zx::error(ZX_ERR_INVALID_ARGS);
  }

  if (has_error_code_flag) {
    // VM entry refuses an error code when the guest is not in protected mode
    // (Volume 3, Section 26.2.1.3), and a real-mode guest has no error code to
    // push anyway. Catch that here, where the caller can see which write was
    // wrong, rather than as an opaque entry failure several entries later.
    AutoVmcs vmcs(vmcs_page_.PhysicalAddress());
    if ((vmcs.Read(VmcsFieldXX::GUEST_CR0) & X86_CR0_PE) == 0) {
      return zx::error(ZX_ERR_BAD_STATE);
    }
  }

  // Everything validated: replace the queue wholesale.
  pending_event_ = {};
  pending_event_.type = in.type;
  pending_event_.vector = in.vector;
  pending_event_.error_code = in.error_code;
  pending_event_.instruction_length = in.instruction_length;
  pending_event_.cr2 = in.cr2;
  pending_event_.has_error_code = has_error_code_flag;
  pending_event_.has_cr2 = has_cr2_flag;
  return zx::ok();
}

zx::result<> Vcpu::ReadPendingEvent(zx_vcpu_pending_event_t& out) {
  if (!ThreadIsOurThread(Thread::Current::Get())) {
    return zx::error(ZX_ERR_BAD_STATE);
  }
  out = {};
  out.magic = ZX_VCPU_PENDING_EVENT_MAGIC;
  out.version = ZX_VCPU_PENDING_EVENT_VERSION;
  out.size = sizeof(zx_vcpu_pending_event_t);
  out.type = pending_event_.type;
  if (pending_event_.type == ZX_VCPU_EVENT_NONE) {
    return zx::ok();
  }
  out.vector = pending_event_.vector;
  out.instruction_length = pending_event_.instruction_length;
  if (pending_event_.has_error_code) {
    out.flags |= ZX_VCPU_EVENT_ERROR_CODE_VALID;
    out.error_code = pending_event_.error_code;
  }
  if (pending_event_.has_cr2) {
    out.flags |= ZX_VCPU_EVENT_CR2_VALID;
    out.cr2 = pending_event_.cr2;
  }
  return zx::ok();
}

zx::result<> Vcpu::WriteVectoringEvent(const zx_vcpu_vectoring_event_t& in) {
  if (!ThreadIsOurThread(Thread::Current::Get())) {
    return zx::error(ZX_ERR_BAD_STATE);
  }
  // Identity first: a caller that does not agree with this kernel about the
  // layout is refused rather than reinterpreted.
  if (in.magic != ZX_VCPU_VECTORING_EVENT_MAGIC || in.version != ZX_VCPU_VECTORING_EVENT_VERSION ||
      in.size != sizeof(zx_vcpu_vectoring_event_t)) {
    return zx::error(ZX_ERR_INVALID_ARGS);
  }

  // `valid` is a strict 0/1 flag: capture emits exactly 1, so a value above 1
  // is a caller that does not agree with the contract.
  if (in.valid > 1) {
    return zx::error(ZX_ERR_INVALID_ARGS);
  }
  // Clearing: valid == 0 means nothing is owed, so every other field must be
  // zero (a caller that set one meant something this does not do).
  if (in.valid == 0) {
    if (in.type != 0 || in.vector != 0 || in.has_error_code != 0 || in.error_code != 0 ||
        in.instruction_length != 0) {
      return zx::error(ZX_ERR_INVALID_ARGS);
    }
    vectoring_event_ = {};
    return zx::ok();
  }

  // Vector is bits 7:0 only, matching kInterruptInfoVectorMask at capture. Check
  // it first so the per-type predicates below reason about a canonical vector.
  if ((in.vector & ~static_cast<uint32_t>(kInterruptInfoVectorMask)) != 0) {
    return zx::error(ZX_ERR_INVALID_ARGS);
  }

  // The type is the raw VMX interruption type in bits 10:8. Only the forms the
  // capture path produces (CaptureVectoringEvent, on VM exit during IDT
  // vectoring) are reinjectable, and each constrains its vector to what VM entry
  // and this implementation's own IssueInterrupt/IssueEvent will accept. Reproduce those
  // constraints here so a corrupt or cross-built durable artifact (valid
  // identity triple, bad payload) is refused with context rather than reaching
  // vmcs.IssueEvent / ENTRY_INSTRUCTION_LENGTH as a shape VM entry rejects
  // opaquely — or, worse, one IssueInterrupt silently reclassifies.
  switch (in.type) {
    case kInterruptTypeExternalInterrupt:
      // IssueInterrupt (this file) reclassifies vectors <= X86_INT_VIRT as
      // NMI/exceptions, so a restored external interrupt with such a vector
      // would change type. Vectors 21..31 are deliberately kept: this
      // implementation delivers them as ICR vectors.
      if (in.vector <= X86_INT_VIRT || in.vector > X86_INT_MAX) {
        return zx::error(ZX_ERR_OUT_OF_RANGE);
      }
      break;
    case kInterruptTypeNmi:
      if (in.vector != X86_INT_NMI) {
        return zx::error(ZX_ERR_INVALID_ARGS);
      }
      break;
    case kInterruptTypeHardwareException:
      if (in.vector > X86_INT_MAX_INTEL_DEFINED) {
        return zx::error(ZX_ERR_OUT_OF_RANGE);
      }
      break;
    case kInterruptTypeSoftwareInterrupt:
      // INT n: any 8-bit vector, already range-checked above.
      break;
    case kInterruptTypePrivilegedSoftwareException:
      // INT1 raises #DB only.
      if (in.vector != X86_INT_DEBUG) {
        return zx::error(ZX_ERR_INVALID_ARGS);
      }
      break;
    case kInterruptTypeSoftwareException:
      // INT3 (#BP) and INTO (#OF) only.
      if (in.vector != X86_INT_BREAKPOINT && in.vector != X86_INT_OVERFLOW) {
        return zx::error(ZX_ERR_INVALID_ARGS);
      }
      break;
    default:
      // Reserved (1<<8) and other-event (7<<8): never a guest-IDT delivery.
      return zx::error(ZX_ERR_INVALID_ARGS);
  }

  // has_error_code is a strict 0/1 flag.
  if (in.has_error_code > 1) {
    return zx::error(ZX_ERR_INVALID_ARGS);
  }
  // The error-code flag must agree EXACTLY with what VM entry requires: only a
  // hardware exception whose vector architecturally pushes one carries it (the
  // same has_error_code() predicate WritePendingEvent uses); every other type,
  // and a hardware exception without one, must not set it. VM entry refuses a
  // deliver-error-code bit on a vector that has none and, for one that has one,
  // omitting it is the silent-zero bug this validation exists to catch.
  const bool needs_error_code =
      in.type == kInterruptTypeHardwareException && has_error_code(in.vector);
  if ((in.has_error_code != 0) != needs_error_code) {
    return zx::error(ZX_ERR_INVALID_ARGS);
  }
  if (in.has_error_code == 0 && in.error_code != 0) {
    return zx::error(ZX_ERR_INVALID_ARGS);
  }
  // Reserved bits: VM entry requires bits 31:16 of the exception error code to
  // be zero. Reject garbage in the high half rather than let it reach the entry
  // field.
  if (in.has_error_code != 0 && (in.error_code >> 16) != 0) {
    return zx::error(ZX_ERR_INVALID_ARGS);
  }
  // VM entry refuses an error code when the guest is not in protected mode
  // (SDM Vol. 3, 26.2.1.3), and a real-mode guest has none to push. The guest
  // CR0 read here reflects the already-restored architectural state (arch state
  // is written before this topic during a restore). Mirrors WritePendingEvent.
  if (in.has_error_code != 0) {
    AutoVmcs vmcs(vmcs_page_.PhysicalAddress());
    if ((vmcs.Read(VmcsFieldXX::GUEST_CR0) & X86_CR0_PE) == 0) {
      return zx::error(ZX_ERR_BAD_STATE);
    }
  }
  // instruction_length is carried only by the software forms that resume past
  // the originating instruction; VM entry bounds it at 15. Every other type
  // must leave it zero.
  if (type_needs_instruction_length(in.type)) {
    if (in.instruction_length == 0 || in.instruction_length > 15) {
      return zx::error(ZX_ERR_OUT_OF_RANGE);
    }
  } else if (in.instruction_length != 0) {
    return zx::error(ZX_ERR_INVALID_ARGS);
  }

  // Everything validated: replace it wholesale. Nothing above this point
  // mutates vectoring_event_, so a rejected write leaves the prior value
  // untouched.
  vectoring_event_ = {};
  vectoring_event_.valid = true;
  vectoring_event_.type = in.type;
  vectoring_event_.vector = in.vector;
  vectoring_event_.has_error_code = in.has_error_code != 0;
  vectoring_event_.error_code = in.error_code;
  vectoring_event_.instruction_length = in.instruction_length;
  return zx::ok();
}

zx::result<> Vcpu::ReadVectoringEvent(zx_vcpu_vectoring_event_t& out) {
  if (!ThreadIsOurThread(Thread::Current::Get())) {
    return zx::error(ZX_ERR_BAD_STATE);
  }
  out = {};
  out.magic = ZX_VCPU_VECTORING_EVENT_MAGIC;
  out.version = ZX_VCPU_VECTORING_EVENT_VERSION;
  out.size = sizeof(zx_vcpu_vectoring_event_t);
  if (!vectoring_event_.valid) {
    return zx::ok();
  }
  out.valid = 1;
  out.type = vectoring_event_.type;
  out.vector = vectoring_event_.vector;
  out.has_error_code = vectoring_event_.has_error_code ? 1 : 0;
  out.error_code = vectoring_event_.error_code;
  out.instruction_length = vectoring_event_.instruction_length;
  return zx::ok();
}

zx::result<> Vcpu::ReadTscState(zx_vcpu_tsc_state_t& out) {
  if (!ThreadIsOurThread(Thread::Current::Get())) {
    return zx::error(ZX_ERR_BAD_STATE);
  }
  out = {};
  out.magic = ZX_VCPU_TSC_STATE_MAGIC;
  out.version = ZX_VCPU_TSC_STATE_VERSION;
  out.size = sizeof(zx_vcpu_tsc_state_t);
  // A live read always carries a captured state.
  out.flags = ZX_VCPU_TSC_STATE_PRESENT;
  AutoVmcs vmcs(vmcs_page_.PhysicalAddress());
  const bool offsetting =
      (vmcs.Read(VmcsField32::PROCBASED_CTLS) & kProcbasedCtlsUseTscOffsetting) != 0;
  if (offsetting) {
    out.flags |= ZX_VCPU_TSC_STATE_OFFSETTING;
    out.tsc_offset = tsc_offset_;
    // The guest's RDTSC is host RDTSC plus this VCPU's TSC_OFFSET; report the
    // value the guest would read right now (the anchor a restore re-anchors to)
    // and the offset itself (the coherent, sampling-instant-independent value a
    // partition restore validates for agreement across VCPUs).
    out.guest_tsc = _rdtsc() + static_cast<uint64_t>(tsc_offset_);
  } else {
    // No TSC offsetting: the guest reads the raw host TSC and the offset is 0.
    out.tsc_offset = 0;
    out.guest_tsc = _rdtsc();
  }
  // The armed IA32_TSC_DEADLINE the guest last wrote (guest TSC units), or zero.
  // Reported UNCONDITIONALLY -- a guest can arm it without the offset control
  // (the WRMSR gate checks only the LVT mode), so a valid capture may carry a
  // nonzero deadline with OFFSETTING clear. Restoring it is this topic's job
  // because the async-state timer snapshot only carries the LVT one-shot/
  // periodic deadline, not the TSC-deadline register.
  out.tsc_deadline = local_apic_state_.tsc_deadline;
  return zx::ok();
}

zx::result<> Vcpu::WriteTscState(const zx_vcpu_tsc_state_t& in) {
  if (!ThreadIsOurThread(Thread::Current::Get())) {
    return zx::error(ZX_ERR_BAD_STATE);
  }
  // Identity first, like every other write topic: a caller that disagrees about
  // the layout is refused rather than reinterpreted.
  if (in.magic != ZX_VCPU_TSC_STATE_MAGIC || in.version != ZX_VCPU_TSC_STATE_VERSION ||
      in.size != sizeof(zx_vcpu_tsc_state_t)) {
    return zx::error(ZX_ERR_INVALID_ARGS);
  }
  // PRESENT clear: a legacy artifact predating this topic. There is nothing to
  // install; leave the running offset AND the armed deadline exactly as they
  // are. The payload must be zero -- a nonzero one is malformed.
  if ((in.flags & ZX_VCPU_TSC_STATE_PRESENT) == 0) {
    if (in.guest_tsc != 0 || in.tsc_offset != 0 || in.tsc_deadline != 0) {
      return zx::error(ZX_ERR_INVALID_ARGS);
    }
    return zx::ok();
  }

  AutoVmcs vmcs(vmcs_page_.PhysicalAddress());
  const bool machine_offsets =
      (vmcs.Read(VmcsField32::PROCBASED_CTLS) & kProcbasedCtlsUseTscOffsetting) != 0;

  // The offset the armed deadline is re-derived through: the value we install
  // when OFFSETTING is set, otherwise the offset already in force (0 on a
  // machine without offsetting).
  int64_t offset = tsc_offset_;
  if ((in.flags & ZX_VCPU_TSC_STATE_OFFSETTING) != 0) {
    if (!machine_offsets) {
      // The capture installs an offset but this machine does not offer TSC
      // offsetting. Refuse rather than silently leave the guest's RDTSC
      // unadjusted -- the same failure mode SetTscOffset guards against, and the
      // reason the userspace partition-restore path preflights every VCPU's
      // capability before mutating any of them.
      return zx::error(ZX_ERR_NOT_SUPPORTED);
    }
    // Install the caller's pre-computed offset VERBATIM. It is NOT re-derived
    // from a fresh RDTSC here: the caller sampled the host TSC once for the
    // whole partition and handed every VCPU the same offset, so they all land on
    // one coherent guest clock instead of skewing by the sequential per-VCPU
    // restore delay.
    offset = in.tsc_offset;
    vmcs.Write(VmcsField64::TSC_OFFSET, static_cast<uint64_t>(offset));
    tsc_offset_ = offset;
  }
  // OFFSETTING clear leaves the VMCS offset untouched (the capture had none, or
  // this machine has none), but the armed deadline below is still restored: a
  // guest can arm IA32_TSC_DEADLINE without the offset control.

  // Re-derive and re-arm (or disarm) the armed IA32_TSC_DEADLINE through the
  // offset now in force. The guest deadline is in guest TSC; the host timer must
  // fire when host RDTSC reaches guest_deadline - offset. Only in TSC-deadline
  // mode; out of it the register is architecturally inert and the LVT one-shot/
  // periodic timer is restored by RestoreAsyncState (which runs before this
  // topic). In TSC-deadline mode this topic is AUTHORITATIVE over the timer:
  // RestoreAsyncState may have armed one from its remaining-time snapshot, and a
  // zero deadline here means "disarmed", so we must actively cancel it rather
  // than leave a live timer contradicting the authoritative TSC state.
  local_apic_state_.tsc_deadline = in.tsc_deadline;
  if ((local_apic_state_.lvt_timer & LVT_TIMER_MODE_MASK) == LVT_TIMER_MODE_TSC_DEADLINE) {
    if (in.tsc_deadline != 0) {
      const int64_t host_deadline_tsc =
          static_cast<int64_t>(in.tsc_deadline - static_cast<uint64_t>(offset));
      const zx_instant_mono_t mono_deadline =
          convert_raw_tsc_timestamp_to_clock_monotonic(host_deadline_tsc);
      RearmApicTimer(local_apic_state_, mono_deadline);
    } else {
      RearmApicTimer(local_apic_state_, 0);
    }
  }
  return zx::ok();
}

zx::result<> Vcpu::SaveAsyncState(VcpuAsyncState& out) {
  if (!ThreadIsOurThread(Thread::Current::Get())) {
    return zx::error(ZX_ERR_BAD_STATE);
  }
  out = {};

  // Local-APIC timer configuration.
  out.lvt_timer = local_apic_state_.lvt_timer;
  out.lvt_initial_count = local_apic_state_.lvt_initial_count;
  out.lvt_divide_config = local_apic_state_.lvt_divide_config;

  // Timer arming: capture the remaining time to the armed deadline (see
  // LocalApicState::timer_deadline), so restore re-anchors it rather than firing
  // on a stale absolute deadline. A deadline already in the past captures as 0
  // remaining (fires immediately on restore).
  if (local_apic_state_.timer_deadline > 0) {
    const zx_instant_mono_t now = current_mono_time();
    out.timer_armed = 1;
    out.timer_remaining_ns = local_apic_state_.timer_deadline > now
                                 ? static_cast<uint64_t>(local_apic_state_.timer_deadline - now)
                                 : 0;
  }

  // Pending-interrupt bitmap. One pass under the tracker's lock rather than a
  // probe per vector.
  local_apic_state_.interrupt_tracker.ForEachPending([&out](uint32_t vector) {
    out.pending_interrupts[vector / 8] |= static_cast<uint8_t>(1u << (vector % 8));
  });

  // Reconcile any outstanding lazy-EOI grant BEFORE reading the ISR. A guest can
  // retire a vector by clearing the lazy-EOI assist word and skipping its
  // architectural EOI; until reconciliation runs, the kernel still holds
  // lazy_eoi_armed and the ISR bit for that vector. Without this call the
  // captured ISR would record a logically-retired bit, and a restore would
  // reinstate a handler the guest has already finished. This applies the pending
  // lazy EOI exactly as the next Vcpu::Enter would (guest_isr_clear of
  // lazy_eoi_vector), so the ISR copied below is the true in-service set.
  guest_lazy_eoi_reconcile(local_apic_state_);

  // In-service-register bitmap: a straight copy of the (now reconciled) live
  // ISR. Distinct from the pending set above; see the field comment in
  // VcpuAsyncState. Same word layout as LocalApicState::isr (guest_isr_get), so
  // it round-trips verbatim.
  static_assert(sizeof(out.isr) == sizeof(local_apic_state_.isr),
                "VcpuAsyncState::isr must match LocalApicState::isr word for word");
  for (size_t i = 0; i < (sizeof(out.isr) / sizeof(out.isr[0])); i++) {
    out.isr[i] = local_apic_state_.isr[i];
  }

  // Paravirtualized clock. |system_time| is non-null exactly when the clock is
  // mapped into guest memory.
  out.pv_clock_enabled = pv_clock_state_.system_time != nullptr ? 1 : 0;
  out.pv_clock_is_stable = pv_clock_state_.is_stable ? 1 : 0;
  out.pv_clock_version = pv_clock_state_.version;
  out.pv_clock_guest_paddr = pv_clock_state_.guest_paddr;
  return zx::ok();
}

zx::result<> Vcpu::RestoreAsyncState(const VcpuAsyncState& in) {
  if (!ThreadIsOurThread(Thread::Current::Get())) {
    return zx::error(ZX_ERR_BAD_STATE);
  }

  // The restore is transactional: ALL fallible work happens first, into
  // temporaries, and NO live field -- LAPIC or paravirtual clock -- is touched
  // until every fallible step has succeeded. A malformed or cross-built artifact
  // is rejected with the VCPU left byte-for-byte as it was. (An earlier version
  // validated the ISR first but still overwrote LVT/pending/ISR/timer before the
  // fallible pv-clock remap, leaving the LAPIC half-restored when a bad guest
  // GPA was refused.)

  // ---- Phase 1: validate / preflight. No live mutation. ----

  // ISR word 0 holds vectors 0-31. Vectors 0..X86_INT_VIRT can never be in
  // service: exceptions and NMIs are not delivered through the APIC and are not
  // acknowledged with an EOI, so a bit there would never be cleared. But this
  // implementation DOES place bare interrupt vectors 21..31
  // (X86_INT_VIRT+1 .. X86_INT_MAX_INTEL_DEFINED) in service as guest ICR/device
  // vectors -- see LocalApicState::isr -- so a guest with, e.g., vector 31 in
  // service must round-trip. Reject only the impossible low bits 0..X86_INT_VIRT,
  // not all of word 0.
  constexpr uint32_t kImpossibleIsrBits = (uint32_t{1} << (X86_INT_VIRT + 1)) - 1;
  if ((in.isr[0] & kImpossibleIsrBits) != 0) {
    return zx::error(ZX_ERR_INVALID_ARGS);
  }
  static_assert((X86_INT_PLATFORM_BASE) == 32,
                "ISR word 0 must hold exactly vectors 0-31");
  static_assert(sizeof(local_apic_state_.isr) == sizeof(in.isr),
                "LocalApicState::isr must match VcpuAsyncState::isr word for word");

  // Preflight the paravirtual-clock mapping into a TEMPORARY. pv_clock_reset_clock
  // validates the guest-physical address (CreateGuestPtr) and, for a malformed or
  // cross-built artifact, fails HERE -- before any live field is touched. On
  // success the mapping is held in |pv_next| and moved into place in phase 2; the
  // temporary's destructor unmaps it harmlessly if we never reach the commit.
  PvClockState pv_next;
  if (in.pv_clock_enabled) {
    if (auto r = pv_clock_reset_clock(&pv_next, &guest_.PhysicalAspace(),
                                      in.pv_clock_guest_paddr);
        r.is_error()) {
      return r;
    }
    pv_next.version = in.pv_clock_version;
    pv_next.is_stable = in.pv_clock_is_stable != 0;
  }

  // ---- Phase 2: commit. Nothing below can fail; there is no error return past
  // this point, so no field is left half-written. ----

  // Revoke any lazy-EOI grant left from this VCPU's pre-restore timeline WITHOUT
  // reconciling it, and do so BEFORE installing the restored ISR below. Its
  // lazy_eoi_vector names a vector from the DISCARDED timeline; reconciling now
  // -- or letting a later reconcile / lazy-EOI sync run against a stale grant --
  // would guest_isr_clear that vector AFTER the restored ISR is in place,
  // clearing a bit the restore legitimately set on a reused VCPU. The lazy-EOI
  // *registration* (the assist page) is a separate topic and is left intact;
  // only the outstanding grant is dropped.
  //
  // Forcing the guest-visible word to 0 is part of dropping it, not an extra.
  // Every other site that clears `lazy_eoi_armed` first makes the word read 0,
  // maintaining the invariant `armed == false` => the word offers no skip.
  // Restore is the one path that can violate it from the OTHER direction: the
  // restored RAM image may itself carry word == 1 (a grant that was live and
  // unconsumed when the snapshot was taken), and the restored ISR below may
  // carry that same vector. Leaving the 1 in place hands the resumed guest a
  // skip nobody armed -- its epilogue consumes the stale grant, skips its EOI,
  // and with armed already false nothing here will ever retire the bit. That is
  // this branch's own strand, reconstituted after a restore.
  //
  // The in-tree VMM does keep an ordering that would mask it -- after
  // `restore_checkpoint` reinstalls the checkpointed VP-assist page it calls
  // `sync_lazy_eoi_topic`, which re-registers the topic and so re-zeroes the
  // word (virt_cerise/src/lib.rs, CeriseProcessor::restore_state) -- but that
  // is a userspace convention this kernel neither enforces nor can observe, and
  // it does not hold for a VMM that restores async state without re-registering
  // the topic. The invariant is cheap to maintain here, so it is maintained
  // here.
  if (uint32_t* word = local_apic_state_.lazy_eoi_guest_ptr.as<uint32_t>(); word != nullptr) {
    ktl::atomic_ref<uint32_t>(*word).store(0, ktl::memory_order_relaxed);
  }
  local_apic_state_.lazy_eoi_armed = false;
  local_apic_state_.lazy_eoi_vector = 0;

  local_apic_state_.lvt_timer = in.lvt_timer;
  local_apic_state_.lvt_initial_count = in.lvt_initial_count;
  local_apic_state_.lvt_divide_config = in.lvt_divide_config;

  // Reconstruct the pending-interrupt set authoritatively: drop whatever is
  // currently pending, then re-track exactly the captured vectors (signaling any
  // waiter, as a live delivery would). InterruptTracker::Interrupt returns an
  // error only for a vector >= X86_INT_COUNT; this loop is bounded by
  // X86_INT_COUNT, so it cannot fail here -- assert rather than propagate, since
  // an error return past the first mutation would break atomicity.
  local_apic_state_.interrupt_tracker.Clear(0, X86_INT_COUNT);
  for (uint32_t v = 0; v < X86_INT_COUNT; v++) {
    if ((in.pending_interrupts[v / 8] & (1u << (v % 8))) != 0) {
      [[maybe_unused]] zx::result<> r = local_apic_state_.interrupt_tracker.Interrupt(v);
      DEBUG_ASSERT(r.is_ok());
    }
  }

  // Install the in-service-register bitmap authoritatively (overwrite, not OR):
  // the captured ISR is the whole truth about what is in service, and a stale
  // bit left from this VCPU's pre-restore timeline would wedge later interrupts.
  for (size_t i = 0; i < (sizeof(local_apic_state_.isr) / sizeof(local_apic_state_.isr[0])); i++) {
    local_apic_state_.isr[i] = in.isr[i];
  }

  // Reconstruct the APIC timer: re-arm the live Timer to fire after the captured
  // remaining duration, re-anchored to the current clock — or cancel it.
  if (in.timer_armed) {
    const zx_instant_mono_t deadline = zx_time_add_duration(
        current_mono_time(), static_cast<zx_duration_t>(in.timer_remaining_ns));
    RearmApicTimer(local_apic_state_, deadline);
  } else {
    RearmApicTimer(local_apic_state_, 0);
  }

  // Commit the paravirtual clock: release any existing mapping, then move the
  // preflighted one into place (its guest pointer's address is stable across the
  // move, so the captured |system_time| stays valid) — or stop the clock.
  if (in.pv_clock_enabled) {
    pv_clock_stop_clock(&pv_clock_state_);
    pv_clock_state_.system_time = pv_next.system_time;
    pv_clock_state_.guest_ptr = ktl::move(pv_next.guest_ptr);
    pv_clock_state_.guest_paddr = pv_next.guest_paddr;
    pv_clock_state_.version = pv_next.version;
    pv_clock_state_.is_stable = pv_next.is_stable;
  } else {
    pv_clock_stop_clock(&pv_clock_state_);
  }
  return zx::ok();
}

namespace {
// Wire format: [magic][version][payload size] header, then the POD state bytes.
constexpr uint32_t kVcpuStateMagic = 0x56435055;       // 'VCPU'
constexpr uint32_t kVcpuAsyncStateMagic = 0x56415359;  // 'VASY'
// The architectural blob and the asynchronous blob are versioned
// INDEPENDENTLY. They were one shared constant, which was a latent trap:
// bumping it to describe a change to only ONE of the two structs silently
// invalidated the other. A released producer emitted both at version 6, and a
// later async-only change that moved the shared constant to 7 made restore
// refuse that producer's UNCHANGED architectural blob before the async blob was
// even examined. Two constants keep each format's version tied to its own
// layout.
//
// v3 moved the local-APIC block out to VcpuAsyncState, where the live objects it
// describes are reconstructed rather than written back.
// v4 added VcpuArchState::tpr, the guest's task-priority register (CR8 / VTPR).
// A v3 blob carries no task priority at all, so applying one would leave
// whatever VTPR the live virtual-APIC page happened to hold -- 0 on a fresh
// VCPU -- which is exactly the bug the field was added to fix.
// v5 added VcpuArchState::cstar. The old behavior accepted and discarded a
// guest write, then injected #GP on the matching read; apart from being
// architecturally incoherent, that kills Windows while it snapshots the syscall
// MSRs. A v4 blob cannot reconstruct compat-mode SYSCALL state.
// v6 is the released architectural layout (tag v0.1.0). VcpuArchState has NOT
// changed since, so v6 is the current architectural version -- a v6 arch blob
// is byte-identical to what this code produces and must still be accepted. Do
// not bump it for a change to the asynchronous blob.
constexpr uint32_t kVcpuArchStateVersion = 6;

// v7 added VcpuAsyncState::isr, the local-APIC in-service-register bitmap. A v6
// async blob carries no ISR, so a naive restore would leave whatever the live
// virtual-APIC page happened to hold -- losing in-service state (priority
// inversion: same/lower-class interrupts admitted before the restored handler
// EOIs) and, for an interrupted external-interrupt vectoring event, landing the
// reinjected interrupt with no ISR bit at all. Rather than refuse the older
// version -- which would break every checkpoint the released v6 producer wrote
// -- a v6 async blob is decoded through the pinned legacy layout below, leaving
// isr[] empty (correct for the quiescent case, and no worse than pre-v7 for a
// mid-vectoring restore). New captures emit v7.
constexpr uint32_t kVcpuAsyncStateVersion = 7;
constexpr uint32_t kVcpuAsyncStateVersionLegacyNoIsr = 6;

struct VcpuStateHeader {
  uint32_t magic;
  uint32_t version;
  uint32_t payload_size;
};

// Pinned byte-for-byte replica of the released v6 VcpuAsyncState layout, from
// before the isr[] field existed. It exists ONLY to decode that historical blob:
// the field order and types must match the old struct exactly so the compiler
// reproduces the original padding. Do not "tidy" or extend it.
struct VcpuAsyncStateV6 {
  uint32_t lvt_timer;
  uint32_t lvt_initial_count;
  uint32_t lvt_divide_config;
  uint8_t timer_armed;
  uint64_t timer_remaining_ns;
  uint8_t pending_interrupts[(X86_INT_COUNT + 7) / 8];
  uint8_t pv_clock_enabled;
  uint8_t pv_clock_is_stable;
  uint32_t pv_clock_version;
  uint64_t pv_clock_guest_paddr;
};
}  // namespace

size_t SerializedVcpuStateSize() { return sizeof(VcpuStateHeader) + sizeof(VcpuArchState); }

zx::result<> SerializeVcpuState(const VcpuArchState& state, uint8_t* buffer, size_t len) {
  if (buffer == nullptr || len < SerializedVcpuStateSize()) {
    return zx::error(ZX_ERR_BUFFER_TOO_SMALL);
  }
  const VcpuStateHeader header = {kVcpuStateMagic, kVcpuArchStateVersion,
                                  static_cast<uint32_t>(sizeof(VcpuArchState))};
  memcpy(buffer, &header, sizeof(header));
  memcpy(buffer + sizeof(header), &state, sizeof(state));
  return zx::ok();
}

zx::result<> DeserializeVcpuState(VcpuArchState& state, const uint8_t* buffer, size_t len) {
  if (buffer == nullptr || len < SerializedVcpuStateSize()) {
    return zx::error(ZX_ERR_BUFFER_TOO_SMALL);
  }
  VcpuStateHeader header = {};
  memcpy(&header, buffer, sizeof(header));
  if (header.magic != kVcpuStateMagic || header.version != kVcpuArchStateVersion ||
      header.payload_size != sizeof(VcpuArchState)) {
    return zx::error(ZX_ERR_INVALID_ARGS);
  }
  memcpy(&state, buffer + sizeof(header), sizeof(state));
  return zx::ok();
}

size_t SerializedVcpuAsyncStateSize() { return sizeof(VcpuStateHeader) + sizeof(VcpuAsyncState); }

zx::result<> SerializeVcpuAsyncState(const VcpuAsyncState& state, uint8_t* buffer, size_t len) {
  if (buffer == nullptr || len < SerializedVcpuAsyncStateSize()) {
    return zx::error(ZX_ERR_BUFFER_TOO_SMALL);
  }
  const VcpuStateHeader header = {kVcpuAsyncStateMagic, kVcpuAsyncStateVersion,
                                  static_cast<uint32_t>(sizeof(VcpuAsyncState))};
  memcpy(buffer, &header, sizeof(header));
  memcpy(buffer + sizeof(header), &state, sizeof(state));
  return zx::ok();
}

zx::result<> DeserializeVcpuAsyncState(VcpuAsyncState& state, const uint8_t* buffer, size_t len) {
  // Only the header is required up front; each version validates its own payload
  // length below so a shorter exact-size legacy buffer is not rejected by a
  // length rule sized for the current struct.
  if (buffer == nullptr || len < sizeof(VcpuStateHeader)) {
    return zx::error(ZX_ERR_BUFFER_TOO_SMALL);
  }
  VcpuStateHeader header = {};
  memcpy(&header, buffer, sizeof(header));
  if (header.magic != kVcpuAsyncStateMagic) {
    return zx::error(ZX_ERR_INVALID_ARGS);
  }
  const uint8_t* payload = buffer + sizeof(header);
  const size_t payload_len = len - sizeof(header);

  if (header.version == kVcpuAsyncStateVersion) {
    if (header.payload_size != sizeof(VcpuAsyncState) || payload_len < sizeof(VcpuAsyncState)) {
      return zx::error(ZX_ERR_INVALID_ARGS);
    }
    memcpy(&state, payload, sizeof(state));
    return zx::ok();
  }

  if (header.version == kVcpuAsyncStateVersionLegacyNoIsr) {
    // Released v6: no ISR bitmap. Decode the pinned legacy layout and lift its
    // fields into the current struct, leaving isr[] empty. Accept BOTH an
    // exact-size legacy buffer (payload_len == sizeof(VcpuAsyncStateV6)) and the
    // released 4096-byte retained buffer (payload_len larger); only the leading
    // sizeof(VcpuAsyncStateV6) bytes are read.
    if (header.payload_size != sizeof(VcpuAsyncStateV6) ||
        payload_len < sizeof(VcpuAsyncStateV6)) {
      return zx::error(ZX_ERR_INVALID_ARGS);
    }
    VcpuAsyncStateV6 legacy = {};
    memcpy(&legacy, payload, sizeof(legacy));
    state = {};  // zero-init: isr[] stays empty, the quiescent-case truth.
    state.lvt_timer = legacy.lvt_timer;
    state.lvt_initial_count = legacy.lvt_initial_count;
    state.lvt_divide_config = legacy.lvt_divide_config;
    state.timer_armed = legacy.timer_armed;
    state.timer_remaining_ns = legacy.timer_remaining_ns;
    static_assert(sizeof(state.pending_interrupts) == sizeof(legacy.pending_interrupts),
                  "legacy pending-interrupt bitmap must match current layout");
    memcpy(state.pending_interrupts, legacy.pending_interrupts, sizeof(state.pending_interrupts));
    state.pv_clock_enabled = legacy.pv_clock_enabled;
    state.pv_clock_is_stable = legacy.pv_clock_is_stable;
    state.pv_clock_version = legacy.pv_clock_version;
    state.pv_clock_guest_paddr = legacy.pv_clock_guest_paddr;
    return zx::ok();
  }

  return zx::error(ZX_ERR_INVALID_ARGS);
}

zx_info_vcpu_t Vcpu::GetInfo() const {
  if (kicked_.load()) {
    return {.flags = ZX_INFO_VCPU_FLAG_KICKED};
  }
  return {};
}

// Copyright 2017 The Fuchsia Authors
//
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT

#ifndef ZIRCON_KERNEL_ARCH_X86_HYPERVISOR_VMEXIT_PRIV_H_
#define ZIRCON_KERNEL_ARCH_X86_HYPERVISOR_VMEXIT_PRIV_H_

#include <zircon/types.h>

#include <arch/x86/registers.h>
#include <hypervisor/aspace.h>
#include <hypervisor/trap_map.h>

// clang-format off

// VM exit reasons.
enum class ExitReason : uint32_t {
    EXCEPTION_OR_NMI            = 0u,
    EXTERNAL_INTERRUPT          = 1u,
    TRIPLE_FAULT                = 2u,
    INIT_SIGNAL                 = 3u,
    STARTUP_IPI                 = 4u,
    IO_SMI                      = 5u,
    OTHER_SMI                   = 6u,
    INTERRUPT_WINDOW            = 7u,
    NMI_WINDOW                  = 8u,
    TASK_SWITCH                 = 9u,
    CPUID                       = 10u,
    GETSEC                      = 11u,
    HLT                         = 12u,
    INVD                        = 13u,
    INVLPG                      = 14u,
    RDPMC                       = 15u,
    RDTSC                       = 16u,
    RSM                         = 17u,
    VMCALL                      = 18u,
    VMCLEAR                     = 19u,
    VMLAUNCH                    = 20u,
    VMPTRLD                     = 21u,
    VMPTRST                     = 22u,
    VMREAD                      = 23u,
    VMRESUME                    = 24u,
    VMWRITE                     = 25u,
    VMXOFF                      = 26u,
    VMXON                       = 27u,
    CONTROL_REGISTER_ACCESS     = 28u,
    MOV_DR                      = 29u,
    IO_INSTRUCTION              = 30u,
    RDMSR                       = 31u,
    WRMSR                       = 32u,
    ENTRY_FAILURE_GUEST_STATE   = 33u,
    ENTRY_FAILURE_MSR_LOADING   = 34u,
    MWAIT                       = 36u,
    MONITOR_TRAP_FLAG           = 37u,
    MONITOR                     = 39u,
    PAUSE                       = 40u,
    ENTRY_FAILURE_MACHINE_CHECK = 41u,
    TPR_BELOW_THRESHOLD         = 43u,
    APIC_ACCESS                 = 44u,
    VIRTUALIZED_EOI             = 45u,
    ACCESS_GDTR_OR_IDTR         = 46u,
    ACCESS_LDTR_OR_TR           = 47u,
    EPT_VIOLATION               = 48u,
    EPT_MISCONFIGURATION        = 49u,
    INVEPT                      = 50u,
    RDTSCP                      = 51u,
    VMX_PREEMPT_TIMER_EXPIRED   = 52u,
    INVVPID                     = 53u,
    WBINVD_OR_WBNOINVD          = 54u,
    XSETBV                      = 55u,
    APIC_WRITE                  = 56u,
    RDRAND                      = 57u,
    INVPCID                     = 58u,
    VMFUNC                      = 59u,
    ENCLS                       = 60u,
    RDSEED                      = 61u,
    PAGE_MODIFICATION_LOG_FULL  = 62u,
    XSAVES                      = 63u,
    XRSTORS                     = 64u,
    SPP_EVENT                   = 66u,
    UMWAIT                      = 67u,
    TPAUSE                      = 68u,
    LOADIWKEY                   = 69u,
};

static inline const char* exit_reason_name(ExitReason exit_reason) {
#define EXIT_REASON_NAME(name) case ExitReason::name: return #name
    switch (exit_reason) {
    EXIT_REASON_NAME(EXCEPTION_OR_NMI);
    EXIT_REASON_NAME(EXTERNAL_INTERRUPT);
    EXIT_REASON_NAME(TRIPLE_FAULT);
    EXIT_REASON_NAME(INIT_SIGNAL);
    EXIT_REASON_NAME(STARTUP_IPI);
    EXIT_REASON_NAME(IO_SMI);
    EXIT_REASON_NAME(OTHER_SMI);
    EXIT_REASON_NAME(INTERRUPT_WINDOW);
    EXIT_REASON_NAME(NMI_WINDOW);
    EXIT_REASON_NAME(TASK_SWITCH);
    EXIT_REASON_NAME(CPUID);
    EXIT_REASON_NAME(GETSEC);
    EXIT_REASON_NAME(HLT);
    EXIT_REASON_NAME(INVD);
    EXIT_REASON_NAME(INVLPG);
    EXIT_REASON_NAME(RDPMC);
    EXIT_REASON_NAME(RDTSC);
    EXIT_REASON_NAME(RSM);
    EXIT_REASON_NAME(VMCALL);
    EXIT_REASON_NAME(VMCLEAR);
    EXIT_REASON_NAME(VMLAUNCH);
    EXIT_REASON_NAME(VMPTRLD);
    EXIT_REASON_NAME(VMPTRST);
    EXIT_REASON_NAME(VMREAD);
    EXIT_REASON_NAME(VMRESUME);
    EXIT_REASON_NAME(VMWRITE);
    EXIT_REASON_NAME(VMXOFF);
    EXIT_REASON_NAME(VMXON);
    EXIT_REASON_NAME(CONTROL_REGISTER_ACCESS);
    EXIT_REASON_NAME(MOV_DR);
    EXIT_REASON_NAME(IO_INSTRUCTION);
    EXIT_REASON_NAME(RDMSR);
    EXIT_REASON_NAME(WRMSR);
    EXIT_REASON_NAME(ENTRY_FAILURE_GUEST_STATE);
    EXIT_REASON_NAME(ENTRY_FAILURE_MSR_LOADING);
    EXIT_REASON_NAME(MWAIT);
    EXIT_REASON_NAME(MONITOR_TRAP_FLAG);
    EXIT_REASON_NAME(MONITOR);
    EXIT_REASON_NAME(PAUSE);
    EXIT_REASON_NAME(ENTRY_FAILURE_MACHINE_CHECK);
    EXIT_REASON_NAME(TPR_BELOW_THRESHOLD);
    EXIT_REASON_NAME(APIC_ACCESS);
    EXIT_REASON_NAME(VIRTUALIZED_EOI);
    EXIT_REASON_NAME(ACCESS_GDTR_OR_IDTR);
    EXIT_REASON_NAME(ACCESS_LDTR_OR_TR);
    EXIT_REASON_NAME(EPT_VIOLATION);
    EXIT_REASON_NAME(EPT_MISCONFIGURATION);
    EXIT_REASON_NAME(INVEPT);
    EXIT_REASON_NAME(RDTSCP);
    EXIT_REASON_NAME(VMX_PREEMPT_TIMER_EXPIRED);
    EXIT_REASON_NAME(INVVPID);
    EXIT_REASON_NAME(WBINVD_OR_WBNOINVD);
    EXIT_REASON_NAME(XSETBV);
    EXIT_REASON_NAME(APIC_WRITE);
    EXIT_REASON_NAME(RDRAND);
    EXIT_REASON_NAME(INVPCID);
    EXIT_REASON_NAME(VMFUNC);
    EXIT_REASON_NAME(ENCLS);
    EXIT_REASON_NAME(RDSEED);
    EXIT_REASON_NAME(PAGE_MODIFICATION_LOG_FULL);
    EXIT_REASON_NAME(XSAVES);
    EXIT_REASON_NAME(XRSTORS);
    EXIT_REASON_NAME(SPP_EVENT);
    EXIT_REASON_NAME(UMWAIT);
    EXIT_REASON_NAME(TPAUSE);
    EXIT_REASON_NAME(LOADIWKEY);
#undef EXIT_REASON_NAME
    default: return "UNKNOWN";
    }
}

// VM exit interruption type.
enum class InterruptionType : uint8_t {
    EXTERNAL_INTERRUPT          = 0u,
    NON_MASKABLE_INTERRUPT      = 2u,
    HARDWARE_EXCEPTION          = 3u,
    SOFTWARE_EXCEPTION          = 6u,
};

// X2APIC MSR addresses from Volume 3, Section 10.12.1.2.
enum class X2ApicMsr : uint32_t {
    ID                  = 0x802,
    VERSION             = 0x803,
    EOI                 = 0x80b,
    TPR                 = 0x808,
    // Read-only. Both were absent from this enum entirely, so a guest reading
    // either fell to the `default` arm and took a #GP -- including PPR, whose
    // whole purpose is to tell the guest what interrupt priority it is running
    // at, and which an APIC bring-up sequence reads.
    APR                 = 0x809,
    PPR                 = 0x80a,
    LDR                 = 0x80d,
    SVR                 = 0x80f,
    ISR_31_0            = 0x810,
    ISR_63_32           = 0x811,
    ISR_95_64           = 0x812,
    ISR_127_96          = 0x813,
    ISR_159_128         = 0x814,
    ISR_191_160         = 0x815,
    ISR_223_192         = 0x816,
    ISR_255_224         = 0x817,
    TMR_31_0            = 0x818,
    TMR_63_32           = 0x819,
    TMR_95_64           = 0x81a,
    TMR_127_96          = 0x81b,
    TMR_159_128         = 0x81c,
    TMR_191_160         = 0x81d,
    TMR_223_192         = 0x81e,
    TMR_255_224         = 0x81f,
    IRR_31_0            = 0x820,
    IRR_63_32           = 0x821,
    IRR_95_64           = 0x822,
    IRR_127_96          = 0x823,
    IRR_159_128         = 0x824,
    IRR_191_160         = 0x825,
    IRR_223_192         = 0x826,
    IRR_255_224         = 0x827,
    ESR                 = 0x828,
    LVT_CMCI            = 0x82f,
    ICR                 = 0x830,
    LVT_TIMER           = 0x832,
    LVT_THERMAL_SENSOR  = 0x833,
    LVT_MONITOR         = 0x834,
    LVT_LINT0           = 0x835,
    LVT_LINT1           = 0x836,
    LVT_ERROR           = 0x837,
    INITIAL_COUNT       = 0x838,
    // Read-only, and likewise absent: reading it is a standard step in
    // local-timer calibration.
    CURRENT_COUNT       = 0x839,
    DCR                 = 0x83e,
    SELF_IPI            = 0x83f,
};

enum class InterruptDeliveryMode : uint8_t {
    FIXED               = 0u,
    SMI                 = 2u,
    NMI                 = 4u,
    INIT                = 5u,
    STARTUP             = 6u,
};

enum class InterruptDestinationMode : bool {
    PHYSICAL            = false,
    LOGICAL             = true,
};

enum class InterruptDestinationShorthand : uint8_t {
    NO_SHORTHAND        = 0u,
    SELF                = 1u,
    ALL_INCLUDING_SELF  = 2u,
    ALL_EXCLUDING_SELF  = 3u,
};

enum class CrAccessType : uint8_t {
    MOV_TO_CR           = 0u,
    MOV_FROM_CR         = 1u,
    CLTS                = 2u,
    LMSW                = 3u,
};

enum VmCallStatus : int64_t {
    OK                  = 0,
    NOT_PERMITTED       = -1,
    FAULT               = -14,
    NOT_SUPPORTED       = -95,
    UNKNOWN_HYPERCALL   = -1000,
};

enum class VmCallType : uint64_t {
    CLOCK_PAIRING       = 9u,
};

// clang-format on

constexpr uint32_t kIpiBroadcastDestination = 0xffff'ffff;

typedef struct zx_port_packet zx_port_packet_t;

class AutoVmcs;
class EoiBitmap;
struct GuestState;
struct LocalApicState;
struct PvClockState;
struct VcpuEnlightenment;

// Stores VM exit info from VMCS fields.
struct ExitInfo {
  bool entry_failure;
  ExitReason exit_reason;
  uint32_t exit_instruction_length;
  uint64_t guest_rip;

  explicit ExitInfo(const AutoVmcs& vmcs);
};

// Stores VM exit interruption information. See Volume 3, Section 24.9.2.
struct ExitInterruptionInfo {
  uint8_t vector;
  InterruptionType interruption_type;
  bool error_code_valid;
  bool valid;

  explicit ExitInterruptionInfo(const AutoVmcs& vmcs);
};

struct PageFaultInfo {
  uint flags;

  explicit PageFaultInfo(uint32_t error_code);
};

// Stores EPT violation info from the VMCS exit qualification field.
struct EptViolationInfo {
  bool read;
  bool write;
  bool instruction;

  explicit EptViolationInfo(uint64_t qualification);
};

// Stores control register access info from the VMCS exit qualification field.
struct CrAccessInfo {
  uint8_t cr_number;
  CrAccessType access_type;
  uint8_t reg;

  explicit CrAccessInfo(uint64_t qualification);
};

// Stores IO instruction info from the VMCS exit qualification field.
struct IoInfo {
  uint8_t access_size;
  bool input;
  bool string;
  bool repeat;
  uint16_t port;

  explicit IoInfo(uint64_t qualification);
};

// Stores VMCALL type and arguments.
struct VmCallInfo {
  VmCallType type;
  uint64_t arg[4];

  explicit VmCallInfo(const GuestState& guest_state);
};

// Interrupt command register.
struct InterruptCommandRegister {
  uint32_t destination;
  enum InterruptDestinationMode destination_mode;
  enum InterruptDeliveryMode delivery_mode;
  enum InterruptDestinationShorthand destination_shorthand;
  uint8_t vector;

  InterruptCommandRegister(uint32_t hi, uint32_t lo);
};

// Returns the x2APIC Logical Destination Register value for |apic_id|.
//
// From Volume 3, Section 10.12.10.2: in x2APIC mode the LDR is read-only and
// architecturally derived from the (32-bit) x2APIC ID:
//   LDR[31:16] = cluster ID = x2APIC ID[19:4]
//   LDR[15:0]  = logical ID = 1 << (x2APIC ID[3:0])
// A VCPU's x2APIC ID is its VPID - 1, matching X2ApicMsr::ID.
uint32_t x2apic_logical_id(uint32_t apic_id);

// Maps a logical-mode ICR destination onto a mask of VCPU indices, as carried by
// ZX_PKT_GUEST_VCPU_INTERRUPT.
//
// The destination is encoded exactly like an LDR: a cluster ID in bits 31:16 and
// a 16-bit "one bit per VCPU within the cluster" field in bits 15:0. A VCPU is a
// target when its own cluster equals the destination's cluster and its bit is set
// in the destination's mask, so cluster N occupies bits [16N, 16N+16) of the
// returned mask. A destination naming a cluster that holds no VCPU (that is, past
// Guest::kMaxGuestVcpus) matches nothing and yields the empty mask.
//
// The broadcast destination (kIpiBroadcastDestination) is *not* handled here: it
// is broadcast in both destination modes and is decoded by the caller.
uint64_t x2apic_logical_target_mask(uint32_t destination);

// Refreshes the xAPIC registers that VMX reads directly from the per-VCPU
// virtual-APIC page. No-op while the VCPU is in x2APIC mode.
void SyncVirtualApicPage(LocalApicState& local_apic_state, uint32_t apic_id);

// Applies one userspace-decoded xAPIC MMIO access to the same local-APIC state
// and side-effect machinery used by VMX's accelerated APIC-write exits.
zx::result<uint32_t> ReadXapicRegister(LocalApicState& local_apic_state, uint32_t apic_id,
                                       uint32_t offset);
zx::result<> WriteXapicRegister(AutoVmcs& vmcs, LocalApicState& local_apic_state,
                                const EoiBitmap& eoi_interest, uint32_t offset, uint32_t value,
                                zx_port_packet_t& packet);

zx::result<> vmexit_handler(AutoVmcs& vmcs, GuestState& guest_state,
                            LocalApicState& local_apic_state, PvClockState& pv_clock,
                            Guest& guest, hypervisor::GuestPhysicalAspace& gpa,
                            hypervisor::TrapMap& traps,
                            zx_port_packet_t& packet, const VcpuEnlightenment& enlightenment,
                            uint16_t vpid, int64_t tsc_offset, const EoiBitmap& eoi_interest,
                            UnhandledMsrLog& unhandled_msrs, UnhandledIoLog& unhandled_io,
                            uint64_t& host_nmis_redispatched);

// Records and announces a guest RDMSR/WRMSR this hypervisor does not implement.
// See UnhandledMsrLog for what is logged, and why the first occurrence of any
// register is never rate-limited away.
void announce_unhandled_msr(UnhandledMsrLog& log, uint32_t msr, uint64_t guest_rip, bool is_write,
                            uint64_t value, bool gp_injected);

// Records and announces guest I/O to a port no VMM registered, which is now
// defaulted rather than fatal. See UnhandledIoLog for why a defaulted READ in
// particular must never be silent.
void announce_unhandled_io(UnhandledIoLog& log, uint16_t port, uint64_t guest_rip, bool is_read,
                           uint8_t access_size, uint64_t value);

// The value an unclaimed I/O port reads back: all-ones, in the width of the
// access. Named rather than open-coded so the one place that decides "what does
// absent hardware answer" is greppable, and so a test can state the same rule
// without copying a mask.
constexpr uint64_t unclaimed_io_read_value(uint8_t access_size) {
  switch (access_size) {
    case 1:
      return 0xff;
    case 2:
      return 0xffff;
    default:
      return 0xffffffff;
  }
}

// Computes the standard-format XSAVE area size for a set of XCR0 components.
//
// A parameter wherever it is used below, rather than a direct call, so the rules
// that depend on it can be driven against a synthetic machine. Read from the
// Measures a machine's XSAVE area for a candidate XCR0. A function pointer so
// the rules below can be driven against a synthetic machine — an AVX-512 host,
// say — rather than only the part this kernel happens to be running on.
using XsaveSizeFn = zx::result<uint32_t> (*)(uint64_t xcr0);

// The XSAVE state components a guest is NOT told about, because this hypervisor
// cannot back them. Cleared from guest CPUID leaf 0xD (both the component bitmap
// and each component's own subleaf) and removed from ValidateGuestXcr0's
// `supported` mask, so the set advertised and the set accepted cannot drift.
//
// MPX (bits 3,4): x86_extended_register_enable_feature() reports it "Currently
// unsupported", so host support is not evidence that we back it. A guest that
// believed CPUID got a refused XSETBV and a BNDMK faulting for no visible reason.
//
// NOTE this is a DENYLIST: a component nobody names here is advertised by
// default on whatever silicon has it.
//
// AVX-512 (bits 5,6,7): ValidateGuestXcr0 refuses it on every host,
// because its standard XSAVE area is roughly 2.5 KiB and cannot fit the 1 KiB
// X86_MAX_EXTENDED_REGISTER_SIZE bound -- so leaving it advertised is a
// guaranteed lie on any AVX-512 part: the guest is told the components exist and
// its XSETBV is then refused. handle_cpuid ALREADY clears the AVX-512 feature
// bits from leaf 7, so before this the two leaves contradicted each other. The
// feature bits and the state components have to move together.
//
// Withholding it here also makes an XSETBV that takes effect (see
// handle_xsetbv) safe by construction rather than by the size bound alone: a
// component the guest is never told about cannot be named in a guest XCR0, so
// the guest cannot enlarge its XSAVE area past the kernel's fixed buffers.
// GROWING X86_MAX_EXTENDED_REGISTER_SIZE is the alternative and is deliberately
// not taken: every part this kernel runs on is Skylake / Coffee Lake / Apollo
// Lake era, none has AVX-512, and the owner has deprioritised it.
// AMX (bits 17,18): the same lie as AVX-512 and for the same reason -- XTILEDATA
// alone is 8 KiB, so ValidateGuestXcr0's 1 KiB bound refuses it on every part that
// has it. No X86_XSAVE_STATE_BIT_* names exist for these because nothing else in
// this tree refers to them; ValidateGuestXcr0Rules names them locally too.
//
// PKRU (bit 9) is deliberately NOT here and is the residual this denylist cannot
// express. Its standard-layout OFFSET depends on which components precede it, so
// on a part with AVX-512 it sits past 1 KiB and the validator refuses it even
// though PKRU itself is eight bytes -- while on a part without AVX-512 it fits.
// A hand-maintained list cannot say that. What catches it instead is an
// assertion, on the real host, that the set this function advertises is one
// ValidateGuestXcr0 accepts; see vcpu_restore_validator_rules.
inline constexpr uint64_t kGuestWithheldXsaveComponents =
    X86_XSAVE_STATE_BIT_MPX_BNDREG | X86_XSAVE_STATE_BIT_MPX_BNDCSR |
    X86_XSAVE_STATE_BIT_AVX512_OPMASK | X86_XSAVE_STATE_BIT_AVX512_LOWERZMM_HIGH |
    X86_XSAVE_STATE_BIT_AVX512_HIGHERZMM | (uint64_t{1} << 17) | (uint64_t{1} << 18);

// The XSAVE component set a guest may name in XCR0, given what a machine
// supports (CPUID.(EAX=0DH,ECX=0).EDX:EAX).
//
// Exists so that "what CPUID advertises" and "what ValidateGuestXcr0 accepts"
// are one expression rather than two applications of the same constant, and so
// that the set can be checked against a synthetic machine this hardware is not
// -- an AVX-512 part, in particular, which neither machine here is.
constexpr uint64_t GuestXsaveComponents(uint64_t host_supported) {
  return host_supported & ~kGuestWithheldXsaveComponents;
}

// The four registers a guest reads from CPUID.(EAX=0DH,ECX=0).
struct XsaveMainLeaf {
  uint32_t eax;  // component bitmap, low half
  uint32_t ebx;  // size for the components ENABLED in the guest's XCR0
  uint32_t ecx;  // size for the components the guest is allowed to enable
  uint32_t edx;  // component bitmap, high half
};

// Derives that leaf from a machine's component bitmap and a guest's XCR0.
//
// A free function taking |host_supported| and |xsave_size_fn| rather than code
// inside handle_cpuid, for the same reason ValidateGuestXcr0Rules is: the
// interesting cases are on parts neither machine here is. The bitmap mask only
// changes ECX where a WITHHELD component would have extended the layout, and on
// on a measured Coffee Lake processor the withheld set is MPX alone -- so the
// difference between the honest ECX and the host's is 256 bytes there and
// nothing at all on a part without MPX. On an AVX-512 part it is the difference
// between 832 and ~2.5 KiB, and that is the case the synthetic machine in
// unittests/guest_enter_test.cc exists to reach.
//
// All four fields move together here BY CONSTRUCTION: there is one `advertised`
// expression and both sizes are measured against it. Splitting them is what
// produced a guest CPUID that named three components and sized five.
zx::result<XsaveMainLeaf> GuestXsaveMainLeaf(uint64_t host_supported, uint64_t guest_xcr0,
                                             XsaveSizeFn xsave_size_fn);

// Checks a candidate guest XCR0 against everything XSETBV would #GP on, plus the
// size of this kernel's fixed XSAVE buffers. Returns ZX_ERR_INVALID_ARGS for a
// value the host must not load.
//
// This exists as a shared entry point because the value reaches the same
// host-context `x86_xsetbv()` from two directions: the guest executing XSETBV
// (handled here) and a VMM restoring a VCPU snapshot (Vcpu::RestoreArchState).
// The register is loaded while the *host* is running, so an illegal value faults
// the kernel rather than the guest.
zx::result<> ValidateGuestXcr0(uint64_t xcr0);

// The rules ValidateGuestXcr0() applies, with everything it would read from this
// CPU passed in instead.
//
// Exposed so the rules can be driven against a synthetic machine -- see
// XsaveSizeFn. |supported| is the component set the guest is allowed to name,
// i.e. GuestXsaveComponents() on a real host; passing raw silicon here is the
// drift this file exists to prevent. A validator that merely whitelisted the one
// value a snapshot round trip produces would pass every test on real hardware,
// which is the other reason the rules are reachable from a table.
zx::result<> ValidateGuestXcr0Rules(uint64_t xcr0, bool xsave_supported, uint64_t supported,
                                    XsaveSizeFn xsave_size_fn);

// The host environment a caller-supplied XSAVE image will be restored into.
struct XsaveRestoreEnv {
  // Which of XRSTORS / XRSTOR / FXRSTOR this host issues. They do not share a
  // fault matrix, so the check has to know.
  enum x86_extended_register_restore_kind instruction;
  // The XCR0 that will be live, in host context, when the image is restored.
  uint64_t live_xcr0;
  // This part's real MXCSR_MASK; every bit outside it is reserved.
  uint32_t mxcsr_mask;
};

// Checks a caller-supplied XSAVE image against everything the restore
// instruction this host issues would #GP on. Returns ZX_ERR_INVALID_ARGS for an
// image the host must not load. |image| must be at least
// X86_MAX_EXTENDED_REGISTER_SIZE bytes.
//
// The image is restored by swap_extended_registers() while the *host* is
// running, so an illegal one faults the kernel rather than the guest -- the same
// shape of bug, and the same class of caller, as an illegal XCR0.
zx::result<> ValidateGuestXsaveImage(const uint8_t* image, uint64_t guest_xcr0);

// The rules ValidateGuestXsaveImage() applies, against a caller-supplied
// environment rather than this CPU's. Exposed for the same reason
// ValidateGuestXcr0Rules is: on any one part only one of the three restore
// instructions is ever reachable.
zx::result<> ValidateXsaveImageRules(const uint8_t* image, const XsaveRestoreEnv& env);

// Arms the guest's local-APIC one-shot timer to fire at |deadline| (a monotonic
// time), or cancels it when |deadline| == 0. Used by VCPU snapshot restore to
// reconstruct the live Timer from captured state.
void RearmApicTimer(LocalApicState& local_apic_state, zx_instant_mono_t deadline);

#endif  // ZIRCON_KERNEL_ARCH_X86_HYPERVISOR_VMEXIT_PRIV_H_

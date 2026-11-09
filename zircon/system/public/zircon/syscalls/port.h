// Copyright 2016 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ZIRCON_SYSCALLS_PORT_H_
#define ZIRCON_SYSCALLS_PORT_H_

#include <zircon/compiler.h>
#include <zircon/types.h>

__BEGIN_CDECLS

// clang-format off

// zx_object_wait_async() options
// Do not use ZX_WAIT_ASYNC_ONCE. It is now superfluous and will be removed.
#define ZX_WAIT_ASYNC_ONCE            ((uint32_t)0u)
#define ZX_WAIT_ASYNC_TIMESTAMP       ((uint32_t)1u)
#define ZX_WAIT_ASYNC_EDGE            ((uint32_t)2u)
#define ZX_WAIT_ASYNC_BOOT_TIMESTAMP  ((uint32_t)4u)

typedef uint32_t zx_packet_type_t;

// packet types.  zx_port_packet_t::type
#define ZX_PKT_TYPE_USER              ((zx_packet_type_t)0x00u)
#define ZX_PKT_TYPE_SIGNAL_ONE        ((zx_packet_type_t)0x01u)
// 0x02 was previously used for "ZX_PKT_TYPE_SIGNAL_REP".
#define ZX_PKT_TYPE_GUEST_BELL        ((zx_packet_type_t)0x03u)
#define ZX_PKT_TYPE_GUEST_MEM         ((zx_packet_type_t)0x04u)
#define ZX_PKT_TYPE_GUEST_IO          ((zx_packet_type_t)0x05u)
#define ZX_PKT_TYPE_GUEST_VCPU        ((zx_packet_type_t)0x06u)
#define ZX_PKT_TYPE_INTERRUPT         ((zx_packet_type_t)0x07u)
#define ZX_PKT_TYPE_GUEST_EXCEPTION   ((zx_packet_type_t)0x08u)
#define ZX_PKT_TYPE_PAGE_REQUEST      ((zx_packet_type_t)0x09u)
// 0x0A reserved for RPPM, see syscall-next.h
#define ZX_PKT_TYPE_GUEST_MSR         ((zx_packet_type_t)0x0Bu)
#define ZX_PKT_TYPE_GUEST_HYPERCALL   ((zx_packet_type_t)0x0Cu)
#define ZX_PKT_TYPE_GUEST_HALT        ((zx_packet_type_t)0x0Du)
#define ZX_PKT_TYPE_GUEST_EOI         ((zx_packet_type_t)0x0Eu)
#define ZX_PKT_TYPE_GUEST_EXIT_OBSERVATION ((zx_packet_type_t)0x0Fu)
#define ZX_PKT_TYPE_GUEST_INSTRUCTION_BUDGET ((zx_packet_type_t)0x10u)
#define ZX_PKT_TYPE_GUEST_MEMORY_ACCESS ((zx_packet_type_t)0x11u)
#define ZX_PKT_TYPE_GUEST_INTEL_PT ((zx_packet_type_t)0x12u)
#define ZX_PKT_TYPE_GUEST_HARDWARE_BREAKPOINT ((zx_packet_type_t)0x13u)
// 0xffffffff is reserved for internal use.

// For options passed to port_create
#define ZX_PORT_BIND_TO_INTERRUPT     ((uint32_t)(0x1u << 0))

#define ZX_PKT_IS_USER(type)          ((type) == ZX_PKT_TYPE_USER)
#define ZX_PKT_IS_SIGNAL_ONE(type)    ((type) == ZX_PKT_TYPE_SIGNAL_ONE)
#define ZX_PKT_IS_GUEST_BELL(type)    ((type) == ZX_PKT_TYPE_GUEST_BELL)
#define ZX_PKT_IS_GUEST_MEM(type)     ((type) == ZX_PKT_TYPE_GUEST_MEM)
#define ZX_PKT_IS_GUEST_IO(type)      ((type) == ZX_PKT_TYPE_GUEST_IO)
#define ZX_PKT_IS_GUEST_VCPU(type)    ((type) == ZX_PKT_TYPE_GUEST_VCPU)
#define ZX_PKT_IS_GUEST_EXCEPTION(type) ((type) == ZX_PKT_TYPE_GUEST_EXCEPTION)
#define ZX_PKT_IS_GUEST_MSR(type)     ((type) == ZX_PKT_TYPE_GUEST_MSR)
#define ZX_PKT_IS_GUEST_HYPERCALL(type) ((type) == ZX_PKT_TYPE_GUEST_HYPERCALL)
#define ZX_PKT_IS_GUEST_EOI(type)     ((type) == ZX_PKT_TYPE_GUEST_EOI)
#define ZX_PKT_IS_GUEST_EXIT_OBSERVATION(type) \
  ((type) == ZX_PKT_TYPE_GUEST_EXIT_OBSERVATION)
#define ZX_PKT_IS_GUEST_INSTRUCTION_BUDGET(type) \
  ((type) == ZX_PKT_TYPE_GUEST_INSTRUCTION_BUDGET)
#define ZX_PKT_IS_GUEST_MEMORY_ACCESS(type) ((type) == ZX_PKT_TYPE_GUEST_MEMORY_ACCESS)
#define ZX_PKT_IS_GUEST_INTEL_PT(type) ((type) == ZX_PKT_TYPE_GUEST_INTEL_PT)
#define ZX_PKT_IS_GUEST_HARDWARE_BREAKPOINT(type) \
  ((type) == ZX_PKT_TYPE_GUEST_HARDWARE_BREAKPOINT)
#define ZX_PKT_IS_INTERRUPT(type)     ((type) == ZX_PKT_TYPE_INTERRUPT)
#define ZX_PKT_IS_PAGE_REQUEST(type)  ((type) == ZX_PKT_TYPE_PAGE_REQUEST)

// zx_packet_guest_vcpu_t::type
#define ZX_PKT_GUEST_VCPU_INTERRUPT   ((uint32_t)0)
#define ZX_PKT_GUEST_VCPU_STARTUP     ((uint32_t)1)

// zx_packet_page_request_t::command
#define ZX_PAGER_VMO_READ             ((uint16_t) 0)
#define ZX_PAGER_VMO_COMPLETE         ((uint16_t) 1)
#define ZX_PAGER_VMO_DIRTY            ((uint16_t) 2)
// clang-format on

// port_packet_t::type ZX_PKT_TYPE_USER.
typedef union zx_packet_user {
  uint64_t u64[4];
  uint32_t u32[8];
  uint16_t u16[16];
  uint8_t c8[32];
} zx_packet_user_t;

// port_packet_t::type ZX_PKT_TYPE_SIGNAL_ONE.
typedef struct zx_packet_signal {
  zx_signals_t trigger;
  zx_signals_t observed;
  uint64_t count;
  zx_time_t timestamp;
  uint64_t reserved1;
} zx_packet_signal_t;

typedef struct zx_packet_guest_bell {
  zx_gpaddr_t addr;
  uint64_t reserved0;
  uint64_t reserved1;
  uint64_t reserved2;
} zx_packet_guest_bell_t;

typedef struct zx_packet_guest_mem {
  zx_gpaddr_t addr;
#if __aarch64__
  uint8_t access_size;
  bool sign_extend;
  uint8_t xt;
  bool read;
  uint8_t padding1[4];
  uint64_t data;
  uint64_t reserved;
#elif __x86_64__
  zx_gpaddr_t cr3;
  zx_vaddr_t rip;
  uint8_t instruction_size;
  // This is the default operand size as determined by the CS and EFER register (Volume 3,
  // Section 5.2.1). If operating in 64-bit mode then near branches and all instructions, except
  // far branches, that implicitly reference the RSP will actually have a default operand size of
  // 64-bits (Volume 2, Section 2.2.1.7), and not the 32-bits that will be given here.
  uint8_t default_operand_size;
  uint8_t reserved[6];
#else
  uint64_t reserved[3];
#endif
} zx_packet_guest_mem_t;

typedef struct zx_packet_guest_io {
  uint16_t port;
  uint8_t access_size;
  bool input;
  union {
    struct {
      uint8_t u8;
      uint8_t padding1[3];
    };
    struct {
      uint16_t u16;
      uint8_t padding2[2];
    };
    uint32_t u32;
    uint8_t data[4];
  };
  uint64_t reserved0;
  uint64_t reserved1;
  uint64_t reserved2;
} zx_packet_guest_io_t;

typedef struct zx_packet_guest_vcpu {
  uint32_t type;
  uint8_t padding1[4];
  union {
    struct {
      uint64_t mask;
      uint8_t vector;
      uint8_t padding1[7];
    } interrupt;
    struct {
      uint64_t id;
      zx_gpaddr_t entry;
    } startup;
  };
  uint64_t reserved;
} zx_packet_guest_vcpu_t;

// Delivered when a guest raises an exception that the hypervisor is configured
// to trap to the host (e.g. a breakpoint / INT3 used for software-breakpoint
// coverage instrumentation). `rip` is the guest instruction pointer at the exit;
// for an intercepted #BP it is the address of the trapping INT3 itself, so a VMM
// can restore the original byte and resume without repositioning RIP.
typedef struct zx_packet_guest_exception {
  uint64_t rip;
  uint64_t error_code;
  uint32_t vector;
  uint8_t padding1[4];
  uint64_t reserved;
} zx_packet_guest_exception_t;

// Delivered when a guest accesses a model-specific register the VMM has claimed
// (see the synthetic-MSR delegation on a VCPU). The guest's instruction pointer
// has already been advanced past the RDMSR/WRMSR, so a read is completed simply
// by writing the value the guest should observe into rax/rdx via
// zx_vcpu_write_state before resuming.
typedef struct zx_packet_guest_msr {
  // The register selected by the guest in ecx.
  uint64_t msr;
  // For a write, the value the guest supplied in edx:eax. Zero for a read.
  uint64_t value;
  // True if the guest executed WRMSR, false for RDMSR.
  uint8_t is_write;
  uint8_t padding1[7];
  uint64_t reserved;
} zx_packet_guest_msr_t;

// Delivered when a guest issues a hypercall the VMM has claimed. As with an MSR
// read, the instruction pointer is already past the instruction, so the VMM
// returns a result by writing rax via zx_vcpu_write_state before resuming.
typedef struct zx_packet_guest_hypercall {
  // Guest rcx: the call code and flags identifying the requested operation.
  uint64_t input;
  // Guest rdx and r8: the operands, which are either addresses of parameter
  // pages or, for a register-passed call, the parameters themselves.
  uint64_t arg0;
  uint64_t arg1;
  uint64_t reserved;
} zx_packet_guest_hypercall_t;

// Delivered when a guest ends an interrupt whose vector the VMM has registered
// interest in with zx_guest_set_trap(ZX_GUEST_TRAP_EOI, vector, 1, ...).
//
// The guest's local APIC is in-kernel and consumes the EOI itself: the
// in-service bit is already cleared and the guest's instruction pointer is
// already past the WRMSR, so this packet reports something that has *happened*
// rather than asking the VMM to complete anything. The VMM resumes the VCPU
// with no state to write back.
//
// It exists for one reason: a level-triggered IO-APIC line sets `remote IRR` on
// delivery and refuses to deliver again until an EOI clears it, and an
// IO-APIC emulated in userspace cannot see an EOI the kernel consumed. Without
// this, such a line delivers once and then stops for as long as its driver
// leaves the redirection entry alone -- which, for a driver that services the
// interrupt without masking and unmasking around it, is the life of the guest.
//
// Registration is per vector and per guest, and is deliberately not the default:
// an EOI is the last instruction of every interrupt handler, so an unregistered
// EOI must stay a no-exit path. Register only the vectors a level-triggered line
// is programmed with — pass len 1 to register a vector, len 0 to unregister it.
// The three reserved words are not padding for its own sake: zx_port_packet_t's
// union must have no padding at all — the kernel refuses to copy a type that
// does, since the bytes it did not write would leak — so every member is
// exactly 32 bytes.
typedef struct zx_packet_guest_eoi {
  // The vector the guest's EOI ended: the highest vector that was in service.
  uint64_t vector;
  uint64_t reserved[3];
} zx_packet_guest_eoi_t;

// A one-shot, post-handler VM-exit boundary requested through
// ZX_VCPU_STATE_EXIT_CONTROL.
//
// The kernel has completed its normal handling before this packet is returned.
// If the original exit first required a different userspace packet, that packet
// is returned first and this observation is returned at the next
// zx_vcpu_enter(), before another VM entry. The VMM must acknowledge `sequence`
// through ZX_VCPU_STATE_EXIT_CONTROL before the VCPU can enter again.
#define ZX_PKT_GUEST_EXIT_OBSERVATION_REASON ((uint32_t)(1u << 0))
#define ZX_PKT_GUEST_EXIT_OBSERVATION_BUDGET ((uint32_t)(1u << 1))

typedef struct zx_packet_guest_exit_observation {
  // Monotonic non-zero sequence used for explicit acknowledgement.
  uint64_t sequence;
  // RIP reported by the VM exit before normal handling.
  zx_vaddr_t exit_rip;
  // RIP from the handled machine state. This proves an instruction-side exit
  // was completed before the stop and prevents resume from replaying it.
  zx_vaddr_t resume_rip;
  // Architectural VM-exit reason.
  uint32_t exit_reason;
  // ZX_PKT_GUEST_EXIT_OBSERVATION_* trigger flags.
  uint32_t flags;
} zx_packet_guest_exit_observation_t;

// One-shot retired-instruction budget reached after guest execution. Counting
// is enabled by VM entry and disabled by VM exit, so host instructions are not
// included. `retired_instructions` is the exact hardware count and may exceed
// `requested_budget` by the PMU interrupt-delivery skid.
typedef struct zx_packet_guest_instruction_budget {
  // Monotonic non-zero sequence used for explicit acknowledgement.
  uint64_t sequence;
  uint64_t requested_budget;
  uint64_t retired_instructions;
  // Guest RIP of the paused machine state observed at the eventual
  // overflow-interrupt exit, after any normal exit handling.
  zx_vaddr_t rip;
} zx_packet_guest_instruction_budget_t;

// Guest-global pre-access EPT stop. The complete processor classification and
// coincident-range mask are read through ZX_VCPU_STATE_MEMORY_ACCESS_CONTROL.
typedef struct zx_packet_guest_memory_access {
  // Monotonic non-zero sequence used for explicit acknowledgement.
  uint64_t sequence;
  zx_gpaddr_t guest_paddr;
  // Zero when the EPT qualification did not mark the guest-linear address
  // field valid.
  zx_vaddr_t guest_vaddr;
  // RIP of the instruction that has not yet executed its selected access.
  zx_vaddr_t rip;
} zx_packet_guest_memory_access_t;

// One immutable Intel PT watermark or terminal boundary. Raw bytes and the
// complete status record are read through ZX_VCPU_STATE_INTEL_PT_CONTROL.
typedef struct zx_packet_guest_intel_pt {
  uint64_t segment_sequence;
  uint64_t trace_generation;
  uint64_t producer_cursor;
  uint32_t status_flags;
  uint32_t reserved;
} zx_packet_guest_intel_pt_t;

// Transparent hardware-breakpoint one-shot. The complete DR6 and boundary
// record is read through ZX_VCPU_STATE_HARDWARE_BREAKPOINT_CONTROL.
typedef struct zx_packet_guest_hardware_breakpoint {
  uint64_t sequence;
  zx_vaddr_t rip;
  uint64_t condition_mask;
  uint16_t vpid;
  uint8_t slot_mask;
  uint8_t boundary;
  uint32_t reserved;
} zx_packet_guest_hardware_breakpoint_t;

// Why a VCPU stopped in a way it cannot be resumed from.
//
// A guest that faults while it has no usable handler for the fault — the classic
// case being a fault taken before the guest has installed its descriptor tables —
// gives up and shuts down. Without a way to report that, such a guest looks
// identical to one that is merely slow, so this exists to make the difference
// visible to the VMM rather than only to the kernel log.
#define ZX_PKT_GUEST_HALT_TRIPLE_FAULT ((uint32_t)0)
// The exit reason had no handler. Reported rather than ignored, since resuming a
// guest whose exit was not serviced usually means taking the same exit again.
#define ZX_PKT_GUEST_HALT_UNHANDLED    ((uint32_t)1)

typedef struct zx_packet_guest_halt {
  // One of ZX_PKT_GUEST_HALT_*.
  uint32_t reason;
  // For ZX_PKT_GUEST_HALT_UNHANDLED, the architectural exit reason, so the VMM
  // can say which one went unserviced. Zero otherwise.
  uint32_t exit_reason;
  // Where the guest was executing when it stopped.
  zx_vaddr_t rip;
  // The guest-physical address the exit named, for the exit reasons that have
  // one: EPT violation (48) and EPT misconfiguration (49). Zero otherwise.
  //
  // Without it an unserviced EPT exit told a VMM only "something about memory
  // went wrong somewhere", and the one artifact that knew the address was a
  // kernel log line the VMM cannot read. Check `exit_reason` before reading it;
  // there is no separate validity flag because `exit_reason` already is one.
  zx_gpaddr_t physical_address;
  // Every member of the zx_port_packet union is exactly 32 bytes. A shorter one
  // would leave padding in the union, which the user_copy ABI-safety assert
  // rejects: padding cannot be copied to userspace without leaking whatever the
  // kernel stack happened to hold there.
  uint64_t reserved1;
} zx_packet_guest_halt_t;

typedef struct zx_packet_interrupt {
  zx_instant_boot_t timestamp;
  uint64_t reserved0;
  uint64_t reserved1;
  uint64_t reserved2;
} zx_packet_interrupt_t;

typedef struct zx_packet_page_request {
  uint16_t command;
  uint16_t flags;
  uint32_t reserved0;
  uint64_t offset;
  uint64_t length;
  uint64_t reserved1;
} zx_packet_page_request_t;

typedef struct {
  /// Request targeting the provided power domain.
  uint32_t domain_id;

  // Options applying to this transition.
  uint32_t options;

  // Control Interface ID provided in the energy model.
  uint64_t control_interface;

  // Control Interface Argument provided in the energy model.
  uint64_t control_argument;

  // Padding bits.
  uint64_t reserved;

} zx_packet_processor_power_level_transition_request_t;

typedef struct zx_port_packet {
  uint64_t key;
  zx_packet_type_t type;
  zx_status_t status;
  union {
    zx_packet_user_t user;
    zx_packet_signal_t signal;
    zx_packet_guest_bell_t guest_bell;
    zx_packet_guest_mem_t guest_mem;
    zx_packet_guest_io_t guest_io;
    zx_packet_guest_vcpu_t guest_vcpu;
    zx_packet_guest_exception_t guest_exception;
    zx_packet_guest_msr_t guest_msr;
    zx_packet_guest_hypercall_t guest_hypercall;
    zx_packet_guest_halt_t guest_halt;
    zx_packet_guest_eoi_t guest_eoi;
    zx_packet_guest_exit_observation_t guest_exit_observation;
    zx_packet_guest_instruction_budget_t guest_instruction_budget;
    zx_packet_guest_memory_access_t guest_memory_access;
    zx_packet_guest_intel_pt_t guest_intel_pt;
    zx_packet_guest_hardware_breakpoint_t guest_hardware_breakpoint;
    zx_packet_interrupt_t interrupt;
    zx_packet_page_request_t page_request;
    zx_packet_processor_power_level_transition_request_t processor_power_level_transition;
  };
} zx_port_packet_t;

__END_CDECLS

#endif  // ZIRCON_SYSCALLS_PORT_H_

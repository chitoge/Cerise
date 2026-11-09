// Copyright 2017 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ZIRCON_SYSCALLS_HYPERVISOR_H_
#define ZIRCON_SYSCALLS_HYPERVISOR_H_

#include <zircon/types.h>

__BEGIN_CDECLS

// clang-format off
typedef uint32_t zx_guest_trap_t;

#define ZX_GUEST_TRAP_BELL ((zx_guest_trap_t) 0u)
#define ZX_GUEST_TRAP_MEM  ((zx_guest_trap_t) 1u)
#define ZX_GUEST_TRAP_IO   ((zx_guest_trap_t) 2u)
// Deliver a ZX_PKT_TYPE_GUEST_EOI packet when the guest ends an interrupt whose
// vector is `addr`. `len` is 1 to register the vector and 0 to unregister it;
// `port` must be ZX_HANDLE_INVALID, since the packet is delivered through
// zx_vcpu_enter() like every other guest exit, and `key` must be 0, since a
// packet delivered that way carries no key. `addr` must be a valid vector
// (below 256).
//
// This is the one guest exit that is registered per *vector* rather than per
// address range, and the one whose default must be "no exit": an EOI ends every
// interrupt a guest takes, so trapping them all would put a userspace round trip
// on every interrupt. See zx_packet_guest_eoi_t for what it is for.
//
// REGISTER THE TRAP BEFORE THE VECTOR CAN BE DELIVERED. Registration is
// consulted when a vector is ADMITTED (it is what declines a Hyper-V lazy-EOI
// grant for that vector), so a registration that lands while a grant for the
// same vector is already outstanding does not retroactively cancel it: that one
// EOI is completed lazily, with no exit and no packet. For a level-triggered
// line whose emulated remote-IRR is cleared by that packet, missing a single
// notification wedges the line. Registering before the device can raise the
// vector -- as part of building the redirection entry, not in response to
// traffic on it -- avoids the window entirely.
#define ZX_GUEST_TRAP_EOI  ((zx_guest_trap_t) 3u)

// Create the VCPU with its local APIC enabled in xAPIC mode. Without this
// option, an x86 VCPU keeps the legacy ABI and starts in x2APIC mode.
//
// This controls reset state, not CPUID: the VMM must separately make the
// guest's advertised x2APIC support agree with the selected initial mode.
#define ZX_VCPU_CREATE_XAPIC ((uint32_t)(1u << 0))

typedef uint32_t zx_vcpu_state_topic_t;

// Rename to ZX_VCPU_STATE_GENERAL_REGS
#define ZX_VCPU_STATE ((zx_vcpu_state_topic_t) 0u)
// Rename to ZX_VCPU_STATE_IO_REGS
#define ZX_VCPU_IO    ((zx_vcpu_state_topic_t) 1u)
// The VCPU's complete architectural state, as a self-describing byte buffer.
//
// ZX_VCPU_STATE carries only the general registers, which is not enough to place
// a VCPU at a chosen point of execution: it omits the instruction pointer, the
// segment and descriptor-table registers, and the control and mode registers. A
// VMM that boots a guest through firmware, or that restores one, needs all of
// them.
//
// The buffer is versioned and carries its own length, so its layout is not part
// of this header and may grow without invalidating callers. Provide a buffer at
// least as large as the kernel needs — a short one is refused with
// ZX_ERR_BUFFER_TOO_SMALL rather than truncated — and read the length actually
// written from the buffer's own header. On write, a buffer that does not
// describe state this kernel understands is refused, so a mismatched producer
// cannot corrupt a VCPU.
#define ZX_VCPU_STATE_FULL ((zx_vcpu_state_topic_t) 2u)
// The paravirtual ("enlightenment") surface this VCPU presents to its guest.
//
// By default a VCPU presents the kernel's own paravirtual surface — the KVM
// identity and the in-kernel clock discovered through it — and services
// synthetic MSRs and hypercalls itself. A VMM that implements a different
// contract (notably Hyper-V, for an enlightened guest such as Windows) writes
// this topic to take ownership of the pieces it implements. Reading it back
// reports the configuration currently in effect, so it can be snapshotted
// alongside ZX_VCPU_STATE_FULL.
//
// The payload is `zx_vcpu_enlightenment_t`, which carries its own
// magic/version/size and is rejected rather than misread if it does not
// describe a configuration this kernel understands.
#define ZX_VCPU_STATE_ENLIGHTENMENT ((zx_vcpu_state_topic_t) 3u)
// The event queued for delivery into the guest on the VCPU's next entry.
//
// `zx_vcpu_interrupt()` raises a bare vector, and may be called from any thread;
// that is the right shape for an asynchronous device or IPI interrupt, but it
// cannot describe an exception. On x86, bare vectors 21 through 31 are treated
// as external interrupts as well: guests may use those reserved vectors in an
// ICR, while a typed architectural #CP uses this state topic. An exception that
// architecturally carries an error code (#DF, #TS, #NP, #SS, #GP, #PF, #AC) is
// delivered with a zero one
// through that path, and #PF additionally needs CR2 set to the faulting linear
// address. A VMM that emulates an instruction and discovers the guest faulted
// has to be able to say what actually happened.
//
// This topic carries the whole architectural payload: which of the four VMX
// interruption types the event is, its vector, whether an error code is present
// and its value, the instruction length a software exception resumes past, and
// CR2 for #PF. The payload is `zx_vcpu_pending_event_t`.
//
// It is a state topic rather than a second action syscall because a queued
// event *is* durable VCPU state until entry consumes it: reading the topic
// reports what is currently queued (so it can be snapshotted alongside
// ZX_VCPU_STATE_FULL), writing it replaces that queue wholesale, and writing
// ZX_VCPU_EVENT_NONE clears it. Like every other state topic — and unlike
// `zx_vcpu_interrupt()` and `zx_vcpu_kick()` — it must be used on the thread the
// VCPU was created on: the event is queued as part of finishing an exit, in
// order with the register writes that accompany it, and the queue holds one
// event with no cross-thread arbitration. A VMM that wants to poke a *running*
// VCPU from elsewhere still wants `zx_vcpu_interrupt()`.
#define ZX_VCPU_STATE_PENDING_EVENT ((zx_vcpu_state_topic_t) 4u)
// A software access to the VCPU's xAPIC register page. A VMM submits one
// request by writing `zx_vcpu_xapic_access_t`, then reads the same topic to
// collect the value and any device-facing side effect. This is used when an
// xAPIC MMIO access exits to userspace but the local-APIC state remains owned
// by the kernel.
#define ZX_VCPU_STATE_XAPIC_ACCESS ((zx_vcpu_state_topic_t) 5u)
// The VCPU's asynchronous, device-facing execution state: the in-kernel local
// APIC timer, pending-interrupt set, and paravirtual-clock mapping.
//
// These are live kernel objects rather than quiescent registers, so they are
// deliberately separate from ZX_VCPU_STATE_FULL. The payload is a versioned,
// self-describing byte stream. Read it only after the VCPU has cooperatively
// stopped, and restore it after ZX_VCPU_STATE_FULL but before the next entry.
// Timer deadlines are represented as remaining durations and are re-anchored
// at restore time. This topic is currently supported only on x86-64.
#define ZX_VCPU_STATE_ASYNC ((zx_vcpu_state_topic_t) 6u)
// Host-assisted debugging controls for this VCPU.
//
// Reading returns `zx_vcpu_debug_state_t`: `supported_flags` is derived from
// the controls the active hypervisor actually offers, and `active_flags`
// reports what is armed now. Writing atomically replaces `active_flags`.
// Requesting a known control that is not in `supported_flags` fails with
// ZX_ERR_NOT_SUPPORTED and leaves every control unchanged.
//
// SINGLE_STEP is one-shot. On x86 it uses VMX monitor-trap flag rather than the
// guest's RFLAGS.TF, so the resulting #DB-shaped host exit is not delivered to
// the guest and the flag is disarmed before userspace observes the exit.
#define ZX_VCPU_STATE_DEBUG ((zx_vcpu_state_topic_t) 7u)
// Host-assisted bounded-run controls for this VCPU.
//
// Reading returns `zx_vcpu_run_control_t`, including runtime-derived support
// and the VMX preemption timer's TSC-rate shift. Writing atomically replaces
// the active controls. The timer is one-shot: expiry disarms it and makes
// zx_vcpu_enter() return ZX_ERR_TIMED_OUT.
#define ZX_VCPU_STATE_RUN_CONTROL ((zx_vcpu_state_topic_t) 8u)
// Versioned, opt-in post-handler VM-exit observation and completed-exit budget.
//
// Reading returns zx_vcpu_exit_control_t with the reasons implemented by the
// active kernel. A write arms one one-shot session. When a selected reason is
// handled, or the completed-exit budget is reached, zx_vcpu_enter() returns
// ZX_PKT_TYPE_GUEST_EXIT_OBSERVATION. Normal exit handling always completes
// first. The returned sequence must be acknowledged before the VCPU can enter
// again; acknowledgement and the next arm may be one atomic write.
#define ZX_VCPU_STATE_EXIT_CONTROL ((zx_vcpu_state_topic_t) 9u)
// Versioned, opt-in guest-only retired-instruction budget.
//
// Reading returns zx_vcpu_instruction_control_t with exact runtime hardware
// and resource availability. A successful write reserves the host PMU resource
// and arms one one-shot budget. Overflow returns
// ZX_PKT_TYPE_GUEST_INSTRUCTION_BUDGET with the exact observed count; its
// sequence must be acknowledged before the VCPU can enter again.
#define ZX_VCPU_STATE_INSTRUCTION_CONTROL ((zx_vcpu_state_topic_t) 10u)
// Versioned, guest-global guest-physical memory-access stop controls.
//
// Ranges are page aligned and may overlap. A selected read, write, or execute
// access stops before the access executes and returns
// ZX_PKT_TYPE_GUEST_MEMORY_ACCESS. The exact result remains pending until its
// sequence is acknowledged. While pending, every VCPU in the guest is stopped
// and the EPT permissions remain restricted.
//
// An acknowledgement with no replacement ranges restores the exact effective
// permissions that existed at arm time. The next entry therefore retries the
// unchanged instruction and performs the access once. An acknowledgement may
// instead atomically install a replacement range set; if it still selects the
// pending access, that access stops again before executing.
#define ZX_VCPU_STATE_MEMORY_ACCESS_CONTROL ((zx_vcpu_state_topic_t) 11u)
// Versioned, opt-in raw Intel Processor Trace control and bounded data access.
//
// Configuration is typed: callers select privilege levels, branch tracing,
// architectural filter values, and a byte quota. The kernel owns every ToPA
// table and output page; no physical address, MSR value, or buffer handle
// crosses this interface. A write selects an idempotent cursor read, while the
// following read returns at most ZX_VCPU_INTEL_PT_MAX_CHUNK_BYTES immutable
// bytes. Only an explicit monotonic acknowledgement permits wholly consumed
// output pairs to be reused.
#define ZX_VCPU_STATE_INTEL_PT_CONTROL ((zx_vcpu_state_topic_t) 12u)
// Versioned, opt-in transparent hardware instruction/data breakpoints.
//
// The kernel virtualizes a bounded subset of DR0-DR3 around the guest's own
// enabled slots. Guest MOV-DR behavior and guest-visible DR state are preserved;
// a request that cannot fit fails rather than taking a guest-owned slot.
// Execute stops are pre-instruction faults, while data stops are post-access
// traps. A result is one-shot and must be acknowledged before any VCPU in the
// guest can resume.
#define ZX_VCPU_STATE_HARDWARE_BREAKPOINT_CONTROL ((zx_vcpu_state_topic_t) 13u)
// The guest-physical address of a paravirtual "no EOI required" word this VCPU
// publishes, and whether it is currently in effect (Hyper-V TLFS lazy EOI, via
// the VP assist page's `apic_assist` field — the VMM decodes the guest's own
// enlightenment MSR and relays only the resulting word address here; this
// kernel has no notion of Hyper-V, TLFS, or the VP assist page's layout).
//
// While enabled, the kernel may write 1 into that guest-physical word only
// when the external interrupt it just admitted is the sole in-service vector.
// A guest may atomically clear-and-test the word in its interrupt epilogue and,
// when it consumed 1, skip the architectural EOI entirely: a guest-memory
// operation with no VM exit. On a later VM entry, the kernel observes that
// consumption and retires that specific vector's in-service bit itself.
//
// The sole-vector rule is required because the assist word is one shared flag,
// while in-service state is per vector. Before a nested vector can execute,
// its admission revokes any outstanding grant by clearing the word; neither
// vector may then use the lazy skip. A grant is never overwritten to name the
// nested vector. Guests must consume the word with one atomic read-modify-write
// operation. A separate load followed later by a clear is unsupported: nested
// admission could revoke the grant between those instructions, leaving the
// guest to act on a stale decision.
//
// A vector registered with ZX_GUEST_TRAP_EOI is never granted a lazy EOI. Its
// architectural EOI must exit so the kernel can produce the requested guest-EOI
// packet; silently reconciling the assist word would swallow that notification.
//
// The payload is `zx_vcpu_lazy_eoi_state_t`, which carries its own
// magic/version/size. Reading it back reports the configuration currently in
// effect, so it can be snapshotted alongside ZX_VCPU_STATE_FULL — like
// ZX_VCPU_STATE_ENLIGHTENMENT, a write replaces the configuration wholesale,
// and this is also how a VMM restores it: writing (re-)creates the kernel's
// mapping of the target guest-physical word and unconditionally arms it to
// "no grant outstanding, word reads 0" before returning, regardless of any
// value read back from an earlier snapshot. A restored VCPU therefore never
// resumes into a grant this kernel does not remember issuing — at most one
// vector takes an ordinary, exit-costing EOI it could otherwise have skipped.
//
// Like every other state topic, this must be used on the thread the VCPU was
// created on.
#define ZX_VCPU_STATE_LAZY_EOI ((zx_vcpu_state_topic_t) 14u)
// Requests one guest-TLB flush (single-context INVVPID, this VCPU's whole
// address space) on this VCPU, and reports whether one is currently
// outstanding. This is the kernel primitive a remote TLB-flush hypercall
// (Hyper-V TLFS `HvCallFlushVirtualAddressSpace[Ex]` /
// `HvCallFlushVirtualAddressList[Ex]`) is built on: the VMM's hypercall
// handler decodes the guest's processor mask and writes this topic once per
// target VCPU. Granularity is coarse on purpose — this kernel has no notion
// of the guest's GVA list or address-space id, so it always flushes
// everything tagged with the target's VPID, which TLFS explicitly permits
// ("a hypercall implementation is allowed to flush more than what was
// requested").
//
// UNLIKE EVERY OTHER STATE TOPIC, this one is deliberately safe to write from
// any thread, for any VCPU whose handle the caller holds — exactly the
// `zx_vcpu_interrupt()` / `zx_vcpu_kick()` exception the general state-topic
// rule already carries. A hypercall targeting several VPs is handled by one
// VCPU's exit thread and has to be able to mark the others pending without
// switching threads.
//
// Write requests a flush: `pending` and `flushes_consumed` are output-only
// and must be zero. The kernel marks the flush pending and forces the target
// out of guest mode (as `zx_vcpu_kick()` does), so it cannot be mid- or
// past-VM-entry on the stale mapping when the write returns. Idempotent: a
// flush already pending stays pending, and a target already outside guest
// mode simply consumes it on its next entry.
//
// Consumption happens on the target's own thread, at the very end of
// `Vcpu::Enter()`'s per-iteration setup — after every other exit handler has
// run and immediately before the hardware VM-entry instruction, i.e. before
// any guest instruction can execute. That ordering is what satisfies TLFS's
// completion guarantee ("the specified virtual TLB entries are not present
// on any virtual processor when the hypercall returns" is read as: once the
// hypercall handler's write returns, the target cannot resume guest code
// without first passing this flush): the write already forced a fresh entry,
// and this kernel does not report the hypercall complete to the guest until
// the VMM's handler — which issued the write and, if targeting several VPs,
// waits for each to be kicked out — is satisfied. Read reports `pending` (1
// until the next consumption) and `flushes_consumed`, a monotonic count of
// completed flushes, so a caller — and a test — can observe consumption
// directly rather than infer it from whether a stale translation happened to
// survive.
//
// A vCPU migrating to a different physical CPU already gets a full
// single-context INVVPID on the destination on arrival (`Vcpu`'s migrate
// function, `Thread::MigrateStage::Restore`), which is a separate mechanism
// that closes a separate hole (stale same-VPID entries left by a prior
// occupant of that physical CPU); this topic's entry-time flush composes with
// it rather than duplicating it.
#define ZX_VCPU_STATE_TLB_FLUSH ((zx_vcpu_state_topic_t) 15u)
// An event that was mid-delivery through the guest IDT when a VM exit aborted
// it, recovered from the VMCS IDT-vectoring-information field and owed
// re-injection on the next entry (topic ZX_VCPU_STATE_VECTORING_EVENT). This is
// DISTINCT from ZX_VCPU_STATE_PENDING_EVENT: a VMM-queued injection and an
// interrupted delivery can both be outstanding at once, and the kernel keeps
// them separate because folding either into the other drops an event. A
// snapshot that omits this loses the interrupted event outright, so it must be
// captured and restored alongside the pending event. The payload is a versioned
// zx_vcpu_vectoring_event_t. Like the pending event, a write replaces it
// wholesale and a `valid == false` value clears it. Snapshot it stopped, and
// restore it after ZX_VCPU_STATE_FULL/ASYNC but before the next entry.
#define ZX_VCPU_STATE_VECTORING_EVENT ((zx_vcpu_state_topic_t) 16u)
// Guest time-stamp counter anchor and armed TSC-deadline (topic
// ZX_VCPU_STATE_TSC). The guest's RDTSC is host RDTSC plus a per-VCPU VMCS
// TSC_OFFSET; the offset is not otherwise captured, so a restored or forked
// guest sees its TSC jump. Reading this topic returns the guest TSC now
// (host RDTSC + offset), the signed VMCS TSC_OFFSET itself, the armed
// IA32_TSC_DEADLINE in the guest's own TSC (zero if unarmed), and flags telling
// whether the topic carries a captured state (PRESENT) and whether TSC
// offsetting is available/used (OFFSETTING).
//
// WRITING it re-anchors the clock WITHOUT re-sampling the host TSC in the
// kernel: the caller supplies the exact signed `tsc_offset` to install, and the
// kernel writes it verbatim to VMCS TSC_OFFSET. This is the whole point of the
// topic at partition scale -- the caller samples the host TSC ONCE for the
// whole partition, computes ONE offset (offset = partition_anchor - host RDTSC
// then), and writes that SAME offset to every VCPU on its own thread. Because
// every VCPU gets the identical offset and the host TSC is synchronized across
// CPUs, the VCPUs land on ONE coherent guest clock rather than skewing by the
// sequential per-VCPU restore delay (which is exactly what happens if each VCPU
// instead derives its own offset from its own RDTSC at its own restore instant).
// The kernel also RE-DERIVES the armed IA32_TSC_DEADLINE through the installed
// offset so a TSC-deadline timer still fires at the right guest time; a zero
// deadline while the LVT is in TSC-deadline mode DISARMS the timer (the TSC
// field is authoritative over any timer the async-state restore just armed).
//
// Flags select the write behavior:
//   * PRESENT clear  -- a pre-TSC-topic (legacy) artifact: leave the running
//     offset AND the armed deadline untouched. guest_tsc/tsc_offset/tsc_deadline
//     must all be zero.
//   * PRESENT set, OFFSETTING clear -- the capture's machine (or this one) had
//     no TSC offsetting: the offset is left untouched, but the armed deadline is
//     still restored (a guest can arm IA32_TSC_DEADLINE without the offset
//     control), including a zero deadline that disarms.
//   * PRESENT set, OFFSETTING set -- install `tsc_offset` verbatim (the
//     destination VMCS must support offsetting, else NOT_SUPPORTED) and restore
//     the deadline through it.
// Snapshot it stopped; restore it after ZX_VCPU_STATE_FULL/ASYNC, before entry.
#define ZX_VCPU_STATE_TSC ((zx_vcpu_state_topic_t) 17u)
// Read-only per-VCPU EOI accounting (topic ZX_VCPU_STATE_EXIT_COUNTERS). See
// zx_vcpu_exit_counters_t. Diagnostics only -- there is no write side. Lets a
// VMM read, per VP, how many EOIs this kernel completed lazily vs the ordinary
// exit-costing way. For an enlightened guest BOTH grow: lazy EOI ships active,
// and nested admissions plus EOI-trapped (level-triggered) vectors deliberately
// decline the grant and take the exit-costing path. lazy_eoi_completions
// staying at 0 while a guest is enlightened is the anomaly worth chasing, not
// the expected state.
#define ZX_VCPU_STATE_EXIT_COUNTERS ((zx_vcpu_state_topic_t) 18u)
// Read-only per-VCPU local-APIC snapshot (topic ZX_VCPU_STATE_LAPIC). See
// zx_vcpu_lapic_state_t. Diagnostics only. The in-kernel software LAPIC is
// otherwise not exposed off-box; this is the on-demand read a VMI tool uses to
// see, at a wedge, which vector is stuck in service, what the processor
// priority is holding delivery at, and whether an outstanding lazy-EOI grant's
// assist word was consumed (0) or not (1).
#define ZX_VCPU_STATE_LAPIC ((zx_vcpu_state_topic_t) 19u)
// clang-format on

// Identity and version of zx_vcpu_tsc_state_t. Checked by the kernel on write.
#define ZX_VCPU_TSC_STATE_MAGIC ((uint32_t)0x41435354u)  // 'TSCA'
#define ZX_VCPU_TSC_STATE_VERSION ((uint32_t)2u)
// Flags in zx_vcpu_tsc_state_t.flags.
//   PRESENT: the topic carries a captured TSC state (a live read always sets
//     it). Clear means "field absent" -- a legacy artifact predating this topic;
//     a write leaves offset and deadline as they are.
//   OFFSETTING: TSC offsetting is available (read) / must be installed (write).
#define ZX_VCPU_TSC_STATE_PRESENT ((uint32_t)1u << 0)
#define ZX_VCPU_TSC_STATE_OFFSETTING ((uint32_t)1u << 1)

// Identity and version of zx_vcpu_debug_state_t.
#define ZX_VCPU_DEBUG_STATE_MAGIC ((uint32_t)0x56444247u)  // 'VDBG'
#define ZX_VCPU_DEBUG_STATE_VERSION ((uint32_t)1u)

// Intercept guest #BP / INT3 as ZX_PKT_TYPE_GUEST_EXCEPTION instead of
// delivering it to the guest IDT. This remains active until explicitly
// cleared.
#define ZX_VCPU_DEBUG_TRAP_SOFTWARE_BREAKPOINT ((uint64_t)(1u << 0))
// Exit after the next guest instruction retires. This is a one-shot control:
// the kernel clears it when the monitor-trap VM exit occurs.
#define ZX_VCPU_DEBUG_SINGLE_STEP ((uint64_t)(1u << 1))

// The complete set of debug flags known to this ABI version.
#define ZX_VCPU_DEBUG_ALL_FLAGS \
  (ZX_VCPU_DEBUG_TRAP_SOFTWARE_BREAKPOINT | ZX_VCPU_DEBUG_SINGLE_STEP)

// Host-assisted debug configuration (topic ZX_VCPU_STATE_DEBUG).
//
// On read, `supported_flags` reports controls this VCPU can implement on the
// current host and `active_flags` reports the controls currently armed. On
// write, `supported_flags` and `reserved` are output-only and must be zero;
// `active_flags` replaces the current configuration wholesale. The complete
// request is validated, including host support, before any VMCS field changes.
typedef struct zx_vcpu_debug_state {
  // ZX_VCPU_DEBUG_STATE_MAGIC.
  uint32_t magic;
  // ZX_VCPU_DEBUG_STATE_VERSION.
  uint32_t version;
  // sizeof(zx_vcpu_debug_state_t).
  uint32_t size;
  // Must be zero.
  uint32_t reserved;
  // Output-only: ZX_VCPU_DEBUG_* capabilities available on this host.
  uint64_t supported_flags;
  // ZX_VCPU_DEBUG_* controls that are active (read) or requested (write).
  uint64_t active_flags;
} zx_vcpu_debug_state_t;

// Identity and version of zx_vcpu_run_control_t.
#define ZX_VCPU_RUN_CONTROL_MAGIC ((uint32_t)0x5652554eu)  // 'VRUN'
#define ZX_VCPU_RUN_CONTROL_VERSION ((uint32_t)1u)

// Exit after `preemption_timer_ticks` VMX preemption-timer ticks. A tick is
// TSC ticks shifted right by `preemption_timer_rate_shift`, which is reported
// on read from IA32_VMX_MISC. This control is one-shot.
#define ZX_VCPU_RUN_PREEMPTION_TIMER ((uint64_t)(1u << 0))
#define ZX_VCPU_RUN_ALL_FLAGS ZX_VCPU_RUN_PREEMPTION_TIMER

// Host-assisted bounded-run configuration (topic ZX_VCPU_STATE_RUN_CONTROL).
//
// On read, `supported_flags`, `active_flags`, and
// `preemption_timer_rate_shift` report the active host's state. On write,
// `supported_flags`, `preemption_timer_rate_shift`, and every reserved field
// must be zero. An active preemption timer requires a non-zero tick count; an
// inactive request requires the count to be zero.
typedef struct zx_vcpu_run_control {
  uint32_t magic;
  uint32_t version;
  uint32_t size;
  uint32_t reserved;
  uint64_t supported_flags;
  uint64_t active_flags;
  uint32_t preemption_timer_ticks;
  uint8_t preemption_timer_rate_shift;
  uint8_t reserved2[3];
} zx_vcpu_run_control_t;

// Identity and version of zx_vcpu_exit_control_t.
#define ZX_VCPU_EXIT_CONTROL_MAGIC ((uint32_t)0x56455843u)  // 'VEXC'
#define ZX_VCPU_EXIT_CONTROL_VERSION ((uint32_t)1u)

// Stop after normal handling of a VM exit whose architectural reason is
// selected in selected_reasons.
#define ZX_VCPU_EXIT_CONTROL_OBSERVE ((uint64_t)(1u << 0))
// Stop after normal handling of exit_budget VM exits in this one-shot session.
#define ZX_VCPU_EXIT_CONTROL_BUDGET ((uint64_t)(1u << 1))
#define ZX_VCPU_EXIT_CONTROL_ALL_FLAGS \
  (ZX_VCPU_EXIT_CONTROL_OBSERVE | ZX_VCPU_EXIT_CONTROL_BUDGET)

// One-shot post-handler VM-exit controls (topic
// ZX_VCPU_STATE_EXIT_CONTROL).
//
// Reasons are architectural VMX basic exit-reason numbers. Word zero covers
// reasons 0-63 and word one covers 64-127. On write, supported_flags,
// supported_reasons, and every pending/result field are output-only and must be
// zero. OBSERVE requires at least one selected supported reason. BUDGET
// requires a non-zero exit_budget. Fields for an inactive control must be zero.
//
// A completed session remains pending after its packet is delivered. Any later
// zx_vcpu_enter() fails with ZX_ERR_BAD_STATE until a write supplies the exact
// pending_sequence in ack_sequence. A stale or absent sequence cannot release
// the VCPU. The same write may acknowledge and arm the next one-shot.
typedef struct zx_vcpu_exit_control {
  uint32_t magic;
  uint32_t version;
  uint32_t size;
  uint32_t reserved;
  // Output-only capabilities.
  uint64_t supported_flags;
  // Active one-shot controls.
  uint64_t active_flags;
  // Output-only exact reason set supported by OBSERVE.
  uint64_t supported_reasons[2];
  // Requested reason set for OBSERVE.
  uint64_t selected_reasons[2];
  // Requested completed-exit count for BUDGET.
  uint64_t exit_budget;
  // Input-only acknowledgement. Zero when no result is being acknowledged.
  uint64_t ack_sequence;
  // Output-only pending result. Zero when no acknowledgement is required.
  uint64_t pending_sequence;
  // Output-only completed exits in the armed session.
  uint64_t exits_seen;
  // Output-only pending result fields.
  uint32_t pending_exit_reason;
  uint32_t pending_flags;
  uint64_t pending_exit_rip;
  uint64_t pending_resume_rip;
} zx_vcpu_exit_control_t;

// Identity and version of zx_vcpu_instruction_control_t.
#define ZX_VCPU_INSTRUCTION_CONTROL_MAGIC ((uint32_t)0x56494e53u)  // 'VINS'
#define ZX_VCPU_INSTRUCTION_CONTROL_VERSION ((uint32_t)1u)

// Request a stop through fixed-counter overflow after at least the requested
// number of retired guest instructions.
#define ZX_VCPU_INSTRUCTION_RETIRED_BUDGET ((uint64_t)(1u << 0))
#define ZX_VCPU_INSTRUCTION_ALL_FLAGS ZX_VCPU_INSTRUCTION_RETIRED_BUDGET

typedef uint32_t zx_vcpu_instruction_availability_t;
#define ZX_VCPU_INSTRUCTION_UNSUPPORTED ((zx_vcpu_instruction_availability_t)0u)
#define ZX_VCPU_INSTRUCTION_AVAILABLE ((zx_vcpu_instruction_availability_t)1u)
#define ZX_VCPU_INSTRUCTION_BUSY ((zx_vcpu_instruction_availability_t)2u)

typedef uint32_t zx_vcpu_instruction_precision_t;
// The target is programmed as a PMU overflow threshold. The exact observed
// count is reported, but interrupt delivery can let additional instructions
// retire before VM exit.
#define ZX_VCPU_INSTRUCTION_PRECISION_OVERFLOW_INTERRUPT \
  ((zx_vcpu_instruction_precision_t)1u)

// Guest-only retired-instruction control (topic
// ZX_VCPU_STATE_INSTRUCTION_CONTROL).
//
// Runtime support requires an architectural fixed retired-instruction counter,
// restorable overflow state, SMM exclusion, VM-entry/VM-exit global-control
// switching, and an idle host PMU/PMI resource. `availability` distinguishes
// missing hardware from a temporary resource conflict. The arm operation
// rechecks both and fails before changing state.
//
// On write, availability, supported_flags, max_budget, counter_width, and every
// pending/result field are output-only and must be zero. RETIRED_BUDGET
// requires a non-zero budget no greater than max_budget.
//
// A completed session remains pending after its packet is delivered. Any later
// zx_vcpu_enter() fails with ZX_ERR_BAD_STATE until a write supplies the exact
// pending_sequence in ack_sequence. Acknowledgement and the next arm may be one
// atomic write.
typedef struct zx_vcpu_instruction_control {
  uint32_t magic;
  uint32_t version;
  uint32_t size;
  uint32_t reserved;
  // Output-only: ZX_VCPU_INSTRUCTION_* availability.
  zx_vcpu_instruction_availability_t availability;
  // Output-only fixed-counter width.
  uint32_t counter_width;
  // Output-only ZX_VCPU_INSTRUCTION_PRECISION_* behavior.
  zx_vcpu_instruction_precision_t precision;
  // Must be zero.
  uint32_t reserved2;
  // Output-only capabilities.
  uint64_t supported_flags;
  // Active control.
  uint64_t active_flags;
  // Output-only maximum representable one-shot budget.
  uint64_t max_budget;
  // Requested retired-instruction budget.
  uint64_t budget;
  // Input-only acknowledgement; zero when no result is acknowledged.
  uint64_t ack_sequence;
  // Output-only result; zero when no acknowledgement is required.
  uint64_t pending_sequence;
  // Output-only exact retired guest instructions observed in this session.
  uint64_t retired_instructions;
  // Output-only guest RIP at the stopped boundary.
  uint64_t pending_rip;
} zx_vcpu_instruction_control_t;

// Identity and version of zx_vcpu_memory_access_control_t.
#define ZX_VCPU_MEMORY_ACCESS_CONTROL_MAGIC ((uint32_t)0x564d4143u)  // 'VMAC'
#define ZX_VCPU_MEMORY_ACCESS_CONTROL_VERSION ((uint32_t)1u)

#define ZX_VCPU_MEMORY_ACCESS_MAX_RANGES ((uint32_t)16u)
#define ZX_VCPU_MEMORY_ACCESS_MAX_PAGES ((uint32_t)64u)

typedef uint32_t zx_vcpu_memory_access_availability_t;
#define ZX_VCPU_MEMORY_ACCESS_UNSUPPORTED ((zx_vcpu_memory_access_availability_t)0u)
#define ZX_VCPU_MEMORY_ACCESS_AVAILABLE ((zx_vcpu_memory_access_availability_t)1u)

// Install the supplied range set. Omitting this flag requests disarm after any
// pending result has been acknowledged.
#define ZX_VCPU_MEMORY_ACCESS_ARM ((uint64_t)(1u << 0))
#define ZX_VCPU_MEMORY_ACCESS_ALL_FLAGS ZX_VCPU_MEMORY_ACCESS_ARM

typedef uint32_t zx_vcpu_memory_access_mask_t;
#define ZX_VCPU_MEMORY_ACCESS_READ ((zx_vcpu_memory_access_mask_t)(1u << 0))
#define ZX_VCPU_MEMORY_ACCESS_WRITE ((zx_vcpu_memory_access_mask_t)(1u << 1))
#define ZX_VCPU_MEMORY_ACCESS_EXECUTE ((zx_vcpu_memory_access_mask_t)(1u << 2))
#define ZX_VCPU_MEMORY_ACCESS_ALL \
  (ZX_VCPU_MEMORY_ACCESS_READ | ZX_VCPU_MEMORY_ACCESS_WRITE | ZX_VCPU_MEMORY_ACCESS_EXECUTE)

// The processor supplied a valid guest-linear address for the pending EPT
// violation. The raw qualification remains available for callers that need the
// processor's complete classification.
#define ZX_VCPU_MEMORY_ACCESS_RESULT_GVA_VALID ((uint32_t)(1u << 0))

typedef struct zx_vcpu_memory_access_range {
  // Page-aligned guest-physical start.
  zx_gpaddr_t guest_paddr;
  // Non-zero, page-multiple length.
  uint64_t length;
  // Non-zero ZX_VCPU_MEMORY_ACCESS_{READ,WRITE,EXECUTE} mask.
  zx_vcpu_memory_access_mask_t access;
  // Must be zero.
  uint32_t reserved;
} zx_vcpu_memory_access_range_t;

// One-shot guest-physical memory-access controls (topic
// ZX_VCPU_STATE_MEMORY_ACCESS_CONTROL).
//
// The range set is guest-global even though this structure is read and written
// through a VCPU handle. At most ZX_VCPU_MEMORY_ACCESS_MAX_PAGES distinct pages
// may be covered. The complete replacement is validated and made resident
// before any effective permission is changed; a rejected request leaves the
// previous control and pending result intact.
//
// On write, availability, limits, supported_flags, supported_access, and every
// pending/result field are output-only and must be zero. ARM requires a
// non-empty range set; disarm requires range_count and every range entry to be
// zero.
//
// supported_access is the set of access kinds that may be selected
// independently by a range. On x86, EPT cannot preserve write permission while
// removing read permission, so READ is not advertised. WRITE and EXECUTE are
// independently supported and preserve the pre-access boundary.
//
// pending_range_mask has one bit for every input range that contains the
// triggering guest-physical address and selects pending_access. The raw EPT
// exit qualification, exact GPA, optional GVA, and RIP all describe the same
// pre-access boundary. pending_sequence must be acknowledged exactly before
// any VCPU may resume.
typedef struct zx_vcpu_memory_access_control {
  uint32_t magic;
  uint32_t version;
  uint32_t size;
  uint32_t reserved;
  // Output-only runtime capability and fixed limits.
  zx_vcpu_memory_access_availability_t availability;
  uint16_t max_ranges;
  uint16_t max_pages;
  uint64_t supported_flags;
  // Active request. active_flags is zero while a result is pending even though
  // its EPT restrictions remain installed until acknowledgement.
  uint64_t active_flags;
  uint32_t range_count;
  uint32_t reserved2;
  zx_vcpu_memory_access_range_t ranges[ZX_VCPU_MEMORY_ACCESS_MAX_RANGES];
  // Input-only acknowledgement; zero when no result is acknowledged.
  uint64_t ack_sequence;
  // Output-only pending result.
  uint64_t pending_sequence;
  zx_gpaddr_t pending_guest_paddr;
  zx_vaddr_t pending_guest_vaddr;
  zx_vaddr_t pending_rip;
  uint64_t pending_qualification;
  uint64_t pending_range_mask;
  zx_vcpu_memory_access_mask_t pending_access;
  uint32_t pending_flags;
  // One-based guest VPID that took the triggering exit.
  uint32_t pending_vpid;
  // Output-only ZX_VCPU_MEMORY_ACCESS_* capability mask.
  zx_vcpu_memory_access_mask_t supported_access;
} zx_vcpu_memory_access_control_t;

// Identity and version of zx_vcpu_intel_pt_control_t.
#define ZX_VCPU_INTEL_PT_CONTROL_MAGIC ((uint32_t)0x56505443u)  // 'VPTC'
#define ZX_VCPU_INTEL_PT_CONTROL_VERSION ((uint32_t)1u)

#define ZX_VCPU_INTEL_PT_MAX_ADDRESS_RANGES ((uint32_t)4u)
#define ZX_VCPU_INTEL_PT_MAX_CPUID_LEAVES ((uint32_t)2u)
#define ZX_VCPU_INTEL_PT_MAX_CHUNK_BYTES ((uint32_t)4096u)
#define ZX_VCPU_INTEL_PT_MAX_BUFFER_BYTES ((uint64_t)(4u * 1024u * 1024u))

typedef uint32_t zx_vcpu_intel_pt_availability_t;
#define ZX_VCPU_INTEL_PT_UNSUPPORTED ((zx_vcpu_intel_pt_availability_t)0u)
#define ZX_VCPU_INTEL_PT_AVAILABLE ((zx_vcpu_intel_pt_availability_t)1u)
#define ZX_VCPU_INTEL_PT_BUSY ((zx_vcpu_intel_pt_availability_t)2u)

// Stable explanation accompanying ZX_VCPU_INTEL_PT_UNSUPPORTED/BUSY.
typedef uint32_t zx_vcpu_intel_pt_unavailable_reason_t;
#define ZX_VCPU_INTEL_PT_REASON_NONE ((zx_vcpu_intel_pt_unavailable_reason_t)0u)
#define ZX_VCPU_INTEL_PT_REASON_NESTED_HOST ((zx_vcpu_intel_pt_unavailable_reason_t)1u)
#define ZX_VCPU_INTEL_PT_REASON_ABSENT ((zx_vcpu_intel_pt_unavailable_reason_t)2u)
#define ZX_VCPU_INTEL_PT_REASON_CPUID_MALFORMED ((zx_vcpu_intel_pt_unavailable_reason_t)3u)
#define ZX_VCPU_INTEL_PT_REASON_TOPA_UNAVAILABLE ((zx_vcpu_intel_pt_unavailable_reason_t)4u)
#define ZX_VCPU_INTEL_PT_REASON_MULTI_ENTRY_TOPA_UNAVAILABLE \
  ((zx_vcpu_intel_pt_unavailable_reason_t)5u)
#define ZX_VCPU_INTEL_PT_REASON_RTIT_MSR_UNAVAILABLE \
  ((zx_vcpu_intel_pt_unavailable_reason_t)6u)
#define ZX_VCPU_INTEL_PT_REASON_PMI_CONFLICT ((zx_vcpu_intel_pt_unavailable_reason_t)7u)
#define ZX_VCPU_INTEL_PT_REASON_VMX_CONTROL_UNAVAILABLE \
  ((zx_vcpu_intel_pt_unavailable_reason_t)8u)
#define ZX_VCPU_INTEL_PT_REASON_BUFFER_ALLOCATION ((zx_vcpu_intel_pt_unavailable_reason_t)9u)

typedef uint32_t zx_vcpu_intel_pt_action_t;
#define ZX_VCPU_INTEL_PT_ACTION_NONE ((zx_vcpu_intel_pt_action_t)0u)
#define ZX_VCPU_INTEL_PT_ACTION_CONFIGURE ((zx_vcpu_intel_pt_action_t)1u)
#define ZX_VCPU_INTEL_PT_ACTION_SELECT_READ ((zx_vcpu_intel_pt_action_t)2u)
#define ZX_VCPU_INTEL_PT_ACTION_ACK ((zx_vcpu_intel_pt_action_t)3u)
#define ZX_VCPU_INTEL_PT_ACTION_STOP ((zx_vcpu_intel_pt_action_t)4u)
#define ZX_VCPU_INTEL_PT_ACTION_RELEASE ((zx_vcpu_intel_pt_action_t)5u)

// Complete-or-fail is the only delivery mode in version 1. The kernel never
// wraps onto unread pages.
typedef uint32_t zx_vcpu_intel_pt_delivery_t;
#define ZX_VCPU_INTEL_PT_DELIVERY_COMPLETE_OR_FAIL ((zx_vcpu_intel_pt_delivery_t)1u)

// Typed configuration flags. TraceEn and ToPA are intentionally absent: the
// kernel owns both and enables them only at the VM-entry boundary.
#define ZX_VCPU_INTEL_PT_TRACE_USER ((uint64_t)(1u << 0))
#define ZX_VCPU_INTEL_PT_TRACE_SUPERVISOR ((uint64_t)(1u << 1))
#define ZX_VCPU_INTEL_PT_BRANCH_TRACE ((uint64_t)(1u << 2))
#define ZX_VCPU_INTEL_PT_CR3_FILTER ((uint64_t)(1u << 3))
#define ZX_VCPU_INTEL_PT_MTC_PACKETS ((uint64_t)(1u << 4))
#define ZX_VCPU_INTEL_PT_CYCLE_PACKETS ((uint64_t)(1u << 5))
#define ZX_VCPU_INTEL_PT_ALL_FLAGS                                               \
  (ZX_VCPU_INTEL_PT_TRACE_USER | ZX_VCPU_INTEL_PT_TRACE_SUPERVISOR |          \
   ZX_VCPU_INTEL_PT_BRANCH_TRACE | ZX_VCPU_INTEL_PT_CR3_FILTER |               \
   ZX_VCPU_INTEL_PT_MTC_PACKETS | ZX_VCPU_INTEL_PT_CYCLE_PACKETS)

typedef uint32_t zx_vcpu_intel_pt_terminal_t;
#define ZX_VCPU_INTEL_PT_TERMINAL_INACTIVE ((zx_vcpu_intel_pt_terminal_t)0u)
#define ZX_VCPU_INTEL_PT_TERMINAL_ACTIVE ((zx_vcpu_intel_pt_terminal_t)1u)
#define ZX_VCPU_INTEL_PT_TERMINAL_COMPLETE ((zx_vcpu_intel_pt_terminal_t)2u)
#define ZX_VCPU_INTEL_PT_TERMINAL_INCOMPLETE ((zx_vcpu_intel_pt_terminal_t)3u)

// Output status bits for the selected immutable segment.
#define ZX_VCPU_INTEL_PT_STATUS_BACKPRESSURE ((uint32_t)(1u << 0))
#define ZX_VCPU_INTEL_PT_STATUS_SEGMENT_COMPLETE ((uint32_t)(1u << 1))
#define ZX_VCPU_INTEL_PT_STATUS_HARDWARE_STOPPED ((uint32_t)(1u << 2))
#define ZX_VCPU_INTEL_PT_STATUS_HARDWARE_ERROR ((uint32_t)(1u << 3))
#define ZX_VCPU_INTEL_PT_STATUS_GAP_BEFORE ((uint32_t)(1u << 4))

typedef struct zx_vcpu_intel_pt_cpuid_leaf {
  uint32_t subleaf;
  uint32_t eax;
  uint32_t ebx;
  uint32_t ecx;
  uint32_t edx;
  uint32_t reserved;
} zx_vcpu_intel_pt_cpuid_leaf_t;

typedef struct zx_vcpu_intel_pt_address_range {
  zx_vaddr_t start;
  uint64_t length;
} zx_vcpu_intel_pt_address_range_t;

// Raw Intel PT configuration, status, and bounded cursor read (topic
// ZX_VCPU_STATE_INTEL_PT_CONTROL).
//
// A CONFIGURE write preallocates and pins all output and replacement pages,
// validates the complete request, reserves the exclusive PMI route, then
// publishes one non-zero trace_generation. SELECT_READ stores only a cursor and
// maximum length; repeated reads after an identical selection return identical
// metadata and bytes. ACK advances acknowledged_cursor monotonically and is the
// only operation allowed to reclaim sealed pairs. STOP disables tracing and
// seals a partial active region as COMPLETE. RELEASE also drops the reservation
// and allocation.
//
// On write, every capability, status, result, CPUID, and data field is
// output-only and must be zero. Fields not consumed by the selected action must
// also be zero. A restore releases any active session before architectural
// state is installed, so the restored VCPU is paused and the old generation is
// invalid.
typedef struct zx_vcpu_intel_pt_control {
  uint32_t magic;
  uint32_t version;
  uint32_t size;
  zx_vcpu_intel_pt_action_t action;

  // Output-only runtime capability identity. The first read is CPUID-only.
  // After CONFIGURE proves a static host prerequisite absent, later reads
  // report UNSUPPORTED with the exact unavailable_reason.
  zx_vcpu_intel_pt_availability_t availability;
  zx_vcpu_intel_pt_unavailable_reason_t unavailable_reason;
  uint32_t cpu_family;
  uint32_t cpu_model;
  uint32_t cpu_stepping;
  uint32_t max_address_ranges;
  uint32_t supported_psb_frequencies;
  uint32_t supported_mtc_frequencies;
  uint32_t supported_cycle_thresholds;
  uint32_t reserved0;
  uint64_t supported_flags;
  zx_vcpu_intel_pt_cpuid_leaf_t cpuid_14[ZX_VCPU_INTEL_PT_MAX_CPUID_LEAVES];

  // CONFIGURE request / negotiated configuration.
  zx_vcpu_intel_pt_delivery_t delivery;
  uint32_t address_range_count;
  uint64_t config_flags;
  uint64_t buffer_bytes;
  zx_vcpu_intel_pt_address_range_t address_ranges[ZX_VCPU_INTEL_PT_MAX_ADDRESS_RANGES];
  uint64_t cr3_match;
  uint32_t psb_frequency;
  uint32_t mtc_frequency;
  uint32_t cycle_threshold;
  uint32_t reserved1;

  // Generation must match for every action after CONFIGURE.
  uint64_t trace_generation;
  // ACK input / read output.
  uint64_t acknowledged_cursor;
  // SELECT_READ input / read output.
  uint64_t read_cursor;
  uint32_t read_max_bytes;
  uint32_t data_size;

  // Output-only immutable-segment and terminal metadata.
  uint64_t next_cursor;
  uint64_t producer_cursor;
  uint64_t segment_sequence;
  uint64_t segment_offset;
  uint64_t hardware_status;
  uint64_t lost_bytes;
  uint64_t watermark_count;
  zx_vcpu_intel_pt_terminal_t terminal;
  uint32_t status_flags;
  uint8_t data[ZX_VCPU_INTEL_PT_MAX_CHUNK_BYTES];
} zx_vcpu_intel_pt_control_t;

// Identity and version of zx_vcpu_hardware_breakpoint_control_t.
#define ZX_VCPU_HARDWARE_BREAKPOINT_CONTROL_MAGIC ((uint32_t)0x56484243u)  // 'VHBC'
#define ZX_VCPU_HARDWARE_BREAKPOINT_CONTROL_VERSION ((uint32_t)1u)
#define ZX_VCPU_HARDWARE_BREAKPOINT_MAX_REQUESTS ((uint32_t)4u)

typedef uint32_t zx_vcpu_hardware_breakpoint_availability_t;
#define ZX_VCPU_HARDWARE_BREAKPOINT_UNSUPPORTED \
  ((zx_vcpu_hardware_breakpoint_availability_t)0u)
#define ZX_VCPU_HARDWARE_BREAKPOINT_AVAILABLE \
  ((zx_vcpu_hardware_breakpoint_availability_t)1u)

// Install the supplied complete request set. Omitting ARM requests disarm after
// acknowledging any pending stop.
#define ZX_VCPU_HARDWARE_BREAKPOINT_ARM ((uint64_t)(1u << 0))
#define ZX_VCPU_HARDWARE_BREAKPOINT_ALL_FLAGS ZX_VCPU_HARDWARE_BREAKPOINT_ARM

// Exact architectural DR7 RW encodings.
typedef uint32_t zx_vcpu_hardware_breakpoint_access_t;
#define ZX_VCPU_HARDWARE_BREAKPOINT_EXECUTE \
  ((zx_vcpu_hardware_breakpoint_access_t)0u)
#define ZX_VCPU_HARDWARE_BREAKPOINT_WRITE \
  ((zx_vcpu_hardware_breakpoint_access_t)1u)
#define ZX_VCPU_HARDWARE_BREAKPOINT_READ_WRITE \
  ((zx_vcpu_hardware_breakpoint_access_t)3u)

// Exact architectural byte lengths. Execute requires length 1.
typedef uint32_t zx_vcpu_hardware_breakpoint_length_t;
#define ZX_VCPU_HARDWARE_BREAKPOINT_LENGTH_1 \
  ((zx_vcpu_hardware_breakpoint_length_t)1u)
#define ZX_VCPU_HARDWARE_BREAKPOINT_LENGTH_2 \
  ((zx_vcpu_hardware_breakpoint_length_t)2u)
#define ZX_VCPU_HARDWARE_BREAKPOINT_LENGTH_4 \
  ((zx_vcpu_hardware_breakpoint_length_t)4u)
#define ZX_VCPU_HARDWARE_BREAKPOINT_LENGTH_8 \
  ((zx_vcpu_hardware_breakpoint_length_t)8u)

typedef uint32_t zx_vcpu_hardware_breakpoint_boundary_t;
#define ZX_VCPU_HARDWARE_BREAKPOINT_PRE_INSTRUCTION \
  ((zx_vcpu_hardware_breakpoint_boundary_t)1u)
#define ZX_VCPU_HARDWARE_BREAKPOINT_POST_ACCESS \
  ((zx_vcpu_hardware_breakpoint_boundary_t)2u)
#define ZX_VCPU_HARDWARE_BREAKPOINT_MIXED_BOUNDARY \
  ((zx_vcpu_hardware_breakpoint_boundary_t)3u)

typedef struct zx_vcpu_hardware_breakpoint_request {
  zx_vaddr_t address;
  zx_vcpu_hardware_breakpoint_access_t access;
  zx_vcpu_hardware_breakpoint_length_t length;
  // Bit selected in pending_condition_mask.
  uint32_t condition_index;
  uint32_t reserved;
} zx_vcpu_hardware_breakpoint_request_t;

// Per-VCPU transparent DR0-DR3 controls. The triggering stop establishes a
// guest-wide paused boundary before its packet is returned.
//
// On write, availability, limits, supported_flags, and every pending/result
// field are output-only and must be zero. ARM requires a non-empty request set;
// disarm requires request_count and every request entry to be zero. A pending
// result requires its exact sequence, and acknowledgement plus replacement is
// one atomic write.
//
// Requests must be canonical and naturally aligned for their length. Ranges
// must not overlap. The complete replacement is validated against the guest's
// currently enabled debug-register slots before any VMCS field changes.
typedef struct zx_vcpu_hardware_breakpoint_control {
  uint32_t magic;
  uint32_t version;
  uint32_t size;
  uint32_t reserved;
  // Output-only runtime capability and fixed limits.
  zx_vcpu_hardware_breakpoint_availability_t availability;
  uint16_t max_slots;
  uint16_t max_requests;
  uint64_t supported_flags;
  // Zero while a one-shot result is pending.
  uint64_t active_flags;
  uint32_t request_count;
  uint32_t reserved2;
  zx_vcpu_hardware_breakpoint_request_t requests[ZX_VCPU_HARDWARE_BREAKPOINT_MAX_REQUESTS];
  // Input-only acknowledgement; zero when no result is acknowledged.
  uint64_t ack_sequence;
  // Output-only exact pending result.
  uint64_t pending_sequence;
  uint64_t pending_condition_mask;
  zx_vaddr_t pending_rip;
  uint64_t pending_raw_dr6;
  uint64_t pending_guest_dr6;
  uint16_t pending_vpid;
  uint8_t pending_slot_mask;
  uint8_t pending_boundary;
  uint32_t reserved3;
} zx_vcpu_hardware_breakpoint_control_t;

// Identity and version of zx_vcpu_xapic_access_t. Both are checked on write,
// together with the fixed structure size and every request/result field.
#define ZX_VCPU_XAPIC_ACCESS_MAGIC ((uint32_t)0x56584150u)  // 'VXAP'
#define ZX_VCPU_XAPIC_ACCESS_VERSION ((uint32_t)1u)

typedef uint32_t zx_vcpu_xapic_action_t;

// Read one 32-bit xAPIC register.
#define ZX_VCPU_XAPIC_ACTION_READ ((zx_vcpu_xapic_action_t)1u)
// Write one 32-bit xAPIC register.
#define ZX_VCPU_XAPIC_ACTION_WRITE ((zx_vcpu_xapic_action_t)2u)

// `value` contains the result of a READ action.
#define ZX_VCPU_XAPIC_RESULT_VALUE_VALID ((uint32_t)(1u << 0))

typedef uint32_t zx_vcpu_xapic_result_kind_t;

// The access produced no device-facing side effect.
#define ZX_VCPU_XAPIC_RESULT_NONE ((zx_vcpu_xapic_result_kind_t)0u)
// `vector` names the interrupt whose EOI completed.
#define ZX_VCPU_XAPIC_RESULT_EOI ((zx_vcpu_xapic_result_kind_t)1u)
// `target` is a VCPU mask and `vector` is the interrupt to deliver.
#define ZX_VCPU_XAPIC_RESULT_INTERRUPT ((zx_vcpu_xapic_result_kind_t)2u)
// `target` is an APIC ID and `entry` is the STARTUP entry address.
#define ZX_VCPU_XAPIC_RESULT_STARTUP ((zx_vcpu_xapic_result_kind_t)3u)

// One software access to the xAPIC MMIO register page (topic
// ZX_VCPU_STATE_XAPIC_ACCESS).
//
// Write submits an action. `offset` is a 16-byte-aligned register offset in
// [0, 0xff0]. For READ, `value` must be zero; for WRITE, it is the register
// value. Every result field (`result_flags`, `result_kind`, `vector`, `target`
// and `entry`) and `reserved` must be zero. A malformed request is rejected
// without accessing the APIC.
//
// Read retrieves the most recently completed action. It echoes `action`,
// `offset` and a WRITE's `value`. A READ replaces `value` and sets
// ZX_VCPU_XAPIC_RESULT_VALUE_VALID. `result_kind` describes at most one
// device-facing side effect:
//
//  * NONE: `vector`, `target` and `entry` are zero.
//  * EOI: `vector` is the completed vector; `target` and `entry` are zero.
//  * INTERRUPT: `target` is the VCPU mask and `vector` is the vector.
//  * STARTUP: `target` is the APIC ID and `entry` is the guest entry address.
//
// Both operations must be performed on the thread that created the VCPU, in
// order between the MMIO exit and the next zx_vcpu_enter().
typedef struct zx_vcpu_xapic_access {
  // ZX_VCPU_XAPIC_ACCESS_MAGIC.
  uint32_t magic;
  // ZX_VCPU_XAPIC_ACCESS_VERSION.
  uint32_t version;
  // sizeof(zx_vcpu_xapic_access_t).
  uint32_t size;
  // One of ZX_VCPU_XAPIC_ACTION_*.
  zx_vcpu_xapic_action_t action;
  // Register offset within the 4 KiB xAPIC MMIO page.
  uint32_t offset;
  // WRITE request value, or READ result when VALUE_VALID is set.
  uint32_t value;
  // ZX_VCPU_XAPIC_RESULT_* flags.
  uint32_t result_flags;
  // One of ZX_VCPU_XAPIC_RESULT_{NONE,EOI,INTERRUPT,STARTUP}.
  zx_vcpu_xapic_result_kind_t result_kind;
  // EOI or interrupt vector, according to `result_kind`.
  uint32_t vector;
  // Must be zero.
  uint32_t reserved;
  // Interrupt VCPU mask or STARTUP APIC ID, according to `result_kind`.
  uint64_t target;
  // STARTUP guest entry address; zero for every other result kind.
  uint64_t entry;
} zx_vcpu_xapic_access_t;

// Identity and version of zx_vcpu_pending_event_t. Both are checked by the
// kernel on write, so a userspace built against a different layout is refused
// instead of being misinterpreted.
#define ZX_VCPU_PENDING_EVENT_MAGIC ((uint32_t)0x5650454eu)  // 'VPEN'
#define ZX_VCPU_PENDING_EVENT_VERSION ((uint32_t)1u)

// The kind of event to deliver. These name the distinction VMX draws in the
// VM-entry interruption-information field (Volume 3, Section 24.8.3): the
// hardware vectors an external interrupt, an NMI and an exception differently,
// and a software exception resumes at the instruction *after* the one that
// raised it. The emulator-driven faults a VMM injects are hardware exceptions,
// not external interrupts.
typedef uint32_t zx_vcpu_event_type_t;

// No event queued. Writing this clears whatever was queued before.
#define ZX_VCPU_EVENT_NONE ((zx_vcpu_event_type_t) 0u)
// A maskable external interrupt. The vector must be in [0x20, 0xff]. Delivery
// waits for the guest to become interruptible (RFLAGS.IF, and no STI/MOV-SS
// shadow), exactly as an interrupt raised through zx_vcpu_interrupt() does.
#define ZX_VCPU_EVENT_EXTERNAL_INTERRUPT ((zx_vcpu_event_type_t) 1u)
// A non-maskable interrupt. The vector must be 2. Delivery waits only for NMI
// blocking to clear.
#define ZX_VCPU_EVENT_NMI ((zx_vcpu_event_type_t) 2u)
// A hardware exception (a fault or trap raised by execution): vector in
// [0, 0x1f]. This is what an instruction emulator injects. It is not maskable,
// so it is delivered on the next entry regardless of RFLAGS.IF.
#define ZX_VCPU_EVENT_HARDWARE_EXCEPTION ((zx_vcpu_event_type_t) 3u)
// A software exception: #BP (3) or #OF (4) only, as raised by INT3 / INTO.
// `instruction_length` must be the length of the raising instruction, since the
// guest resumes past it rather than at it.
#define ZX_VCPU_EVENT_SOFTWARE_EXCEPTION ((zx_vcpu_event_type_t) 4u)

// `error_code` holds the error code to deliver. Required for, and permitted only
// for, a hardware exception whose vector architecturally has one: #DF (8),
// #TS (10), #NP (11), #SS (12), #GP (13), #PF (14) and #AC (17).
#define ZX_VCPU_EVENT_ERROR_CODE_VALID ((uint32_t)(1u << 0))
// `cr2` holds the faulting linear address to place in CR2 before delivery.
// Required for, and permitted only for, #PF (14).
#define ZX_VCPU_EVENT_CR2_VALID ((uint32_t)(1u << 1))

// The event queued for delivery on a VCPU's next entry (topic
// ZX_VCPU_STATE_PENDING_EVENT).
//
// Nothing is applied unless the entire structure validates, so a rejected write
// leaves the VCPU exactly as it was rather than half-queued — and, in
// particular, cannot leave the VMCS in a shape that VM entry would refuse. Every
// field not used by the chosen `type` must be zero, so a field that gains a
// meaning later cannot be silently ignored today.
typedef struct zx_vcpu_pending_event {
  // ZX_VCPU_PENDING_EVENT_MAGIC.
  uint32_t magic;
  // ZX_VCPU_PENDING_EVENT_VERSION.
  uint32_t version;
  // sizeof(zx_vcpu_pending_event_t).
  uint32_t size;
  // One of ZX_VCPU_EVENT_*.
  uint32_t type;
  // The interrupt or exception vector, within the range its `type` allows.
  uint32_t vector;
  // ZX_VCPU_EVENT_* payload-presence flags.
  uint32_t flags;
  // The architectural error code, if ZX_VCPU_EVENT_ERROR_CODE_VALID; else zero.
  uint32_t error_code;
  // Length in bytes of the instruction that raised a software exception, in
  // [1, 15]; zero for every other type.
  uint32_t instruction_length;
  // The faulting linear address to load into CR2, if ZX_VCPU_EVENT_CR2_VALID
  // (i.e. for #PF); else zero.
  uint64_t cr2;
} zx_vcpu_pending_event_t;

// Identity and version of zx_vcpu_vectoring_event_t. Checked by the kernel on
// write, so a userspace built against a different layout is refused rather than
// misinterpreted.
#define ZX_VCPU_VECTORING_EVENT_MAGIC ((uint32_t)0x5645434eu)  // 'VECN'
#define ZX_VCPU_VECTORING_EVENT_VERSION ((uint32_t)1u)

// An event interrupted mid-delivery through the guest IDT, recovered from the
// VMCS IDT-vectoring-information field (topic ZX_VCPU_STATE_VECTORING_EVENT).
//
// Unlike zx_vcpu_pending_event_t, which speaks the abstract ZX_VCPU_EVENT_*
// vocabulary, this carries the RAW VMX interruption type already shifted into
// bits 10:8, exactly as the VM-entry interruption-information field wants it:
// the abstract enum cannot name a software interrupt (type 4) or a privileged
// software exception (type 5), and re-injection must reproduce the exact type
// the hardware reported so the event resumes with identical semantics. Only the
// three reinjectable subfields are carried; VM entry never re-delivers the
// reserved (type 1) or "other event" (type 7) forms and this never reports one.
//
// A write replaces it wholesale and validates the whole structure before
// applying any of it; `valid == 0` clears it (nothing owed on the next entry).
typedef struct zx_vcpu_vectoring_event {
  // ZX_VCPU_VECTORING_EVENT_MAGIC.
  uint32_t magic;
  // ZX_VCPU_VECTORING_EVENT_VERSION.
  uint32_t version;
  // sizeof(zx_vcpu_vectoring_event_t).
  uint32_t size;
  // Nonzero if an interrupted delivery is owed; zero means nothing is queued
  // and every other field must be zero.
  uint32_t valid;
  // Raw VMX interruption type, already shifted into bits 10:8 (one of
  // 0/2/3/4/5/6 << 8). Never the reserved (1<<8) or other-event (7<<8) forms.
  uint32_t type;
  // The interrupt or exception vector (bits 7:0; the NMI-unblocking bit is not
  // part of it and is never carried here).
  uint32_t vector;
  // Nonzero if error_code carries a delivered error code.
  uint32_t has_error_code;
  // The architectural error code, if has_error_code; else zero.
  uint32_t error_code;
  // Length of the originating instruction, for the software-interrupt /
  // privileged-software-exception / software-exception types that resume past
  // it; zero for every other type.
  uint32_t instruction_length;
} zx_vcpu_vectoring_event_t;

// Guest TSC anchor and armed TSC-deadline (topic ZX_VCPU_STATE_TSC).
typedef struct zx_vcpu_tsc_state {
  // ZX_VCPU_TSC_STATE_MAGIC.
  uint32_t magic;
  // ZX_VCPU_TSC_STATE_VERSION.
  uint32_t version;
  // sizeof(zx_vcpu_tsc_state_t).
  uint32_t size;
  // ZX_VCPU_TSC_STATE_PRESENT | ZX_VCPU_TSC_STATE_OFFSETTING. See the topic
  // comment: PRESENT/OFFSETTING together select read reporting and write
  // behavior. `PRESENT` separates "this topic carries a captured state" from
  // "TSC offsetting is available" so a capture that armed a deadline WITHOUT the
  // offset control (legal -- the WRMSR gate checks only the LVT mode) is not
  // mistaken for a legacy artifact.
  uint32_t flags;
  // Read: the guest's TSC now (host RDTSC + VMCS TSC_OFFSET, or plain host RDTSC
  // when OFFSETTING is clear). Write: informational only -- the anchor the
  // capture recorded; the kernel installs `tsc_offset`, NOT this, so a restore
  // does not re-sample RDTSC per VCPU. Kept so a durable artifact records the
  // absolute guest TSC the partition offset was computed from.
  uint64_t guest_tsc;
  // The signed VMCS TSC_OFFSET (guest RDTSC = host RDTSC + tsc_offset). Read:
  // the offset in force (0 when OFFSETTING is clear). Write (with PRESENT and
  // OFFSETTING): installed VERBATIM -- a pre-computed single-partition offset,
  // never re-derived in the kernel -- so every VCPU given the same value shares
  // one coherent clock.
  int64_t tsc_offset;
  // The armed IA32_TSC_DEADLINE in the guest's own TSC (what the guest wrote to
  // the MSR), or zero if no deadline is armed. On write (when PRESENT),
  // re-derived through the installed/current offset and re-armed -- or, at zero
  // in TSC-deadline mode, DISARMED. On read, the value the guest last wrote.
  // Only meaningful while the LVT timer is in TSC-deadline mode.
  uint64_t tsc_deadline;
} zx_vcpu_tsc_state_t;

// Read-only per-VCPU EOI accounting (topic ZX_VCPU_STATE_EXIT_COUNTERS). Both
// values are cumulative over the life of the VCPU. Diagnostics only; no magic/
// version/size because there is no write path to validate against -- the read
// path checks the buffer is exactly this size.
typedef struct zx_vcpu_exit_counters {
  // EOIs this kernel completed for the guest through the Hyper-V lazy-EOI
  // ("no EOI required") path -- retired without a VM exit.
  //
  // A POSITIVE VALUE IS THE HEALTHY, EXPECTED SIGNATURE for a lazy-EOI-
  // enlightened guest: lazy EOI ships ACTIVE and is completed by this kernel's
  // software reconcile. (An earlier revision of this comment said zero here
  // confirmed a virtual-interrupt-delivery gate held. That gate is not shipped;
  // reading zero as "correct" is the inverse of the truth, and this is the very
  // counter used to diagnose an EOI wedge.) Zero means the guest never
  // registered an assist page, or every admission was nested / EOI-trapped and
  // so declined a grant.
  uint64_t lazy_eoi_completions;
  // EOIs that ended a real in-service interrupt through the ordinary,
  // exit-costing WRMSR/MMIO path (LocalApicState::eoi_completions). This is the
  // exit rate the lazy path would otherwise reduce.
  uint64_t real_eoi_completions;
} zx_vcpu_exit_counters_t;

// Sentinels for zx_vcpu_lapic_state_t::lazy_eoi_assist_word.
//
// NOT FORGERY-PROOF, and must not be treated as such: the assist word lives in
// GUEST memory, so a guest is free to write these exact bit patterns into it.
// An ON-THREAD read can therefore legitimately return either value as the
// guest's own data. They are unambiguous only in the direction that matters --
// the kernel emits them ONLY for "no mapping" and "refused off-thread", so
// seeing one never means a grant state was observed. A consumer that must
// distinguish the two cases should use the read's own thread context, not the
// value alone.
#define ZX_VCPU_LAPIC_ASSIST_WORD_UNMAPPED ((uint32_t)0xffffffffu)
#define ZX_VCPU_LAPIC_ASSIST_WORD_OFF_THREAD ((uint32_t)0xfffffffeu)

// Read-only per-VCPU software-LAPIC snapshot (topic ZX_VCPU_STATE_LAPIC).
// Diagnostics only; captured on the calling thread from the same-thread state,
// so a cross-thread read may be a tick stale. Together these pin an interrupt
// wedge: `isr`/`isrv` say what is in service, `irr` what is waiting, `ppr`/`tpr`
// what is gating delivery, and the lazy_eoi_* fields whether a grant is
// outstanding and whether the guest has consumed its assist word.
typedef struct zx_vcpu_lapic_state {
  // In-service register: 256 bits, bit (v%32) of word (v/32) set means vector v
  // is in service. This is what raises the processor priority and blocks lower
  // vectors.
  uint32_t isr[8];
  // Interrupt-request register: vectors requested and not yet accepted (this
  // kernel's interrupt tracker). What is waiting to be delivered.
  uint32_t irr[8];
  // Highest vector currently in service, or 0 if none.
  uint32_t isrv;
  // Processor priority (0..255). A candidate vector is delivered only if its
  // class (bits 7:4) EXCEEDS ppr's class. If isrv is high, ppr is high, and a
  // lower pending vector cannot be delivered -- the wedge.
  uint32_t ppr;
  // Task priority (VTPR, 0..255), the guest's own IRQL as set via CR8/TPR.
  uint32_t tpr;
  // 1 if this VCPU has a lazy-EOI assist page registered (grant machinery live).
  uint32_t lazy_eoi_registered;
  // 1 if a lazy-EOI grant is currently outstanding (armed, awaiting consume).
  uint32_t lazy_eoi_armed;
  // The vector an outstanding grant names (meaningful only when armed).
  uint32_t lazy_eoi_vector;
  // The assist word as this kernel reads it from guest memory: 0 = the guest
  // CONSUMED the grant (took the lazy skip; this kernel owes it an ISR retire),
  // NON-ZERO = NOT consumed (the guest has not lazy-EOI'd, or will never --
  // e.g. an auto-EOI vector). This kernel writes 1 when it arms a grant, but
  // the field is guest memory and only ZERO is load-bearing: every non-zero
  // value means the same thing, so do not test for == 1.
  // ZX_VCPU_LAPIC_ASSIST_WORD_UNMAPPED = no assist mapping,
  // ZX_VCPU_LAPIC_ASSIST_WORD_OFF_THREAD = this field alone was not sampled,
  // because the read came from a thread other than the VCPU's own.
  //
  // Reading the word dereferences the kernel's mapping of the guest's VP assist
  // page, and the VCPU thread can drop and replace that mapping at any moment
  // (the guest writes HV_X64_MSR_VP_ASSIST_PAGE). Doing it off-thread is a data
  // race that can fault the host kernel, so it is refused rather than served
  // stale. EVERY OTHER FIELD in this struct is still filled in off-thread --
  // only this one carries the sentinel. To sample it for real, read the topic
  // from the VCPU's own thread.
  uint32_t lazy_eoi_assist_word;
  // Explicit padding so the u64s below are naturally aligned with NO implicit
  // padding -- the user-copy ABI-safety check rejects a struct with padding
  // holes. Must be zero.
  uint32_t reserved;
  // Cumulative lazy vs real EOI completions (as in zx_vcpu_exit_counters_t).
  uint64_t lazy_eoi_completions;
  uint64_t real_eoi_completions;
} zx_vcpu_lapic_state_t;

// Identity and version of zx_vcpu_enlightenment_t. Both are checked by the
// kernel on write, so a userspace built against a different layout is refused
// instead of being misinterpreted.
#define ZX_VCPU_ENLIGHTENMENT_MAGIC ((uint32_t)0x564e4c54u)  // 'VNLT'
#define ZX_VCPU_ENLIGHTENMENT_VERSION ((uint32_t)1u)

// Present the hypervisor to the guest as Hyper-V ("Microsoft Hv") through the
// 0x4000_0000 CPUID leaves, instead of the default KVM identity. The leaves
// below describe what that identity advertises; they are inert without this
// flag.
#define ZX_VCPU_ENLIGHTENMENT_HYPERV_IDENTITY ((uint32_t)(1u << 0))
// Deliver guest accesses to the synthetic MSR block (0x4000_0000-0x4000_ffff)
// to the VMM as ZX_PKT_TYPE_GUEST_MSR packets, instead of faulting the guest.
// Scoped to that block: the MSRs the kernel models (the local APIC, the
// in-kernel clock, the timer deadline) keep their existing behavior.
#define ZX_VCPU_ENLIGHTENMENT_DELEGATE_MSRS ((uint32_t)(1u << 1))
// Deliver guest hypercalls to the VMM as ZX_PKT_TYPE_GUEST_HYPERCALL packets,
// instead of servicing them against the kernel's own hypercall set.
#define ZX_VCPU_ENLIGHTENMENT_DELEGATE_HYPERCALLS ((uint32_t)(1u << 2))

// The Hyper-V CPUID leaves a VMM may supply: the version leaf, the feature and
// recommendation bits, and the implementation limits. The identity leaves below
// this range are fixed and answered by the kernel. A leaf outside this range is
// rejected with ZX_ERR_OUT_OF_RANGE.
#define ZX_VCPU_HYPERV_CPUID_LEAF_FIRST ((uint32_t)0x40000002u)
#define ZX_VCPU_HYPERV_CPUID_LEAF_LAST ((uint32_t)0x40000005u)
#define ZX_VCPU_HYPERV_CPUID_MAX ((uint32_t)4u)

// One synthetic CPUID leaf and the four registers it reports.
typedef struct zx_vcpu_hyperv_cpuid {
  uint32_t leaf;
  uint32_t eax;
  uint32_t ebx;
  uint32_t ecx;
  uint32_t edx;
} zx_vcpu_hyperv_cpuid_t;

// The paravirtual surface configuration of a VCPU (topic
// ZX_VCPU_STATE_ENLIGHTENMENT).
//
// A write replaces the whole configuration, as a state write should: `flags`
// names every capability that is on afterwards, and any synthetic CPUID leaf not
// listed in `cpuid[0..cpuid_count)` reads back as zero. To change one thing,
// read the topic, adjust, and write it back. Nothing is applied unless the
// entire structure validates, so a rejected write leaves the VCPU exactly as it
// was — and the all-zero-flags configuration is the default, so a VCPU that is
// never written keeps the kernel's own paravirtual surface.
typedef struct zx_vcpu_enlightenment {
  // ZX_VCPU_ENLIGHTENMENT_MAGIC.
  uint32_t magic;
  // ZX_VCPU_ENLIGHTENMENT_VERSION.
  uint32_t version;
  // sizeof(zx_vcpu_enlightenment_t).
  uint32_t size;
  // ZX_VCPU_ENLIGHTENMENT_* flags.
  uint32_t flags;
  // Number of valid entries in `cpuid`; at most ZX_VCPU_HYPERV_CPUID_MAX.
  uint32_t cpuid_count;
  // Must be zero.
  uint32_t reserved;
  zx_vcpu_hyperv_cpuid_t cpuid[ZX_VCPU_HYPERV_CPUID_MAX];
} zx_vcpu_enlightenment_t;

// Identity and version of zx_vcpu_lazy_eoi_state_t. Both are checked by the
// kernel on write, so a userspace built against a different layout is refused
// instead of being misinterpreted.
#define ZX_VCPU_LAZY_EOI_STATE_MAGIC ((uint32_t)0x45495a4cu)  // 'LZIE'
#define ZX_VCPU_LAZY_EOI_STATE_VERSION ((uint32_t)1u)

// The lazy-EOI ("no EOI required") configuration of a VCPU (topic
// ZX_VCPU_STATE_LAZY_EOI).
//
// A write replaces the configuration wholesale: `enabled` false disables the
// mechanism and releases any kernel mapping of a previous `assist_gpa`;
// `enabled` true (re-)establishes a kernel mapping of the guest-physical word
// at `assist_gpa` and unconditionally arms it to "no grant outstanding" —
// see ZX_VCPU_STATE_LAZY_EOI's own comment for why a write, including one
// that restores a snapshot, never resumes into a pre-existing grant.
//
// `assist_gpa` need not be page-aligned, but MUST be 4-byte aligned (checked;
// a misaligned value is refused with ZX_ERR_INVALID_ARGS rather than making
// the atomic access this kernel performs on it non-atomic), and is
// meaningful only when `enabled` is true; it must be zero otherwise. It
// names exactly the 4-byte word the kernel writes and reads (the TLFS VP
// assist page's `apic_assist` field) — this kernel has no other knowledge of
// that page's layout, so the VMM is responsible for adding whatever
// intra-page offset TLFS specifies before writing this topic. The 4 bytes at
// `assist_gpa` must not straddle a guest page boundary (also checked,
// separately from alignment).
typedef struct zx_vcpu_lazy_eoi_state {
  // ZX_VCPU_LAZY_EOI_STATE_MAGIC.
  uint32_t magic;
  // ZX_VCPU_LAZY_EOI_STATE_VERSION.
  uint32_t version;
  // sizeof(zx_vcpu_lazy_eoi_state_t).
  uint32_t size;
  // Whether lazy EOI is enabled for this VCPU: 0 or 1.
  uint32_t enabled;
  // Must be zero.
  uint64_t reserved;
  // Guest-physical address of the "no EOI required" word. Meaningful, and
  // must be nonzero, only when `enabled` is 1; must be zero otherwise.
  uint64_t assist_gpa;
} zx_vcpu_lazy_eoi_state_t;

// Identity and version of zx_vcpu_tlb_flush_state_t. Both are checked by the
// kernel on write, so a userspace built against a different layout is refused
// instead of being misinterpreted.
#define ZX_VCPU_TLB_FLUSH_STATE_MAGIC ((uint32_t)0x46544c56u)  // 'VLTF'
#define ZX_VCPU_TLB_FLUSH_STATE_VERSION ((uint32_t)1u)

// The TLB-flush request/status of a VCPU (topic ZX_VCPU_STATE_TLB_FLUSH). See
// that topic's own comment for the full mechanism, its cross-thread
// exception, and the completion-guarantee argument.
typedef struct zx_vcpu_tlb_flush_state {
  // ZX_VCPU_TLB_FLUSH_STATE_MAGIC.
  uint32_t magic;
  // ZX_VCPU_TLB_FLUSH_STATE_VERSION.
  uint32_t version;
  // sizeof(zx_vcpu_tlb_flush_state_t).
  uint32_t size;
  // Output-only; must be zero on write, since a write always means "request
  // one flush" and there is nothing else to say. On read: 1 if a flush is
  // currently requested but not yet consumed at a VM entry, else 0.
  uint32_t pending;
  // Output-only; must be zero on write. On read: how many flushes this VCPU
  // has consumed (executed the INVVPID for) at a VM entry, in total.
  // Monotonic.
  uint64_t flushes_consumed;
} zx_vcpu_tlb_flush_state_t;

// Rename to zx_vcpu_state_general_regs_t
// Structure to read and write VCPU state.
typedef struct zx_vcpu_state {
#if defined(__aarch64__)
  uint64_t x[31];
  uint64_t sp;
  // Contains only the user-controllable upper 4-bits (NZCV).
  uint32_t cpsr;
  uint8_t padding1[4];
#elif defined(__x86_64__)
  uint64_t rax;
  uint64_t rcx;
  uint64_t rdx;
  uint64_t rbx;
  uint64_t rsp;
  uint64_t rbp;
  uint64_t rsi;
  uint64_t rdi;
  uint64_t r8;
  uint64_t r9;
  uint64_t r10;
  uint64_t r11;
  uint64_t r12;
  uint64_t r13;
  uint64_t r14;
  uint64_t r15;
  // Contains only the user-controllable lower 32-bits.
  uint64_t rflags;
#else
  // Placeholder to avoid warnings about C vs C++ struct size differences.
  uint32_t empty;
#endif
} zx_vcpu_state_t;

// Rename to zx_vcpu_state_io_regs_t
// Structure to read and write VCPU state for IO ports.
typedef struct zx_vcpu_io {
  uint8_t access_size;
  uint8_t padding1[3];
  union {
    struct {
      uint8_t u8;
      uint8_t padding2[3];
    };
    struct {
      uint16_t u16;
      uint8_t padding3[2];
    };
    uint32_t u32;
    uint8_t data[4];
  };
} zx_vcpu_io_t;

__END_CDECLS

#endif  // ZIRCON_SYSCALLS_HYPERVISOR_H_

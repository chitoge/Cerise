// Copyright 2017 The Fuchsia Authors
//
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT

#ifndef ZIRCON_KERNEL_OBJECT_INCLUDE_OBJECT_VCPU_DISPATCHER_H_
#define ZIRCON_KERNEL_OBJECT_INCLUDE_OBJECT_VCPU_DISPATCHER_H_

#include <zircon/rights.h>
#include <zircon/syscalls/hypervisor.h>

#include <object/dispatcher.h>
#include <object/handle.h>

class GuestDispatcher;
class Vcpu;
class VmObject;

typedef struct zx_port_packet zx_port_packet_t;

class VcpuDispatcher final : public SoloDispatcher<VcpuDispatcher, ZX_DEFAULT_VCPU_RIGHTS> {
 public:
  static zx_status_t Create(const fbl::RefPtr<GuestDispatcher>& guest_dispatcher, uint32_t options,
                            zx_vaddr_t entry, KernelHandle<VcpuDispatcher>* handle,
                            zx_rights_t* rights);
  ~VcpuDispatcher();

  zx_obj_type_t get_type() const { return ZX_OBJ_TYPE_VCPU; }

  zx_status_t Enter(zx_port_packet_t& packet);
  void Kick();
  zx_status_t Interrupt(uint32_t vector);
  zx_status_t ReadState(zx_vcpu_state_t& vcpu_state) const;
  zx_status_t WriteState(const zx_vcpu_state_t& vcpu_state);
  zx_status_t WriteState(const zx_vcpu_io_t& io_state);

  // The VCPU's paravirtual ("enlightenment") configuration: which parts of the
  // synthetic surface the guest sees, and which of them the VMM owns rather than
  // the kernel. Carried by the ZX_VCPU_STATE_ENLIGHTENMENT topic.
  //
  // A write replaces the configuration wholesale and is all-or-nothing: the
  // structure's identity, version and size, its flags, and every synthetic CPUID
  // leaf it names are validated before any of it is applied, so a malformed or
  // out-of-range request cannot leave the VCPU in a state the exit handlers do
  // not expect.
  zx_status_t ReadState(zx_vcpu_enlightenment_t& enlightenment) const;
  zx_status_t WriteState(const zx_vcpu_enlightenment_t& enlightenment);

  // The event queued for delivery into the guest on the VCPU's next entry:
  // interruption type, vector, error code and, for #PF, CR2. Carried by the
  // ZX_VCPU_STATE_PENDING_EVENT topic, and the only way to inject an exception
  // with its real architectural payload — zx_vcpu_interrupt() has a vector and
  // nothing else, so it delivers a zero error code.
  //
  // A write replaces the queue wholesale and is all-or-nothing: the structure's
  // identity, version and size, and the consistency of type/vector/error
  // code/CR2/instruction length against what the architecture allows, are all
  // validated before anything is queued. Userspace therefore cannot compose an
  // interruption-information field that VM entry would reject — which would
  // otherwise surface as an opaque entry failure with no path back to the call
  // that caused it.
  zx_status_t ReadState(zx_vcpu_pending_event_t& event) const;
  zx_status_t WriteState(const zx_vcpu_pending_event_t& event);

  // The interrupted-delivery (VMCS IDT-vectoring) event, captured/restored
  // alongside the pending event; the two are distinct and both can be
  // outstanding. A write validates the whole structure (identity/version/size
  // plus the raw VMX type, vector, error-code flag and instruction length
  // against what the capture path can produce) before applying any of it, and
  // `valid == 0` clears it.
  zx_status_t ReadState(zx_vcpu_vectoring_event_t& event) const;
  zx_status_t WriteState(const zx_vcpu_vectoring_event_t& event);

  // The guest TSC anchor and armed IA32_TSC_DEADLINE. A write re-anchors the
  // TSC offset to the supplied guest TSC and re-derives the deadline; see
  // ZX_VCPU_STATE_TSC.
  zx_status_t ReadState(zx_vcpu_tsc_state_t& tsc) const;
  zx_status_t WriteState(const zx_vcpu_tsc_state_t& tsc);

  // A software access to the VCPU's xAPIC MMIO register page, carried by
  // ZX_VCPU_STATE_XAPIC_ACCESS. Write submits one validated access; read
  // retrieves its value and any EOI, interrupt, or STARTUP side effect.
  zx_status_t ReadState(zx_vcpu_xapic_access_t& access) const;
  zx_status_t WriteState(const zx_vcpu_xapic_access_t& access);

  // Host-assisted VCPU debugging controls, carried by ZX_VCPU_STATE_DEBUG.
  // Read reports host-derived support and current state; write atomically
  // replaces the active controls after validating the versioned request.
  zx_status_t ReadState(zx_vcpu_debug_state_t& debug) const;
  zx_status_t WriteState(const zx_vcpu_debug_state_t& debug);

  // Host-assisted bounded-run controls, carried by
  // ZX_VCPU_STATE_RUN_CONTROL.
  zx_status_t ReadState(zx_vcpu_run_control_t& control) const;
  zx_status_t WriteState(const zx_vcpu_run_control_t& control);

  // One-shot post-handler VM-exit observation and completed-exit budget,
  // carried by ZX_VCPU_STATE_EXIT_CONTROL.
  zx_status_t ReadState(zx_vcpu_exit_control_t& control) const;
  zx_status_t WriteState(const zx_vcpu_exit_control_t& control);

  // One-shot guest-only retired-instruction budget, carried by
  // ZX_VCPU_STATE_INSTRUCTION_CONTROL.
  zx_status_t ReadState(zx_vcpu_instruction_control_t& control) const;
  zx_status_t WriteState(const zx_vcpu_instruction_control_t& control);

  // Guest-global EPT-backed guest-physical memory-access stops, carried by
  // ZX_VCPU_STATE_MEMORY_ACCESS_CONTROL.
  zx_status_t ReadState(zx_vcpu_memory_access_control_t& control) const;
  zx_status_t WriteState(const zx_vcpu_memory_access_control_t& control);

  // Typed Intel PT configuration and bounded immutable cursor reads, carried
  // by ZX_VCPU_STATE_INTEL_PT_CONTROL.
  zx_status_t ReadState(zx_vcpu_intel_pt_control_t& control) const;
  zx_status_t WriteState(const zx_vcpu_intel_pt_control_t& control);

  // Transparent hardware instruction/data breakpoints, carried by
  // ZX_VCPU_STATE_HARDWARE_BREAKPOINT_CONTROL.
  zx_status_t ReadState(zx_vcpu_hardware_breakpoint_control_t& control) const;
  zx_status_t WriteState(const zx_vcpu_hardware_breakpoint_control_t& control);

  // The lazy-EOI ("no EOI required" VP-assist-page word) configuration,
  // carried by ZX_VCPU_STATE_LAZY_EOI. Write (re)creates or releases the
  // kernel's mapping of the target guest-physical word and unconditionally
  // arms it to "no grant outstanding" -- including on a snapshot restore, per
  // that topic's documented conservative posture.
  zx_status_t ReadState(zx_vcpu_lazy_eoi_state_t& state) const;
  zx_status_t WriteState(const zx_vcpu_lazy_eoi_state_t& state);

  // TLB-flush request/status, carried by ZX_VCPU_STATE_TLB_FLUSH. UNLIKE
  // every other topic above, both of these are safe to call from any thread
  // for any VCPU whose handle the caller holds -- see that topic's doc
  // comment.
  zx_status_t ReadState(zx_vcpu_tlb_flush_state_t& state) const;
  zx_status_t WriteState(const zx_vcpu_tlb_flush_state_t& state);

  // Read-only per-VCPU EOI accounting, carried by ZX_VCPU_STATE_EXIT_COUNTERS.
  // Like the TLB-flush read above, safe to call from any thread for any VCPU
  // whose handle the caller holds -- it only copies out two cumulative counters.
  zx_status_t ReadState(zx_vcpu_exit_counters_t& counters) const;

  // Read-only per-VCPU software-LAPIC snapshot, carried by ZX_VCPU_STATE_LAPIC.
  // Diagnostics; a cross-thread read may be a tick stale.
  zx_status_t ReadState(zx_vcpu_lapic_state_t& lapic) const;

  // The VCPU's complete architectural state, serialized into `buffer` (and read
  // back from it). Unlike the general-register accessors above these carry the
  // instruction pointer, the segment and descriptor-table registers, and the
  // control and mode registers, which is what a VMM needs to place a VCPU at a
  // chosen point of execution rather than merely adjust one that is running.
  //
  // The serialized form is versioned and self-describing, so `buffer_size` need
  // only be large enough; `actual` reports how much was written. A buffer that
  // is too small, or that on write does not describe state this kernel
  // understands, is refused rather than partially applied.
  zx_status_t ReadStateFull(uint8_t* buffer, size_t buffer_size, size_t* actual) const;
  zx_status_t WriteStateFull(const uint8_t* buffer, size_t buffer_size);

  // The VCPU's local-APIC timer, pending interrupts, and paravirtual-clock
  // mapping. Like the full architectural state, this is serialized into a
  // versioned byte stream so its live kernel objects never become ABI structs.
  zx_status_t ReadStateAsync(uint8_t* buffer, size_t buffer_size, size_t* actual) const;
  zx_status_t WriteStateAsync(const uint8_t* buffer, size_t buffer_size);

  zx_info_vcpu_t GetInfo() const;

 private:
  VcpuDispatcher(fbl::RefPtr<GuestDispatcher> guest_dispatcher, ktl::unique_ptr<Vcpu> vcpu);

  fbl::RefPtr<GuestDispatcher> guest_dispatcher_;
  ktl::unique_ptr<Vcpu> vcpu_;
};

#endif  // ZIRCON_KERNEL_OBJECT_INCLUDE_OBJECT_VCPU_DISPATCHER_H_

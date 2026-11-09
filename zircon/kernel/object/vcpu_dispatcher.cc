// Copyright 2017 The Fuchsia Authors
//
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT

#include "object/vcpu_dispatcher.h"

#include <lib/counters.h>
#include <zircon/rights.h>
#include <zircon/types.h>

#include <arch/hypervisor.h>
#include <fbl/alloc_checker.h>
#include <ktl/type_traits.h>
#include <object/guest_dispatcher.h>
#include <vm/vm_object.h>

KCOUNTER(dispatcher_vcpu_create_count, "dispatcher.vcpu.create")
KCOUNTER(dispatcher_vcpu_destroy_count, "dispatcher.vcpu.destroy")

static_assert(sizeof(zx_vcpu_xapic_access_t) == 56);
static_assert(sizeof(zx_vcpu_debug_state_t) == 32);
static_assert(sizeof(zx_vcpu_run_control_t) == 40);
static_assert(sizeof(zx_vcpu_exit_control_t) == 120);
static_assert(sizeof(zx_packet_guest_exit_observation_t) == 32);
static_assert(sizeof(zx_vcpu_instruction_control_t) == 96);
static_assert(sizeof(zx_packet_guest_instruction_budget_t) == 32);
static_assert(sizeof(zx_vcpu_memory_access_range_t) == 24);
static_assert(sizeof(zx_vcpu_memory_access_control_t) == 504);
static_assert(sizeof(zx_packet_guest_memory_access_t) == 32);
static_assert(sizeof(zx_vcpu_lazy_eoi_state_t) == 32);
static_assert(sizeof(zx_vcpu_tlb_flush_state_t) == 24);

zx_status_t VcpuDispatcher::Create(const fbl::RefPtr<GuestDispatcher>& guest_dispatcher,
                                   uint32_t options, zx_vaddr_t entry,
                                   KernelHandle<VcpuDispatcher>* handle, zx_rights_t* rights) {
#if defined(__x86_64__)
  auto vcpu = Vcpu::Create(guest_dispatcher->guest(), entry, options);
#else
  if (options != 0) {
    return ZX_ERR_INVALID_ARGS;
  }
  auto vcpu = Vcpu::Create(guest_dispatcher->guest(), entry);
#endif
  if (vcpu.is_error()) {
    return vcpu.status_value();
  }

  fbl::AllocChecker ac;
  KernelHandle new_handle(
      fbl::AdoptRef(new (&ac) VcpuDispatcher(guest_dispatcher, ktl::move(*vcpu))));
  if (!ac.check())
    return ZX_ERR_NO_MEMORY;

  *rights = default_rights();
  *handle = ktl::move(new_handle);
  return ZX_OK;
}

VcpuDispatcher::VcpuDispatcher(fbl::RefPtr<GuestDispatcher> guest_dispatcher,
                               ktl::unique_ptr<Vcpu> vcpu)
    : guest_dispatcher_(std::move(guest_dispatcher)), vcpu_(ktl::move(vcpu)) {
  kcounter_add(dispatcher_vcpu_create_count, 1);
}

VcpuDispatcher::~VcpuDispatcher() { kcounter_add(dispatcher_vcpu_destroy_count, 1); }

zx_status_t VcpuDispatcher::Enter(zx_port_packet_t& packet) {
  canary_.Assert();
  return vcpu_->Enter(packet).status_value();
}

void VcpuDispatcher::Kick() {
  canary_.Assert();
  vcpu_->Kick();
}

zx_status_t VcpuDispatcher::Interrupt(uint32_t vector) {
  canary_.Assert();
  return vcpu_->Interrupt(vector).status_value();
}

zx_status_t VcpuDispatcher::ReadState(zx_vcpu_state_t& vcpu_state) const {
  canary_.Assert();
  return vcpu_->ReadState(vcpu_state).status_value();
}

zx_status_t VcpuDispatcher::WriteState(const zx_vcpu_state_t& vcpu_state) {
  canary_.Assert();
  return vcpu_->WriteState(vcpu_state).status_value();
}

zx_status_t VcpuDispatcher::WriteState(const zx_vcpu_io_t& io_state) {
  canary_.Assert();
  return vcpu_->WriteState(io_state).status_value();
}

// Whole-VCPU state serialization and the paravirtual ("enlightenment")
// configuration are implemented by the x86 hypervisor only; VcpuArchState,
// VcpuEnlightenment and their accessors live in arch/x86's hypervisor header and
// have no arm64 counterpart yet. Report that plainly rather than failing to
// build there: these topics are optional, and a caller that asks for one on an
// architecture that cannot supply it deserves an error it can act on.
#if defined(__x86_64__)

zx_status_t VcpuDispatcher::ReadStateFull(uint8_t* buffer, size_t buffer_size,
                                          size_t* actual) const {
  canary_.Assert();
  const size_t needed = SerializedVcpuStateSize();
  if (buffer_size < needed) {
    return ZX_ERR_BUFFER_TOO_SMALL;
  }
  VcpuArchState state{};
  if (auto result = vcpu_->SaveArchState(state); result.is_error()) {
    return result.status_value();
  }
  if (auto result = SerializeVcpuState(state, buffer, buffer_size); result.is_error()) {
    return result.status_value();
  }
  *actual = needed;
  return ZX_OK;
}

zx_status_t VcpuDispatcher::ReadState(zx_vcpu_enlightenment_t& enlightenment) const {
  canary_.Assert();
  return vcpu_->ReadEnlightenment(enlightenment).status_value();
}

zx_status_t VcpuDispatcher::WriteState(const zx_vcpu_enlightenment_t& enlightenment) {
  canary_.Assert();
  // Vcpu::WriteEnlightenment validates the structure in full before applying any
  // of it, so nothing is trusted from the caller here.
  return vcpu_->WriteEnlightenment(enlightenment).status_value();
}

zx_status_t VcpuDispatcher::ReadState(zx_vcpu_pending_event_t& event) const {
  canary_.Assert();
  return vcpu_->ReadPendingEvent(event).status_value();
}

zx_status_t VcpuDispatcher::WriteState(const zx_vcpu_pending_event_t& event) {
  canary_.Assert();
  // Vcpu::WritePendingEvent validates the structure in full before queueing any
  // of it, so nothing is trusted from the caller here.
  return vcpu_->WritePendingEvent(event).status_value();
}

zx_status_t VcpuDispatcher::ReadState(zx_vcpu_vectoring_event_t& event) const {
  canary_.Assert();
  return vcpu_->ReadVectoringEvent(event).status_value();
}

zx_status_t VcpuDispatcher::WriteState(const zx_vcpu_vectoring_event_t& event) {
  canary_.Assert();
  // Vcpu::WriteVectoringEvent validates the structure in full before applying
  // any of it, so nothing is trusted from the caller here.
  return vcpu_->WriteVectoringEvent(event).status_value();
}

zx_status_t VcpuDispatcher::ReadState(zx_vcpu_tsc_state_t& tsc) const {
  canary_.Assert();
  return vcpu_->ReadTscState(tsc).status_value();
}

zx_status_t VcpuDispatcher::ReadState(zx_vcpu_exit_counters_t& counters) const {
  canary_.Assert();
  return vcpu_->ReadExitCounters(counters).status_value();
}

zx_status_t VcpuDispatcher::ReadState(zx_vcpu_lapic_state_t& lapic) const {
  canary_.Assert();
  return vcpu_->ReadLapicState(lapic).status_value();
}

zx_status_t VcpuDispatcher::WriteState(const zx_vcpu_tsc_state_t& tsc) {
  canary_.Assert();
  // Vcpu::WriteTscState validates identity before applying anything.
  return vcpu_->WriteTscState(tsc).status_value();
}

zx_status_t VcpuDispatcher::ReadState(zx_vcpu_xapic_access_t& access) const {
  canary_.Assert();
  return vcpu_->ReadXapicAccess(access).status_value();
}

zx_status_t VcpuDispatcher::WriteState(const zx_vcpu_xapic_access_t& access) {
  canary_.Assert();
  // Validate the entire userspace request before allowing the architecture
  // implementation to touch local-APIC state. Result fields are output-only,
  // and rejecting them here prevents an old kernel from accidentally treating
  // a future result extension as an input.
  if (access.magic != ZX_VCPU_XAPIC_ACCESS_MAGIC ||
      access.version != ZX_VCPU_XAPIC_ACCESS_VERSION ||
      access.size != sizeof(zx_vcpu_xapic_access_t) ||
      (access.action != ZX_VCPU_XAPIC_ACTION_READ &&
       access.action != ZX_VCPU_XAPIC_ACTION_WRITE) ||
      access.offset >= 0x1000 || (access.offset & 0xf) != 0 ||
      (access.action == ZX_VCPU_XAPIC_ACTION_READ && access.value != 0) ||
      access.result_flags != 0 || access.result_kind != ZX_VCPU_XAPIC_RESULT_NONE ||
      access.vector != 0 || access.reserved != 0 || access.target != 0 || access.entry != 0) {
    return ZX_ERR_INVALID_ARGS;
  }
  return vcpu_->WriteXapicAccess(access).status_value();
}

zx_status_t VcpuDispatcher::ReadState(zx_vcpu_debug_state_t& debug) const {
  canary_.Assert();
  return vcpu_->ReadDebugState(debug).status_value();
}

zx_status_t VcpuDispatcher::WriteState(const zx_vcpu_debug_state_t& debug) {
  canary_.Assert();
  return vcpu_->WriteDebugState(debug).status_value();
}

zx_status_t VcpuDispatcher::ReadState(zx_vcpu_run_control_t& control) const {
  canary_.Assert();
  return vcpu_->ReadRunControl(control).status_value();
}

zx_status_t VcpuDispatcher::WriteState(const zx_vcpu_run_control_t& control) {
  canary_.Assert();
  return vcpu_->WriteRunControl(control).status_value();
}

zx_status_t VcpuDispatcher::ReadState(zx_vcpu_exit_control_t& control) const {
  canary_.Assert();
  return vcpu_->ReadExitControl(control).status_value();
}

zx_status_t VcpuDispatcher::WriteState(const zx_vcpu_exit_control_t& control) {
  canary_.Assert();
  return vcpu_->WriteExitControl(control).status_value();
}

zx_status_t VcpuDispatcher::ReadState(zx_vcpu_instruction_control_t& control) const {
  canary_.Assert();
  return vcpu_->ReadInstructionControl(control).status_value();
}

zx_status_t VcpuDispatcher::WriteState(const zx_vcpu_instruction_control_t& control) {
  canary_.Assert();
  return vcpu_->WriteInstructionControl(control).status_value();
}

zx_status_t VcpuDispatcher::ReadState(zx_vcpu_memory_access_control_t& control) const {
  canary_.Assert();
  return vcpu_->ReadMemoryAccessControl(control).status_value();
}

zx_status_t VcpuDispatcher::WriteState(const zx_vcpu_memory_access_control_t& control) {
  canary_.Assert();
  return vcpu_->WriteMemoryAccessControl(control).status_value();
}

zx_status_t VcpuDispatcher::ReadState(zx_vcpu_intel_pt_control_t& control) const {
  canary_.Assert();
  return vcpu_->ReadIntelPtControl(control).status_value();
}

zx_status_t VcpuDispatcher::WriteState(const zx_vcpu_intel_pt_control_t& control) {
  canary_.Assert();
  return vcpu_->WriteIntelPtControl(control).status_value();
}

zx_status_t VcpuDispatcher::ReadState(
    zx_vcpu_hardware_breakpoint_control_t& control) const {
  canary_.Assert();
  return vcpu_->ReadHardwareBreakpointControl(control).status_value();
}

zx_status_t VcpuDispatcher::WriteState(
    const zx_vcpu_hardware_breakpoint_control_t& control) {
  canary_.Assert();
  return vcpu_->WriteHardwareBreakpointControl(control).status_value();
}

zx_status_t VcpuDispatcher::ReadState(zx_vcpu_lazy_eoi_state_t& state) const {
  canary_.Assert();
  return vcpu_->ReadLazyEoiState(state).status_value();
}

zx_status_t VcpuDispatcher::WriteState(const zx_vcpu_lazy_eoi_state_t& state) {
  canary_.Assert();
  // Vcpu::WriteLazyEoiState validates the structure in full, including that
  // fields not meaningful for the given `enabled` are zero, before applying
  // anything.
  return vcpu_->WriteLazyEoiState(state).status_value();
}

zx_status_t VcpuDispatcher::ReadState(zx_vcpu_tlb_flush_state_t& state) const {
  canary_.Assert();
  return vcpu_->ReadTlbFlushState(state).status_value();
}

zx_status_t VcpuDispatcher::WriteState(const zx_vcpu_tlb_flush_state_t& state) {
  canary_.Assert();
  // Vcpu::WriteTlbFlushState validates the structure and, deliberately unlike
  // every sibling WriteState above, is safe to call from any thread.
  return vcpu_->WriteTlbFlushState(state).status_value();
}

zx_status_t VcpuDispatcher::WriteStateFull(const uint8_t* buffer, size_t buffer_size) {
  canary_.Assert();
  VcpuArchState state{};
  // Deserialize validates the buffer's identity, version and payload size, so
  // state from a different kernel is refused here rather than applied.
  if (auto result = DeserializeVcpuState(state, buffer, buffer_size); result.is_error()) {
    return result.status_value();
  }
  return vcpu_->RestoreArchState(state).status_value();
}

zx_status_t VcpuDispatcher::ReadStateAsync(uint8_t* buffer, size_t buffer_size,
                                           size_t* actual) const {
  canary_.Assert();
  const size_t needed = SerializedVcpuAsyncStateSize();
  if (buffer_size < needed) {
    return ZX_ERR_BUFFER_TOO_SMALL;
  }
  VcpuAsyncState state{};
  if (auto result = vcpu_->SaveAsyncState(state); result.is_error()) {
    return result.status_value();
  }
  if (auto result = SerializeVcpuAsyncState(state, buffer, buffer_size); result.is_error()) {
    return result.status_value();
  }
  *actual = needed;
  return ZX_OK;
}

zx_status_t VcpuDispatcher::WriteStateAsync(const uint8_t* buffer, size_t buffer_size) {
  canary_.Assert();
  VcpuAsyncState state{};
  if (auto result = DeserializeVcpuAsyncState(state, buffer, buffer_size); result.is_error()) {
    return result.status_value();
  }
  return vcpu_->RestoreAsyncState(state).status_value();
}

#else  // !defined(__x86_64__)

zx_status_t VcpuDispatcher::ReadStateFull(uint8_t* buffer, size_t buffer_size,
                                          size_t* actual) const {
  canary_.Assert();
  return ZX_ERR_NOT_SUPPORTED;
}

zx_status_t VcpuDispatcher::WriteStateFull(const uint8_t* buffer, size_t buffer_size) {
  canary_.Assert();
  return ZX_ERR_NOT_SUPPORTED;
}

zx_status_t VcpuDispatcher::ReadStateAsync(uint8_t* buffer, size_t buffer_size,
                                           size_t* actual) const {
  canary_.Assert();
  return ZX_ERR_NOT_SUPPORTED;
}

zx_status_t VcpuDispatcher::WriteStateAsync(const uint8_t* buffer, size_t buffer_size) {
  canary_.Assert();
  return ZX_ERR_NOT_SUPPORTED;
}

zx_status_t VcpuDispatcher::ReadState(zx_vcpu_enlightenment_t& enlightenment) const {
  canary_.Assert();
  return ZX_ERR_NOT_SUPPORTED;
}

zx_status_t VcpuDispatcher::WriteState(const zx_vcpu_enlightenment_t& enlightenment) {
  canary_.Assert();
  return ZX_ERR_NOT_SUPPORTED;
}

zx_status_t VcpuDispatcher::ReadState(zx_vcpu_pending_event_t& event) const {
  canary_.Assert();
  return ZX_ERR_NOT_SUPPORTED;
}

zx_status_t VcpuDispatcher::WriteState(const zx_vcpu_pending_event_t& event) {
  canary_.Assert();
  return ZX_ERR_NOT_SUPPORTED;
}

zx_status_t VcpuDispatcher::ReadState(zx_vcpu_xapic_access_t& access) const {
  canary_.Assert();
  return ZX_ERR_NOT_SUPPORTED;
}

zx_status_t VcpuDispatcher::WriteState(const zx_vcpu_xapic_access_t& access) {
  canary_.Assert();
  return ZX_ERR_NOT_SUPPORTED;
}

zx_status_t VcpuDispatcher::ReadState(zx_vcpu_debug_state_t& debug) const {
  canary_.Assert();
  return ZX_ERR_NOT_SUPPORTED;
}

zx_status_t VcpuDispatcher::WriteState(const zx_vcpu_debug_state_t& debug) {
  canary_.Assert();
  return ZX_ERR_NOT_SUPPORTED;
}

zx_status_t VcpuDispatcher::ReadState(zx_vcpu_run_control_t& control) const {
  canary_.Assert();
  return ZX_ERR_NOT_SUPPORTED;
}

zx_status_t VcpuDispatcher::WriteState(const zx_vcpu_run_control_t& control) {
  canary_.Assert();
  return ZX_ERR_NOT_SUPPORTED;
}

zx_status_t VcpuDispatcher::ReadState(zx_vcpu_exit_control_t& control) const {
  canary_.Assert();
  return ZX_ERR_NOT_SUPPORTED;
}

zx_status_t VcpuDispatcher::WriteState(const zx_vcpu_exit_control_t& control) {
  canary_.Assert();
  return ZX_ERR_NOT_SUPPORTED;
}

zx_status_t VcpuDispatcher::ReadState(zx_vcpu_instruction_control_t& control) const {
  canary_.Assert();
  return ZX_ERR_NOT_SUPPORTED;
}

zx_status_t VcpuDispatcher::WriteState(const zx_vcpu_instruction_control_t& control) {
  canary_.Assert();
  return ZX_ERR_NOT_SUPPORTED;
}

zx_status_t VcpuDispatcher::ReadState(zx_vcpu_memory_access_control_t& control) const {
  canary_.Assert();
  return ZX_ERR_NOT_SUPPORTED;
}

zx_status_t VcpuDispatcher::WriteState(const zx_vcpu_memory_access_control_t& control) {
  canary_.Assert();
  return ZX_ERR_NOT_SUPPORTED;
}

zx_status_t VcpuDispatcher::ReadState(zx_vcpu_intel_pt_control_t& control) const {
  canary_.Assert();
  return ZX_ERR_NOT_SUPPORTED;
}

zx_status_t VcpuDispatcher::WriteState(const zx_vcpu_intel_pt_control_t& control) {
  canary_.Assert();
  return ZX_ERR_NOT_SUPPORTED;
}

// Pre-existing gap, found while adding the two stubs below: this one was
// missing entirely, and a non-x86 (arm64) kernel link -- `bazel build
// //build/kernel:arm64-vmzircon` -- fails on the undefined symbol without
// it. Not introduced by ZX_VCPU_STATE_LAZY_EOI/ZX_VCPU_STATE_TLB_FLUSH; fixed
// here because it was found in the course of adding them and blocks the same
// link.
zx_status_t VcpuDispatcher::ReadState(zx_vcpu_hardware_breakpoint_control_t& control) const {
  canary_.Assert();
  return ZX_ERR_NOT_SUPPORTED;
}

zx_status_t VcpuDispatcher::WriteState(const zx_vcpu_hardware_breakpoint_control_t& control) {
  canary_.Assert();
  return ZX_ERR_NOT_SUPPORTED;
}

zx_status_t VcpuDispatcher::ReadState(zx_vcpu_lazy_eoi_state_t& state) const {
  canary_.Assert();
  return ZX_ERR_NOT_SUPPORTED;
}

zx_status_t VcpuDispatcher::WriteState(const zx_vcpu_lazy_eoi_state_t& state) {
  canary_.Assert();
  return ZX_ERR_NOT_SUPPORTED;
}

zx_status_t VcpuDispatcher::ReadState(zx_vcpu_tlb_flush_state_t& state) const {
  canary_.Assert();
  return ZX_ERR_NOT_SUPPORTED;
}

zx_status_t VcpuDispatcher::WriteState(const zx_vcpu_tlb_flush_state_t& state) {
  canary_.Assert();
  return ZX_ERR_NOT_SUPPORTED;
}

#endif  // defined(__x86_64__)

zx_info_vcpu_t VcpuDispatcher::GetInfo() const {
  canary_.Assert();
  return vcpu_->GetInfo();
}

// Copyright 2017 The Fuchsia Authors
//
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT

#include <lib/syscalls/forward.h>
#include <zircon/syscalls/hypervisor.h>

#include <arch/hypervisor.h>
#include <fbl/alloc_checker.h>
#include <fbl/ref_ptr.h>
#include <ktl/unique_ptr.h>
#include <object/guest_dispatcher.h>
#include <object/handle.h>
#include <object/port_dispatcher.h>
#include <object/process_dispatcher.h>
#include <object/resource.h>
#include <object/vcpu_dispatcher.h>
#include <object/vm_address_region_dispatcher.h>
#include <object/vm_object_dispatcher.h>

zx_status_t sys_guest_create(zx_handle_t resource, uint32_t options, zx_handle_t* guest_handle,
                             zx_handle_t* vmar_handle) {
  zx_status_t status =
      validate_ranged_resource(resource, ZX_RSRC_KIND_SYSTEM, ZX_RSRC_SYSTEM_HYPERVISOR_BASE, 1);
  if (status != ZX_OK) {
    return status;
  }

  KernelHandle<GuestDispatcher> new_guest_handle;
  KernelHandle<VmAddressRegionDispatcher> new_vmar_handle;
  zx_rights_t guest_rights, vmar_rights;
  status = GuestDispatcher::Create(options, &new_guest_handle, &guest_rights, &new_vmar_handle,
                                   &vmar_rights);
  if (status != ZX_OK) {
    return status;
  }
  auto up = ProcessDispatcher::GetCurrent();
  status = up->MakeAndAddHandle(ktl::move(new_guest_handle), guest_rights, guest_handle);
  if (status != ZX_OK) {
    return status;
  }
  return up->MakeAndAddHandle(ktl::move(new_vmar_handle), vmar_rights, vmar_handle);
}

zx_status_t sys_guest_set_trap(zx_handle_t handle, uint32_t kind, zx_vaddr_t addr, size_t size,
                               zx_handle_t port_handle, uint64_t key) {
  auto up = ProcessDispatcher::GetCurrent();

  fbl::RefPtr<GuestDispatcher> guest;
  zx_status_t status =
      up->handle_table().GetDispatcherWithRights(*up, handle, ZX_RIGHT_WRITE, &guest);
  if (status != ZX_OK) {
    return status;
  }

  fbl::RefPtr<PortDispatcher> port;
  if (port_handle != ZX_HANDLE_INVALID) {
    status = up->handle_table().GetDispatcherWithRights(*up, port_handle, ZX_RIGHT_WRITE, &port);
    if (status != ZX_OK) {
      return status;
    }
  }

  return guest->SetTrap(kind, addr, size, ktl::move(port), key);
}

zx_status_t sys_vcpu_create(zx_handle_t guest_handle, uint32_t options, zx_vaddr_t entry,
                            zx_handle_t* out) {
#if defined(__x86_64__)
  if ((options & ~ZX_VCPU_CREATE_XAPIC) != 0u) {
#else
  if (options != 0u) {
#endif
    return ZX_ERR_INVALID_ARGS;
  }

  auto up = ProcessDispatcher::GetCurrent();
  fbl::RefPtr<GuestDispatcher> guest;
  zx_status_t status =
      up->handle_table().GetDispatcherWithRights(*up, guest_handle, ZX_RIGHT_MANAGE_THREAD, &guest);
  if (status != ZX_OK) {
    return status;
  }

  KernelHandle<VcpuDispatcher> handle;
  zx_rights_t rights;
  status = VcpuDispatcher::Create(guest, options, entry, &handle, &rights);
  if (status != ZX_OK) {
    return status;
  }

  return up->MakeAndAddHandle(ktl::move(handle), rights, out);
}

zx_status_t sys_vcpu_enter(zx_handle_t handle, user_out_ptr<zx_port_packet_t> user_packet) {
  auto up = ProcessDispatcher::GetCurrent();

  fbl::RefPtr<VcpuDispatcher> vcpu;
  zx_status_t status =
      up->handle_table().GetDispatcherWithRights(*up, handle, ZX_RIGHT_EXECUTE, &vcpu);
  if (status != ZX_OK) {
    return status;
  }

  zx_port_packet packet{};
  status = vcpu->Enter(packet);
  if (status != ZX_OK) {
    return status;
  }

  status = user_packet.copy_to_user(packet);
  if (status != ZX_OK) {
    return status;
  }

  return ZX_OK;
}

zx_status_t sys_vcpu_kick(zx_handle_t handle) {
  auto up = ProcessDispatcher::GetCurrent();

  fbl::RefPtr<VcpuDispatcher> vcpu;
  zx_status_t status =
      up->handle_table().GetDispatcherWithRights(*up, handle, ZX_RIGHT_EXECUTE, &vcpu);
  if (status != ZX_OK) {
    return status;
  }

  vcpu->Kick();
  return ZX_OK;
}

zx_status_t sys_vcpu_interrupt(zx_handle_t handle, uint32_t vector) {
  auto up = ProcessDispatcher::GetCurrent();

  fbl::RefPtr<VcpuDispatcher> vcpu;
  zx_status_t status =
      up->handle_table().GetDispatcherWithRights(*up, handle, ZX_RIGHT_SIGNAL, &vcpu);
  if (status != ZX_OK) {
    return status;
  }

  return vcpu->Interrupt(vector);
}

zx_status_t sys_vcpu_read_state(zx_handle_t handle, uint32_t kind, user_out_ptr<void> user_buffer,
                                size_t buffer_size) {
  auto up = ProcessDispatcher::GetCurrent();

  fbl::RefPtr<VcpuDispatcher> vcpu;
  zx_status_t status =
      up->handle_table().GetDispatcherWithRights(*up, handle, ZX_RIGHT_READ, &vcpu);
  if (status != ZX_OK) {
    return status;
  }
  if (kind == ZX_VCPU_STATE_FULL) {
#if defined(__x86_64__)
    // Serialize into a kernel buffer first: the serialized form is built from
    // several sources (the VMCS, saved register and extended state), so it is
    // assembled here and copied out once, rather than written piecemeal into
    // user memory.
    const size_t needed = SerializedVcpuStateSize();
    if (buffer_size < needed) {
      return ZX_ERR_BUFFER_TOO_SMALL;
    }
    fbl::AllocChecker ac;
    ktl::unique_ptr<uint8_t[]> buffer(new (&ac) uint8_t[needed]);
    if (!ac.check()) {
      return ZX_ERR_NO_MEMORY;
    }
    size_t actual = 0;
    status = vcpu->ReadStateFull(buffer.get(), needed, &actual);
    if (status != ZX_OK) {
      return status;
    }
    return user_buffer.reinterpret<uint8_t>().copy_array_to_user(buffer.get(), actual);
#else
    return ZX_ERR_NOT_SUPPORTED;
#endif
  }

  if (kind == ZX_VCPU_STATE_ASYNC) {
#if defined(__x86_64__)
    const size_t needed = SerializedVcpuAsyncStateSize();
    if (buffer_size < needed) {
      return ZX_ERR_BUFFER_TOO_SMALL;
    }
    fbl::AllocChecker ac;
    ktl::unique_ptr<uint8_t[]> buffer(new (&ac) uint8_t[needed]);
    if (!ac.check()) {
      return ZX_ERR_NO_MEMORY;
    }
    size_t actual = 0;
    status = vcpu->ReadStateAsync(buffer.get(), needed, &actual);
    if (status != ZX_OK) {
      return status;
    }
    return user_buffer.reinterpret<uint8_t>().copy_array_to_user(buffer.get(), actual);
#else
    return ZX_ERR_NOT_SUPPORTED;
#endif
  }

  if (kind == ZX_VCPU_STATE_ENLIGHTENMENT) {
    // Fixed-size, self-describing structure: the size is part of the contract,
    // so a buffer of any other length is a caller that does not agree with this
    // kernel about the layout.
    if (buffer_size != sizeof(zx_vcpu_enlightenment_t)) {
      return ZX_ERR_INVALID_ARGS;
    }
    zx_vcpu_enlightenment_t enlightenment{};
    status = vcpu->ReadState(enlightenment);
    if (status != ZX_OK) {
      return status;
    }
    return user_buffer.reinterpret<zx_vcpu_enlightenment_t>().copy_to_user(enlightenment);
  }

  if (kind == ZX_VCPU_STATE_PENDING_EVENT) {
    // Fixed-size, self-describing structure, as above: the size is part of the
    // contract, so a buffer of any other length is a caller that does not agree
    // with this kernel about the layout.
    if (buffer_size != sizeof(zx_vcpu_pending_event_t)) {
      return ZX_ERR_INVALID_ARGS;
    }
    zx_vcpu_pending_event_t event{};
    status = vcpu->ReadState(event);
    if (status != ZX_OK) {
      return status;
    }
    return user_buffer.reinterpret<zx_vcpu_pending_event_t>().copy_to_user(event);
  }

  if (kind == ZX_VCPU_STATE_VECTORING_EVENT) {
    // Fixed-size, self-describing structure, as above: the size is part of the
    // contract, so a buffer of any other length is a caller that does not agree
    // with this kernel about the layout.
    if (buffer_size != sizeof(zx_vcpu_vectoring_event_t)) {
      return ZX_ERR_INVALID_ARGS;
    }
    zx_vcpu_vectoring_event_t event{};
    status = vcpu->ReadState(event);
    if (status != ZX_OK) {
      return status;
    }
    return user_buffer.reinterpret<zx_vcpu_vectoring_event_t>().copy_to_user(event);
  }

  if (kind == ZX_VCPU_STATE_TSC) {
    if (buffer_size != sizeof(zx_vcpu_tsc_state_t)) {
      return ZX_ERR_INVALID_ARGS;
    }
    zx_vcpu_tsc_state_t tsc{};
    status = vcpu->ReadState(tsc);
    if (status != ZX_OK) {
      return status;
    }
    return user_buffer.reinterpret<zx_vcpu_tsc_state_t>().copy_to_user(tsc);
  }

  if (kind == ZX_VCPU_STATE_XAPIC_ACCESS) {
    if (buffer_size != sizeof(zx_vcpu_xapic_access_t)) {
      return ZX_ERR_INVALID_ARGS;
    }
    zx_vcpu_xapic_access_t access{};
    status = vcpu->ReadState(access);
    if (status != ZX_OK) {
      return status;
    }
    return user_buffer.reinterpret<zx_vcpu_xapic_access_t>().copy_to_user(access);
  }

  if (kind == ZX_VCPU_STATE_DEBUG) {
    if (buffer_size != sizeof(zx_vcpu_debug_state_t)) {
      return ZX_ERR_INVALID_ARGS;
    }
    zx_vcpu_debug_state_t debug{};
    status = vcpu->ReadState(debug);
    if (status != ZX_OK) {
      return status;
    }
    return user_buffer.reinterpret<zx_vcpu_debug_state_t>().copy_to_user(debug);
  }

  if (kind == ZX_VCPU_STATE_RUN_CONTROL) {
    if (buffer_size != sizeof(zx_vcpu_run_control_t)) {
      return ZX_ERR_INVALID_ARGS;
    }
    zx_vcpu_run_control_t control{};
    status = vcpu->ReadState(control);
    if (status != ZX_OK) {
      return status;
    }
    return user_buffer.reinterpret<zx_vcpu_run_control_t>().copy_to_user(control);
  }

  if (kind == ZX_VCPU_STATE_EXIT_CONTROL) {
    if (buffer_size != sizeof(zx_vcpu_exit_control_t)) {
      return ZX_ERR_INVALID_ARGS;
    }
    zx_vcpu_exit_control_t control{};
    status = vcpu->ReadState(control);
    if (status != ZX_OK) {
      return status;
    }
    return user_buffer.reinterpret<zx_vcpu_exit_control_t>().copy_to_user(control);
  }

  if (kind == ZX_VCPU_STATE_INSTRUCTION_CONTROL) {
    if (buffer_size != sizeof(zx_vcpu_instruction_control_t)) {
      return ZX_ERR_INVALID_ARGS;
    }
    zx_vcpu_instruction_control_t control{};
    status = vcpu->ReadState(control);
    if (status != ZX_OK) {
      return status;
    }
    return user_buffer.reinterpret<zx_vcpu_instruction_control_t>().copy_to_user(control);
  }

  if (kind == ZX_VCPU_STATE_MEMORY_ACCESS_CONTROL) {
    if (buffer_size != sizeof(zx_vcpu_memory_access_control_t)) {
      return ZX_ERR_INVALID_ARGS;
    }
    zx_vcpu_memory_access_control_t control{};
    status = vcpu->ReadState(control);
    if (status != ZX_OK) {
      return status;
    }
    return user_buffer.reinterpret<zx_vcpu_memory_access_control_t>().copy_to_user(control);
  }

  if (kind == ZX_VCPU_STATE_INTEL_PT_CONTROL) {
    if (buffer_size != sizeof(zx_vcpu_intel_pt_control_t)) {
      return ZX_ERR_INVALID_ARGS;
    }
    // The fixed response carries one 4 KiB raw trace chunk. Keep it off the
    // syscall kernel stack.
    fbl::AllocChecker ac;
    ktl::unique_ptr<zx_vcpu_intel_pt_control_t> control(
        new (&ac) zx_vcpu_intel_pt_control_t{});
    if (!ac.check()) {
      return ZX_ERR_NO_MEMORY;
    }
    status = vcpu->ReadState(*control);
    if (status != ZX_OK) {
      return status;
    }
    return user_buffer.reinterpret<zx_vcpu_intel_pt_control_t>().copy_to_user(*control);
  }

  if (kind == ZX_VCPU_STATE_HARDWARE_BREAKPOINT_CONTROL) {
    if (buffer_size != sizeof(zx_vcpu_hardware_breakpoint_control_t)) {
      return ZX_ERR_INVALID_ARGS;
    }
    zx_vcpu_hardware_breakpoint_control_t control{};
    status = vcpu->ReadState(control);
    if (status != ZX_OK) {
      return status;
    }
    return user_buffer.reinterpret<zx_vcpu_hardware_breakpoint_control_t>()
        .copy_to_user(control);
  }

  if (kind == ZX_VCPU_STATE_LAZY_EOI) {
    if (buffer_size != sizeof(zx_vcpu_lazy_eoi_state_t)) {
      return ZX_ERR_INVALID_ARGS;
    }
    zx_vcpu_lazy_eoi_state_t state{};
    status = vcpu->ReadState(state);
    if (status != ZX_OK) {
      return status;
    }
    return user_buffer.reinterpret<zx_vcpu_lazy_eoi_state_t>().copy_to_user(state);
  }

  if (kind == ZX_VCPU_STATE_TLB_FLUSH) {
    if (buffer_size != sizeof(zx_vcpu_tlb_flush_state_t)) {
      return ZX_ERR_INVALID_ARGS;
    }
    zx_vcpu_tlb_flush_state_t state{};
    status = vcpu->ReadState(state);
    if (status != ZX_OK) {
      return status;
    }
    return user_buffer.reinterpret<zx_vcpu_tlb_flush_state_t>().copy_to_user(state);
  }

  if (kind == ZX_VCPU_STATE_EXIT_COUNTERS) {
    if (buffer_size != sizeof(zx_vcpu_exit_counters_t)) {
      return ZX_ERR_INVALID_ARGS;
    }
    zx_vcpu_exit_counters_t counters{};
    status = vcpu->ReadState(counters);
    if (status != ZX_OK) {
      return status;
    }
    return user_buffer.reinterpret<zx_vcpu_exit_counters_t>().copy_to_user(counters);
  }

  if (kind == ZX_VCPU_STATE_LAPIC) {
    if (buffer_size != sizeof(zx_vcpu_lapic_state_t)) {
      return ZX_ERR_INVALID_ARGS;
    }
    zx_vcpu_lapic_state_t lapic{};
    status = vcpu->ReadState(lapic);
    if (status != ZX_OK) {
      return status;
    }
    return user_buffer.reinterpret<zx_vcpu_lapic_state_t>().copy_to_user(lapic);
  }

  if (kind != ZX_VCPU_STATE || buffer_size != sizeof(zx_vcpu_state_t)) {
    return ZX_ERR_INVALID_ARGS;
  }

  zx_vcpu_state_t state{};
  status = vcpu->ReadState(state);
  if (status != ZX_OK) {
    return status;
  }

  return user_buffer.reinterpret<zx_vcpu_state_t>().copy_to_user(state);
}

template <typename T>
static zx_status_t WriteState(VcpuDispatcher* vcpu, user_in_ptr<const void> user_buffer,
                              size_t buffer_size) {
  if (buffer_size != sizeof(T)) {
    return ZX_ERR_INVALID_ARGS;
  }

  T state{};
  zx_status_t status = user_buffer.reinterpret<const T>().copy_from_user(&state);
  if (status != ZX_OK) {
    return status;
  }
  return vcpu->WriteState(state);
}

zx_status_t sys_vcpu_write_state(zx_handle_t handle, uint32_t kind,
                                 user_in_ptr<const void> user_buffer, size_t buffer_size) {
  auto up = ProcessDispatcher::GetCurrent();

  fbl::RefPtr<VcpuDispatcher> vcpu;
  zx_status_t status =
      up->handle_table().GetDispatcherWithRights(*up, handle, ZX_RIGHT_WRITE, &vcpu);
  if (status != ZX_OK) {
    return status;
  }

  switch (kind) {
    case ZX_VCPU_STATE:
      return WriteState<zx_vcpu_state_t>(vcpu.get(), user_buffer, buffer_size);
    case ZX_VCPU_IO:
      return WriteState<zx_vcpu_io_t>(vcpu.get(), user_buffer, buffer_size);
    case ZX_VCPU_STATE_ENLIGHTENMENT:
      // The structure carries its own magic, version and size, all checked
      // below the copy; the exact-length check the template applies only
      // establishes that the caller and this kernel agree on how much there is
      // to read.
      return WriteState<zx_vcpu_enlightenment_t>(vcpu.get(), user_buffer, buffer_size);
    case ZX_VCPU_STATE_PENDING_EVENT:
      // As above: the structure carries its own magic, version and size, and
      // the whole architectural shape of the event is checked below the copy.
      // The exact-length check the template applies only establishes that the
      // caller and this kernel agree on how much there is to read.
      return WriteState<zx_vcpu_pending_event_t>(vcpu.get(), user_buffer, buffer_size);
    case ZX_VCPU_STATE_VECTORING_EVENT:
      // Self-describing like the pending event; WriteVectoringEvent validates
      // the identity triple and the whole raw-VMX shape before applying any of
      // it. The template's exact-length check only confirms the caller and this
      // kernel agree on the size.
      return WriteState<zx_vcpu_vectoring_event_t>(vcpu.get(), user_buffer, buffer_size);
    case ZX_VCPU_STATE_TSC:
      // Self-describing; WriteTscState validates the identity triple before it
      // re-anchors the TSC offset. The template's exact-length check only
      // confirms the caller and this kernel agree on the size.
      return WriteState<zx_vcpu_tsc_state_t>(vcpu.get(), user_buffer, buffer_size);
    case ZX_VCPU_STATE_XAPIC_ACCESS:
      // The fixed-size structure carries its own identity and version. The
      // dispatcher validates those and all request/result fields before the
      // architecture implementation touches the local APIC.
      return WriteState<zx_vcpu_xapic_access_t>(vcpu.get(), user_buffer, buffer_size);
    case ZX_VCPU_STATE_DEBUG:
      // Fixed-size and self-describing. The architecture implementation checks
      // the identity, version, output-only fields, requested flags, and actual
      // host support before changing any control.
      return WriteState<zx_vcpu_debug_state_t>(vcpu.get(), user_buffer, buffer_size);
    case ZX_VCPU_STATE_RUN_CONTROL:
      // Fixed-size and self-describing. Host support and the complete request
      // are validated before the VMX execution control is changed.
      return WriteState<zx_vcpu_run_control_t>(vcpu.get(), user_buffer, buffer_size);
    case ZX_VCPU_STATE_EXIT_CONTROL:
      // Fixed-size and self-describing. The architecture validates the exact
      // runtime reason set, one-shot budget, and acknowledgement before
      // replacing the current control.
      return WriteState<zx_vcpu_exit_control_t>(vcpu.get(), user_buffer, buffer_size);
    case ZX_VCPU_STATE_INSTRUCTION_CONTROL:
      // Fixed-size and self-describing. Hardware support, global PMU resource
      // ownership, the budget, and acknowledgement are validated before the
      // VCPU state or PMU reservation changes.
      return WriteState<zx_vcpu_instruction_control_t>(vcpu.get(), user_buffer, buffer_size);
    case ZX_VCPU_STATE_MEMORY_ACCESS_CONTROL:
      // The architecture validates the complete bounded range set, exact
      // acknowledgement, mappings, and effective permissions before changing
      // any guest-global EPT state.
      return WriteState<zx_vcpu_memory_access_control_t>(vcpu.get(), user_buffer, buffer_size);
    case ZX_VCPU_STATE_INTEL_PT_CONTROL: {
      if (buffer_size != sizeof(zx_vcpu_intel_pt_control_t)) {
        return ZX_ERR_INVALID_ARGS;
      }
      // Keep the 4 KiB request/response carrier off the syscall kernel stack.
      fbl::AllocChecker ac;
      ktl::unique_ptr<zx_vcpu_intel_pt_control_t> control(
          new (&ac) zx_vcpu_intel_pt_control_t{});
      if (!ac.check()) {
        return ZX_ERR_NO_MEMORY;
      }
      status =
          user_buffer.reinterpret<const zx_vcpu_intel_pt_control_t>().copy_from_user(control.get());
      if (status != ZX_OK) {
        return status;
      }
      return vcpu->WriteState(*control);
    }
    case ZX_VCPU_STATE_HARDWARE_BREAKPOINT_CONTROL:
      return WriteState<zx_vcpu_hardware_breakpoint_control_t>(
          vcpu.get(), user_buffer, buffer_size);
    case ZX_VCPU_STATE_LAZY_EOI:
      // The structure carries its own magic, version and size, and every
      // field not meaningful for the given `enabled` is checked below the
      // copy. The exact-length check the template applies only establishes
      // that the caller and this kernel agree on how much there is to read.
      return WriteState<zx_vcpu_lazy_eoi_state_t>(vcpu.get(), user_buffer, buffer_size);
    case ZX_VCPU_STATE_TLB_FLUSH:
      // Unlike every other case here, Vcpu::WriteTlbFlushState is safe to run
      // against a `vcpu` this thread did not create -- the caller need only
      // hold a handle with ZX_RIGHT_WRITE to it, exactly as for any other
      // topic; the exception is that the *target* VCPU need not be the
      // *calling thread's* VCPU. See ZX_VCPU_STATE_TLB_FLUSH's doc comment.
      return WriteState<zx_vcpu_tlb_flush_state_t>(vcpu.get(), user_buffer, buffer_size);
    case ZX_VCPU_STATE_FULL: {
#if defined(__x86_64__)
      // Bound the copy before allocating: the serialized form's length is fixed
      // by this kernel, so a larger buffer says nothing useful and a smaller one
      // cannot describe a complete state.
      const size_t needed = SerializedVcpuStateSize();
      if (buffer_size < needed) {
        return ZX_ERR_BUFFER_TOO_SMALL;
      }
      fbl::AllocChecker ac;
      ktl::unique_ptr<uint8_t[]> buffer(new (&ac) uint8_t[needed]);
      if (!ac.check()) {
        return ZX_ERR_NO_MEMORY;
      }
      status = user_buffer.reinterpret<const uint8_t>().copy_array_from_user(buffer.get(), needed);
      if (status != ZX_OK) {
        return status;
      }
      return vcpu->WriteStateFull(buffer.get(), needed);
#else
      return ZX_ERR_NOT_SUPPORTED;
#endif
    }
    case ZX_VCPU_STATE_ASYNC: {
#if defined(__x86_64__)
      const size_t needed = SerializedVcpuAsyncStateSize();
      if (buffer_size < needed) {
        return ZX_ERR_BUFFER_TOO_SMALL;
      }
      fbl::AllocChecker ac;
      ktl::unique_ptr<uint8_t[]> buffer(new (&ac) uint8_t[needed]);
      if (!ac.check()) {
        return ZX_ERR_NO_MEMORY;
      }
      status = user_buffer.reinterpret<const uint8_t>().copy_array_from_user(buffer.get(), needed);
      if (status != ZX_OK) {
        return status;
      }
      return vcpu->WriteStateAsync(buffer.get(), needed);
#else
      return ZX_ERR_NOT_SUPPORTED;
#endif
    }
    default:
      return ZX_ERR_INVALID_ARGS;
  }
}

// Stub dispatcher implementations when //config:hypervisor=false.
//
// object_info.cc unconditionally references VcpuDispatcher (OB_GET_INFO macro),
// so the vtable and destructor must exist in the binary even though VCPUs can
// never be created when hypervisor support is compiled out.
//
// Vcpu and Guest are defined here as minimal complete types before the
// dispatcher headers are included, satisfying unique_ptr<Vcpu> and
// unique_ptr<Guest> destructors without pulling in arch/hypervisor.h.

// Minimal stub types so unique_ptr<Vcpu>/unique_ptr<Guest> destructors compile.
class Vcpu {
 public:
  ~Vcpu() {}
};
class Guest {
 public:
  virtual ~Guest() {}
};

#include "object/guest_dispatcher.h"
#include "object/vcpu_dispatcher.h"
#include <zircon/errors.h>
#include <zircon/types.h>
#include <zircon/syscalls/hypervisor.h>

GuestDispatcher::~GuestDispatcher() {}

// static
zx_status_t GuestDispatcher::Create(uint32_t /*options*/,
                                    KernelHandle<GuestDispatcher>* /*guest_handle*/,
                                    zx_rights_t* /*guest_rights*/,
                                    KernelHandle<VmAddressRegionDispatcher>* /*vmar_handle*/,
                                    zx_rights_t* /*vmar_rights*/) {
  return ZX_ERR_NOT_SUPPORTED;
}

zx_status_t GuestDispatcher::SetTrap(uint32_t /*kind*/, zx_vaddr_t /*addr*/, size_t /*len*/,
                                     fbl::RefPtr<PortDispatcher> /*port*/, uint64_t /*key*/) {
  return ZX_ERR_NOT_SUPPORTED;
}

VcpuDispatcher::~VcpuDispatcher() {}

// static
zx_status_t VcpuDispatcher::Create(const fbl::RefPtr<GuestDispatcher>& /*guest_dispatcher*/,
                                   uint32_t /*options*/, zx_vaddr_t /*entry*/,
                                   KernelHandle<VcpuDispatcher>* /*handle*/,
                                   zx_rights_t* /*rights*/) {
  return ZX_ERR_NOT_SUPPORTED;
}

zx_status_t VcpuDispatcher::Enter(zx_port_packet_t& /*packet*/) {
  return ZX_ERR_NOT_SUPPORTED;
}

void VcpuDispatcher::Kick() {}

zx_status_t VcpuDispatcher::Interrupt(uint32_t /*vector*/) {
  return ZX_ERR_NOT_SUPPORTED;
}

zx_status_t VcpuDispatcher::ReadState(zx_vcpu_state_t& /*vcpu_state*/) const {
  return ZX_ERR_NOT_SUPPORTED;
}

zx_status_t VcpuDispatcher::WriteState(const zx_vcpu_state_t& /*vcpu_state*/) {
  return ZX_ERR_NOT_SUPPORTED;
}

zx_status_t VcpuDispatcher::WriteState(const zx_vcpu_io_t& /*io_state*/) {
  return ZX_ERR_NOT_SUPPORTED;
}

zx_info_vcpu_t VcpuDispatcher::GetInfo() const { return {}; }

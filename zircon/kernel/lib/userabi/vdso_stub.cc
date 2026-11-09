// Stub used when real vDSO creation is unavailable.
// Provides a minimal VDso::Create so the kernel links without vdso-code.h.

#include <lib/userabi/vdso.h>
#include <ktl/span.h>
#include <object/handle.h>
#include <object/vm_object_dispatcher.h>
#include <phys/handoff.h>

const VDso* VDso::Create(
    const HandoffEnd::Elf& /*elf_image*/,
    ktl::span<KernelHandle<VmObjectDispatcher>, userboot::kNumVdsoVariants> /*vmo_kernel_handles*/,
    KernelHandle<VmObjectDispatcher>* /*time_values_handle*/) {
  // Stub: vDSO creation is not implemented in this build.
  return nullptr;
}

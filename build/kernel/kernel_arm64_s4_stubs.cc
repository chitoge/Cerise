// ARM64 kernel stubs: hw_watchdog, vDSO, code-patching self-test, libc runtime globals,
// user-copy, clocks_and_pmic, and hypervisor (Vcpu) stubs for tree-build.
// x86-specific stubs (_x86_copy_to_or_from_user etc.) are omitted.

#include <arch/hypervisor.h>
#include <arch/arm64/hypervisor/el2_state.h>
#include <arch/arm64/hypervisor/gic/gicv2.h>
#include <arch/arm64/hypervisor/gic/gicv3.h>
#include <arch/user_copy.h>
#include <dev/clocks_and_pmic.h>
#include <dev/hw_watchdog.h>
#include <lib/code-patching/self-test.h>
#include <object/port_dispatcher.h>
#include <zircon/errors.h>
#include <zircon/syscalls/hypervisor.h>
#include <new>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

// ── hw_watchdog ────────────────────────────────────────────────────────────
extern "C" void hw_watchdog_pet(void) {}
extern "C" void hw_watchdog_suppress_petting(bool suppress) { (void)suppress; }
extern "C" zx_status_t hw_watchdog_set_enabled(bool enabled) {
  (void)enabled;
  return ZX_OK;
}

extern "C" { void* __dso_handle = &__dso_handle; }

// ── code patching ──────────────────────────────────────────────────────────
extern "C" void CodePatchingNopTest() {}

// ── nothrow new ────────────────────────────────────────────────────────────
namespace std { const nothrow_t nothrow{}; }
void* operator new(size_t, const std::nothrow_t&) noexcept { return nullptr; }
void* operator new[](size_t, const std::nothrow_t&) noexcept { return nullptr; }

// ── arch user-copy (minimal: no EL0 access validation, for tree-build only) ─
zx_status_t arch_copy_to_user(void* dst, const void* src, size_t len) {
  memcpy(dst, src, len);
  return ZX_OK;
}
zx_status_t arch_copy_from_user(void* dst, const void* src, size_t len) {
  memcpy(dst, src, len);
  return ZX_OK;
}
UserCopyCaptureFaultsResult arch_copy_to_user_capture_faults(
    void* dst, const void* src, size_t len, CopyContext) {
  memcpy(dst, src, len);
  return UserCopyCaptureFaultsResult{ZX_OK};
}
UserCopyCaptureFaultsResult arch_copy_from_user_capture_faults(
    void* dst, const void* src, size_t len, CopyContext) {
  memcpy(dst, src, len);
  return UserCopyCaptureFaultsResult{ZX_OK};
}

// ── clocks_and_pmic (no SOC-specific HW in tree-build) ────────────────────
zx_status_t clocks_and_pmic_prepare_for_suspend() { return ZX_ERR_NOT_SUPPORTED; }
zx_status_t clocks_and_pmic_wakeup_from_suspend() { return ZX_ERR_NOT_SUPPORTED; }

// ── hypervisor (Vcpu / Guest) stubs ───────────────────────────────────────
zx::result<ktl::unique_ptr<Vcpu>> Vcpu::Create(Guest&, zx_vaddr_t) {
  return zx::error(ZX_ERR_NOT_SUPPORTED);
}
Vcpu::~Vcpu() {}
zx::result<> Vcpu::Enter(zx_port_packet_t&) { return zx::error(ZX_ERR_NOT_SUPPORTED); }
void Vcpu::Kick() {}
zx::result<> Vcpu::Interrupt(uint32_t) { return zx::error(ZX_ERR_NOT_SUPPORTED); }
zx::result<> Vcpu::ReadState(zx_vcpu_state_t&) const { return zx::error(ZX_ERR_NOT_SUPPORTED); }
zx::result<> Vcpu::WriteState(const zx_vcpu_state_t&) { return zx::error(ZX_ERR_NOT_SUPPORTED); }
zx_info_vcpu_t Vcpu::GetInfo() const { return {}; }

zx::result<ktl::unique_ptr<Guest>> Guest::Create() { return zx::error(ZX_ERR_NOT_SUPPORTED); }
Guest::~Guest() {}
zx::result<> Guest::SetTrap(uint32_t, zx_vaddr_t, size_t, fbl::RefPtr<PortDispatcher>, uint64_t) {
  return zx::error(ZX_ERR_NOT_SUPPORTED);
}

// ── EL2 TLB invalidation (hypervisor, no-op stubs) ────────────────────────
extern "C" zx_status_t arm64_el2_tlbi_ipa(uint64_t, zx_vaddr_t, bool) {
  return ZX_ERR_NOT_SUPPORTED;
}
extern "C" zx_status_t arm64_el2_tlbi_vmid(uint64_t) { return ZX_ERR_NOT_SUPPORTED; }
extern "C" zx_status_t arm64_el2_tlbi_el2() { return ZX_ERR_NOT_SUPPORTED; }

// ── GIC hypervisor hw_interface registration (no-op stubs) ────────────────
void gicv2_hw_interface_register() {}
void gicv3_hw_interface_register() {}

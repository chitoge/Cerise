// Copyright 2021 The Fuchsia Authors
//
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT

// Minimal dev-init for qemu-arm64 / tree-build: only includes drivers present
// in this vendor tree. SOC-specific drivers (moonflower, amlogic, qcom, iris,
// motmot, hdcp, watchdog32) are excluded because their headers are not in tree.

#include <lib/boot-options/boot-options.h>

#include <dev/arm_smmu/smmu.h>
#include <dev/arm_smmu/smmu_mode.h>
#include <dev/interrupt/arm_gicv2_init.h>
#include <dev/interrupt/arm_gicv3_init.h>
#include <dev/psci.h>
#include <dev/timer/arm_generic.h>
#include <ktl/type_traits.h>
#include <ktl/variant.h>
#include <phys/arch/arch-handoff.h>

#include <ktl/enforce.h>

namespace {

void ArmGicInitEarly(const ktl::monostate&) {}
void ArmGicInitPostVm(const ktl::monostate&) {}
void ArmGicInitLate(const ktl::monostate&) {}

}  // namespace

void PlatformDriverHandoffEarly(const ArchPhysHandoff& arch_handoff) {
  ktl::visit([](const auto& config) { ArmGicInitEarly(config); }, arch_handoff.gic_driver);

  if (arch_handoff.generic_timer_driver) {
    ArmGenericTimerInit(arch_handoff.generic_timer_driver.value());
  }

  if (arch_handoff.psci_driver) {
    PsciInit(arch_handoff.psci_driver.value(), arch_handoff.psci_cpu_suspend_driver.get());
  }
}

void PlatformDriverHandoffPostVm(const ArchPhysHandoff& arch_handoff) {
  ktl::visit([](const auto& config) { ArmGicInitPostVm(config); }, arch_handoff.gic_driver);

  if (arch_handoff.generic_timer_driver) {
    ArmGenericTimerInitPostVm(arch_handoff.generic_timer_driver.value());
  }
}

void PlatformDriverHandoffLate(const ArchPhysHandoff& arch_handoff) {
  ktl::visit([](const auto& config) { ArmGicInitLate(config); }, arch_handoff.gic_driver);

  if (const char* const mode_string = BootOptions::Get()->arm_smmu_mode.data();
      (arch_handoff.arm_smmu_drivers.size() > 0) &&
      !::arm_smmu::ValidateSmmuModeString(mode_string)) {
    dprintf(INFO, "WARNING - Parse errors present in kernel.arm-smmu-mode string \"%s\"\n",
            mode_string);
  }

  for (const zbi_dcfg_arm_smmu_driver_t& config : arch_handoff.arm_smmu_drivers.get()) {
    zx::result<fbl::RefPtr<iommu::Iommu>> result = ArmSmmu::Create(config);
    if (result.is_error()) {
      dprintf(INFO, "WARNING - Failed to construct ARM SMMU @ 0x%08lx result %d\n",
              config.mmio_phys, result.error_value());
    }
  }
}

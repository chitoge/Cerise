// Copyright 2020 The Fuchsia Authors
//
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT

#ifndef ZIRCON_KERNEL_LIB_ARCH_INCLUDE_LIB_ARCH_X86_POWER_H_
#define ZIRCON_KERNEL_LIB_ARCH_INCLUDE_LIB_ARCH_X86_POWER_H_

#include <lib/arch/x86/cpuid.h>
#include <lib/arch/x86/feature.h>

namespace arch {

// Sets the "Turbo" state, which allows the processor to dynamically adjust and
// control its operating frequency. Turbo here collectively refers to the
// analogous technologies of "Intel Turbo Boost" and "AMD Turbo Core". Returns
// false if Turbo is unsupported; else returns true.
//
// For more detail, see:
// [intel/vol3]: 14.3.3  Intel® Turbo Boost Technology.
// [amd/vol2]: 17.2  Core Performance Boost.
template <typename CpuidIoProvider, typename MsrIoProvider>
inline bool SetX86CpuTurboState(CpuidIoProvider&& cpuid, MsrIoProvider&& msr, bool enable) {
  // [intel/vol3]: 14.3.2.1  Discover Hardware Support and Enabling of Opportunistic Processor
  // Performance Operation.
  //
  // The Intel way, which Intel makes rather convoluted. Initially, when
  // powered on, IA32_MISC_ENABLE enumerates whether Turbo is supported: if
  // IDA_DISABLE is set, then Turbo is supported and is disabled by default;
  // else it is not supported. Moreover, unlike every other CPUID feature, leaf
  // 0x6 EAX does not enumerate whether Turbo is supported, but instead
  // dynamically reflects the actual Turbo state. Accordingly, to determine
  // whether Turbo is supported we must cross-reference both CPUID and MSR
  // state.
  //
  // IDA stands for "Intel Dynamic Acceleration", an earlier name/iteration of
  // Intel Turbo Boost.
  if (MiscFeaturesMsr::IsSupported(cpuid) &&
      CpuidSupports<CpuidThermalAndPowerFeatureFlagsA>(cpuid)) {
    const auto intel_features = cpuid.template Read<CpuidThermalAndPowerFeatureFlagsA>();
    auto misc_enable = MiscFeaturesMsr::Get().ReadFrom(&msr);
    const bool intel_supported_and_on = intel_features.turbo() || intel_features.turbo_max();
    const bool intel_supported_and_off = misc_enable.ida_disable();
    const bool intel_supported = intel_supported_and_on || intel_supported_and_off;
    if (intel_supported) {
      // Only write if the bit is not already what we want. IA32_MISC_ENABLE is
      // routinely trapped to SMM by OEM firmware, and an SMI is broadcast to
      // every core, so a redundant write is not free -- on firmware whose
      // handler misbehaves it can wedge the whole machine with no output on any
      // channel and no reset. Skipping a write that would change nothing costs
      // nothing and avoids entering that path on the common case where the
      // desired turbo state is already in effect.
      if (misc_enable.ida_disable() != !enable) {
        misc_enable.set_ida_disable(!enable).WriteTo(&msr);
      }
      return true;
    }
  }

  // The AMD way.
  // CPB stands for "Core Performance Boost", an earlier name/iteration of AMD
  // Turbo Core.
  if (CpuidSupports<CpuidAdvancedPowerFeatureFlags>(cpuid) &&
      cpuid.template Read<CpuidAdvancedPowerFeatureFlags>().cpb()) {
    // Same reasoning as the Intel path above: skip a write that would not
    // change the bit.
    auto hwcr = AmdHardwareConfigurationMsr::Get().ReadFrom(&msr);
    if (hwcr.cpb_dis() != !enable) {
      hwcr.set_cpb_dis(!enable).WriteTo(&msr);
    }
    return true;
  }

  // Unsupported.
  return false;
}

}  // namespace arch

#endif  // ZIRCON_KERNEL_LIB_ARCH_INCLUDE_LIB_ARCH_X86_POWER_H_

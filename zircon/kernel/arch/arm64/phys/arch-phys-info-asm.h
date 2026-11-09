// Copyright 2021 The Fuchsia Authors
//
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT
//
// Minimal arch-phys-info-asm.h: assembly constants for ArchPhysInfo struct offsets.
// Generated from gen-arch-phys-info-asm.cc via hwreg::AsmHeader; this is a
// checked-in minimal subset covering what arm64/phys assembly files need.
//
// ArchPhysInfo layout:
//   uint64_t psci_reset_registers[4];  // offset 0, size 32
//   bool smccc_use_hvc;                // offset 32
//   bool smccc_disabled;               // offset 33
//   bool have_psci_features;           // offset 34

#ifndef ZIRCON_KERNEL_ARCH_ARM64_PHYS_ARCH_PHYS_INFO_ASM_H_
#define ZIRCON_KERNEL_ARCH_ARM64_PHYS_ARCH_PHYS_INFO_ASM_H_

#define ARCH_PHYS_INFO_PSCI_RESET_REGISTERS       0
#define ARCH_PHYS_INFO_PSCI_RESET_REGISTERS_COUNT 4
#define ARCH_PHYS_INFO_SMCCC_USE_HVC              32
#define ARCH_PHYS_INFO_SMCCC_DISABLED             33
#define ARCH_PHYS_INFO_HAVE_PSCI_FEATURES         34

#endif  // ZIRCON_KERNEL_ARCH_ARM64_PHYS_ARCH_PHYS_INFO_ASM_H_

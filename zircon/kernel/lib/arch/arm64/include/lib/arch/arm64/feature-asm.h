// Copyright 2021 The Fuchsia Authors
//
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT
//
// Minimal feature-asm.h: assembly constants for ARM64 ID registers (feature detection).
// Generated from gen-arm64-feature-asm.cc via hwreg::AsmHeader; this is a
// checked-in minimal subset covering what the phys and kernel assembly files need.

#ifndef ZIRCON_KERNEL_LIB_ARCH_ARM64_INCLUDE_LIB_ARCH_ARM64_FEATURE_ASM_H_
#define ZIRCON_KERNEL_LIB_ARCH_ARM64_INCLUDE_LIB_ARCH_ARM64_FEATURE_ASM_H_

// ID_AA64ISAR0_EL1 — Instruction Set Attribute Register 0, EL1
// RNDR field at bits [63:60]: 0=not implemented, 1=RNDR, 2=RNDR+RNDRRS
#define ID_AA64ISAR0_EL1_RNDR_SHIFT   60
#define ID_AA64ISAR0_EL1_RNDR         (0xfULL << 60)   // mask bits [63:60]
#define ID_AA64ISAR0_EL1_RNDR_FIELD(x) ((x) << 60)
// TLB field at bits [59:56]: 0=none, 1=TLB range, 2=outer+inner range
#define ID_AA64ISAR0_EL1_TLB_SHIFT    56
#define ID_AA64ISAR0_EL1_TLB          (0xfULL << 56)
// TS field at bits [55:52]: flagm
#define ID_AA64ISAR0_EL1_TS_SHIFT     52
#define ID_AA64ISAR0_EL1_TS           (0xfULL << 52)
// Atomic field at bits [23:20]: LSE atomics
#define ID_AA64ISAR0_EL1_ATOMIC_SHIFT 20
#define ID_AA64ISAR0_EL1_ATOMIC       (0xf << 20)
// CRC32 field at bits [19:16]
#define ID_AA64ISAR0_EL1_CRC32_SHIFT  16
#define ID_AA64ISAR0_EL1_CRC32        (0xf << 16)
// SHA2 field at bits [15:12]
#define ID_AA64ISAR0_EL1_SHA2_SHIFT   12
#define ID_AA64ISAR0_EL1_SHA2         (0xf << 12)
// SHA1 field at bits [11:8]
#define ID_AA64ISAR0_EL1_SHA1_SHIFT   8
#define ID_AA64ISAR0_EL1_SHA1         (0xf << 8)
// AES field at bits [7:4]
#define ID_AA64ISAR0_EL1_AES_SHIFT    4
#define ID_AA64ISAR0_EL1_AES          (0xf << 4)

// ID_AA64ISAR1_EL1 — Instruction Set Attribute Register 1, EL1
// GPA/GPI/APA/API fields for PAUTH
#define ID_AA64ISAR1_EL1_GPI_SHIFT    28
#define ID_AA64ISAR1_EL1_GPI          (0xf << 28)
#define ID_AA64ISAR1_EL1_GPA_SHIFT    24
#define ID_AA64ISAR1_EL1_GPA          (0xf << 24)
#define ID_AA64ISAR1_EL1_LRCPC_SHIFT  20
#define ID_AA64ISAR1_EL1_LRCPC        (0xf << 20)
#define ID_AA64ISAR1_EL1_FCMA_SHIFT   16
#define ID_AA64ISAR1_EL1_FCMA         (0xf << 16)
#define ID_AA64ISAR1_EL1_JSCVT_SHIFT  12
#define ID_AA64ISAR1_EL1_JSCVT        (0xf << 12)
#define ID_AA64ISAR1_EL1_API_SHIFT    8
#define ID_AA64ISAR1_EL1_API          (0xf << 8)
#define ID_AA64ISAR1_EL1_APA_SHIFT    4
#define ID_AA64ISAR1_EL1_APA          (0xf << 4)
#define ID_AA64ISAR1_EL1_DPB_SHIFT    0
#define ID_AA64ISAR1_EL1_DPB          (0xf)

// ID_AA64PFR0_EL1 — Processor Feature Register 0, EL1
// EL3 field at bits [15:12]: 0=not impl, 1=AArch64 only, 2=AArch64+AArch32
#define ID_AA64PFR0_EL1_EL3_SHIFT     12
#define ID_AA64PFR0_EL1_EL3           (0xf << 12)
// EL2 field at bits [11:8]
#define ID_AA64PFR0_EL1_EL2_SHIFT     8
#define ID_AA64PFR0_EL1_EL2           (0xf << 8)
// SVE field at bits [35:32]
#define ID_AA64PFR0_EL1_SVE_SHIFT     32
#define ID_AA64PFR0_EL1_SVE           (0xfULL << 32)

// ID_AA64MMFR0_EL1 — Memory Model Feature Register 0, EL1
// PARange field at bits [3:0]: physical address range
#define ID_AA64MMFR0_EL1_PARANGE_SHIFT 0
#define ID_AA64MMFR0_EL1_PARANGE      (0xf)
// TGran4 field at bits [31:28]: 4KB page support
#define ID_AA64MMFR0_EL1_TGRAN4_SHIFT 28
#define ID_AA64MMFR0_EL1_TGRAN4       (0xf << 28)

// ID_AA64MMFR1_EL1 — Memory Model Feature Register 1, EL1
// PAN field at bits [23:20]
#define ID_AA64MMFR1_EL1_PAN_SHIFT    20
#define ID_AA64MMFR1_EL1_PAN          (0xf << 20)
// HCX field at bits [43:40]: HCRX_EL2 support (FEAT_HCX)
#define ID_AA64MMFR1_EL1_HCX_SHIFT   40
#define ID_AA64MMFR1_EL1_HCX         (0xfULL << 40)

// ID_AA64MMFR2_EL1 — Memory Model Feature Register 2, EL1
// E0PD field at bits [63:60]
#define ID_AA64MMFR2_EL1_E0PD_SHIFT   60
#define ID_AA64MMFR2_EL1_E0PD         (0xfULL << 60)

// ID_AA64MMFR3_EL1 — Memory Model Feature Register 3, EL1
// TCRX field at bits [3:0]: TCR extension (FEAT_TCR2)
#define ID_AA64MMFR3_EL1_TCRX_SHIFT  0
#define ID_AA64MMFR3_EL1_TCRX        (0xf)
// SCTLRX field at bits [7:4]: SCTLR extension (FEAT_SCTLR2)
#define ID_AA64MMFR3_EL1_SCTLRX_SHIFT 4
#define ID_AA64MMFR3_EL1_SCTLRX      (0xf << 4)
// D128 field at bits [35:32]: 128-bit translation table (FEAT_D128)
#define ID_AA64MMFR3_EL1_D128_SHIFT  32
#define ID_AA64MMFR3_EL1_D128        (0xfULL << 32)

// ID_AA64ISAR1_EL1 additions
// LS64 field at bits [63:60]: 64-byte load/store (FEAT_LS64)
#define ID_AA64ISAR1_EL1_LS64_SHIFT  60
#define ID_AA64ISAR1_EL1_LS64        (0xfULL << 60)

// ID_AA64ISAR2_EL1 — Instruction Set Attribute Register 2, EL1
// MOPS field at bits [19:16]: Memory Copy/Set instructions (FEAT_MOPS)
#define ID_AA64ISAR2_EL1_MOPS_SHIFT  16
#define ID_AA64ISAR2_EL1_MOPS        (0xf << 16)
// SYSREG_128 field at bits [35:32]: 128-bit system register access (FEAT_SYSREG128)
#define ID_AA64ISAR2_EL1_SYSREG_128_SHIFT 32
#define ID_AA64ISAR2_EL1_SYSREG_128  (0xfULL << 32)

// ID_AA64PFR0_EL1 additions
// GIC field at bits [27:24]: GIC system register extensions
#define ID_AA64PFR0_EL1_GIC_SHIFT    24
#define ID_AA64PFR0_EL1_GIC          (0xf << 24)

// ID_AA64PFR1_EL1 — Processor Feature Register 1, EL1
// THE field at bits [51:48]: Translation Hardening Extension (FEAT_THE)
#define ID_AA64PFR1_EL1_THE_SHIFT    48
#define ID_AA64PFR1_EL1_THE          (0xfULL << 48)

#endif  // ZIRCON_KERNEL_LIB_ARCH_ARM64_INCLUDE_LIB_ARCH_ARM64_FEATURE_ASM_H_

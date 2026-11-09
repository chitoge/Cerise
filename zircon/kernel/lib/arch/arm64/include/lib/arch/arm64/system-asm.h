// Copyright 2021 The Fuchsia Authors
//
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT
//
// Minimal system-asm.h: assembly constants for ARM64 system registers.
// Generated from gen-arm64-system-asm.cc via hwreg::AsmHeader; this is a
// checked-in minimal subset covering what the phys and kernel assembly files
// actually need.

#ifndef ZIRCON_KERNEL_LIB_ARCH_ARM64_INCLUDE_LIB_ARCH_ARM64_SYSTEM_ASM_H_
#define ZIRCON_KERNEL_LIB_ARCH_ARM64_INCLUDE_LIB_ARCH_ARM64_SYSTEM_ASM_H_

// CTR_EL0 — Cache Type Register
#define CTR_EL0_IMINLINE (0xf)          // bits [3:0]: I-cache minimum line size
#define CTR_EL0_IMINLINE_SHIFT 0
#define CTR_EL0_IMINLINE_FIELD(x)    ((x) << CTR_EL0_IMINLINE_SHIFT)
#define CTR_EL0_DMINLINE (0xf << 16)    // bits [19:16]: D-cache minimum line size
#define CTR_EL0_DMINLINE_SHIFT 16
#define CTR_EL0_DMINLINE_FIELD(x)    ((x) << CTR_EL0_DMINLINE_SHIFT)
// Names expected by lib/arch/cache.h macros (cache_range_op)
#define CTR_EL0_IMIN_LINE_SHIFT  0   // bit offset of IminLine field
#define CTR_EL0_IMIN_LINE_WIDTH  4   // width of IminLine field (bits [3:0])
#define CTR_EL0_DMIN_LINE_SHIFT  16  // bit offset of DminLine field
#define CTR_EL0_DMIN_LINE_WIDTH  4   // width of DminLine field (bits [19:16])

// CurrentEL — Current Exception Level
// bits [3:2] = EL field
#define CURRENT_EL_EL         0xc       // mask for bits [3:2]
#define CURRENT_EL_EL_SHIFT   2
#define CURRENT_EL_EL_FIELD(x)  ((x) << CURRENT_EL_EL_SHIFT)

// DAIF — Interrupt Mask Bits (from ArmDaif: D=bit9, A=bit8, I=bit7, F=bit6)
#define DAIF_D  (1 << 9)
#define DAIF_A  (1 << 8)
#define DAIF_I  (1 << 7)
#define DAIF_F  (1 << 6)
#define DAIF_MASK  (DAIF_D | DAIF_A | DAIF_I | DAIF_F)

// DAIFSetClr — immediate operand for MSR DAIFSet/DAIFClr (bits [3:0])
#define DAIFSETCLR_D  (1 << 3)
#define DAIFSETCLR_A  (1 << 2)
#define DAIFSETCLR_I  (1 << 1)
#define DAIFSETCLR_F  (1 << 0)
#define DAIFSETCLR_MASK  (DAIFSETCLR_D | DAIFSETCLR_A | DAIFSETCLR_I | DAIFSETCLR_F)

// ESR_EL1 — Exception Syndrome Register (EL1)
// Exception Class field at bits [31:26]
#define ESR_EL1_EC_SHIFT  26
#define ESR_EL1_EC_WIDTH  6                             // EC field is bits [31:26]
#define ESR_EL1_EC        (0x3f << ESR_EL1_EC_SHIFT)   // mask for bits [31:26]
#define ESR_EL1_EC_FIELD(x)  ((x) << ESR_EL1_EC_SHIFT)
#define ESR_EL1_IL        (1 << 25)    // Instruction Length bit
#define ESR_EL1_ISS       (0x1ffffff)  // bits [24:0]: Instruction Specific Syndrome
// Exception class encodings
#define ESR_EC_SVC32      0x11
#define ESR_EC_SVC64      0x15
#define ESR_EC_DATA_ABORT_LOWER  0x24
#define ESR_EC_DATA_ABORT        0x25
#define ESR_EC_INST_ABORT_LOWER  0x20
#define ESR_EC_INST_ABORT        0x21

// SCTLR_EL1 — System Control Register (EL1)
#define SCTLR_EL1_M    (1 << 0)   // MMU enable
#define SCTLR_EL1_A    (1 << 1)   // Alignment check enable
#define SCTLR_EL1_C    (1 << 2)   // Data/unified cache enable
#define SCTLR_EL1_SA   (1 << 3)   // SP alignment check (EL1)
#define SCTLR_EL1_SA0  (1 << 4)   // SP alignment check (EL0)
#define SCTLR_EL1_I    (1 << 12)  // Instruction cache enable
#define SCTLR_EL1_UCT  (1 << 15)  // EL0 access to CTR_EL0
#define SCTLR_EL1_nTWI (1 << 16)  // Don't trap WFI from EL0
#define SCTLR_EL1_nTWE (1 << 18)  // Don't trap WFE from EL0
#define SCTLR_EL1_WXN  (1 << 19)  // Write-Execute never
#define SCTLR_EL1_SPAN (1 << 23)  // PAN bit not set on exception

// SCTLR_EL2 — System Control Register (EL2) — same bit positions as EL1 for M/A/C/I
#define SCTLR_EL2_M    (1 << 0)   // MMU enable
#define SCTLR_EL2_A    (1 << 1)   // Alignment check enable
#define SCTLR_EL2_C    (1 << 2)   // Data/unified cache enable
#define SCTLR_EL2_SA   (1 << 3)   // SP alignment check (EL2)
#define SCTLR_EL2_I    (1 << 12)  // Instruction cache enable
#define SCTLR_EL2_nTWI (1 << 16)  // Don't trap WFI from EL1
#define SCTLR_EL2_nTWE (1 << 18)  // Don't trap WFE from EL1
#define SCTLR_EL2_WXN  (1 << 19)  // Write-Execute never

// HCR_EL2 — Hypervisor Configuration Register
#define HCR_EL2_VM    (1 << 0)   // Virtualization enable
#define HCR_EL2_RW    (1 << 31)  // EL1 is AArch64
#define HCR_EL2_HCD   (1 << 29)  // HVC disable

// CPTR_EL2 — Architectural Feature Trap Register (EL2)
#define CPTR_EL2_TZ   (1 << 8)   // Trap SVE
#define CPTR_EL2_TFP  (1 << 10)  // Trap FP/SIMD
// RES1 bits (must be 1): bits [13:12], [9:8] in the no-E2H form
#define CPTR_EL2_UNKNOWN  ((1 << 9) | (1 << 8) | (1 << 13) | (1 << 12))
#define CPTR_EL2_RES1  CPTR_EL2_UNKNOWN

// CNTHCTL_EL2 — Counter-timer Hypervisor Control Register
#define CNTHCTL_EL2_EL1PCTEN  (1 << 0)  // Don't trap EL0 access to CNTPCT_EL0
#define CNTHCTL_EL2_EL1PCEN   (1 << 1)  // Don't trap EL0 access to CNTP_*

// ICC_SRE_EL2 — GIC System Register Enable Register (EL2)
#define ICC_SRE_EL2_SRE    (1 << 0)
#define ICC_SRE_EL2_EN     (1 << 3)
#define ICC_SRE_EL2_ENABLE (1 << 3)   // alias for ICC_SRE_EL2_EN (used by drop-el.S)

// HCRX_EL2 — Hypervisor Configuration Register Extension (FEAT_HCX, ARMv8.7+)
#define HCRX_EL2_ENAS0    (1 << 0)   // FEAT_LS64: enable ST64B* from EL0
#define HCRX_EL2_ENALS    (1 << 1)   // FEAT_LS64: enable LD64B* instructions
#define HCRX_EL2_ENASR    (1 << 2)   // FEAT_LS64: enable STEOSR instruction
#define HCRX_EL2_D128EN   (1 << 5)   // FEAT_D128: enable 128-bit page tables
#define HCRX_EL2_PTTWI   (1 << 6)   // FEAT_THE: translation page table walk interrupt
#define HCRX_EL2_MSCEN   (1 << 7)   // FEAT_MOPS: enable memory copy/set instructions
#define HCRX_EL2_ENIDCP128 (1 << 13) // FEAT_SYSREG128: enable 128-bit sysreg instructions
#define HCRX_EL2_TCR2EN  (1 << 14)  // FEAT_TCR2: enable TCR2_ELx registers
#define HCRX_EL2_SCTLR2EN (1 << 15) // FEAT_SCTLR2: enable SCTLR2_ELx registers

// SPSR_EL2 — Saved Program Status Register (EL2)
#define SPSR_EL2_M_SHIFT  0
#define SPSR_EL2_M        0x1f   // bits [4:0]
#define SPSR_EL2_M_FIELD(x)  ((x) << SPSR_EL2_M_SHIFT)
#define SPSR_EL2_F        (1 << 6)
#define SPSR_EL2_I        (1 << 7)
#define SPSR_EL2_A        (1 << 8)
#define SPSR_EL2_D        (1 << 9)
#define SPSR_EL2_DAIF     (SPSR_EL2_D | SPSR_EL2_A | SPSR_EL2_I | SPSR_EL2_F)
#define SPSR_EL2_M_EL1H  SPSR_EL2_M_FIELD(0b00101)  // EL1h = EL1 with SP_EL1

#endif  // ZIRCON_KERNEL_LIB_ARCH_ARM64_INCLUDE_LIB_ARCH_ARM64_SYSTEM_ASM_H_

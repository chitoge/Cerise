/******************************************************************************
  SPDX-License-Identifier: BSD-3-Clause

  Copyright (c) 2001-2015, Intel Corporation
  All rights reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions are met:

   1. Redistributions of source code must retain the above copyright notice,
      this list of conditions and the following disclaimer.

   2. Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in the
      documentation and/or other materials provided with the distribution.

   3. Neither the name of the Intel Corporation nor the names of its
      contributors may be used to endorse or promote products derived from
      this software without specific prior written permission.

  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
  POSSIBILITY OF SUCH DAMAGE.

******************************************************************************/

/*
 * Cerise DFv2 port of the FreeBSD/Intel e1000 shared-code OS-dependent layer.
 *
 * Provenance: the ORIGINAL of this file bridged the shared code to Fuchsia's
 * DFv1 DDK (ddk/protocol/pci banjo, ddk/mmio-buffer). This rewrite retargets
 * the SAME register/PCI abstraction at a DFv2 driver: register access goes
 * through a plain memory-mapped base pointer (`membase`, set by the driver to
 * its fdf::MmioBuffer virtual base), and PCI config space goes through a small
 * set of C-callable shims (e1000_osdep_pci_*) that the C++ driver implements
 * against the fuchsia.hardware.pci FIDL client. No DDK headers are pulled in.
 *
 * The E1000_* register macros below are UNCHANGED from the upstream osdep so
 * the shared code (e1000_mac.c, e1000_phy.c, e1000_ich8lan.c, ...) compiles and
 * behaves identically. See README.fuchsia for the full provenance chain.
 */

#ifndef _FUCHSIA_OS_H_
#define _FUCHSIA_OS_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

/* --- Shared-code integer types (match upstream osdep) --------------------- */
typedef uint64_t u64;
typedef uint32_t u32;
typedef uint16_t u16;
typedef uint8_t u8;
typedef int64_t s64;
typedef int32_t s32;
typedef int16_t s16;
typedef int8_t s8;

#define __le16 u16
#define __le32 u32
#define __le64 u64

#ifndef FALSE
#define FALSE 0
#endif
#ifndef TRUE
#define TRUE 1
#endif

#define STATIC static

/* PCI command register "memory write & invalidate enable" bit (BIT_4). The
 * upstream osdep defined this; the shared code (e1000_82542.c) references it. */
#ifndef CMD_MEM_WRT_INVALIDATE
#define CMD_MEM_WRT_INVALIDATE 0x0010
#endif

/* --- Timing --------------------------------------------------------------- */
/*
 * The shared code busy-waits in microsecond/millisecond units. These are
 * provided by the C++ driver so this header stays free of syscall headers.
 */
void e1000_osdep_delay_usec(uint32_t usec);
#define usec_delay(x) e1000_osdep_delay_usec(x)
#define usec_delay_irq(x) e1000_osdep_delay_usec(x)
#define msec_delay(x) e1000_osdep_delay_usec((x) * 1000u)
#define msec_delay_irq(x) e1000_osdep_delay_usec((x) * 1000u)

/* --- Debug ---------------------------------------------------------------- */
/*
 * The shared code emits verbose trace via DEBUGOUT/DEBUGFUNC. Compiled out:
 * the shared code is battle-tested and its trace is not part of the Cerise
 * gate. Keeping these as no-ops avoids pulling a varargs/printf dependency
 * into a -nodefaultlibs driver .so.
 */
#define DEBUGOUT(...) \
  do {                \
  } while (0)
#define DEBUGOUT1(...) DEBUGOUT(__VA_ARGS__)
#define DEBUGOUT2(...) DEBUGOUT(__VA_ARGS__)
#define DEBUGOUT3(...) DEBUGOUT(__VA_ARGS__)
#define DEBUGOUT7(...) DEBUGOUT(__VA_ARGS__)
#define DEBUGFUNC(F) \
  do {               \
  } while (0)

#define ASSERT(x) \
  do {            \
  } while (0)
#define ASSERT_CTX_LOCK_HELD(hw)
#define ASSERT_NO_LOCKS()

/* --- PCI config-space shims (implemented by the C++ driver) --------------- */
struct e1000_hw;
/* Read/write 16 bits of PCI config space at byte offset `reg`. */
void e1000_osdep_pci_read16(void* pci_ctx, uint32_t reg, uint16_t* value);
void e1000_osdep_pci_write16(void* pci_ctx, uint32_t reg, uint16_t value);
/*
 * Find the byte offset of the first PCI capability of type `cap_id`.
 * Returns 0 on success and writes the offset to *offset; non-zero on failure.
 */
int e1000_osdep_pci_find_cap(void* pci_ctx, uint8_t cap_id, uint8_t* offset);

/* Mirrors the upstream layout: the shared code reaches registers/PCI through
 * hw->back, which points at this struct. */
struct e1000_osdep {
  void* pci_ctx;     /* opaque handle for the PCI config shims */
  uintptr_t membase; /* virtual base of BAR0 MMIO (register space) */
  uintptr_t iobase;  /* unused in DFv2 (see E1000_WRITE_REG_IO below) */
};

#define hw2osdep(hw) ((struct e1000_osdep*)(hw)->back)
#define hw2pcictx(hw) (hw2osdep(hw)->pci_ctx)
#define hw2membase(hw) (hw2osdep(hw)->membase)
#define hw2iobase(hw) (hw2osdep(hw)->iobase)

/* --- MMIO primitives ------------------------------------------------------ */
static inline void e1000_writeb(u8 v, uintptr_t a) {
  *(volatile u8*)a = v;
}
static inline void e1000_writew(u16 v, uintptr_t a) {
  *(volatile u16*)a = v;
}
static inline void e1000_writel(u32 v, uintptr_t a) {
  *(volatile u32*)a = v;
}
static inline void e1000_writell(u64 v, uintptr_t a) {
  *(volatile u64*)a = v;
}
static inline u8 e1000_readb(uintptr_t a) {
  return *(volatile u8*)a;
}
static inline u16 e1000_readw(uintptr_t a) {
  return *(volatile u16*)a;
}
static inline u32 e1000_readl(uintptr_t a) {
  return *(volatile u32*)a;
}
static inline u64 e1000_readll(uintptr_t a) {
  return *(volatile u64*)a;
}

/* --- Register access macros (UNCHANGED from upstream osdep) ---------------- */
#define E1000_REGISTER(hw, reg)                   \
  (((hw)->mac.type >= e1000_82543) ? (u32)(reg) \
                                   : e1000_translate_register_82542(reg))

#define E1000_WRITE_FLUSH(a) E1000_READ_REG(a, E1000_STATUS)

/* Read/write at an absolute offset in the adapter's MMIO space. */
#define E1000_READ_OFFSET(hw, offset) e1000_readl(hw2membase(hw) + (offset))
#define E1000_WRITE_OFFSET(hw, offset, value) \
  e1000_writel((value), hw2membase(hw) + (offset))

#define E1000_READ_REG(hw, reg) E1000_READ_OFFSET((hw), E1000_REGISTER((hw), (reg)))
#define E1000_WRITE_REG(hw, reg, value) \
  E1000_WRITE_OFFSET((hw), E1000_REGISTER((hw), (reg)), (value))

#define E1000_READ_REG_ARRAY(hw, reg, index) \
  E1000_READ_OFFSET((hw), E1000_REGISTER((hw), (reg)) + ((index) << 2))
#define E1000_WRITE_REG_ARRAY(hw, reg, index, value) \
  E1000_WRITE_OFFSET((hw), E1000_REGISTER((hw), (reg)) + ((index) << 2), (value))

#define E1000_READ_REG_ARRAY_DWORD E1000_READ_REG_ARRAY
#define E1000_WRITE_REG_ARRAY_DWORD E1000_WRITE_REG_ARRAY

#define E1000_READ_REG_ARRAY_BYTE(hw, reg, index) \
  e1000_readb(hw2membase(hw) + E1000_REGISTER((hw), (reg)) + (index))
#define E1000_WRITE_REG_ARRAY_BYTE(hw, reg, index, value) \
  e1000_writeb((value), hw2membase(hw) + E1000_REGISTER((hw), (reg)) + (index))
#define E1000_WRITE_REG_ARRAY_WORD(hw, reg, index, value) \
  e1000_writew((value), hw2membase(hw) + E1000_REGISTER((hw), (reg)) + ((index) << 1))

/*
 * Upstream routed E1000_WRITE_REG_IO through the IO-mapped BAR to work around a
 * real-silicon (82540/82544) erratum where an MMIO CTRL.RST is unreliable. In
 * Cerise this path is only reachable for QEMU's emulated 82540EM, where MMIO
 * reset is reliable and no separate IO BAR / ioport resource is wired. Route it
 * to MMIO. Our real-hardware targets (82574L/I219/I211) never take this path.
 */
#define E1000_WRITE_REG_IO(hw, reg, value) E1000_WRITE_REG((hw), (reg), (value))

/* --- Flash register access (ICH8/PCH parts, e.g. I219) --------------------
 *
 * These MUST go through hw->flash_address, exactly like Linux's e1000e
 * (__er32flash/__ew32flash), and NOT through a base cached in e1000_osdep.
 * That is not a style choice — on I219 the shared code sets the base ITSELF,
 * after the driver has already filled in the osdep struct:
 *
 *   e1000_init_nvm_params_ich8lan() (e1000_ich8lan.c), for mac.type >=
 *   e1000_pch_spt: "in SPT the GbE Flash region is no longer accessed through
 *   the flash registers ... the Flash region access registers are now
 *   implemented in GbE memory space", and it assigns
 *       hw->flash_address = hw->hw_addr + E1000_FLASH_BASE_ADDR;   (BAR0+0xE000)
 *
 * So an osdep-cached base is stale by construction for every SPT-or-later part
 * (I219-LM 0x156f included). It was 0, which made each of the ~30 flash
 * accesses in e1000_ich8lan.c a load/store through a near-null pointer, which
 * is a fatal page fault in the driver host process, not an error return.
 * MEASURED on a Panasonic CF-SZ5 (I219-LM at 00:1f.6): driver_host.cm died with
 * return_code=-1028 (ZX_TASK_RETCODE_EXCEPTION_KILL) immediately after
 * driver_manager bound e1000 to node 00_1f_6, and the node was quarantined.
 *
 * QEMU cannot reproduce it: the emulated 82574L is mac.type e1000_82574, whose
 * NVM is EERD-based, so it never enters e1000_ich8lan.c at all and never
 * touches a flash register.
 *
 * For PRE-SPT ICH8/PCH parts the flash regs live in a separate BAR1 that this
 * driver does not map, so hw->flash_address stays NULL for them — and that is
 * handled, not faulted: the same init function bails with
 * "ERROR: Flash registers not mapped" / -E1000_ERR_CONFIG before any flash
 * access happens. Wiring BAR1 is what those parts would additionally need.
 */
#define E1000_READ_FLASH_REG(hw, reg) e1000_readl((uintptr_t)(hw)->flash_address + (reg))
#define E1000_READ_FLASH_REG16(hw, reg) e1000_readw((uintptr_t)(hw)->flash_address + (reg))
#define E1000_WRITE_FLASH_REG(hw, reg, value) \
  e1000_writel((value), (uintptr_t)(hw)->flash_address + (reg))
#define E1000_WRITE_FLASH_REG16(hw, reg, value) \
  e1000_writew((value), (uintptr_t)(hw)->flash_address + (reg))

#ifdef __cplusplus
}
#endif

#endif /* _FUCHSIA_OS_H_ */

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
 * Cerise DFv2 port. These OS-specific routines are provided to the shared code
 * with the same names/signatures as upstream, but implemented against the
 * e1000_osdep_pci_* C shims (see e1000_osdep.h) instead of the DFv1 banjo PCI
 * protocol.
 */

#include "e1000_api.h"

/* PCI config-space command register offset and the "memory write & invalidate
 * enable" bit (BIT_4), matching upstream's CMD_MEM_WRT_INVALIDATE. */
#define E1000_PCI_CONFIG_COMMAND 0x04
#define E1000_PCI_CMD_MEM_WRT_INVALIDATE 0x0010
/* PCI Express capability id. */
#define E1000_PCI_CAP_ID_PCI_EXPRESS 0x10

void e1000_write_pci_cfg(struct e1000_hw* hw, u32 reg, u16* value) {
  e1000_osdep_pci_write16(hw2pcictx(hw), reg, *value);
}

void e1000_read_pci_cfg(struct e1000_hw* hw, u32 reg, u16* value) {
  e1000_osdep_pci_read16(hw2pcictx(hw), reg, value);
}

void e1000_pci_set_mwi(struct e1000_hw* hw) {
  e1000_osdep_pci_write16(hw2pcictx(hw), E1000_PCI_CONFIG_COMMAND,
                          (u16)(hw->bus.pci_cmd_word | E1000_PCI_CMD_MEM_WRT_INVALIDATE));
}

void e1000_pci_clear_mwi(struct e1000_hw* hw) {
  e1000_osdep_pci_write16(hw2pcictx(hw), E1000_PCI_CONFIG_COMMAND,
                          (u16)(hw->bus.pci_cmd_word & ~E1000_PCI_CMD_MEM_WRT_INVALIDATE));
}

s32 e1000_read_pcie_cap_reg(struct e1000_hw* hw, u32 reg, u16* value) {
  u8 offset;
  if (e1000_osdep_pci_find_cap(hw2pcictx(hw), E1000_PCI_CAP_ID_PCI_EXPRESS, &offset) != 0) {
    return E1000_ERR_CONFIG;
  }
  e1000_osdep_pci_read16(hw2pcictx(hw), (u32)offset + reg, value);
  return E1000_SUCCESS;
}

s32 e1000_write_pcie_cap_reg(struct e1000_hw* hw, u32 reg, u16* value) {
  u8 offset;
  if (e1000_osdep_pci_find_cap(hw2pcictx(hw), E1000_PCI_CAP_ID_PCI_EXPRESS, &offset) != 0) {
    return E1000_ERR_CONFIG;
  }
  e1000_osdep_pci_write16(hw2pcictx(hw), (u32)offset + reg, *value);
  return E1000_SUCCESS;
}

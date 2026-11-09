// Copyright 2023 The Fuchsia Authors
//
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT

#include <lib/root_resource_filter.h>
#include <lib/uart/uart.h>
#include <lib/zbi-format/driver-config.h>
#include <zircon/syscalls/resource.h>

#include <cstdint>

#include <arch/x86/apic.h>
#include <ktl/optional.h>
#include <platform/uart.h>
#include <vm/physmap.h>

ktl::optional<uint32_t> PlatformUartGetIrqNumber(uint32_t irq_num) {
  if (irq_num == 0) {
    return ktl::nullopt;
  }
  // Only legacy ISA IRQs (0-15) go through the ACPI MADT interrupt-source
  // override table; apic_io_isa_to_global ASSERTs that its argument is one, so
  // handing it anything larger is a hard kernel panic before the console is
  // even usable:
  //
  //   ASSERT FAILED at (zircon/kernel/arch/x86/ioapic.cc:406):
  //       isa_irq < NUM_ISA_IRQS
  //
  // That is reachable from board data, not just from a programming bug: a UART
  // that is a PCI function rather than a southbridge COM port has a global
  // system interrupt (GSI), which is routinely >= 16. The concrete case is the
  // Intel AMT Serial-over-LAN 16550 (PCI 00:16.3) on //boards/cf-sz5, whose
  // firmware assigns GSI 19. A GSI is ALREADY global — remapping it would be
  // wrong even if the table were large enough — so pass it through untranslated.
  //
  // NOTE: this only stops the panic and yields the correct global IRQ number.
  // Whether a given PCI-function UART's interrupt is then usable also depends on
  // trigger mode/polarity, which this path leaves at the IOAPIC defaults; boards
  // that have not verified interrupt delivery on real silicon should configure
  // the UART with irq=0, which selects the kernel's supported polling mode.
  if (irq_num >= NUM_ISA_IRQS) {
    return irq_num;
  }
  return apic_io_isa_to_global(static_cast<uint8_t>(irq_num));
}

// Copyright 2021 The Fuchsia Authors
//
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT

#include <stdio.h>

#include <phys/stdio.h>
#include <phys/uart-console.h>

#if defined(__x86_64__) || defined(__i386__)
#include <hwreg/pio.h>

#include <ktl/optional.h>
#endif

#include <ktl/enforce.h>

#if defined(__x86_64__) || defined(__i386__)

// Waking up a port-mapped 16550 that firmware left behind a disabled PCI
// window.
//
// A PC-compatible 16550 at a fixed legacy I/O port (0x3f8 and friends) is
// always decoded: it hangs off the LPC/ISA bridge and there is no per-device
// enable to get wrong.  A 16550 that lives in a PCI function is different --
// it only answers on its I/O ports while the I/O-space-enable bit of its PCI
// COMMAND register is set, and firmware is under no obligation to leave that
// bit set for an OS that has not yet enumerated PCI.
//
// This is not hypothetical.  On the Panasonic CF-SZ5 (//boards/cf-sz5) the
// console is the Intel AMT Serial-over-LAN 16550 at PCI 00:16.3.  Firmware
// programs its BAR0 (I/O 0xf0a0-0xf0a7) and leaves it in D0, but hands the OS
// COMMAND = 0x0000, so the window is dead.  Measured on the machine:
//
//     base=0xf0a0 IER=ff IIR=ff LCR=ff MCR=ff LSR=ff MSR=ff SCR=ff
//     pci 00:16.3 id=9d3d8086 cmd=0000 bar0=0000f0a1 pmcap=50 pmcsr=0008
//
// That failure mode is completely silent, and worse than silent: an
// unclaimed x86 I/O port reads as all-ones, so LSR bit 5 (transmitter empty)
// appears set forever, TxReady() returns true immediately, and every byte is
// handed to a port that nobody answers with no error reported anywhere.  The
// machine boots perfectly and says nothing.
//
// Linux looks like it prints from timestamp zero on such a machine only
// because printk replays its ring buffer when the console registers, which
// happens after the PCI core has enabled the device.  Nothing was on the wire
// before that either.
//
// So: if the configured PIO UART reads back as an empty bus, go find the PCI
// function whose I/O BAR is that port and turn its decode on.  Legacy
// 0xcf8/0xcfc configuration access is enough -- everything touched here lives
// in the first 256 bytes of configuration space -- and it needs no ACPI, no
// MMIO mapping and no allocator, all of which matters this early.
//
// The gates on this are deliberately narrow, so that it does nothing at all
// on a healthy board:
//
//   * x86 only, and only for a port-mapped driver.  MMIO UARTs are not PCI
//     functions on any board in tree and have no COMMAND register to fix.
//   * Only when every 16550 register reads 0xff.  A working UART -- QEMU's
//     isa-serial included -- never does: LCR alone will be a plausible line
//     configuration.  QEMU also has no PCI function behind isa-serial, so
//     even a forced scan would find nothing.
//   * Only functions whose I/O decode is already off are examined at all, and
//     nothing is written unless one of them owns the port in question.  On a
//     board where firmware did its job the scan is read-only and finds no
//     candidate.

namespace {

// Legacy PCI configuration access ports.
constexpr uint16_t kConfigAddressPort = 0xcf8;
constexpr uint16_t kConfigDataPort = 0xcfc;

// Type 0 configuration header offsets, as dword-aligned byte offsets.
constexpr uint8_t kVendorDeviceOffset = 0x00;
constexpr uint8_t kCommandStatusOffset = 0x04;
constexpr uint8_t kHeaderTypeOffset = 0x0c;  // Header type is byte 2 here.
constexpr uint8_t kBar0Offset = 0x10;
constexpr uint8_t kCapabilitiesPtrOffset = 0x34;

constexpr uint32_t kCommandIoSpaceEnable = 1u << 0;
// STATUS is the upper half of the COMMAND dword; its bits are write-1-to-clear,
// so writes to that dword must put zeroes there.
constexpr uint32_t kStatusCapabilityList = 1u << (4 + 16);
constexpr uint32_t kCommandMask = 0xffff;

constexpr uint8_t kCapIdPowerManagement = 0x01;
constexpr uint32_t kPmcsrPowerStateMask = 0x3;
// PME_Status (bit 15) is write-1-to-clear, and the upper half of the PMCSR
// dword is read-only, so preserve only the writable low bits.
constexpr uint32_t kPmcsrWritebackMask = 0x7ffc;

// The number of registers in a 16550 register file.
constexpr uint32_t kUartRegisterCount = 8;

struct PciAddress {
  uint8_t bus, dev, func;
};

uint32_t ConfigAddress(const PciAddress& addr, uint8_t offset) {
  return 0x8000'0000u | (uint32_t{addr.bus} << 16) | (uint32_t{addr.dev} << 11) |
         (uint32_t{addr.func} << 8) | (offset & 0xfcu);
}

uint32_t ConfigRead32(const PciAddress& addr, uint8_t offset) {
  hwreg::RegisterDirectPio pio;
  pio.Write<uint32_t>(ConfigAddress(addr, offset), kConfigAddressPort);
  return pio.Read<uint32_t>(kConfigDataPort);
}

void ConfigWrite32(const PciAddress& addr, uint8_t offset, uint32_t value) {
  hwreg::RegisterDirectPio pio;
  pio.Write<uint32_t>(ConfigAddress(addr, offset), kConfigAddressPort);
  pio.Write<uint32_t>(value, kConfigDataPort);
}

// Put the function into D0 if its Power Management capability says it is
// anywhere else.  A device in D3hot answers configuration cycles but not its
// BARs, which presents exactly the same all-ones symptom as a disabled window.
void ForceD0(const PciAddress& addr) {
  if ((ConfigRead32(addr, kCommandStatusOffset) & kStatusCapabilityList) == 0) {
    return;
  }
  uint8_t cap = static_cast<uint8_t>(ConfigRead32(addr, kCapabilitiesPtrOffset) & 0xfcu);
  // Bound the walk: a corrupt or cyclic list must not hang the boot.
  for (unsigned int hops = 0; cap >= 0x40 && hops < 48; ++hops) {
    const uint32_t header = ConfigRead32(addr, cap);
    if ((header & 0xffu) == kCapIdPowerManagement) {
      const uint8_t pmcsr_offset = static_cast<uint8_t>(cap + 4);
      const uint32_t pmcsr = ConfigRead32(addr, pmcsr_offset);
      if ((pmcsr & kPmcsrPowerStateMask) != 0) {
        ConfigWrite32(addr, pmcsr_offset, pmcsr & kPmcsrWritebackMask & ~kPmcsrPowerStateMask);
        // The PCI PM spec allows 10ms to recover from D3hot.  There is no
        // timer here yet, so poll the register instead: a configuration cycle
        // costs roughly a microsecond on this class of hardware, which makes
        // this both the delay and the confirmation that it took.
        for (unsigned int i = 0; i < 20000; ++i) {
          if ((ConfigRead32(addr, pmcsr_offset) & kPmcsrPowerStateMask) == 0) {
            break;
          }
        }
      }
      return;
    }
    cap = static_cast<uint8_t>((header >> 8) & 0xfcu);
  }
}

// Returns true if this function is a type 0 endpoint with I/O decode currently
// disabled and an I/O BAR based at `port`.
bool FunctionOwnsDisabledIoPort(const PciAddress& addr, uint16_t port) {
  if ((ConfigRead32(addr, kVendorDeviceOffset) & 0xffffu) == 0xffffu) {
    return false;
  }

  // Only a type 0 header has six BARs; bridges are not UARTs.
  if (((ConfigRead32(addr, kHeaderTypeOffset) >> 16) & 0x7fu) != 0) {
    return false;
  }

  // If the function is already decoding I/O space then its window is live and
  // whatever is wrong with the UART is not this.  Skipping it also keeps the
  // scan read-only on a board where firmware enabled everything.
  if ((ConfigRead32(addr, kCommandStatusOffset) & kCommandIoSpaceEnable) != 0) {
    return false;
  }

  for (uint32_t bar = 0; bar < 6; ++bar) {
    const uint32_t value = ConfigRead32(addr, static_cast<uint8_t>(kBar0Offset + bar * 4));
    if ((value & 1u) == 0) {
      // A memory BAR, and a 64-bit one consumes the following slot as well.
      if ((value & 0x6u) == 0x4u) {
        ++bar;
      }
      continue;
    }
    // The BAR base must be exactly the configured port.  Accepting a UART at
    // some offset inside a larger window would mean sizing the BAR, which
    // means writing 0xffffffff into a stranger's BAR and putting it back, and
    // nothing in tree needs it: a PCI UART puts register 0 of its first port
    // at BAR offset 0.
    if ((value & ~0x3u) == port) {
      return true;
    }
  }
  return false;
}

// Brute-force the configuration space looking for the owner of `port`.  There
// is no bus topology to consult this early, but the search is bounded and each
// step is a pair of I/O accesses, so the whole sweep costs single-digit
// milliseconds in the worst case and stops at the first match.
ktl::optional<PciAddress> EnableIoDecodeForPort(uint16_t port) {
  for (uint32_t bus = 0; bus < 256; ++bus) {
    for (uint32_t dev = 0; dev < 32; ++dev) {
      const PciAddress func0 = {static_cast<uint8_t>(bus), static_cast<uint8_t>(dev), 0};
      if ((ConfigRead32(func0, kVendorDeviceOffset) & 0xffffu) == 0xffffu) {
        continue;
      }
      const bool multifunction = (ConfigRead32(func0, kHeaderTypeOffset) & 0x0080'0000u) != 0;
      const uint32_t functions = multifunction ? 8 : 1;
      for (uint32_t func = 0; func < functions; ++func) {
        const PciAddress addr = {static_cast<uint8_t>(bus), static_cast<uint8_t>(dev),
                                 static_cast<uint8_t>(func)};
        if (!FunctionOwnsDisabledIoPort(addr, port)) {
          continue;
        }
        ForceD0(addr);
        const uint32_t command = ConfigRead32(addr, kCommandStatusOffset) & kCommandMask;
        ConfigWrite32(addr, kCommandStatusOffset, command | kCommandIoSpaceEnable);
        return addr;
      }
    }
  }
  return ktl::nullopt;
}

// If the configured port-mapped UART reads back as an unclaimed bus, try to
// find and enable the PCI function behind it.  Returns the function enabled,
// or nothing at all -- which is the expected outcome everywhere but the one
// board this exists for.
ktl::optional<PciAddress> MaybeEnableUartPciDecode(uint32_t base) {
  if (base == 0 || base > 0xffff) {
    return ktl::nullopt;
  }
  const hwreg::RegisterDirectPio uart(static_cast<uint16_t>(base));
  // Register 0 is deliberately not read: on a live UART that would consume a
  // received byte.  The other seven are enough, and no working 16550 reads
  // 0xff in all of them.
  for (uint32_t reg = 1; reg < kUartRegisterCount; ++reg) {
    if (uart.Read<uint8_t>(reg) != 0xff) {
      return ktl::nullopt;
    }
  }
  return EnableIoDecodeForPort(static_cast<uint16_t>(base));
}

// These two exist only to keep the driver-type-dependent expressions inside an
// `if constexpr`: an MMIO or stub configuration has no `base` at all.
template <typename KernelDriverType>
ktl::optional<PciAddress> MaybeEnableUartPciDecodeFor(KernelDriverType& driver) {
  if constexpr (uart::PioDriver<typename KernelDriverType::uart_type>) {
    return MaybeEnableUartPciDecode(driver.config().base);
  } else {
    return ktl::nullopt;
  }
}

template <typename KernelDriverType>
void ReportUartPciDecode(KernelDriverType& driver, const ktl::optional<PciAddress>& enabled) {
  if constexpr (uart::PioDriver<typename KernelDriverType::uart_type>) {
    if (enabled) {
      printf("phys: UART at I/O %#x was not decoded; enabled PCI %02x:%02x.%x I/O space\n",
             driver.config().base, enabled->bus, enabled->dev, enabled->func);
    }
  }
}

}  // namespace

#endif  // defined(__x86_64__) || defined(__i386__)

UartDriver& GetUartDriver() {
  // This is function-local so it can be non-constinit.
  static UartDriver uart;
  return uart;
}

void SetUartConsole(const uart::all::Config<>& uart_config) {
  GetUartDriver() = uart::all::MakeDriver(uart_config);
  GetUartDriver().Visit([](auto& driver) {
#if defined(__x86_64__) || defined(__i386__)
    // Must happen before Init(): programming a UART whose window is not
    // decoded accomplishes nothing, silently.
    const ktl::optional<PciAddress> enabled = MaybeEnableUartPciDecodeFor(driver);
#endif

    driver.Init();

    // Update stdout global to write to the configured driver.
    PhysConsole::Get().set_serial(FILE{&driver});

#if defined(__x86_64__) || defined(__i386__)
    // Reported after the console is wired up, so that it lands on the very
    // serial port it is talking about.
    ReportUartPciDecode(driver, enabled);
#endif
  });
}

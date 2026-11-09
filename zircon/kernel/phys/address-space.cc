// Copyright 2021 The Fuchsia Authors
//
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT

#include "phys/address-space.h"

#include <inttypes.h>
#include <lib/arch/paging.h>
#include <lib/memalloc/pool.h>
#include <lib/memalloc/range.h>
#include <lib/uart/uart.h>
#include <zircon/types.h>

#include <fbl/algorithm.h>
#include <ktl/algorithm.h>
#include <ktl/byte.h>
#include <ktl/optional.h>
#include <ktl/ref.h>
#include <ktl/type_traits.h>
#include <ktl/utility.h>
#include <phys/allocation.h>
#include <phys/framebuffer-console.h>
#include <phys/main.h>
#include <phys/stdio.h>
#include <phys/uart-console.h>

#include <ktl/enforce.h>

AddressSpace* gAddressSpace = nullptr;

void AddressSpace::AllocateRootPageTables() {
  // See allocator descriptions for the appropriate use-cases.
  auto lower_allocator = kDualSpaces ? temporary_allocator() : permanent_allocator();
  ktl::optional<uint64_t> lower_root =
      lower_allocator(LowerPaging::kTableSize, LowerPaging::kTableAlignment);
  ZX_ASSERT_MSG(lower_root, "failed to allocate %sroot page table", kDualSpaces ? "lower " : "");
  lower_root_paddr_ = *lower_root;

  if constexpr (kDualSpaces) {
    ktl::optional<uint64_t> upper_root =
        permanent_allocator()(UpperPaging::kTableSize, UpperPaging::kTableAlignment);
    ZX_ASSERT_MSG(upper_root, "failed to allocate upper root page table");
    upper_root_paddr_ = *upper_root;
  }
}

void AddressSpace::IdentityMapRam() {
  memalloc::Pool& pool = Allocation::GetPool();

  // To account for the case of non-page-aligned RAM, we extend the mapped
  // region to page-aligned boundaries, tracking the end of the last aligned
  // range in the process. There should not be cases where both RAM and MMIO
  // appear within the same page.
  ktl::optional<uint64_t> last_aligned_end;
  memalloc::NormalizeRam(pool, [&](const memalloc::Range& range) {
    // If the end of the last page-aligned range overlaps with the current,
    // take that to be the start of the current range.
    uint64_t addr, size;
    if (last_aligned_end && *last_aligned_end > range.addr) {
      if (*last_aligned_end >= range.end()) {
        return true;
      }
      addr = *last_aligned_end;
      size = range.end() - *last_aligned_end;
    } else {
      addr = range.addr & -uint64_t{kPageSize};
      size = (range.addr - addr) + range.size;
    }

    // Now page-align up the size.
    size = (size + kPageSize - 1) & ~(kPageSize - 1);

    auto result = IdentityMap(addr, size,
                              AddressSpace::NormalMapSettings({
                                  .readable = true,
                                  .writable = true,
                                  .executable = true,
                              }));
    if (result.is_error()) {
      ZX_PANIC("Failed to identity-map range [%#" PRIx64 ", %#" PRIx64
               ") (page-aligned from [%#" PRIx64 ", %#" PRIx64 "))",
               addr, addr + size, range.addr, range.end());
    }

    last_aligned_end = addr + size;
    return true;
  });
}

// Unlike the UART, a framebuffer that cannot be mapped is not fatal: it is a
// diagnostic channel, and a boot that would otherwise succeed must not be
// brought down by it.  The console is disabled instead, so later writes go
// nowhere rather than faulting on an address this address space cannot reach.
void AddressSpace::IdentityMapFramebuffer() {
  FramebufferConsole& console = GetFramebufferConsole();
  const ktl::optional fb_range = console.maybe_mmio_range();
  if (!fb_range) {
    return;
  }
  const auto [start, size] = fb_range->AlignedTo(kPageSize);
  if (IdentityMap(start, size, MmioMapSettings()).is_error()) {
    printf("%s: cannot map framebuffer [%#" PRIx64 ", %#" PRIx64
           "); framebuffer console disabled\n",
           ProgramName(), start, start + size);
    console.Disable();
    PhysConsole& phys_console = PhysConsole::Get();
    phys_console.set_graphics(*phys_console.null());
  }
}

void AddressSpace::IdentityMapUart() {
  if (const ktl::optional uart_range = GetUartDriver().maybe_mmio_range()) {
    const auto [start, size] = uart_range->AlignedTo(kPageSize);
    auto result = IdentityMap(start, size, MmioMapSettings());
    ZX_ASSERT_MSG(result.is_ok(), "Failed to map in UART range: [%#" PRIx64 ", %#" PRIx64 ")",
                  start, size);
  }
}

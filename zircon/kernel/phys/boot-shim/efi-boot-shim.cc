// Copyright 2023 The Fuchsia Authors
//
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT

#include <lib/boot-shim/efi-boot-shim.h>
#include <lib/zbitl/error-stdio.h>
#include <stdint.h>

#include <ktl/string_view.h>
#include <ktl/utility.h>
#include <phys/efi/efi-boot-zbi.h>
#include <phys/efi/file.h>
#include <phys/efi/main.h>
#include <phys/symbolize.h>

#include <ktl/enforce.h>

namespace {

constexpr ktl::string_view kDefaultZbiFilename = DEFAULT_ZBI_FILENAME;

using Shim = boot_shim::EfiBootShim<>;

// ---------------------------------------------------------------------------
// Cerise OS-self-OTA A/B slot metadata (a simplified ABR).
//
// The shim reads "\abr" from the ESP (UEFI Simple File System) before load and
// uses it to pick which of two slot ZBIs to boot.  When "\abr" is ABSENT the
// shim behaves exactly as before (single-slot: load DEFAULT_ZBI_FILENAME) so
// all existing single-slot products are unaffected.
//
// On-disk format: a fixed 16-byte little-endian record (no CRC — a torn or
// corrupt record simply fails the magic/version check and is treated as
// absent, i.e. safe single-slot fallback; anti-rollback/CRC is a documented
// future item):
//
//   off 0  magic[4]      = 'C','A','B','R'
//   off 4  version u8    = 1
//   off 5  active u8     slot last selected as active: 0 = A, 1 = B
//   off 6  tries[0] u8   remaining boot attempts for slot A
//   off 7  tries[1] u8   remaining boot attempts for slot B
//   off 8  successful[0] u8  slot A committed-good flag (0/1)
//   off 9  successful[1] u8  slot B committed-good flag (0/1)
//   off 10 reserved[6]   zero
//
// Slot select semantics (matches Fuchsia libabr in spirit):
//  * a slot is bootable if successful==1 OR tries>0.
//  * prefer the active slot if bootable; else fall back to the other slot.
//  * before booting a not-yet-successful slot, DECREMENT its tries and WRITE
//    "\abr" back.  This is what makes hang/panic-before-commit roll back: the
//    decrement persists across the reboot, so once tries hits 0 the slot stops
//    being bootable and the next boot falls back to the other slot.
//  * a load FAILURE (truncated/corrupt ZBI, detected before ExitBootServices)
//    is handled in-process: mark the other slot active, write "\abr", and try
//    it in the same shim invocation.
struct CeriseAbr {
  uint8_t magic[4];
  uint8_t version;
  uint8_t active;
  uint8_t tries[2];
  uint8_t successful[2];
  uint8_t reserved[6];
};
static_assert(sizeof(CeriseAbr) == 16);

constexpr uint8_t kAbrVersion = 1;
constexpr ktl::string_view kAbrFilename = "abr";
constexpr ktl::string_view kSlotZbi[2] = {"zircon_a.zbi", "zircon_b.zbi"};

bool AbrValid(const CeriseAbr& abr) {
  return abr.magic[0] == 'C' && abr.magic[1] == 'A' && abr.magic[2] == 'B' &&
         abr.magic[3] == 'R' && abr.version == kAbrVersion && abr.active < 2;
}

bool AbrBootable(const CeriseAbr& abr, uint8_t slot) {
  return abr.successful[slot] != 0 || abr.tries[slot] > 0;
}

// Reads "\abr".  Returns true and fills `abr` if a valid record is present.
bool ReadAbr(const char* shim_name, CeriseAbr& abr) {
  auto result = EfiOpenFile(kAbrFilename);
  if (result.is_error()) {
    return false;  // No \abr: single-slot mode.
  }
  EfiFilePtr file = ktl::move(result).value();
  size_t len = sizeof(abr);
  efi_status status = file->Read(file.get(), &len, &abr);
  if (status != EFI_SUCCESS || len != sizeof(abr) || !AbrValid(abr)) {
    printf("%s: CERISE-ABR-INVALID (status=%#zx len=%zu); single-slot fallback\n", shim_name,
           status, len);
    return false;
  }
  return true;
}

// Writes the 16-byte record back to "\abr" in place.
void WriteAbr(const char* shim_name, const CeriseAbr& abr) {
  auto result = EfiOpenFileReadWrite(kAbrFilename);
  if (result.is_error()) {
    printf("%s: CERISE-ABR-WRITE-FAIL open %#zx\n", shim_name, result.error_value());
    return;
  }
  EfiFilePtr file = ktl::move(result).value();
  file->SetPosition(file.get(), 0);
  size_t len = sizeof(abr);
  efi_status status = file->Write(file.get(), &len, &abr);
  file->Flush(file.get());
  if (status != EFI_SUCCESS || len != sizeof(abr)) {
    printf("%s: CERISE-ABR-WRITE-FAIL write %#zx len=%zu\n", shim_name, status, len);
  }
}

}  // namespace

int main(int argc, char** argv) {
  MainSymbolize symbolize(argc == 0 ? "efi-boot-shim" : argv[0]);

  Shim shim(symbolize.name());
  const char* shim_name = shim.shim_name();

  // Read the A/B slot record (if any) before touching the UEFI memory map.
  CeriseAbr abr{};
  const bool have_abr = ReadAbr(shim_name, abr);

  // Collect the standard UEFI-based items once (memory map, ACPI, GOP, ...).
  if (!shim.Check("Failed to collect UEFI data", shim.Init(gEfiSystemTable))) {
    return 1;
  }
  // EfiBootShim::Init's SFINAE dispatch passes optional<AcpiParser> but both
  // AcpiRsdpItem::Init and AcpiUartItem::Init take the unwrapped parser type,
  // so they are silently skipped.  Explicitly initialize them here.
  if (shim.acpi().has_value()) {
    shim.InitGetItem<boot_shim::AcpiRsdpItem>(*shim.acpi());
    shim.InitGetItem<boot_shim::AcpiUartItem>(*shim.acpi());
  }

  // Attempts to load+boot the ZBI at `filename`.  On success this never
  // returns (it ExitBootServices() and jumps into the kernel).  It returns
  // only on failure — either the file couldn't be opened, or the ZBI failed to
  // load (which is detected while UEFI Boot Services are still live, so we can
  // safely try another slot).
  auto boot_from_file = [&](ktl::string_view filename) {
    printf("%s: Loading ZBI from file \"%.*s\"...\n", shim_name,
           static_cast<int>(filename.size()), filename.data());
    EfiFilePtr file;
    if (auto result = EfiOpenFile(filename); result.is_ok()) {
      file = ktl::move(result).value();
    } else {
      shim.Check("Cannot open ZBI file", result);
      return;
    }
    EfiBootZbi boot(ktl::move(file));
    auto error =
        shim.LoadAndBoot(gEfiSystemTable->BootServices, gEfiImageHandle, boot.LoadFunction(),
                         boot.LastChanceFunction(), boot.BootFunction());
    printf("%s: Failed to load ZBI: ", shim_name);
    zbitl::PrintViewError(error);
    printf("\n");
    boot.DataZbi().ignore_error();
  };

  if (!have_abr) {
    // Single-slot legacy behavior: unchanged from before OTA support.
    ktl::string_view filename;
    if (argc <= 1) {
      filename = kDefaultZbiFilename;
    } else {
      filename = argv[1];
    }
    boot_from_file(filename);
    return 1;
  }

  // A/B path.  Decide the attempt order: prefer the active slot if it's
  // bootable, otherwise try the other slot first (rollback).
  const uint8_t original_active = abr.active;
  uint8_t order[2];
  if (AbrBootable(abr, abr.active)) {
    order[0] = abr.active;
    order[1] = static_cast<uint8_t>(abr.active ^ 1u);
  } else {
    order[0] = static_cast<uint8_t>(abr.active ^ 1u);
    order[1] = abr.active;
  }

  CeriseAbr on_disk = abr;
  for (uint8_t i = 0; i < 2; ++i) {
    const uint8_t slot = order[i];
    if (slot != original_active) {
      printf("%s: CERISE-ABR-FALLBACK from %c to %c\n", shim_name,
             static_cast<char>('A' + original_active), static_cast<char>('A' + slot));
    }
    // Make this slot active and, if it isn't yet committed-good, spend one try.
    abr.active = slot;
    if (abr.successful[slot] == 0 && abr.tries[slot] > 0) {
      abr.tries[slot]--;
    }
    if (__builtin_memcmp(&abr, &on_disk, sizeof(abr)) != 0) {
      WriteAbr(shim_name, abr);
      on_disk = abr;
    }
    printf("%s: CERISE-ABR-SLOT=%c tries=%u successful=%u\n", shim_name,
           static_cast<char>('A' + slot), abr.tries[slot], abr.successful[slot]);
    boot_from_file(kSlotZbi[slot]);  // Returns only if this slot failed to load.
  }

  printf("%s: CERISE-ABR-NO-BOOTABLE all slots failed to load\n", shim_name);
  return 1;
}

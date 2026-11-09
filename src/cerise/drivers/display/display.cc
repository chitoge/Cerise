// Cerise native DFv2 display driver — owns the QEMU stdvga (PCI 1234:1111) hardware and
// serves the minimal cerise.display FIDL protocol so that a console client can render
// text with ZERO hardware capability of its own.
//
// This REPLACES the least-privilege violation in status_console/src/fb.rs, which grabbed
// the ambient root fuchsia.kernel.{Mmio,Ioport}Resource (whole-address-space capabilities),
// poked PCI config over CF8/CFC, VBE-mode-set via BAR2 MMIO, and mapped BAR0 with
// zx_vmo_create_physical(). Here the driver sources its MMIO from the parent's
// fuchsia.hardware.pci.Service — the PCI bus hands it VMOs SCOPED to this device's BARs
// (GetBar), not the whole physical address space. That is the least-privilege win.
//
// Bring-up (the stdvga logic moved verbatim from fb.rs, only the MMIO source changed):
//   * GetBar(0) -> the linear framebuffer VMO (VRAM aperture). Kept and duplicated to
//     clients; its cache policy is forced UNCACHED_DEVICE so guest writes reach QEMU's
//     scanout with no flush (the old physical-VMO default).
//   * GetBar(2) -> the stdvga MMIO register window; mapped and used to program the Bochs
//     VBE DISPI registers at BAR2 offset 0x500 (reg N at 0x500 + N*2). The legacy VBE I/O
//     ports 0x1CE/0x1CF are NOT used (they faulted; see fb.rs history).
//
// DFv2 shape modeled on src/cerise/drivers/e1000 (DriverBase + FUCHSIA_DRIVER_EXPORT +
// GetBar via fuchsia.hardware.pci); the serve-a-service pattern (Service::InstanceHandler
// + outgoing()->AddService + .cml capabilities/expose) mirrors the upstream nvme driver
// (namespace.cc) exposing fuchsia.hardware.block.volume.Service from the boot-drivers
// collection.
#include <fidl/cerise.display/cpp/fidl.h>
#include <fidl/fuchsia.hardware.pci/cpp/fidl.h>
#include <lib/driver/component/cpp/driver_base.h>
#include <lib/driver/component/cpp/driver_export.h>
#include <lib/driver/logging/cpp/logger.h>
#include <lib/driver/mmio/cpp/mmio-buffer.h>
#include <lib/fidl/cpp/wire/server.h>
#include <zircon/syscalls.h>

namespace cerise_display_driver {

// The mode this driver programs. Matches status_console's WIDTH/HEIGHT so the client's
// fixed layout constants line up with the reported geometry.
constexpr uint32_t kWidth = 1024;
constexpr uint32_t kHeight = 768;
constexpr uint32_t kBytesPerPixel = 4;  // 32bpp X8R8G8B8.

// Bochs VBE DISPI registers, programmed through the stdvga BAR2 MMIO aperture (reg N at
// 0x500 + N*2). Copied from status_console/src/fb.rs.
constexpr zx_off_t kVbeMmioOffset = 0x500;
constexpr uint32_t kVbeIndexXres = 1;
constexpr uint32_t kVbeIndexYres = 2;
constexpr uint32_t kVbeIndexBpp = 3;
constexpr uint32_t kVbeIndexEnable = 4;
constexpr uint32_t kVbeIndexVirtWidth = 6;
constexpr uint16_t kVbeEnabled = 0x01;
constexpr uint16_t kVbeLfbEnabled = 0x40;

class DisplayDriver : public fdf::DriverBase, public fidl::Server<cerise_display::Framebuffer> {
 public:
  DisplayDriver(fdf::DriverStartArgs start_args,
                fdf::UnownedSynchronizedDispatcher driver_dispatcher)
      : fdf::DriverBase("display", std::move(start_args), std::move(driver_dispatcher)) {}

  zx::result<> Start() override {
    // Connect to the parent's PCI service (composite spec's pci parent). Same as e1000.
    zx::result<fidl::ClientEnd<fuchsia_hardware_pci::Device>> pci_client =
        incoming()->Connect<fuchsia_hardware_pci::Service::Device>();
    if (pci_client.is_error()) {
      FDF_LOG(ERROR, "Failed to connect to fuchsia.hardware.pci.Service: %s",
              pci_client.status_string());
      return pci_client.take_error();
    }
    pci_.Bind(std::move(pci_client.value()));

    // Enable bus mastering (PCI command bit 2). bus-pci already turns on memory-space
    // decode (command bit 1) when it enables the device, so BAR0/BAR2 already respond —
    // we don't touch bit 1 (the e1000 template likewise writes no command bits and reads
    // MMIO fine). This is belt-and-suspenders and non-fatal if it fails.
    fidl::Result<fuchsia_hardware_pci::Device::SetBusMastering> bm =
        pci_->SetBusMastering(true);
    if (bm.is_error()) {
      FDF_LOG(WARNING, "SetBusMastering failed (continuing): %s",
              bm.error_value().FormatDescription().c_str());
    }

    // BAR0: the linear framebuffer. Keep the VMO; force uncached-device so client writes
    // are scanned out with no flush, then hand duplicates to clients via GetBuffer().
    zx::result<zx::vmo> bar0 = GetBarVmo(0);
    if (bar0.is_error()) {
      FDF_LOG(ERROR, "GetBar(0) (framebuffer) failed: %s", bar0.status_string());
      return bar0.take_error();
    }
    framebuffer_vmo_ = std::move(bar0.value());
    zx_status_t cp = framebuffer_vmo_.set_cache_policy(ZX_CACHE_POLICY_UNCACHED_DEVICE);
    if (cp != ZX_OK && cp != ZX_ERR_BAD_STATE && cp != ZX_ERR_NOT_SUPPORTED) {
      FDF_LOG(ERROR, "set_cache_policy(UNCACHED_DEVICE) on framebuffer failed: %d", cp);
      return zx::error(cp);
    }

    // BAR2: the MMIO register window. Map it and program the VBE mode.
    zx::result<zx::vmo> bar2 = GetBarVmo(2);
    if (bar2.is_error()) {
      FDF_LOG(ERROR, "GetBar(2) (MMIO regs) failed: %s", bar2.status_string());
      return bar2.take_error();
    }
    uint64_t bar2_size = 0;
    if (zx_status_t st = bar2.value().get_size(&bar2_size); st != ZX_OK) {
      FDF_LOG(ERROR, "framebuffer BAR2 get_size failed: %d", st);
      return zx::error(st);
    }
    zx::result<fdf::MmioBuffer> mmio = fdf::MmioBuffer::Create(
        0, bar2_size, std::move(bar2.value()), ZX_CACHE_POLICY_UNCACHED_DEVICE);
    if (mmio.is_error()) {
      FDF_LOG(ERROR, "Failed to map BAR2 MMIO: %s", mmio.status_string());
      return mmio.take_error();
    }
    fdf::MmioBuffer& regs = mmio.value();

    // Program the Bochs VBE mode: disable, set geometry (32bpp), then enable the LFB.
    regs.Write16(0, kVbeMmioOffset + kVbeIndexEnable * 2);
    regs.Write16(static_cast<uint16_t>(kWidth), kVbeMmioOffset + kVbeIndexXres * 2);
    regs.Write16(static_cast<uint16_t>(kHeight), kVbeMmioOffset + kVbeIndexYres * 2);
    regs.Write16(32, kVbeMmioOffset + kVbeIndexBpp * 2);
    regs.Write16(static_cast<uint16_t>(kWidth), kVbeMmioOffset + kVbeIndexVirtWidth * 2);
    regs.Write16(kVbeEnabled | kVbeLfbEnabled, kVbeMmioOffset + kVbeIndexEnable * 2);
    FDF_LOG(INFO, "display: VBE mode set %ux%ux32", kWidth, kHeight);

    // Serve cerise.display.Service (member "framebuffer") from the outgoing directory.
    // This is the least-privilege handoff: the client gets a VMO scoped to this device's
    // BAR0, never an ambient MMIO resource.
    cerise_display::Service::InstanceHandler handler({
        .framebuffer = bindings_.CreateHandler(this, dispatcher(), fidl::kIgnoreBindingClosure),
    });
    zx::result<> add = outgoing()->AddService<cerise_display::Service>(std::move(handler));
    if (add.is_error()) {
      FDF_LOG(ERROR, "Failed to add cerise.display.Service: %s", add.status_string());
      return add.take_error();
    }

    static constexpr char kMarker[] = "CERISE-DISPLAY-BOUND\n";
    zx_debug_write(kMarker, sizeof(kMarker) - 1);
    FDF_LOG(INFO, "CERISE-DISPLAY-BOUND");
    return zx::ok();
  }

  // fidl::Server<cerise_display::Framebuffer>.
  void GetInfo(GetInfoCompleter::Sync& completer) override {
    cerise_display::Info info(kWidth, kHeight, kWidth * kBytesPerPixel, kBytesPerPixel,
                              cerise_display::PixelFormat::kX8R8G8B8);
    completer.Reply(fidl::Response<cerise_display::Framebuffer::GetInfo>(std::move(info)));
  }

  void GetBuffer(GetBufferCompleter::Sync& completer) override {
    zx::vmo dup;
    zx_status_t st = framebuffer_vmo_.duplicate(ZX_RIGHT_SAME_RIGHTS, &dup);
    if (st != ZX_OK) {
      FDF_LOG(ERROR, "duplicate framebuffer VMO failed: %d", st);
      completer.Close(st);
      return;
    }
    completer.Reply(fidl::Response<cerise_display::Framebuffer::GetBuffer>(std::move(dup)));
  }

 private:
  // Extracts a VMO-backed BAR from the PCI device (same tag-check as e1000).
  zx::result<zx::vmo> GetBarVmo(uint32_t bar_id) {
    fidl::Result bar_result = pci_->GetBar(bar_id);
    if (bar_result.is_error()) {
      if (bar_result.error_value().is_domain_error()) {
        return zx::error(bar_result.error_value().domain_error());
      }
      return zx::error(bar_result.error_value().framework_error().status());
    }
    if (bar_result->result().result().Which() != fuchsia_hardware_pci::BarResult::Tag::kVmo) {
      FDF_LOG(ERROR, "BAR%u is not VMO-backed MMIO", bar_id);
      return zx::error(ZX_ERR_WRONG_TYPE);
    }
    return zx::ok(zx::vmo(bar_result->result().result().vmo()->release()));
  }

  fidl::SyncClient<fuchsia_hardware_pci::Device> pci_;
  zx::vmo framebuffer_vmo_;
  fidl::ServerBindingGroup<cerise_display::Framebuffer> bindings_;
};

}  // namespace cerise_display_driver

FUCHSIA_DRIVER_EXPORT(cerise_display_driver::DisplayDriver);

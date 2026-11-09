// Cerise GOP framebuffer DFv2 display driver — first-light display path for real
// hardware. The EFI boot-shim queries the UEFI Graphics Output Protocol and emits a
// ZBI_TYPE_FRAMEBUFFER item (zbi_swfb_t); this driver consumes that item and serves the
// SAME cerise.display FIDL as the stdvga driver (src/cerise/drivers/display), so
// status_console lights a real panel completely unchanged.
//
// HOW THE DRIVER LEARNS THE FRAMEBUFFER (the ZBI-item-to-driver plumbing):
//   * Geometry + physical base come from fuchsia.boot.Items.Get(ZBI_TYPE_FRAMEBUFFER)
//     — component_manager's builtin ZBI item server (it stores ZbiType::Framebuffer;
//     builtin_environment.rs), whose protocol driver_manager already re-offers into the
//     #boot-drivers collection (driver_manager_rust_dfv2acpi.cml "fuchsia.boot.Items"
//     offer). No realm or policy edits are needed: this driver just `use`s the protocol.
//   * The framebuffer is a FIXED PHYSICAL RANGE picked by firmware — it is NOT a PCI BAR
//     handed out by bus-pci (on real Intel iGPUs the GOP framebuffer lives inside stolen
//     memory / a BAR the VGA class code doesn't describe uniformly), so unlike the stdvga
//     driver we cannot get a device-scoped VMO from fuchsia.hardware.pci. Instead the
//     driver takes fuchsia.kernel.MmioResource (also already offered into #boot-drivers,
//     and covered by the cm_config security allowlist for /driver_manager_rust/
//     boot-drivers:**) and carves exactly the ZBI-described range with
//     zx_vmo_create_physical(). CAPABILITY STORY: this is an ambient-range capability,
//     deliberately confined to a driver in the driver collection (the same confinement
//     argument that moved stdvga bring-up out of status_console); the client still only
//     ever sees the range-scoped framebuffer VMO.
//
// BIND: composite on the PCI display-class device (fuchsia.BIND_PCI_CLASS == DISPLAY,
// 0x03) published by bus-pci — a hardware-portable anchor (Intel iGPU on real hardware,
// stdvga-with-OVMF-GOP on the QEMU gate) that is NOT a VID:DID. The stdvga driver also
// matches class 0x03 devices, so the two drivers are mutually exclusive AT THE PRODUCT
// LEVEL: hw-x64-firstlight stages gop_display and not the stdvga display driver; the
// QEMU console products stage stdvga and not this. Never stage both.
#include <fidl/cerise.display/cpp/fidl.h>
#include <fidl/fuchsia.boot/cpp/fidl.h>
#include <fidl/fuchsia.kernel/cpp/fidl.h>
#include <lib/driver/component/cpp/driver_base.h>
#include <lib/driver/component/cpp/driver_export.h>
#include <lib/driver/logging/cpp/logger.h>
#include <lib/fidl/cpp/wire/server.h>
#include <lib/zbi-format/graphics.h>
#include <lib/zbi-format/zbi.h>
#include <zircon/syscalls.h>

namespace cerise_gop_display {

constexpr uint32_t kBytesPerPixel = 4;

class GopDisplayDriver : public fdf::DriverBase,
                         public fidl::Server<cerise_display::Framebuffer> {
 public:
  GopDisplayDriver(fdf::DriverStartArgs start_args,
                   fdf::UnownedSynchronizedDispatcher driver_dispatcher)
      : fdf::DriverBase("gop_display", std::move(start_args), std::move(driver_dispatcher)) {}

  zx::result<> Start() override {
    // 1. Fetch the boot-shim's ZBI_TYPE_FRAMEBUFFER item.
    zx::result<fidl::ClientEnd<fuchsia_boot::Items>> items_client =
        incoming()->Connect<fuchsia_boot::Items>();
    if (items_client.is_error()) {
      FDF_LOG(ERROR, "Failed to connect to fuchsia.boot.Items: %s",
              items_client.status_string());
      return items_client.take_error();
    }
    fidl::SyncClient<fuchsia_boot::Items> items(std::move(items_client.value()));
    fidl::Result<fuchsia_boot::Items::Get> item =
        items->Get({{.type = ZBI_TYPE_FRAMEBUFFER, .extra = 0}});
    if (item.is_error()) {
      FDF_LOG(ERROR, "fuchsia.boot.Items.Get(FRAMEBUFFER) failed: %s",
              item.error_value().FormatDescription().c_str());
      return zx::error(item.error_value().status());
    }
    if (!item->payload().is_valid() || item->length() < sizeof(zbi_swfb_t)) {
      // GOP-absent boot (headless, or shim found no linear FB): the item simply
      // isn't there. This is a supported headless state, not a failed driver
      // start. Complete Start successfully without publishing the display
      // service or success marker so the driver manager can continue binding
      // unrelated storage and network composites. status_console keeps retrying
      // and simply never renders — same as no display hardware.
      FDF_LOG(WARNING, "No ZBI_TYPE_FRAMEBUFFER item (len=%u); GOP display unavailable",
              item->length());
      return zx::ok();
    }
    zbi_swfb_t fb = {};
    if (zx_status_t st = item->payload().read(&fb, 0, sizeof(fb)); st != ZX_OK) {
      FDF_LOG(ERROR, "read of framebuffer item VMO failed: %d", st);
      return zx::error(st);
    }

    // 2. Validate. We serve X8R8G8B8 (what status_console consumes): the shim maps
    // little-endian BGRx GOP modes to ZBI_PIXEL_FORMAT_ARGB_8888; RGB_X888 is the
    // same 32bpp 0xXXRRGGBB word layout.
    if (fb.format != ZBI_PIXEL_FORMAT_ARGB_8888 && fb.format != ZBI_PIXEL_FORMAT_RGB_X888) {
      FDF_LOG(ERROR, "Unsupported ZBI framebuffer format %#x", fb.format);
      return zx::error(ZX_ERR_NOT_SUPPORTED);
    }
    if (fb.base == 0 || fb.width == 0 || fb.height == 0 || fb.stride < fb.width ||
        (fb.base & (zx_system_get_page_size() - 1)) != 0) {
      FDF_LOG(ERROR, "Bad ZBI framebuffer: base=%#lx %ux%u stride=%u",
              static_cast<unsigned long>(fb.base), fb.width, fb.height, fb.stride);
      return zx::error(ZX_ERR_OUT_OF_RANGE);
    }
    uint64_t size_bytes = static_cast<uint64_t>(fb.stride) * fb.height * kBytesPerPixel;
    const uint64_t page = zx_system_get_page_size();
    size_bytes = (size_bytes + page - 1) & ~(page - 1);

    // 3. Materialize the physical range as a VMO via the MMIO root resource.
    zx::result<fidl::ClientEnd<fuchsia_kernel::MmioResource>> mmio_client =
        incoming()->Connect<fuchsia_kernel::MmioResource>();
    if (mmio_client.is_error()) {
      FDF_LOG(ERROR, "Failed to connect to fuchsia.kernel.MmioResource: %s",
              mmio_client.status_string());
      return mmio_client.take_error();
    }
    fidl::SyncClient<fuchsia_kernel::MmioResource> mmio(std::move(mmio_client.value()));
    fidl::Result<fuchsia_kernel::MmioResource::Get> res = mmio->Get();
    if (res.is_error()) {
      FDF_LOG(ERROR, "MmioResource.Get failed: %s",
              res.error_value().FormatDescription().c_str());
      return zx::error(res.error_value().status());
    }
    zx::vmo fb_vmo;
    if (zx_status_t st = zx_vmo_create_physical(res->resource().get(), fb.base, size_bytes,
                                                fb_vmo.reset_and_get_address());
        st != ZX_OK) {
      FDF_LOG(ERROR, "zx_vmo_create_physical(%#lx, %#lx) failed: %d",
              static_cast<unsigned long>(fb.base), static_cast<unsigned long>(size_bytes), st);
      return zx::error(st);
    }
    // Same cache policy story as the stdvga driver: uncached-device so client writes
    // scan out with no explicit flush; tolerate already-set/unsupported.
    zx_status_t cp = fb_vmo.set_cache_policy(ZX_CACHE_POLICY_UNCACHED_DEVICE);
    if (cp != ZX_OK && cp != ZX_ERR_BAD_STATE && cp != ZX_ERR_NOT_SUPPORTED) {
      FDF_LOG(ERROR, "set_cache_policy(UNCACHED_DEVICE) failed: %d", cp);
      return zx::error(cp);
    }
    framebuffer_vmo_ = std::move(fb_vmo);
    info_ = fb;

    // 4. Serve cerise.display.Service — identical shape to the stdvga driver, so the
    // aggregation route (driver_manager expose of cerise.display.Service from
    // #boot-drivers) and status_console work unchanged.
    cerise_display::Service::InstanceHandler handler({
        .framebuffer = bindings_.CreateHandler(this, dispatcher(), fidl::kIgnoreBindingClosure),
    });
    zx::result<> add = outgoing()->AddService<cerise_display::Service>(std::move(handler));
    if (add.is_error()) {
      FDF_LOG(ERROR, "Failed to add cerise.display.Service: %s", add.status_string());
      return add.take_error();
    }

    static constexpr char kMarker[] = "CERISE-GOP-DISPLAY-OK\n";
    zx_debug_write(kMarker, sizeof(kMarker) - 1);
    FDF_LOG(INFO, "CERISE-GOP-DISPLAY-OK %ux%u stride=%u base=%#lx", fb.width, fb.height,
            fb.stride, static_cast<unsigned long>(fb.base));
    return zx::ok();
  }

  // fidl::Server<cerise_display::Framebuffer>.
  void GetInfo(GetInfoCompleter::Sync& completer) override {
    cerise_display::Info info(info_.width, info_.height, info_.stride * kBytesPerPixel,
                              kBytesPerPixel, cerise_display::PixelFormat::kX8R8G8B8);
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
  zx::vmo framebuffer_vmo_;
  zbi_swfb_t info_ = {};
  fidl::ServerBindingGroup<cerise_display::Framebuffer> bindings_;
};

}  // namespace cerise_gop_display

FUCHSIA_DRIVER_EXPORT(cerise_gop_display::GopDisplayDriver);

// Driver-host bring-up, Step 2: PARENT native DFv2 driver.
//
// This is the ROOT driver in the x64-dfv2-match product: driver_manager's REAL
// DriverRunner start_root_driver()s it by URL (no driver-index match needed for the
// root). In Start() it calls the real fdf Node.AddChild on the Node client it received
// in DriverStartArgs (served by driver_manager) to create a CHILD node carrying a bind
// property. driver_manager's Node server records the child and asks driver-index to
// MATCH a driver against that property — driving the real match/start loop that loads
// the CHILD driver (see //src/cerise/child_driver). Marker: CERISE-DFV2-PARENT-OK.
#include <lib/driver/component/cpp/driver_base.h>
#include <lib/driver/component/cpp/driver_export.h>
#include <lib/driver/component/cpp/node_properties.h>
#include <lib/driver/logging/cpp/logger.h>
#include <zircon/syscalls.h>

#include <vector>

namespace parent_driver {

class ParentDriver : public fdf::DriverBase {
 public:
  ParentDriver(fdf::DriverStartArgs start_args,
               fdf::UnownedSynchronizedDispatcher driver_dispatcher)
      : fdf::DriverBase("cerise_parent_driver", std::move(start_args),
                        std::move(driver_dispatcher)) {
    const char kCtor[] = "CERISE-DFV2-PARENT-CTOR\n";
    zx_debug_write(kCtor, sizeof(kCtor) - 1);
  }

  zx::result<> Start() override {
    const char kStart[] = "CERISE-DFV2-PARENT-START\n";
    zx_debug_write(kStart, sizeof(kStart) - 1);

    // Create a child node with a bind property the CHILD driver matches on. The driver
    // framework will try to match+bind a driver to this child (the real driver-index
    // MATCH/START loop). AddChild is a synchronous fdf call; the driver dispatcher in
    // driver_host_dfv2 is created allow_thread_blocking() so sync calls are permitted.
    std::vector<fuchsia_driver_framework::NodeProperty2> properties = {
        fdf::MakeProperty2("cerise.test.DEVICE", "cerise-di-match"),
    };
    std::vector<fuchsia_driver_framework::Offer> offers;
    zx::result<fidl::ClientEnd<fuchsia_driver_framework::NodeController>> child =
        AddChild("child", properties, offers);
    if (child.is_error()) {
      const char kErr[] = "CERISE-DFV2-PARENT-ADDCHILD-ERR\n";
      zx_debug_write(kErr, sizeof(kErr) - 1);
      FDF_LOG(ERROR, "CERISE parent AddChild failed: %s", child.status_string());
      return child.take_error();
    }
    // Keep the NodeController alive so the child node is not torn down.
    controller_ = std::move(child.value());

    const char kMark[] = "CERISE-DFV2-PARENT-OK\n";
    zx_debug_write(kMark, sizeof(kMark) - 1);
    FDF_LOG(INFO, "CERISE-DFV2-PARENT-OK");
    return zx::ok();
  }

 private:
  fidl::ClientEnd<fuchsia_driver_framework::NodeController> controller_;
};

}  // namespace parent_driver

FUCHSIA_DRIVER_EXPORT(parent_driver::ParentDriver);

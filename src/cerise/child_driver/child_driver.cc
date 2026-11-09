// Driver-host bring-up, Step 2: CHILD native DFv2 driver.
//
// This is the POST-MATCH driver: driver-index matches it (by its .bindbc bind rules,
// see meta/child.bind) against the bind property the PARENT driver attached to the
// child node it AddChild()ed. driver_manager then loads + Start()-runs this driver in
// a driver_host. Its Start() running is the proof that the real driver-index MATCH/START
// loop executed end-to-end. Markers: CERISE-DFV2-CHILD-OK + CERISE-DI-MATCH-OK (the
// latter distinguishes "started after a real driver-index match" from the parent's own
// start, which was by-URL with no match).
#include <lib/driver/component/cpp/driver_base.h>
#include <lib/driver/component/cpp/driver_export.h>
#include <lib/driver/logging/cpp/logger.h>
#include <zircon/syscalls.h>

namespace child_driver {

class ChildDriver : public fdf::DriverBase {
 public:
  ChildDriver(fdf::DriverStartArgs start_args,
              fdf::UnownedSynchronizedDispatcher driver_dispatcher)
      : fdf::DriverBase("cerise_child_driver", std::move(start_args),
                        std::move(driver_dispatcher)) {
    const char kCtor[] = "CERISE-DFV2-CHILD-CTOR\n";
    zx_debug_write(kCtor, sizeof(kCtor) - 1);
  }

  zx::result<> Start() override {
    const char kChild[] = "CERISE-DFV2-CHILD-OK\n";
    zx_debug_write(kChild, sizeof(kChild) - 1);
    // This driver only runs because driver-index MATCHED its bind rules to the child
    // node's property. Emit the distinct match marker.
    const char kMatch[] = "CERISE-DI-MATCH-OK\n";
    zx_debug_write(kMatch, sizeof(kMatch) - 1);
    FDF_LOG(INFO, "CERISE-DFV2-CHILD-OK");
    FDF_LOG(INFO, "CERISE-DI-MATCH-OK");
    return zx::ok();
  }
};

}  // namespace child_driver

FUCHSIA_DRIVER_EXPORT(child_driver::ChildDriver);

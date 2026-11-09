// PCI bring-up: PCI probe driver — minimal DFv2-native driver that binds
// to the e1000 isolate child node (8086:100e) published by bus-pci's FidlDevice::Create().
// Prints CERISE-PCI-DEVICE-BOUND from Start() to prove the full chain:
//   PCI-enumerate → isolate-node-publish → driver-index match → driver_host Start → probe Start.
//
// Modeled exactly on src/cerise/minimal_driver/ (the proven DFv2-native .so template).
// Version-script (pci_probe.ld) exports ONLY __fuchsia_driver_registration__ (DFv2 loader lesson).
#include <lib/driver/component/cpp/driver_base.h>
#include <lib/driver/component/cpp/driver_export.h>
#include <lib/driver/logging/cpp/logger.h>
#include <zircon/syscalls.h>

namespace pci_probe {

class PciProbeDriver : public fdf::DriverBase {
 public:
  PciProbeDriver(fdf::DriverStartArgs start_args,
                 fdf::UnownedSynchronizedDispatcher driver_dispatcher)
      : fdf::DriverBase("cerise_pci_probe", std::move(start_args),
                        std::move(driver_dispatcher)) {}

  zx::result<> Start() override {
    // Emit the validation marker: proves the full PCI→driver-index→driver_host→Start chain.
    const char kMark[] = "CERISE-PCI-DEVICE-BOUND\n";
    zx_debug_write(kMark, sizeof(kMark) - 1);
    FDF_LOG(INFO, "CERISE-PCI-DEVICE-BOUND");
    return zx::ok();
  }
};

}  // namespace pci_probe

FUCHSIA_DRIVER_EXPORT(pci_probe::PciProbeDriver);

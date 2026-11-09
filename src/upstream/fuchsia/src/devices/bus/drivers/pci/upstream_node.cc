// Copyright 2018 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/devices/bus/drivers/pci/upstream_node.h"

#include <assert.h>
#include <err.h>
#include <inttypes.h>
#include <stdio.h>   // Cerise change: snprintf for the PCI-CFG diagnostic markers
#include <string.h>
#include <zircon/syscalls.h>  // Cerise change: zx_debug_write for PCI-CFG markers

#include <fbl/algorithm.h>

#include "src/devices/bus/drivers/pci/common.h"

namespace pci {

void UpstreamNode::ConfigureDownstreamDevices() {
  // A helper function to split device and bridge configuration into separate
  // passes. Since bridges are added to the topology as they are found in a DFS
  // manner, this ensures we will fulfill the windows in the proper order.
  auto configure_downstream_devices = [this](bool configuring_bridges) {
    for (auto& device : downstream_) {
      if (device.is_bridge() == configuring_bridges) {
        // Cerise change (diagnostic): announce the device *before* touching it.
        // If the console dies mid-pass, the last line names the culprit.
        {
          char buf[96];
          snprintf(buf, sizeof(buf), "PCI-CFG bdf=%s bridge=%d bars-begin\n",
                   device.config()->addr(), configuring_bridges ? 1 : 0);
          zx_debug_write(buf, strlen(buf));
        }
        // Some capabilities can only be configured after device BARs have been
        // configured, and device BARs cannot be configured when a Device is object
        // is created since bridge windows still need to be allocated.
        if (auto result = device.AllocateBars(); result.is_error()) {
          {
            char buf[96];
            snprintf(buf, sizeof(buf), "PCI-CFG bdf=%s bars-FAILED-disabling\n",
                     device.config()->addr());
            zx_debug_write(buf, strlen(buf));
          }
          device.Disable();
        }
        {
          char buf[96];
          snprintf(buf, sizeof(buf), "PCI-CFG bdf=%s caps-begin\n", device.config()->addr());
          zx_debug_write(buf, strlen(buf));
        }
        if (auto result = device.ConfigureCapabilities(); result.is_error()) {
          {
            char buf[96];
            snprintf(buf, sizeof(buf), "PCI-CFG bdf=%s caps-FAILED-disabling\n",
                     device.config()->addr());
            zx_debug_write(buf, strlen(buf));
          }
          device.Disable();
        }
        {
          char buf[96];
          snprintf(buf, sizeof(buf), "PCI-CFG bdf=%s done\n", device.config()->addr());
          zx_debug_write(buf, strlen(buf));
        }
      }
    }
  };

  // Configure bridges first so they can set up their IO windows.
  configure_downstream_devices(/*configuring_bridges=*/true);
  // Now configure device BARs and capabilities with the bridges configured ahead of time.
  configure_downstream_devices(/*configuring_bridges=*/false);
}

void UpstreamNode::DisableDownstream() {
  for (auto& device : downstream_) {
    device.Disable();
  }
}

void UpstreamNode::UnplugDownstream() {
  // Unplug our downstream devices and clear them out of the topology.  They
  // will remove themselves from the bus list and their resources will be
  // cleaned up.
  size_t idx = downstream_.size_slow();
  while (!downstream_.is_empty()) {
    // Catch if we've iterated longer than we should have without needing a
    // stable iterator while devices are removing themselves.
    ZX_DEBUG_ASSERT(idx-- > 0);
    // Hold a device reference to ensure the dtor fires after unplug has
    // finished.
    fbl::RefPtr<Device> dev = fbl::RefPtr(&downstream_.front());
    dev->Unplug();
  }
}

}  // namespace pci

// Copyright 2026 The Cerise Authors. All rights reserved.

#ifndef SRC_DEVICES_BUS_DRIVERS_PCI_MSI_LOCK_H_
#define SRC_DEVICES_BUS_DRIVERS_PCI_MSI_LOCK_H_

#include <utility>

namespace pci::internal {

// Runs one platform MSI allocation while holding only the caller-supplied
// allocation lock. In particular, this helper has no topology-lock access;
// Device::EnableMsi already owns a device lock when it calls into the bus.
template <typename Lock, typename Guard, typename Callback>
decltype(auto) WithMsiAllocationLock(Lock* lock, Callback&& callback) {
  Guard guard(lock);
  return std::forward<Callback>(callback)();
}

}  // namespace pci::internal

#endif  // SRC_DEVICES_BUS_DRIVERS_PCI_MSI_LOCK_H_

// Copyright 2020 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
#include <zircon/errors.h>
#include <zircon/status.h>

#include "src/devices/bus/drivers/pci/bus.h"
#include "src/devices/bus/drivers/pci/msi_lock.h"

namespace pci {

zx_status_t Bus::LinkDevice(fbl::RefPtr<pci::Device> device) {
  fbl::AutoLock _(&devices_lock_);
  if (devices_.find(device->config()->bdf())) {
    return ZX_ERR_ALREADY_EXISTS;
  }
  devices_.insert(device);
  return ZX_OK;
}

zx_status_t Bus::UnlinkDevice(pci::Device* device) {
  fbl::AutoLock _(&devices_lock_);
  ZX_DEBUG_ASSERT(device);
  if (devices_.find(device->config()->bdf())) {
    devices_.erase(*device);
    return ZX_OK;
  }
  return ZX_ERR_NOT_FOUND;
}

zx_status_t Bus::AllocateMsi(uint32_t count, zx::msi* msi) {
  // Do not take devices_lock_ here. Device::EnableMsi calls this while
  // holding that device's dev_lock_. The topology/IRQ paths take
  // devices_lock_ before individual dev_lock_ instances, so taking the
  // topology lock here creates a device_lock -> devices_lock inversion and
  // can strand the single PCI FIDL dispatcher. Serialize root allocations
  // with the dedicated MSI lock instead; it has no topology lock dependency.
  return internal::WithMsiAllocationLock<fbl::Mutex, fbl::AutoLock<fbl::Mutex>>(
      &msi_lock_, [this, count, msi] { return pciroot().AllocateMsi(count, false, msi); });
}

zx_status_t Bus::GetBti(const pci::Device* device, uint32_t index, zx::bti* bti) {
  if (!device) {
    return ZX_ERR_INVALID_ARGS;
  }
  fbl::AutoLock devices_lock(&devices_lock_);
  return pciroot().GetBti(device->packed_addr(), index, bti);
}

zx_status_t Bus::AddToSharedIrqList(pci::Device* device, uint32_t vector) {
  ZX_DEBUG_ASSERT(vector);
  fbl::AutoLock _(&devices_lock_);

  if (auto result = shared_irqs_.find(vector); result != shared_irqs_.end()) {
    auto& list = result->second->list;
    if (list.find_if([device](auto& iter) -> bool { return device == &iter; }) != list.end()) {
      return ZX_ERR_ALREADY_EXISTS;
    }
    list.push_back(device);
    zxlogf(TRACE, "[%s] inserted into list for vector %#x", device->config()->addr(), vector);
    return ZX_OK;
  }
  return ZX_ERR_BAD_STATE;
}

zx_status_t Bus::RemoveFromSharedIrqList(pci::Device* device, uint32_t vector) {
  ZX_DEBUG_ASSERT(vector);
  fbl::AutoLock _(&devices_lock_);

  if (auto result = shared_irqs_.find(vector); result != shared_irqs_.end()) {
    auto& list = result->second->list;
    if (list.erase(*device) != nullptr) {
      zxlogf(TRACE, "[%s] removed from vector %#x list", device->config()->addr(), vector);
      return ZX_OK;
    }
    return ZX_ERR_NOT_FOUND;
  }
  return ZX_ERR_BAD_STATE;
}

}  // namespace pci

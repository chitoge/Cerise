// Copyright 2026 The Cerise Authors. All rights reserved.

#include "msi_lock.h"

#include <assert.h>

#include <atomic>
#include <chrono>
#include <mutex>
#include <thread>

namespace {

struct MsiProbe {
  std::atomic<bool> entered = false;
  std::atomic<bool> allow_return = false;
};

struct StdAutoLock {
  explicit StdAutoLock(std::timed_mutex* lock) : lock_(lock) { lock_->lock(); }
  ~StdAutoLock() { lock_->unlock(); }

 private:
  std::timed_mutex* lock_;
};

}  // namespace

int main() {
  MsiProbe probe;
  std::timed_mutex topology_lock;
  std::timed_mutex modeled_device_lock;
  std::timed_mutex msi_lock;
  std::atomic<bool> topology_held = false;
  std::atomic<bool> device_held = false;
  std::atomic<bool> start_device_attempt = false;
  std::atomic<bool> entered_while_topology_held = false;
  std::atomic<bool> worker_done = false;

  // Model the IRQ worker/GetDevices lock order: topology, then device.
  std::thread worker([&] {
    std::unique_lock topology_guard(topology_lock);
    topology_held.store(true, std::memory_order_release);
    while (!start_device_attempt.load(std::memory_order_acquire)) {
      std::this_thread::yield();
    }
    const bool got_device = modeled_device_lock.try_lock_for(std::chrono::milliseconds(100));
    if (got_device) {
      modeled_device_lock.unlock();
    }
    entered_while_topology_held.store(probe.entered.load(std::memory_order_acquire),
                                      std::memory_order_release);
    worker_done.store(true, std::memory_order_release);
  });

  while (!topology_held.load(std::memory_order_acquire)) {
    std::this_thread::yield();
  }

  // Model Device::SetIrqMode holding a device lock while asking the bus for
  // an MSI. WithMsiAllocationLock must not acquire topology_lock.
  std::thread msi([&] {
    std::unique_lock device_guard(modeled_device_lock);
    device_held.store(true, std::memory_order_release);
    while (!topology_held.load(std::memory_order_acquire)) {
      std::this_thread::yield();
    }
    pci::internal::WithMsiAllocationLock<std::timed_mutex, StdAutoLock>(
        &msi_lock, [&] {
          probe.entered.store(true, std::memory_order_release);
          while (!probe.allow_return.load(std::memory_order_acquire)) {
            std::this_thread::yield();
          }
        });
  });

  while (!device_held.load(std::memory_order_acquire)) {
    std::this_thread::yield();
  }
  start_device_attempt.store(true, std::memory_order_release);
  while (!worker_done.load(std::memory_order_acquire)) {
    std::this_thread::yield();
  }

  // The old implementation acquired devices_lock_ here and could not reach
  // the allocation callback until the worker released topology_lock. The
  // dedicated MSI lock lets the callback run while topology_lock is held.
  assert(entered_while_topology_held.load(std::memory_order_acquire));
  probe.allow_return.store(true, std::memory_order_release);
  msi.join();
  worker.join();
  return 0;
}

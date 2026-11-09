// Copyright 2025 The Fuchsia Authors
//
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT
//
// Cerise ARMv7 MMIO generic timer driver interface stub.
// Production implementation: zircon/kernel/dev/timer/arm_generic (to be imported).

#ifndef DEV_TIMER_ARMV7_MMIO_TIMER_H_
#define DEV_TIMER_ARMV7_MMIO_TIMER_H_

#include <stddef.h>
#include <stdint.h>
#include <zircon/types.h>

// Stub for the ARMv7 MMIO timer driver used by suspend_wakeup_timer.
class Armv7MmioTimer {
 public:
  enum class Type { VCT, PCT };
  enum class IrqHandlerResult { RemainRegistered, Unregister };

  static constexpr size_t kMaxTimers = 0;

  // Inner Timer object for a single comparator channel.
  class Timer {
   public:
    bool supported() const { return false; }
    bool enabled() const { return false; }
    zx_status_t CancelTimer() { return ZX_ERR_NOT_SUPPORTED; }
    template <typename F>
    zx_status_t SetHandler(F&& handler, uint32_t cpu_mask) {
      return ZX_ERR_NOT_SUPPORTED;
    }
    void SetRelativeTimer(zx_duration_t delta) {}
  };

  // Returns nullptr: no hardware present in stub.
  static Armv7MmioTimer* Get(size_t index) { return nullptr; }

  Timer& vct_timer() { return timer_; }
  Timer& pct_timer() { return timer_; }

 private:
  Timer timer_;
};

#endif  // DEV_TIMER_ARMV7_MMIO_TIMER_H_

// Copyright 2017 The Fuchsia Authors
//
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT

#ifndef ZIRCON_KERNEL_HYPERVISOR_INCLUDE_HYPERVISOR_INTERRUPT_TRACKER_H_
#define ZIRCON_KERNEL_HYPERVISOR_INCLUDE_HYPERVISOR_INTERRUPT_TRACKER_H_

#include <lib/fit/defer.h>
#include <lib/ktrace.h>
#include <lib/zx/result.h>

#include <bitmap/raw-bitmap.h>
#include <bitmap/storage.h>
#include <hypervisor/ktrace.h>
#include <hypervisor/state_invalidator.h>
#include <kernel/event.h>

namespace hypervisor {

template <uint32_t N>
class InterruptBitmap {
 public:
  InterruptBitmap() {
    zx_status_t result = bitmap_.Reset(N);
    // `bitmap_` uses static storage, so `Reset` cannot fail.
    DEBUG_ASSERT(result == ZX_OK);
  }

  bool Get(uint32_t vector) const { return bitmap_.GetOne(vector); }
  void Set(uint32_t vector) { bitmap_.SetOne(vector); }
  void Clear(uint32_t min, uint32_t max) { bitmap_.Clear(min, max); }

  // The 32 vectors [base, base + 32) as a bitmask, bit i being vector base + i.
  // Built a bit at a time rather than by reaching into the bitmap's storage,
  // because `RawBitmapGeneric`'s word type is not part of its public contract.
  uint32_t GetWord(uint32_t base) const {
    uint32_t word = 0;
    for (uint32_t i = 0; i < 32 && base + i < N; i++) {
      if (bitmap_.GetOne(base + i)) {
        word |= uint32_t{1} << i;
      }
    }
    return word;
  }

  bool Scan(uint32_t* vector) {
    size_t bitoff = 0;
#if defined(__aarch64__) || defined(__riscv)
    bool is_empty = bitmap_.Scan(0, N, false, &bitoff);
#elif defined(__x86_64__)
    bool is_empty = bitmap_.ReverseScan(0, N, false, &bitoff);
#else
#error add support for this architecture
#endif
    if (is_empty) {
      return false;
    }
    *vector = static_cast<uint32_t>(bitoff);
    return true;
  }

 private:
  bitmap::RawBitmapGeneric<bitmap::FixedStorage<N>> bitmap_;
};

// |N| is the maximum number of interrupts to be tracked.
template <uint32_t N>
class InterruptTracker {
 public:
  // Returns whether there are pending interrupts.
  bool Pending() {
    uint32_t vector;
    Guard<SpinLock, IrqSave> lock{&lock_};
    return bitmap_.Scan(&vector);
  }

  // Non-destructively returns the HIGHEST pending vector, if any. Same scan
  // Pop() uses to choose what to deliver next, but without consuming it -- so a
  // caller can ask "what would be delivered, and would it be deliverable at the
  // guest's current priority" before deciding whether to block. Used by
  // handle_hlt to avoid parking a guest that lazy-EOI'd a higher vector and is
  // awaiting a now-deliverable lower one.
  bool Peek(uint32_t* vector) {
    Guard<SpinLock, IrqSave> lock{&lock_};
    return bitmap_.Scan(vector);
  }

  // Clears all vectors in the range [min, max).
  void Clear(uint32_t min, uint32_t max) {
    Guard<SpinLock, IrqSave> lock{&lock_};
    bitmap_.Clear(min, max);
  }

  // Non-destructively returns whether |vector| is currently pending. Used by
  // snapshot capture and its validation; unlike Pop/TryPop it does not consume.
  bool Get(uint32_t vector) {
    if (vector >= N) {
      return false;
    }
    Guard<SpinLock, IrqSave> lock{&lock_};
    return bitmap_.Get(vector);
  }

  // The 32 pending vectors starting at |base|, as a bitmask. This is what the
  // x2APIC IRR registers (0x820-0x827) expose: the interrupt-request register is
  // exactly "which vectors have been requested and not yet accepted", which for
  // this hypervisor is this bitmap. Non-destructive.
  uint32_t PendingWord(uint32_t base) {
    if (base >= N) {
      return 0;
    }
    Guard<SpinLock, IrqSave> lock{&lock_};
    return bitmap_.GetWord(base);
  }

  // Serialization support: invokes `fn(vector)` for every currently-pending
  // vector without consuming it or waking waiters. Used by VCPU state capture
  // (snapshot/restore); `fn` must not re-enter the tracker.
  template <typename F>
  void ForEachPending(F&& fn) {
    Guard<SpinLock, IrqSave> lock{&lock_};
    for (uint32_t vector = 0; vector < N; ++vector) {
      if (bitmap_.Get(vector)) {
        fn(vector);
      }
    }
  }

  // Pops the specified vector, if it is pending.
  bool TryPop(uint32_t vector) {
    // The bounds test guards the bitmap access, so it admits in-range vectors.
    // It was inverted, which made this return false for every vector a caller
    // could legitimately pass: its only caller asks for the NMI first, in order
    // to give NMIs the priority the architecture gives them, and that never
    // happened. The NMI then fell through to `Pop`'s highest-vector-first scan,
    // where vector 2 loses to every ordinary interrupt.
    if (vector < N) {
      Guard<SpinLock, IrqSave> lock{&lock_};
      if (bitmap_.Get(vector)) {
        bitmap_.Clear(vector, vector + 1);
        return true;
      }
    }
    return false;
  }

  // Pops the highest priority interrupt.
  bool Pop(uint32_t* vector) {
    Guard<SpinLock, IrqSave> lock{&lock_};
    if (bitmap_.Scan(vector)) {
      bitmap_.Clear(*vector, *vector + 1);
      return true;
    }
    return false;
  }

  // Tracks the given interrupt.
  zx::result<> Track(uint32_t vector) {
    if (vector >= N) {
      return zx::error(ZX_ERR_OUT_OF_RANGE);
    }
    Guard<SpinLock, IrqSave> lock{&lock_};
    bitmap_.Set(vector);
    return zx::ok();
  }

  template <uint32_t Vector>
  void Track() {
    static_assert(Vector < N, "Vector out of bounds");
    [[maybe_unused]] zx::result<> result = Track(Vector);
  }

  // Tracks the given interrupt, and signals any waiters.
  zx::result<> Interrupt(uint32_t vector) {
    zx::result<> result = Track(vector);
    if (result.is_ok()) {
      event_.Signal();
    }
    return result;
  }

  template <uint32_t Vector>
  void Interrupt() {
    static_assert(Vector < N, "Vector out of bounds");
    [[maybe_unused]] zx::result<> result = Interrupt(Vector);
  }

  // Cancels a wait for an interrupt.
  //
  // We signal `ZX_ERR_INTERNAL_INTR_RETRY`, so that if the status is propagated
  // to the syscall-layer, we will retry the syscall.
  void Cancel() { event_.Signal(ZX_ERR_INTERNAL_INTR_RETRY); }

  // Waits for an interrupt.
  zx::result<> Wait(zx_instant_mono_t deadline, StateInvalidator* invalidator = nullptr) {
    if (invalidator != nullptr) {
      invalidator->Invalidate();
    }
    ktrace_vcpu(VCPU_BLOCK, VCPU_INTERRUPT);
    auto defer = fit::defer([] { ktrace_vcpu(VCPU_UNBLOCK, VCPU_INTERRUPT); });
    do {
      zx_status_t status = event_.Wait(Deadline::no_slack(deadline));
      switch (status) {
        case ZX_OK:
          continue;
        case ZX_ERR_TIMED_OUT:
          // If the event timed out, return ZX_OK to resume the VCPU.
          return zx::ok();
        default:
          // Otherwise, return the status.
          return zx::error(status);
      }
    } while (!Pending());
    return zx::ok();
  }

 private:
  AutounsignalEvent event_;
  DECLARE_SPINLOCK(InterruptTracker) lock_;
  InterruptBitmap<N> bitmap_ TA_GUARDED(lock_);
};

}  // namespace hypervisor

#endif  // ZIRCON_KERNEL_HYPERVISOR_INCLUDE_HYPERVISOR_INTERRUPT_TRACKER_H_

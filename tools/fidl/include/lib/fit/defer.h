#ifndef LIB_FIT_DEFER_H_
#define LIB_FIT_DEFER_H_

#include <lib/fit/function.h>

#include <utility>

namespace fit {

template <typename Callable>
class deferred_action {
 public:
  deferred_action() = default;

  explicit deferred_action(Callable callable) : callable_(std::move(callable)), active_(true) {}

  deferred_action(deferred_action&& other) noexcept
      : callable_(std::move(other.callable_)), active_(other.active_) {
    other.active_ = false;
  }

  deferred_action& operator=(deferred_action&& other) noexcept {
    if (this == &other) {
      return *this;
    }
    callable_ = std::move(other.callable_);
    active_ = other.active_;
    other.active_ = false;
    return *this;
  }

  deferred_action(const deferred_action&) = delete;
  deferred_action& operator=(const deferred_action&) = delete;

  ~deferred_action() {
    if (active_) {
      callable_();
    }
  }

  explicit operator bool() const noexcept { return active_; }

  void cancel() noexcept { active_ = false; }

  void call() {
    if (!active_) {
      return;
    }
    active_ = false;
    callable_();
  }

 private:
  Callable callable_{};
  bool active_ = false;
};

template <typename Callable = closure, typename Callback>
deferred_action<Callable> defer(Callback&& callback) {
  return deferred_action<Callable>(Callable(std::forward<Callback>(callback)));
}

}  // namespace fit

#endif  // LIB_FIT_DEFER_H_
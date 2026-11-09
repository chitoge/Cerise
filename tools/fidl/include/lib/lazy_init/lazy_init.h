#ifndef LIB_LAZY_INIT_LAZY_INIT_H_
#define LIB_LAZY_INIT_LAZY_INIT_H_

#include <new>
#include <utility>

namespace lazy_init {

enum class CheckType {
  None,
  Basic,
};

enum class Destructor {
  Enabled,
  Disabled,
};

struct Access;

// Declaration-only shim for headers that expose LazyInit in their public types.
template <typename T, CheckType = CheckType::Basic, Destructor = Destructor::Enabled>
class LazyInit {
 public:
  constexpr LazyInit() = default;

  template <typename... Args>
  T& Initialize(Args&&... args) {
    if (!initialized_) {
      ::new (static_cast<void*>(storage_)) T(std::forward<Args>(args)...);
      initialized_ = true;
    }
    return Get();
  }

  T& Get() {
    CheckInitialized();
    return *std::launder(reinterpret_cast<T*>(storage_));
  }

  const T& Get() const {
    CheckInitialized();
    return *std::launder(reinterpret_cast<const T*>(storage_));
  }

  T* operator->() { return &Get(); }
  const T* operator->() const { return &Get(); }

  T& operator*() { return Get(); }
  const T& operator*() const { return Get(); }

 private:
  void CheckInitialized() const {
    if (!initialized_) {
      __builtin_trap();
    }
  }

  alignas(T) unsigned char storage_[sizeof(T)] = {};
  bool initialized_ = false;
};

}  // namespace lazy_init

#endif  // LIB_LAZY_INIT_LAZY_INIT_H_
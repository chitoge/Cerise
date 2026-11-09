#ifndef LIB_ZX_RESULT_H_
#define LIB_ZX_RESULT_H_

#include <zircon/types.h>

#include <optional>
#include <type_traits>
#include <utility>

namespace zx {

template <typename Value = void>
class ok_result;

template <typename Value = void>
class [[nodiscard]] result;

template <typename Value>
class ok_result {
 public:
  explicit ok_result(Value value) : value_(std::move(value)) {}

 private:
  template <typename>
  friend class result;

  Value value_;
};

template <>
class ok_result<void> {};

class error_result {
 public:
  explicit error_result(zx_status_t status) : status_(status) {}

 private:
  template <typename>
  friend class result;

  zx_status_t status_;
};

using error = error_result;

inline ok_result<void> ok() { return ok_result<void>{}; }

inline ok_result<void> success() { return ok(); }

template <typename Value>
ok_result<std::decay_t<Value>> ok(Value&& value) {
  return ok_result<std::decay_t<Value>>(std::forward<Value>(value));
}

template <typename Value>
ok_result<std::decay_t<Value>> success(Value&& value) {
  return ok(std::forward<Value>(value));
}

inline result<> make_result(zx_status_t status);

template <typename Value>
result<std::remove_reference_t<Value>> make_result(zx_status_t status, Value&& value);

template <typename Value>
class [[nodiscard]] result {
 public:
  result() = default;

  result(ok_result<Value> success) : value_(std::move(success.value_)), state_(State::kOk) {}

  template <
      typename Other,
      typename = std::enable_if_t<!std::is_same_v<Value, Other> &&
                                  std::is_constructible_v<Value, Other&&>>>
  result(ok_result<Other> success)
      : value_(Value(std::move(success.value_))), state_(State::kOk) {}

  template <
      typename Other,
      typename = std::enable_if_t<!std::is_same_v<Value, Other> &&
                                  std::is_constructible_v<Value, Other&&>>,
      int = 0>
  result(result<Other>&& other) : status_(other.status_value()) {
    if (other.is_ok()) {
      value_.emplace(Value(std::move(other.value())));
      state_ = State::kOk;
    } else if (other.is_error()) {
      state_ = State::kError;
    }
  }

  template <
      typename Other,
      typename = std::enable_if_t<!std::is_same_v<Value, Other> &&
                                  std::is_constructible_v<Value, const Other&>>,
      int = 0,
      int = 0>
  result(const result<Other>& other) : status_(other.status_value()) {
    if (other.is_ok()) {
      value_.emplace(Value(other.value()));
      state_ = State::kOk;
    } else if (other.is_error()) {
      state_ = State::kError;
    }
  }

  result(error_result failure) : status_(failure.status_), state_(State::kError) {}

  bool is_ok() const { return state_ == State::kOk; }
  bool is_error() const { return state_ == State::kError; }

  zx_status_t error_value() const { return status_; }
  zx_status_t status_value() const { return is_error() ? status_ : ZX_OK; }

  error_result take_error() const { return error_result(status_value()); }

  Value& value() & { return *value_; }
  const Value& value() const& { return *value_; }
  Value&& value() && { return std::move(*value_); }

  template <typename Default>
  Value value_or(Default&& default_value) const& {
    if (is_ok()) {
      return *value_;
    }
    return static_cast<Value>(std::forward<Default>(default_value));
  }

  template <typename Default>
  Value value_or(Default&& default_value) && {
    if (is_ok()) {
      return std::move(*value_);
    }
    return static_cast<Value>(std::forward<Default>(default_value));
  }

  Value& operator*() & { return value(); }
  const Value& operator*() const& { return value(); }
  Value&& operator*() && { return std::move(value()); }

  auto operator->() { return Arrow(value(), 0); }
  auto operator->() const { return Arrow(value(), 0); }

 private:
  enum class State {
    kEmpty,
    kOk,
    kError,
  };

  template <typename T>
  static T* Arrow(T* current_value, int) {
    return current_value;
  }

  template <typename T>
  static auto Arrow(T& current_value, int) -> decltype(current_value.operator->()) {
    return current_value.operator->();
  }

  template <typename T>
  static T* Arrow(T& current_value, long) {
    return &current_value;
  }

  std::optional<Value> value_;
  zx_status_t status_ = ZX_OK;
  State state_ = State::kEmpty;
};

template <>
class [[nodiscard]] result<void> {
 public:
  result() = default;

  result(ok_result<void>) : state_(State::kOk) {}

  result(error_result failure) : status_(failure.status_), state_(State::kError) {}

  bool is_ok() const { return state_ == State::kOk; }
  bool is_error() const { return state_ == State::kError; }

  zx_status_t error_value() const { return status_; }
  zx_status_t status_value() const { return status_; }
  error_result take_error() const { return error_result(status_value()); }

 private:
  enum class State {
    kEmpty,
    kOk,
    kError,
  };

  zx_status_t status_ = ZX_OK;
  State state_ = State::kEmpty;
};

inline result<> make_result(zx_status_t status) {
  if (status == ZX_OK) {
    return ok();
  }
  return error_result(status);
}

template <typename Value>
result<std::remove_reference_t<Value>> make_result(zx_status_t status, Value&& value) {
  if (status == ZX_OK) {
    return ok(std::forward<Value>(value));
  }
  return error_result(status);
}

}  // namespace zx

#endif  // LIB_ZX_RESULT_H_
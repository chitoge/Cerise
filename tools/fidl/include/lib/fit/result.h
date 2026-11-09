#ifndef LIB_FIT_RESULT_H_
#define LIB_FIT_RESULT_H_

#include <optional>
#include <type_traits>
#include <utility>
#include <variant>

namespace fit {

struct failed {};

template <typename Error>
class error {
 public:
  using __allow_ctad = void;

  constexpr explicit error(Error value) : value_(std::move(value)) {}

  constexpr Error& value() & { return value_; }
  constexpr const Error& value() const& { return value_; }
  constexpr Error&& value() && { return std::move(value_); }

 private:
  template <typename, typename>
  friend class result;

  Error value_;
};

template <typename Value>
class success {
 public:
  using __allow_ctad = void;

  constexpr explicit success(Value value) : value_(std::move(value)) {}

  constexpr Value& value() & { return value_; }
  constexpr const Value& value() const& { return value_; }
  constexpr Value&& value() && { return std::move(value_); }

 private:
  template <typename, typename>
  friend class result;

  Value value_;
};

template <>
class success<void> {
 public:
  using __allow_ctad = void;
};

constexpr success<void> ok() { return success<void>{}; }

template <typename Value>
constexpr success<std::decay_t<Value>> ok(Value&& value) {
  return success<std::decay_t<Value>>(std::forward<Value>(value));
}

template <typename Error, typename Value = void>
class result;

template <typename Error, typename Value>
class [[nodiscard]] result {
 public:
  using value_type = Value;

  constexpr result(success<Value> success) : storage_(std::move(success.value_)) {}

  constexpr result(error<Error> failure) : storage_(std::move(failure.value_)) {}

  template <typename E = Error, typename = std::enable_if_t<std::is_same_v<E, failed>>>
  constexpr result(failed failure) : storage_(failure) {}

  constexpr bool is_ok() const { return std::holds_alternative<Value>(storage_); }
  constexpr bool is_error() const { return !is_ok(); }

  constexpr Value& value() & { return std::get<Value>(storage_); }
  constexpr const Value& value() const& { return std::get<Value>(storage_); }
  constexpr Value&& value() && { return std::move(std::get<Value>(storage_)); }

  constexpr Value& operator*() & { return value(); }
  constexpr const Value& operator*() const& { return value(); }
  constexpr Value&& operator*() && { return std::move(value()); }

  constexpr Value* operator->() { return &value(); }
  constexpr const Value* operator->() const { return &value(); }

  constexpr Error& error_value() & { return std::get<Error>(storage_); }
  constexpr const Error& error_value() const& { return std::get<Error>(storage_); }

  constexpr error<Error> take_error() {
    return error<Error>(std::move(std::get<Error>(storage_)));
  }

 private:
  std::variant<Value, Error> storage_;
};

template <typename Error>
class [[nodiscard]] result<Error, void> {
 public:
  using value_type = void;

  constexpr result() = default;

  constexpr result(success<void>) {}

  constexpr result(error<Error> failure) : error_(std::move(failure.value_)) {}

  template <typename E = Error, typename = std::enable_if_t<std::is_same_v<E, failed>>>
  constexpr result(failed failure) : error_(failure) {}

  constexpr bool is_ok() const { return !error_.has_value(); }
  constexpr bool is_error() const { return error_.has_value(); }

  constexpr Error& error_value() & { return *error_; }
  constexpr const Error& error_value() const& { return *error_; }

  constexpr error<Error> take_error() { return error<Error>(std::move(*error_)); }

 private:
  std::optional<Error> error_;
};

}  // namespace fit

#endif  // LIB_FIT_RESULT_H_
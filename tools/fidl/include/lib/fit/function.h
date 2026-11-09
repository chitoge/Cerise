#ifndef LIB_FIT_FUNCTION_H_
#define LIB_FIT_FUNCTION_H_

#include <cstddef>
#include <memory>
#include <type_traits>
#include <utility>

namespace fit {

template <typename Signature>
class function;

template <typename Result, typename... Args>
class function<Result(Args...)> {
 public:
	function() = default;
	function(std::nullptr_t) {}

	function(function&&) noexcept = default;
	function& operator=(function&&) noexcept = default;

	function(const function&) = delete;
	function& operator=(const function&) = delete;

	template <typename Callable,
						typename = std::enable_if_t<!std::is_same_v<std::decay_t<Callable>, function>>>
	function(Callable&& callable)
			: target_(std::make_unique<model<std::decay_t<Callable>>>(std::forward<Callable>(callable))) {}

	template <typename Callable,
						typename = std::enable_if_t<!std::is_same_v<std::decay_t<Callable>, function>>>
	function& operator=(Callable&& callable) {
		target_ = std::make_unique<model<std::decay_t<Callable>>>(std::forward<Callable>(callable));
		return *this;
	}

	function& operator=(std::nullptr_t) {
		target_.reset();
		return *this;
	}

	explicit operator bool() const noexcept { return static_cast<bool>(target_); }

	bool operator==(std::nullptr_t) const noexcept { return !target_; }
	bool operator!=(std::nullptr_t) const noexcept { return static_cast<bool>(target_); }

	Result operator()(Args... args) const {
		return target_->invoke(std::forward<Args>(args)...);
	}

 private:
	struct base {
		virtual ~base() = default;
		virtual Result invoke(Args... args) const = 0;
	};

	template <typename Callable>
	struct model final : base {
		template <typename OtherCallable>
		explicit model(OtherCallable&& callable_in) : callable(std::forward<OtherCallable>(callable_in)) {}

		Result invoke(Args... args) const override {
			if constexpr (std::is_void_v<Result>) {
				callable(std::forward<Args>(args)...);
			} else {
				return callable(std::forward<Args>(args)...);
			}
		}

		mutable Callable callable;
	};

	std::unique_ptr<base> target_;
};

using closure = function<void()>;

template <typename Signature, size_t inline_target_size = 2 * sizeof(void*)>
using inline_function = function<Signature>;

}  // namespace fit

#endif  // LIB_FIT_FUNCTION_H_
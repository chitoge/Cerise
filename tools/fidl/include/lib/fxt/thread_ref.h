#ifndef LIB_FXT_THREAD_REF_H_
#define LIB_FXT_THREAD_REF_H_

#include <stdint.h>

#include <lib/fxt/string_ref.h>

namespace fxt {

template <RefType>
class ThreadRef;

template <>
class ThreadRef<RefType::kId> {
 public:
  constexpr ThreadRef() = default;
  constexpr explicit ThreadRef(uint16_t id) : id_(id) {}

  constexpr uint16_t id() const { return id_; }
  constexpr uint64_t HeaderEntry() const { return id_; }

 private:
  uint16_t id_ = InternedString::kInvalidId;
};

template <>
class ThreadRef<RefType::kInline> {
 public:
  struct KoidRef {
    uint64_t koid = 0;
  };

  constexpr ThreadRef() = default;
  template <typename ProcessKoid, typename ThreadKoid>
  constexpr ThreadRef(ProcessKoid process_koid, ThreadKoid thread_koid)
      : process_koid_(static_cast<uint64_t>(process_koid)),
        thread_koid_(static_cast<uint64_t>(thread_koid)) {}

  constexpr uint64_t process_koid() const { return process_koid_; }
  constexpr uint64_t thread_koid() const { return thread_koid_; }
  constexpr KoidRef process() const { return {process_koid_}; }
  constexpr KoidRef thread() const { return {thread_koid_}; }
  constexpr uint64_t HeaderEntry() const { return 0; }

 private:
  uint64_t process_koid_ = 0;
  uint64_t thread_koid_ = 0;
};

template <typename ProcessKoid, typename ThreadKoid>
ThreadRef(ProcessKoid, ThreadKoid) -> ThreadRef<RefType::kInline>;

}  // namespace fxt

#endif  // LIB_FXT_THREAD_REF_H_
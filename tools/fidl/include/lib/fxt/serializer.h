#ifndef LIB_FXT_SERIALIZER_H_
#define LIB_FXT_SERIALIZER_H_

#include <lib/fxt/argument.h>
#include <lib/fxt/record_types.h>
#include <lib/fxt/thread_ref.h>

#include <utility>

#include <zircon/errors.h>
#include <zircon/types.h>

namespace fxt {

template <typename Writer, typename... Args>
constexpr zx_status_t WriteMagicNumberRecord(Writer*, Args&&...) {
  return ZX_OK;
}

template <typename Writer, typename... Args>
constexpr zx_status_t WriteInitializationRecord(Writer*, Args&&...) {
  return ZX_OK;
}

template <typename Writer, typename... Args>
constexpr zx_status_t WriteStringRecord(Writer*, Args&&...) {
  return ZX_OK;
}

template <typename Writer, typename... Args>
constexpr zx_status_t WriteKernelObjectRecord(Writer*, Args&&...) {
  return ZX_OK;
}

template <typename Writer, typename... Args>
constexpr zx_status_t WriteInstantEventRecord(Writer*, Args&&...) {
  return ZX_OK;
}

template <typename Writer, typename... Args>
constexpr zx_status_t WriteDurationBeginEventRecord(Writer*, Args&&...) {
  return ZX_OK;
}

template <typename Writer, typename... Args>
constexpr zx_status_t WriteDurationEndEventRecord(Writer*, Args&&...) {
  return ZX_OK;
}

template <typename Writer, typename... Args>
constexpr zx_status_t WriteDurationCompleteEventRecord(Writer*, Args&&...) {
  return ZX_OK;
}

template <typename Writer, typename... Args>
constexpr zx_status_t WriteCounterEventRecord(Writer*, Args&&...) {
  return ZX_OK;
}

template <typename Writer, typename... Args>
constexpr zx_status_t WriteFlowBeginEventRecord(Writer*, Args&&...) {
  return ZX_OK;
}

template <typename Writer, typename... Args>
constexpr zx_status_t WriteFlowStepEventRecord(Writer*, Args&&...) {
  return ZX_OK;
}

template <typename Writer, typename... Args>
constexpr zx_status_t WriteFlowEndEventRecord(Writer*, Args&&...) {
  return ZX_OK;
}

template <typename Writer, typename... Args>
constexpr zx_status_t WriteThreadWakeupRecord(Writer*, Args&&...) {
  return ZX_OK;
}

template <typename Writer, typename... Args>
constexpr zx_status_t WriteContextSwitchRecord(Writer*, Args&&...) {
  return ZX_OK;
}

template <typename Writer, typename... Args>
constexpr zx_status_t WriteLargeBlobRecordWithMetadata(Writer*, Args&&...) {
  return ZX_OK;
}

}  // namespace fxt

#endif  // LIB_FXT_SERIALIZER_H_
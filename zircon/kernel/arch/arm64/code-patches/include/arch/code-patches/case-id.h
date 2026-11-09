// Stub for Cerise build — arm64 not targeted.
#pragma once
#include <stdint.h>
enum class CodePatchId : uint32_t { kSelfTest };
inline constexpr auto WithCodePatchNames = [](auto&& cb) { return cb({}); };

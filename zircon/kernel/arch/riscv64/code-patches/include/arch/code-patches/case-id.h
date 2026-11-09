// Stub for Cerise build — riscv64 not targeted.
#pragma once
#include <stdint.h>
enum class CodePatchId : uint32_t { kSelfTest };
inline constexpr auto WithCodePatchNames = [](auto&& cb) { return cb({}); };

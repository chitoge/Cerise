// Copyright 2026 The Fuchsia Authors
//
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT

#include "hardware_breakpoint.h"

#include <zircon/errors.h>

#include <arch/hypervisor.h>

namespace {

constexpr uint32_t kPrimaryMovDrExiting = uint32_t{1} << 23;
constexpr uint32_t kEntryLoadDebugControls = uint32_t{1} << 2;
constexpr uint32_t kExitSaveDebugControls = uint32_t{1} << 2;
constexpr uint64_t kDr6BreakpointMask = 0xf;
constexpr uint64_t kDr6ReservedOnes = 0xffff0ff0;
constexpr uint64_t kDr6Writable = 0xe00f;
constexpr uint64_t kDr7Writable = 0xffff27ff;

bool Flexible(uint64_t capability, uint32_t bit) {
  const uint32_t must_be_one = static_cast<uint32_t>(capability);
  const uint32_t may_be_one = static_cast<uint32_t>(capability >> 32);
  return (may_be_one & bit) != 0 && (must_be_one & bit) == 0;
}

uint64_t RequestEnd(const HardwareBreakpointController::Request& request) {
  return request.address + static_cast<uint8_t>(request.length);
}

uint64_t NormalizeGuestDr7(uint64_t value) {
  // Bits 11:12, 14:15, and 63:32 read as zero; bit 10 reads as one.
  // GD, LE/GE, every enable, and every RW/LEN field remain guest-owned.
  return (value & kDr7Writable) | (uint64_t{1} << 10);
}

}  // namespace

bool HardwareBreakpointController::RuntimeSupported(uint64_t true_primary_controls,
                                                    uint64_t true_entry_controls,
                                                    uint64_t true_exit_controls) {
  return Flexible(true_primary_controls, kPrimaryMovDrExiting) &&
         (static_cast<uint32_t>(true_entry_controls >> 32) & kEntryLoadDebugControls) != 0 &&
         (static_cast<uint32_t>(true_exit_controls >> 32) & kExitSaveDebugControls) != 0;
}

zx::result<uint8_t> HardwareBreakpointController::EncodeLength(Length length) {
  switch (length) {
    case Length::k1:
      return zx::ok(uint8_t{0});
    case Length::k2:
      return zx::ok(uint8_t{1});
    case Length::k4:
      return zx::ok(uint8_t{3});
    case Length::k8:
      return zx::ok(uint8_t{2});
  }
  return zx::error(ZX_ERR_INVALID_ARGS);
}

bool HardwareBreakpointController::IsCanonical(uint64_t address,
                                               uint8_t linear_address_width) {
  if (linear_address_width != 48 && linear_address_width != 57) {
    return false;
  }
  const uint8_t high_width = 64 - linear_address_width;
  const uint64_t high = address >> linear_address_width;
  const bool sign = (address & (uint64_t{1} << (linear_address_width - 1))) != 0;
  const uint64_t high_ones = (uint64_t{1} << high_width) - 1;
  return high == (sign ? high_ones : 0);
}

bool HardwareBreakpointController::IsSlotEnabled(uint64_t dr7, uint32_t slot) {
  return (dr7 & SlotEnableMask(slot)) != 0;
}

uint64_t HardwareBreakpointController::SlotEnableMask(uint32_t slot) {
  return uint64_t{3} << (slot * 2);
}

uint64_t HardwareBreakpointController::SlotControlMask(uint32_t slot) {
  return uint64_t{0xf} << (16 + slot * 4);
}

void HardwareBreakpointController::Clear() {
  for (uint32_t i = 0; i < kSlotCount; ++i) {
    requests_[i] = {};
    request_to_slot_[i] = kNoRequest;
    slot_to_request_[i] = kNoRequest;
  }
  request_count_ = 0;
  armed_ = false;
}

void HardwareBreakpointController::Disarm() { Clear(); }

bool HardwareBreakpointController::AssignSlots(uint64_t guest_dr7) {
  for (uint32_t i = 0; i < kSlotCount; ++i) {
    request_to_slot_[i] = kNoRequest;
    slot_to_request_[i] = kNoRequest;
  }
  uint32_t next_request = 0;
  for (uint32_t slot = 0; slot < kSlotCount && next_request < request_count_; ++slot) {
    if (!IsSlotEnabled(guest_dr7, slot)) {
      request_to_slot_[next_request] = static_cast<uint8_t>(slot);
      slot_to_request_[slot] = static_cast<uint8_t>(next_request);
      ++next_request;
    }
  }
  return next_request == request_count_;
}

zx::result<> HardwareBreakpointController::Arm(const Request* requests,
                                               uint32_t request_count,
                                               const GuestState& guest) {
  if (requests == nullptr || request_count == 0 || request_count > kSlotCount) {
    return zx::error(ZX_ERR_INVALID_ARGS);
  }

  HardwareBreakpointController replacement;
  replacement.request_count_ = request_count;
  for (uint32_t i = 0; i < request_count; ++i) {
    const Request& request = requests[i];
    auto length_encoding = EncodeLength(request.length);
    if (length_encoding.is_error() ||
        !IsCanonical(request.address, guest.linear_address_width) ||
        request.condition_index >= 64) {
      return zx::error(ZX_ERR_INVALID_ARGS);
    }
    const uint64_t length = static_cast<uint8_t>(request.length);
    if (request.address > UINT64_MAX - length ||
        (request.access == Access::kExecute && request.length != Length::k1) ||
        (request.access != Access::kExecute && request.access != Access::kWrite &&
         request.access != Access::kReadWrite) ||
        (request.address & (length - 1)) != 0) {
      return zx::error(ZX_ERR_INVALID_ARGS);
    }
    for (uint32_t prior = 0; prior < i; ++prior) {
      if (request.address < RequestEnd(replacement.requests_[prior]) &&
          replacement.requests_[prior].address < RequestEnd(request)) {
        return zx::error(ZX_ERR_ALREADY_EXISTS);
      }
    }
    replacement.requests_[i] = request;
  }
  if (!replacement.AssignSlots(guest.dr7)) {
    return zx::error(ZX_ERR_NO_RESOURCES);
  }
  replacement.armed_ = true;
  *this = replacement;
  return zx::ok();
}

uint8_t HardwareBreakpointController::owned_slot_mask() const {
  uint8_t mask = 0;
  for (uint32_t slot = 0; slot < kSlotCount; ++slot) {
    if (slot_to_request_[slot] != kNoRequest) {
      mask |= static_cast<uint8_t>(1u << slot);
    }
  }
  return mask;
}

HardwareBreakpointController::PhysicalState
HardwareBreakpointController::BuildPhysicalState(const GuestState& guest) const {
  PhysicalState physical = {};
  physical.dr7 = guest.dr7;
  for (uint32_t slot = 0; slot < kSlotCount; ++slot) {
    physical.address[slot] = guest.address[slot];
    const uint8_t request_index = slot_to_request_[slot];
    if (!armed_ || request_index == kNoRequest) {
      continue;
    }
    const Request& request = requests_[request_index];
    const uint8_t length = EncodeLength(request.length).value();
    physical.address[slot] = request.address;
    physical.owned_slot_mask |= static_cast<uint8_t>(1u << slot);
    physical.dr7 &= ~SlotEnableMask(slot);
    physical.dr7 &= ~SlotControlMask(slot);
    // Local enable only. Global enable would unnecessarily survive task
    // switches inside a guest if a future adapter stopped intercepting MOV-DR.
    physical.dr7 |= uint64_t{1} << (slot * 2);
    physical.dr7 |= static_cast<uint64_t>(request.access) << (16 + slot * 4);
    physical.dr7 |= static_cast<uint64_t>(length) << (18 + slot * 4);
  }
  return physical;
}

zx::result<> HardwareBreakpointController::WriteGuestAddress(uint32_t slot, uint64_t value,
                                                             GuestState& guest) const {
  if (slot >= kSlotCount) {
    return zx::error(ZX_ERR_INVALID_ARGS);
  }
  guest.address[slot] = value;
  return zx::ok();
}

void HardwareBreakpointController::WriteGuestDr6(uint64_t value, GuestState& guest) const {
  guest.dr6 = (value & kDr6Writable) | kDr6ReservedOnes;
}

HardwareBreakpointController::GuestDr7WriteResult
HardwareBreakpointController::WriteGuestDr7(uint64_t value, GuestState& guest) {
  guest.dr7 = NormalizeGuestDr7(value);
  if (!armed_) {
    return GuestDr7WriteResult::kApplied;
  }
  if (AssignSlots(guest.dr7)) {
    return GuestDr7WriteResult::kApplied;
  }
  Clear();
  return GuestDr7WriteResult::kControlLost;
}

uint64_t HardwareBreakpointController::ReadGuestAddress(uint32_t slot,
                                                        const GuestState& guest) const {
  return slot < kSlotCount ? guest.address[slot] : 0;
}

bool HardwareBreakpointController::ClassifyDebugExit(uint64_t raw_dr6, uint64_t rip,
                                                      uint16_t vpid, Stop& out) {
  if (!armed_) {
    return false;
  }
  const uint8_t slots =
      static_cast<uint8_t>(raw_dr6 & kDr6BreakpointMask) & owned_slot_mask();
  if (slots == 0) {
    return false;
  }

  out = {};
  out.rip = rip;
  out.raw_dr6 = raw_dr6;
  out.guest_dr6 = raw_dr6 & ~static_cast<uint64_t>(slots);
  out.vpid = vpid;
  out.slot_mask = slots;
  bool pre_instruction = false;
  bool post_access = false;
  for (uint32_t slot = 0; slot < kSlotCount; ++slot) {
    if ((slots & (uint8_t{1} << slot)) == 0) {
      continue;
    }
    const uint8_t request_index = slot_to_request_[slot];
    if (request_index == kNoRequest) {
      continue;
    }
    const Request& request = requests_[request_index];
    out.condition_mask |= uint64_t{1} << request.condition_index;
    pre_instruction |= request.access == Access::kExecute;
    post_access |= request.access != Access::kExecute;
  }
  out.boundary = pre_instruction && post_access
                     ? Boundary::kMixed
                     : (post_access ? Boundary::kPostAccess : Boundary::kPreInstruction);
  armed_ = false;
  return true;
}

zx::result<> HardwareBreakpointSession::Replace(
    uint64_t ack_sequence, const Request* requests, uint32_t request_count,
    const GuestState& guest) {
  if (pending_) {
    if (ack_sequence != pending_stop_.sequence) {
      return zx::error(ZX_ERR_BAD_STATE);
    }
  } else if (ack_sequence != 0) {
    return zx::error(ZX_ERR_NOT_FOUND);
  }

  HardwareBreakpointController replacement;
  if (request_count == 0) {
    if (requests != nullptr) {
      return zx::error(ZX_ERR_INVALID_ARGS);
    }
  } else {
    if (auto result = replacement.Arm(requests, request_count, guest);
        result.is_error()) {
      return result.take_error();
    }
  }

  controller_ = replacement;
  pending_stop_ = {};
  pending_ = false;
  return zx::ok();
}

bool HardwareBreakpointSession::MaybeLatchDebugExit(uint64_t raw_dr6, uint64_t rip,
                                                    uint16_t vpid,
                                                    PendingStop& out) {
  if (pending_) {
    out = pending_stop_;
    return true;
  }

  Stop stop = {};
  if (!controller_.ClassifyDebugExit(raw_dr6, rip, vpid, stop)) {
    return false;
  }
  pending_stop_.sequence = next_sequence_++;
  if (next_sequence_ == 0) {
    next_sequence_ = 1;
  }
  pending_stop_.stop = stop;
  pending_ = true;
  out = pending_stop_;
  return true;
}

void HardwareBreakpointSession::Reset() {
  controller_.Disarm();
  pending_stop_ = {};
  pending_ = false;
}

bool Guest::ClaimHardwareBreakpointStop(uint16_t vpid) {
  uint16_t expected = 0;
  return hardware_breakpoint_trigger_vpid_.compare_exchange_strong(
      expected, vpid, ktl::memory_order_acq_rel, ktl::memory_order_acquire);
}

void Guest::ReleaseHardwareBreakpointStop(uint16_t vpid) {
  uint16_t expected = vpid;
  const bool released =
      hardware_breakpoint_trigger_vpid_.compare_exchange_strong(
          expected, 0, ktl::memory_order_acq_rel, ktl::memory_order_acquire);
  DEBUG_ASSERT(released);
}

void Guest::QuiesceHardwareBreakpointStop(Vcpu& trigger) {
  if (IsHardwareBreakpointTrigger(trigger.vpid_)) {
    QuiesceVcpus(&trigger);
  }
}

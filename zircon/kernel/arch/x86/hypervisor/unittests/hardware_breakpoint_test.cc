// Copyright 2026 The Fuchsia Authors
//
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT

#include "hardware_breakpoint.h"

#include <lib/unittest/unittest.h>

namespace {

using Access = HardwareBreakpointController::Access;
using Length = HardwareBreakpointController::Length;
using Request = HardwareBreakpointController::Request;

bool hardware_breakpoint_encodes_all_accesses_and_lengths() {
  BEGIN_TEST;

  HardwareBreakpointController controller;
  HardwareBreakpointController::GuestState guest = {};
  const Request requests[] = {
      {.address = 0x1000, .access = Access::kExecute, .length = Length::k1, .condition_index = 1},
      {.address = 0x2000, .access = Access::kWrite, .length = Length::k2, .condition_index = 2},
      {.address = 0x3000, .access = Access::kReadWrite, .length = Length::k4,
       .condition_index = 3},
      {.address = 0x4000, .access = Access::kWrite, .length = Length::k8, .condition_index = 4},
  };
  ASSERT_OK(controller.Arm(requests, 4, guest).status_value(), "arm all four encodings");
  const auto physical = controller.BuildPhysicalState(guest);
  EXPECT_EQ(0xf, physical.owned_slot_mask, "all slots owned");
  EXPECT_EQ(0x1000, physical.address[0], "DR0");
  EXPECT_EQ(0x2000, physical.address[1], "DR1");
  EXPECT_EQ(0x3000, physical.address[2], "DR2");
  EXPECT_EQ(0x4000, physical.address[3], "DR3");
  // RW/LEN: exec/1=0000, write/2=0101, rw/4=1111, write/8=1001.
  EXPECT_EQ(0u, (physical.dr7 >> 16) & 0xf, "execute/1 encoding");
  EXPECT_EQ(0x5u, (physical.dr7 >> 20) & 0xf, "write/2 encoding");
  EXPECT_EQ(0xfu, (physical.dr7 >> 24) & 0xf, "read-write/4 encoding");
  EXPECT_EQ(0x9u, (physical.dr7 >> 28) & 0xf, "write/8 encoding");

  struct DataEncoding {
    Access access;
    Length length;
    uint8_t expected;
  };
  const DataEncoding encodings[] = {
      {Access::kWrite, Length::k1, 0x1},     {Access::kWrite, Length::k2, 0x5},
      {Access::kWrite, Length::k4, 0xd},     {Access::kWrite, Length::k8, 0x9},
      {Access::kReadWrite, Length::k1, 0x3}, {Access::kReadWrite, Length::k2, 0x7},
      {Access::kReadWrite, Length::k4, 0xf}, {Access::kReadWrite, Length::k8, 0xb},
  };
  for (const auto& encoding : encodings) {
    controller.Disarm();
    const Request request = {
        .address = 0x8000,
        .access = encoding.access,
        .length = encoding.length,
        .condition_index = 0,
    };
    ASSERT_OK(controller.Arm(&request, 1, guest).status_value(), "arm data encoding");
    EXPECT_EQ(encoding.expected, (controller.BuildPhysicalState(guest).dr7 >> 16) & 0xf,
              "exact RW/LEN encoding");
  }

  END_TEST;
}

bool hardware_breakpoint_runtime_support_fails_closed() {
  BEGIN_TEST;

  constexpr uint64_t kMovDr = uint64_t{1} << (32 + 23);
  constexpr uint64_t kLoadDebug = uint64_t{1} << (32 + 2);
  constexpr uint64_t kSaveDebug = uint64_t{1} << (32 + 2);
  EXPECT_TRUE(HardwareBreakpointController::RuntimeSupported(kMovDr, kLoadDebug, kSaveDebug),
              "complete flexible VMX support");
  EXPECT_FALSE(HardwareBreakpointController::RuntimeSupported(0, kLoadDebug, kSaveDebug),
               "missing MOV-DR exiting");
  EXPECT_FALSE(HardwareBreakpointController::RuntimeSupported(kMovDr, 0, kSaveDebug),
               "missing guest DR7 load");
  EXPECT_FALSE(HardwareBreakpointController::RuntimeSupported(kMovDr, kLoadDebug, 0),
               "missing guest DR7 save");
  // A must-be-one MOV-DR control cannot provide the promised zero-exit unarmed
  // path, even though the bit is also present in allowed-one.
  EXPECT_FALSE(HardwareBreakpointController::RuntimeSupported(
                   kMovDr | (uint64_t{1} << 23), kLoadDebug, kSaveDebug),
               "non-clearable MOV-DR exiting fails closed");

  END_TEST;
}

bool hardware_breakpoint_preserves_guest_slots_and_remaps_or_cancels() {
  BEGIN_TEST;

  HardwareBreakpointController controller;
  HardwareBreakpointController::GuestState guest = {};
  guest.address[0] = 0xaaaa;
  guest.address[2] = 0xcccc;
  guest.dr7 = (uint64_t{1} << 0) | (uint64_t{1} << 4);
  const Request requests[] = {
      {.address = 0x2000, .access = Access::kWrite, .length = Length::k1, .condition_index = 6},
      {.address = 0x3000, .access = Access::kExecute, .length = Length::k1, .condition_index = 7},
  };
  ASSERT_OK(controller.Arm(requests, 2, guest).status_value(), "use only free guest slots");
  auto physical = controller.BuildPhysicalState(guest);
  EXPECT_EQ(0xau, physical.owned_slot_mask, "host uses DR1 and DR3");
  EXPECT_EQ(0xaaaa, physical.address[0], "guest DR0 preserved");
  EXPECT_EQ(0xcccc, physical.address[2], "guest DR2 preserved");

  // Guest releases DR0 and claims DR1; first-free placement remaps the host
  // controls to DR0 and DR2.
  guest.dr7 = 0;
  EXPECT_EQ(HardwareBreakpointController::GuestDr7WriteResult::kApplied,
            controller.WriteGuestDr7(uint64_t{1} << 2, guest), "transparent remap");
  physical = controller.BuildPhysicalState(guest);
  EXPECT_EQ(0x5u, physical.owned_slot_mask, "remapped around guest DR1");
  EXPECT_EQ((uint64_t{1} << 10) | (uint64_t{1} << 2),
            controller.ReadGuestDr7(guest),
            "guest sees its exact writable bits plus architectural bit 10");

  // Three guest-owned slots leave no complete placement for two controls.
  EXPECT_EQ(HardwareBreakpointController::GuestDr7WriteResult::kControlLost,
            controller.WriteGuestDr7((uint64_t{1} << 0) | (uint64_t{1} << 2) |
                                         (uint64_t{1} << 4),
                                     guest),
            "cancel instead of confiscating a guest slot");
  EXPECT_FALSE(controller.armed(), "control canceled");
  EXPECT_EQ((uint64_t{1} << 10) | (uint64_t{1} << 0) |
                (uint64_t{1} << 2) | (uint64_t{1} << 4),
            guest.dr7,
            "guest writable bits survive cancellation with architectural normalization");

  END_TEST;
}

bool hardware_breakpoint_validation_is_atomic() {
  BEGIN_TEST;

  HardwareBreakpointController controller;
  HardwareBreakpointController::GuestState guest = {};
  const Request valid = {
      .address = 0x5000, .access = Access::kWrite, .length = Length::k4, .condition_index = 9};
  ASSERT_OK(controller.Arm(&valid, 1, guest).status_value(), "baseline arm");
  const auto baseline = controller.BuildPhysicalState(guest);

  const Request overlap[] = {
      {.address = 0x6000, .access = Access::kWrite, .length = Length::k4, .condition_index = 1},
      {.address = 0x6002, .access = Access::kReadWrite, .length = Length::k2,
       .condition_index = 2},
  };
  EXPECT_EQ(ZX_ERR_ALREADY_EXISTS, controller.Arm(overlap, 2, guest).status_value(),
            "overlap rejected");
  EXPECT_EQ(baseline.address[0], controller.BuildPhysicalState(guest).address[0],
            "failed replace preserves old plan");

  const Request bad_execute = {
      .address = 0x7000, .access = Access::kExecute, .length = Length::k2, .condition_index = 1};
  EXPECT_EQ(ZX_ERR_INVALID_ARGS, controller.Arm(&bad_execute, 1, guest).status_value(),
            "execute length must be one");
  const Request bad_alignment = {
      .address = 0x7001, .access = Access::kWrite, .length = Length::k4, .condition_index = 1};
  EXPECT_EQ(ZX_ERR_INVALID_ARGS, controller.Arm(&bad_alignment, 1, guest).status_value(),
            "misaligned watchpoint rejected");
  const Request noncanonical = {
      .address = 0x0001'0000'0000'0000,
      .access = Access::kWrite,
      .length = Length::k1,
      .condition_index = 1};
  EXPECT_EQ(ZX_ERR_INVALID_ARGS, controller.Arm(&noncanonical, 1, guest).status_value(),
            "noncanonical address rejected");

  guest.linear_address_width = 57;
  const Request la57 = {
      .address = 0x00ff'0000'0000'0000,
      .access = Access::kWrite,
      .length = Length::k1,
      .condition_index = 1};
  ASSERT_OK(controller.Arm(&la57, 1, guest).status_value(),
            "canonical LA57 address accepted");
  guest.linear_address_width = 56;
  EXPECT_EQ(ZX_ERR_INVALID_ARGS, controller.Arm(&valid, 1, guest).status_value(),
            "unknown linear-address width fails closed");

  END_TEST;
}

bool hardware_breakpoint_classifies_truthful_boundaries_and_guest_dr6() {
  BEGIN_TEST;

  HardwareBreakpointController controller;
  HardwareBreakpointController::GuestState guest = {};
  const Request execute = {
      .address = 0x8000, .access = Access::kExecute, .length = Length::k1, .condition_index = 12};
  ASSERT_OK(controller.Arm(&execute, 1, guest).status_value(), "arm execute");
  HardwareBreakpointController::Stop stop = {};
  ASSERT_TRUE(controller.ClassifyDebugExit(0xffff0ff1, 0x8000, 3, stop), "classify execute");
  EXPECT_EQ(0x1u, stop.slot_mask, "slot");
  EXPECT_EQ(uint64_t{1} << 12, stop.condition_mask, "condition");
  EXPECT_EQ(HardwareBreakpointController::Boundary::kPreInstruction, stop.boundary,
            "execute is pre-instruction");
  EXPECT_EQ(0u, stop.guest_dr6 & 1, "host-owned B0 hidden from guest");
  EXPECT_EQ(3u, stop.vpid, "VP");
  EXPECT_FALSE(controller.armed(), "matching #DB consumes the one-shot");

  const Request data = {
      .address = 0x9000, .access = Access::kReadWrite, .length = Length::k8, .condition_index = 13};
  ASSERT_OK(controller.Arm(&data, 1, guest).status_value(), "arm data");
  ASSERT_TRUE(controller.ClassifyDebugExit(0xffff4ff1, 0x9008, 4, stop), "classify data");
  EXPECT_EQ(HardwareBreakpointController::Boundary::kPostAccess, stop.boundary,
            "data watchpoint is post-access");
  EXPECT_NE(0u, stop.guest_dr6 & (uint64_t{1} << 14),
            "coincident guest BS cause preserved");
  EXPECT_EQ(0x9008u, stop.rip, "architectural post-access RIP");

  END_TEST;
}

bool hardware_breakpoint_session_requires_exact_ack_and_cleans_up() {
  BEGIN_TEST;

  HardwareBreakpointSession session;
  HardwareBreakpointController::GuestState guest = {};
  guest.address[0] = 0x1111;
  guest.dr6 = 0xffff4ff0;
  guest.dr7 = uint64_t{1} << 2;
  const auto exact_guest = guest;
  const Request first = {
      .address = 0xa000, .access = Access::kExecute, .length = Length::k1,
      .condition_index = 5};
  ASSERT_OK(session.Replace(0, &first, 1, guest).status_value(), "initial arm");

  HardwareBreakpointSession::PendingStop pending = {};
  ASSERT_TRUE(session.MaybeLatchDebugExit(0xffff0ff1, 0xa000, 2, pending),
              "latch the first stop");
  ASSERT_NE(0u, pending.sequence, "nonzero sequence");
  EXPECT_TRUE(session.pending(), "pending stop is latched");
  EXPECT_FALSE(session.armed(), "one-shot is inactive while pending");

  HardwareBreakpointSession::PendingStop peer = {};
  ASSERT_TRUE(session.MaybeLatchDebugExit(0xffff0ff2, 0xb000, 3, peer),
              "peer observes pending state");
  EXPECT_EQ(pending.sequence, peer.sequence, "peer cannot publish a duplicate");
  EXPECT_EQ(pending.stop.rip, peer.stop.rip, "first trigger remains immutable");
  EXPECT_EQ(pending.stop.vpid, peer.stop.vpid, "first VP remains immutable");

  const Request replacement = {
      .address = 0xb000, .access = Access::kWrite, .length = Length::k4,
      .condition_index = 6};
  EXPECT_EQ(ZX_ERR_BAD_STATE,
            session.Replace(pending.sequence + 1, &replacement, 1, guest).status_value(),
            "wrong pending acknowledgement rejected");
  EXPECT_TRUE(session.pending(), "failed acknowledgement preserves stop");
  EXPECT_EQ(ZX_ERR_BAD_STATE, session.Replace(0, nullptr, 0, guest).status_value(),
            "pending stop cannot be canceled without acknowledgement");
  ASSERT_OK(session.Replace(pending.sequence, &replacement, 1, guest).status_value(),
            "exact acknowledgement rearms atomically");
  EXPECT_FALSE(session.pending(), "stop consumed");
  EXPECT_TRUE(session.armed(), "replacement armed");
  EXPECT_EQ(ZX_ERR_NOT_FOUND,
            session.Replace(pending.sequence, nullptr, 0, guest).status_value(),
            "stale acknowledgement cannot cancel replacement");
  EXPECT_TRUE(session.armed(), "stale acknowledgement changes nothing");

  session.Reset();
  EXPECT_FALSE(session.pending(), "cleanup clears pending stop");
  EXPECT_FALSE(session.armed(), "cleanup disarms physical controls");
  EXPECT_EQ(exact_guest.address[0], guest.address[0], "guest DR0 unchanged by lifecycle");
  EXPECT_EQ(exact_guest.dr6, guest.dr6, "guest DR6 unchanged by lifecycle");
  EXPECT_EQ(exact_guest.dr7, guest.dr7, "guest DR7 unchanged by lifecycle");

  ASSERT_OK(session.Replace(0, &first, 1, guest).status_value(), "arm after cleanup");
  ASSERT_TRUE(session.MaybeLatchDebugExit(0xffff0ff1, 0xa000, 2, peer),
              "latch after cleanup");
  EXPECT_NE(pending.sequence, peer.sequence, "cleanup does not recycle sequence");

  END_TEST;
}

UNITTEST_START_TESTCASE(hardware_breakpoint_tests)
UNITTEST("hardware breakpoint runtime support fails closed",
         hardware_breakpoint_runtime_support_fails_closed)
UNITTEST("hardware breakpoint encodes all access/length combinations",
         hardware_breakpoint_encodes_all_accesses_and_lengths)
UNITTEST("hardware breakpoint preserves guest slots and remaps or cancels",
         hardware_breakpoint_preserves_guest_slots_and_remaps_or_cancels)
UNITTEST("hardware breakpoint validation is atomic",
         hardware_breakpoint_validation_is_atomic)
UNITTEST("hardware breakpoint names pre-instruction and post-access boundaries truthfully",
         hardware_breakpoint_classifies_truthful_boundaries_and_guest_dr6)
UNITTEST("hardware breakpoint session requires exact acknowledgement and cleanup",
         hardware_breakpoint_session_requires_exact_ack_and_cleans_up)
UNITTEST_END_TESTCASE(hardware_breakpoint_tests, "hardware_breakpoint", "Hardware breakpoint policy")

}  // namespace

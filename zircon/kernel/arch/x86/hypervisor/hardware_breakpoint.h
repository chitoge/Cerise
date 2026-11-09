// Copyright 2026 The Fuchsia Authors
//
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT

#ifndef ZIRCON_KERNEL_ARCH_X86_HYPERVISOR_HARDWARE_BREAKPOINT_H_
#define ZIRCON_KERNEL_ARCH_X86_HYPERVISOR_HARDWARE_BREAKPOINT_H_

#include <lib/zx/result.h>
#include <stdint.h>

// Fixed-state policy and encoding for a host-owned subset of DR0-DR3.
//
// This class deliberately does not touch the VMCS or physical debug registers.
// It is the allocation/virtualization core used by the VCPU entry/exit adapter:
// guest-visible state goes in, a merged physical state comes out, and a #DB is
// classified without allocating or consulting guest page tables.
class HardwareBreakpointController {
 public:
  static constexpr uint32_t kSlotCount = 4;
  static constexpr uint8_t kNoRequest = 0xff;

  enum class Access : uint8_t {
    // Architectural instruction breakpoint: #DB is a fault before execution.
    kExecute = 0,
    // Architectural data watchpoint: #DB is a trap after the access.
    kWrite = 1,
    kReadWrite = 3,
  };

  enum class Length : uint8_t {
    k1 = 1,
    k2 = 2,
    k4 = 4,
    k8 = 8,
  };

  struct Request {
    uint64_t address = 0;
    Access access = Access::kExecute;
    Length length = Length::k1;
    // Index in the caller's bounded RunUntil OR-set.
    uint32_t condition_index = 0;
  };

  // The complete guest-visible debug-register file. Even when a physical slot
  // is host-owned, MOV-DR reads and writes operate on this state.
  struct GuestState {
    uint64_t address[kSlotCount] = {};
    uint64_t dr6 = 0xffff0ff0;
    uint64_t dr7 = 0x400;
    // Architectural linear-address width currently exposed to the guest.
    // The ABI supports the x86-64 paging widths, including LA57 where present.
    uint8_t linear_address_width = 48;
  };

  // State to install only while entering the guest. GuestState is never
  // overwritten with these host-owned addresses or DR7 encodings.
  struct PhysicalState {
    uint64_t address[kSlotCount] = {};
    uint64_t dr7 = 0;
    uint8_t owned_slot_mask = 0;
  };

  enum class Boundary : uint8_t {
    kPreInstruction = 1,
    kPostAccess = 2,
    // Defensive representation for a raw DR6 that reports owned execute and
    // data slots together. Hardware normally reports those at different
    // architectural boundaries, so silently choosing either would be false.
    kMixed = 3,
  };

  struct Stop {
    uint64_t condition_mask = 0;
    uint64_t rip = 0;
    uint64_t raw_dr6 = 0;
    uint64_t guest_dr6 = 0;
    uint16_t vpid = 0;
    uint8_t slot_mask = 0;
    Boundary boundary = Boundary::kPreInstruction;
  };

  enum class GuestDr7WriteResult : uint8_t {
    // Every host request was transparently remapped around the guest's enabled
    // slots.
    kApplied = 0,
    // The guest now owns too many slots. Its write is still applied exactly,
    // while the host control is canceled rather than confiscating a slot.
    kControlLost = 1,
  };

  // MOV-DR exiting must be both settable and clearable so an unarmed VCPU does
  // not inherit exits. VM entry/exit must also load/save guest DR7.
  static bool RuntimeSupported(uint64_t true_primary_controls,
                               uint64_t true_entry_controls,
                               uint64_t true_exit_controls);

  // Validates and atomically replaces the complete request set. Overlapping
  // ranges and requests that cannot fit around the guest's enabled slots fail
  // without changing the existing controller.
  zx::result<> Arm(const Request* requests, uint32_t request_count,
                   const GuestState& guest);
  void Disarm();

  bool armed() const { return armed_; }
  uint32_t request_count() const { return request_count_; }
  const Request& request(uint32_t index) const { return requests_[index]; }
  uint8_t owned_slot_mask() const;

  PhysicalState BuildPhysicalState(const GuestState& guest) const;

  // MOV to DR0-DR3 and DR6 update only guest-visible state. MOV to DR7 may
  // remap owned physical slots; if no complete remap exists it cancels the
  // control but preserves the guest's exact requested value.
  zx::result<> WriteGuestAddress(uint32_t slot, uint64_t value, GuestState& guest) const;
  void WriteGuestDr6(uint64_t value, GuestState& guest) const;
  GuestDr7WriteResult WriteGuestDr7(uint64_t value, GuestState& guest);

  uint64_t ReadGuestAddress(uint32_t slot, const GuestState& guest) const;
  uint64_t ReadGuestDr6(const GuestState& guest) const { return guest.dr6; }
  uint64_t ReadGuestDr7(const GuestState& guest) const { return guest.dr7; }

  // Returns true only when DR6 names at least one host-owned slot. Owned B0-B3
  // bits are removed from the guest-visible DR6; all coincident guest #DB
  // causes remain for later delivery to the guest.
  // A matching result consumes the one-shot. The request-to-slot mapping stays
  // available in |out|, but BuildPhysicalState immediately falls back to the
  // unmodified guest state until an exact acknowledgement installs a new set.
  bool ClassifyDebugExit(uint64_t raw_dr6, uint64_t rip, uint16_t vpid, Stop& out);

 private:
  static zx::result<uint8_t> EncodeLength(Length length);
  static bool IsCanonical(uint64_t address, uint8_t linear_address_width);
  static bool IsSlotEnabled(uint64_t dr7, uint32_t slot);
  static uint64_t SlotEnableMask(uint32_t slot);
  static uint64_t SlotControlMask(uint32_t slot);

  bool AssignSlots(uint64_t guest_dr7);
  void Clear();

  Request requests_[kSlotCount] = {};
  uint8_t request_to_slot_[kSlotCount] = {kNoRequest, kNoRequest, kNoRequest, kNoRequest};
  uint8_t slot_to_request_[kSlotCount] = {kNoRequest, kNoRequest, kNoRequest, kNoRequest};
  uint32_t request_count_ = 0;
  bool armed_ = false;
};

// Exact stop/ack lifecycle kept outside HardwareBreakpointController so the
// VM-entry adapter can quiesce all VPs before publishing the latched result.
// This object has fixed storage and performs no allocation.
class HardwareBreakpointSession {
 public:
  using GuestState = HardwareBreakpointController::GuestState;
  using Request = HardwareBreakpointController::Request;
  using Stop = HardwareBreakpointController::Stop;

  struct PendingStop {
    uint64_t sequence = 0;
    Stop stop = {};
  };

  // Atomically replaces the complete plan. A pending one-shot requires its
  // exact sequence; a nonzero stale acknowledgement is rejected. A null,
  // zero-count replacement is a cancel.
  zx::result<> Replace(uint64_t ack_sequence, const Request* requests,
                       uint32_t request_count, const GuestState& guest);

  // Latches the first matching #DB as a one-shot stop. While one is pending,
  // peers receive the same immutable record and must leave without publishing
  // a duplicate.
  bool MaybeLatchDebugExit(uint64_t raw_dr6, uint64_t rip, uint16_t vpid,
                           PendingStop& out);

  // Restore, VCPU teardown, and terminal-error cleanup all use the same exact
  // path. Sequence numbers stay monotonic so an acknowledgement retained by a
  // client cannot acknowledge a later session accidentally.
  void Reset();

  bool armed() const { return controller_.armed(); }
  bool pending() const { return pending_; }
  const PendingStop& pending_stop() const { return pending_stop_; }
  const HardwareBreakpointController& controller() const { return controller_; }
  HardwareBreakpointController& controller() { return controller_; }

 private:
  HardwareBreakpointController controller_;
  uint64_t next_sequence_ = 1;
  PendingStop pending_stop_ = {};
  bool pending_ = false;
};

#endif  // ZIRCON_KERNEL_ARCH_X86_HYPERVISOR_HARDWARE_BREAKPOINT_H_

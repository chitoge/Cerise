// Copyright 2026 The Cerise Authors
//
// Use of this source code is governed by a MIT-style license that can be found
// in the LICENSE file.

#ifndef ZIRCON_KERNEL_ARCH_X86_HYPERVISOR_INTEL_PT_H_
#define ZIRCON_KERNEL_ARCH_X86_HYPERVISOR_INTEL_PT_H_

#include <lib/zx/result.h>
#include <zircon/syscalls/hypervisor.h>
#include <zircon/syscalls/port.h>

#include <arch/x86/perf_mon.h>
#include <hypervisor/page.h>
#include <ktl/unique_ptr.h>

class AutoVmcs;

enum class IntelPtSwitchingMode : uint8_t {
  // Hardware loads guest IA32_RTIT_CTL on VM entry and clears it on VM exit.
  kDedicatedVmxControls,
  // Hardware loads IA32_RTIT_CTL from the ordinary VM-entry/VM-exit MSR-load
  // lists. This gives older processors the same exact transition boundary
  // without requiring the later dedicated PT controls.
  kVmxMsrLoadLists,
};

// Per-VCPU, complete-or-fail Intel PT state. Every table and output page is
// allocated before the state is published. VM-exit only latches registers and
// rotates fixed records; raw bytes are copied later by ReadControl in syscall
// context.
class IntelPtState {
 public:
  static zx::result<ktl::unique_ptr<IntelPtState>> Create(
      const zx_vcpu_intel_pt_control_t& request, const X86VcpuPtProperties& properties,
      IntelPtSwitchingMode switching_mode);
  static void ReadCapabilities(zx_vcpu_intel_pt_control_t& out,
                               const X86VcpuPtProperties& properties,
                               zx_vcpu_intel_pt_availability_t availability,
                               zx_vcpu_intel_pt_unavailable_reason_t override_reason);
  static zx_vcpu_intel_pt_unavailable_reason_t PublicUnavailableReason(
      X86VcpuPtUnavailableReason reason);

  IntelPtState(const IntelPtState&) = delete;
  IntelPtState& operator=(const IntelPtState&) = delete;
  ~IntelPtState();

  zx::result<> ReadControl(zx_vcpu_intel_pt_control_t& out) const;
  zx::result<> SelectRead(uint64_t generation, uint64_t cursor, uint32_t max_bytes);
  zx::result<> Ack(uint64_t generation, uint64_t through_cursor);
  zx::result<> Stop(uint64_t generation);

  bool MayEnter() const;
  zx::result<> PrepareEntry(AutoVmcs& vmcs);
  void FinishExit(AutoVmcs& vmcs, bool entry_succeeded);

  bool TakePacket(zx_packet_guest_intel_pt_t& packet);
  uint64_t generation() const { return generation_; }

 private:
  static constexpr uint32_t kPairCount = 3;

  enum class PairState : uint8_t {
    kFree,
    kActive,
    kSealed,
  };

  struct Pair {
    hypervisor::Page table;
    PairState state = PairState::kFree;
    uint32_t first_output_page = 0;
    uint32_t main_pages = 0;
    uint32_t guard_page = 0;
    uint64_t rotation_generation = 0;
    uint64_t sequence = 0;
    uint64_t start_cursor = 0;
    uint64_t end_cursor = 0;
    uint64_t main_bytes = 0;
    uint64_t guard_bytes = 0;
    uint64_t hardware_status = 0;
    uint32_t status_flags = 0;
  };

  struct HostState {
    uint64_t control = 0;
    uint64_t status = 0;
    uint64_t output_base = 0;
    uint64_t output_mask_ptrs = 0;
    uint64_t cr3_match = 0;
    uint64_t address_a[ZX_VCPU_INTEL_PT_MAX_ADDRESS_RANGES] = {};
    uint64_t address_b[ZX_VCPU_INTEL_PT_MAX_ADDRESS_RANGES] = {};
    uint32_t entry_controls = 0;
    uint32_t exit_controls = 0;
    uint64_t guest_control = 0;
    uint64_t entry_msr_load_address = 0;
    uint64_t exit_msr_load_address = 0;
    uint32_t entry_msr_load_count = 0;
    uint32_t exit_msr_load_count = 0;
    bool pmi_masked = true;
  };

  IntelPtState() = default;
  zx::result<> Initialize(const zx_vcpu_intel_pt_control_t& request,
                          const X86VcpuPtProperties& properties,
                          IntelPtSwitchingMode switching_mode);
  zx::result<uint32_t> PopulateMsrLoadList(hypervisor::Page& page,
                                          uint64_t source_address, uint32_t source_count,
                                          uint64_t control_value);
  zx::result<> ActivateFreePair();
  void SealActive(uint64_t main_bytes, uint64_t guard_bytes, uint64_t hardware_status,
                  uint32_t status_flags);
  void Fail(uint32_t status_flags);
  void QueuePacket(const Pair* pair, uint32_t status_flags);
  Pair* ActivePair();
  const Pair* SelectedPair() const;
  uint32_t FreePairCount() const;
  void CopyPairBytes(const Pair& pair, uint64_t offset, uint32_t length, uint8_t* out) const;
  static bool DecodeOutputPosition(const Pair& pair, uint64_t output_mask_ptrs,
                                   uint64_t* main_bytes, uint64_t* guard_bytes);

  X86VcpuPtProperties properties_ = {};
  uint64_t config_flags_ = 0;
  uint64_t control_value_ = 0;
  uint64_t cr3_match_ = 0;
  uint64_t address_a_[ZX_VCPU_INTEL_PT_MAX_ADDRESS_RANGES] = {};
  uint64_t address_b_[ZX_VCPU_INTEL_PT_MAX_ADDRESS_RANGES] = {};
  uint32_t address_range_count_ = 0;
  uint32_t psb_frequency_ = 0;
  uint32_t mtc_frequency_ = 0;
  uint32_t cycle_threshold_ = 0;
  uint64_t buffer_bytes_ = 0;
  IntelPtSwitchingMode switching_mode_ = IntelPtSwitchingMode::kDedicatedVmxControls;

  Pair pairs_[kPairCount];
  hypervisor::Page entry_msr_load_page_;
  hypervisor::Page exit_msr_load_page_;
  ktl::unique_ptr<hypervisor::Page[]> output_pages_;
  uint32_t output_page_count_ = 0;
  int32_t active_pair_ = -1;
  uint64_t active_output_mask_ptrs_ = 0x7f;
  uint64_t next_rotation_generation_ = 1;
  uint64_t next_segment_sequence_ = 1;
  uint64_t producer_cursor_ = 0;
  uint64_t acknowledged_cursor_ = 0;
  uint64_t generation_ = 0;
  uint64_t selected_cursor_ = 0;
  uint32_t selected_max_bytes_ = 0;
  uint64_t watermark_count_ = 0;
  zx_vcpu_intel_pt_terminal_t terminal_ = ZX_VCPU_INTEL_PT_TERMINAL_ACTIVE;
  bool backpressure_ = false;
  bool entry_prepared_ = false;
  bool reserved_ = false;

  HostState host_state_ = {};
  bool packet_pending_ = false;
  zx_packet_guest_intel_pt_t pending_packet_ = {};
};

#endif  // ZIRCON_KERNEL_ARCH_X86_HYPERVISOR_INTEL_PT_H_

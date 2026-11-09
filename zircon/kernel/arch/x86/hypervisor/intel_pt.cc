// Copyright 2026 The Cerise Authors
//
// Use of this source code is governed by a MIT-style license that can be found
// in the LICENSE file.

#include "intel_pt.h"

#include <align.h>
#include <lib/fit/defer.h>
#include <lib/page/size.h>
#include <string.h>

#include <arch/x86.h>
#include <arch/x86/apic.h>
#include <fbl/alloc_checker.h>
#include <ktl/algorithm.h>
#include <ktl/atomic.h>
#include <vm/physmap.h>

#include "vcpu_priv.h"

namespace {

constexpr uint32_t kMsrRtitOutputBase = 0x560;
constexpr uint32_t kMsrRtitOutputMaskPtrs = 0x561;
constexpr uint32_t kMsrRtitControl = 0x570;
constexpr uint32_t kMsrRtitStatus = 0x571;
constexpr uint32_t kMsrRtitCr3Match = 0x572;
constexpr uint32_t kMsrRtitAddress0A = 0x580;
constexpr uint32_t kMsrPerfGlobalStatus = 0x38e;
constexpr uint32_t kMsrPerfGlobalStatusReset = 0x390;

constexpr uint64_t kRtitControlTraceEnable = uint64_t{1} << 0;
constexpr uint64_t kRtitControlCycleEnable = uint64_t{1} << 1;
constexpr uint64_t kRtitControlOs = uint64_t{1} << 2;
constexpr uint64_t kRtitControlUser = uint64_t{1} << 3;
constexpr uint64_t kRtitControlCr3Filter = uint64_t{1} << 7;
constexpr uint64_t kRtitControlTopa = uint64_t{1} << 8;
constexpr uint64_t kRtitControlMtcEnable = uint64_t{1} << 9;
constexpr uint64_t kRtitControlBranchEnable = uint64_t{1} << 13;
constexpr uint64_t kRtitStatusError = uint64_t{1} << 4;
constexpr uint64_t kRtitStatusStopped = uint64_t{1} << 5;
constexpr uint64_t kPerfGlobalStatusTopaPmi = uint64_t{1} << 55;

constexpr uint64_t kTopaEnd = uint64_t{1} << 0;
constexpr uint64_t kTopaInterrupt = uint64_t{1} << 2;
constexpr uint64_t kTopaStop = uint64_t{1} << 4;
constexpr uint64_t kTopaInitialOutputMaskPtrs = 0x7f;
constexpr uint64_t kTopaTableOffsetMask = 0xffff'ff80;

struct alignas(16) VmxMsrLoadEntry {
  uint32_t index;
  uint32_t reserved;
  uint64_t value;
};
static_assert(sizeof(VmxMsrLoadEntry) == 16);
constexpr uint32_t kMaxMsrLoadEntries = kPageSize / sizeof(VmxMsrLoadEntry);

ktl::atomic<uint64_t> g_next_trace_generation{1};

bool EncodingSupported(uint32_t mask, uint32_t value) {
  return value < 32 && (mask & (uint32_t{1} << value)) != 0;
}

uint32_t MaxAddressRanges(const X86VcpuPtProperties& properties) {
  return ktl::min<uint32_t>(properties.leaf_14_1.eax & 0x7,
                            ZX_VCPU_INTEL_PT_MAX_ADDRESS_RANGES);
}

uint64_t NextGeneration() {
  uint64_t generation = g_next_trace_generation.fetch_add(1, ktl::memory_order_relaxed);
  if (generation == 0) {
    generation = g_next_trace_generation.fetch_add(1, ktl::memory_order_relaxed);
  }
  return generation;
}

uint32_t PublicReason(X86VcpuPtUnavailableReason reason) {
  switch (reason) {
    case X86VcpuPtUnavailableReason::kNone:
      return ZX_VCPU_INTEL_PT_REASON_NONE;
    case X86VcpuPtUnavailableReason::kNestedHost:
      return ZX_VCPU_INTEL_PT_REASON_NESTED_HOST;
    case X86VcpuPtUnavailableReason::kIntelPtAbsent:
      return ZX_VCPU_INTEL_PT_REASON_ABSENT;
    case X86VcpuPtUnavailableReason::kCpuid14Malformed:
      return ZX_VCPU_INTEL_PT_REASON_CPUID_MALFORMED;
    case X86VcpuPtUnavailableReason::kTopaUnavailable:
      return ZX_VCPU_INTEL_PT_REASON_TOPA_UNAVAILABLE;
    case X86VcpuPtUnavailableReason::kMultiEntryTopaUnavailable:
      return ZX_VCPU_INTEL_PT_REASON_MULTI_ENTRY_TOPA_UNAVAILABLE;
    case X86VcpuPtUnavailableReason::kRtitMsrUnavailable:
      return ZX_VCPU_INTEL_PT_REASON_RTIT_MSR_UNAVAILABLE;
    case X86VcpuPtUnavailableReason::kPmiResourceConflict:
      return ZX_VCPU_INTEL_PT_REASON_PMI_CONFLICT;
  }
  return ZX_VCPU_INTEL_PT_REASON_ABSENT;
}

void FillCapabilities(zx_vcpu_intel_pt_control_t& out,
                      const X86VcpuPtProperties& properties,
                      zx_vcpu_intel_pt_availability_t availability) {
  out.availability = availability;
  out.unavailable_reason = PublicReason(properties.unavailable_reason);
  out.cpu_family = properties.display_family;
  out.cpu_model = properties.display_model;
  out.cpu_stepping = properties.stepping;
  out.max_address_ranges = MaxAddressRanges(properties);
  out.supported_psb_frequencies = properties.leaf_14_1.ebx >> 16;
  out.supported_mtc_frequencies = properties.leaf_14_1.eax >> 16;
  out.supported_cycle_thresholds = properties.leaf_14_1.ebx & 0xffff;
  out.supported_flags = ZX_VCPU_INTEL_PT_TRACE_USER | ZX_VCPU_INTEL_PT_TRACE_SUPERVISOR |
                        ZX_VCPU_INTEL_PT_BRANCH_TRACE;
  if ((properties.leaf_14_0.ebx & (uint32_t{1} << 0)) != 0) {
    out.supported_flags |= ZX_VCPU_INTEL_PT_CR3_FILTER;
  }
  if ((properties.leaf_14_0.ebx & (uint32_t{1} << 3)) != 0) {
    out.supported_flags |= ZX_VCPU_INTEL_PT_MTC_PACKETS;
  }
  if ((properties.leaf_14_0.ebx & (uint32_t{1} << 1)) != 0) {
    out.supported_flags |= ZX_VCPU_INTEL_PT_CYCLE_PACKETS;
  }
  out.cpuid_14[0] = {
      .subleaf = 0,
      .eax = properties.leaf_14_0.eax,
      .ebx = properties.leaf_14_0.ebx,
      .ecx = properties.leaf_14_0.ecx,
      .edx = properties.leaf_14_0.edx,
  };
  out.cpuid_14[1] = {
      .subleaf = 1,
      .eax = properties.leaf_14_1.eax,
      .ebx = properties.leaf_14_1.ebx,
      .ecx = properties.leaf_14_1.ecx,
      .edx = properties.leaf_14_1.edx,
  };
}

}  // namespace

bool IntelPtState::DecodeOutputPosition(const Pair& pair, uint64_t output_mask_ptrs,
                                        uint64_t* main_bytes, uint64_t* guard_bytes) {
  // In ToPA mode bits 31:7 encode the current table-entry index. They are not
  // a byte address: entry one is represented as bit 7, not as the value 8.
  const uint64_t entry = (output_mask_ptrs & kTopaTableOffsetMask) >> 7;
  const uint64_t offset = output_mask_ptrs >> 32;
  if (offset > kPageSize || entry > pair.main_pages) {
    return false;
  }
  if (entry < pair.main_pages) {
    *main_bytes = entry * kPageSize + offset;
    *guard_bytes = 0;
  } else {
    *main_bytes = uint64_t{pair.main_pages} * kPageSize;
    *guard_bytes = offset;
  }
  return true;
}

zx::result<ktl::unique_ptr<IntelPtState>> IntelPtState::Create(
    const zx_vcpu_intel_pt_control_t& request, const X86VcpuPtProperties& properties,
    IntelPtSwitchingMode switching_mode) {
  fbl::AllocChecker ac;
  ktl::unique_ptr<IntelPtState> state(new (&ac) IntelPtState());
  if (!ac.check()) {
    x86_perfmon_release_vcpu_pt();
    return zx::error(ZX_ERR_NO_MEMORY);
  }
  state->reserved_ = true;
  if (auto result = state->Initialize(request, properties, switching_mode);
      result.is_error()) {
    return result.take_error();
  }
  return zx::ok(ktl::move(state));
}

IntelPtState::~IntelPtState() {
  if (reserved_) {
    x86_perfmon_release_vcpu_pt();
  }
}

void IntelPtState::ReadCapabilities(
    zx_vcpu_intel_pt_control_t& out, const X86VcpuPtProperties& properties,
    zx_vcpu_intel_pt_availability_t availability,
    zx_vcpu_intel_pt_unavailable_reason_t override_reason) {
  out = {};
  out.magic = ZX_VCPU_INTEL_PT_CONTROL_MAGIC;
  out.version = ZX_VCPU_INTEL_PT_CONTROL_VERSION;
  out.size = sizeof(out);
  FillCapabilities(out, properties, availability);
  if (override_reason != ZX_VCPU_INTEL_PT_REASON_NONE) {
    out.unavailable_reason = override_reason;
  }
}

zx_vcpu_intel_pt_unavailable_reason_t IntelPtState::PublicUnavailableReason(
    X86VcpuPtUnavailableReason reason) {
  return PublicReason(reason);
}

zx::result<> IntelPtState::Initialize(const zx_vcpu_intel_pt_control_t& request,
                                      const X86VcpuPtProperties& properties,
                                      IntelPtSwitchingMode switching_mode) {
  const uint32_t max_ranges = MaxAddressRanges(properties);
  const uint64_t supported_flags =
      ZX_VCPU_INTEL_PT_TRACE_USER | ZX_VCPU_INTEL_PT_TRACE_SUPERVISOR |
      ZX_VCPU_INTEL_PT_BRANCH_TRACE |
      ((properties.leaf_14_0.ebx & 1) ? ZX_VCPU_INTEL_PT_CR3_FILTER : 0) |
      ((properties.leaf_14_0.ebx & (1u << 3)) ? ZX_VCPU_INTEL_PT_MTC_PACKETS : 0) |
      ((properties.leaf_14_0.ebx & (1u << 1)) ? ZX_VCPU_INTEL_PT_CYCLE_PACKETS : 0);

  if (request.delivery != ZX_VCPU_INTEL_PT_DELIVERY_COMPLETE_OR_FAIL ||
      (request.config_flags & ~supported_flags) != 0 ||
      (request.config_flags &
       (ZX_VCPU_INTEL_PT_TRACE_USER | ZX_VCPU_INTEL_PT_TRACE_SUPERVISOR)) == 0 ||
      request.address_range_count > max_ranges ||
      (request.address_range_count != 0 && max_ranges == 0) ||
      request.buffer_bytes < uint64_t{kPairCount} * kPageSize ||
      request.buffer_bytes > ZX_VCPU_INTEL_PT_MAX_BUFFER_BYTES ||
      request.buffer_bytes % kPageSize != 0 ||
      ((request.config_flags & ZX_VCPU_INTEL_PT_CR3_FILTER) == 0 &&
       request.cr3_match != 0) ||
      ((request.config_flags & ZX_VCPU_INTEL_PT_CR3_FILTER) != 0 &&
       request.cr3_match % kPageSize != 0) ||
      ((request.config_flags & ZX_VCPU_INTEL_PT_MTC_PACKETS) == 0 &&
       request.mtc_frequency != 0) ||
      ((request.config_flags & ZX_VCPU_INTEL_PT_CYCLE_PACKETS) == 0 &&
       request.cycle_threshold != 0)) {
    return zx::error(ZX_ERR_INVALID_ARGS);
  }

  const uint32_t psb_mask = properties.leaf_14_1.ebx >> 16;
  const uint32_t mtc_mask = properties.leaf_14_1.eax >> 16;
  const uint32_t cycle_mask = properties.leaf_14_1.ebx & 0xffff;
  if (!EncodingSupported(psb_mask, request.psb_frequency) ||
      ((request.config_flags & ZX_VCPU_INTEL_PT_MTC_PACKETS) != 0 &&
       !EncodingSupported(mtc_mask, request.mtc_frequency)) ||
      ((request.config_flags & ZX_VCPU_INTEL_PT_CYCLE_PACKETS) != 0 &&
       !EncodingSupported(cycle_mask, request.cycle_threshold))) {
    return zx::error(ZX_ERR_NOT_SUPPORTED);
  }

  for (uint32_t i = 0; i < request.address_range_count; ++i) {
    const auto& range = request.address_ranges[i];
    uint64_t end = 0;
    if (range.length == 0 || add_overflow(range.start, range.length - 1, &end) ||
        !x86_is_vaddr_canonical(range.start) || !x86_is_vaddr_canonical(end)) {
      return zx::error(ZX_ERR_INVALID_ARGS);
    }
    address_a_[i] = range.start;
    address_b_[i] = end;
  }
  for (uint32_t i = request.address_range_count;
       i < ZX_VCPU_INTEL_PT_MAX_ADDRESS_RANGES; ++i) {
    if (request.address_ranges[i].start != 0 || request.address_ranges[i].length != 0) {
      return zx::error(ZX_ERR_INVALID_ARGS);
    }
  }

  properties_ = properties;
  switching_mode_ = switching_mode;
  config_flags_ = request.config_flags;
  address_range_count_ = request.address_range_count;
  cr3_match_ = request.cr3_match;
  psb_frequency_ = request.psb_frequency;
  mtc_frequency_ = request.mtc_frequency;
  cycle_threshold_ = request.cycle_threshold;
  buffer_bytes_ = request.buffer_bytes;

  control_value_ = kRtitControlTopa;
  if ((config_flags_ & ZX_VCPU_INTEL_PT_TRACE_USER) != 0) {
    control_value_ |= kRtitControlUser;
  }
  if ((config_flags_ & ZX_VCPU_INTEL_PT_TRACE_SUPERVISOR) != 0) {
    control_value_ |= kRtitControlOs;
  }
  if ((config_flags_ & ZX_VCPU_INTEL_PT_BRANCH_TRACE) != 0) {
    control_value_ |= kRtitControlBranchEnable;
  }
  if ((config_flags_ & ZX_VCPU_INTEL_PT_CR3_FILTER) != 0) {
    control_value_ |= kRtitControlCr3Filter;
  }
  if ((config_flags_ & ZX_VCPU_INTEL_PT_MTC_PACKETS) != 0) {
    control_value_ |= kRtitControlMtcEnable;
  }
  if ((config_flags_ & ZX_VCPU_INTEL_PT_CYCLE_PACKETS) != 0) {
    control_value_ |= kRtitControlCycleEnable;
  }
  control_value_ |= uint64_t{mtc_frequency_} << 14;
  control_value_ |= uint64_t{cycle_threshold_} << 19;
  control_value_ |= uint64_t{psb_frequency_} << 24;
  for (uint32_t i = 0; i < address_range_count_; ++i) {
    control_value_ |= uint64_t{1} << (32 + 4 * i);
  }

  if (switching_mode_ == IntelPtSwitchingMode::kVmxMsrLoadLists) {
    if (auto result = entry_msr_load_page_.Alloc(0); result.is_error()) {
      return result.take_error();
    }
    if (auto result = exit_msr_load_page_.Alloc(0); result.is_error()) {
      return result.take_error();
    }
  }

  const uint32_t main_page_count = static_cast<uint32_t>(buffer_bytes_ / kPageSize);
  output_page_count_ = main_page_count + kPairCount;
  fbl::AllocChecker ac;
  output_pages_.reset(new (&ac) hypervisor::Page[output_page_count_]);
  if (!ac.check()) {
    return zx::error(ZX_ERR_NO_MEMORY);
  }
  for (uint32_t i = 0; i < output_page_count_; ++i) {
    if (auto result = output_pages_[i].Alloc(0); result.is_error()) {
      return result.take_error();
    }
  }

  const uint32_t per_pair = main_page_count / kPairCount;
  const uint32_t extra = main_page_count % kPairCount;
  uint32_t output_index = 0;
  for (uint32_t pair_index = 0; pair_index < kPairCount; ++pair_index) {
    Pair& pair = pairs_[pair_index];
    pair.first_output_page = output_index;
    pair.main_pages = per_pair + (pair_index < extra ? 1 : 0);
    pair.guard_page = output_index + pair.main_pages;
    output_index = pair.guard_page + 1;
    if (pair.main_pages == 0 || pair.main_pages + 2 > kPageSize / sizeof(uint64_t)) {
      return zx::error(ZX_ERR_OUT_OF_RANGE);
    }
    if (auto result = pair.table.Alloc(0); result.is_error()) {
      return result.take_error();
    }
    auto* entries = pair.table.VirtualAddress<uint64_t>();
    for (uint32_t page = 0; page < pair.main_pages; ++page) {
      entries[page] = output_pages_[pair.first_output_page + page].PhysicalAddress();
      if (page + 1 == pair.main_pages) {
        entries[page] |= kTopaInterrupt;
      }
    }
    entries[pair.main_pages] =
        output_pages_[pair.guard_page].PhysicalAddress() | kTopaStop;
    entries[pair.main_pages + 1] = pair.table.PhysicalAddress() | kTopaEnd;
  }
  DEBUG_ASSERT(output_index == output_page_count_);

  generation_ = NextGeneration();
  return ActivateFreePair();
}

zx::result<uint32_t> IntelPtState::PopulateMsrLoadList(hypervisor::Page& page,
                                                       uint64_t source_address,
                                                       uint32_t source_count,
                                                       uint64_t control_value) {
  uint64_t source_end = 0;
  const uint64_t source_bytes =
      uint64_t{source_count} * sizeof(VmxMsrLoadEntry);
  if (source_count > kMaxMsrLoadEntries ||
      (source_count != 0 &&
       ((source_address & (alignof(VmxMsrLoadEntry) - 1)) != 0 ||
        add_overflow(source_address, source_bytes - 1, &source_end) ||
        !is_physmap_phys_addr(source_address) ||
        !is_physmap_phys_addr(source_end)))) {
    return zx::error(ZX_ERR_NOT_SUPPORTED);
  }

  auto* destination = page.VirtualAddress<VmxMsrLoadEntry>();
  if (source_count != 0) {
    memcpy(destination, paddr_to_physmap(source_address),
           size_t{source_count} * sizeof(VmxMsrLoadEntry));
  }

  bool replaced = false;
  for (uint32_t i = 0; i < source_count; ++i) {
    if (destination[i].index == kMsrRtitControl) {
      destination[i].value = control_value;
      replaced = true;
    }
  }
  if (replaced) {
    return zx::ok(source_count);
  }
  if (source_count == kMaxMsrLoadEntries) {
    return zx::error(ZX_ERR_NO_RESOURCES);
  }
  destination[source_count] = {
      .index = kMsrRtitControl,
      .reserved = 0,
      .value = control_value,
  };
  return zx::ok(source_count + 1);
}

zx::result<> IntelPtState::ActivateFreePair() {
  for (uint32_t i = 0; i < kPairCount; ++i) {
    Pair& pair = pairs_[i];
    if (pair.state != PairState::kFree) {
      continue;
    }
    pair.state = PairState::kActive;
    pair.rotation_generation = next_rotation_generation_++;
    active_pair_ = static_cast<int32_t>(i);
    active_output_mask_ptrs_ = kTopaInitialOutputMaskPtrs;
    return zx::ok();
  }
  return zx::error(ZX_ERR_SHOULD_WAIT);
}

IntelPtState::Pair* IntelPtState::ActivePair() {
  return active_pair_ < 0 ? nullptr : &pairs_[active_pair_];
}

uint32_t IntelPtState::FreePairCount() const {
  uint32_t count = 0;
  for (const Pair& pair : pairs_) {
    if (pair.state == PairState::kFree) {
      ++count;
    }
  }
  return count;
}

bool IntelPtState::MayEnter() const {
  return terminal_ == ZX_VCPU_INTEL_PT_TERMINAL_ACTIVE && active_pair_ >= 0 &&
         !backpressure_;
}

zx::result<> IntelPtState::PrepareEntry(AutoVmcs& vmcs) {
  Pair* pair = ActivePair();
  if (!MayEnter() || pair == nullptr || entry_prepared_) {
    return zx::error(ZX_ERR_BAD_STATE);
  }

  uint32_t entry_msr_load_count = 0;
  uint32_t exit_msr_load_count = 0;
  if (switching_mode_ == IntelPtSwitchingMode::kDedicatedVmxControls) {
    host_state_.entry_controls = vmcs.Read(VmcsField32::ENTRY_CTLS);
    host_state_.exit_controls = vmcs.Read(VmcsField32::EXIT_CTLS);
    host_state_.guest_control = vmcs.Read(VmcsField64::GUEST_IA32_RTIT_CTL);
  } else {
    host_state_.entry_msr_load_address =
        vmcs.Read(VmcsField64::ENTRY_MSR_LOAD_ADDRESS);
    host_state_.exit_msr_load_address =
        vmcs.Read(VmcsField64::EXIT_MSR_LOAD_ADDRESS);
    host_state_.entry_msr_load_count =
        vmcs.Read(VmcsField32::ENTRY_MSR_LOAD_COUNT);
    host_state_.exit_msr_load_count =
        vmcs.Read(VmcsField32::EXIT_MSR_LOAD_COUNT);

    auto entry_list = PopulateMsrLoadList(
        entry_msr_load_page_, host_state_.entry_msr_load_address,
        host_state_.entry_msr_load_count, control_value_ | kRtitControlTraceEnable);
    if (entry_list.is_error()) {
      return entry_list.take_error();
    }
    auto exit_list =
        PopulateMsrLoadList(exit_msr_load_page_, host_state_.exit_msr_load_address,
                            host_state_.exit_msr_load_count, 0);
    if (exit_list.is_error()) {
      return exit_list.take_error();
    }
    entry_msr_load_count = entry_list.value();
    exit_msr_load_count = exit_list.value();
  }
  if (read_msr_safe(kMsrRtitControl, &host_state_.control) != ZX_OK ||
      read_msr_safe(kMsrRtitStatus, &host_state_.status) != ZX_OK ||
      read_msr_safe(kMsrRtitOutputBase, &host_state_.output_base) != ZX_OK ||
      read_msr_safe(kMsrRtitOutputMaskPtrs, &host_state_.output_mask_ptrs) != ZX_OK ||
      read_msr_safe(kMsrRtitCr3Match, &host_state_.cr3_match) != ZX_OK) {
    Fail(ZX_VCPU_INTEL_PT_STATUS_HARDWARE_ERROR);
    return zx::error(ZX_ERR_IO);
  }
  for (uint32_t i = 0; i < address_range_count_; ++i) {
    if (read_msr_safe(kMsrRtitAddress0A + 2 * i, &host_state_.address_a[i]) != ZX_OK ||
        read_msr_safe(kMsrRtitAddress0A + 2 * i + 1, &host_state_.address_b[i]) != ZX_OK) {
      Fail(ZX_VCPU_INTEL_PT_STATUS_HARDWARE_ERROR);
      return zx::error(ZX_ERR_IO);
    }
  }

  auto restore_on_error = fit::defer([&] {
    write_msr_safe(kMsrRtitControl, 0);
    write_msr_safe(kMsrRtitOutputBase, host_state_.output_base);
    write_msr_safe(kMsrRtitOutputMaskPtrs, host_state_.output_mask_ptrs);
    write_msr_safe(kMsrRtitStatus, host_state_.status);
    write_msr_safe(kMsrRtitCr3Match, host_state_.cr3_match);
    for (uint32_t i = 0; i < address_range_count_; ++i) {
      write_msr_safe(kMsrRtitAddress0A + 2 * i, host_state_.address_a[i]);
      write_msr_safe(kMsrRtitAddress0A + 2 * i + 1, host_state_.address_b[i]);
    }
    write_msr_safe(kMsrRtitControl, host_state_.control);
    if (switching_mode_ == IntelPtSwitchingMode::kDedicatedVmxControls) {
      vmcs.Write(VmcsField32::ENTRY_CTLS, host_state_.entry_controls);
      vmcs.Write(VmcsField32::EXIT_CTLS, host_state_.exit_controls);
      vmcs.Write(VmcsField64::GUEST_IA32_RTIT_CTL, host_state_.guest_control);
    } else {
      vmcs.Write(VmcsField32::ENTRY_MSR_LOAD_COUNT,
                 host_state_.entry_msr_load_count);
      vmcs.Write(VmcsField32::EXIT_MSR_LOAD_COUNT,
                 host_state_.exit_msr_load_count);
      vmcs.Write(VmcsField64::ENTRY_MSR_LOAD_ADDRESS,
                 host_state_.entry_msr_load_address);
      vmcs.Write(VmcsField64::EXIT_MSR_LOAD_ADDRESS,
                 host_state_.exit_msr_load_address);
    }
  });

  if (write_msr_safe(kMsrRtitControl, 0) != ZX_OK ||
      write_msr_safe(kMsrRtitStatus, 0) != ZX_OK ||
      write_msr_safe(kMsrRtitOutputBase, pair->table.PhysicalAddress()) != ZX_OK ||
      write_msr_safe(kMsrRtitOutputMaskPtrs, active_output_mask_ptrs_) != ZX_OK ||
      write_msr_safe(kMsrRtitCr3Match, cr3_match_) != ZX_OK) {
    Fail(ZX_VCPU_INTEL_PT_STATUS_HARDWARE_ERROR);
    return zx::error(ZX_ERR_IO);
  }
  for (uint32_t i = 0; i < address_range_count_; ++i) {
    if (write_msr_safe(kMsrRtitAddress0A + 2 * i, address_a_[i]) != ZX_OK ||
        write_msr_safe(kMsrRtitAddress0A + 2 * i + 1, address_b_[i]) != ZX_OK) {
      Fail(ZX_VCPU_INTEL_PT_STATUS_HARDWARE_ERROR);
      return zx::error(ZX_ERR_IO);
    }
  }

  if (switching_mode_ == IntelPtSwitchingMode::kDedicatedVmxControls) {
    vmcs.Write(VmcsField64::GUEST_IA32_RTIT_CTL, control_value_ | kRtitControlTraceEnable);
    vmcs.Write(VmcsField32::ENTRY_CTLS,
               host_state_.entry_controls | kEntryCtlsLoadIa32RtitControl);
    vmcs.Write(VmcsField32::EXIT_CTLS,
               host_state_.exit_controls | kExitCtlsClearIa32RtitControl);
  } else {
    vmcs.Write(VmcsField64::ENTRY_MSR_LOAD_ADDRESS,
               entry_msr_load_page_.PhysicalAddress());
    vmcs.Write(VmcsField64::EXIT_MSR_LOAD_ADDRESS,
               exit_msr_load_page_.PhysicalAddress());
    vmcs.Write(VmcsField32::ENTRY_MSR_LOAD_COUNT, entry_msr_load_count);
    vmcs.Write(VmcsField32::EXIT_MSR_LOAD_COUNT, exit_msr_load_count);
  }
  // The PT ToPA INT bit raises the architectural performance-monitoring
  // interrupt. The global reservation guarantees that this VCPU is its only
  // owner, but the route is normally masked. Expose it only across the guest
  // transition, exactly as the retired-instruction budget path does.
  host_state_.pmi_masked = apic_pmi_is_masked();
  apic_pmi_unmask();
  x86_perfmon_vcpu_pt_note_msr_accesses(5 + 2 * address_range_count_);
  entry_prepared_ = true;
  restore_on_error.cancel();
  return zx::ok();
}

void IntelPtState::FinishExit(AutoVmcs& vmcs, bool entry_succeeded) {
  if (!entry_prepared_) {
    return;
  }

  uint64_t output_mask_ptrs = 0;
  uint64_t hardware_status = 0;
  uint64_t global_status = 0;
  // A successful transition cleared TraceEn in hardware before the first host
  // instruction. A failed VM entry may have partially processed its MSR-load
  // list without executing a VM exit, so explicitly quiesce PT in that case.
  const bool disable_ok = entry_succeeded || write_msr_safe(kMsrRtitControl, 0) == ZX_OK;
  const bool read_ok =
      disable_ok &&
      read_msr_safe(kMsrRtitOutputMaskPtrs, &output_mask_ptrs) == ZX_OK &&
      read_msr_safe(kMsrRtitStatus, &hardware_status) == ZX_OK &&
      read_msr_safe(kMsrPerfGlobalStatus, &global_status) == ZX_OK;
  x86_perfmon_vcpu_pt_note_msr_accesses(3);

  // Stop new PMI delivery before restoring any displaced host state. A vector
  // already accepted from the guest run remains pending and is acknowledged by
  // the reserved-owner branch of the common PMI handler.
  apic_pmi_mask();

  // Restore every host-owned register before normal VM-exit handling.
  write_msr_safe(kMsrRtitControl, 0);
  write_msr_safe(kMsrRtitOutputBase, host_state_.output_base);
  write_msr_safe(kMsrRtitOutputMaskPtrs, host_state_.output_mask_ptrs);
  write_msr_safe(kMsrRtitStatus, host_state_.status);
  write_msr_safe(kMsrRtitCr3Match, host_state_.cr3_match);
  for (uint32_t i = 0; i < address_range_count_; ++i) {
    write_msr_safe(kMsrRtitAddress0A + 2 * i, host_state_.address_a[i]);
    write_msr_safe(kMsrRtitAddress0A + 2 * i + 1, host_state_.address_b[i]);
  }
  write_msr_safe(kMsrRtitControl, host_state_.control);
  if (switching_mode_ == IntelPtSwitchingMode::kDedicatedVmxControls) {
    vmcs.Write(VmcsField32::ENTRY_CTLS, host_state_.entry_controls);
    vmcs.Write(VmcsField32::EXIT_CTLS, host_state_.exit_controls);
    vmcs.Write(VmcsField64::GUEST_IA32_RTIT_CTL, host_state_.guest_control);
  } else {
    vmcs.Write(VmcsField32::ENTRY_MSR_LOAD_COUNT,
               host_state_.entry_msr_load_count);
    vmcs.Write(VmcsField32::EXIT_MSR_LOAD_COUNT,
               host_state_.exit_msr_load_count);
    vmcs.Write(VmcsField64::ENTRY_MSR_LOAD_ADDRESS,
               host_state_.entry_msr_load_address);
    vmcs.Write(VmcsField64::EXIT_MSR_LOAD_ADDRESS,
               host_state_.exit_msr_load_address);
  }
  if (!host_state_.pmi_masked) {
    apic_pmi_unmask();
  }
  x86_perfmon_vcpu_pt_note_msr_accesses(6 + 2 * address_range_count_);
  entry_prepared_ = false;

  if (!entry_succeeded || !read_ok) {
    Fail(ZX_VCPU_INTEL_PT_STATUS_HARDWARE_ERROR);
    return;
  }

  active_output_mask_ptrs_ = output_mask_ptrs;
  const bool topa_pmi = (global_status & kPerfGlobalStatusTopaPmi) != 0;
  const bool stopped = (hardware_status & kRtitStatusStopped) != 0;
  const bool error = (hardware_status & kRtitStatusError) != 0;
  if (topa_pmi) {
    write_msr(kMsrPerfGlobalStatusReset, kPerfGlobalStatusTopaPmi);
    x86_perfmon_vcpu_pt_note_msr_accesses(1);
    x86_perfmon_vcpu_pt_pmi_pending();
  }
  if (!topa_pmi && !stopped && !error) {
    return;
  }

  Pair* pair = ActivePair();
  uint64_t main_bytes = 0;
  uint64_t guard_bytes = 0;
  if (pair == nullptr ||
      !DecodeOutputPosition(*pair, output_mask_ptrs, &main_bytes, &guard_bytes)) {
    Fail(ZX_VCPU_INTEL_PT_STATUS_GAP_BEFORE);
    return;
  }

  uint32_t status_flags = 0;
  if (stopped) {
    status_flags |= ZX_VCPU_INTEL_PT_STATUS_HARDWARE_STOPPED;
  }
  if (error) {
    status_flags |= ZX_VCPU_INTEL_PT_STATUS_HARDWARE_ERROR;
  }
  if (!topa_pmi || main_bytes != uint64_t{pair->main_pages} * kPageSize) {
    status_flags |= ZX_VCPU_INTEL_PT_STATUS_GAP_BEFORE;
  }
  SealActive(main_bytes, guard_bytes, hardware_status, status_flags);
  if (status_flags != 0) {
    terminal_ = ZX_VCPU_INTEL_PT_TERMINAL_INCOMPLETE;
    active_pair_ = -1;
    backpressure_ = true;
    return;
  }

  if (ActivateFreePair().is_error()) {
    terminal_ = ZX_VCPU_INTEL_PT_TERMINAL_INCOMPLETE;
    backpressure_ = true;
    QueuePacket(nullptr, ZX_VCPU_INTEL_PT_STATUS_GAP_BEFORE);
    return;
  }
  if (FreePairCount() == 0) {
    backpressure_ = true;
    pending_packet_.status_flags |= ZX_VCPU_INTEL_PT_STATUS_BACKPRESSURE;
  }
}

void IntelPtState::SealActive(uint64_t main_bytes, uint64_t guard_bytes,
                              uint64_t hardware_status, uint32_t status_flags) {
  Pair* pair = ActivePair();
  if (pair == nullptr || main_bytes > uint64_t{pair->main_pages} * kPageSize ||
      guard_bytes > kPageSize ||
      (main_bytes < uint64_t{pair->main_pages} * kPageSize && guard_bytes != 0)) {
    Fail(status_flags | ZX_VCPU_INTEL_PT_STATUS_GAP_BEFORE);
    return;
  }
  const uint64_t bytes = main_bytes + guard_bytes;
  pair->state = PairState::kSealed;
  pair->sequence = next_segment_sequence_++;
  pair->start_cursor = producer_cursor_;
  pair->end_cursor = producer_cursor_ + bytes;
  pair->main_bytes = main_bytes;
  pair->guard_bytes = guard_bytes;
  pair->hardware_status = hardware_status;
  pair->status_flags = status_flags | ZX_VCPU_INTEL_PT_STATUS_SEGMENT_COMPLETE;
  producer_cursor_ = pair->end_cursor;
  active_pair_ = -1;
  ++watermark_count_;
  QueuePacket(pair, pair->status_flags);
}

void IntelPtState::Fail(uint32_t status_flags) {
  terminal_ = ZX_VCPU_INTEL_PT_TERMINAL_INCOMPLETE;
  backpressure_ = true;
  active_pair_ = -1;
  QueuePacket(nullptr, status_flags);
}

void IntelPtState::QueuePacket(const Pair* pair, uint32_t status_flags) {
  pending_packet_ = {};
  pending_packet_.segment_sequence = pair == nullptr ? 0 : pair->sequence;
  pending_packet_.trace_generation = generation_;
  pending_packet_.producer_cursor = producer_cursor_;
  pending_packet_.status_flags = status_flags;
  packet_pending_ = true;
}

bool IntelPtState::TakePacket(zx_packet_guest_intel_pt_t& packet) {
  if (!packet_pending_) {
    return false;
  }
  packet = pending_packet_;
  packet_pending_ = false;
  return true;
}

zx::result<> IntelPtState::SelectRead(uint64_t generation, uint64_t cursor,
                                      uint32_t max_bytes) {
  if (generation != generation_) {
    return zx::error(ZX_ERR_NOT_FOUND);
  }
  if (max_bytes == 0 || max_bytes > ZX_VCPU_INTEL_PT_MAX_CHUNK_BYTES ||
      cursor < acknowledged_cursor_ || cursor > producer_cursor_) {
    return zx::error(ZX_ERR_OUT_OF_RANGE);
  }
  if (cursor < producer_cursor_) {
    bool found = false;
    for (const Pair& pair : pairs_) {
      if (pair.state == PairState::kSealed && cursor >= pair.start_cursor &&
          cursor < pair.end_cursor) {
        found = true;
        break;
      }
    }
    if (!found) {
      return zx::error(ZX_ERR_NOT_FOUND);
    }
  }
  selected_cursor_ = cursor;
  selected_max_bytes_ = max_bytes;
  return zx::ok();
}

zx::result<> IntelPtState::Ack(uint64_t generation, uint64_t through_cursor) {
  if (generation != generation_) {
    return zx::error(ZX_ERR_NOT_FOUND);
  }
  if (through_cursor < acknowledged_cursor_ || through_cursor > producer_cursor_) {
    return zx::error(ZX_ERR_OUT_OF_RANGE);
  }
  for (Pair& pair : pairs_) {
    if (pair.state == PairState::kSealed && pair.end_cursor <= through_cursor) {
      pair.state = PairState::kFree;
      pair.sequence = 0;
    }
  }
  acknowledged_cursor_ = through_cursor;
  if (terminal_ == ZX_VCPU_INTEL_PT_TERMINAL_ACTIVE && FreePairCount() != 0) {
    backpressure_ = false;
  }
  if (selected_cursor_ < acknowledged_cursor_) {
    selected_cursor_ = acknowledged_cursor_;
  }
  return zx::ok();
}

zx::result<> IntelPtState::Stop(uint64_t generation) {
  if (generation != generation_) {
    return zx::error(ZX_ERR_NOT_FOUND);
  }
  if (terminal_ != ZX_VCPU_INTEL_PT_TERMINAL_ACTIVE) {
    return zx::ok();
  }
  Pair* pair = ActivePair();
  if (pair != nullptr) {
    uint64_t main_bytes = 0;
    uint64_t guard_bytes = 0;
    if (!DecodeOutputPosition(*pair, active_output_mask_ptrs_, &main_bytes, &guard_bytes)) {
      Fail(ZX_VCPU_INTEL_PT_STATUS_GAP_BEFORE);
      return zx::error(ZX_ERR_IO_DATA_INTEGRITY);
    }
    if (main_bytes != 0 || guard_bytes != 0) {
      SealActive(main_bytes, guard_bytes, 0, 0);
    } else {
      pair->state = PairState::kFree;
      active_pair_ = -1;
    }
  }
  terminal_ = ZX_VCPU_INTEL_PT_TERMINAL_COMPLETE;
  backpressure_ = true;
  QueuePacket(nullptr, 0);
  return zx::ok();
}

const IntelPtState::Pair* IntelPtState::SelectedPair() const {
  if (selected_cursor_ >= producer_cursor_) {
    return nullptr;
  }
  for (const Pair& pair : pairs_) {
    if (pair.state == PairState::kSealed && selected_cursor_ >= pair.start_cursor &&
        selected_cursor_ < pair.end_cursor) {
      return &pair;
    }
  }
  return nullptr;
}

void IntelPtState::CopyPairBytes(const Pair& pair, uint64_t offset, uint32_t length,
                                 uint8_t* out) const {
  uint32_t copied = 0;
  while (copied < length) {
    const uint64_t logical = offset + copied;
    const uint32_t page_in_pair = static_cast<uint32_t>(logical / kPageSize);
    const uint32_t page_offset = static_cast<uint32_t>(logical % kPageSize);
    const uint32_t page_index = page_in_pair < pair.main_pages
                                    ? pair.first_output_page + page_in_pair
                                    : pair.guard_page;
    const uint32_t part = ktl::min<uint32_t>(length - copied, kPageSize - page_offset);
    memcpy(out + copied, output_pages_[page_index].VirtualAddress<uint8_t>() + page_offset, part);
    copied += part;
  }
}

zx::result<> IntelPtState::ReadControl(zx_vcpu_intel_pt_control_t& out) const {
  out = {};
  out.magic = ZX_VCPU_INTEL_PT_CONTROL_MAGIC;
  out.version = ZX_VCPU_INTEL_PT_CONTROL_VERSION;
  out.size = sizeof(out);
  FillCapabilities(out, properties_, ZX_VCPU_INTEL_PT_AVAILABLE);
  out.delivery = ZX_VCPU_INTEL_PT_DELIVERY_COMPLETE_OR_FAIL;
  out.address_range_count = address_range_count_;
  out.config_flags = config_flags_;
  out.buffer_bytes = buffer_bytes_;
  for (uint32_t i = 0; i < address_range_count_; ++i) {
    out.address_ranges[i].start = address_a_[i];
    out.address_ranges[i].length = address_b_[i] - address_a_[i] + 1;
  }
  out.cr3_match = cr3_match_;
  out.psb_frequency = psb_frequency_;
  out.mtc_frequency = mtc_frequency_;
  out.cycle_threshold = cycle_threshold_;
  out.trace_generation = generation_;
  out.acknowledged_cursor = acknowledged_cursor_;
  out.read_cursor = selected_cursor_;
  out.read_max_bytes = selected_max_bytes_;
  out.producer_cursor = producer_cursor_;
  out.watermark_count = watermark_count_;
  out.terminal = terminal_;
  if (backpressure_) {
    out.status_flags |= ZX_VCPU_INTEL_PT_STATUS_BACKPRESSURE;
  }

  const Pair* pair = SelectedPair();
  if (pair == nullptr || selected_max_bytes_ == 0) {
    out.next_cursor = selected_cursor_;
    return zx::ok();
  }
  const uint64_t available = pair->end_cursor - selected_cursor_;
  out.data_size =
      static_cast<uint32_t>(ktl::min<uint64_t>(available, selected_max_bytes_));
  out.next_cursor = selected_cursor_ + out.data_size;
  out.segment_sequence = pair->sequence;
  out.segment_offset = selected_cursor_ - pair->start_cursor;
  out.hardware_status = pair->hardware_status;
  out.status_flags |= pair->status_flags;
  if (out.next_cursor != pair->end_cursor) {
    out.status_flags &= ~ZX_VCPU_INTEL_PT_STATUS_SEGMENT_COMPLETE;
  }
  CopyPairBytes(*pair, out.segment_offset, out.data_size, out.data);
  return zx::ok();
}

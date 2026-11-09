// Copyright 2017 The Fuchsia Authors
//
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT

// This file contains declarations internal to x86.
// Declarations visible outside of x86 belong in arch_perfmon.h.

#ifndef ZIRCON_KERNEL_ARCH_X86_INCLUDE_ARCH_X86_PERF_MON_H_
#define ZIRCON_KERNEL_ARCH_X86_INCLUDE_ARCH_X86_PERF_MON_H_

#include <arch/x86.h>
#include <zircon/types.h>

struct X86VcpuPmuProperties {
  uint8_t counter_width = 0;
  uint64_t max_budget = 0;
};

// Complete physical-PMU state displaced while one VCPU entry counts retired
// guest instructions. The VMCS swaps IA32_PERF_GLOBAL_CTRL exactly at the
// VM-entry/VM-exit boundary; this record covers the remaining shared state.
struct X86VcpuPmuContext {
  uint64_t host_global_ctrl = 0;
  uint64_t host_fixed_ctrl = 0;
  uint64_t host_fixed_counter = 0;
  uint64_t initial_counter = 0;
  uint64_t budget = 0;
  bool host_overflow = false;
  bool host_pmi_masked = true;
};

struct X86VcpuPmuSample {
  uint64_t retired = 0;
  bool overflow = false;
};

struct X86VcpuPtCpuidLeaf {
  uint32_t eax = 0;
  uint32_t ebx = 0;
  uint32_t ecx = 0;
  uint32_t edx = 0;
};

enum class X86VcpuPtUnavailableReason : uint32_t {
  kNone = 0,
  kNestedHost = 1,
  kIntelPtAbsent = 2,
  kCpuid14Malformed = 3,
  kTopaUnavailable = 4,
  kMultiEntryTopaUnavailable = 5,
  kRtitMsrUnavailable = 6,
  kPmiResourceConflict = 7,
};

// Exact CPUID processor-trace capability identity returned to the VCPU owner.
// VMX controls, RTIT MSR accessibility and PMI ownership are deliberately
// Configure-time conditions rather than discovery-time predicates.
struct X86VcpuPtProperties {
  X86VcpuPtCpuidLeaf leaf_14_0 = {};
  X86VcpuPtCpuidLeaf leaf_14_1 = {};
  uint32_t display_family = 0;
  uint32_t display_model = 0;
  uint32_t stepping = 0;
  X86VcpuPtUnavailableReason unavailable_reason = X86VcpuPtUnavailableReason::kNone;
};

void apic_pmi_interrupt_handler(iframe_t *frame);

// Reports exact hardware/resource availability for the VCPU-only fixed
// retired-instruction counter. |already_reserved| is true only for the VCPU
// asking about the reservation it already owns.
zx_status_t x86_perfmon_vcpu_counter_status(bool already_reserved,
                                            X86VcpuPmuProperties* properties);

// Reserves fixed counter zero and the PMI route globally. The normal perfmon
// service and every other VCPU are excluded until release.
zx_status_t x86_perfmon_reserve_vcpu_counter(X86VcpuPmuProperties* properties);
// If the counter overflow PMI has not reached its handler yet, release is
// deferred until that handler acknowledges the interrupt. Callers may forget
// their local ownership immediately; new reservations remain excluded until
// the deferred release completes.
void x86_perfmon_release_vcpu_counter();

// Programs/stops one guest-only counting interval. The caller has interrupts
// disabled and uses VM-entry/VM-exit IA32_PERF_GLOBAL_CTRL loading so the
// counter is never enabled while host instructions execute.
void x86_perfmon_prepare_vcpu_counter(uint64_t budget, X86VcpuPmuContext* context);
X86VcpuPmuSample x86_perfmon_finish_vcpu_counter(const X86VcpuPmuContext& context);

// Test instrument: increments only when the armed path touches PMU MSRs.
uint64_t x86_perfmon_vcpu_counter_msr_accesses();

// Reports only the architectural CPUID.14/ToPA prerequisites. It performs no
// MSR access, VMX-control check, cross-CPU scan or resource reservation, so it
// is safe for read-only capability discovery.
zx_status_t x86_perfmon_vcpu_pt_status(bool already_reserved, X86VcpuPtProperties* properties);

// Intel PT shares the same host-global PMI route as VCPU instruction budgets
// and ordinary perfmon.  Reservation performs the Configure-time physical-host
// and resource checks and preserves deferred release through the final PMI EOI.
zx_status_t x86_perfmon_reserve_vcpu_pt(X86VcpuPtProperties* properties);
void x86_perfmon_release_vcpu_pt();

// Called after VM exit has cleared TraceEn and the VCPU has latched the PT
// output state.  It keeps the exclusive owner live until the matching PMI is
// acknowledged.
void x86_perfmon_vcpu_pt_pmi_pending();

// Test instrument: capability probing is counted separately; this counter
// changes only when an armed PT path touches IA32_RTIT_* state.
uint64_t x86_perfmon_vcpu_pt_msr_accesses();
void x86_perfmon_vcpu_pt_note_msr_accesses(uint64_t count);

#endif  // ZIRCON_KERNEL_ARCH_X86_INCLUDE_ARCH_X86_PERF_MON_H_

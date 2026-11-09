// Copyright 2020 The Fuchsia Authors
//
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT

// This file is #include'd multiple times with the DEFINE_OPTION macro defined.
// See kernel/lib/boot-options/README.md for details.
//
// These are the x86-specific boot options.

DEFINE_OPTION("kernel.x86.disable_spec_mitigations", bool, x86_disable_spec_mitigations, {false},
              R"""(
If set, disables all speculative execution information leak mitigations.

If unset, the per-mitigation defaults will be used.
)""")

DEFINE_OPTION("kernel.x86.hwp", bool, x86_hwp, {true}, R"""(
This settings enables HWP (hardware P-states) on supported chips. This feature
lets Intel CPUs automatically scale their own clock speed.
)""")

DEFINE_OPTION("kernel.x86.hwp_policy", IntelHwpPolicy, x86_hwp_policy,
              {IntelHwpPolicy::kBiosSpecified}, R"""(
Set a power/performance tradeoff policy of the CPU. x86 CPUs with HWP
(hardware P-state) support can be configured to autonomusly scale their
frequency to favour different policies.

Currently supported policies are:

*   `bios-specified`: Use the power/performance tradeoff policy
    specified in firmware/BIOS settings. If no policy is available, falls back
    to `balanced`.
*   `performance`: Maximise performance.
*   `balanced`: Balance performance / power savings.
*   `power-save`: Reduce power usage, at the cost of lower performance.
*   `stable-performance`: Use settings that keep system performance consistent.
    This may be useful for benchmarking, for example, where keeping performance
    predictable is more important than maximising performance.
)""")

DEFINE_OPTION("kernel.x86.md_clear_on_user_return", bool, x86_md_clear_on_user_return, {true}, R"""(
MDS (Microarchitectural Data Sampling) is a family of speculative execution
information leak bugs that allow the contents of recent loads or stores to be
inferred by hostile code, regardless of privilege level (CVE-2019-11091,
CVE-2018-12126, CVE-2018-12130, CVE-2018-12127). For example, this could allow
user code to read recent kernel loads/stores.

To avoid this bug, it is required that all microarchitectural structures
that could leak data be flushed on trust level transitions. Also, it is
important that trust levels do not concurrently execute on a single physical
processor core.

This option controls whether microarchitectual structures are flushed on
the kernel to user exit path, if possible. It may have a negative performance
impact.

*   If set to true (the default), structures are flushed if the processor is
    vulnerable.
*   If set to false, no flush is executed on structures.
)""")

DEFINE_OPTION("kernel.x86.spec_store_bypass_disable", bool, x86_spec_store_bypass_disable, {false},
              R"""(
Spec-store-bypass (Spectre V4) is a speculative execution information leak
vulnerability that affects many Intel and AMD x86 CPUs. It targets memory
disambiguation hardware to infer the contents of recent stores. The attack
only affects same-privilege-level, intra-process data.

This command line option controls whether a mitigation is enabled. The
mitigation has negative performance impacts.

* If true, the mitigation is enabled on CPUs that need it.
* If false (the default), the mitigation is not enabled.
)""")

DEFINE_OPTION("kernel.x86.turbo", bool, x86_turbo, {true}, R"""(
Turbo Boost or Core Performance Boost are mechanisms that allow processors to
dynamically vary their performance at runtime based on available thermal and
electrical budget. This may provide improved interactive performance at the cost
of performance variability. Some workloads may benefit from disabling Turbo; if
this command line flag is set to false, turbo is disabled for all CPUs in the
system.
)""")

DEFINE_OPTION("kernel.x86.enable_pcid", bool, x86_enable_pcid, {true}, R"""(
This option controls whether PCIDs are used, if there is sufficient CPU support.
If this option is enabled and there is not sufficient CPU support, then this
option has no effect.
)""")

DEFINE_OPTION("kernel.x86.idle_prefer_hlt", bool, x86_idle_prefer_hlt, {false}, R"""(
Idle CPUs normally wait for work with MONITOR/MWAIT when the processor supports
it. Setting this to true makes them use HLT instead, exactly as if the
processor had no MONITOR support. Cross-CPU wakeups then always take the
reschedule-IPI path rather than a write to the monitored cache line.

This is a hardware-triage knob in the spirit of Linux's `idle=halt`: on
firmware whose SMM interacts badly with MWAIT wakeups, an idle CPU can sleep
through its own timer deadline for seconds at a time, which presents as a
near-silent boot stall on an otherwise healthy kernel (measured on an HP
EliteDesk 800 G3: heartbeat gaps of ~3000 ms against a 1000 ms period, idle
MWAIT residencies of 0.6-2 s, and `bootstrap2` progressing ~12 ms/minute).
It costs some idle power and wakeup latency, and is off by default.
)""")

DEFINE_OPTION("kernel.x86.disable_x2apic", bool, x86_disable_x2apic, {false}, R"""(
The local APIC is normally switched into x2APIC mode when the processor
advertises it. Setting this to true keeps it in legacy xAPIC (MMIO) mode,
the same fallback Linux's `nox2apic` provides. Zircon enables x2APIC on the
CPUID bit alone and does not consult the platform's DMAR x2APIC-opt-out
flag, which some OEM firmware sets to declare that x2APIC must not be used
without interrupt remapping; this knob makes that mismatch testable from
the boot command line.
)""")

DEFINE_OPTION("kernel.x86.disable_tsc_deadline", bool, x86_disable_tsc_deadline, {false}, R"""(
The local APIC timer normally runs in TSC-deadline mode when the processor
advertises it. Setting this to true forces one-shot mode instead. Several
Skylake-generation parts have errata in which an armed TSC deadline that
expires while the CPU is in an MWAIT state can be lost (Linux disables the
mode outright on such parts unless a minimum microcode level is present);
this knob makes that hypothesis testable from the boot command line rather
than requiring a kernel rebuild.
)""")

// TODO(https://fxbug.dev/42160387): Unify arch agnostic options.
DEFINE_OPTION("kernel.smp.maxcpus", uint32_t, x86_smp_max_cpus, {32}, R"""(
This option caps the number of CPUs to initialize.  It cannot be greater than *SMP\_MAX\_CPUS*
for a specific architecture.

Note: The default value may vary for each architecture.
)""")

DEFINE_OPTION("kernel.wallclock", WallclockType, x86_wallclock, {WallclockType::kAutoDetect}, R"""(
This option can be used to force the selection of a particular wall clock on pc builds.
)""")

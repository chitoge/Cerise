// cm_config: the minimal standalone producer for /boot/config/component_manager,
// a fuchsia.component.internal.Config blob. This is the ONE bootfs artifact cmc/.cml
// cannot produce (Config is not a component manifest), so it cannot migrate to
// cerise_component. It is a tiny focused tool that emits this Config literal directly.
//
//   argv[1] = output path for config/component_manager
//
// Minimal config for the root component_manager booted from userboot: builtin
// process launcher, boot resolver (fuchsia-boot:/// scheme), klog, single thread,
// ABI-revision allowlist for boot components, a maintained UTC clock, the builtin
// capabilities (elf runner + process.Launcher + resolution.Resolver + boot.Items,
// the six root kernel resources, and narrowly policy-confined service protocols)
// that above-root routing draws from, and a real
// runtime `security_policy` stanza that component_manager actually enforces at
// route time, on top of route_check's build-time lint.
//
// IMPORTANT: this ONE Config is staged into EVERY product's bootfs (see
// bundles/BUILD.bazel:37 and products/BUILD.bazel's four `product_bootfs` maps,
// all pointing at "//src/cerise/cm_config:config/component_manager"). There is no
// per-product cm_config invocation. Every `target_monikers` entry below must
// therefore be justified against the UNION of all eight root-realm variants in
// src/cerise/realms/meta/root_dfv2acpi*.cml, not just one product — see the
// per-entry comments and the capability-routing rules ("Runtime enforcement").

use fidl::persist;
use fidl_fuchsia_component_decl::{Capability, Protocol, Ref, Runner, SelfRef};
use fidl_fuchsia_component_internal::{
    AbiRevisionPolicy, AllowlistedCapability, AllowlistedProtocol, BuiltinBootResolver,
    CapabilityAllowlistEntry, CapabilityPolicyAllowlists, ChildPolicyAllowlists, Config,
    DebugRegistrationPolicyAllowlists, JobPolicyAllowlists, LogDestination, SecurityPolicy,
};
use std::fs;

/// One `capability_policy` allowlist entry for a builtin protocol:
/// `source_moniker: "<component_manager>"` (it's a builtin capability,
/// declared in `builtin_capabilities` below) + `source: self` (matches
/// `CapabilitySource::Builtin` in the vendored routing/policy.rs `get_policy_key`,
/// which maps every builtin capability to `CapabilityAllowlistSource::Self_` — see
/// src/upstream/fuchsia/src/sys/lib/routing/src/policy.rs).
fn builtin_protocol_entry(name: &str, target_monikers: Vec<&str>) -> CapabilityAllowlistEntry {
    CapabilityAllowlistEntry {
        source_moniker: Some("<component_manager>".to_string()),
        source_name: Some(name.to_string()),
        source: Some(Ref::Self_(SelfRef {})),
        capability: Some(AllowlistedCapability::Protocol(AllowlistedProtocol::default())),
        target_monikers: Some(target_monikers.into_iter().map(str::to_string).collect()),
        ..Default::default()
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let out = args.get(1).expect("usage: cm_config <output-path>");

    // ── Who legitimately holds each of the six root kernel resources, derived
    // from src/cerise/realms/meta/*.cml (grepped tree-wide for `fuchsia.kernel.`,
    // cross-checked against the capability-routing rules "Driver-resource
    // hierarchy"). `component_manager`'s policy check (routing::policy::
    // GlobalPolicyChecker::can_route_capability, called from
    // routing::bedrock::with_policy_check at the *consuming* component's `use`
    // site — NOT at every offer hop) only needs the actual `use`rs, not every
    // component the capability is merely offered through:
    //
    //   * "/driver_manager_rust" — the driver_manager realm itself `use`s all six
    //     directly (driver_manager_rust_dfv2acpi.cml:73-78); the generic in-process
    //     `platform-bus` root driver runs in driver_manager's OWN process (fdf
    //     handles are process-local), so the `use` is load-bearing there too, not
    //     vestigial. This moniker is identical across all eight root-realm variants
    //     (root_dfv2acpi{,_console,_console_spike,_diagnostics,_fasync_spike,
    //     _fileserver,_fshost,_netstack3}.cml) — the child is always literally
    //     named "driver_manager_rust", never renamed.
    //   * "/driver_manager_rust/boot-drivers:**" — driver_manager re-offers all six
    //     into its `boot-drivers` collection (driver_manager_rust_dfv2acpi.cml:
    //     137-142), where the compat `platform-bus-x86` board driver `use`s all six
    //     to publish the x86 PCI root (ECAM/ioport, BAR windows, legacy IRQ+MSI,
    //     IOMMU, power) — see capability-routing.md's "residual root-resource
    //     grant" section for why this is irreducible. `:**` (AnyDescendantInCollection)
    //     rather than `:*`: boot-drivers uses `allow_long_names: true` for composite
    //     driver topologies, so a wildcard that also covers descendants is the safe
    //     choice — it costs nothing (the over-privilege lint at build time already
    //     confines who may `use` these to the driver framework + `driver`-runner
    //     components; this is just the runtime mirror of that same boundary).
    //     `driver_host*` deliberately holds ZERO kernel resources (driver_manager
    //     offers them to #boot-drivers only, never to #driver-hosts) — already
    //     least-privilege, so it is NOT in any of these lists.
    //
    // MmioResource and IoportResource ALSO need:
    //   * "/fb_spike" — root_dfv2acpi_console_spike.cml:95-96 offers these two
    //     (only these two) directly to the `fb_spike` Eager child, which drives
    //     QEMU stdvga directly (status_console/meta/fb_spike.cml:11-14 `use`s
    //     both). This is a real, buildable, bootable product
    //     (qemu-x64-console-spike, products/BUILD.bazel:934) that stages the SAME
    //     shared config/component_manager as every other product — omitting this
    //     moniker would deny fb_spike's route and break that product's boot, even
    //     though qemu-x64-console-spike is NOT one of the "six real products"
    //     route_check's positive gate covers (capability-routing.md calls it out
    //     as an intentionally-excluded spike product). This is a deliberate,
    //     narrowly-scoped carve-out for a STAGE-1 de-risk spike, not a driver — it
    //     is exactly the kind of grant the over-privilege lint would flag were
    //     console-spike in scope for that checker. `status_console.cml` (the
    //     non-spike production console) holds NO kernel resources — it acquires
    //     its framebuffer via `cerise.display.Service` instead, so it is correctly
    //     absent from every list below.
    const DRIVER_MGR: &str = "/driver_manager_rust";
    const BOOT_DRIVERS: &str = "/driver_manager_rust/boot-drivers:**";
    const FB_SPIKE: &str = "/fb_spike";
    // The virtual machine monitor, a direct child of the VMM realm's root.
    const CRYOGEN_VMM: &str = "/cryogen_vmm";
    // Multi-instance products use three neutral VMM slots. Product-private
    // configuration decides which image each slot owns; the shared policy only
    // needs to identify the least-privilege component boundary.
    const VMM_SLOTS: &[&str] = &[
        "/cryogen_vmm_1",
        "/cryogen_vmm_2",
        "/cryogen_vmm_3",
    ];
    // Ordinary VM-host workers are dynamic children below the gateway. The
    // wildcard names only that collection; other gateway descendants remain
    // denied by runtime capability policy.
    const VMM_WORKERS: &str = "/vm_gateway/workers:**";
    // The package resolver, a direct child of the root in all three realms that
    // stage it (root_dfv2acpi_pkg, root_dfv2acpi_pkg_update, root_dfv2acpi_console_pkg).
    const PKG_RESOLVER: &str = "/pkg_resolver";

    let capability_policy_allowlist = vec![
        builtin_protocol_entry("fuchsia.kernel.IommuResource", vec![DRIVER_MGR, BOOT_DRIVERS]),
        builtin_protocol_entry(
            "fuchsia.kernel.IoportResource",
            vec![DRIVER_MGR, BOOT_DRIVERS, FB_SPIKE],
        ),
        builtin_protocol_entry("fuchsia.kernel.IrqResource", vec![DRIVER_MGR, BOOT_DRIVERS]),
        builtin_protocol_entry(
            "fuchsia.kernel.MmioResource",
            vec![DRIVER_MGR, BOOT_DRIVERS, FB_SPIKE],
        ),
        builtin_protocol_entry("fuchsia.kernel.MsiResource", vec![DRIVER_MGR, BOOT_DRIVERS]),
        builtin_protocol_entry("fuchsia.kernel.PowerResource", vec![DRIVER_MGR, BOOT_DRIVERS]),
        // Post-mortem gate: the root job goes to the crash_handler
        // component ONLY. crash_handler binds the root job's exception channel to
        // observe every unhandled userspace crash system-wide. This is the whole
        // machine's root job (SAME_RIGHTS), so it is the single most privileged
        // handle a non-driver component holds — hence a runtime allowlist pinned to
        // exactly "/crash_handler" (its moniker in root_crash_handler.cml, a direct
        // child of the root), matching route_check's build-time permitted_privileged_use
        // exception. Two products route RootJob: qemu-x64-crash-handler (the
        // gate) and cf-sz5-vm-host (the real laptop product), each staging
        // crash_handler as a direct child of ITS OWN root realm — so both
        // resolve to the identical moniker "/crash_handler" and this one entry
        // covers both without widening the allowlist.
        builtin_protocol_entry("fuchsia.kernel.RootJob", vec!["/crash_handler"]),
        // PMU path A: the DebugResource (ZX_RSRC_KIND_SYSTEM @ ZX_RSRC_SYSTEM_DEBUG_BASE)
        // goes to the perfmon component ONLY. perfmon uses it to drive
        // zx_mtrace_control(MTRACE_KIND_PERFMON) and read raw hardware performance
        // counters. Like RootJob, this is a runtime allowlist pinned to exactly
        // "/perfmon" (its moniker in root_perfmon.cml, a direct child of the root),
        // matching route_check's build-time permitted_privileged_use exception. Only the
        // qemu-x64-perfmon product routes DebugResource at all — and only that product
        // sets kernel.enable-debugging-syscalls=true, without which the syscall itself
        // is refused. + capability-routing.md.
        builtin_protocol_entry("fuchsia.kernel.DebugResource", vec!["/perfmon"]),
        // Status panel: the DECODED kernel stats go to status_console ONLY. Unlike every
        // other entry in this list, fuchsia.kernel.Stats vends no handle — component_manager
        // keeps the ZX_RSRC_SYSTEM_INFO_BASE resource its builtin derived and answers
        // GetMemoryStats/GetCpuStats from it (component_manager/lib/builtins/src/
        // kernel_stats.rs). It is pinned anyway, on the same principle as RootJob and
        // DebugResource: it is systemwide telemetry, exactly one component has a reason to
        // read it, and an unenforced capability is one nobody notices spreading.
        //
        // "/status_console" is the moniker in BOTH realms that stage the console —
        // root_dfv2acpi_console.cml and root_dfv2acpi_console_pkg.cml each declare the child
        // literally as `status_console`, a direct child of the root, so this one moniker
        // covers qemu-x64-console, qemu-x64-console-pkg, hw-x64-firstlight and
        // cf-sz5-firstlight. The console-SPIKE product stages `fb_spike`, not the console,
        // and routes no Stats, so it is unaffected. Products that never route Stats perform
        // no such route and are likewise unaffected.
        builtin_protocol_entry("fuchsia.kernel.Stats", vec!["/status_console"]),
        // Virtualization: the HYPERVISOR resource goes to the VMM only. This is the
        // resource `zx_guest_create` validates against — a SYSTEM child at
        // ZX_RSRC_SYSTEM_HYPERVISOR_BASE, size 1 — and holding it is the difference
        // between a process that can create a guest partition and one that cannot.
        // There is no narrower door: the kernel offers no "hypervisor service" that
        // owns the resource and hands out guests, so the VMM holds it directly.
        // Pinned to exactly "/cryogen_vmm", matching route_check's build-time
        // permitted_privileged_use exception.
        builtin_protocol_entry(
            "fuchsia.kernel.HypervisorResource",
            std::iter::once(CRYOGEN_VMM)
                .chain(VMM_SLOTS.iter().copied())
                .chain(std::iter::once(VMM_WORKERS))
                .collect(),
        ),
        // Virtualization + packages: VMEX, and this entry CHANGES BEHAVIOUR for an
        // existing consumer, so read the moniker list before editing it.
        //
        // Until now `fuchsia.kernel.VmexResource` was listed as a builtin and had NO
        // capability_policy entry at all, which under
        // GlobalPolicyChecker::can_route_capability means `None => Ok(())` —
        // unenforced, routable to anyone a realm cares to offer it to. Adding an
        // entry switches it to default-deny, so **every** legitimate user must be
        // named here or its route fails at runtime with a policy error.
        //
        // There are two:
        //   * "/pkg_resolver" — already uses it (realms/meta/pkg_resolver.cml), to
        //     grant EXECUTE to blobs it serves as a launched component's /pkg. It is
        //     a direct child of the root in all three realms that stage it. Omitting
        //     it would break the packaged app tier at runtime, and nothing at build
        //     time would say so.
        //   * "/cryogen_vmm" — the VMM re-mints its guest-RAM VMO executable
        //     (`zx_vmo_replace_as_executable`), because zx_vmo_create grants no
        //     ZX_RIGHT_EXECUTE and the guest firmware fetches every one of its
        //     instructions out of that VMO.
        //
        // Two resources, not one, and this is the single most likely way to get a
        // confusing failure: `sys_guest_create` validates SYSTEM @
        // ZX_RSRC_SYSTEM_HYPERVISOR_BASE and `sys_vmo_replace_as_executable`
        // validates SYSTEM @ ZX_RSRC_SYSTEM_VMEX_BASE. A HypervisorResource child is
        // base 0 size 1 and does NOT satisfy the vmex check; the VMM gets away with a
        // single handle under userboot only because PA_SYSTEM_RESOURCE is the ranged
        // ROOT system resource, which short-circuits the base check entirely.
        builtin_protocol_entry(
            "fuchsia.kernel.VmexResource",
            std::iter::once(PKG_RESOLVER)
                .chain(std::iter::once(CRYOGEN_VMM))
                .chain(VMM_SLOTS.iter().copied())
                .chain(std::iter::once(VMM_WORKERS))
                .collect(),
        ),
        // Production diagnostics: only the eager root Archivist may acquire a
        // readable kernel debuglog handle. Other products use the same global
        // component-manager config but do not route this builtin, so the policy
        // entry is inert there. Write-only DLOG producers need no resource and
        // therefore receive no related capability.
        builtin_protocol_entry("fuchsia.boot.ReadOnlyLog", vec!["/archivist"]),
    ];

    let config = Config {
        use_builtin_process_launcher: Some(true),
        log_destination: Some(LogDestination::Klog),
        builtin_boot_resolver: Some(BuiltinBootResolver::Boot),
        num_threads: Some(1),
        // NOT narrowed (item 2, deliberate deferral — documented in
        // the capability-routing rules "Runtime enforcement"). component_manager
        // checks ABI revision compatibility at EVERY component's Resolve action
        // (src/sys/component_manager/src/model/actions/resolve.rs:89-99), and
        // src/sys/lib/cm_config's `AbiRevisionPolicy::check_compatibility` hard-fails
        // resolution (`CompatibilityCheckError::AbiRevisionAbsent`) for any
        // NON-allowlisted component whose *resolved* `abi_revision` (component_info.
        // abi_revision, supplied by the resolver — not something this comment claims
        // to know the exact provenance of) is absent. A tree-wide grep found NO
        // ABI-revision stamping wired into any cmc/build invocation in this repo, and
        // there is no way to verify at host-build time that every boot
        // component resolves with a valid embedded revision. Narrowing this allowlist
        // away from "everyone" therefore risks turning ABI-compatibility (largely
        // irrelevant to Cerise, which does not do cross-version rolling software
        // updates) into a boot-breaking `AbiRevisionAbsent`/`TooNew`/`Retired` hard
        // failure for components that resolve fine today. The wide-open allowlist is
        // therefore load-bearing until proven otherwise; narrowing it safely needs a
        // QEMU boot verification pass that is not run at host-build time (disk
        // budget) and is instead covered by the QEMU boot test.
        abi_revision_policy: Some(AbiRevisionPolicy {
            allowlist: Some(vec!["/".to_string(), "/**".to_string()]),
            ..Default::default()
        }),
        maintain_utc_clock: Some(true),
        // Runtime enforcement: component_manager's capability_policy is
        // opt-in per (source_moniker, source_name, source, capability) — see
        // GlobalPolicyChecker::can_route_capability in
        // src/upstream/fuchsia/src/sys/lib/routing/src/policy.rs: `None => Ok(())`
        // when no entry exists, `Some(entries) => target must match` when one does.
        // Adding an entry for a capability therefore SWITCHES that capability from
        // "unenforced" to "default-deny except these monikers" — a wrong/missing
        // target moniker here is a silent build-time no-op that becomes a LOUD,
        // attributable runtime failure at boot ("Security policy prevented `<cap>`
        // ... being routed to `<moniker>`"), not a hang or silent misbehavior.
        security_policy: Some(SecurityPolicy {
            capability_policy: Some(CapabilityPolicyAllowlists {
                allowlist: Some(capability_policy_allowlist),
                ..Default::default()
            }),
            // No component in the tree requests any of these three job-policy flags
            // in its `program` block (grepped tree-wide for main_process_critical /
            // job_policy_ambient_mark_vmo_exec / job_policy_create_raw_processes across
            // every staged .cml — archivist.cml even calls out deliberately NOT
            // setting main_process_critical). Empty allowlists are therefore a pure
            // least-privilege win: zero behavior change today, and a loud, attributable
            // policy-error failure (not silent misbehavior) if a future component ever
            // requests one without also updating this list.
            job_policy: Some(JobPolicyAllowlists {
                ambient_mark_vmo_exec: Some(vec![]),
                main_process_critical: Some(vec![]),
                create_raw_processes: Some(vec![]),
                ..Default::default()
            }),
            // No `environments[].debug` registration exists anywhere in the tree
            // (grepped every staged .cml) — empty allowlist matches reality exactly.
            debug_registration_policy: Some(DebugRegistrationPolicyAllowlists {
                allowlist: Some(vec![]),
                ..Default::default()
            }),
            // No component sets `on_terminate: "reboot"` on a child anywhere in the
            // tree — empty allowlist matches reality exactly.
            child_policy: Some(ChildPolicyAllowlists {
                reboot_on_terminate: Some(vec![]),
                ..Default::default()
            }),
            ..Default::default()
        }),
        builtin_capabilities: Some(vec![
            Capability::Runner(Runner {
                name: Some("builtin_elf_runner".to_string()),
                ..Default::default()
            }),
            Capability::Protocol(Protocol {
                name: Some("fuchsia.process.Launcher".to_string()),
                ..Default::default()
            }),
            Capability::Protocol(Protocol {
                name: Some("fuchsia.component.resolution.Resolver".to_string()),
                ..Default::default()
            }),
            Capability::Protocol(Protocol {
                name: Some("fuchsia.boot.Items".to_string()),
                ..Default::default()
            }),
            // Production diagnostics: component_manager retains the privileged
            // readable DebugLog creation path and vends it only through this
            // protocol. Runtime capability policy above pins the sole consumer
            // to the eager /archivist child.
            Capability::Protocol(Protocol {
                name: Some("fuchsia.boot.ReadOnlyLog".to_string()),
                ..Default::default()
            }),
            Capability::Protocol(Protocol {
                name: Some("fuchsia.kernel.IommuResource".to_string()),
                ..Default::default()
            }),
            Capability::Protocol(Protocol {
                name: Some("fuchsia.kernel.IoportResource".to_string()),
                ..Default::default()
            }),
            Capability::Protocol(Protocol {
                name: Some("fuchsia.kernel.IrqResource".to_string()),
                ..Default::default()
            }),
            Capability::Protocol(Protocol {
                name: Some("fuchsia.kernel.MmioResource".to_string()),
                ..Default::default()
            }),
            Capability::Protocol(Protocol {
                name: Some("fuchsia.kernel.MsiResource".to_string()),
                ..Default::default()
            }),
            Capability::Protocol(Protocol {
                name: Some("fuchsia.kernel.PowerResource".to_string()),
                ..Default::default()
            }),
            // Packages: the VMEX resource, so a component that serves EXECUTABLE
            // blobs from the fxfs blob volume can grant EXECUTE (replace_as_executable). Only
            // pkg_resolver `use`s it — to serve a launched component's /pkg (binary + libs) from
            // disk blobs — routed to it by the x64-pkg realm (root_dfv2acpi_pkg.cml). Like every
            // builtin above, it must be listed here to be routable from above-root
            // (add_builtin_protocol_if_enabled silently omits an unlisted builtin). Additive:
            // products that don't route it are unaffected. VmexResource has NO capability_policy
            // allowlist entry, so runtime policy leaves it unenforced (None => Ok); the build-time
            // guard is route_check's over-privilege lint, which permits precisely
            // (pkg_resolver, VmexResource) and (cryogen_vmm, VmexResource).
            //
            // It now ALSO has a capability_policy allowlist entry (see above), naming
            // both /pkg_resolver and /cryogen_vmm, so runtime policy default-denies it
            // to everyone else. That is a change from "unenforced" and the reason the
            // moniker list has to be complete rather than merely correct.
            Capability::Protocol(Protocol {
                name: Some("fuchsia.kernel.VmexResource".to_string()),
                ..Default::default()
            }),
            // Virtualization: the HYPERVISOR resource builtin. component_manager's
            // builtin_environment creates a SYSTEM child at
            // ZX_RSRC_SYSTEM_HYPERVISOR_BASE (size 1) and serves
            // fuchsia.kernel.HypervisorResource from it; that is the resource
            // `zx_guest_create` validates against, so without this entry the protocol
            // is minted in-process and simply unroutable —
            // add_builtin_protocol_if_enabled returns silently for a name absent from
            // this list, and the failure mode is a capability that is not there with
            // no log line to say so. Only cryogen_vmm `use`s it. Additive: products
            // that don't route it are unaffected. It HAS a capability_policy allowlist
            // entry (pinned to /cryogen_vmm), so runtime policy default-denies it to
            // everyone else. The build-time guard is route_check's over-privilege lint,
            // which permits precisely (cryogen_vmm, HypervisorResource).
            Capability::Protocol(Protocol {
                name: Some("fuchsia.kernel.HypervisorResource".to_string()),
                ..Default::default()
            }),
            // Post-mortem gate: the root job builtin, served by
            // component_manager's root_job builtin (a SAME_RIGHTS duplicate of its
            // own default/root job). Only crash_handler `use`s it — to bind the
            // root job's exception channel and observe every unhandled userspace
            // crash — routed to it by both realms that stage a crash_handler
            // child (root_crash_handler.cml, the post-mortem gate, and
            // root_laptop_vm_host.cml, the cf-sz5-vm-host product). Like every
            // builtin above it must be listed
            // here to be routable from above-root (add_builtin_protocol_if_enabled
            // silently omits an unlisted builtin). Additive: products that don't
            // route it are unaffected. Unlike VmexResource, RootJob HAS a
            // capability_policy allowlist entry (pinned to /crash_handler), so
            // runtime policy default-denies it to everyone else. The build-time
            // guard is route_check's over-privilege lint, which permits precisely
            // (crash_handler, RootJob).
            Capability::Protocol(Protocol {
                name: Some("fuchsia.kernel.RootJob".to_string()),
                ..Default::default()
            }),
            // PMU path A: the DebugResource builtin (component_manager's
            // builtin_environment creates a ZX_RSRC_SYSTEM_DEBUG_BASE child of the
            // system resource and serves fuchsia.kernel.DebugResource). Only perfmon
            // `use`s it — to drive zx_mtrace_control(MTRACE_KIND_PERFMON) — routed to it
            // by the x64-perfmon realm (root_perfmon.cml). Like every builtin above it
            // must be listed here to be routable from above-root
            // (add_builtin_protocol_if_enabled silently omits an unlisted builtin).
            // Additive: products that don't route it are unaffected. Like RootJob it HAS
            // a capability_policy allowlist entry (pinned to /perfmon), so runtime policy
            // default-denies it to everyone else. The build-time guard is route_check's
            // over-privilege lint, which permits precisely (perfmon, DebugResource). See
            Capability::Protocol(Protocol {
                name: Some("fuchsia.kernel.DebugResource".to_string()),
                ..Default::default()
            }),
            // Orderly-shutdown chain. fuchsia.sys2.SystemController lets a routed
            // component drive component_manager's reverse-dependency topology teardown;
            // fuchsia.kernel.MexecResource is the second resource driver_manager's
            // shutdown_manager requires (alongside PowerResource) before it will issue
            // the final zx_system_powerctl. Both are derived from the same system
            // resource handle as the other builtins and are additive: products that
            // don't route them are unaffected.
            Capability::Protocol(Protocol {
                name: Some("fuchsia.sys2.SystemController".to_string()),
                ..Default::default()
            }),
            Capability::Protocol(Protocol {
                name: Some("fuchsia.kernel.MexecResource".to_string()),
                ..Default::default()
            }),
            // Status panel: the kernel stats builtin. component_manager's
            // builtin_environment derives a ZX_RSRC_SYSTEM_INFO_BASE child of the system
            // resource, KEEPS it, and serves fuchsia.kernel.Stats from it — so a consumer
            // gets decoded memory/CPU numbers and never a handle. The alternative,
            // fuchsia.kernel.InfoResource, reaches the same kernel gate but hands the
            // resource itself over; it is deliberately NOT listed here, so it stays
            // unroutable. Only status_console `use`s Stats, routed to it by the two console
            // realms. Like every builtin above it must be listed here to be routable from
            // above-root at all (add_builtin_protocol_if_enabled silently omits an unlisted
            // builtin — the failure mode is a capability that simply is not there, with no
            // log line to say so). Additive: products that don't route it are unaffected.
            // It HAS a capability_policy allowlist entry (pinned to /status_console), so
            // runtime policy default-denies it to everyone else. The build-time guard is
            // route_check's over-privilege lint, which permits precisely
            // (status_console, Stats).
            Capability::Protocol(Protocol {
                name: Some("fuchsia.kernel.Stats".to_string()),
                ..Default::default()
            }),
            // The shutdown-shim builtin runner (registered in component_manager's
            // builtin_runner.rs). Like builtin_elf_runner, a builtin runner must be
            // listed here to be routable from above-root, else routing rejects it with
            // "is not a built-in capability".
            Capability::Runner(Runner {
                name: Some("builtin_shutdown_shim".to_string()),
                ..Default::default()
            }),
        ]),
        ..Default::default()
    };

    let bytes = persist(&config).expect("failed to persist Config");
    fs::write(out, &bytes).expect("failed to write config/component_manager");
}

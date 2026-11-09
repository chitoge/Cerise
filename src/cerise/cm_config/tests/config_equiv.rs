// Two independent gates on config/component_manager (fuchsia.component.internal.Config):
//
//   1. `standalone_producer_matches_golden` — byte-for-byte equality against a
//      checked-in golden (goldens/component_manager). This is a pure regression
//      freeze: it proves cm_config's output hasn't silently drifted since the last
//      deliberate review, nothing more. It does NOT prove the security_policy
//      content is correct — a wrong moniker baked into main.rs would freeze into
//      the golden just as happily as a right one. (Historical note: this golden was
//      once a frozen reference output and the test proved byte-identity to it; that
//      equivalence claim is no longer what this test proves, since the security
//      policy has no earlier precedent to match. It is now a plain
//      future-regression gate.)
//
//   2. `security_policy_matches_realm_topology` — decodes the produced Config with
//      the VENDORED `cm_config`/`cm_rust`/`moniker` crates (the exact code
//      component_manager itself runs at boot to parse this blob and enforce
//      routing — see routing::policy::GlobalPolicyChecker::can_route_capability)
//      and asserts the policy content directly: which monikers are, and are not,
//      allowed to route each privileged builtin protocol. This is the
//      machine-verified check asks for — a hand-edited golden can't lie
//      about it, because the assertions are against parsed policy semantics
//      (AllowlistEntry::matches), not raw bytes. It cannot prove the allowlisted
//      monikers correspond to REAL components in the realm .cml (that's the
//      cross-check documented inline in main.rs and in
//      the capability-routing rules, verified by route_check + the
//      the QEMU boot test); it proves the policy this tool emits says what main.rs
//      claims it says.

use cm_config::{CapabilityAllowlistKey, CapabilityAllowlistSource, RuntimeConfig};
use cm_rust::CapabilityTypeName;
use fidl_fuchsia_component_internal::Config;
use moniker::{ExtendedMoniker, Moniker};

fn read(key: &str) -> Vec<u8> {
    let p = std::env::var(key).unwrap_or_else(|_| panic!("env {key} unset"));
    std::fs::read(&p).unwrap_or_else(|e| panic!("read {p}: {e}"))
}

#[test]
fn standalone_producer_matches_golden() {
    let mine = read("MINE");
    let gt = read("GT");
    assert_eq!(mine, gt, "config/component_manager bytes must match the checked-in golden");

    let mine_cfg: Config = fidl::unpersist(&mine).expect("decode mine");
    let gt_cfg: Config = fidl::unpersist(&gt).expect("decode gt");
    assert_eq!(mine_cfg, gt_cfg, "decoded Config must match");
    // Spot-assert the load-bearing fields survived the extraction.
    assert_eq!(mine_cfg.use_builtin_process_launcher, Some(true));
    assert_eq!(mine_cfg.num_threads, Some(1));
    assert_eq!(
        mine_cfg.builtin_capabilities.as_ref().map(|v| v.len()),
        Some(19),
        "19 builtin capabilities (elf runner + shutdown-shim runner + 17 protocols): the \
         shutdown chain (SystemController, MexecResource, shutdown-shim runner), \
         the production Archivist's fuchsia.boot.ReadOnlyLog, \
         the fuchsia.kernel.VmexResource (pkg_resolver), the \
         fuchsia.kernel.RootJob (routed to crash_handler for the root-job exception channel), \
         PMU path A's fuchsia.kernel.DebugResource (routed to perfmon for \
         zx_mtrace_control), and the status panel's fuchsia.kernel.Stats (routed to \
         status_console for ZX_INFO_KMEM_STATS/ZX_INFO_CPU_STATS as DECODED numbers — \
         fuchsia.kernel.InfoResource, which would hand over the resource HANDLE for the \
         same two topics, is deliberately NOT listed and so stays unroutable), and \
         virtualization's fuchsia.kernel.HypervisorResource (routed to cryogen_vmm, \
         the resource zx_guest_create validates against)"
    );
}

/// Look up the capability_policy entry for a builtin protocol (`source: self`,
/// `source_moniker: <component_manager>`).
fn builtin_protocol_targets<'a>(
    policy: &'a std::collections::HashMap<CapabilityAllowlistKey, std::collections::HashSet<cm_config::AllowlistEntry>>,
    name: &str,
) -> &'a std::collections::HashSet<cm_config::AllowlistEntry> {
    let key = CapabilityAllowlistKey {
        source_moniker: ExtendedMoniker::ComponentManager,
        source_name: name.parse().unwrap_or_else(|_| panic!("invalid capability name {name}")),
        source: CapabilityAllowlistSource::Self_,
        capability: CapabilityTypeName::Protocol,
    };
    policy
        .get(&key)
        .unwrap_or_else(|| panic!("no capability_policy entry for {name} (source=self, source_moniker=<component_manager>)"))
}

fn matches_any(entries: &std::collections::HashSet<cm_config::AllowlistEntry>, moniker: &str) -> bool {
    let m = Moniker::parse_str(moniker).unwrap_or_else(|e| panic!("bad test moniker {moniker}: {e}"));
    entries.iter().any(|e| e.matches(&m))
}

#[test]
fn security_policy_matches_realm_topology() {
    let mine = read("MINE");
    let fidl_cfg: Config = fidl::unpersist(&mine).expect("decode config");
    let cfg = RuntimeConfig::try_from(fidl_cfg).expect(
        "config/component_manager must parse through the same cm_config::RuntimeConfig \
         conversion component_manager runs at boot",
    );

    // job_policy: nothing in the realm .cml tree requests these flags, so all three
    // allowlists must be empty (present-but-empty, i.e. explicit deny-by-default —
    // not "unset", which would be a different, unenforced state upstream).
    assert!(
        cfg.security_policy.job_policy.main_process_critical.is_empty(),
        "no component requests main_process_critical"
    );
    assert!(
        cfg.security_policy.job_policy.ambient_mark_vmo_exec.is_empty(),
        "no component requests job_policy_ambient_mark_vmo_exec"
    );
    assert!(
        cfg.security_policy.job_policy.create_raw_processes.is_empty(),
        "no component requests job_policy_create_raw_processes"
    );
    assert!(
        cfg.security_policy.debug_capability_policy.is_empty(),
        "no environment registers a debug capability"
    );
    assert!(
        cfg.security_policy.child_policy.reboot_on_terminate.is_empty(),
        "no component sets on_terminate: reboot"
    );

    // capability_policy: all six kernel resources must have an entry (that's what
    // switches them from "unenforced" to "default-deny except these monikers" — see
    // GlobalPolicyChecker::can_route_capability's `None => Ok(())` vs `Some(entries)`
    // branches in the vendored routing crate).
    let policy = &cfg.security_policy.capability_policy;
    assert_eq!(
        policy.len(),
        12,
        "exactly the six fuchsia.kernel.*Resource entries plus the \
         fuchsia.kernel.RootJob entry plus PMU path A's fuchsia.kernel.DebugResource \
         entry plus the status panel's fuchsia.kernel.Stats entry plus \
         virtualization's fuchsia.kernel.HypervisorResource and \
         fuchsia.kernel.VmexResource entries plus the production Archivist's \
         fuchsia.boot.ReadOnlyLog entry, no more"
    );

    for name in [
        "fuchsia.kernel.IommuResource",
        "fuchsia.kernel.IrqResource",
        "fuchsia.kernel.MsiResource",
        "fuchsia.kernel.PowerResource",
    ] {
        let entries = builtin_protocol_targets(policy, name);
        assert!(matches_any(entries, "/driver_manager_rust"), "{name}: driver_manager_rust itself uses this (driver_manager_rust_dfv2acpi.cml)");
        assert!(
            matches_any(entries, "/driver_manager_rust/boot-drivers:platform-bus-x86"),
            "{name}: platform-bus-x86 (boot-drivers collection member) uses this"
        );
        assert!(
            !matches_any(entries, "/fb_spike"),
            "{name}: fb_spike is only offered Mmio/Ioport, not {name}"
        );
        assert!(
            !matches_any(entries, "/status_console"),
            "{name}: status_console holds NO kernel resource handle - its framebuffer comes from cerise.display.Service and its numbers from fuchsia.kernel.Stats, which vends no handle"
        );
        assert!(
            !matches_any(entries, "/driver_host_dfv2"),
            "{name}: driver_host holds ZERO kernel resources (offered to #boot-drivers only, never #driver-hosts)"
        );
        assert!(
            !matches_any(entries, "/cryogen_vmm"),
            "{name}: the VMM holds exactly two kernel resources — HypervisorResource and \
             VmexResource — and no device resource of any kind"
        );
    }

    // Mmio/Ioport additionally cover fb_spike (root_dfv2acpi_console_spike.cml:95-96).
    for name in ["fuchsia.kernel.MmioResource", "fuchsia.kernel.IoportResource"] {
        let entries = builtin_protocol_targets(policy, name);
        assert!(matches_any(entries, "/driver_manager_rust"), "{name}: driver_manager_rust itself uses this");
        assert!(
            matches_any(entries, "/driver_manager_rust/boot-drivers:platform-bus-x86"),
            "{name}: platform-bus-x86 uses this"
        );
        assert!(
            matches_any(entries, "/fb_spike"),
            "{name}: fb_spike (qemu-x64-console-spike) is directly offered this and uses it"
        );
        assert!(
            !matches_any(entries, "/status_console"),
            "{name}: status_console holds no kernel resource handle; fuchsia.kernel.Stats is the only fuchsia.kernel.* capability it may route, and that one vends no handle"
        );
        assert!(
            !matches_any(entries, "/netstack3"),
            "{name}: netstack3 is an application, not the driver framework or a driver"
        );
        assert!(
            !matches_any(entries, "/cryogen_vmm"),
            "{name}: the VMM traps its guest's IO and MMIO through the hypervisor, not \
             through a device resource"
        );
    }

    // Virtualization: fuchsia.kernel.HypervisorResource is default-deny except
    // /cryogen_vmm — the only component that may call zx_guest_create. Not the
    // driver framework, and specifically NOT the package resolver, which holds the
    // other half of the VMM's pair (VmexResource) and must not accumulate this one.
    {
        let entries = builtin_protocol_targets(policy, "fuchsia.kernel.HypervisorResource");
        assert!(
            matches_any(entries, "/cryogen_vmm"),
            "HypervisorResource: the VMM is the sole allowed user"
        );
        assert!(
            !matches_any(entries, "/driver_manager_rust"),
            "HypervisorResource: the driver framework creates no guest partitions"
        );
        assert!(
            !matches_any(entries, "/driver_manager_rust/boot-drivers:platform-bus-x86"),
            "HypervisorResource: no driver creates a guest partition"
        );
        assert!(
            !matches_any(entries, "/pkg_resolver"),
            "HypervisorResource: the resolver holds VmexResource, not this"
        );
    }

    // Virtualization + packages: VmexResource. This one has TWO legitimate users and
    // the second was easy to lose — until this entry existed the capability had no
    // policy at all, i.e. `None => Ok(())`, unenforced. Adding the entry switched it
    // to default-deny, so an incomplete moniker list would have broken the packaged
    // app tier at runtime with nothing at build time to say so. Both are asserted
    // here for exactly that reason.
    {
        let entries = builtin_protocol_targets(policy, "fuchsia.kernel.VmexResource");
        assert!(
            matches_any(entries, "/pkg_resolver"),
            "VmexResource: the package resolver grants EXECUTE to blobs it serves as a \
             launched component's /pkg — it used this before any policy entry existed, \
             and pinning the capability must not have taken it away"
        );
        assert!(
            matches_any(entries, "/cryogen_vmm"),
            "VmexResource: the VMM re-mints its guest-RAM VMO executable, because \
             zx_vmo_create grants no ZX_RIGHT_EXECUTE and the guest firmware fetches \
             every instruction out of it"
        );
        assert!(
            !matches_any(entries, "/driver_manager_rust"),
            "VmexResource: the driver framework mints no executable VMOs"
        );
        assert!(
            !matches_any(entries, "/status_console"),
            "VmexResource: the console runs no code but its own"
        );
        assert!(
            !matches_any(entries, "/pkg_fetcher"),
            "VmexResource: the fetcher downloads blobs; the resolver is what makes them \
             executable"
        );
    }

    // Post-mortem gate: fuchsia.kernel.RootJob is default-deny except
    // /crash_handler — the ONLY component that may bind the root job's exception
    // channel. It must NOT reach the driver framework or any other component.
    {
        let entries = builtin_protocol_targets(policy, "fuchsia.kernel.RootJob");
        assert!(
            matches_any(entries, "/crash_handler"),
            "RootJob: crash_handler is the sole allowed user (root_crash_handler.cml)"
        );
        assert!(
            !matches_any(entries, "/driver_manager_rust"),
            "RootJob: the driver framework must NOT get the root job"
        );
        assert!(
            !matches_any(entries, "/driver_manager_rust/boot-drivers:platform-bus-x86"),
            "RootJob: no driver gets the root job"
        );
        assert!(
            !matches_any(entries, "/crasher"),
            "RootJob: the crasher fixture holds no capabilities"
        );
    }

    // PMU path A: fuchsia.kernel.DebugResource is default-deny except /perfmon — the
    // ONLY component that may drive zx_mtrace_control(MTRACE_KIND_PERFMON). It must NOT
    // reach the driver framework or any other component.
    {
        let entries = builtin_protocol_targets(policy, "fuchsia.kernel.DebugResource");
        assert!(
            matches_any(entries, "/perfmon"),
            "DebugResource: perfmon is the sole allowed user (root_perfmon.cml)"
        );
        assert!(
            !matches_any(entries, "/driver_manager_rust"),
            "DebugResource: the driver framework must NOT get the debug resource"
        );
        assert!(
            !matches_any(entries, "/crash_handler"),
            "DebugResource: crash_handler holds RootJob, not DebugResource"
        );
    }

    // Status panel: fuchsia.kernel.Stats is default-deny except /status_console.
    // Unlike every other entry above, this one vends no HANDLE — component_manager
    // keeps the ZX_RSRC_SYSTEM_INFO_BASE resource and answers GetMemoryStats /
    // GetCpuStats from it. It is pinned anyway because it is systemwide telemetry with
    // exactly one legitimate reader.
    {
        let entries = builtin_protocol_targets(policy, "fuchsia.kernel.Stats");
        assert!(
            matches_any(entries, "/status_console"),
            "Stats: status_console is the sole allowed user (both console realms name \
             the child `status_console`)"
        );
        assert!(
            !matches_any(entries, "/driver_manager_rust"),
            "Stats: the driver framework has no reason to read systemwide memory/CPU stats"
        );
        assert!(
            !matches_any(entries, "/driver_manager_rust/boot-drivers:platform-bus-x86"),
            "Stats: no driver reads systemwide memory/CPU stats"
        );
        assert!(
            !matches_any(entries, "/fileserver"),
            "Stats: the file server publishes storage state, it does not read kernel stats"
        );
        assert!(
            !matches_any(entries, "/fb_spike"),
            "Stats: the framebuffer spike reads no stats"
        );
    }

    // Production diagnostics: the readable kernel log is default-deny except
    // for the eager root Archivist. cerise_logsink creates only a write-only
    // DebugLog with an invalid resource and therefore needs no builtin handle.
    {
        let entries = builtin_protocol_targets(policy, "fuchsia.boot.ReadOnlyLog");
        assert!(
            matches_any(entries, "/archivist"),
            "ReadOnlyLog: /archivist is the sole allowed DLOG reader"
        );
        for denied in [
            "/cerise_logsink",
            "/driver_index",
            "/driver_manager_rust",
            "/vm_gateway",
            "/vm_gateway/workers:vm-1",
        ] {
            assert!(
                !matches_any(entries, denied),
                "ReadOnlyLog must not route to {denied}"
            );
        }
    }

    // abi_revision_policy is deliberately left wide-open — see main.rs's inline
    // rationale (cmc does not stamp abi_revision; narrowing hard-fails resolution
    // for any non-allowlisted component). Drive the REAL production entrypoint
    // (`AbiRevisionPolicy::check_compatibility`, the exact call
    // model/actions/resolve.rs makes at every component's Resolve action) with a
    // missing ABI revision on an arbitrary deep moniker; it must still resolve Ok,
    // proving the allowlist still covers "everyone". If a future edit narrows this
    // allowlist, this assertion fails here instead of only at boot.
    let arbitrary_deep_moniker = Moniker::parse_str("/some/arbitrary/deeply/nested/component")
        .expect("valid moniker syntax");
    assert_eq!(
        cfg.abi_revision_policy.check_compatibility(
            &version_history_data::HISTORY,
            &arbitrary_deep_moniker,
            None,
        ),
        Ok(()),
        "abi_revision_policy must remain wide-open (\"/\", \"/**\") until cmc stamps abi_revision \
         into compiled .cm files; see main.rs's inline rationale"
    );
}

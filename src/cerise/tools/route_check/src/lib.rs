// route_check — a build-time checker over the compiled CFv2 component graph.
//
// Motivation: Fuchsia's component_manager
// resolves capability routing and enforces the security policy allowlist at
// RUNTIME. A "forgot to offer" bug or an over-privileged component is therefore
// discovered only when the guest boots and the route fails (or, worse, silently
// succeeds). Cerise assembles its realms from real `.cml` compiled to `.cm` at
// BUILD time, so we can decode that same `.cm` graph with the vendored `cm_rust`
// and verify two properties statically, before anything boots:
//
//   1. OVER-PRIVILEGE LINT (least-privilege). No component may `use` a privileged
//      kernel/root resource protocol (fuchsia.kernel.* — MmioResource,
//      IoportResource, IrqResource, SmcResource, PowerResource, RootJob, ... —
//      or fuchsia.boot.RootResource) unless it is the driver framework
//      (driver_manager_rust / driver_host / driver_index) or an actual driver
//      component (runs under the `driver` runner). This is the security win: an
//      application/service/probe that reaches for raw MMIO fails the build.
//
//   2. ROUTING COMPLETENESS. For every `use` of a protocol/service/directory that
//      names `parent` as its source, some ancestor realm must actually `offer`
//      that capability to this component (matched by capability type + delivered
//      name + target child). This catches the common "forgot to offer" bug.
//
// Mechanism: parse each `.cm` (persistent FIDL fuchsia.component.decl.Component)
// with `fidl::unpersist` + `cm_rust`'s `FidlIntoNative` into a native
// `cm_rust::ComponentDecl`, then walk the static realm tree from a product's root
// `.cm`, resolving statically-declared children by their bootfs URL
// (fuchsia-boot:///pkg#meta/<name>.cm) against a caller-supplied pool of `.cm`
// files. Dynamic constructs that cannot be resolved statically (collection /
// aggregated-service sources, dictionaries, environment-provided runners) are
// explicitly WHITELISTED here rather than false-positived — see the notes inline
// and in the module docs. This is deliberately NOT a reimplementation of
// component_manager's full router; it is the tractable high-value core.

use cm_rust::{ComponentDecl, FidlIntoNative, OfferDeclCommon, SourceName, UseDeclCommon};
use fidl_fuchsia_component_decl as fdecl;
use std::collections::BTreeMap;

/// The two classes of finding this checker emits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// A component `use`s a privileged capability it is not permitted to use.
    OverPrivilege,
    /// A component `use`s a capability from `parent` that no ancestor offers it.
    Routing,
}

/// A single build-time violation, with enough context to fix it by hand.
#[derive(Debug, Clone)]
pub struct Violation {
    pub kind: Kind,
    pub product: String,
    /// Slash-delimited moniker of the offending component within the realm.
    pub moniker: String,
    pub message: String,
}

impl std::fmt::Display for Violation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let tag = match self.kind {
            Kind::OverPrivilege => "OVER-PRIVILEGE",
            Kind::Routing => "ROUTING",
        };
        write!(f, "[{}] {} @ {}: {}", tag, self.product, self.moniker, self.message)
    }
}

/// A capability name is "privileged" (a raw kernel/root resource) if it lives in
/// the `fuchsia.kernel.*` namespace (MmioResource, IoportResource, IrqResource,
/// SmcResource, PowerResource, RootJob, IommuResource, MsiResource, DebugResource,
/// InfoResource, VmexResource, ...) or is `fuchsia.boot.RootResource`. Matching by
/// namespace rather than an explicit enumeration keeps the policy correct as new
/// kernel resource protocols are added upstream.
pub fn is_privileged_protocol(name: &str) -> bool {
    name.starts_with("fuchsia.kernel.") || name == "fuchsia.boot.RootResource"
}

/// Least-privilege policy: may this component legitimately `use` privileged
/// kernel/root resources? True iff it is the driver framework core (identified by
/// component name) or an actual driver (runs under the `driver` runner). Everything
/// else — applications, services, probes, filesystems, the console — may not.
fn may_use_privileged(meta_name: &str, decl: &ComponentDecl) -> bool {
    // Driver framework core, matched by the component's bootfs meta-name.
    if meta_name.starts_with("driver_manager_rust")
        || meta_name.starts_with("driver_host")
        || meta_name.starts_with("driver_index")
    {
        return true;
    }
    // Actual driver components run under the `driver` runner (registered by
    // driver_manager into its driver-env). This lets add legitimate
    // driver resource `use`s without touching this allowlist.
    matches!(
        decl.program.as_ref().and_then(|p| p.runner.as_ref()).map(|r| r.as_str()),
        Some("driver")
    )
}

/// Narrow, protocol-SPECIFIC exceptions to the over-privilege lint for non-driver components.
/// Unlike `may_use_privileged` (which grants a component ALL kernel/root resources), this permits
/// exactly one (component, protocol) pair and nothing else.
///
/// `(pkg_resolver, fuchsia.kernel.VmexResource)` — packages. The package resolver
/// legitimately holds the VMEX resource: it serves a launched component's /pkg (binary + shared
/// libs) from the fxfs blob volume and must grant EXECUTE to those blobs
/// (`vmo_blob`/`replace_as_executable`). This is the SAME executability trust boundary pkg-cache
/// holds in upstream Fuchsia. VmexResource (executability) is qualitatively distinct from device
/// MMIO/IOPORT/IRQ/IOMMU — it hands out no hardware access — so this is a deliberate, documented,
/// least-surprise grant, not a blanket kernel-resource allowance. See
/// the capability-routing rules ("Executability grant for the package resolver").
fn permitted_privileged_use(meta_name: &str, protocol: &str) -> bool {
    (meta_name.starts_with("pkg_resolver") && protocol == "fuchsia.kernel.VmexResource")
        // Post-mortem gate: crash_handler binds the ROOT JOB's exception
        // channel to observe every unhandled userspace crash system-wide. RootJob is
        // the whole machine's root job (the single most privileged handle a non-driver
        // component can hold), so this is a deliberate, documented, narrowly-scoped
        // grant to exactly one (component, protocol) pair — mirrored at runtime by the
        // cm_config capability_policy entry pinned to /crash_handler. See
        // the capability-routing rules ("Root-job grant for the crash handler").
        || (meta_name.starts_with("crash_handler") && protocol == "fuchsia.kernel.RootJob")
        // PMU path A: perfmon holds the DebugResource (ZX_RSRC_KIND_SYSTEM @
        // ZX_RSRC_SYSTEM_DEBUG_BASE) to drive zx_mtrace_control(MTRACE_KIND_PERFMON) and
        // read raw hardware performance counters. A deliberate, documented, narrowly-scoped
        // grant to exactly one (component, protocol) pair — mirrored at runtime by the
        // cm_config capability_policy entry pinned to /perfmon. The syscall is additionally
        // refused unless kernel.enable-debugging-syscalls=true, which only the profiling
        // product sets.
        || (meta_name.starts_with("perfmon") && protocol == "fuchsia.kernel.DebugResource")
        // Status panel: status_console reads memory and CPU numbers for the on-screen
        // panel. This pair is different in kind from the three above and the difference is
        // the whole justification: `fuchsia.kernel.Stats` VENDS NO HANDLE. Every other
        // capability this lint guards ends with a component holding a kernel resource;
        // component_manager keeps the ZX_RSRC_SYSTEM_INFO_BASE resource its builtin derived
        // and answers GetMemoryStats/GetCpuStats from it, returning plain integers. It is
        // caught here only because `is_privileged_protocol` matches the whole
        // `fuchsia.kernel.` namespace — a deliberate over-approximation (see its doc
        // comment) that keeps a genuinely new resource protocol from slipping in unreviewed.
        //
        // The over-approximation is kept and this ONE pair is named, rather than teaching
        // `is_privileged_protocol` that Stats is harmless: excluding it by classification
        // would un-gate it for every component forever, and would also un-gate any future
        // extension of that same protocol. Naming the pair keeps the default deny.
        //
        // Exact equality, not a prefix: there is exactly one component this is for, and
        // `starts_with` would silently admit a future `status_console_v2`.
        // Mirrored at runtime by the cm_config capability_policy entry pinned to
        // /status_console. The narrower option — a purpose-built stats broker exposing only
        // total/free/idle — remains open and would let this pair be deleted.
        || (meta_name == "status_console" && protocol == "fuchsia.kernel.Stats")
        // Virtualization: the VMM holds the two resources a guest partition needs.
        //
        // This lint asking the question is the tree working as designed, and the
        // honest answer is that `zx_guest_create` has no other door — there is no
        // hypervisor-service component that owns the resource and hands out guests.
        // Building one is a real alternative and a better one on least-privilege
        // grounds; it is not taken here because `zx_guest_create` returns a guest
        // handle AND a VMAR handle, so the service's protocol would be handle-passing
        // with a lifetime contract, and getting that wrong is a host-safety bug rather
        // than a routing bug.
        //
        // TWO pairs, not one, and the second is the one that is easy to forget:
        //   * HypervisorResource is what `zx_guest_create` validates (SYSTEM @
        //     ZX_RSRC_SYSTEM_HYPERVISOR_BASE, size 1).
        //   * VmexResource is what `zx_vmo_replace_as_executable` validates (SYSTEM @
        //     ZX_RSRC_SYSTEM_VMEX_BASE, size 1). A HypervisorResource child does NOT
        //     satisfy it. The VMM re-mints its guest-RAM VMO executable because
        //     zx_vmo_create grants no ZX_RIGHT_EXECUTE and the guest firmware fetches
        //     every instruction out of it.
        // Both are mirrored at runtime by cm_config capability_policy entries; the
        // VmexResource entry names /pkg_resolver as well, because adding any entry
        // switches that capability from unenforced to default-deny.
        //
        // Exact equality, not a prefix, for the reason the status_console pair gives:
        // `starts_with` would silently admit a future `cryogen_vmm_v2`.
        || (meta_name == "cryogen_vmm" && protocol == "fuchsia.kernel.HypervisorResource")
        || (meta_name == "cryogen_vmm" && protocol == "fuchsia.kernel.VmexResource")
}

/// Decode a persistent-FIDL `.cm` blob into a native `cm_rust::ComponentDecl`.
pub fn load_decl(path: &str) -> Result<ComponentDecl, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("read {path}: {e}"))?;
    let fidl_decl: fdecl::Component =
        fidl::unpersist(&bytes).map_err(|e| format!("unpersist {path}: {e:?}"))?;
    Ok(fidl_decl.fidl_into_native())
}

/// Extract the pool key (`<name>` from `...#meta/<name>.cm`) of a child URL.
/// Returns None for URLs we cannot resolve to a bootfs `.cm` meta-name.
fn meta_name_of_url(url: &str) -> Option<String> {
    let frag = url.split("#meta/").nth(1)?;
    let name = frag.strip_suffix(".cm").unwrap_or(frag);
    Some(name.to_string())
}

/// The capability type of a `UseDecl`, restricted to the three routable kinds we
/// check for completeness. Returns None for kinds we intentionally skip
/// (storage/event_stream/runner/config/dictionary — see module docs).
fn routable_use_type(u: &cm_rust::UseDecl) -> Option<cm_rust::CapabilityTypeName> {
    match u {
        cm_rust::UseDecl::Protocol(_) => Some(cm_rust::CapabilityTypeName::Protocol),
        cm_rust::UseDecl::Directory(_) => Some(cm_rust::CapabilityTypeName::Directory),
        cm_rust::UseDecl::Service(_) => Some(cm_rust::CapabilityTypeName::Service),
        _ => None,
    }
}

/// The capability type of an `OfferDecl`, for the three routable kinds. Returns
/// None for other kinds (runner/config/dictionary/... offers we don't match).
fn routable_offer_type(o: &cm_rust::OfferDecl) -> Option<cm_rust::CapabilityTypeName> {
    match o {
        cm_rust::OfferDecl::Protocol(_) => Some(cm_rust::CapabilityTypeName::Protocol),
        cm_rust::OfferDecl::Directory(_) => Some(cm_rust::CapabilityTypeName::Directory),
        cm_rust::OfferDecl::Service(_) => Some(cm_rust::CapabilityTypeName::Service),
        _ => None,
    }
}

/// Known, deliberately-tolerated routing gaps in the current tree. Each is a
/// *required* `use` that no ancestor offers, whitelisted explicitly — rather than
/// weakening the check or silently passing — so the gate stays strict for every
/// other route while a gap remains a visible realm-owner follow-up.
///
/// Both gaps inherited from the earlier realm topology were CLOSED in
/// (the realms became editable `.cml` and the fixes boot-verified), so this list is
/// now empty:
///   * `/fshost/fxfs` + `fuchsia.logger.LogSink` — fixed: `fshost.cml` now offers
///     LogSink to `#fxfs` alongside `#fxfs-crypt`.
///   * `/fshost_probe` + `fuchsia.hardware.block.volume.Service` — fixed: the
///     vestigial `use` was removed from `fshost_probe.cml` (its real data path is
///     fshost's exposed `fshost-fs` directory, which IS offered to it).
///
/// Matched as `(moniker-suffix, capability-name)`.
const TOLERATED_ROUTING_GAPS: &[(&str, &str)] = &[];

fn is_tolerated_routing_gap(moniker: &str, cap_name: &str) -> bool {
    TOLERATED_ROUTING_GAPS
        .iter()
        .any(|(suffix, cap)| moniker.ends_with(suffix) && *cap == cap_name)
}

/// Does `parent` offer a capability of `ty` delivered as `cap_name` to the child
/// named `child_ref`? A matching offer of ANY source (parent/self/child/collection/
/// framework/void) counts as "routed to the target" — chasing the offer's own
/// source transitively (aggregated-service collections, dictionaries) is the
/// deferred stretch, so we deliberately only assert the offer EXISTS at the target.
/// A `void` offer is a deliberate "explicitly unavailable" routing decision and so
/// also counts as offered (the target's use of it must be optional, which
/// component_manager enforces at runtime — out of scope here).
fn parent_offers_to_child(
    parent: &ComponentDecl,
    ty: cm_rust::CapabilityTypeName,
    cap_name: &str,
    child_ref: &str,
) -> bool {
    for o in parent.offers.iter() {
        if routable_offer_type(o) != Some(ty) {
            continue;
        }
        if o.target_name().as_str() != cap_name {
            continue;
        }
        match o.target() {
            cm_rust::OfferTarget::Child(c) if c.name.as_str() == child_ref => return true,
            // Offers to a collection target dynamic children; our static children
            // are never in a collection, so this never matches them. (Kept explicit
            // to document the intentional non-match.)
            cm_rust::OfferTarget::Collection(_) => {}
            _ => {}
        }
    }
    false
}

/// Recursively walk the static realm rooted at `decl`, appending violations.
///
/// * `product`      — logical product name, for messages.
/// * `moniker`      — this component's slash-path within the realm.
/// * `meta_name`    — this component's bootfs meta-name (pool key).
/// * `self_ref`     — how this component's PARENT refers to it (the child name in
///                    the parent's `children`/`offer to`), or None for the root.
/// * `parent`       — the parent realm's decl, or None for the root.
/// * `pool`         — meta-name -> `.cm` path, to resolve child URLs.
#[allow(clippy::too_many_arguments)]
fn walk(
    product: &str,
    moniker: &str,
    meta_name: &str,
    self_ref: Option<&str>,
    decl: &ComponentDecl,
    parent: Option<&ComponentDecl>,
    pool: &BTreeMap<String, String>,
    out: &mut Vec<Violation>,
) {
    // ── Check 1: over-privilege lint (per component, source-independent). ──
    if !may_use_privileged(meta_name, decl) {
        for u in decl.uses.iter() {
            if matches!(u, cm_rust::UseDecl::Protocol(_)) {
                let name = u.source_name().as_str();
                if is_privileged_protocol(name) && !permitted_privileged_use(meta_name, name) {
                    out.push(Violation {
                        kind: Kind::OverPrivilege,
                        product: product.to_string(),
                        moniker: moniker.to_string(),
                        message: format!(
                            "non-driver component `{meta_name}` uses privileged resource \
                             protocol `{name}`; only the driver framework \
                             (driver_manager_rust/driver_host/driver_index) and driver \
                             components (runner=\"driver\") may use kernel/root resources"
                        ),
                    });
                }
            }
        }
    }

    // ── Check 2: routing completeness for uses-from-parent (needs a parent). ──
    if let (Some(parent_decl), Some(child_ref)) = (parent, self_ref) {
        for u in decl.uses.iter() {
            let Some(ty) = routable_use_type(u) else { continue };
            // Only uses sourced from `parent` require an ancestor offer. framework /
            // debug / self / capability / environment sources are satisfied by
            // component_manager builtins or by the component itself.
            if !matches!(u.source(), cm_rust::UseSource::Parent) {
                continue;
            }
            // An optional/transitional `use` needs no offer: component_manager treats
            // an unrouted optional capability as legitimately absent (equivalent to a
            // `from void` offer). Only required uses demand a matching ancestor offer.
            if matches!(
                u.availability(),
                cm_rust::Availability::Optional | cm_rust::Availability::Transitional
            ) {
                continue;
            }
            // A use routed through a dictionary (`from parent/<dict>`) is the deferred
            // dictionary-resolution stretch — whitelist rather than false-positive.
            if let cm_rust::UseDecl::Protocol(p) = u {
                if !p.source_dictionary.is_dot() {
                    continue;
                }
            }
            let cap_name = u.source_name().as_str();
            if is_tolerated_routing_gap(moniker, cap_name) {
                continue;
            }
            if !parent_offers_to_child(parent_decl, ty, cap_name, child_ref) {
                out.push(Violation {
                    kind: Kind::Routing,
                    product: product.to_string(),
                    moniker: moniker.to_string(),
                    message: format!(
                        "component `{meta_name}` uses {ty} `{cap_name}` from parent, but \
                         its parent realm offers no matching `{cap_name}` to `#{child_ref}`"
                    ),
                });
            }
        }
    }

    // ── Recurse into statically-declared children we can resolve. ──
    for child in decl.children.iter() {
        let child_name = child.name.as_str();
        let Some(cm) = meta_name_of_url(child.url.as_str()) else {
            continue; // non-bootfs URL; nothing to inspect.
        };
        let Some(path) = pool.get(&cm) else {
            // Statically-declared child whose .cm isn't in the pool (e.g. an
            // upstream driver package). We cannot inspect its uses, so there is
            // nothing to check — skip rather than guess.
            continue;
        };
        match load_decl(path) {
            Ok(child_decl) => {
                let child_moniker = format!("{moniker}/{child_name}");
                walk(
                    product,
                    &child_moniker,
                    &cm,
                    Some(child_name),
                    &child_decl,
                    Some(decl),
                    pool,
                    out,
                );
            }
            Err(e) => out.push(Violation {
                kind: Kind::Routing,
                product: product.to_string(),
                moniker: format!("{moniker}/{child_name}"),
                message: format!("failed to decode child `.cm` ({cm}): {e}"),
            }),
        }
    }
}

/// Run both checks over one product, identified by its root `.cm` path, resolving
/// children against `pool` (meta-name -> `.cm` path). `root_meta` is the root's
/// own meta-name (used only for the over-privilege classification / messages).
pub fn check_product(
    product: &str,
    root_meta: &str,
    root_cm: &str,
    pool: &BTreeMap<String, String>,
) -> Result<Vec<Violation>, String> {
    let root_decl = load_decl(root_cm)?;
    let mut out = Vec::new();
    walk(product, root_meta, root_meta, None, &root_decl, None, pool, &mut out);
    Ok(out)
}

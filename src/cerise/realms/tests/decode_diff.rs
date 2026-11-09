// Decode-diff GATE: prove the driver_manager_rust_dfv2acpi realm authored
// as real .cml (compiled by cmc via cerise_component) round-trips STRUCTURALLY
// identically to the frozen golden fidl_fuchsia_component_decl blob — i.e. the
// exotic cmc features (transient collections, self-declared driver runner + env
// registration, dev directory cap, service aggregated from a collection, inline
// config capabilities with baked values, offer renames) produce the same routing.
//
// Method: decode BOTH the frozen golden blob (GT —
// //src/cerise/realms/goldens/*.cm, checked in
// as the frozen reference) and the cerise_component-produced .cm (MINE), project
// each into normalized sets of the load-bearing facts, and assert the sets are
// equal. This is now a REGRESSION gate on the .cml (the goldens are frozen); benign
// encoder differences (field ordering, and cmc setting availability=Required
// explicitly where the golden left it None — semantically identical) are normalized away.

use fidl_fuchsia_component_decl as fdecl;
use std::collections::BTreeSet;

fn load(env_key: &str) -> fdecl::Component {
    let path = std::env::var(env_key).unwrap_or_else(|_| panic!("env {env_key} unset"));
    let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("read {path}: {e}"));
    fidl::unpersist(&bytes).expect("persistent-FIDL Component")
}

fn refstr(r: &fdecl::Ref) -> String {
    match r {
        fdecl::Ref::Parent(_) => "parent".into(),
        fdecl::Ref::Self_(_) => "self".into(),
        fdecl::Ref::Framework(_) => "framework".into(),
        fdecl::Ref::Child(c) => format!("child:{}", c.name),
        fdecl::Ref::Collection(c) => format!("collection:{}", c.name),
        fdecl::Ref::Capability(c) => format!("capability:{}", c.name),
        other => format!("{other:?}"),
    }
}

// ── Projections: each returns a normalized set of load-bearing strings. ──

fn collections(c: &fdecl::Component) -> BTreeSet<String> {
    c.collections
        .as_ref()
        .map(|v| {
            v.iter()
                .map(|col| {
                    format!(
                        "{}|{:?}|{}|{:?}|{:?}",
                        col.name.as_deref().unwrap_or(""),
                        col.durability,
                        col.environment.as_deref().unwrap_or(""),
                        col.allowed_offers,
                        col.allow_long_names,
                    )
                })
                .collect()
        })
        .unwrap_or_default()
}

fn children(c: &fdecl::Component) -> BTreeSet<String> {
    c.children
        .as_ref()
        .map(|v| {
            v.iter()
                .map(|ch| {
                    format!(
                        "{}|{}|{:?}|{}",
                        ch.name.as_deref().unwrap_or(""),
                        ch.url.as_deref().unwrap_or(""),
                        ch.startup,
                        ch.environment.as_deref().unwrap_or(""),
                    )
                })
                .collect()
        })
        .unwrap_or_default()
}

fn env_runner_regs(c: &fdecl::Component) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for e in c.environments.iter().flatten() {
        let ename = e.name.as_deref().unwrap_or("");
        for r in e.runners.iter().flatten() {
            out.insert(format!(
                "env={} runner={} from={} as={}",
                ename,
                r.source_name.as_deref().unwrap_or(""),
                r.source.as_ref().map(refstr).unwrap_or_default(),
                r.target_name.as_deref().unwrap_or(""),
            ));
        }
    }
    out
}

fn capabilities(c: &fdecl::Component) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for cap in c.capabilities.iter().flatten() {
        let s = match cap {
            fdecl::Capability::Runner(r) => {
                format!("runner:{}@{}", r.name.as_deref().unwrap_or(""), r.source_path.as_deref().unwrap_or(""))
            }
            fdecl::Capability::Protocol(p) => {
                format!("protocol:{}@{}", p.name.as_deref().unwrap_or(""), p.source_path.as_deref().unwrap_or(""))
            }
            fdecl::Capability::Directory(d) => format!(
                "directory:{}@{} rights={:?}",
                d.name.as_deref().unwrap_or(""),
                d.source_path.as_deref().unwrap_or(""),
                d.rights,
            ),
            fdecl::Capability::Config(cfg) => {
                format!("config:{}={:?}", cfg.name.as_deref().unwrap_or(""), cfg.value)
            }
            other => format!("{other:?}"),
        };
        out.insert(s);
    }
    out
}

fn exposes(c: &fdecl::Component) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for e in c.exposes.iter().flatten() {
        let s = match e {
            // Directory-expose rights are dropped here: cmc omits them on an
            // expose-from-self (they come from the capability decl) where the golden
            // repeated them — benign, and rights are still asserted via capabilities().
            fdecl::Expose::Directory(d) => format!(
                "dir:{}->{}:{}",
                d.source_name.as_deref().unwrap_or(""),
                d.target.as_ref().map(refstr).unwrap_or_default(),
                d.target_name.as_deref().unwrap_or(""),
            ),
            fdecl::Expose::Service(s) => format!(
                "svc:{} from={} ->{}:{}",
                s.source_name.as_deref().unwrap_or(""),
                s.source.as_ref().map(refstr).unwrap_or_default(),
                s.target.as_ref().map(refstr).unwrap_or_default(),
                s.target_name.as_deref().unwrap_or(""),
            ),
            fdecl::Expose::Protocol(p) => format!(
                "proto:{} from={}",
                p.source_name.as_deref().unwrap_or(""),
                p.source.as_ref().map(refstr).unwrap_or_default()
            ),
            other => format!("{other:?}"),
        };
        out.insert(s);
    }
    out
}

// Offers, normalized: availability is dropped (cmc emits Required explicitly where
// the golden left None; both mean Required).
fn offers(c: &fdecl::Component) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for o in c.offers.iter().flatten() {
        let s = match o {
            fdecl::Offer::Protocol(p) => format!(
                "proto:{} {}->{}:{}",
                p.source_name.as_deref().unwrap_or(""),
                p.source.as_ref().map(refstr).unwrap_or_default(),
                p.target.as_ref().map(refstr).unwrap_or_default(),
                p.target_name.as_deref().unwrap_or(""),
            ),
            fdecl::Offer::Config(cfg) => format!(
                "config:{} {}->{}:{}",
                cfg.source_name.as_deref().unwrap_or(""),
                cfg.source.as_ref().map(refstr).unwrap_or_default(),
                cfg.target.as_ref().map(refstr).unwrap_or_default(),
                cfg.target_name.as_deref().unwrap_or(""),
            ),
            fdecl::Offer::Directory(d) => format!(
                "dir:{} {}->{}:{}",
                d.source_name.as_deref().unwrap_or(""),
                d.source.as_ref().map(refstr).unwrap_or_default(),
                d.target.as_ref().map(refstr).unwrap_or_default(),
                d.target_name.as_deref().unwrap_or(""),
            ),
            fdecl::Offer::Service(s) => format!(
                "svc:{} {}->{}:{}",
                s.source_name.as_deref().unwrap_or(""),
                s.source.as_ref().map(refstr).unwrap_or_default(),
                s.target.as_ref().map(refstr).unwrap_or_default(),
                s.target_name.as_deref().unwrap_or(""),
            ),
            fdecl::Offer::Runner(r) => format!(
                "runner:{} {}->{}:{}",
                r.source_name.as_deref().unwrap_or(""),
                r.source.as_ref().map(refstr).unwrap_or_default(),
                r.target.as_ref().map(refstr).unwrap_or_default(),
                r.target_name.as_deref().unwrap_or(""),
            ),
            other => format!("{other:?}"),
        };
        out.insert(s);
    }
    out
}

fn uses(c: &fdecl::Component) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for u in c.uses.iter().flatten() {
        let s = match u {
            fdecl::Use::Protocol(p) => format!(
                "proto:{} from={}",
                p.source_name.as_deref().unwrap_or(""),
                p.source.as_ref().map(refstr).unwrap_or_default(),
            ),
            fdecl::Use::Directory(d) => format!(
                "dir:{} from={}",
                d.source_name.as_deref().unwrap_or(""),
                d.source.as_ref().map(refstr).unwrap_or_default(),
            ),
            fdecl::Use::Service(s) => format!(
                "svc:{} from={}",
                s.source_name.as_deref().unwrap_or(""),
                s.source.as_ref().map(refstr).unwrap_or_default(),
            ),
            other => format!("{other:?}"),
        };
        out.insert(s);
    }
    out
}

fn program(c: &fdecl::Component) -> String {
    let Some(p) = c.program.as_ref() else {
        return "none".to_string();
    };
    let binary = p
        .info
        .as_ref()
        .and_then(|d| d.entries.as_ref())
        .and_then(|e| e.iter().find(|x| x.key == "binary"))
        .and_then(|e| e.value.as_deref())
        .map(|v| format!("{v:?}"))
        .unwrap_or_default();
    format!("runner={} binary={}", p.runner.as_deref().unwrap_or(""), binary)
}

#[test]
fn driver_manager_realm_roundtrips_structurally() {
    let gt = load("GT_DM");
    let mine = load("MINE_DM");

    assert_eq!(program(&gt), program(&mine), "program");
    assert_eq!(collections(&gt), collections(&mine), "collections");
    assert_eq!(env_runner_regs(&gt), env_runner_regs(&mine), "environment runner registrations");
    assert_eq!(capabilities(&gt), capabilities(&mine), "capabilities (incl inline config values, dev dir, driver runner)");
    assert_eq!(exposes(&gt), exposes(&mine), "exposes (incl block.volume Service from collection)");
    assert_eq!(offers(&gt), offers(&mine), "offers");
    assert_eq!(uses(&gt), uses(&mine), "uses");

    // Spot-assert the specific exotic facts the plan enumerates, so a regression
    // names the exact feature that broke rather than just "sets differ".
    let caps = capabilities(&mine);
    assert!(caps.contains("runner:driver@/svc/fuchsia.component.runner.ComponentRunner"), "self driver runner");
    assert!(caps.iter().any(|s| s.starts_with("directory:dev@/dev")), "dev directory cap");
    assert!(caps.contains(r#"config:fuchsia.power.SuspendEnabled=Some(Single(Bool(false)))"#), "SuspendEnabled inline value");
    assert!(caps.contains(r#"config:fuchsia.platform.bus.SoftwareDeviceNames=Some(Vector(StringVector([])))"#), "SoftwareDeviceNames inline empty vector");

    let cols = collections(&mine);
    assert!(cols.iter().any(|s| s.starts_with("boot-drivers|Some(Transient)|driver-env|Some(StaticAndDynamic)|Some(true)")), "boot-drivers collection shape");

    let regs = env_runner_regs(&mine);
    assert!(regs.contains("env=driver-env runner=driver from=self as=driver"), "driver runner reg in driver-env");
    assert!(regs.contains("env=driver-host-env runner=elf from=parent as=elf"), "elf runner reg in driver-host-env");

    let exp = exposes(&mine);
    assert!(exp.iter().any(|s| s.contains("svc:fuchsia.hardware.block.volume.Service from=collection:boot-drivers")), "block.volume aggregated from boot-drivers");
    // the native display driver's framebuffer service aggregates here too.
    assert!(exp.iter().any(|s| s.contains("svc:cerise.display.Service from=collection:boot-drivers")), "cerise.display aggregated from boot-drivers");
}

#[test]
fn root_dfv2acpi_realm_roundtrips_structurally() {
    let gt = load("GT_ROOT");
    let mine = load("MINE_ROOT");

    assert_eq!(children(&gt), children(&mine), "children (names/urls/startup/env)");
    assert_eq!(env_runner_regs(&gt), env_runner_regs(&mine), "elf-env runner registration");
    assert_eq!(offers(&gt), offers(&mine), "offers (incl Resolver->-boot rename, dev/service/dir routing)");
    assert_eq!(uses(&gt), uses(&mine), "uses");
    assert_eq!(exposes(&gt), exposes(&mine), "exposes");

    // Spot-assert the load-bearing root facts.
    let regs = env_runner_regs(&mine);
    assert!(regs.contains("env=elf-env runner=elf from=child:elf_runner as=elf"), "elf runner reg from #elf_runner child");
    let offs = offers(&mine);
    assert!(offs.iter().any(|s| s == "proto:fuchsia.component.resolution.Resolver parent->child:driver_index:fuchsia.component.resolution.Resolver-boot"), "Resolver renamed to -boot");
    let chs = children(&mine);
    assert!(chs.iter().any(|s| s.starts_with("crypt_fxfs|") && s.contains("Lazy")), "crypt_fxfs is Lazy");
    assert!(chs.iter().any(|s| s.starts_with("driver_manager_rust|fuchsia-boot:///driver_manager_rust_dfv2platbus#meta/driver_manager_rust_dfv2acpi.cm")), "driver_manager child url");
}

#[test]
fn root_console_spike_realm_roundtrips_structurally() {
    let gt = load("GT_CS");
    let mine = load("MINE_CS");

    assert_eq!(children(&gt), children(&mine), "children");
    assert_eq!(env_runner_regs(&gt), env_runner_regs(&mine), "elf-env runner registration");
    assert_eq!(offers(&gt), offers(&mine), "offers (incl fb_spike Mmio/Ioport, Resolver->-boot)");
    assert_eq!(uses(&gt), uses(&mine), "uses");
    assert_eq!(exposes(&gt), exposes(&mine), "exposes");

    let chs = children(&mine);
    assert!(chs.iter().any(|s| s.starts_with("fb_spike|fuchsia-boot:///fb_spike#meta/fb_spike.cm") && s.contains("Eager")), "fb_spike Eager child");
    let offs = offers(&mine);
    assert!(offs.contains("proto:fuchsia.kernel.MmioResource parent->child:fb_spike:fuchsia.kernel.MmioResource"), "Mmio to fb_spike");
}

// Leaf program-manifest comparison: program (runner+binary), uses, capabilities,
// exposes must all match the golden blob. GT_LEAVES/MINE_LEAVES are space-separated
// path lists in matching order.
#[test]
fn leaf_manifests_roundtrip_structurally() {
    let gt_paths: Vec<String> = std::env::var("GT_LEAVES").unwrap().split(' ').map(|s| s.to_string()).collect();
    let mine_paths: Vec<String> = std::env::var("MINE_LEAVES").unwrap().split(' ').map(|s| s.to_string()).collect();
    let names: Vec<String> = std::env::var("LEAF_NAMES").unwrap().split(' ').map(|s| s.to_string()).collect();
    assert_eq!(gt_paths.len(), mine_paths.len());
    assert_eq!(gt_paths.len(), names.len());
    for i in 0..gt_paths.len() {
        let load_path = |p: &str| -> fdecl::Component {
            let bytes = std::fs::read(p).unwrap_or_else(|e| panic!("read {p}: {e}"));
            fidl::unpersist(&bytes).expect("Component")
        };
        let gt = load_path(&gt_paths[i]);
        let mine = load_path(&mine_paths[i]);
        let n = &names[i];
        assert_eq!(program(&gt), program(&mine), "{n}: program");
        assert_eq!(uses(&gt), uses(&mine), "{n}: uses");
        assert_eq!(capabilities(&gt), capabilities(&mine), "{n}: capabilities");
        assert_eq!(exposes(&gt), exposes(&mine), "{n}: exposes");
        assert_eq!(offers(&gt), offers(&mine), "{n}: offers");
        assert_eq!(children(&gt), children(&mine), "{n}: children");
        assert_eq!(env_runner_regs(&gt), env_runner_regs(&mine), "{n}: env runner regs");
        assert_eq!(collections(&gt), collections(&mine), "{n}: collections");
    }
}

// NEGATIVE gate: prove the over-privilege lint is not vacuous. The fixture realm
// (evil_root → evil_app) is a well-routed graph in which an ordinary `elf`
// application component nonetheless `use`s fuchsia.kernel.MmioResource. The checker
// MUST report exactly one OverPrivilege violation naming evil_app + MmioResource,
// and (because evil_root offers everything evil_app uses) MUST report NO routing
// violations. If this test ever passes with zero findings, the guard has silently
// broken and the positive test's green is worthless.

use route_check::{check_product, Kind};
use std::collections::BTreeMap;

#[test]
fn checker_catches_illegitimate_mmio_use() {
    let evil_app = std::env::var("EVIL_APP").expect("EVIL_APP unset");
    let evil_root = std::env::var("EVIL_ROOT").expect("EVIL_ROOT unset");

    let mut pool = BTreeMap::new();
    pool.insert("evil_app".to_string(), evil_app);

    let violations =
        check_product("evil-fixture", "evil_root", &evil_root, &pool).expect("check ran");

    let over: Vec<_> = violations.iter().filter(|v| v.kind == Kind::OverPrivilege).collect();
    let routing: Vec<_> = violations.iter().filter(|v| v.kind == Kind::Routing).collect();

    assert_eq!(
        over.len(),
        1,
        "expected exactly one over-privilege violation, got {}: {violations:?}",
        over.len()
    );
    assert!(
        over[0].message.contains("fuchsia.kernel.MmioResource")
            && over[0].moniker.contains("evil_app"),
        "violation should name evil_app + MmioResource: {}",
        over[0]
    );
    assert!(
        routing.is_empty(),
        "evil_root offers everything evil_app uses; no routing violation expected, got: {routing:?}"
    );
}

/// The two VMM allowlist entries are exact-match, and this proves it.
///
/// `permitted_privileged_use` grants `cryogen_vmm` + HypervisorResource and
/// `cryogen_vmm` + VmexResource with `==` rather than `starts_with`. The fixture
/// is a well-routed realm whose child is named `cryogen_vmm_v2` — the exact shape
/// a prefix match would admit — and it uses both protocols. Two over-privilege
/// violations, no routing violations.
///
/// Without this, both new allowlist entries would have shipped with no red
/// control: the existing negative test covers only fuchsia.kernel.MmioResource.
#[test]
fn checker_catches_a_second_vmm_claiming_the_hypervisor_grant() {
    let app = std::env::var("VMM_V2_APP").expect("VMM_V2_APP unset");
    let root = std::env::var("VMM_V2_ROOT").expect("VMM_V2_ROOT unset");

    let mut pool = BTreeMap::new();
    pool.insert("cryogen_vmm_v2".to_string(), app);

    let violations =
        check_product("vmm-v2-fixture", "vmm_v2_root", &root, &pool).expect("check ran");

    let over: Vec<_> = violations.iter().filter(|v| v.kind == Kind::OverPrivilege).collect();
    let routing: Vec<_> = violations.iter().filter(|v| v.kind == Kind::Routing).collect();

    assert_eq!(
        over.len(),
        2,
        "expected one over-privilege violation per privileged protocol, got {}: {violations:?}",
        over.len()
    );
    for protocol in ["fuchsia.kernel.HypervisorResource", "fuchsia.kernel.VmexResource"] {
        assert!(
            over.iter()
                .any(|v| v.message.contains(protocol) && v.moniker.contains("cryogen_vmm_v2")),
            "a violation should name cryogen_vmm_v2 + {protocol}; got {over:?}"
        );
    }
    assert!(
        routing.is_empty(),
        "the fixture root offers everything its child uses; no routing violation expected, \
         got: {routing:?}"
    );
}

#[test]
fn checker_catches_forgotten_offer() {
    let orphan_app = std::env::var("ORPHAN_APP").expect("ORPHAN_APP unset");
    let orphan_root = std::env::var("ORPHAN_ROOT").expect("ORPHAN_ROOT unset");

    let mut pool = BTreeMap::new();
    pool.insert("orphan_app".to_string(), orphan_app);

    let violations =
        check_product("orphan-fixture", "orphan_root", &orphan_root, &pool).expect("check ran");

    let routing: Vec<_> = violations.iter().filter(|v| v.kind == Kind::Routing).collect();
    assert_eq!(
        routing.len(),
        1,
        "expected exactly one routing violation, got {}: {violations:?}",
        routing.len()
    );
    assert!(
        routing[0].message.contains("cerise.example.Unoffered")
            && routing[0].moniker.contains("orphan_app"),
        "violation should name orphan_app + the unoffered protocol: {}",
        routing[0]
    );
}

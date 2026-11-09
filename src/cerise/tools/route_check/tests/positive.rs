// POSITIVE gate: the six real Cerise products' compiled realm graphs must be
// clean under BOTH checks — routing-complete and least-privilege. Post-#19 the
// tree is clean (status_console acquires its framebuffer via the cerise.display
// FIDL client, no longer using fuchsia.kernel.MmioResource), so this test asserts
// ZERO violations. A regression (a forgotten offer, or a new privileged `use` in a
// non-driver component) fails `bazel test` here, before any boot.
//
// Inputs arrive as rootpaths via env (the decode_diff idiom): PRODUCT_NAMES lists
// the products; ROOT_<name> is each product's root .cm; POOL is a whitespace-
// separated list of `<meta_name>=<path>` entries used to resolve child URLs.

use route_check::check_product;
use std::collections::BTreeMap;

fn pool() -> BTreeMap<String, String> {
    let raw = std::env::var("POOL").expect("POOL unset");
    raw.split_whitespace()
        .map(|kv| {
            let (k, v) = kv.split_once('=').expect("POOL entry must be name=path");
            (k.to_string(), v.to_string())
        })
        .collect()
}

#[test]
fn all_real_products_are_routing_complete_and_least_privilege() {
    let pool = pool();
    let names: Vec<String> =
        std::env::var("PRODUCT_NAMES").expect("PRODUCT_NAMES unset").split_whitespace().map(String::from).collect();
    assert!(!names.is_empty(), "no products under test");

    let mut violations = Vec::new();
    for name in &names {
        let root = std::env::var(format!("ROOT_{name}"))
            .unwrap_or_else(|_| panic!("ROOT_{name} unset"));
        let v = check_product(name, name, &root, &pool)
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        violations.extend(v);
    }

    if !violations.is_empty() {
        let mut msg = format!("{} unexpected violation(s):\n", violations.len());
        for v in &violations {
            msg.push_str(&format!("  {v}\n"));
        }
        panic!("{msg}");
    }
}

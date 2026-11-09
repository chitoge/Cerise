// route_check CLI — standalone host driver for the build-time routing +
// least-privilege checker (see lib.rs).
//
// Usage:
//   route_check \
//     --pool <meta_name>=<path-to-.cm> [--pool ...] \
//     --product <product_name>:<root_meta_name>:<path-to-root-.cm> [--product ...] \
//     [--expect-violations]
//
// Exit status (normal mode): 0 if the component graph is clean, 1 if any
// over-privilege or routing-completeness violation was found (each printed to
// stderr). With --expect-violations the sense is inverted (used by the negative
// test to prove the guard actually fires): exit 0 iff at least one violation was
// found, 1 if the graph was unexpectedly clean.

use std::collections::BTreeMap;

fn main() {
    let mut pool: BTreeMap<String, String> = BTreeMap::new();
    let mut products: Vec<(String, String, String)> = Vec::new();
    let mut expect_violations = false;

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--pool" => {
                let v = args.next().expect("--pool needs <meta_name>=<path>");
                let (name, path) = v.split_once('=').expect("--pool value must be name=path");
                pool.insert(name.to_string(), path.to_string());
            }
            "--product" => {
                let v = args.next().expect("--product needs name:root_meta:path");
                let parts: Vec<&str> = v.splitn(3, ':').collect();
                assert_eq!(parts.len(), 3, "--product must be name:root_meta:path");
                products.push((parts[0].to_string(), parts[1].to_string(), parts[2].to_string()));
            }
            "--expect-violations" => expect_violations = true,
            other => panic!("unknown argument: {other}"),
        }
    }

    assert!(!products.is_empty(), "at least one --product is required");

    let mut all = Vec::new();
    for (product, root_meta, root_cm) in &products {
        match route_check::check_product(product, root_meta, root_cm, &pool) {
            Ok(mut v) => all.append(&mut v),
            Err(e) => {
                eprintln!("route_check: {product}: {e}");
                std::process::exit(2);
            }
        }
    }

    for v in &all {
        eprintln!("{v}");
    }

    if expect_violations {
        if all.is_empty() {
            eprintln!(
                "route_check: FAIL — expected at least one violation but the graph was clean"
            );
            std::process::exit(1);
        }
        eprintln!("route_check: OK — {} expected violation(s) detected", all.len());
        return;
    }

    if !all.is_empty() {
        eprintln!(
            "route_check: FAIL — {} violation(s) across {} product(s)",
            all.len(),
            products.len()
        );
        std::process::exit(1);
    }
    eprintln!(
        "route_check: OK — {} product(s) clean (routing complete, least-privilege upheld)",
        products.len()
    );
}

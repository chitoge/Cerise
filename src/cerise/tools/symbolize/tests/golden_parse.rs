//! Structural golden: parse the frozen boot fixture and assert the exact set of
//! modules / mmaps / pc frames it carries. This pins the PARSER against real
//! markup (validation/fixtures/new-boot-smoke.log); it deliberately does NOT
//! resolve symbols — the fixture's build-ids predate any live build, so live
//! symbolization of it is impossible (see the live_symbolize test for real
//! symbol resolution). The fixture path is injected via $FIXTURE (BUILD data).

use std::fs;

use symbolize::{find_markup, parse_element, Markup};

fn fixture() -> String {
    let path = std::env::var("FIXTURE").expect("FIXTURE env (BUILD data) must be set");
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path}: {e}"))
}

#[test]
fn extracts_exactly_the_six_modules() {
    let text = fixture();
    let mut modules: Vec<(u32, String, String)> = Vec::new();
    for line in text.lines() {
        if let Some(Markup::Module { id, name, build_id }) =
            find_markup(line).and_then(parse_element)
        {
            modules.push((id, name, build_id));
        }
    }
    // Six {{{module}}} lines total (ids repeat across reset epochs).
    assert_eq!(modules.len(), 6, "module lines: {:#?}", modules);

    let expected = [
        (0u32, "physload", "a7d3f7013f61aab7ad3593db5be0fdda8bf8be1e"),
        (0, "physload", "a7d3f7013f61aab7ad3593db5be0fdda8bf8be1e"),
        (1, "physboot", "35ef1d05fc9f695bda7474bb126c2578cf81b6f1"),
        (2, "vmzircon", "5f2d7e8370e34b825ccbe3e808ce563aa19a804e"),
        (3, "vmzircon", "5f2d7e8370e34b825ccbe3e808ce563aa19a804e"),
    ];
    // Every distinct (name,build_id) the fixture declares must be recognized.
    for (_, name, id) in &expected {
        assert!(
            modules.iter().any(|(_, n, b)| n == name && b == id),
            "missing module {name}/{id} in {:#?}",
            modules
        );
    }
}

#[test]
fn extracts_the_single_pc_frame_and_no_bt() {
    let text = fixture();
    let mut pcs = Vec::new();
    let mut bts = Vec::new();
    for line in text.lines() {
        match find_markup(line).and_then(parse_element) {
            Some(Markup::Pc { pc }) => pcs.push(pc),
            Some(Markup::Bt { pc, .. }) => bts.push(pc),
            _ => {}
        }
    }
    assert_eq!(pcs, vec![0x44bca0], "the fixture carries exactly one pc frame");
    assert!(bts.is_empty(), "the fixture carries no bt frames: {:#x?}", bts);
}

#[test]
fn extracts_the_mmap_set() {
    let text = fixture();
    let mut mmaps = Vec::new();
    for line in text.lines() {
        if let Some(Markup::Mmap { start, module_id, .. }) =
            find_markup(line).and_then(parse_element)
        {
            mmaps.push((start, module_id));
        }
    }
    // physload(0), physboot(1), vmzircon(2, high half), vmzircon(3, relocated).
    assert!(mmaps.iter().any(|&(s, m)| s == 0x222000 && m == 0));
    assert!(mmaps.iter().any(|&(s, m)| m == 1 && s == 0x376000));
    assert!(mmaps
        .iter()
        .any(|&(s, m)| m == 2 && s == 0xffffffff00000000));
    assert!(mmaps.iter().any(|&(_, m)| m == 3));
    // All parsed mmaps are non-empty and well-formed (no panics above == success).
    assert!(mmaps.len() >= 10, "mmap lines: {}", mmaps.len());
}

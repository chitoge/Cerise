// Host debug-dumper: decode a persistent-FIDL .cm (fuchsia.component.decl.Component)
// and print its full structure. Used to extract the ground-truth structure of
// the golden emitted blobs when authoring the equivalent .cml.
use fidl_fuchsia_component_decl as fdecl;

#[test]
fn dump() {
    let path = std::env::var("CM_PATH").expect("CM_PATH not set");
    let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("read {path}: {e}"));
    let component: fdecl::Component =
        fidl::unpersist(&bytes).expect("not a persistent-FIDL Component");
    eprintln!("=== DUMP {path} ===");
    eprintln!("{component:#?}");
    eprintln!("=== END DUMP ===");
}

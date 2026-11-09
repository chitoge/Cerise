// Artifact-level proof that the cerise_component pipeline delivers structured
// config for real — rather than hardcoding `Config` literals
// in Rust because there was no build-time delivery path.
//
// This host test decodes the two artifacts `bazel build //src/cerise/hello_cml`
// produces and asserts their contents by real persistent-FIDL decode (the same
// wire format cmc/configc emit and component_manager reads — not an exit-0 / file
// non-empty smoke check):
//
//   * meta/hello_cml.cm  -> fuchsia.component.decl/Component: program.runner == "elf",
//     program.info["binary"] == "bin/hello_cml", and the config SCHEMA carries the
//     declared fields (greeting, max_len) with value_source == the .cvf package path.
//   * meta/hello_cml.cvf -> fuchsia.component.decl/ConfigValuesData: the delivered
//     VALUES (greeting == "hello-cerise", max_len == 64u32).
//
// Field->value correspondence is derived structurally: configc emits .cvf values in
// the .cm schema's field order, so values[i] pairs with fields[i]. We read the field
// order out of the .cm and index the .cvf by the same ordinal — never assuming an
// alphabetical or declaration order.

use fidl_fuchsia_component_decl as fdecl;
use fidl_fuchsia_data as fdata;
use std::path::PathBuf;

// The build passes each artifact's runfiles-root-relative path in an env var. We try
// it against the handful of runfiles base dirs Bazel might root the test at, which is
// robust across the legacy/bzlmod runfiles layouts without pulling in a runfiles crate.
fn read_artifact(env_key: &str) -> Vec<u8> {
    let rel = std::env::var(env_key)
        .unwrap_or_else(|_| panic!("env {env_key} not set by the BUILD rule"));
    let srcdir = std::env::var("TEST_SRCDIR").unwrap_or_default();
    let workspace = std::env::var("TEST_WORKSPACE").unwrap_or_default();
    let candidates = [
        PathBuf::from(&rel),
        PathBuf::from(&srcdir).join(&workspace).join(&rel),
        PathBuf::from(&srcdir).join(&rel),
    ];
    for c in &candidates {
        if let Ok(bytes) = std::fs::read(c) {
            return bytes;
        }
    }
    panic!("could not locate artifact {rel} (tried {candidates:?})");
}

fn dict_get<'a>(dict: &'a fdata::Dictionary, key: &str) -> Option<&'a fdata::DictionaryValue> {
    dict.entries
        .as_ref()?
        .iter()
        .find(|e| e.key == key)
        .and_then(|e| e.value.as_deref())
}

#[test]
fn cm_declares_elf_program_and_config_schema() {
    let bytes = read_artifact("HELLO_CM");
    let component: fdecl::Component =
        fidl::unpersist(&bytes).expect("meta/hello_cml.cm is not persistent-FIDL Component");

    // program { runner: "elf", binary: "bin/hello_cml" }
    let program = component.program.as_ref().expect("component has no program");
    assert_eq!(
        program.runner.as_deref(),
        Some("elf"),
        "program.runner must be elf (from the .cml)"
    );
    let info = program.info.as_ref().expect("program has no info dictionary");
    match dict_get(info, "binary") {
        Some(fdata::DictionaryValue::Str(s)) => {
            assert_eq!(s, "bin/hello_cml", "program.binary")
        }
        other => panic!("program.info[binary] not a string: {other:?}"),
    }

    // config schema: the declared fields survive cmc lowering, and the value source
    // points at the package-relative .cvf path cerise_component wired.
    let schema = component.config.as_ref().expect("component has no config schema");
    let field_keys: Vec<&str> = schema
        .fields
        .as_ref()
        .expect("config schema has no fields")
        .iter()
        .map(|f| f.key.as_deref().expect("config field missing key"))
        .collect();
    assert!(field_keys.contains(&"greeting"), "schema missing greeting: {field_keys:?}");
    assert!(field_keys.contains(&"max_len"), "schema missing max_len: {field_keys:?}");

    match schema.value_source.as_ref().expect("config has no value_source") {
        fdecl::ConfigValueSource::PackagePath(p) => {
            assert_eq!(p, "meta/hello_cml.cvf", "config value_source package path")
        }
        other => panic!("unexpected config value_source: {other:?}"),
    }
}

#[test]
fn cvf_delivers_the_build_time_values() {
    // Read the field order from the .cm so we can pair schema fields with .cvf values
    // by ordinal (configc emits values in schema-field order).
    let cm_bytes = read_artifact("HELLO_CM");
    let component: fdecl::Component = fidl::unpersist(&cm_bytes).expect("decode .cm");
    let schema = component.config.as_ref().expect("no config schema");
    let field_keys: Vec<String> = schema
        .fields
        .as_ref()
        .expect("no fields")
        .iter()
        .map(|f| f.key.clone().expect("field key"))
        .collect();

    let cvf_bytes = read_artifact("HELLO_CVF");
    let values_data: fdecl::ConfigValuesData =
        fidl::unpersist(&cvf_bytes).expect("meta/hello_cml.cvf is not persistent-FIDL ConfigValuesData");

    // The delivery-consistency gate: component_manager (and the generated crate's
    // from_bytes, whose error enum has ChecksumMismatch) rejects a .cvf whose
    // ConfigChecksum doesn't match the .cm schema's. Asserting it here proves these
    // two artifacts belong together — and catches the exact future regression
    // (a stale/divergent manifest threaded into the cvf stage) that would break
    // runtime delivery, turning the docs' "proves delivery" claim from
    // by-construction into asserted.
    assert_eq!(
        schema.checksum, values_data.checksum,
        ".cvf checksum must match .cm schema checksum (runtime config-delivery gate)"
    );
    let values = values_data.values.expect("cvf has no values");
    assert_eq!(
        values.len(),
        field_keys.len(),
        "cvf value count must match schema field count"
    );

    let value_for = |key: &str| -> &fdecl::ConfigValue {
        let idx = field_keys.iter().position(|k| k == key).expect("key in schema");
        values[idx].value.as_ref().expect("value spec has value")
    };

    match value_for("greeting") {
        fdecl::ConfigValue::Single(fdecl::ConfigSingleValue::String(s)) => {
            assert_eq!(s, "hello-cerise", "delivered greeting value")
        }
        other => panic!("greeting not a single string: {other:?}"),
    }
    match value_for("max_len") {
        fdecl::ConfigValue::Single(fdecl::ConfigSingleValue::Uint32(n)) => {
            assert_eq!(*n, 64, "delivered max_len value")
        }
        other => panic!("max_len not a single uint32: {other:?}"),
    }
}

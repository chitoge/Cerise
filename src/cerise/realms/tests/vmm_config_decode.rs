// Artifact-level proof that the VMM's structured config is DELIVERED, not merely
// declared.
//
// The VMM takes no parameters of any kind today: two startup handles and nothing
// else. Every knob — guest RAM, the cache bound, the deadline, the trace budget,
// the firmware path — is a compile-time constant, which is why there are three
// binary targets over identical sources differing only by `rustc_env`. The
// component build replaces all of that with one delivered config VMO, and this
// host test decodes the two artifacts that carry it:
//
//   * meta/cryogen_vmm.cm  -> the SCHEMA cmc lowered out of the .cml, with
//     value_source pointing at the .cvf's package path.
//   * meta/cryogen_vmm.cvf -> the VALUES configc produced from BUILD.bazel.
//
// Modelled on //src/cerise/hello_cml:decode_test, which proves the same pipeline
// for the demonstrator. Two things it asserts that a "the file is non-empty"
// check would not:
//
//   * THE CHECKSUMS MATCH. component_manager rejects a .cvf whose ConfigChecksum
//     differs from the .cm schema's, so a stale manifest threaded into the cvf
//     stage produces two artifacts that each decode fine and cannot be delivered
//     together. Asserting equality here is what turns "the pipeline ran" into
//     "these two belong to each other".
//   * `low_mmio_mb` IS ABSENT. That is a deliberate omission, not an oversight:
//     the LAPIC guard's negative control is a separately built binary with a
//     24 MiB window, and converting that knob to config without replacing the
//     control would delete one of the few observed-red gates in this package. A
//     test that only checks what is present would let it reappear silently.
//
// Field->value correspondence is derived structurally: configc emits .cvf values
// in the .cm schema's field order, so values[i] pairs with fields[i]. The order
// is read out of the .cm rather than assumed.

use fidl_fuchsia_component_decl as fdecl;
use fidl_fuchsia_data as fdata;
use std::path::PathBuf;

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

fn schema_field_keys(component: &fdecl::Component) -> Vec<String> {
    component
        .config
        .as_ref()
        .expect("the VMM manifest declares a config schema")
        .fields
        .as_ref()
        .expect("config schema has fields")
        .iter()
        .map(|f| f.key.clone().expect("config field has a key"))
        .collect()
}

#[test]
fn cm_declares_the_elf_program_and_the_whole_config_schema() {
    let bytes = read_artifact("VMM_CM");
    let component: fdecl::Component =
        fidl::unpersist(&bytes).expect("meta/cryogen_vmm.cm is not persistent-FIDL Component");

    let program = component.program.as_ref().expect("component has a program");
    assert_eq!(program.runner.as_deref(), Some("elf"), "program.runner");
    let info = program.info.as_ref().expect("program has an info dictionary");
    match dict_get(info, "binary") {
        Some(fdata::DictionaryValue::Str(s)) => assert_eq!(s, "bin/cryogen_vmm"),
        other => panic!("program.info[binary] is not a string: {other:?}"),
    }

    // The job-policy flag the VMM must NOT ask for. `zx_vmo_replace_as_executable`
    // enforces ZX_POL_AMBIENT_MARK_VMO_EXEC only when the vmex handle is invalid,
    // and the VMM passes a real one — while the tree's allowlist for that flag is
    // empty (default-deny), so requesting it would fail loudly for no benefit.
    assert!(
        dict_get(info, "job_policy_ambient_mark_vmo_exec").is_none(),
        "the VMM must not request ambient mark-vmo-exec: it holds a real VmexResource, \
         and the job_policy allowlist for that flag is empty"
    );

    let keys = schema_field_keys(&component);
    for expected in [
        "guest_mem_mb",
        "vp_count",
        "cryogen_cache_pages",
        "guest_deadline_secs",
        "fw_line_budget",
        "firmware_path",
        "store_source",
        "store_partition_guid",
        "store_path",
        "store_server",
        "vmi_enabled",
    ] {
        assert!(keys.iter().any(|k| k == expected), "schema is missing {expected}: {keys:?}");
    }

    // Deliberately absent — see this file's header. If this ever fires, the LAPIC
    // guard's negative control needs a replacement in the same change.
    assert!(
        !keys.iter().any(|k| k == "low_mmio_mb"),
        "low_mmio_mb must stay a build-time constant until the LAPIC-guard negative \
         control is replaced by a second product with a different .cvf; it is the \
         control that made the guard observable, and converting the knob without \
         replacing the control deletes it silently: {keys:?}"
    );

    match component
        .config
        .as_ref()
        .unwrap()
        .value_source
        .as_ref()
        .expect("config has a value_source")
    {
        fdecl::ConfigValueSource::PackagePath(p) => assert_eq!(p, "meta/cryogen_vmm.cvf"),
        other => panic!("unexpected config value_source: {other:?}"),
    }
}

#[test]
fn cvf_delivers_the_build_time_values() {
    let cm_bytes = read_artifact("VMM_CM");
    let component: fdecl::Component = fidl::unpersist(&cm_bytes).expect("decode .cm");
    let field_keys = schema_field_keys(&component);
    let schema = component.config.as_ref().unwrap();

    let cvf_bytes = read_artifact("VMM_CVF");
    let values_data: fdecl::ConfigValuesData = fidl::unpersist(&cvf_bytes)
        .expect("meta/cryogen_vmm.cvf is not persistent-FIDL ConfigValuesData");

    assert_eq!(
        schema.checksum, values_data.checksum,
        ".cvf checksum must match the .cm schema checksum, or component_manager will \
         refuse to deliver these two together at runtime"
    );
    let values = values_data.values.expect("cvf has values");
    assert_eq!(values.len(), field_keys.len(), "one value per schema field");

    let value_for = |key: &str| -> &fdecl::ConfigValue {
        let idx = field_keys
            .iter()
            .position(|k| k == key)
            .unwrap_or_else(|| panic!("{key} is in the schema"));
        values[idx].value.as_ref().expect("value spec has a value")
    };
    let u32_of = |key: &str| -> u32 {
        match value_for(key) {
            fdecl::ConfigValue::Single(fdecl::ConfigSingleValue::Uint32(n)) => *n,
            other => panic!("{key} is not a single uint32: {other:?}"),
        }
    };
    let str_of = |key: &str| -> String {
        match value_for(key) {
            fdecl::ConfigValue::Single(fdecl::ConfigSingleValue::String(s)) => s.clone(),
            other => panic!("{key} is not a single string: {other:?}"),
        }
    };
    let bool_of = |key: &str| -> bool {
        match value_for(key) {
            fdecl::ConfigValue::Single(fdecl::ConfigSingleValue::Bool(v)) => *v,
            other => panic!("{key} is not a single bool: {other:?}"),
        }
    };

    // The synthetic gate's numbers, and they are small on purpose. A four-page
    // cache is below the synthetic store's whole content, which is what makes
    // every run of that gate exercise eviction; raising it would quietly change
    // what a green run proves.
    assert_eq!(u32_of("cryogen_cache_pages"), 4, "the cache bound that forces eviction");
    assert_eq!(u32_of("guest_mem_mb"), 512);
    assert_eq!(u32_of("guest_deadline_secs"), 45);
    assert_eq!(u32_of("fw_line_budget"), 2000);
    match value_for("vp_count") {
        fdecl::ConfigValue::Single(fdecl::ConfigSingleValue::Uint8(n)) => assert_eq!(*n, 1),
        other => panic!("vp_count is not a single uint8: {other:?}"),
    }

    // The firmware path is a config fact rather than a constant precisely so the
    // package layout and the program cannot disagree silently, so assert it names
    // the component's own package directory.
    let fw = str_of("firmware_path");
    assert!(
        fw.starts_with("/pkg/"),
        "the firmware must come from the component's own package directory, got {fw:?}"
    );

    // "none" is the blank-disk configuration. It is a deliberately producible
    // intermediate state, and the values shipped here are that state — so a run
    // of this component cannot be reading a store nobody configured.
    assert_eq!(str_of("store_source"), "none");
    assert!(!bool_of("vmi_enabled"), "the ordinary boot gate must terminate");
    assert_eq!(
        str_of("store_partition_guid"),
        "",
        "store_source=\"none\" must not carry a partition GUID: a GUID that is present \
         but unused is a GUID somebody will later assume was chosen"
    );
}

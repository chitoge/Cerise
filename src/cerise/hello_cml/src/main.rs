// Cerise demonstrator: an ELF component that reads its OWN structured config at
// runtime and proves the delivered values match what the build put in meta/hello_cml.cvf.
//
// The config path is the real Fuchsia one, end to end:
//   * meta/hello_cml.cml declares `config: { greeting, max_len }` (the SCHEMA).
//   * cmc lowers that schema into meta/hello_cml.cm, with value_source pointing at
//     meta/hello_cml.cvf.
//   * configc turns the BUILD.bazel `config_values` dict into meta/hello_cml.cvf
//     (the VALUES).
//   * component_manager's config resolution hands us those values as the config VMO
//     on the ComponentConfigVmo startup handle.
//   * `hello_cml_config::Config::take_from_startup_handle()` (the crate cmc/configc
//     generate from the SAME schema) takes that handle and FIDL-decodes it.
//
// Previously, components like fshost/driver-index hardcoded `Config`
// literals in Rust because there was no delivery path. Here the value is authored
// once, in BUILD.bazel, and travels through cmc/configc to the component untouched.
//
// The on-target proof boots this component in a product and observes
// CERISE-CONFIG-OK on serial.
//
// `hello_cml_config::Config::take_from_startup_handle()` is an inherent method the
// generated crate provides (it delegates to the fuchsia_component_config::Config
// trait internally), so no trait import is needed here.

fn emit(msg: &str) {
    unsafe {
        zx::sys::zx_debug_write(msg.as_ptr(), msg.len());
    }
}

// Build-time expectations — must match the `config_values` in BUILD.bazel. If the
// delivered VMO round-trips these, the whole cmc/configc/component_manager delivery
// path is proven live.
const EXPECTED_GREETING: &str = "hello-cerise";
const EXPECTED_MAX_LEN: u32 = 64;

#[fuchsia::main(logging_tags = ["hello_cml"])]
async fn main() {
    // Boot marker — keep on serial verbatim (matches the documented convention).
    emit("CERISE-HELLO-CML-START\n");

    // Take the config VMO from the startup handle and FIDL-decode it via the
    // generated (schema-derived) Config wrapper.
    let config = hello_cml_config::Config::take_from_startup_handle();

    // Delivered structured-config values: ops output -> structured LogSink record
    // (tag "hello_cml"), no longer a raw serial line.
    log::info!(
        greeting:% = config.greeting, max_len = config.max_len;
        "hello_cml decoded delivered structured config"
    );

    if config.greeting == EXPECTED_GREETING && config.max_len == EXPECTED_MAX_LEN {
        // Delivered structured config matched the build-time values byte for byte.
        // Boot-gate marker — keep on serial verbatim.
        emit("CERISE-CONFIG-OK\n");
    } else {
        log::error!(
            greeting:% = config.greeting, max_len = config.max_len,
            want_greeting:% = EXPECTED_GREETING, want_max_len = EXPECTED_MAX_LEN;
            "hello_cml structured-config mismatch"
        );
    }
}

// Cerise stub for include_bytes_from_working_dir.
// Real implementation is a proc-macro that embeds file bytes from an env-var path.
// For component-manager bring-up, all embedded CML data returns empty bytes (not launched at runtime yet).

/// Stub macro — evaluates to an empty byte slice literal.
/// Used in component_manager/builtin_resolver.rs to embed ELF runner / dispatcher CML.
#[macro_export]
macro_rules! include_bytes_from_working_dir_env {
    ($env_name:literal) => {
        &[] as &'static [u8]
    };
}

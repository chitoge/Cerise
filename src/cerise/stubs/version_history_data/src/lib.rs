// Cerise stub: provides VERSION_HISTORY as raw JSON bytes for the
// version_history_macro proc-macro to parse at compile time.
// This mimics the Fuchsia rustc_embed_files("version_history_data") build rule.
pub const VERSION_HISTORY: &[u8] =
    include_bytes!("../version_history.json");

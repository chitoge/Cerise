// Cerise stub for dispatcher_config.
// Real dispatcher_config is generated from a component configuration schema.
// for component-manager bring-up we provide a stub Config that always returns an empty/default config.

/// Stub dispatcher configuration.
pub struct Config {
    pub type_to_dispatch: String,
    pub what_to_dispatch: String,
    pub who_to_dispatch_to: String,
}

impl Config {
    pub fn from_vmo(_vmo: &zx::Vmo) -> Result<Self, anyhow::Error> {
        Ok(Config {
            type_to_dispatch: String::new(),
            what_to_dispatch: String::new(),
            who_to_dispatch_to: String::new(),
        })
    }
}

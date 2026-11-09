// Cerise stand-in for the service-broker builtin runner.
//
// Not implemented in Cerise yet. The previous stub returned Ok(()) immediately,
// making any component assigned this runner "succeed" instantly while brokering nothing —
// a masked failure. No component in the current topology uses it, so fail loud: a future
// consumer breaks here with a clear message instead of silently downstream.
use anyhow::{bail, Result};
use fidl::endpoints::ServerEnd;
use fidl_fuchsia_data as fdata;
use fidl_fuchsia_io as fio;
use fidl_fuchsia_process as fprocess;
use fidl_fuchsia_process_lifecycle as fpl;

pub async fn main(
    _ns_entries: Vec<fprocess::NameInfo>,
    _directory_request: ServerEnd<fio::DirectoryMarker>,
    _lifecycle: ServerEnd<fpl::LifecycleMarker>,
    _program: Option<fdata::Dictionary>,
) -> Result<()> {
    bail!("CERISE: service-broker builtin runner is not implemented. A component \
           was assigned the service-broker runner; implement it before relying on it.");
}

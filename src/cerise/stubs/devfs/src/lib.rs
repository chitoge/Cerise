// Cerise stand-in for the devfs builtin runner.
//
// The real devfs runner serves the device filesystem. It is NOT implemented in Cerise
// yet. The previous stub returned Ok(()) immediately, which makes any component
// assigned the devfs runner "succeed" instantly — a masked failure: dependents see the
// runner come up, then nothing serves the directory. No component in the current topology
// uses this runner, so fail loud instead: if one ever does, it breaks here with a
// clear message rather than silently elsewhere.
use anyhow::{bail, Result};
use fidl::endpoints::ServerEnd;
use fidl_fuchsia_io as fio;
use fidl_fuchsia_process as fprocess;
use fidl_fuchsia_process_lifecycle as fpl;

pub async fn main(
    _ns_entries: Vec<fprocess::NameInfo>,
    _directory_request: ServerEnd<fio::DirectoryMarker>,
    _lifecycle: ServerEnd<fpl::LifecycleMarker>,
) -> Result<()> {
    bail!("CERISE: devfs builtin runner is not implemented. A component was \
           assigned the devfs runner; implement it before relying on devfs.");
}

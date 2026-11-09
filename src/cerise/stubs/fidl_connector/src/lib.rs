// Cerise stub for fidl-connector.
// Provides the Connect trait used by elf_runner's process_launcher.

pub trait Connect {
    type Proxy;

    fn connect(&self) -> Result<Self::Proxy, anyhow::Error>;
}

// Cerise stub for attribution_server (memory attribution).
// for component-manager bring-up we only need the API surface to compile elf_runner's memory reporter.

use fidl_fuchsia_memory_attribution as fattribution;

pub struct AttributionServerHandle(AttributionServer);

pub struct AttributionServer;

impl AttributionServer {
    pub fn new(
        _get_attribution: Box<dyn Fn() -> Vec<fattribution::AttributionUpdate> + Send + Sync>,
    ) -> AttributionServerHandle {
        AttributionServerHandle(AttributionServer)
    }

    pub fn new_publisher(&self) -> Publisher {
        Publisher
    }

    pub fn new_observer(&self, _control_handle: impl std::any::Any) -> Observer {
        Observer
    }
}

impl AttributionServerHandle {
    pub fn new_publisher(&self) -> Publisher {
        Publisher
    }

    pub fn new_observer(&self, _control_handle: impl std::any::Any) -> Observer {
        Observer
    }
}

pub struct Publisher;

impl Publisher {
    pub fn on_update(&self, _updates: Vec<fattribution::AttributionUpdate>) {}
}

pub struct Observer;

impl Observer {
    pub fn next(&self, _responder: impl std::any::Any) {}
}

//! VM inventory and image-store status from the component that owns them.

use anyhow::{anyhow, Context, Result};
use fidl_cerise_vm as fvm;
use fuchsia_component::client::connect_to_protocol_at_path;

#[derive(Clone)]
pub struct Store {
    pub total_bytes: u64,
    pub used_bytes: u64,
    pub free_bytes: u64,
}

#[derive(Clone)]
pub struct Image {
    pub id: String,
    pub name: String,
    pub stored_bytes: u64,
    pub virtual_bytes: u64,
}

#[derive(Clone, Copy)]
pub enum State {
    Stopped,
    Starting,
    Running,
    Paused,
    Failed,
    Unknown,
}

impl State {
    pub fn text(self) -> &'static str {
        match self {
            Self::Stopped => "STOPPED",
            Self::Starting => "STARTING",
            Self::Running => "RUNNING",
            Self::Paused => "PAUSED",
            Self::Failed => "FAILED",
            Self::Unknown => "UNKNOWN",
        }
    }
}

#[derive(Clone, Copy)]
pub enum Population {
    Unpopulated,
    Populating,
    Populated,
    Degraded,
    Unknown,
}

impl Population {
    pub fn text(self) -> &'static str {
        match self {
            Self::Unpopulated => "UNPOPULATED",
            Self::Populating => "POPULATING",
            Self::Populated => "POPULATED",
            Self::Degraded => "DEGRADED",
            Self::Unknown => "UNKNOWN",
        }
    }
}

#[derive(Clone)]
pub struct Vm {
    pub id: String,
    pub name: String,
    pub image_id: String,
    pub state: State,
    pub memory_mib: u64,
    pub vp_count: u32,
    pub epoch: u64,
    pub head_id: String,
    pub memory_only: bool,
    pub snapshot_count: u64,
    pub checkpoint_count: u64,
    pub last_error: String,
    pub desired_state: State,
    pub observed_state: Option<State>,
    pub population: Population,
    pub resident_dirty_bytes: u64,
    pub spill_bytes: u64,
}

pub struct Report {
    pub store: Option<Store>,
    pub images: Vec<Image>,
    pub vms: Vec<Vm>,
    pub gateway_port: Option<u16>,
}

fn state(value: fvm::State) -> State {
    match value {
        fvm::State::Stopped => State::Stopped,
        fvm::State::Starting => State::Starting,
        fvm::State::Running => State::Running,
        fvm::State::Paused => State::Paused,
        fvm::State::Failed => State::Failed,
        _ => State::Unknown,
    }
}

fn population(value: fvm::Population) -> Population {
    match value {
        fvm::Population::Unpopulated => Population::Unpopulated,
        fvm::Population::Populating => Population::Populating,
        fvm::Population::Populated => Population::Populated,
        fvm::Population::Degraded => Population::Degraded,
        _ => Population::Unknown,
    }
}

pub struct Status {
    proxies: Vec<fvm::StatusProxy>,
}

impl Status {
    pub fn connect() -> Result<Self> {
        // The gateway is the inventory join point. Opening worker slots here
        // would make the UI a second population model and would duplicate VMs
        // whenever a gateway already aggregated them.
        let proxies = vec![connect_to_protocol_at_path::<fvm::StatusMarker>(
            "/svc/cerise.vm.Status.catalog",
        )
        .context("connect VM catalog authority")?];
        Ok(Self { proxies })
    }

    pub async fn report(&self) -> Result<Report> {
        let mut reports = Vec::new();
        for proxy in &self.proxies {
            if let Ok(report) = proxy.get_report().await {
                reports.push(report);
            }
        }
        if reports.is_empty() {
            return Err(anyhow!("no VM status source returned a report"));
        }
        let mut store = None;
        let mut images = Vec::new();
        let mut vms = Vec::new();
        let mut gateway_port = None;
        let mut health_errors = Vec::new();
        let mut counted_store_images = Vec::<String>::new();
        for report in reports {
            if let Some(health) = &report.health {
                if health.available == Some(false) {
                    health_errors.push(
                        health
                            .message
                            .clone()
                            .filter(|message| !message.is_empty())
                            .unwrap_or_else(|| "VM status service is unavailable".to_owned()),
                    );
                    continue;
                }
            }
            let report_image_ids = report
                .images
                .as_ref()
                .into_iter()
                .flatten()
                .filter_map(|image| image.id.clone())
                .collect::<Vec<_>>();
            let store_already_counted = !report_image_ids.is_empty()
                && report_image_ids
                    .iter()
                    .all(|id| counted_store_images.contains(id));
            if let Some(part) = report.store.filter(|_| !store_already_counted) {
                let part = Store {
                    total_bytes: part
                        .total_bytes
                        .ok_or_else(|| anyhow!("VM store omitted total_bytes"))?,
                    used_bytes: part
                        .used_bytes
                        .ok_or_else(|| anyhow!("VM store omitted used_bytes"))?,
                    free_bytes: part
                        .free_bytes
                        .ok_or_else(|| anyhow!("VM store omitted free_bytes"))?,
                };
                let total = store.get_or_insert(Store {
                    total_bytes: 0,
                    used_bytes: 0,
                    free_bytes: 0,
                });
                total.total_bytes = total.total_bytes.saturating_add(part.total_bytes);
                total.used_bytes = total.used_bytes.saturating_add(part.used_bytes);
                total.free_bytes = total.free_bytes.saturating_add(part.free_bytes);
            }
            for id in report_image_ids {
                if !counted_store_images.contains(&id) {
                    counted_store_images.push(id);
                }
            }
            images.extend(report.images.unwrap_or_default().into_iter().map(|image| Image {
                id: image.id.unwrap_or_default(),
                name: image.name.unwrap_or_default(),
                stored_bytes: image.stored_bytes.unwrap_or(0),
                virtual_bytes: image.virtual_bytes.unwrap_or(0),
            }));
            vms.extend(report.vms.unwrap_or_default().into_iter().map(|vm| Vm {
                id: vm.id.unwrap_or_default(),
                name: vm.name.unwrap_or_default(),
                image_id: vm.image_id.unwrap_or_default(),
                state: vm.state.map(state).unwrap_or(State::Unknown),
                memory_mib: vm.memory_mib.unwrap_or(0),
                vp_count: vm.vp_count.unwrap_or(0),
                epoch: vm.epoch.unwrap_or(0),
                head_id: vm.head_id.unwrap_or_default(),
                memory_only: vm.memory_only.unwrap_or(false),
                snapshot_count: vm.snapshot_count.unwrap_or(0),
                checkpoint_count: vm.checkpoint_count.unwrap_or(0),
                last_error: vm.last_error.unwrap_or_default(),
                desired_state: vm.desired_state.map(state).unwrap_or(State::Unknown),
                observed_state: vm.observed_state.map(state),
                population: vm
                    .population
                    .map(population)
                    .unwrap_or(Population::Unknown),
                resident_dirty_bytes: vm.resident_dirty_bytes.unwrap_or(0),
                spill_bytes: vm.spill_bytes.unwrap_or(0),
            }));
            gateway_port = gateway_port.or(report.gateway_port);
        }
        if !health_errors.is_empty() {
            return Err(anyhow!(health_errors.join("; ")));
        }
        images.sort_by(|a, b| a.id.cmp(&b.id));
        images.dedup_by(|a, b| a.id == b.id);
        vms.sort_by(|a, b| a.id.cmp(&b.id));
        vms.dedup_by(|a, b| a.id == b.id);
        Ok(Report { store, images, vms, gateway_port })
    }
}

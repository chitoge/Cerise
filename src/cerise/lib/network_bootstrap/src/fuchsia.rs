//! Fuchsia interface-installation adapter.
//!
//! This is deliberately a separate target from the generic RAII crate: endpoint
//! ownership and policy are host-testable, while devfs/FIDL work only exists on
//! Fuchsia.

#![forbid(unsafe_code)]

use anyhow::{anyhow, Context, Result};
use cerise_network_bootstrap::{BootstrapPolicy, NetworkBootstrap};
use fidl::endpoints::{create_endpoints, create_proxy, ServerEnd};
use fidl_fuchsia_device as fdevice;
use fidl_fuchsia_hardware_network as fhardware_network;
use fidl_fuchsia_io as fio;
use fidl_fuchsia_net as fnet;
use fidl_fuchsia_net_head as fnet_head;
use fidl_fuchsia_net_interfaces as fnet_interfaces;
use fidl_fuchsia_net_interfaces_admin as fnet_interfaces_admin;
use fidl_fuchsia_net_resources as fnet_resources;
use fidl_fuchsia_net_routes as fnet_routes;
use fidl_fuchsia_net_routes_admin as fnet_routes_admin;
use fidl_fuchsia_posix_socket as fposix_socket;
use fidl_fuchsia_posix_socket_packet as fppacket;
use fuchsia_component::client::connect_to_protocol;
use fuchsia_fs::directory::{open_channel_in_namespace, readdir};
use fuchsia_fs::node::open_channel_in_namespace as open_node_channel_in_namespace;

pub type InterfaceLifetime = NetworkBootstrap<
    fnet_interfaces_admin::ControlProxy,
    fnet_interfaces_admin::DeviceControlProxy,
    fnet_interfaces_admin::AddressStateProviderProxy,
    fnet_routes_admin::RouteSetV4Proxy,
>;

/// How the adapter obtains its IPv4 address.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Ipv4Configuration {
    Static { address: [u8; 4], prefix_len: u8 },
    Dhcp { timeout_seconds: u32 },
}

/// Fuchsia-specific configuration for one interface bootstrap.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FuchsiaBootstrapConfig {
    pub interface_name: &'static str,
    pub ipv4: Ipv4Configuration,
    pub policy: BootstrapPolicy,
    /// DHCP must enable before DORA. The spike intentionally tests add-before-enable.
    pub enable_before_address: bool,
    pub observe_slaac: bool,
    pub install_default_route: bool,
    pub check_socket_provider: bool,
}

/// Address information returned by a successfully provisioned interface.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ipv4Result {
    pub address: [u8; 4],
    pub prefix_len: u8,
    pub router: Option<[u8; 4]>,
    pub dns_servers: Vec<[u8; 4]>,
    pub default_route_installed: bool,
}

/// Result and lifetime token. `lifetime` is `None` only when a compatible
/// existing interface was intentionally reused.
#[must_use = "retain lifetime while the installed interface is required"]
pub struct FuchsiaBootstrapResult {
    pub lifetime: Option<InterfaceLifetime>,
    pub interface_id: Option<u64>,
    pub ipv4: Option<Ipv4Result>,
    pub reused_existing_ipv4: bool,
    pub slaac_link_local_observed: Option<bool>,
}

fn trace(trace: Option<fn(&str)>, stage: &str) {
    if let Some(trace) = trace {
        trace(stage);
    }
}

async fn existing_ipv4_interface() -> bool {
    let Ok(state) = connect_to_protocol::<fnet_interfaces::StateMarker>() else {
        return false;
    };
    let (watcher, server) = create_proxy::<fnet_interfaces::WatcherMarker>();
    if state
        .get_watcher(&fnet_interfaces::WatcherOptions::default(), server)
        .is_err()
    {
        return false;
    }
    loop {
        let deadline =
            fuchsia_async::MonotonicInstant::after(std::time::Duration::from_secs(5).into());
        let event = match fuchsia_async::TimeoutExt::on_timeout(
            async { Some(watcher.watch().await) },
            deadline,
            || None,
        )
        .await
        {
            Some(Ok(event)) => event,
            Some(Err(_)) | None => return false,
        };
        let props = match event {
            fnet_interfaces::Event::Existing(p) | fnet_interfaces::Event::Added(p) => p,
            fnet_interfaces::Event::Idle(_) => return false,
            _ => continue,
        };
        if props.addresses.as_ref().is_some_and(|addresses| addresses.iter().any(|address| matches!(
            address.addr,
            Some(fnet::Subnet { addr: fnet::IpAddress::Ipv4(fnet::Ipv4Address { addr: [first, ..] }), .. }) if first != 127
        ))) { return true; }
    }
}

async fn find_first_network_instance() -> Result<String> {
    let (dev_dir, server) = create_proxy::<fio::DirectoryMarker>();
    open_channel_in_namespace(
        "/dev/class/network",
        fio::PERM_READABLE,
        ServerEnd::new(server.into_channel()),
    )
    .context("open /dev/class/network")?;
    let entries = readdir(&dev_dir).await.context("read /dev/class/network")?;
    entries
        .into_iter()
        .next()
        .map(|entry| entry.name)
        .ok_or_else(|| anyhow!("no network device appeared under /dev/class/network"))
}

async fn open_network_device(
    instance: &str,
) -> Result<fidl::endpoints::ClientEnd<fhardware_network::DeviceMarker>> {
    let node_path = format!("/dev/class/network/{instance}/device_controller");
    let (controller, server) = create_proxy::<fdevice::ControllerMarker>();
    open_node_channel_in_namespace(
        &node_path,
        fio::Flags::PROTOCOL_SERVICE,
        ServerEnd::new(server.into_channel()),
    )
    .context("open device_controller")?;
    controller
        .get_topological_path()
        .await
        .context("GetTopologicalPath transport")?
        .map_err(|status| anyhow!("GetTopologicalPath: {status}"))?;
    let (client, server) = create_endpoints::<fhardware_network::DeviceMarker>();
    controller
        .connect_to_device_fidl(server.into_channel())
        .context("ConnectToDeviceFidl")?;
    Ok(client)
}

async fn discover_port_id(
    device: fhardware_network::DeviceProxy,
) -> Result<fhardware_network::PortId> {
    let (watcher, server) = create_proxy::<fhardware_network::PortWatcherMarker>();
    device.get_port_watcher(server).context("GetPortWatcher")?;
    for _ in 0..8 {
        match watcher
            .watch()
            .await
            .context("PortWatcher.Watch transport")?
        {
            fhardware_network::DevicePortEvent::Existing(port) => return Ok(port),
            fhardware_network::DevicePortEvent::Idle(_) => break,
            _ => {}
        }
    }
    Err(anyhow!("no port before Idle"))
}

async fn install_default_route(
    control: &fnet_interfaces_admin::ControlProxy,
    interface_id: u64,
    router: [u8; 4],
) -> Result<fnet_routes_admin::RouteSetV4Proxy> {
    let routes = connect_to_protocol::<fnet_routes_admin::RouteTableV4Marker>()
        .context("connect RouteTableV4")?;
    let (route_set, server) = create_proxy::<fnet_routes_admin::RouteSetV4Marker>();
    routes
        .new_route_set(server)
        .context("creating DHCP route set")?;
    let fnet_resources::GrantForInterfaceAuthorization {
        interface_id: authorized_interface,
        token,
    } = control
        .get_authorization_for_interface()
        .await
        .context("getting interface route authorization")?;
    anyhow::ensure!(
        authorized_interface == interface_id,
        "interface authorization named {authorized_interface}, expected {interface_id}"
    );
    route_set
        .authenticate_for_interface(fnet_resources::ProofOfInterfaceAuthorization {
            interface_id: authorized_interface,
            token,
        })
        .await
        .context("authenticating IPv4 route set")?
        .map_err(|error| anyhow!("route-set authentication failed: {error:?}"))?;
    let route = fnet_routes::RouteV4 {
        destination: fnet_head::Ipv4AddressWithPrefix {
            addr: fnet_head::Ipv4Address { addr: [0; 4] },
            prefix_len: 0,
        },
        action: fnet_routes::RouteActionV4::Forward(fnet_routes::RouteTargetV4 {
            outbound_interface: interface_id,
            next_hop: Some(Box::new(fnet_head::Ipv4Address { addr: router })),
        }),
        properties: fnet_routes::RoutePropertiesV4 {
            specified_properties: Some(fnet_routes::SpecifiedRouteProperties {
                metric: Some(fnet_routes::SpecifiedMetric::InheritedFromInterface(
                    fnet_routes::Empty {},
                )),
                ..Default::default()
            }),
            ..Default::default()
        },
    };
    route_set
        .add_route(&route)
        .await
        .context("adding DHCP default route")?
        .map_err(|error| anyhow!("adding DHCP default route failed: {error:?}"))?;
    Ok(route_set)
}

/// Discovers, installs, enables, addresses, and retains one netstack interface.
async fn bootstrap_once(
    config: FuchsiaBootstrapConfig,
    stage_trace: Option<fn(&str)>,
) -> Result<FuchsiaBootstrapResult> {
    trace(stage_trace, "FIND-INSTANCE");
    let instance = find_first_network_instance().await?;
    trace(stage_trace, "OPEN-DEVICE-FOR-PORT");
    let port_device = open_network_device(&instance).await?.into_proxy();
    trace(stage_trace, "DISCOVER-PORT-ID");
    let port_id = discover_port_id(port_device).await?;
    trace(stage_trace, "OPEN-DEVICE-FOR-INSTALL");
    let install_device = open_network_device(&instance).await?;
    trace(stage_trace, "CONNECT-INSTALLER");
    let installer = connect_to_protocol::<fnet_interfaces_admin::InstallerMarker>()
        .context("connect Installer")?;
    trace(stage_trace, "INSTALL-DEVICE");
    let (device_control, device_server) =
        create_proxy::<fnet_interfaces_admin::DeviceControlMarker>();
    installer
        .install_device(install_device, device_server)
        .context("InstallDevice")?;
    trace(stage_trace, "CREATE-INTERFACE");
    let (control, control_server) = create_proxy::<fnet_interfaces_admin::ControlMarker>();
    device_control
        .create_interface(
            &port_id,
            control_server,
            fnet_interfaces_admin::Options {
                name: Some(config.interface_name.to_string()),
                ..Default::default()
            },
        )
        .context("CreateInterface")?;
    if config.enable_before_address {
        trace(stage_trace, "ENABLE");
        control
            .enable()
            .await
            .context("Enable transport")?
            .map_err(|error| anyhow!("Enable: {error:?}"))?;
    }
    let interface_id = control.get_id().await.context("GetId transport")?;
    let (address, prefix_len, router, dns_servers) = match config.ipv4 {
        Ipv4Configuration::Static {
            address,
            prefix_len,
        } => (address, prefix_len, None, Vec::new()),
        Ipv4Configuration::Dhcp { timeout_seconds } => {
            trace(stage_trace, "DHCP-DORA");
            let provider = connect_to_protocol::<fppacket::ProviderMarker>()
                .context("connect packet Provider")?;
            let lease = cerise_dhcp::acquire(&provider, interface_id, timeout_seconds as f64)
                .await
                .context("DHCP DORA failed")?;
            (lease.yiaddr, lease.prefix_len, lease.router, lease.dns)
        }
    };
    trace(stage_trace, "ADD-ADDRESS");
    let (address_state_provider, asp_server) =
        create_proxy::<fnet_interfaces_admin::AddressStateProviderMarker>();
    control
        .add_address(
            &fnet::Subnet {
                addr: fnet::IpAddress::Ipv4(fnet::Ipv4Address { addr: address }),
                prefix_len,
            },
            &fnet_interfaces_admin::AddressParameters {
                add_subnet_route: Some(true),
                perform_dad: Some(false),
                ..Default::default()
            },
            asp_server,
        )
        .context("AddAddress")?;
    if !config.enable_before_address {
        trace(stage_trace, "ENABLE");
        control
            .enable()
            .await
            .context("Enable transport")?
            .map_err(|error| anyhow!("Enable: {error:?}"))?;
    }
    let default_route = if config.install_default_route {
        match router {
            Some(gateway) => match install_default_route(&control, interface_id, gateway).await {
                Ok(route_set) => Some(route_set),
                Err(error) => {
                    log::warn!(error:?; "DHCP default route was not installed");
                    None
                }
            },
            None => None,
        }
    } else {
        None
    };
    let slaac_link_local_observed = if config.observe_slaac {
        trace(stage_trace, "SLAAC-WATCH");
        match connect_to_protocol::<fnet_interfaces::StateMarker>()
            .context("connect interfaces.State")
        {
            Ok(state) => match cerise_dhcp::observe_slaac_v6(&state, interface_id, 20.0).await {
                Ok(addrs) => Some(addrs.link_local.is_some()),
                Err(error) => {
                    log::warn!(error:?; "SLAAC watch error");
                    Some(false)
                }
            },
            Err(error) => {
                log::warn!(error:?; "SLAAC watch error");
                Some(false)
            }
        }
    } else {
        None
    };
    if config.check_socket_provider {
        trace(stage_trace, "SOCKET-PROVIDER-CHECK");
        let _ = connect_to_protocol::<fposix_socket::ProviderMarker>()
            .context("connect Socket Provider")?;
    }
    let ipv4 = Ipv4Result {
        address,
        prefix_len,
        router,
        dns_servers,
        default_route_installed: default_route.is_some(),
    };
    Ok(FuchsiaBootstrapResult {
        lifetime: Some(NetworkBootstrap::with_optional_default_route(
            control,
            device_control,
            address_state_provider,
            default_route,
        )),
        interface_id: Some(interface_id),
        ipv4: Some(ipv4),
        reused_existing_ipv4: false,
        slaac_link_local_observed,
    })
}

/// Discovers, installs, enables, addresses, and retains one netstack interface.
///
/// Each policy attempt includes the complete transaction. On a failed attempt,
/// all locally-created FIDL endpoints are dropped before the delay and retry.
pub async fn bootstrap(
    config: FuchsiaBootstrapConfig,
    stage_trace: Option<fn(&str)>,
) -> Result<FuchsiaBootstrapResult> {
    let mut last_error = None;
    for attempt in 0..config.policy.attempts() {
        // Recheck before every full attempt: another component can finish DHCP
        // while we were waiting after an earlier failed install.
        if config.policy.reuse_existing_ipv4 && existing_ipv4_interface().await {
            return Ok(FuchsiaBootstrapResult {
                lifetime: None,
                interface_id: None,
                ipv4: None,
                reused_existing_ipv4: true,
                slaac_link_local_observed: None,
            });
        }
        match bootstrap_once(config, stage_trace).await {
            Ok(result) => return Ok(result),
            Err(error) => {
                last_error = Some(error);
                if config.policy.retries_after(attempt) && config.policy.retry_delay_seconds != 0 {
                    fuchsia_async::Timer::new(fuchsia_async::MonotonicInstant::after(
                        std::time::Duration::from_secs(config.policy.retry_delay_seconds as u64)
                            .into(),
                    ))
                    .await;
                }
            }
        }
    }
    Err(last_error.expect("BootstrapPolicy always has at least one attempt"))
}

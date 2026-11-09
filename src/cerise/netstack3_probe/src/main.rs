// Networking gate: netstack3_probe proves DHCP-configured real networking and a
// blocking TCP HTTP echo over fuchsia.posix.socket. The shared Fuchsia
// network-bootstrap adapter owns devfs discovery, Installer setup, interface
// lifetime, DHCP addressing, and SLAAC observation; this component owns the
// component-specific listener and serial proof markers.

use anyhow::{Context, Result};
use cerise_network_bootstrap::BootstrapPolicy;
use cerise_network_bootstrap_fuchsia::{bootstrap, FuchsiaBootstrapConfig, Ipv4Configuration};
use std::io::{Read, Write};
use std::net::TcpListener;

fn emit(msg: &str) {
    unsafe {
        zx::sys::zx_debug_write(msg.as_ptr(), msg.len());
    }
}

// Stage-entry diagnostics now flow as structured DEBUG records through LogSink
// (tag "netstack3_probe") rather than raw serial markers.
fn trace(stage: &str) {
    log::debug!(stage; "netstack3_probe stage entry");
}

async fn try_once() -> Result<()> {
    let result = match bootstrap(
        FuchsiaBootstrapConfig {
            interface_name: "cerise-eth0",
            ipv4: Ipv4Configuration::Dhcp {
                timeout_seconds: 45,
            },
            // Preserve the original 90 × 5s device-publication wait envelope.
            policy: BootstrapPolicy {
                discovery_attempts: 90,
                retry_delay_seconds: 5,
                reuse_existing_ipv4: false,
            },
            enable_before_address: true,
            observe_slaac: true,
            install_default_route: false,
            check_socket_provider: true,
        },
        Some(trace),
    )
    .await
    {
        Ok(result) => result,
        Err(error) => {
            log::error!(error:?; "cerise-dhcp: network bootstrap failed");
            emit("CERISE-DHCP-FAIL\n");
            std::process::exit(1);
        }
    };
    let ipv4 = result
        .ipv4
        .context("adapter returned no DHCP configuration")?;
    // Boot-gate marker with the observed lease (expected 10.0.2.15/24 under slirp).
    emit(&format!(
        "CERISE-DHCP-LEASE={}.{}.{}.{}/{}\n",
        ipv4.address[0], ipv4.address[1], ipv4.address[2], ipv4.address[3], ipv4.prefix_len
    ));
    if result.slaac_link_local_observed == Some(true) {
        emit("CERISE-SLAAC-ADDR-OK\n");
    }

    trace("TCP-LISTEN");
    let bind_addr = format!(
        "{}.{}.{}.{}:80",
        ipv4.address[0], ipv4.address[1], ipv4.address[2], ipv4.address[3]
    );
    let listener = TcpListener::bind(&bind_addr).context("std::net::TcpListener::bind failed")?;
    log::info!("netstack3 interface configured via DHCP; TCP listener bound on :80");
    // Keep the interface, address, and device ownership for the accept loop.
    let _network = result.lifetime;
    // Boot-gate markers — keep on serial verbatim (validation/run-qemu grep these).
    emit("CERISE-NETSTACK3-INTERFACE-UP\n");
    emit("CERISE-NETSTACK3-SOCKET-OK\n");

    trace("ACCEPT-LOOP");
    for stream in listener.incoming() {
        let mut stream = match stream {
            Ok(s) => s,
            Err(_) => continue,
        };
        let mut buf = [0u8; 4096];
        let n = match stream.read(&mut buf) {
            Ok(n) if n > 0 => n,
            _ => continue,
        };
        // Echo the request body back verbatim as the HTTP response body — matches
        // run-qemu.sh's http_probe(), which POSTs a payload and checks it's present
        // in the raw response text (it doesn't parse real HTTP framing).
        let body = &buf[..n];
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        let _ = stream.write_all(response.as_bytes());
        let _ = stream.write_all(body);
        log::info!(bytes = body.len(); "served HTTP echo request");
        // Boot-gate marker — keep on serial verbatim.
        emit("CERISE-NETSTACK3-HTTP-OK\n");
    }

    Ok(())
}

#[fuchsia::main(logging_tags = ["netstack3_probe"])]
async fn main() {
    log::info!(
        "netstack3_probe starting: discovering the network device and bringing up an interface"
    );
    if let Err(error) = try_once().await {
        log::error!(error:?; "netstack3_probe network bootstrap failed");
    }
}

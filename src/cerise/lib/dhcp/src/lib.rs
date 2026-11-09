// cerise-dhcp — a minimal, self-contained DHCPv4 client (RFC 2131 DORA) plus a
// SLAAC/NDP observation helper, both built on the real Fuchsia netstack3 surface.
//
// SHAPE DECISION: this is a LIBRARY crate, not a standalone daemon
// component. DORA runs over a `fuchsia.posix.socket.packet` link/network socket,
// which works *before* the interface has any IP address, so the natural place to
// run it is inside whichever component is already bringing the interface up
// (netstack3_probe, fileserver). Both consumers already hold the interface
// `Control` + `AddressStateProvider` for the process lifetime; a library keeps
// them ordinary consumers (no new always-on component, no new realm child, no new
// decode/route golden surface) while sharing one DORA implementation.
//
// Packets are encoded/parsed by hand (std + manual byte work, no new external
// crates): DHCP is a fixed BOOTP header + TLV options, wrapped in UDP (68->67)
// inside IPv4 (0.0.0.0 -> 255.255.255.255), and the netstack builds the ethernet
// header for us (Kind::Network packet socket). Replies come back broadcast (we set
// the BOOTP broadcast flag) and are read off the same packet socket.
//
// RENEW: see `Lease::t1_secs`. A best-effort renewal loop is provided via
// `renew_forever`, but note that under QEMU slirp the offered lease is very long
// (slirp's built-in bootp server), so T1 will not elapse within a boot-gate
// window; callers that only need address acquisition may drop the returned future.

use anyhow::{anyhow, Context, Result};
use fidl_fuchsia_net as fnet;
use fidl_fuchsia_net_interfaces as fnet_interfaces;
use fidl_fuchsia_posix as fposix;
use fidl_fuchsia_posix_socket as fposix_socket;
use fidl_fuchsia_posix_socket_packet as fppacket;

// ETH_P_IP: the ethertype we bind the packet socket to (only IPv4 frames).
const ETH_P_IP: u16 = 0x0800;
const IPPROTO_UDP: u8 = 17;
const DHCP_CLIENT_PORT: u16 = 68;
const DHCP_SERVER_PORT: u16 = 67;
const BROADCAST_MAC: [u8; 6] = [0xff; 6];
const DHCP_MAGIC_COOKIE: [u8; 4] = [0x63, 0x82, 0x53, 0x63];

// DHCP message types (option 53).
const DHCPDISCOVER: u8 = 1;
const DHCPOFFER: u8 = 2;
const DHCPREQUEST: u8 = 3;
const DHCPACK: u8 = 5;
const DHCPNAK: u8 = 6;

// DHCP option codes we produce/consume.
const OPT_SUBNET_MASK: u8 = 1;
const OPT_ROUTER: u8 = 3;
const OPT_DNS: u8 = 6;
const OPT_REQUESTED_IP: u8 = 50;
const OPT_LEASE_TIME: u8 = 51;
const OPT_MSG_TYPE: u8 = 53;
const OPT_SERVER_ID: u8 = 54;
const OPT_PARAM_REQUEST: u8 = 55;
const OPT_RENEWAL_T1: u8 = 58;
const OPT_REBIND_T2: u8 = 59;
const OPT_END: u8 = 255;
const OPT_PAD: u8 = 0;

/// A parsed, validated DHCPv4 lease.
#[derive(Debug, Clone)]
pub struct Lease {
    /// The leased client address (BOOTP `yiaddr`).
    pub yiaddr: [u8; 4],
    /// Prefix length derived from the subnet mask option (option 1).
    pub prefix_len: u8,
    /// Default gateway (option 3), if offered.
    pub router: Option<[u8; 4]>,
    /// DNS servers (option 6).
    pub dns: Vec<[u8; 4]>,
    /// The DHCP server identifier (option 54).
    pub server_id: [u8; 4],
    /// Lease time in seconds (option 51).
    pub lease_secs: u32,
    /// Renewal timer in seconds (option 58, or lease/2 if absent).
    pub t1_secs: u32,
    /// Rebind timer in seconds (option 59, or lease*7/8 if absent).
    pub t2_secs: u32,
}

impl Lease {
    /// Renders the leased address in `A.B.C.D/prefix` form for logging/markers.
    pub fn cidr(&self) -> String {
        let [a, b, c, d] = self.yiaddr;
        format!("{a}.{b}.{c}.{d}/{}", self.prefix_len)
    }
}

fn fmt_ip(ip: [u8; 4]) -> String {
    let [a, b, c, d] = ip;
    format!("{a}.{b}.{c}.{d}")
}

// ---------------------------------------------------------------------------
// Packet encoding (manual, no external crates).
// ---------------------------------------------------------------------------

// The internet checksum (RFC 1071): 16-bit ones-complement sum of the data.
fn checksum16(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn prefix_from_mask(mask: [u8; 4]) -> u8 {
    let bits = u32::from_be_bytes(mask);
    bits.count_ones() as u8
}

// Builds the DHCP BOOTP message (fixed header + magic cookie + options).
fn build_dhcp(xid: u32, chaddr: [u8; 6], msg_type: u8, extra_opts: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(300);
    m.push(1); // op = BOOTREQUEST
    m.push(1); // htype = ethernet
    m.push(6); // hlen = 6
    m.push(0); // hops
    m.extend_from_slice(&xid.to_be_bytes());
    m.extend_from_slice(&0u16.to_be_bytes()); // secs
    m.extend_from_slice(&0x8000u16.to_be_bytes()); // flags: broadcast (server replies broadcast)
    m.extend_from_slice(&[0; 4]); // ciaddr
    m.extend_from_slice(&[0; 4]); // yiaddr
    m.extend_from_slice(&[0; 4]); // siaddr
    m.extend_from_slice(&[0; 4]); // giaddr
    m.extend_from_slice(&chaddr); // chaddr (6) ...
    m.extend_from_slice(&[0; 10]); // ... + 10 pad = 16
    m.extend_from_slice(&[0; 64]); // sname
    m.extend_from_slice(&[0; 128]); // file
    m.extend_from_slice(&DHCP_MAGIC_COOKIE);
    // Option 53: DHCP message type.
    m.extend_from_slice(&[OPT_MSG_TYPE, 1, msg_type]);
    // Option 61: client identifier (htype 1 + MAC) — helps the server key the lease.
    m.push(61);
    m.push(7);
    m.push(1);
    m.extend_from_slice(&chaddr);
    // Option 55: parameter request list.
    m.extend_from_slice(&[
        OPT_PARAM_REQUEST,
        4,
        OPT_SUBNET_MASK,
        OPT_ROUTER,
        OPT_DNS,
        OPT_LEASE_TIME,
    ]);
    m.extend_from_slice(extra_opts);
    m.push(OPT_END);
    m
}

// Wraps a UDP payload in UDP+IPv4 (src 0.0.0.0:68 -> dst 255.255.255.255:67).
fn build_udp_ip(payload: &[u8]) -> Vec<u8> {
    let udp_len = 8 + payload.len();
    let mut udp = Vec::with_capacity(udp_len);
    udp.extend_from_slice(&DHCP_CLIENT_PORT.to_be_bytes());
    udp.extend_from_slice(&DHCP_SERVER_PORT.to_be_bytes());
    udp.extend_from_slice(&(udp_len as u16).to_be_bytes());
    udp.extend_from_slice(&0u16.to_be_bytes()); // checksum 0 = disabled (legal for IPv4 UDP)
    udp.extend_from_slice(payload);

    let total_len = 20 + udp_len;
    let mut ip = Vec::with_capacity(total_len);
    ip.push(0x45); // version 4, IHL 5
    ip.push(0x00); // DSCP/ECN
    ip.extend_from_slice(&(total_len as u16).to_be_bytes());
    ip.extend_from_slice(&0u16.to_be_bytes()); // identification
    ip.extend_from_slice(&0u16.to_be_bytes()); // flags/frag
    ip.push(64); // TTL
    ip.push(IPPROTO_UDP);
    ip.extend_from_slice(&0u16.to_be_bytes()); // checksum placeholder
    ip.extend_from_slice(&[0, 0, 0, 0]); // src 0.0.0.0
    ip.extend_from_slice(&[255, 255, 255, 255]); // dst broadcast
    let csum = checksum16(&ip[..20]);
    ip[10..12].copy_from_slice(&csum.to_be_bytes());
    ip.extend_from_slice(&udp);
    ip
}

// ---------------------------------------------------------------------------
// Packet parsing.
// ---------------------------------------------------------------------------

struct ParsedReply {
    msg_type: u8,
    yiaddr: [u8; 4],
    subnet_mask: Option<[u8; 4]>,
    router: Option<[u8; 4]>,
    dns: Vec<[u8; 4]>,
    server_id: Option<[u8; 4]>,
    lease_secs: Option<u32>,
    t1_secs: Option<u32>,
    t2_secs: Option<u32>,
}

fn ip4(b: &[u8]) -> Option<[u8; 4]> {
    (b.len() >= 4).then(|| [b[0], b[1], b[2], b[3]])
}

// Parses an IPv4 packet (as delivered by a Kind::Network packet socket, ethernet
// header already stripped) into a DHCP reply if it is one addressed to us.
fn parse_reply(ip: &[u8], xid: u32) -> Option<ParsedReply> {
    if ip.len() < 20 || (ip[0] >> 4) != 4 {
        return None;
    }
    let ihl = ((ip[0] & 0x0f) as usize) * 4;
    if ihl < 20 || ip.len() < ihl + 8 || ip[9] != IPPROTO_UDP {
        return None;
    }
    let udp = &ip[ihl..];
    let dst_port = u16::from_be_bytes([udp[2], udp[3]]);
    if dst_port != DHCP_CLIENT_PORT {
        return None;
    }
    let dhcp = &udp[8..];
    // Fixed BOOTP header is 236 bytes, then a 4-byte magic cookie, then options.
    if dhcp.len() < 240 || dhcp[0] != 2 {
        return None;
    }
    let reply_xid = u32::from_be_bytes([dhcp[4], dhcp[5], dhcp[6], dhcp[7]]);
    if reply_xid != xid {
        return None;
    }
    if dhcp[236..240] != DHCP_MAGIC_COOKIE {
        return None;
    }
    let yiaddr = [dhcp[16], dhcp[17], dhcp[18], dhcp[19]];

    let mut r = ParsedReply {
        msg_type: 0,
        yiaddr,
        subnet_mask: None,
        router: None,
        dns: Vec::new(),
        server_id: None,
        lease_secs: None,
        t1_secs: None,
        t2_secs: None,
    };

    let mut i = 240;
    while i < dhcp.len() {
        let code = dhcp[i];
        if code == OPT_END {
            break;
        }
        if code == OPT_PAD {
            i += 1;
            continue;
        }
        if i + 1 >= dhcp.len() {
            break;
        }
        let len = dhcp[i + 1] as usize;
        let val_start = i + 2;
        if val_start + len > dhcp.len() {
            break;
        }
        let val = &dhcp[val_start..val_start + len];
        match code {
            OPT_MSG_TYPE if len >= 1 => r.msg_type = val[0],
            OPT_SUBNET_MASK => r.subnet_mask = ip4(val),
            OPT_ROUTER => r.router = ip4(val),
            OPT_DNS => {
                for chunk in val.chunks_exact(4) {
                    r.dns.push([chunk[0], chunk[1], chunk[2], chunk[3]]);
                }
            }
            OPT_SERVER_ID => r.server_id = ip4(val),
            OPT_LEASE_TIME if len >= 4 => {
                r.lease_secs = Some(u32::from_be_bytes([val[0], val[1], val[2], val[3]]))
            }
            OPT_RENEWAL_T1 if len >= 4 => {
                r.t1_secs = Some(u32::from_be_bytes([val[0], val[1], val[2], val[3]]))
            }
            OPT_REBIND_T2 if len >= 4 => {
                r.t2_secs = Some(u32::from_be_bytes([val[0], val[1], val[2], val[3]]))
            }
            _ => {}
        }
        i = val_start + len;
    }
    Some(r)
}

// ---------------------------------------------------------------------------
// Socket helpers.
// ---------------------------------------------------------------------------

const INCOMING: zx::Signals =
    zx::Signals::from_bits_truncate(fposix_socket::SIGNAL_DATAGRAM_INCOMING);

fn after(secs: f64) -> fuchsia_async::MonotonicInstant {
    fuchsia_async::MonotonicInstant::after(zx::MonotonicDuration::from_nanos(
        (secs * 1e9) as i64,
    ))
}

async fn send_frame(
    socket: &fppacket::SocketProxy,
    interface_id: u64,
    data: &[u8],
) -> Result<()> {
    let packet_info = fppacket::PacketInfo {
        protocol: ETH_P_IP,
        interface_id,
        addr: fppacket::HardwareAddress::Eui48(fnet::MacAddress { octets: BROADCAST_MAC }),
    };
    socket
        .send_msg(
            Some(&packet_info),
            data,
            &fppacket::SendControlData::default(),
            fposix_socket::SendMsgFlags::empty(),
        )
        .await
        .context("packet SendMsg transport error")?
        .map_err(|e| anyhow!("packet SendMsg failed: {e:?}"))?;
    Ok(())
}

// Waits (until `deadline`) for a DHCP reply of `want_type` matching `xid`. Returns
// Ok(Some(reply)) on match, Ok(None) on deadline, Err on transport failure.
async fn recv_until(
    socket: &fppacket::SocketProxy,
    event: &zx::EventPair,
    xid: u32,
    want_type: u8,
    deadline: fuchsia_async::MonotonicInstant,
) -> Result<Option<ParsedReply>> {
    loop {
        // Drain whatever is queued right now.
        loop {
            match socket
                .recv_msg(false, 2048, false, fposix_socket::RecvMsgFlags::empty())
                .await
                .context("packet RecvMsg transport error")?
            {
                Ok((_info, data, _control, _truncated)) => {
                    if let Some(reply) = parse_reply(&data, xid) {
                        if reply.msg_type == want_type {
                            return Ok(Some(reply));
                        }
                        if reply.msg_type == DHCPNAK {
                            return Err(anyhow!("server sent DHCPNAK"));
                        }
                    }
                }
                Err(fposix::Errno::Eagain) => break, // queue drained
                Err(e) => return Err(anyhow!("packet RecvMsg failed: {e:?}")),
            }
        }
        // Nothing matched; wait for the socket to signal incoming data, bounded by
        // the deadline. On timeout the closure yields `false` and we give up.
        if fuchsia_async::MonotonicInstant::now() >= deadline {
            return Ok(None);
        }
        let woke = fuchsia_async::TimeoutExt::on_timeout(
            async {
                let _ = fuchsia_async::OnSignalsRef::new(
                    zx::AsHandleRef::as_handle_ref(event),
                    INCOMING,
                )
                .await;
                true
            },
            deadline,
            || false,
        )
        .await;
        if !woke {
            return Ok(None);
        }
    }
}

// ---------------------------------------------------------------------------
// The DORA exchange.
// ---------------------------------------------------------------------------

/// Runs a full DHCPv4 DISCOVER->OFFER->REQUEST->ACK exchange over a packet socket
/// obtained from `provider`, on the interface identified by `interface_id`.
///
/// Retransmits DISCOVER/REQUEST with exponential backoff (2,4,8,16s, capped),
/// bounded by `overall_timeout_secs`. Returns the validated [`Lease`], or an error
/// (the caller is expected to surface this LOUDLY — no silent fallback).
pub async fn acquire(
    provider: &fppacket::ProviderProxy,
    interface_id: u64,
    overall_timeout_secs: f64,
) -> Result<Lease> {
    let overall_deadline = after(overall_timeout_secs);

    // Create a network-layer packet socket and bind it to IPv4 on our interface.
    let client = provider
        .socket(fppacket::Kind::Network)
        .await
        .context("packet Provider.Socket transport error")?
        .map_err(|e| anyhow!("packet Provider.Socket failed: {e:?}"))?;
    let socket = client.into_proxy();
    socket
        .bind(
            Some(&fppacket::ProtocolAssociation::Specified(ETH_P_IP)),
            &fppacket::BoundInterfaceId::Specified(interface_id),
        )
        .await
        .context("packet Socket.Bind transport error")?
        .map_err(|e| anyhow!("packet Socket.Bind failed: {e:?}"))?;

    // Recover our MAC from the bound interface (used as chaddr).
    let (_kind, _proto, bound) = socket
        .get_info()
        .await
        .context("packet Socket.GetInfo transport error")?
        .map_err(|e| anyhow!("packet Socket.GetInfo failed: {e:?}"))?;
    let chaddr = match bound {
        fppacket::BoundInterface::Specified(props) => match props.addr {
            fppacket::HardwareAddress::Eui48(m) => m.octets,
            other => return Err(anyhow!("interface has no EUI-48 address: {other:?}")),
        },
        other => return Err(anyhow!("packet socket not bound to a specific interface: {other:?}")),
    };

    let describe = socket
        .describe()
        .await
        .context("packet Socket.Describe transport error")?;
    let event = describe.event.ok_or_else(|| anyhow!("packet socket Describe returned no event"))?;

    let mut xid_bytes = [0u8; 4];
    zx::cprng_draw(&mut xid_bytes);
    let xid = u32::from_be_bytes(xid_bytes);

    log::info!(xid, mac:? = chaddr, iface = interface_id; "cerise-dhcp: starting DORA");

    // ---- DISCOVER -> OFFER ----
    let discover = build_udp_ip(&build_dhcp(xid, chaddr, DHCPDISCOVER, &[]));
    let offer = retransmit(&socket, interface_id, &event, &discover, xid, DHCPOFFER, overall_deadline)
        .await
        .context("DHCPDISCOVER")?;
    let server_id = offer
        .server_id
        .ok_or_else(|| anyhow!("OFFER missing server identifier (option 54)"))?;
    log::info!(
        yiaddr = fmt_ip(offer.yiaddr).as_str(),
        server = fmt_ip(server_id).as_str();
        "cerise-dhcp: got OFFER"
    );

    // ---- REQUEST -> ACK ----
    let mut req_opts = Vec::new();
    req_opts.extend_from_slice(&[OPT_REQUESTED_IP, 4]);
    req_opts.extend_from_slice(&offer.yiaddr);
    req_opts.extend_from_slice(&[OPT_SERVER_ID, 4]);
    req_opts.extend_from_slice(&server_id);
    let request = build_udp_ip(&build_dhcp(xid, chaddr, DHCPREQUEST, &req_opts));
    let ack = retransmit(&socket, interface_id, &event, &request, xid, DHCPACK, overall_deadline)
        .await
        .context("DHCPREQUEST")?;

    let mask = ack.subnet_mask.or(offer.subnet_mask).unwrap_or([255, 255, 255, 0]);
    let lease_secs = ack.lease_secs.or(offer.lease_secs).unwrap_or(3600);
    let t1_secs = ack.t1_secs.or(offer.t1_secs).unwrap_or(lease_secs / 2);
    let t2_secs = ack.t2_secs.or(offer.t2_secs).unwrap_or(lease_secs / 8 * 7);
    let lease = Lease {
        yiaddr: ack.yiaddr,
        prefix_len: prefix_from_mask(mask),
        router: ack.router.or(offer.router),
        dns: if ack.dns.is_empty() { offer.dns } else { ack.dns },
        server_id: ack.server_id.unwrap_or(server_id),
        lease_secs,
        t1_secs,
        t2_secs,
    };
    log::info!(
        cidr = lease.cidr().as_str(),
        router:? = lease.router.map(fmt_ip),
        lease_secs = lease.lease_secs;
        "cerise-dhcp: got ACK, lease acquired"
    );
    Ok(lease)
}

// Sends `frame`, waits for `want_type`, retransmitting with exponential backoff
// until a reply arrives or `overall_deadline` passes.
async fn retransmit(
    socket: &fppacket::SocketProxy,
    interface_id: u64,
    event: &zx::EventPair,
    frame: &[u8],
    xid: u32,
    want_type: u8,
    overall_deadline: fuchsia_async::MonotonicInstant,
) -> Result<ParsedReply> {
    let mut backoff = 2.0f64;
    loop {
        send_frame(socket, interface_id, frame).await?;
        let now = fuchsia_async::MonotonicInstant::now();
        if now >= overall_deadline {
            return Err(anyhow!("timed out waiting for DHCP reply (type {want_type})"));
        }
        // Cap this attempt's wait at both the backoff and the overall deadline.
        let attempt_deadline = std::cmp::min(after(backoff), overall_deadline);
        if let Some(reply) = recv_until(socket, event, xid, want_type, attempt_deadline).await? {
            return Ok(reply);
        }
        if fuchsia_async::MonotonicInstant::now() >= overall_deadline {
            return Err(anyhow!("timed out waiting for DHCP reply (type {want_type})"));
        }
        backoff = (backoff * 2.0).min(16.0);
    }
}

/// Best-effort lease renewal: sleeps until T1, then unicasts a REQUEST to the
/// leasing server and updates the lease. Loops forever. Intended to be spawned as
/// a background task by a caller that holds the interface for the process lifetime.
///
/// NOTE: under QEMU slirp the lease is effectively permanent, so this never fires
/// within a boot-gate window; it is provided for real-hardware correctness.
pub async fn renew_forever(
    provider: fppacket::ProviderProxy,
    interface_id: u64,
    mut lease: Lease,
) {
    loop {
        fuchsia_async::Timer::new(after(lease.t1_secs.max(1) as f64)).await;
        // Re-run DORA; slirp/real servers will re-hand the same address. A real
        // unicast-to-server RENEW is a future refinement; re-DORA is correct and
        // keeps the server-side lease fresh.
        match acquire(&provider, interface_id, 30.0).await {
            Ok(new_lease) => {
                log::info!(cidr = new_lease.cidr().as_str(); "cerise-dhcp: lease renewed");
                lease = new_lease;
            }
            Err(e) => {
                log::warn!("cerise-dhcp: renewal failed, retrying at next T1: {e:#}");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// SLAAC / NDP observation.
// ---------------------------------------------------------------------------

/// IPv6 addresses observed on an interface via SLAAC.
#[derive(Debug, Default, Clone)]
pub struct SlaacAddrs {
    /// A link-local (fe80::/10) address, auto-generated on interface enable.
    pub link_local: Option<[u8; 16]>,
    /// A global (2000::/3) address, present only if a router advertised a prefix.
    pub global: Option<[u8; 16]>,
}

fn is_link_local_v6(a: &[u8; 16]) -> bool {
    a[0] == 0xfe && (a[1] & 0xc0) == 0x80
}

fn is_global_v6(a: &[u8; 16]) -> bool {
    (a[0] & 0xe0) == 0x20
}

fn fmt_v6(a: &[u8; 16]) -> String {
    let groups: Vec<String> = a
        .chunks_exact(2)
        .map(|c| format!("{:x}", u16::from_be_bytes([c[0], c[1]])))
        .collect();
    groups.join(":")
}

/// Watches `fuchsia.net.interfaces.State` until the interface `interface_id`
/// reports a SLAAC IPv6 link-local address (and captures a global one if present),
/// or `timeout_secs` elapses. Returns whatever was observed.
pub async fn observe_slaac_v6(
    state: &fnet_interfaces::StateProxy,
    interface_id: u64,
    timeout_secs: f64,
) -> Result<SlaacAddrs> {
    let (watcher, server) = fidl::endpoints::create_proxy::<fnet_interfaces::WatcherMarker>();
    state
        .get_watcher(&fnet_interfaces::WatcherOptions::default(), server)
        .context("interfaces State.GetWatcher failed")?;

    let deadline = after(timeout_secs);
    let mut found = SlaacAddrs::default();

    loop {
        let ev_opt = fuchsia_async::TimeoutExt::on_timeout(
            async { Some(watcher.watch().await) },
            deadline,
            || None,
        )
        .await;
        let event = match ev_opt {
            None => return Ok(found), // deadline reached
            Some(res) => res.context("interfaces Watcher.Watch transport error")?,
        };

        let props = match event {
            fnet_interfaces::Event::Existing(p)
            | fnet_interfaces::Event::Added(p)
            | fnet_interfaces::Event::Changed(p) => p,
            _ => continue,
        };
        if props.id != Some(interface_id) {
            continue;
        }
        let Some(addresses) = props.addresses else { continue };
        for addr in addresses {
            let Some(fnet::Subnet { addr: fnet::IpAddress::Ipv6(fnet::Ipv6Address { addr }), .. }) =
                addr.addr
            else {
                continue;
            };
            if is_link_local_v6(&addr) {
                if found.link_local.is_none() {
                    log::info!(addr = fmt_v6(&addr).as_str(); "cerise-dhcp: SLAAC link-local observed");
                }
                found.link_local = Some(addr);
            } else if is_global_v6(&addr) {
                if found.global.is_none() {
                    log::info!(addr = fmt_v6(&addr).as_str(); "cerise-dhcp: SLAAC global observed");
                }
                found.global = Some(addr);
            }
        }
        // The reliable observable is the link-local; a global needs a router RA
        // that slirp does not send. Stop as soon as the link-local is up.
        if found.link_local.is_some() {
            return Ok(found);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksum_and_prefix() {
        assert_eq!(prefix_from_mask([255, 255, 255, 0]), 24);
        assert_eq!(prefix_from_mask([255, 255, 0, 0]), 16);
        // A well-formed IPv4 header must checksum-verify to zero.
        let ip = build_udp_ip(&build_dhcp(0x1234, [1, 2, 3, 4, 5, 6], DHCPDISCOVER, &[]));
        assert_eq!(checksum16(&ip[..20]), 0);
    }

    #[test]
    fn roundtrip_offer() {
        // Hand-build an OFFER and make sure we parse it back.
        let xid = 0xdead_beef;
        let opts = {
            let mut o = Vec::new();
            o.extend_from_slice(&[OPT_SUBNET_MASK, 4, 255, 255, 255, 0]);
            o.extend_from_slice(&[OPT_ROUTER, 4, 10, 0, 2, 2]);
            o.extend_from_slice(&[OPT_SERVER_ID, 4, 10, 0, 2, 2]);
            o.extend_from_slice(&[OPT_LEASE_TIME, 4, 0, 0, 0x0e, 0x10]); // 3600
            o
        };
        let mut dhcp = build_dhcp(xid, [1, 2, 3, 4, 5, 6], DHCPOFFER, &opts);
        // Make it a BOOTREPLY with a yiaddr.
        dhcp[0] = 2;
        dhcp[16..20].copy_from_slice(&[10, 0, 2, 15]);
        let ip = build_udp_ip(&dhcp);
        // Swap ports so it looks server->client.
        let ihl = ((ip[0] & 0x0f) as usize) * 4;
        let mut ip = ip;
        ip[ihl..ihl + 2].copy_from_slice(&DHCP_SERVER_PORT.to_be_bytes());
        ip[ihl + 2..ihl + 4].copy_from_slice(&DHCP_CLIENT_PORT.to_be_bytes());
        let r = parse_reply(&ip, xid).expect("should parse");
        assert_eq!(r.msg_type, DHCPOFFER);
        assert_eq!(r.yiaddr, [10, 0, 2, 15]);
        assert_eq!(r.subnet_mask, Some([255, 255, 255, 0]));
        assert_eq!(r.router, Some([10, 0, 2, 2]));
        assert_eq!(r.server_id, Some([10, 0, 2, 2]));
        assert_eq!(r.lease_secs, Some(3600));
    }
}

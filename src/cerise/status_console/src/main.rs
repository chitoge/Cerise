//! Cerise status console — an ESXi-DCUI-style full-screen status screen rendered to a
//! real QEMU framebuffer.
//!
//! Acquires the framebuffer as a FIDL client of the native display driver via
//! `fb::Framebuffer` (cerise.display.Service — the console holds NO hardware capability),
//! reads live interface state through `fuchsia.net.interfaces/Watcher` and memory and CPU
//! through `fuchsia.kernel.Stats`. Paints a title bar, then prioritises network identity,
//! VM access, endpoint roles, and the
//! snapshot/fork model; host memory and CPU remain visible as capacity context. Redraws
//! whenever an interface changes and on a periodic tick.
//!
//! NO SECTION EVER SHOWS A NUMBER IT DID NOT READ. Memory and CPU are populated from a
//! live sample or rendered as unavailable. There is no zero-fill, placeholder, or
//! last-known-good value.

mod fb;
mod font;
mod metrics;
mod storage;
mod vm;

use std::collections::BTreeMap;

use anyhow::{Context, Result};
use fidl::endpoints::create_proxy;
use fidl_fuchsia_net as fnet;
use fidl_fuchsia_net_interfaces as fnet_if;
use fuchsia_component::client::connect_to_protocol;
use futures::FutureExt;

use fb::Framebuffer;

const WIDTH: usize = 1024;
const HEIGHT: usize = 768;
const HOSTNAME: &str = "cerise";

/// How often the panel re-samples memory/CPU/storage and repaints. CPU utilisation is
/// a delta between consecutive samples, so this is also the measurement window.
const SAMPLE_PERIOD_SECS: u64 = 2;

/// Text scale for body text, and the resulting cell size in pixels. An 8x8 glyph at
/// scale 2 occupies a 16x16 cell.
const SCALE: usize = 2;
const CELL: usize = 8 * SCALE;

/// Labels in the right-hand column are padded to this many cells, so every value in
/// the column starts at the same x. That makes each value's position a fixed function
/// of its section — which is what lets the boot gate assert on a value's PIXELS at a
/// known place, anchored by its own label, rather than hunting for loose digits that
/// an IP address could satisfy by accident.
const LABEL_CELLS: usize = 10;

// ESXi-DCUI-ish palette (0x00RRGGBB; QEMU stdvga scans it out as RGB, verified initial prototype).
const C_BG: u32 = 0x0011_1820;
const C_TITLE_BG: u32 = 0x00C5_1B5D;
const C_TITLE_FG: u32 = 0x00FF_F7FA;
const C_TITLE_MUTED: u32 = 0x00FB_D5E3;
const C_SUBTLE: u32 = 0x0090_A4B4;
const C_LABEL: u32 = 0x0082_97A6;
const C_VALUE: u32 = 0x00E8_EEF2;
const C_UP: u32 = 0x0045_D07C;
const C_DOWN: u32 = 0x00E0_5555;
const C_ACCENT: u32 = 0x00F0_C24A;
const C_RULE: u32 = 0x0024_3444;

// ---------------------------------------------------------------------------
// Text rendering: an 8x8 glyph drawn as scale x scale blocks.
// ---------------------------------------------------------------------------

fn draw_char(fb: &Framebuffer, x: usize, y: usize, scale: usize, color: u32, c: u8) {
    let g = font::glyph(c);
    for (row, bits) in g.iter().enumerate() {
        for col in 0..8 {
            if (bits >> (7 - col)) & 1 == 1 {
                fb.fill_rect(x + col * scale, y + row * scale, scale, scale, color);
            }
        }
    }
}

/// Draws `s` and returns the x coordinate just past the last glyph.
fn draw_text(fb: &Framebuffer, x: usize, y: usize, scale: usize, color: u32, s: &str) -> usize {
    let mut cx = x;
    for b in s.bytes() {
        draw_char(fb, cx, y, scale, color, b);
        cx += 8 * scale;
    }
    cx
}

/// Splits `s` into chunks of at most `cells` characters.
///
/// NOTHING MAY BE DRAWN OUTSIDE ITS OWN COLUMN. A full IPv6 address in hextet form is 39
/// characters, and at scale 2 from the interface indent that is well past the halfway
/// point of a 1024-wide screen — so the left column's address lines used to be painted
/// straight over the right column's CPU section. The panel still *looked* plausible,
/// which is exactly why this went unnoticed until the boot gate started comparing
/// glyphs pixel-for-pixel. Wrapping rather than truncating: an address with its tail cut
/// off is worse than no address, because it reads as a complete one.
fn wrap_cells(s: &str, cells: usize) -> Vec<String> {
    if cells == 0 {
        return Vec::new();
    }
    let chars: Vec<char> = s.chars().collect();
    if chars.is_empty() {
        return Vec::new();
    }
    chars.chunks(cells).map(|c| c.iter().collect()).collect()
}

// ---------------------------------------------------------------------------
// Interface model, maintained from the interfaces Watcher event stream.
// ---------------------------------------------------------------------------

#[derive(Default, Clone)]
struct Iface {
    name: String,
    online: bool,
    v4: Vec<([u8; 4], u8)>,
    v6: Vec<([u8; 16], u8)>,
}

fn split_addrs(addrs: &[fnet_if::Address]) -> (Vec<([u8; 4], u8)>, Vec<([u8; 16], u8)>) {
    let mut v4 = Vec::new();
    let mut v6 = Vec::new();
    for a in addrs {
        if let Some(subnet) = &a.addr {
            match subnet.addr {
                fnet::IpAddress::Ipv4(ip) => v4.push((ip.addr, subnet.prefix_len)),
                fnet::IpAddress::Ipv6(ip) => v6.push((ip.addr, subnet.prefix_len)),
            }
        }
    }
    (v4, v6)
}

/// Applies one Watcher event to the interface map.
fn apply(ifaces: &mut BTreeMap<u64, Iface>, event: fnet_if::Event) {
    match event {
        fnet_if::Event::Existing(p) | fnet_if::Event::Added(p) => {
            if let Some(id) = p.id {
                let (v4, v6) = p.addresses.as_deref().map(split_addrs).unwrap_or_default();
                ifaces.insert(
                    id,
                    Iface {
                        name: p.name.unwrap_or_default(),
                        online: p.online.unwrap_or(false),
                        v4,
                        v6,
                    },
                );
            }
        }
        fnet_if::Event::Changed(p) => {
            if let Some(id) = p.id {
                let e = ifaces.entry(id).or_default();
                if let Some(name) = p.name {
                    e.name = name;
                }
                if let Some(online) = p.online {
                    e.online = online;
                }
                if let Some(addrs) = p.addresses {
                    let (v4, v6) = split_addrs(&addrs);
                    e.v4 = v4;
                    e.v6 = v6;
                }
            }
        }
        fnet_if::Event::Removed(id) => {
            ifaces.remove(&id);
        }
        fnet_if::Event::Idle(_) => {}
    }
}

fn fmt_v4(a: &[u8; 4]) -> String {
    format!("{}.{}.{}.{}", a[0], a[1], a[2], a[3])
}

fn fmt_v6(a: &[u8; 16]) -> String {
    // Compact-enough hextet form (no :: compression — legible and unambiguous).
    let mut parts = Vec::with_capacity(8);
    for i in 0..8 {
        parts.push(format!("{:x}", ((a[2 * i] as u16) << 8) | a[2 * i + 1] as u16));
    }
    parts.join(":")
}

fn is_loopback_v4(a: &[u8; 4]) -> bool {
    a[0] == 127
}

/// Picks the interface's primary (non-loopback) IPv4 for the file-server endpoint.
fn primary_v4(ifaces: &BTreeMap<u64, Iface>) -> Option<[u8; 4]> {
    for iface in ifaces.values() {
        for (a, _) in &iface.v4 {
            if !is_loopback_v4(a) {
                return Some(*a);
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Screen layout.
// ---------------------------------------------------------------------------

/// The live sample set one paint renders. Each field is a `Result` so an unavailable
/// metric carries its own reason to the screen rather than degrading into a number.
struct Samples {
    memory: Result<metrics::Memory>,
    cpu: Result<metrics::CpuUsage>,
    // Kept as serial evidence for the combined fileserver gate, but storage is no
    // longer panel content: VM state and access are the operator-facing priority.
    storage: Result<storage::Report>,
    vms: Result<vm::Report>,
}

/// A column being filled top-down. Keeps the x origin and the running y so a section
/// never has to know what came before it.
struct Column<'a> {
    fb: &'a Framebuffer,
    x: usize,
    y: usize,
    width: usize,
    line: usize,
    /// The last y a line may START at. Every draw path checks it, so a section that
    /// runs long is cut off cleanly at the bottom of the screen instead of drawing
    /// half-glyphs into the framebuffer's last row — or, worse, appearing to have
    /// said something it did not finish saying.
    bottom: usize,
}

impl<'a> Column<'a> {
    fn new(fb: &'a Framebuffer, x: usize, y: usize, width: usize) -> Column<'a> {
        let bottom = fb.height.saturating_sub(8 * SCALE);
        Column { fb, x, y, width, line: 26, bottom }
    }

    /// Is there room for another line?
    fn room(&self) -> bool {
        self.y <= self.bottom
    }

    /// How many glyph cells fit in this column from an x indent of `indent` pixels.
    fn cells_from(&self, indent: usize) -> usize {
        self.width.saturating_sub(indent) / CELL
    }

    /// Accent heading over a rule — the established section style.
    fn heading(&mut self, title: &str) {
        if !self.room() {
            return;
        }
        let clipped: String = title.chars().take(self.cells_from(0)).collect();
        draw_text(self.fb, self.x, self.y, SCALE, C_ACCENT, &clipped);
        self.y += self.line;
        self.fb.fill_rect(self.x, self.y, self.width, 2, C_RULE);
        self.y += 12;
    }

    /// A label/value row. The label is padded — and, if need be, TRUNCATED — to
    /// `LABEL_CELLS`, so the value always begins at `x + 16 + LABEL_CELLS * CELL`. That
    /// fixed offset is what lets the boot gate locate a value by its own label instead of
    /// by loose pattern matching, and an over-long label would silently break it by
    /// running into the value's cells. Truncating here rather than trusting every caller
    /// to keep labels short: one of them did not.
    fn row(&mut self, label: &str, value: &str, color: u32) {
        if !self.room() {
            return;
        }
        let clipped: String = label.chars().take(LABEL_CELLS).collect();
        let padded = format!("{clipped:<w$}", w = LABEL_CELLS);
        draw_text(self.fb, self.x + 16, self.y, SCALE, C_LABEL, &padded);
        // The value is clipped to what is left of the column, for the same reason the
        // label is: nothing may be drawn outside its own column.
        let value_x = self.x + 16 + LABEL_CELLS * CELL;
        let value_cells = self.cells_from(16 + LABEL_CELLS * CELL);
        let value: String = value.chars().take(value_cells).collect();
        draw_text(self.fb, value_x, self.y, SCALE, color, &value);
        self.y += self.line;
    }

    /// Free text, wrapped to the column. Used for refusal reasons, which are whole
    /// sentences: the operator needs to read WHY the disk was declined, and truncating
    /// that to fit would remove the only actionable part.
    fn wrapped(&mut self, text: &str, color: u32, max_lines: usize) {
        let cells = self.cells_from(16);
        if cells == 0 {
            return;
        }
        let mut drawn = 0usize;
        let mut current = String::new();
        // Clipped on EVERY emitted line, not just the last: a single word longer than
        // the column (a URL, a long instance id) reaches the draw below still oversized,
        // because the "keep the word, flush the line" branch flushes `current` — which
        // may itself be that oversized word from the previous iteration.
        let emit = |me: &mut Self, line: &str| -> bool {
            if !me.room() {
                return false;
            }
            let clipped: String = line.chars().take(cells).collect();
            draw_text(me.fb, me.x + 16, me.y, SCALE, color, &clipped);
            me.y += me.line;
            true
        };
        for word in text.split_whitespace() {
            let candidate =
                if current.is_empty() { word.to_string() } else { format!("{current} {word}") };
            if candidate.chars().count() > cells && !current.is_empty() {
                if !emit(self, &current) {
                    return;
                }
                drawn += 1;
                if drawn == max_lines {
                    return;
                }
                current = word.to_string();
            } else {
                current = candidate;
            }
        }
        if !current.is_empty() && drawn < max_lines {
            emit(self, &current);
        }
    }

    /// The one way a section says it has nothing to show. Rendered in the "bad" colour
    /// with the reason, so it can never be mistaken for a reading.
    fn unavailable(&mut self, err: &anyhow::Error) {
        self.row("reading", "unavailable", C_DOWN);
        self.wrapped(&format!("{err:#}"), C_SUBTLE, 3);
    }

    fn gap(&mut self) {
        self.y += 14;
    }
}

fn render_memory(col: &mut Column<'_>, memory: &Result<metrics::Memory>) {
    col.heading("Memory");
    match memory {
        Ok(m) => {
            col.row("total", &format!("{} MiB", metrics::mib(m.total)), C_VALUE);
            let used = match m.used_pct() {
                Some(p) => format!("{} MiB  {p}%", metrics::mib(m.used())),
                None => format!("{} MiB", metrics::mib(m.used())),
            };
            col.row("used", &used, C_VALUE);
            col.row("free", &format!("{} MiB", metrics::mib(m.free)), C_VALUE);
        }
        Err(e) => col.unavailable(e),
    }
}

fn render_cpu(col: &mut Column<'_>, cpu: &Result<metrics::CpuUsage>) {
    col.heading("CPU");
    match cpu {
        Ok(u) => {
            col.row("cores", &format!("{}", u.num_cpus), C_VALUE);
            let mean = u.mean_pct();
            col.row(
                "usage",
                &format!("{mean}%  {}", bar(mean)),
                if mean >= 90 { C_DOWN } else { C_VALUE },
            );
        }
        Err(e) => col.unavailable(e),
    }
}

fn render_vms(col: &mut Column<'_>, report: &Result<vm::Report>) {
    col.heading("Virtual Machines");
    match report {
        Ok(report) => {
            if report.vms.is_empty() {
                col.row("inventory", "no VMs", C_SUBTLE);
            }
            for vm in &report.vms {
                let name = if vm.name.is_empty() { &vm.id } else { &vm.name };
                let color = match vm.state {
                    vm::State::Running => C_UP,
                    vm::State::Starting | vm::State::Paused | vm::State::Stopped => C_ACCENT,
                    vm::State::Failed | vm::State::Unknown => C_DOWN,
                };
                col.wrapped(&format!("{name}  {}", vm.state.text()), color, 1);
                let head_kind = if vm.memory_only { "RAM" } else { "durable" };
                col.wrapped(
                    &format!(
                        "{}  {} MiB  {} VP  epoch {}  head {} ({})",
                        vm.population.text(),
                        vm.memory_mib,
                        vm.vp_count,
                        vm.epoch,
                        vm.head_id,
                        head_kind
                    ),
                    C_SUBTLE,
                    2,
                );
                if vm.observed_state.is_some_and(|observed| {
                    observed.text() != vm.desired_state.text()
                }) {
                    col.wrapped(
                        &format!(
                            "desired {} / observed {}",
                            vm.desired_state.text(),
                            vm.observed_state.unwrap().text()
                        ),
                        C_ACCENT,
                        1,
                    );
                }
                if vm.snapshot_count != 0 || vm.checkpoint_count != 0 {
                    col.wrapped(
                        &format!(
                            "{} snapshot(s), {} checkpoint(s)",
                            vm.snapshot_count, vm.checkpoint_count
                        ),
                        C_SUBTLE,
                        1,
                    );
                }
                if vm.resident_dirty_bytes != 0 || vm.spill_bytes != 0 {
                    col.wrapped(
                        &format!(
                            "overlay: {} MiB RAM, {} MiB spill",
                            metrics::mib(vm.resident_dirty_bytes),
                            metrics::mib(vm.spill_bytes)
                        ),
                        C_SUBTLE,
                        1,
                    );
                }
                if !vm.last_error.is_empty() {
                    col.wrapped(&vm.last_error, C_DOWN, 2);
                }
            }
        }
        Err(err) => col.unavailable(err),
    }
}

fn render_image_store(col: &mut Column<'_>, report: &Result<vm::Report>) {
    col.heading("VM Image Store");
    match report {
        Ok(report) => {
            match &report.store {
                Some(store) => {
                    col.row("capacity", &metrics::human_bytes(store.total_bytes), C_VALUE);
                    col.row("free", &metrics::human_bytes(store.free_bytes), C_UP);
                    col.row("used", &metrics::human_bytes(store.used_bytes), C_VALUE);
                }
                None => col.row("capacity", "discovering", C_ACCENT),
            }
            col.row("images", &report.images.len().to_string(), C_VALUE);
            for image in &report.images {
                let name = if image.name.is_empty() { &image.id } else { &image.name };
                col.wrapped(name, C_LABEL, 1);
                let size = if image.virtual_bytes == 0 {
                    format!("{} stored", metrics::human_bytes(image.stored_bytes))
                } else {
                    format!(
                        "{} stored / {} virtual",
                        metrics::human_bytes(image.stored_bytes),
                        metrics::human_bytes(image.virtual_bytes)
                    )
                };
                col.wrapped(&size, C_SUBTLE, 1);
            }
        }
        Err(err) => col.unavailable(err),
    }
}

/// A 12-cell utilisation bar. `#` and `.` are both in the font.
fn bar(pct: u32) -> String {
    const CELLS: u32 = 12;
    let filled = (pct.min(100) * CELLS / 100) as usize;
    format!("[{}{}]", "#".repeat(filled), ".".repeat(CELLS as usize - filled))
}

fn render(fb: &Framebuffer, ifaces: &BTreeMap<u64, Iface>, samples: &Samples) {
    // Lay out against the framebuffer's REAL geometry, not the requested constants:
    // the same binary drives QEMU's 1024x768 and the laptop's 1920x1200 panel.
    let width = fb.width.max(640);
    fb.clear(C_BG);

    // Title bar.
    fb.fill_rect(0, 0, width, 52, C_TITLE_BG);
    draw_text(fb, 20, 12, 4, C_TITLE_FG, "Cryogen");
    let title = "Virtual Machine Host";
    draw_text(
        fb,
        width.saturating_sub(title.len() * CELL + 20),
        18,
        SCALE,
        C_TITLE_MUTED,
        title,
    );

    let top = 84usize;
    let line = 26usize;

    // Two columns when there is room, otherwise one long column that scrolls off the
    // bottom exactly as it used to — never a squashed, unreadable one.
    let two_col = width >= 900;
    let col_w = if two_col { width / 2 - 40 } else { width - 48 };
    let right_x = if two_col { width / 2 + 16 } else { 24 };

    let mut left = Column::new(fb, 24, top, col_w);

    // Hostname.
    draw_text(fb, left.x, left.y, SCALE, C_LABEL, "Hostname:");
    draw_text(fb, left.x + 11 * CELL, left.y, SCALE, C_VALUE, HOSTNAME);
    left.y += line + 8;

    left.heading("Network Interfaces");
    // Everything below is wrapped to the column, never merely drawn and hoped for —
    // see wrap_cells.
    let addr_indent = 72usize;
    let addr_cells = (24 + col_w).saturating_sub(addr_indent) / CELL;
    if ifaces.is_empty() {
        draw_text(fb, 40, left.y, SCALE, C_SUBTLE, "(no interfaces reported)");
        left.y += line;
    }
    // Interface names come from the netstack and are not bounded by anything here, so
    // they are clipped like everything else — leaving room for the UP/DOWN badge.
    let name_cells = ((24 + col_w).saturating_sub(40) / CELL).saturating_sub(6);
    for iface in ifaces.values() {
        if !left.room() {
            break;
        }
        let name = if iface.name.is_empty() { "(unnamed)" } else { &iface.name };
        let name: String = name.chars().take(name_cells).collect();
        let nx = draw_text(fb, 40, left.y, SCALE, C_VALUE, &name);
        let (state, sc) = if iface.online { ("UP", C_UP) } else { ("DOWN", C_DOWN) };
        draw_text(fb, nx + 24, left.y, SCALE, sc, state);
        left.y += line;
        for (a, p) in &iface.v4 {
            for chunk in wrap_cells(&format!("IPv4  {}/{}", fmt_v4(a), p), addr_cells) {
                if !left.room() {
                    break;
                }
                draw_text(fb, addr_indent, left.y, SCALE, C_SUBTLE, &chunk);
                left.y += line;
            }
        }
        for (a, p) in &iface.v6 {
            for chunk in wrap_cells(&format!("IPv6  {}/{}", fmt_v6(a), p), addr_cells) {
                if !left.room() {
                    break;
                }
                draw_text(fb, addr_indent, left.y, SCALE, C_SUBTLE, &chunk);
                left.y += line;
            }
        }
        left.y += 6;
    }

    left.gap();
    left.heading("VM Access");
    let endpoint = match &samples.vms {
        Ok(report) => match (report.gateway_port, primary_v4(ifaces)) {
            (Some(port), Some(a)) => format!("grpc://{}:{port}", fmt_v4(&a)),
            (Some(port), None) => format!("grpc://(pending):{port}"),
            (None, _) => "not published".to_string(),
        },
        Err(_) => "unavailable".to_string(),
    };
    let ex = draw_text(fb, 40, left.y, SCALE, C_LABEL, "gateway:  ");
    let endpoint_cells = (24 + col_w).saturating_sub(ex) / CELL;
    for (i, chunk) in wrap_cells(&endpoint, endpoint_cells).into_iter().enumerate() {
        if !left.room() {
            break;
        }
        draw_text(fb, if i == 0 { ex } else { addr_indent }, left.y, SCALE, C_VALUE, &chunk);
        left.y += line;
    }

    // The right column starts at a FIXED y, independent of how many interfaces the
    // left column drew. That is what makes each value's position a function of its
    // own section alone, which the boot gate's anchored pixel assertion depends on.
    let mut right = if two_col {
        Column::new(fb, right_x, top, col_w)
    } else {
        Column::new(fb, 24, left.y + 14, col_w)
    };

    render_vms(&mut right, &samples.vms);
    right.gap();
    render_image_store(&mut right, &samples.vms);
    right.gap();
    render_memory(&mut right, &samples.memory);
    right.gap();
    render_cpu(&mut right, &samples.cpu);

    // A completed render means pixels reached scanout, not merely the cached canvas.
    fb.present();
}

// ---------------------------------------------------------------------------
// Interface watching.
// ---------------------------------------------------------------------------

async fn make_watcher() -> Result<fnet_if::WatcherProxy> {
    let state = connect_to_protocol::<fnet_if::StateMarker>()
        .context("connect fuchsia.net.interfaces.State")?;
    let (watcher, server) = create_proxy::<fnet_if::WatcherMarker>();
    state
        .get_watcher(&fnet_if::WatcherOptions::default(), server)
        .context("State.GetWatcher")?;
    Ok(watcher)
}

/// Holds the live sources and the previous CPU sample, and produces one `Samples`
/// per tick.
///
/// The sources are connected ONCE and the connection error, if any, is kept and
/// re-reported every tick. Reconnecting per tick would turn "this capability is not
/// routed" — a permanent, static fact — into a per-tick namespace lookup, and would
/// hide it behind a transient-looking error each time.
struct Sources {
    stats: Result<metrics::Stats>,
    storage: Result<storage::Storage>,
    vms: Result<vm::Status>,
    prev_cpu: Option<metrics::CpuSample>,
}

impl Sources {
    fn connect() -> Sources {
        Sources {
            stats: metrics::Stats::connect(),
            storage: storage::Storage::connect(),
            vms: vm::Status::connect(),
            prev_cpu: None,
        }
    }

    async fn sample(&mut self) -> Samples {
        let memory = match &self.stats {
            Ok(s) => s.memory().await,
            Err(e) => Err(anyhow::anyhow!("{e:#}")),
        };
        let cpu = match &self.stats {
            Ok(s) => match s.cpu().await {
                Ok(now) => {
                    // Utilisation needs two samples. The FIRST tick therefore has no
                    // answer, and says so, rather than reporting a fabricated 0%.
                    let usage = match &self.prev_cpu {
                        Some(prev) => metrics::utilisation(prev, &now).ok_or_else(|| {
                            anyhow::anyhow!("not enough elapsed time between CPU samples yet")
                        }),
                        None => Err(anyhow::anyhow!("measuring (first CPU sample taken)")),
                    };
                    self.prev_cpu = Some(now);
                    usage
                }
                Err(e) => Err(e),
            },
            Err(e) => Err(anyhow::anyhow!("{e:#}")),
        };
        let storage = match &self.storage {
            Ok(s) => s.report().await,
            Err(e) => Err(anyhow::anyhow!("{e:#}")),
        };
        let vms = match &self.vms {
            Ok(status) => status.report().await,
            Err(e) => Err(anyhow::anyhow!("{e:#}")),
        };
        Samples { memory, cpu, storage, vms }
    }
}

/// Emits boot-gate evidence after one presented frame.
///
/// Memory and CPU markers carry the raw values behind visible panel rows, so the gate
/// can validate them independently and derive the expected on-screen text. The disk
/// marker remains background evidence for the combined fileserver test; storage is
/// deliberately no longer rendered on the operator panel.
///
/// Emitted only when the stable identity changes — availability, total memory, core
/// count, or storage verdict — rather than on every tick. Free/used
/// memory, CPU deltas, and filesystem usage are liveness evidence sampled at emission;
/// only the pixel comparison proves visible content.
fn evidence_key(samples: &Samples) -> String {
    let mem = match &samples.memory {
        Ok(m) => format!("mem:{}", m.total),
        Err(_) => "mem:-".to_string(),
    };
    let cpu = match &samples.cpu {
        Ok(u) => format!("cpu:{}", u.num_cpus),
        Err(_) => "cpu:-".to_string(),
    };
    let disk = match &samples.storage {
        Ok(r) => format!("disk:{}:{:?}", r.state, r.usage.map(|(t, _)| t)),
        Err(_) => "disk:-".to_string(),
    };
    let vms = match &samples.vms {
        Ok(report) => format!(
            "vms:{}:{}:{}",
            report.vms.len(),
            report
                .gateway_port
                .map(|port| port.to_string())
                .unwrap_or_else(|| "-".to_owned()),
            report
                .vms
                .iter()
                .map(|vm| vm.state.text())
                .collect::<Vec<_>>()
                .join(",")
        ),
        Err(_) => "vms:-".to_string(),
    };
    format!("{mem} {cpu} {disk} {vms}")
}

fn emit_evidence(samples: &Samples) {
    match &samples.memory {
        Ok(m) => fb::emit(&format!(
            "CERISE-CONSOLE-MEM-OK: total_bytes={} free_bytes={} used_bytes={} total_mib={}\n",
            m.total,
            m.free,
            m.used(),
            metrics::mib(m.total)
        )),
        Err(e) => fb::emit(&format!("CERISE-CONSOLE-MEM-UNAVAILABLE: {e:#}\n")),
    }
    match &samples.cpu {
        // idle_delta_ns and interval_ns are reported so the gate can insist the sample
        // came from two real, separated observations of an advancing kernel counter —
        // a constant would produce neither.
        Ok(u) => fb::emit(&format!(
            "CERISE-CONSOLE-CPU-OK: cores={} reported={} idle_delta_ns={} interval_ns={} mean_pct={}\n",
            u.num_cpus,
            u.per_core_pct.len(),
            u.idle_delta_ns,
            u.interval_ns,
            u.mean_pct()
        )),
        Err(e) => fb::emit(&format!("CERISE-CONSOLE-CPU-UNAVAILABLE: {e:#}\n")),
    }
    match &samples.storage {
        Ok(r) => {
            let (total, used) = match r.usage {
                Some((t, u)) => (t.to_string(), u.to_string()),
                // "none", not 0 — the gate must be able to tell "no filesystem" from
                // "an empty one", and a zero would read as the latter.
                None => ("none".to_string(), "none".to_string()),
            };
            fb::emit(&format!(
                "CERISE-CONSOLE-DISK-OK: state={} devices={} total_bytes={} used_bytes={}\n",
                r.state.replace(' ', "_"),
                r.devices.len(),
                total,
                used
            ));
        }
        Err(e) => fb::emit(&format!("CERISE-CONSOLE-DISK-UNAVAILABLE: {e:#}\n")),
    }
    match &samples.vms {
        Ok(report) => {
            let total = report.store.as_ref().map(|s| s.total_bytes.to_string()).unwrap_or_else(|| "none".to_owned());
            let free = report.store.as_ref().map(|s| s.free_bytes.to_string()).unwrap_or_else(|| "none".to_owned());
            let states = report
                .vms
                .iter()
                .map(|vm| format!("{}={}", vm.id, vm.state.text()))
                .collect::<Vec<_>>()
                .join(",");
            fb::emit(&format!(
                "CERISE-CONSOLE-VM-OK: vms={} images={} store_total_bytes={} \
                 store_free_bytes={} gateway_port={} states={}\n",
                report.vms.len(),
                report.images.len(),
                total,
                free,
                report.gateway_port.map(|p| p.to_string()).unwrap_or_else(|| "none".to_owned()),
                states,
            ));
        }
        Err(err) => fb::emit(&format!("CERISE-CONSOLE-VM-UNAVAILABLE: {err:#}\n")),
    }
    fb::emit("CERISE-CONSOLE-METRICS-RENDERED\n");
}

async fn run() {
    fb::emit("CERISE-CONSOLE-START\n");

    // Acquire the framebuffer from the display driver (retry: the display driver is a
    // non-colocated composite PCI driver that spawns its own driver_host after the
    // nvme/ahci/e1000 stack, so it can take ~90s into boot to bind and publish its
    // service. A generous window keeps this robust on slow boots — well within the
    // validation harness's 600s CONSOLE-RENDERED deadline).
    let mut fb_opt = None;
    for _ in 0..150 {
        match Framebuffer::init(WIDTH, HEIGHT).await {
            Ok(f) => {
                fb_opt = Some(f);
                break;
            }
            Err(e) => {
                fb::emit(&format!("CERISE-CONSOLE-FB-RETRY: {e:#}\n"));
                fuchsia_async::Timer::new(fuchsia_async::MonotonicInstant::after(
                    std::time::Duration::from_secs(2).into(),
                ))
                .await;
            }
        }
    }
    let fb = match fb_opt {
        Some(f) => f,
        None => {
            fb::emit("CERISE-CONSOLE-FAIL: framebuffer bring-up\n");
            return;
        }
    };
    fb::emit("CERISE-CONSOLE-FB-OK\n");

    // Paint an initial screen immediately (before any interface data) so the console
    // is visible even if netstack is slow; then keep it live from the Watcher.
    let mut ifaces: BTreeMap<u64, Iface> = BTreeMap::new();
    let mut sources = Sources::connect();
    let mut samples = sources.sample().await;
    render(&fb, &ifaces, &samples);

    let watcher = loop {
        match make_watcher().await {
            Ok(w) => break w,
            Err(e) => {
                fb::emit(&format!("CERISE-CONSOLE-NET-RETRY: {e:#}\n"));
                fuchsia_async::Timer::new(fuchsia_async::MonotonicInstant::after(
                    std::time::Duration::from_secs(2).into(),
                ))
                .await;
            }
        }
    };

    // ONE loop, two wake-ups. The interface Watcher only fires on change, but CPU
    // utilisation is a delta between samples and the storage verdict is settled
    // asynchronously by another component, so both also need a periodic tick. Racing
    // the two in a single select keeps that as one repaint path rather than two
    // painters fighting over the framebuffer.
    fn next_tick() -> futures::future::Fuse<futures::future::LocalBoxFuture<'static, ()>> {
        async {
            fuchsia_async::Timer::new(fuchsia_async::MonotonicInstant::after(
                std::time::Duration::from_secs(SAMPLE_PERIOD_SECS).into(),
            ))
            .await
        }
        .boxed_local()
        .fuse()
    }

    let mut rendered = false;
    // CERISE-CONSOLE-RENDERED has always meant "painted with a full interface snapshot",
    // and three existing gates order other markers against it. The sampling tick can now
    // trigger a paint before the Watcher has delivered its Idle, so that meaning is held
    // explicitly here rather than left to fall out of the loop's shape.
    let mut have_net_snapshot = false;
    let mut last_evidence: Option<String> = None;
    let mut watch = watcher.watch().boxed_local().fuse();
    let mut tick = next_tick();
    loop {
        let mut repaint = false;
        futures::select! {
            event = watch => {
                match event {
                    Ok(event) => {
                        let is_idle = matches!(event, fnet_if::Event::Idle(_));
                        apply(&mut ifaces, event);
                        // During the initial burst, wait for Idle (the full snapshot)
                        // before the first paint; after that, repaint on every change.
                        have_net_snapshot |= is_idle;
                        repaint = have_net_snapshot;
                        watch = watcher.watch().boxed_local().fuse();
                    }
                    Err(e) => {
                        // The interface stream ending is not fatal — memory, CPU and
                        // storage are all still live, so keep the panel running rather
                        // than freezing the last frame forever. Park this branch for
                        // good and let the tick drive the rest of the boot.
                        fb::emit(&format!("CERISE-CONSOLE-WATCH-END: {e:?}\n"));
                        watch = futures::future::pending().boxed_local().fuse();
                    }
                }
            }
            _ = tick => {
                samples = sources.sample().await;
                repaint = true;
                tick = next_tick();
            }
        }
        if !repaint {
            continue;
        }
        render(&fb, &ifaces, &samples);
        // AFTER the paint, never before: these markers assert what is on the screen.
        let key = evidence_key(&samples);
        if last_evidence.as_deref() != Some(key.as_str()) {
            emit_evidence(&samples);
            last_evidence = Some(key);
        }
        if !rendered && have_net_snapshot {
            rendered = true;
            fb::emit("CERISE-CONSOLE-RENDERED\n");
        }
    }
}

fn main() {
    let mut executor = fuchsia_async::LocalExecutor::default();
    executor.run_singlethreaded(run());
}

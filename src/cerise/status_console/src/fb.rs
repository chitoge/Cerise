//! Cerise status-console framebuffer: a FIDL CLIENT of the native display driver.
//!
//! Previously this module drove the QEMU stdvga (PCI 1234:1111) DIRECTLY — grabbing the
//! ambient root fuchsia.kernel.{Mmio,Ioport}Resource, poking PCI config over CF8/CFC,
//! VBE-mode-setting via BAR2 MMIO, and mapping BAR0 with zx_vmo_create_physical(). That
//! made a plain component hold whole-address-space capabilities — a least-privilege
//! violation. The hardware now lives behind a native DFv2 display driver
//! (src/cerise/drivers/display) that sources its MMIO from the PCI bus (BAR-scoped VMOs,
//! not ambient MmioResource). This console holds ZERO hardware capability: it connects to
//! cerise.display.Service, asks for the framebuffer geometry and VMO, maps that VMO
//! writable, and paints — exactly the same put_pixel/clear/fill_rect surface as before,
//! only the framebuffer ACQUISITION changed (raw MMIO -> FIDL client).
//!
//! (The old raw bring-up survives verbatim in fb_raw.rs, used only by the fb_spike
//! de-risk binary; it is not compiled into status_console.)

use anyhow::{anyhow, bail, Context, Result};
use fidl_cerise_display::{PixelFormat, ServiceMarker};
use fuchsia_component::client::{open_service, Service};
use std::cell::{Cell, RefCell};
use zx::Vmo;

/// Write a boot/test marker straight to the kernel debuglog (surfaced on serial),
/// the same mechanism netstack3_probe/fileserver use — no LogSink dependency.
pub fn emit(msg: &str) {
    // SAFETY: zx_debug_write takes a (ptr,len) of readable bytes; msg is a live &str.
    unsafe {
        zx::sys::zx_debug_write(msg.as_ptr(), msg.len());
    }
}

/// Fine-grained progress marker on the debuglog, to localize failures across a boot.
pub fn trace(stage: &str) {
    emit(&format!("CERISE-FB-TRACE-{stage}\n"));
}

/// A mapped, writable linear framebuffer, backed by the display driver's VMO.
pub struct Framebuffer {
    base: *mut u32,
    pub width: usize,
    pub height: usize,
    /// Row stride in pixels.
    pub stride: usize,
    // Painting directly into an uncached device mapping makes every glyph pixel a
    // device transaction. Keep the frame in ordinary cached memory instead, then
    // publish only spans that changed since the previous frame.
    shadow: RefCell<Vec<u32>>,
    presented: RefCell<Vec<u32>>,
    reported_full_present: Cell<bool>,
    reported_incremental_present: Cell<bool>,
    // Keep the mapping/VMO alive for the process lifetime (the console never exits).
    _vmo: Vmo,
    _mapping_len: usize,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PresentStats {
    pub dirty_pixels: usize,
    pub dirty_spans: usize,
}

impl Framebuffer {
    /// Connects to the display driver's cerise.display.Service, reads the framebuffer
    /// geometry, gets the writable framebuffer VMO, and maps it. The `want_*` arguments
    /// are the console's expected geometry; the driver is the source of truth and its
    /// reported dimensions are used. QEMU normally reports 1024x768; the laptop GOP
    /// driver reports the firmware's native panel mode. No hardware capability is touched.
    ///
    /// The service is AGGREGATED from the driver framework's boot-drivers collection, so
    /// its instance name is assigned by component_manager (not "default") — enumerate the
    /// service directory and use the first published instance (same pattern the fileserver
    /// uses for the block.volume aggregate). Until the driver has bound, the directory is
    /// empty and this returns an error so the caller retries.
    pub async fn init(want_width: usize, want_height: usize) -> Result<Framebuffer> {
        trace("OPEN-DISPLAY-SVC");
        let dir = open_service::<ServiceMarker>().context("open cerise.display.Service dir")?;
        let instance = fuchsia_fs::directory::readdir(&dir)
            .await
            .context("readdir cerise.display.Service dir")?
            .into_iter()
            .map(|e| e.name)
            .next()
            .ok_or_else(|| anyhow!("no cerise.display.Service instance published yet"))?;

        trace("CONNECT-INSTANCE");
        let dir = open_service::<ServiceMarker>().context("re-open cerise.display.Service dir")?;
        let service = Service::<ServiceMarker>::from_service_dir_proxy(dir, ServiceMarker);
        let svc = service
            .connect_to_instance(&instance)
            .context("connect to display service instance")?;
        let fb = svc
            .connect_to_framebuffer()
            .context("connect to Framebuffer member")?;

        trace("GET-INFO");
        let info = fb.get_info().await.context("Framebuffer.GetInfo")?;
        let width = info.width as usize;
        let height = info.height as usize;
        let bytes_per_pixel = info.bytes_per_pixel as usize;
        let stride_bytes = info.stride_bytes as usize;
        if bytes_per_pixel != 4 || info.format != PixelFormat::X8R8G8B8 {
            bail!(
                "unsupported framebuffer format: bpp={bytes_per_pixel} format={:?}",
                info.format
            );
        }
        if width == 0 || height == 0 || stride_bytes < width * 4 {
            bail!("bad framebuffer geometry: {width}x{height} stride_bytes={stride_bytes}");
        }
        if width != want_width || height != want_height {
            // Not fatal — the console lays out against the driver's real dimensions.
            emit(&format!(
                "CERISE-CONSOLE-FB-DIMS: driver={width}x{height} expected={want_width}x{want_height}\n"
            ));
        }

        trace("GET-BUFFER");
        let vmo: Vmo = fb.get_buffer().await.context("Framebuffer.GetBuffer")?;

        let map_len = stride_bytes
            .checked_mul(height)
            .ok_or_else(|| anyhow!("framebuffer size overflow"))?;

        trace("MAP-FRAMEBUFFER");
        // The driver already forced the VMO uncached-device, so writes reach QEMU's
        // scanout with no explicit flush.
        let addr = fuchsia_runtime::vmar_root_self()
            .map(
                0,
                &vmo,
                0,
                map_len,
                zx::VmarFlags::PERM_READ | zx::VmarFlags::PERM_WRITE,
            )
            .context("map framebuffer VMO into address space")?;
        trace("FRAMEBUFFER-MAPPED");

        let pixels =
            width.checked_mul(height).ok_or_else(|| anyhow!("framebuffer pixel overflow"))?;
        Ok(Framebuffer {
            base: addr as *mut u32,
            width,
            height,
            stride: stride_bytes / 4,
            shadow: RefCell::new(vec![0; pixels]),
            // Console colours are 24-bit RGB, so this sentinel cannot equal a painted
            // pixel. The first present therefore publishes the complete frame.
            presented: RefCell::new(vec![u32::MAX; pixels]),
            reported_full_present: Cell::new(false),
            reported_incremental_present: Cell::new(false),
            _vmo: vmo,
            _mapping_len: map_len,
        })
    }

    /// Writes one pixel into the cached back buffer (0xRRGGBB).
    #[inline]
    pub fn put_pixel(&self, x: usize, y: usize, color: u32) {
        if x >= self.width || y >= self.height {
            return;
        }
        self.shadow.borrow_mut()[y * self.width + x] = color;
    }

    /// Fills the cached back buffer with a single color.
    pub fn clear(&self, color: u32) {
        self.shadow.borrow_mut().fill(color);
    }

    /// Fills an axis-aligned rectangle in the cached back buffer.
    pub fn fill_rect(&self, x0: usize, y0: usize, w: usize, h: usize, color: u32) {
        let x1 = x0.saturating_add(w).min(self.width);
        let y1 = y0.saturating_add(h).min(self.height);
        if x0 >= x1 || y0 >= y1 {
            return;
        }
        let mut shadow = self.shadow.borrow_mut();
        for y in y0..y1 {
            let row = y * self.width;
            shadow[row + x0..row + x1].fill(color);
        }
    }

    /// Publishes changed spans from cached memory to the uncached scanout mapping.
    ///
    /// A normal repaint still rebuilds the complete shadow image, which is cheap and
    /// keeps layout code simple. Device writes, however, are proportional to the visual
    /// change: after the first frame a CPU percentage changing by one digit touches a
    /// few glyph spans rather than every pixel of a 1920x1200 panel.
    pub fn present(&self) -> PresentStats {
        let shadow = self.shadow.borrow();
        let mut presented = self.presented.borrow_mut();
        let mut stats = PresentStats::default();

        for y in 0..self.height {
            let row = y * self.width;
            let mut x = 0usize;
            while x < self.width {
                while x < self.width && shadow[row + x] == presented[row + x] {
                    x += 1;
                }
                if x == self.width {
                    break;
                }
                let start = x;
                while x < self.width && shadow[row + x] != presented[row + x] {
                    x += 1;
                }
                let end = x;

                // SAFETY: start/end are within the visible width, stride is at least
                // width, and the driver supplied a mapping of stride*height pixels.
                unsafe {
                    let dst = self.base.add(y * self.stride + start);
                    for (offset, pixel) in shadow[row + start..row + end].iter().enumerate() {
                        dst.add(offset).write_volatile(*pixel);
                    }
                }
                presented[row + start..row + end]
                    .copy_from_slice(&shadow[row + start..row + end]);
                stats.dirty_pixels += end - start;
                stats.dirty_spans += 1;
            }
        }
        let frame_pixels = self.width * self.height;
        if stats.dirty_pixels == frame_pixels && !self.reported_full_present.replace(true) {
            emit(&format!(
                "CERISE-CONSOLE-PRESENT-FULL: pixels={} spans={}\n",
                stats.dirty_pixels, stats.dirty_spans
            ));
        } else if stats.dirty_pixels > 0
            && stats.dirty_pixels < frame_pixels
            && !self.reported_incremental_present.replace(true)
        {
            emit(&format!(
                "CERISE-CONSOLE-PRESENT-DIRTY: pixels={} spans={} frame_pixels={}\n",
                stats.dirty_pixels, stats.dirty_spans, frame_pixels
            ));
        }
        stats
    }
}

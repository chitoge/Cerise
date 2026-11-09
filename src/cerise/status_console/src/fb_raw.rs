//! Cerise status-console framebuffer: a driverless QEMU stdvga bring-up.
//!
//! There is NO display stack vendored in this tree (no `graphics/display/drivers`,
//! no `fuchsia.hardware.display`, no kernel gfxconsole, no ZBI framebuffer producer),
//! and the netstack-sized products boot via the direct-kernel path (`-kernel`/`-initrd`)
//! with no UEFI GOP. So this module is the *producer*: a plain CFv2 component talks to
//! the QEMU "VGA" (stdvga, PCI 1234:1111) device directly and hands back a writable
//! linear framebuffer that QEMU scans out (and a QMP `screendump` captures).
//!
//! It needs exactly two kernel capabilities, both already served by component_manager's
//! builtins and routed like the driver_manager's own resources:
//!   * `fuchsia.kernel.IoportResource` — to touch x86 I/O ports: the PCI config
//!     mechanism (0xCF8/0xCFC, decoded unconditionally by the q35 host bridge — no
//!     firmware/bus-pci/ACPI needed) and the Bochs VBE DISPI registers (0x1CE/0x1CF).
//!   * `fuchsia.kernel.MmioResource` — to `zx_vmo_create_physical()` the framebuffer
//!     BAR and map it writable.
//!
//! The config path is idempotent: if a PCI bus driver already assigned/enabled the
//! BAR, we reuse it; otherwise we assign one ourselves. That means the identical code
//! works whether or not the `driver_framework` bundle's bus-pci is present.

use std::arch::asm;

use anyhow::{anyhow, bail, Context, Result};
use fidl_fuchsia_kernel::{IoportResourceMarker, MmioResourceMarker};
use fuchsia_component::client::connect_to_protocol_sync;
use zx::{MonotonicInstant, Resource, Vmo};

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

// ---------------------------------------------------------------------------
// x86 port I/O primitives. Valid only after zx_ioports_request() has granted the
// process access to the relevant ports (it clears the per-thread I/O permission
// bitmap bits, so the `in`/`out` instructions no longer #GP).
// ---------------------------------------------------------------------------

#[inline]
unsafe fn outl(port: u16, val: u32) {
    asm!("out dx, eax", in("dx") port, in("eax") val, options(nomem, nostack, preserves_flags));
}

#[inline]
unsafe fn inl(port: u16) -> u32 {
    let val: u32;
    asm!("in eax, dx", out("eax") val, in("dx") port, options(nomem, nostack, preserves_flags));
    val
}

// --- PCI config space via the CF8/CFC mechanism (bus 0 only; QEMU q35). ---

const PCI_CONFIG_ADDRESS: u16 = 0xCF8;
const PCI_CONFIG_DATA: u16 = 0xCFC;

fn cfg_address(bus: u8, dev: u8, func: u8, offset: u8) -> u32 {
    0x8000_0000
        | ((bus as u32) << 16)
        | ((dev as u32) << 11)
        | ((func as u32) << 8)
        | ((offset as u32) & 0xFC)
}

unsafe fn pci_read32(bus: u8, dev: u8, func: u8, offset: u8) -> u32 {
    outl(PCI_CONFIG_ADDRESS, cfg_address(bus, dev, func, offset));
    inl(PCI_CONFIG_DATA)
}

unsafe fn pci_write32(bus: u8, dev: u8, func: u8, offset: u8, val: u32) {
    outl(PCI_CONFIG_ADDRESS, cfg_address(bus, dev, func, offset));
    outl(PCI_CONFIG_DATA, val);
}

// --- Bochs VBE DISPI registers, programmed through the stdvga BAR2 MMIO aperture. ---
//
// The legacy VBE I/O ports (0x1CE/0x1CF) proved unusable here: even after a successful
// zx_ioports_request for them, the first 16-bit `out` to 0x1CE faulted the process
// (while 32-bit CF8/CFC config I/O works fine). QEMU stdvga also exposes the same VBE
// dispi registers via its BAR2 MMIO window at offset 0x500 (reg N at 0x500 + N*2), so
// we program the mode through MmioResource instead — no legacy port I/O for the mode set.
const VGA_MMIO_VBE_OFFSET: usize = 0x500;
const VBE_DISPI_INDEX_XRES: usize = 1;
const VBE_DISPI_INDEX_YRES: usize = 2;
const VBE_DISPI_INDEX_BPP: usize = 3;
const VBE_DISPI_INDEX_ENABLE: usize = 4;
const VBE_DISPI_INDEX_VIRT_WIDTH: usize = 6;
const VBE_DISPI_ENABLED: u16 = 0x01;
const VBE_DISPI_LFB_ENABLED: u16 = 0x40;

// SAFETY: `mmio_base` must be a valid mapping of the device's BAR2 of at least
// VGA_MMIO_VBE_OFFSET + 0x40 bytes.
unsafe fn dispi_write(mmio_base: *mut u8, index: usize, val: u16) {
    let reg = mmio_base.add(VGA_MMIO_VBE_OFFSET + index * 2) as *mut u16;
    reg.write_volatile(val);
}

// QEMU stdvga / bochs-display PCI identity.
const VGA_VENDOR_ID: u16 = 0x1234;
const VGA_DEVICE_ID: u16 = 0x1111;

fn ioports_request(res: &Resource, addr: u16, len: u32) -> Result<()> {
    // SAFETY: res is a valid IoportResource handle; grants [addr, addr+len) to this process.
    let st = unsafe { zx::sys::zx_ioports_request(res.raw_handle(), addr, len) };
    if st != zx::sys::ZX_OK {
        bail!("zx_ioports_request(addr={addr:#x}, len={len}) failed: status {st}");
    }
    Ok(())
}

fn create_physical_vmo(mmio: &Resource, paddr: usize, size: usize) -> Result<Vmo> {
    let mut handle: zx::sys::zx_handle_t = zx::sys::ZX_HANDLE_INVALID;
    // SAFETY: mmio is a valid MmioResource; paddr/size are page-aligned; out ptr is valid.
    let st = unsafe { zx::sys::zx_vmo_create_physical(mmio.raw_handle(), paddr, size, &mut handle) };
    if st != zx::sys::ZX_OK {
        bail!("zx_vmo_create_physical(paddr={paddr:#x}, size={size:#x}) failed: status {st}");
    }
    // SAFETY: the syscall returned a fresh, owned VMO handle on success.
    Ok(Vmo::from(unsafe { zx::NullableHandle::from_raw(handle) }))
}

/// Maps a physical MMIO/device range writable and returns (base_ptr, page_len, vmo).
/// `paddr`/`len` are page-aligned internally. The returned Vmo must be kept alive for
/// as long as the mapping is used.
fn map_physical(mmio: &Resource, paddr: usize, len: usize) -> Result<(usize, usize, Vmo)> {
    let page_off = paddr & 0xFFF;
    let base = paddr & !0xFFF;
    let map_len = ((len + page_off) + 0xFFF) & !0xFFF;
    let vmo = create_physical_vmo(mmio, base, map_len)?;
    let addr = fuchsia_runtime::vmar_root_self()
        .map(
            0,
            &vmo,
            0,
            map_len,
            zx::VmarFlags::PERM_READ | zx::VmarFlags::PERM_WRITE,
        )
        .context("map physical VMO into address space")?;
    Ok((addr + page_off, map_len, vmo))
}

/// A mapped, writable linear framebuffer.
pub struct Framebuffer {
    base: *mut u32,
    pub width: usize,
    pub height: usize,
    /// Row stride in pixels (== width for these modes).
    pub stride: usize,
    // Keep the mapping/VMO alive for the process lifetime (the console never exits).
    _vmo: Vmo,
    _mapping_len: usize,
}

impl Framebuffer {
    /// Brings up the QEMU stdvga device at `width`x`height`x32bpp and maps its
    /// linear framebuffer writable. Self-contained: acquires the kernel resources,
    /// finds the device on PCI bus 0, ensures its BAR0 is assigned + decoding, sets
    /// the VBE mode, and maps BAR0.
    pub fn init(width: usize, height: usize) -> Result<Framebuffer> {
        trace("CONNECT-IOPORT-RES");
        let ioport = connect_to_protocol_sync::<IoportResourceMarker>()
            .context("connect fuchsia.kernel.IoportResource")?
            .get(MonotonicInstant::INFINITE)
            .context("IoportResource.Get")?;
        trace("CONNECT-MMIO-RES");
        let mmio = connect_to_protocol_sync::<MmioResourceMarker>()
            .context("connect fuchsia.kernel.MmioResource")?
            .get(MonotonicInstant::INFINITE)
            .context("MmioResource.Get")?;

        // Grant only the PCI config mechanism ports (0xCF8..0xCFF). The VBE mode set is
        // done through BAR2 MMIO, not the legacy 0x1CE/0x1CF I/O ports.
        trace("IOPORTS-REQUEST");
        ioports_request(&ioport, PCI_CONFIG_ADDRESS, 8).context("request PCI config ports")?;
        trace("IOPORTS-GRANTED");

        // Find the device + program the VBE mode (via BAR2 MMIO); returns the BAR0 base.
        // SAFETY: the CF8/CFC grant above is in place before any port I/O runs.
        let fb_base = unsafe { Self::program_device(&mmio, width, height)? };
        trace(&format!("FB-BASE-{fb_base:#010x}"));

        let fb_len = width
            .checked_mul(height)
            .and_then(|p| p.checked_mul(4))
            .ok_or_else(|| anyhow!("framebuffer size overflow"))?;

        trace("MAP-FRAMEBUFFER");
        // Leave the mapping uncached (the physical-VMO default): every write is
        // immediately visible to QEMU's scanout with no explicit flush needed.
        let (addr, map_len, vmo) =
            map_physical(&mmio, fb_base, fb_len).context("map framebuffer BAR0")?;
        trace("FRAMEBUFFER-MAPPED");

        Ok(Framebuffer {
            base: addr as *mut u32,
            width,
            height,
            stride: width,
            _vmo: vmo,
            _mapping_len: map_len,
        })
    }

    /// Finds the stdvga device, ensures memory decoding is on, programs the VBE mode
    /// through the BAR2 MMIO aperture, and returns the BAR0 (framebuffer) physical base.
    ///
    /// SAFETY: caller must have obtained the CF8/CFC port grant first.
    unsafe fn program_device(mmio: &Resource, width: usize, height: usize) -> Result<usize> {
        trace("PCI-SCAN-FIRST-IO");
        let mut found: Option<u8> = None;
        for dev in 0u8..32 {
            let id = pci_read32(0, dev, 0, 0x00);
            let vendor = (id & 0xFFFF) as u16;
            let device = (id >> 16) as u16;
            if vendor == VGA_VENDOR_ID && device == VGA_DEVICE_ID {
                found = Some(dev);
                break;
            }
        }
        let dev = found.ok_or_else(|| {
            anyhow!("QEMU stdvga (PCI {VGA_VENDOR_ID:#06x}:{VGA_DEVICE_ID:#06x}) not found on bus 0")
        })?;

        let cmd = pci_read32(0, dev, 0, 0x04);
        let bar0 = pci_read32(0, dev, 0, 0x10); // BAR0: linear framebuffer (32-bit mem BAR).
        let bar2 = pci_read32(0, dev, 0, 0x18); // BAR2: MMIO registers (incl. VBE dispi).
        trace(&format!("CFG-cmd{cmd:#06x}-bar0{bar0:#010x}-bar2{bar2:#010x}"));

        let fb_base = (bar0 & 0xFFFF_FFF0) as usize;
        let mmio_base = (bar2 & 0xFFFF_FFF0) as usize;
        if fb_base == 0 || mmio_base == 0 {
            bail!("stdvga BARs not assigned (bar0={bar0:#x} bar2={bar2:#x}); no PCI bus driver?");
        }

        // Ensure memory-space decode is enabled (bus-pci normally already did this).
        pci_write32(0, dev, 0, 0x04, cmd | 0x2);
        trace("MEM-DECODE-ON");

        // Map BAR2 to program the VBE dispi registers via MMIO. The mapping is dropped
        // when this function returns; the programmed mode stays latched in the device.
        let (mmio_ptr, _len, _vmo) =
            map_physical(mmio, mmio_base, VGA_MMIO_VBE_OFFSET + 0x40).context("map BAR2 MMIO")?;
        let mmio_ptr = mmio_ptr as *mut u8;
        trace("BAR2-MAPPED");

        // Program the Bochs VBE mode: disable, set geometry, enable the linear FB.
        dispi_write(mmio_ptr, VBE_DISPI_INDEX_ENABLE, 0);
        dispi_write(mmio_ptr, VBE_DISPI_INDEX_XRES, width as u16);
        dispi_write(mmio_ptr, VBE_DISPI_INDEX_YRES, height as u16);
        dispi_write(mmio_ptr, VBE_DISPI_INDEX_BPP, 32);
        dispi_write(mmio_ptr, VBE_DISPI_INDEX_VIRT_WIDTH, width as u16);
        dispi_write(
            mmio_ptr,
            VBE_DISPI_INDEX_ENABLE,
            VBE_DISPI_ENABLED | VBE_DISPI_LFB_ENABLED,
        );
        trace("DISPI-MODE-SET");

        Ok(fb_base)
    }

    /// Writes one pixel (0xRRGGBB; the alpha byte is ignored by QEMU stdvga).
    #[inline]
    pub fn put_pixel(&self, x: usize, y: usize, color: u32) {
        if x >= self.width || y >= self.height {
            return;
        }
        // SAFETY: bounds checked; base points at a mapping of at least stride*height px.
        unsafe {
            self.base.add(y * self.stride + x).write_volatile(color);
        }
    }

    /// Fills the whole framebuffer with a single color.
    pub fn clear(&self, color: u32) {
        for y in 0..self.height {
            for x in 0..self.width {
                self.put_pixel(x, y, color);
            }
        }
    }

    /// Fills an axis-aligned rectangle (clipped to the screen).
    pub fn fill_rect(&self, x0: usize, y0: usize, w: usize, h: usize, color: u32) {
        let x1 = (x0 + w).min(self.width);
        let y1 = (y0 + h).min(self.height);
        for y in y0..y1 {
            for x in x0..x1 {
                self.put_pixel(x, y, color);
            }
        }
    }
}

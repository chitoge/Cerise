//! initial prototype de-risk spike: prove a driverless writable QEMU framebuffer end to end.
//!
//! This component brings up the QEMU stdvga linear framebuffer via `fb::Framebuffer`
//! (PCI CF8/CFC + Bochs VBE + a physical-VMO mapping — no display driver, no
//! driver-index, no bind rules), paints a deterministic, obviously-non-blank pattern,
//! and emits `CERISE-FBSPIKE-RENDERED`. The validation harness boots this in a product,
//! waits for that marker on serial, then takes a QMP `screendump` — the residual risk
//! being proven is "a guest write to the stdvga BAR shows up in a screendump."
//!
//! The process then parks forever so the framebuffer content persists for capture.

#[path = "fb_raw.rs"]
mod fb;

use fb::Framebuffer;

const WIDTH: usize = 1024;
const HEIGHT: usize = 768;

// A few distinctive colors so the screendump is unambiguously structured, not noise.
const BG: u32 = 0x0011_2244; // deep blue background
const BAR_R: u32 = 0x00CC_2222;
const BAR_G: u32 = 0x0022_CC22;
const BAR_B: u32 = 0x0022_44CC;
const PANEL: u32 = 0x00F0_C040; // amber panel (ESXi-ish)

fn main() {
    fb::emit("CERISE-FBSPIKE-START\n");

    let fb = match Framebuffer::init(WIDTH, HEIGHT) {
        Ok(fb) => fb,
        Err(e) => {
            fb::emit(&format!("CERISE-FBSPIKE-FAIL: {e:#}\n"));
            park();
        }
    };

    // Background.
    fb.clear(BG);

    // Three vertical R/G/B bars across the bottom third — trivially recognizable.
    let third = WIDTH / 3;
    let bar_y = HEIGHT * 2 / 3;
    let bar_h = HEIGHT - bar_y;
    fb.fill_rect(0, bar_y, third, bar_h, BAR_R);
    fb.fill_rect(third, bar_y, third, bar_h, BAR_G);
    fb.fill_rect(2 * third, bar_y, WIDTH - 2 * third, bar_h, BAR_B);

    // A centered amber panel with a nested blue inset (a clear rectangle-in-rectangle).
    let pw = WIDTH / 2;
    let ph = HEIGHT / 3;
    let px = (WIDTH - pw) / 2;
    let py = HEIGHT / 6;
    fb.fill_rect(px, py, pw, ph, PANEL);
    fb.fill_rect(px + 16, py + 16, pw - 32, ph - 32, BG);

    fb::emit("CERISE-FBSPIKE-RENDERED\n");
    park();
}

fn park() -> ! {
    loop {
        std::thread::sleep(std::time::Duration::from_secs(3600));
    }
}

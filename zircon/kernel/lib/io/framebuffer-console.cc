// Copyright 2026 The Cerise Authors
//
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT

// The kernel's half of the framebuffer console.  The renderer itself is shared
// with physboot (//zircon/kernel/phys/framebuffer-console.cc, compiled into
// this library too); this file is only the wiring: where the framebuffer comes
// from, when the console starts, and what feeds it.
//
// Why this exists: on a machine whose UART produces nothing, everything the
// kernel prints between the hand-off and userspace bringing up a display
// driver is invisible.  A boot that dies in there is indistinguishable from a
// boot that never got there at all, which makes every hypothesis about it
// unfalsifiable.  Drawing on the panel the boot loader already set up removes
// that blind spot.

#include <debug.h>
#include <inttypes.h>
#include <lib/boot-options/boot-options.h>
#include <lk/init.h>

#include <ktl/string_view.h>
#include <phys/framebuffer-console.h>
#include <phys/handoff.h>

#include <ktl/enforce.h>

void FramebufferConsoleInitEarly(const PhysHandoff& handoff) {
  // No ZBI_TYPE_FRAMEBUFFER item, or one physboot declined to map (an unusable
  // pixel format, say): all normal, all meaning no framebuffer console.  Every
  // serial-only board and every QEMU serial boot lands here.
  if (!handoff.framebuffer || handoff.framebuffer_mmio.empty()) {
    return;
  }

  FramebufferConsole& console = GetFramebufferConsole();
  // The framebuffer is no longer identity mapped as it was in physboot, so the
  // console is pointed at the hand-off's mapping of it rather than at the
  // physical address the item reports.
  if (!console.Init(*handoff.framebuffer,
                    reinterpret_cast<void*>(handoff.framebuffer_mmio.vaddr()))) {
    return;
  }

  // The banner is drawn straight away, before printf is usable -- there is no
  // debuglog, no current thread and no static constructors yet -- because the
  // whole point is to be on screen before anything that could hang.  Seeing it
  // means the kernel's first instructions ran and the hand-off's framebuffer
  // mapping is good; not seeing it, with physboot's text still on the panel,
  // means the kernel never got this far.
  console.Banner("CERISE KERNEL FRAMEBUFFER CONSOLE"sv);
}

void FramebufferConsoleWrite(ktl::string_view str) { GetFramebufferConsole().Write(str); }

void FramebufferConsoleAnnounce(const PhysHandoff& handoff) {
  const FramebufferConsole& console = GetFramebufferConsole();
  if (!console.active()) {
    return;
  }
  const zbi_swfb_t& fb = *handoff.framebuffer;
  // dprintf(ALWAYS) so this is not hidden behind a log level: it is the only
  // thing that tells a serial-side reader -- and //validation:firstlight-uefi-boot,
  // which then measures the banner in pixels -- that the panel is the kernel's
  // now, and what geometry it found there.
  dprintf(ALWAYS,
          "CERISE-KERNEL-FB-CONSOLE base=%#" PRIx64 " vaddr=%#" PRIxPTR " %" PRIu32 "x%" PRIu32
          " stride=%" PRIu32 " format=%#" PRIx32 " %" PRIu32 "x%" PRIu32 " cells scale=%" PRIu32
          "\n",
          fb.base, handoff.framebuffer_mmio.vaddr(), fb.width, fb.height, fb.stride, fb.format,
          console.columns(), console.rows(), console.scale());
}

// The kernel console exists to cover the otherwise invisible interval from
// physboot through kernel initialization. Once userspace is about to start, the
// display service and status console become the sole framebuffer owner. Leaving
// this renderer active would let later debuglog writes scribble over their
// pixels, and a cached userspace compositor cannot even detect those out-of-band
// writes reliably.
//
// This hook runs immediately before userboot_init(). Panics and hangs before it
// remain visible on the panel; later diagnostics continue over the configured
// serial/debuglog path.
LK_INIT_HOOK(
    framebuffer_console_handoff,
    [](unsigned int /*level*/) {
      FramebufferConsole& console = GetFramebufferConsole();
      if (!console.active()) {
        return;
      }
      // Keeping the renderer active past this point means later debuglog
      // writes scribble over userspace's pixels — which is exactly what the
      // triage knob asks for: on a machine with no working serial capture, a
      // boot that stalls between this hook and the display service coming up
      // is otherwise invisible (observed on the HP EliteDesk 800 G3, whose
      // SOL session drops across the reset that starts the boot).
      if (BootOptions::Get()->framebuffer_console_keep) {
        dprintf(ALWAYS,
                "CERISE-KERNEL-FB-CONSOLE-KEPT: kernel.framebuffer-console.keep=true — the "
                "kernel renderer stays active and WILL overdraw userspace's framebuffer\n");
        return;
      }
      console.Disable();
      dprintf(ALWAYS,
              "CERISE-KERNEL-FB-CONSOLE-HANDOFF: userspace is now the framebuffer owner\n");
    },
    LK_INIT_LEVEL_USER - 1)

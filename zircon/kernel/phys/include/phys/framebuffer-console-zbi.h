// Copyright 2026 The Cerise Authors
//
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT

#ifndef ZIRCON_KERNEL_PHYS_INCLUDE_PHYS_FRAMEBUFFER_CONSOLE_ZBI_H_
#define ZIRCON_KERNEL_PHYS_INCLUDE_PHYS_FRAMEBUFFER_CONSOLE_ZBI_H_

#include <phys/early-boot.h>
#include <phys/framebuffer-console.h>

// This is physboot's half of the framebuffer console, kept apart from the
// renderer itself because the renderer is also compiled into the kernel, where
// neither EarlyBootZbi nor PhysConsole exists.

// Finds a ZBI_TYPE_FRAMEBUFFER item in `zbi` and, if it describes a usable
// framebuffer, wires the console up to stdout via PhysConsole::set_graphics.
// Absent or unusable item means no framebuffer console and no other effect.
void SetFramebufferConsole(EarlyBootZbi& zbi);

#endif  // ZIRCON_KERNEL_PHYS_INCLUDE_PHYS_FRAMEBUFFER_CONSOLE_ZBI_H_

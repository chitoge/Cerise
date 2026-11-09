// Copyright 2017 The Fuchsia Authors
//
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT
//
// Minimal pdev interrupt abstraction layer for the GIC interrupt controller drivers.

#ifndef ZIRCON_KERNEL_DEV_PDEV_INCLUDE_PDEV_INTERRUPT_H_
#define ZIRCON_KERNEL_DEV_PDEV_INCLUDE_PDEV_INTERRUPT_H_

#include <sys/types.h>
#include <zircon/types.h>

#include <dev/interrupt.h>
#include <kernel/mp.h>
#include <kernel/cpu.h>

struct iframe_t;

// Interrupt controller operations registered via pdev_register_interrupts().
struct pdev_interrupt_ops {
  zx_status_t (*mask)(interrupt_vector_t vector);
  zx_status_t (*unmask)(interrupt_vector_t vector);
  zx_status_t (*deactivate)(interrupt_vector_t vector);
  zx_status_t (*configure)(interrupt_vector_t vector, interrupt_trigger_mode tm,
                            interrupt_polarity pol);
  zx_status_t (*get_config)(interrupt_vector_t vector, interrupt_trigger_mode* tm,
                              interrupt_polarity* pol);
  zx_status_t (*set_affinity)(interrupt_vector_t vector, cpu_mask_t mask);
  bool (*is_valid)(uint vector, uint32_t flags);
  uint32_t (*get_base_vector)();
  uint32_t (*get_max_vector)();
  interrupt_vector_t (*remap)(interrupt_vector_t vector);
  zx_status_t (*send_ipi)(cpu_mask_t logical_target, mp_ipi ipi);
  void (*init_percpu_early)();
  void (*init_percpu)();
  void (*handle_irq)(iframe_t* frame);
  void (*shutdown)();
  void (*shutdown_cpu)();
  zx_status_t (*suspend_cpu)();
  zx_status_t (*resume_cpu)();
  bool (*msi_is_supported)();
  bool (*msi_supports_masking)();
  void (*msi_mask_unmask)(const msi_block_t* block, uint msi_id, bool mask);
  zx_status_t (*msi_alloc_block)(uint requested_irqs, bool can_target_64bit, bool is_msix,
                                  msi_block_t* out_block);
  void (*msi_free_block)(msi_block_t* block);
  void (*msi_register_handler)(const msi_block_t* block, uint msi_id,
                                interrupt_handler_t handler);
  zx_status_t (*get_status)(interrupt_vector_t vector, bool& out_pending, bool& out_enabled);
};

// Register an interrupt controller.  Only one may be registered at a time.
void pdev_register_interrupts(const pdev_interrupt_ops* ops);

// Invoke the registered interrupt handler for `vector`, if one is registered.
void pdev_invoke_int_if_present(interrupt_vector_t vector);

#endif  // ZIRCON_KERNEL_DEV_PDEV_INCLUDE_PDEV_INTERRUPT_H_

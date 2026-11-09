// Minimal pdev interrupt dispatch layer.
// Provides pdev_register_interrupts (called by GIC driver at boot) and
// pdev_invoke_int_if_present (called by GIC handle_irq to run software handlers).
//
// The software handler table is maintained here; callers use register_int_handler()
// from dev/interrupt.h to register handlers.

#include <pdev/interrupt.h>

#include <dev/interrupt.h>
#include <kernel/spinlock.h>
#include <ktl/array.h>
#include <zircon/errors.h>

namespace {
DECLARE_SINGLETON_SPINLOCK(gPdevInterruptLock);
const pdev_interrupt_ops* gOps = nullptr;

// Software handler table indexed by interrupt vector.
ktl::array<interrupt_handler_t, MAX_INTERRUPTS> gHandlers;
}  // namespace

void pdev_register_interrupts(const pdev_interrupt_ops* ops) {
  Guard<SpinLock, IrqSave> guard{gPdevInterruptLock::Get()};
  gOps = ops;
}

void pdev_invoke_int_if_present(interrupt_vector_t vector) {
  if (vector >= MAX_INTERRUPTS) {
    return;
  }
  // Call without lock — handler is stored atomically by register_int_handler.
  if (gHandlers[vector]) {
    gHandlers[vector]();
  }
}

// platform_irq is called from the ARM64 exception handler (exceptions_c.cc).
// It dispatches to the registered interrupt controller's handle_irq, which
// reads the IAR register, identifies the vector, and calls pdev_invoke_int_if_present.
void platform_irq(iframe_t* frame) {
  const pdev_interrupt_ops* ops;
  {
    Guard<SpinLock, IrqSave> guard{gPdevInterruptLock::Get()};
    ops = gOps;
  }
  if (ops && ops->handle_irq) {
    ops->handle_irq(frame);
  }
}

zx_status_t register_int_handler(unsigned int vector, interrupt_handler_t handler) {
  if (vector >= MAX_INTERRUPTS) {
    return ZX_ERR_INVALID_ARGS;
  }
  gHandlers[vector] = ktl::move(handler);
  return ZX_OK;
}

zx_status_t register_permanent_int_handler(unsigned int vector, interrupt_handler_t handler) {
  return register_int_handler(vector, ktl::move(handler));
}

uint32_t interrupt_get_base_vector() {
  Guard<SpinLock, IrqSave> guard{gPdevInterruptLock::Get()};
  if (gOps && gOps->get_base_vector) {
    return gOps->get_base_vector();
  }
  return 0;
}

uint32_t interrupt_get_max_vector() {
  Guard<SpinLock, IrqSave> guard{gPdevInterruptLock::Get()};
  if (gOps && gOps->get_max_vector) {
    return gOps->get_max_vector();
  }
  return MAX_INTERRUPTS - 1;
}

bool is_valid_interrupt(unsigned int vector, uint32_t flags) {
  Guard<SpinLock, IrqSave> guard{gPdevInterruptLock::Get()};
  if (gOps && gOps->is_valid) {
    return gOps->is_valid(vector, flags);
  }
  return vector < MAX_INTERRUPTS;
}

unsigned int remap_interrupt(unsigned int vector) {
  Guard<SpinLock, IrqSave> guard{gPdevInterruptLock::Get()};
  if (gOps && gOps->remap) {
    return gOps->remap(vector);
  }
  return vector;
}

zx_status_t mask_interrupt(unsigned int vector) {
  Guard<SpinLock, IrqSave> guard{gPdevInterruptLock::Get()};
  if (gOps && gOps->mask) {
    return gOps->mask(vector);
  }
  return ZX_ERR_NOT_SUPPORTED;
}

zx_status_t unmask_interrupt(unsigned int vector) {
  Guard<SpinLock, IrqSave> guard{gPdevInterruptLock::Get()};
  if (gOps && gOps->unmask) {
    return gOps->unmask(vector);
  }
  return ZX_ERR_NOT_SUPPORTED;
}

zx_status_t deactivate_interrupt(unsigned int vector) {
  Guard<SpinLock, IrqSave> guard{gPdevInterruptLock::Get()};
  if (gOps && gOps->deactivate) {
    return gOps->deactivate(vector);
  }
  return ZX_ERR_NOT_SUPPORTED;
}

zx_status_t configure_interrupt(unsigned int vector, interrupt_trigger_mode tm,
                                 interrupt_polarity pol) {
  Guard<SpinLock, IrqSave> guard{gPdevInterruptLock::Get()};
  if (gOps && gOps->configure) {
    return gOps->configure(vector, tm, pol);
  }
  return ZX_ERR_NOT_SUPPORTED;
}

zx_status_t get_interrupt_config(unsigned int vector, interrupt_trigger_mode* tm,
                                  interrupt_polarity* pol) {
  Guard<SpinLock, IrqSave> guard{gPdevInterruptLock::Get()};
  if (gOps && gOps->get_config) {
    return gOps->get_config(vector, tm, pol);
  }
  return ZX_ERR_NOT_SUPPORTED;
}

zx_status_t set_interrupt_affinity(unsigned int vector, cpu_mask_t mask) {
  Guard<SpinLock, IrqSave> guard{gPdevInterruptLock::Get()};
  if (gOps && gOps->set_affinity) {
    return gOps->set_affinity(vector, mask);
  }
  return ZX_ERR_NOT_SUPPORTED;
}

zx_status_t interrupt_send_ipi(cpu_mask_t target, mp_ipi ipi) {
  Guard<SpinLock, IrqSave> guard{gPdevInterruptLock::Get()};
  if (gOps && gOps->send_ipi) {
    return gOps->send_ipi(target, ipi);
  }
  return ZX_ERR_NOT_SUPPORTED;
}

void interrupt_init_percpu_early() {
  const pdev_interrupt_ops* ops;
  {
    Guard<SpinLock, IrqSave> guard{gPdevInterruptLock::Get()};
    ops = gOps;
  }
  if (ops && ops->init_percpu_early) {
    ops->init_percpu_early();
  }
}

void interrupt_init_percpu() {
  const pdev_interrupt_ops* ops;
  {
    Guard<SpinLock, IrqSave> guard{gPdevInterruptLock::Get()};
    ops = gOps;
  }
  if (ops && ops->init_percpu) {
    ops->init_percpu();
  }
}

void shutdown_interrupts() {
  const pdev_interrupt_ops* ops;
  {
    Guard<SpinLock, IrqSave> guard{gPdevInterruptLock::Get()};
    ops = gOps;
  }
  if (ops && ops->shutdown) {
    ops->shutdown();
  }
}

void shutdown_interrupts_curr_cpu() {
  const pdev_interrupt_ops* ops;
  {
    Guard<SpinLock, IrqSave> guard{gPdevInterruptLock::Get()};
    ops = gOps;
  }
  if (ops && ops->shutdown_cpu) {
    ops->shutdown_cpu();
  }
}

zx_status_t suspend_interrupts_curr_cpu() {
  const pdev_interrupt_ops* ops;
  {
    Guard<SpinLock, IrqSave> guard{gPdevInterruptLock::Get()};
    ops = gOps;
  }
  if (ops && ops->suspend_cpu) {
    return ops->suspend_cpu();
  }
  return ZX_ERR_NOT_SUPPORTED;
}

zx_status_t resume_interrupts_curr_cpu() {
  const pdev_interrupt_ops* ops;
  {
    Guard<SpinLock, IrqSave> guard{gPdevInterruptLock::Get()};
    ops = gOps;
  }
  if (ops && ops->resume_cpu) {
    return ops->resume_cpu();
  }
  return ZX_ERR_NOT_SUPPORTED;
}

bool msi_is_supported() {
  Guard<SpinLock, IrqSave> guard{gPdevInterruptLock::Get()};
  return gOps && gOps->msi_is_supported && gOps->msi_is_supported();
}

bool msi_supports_masking() {
  Guard<SpinLock, IrqSave> guard{gPdevInterruptLock::Get()};
  return gOps && gOps->msi_supports_masking && gOps->msi_supports_masking();
}

void msi_mask_unmask(const msi_block_t* block, uint msi_id, bool mask) {
  const pdev_interrupt_ops* ops;
  {
    Guard<SpinLock, IrqSave> guard{gPdevInterruptLock::Get()};
    ops = gOps;
  }
  if (ops && ops->msi_mask_unmask) {
    ops->msi_mask_unmask(block, msi_id, mask);
  }
}

zx_status_t msi_alloc_block(uint requested_irqs, bool can_target_64bit, bool is_msix,
                              msi_block_t* out_block) {
  const pdev_interrupt_ops* ops;
  {
    Guard<SpinLock, IrqSave> guard{gPdevInterruptLock::Get()};
    ops = gOps;
  }
  if (ops && ops->msi_alloc_block) {
    return ops->msi_alloc_block(requested_irqs, can_target_64bit, is_msix, out_block);
  }
  return ZX_ERR_NOT_SUPPORTED;
}

void msi_free_block(msi_block_t* block) {
  const pdev_interrupt_ops* ops;
  {
    Guard<SpinLock, IrqSave> guard{gPdevInterruptLock::Get()};
    ops = gOps;
  }
  if (ops && ops->msi_free_block) {
    ops->msi_free_block(block);
  }
}

void msi_register_handler(const msi_block_t* block, uint msi_id, interrupt_handler_t handler) {
  const pdev_interrupt_ops* ops;
  {
    Guard<SpinLock, IrqSave> guard{gPdevInterruptLock::Get()};
    ops = gOps;
  }
  if (ops && ops->msi_register_handler) {
    ops->msi_register_handler(block, msi_id, ktl::move(handler));
  }
}

zx_status_t interrupt_get_status(interrupt_vector_t vector, bool& out_pending, bool& out_enabled) {
  Guard<SpinLock, IrqSave> guard{gPdevInterruptLock::Get()};
  if (gOps && gOps->get_status) {
    return gOps->get_status(vector, out_pending, out_enabled);
  }
  return ZX_ERR_NOT_SUPPORTED;
}

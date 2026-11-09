// Stub DAP (Debug Access Port) implementation.
// The full dap.cc requires <dev/coresight/rom_table.h> which is not present in this tree.
// These stubs satisfy the linker without the coresight dependency.
#include <arch/arm64/dap.h>
#include <stdio.h>
#include <zircon/errors.h>

bool arm64_dap_is_enabled() { return false; }

zx_status_t arm64_dap_read_processor_state(cpu_num_t, arm64_dap_processor_state*) {
  return ZX_ERR_NOT_SUPPORTED;
}

void arm64_dap_processor_state::Dump(FILE* fp) {
  fprintf(fp, "DAP not available\n");
}

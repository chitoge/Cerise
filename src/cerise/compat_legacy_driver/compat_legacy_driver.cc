// Driver-host bring-up, Step 3 — MINIMAL LEGACY (DFv1 / ZIRCON_DRIVER) driver.
//
// This is the smallest possible DFv1 driver used to de-risk the compat MODULE
// mechanism in isolation: it is loaded by driver_host_dfv2 as an additional ELF
// MODULE alongside the DFv2 compat shim (compat.so), and its bind hook is invoked
// THROUGH compat (compat reads this module's __zircon_driver_rec__ -> ops.bind from
// DriverStartArgs.symbols, which the loader populates).
//
// It has no DT_NEEDED on libdriver.so: it is built --allow-shlib-undefined so the
// DFv1 ABI symbols it references (device_add -> device_add_from_driver) are left
// UND and resolved at load time against compat.so, which is dlopen'd RTLD_GLOBAL in
// the same driver_host process and exports the 29 DFv1 ABI symbols (compat.ld). This
// is the symbol-scoping that the compat.shard.cml `loader_overrides: libdriver.so ->
// driver/compat.so` achieves upstream.
//
// On bind it (1) logs CERISE-COMPAT-LEGACY-OK via zx_debug_write — the AUTHORITATIVE
// proof that the legacy bind hook ran through compat — and (2) calls device_add once
// (a trivial child device), which compat's device_add bridge (device.cc:Add ->
// AddChild) surfaces as a DFv2 node.

#include <lib/ddk/binding_driver.h>
#include <lib/ddk/device.h>
#include <lib/ddk/driver.h>
#include <zircon/syscalls.h>
#include <zircon/types.h>

namespace {

void Mark(const char* s, size_t n) { zx_debug_write(s, n); }
#define MARK(lit) Mark(lit, sizeof(lit) - 1)

// Trivial child device ops. The compat shim wraps the device_add'd child in a
// compat::Device; only the version is required, the hooks are optional.
zx_protocol_device_t kChildOps = {
    .version = DEVICE_OPS_VERSION,
};

zx_status_t LegacyBind(void* ctx, zx_device_t* parent) {
  // AUTHORITATIVE marker: the legacy bind hook ran THROUGH compat.
  MARK("CERISE-COMPAT-LEGACY-OK\n");

  // Add one trivial child device. compat::Device::Add bridges this to the DFv2
  // node (AddChild), proving device_add surfaced through the compat shim.
  device_add_args_t args = {};
  args.version = DEVICE_ADD_ARGS_VERSION;
  args.name = "cerise-compat-legacy-child";
  args.ops = &kChildOps;

  zx_device_t* child = nullptr;
  zx_status_t status = device_add(parent, &args, &child);
  if (status != ZX_OK) {
    MARK("CERISE-COMPAT-LEGACY-DEVICE-ADD-FAIL\n");
    return status;
  }
  MARK("CERISE-COMPAT-LEGACY-DEVICE-ADD-OK\n");
  return ZX_OK;
}

zx_driver_ops_t kLegacyOps = {
    .version = DRIVER_OPS_VERSION,
    .bind = LegacyBind,
};

}  // namespace

ZIRCON_DRIVER(cerise_compat_legacy, kLegacyOps, "cerise", "0.1");

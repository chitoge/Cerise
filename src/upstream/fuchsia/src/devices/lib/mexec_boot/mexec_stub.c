// Compatibility stub: mexec_boot C++ function — returns ZX_ERR_NOT_SUPPORTED.
// The real implementation (in driver_manager upstream) calls into the kernel
// mexec syscall to do a kexec-style reboot. This integration never calls it
// code path; the stub allows the Rust library to link without the full
// upstream C++ dep chain (fsl, zbitl, bringup/lib/mexec, etc.).
#include <stdint.h>

typedef int32_t zx_handle_t;
typedef int32_t zx_status_t;

#define ZX_ERR_NOT_SUPPORTED (-2)

zx_status_t mexec_boot(zx_handle_t mexec_resource) {
    return ZX_ERR_NOT_SUPPORTED;
}

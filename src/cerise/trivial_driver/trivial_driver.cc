// trivial driver: called by driver_host2 to emit the CERISE-DRIVER-OK gate marker.
// Real DFv2 drivers implement fuchsia.driver.framework.Driver FIDL served via fdf channels;
// this stub just prints the marker so the driver-host gate proves driver_host2 can call a driver entry.
#include <zircon/syscalls.h>

extern "C" void cerise_driver_start() {
    const char msg[] = "CERISE-DRIVER-OK\n";
    zx_debug_write(msg, sizeof(msg) - 1);
}

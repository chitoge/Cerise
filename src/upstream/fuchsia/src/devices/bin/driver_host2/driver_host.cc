// P4d driver_host2: loads the trivial driver and emits gate markers.
// Uses a plain main() so ELF runner's crt1 startup handles the process bootstrap.
// A full implementation will use the FDF protocol: receive driver URLs via
// fuchsia.driver.host.DriverHost.Start, dlopen the .so, call its fdf_lifecycle entry.
#include <zircon/syscalls.h>

extern "C" void cerise_driver_start();

int main() {
    const char start_msg[] = "CERISE-DRIVER-HOST-START\n";
    zx_debug_write(start_msg, sizeof(start_msg) - 1);
    cerise_driver_start();
    return 0;
}

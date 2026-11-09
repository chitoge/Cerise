// Cerise stub: satisfies the fdf:: driver-runtime symbols that every FIDL C++
// library's generated driver-transport bindings reference, for consumers that are
// plain (non-driver) executables and never actually call into them.
//
// WHY THIS EXISTS: build/fidl/fidl.bzl's fidl_cpp rule alwayslink's every generated
// FIDL C++ library, including its driver/*Messaging translation unit — the codegen
// always emits driver-transport wire/natural bindings referencing fdf:: symbols,
// regardless of whether the FIDL library declares any @transport("Driver") method.
// alwayslink forces that whole translation unit's object code into any final binary
// that depends on the library, even a plain zircon-transport-only executable that
// never references it — normal (non-alwayslink) linking would drop the unreferenced
// object file, but alwayslink is required for driver .so builds (dlopen'd, so the
// method bodies must be present in the .so's own exported symbol table) and the rule
// is shared by every consumer. See build/fidl/fidl.bzl's _fidl_cpp_impl comment.
//
// A linker flag alone (--unresolved-symbols=ignore-all) is NOT sufficient here:
// Cerise's ported musl dynamic linker performs EAGER (not lazy) PLT/GOT relocation
// at process load time, so an unresolved symbol crashes relocation even if the
// enclosing code path is never executed (confirmed empirically: netdev_probe failed
// with "Error relocating ...: fdf_channel_wait_async: symbol not found" despite the
// binary never calling any fdf:: API). Real (even if functionally inert) symbol
// definitions are required for such a binary to load at all.
//
// SAFE ONLY for genuinely driver-transport-inert consumers: this must not be linked
// into any component that legitimately uses fdf:: (drivers link the real
// driver_runtime instead). netdev_probe only performs plain zircon-transport wire
// calls (fuchsia.io/Directory.Open, fuchsia.device/Controller.ConnectToDeviceFidl,
// fuchsia.hardware.network/Device.GetInfo) — the driver-transport code these stubs
// satisfy is provably dead code for it.

#include <lib/fdf/channel.h>
#include <lib/fdf/channel_read.h>
#include <lib/fdf/dispatcher.h>
#include <lib/fdf/handle.h>
#include <lib/fdf/token.h>

extern "C" {

zx_status_t fdf_token_register(zx_handle_t token, fdf_dispatcher_t* dispatcher,
                                fdf_token_t* handler) {
  return ZX_ERR_NOT_SUPPORTED;
}

zx_status_t fdf_token_receive(zx_handle_t token, fdf_handle_t* handle) {
  return ZX_ERR_NOT_SUPPORTED;
}

zx_status_t fdf_token_transfer(zx_handle_t token, fdf_handle_t handle) {
  return ZX_ERR_NOT_SUPPORTED;
}

uint32_t fdf_dispatcher_get_options(const fdf_dispatcher_t* dispatcher) { return 0; }

zx_status_t fdf_channel_wait_async(fdf_dispatcher_t* dispatcher,
                                    fdf_channel_read_t* channel_read, uint32_t options) {
  return ZX_ERR_NOT_SUPPORTED;
}

zx_status_t fdf_channel_cancel_wait(fdf_handle_t handle) { return ZX_ERR_NOT_SUPPORTED; }

void fdf_handle_close(fdf_handle_t handle) {}

}  // extern "C"

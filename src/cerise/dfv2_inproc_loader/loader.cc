// Cerise DFv2 in-process driver LOADER (DFv2 runtime bring-up, Component 5).
//
// This is the C++ "missing half" of the real DFv2 fdf round-trip that runs
// IN-PROCESS inside the Rust driver_manager (driver_manager_rust_dfv2). The Rust
// side (src/.../driver_manager_rust/src/fdf_start.rs) owns the fdf runtime, the
// fdf Driver channel pair, and drives Driver.Start with a COMPLETE
// DriverStartArgs. This function performs ONLY the loader-specific steps proven
// by the C++ spike (//src/cerise/dfv2_loader_spike): dlopen the self-contained
// DFv2 driver .so, resolve __fuchsia_driver_registration__ (ABI in
// sdk/lib/driver/symbols/symbols.h), and call v1.initialize(server_handle) so the
// driver builds its DriverServer<T> bound to the CURRENT fdf dispatcher.
//
// CO-LOCATION (why in-process): fdf handles are PROCESS-LOCAL runtime handles, not
// zircon kernel handles, so the fdf Driver server end cannot cross to a separate
// driver_host process. The loader therefore runs in the SAME process that owns the
// fdf runtime (driver_manager_rust_dfv2). A true separate driver_host would need a
// cross-process fdf transport (deferred).
//
// THREADING: initialize() reads fdf_dispatcher_get_current_dispatcher() and binds
// the DriverServer to it, so this function MUST run on an fdf dispatcher thread.
// The Rust caller posts it onto the dedicated "driver" dispatcher (distinct from
// the "client" dispatcher that drives Driver.Start), mirroring the spike's
// two-dispatcher topology.
//
// LOADING: driver_manager_rust_dfv2 runs as a component under component_manager,
// so the ELF runner gives it a framework loader service serving its /pkg/lib. With
// LDSVC_KEEP=1 in its program.environ, musl retains that loader service past
// startup (dynlink.c gate), so a name-based dlopen("cerise_minimal_driver.so")
// resolves the staged driver from /pkg/lib at runtime.

#include <dlfcn.h>
#include <lib/driver/symbols/symbols.h>
#include <lib/fdf/handle.h>
#include <lib/fdf/types.h>
#include <zircon/errors.h>
#include <zircon/syscalls.h>
#include <zircon/types.h>

#include <new>

namespace {

void Marker(const char* s, size_t n) { zx_debug_write(s, n); }
#define MARK(lit) Marker(lit, sizeof(lit) - 1)

struct LoadedDriver {
  void* library;
  const DriverRegistration* registration;
  void* token;
};

}  // namespace

// Loads `so_path` and initializes the DFv2 driver on the CURRENT fdf dispatcher.
// `server_handle` is the raw fdf Driver SERVER-end handle (an fdf_handle_t, which
// is numerically a uint32_t) produced by the Rust caller's fdf Channel pair;
// ownership transfers to the driver's DriverServer via initialize().
// Returns ZX_OK on success.
extern "C" zx_status_t cerise_load_and_init_driver_with_token(const char* so_path,
                                                                fdf_handle_t server_handle,
                                                                void** out_driver) {
  if (out_driver == nullptr) {
    return ZX_ERR_INVALID_ARGS;
  }
  *out_driver = nullptr;

  void* handle = dlopen(so_path, RTLD_NOW | RTLD_GLOBAL);
  if (handle == nullptr) {
    MARK("CERISE-DFV2-DLOPEN-FAIL: ");
    const char* err = dlerror();
    if (err != nullptr) {
      Marker(err, __builtin_strlen(err));
    }
    Marker("\n", 1);
    fdf_handle_close(server_handle);
    return ZX_ERR_NOT_FOUND;
  }
  MARK("CERISE-DFV2-DLOPEN-OK\n");

  const DriverRegistration* registration = reinterpret_cast<const DriverRegistration*>(
      dlsym(handle, "__fuchsia_driver_registration__"));
  if (registration == nullptr) {
    MARK("CERISE-DFV2-DLSYM-FAIL\n");
    fdf_handle_close(server_handle);
    dlclose(handle);
    return ZX_ERR_NOT_FOUND;
  }
  MARK("CERISE-DFV2-REGISTRATION-FOUND\n");

  // Allocate the exact per-driver identity before initialize(): initialize() has
  // no failure return and its opaque token is allowed to be null. Once it has run,
  // the DSO must remain loaded until the driver's dispatchers have stopped.
  LoadedDriver* driver = new (std::nothrow) LoadedDriver{handle, registration, nullptr};
  if (driver == nullptr) {
    fdf_handle_close(server_handle);
    dlclose(handle);
    return ZX_ERR_NO_MEMORY;
  }
  driver->token = registration->v1.initialize(server_handle);
  MARK("CERISE-DFV2-INITIALIZE-CALLED\n");
  *out_driver = driver;
  return ZX_OK;
}

// Compatibility entry point for the original process-lifetime loader user. The
// returned registration is deliberately retained: that caller has no lifecycle
// protocol yet and its root driver lives until the process exits.
extern "C" zx_status_t cerise_load_and_init_driver(const char* so_path,
                                                     fdf_handle_t server_handle) {
  void* driver = nullptr;
  zx_status_t status =
      cerise_load_and_init_driver_with_token(so_path, server_handle, &driver);
  if (status != ZX_OK) {
    return status;
  }
  (void)driver;
  return ZX_OK;
}

// The caller must invoke this only after every dispatcher belonging to the
// driver, including its default dispatcher, has fully shut down. The opaque
// record binds the exact registration; multiple drivers in one host cannot
// overwrite each other's teardown identity.
extern "C" void cerise_destroy_driver(void* opaque_driver) {
  auto* driver = static_cast<LoadedDriver*>(opaque_driver);
  if (driver == nullptr) {
    return;
  }
  driver->registration->v1.destroy(driver->token);
  // Keep initialized DSOs resident for the process lifetime. Compat can load
  // legacy modules whose unresolved ABI symbols bind to this RTLD_GLOBAL DSO
  // without recording a DT_NEEDED edge, so dlclose here could invalidate code
  // still used by another colocated legacy driver.
  (void)driver->library;
  delete driver;
}

// driver-host Step 3 — the compat MODULE mechanism. Loads a LEGACY (DFv1 / ZIRCON_DRIVER)
// driver .so as an ADDITIONAL ELF module alongside the already-loaded compat.so, and
// returns the addresses of its `__zircon_driver_note__` / `__zircon_driver_rec__`
// symbols so the Rust caller can populate them into DriverStartArgs.symbols (where the
// compat shim reads them via fdf_internal::GetSymbol(symbols, module_name, name)).
//
// This is the loader half of compat.shard.cml's `modules` entry:
//   * MODULE: the legacy .so named by `program.compat` is dlopen'd here as a sibling
//     module of compat.so in the SAME driver_host process.
//   * loader_overrides (libdriver.so -> driver/compat.so): the legacy .so is built
//     --allow-shlib-undefined with no DT_NEEDED on libdriver.so, so its UND DFv1 ABI
//     symbols (device_add_from_driver, get_*_resource, ...) resolve against compat.so,
//     which cerise_load_and_init_driver() above dlopen'd RTLD_GLOBAL FIRST. RTLD_GLOBAL
//     symbol-scope ordering reproduces exactly what the loader_override achieves upstream.
//   * symbols (__zircon_driver_note__, __zircon_driver_rec__): dlsym'd here and returned.
//
// PRECONDITION: cerise_load_and_init_driver() (compat.so, RTLD_GLOBAL) MUST have run
// first so compat.so is in the global symbol scope. RTLD_NOW would otherwise fail to
// resolve the legacy .so's DFv1 ABI references.
extern "C" zx_status_t cerise_load_compat_module(const char* legacy_so_path,
                                                   uint64_t* out_note_addr,
                                                   uint64_t* out_rec_addr) {
  // DIAGNOSTIC: mark before dlopen so a hang inside it is distinguishable from
  // a hang before the FFI call.  The next marker (DLOPEN-OK or DLOPEN-FAIL) is
  // emitted by dlopen's return path below.
  MARK("CERISE-COMPAT-MODULE-DLOPEN-TRY\n");
  void* handle = dlopen(legacy_so_path, RTLD_NOW | RTLD_GLOBAL);
  if (handle == nullptr) {
    MARK("CERISE-COMPAT-MODULE-DLOPEN-FAIL: ");
    const char* err = dlerror();
    if (err != nullptr) {
      Marker(err, __builtin_strlen(err));
    }
    Marker("\n", 1);
    return ZX_ERR_NOT_FOUND;
  }
  MARK("CERISE-COMPAT-MODULE-DLOPEN-OK\n");

  void* note = dlsym(handle, "__zircon_driver_note__");
  void* rec = dlsym(handle, "__zircon_driver_rec__");
  if (note == nullptr || rec == nullptr) {
    MARK("CERISE-COMPAT-MODULE-DLSYM-FAIL\n");
    return ZX_ERR_NOT_FOUND;
  }
  *out_note_addr = reinterpret_cast<uint64_t>(note);
  *out_rec_addr = reinterpret_cast<uint64_t>(rec);
  MARK("CERISE-COMPAT-MODULE-OK\n");
  return ZX_OK;
}

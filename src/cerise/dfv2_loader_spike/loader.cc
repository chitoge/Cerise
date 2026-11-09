// Cerise DFv2 driver LOADER CORE (DFv2 runtime bring-up, Component 2).
//
// Proves the loader core end-to-end against a REAL DFv2 driver over the REAL fdf
// Driver transport: bring up the fdf runtime + a synchronized dispatcher (proven
// in Component 1), load the minimal driver .so, resolve __fuchsia_driver_registration__,
// call v1.initialize(server_handle) on the dispatcher thread (it builds a
// DriverServer<MinimalDriver> serving the Driver protocol), then act as the Driver
// client and call Start(DriverStartArgs) so the driver's Start() runs and prints
// CERISE-DFV2-DRIVER-OK. No stubbing of the driver, the transport, or the marker.
//
// Loading: this binary runs as a COMPONENT under component_manager, so the ELF
// runner gives it a framework loader service (backed by component_manager's VMEX)
// serving its package's /pkg/lib. With LDSVC_KEEP=1 in program.environ, musl
// retains that loader service past startup (dynlink.c gate), so a name-based
// dlopen("cerise_minimal_driver.so") resolves it from /pkg/lib at runtime.
// (A direct userboot.next process can't do this: no PA_RESOURCE for exec VMOs and
// musl closes the loader svc after startup — hence the component route.)

#include <dlfcn.h>
#include <fidl/fuchsia.component.runner/cpp/wire.h>
#include <fidl/fuchsia.driver.framework/cpp/driver/wire.h>
#include <fidl/fuchsia.io/cpp/wire.h>
#include <lib/async/cpp/task.h>
#include <lib/driver/symbols/symbols.h>
#include <lib/fdf/cpp/arena.h>
#include <lib/fdf/cpp/channel.h>
#include <lib/fdf/cpp/dispatcher.h>
#include <lib/fdf/cpp/env.h>
#include <lib/fdf/env.h>
#include <lib/sync/completion.h>
#include <zircon/syscalls.h>

namespace {

void Marker(const char* s, size_t n) { zx_debug_write(s, n); }
#define MARK(lit) Marker(lit, sizeof(lit) - 1)

}  // namespace

int main(int argc, char** argv) {
  MARK("CERISE-DFV2-LOADER-START\n");

  if (fdf_env_start(0) != ZX_OK) {
    MARK("CERISE-DFV2-ENV-START-FAIL\n");
    return 1;
  }

  // TWO dispatchers so the loader's Driver CLIENT and the driver's DriverServer
  // run on SEPARATE threads. With a single dispatcher the async two-way Start was
  // never processed server-side (no DRIVER-CTOR marker) — the real topology
  // (driver_manager and the driver host on different dispatchers) avoids that.
  int owner_driver = 0, owner_client = 0;
  sync_completion_t driver_shutdown, client_shutdown;
  auto driver_disp = fdf_env::DispatcherBuilder::CreateSynchronizedWithOwner(
      &owner_driver, fdf::SynchronizedDispatcher::Options::kAllowSyncCalls, "cerise-dfv2-driver",
      [&driver_shutdown](fdf_dispatcher_t*) { sync_completion_signal(&driver_shutdown); });
  if (driver_disp.is_error()) {
    MARK("CERISE-DFV2-DISPATCHER-FAIL\n");
    return 1;
  }
  auto client_disp = fdf_env::DispatcherBuilder::CreateSynchronizedWithOwner(
      &owner_client, fdf::SynchronizedDispatcher::Options::kAllowSyncCalls, "cerise-dfv2-client",
      [&client_shutdown](fdf_dispatcher_t*) { sync_completion_signal(&client_shutdown); });
  if (client_disp.is_error()) {
    MARK("CERISE-DFV2-DISPATCHER-FAIL\n");
    return 1;
  }

  // The Driver protocol fdf channel pair: server end goes to the loaded driver,
  // client end is used by us (the "driver_manager" role) to call Start.
  auto channels = fdf::ChannelPair::Create(0);
  if (channels.is_error()) {
    MARK("CERISE-DFV2-CHANNELPAIR-FAIL\n");
    return 1;
  }

  // 1. Load + initialize the driver on the DRIVER dispatcher (initialize() reads
  //    fdf_dispatcher_get_current_dispatcher(), so it must run there; the
  //    DriverServer<MinimalDriver> is bound to the driver dispatcher).
  sync_completion_t init_done;
  bool init_ok = false;
  const DriverRegistration* reg = nullptr;
  void* token = nullptr;
  zx_status_t post = async::PostTask(
      driver_disp->async_dispatcher(),
      [&]() mutable {
        // Name-based dlopen: resolved by the framework loader service from /pkg/lib.
        void* handle = dlopen("cerise_minimal_driver.so", RTLD_NOW | RTLD_GLOBAL);
        if (handle == nullptr) {
          MARK("CERISE-DFV2-DLOPEN-FAIL: ");
          const char* err = dlerror();
          if (err != nullptr) {
            Marker(err, __builtin_strlen(err));
          }
          Marker("\n", 1);
          sync_completion_signal(&init_done);
          return;
        }
        MARK("CERISE-DFV2-DLOPEN-OK\n");
        reg = reinterpret_cast<const DriverRegistration*>(
            dlsym(handle, "__fuchsia_driver_registration__"));
        if (reg == nullptr) {
          MARK("CERISE-DFV2-DLSYM-FAIL\n");
          sync_completion_signal(&init_done);
          return;
        }
        MARK("CERISE-DFV2-REGISTRATION-FOUND\n");
        token = reg->v1.initialize(channels->end0.release());
        MARK("CERISE-DFV2-INITIALIZE-CALLED\n");
        init_ok = true;
        sync_completion_signal(&init_done);
      });
  if (post != ZX_OK) {
    MARK("CERISE-DFV2-POSTTASK-FAIL\n");
    return 1;
  }
  sync_completion_wait(&init_done, ZX_TIME_INFINITE);

  // 2. Drive Driver.Start from the CLIENT dispatcher (a different thread); the
  //    driver dispatcher is then free to process the server side -> DriverBase
  //    ctor -> MinimalDriver::Start -> marker. We block on `done`, so the client +
  //    arena + outgoing channel (this scope) outlive the async response.
  sync_completion_t done;
  bool ok = false;
  if (init_ok) {
    fdf::Arena arena('LDR0');
    zx::channel out_client, out_server;
    zx::channel::create(0, &out_client, &out_server);
    std::optional<fdf::WireClient<fuchsia_driver_framework::Driver>> driver_client;
    zx_status_t post2 = async::PostTask(
        client_disp->async_dispatcher(),
        [&]() mutable {
          // Minimal-but-valid DriverStartArgs: DriverBase requires incoming (an
          // empty namespace is valid) + outgoing_dir; node is only for AddChild.
          fidl::VectorView<fuchsia_component_runner::wire::ComponentNamespaceEntry> incoming(arena,
                                                                                            0);
          auto args =
              fuchsia_driver_framework::wire::DriverStartArgs::Builder(arena)
                  .incoming(incoming)
                  .outgoing_dir(fidl::ServerEnd<fuchsia_io::Directory>(std::move(out_server)))
                  .Build();
          driver_client.emplace(
              fdf::ClientEnd<fuchsia_driver_framework::Driver>(std::move(channels->end1)),
              client_disp->get());
          MARK("CERISE-DFV2-START-SENDING\n");
          (*driver_client)
              .buffer(arena)
              ->Start(args)
              .ThenExactlyOnce(
                  [&done, &ok](
                      fdf::WireUnownedResult<fuchsia_driver_framework::Driver::Start>& result) {
                    if (result.ok()) {
                      MARK("CERISE-DFV2-START-REPLIED\n");
                      ok = true;
                    } else {
                      MARK("CERISE-DFV2-START-FAIL\n");
                    }
                    sync_completion_signal(&done);
                  });
        });
    if (post2 != ZX_OK) {
      MARK("CERISE-DFV2-POSTTASK-FAIL\n");
    } else {
      sync_completion_wait(&done, ZX_TIME_INFINITE);
    }
  }

  // 3. destroy on the DRIVER dispatcher (the DriverServer is bound there).
  if (token != nullptr && reg != nullptr) {
    sync_completion_t destroy_done;
    async::PostTask(driver_disp->async_dispatcher(), [&]() {
      reg->v1.destroy(token);
      sync_completion_signal(&destroy_done);
    });
    sync_completion_wait(&destroy_done, ZX_TIME_INFINITE);
  }

  client_disp->ShutdownAsync();
  sync_completion_wait(&client_shutdown, ZX_TIME_INFINITE);
  driver_disp->ShutdownAsync();
  sync_completion_wait(&driver_shutdown, ZX_TIME_INFINITE);

  MARK(ok ? "CERISE-DFV2-LOADER-DONE\n" : "CERISE-DFV2-LOADER-INCOMPLETE\n");
  return ok ? 0 : 1;
}

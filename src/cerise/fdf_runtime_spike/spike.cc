// Cerise FDF runtime bring-up spike (DFv2 runtime bring-up, Component 1).
//
// Proves the REAL Fuchsia Driver Framework runtime (libfdf / driver_runtime)
// actually runs in a Cerise process: start the runtime, create a synchronized
// fdf dispatcher, post a task onto it, and confirm the task RAN on an fdf
// dispatcher thread by emitting a marker. This is the foundation the C++ driver
// loader and driver_manager's real fdf channels depend on.
//
// Uses the real upstream APIs (fdf_env_start, fdf_env::DispatcherBuilder); no
// stubbing. If the runtime can't come up, the failure marker / absence of
// CERISE-FDF-RUNTIME-OK is the real finding.

#include <lib/async/cpp/task.h>
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
  MARK("CERISE-FDF-SPIKE-START\n");

  zx_status_t status = fdf_env_start(0);
  if (status != ZX_OK) {
    MARK("CERISE-FDF-ENV-START-FAIL\n");
    return 1;
  }
  MARK("CERISE-FDF-ENV-STARTED\n");

  // Opaque, unique driver-owner token (the runtime only uses its address).
  int driver_owner = 0;

  sync_completion_t dispatcher_shutdown;
  auto dispatcher = fdf_env::DispatcherBuilder::CreateSynchronizedWithOwner(
      &driver_owner, fdf::SynchronizedDispatcher::Options::kAllowSyncCalls, "cerise-fdf-spike",
      [&dispatcher_shutdown](fdf_dispatcher_t*) { sync_completion_signal(&dispatcher_shutdown); });
  if (dispatcher.is_error()) {
    MARK("CERISE-FDF-DISPATCHER-CREATE-FAIL\n");
    return 1;
  }
  MARK("CERISE-FDF-DISPATCHER-CREATED\n");

  // Post a task onto the fdf dispatcher; it runs on a runtime-owned thread.
  sync_completion_t task_ran;
  zx_status_t post = async::PostTask(dispatcher->async_dispatcher(), [&task_ran]() {
    MARK("CERISE-FDF-RUNTIME-OK\n");
    sync_completion_signal(&task_ran);
  });
  if (post != ZX_OK) {
    MARK("CERISE-FDF-POSTTASK-FAIL\n");
    return 1;
  }

  // Wait for the task to actually run (proves the dispatcher thread is live).
  sync_completion_wait(&task_ran, ZX_TIME_INFINITE);

  // Clean shutdown of the dispatcher (exercises the shutdown observer path).
  dispatcher->ShutdownAsync();
  sync_completion_wait(&dispatcher_shutdown, ZX_TIME_INFINITE);

  MARK("CERISE-FDF-SPIKE-DONE\n");
  return 0;
}

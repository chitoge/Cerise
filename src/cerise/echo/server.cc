// FIDL round-trip gate: FIDL Echo demo.
// C++ async-loop server + synchronous client in the same process.
// Demonstrates the full C++ FIDL wire protocol + async-loop stack.
// Prints "CERISE-FIDL-ROUNDTRIP-OK" on success.

#include <fidl/cerise.echo/cpp/wire.h>
#include <lib/async-loop/cpp/loop.h>
#include <lib/async-loop/default.h>
#include <lib/fidl/cpp/wire/channel.h>

#include <zircon/syscalls.h>

namespace {

class EchoServerImpl : public fidl::WireServer<cerise_echo::Echo> {
 public:
  void EchoValue(EchoValueRequestView request,
                 EchoValueCompleter::Sync& completer) override {
    completer.Reply(request->value);
  }
};

}  // namespace

int main() {
  // Create channel endpoints.
  auto endpoints = fidl::Endpoints<cerise_echo::Echo>::Create();

  // Start async-loop server thread.
  async::Loop loop(&kAsyncLoopConfigNoAttachToCurrentThread);
  fidl::BindServer(loop.dispatcher(),
                   std::move(endpoints.server),
                   std::make_unique<EchoServerImpl>());
  loop.StartThread("echo-server");

  // Synchronous client call.
  fidl::WireSyncClient<cerise_echo::Echo> client(std::move(endpoints.client));
  auto result = client->EchoValue(42u);
  if (!result.ok()) {
    zx_debug_write("CERISE-FIDL-ROUNDTRIP-FAIL-STATUS\n", 36);
    return 1;
  }
  if (result->response != 42u) {
    zx_debug_write("CERISE-FIDL-ROUNDTRIP-FAIL-VALUE\n", 35);
    return 1;
  }

  zx_debug_write("CERISE-FIDL-ROUNDTRIP-OK\n", 27);
  loop.Shutdown();
  return 0;
}

// Cerise minimal native DFv2 driver — the de-risk target for the Rust
// driver_host loader (DFv2 runtime bring-up). It exercises the full DFv2 load
// path (dlopen -> __fuchsia_driver_registration__ -> DriverServer<T>::initialize
// -> construct on the driver dispatcher -> Start()) with the smallest possible
// surface: Start() just logs a marker and returns ok (no AddChild, no node use).
#include <fidl/cerise.echo/cpp/fidl.h>
#include <lib/driver/component/cpp/driver_base.h>
#include <lib/driver/component/cpp/driver_export.h>
#include <lib/driver/component/cpp/internal/start_args.h>
#include <lib/driver/logging/cpp/logger.h>
#include <zircon/syscalls.h>

namespace minimal_driver {

namespace {

struct ParsedStartArgs {
  fdf::DriverStartArgs start_args;
  bool fail_start;
};

ParsedStartArgs ParseStartArgs(fdf::DriverStartArgs start_args) {
  bool fail_start = false;
  zx::result<std::string> value =
      fdf_internal::ProgramValue(start_args.program(), "cerise.test.fail_start");
  if (value.is_ok()) {
    fail_start = *value == "true";
  }
  return {.start_args = std::move(start_args), .fail_start = fail_start};
}

}  // namespace

class MinimalDriver : public fdf::DriverBase, public fidl::Server<cerise_echo::Echo> {
 public:
  MinimalDriver(fdf::DriverStartArgs start_args,
                fdf::UnownedSynchronizedDispatcher driver_dispatcher)
      : MinimalDriver(ParseStartArgs(std::move(start_args)), std::move(driver_dispatcher)) {}

  zx::result<> Start() override {
    if (fail_start_) {
      static constexpr char kFail[] = "CERISE-DFV2-DRIVER-START-FAIL status=-25\n";
      zx_debug_write(kFail, sizeof(kFail) - 1);
      return zx::error(ZX_ERR_NOT_FOUND);
    }
    zx::result<> add = outgoing()->component().AddUnmanagedProtocol<cerise_echo::Echo>(
        bindings_.CreateHandler(this, dispatcher(), fidl::kIgnoreBindingClosure));
    if (add.is_error()) {
      return add.take_error();
    }
    // Emit via zx_debug_write so the marker reaches serial even when no LogSink
    // is wired (in the loader de-risk there's no component_manager; the DriverBase
    // logger degrades to NoOp). Also log via FDF_LOG for the real-runtime path.
    const char kMark[] = "CERISE-DFV2-DRIVER-OK\n";
    zx_debug_write(kMark, sizeof(kMark) - 1);
    FDF_LOG(INFO, "CERISE-DFV2-DRIVER-OK");
    return zx::ok();
  }

  void EchoValue(EchoValueRequest& request, EchoValueCompleter::Sync& completer) override {
    completer.Reply(fidl::Response<cerise_echo::Echo::EchoValue>(request.value()));
  }

  void PrepareStop(fdf::PrepareStopCompleter completer) override {
    static constexpr char kMark[] = "CERISE-DFV2-DRIVER-STOP\n";
    zx_debug_write(kMark, sizeof(kMark) - 1);
    completer(zx::ok());
  }

 private:
  MinimalDriver(ParsedStartArgs parsed,
                fdf::UnownedSynchronizedDispatcher driver_dispatcher)
      : fdf::DriverBase("cerise_minimal_driver", std::move(parsed.start_args),
                        std::move(driver_dispatcher)),
        fail_start_(parsed.fail_start) {
    // Diagnostic: ctor body runs after the DriverBase base-ctor — proves the base
    // ctor (logger/namespace/outgoing setup) completed and the driver is being
    // constructed (distinguishes a base-ctor hang from a Start-dispatch issue).
    const char kCtor[] = "CERISE-DFV2-DRIVER-CTOR\n";
    zx_debug_write(kCtor, sizeof(kCtor) - 1);
  }
  bool fail_start_;
  fidl::ServerBindingGroup<cerise_echo::Echo> bindings_;
};

}  // namespace minimal_driver

FUCHSIA_DRIVER_EXPORT(minimal_driver::MinimalDriver);

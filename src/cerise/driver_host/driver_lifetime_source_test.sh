#!/bin/sh
set -eu

rust_source="src/cerise/driver_host/src/dfv2_main.rs"
loader_source="src/cerise/dfv2_inproc_loader/loader.cc"
harness_source="src/cerise/dh_xproc_harness/src/main.rs"
driver_source="src/cerise/minimal_driver/minimal_driver.cc"
qemu_gate="validation/run-qemu.sh"
compat_source="src/upstream/fuchsia/src/devices/misc/drivers/compat/device.cc"
composite_source="src/upstream/fuchsia/src/devices/bin/driver_manager_rust/composite/src/spec.rs"

require() {
  pattern="$1"
  file="$2"
  message="$3"
  if ! grep -Eq "$pattern" "$file"; then
    echo "FAIL: $message" >&2
    exit 1
  fi
}

reject() {
  pattern="$1"
  file="$2"
  message="$3"
  if grep -Eq "$pattern" "$file"; then
    echo "FAIL: $message" >&2
    exit 1
  fi
}

require 'struct StartedDriver' "$rust_source" \
  'the process-local Driver client has no explicit lifetime owner'
require 'Result<StartedDriver, Error>' "$rust_source" \
  'DriverHost.Start does not return the retained driver lifetime'
require 'fdh::DriverRequest::Stop' "$rust_source" \
  'the zircon Driver lifecycle does not forward Stop'
reject 'mem::forget\((driver_disp|client_disp)\)' "$rust_source" \
  'driver dispatchers are leaked instead of owned by the driver lifetime'
require 'read_bytes\(CurrentDispatcher\)' "$rust_source" \
  'Driver Start/Stop does not use dispatcher-native channel reads'
reject 'try_read_bytes|thread::sleep' "$rust_source" \
  'Driver Start/Stop regressed to sleep polling'
reject 'Ok\(Some\(_reply\)\) => Ok\(true\)' "$rust_source" \
  'Driver.Start still treats every flexible reply, including an application error, as success'
require 'FlexibleResultType<fidl::encoding::EmptyStruct, i32>' "$rust_source" \
  'Driver.Start does not decode the flexible result payload'
require 'FlexibleResult::DomainErr' "$rust_source" \
  'Driver.Start does not preserve the driver application error status'
require 'FlexibleResult::FrameworkErr' "$rust_source" \
  'Driver.Start does not handle a flexible-method framework error'
require 'shutdown_driver_dispatchers\(driver_owner\)' "$rust_source" \
  'driver-owned dispatchers are not fully shut down before destroy'
require 'CERISE-DH-XPROC-POST-REPLY-DRIVER-DISPATCHER' "$rust_source" \
  'Driver.Start has no post-reply dispatcher liveness sentinel'
require 'identity\._driver_dispatcher\.spawn' "$rust_source" \
  'the post-reply liveness sentinel is not queued on the driver owner dispatcher'
require 'fn exit_after_driver_start_timeout\(\) -> !' "$rust_source" \
  'a timed-out Driver.Start does not fail-stop the isolated driver-host process'
require 'std::process::exit\(' "$rust_source" \
  'the Driver.Start timeout path can still block on in-process cleanup'
require 'CERISE-DH-XPROC-FDF-TIMEOUT-EXIT' "$rust_source" \
  'the bounded process-isolation timeout exit is not observable'
reject 'tearing down timed-out Driver\.Start' "$rust_source" \
  'Driver.Start timeout still waits synchronously behind the hung driver dispatcher'

require 'CERISE-COMPAT-ADDCHILD-SUBMIT' "$compat_source" \
  'the filtered compat AddChild submission marker is absent'
require 'CERISE-COMPAT-ADDCHILD-CALLBACK.*outcome=' "$compat_source" \
  'the filtered compat AddChild callback outcome marker is absent'
for topology in 'BIND_PCI_TOPO_PACK\(0, 2, 0\)' \
                'BIND_PCI_TOPO_PACK\(0, 0x17, 0\)' \
                'BIND_PCI_TOPO_PACK\(0, 0x1f, 6\)'; do
  require "$topology" "$compat_source" \
    'the compat diagnostic filter lost a required PCI topology'
done
require 'BusType::kPci' "$compat_source" \
  'the compat diagnostic no longer identifies PCI nodes'
require 'BusType::kAcpi' "$compat_source" \
  'the compat diagnostic no longer identifies ACPI companion nodes'

require 'matches!\(self\.name\.as_str\(\), "00_02_0" \| "00_17_0" \| "00_1f_6"\)' \
  "$composite_source" 'the composite diagnostic filter is not exact'
for outcome in wait complete already error; do
  require "CERISE-COMPOSITE-BIND-PARENT outcome=${outcome}" "$composite_source" \
    "the composite parent diagnostic lost outcome=${outcome}"
done
require 'filled=\{\} total=\{\}' "$composite_source" \
  'the composite parent diagnostic lost filled/total state'

if grep -E 'CERISE-(COMPAT-ADDCHILD|COMPOSITE-BIND-PARENT)' \
    "$compat_source" "$composite_source" | \
    grep -Eiq '(%p|raw.pointer|address=|handle=|as_ptr|reinterpret_cast)'; then
  echo 'FAIL: a diagnostic marker exposes a raw pointer or handle' >&2
  exit 1
fi

require 'cerise_load_and_init_driver_with_token' "$loader_source" \
  'the loader cannot return the exact registration token for a driver'
require 'cerise_destroy_driver' "$loader_source" \
  'the loader cannot destroy the exact registration token after Stop'
reject '(^|[^[:alnum:]_])g_token([^[:alnum:]_]|$)' "$loader_source" \
  'the loader still overwrites a process-global registration token'
reject 'token == nullptr|dlclose\(driver->library\)' "$loader_source" \
  'the loader rejects valid null tokens or unloads an initialized driver DSO'

require 'CERISE-DH-XPROC-HARNESS-SERVICE-OK' "$harness_source" \
  'the cross-process harness does not prove post-Start service reachability'
require 'CERISE-DH-XPROC-HARNESS-STOP-OK' "$harness_source" \
  'the cross-process harness does not require clean Stop completion'
require 'CERISE-DH-XPROC-HARNESS-APP-ERROR-OK' "$harness_source" \
  'the cross-process harness does not require exact Driver.Start application-error propagation'
require 'CERISE-DH-XPROC-HARNESS-SIBLING-OK' "$harness_source" \
  'the cross-process harness does not prove a sibling Start continues after an application error'
require 'CERISE-DFV2-DRIVER-START-FAIL' "$driver_source" \
  'the behavioral driver has no observable failing Start path'
require 'CERISE-DFV2-DRIVER-STOP' "$driver_source" \
  'the behavioral driver has no observable Stop hook'
require 'CERISE-DH-XPROC-HARNESS-SERVICE-OK' "$qemu_gate" \
  'the QEMU gate does not require post-Start service reachability'
require 'CERISE-DH-XPROC-HARNESS-STOP-OK' "$qemu_gate" \
  'the QEMU gate does not require lifecycle teardown'

echo 'driver lifetime ownership source gate: PASS'

// Network-device client gate: netdev_probe — proves the devfs CLIENT path AND the network-device
// session/FIFO dataplane end-to-end.
//
// network-device's client-facing protocol (fuchsia.hardware.network/Device) is only
// reachable through devfs: network_device.cc calls AddOwnedChild with
// DevfsAddArgs{class_name: "network", connector_supports: kController}, publishing a
// node under /dev/class/network/<instance>. This component is a plain (non-driver)
// CFv2 ELF component that:
//   1. Opens its incoming "/dev" directory (routed from driver_manager_rust's outgoing
//      dir, which already serves devfs — see driver_manager_rust/src/main.rs's
//      `fs.add_remote("dev", driver_runner.devfs.as_ref().serve())`).
//   2. Enumerates "/dev/class/network" to discover the instance name. It is NOT "000":
//      driver_manager_rust's devfs (devfs/src/lib.rs Devfs::make_instance_name) only
//      hands out sequential "{:03}" names to classes listed in
//      CLASSES_THAT_ASSUME_ORDERING (class_names.rs — "block", "adc", "backlight",
//      etc). "network" is not in that list, so it gets a random u32 printed as
//      decimal — confirmed by dumping devfs's actual directory contents. A real
//      client must always enumerate, never hardcode the instance.
//   3. Opens "class/network/<instance>/device_controller" to get a
//      fuchsia.device/Controller. The node's own path (empty remainder) is NOT the
//      Controller: DevnodeVnode::open (devfs/src/lib.rs) routes an empty-path open
//      requesting PROTOCOL_SERVICE to ConnectorMsg::Protocol, which network-device
//      never wires (it only registers connector_supports=CONTROLLER, no explicit
//      protocol connector) — that silently drops the server end, which is what
//      produced the ZX_ERR_PEER_CLOSED this file was chasing. The Controller is
//      reached only via the named "device_controller" child entry.
//   4. Calls Controller.ConnectToDeviceFidl to get the underlying
//      fuchsia.hardware.network/Device channel.
//   5. Calls Device.GetInfo() — a real two-way FIDL call — and on success emits
//      CERISE-DEVFS-CLIENT-OK.
//
// proves a REAL frame moves through the dataplane —
// the same OpenSession/FIFO/VMO mechanism a future e1000 driver will also depend on,
// since it's generic to every network-device client, not specific to virtio-net:
//   6. Device.GetPortWatcher + PortWatcher.Watch() to discover the device's port id
//      (there is no "get the default port" call — enumeration is the only way).
//   7. Device.GetInfo() again (base_info) to size buffers correctly: rx/tx depth,
//      minimum buffer lengths, required head/tail room, alignment.
//   8. Create a descriptors VMO (one buffer_descriptor_t per index — the real
//      upstream struct from buffer_descriptor.h, already vendored for the network-device work) and a
//      data VMO (backing storage for actual frame bytes), then Device.OpenSession
//      with that VMO pair.
//   9. Session.Attach to the discovered port for Ethernet rx frames.
//  10. Lend empty rx descriptors on the rx FIFO; write one crafted broadcast ARP
//      frame (real, semantically valid Ethernet content) into a tx descriptor and
//      submit it on the tx FIFO.
//  11. Block on tx FIFO completion (ZX_FIFO_READABLE) — this is the real go/no-go:
//      the descriptor only round-trips through network-device -> virtio-net -> the
//      actual virtio ring -> QEMU's backend if the whole FIFO/VMO dataplane works.
//      Check the completed descriptor's return_flags for TX_RET_ERROR. Emits
//      CERISE-NETDEV-FRAME-OK on success.
//  12. Briefly (non-gating) poll the rx FIFO too: QEMU's "-netdev user" (SLIRP)
//      backend answers ARP for its own gateway, so a reply may come back — but
//      whether it does depends on MAC-filtering behavior this file doesn't control,
//      so RX is logged as a bonus (CERISE-NETDEV-RX-OK) and never gates success.
//
// Scope: stops after one real tx completion (+ opportunistic rx). Multi-frame
// steady-state exchange, session teardown, and error-path recovery are explicitly
// out of scope for this probe.
//
// fuchsia.io/Directory.Open at API level 30: directory.fidl defines THREE Open
// variants gated by @available. At level 30 (this repo's default), the active one is
// `@available(added=27, replaced=31) strict Open(resource struct { path Path; flags
// Flags; options Options; object zx.Handle:CHANNEL; });` (wire selector
// "fuchsia.io/Directory.Open3", but the FIDL/C++ method name at this level is `Open`).
// `Open` here is one-way (fire-and-forget; any failure to resolve `path` surfaces as
// an epitaph on the handed-back channel, not as a synchronous error from this call),
// which is why the real go/no-go check in this file is a two-way call at the end of
// each step, not the intermediate Opens.
//
// Device-discovery retry loop: netdev_probe is an Eager child of root, started in
// parallel with every other eager child (component_manager's
// start_eager_children_recursive uses join_all — no dependency-graph ordering is
// enforced for eager starts). network-device isn't actually bound (AddOwnedChild
// publishing its devfs node) until the full PCI/ACPI/composite-bind chain completes:
// driver-index serving -> platform-bus -> ACPI -> pciroot -> bus-pci scan -> composite
// spec match -> virtio-net bind -> network-device bind. Measured on a real boot:
// netdev_probe's first attempt starts around t=105-128s, but network-device doesn't
// bind until t=193s+ — a ~65-90s gap. A channel that's seen ZX_ERR_PEER_CLOSED is
// permanently dead, so retrying the whole enumerate/open/connect/GetInfo sequence
// from scratch (not just the last call) each attempt is required. runs once,
// The data-plane check runs once after discovery succeeds, since the device is then
// known to be bound and responsive.

#include <fidl/fuchsia.device/cpp/wire.h>
#include <fidl/fuchsia.hardware.network/cpp/wire.h>
#include <fidl/fuchsia.io/cpp/wire.h>
#include <lib/component/incoming/cpp/directory.h>
#include <lib/fidl/cpp/wire/channel.h>
#include <lib/syslog/cpp/log_settings.h>
#include <lib/syslog/cpp/macros.h>

#include <zircon/syscalls.h>
#include <zircon/time.h>

#include <cstdio>
#include <cstring>

#include "src/connectivity/lib/network-device/buffer_descriptor/buffer_descriptor.h"

namespace {

// Raw serial write, reserved for the CERISE-* boot-gate markers the validation boot
// tests grep for. Operational/diagnostic output goes through FX_LOGS -> LogSink.
void Emit(const char* msg, size_t len) { zx_debug_write(msg, len); }

// TxFlags.TX_RET_ERROR (frames.fidl) — always set alongside a more specific
// TX_RET_* bit when the device failed to send a frame.
constexpr uint32_t kTxRetError = 0x80000000u;

// Finds the first non-"." entry under an absolute namespace directory path and copies
// its name into `out` (NUL-terminated). Returns ZX_OK on success.
zx_status_t FindFirstInstance(const char* dir_path, char* out, size_t out_len) {
  zx::result<fidl::ClientEnd<fuchsia_io::Directory>> dir = component::OpenDirectory(dir_path);
  if (dir.is_error()) {
    return dir.status_value();
  }
  fidl::WireSyncClient client{std::move(dir.value())};

  fidl::WireResult result = client->ReadDirents(4096);
  if (!result.ok()) {
    return result.status();
  }
  if (result->s != ZX_OK) {
    return result->s;
  }
  const auto& dirents = result->dirents;
  size_t i = 0;
  while (i + 10 <= dirents.size()) {
    uint8_t name_len = dirents[i + 8];
    size_t entry_end = i + 10 + name_len;
    if (entry_end > dirents.size()) break;
    if (!(name_len == 1 && dirents[i + 10] == '.')) {
      size_t copy_len = name_len < out_len - 1 ? name_len : out_len - 1;
      memcpy(out, &dirents[i + 10], copy_len);
      out[copy_len] = '\0';
      return ZX_OK;
    }
    i = entry_end;
  }
  return ZX_ERR_NOT_FOUND;
}

// One attempt at the full enumerate -> open -> connect -> GetInfo sequence. On
// success, `*out_device` receives the connected Device client end (moved out so
// the data-plane check can reuse the connection instead of rediscovering it). Returns the
// terminal zx_status_t: ZX_OK on success, or the failing step's status otherwise.
// `stage` names the step that failed for diagnostics.
zx_status_t TryOnce(const char** stage,
                     fidl::ClientEnd<fuchsia_hardware_network::Device>* out_device) {
  *stage = "OPEN-DEV";
  zx::result<fidl::ClientEnd<fuchsia_io::Directory>> dev_dir = component::OpenDirectory("/dev");
  if (dev_dir.is_error()) {
    return dev_dir.status_value();
  }

  *stage = "FIND-INSTANCE";
  char instance[32];
  zx_status_t find_status = FindFirstInstance("/dev/class/network", instance, sizeof(instance));
  if (find_status != ZX_OK) {
    return find_status;
  }

  // devfs models each class node (e.g. "class/network/<instance>") as a
  // directory-like vnode with THREE special named children: "device_controller",
  // "device_protocol", and "device_topology" (fuchsia.device.fs names.fidl). Opening
  // the node's own path (empty remainder) with PROTOCOL_SERVICE routes to
  // ConnectorMsg::Protocol instead (DevnodeVnode::open in devfs/src/lib.rs) —
  // network-device only registered connector_supports=CONTROLLER (no explicit
  // protocol connector), so that message is silently dropped and the server end
  // closes with no reply. The Controller is reached by opening the named child
  // directly.
  *stage = "OPEN-NODE";
  char node_path[64];
  snprintf(node_path, sizeof(node_path), "class/network/%s/device_controller", instance);
  auto controller_endpoints = fidl::Endpoints<fuchsia_device::Controller>::Create();
  {
    fidl::OneWayStatus status =
        fidl::WireCall(dev_dir.value())
            ->Open(fidl::StringView::FromExternal(node_path),
                   fuchsia_io::wire::Flags::kProtocolService, {},
                   controller_endpoints.server.TakeChannel());
    if (!status.ok()) {
      return status.status();
    }
  }

  // GetTopologicalPath is a real two-way call on Controller — used as the go/no-go
  // check that the Controller channel actually got served.
  *stage = "TOPO-PATH";
  fidl::WireSyncClient controller{std::move(controller_endpoints.client)};
  fidl::WireResult topo_result = controller->GetTopologicalPath();
  if (!topo_result.ok()) {
    return topo_result.status();
  }

  *stage = "CONNECT-DEVICE";
  auto device_endpoints = fidl::Endpoints<fuchsia_hardware_network::Device>::Create();
  {
    fidl::OneWayStatus status =
        controller->ConnectToDeviceFidl(device_endpoints.server.TakeChannel());
    if (!status.ok()) {
      return status.status();
    }
  }

  *stage = "GETINFO";
  fidl::WireSyncClient device{std::move(device_endpoints.client)};
  fidl::WireResult result = device->GetInfo();
  if (!result.ok()) {
    return result.status();
  }

  *out_device = device.TakeClientEnd();
  return ZX_OK;
}

// OpenSession + FIFO + one real tx completion (+ opportunistic rx). Returns
// ZX_OK on a verified tx completion with no error flag. `stage` names the step that
// failed for diagnostics.
zx_status_t RunSessionAndFrame(fidl::ClientEnd<fuchsia_hardware_network::Device> device_client,
                                const char** stage) {
  fidl::WireSyncClient device{std::move(device_client)};

  // Discover the device's port. There is no "get the default port" call — a
  // PortWatcher is the only enumeration mechanism (device.fidl GetPortWatcher).
  *stage = "GET-PORT-WATCHER";
  auto watcher_endpoints = fidl::Endpoints<fuchsia_hardware_network::PortWatcher>::Create();
  {
    fidl::OneWayStatus status = device->GetPortWatcher(std::move(watcher_endpoints.server));
    if (!status.ok()) {
      return status.status();
    }
  }
  fidl::WireSyncClient watcher{std::move(watcher_endpoints.client)};

  *stage = "WATCH-PORT";
  fuchsia_hardware_network::wire::PortId port_id{};
  bool found_port = false;
  // The first N calls return `existing` (one per pre-existing port), then one
  // `idle` marks the end. Take the first existing port; bail after a bounded
  // number of calls rather than looping forever if something is wrong.
  for (int i = 0; i < 8 && !found_port; ++i) {
    fidl::WireResult watch_result = watcher->Watch();
    if (!watch_result.ok()) {
      return watch_result.status();
    }
    const auto& event = watch_result->event;
    if (event.is_existing()) {
      port_id = event.existing();
      found_port = true;
    } else if (event.is_idle()) {
      break;
    }
  }
  if (!found_port) {
    return ZX_ERR_NOT_FOUND;
  }

  // GetInfo again (this connection's first GetInfo, in TryOnce, already proved the
  // channel works) to read base_info: buffer sizing depends on the real device
  // limits, not assumptions.
  *stage = "GETINFO2";
  fidl::WireResult info_result = device->GetInfo();
  if (!info_result.ok()) {
    return info_result.status();
  }
  const auto& device_info = info_result->info;
  if (!device_info.has_min_descriptor_length() || !device_info.has_descriptor_version() ||
      !device_info.has_base_info()) {
    return ZX_ERR_BAD_STATE;
  }
  const auto& base_info = device_info.base_info();
  const uint32_t min_rx_len =
      base_info.has_min_rx_buffer_length() ? base_info.min_rx_buffer_length() : 0;
  const uint32_t min_tx_len =
      base_info.has_min_tx_buffer_length() ? base_info.min_tx_buffer_length() : 0;
  const uint16_t min_tx_head =
      base_info.has_min_tx_buffer_head() ? base_info.min_tx_buffer_head() : 0;
  const uint16_t min_tx_tail =
      base_info.has_min_tx_buffer_tail() ? base_info.min_tx_buffer_tail() : 0;
  const uint32_t alignment = (base_info.has_buffer_alignment() && base_info.buffer_alignment() != 0)
                                 ? base_info.buffer_alignment()
                                 : 1;

  static_assert(sizeof(buffer_descriptor_t) % 8 == 0,
                "buffer_descriptor_t must be a whole number of 64-bit words");
  const uint8_t descriptor_length_words = static_cast<uint8_t>(sizeof(buffer_descriptor_t) / 8);
  if (device_info.min_descriptor_length() > descriptor_length_words) {
    // The real upstream struct doesn't meet this device's stated minimum — bail
    // loudly rather than silently under-sizing descriptors.
    return ZX_ERR_NOT_SUPPORTED;
  }
  const uint8_t descriptor_version = device_info.descriptor_version();

  constexpr uint16_t kRxDescriptors = 4;
  constexpr uint16_t kTxDescriptors = 4;
  constexpr uint16_t kDescriptorCount = kRxDescriptors + kTxDescriptors;
  constexpr uint16_t kTxIndex = kRxDescriptors;  // first tx descriptor index

  uint32_t buffer_size = 2048;
  if (buffer_size < min_rx_len) buffer_size = min_rx_len;
  const uint32_t tx_needed = min_tx_len + min_tx_head + min_tx_tail;
  if (buffer_size < tx_needed) buffer_size = tx_needed;
  buffer_size = ((buffer_size + alignment - 1) / alignment) * alignment;

  *stage = "CREATE-DESCRIPTORS-VMO";
  zx_handle_t descriptors_vmo = ZX_HANDLE_INVALID;
  zx_status_t vmo_status = zx_vmo_create(
      static_cast<uint64_t>(kDescriptorCount) * sizeof(buffer_descriptor_t), 0, &descriptors_vmo);
  if (vmo_status != ZX_OK) {
    return vmo_status;
  }

  *stage = "CREATE-DATA-VMO";
  zx_handle_t data_vmo = ZX_HANDLE_INVALID;
  vmo_status = zx_vmo_create(static_cast<uint64_t>(kDescriptorCount) * buffer_size, 0, &data_vmo);
  if (vmo_status != ZX_OK) {
    return vmo_status;
  }

  // Populate the empty rx descriptors (indices [0, kRxDescriptors)) — device fills
  // these on receive and hands the same index back on the rx FIFO.
  *stage = "FILL-RX-DESCRIPTORS";
  for (uint16_t i = 0; i < kRxDescriptors; ++i) {
    buffer_descriptor_t desc = {};
    desc.vmo_id = 0;
    desc.offset = static_cast<uint64_t>(i) * buffer_size;
    desc.data_length = buffer_size;
    zx_status_t write_status = zx_vmo_write(descriptors_vmo, &desc,
                                             static_cast<uint64_t>(i) * sizeof(desc), sizeof(desc));
    if (write_status != ZX_OK) {
      return write_status;
    }
  }

  // Craft a broadcast ARP request ("who has <SLIRP gateway 10.0.2.2>") as the
  // outbound frame — a real, semantically valid Ethernet frame that QEMU's
  // "-netdev user" (SLIRP) backend is expected to answer. The reply (if any) is
  // opportunistic (see RX bonus below, gated on MAC filtering this file doesn't
  // control) — frame movement itself, not the reply, is what's actually proven.
  *stage = "BUILD-ARP-FRAME";
  uint8_t frame[60] = {};  // 14 (eth) + 28 (arp) = 42 bytes, zero-padded to the
                           // minimum 60-byte Ethernet frame size.
  memset(frame + 0, 0xff, 6);  // dst = broadcast
  const uint8_t src_mac[6] = {0x02, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e};  // locally-administered
  memcpy(frame + 6, src_mac, 6);
  frame[12] = 0x08;
  frame[13] = 0x06;  // ethertype = ARP
  frame[14] = 0x00;
  frame[15] = 0x01;  // htype = ethernet
  frame[16] = 0x08;
  frame[17] = 0x00;  // ptype = ipv4
  frame[18] = 6;     // hlen
  frame[19] = 4;     // plen
  frame[20] = 0x00;
  frame[21] = 0x01;  // oper = request
  memcpy(frame + 22, src_mac, 6);
  frame[28] = 10;
  frame[29] = 0;
  frame[30] = 2;
  frame[31] = 15;  // sender proto addr (guest default 10.0.2.15)
  memset(frame + 32, 0x00, 6);
  frame[38] = 10;
  frame[39] = 0;
  frame[40] = 2;
  frame[41] = 2;  // target proto addr (SLIRP gateway 10.0.2.2)

  const uint32_t frame_len = sizeof(frame) > min_tx_len ? sizeof(frame) : min_tx_len;
  if (min_tx_head + frame_len + min_tx_tail > buffer_size) {
    return ZX_ERR_BUFFER_TOO_SMALL;
  }

  // The device requires min_tx_buffer_head/tail bytes of reserved space around the
  // payload within the descriptor's region (network-device's session.cc validates
  // this and killed the session with "insufficient head length" when this file
  // first tried head_length=0 unconditionally). The payload itself starts
  // min_tx_buffer_head bytes into the buffer's |offset|.
  *stage = "WRITE-TX-FRAME";
  const uint64_t tx_slot_offset = static_cast<uint64_t>(kTxIndex) * buffer_size;
  zx_status_t write_status =
      zx_vmo_write(data_vmo, frame, tx_slot_offset + min_tx_head, sizeof(frame));
  if (write_status != ZX_OK) {
    return write_status;
  }
  {
    buffer_descriptor_t desc = {};
    desc.frame_type = static_cast<uint8_t>(fuchsia_hardware_network::FrameType::kEthernet);
    desc.vmo_id = 0;
    desc.offset = tx_slot_offset;
    desc.head_length = min_tx_head;
    desc.tail_length = min_tx_tail;
    desc.data_length = frame_len;
    desc.port_id.base = port_id.base;
    desc.port_id.salt = port_id.salt;
    zx_status_t desc_write = zx_vmo_write(
        descriptors_vmo, &desc, static_cast<uint64_t>(kTxIndex) * sizeof(desc), sizeof(desc));
    if (desc_write != ZX_OK) {
      return desc_write;
    }
  }
  // Remaining tx descriptors [kTxIndex+1, kDescriptorCount) stay zero-initialized
  // and unused — only one tx buffer is exercised here.

  // Hand the VMOs to the device and open the session. `descriptors_vmo` is
  // duplicated: the duplicate is moved into SessionInfo (owned by the FIDL call),
  // while the original stays with us so we can read the driver-written completion
  // status back out of it later — both handles reference the same underlying VMO.
  *stage = "OPEN-SESSION";
  zx_handle_t descriptors_vmo_for_session = ZX_HANDLE_INVALID;
  vmo_status =
      zx_handle_duplicate(descriptors_vmo, ZX_RIGHT_SAME_RIGHTS, &descriptors_vmo_for_session);
  if (vmo_status != ZX_OK) {
    return vmo_status;
  }

  fidl::Arena arena;
  auto data_vmo_entry = fuchsia_hardware_network::wire::DataVmo::Builder(arena)
                            .id(0)
                            .vmo(zx::vmo(data_vmo))
                            .num_rx_buffers(kRxDescriptors)
                            .Build();
  fidl::VectorView<fuchsia_hardware_network::wire::DataVmo> data_vmos(arena, 1);
  data_vmos[0] = std::move(data_vmo_entry);

  auto session_info = fuchsia_hardware_network::wire::SessionInfo::Builder(arena)
                           .descriptors(zx::vmo(descriptors_vmo_for_session))
                           .data(data_vmos)
                           .descriptor_version(descriptor_version)
                           .descriptor_length(descriptor_length_words)
                           .descriptor_count(kDescriptorCount)
                           .Build();

  fidl::WireResult open_result =
      device->OpenSession(fidl::StringView("netdev_probe"), session_info);
  if (!open_result.ok()) {
    return open_result.status();
  }
  // WireResult's -> operator for a method with an `error` clause unwraps the raw
  // wire union into a fit::result<int32_t, ResponseType*> (is_ok()/value()/
  // error_value()), not the union's own is_response()/response()/err() accessors.
  if (open_result->is_error()) {
    return open_result->error_value();
  }

  fidl::WireSyncClient session{std::move(open_result->value()->session)};
  zx::fifo rx_fifo = std::move(open_result->value()->fifos.rx);
  zx::fifo tx_fifo = std::move(open_result->value()->fifos.tx);

  *stage = "ATTACH";
  fidl::VectorView<fuchsia_hardware_network::wire::FrameType> rx_frames(arena, 1);
  rx_frames[0] = fuchsia_hardware_network::FrameType::kEthernet;
  fidl::WireResult attach_result = session->Attach(port_id, rx_frames);
  if (!attach_result.ok()) {
    return attach_result.status();
  }
  if (attach_result->is_error()) {
    return attach_result->error_value();
  }

  *stage = "SUBMIT-RX";
  uint16_t rx_indices[kRxDescriptors];
  for (uint16_t i = 0; i < kRxDescriptors; ++i) rx_indices[i] = i;
  size_t actual = 0;
  zx_status_t fifo_status =
      zx_fifo_write(rx_fifo.get(), sizeof(uint16_t), rx_indices, kRxDescriptors, &actual);
  if (fifo_status != ZX_OK || actual != kRxDescriptors) {
    return fifo_status != ZX_OK ? fifo_status : ZX_ERR_IO;
  }

  *stage = "SUBMIT-TX";
  uint16_t tx_index = kTxIndex;
  fifo_status = zx_fifo_write(tx_fifo.get(), sizeof(uint16_t), &tx_index, 1, &actual);
  if (fifo_status != ZX_OK || actual != 1) {
    return fifo_status != ZX_OK ? fifo_status : ZX_ERR_IO;
  }

  // Wait for tx completion — the real go/no-go: the descriptor only round-trips
  // through network-device -> virtio-net -> QEMU's virtio ring if the whole
  // FIFO/VMO dataplane actually works.
  *stage = "WAIT-TX-COMPLETE";
  zx_signals_t observed = 0;
  zx_status_t wait_status =
      zx_object_wait_one(tx_fifo.get(), ZX_FIFO_READABLE, zx_deadline_after(ZX_SEC(10)), &observed);
  if (wait_status != ZX_OK) {
    return wait_status;
  }

  *stage = "READ-TX-COMPLETION";
  uint16_t completed_index = 0xffff;
  fifo_status = zx_fifo_read(tx_fifo.get(), sizeof(uint16_t), &completed_index, 1, &actual);
  if (fifo_status != ZX_OK || actual != 1) {
    return fifo_status != ZX_OK ? fifo_status : ZX_ERR_IO;
  }
  if (completed_index != kTxIndex) {
    return ZX_ERR_BAD_STATE;
  }

  *stage = "CHECK-TX-RESULT";
  buffer_descriptor_t completed_desc = {};
  zx_status_t read_status =
      zx_vmo_read(descriptors_vmo, &completed_desc,
                  static_cast<uint64_t>(kTxIndex) * sizeof(completed_desc), sizeof(completed_desc));
  if (read_status != ZX_OK) {
    return read_status;
  }
  if (completed_desc.return_flags & kTxRetError) {
    return ZX_ERR_IO_REFUSED;
  }

  // Bonus (non-gating): briefly poll for an rx completion. Not required for
  // CERISE-NETDEV-FRAME-OK — whether SLIRP's ARP reply reaches us depends on MAC
  // filtering behavior this file doesn't control.
  observed = 0;
  if (zx_object_wait_one(rx_fifo.get(), ZX_FIFO_READABLE, zx_deadline_after(ZX_SEC(2)), &observed) ==
      ZX_OK) {
    uint16_t rx_index = 0xffff;
    if (zx_fifo_read(rx_fifo.get(), sizeof(uint16_t), &rx_index, 1, &actual) == ZX_OK &&
        actual == 1) {
      static constexpr char kRxMarker[] = "CERISE-NETDEV-RX-OK\n";
      Emit(kRxMarker, sizeof(kRxMarker) - 1);
    }
  }

  return ZX_OK;
}

}  // namespace

int main() {
  // Initialize the LogSink-backed structured logging backend. This component is fully
  // synchronous (no async loop), so the interest listener — which needs a dispatcher —
  // is disabled; the default INFO severity is used.
  fuchsia_logging::LogSettingsBuilder()
      .WithTags({"netdev_probe"})
      .DisableInterestListener()
      .BuildAndInitialize();
  FX_LOGS(INFO) << "netdev_probe starting: discovering the network device via devfs";

  // Measured gap between netdev_probe's first attempt and network-device's actual
  // bind is ~65-90s (see header comment). 40 attempts * 5s = 200s budget, well clear
  // of that gap and within run-qemu.sh's 420s TIMEOUT_SECONDS for x64-pci.
  constexpr int kMaxAttempts = 40;
  constexpr zx_duration_t kRetryDelay = ZX_SEC(5);

  const char* stage = "OPEN-DEV";
  zx_status_t status = ZX_ERR_INTERNAL;
  fidl::ClientEnd<fuchsia_hardware_network::Device> device_client;
  for (int attempt = 0; attempt < kMaxAttempts; ++attempt) {
    status = TryOnce(&stage, &device_client);
    if (status == ZX_OK) {
      break;
    }
    zx_nanosleep(zx_deadline_after(kRetryDelay));
  }

  if (status != ZX_OK) {
    FX_LOGS(ERROR) << "devfs client path failed at stage " << stage << " status=" << status;
    return 1;
  }

  FX_LOGS(INFO) << "devfs client path verified (Device.GetInfo succeeded)";
  // Boot-gate marker — keep on serial verbatim (validation greps this).
  static constexpr char kDevfsMarker[] = "CERISE-DEVFS-CLIENT-OK\n";
  Emit(kDevfsMarker, sizeof(kDevfsMarker) - 1);

  status = RunSessionAndFrame(std::move(device_client), &stage);
  if (status != ZX_OK) {
    FX_LOGS(ERROR) << "network-device dataplane failed at stage " << stage
                   << " status=" << status;
    return 1;
  }

  FX_LOGS(INFO) << "network-device dataplane verified (tx frame round-tripped)";
  // Boot-gate marker — keep on serial verbatim.
  static constexpr char kFrameMarker[] = "CERISE-NETDEV-FRAME-OK\n";
  Emit(kFrameMarker, sizeof(kFrameMarker) - 1);
  return 0;
}

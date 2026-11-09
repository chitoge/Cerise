// Cerise real-hardware NIC workstream: a REAL DFv2 e1000/e1000e-family driver.
//
// This replaces the earlier 118-line bind+MMIO stub with a working network
// device: TX/RX legacy descriptor rings, MSI (or legacy) interrupts, and a
// fuchsia.hardware.network.driver port so netstack3 sees it exactly like the
// virtio-net driver. The FreeBSD/Intel shared-code HAL (vendored under
// third_party/e1000, see README.fuchsia) handles MAC/PHY/NVM bring-up; the
// DFv2 glue, descriptor rings, and netdevice integration are Cerise-native and
// modeled on virtio-net's netdevice.cc.
//
// Families bound (see meta/e1000.bind): QEMU 82540EM (8086:100e, legacy e1000,
// live under `-device e1000`), QEMU 82574L (8086:10d3, e1000e, live under
// `-device e1000e`), Intel I211 (8086:1539), and the Skylake/Sunrise-Point
// I219-LM/-V set (0x156f/0x1570/0x15b7/0x15b8/0x15d6/0x15d7/0x15d8/0x15e3),
// covering common Intel client NICs. Legacy descriptors are the common denominator
// across all of them, so the ring code is family-independent.
#include <fidl/fuchsia.driver.framework/cpp/fidl.h>
#include <fidl/fuchsia.hardware.network.driver/cpp/driver/wire.h>
#include <fidl/fuchsia.hardware.network/cpp/wire.h>
#include <fidl/fuchsia.hardware.pci/cpp/fidl.h>
#include <lib/driver/compat/cpp/device_server.h>
#include <lib/driver/component/cpp/driver_base2.h>
#include <lib/driver/component/cpp/driver_export2.h>
#include <lib/driver/component/cpp/node_add_args.h>
#include <lib/driver/logging/cpp/logger.h>
#include <lib/sync/cpp/completion.h>
#include <lib/zx/bti.h>
#include <lib/zx/interrupt.h>
#include <lib/zx/pmt.h>
#include <lib/zx/vmar.h>
#include <lib/zx/vmo.h>
#include <zircon/syscalls.h>
#include <zircon/threads.h>

#include <array>
#include <atomic>
#include <memory>
#include <mutex>
#include <optional>
#include <thread>

#include "src/lib/vmo_store/vmo_store.h"

// The vendored FreeBSD/Intel shared code is C. Its osdep header pulls in the C
// library headers below; include them FIRST at normal C++ linkage so their
// include guards no-op the re-includes inside the extern "C" block (libc++'s
// <string.h> etc. must never be parsed inside extern "C").
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

// Now pull in the HAL with C linkage for its function declarations. The osdep
// PCI/delay shims below are defined with matching C linkage.
extern "C" {
#include "third_party/e1000/e1000_api.h"
}

namespace e1000 {

namespace netdev = fuchsia_hardware_network_driver;
namespace netdrv = fuchsia_hardware_network;

using VmoStore = vmo_store::VmoStore<vmo_store::SlabStorage<uint32_t>>;

namespace {

// Ring sizing. Legacy descriptors are 16 bytes; 256 * 16 = 4096 = one page per
// ring. Must be a multiple of 8 (E1000 requires the descriptor length register
// to be 128-byte aligned).
constexpr uint16_t kNumTxDesc = 256;
constexpr uint16_t kNumRxDesc = 256;
constexpr uint16_t kMaxDepth = 256;

constexpr uint32_t kTxRingBytes = kNumTxDesc * sizeof(e1000_tx_desc);
constexpr uint32_t kRxRingBytes = kNumRxDesc * sizeof(e1000_rx_desc);

constexpr uint8_t kPortId = 1;
constexpr size_t kMtu = 1514;

void E1000StartMark(const char* marker) { zx_debug_write(marker, strlen(marker)); }
// Receive buffer size programmed into RCTL (E1000_RCTL_SZ_2048). Rx space
// buffers handed to us by the netdevice framework must be at least this large.
constexpr size_t kRxBufferSize = 2048;
constexpr size_t kBufferAlignment = 64;
constexpr uint16_t kEthernetFcsBytes = 4;

constexpr char kChildNodeName[] = "e1000-netdev";

// --- i219 descriptor-ring flush ("unit hang") constants ---
//
// None of these are in the vendored shared code, because the shared code has no
// equivalent of Linux's e1000_flush_desc_rings() at all (grep for flush_desc /
// flush_tx_ring / flush_rx_ring under third_party/e1000: zero hits). They are
// defined here rather than in the vendored headers so the vendored tree stays a
// clean import.
//
// PCICFG_DESC_RING_STATUS is a PCI CONFIG-space (not MMIO) word: on i219 the
// device reports "my internal descriptor unit still holds state, flush me before
// you reset" in bit 8. Linux: drivers/net/ethernet/intel/e1000e/e1000.h:79-80.
constexpr uint16_t kPciCfgDescRingStatus = 0xe4;
constexpr uint16_t kFlushDescRequired = 0x100;
// Linux drivers/net/ethernet/intel/e1000e/ich8lan.h:94.
constexpr uint32_t kRxdctlThreshUnitDesc = 0x01000000;
// The dummy frame e1000_flush_tx_ring() pushes through the transmitter.
constexpr uint16_t kFlushTxDummyLen = 512;
// One extra page in the ring VMO, used as a DMA source for the transmit
// self-test. It sits in the SAME pinned contiguous allocation as the rings, so
// the device is already demonstrably able to read it -- that is the whole point
// (see TxSelfTest).
constexpr uint32_t kScratchBytes = 4096;
constexpr uint16_t kSelfTestFrameLen = 60;

// "Is this one of the PCH parts that i219-era workarounds apply to?"
//
// NEVER write this as `mac.type >= e1000_pch_spt`, however natural that looks
// when transcribing Linux. Linux's e1000e enum contains ONLY the ICH/PCH parts,
// so `>=` there means "SPT and newer PCH". The vendored FreeBSD enum is the
// merged em+igb list, and it continues past the PCH block into the igb family
// (e1000_hw.h): ... pch_lpt, pch_spt=25, pch_cnp=26, 82575=27, 82576, 82580,
// i350, i354, i210, i211=33 ... So `>= e1000_pch_spt` is TRUE FOR I211, which
// this driver binds (8086:1539).
//
// That is not a harmless over-application. The registers involved are aliased
// across the two families: E1000_FEXTNVM11 is 0x5BBC on PCH, and 0x5BBC is
// E1000_BARCTRL -- the BAR CONTROL register -- on the igb parts
// (e1000_regs.h:51 vs :70). A `>=` gate quietly turns an i219 errata workaround
// into a BAR-control write on an I211.
constexpr bool IsPchSptFamily(e1000_mac_type t) {
  return t == e1000_pch_spt || t == e1000_pch_cnp;
}

constexpr bool IsPchManageabilityFamily(e1000_mac_type t) {
  return t == e1000_pch_lpt || IsPchSptFamily(t);
}

// Build the host-owned portion of RCTL without replacing firmware-owned or
// silicon-initialised bits.  The PCH LAN controller is shared with the
// manageability engine, so RCTL must be treated like TCTL: read, modify only
// the fields the host receive queue owns, then write it back.
constexpr uint32_t ConfigureReceiveControl(uint32_t current, bool hardware_strips_fcs) {
  constexpr uint32_t kHostOwnedFields =
      E1000_RCTL_EN | E1000_RCTL_SBP | E1000_RCTL_UPE | E1000_RCTL_MPE |
      E1000_RCTL_LPE | E1000_RCTL_LBM_TCVR | E1000_RCTL_DTYP_PS | E1000_RCTL_MO_3 |
      E1000_RCTL_SZ_4096 | E1000_RCTL_VFE | E1000_RCTL_CFIEN | E1000_RCTL_BSEX |
      E1000_RCTL_SECRC;
  uint32_t configured = current & ~kHostOwnedFields;
  configured |= E1000_RCTL_EN | E1000_RCTL_BAM | E1000_RCTL_UPE | E1000_RCTL_MPE |
                E1000_RCTL_LBM_NO | E1000_RCTL_RDMTS_HALF | E1000_RCTL_SZ_2048;
  if (hardware_strips_fcs) {
    configured |= E1000_RCTL_SECRC;
  }
  return configured;
}

constexpr uint16_t HostFrameLength(uint16_t device_length, bool hardware_strips_fcs) {
  if (hardware_strips_fcs) {
    return device_length;
  }
  return device_length >= kEthernetFcsBytes ? device_length - kEthernetFcsBytes : 0;
}

static_assert((ConfigureReceiveControl(0x80000000u, false) & 0x80000000u) != 0,
              "RCTL configuration must preserve fields outside host ownership");
static_assert((ConfigureReceiveControl(0, false) & E1000_RCTL_SECRC) == 0,
              "management-capable PCH receive must retain the FCS for SMBus");
static_assert(HostFrameLength(64, false) == 60,
              "software must remove a retained Ethernet FCS before netstack delivery");

}  // namespace

class E1000Driver : public fdf::DriverBase2,
                    public fdf::WireServer<netdev::NetworkDeviceImpl>,
                    public fdf::WireServer<netdev::NetworkPort>,
                    public fdf::WireServer<netdev::MacAddr> {
 public:
  E1000Driver() : fdf::DriverBase2("e1000") {}

  // DriverBase2 lifecycle: outgoing() serves BOTH zircon- and driver-transport
  // services, which the driver-transport netdev::Service requires.
  zx::result<> Start(fdf::DriverContext context) override;
  void Stop(fdf::StopCompleter completer) override;

  // --- osdep C shims (see e1000_osdep.h). Called by the HAL during bring-up. ---
  void PciRead16(uint32_t reg, uint16_t* value);
  void PciWrite16(uint32_t reg, uint16_t value);
  int PciFindCap(uint8_t cap_id, uint8_t* offset);

  // --- NetworkDeviceImpl ---
  void Init(netdev::wire::NetworkDeviceImplInitRequest* request, fdf::Arena& arena,
            InitCompleter::Sync& completer) override;
  void Start(fdf::Arena& arena, StartCompleter::Sync& completer) override;
  void Stop(fdf::Arena& arena, StopCompleter::Sync& completer) override;
  void GetInfo(fdf::Arena& arena,
               fdf::WireServer<netdev::NetworkDeviceImpl>::GetInfoCompleter::Sync& completer)
      override;
  void QueueTx(netdev::wire::NetworkDeviceImplQueueTxRequest* request, fdf::Arena& arena,
               QueueTxCompleter::Sync& completer) override;
  void QueueRxSpace(netdev::wire::NetworkDeviceImplQueueRxSpaceRequest* request, fdf::Arena& arena,
                    QueueRxSpaceCompleter::Sync& completer) override;
  void PrepareVmo(netdev::wire::NetworkDeviceImplPrepareVmoRequest* request, fdf::Arena& arena,
                  PrepareVmoCompleter::Sync& completer) override;
  void ReleaseVmo(netdev::wire::NetworkDeviceImplReleaseVmoRequest* request, fdf::Arena& arena,
                  ReleaseVmoCompleter::Sync& completer) override;

  // --- NetworkPort ---
  void GetInfo(fdf::Arena& arena,
               fdf::WireServer<netdev::NetworkPort>::GetInfoCompleter::Sync& completer) override;
  void GetStatus(fdf::Arena& arena, GetStatusCompleter::Sync& completer) override;
  void SetActive(netdev::wire::NetworkPortSetActiveRequest* request, fdf::Arena& arena,
                 SetActiveCompleter::Sync& completer) override;
  void GetMac(fdf::Arena& arena, GetMacCompleter::Sync& completer) override;
  void Removed(fdf::Arena& arena, RemovedCompleter::Sync& completer) override;

  // --- MacAddr ---
  void GetAddress(fdf::Arena& arena, GetAddressCompleter::Sync& completer) override;
  void GetFeatures(fdf::Arena& arena, GetFeaturesCompleter::Sync& completer) override;
  void SetMode(netdev::wire::MacAddrSetModeRequest* request, fdf::Arena& arena,
               SetModeCompleter::Sync& completer) override;

 private:
  // Register helpers (direct MMIO; the HAL uses its own macros over membase_).
  uint32_t Rd(uint32_t reg) { return *reinterpret_cast<volatile uint32_t*>(membase_ + reg); }
  void Wr(uint32_t reg, uint32_t val) {
    *reinterpret_cast<volatile uint32_t*>(membase_ + reg) = val;
  }

  zx_status_t InitHardware();
  zx_status_t SetupInterrupt();
  zx_status_t AllocRings();
  zx_status_t AddNetdevChild();
  void EnableRxTx();
  void DisableRxTx();
  void DrainOutstandingBuffers(fdf::Arena& arena, zx_status_t tx_status);
  void NotifyPortStatus();
  void LogManageabilityState(const char* phase);
  // i219 pre-reset descriptor-ring flush (Linux e1000_flush_desc_rings et al).
  void FlushDescRings();
  void FlushTxRing();
  void FlushRxRing();
  void LogTxForensics(const char* where, uint16_t desc_index = 0);
  void TxSelfTest();
  void IrqThread();
  void ReclaimTx();
  void HarvestRx();
  netdrv::wire::PortStatus ReadPortStatus(fidl::AnyArena& arena);

  // PCI + MMIO.
  fidl::ClientEnd<fuchsia_hardware_pci::Device> pci_;
  zx::bti bti_;
  zx::vmo bar0_vmo_;
  uintptr_t membase_ = 0;
  size_t bar0_size_ = 0;

  // HAL state.
  struct e1000_hw hw_ = {};
  struct e1000_osdep osdep_ = {};
  bool is_e1000e_family_ = false;
  bool rx_hardware_strips_fcs_ = true;
  uint8_t mac_[6] = {};

  // Interrupt.
  zx::interrupt irq_;
  bool irq_is_legacy_ = false;
  std::thread irq_thread_;
  std::atomic<bool> irq_running_{false};
  std::atomic<uint32_t> irq_diag_count_{0};
  std::atomic<uint32_t> tx_diag_count_{0};

  // Serializes attach-grade MAC/PHY reset with the IRQ and netdevice lifecycle
  // paths. QueueTx/QueueRxSpace are fenced by started_ and their ring locks.
  std::mutex hardware_lock_;
  // Descriptor rings (one contiguous, pinned VMO).
  zx::vmo ring_vmo_;
  zx::pmt ring_pmt_;
  uintptr_t ring_virt_ = 0;
  zx_paddr_t ring_phys_ = 0;
  volatile e1000_tx_desc* tx_ring_ = nullptr;
  volatile e1000_rx_desc* rx_ring_ = nullptr;
  zx_paddr_t tx_ring_phys_ = 0;
  zx_paddr_t rx_ring_phys_ = 0;
  uint8_t* scratch_virt_ = nullptr;
  zx_paddr_t scratch_phys_ = 0;

  // TX bookkeeping.
  std::mutex tx_lock_;
  uint16_t tx_next_ = 0;      // next slot to fill
  uint16_t tx_reclaim_ = 0;   // next slot to reclaim
  uint32_t tx_buf_id_[kNumTxDesc] = {};

  // RX bookkeeping.
  std::mutex rx_lock_;
  uint16_t rx_tail_ = 0;   // RDT value / next slot to fill
  uint16_t rx_clean_ = 0;  // next slot to harvest
  uint32_t rx_buf_id_[kNumRxDesc] = {};
  bool rx_slot_valid_[kNumRxDesc] = {};

  // DriverBase2 context captured in Start().
  std::shared_ptr<fdf::Namespace> incoming_;
  std::optional<std::string> node_name_;

  // netdevice plumbing.
  std::mutex state_lock_;
  fdf::WireSharedClient<netdev::NetworkDeviceIfc> ifc_;
  std::atomic<bool> started_{false};
  fdf::UnsynchronizedDispatcher netdevice_dispatcher_;
  libsync::Completion netdevice_dispatcher_shutdown_;
  compat::SyncInitializedDeviceServer compat_server_;
  fidl::ClientEnd<fuchsia_driver_framework::NodeController> netdev_child_;
  std::optional<VmoStore> vmo_store_;
};

// ---------------------------------------------------------------------------
// osdep C shims. The HAL calls these (via e1000_osdep.c) with pci_ctx == this.
// ---------------------------------------------------------------------------
extern "C" {
void e1000_osdep_delay_usec(uint32_t usec) {
  zx_nanosleep(zx_deadline_after(ZX_USEC(usec)));
}
void e1000_osdep_pci_read16(void* ctx, uint32_t reg, uint16_t* value) {
  static_cast<E1000Driver*>(ctx)->PciRead16(reg, value);
}
void e1000_osdep_pci_write16(void* ctx, uint32_t reg, uint16_t value) {
  static_cast<E1000Driver*>(ctx)->PciWrite16(reg, value);
}
int e1000_osdep_pci_find_cap(void* ctx, uint8_t cap_id, uint8_t* offset) {
  return static_cast<E1000Driver*>(ctx)->PciFindCap(cap_id, offset);
}
}  // extern "C"

void E1000Driver::PciRead16(uint32_t reg, uint16_t* value) {
  *value = 0xffff;
  auto result = fidl::Call(pci_)->ReadConfig16(static_cast<uint16_t>(reg));
  if (result.is_ok()) {
    *value = result->value();
  }
}
void E1000Driver::PciWrite16(uint32_t reg, uint16_t value) {
  (void)fidl::Call(pci_)->WriteConfig16({static_cast<uint16_t>(reg), value});
}
int E1000Driver::PciFindCap(uint8_t cap_id, uint8_t* offset) {
  auto result = fidl::Call(pci_)->GetCapabilities(
      fuchsia_hardware_pci::DeviceGetCapabilitiesRequest(fuchsia_hardware_pci::CapabilityId(cap_id)));
  if (result.is_error() || result->offsets().empty()) {
    return -1;
  }
  *offset = result->offsets()[0];
  return 0;
}

// ---------------------------------------------------------------------------
// Driver lifecycle.
// ---------------------------------------------------------------------------
zx::result<> E1000Driver::Start(fdf::DriverContext context) {
  incoming_ = std::shared_ptr<fdf::Namespace>(context.take_incoming());
  node_name_ = context.node_name();

  // Connect to the parent's PCI service (composite spec's pci parent).
  zx::result<fidl::ClientEnd<fuchsia_hardware_pci::Device>> pci =
      incoming_->Connect<fuchsia_hardware_pci::Service::Device>();
  if (pci.is_error()) {
    FDF_LOG(ERROR, "Failed to connect to fuchsia.hardware.pci.Service: %s", pci.status_string());
    return pci.take_error();
  }
  pci_ = std::move(pci.value());

  // Bus mastering is required for descriptor-ring DMA.
  if (auto r = fidl::Call(pci_)->SetBusMastering(true); r.is_error()) {
    FDF_LOG(ERROR, "SetBusMastering failed");
    return zx::error(ZX_ERR_INTERNAL);
  }

  // Map BAR0 (register space).
  auto bar = fidl::Call(pci_)->GetBar(0);
  if (bar.is_error()) {
    FDF_LOG(ERROR, "GetBar(0) failed");
    return zx::error(ZX_ERR_INTERNAL);
  }
  if (bar->result().result().Which() != fuchsia_hardware_pci::BarResult::Tag::kVmo) {
    FDF_LOG(ERROR, "BAR0 is not VMO-backed MMIO");
    return zx::error(ZX_ERR_WRONG_TYPE);
  }
  bar0_vmo_ = zx::vmo(bar->result().result().vmo()->release());
  bar0_size_ = bar->result().size();
  // BAR0 is device MMIO: it MUST be mapped uncached, or register writes may be
  // held in the CPU cache and never reach the NIC (and reads return stale) — a
  // silent, marker-less failure of the whole bring-up. A device VMO defaults to
  // CACHED on x86 and the PCI bus driver does not pre-set the policy.
  if (zx_status_t st = bar0_vmo_.set_cache_policy(ZX_CACHE_POLICY_UNCACHED_DEVICE); st != ZX_OK) {
    FDF_LOG(ERROR, "set_cache_policy(UNCACHED_DEVICE) on BAR0 failed: %s",
            zx_status_get_string(st));
    return zx::error(st);
  }
  if (zx_status_t st = zx::vmar::root_self()->map(ZX_VM_PERM_READ | ZX_VM_PERM_WRITE, 0, bar0_vmo_,
                                                  0, bar0_size_, &membase_);
      st != ZX_OK) {
    FDF_LOG(ERROR, "Failed to map BAR0: %s", zx_status_get_string(st));
    return zx::error(st);
  }

  // BTI for DMA.
  auto bti = fidl::Call(pci_)->GetBti(0);
  if (bti.is_error()) {
    FDF_LOG(ERROR, "GetBti(0) failed");
    return zx::error(ZX_ERR_INTERNAL);
  }
  bti_ = std::move(bti->bti());

  // Rings BEFORE hardware bring-up. This order is required, not cosmetic: on
  // i219 the descriptor rings must be flushed before the MAC is reset (see
  // FlushDescRings), and flushing means pushing a descriptor through a ring the
  // driver owns. Doing it the other way round would leave the flush no choice
  // but to DMA through whatever ring base firmware happened to leave behind.
  // AllocRings touches no device registers, so nothing about the manageability
  // ordering in InitHardware is affected by moving it earlier.
  if (zx_status_t st = AllocRings(); st != ZX_OK) {
    return zx::error(st);
  }
  if (zx_status_t st = InitHardware(); st != ZX_OK) {
    return zx::error(st);
  }
  if (zx_status_t st = SetupInterrupt(); st != ZX_OK) {
    return zx::error(st);
  }
  E1000StartMark("CERISE-E1000-POST-INTERRUPT\n");

  // vmo_store for pinning the netdevice framework's data VMOs.
  vmo_store_.emplace(vmo_store::Options{
      .map = vmo_store::MapOptions{.vm_option = ZX_VM_PERM_READ | ZX_VM_PERM_WRITE |
                                                ZX_VM_REQUIRE_NON_RESIZABLE,
                                   .vmar = nullptr},
      .pin = vmo_store::PinOptions{.bti = zx::unowned_bti(bti_),
                                   .bti_pin_options = ZX_BTI_PERM_READ | ZX_BTI_PERM_WRITE,
                                   .index = true},
  });
  if (zx_status_t st = vmo_store_->Reserve(netdrv::wire::kMaxDataVmos); st != ZX_OK) {
    FDF_LOG(ERROR, "vmo_store reserve failed: %s", zx_status_get_string(st));
    return zx::error(st);
  }
  E1000StartMark("CERISE-E1000-VMO-STORE-READY\n");

  // Dispatcher that serves the NetworkDeviceImpl protocol.
  auto disp = fdf::UnsynchronizedDispatcher::Create(
      {}, "e1000-netdev", [this](fdf_dispatcher_t*) { netdevice_dispatcher_shutdown_.Signal(); });
  if (disp.is_error()) {
    return disp.take_error();
  }
  netdevice_dispatcher_ = std::move(disp.value());
  E1000StartMark("CERISE-E1000-NETDEV-DISPATCHER-READY\n");

  if (zx_status_t st = AddNetdevChild(); st != ZX_OK) {
    return zx::error(st);
  }

  // Start the interrupt-handling thread.
  irq_running_ = true;
  irq_thread_ = std::thread([this] { IrqThread(); });

  // Bind markers. CERISE-E1000-BOUND keeps the qemu-x64-pci gate green (it
  // requires this marker for the 82540EM bind); CERISE-E1000E-BOUND is the new
  // e1000e-family signal.
  static constexpr char kMarker[] = "CERISE-E1000-BOUND\n";
  zx_debug_write(kMarker, sizeof(kMarker) - 1);
  FDF_LOG(INFO, "CERISE-E1000-BOUND (mac_type=%u did=0x%04x)", hw_.mac.type, hw_.device_id);
  if (is_e1000e_family_) {
    static constexpr char kMarkerE[] = "CERISE-E1000E-BOUND\n";
    zx_debug_write(kMarkerE, sizeof(kMarkerE) - 1);
    FDF_LOG(INFO, "CERISE-E1000E-BOUND");
  }
  return zx::ok();
}

zx_status_t E1000Driver::InitHardware() {
  osdep_.pci_ctx = this;
  osdep_.membase = membase_;
  osdep_.iobase = 0;
  hw_.back = &osdep_;
  // The shared code sanity-checks hw->hw_addr (e.g. setup_init_funcs returns
  // ERR_CONFIG if it is NULL) and some paths dereference it directly for
  // register access. Point it at the same BAR0 MMIO base the osdep macros use.
  hw_.hw_addr = reinterpret_cast<u8*>(membase_);
  // hw_.flash_address is deliberately left NULL here and NOT mirrored into
  // e1000_osdep: on I219 (mac.type >= e1000_pch_spt) the flash registers live
  // inside BAR0 at +0xE000 and e1000_init_nvm_params_ich8lan assigns
  // hw->flash_address itself, later than this function runs. The osdep flash
  // macros therefore read hw->flash_address directly — see the long comment on
  // E1000_READ_FLASH_REG in e1000_osdep.h; caching a base here is what made the
  // driver host fault on real I219 silicon. Pre-SPT ICH8/PCH parts keep NULL
  // and are rejected cleanly by that same init function (-E1000_ERR_CONFIG).
  hw_.flash_address = nullptr;

  // Identify the device from PCI config space.
  uint16_t vid = 0, did = 0, ssvid = 0, ssid = 0;
  PciRead16(0x00, &vid);
  PciRead16(0x02, &did);
  PciRead16(0x2c, &ssvid);
  PciRead16(0x2e, &ssid);
  uint8_t rev = 0;
  if (auto r = fidl::Call(pci_)->ReadConfig8(0x08); r.is_ok()) {
    rev = r->value();
  }
  hw_.vendor_id = vid;
  hw_.device_id = did;
  hw_.subsystem_vendor_id = ssvid;
  hw_.subsystem_device_id = ssid;
  hw_.revision_id = rev;

  if (s32 st = e1000_set_mac_type(&hw_); st != E1000_SUCCESS) {
    FDF_LOG(ERROR, "e1000_set_mac_type failed for did=0x%04x: %d", did, st);
    return ZX_ERR_NOT_SUPPORTED;
  }
  // e1000e / I2xx family are mac.type >= 82571 (excludes the legacy 8254x).
  is_e1000e_family_ = hw_.mac.type >= e1000_82571;

  if (s32 st = e1000_setup_init_funcs(&hw_, true); st != E1000_SUCCESS) {
    FDF_LOG(ERROR, "e1000_setup_init_funcs failed: %d", st);
    return ZX_ERR_INTERNAL;
  }
  e1000_get_bus_info(&hw_);

  // Supply the link policy that an operating-system driver normally owns.
  //
  // The shared HAL deliberately does not invent policy: a zero-initialised
  // e1000_hw means forced 10/half, not "use the fastest common mode". Linux
  // e1000e sets these fields before its first reset for the same reason. Cerise
  // previously omitted them and happened to inherit whatever mode firmware
  // left in the PHY. On the CF-SZ5 direct link that was measurably 10/half.
  //
  // This is safe to establish even while manageability is active because these
  // are software fields only. e1000_setup_link_ich8lan checks the firmware PHY
  // reset block before touching PHY registers. If setup is blocked, the
  // firmware-established link remains authoritative for this driver instance.
  // A later speed-policy change requires a deliberately qualified driver
  // rebind; an asynchronous reset on firmware release can destroy AMT's packet
  // filters.
  if (hw_.phy.media_type == e1000_media_type_copper) {
    hw_.mac.autoneg = true;
    hw_.phy.autoneg_advertised = hw_.phy.autoneg_mask;
    hw_.phy.autoneg_wait_to_complete = false;
    if (IsPchManageabilityFamily(hw_.mac.type)) {
      // These are the e1000e defaults for a standard-MTU PCH interface.  The
      // PCH setup path resolves e1000_fc_default to full flow control and
      // immediately programs all four thresholds, so selecting "default"
      // while leaving the zero-initialised thresholds in place emits
      // pathological pause frames.
      hw_.fc.requested_mode = e1000_fc_default;
      hw_.fc.current_mode = e1000_fc_default;
      hw_.fc.pause_time = 0xffff;
      hw_.fc.refresh_time = 0xffff;
      hw_.fc.high_water = 0x05c20;
      hw_.fc.low_water = 0x05048;
      hw_.fc.send_xon = true;
    } else {
      // The other copper parts previously ran without flow control. Preserve
      // that known policy until their FIFO-specific thresholds are supplied.
      hw_.fc.requested_mode = e1000_fc_none;
      hw_.fc.current_mode = e1000_fc_none;
    }
  }

  // ---------------------------------------------------------------------
  // Manageability (Intel ME / AMT) coexistence.
  //
  // On ICH8/PCH/SPT parts -- the I219-LM in the CF-SZ5 is mac_type
  // e1000_pch_spt -- the ME has NO MAC and NO PHY of its own. AMT is muxed
  // through THIS LAN controller, and on this platform through the very same
  // unicast address the host uses (the ARP entry for the AMT address carries
  // the NIC's own MAC). So the receive-address filters are not just ours:
  // invalidating them takes out the machine's only remote console, which costs
  // a physical power cycle to recover. Everything below exists to keep them.
  // The shared code needs the frame size before several of its PCH paths will
  // run at all. Most importantly e1000_platform_pm_pch_lpt() -- the Latency
  // Tolerance Reporting / OBFF setup that e1000_check_for_copper_link_ich8lan
  // calls on every link-up for mac.type >= e1000_pch_lpt -- bails out with
  // -E1000_ERR_CONFIG the moment it sees a zero here ("max_frame_size not
  // set."), and that error propagates out of check_for_link and skips the
  // collision-distance and post-link flow-control programming that follow it.
  // Nothing in the shared code initialises this; Linux sets it from
  // netdev->mtu + ETH_HLEN + ETH_FCS_LEN. kMtu is already the framed size
  // including the Ethernet header, so this is MTU + FCS = 1518.
  hw_.mac.max_frame_size = kMtu + 4;

  const uint32_t fwsm = Rd(E1000_FWSM);
  const bool mng_active = e1000_check_mng_mode(&hw_);
  const s32 reset_blocked = e1000_check_reset_block(&hw_);
  FDF_LOG(INFO, "CERISE-E1000-MNG fwsm=%08x fw_valid=%d mng=%d reset_block=%d wlock_mac=%u", fwsm,
          (fwsm & E1000_ICH_FWSM_FW_VALID) != 0, mng_active, reset_blocked,
          (fwsm & E1000_FWSM_WLOCK_MAC_MASK) >> E1000_FWSM_WLOCK_MAC_SHIFT);
  LogManageabilityState("pre-reset");

  // Linux deliberately leaves FLAG2_CRC_STRIPPING clear for PCH-SPT/I219.
  // RCTL.SECRC strips the FCS before sending a frame to BOTH host memory and
  // SMBus; Intel platforms exist whose management firmware expects the SMBus
  // copy to retain it.  Keep the FCS in DMA on these shared PCH parts and
  // remove it in HarvestRx before exposing the ordinary Ethernet frame to the
  // Cerise netstack.  Other supported controllers retain their established
  // hardware-stripping behavior.
  rx_hardware_strips_fcs_ = !IsPchManageabilityFamily(hw_.mac.type);

  // e1000e's get_hw_control(): announce to the ME that an OS driver is present
  // and is now responsible for the interface. Linux does this in probe/open and
  // clears it on close/remove; while it is set, firmware stops driving the parts
  // of the link it maintains on the OS's behalf. Set it BEFORE the reset so the
  // ME never sees a reset from a device it believes is unowned.
  Wr(E1000_CTRL_EXT, Rd(E1000_CTRL_EXT) | E1000_CTRL_EXT_DRV_LOAD);

  // Keep only RAR[0] as a fallback for recovering the permanent address after
  // reset. RAR[1..] on PCH-LPT and newer parts are shared with the ME. The
  // hardware-aware rar_set operation uses FWSM.WLOCK_MAC and the software
  // semaphore to decide which of those entries the host may modify; copying
  // them with raw MMIO would bypass both ownership mechanisms. Linux e1000e and
  // Intel's shared FreeBSD driver both rely on rar_set and never snapshot and
  // replay SHRA entries around init_hw.
  const uint32_t ral_pre = Rd(E1000_RAL(0));
  const uint32_t rah_pre = Rd(E1000_RAH(0));

  // Empty the descriptor rings BEFORE the reset. On i219 this is mandatory, and
  // skipping it is what wedges the transmitter -- see FlushDescRings.
  FlushDescRings();

  // Reset the MAC/PHY. e1000_reset_hw_ich8lan already consults
  // phy->ops.check_reset_block (e1000_ich8lan.c:4995) and omits CTRL_PHY_RST
  // when the ME has PHY reset blocked, so the reset itself is ME-aware.
  if (s32 st = e1000_reset_hw(&hw_); st != E1000_SUCCESS) {
    FDF_LOG(ERROR, "e1000_reset_hw failed: %d", st);
    Wr(E1000_CTRL_EXT, Rd(E1000_CTRL_EXT) & ~E1000_CTRL_EXT_DRV_LOAD);
    LogManageabilityState("reset-failed");
    return ZX_ERR_INTERNAL;
  }

  // Recover the permanent MAC address NOW -- BEFORE e1000_init_hw().
  //
  // THIS ORDERING IS THE WHOLE BUG FIX, and it is what cost the machine its AMT
  // session the first time round. e1000_init_hw_ich8lan calls
  // e1000_init_rx_addrs_generic(hw, rar_entry_count) (e1000_ich8lan.c:5081),
  // which writes hw->mac.addr into RAR[0] and zeroes every remaining entry
  // (e1000_mac.c:381-386). The driver used to call e1000_read_mac_addr() AFTER
  // init_hw, so hw_.mac.addr was still all-zero at that moment and init_hw
  // faithfully programmed 00:00:00:00:00:00 into RAR[0].
  //
  // e1000_rar_set_pch_lpt's index==0 path (e1000_ich8lan.c:2091-2097) has no
  // manageability guard whatsoever, and its "if MAC address zero, no need to
  // set the AV bit" test (:2088) then leaves RAR[0] *invalid*. On a part where
  // AMT shares the host's unicast address that deletes the only filter AMT's
  // packets match -- which is exactly the observed lockout. It also explains the
  // reported MAC of 00:00:00:00:00:00: read_mac_addr is never overridden for
  // ich8lan (it stays e1000_read_mac_addr_generic, e1000_mac.c:61), and that
  // function just reads RAR[0] back and returns E1000_SUCCESS unconditionally
  // (e1000_nvm.c:1131-1149) -- "success" with a zero result.
  //
  // Feeding the real address in first makes init_hw REPROGRAM RAR[0] correctly
  // (AV set) instead of destroying it.
  //
  // Go through e1000_read_mac_addr() rather than reading RAR[0] directly: the
  // other families this driver binds DO override the op and need that path
  // (82571 wraps it at e1000_82571.c:1840, and the I211/82575 version at
  // e1000_82575.c:1942 additionally honours an NVM alternate MAC address).
  // Only fall back to raw RAR[0] when it comes back empty.
  if (s32 st = e1000_read_mac_addr(&hw_); st != E1000_SUCCESS) {
    FDF_LOG(WARNING, "e1000_read_mac_addr returned %d; falling back to RAL/RAH", st);
  }
  bool have_mac = false;
  for (int i = 0; i < 6; i++) {
    if (hw_.mac.addr[i] != 0) {
      have_mac = true;
    }
  }
  if (!have_mac) {
    // Note e1000_read_mac_addr_generic returns E1000_SUCCESS even when RAR[0]
    // reads zero (e1000_nvm.c:1149), so "success" is not evidence of an
    // address -- the zero check above is what actually decides.
    uint32_t ral = Rd(E1000_RAL(0));
    uint32_t rah = Rd(E1000_RAH(0));
    if ((ral | (rah & 0xffff)) == 0) {
      // A software reset should not clear a firmware-programmed RAR0 on these
      // parts, but if it did, the pre-reset snapshot is still authoritative.
      ral = ral_pre;
      rah = rah_pre;
    }
    hw_.mac.addr[0] = ral & 0xff;
    hw_.mac.addr[1] = (ral >> 8) & 0xff;
    hw_.mac.addr[2] = (ral >> 16) & 0xff;
    hw_.mac.addr[3] = (ral >> 24) & 0xff;
    hw_.mac.addr[4] = rah & 0xff;
    hw_.mac.addr[5] = (rah >> 8) & 0xff;
  }
  for (int i = 0; i < 6; i++) {
    mac_[i] = hw_.mac.addr[i];
    hw_.mac.perm_addr[i] = mac_[i];
  }
  FDF_LOG(INFO, "CERISE-E1000-RAR0 pre=%08x:%08x post-reset=%08x:%08x", rah_pre, ral_pre,
          Rd(E1000_RAH(0)), Rd(E1000_RAL(0)));

  // Re-assert DRV_LOAD after the reset. The global reset in
  // e1000_reset_hw_ich8lan (E1000_CTRL | E1000_CTRL_RST) clears CTRL_EXT along
  // with the rest of the device, so the pre-reset write above does not survive
  // it. Linux's e1000e re-calls e1000e_get_hw_control() after reset for exactly
  // this reason; setting it only once, before, leaves the ME believing no OS
  // driver is present for the entire life of the driver.
  Wr(E1000_CTRL_EXT, Rd(E1000_CTRL_EXT) | E1000_CTRL_EXT_DRV_LOAD);

  // Match e1000e_reset(): once the live driver has reclaimed control after the
  // global reset, clear wakeup-mode programming before init_hw configures the
  // active data path.  This does not disable AMT; DRV_LOAD and the MANC/FWSM
  // state continue to describe the shared host/ME ownership boundary.
  Wr(E1000_WUC, 0);

  if (s32 st = e1000_init_hw(&hw_); st != E1000_SUCCESS) {
    FDF_LOG(ERROR, "e1000_init_hw failed: %d", st);
    Wr(E1000_CTRL_EXT, Rd(E1000_CTRL_EXT) & ~E1000_CTRL_EXT_DRV_LOAD);
    LogManageabilityState("init-failed");
    return ZX_ERR_INTERNAL;
  }
  LogManageabilityState("post-init");

  // Sunrise Point / Kaby Lake silicon errata workaround: AVOID A TRANSMIT HANG.
  //
  // The vendored FreeBSD shared code carries the constants for this
  // (E1000_TARC0_CB_MULTIQ_3_REQ / _2_REQ, e1000_ich8lan.h:127-128, and
  // E1000_IOSFPC, e1000_regs.h:114) but never applies the workaround --
  // e1000_initialize_hw_bits_ich8lan only sets TARC(0) bits 23/24/26/27
  // (e1000_ich8lan.c:5173-5177) and leaves the concurrent-request field alone.
  // Linux's e1000e applies it in e1000e_reset() for precisely
  // mac.type == e1000_pch_spt: cap TARC0 at two concurrent requests instead of
  // three, and set IOSFPC's RDMTS bit.
  //
  // This is not speculative housekeeping. MEASURED on this exact part: with the
  // link up at 1000/full and RX working (RDH advancing 2 -> 3 -> 5), TDH stayed
  // pinned at 0 while TDT advanced 10 -> 10 -> 11 -- the transmitter never
  // consumed a single descriptor. That is the signature this erratum produces,
  // and DHCP DISCOVER consequently never reached the wire.
  //
  // Applied after init_hw because initialize_hw_bits_ich8lan writes TARC(0).
  if (IsPchSptFamily(hw_.mac.type)) {
    Wr(E1000_IOSFPC, Rd(E1000_IOSFPC) | E1000_RCTL_RDMTS_HEX);
    const uint32_t tarc0 =
        (Rd(E1000_TARC(0)) & ~E1000_TARC0_CB_MULTIQ_3_REQ) | E1000_TARC0_CB_MULTIQ_2_REQ;
    Wr(E1000_TARC(0), tarc0);

    // Keep FEXTNVM11.DISABLE_MULR_FIX asserted across the reset.
    //
    // CORRECTION TO WHAT THIS COMMENT USED TO CLAIM, because the mistake is the
    // reason the transmitter stayed dead through three boots: this bit is NOT a
    // free-standing "i219 Tx hang" erratum workaround that e1000e_reset()
    // applies. In all of Linux's e1000e, E1000_FEXTNVM11_DISABLE_MULR_FIX is
    // written in exactly ONE place -- the opening lines of
    // e1000_flush_desc_rings() -- as a PREREQUISITE for the descriptor-ring
    // flush that actually clears the hang. Setting the bit and skipping the
    // flush, which is what this driver did, does nothing for the hang at all.
    // The flush now happens in FlushDescRings(), before the reset; this write
    // simply re-asserts the bit afterwards, since the global reset restores
    // FEXTNVM11 and Linux never clears it once set.
    Wr(E1000_FEXTNVM11, Rd(E1000_FEXTNVM11) | E1000_FEXTNVM11_DISABLE_MULR_FIX);

    FDF_LOG(INFO, "CERISE-E1000-SPT-ERRATA tarc0=%08x iosfpc=%08x fextnvm11=%08x",
            Rd(E1000_TARC(0)), Rd(E1000_IOSFPC), Rd(E1000_FEXTNVM11));
  }
  // NOTE: no explicit e1000_setup_link() call here. e1000_init_hw_ich8lan
  // already invokes mac->ops.setup_link (e1000_ich8lan.c:5102) and returns its
  // status; calling it a second time re-runs the copper/PHY configuration and
  // bounces the link again for no benefit -- an extra disturbance on a wire the
  // ME is using.

  FDF_LOG(INFO, "CERISE-E1000-RAR post-init rar0=%08x:%08x", Rd(E1000_RAH(0)),
          Rd(E1000_RAL(0)));

  FDF_LOG(INFO, "e1000: MAC %02x:%02x:%02x:%02x:%02x:%02x", mac_[0], mac_[1], mac_[2], mac_[3],
          mac_[4], mac_[5]);

  // ---------------------------------------------------------------------
  // Bring the MAC's side of the link up.
  //
  // e1000_setup_link_ich8lan bails out at its very FIRST line when the ME has
  // PHY reset blocked (e1000_ich8lan.c:5238 --
  // `if (hw->phy.ops.check_reset_block(hw)) return E1000_SUCCESS;`), and on this
  // machine check_reset_block returns E1000_BLK_PHY_RESET (logged above as
  // reset_block=12). So mac->ops.setup_physical_interface -- for pch_spt that is
  // e1000_setup_copper_link_pch_lpt (assigned at :821) -- NEVER RUNS, and the
  // MAC bits it would have set are left untouched: CTRL.SLU ("set link up") and
  // a cleared FRCSPD/FRCDPX (:5384-5387).
  //
  // The PHY is already up because the ME is passing manageability traffic over
  // it. A reset block is an ownership boundary, not merely a request to avoid
  // PHY_RST: rewriting PHY_AUTONEG_ADV or asserting RESTART_AUTO_NEG can still
  // interrupt the firmware-owned link. Preserve that state while the bit is
  // clear. A future transition of RSPCIPHY is not an invitation to reset or
  // run a reset-time setup sequence against a live shared interface.
  //
  // Every other family this driver binds reaches setup_physical_interface
  // normally through init_hw and keeps the policy programmed there.
  // Take a fresh nonblocking ownership sample because firmware can change
  // RSPCIPHY while reset/init runs. This is used only to avoid touching the
  // PHY; it never arms deferred work against the live interface.
  const bool phy_blocked_after_init =
      IsPchManageabilityFamily(hw_.mac.type) &&
      !(Rd(E1000_FWSM) & E1000_ICH_FWSM_RSPCIPHY);
  const bool phy_setup_may_have_been_skipped =
      IsPchManageabilityFamily(hw_.mac.type) &&
      (reset_blocked != E1000_SUCCESS || phy_blocked_after_init);
  if (phy_setup_may_have_been_skipped) {
    uint32_t ctrl = Rd(E1000_CTRL);
    ctrl |= E1000_CTRL_SLU | E1000_CTRL_ASDE;
    ctrl &= ~(E1000_CTRL_FRCSPD | E1000_CTRL_FRCDPX);
    Wr(E1000_CTRL, ctrl);
    // Do not call PHY read operations or e1000_check_for_link here.
    // e1000_check_for_copper_link_ich8lan is not observational on PCH: after
    // reading the PHY it can write RX configuration, PLL, power-management and
    // page-776 registers. RSPCIPHY being clear means all such access belongs to
    // firmware, including diagnostics and link-status interrupt handling.
    FDF_LOG(INFO,
            "CERISE-E1000-PHY firmware-owned owner=%s fwsm=%08x status=%08x ctrl=%08x",
            phy_blocked_after_init ? "firmware" : "host", Rd(E1000_FWSM),
            Rd(E1000_STATUS), Rd(E1000_CTRL));
  }
  const uint32_t status = Rd(E1000_STATUS);
  const uint16_t speed = (status & E1000_STATUS_SPEED_1000)
                             ? SPEED_1000
                             : ((status & E1000_STATUS_SPEED_100) ? SPEED_100 : SPEED_10);
  const uint16_t duplex = (status & E1000_STATUS_FD) ? FULL_DUPLEX : HALF_DUPLEX;
  FDF_LOG(INFO, "CERISE-E1000-LINK status=%08x lu=%d speed=%u duplex=%s ctrl=%08x", status,
          (status & E1000_STATUS_LU) ? 1 : 0, speed, duplex == FULL_DUPLEX ? "full" : "half",
          Rd(E1000_CTRL));
  return ZX_OK;
}

void E1000Driver::LogManageabilityState(const char* phase) {
  FDF_LOG(INFO,
          "CERISE-E1000-MNG-STATE phase=%s manc=%08x manc2h=%08x fwsm=%08x factps=%08x "
          "swsm=%08x ctrl_ext=%08x rctl=%08x wuc=%08x",
          phase, Rd(E1000_MANC), Rd(E1000_MANC2H), Rd(E1000_FWSM), Rd(E1000_FACTPS),
          Rd(E1000_SWSM), Rd(E1000_CTRL_EXT), Rd(E1000_RCTL), Rd(E1000_WUC));
}

// ---------------------------------------------------------------------------
// i219 descriptor-ring flush.
//
// MEASURED RESULT FIRST, so nobody re-derives it: this is a REAL omission and
// it is worth having, but it is NOT the cause of the transmit hang on the
// CF-SZ5. On the unit, with this code in place:
//
//   CERISE-E1000-FLUSH cfg_e4_before=0000 required=0 tdlen=4096
//                      flushed_tx=0 flushed_rx=0 cfg_e4_after=0000
//
// The device's own FLUSH_DESC_REQUIRED bit was CLEAR at attach, so the i219
// "unit hang state" was never entered and no flush was needed. That refutes the
// hypothesis this function was written to test. It is kept because it is what
// Linux does unconditionally for this family and because the state it guards
// against is, by Intel's own account, unrecoverable short of a PCI reset --
// paying a config-space read per attach to never hit that is a good trade.
//
// Why the bit was clear is worth knowing too: Ubuntu's e1000e runs the same
// flush on e1000e_down(), so the previous owner hands the device over clean.
// A boot that reaches cerise from firmware alone might not be so lucky.
//
// Linux's e1000e says it plainly, at the head of e1000_flush_desc_rings()
// (drivers/net/ethernet/intel/e1000e/netdev.c):
//
//     In i219, the descriptor rings must be emptied before resetting the HW
//     or before changing the device state to D3 during runtime (runtime PM).
//     Failure to do this will cause the HW to enter a unit hang state which
//     can only be released by PCI reset on the device
//
// and e1000e_reset() therefore runs it on EVERY reset of EVERY part from
// e1000_pch_spt onwards, immediately before mac->ops.reset_hw():
//
//     if (hw->mac.type >= e1000_pch_spt)
//             e1000_flush_desc_rings(adapter);
//     mac->ops.reset_hw(hw);
//
// "Unit hang state" reads exactly like the observed symptom -- TDH pinned at 0
// while TDT advances, surviving a software reset, RX unaffected, the ME's own
// transmits still counting -- which is why it was the leading hypothesis. The
// hardware said no; see the measurement above.
//
// The vendored FreeBSD/Intel shared code does not implement this AT ALL: there
// is no flush_desc_rings, flush_tx_ring or flush_rx_ring anywhere under
// third_party/e1000. So unlike the TARC0/IOSFPC/FEXTNVM11 errata -- which were
// vendored-but-unreferenced -- this one had to be ported.
//
// One genuine documentation bug was found on the way here, and it is worth
// recording because it is how a whole mechanism went missing: the driver wrote
// FEXTNVM11 |= DISABLE_MULR_FIX and described it as a standalone erratum
// workaround "e1000e sets in e1000e_reset()". It is not. That write appears in
// exactly ONE place in all of e1000e, and it is the FIRST LINE OF THIS
// FUNCTION -- a prerequisite that lets the flush drain the unit. The driver had
// implemented the prologue of a workaround and omitted the workaround, while
// its comment asserted the opposite.
//
// The gating condition is a PCI CONFIG-space read, not an MMIO one, which is
// also why nothing in a register dump of BAR0 ever revealed it.
void E1000Driver::FlushDescRings() {
  if (!IsPchSptFamily(hw_.mac.type)) {
    return;
  }
  // Sample the device's own hang report FIRST, before this function perturbs
  // anything, so the logged value describes the state we inherited.
  uint16_t hang_state = 0;
  PciRead16(kPciCfgDescRingStatus, &hang_state);
  const uint16_t hang_before = hang_state;
  // PciRead16 yields 0xffff when the config read fails, and 0xffff has bit 8
  // set. Never let a failed read talk us into DMA-ing a dummy frame.
  const bool hang_valid = hang_before != 0xffff;

  // Step 1 (Linux: "First, disable MULR fix in FEXTNVM11"). A prerequisite for
  // the drain below, not a workaround in its own right.
  Wr(E1000_FEXTNVM11, Rd(E1000_FEXTNVM11) | E1000_FEXTNVM11_DISABLE_MULR_FIX);

  uint32_t tdlen = Rd(E1000_TDLEN(0));
  bool flushed_tx = false, flushed_rx = false;

  // NOTHING BELOW THIS POINT RUNS UNLESS THE DEVICE ASKED FOR IT.
  //
  // Linux touches no rings and no TCTL when the hang bit is clear, and neither
  // do we. That restraint is the point on a controller the ME shares: an
  // unconditional transmitter disable, even a 10ms one, is a disturbance to
  // traffic that is not ours. On this machine the bit has always measured
  // clear, so in practice this function is a config-space read and one FEXTNVM
  // write.
  if (hang_valid && (hang_state & kFlushDescRequired)) {
    // Quiesce the transmitter BEFORE re-basing its ring. Firmware may hand us
    // the device with TCTL.EN set and a stale TDH/TDT pair; repointing TDBAL
    // while the transmitter is live would invite it to fetch descriptors
    // [TDH, TDT) out of memory we just claimed. This is the same step
    // e1000_reset_hw_ich8lan performs a moment later (E1000_WRITE_REG(hw,
    // E1000_TCTL, E1000_TCTL_PSP), e1000_ich8lan.c:4967).
    Wr(E1000_TCTL, Rd(E1000_TCTL) & ~E1000_TCTL_EN);
    (void)Rd(E1000_STATUS);  // posted-write flush
    zx_nanosleep(zx_deadline_after(ZX_MSEC(10)));

    // Point BOTH rings at memory we own before flushing through either.
    //
    // Linux can skip this because e1000e_reset() runs on an adapter whose rings
    // are already configured; at driver attach we have no such guarantee.
    // Rebasing the receive ring matters just as much as the transmit ring:
    // FlushRxRing momentarily sets RCTL.EN, and if RDBAL/RDT still described a
    // previous owner's ring the device could DMA received frames into memory
    // that is no longer anybody's. Linux's own "|| !tdlen" guard exists for the
    // same reason -- never flush through a ring that is not set up.
    Wr(E1000_TDBAL(0), static_cast<uint32_t>(tx_ring_phys_));
    Wr(E1000_TDBAH(0), static_cast<uint32_t>(tx_ring_phys_ >> 32));
    Wr(E1000_TDLEN(0), kTxRingBytes);
    Wr(E1000_TDH(0), 0);
    Wr(E1000_TDT(0), 0);
    Wr(E1000_RDBAL(0), static_cast<uint32_t>(rx_ring_phys_));
    Wr(E1000_RDBAH(0), static_cast<uint32_t>(rx_ring_phys_ >> 32));
    Wr(E1000_RDLEN(0), kRxRingBytes);
    Wr(E1000_RDH(0), 0);
    Wr(E1000_RDT(0), 0);  // no receive descriptors are available to the device
    tdlen = Rd(E1000_TDLEN(0));

    if (tdlen != 0) {
      FlushTxRing();
      flushed_tx = true;
      // Recheck: the fault may have been on the receive ring instead. A failed
      // config read reads back 0xffff, whose bit 8 is set -- never let that
      // talk us into the receive flush either.
      uint16_t recheck = 0;
      PciRead16(kPciCfgDescRingStatus, &recheck);
      if (recheck != 0xffff && (recheck & kFlushDescRequired)) {
        FlushRxRing();
        flushed_rx = true;
      }
    }
  }
  uint16_t hang_after = 0;
  PciRead16(kPciCfgDescRingStatus, &hang_after);

  // The decisive measurement. hang_before bit 8 tells us, from the DEVICE's own
  // report rather than from inference, whether the transmit unit was wedged on
  // entry; hang_after tells us whether the flush cleared it. Logged
  // unconditionally, including when no flush was needed, because "bit 8 was
  // clear all along" REFUTES this diagnosis and is exactly as valuable.
  FDF_LOG(INFO,
          "CERISE-E1000-FLUSH cfg_e4_before=%04x required=%d tdlen=%u flushed_tx=%d "
          "flushed_rx=%d cfg_e4_after=%04x fextnvm11=%08x",
          hang_before, (hang_before & kFlushDescRequired) ? 1 : 0, tdlen, flushed_tx,
          flushed_rx, hang_after, Rd(E1000_FEXTNVM11));

  // Deliberately NOT zeroing the ring here. FlushTxRing leaves TCTL.EN set and
  // only waits a fixed 250us, so the device may still be retiring the dummy
  // descriptor; racing it with a memset would have the CPU and the device
  // touching the same descriptor. Linux does not do it either, and it is not
  // needed -- QueueTx writes every field of a descriptor before arming it, and
  // the hardware reset that follows immediately re-initialises the unit.
}

// Port of Linux e1000_flush_tx_ring(): push one dummy descriptor through the
// transmitter so the wedged unit retires its internal state. The descriptor
// deliberately names the ring itself as its data buffer -- the bytes are
// irrelevant, only the fetch-and-retire matters -- and carries neither EOP nor
// RS, so no frame is completed onto the wire and no writeback is expected.
void E1000Driver::FlushTxRing() {
  const uint32_t tctl = Rd(E1000_TCTL);
  Wr(E1000_TCTL, tctl | E1000_TCTL_EN);

  volatile e1000_tx_desc& d = tx_ring_[0];
  d.buffer_addr = tx_ring_phys_;
  d.lower.data = E1000_TXD_CMD_IFCS | kFlushTxDummyLen;
  d.upper.data = 0;
  // Descriptor must be visible to the device before the tail write that arms
  // it. The ring is a cached mapping and TDT is uncached device MMIO.
  std::atomic_thread_fence(std::memory_order_seq_cst);
  Wr(E1000_TDT(0), 1);
  // Linux sleeps 200-250us here; the unit needs time to retire the descriptor.
  zx_nanosleep(zx_deadline_after(ZX_USEC(250)));
}

// Port of Linux e1000_flush_rx_ring(): mark the receive ring consumed and leave
// the receiver disabled. Only reached when the transmit flush did not clear the
// hang bit, i.e. when the fault is on the receive side.
void E1000Driver::FlushRxRing() {
  const uint32_t rctl = Rd(E1000_RCTL);
  Wr(E1000_RCTL, rctl & ~E1000_RCTL_EN);
  (void)Rd(E1000_STATUS);  // posted-write flush
  zx_nanosleep(zx_deadline_after(ZX_USEC(150)));

  // Zero the low 14 bits (prefetch and host thresholds), then set pthresh=31,
  // hthresh=1 and descriptor (not cache-line) granularity.
  uint32_t rxdctl = Rd(E1000_RXDCTL(0)) & 0xffffc000;
  rxdctl |= 0x1f | (1u << 8) | kRxdctlThreshUnitDesc;
  Wr(E1000_RXDCTL(0), rxdctl);

  // Momentarily enable the receiver so the change takes effect, then leave it
  // disabled -- EnableRxTx programs RCTL properly later.
  Wr(E1000_RCTL, rctl | E1000_RCTL_EN);
  (void)Rd(E1000_STATUS);
  zx_nanosleep(zx_deadline_after(ZX_USEC(150)));
  Wr(E1000_RCTL, rctl & ~E1000_RCTL_EN);
}

// A single place that reports everything needed to tell the remaining transmit
// hypotheses apart, INCLUDING the descriptor memory read back from the ring
// rather than the driver's idea of what it wrote there. Cheap, and called only
// a handful of times.
void E1000Driver::LogTxForensics(const char* where, uint16_t desc_index) {
  uint16_t hang_state = 0;
  PciRead16(kPciCfgDescRingStatus, &hang_state);
  uint16_t cmd = 0;
  PciRead16(0x04, &cmd);
  // Read the descriptor back out of ring memory. This is the driver's view of
  // the same bytes the device fetches, and it is the only way to tell "we wrote
  // a malformed descriptor" from "the device never looked at it".
  volatile e1000_tx_desc& d = tx_ring_[desc_index % kNumTxDesc];
  FDF_LOG(INFO,
          "CERISE-E1000-TXDIAG %s tctl=%08x tipg=%08x tarc0=%08x tarc1=%08x txdctl0=%08x "
          "txdctl1=%08x pba=%08x pbs=%08x tdbal=%08x tdbah=%08x tdlen=%u tdh=%u tdt=%u "
          "tidv=%08x tadv=%08x ctrl=%08x status=%08x cfg_e4=%04x pcicmd=%04x "
          "d[%u].addr=%016llx lower=%08x upper=%08x ring_phys=%016llx",
          where, Rd(E1000_TCTL), Rd(E1000_TIPG), Rd(E1000_TARC(0)), Rd(E1000_TARC(1)),
          Rd(E1000_TXDCTL(0)), Rd(E1000_TXDCTL(1)), Rd(E1000_PBA), Rd(E1000_PBS),
          Rd(E1000_TDBAL(0)), Rd(E1000_TDBAH(0)), Rd(E1000_TDLEN(0)), Rd(E1000_TDH(0)),
          Rd(E1000_TDT(0)), Rd(E1000_TIDV), Rd(E1000_TADV), Rd(E1000_CTRL), Rd(E1000_STATUS),
          hang_state, cmd, desc_index % kNumTxDesc,
          static_cast<unsigned long long>(d.buffer_addr), d.lower.data, d.upper.data,
          static_cast<unsigned long long>(tx_ring_phys_));
  // Second line: the transmit FIFO pointers and the counters that separate the
  // surviving hypotheses.
  //  * TDFH/TDFT/TDFPC -- did the descriptor's DATA ever reach the Tx FIFO? A
  //    stuck TDH with a moving TDFT would mean something very different from
  //    both being frozen.
  //  * xoffrxc -- MEASURED on the unit, cerise leaves CTRL.RFCE SET
  //    (ctrl=08180240) where Linux leaves it CLEAR (ctrl=40180240), i.e. this
  //    driver honours incoming PAUSE frames and Linux does not. A link partner
  //    holding us XOFF would stall the transmitter with the ring perfectly
  //    configured. This counter is how that stops being speculation.
  //  * colc/latecol/ecol/tncrs/dc -- a transmitter that is trying and failing
  //    on the wire, versus one that never started.
  // All of these are clear-on-read, so each line reports the delta since the
  // previous line.
  FDF_LOG(INFO,
          "CERISE-E1000-TXDIAG2 %s tdfh=%08x tdft=%08x tdfhs=%08x tdfts=%08x tdfpc=%08x "
          "gptc=%u tpt=%u colc=%u latecol=%u ecol=%u tncrs=%u dc=%u xoffrxc=%u xonrxc=%u",
          where, Rd(E1000_TDFH), Rd(E1000_TDFT), Rd(E1000_TDFHS), Rd(E1000_TDFTS),
          Rd(E1000_TDFPC), Rd(E1000_GPTC), Rd(E1000_TPT), Rd(E1000_COLC), Rd(E1000_LATECOL),
          Rd(E1000_ECOL), Rd(E1000_TNCRS), Rd(E1000_DC), Rd(E1000_XOFFRXC), Rd(E1000_XONRXC));
}

zx_status_t E1000Driver::AllocRings() {
  const uint32_t ring_bytes = kTxRingBytes + kRxRingBytes + kScratchBytes;
  if (zx_status_t st = zx::vmo::create_contiguous(bti_, ring_bytes, 0, &ring_vmo_); st != ZX_OK) {
    FDF_LOG(ERROR, "descriptor ring vmo alloc failed: %s", zx_status_get_string(st));
    return st;
  }
  zx_paddr_t phys = 0;
  if (zx_status_t st = bti_.pin(ZX_BTI_PERM_READ | ZX_BTI_PERM_WRITE | ZX_BTI_CONTIGUOUS, ring_vmo_,
                                0, ring_bytes, &phys, 1, &ring_pmt_);
      st != ZX_OK) {
    FDF_LOG(ERROR, "descriptor ring pin failed: %s", zx_status_get_string(st));
    return st;
  }
  ring_phys_ = phys;
  if (zx_status_t st = zx::vmar::root_self()->map(ZX_VM_PERM_READ | ZX_VM_PERM_WRITE, 0, ring_vmo_,
                                                  0, ring_bytes, &ring_virt_);
      st != ZX_OK) {
    FDF_LOG(ERROR, "descriptor ring map failed: %s", zx_status_get_string(st));
    return st;
  }
  memset(reinterpret_cast<void*>(ring_virt_), 0, ring_bytes);
  tx_ring_ = reinterpret_cast<volatile e1000_tx_desc*>(ring_virt_);
  rx_ring_ = reinterpret_cast<volatile e1000_rx_desc*>(ring_virt_ + kTxRingBytes);
  tx_ring_phys_ = ring_phys_;
  rx_ring_phys_ = ring_phys_ + kTxRingBytes;
  scratch_virt_ = reinterpret_cast<uint8_t*>(ring_virt_ + kTxRingBytes + kRxRingBytes);
  scratch_phys_ = ring_phys_ + kTxRingBytes + kRxRingBytes;
  return ZX_OK;
}

void E1000Driver::EnableRxTx() {
  LogManageabilityState("netdevice-start-before");
  // Program TX ring registers.
  Wr(E1000_TDBAL(0), static_cast<uint32_t>(tx_ring_phys_));
  Wr(E1000_TDBAH(0), static_cast<uint32_t>(tx_ring_phys_ >> 32));
  Wr(E1000_TDLEN(0), kTxRingBytes);
  Wr(E1000_TDH(0), 0);
  Wr(E1000_TDT(0), 0);
  tx_next_ = tx_reclaim_ = 0;
  // Transmit Inter-Packet Gap. The transmitter will not move descriptors with a
  // zero IPG, and nothing else in this driver programs it: the shared code only
  // ever read-modify-writes the IPGT field from
  // e1000_check_for_copper_link_ich8lan, so if that path is skipped or aborts
  // early TIPG keeps whatever the reset left behind. These are the shared code's
  // own documented defaults (e1000_defines.h:455-466).
  Wr(E1000_TIPG, DEFAULT_82543_TIPG_IPGT_COPPER |
                     (DEFAULT_82543_TIPG_IPGR1 << E1000_TIPG_IPGR1_SHIFT) |
                     (DEFAULT_82543_TIPG_IPGR2 << E1000_TIPG_IPGR2_SHIFT));
  // TCTL: READ-MODIFY-WRITE, never a wholesale store.
  //
  // The previous wholesale write clobbered bits this part comes up with set and
  // expects to keep. MEASURED on the CF-SZ5's own I219-LM: Linux's working
  // e1000e leaves TCTL = 0x3103f0fa, while this driver produced 0x000400fa.
  // The difference is not cosmetic -- the wholesale store dropped
  //   bit 24 RTLC  (re-transmit on late collision),
  //   bit 28 MULR  (multiple request support),
  //   bit 29       (reserved, but set by the hardware/init_hw on this part),
  // and set COLD to 64 where the shared code's own E1000_COLLISION_DISTANCE
  // is 63.
  //
  // MULR in particular is not ours to clear behind the shared code's back:
  // e1000_initialize_hw_bits_ich8lan (e1000_ich8lan.c:5180-5186) decides
  // TARC(1) bit 28 by reading TCTL.MULR at init_hw time --
  //     if (E1000_READ_REG(hw, E1000_TCTL) & E1000_TCTL_MULR)
  //             reg &= ~(1 << 28);
  //     else
  //             reg |= (1 << 28);
  // -- so clearing MULL afterwards leaves the transmit arbiter configured for
  // the opposite mode to the one the transmitter is now in. Linux avoids this
  // by construction: e1000_configure_tx() does
  //     tctl = er32(TCTL); tctl &= ~E1000_TCTL_CT; tctl |= PSP|RTLC|CT;
  // preserving everything it does not name, and then lets
  // mac->ops.config_collision_dist() own the COLD field.
  uint32_t tctl = Rd(E1000_TCTL);
  tctl &= ~E1000_TCTL_CT;
  tctl |= E1000_TCTL_EN | E1000_TCTL_PSP | E1000_TCTL_RTLC |
          (E1000_COLLISION_THRESHOLD << E1000_CT_SHIFT);
  Wr(E1000_TCTL, tctl);
  // Owns the COLD field, and knows where it lives: the generic implementation
  // writes TCTL.COLD (82540/82574/I219) while the I211 one writes TCTL_EXT.COLD.
  // Never called before now, though it is wired into mac.ops for every family
  // this driver binds. (It programs the family's fixed collision distance; it
  // is not duplex-dependent, whatever an earlier comment here claimed.)
  e1000_config_collision_dist(&hw_);

  // Program RX ring registers.
  Wr(E1000_RDBAL(0), static_cast<uint32_t>(rx_ring_phys_));
  Wr(E1000_RDBAH(0), static_cast<uint32_t>(rx_ring_phys_ >> 32));
  Wr(E1000_RDLEN(0), kRxRingBytes);
  Wr(E1000_RDH(0), 0);
  Wr(E1000_RDT(0), 0);
  rx_tail_ = 0;
  rx_clean_ = 0;
  // RCTL: read-modify-write, for the same reason as TCTL above.  In particular,
  // never unconditionally set SECRC on an I219: it strips the FCS from both
  // host DMA and the SMBus copy consumed by management firmware.  We retain it
  // there and remove it in software before delivering the host frame.
  const uint32_t rctl_before = Rd(E1000_RCTL);
  const uint32_t rctl = ConfigureReceiveControl(rctl_before, rx_hardware_strips_fcs_);
  Wr(E1000_RCTL, rctl);
  FDF_LOG(INFO, "CERISE-E1000-RCTL before=%08x after=%08x hw_strips_fcs=%d", rctl_before,
          rctl, rx_hardware_strips_fcs_);

  // Read the ring configuration straight back out of the device. A stuck TDH
  // with an advancing TDT means the transmitter never accepted the queue, and
  // the first thing to rule out is that these registers do not hold what we
  // think we wrote.
  FDF_LOG(INFO,
          "CERISE-E1000-RINGS tctl=%08x rctl=%08x tipg=%08x tdbal=%08x tdlen=%u tdh=%u tdt=%u "
          "rdbal=%08x rdlen=%u rdh=%u rdt=%u txdctl=%08x status=%08x",
          Rd(E1000_TCTL), Rd(E1000_RCTL), Rd(E1000_TIPG), Rd(E1000_TDBAL(0)), Rd(E1000_TDLEN(0)),
          Rd(E1000_TDH(0)), Rd(E1000_TDT(0)), Rd(E1000_RDBAL(0)), Rd(E1000_RDLEN(0)),
          Rd(E1000_RDH(0)), Rd(E1000_RDT(0)), Rd(E1000_TXDCTL(0)), Rd(E1000_STATUS));
  LogManageabilityState("netdevice-start-after");
  LogTxForensics("post-enable", 0);
  TxSelfTest();
}

void E1000Driver::DisableRxTx() {
  Wr(E1000_IMC, 0xffffffff);
  Wr(E1000_RCTL, Rd(E1000_RCTL) & ~E1000_RCTL_EN);
  Wr(E1000_TCTL, Rd(E1000_TCTL) & ~E1000_TCTL_EN);
  (void)Rd(E1000_STATUS);  // flush posted writes before touching ring state
  zx_nanosleep(zx_deadline_after(ZX_MSEC(10)));
}

void E1000Driver::DrainOutstandingBuffers(fdf::Arena& arena, zx_status_t tx_status) {
  std::array<netdev::wire::TxResult, kMaxDepth> tx_ret;
  size_t tx_count = 0;
  {
    std::lock_guard lock(tx_lock_);
    while (tx_reclaim_ != tx_next_) {
      tx_ret[tx_count++] = {.id = tx_buf_id_[tx_reclaim_], .status = tx_status};
      tx_reclaim_ = static_cast<uint16_t>((tx_reclaim_ + 1) % kNumTxDesc);
    }
  }
  if (tx_count != 0) {
    std::lock_guard state(state_lock_);
    if (ifc_.is_valid()) {
      (void)ifc_.buffer(arena)->CompleteTx(
          fidl::VectorView<netdev::wire::TxResult>::FromExternal(tx_ret.data(), tx_count));
    }
  }

  std::array<netdev::wire::RxBuffer, kMaxDepth> rx_ret;
  std::array<netdev::wire::RxBufferPart, kMaxDepth> rx_parts;
  size_t rx_count = 0;
  {
    std::lock_guard lock(rx_lock_);
    for (uint16_t i = 0; i < kNumRxDesc; i++) {
      if (!rx_slot_valid_[i]) {
        continue;
      }
      rx_parts[rx_count] = {.id = rx_buf_id_[i], .offset = 0, .length = 0};
      rx_ret[rx_count] = netdev::wire::RxBuffer{
          .meta = {.port = kPortId, .frame_type = netdrv::wire::FrameType::kEthernet},
          .data = fidl::VectorView<netdev::wire::RxBufferPart>::FromExternal(&rx_parts[rx_count], 1),
      };
      rx_slot_valid_[i] = false;
      rx_count++;
    }
  }
  if (rx_count != 0) {
    std::lock_guard state(state_lock_);
    if (ifc_.is_valid()) {
      (void)ifc_.buffer(arena)->CompleteRx(
          fidl::VectorView<netdev::wire::RxBuffer>::FromExternal(rx_ret.data(), rx_count));
    }
  }
}

void E1000Driver::NotifyPortStatus() {
  std::lock_guard state(state_lock_);
  if (!ifc_.is_valid()) {
    return;
  }
  fdf::Arena arena(0u);
  (void)ifc_.buffer(arena)->PortStatusChanged(kPortId, ReadPortStatus(arena));
}

// A transmit the DRIVER originates, with nothing else in the loop.
//
// Why this exists: every observation so far has come through netstack3, which
// means every failure has had at least four candidate explanations -- the
// device, the descriptor contents, the netdevice buffer plumbing, or the
// physical addresses that vmo_store hands back for framework-supplied VMOs.
// This test removes three of them.
//
// The frame's DMA source is the scratch page at the tail of the SAME pinned
// contiguous VMO that holds the descriptor rings. The device is already
// provably able to read that allocation -- it fetches receive descriptors out
// of it every time RDH advances -- so an unreachable buffer address cannot be
// the reason this particular descriptor goes unserviced.
//
// So the result is a clean split:
//   TDH advances / DD set  -> the transmit unit works; the fault is upstream,
//                             in the netdevice buffer path (pinned addresses,
//                             lengths, or completion bookkeeping).
//   TDH stays at 0         -> the transmit unit itself refuses to fetch, and
//                             no amount of work on the netdevice side will
//                             help. The registers logged alongside are then
//                             the whole story.
//
// The frame is addressed from this NIC to this NIC with the IEEE local
// experimental EtherType 0x88b5, so a switch learns nothing new and no host on
// the segment has any reason to act on it.
void E1000Driver::TxSelfTest() {
  if (scratch_virt_ == nullptr) {
    return;
  }
  memset(scratch_virt_, 0, kSelfTestFrameLen);
  memcpy(scratch_virt_ + 0, mac_, 6);  // destination: ourselves
  memcpy(scratch_virt_ + 6, mac_, 6);  // source
  scratch_virt_[12] = 0x88;
  scratch_virt_[13] = 0xb5;
  memcpy(scratch_virt_ + 14, "CERISE-E1000-SELFTEST", 21);

  const uint32_t tdh_before = Rd(E1000_TDH(0));
  volatile e1000_tx_desc& d = tx_ring_[0];
  d.buffer_addr = scratch_phys_;
  d.lower.data = kSelfTestFrameLen | E1000_TXD_CMD_EOP | E1000_TXD_CMD_RS | E1000_TXD_CMD_IFCS;
  d.upper.data = 0;
  std::atomic_thread_fence(std::memory_order_seq_cst);
  Wr(E1000_TDT(0), 1);

  // Poll for up to ~200ms. A working transmitter retires this in microseconds.
  uint32_t tdh = tdh_before;
  uint8_t status = 0;
  int waited_us = 0;
  for (; waited_us < 200000; waited_us += 500) {
    zx_nanosleep(zx_deadline_after(ZX_USEC(500)));
    tdh = Rd(E1000_TDH(0));
    status = d.upper.fields.status;
    if (tdh != tdh_before || (status & E1000_TXD_STAT_DD)) {
      break;
    }
  }
  const bool consumed = (tdh != tdh_before) || (status & E1000_TXD_STAT_DD);
  FDF_LOG(INFO,
          "CERISE-E1000-SELFTEST consumed=%d tdh_before=%u tdh_after=%u tdt=%u dd=%d "
          "status=%02x waited_us=%d buf_phys=%016llx len=%u",
          consumed, tdh_before, tdh, Rd(E1000_TDT(0)), (status & E1000_TXD_STAT_DD) ? 1 : 0,
          status, waited_us, static_cast<unsigned long long>(scratch_phys_), kSelfTestFrameLen);
  LogTxForensics(consumed ? "selftest-pass" : "selftest-FAIL", 0);

  // Put the ring back into a consistent state either way. When the descriptor
  // was NOT consumed, TDH is still 0 and retracting the tail to match is legal
  // and leaves nothing half-armed for the netstack's first real packet.
  const uint32_t tdh_final = Rd(E1000_TDH(0));
  d.upper.data = 0;
  d.lower.data = 0;
  d.buffer_addr = 0;
  std::atomic_thread_fence(std::memory_order_seq_cst);
  Wr(E1000_TDT(0), tdh_final);
  tx_next_ = tx_reclaim_ = static_cast<uint16_t>(tdh_final % kNumTxDesc);
}

zx_status_t E1000Driver::SetupInterrupt() {
  auto modes = fidl::Call(pci_)->GetInterruptModes();
  if (modes.is_error()) {
    return ZX_ERR_INTERNAL;
  }
  fuchsia_hardware_pci::InterruptMode mode = fuchsia_hardware_pci::InterruptMode::kLegacy;
  irq_is_legacy_ = true;
  if (modes->modes().msi_count() > 0) {
    mode = fuchsia_hardware_pci::InterruptMode::kMsi;
    irq_is_legacy_ = false;
  }
  if (auto r = fidl::Call(pci_)->SetInterruptMode({mode, 1}); r.is_error()) {
    // Fall back to legacy if MSI setup failed.
    if (!irq_is_legacy_) {
      irq_is_legacy_ = true;
      if (auto r2 = fidl::Call(pci_)->SetInterruptMode(
              {fuchsia_hardware_pci::InterruptMode::kLegacy, 1});
          r2.is_error()) {
        return ZX_ERR_INTERNAL;
      }
    } else {
      return ZX_ERR_INTERNAL;
    }
  }
  auto irq = fidl::Call(pci_)->MapInterrupt(0);
  if (irq.is_error()) {
    FDF_LOG(ERROR, "MapInterrupt failed");
    return ZX_ERR_INTERNAL;
  }
  irq_ = std::move(irq->interrupt());
  FDF_LOG(INFO, "e1000: interrupt mode=%s", irq_is_legacy_ ? "legacy" : "msi");
  return ZX_OK;
}

zx_status_t E1000Driver::AddNetdevChild() {
  E1000StartMark("CERISE-E1000-COMPAT-BEGIN\n");
  if (zx::result r =
          compat_server_.Initialize(incoming_, outgoing(), node_name_, kChildNodeName);
      r.is_error()) {
    FDF_LOG(ERROR, "compat server init failed: %s", r.status_string());
    return r.status_value();
  }
  E1000StartMark("CERISE-E1000-COMPAT-END\n");
  auto protocol = [this](fdf::ServerEnd<netdev::NetworkDeviceImpl> server_end) mutable {
    fdf::BindServer(netdevice_dispatcher_.get(), std::move(server_end), this);
  };
  netdev::Service::InstanceHandler handler({.network_device_impl = std::move(protocol)});
  E1000StartMark("CERISE-E1000-NETDEV-ADDSERVICE-BEGIN\n");
  if (auto st = outgoing()->AddService<netdev::Service>(std::move(handler)); st.is_error()) {
    FDF_LOG(ERROR, "AddService failed: %s", st.status_string());
    return st.error_value();
  }
  E1000StartMark("CERISE-E1000-NETDEV-ADDSERVICE-END\n");

  std::vector offers = compat_server_.CreateOffers2();
  offers.push_back(fdf::MakeOffer2<netdev::Service>());

  auto [controller_client, controller_server] =
      fidl::Endpoints<fuchsia_driver_framework::NodeController>::Create();
  fuchsia_driver_framework::NodeAddArgs args{{
      .name = kChildNodeName,
      .offers2 = std::move(offers),
  }};
  E1000StartMark("CERISE-E1000-NETDEV-ADDCHILD-BEGIN\n");
  auto result = fidl::Call(node())->AddChild(
      {{.args = std::move(args), .controller = std::move(controller_server), .node = {}}});
  if (result.is_error()) {
    FDF_LOG(ERROR, "AddChild failed");
    return ZX_ERR_INTERNAL;
  }
  E1000StartMark("CERISE-E1000-NETDEV-ADDCHILD-END\n");
  netdev_child_ = std::move(controller_client);
  return ZX_OK;
}

void E1000Driver::Stop(fdf::StopCompleter completer) {
  // e1000e's release_hw_control(): hand the interface back to firmware, so the
  // ME resumes maintaining the link/manageability traffic once no OS driver
  // owns the part. Linux does this on close/remove; skipping it is how a NIC
  // ends up with neither the driver nor the ME driving it.
  // Stop queue work and DMA before joining the interrupt thread, then disable
  // bus mastering before handing the part back to firmware.
  // The IRQ thread touches PHY/MAC state (the LSC handler calls into the shared
  // code), and CTRL_EXT.DRV_LOAD is precisely the flag that tells the ME no OS
  // driver owns the device any more. Clearing it while a link-status handler is
  // still in flight would have us driving a device we have just disclaimed --
  // on this part that is the ME's device too.
  // Stop DMA before relinquishing ownership. Driver-manager teardown can call
  // this while the NetworkDevice is still started, so do not assume its Stop
  // hook already ran.
  started_.store(false);
  {
    std::lock_guard hardware(hardware_lock_);
    if (membase_ != 0) {
      DisableRxTx();
      LogManageabilityState("driver-stop-dma-disabled");
    }
  }
  irq_running_ = false;
  if (irq_.is_valid()) {
    irq_.destroy();
  }
  if (irq_thread_.joinable()) {
    irq_thread_.join();
  }
  if (pci_.is_valid()) {
    if (auto result = fidl::Call(pci_)->SetBusMastering(false); result.is_error()) {
      FDF_LOG(WARNING, "SetBusMastering(false) failed during Stop");
    }
  }
  // e1000e's release_hw_control(), now that nothing else can touch the part.
  if (membase_ != 0) {
    std::lock_guard hardware(hardware_lock_);
    Wr(E1000_CTRL_EXT, Rd(E1000_CTRL_EXT) & ~E1000_CTRL_EXT_DRV_LOAD);
    LogManageabilityState("driver-stop-released");
  }
  if (netdevice_dispatcher_.get()) {
    netdevice_dispatcher_.ShutdownAsync();
    netdevice_dispatcher_shutdown_.Wait();
  }
  completer(zx::ok());
}

// ---------------------------------------------------------------------------
// Interrupt path.
// ---------------------------------------------------------------------------
void E1000Driver::IrqThread() {
  while (irq_running_.load()) {
    zx::time timestamp;
    zx_status_t st = irq_.wait(&timestamp);
    if (st != ZX_OK) {
      break;  // destroyed on teardown
    }
    // Serialize interrupt-time HAL/MMIO work with explicit netdevice start and
    // stop transitions.
    std::lock_guard hardware(hardware_lock_);
    // Reading ICR clears the pending cause bits.
    const uint32_t icr = Rd(E1000_ICR);
    // Diagnostics for the first few interrupts only: enough to tell "we never
    // transmitted" from "we transmitted and nothing came back", which are
    // different bugs, without turning the log into a firehose. All of these
    // counters are clear-on-read, so reading them here also keeps them from
    // saturating. GPTC/GPRC are good packets Tx/Rx; MPC is missed packets (Rx
    // ring starved); RNBC is Rx-no-buffers.
    if (uint32_t n = irq_diag_count_.fetch_add(1); n < 8) {
      FDF_LOG(INFO,
              "CERISE-E1000-IRQ n=%u icr=%08x status=%08x tdh=%u tdt=%u rdh=%u rdt=%u gptc=%u "
              "gprc=%u mpc=%u rnbc=%u crcerrs=%u tpt=%u xoffrxc=%u xonrxc=%u colc=%u tncrs=%u "
              "tdfpc=%08x ctrl=%08x tctl=%08x",
              n, icr, Rd(E1000_STATUS), Rd(E1000_TDH(0)), Rd(E1000_TDT(0)), Rd(E1000_RDH(0)),
              Rd(E1000_RDT(0)), Rd(E1000_GPTC), Rd(E1000_GPRC), Rd(E1000_MPC), Rd(E1000_RNBC),
              Rd(E1000_CRCERRS), Rd(E1000_TPT), Rd(E1000_XOFFRXC), Rd(E1000_XONRXC),
              Rd(E1000_COLC), Rd(E1000_TNCRS), Rd(E1000_TDFPC), Rd(E1000_CTRL), Rd(E1000_TCTL));
    }
    // Link Status Change. IMS asks for this interrupt but nothing acted on it,
    // so a cable pulled after Start() left the port reporting Online forever.
    // The shared code needs get_link_status set before it will re-read the PHY
    // (e1000_check_for_copper_link_ich8lan bails out otherwise,
    // e1000_ich8lan.c:1557).
    if ((icr & E1000_ICR_LSC) && started_.load()) {
      // A link-status check performs PHY writes on PCH parts, so honor the same
      // reset-block ownership bit used by setup_link. When firmware owns the
      // PHY, MAC STATUS is sufficient for the netdevice online bit. When the
      // host owns it, check_for_link performs the ordinary post-link work under
      // the shared code's PHY semaphore; it does not renegotiate the link.
      const bool firmware_owns_phy =
          IsPchManageabilityFamily(hw_.mac.type) &&
          !(Rd(E1000_FWSM) & E1000_ICH_FWSM_RSPCIPHY);
      if (!firmware_owns_phy) {
        hw_.mac.get_link_status = true;
        (void)e1000_check_for_link(&hw_);
      }
      std::lock_guard lock(state_lock_);
      if (ifc_.is_valid()) {
        fdf::Arena a(0u);
        (void)ifc_.buffer(a)->PortStatusChanged(kPortId, ReadPortStatus(a));
      }
    }
    if (started_.load()) {
      ReclaimTx();
      HarvestRx();
    }
    if (irq_is_legacy_) {
      (void)fidl::Call(pci_)->AckInterrupt();
    }
  }
}

void E1000Driver::ReclaimTx() {
  std::array<netdev::wire::TxResult, kMaxDepth> results;
  size_t count = 0;
  {
    std::lock_guard lock(tx_lock_);
    while (tx_reclaim_ != tx_next_) {
      volatile e1000_tx_desc& d = tx_ring_[tx_reclaim_];
      if ((d.upper.fields.status & E1000_TXD_STAT_DD) == 0) {
        break;
      }
      results[count++] = {.id = tx_buf_id_[tx_reclaim_], .status = ZX_OK};
      d.upper.fields.status = 0;
      tx_reclaim_ = (tx_reclaim_ + 1) % kNumTxDesc;
    }
  }
  if (count == 0) {
    return;
  }
  std::lock_guard state(state_lock_);
  if (!ifc_.is_valid()) {
    return;
  }
  fdf::Arena arena(0u);
  (void)ifc_.buffer(arena)->CompleteTx(
      fidl::VectorView<netdev::wire::TxResult>::FromExternal(results.data(), count));
}

void E1000Driver::HarvestRx() {
  std::array<netdev::wire::RxBuffer, kMaxDepth> buffers;
  std::array<netdev::wire::RxBufferPart, kMaxDepth> parts;
  size_t count = 0;
  {
    std::lock_guard lock(rx_lock_);
    while (rx_slot_valid_[rx_clean_]) {
      volatile e1000_rx_desc& d = rx_ring_[rx_clean_];
      if ((d.status & E1000_RXD_STAT_DD) == 0) {
        break;
      }
      // PCH/I219 keeps the FCS because RCTL.SECRC also controls the SMBus copy
      // seen by management firmware.  NetworkDevice consumers expect an
      // ordinary Ethernet frame without those four bytes, just as they did
      // when the MAC stripped it, so remove it from the reported host length.
      const uint16_t len = HostFrameLength(d.length, rx_hardware_strips_fcs_);
      parts[count] = {.id = rx_buf_id_[rx_clean_], .offset = 0, .length = len};
      buffers[count] = netdev::wire::RxBuffer{
          .meta = {.port = kPortId, .frame_type = netdrv::wire::FrameType::kEthernet},
          .data = fidl::VectorView<netdev::wire::RxBufferPart>::FromExternal(&parts[count], 1),
      };
      d.status = 0;
      rx_slot_valid_[rx_clean_] = false;
      count++;
      rx_clean_ = (rx_clean_ + 1) % kNumRxDesc;
    }
  }
  if (count == 0) {
    return;
  }
  std::lock_guard state(state_lock_);
  if (!ifc_.is_valid()) {
    return;
  }
  fdf::Arena arena(0u);
  (void)ifc_.buffer(arena)->CompleteRx(
      fidl::VectorView<netdev::wire::RxBuffer>::FromExternal(buffers.data(), count));
}

// ---------------------------------------------------------------------------
// NetworkDeviceImpl.
// ---------------------------------------------------------------------------
void E1000Driver::Init(netdev::wire::NetworkDeviceImplInitRequest* request, fdf::Arena& arena,
                       InitCompleter::Sync& completer) {
  {
    std::lock_guard lock(state_lock_);
    ifc_.Bind(std::move(request->iface), netdevice_dispatcher_.get());
  }
  auto [client, server] = fdf::Endpoints<netdev::NetworkPort>::Create();
  fdf::BindServer(netdevice_dispatcher_.get(), std::move(server), this);
  std::lock_guard lock(state_lock_);
  ifc_.buffer(arena)
      ->AddPort(kPortId, std::move(client))
      .Then([completer = completer.ToAsync()](
                fdf::WireUnownedResult<netdev::NetworkDeviceIfc::AddPort>& result) mutable {
        fdf::Arena a(0u);
        completer.buffer(a).Reply(result.ok() ? result->status : result.status());
      });
}

void E1000Driver::Start(fdf::Arena& arena, StartCompleter::Sync& completer) {
  {
    std::lock_guard hardware(hardware_lock_);
    EnableRxTx();
    // Enable interrupts: RX timer, RX descriptor minimum threshold, TX
    // descriptor written back, link status change.
    Wr(E1000_IMS, E1000_IMS_RXT0 | E1000_IMS_RXDMT0 | E1000_IMS_TXDW | E1000_IMS_LSC);
    started_.store(true);
  }
  NotifyPortStatus();
  completer.buffer(arena).Reply(ZX_OK);
}

void E1000Driver::Stop(fdf::Arena& arena, StopCompleter::Sync& completer) {
  // Fence new queue submissions before waiting for interrupt-time hardware
  // access to leave the data-path transition.
  started_.store(false);
  {
    std::lock_guard hardware(hardware_lock_);
    // Clear ONLY the enable bits, preserving the rest of RCTL/TCTL. This is
    // what Linux's e1000e_down does, and on a part the ME shares it matters:
    // zeroing these registers wholesale discards receive configuration that is
    // not exclusively ours.
    DisableRxTx();
    DrainOutstandingBuffers(arena, ZX_ERR_UNAVAILABLE);
  }
  completer.buffer(arena).Reply();
}

void E1000Driver::GetInfo(
    fdf::Arena& arena,
    fdf::WireServer<netdev::NetworkDeviceImpl>::GetInfoCompleter::Sync& completer) {
  // Report depth N-1, not N: the e1000 rule is that hardware owns descriptors in
  // [RDH, RDT), so the ring can never be fully populated — the tail must never
  // advance to equal the head, or the ring reads as EMPTY. The netdevice
  // framework fills rx-space up to rx_depth, so capping at N-1 keeps RDT clear of
  // RDH (same argument applies to TX).
  netdev::wire::DeviceImplInfo info = netdev::wire::DeviceImplInfo::Builder(arena)
                                          .tx_depth(kNumTxDesc - 1)
                                          .rx_depth(kNumRxDesc - 1)
                                          .rx_threshold((kNumRxDesc - 1) / 2)
                                          .max_buffer_parts(1)
                                          .max_buffer_length(kRxBufferSize)
                                          .buffer_alignment(kBufferAlignment)
                                          .min_rx_buffer_length(kRxBufferSize)
                                          .min_tx_buffer_length(60)
                                          .tx_head_length(0)
                                          .Build();
  completer.buffer(arena).Reply(info);
}

void E1000Driver::QueueTx(netdev::wire::NetworkDeviceImplQueueTxRequest* request, fdf::Arena& arena,
                          QueueTxCompleter::Sync& completer) {
  // A buffer handed to QueueTx must be completed EXACTLY ONCE, always. There is
  // no "drop it on the floor" outcome in the netdevice contract: the framework
  // owns a fixed pool and a buffer that is never completed is leaked from that
  // pool for the life of the device, so enough of them wedge the interface with
  // no error anywhere. The old code did `continue` on every failure path.
  std::array<netdev::wire::TxResult, kMaxDepth> failed;
  size_t nfailed = 0;
  bool queued = false;
  // Snapshotted under tx_lock_ so the diagnostic below cannot read a tail that
  // a concurrent QueueTx on the unsynchronized dispatcher has since moved.
  uint16_t armed_tail = 0;
  {
    std::lock_guard lock(tx_lock_);
    // Stop() stores started_=false BEFORE it takes tx_lock_ to drain the ring,
    // so this test under the lock is what makes the handover total: either we
    // get the lock first and Stop drains what we queued, or Stop got there
    // first and we hand everything straight back. Without it a QueueTx racing
    // teardown enqueues buffers that nothing will ever complete.
    const bool running = started_.load();
    for (const auto& buffer : request->buffers) {
      auto fail = [&](zx_status_t st) {
        if (nfailed < failed.size()) {
          failed[nfailed++] = {.id = buffer.id, .status = st};
        }
      };
      if (!running) {
        fail(ZX_ERR_BAD_STATE);
        continue;
      }
      if (buffer.data.size() != 1) {
        // GetInfo reports max_buffer_parts(1), so this should not happen.
        fail(ZX_ERR_NOT_SUPPORTED);
        continue;
      }
      const netdev::wire::BufferRegion& region = buffer.data[0];
      VmoStore::StoredVmo* stored = vmo_store_->GetVmo(region.vmo);
      if (stored == nullptr) {
        fail(ZX_ERR_NOT_FOUND);
        continue;
      }
      fzl::PinnedVmo::Region phys;
      size_t actual = 0;
      if (stored->GetPinnedRegions(region.offset, region.length, &phys, 1, &actual) != ZX_OK ||
          actual != 1) {
        fail(ZX_ERR_INVALID_ARGS);
        continue;
      }
      // Never let the tail catch the reclaim point: TDT == TDH reads as an EMPTY
      // ring to the device, so overrunning here would silently un-queue
      // everything outstanding. tx_depth is kNumTxDesc-1 so the framework should
      // not be able to get us here, but the ring is the thing that breaks.
      const uint16_t next = static_cast<uint16_t>((tx_next_ + 1) % kNumTxDesc);
      if (next == tx_reclaim_) {
        fail(ZX_ERR_NO_RESOURCES);
        continue;
      }
      volatile e1000_tx_desc& d = tx_ring_[tx_next_];
      d.buffer_addr = phys.phys_addr;
      d.lower.data = static_cast<uint32_t>(region.length) | E1000_TXD_CMD_EOP | E1000_TXD_CMD_RS |
                     E1000_TXD_CMD_IFCS;
      d.upper.data = 0;
      tx_buf_id_[tx_next_] = buffer.id;
      tx_next_ = next;
      queued = true;
    }
    if (queued) {
      // The descriptors live in a CACHED mapping; TDT is UNCACHED device MMIO.
      // x86's store ordering already prevents the tail write from overtaking
      // them, but nothing here should depend on that being remembered.
      std::atomic_thread_fence(std::memory_order_seq_cst);
      Wr(E1000_TDT(0), tx_next_);
      armed_tail = tx_next_;
    }
  }
  // First few submissions only: did the device actually take the descriptors?
  // Reading TDH a moment after arming the tail separates "the queue is
  // unserviced" from "we transmitted and the completion path is broken", which
  // look identical from the netstack.
  if (queued) {
    if (uint32_t n = tx_diag_count_.fetch_add(1); n < 4) {
      // The descriptor and TDT were published under tx_lock_. A deferred full
      // reset waits for that lock before proceeding; serialize these later
      // diagnostic MMIO reads too so they cannot land inside the reset window.
      std::lock_guard hardware(hardware_lock_);
      const uint32_t tdh_immediate = Rd(E1000_TDH(0));
      zx_nanosleep(zx_deadline_after(ZX_MSEC(1)));
      FDF_LOG(INFO, "CERISE-E1000-TXKICK n=%u tdt=%u tdh_now=%u tdh_1ms=%u gptc=%u tpt=%u",
              n, armed_tail, tdh_immediate, Rd(E1000_TDH(0)), Rd(E1000_GPTC), Rd(E1000_TPT));
      LogTxForensics("txkick", static_cast<uint16_t>(armed_tail + kNumTxDesc - 1));
    }
  }
  if (nfailed != 0) {
    std::lock_guard state(state_lock_);
    if (ifc_.is_valid()) {
      (void)ifc_.buffer(arena)->CompleteTx(
          fidl::VectorView<netdev::wire::TxResult>::FromExternal(failed.data(), nfailed));
    }
  }
}

void E1000Driver::QueueRxSpace(netdev::wire::NetworkDeviceImplQueueRxSpaceRequest* request,
                               fdf::Arena& arena, QueueRxSpaceCompleter::Sync& completer) {
  // Same contract as QueueTx: an rx-space buffer we cannot use must be returned
  // to the framework (as a zero-length receive), not dropped on a `continue`.
  std::array<netdev::wire::RxBuffer, kMaxDepth> returned;
  std::array<netdev::wire::RxBufferPart, kMaxDepth> returned_parts;
  size_t nreturned = 0;
  bool queued = false;
  {
    std::lock_guard lock(rx_lock_);
    const bool running = started_.load();  // see the note in QueueTx
    for (const auto& buffer : request->buffers) {
      auto give_back = [&]() {
        if (nreturned >= returned.size()) {
          return;
        }
        returned_parts[nreturned] = {.id = buffer.id, .offset = 0, .length = 0};
        returned[nreturned] = netdev::wire::RxBuffer{
            .meta = {.port = kPortId, .frame_type = netdrv::wire::FrameType::kEthernet},
            .data = fidl::VectorView<netdev::wire::RxBufferPart>::FromExternal(
                &returned_parts[nreturned], 1),
        };
        nreturned++;
      };
      if (!running) {
        give_back();
        continue;
      }
      const netdev::wire::BufferRegion& region = buffer.region;
      VmoStore::StoredVmo* stored = vmo_store_->GetVmo(region.vmo);
      if (stored == nullptr) {
        give_back();
        continue;
      }
      fzl::PinnedVmo::Region phys;
      size_t actual = 0;
      if (stored->GetPinnedRegions(region.offset, region.length, &phys, 1, &actual) != ZX_OK ||
          actual != 1) {
        give_back();
        continue;
      }
      if (rx_slot_valid_[rx_tail_]) {
        // Ring already full; handing this to hardware would overwrite a slot the
        // device still owns.
        give_back();
        continue;
      }
      volatile e1000_rx_desc& d = rx_ring_[rx_tail_];
      d.buffer_addr = phys.phys_addr;
      d.status = 0;
      rx_buf_id_[rx_tail_] = buffer.id;
      rx_slot_valid_[rx_tail_] = true;
      rx_tail_ = static_cast<uint16_t>((rx_tail_ + 1) % kNumRxDesc);
      queued = true;
    }
    if (queued) {
      std::atomic_thread_fence(std::memory_order_seq_cst);
      // RDT points one past the last descriptor handed to hardware.
      Wr(E1000_RDT(0), rx_tail_);
    }
  }
  if (nreturned != 0) {
    std::lock_guard state(state_lock_);
    if (ifc_.is_valid()) {
      (void)ifc_.buffer(arena)->CompleteRx(
          fidl::VectorView<netdev::wire::RxBuffer>::FromExternal(returned.data(), nreturned));
    }
  }
}

void E1000Driver::PrepareVmo(netdev::wire::NetworkDeviceImplPrepareVmoRequest* request,
                             fdf::Arena& arena, PrepareVmoCompleter::Sync& completer) {
  zx_status_t st = vmo_store_->RegisterWithKey(request->id, std::move(request->vmo));
  completer.buffer(arena).Reply(st);
}

void E1000Driver::ReleaseVmo(netdev::wire::NetworkDeviceImplReleaseVmoRequest* request,
                             fdf::Arena& arena, ReleaseVmoCompleter::Sync& completer) {
  (void)vmo_store_->Unregister(request->id);
  completer.buffer(arena).Reply();
}

// ---------------------------------------------------------------------------
// NetworkPort.
// ---------------------------------------------------------------------------
netdrv::wire::PortStatus E1000Driver::ReadPortStatus(fidl::AnyArena& arena) {
  bool link_up = (Rd(E1000_STATUS) & E1000_STATUS_LU) != 0;
  return netdrv::wire::PortStatus::Builder(arena)
      .flags(link_up ? netdrv::wire::StatusFlags::kOnline : netdrv::wire::StatusFlags{})
      .mtu(kMtu)
      .Build();
}

void E1000Driver::GetInfo(fdf::Arena& arena,
                          fdf::WireServer<netdev::NetworkPort>::GetInfoCompleter::Sync& completer) {
  static constexpr netdrv::wire::FrameType kRxTypes[] = {netdrv::wire::FrameType::kEthernet};
  static constexpr netdrv::wire::FrameTypeSupport kTxTypes[] = {
      {.type = netdrv::wire::FrameType::kEthernet, .features = netdrv::wire::kFrameFeaturesRaw}};
  netdrv::wire::PortBaseInfo info = netdrv::wire::PortBaseInfo::Builder(arena)
                                        .port_class(netdrv::wire::PortClass::kEthernet)
                                        .rx_types(fidl::VectorView<netdrv::wire::FrameType>::
                                                      FromExternal(const_cast<netdrv::wire::FrameType*>(kRxTypes), 1))
                                        .tx_types(fidl::VectorView<netdrv::wire::FrameTypeSupport>::
                                                      FromExternal(const_cast<netdrv::wire::FrameTypeSupport*>(kTxTypes), 1))
                                        .Build();
  completer.buffer(arena).Reply(info);
}

void E1000Driver::GetStatus(fdf::Arena& arena, GetStatusCompleter::Sync& completer) {
  // ReadPortStatus samples MMIO. Keep an external status request out of the
  // attach-grade reset window used after firmware releases PHY ownership.
  std::lock_guard hardware(hardware_lock_);
  completer.buffer(arena).Reply(ReadPortStatus(arena));
}

void E1000Driver::SetActive(netdev::wire::NetworkPortSetActiveRequest* request, fdf::Arena& arena,
                            SetActiveCompleter::Sync& completer) {}

void E1000Driver::GetMac(fdf::Arena& arena, GetMacCompleter::Sync& completer) {
  auto [client, server] = fdf::Endpoints<netdev::MacAddr>::Create();
  fdf::BindServer(netdevice_dispatcher_.get(), std::move(server), this);
  completer.buffer(arena).Reply(std::move(client));
}

void E1000Driver::Removed(fdf::Arena& arena, RemovedCompleter::Sync& completer) {}

// ---------------------------------------------------------------------------
// MacAddr.
// ---------------------------------------------------------------------------
void E1000Driver::GetAddress(fdf::Arena& arena, GetAddressCompleter::Sync& completer) {
  fuchsia_net::wire::MacAddress mac;
  memcpy(mac.octets.data(), mac_, 6);
  completer.buffer(arena).Reply(mac);
}

void E1000Driver::GetFeatures(fdf::Arena& arena, GetFeaturesCompleter::Sync& completer) {
  netdev::wire::Features features =
      netdev::wire::Features::Builder(arena)
          .multicast_filter_count(0)
          .supported_modes(netdev::wire::SupportedMacFilterMode::kPromiscuous)
          .Build();
  completer.buffer(arena).Reply(features);
}

void E1000Driver::SetMode(netdev::wire::MacAddrSetModeRequest* request, fdf::Arena& arena,
                          SetModeCompleter::Sync& completer) {
  completer.buffer(arena).Reply();
}

}  // namespace e1000

FUCHSIA_DRIVER_EXPORT2(e1000::E1000Driver);

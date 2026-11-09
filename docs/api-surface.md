# Cerise API surface

This is what you program against in Cerise: the Bazel rules that build and
compose the system, the providers those rules exchange, and the runtime
interfaces components speak. It complements
[docs/composition-model.md](docs/composition-model.md), which explains how the
composition rules fit together.

## Build rules

All are Starlark macros/rules loaded from `//assembly` and `//build`.

| Rule | Purpose |
|------|---------|
| `cerise_component` | Compile a real Fuchsia `.cml` to a component manifest via the vendored `cmc`, with optional structured-config schema. The building block for every component. |
| `cerise_config_values` | Produce a structured-config value file (`.cvf`) for a component from its compiled manifest via `configc`. |
| `cerise_board` | Declare hardware identity → `BoardInfo` (see the composition model). |
| `cerise_assembly_input_bundle` | Declare a reusable capability set → `AIBInfo`. |
| `cerise_product` | Compose board + bundles + root realm into a bootable `<name>.zbi` → `ProductBundleInfo`. |
| `cerise_package` | Build a real Fuchsia package (`meta.far` + content-addressed blobs) → `PackageInfo`. |
| `cerise_debug_symbols` | Collect the unstripped ELFs of a product into a `.build-id/xx/rest.debug` store for symbolization and debuginfod. |

Structured-config client libraries are generated with
`fuchsia_structured_config_rust_lib`, `fuchsia_structured_config_rust_lib_from_cm`,
and `fuchsia_structured_config_cpp_elf_lib` — a component reads its delivered
configuration through the generated typed API, never a hand-written literal.

### The shape of a component

```python
cerise_component(
    name = "my_component",
    manifest = "meta/my_component.cml",       # real .cml, compiled by cmc
    config_package_path = "meta/my_component.cvf",  # optional structured config
)
```

## Providers

The typed contracts the rules exchange in analysis. These are the extension
points: a third-party rule that emits one of these participates in composition.

| Provider | Emitted by | Carries |
|----------|------------|---------|
| `BoardInfo` | `cerise_board` | arch, platform, provided features, boot-driver URLs, cmdline, kernel drivers, bootfs |
| `AIBInfo` | `cerise_assembly_input_bundle` | required features, bootfs placements, cmdline fragments, config schemas + values |
| `ProductBundleInfo` | `cerise_product` | the assembled bootfs set and product config |
| `ComponentInfo` | `cerise_component` | the compiled manifest and config-value artifacts |
| `PackageInfo` | `cerise_package` | the `meta.far` and the package's content blobs |
| `CeriseUnstrippedInfo` / `CeriseUnstrippedCollectionInfo` | stripped-binary rules / the debug-symbol aspect | the unstripped ELF + build-id, for the symbol store |

## Runtime interfaces

### FIDL — in-system protocols

Cerise-original FIDL lives under `src/cerise/fidl/`.

- **`cerise.display`** — `Framebuffer` (a driver serves the framebuffer: geometry
  + a VMO) and its `Service`. A display driver publishes it; the status console
  consumes it, so the console is portable across a QEMU stdvga driver and a real
  GOP-framebuffer driver without change.
- **`cerise.echo`** — a minimal echo protocol used as a component/IPC probe.
- **`cerise.storage`** — storage status plus the generation-bound
  `Lifecycle.FreezeAndSync`/`Thaw` durability barrier used by orderly host
  transitions.
- **`cerise.update`** — the on-demand inactive-slot `Stager`. Preparation takes
  an explicit source and authenticates the full candidate; staging selects an
  unambiguous or GUID-pinned disk/ESP, flushes and readback-verifies the slot,
  then commits activation. It has no reboot authority.
- **`cerise.vm`** — component-local worker status, lifecycle, VMI, and data-plane
  protocols. The host gateway consumes these; individual workers do not own
  public listener ports.

Components otherwise speak the standard Fuchsia protocol surface the vendored
frameworks provide — `fuchsia.posix.socket` (through fdio and `fuchsia-async`),
`fuchsia.net.interfaces`, `fuchsia.fxfs` (`BlobCreator` / `BlobReader`),
`fuchsia.component.resolution`, `fuchsia.hardware.pci`, and so on.

### gRPC — the file server

The flagship file server is a network service, not an in-system FIDL protocol:
`cerise.fileserver.v1.FileServer` (protobuf/gRPC), served over tonic + hyper
HTTP/2 on a `fuchsia-async` executor with no tokio runtime on target. Methods:
`Stat`, `List`, `Read`, `Write`, `Mkdir`, `Rename`, `Delete`. It is an ordinary
component: nothing about it is privileged or hard-wired.

### gRPC — VM and host control

The VM gateway serves one shared HTTP/2 listener for all VM inventory,
lifecycle, snapshot-tree, VMI, display/input/serial/network, and external-device
traffic. `cerise.manager.v1.VmManager` owns VM configuration and lifecycle;
`VmiGateway` exposes typed execution, event, memory/register, and raw trace
primitives. If a host loss destroys a process-local mutable tail,
`VmManager.RollbackHead` explicitly reinstalls that VM's retained durable
recovery point and advances its epoch. A resumable machine root is left
paused so epoch-scoped devices can reconnect before execution continues; a
cold recovery point, including the original image baseline, is reconstructed
stopped and enters the guest only on a later `Start`.

Rollback callers must retain one non-empty request identity for the entire
logical operation. Repeating that identity replays the original result or its
remaining projection tail without allocating another epoch or head; changing
the VM for an existing identity is rejected. The raw gRPC field remains
optional for wire compatibility, but an empty identity selects the legacy
non-idempotent behavior and must not be retried after an ambiguous outcome.
Browser-facing gateways therefore require a non-empty identity and limit it to
128 UTF-8 bytes.

`UpdateVm` is the atomic editor mutation for a stopped VM. One identified
request carries the complete target configuration and metadata, so observers
never see a stable half-save. Admission requires the catalog incarnation,
epoch, head identity, and versioned authority etag from the same inventory VM
row. The etag covers the complete durable row, including manager-owned head
state that is intentionally absent from the public model; runtime population
and usage are excluded. A configuration change reserves one replacement epoch
and head before its idempotent worker effect, while a metadata-only update
preserves both. `CoreApplied` publishes the complete target row atomically and
`Completed` is withheld until device and VMI projections converge.

The older `UpdateVmConfig` and `UpdateVmMetadata` methods remain in the
protobuf service only for wire compatibility. They are retired, are advertised
as unavailable, and return `FAILED_PRECONDITION` without applying a mutation.
Clients must use `UpdateVm`; HTTP gateways expose only the atomic whole-VM
update route and do not fall back to either split method.

`DeleteVm` requires a non-empty request ID and uses the same durable receipt
boundary. The request-ID field remains in the wire schema for compatibility,
but an empty value fails with `INVALID_ARGUMENT` before per-VM coordination,
durable mutation admission, or any destructive or projection effect. The
request also requires the
caller's observed catalog-incarnation token, VM epoch, and mutable-head
identity. The catalog token is stable across ordinary revisions and reboots
but rotates before a restored pool becomes authority. Together these fields
prevent a delayed first delivery from deleting a later incarnation that reused
the visible VM tuple. Admission binds that exact source before worker retirement;
catalog removal publishes `CoreApplied`, and `Completed` is withheld until
checkpoint, data-plane, device, and VMI projections, the event cursor, and the
durable guest-event outbox are retired. Ordinary data-plane deletion preserves
typed `VmDeleted` close results. An exact completed retry is a pure replay and
never touches a later VM.

Only authoritative inventory projections (`GetVm`, `ListVms`, and the VM rows
in `GetHostStatus`) carry the current catalog-incarnation token and VM authority
etag. Historical or mutation-result VM projections omit them; callers must
refresh inventory before forming another fenced mutation.

Deploy these protocol extensions manager-first, followed by the on-target
gateway and clients. Older protobuf servers ignore fields added to existing
requests and can therefore execute those calls with legacy semantics; they
return `UNIMPLEMENTED` for the new `UpdateVm` method. The editor requires the
advertised atomic method and never falls back to the split legacy
configuration/metadata calls. Once a durable rollback, update, or delete
receipt has been admitted, do not downgrade the manager to a binary that cannot
decode it. The durable mutation registry currently admits at most 4096 records
and fails closed when full; receipt acknowledgement and compaction are not yet
part of the API.

`VmManager.RegisterExtension`, `ListExtensions`, and `InvokeExtension` provide
the authoritative runtime package plane for bounded read-only Rhai operations.
Registration computes the source digest, validates exact dependencies and
declared host/read authority, compiles the complete closure, and durably
publishes an immutable `name@version`. The on-machine `cerise.vm.FastControl`
protocol lists and invokes the same active package snapshot. Runtime packages
receive no write binding; guest-memory mutation remains on typed mutation
routes with their own authorization and lifecycle fences.

`cerise.manager.v1.HostControl` is the sole host-wide update/reboot/poweroff
entry point:

- `PrepareUpdate` downloads and authenticates a candidate while retaining a
  mutation-admission lease. After an updater restart at the terminal boundary,
  the same operation ID may use it to repopulate the in-memory candidate; the
  gateway accepts only the durable candidate identity and does not reopen
  ordinary mutation admission.
- `ApplyPreparedUpdate`, `RebootHost`, and `PoweroffHost` close admission,
  drain prior mutations, publish a complete durable head for every VM, freeze
  and sync storage, and only then request orderly platform shutdown.
- `GetOperation` reports the durable transaction journal for retry and
  recovery.

Successful terminal calls normally end by closing the connection as the
component topology stops. Client cancellation does not cancel the
gateway-owned host transaction.

## Feature tokens

Composition negotiates hardware capability through string tokens: a board
`provides` them, a bundle `requires` them, and the product rule checks the
intersection at analysis time. Current tokens include `cerise::block`,
`cerise::virtio-net`, `cerise::e1000`, `cerise::nvme`, `cerise::ahci`,
`cerise::pci`, and `cerise::acpi`. Adding hardware means adding a driver to a
board and a token to its `provided_features` — no core edit.

## Observability markers

Boot and runtime progress is reported on the serial console with `CERISE-…`
markers (for example `CERISE-PCI-ENUM`, `CERISE-FILESERVER-LISTENING`). The live
boot tests under `//validation` assert ordered sequences of these markers
against the running guest, so a passing test is a real boot, not a fixture. On a
failure, captured backtraces are symbolized against the product's `.build-id`
store automatically.

# Legacy QEMU Boot Recipe

This directory records the legacy boot recipe for `//kernel:x64_boot_zbi`.

## Verification status

This recipe is committed and reproducible as a documented command line, but it
is **unverified**: the probe on this host did not produce a successful legacy
boot.

## Runner

`validation/run-qemu.sh` builds:

- `//kernel:x64_boot_zbi`
- `//kernel:x64_linux_x86_64_boot_shim`

then launches:

- `qemu-system-x86_64`
- `-nographic`
- `-monitor none`
- `-no-reboot`
- `-serial file:<log>`
- `-netdev user,id=net0,hostfwd=tcp::8080-:80`
- `-device e1000,netdev=net0`
- `-kernel bazel-bin/kernel/linux-x86-64-boot-shim.bin`
- `-initrd bazel-bin/kernel/x64_boot.zbi`

The runner exits successfully only after the serial log contains both required
parity markers and no forbidden panic markers.

## Contract targets

`validation/BUILD.bazel` carries the source-derived marker contract:

- `//validation:marker_contract_good` checks the frozen good serial log.
- `//validation:marker_contract_bad` proves the checker rejects the bad log.
- `validation/goldens/smoke-markers.json` is the frozen marker contract used by
  both targets.

## Observed host provenance

- QEMU: `qemu-system-x86_64` 8.2.2 (`Debian 1:8.2.2+ds-0ubuntu1.16`)
- Firmware available on this host: `/usr/share/OVMF/OVMF_CODE_4M.fd`

The legacy path does not use OVMF directly because it boots through the
Linux-style `-kernel`/`-initrd` path. The firmware path is recorded here for
the future EFI boot path.

## Operational assumptions

- The guest is expected to expose the smoke payload on `10.0.2.15:80` under
  QEMU user networking.
- The runner defaults to a 180 second timeout and can be overridden with
  `TIMEOUT_SECONDS`.
- `HOSTFWD_PORT` defaults to `8080` and forwards host loopback traffic to the
  guest HTTP port for optional probing.
- `QEMU_BIN` and `BAZEL_BIN` may be overridden if the host environment uses a
  different executable path.

## arm64 kernel boot gates

The arm64 kernel/phys layer is proven by two live `bazel test` gates that boot a
product ZBI on the pinned `@qemu_aarch64` (`qemu-system-aarch64`, hermeticbuild
11.0.0.1 aarch64-softmmu) via the **direct-kernel** path — the arm64 analogue of
the x86 `-kernel`/`-initrd` recipe. This is **not** UEFI: `qemu-system-aarch64
-machine virt` loads `//build/phys/qemu_arm64_boot_shim:arm64_qemu_boot_shim` as a
Linux arm64 `Image` (`-kernel`), QEMU places the product ZBI as `-initrd`, and the
bare-metal shim scans RAM for the ZBI container and jumps to physload. No OVMF /
firmware / qemu data dir is needed (`-net none` removes the only option-ROM
dependency).

Run the gates:

```
bazel test //validation:arm64-smoke-boot   # 4 kernel markers
bazel test //validation:arm64-hello-boot   # kernel + hello-arm64 userspace + IPC
```

(They are tagged `manual`/`local`/`no-remote`, so they run on demand, not under a
bare `bazel test //...`. Emulation is pure TCG — no arm64 KVM on an x86 host — but
the markers appear within a couple of seconds.)

The exact QEMU invocation the harness runs (`validation/arm64_boot_test.py`):

```
qemu-system-aarch64 -machine virt,gic-version=2 -cpu cortex-a53 -m 2048M \
  -no-reboot -net none -display none -monitor none \
  -serial file:<log> -kernel <arm64_qemu_boot_shim.bin> -initrd <product.zbi>
```

`-machine virt,gic-version=2` matches the product's GICv2 ZBI driver item (the
golden asserts `GICv2 detected`); `-m 2048M` matches the product `mem_config`
(DRAM `0x40000000..0xC0000000`). Marker contracts:
`validation/goldens/arm64-smoke-markers.json` and `arm64-hello-markers.json`.

A kernel-only smoke ends in a benign `HALT: spinning forever (reason = 6)` once the
root job exits (no `userboot.next`, no PSCI item) — so `HALT` is deliberately **not**
a forbidden marker, and bare `fatal` is avoided because it substring-matches the
benign `lockup_detector` `fatal threshold` line.

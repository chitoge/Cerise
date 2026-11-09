#!/usr/bin/env python3
"""Cerise status-console storage-backed integration live-boot proof: the combined fileserver + console.

Boots //products:qemu-x64-console via the direct-kernel path with an NVMe scratch disk
(fileserver's fxfs), a virtio-net NIC (netstack3), a `-device VGA` display, and a QMP
channel. In the guest the fileserver brings up the network (10.0.2.15) + serves gRPC on
:50051, while the status_console reads interface state via fuchsia.net.interfaces.State
and paints a VM-host status screen (hostname, interface up/down, IPv4/IPv6, VM access,
VM inventory, and image-store capacity) to the framebuffer.

This harness waits for CERISE-CONSOLE-RENDERED (console is drawing) and
CERISE-FILESERVER-LISTENING (network up + IP assigned, so the console has repainted with
the address), then drives QMP `screendump`, saves the PPM as an undeclared test output,
and asserts the framebuffer.

WHAT THE PIXEL ASSERTION ACTUALLY PROVES. It used to be "not one flat colour", which a
blue title bar alone satisfies. It now proves that live memory/CPU measurements and the
VM inventory/store sections are physically drawn on the panel.

  1. The console emits raw memory/CPU evidence only after presenting the frame that
     contains those rows. Disk evidence is retained separately to verify the combined
     fileserver product even though storage is intentionally absent from the panel.
  2. This harness validates the raw values against things IT knows and the guest does
     not get to choose: the memory it passed to QEMU, the exact byte size of the NVMe
     image it created itself, and the CPU count it configured. A fabricated constant
     cannot track all three.
  3. This harness formats the expected memory/CPU text itself, and independently expects
     the VM inventory/store headings; it does not echo strings from a guest marker.
  4. It finds that text on the screen by exact, full-cell glyph comparison — foreground
     AND background — anchored to its own label, using the font parsed from the
     renderer's own font.rs, and requires exactly one match.

So the gate fails if a visible live value is unavailable or wrong, or if the VM-facing
content never reached the framebuffer.

WHAT IT STILL DOES NOT PROVE, stated so nobody credits it with more: that the panel is
repainting. The console re-emits its evidence only when a value's STABLE identity changes
(`evidence_key` in status_console/src/main.rs), so a framebuffer frozen on a frame whose
memory total, core count, and listener state have not changed satisfies every term here. A
paint-generation token drawn on screen is what would close that, and the console does not
draw one yet.
"""
from __future__ import annotations
import argparse, json, os, pathlib, re, socket, subprocess, sys, time

import panel_check

CONSOLE_RENDERED = "CERISE-CONSOLE-RENDERED"
CONSOLE_FAIL = "CERISE-CONSOLE-FAIL"
LISTENING = "CERISE-FILESERVER-LISTENING"
FS_FAIL = "CERISE-FILESERVER-FAIL"
# A degraded file server still LISTENS, so without this the gate would pass on a
# boot where the (blank) disk was refused. Fail markers are checked before the
# success needle for exactly that reason.
FS_DEGRADED = "CERISE-FILESERVER-DEGRADED"

# The evidence marker is emitted after presentation. Memory/CPU describe visible rows;
# disk remains a separate combined-product health check.
METRICS_RENDERED = "CERISE-CONSOLE-METRICS-RENDERED"
MEM_OK = "CERISE-CONSOLE-MEM-OK"
CPU_OK = "CERISE-CONSOLE-CPU-OK"
DISK_OK = "CERISE-CONSOLE-DISK-OK"
# Each metric emits its -OK or its -UNAVAILABLE, never both. Treating the latter as fail
# markers is what stops the gate passing on a panel that had nothing to show.
METRIC_FAIL = [
    "CERISE-CONSOLE-MEM-UNAVAILABLE",
    "CERISE-CONSOLE-CPU-UNAVAILABLE",
    "CERISE-CONSOLE-DISK-UNAVAILABLE",
]

BOOT_TIMEOUT_S = 600.0

# What we give QEMU. The harness asserts the guest's own numbers against these, so they
# are an oracle the guest cannot influence — keep them and the -m/-smp flags in step.
GUEST_MEM_MB = 4096
GUEST_SMP = 1
# The NVMe scratch image this harness creates, to the byte. The file server takes the
# whole raw device, so a mounted filesystem's total size must equal it exactly.
NVME_BYTES = 256 * 1024 * 1024


def _need(path, what):
    if not path or not os.path.exists(path):
        raise SystemExit(f"{what} not found: {path}")
    return path


def _free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Qmp:
    """A minimal QMP client over TCP (TCP, not a unix socket: bazel's TEST_TMPDIR path
    easily exceeds the 108-char AF_UNIX limit)."""

    def __init__(self, host, port):
        self.sock = socket.create_connection((host, port))
        self.f = self.sock.makefile("rwb", buffering=0)
        assert "QMP" in self._read(), "bad QMP greeting"
        self.execute("qmp_capabilities")

    def _read(self):
        while True:
            line = self.f.readline()
            if not line:
                raise RuntimeError("QMP connection closed")
            msg = json.loads(line)
            if "event" in msg:
                continue
            return msg

    def execute(self, command, arguments=None):
        req = {"execute": command}
        if arguments:
            req["arguments"] = arguments
        self.f.write(json.dumps(req).encode() + b"\n")
        resp = self._read()
        if "error" in resp:
            raise RuntimeError(f"QMP {command} failed: {resp['error']}")
        return resp.get("return")

    def close(self):
        try:
            self.f.close()
            self.sock.close()
        except OSError:
            pass


# The console's evidence markers are parsed by ONE parser, in panel_check, shared with
# the other framebuffer gates. Two copies of a parser are two parsers that drift, and a
# gate whose parser has quietly stopped matching the marker it looks for reads as "the
# guest never said it" — a false red at best, and a silently narrowed contract at worst.
_marker_lines = panel_check.marker_lines
_metric_settled = panel_check.metric_settled
_last_marker = panel_check.last_marker
_int_field = panel_check.int_field


def check_reported_values(text):
    """Validates the guest's RAW numbers against what this harness configured.

    This is the independent-oracle step. Every bound here comes from a value the harness
    chose (QEMU's -m, -smp, and the size of the disk image it wrote), so a hardcoded or
    placeholder number in the guest cannot satisfy them.

    Reads through `_metric_settled`, not the last -OK line: that way a metric which went
    UNAVAILABLE after its last good reading fails here rather than being validated
    against a stale success. This function is called again after the screendump for
    exactly that reason.
    """
    for family in ("MEM", "CPU", "DISK"):
        fields, why = _metric_settled(text, family)
        if fields is None:
            raise AssertionError(f"{family} is not currently available on the panel: {why}")
    mem = _last_marker(text, MEM_OK)
    total_bytes = _int_field(mem, "total_bytes", MEM_OK)
    free_bytes = _int_field(mem, "free_bytes", MEM_OK)
    used_bytes = _int_field(mem, "used_bytes", MEM_OK)
    limit = GUEST_MEM_MB * (1 << 20)
    # TIGHT. The kernel never sees quite all of -m (firmware and bootloader reservations)
    # and it cannot see more, but the shortfall is small — measured at 0.03% on this
    # exact configuration. A 10% floor leaves generous headroom for a different board or
    # a bigger reservation while still pinning the value to within a tenth of whatever
    # GUEST_MEM_MB says, so a hardcoded constant cannot satisfy it across configurations.
    floor = limit - limit // 10
    if not (floor < total_bytes <= limit):
        raise AssertionError(
            f"reported memory total {total_bytes} B is not a reading of the "
            f"{GUEST_MEM_MB} MiB given to QEMU (expected {floor} < x <= {limit})"
        )
    if not (0 < free_bytes < total_bytes):
        raise AssertionError(f"free {free_bytes} B is not between 0 and total {total_bytes} B")
    if used_bytes != total_bytes - free_bytes:
        raise AssertionError(f"used {used_bytes} != total {total_bytes} - free {free_bytes}")

    cpu = _last_marker(text, CPU_OK)
    cores = _int_field(cpu, "cores", CPU_OK)
    if cores != GUEST_SMP:
        raise AssertionError(f"reported {cores} cores, QEMU was configured with {GUEST_SMP}")
    reported = _int_field(cpu, "reported", CPU_OK)
    if reported != cores:
        raise AssertionError(
            f"the kernel says {cores} CPUs exist but only {reported} were sampled; the "
            "per-core figures on the panel would not describe the whole machine"
        )
    interval_ns = _int_field(cpu, "interval_ns", CPU_OK)
    idle_delta_ns = _int_field(cpu, "idle_delta_ns", CPU_OK)
    mean_pct = _int_field(cpu, "mean_pct", CPU_OK)
    # Utilisation is a delta, so these prove the sample came from two separated
    # observations of a kernel counter that really advanced. A constant produces neither,
    # and a single sample produces no marker at all.
    if interval_ns <= 0:
        raise AssertionError(f"CPU sample interval {interval_ns} ns: no time elapsed")
    if idle_delta_ns <= 0:
        raise AssertionError(
            f"idle time advanced by {idle_delta_ns} ns across {interval_ns} ns: an idle "
            "guest must accumulate idle time, so this is not a live reading"
        )
    # Physically impossible to exceed: N cores cannot accumulate more idle nanoseconds
    # than N x the elapsed wall time.
    if idle_delta_ns > interval_ns * reported:
        raise AssertionError(
            f"{reported} core(s) reported {idle_delta_ns} ns idle across {interval_ns} ns "
            "of wall time, which is more idle time than existed"
        )
    if not (0 <= mean_pct <= 100):
        raise AssertionError(f"mean utilisation {mean_pct}% is not a percentage")

    disk = _last_marker(text, DISK_OK)
    if disk.get("state") != "MOUNTED":
        raise AssertionError(f"file server storage state is {disk.get('state')!r}, expected MOUNTED")
    disk_total = _int_field(disk, "total_bytes", DISK_OK)
    disk_used = _int_field(disk, "used_bytes", DISK_OK)
    # EXACT: this harness created the image, and the file server takes the whole raw
    # device. There is no rounding to hide behind.
    if disk_total != NVME_BYTES:
        raise AssertionError(
            f"mounted filesystem reports {disk_total} B; this harness created a "
            f"{NVME_BYTES} B NVMe image and the file server claims the whole device"
        )
    if not (0 < disk_used < disk_total):
        raise AssertionError(
            f"used {disk_used} B is not between 0 and {disk_total} B; a freshly formatted "
            "fxfs has real metadata, so zero would mean the number was not measured"
        )
    return {"mem_total": total_bytes, "cores": cores, "disk_total": disk_total}


def assert_panel_shows(screenshot, font, values):
    """Asserts the validated numbers are physically drawn on the panel.

    The expected strings are formatted HERE, from the raw numbers already validated
    above — never scraped from the guest's own output.
    """
    ppm = panel_check.read_ppm(screenshot)
    # Cheap first, so a wholesale regression (nothing scanned out) says so plainly
    # rather than reporting a glyph that was not found. It is a smoke check and nothing
    # more — a title bar satisfies it, which is why it is not the assertion below.
    panel_check.assert_not_flat(ppm, "console screendump")
    found = {}
    found["memory"] = panel_check.assert_panel_value(
        ppm, font, "total", panel_check.mib(values["mem_total"]), "Memory total"
    )
    found["cpu"] = panel_check.assert_panel_value(
        ppm, font, "cores", str(values["cores"]), "CPU core count"
    )
    for key, heading in (
        ("vms", "Virtual Machines"),
        ("store", "VM Image Store"),
    ):
        hits = panel_check.find_text(
            ppm, [(heading, panel_check.C_ACCENT)], font
        )
        if len(hits) != 1:
            raise AssertionError(
                f"{heading}: expected exactly one on-screen heading, found "
                f"{len(hits)}{' at ' + str(hits) if hits else ''}"
            )
        found[key] = hits[0]
    # STRUCTURAL, not coordinate-hardcoded. All four rows are drawn by Column::row in
    # the one right-hand column, so they share an x; and the sections are rendered in a
    # fixed order, so their y increases VM -> Memory -> CPU -> snapshot model. Requiring
    # that rules out the strings being found scattered anywhere on the screen — which a
    # whole-framebuffer search alone would allow — without freezing the layout into the
    # test, which would break on any legitimate reflow.
    value_xs = {k: found[k][0] for k in ("memory", "cpu")}
    heading_xs = {k: found[k][0] for k in ("vms", "store")}
    if len(set(value_xs.values())) != 1 or len(set(heading_xs.values())) != 1:
        raise AssertionError(
            f"panel content is not aligned by kind: values={value_xs}, "
            f"headings={heading_xs}"
        )
    order = [
        found["vms"][1],
        found["store"][1],
        found["memory"][1],
        found["cpu"][1],
    ]
    if not (order[0] < order[1] < order[2] < order[3]):
        raise AssertionError(
            f"panel rows are out of section order (VMs, store, memory, CPU) at y={order}"
        )
    return ppm, found


def _wait_for(serial, needle, fail_needles, proc, deadline):
    # Fail markers are tested BEFORE the success needle: a file server that refused its
    # disk still emits CERISE-FILESERVER-LISTENING (it serves, answering
    # FAILED_PRECONDITION), so needle-first would let that boot pass.
    while time.time() < deadline:
        txt = serial.read_text(errors="replace") if serial.exists() else ""
        for fn in fail_needles:
            if fn in txt:
                tail = txt[txt.rfind(fn):][:400]
                raise AssertionError(f"guest failure marker: {tail}")
        if needle in txt:
            return txt
        if proc.poll() is not None:
            raise AssertionError(f"QEMU exited early ({proc.returncode})")
        time.sleep(3)
    raise AssertionError(f"timed out waiting for {needle}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--qemu", required=True)
    ap.add_argument("--shim", required=True)
    ap.add_argument("--zbi", required=True)
    ap.add_argument("--qemu-data-dir", required=True)
    # The renderer's own glyph table. Parsed rather than transcribed so the gate's idea
    # of what a digit looks like cannot drift from what the console actually draws.
    ap.add_argument("--font", required=True)
    ns = ap.parse_args()
    qemu = _need(ns.qemu, "qemu")
    shim = _need(ns.shim, "shim")
    zbi = _need(ns.zbi, "zbi")
    datadir = _need(ns.qemu_data_dir, "qemu data dir")

    tmp = pathlib.Path(os.environ.get("TEST_TMPDIR", "/tmp"))
    outdir = pathlib.Path(os.environ.get("TEST_UNDECLARED_OUTPUTS_DIR", str(tmp)))
    outdir.mkdir(parents=True, exist_ok=True)
    serial = tmp / "console-serial.log"
    if serial.exists():
        serial.unlink()
    nvme = tmp / "console-fxfs-nvme.img"
    with open(nvme, "wb") as f:
        f.truncate(NVME_BYTES)
    qmp_port = _free_port()
    fwd_port = _free_port()
    screenshot = outdir / "console-screendump.ppm"

    cmd = [qemu, "-L", datadir, "-machine", "q35", "-display", "none",
           "-monitor", "none", "-no-reboot", "-m", f"{GUEST_MEM_MB}M",
           "-smp", str(GUEST_SMP),
           "-cpu", "qemu64,+popcnt,+sse4.1,+sse4.2,+ssse3,+aes,+avx",
           "-serial", f"file:{serial}",
           "-qmp", f"tcp:127.0.0.1:{qmp_port},server,nowait",
           "-netdev", f"user,id=net0,hostfwd=tcp:127.0.0.1:{fwd_port}-:50051",
           "-device", "virtio-net-pci,disable-legacy=on,netdev=net0,romfile=",
           "-drive", f"file={nvme},if=none,format=raw,id=nvm0",
           "-device", "nvme,drive=nvm0,serial=deadbeef",
           "-device", "VGA",
           "-kernel", shim, "-initrd", zbi]
    print("[console] booting qemu-x64-console (fileserver + status_console) + VGA + QMP",
          flush=True)
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                            start_new_session=True)
    try:
        deadline = time.time() + BOOT_TIMEOUT_S
        _wait_for(serial, CONSOLE_RENDERED, [CONSOLE_FAIL], proc, deadline)
        print(f"[console] {CONSOLE_RENDERED} (console is drawing)", flush=True)
        # Wait for the network to come up so the console has repainted with the IP.
        _wait_for(serial, LISTENING, [FS_FAIL, FS_DEGRADED, CONSOLE_FAIL], proc, deadline)
        print(f"[console] {LISTENING} (network up, IP assigned)", flush=True)

        # The metrics markers are emitted only AFTER a paint that contained them, and a
        # metric that could not be read emits its -UNAVAILABLE instead. Wait for all
        # three to SETTLE into -OK, with storage actually MOUNTED — CPU needs a second
        # sample and the file server surveys the disk a minute or so into boot, so the
        # early frames are honestly incomplete and screenshotting one would prove
        # nothing. A metric that never settles times out; one that settles unavailable
        # never satisfies this loop.
        pending = ""
        while time.time() < deadline:
            text = serial.read_text(errors="replace") if serial.exists() else ""
            for fn in (CONSOLE_FAIL, FS_FAIL, FS_DEGRADED):
                if fn in text:
                    raise AssertionError(f"guest failure marker: {text[text.rfind(fn):][:400]}")
            states = {f: _metric_settled(text, f) for f in ("MEM", "CPU", "DISK")}
            unsettled = [f"{f}: {why or 'no marker yet'}" for f, (ok, why) in states.items() if ok is None]
            disk_fields = states["DISK"][0]
            if disk_fields is not None and disk_fields.get("state") != "MOUNTED":
                unsettled.append(f"DISK: state={disk_fields.get('state')}")
            if not unsettled:
                break
            pending = "; ".join(unsettled)
            if proc.poll() is not None:
                raise AssertionError(f"QEMU exited early ({proc.returncode})")
            time.sleep(3)
        else:
            raise AssertionError(f"metrics never settled on the panel: {pending}")
        print("[console] memory + CPU + storage all settled and painted", flush=True)

        values = check_reported_values(text)
        print(f"[console] raw values validated against this harness's own configuration: "
              f"{values}", flush=True)

        font = panel_check.load_font(_need(ns.font, "font.rs"))

        # Presentation is dirty-span based, so a dump normally sees a complete frame.
        # Retry anyway because QMP and scanout are asynchronous and can overlap a publish.
        # Bounded, and deliberately much shorter than the boot deadline: the panel
        # repaints every couple of seconds, so a minute of identical failures is a panel
        # that is not going to draw the value, not a capture that keeps landing badly.
        # Running this loop to the full boot deadline makes a real red take ten minutes
        # (measured on the first-light gate), which is how a gate stops being run.
        last_err = None
        capture_deadline = min(deadline, time.time() + 120.0)
        while time.time() < capture_deadline:
            qmp = Qmp("127.0.0.1", qmp_port)
            try:
                qmp.execute("screendump", {"filename": str(screenshot)})
            finally:
                qmp.close()
            if not screenshot.is_file():
                raise AssertionError("QMP screendump produced no file")
            try:
                ppm, found = assert_panel_shows(screenshot, font, values)
                # RE-READ THE SERIAL LOG AFTER the capture and require the identity to be
                # unchanged and still settled. Without this the gate could validate an
                # early frame and never notice a metric that went unavailable afterwards,
                # or accept a stale screenshot whose values had since moved.
                after = serial.read_text(errors="replace")
                if check_reported_values(after) != values:
                    raise AssertionError(
                        "the reported values changed between validation and capture; "
                        "the screendump does not describe the current panel"
                    )
                break
            except AssertionError as e:
                last_err = e
                if proc.poll() is not None:
                    raise AssertionError(f"QEMU exited early ({proc.returncode})") from e
                time.sleep(2)
        else:
            raise AssertionError(f"panel never showed the reported values: {last_err}")

        w, h, _ = ppm
        print(f"[console] PASS: {w}x{h} status screen captured to {screenshot} "
              f"({screenshot.stat().st_size} bytes). Verified ON SCREEN by exact "
              f"full-cell glyph match: VM inventory heading at {found['vms']}, image "
              f"store heading at {found['store']}, memory total "
              f"{panel_check.mib(values['mem_total'])} at {found['memory']}, CPU cores "
              f"{values['cores']} at {found['cpu']}", flush=True)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
    return 0


if __name__ == "__main__":
    sys.exit(main())

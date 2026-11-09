#!/usr/bin/env python3
"""OS-self-OTA UPDATE gate: the in-OS updater applies a new OS image the shim then boots.

The ESP (a real protective-MBR/GPT disk booted under OVMF like hardware) is staged with:
  \\zircon_a.zbi = //products:qemu-x64-ota      (v1 factory; ota_updater apply=true)
  \\zircon_b.zbi = a placeholder (overwritten)
  \\abr          = active=A, tries=[A:0,B:1... actually A:0], successful=[A:1,B:0]

A host-side plain-HTTP server (127.0.0.1:52099) serves the v2 image
(//products:qemu-x64-ota-v2's ZBI) as /zbi plus a /manifest.json.

THE MANIFEST IS NOT COMPUTED HERE ANY MORE, AND THAT IS THE POINT. It used to be:
this harness ran hashlib.sha256() over the very bytes it was about to serve as the
image, so the manifest and the image always moved together and the device's "integrity
check" could not fail. A substituted image plus its recomputed manifest passed
identically to a genuine pair, and no tampered-image negative test was CONSTRUCTIBLE.
The manifest is now built at build time by //src/cerise/ota_updater:ota_signer from the
private seed under //build/keys and carries an ed25519 signature; the device holds only
the derived public key, staged in its own package. This harness serves that file
verbatim and cannot forge another. `--tamper-manifest` then serves the deliberately
corrupted-signature variant the same tool emits, which is what makes
//validation:ota-update-tamper-boot possible at all.

TWO MODES.

  DEFAULT (the positive gate): two launches against the SAME writable disk (persistence
  lives on the disk, not in RAM), described below.

  --tamper-manifest (//validation:ota-update-tamper-boot): ONE launch, serving the
  corrupt-signature manifest, which must be REFUSED. See tamper_run() for what it
  asserts, including a byte-level check that the offered image never reached the disk.

  LAUNCH 1 (slot A, apply=true): shim boots A. The updater success-commits A (already
    good => CERISE-OTA-PERSISTED), brings up the NIC + DHCP, fetches the v2 ZBI and
    verifies its SIGNED manifest (CERISE-OTA-SIG-OK), writes it to \\zircon_b.zbi,
    flips \\abr to B (tries=3),
    emits CERISE-OTA-APPLIED, and requests a warm reboot (CERISE-SHUTDOWN-REBOOT-REQUESTED).
    The harness then kills QEMU and relaunches (not depending on the guest reset re-running
    OVMF).

  LAUNCH 2 (slot B): shim reads \\abr (active=B) and boots \\zircon_b.zbi = v2. The updater
    (apply=false) success-commits B for the first time (CERISE-OTA-COMMITTED), prints
    CERISE-OS-VERSION=2 — proving the fetched image booted — and does NOT re-apply.

The remaining step — that a committed slot B keeps booting B on a later reboot with no
re-apply — is proven by //validation:ota-persist-boot (a single launch off a pre-staged
committed-B disk), split out so each gate's QEMU runtime stays under the foreground cap.
"""
from __future__ import annotations
import argparse
import gzip
import hashlib
import http.server
import json
import os
import pathlib
import shutil
import socketserver
import subprocess
import sys
import threading
import time

HTTP_PORT = 52099  # must match ota_updater's HOST_ADDR (10.0.2.2:52099)

SLOT_A = "CERISE-ABR-SLOT=A"
SLOT_B = "CERISE-ABR-SLOT=B"
OS_V1 = "CERISE-OS-VERSION=1"
OS_V2 = "CERISE-OS-VERSION=2"
PERSISTED = "CERISE-OTA-PERSISTED"
COMMITTED = "CERISE-OTA-COMMITTED"
FETCH_OK = "CERISE-OTA-FETCH-OK"
APPLIED = "CERISE-OTA-APPLIED"
REBOOT_REQ = "CERISE-SHUTDOWN-REBOOT-REQUESTED"
# The trust root was found and loaded. Required on the apply launch: without it the
# updater refuses, so its ABSENCE would silently mean the signature gate never ran.
PUBKEY_OK = "CERISE-OTA-PUBKEY-OK"
# The signed manifest verified. Distinct from FETCH_OK on purpose: FETCH_OK also
# existed in the sha256-only design, so requiring it alone would not prove the
# signature was checked.
SIG_OK = "CERISE-OTA-SIG-OK"
# The ESP was located by a fully validated GPT parse (header CRC, entry-array CRC,
# checked geometry) rather than guessed at.
ESP_OK = "CERISE-OTA-ESP-OK"
# The image was refused. `CERISE-OTA-IMAGE-REJECT: <token>` — bad-signature,
# hash-mismatch, rollback, no-pubkey, ...
IMAGE_REJECT = "CERISE-OTA-IMAGE-REJECT"
# The GPT parse refused to nominate a partition. Previously impossible: with no ESP
# the updater fell back to the first non-empty partition and wrote the OS image there.
ESP_REFUSED = "CERISE-OTA-ESP-REFUSED"
# The fallback that used to redirect a whole-OS-image write to an arbitrary partition.
# It no longer exists; if this string ever reappears in a log, it came back.
ESP_FALLBACK_WARN = "ESP type-GUID not matched"

FAIL_MARKERS = ["CERISE-OTA-FAIL", "CERISE-ABR-NO-BOOTABLE", "CERISE-ABR-WRITE-FAIL",
                "KERNEL PANIC", "triple fault", "KERNEL FAULT"]
# Forbidden on the POSITIVE gate: a run that refuses the image or the partition table,
# or that guesses at a partition, must not be able to reach a green verdict by any
# route. These are separate from FAIL_MARKERS because the tamper gate REQUIRES the
# first of them.
POSITIVE_FORBIDDEN = [IMAGE_REJECT, ESP_REFUSED, ESP_FALLBACK_WARN,
                      "CERISE-OTA-NO-PUBKEY", "CERISE-OTA-PUBKEY-BAD"]
# Heavy netstack3+AHCI product under TCG (no KVM): the existing storage/net gates budget
# 900s just to reach their probe markers; the apply launch additionally does DHCP, a 47 MB
# HTTP fetch, and a 47 MB fatfs write. Give each launch a generous window (matches the
# run-qemu.sh heavy-product timeouts, with headroom for the slot write).
BOOT_TIMEOUT_S = 1500.0
# How long the tamper gate keeps watching AFTER the refusal marker appears. A refusal
# that is followed by a write is the failure mode this gate exists to exclude, and it
# cannot be excluded by observing the log only up to the moment of refusal.
SETTLE_S = 20.0


def _need(path, what):
    if not path or not os.path.exists(path):
        raise SystemExit(f"{what} not found: {path}")
    return path


def make_server(zbi_bytes: bytes, manifest: bytes):
    """Serve the image and a manifest this harness did NOT produce.

    `manifest` comes from //src/cerise/ota_updater:ota_signer at build time and is
    served byte for byte. The harness has no access to the private seed, so it cannot
    construct a manifest the device would accept for any other bytes — which is exactly
    the property the old design lacked.
    """
    # Per-path request counts. Asserted by both modes: without this the gate cannot
    # tell "the guest fetched and refused" from "the guest never got as far as asking",
    # and a boot that fails before the network comes up would look like a refusal.
    counter = {"/manifest.json": 0, "/zbi": 0, "other": 0}

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            counter[self.path if self.path in counter else "other"] += 1
            if self.path == "/manifest.json":
                body = manifest
            elif self.path == "/zbi":
                body = zbi_bytes
            else:
                self.send_response(404)
                self.end_headers()
                return
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    class ReusableServer(socketserver.ThreadingTCPServer):
        allow_reuse_address = True
        daemon_threads = True

    httpd = ReusableServer(("127.0.0.1", HTTP_PORT), Handler)
    return httpd, counter


def boot(qemu, datadir, code, ovmf_vars, disk, serial):
    if serial.exists():
        serial.unlink()
    # -enable-kvm: this heavy AHCI + netstack3 + updater product takes ~700s just
    # to bind AHCI under pure-TCG emulation; with KVM the same boot is seconds, so
    # the whole gate fits the foreground time budget. Keep the controlled qemu64
    # CPU model the other Cerise gates use (NOT -cpu host — passing through host
    # features page-faults the Zircon kernel at ~91ms). Fall back to TCG if KVM
    # can't be opened.
    accel = ["-enable-kvm"] if os.access("/dev/kvm", os.R_OK | os.W_OK) else []
    cmd = [qemu, "-L", datadir, "-machine", "q35", "-display", "none",
           "-monitor", "none", "-no-reboot", "-m", "4096M", *accel,
           "-cpu", "qemu64,+popcnt,+sse4.1,+sse4.2,+ssse3,+aes,+avx",
           "-serial", f"file:{serial}",
           "-netdev", "user,id=net0",
           "-device", "virtio-net-pci,disable-legacy=on,netdev=net0,romfile=",
           "-drive", f"if=pflash,format=raw,readonly=on,file={code}",
           "-drive", f"if=pflash,format=raw,file={ovmf_vars}",
           # cache=writeback (not writethrough): the updater writes a ~45 MB ZBI
           # into the ESP FAT via fatfs — one block FIFO op per cluster. A host
           # fsync per op (writethrough) makes that ~10x slower. The updater
           # issues an explicit block FLUSH (client.flush()) after the slot +
           # \abr writes, so the bytes are durable in the host file before the
           # next launch reads it; between launches the OS page cache keeps the
           # view consistent (same host file, sequential QEMU processes).
           "-drive", f"if=none,id=ota,format=raw,cache=writeback,file={disk}",
           "-device", "ide-hd,drive=ota,bus=ide.0"]
    return subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                            start_new_session=True)


def stop(proc):
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            # Wait after the kill as well: the measurement that follows reads the disk
            # image, and a QEMU still holding it has not necessarily flushed.
            proc.wait(timeout=30)


def wait_for(serial, needle, proc, deadline, forbidden=(), fail_markers=FAIL_MARKERS):
    """Poll the serial log for `needle`.

    NEGATIVE ASSERTIONS ARE CHECKED FIRST, on every poll, before the success test. The
    reverse order (which this harness used to have) lets a snapshot that contains both a
    failure and the success marker be accepted on the strength of the success marker.
    This is the ordering tests/zircon/zbi_boot_test.py:228-243 already uses.
    """
    while time.time() < deadline:
        txt = serial.read_text(errors="replace") if serial.exists() else ""
        for fm in fail_markers:
            if fm in txt:
                raise AssertionError(f"guest failure marker {fm!r}: {txt[txt.rfind(fm):][:500]}")
        for fb in forbidden:
            if fb in txt:
                raise AssertionError(f"forbidden marker {fb!r}: {txt[txt.rfind(fb):][:500]}")
        if needle in txt:
            return txt
        if proc.poll() is not None:
            raise AssertionError(f"QEMU exited early (rc={proc.returncode})\n{txt[-1500:]}")
        time.sleep(3)
    raise AssertionError(f"timed out waiting for {needle!r}\n"
                         f"{(serial.read_text(errors='replace') if serial.exists() else '')[-2000:]}")


def assert_ordered(txt, markers):
    last = -1
    for m in markers:
        i = txt.find(m, last + 1)
        if i < 0:
            raise AssertionError(f"missing expected marker {m!r}\n--- tail ---\n{txt[-2000:]}")
        last = i


def assert_absent(txt, markers, why):
    for m in markers:
        if m in txt:
            raise AssertionError(f"{why}: found {m!r}\n{txt[txt.rfind(m):][:500]}")


# The updater writes a ~45 MiB ZBI into the inactive slot. These bound "an OS image was
# written" against "nothing much happened", in units the write itself cannot fake.
#
# A REFUSED update must leave the disk essentially untouched. Not bit-for-bit: the boot
# shim may rewrite the 16-byte \abr record and FAT metadata around it, so a small budget
# is allowed. 1 MiB is ~45x smaller than the smallest thing a slot write could be, so
# there is no value a real slot write could land in.
MAX_REFUSED_DELTA = 1 << 20
# An APPLIED update must change at least this much: the slot file is ~45 MiB and was
# previously a small placeholder, so essentially all of it is newly written.
MIN_APPLIED_DELTA = 20 << 20


def disk_delta(pristine: bytes, after: bytes) -> int:
    """How many bytes of the disk image changed.

    THIS REPLACED A CONTENT PROBE THAT DID NOT WORK, AND THE FAILURE IS WORTH RECORDING.
    The first version searched the disk for byte windows unique to the v2 image, on the
    assumption that v1 and v2 — the same product differing only in one staged config
    file — would diverge in content. Measured against the real artifacts, they do not in
    the way that assumption needed: every one of 128 sampled 512-byte windows of v2 was
    found SOMEWHERE in v1. The two images carry the same material at shifted offsets, so
    "is this window unique to v2" is not a question the bytes can answer, and a probe
    built that way would either never fire or fire for reasons unrelated to the write.

    Counting changed bytes needs no such assumption, and is the stronger claim for the
    negative gate anyway: it catches the updater writing ANYTHING, not merely writing
    the particular image that was offered.
    """
    if len(pristine) != len(after):
        raise AssertionError(f"disk changed size: {len(pristine)} -> {len(after)}")
    # zip over 64 KiB slices: fast enough on a 300 MiB image, and exact.
    n = 0
    step = 1 << 16
    for i in range(0, len(pristine), step):
        a, b = pristine[i:i + step], after[i:i + step]
        if a != b:
            n += sum(1 for x, y in zip(a, b) if x != y)
    return n


def human_mib(n: int) -> str:
    return f"{n / (1 << 20):.2f} MiB"


def assert_fetched(counter, what):
    """The guest must actually have asked the host for both objects."""
    if counter["/manifest.json"] < 1 or counter["/zbi"] < 1:
        raise AssertionError(
            f"{what}: the guest did not fetch both objects (manifest="
            f"{counter['/manifest.json']}, zbi={counter['/zbi']}) — so whatever the log "
            "says, it is not a verdict about the served image")


def positive_run(qemu, datadir, code, ovmf_vars, disk, tmp, pristine, counter):
    """Two launches: apply the signed v2 image, then boot the slot it was written to."""
    # ---- Launch 1: slot A applies the update. ----
    serial1 = tmp / "ota-update-1.log"
    proc = boot(qemu, datadir, code, ovmf_vars, disk, serial1)
    try:
        print("[ota-update] launch 1: slot A fetches + verifies + stages v2", flush=True)
        deadline = time.time() + BOOT_TIMEOUT_S
        wait_for(serial1, REBOOT_REQ, proc, deadline, forbidden=POSITIVE_FORBIDDEN)
        txt = serial1.read_text(errors="replace")
        # One block session does commit + stage-inactive-slot, so the fetch (and
        # FETCH_OK) precedes the commit's PERSISTED; APPLIED then REBOOT_REQ (the
        # shim actually handling statecontrol PerformReboot) close it out.
        #
        # PUBKEY_OK and SIG_OK are REQUIRED, not merely un-forbidden: the updater
        # refuses without a key, so if the key were dropped from the product staging
        # this gate would otherwise go red only via a generic OTA-FAIL, and if the
        # signature check were removed it would not go red at all. ESP_OK likewise
        # proves the validated parse ran rather than being skipped.
        assert_ordered(txt, [SLOT_A, OS_V1, PUBKEY_OK, FETCH_OK, SIG_OK,
                             ESP_OK, PERSISTED, APPLIED, REBOOT_REQ])
        assert_absent(txt, POSITIVE_FORBIDDEN, "a successful apply must not refuse anything")
        print("[ota-update] launch 1 OK: A -> verified v2 -> APPLIED -> reboot requested",
              flush=True)
    finally:
        stop(proc)

    # The marker said it applied; check the disk says so too. This is also what makes
    # the tamper gate's negated version of the same measurement meaningful: the same
    # number is shown HERE to go large when an image really is written, so a small one
    # there is evidence rather than a property the measurement always had.
    assert_fetched(counter, "apply launch")
    delta = disk_delta(pristine, disk.read_bytes())
    print(f"[ota-update] launch 1 fetched manifest x{counter['/manifest.json']} "
          f"zbi x{counter['/zbi']} and wrote {human_mib(delta)} to the disk", flush=True)
    if delta < MIN_APPLIED_DELTA:
        raise AssertionError(
            f"CERISE-OTA-APPLIED was printed but only {human_mib(delta)} of the disk "
            f"changed (a slot write is ~45 MiB; need >= {human_mib(MIN_APPLIED_DELTA)})")

    # ---- Launch 2: shim boots the newly-staged slot B (v2). ----
    serial2 = tmp / "ota-update-2.log"
    proc = boot(qemu, datadir, code, ovmf_vars, disk, serial2)
    try:
        print("[ota-update] launch 2: shim should boot slot B = v2", flush=True)
        deadline = time.time() + BOOT_TIMEOUT_S
        wait_for(serial2, COMMITTED, proc, deadline, forbidden=POSITIVE_FORBIDDEN)
        txt = serial2.read_text(errors="replace")
        assert_ordered(txt, [SLOT_B, OS_V2, ESP_OK, COMMITTED])
        # The update took effect: the shim booted the newly-staged slot B, it
        # is v2, and it committed. Persistence across a further reboot (still B,
        # no re-apply) is proven separately by //validation:ota-persist-boot,
        # which boots a pre-staged committed-B disk — split out so each gate's
        # QEMU run stays well under the foreground time cap.
        if APPLIED in txt:
            raise AssertionError("launch 2 unexpectedly re-applied (v2 should have apply=false)")
        print("[ota-update] launch 2 OK: SLOT=B, OS-VERSION=2, COMMITTED, no re-apply",
              flush=True)
    finally:
        stop(proc)


def tamper_run(qemu, datadir, code, ovmf_vars, disk, tmp, pristine, counter):
    """One launch, serving an image whose manifest signature is corrupt.

    THE NEGATIVE CONTROL. Everything the positive gate asserts about verification is
    only worth asserting if a bad image can be shown to be refused, and until the
    manifest was signed no bad image was constructible: the harness computed the digest
    from the bytes it served, so its own substitutions were self-consistent by
    construction. //src/cerise/ota_updater:ota_signer --tamper produces a manifest
    identical to the genuine one in every field except one hex character of the
    signature, and this run serves it.

    Three assertions, in increasing strength:
      1. the guest REQUIRES `CERISE-OTA-IMAGE-REJECT: bad-signature` — a specific
         reason, so a refusal for some unrelated reason (no key staged, the network
         never came up, a hash mismatch from a build wiring slip) fails this gate
         instead of passing it as a "successful" rejection;
      2. it FORBIDS `CERISE-OTA-APPLIED` and `CERISE-OTA-SIG-OK`;
      3. the disk is essentially unchanged afterwards — the same measurement the
         positive run shows going to tens of MiB when an image really is written.
         Markers can be printed by code that also wrote; changed bytes cannot.
    """
    serial = tmp / "ota-tamper.log"
    proc = boot(qemu, datadir, code, ovmf_vars, disk, serial)
    try:
        print("[ota-tamper] serving a manifest with a corrupted signature; expecting refusal",
              flush=True)
        deadline = time.time() + BOOT_TIMEOUT_S
        # CERISE-OTA-FAIL is EXPECTED here (the refusal propagates out of run()), so it
        # is not a fail marker for this mode. The panic patterns still are.
        wait_for(serial, IMAGE_REJECT, proc, deadline,
                 forbidden=[APPLIED, SIG_OK, FETCH_OK],
                 fail_markers=["KERNEL PANIC", "triple fault", "KERNEL FAULT",
                               "CERISE-ABR-NO-BOOTABLE"])
        txt = serial.read_text(errors="replace")
        assert_ordered(txt, [SLOT_A, OS_V1, PUBKEY_OK,
                             f"{IMAGE_REJECT}: bad-signature"])
        assert_absent(txt, [APPLIED, SIG_OK, FETCH_OK],
                      "a refused image must not be fetched-OK, verified or applied")
        print("[ota-tamper] guest refused with the expected reason", flush=True)

        # SETTLE BEFORE JUDGING. Accepting on the first read that shows the rejection
        # and killing QEMU immediately would let a "print the refusal, then write
        # anyway" implementation pass: the write would simply not have landed yet. Keep
        # the guest running and re-check, so the forbidden markers have to stay absent
        # and any write has time to reach the image file. This is the
        # --settle-seconds discipline tests/zircon/zbi_boot_test.py:260-266 already
        # applies for a panic flushed just after a success marker.
        settle_end = time.time() + SETTLE_S
        while time.time() < settle_end:
            time.sleep(3)
            txt = serial.read_text(errors="replace")
            assert_absent(txt, [APPLIED, SIG_OK, FETCH_OK],
                          "a refused image must not be applied after the refusal either")
        print(f"[ota-tamper] settled {SETTLE_S:.0f}s: still refused, nothing applied",
              flush=True)
    finally:
        stop(proc)
    # Terminate first, THEN measure: QEMU's writeback cache is flushed to the image
    # file on shutdown, so measuring while it is still running could miss a write that
    # is only in the host's cache.

    # The refusal only means something if the guest actually fetched what it refused.
    assert_fetched(counter, "tamper run")
    delta = disk_delta(pristine, disk.read_bytes())
    print(f"[ota-tamper] fetched manifest x{counter['/manifest.json']} zbi x{counter['/zbi']}; "
          f"the refused run changed {human_mib(delta)} of the disk", flush=True)
    if delta > MAX_REFUSED_DELTA:
        raise AssertionError(
            f"a REFUSED update changed {human_mib(delta)} of the disk (budget "
            f"{human_mib(MAX_REFUSED_DELTA)}): the updater printed a rejection and "
            "wrote anyway")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--qemu", required=True)
    ap.add_argument("--qemu-data-dir", required=True)
    ap.add_argument("--ovmf-code", required=True)
    ap.add_argument("--ovmf-vars", required=True)
    ap.add_argument("--disk", required=True)
    ap.add_argument("--v2-zbi", required=True)
    ap.add_argument("--manifest", required=True,
                    help="the SIGNED manifest from //src/cerise/ota_updater:ota_signer. "
                         "Served verbatim; this harness cannot produce one.")
    ap.add_argument("--tamper-manifest", action="store_true",
                    help="negative mode: --manifest is the corrupt-signature variant and "
                         "the guest must refuse it")
    ns = ap.parse_args()
    qemu = _need(ns.qemu, "qemu")
    datadir = _need(ns.qemu_data_dir, "qemu data dir")
    code = _need(ns.ovmf_code, "OVMF_CODE")
    vars_src = _need(ns.ovmf_vars, "OVMF_VARS")
    disk_src = _need(ns.disk, "ota-update disk image")
    v2_zbi = pathlib.Path(_need(ns.v2_zbi, "v2 ZBI"))
    manifest_path = pathlib.Path(_need(ns.manifest, "signed manifest"))

    tmp = pathlib.Path(os.environ.get("TEST_TMPDIR", "/tmp"))
    ovmf_vars = tmp / "OVMF_VARS.fd"
    shutil.copyfile(vars_src, ovmf_vars)
    os.chmod(ovmf_vars, 0o644)
    disk = tmp / "ota-update-disk.img"
    with open(disk_src, "rb") as f:
        magic = f.read(2)
    if magic == b"\x1f\x8b":
        with gzip.open(disk_src, "rb") as src, open(disk, "wb") as dst:
            shutil.copyfileobj(src, dst)
    else:
        shutil.copyfile(disk_src, disk)
    os.chmod(disk, 0o644)

    zbi_bytes = v2_zbi.read_bytes()
    manifest_bytes = manifest_path.read_bytes()
    manifest = json.loads(manifest_bytes)

    # The manifest is built from the ZBI by a genrule; if the two ever came from
    # different builds, the guest would refuse for a hash reason and the tamper gate
    # would go green for entirely the wrong cause. Check the wiring here, where the
    # failure is legible, rather than letting it masquerade as a signature result.
    actual_sha = hashlib.sha256(zbi_bytes).hexdigest()
    if manifest["sha256"] != actual_sha or manifest["size"] != len(zbi_bytes):
        raise SystemExit(
            f"manifest does not describe the served ZBI (build wiring): manifest "
            f"sha256={manifest['sha256']} size={manifest['size']}, actual "
            f"sha256={actual_sha} size={len(zbi_bytes)}")
    if len(manifest.get("signature", "")) != 128:
        raise SystemExit(f"manifest carries no 128-hex signature: {manifest.get('signature')!r}")

    pristine = disk.read_bytes()

    httpd, counter = make_server(zbi_bytes, manifest_bytes)
    server_thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    server_thread.start()
    tag = "ota-tamper" if ns.tamper_manifest else "ota-update"
    print(f"[{tag}] host v2 server on 127.0.0.1:{HTTP_PORT} (sha256={actual_sha[:16]}..., "
          f"sig={manifest['signature'][:16]}...); guest reaches it at 10.0.2.2:{HTTP_PORT}",
          flush=True)

    try:
        if ns.tamper_manifest:
            tamper_run(qemu, datadir, code, ovmf_vars, disk, tmp, pristine, counter)
        else:
            positive_run(qemu, datadir, code, ovmf_vars, disk, tmp, pristine, counter)
    finally:
        httpd.shutdown()

    print(f"[{tag}] PASS", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())

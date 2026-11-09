#!/usr/bin/env bash
# The PASS CONTRACT for an `ut all` run of //tests/zircon:cf-sz5-kernel-utest on
# the real Panasonic CF-SZ5, checked against a serial log that `amtterm` (or any
# other capture) is writing over AMT Serial-over-LAN.
#
#     bazel run //tests/zircon:cf-sz5-utest-contract -- /abs/path/to/sol.log [extra flags]
#
# It runs the SAME zbi_boot_test.py that //tests/zircon:kernel-utest-boot uses,
# in --no-launch mode: nothing is booted here, the contract is just applied to a
# log someone else is filling. That shared implementation is the point — the
# hardware run and the QEMU gate cannot drift apart in what they call a pass.
#
# WHY THE CONTRACT IS WHAT IT IS. Under TCG the very same image reports
# (re-measured 2026-07-26 on a captured TCG boot; the counts below used to say
# 45/45 and had drifted from the code)
#
#     hypervisor-enter : All tests passed (59/59)
#     SUMMARY: Ran 7 test cases: 0 failed
#     BOOT_TEST_SUCCESS:userspace-started
#
# while printing "VMX not supported here" 57 times — every hypervisor test
# self-skipped, and a skip is a PASS to Zircon's unittest framework. Verified by
# capture, not assumed. So the first three assertions below prove only "the
# kernel booted and its suites are green"; it is the last two that make a run on
# the laptop mean anything at all. Native VMX is the whole reason to be on that
# machine, so the run must show POSITIVE evidence that a VMLAUNCH happened
# (guest-entry OK, printed only after Vcpu::Enter() returns a real guest I/O
# exit) and must contain ZERO self-skips. Absence of the skip line alone is not
# proof — a suite that never ran also never prints it.
#
# DEPTH IS NOW CHECKED HERE, not left to the caller. This comment used to say the
# log proved a VMLAUNCH executed but not WHERE, and that "Cerise as L0" rested on
# the provenance of the capture. The kernel banner settles it: a native boot
# reports "Hypervisor: None" and a boot under qemu -accel=kvm reports
# "Hypervisor: KVMKVMKVM" (both measured). That marker is required below.
#
# What is still the caller's job: that the bytes came off the CF-SZ5's AMT
# Serial-over-LAN port at all, rather than from some other bare-metal machine.
#
# argv: $1 = serial log path; remaining args are forwarded to the harness
# (e.g. --timeout-seconds=600, or --alive-command="pgrep -x amtterm").
set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "usage: $0 <serial-log-path> [extra zbi_boot_test.py flags...]" >&2
  exit 2
fi
# The log path is the first NON-FLAG argument, not simply $1. Taking $1 blindly
# meant `-- --static-log /path/to/log` consumed the flag as the path and pushed
# the real path through as a stray positional, failing with an unhelpful
# "unrecognized arguments".
LOG=""
EXTRA=()
for arg in "$@"; do
  if [[ -z "${LOG}" && "${arg}" != -* ]]; then
    LOG="${arg}"
  else
    EXTRA+=("${arg}")
  fi
done
if [[ -z "${LOG}" ]]; then
  echo "usage: $0 <serial-log-path> [extra zbi_boot_test.py flags...]" >&2
  exit 2
fi

# --settle-seconds only means something while a capture is still being written;
# the harness rejects it outright with --static-log. Drop our default rather than
# making every caller pass --settle-seconds=0 to undo it.
STATIC_LOG=0
for arg in ${EXTRA[@]+"${EXTRA[@]}"}; do
  [[ "${arg}" == --static-log* ]] && STATIC_LOG=1
done

RUNFILES="${RUNFILES_DIR:-${TEST_SRCDIR:-}}"
if [[ -z "${RUNFILES}" ]]; then
  RUNFILES="${0}.runfiles"
fi
HARNESS=""
for base in "${RUNFILES}" "${RUNFILES}/_main" "${RUNFILES}/cerise"; do
  if [[ -e "${base}/tests/zircon/zbi_boot_test.py" ]]; then
    HARNESS="${base}/tests/zircon/zbi_boot_test.py"
    break
  fi
done
if [[ -z "${HARNESS}" ]]; then
  # `|| true` matters under `set -e`: find exits non-zero when RUNFILES does not
  # exist (running this outside bazel), and the assignment would then kill the
  # script with NO output at all — indistinguishable from a contract failure.
  HARNESS="$(find "${RUNFILES}" -path '*/tests/zircon/zbi_boot_test.py' -print -quit 2>/dev/null || true)"
fi
if [[ -z "${HARNESS}" ]]; then
  echo "cannot find zbi_boot_test.py in runfiles ${RUNFILES}" >&2
  exit 2
fi

CONTRACT=(
  --no-launch
  --serial-log="${LOG}"

  # Printed by `boot-test-success` ONLY when `ut all` returned 0.
  --marker=BOOT_TEST_SUCCESS:userspace-started

  # A non-zero case count, so a vacuous zero-case run cannot pass.
  --require-regex='Ran [1-9][0-9]* test cases?: 0 failed'

  # The hypervisor suite specifically reached a GREEN TERMINAL summary. A failing
  # suite ABORTS at its first failure, so without this a run that stopped before
  # the hypervisor tests could still satisfy the line above.
  --require-regex='hypervisor-enter : All tests passed \([1-9][0-9]*/[1-9][0-9]*\)'

  # POSITIVE proof that a VMLAUNCH actually executed and a guest ran: printed only
  # after Vcpu::Enter() returns the guest's I/O exit (guest_enter_test.cc). Absent
  # from a TCG capture, and absent from a run where the suite never executed.
  --require-regex='guest-entry OK: nested VMLAUNCH ran a 64-bit guest'

  # ...and not one of those tests skipped itself for want of VT-x.
  --forbid-regex='VMX not supported here'

  # PROOF OF DEPTH. The kernel's own banner reports what is above it, and the two
  # cases are unambiguous (both measured 2026-07-25):
  #     CF-SZ5, booted natively     -> "Hypervisor: None"
  #     a dev host, qemu -accel=kvm -> "Hypervisor: KVMKVMKVM"
  # so requiring this makes the contract establish "Cerise is L0" itself, rather
  # than resting it on the caller's account of where the bytes came from. That
  # was previously listed below as something this script could not check.
  --require-regex='Hypervisor: None'

  # The red summary, for a suite that fails without panicking.
  --forbid='Not all tests passed'

  # A UART capture lags the machine: hold after the contract is met and re-check
  # the forbidden patterns, so a panic flushed just after BOOT_TEST_SUCCESS still
  # fails the run.
  # (added below only when the log is still being written)

  --timeout-seconds=600
)

if [[ "${STATIC_LOG}" -eq 0 ]]; then
  CONTRACT+=(--settle-seconds=10)
fi

exec python3 "${HARNESS}" "${CONTRACT[@]}" ${EXTRA[@]+"${EXTRA[@]}"}

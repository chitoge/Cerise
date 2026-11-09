#!/usr/bin/env bash
set -euo pipefail

runfiles="${RUNFILES_DIR:-${TEST_SRCDIR:-}}"
source_file=""
for candidate in \
    "$runfiles/cerise/src/cerise/drivers/e1000/e1000.cc" \
    "$runfiles/_main/src/cerise/drivers/e1000/e1000.cc" \
    "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/e1000.cc"; do
    if [[ -f "$candidate" ]]; then
        source_file="$candidate"
        break
    fi
done
if [[ -z "$source_file" ]]; then
    echo "manageability-ownership-test: e1000.cc is absent from runfiles" >&2
    exit 1
fi

if grep -Fq 'e1000_setup_link(&hw_)' "$source_file"; then
    echo "manageability-ownership-test: reset-time link setup escaped into the live driver" >&2
    exit 1
fi

if grep -Eq 'PhyRecovery|phy_recovery|RecoverReleasedPhy' "$source_file"; then
    echo "manageability-ownership-test: firmware PHY release must not trigger a background reset" >&2
    exit 1
fi

# One declaration, one definition, and the single driver-bind call are the
# complete InitHardware surface. A fourth occurrence means an interrupt,
# watcher, or netdevice callback can reset the shared controller after attach.
init_hardware_occurrences="$(grep -Ec 'InitHardware\(\)' "$source_file")"
if [[ "$init_hardware_occurrences" -ne 3 ]]; then
    echo "manageability-ownership-test: InitHardware escaped the single attach path" >&2
    exit 1
fi

if grep -Fq 'Wr(E1000_RAL(' "$source_file" || grep -Fq 'Wr(E1000_RAH(' "$source_file"; then
    echo "manageability-ownership-test: receive-address writes bypass the shared-code lock" >&2
    exit 1
fi

if grep -Eq 'Wr\(E1000_RCTL, E1000_RCTL_' "$source_file"; then
    echo "manageability-ownership-test: RCTL must be read-modify-written, not replaced" >&2
    exit 1
fi

if ! grep -Fq 'ConfigureReceiveControl(rctl_before, rx_hardware_strips_fcs_)' "$source_file"; then
    echo "manageability-ownership-test: receive setup bypasses the coexistence-preserving RCTL path" >&2
    exit 1
fi

if ! grep -Fq 'rx_hardware_strips_fcs_ = !IsPchManageabilityFamily(hw_.mac.type)' "$source_file"; then
    echo "manageability-ownership-test: shared PCH receive no longer retains the management FCS" >&2
    exit 1
fi

if ! grep -Fq 'HostFrameLength(d.length, rx_hardware_strips_fcs_)' "$source_file"; then
    echo "manageability-ownership-test: retained management FCS is exposed to the host netstack" >&2
    exit 1
fi

read_line="$(grep -Fn -m1 'e1000_read_mac_addr(&hw_)' "$source_file" | cut -d: -f1)"
init_line="$(grep -Fn -m1 'e1000_init_hw(&hw_)' "$source_file" | cut -d: -f1)"
if [[ -z "$read_line" || -z "$init_line" || "$read_line" -ge "$init_line" ]]; then
    echo "manageability-ownership-test: permanent MAC must be read before init_hw programs RAR0" >&2
    exit 1
fi

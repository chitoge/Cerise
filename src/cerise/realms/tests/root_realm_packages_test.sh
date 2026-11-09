#!/bin/sh
set -eu
exec python3 "${TEST_SRCDIR}/${TEST_WORKSPACE}/src/cerise/realms/tests/root_realm_packages_test.py" "$@"

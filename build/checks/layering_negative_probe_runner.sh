#!/usr/bin/env bash
set -euo pipefail

RUNFILES="${RUNFILES_DIR:-${TEST_SRCDIR:-}}"
if [[ -z "${RUNFILES}" ]]; then
  echo "ERROR: neither RUNFILES_DIR nor TEST_SRCDIR is set" >&2
  exit 1
fi

find_runfile() {
  local rel="$1"
  local candidate
  for candidate in \
    "${RUNFILES}/cerise/${rel}" \
    "${RUNFILES}/_main/${rel}" \
    "$(pwd)/${rel}"; do
    if [[ -f "${candidate}" ]]; then
      printf '%s\n' "${candidate}"
      return 0
    fi
  done
  return 1
}

read_includes() {
  local file="$1"
  grep -E '^[[:space:]]*#include[[:space:]]+"[^"]+"' "${file}" | \
    sed -E 's/^[[:space:]]*#include[[:space:]]+"([^"]+)".*$/\1/' | \
    sort -u
}

check_fixture_shape() {
  local good_c="$1"
  local good_h="$2"
  local bad_c="$3"
  local build_bazel="$4"

  local good_includes bad_includes
  good_includes="$(read_includes "${good_c}")"
  bad_includes="$(read_includes "${bad_c}")"

  if [[ "${good_includes}" != "layering_probe_good.h" ]]; then
    echo "expected good probe to include only layering_probe_good.h" >&2
    printf '%s\n' "${good_includes}" >&2
    return 1
  fi

  if [[ "${bad_includes}" != "layering_probe_good.h" ]]; then
    echo "expected bad probe to include layering_probe_good.h" >&2
    printf '%s\n' "${bad_includes}" >&2
    return 1
  fi

  if ! grep -Eq 'name = "layering_probe_bad"' "${build_bazel}"; then
    echo "expected layering_probe_bad target in BUILD.bazel" >&2
    return 1
  fi

  if ! awk '
    /name = "layering_probe_bad"/ { in_target = 1 }
    in_target && /deps = \[\]/ { found = 1 }
    in_target && /\)/ { exit }
    END { exit(found ? 0 : 1) }
  ' "${build_bazel}"; then
    echo "expected layering_probe_bad to have no deps" >&2
    return 1
  fi

  if ! grep -Eq 'int layering_probe_good_value\(void\);' "${good_h}"; then
    echo "expected good header declaration" >&2
    return 1
  fi

  echo "layering probe: negative fixture encodes an undeclared include"
}

if [[ "${1:-}" == "--self-test" ]]; then
  tmpdir="$(mktemp -d)"
  trap 'rm -rf "${tmpdir}"' EXIT
  cat >"${tmpdir}/good.h" <<'EOF'
#ifndef TOOLCHAIN_TESTS_LAYERING_PROBE_GOOD_H_
#define TOOLCHAIN_TESTS_LAYERING_PROBE_GOOD_H_

int layering_probe_good_value(void);

#endif
EOF
  cat >"${tmpdir}/good.c" <<'EOF'
#include "layering_probe_good.h"

int layering_probe_good_value(void) {
  return 42;
}
EOF
  cat >"${tmpdir}/bad.c" <<'EOF'
#include "layering_probe_good.h"

int layering_probe_bad_value(void) {
  return layering_probe_good_value();
}
EOF
  cat >"${tmpdir}/BUILD.bazel" <<'EOF'
cc_library(
    name = "layering_probe_bad",
    srcs = ["layering_probe_bad.c"],
    deps = [],
)
EOF
  check_fixture_shape "${tmpdir}/good.c" "${tmpdir}/good.h" "${tmpdir}/bad.c" "${tmpdir}/BUILD.bazel"
  echo "Self-test passed."
  exit 0
fi

GOOD_C="$(find_runfile "toolchain/tests/layering_probe_good.c")"
GOOD_H="$(find_runfile "toolchain/tests/layering_probe_good.h")"
BAD_C="$(find_runfile "toolchain/tests/layering_probe_bad.c")"
BUILD_BAZEL="$(find_runfile "toolchain/tests/BUILD.bazel")"

check_fixture_shape "${GOOD_C}" "${GOOD_H}" "${BAD_C}" "${BUILD_BAZEL}"

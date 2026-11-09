#!/usr/bin/env bash
# structural check: the runtime ABI symbols that were historically
# holes must stay defined+exported in the built target libraries.
#
#   libc.so   : setjmp/_setjmp/longjmp/_longjmp (T) + sigsetjmp/siglongjmp (W)
#   libc++.so : real __cxa_demangle (nonzero size) + the full exception ABI
#               (__cxa_throw/begin/end/rethrow/allocate, __gxx_personality_v0,
#               _Unwind_RaiseException/_Unwind_Resume)
#
# Usage: runtime_abi_symbols_test.sh <llvm-nm> <libc.so> <libc++.so>
set -euo pipefail

NM="$1"
LIBC="$2"
LIBCXX="$3"

fail=0

# require_defined <lib> <dynsym-dump> <symbol> <type-regex>
require_defined() {
  local lib="$1" dump="$2" sym="$3" type_re="$4"
  # llvm-nm -D --print-size line: <addr> [<size>] <type> <name>[@@VERSION]
  if ! grep -qE "^[0-9a-f]+ ([0-9a-f]+ )?${type_re} ${sym}(@@?[A-Za-z0-9_.]+)?\$" "$dump"; then
    echo "FAIL: ${sym} not defined/exported (${type_re}) in ${lib}" >&2
    fail=1
  fi
}

libc_dump="$(mktemp)"
libcxx_dump="$(mktemp)"
trap 'rm -f "$libc_dump" "$libcxx_dump"' EXIT
"$NM" -D --print-size "$LIBC" > "$libc_dump"
"$NM" -D --print-size "$LIBCXX" > "$libcxx_dump"

# --- libc.so: setjmp family (libc.ifs: setjmp/longjmp/_setjmp/_longjmp Func,
# sigsetjmp/siglongjmp weak) ---
for sym in setjmp _setjmp longjmp _longjmp; do
  require_defined libc.so "$libc_dump" "$sym" "T"
done
for sym in sigsetjmp siglongjmp; do
  require_defined libc.so "$libc_dump" "$sym" "W"
done

# --- libc++.so: exception ABI + unwinder ---
for sym in __cxa_throw __cxa_begin_catch __cxa_end_catch __cxa_rethrow \
           __cxa_allocate_exception __cxa_free_exception __gxx_personality_v0 \
           _Unwind_RaiseException _Unwind_Resume; do
  require_defined libc++.so "$libcxx_dump" "$sym" "T"
done

# --- libc++.so: __cxa_demangle must be REAL (defined with nonzero size), not
# the old nullptr stub (which was ~10 bytes) — require > 0x100. ---
demangle_line="$(grep -E '^[0-9a-f]+ [0-9a-f]+ T __cxa_demangle(@@?[A-Za-z0-9_.]+)?$' "$libcxx_dump" || true)"
if [[ -z "$demangle_line" ]]; then
  echo "FAIL: __cxa_demangle not defined/exported with a size in libc++.so" >&2
  fail=1
else
  size=$((16#$(echo "$demangle_line" | awk '{print $2}')))
  if (( size < 256 )); then
    echo "FAIL: __cxa_demangle suspiciously small (${size} bytes) — stub regression?" >&2
    fail=1
  fi
fi

if (( fail )); then
  exit 1
fi
echo "PASS: runtime ABI symbols (setjmp family, exception ABI, real __cxa_demangle)"

# Fuchsia API level cfg flags for Rust targets vendored from upstream Fuchsia.
#
# fidl.bzl compiles FIDL at --available fuchsia:30 (to keep fuchsia.io's OnOpen,
# which is @available(removed=NEXT)). Rust cfg predicates must agree with that level:
# levels ≤30 are true; 31, NEXT, HEAD, PLATFORM are false; less_than="HEAD" is true.
#
# Use this constant in rustc_flags on any upstream Fuchsia Rust target that has
# #[cfg(fuchsia_api_level_*)] guards in its source. Proc-macro (host-side) targets
# do not need it.
#
# HEAD implies every lower special level too (numeric levels, then 31, then NEXT,
# then HEAD, then PLATFORM — "at_least" must be monotonic). Real Fuchsia sources
# (e.g. vfs's `#[cfg(any(fuchsia_api_level_at_least = "PLATFORM",
# not(fuchsia_api_level_at_least = "NEXT")))]` gates around DeprecatedOpen/
# NodeInfoDeprecated, which are `@available(removed=NEXT)` in fuchsia.io) rely on
# this: at HEAD, NEXT must also read true or that deprecated-only code compiles
# against a binding (fidl_fuchsia_io_head) where those types no longer exist.
# "31" is included for the same monotonicity reason even though nothing currently
# vendored branches on it.
FUCHSIA_API_LEVEL_HEAD_RUSTC_FLAGS = [
    '--cfg=fuchsia_api_level_at_least="25"',
    '--cfg=fuchsia_api_level_at_least="26"',
    '--cfg=fuchsia_api_level_at_least="27"',
    '--cfg=fuchsia_api_level_at_least="28"',
    '--cfg=fuchsia_api_level_at_least="29"',
    '--cfg=fuchsia_api_level_at_least="30"',
    '--cfg=fuchsia_api_level_at_least="31"',
    '--cfg=fuchsia_api_level_at_least="NEXT"',
    '--cfg=fuchsia_api_level_at_least="HEAD"',
]

# PLATFORM is the level real in-tree Fuchsia platform code (vfs, pseudo_fs, fxfs,
# fxfs/platform) actually compiles at — it's monotonically beyond HEAD (25...30,
# 31, NEXT, HEAD, PLATFORM) and keeps every @available(removed=NEXT) item that HEAD
# alone drops (e.g. fuchsia.io's DeprecatedOpen/NodeInfoDeprecated), because vfs's own
# real gate for those is `any(at_least="PLATFORM", not(at_least="NEXT"))` — an OR, so
# adding at_least("PLATFORM")=true on top of the HEAD set satisfies it directly without
# needing to un-set NEXT. Use this (not the HEAD list) for any upstream platform target
# that both needs HEAD-class additions (MutableNodeAttributes, allocate(), etc.) AND
# still implements/uses NEXT-removed-but-PLATFORM-kept deprecated surface.
FUCHSIA_API_LEVEL_PLATFORM_RUSTC_FLAGS = FUCHSIA_API_LEVEL_HEAD_RUSTC_FLAGS + [
    '--cfg=fuchsia_api_level_at_least="PLATFORM"',
]

FUCHSIA_API_LEVEL_30_RUSTC_FLAGS = [
    '--cfg=fuchsia_api_level_at_least="25"',
    # Level 26 needed for DeprecatedClone availability gates in fuchsia.io
    '--cfg=fuchsia_api_level_at_least="26"',
    # Level 27 needed for DeprecatedOpen availability gates in fuchsia.io
    '--cfg=fuchsia_api_level_at_least="27"',
    # Level 28 needed for vfs: GetAttr→DeprecatedGetAttr rename gate
    '--cfg=fuchsia_api_level_at_least="28"',
    '--cfg=fuchsia_api_level_at_least="29"',
    '--cfg=fuchsia_api_level_at_least="30"',
    '--cfg=fuchsia_api_level_less_than="HEAD"',
]

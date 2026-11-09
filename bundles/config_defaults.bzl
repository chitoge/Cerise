"""Bundle-default structured-config values (config-literal burn-down).

ONE authoritative home for each component's delivered config values, loaded by:
  * //bundles:BUILD.bazel — the cerise_assembly_input_bundle `configs` entries
    (the cerise_product pipeline generates + stages the .cvf from these), and
  * legacy product definitions that stage the same configuration values.

These dicts are DATA: every field must satisfy the `config: {}` schema in the
component's realm manifest (//src/cerise/realms/meta/*.cml) — configc validates
name/type/size at build time, and the runtime checksum handshake (generated
crate vs delivered .cvf, both derived from the same compiled .cm) makes a
schema/values mismatch impossible to ship.
"""

# driver_manager (realm manifest meta/driver_manager_rust_dfv2acpi.cml).
# root_driver: platform-bus is the DFv2-native root of the device topology
# (started by URL, not indexed). Formerly baked into the hand-written
# driver_manager_config stub crate's "dfv2platbus" feature variant.
DRIVER_MANAGER_CONFIG_VALUES = {
    "enable_test_shutdown_delays": False,
    "power_inject_offer": False,
    "power_suspend_enabled": False,
    "root_driver": "fuchsia-boot:///platform_bus#meta/platform-bus.cm",
}

# fshost (realm manifest meta/fshost.cml). Cerise's real storage topology,
# formerly the literal in fshost's main.rs:
#   * fxfs_blob=true, fvm/gpt/blobfs=false: single Fxfs container on a raw
#     whole disk; no FVM, no GPT driver, no standalone blobfs.
#   * no_zxcrypt=true: zxcrypt stays dead — Fxfs-native per-volume crypt.
#   * fxfs_crypt_url is ABSOLUTE, not upstream's package-relative
#     "#meta/crypt_fxfs.cm": Cerise's boot resolver has no package-scoping to
#     resolve a fragment-only URL against fshost's own package (crypt_fxfs is
#     its own bootfs package). Realm.CreateChild accepts any resolvable URL.
#   * provision_fxfs=false: the upstream FxfsProvisioner fallback would panic
#     (no FxfsProvisioner server exists in the vendored tree, only the FIDL +
#     fshost's client call) AND its trigger is gated on a GPT
#     SUPER_AND_USERDATA partition label this no-GPT topology never produces
#     (matcher.rs:252) — on a virgin raw disk fshost's match_device even
#     returns false, so fshost can't self-bootstrap a blank disk. Instead a
#     Cerise-native first-boot fxfs_provisioner component lays down the
#     Fxfs container + "blob" volume on a virgin disk and RELEASES it; fshost
#     then content-sniffs, auto-mounts, and creates its own data/unencrypted
#     volumes via its keybag path. See src/cerise/fxfs_provisioner and
FSHOST_CONFIG_VALUES = {
    "blobfs": False,
    "blobfs_initial_inodes": 0,
    "blob_max_bytes": 0,
    "blobfs_use_deprecated_padded_format": False,
    "data": True,
    "data_filesystem_format": "",
    "data_max_bytes": 0,
    "disable_block_watcher": False,
    "factory": False,
    "format_data_on_corruption": True,
    "check_filesystems": True,
    "fvm": False,
    "ramdisk_image": False,
    "fvm_slice_size": 1048576,
    "fxfs_blob": True,
    "fxfs_crypt_url": "fuchsia-boot:///crypt_fxfs#meta/crypt_fxfs.cm",
    "gpt": False,
    "gpt_all": False,
    "merge_super_and_userdata": False,
    "no_zxcrypt": True,
    "starnix_volume_name": "",
    "inline_crypto": False,
    "disable_automount": False,
    "provision_fxfs": False,
    "watch_deprecated_v1_drivers": False,
}

# driver_index (realm manifest meta/driver_index_acpi.cml). Deliberately does
# NOT carry "boot_drivers": that field is BOARD data — the driver_framework
# bundle's configs entry declares boot_drivers_field = "boot_drivers", and the
# product rule fills it from cerise_board.boot_drivers (the legacy products
# splice //boards/qemu-x64:drivers.bzl's list in directly). Everything else is
# the neutral default the retired stub crate hardcoded: no ephemeral drivers
# (no full package resolver), no eager/disabled lists, no base drivers (no
# package delivery), no load fuzzer, never idle-stop (-1 = INFINITE).
DRIVER_INDEX_CONFIG_VALUES = {
    "enable_ephemeral_drivers": False,
    "bind_eager": [],
    "disabled_drivers": [],
    "base_drivers": [],
    "enable_driver_load_fuzzer": False,
    "delay_fallback_until_base_drivers_indexed": False,
    "driver_load_fuzzer_max_delay_ms": 0,
    "stop_on_idle_timeout_millis": -1,
}

# netstack3 (realm manifest meta/netstack3.cml). Mirrors real upstream's own
# config/test.json5 defaults (num_threads=4, opaque_iids=true,
# sampled_stats_enabled=true; debug_logs/suspend_enabled=false — no power
# framework wired). Formerly a hardcoded literal in netstack3's main.rs
# (the retired adaptation).
NETSTACK3_CONFIG_VALUES = {
    "num_threads": 4,
    "debug_logs": False,
    "opaque_iids": True,
    "suspend_enabled": False,
    "sampled_stats_enabled": True,
}

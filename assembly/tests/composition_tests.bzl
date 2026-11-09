"""Analysis-test rules + fixture declarations for the composition layer.

Test-rule implementations (and analysistest.make) must live in a .bzl file, not
a BUILD file. The fixtures (fake boards/bundles/products) and the test targets
are declared by `declare_composition_tests()`, called once from the BUILD file.

All fake targets are named test_* (never an arch token) and tagged "manual" so
the //... wildcard and `bazel build` never execute their emit_zbi action;
analysistest only analyzes them.
"""

load("@bazel_skylib//lib:unittest.bzl", "analysistest", "asserts")
load("//assembly:defs.bzl", "cerise_architecture_artifact", "cerise_assembly_input_bundle", "cerise_board", "cerise_product", "cerise_root_realm")
load("//assembly:providers.bzl", "ProductBundleInfo")

# ---------------------------------------------------------------------------
# 1. Happy path: board provides the bundle's feature -> ProductBundleInfo.
# ---------------------------------------------------------------------------
def _happy_path_test_impl(ctx):
    env = analysistest.begin(ctx)
    tut = analysistest.target_under_test(env)
    asserts.true(env, ProductBundleInfo in tut, "product must provide ProductBundleInfo")
    info = tut[ProductBundleInfo]
    asserts.equals(env, "test_product_ok", info.product_name)
    asserts.equals(env, "test_board", info.board_name)
    asserts.equals(env, ["test_bundle_ok"], info.bundle_names)
    asserts.true(env, info.zbi.basename.endswith(".zbi"), "product must declare a .zbi output")
    return analysistest.end(env)

_happy_path_test = analysistest.make(_happy_path_test_impl)

# ---------------------------------------------------------------------------
# 2. Missing feature -> analysis failure naming the feature.
# ---------------------------------------------------------------------------
def _missing_feature_test_impl(ctx):
    env = analysistest.begin(ctx)
    asserts.expect_failure(env, "does not provide feature")
    asserts.expect_failure(env, "cerise::absent-feature")
    return analysistest.end(env)

_missing_feature_test = analysistest.make(
    _missing_feature_test_impl,
    expect_failure = True,
)

# ---------------------------------------------------------------------------
# 3. bootfs collision -> analysis failure naming the path.
# ---------------------------------------------------------------------------
def _collision_test_impl(ctx):
    env = analysistest.begin(ctx)
    asserts.expect_failure(env, "bootfs collision")
    asserts.expect_failure(env, "pkg/shared/data")
    return analysistest.end(env)

_collision_test = analysistest.make(
    _collision_test_impl,
    expect_failure = True,
)

# ---------------------------------------------------------------------------
# 4. Component config happy path: bundle defaults + board boot_drivers
#    injection + product override merge; .cvf staged at the derived dest.
# ---------------------------------------------------------------------------
def _config_happy_test_impl(ctx):
    env = analysistest.begin(ctx)
    tut = analysistest.target_under_test(env)
    info = tut[ProductBundleInfo]
    asserts.equals(env, 1, len(info.configs), "exactly one config entry expected")
    cfg = info.configs[0]
    asserts.equals(env, "cfgcomp", cfg.component)
    asserts.equals(env, "pkg/cfgcomp/meta/cfgcomp.cvf", cfg.dest)
    asserts.equals(
        env,
        {
            # "answer" overridden by the product; "greeting" is the bundle default;
            # "boot_drivers" injected from BoardInfo.boot_drivers.
            "answer": 43,
            "greeting": "hello",
            "boot_drivers": ["fuchsia-boot:///testdrv#meta/testdrv.cm"],
        },
        cfg.values,
    )
    return analysistest.end(env)

_config_happy_test = analysistest.make(_config_happy_test_impl)

# ---------------------------------------------------------------------------
# 5. Product override of an unknown config KEY -> analysis failure naming it.
# ---------------------------------------------------------------------------
def _config_unknown_key_test_impl(ctx):
    env = analysistest.begin(ctx)
    asserts.expect_failure(env, "unknown key")
    asserts.expect_failure(env, "no_such_field")
    return analysistest.end(env)

_config_unknown_key_test = analysistest.make(
    _config_unknown_key_test_impl,
    expect_failure = True,
)

# ---------------------------------------------------------------------------
# 6. Product override of an unknown COMPONENT -> analysis failure naming it.
# ---------------------------------------------------------------------------
def _config_unknown_component_test_impl(ctx):
    env = analysistest.begin(ctx)
    asserts.expect_failure(env, "no composed bundle carries a config")
    asserts.expect_failure(env, "no_such_component")
    return analysistest.end(env)

_config_unknown_component_test = analysistest.make(
    _config_unknown_component_test_impl,
    expect_failure = True,
)

# ---------------------------------------------------------------------------
# 7. Two bundles carrying a config for the same component -> analysis failure.
# ---------------------------------------------------------------------------
def _config_dup_component_test_impl(ctx):
    env = analysistest.begin(ctx)
    asserts.expect_failure(env, "config entries in both")
    asserts.expect_failure(env, "cfgcomp")
    return analysistest.end(env)

_config_dup_component_test = analysistest.make(
    _config_dup_component_test_impl,
    expect_failure = True,
)

# ---------------------------------------------------------------------------
# 8-9. File-valued inputs must have exactly one output.
# ---------------------------------------------------------------------------
def _zero_output_test_impl(ctx):
    env = analysistest.begin(ctx)
    asserts.expect_failure(env, "must produce exactly one file, but produces 0")
    return analysistest.end(env)

_zero_output_test = analysistest.make(
    _zero_output_test_impl,
    expect_failure = True,
)

def _multiple_outputs_test_impl(ctx):
    env = analysistest.begin(ctx)
    asserts.expect_failure(env, "must produce exactly one file, but produces 2")
    return analysistest.end(env)

_multiple_outputs_test = analysistest.make(
    _multiple_outputs_test_impl,
    expect_failure = True,
)

# ---------------------------------------------------------------------------
# 10-14. Network software can compose loopback-only; consumers that require an
# external interface need the NIC-neutral network-device capability. Either
# e1000 or virtio-net may truthfully back that capability.
# ---------------------------------------------------------------------------
def _network_capability_test_impl(ctx):
    env = analysistest.begin(ctx)
    tut = analysistest.target_under_test(env)
    info = tut[ProductBundleInfo]
    asserts.true(env, "cerise::network-device" in info.provided_features)
    asserts.true(env, ctx.attr.implementation in info.provided_features)
    asserts.equals(env, ["cerise::network-device"], info.requested_features)
    return analysistest.end(env)

_network_capability_test = analysistest.make(
    _network_capability_test_impl,
    attrs = {"implementation": attr.string(mandatory = True)},
)

def _loopback_netstack_test_impl(ctx):
    env = analysistest.begin(ctx)
    tut = analysistest.target_under_test(env)
    info = tut[ProductBundleInfo]
    asserts.equals(env, "test_board_loopback", info.board_name)
    asserts.equals(env, [], info.requested_features)
    return analysistest.end(env)

_loopback_netstack_test = analysistest.make(_loopback_netstack_test_impl)

def _missing_network_device_test_impl(ctx):
    env = analysistest.begin(ctx)
    asserts.expect_failure(env, "does not provide feature")
    asserts.expect_failure(env, "cerise::network-device")
    return analysistest.end(env)

_missing_network_device_test = analysistest.make(
    _missing_network_device_test_impl,
    expect_failure = True,
)

def _architecture_positive_test_impl(ctx):
    env = analysistest.begin(ctx)
    tut = analysistest.target_under_test(env)
    info = tut[ProductBundleInfo]
    asserts.equals(env, ctx.attr.board_name, info.board_name)
    return analysistest.end(env)

_architecture_positive_test = analysistest.make(
    _architecture_positive_test_impl,
    attrs = {"board_name": attr.string(mandatory = True)},
)

def _architecture_mismatch_test_impl(ctx):
    env = analysistest.begin(ctx)
    asserts.expect_failure(env, "declares architecture")
    asserts.expect_failure(env, ctx.attr.artifact_role)
    return analysistest.end(env)

_architecture_mismatch_test = analysistest.make(
    _architecture_mismatch_test_impl,
    expect_failure = True,
    attrs = {"artifact_role": attr.string(mandatory = True)},
)

# ---------------------------------------------------------------------------
# Board inputs must not reach upward into product composition.
# ---------------------------------------------------------------------------
def _board_product_dependency_test_impl(ctx):
    env = analysistest.begin(ctx)
    asserts.expect_failure(env, "must not depend on product target")
    asserts.expect_failure(env, "//products:x64-smoke")
    return analysistest.end(env)

_board_product_dependency_test = analysistest.make(
    _board_product_dependency_test_impl,
    expect_failure = True,
)

def _bundle_product_dependency_test_impl(ctx):
    env = analysistest.begin(ctx)
    asserts.expect_failure(env, "must not depend on product target")
    asserts.expect_failure(env, "//products:x64-smoke")
    return analysistest.end(env)

_bundle_product_dependency_test = analysistest.make(
    _bundle_product_dependency_test_impl,
    expect_failure = True,
)

def _orphan_executable_test_impl(ctx):
    env = analysistest.begin(ctx)
    asserts.expect_failure(env, "is not reachable")
    asserts.expect_failure(env, "pkg/orphan/bin/orphan")
    return analysistest.end(env)

_orphan_executable_test = analysistest.make(
    _orphan_executable_test_impl,
    expect_failure = True,
)

def _validation_executable_test_impl(ctx):
    env = analysistest.begin(ctx)
    tut = analysistest.target_under_test(env)
    asserts.true(env, ProductBundleInfo in tut, "validation tooling product must compose")
    return analysistest.end(env)

_validation_executable_test = analysistest.make(_validation_executable_test_impl)

def _missing_required_package_test_impl(ctx):
    env = analysistest.begin(ctx)
    asserts.expect_failure(env, "not staged in bootfs")
    asserts.expect_failure(env, "missing_package")
    return analysistest.end(env)

_missing_required_package_test = analysistest.make(
    _missing_required_package_test_impl,
    expect_failure = True,
)

def declare_composition_tests(testfile, testfile2, testschema):
    """Declare fixtures and the analysis tests.

    Args:
      testfile:   label of a tiny file used as the bootfs / physload payload.
      testfile2:  a second, distinct tiny file (kernel_storage stand-in) — the
                  rule's input_zbis is a label_list and rejects duplicate labels.
      testschema: a tiny .cm stand-in for config-schema fixtures (analysis only;
                  the configc action it feeds is never executed).
    """

    # --- shared fixtures ---
    cerise_root_realm(
        name = "test_root_realm",
        cm = testschema,
        required_boot_packages = [],
        reachable_executables = ["bin/test"],
        tags = ["manual"],
    )
    cerise_root_realm(
        name = "test_root_realm_missing_package",
        cm = testschema,
        required_boot_packages = ["missing_package"],
        tags = ["manual"],
    )
    cerise_board(
        name = "test_board",
        provided_features = ["cerise::test-feature"],
        bootfs = {"pkg/board_thing/data": testfile},
        boot_drivers = ["fuchsia-boot:///testdrv#meta/testdrv.cm"],
        tags = ["manual"],
    )
    cerise_assembly_input_bundle(
        name = "test_bundle_ok",
        requires_features = ["cerise::test-feature"],
        cmdline = ["test.flag=1"],
        bootfs = {"pkg/ok/data": testfile},
        tags = ["manual"],
    )
    cerise_assembly_input_bundle(
        name = "test_bundle_needy",
        requires_features = ["cerise::absent-feature"],
        bootfs = {"pkg/needy/data": testfile},
        tags = ["manual"],
    )
    cerise_assembly_input_bundle(
        name = "test_bundle_product_dependency",
        bootfs = {"pkg/invalid/data": "//products:x64-smoke"},
        tags = ["manual"],
    )
    cerise_assembly_input_bundle(
        name = "test_bundle_orphan_executable",
        bootfs = {"pkg/orphan/bin/orphan": testfile},
        tags = ["manual"],
    )
    cerise_assembly_input_bundle(
        name = "test_bundle_validation_executable",
        validation = True,
        bootfs = {"pkg/orphan/bin/orphan": testfile},
        tags = ["manual"],
    )
    # netstack software itself can run with only loopback. A separate consumer
    # declares when a staged network device is necessary for external traffic.
    cerise_assembly_input_bundle(
        name = "test_bundle_netstack",
        tags = ["manual"],
    )
    cerise_assembly_input_bundle(
        name = "test_bundle_network_uplink",
        requires_features = ["cerise::network-device"],
        tags = ["manual"],
    )
    cerise_assembly_input_bundle(
        name = "test_bundle_collide_a",
        bootfs = {"pkg/shared/data": testfile},
        tags = ["manual"],
    )
    cerise_assembly_input_bundle(
        name = "test_bundle_collide_b",
        bootfs = {"pkg/shared/data": testfile},
        tags = ["manual"],
    )
    cerise_assembly_input_bundle(
        name = "test_bundle_config",
        bootfs = {"pkg/cfgcomp/meta/cfgcomp.cm": testschema},
        configs = {
            "cfgcomp": {
                "cm": testschema,
                "values": {"answer": 42, "greeting": "hello"},
                "boot_drivers_field": "boot_drivers",
            },
        },
        tags = ["manual"],
    )
    cerise_assembly_input_bundle(
        name = "test_bundle_config_dup",
        configs = {
            "cfgcomp": {
                "cm": testschema,
                "values": {"answer": 0},
            },
        },
        tags = ["manual"],
    )
    native.filegroup(
        name = "test_no_outputs",
        srcs = [],
        tags = ["manual"],
    )
    cerise_architecture_artifact(
        name = "test_x64_physload",
        src = testfile,
        arch = "x86_64",
        kind = "physload",
        tags = ["manual"],
    )
    cerise_architecture_artifact(
        name = "test_x64_kernel_storage",
        src = testfile2,
        arch = "x86_64",
        kind = "kernel_storage",
        tags = ["manual"],
    )
    cerise_architecture_artifact(
        name = "test_arm64_physload",
        src = testfile,
        arch = "aarch64",
        kind = "physload",
        tags = ["manual"],
    )
    cerise_architecture_artifact(
        name = "test_arm64_kernel_storage",
        src = testfile2,
        arch = "aarch64",
        kind = "kernel_storage",
        tags = ["manual"],
    )
    cerise_architecture_artifact(
        name = "test_x64_userspace",
        src = testfile,
        arch = "x86_64",
        kind = "userspace",
        tags = ["manual"],
    )
    cerise_architecture_artifact(
        name = "test_arm64_userspace",
        src = testfile,
        arch = "aarch64",
        kind = "userspace",
        tags = ["manual"],
    )
    native.filegroup(
        name = "test_multiple_outputs",
        srcs = [testfile, testfile2],
        tags = ["manual"],
    )
    cerise_board(
        name = "test_board_zero_output",
        provided_features = [],
        bootfs = {"pkg/zero/data": ":test_no_outputs"},
        tags = ["manual"],
    )
    cerise_board(
        name = "test_board_multiple_outputs",
        provided_features = [],
        bootfs = {"pkg/multiple/data": ":test_multiple_outputs"},
        tags = ["manual"],
    )
    cerise_board(
        name = "test_board_loopback",
        tags = ["manual"],
    )
    cerise_board(
        name = "test_board_e1000",
        provided_features = ["cerise::network-device", "cerise::e1000"],
        tags = ["manual"],
    )
    cerise_board(
        name = "test_board_virtio_net",
        provided_features = ["cerise::network-device", "cerise::virtio-net"],
        tags = ["manual"],
    )
    cerise_board(
        name = "test_board_aarch64",
        arch = "aarch64",
        platform = "//platforms:arm64-user",
        tags = ["manual"],
    )
    cerise_board(
        name = "test_board_product_dependency",
        bootfs = {"pkg/invalid/data": "//products:x64-smoke"},
        tags = ["manual"],
    )

    # --- targets under test (fake input ZBIs; action never executed) ---
    cerise_product(
        name = "test_product_ok",
        board = ":test_board",
        root_realm = ":test_root_realm",
        bundles = [":test_bundle_ok"],
        physload = ":test_x64_physload",
        kernel_storage = ":test_x64_kernel_storage",
        tags = ["manual"],
    )
    cerise_product(
        name = "test_product_missing_feature",
        board = ":test_board",
        root_realm = ":test_root_realm",
        bundles = [":test_bundle_needy"],
        physload = ":test_x64_physload",
        kernel_storage = ":test_x64_kernel_storage",
        tags = ["manual"],
    )
    cerise_product(
        name = "test_product_collision",
        board = ":test_board",
        root_realm = ":test_root_realm",
        bundles = [":test_bundle_collide_a", ":test_bundle_collide_b"],
        physload = ":test_x64_physload",
        kernel_storage = ":test_x64_kernel_storage",
        tags = ["manual"],
    )
    cerise_product(
        name = "test_product_config_ok",
        board = ":test_board",
        root_realm = ":test_root_realm",
        bundles = [":test_bundle_config"],
        config_overrides = {"cfgcomp": {"answer": 43}},
        physload = ":test_x64_physload",
        kernel_storage = ":test_x64_kernel_storage",
        tags = ["manual"],
    )
    cerise_product(
        name = "test_product_config_unknown_key",
        board = ":test_board",
        root_realm = ":test_root_realm",
        bundles = [":test_bundle_config"],
        config_overrides = {"cfgcomp": {"no_such_field": 1}},
        physload = ":test_x64_physload",
        kernel_storage = ":test_x64_kernel_storage",
        tags = ["manual"],
    )
    cerise_product(
        name = "test_product_config_unknown_component",
        board = ":test_board",
        root_realm = ":test_root_realm",
        bundles = [":test_bundle_config"],
        config_overrides = {"no_such_component": {"answer": 1}},
        physload = ":test_x64_physload",
        kernel_storage = ":test_x64_kernel_storage",
        tags = ["manual"],
    )
    cerise_product(
        name = "test_product_config_dup",
        board = ":test_board",
        root_realm = ":test_root_realm",
        bundles = [":test_bundle_config", ":test_bundle_config_dup"],
        physload = ":test_x64_physload",
        kernel_storage = ":test_x64_kernel_storage",
        tags = ["manual"],
    )
    cerise_product(
        name = "test_product_loopback_netstack",
        board = ":test_board_loopback",
        root_realm = ":test_root_realm",
        bundles = [":test_bundle_netstack"],
        physload = ":test_x64_physload",
        kernel_storage = ":test_x64_kernel_storage",
        tags = ["manual"],
    )
    cerise_product(
        name = "test_product_e1000_uplink",
        board = ":test_board_e1000",
        root_realm = ":test_root_realm",
        bundles = [":test_bundle_netstack", ":test_bundle_network_uplink"],
        physload = ":test_x64_physload",
        kernel_storage = ":test_x64_kernel_storage",
        tags = ["manual"],
    )
    cerise_product(
        name = "test_product_virtio_net_uplink",
        board = ":test_board_virtio_net",
        root_realm = ":test_root_realm",
        bundles = [":test_bundle_netstack", ":test_bundle_network_uplink"],
        physload = ":test_x64_physload",
        kernel_storage = ":test_x64_kernel_storage",
        tags = ["manual"],
    )
    cerise_product(
        name = "test_product_missing_network_device",
        board = ":test_board_loopback",
        root_realm = ":test_root_realm",
        bundles = [":test_bundle_netstack", ":test_bundle_network_uplink"],
        physload = ":test_x64_physload",
        kernel_storage = ":test_x64_kernel_storage",
        tags = ["manual"],
    )
    cerise_product(
        name = "test_product_aarch64",
        board = ":test_board_aarch64",
        root_realm = ":test_root_realm",
        product_bootfs = {"bin/test": ":test_arm64_userspace"},
        physload = ":test_arm64_physload",
        kernel_storage = ":test_arm64_kernel_storage",
        tags = ["manual"],
    )
    cerise_product(
        name = "test_product_kernel_arch_mismatch",
        board = ":test_board",
        root_realm = ":test_root_realm",
        physload = ":test_x64_physload",
        kernel_storage = ":test_arm64_kernel_storage",
        tags = ["manual"],
    )
    cerise_product(
        name = "test_product_phys_arch_mismatch",
        board = ":test_board",
        root_realm = ":test_root_realm",
        physload = ":test_arm64_physload",
        kernel_storage = ":test_x64_kernel_storage",
        tags = ["manual"],
    )
    cerise_product(
        name = "test_product_userspace_arch_mismatch",
        board = ":test_board",
        root_realm = ":test_root_realm",
        product_bootfs = {"bin/test": ":test_arm64_userspace"},
        physload = ":test_x64_physload",
        kernel_storage = ":test_x64_kernel_storage",
        tags = ["manual"],
    )
    cerise_product(
        name = "test_product_orphan_executable",
        board = ":test_board",
        root_realm = ":test_root_realm",
        bundles = [":test_bundle_orphan_executable"],
        physload = ":test_x64_physload",
        kernel_storage = ":test_x64_kernel_storage",
        tags = ["manual"],
    )
    cerise_product(
        name = "test_product_validation_executable",
        board = ":test_board",
        root_realm = ":test_root_realm",
        bundles = [":test_bundle_validation_executable"],
        physload = ":test_x64_physload",
        kernel_storage = ":test_x64_kernel_storage",
        tags = ["manual"],
    )
    cerise_product(
        name = "test_product_missing_required_package",
        board = ":test_board",
        root_realm = ":test_root_realm_missing_package",
        physload = ":test_x64_physload",
        kernel_storage = ":test_x64_kernel_storage",
        tags = ["manual"],
    )

    # --- tests ---
    _happy_path_test(
        name = "happy_path_test",
        target_under_test = ":test_product_ok",
    )
    _missing_feature_test(
        name = "missing_feature_test",
        target_under_test = ":test_product_missing_feature",
    )
    _collision_test(
        name = "collision_test",
        target_under_test = ":test_product_collision",
    )
    _config_happy_test(
        name = "config_happy_test",
        target_under_test = ":test_product_config_ok",
    )
    _config_unknown_key_test(
        name = "config_unknown_key_test",
        target_under_test = ":test_product_config_unknown_key",
    )
    _config_unknown_component_test(
        name = "config_unknown_component_test",
        target_under_test = ":test_product_config_unknown_component",
    )
    _config_dup_component_test(
        name = "config_dup_component_test",
        target_under_test = ":test_product_config_dup",
    )
    _zero_output_test(
        name = "zero_output_test",
        target_under_test = ":test_board_zero_output",
    )
    _multiple_outputs_test(
        name = "multiple_outputs_test",
        target_under_test = ":test_board_multiple_outputs",
    )
    _loopback_netstack_test(
        name = "loopback_netstack_test",
        target_under_test = ":test_product_loopback_netstack",
    )
    _network_capability_test(
        name = "e1000_network_capability_test",
        target_under_test = ":test_product_e1000_uplink",
        implementation = "cerise::e1000",
    )
    _network_capability_test(
        name = "virtio_net_network_capability_test",
        target_under_test = ":test_product_virtio_net_uplink",
        implementation = "cerise::virtio-net",
    )
    _missing_network_device_test(
        name = "missing_network_device_test",
        target_under_test = ":test_product_missing_network_device",
    )
    _architecture_positive_test(
        name = "aarch64_architecture_compatibility_test",
        target_under_test = ":test_product_aarch64",
        board_name = "test_board_aarch64",
    )
    _architecture_mismatch_test(
        name = "kernel_architecture_mismatch_test",
        target_under_test = ":test_product_kernel_arch_mismatch",
        artifact_role = "kernel_storage",
    )
    _architecture_mismatch_test(
        name = "physload_architecture_mismatch_test",
        target_under_test = ":test_product_phys_arch_mismatch",
        artifact_role = "physload",
    )
    _architecture_mismatch_test(
        name = "userspace_architecture_mismatch_test",
        target_under_test = ":test_product_userspace_arch_mismatch",
        artifact_role = "bootfs artifact",
    )
    _board_product_dependency_test(
        name = "board_product_dependency_test",
        target_under_test = ":test_board_product_dependency",
    )
    _bundle_product_dependency_test(
        name = "bundle_product_dependency_test",
        target_under_test = ":test_bundle_product_dependency",
    )
    _orphan_executable_test(
        name = "orphan_executable_test",
        target_under_test = ":test_product_orphan_executable",
    )
    _validation_executable_test(
        name = "validation_executable_test",
        target_under_test = ":test_product_validation_executable",
    )
    _missing_required_package_test(
        name = "missing_required_package_test",
        target_under_test = ":test_product_missing_required_package",
    )

"""zircon_system: product-composition macro for a bootable Zircon system image.

Each call assembles one complete ZBI (physload + kernel storage + optional
extras) and produces a Bazel target whose default output is <name>.zbi.

Args:
  name:           target name; output file is <name>.zbi
  physload:       physboot loader ZBI (default: //build/phys:physload)
  kernel_storage: pre-built kernel+vdso+userboot+base-bootfs ZBI
                  (default: //build/kernel:kernel_storage_zbi)
  cmdline:        extra kernel cmdline strings to append (list of strings)
  extra_bootfs:   dict {bootfs_dest_path: source_label} of extra STORAGE_BOOTFS
                  files to layer on top of the kernel storage's bootfs
  mem_config:     list of "PADDR,SIZE,TYPE" ZBI_TYPE_MEM_CONFIG items
  nvram:          list of "BASE,SIZE" ZBI_TYPE_NVRAM persistent-RAM regions
                  (the ram-crashlog / warm-reboot survival region)
"""

load("//build/images:zbi.bzl", "zbi_image")

_DEFAULT_PHYSLOAD = "//build/phys:physload"
_DEFAULT_KERNEL_STORAGE = "//build/kernel:kernel_storage_zbi"

def zircon_system(
        name,
        physload = _DEFAULT_PHYSLOAD,
        kernel_storage = _DEFAULT_KERNEL_STORAGE,
        cmdline = [],
        extra_bootfs = {},
        mem_config = [],
        nvram = []):
    # Sort by dest path so the ZBI layout is deterministic.
    sorted_dests = sorted(extra_bootfs.keys())
    sorted_srcs = [extra_bootfs[d] for d in sorted_dests]

    zbi_image(
        name = name,
        input_zbis = [physload, kernel_storage],
        cmdline = cmdline,
        extra_bootfs_dests = sorted_dests,
        extra_bootfs_srcs = sorted_srcs,
        mem_config = mem_config,
        nvram = nvram,
    )

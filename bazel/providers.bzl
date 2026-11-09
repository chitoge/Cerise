ZirconKernelInfo = provider(
    doc = "Kernel binary surface for image assembly and QEMU validation.",
    fields = {
        "binary": "Kernel ELF or PE/COFF artifact.",
        "symbols": "Optional debug symbols artifact.",
        "boot_args": "Boot argument list used for image assembly.",
    },
)

ZirconImageInfo = provider(
    doc = "Bootable image surface emitted by Bazel-native packaging rules.",
    fields = {
        "efi_binary": "UEFI-loadable artifact.",
        "disk_image": "Optional raw disk image for QEMU.",
        "manifest": "Deterministic manifest of packaged payloads.",
    },
)

ZirconAbiInfo = provider(
    doc = "Generated syscall ABI surface emitted by Bazel-native codegen.",
    fields = {
        "headers": "Public header depset exposed to downstream consumers.",
        "manifest": "Stable ABI boundary manifest.",
        "vdso_inputs": "Generated inputs required to compile ABI FIDL and build the vDSO.",
        "fidlc_response": "Executable fidlc response file for the staged ABI FIDL sources.",
        "library_manifest": "Structured description of the staged FIDL library ordering.",
        "staged_fidl": "Directory artifact containing deterministic staged ABI FIDL inputs.",
        "staged_headers": "Directory artifact containing deterministic staged public header inputs.",
    },
)

ZirconSdkInfo = provider(
    doc = "Public SDK surface exposed to Bazel userland consumers.",
    fields = {
        "headers": "Public header depset.",
        "libraries": "Linkable library depset.",
        "syscall_manifest": "Generated syscall ABI metadata.",
    },
)

QemuBootTestInfo = provider(
    doc = "Machine-readable QEMU validation outputs for a boot attempt.",
    fields = {
        "serial_log": "Captured serial output artifact.",
        "report": "Structured JSON or text report for CI.",
        "exit_reason": "Normalized exit reason such as success, panic, or timeout.",
    },
)


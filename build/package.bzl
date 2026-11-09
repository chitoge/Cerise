"""cerise_package: build a real Fuchsia package (meta.far) + a runtime ingest manifest.

(packages foundation). A `cerise_package` produces, at build time, from the
vendored fuchsia-pkg library (via the //src/cerise/tools/pkg_builder host tool):

  * <name>.meta.far        — a genuine meta.far (meta/package, meta/contents,
                             meta/fuchsia.abi/abi-revision, the FAR-embedded files such as a
                             compiled component manifest .cm), with real merkle roots.
  * <name>.manifest.json   — the Cerise "ingest manifest": the meta.far merkle (== package
                             hash) and every content blob's runtime staging path + merkle.
                             pkg_probe reads this on-target to write the blobs into the fxfs
                             `blob` volume via fuchsia.fxfs/BlobCreator (content-addressed).
  * <name>.blob_<i>        — a copy of each content blob's raw bytes (single source of truth:
                             the staged bytes and the manifest merkle come from one action).

No checked-in generated artifacts — everything is produced from the vendored libraries.

The blobs are staged into the CONSUMER component's package bootfs (pkg/<consumer>/blobs/...),
so pkg_probe reads them from its own /pkg namespace. Runtime paths are /pkg-relative:
"blobs/meta.far", "blobs/manifest.json", "blobs/blob_0", ... — mirror them in the product's
extra_bootfs under pkg/<consumer>/ (see //products:qemu-x64-pkg).

Sub-targets:
  :<name>            -> PackageInfo + DefaultInfo (all produced files).
  :<name>_meta_far   -> the meta.far File.
  :<name>_manifest   -> the ingest manifest File.
  :<name>_blob_<i>   -> the i-th content blob copy (i in sorted-by-package-path order).
"""

PackageInfo = provider(
    doc = "A built Fuchsia package: meta.far, ingest manifest, and content-blob copies, " +
          "with the /pkg-relative runtime staging paths pkg_probe reads.",
    fields = {
        "package_name": "String package identity.",
        "meta_far": "The meta.far File.",
        "manifest": "The ingest manifest JSON File.",
        "blob_copies": "list[File] of content-blob byte copies (blob_0, blob_1, ...).",
        "staging": "list[struct(runtime_path, file)] — /pkg-relative staging placements " +
                   "for meta.far + manifest + every blob copy.",
    },
)

_MANIFEST_RUNTIME_PATH = "blobs/manifest.json"
_META_FAR_RUNTIME_PATH = "blobs/meta.far"

def _cerise_package_impl(ctx):
    name = ctx.attr.package_name or ctx.label.name

    # far_files: {label: pkg_path} embedded inside meta.far (e.g. the .cm).
    far_files = []
    far_inputs = []
    for lbl, pkg_path in ctx.attr.far_files.items():
        f = lbl.files.to_list()[0]
        far_inputs.append(f)
        far_files.append(struct(pkg_path = pkg_path, source = f.path))

    # blobs: {label: pkg_path} external content blobs. Sort by pkg_path for a deterministic
    # blob_<i> assignment (label dict order is not guaranteed stable).
    blob_items = sorted(ctx.attr.blobs.items(), key = lambda kv: kv[1])
    blob_specs = []
    blob_copies = []
    blob_inputs = []
    staging = []
    for i, (lbl, pkg_path) in enumerate(blob_items):
        src = lbl.files.to_list()[0]
        blob_inputs.append(src)
        out_copy = ctx.actions.declare_file("%s.blob_%d" % (ctx.label.name, i))
        blob_copies.append(out_copy)
        runtime_path = "blobs/blob_%d" % i
        blob_specs.append(struct(
            pkg_path = pkg_path,
            source = src.path,
            out_copy = out_copy.path,
            runtime_path = runtime_path,
        ))
        staging.append(struct(runtime_path = runtime_path, file = out_copy))

    meta_far = ctx.actions.declare_file(ctx.label.name + ".meta.far")
    manifest = ctx.actions.declare_file(ctx.label.name + ".manifest.json")
    gendir = ctx.actions.declare_directory(ctx.label.name + ".gen")

    spec = struct(
        name = name,
        far_files = far_files,
        blobs = blob_specs,
        meta_far_out = meta_far.path,
        manifest_out = manifest.path,
        gendir = gendir.path,
        meta_far_runtime_path = _META_FAR_RUNTIME_PATH,
    )
    spec_file = ctx.actions.declare_file(ctx.label.name + ".spec.json")
    ctx.actions.write(spec_file, json.encode(spec))

    ctx.actions.run(
        executable = ctx.executable._pkg_builder,
        arguments = [spec_file.path],
        inputs = far_inputs + blob_inputs + [spec_file],
        outputs = [meta_far, manifest, gendir] + blob_copies,
        mnemonic = "CERISEPKG",
        progress_message = "Building Fuchsia package %s" % ctx.label,
    )

    staging = [
        struct(runtime_path = _META_FAR_RUNTIME_PATH, file = meta_far),
        struct(runtime_path = _MANIFEST_RUNTIME_PATH, file = manifest),
    ] + staging

    all_files = [meta_far, manifest] + blob_copies

    # Per-file output groups so the macro can expose each produced file as its own addressable
    # filegroup target (products stage them individually into pkg/<consumer>/blobs/).
    output_groups = {
        "meta_far": depset([meta_far]),
        "manifest": depset([manifest]),
    }
    for i, f in enumerate(blob_copies):
        output_groups["blob_%d" % i] = depset([f])

    return [
        PackageInfo(
            package_name = name,
            meta_far = meta_far,
            manifest = manifest,
            blob_copies = blob_copies,
            staging = staging,
        ),
        OutputGroupInfo(**output_groups),
        DefaultInfo(files = depset(all_files)),
    ]

_cerise_package = rule(
    implementation = _cerise_package_impl,
    attrs = {
        "package_name": attr.string(),
        "far_files": attr.label_keyed_string_dict(
            allow_files = True,
            doc = "{file label: package path} embedded INSIDE meta.far (e.g. meta/<n>.cm).",
        ),
        "blobs": attr.label_keyed_string_dict(
            allow_files = True,
            doc = "{file label: package path} external content blobs (binary, libs).",
        ),
        "_pkg_builder": attr.label(
            default = "//src/cerise/tools/pkg_builder:pkg_builder",
            executable = True,
            cfg = "exec",
        ),
    },
)

def cerise_package(name, far_files = {}, blobs = {}, visibility = None, **kwargs):
    """Build a real meta.far + ingest manifest from a set of FAR files and content blobs.

    Args:
      name: target name; package identity (unless package_name is passed via kwargs).
      far_files: {file label: package-path} to embed in meta.far (typically the .cm).
      blobs: {file label: package-path} external content blobs (binary + shared libs).
      visibility: target visibility.
      **kwargs: forwarded (e.g. package_name, tags).
    """
    _cerise_package(
        name = name,
        far_files = far_files,
        blobs = blobs,
        visibility = visibility,
        **kwargs
    )

    # Expose each produced file as its own single-file target (products stage them into
    # pkg/<consumer>/blobs/). Blob indices match the rule's sorted-by-package-path order.
    tags = kwargs.get("tags", [])
    native.filegroup(
        name = name + "_meta_far",
        srcs = [":" + name],
        output_group = "meta_far",
        visibility = visibility,
        tags = tags,
    )
    native.filegroup(
        name = name + "_manifest_json",
        srcs = [":" + name],
        output_group = "manifest",
        visibility = visibility,
        tags = tags,
    )
    for i in range(len(blobs)):
        native.filegroup(
            name = "%s_blob_%d" % (name, i),
            srcs = [":" + name],
            output_group = "blob_%d" % i,
            visibility = visibility,
            tags = tags,
        )

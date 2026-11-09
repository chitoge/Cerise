# Reference

Generated API reference for the Bazel layer, produced from the rule and provider
docstrings with [Stardoc](https://github.com/bazelbuild/stardoc). The
hand-written [API surface](../api-surface.md) is the narrative overview; this
section is the precise, always-in-sync detail.

- **[Providers](providers.md)** — the typed values the composition rules exchange
  (`BoardInfo`, `AIBInfo`, `ProductBundleInfo`).

To regenerate after changing a rule or provider:

```sh
bazel build //docs/reference:providers_md
cp bazel-bin/docs/reference/providers.gen.md docs/reference/providers.md
```

The output is checked in so the published site does not need to run Bazel.

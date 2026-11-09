# cryogen

A content-addressed page store with copy-on-write snapshot generations, plus the
disk readers that feed it.

This is storage substrate, not a virtual machine monitor. It answers one question
— *how do you keep many large, mostly-identical disk and memory images without
paying for each one* — and answers it independently of whatever produced the
images. Components that host and inspect guests build on top of it and are not
part of this directory.

## What it does

- **Stores a nominally huge image for its unique content only.** Pages are 4 KiB
  blobs addressed by the hash of their bytes, so identical pages — including the
  vast zero-filled regions of a sparse disk — are stored once.
- **Makes snapshots cheap.** A snapshot is a copy-on-write generation over the
  same store. Taking one is O(1); it costs only the pages that diverge from its
  parent. The governing invariant is that a generation's overlay holds an entry
  for a page *only if* that page differs from what its parent chain already
  yields — which is what keeps a chain of snapshots from degenerating into a
  chain of full copies.
- **Admits a guest's scratch space as a new generation.** A packed image is
  read-only by construction, so a running guest writes into a scratch overlay
  above it; on a normal shutdown that overlay is discarded, and on a snapshot it
  is *admitted* — the changed pages are content-addressed, deduplicated against
  everything the store already holds, and recorded as a child generation.

  One qualification, because the sentence above is the kind that gets rounded
  up: a `.cryostore` is **self-contained**, and a child's file therefore
  contains a copy of its parent's pack. What is proportional to the change is
  the *content the child adds*, which is what `cryostore snapshot` reports as
  `added`; the file's total size is not. Keeping a parent and a child as two
  files costs both packs. Sharing one pack between files would be a format
  change, and the reason it has not been made is that a reader can open a chain
  today without knowing chains exist.
- **Reads a sparse disk without reading the holes.** The VHDX reader consults the
  block allocation table and synthesizes zeros for unallocated regions instead of
  faulting them in.

## Layout

- `store/` — the content-addressed page-blob store and its copy-on-write snapshot
  generations.
- `hash/` — SHA-256, which supplies the store's content addresses. A page's
  identity is the hash of its bytes, so collision resistance is a correctness
  property here, not merely a lookup detail.
- `vhdx/` — reads a VHDX virtual disk's *logical* contents via its block
  allocation table, synthesizing absent regions rather than reading them. This is
  what lets a pass over a large sparse disk touch only the bytes it actually
  allocated.
- `ingest/` — walks a disk's pages into the store. Also provides `vhdx_stats`, a
  host tool reporting what ingesting a given image would cost.
- `format/` — the `.cryostore` on-disk format: header, index reader and streaming
  packer, including the packer that emits a child generation over an existing
  store.
- `snapshot/` — turns a scratch overlay's dirty sectors into that child
  generation: reassembles partially written pages, deduplicates against the
  parent, and records the pages the guest *erased* explicitly.
- `cli/` — `cryostore`, the host tool: `pack`, `snapshot`, `verify`, `inspect`.

All of them are platform-agnostic (`no_std`, no system calls) except `cli`, and
unit-tested on the build host, so the same code serves a host-side tool and an
on-target consumer.

## The one thing that is easy to get wrong

A page a child generation does not record is **inherited**, not zero. So if the
parent holds content at page P and the guest zeroes P, the child must record P
explicitly — pointing at nothing — or the snapshot silently serves the parent's
stale bytes. Dropping the entry "because the page is zero now" is the natural
implementation and it is a data-corruption bug; the format reserves a tombstone
slot for exactly this, and it costs an index entry and no stored page.

It is not a corner case. A single boot of a Windows guest measured below erased
1,148 pages that the base image had content for.

## Measured

Ingesting a 64 GiB disk image whose file occupies ~561 MiB:

```
total_pages           = 16777216
zero_pages            = 16643003 (99.2%)
unique_nonzero_pages  = 124222
deduped_store         = 485.2 MiB (124223 blobs, incl 1 zero blob)
dedup_ratio           = 135.1x
```

The deduped store comes in *under* the image's own compact on-disk form, because
it also collapses duplicate non-zero pages rather than only empty space.
Reproduce with:

```
bazel run //src/cryogen/ingest:vhdx_stats -- /path/to/disk.vhdx
```

Read that ratio for what it is: a property of images that are mostly zeros and
mostly alike, which is precisely the case this store exists to serve. It is not a
general-purpose compression claim — an image of unique incompressible data would
show close to 1×.

### What a snapshot of a real boot costs

The same 64 GiB image, packed to a 514,400,256-byte `.cryostore`, then booted
under QEMU/KVM with an overlay catching every write, to a shell prompt. The
overlay's own clusters were harvested into a scratch dump and admitted:

```
scratch       158208 sectors (81,002,496 B) over 19776 dirty pages
recorded      10919 entries: 9532 novel, 239 deduplicated, 1148 zeroed;
              8857 unchanged pages cost nothing
added         39,043,072 pack B + 438,272 index B = 39,481,344 B
              (7.68% of the parent store)
```

Three numbers are worth reading twice. **8,857 of the 19,776 pages the guest
wrote were byte-identical to what was already there** — an overlay records
writes, not changes, so nearly half of a boot's dirty pages cost nothing at all.
**239 more already existed elsewhere in the store**, so they cost an index entry
and no bytes. And **1,148 pages were erased**, each of which must be recorded or
the parent's content comes back.

```
bazel run //src/cryogen/cli:cryostore -- pack     disk.vhdx base.cryostore
bazel run //src/cryogen/cli:cryostore -- snapshot base.cryostore boot.cryoscratch child.cryostore
bazel run //src/cryogen/cli:cryostore -- inspect  child.cryostore
```

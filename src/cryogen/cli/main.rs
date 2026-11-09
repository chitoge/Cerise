//! `cryostore` — pack, snapshot, verify and inspect `.cryostore` files.
//!
//! ```text
//! cryostore pack [--sentinel-page N]... <image.img|image.vhdx> <out.cryostore>
//! cryostore snapshot <parent.cryostore> <scratch.cryoscratch> <out.cryostore>
//! cryostore verify <store.cryostore>
//! cryostore inspect <store.cryostore>
//! ```
//!
//! # `snapshot`
//!
//! A packed image is read-only: content-addressed pages have nowhere to put a
//! changed byte, so a running guest writes into a scratch overlay above it that
//! is discarded at shutdown. `snapshot` is the other ending — the scratch is
//! admitted to the store as a **new generation**, which records an entry for
//! each page that differs from the parent and nothing for the rest.
//!
//! The output is an ordinary `.cryostore` holding the whole chain: the parent's
//! generations verbatim, its slots, its pack, and then whatever the child
//! added. So a reader needs to know nothing about snapshots — it opens the file
//! and gets the newest generation — while `--generation`-aware tooling can read
//! any point in the history out of the same file. The cost of that
//! self-containment is that the parent's pack is copied; what a snapshot *adds*
//! is reported separately from what the file weighs, and it is the number that
//! says whether the snapshot was really differential.
//!
//! # The packer streams
//!
//! This is not a style preference. `cryogen_store::PageStore` accumulates every
//! unique page as a `Vec<u8>` in a `BTreeMap`, so its peak memory is the whole
//! deduped store: packing a large Windows image that way exceeded 6.48 GiB of
//! resident content and had to be abandoned, on a 15 GiB machine. The packer
//! here holds only the index — measured at 29 MB peak resident for a 64 GiB
//! image with 124,222 distinct pages — and appends page bytes to a file it does
//! not read back *while packing*.
//!
//! The pack is written to a sibling temporary file and copied into place at the
//! end, because `pack_off` is not known until the index is complete and the
//! index's size is not known until the last page has been offered. That final
//! copy is sequential through a fixed buffer, so it is the one place the pack is
//! read, and it costs bounded memory and transient disk. Reserving a guessed
//! offset and leaving a hole would avoid the copy but would make the file's
//! layout depend on a guess.

use std::fs::File;
use std::io::{BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use cryogen_format::{Disposition, HexId, Packer, StoreIndex, ZERO_SLOT, PAGE_SIZE};
use cryogen_hash::sha256;
use cryogen_snapshot::{admit, BaseImage, ScratchDump, SnapshotStats};
use cryogen_vhdx::{Error as VhdxError, ImageReader, Vhdx};

/// Bytes copied per iteration when concatenating the pack, and read per
/// iteration when scanning a raw image.
const IO_CHUNK: usize = 1 << 20;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let r = match args.first().map(String::as_str) {
        Some("pack") => cmd_pack(&args[1..]),
        Some("snapshot") => cmd_snapshot(&args[1..]),
        Some("verify") => cmd_verify(&args[1..]),
        Some("inspect") => cmd_inspect(&args[1..]),
        _ => {
            eprintln!(
                "usage:\n  \
                 cryostore pack [--sentinel-page N]... <image.img|image.vhdx> <out.cryostore>\n  \
                 cryostore snapshot <parent.cryostore> <scratch.cryoscratch> <out.cryostore>\n  \
                 cryostore verify <store.cryostore>\n  \
                 cryostore inspect <store.cryostore>"
            );
            std::process::exit(2);
        }
    };
    if let Err(e) = r {
        eprintln!("cryostore: {e}");
        std::process::exit(1);
    }
}

// ── Sources ────────────────────────────────────────────────────────────────

/// A logical image being packed: something that yields `PAGE_SIZE` pages in
/// ascending order and knows its own logical size.
///
/// Two implementations, because the two images that matter arrive differently:
/// a test disk is a raw GPT image produced by an image rule, and
/// a Windows guest image is a dynamic VHDX. Both are read *sparsely* — the VHDX
/// reader synthesizes absent blocks rather than reading them, and a raw image
/// on a sparse filesystem costs only its allocated extents.
trait PageStream {
    /// Logical size in bytes.
    fn disk_size(&self) -> u64;
    /// Reads logical page `page` into `out` (exactly `PAGE_SIZE` bytes).
    fn read_page(&mut self, page: u64, out: &mut [u8]) -> Result<(), String>;
    /// How many pages starting at `page` are known to be all-zero **without
    /// reading them**. `0` means "no such promise; read them".
    ///
    /// This is not an optimisation detail, it is what makes packing a real
    /// image finish. A 64 GiB sparse VHDX is 16,777,216 pages, of which 99.2%
    /// are in blocks the image does not store at all; without this the packer
    /// synthesizes and then scans 64 GiB of zeros a page at a time. A first
    /// run over a 64 GiB image was still going after five minutes with the pack
    /// already complete, doing nothing but that.
    fn zero_run_at(&mut self, page: u64) -> u64 {
        let _ = page;
        0
    }
}

struct RawImage {
    file: File,
    len: u64,
}

impl PageStream for RawImage {
    fn disk_size(&self) -> u64 {
        self.len
    }

    fn read_page(&mut self, page: u64, out: &mut [u8]) -> Result<(), String> {
        let off = page * PAGE_SIZE as u64;
        self.file
            .seek(SeekFrom::Start(off))
            .map_err(|e| format!("seeking to {off}: {e}"))?;
        // The last page of an image whose size is not a page multiple is
        // zero-filled to the right, which is what a disk reader would see.
        let want = (self.len - off).min(PAGE_SIZE as u64) as usize;
        out[..want].fill(0);
        out[want..].fill(0);
        self.file
            .read_exact(&mut out[..want])
            .map_err(|e| format!("reading {want} bytes at {off}: {e}"))
    }
}

struct FileImage(File);

impl ImageReader for FileImage {
    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<(), VhdxError> {
        self.0.seek(SeekFrom::Start(offset)).map_err(|_| VhdxError::Io)?;
        self.0.read_exact(buf).map_err(|_| VhdxError::Io)
    }
}

/// A VHDX, read one logical block at a time and sliced into pages. Blocks are
/// cached for exactly as long as the pages inside them are being consumed, so
/// peak memory is one block rather than one image.
struct VhdxImage {
    inner: Vhdx<FileImage>,
    block_size: usize,
    block: Vec<u8>,
    /// Which block `block` currently holds, if any.
    loaded: Option<u64>,
    disk_size: u64,
}

impl VhdxImage {
    fn open(path: &Path) -> Result<Self, String> {
        let f = File::open(path).map_err(|e| format!("open {}: {e}", path.display()))?;
        let inner =
            Vhdx::open(FileImage(f)).map_err(|e| format!("parse {}: {e:?}", path.display()))?;
        let g = inner.geometry();
        let block_size = g.block_size as usize;
        if !block_size.is_multiple_of(PAGE_SIZE) {
            return Err(format!(
                "VHDX block size {block_size} is not a multiple of the {PAGE_SIZE}-byte page"
            ));
        }
        Ok(VhdxImage {
            block_size,
            block: vec![0u8; block_size],
            loaded: None,
            disk_size: g.virtual_disk_size,
            inner,
        })
    }
}

impl PageStream for VhdxImage {
    fn disk_size(&self) -> u64 {
        self.disk_size
    }

    fn zero_run_at(&mut self, page: u64) -> u64 {
        let pages_per_block = (self.block_size / PAGE_SIZE) as u64;
        let b = page / pages_per_block;
        if self.inner.block_state(b).has_stored_data() {
            return 0;
        }
        // The reader synthesizes zeros for a block the image does not store,
        // so every page of it is zero and none of them need to be materialised.
        pages_per_block - (page % pages_per_block)
    }

    fn read_page(&mut self, page: u64, out: &mut [u8]) -> Result<(), String> {
        let pages_per_block = (self.block_size / PAGE_SIZE) as u64;
        let b = page / pages_per_block;
        if self.loaded != Some(b) {
            let mut buf = std::mem::take(&mut self.block);
            let r = self.inner.read_block(b, &mut buf);
            self.block = buf;
            r.map_err(|e| format!("reading VHDX block {b}: {e:?}"))?;
            self.loaded = Some(b);
        }
        let p = (page % pages_per_block) as usize;
        out.copy_from_slice(&self.block[p * PAGE_SIZE..(p + 1) * PAGE_SIZE]);
        Ok(())
    }
}

fn open_image(path: &Path) -> Result<Box<dyn PageStream>, String> {
    // Sniff the VHDX signature rather than trust the extension: the file that
    // gets packed is whatever a build rule handed us, and a mislabelled input
    // should be a refusal, not a store full of nonsense.
    let mut f = File::open(path).map_err(|e| format!("open {}: {e}", path.display()))?;
    let mut sig = [0u8; 8];
    let n = f.read(&mut sig).map_err(|e| format!("reading {}: {e}", path.display()))?;
    if n == 8 && &sig == b"vhdxfile" {
        return Ok(Box::new(VhdxImage::open(path)?));
    }
    let len = f
        .metadata()
        .map_err(|e| format!("stat {}: {e}", path.display()))?
        .len();
    if len == 0 {
        return Err(format!("{} is empty", path.display()));
    }
    Ok(Box::new(RawImage { file: f, len }))
}

// ── pack ───────────────────────────────────────────────────────────────────

fn cmd_pack(args: &[String]) -> Result<(), String> {
    let mut sentinels: Vec<u64> = Vec::new();
    let mut positional: Vec<&String> = Vec::new();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--sentinel-page" => {
                let v = args
                    .get(i + 1)
                    .ok_or("--sentinel-page needs a page index")?
                    .parse::<u64>()
                    .map_err(|e| format!("--sentinel-page: {e}"))?;
                sentinels.push(v);
                i += 2;
            }
            other if other.starts_with("--") => return Err(format!("unknown flag {other}")),
            _ => {
                positional.push(&args[i]);
                i += 1;
            }
        }
    }
    if positional.len() != 2 {
        return Err("pack takes an input image and an output path".into());
    }
    let in_path = PathBuf::from(positional[0]);
    let out_path = PathBuf::from(positional[1]);
    sentinels.sort_unstable();
    sentinels.dedup();

    let mut image = open_image(&in_path)?;
    let disk_size = image.disk_size();
    let disk_pages = disk_size.div_ceil(PAGE_SIZE as u64);

    // The pack goes to a sibling temp file; see the module docs for why.
    let tmp_path = out_path.with_extension("packtmp");
    let mut tmp = BufWriter::new(
        File::create(&tmp_path).map_err(|e| format!("create {}: {e}", tmp_path.display()))?,
    );

    let mut packer = Packer::new(disk_size);
    let mut page = vec![0u8; PAGE_SIZE];
    let sentinel = cryogen_format::sentinel_page();
    let mut sentinel_iter = sentinels.iter().peekable();
    let mut placed = 0usize;

    // Pages are offered in ascending order — the packer requires it, and it is
    // what lets the overlay section be written sorted without a sort pass.
    let last_page = sentinels.iter().copied().max().map_or(disk_pages, |m| disk_pages.max(m + 1));
    let mut idx = 0u64;
    while idx < last_page {
        let bytes: &[u8] = if sentinel_iter.peek() == Some(&&idx) {
            sentinel_iter.next();
            if idx < disk_pages {
                // Placing a sentinel over real content would corrupt the image
                // silently, and the point of the sentinel is that reading it is
                // a *fault*. Refuse rather than overwrite.
                image.read_page(idx, &mut page)?;
                if page.iter().any(|&b| b != 0) {
                    return Err(format!(
                        "--sentinel-page {idx} lands on non-zero image content (byte offset {}); \
                         pick a page inside an unallocated region",
                        idx * PAGE_SIZE as u64
                    ));
                }
            }
            placed += 1;
            &sentinel
        } else if idx < disk_pages {
            // A run the image can promise is zero costs no read, no scan and no
            // index entry — the store's address space is zero-filled, so a zero
            // page is exactly what "not recorded" already means. The run is
            // clamped so it can never step over a sentinel placement.
            let run = image.zero_run_at(idx);
            if run > 0 {
                let stop = sentinel_iter.peek().map_or(u64::MAX, |&&s| s);
                let skip = run.min(disk_pages - idx).min(stop.saturating_sub(idx));
                if skip > 0 {
                    packer.note_zero_pages(idx, skip);
                    idx += skip;
                    continue;
                }
            }
            image.read_page(idx, &mut page)?;
            &page
        } else {
            idx += 1;
            continue;
        };
        if let Disposition::Novel(_) = packer.add_page(idx, bytes).map_err(|e| e.to_string())? {
            tmp.write_all(bytes)
                .map_err(|e| format!("appending to {}: {e}", tmp_path.display()))?;
        }
        idx += 1;
    }
    if placed != sentinels.len() {
        return Err("internal: not every requested sentinel was placed".into());
    }
    tmp.flush().map_err(|e| format!("flushing {}: {e}", tmp_path.display()))?;
    drop(tmp);

    let index = packer.finish();
    let mut out = BufWriter::new(
        File::create(&out_path).map_err(|e| format!("create {}: {e}", out_path.display()))?,
    );
    out.write_all(&index)
        .map_err(|e| format!("writing the index to {}: {e}", out_path.display()))?;
    let mut tmp_in =
        File::open(&tmp_path).map_err(|e| format!("reopen {}: {e}", tmp_path.display()))?;
    let mut buf = vec![0u8; IO_CHUNK];
    loop {
        let n = tmp_in
            .read(&mut buf)
            .map_err(|e| format!("reading {}: {e}", tmp_path.display()))?;
        if n == 0 {
            break;
        }
        out.write_all(&buf[..n])
            .map_err(|e| format!("writing the pack to {}: {e}", out_path.display()))?;
    }
    out.flush().map_err(|e| format!("flushing {}: {e}", out_path.display()))?;
    drop(out);
    drop(tmp_in);
    let _ = std::fs::remove_file(&tmp_path);

    let parsed = StoreIndex::parse(&index).map_err(|e| format!("re-reading the index we wrote: {e}"))?;
    let h = parsed.header();
    let (total, zero) = packer.page_counts();
    println!("packed {} -> {}", in_path.display(), out_path.display());
    println!("  root_hash     {}", HexId(&h.root_hash));
    println!("  disk_size     {} B ({} pages)", h.disk_size, disk_pages);
    println!("  pages offered {total} ({zero} zero, {:.2}%)", zero as f64 * 100.0 / total.max(1) as f64);
    println!("  blob_count    {}", h.blob_count);
    println!("  index_entries {}", parsed.index_entries());
    println!(
        "  index         {} B ({:.2}% of the store)",
        h.index_len(),
        h.index_len() as f64 * 100.0 / h.total_len().max(1) as f64
    );
    println!("  pack          {} B at offset {}", h.pack_len(), h.pack_off);
    println!("  total         {} B", h.total_len());
    match parsed.sentinel_slots().as_slice() {
        [] => println!("  sentinel      none"),
        slots => println!("  sentinel      slot(s) {slots:?}, placed at page(s) {sentinels:?}"),
    }
    Ok(())
}

// ── snapshot ───────────────────────────────────────────────────────────────

/// Opens a store and parses its index prefix — everything below `pack_off`,
/// which is all a description or a resolution needs. The pack is left on disk.
fn open_store(path: &str) -> Result<(File, StoreIndex), String> {
    let mut f = File::open(path).map_err(|e| format!("open {path}: {e}"))?;
    let len = f.metadata().map_err(|e| format!("stat {path}: {e}"))?.len();
    let mut head = [0u8; cryogen_format::HEADER_LEN];
    f.read_exact(&mut head).map_err(|e| format!("read {path}: {e}"))?;
    let index_len = u64::from_le_bytes(head[72..80].try_into().unwrap());
    if index_len < cryogen_format::HEADER_LEN as u64 || index_len > len {
        return Err(format!(
            "{path} claims a {index_len}-byte index inside a {len}-byte file"
        ));
    }
    let mut buf = vec![0u8; index_len as usize];
    f.seek(SeekFrom::Start(0)).map_err(|e| format!("seek {path}: {e}"))?;
    f.read_exact(&mut buf).map_err(|e| format!("read {path}: {e}"))?;
    let index = StoreIndex::parse(&buf).map_err(|e| format!("{path}: {e}"))?;
    if len != index.header().total_len() {
        return Err(format!(
            "{path} is {len} bytes; the header describes {} bytes",
            index.header().total_len()
        ));
    }
    Ok((f, index))
}

/// The parent generation, as the pages a scratch overlay sat on.
///
/// Every page it hands back is verified against the `BlobId` the index names,
/// for the same reason a consumer verifies: a snapshot assembled from corrupt
/// parent bytes would be content-addressed, self-consistent and wrong, and the
/// hash of the corruption would become part of the store's identity.
struct StoreBase {
    file: File,
    index: StoreIndex,
    generation: u32,
}

impl BaseImage for StoreBase {
    type Error = String;

    fn read_page(&mut self, page: u64, out: &mut [u8]) -> Result<(), String> {
        let Some(slot) = self.index.resolve(self.generation, page) else {
            // Unrecorded, or erased by a generation on the chain: zero, and no
            // read at all.
            out.fill(0);
            return Ok(());
        };
        let off = self.index.header().slot_offset(slot);
        self.file
            .seek(SeekFrom::Start(off))
            .map_err(|e| format!("seeking to slot {slot} at {off}: {e}"))?;
        self.file
            .read_exact(out)
            .map_err(|e| format!("reading slot {slot} at {off}: {e}"))?;
        let want = self.index.slot_id(slot).expect("resolve returned a valid slot");
        let got = sha256(out);
        if &got != want {
            return Err(format!(
                "parent slot {slot}: index says {}, content hashes to {}",
                HexId(want),
                HexId(&got)
            ));
        }
        Ok(())
    }
}

fn cmd_snapshot(args: &[String]) -> Result<(), String> {
    if args.len() != 3 {
        return Err("snapshot takes a parent store, a scratch dump and an output path".into());
    }
    let parent_path = &args[0];
    let scratch_path = &args[1];
    let out_path = PathBuf::from(&args[2]);
    // The output is created by truncation, so writing it over an input would
    // destroy the thing being read halfway through.
    if out_path == Path::new(parent_path) || out_path == Path::new(scratch_path) {
        return Err("the output would overwrite an input".into());
    }

    let (parent_file, parent_index) = open_store(parent_path)?;
    let ph = *parent_index.header();
    // Kept open across the whole run rather than reopened by path at the end:
    // the child's slot *n* must be the parent's slot *n*, and a parent replaced
    // between admission and the copy would silently mix two stores into one.
    let mut parent_pack = parent_file
        .try_clone()
        .map_err(|e| format!("duplicating the handle on {parent_path}: {e}"))?;

    // The scratch is read whole. It is the *changed* sectors and nothing else —
    // it came out of an overlay that was resident in the first place — so its
    // size is the change set, not the disk.
    let scratch_bytes = std::fs::read(scratch_path)
        .map_err(|e| format!("read {scratch_path}: {e}"))?;
    let dump = ScratchDump::parse(&scratch_bytes)
        .map_err(|e| format!("{scratch_path}: {e}"))?;

    let mut packer = Packer::new_child(&parent_index);
    let mut base = StoreBase {
        file: parent_file,
        index: parent_index.clone(),
        generation: parent_index.tip(),
    };

    // Novel pages go to a sibling temp file, as in `pack`: the index's size —
    // and so `pack_off` — is not known until the last page has been offered.
    // The name is derived from the output, so it can collide with an input or
    // with the output itself if someone named a store `*.packtmp` — and the
    // collision is destructive in both directions (it is created by truncation
    // and removed at the end). Refused rather than defended against.
    let tmp_path = out_path.with_extension("packtmp");
    if tmp_path == out_path
        || tmp_path == Path::new(parent_path)
        || tmp_path == Path::new(scratch_path)
    {
        return Err(format!(
            "the temporary file {} would collide with an input or the output; \
             pick an output name that does not end in .packtmp",
            tmp_path.display()
        ));
    }
    let mut tmp = BufWriter::new(
        File::create(&tmp_path).map_err(|e| format!("create {}: {e}", tmp_path.display()))?,
    );
    let stats: SnapshotStats = admit(
        &mut packer,
        &dump,
        &mut base,
        |bytes| {
            tmp.write_all(bytes)
                .map_err(|e| format!("appending to {}: {e}", tmp_path.display()))
        },
        ph.disk_size,
    )
    .map_err(|e| format!("admitting {scratch_path}: {e}"))?;
    tmp.flush().map_err(|e| format!("flushing {}: {e}", tmp_path.display()))?;
    drop(tmp);

    // Checked before anything is written: the pack the admission described and
    // the bytes it actually produced must agree, or the store would name slots
    // whose content is not there.
    let novel_len = std::fs::metadata(&tmp_path)
        .map_err(|e| format!("stat {}: {e}", tmp_path.display()))?
        .len();
    if novel_len != stats.new_pack_bytes {
        return Err(format!(
            "internal: appended {novel_len} pack bytes for {} novel slots",
            stats.new_slots
        ));
    }

    let index = packer.finish();
    let mut out = BufWriter::new(
        File::create(&out_path).map_err(|e| format!("create {}: {e}", out_path.display()))?,
    );
    out.write_all(&index)
        .map_err(|e| format!("writing the index to {}: {e}", out_path.display()))?;
    // The parent's pack, verbatim and streamed, through the handle opened at
    // the start.
    parent_pack
        .seek(SeekFrom::Start(ph.pack_off))
        .map_err(|e| format!("seek {parent_path}: {e}"))?;
    copy_exact(&mut parent_pack, &mut out, ph.pack_len(), parent_path, &out_path)?;
    let mut novel =
        File::open(&tmp_path).map_err(|e| format!("reopen {}: {e}", tmp_path.display()))?;
    copy_exact(
        &mut novel,
        &mut out,
        novel_len,
        &tmp_path.display().to_string(),
        &out_path,
    )?;
    out.flush().map_err(|e| format!("flushing {}: {e}", out_path.display()))?;
    drop(out);
    drop(novel);
    let _ = std::fs::remove_file(&tmp_path);

    let parsed = StoreIndex::parse(&index)
        .map_err(|e| format!("re-reading the index we wrote: {e}"))?;
    let h = parsed.header();
    let grew = h.total_len() - ph.total_len();
    println!("snapshot {parent_path} + {scratch_path} -> {}", out_path.display());
    println!("  parent        {} (generation {})", HexId(&ph.root_hash), parent_index.tip());
    println!("  root_hash     {} (generation {})", HexId(&h.root_hash), parsed.tip());
    println!("  generations   {}", h.gen_count);
    println!(
        "  scratch       {} sectors ({} B) over {} pages",
        stats.dirty_sectors,
        scratch_bytes.len(),
        stats.dirty_pages
    );
    println!(
        "  base reads    {} pages (partially written pages only)",
        stats.base_pages_read
    );
    println!(
        "  recorded      {} entries: {} novel, {} deduplicated, {} zeroed; {} unchanged pages cost nothing",
        stats.entries_recorded,
        stats.novel_pages,
        stats.deduplicated_pages,
        stats.zero_overrides,
        stats.unchanged_pages
    );
    if stats.bulk_erased_pages > 0 {
        println!("  bulk erased   {} pages above the scratch's zero boundary", stats.bulk_erased_pages);
    }
    println!(
        "  added         {} pack B + {} index B = {} B ({:.4}% of the parent's {} B)",
        stats.new_pack_bytes,
        grew - stats.new_pack_bytes,
        grew,
        grew as f64 * 100.0 / ph.total_len().max(1) as f64,
        ph.total_len()
    );
    println!("  total         {} B", h.total_len());
    Ok(())
}

/// Copies exactly `len` bytes, so a short parent pack is an error here rather
/// than a store whose slots are silently shifted.
fn copy_exact(
    from: &mut File,
    to: &mut BufWriter<File>,
    len: u64,
    from_name: &str,
    to_path: &Path,
) -> Result<(), String> {
    let mut buf = vec![0u8; IO_CHUNK];
    let mut left = len;
    while left > 0 {
        let want = left.min(IO_CHUNK as u64) as usize;
        from.read_exact(&mut buf[..want])
            .map_err(|e| format!("reading {want} bytes of {from_name}: {e}"))?;
        to.write_all(&buf[..want])
            .map_err(|e| format!("writing to {}: {e}", to_path.display()))?;
        left -= want as u64;
    }
    Ok(())
}

// ── verify ─────────────────────────────────────────────────────────────────

fn cmd_verify(args: &[String]) -> Result<(), String> {
    let path = args.first().ok_or("verify takes a store path")?;
    // The index is read whole; the pack is streamed a page at a time. Reading
    // the file into memory would defeat the point of the format: a large
    // image's pack runs to several GiB and this tool has to be able to check it.
    //
    // `StoreIndex::parse` checks `root_hash` over the index. What remains is
    // the chain, and the pack — and the pack's check is per slot: the index
    // names each page's SHA-256, so a mismatch identifies the slot rather than
    // merely condemning the file.
    let (mut f, index) = open_store(path)?;
    let h = index.header();
    verify_chain(&index)?;
    f.seek(SeekFrom::Start(h.pack_off))
        .map_err(|e| format!("seek {path}: {e}"))?;
    let mut page = vec![0u8; PAGE_SIZE];
    let mut bad = 0usize;
    for slot in 0..h.blob_count {
        f.read_exact(&mut page)
            .map_err(|e| format!("reading slot {slot} of {path}: {e}"))?;
        let got = sha256(&page);
        let want = index.slot_id(slot).unwrap();
        if &got != want {
            bad += 1;
            eprintln!(
                "slot {slot} (offset {}): index says {}, content hashes to {}",
                h.slot_offset(slot),
                HexId(want),
                HexId(&got)
            );
        }
    }
    if bad != 0 {
        return Err(format!("{bad} of {} slots do not match their hash", h.blob_count));
    }
    println!(
        "{path}: OK — root_hash {}, {} slots verified, {} generations, chain to the tip is {:?}",
        HexId(&h.root_hash),
        h.blob_count,
        h.gen_count,
        index.chain(index.tip())
    );
    Ok(())
}

/// Checks the generation graph, which `StoreIndex::parse` bounds but does not
/// interpret: the chain terminates, every entry a generation records is what a
/// reader resolves at that generation, and every non-tombstone entry names a
/// slot the index has an id for.
///
/// **What this cannot do**, stated because the opposite is easy to assume: it
/// cannot tell whether a generation is *missing* an entry. An absent entry is
/// indistinguishable from deliberate inheritance — that is what inheritance
/// *is* — so a child that dropped the tombstone for a page its guest erased
/// produces a store that passes every check here. Catching that needs the
/// scratch the generation was built from, or an independent image to compare
/// against; it is a property of the admission, and it is enforced there and
/// tested there.
fn verify_chain(index: &StoreIndex) -> Result<(), String> {
    for (g, gen) in index.generations().iter().enumerate() {
        let g = g as u32;
        // A cycle or a forward reference would make resolution non-terminating;
        // parse rejects it, so reaching the root here is a re-check, not a
        // guess.
        let chain = index.chain(g);
        if chain.last() != Some(&0) && !chain.is_empty() {
            let root = *chain.last().unwrap();
            if index.generation(root).and_then(|n| n.parent).is_some() {
                return Err(format!("generation {g}'s chain does not terminate"));
            }
        }
        for &(page, slot) in &gen.entries {
            let want = (slot != ZERO_SLOT).then_some(slot);
            let got = index.resolve(g, page);
            if got != want {
                return Err(format!(
                    "generation {g} records page {page} as {slot}, but resolves it to {got:?}"
                ));
            }
            if slot != ZERO_SLOT && index.slot_id(slot).is_none() {
                return Err(format!("generation {g} names slot {slot}, which has no id"));
            }
        }
    }
    Ok(())
}

// ── inspect ────────────────────────────────────────────────────────────────

fn cmd_inspect(args: &[String]) -> Result<(), String> {
    let path = args.first().ok_or("inspect takes a store path")?;
    // Only the index is read: everything a description needs lives below
    // `pack_off`, which is the property that makes the format worth having.
    let (_, index) = open_store(path)?;
    let h = index.header();
    println!("{path}");
    println!("  root_hash     {}", HexId(&h.root_hash));
    println!("  disk_size     {} B", h.disk_size);
    println!("  generations   {} (tip {})", h.gen_count, index.tip());
    println!("  blob_count    {}", h.blob_count);
    println!("  index_entries {}", index.index_entries());
    println!("  index         {} B", h.index_len());
    println!("  pack          {} B at offset {}", h.pack_len(), h.pack_off);
    println!("  total         {} B", h.total_len());
    println!("  sentinel      {:?}", index.sentinel_slots());

    // The chain, with each generation's cost attributed to it. `first-ref
    // slots` is the number that says whether a generation was really
    // differential: a child that merely restated its parent shows entries and
    // no first references, and a child that re-packed the image shows as many
    // as it has entries.
    //
    // It is *first reference in generation order*, not "the slots this
    // generation appended" — the format records no per-generation slot
    // watermark, so for a store this tool did not write the two can differ.
    // For one it did write they coincide, because a child only ever appends.
    println!("  chain (nearest ancestor first from the tip: {:?})", index.chain(index.tip()));
    println!("    gen  parent  entries  zeroed  first-ref slots  pack B");
    let mut seen = vec![false; h.blob_count as usize];
    for (g, gen) in index.generations().iter().enumerate() {
        let mut novel = 0u32;
        for &(_, slot) in &gen.entries {
            if slot != ZERO_SLOT && !seen[slot as usize] {
                seen[slot as usize] = true;
                novel += 1;
            }
        }
        println!(
            "    {:>3}  {:>6}  {:>7}  {:>6}  {:>15}  {:>10}",
            g,
            gen.parent.map_or("-".to_string(), |p| p.to_string()),
            gen.entry_count(),
            gen.zero_entries(),
            novel,
            novel as u64 * PAGE_SIZE as u64
        );
    }
    Ok(())
}

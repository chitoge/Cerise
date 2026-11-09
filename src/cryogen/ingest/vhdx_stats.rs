//! Reports what ingesting a VHDX costs the content-addressed page store.
//!
//! This is the measurement behind the claim that a virtual disk can be kept
//! whole without keeping its virtual size. It ingests the image through the real
//! `PageStore` — not a stand-in — so the numbers it prints are the store's
//! actual cost, in both content and index. It then reads the disk back out of
//! the store and compares against the image, so the figures describe something
//! that demonstrably holds the data rather than merely counting it.
//!
//!   bazel run //src/cryogen/ingest:vhdx_stats -- /path/to/disk.vhdx

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};

use cryogen_hash::sha256;
use cryogen_ingest::ingest_vhdx;
use cryogen_store::{PageStore, PAGE_SIZE};
use cryogen_vhdx::{Error, ImageReader, Vhdx};

/// A VHDX file opened for reading.
struct FileImage(File);

impl ImageReader for FileImage {
    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<(), Error> {
        self.0.seek(SeekFrom::Start(offset)).map_err(|_| Error::Io)?;
        self.0.read_exact(buf).map_err(|_| Error::Io)
    }
}

fn open(path: &str) -> Vhdx<FileImage> {
    let file = File::open(path).unwrap_or_else(|e| {
        eprintln!("open {}: {}", path, e);
        std::process::exit(1);
    });
    Vhdx::open(FileImage(file)).unwrap_or_else(|e| {
        eprintln!("parse {}: {:?}", path, e);
        std::process::exit(1);
    })
}

/// Peak resident set size in bytes, from the kernel's own accounting.
fn peak_rss_bytes() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("VmHWM:") {
            let kb: u64 = rest.trim().trim_end_matches(" kB").trim().parse().ok()?;
            return Some(kb * 1024);
        }
    }
    None
}

fn main() {
    let path = match std::env::args().nth(1) {
        Some(p) => p,
        None => {
            eprintln!("usage: vhdx_stats <image.vhdx>");
            std::process::exit(2);
        }
    };

    let mut image = open(&path);
    let geometry = image.geometry();

    // Block census first: reading the allocation table needs no I/O, so this is
    // free and says how much of the virtual disk is actually backed.
    let stored_blocks = (0..geometry.data_blocks)
        .filter(|&b| image.block_state(b).has_stored_data())
        .count() as u64;

    // Ingest through the real store.
    let zero_page = [0u8; PAGE_SIZE];
    let zero_id = sha256(&zero_page);
    let mut store = PageStore::new(zero_id);
    let gen = store.base();
    let stats = ingest_vhdx(&mut image, &mut store, gen).unwrap_or_else(|e| {
        eprintln!("ingest {}: {:?}", path, e);
        std::process::exit(1);
    });

    let mib = (1u64 << 20) as f64;
    let gib = (1u64 << 30) as f64;

    println!("image                 = {}", path);
    println!(
        "virtual_size          = {:.2} GiB ({} bytes)",
        geometry.virtual_disk_size as f64 / gib,
        geometry.virtual_disk_size
    );
    println!("block_size            = {} KiB", geometry.block_size / 1024);
    println!("logical_sector_size   = {}", geometry.logical_sector_size);
    println!(
        "blocks_with_data      = {} of {}",
        stored_blocks, geometry.data_blocks
    );
    println!("total_pages           = {}", stats.total_pages);
    println!(
        "zero_pages            = {} ({:.1}%)",
        stats.zero_pages,
        stats.zero_pages as f64 * 100.0 / stats.total_pages.max(1) as f64
    );
    println!("unique_nonzero_pages  = {}", stats.unique_nonzero_pages);
    println!(
        "deduped_store         = {:.1} MiB ({} blobs, incl 1 zero blob)",
        stats.deduped_bytes() as f64 / mib,
        stats.blobs
    );
    println!(
        "dedup_ratio           = {:.1}x",
        stats.dedup_ratio().unwrap_or(0.0)
    );

    // The index side: what it costs to know *where* each page lives. Empty space
    // is unrecorded, so this counts the disk's allocated pages, not its virtual
    // size — the difference between an index of thousands and one of millions.
    println!("index_entries         = {}", stats.index_entries);
    println!(
        "index_vs_total_pages  = {:.4}% ({} of {})",
        stats.index_entries as f64 * 100.0 / stats.total_pages.max(1) as f64,
        stats.index_entries,
        stats.total_pages
    );
    println!("zero_page_id          = {}", hex(&zero_id));

    // Read the disk back out of the store and compare with the image. Every
    // block that carries data is checked, plus a sample of absent ones, so the
    // numbers above describe a store that can actually reproduce the disk.
    let mut verified_blocks: u64 = 0;
    let mut verified_pages: u64 = 0;
    let mut block = vec![0u8; geometry.block_size as usize];
    let pages_per_block = geometry.block_size as usize / PAGE_SIZE;
    let absent_sample_stride = (geometry.data_blocks / 64).max(1);

    for b in 0..geometry.data_blocks {
        let has_data = image.block_state(b).has_stored_data();
        if !has_data && b % absent_sample_stride != 0 {
            continue;
        }
        image.read_block(b, &mut block).unwrap_or_else(|e| {
            eprintln!("verify: read block {}: {:?}", b, e);
            std::process::exit(1);
        });
        for p in 0..pages_per_block {
            let expected = &block[p * PAGE_SIZE..(p + 1) * PAGE_SIZE];
            let index = b * pages_per_block as u64 + p as u64;
            let id = store.read_page(gen, index);
            let got = store.blob(&id).unwrap_or_else(|| {
                eprintln!("verify: page {} resolves to a blob the store lacks", index);
                std::process::exit(1);
            });
            if got != expected {
                eprintln!("verify: page {} differs from the image", index);
                std::process::exit(1);
            }
            verified_pages += 1;
        }
        verified_blocks += 1;
    }
    println!(
        "verified              = {} pages across {} blocks (all with data, plus absent sample)",
        verified_pages, verified_blocks
    );

    if let Some(rss) = peak_rss_bytes() {
        println!("peak_rss              = {:.1} MiB", rss as f64 / mib);
    }
}

fn hex(d: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for b in d {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

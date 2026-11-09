//! Writes the GPT the provisioner would write onto a sparse image file, so the
//! table can be checked with a tool that has never heard of this codebase.
//!
//! A partition table that only our own parser agrees with is not a GPT. The
//! host unit tests in `layout.rs` check the bytes against the spec's field
//! layout; this tool exists so the same bytes can be handed to `sgdisk` and
//! `parted`, which validate the CRCs, the primary/backup agreement and the
//! usable-LBA arithmetic independently.
//!
//!   bazel run //src/cerise/fxfs_provisioner:gpt_image_tool -- /tmp/d.img 64GiB
//!   sgdisk -p -v /tmp/d.img
//!   parted -s /tmp/d.img print
//!
//! Sizes may be given as bytes or with a KiB/MiB/GiB/TiB suffix. An optional
//! third argument sets the logical block size (default 512).

use std::io::{Seek, SeekFrom, Write};

fn parse_size(s: &str) -> Option<u64> {
    let s = s.trim();
    for (suffix, scale) in
        [("TiB", 1u64 << 40), ("GiB", 1 << 30), ("MiB", 1 << 20), ("KiB", 1 << 10)]
    {
        if let Some(n) = s.strip_suffix(suffix) {
            return n.trim().parse::<u64>().ok().map(|v| v * scale);
        }
    }
    s.parse::<u64>().ok()
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("usage: {} <image-path> <disk-size> [block-size]", args[0]);
        std::process::exit(2);
    }
    let path = &args[1];
    let disk_bytes = parse_size(&args[2]).expect("unparseable disk size");
    let block_size: u64 = args.get(3).map(|s| s.parse().expect("bad block size")).unwrap_or(512);
    let block_count = disk_bytes / block_size;

    let plan = match boot_layout::plan_layout(block_size, block_count) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    };
    // Fixed GUIDs: this tool is for inspecting the LAYOUT, and stable GUIDs make
    // repeated runs diffable. The provisioner itself draws them from the CPRNG.
    let img = boot_layout::build_gpt(&plan, [0xA1; 16], [0xB2; 16], [0xC3; 16]);

    let mut f = std::fs::File::create(path).expect("create image");
    // Sparse: seek to the end and write one byte, so a 64 GiB image costs ~0.
    f.seek(SeekFrom::Start(disk_bytes - 1)).unwrap();
    f.write_all(&[0]).unwrap();

    let mut put = |lba: u64, bytes: &[u8]| {
        f.seek(SeekFrom::Start(lba * block_size)).unwrap();
        f.write_all(bytes).unwrap();
    };
    put(0, &img.protective_mbr);
    put(1, &img.primary_header);
    put(img.primary_entries_lba, &img.entries);
    put(img.backup_entries_lba, &img.entries);
    put(img.backup_header_lba, &img.backup_header);
    f.flush().unwrap();

    println!(
        "wrote {path}: {block_count} x {block_size}B blocks\n  \
         ESP  LBA {}..{} ({})\n  \
         fxfs LBA {}..{} ({})",
        plan.esp.first_lba,
        plan.esp.last_lba,
        boot_layout::human(plan.esp.block_count() * block_size),
        plan.fxfs.first_lba,
        plan.fxfs.last_lba,
        boot_layout::human(plan.fxfs.block_count() * block_size),
    );
}

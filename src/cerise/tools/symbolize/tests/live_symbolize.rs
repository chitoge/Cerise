//! Live end-to-end symbolization against REAL kernel symbols.
//!
//! Builds a .build-id store from the live UNSTRIPPED kernel ELF
//! (//build/kernel:vmzircon), reads its build-id and a real function address at
//! runtime (via //toolchain:llvm_nm — never hardcoded, both drift per build),
//! synthesizes symbolizer markup pointing at that function, and asserts the
//! tool resolves it to the real function name through the store + llvm-symbolizer
//! path. This is the "real symbolized kernel frame" proof.
//!
//! Env (injected by BUILD data):
//!   KERNEL_ELF       — path to the unstripped vmzircon ELF
//!   LLVM_NM          — path to llvm-nm
//!   LLVM_SYMBOLIZER  — path to llvm-symbolizer

use std::fs;
use std::io::Cursor;
use std::path::PathBuf;
use std::process::Command;

use symbolize::{read_build_id, Symbolizer};

fn env_path(k: &str) -> PathBuf {
    PathBuf::from(std::env::var(k).unwrap_or_else(|_| panic!("{k} env (BUILD data) must be set")))
}

/// Pick a defined text symbol with a plain C name (no C++ mangling, so it
/// passes through llvm-symbolizer's demangler unchanged) and a nonzero address.
fn pick_function(nm: &PathBuf, elf: &PathBuf) -> (u64, String) {
    let out = Command::new(nm)
        .arg("--defined-only")
        .arg(elf)
        .output()
        .expect("run llvm-nm");
    assert!(out.status.success(), "llvm-nm failed");
    let text = String::from_utf8_lossy(&out.stdout);
    for line in text.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() != 3 {
            continue;
        }
        // Text symbols: 'T' (global) or 't' (local).
        if f[1] != "T" && f[1] != "t" {
            continue;
        }
        let name = f[2];
        if name.starts_with("_Z") || name.starts_with('$') {
            continue; // mangled / linker-local; demangling would change it
        }
        if !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            continue;
        }
        if let Ok(addr) = u64::from_str_radix(f[0], 16) {
            if addr != 0 {
                return (addr, name.to_string());
            }
        }
    }
    panic!("no plain-C text symbol found in {}", elf.display());
}

#[test]
fn resolves_a_real_kernel_frame_through_the_store() {
    let elf = env_path("KERNEL_ELF");
    let nm = env_path("LLVM_NM");
    let symbolizer_bin = env_path("LLVM_SYMBOLIZER");

    let build_id = read_build_id(&elf).expect("kernel ELF has a GNU build-id");
    assert!(
        build_id.len() >= 8 && build_id.bytes().all(|b| b.is_ascii_hexdigit()),
        "build-id looks wrong: {build_id}"
    );

    let (func_addr, func_name) = pick_function(&nm, &elf);

    // Build the standard hashed .build-id store from the unstripped ELF, so the
    // tool's store-lookup path is exercised (not just --obj=).
    let tmp = std::env::temp_dir().join(format!("symbolize_store_{}", std::process::id()));
    let (prefix, rest) = build_id.split_at(2);
    let dir = tmp.join(".build-id").join(prefix);
    fs::create_dir_all(&dir).unwrap();
    fs::copy(&elf, dir.join(format!("{rest}.debug"))).unwrap();

    // Markup: module 0 loaded at static base 0, so module-relative addr == pc ==
    // the symbol's vaddr. size covers the (high-half) kernel vaddr.
    let log = format!(
        "boot: {{{{{{module:0:vmzircon:elf:{id}}}}}}}\n\
         boot: {{{{{{mmap:0x0:{size:#x}:load:0:rx:0x0}}}}}}\n\
         boot: {{{{{{bt:0:{pc:#x}:ra}}}}}}\n",
        id = build_id,
        size = func_addr + 0x1000,
        pc = func_addr,
    );

    let mut symb = Symbolizer::new(
        vec![tmp.clone()],
        symbolizer_bin.to_string_lossy().to_string(),
    );
    let mut out: Vec<u8> = Vec::new();
    symb.process(Cursor::new(log.as_bytes()), &mut out).unwrap();
    let out = String::from_utf8(out).unwrap();

    let _ = fs::remove_dir_all(&tmp);

    assert!(
        out.contains(&func_name),
        "expected real function {func_name:?} (@{func_addr:#x}) in symbolized output:\n{out}"
    );
    // And the original markup line is still present (echo, not replace).
    assert!(out.contains("{{{bt:0:"), "original markup line preserved");
}

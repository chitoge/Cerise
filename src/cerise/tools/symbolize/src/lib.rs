//! symbolize — resolve Fuchsia symbolizer-markup frames in a serial log.
//!
//! Consumes a boot serial log carrying symbolizer markup (see the vendored
//! writer at src/upstream/fuchsia/src/lib/symbolizer-markup) and rewrites it
//! with a symbolized line appended after every `{{{bt}}}` / `{{{pc}}}` frame.
//! Module + load-image (`{{{mmap}}}`) context is tracked as it streams; a
//! `{{{reset}}}` clears it. PCs are turned into module-relative addresses and
//! resolved against the module's *unstripped* ELF, located in a `.build-id`
//! store (the standard `xx/rest.debug` hashed layout) via `llvm-symbolizer`.
//!
//! std-only by deliberate policy: this is a host tool and the repo pins its
//! crate universe via CARGO_BAZEL_REPIN; avoiding external deps keeps it a
//! zero-friction addition (matches assembly/tools/bootfs_diff.py's convention).

use std::collections::BTreeMap;
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

/// One parsed symbolizer-markup element (the text between `{{{` and `}}}`).
#[derive(Debug, Clone, PartialEq)]
pub enum Markup {
    /// `{{{reset}}}` — clears module + mmap context.
    Reset,
    /// `{{{module:$id:$name:elf:$build_id}}}`.
    Module { id: u32, name: String, build_id: String },
    /// `{{{mmap:$start:$size:load:$module_id:$perms:$static_start}}}`.
    Mmap {
        start: u64,
        size: u64,
        module_id: u32,
        perms: String,
        static_start: u64,
    },
    /// `{{{bt:$frame:$pc[:ra|:pc]}}}`.
    Bt { frame: u32, pc: u64, kind: Option<String> },
    /// `{{{pc:$addr}}}`.
    Pc { pc: u64 },
    /// A well-formed element we don't act on (symbol/data/dumpfile/unknown).
    Other(String),
}

fn parse_u64_hex(s: &str) -> Option<u64> {
    let t = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
    if t.is_empty() {
        return None;
    }
    u64::from_str_radix(t, 16).ok()
}

/// Extract the text inside the first `{{{...}}}` on `line`, if any.
///
/// Returns `None` when there is no `{{{` at all, or a `{{{` with no closing
/// `}}}` (a truncated line — passed through untouched by callers).
pub fn find_markup(line: &str) -> Option<&str> {
    let open = line.find("{{{")?;
    let after = &line[open + 3..];
    let close = after.find("}}}")?;
    Some(&after[..close])
}

/// Parse a single element body (no surrounding braces). Returns `None` for
/// anything malformed — a bad field count, non-hex address, etc. — so callers
/// pass the original line through rather than crashing.
pub fn parse_element(body: &str) -> Option<Markup> {
    let fields: Vec<&str> = body.split(':').collect();
    match fields[0] {
        "reset" => {
            if fields.len() == 1 {
                Some(Markup::Reset)
            } else {
                None
            }
        }
        "module" => {
            // module:$id:$name:elf:$build_id — $name may itself contain ':',
            // so anchor on the fixed "elf" tag second-from-last.
            if fields.len() < 5 || fields[fields.len() - 2] != "elf" {
                return None;
            }
            let id: u32 = fields[1].parse().ok()?;
            let build_id = fields[fields.len() - 1];
            if build_id.is_empty() || !build_id.bytes().all(|b| b.is_ascii_hexdigit()) {
                return None;
            }
            let name = fields[2..fields.len() - 2].join(":");
            Some(Markup::Module {
                id,
                name,
                build_id: build_id.to_ascii_lowercase(),
            })
        }
        "mmap" => {
            // mmap:$start:$size:load:$module_id:$perms:$static_start
            if fields.len() != 7 || fields[3] != "load" {
                return None;
            }
            Some(Markup::Mmap {
                start: parse_u64_hex(fields[1])?,
                size: parse_u64_hex(fields[2])?,
                module_id: fields[4].parse().ok()?,
                perms: fields[5].to_string(),
                static_start: parse_u64_hex(fields[6])?,
            })
        }
        "bt" => {
            if fields.len() < 3 || fields.len() > 4 {
                return None;
            }
            Some(Markup::Bt {
                frame: fields[1].parse().ok()?,
                pc: parse_u64_hex(fields[2])?,
                kind: fields.get(3).map(|s| s.to_string()),
            })
        }
        "pc" => {
            if fields.len() != 2 {
                return None;
            }
            Some(Markup::Pc {
                pc: parse_u64_hex(fields[1])?,
            })
        }
        _ => Some(Markup::Other(body.to_string())),
    }
}

#[derive(Debug, Clone)]
struct ModuleInfo {
    #[allow(dead_code)]
    name: String,
    build_id: String,
}

#[derive(Debug, Clone)]
struct MmapInfo {
    start: u64,
    size: u64,
    module_id: u32,
    static_start: u64,
}

/// Streaming symbolizer: tracks module/mmap context and resolves frames.
pub struct Symbolizer {
    stores: Vec<PathBuf>,
    llvm_symbolizer: String,
    modules: BTreeMap<u32, ModuleInfo>,
    mmaps: Vec<MmapInfo>,
}

/// Result of resolving one frame, for appending under the original line.
struct Resolution {
    build_id: String,
    lookup: LookupResult,
}

enum LookupResult {
    /// build-id had no ELF in any store (or the module was never declared).
    NoStoreEntry,
    /// llvm-symbolizer output (function, file:line).
    Symbol { function: String, location: String },
}

impl Symbolizer {
    pub fn new(stores: Vec<PathBuf>, llvm_symbolizer: String) -> Self {
        Symbolizer {
            stores,
            llvm_symbolizer,
            modules: BTreeMap::new(),
            mmaps: Vec::new(),
        }
    }

    /// Locate the unstripped ELF for `build_id` in the `.build-id` stores.
    /// Accepts both a store dir that *is* the `.build-id` root and one that
    /// *contains* a `.build-id` subdir.
    fn find_elf(&self, build_id: &str) -> Option<PathBuf> {
        if build_id.len() < 3 {
            return None;
        }
        let (prefix, rest) = build_id.split_at(2);
        let leaf = format!("{}.debug", rest);
        for store in &self.stores {
            let direct = store.join(prefix).join(&leaf);
            if direct.exists() {
                return Some(direct);
            }
            let nested = store.join(".build-id").join(prefix).join(&leaf);
            if nested.exists() {
                return Some(nested);
            }
        }
        None
    }

    fn resolve(&self, pc: u64) -> Option<Resolution> {
        // Find the active mapping covering pc (last one wins on overlap).
        let mmap = self
            .mmaps
            .iter()
            .rev()
            .find(|m| pc >= m.start && pc < m.start.saturating_add(m.size))?;
        let module = self.modules.get(&mmap.module_id);
        let module_rel = mmap.static_start.wrapping_add(pc.wrapping_sub(mmap.start));
        let build_id = match module {
            Some(m) => m.build_id.clone(),
            None => {
                return Some(Resolution {
                    build_id: String::new(),
                    lookup: LookupResult::NoStoreEntry,
                })
            }
        };
        let elf = match self.find_elf(&build_id) {
            Some(p) => p,
            None => {
                return Some(Resolution {
                    build_id,
                    lookup: LookupResult::NoStoreEntry,
                })
            }
        };
        let lookup = match self.run_symbolizer(&elf, module_rel) {
            Some((function, location)) => LookupResult::Symbol { function, location },
            None => LookupResult::NoStoreEntry,
        };
        Some(Resolution {
            build_id,
            lookup,
        })
    }

    fn run_symbolizer(&self, elf: &Path, addr: u64) -> Option<(String, String)> {
        let out = Command::new(&self.llvm_symbolizer)
            .arg(format!("--obj={}", elf.display()))
            .arg(format!("0x{:x}", addr))
            .output()
            .ok()?;
        if !out.status.success() {
            return None;
        }
        let text = String::from_utf8_lossy(&out.stdout);
        let mut lines = text.lines();
        let function = lines.next()?.trim().to_string();
        let location = lines.next().unwrap_or("").trim().to_string();
        if function.is_empty() || function == "??" {
            return None;
        }
        Some((function, location))
    }

    /// Update context / return appended symbolization lines for one input line.
    /// Returns the (possibly empty) extra lines to print after the input line.
    fn handle(&mut self, line: &str) -> Vec<String> {
        let body = match find_markup(line) {
            Some(b) => b,
            None => return Vec::new(),
        };
        let elem = match parse_element(body) {
            Some(e) => e,
            None => return Vec::new(),
        };
        match elem {
            Markup::Reset => {
                self.modules.clear();
                self.mmaps.clear();
                Vec::new()
            }
            Markup::Module { id, name, build_id } => {
                self.modules.insert(id, ModuleInfo { name, build_id });
                Vec::new()
            }
            Markup::Mmap {
                start,
                size,
                module_id,
                static_start,
                ..
            } => {
                self.mmaps.push(MmapInfo {
                    start,
                    size,
                    module_id,
                    static_start,
                });
                Vec::new()
            }
            Markup::Bt { frame, pc, .. } => self.render_frame(frame, pc),
            Markup::Pc { pc } => self.render_frame(0, pc),
            Markup::Other(_) => Vec::new(),
        }
    }

    fn render_frame(&self, frame: u32, pc: u64) -> Vec<String> {
        match self.resolve(pc) {
            None => vec![format!(
                "    #{:<2} {:#018x}  <no active load image for pc>",
                frame, pc
            )],
            Some(r) => match r.lookup {
                LookupResult::Symbol { function, location } => {
                    let loc = if location.is_empty() {
                        String::new()
                    } else {
                        format!(" {}", location)
                    };
                    vec![format!(
                        "    #{:<2} {:#018x}  {}{}",
                        frame, pc, function, loc
                    )]
                }
                LookupResult::NoStoreEntry => vec![format!(
                    "    #{:<2} {:#018x}  <no symbols for build-id {}>",
                    frame,
                    pc,
                    if r.build_id.is_empty() {
                        "?"
                    } else {
                        &r.build_id
                    }
                )],
            },
        }
    }

    /// Stream `reader` to `writer`, echoing every line and appending a
    /// symbolized line under each frame.
    pub fn process<R: BufRead, W: Write>(
        &mut self,
        reader: R,
        writer: &mut W,
    ) -> std::io::Result<()> {
        for line in reader.lines() {
            let line = line?;
            writeln!(writer, "{}", line)?;
            for extra in self.handle(&line) {
                writeln!(writer, "{}", extra)?;
            }
        }
        Ok(())
    }
}

/// Read the GNU build-id (lowercase hex) from a 64-bit little-endian ELF, by
/// scanning its PT_NOTE segments for NT_GNU_BUILD_ID. std-only ELF poke; used
/// by tests to construct markup referencing a live module, and handy standalone
/// (`symbolize --build-id <elf>`).
pub fn read_build_id(elf: &Path) -> Option<String> {
    let data = std::fs::read(elf).ok()?;
    if data.len() < 64 || &data[0..4] != b"\x7fELF" || data[4] != 2 || data[5] != 1 {
        return None; // not ELF64 LE
    }
    let u16at = |o: usize| u16::from_le_bytes([data[o], data[o + 1]]) as usize;
    let u32at = |o: usize| {
        u32::from_le_bytes([data[o], data[o + 1], data[o + 2], data[o + 3]]) as usize
    };
    let u64at = |o: usize| {
        u64::from_le_bytes([
            data[o],
            data[o + 1],
            data[o + 2],
            data[o + 3],
            data[o + 4],
            data[o + 5],
            data[o + 6],
            data[o + 7],
        ]) as usize
    };
    let e_phoff = u64at(0x20);
    let e_phentsize = u16at(0x36);
    let e_phnum = u16at(0x38);
    const PT_NOTE: usize = 4;
    for i in 0..e_phnum {
        let ph = e_phoff + i * e_phentsize;
        if ph + 0x38 > data.len() {
            break;
        }
        if u32at(ph) != PT_NOTE as usize {
            continue;
        }
        let p_offset = u64at(ph + 0x08);
        let p_filesz = u64at(ph + 0x20);
        if let Some(id) = scan_notes(&data, p_offset, p_filesz) {
            return Some(id);
        }
    }
    None
}

fn scan_notes(data: &[u8], mut off: usize, len: usize) -> Option<String> {
    const NT_GNU_BUILD_ID: u32 = 3;
    let end = off.checked_add(len)?;
    if end > data.len() {
        return None;
    }
    while off + 12 <= end {
        let namesz = u32::from_le_bytes(data[off..off + 4].try_into().ok()?) as usize;
        let descsz = u32::from_le_bytes(data[off + 4..off + 8].try_into().ok()?) as usize;
        let ntype = u32::from_le_bytes(data[off + 8..off + 12].try_into().ok()?);
        let name_off = off + 12;
        let desc_off = name_off + namesz.div_ceil(4) * 4;
        let desc_end = desc_off + descsz;
        if desc_end > end {
            break;
        }
        let name = &data[name_off..name_off + namesz];
        if ntype == NT_GNU_BUILD_ID && name.starts_with(b"GNU\0") {
            let hex: String = data[desc_off..desc_end]
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect();
            return Some(hex);
        }
        off = desc_end + (4 - descsz % 4) % 4;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_reset() {
        assert_eq!(parse_element("reset"), Some(Markup::Reset));
        assert_eq!(parse_element("reset:extra"), None);
    }

    #[test]
    fn parses_module() {
        let m = parse_element("module:2:vmzircon:elf:5F2D7e83").unwrap();
        assert_eq!(
            m,
            Markup::Module {
                id: 2,
                name: "vmzircon".to_string(),
                build_id: "5f2d7e83".to_string(),
            }
        );
    }

    #[test]
    fn parses_mmap() {
        let m = parse_element("mmap:0x222000:0x153000:load:0:rw:0x0").unwrap();
        assert_eq!(
            m,
            Markup::Mmap {
                start: 0x222000,
                size: 0x153000,
                module_id: 0,
                perms: "rw".to_string(),
                static_start: 0x0,
            }
        );
    }

    #[test]
    fn parses_bt_and_pc() {
        assert_eq!(
            parse_element("bt:0:0x44bca0"),
            Some(Markup::Bt {
                frame: 0,
                pc: 0x44bca0,
                kind: None
            })
        );
        assert_eq!(
            parse_element("bt:3:0xdead:ra"),
            Some(Markup::Bt {
                frame: 3,
                pc: 0xdead,
                kind: Some("ra".to_string())
            })
        );
        assert_eq!(
            parse_element("pc:0x44bca0"),
            Some(Markup::Pc { pc: 0x44bca0 })
        );
    }

    // ---- malformed / adversarial cases: must not panic, must pass through ----

    #[test]
    fn truncated_open_has_no_markup() {
        assert_eq!(find_markup("physload: {{{module:0:x:elf:ab"), None);
        assert_eq!(find_markup("no markup here"), None);
    }

    #[test]
    fn bad_hex_addr_rejected() {
        assert_eq!(parse_element("pc:0xZZZZ"), None);
        assert_eq!(parse_element("bt:0:nothex"), None);
        assert_eq!(parse_element("mmap:0xg:0x1:load:0:rx:0x0"), None);
    }

    #[test]
    fn wrong_field_count_rejected() {
        assert_eq!(parse_element("mmap:0x1:0x2:load:0:rx"), None); // 6 not 7
        assert_eq!(parse_element("module:0:name"), None); // no elf tag
        assert_eq!(parse_element("pc"), None);
        assert_eq!(parse_element("bt:0:0x1:ra:extra"), None);
    }

    #[test]
    fn unknown_element_is_other_not_crash() {
        assert_eq!(
            parse_element("symbol:foo"),
            Some(Markup::Other("symbol:foo".to_string()))
        );
        assert_eq!(
            parse_element("dumpfile:core:x"),
            Some(Markup::Other("dumpfile:core:x".to_string()))
        );
    }

    #[test]
    fn empty_build_id_rejected() {
        assert_eq!(parse_element("module:0:name:elf:"), None);
        assert_eq!(parse_element("module:0:name:elf:xyz"), None); // non-hex
    }

    #[test]
    fn mmap_for_unknown_module_does_not_crash() {
        // A frame under an mmap whose module was never declared resolves to a
        // clean "no symbols" line rather than panicking.
        let mut s = Symbolizer::new(vec![], "llvm-symbolizer".to_string());
        // Only an mmap for module 9, no {{{module:9:...}}}.
        s.handle("{{{mmap:0x1000:0x1000:load:9:rx:0x0}}}");
        let out = s.handle("{{{bt:0:0x1500}}}");
        assert_eq!(out.len(), 1);
        assert!(out[0].contains("no symbols"), "got: {}", out[0]);
    }

    #[test]
    fn frame_outside_any_mmap() {
        let mut s = Symbolizer::new(vec![], "llvm-symbolizer".to_string());
        let out = s.handle("{{{pc:0x9999}}}");
        assert_eq!(out.len(), 1);
        assert!(out[0].contains("no active load image"), "got: {}", out[0]);
    }
}

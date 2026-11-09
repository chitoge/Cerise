//! symbolize CLI — see lib.rs for the parsing/resolution engine.
//!
//! Usage:
//!   symbolize [--build-id-dir DIR]... [--llvm-symbolizer PATH] [INPUT_LOG]
//!   symbolize --build-id <ELF>          # print an ELF's GNU build-id and exit
//!
//! Reads a boot serial log (INPUT_LOG or stdin), echoes it, and appends a
//! symbolized line under each {{{bt}}}/{{{pc}}} frame it can resolve against the
//! .build-id store(s). The llvm-symbolizer binary defaults to
//! $CERISE_LLVM_SYMBOLIZER, then "llvm-symbolizer" on PATH.

use std::fs::File;
use std::io::{self, BufReader, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use symbolize::{read_build_id, Symbolizer};

fn main() -> ExitCode {
    let mut stores: Vec<PathBuf> = Vec::new();
    let mut input: Option<PathBuf> = None;
    let mut llvm_symbolizer = std::env::var("CERISE_LLVM_SYMBOLIZER")
        .unwrap_or_else(|_| "llvm-symbolizer".to_string());

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--build-id-dir" => {
                let d = match args.next() {
                    Some(d) => d,
                    None => return usage("--build-id-dir needs a directory"),
                };
                stores.push(PathBuf::from(d));
            }
            "--llvm-symbolizer" => {
                llvm_symbolizer = match args.next() {
                    Some(p) => p,
                    None => return usage("--llvm-symbolizer needs a path"),
                };
            }
            "--build-id" => {
                let elf = match args.next() {
                    Some(e) => e,
                    None => return usage("--build-id needs an ELF path"),
                };
                match read_build_id(&PathBuf::from(&elf)) {
                    Some(id) => {
                        println!("{}", id);
                        return ExitCode::SUCCESS;
                    }
                    None => {
                        eprintln!("symbolize: no GNU build-id in {}", elf);
                        return ExitCode::FAILURE;
                    }
                }
            }
            "--help" | "-h" => {
                print_help();
                return ExitCode::SUCCESS;
            }
            other if other.starts_with('-') => return usage(&format!("unknown flag {other}")),
            other => {
                if input.is_some() {
                    return usage("at most one input log may be given");
                }
                input = Some(PathBuf::from(other));
            }
        }
    }

    let mut symbolizer = Symbolizer::new(stores, llvm_symbolizer);
    let stdout = io::stdout();
    let mut out = stdout.lock();

    let result = match input {
        Some(path) => match File::open(&path) {
            Ok(f) => symbolizer.process(BufReader::new(f), &mut out),
            Err(e) => {
                eprintln!("symbolize: {}: {}", path.display(), e);
                return ExitCode::FAILURE;
            }
        },
        None => {
            let stdin = io::stdin();
            symbolizer.process(stdin.lock(), &mut out)
        }
    };
    let _ = out.flush();
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("symbolize: {}", e);
            ExitCode::FAILURE
        }
    }
}

fn usage(msg: &str) -> ExitCode {
    eprintln!("symbolize: {}", msg);
    eprintln!("try `symbolize --help`");
    ExitCode::from(2)
}

fn print_help() {
    print!(
        "symbolize — resolve Fuchsia symbolizer-markup frames in a serial log.\n\
         \n\
         Usage:\n\
         \x20 symbolize [--build-id-dir DIR]... [--llvm-symbolizer PATH] [INPUT_LOG]\n\
         \x20 symbolize --build-id <ELF>\n\
         \n\
         Options:\n\
         \x20 --build-id-dir DIR     a .build-id store to resolve modules against (repeatable)\n\
         \x20 --llvm-symbolizer P    path to llvm-symbolizer (default $CERISE_LLVM_SYMBOLIZER)\n\
         \x20 --build-id ELF         print an ELF's GNU build-id and exit\n\
         \x20 INPUT_LOG              serial log to read (default: stdin)\n"
    );
}

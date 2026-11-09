//! debuginfod CLI: `debuginfod <store-dir> [--addr 127.0.0.1:PORT]`.
//!
//! Serves the debuginfod protocol over a `.build-id` store so gdb / lldb /
//! llvm-symbolizer resolve symbols with zero client config:
//!
//!   bazel run //src/cerise/tools/debuginfod -- bazel-bin/validation/x64-smoke.build-id
//!   export DEBUGINFOD_URLS=http://127.0.0.1:8002
//!
//! See src/lib.rs.

use debuginfod::Server;
use std::path::Path;
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let mut store: Option<String> = None;
    let mut addr = "127.0.0.1:8002".to_string();
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--addr" => {
                i += 1;
                match args.get(i) {
                    Some(a) => addr = a.clone(),
                    None => {
                        eprintln!("--addr requires an argument");
                        return ExitCode::from(2);
                    }
                }
            }
            "-h" | "--help" => {
                eprintln!("usage: debuginfod <store-dir> [--addr HOST:PORT]");
                return ExitCode::SUCCESS;
            }
            other if store.is_none() => store = Some(other.to_string()),
            other => {
                eprintln!("unexpected argument: {other}");
                return ExitCode::from(2);
            }
        }
        i += 1;
    }

    let Some(store) = store else {
        eprintln!("usage: debuginfod <store-dir> [--addr HOST:PORT]");
        return ExitCode::from(2);
    };
    let store_path = Path::new(&store);
    if !store_path.is_dir() {
        eprintln!("debuginfod: store dir not found: {store}");
        return ExitCode::from(1);
    }

    match Server::new(store_path).serve(&addr) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("debuginfod: fatal: {e}");
            ExitCode::from(1)
        }
    }
}

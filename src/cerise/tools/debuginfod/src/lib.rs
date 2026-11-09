//! debuginfod — a tiny std-only HTTP server over a `.build-id` debug-symbol
//! store.
//!
//! Speaks the subset of the debuginfod protocol that gdb / lldb /
//! llvm-symbolizer consume via `DEBUGINFOD_URLS`:
//!
//!   GET /buildid/<hex-build-id>/debuginfo   -> the unstripped ELF (symbols+debug)
//!   GET /buildid/<hex-build-id>/executable  -> the same unstripped ELF
//!
//! Both map to the standard hashed store layout `.build-id/<xx>/<rest>.debug`
//! materialised by `cerise_debug_symbols` (bazel/debug_symbols.bzl). Because our
//! store keeps a single UNSTRIPPED ELF per build-id (it carries both the code and
//! the debug info), `debuginfo` and `executable` resolve to the same file — a
//! debuginfod client asking for either gets a working object.
//!
//! std-only by deliberate policy (matches //src/cerise/tools/symbolize and
//! assembly/tools/bootfs_diff.py): blocking `std::net`, a fixed worker pool,
//! bounded request parsing, and no external crates. This keeps it a
//! zero-friction host tool without giving slow clients unbounded resources.

use std::fs::File;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::Duration;

const WORKER_COUNT: usize = 8;
const PENDING_CONNECTIONS: usize = 32;
const IO_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_REQUEST_LINE_BYTES: usize = 8 * 1024;
const MAX_HEADER_LINE_BYTES: usize = 8 * 1024;
const MAX_HEADER_BYTES: usize = 32 * 1024;

/// A debuginfod server bound to a `.build-id` store directory.
pub struct Server {
    /// The `.build-id` root (the directory that directly contains the `xx/`
    /// two-hex-digit subdirectories). Accepts either a store dir that *is* the
    /// `.build-id` root or one that *contains* a `.build-id` subdir — resolved
    /// once at construction.
    build_id_root: PathBuf,
}

/// What a parsed request line resolved to.
#[derive(Debug, PartialEq, Eq)]
pub enum Request {
    /// `/buildid/<id>/debuginfo` or `/buildid/<id>/executable`: serve the ELF
    /// for this (lowercased, validated-hex) build-id.
    Artifact { build_id: String },
    /// A well-formed GET we don't serve (unknown path / artifact kind) -> 404.
    NotFound,
    /// A malformed or non-GET request -> 400.
    BadRequest,
}

impl Server {
    /// Resolve `store` to its `.build-id` root. A store produced by
    /// `cerise_debug_symbols` is a directory containing a `.build-id/` subtree;
    /// pointing directly at a `.build-id` dir also works.
    pub fn new(store: &Path) -> Self {
        let nested = store.join(".build-id");
        let build_id_root = if nested.is_dir() {
            nested
        } else {
            store.to_path_buf()
        };
        Server { build_id_root }
    }

    /// The absolute path an artifact request maps to, if the build-id is
    /// well-formed. Does not check existence (the caller distinguishes 404).
    pub fn artifact_path(&self, build_id: &str) -> Option<PathBuf> {
        if build_id.len() < 3 || !build_id.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        let id = build_id.to_ascii_lowercase();
        let (prefix, rest) = id.split_at(2);
        Some(
            self.build_id_root
                .join(prefix)
                .join(format!("{rest}.debug")),
        )
    }

    /// Bind and serve forever. Returns only on a fatal accept error.
    pub fn serve(self, addr: &str) -> std::io::Result<()> {
        let listener = TcpListener::bind(addr)?;
        self.serve_listener(listener)
    }

    /// Serve a pre-bound listener. Besides eliminating bind races in tests,
    /// this lets a supervisor choose and reserve the socket before starting the
    /// worker pool.
    pub fn serve_listener(self, listener: TcpListener) -> std::io::Result<()> {
        let local = listener.local_addr()?;
        eprintln!(
            "debuginfod: serving {} on http://{}",
            self.build_id_root.display(),
            local
        );
        eprintln!("debuginfod: export DEBUGINFOD_URLS=http://{local}");
        let this = Arc::new(self);

        // A fixed worker pool plus a bounded pending queue prevents a stream of
        // slow clients from creating unbounded threads. Receiver is not Sync,
        // so workers briefly share a mutex only while dequeuing a connection.
        let (sender, receiver) = mpsc::sync_channel::<TcpStream>(PENDING_CONNECTIONS);
        let receiver = Arc::new(Mutex::new(receiver));
        for worker_id in 0..WORKER_COUNT {
            let this = Arc::clone(&this);
            let receiver = Arc::clone(&receiver);
            thread::Builder::new()
                .name(format!("debuginfod-{worker_id}"))
                .spawn(move || loop {
                    let stream = match receiver.lock() {
                        Ok(receiver) => receiver.recv(),
                        Err(_) => return,
                    };
                    let stream = match stream {
                        Ok(stream) => stream,
                        Err(_) => return,
                    };
                    if let Err(error) = this.handle(stream) {
                        eprintln!("debuginfod: connection error: {error}");
                    }
                })?;
        }

        for stream in listener.incoming() {
            match stream {
                Ok(stream) => match sender.try_send(stream) {
                    Ok(()) => {}
                    Err(mpsc::TrySendError::Full(mut stream)) => {
                        let _ = stream.set_write_timeout(Some(IO_TIMEOUT));
                        let _ = write_response(
                            &mut stream,
                            503,
                            "Service Unavailable",
                            "text/plain",
                            b"server busy\n",
                        );
                    }
                    Err(mpsc::TrySendError::Disconnected(_)) => {
                        return Err(io::Error::new(
                            io::ErrorKind::BrokenPipe,
                            "debuginfod worker pool stopped",
                        ));
                    }
                },
                Err(error) => {
                    eprintln!("debuginfod: accept error: {error}");
                    continue;
                }
            }
        }
        Ok(())
    }

    /// Serve one connection: parse the request line, resolve, respond.
    fn handle(&self, stream: TcpStream) -> std::io::Result<()> {
        stream.set_read_timeout(Some(IO_TIMEOUT))?;
        stream.set_write_timeout(Some(IO_TIMEOUT))?;
        let mut reader = BufReader::new(stream.try_clone()?);
        let request_line = match read_request(&mut reader) {
            Ok(Some(line)) => line,
            Ok(None) => return Ok(()),
            Err(error) if error.kind() == io::ErrorKind::InvalidData => {
                let mut stream = stream;
                return write_response(
                    &mut stream,
                    400,
                    "Bad Request",
                    "text/plain",
                    b"bad request\n",
                );
            }
            Err(error) => return Err(error),
        };

        let mut stream = stream;
        match parse_request_line(&request_line) {
            Request::Artifact { build_id } => match self.artifact_path(&build_id) {
                Some(path) if path.is_file() => write_file_response(&mut stream, &path),
                _ => write_response(
                    &mut stream,
                    404,
                    "Not Found",
                    "text/plain",
                    format!("no debuginfo for build-id {build_id}\n").as_bytes(),
                ),
            },
            Request::NotFound => {
                write_response(&mut stream, 404, "Not Found", "text/plain", b"not found\n")
            }
            Request::BadRequest => write_response(
                &mut stream,
                400,
                "Bad Request",
                "text/plain",
                b"bad request\n",
            ),
        }
    }
}

/// Read one line without ever allocating beyond `limit`. The returned bytes
/// include the line ending when present.
fn read_bounded_line<R: BufRead>(reader: &mut R, limit: usize) -> io::Result<Option<Vec<u8>>> {
    let mut line = Vec::new();
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            return if line.is_empty() {
                Ok(None)
            } else {
                Ok(Some(line))
            };
        }
        let take = available
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(available.len(), |index| index + 1);
        let new_len = line.len().checked_add(take).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "HTTP line length overflow")
        })?;
        if new_len > limit {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "HTTP line too long",
            ));
        }
        line.extend_from_slice(&available[..take]);
        let ended = available[take - 1] == b'\n';
        reader.consume(take);
        if ended {
            return Ok(Some(line));
        }
    }
}

/// Read and validate the request-line/header envelope. Header contents are not
/// used, but both individual lines and the aggregate are bounded.
fn read_request<R: BufRead>(reader: &mut R) -> io::Result<Option<String>> {
    let request = match read_bounded_line(reader, MAX_REQUEST_LINE_BYTES)? {
        Some(request) => request,
        None => return Ok(None),
    };
    let mut total = request.len();
    loop {
        let header = read_bounded_line(reader, MAX_HEADER_LINE_BYTES)?
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "truncated HTTP headers"))?;
        total = total.checked_add(header.len()).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "HTTP header length overflow")
        })?;
        if total > MAX_HEADER_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "HTTP headers too large",
            ));
        }
        if header == b"\r\n" || header == b"\n" {
            break;
        }
    }
    String::from_utf8(request)
        .map(Some)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "request line is not UTF-8"))
}

/// Parse an HTTP request line (`GET /buildid/<id>/<kind> HTTP/1.1`).
///
/// Only `GET` is served. `<kind>` is `debuginfo` or `executable` (both resolve
/// to the store's unstripped ELF). Anything else is NotFound; a non-GET or
/// structurally-broken line is BadRequest.
pub fn parse_request_line(line: &str) -> Request {
    let mut parts = line.split_whitespace();
    let (method, target) = match (parts.next(), parts.next()) {
        (Some(m), Some(t)) => (m, t),
        _ => return Request::BadRequest,
    };
    if method != "GET" {
        return Request::BadRequest;
    }
    // Strip any query string, then split the path.
    let path = target.split('?').next().unwrap_or(target);
    let segs: Vec<&str> = path.trim_start_matches('/').split('/').collect();
    // buildid/<id>/<kind>
    if segs.len() == 3
        && segs[0] == "buildid"
        && (segs[2] == "debuginfo" || segs[2] == "executable")
    {
        let id = segs[1];
        if id.len() >= 3 && id.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Request::Artifact {
                build_id: id.to_ascii_lowercase(),
            };
        }
    }
    Request::NotFound
}

/// Write a minimal, well-formed HTTP/1.1 response with an explicit
/// Content-Length and `Connection: close` (so a client without keep-alive
/// bookkeeping sees a clean EOF).
fn write_response(
    stream: &mut TcpStream,
    code: u16,
    reason: &str,
    content_type: &str,
    body: &[u8],
) -> std::io::Result<()> {
    write_response_header(stream, code, reason, content_type, body.len() as u64)?;
    stream.write_all(body)?;
    stream.flush()
}

fn write_response_header(
    stream: &mut TcpStream,
    code: u16,
    reason: &str,
    content_type: &str,
    content_length: u64,
) -> io::Result<()> {
    let header = format!(
        "HTTP/1.1 {code} {reason}\r\n\
         Content-Type: {content_type}\r\n\
         Content-Length: {content_length}\r\n\
         Connection: close\r\n\
         \r\n"
    );
    stream.write_all(header.as_bytes())
}

fn write_file_response(stream: &mut TcpStream, path: &Path) -> io::Result<()> {
    let mut file = File::open(path)?;
    let length = file.metadata()?.len();
    write_response_header(stream, 200, "OK", "application/octet-stream", length)?;
    io::copy(&mut file, stream)?;
    stream.flush()
}

/// Blocking helper: issue a single `GET <path>` to `addr` and return
/// `(status_code, body_bytes)`. std-only, used by the tests and handy for
/// scripted checks. Not part of the server hot path.
pub fn http_get(addr: &str, path: &str) -> std::io::Result<(u16, Vec<u8>)> {
    let mut stream = TcpStream::connect(addr)?;
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
    )?;
    stream.flush()?;
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw)?;
    // Split headers/body on the first CRLFCRLF.
    let sep = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "no header terminator")
        })?;
    let head = String::from_utf8_lossy(&raw[..sep]);
    let body = raw[sep + 4..].to_vec();
    let status = head
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|c| c.parse::<u16>().ok())
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "no status code"))?;
    Ok((status, body))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_debuginfo_and_executable() {
        assert_eq!(
            parse_request_line("GET /buildid/abcdef12/debuginfo HTTP/1.1"),
            Request::Artifact {
                build_id: "abcdef12".to_string()
            }
        );
        assert_eq!(
            parse_request_line("GET /buildid/ABCDEF12/executable HTTP/1.1\r\n"),
            Request::Artifact {
                build_id: "abcdef12".to_string()
            }
        );
    }

    #[test]
    fn rejects_non_get_and_garbage() {
        assert_eq!(
            parse_request_line("POST /buildid/ab/debuginfo HTTP/1.1"),
            Request::BadRequest
        );
        assert_eq!(parse_request_line("garbage"), Request::BadRequest);
        assert_eq!(parse_request_line(""), Request::BadRequest);
    }

    #[test]
    fn unknown_paths_are_not_found() {
        assert_eq!(parse_request_line("GET / HTTP/1.1"), Request::NotFound);
        assert_eq!(
            parse_request_line("GET /buildid/ab/source HTTP/1.1"),
            Request::NotFound
        );
        // Non-hex or too-short build-id.
        assert_eq!(
            parse_request_line("GET /buildid/xy/debuginfo HTTP/1.1"),
            Request::NotFound
        );
        assert_eq!(
            parse_request_line("GET /buildid/a/debuginfo HTTP/1.1"),
            Request::NotFound
        );
    }

    #[test]
    fn artifact_path_maps_to_store_layout() {
        let s = Server {
            build_id_root: PathBuf::from("/store/.build-id"),
        };
        assert_eq!(
            s.artifact_path("abcdef"),
            Some(PathBuf::from("/store/.build-id/ab/cdef.debug"))
        );
        assert_eq!(s.artifact_path("zz"), None); // non-hex
    }
}

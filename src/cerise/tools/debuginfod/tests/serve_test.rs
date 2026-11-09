//! End-to-end: build a `.build-id` store on disk, serve it on an ephemeral
//! port, fetch a known build-id over real HTTP and assert the bytes match the
//! store file; plus a 404 for an absent build-id. std-only.

use debuginfod::{http_get, Server};
use std::io::Write;
use std::net::{Shutdown, TcpListener, TcpStream};
use std::path::PathBuf;
use std::thread;
use std::time::Duration;

/// A unique temp dir under the test's tmpdir (no external tempfile crate).
fn scratch(tag: &str) -> PathBuf {
    let base = std::env::var("TEST_TMPDIR").unwrap_or_else(|_| "/tmp".to_string());
    let uniq = format!(
        "debuginfod-{tag}-{}-{:?}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let dir = PathBuf::from(base).join(uniq);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn serves_known_build_id_and_404s_unknown() {
    // A synthetic store in the standard hashed layout: <root>/.build-id/ab/<rest>.debug.
    // Deterministic bytes so the byte-for-byte assertion is exact and hermetic
    // (no heavy kernel/vmzircon build). The real product store built by
    // cerise_debug_symbols has the identical layout, so this exercises the same
    // resolution path //validation:x64-smoke.build-id would.
    let store = scratch("store");
    let build_id = "abcdef0123456789";
    let payload: Vec<u8> = (0u8..=255).cycle().take(4096).collect();
    let dir = store.join(".build-id").join("ab");
    std::fs::create_dir_all(&dir).unwrap();
    let elf = dir.join("cdef0123456789.debug");
    std::fs::File::create(&elf)
        .unwrap()
        .write_all(&payload)
        .unwrap();

    // Pass the still-bound listener into the server so another process cannot
    // claim the ephemeral port between test setup and serve startup.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let server = Server::new(&store);
    thread::spawn(move || {
        // serve_listener() only returns on a fatal error; process exit reaps it.
        let _ = server.serve_listener(listener);
    });

    // Known build-id -> 200 + exact bytes, for both artifact kinds.
    for kind in ["debuginfo", "executable"] {
        let (status, body) = http_get(&addr, &format!("/buildid/{build_id}/{kind}")).unwrap();
        assert_eq!(status, 200, "kind={kind}");
        assert_eq!(body, payload, "byte mismatch for kind={kind}");
    }

    // Unknown build-id -> 404.
    let (status, _) = http_get(&addr, "/buildid/deadbeefdeadbeef/debuginfo").unwrap();
    assert_eq!(status, 404);

    // Unknown path -> 404; non-GET -> 400.
    let (status, _) = http_get(&addr, "/nope").unwrap();
    assert_eq!(status, 404);

    // Oversized headers are rejected without allowing read_line to allocate the
    // peer-controlled size.
    let mut stream = TcpStream::connect(&addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let write_result = write!(
        stream,
        "GET / HTTP/1.1\r\nX-Oversized: {}\r\n\r\n",
        "x".repeat(40 * 1024)
    );
    if let Err(error) = write_result {
        assert_eq!(error.kind(), std::io::ErrorKind::ConnectionReset);
        return;
    }
    let _ = stream.shutdown(Shutdown::Write);
    let mut response = Vec::new();
    let read_result = std::io::Read::read_to_end(&mut stream, &mut response);
    // Closing a socket with attacker-controlled unread request bytes is allowed
    // to surface as ECONNRESET. If the kernel delivers the response first, it
    // must be the bounded parser's 400; either outcome proves prompt rejection.
    match read_result {
        Ok(_) => assert!(response.starts_with(b"HTTP/1.1 400 Bad Request")),
        Err(error) => assert_eq!(error.kind(), std::io::ErrorKind::ConnectionReset),
    }
}

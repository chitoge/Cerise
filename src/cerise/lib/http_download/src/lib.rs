//! A deliberately small, bounded HTTP/1 download client.
//!
//! Package bytes are authenticated only after download, so every unauthenticated
//! byte accepted here is bounded locally.  The client supports the subset its
//! callers need: one `GET`, an exact `200` response, optional `Content-Length`,
//! no transfer coding, and either a declared length or connection-close framing.

use anyhow::{Context as _, Result, anyhow};
use std::net::SocketAddr;
use std::time::Duration;

const DEFAULT_MAX_HEADER_BYTES: usize = 64 << 10;
const DEFAULT_IO_TIMEOUT: Duration = Duration::from_secs(30);
const DEFAULT_TOTAL_TIMEOUT: Duration = Duration::from_secs(120);
const READ_CHUNK_BYTES: usize = 16 << 10;
const MAX_REQUEST_TARGET_BYTES: usize = 8 << 10;

/// Keep the status line bounded independently of the complete response-header bound.
pub const MAX_STATUS_LINE_BYTES: usize = 8 << 10;

/// Per-request resource limits.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Maximum bytes before and including the header terminator.
    pub max_header_bytes: usize,
    /// Maximum response-body bytes.
    pub max_body_bytes: usize,
    /// Connect deadline, write deadline, and idle deadline for each read.
    pub io_timeout: Duration,
    /// Deadline for the complete request, including a peer that keeps making
    /// progress just often enough to avoid the per-operation idle deadline.
    pub total_timeout: Duration,
}

impl Limits {
    /// Construct limits with a 64-KiB header ceiling and a 30-second I/O deadline.
    pub const fn new(max_body_bytes: usize) -> Self {
        Self {
            max_header_bytes: DEFAULT_MAX_HEADER_BYTES,
            max_body_bytes,
            io_timeout: DEFAULT_IO_TIMEOUT,
            total_timeout: DEFAULT_TOTAL_TIMEOUT,
        }
    }
}

/// Validate an HTTP/1.x status line and require the successful status code.
///
/// `line` excludes its terminating CRLF. Redirects and all non-200 responses
/// are deliberately refused because their bodies are not candidate package data.
pub fn validate_status_line(line: &[u8]) -> std::result::Result<(), &'static str> {
    if line.is_empty() {
        return Err("empty status line");
    }
    if line.len() > MAX_STATUS_LINE_BYTES {
        return Err("status line is too long");
    }

    let rest = if let Some(rest) = line.strip_prefix(b"HTTP/1.0 ") {
        rest
    } else if let Some(rest) = line.strip_prefix(b"HTTP/1.1 ") {
        rest
    } else {
        return Err("unsupported HTTP status-line version or spacing");
    };
    let reason = rest
        .strip_prefix(b"200 ")
        .ok_or("status code is not exactly 200 or has invalid spacing")?;
    if reason.iter().any(|&byte| byte < 0x20 || byte == 0x7f) {
        return Err("status reason contains a control byte");
    }
    Ok(())
}

/// Download one HTTP response body subject to `limits`.
///
/// The Fuchsia implementation uses the native asynchronous fdio socket path,
/// because `std::net::TcpStream::connect_timeout` is not supported there. The
/// host implementation exists so the same framing and timeout behavior can be
/// exercised against real TCP peers in unit tests.
pub async fn get(address: &str, path: &str, limits: Limits) -> Result<Vec<u8>> {
    validate_inputs(path, limits)?;
    let socket_addr: SocketAddr = address
        .parse()
        .with_context(|| format!("parse HTTP socket address {address}"))?;
    let request =
        format!("GET {path} HTTP/1.0\r\nHost: {socket_addr}\r\nConnection: close\r\n\r\n");

    #[cfg(target_os = "fuchsia")]
    {
        use fuchsia_async::TimeoutExt as _;

        let deadline = fuchsia_async::MonotonicInstant::after(limits.total_timeout.into());
        get_fuchsia(socket_addr, path, request.as_bytes(), limits)
            .on_timeout(deadline, || {
                Err(anyhow!("HTTP GET {path} overall deadline expired"))
            })
            .await
    }
    #[cfg(not(target_os = "fuchsia"))]
    {
        get_host(socket_addr, path, request.as_bytes(), limits)
    }
}

/// Download one HTTP response body into `writer` without retaining it in RAM.
///
/// The same framing, size, and idle-deadline checks as [`get`] are applied.
/// Bytes are written only after the complete response header has been
/// validated. Callers should treat a writer that received an error as partial
/// and discard it.
pub async fn get_to<W: std::io::Write>(
    address: &str,
    path: &str,
    limits: Limits,
    writer: &mut W,
) -> Result<usize> {
    validate_inputs(path, limits)?;
    let socket_addr: SocketAddr = address
        .parse()
        .with_context(|| format!("parse HTTP socket address {address}"))?;
    let request =
        format!("GET {path} HTTP/1.0\r\nHost: {socket_addr}\r\nConnection: close\r\n\r\n");

    #[cfg(target_os = "fuchsia")]
    {
        use fuchsia_async::TimeoutExt as _;

        let deadline = fuchsia_async::MonotonicInstant::after(limits.total_timeout.into());
        get_to_fuchsia(socket_addr, path, request.as_bytes(), limits, writer)
            .on_timeout(deadline, || {
                Err(anyhow!("HTTP GET {path} overall deadline expired"))
            })
            .await
    }
    #[cfg(not(target_os = "fuchsia"))]
    {
        get_to_host(socket_addr, path, request.as_bytes(), limits, writer)
    }
}

fn validate_inputs(path: &str, limits: Limits) -> Result<()> {
    if !path.starts_with('/') {
        return Err(anyhow!("HTTP request target must start with '/': {path:?}"));
    }
    if path.len() > MAX_REQUEST_TARGET_BYTES {
        return Err(anyhow!(
            "HTTP request target exceeds {MAX_REQUEST_TARGET_BYTES} bytes"
        ));
    }
    if path.bytes().any(|byte| !(0x21..=0x7e).contains(&byte)) {
        return Err(anyhow!(
            "HTTP request target contains whitespace or a control/non-ASCII byte"
        ));
    }
    if limits.max_header_bytes < 4 {
        return Err(anyhow!("HTTP header ceiling must be at least four bytes"));
    }
    if limits.io_timeout.is_zero() {
        return Err(anyhow!("HTTP I/O timeout must be nonzero"));
    }
    if limits.total_timeout.is_zero() {
        return Err(anyhow!("HTTP overall timeout must be nonzero"));
    }
    limits
        .max_header_bytes
        .checked_add(limits.max_body_bytes)
        .ok_or_else(|| anyhow!("HTTP response byte ceiling overflow"))?;
    Ok(())
}

#[cfg(target_os = "fuchsia")]
async fn get_fuchsia(
    socket_addr: SocketAddr,
    path: &str,
    request: &[u8],
    limits: Limits,
) -> Result<Vec<u8>> {
    use fuchsia_async::TimeoutExt as _;
    use futures::io::{AsyncReadExt as _, AsyncWriteExt as _};

    let connecting = fuchsia_async::net::TcpStream::connect(socket_addr)
        .with_context(|| format!("begin connect {socket_addr}"))?;
    let connect_deadline = fuchsia_async::MonotonicInstant::after(limits.io_timeout.into());
    let mut stream = connecting
        .on_timeout(connect_deadline, || {
            Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "connect deadline expired",
            ))
        })
        .await
        .with_context(|| format!("connect {socket_addr}"))?;

    let write_deadline = fuchsia_async::MonotonicInstant::after(limits.io_timeout.into());
    stream
        .write_all(request)
        .on_timeout(write_deadline, || {
            Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "write deadline expired",
            ))
        })
        .await
        .with_context(|| format!("HTTP GET {path} write request"))?;

    let mut response = Response::new(limits);
    let mut chunk = vec![0; READ_CHUNK_BYTES];
    while !response.is_complete() {
        let read_deadline = fuchsia_async::MonotonicInstant::after(limits.io_timeout.into());
        let read = stream
            .read(&mut chunk)
            .on_timeout(read_deadline, || {
                Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "read idle deadline expired",
                ))
            })
            .await
            .with_context(|| format!("HTTP GET {path} read response"))?;
        if read == 0 {
            break;
        }
        response.push(&chunk[..read])?;
    }
    response.finish(path)
}

#[cfg(not(target_os = "fuchsia"))]
fn remaining_host_timeout(started: std::time::Instant, limits: Limits) -> Result<Duration> {
    let remaining = limits
        .total_timeout
        .checked_sub(started.elapsed())
        .filter(|remaining| !remaining.is_zero())
        .ok_or_else(|| anyhow!("HTTP overall deadline expired"))?;
    Ok(remaining.min(limits.io_timeout))
}

#[cfg(not(target_os = "fuchsia"))]
fn get_host(
    socket_addr: SocketAddr,
    path: &str,
    request: &[u8],
    limits: Limits,
) -> Result<Vec<u8>> {
    use std::io::{Read as _, Write as _};

    let started = std::time::Instant::now();
    let mut stream = std::net::TcpStream::connect_timeout(
        &socket_addr,
        remaining_host_timeout(started, limits)?,
    )
    .with_context(|| format!("connect {socket_addr}"))?;
    stream
        .set_write_timeout(Some(remaining_host_timeout(started, limits)?))
        .context("set HTTP write deadline")?;
    stream
        .write_all(request)
        .with_context(|| format!("HTTP GET {path} write request"))?;

    let mut response = Response::new(limits);
    let mut chunk = vec![0; READ_CHUNK_BYTES];
    while !response.is_complete() {
        stream
            .set_read_timeout(Some(remaining_host_timeout(started, limits)?))
            .context("set HTTP read deadline")?;
        let read = stream
            .read(&mut chunk)
            .with_context(|| format!("HTTP GET {path} read response"))?;
        if read == 0 {
            break;
        }
        response.push(&chunk[..read])?;
    }
    response.finish(path)
}

#[cfg(target_os = "fuchsia")]
async fn get_to_fuchsia<W: std::io::Write>(
    socket_addr: SocketAddr,
    path: &str,
    request: &[u8],
    limits: Limits,
    writer: &mut W,
) -> Result<usize> {
    use fuchsia_async::TimeoutExt as _;
    use futures::io::{AsyncReadExt as _, AsyncWriteExt as _};

    let connecting = fuchsia_async::net::TcpStream::connect(socket_addr)
        .with_context(|| format!("begin connect {socket_addr}"))?;
    let connect_deadline = fuchsia_async::MonotonicInstant::after(limits.io_timeout.into());
    let mut stream = connecting
        .on_timeout(connect_deadline, || {
            Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "connect deadline expired",
            ))
        })
        .await
        .with_context(|| format!("connect {socket_addr}"))?;

    let write_deadline = fuchsia_async::MonotonicInstant::after(limits.io_timeout.into());
    stream
        .write_all(request)
        .on_timeout(write_deadline, || {
            Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "write deadline expired",
            ))
        })
        .await
        .with_context(|| format!("HTTP GET {path} write request"))?;

    let mut response = StreamingResponse::new(limits, writer);
    let mut chunk = vec![0; READ_CHUNK_BYTES];
    while !response.is_complete() {
        let read_deadline = fuchsia_async::MonotonicInstant::after(limits.io_timeout.into());
        let read = stream
            .read(&mut chunk)
            .on_timeout(read_deadline, || {
                Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "read idle deadline expired",
                ))
            })
            .await
            .with_context(|| format!("HTTP GET {path} read response"))?;
        if read == 0 {
            break;
        }
        response.push(&chunk[..read])?;
    }
    response.finish(path)
}

#[cfg(not(target_os = "fuchsia"))]
fn get_to_host<W: std::io::Write>(
    socket_addr: SocketAddr,
    path: &str,
    request: &[u8],
    limits: Limits,
    writer: &mut W,
) -> Result<usize> {
    use std::io::{Read as _, Write as _};

    let started = std::time::Instant::now();
    let mut stream = std::net::TcpStream::connect_timeout(
        &socket_addr,
        remaining_host_timeout(started, limits)?,
    )
    .with_context(|| format!("connect {socket_addr}"))?;
    stream
        .set_write_timeout(Some(remaining_host_timeout(started, limits)?))
        .context("set HTTP write deadline")?;
    stream
        .write_all(request)
        .with_context(|| format!("HTTP GET {path} write request"))?;

    let mut response = StreamingResponse::new(limits, writer);
    let mut chunk = vec![0; READ_CHUNK_BYTES];
    while !response.is_complete() {
        stream
            .set_read_timeout(Some(remaining_host_timeout(started, limits)?))
            .context("set HTTP read deadline")?;
        let read = stream
            .read(&mut chunk)
            .with_context(|| format!("HTTP GET {path} read response"))?;
        if read == 0 {
            break;
        }
        response.push(&chunk[..read])?;
    }
    response.finish(path)
}

struct StreamingResponse<'a, W> {
    header: Vec<u8>,
    header_complete: bool,
    content_length: Option<usize>,
    body_len: usize,
    limits: Limits,
    writer: &'a mut W,
}

impl<'a, W: std::io::Write> StreamingResponse<'a, W> {
    fn new(limits: Limits, writer: &'a mut W) -> Self {
        Self {
            header: Vec::new(),
            header_complete: false,
            content_length: None,
            body_len: 0,
            limits,
            writer,
        }
    }

    fn push(&mut self, chunk: &[u8]) -> Result<()> {
        if self.header_complete {
            return self.write_body(chunk);
        }

        if self.header.len().saturating_add(chunk.len())
            > self
                .limits
                .max_header_bytes
                .saturating_add(self.limits.max_body_bytes)
        {
            return Err(anyhow!("HTTP response exceeds its configured byte ceiling"));
        }
        self.header.extend_from_slice(chunk);
        let Some(index) = find_bytes(&self.header, b"\r\n\r\n") else {
            if self.header.len() > self.limits.max_header_bytes {
                return Err(anyhow!(
                    "HTTP response header exceeds {} bytes",
                    self.limits.max_header_bytes
                ));
            }
            return Ok(());
        };

        let header_end = index + 4;
        if header_end > self.limits.max_header_bytes {
            return Err(anyhow!(
                "HTTP response header exceeds {} bytes",
                self.limits.max_header_bytes
            ));
        }
        self.content_length = parse_header(&self.header[..index], self.limits.max_body_bytes)?;
        self.header_complete = true;
        let body = self.header[header_end..].to_vec();
        self.header.clear();
        self.write_body(&body)
    }

    fn write_body(&mut self, bytes: &[u8]) -> Result<()> {
        let next = self
            .body_len
            .checked_add(bytes.len())
            .ok_or_else(|| anyhow!("HTTP response body length overflow"))?;
        if next > self.limits.max_body_bytes {
            return Err(anyhow!(
                "HTTP response body exceeds {} bytes",
                self.limits.max_body_bytes
            ));
        }
        if self.content_length.is_some_and(|expected| next > expected) {
            return Err(anyhow!(
                "HTTP response body is longer than Content-Length {}",
                self.content_length.unwrap()
            ));
        }
        self.writer
            .write_all(bytes)
            .context("write streamed HTTP response body")?;
        self.body_len = next;
        Ok(())
    }

    fn is_complete(&self) -> bool {
        self.header_complete && self.content_length == Some(self.body_len)
    }

    fn finish(self, path: &str) -> Result<usize> {
        if !self.header_complete {
            return Err(anyhow!(
                "HTTP GET {path} response ended before the header terminator"
            ));
        }
        if let Some(expected) = self.content_length {
            if self.body_len != expected {
                return Err(anyhow!(
                    "HTTP GET {path} response ended after {} body bytes; Content-Length is {expected}",
                    self.body_len
                ));
            }
        }
        Ok(self.body_len)
    }
}

struct Response {
    bytes: Vec<u8>,
    header_end: Option<usize>,
    content_length: Option<usize>,
    limits: Limits,
}

impl Response {
    fn new(limits: Limits) -> Self {
        Self {
            bytes: Vec::new(),
            header_end: None,
            content_length: None,
            limits,
        }
    }

    fn push(&mut self, chunk: &[u8]) -> Result<()> {
        let wire_limit = self
            .limits
            .max_header_bytes
            .checked_add(self.limits.max_body_bytes)
            .ok_or_else(|| anyhow!("HTTP response byte ceiling overflow"))?;
        if self.bytes.len().saturating_add(chunk.len()) > wire_limit {
            return Err(anyhow!(
                "HTTP response exceeds the {}-byte header plus {}-byte body ceiling",
                self.limits.max_header_bytes,
                self.limits.max_body_bytes
            ));
        }
        self.bytes.extend_from_slice(chunk);

        if self.header_end.is_none() {
            if let Some(index) = find_bytes(&self.bytes, b"\r\n\r\n") {
                let header_end = index + 4;
                if header_end > self.limits.max_header_bytes {
                    return Err(anyhow!(
                        "HTTP response header exceeds {} bytes",
                        self.limits.max_header_bytes
                    ));
                }
                self.content_length =
                    parse_header(&self.bytes[..index], self.limits.max_body_bytes)?;
                self.header_end = Some(header_end);
            } else if self.bytes.len() > self.limits.max_header_bytes {
                return Err(anyhow!(
                    "HTTP response header exceeds {} bytes",
                    self.limits.max_header_bytes
                ));
            }
        }

        if let Some(header_end) = self.header_end {
            let body_len = self.bytes.len() - header_end;
            if body_len > self.limits.max_body_bytes {
                return Err(anyhow!(
                    "HTTP response body exceeds {} bytes",
                    self.limits.max_body_bytes
                ));
            }
            if let Some(expected) = self.content_length {
                if body_len > expected {
                    return Err(anyhow!(
                        "HTTP response body is longer than Content-Length {expected}"
                    ));
                }
            }
        }
        Ok(())
    }

    fn is_complete(&self) -> bool {
        match (self.header_end, self.content_length) {
            (Some(header_end), Some(expected)) => self.bytes.len() - header_end == expected,
            _ => false,
        }
    }

    fn finish(mut self, path: &str) -> Result<Vec<u8>> {
        let header_end = self.header_end.ok_or_else(|| {
            anyhow!("HTTP GET {path} response ended before the header terminator")
        })?;
        if let Some(expected) = self.content_length {
            let actual = self.bytes.len() - header_end;
            if actual != expected {
                return Err(anyhow!(
                    "HTTP GET {path} response ended after {actual} body bytes; Content-Length is {expected}"
                ));
            }
        }
        self.bytes.drain(..header_end);
        Ok(self.bytes)
    }
}

fn parse_header(header: &[u8], max_body_bytes: usize) -> Result<Option<usize>> {
    // With no response headers, the status line's CRLF is also the first half
    // of the CRLFCRLF terminator and is not present in this slice.
    let status_end = find_bytes(header, b"\r\n").unwrap_or(header.len());
    validate_status_line(&header[..status_end])
        .map_err(|reason| anyhow!("HTTP response is not an exact 200: {reason}"))?;

    let mut content_length = None;
    let mut cursor = if status_end == header.len() {
        header.len()
    } else {
        status_end + 2
    };
    while cursor < header.len() {
        let end = find_bytes(&header[cursor..], b"\r\n")
            .map(|relative| cursor + relative)
            .unwrap_or(header.len());
        let line = &header[cursor..end];
        parse_header_line(line, &mut content_length, max_body_bytes)?;
        if end == header.len() {
            break;
        }
        cursor = end + 2;
    }
    Ok(content_length)
}

fn parse_header_line(
    line: &[u8],
    content_length: &mut Option<usize>,
    max_body_bytes: usize,
) -> Result<()> {
    let colon = line
        .iter()
        .position(|&byte| byte == b':')
        .ok_or_else(|| anyhow!("HTTP response contains a malformed header line"))?;
    let (name, value_with_colon) = line.split_at(colon);
    if name.is_empty() || !name.iter().copied().all(is_header_name_byte) {
        return Err(anyhow!("HTTP response contains an invalid header name"));
    }
    let value = trim_optional_whitespace(&value_with_colon[1..]);
    if value
        .iter()
        .any(|&byte| (byte < 0x20 && byte != b'\t') || byte == 0x7f)
    {
        return Err(anyhow!(
            "HTTP response contains a control byte in a header value"
        ));
    }

    if name.eq_ignore_ascii_case(b"transfer-encoding") {
        return Err(anyhow!("HTTP Transfer-Encoding is not supported"));
    }
    if name.eq_ignore_ascii_case(b"content-length") {
        if content_length.is_some() {
            return Err(anyhow!(
                "HTTP response contains duplicate Content-Length headers"
            ));
        }
        if value.is_empty() || !value.iter().all(u8::is_ascii_digit) {
            return Err(anyhow!("HTTP response has an invalid Content-Length"));
        }
        let mut parsed = 0usize;
        for &digit in value {
            parsed = parsed
                .checked_mul(10)
                .and_then(|number| number.checked_add((digit - b'0') as usize))
                .ok_or_else(|| anyhow!("HTTP Content-Length overflows usize"))?;
        }
        if parsed > max_body_bytes {
            return Err(anyhow!(
                "HTTP response Content-Length {parsed} exceeds the {max_body_bytes}-byte body ceiling"
            ));
        }
        *content_length = Some(parsed);
    }
    Ok(())
}

fn is_header_name_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte)
}

fn trim_optional_whitespace(mut value: &[u8]) -> &[u8] {
    while matches!(value.first(), Some(b' ' | b'\t')) {
        value = &value[1..];
    }
    while matches!(value.last(), Some(b' ' | b'\t')) {
        value = &value[..value.len() - 1];
    }
    value
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::{
        Limits, MAX_STATUS_LINE_BYTES, Response, StreamingResponse, get, validate_status_line,
    };
    use std::io::Write as _;
    use std::net::TcpListener;
    use std::thread;
    use std::time::Duration;

    fn limits(max_header_bytes: usize, max_body_bytes: usize) -> Limits {
        Limits {
            max_header_bytes,
            max_body_bytes,
            io_timeout: Duration::from_millis(75),
            total_timeout: Duration::from_millis(500),
        }
    }

    fn parse(response: &[u8], limits: Limits) -> anyhow::Result<Vec<u8>> {
        let mut parser = Response::new(limits);
        for chunk in response.chunks(3) {
            parser.push(chunk)?;
        }
        parser.finish("/test")
    }

    fn parse_streamed(response: &[u8], limits: Limits) -> anyhow::Result<Vec<u8>> {
        let mut body = Vec::new();
        let mut parser = StreamingResponse::new(limits, &mut body);
        for chunk in response.chunks(3) {
            parser.push(chunk)?;
        }
        let written = parser.finish("/test")?;
        assert_eq!(written, body.len());
        Ok(body)
    }

    #[test]
    fn exact_status_validation_rejects_lookalikes() {
        for line in [b"HTTP/1.0 200 OK".as_slice(), b"HTTP/1.1 200 ".as_slice()] {
            assert!(validate_status_line(line).is_ok(), "{line:?}");
        }
        for line in [
            b"HTTP/1.1 2000 OK".as_slice(),
            b"HTTP/1.1 1200 OK".as_slice(),
            b"HTTP/1.1 0200 OK".as_slice(),
            b"HTTP/1.1 200OK".as_slice(),
            b"prefix HTTP/1.1 200 OK".as_slice(),
        ] {
            assert!(validate_status_line(line).is_err(), "accepted {line:?}");
        }
        let mut oversized = b"HTTP/1.1 200 ".to_vec();
        oversized.extend(std::iter::repeat(b'A').take(MAX_STATUS_LINE_BYTES));
        assert!(validate_status_line(&oversized).is_err());
    }

    #[test]
    fn parser_accepts_declared_and_close_delimited_bodies_incrementally() {
        assert_eq!(
            parse(
                b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello",
                limits(128, 5),
            )
            .unwrap(),
            b"hello"
        );
        assert_eq!(
            parse_streamed(
                b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello",
                limits(128, 5),
            )
            .unwrap(),
            b"hello"
        );
        assert_eq!(
            parse_streamed(
                b"HTTP/1.0 200 OK\r\nConnection: close\r\n\r\nhello",
                limits(128, 5),
            )
            .unwrap(),
            b"hello"
        );
        assert_eq!(
            parse(
                b"HTTP/1.0 200 OK\r\nConnection: close\r\n\r\nhello",
                limits(128, 5)
            )
            .unwrap(),
            b"hello"
        );
    }

    #[test]
    fn malformed_framing_is_rejected() {
        for response in [
            b"HTTP/1.1 200 OK\nContent-Length: 0\n\n".as_slice(),
            b"HTTP/1.1 200 OK\r\nnot-a-header\r\n\r\n".as_slice(),
            b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\nx".as_slice(),
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n".as_slice(),
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nx".as_slice(),
        ] {
            assert!(
                parse(response, limits(256, 32)).is_err(),
                "accepted {response:?}"
            );
        }
    }

    #[test]
    fn header_and_body_ceilings_are_enforced_before_eof() {
        let long_header = format!("HTTP/1.1 200 OK\r\nX: {}\r\n\r\n", "a".repeat(100));
        assert!(parse(long_header.as_bytes(), limits(32, 256)).is_err());

        let declared_oversize = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n";
        assert!(parse(declared_oversize, limits(128, 4)).is_err());

        let streamed_oversize = b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n12345";
        assert!(parse(streamed_oversize, limits(128, 4)).is_err());
        assert!(parse_streamed(streamed_oversize, limits(128, 4)).is_err());
    }

    #[test]
    fn real_tcp_read_stall_hits_idle_deadline() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\n")
                .unwrap();
            stream.flush().unwrap();
            thread::sleep(Duration::from_millis(250));
        });

        let error =
            futures::executor::block_on(get(&address.to_string(), "/stall", limits(128, 8)))
                .unwrap_err();
        let message = format!("{error:#}");
        assert!(
            message.contains("timed out") || message.contains("temporarily unavailable"),
            "unexpected stall error: {message}"
        );
        server.join().unwrap();
    }

    #[test]
    fn real_tcp_slow_trickle_hits_overall_deadline() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\n")
                .unwrap();
            for byte in b"12345678" {
                if stream.write_all(&[*byte]).is_err() {
                    break;
                }
                let _ = stream.flush();
                thread::sleep(Duration::from_millis(40));
            }
        });

        let mut request_limits = limits(128, 8);
        request_limits.io_timeout = Duration::from_millis(100);
        request_limits.total_timeout = Duration::from_millis(130);
        let error =
            futures::executor::block_on(get(&address.to_string(), "/slow-trickle", request_limits))
                .unwrap_err();
        let message = format!("{error:#}");
        assert!(
            message.contains("deadline")
                || message.contains("timed out")
                || message.contains("temporarily unavailable"),
            "unexpected total-deadline error: {message}"
        );
        server.join().unwrap();
    }

    #[test]
    fn request_target_cannot_inject_another_header() {
        let error =
            futures::executor::block_on(get("127.0.0.1:9", "/ok\r\nX-Evil: yes", limits(128, 8)))
                .unwrap_err();
        assert!(error.to_string().contains("whitespace or a control"));
    }
}

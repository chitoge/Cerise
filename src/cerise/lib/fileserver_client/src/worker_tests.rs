//! Tests for the driver, against a fake file server that captures the wire.
//!
//! # Why this exists separately from the assembler tests
//!
//! `RangeAssembler`'s tests decide what a *reply* may look like. They say
//! nothing about the *request*. A client that sends the wrong path, or an
//! offset short by one page,
//! and then seeds the assembler with the same wrong request, satisfies every
//! assembler assertion and every assertion a consumer can make against a fake
//! `RangeReader`. Both halves agree, and both are wrong. Nothing above this
//! layer can see it, because above this layer the request never existed.
//!
//! So the fake here is not a fake `RangeReader` — it is a fake **service**,
//! sitting where `hyper` would, receiving whatever `tonic` actually serialised.
//! It decodes the `ReadRequest` off the wire and the tests assert on its
//! fields.
//!
//! It stops short of a socket deliberately. Framing, HPACK and flow control are
//! `hyper`'s and `h2`'s, they are the same code on the host and the target, and
//! putting a loopback connection in the middle would test them instead of this
//! — while making the request log harder to read, not easier.

use std::collections::VecDeque;
use std::future::Future as _;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::Mutex;
use std::task::Context;
use std::task::Poll;
use std::time::Duration;

use bytes::Bytes;
use futures::executor::block_on;

use fileserver_proto::cerise::fileserver::v1 as pb;

use crate::FileMutator;
use crate::RangeReader;

// ── a canned response body ────────────────────────────────────────────────

/// An `http_body::Body` that replays a fixed list of frames.
///
/// Hand-rolled rather than assembled out of combinators because a gRPC reply
/// needs *trailers* — the `grpc-status` that says whether the call succeeded —
/// and control over exactly where the data frames are split is the whole point
/// of several of these tests.
struct Canned {
    frames: VecDeque<Result<http_body::Frame<Bytes>, io::Error>>,
    pending_at_end: bool,
    delay_each: Option<Duration>,
    delay_before_next: Option<Pin<Box<futures_timer::Delay>>>,
}

impl http_body::Body for Canned {
    type Data = Bytes;
    type Error = io::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<http_body::Frame<Bytes>, io::Error>>> {
        if !self.frames.is_empty() {
            if let Some(delay) = self.delay_each {
                let timer = self
                    .delay_before_next
                    .get_or_insert_with(|| Box::pin(futures_timer::Delay::new(delay)));
                if timer.as_mut().poll(cx).is_pending() {
                    return Poll::Pending;
                }
                self.delay_before_next = None;
            }
        }
        match self.frames.pop_front() {
            Some(frame) => Poll::Ready(Some(frame)),
            None if self.pending_at_end => Poll::Pending,
            None => Poll::Ready(None),
        }
    }
}

/// Wraps `msg` in one gRPC length-prefixed frame: a compression flag and a
/// big-endian length, which is the framing the codec on the other side expects.
fn grpc_frame<M: prost::Message>(msg: &M) -> Vec<u8> {
    let body = msg.encode_to_vec();
    let mut out = Vec::with_capacity(5 + body.len());
    out.push(0);
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(&body);
    out
}

fn ok_trailers() -> http::HeaderMap {
    let mut t = http::HeaderMap::new();
    t.insert("grpc-status", http::HeaderValue::from_static("0"));
    t
}

fn err_trailers(code: u8, msg: &str) -> http::HeaderMap {
    let mut t = http::HeaderMap::new();
    t.insert(
        "grpc-status",
        http::HeaderValue::from_str(&code.to_string()).unwrap(),
    );
    t.insert("grpc-message", http::HeaderValue::from_str(msg).unwrap());
    t
}

fn response(frames: Vec<http_body::Frame<Bytes>>) -> http::Response<Canned> {
    http::Response::builder()
        .status(200)
        .header("content-type", "application/grpc")
        .body(Canned {
            frames: frames.into_iter().map(Ok).collect(),
            pending_at_end: false,
            delay_each: None,
            delay_before_next: None,
        })
        .unwrap()
}

fn delayed_response(
    frames: Vec<http_body::Frame<Bytes>>,
    delay_each: Duration,
) -> http::Response<Canned> {
    http::Response::builder()
        .status(200)
        .header("content-type", "application/grpc")
        .body(Canned {
            frames: frames.into_iter().map(Ok).collect(),
            pending_at_end: false,
            delay_each: Some(delay_each),
            delay_before_next: None,
        })
        .unwrap()
}

fn pending_stream_response() -> http::Response<Canned> {
    http::Response::builder()
        .status(200)
        .header("content-type", "application/grpc")
        .body(Canned {
            frames: VecDeque::new(),
            pending_at_end: true,
            delay_each: None,
            delay_before_next: None,
        })
        .unwrap()
}

// ── the fake server ───────────────────────────────────────────────────────

/// What the fake answers with.
enum Reply {
    /// Never produce response headers. This is the shape of a half-open local
    /// HTTP/2 stream that used to own the serial request driver forever.
    Never,
    /// Produce response headers, then never deliver a message or trailers.
    NeverStream,
    /// One `ReadChunk` per `(offset, bytes)`, then `grpc-status: 0`.
    Chunks(Vec<(u64, Vec<u8>)>),
    /// A `StatResponse` carrying this size.
    Size(u64),
    /// Directory entries followed by a successful terminal status.
    Entries(Vec<pb::DirEntry>),
    /// Directory entries and terminal status, each delayed independently.
    DelayedEntries(Vec<pb::DirEntry>, Duration),
    /// A successful unary mutation response.
    Write(u64),
    BeginImport(pb::BeginImageImportResponse),
    AcceptedImport(u64),
    DurableImport(u64),
    CommittedImport(pb::CommitImageImportResponse),
    Empty,
    /// Data frames, then a failing status — a stream that dies partway.
    ChunksThenStatus(Vec<(u64, Vec<u8>)>, u8, String),
    /// Data frames followed by an HTTP body error: transport loss, not a
    /// decoded application status.
    ChunksThenBodyError(Vec<(u64, Vec<u8>)>),
}

/// Everything the client actually put on the wire.
#[derive(Debug, Clone, PartialEq)]
struct Seen {
    path_and_query: String,
    read: Option<pb::ReadRequest>,
    stat: Option<pb::StatRequest>,
    list: Option<pb::ListRequest>,
    write: Option<pb::WriteRequest>,
    mkdir: Option<pb::MkdirRequest>,
    rename: Option<pb::RenameRequest>,
    begin_import: Option<pb::BeginImageImportRequest>,
    write_import: Option<pb::WriteImageImportRequest>,
    flush_import: Option<pb::FlushImageImportRequest>,
    commit_import: Option<pb::CommitImageImportRequest>,
    abort_import: Option<pb::AbortImageImportRequest>,
}

/// A `tower` service standing where the HTTP/2 connection would be.
#[derive(Clone)]
struct FakeServer {
    seen: Arc<Mutex<Vec<Seen>>>,
    replies: Arc<Mutex<VecDeque<Reply>>>,
}

impl FakeServer {
    fn new(replies: Vec<Reply>) -> Self {
        FakeServer {
            seen: Arc::new(Mutex::new(Vec::new())),
            replies: Arc::new(Mutex::new(replies.into())),
        }
    }
}

/// Strips the gRPC length prefix and decodes one message.
fn decode<M: prost::Message + Default>(body: &[u8]) -> M {
    assert!(
        body.len() >= 5,
        "a gRPC message needs a 5-byte prefix, got {}",
        body.len()
    );
    assert_eq!(body[0], 0, "this client must not request compression");
    let len = u32::from_be_bytes(body[1..5].try_into().unwrap()) as usize;
    assert_eq!(body.len(), 5 + len, "the frame length must match the body");
    M::decode(&body[5..]).expect("a well-formed message")
}

impl tower::Service<http::Request<tonic::body::BoxBody>> for FakeServer {
    type Response = http::Response<Canned>;
    type Error = std::convert::Infallible;
    type Future = Pin<Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>>>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: http::Request<tonic::body::BoxBody>) -> Self::Future {
        let seen = self.seen.clone();
        let replies = self.replies.clone();
        Box::pin(async move {
            let path = req.uri().path().to_owned();
            let body = {
                use http_body_util::BodyExt as _;
                req.into_body().collect().await.expect("a body").to_bytes()
            };
            let mut record = Seen {
                path_and_query: path.clone(),
                read: None,
                stat: None,
                list: None,
                write: None,
                mkdir: None,
                rename: None,
                begin_import: None,
                write_import: None,
                flush_import: None,
                commit_import: None,
                abort_import: None,
            };
            if path.ends_with("/Read") {
                record.read = Some(decode::<pb::ReadRequest>(&body));
            } else if path.ends_with("/Stat") {
                record.stat = Some(decode::<pb::StatRequest>(&body));
            } else if path.ends_with("/List") {
                record.list = Some(decode::<pb::ListRequest>(&body));
            } else if path.ends_with("/Write") {
                record.write = Some(decode::<pb::WriteRequest>(&body));
            } else if path.ends_with("/Mkdir") {
                record.mkdir = Some(decode::<pb::MkdirRequest>(&body));
            } else if path.ends_with("/Rename") {
                record.rename = Some(decode::<pb::RenameRequest>(&body));
            } else if path.ends_with("/BeginImageImport") {
                record.begin_import = Some(decode::<pb::BeginImageImportRequest>(&body));
            } else if path.ends_with("/WriteImageImport") {
                record.write_import = Some(decode::<pb::WriteImageImportRequest>(&body));
            } else if path.ends_with("/FlushImageImport") {
                record.flush_import = Some(decode::<pb::FlushImageImportRequest>(&body));
            } else if path.ends_with("/CommitImageImport") {
                record.commit_import = Some(decode::<pb::CommitImageImportRequest>(&body));
            } else if path.ends_with("/AbortImageImport") {
                record.abort_import = Some(decode::<pb::AbortImageImportRequest>(&body));
            }
            seen.lock().unwrap().push(record);

            let reply = replies
                .lock()
                .unwrap()
                .pop_front()
                .expect("the fake was asked for more replies than it was given");
            let frames =
                match reply {
                    Reply::Never => return futures::future::pending().await,
                    Reply::NeverStream => return Ok(pending_stream_response()),
                    Reply::Chunks(cs) => {
                        let mut f: Vec<_> =
                            cs.into_iter()
                                .map(|(offset, data)| {
                                    http_body::Frame::data(Bytes::from(grpc_frame(
                                        &pb::ReadChunk { data, offset },
                                    )))
                                })
                                .collect();
                        f.push(http_body::Frame::trailers(ok_trailers()));
                        f
                    }
                    Reply::Size(size) => vec![
                        http_body::Frame::data(Bytes::from(grpc_frame(&pb::StatResponse {
                            r#type: 1,
                            size,
                            mtime_unix_nanos: 0,
                            mode: 0o444,
                        }))),
                        http_body::Frame::trailers(ok_trailers()),
                    ],
                    Reply::Entries(entries) => {
                        let mut frames = entries
                            .into_iter()
                            .map(|entry| http_body::Frame::data(Bytes::from(grpc_frame(&entry))))
                            .collect::<Vec<_>>();
                        frames.push(http_body::Frame::trailers(ok_trailers()));
                        frames
                    }
                    Reply::DelayedEntries(entries, delay_each) => {
                        let mut frames = entries
                            .into_iter()
                            .map(|entry| http_body::Frame::data(Bytes::from(grpc_frame(&entry))))
                            .collect::<Vec<_>>();
                        frames.push(http_body::Frame::trailers(ok_trailers()));
                        return Ok(delayed_response(frames, delay_each));
                    }
                    Reply::Write(bytes_written) => vec![
                        http_body::Frame::data(Bytes::from(grpc_frame(&pb::WriteResponse {
                            bytes_written,
                        }))),
                        http_body::Frame::trailers(ok_trailers()),
                    ],
                    Reply::BeginImport(value) => vec![
                        http_body::Frame::data(Bytes::from(grpc_frame(&value))),
                        http_body::Frame::trailers(ok_trailers()),
                    ],
                    Reply::AcceptedImport(accepted_offset) => vec![
                        http_body::Frame::data(Bytes::from(grpc_frame(
                            &pb::WriteImageImportResponse { accepted_offset },
                        ))),
                        http_body::Frame::trailers(ok_trailers()),
                    ],
                    Reply::DurableImport(durable_offset) => vec![
                        http_body::Frame::data(Bytes::from(grpc_frame(
                            &pb::FlushImageImportResponse { durable_offset },
                        ))),
                        http_body::Frame::trailers(ok_trailers()),
                    ],
                    Reply::CommittedImport(value) => vec![
                        http_body::Frame::data(Bytes::from(grpc_frame(&value))),
                        http_body::Frame::trailers(ok_trailers()),
                    ],
                    Reply::Empty => vec![
                        http_body::Frame::data(Bytes::from(grpc_frame(&pb::MkdirResponse {}))),
                        http_body::Frame::trailers(ok_trailers()),
                    ],
                    Reply::ChunksThenStatus(cs, code, msg) => {
                        let mut f: Vec<_> =
                            cs.into_iter()
                                .map(|(offset, data)| {
                                    http_body::Frame::data(Bytes::from(grpc_frame(
                                        &pb::ReadChunk { data, offset },
                                    )))
                                })
                                .collect();
                        f.push(http_body::Frame::trailers(err_trailers(code, &msg)));
                        f
                    }
                    Reply::ChunksThenBodyError(cs) => {
                        let mut frames: VecDeque<_> = cs
                            .into_iter()
                            .map(|(offset, data)| {
                                Ok(http_body::Frame::data(Bytes::from(grpc_frame(
                                    &pb::ReadChunk { data, offset },
                                ))))
                            })
                            .collect();
                        frames.push_back(Err(io::Error::new(
                            io::ErrorKind::ConnectionReset,
                            "injected response-body transport loss",
                        )));
                        return Ok(http::Response::builder()
                            .status(200)
                            .header("content-type", "application/grpc")
                            .body(Canned {
                                frames,
                                pending_at_end: false,
                                delay_each: None,
                                delay_before_next: None,
                            })
                            .unwrap());
                    }
                };
            Ok(response(frames))
        })
    }
}

// ── the harness ───────────────────────────────────────────────────────────

/// Runs `work` against a fake server, driving the connection alongside it.
///
/// The driver ends when the last handle is dropped, which `work` does by
/// consuming its own clone — so this returns rather than hanging.
fn against<T, F>(replies: Vec<Reply>, work: F) -> (T, Vec<Seen>)
where
    F: FnOnce(crate::FileServerHandle) -> futures::future::LocalBoxFuture<'static, T>,
{
    let fake = FakeServer::new(replies);
    let seen = fake.seen.clone();
    let client = pb::file_server_client::FileServerClient::new(fake);
    let (handle, rx) = crate::channel();
    let driver = crate::serve(client, rx);
    let job = work(handle);
    let (out, ()) = block_on(futures::future::join(job, driver));
    let seen = seen.lock().unwrap().clone();
    (out, seen)
}

/// The one-call shape every test below uses: issue a request, then drop the
/// handle so the driver stops.
fn one<T: 'static>(
    replies: Vec<Reply>,
    f: impl FnOnce(crate::FileServerHandle) -> futures::future::LocalBoxFuture<'static, T> + 'static,
) -> (T, Vec<Seen>) {
    against(replies, f)
}

fn pattern(from: u64, n: usize) -> Vec<u8> {
    (0..n)
        .map(|i| ((from as usize + i) * 31 + 7) as u8)
        .collect()
}

fn directory_entry(name: &str) -> pb::DirEntry {
    pb::DirEntry {
        name: name.to_owned(),
        r#type: pb::FileType::File as i32,
        size: 1,
    }
}

// ── what goes on the wire ─────────────────────────────────────────────────

/// The request the client sends is the request the caller asked for: same
/// path, same offset, same length, and the right RPC.
///
/// This is the assertion that closes the "both halves agree and both are wrong"
/// hole. A client that shifted the offset by a page, or reached for a different
/// file, would satisfy every other test in this crate and every test written
/// against a fake `RangeReader`, because both of those check the reply against
/// the *client's own* idea of what it asked for. Only the wire knows.
#[test]
fn the_request_carries_the_callers_path_offset_and_length() {
    let want = pattern(8192, 4096);
    let body = want.clone();
    let (got, seen) = one(vec![Reply::Chunks(vec![(8192, body)])], move |h| {
        Box::pin(async move { h.read_range("images/guest.img", 8192, 4096).await })
    });
    assert_eq!(got.expect("read"), want);
    assert_eq!(seen.len(), 1);
    assert_eq!(
        seen[0].path_and_query,
        "/cerise.fileserver.v1.FileServer/Read"
    );
    assert_eq!(
        seen[0].read,
        Some(pb::ReadRequest {
            path: "images/guest.img".into(),
            offset: 8192,
            length: 4096,
        }),
    );
}

/// A logical read larger than the server's 16 MiB operational ceiling is
/// transported as consecutive bounded RPCs and reassembled byte-exactly.
///
/// This is the shape of a large Cryostore index.  Testing above the server
/// ceiling, rather than merely above the client's smaller chunk size, prevents
/// the original invalid one-shot request from returning unnoticed.
#[test]
fn a_read_larger_than_the_server_limit_is_split_and_reassembled() {
    const SERVER_READ_LIMIT: usize = 16 * 1024 * 1024;
    let base = 123u64;
    let len = SERVER_READ_LIMIT + 17;
    let whole = pattern(base, len);
    let mut replies = Vec::new();
    let mut at = 0usize;
    while at < whole.len() {
        let end = (at + crate::FILESERVER_IO_CHUNK_BYTES).min(whole.len());
        replies.push(Reply::Chunks(vec![(
            base + at as u64,
            whole[at..end].to_vec(),
        )]));
        at = end;
    }
    let want = whole.clone();
    let (got, seen) = one(replies, move |h| {
        Box::pin(async move {
            h.read_range("images/win10.cryostore", base, len as u64)
                .await
        })
    });
    assert_eq!(got.expect("large read"), want);
    assert_eq!(seen.len(), len.div_ceil(crate::FILESERVER_IO_CHUNK_BYTES));
    for (index, request) in seen.iter().enumerate() {
        let request = request.read.as_ref().expect("Read request");
        let expected_offset = base + (index * crate::FILESERVER_IO_CHUNK_BYTES) as u64;
        assert_eq!(request.path, "images/win10.cryostore");
        assert_eq!(request.offset, expected_offset);
        assert_eq!(
            request.length,
            ((base + len as u64) - expected_offset).min(crate::FILESERVER_IO_CHUNK_BYTES as u64)
        );
    }
}

/// The wire requires a positive bounded range, so a zero-length read must send
/// nothing at all rather than make an invalid request.
///
/// The caller already has the complete answer locally.
#[test]
fn a_zero_length_read_sends_no_request() {
    let (got, seen) = one(vec![], move |h| {
        Box::pin(async move { h.read_range("images/guest.img", 40, 0).await })
    });
    assert!(got.expect("read").is_empty());
    assert!(seen.is_empty(), "nothing may go on the wire: {seen:?}");
}

/// `size_of` is a `Stat`, and it names the same path.
#[test]
fn size_of_stats_the_path() {
    let (got, seen) = one(vec![Reply::Size(514_899_956)], move |h| {
        Box::pin(async move { h.size_of("images/guest.img").await })
    });
    assert_eq!(got.expect("stat"), 514_899_956);
    assert_eq!(
        seen[0].path_and_query,
        "/cerise.fileserver.v1.FileServer/Stat"
    );
    assert_eq!(
        seen[0].stat,
        Some(pb::StatRequest {
            path: "images/guest.img".into()
        })
    );
}

#[test]
fn bounded_list_sends_its_limit_and_rejects_max_plus_one() {
    let (result, seen) = one(
        vec![Reply::Entries(vec![
            directory_entry("a"),
            directory_entry("b"),
            directory_entry("c"),
        ])],
        move |handle| Box::pin(async move { handle.list_bounded("objects", 2).await }),
    );
    let error = result.expect_err("an older server may ignore the additive limit field");
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert!(error
        .to_string()
        .contains("more than the requested 2 entries"));
    assert_eq!(seen.len(), 1);
    assert_eq!(
        seen[0].path_and_query,
        "/cerise.fileserver.v1.FileServer/List"
    );
    assert_eq!(
        seen[0].list,
        Some(pb::ListRequest {
            path: "objects".to_owned(),
            max_entries: 2,
        })
    );
}

#[test]
fn list_without_a_limit_preserves_the_original_wire_contract() {
    let (result, seen) = one(
        vec![Reply::Entries(vec![
            directory_entry("a"),
            directory_entry("b"),
            directory_entry("c"),
        ])],
        move |handle| Box::pin(async move { handle.list("objects").await }),
    );
    assert_eq!(result.unwrap().len(), 3);
    assert_eq!(
        seen[0].list,
        Some(pb::ListRequest {
            path: "objects".to_owned(),
            max_entries: 0,
        })
    );
}

#[test]
fn bounded_list_rejects_zero_before_sending_a_request() {
    let (result, seen) = one(vec![], move |handle| {
        Box::pin(async move { handle.list_bounded("objects", 0).await })
    });
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidInput);
    assert!(seen.is_empty());
}

#[test]
fn list_uses_one_deadline_across_the_entire_stream() {
    let fake = FakeServer::new(vec![
        Reply::DelayedEntries(
            vec![directory_entry("a"), directory_entry("b")],
            Duration::from_millis(60),
        ),
        Reply::Entries(vec![directory_entry("after")]),
    ]);
    let seen = fake.seen.clone();
    let client = pb::file_server_client::FileServerClient::new(fake);
    let (handle, rx) = crate::channel();
    let driver = crate::worker::serve_with_timeouts(
        client,
        rx,
        Duration::from_millis(100),
        Duration::from_millis(100),
    );
    let job = async move {
        let error = handle
            .list_bounded("objects", 2)
            .await
            .expect_err("per-entry progress must not renew the List deadline");
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(crate::is_transport_loss(&error));
        assert_eq!(
            handle
                .list("after")
                .await
                .expect("the driver remains usable after the expired List")
                .len(),
            1
        );
    };
    let ((), ()) = block_on(futures::future::join(job, driver));
    assert_eq!(seen.lock().unwrap().len(), 2);
}

#[test]
fn mutations_preserve_all_fields_on_the_wire() {
    let (result, seen) = against(
        vec![Reply::Write(4), Reply::Empty, Reply::Empty],
        move |h| {
            Box::pin(async move {
                h.write_range("vm-heads/vm.head", 8192, vec![1, 2, 3, 4], true, false)
                    .await?;
                h.mkdir("vm-heads", true).await?;
                h.rename("vm-heads/old", "vm-heads/new").await
            })
        },
    );
    result.expect("mutations");
    assert_eq!(
        seen[0].write,
        Some(pb::WriteRequest {
            path: "vm-heads/vm.head".into(),
            offset: 8192,
            data: vec![1, 2, 3, 4],
            create: true,
            truncate: false,
            durability: pb::WriteDurability::Unspecified as i32,
            mutation_context: None,
        })
    );
    assert_eq!(
        seen[1].mkdir,
        Some(pb::MkdirRequest {
            path: "vm-heads".into(),
            parents: true,
            mutation_context: None,
        })
    );
    assert_eq!(
        seen[2].rename,
        Some(pb::RenameRequest {
            from: "vm-heads/old".into(),
            to: "vm-heads/new".into(),
            mutation_context: None,
        })
    );
}

#[test]
fn source_bound_mutation_carries_the_exact_identity_on_the_wire() {
    let source = crate::MutationSourceIdentity {
        authority_domain_id: "ab".repeat(32),
        boot_id: 11,
        generation: 29,
        principal_id: "writer-a".to_owned(),
    };
    let expected = source.clone();
    let (result, seen) = one(vec![Reply::Write(3)], move |handle| {
        let source = source.clone();
        Box::pin(async move {
            handle
                .with_mutation_source(source)?
                .write_range("state/value.tmp", 4, vec![1, 2, 3], true, false)
                .await
        })
    });
    result.expect("source-bound write");
    let context = seen[0]
        .write
        .as_ref()
        .and_then(|request| request.mutation_context.as_ref())
        .expect("source context");
    let Some(pb::mutation_context::Actor::Source(actual)) = context.actor.as_ref() else {
        panic!("source actor");
    };
    assert_eq!(
        actual,
        &pb::MutationSourceIdentity {
            authority_domain_id: expected.authority_domain_id,
            boot_id: expected.boot_id,
            generation: expected.generation,
            principal_id: expected.principal_id,
        }
    );
}

#[test]
fn mutation_source_wire_responses_are_strictly_bound_and_canonical() {
    use crate::worker::{
        decode_compaction_response, decode_legacy_seal_response, decode_mutation_source_receipt,
        drain_receipt_digest, ReceiptRequestBinding,
    };

    let source = crate::MutationSourceIdentity {
        authority_domain_id: "ab".repeat(32),
        boot_id: 11,
        generation: 29,
        principal_id: "writer-a".to_owned(),
    };
    let pb_source = || pb::MutationSourceIdentity {
        authority_domain_id: source.authority_domain_id.clone(),
        boot_id: source.boot_id,
        generation: source.generation,
        principal_id: source.principal_id.clone(),
    };
    let valid = || pb::MutationSourceReceipt {
        source: Some(pb_source()),
        open_request_id: "open-1".to_owned(),
        drain_request_id: "drain-1".to_owned(),
        phase: pb::MutationSourcePhase::Drained as i32,
        receipt_sha256: drain_receipt_digest(&source, "open-1", "drain-1"),
        ledger_revision: 7,
        request_id: "drain-1".to_owned(),
        closed_generation_floor: 0,
    };
    assert!(decode_mutation_source_receipt(
        "DrainMutationSource",
        Some(valid()),
        &source,
        "drain-1",
        ReceiptRequestBinding::Drain,
    )
    .is_ok());

    let mut wrong_source = valid();
    wrong_source.source.as_mut().unwrap().generation += 1;
    let mut wrong_request = valid();
    wrong_request.request_id = "other".to_owned();
    let mut wrong_digest = valid();
    wrong_digest.receipt_sha256 = "0".repeat(64);
    let mut zero_revision = valid();
    zero_revision.ledger_revision = 0;
    let mut over_bound = valid();
    over_bound.open_request_id = "x".repeat(129);
    for invalid in [
        wrong_source,
        wrong_request,
        wrong_digest,
        zero_revision,
        over_bound,
    ] {
        assert!(decode_mutation_source_receipt(
            "DrainMutationSource",
            Some(invalid),
            &source,
            "drain-1",
            ReceiptRequestBinding::Drain,
        )
        .is_err());
    }

    let retired = pb::MutationSourceReceipt {
        source: Some(pb_source()),
        open_request_id: String::new(),
        drain_request_id: String::new(),
        phase: pb::MutationSourcePhase::Retired as i32,
        receipt_sha256: String::new(),
        ledger_revision: 9,
        request_id: "query-retired".to_owned(),
        closed_generation_floor: source.generation,
    };
    assert!(decode_mutation_source_receipt(
        "GetMutationSource",
        Some(retired.clone()),
        &source,
        "query-retired",
        ReceiptRequestBinding::Either,
    )
    .is_ok());
    let mut uncovered = retired;
    uncovered.closed_generation_floor = source.generation - 1;
    assert!(decode_mutation_source_receipt(
        "GetMutationSource",
        Some(uncovered),
        &source,
        "query-retired",
        ReceiptRequestBinding::Either,
    )
    .is_err());

    let compaction = pb::CompactMutationSourcesResponse {
        closed_through_generation: 29,
        ledger_revision: 10,
        authority_domain_id: source.authority_domain_id.clone(),
        request_id: "compact-1".to_owned(),
    };
    assert!(decode_compaction_response(
        "CompactMutationSources",
        compaction.clone(),
        &source.authority_domain_id,
        29,
        "compact-1",
    )
    .is_ok());
    let mut wrong_floor = compaction;
    wrong_floor.closed_through_generation = 28;
    assert!(decode_compaction_response(
        "CompactMutationSources",
        wrong_floor,
        &source.authority_domain_id,
        29,
        "compact-1",
    )
    .is_err());

    assert!(decode_legacy_seal_response(
        pb::SealLegacyMutationAdmissionResponse {
            ledger_revision: 11,
            request_id: "seal-1".to_owned(),
        },
        "seal-1",
    )
    .is_ok());
    assert!(decode_legacy_seal_response(
        pb::SealLegacyMutationAdmissionResponse {
            ledger_revision: 0,
            request_id: "seal-1".to_owned(),
        },
        "seal-1",
    )
    .is_err());
}

#[test]
fn lazy_staging_write_is_explicit_on_the_wire() {
    let (result, seen) = one(vec![Reply::Write(3)], move |h| {
        Box::pin(async move {
            h.write_range_lazy(
                "vm-state/v1/objects/value.tmp",
                0,
                vec![1, 2, 3],
                true,
                true,
            )
            .await
        })
    });
    result.expect("lazy write");
    assert_eq!(
        seen[0].write,
        Some(pb::WriteRequest {
            path: "vm-state/v1/objects/value.tmp".into(),
            offset: 0,
            data: vec![1, 2, 3],
            create: true,
            truncate: true,
            durability: pb::WriteDurability::Lazy as i32,
            mutation_context: None,
        })
    );
}

#[test]
fn image_import_driver_preserves_resume_and_verified_publication_fields() {
    let digest = "a".repeat(64);
    let root = "b".repeat(64);
    let replies = vec![
        Reply::BeginImport(pb::BeginImageImportResponse {
            import_id: "upload-1".into(),
            accepted_offset: 4,
            durable_offset: 2,
        }),
        Reply::AcceptedImport(8),
        Reply::DurableImport(8),
        Reply::CommittedImport(pb::CommitImageImportResponse {
            path: "vm-images/v1/sha256/value.cryostore".into(),
            sha256: digest.clone(),
            encoded_bytes: 8,
            cryostore_root_hash: root.clone(),
            guest_disk_bytes: 4096,
            format_version: 1,
        }),
        Reply::Empty,
    ];
    let expected_digest = digest.clone();
    let (result, seen) = against(replies, move |handle| {
        Box::pin(async move {
            let begin = handle
                .begin_image_import("upload-1", 8, &expected_digest)
                .await?;
            let accepted = handle
                .write_image_import("upload-1", begin.accepted_offset, vec![5, 6, 7, 8])
                .await?;
            let durable = handle.flush_image_import("upload-1").await?;
            let verified = handle
                .commit_image_import("upload-1", &expected_digest)
                .await?;
            handle.abort_image_import("upload-1").await?;
            Ok::<_, io::Error>((begin, accepted, durable, verified))
        })
    });
    let (begin, accepted, durable, verified) = result.expect("image import sequence");
    assert_eq!(begin.accepted_offset, 4);
    assert_eq!(accepted, 8);
    assert_eq!(durable, 8);
    assert_eq!(verified.sha256, digest);
    assert_eq!(verified.cryostore_root_hash, root);
    assert_eq!(
        seen[0].begin_import,
        Some(pb::BeginImageImportRequest {
            import_id: "upload-1".into(),
            expected_sha256: "a".repeat(64),
            expected_size: 8,
        })
    );
    assert_eq!(seen[1].write_import.as_ref().unwrap().offset, 4);
    assert_eq!(seen[1].write_import.as_ref().unwrap().data, [5, 6, 7, 8]);
    assert_eq!(seen[2].flush_import.as_ref().unwrap().import_id, "upload-1");
    assert_eq!(
        seen[3].commit_import.as_ref().unwrap().expected_sha256,
        "a".repeat(64)
    );
    assert_eq!(seen[4].abort_import.as_ref().unwrap().import_id, "upload-1");
}

/// A transport stream that never answers is a finite failure, and dropping
/// that stream does not poison the serial request driver for the next call.
///
/// Spill I/O holds its state lock while a backing request is in flight. Before
/// this deadline existed, the first call below prevented both the second call
/// and every VM pause/stop durability barrier from ever completing.
#[test]
fn unanswered_rpc_times_out_and_the_driver_serves_the_next_request() {
    let fake = FakeServer::new(vec![Reply::Never, Reply::Write(1)]);
    let seen = fake.seen.clone();
    let client = pb::file_server_client::FileServerClient::new(fake);
    let (handle, rx) = crate::channel();
    let driver = crate::worker::serve_with_timeouts(
        client,
        rx,
        Duration::from_millis(10),
        Duration::from_millis(10),
    );
    let job = async move {
        let first = handle
            .write_range_lazy("vm-swap/v2/boot/worker/disk.swap", 0, vec![1], true, false)
            .await;
        let error = first.expect_err("hung RPC must fail");
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(crate::is_transport_loss(&error));
        handle
            .write_range_lazy("vm-swap/v2/boot/worker/disk.swap", 1, vec![2], false, false)
            .await
            .expect("driver remains usable after a timed-out stream");
    };
    let ((), ()) = block_on(futures::future::join(job, driver));
    assert_eq!(seen.lock().unwrap().len(), 2);
}

#[test]
fn unanswered_stream_body_times_out_and_the_driver_serves_the_next_request() {
    let fake = FakeServer::new(vec![Reply::NeverStream, Reply::Chunks(vec![(0, vec![9])])]);
    let client = pb::file_server_client::FileServerClient::new(fake);
    let (handle, rx) = crate::channel();
    let driver = crate::worker::serve_with_timeouts(
        client,
        rx,
        Duration::from_millis(10),
        Duration::from_millis(10),
    );
    let job = async move {
        let first = handle.read_range("object", 0, 1).await;
        let error = first.expect_err("hung stream body must fail");
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(crate::is_transport_loss(&error));
        assert_eq!(
            handle
                .read_range("object", 0, 1)
                .await
                .expect("driver remains usable after a timed-out stream body"),
            vec![9]
        );
    };
    let ((), ()) = block_on(futures::future::join(job, driver));
}

// ── what comes off it ─────────────────────────────────────────────────────

/// A reply split across several `ReadChunk`s at boundaries that are not page
/// boundaries reassembles byte-exactly. A chunk boundary is not a page
/// boundary and the server picks it.
#[test]
fn a_split_reply_reassembles() {
    let base = 4096 * 3;
    let whole = pattern(base, 12288);
    let cs = vec![
        (base, whole[..1].to_vec()),
        (base + 1, whole[1..5000].to_vec()),
        (base + 5000, whole[5000..12287].to_vec()),
        (base + 12287, whole[12287..].to_vec()),
    ];
    let want = whole.clone();
    let (got, seen) = one(vec![Reply::Chunks(cs)], move |h| {
        Box::pin(async move { h.read_range("images/guest.img", base, 12288).await })
    });
    assert_eq!(got.expect("read"), want);
    assert_eq!(seen[0].read.as_ref().unwrap().length, 12288);
}

/// A stream that ends before the requested length is an error, not a short
/// buffer — the shape of a truncated file and of a store that is not the one
/// the index came from.
#[test]
fn a_truncated_reply_is_an_error() {
    let (got, _) = one(vec![Reply::Chunks(vec![(0, vec![1u8; 100])])], move |h| {
        Box::pin(async move { h.read_range("images/guest.img", 0, 4096).await })
    });
    let e = got.expect_err("a short reply must be refused");
    assert_eq!(e.kind(), io::ErrorKind::UnexpectedEof);
    assert!(e.to_string().contains("after 100 of 4096"), "{e}");
}

/// Chunks whose offsets are consistent with each other but shifted relative to
/// the request are refused. The client seeds its expectation from what *it*
/// asked for, which is the only reason this is visible at all.
#[test]
fn a_shifted_reply_is_an_error() {
    let (got, _) = one(vec![Reply::Chunks(vec![(0, vec![1u8; 4096])])], move |h| {
        Box::pin(async move { h.read_range("images/guest.img", 4096, 4096).await })
    });
    let e = got.expect_err("a shifted reply must be refused");
    assert_eq!(e.kind(), io::ErrorKind::InvalidData);
    assert!(e.to_string().contains("where 4096 was due"), "{e}");
}

/// A stream that carries some data and then a failing status is an error,
/// naming the code — not the partial data.
///
/// A decoded status is an authoritative server reply even after data frames.
#[test]
fn a_status_partway_through_a_stream_is_an_error() {
    let (got, _) = one(
        vec![Reply::ChunksThenStatus(
            vec![(0, vec![1u8; 2048])],
            13,
            "the backing store went away".into(),
        )],
        move |h| Box::pin(async move { h.read_range("images/guest.img", 0, 4096).await }),
    );
    let e = got.expect_err("a mid-stream status must be refused");
    assert!(e.to_string().contains("Internal"), "{e}");
    assert!(e.to_string().contains("went away"), "{e}");
    assert!(!crate::is_transport_loss(&e));
}

#[test]
fn server_unavailable_status_is_a_known_reply() {
    let (got, _) = one(
        vec![Reply::ChunksThenStatus(vec![], 14, "try later".into())],
        move |h| Box::pin(async move { h.read_range("images/guest.img", 0, 4096).await }),
    );
    let error = got.expect_err("UNAVAILABLE must be returned");
    assert!(error.to_string().contains("Unavailable"), "{error}");
    assert!(!crate::is_transport_loss(&error));
}

#[test]
fn partial_stream_transport_loss_discards_bytes_and_is_retryable() {
    let (got, _) = one(
        vec![Reply::ChunksThenBodyError(vec![(0, vec![1u8; 2048])])],
        move |h| Box::pin(async move { h.read_range("images/guest.img", 0, 4096).await }),
    );
    let error = got.expect_err("a partial transport reply must not return bytes");
    assert!(crate::is_transport_loss(&error), "{error}");
}

/// `NOT_FOUND` keeps its identity through the `io::Error`, because "the store
/// is not there" and "the server is broken" call for different responses.
#[test]
fn a_missing_file_is_reported_as_not_found() {
    let (got, _) = one(
        vec![Reply::ChunksThenStatus(vec![], 5, "no such file".into())],
        move |h| Box::pin(async move { h.read_range("absent", 0, 4096).await }),
    );
    let e = got.expect_err("NOT_FOUND must be refused");
    assert_eq!(e.kind(), io::ErrorKind::NotFound);
}

/// With no driver running, a request fails immediately rather than hanging.
#[test]
fn a_request_with_no_driver_is_a_broken_pipe() {
    let (handle, rx) = crate::channel();
    drop(rx);
    let e = block_on(handle.read_range("images/guest.img", 0, 4096))
        .expect_err("a dead driver must be reported");
    assert_eq!(e.kind(), io::ErrorKind::BrokenPipe);
    assert!(crate::is_transport_loss(&e));
}

#[test]
fn every_wire_request_has_an_explicit_replay_class() {
    use crate::{Request, RequestClass};
    use futures::channel::oneshot;

    let (reply, _) = oneshot::channel();
    assert_eq!(
        Request::Read {
            path: String::new(),
            offset: 0,
            len: 0,
            reply
        }
        .class(),
        RequestClass::Read
    );
    let (reply, _) = oneshot::channel();
    assert_eq!(
        Request::Size {
            path: String::new(),
            reply
        }
        .class(),
        RequestClass::Read
    );
    let (reply, _) = oneshot::channel();
    assert_eq!(
        Request::List {
            path: String::new(),
            reply,
        }
        .class(),
        RequestClass::Read
    );
    let (reply, _) = oneshot::channel();
    assert_eq!(
        Request::ListBounded {
            path: String::new(),
            max_entries: 1,
            reply
        }
        .class(),
        RequestClass::Read
    );
    let (reply, _) = oneshot::channel();
    assert_eq!(Request::Usage { reply }.class(), RequestClass::Read);

    let (reply, _) = oneshot::channel();
    assert_eq!(
        Request::Write {
            path: String::new(),
            offset: 0,
            data: Vec::new(),
            create: false,
            truncate: false,
            durable: true,
            reply,
        }
        .class(),
        RequestClass::Mutation
    );
    let (reply, _) = oneshot::channel();
    assert_eq!(
        Request::Mkdir {
            path: String::new(),
            parents: false,
            reply
        }
        .class(),
        RequestClass::Mutation
    );
    let (reply, _) = oneshot::channel();
    assert_eq!(
        Request::Rename {
            from: String::new(),
            to: String::new(),
            reply
        }
        .class(),
        RequestClass::Mutation
    );
    let (reply, _) = oneshot::channel();
    assert_eq!(
        Request::Delete {
            path: String::new(),
            recursive: false,
            reply
        }
        .class(),
        RequestClass::Mutation
    );
    let (reply, _) = oneshot::channel();
    assert_eq!(
        Request::BeginImageImport {
            import_id: String::new(),
            expected_sha256: String::new(),
            expected_size: 0,
            reply,
        }
        .class(),
        RequestClass::Mutation
    );
    let (reply, _) = oneshot::channel();
    assert_eq!(
        Request::WriteImageImport {
            import_id: String::new(),
            offset: 0,
            data: Vec::new(),
            reply,
        }
        .class(),
        RequestClass::Mutation
    );
    let (reply, _) = oneshot::channel();
    assert_eq!(
        Request::FlushImageImport {
            import_id: String::new(),
            reply
        }
        .class(),
        RequestClass::Mutation
    );
    let (reply, _) = oneshot::channel();
    assert_eq!(
        Request::CommitImageImport {
            import_id: String::new(),
            expected_sha256: String::new(),
            reply,
        }
        .class(),
        RequestClass::Mutation
    );
    let (reply, _) = oneshot::channel();
    assert_eq!(
        Request::AbortImageImport {
            import_id: String::new(),
            reply
        }
        .class(),
        RequestClass::Mutation
    );
}

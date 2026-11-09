//! The adapter between `hyper`'s HTTP/2 client connection and `tonic`'s client.
//!
//! `tonic`'s generated client wants a `tower` service taking
//! `http::Request<tonic::body::BoxBody>` and returning an `http::Response`
//! whose body is an `http_body::Body`. `hyper` 1.x deliberately does not
//! implement `tower::Service` on `SendRequest` — the integration lives in
//! `hyper-util`, which this tree builds with only its `service` feature (the
//! server-side `TowerToHyperService`) because the rest of it pulls `tokio`'s
//! networking, which cannot build for the target.
//!
//! So this is the missing direction, and it is four lines of substance. Note
//! that gRPC over HTTP/2 with prior knowledge (h2c) is exactly what the target
//! speaks: there is no TLS and no upgrade dance, so a raw
//! `hyper::client::conn::http2` connection is the whole transport.

use std::future::Future;
use std::pin::Pin;
use std::task::Context;
use std::task::Poll;

use hyper::client::conn::http2::SendRequest;
use tonic::body::BoxBody;

/// A `hyper` HTTP/2 client connection, as a `tower` service.
///
/// `Clone` because `SendRequest` is: cloning gives another handle onto the same
/// multiplexed connection, which is how more than one request would be put in
/// flight at once.
#[derive(Clone)]
pub struct SendRequestService {
    inner: SendRequest<BoxBody>,
}

impl SendRequestService {
    /// Wraps the sender half of a completed HTTP/2 handshake.
    pub fn new(inner: SendRequest<BoxBody>) -> Self {
        SendRequestService { inner }
    }
}

impl std::fmt::Debug for SendRequestService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SendRequestService")
    }
}

impl tower::Service<http::Request<BoxBody>> for SendRequestService {
    type Response = http::Response<hyper::body::Incoming>;
    type Error = hyper::Error;
    // `SendRequest::send_request` returns an unnameable future, so it is boxed.
    // One allocation per RPC, against a network round trip; not worth a
    // hand-written future to avoid.
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: http::Request<BoxBody>) -> Self::Future {
        Box::pin(self.inner.send_request(req))
    }
}

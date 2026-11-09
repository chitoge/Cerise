//! Bounded sequential response streams over either one opened immutable object
//! or a path that is resolved again for every chunk.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

pub(crate) type ReadFuture<'a, T, E> =
    Pin<Box<dyn Future<Output = Result<T, E>> + Send + 'a>>;

/// Storage operations used by the production read stream.
///
/// Immutable sources return an owned handle. Path-following sources deliberately
/// keep their current resolution semantics for concurrently replaced files.
pub(crate) trait Backend: Send + Sync + 'static {
    type Error: Send + 'static;
    type Opened: Send + Sync + 'static;

    fn stat_regular<'a>(
        &'a self,
        components: &'a [String],
    ) -> ReadFuture<'a, u64, Self::Error>;

    fn open_regular<'a>(
        &'a self,
        components: &'a [String],
    ) -> ReadFuture<'a, (Self::Opened, u64), Self::Error>;

    fn read_opened<'a>(
        &'a self,
        opened: &'a Self::Opened,
        offset: u64,
        length: u64,
    ) -> ReadFuture<'a, Vec<u8>, Self::Error>;

    fn read_path<'a>(
        &'a self,
        components: &'a [String],
        offset: u64,
        length: u64,
    ) -> ReadFuture<'a, Vec<u8>, Self::Error>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SourceStability {
    /// The path is a published content address. Its owning protocol never
    /// replaces or truncates the object bound to that identity.
    Immutable,
    /// The path may be replaced or truncated while a response is streaming.
    PathFollowing,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum PrepareError<E> {
    Source(E),
    OffsetOverflow,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum StreamError<E> {
    Source(E),
    LengthMismatch {
        offset: u64,
        expected: u64,
        actual: usize,
    },
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct Chunk {
    pub(crate) data: Vec<u8>,
    pub(crate) offset: u64,
}

enum Source<O> {
    Opened(O),
    Path,
}

/// State retained by the response stream. `backend` remains present for an
/// opened source so the filesystem mount outlives its object handle.
pub(crate) struct State<B: Backend> {
    // Rust drops fields in declaration order. The opened handle must be
    // released before the mount/backend that owns its filesystem lifetime.
    source: Source<B::Opened>,
    backend: B,
    components: Arc<Vec<String>>,
    offset: u64,
    end: u64,
    chunk_bytes: u64,
}

impl<B: Backend> State<B> {
    pub(crate) fn planned_bytes(&self) -> u64 {
        self.end.saturating_sub(self.offset)
    }
}

/// Resolves the requested source and fixes the bounded response extent.
/// Immutable paths are opened exactly once here. Mutable paths retain the
/// initial Stat followed by per-chunk path reads used by the existing API.
pub(crate) async fn prepare<B: Backend>(
    backend: B,
    components: Arc<Vec<String>>,
    offset: u64,
    length: u64,
    chunk_bytes: usize,
    stability: SourceStability,
) -> Result<State<B>, PrepareError<B::Error>> {
    assert!(chunk_bytes > 0, "read stream chunk size must be nonzero");
    let (source, size) = match stability {
        SourceStability::Immutable => {
            let (opened, size) = backend
                .open_regular(&components)
                .await
                .map_err(PrepareError::Source)?;
            (Source::Opened(opened), size)
        }
        SourceStability::PathFollowing => {
            let size = backend
                .stat_regular(&components)
                .await
                .map_err(PrepareError::Source)?;
            (Source::Path, size)
        }
    };
    let end = if offset >= size {
        offset
    } else {
        offset
            .checked_add(length)
            .ok_or(PrepareError::OffsetOverflow)?
            .min(size)
    };
    Ok(State {
        source,
        backend,
        components,
        offset,
        end,
        chunk_bytes: chunk_bytes as u64,
    })
}

/// Produces at most one chunk. Errors are terminal and retain no background
/// work; dropping the returned state cancels the remaining reads.
pub(crate) async fn next<B: Backend>(
    mut state: State<B>,
) -> Option<(Result<Chunk, StreamError<B::Error>>, State<B>)> {
    if state.offset >= state.end {
        return None;
    }
    let offset = state.offset;
    let length = (state.end - offset).min(state.chunk_bytes);
    let read = match &state.source {
        Source::Opened(opened) => state.backend.read_opened(opened, offset, length).await,
        Source::Path => {
            state
                .backend
                .read_path(&state.components, offset, length)
                .await
        }
    };
    let result = match read {
        Ok(data) if data.len() as u64 == length => Ok(Chunk { data, offset }),
        Ok(data) => Err(StreamError::LengthMismatch {
            offset,
            expected: length,
            actual: data.len(),
        }),
        Err(error) => Err(StreamError::Source(error)),
    };
    if result.is_ok() {
        state.offset += length;
    } else {
        state.offset = state.end;
    }
    Some((result, state))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    #[derive(Default)]
    struct Counts {
        stats: usize,
        opens: usize,
        opened_reads: usize,
        path_reads: usize,
    }

    struct Inner {
        bytes: Vec<u8>,
        declared_size: Option<u64>,
        fail_at: Option<u64>,
        counts: Counts,
    }

    struct Observation {
        inner: Arc<Mutex<Inner>>,
        backend_drops: Arc<AtomicUsize>,
        opened_drops: Arc<AtomicUsize>,
    }

    struct FakeBackend {
        inner: Arc<Mutex<Inner>>,
        backend_drops: Arc<AtomicUsize>,
        opened_drops: Arc<AtomicUsize>,
    }

    struct FakeOpened {
        bytes: Arc<Vec<u8>>,
        backend_drops: Arc<AtomicUsize>,
        opened_drops: Arc<AtomicUsize>,
    }

    impl Drop for FakeBackend {
        fn drop(&mut self) {
            self.backend_drops.fetch_add(1, Ordering::SeqCst);
        }
    }

    impl Drop for FakeOpened {
        fn drop(&mut self) {
            assert_eq!(
                self.backend_drops.load(Ordering::SeqCst),
                0,
                "opened handle outlived its mount/backend"
            );
            self.opened_drops.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn fake_backend(bytes: Vec<u8>) -> (FakeBackend, Observation) {
        let inner = Arc::new(Mutex::new(Inner {
            bytes,
            declared_size: None,
            fail_at: None,
            counts: Counts::default(),
        }));
        let backend_drops = Arc::new(AtomicUsize::new(0));
        let opened_drops = Arc::new(AtomicUsize::new(0));
        (
            FakeBackend {
                inner: inner.clone(),
                backend_drops: backend_drops.clone(),
                opened_drops: opened_drops.clone(),
            },
            Observation {
                inner,
                backend_drops,
                opened_drops,
            },
        )
    }

    fn path() -> Arc<Vec<String>> {
        Arc::new(vec!["objects".to_owned(), "digest".to_owned()])
    }

    fn range(bytes: &[u8], offset: u64, length: u64) -> Vec<u8> {
        let start = usize::try_from(offset).unwrap_or(usize::MAX);
        if start >= bytes.len() {
            return Vec::new();
        }
        let requested_end = start.saturating_add(usize::try_from(length).unwrap_or(usize::MAX));
        bytes[start..requested_end.min(bytes.len())].to_vec()
    }

    impl Backend for FakeBackend {
        type Error = &'static str;
        type Opened = FakeOpened;

        fn stat_regular<'a>(
            &'a self,
            _components: &'a [String],
        ) -> ReadFuture<'a, u64, Self::Error> {
            Box::pin(async move {
                let mut inner = self.inner.lock().unwrap();
                inner.counts.stats += 1;
                Ok(inner.declared_size.unwrap_or(inner.bytes.len() as u64))
            })
        }

        fn open_regular<'a>(
            &'a self,
            _components: &'a [String],
        ) -> ReadFuture<'a, (Self::Opened, u64), Self::Error> {
            Box::pin(async move {
                let mut inner = self.inner.lock().unwrap();
                inner.counts.opens += 1;
                let size = inner.declared_size.unwrap_or(inner.bytes.len() as u64);
                Ok((
                    FakeOpened {
                        bytes: Arc::new(inner.bytes.clone()),
                        backend_drops: self.backend_drops.clone(),
                        opened_drops: self.opened_drops.clone(),
                    },
                    size,
                ))
            })
        }

        fn read_opened<'a>(
            &'a self,
            opened: &'a Self::Opened,
            offset: u64,
            length: u64,
        ) -> ReadFuture<'a, Vec<u8>, Self::Error> {
            Box::pin(async move {
                let mut inner = self.inner.lock().unwrap();
                inner.counts.opened_reads += 1;
                if inner.fail_at == Some(offset) {
                    return Err("injected read error");
                }
                Ok(range(&opened.bytes, offset, length))
            })
        }

        fn read_path<'a>(
            &'a self,
            _components: &'a [String],
            offset: u64,
            length: u64,
        ) -> ReadFuture<'a, Vec<u8>, Self::Error> {
            Box::pin(async move {
                let mut inner = self.inner.lock().unwrap();
                inner.counts.path_reads += 1;
                if inner.fail_at == Some(offset) {
                    return Err("injected read error");
                }
                Ok(range(&inner.bytes, offset, length))
            })
        }
    }

    #[test]
    fn immutable_large_streams_open_once_and_read_exact_chunks() {
        const CHUNK: usize = 64 * 1024;
        for total in [2 * 1024 * 1024, 16 * 1024 * 1024] {
            let expected = (0..total).map(|index| (index % 251) as u8).collect::<Vec<_>>();
            let (backend, observed) = fake_backend(expected.clone());
            let mut state = futures::executor::block_on(prepare(
                backend,
                path(),
                0,
                total as u64,
                CHUNK,
                SourceStability::Immutable,
            ))
            .unwrap();
            assert_eq!(state.planned_bytes(), total as u64);

            let mut got = Vec::new();
            while let Some((chunk, next_state)) = futures::executor::block_on(next(state)) {
                let chunk = chunk.unwrap();
                assert_eq!(chunk.offset, got.len() as u64);
                assert_eq!(chunk.data.len(), CHUNK);
                got.extend_from_slice(&chunk.data);
                state = next_state;
            }
            assert_eq!(got, expected);
            let inner = observed.inner.lock().unwrap();
            assert_eq!(inner.counts.stats, 0);
            assert_eq!(inner.counts.opens, 1);
            assert_eq!(inner.counts.opened_reads, total / CHUNK);
            assert_eq!(inner.counts.path_reads, 0);
        }
    }

    #[test]
    fn mutable_stream_follows_replacement_and_reports_truncation() {
        const CHUNK: usize = 64 * 1024;
        let (backend, observed) = fake_backend(vec![0x11; CHUNK * 3]);
        let state = futures::executor::block_on(prepare(
            backend,
            path(),
            0,
            (CHUNK * 3) as u64,
            CHUNK,
            SourceStability::PathFollowing,
        ))
        .unwrap();
        let (first, state) = futures::executor::block_on(next(state)).unwrap();
        assert_eq!(first.unwrap().data, vec![0x11; CHUNK]);

        observed.inner.lock().unwrap().bytes = vec![0x22; CHUNK * 3];
        let (second, state) = futures::executor::block_on(next(state)).unwrap();
        assert_eq!(second.unwrap().data, vec![0x22; CHUNK]);

        observed.inner.lock().unwrap().bytes.truncate(CHUNK + 1);
        let (third, state) = futures::executor::block_on(next(state)).unwrap();
        assert_eq!(
            third,
            Err(StreamError::LengthMismatch {
                offset: (CHUNK * 2) as u64,
                expected: CHUNK as u64,
                actual: 0,
            })
        );
        assert!(futures::executor::block_on(next(state)).is_none());
        let inner = observed.inner.lock().unwrap();
        assert_eq!(inner.counts.stats, 1);
        assert_eq!(inner.counts.opens, 0);
        assert_eq!(inner.counts.opened_reads, 0);
        assert_eq!(inner.counts.path_reads, 3);
    }

    #[test]
    fn eof_overflow_and_source_errors_are_terminal() {
        let (backend, observed) = fake_backend((0..10).collect());
        let state = futures::executor::block_on(prepare(
            backend,
            path(),
            6,
            10,
            8,
            SourceStability::Immutable,
        ))
        .unwrap();
        assert_eq!(state.planned_bytes(), 4);
        let (chunk, state) = futures::executor::block_on(next(state)).unwrap();
        assert_eq!(chunk.unwrap(), Chunk { data: vec![6, 7, 8, 9], offset: 6 });
        assert!(futures::executor::block_on(next(state)).is_none());
        assert_eq!(observed.inner.lock().unwrap().counts.opened_reads, 1);

        let (backend, observed) = fake_backend(vec![1; 10]);
        let state = futures::executor::block_on(prepare(
            backend,
            path(),
            10,
            1,
            4,
            SourceStability::Immutable,
        ))
        .unwrap();
        assert!(futures::executor::block_on(next(state)).is_none());
        assert_eq!(observed.inner.lock().unwrap().counts.opened_reads, 0);

        let (backend, observed) = fake_backend(Vec::new());
        observed.inner.lock().unwrap().declared_size = Some(u64::MAX);
        let error = futures::executor::block_on(prepare(
            backend,
            path(),
            u64::MAX - 1,
            4,
            4,
            SourceStability::PathFollowing,
        ));
        assert!(matches!(error, Err(PrepareError::OffsetOverflow)));

        let (backend, observed) = fake_backend(vec![1; 8]);
        observed.inner.lock().unwrap().fail_at = Some(4);
        let state = futures::executor::block_on(prepare(
            backend,
            path(),
            0,
            8,
            4,
            SourceStability::Immutable,
        ))
        .unwrap();
        let (first, state) = futures::executor::block_on(next(state)).unwrap();
        assert!(first.is_ok());
        let (error, state) = futures::executor::block_on(next(state)).unwrap();
        assert_eq!(error, Err(StreamError::Source("injected read error")));
        assert!(futures::executor::block_on(next(state)).is_none());
    }

    #[test]
    fn dropping_stream_state_cancels_reads_and_drops_handle_before_mount() {
        let (backend, observed) = fake_backend(vec![1; 12]);
        let state = futures::executor::block_on(prepare(
            backend,
            path(),
            0,
            12,
            4,
            SourceStability::Immutable,
        ))
        .unwrap();
        let (_, state) = futures::executor::block_on(next(state)).unwrap();
        assert_eq!(observed.inner.lock().unwrap().counts.opened_reads, 1);
        drop(state);
        assert_eq!(observed.inner.lock().unwrap().counts.opened_reads, 1);
        assert_eq!(observed.opened_drops.load(Ordering::SeqCst), 1);
        assert_eq!(observed.backend_drops.load(Ordering::SeqCst), 1);
    }
}

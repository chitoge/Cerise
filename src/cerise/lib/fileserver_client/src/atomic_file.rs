//! Atomic whole-object persistence over the file-server contract.
//!
//! A replacement is written at `<path>.tmp` before one durable atomic rename
//! publishes it. Temporary chunks need no filesystem-wide sync: the final
//! rename orders their flushed contents and checkpoints Fxfs before returning.
//! Whole objects remain buffered by the caller, but their transport is split
//! into bounded ranged operations so neither reads nor writes depend on a gRPC
//! implementation's maximum message size.

use std::io;

use crate::DurableFileStore;
use crate::FILESERVER_IO_CHUNK_BYTES;

/// One small durable object stored as a file.
#[derive(Clone, Debug)]
pub struct AtomicFile<R> {
    io: R,
    path: String,
    temp_path: String,
    parent: Option<String>,
}

impl<R> AtomicFile<R>
where
    R: DurableFileStore,
{
    /// Creates a handle for one relative file-server path.
    ///
    /// A handle is single-writer: all clones use the same temporary path and
    /// must be externally serialized. VM manager StateStore operations already
    /// satisfy that contract through the manager lock.
    pub fn new(io: R, path: impl Into<String>) -> io::Result<Self> {
        let path = path.into();
        validate_path(&path)?;
        let parent = path
            .rsplit_once('/')
            .map(|(parent, _)| parent.to_owned());
        Ok(Self {
            temp_path: format!("{path}.tmp"),
            io,
            path,
            parent,
        })
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    /// Loads the complete object, or `None` when it has not been created.
    pub async fn load(&self) -> io::Result<Option<Vec<u8>>> {
        let size = match self.io.size_of(&self.path).await {
            Ok(size) => size,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
        if size == 0 {
            return Ok(Some(Vec::new()));
        }
        let capacity = usize::try_from(size).map_err(|_| {
            io::Error::new(
                io::ErrorKind::OutOfMemory,
                "atomic file does not fit in the client address space",
            )
        })?;
        let mut bytes = Vec::with_capacity(capacity);
        let mut offset = 0u64;
        while offset < size {
            let len = (size - offset).min(FILESERVER_IO_CHUNK_BYTES as u64);
            let chunk = self.io.read_range(&self.path, offset, len).await?;
            if chunk.len() as u64 != len {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "atomic file ranged read returned fewer bytes than requested",
                ));
            }
            bytes.extend_from_slice(&chunk);
            offset += len;
        }
        Ok(Some(bytes))
    }

    /// Loads the complete object when its declared size does not exceed
    /// `max_bytes`, or `None` when it has not been created.
    ///
    /// The bound is checked before converting the size to the client address
    /// space, reserving memory, or issuing any ranged read.
    ///
    /// The caller must exclude replacement from the initial size observation
    /// through the final ranged read. This method does not create a versioned
    /// storage snapshot: a concurrent rename can otherwise mix its size and
    /// bytes with different object versions. In particular, catalog authority
    /// admission must use a server-issued observation cut rather than this
    /// unversioned helper.
    pub async fn load_bounded(&self, max_bytes: u64) -> io::Result<Option<Vec<u8>>> {
        let size = match self.io.size_of(&self.path).await {
            Ok(size) => size,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
        if size > max_bytes {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "atomic file exceeds the configured size limit",
            ));
        }
        if size == 0 {
            return Ok(Some(Vec::new()));
        }
        let capacity = usize::try_from(size).map_err(|_| {
            io::Error::new(
                io::ErrorKind::OutOfMemory,
                "atomic file does not fit in the client address space",
            )
        })?;
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(capacity).map_err(|_| {
            io::Error::new(
                io::ErrorKind::OutOfMemory,
                "atomic file result buffer could not be reserved",
            )
        })?;
        let mut offset = 0u64;
        while offset < size {
            let len = (size - offset).min(FILESERVER_IO_CHUNK_BYTES as u64);
            let chunk = self.io.read_range(&self.path, offset, len).await?;
            if chunk.len() as u64 != len {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "atomic file ranged read returned fewer bytes than requested",
                ));
            }
            bytes.extend_from_slice(&chunk);
            offset += len;
        }
        Ok(Some(bytes))
    }

    /// Durably replaces the complete object.
    pub async fn replace(&self, bytes: Vec<u8>) -> io::Result<()> {
        if let Some(parent) = &self.parent {
            match self.io.mkdir(parent, true).await {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error),
            }
        }
        if bytes.is_empty() {
            self.io
                .write_range_lazy(&self.temp_path, 0, Vec::new(), true, true)
                .await?;
        } else {
            for (index, chunk) in bytes.chunks(FILESERVER_IO_CHUNK_BYTES).enumerate() {
                let offset = index
                    .checked_mul(FILESERVER_IO_CHUNK_BYTES)
                    .and_then(|offset| u64::try_from(offset).ok())
                    .ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "atomic file write offset overflowed",
                        )
                    })?;
                self.io
                    .write_range_lazy(
                        &self.temp_path,
                        offset,
                        chunk.to_vec(),
                        index == 0,
                        index == 0,
                    )
                    .await?;
            }
        }
        self.io.rename(&self.temp_path, &self.path).await
    }
}

fn validate_path(path: &str) -> io::Result<()> {
    if path.is_empty()
        || path.starts_with('/')
        || path
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "atomic file path must be a non-empty relative path without dot components",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::sync::{Arc, Mutex};

    use super::*;
    use crate::{FileMutator, RangeReader};

    #[derive(Clone, Default)]
    struct Fake {
        inner: Arc<Mutex<Inner>>,
    }

    #[derive(Default)]
    struct Inner {
        files: BTreeMap<String, Vec<u8>>,
        directories: BTreeSet<String>,
        operations: Vec<String>,
        read_ranges: Vec<(String, u64, u64)>,
        declared_size: Option<u64>,
        fail_rename: bool,
        shorten_reads: bool,
    }

    impl RangeReader for Fake {
        async fn read_range(&self, path: &str, offset: u64, len: u64) -> io::Result<Vec<u8>> {
            let mut inner = self.inner.lock().unwrap();
            inner.read_ranges.push((path.to_owned(), offset, len));
            let file = inner
                .files
                .get(path)
                .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?;
            let start = usize::try_from(offset).unwrap();
            let end = usize::try_from(offset + len).unwrap();
            let mut bytes = file
                .get(start..end)
                .map(ToOwned::to_owned)
                .ok_or_else(|| io::Error::from(io::ErrorKind::UnexpectedEof))?;
            if inner.shorten_reads && !bytes.is_empty() {
                bytes.pop();
            }
            Ok(bytes)
        }

        async fn size_of(&self, path: &str) -> io::Result<u64> {
            let inner = self.inner.lock().unwrap();
            if let Some(size) = inner.declared_size {
                return Ok(size);
            }
            inner
                .files
                .get(path)
                .map(|bytes| bytes.len() as u64)
                .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))
        }
    }

    impl FileMutator for Fake {
        async fn write_range(
            &self,
            path: &str,
            offset: u64,
            data: Vec<u8>,
            create: bool,
            truncate: bool,
        ) -> io::Result<()> {
            let mut inner = self.inner.lock().unwrap();
            inner.operations.push(format!("write:{path}"));
            if !create && !inner.files.contains_key(path) {
                return Err(io::Error::from(io::ErrorKind::NotFound));
            }
            let file = inner.files.entry(path.to_owned()).or_default();
            if truncate {
                file.clear();
            }
            let start = usize::try_from(offset).unwrap();
            file.resize(file.len().max(start + data.len()), 0);
            file[start..start + data.len()].copy_from_slice(&data);
            Ok(())
        }

        async fn mkdir(&self, path: &str, _parents: bool) -> io::Result<()> {
            let mut inner = self.inner.lock().unwrap();
            inner.operations.push(format!("mkdir:{path}"));
            if !inner.directories.insert(path.to_owned()) {
                return Err(io::Error::from(io::ErrorKind::AlreadyExists));
            }
            Ok(())
        }

        async fn rename(&self, from: &str, to: &str) -> io::Result<()> {
            let mut inner = self.inner.lock().unwrap();
            inner.operations.push(format!("rename:{from}:{to}"));
            if inner.fail_rename {
                return Err(io::Error::other("injected rename failure"));
            }
            let bytes = inner
                .files
                .remove(from)
                .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?;
            inner.files.insert(to.to_owned(), bytes);
            Ok(())
        }
    }

    #[test]
    fn replace_publishes_only_after_temp_write() {
        let fake = Fake::default();
        let file = AtomicFile::new(fake.clone(), "vm-manager/catalog.json").unwrap();

        futures::executor::block_on(file.replace(b"new catalog".to_vec())).unwrap();

        assert_eq!(
            futures::executor::block_on(file.load()).unwrap(),
            Some(b"new catalog".to_vec())
        );
        assert_eq!(
            fake.inner.lock().unwrap().operations,
            [
                "mkdir:vm-manager",
                "write:vm-manager/catalog.json.tmp",
                "rename:vm-manager/catalog.json.tmp:vm-manager/catalog.json",
            ]
        );
    }

    #[test]
    fn failed_publish_preserves_previous_catalog() {
        let fake = Fake::default();
        fake.inner
            .lock()
            .unwrap()
            .files
            .insert("vm-manager/catalog.json".to_owned(), b"old".to_vec());
        let file = AtomicFile::new(fake.clone(), "vm-manager/catalog.json").unwrap();
        fake.inner.lock().unwrap().fail_rename = true;

        assert!(futures::executor::block_on(file.replace(b"new".to_vec())).is_err());
        assert_eq!(
            futures::executor::block_on(file.load()).unwrap(),
            Some(b"old".to_vec())
        );
    }

    #[test]
    fn large_objects_use_bounded_ranged_io() {
        let fake = Fake::default();
        let file = AtomicFile::new(fake.clone(), "vm-state/object").unwrap();
        let bytes = vec![0x5a; FILESERVER_IO_CHUNK_BYTES + 17];

        futures::executor::block_on(file.replace(bytes.clone())).unwrap();

        assert_eq!(
            futures::executor::block_on(file.load()).unwrap(),
            Some(bytes)
        );
        assert_eq!(
            fake.inner
                .lock()
                .unwrap()
                .operations
                .iter()
                .filter(|operation| *operation == "write:vm-state/object.tmp")
                .count(),
            2
        );
    }

    #[test]
    fn bounded_load_rejects_oversize_before_any_ranged_read() {
        let fake = Fake::default();
        fake.inner.lock().unwrap().declared_size = Some(u64::MAX);
        let file = AtomicFile::new(fake.clone(), "vm-state/object").unwrap();

        let error = futures::executor::block_on(file.load_bounded(u64::MAX - 1)).unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(fake.inner.lock().unwrap().read_ranges.is_empty());
    }

    #[test]
    fn bounded_load_accepts_exact_limit_and_keeps_chunk_boundaries() {
        let fake = Fake::default();
        let bytes = vec![0x5a; FILESERVER_IO_CHUNK_BYTES + 17];
        fake.inner
            .lock()
            .unwrap()
            .files
            .insert("vm-state/object".to_owned(), bytes.clone());
        let file = AtomicFile::new(fake.clone(), "vm-state/object").unwrap();

        assert_eq!(
            futures::executor::block_on(file.load_bounded(bytes.len() as u64)).unwrap(),
            Some(bytes)
        );
        assert_eq!(
            fake.inner.lock().unwrap().read_ranges,
            [
                (
                    "vm-state/object".to_owned(),
                    0,
                    FILESERVER_IO_CHUNK_BYTES as u64,
                ),
                (
                    "vm-state/object".to_owned(),
                    FILESERVER_IO_CHUNK_BYTES as u64,
                    17,
                ),
            ]
        );
    }

    #[test]
    fn bounded_load_allows_empty_object_at_zero_limit() {
        let fake = Fake::default();
        fake.inner
            .lock()
            .unwrap()
            .files
            .insert("vm-state/object".to_owned(), Vec::new());
        let file = AtomicFile::new(fake.clone(), "vm-state/object").unwrap();

        assert_eq!(
            futures::executor::block_on(file.load_bounded(0)).unwrap(),
            Some(Vec::new())
        );
        assert!(fake.inner.lock().unwrap().read_ranges.is_empty());
    }

    #[test]
    fn bounded_load_rejects_short_ranged_read() {
        let fake = Fake::default();
        {
            let mut inner = fake.inner.lock().unwrap();
            inner
                .files
                .insert("vm-state/object".to_owned(), b"data".to_vec());
            inner.shorten_reads = true;
        }
        let file = AtomicFile::new(fake, "vm-state/object").unwrap();

        let error = futures::executor::block_on(file.load_bounded(4)).unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn missing_and_unsafe_paths_are_distinct() {
        let fake = Fake::default();
        let file = AtomicFile::new(fake.clone(), "catalog.json").unwrap();
        assert_eq!(futures::executor::block_on(file.load()).unwrap(), None);
        assert!(AtomicFile::new(fake, "../catalog.json").is_err());
    }
}

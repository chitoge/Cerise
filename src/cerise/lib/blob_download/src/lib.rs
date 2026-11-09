//! Bounded, verified package-blob downloads backed by a temporary file.

#![forbid(unsafe_code)]

use anyhow::{Context as _, Result, anyhow};
use cerise_http_download::Limits;
use fuchsia_merkle::Hash;
use std::fs::{File, OpenOptions};
use std::io::{Seek as _, Write as _};
use std::path::{Path, PathBuf};

/// A Merkle-verified payload file that removes itself when dropped.
#[derive(Debug)]
pub struct VerifiedBlob {
    file: Option<File>,
    path: PathBuf,
    len: u64,
}

impl VerifiedBlob {
    pub fn len(&self) -> u64 {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The reader is positioned at byte zero when a verified blob is returned.
    pub fn reader(&mut self) -> &mut File {
        self.file.as_mut().expect("verified blob file is live")
    }
}

impl Drop for VerifiedBlob {
    fn drop(&mut self) {
        // Close before unlinking so cleanup has the same behavior on every host
        // filesystem, not only filesystems with POSIX unlink-while-open.
        drop(self.file.take());
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Download `path`, verify its Merkle root, and rewind the bounded spool.
///
/// Any error leaves no persistent partial file. Callers must not publish index
/// state until this function and the subsequent blob-store write both succeed.
pub async fn download_verified(
    address: &str,
    path: &str,
    limits: Limits,
    spool_path: &Path,
    claimed: &Hash,
) -> Result<VerifiedBlob> {
    if let Some(parent) = spool_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create blob spool directory {}", parent.display()))?;
    }
    let file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .read(true)
        .write(true)
        .open(spool_path)
        .with_context(|| format!("open blob spool {}", spool_path.display()))?;
    let mut blob = VerifiedBlob {
        file: Some(file),
        path: spool_path.to_path_buf(),
        len: 0,
    };

    let downloaded = cerise_http_download::get_to(address, path, limits, blob.reader())
        .await
        .with_context(|| format!("download blob {path}"))?;
    blob.reader()
        .flush()
        .context("flush downloaded blob spool")?;
    let downloaded =
        u64::try_from(downloaded).context("downloaded blob length does not fit u64")?;
    let file_len = blob
        .reader()
        .metadata()
        .context("stat downloaded blob spool")?
        .len();
    if file_len != downloaded {
        return Err(anyhow!(
            "downloaded blob spool is {file_len} bytes, expected {downloaded}"
        ));
    }

    blob.reader()
        .seek(std::io::SeekFrom::Start(0))
        .context("rewind blob spool before Merkle verification")?;
    let actual = fuchsia_merkle::root_from_reader(blob.reader())
        .context("compute downloaded blob Merkle root")?;
    if &actual != claimed {
        return Err(anyhow!(
            "downloaded blob Merkle {actual} does not match claimed {claimed}"
        ));
    }
    blob.reader()
        .seek(std::io::SeekFrom::Start(0))
        .context("rewind verified blob spool")?;
    blob.len = downloaded;
    Ok(blob)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn scratch(name: &str) -> PathBuf {
        let root = std::env::var_os("TEST_TMPDIR")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        root.join(format!(
            "blob-download-{name}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    fn serve(payload: &'static [u8]) -> (String, std::thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                payload.len()
            )
            .unwrap();
            stream.write_all(payload).unwrap();
        });
        (address, server)
    }

    #[test]
    fn verified_spool_is_rewound_and_removed_on_drop() {
        use std::io::Read as _;

        const PAYLOAD: &[u8] = b"streamed and verified package blob";
        let claimed = fuchsia_merkle::root_from_slice(PAYLOAD);
        let path = scratch("valid");
        let (address, server) = serve(PAYLOAD);
        let mut blob = futures::executor::block_on(download_verified(
            &address,
            "/blob",
            Limits::new(1024),
            &path,
            &claimed,
        ))
        .unwrap();
        server.join().unwrap();
        assert_eq!(blob.len(), PAYLOAD.len() as u64);
        let mut bytes = Vec::new();
        blob.reader().read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, PAYLOAD);
        assert!(path.exists());
        drop(blob);
        assert!(!path.exists());
    }

    #[test]
    fn merkle_mismatch_removes_partial_spool() {
        const PAYLOAD: &[u8] = b"tampered";
        let claimed = fuchsia_merkle::root_from_slice(b"expected");
        let path = scratch("mismatch");
        let (address, server) = serve(PAYLOAD);
        let error = futures::executor::block_on(download_verified(
            &address,
            "/blob",
            Limits::new(1024),
            &path,
            &claimed,
        ))
        .unwrap_err();
        server.join().unwrap();
        assert!(error.to_string().contains("Merkle"));
        assert!(!path.exists());
    }
}

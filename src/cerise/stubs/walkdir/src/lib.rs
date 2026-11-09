// Cerise stub: provides walkdir types used in fuchsia-pkg non-test error/manifest code.
// Real walkdir does recursive directory traversal; for component-manager bring-up we only need the types
// to compile fuchsia-pkg's errors.rs and package_build_manifest.rs.

use std::path::Path;

/// Stub file type — reports everything as a file.
pub struct FileType;

impl FileType {
    pub fn is_dir(&self) -> bool { false }
    pub fn is_file(&self) -> bool { true }
    pub fn is_symlink(&self) -> bool { false }
}

/// Stub DirEntry — not populated in the stub.
#[derive(Debug)]
pub struct DirEntry {
    path: std::path::PathBuf,
}

impl DirEntry {
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn file_type(&self) -> FileType {
        FileType
    }
}

/// Stub walkdir error.
#[derive(Debug)]
pub struct Error;

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "walkdir stub error")
    }
}
impl std::error::Error for Error {}

/// Stub WalkDir iterator — always yields nothing.
pub struct WalkDir;

impl WalkDir {
    pub fn new(_root: impl AsRef<Path>) -> Self {
        Self
    }

    pub fn min_depth(self, _n: usize) -> Self {
        self
    }

    pub fn max_depth(self, _n: usize) -> Self {
        self
    }

    pub fn follow_links(self, _yes: bool) -> Self {
        self
    }
}

impl IntoIterator for WalkDir {
    type Item = Result<DirEntry, Error>;
    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        vec![].into_iter()
    }
}

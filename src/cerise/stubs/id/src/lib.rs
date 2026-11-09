// Cerise stub for the id crate (used by elf_runner::component_set).
// Provides a simple monotonic ID type.

use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Id(u64);

impl Id {
    pub fn new<T>(_key: T) -> Self {
        Id(NEXT_ID.fetch_add(1, Ordering::Relaxed))
    }
}

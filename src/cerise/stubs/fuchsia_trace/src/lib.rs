// Cerise stub for fuchsia_trace (used by elf_runner, component_manager).
// Tracing is later work; for component-manager bring-up we only need the API surface to compile.

/// Stub trace provider — no-op.
pub mod provider {}

/// Stub trace category.
pub fn category_enabled(_category: &[u8]) -> bool {
    false
}

/// Stub duration event — no-op.
#[macro_export]
macro_rules! duration {
    ($category:expr, $name:expr $(, $key:expr => $val:expr)*) => {};
}

/// Stub instant event — no-op.
#[macro_export]
macro_rules! instant {
    ($category:expr, $name:expr, $scope:expr $(, $key:expr => $val:expr)*) => {};
}

/// Stub flow begin — no-op.
#[macro_export]
macro_rules! flow_begin {
    ($category:expr, $name:expr, $id:expr $(, $key:expr => $val:expr)*) => {};
}

/// Stub flow end — no-op.
#[macro_export]
macro_rules! flow_end {
    ($category:expr, $name:expr, $id:expr $(, $key:expr => $val:expr)*) => {};
}

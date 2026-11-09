// Cerise stub for injectable_time.
// Provides TimeSource trait used by component_manager diagnostics.
// BootInstant here is a TimeSource impl (real time), distinct from zx::BootInstant.

pub trait TimeSource: std::fmt::Debug {
    fn now(&self) -> i64;
}

#[derive(Debug)]
pub struct BootInstant;

impl BootInstant {
    pub fn new() -> Self {
        BootInstant
    }
}

impl TimeSource for BootInstant {
    fn now(&self) -> i64 {
        0
    }
}

#[derive(Debug)]
pub struct FakeTime {
    value: std::sync::atomic::AtomicI64,
}

impl FakeTime {
    pub fn new() -> Self {
        FakeTime { value: std::sync::atomic::AtomicI64::new(0) }
    }
    pub fn set_ticks(&self, t: i64) {
        self.value.store(t, std::sync::atomic::Ordering::Relaxed);
    }
}

impl TimeSource for FakeTime {
    fn now(&self) -> i64 {
        self.value.load(std::sync::atomic::Ordering::Relaxed)
    }
}

#[derive(Debug)]
pub struct IncrementingFakeTime {
    value: std::sync::atomic::AtomicI64,
    increment: i64,
}

impl IncrementingFakeTime {
    pub fn new(start: i64, increment: i64) -> Self {
        IncrementingFakeTime {
            value: std::sync::atomic::AtomicI64::new(start),
            increment,
        }
    }
}

impl TimeSource for IncrementingFakeTime {
    fn now(&self) -> i64 {
        self.value.fetch_add(self.increment, std::sync::atomic::Ordering::Relaxed)
    }
}

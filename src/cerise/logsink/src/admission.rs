//! Resource and hanging-get limits that do not depend on Fuchsia APIs.

use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

/// Each client owns a 256 KiB IOBuffer mapping, a task, and a channel.
pub const MAX_LOGSINK_CLIENTS: usize = 64;

/// A process-wide cap with an owned permit for each admitted connection.
pub struct ClientLimiter {
    limit: usize,
    active: AtomicUsize,
}

impl ClientLimiter {
    pub fn new(limit: usize) -> Self {
        Self {
            limit,
            active: AtomicUsize::new(0),
        }
    }

    pub fn try_acquire(self: &Arc<Self>) -> Option<ClientPermit> {
        self.active
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |active| {
                let next = active.checked_add(1)?;
                (next <= self.limit).then_some(next)
            })
            .ok()?;
        Some(ClientPermit {
            limiter: Arc::clone(self),
        })
    }

    pub fn active(&self) -> usize {
        self.active.load(Ordering::Acquire)
    }
}

pub struct ClientPermit {
    limiter: Arc<ClientLimiter>,
}

impl Drop for ClientPermit {
    fn drop(&mut self) {
        let released =
            self.limiter
                .active
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |active| {
                    active.checked_sub(1)
                });
        debug_assert!(
            released.is_ok(),
            "a client permit must not be released twice"
        );
    }
}

/// Action for an incoming `WaitForInterestChange` request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterestAction {
    /// Reply once with the initial interest state.
    ReplyInitial,
    /// Retain this responder as the connection's one outstanding hanging get.
    Park,
    /// A hanging get is already outstanding; the connection violated the protocol.
    RejectDuplicate,
}

/// Tracks the hanging-get contract for one LogSink connection.
#[derive(Debug, Default)]
pub struct InterestHangingGet {
    initial_replied: bool,
    outstanding: bool,
}

impl InterestHangingGet {
    pub fn on_request(&mut self) -> InterestAction {
        if !self.initial_replied {
            self.initial_replied = true;
            InterestAction::ReplyInitial
        } else if !self.outstanding {
            self.outstanding = true;
            InterestAction::Park
        } else {
            InterestAction::RejectDuplicate
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limiter_rejects_above_cap_and_releases_on_drop() {
        let limiter = Arc::new(ClientLimiter::new(2));
        let first = limiter.try_acquire().expect("first client");
        let second = limiter.try_acquire().expect("second client");
        assert_eq!(limiter.active(), 2);
        assert!(limiter.try_acquire().is_none());

        drop(first);
        assert_eq!(limiter.active(), 1);
        let replacement = limiter
            .try_acquire()
            .expect("released capacity is reusable");
        assert_eq!(limiter.active(), 2);

        drop((second, replacement));
        assert_eq!(limiter.active(), 0);
    }

    #[test]
    fn zero_limit_admits_nobody() {
        let limiter = Arc::new(ClientLimiter::new(0));
        assert!(limiter.try_acquire().is_none());
        assert_eq!(limiter.active(), 0);
    }

    #[test]
    fn hanging_get_allows_only_one_outstanding_request() {
        let mut state = InterestHangingGet::default();
        assert_eq!(state.on_request(), InterestAction::ReplyInitial);
        assert_eq!(state.on_request(), InterestAction::Park);
        assert_eq!(state.on_request(), InterestAction::RejectDuplicate);
        assert_eq!(state.on_request(), InterestAction::RejectDuplicate);
    }
}

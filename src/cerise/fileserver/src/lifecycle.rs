//! Mutation admission and drain barrier for store-wide host transitions.
//!
//! The file server performs a durability sync at the end of every mutating RPC,
//! but an orderly host transition needs a stronger boundary: no mutation may
//! start after the transition begins, every mutation already admitted must
//! finish, and then one final filesystem-wide sync must complete.  This module
//! owns the first two parts.  The service layer owns the actual Fxfs sync.
//!
//! Reads do not acquire a permit.  Fxfs supports reads while syncing, and a read
//! cannot make the durable image newer than the freeze boundary.

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll, Waker};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Phase {
    Open,
    Freezing,
    Frozen,
    FrozenUnsynced,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Snapshot {
    pub phase: Phase,
    pub generation: u64,
    pub active_mutations: u64,
    /// Most recent generation whose final filesystem sync completed.  This is
    /// retained across thaw so a concurrent FreezeAndSync waiter cannot miss a
    /// successful completion merely because the leader was thawed first.
    pub last_synced_generation: u64,
}

struct State {
    phase: Phase,
    generation: u64,
    active_mutations: u64,
    last_synced_generation: u64,
    drain_wakers: Vec<Waker>,
    freeze_wakers: Vec<Waker>,
}

impl Default for State {
    fn default() -> Self {
        Self {
            phase: Phase::Open,
            generation: 0,
            active_mutations: 0,
            last_synced_generation: 0,
            drain_wakers: Vec::new(),
            freeze_wakers: Vec::new(),
        }
    }
}

#[derive(Clone, Default)]
pub struct MutationGate {
    inner: Arc<Mutex<State>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MutationRejected {
    Frozen,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ThawError {
    Busy,
    StaleGeneration,
}

pub enum FreezeRole {
    /// This generation has already completed its store-wide sync.
    AlreadyFrozen { generation: u64 },
    /// Another caller owns the sync attempt for this generation.
    Wait(FreezeWait),
    /// The caller must drain admitted mutations and perform the final sync.
    Leader(FreezeAttempt),
}

pub struct MutationPermit {
    gate: MutationGate,
    active: bool,
}

pub struct FreezeAttempt {
    gate: MutationGate,
    generation: u64,
    finished: bool,
}

pub struct DrainWait {
    gate: MutationGate,
    generation: u64,
}

pub struct FreezeWait {
    gate: MutationGate,
    generation: u64,
}

fn lock_state(gate: &MutationGate) -> MutexGuard<'_, State> {
    gate.inner
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn remember_waker(wakers: &mut Vec<Waker>, candidate: &Waker) {
    if !wakers.iter().any(|waker| waker.will_wake(candidate)) {
        wakers.push(candidate.clone());
    }
}

fn wake_all(wakers: Vec<Waker>) {
    for waker in wakers {
        waker.wake();
    }
}

impl MutationGate {
    pub fn snapshot(&self) -> Snapshot {
        let state = lock_state(self);
        Snapshot {
            phase: state.phase,
            generation: state.generation,
            active_mutations: state.active_mutations,
            last_synced_generation: state.last_synced_generation,
        }
    }

    /// Admits one complete mutating RPC.
    ///
    /// The returned permit must live through the RPC's final durability sync.
    /// Once freeze changes the phase away from `Open`, admission fails without
    /// waiting; otherwise the active count is incremented while holding the
    /// same lock used to close admission, so there is no check/increment race.
    pub fn begin_mutation(&self) -> Result<MutationPermit, MutationRejected> {
        let mut state = lock_state(self);
        if state.phase != Phase::Open {
            return Err(MutationRejected::Frozen);
        }
        state.active_mutations = state
            .active_mutations
            .checked_add(1)
            .expect("mutation permit count overflow");
        Ok(MutationPermit {
            gate: self.clone(),
            active: true,
        })
    }

    /// Closes mutation admission and elects at most one sync leader.
    ///
    /// A failed or cancelled sync attempt leaves the same generation in
    /// `FrozenUnsynced`.  A later call becomes leader for a retry without
    /// briefly reopening mutation admission.
    pub fn begin_freeze(&self) -> FreezeRole {
        let mut state = lock_state(self);
        match state.phase {
            Phase::Open => {
                state.generation = state.generation.wrapping_add(1);
                // Generation zero is reserved for "no freeze has happened".
                if state.generation == 0 {
                    state.generation = 1;
                }
                state.phase = Phase::Freezing;
                FreezeRole::Leader(FreezeAttempt {
                    gate: self.clone(),
                    generation: state.generation,
                    finished: false,
                })
            }
            Phase::Freezing => FreezeRole::Wait(FreezeWait {
                gate: self.clone(),
                generation: state.generation,
            }),
            Phase::Frozen => FreezeRole::AlreadyFrozen {
                generation: state.generation,
            },
            Phase::FrozenUnsynced => {
                state.phase = Phase::Freezing;
                FreezeRole::Leader(FreezeAttempt {
                    gate: self.clone(),
                    generation: state.generation,
                    finished: false,
                })
            }
        }
    }

    /// Reopens mutation admission for the matching completed generation.
    ///
    /// Repeating a successful thaw is harmless.  A thaw racing the elected
    /// sync leader is rejected rather than cancelling a durability boundary.
    pub fn thaw(&self, generation: u64) -> Result<(), ThawError> {
        let freeze_wakers = {
            let mut state = lock_state(self);
            if generation == 0 || generation != state.generation {
                return Err(ThawError::StaleGeneration);
            }
            match state.phase {
                Phase::Open => return Ok(()),
                Phase::Freezing => return Err(ThawError::Busy),
                Phase::Frozen | Phase::FrozenUnsynced => {
                    state.phase = Phase::Open;
                    state.drain_wakers.clear();
                    std::mem::take(&mut state.freeze_wakers)
                }
            }
        };
        wake_all(freeze_wakers);
        Ok(())
    }
}

impl Drop for MutationPermit {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        self.active = false;
        let drain_wakers = {
            let mut state = lock_state(&self.gate);
            debug_assert!(state.active_mutations > 0);
            state.active_mutations -= 1;
            if state.active_mutations == 0 && state.phase == Phase::Freezing {
                std::mem::take(&mut state.drain_wakers)
            } else {
                Vec::new()
            }
        };
        wake_all(drain_wakers);
    }
}

impl FreezeAttempt {
    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn wait_for_drain(&self) -> DrainWait {
        DrainWait {
            gate: self.gate.clone(),
            generation: self.generation,
        }
    }

    pub fn complete_synced(mut self) {
        self.finish(Phase::Frozen);
    }

    pub fn complete_unsynced(mut self) {
        self.finish(Phase::FrozenUnsynced);
    }

    fn finish(&mut self, phase: Phase) {
        let freeze_wakers = {
            let mut state = lock_state(&self.gate);
            if state.phase == Phase::Freezing && state.generation == self.generation {
                state.phase = phase;
                if phase == Phase::Frozen {
                    state.last_synced_generation = self.generation;
                }
                state.drain_wakers.clear();
                std::mem::take(&mut state.freeze_wakers)
            } else {
                Vec::new()
            }
        };
        self.finished = true;
        wake_all(freeze_wakers);
    }
}

impl Drop for FreezeAttempt {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        // A disconnected controller or cancelled task must not strand the gate
        // in Freezing.  Keep admission closed, mark the generation unsynced,
        // and let an explicit later FreezeAndSync retry it.
        self.finish(Phase::FrozenUnsynced);
    }
}

impl Future for DrainWait {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut state = lock_state(&self.gate);
        if state.generation != self.generation
            || state.phase != Phase::Freezing
            || state.active_mutations == 0
        {
            Poll::Ready(())
        } else {
            remember_waker(&mut state.drain_wakers, cx.waker());
            Poll::Pending
        }
    }
}

impl FreezeWait {
    pub fn generation(&self) -> u64 {
        self.generation
    }
}

impl Future for FreezeWait {
    type Output = Snapshot;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut state = lock_state(&self.gate);
        if state.generation != self.generation || state.phase != Phase::Freezing {
            Poll::Ready(Snapshot {
                phase: state.phase,
                generation: state.generation,
                active_mutations: state.active_mutations,
                last_synced_generation: state.last_synced_generation,
            })
        } else {
            remember_waker(&mut state.freeze_wakers, cx.waker());
            Poll::Pending
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;
    use std::time::Duration;

    #[test]
    fn freeze_closes_admission_before_it_drains() {
        let gate = MutationGate::default();
        let permit = gate.begin_mutation().expect("first mutation");
        let FreezeRole::Leader(attempt) = gate.begin_freeze() else {
            panic!("first freeze must elect a leader");
        };
        assert_eq!(gate.begin_mutation().err(), Some(MutationRejected::Frozen));
        assert_eq!(gate.snapshot().active_mutations, 1);

        let wait = attempt.wait_for_drain();
        let (done_tx, done_rx) = mpsc::channel();
        std::thread::spawn(move || {
            futures::executor::block_on(wait);
            done_tx.send(()).expect("report drained");
        });
        assert!(done_rx.recv_timeout(Duration::from_millis(20)).is_err());
        drop(permit);
        done_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("drain completes after admitted mutation");

        let generation = attempt.generation();
        attempt.complete_synced();
        assert_eq!(gate.snapshot().phase, Phase::Frozen);
        gate.thaw(generation).expect("matching thaw");
        assert!(gate.begin_mutation().is_ok());
    }

    #[test]
    fn completed_freeze_and_thaw_are_idempotent() {
        let gate = MutationGate::default();
        let FreezeRole::Leader(attempt) = gate.begin_freeze() else {
            panic!("first freeze must elect a leader");
        };
        let generation = attempt.generation();
        attempt.complete_synced();
        assert!(matches!(
            gate.begin_freeze(),
            FreezeRole::AlreadyFrozen { generation: seen } if seen == generation
        ));
        assert_eq!(gate.thaw(generation), Ok(()));
        assert_eq!(gate.thaw(generation), Ok(()));
        assert_eq!(gate.thaw(generation + 1), Err(ThawError::StaleGeneration));
    }

    #[test]
    fn concurrent_freezes_join_one_generation_and_completion() {
        let gate = MutationGate::default();
        let permit = gate.begin_mutation().expect("mutation before freeze");
        let FreezeRole::Leader(attempt) = gate.begin_freeze() else {
            panic!("first freeze must elect a leader");
        };
        let FreezeRole::Wait(waiter) = gate.begin_freeze() else {
            panic!("concurrent freeze must wait for the elected leader");
        };
        let generation = attempt.generation();
        assert_eq!(waiter.generation(), generation);

        let (done_tx, done_rx) = mpsc::channel();
        std::thread::spawn(move || {
            let completed = futures::executor::block_on(waiter);
            done_tx.send(completed).expect("report joined completion");
        });
        drop(permit);
        futures::executor::block_on(attempt.wait_for_drain());
        attempt.complete_synced();

        let completed = done_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("joined freeze completes");
        assert_eq!(completed.last_synced_generation, generation);
        assert_eq!(completed.phase, Phase::Frozen);
    }

    #[test]
    fn cancelled_or_failed_sync_stays_closed_and_is_retryable() {
        let gate = MutationGate::default();
        let FreezeRole::Leader(attempt) = gate.begin_freeze() else {
            panic!("first freeze must elect a leader");
        };
        let generation = attempt.generation();
        drop(attempt);
        assert_eq!(gate.snapshot().phase, Phase::FrozenUnsynced);
        assert_eq!(gate.begin_mutation().err(), Some(MutationRejected::Frozen));

        let FreezeRole::Leader(retry) = gate.begin_freeze() else {
            panic!("unsynced generation must elect a retry leader");
        };
        assert_eq!(retry.generation(), generation);
        retry.complete_synced();
        assert_eq!(gate.snapshot().phase, Phase::Frozen);
    }

    #[test]
    fn thaw_cannot_race_the_sync_leader() {
        let gate = MutationGate::default();
        let FreezeRole::Leader(attempt) = gate.begin_freeze() else {
            panic!("first freeze must elect a leader");
        };
        assert_eq!(gate.thaw(attempt.generation()), Err(ThawError::Busy));
        attempt.complete_unsynced();
        assert_eq!(gate.snapshot().phase, Phase::FrozenUnsynced);
    }
}

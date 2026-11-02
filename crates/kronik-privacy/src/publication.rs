//! The owned keystore's negative publication data, never caller authority.
//! No publisher guard may span SQL, filesystem work, or an await.

use std::sync::{Arc, Mutex, TryLockError};

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PublicationError {
    #[error("the keystore publication is busy")]
    Busy,
    #[error("the keystore has no original mutable-store ownership")]
    Unowned,
    #[error("the keystore publication is not certified")]
    Uncertified,
    #[error("the keystore publication generation is exhausted")]
    Exhausted,
    #[error("the original SQLite file identity is unavailable: {0}")]
    FileIdentity(&'static str),
}

#[derive(Default)]
struct State {
    generation: u64,
    mutations: usize,
    failed: bool,
    live: Option<(u64, u64)>,
    stage: Option<u64>,
}

#[derive(Default)]
pub(crate) struct DataPublisher {
    state: Mutex<State>,
}

impl DataPublisher {
    pub(crate) fn revision_for(
        &self,
        identity: Option<(u64, u64)>,
        stage: Option<u64>,
    ) -> Result<u64, PublicationError> {
        let state = self.try_state()?;
        Self::certified(&state, identity, stage)?;
        Ok(state.generation)
    }

    fn try_state(&self) -> Result<std::sync::MutexGuard<'_, State>, PublicationError> {
        self.state.try_lock().map_err(|error| match error {
            TryLockError::WouldBlock => PublicationError::Busy,
            TryLockError::Poisoned(_) => PublicationError::Uncertified,
        })
    }

    fn certified(
        state: &State,
        identity: Option<(u64, u64)>,
        stage: Option<u64>,
    ) -> Result<(), PublicationError> {
        let active = if stage.is_some() && stage == state.stage {
            1
        } else {
            0
        };
        if state.failed || state.mutations != active || stage != state.stage {
            return Err(PublicationError::Uncertified);
        }
        if identity.is_some() && identity != state.live {
            return Err(PublicationError::Unowned);
        }
        Ok(())
    }

    pub(crate) fn select_initial(&self, identity: (u64, u64)) -> Result<(), PublicationError> {
        let mut state = self.try_state()?;
        Self::certified(&state, None, None)?;
        match state.live {
            Some(current) if current != identity => Err(PublicationError::Unowned),
            _ => {
                state.live = Some(identity);
                Ok(())
            }
        }
    }

    pub(crate) fn check_mutable(&self, stage: Option<u64>) -> Result<(), PublicationError> {
        let state = self.try_state()?;
        if state.failed || state.stage != stage {
            return Err(PublicationError::Uncertified);
        }
        Ok(())
    }

    pub(crate) fn publish_for<T>(
        &self,
        expected: u64,
        identity: Option<(u64, u64)>,
        stage: Option<u64>,
        publish: impl FnOnce() -> T,
    ) -> Result<Option<T>, PublicationError> {
        let state = self.try_state()?;
        Self::certified(&state, identity, stage)?;
        if state.generation != expected {
            return Ok(None);
        }
        let result = publish();
        drop(state);
        Ok(Some(result))
    }

    /// Invalidate before the first destructive write; this returns no lock.
    pub(crate) fn begin(self: &Arc<Self>) -> Result<KeystoreMutation, PublicationError> {
        self.begin_for(None)
    }

    pub(crate) fn begin_for(
        self: &Arc<Self>,
        stage: Option<u64>,
    ) -> Result<KeystoreMutation, PublicationError> {
        self.begin_inner(stage, false)
    }

    pub(crate) fn begin_stage(self: &Arc<Self>) -> Result<KeystoreMutation, PublicationError> {
        self.begin_inner(None, true)
    }

    fn begin_inner(
        self: &Arc<Self>,
        stage: Option<u64>,
        restoring: bool,
    ) -> Result<KeystoreMutation, PublicationError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| PublicationError::Uncertified)?;
        if state.failed || state.stage != stage {
            return Err(PublicationError::Uncertified);
        }
        if restoring && state.mutations != 0 {
            return Err(PublicationError::Busy);
        }
        let generation = state
            .generation
            .checked_add(1)
            .ok_or(PublicationError::Exhausted)?;
        let mutations = state
            .mutations
            .checked_add(1)
            .ok_or(PublicationError::Exhausted)?;
        state.generation = generation;
        state.mutations = mutations;
        if restoring {
            state.stage = Some(generation);
        }
        drop(state);
        Ok(KeystoreMutation {
            publisher: self.clone(),
            id: generation,
            restoring,
            settled: false,
        })
    }
}

/// A data-only mutation phase. No SQL/FS lock or caller authority is retained.
pub(crate) struct KeystoreMutation {
    publisher: Arc<DataPublisher>,
    id: u64,
    restoring: bool,
    settled: bool,
}

impl KeystoreMutation {
    pub(crate) fn id(&self) -> u64 {
        self.id
    }

    pub(crate) fn finish(self) -> Result<(), PublicationError> {
        self.complete(None)
    }

    pub(crate) fn finish_selected(self, identity: (u64, u64)) -> Result<(), PublicationError> {
        self.complete(Some(identity))
    }

    fn complete(mut self, identity: Option<(u64, u64)>) -> Result<(), PublicationError> {
        let mut state = self
            .publisher
            .state
            .lock()
            .map_err(|_| PublicationError::Uncertified)?;
        if self.restoring && (state.mutations != 1 || state.stage != Some(self.id)) {
            state.failed = true;
            return Err(PublicationError::Uncertified);
        }
        let Some(generation) = state.generation.checked_add(1) else {
            state.failed = true;
            return Err(PublicationError::Exhausted);
        };
        state.generation = generation;
        state.mutations -= 1;
        if self.restoring {
            state.stage = None;
        }
        if let Some(identity) = identity {
            state.live = Some(identity);
        }
        self.settled = true;
        if state.failed {
            return Err(PublicationError::Uncertified);
        }
        Ok(())
    }
}

impl Drop for KeystoreMutation {
    fn drop(&mut self) {
        if !self.settled
            && let Ok(mut state) = self.publisher.state.lock()
        {
            state.failed = true;
            state.mutations -= 1;
            if self.restoring {
                state.stage = None;
            }
        }
    }
}

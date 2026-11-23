//! The turn gate: where a turn starts, the one mechanism behind every code
//! switch (ADR 0013) and every pause of main's turns (ADR 0018).
//!
//! - **Gate.** A turn takes its code and epoch under the read lock;
//!   deploy, promote, rollback and the rebase switch hold the write lock from
//!   their record's commit until every kind and the epoch are installed. So
//!   a turn starts either before a switch with the old code of every kind or
//!   after its LSN with the new code.
//! - **Drain.** A worker picks its next job under the drain state: while
//!   drained only callee turns of calls whose caller still waits start
//!   (their callers are running and wait for them), and [`Drain`] holds
//!   until no turn runs. The rebase switch drains (with the deploy lock), so
//!   do foreign checkpoints (M14).
//! - **Commit.** A turn appends its record under a second read lock, and a
//!   promote holds the write lock from before it counts until its
//!   `Deployment` is in the log (issue #126). Running turns need not finish:
//!   only an append that has not reached the log yet is ordered after it.
//!
//! Lock order: deploy lock, then drain, then the switch write lock, then the
//! commit write lock. The switch write lock is never held while waiting for
//! turns; a drain never takes either write lock itself.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use kronik_core::authority::AuthLease;
use kronik_core::error::{ApiError, ErrorCode};
use kronik_core::sync::lock;

use tokio::sync::{Notify, OwnedMutexGuard, OwnedRwLockWriteGuard, RwLock, RwLockReadGuard};

use crate::node::Node;
use crate::rebase::stale;

#[derive(Default)]
pub(crate) struct DrainState {
    /// Only callee turns of calls start.
    pub(crate) drained: bool,
    /// Turns in progress.
    pub(crate) running: usize,
}

#[derive(Default)]
pub(crate) struct TurnGate {
    switch: Arc<RwLock<()>>,
    /// A turn's record append against a switch's count.
    commit: Arc<RwLock<()>>,
    pub(crate) drain: Mutex<DrainState>,
    /// Signalled when a drain begins or ends, a turn ends during a drain,
    /// or a call is queued (a drained worker may start it).
    pub(crate) changed: Notify,
}

impl TurnGate {
    /// A turn's start: read its code and epoch under this.
    pub(crate) async fn start(&self) -> RwLockReadGuard<'_, ()> {
        self.switch.read().await
    }

    /// A code switch: hold this from the commit of its record until its
    /// code and epoch are installed. Owned, so the switch's task holds it.
    pub(crate) async fn switch(&self) -> OwnedRwLockWriteGuard<()> {
        self.switch.clone().write_owned().await
    }

    /// A turn's record append. Held until the append has its LSN, so a
    /// promote's write half waits for every append already under way.
    pub(crate) async fn commit(&self) -> RwLockReadGuard<'_, ()> {
        self.commit.read().await
    }

    /// A promote's count and Deployment: no turn appends its record while
    /// this is held, so none can land between the count and the record.
    pub(crate) async fn switch_commits(&self) -> OwnedRwLockWriteGuard<()> {
        self.commit.clone().write_owned().await
    }

    /// A turn ended; a drain waiting for running turns hears of it.
    pub(crate) fn turn_ended(&self) {
        let drained = {
            let mut d = lock(&self.drain);
            d.running -= 1;
            d.drained
        };
        if drained {
            self.changed.notify_waiters();
        }
    }
}

/// Main's turns held (ADR 0018); dropping it lets them start again.
pub struct Drain {
    node: std::sync::Arc<Node>,
    deadline: Duration,
    /// A rebase switch's drain holds the deploy lock (taken before it).
    deploy: Option<OwnedMutexGuard<()>>,
}

impl Drain {
    /// Whether this drain holds the deploy lock (a rebase switch's).
    pub(crate) fn holds_deploy_lock(&self) -> bool {
        self.deploy.is_some()
    }

    /// The drain's time is up: nothing more may be written.
    pub fn expired(&self) -> bool {
        self.node.env().clock.monotonic() >= self.deadline
    }

    /// The time left of this drain's bound; zero once it expired.
    pub fn remaining(&self) -> Duration {
        self.deadline
            .saturating_sub(self.node.env().clock.monotonic())
    }

    /// Still no turn running: a callee turn whose caller gave up may have
    /// started (call it with the switch gate held, so none starts after).
    pub(crate) fn check_quiet(&self) -> Result<(), ApiError> {
        match lock(&self.node.gate.drain).running {
            0 => Ok(()),
            n => Err(stale(format!(
                "{n} turn(s) started during the pause; nothing was switched"
            ))),
        }
    }
}

impl Drop for Drain {
    fn drop(&mut self) {
        lock(&self.node.gate.drain).drained = false;
        self.node.gate.changed.notify_waiters();
    }
}

impl Node {
    /// Holds main's turns: no turn starts but callee turns of calls, and
    /// this waits until none runs, at most `max`. Waits for another drain
    /// to end first, within the same `max`. Not a rebase's: its error is
    /// `UNAVAILABLE`.
    pub async fn drain(&self, max: Duration) -> Result<Drain, ApiError> {
        self.drain_with(max, None).await
    }

    /// The rebase switch's drain (lock order: the deploy lock first, so a
    /// set switch never lands between the rebase's last round and its
    /// switch, and waits for the switch instead). Its error is
    /// `PROPOSAL_STALE` naming `rebase.max_pause`.
    pub async fn rebase_pause(
        &self,
        max: Duration,
        authority: AuthLease,
    ) -> Result<Drain, ApiError> {
        authority.check()?;
        let deploy = self.lock_deploy_authorized(&authority).await?;
        tokio::select! {
            biased;
            () = authority.cancelled() => Err(ApiError::new(ErrorCode::Unauthenticated, "rebase request revoked while draining")),
            drain = self.drain_with(max, Some(deploy)) => drain,
        }
    }

    async fn drain_with(
        &self,
        max: Duration,
        deploy: Option<OwnedMutexGuard<()>>,
    ) -> Result<Drain, ApiError> {
        let node = self.arc()?;
        let deadline = self.env().clock.monotonic() + max;
        let rebase = deploy.is_some();
        let stale = |what: String| {
            if rebase {
                stale(format!(
                    "{what} after rebase.max_pause ({max:?}); nothing was switched"
                ))
            } else {
                ApiError::new(
                    ErrorCode::Unavailable,
                    format!("main's turns did not pause within {max:?}: {what}"),
                )
            }
        };
        loop {
            let changed = self.gate.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            {
                let mut d = lock(&self.gate.drain);
                if !d.drained {
                    d.drained = true;
                    break;
                }
            }
            let left = deadline.saturating_sub(self.env().clock.monotonic());
            if left.is_zero() {
                return Err(stale("main's turns were held by another pause".into()));
            }
            let _ = self.env().timeout(left, changed).await;
        }
        let drain = Drain {
            node,
            deadline,
            deploy,
        };
        loop {
            let changed = self.gate.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            let running = lock(&self.gate.drain).running;
            if running == 0 {
                return Ok(drain);
            }
            let left = deadline.saturating_sub(self.env().clock.monotonic());
            if left.is_zero() {
                return Err(stale(format!("{running} turn(s) still ran")));
            }
            let _ = self.env().timeout(left, changed).await;
        }
    }
}

// Tests run on real tokio time and tasks.
#[cfg(test)]
#[allow(clippy::disallowed_methods)]
mod tests;

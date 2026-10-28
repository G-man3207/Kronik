//! A clock that moves only when the test says so.

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use kronik_core::env::{BoxFuture, Clock};
use tokio::sync::oneshot;

/// Wall and monotonic time that stand still until [`ManualClock::advance`].
/// A sleep completes when the clock has been advanced past its deadline, so
/// a timer an actor schedules fires only when a test moves time to it.
pub struct ManualClock {
    state: Mutex<State>,
}

struct State {
    wall_ms: u64,
    monotonic: Duration,
    /// Pending sleeps: the monotonic deadline and who to wake.
    sleepers: Vec<(Duration, oneshot::Sender<()>)>,
}

impl ManualClock {
    pub fn new(wall_ms: u64) -> Arc<ManualClock> {
        Arc::new(ManualClock {
            state: Mutex::new(State {
                wall_ms,
                monotonic: Duration::ZERO,
                sleepers: Vec::new(),
            }),
        })
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Moves both clocks forward by `d` and wakes the sleeps that are due.
    pub fn advance(&self, d: Duration) {
        let due = {
            let mut st = self.state();
            st.wall_ms = st
                .wall_ms
                .saturating_add(u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
            st.monotonic += d;
            let now = st.monotonic;
            let (due, pending) = std::mem::take(&mut st.sleepers)
                .into_iter()
                .partition::<Vec<_>, _>(|(deadline, _)| *deadline <= now);
            st.sleepers = pending;
            due
        };
        for (_, wake) in due {
            let _ = wake.send(());
        }
    }
}

impl Clock for ManualClock {
    fn wall_ms(&self) -> u64 {
        self.state().wall_ms
    }

    fn monotonic(&self) -> Duration {
        self.state().monotonic
    }

    fn sleep(&self, d: Duration) -> BoxFuture<'static, ()> {
        if d.is_zero() {
            return Box::pin(std::future::ready(()));
        }
        let (tx, rx) = oneshot::channel();
        let mut st = self.state();
        // Sleeps that were dropped (a select! that took another branch) go.
        st.sleepers.retain(|(_, wake)| !wake.is_closed());
        let deadline = st.monotonic + d;
        st.sleepers.push((deadline, tx));
        Box::pin(async move {
            let _ = rx.await;
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn sleeps_end_when_the_clock_passes_them() {
        let clock = ManualClock::new(1_000);
        let short = clock.sleep(Duration::from_millis(10));
        let long = clock.sleep(Duration::from_millis(100));
        clock.advance(Duration::from_millis(50));
        short.await;
        assert_eq!(clock.wall_ms(), 1_050);
        assert_eq!(clock.state().sleepers.len(), 1);
        clock.advance(Duration::from_millis(50));
        long.await;
        assert_eq!(clock.monotonic(), Duration::from_millis(100));
    }
}

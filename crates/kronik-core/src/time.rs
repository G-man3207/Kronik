//! Logical time (I15).
//!
//! A turn's `now-ms` is `max(wall clock, high-water mark, parent time)`. The
//! high-water mark is the largest logical time handed out so far; at startup
//! it is the largest logical time in the log plus 1 ms. So time never goes
//! backwards when the host clock does, survives restarts, and a receiver
//! never runs earlier than the message or timer that started it. Within one
//! run several turns may share a millisecond (strictly increasing time would
//! drift ahead of the wall clock above 1000 turns per second).

use std::sync::Mutex;

use crate::env::Clock;

pub struct LogicalClock {
    hwm: Mutex<u64>,
}

impl LogicalClock {
    /// `recovered_max` is the largest logical time found in the log (0 for an
    /// empty log).
    pub fn new(recovered_max: u64) -> LogicalClock {
        LogicalClock {
            hwm: Mutex::new(if recovered_max == 0 {
                0
            } else {
                recovered_max + 1
            }),
        }
    }

    /// The logical time for a new turn whose triggering message or timer
    /// carries `parent` (0 for root inputs).
    pub fn next(&self, clock: &dyn Clock, parent: u64) -> u64 {
        let wall = clock.wall_ms();
        let mut hwm = self.hwm.lock().unwrap_or_else(|e| e.into_inner());
        let t = wall.max(*hwm).max(parent);
        *hwm = t;
        t
    }

    /// The largest time handed out so far.
    pub fn high_water(&self) -> u64 {
        *self.hwm.lock().unwrap_or_else(|e| e.into_inner())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Duration;

    use super::*;
    use crate::env::BoxFuture;

    struct Fixed(AtomicU64);
    impl Clock for Fixed {
        fn wall_ms(&self) -> u64 {
            self.0.load(Ordering::SeqCst)
        }
        fn monotonic(&self) -> Duration {
            Duration::ZERO
        }
        fn sleep(&self, _d: Duration) -> BoxFuture<'static, ()> {
            Box::pin(async {})
        }
    }

    #[test]
    fn clock_jump_back_never_lowers_time() {
        let c = Fixed(AtomicU64::new(1_000));
        let lc = LogicalClock::new(0);
        assert_eq!(lc.next(&c, 0), 1_000);
        c.0.store(500, Ordering::SeqCst);
        assert_eq!(lc.next(&c, 0), 1_000);
        assert_eq!(lc.next(&c, 2_000), 2_000);
        assert_eq!(lc.next(&c, 0), 2_000);
        // After a restart with a clock behind the log.
        let lc = LogicalClock::new(2_000);
        assert_eq!(lc.next(&c, 0), 2_001);
    }
}

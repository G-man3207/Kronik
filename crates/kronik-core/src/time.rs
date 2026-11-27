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
use crate::sync::lock;

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
        let mut hwm = lock(&self.hwm);
        let t = wall.max(*hwm).max(parent);
        *hwm = t;
        t
    }

    /// The largest time handed out so far.
    pub fn high_water(&self) -> u64 {
        *lock(&self.hwm)
    }
}

/// The proleptic Gregorian date `(year, month, day)` of a day count since
/// 1970-01-01 (Howard Hinnant's `civil_from_days`, for non-negative days).
pub fn civil_from_days(days: u64) -> (u64, u64, u64) {
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z % 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + u64::from(month <= 2);
    (year, month, day)
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

    #[test]
    fn civil_dates_cover_leap_years_and_centuries() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(1), (1970, 1, 2));
        assert_eq!(civil_from_days(59), (1970, 3, 1));
        assert_eq!(civil_from_days(789), (1972, 2, 29));
        assert_eq!(civil_from_days(11_016), (2000, 2, 29));
        assert_eq!(civil_from_days(47_482), (2100, 1, 1));
        assert_eq!(civil_from_days(47_541), (2100, 3, 1));
        assert_eq!(civil_from_days(2_932_896), (9999, 12, 31));
    }
}

//! The retention plan (docs/design/m6-storage.md §2, §5): which snapshots
//! are kept, and the base every fork point in the history window starts
//! from. Simulates hourly snapshots over weeks of logical time.

use super::*;

const HOUR: u64 = 3_600_000;
const DAY: u64 = 24 * HOUR;

/// Hourly snapshots of a node with one LSN per minute, from hour 1 to
/// `hours`, pruned after each as `retain` does, with compaction moving the
/// log's start to the window's base. Returns the snapshots left, the log's
/// first LSN and the cutoff.
fn run(hours: u64, history: u64, kept: usize) -> (Vec<SnapshotPoint>, Lsn, u64) {
    let step = (history / 7).max(HOUR);
    let mut snaps: Vec<SnapshotPoint> = Vec::new();
    let mut log_first: Lsn = 1;
    let mut cutoff = 0;
    for h in 1..=hours {
        let now = h * HOUR;
        snaps.push(SnapshotPoint {
            lsn: h * 60,
            logical_time_ms: now,
        });
        cutoff = now.saturating_sub(history);
        let plan = retention_plan(&snaps, log_first, cutoff, kept, step, None);
        // Compaction: whole hours older than the window go, never past the
        // base's cut, so the base stays usable.
        if let Some(base) = plan.base {
            let window_start = cutoff / HOUR * 60;
            log_first = log_first.max((base + 1).min(window_start.max(1)));
        }
        snaps.retain(|s| plan.keep.contains(&s.lsn));
    }
    (snaps, log_first, cutoff)
}

/// The newest snapshot at or before `lsn` that the log continues: the
/// base `pick_base` gives a fork at `lsn`.
fn base_for(snaps: &[SnapshotPoint], log_first: Lsn, lsn: Lsn) -> Option<SnapshotPoint> {
    snaps
        .iter()
        .rev()
        .find(|s| s.lsn <= lsn && (log_first <= 1 || s.lsn + 1 >= log_first))
        .copied()
}

#[test]
fn every_point_in_the_window_has_a_base_as_the_window_moves() {
    let history = 7 * DAY;
    // Check after every hour of three weeks: the base moves many times.
    for hours in (7 * 24..21 * 24).step_by(5) {
        let (snaps, log_first, cutoff) = run(hours, history, 48);
        let oldest_in_window = (cutoff / 60_000).max(1);
        // The log still reaches the window's start.
        assert!(log_first <= oldest_in_window, "hour {hours}");
        if log_first <= 1 {
            // Nothing compacted yet: a replay starts at LSN 1.
            continue;
        }
        let base = base_for(&snaps, log_first, oldest_in_window)
            .unwrap_or_else(|| panic!("hour {hours}: no base for the window's oldest point"));
        // The base is at most a step (a day) and an interval older than the
        // window's start, so is the log's start.
        assert!(
            cutoff - base.logical_time_ms <= DAY + HOUR,
            "hour {hours}: base {} is too old for cutoff {cutoff}",
            base.logical_time_ms
        );
        assert!(log_first <= base.lsn + 1);
        // About 48 + 7 snapshots, not one per hour of the window.
        assert!(
            snaps.len() <= 48 + 9,
            "hour {hours}: {} snapshots",
            snaps.len()
        );
    }
}

#[test]
fn a_cursor_older_than_the_newest_kept_applies_at_most_a_step() {
    let history = 7 * DAY;
    let (snaps, log_first, cutoff) = run(15 * 24, history, 48);
    let now = 15 * DAY;
    for point_ms in (cutoff..now).step_by(HOUR as usize) {
        let lsn = point_ms / 60_000;
        let base = base_for(&snaps, log_first, lsn).expect("a base");
        let behind = point_ms - base.logical_time_ms;
        // The newest 48 hourly snapshots span the last 47 hours.
        let bound = if now - point_ms <= 47 * HOUR {
            HOUR
        } else {
            DAY + HOUR
        };
        assert!(
            behind <= bound,
            "a fork at {point_ms} starts {behind} ms back"
        );
    }
}

#[test]
fn no_base_is_chosen_before_a_snapshot_is_older_than_the_window() {
    // A young node: nothing is old enough, so compaction deletes nothing,
    // and the oldest snapshot is kept to become the base.
    let snaps: Vec<SnapshotPoint> = (1..=60)
        .map(|h| SnapshotPoint {
            lsn: h * 60,
            logical_time_ms: h * HOUR,
        })
        .collect();
    let plan = retention_plan(&snaps, 1, 0, 48, DAY, None);
    assert_eq!(plan.base, None);
    assert!(
        plan.keep.contains(&60),
        "the oldest is kept as the base to be"
    );
    assert_eq!(plan.keep.len(), 48 + 1);
}

#[test]
fn a_zero_window_bases_on_the_newest_snapshot() {
    // history = 0 (tests): the newest snapshot's state is the window's
    // start, so it is the base and nothing older is kept.
    let snaps: Vec<SnapshotPoint> = (1..=5)
        .map(|i| SnapshotPoint {
            lsn: i * 10,
            logical_time_ms: i * 1000,
        })
        .collect();
    let plan = retention_plan(&snaps, 25, 5000, 2, 3_600_000, None);
    assert_eq!(plan.base, Some(50));
    assert_eq!(plan.keep.iter().copied().collect::<Vec<_>>(), vec![40, 50]);
}

#[test]
fn after_an_erasure_the_first_snapshot_after_it_is_the_base() {
    // The erasure at 300 deleted every snapshot before it; none after it
    // is older than the window yet.
    let snaps: Vec<SnapshotPoint> = (5..=8)
        .map(|h| SnapshotPoint {
            lsn: h * 60,
            logical_time_ms: h * HOUR,
        })
        .collect();
    let plan = retention_plan(&snaps, 100, HOUR, 2, DAY, Some(300));
    assert_eq!(plan.base, Some(300));
    assert!(plan.keep.contains(&300));
    // Without an erasure there is no base yet.
    assert_eq!(retention_plan(&snaps, 100, HOUR, 2, DAY, None).base, None);
}

#[test]
fn a_snapshot_the_log_no_longer_continues_is_never_the_base() {
    let snaps = [
        SnapshotPoint {
            lsn: 10,
            logical_time_ms: 1000,
        },
        SnapshotPoint {
            lsn: 50,
            logical_time_ms: 2000,
        },
    ];
    // The log starts at 40: 10 is useless, 50 is usable and old enough.
    let plan = retention_plan(&snaps, 40, 2500, 1, 10_000, None);
    assert_eq!(plan.base, Some(50));
    assert!(!plan.keep.contains(&10));
}

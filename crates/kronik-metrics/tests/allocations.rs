//! Recording a label set that the registry already holds allocates nothing
//! (issue #273). Every turn, connection frame, log write and HTTP request
//! records, so a key built per call put its garbage on every hot path.

// A global allocator is `unsafe` to implement. This one counts the calls
// and forwards each to the system allocator; it serves this test binary.
#![allow(unsafe_code)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};
use std::time::Duration;

static ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);

struct Counting;

// SAFETY: every call is forwarded to the system allocator with the
// caller's pointer, layout and size.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Relaxed);
        // SAFETY: as the impl says.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: as the impl says.
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Relaxed);
        // SAFETY: as the impl says.
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static GLOBAL: Counting = Counting;

/// The heap allocations made while `f` runs.
fn allocated(f: impl FnOnce()) -> usize {
    let before = ALLOCATIONS.load(Relaxed);
    f();
    ALLOCATIONS.load(Relaxed) - before
}

const FRAMES: [(&str, &str); 3] = [
    ("kind", "chat"),
    ("protocol", "websocket"),
    ("direction", "out"),
];

#[test]
fn recording_a_label_set_the_registry_holds_allocates_nothing() {
    let recorders: [(&str, fn()); 6] = [
        ("inc", || {
            kronik_metrics::inc("kronik_connection_frames_total", &FRAMES)
        }),
        ("add, the same label set in another order", || {
            kronik_metrics::add(
                "kronik_connection_frames_total",
                &[
                    ("direction", "out"),
                    ("kind", "chat"),
                    ("protocol", "websocket"),
                ],
                3,
            )
        }),
        ("add, another metric with the same labels", || {
            kronik_metrics::add("kronik_connection_frame_bytes_total", &FRAMES, 1024)
        }),
        ("set", || {
            kronik_metrics::set(
                "kronik_connections_open",
                &[("protocol", "websocket"), ("kind", "chat")],
                1.0,
            )
        }),
        ("observe, no label", || {
            kronik_metrics::observe(
                "kronik_log_fsync_duration_seconds",
                &[],
                Duration::from_millis(3),
            )
        }),
        ("timer, a label it borrows", || {
            let kind = *b"chat";
            let kind = std::str::from_utf8(&kind).unwrap();
            drop(kronik_metrics::timer(
                "kronik_turn_duration_seconds",
                ("kind", kind),
                || Duration::ZERO,
            ));
        }),
    ];
    // The first use of a label set interns it, so it allocates: the zeros
    // below say something.
    let first = allocated(|| {
        for (_, record) in recorders {
            record();
        }
    });
    assert!(first > 0, "the first use of a label set allocated nothing");
    for (what, record) in recorders {
        for _ in 0..1_000 {
            assert_eq!(allocated(record), 0, "{what}");
        }
    }
    // Both recorders of the label set wrote one series, in either order.
    let mut frames: Vec<_> = kronik_metrics::snapshot()
        .into_iter()
        .filter(|s| s.def.name == "kronik_connection_frames_total")
        .map(|s| (s.labels, s.value))
        .collect();
    assert_eq!(frames.len(), 1, "{frames:?}");
    let (labels, value) = frames.pop().unwrap();
    assert_eq!(
        labels,
        [
            ("direction", "out".into()),
            ("kind", "chat".into()),
            ("protocol", "websocket".into()),
        ]
    );
    assert_eq!(value, kronik_metrics::SampleValue::Counter(4_004));
}

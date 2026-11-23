//! Synchronization helpers shared by every Kronik crate.

use std::sync::{Mutex, MutexGuard, PoisonError};

/// Locks `m`, and hands out its data even when the mutex is poisoned (a
/// thread panicked while holding it): a panic is a bug in the daemon, and it
/// must not also fail every later lock of the same mutex.
pub fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;

    // Only a thread that panics while holding the mutex can poison it.
    #[allow(clippy::disallowed_methods)]
    #[test]
    fn a_poisoned_mutex_still_hands_out_its_data() {
        let m = Arc::new(Mutex::new(7));
        let held = Arc::clone(&m);
        let panicked = std::thread::spawn(move || {
            let _guard = held.lock().unwrap();
            panic!("poison the mutex");
        })
        .join();
        assert!(panicked.is_err());
        assert!(m.is_poisoned());
        assert_eq!(*lock(&m), 7);
    }
}

//! A retained current-name selection is DATA, never authority to use its value.
use std::future::{Future, poll_fn};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration;

use kronik_core::env::Clock;
use kronik_core::error::{ApiError, ErrorCode};
use kronik_proto::log::v1 as pb;
use tokio::sync::Notify;
use zeroize::Zeroizing;

type DataPublication = dyn Fn(
        &[CurrentSecretSelection],
        &mut Option<ApiError>,
        &mut dyn FnMut() -> Result<(), ApiError>,
    ) -> Result<(), ApiError>
    + Send
    + Sync;
struct Selection {
    record: pb::SecretVersion,
    value: Arc<Zeroizing<Vec<u8>>>,
    until: Duration,
    clock: Arc<dyn Clock>,
    changed: Arc<Notify>,
    current: Box<dyn Fn() -> bool + Send + Sync>,
    publication: Box<DataPublication>,
    live: AtomicBool,
}

/// The caller must conjoin this selection with its SAME complete original
/// authority at final admission, and retain it through the running consumer.
#[derive(Clone)]
pub struct CurrentSecretSelection(Arc<Selection>);

fn unavailable() -> ApiError {
    ApiError::new(
        ErrorCode::SecretUnavailable,
        "the operational current secret selection ended",
    )
}

impl CurrentSecretSelection {
    /// `current` only compares facts from the actual original publisher. It
    /// must perform no IO, lookup, lock acquisition or authority admission.
    pub fn new(
        record: pb::SecretVersion,
        value: Arc<Zeroizing<Vec<u8>>>,
        until: Duration,
        clock: Arc<dyn Clock>,
        changed: Arc<Notify>,
        current: Box<dyn Fn() -> bool + Send + Sync>,
        publication: Box<DataPublication>,
    ) -> Result<Self, ApiError> {
        if record.phase != pb::secret_version::Phase::Active as i32
            || record.deleted
            || record.version_hash.len() != 16
            || kronik_proto::validate_secret_version(&record).is_err()
            || clock.monotonic() >= until
            || !current()
        {
            return Err(unavailable());
        }
        Ok(Self(Arc::new(Selection {
            record,
            value,
            until,
            clock,
            changed,
            current,
            publication,
            live: AtomicBool::new(true),
        })))
    }

    pub fn record(&self) -> &pb::SecretVersion {
        &self.0.record
    }
    pub fn value(&self) -> &Arc<Zeroizing<Vec<u8>>> {
        &self.0.value
    }

    /// Pure DATA check inside the original publisher's existing admission.
    /// A retired selection never revives, even if an old scalar reappears.
    pub fn data_is_current_under_publication(&self) -> bool {
        if !self.0.live.load(Ordering::Acquire) {
            return false;
        }
        if self.0.clock.monotonic() >= self.0.until || !(self.0.current)() {
            self.0.live.store(false, Ordering::Release);
            return false;
        }
        true
    }
    /// One bounded DATA fence, inside the caller's SAME original admission.
    /// Prepare the one-shot denial before that admission; no error is allocated here.
    pub fn with_data_under_publication(
        &self,
        selections: &[Self],
        denial: &mut Option<ApiError>,
        enqueue: &mut dyn FnMut() -> Result<(), ApiError>,
    ) -> Result<(), ApiError> {
        if denial.is_none()
            || selections
                .iter()
                .any(|selection| !Arc::ptr_eq(&self.0.changed, &selection.0.changed))
        {
            return Err(denial.take().unwrap_or_else(|| ApiError {
                code: ErrorCode::SecretUnavailable,
                message: String::new(),
                hint: None,
            }));
        }
        (self.0.publication)(selections, denial, enqueue)
    }

    pub fn is_from_publication(&self, changed: &Arc<Notify>) -> bool {
        Arc::ptr_eq(&self.0.changed, changed)
    }

    pub fn cancelled(&self) -> impl Future<Output = ()> + Send + 'static {
        let selection = self.clone();
        async move {
            loop {
                let mut changed = std::pin::pin!(selection.0.changed.notified());
                changed.as_mut().enable();
                if !selection.data_is_current_under_publication() {
                    return;
                }
                let remaining = selection
                    .0
                    .until
                    .saturating_sub(selection.0.clock.monotonic());
                let mut timeout = selection.0.clock.sleep(remaining);
                poll_fn(|cx| {
                    if changed.as_mut().poll(cx).is_ready() || timeout.as_mut().poll(cx).is_ready()
                    {
                        std::task::Poll::Ready(())
                    } else {
                        std::task::Poll::Pending
                    }
                })
                .await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kronik_core::env::BoxFuture;
    use std::sync::atomic::AtomicU64;

    struct TestClock {
        now: AtomicU64,
        changed: Arc<Notify>,
    }
    impl Clock for TestClock {
        fn wall_ms(&self) -> u64 {
            self.now.load(Ordering::Acquire)
        }
        fn monotonic(&self) -> Duration {
            Duration::from_millis(self.wall_ms())
        }
        fn sleep(&self, _: Duration) -> BoxFuture<'static, ()> {
            let changed = self.changed.clone();
            Box::pin(async move {
                changed.notified().await;
            })
        }
    }
    fn record() -> pb::SecretVersion {
        pb::SecretVersion {
            name: "token".into(),
            version: 1,
            version_hash: vec![7; 16],
            backend: "file".into(),
            binding: "file".into(),
            r#ref: "token".into(),
            canonical_ref: "token".into(),
            source_version: "1".into(),
            hash_revision: 1,
            phase: pb::secret_version::Phase::Active as i32,
            audit: Some(pb::Audit {
                token_id: "operator".into(),
                reason: "select current".into(),
                wall_time_ms: 1,
            }),
            ..Default::default()
        }
    }
    fn publication() -> Box<DataPublication> {
        let state = std::sync::Mutex::new(());
        Box::new(move |selections, denial, enqueue| {
            let _state = state
                .try_lock()
                .map_err(|_| denial.take().expect("one test handoff"))?;
            if selections
                .iter()
                .any(|selection| !selection.data_is_current_under_publication())
            {
                return Err(denial.take().expect("one test handoff"));
            }
            enqueue()
        })
    }

    #[test]
    fn a_consumed_denial_cannot_enqueue_a_later_frame() {
        let clock = Arc::new(TestClock {
            now: AtomicU64::new(1),
            changed: Arc::new(Notify::new()),
        });
        let first = CurrentSecretSelection::new(
            record(),
            Arc::new(Zeroizing::new(vec![1])),
            Duration::from_millis(10),
            clock.clone(),
            Arc::new(Notify::new()),
            Box::new(|| true),
            publication(),
        )
        .unwrap();
        let other = CurrentSecretSelection::new(
            record(),
            Arc::new(Zeroizing::new(vec![2])),
            Duration::from_millis(10),
            clock,
            Arc::new(Notify::new()),
            Box::new(|| true),
            publication(),
        )
        .unwrap();
        let (sender, receiver) = std::sync::mpsc::sync_channel(1);
        let mut enqueue = || {
            sender
                .try_send("one exact prepared frame")
                .map_err(|_| ApiError {
                    code: ErrorCode::Unavailable,
                    message: String::new(),
                    hint: None,
                })
        };
        let mut denial = Some(unavailable());
        assert_eq!(
            first
                .with_data_under_publication(&[first.clone(), other], &mut denial, &mut enqueue)
                .unwrap_err()
                .code,
            ErrorCode::SecretUnavailable
        );
        assert_eq!(
            first
                .with_data_under_publication(
                    std::slice::from_ref(&first),
                    &mut denial,
                    &mut enqueue
                )
                .unwrap_err()
                .code,
            ErrorCode::SecretUnavailable
        );
        assert!(matches!(
            receiver.try_recv(),
            Err(std::sync::mpsc::TryRecvError::Empty)
        ));
        let mut fresh_denial = Some(unavailable());
        first
            .with_data_under_publication(
                std::slice::from_ref(&first),
                &mut fresh_denial,
                &mut enqueue,
            )
            .unwrap();
        assert_eq!(receiver.try_recv().unwrap(), "one exact prepared frame");
    }

    #[tokio::test]
    async fn a_selected_name_retires_on_rebind_and_never_revives() {
        let changed = Arc::new(Notify::new());
        let clock = Arc::new(TestClock {
            now: AtomicU64::new(1),
            changed: Arc::new(Notify::new()),
        });
        let revision = Arc::new(AtomicU64::new(3));
        let observed = revision.clone();
        let value = Arc::new(Zeroizing::new(b"selected value".to_vec()));
        let selection = CurrentSecretSelection::new(
            record(),
            value,
            Duration::from_millis(10),
            clock,
            changed.clone(),
            Box::new(move || observed.load(Ordering::Acquire) == 3),
            publication(),
        )
        .unwrap();
        assert_eq!(selection.value().as_slice(), b"selected value");
        assert!(selection.data_is_current_under_publication());
        let cancelled = selection.cancelled();
        tokio::pin!(cancelled);
        assert!(matches!(
            futures_poll(&mut cancelled),
            std::task::Poll::Pending
        ));
        revision.store(4, Ordering::Release);
        changed.notify_waiters();
        cancelled.await;
        revision.store(3, Ordering::Release);
        assert!(!selection.data_is_current_under_publication());
    }

    fn futures_poll<F: Future>(future: &mut std::pin::Pin<&mut F>) -> std::task::Poll<F::Output> {
        let waker = std::task::Waker::noop();
        future
            .as_mut()
            .poll(&mut std::task::Context::from_waker(waker))
    }

    #[tokio::test]
    async fn an_awaiting_consumer_expires_without_a_catalogue_notification() {
        let clock = Arc::new(TestClock {
            now: AtomicU64::new(1),
            changed: Arc::new(Notify::new()),
        });
        let selection = CurrentSecretSelection::new(
            record(),
            Arc::new(Zeroizing::new(vec![1])),
            Duration::from_millis(10),
            clock.clone(),
            Arc::new(Notify::new()),
            Box::new(|| true),
            publication(),
        )
        .unwrap();
        let cancelled = selection.cancelled();
        tokio::pin!(cancelled);
        assert!(matches!(
            futures_poll(&mut cancelled),
            std::task::Poll::Pending
        ));
        clock.now.store(10, Ordering::Release);
        clock.changed.notify_waiters();
        cancelled.await;
        assert!(!selection.data_is_current_under_publication());
    }

    #[tokio::test]
    async fn retained_deleted_or_pending_rows_are_not_current_selections() {
        let clock = Arc::new(TestClock {
            now: AtomicU64::new(1),
            changed: Arc::new(Notify::new()),
        });
        let mut deleted = record();
        deleted.deleted = true;
        assert!(
            CurrentSecretSelection::new(
                deleted,
                Arc::new(Zeroizing::new(vec![1])),
                Duration::from_millis(10),
                clock.clone(),
                Arc::new(Notify::new()),
                Box::new(|| true),
                publication()
            )
            .is_err()
        );
        let mut pending = record();
        pending.phase = pb::secret_version::Phase::Reserved as i32;
        assert!(
            CurrentSecretSelection::new(
                pending,
                Arc::new(Zeroizing::new(vec![1])),
                Duration::from_millis(10),
                clock,
                Arc::new(Notify::new()),
                Box::new(|| true),
                publication()
            )
            .is_err()
        );
    }
}

use super::*;
use exec::{Executor, RunEnd, SUPERVISOR};
use kronik_core::env::Stdio;

fn clock(handle: &Handle) -> Arc<dyn Clock> {
    Arc::new(SimClock {
        exec: handle.clone(),
        wall_base_ms: 0,
        wall_offset_ms: Arc::new(AtomicI64::new(0)),
    })
}

fn request(timeout: Duration) -> SensitiveProcessRequest {
    SensitiveProcessRequest {
        spec: ProcessSpec {
            program: "configured-helper".into(),
            args: vec![],
            env: vec![],
            cwd: None,
            stdout: Stdio::Null,
            stderr: Stdio::Null,
        },
        stdin: vec![b'x'].into(),
        pin_file: "configured-pin".into(),
        timeout,
    }
}

#[test]
fn sensitive_exchange_deadline_and_node_crash_are_sticky_reaped_states() {
    for cancel in [false, true] {
        for seed in 0..8 {
            let executor = Executor::new(seed);
            let handle = executor.handle();
            let process = Arc::new(SimProcess::new());
            let child = process.clone();
            let completed = Arc::new(AtomicBool::new(false));
            let result = completed.clone();
            let exchange =
                sensitive_exchange(clock(&handle), request(Duration::from_secs(1)), child);
            handle.spawn(
                1,
                "sensitive exchange",
                Box::pin(async move {
                    assert_eq!(exchange.await.unwrap_err().kind(), io::ErrorKind::TimedOut);
                    result.store(true, Ordering::SeqCst);
                }),
            );
            if cancel {
                let supervisor = handle.clone();
                handle.spawn(
                    SUPERVISOR,
                    "crash helper caller",
                    Box::pin(async move {
                        supervisor.sleep(Duration::from_millis(10)).await;
                        assert_eq!(supervisor.kill_node(1), 1);
                    }),
                );
            }
            assert_eq!(
                executor.run(100, || process.reaped.load(Ordering::SeqCst)),
                RunEnd::Stopped
            );
            assert!(*process.killed.borrow());
            assert!(process.reaped.load(Ordering::SeqCst));
            assert_eq!(completed.load(Ordering::SeqCst), !cancel);
            assert_eq!(
                handle.now(),
                if cancel {
                    Duration::from_millis(10)
                } else {
                    Duration::from_secs(1)
                }
            );
            assert!(handle.live_tasks(1).is_empty());
        }
    }
}

#[test]
fn ordinary_process_kill_before_wait_and_repeated_wait_cannot_lose_exit() {
    let executor = Executor::new(0);
    let handle = executor.handle();
    let process = Arc::new(SimProcess::new());
    let child = process.clone();
    handle.spawn(
        1,
        "sticky wait",
        Box::pin(async move {
            child.kill().await.unwrap();
            assert_eq!(child.wait().await.unwrap(), None);
            assert_eq!(child.wait().await.unwrap(), None);
        }),
    );
    assert_eq!(executor.run(100, || false), RunEnd::Quiescent);
    assert!(process.reaped.load(Ordering::SeqCst));
    assert!(handle.live_tasks(1).is_empty());
    assert_eq!(handle.now(), Duration::ZERO);
}

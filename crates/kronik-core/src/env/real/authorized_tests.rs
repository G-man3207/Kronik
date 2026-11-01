use super::*;
use crate::authority::Authority;
use crate::env::Env;
use crate::error::{ApiError, ErrorCode};
use bytes::Bytes;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use std::time::Duration;
use tokio::sync::Notify;

struct Gate {
    publication: Mutex<()>,
    revoked: Arc<AtomicBool>,
    changed: Arc<Notify>,
    final_calls: AtomicUsize,
    deny_at_send: bool,
    connection_ready: Mutex<Option<std::sync::mpsc::Receiver<()>>>,
}
impl Gate {
    fn new(
        deny_at_send: bool,
        connection_ready: Option<std::sync::mpsc::Receiver<()>>,
    ) -> Arc<Self> {
        Arc::new(Self {
            publication: Mutex::new(()),
            revoked: Arc::new(AtomicBool::new(false)),
            changed: Arc::new(Notify::new()),
            final_calls: AtomicUsize::new(0),
            deny_at_send,
            connection_ready: Mutex::new(connection_ready),
        })
    }
    fn revoke(&self) {
        let _publication = self.publication.lock().unwrap();
        self.revoked.store(true, Ordering::Release);
        self.changed.notify_waiters();
    }
}
impl Authority for Gate {
    fn check(&self) -> Result<(), ApiError> {
        if self.revoked.load(Ordering::Acquire) {
            Err(ApiError::new(ErrorCode::Unauthenticated, "test revoked"))
        } else {
            Ok(())
        }
    }
    fn cancelled(&self) -> BoxFuture<'static, ()> {
        let revoked = self.revoked.clone();
        let changed = self.changed.clone();
        Box::pin(async move {
            loop {
                let notified = changed.notified();
                tokio::pin!(notified);
                notified.as_mut().enable();
                if revoked.load(Ordering::Acquire) {
                    return;
                }
                notified.await;
            }
        })
    }
    fn admit(&self, effect: &mut dyn FnMut() -> Result<(), ApiError>) -> Result<(), ApiError> {
        if let Some(ready) = self.connection_ready.lock().unwrap().take() {
            ready.recv_timeout(Duration::from_secs(2)).expect(
                "final admission must follow actual connection readiness, not a lazy client future",
            );
        }
        let _publication = self.publication.lock().unwrap();
        self.final_calls.fetch_add(1, Ordering::SeqCst);
        if self.deny_at_send {
            self.revoked.store(true, Ordering::Release);
            self.changed.notify_waiters();
        }
        self.check()?;
        effect()
    }
}
fn request(address: std::net::SocketAddr) -> HttpRequest {
    HttpRequest {
        method: "POST".into(),
        url: format!("http://{address}/effect"),
        headers: Vec::new(),
        body: Bytes::from_static(b"payload"),
        max_response_bytes: 64,
    }
}
fn read_request(stream: &mut std::net::TcpStream) {
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let mut request = Vec::new();
    let mut buffer = [0; 1024];
    while !request.ends_with(b"payload") {
        let count = stream.read(&mut buffer).unwrap();
        assert!(count > 0);
        request.extend_from_slice(&buffer[..count]);
    }
}

#[tokio::test(flavor = "current_thread")]
async fn final_refusal_after_real_connection_ready_sends_no_http_bytes() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let (accepted, ready) = std::sync::mpsc::channel();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        accepted.send(()).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut bytes = [0; 1024];
        match stream.read(&mut bytes) {
            Ok(count) => count,
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                0
            }
            Err(error) => panic!("unexpected socket read: {error}"),
        }
    });
    let env = Env::real(tokio::runtime::Handle::current());
    let gate = Gate::new(true, Some(ready));
    assert!(matches!(
        env.net
            .http_authorized(request(address), gate.clone())
            .await,
        Err(NetError::Connect(_))
    ));
    assert_eq!(gate.final_calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        env.blocking("http-refusal-observer", move || server.join().unwrap())
            .await
            .unwrap(),
        0
    );
}

#[tokio::test(flavor = "current_thread")]
async fn an_actual_enqueued_request_finishes_after_revocation_without_re_admission() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let (seen, observed) = std::sync::mpsc::channel();
    let (release, wait) = std::sync::mpsc::channel();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        read_request(&mut stream);
        seen.send(()).unwrap();
        wait.recv_timeout(Duration::from_secs(3)).unwrap();
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            .unwrap();
    });
    let env = Env::real(tokio::runtime::Handle::current());
    let gate = Gate::new(false, None);
    let net = env.net.clone();
    let authority = gate.clone();
    let sent = env.spawn("http-admission-test", async move {
        net.http_authorized(request(address), authority).await
    });
    env.blocking("http-admission-observer", move || {
        observed.recv_timeout(Duration::from_secs(3)).unwrap()
    })
    .await
    .unwrap();
    gate.revoke();
    release.send(()).unwrap();
    let response = sent.await.unwrap().unwrap();
    assert_eq!(response.status, 200);
    assert_eq!(response.body, Bytes::from_static(b"ok"));
    assert_eq!(gate.final_calls.load(Ordering::SeqCst), 1);
    server.join().unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn original_and_completion_remain_owned_after_headers_until_actual_body_eof() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let (headers, observed) = std::sync::mpsc::channel();
    let (release, wait) = std::sync::mpsc::channel();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        read_request(&mut stream);
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n")
            .unwrap();
        stream.flush().unwrap();
        headers.send(()).unwrap();
        wait.recv_timeout(Duration::from_secs(3)).unwrap();
        stream.write_all(b"ok").unwrap();
    });
    let env = Env::real(tokio::runtime::Handle::current());
    let gate = Gate::new(false, None);
    let held = Arc::downgrade(&gate);
    let net = env.net.clone();
    let mut sent = env.spawn("http-body-eof-test", async move {
        net.http_authorized(request(address), gate).await
    });
    env.blocking("http-head-observer", move || {
        observed.recv_timeout(Duration::from_secs(3)).unwrap()
    })
    .await
    .unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(100), &mut sent)
            .await
            .is_err(),
        "response headers cannot complete a byte-body request"
    );
    let original = held
        .upgrade()
        .expect("the actual response body must retain the original scope");
    assert_eq!(original.final_calls.load(Ordering::SeqCst), 1);
    original.revoke();
    drop(original);
    release.send(()).unwrap();
    assert_eq!(sent.await.unwrap().unwrap().body, Bytes::from_static(b"ok"));
    assert!(
        held.upgrade().is_none(),
        "body EOF releases the original scope"
    );
    server.join().unwrap();
}

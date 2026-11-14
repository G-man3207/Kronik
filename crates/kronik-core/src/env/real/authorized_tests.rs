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

/// A source of `chunks`, for a streamed request body.
struct Chunks(std::collections::VecDeque<Bytes>);

impl crate::env::BodySource for Chunks {
    fn next(&mut self) -> BoxFuture<'_, std::io::Result<Option<Bytes>>> {
        let chunk = self.0.pop_front();
        Box::pin(async move { Ok(chunk) })
    }
}

/// Reads one request's head and `Content-Length` body.
fn read_whole_request(stream: &mut std::net::TcpStream) -> (String, Vec<u8>) {
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let mut data = Vec::new();
    let mut buffer = [0; 4096];
    let head_end = loop {
        if let Some(at) = data.windows(4).position(|w| w == b"\r\n\r\n") {
            break at + 4;
        }
        let count = stream.read(&mut buffer).unwrap();
        assert!(count > 0);
        data.extend_from_slice(&buffer[..count]);
    };
    let head = String::from_utf8_lossy(&data[..head_end]).into_owned();
    let len: usize = head
        .lines()
        .find_map(|l| {
            let (name, value) = l.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse().unwrap())
        })
        .unwrap_or(0);
    while data.len() < head_end + len {
        let count = stream.read(&mut buffer).unwrap();
        assert!(count > 0);
        data.extend_from_slice(&buffer[..count]);
    }
    (head, data[head_end..head_end + len].to_vec())
}

/// M25 §7.1: a streamed request body arrives whole with its length, and a
/// response body is read as it arrives, in more than one chunk, and stops
/// with `response_too_large` past the request's limit.
#[tokio::test(flavor = "current_thread")]
async fn a_streamed_exchange_sends_and_reads_in_chunks() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let part = vec![b'x'; 100_000];
    let sent_part = part.clone();
    let server = std::thread::spawn(move || {
        let mut seen = Vec::new();
        for _ in 0..2 {
            let (mut stream, _) = listener.accept().unwrap();
            seen.push(read_whole_request(&mut stream));
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 300000\r\nConnection: close\r\n\r\n",
                )
                .unwrap();
            // The limited exchange stops reading and closes mid-body.
            for _ in 0..3 {
                if stream
                    .write_all(&sent_part)
                    .and_then(|()| stream.flush())
                    .is_err()
                {
                    break;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
        }
        seen
    });
    let env = Env::real(tokio::runtime::Handle::current());
    let request = |limit: u64, chunks: &[&'static [u8]]| crate::env::HttpStreamRequest {
        method: "POST".into(),
        url: format!("http://{address}/stream"),
        headers: Vec::new(),
        body: crate::env::HttpBody::Stream {
            len: chunks.iter().map(|c| c.len() as u64).sum(),
            source: Box::new(Chunks(
                chunks.iter().map(|c| Bytes::from_static(c)).collect(),
            )),
        },
        max_response_bytes: limit,
    };
    let mut response = env
        .net
        .http_stream_authorized(
            request(1 << 20, &[b"first ", b"second ", b"third"]),
            Gate::new(false, None),
        )
        .await
        .unwrap();
    assert_eq!(response.status, 200);
    let mut body = Vec::new();
    let mut chunks = 0;
    while let Some(chunk) = response.body.next().await.unwrap() {
        chunks += 1;
        body.extend_from_slice(&chunk);
    }
    assert_eq!(body.len(), 300_000);
    assert!(body.iter().all(|b| *b == b'x'));
    assert!(chunks > 1, "the body arrived in {chunks} chunk(s)");

    let mut limited = env
        .net
        .http_stream_authorized(request(150_000, &[b"again"]), Gate::new(false, None))
        .await
        .unwrap();
    let mut read = 0;
    let error = loop {
        match limited.body.next().await {
            Ok(Some(chunk)) => read += chunk.len(),
            Ok(None) => panic!("the body ended at {read} bytes, past its limit"),
            Err(error) => break error,
        }
    };
    assert!(crate::env::is_response_too_large(&error), "{error}");
    assert!(read <= 150_000);
    drop(limited);
    let seen = server.join().unwrap();
    assert_eq!(seen[0].1, b"first second third");
    assert!(
        seen[0]
            .0
            .to_ascii_lowercase()
            .contains("content-length: 18"),
        "{}",
        seen[0].0
    );
    assert_eq!(seen[1].1, b"again");
}

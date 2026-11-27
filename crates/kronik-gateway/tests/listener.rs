//! The gateway's TCP listener (`server::serve`) with a TLS configuration:
//! a request is served over TLS, a TLS-ALPN-01 validation by an ACME CA
//! ends after the handshake (ADR 0009), and a connection over its client's
//! share of the slots is answered 503, plain or over TLS.
#![cfg(feature = "server")]
// Test helpers outside #[test] functions may unwrap too; the tests run on
// the tokio runtime directly.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::disallowed_methods)]

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::room_node;
use kronik_gateway::tls::ACME_TLS_ALPN;
use kronik_sched::connections::ConnectionsConfig;
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio::net::TcpStream;

trait Stream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Stream for T {}

const GET: &str = "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
const KEEP_ALIVE: &str = "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n";
/// Longer than the gateway takes to answer or to refuse a connection.
const LIMIT: Duration = Duration::from_secs(10);

/// The gateway's TLS configuration for a self-signed certificate of
/// `localhost`, with the ALPN list of `tls::start`, and a client's that
/// trusts only that certificate. The gateway's resolver answers an
/// `acme-tls/1` ClientHello with a challenge certificate, which exists only
/// during an ACME order; this one answers every handshake with the same
/// certificate.
fn tls_configs() -> (Arc<rustls::ServerConfig>, Arc<rustls::ClientConfig>) {
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = rcgen::CertificateParams::new(vec!["localhost".into()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut server = rustls::ServerConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.der().clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
        )
        .unwrap();
    server.alpn_protocols = vec![b"http/1.1".to_vec(), ACME_TLS_ALPN.to_vec()];
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.der().clone()).unwrap();
    let client = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    (Arc::new(server), Arc::new(client))
}

/// A connection to the gateway; over TLS when `tls` is given, offering
/// `alpn` alone. A slot the gateway does not give back parks the handshake,
/// so that is bounded too.
async fn connect(
    addr: std::net::SocketAddr,
    tls: Option<&Arc<rustls::ClientConfig>>,
    alpn: &[u8],
) -> Box<dyn Stream> {
    let tcp = TcpStream::connect(addr).await.unwrap();
    let Some(tls) = tls else {
        return Box::new(tcp);
    };
    let mut config = (**tls).clone();
    config.alpn_protocols = vec![alpn.to_vec()];
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
    let tls = tokio::time::timeout(LIMIT, connector.connect(name, tcp))
        .await
        .expect("the gateway takes the handshake")
        .unwrap();
    assert_eq!(tls.get_ref().1.alpn_protocol(), Some(alpn));
    Box::new(tls)
}

/// `request` on a new connection; the whole answer.
async fn answer(
    addr: std::net::SocketAddr,
    tls: Option<&Arc<rustls::ClientConfig>>,
    request: &str,
) -> String {
    let mut s = connect(addr, tls, b"http/1.1").await;
    s.write_all(request.as_bytes()).await.unwrap();
    let mut bytes = Vec::new();
    // The server may close without close_notify after the answer.
    let _ = tokio::time::timeout(LIMIT, s.read_to_end(&mut bytes))
        .await
        .expect("the gateway answers and closes");
    String::from_utf8_lossy(&bytes).into_owned()
}

/// Reads through the end of the answer's head on an open connection.
async fn read_head(s: &mut dyn Stream) {
    tokio::time::timeout(LIMIT, async {
        let mut bytes = Vec::new();
        let mut buf = [0u8; 1024];
        while !bytes.windows(4).any(|w| w == b"\r\n\r\n") {
            let n = s.read(&mut buf).await.unwrap();
            assert!(
                n > 0,
                "closed before a whole head: {}",
                String::from_utf8_lossy(&bytes)
            );
            bytes.extend_from_slice(&buf[..n]);
        }
    })
    .await
    .expect("the gateway answers");
}

/// The gateway has one slot: a validation that kept its connection would
/// hold it, and the request after it would not be answered.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_acme_validation_ends_after_the_handshake() {
    let (_dir, node) = room_node(ConnectionsConfig::default()).await;
    let (server, client) = tls_configs();
    let (addr, _task) = common::serve(&node, Some(server), 1).await;

    let served = answer(addr, Some(&client), GET).await;
    assert!(served.contains("ROUTE_NOT_FOUND"), "{served}");

    let mut validation = connect(addr, Some(&client), ACME_TLS_ALPN).await;
    let mut sent = Vec::new();
    let closed =
        tokio::time::timeout(Duration::from_secs(5), validation.read_to_end(&mut sent)).await;
    assert!(closed.is_ok(), "the validation's connection stayed open");
    assert!(
        sent.is_empty(),
        "the validation's connection got {}",
        String::from_utf8_lossy(&sent)
    );

    let served = answer(addr, Some(&client), GET).await;
    assert!(served.contains("ROUTE_NOT_FOUND"), "{served}");
}

/// Four of the gateway's eight slots are one client address's share (a
/// quarter of them, and at least four); a connection over it is answered
/// 503 and `retry-after`, plain or over TLS.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_connection_over_its_clients_share_is_answered_503_plain_and_over_tls() {
    let (_dir, node) = room_node(ConnectionsConfig::default()).await;
    let (config, client) = tls_configs();
    for server in [None, Some(config)] {
        let tls = server.as_ref().map(|_| &client);
        let (addr, _task) = common::serve(&node, server, 8).await;

        // Answered requests on connections that then stay open hold it.
        let mut held = Vec::new();
        for _ in 0..4 {
            let mut s = connect(addr, tls, b"http/1.1").await;
            s.write_all(KEEP_ALIVE.as_bytes()).await.unwrap();
            read_head(&mut s).await;
            held.push(s);
        }
        let refused = answer(addr, tls, GET).await;
        assert!(
            refused.starts_with("HTTP/1.1 503 Service Unavailable"),
            "{refused}"
        );
        assert!(
            refused.contains("too many connections from this address"),
            "{refused}"
        );
        assert!(refused.contains("retry-after: 1"), "{refused}");
    }
}

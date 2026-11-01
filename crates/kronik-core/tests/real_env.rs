#![cfg(all(feature = "real", feature = "host-identity"))]
#![allow(clippy::disallowed_methods)]

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use futures_util::{SinkExt as _, StreamExt as _};
use kronik_core::env::{Env, HttpRequest, NetError, TlsConfig, WebSocketRequest};
use rustls::pki_types::PrivatePkcs8KeyDer;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio_tungstenite::tungstenite::Message;

const DEADLINE: Duration = Duration::from_secs(5);

struct Certificates {
    ca: Vec<u8>,
    client: Vec<u8>,
    key: Vec<u8>,
    ordinary: rustls::ServerConfig,
    authenticated: rustls::ServerConfig,
}

fn certificates() -> Certificates {
    let root_key = rcgen::KeyPair::generate().unwrap();
    let mut params = rcgen::CertificateParams::new(vec![]).unwrap();
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::CrlSign,
    ];
    let root = params.self_signed(&root_key).unwrap();
    let issuer = rcgen::Issuer::from_params(&params, &root_key);
    let server_key = rcgen::KeyPair::generate().unwrap();
    let mut params = rcgen::CertificateParams::new(vec!["localhost".into()]).unwrap();
    params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
    let server = params.signed_by(&server_key, &issuer).unwrap();
    let client_key = rcgen::KeyPair::generate().unwrap();
    let mut params = rcgen::CertificateParams::new(vec![]).unwrap();
    params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
    let client = params.signed_by(&client_key, &issuer).unwrap();
    let crypto = Arc::new(rustls::crypto::ring::default_provider());
    let builder = || {
        rustls::ServerConfig::builder_with_provider(crypto.clone())
            .with_safe_default_protocol_versions()
            .unwrap()
    };
    let key = || PrivatePkcs8KeyDer::from(server_key.serialize_der()).into();
    let ordinary = builder()
        .with_no_client_auth()
        .with_single_cert(vec![server.der().clone()], key())
        .unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(root.der().clone()).unwrap();
    let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
        Arc::new(roots),
        crypto.clone(),
    )
    .build()
    .unwrap();
    let authenticated = builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(vec![server.der().clone()], key())
        .unwrap();
    Certificates {
        ca: root.der().to_vec(),
        client: client.der().to_vec(),
        key: client_key.serialize_der(),
        ordinary,
        authenticated,
    }
}

impl Certificates {
    fn tls(&self, identity: bool) -> TlsConfig {
        TlsConfig {
            ca: vec![self.ca.clone()],
            identity: identity.then(|| (vec![self.client.clone()], self.key.clone())),
        }
    }
}

type Server = tokio::task::JoinHandle<Result<(), String>>;

async fn tls_server(
    config: rustls::ServerConfig,
    websocket: bool,
    client: Option<Vec<u8>>,
) -> (String, Server) {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        tokio::time::timeout(DEADLINE, async move {
            let (socket, _) = listener.accept().await.map_err(|e| e.to_string())?;
            let stream = tokio_rustls::TlsAcceptor::from(Arc::new(config))
                .accept(socket)
                .await
                .map_err(|e| e.to_string())?;
            if let Some(client) = client {
                let chain = stream
                    .get_ref()
                    .1
                    .peer_certificates()
                    .ok_or("missing client identity")?;
                assert_eq!(chain[0].as_ref(), client);
            }
            if websocket {
                let mut socket = tokio_tungstenite::accept_hdr_async(
                    stream,
                    |request: &tokio_tungstenite::tungstenite::handshake::server::Request,
                     response| {
                        assert_eq!(
                            request.headers().get("authorization").unwrap(),
                            "Bearer scoped"
                        );
                        Ok(response)
                    },
                )
                .await
                .map_err(|e| e.to_string())?;
                assert_eq!(
                    socket.next().await.unwrap().map_err(|e| e.to_string())?,
                    Message::Binary(Bytes::from_static(b"hello"))
                );
                socket
                    .send(Message::Ping(Bytes::from_static(b"p")))
                    .await
                    .map_err(|e| e.to_string())?;
                socket
                    .send(Message::Text("answer".into()))
                    .await
                    .map_err(|e| e.to_string())?;
                socket
                    .send(Message::Binary(Bytes::from_static(b"again")))
                    .await
                    .map_err(|e| e.to_string())?;
                assert_eq!(
                    socket.next().await.unwrap().map_err(|e| e.to_string())?,
                    Message::Pong(Bytes::from_static(b"p"))
                );
                socket.close(None).await.map_err(|e| e.to_string())?;
                assert!(matches!(
                    socket.next().await,
                    Some(Ok(Message::Close(_))) | None
                ));
            } else {
                let mut stream = stream;
                let mut request = Vec::new();
                while !request.ends_with(b"\r\n\r\n") {
                    if request.len() >= 16 * 1024 {
                        return Err("request too large".into());
                    }
                    request.push(stream.read_u8().await.map_err(|e| e.to_string())?);
                }
                stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                    )
                    .await
                    .map_err(|e| e.to_string())?;
                stream.flush().await.map_err(|e| e.to_string())?;
            }
            Ok(())
        })
        .await
        .map_err(|e| e.to_string())?
    });
    (
        format!(
            "{}://localhost:{port}/control",
            if websocket { "wss" } else { "https" }
        ),
        server,
    )
}

fn http(url: String) -> HttpRequest {
    HttpRequest {
        method: "GET".into(),
        url,
        headers: vec![],
        body: Bytes::new(),
        max_response_bytes: 16,
    }
}

fn websocket(url: String, max_message_bytes: usize) -> WebSocketRequest {
    WebSocketRequest {
        url,
        headers: vec![("authorization".into(), "Bearer scoped".into())],
        max_message_bytes,
    }
}

#[tokio::test]
async fn pinned_http_uses_only_selected_roots_and_client_identity_without_changing_guest() {
    let env = Env::real(tokio::runtime::Handle::current());
    let certs = certificates();
    let guest_with_ca = env.net.with_tls(certs.tls(false)).unwrap();
    let pinned = guest_with_ca.with_pinned_tls(certs.tls(true)).unwrap();
    let additive = env.net.with_tls(certs.tls(true)).unwrap();
    for net in [&pinned, &additive] {
        let (url, server) = tls_server(
            certs.authenticated.clone(),
            false,
            Some(certs.client.clone()),
        )
        .await;
        assert_eq!(
            tokio::time::timeout(DEADLINE, net.http(http(url)))
                .await
                .unwrap()
                .unwrap()
                .body,
            "ok"
        );
        server.await.unwrap().unwrap();
    }
    let wrong = guest_with_ca
        .with_pinned_tls(certificates().tls(true))
        .unwrap();
    for (net, config) in [
        (&env.net, certs.ordinary.clone()),
        (&guest_with_ca, certs.authenticated.clone()),
        (&wrong, certs.ordinary.clone()),
    ] {
        let (url, server) = tls_server(config, false, None).await;
        assert!(
            tokio::time::timeout(DEADLINE, net.http(http(url)))
                .await
                .unwrap()
                .is_err()
        );
        assert!(server.await.unwrap().is_err());
    }
    let (url, server) = tls_server(certs.ordinary.clone(), false, None).await;
    assert_eq!(guest_with_ca.http(http(url)).await.unwrap().status, 200);
    server.await.unwrap().unwrap();
    assert!(
        env.net
            .with_pinned_tls(TlsConfig {
                ca: vec![],
                identity: None
            })
            .is_err()
    );
    assert!(
        env.net
            .with_pinned_tls(TlsConfig {
                ca: vec![vec![1]],
                identity: None
            })
            .is_err()
    );
    let mut invalid = certs.tls(true);
    invalid.identity.as_mut().unwrap().1 = vec![1, 2, 3];
    assert!(env.net.with_pinned_tls(invalid).is_err());
    let mut mismatched = certs.tls(true);
    mismatched.identity.as_mut().unwrap().1 = rcgen::KeyPair::generate().unwrap().serialize_der();
    assert!(env.net.with_pinned_tls(mismatched).is_err());
    let debug = format!("{:?}", certs.tls(true));
    assert!(debug.contains("[redacted]"));
    assert!(!debug.contains(&format!("{:?}", certs.key)));
}

#[tokio::test]
async fn websocket_reuses_pinned_mtls_and_remains_full_duplex_with_pending_receive() {
    let env = Env::real(tokio::runtime::Handle::current());
    let certs = certificates();
    let guest_with_ca = env.net.with_tls(certs.tls(false)).unwrap();
    let pinned = env.net.with_pinned_tls(certs.tls(true)).unwrap();
    let (url, server) = tls_server(
        certs.authenticated.clone(),
        true,
        Some(certs.client.clone()),
    )
    .await;
    let socket = tokio::time::timeout(DEADLINE, pinned.websocket(websocket(url, 64)))
        .await
        .unwrap()
        .unwrap();
    let (reply, sent) = tokio::time::timeout(DEADLINE, async {
        tokio::join!(socket.recv(), socket.send(Bytes::from_static(b"hello")))
    })
    .await
    .unwrap();
    sent.unwrap();
    assert_eq!(reply.unwrap().unwrap(), "answer");
    assert_eq!(socket.recv().await.unwrap().unwrap(), "again");
    assert_eq!(socket.recv().await.unwrap(), None);
    socket.close().await.unwrap();
    socket.close().await.unwrap();
    assert_eq!(socket.recv().await.unwrap(), None);
    assert!(socket.send(Bytes::from_static(b"closed")).await.is_err());
    server.await.unwrap().unwrap();
    let wrong = guest_with_ca
        .with_pinned_tls(certificates().tls(true))
        .unwrap();
    for (net, config) in [
        (&env.net, certs.ordinary),
        (&guest_with_ca, certs.authenticated.clone()),
        (&wrong, certs.authenticated),
    ] {
        let (url, server) = tls_server(config, true, None).await;
        assert!(
            tokio::time::timeout(DEADLINE, net.websocket(websocket(url, 64)))
                .await
                .unwrap()
                .is_err()
        );
        assert!(server.await.unwrap().is_err());
    }
}

#[tokio::test]
async fn websocket_tls_truncation_before_protocol_close_remains_an_error() {
    let env = Env::real(tokio::runtime::Handle::current());
    let certs = certificates();
    let pinned = env.net.with_pinned_tls(certs.tls(true)).unwrap();
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .unwrap();
    let url = format!(
        "wss://localhost:{}/control",
        listener.local_addr().unwrap().port()
    );
    let (release, released) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        tokio::time::timeout(DEADLINE, async move {
            let (stream, _) = listener.accept().await.unwrap();
            let stream = tokio_rustls::TlsAcceptor::from(Arc::new(certs.authenticated))
                .accept(stream)
                .await
                .unwrap();
            let socket = tokio_tungstenite::accept_async(stream).await.unwrap();
            released.await.unwrap();
            drop(socket);
        })
        .await
        .unwrap();
    });
    let socket = tokio::time::timeout(DEADLINE, pinned.websocket(websocket(url, 64)))
        .await
        .unwrap()
        .unwrap();
    release.send(()).unwrap();
    assert!(matches!(
        tokio::time::timeout(DEADLINE, socket.recv()).await.unwrap(),
        Err(NetError::Io(_))
    ));
    server.await.unwrap();
}

#[tokio::test]
async fn websocket_limits_frames_messages_and_sends_and_rejects_invalid_handshakes() {
    let env = Env::real(tokio::runtime::Handle::current());
    for fragmented in [false, true] {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let url = format!("ws://{}/", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            tokio::time::timeout(DEADLINE, async move {
                let (socket, _) = listener.accept().await.unwrap();
                let mut socket = tokio_tungstenite::accept_async(socket).await.unwrap();
                if fragmented {
                    // Two legal frames exceed only the aggregate message limit.
                    socket
                        .get_mut()
                        .write_all(b"\x02\x09abcdefghi\x80\x09jklmnopqr")
                        .await
                        .unwrap();
                } else {
                    socket
                        .send(Message::Binary(Bytes::from_static(b"abcdefghijklmnopq")))
                        .await
                        .unwrap();
                }
            })
            .await
            .unwrap();
        });
        let socket = env.net.websocket(websocket(url, 16)).await.unwrap();
        assert_eq!(
            socket.send(Bytes::from_static(b"abcdefghijklmnopq")).await,
            Err(NetError::TooLarge)
        );
        assert_eq!(
            tokio::time::timeout(DEADLINE, socket.recv()).await.unwrap(),
            Err(NetError::TooLarge)
        );
        server.await.unwrap();
    }
    for request in [
        websocket("https://localhost/".into(), 16),
        websocket("ws://192.0.2.1/".into(), 16),
        websocket("ws://127.0.0.1/".into(), 0),
        websocket("ws://127.0.0.1/".into(), usize::MAX),
        websocket("not a url".into(), 16),
        WebSocketRequest {
            headers: vec![("host".into(), "attacker.invalid".into())],
            ..websocket("ws://127.0.0.1/".into(), 16)
        },
        WebSocketRequest {
            headers: vec![("sec-websocket-key".into(), "forged".into())],
            ..websocket("ws://127.0.0.1/".into(), 16)
        },
        WebSocketRequest {
            headers: vec![("bad name".into(), "value".into())],
            ..websocket("ws://127.0.0.1/".into(), 16)
        },
        WebSocketRequest {
            headers: vec![("authorization".into(), "secret\r\ninjected: value".into())],
            ..websocket("ws://127.0.0.1/".into(), 16)
        },
    ] {
        assert!(matches!(
            env.net.websocket(request).await,
            Err(NetError::Connect(_))
        ));
    }
}

#[tokio::test]
async fn websocket_does_not_follow_redirect_or_forward_authorization() {
    let env = Env::real(tokio::runtime::Handle::current());
    let target = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .unwrap();
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .unwrap();
    let url = format!("ws://{}/", listener.local_addr().unwrap());
    let redirect = format!(
        "HTTP/1.1 302 Found\r\nLocation: ws://{}/stolen\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        target.local_addr().unwrap()
    );
    let server = tokio::spawn(async move {
        tokio::time::timeout(DEADLINE, async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                request.push(socket.read_u8().await.unwrap());
            }
            assert!(
                String::from_utf8(request)
                    .unwrap()
                    .contains("Bearer scoped")
            );
            socket.write_all(redirect.as_bytes()).await.unwrap();
        })
        .await
        .unwrap();
    });
    assert!(env.net.websocket(websocket(url, 16)).await.is_err());
    server.await.unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(50), target.accept())
            .await
            .is_err()
    );
}

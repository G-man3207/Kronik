//! Native listener authentication binds this original node lifetime before issuing any credential lease.
use super::*;
use kronik_core::authority::Authority as _;

#[cfg(test)]
mod source_tests;

#[cfg(test)]
tokio::task_local! {
    static STARTING_NATIVE_NODE: std::cell::RefCell<Option<oneshot::Sender<Arc<Node>>>>;
}

#[cfg(test)]
pub(super) fn observe_startup(node: &Arc<Node>) {
    let _ = STARTING_NATIVE_NODE.try_with(|capture| {
        if let Some(sender) = capture.borrow_mut().take() {
            let _ = sender.send(node.clone());
        }
    });
}

impl Node {
    pub(crate) fn native_snapshot_execution(
        &self,
    ) -> Arc<crate::native_execution::NativeExecution> {
        self.native_execution.clone()
    }

    pub fn publication_domain(&self) -> Arc<Mutex<()>> {
        self.publication.clone()
    }

    pub fn local_operator_authority(&self) -> Result<AuthLease, ApiError> {
        self.native_execution.check()?;
        Ok(self.native_execution.clone())
    }

    /// Startup recovery retains this original lease across its awaits and queued work.
    pub(crate) fn native_recovery_authority(&self) -> Result<AuthLease, ApiError> {
        self.native_recovery.check()?;
        Ok(self.native_recovery.clone())
    }

    /// Trusted native daemon shutdown, after its final snapshot and before releasing listeners/resources.
    pub fn stop_native_execution(&self) -> Result<(), ApiError> {
        self.native_execution.stop_physical()
    }

    /// A source is a historical frame, not current authority. The native
    /// constructor supplies the shard domain; the held WAL header supplies the
    /// namespace. The caller proves the existing record's exact edge role.
    pub async fn actor_source(
        &self,
        lsn: Lsn,
        matches: impl Fn(&Record) -> bool,
    ) -> Result<pb::ActorSource, ApiError> {
        if lsn == 0 || lsn > i64::MAX as u64 {
            return Err(ApiError::new(
                ErrorCode::BadRequest,
                "invalid actor source position",
            ));
        }
        let first = self.native_execution.native_source_start(self, &self.log)?;
        if lsn < first {
            return Err(ApiError::new(
                ErrorCode::Unavailable,
                "actor source predates its original native log",
            ));
        }
        let mut source = None;
        let mut expected = first;
        // Without a member/provenance projection this native profile cannot
        // claim a source after an unknown record or a missing historical prefix.
        // Decode the dense prefix in bounded frames; never call truncation complete.
        self.reader
            .read_while_with_namespace(first, lsn, |branch, committed| {
                if committed.lsn != expected {
                    return Err(kronik_log::LogError::Corrupt(
                        "incomplete native source prefix".into(),
                    ));
                }
                if committed.lsn < lsn {
                    expected += 1;
                    return Ok(true);
                }
                if !matches!(
                    &committed.record,
                    Record::TurnBegin(_) | Record::TurnRecord(_)
                ) || !matches(&committed.record)
                {
                    return Err(kronik_log::LogError::Corrupt(
                        "actor source does not match its original turn".into(),
                    ));
                }
                let actual = pb::ActorSource {
                    shard: None,
                    lsn: committed.lsn,
                    branch: branch.to_owned(),
                };
                actual.validate().map_err(|_| {
                    kronik_log::LogError::Corrupt("invalid original actor source namespace".into())
                })?;
                source = Some(actual);
                Ok(false)
            })
            .await
            .map_err(|error| ApiError::new(ErrorCode::StorageCorrupt, error.to_string()))?;
        self.native_execution.native_source_start(self, &self.log)?;
        source.ok_or_else(|| {
            ApiError::new(
                ErrorCode::Unavailable,
                "the original actor source frame is unavailable",
            )
        })
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        self.native_execution.stop();
        let _publication = lock(&self.publication);
        self.lifecycle.stop_under_publication();
    }
}

#[cfg(test)]
mod tests {
    // The tests race real time and spawned tasks around admitted work: the
    // direct calls are the harness, not daemon paths.
    #![allow(clippy::disallowed_methods)]

    use super::*;

    use kronik_core::env::{BoxFuture, HttpRequest, HttpResponse, NetError};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    struct StartupForeignWait {
        env: Env,
        entered: Mutex<Option<oneshot::Sender<()>>>,
        release: Mutex<Option<oneshot::Receiver<()>>>,
    }

    impl kronik_effects::foreign::ForeignHost for StartupForeignWait {
        fn reconcile(
            &self,
            _declared: Vec<pb::ForeignActor>,
            _secrets: Option<Arc<SecretStore>>,
            _links: kronik_effects::foreign::SecretLinks,
        ) -> BoxFuture<'static, ()> {
            let release = self.release.lock().unwrap().take().unwrap();
            self.entered
                .lock()
                .unwrap()
                .take()
                .unwrap()
                .send(())
                .unwrap();
            Box::pin(async move {
                release.await.unwrap();
            })
        }

        fn http(
            &self,
            _name: &str,
            request: HttpRequest,
        ) -> BoxFuture<'static, Result<HttpResponse, NetError>> {
            self.env.net.http(request)
        }
    }

    fn startup_http_request(url: &str) -> HttpRequest {
        HttpRequest {
            method: "GET".into(),
            url: url.into(),
            headers: Vec::new(),
            body: bytes::Bytes::new(),
            max_response_bytes: 16,
        }
    }

    async fn unfinished_native_factory_retires_its_actual_consumers(cancel: bool) {
        let directory = tempfile::tempdir().unwrap();
        let env = Env::real(tokio::runtime::Handle::current());
        let (capture, captured) = oneshot::channel();
        let (entered, mut reached) = oneshot::channel();
        let (release, released) = oneshot::channel();
        let host = Arc::new(StartupForeignWait {
            env: env.clone(),
            entered: Mutex::new(Some(entered)),
            release: Mutex::new(Some(released)),
        });
        let config = NodeConfig {
            foreign: kronik_effects::foreign::ForeignSlot(Some(host)),
            group_commit_window: Some(Duration::ZERO),
            ..Default::default()
        };
        let mut startup = Box::pin(STARTING_NATIVE_NODE.scope(
            std::cell::RefCell::new(Some(capture)),
            crate::start_local(env.clone(), directory.path(), config),
        ));
        env.timeout(Duration::from_secs(5), async {
            tokio::select! {
                biased;
                result = &mut reached => result.unwrap(),
                _ = startup.as_mut() => panic!("native factory ended before its actual Foreign wait"),
            }
        }).await.unwrap();
        let node = captured.await.unwrap();
        let original = node.local_operator_authority().unwrap();
        let audit = pb::Audit {
            token_id: "unix:uid=0".into(),
            reason: "unfinished native startup".into(),
            wall_time_ms: 1,
        };
        let accepted = node
            .record_audit_event_authorized(
                "test.native",
                "before startup abort",
                Default::default(),
                audit.clone(),
                original.clone(),
            )
            .await
            .unwrap();
        let reader = Arc::new(node.capture_system_export_reader().await.unwrap());
        assert!(
            !reader
                .page(0, 16, 1 << 20)
                .await
                .unwrap()
                .records
                .is_empty()
        );
        // The preceding commit retires the current certificate until the applier
        // catches up; wait for a genuinely current publication, don't race it.
        let (_snapshot, publication) = env
            .timeout(Duration::from_secs(5), async {
                loop {
                    if let Ok(pair) = node.native_secret_snapshot_with_publication() {
                        break pair;
                    }
                    node.env.clock.sleep(Duration::from_millis(1)).await;
                }
            })
            .await
            .unwrap();
        let (finish, held) = oneshot::channel::<()>();
        let held_node = node.clone();
        let held_reader = reader.clone();
        let retaining_task = env.spawn("retain-unfinished-native-startup", async move {
            let _ = held.await;
            drop((held_node, held_reader));
        });

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!(
            "http://{}/native-startup-proof",
            listener.local_addr().unwrap()
        );
        let server = env.spawn("native-startup-proof-server", async move {
            tokio::time::timeout(Duration::from_secs(5), async {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut headers = Vec::new();
                let mut chunk = [0; 256];
                while !headers.windows(4).any(|bytes| bytes == b"\r\n\r\n") {
                    let read = stream.read(&mut chunk).await.unwrap();
                    assert!(read > 0);
                    headers.extend_from_slice(&chunk[..read]);
                    assert!(headers.len() <= 4096);
                }
                assert!(headers.starts_with(b"GET /native-startup-proof "));
                stream
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                    .await
                    .unwrap();
                stream.shutdown().await.unwrap();
            })
            .await
            .unwrap();
            listener
        });
        let response = env
            .timeout(
                Duration::from_secs(5),
                env.net
                    .http_authorized(startup_http_request(&url), original.clone()),
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(response.status, 200);
        assert!(response.body.is_empty());
        let listener = env
            .timeout(Duration::from_secs(5), server)
            .await
            .unwrap()
            .unwrap();

        if cancel {
            drop(startup);
            drop(release);
        } else {
            node.stop_native_execution().unwrap();
            release.send(()).unwrap();
            assert!(matches!(
                env.timeout(Duration::from_secs(5), startup).await.unwrap(),
                Err(StartError::Corrupt(_))
            ));
        }

        assert!(matches!(
            env.timeout(
                Duration::from_secs(5),
                env.net
                    .http_authorized(startup_http_request(&url), original.clone())
            )
            .await
            .unwrap(),
            Err(NetError::Connect(_))
        ));
        let listener = listener.into_std().unwrap();
        match listener.accept() {
            Err(error) => assert_eq!(error.kind(), std::io::ErrorKind::WouldBlock),
            Ok(_) => panic!("unfinished native startup admitted a new transport command"),
        }
        assert_eq!(
            reader.page(0, 16, 1 << 20).await.err().unwrap().code,
            ErrorCode::Unavailable
        );
        assert_eq!(
            publication.check_current().unwrap_err().code,
            ErrorCode::Unavailable
        );
        let error = node
            .record_audit_event_authorized(
                "test.native",
                "after startup abort",
                Default::default(),
                audit,
                original,
            )
            .await
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::Unavailable);
        assert_eq!(node.applied_lsn(), accepted);
        finish.send(()).unwrap();
        assert!(
            env.timeout(Duration::from_secs(5), retaining_task)
                .await
                .unwrap()
                .is_some()
        );
    }

    #[tokio::test]
    async fn failed_native_factory_retires_consumers_while_a_task_retains_its_node() {
        unfinished_native_factory_retires_its_actual_consumers(false).await;
    }

    #[tokio::test]
    async fn cancelled_native_factory_retires_consumers_while_a_task_retains_its_node() {
        unfinished_native_factory_retires_its_actual_consumers(true).await;
    }

    #[tokio::test]
    async fn original_native_authority_rejects_wal_mutation_after_real_stop() {
        let data = tempfile::tempdir().unwrap();
        let env = Env::real(tokio::runtime::Handle::current());
        let node = crate::start_local(env, data.path(), NodeConfig::default())
            .await
            .unwrap();
        let original = node.local_operator_authority().unwrap();
        let audit = pb::Audit {
            token_id: "unix:uid=0".into(),
            reason: "native lifecycle".into(),
            wall_time_ms: 1,
        };
        let accepted = node
            .record_audit_event_authorized(
                "test.native",
                "accepted",
                Default::default(),
                audit.clone(),
                original.clone(),
            )
            .await
            .unwrap();
        assert_eq!(node.applied_lsn(), accepted);
        node.stop_native_execution().unwrap();
        tokio::time::timeout(Duration::from_secs(2), original.cancelled())
            .await
            .unwrap();
        let denied = node
            .record_audit_event_authorized(
                "test.native",
                "stopped",
                Default::default(),
                audit,
                original,
            )
            .await
            .unwrap_err();
        assert_eq!(denied.code, ErrorCode::Unavailable);
        assert_eq!(node.applied_lsn(), accepted);
        assert!(node.local_operator_authority().is_err());
    }

    #[tokio::test]
    async fn native_stop_cancels_original_configuration_lock_wait() {
        let data = tempfile::tempdir().unwrap();
        let env = Env::real(tokio::runtime::Handle::current());
        let node = crate::start_local(env, data.path(), NodeConfig::default())
            .await
            .unwrap();
        let original = node.local_operator_authority().unwrap();
        let bytes = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/guests/counter.wasm",
        ))
        .unwrap();
        let held = node.deploy_lock.clone().lock_owned().await;
        let applied = node.applied_lsn();
        let epoch = node.epoch();
        let mut request = Box::pin(node.deploy(&bytes, pb::Audit::default(), false, original));
        std::future::poll_fn(|cx| {
            assert!(request.as_mut().poll(cx).is_pending());
            std::task::Poll::Ready(())
        })
        .await;
        node.stop_native_execution().unwrap();
        assert!(
            tokio::time::timeout(Duration::from_secs(2), request)
                .await
                .unwrap()
                .is_err()
        );
        assert_eq!(node.applied_lsn(), applied);
        assert_eq!(node.epoch(), epoch);
        assert!(!node.kind_exists("counter"));
        drop(held);
    }

    #[tokio::test]
    async fn actual_fatal_publication_revokes_native_execution() {
        let data = tempfile::tempdir().unwrap();
        let env = Env::real(tokio::runtime::Handle::current());
        let node = crate::start_local(env, data.path(), NodeConfig::default())
            .await
            .unwrap();
        let recovery = node.native_recovery_authority().unwrap();
        let original = node.local_operator_authority().unwrap();
        node.fatal
            .set("exercise actual native fatal publisher".into());
        assert!(recovery.check().is_err());
        tokio::time::timeout(Duration::from_secs(2), recovery.cancelled())
            .await
            .unwrap();
        assert!(original.check().is_err());
        tokio::time::timeout(Duration::from_secs(2), original.cancelled())
            .await
            .unwrap();
        assert!(node.local_operator_authority().is_err());
    }

    #[tokio::test]
    async fn member_scope_declaration_revokes_native_but_not_physical_lifetime() {
        let data = tempfile::tempdir().unwrap();
        let env = Env::real(tokio::runtime::Handle::current());
        let node = crate::start_local(env, data.path(), NodeConfig::default())
            .await
            .unwrap();
        let recovery = node.native_recovery_authority().unwrap();
        let original = node.local_operator_authority().unwrap();
        {
            let _publication = lock(&node.publication);
            node.lifecycle.declare_member_under_publication();
        }
        assert!(original.check().is_err());
        tokio::time::timeout(Duration::from_secs(2), original.cancelled())
            .await
            .unwrap();
        assert!(recovery.check().is_err());
        tokio::time::timeout(Duration::from_secs(2), recovery.cancelled())
            .await
            .unwrap();
        assert!(node.lifecycle.check().is_ok());
        assert!(node.local_operator_authority().is_err());
        assert!(node.stop_native_execution().is_err());
        assert!(node.lifecycle.check().is_ok());
    }

    #[tokio::test]
    async fn native_capability_does_not_keep_its_original_node_alive() {
        let data = tempfile::tempdir().unwrap();
        let env = Env::real(tokio::runtime::Handle::current());
        let node = crate::start_local(env, data.path(), NodeConfig::default())
            .await
            .unwrap();
        let original = node.local_operator_authority().unwrap();
        let recovery = node.native_recovery_authority().unwrap();
        let node_lifetime = Arc::downgrade(&node);
        drop(node);
        tokio::time::timeout(Duration::from_secs(2), original.cancelled())
            .await
            .unwrap();
        assert!(node_lifetime.upgrade().is_none());
        tokio::time::timeout(Duration::from_secs(2), recovery.cancelled())
            .await
            .unwrap();
        assert!(recovery.check().is_err());
        assert!(original.check().is_err());
    }

    #[tokio::test]
    async fn private_recovery_admits_real_wal_before_public_readiness_and_retains_its_scope() {
        use kronik_core::authority::Authority as _;
        let data = tempfile::tempdir().unwrap();
        let env = Env::real(tokio::runtime::Handle::current());
        let node = crate::start_local(env, data.path(), NodeConfig::default())
            .await
            .unwrap();
        let publication = node.publication_domain();
        let writer = node
            .log
            .bind_native_execution(publication.clone(), node.lifecycle.ownership())
            .unwrap();
        let pending = crate::native_execution::NativeExecution::new(
            publication,
            node.lifecycle.clone(),
            writer,
            node.native_execution
                .native_source_start(&node, &node.log)
                .unwrap(),
        );
        let recovery = pending.recovery_authority().unwrap();
        assert!(
            pending.recovery_authority().is_err(),
            "startup issuance is one-shot"
        );
        assert!(
            recovery.check().is_err(),
            "the original Node must be bound before use"
        );
        pending.bind_node(Arc::downgrade(&node)).unwrap();
        assert!(pending.check().is_err(), "public execution is not ready");
        recovery.check().unwrap();
        let audit = pb::Audit {
            token_id: "system:recovery".into(),
            reason: "private startup recovery".into(),
            wall_time_ms: 1,
        };
        let recovered = node
            .record_audit_event_authorized(
                "test.native.recovery",
                "pending",
                Default::default(),
                audit.clone(),
                recovery.clone(),
            )
            .await
            .unwrap();
        assert_eq!(node.applied_lsn(), recovered);
        assert!(
            pending.check().is_err(),
            "a completed recovery write does not publish readiness"
        );
        pending.activate().unwrap();
        pending.check().unwrap();
        recovery.check().unwrap();
        let drained = node
            .record_audit_event_authorized(
                "test.native.recovery",
                "ready",
                Default::default(),
                audit.clone(),
                recovery.clone(),
            )
            .await
            .unwrap();
        assert!(drained > recovered);
        pending.stop_physical().unwrap();
        tokio::time::timeout(Duration::from_secs(2), recovery.cancelled())
            .await
            .unwrap();
        let denied = node
            .record_audit_event_authorized(
                "test.native.recovery",
                "stopped",
                Default::default(),
                audit,
                recovery,
            )
            .await
            .unwrap_err();
        assert_eq!(denied.code, ErrorCode::Unavailable);
        assert_eq!(node.applied_lsn(), drained);
    }

    #[tokio::test]
    async fn retained_recovery_leases_cannot_publish_after_physical_stop() {
        let data = tempfile::tempdir().unwrap();
        let env = Env::real(tokio::runtime::Handle::current());
        let node = crate::start_local(env, data.path(), NodeConfig::default())
            .await
            .unwrap();
        let original = node.native_recovery_authority().unwrap();
        let same = node.native_recovery_authority().unwrap();
        assert!(node.native_execution.recovery_authority().is_err());
        node.stop_native_execution().unwrap();
        assert!(node.native_recovery_authority().is_err());
        let applied = node.applied_lsn();
        for lease in [original, same] {
            let audit = pb::Audit {
                token_id: "system:recovery".into(),
                reason: "stopped recovery".into(),
                wall_time_ms: 1,
            };
            let error = node
                .record_audit_event_authorized(
                    "test.native.recovery",
                    "stopped",
                    Default::default(),
                    audit,
                    lease,
                )
                .await
                .unwrap_err();
            assert_eq!(error.code, ErrorCode::Unavailable);
        }
        assert_eq!(node.applied_lsn(), applied);
    }
}

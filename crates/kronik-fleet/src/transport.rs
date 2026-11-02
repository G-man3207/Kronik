//! Installation-originated mTLS WebSocket carrying an ordinary HTTP/1 byte stream.
//! The caller serves the bounded in-memory connection through its existing API
//! server; this crate does not route operations or interpret HTTP/WS payloads.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::BytesMut;
use kronik_core::authority::AuthLease;
use kronik_core::env::{BoxFuture, Env, Net, WebSocket, WebSocketRequest};
use kronik_core::error::{ApiError, ErrorCode};
use sha2::{Digest as _, Sha256};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _, DuplexStream};
use tokio::sync::Notify;

use crate::enrollment::{ControllerClient, EnrollmentPhase, EnrollmentRecord, FleetError};

pub const TUNNEL_CHUNK_BYTES: usize = 64 << 10;

pub struct EpochAuthority {
    state: Mutex<EpochState>,
    changed: Notify,
}

struct EpochState {
    epoch: u64,
    request_id: Option<Arc<str>>,
    phase: Option<EnrollmentPhase>,
    revision: u64,
}

#[derive(Clone)]
pub struct EpochGuard {
    authority: Arc<EpochAuthority>,
    epoch: u64,
    revision: u64,
    request_id: Option<Arc<str>>,
}

impl EpochAuthority {
    /// A recovered epoch is denied until its exact durable state is published.
    pub fn new(epoch: u64) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(EpochState {
                epoch,
                request_id: None,
                phase: None,
                revision: 0,
            }),
            changed: Notify::new(),
        })
    }

    pub fn guard(self: &Arc<Self>) -> EpochGuard {
        let state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        EpochGuard {
            authority: self.clone(),
            epoch: state.epoch,
            revision: state.revision,
            request_id: state.request_id.clone(),
        }
    }

    /// Publish only after durable admission, under the ordinary authorization
    /// fence. Checking a guard never acquires that outer fence.
    pub fn publish(&self, record: &EnrollmentRecord) -> Result<(), FleetError> {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        if record.epoch == 0 || record.request_id.is_empty() || record.epoch < state.epoch {
            return Err(FleetError::Invalid("stale enrollment authority"));
        }
        if record.epoch == state.epoch {
            if state
                .request_id
                .as_deref()
                .is_some_and(|id| id != record.request_id)
            {
                return Err(FleetError::Invalid("enrollment request identity changed"));
            }
            let allowed = match state.phase {
                None => true,
                Some(EnrollmentPhase::Pending) => matches!(
                    record.phase,
                    EnrollmentPhase::Pending
                        | EnrollmentPhase::Requested
                        | EnrollmentPhase::Revoked
                ),
                Some(EnrollmentPhase::Requested) => matches!(
                    record.phase,
                    EnrollmentPhase::Requested | EnrollmentPhase::Active | EnrollmentPhase::Revoked
                ),
                Some(EnrollmentPhase::Active) => matches!(
                    record.phase,
                    EnrollmentPhase::Active | EnrollmentPhase::Revoked
                ),
                Some(EnrollmentPhase::Revoked) => record.phase == EnrollmentPhase::Revoked,
            };
            if !allowed {
                return Err(FleetError::Revoked);
            }
            if state.phase == Some(record.phase) {
                return Ok(());
            }
        } else if state.request_id.as_deref() == Some(record.request_id.as_str()) {
            return Err(FleetError::Invalid(
                "a new epoch requires a new request identity",
            ));
        }
        state.revision = state.revision.checked_add(1).ok_or(FleetError::Invalid(
            "enrollment authority revision exhausted",
        ))?;
        state.epoch = record.epoch;
        if state.request_id.as_deref() != Some(record.request_id.as_str()) {
            state.request_id = Some(Arc::from(record.request_id.as_str()));
        }
        state.phase = Some(record.phase);
        drop(state);
        self.changed.notify_waiters();
        Ok(())
    }
}

impl EpochGuard {
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    pub fn request_id(&self) -> Option<&str> {
        self.request_id.as_deref()
    }

    pub fn check(&self) -> Result<(), FleetError> {
        let state = self
            .authority
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if self.epoch == 0
            || state.epoch != self.epoch
            || state.revision != self.revision
            || state.phase != Some(EnrollmentPhase::Active)
            || state.request_id.as_deref() != self.request_id.as_deref()
        {
            return Err(FleetError::Revoked);
        }
        Ok(())
    }

    pub async fn cancelled(&self) {
        loop {
            let notified = self.authority.changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.check().is_err() {
                return;
            }
            notified.await;
        }
    }
}

struct ConnectCommand {
    env: Env,
    net: Arc<dyn Net>,
    request: WebSocketRequest,
    original: AuthLease,
    guard: EpochGuard,
    request_id: Arc<str>,
    key_version: [u8; 32],
    body_hash: [u8; 32],
    command_hash: [u8; 32],
    permit: tokio::sync::OwnedSemaphorePermit,
}

/// One immutable, capacity-reserved opening. It grants no authority to later
/// requests; those still use the ordinary API's original command authorities.
pub struct PreparedControl {
    command: ConnectCommand,
}

impl PreparedControl {
    pub fn destination(&self) -> &str {
        &self.command.request.url
    }
    pub fn body_hash(&self) -> [u8; 32] {
        self.command.body_hash
    }
    pub fn command_hash(&self) -> [u8; 32] {
        self.command.command_hash
    }
    pub fn key_version(&self) -> [u8; 32] {
        self.command.key_version
    }
    pub fn epoch(&self) -> u64 {
        self.command.guard.epoch()
    }
    pub fn request_id(&self) -> &str {
        &self.command.request_id
    }

    /// Every opening requires its source admission: Native supplies its durable
    /// ordinary opening intent; Member runs the entire sealed exact-job flow.
    /// The callback returns resources only, never a replacement command or lease.
    pub async fn dispatch_with_admission<F, Fut, H>(
        self,
        before_io: F,
    ) -> Result<Arc<dyn WebSocket>, FleetError>
    where
        F: FnOnce() -> Fut + Send + 'static,
        Fut: Future<Output = Result<H, FleetError>> + Send + 'static,
        H: Send + 'static,
    {
        let env = self.command.env.clone();
        let original = self.command.original.clone();
        let guard = self.command.guard.clone();
        let job_env = env.clone();
        let job_original = original.clone();
        let job_guard = guard.clone();
        let job = async move {
            let mut pending = Some(self.command);
            let mut ready = None;
            let mut stale = String::from("fleet control opening was revoked");
            let mut duplicate = String::from("fleet control opening was handed off twice");
            job_env
                .timeout(Duration::from_secs(30), async move {
                    check_control(&job_original, &job_guard)?;
                    let _hold = before_io().await?;
                    // The final fence transfers the WHOLE command into this already
                    // owned job's sole ready continuation. No I/O or lazy future is admitted.
                    job_original
                        .admit(&mut || {
                            if job_guard.check().is_err() {
                                return Err(ApiError {
                                    code: ErrorCode::Unauthenticated,
                                    message: std::mem::take(&mut stale),
                                    hint: None,
                                });
                            }
                            if ready.is_some() {
                                return Err(ApiError {
                                    code: ErrorCode::Internal,
                                    message: std::mem::take(&mut duplicate),
                                    hint: None,
                                });
                            }
                            let command = pending.take().ok_or_else(|| ApiError {
                                code: ErrorCode::Internal,
                                message: std::mem::take(&mut duplicate),
                                hint: None,
                            })?;
                            ready = Some(ReadyControl(command));
                            Ok(())
                        })
                        .map_err(|_| FleetError::Revoked)?;
                    ready.ok_or(FleetError::Revoked)?.open().await
                })
                .await
                .map_err(|_| FleetError::Unavailable)?
        };
        let opened = env.spawn("fleet-control-opening", job);
        tokio::select! {
            biased;
            () = original.cancelled() => Err(FleetError::Revoked),
            () = guard.cancelled() => Err(FleetError::Revoked),
            result = opened => result.ok_or(FleetError::Unavailable)?,
        }
    }
}

// Only the original admission fence constructs this continuation. Its sole
// consumer opens exactly the transferred payload, with no subsequent lookup.
struct ReadyControl(ConnectCommand);

impl ReadyControl {
    async fn open(self) -> Result<Arc<dyn WebSocket>, FleetError> {
        let ConnectCommand {
            env,
            net,
            request,
            original,
            guard,
            permit,
            key_version,
            body_hash,
            command_hash,
            request_id,
        } = self.0;
        let _binding = (key_version, body_hash, command_hash, request_id);
        let _opening_permit = permit;
        let socket = net
            .websocket(request)
            .await
            .map_err(|_| FleetError::Unavailable)?;
        if check_control(&original, &guard).is_err() {
            let _ = env.timeout(Duration::from_secs(2), socket.close()).await;
            return Err(FleetError::Revoked);
        }
        Ok(socket)
    }
}

fn check_control(original: &AuthLease, guard: &EpochGuard) -> Result<(), FleetError> {
    original.check().map_err(|_| FleetError::Revoked)?;
    guard.check()
}

fn hash_field(hash: &mut Sha256, bytes: &[u8]) {
    hash.update((bytes.len() as u64).to_be_bytes());
    hash.update(bytes);
}

fn control_hashes(
    request: &WebSocketRequest,
    enrollment: &EnrollmentRecord,
) -> Result<([u8; 32], [u8; 32]), FleetError> {
    let key_version = kronik_proto::control::fleet_control_tls_version(
        &enrollment.plan.ca_sha256,
        &enrollment.client_key_sha256,
        enrollment
            .client_cert_der
            .as_deref()
            .ok_or(FleetError::Protocol)?,
    )
    .map_err(|_| FleetError::Protocol)?;
    let mut command = Sha256::new();
    hash_field(&mut command, b"kronik.fleet-control-opening/v1");
    hash_field(&mut command, b"GET");
    hash_field(&mut command, request.url.as_bytes());
    hash_field(&mut command, &(request.headers.len() as u64).to_be_bytes());
    for (name, value) in &request.headers {
        hash_field(&mut command, name.as_bytes());
        hash_field(&mut command, value.as_bytes());
    }
    hash_field(&mut command, b"");
    hash_field(
        &mut command,
        &(request.max_message_bytes as u64).to_be_bytes(),
    );
    hash_field(&mut command, &key_version);
    Ok((key_version, command.finalize().into()))
}

/// One ordinary HTTP connection, including native streaming and upgrades.
/// Opening uses its required original-bound producer; the opening slot is not
/// retained by the channel. Later commands use ordinary per-operation admission.
// One control connection's admission: client, enrollment, streams and
// callbacks.
#[allow(clippy::too_many_arguments)]
pub async fn run_control<S, D>(
    env: &Env,
    client: &ControllerClient,
    enrollment: &EnrollmentRecord,
    bearer: &str,
    guard: EpochGuard,
    original: AuthLease,
    opening_capacity: Arc<tokio::sync::Semaphore>,
    dispatch: D,
    serve: S,
) -> Result<(), FleetError>
where
    S: FnOnce(DuplexStream, EpochGuard) -> BoxFuture<'static, ()> + Send + 'static,
    D: FnOnce(PreparedControl) -> BoxFuture<'static, Result<Arc<dyn WebSocket>, FleetError>>,
{
    check_control(&original, &guard)?;
    client.validate_plan(&enrollment.plan)?;
    if enrollment.phase != EnrollmentPhase::Active
        || enrollment.epoch != guard.epoch()
        || guard.request_id() != Some(enrollment.request_id.as_str())
        || bearer.is_empty()
        || bearer.len() > 4096
        || !bearer.bytes().all(|byte| byte.is_ascii_graphic())
    {
        return Err(FleetError::Revoked);
    }
    let net = tokio::select! {
        biased;
        () = original.cancelled() => return Err(FleetError::Revoked),
        () = guard.cancelled() => return Err(FleetError::Revoked),
        net = client.authenticated_net(env, enrollment) => net?,
    };
    check_control(&original, &guard)?;
    let request = WebSocketRequest {
        url: client
            .endpoint("/v1/control")
            .replacen("https://", "wss://", 1),
        headers: vec![
            ("authorization".into(), format!("Bearer {bearer}")),
            ("x-kronik-enrollment".into(), enrollment.request_id.clone()),
            ("x-kronik-epoch".into(), enrollment.epoch.to_string()),
        ],
        max_message_bytes: TUNNEL_CHUNK_BYTES,
    };
    let (key_version, command_hash) = control_hashes(&request, enrollment)?;
    let request_id = guard.request_id.clone().ok_or(FleetError::Revoked)?;
    let permit = tokio::select! {
        biased;
        () = original.cancelled() => return Err(FleetError::Revoked),
        () = guard.cancelled() => return Err(FleetError::Revoked),
        permit = opening_capacity.acquire_owned() => permit.map_err(|_| FleetError::Unavailable)?,
    };
    let command = ConnectCommand {
        env: env.clone(),
        net,
        request,
        original: original.clone(),
        guard: guard.clone(),
        request_id,
        key_version,
        body_hash: Sha256::digest(b"").into(),
        command_hash,
        permit,
    };
    let socket = dispatch(PreparedControl { command }).await?;
    if check_control(&original, &guard).is_err() {
        let _ = env.timeout(Duration::from_secs(2), socket.close()).await;
        return Err(FleetError::Revoked);
    }
    let (server, tunnel) = tokio::io::duplex(TUNNEL_CHUNK_BYTES);
    // The ordinary HTTP server may hand its endpoint to an upgraded WS task.
    // Its HTTP connection future finishing therefore does not end the byte pipe.
    drop(env.spawn("fleet-http-connection", serve(server, guard.clone())));
    let (mut read, mut write) = tokio::io::split(tunnel);
    let inbound = async {
        loop {
            check_control(&original, &guard)?;
            let frame = socket.recv().await;
            check_control(&original, &guard)?;
            let Some(frame) = frame.map_err(|_| FleetError::Unavailable)? else {
                return Ok::<(), FleetError>(());
            };
            if frame.len() > TUNNEL_CHUNK_BYTES {
                return Err(FleetError::Protocol);
            }
            env.timeout(Duration::from_secs(120), write.write_all(&frame))
                .await
                .map_err(|_| FleetError::Unavailable)?
                .map_err(|_| FleetError::Unavailable)?;
            check_control(&original, &guard)?;
        }
    };
    let outbound = async {
        let mut buffer = BytesMut::with_capacity(TUNNEL_CHUNK_BYTES);
        loop {
            check_control(&original, &guard)?;
            buffer.reserve(TUNNEL_CHUNK_BYTES);
            let mut bounded = (&mut read).take(TUNNEL_CHUNK_BYTES as u64);
            let count = bounded.read_buf(&mut buffer).await;
            check_control(&original, &guard)?;
            let count = count.map_err(|_| FleetError::Unavailable)?;
            if count == 0 {
                return Ok::<(), FleetError>(());
            }
            check_control(&original, &guard)?;
            env.timeout(
                Duration::from_secs(30),
                socket.send(buffer.split().freeze()),
            )
            .await
            .map_err(|_| FleetError::Unavailable)?
            .map_err(|_| FleetError::Unavailable)?;
        }
    };
    let result = tokio::select! {
        biased;
        () = original.cancelled() => Err(FleetError::Revoked),
        _ = guard.cancelled() => Err(FleetError::Revoked),
        result = inbound => result,
        result = outbound => result,
    };
    drop(read);
    drop(write);
    let _ = env.timeout(Duration::from_secs(2), socket.close()).await;
    check_control(&original, &guard)?;
    result
}

//! Native event startup uses the same M28 streams, actual Node and immutable M23 signer.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use kronik_core::authority::AuthLease;
use kronik_core::error::{ApiError, ErrorCode};
use kronik_core::ids::SourcePos;
use kronik_fleet::{events::Identity, webhook::{Resolver, SecretVersion, Settings, Webhook}};
use kronik_otel::{audit::{Keys, Mapper}, cursor::{Cursors, Entry}, follow::{self, Options, Stream}};
use kronik_proto::log::v1 as pb;
use kronik_sched::Node;

/// This serve path owns one native actor log, not a synthetic global shard.
/// Member actors use their actual registered M28 source and member runner.
pub async fn start(
    node: Arc<Node>,
    installation: &str,
    config: &crate::config::Events,
    cursors: Arc<Cursors>,
    execution: AuthLease,
) -> Result<BTreeMap<String, Arc<Stream>>, ApiError> {
    execution.check()?;
    let shard = None;
    if config.webhook.len() > 64 {
        return Err(ApiError::new(ErrorCode::BadRequest, "at most 64 event webhooks may start per shard"));
    }
    let identity = Identity { installation: installation.into(), branch: node.branch().into() };
    identity.validate().map_err(config_error)?;
    kronik_fleet::events::ResumeCursor::new(identity.clone())
        .rewind(kronik_fleet::events::Position { source: SourcePos::Actor { shard, lsn: 1 }, subindex: 0 })
        .map_err(config_error)?;
    let domain = kronik_fleet::events::domain(SourcePos::Actor { shard, lsn: 1 });
    let mut streams = BTreeMap::new();
    let mapper = Arc::new(Mapper { keys: Keys::Omit, sealer: node.sealer().clone(), branch: node.branch().into() });
    let signer = signer(node.clone());
    let initialized: Result<(), ApiError> = async {
        for webhook in &config.webhook {
            kronik_fleet::webhook::validate_url(&webhook.url).map_err(|_| config_error("event webhook endpoint is invalid")
                .with_hint("Use HTTPS or loopback HTTP without credentials or fragments."))?;
            let public_name = format!("{}:{domain}", webhook.name);
            if streams.contains_key(&public_name) {
                return Err(ApiError::new(ErrorCode::BadRequest, "event webhook names must be unique"));
            }
            let committed = node.secret_identity(node.branch(), &webhook.secret, webhook.version).await?;
            let secret = pin_version(node.branch(), committed)?;
            let label = format!("events-{}:{domain}", webhook.name);
            if label.len() > 128 {
                return Err(config_error("event webhook stream identity is too long"));
            }
            let name: Arc<str> = label.into();
            let first = match node.storage_config() {
                Some(storage) => node.log_first(storage)?,
                None => 1,
            };
            let cursor = cursors.get(name.as_ref()).map_or(first.saturating_sub(1), |entry| entry.lsn);
            let stream = Stream::new(name, true, kronik_otel::http::scheme_host(&webhook.url), cursor, cursors.clone());
            stream.initialize_native_cursor(&node, Entry { lsn: cursor, ..Entry::default() }, execution.clone()).await?;
            let (factory_node, factory_mapper, factory_identity) = (node.clone(), mapper.clone(), identity.clone());
            let (factory_stream, factory_cursors, factory_signer) = (stream.clone(), cursors.clone(), signer.clone());
            let factory_execution = execution.clone();
            let settings = Settings { url: webhook.url.clone(), secret };
            let make = move |_entry| Webhook::open(factory_node.clone(), factory_mapper.clone(), factory_identity.clone(),
                shard, factory_stream.clone(), factory_cursors.clone(), settings.clone(), factory_signer.clone(),
                factory_execution.clone());
            stream.own_task(node.env().spawn("events-webhook", follow::supervise(node.clone(), stream.clone(),
                Options { batch: 1, interval: Duration::from_millis(100) }, make, execution.clone())));
            streams.insert(public_name, stream);
        }
        Ok(())
    }.await;
    if let Err(mut error) = initialized {
        for stream in streams.into_values() {
            if let Err(cleanup) = stream.stop_and_join().await {
                error.message.push_str("; cleanup ");
                error.message.push_str(cleanup.code.as_str());
                error.message.push_str(": ");
                error.message.push_str(&cleanup.message);
            }
        }
        return Err(error);
    }
    Ok(streams)
}

pub(crate) async fn start_native(
    node: Arc<Node>, installation: &str, config: &crate::config::Events, cursors: Arc<Cursors>,
    execution: AuthLease,
) -> Result<(Arc<kronik_api::events::Events>, Vec<Arc<Stream>>), ApiError> {
    let streams = start(node.clone(), installation, config, cursors, execution).await?;
    let identity = Identity { installation: installation.to_owned(), branch: node.branch().to_owned() };
    let targets = streams.iter().map(|(name, stream)| (name.clone(),
        kronik_api::events::WebhookTarget::Native { stream: stream.clone() })).collect();
    match kronik_api::events::Events::native(identity, node).and_then(|events| events.with_webhooks(targets)) {
        Ok(events) => Ok((Arc::new(events), streams.into_values().collect())),
        Err(mut error) => {
            for stream in streams.into_values() {
                if let Err(cleanup) = stream.stop_and_join().await {
                    error.message.push_str("; cleanup ");
                    error.message.push_str(cleanup.code.as_str());
                    error.message.push_str(": ");
                    error.message.push_str(&cleanup.message);
                }
            }
            Err(error)
        }
    }
}

pub(crate) fn signer(node: Arc<Node>) -> Arc<Resolver> {
    Arc::new(move |pin, message, original| {
        let node = node.clone();
        Box::pin(async move {
            let expected = expected_version(&pin);
            node.secret_hmac(&pin.branch, &expected, &message, original).await
                .map_err(|error| error.code.as_str().to_owned())
        })
    })
}

fn config_error(message: impl Into<String>) -> ApiError {
    ApiError::new(ErrorCode::BadRequest, message)
}


pub(crate) fn pin_version(branch: &str, version: pb::SecretVersion) -> Result<SecretVersion, ApiError> {
    let version_hash: [u8;16] = version.version_hash.try_into()
        .map_err(|_| ApiError::new(ErrorCode::SecretUnavailable, "secret version identity is invalid"))?;
    Ok(SecretVersion { name: version.name, version: version.version, branch: branch.into(), version_hash,
        hash_revision: version.hash_revision, backend: version.backend, binding: version.binding,
        reference: version.r#ref, canonical_ref: version.canonical_ref,
        link_generation: version.link_generation, source_version: version.source_version })
}

fn expected_version(pin: &SecretVersion) -> pb::SecretVersion {
    pb::SecretVersion { name: pin.name.clone(), version: pin.version, version_hash: pin.version_hash.to_vec(),
        hash_revision: pin.hash_revision, backend: pin.backend.clone(), binding: pin.binding.clone(),
        r#ref: pin.reference.clone(), canonical_ref: pin.canonical_ref.clone(),
        link_generation: pin.link_generation, source_version: pin.source_version.clone(),
        phase: pb::secret_version::Phase::Active as i32, deleted: false, audit: None }
}

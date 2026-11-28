//! Helpers shared by the runtime's integration tests.

#![allow(dead_code)]

use std::collections::BTreeMap;

use kronik_core::ids::ActorRef;
use kronik_proto::log::v1 as pb;
use kronik_runtime::{CodeStore, PoolSize, StateView, TurnLimits, TurnRequest, build_engine};

/// An actor's state: empty, or the map a test gives it.
#[derive(Default)]
pub struct Map(pub BTreeMap<String, Vec<u8>>);

impl StateView for Map {
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>, String> {
        Ok(self.0.get(key).cloned())
    }
    fn keys(&self, prefix: &str) -> Result<Vec<String>, String> {
        Ok(self
            .0
            .keys()
            .filter(|k| k.starts_with(prefix))
            .cloned()
            .collect())
    }
    fn timer_pending(&self, _id: u64) -> Result<bool, String> {
        Ok(false)
    }
    fn connection(&self, _: &str) -> Result<Option<kronik_runtime::ConnectionView>, String> {
        Ok(None)
    }
}

pub fn store() -> CodeStore {
    CodeStore::new(build_engine(PoolSize { concurrency: 2 }).unwrap(), None).unwrap()
}

/// An operator message with a plain body and no subject.
pub fn message(name: &str, body: &[u8]) -> pb::Input {
    pb::Input {
        kind: Some(pb::input::Kind::Message(pb::MessageInput {
            source: pb::MessageSource::Operator as i32,
            msg: Some(pb::Message {
                name: name.into(),
                content_type: "text/plain".into(),
                body: Some(pb::Sealable::new_plain(None, body.to_vec())),
                blobs: vec![],
                retained_compensation_source: None,
            }),
            message_id: "m".into(),
            ..Default::default()
        })),
    }
}

/// A turn request with the tests' default causal key, time, seed and limits;
/// a test changes only the fields it cares about.
pub fn request(actor: &str, input: pb::Input) -> TurnRequest {
    TurnRequest {
        actor: ActorRef::parse(actor).unwrap(),
        causal_key: kronik_core::causal::root("r".into()),
        logical_time_ms: 1_761_300_000_000,
        seed: [7; 32],
        input,
        limits: TurnLimits::default(),
        subject: None,
    }
}

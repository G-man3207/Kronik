//! Read-only committed metadata audit coverage, distinct from actor LSNs.

use kronik_core::error::ApiError;
use kronik_proto::Record;

pub const MAX_METADATA_AUDIT_RECORDS: usize = 1024;

/// A canonical record and adoption provenance captured from the same durable image.
/// `index` is the metadata adoption/application receipt, never the original actor LSN.
#[derive(PartialEq)]
pub struct MetadataAuditRecord {
    pub index: u64,
    pub record: Record,
    /// Only imported Record45 identities use this view; Record40 keeps its embedded origin.
    pub native_origin: Option<kronik_proto::log::v1::NativeAuthorityOrigin>,
}

impl MetadataAuditRecord {
    pub fn validate(&self) -> Result<(), ApiError> {
        use kronik_core::error::ErrorCode;
        if self.index == 0
            || self.index > i64::MAX as u64
            || !matches!(
                &self.record,
                Record::AuditEvent(_)
                    | Record::SecretVersion(_)
                    | Record::SecretLink(_)
                    | Record::Approval(_)
            )
        {
            return Err(ApiError::new(
                ErrorCode::StorageCorrupt,
                "invalid metadata audit record",
            ));
        }
        if let Record::Approval(approval) = &self.record {
            kronik_proto::validate_proposal_approval(approval).map_err(|_| {
                ApiError::new(
                    ErrorCode::StorageCorrupt,
                    "invalid ordinary metadata proposal approval",
                )
            })?;
        }
        if let Some(origin) = &self.native_origin {
            if !matches!(&self.record, Record::SecretVersion(_)) {
                return Err(ApiError::new(
                    ErrorCode::StorageCorrupt,
                    "metadata adoption context is not a secret identity",
                ));
            }
            self.record.validate().map_err(|_| {
                ApiError::new(
                    ErrorCode::StorageCorrupt,
                    "invalid imported secret identity",
                )
            })?;
            kronik_proto::control::validate_native_authority_origin(origin).map_err(|_| {
                ApiError::new(
                    ErrorCode::StorageCorrupt,
                    "invalid metadata native adoption origin",
                )
            })?;
        }
        Ok(())
    }
}

/// One atomically captured durable image; holes are non-control metadata entries.
pub struct MetadataAuditBatch {
    /// First index for which complete control-event coverage is retained.
    pub covered_from: u64,
    pub durable_through: u64,
    /// Last examined index, not merely the last matching control event.
    pub scanned_through: u64,
    pub records: Vec<MetadataAuditRecord>,
}

/// Implemented by the existing metadata state, not a second journal or exporter.
pub trait MetadataAuditSource: Send + Sync {
    /// Inclusive `from`; `limit` must be 1..=MAX_METADATA_AUDIT_RECORDS.
    /// A full batch scans through its last event; a partial batch scans through
    /// durable_through. Capture coverage, records and durability from ONE image.
    fn read_from(&self, from: u64, limit: usize) -> Result<MetadataAuditBatch, ApiError>;
}

/// A fixed metadata coverage notice, not an actor range or new audit journal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MetadataAuditGap {
    pub stream: String,
    pub from_index: u64,
    pub through_index: u64,
}

impl MetadataAuditGap {
    pub fn from_details(
        details: &std::collections::BTreeMap<String, String>,
    ) -> Result<Self, kronik_proto::DecodeError> {
        let (stream, from_index, through_index) =
            kronik_proto::control::metadata_audit_gap_details(details)?;
        Ok(Self {
            stream: stream.to_owned(),
            from_index,
            through_index,
        })
    }

    /// The event validator checks this exact closed schema before admission.
    pub fn to_details(&self) -> std::collections::BTreeMap<String, String> {
        self.clone().into_details()
    }

    pub fn into_details(self) -> std::collections::BTreeMap<String, String> {
        std::collections::BTreeMap::from([
            ("namespace".into(), "metadata".into()),
            ("stream".into(), self.stream),
            ("from_index".into(), self.from_index.to_string()),
            ("through_index".into(), self.through_index.to_string()),
        ])
    }
}

/// The fixed metadata webhook signing-key configuration change.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MetadataWebhookKeyChange {
    pub stream: String,
    pub from_version: u64,
    pub to_version: u64,
}

impl MetadataWebhookKeyChange {
    pub fn from_event(
        event: &kronik_proto::log::v1::AuditEvent,
    ) -> Result<Self, kronik_proto::DecodeError> {
        kronik_proto::control::validate_metadata_webhook_key_change_event(event)?;
        let (from_version, to_version) =
            kronik_proto::control::metadata_webhook_key_change_details(&event.details)?;
        Ok(Self {
            stream: event.target.clone(),
            from_version,
            to_version,
        })
    }

    /// The fixed producer validates the whole event before durable admission.
    pub fn to_details(&self) -> std::collections::BTreeMap<String, String> {
        std::collections::BTreeMap::from([
            ("change".into(), "webhook.signing_key".into()),
            ("source".into(), "metadata".into()),
            ("from_version".into(), self.from_version.to_string()),
            ("to_version".into(), self.to_version.to_string()),
        ])
    }

    pub fn into_details(self) -> std::collections::BTreeMap<String, String> {
        self.to_details()
    }
}

/// A replay request for one registered metadata webhook stream.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MetadataWebhookReplay {
    pub stream: String,
    pub from_index: u64,
}

impl MetadataWebhookReplay {
    pub fn from_event(
        event: &kronik_proto::log::v1::AuditEvent,
    ) -> Result<Self, kronik_proto::DecodeError> {
        kronik_proto::control::validate_metadata_webhook_replay_event(event)?;
        let from_index = kronik_proto::control::metadata_webhook_replay_details(&event.details)?;
        Ok(Self {
            stream: event.target.clone(),
            from_index,
        })
    }

    /// The fixed producer validates the whole event before durable admission.
    pub fn to_details(&self) -> std::collections::BTreeMap<String, String> {
        std::collections::BTreeMap::from([
            ("source".into(), "metadata".into()),
            ("position".into(), self.from_index.to_string()),
        ])
    }

    pub fn into_details(self) -> std::collections::BTreeMap<String, String> {
        self.to_details()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_webhook_replay_round_trips_without_an_actor_position_alias() {
        let replay = MetadataWebhookReplay {
            stream: "events-control:metadata".into(),
            from_index: i64::MAX as u64,
        };
        let mut event = kronik_proto::log::v1::AuditEvent {
            action: "events.webhook.replay".into(),
            target: replay.stream.clone(),
            details: replay.to_details(),
            audit: Some(kronik_proto::log::v1::Audit {
                token_id: "token:operator".into(),
                reason: "recover receiver".into(),
                wall_time_ms: 1,
            }),
            ..Default::default()
        };
        assert_eq!(MetadataWebhookReplay::from_event(&event).unwrap(), replay);
        assert_eq!(replay.into_details(), event.details);
        event.details.insert("from_lsn".into(), "1".into());
        assert!(MetadataWebhookReplay::from_event(&event).is_err());
    }

    #[test]
    fn metadata_webhook_key_change_round_trips_the_closed_event() {
        let change = MetadataWebhookKeyChange {
            stream: "events-metadata".into(),
            from_version: u32::MAX as u64 + 1,
            to_version: kronik_proto::secret::MAX_SECRET_VERSION,
        };
        let mut event = kronik_proto::log::v1::AuditEvent {
            action: "audit.config".into(),
            target: change.stream.clone(),
            details: change.to_details(),
            audit: Some(kronik_proto::log::v1::Audit {
                token_id: "system".into(),
                reason: "signing key changed".into(),
                wall_time_ms: 1,
            }),
            ..Default::default()
        };
        assert_eq!(
            MetadataWebhookKeyChange::from_event(&event).unwrap(),
            change
        );
        assert_eq!(change.into_details(), event.details);
        event.details.insert("secret_name".into(), "private".into());
        assert!(MetadataWebhookKeyChange::from_event(&event).is_err());
    }

    #[test]
    fn metadata_gap_is_a_closed_index_range_not_an_actor_lsn_alias() {
        let gap = MetadataAuditGap {
            stream: "fleet-metadata".into(),
            from_index: 1,
            through_index: 17,
        };
        let details = gap.to_details();
        assert_eq!(MetadataAuditGap::from_details(&details).unwrap(), gap);
        assert!(!details.contains_key("from") && !details.contains_key("to"));
        for (key, value) in [
            ("namespace", "actor"),
            ("from_index", "0"),
            ("from_index", "01"),
            ("from_index", "18"),
            ("through_index", "9223372036854775808"),
            ("stream", ""),
            ("stream", "line\nbreak"),
        ] {
            let mut invalid = details.clone();
            invalid.insert(key.into(), value.into());
            assert!(MetadataAuditGap::from_details(&invalid).is_err(), "{key}");
        }
        let mut mixed = details;
        mixed.insert("from".into(), "1".into());
        assert!(MetadataAuditGap::from_details(&mixed).is_err());
    }
}

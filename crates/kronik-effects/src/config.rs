//! Capabilities, grants and limits as of a configuration epoch (I5, I6).

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use kronik_proto::Record;
use kronik_proto::log::v1 as pb;

/// A delivery class (I17).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Delivery {
    ReplaySafe,
    IdempotencyKeyed,
    Unsafe,
}

impl Delivery {
    pub fn as_str(self) -> &'static str {
        match self {
            Delivery::ReplaySafe => "replay-safe",
            Delivery::IdempotencyKeyed => "idempotency-keyed",
            Delivery::Unsafe => "unsafe",
        }
    }

    pub fn parse(s: &str) -> Option<Delivery> {
        match s {
            "replay-safe" => Some(Delivery::ReplaySafe),
            "idempotency-keyed" => Some(Delivery::IdempotencyKeyed),
            "unsafe" => Some(Delivery::Unsafe),
            _ => None,
        }
    }

    pub fn from_pb(v: i32) -> Option<Delivery> {
        match pb::Delivery::try_from(v).ok()? {
            pb::Delivery::ReplaySafe => Some(Delivery::ReplaySafe),
            pb::Delivery::IdempotencyKeyed => Some(Delivery::IdempotencyKeyed),
            pb::Delivery::Unsafe => Some(Delivery::Unsafe),
            pb::Delivery::Unspecified => None,
        }
    }

    pub fn to_pb(self) -> i32 {
        (match self {
            Delivery::ReplaySafe => pb::Delivery::ReplaySafe,
            Delivery::IdempotencyKeyed => pb::Delivery::IdempotencyKeyed,
            Delivery::Unsafe => pb::Delivery::Unsafe,
        }) as i32
    }

    /// The default when the grant names none: replay-safe for GET, HEAD and
    /// OPTIONS, unsafe otherwise.
    pub fn default_for(method: &str) -> Delivery {
        match method.to_ascii_uppercase().as_str() {
            "GET" | "HEAD" | "OPTIONS" => Delivery::ReplaySafe,
            _ => Delivery::Unsafe,
        }
    }
}

/// At most `count` calls per `per`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rate {
    pub count: u32,
    pub per: Duration,
}

impl Rate {
    /// `N/s`, `N/m` or `N/h`.
    pub fn parse(s: &str) -> Option<Rate> {
        let (n, unit) = s.trim().split_once('/')?;
        let count: u32 = n.trim().parse().ok().filter(|c| *c > 0)?;
        let per = match unit.trim() {
            "s" => Duration::from_secs(1),
            "m" => Duration::from_secs(60),
            "h" => Duration::from_secs(3600),
            _ => return None,
        };
        Some(Rate { count, per })
    }

    pub fn render(&self) -> String {
        let unit = match self.per.as_secs() {
            1 => "s",
            60 => "m",
            3600 => "h",
            _ => return format!("{}/{}ms", self.count, self.per.as_millis()),
        };
        format!("{}/{unit}", self.count)
    }

    pub fn to_pb(&self) -> pb::Rate {
        pb::Rate {
            count: self.count,
            per_ms: self.per.as_millis() as u64,
        }
    }

    pub fn from_pb(r: &pb::Rate) -> Option<Rate> {
        (r.count > 0 && r.per_ms > 0).then(|| Rate {
            count: r.count,
            per: Duration::from_millis(r.per_ms),
        })
    }
}

/// A parsed capability string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Capability {
    /// `http:<host>` or `http:*.<suffix>`.
    Http(String),
    Foreign(String),
    Secret(String),
    SecretReveal(String),
}

impl Capability {
    pub fn parse(s: &str) -> Option<Capability> {
        let (kind, target) = s.split_once(':')?;
        if target.is_empty() {
            return None;
        }
        match kind {
            "http" => {
                let host = target.to_ascii_lowercase();
                let bare = host.strip_prefix("*.").unwrap_or(&host);
                let ok = !bare.is_empty()
                    && bare
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b':'));
                ok.then_some(Capability::Http(host))
            }
            "foreign" => {
                let name = target.to_ascii_lowercase();
                crate::foreign::valid_name(&name).then_some(Capability::Foreign(name))
            }
            "secret" => {
                kronik_privacy::valid_name(target).then(|| Capability::Secret(target.to_owned()))
            }
            "secret-reveal" => kronik_privacy::valid_name(target)
                .then(|| Capability::SecretReveal(target.to_owned())),
            _ => None,
        }
    }

    pub fn render(&self) -> String {
        match self {
            Capability::Http(h) => format!("http:{h}"),
            Capability::Foreign(n) => format!("foreign:{n}"),
            Capability::Secret(n) => format!("secret:{n}"),
            Capability::SecretReveal(n) => format!("secret-reveal:{n}"),
        }
    }
}

/// How specifically an `http:` pattern matches `host`: `None` for no match,
/// higher is more specific (exact beats any wildcard, longer suffixes beat
/// shorter ones). A wildcard never matches its apex.
pub fn http_match(pattern: &str, host: &str) -> Option<usize> {
    let host = host.to_ascii_lowercase();
    match pattern.strip_prefix("*.") {
        Some(suffix) => (host.len() > suffix.len() + 1
            && host.ends_with(suffix)
            && host.as_bytes()[host.len() - suffix.len() - 1] == b'.')
            .then_some(suffix.len()),
        None => (pattern == host).then_some(usize::MAX),
    }
}

/// One active grant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Grant {
    pub kind: String,
    pub capability: String,
    pub delivery: Option<Delivery>,
    pub rate: Option<Rate>,
    pub epoch: u64,
    pub reason: String,
}

/// Per-kind limits; the defaults are the brief's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KindLimits {
    pub fuel: u64,
    pub memory_bytes: u64,
    pub message_bytes: u64,
    pub state_value_bytes: u64,
    pub sql_bytes_per_actor: u64,
    pub effect_timeout: Duration,
    pub effect_response_bytes: u64,
}

impl Default for KindLimits {
    fn default() -> Self {
        KindLimits {
            fuel: 50_000_000,
            memory_bytes: 64 << 20,
            message_bytes: 1 << 20,
            state_value_bytes: 1 << 20,
            sql_bytes_per_actor: 1 << 30,
            effect_timeout: Duration::from_secs(10),
            effect_response_bytes: 10 << 20,
        }
    }
}

impl KindLimits {
    fn apply(&mut self, l: &pb::Limits) {
        let set = |dst: &mut u64, v: Option<u64>| {
            if let Some(v) = v {
                *dst = v;
            }
        };
        set(&mut self.fuel, l.fuel);
        set(&mut self.memory_bytes, l.memory_bytes);
        set(&mut self.message_bytes, l.message_bytes);
        set(&mut self.state_value_bytes, l.state_value_bytes);
        set(&mut self.sql_bytes_per_actor, l.sql_bytes_per_actor);
        set(&mut self.effect_response_bytes, l.effect_response_bytes);
        if let Some(ms) = l.effect_timeout_ms {
            self.effect_timeout = Duration::from_millis(ms);
        }
    }
}

/// Grants, limits, declared foreign actors and the privacy mode as of one
/// epoch.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Config {
    pub epoch: u64,
    grants: BTreeMap<(String, String), Grant>,
    limits: BTreeMap<String, KindLimits>,
    /// `ForeignActor` add records by name (docs/design/m7-foreign.md §2).
    foreign: BTreeMap<String, pb::ForeignActor>,
    /// The latest `PrivacyMode` record's epoch and mode
    /// (docs/design/m8-privacy.md §3).
    privacy: Option<(u64, pb::PrivacyState)>,
    /// Simulator configuration by target (M12): the latest
    /// `SimulatorConfig` record of each.
    simulators: BTreeMap<String, pb::SimulatorConfig>,
    /// Installation default for `sql_bytes_per_actor` when a kind has no
    /// value in a `Limits` record. `None` keeps [`KindLimits::default`]
    /// (1 GiB), which DST and tests rely on.
    sql_default: Option<u64>,
}

impl Config {
    /// Folds one configuration record in.
    pub fn apply(&mut self, record: &Record) {
        match record {
            Record::Grant(g) => {
                self.epoch = self.epoch.max(g.epoch);
                let key = (g.kind.clone(), g.capability.clone());
                if g.op == pb::GrantOp::Revoke as i32 {
                    self.grants.remove(&key);
                } else {
                    self.grants.insert(
                        key,
                        Grant {
                            kind: g.kind.clone(),
                            capability: g.capability.clone(),
                            delivery: g.delivery.and_then(Delivery::from_pb),
                            rate: g.rate.as_ref().and_then(Rate::from_pb),
                            epoch: g.epoch,
                            reason: g
                                .audit
                                .as_ref()
                                .map(|a| a.reason.clone())
                                .unwrap_or_default(),
                        },
                    );
                }
            }
            Record::Limits(l) => {
                self.epoch = self.epoch.max(l.epoch);
                let base = self.installation_limits();
                self.limits.entry(l.kind.clone()).or_insert(base).apply(l);
            }
            Record::Deployment(d) => self.epoch = self.epoch.max(d.epoch),
            Record::PrivacyMode(p) => {
                self.epoch = self.epoch.max(p.epoch);
                let mode = pb::PrivacyState::try_from(p.mode).unwrap_or(pb::PrivacyState::Off);
                self.privacy = Some((p.epoch, mode));
            }
            Record::ForeignActor(f) => {
                self.epoch = self.epoch.max(f.epoch);
                if f.op == pb::ForeignOp::Remove as i32 {
                    self.foreign.remove(&f.name);
                } else {
                    self.foreign.insert(f.name.clone(), f.clone());
                }
            }
            Record::SimulatorConfig(m) => {
                self.epoch = self.epoch.max(m.epoch);
                if simulator_config_empty(m) {
                    self.simulators.remove(&m.target);
                } else {
                    self.simulators.insert(m.target.clone(), m.clone());
                }
            }
            _ => {}
        }
    }

    pub fn grants(&self) -> impl Iterator<Item = &Grant> {
        self.grants.values()
    }

    pub fn grant(&self, kind: &str, capability: &str) -> Option<&Grant> {
        self.grants.get(&(kind.to_owned(), capability.to_owned()))
    }

    /// The most specific `http:` grant of `kind` matching `host`.
    pub fn http_grant(&self, kind: &str, host: &str) -> Option<&Grant> {
        self.grants
            .range((kind.to_owned(), String::new())..)
            .take_while(|((k, _), _)| k == kind)
            .filter_map(|((_, cap), g)| {
                let pattern = cap.strip_prefix("http:")?;
                Some((http_match(pattern, host)?, g))
            })
            .max_by_key(|(score, _)| *score)
            .map(|(_, g)| g)
    }

    /// The privacy mode, `Off` until a `PrivacyMode` record says otherwise,
    /// with that record's epoch.
    pub fn privacy(&self) -> (pb::PrivacyState, Option<u64>) {
        match self.privacy {
            Some((epoch, pb::PrivacyState::On)) => (pb::PrivacyState::On, Some(epoch)),
            Some((epoch, _)) => (pb::PrivacyState::Off, Some(epoch)),
            None => (pb::PrivacyState::Off, None),
        }
    }

    pub fn limits(&self, kind: &str) -> KindLimits {
        self.limits
            .get(kind)
            .copied()
            .unwrap_or_else(|| self.installation_limits())
    }

    /// `sql_bytes_per_actor` from the installation, else 1 GiB.
    pub fn with_sql_default(mut self, bytes: u64) -> Config {
        self.sql_default = Some(bytes);
        self
    }

    fn installation_limits(&self) -> KindLimits {
        let mut limits = KindLimits::default();
        if let Some(bytes) = self.sql_default {
            limits.sql_bytes_per_actor = bytes;
        }
        limits
    }

    /// The declared foreign actor `name` (its add record).
    pub fn foreign(&self, name: &str) -> Option<&pb::ForeignActor> {
        self.foreign.get(name)
    }

    /// Every declared foreign actor, by name.
    /// The simulator configuration of every target that has one (M12).
    pub fn simulators(&self) -> &BTreeMap<String, pb::SimulatorConfig> {
        &self.simulators
    }

    pub fn foreign_actors(&self) -> impl Iterator<Item = &pb::ForeignActor> {
        self.foreign.values()
    }
}

/// Whether a `SimulatorConfig` record clears its target.
pub fn simulator_config_empty(m: &pb::SimulatorConfig) -> bool {
    m.stubs.is_empty() && m.contract.is_empty() && !m.neighbor && !m.model
}

/// Every configuration record with its epoch, so the configuration of any
/// epoch can be rebuilt (re-runs use the epoch of their `TurnBegin`).
#[derive(Debug)]
pub struct ConfigHistory {
    records: Vec<Record>,
    snapshots: BTreeMap<u64, Arc<Config>>,
    sql_default: u64,
}

impl Default for ConfigHistory {
    fn default() -> Self {
        ConfigHistory {
            records: Vec::new(),
            snapshots: BTreeMap::new(),
            sql_default: KindLimits::default().sql_bytes_per_actor,
        }
    }
}

impl ConfigHistory {
    /// Installation default for a kind with no `sql_bytes_per_actor` in a
    /// `Limits` record (`[sql] max_size_per_actor`).
    pub fn with_sql_default(mut self, bytes: u64) -> ConfigHistory {
        self.sql_default = bytes;
        self.snapshots.clear();
        self
    }

    pub fn push(&mut self, record: Record) {
        self.records.push(record);
        self.snapshots.clear();
    }

    /// The configuration after every record with epoch <= `epoch`.
    pub fn at(&mut self, epoch: u64) -> Arc<Config> {
        if let Some(c) = self.snapshots.get(&epoch) {
            return c.clone();
        }
        let mut c = Config::default().with_sql_default(self.sql_default);
        for r in &self.records {
            let e = match r {
                Record::Grant(g) => g.epoch,
                Record::Limits(l) => l.epoch,
                Record::Deployment(d) => d.epoch,
                Record::ForeignActor(f) => f.epoch,
                Record::PrivacyMode(p) => p.epoch,
                Record::SimulatorConfig(m) => m.epoch,
                _ => continue,
            };
            if e <= epoch {
                c.apply(r);
            }
        }
        let c = Arc::new(c);
        self.snapshots.insert(epoch, c.clone());
        c
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn grant(epoch: u64, cap: &str, op: pb::GrantOp, delivery: Option<pb::Delivery>) -> Record {
        Record::Grant(pb::Grant {
            epoch,
            op: op as i32,
            kind: "billing".into(),
            capability: cap.into(),
            delivery: delivery.map(|d| d as i32),
            rate: None,
            audit: None,
        })
    }

    #[test]
    fn wildcards_and_specificity() {
        assert_eq!(
            http_match("api.example.com", "API.example.com"),
            Some(usize::MAX)
        );
        assert!(http_match("*.example.com", "a.example.com").is_some());
        assert!(http_match("*.example.com", "a.b.example.com").is_some());
        assert!(http_match("*.example.com", "example.com").is_none());
        assert!(http_match("*.example.com", "badexample.com").is_none());
        let mut c = Config::default();
        c.apply(&grant(1, "http:*.example.com", pb::GrantOp::Grant, None));
        c.apply(&grant(
            2,
            "http:api.example.com",
            pb::GrantOp::Grant,
            Some(pb::Delivery::IdempotencyKeyed),
        ));
        assert_eq!(
            c.http_grant("billing", "api.example.com")
                .unwrap()
                .capability,
            "http:api.example.com"
        );
        assert_eq!(
            c.http_grant("billing", "x.example.com").unwrap().capability,
            "http:*.example.com"
        );
        assert!(c.http_grant("other", "api.example.com").is_none());
        assert!(c.http_grant("billing", "example.org").is_none());
    }

    #[test]
    fn history_rebuilds_any_epoch() {
        let mut h = ConfigHistory::default();
        h.push(grant(1, "http:a.com", pb::GrantOp::Grant, None));
        h.push(grant(2, "http:a.com", pb::GrantOp::Revoke, None));
        h.push(Record::Limits(pb::Limits {
            epoch: 3,
            kind: "billing".into(),
            fuel: Some(7),
            ..Default::default()
        }));
        assert!(h.at(1).http_grant("billing", "a.com").is_some());
        assert!(h.at(2).http_grant("billing", "a.com").is_none());
        assert_eq!(h.at(2).limits("billing").fuel, 50_000_000);
        assert_eq!(h.at(3).limits("billing").fuel, 7);
        assert_eq!(
            h.at(3).limits("billing").effect_timeout,
            Duration::from_secs(10)
        );
    }

    #[test]
    fn foreign_actors_follow_their_records() {
        let foreign = |epoch, op: pb::ForeignOp, name: &str| {
            Record::ForeignActor(pb::ForeignActor {
                epoch,
                op: op as i32,
                name: name.into(),
                port: 8080,
                ..Default::default()
            })
        };
        let mut h = ConfigHistory::default();
        h.push(foreign(1, pb::ForeignOp::Add, "echo"));
        h.push(foreign(2, pb::ForeignOp::Add, "payments.internal"));
        h.push(foreign(3, pb::ForeignOp::Remove, "echo"));
        assert!(h.at(0).foreign("echo").is_none());
        assert_eq!(h.at(1).foreign("echo").map(|f| f.port), Some(8080));
        assert_eq!(h.at(2).foreign_actors().count(), 2);
        assert!(h.at(3).foreign("echo").is_none());
        assert_eq!(h.at(3).epoch, 3);
        let at3 = h.at(3);
        let names: Vec<&str> = at3.foreign_actors().map(|f| f.name.as_str()).collect();
        assert_eq!(names, ["payments.internal"]);
    }

    #[test]
    fn parsing() {
        assert_eq!(
            Rate::parse("2/s"),
            Some(Rate {
                count: 2,
                per: Duration::from_secs(1)
            })
        );
        assert_eq!(Rate::parse("2/s").unwrap().render(), "2/s");
        assert!(Rate::parse("0/s").is_none());
        assert!(Rate::parse("2/d").is_none());
        assert_eq!(
            Capability::parse("http:*.Example.com"),
            Some(Capability::Http("*.example.com".into()))
        );
        assert_eq!(
            Capability::parse("secret:stripe-key"),
            Some(Capability::Secret("stripe-key".into()))
        );
        assert!(Capability::parse("http:").is_none());
        assert!(Capability::parse("ftp:x").is_none());
        assert_eq!(Delivery::default_for("get"), Delivery::ReplaySafe);
        assert_eq!(Delivery::default_for("POST"), Delivery::Unsafe);
    }

    #[test]
    fn the_privacy_mode_follows_its_records_by_epoch() {
        let mode = |epoch, mode: pb::PrivacyState| {
            Record::PrivacyMode(pb::PrivacyMode {
                epoch,
                mode: mode as i32,
                audit: None,
            })
        };
        let mut h = ConfigHistory::default();
        assert_eq!(h.at(0).privacy(), (pb::PrivacyState::Off, None));
        h.push(mode(2, pb::PrivacyState::On));
        h.push(mode(4, pb::PrivacyState::Off));
        assert_eq!(h.at(1).privacy(), (pb::PrivacyState::Off, None));
        assert_eq!(h.at(2).privacy(), (pb::PrivacyState::On, Some(2)));
        assert_eq!(h.at(3).privacy(), (pb::PrivacyState::On, Some(2)));
        assert_eq!(h.at(4).privacy(), (pb::PrivacyState::Off, Some(4)));
        assert_eq!(h.at(4).epoch, 4);
    }
}

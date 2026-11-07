//! The links of a fork (docs/design/m23-secret-backends.md section 6): the
//! configuration of a fork is main's at its fork point, links included. An
//! unmatched `crypto.*` of a fork refuses a name that is linked to an
//! external backend there (`SECRET_EXTERNAL`) instead of computing with the
//! built-in store's older value of it.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::disallowed_methods)]

use kronik_fork::{ProductionIndex, config_at, config_at_with};
use kronik_log::{Committed, Position};
use kronik_proto::Record;
use kronik_proto::log::v1 as pb;

/// A record of the log at `lsn`: a link of `name` to `backend`, or, with no
/// backend, the record an unlink leaves.
fn link(lsn: u64, name: &str, backend: &str) -> Committed {
    Committed {
        lsn,
        pos: Position {
            segment: 1,
            offset: lsn * 100,
        },
        record: Record::SecretLink(pb::SecretLink {
            name: name.into(),
            backend: backend.into(),
            r#ref: if backend.is_empty() {
                ""
            } else {
                "secret/a#key"
            }
            .into(),
            epoch: lsn,
            generation: lsn,
            ..Default::default()
        }),
    }
}

/// A link made after the fork point is not in force there, and an unlink is
/// not a link: the window of a fork reads like main's own configuration.
#[test]
fn a_fork_sees_the_links_in_force_at_its_fork_point() {
    // lsn 2: stripe is linked, lsn 4: it is unlinked, lsn 6: linked again;
    // `other` is linked at lsn 3 and never unlinked.
    let records = vec![
        link(2, "stripe", "bao"),
        link(3, "other", "bao"),
        link(4, "stripe", ""),
        link(6, "stripe", "bao"),
    ];
    let index = ProductionIndex::from_records(records, 6, 6);
    let linked = |fork_lsn: u64, name: &str| config_at(&index, fork_lsn).secret_is_linked(name);
    assert!(!linked(1, "stripe"), "before the link");
    assert!(linked(2, "stripe"), "at the link");
    assert!(linked(3, "stripe"));
    assert!(!linked(4, "stripe"), "at the unlink");
    assert!(!linked(5, "stripe"));
    assert!(linked(6, "stripe"), "linked again");
    assert!(!linked(2, "other"), "other: before its link");
    assert!(linked(5, "other"), "other: still linked");
    assert!(!linked(6, "unrelated"), "a name that was never linked");
    // The links count in the epoch of the configuration, as they do in
    // main's: the fork's turns carry the epoch of the fork point.
    assert_eq!(config_at_with(&index, 6, 0).epoch, 6);
    assert_eq!(config_at_with(&index, 3, 0).epoch, 3);
}

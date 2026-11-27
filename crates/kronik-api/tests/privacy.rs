//! `/v1/privacy` (docs/design/m8-privacy.md §3, §12): the mode is a recorded
//! configuration that survives a restart and a rebuild from the log.

// Test helpers outside #[test] functions may unwrap too.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use common::Site;
use serde_json::{Value, json};

impl Site {
    fn status(&self) -> Value {
        let (s, v) = self.call("GET", "/v1/privacy", Value::Null);
        assert_eq!(s, 200, "{v}");
        v
    }
}

#[test]
fn the_privacy_mode_is_recorded_and_survives_restart_and_rebuild() {
    let dir = tempfile::tempdir().unwrap();
    let epoch = {
        let d = Site::start(dir.path());
        assert_eq!(
            d.status(),
            json!({
                "mode": "off",
                "epoch": null,
                "keystore": {"subjects": 0, "keys": 0, "erased": 0},
                "pending_erasures": 0,
                "reseal": {
                    "segments_done": 0,
                    "segments_total": 0,
                    "values_sealed": 0,
                    "tombstones": 0,
                    "pending_segments": 0,
                    "blobs_sealed": 0,
                    "pending_blobs": 0
                }
            })
        );

        // The mode is "on" or "off".
        let (s, v) = d.call(
            "POST",
            "/v1/privacy/mode",
            json!({"mode": "maybe", "reason": "r"}),
        );
        assert_eq!(
            (s, v["error"]["code"].as_str()),
            (400, Some("BAD_REQUEST")),
            "{v}"
        );

        // A dry run says what would happen and records nothing.
        let (s, v) = d.call(
            "POST",
            "/v1/privacy/mode",
            json!({"mode": "on", "reason": "GDPR", "dry_run": true}),
        );
        assert_eq!(s, 200, "{v}");
        assert_eq!(
            (
                &v["dry_run"],
                &v["changed"],
                &v["mode"],
                &v["previous"],
                &v["lsn"]
            ),
            (
                &json!(true),
                &json!(true),
                &json!("on"),
                &json!("off"),
                &Value::Null
            )
        );
        assert!(v["epoch"].is_u64(), "{v}");
        assert_eq!(d.status()["mode"], "off");

        let (s, v) = d.call(
            "POST",
            "/v1/privacy/mode",
            json!({"mode": "on", "reason": "GDPR"}),
        );
        assert_eq!(s, 200, "{v}");
        assert_eq!(
            (&v["changed"], &v["previous"]),
            (&json!(true), &json!("off"))
        );
        assert!(v["lsn"].as_u64().unwrap() > 0, "{v}");
        let epoch = v["epoch"].as_u64().unwrap();
        assert_eq!(
            (&d.status()["mode"], d.status()["epoch"].as_u64()),
            (&json!("on"), Some(epoch))
        );

        // Asking for the mode in effect records nothing.
        let (_, v) = d.call(
            "POST",
            "/v1/privacy/mode",
            json!({"mode": "on", "reason": "again"}),
        );
        assert_eq!(
            (&v["changed"], &v["lsn"], v["epoch"].as_u64()),
            (&json!(false), &Value::Null, Some(epoch))
        );
        epoch
        // The runtime and its tasks are dropped here: a crash.
    };
    {
        let d = Site::start(dir.path());
        assert_eq!(
            (&d.status()["mode"], d.status()["epoch"].as_u64()),
            (&json!("on"), Some(epoch))
        );
    }
    // The materialized state is rebuilt from the log, the mode with it.
    std::fs::remove_file(dir.path().join("branches/main/state.db")).unwrap();
    let _ = std::fs::remove_file(dir.path().join("branches/main/state.db-wal"));
    let d = Site::start(dir.path());
    assert_eq!(
        (&d.status()["mode"], d.status()["epoch"].as_u64()),
        (&json!("on"), Some(epoch))
    );
    let (_, v) = d.call(
        "POST",
        "/v1/privacy/mode",
        json!({"mode": "off", "reason": "pilot over"}),
    );
    assert_eq!(
        (&v["changed"], &v["previous"]),
        (&json!(true), &json!("on"))
    );
    assert_eq!(d.status()["mode"], "off");
}

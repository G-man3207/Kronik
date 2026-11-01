use super::*;

#[test]
fn erasure_floor_distinguishes_no_row_from_zero_without_minting_or_changing_rows() {
    let pair = Pair::new();
    let revision = pair.first.revision().unwrap();
    assert_eq!(pair.a.erasure_floor("user:1").unwrap(), None);
    assert_eq!(pair.b.erasure_floor("user:1").unwrap(), None);
    assert_eq!(pair.first.revision().unwrap(), revision);
    assert_eq!(pair.first.stats().unwrap().keys, 0);
    assert_eq!(pair.first.stats().unwrap().erased, 0);
    pair.second.erase_through("user:1", 0, 1).unwrap();
    let revision = pair.first.revision().unwrap();
    assert_eq!(pair.a.erasure_floor("user:1").unwrap(), Some(0));
    assert_eq!(pair.b.erasure_floor("user:1").unwrap(), Some(0));
    assert_eq!(pair.first.revision().unwrap(), revision);
    assert_eq!(pair.first.stats().unwrap().keys, 0);
    let new = pair.seal(&pair.a, b"live data after zero-floor erasure");
    assert_eq!(version(&new), 1);
    assert_eq!(pair.a.erasure_floor("user:1").unwrap(), Some(0));
    assert_eq!(pair.b.erasure_floor("user:1").unwrap(), Some(0));
}

#[test]
fn erasure_floor_never_uses_active_a2_as_proof_of_old_plaintext_provenance() {
    let pair = Pair::new();
    let old = warm(&pair);
    assert_eq!(pair.a.erasure_floor("user:1").unwrap(), None);
    assert_eq!(pair.b.erasure_floor("user:1").unwrap(), None);
    let mut legacy = plain(b"old plaintext must not inherit A2 authority");
    pair.second.erase_through("user:1", 1, 2).unwrap();
    let new = pair.seal(&pair.a, b"new active A2");
    assert_eq!(version(&new), 2);
    let revision = pair.first.revision().unwrap();
    assert_eq!(pair.a.erasure_floor("user:1").unwrap(), Some(1));
    assert_eq!(pair.b.erasure_floor("user:1").unwrap(), Some(1));
    assert_eq!(pair.first.revision().unwrap(), revision);
    assert!(matches!(pair.a.open(&old), Opened::Erased { .. }));
    assert_eq!(pair.b.open(&new).bytes(), Some(b"new active A2".as_slice()));
    let original = legacy.clone();
    assert!(pair.a.seal_plain_source(&mut legacy, None, &|bytes| pair.fill(bytes), 3).is_err());
    assert_eq!(legacy, original);
}

#[test]
fn erasure_floor_failure_cannot_reuse_cached_absence_or_guess_unknown_history() {
    assert!(Sealer::plain().erasure_floor("user:1").is_err());
    for erased in [false, true] {
        let pair = Pair::new();
        if erased { pair.second.erase_through("user:1", 0, 1).unwrap(); }
        assert_eq!(pair.a.erasure_floor("user:1").unwrap(), erased.then_some(0));
        pair.first.conn().execute("DROP TABLE keystore_revision", []).unwrap();
        assert!(pair.a.erasure_floor("user:1").is_err());
        assert!(pair.b.erasure_floor("user:1").is_err());
        assert!(pair.a.erasure_floor("bad subject").is_err());
    }
}

#[test]
fn erasure_floor_and_revision_share_one_snapshot_despite_concurrent_zero_floor_commit() {
    let pair = Pair::new();
    let before = pair.first.revision().unwrap();
    let data_before = data_version(&pair.first.conn()).unwrap();
    let erased = Arc::new(AtomicBool::new(false));
    let observed = erased.clone();
    let writer = pair.second.clone();
    pair.first.conn().authorizer(Some(move |context: AuthContext<'_>| {
        if matches!(context.action, AuthAction::Read { table_name: "keystore_revision", .. })
            && !observed.swap(true, Ordering::SeqCst)
        { writer.erase_through("user:1", 0, 1).unwrap(); }
        Authorization::Allow
    })).unwrap();
    let (stamp, floor) = pair.first.erasure_floor_at_revision("user:1").unwrap();
    pair.first.conn().authorizer(None::<fn(AuthContext<'_>) -> Authorization>).unwrap();
    assert!(erased.load(Ordering::SeqCst));
    assert_eq!(floor, None);
    assert_eq!(stamp.revision, before);
    assert_eq!(stamp.data_version, data_before);
    assert!(pair.first.revision().unwrap() > stamp.revision);
    assert_eq!(pair.a.erasure_floor("user:1").unwrap(), Some(0));
    assert_eq!(pair.b.erasure_floor("user:1").unwrap(), Some(0));
}

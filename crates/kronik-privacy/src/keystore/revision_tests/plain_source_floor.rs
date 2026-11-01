use super::*;

#[test]
fn plain_source_floor_cas_accepts_never_erased_zero_and_one_receipts_without_live_off_mint() {
    for floor in [None, Some(0), Some(1)] {
        let pair = Pair::new();
        if let Some(floor) = floor {
            if floor == 1 {
                warm(&pair);
            }
            pair.second.erase_through("user:1", floor, 2).unwrap();
        }
        pair.a.set_on(false);
        let mut ordinary = plain(b"ordinary privacy-off data stays as recorded");
        let original = ordinary.clone();
        let before = pair.first.stats().unwrap();
        let revision = pair.first.revision().unwrap();
        pair.a
            .seal_value(&mut ordinary, &|_| panic!("ordinary off must not mint"), 3)
            .unwrap();
        assert_eq!(ordinary, original);
        assert_eq!(pair.first.stats().unwrap(), before);
        assert_eq!(pair.first.revision().unwrap(), revision);
        let mut proved_source = plain(b"fixture source belongs to the matching current receipt");
        pair.a
            .seal_plain_source(&mut proved_source, floor, &|bytes| pair.fill(bytes), 3)
            .unwrap();
        assert_eq!(version(&proved_source), floor.unwrap_or(0) + 1);
        assert_eq!(
            pair.b.open(&proved_source).bytes(),
            Some(b"fixture source belongs to the matching current receipt".as_slice())
        );
        assert_eq!(pair.a.erasure_floor("user:1").unwrap(), floor);
        let before = pair.first.stats().unwrap();
        let revision = pair.first.revision().unwrap();
        let mut second = plain(b"same receipt reuses the exact current key");
        pair.a
            .seal_plain_source(&mut second, floor, &|bytes| pair.fill(bytes), 4)
            .unwrap();
        assert_eq!(version(&second), version(&proved_source));
        assert_eq!(pair.first.stats().unwrap(), before);
        assert_eq!(pair.first.revision().unwrap(), revision);
    }
}

#[test]
fn plain_source_floor_cas_mismatch_never_mutates_or_uses_the_newest_key() {
    for (actual, expected) in [
        (None, Some(0)),
        (Some(0), None),
        (Some(1), None),
        (Some(1), Some(0)),
        (Some(1), Some(2)),
    ] {
        let pair = Pair::new();
        let mut value = plain(b"source captured before the mismatching receipt");
        let original = value.clone();
        if let Some(floor) = actual {
            pair.second.erase_through("user:1", floor, 1).unwrap();
            if floor == 1 {
                assert_eq!(
                    version(&pair.seal(&pair.a, b"active A2 is not source proof")),
                    2
                );
            }
        }
        let before = pair.first.stats().unwrap();
        let revision = pair.first.revision().unwrap();
        assert!(
            pair.a
                .seal_plain_source(&mut value, expected, &|bytes| pair.fill(bytes), 2)
                .is_err()
        );
        assert_eq!(value, original);
        assert_eq!(pair.first.stats().unwrap(), before);
        assert_eq!(pair.first.revision().unwrap(), revision);
        assert_eq!(pair.b.erasure_floor("user:1").unwrap(), actual);
    }
}

#[test]
fn plain_source_floor_advance_and_erased_original_a1_never_fall_back_to_a2_or_a3() {
    let pair = Pair::new();
    let a1 = warm(&pair);
    pair.second.erase_through("user:1", 1, 2).unwrap();
    let a2 = pair.seal(&pair.a, b"new live A2 after A1 erasure");
    assert_eq!(version(&a2), 2);
    let mut original_a1 = plain(b"logical row whose original sealed version is A1");
    let original = original_a1.clone();
    let revision = pair.first.revision().unwrap();
    assert!(
        pair.a
            .seal_value_at(&mut original_a1, 1, &|_| panic!(
                "missing original A1 must not request a nonce"
            ))
            .is_err()
    );
    assert_eq!(original_a1, original);
    assert_eq!(pair.first.revision().unwrap(), revision);
    assert!(matches!(pair.b.open(&a1), Opened::Erased { .. }));
    assert_eq!(
        pair.b.open(&a2).bytes(),
        Some(b"new live A2 after A1 erasure".as_slice())
    );
    let mut post_e_source = plain(b"fixture current source with a real E1 receipt");
    pair.a
        .seal_plain_source(&mut post_e_source, Some(1), &|bytes| pair.fill(bytes), 3)
        .unwrap();
    assert_eq!(version(&post_e_source), 2);
    let mut pending = plain(b"source captured under E1 before E2 committed");
    let original = pending.clone();
    pair.second.erase_through("user:1", 2, 4).unwrap();
    let before = pair.first.stats().unwrap();
    let revision = pair.first.revision().unwrap();
    assert!(
        pair.a
            .seal_plain_source(&mut pending, Some(1), &|bytes| pair.fill(bytes), 5)
            .is_err()
    );
    assert_eq!(pending, original);
    assert_eq!(pair.first.stats().unwrap(), before);
    assert_eq!(pair.first.revision().unwrap(), revision);
    assert_eq!(pair.first.stats().unwrap().keys, 0);
    assert!(matches!(pair.b.open(&a2), Opened::Erased { .. }));
}

#[test]
fn prepared_plain_source_version_is_bound_before_context_and_never_falls_forward_after_erasure() {
    let pair = Pair::new();
    let selected = pair
        .a
        .prepare_plain_source_version("user:1", None, &|bytes| pair.fill(bytes), 1)
        .unwrap();
    pair.second
        .rotate("user:1", [131; 32], [132; 24], 2)
        .unwrap();
    let mut bound_source = plain(b"source context already commits the selected version");
    pair.a
        .seal_value_at(&mut bound_source, selected, &|bytes| pair.fill(bytes))
        .unwrap();
    assert_eq!(version(&bound_source), selected);
    assert_eq!(
        pair.b.open(&bound_source).bytes(),
        Some(b"source context already commits the selected version".as_slice())
    );

    pair.second.erase_through("user:1", selected, 3).unwrap();
    let before = pair.first.stats().unwrap();
    let revision = pair.first.revision().unwrap();
    assert!(
        pair.a
            .prepare_plain_source_version("user:1", None, &|bytes| pair.fill(bytes), 4)
            .is_err()
    );
    let mut stale = plain(b"must not move the old source into the remaining newer key");
    let original = stale.clone();
    assert!(
        pair.a
            .seal_value_at(&mut stale, selected, &|_| panic!(
                "erased original must not request a nonce"
            ))
            .is_err()
    );
    assert_eq!(stale, original);
    assert_eq!(pair.first.stats().unwrap(), before);
    assert_eq!(pair.first.revision().unwrap(), revision);

    let current = pair
        .a
        .prepare_plain_source_version("user:1", Some(selected), &|bytes| pair.fill(bytes), 4)
        .unwrap();
    assert_eq!(current, selected + 1);
    assert_eq!(pair.first.stats().unwrap(), before);
    assert_eq!(pair.first.revision().unwrap(), revision);
    let mut proved_post_erasure = plain(b"separate current source with the real new receipt");
    pair.a
        .seal_value_at(&mut proved_post_erasure, current, &|bytes| pair.fill(bytes))
        .unwrap();
    assert_eq!(
        pair.b.open(&proved_post_erasure).bytes(),
        Some(b"separate current source with the real new receipt".as_slice())
    );
}

use super::*;

#[test]
fn wrapped_merge_local_applied_clock_changes_only_when_globally_proved_floor_advances() {
    let receiver = Pair::new();
    let mut capsule = WrappedSubjectVersion {
        subject: "user:1".into(),
        version: 3,
        key: None,
        erasure: Some(SubjectErasure {
            last_version: 1,
            erased_wall_ms: 7,
        }),
    };
    assert_eq!(
        receiver
            .first
            .merge_wrapped_version("user:1", 3, &capsule, Some(("user:1", 1)), 100)
            .unwrap(),
        WrappedVersionStatus::Missing
    );
    assert_eq!(
        receiver
            .first
            .export_wrapped_version("user:1", 3)
            .unwrap()
            .erasure,
        Some(SubjectErasure {
            last_version: 1,
            erased_wall_ms: 100
        })
    );
    let revision = receiver.first.revision().unwrap();
    capsule.erasure.as_mut().unwrap().erased_wall_ms = 777;
    for proof in [None, Some(("user:1", 0)), Some(("user:1", 1))] {
        assert_eq!(
            receiver
                .first
                .merge_wrapped_version("user:1", 3, &capsule, proof, 200)
                .unwrap(),
            WrappedVersionStatus::Missing
        );
        assert_eq!(receiver.first.revision().unwrap(), revision);
        assert_eq!(
            receiver
                .first
                .export_wrapped_version("user:1", 3)
                .unwrap()
                .erasure,
            Some(SubjectErasure {
                last_version: 1,
                erased_wall_ms: 100
            })
        );
    }
    capsule.erasure = Some(SubjectErasure {
        last_version: 2,
        erased_wall_ms: 8,
    });
    assert_eq!(
        receiver
            .first
            .merge_wrapped_version("user:1", 3, &capsule, Some(("user:1", 2)), 300)
            .unwrap(),
        WrappedVersionStatus::Missing
    );
    assert!(receiver.first.revision().unwrap() > revision);
    assert_eq!(
        receiver
            .first
            .export_wrapped_version("user:1", 3)
            .unwrap()
            .erasure,
        Some(SubjectErasure {
            last_version: 2,
            erased_wall_ms: 300
        })
    );
    let before = receiver.first.stats().unwrap();
    let revision = receiver.first.revision().unwrap();
    capsule.erasure = Some(SubjectErasure {
        last_version: 3,
        erased_wall_ms: 9,
    });
    assert!(
        receiver
            .first
            .merge_wrapped_version("user:1", 3, &capsule, None, 400)
            .is_err()
    );
    assert!(
        receiver
            .first
            .merge_wrapped_version("user:1", 3, &capsule, Some(("other:1", 3)), 400)
            .is_err()
    );
    assert!(
        receiver
            .first
            .merge_wrapped_version("user:1", 3, &capsule, Some(("user:1", 3)), u64::MAX)
            .is_err()
    );
    assert_eq!(receiver.first.stats().unwrap(), before);
    assert_eq!(receiver.first.revision().unwrap(), revision);
    assert_eq!(
        receiver
            .first
            .export_wrapped_version("user:1", 3)
            .unwrap()
            .erasure,
        Some(SubjectErasure {
            last_version: 2,
            erased_wall_ms: 300
        })
    );
}

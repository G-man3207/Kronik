#![allow(clippy::unwrap_used, clippy::expect_used)]

use kronik_effects::http::CompiledScrubber;
use kronik_proto::log::v1 as pb;
use kronik_sched::scrub::{MAX_SECRET_PATTERN_BYTES, http_request, http_url_contains};
use prost::Message as _;

#[test]
fn strict_raw_host_no_match_preserves_existing_canonical_v2_bytes_and_fingerprint() {
    use kronik_effects::http::{fingerprint, fingerprint_v2, parse_request_url, prepared_target};
    let values = [("unused", b"private-value".as_slice())];
    let matcher = CompiledScrubber::new(&values, MAX_SECRET_PATTERN_BYTES).unwrap();
    for (url, canonical_url) in [
        (
            "https://MiXeD.example/echo?x=1",
            "https://mixed.example/echo?x=1",
        ),
        ("https://[ABCD:DB8::1]/echo", "https://[abcd:db8::1]/echo"),
    ] {
        let source = pb::HttpEffectRequest {
            method: "GET".into(),
            url: url.into(),
            ..Default::default()
        };
        let original_bytes = source.encode_to_vec();
        let legacy = fingerprint(&source).unwrap();
        let (canonical, raw_host) = parse_request_url(&source.url).unwrap();
        assert!(
            !http_url_contains(&canonical, raw_host, &|bytes| matcher.is_match(bytes)).unwrap()
        );
        let mut expected = source.clone();
        expected.url = canonical_url.into();
        expected.fingerprint_version = 2;
        let expected_fingerprint = fingerprint_v2(&expected, &canonical).unwrap();
        let mut prepared = source.clone();
        let target = http_request(&mut prepared, &canonical, raw_host, &matcher, 4096).unwrap();
        assert_eq!(prepared.encode_to_vec(), expected.encode_to_vec());
        assert_eq!(target, canonical);
        assert_eq!(prepared_target(&prepared).unwrap(), target);
        assert_eq!(
            fingerprint_v2(&prepared, &target).unwrap(),
            expected_fingerprint
        );
        assert_eq!(source.encode_to_vec(), original_bytes);
        assert_eq!(fingerprint(&source).unwrap(), legacy);
    }
}

#[test]
fn strict_raw_host_and_canonical_fallback_share_match_policy_without_rescanning_marker_names() {
    use kronik_effects::http::{
        fingerprint, fingerprint_v2, parse_request_url, prepared_target, target_of,
    };
    for value in [b"ABC".as_slice(), b"abc".as_slice()] {
        let values = [("CaseNAME", value), ("later", b"CaseNAME".as_slice())];
        let matcher = CompiledScrubber::new(&values, MAX_SECRET_PATTERN_BYTES).unwrap();
        let source = pb::HttpEffectRequest {
            method: "GET".into(),
            url: "https://ABC.ExAmPlE/echo".into(),
            ..Default::default()
        };
        let original_bytes = source.encode_to_vec();
        let legacy = fingerprint(&source).unwrap();
        let (canonical, raw_host) = parse_request_url(&source.url).unwrap();
        assert!(http_url_contains(&canonical, raw_host, &|bytes| matcher.is_match(bytes)).unwrap());
        let mut prepared = source.clone();
        let target = http_request(&mut prepared, &canonical, raw_host, &matcher, 4096).unwrap();
        assert_eq!(target.host, "%5bsecret%3aCaseNAME%5d.example");
        assert_eq!(prepared.url, "https://%5bsecret%3aCaseNAME%5d.example/echo");
        assert!(!prepared.url.contains(std::str::from_utf8(value).unwrap()));
        assert_eq!(prepared_target(&prepared).unwrap(), target);
        assert_eq!(target_of(&prepared).unwrap().1, target.host);
        assert_eq!(
            fingerprint_v2(&prepared, &target).unwrap(),
            fingerprint_v2(&prepared, &prepared_target(&prepared).unwrap()).unwrap()
        );
        assert_eq!(source.encode_to_vec(), original_bytes);
        assert_eq!(fingerprint(&source).unwrap(), legacy);
    }
}

//! AWS Signature Version 4 for the fixed REST request shapes used by KMS.
use ring::{digest, hmac};
use zeroize::Zeroizing;

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 15) as usize] as char);
    }
    s
}
fn sha(bytes: &[u8]) -> String {
    hex(digest::digest(&digest::SHA256, bytes).as_ref())
}
fn mac(key: &[u8], bytes: &[u8]) -> Zeroizing<[u8; 32]> {
    let tag = hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, key), bytes);
    let mut result = Zeroizing::new([0; 32]);
    result.copy_from_slice(tag.as_ref());
    result
}
/// UTC from Env's Unix milliseconds, using the same civil-date algorithm as the CLI.
pub fn timestamp(wall_ms: u64) -> Result<String, String> {
    let seconds = wall_ms / 1000;
    let z = seconds / 86_400 + 719_468;
    let era = z / 146_097;
    let doe = z % 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + u64::from(m <= 2);
    if y > 9999 {
        return Err("AWS signing clock out of range".into());
    }
    let rem = seconds % 86_400;
    Ok(format!(
        "{y:04}{m:02}{d:02}T{:02}{:02}{:02}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    ))
}
/// `path` and `query` are already canonical; KMS uses `/` and an empty query.
#[allow(clippy::too_many_arguments)]
pub fn authorization(
    method: &str,
    path: &str,
    query: &str,
    headers: &[(String, String)],
    body: &[u8],
    access: &str,
    secret: &str,
    region: &str,
    service: &str,
    date: &str,
) -> Result<String, String> {
    if date.len() != 16 || !date.is_ascii() || !date[..8].bytes().all(|c| c.is_ascii_digit()) {
        return Err("invalid AWS signing date".into());
    }
    let mut headers: Vec<_> = headers
        .iter()
        .map(|(k, v)| {
            (
                k.to_ascii_lowercase(),
                Zeroizing::new(v.split_whitespace().collect::<Vec<_>>().join(" ")),
            )
        })
        .collect();
    headers.sort_by(|a, b| a.0.cmp(&b.0));
    if headers.windows(2).any(|p| p[0].0 == p[1].0) {
        return Err("duplicate AWS signing header".into());
    }
    let names = headers
        .iter()
        .map(|(k, _)| k.as_str())
        .collect::<Vec<_>>()
        .join(";");
    let mut canonical_headers = Zeroizing::new(String::new());
    for (k, v) in &headers {
        canonical_headers.push_str(k);
        canonical_headers.push(':');
        canonical_headers.push_str(v);
        canonical_headers.push('\n');
    }
    let canonical = Zeroizing::new(format!(
        "{method}\n{path}\n{query}\n{}\n{names}\n{}",
        canonical_headers.as_str(),
        sha(body)
    ));
    let day = &date[..8];
    let scope = format!("{day}/{region}/{service}/aws4_request");
    let to_sign = format!(
        "AWS4-HMAC-SHA256\n{date}\n{scope}\n{}",
        sha(canonical.as_bytes())
    );
    let initial = Zeroizing::new(format!("AWS4{secret}"));
    let kd = mac(initial.as_bytes(), day.as_bytes());
    let kr = mac(&kd[..], region.as_bytes());
    let ks = mac(&kr[..], service.as_bytes());
    let signing = mac(&ks[..], b"aws4_request");
    Ok(format!(
        "AWS4-HMAC-SHA256 Credential={access}/{scope}, SignedHeaders={names}, Signature={}",
        hex(&mac(&signing[..], to_sign.as_bytes())[..])
    ))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn published_get_vanilla_vector() {
        // AWS test suite, mirrored at Gooseus/nimaws/tests/aws-sig-v4-test-suite/get-vanilla.
        let auth = authorization(
            "GET",
            "/",
            "",
            &[
                ("Host".into(), "example.amazonaws.com".into()),
                ("X-Amz-Date".into(), "20150830T123600Z".into()),
            ],
            b"",
            "AKIDEXAMPLE",
            "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            "us-east-1",
            "service",
            "20150830T123600Z",
        )
        .unwrap();
        assert_eq!(
            auth,
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date, Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"
        );
    }
    #[test]
    fn published_fixed_path_post_and_session_vectors() {
        // aws-c-auth 3d29adce, tests/aws-signing-test-suite/v4; no upstream code copied.
        let cases = [
            (
                "POST",
                vec![],
                "5da7c1a2acd57cee7505fc6676e4e544621c30862966e37dddb68e92efbe5d6b",
            ),
            (
                "POST",
                vec![("My-Header1", "value1")],
                "c5410059b04c1ee005303aed430f6e6645f61f4dc9e1461ec8f8916fdf18852c",
            ),
            (
                "GET",
                vec![("My-Header1", " value1"), ("My-Header2", " \"a   b   c\"")],
                "acc3ed3afb60bb290fc8d2dd0098b9911fcaa05412b367055dee359757a9c736",
            ),
            (
                "GET",
                vec![(
                    "X-Amz-Security-Token",
                    "6e86291e8372ff2a2260956d9b8aae1d763fbf315fa00fa31553b73ebf194267",
                )],
                "07ec1639c89043aa0e3e2de82b96708f198cceab042d4a97044c66dd9f74e7f8",
            ),
        ];
        for (method, extra, expected) in cases {
            let mut headers = vec![
                ("Host".into(), "example.amazonaws.com".into()),
                ("X-Amz-Date".into(), "20150830T123600Z".into()),
            ];
            headers.extend(extra.into_iter().map(|(k, v)| (k.into(), v.into())));
            let signed = authorization(
                method,
                "/",
                "",
                &headers,
                b"",
                "AKIDEXAMPLE",
                "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
                "us-east-1",
                "service",
                "20150830T123600Z",
            )
            .unwrap();
            assert_eq!(signed.rsplit_once("Signature=").unwrap().1, expected);
        }
    }
    #[test]
    fn utc_calendar_boundaries() {
        assert_eq!(timestamp(0).unwrap(), "19700101T000000Z");
        assert_eq!(timestamp(1_440_938_160_000).unwrap(), "20150830T123600Z");
        assert!(timestamp(u64::MAX).is_err());
    }
}

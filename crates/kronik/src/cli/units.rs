//! Human units on the command line and in output: sizes such as `128Mi`,
//! counts such as `100M`, durations such as `10s`, and UTC times.

/// A size in bytes: a number, optionally with a binary suffix (`Ki`, `Mi`,
/// `Gi`, `Ti`, powers of 1024) or a decimal one (`k`, `M`, `G`, `T`, powers
/// of 1000), e.g. `128Mi`.
pub fn parse_size(s: &str) -> Result<u64, String> {
    let (n, unit) = number(s)?;
    let factor: u64 = match unit {
        "" => 1,
        "Ki" => 1 << 10,
        "Mi" => 1 << 20,
        "Gi" => 1 << 30,
        "Ti" => 1 << 40,
        "k" => 1_000,
        "M" => 1_000_000,
        "G" => 1_000_000_000,
        "T" => 1_000_000_000_000,
        _ => {
            return Err(format!(
                "unknown size unit {unit:?}: give bytes, or a number with Ki, Mi, Gi or Ti \
                 (1024) or k, M, G or T (1000), e.g. 128Mi"
            ));
        }
    };
    scale(s, n, factor)
}

/// A count: a number, optionally with `k`, `M` or `G` (powers of 1000),
/// e.g. `100M`.
pub fn parse_count(s: &str) -> Result<u64, String> {
    let (n, unit) = number(s)?;
    let factor: u64 = match unit {
        "" => 1,
        "k" => 1_000,
        "M" => 1_000_000,
        "G" => 1_000_000_000,
        _ => {
            return Err(format!(
                "unknown unit {unit:?}: give a number, optionally with k, M or G, e.g. 100M"
            ));
        }
    };
    scale(s, n, factor)
}

/// A duration in milliseconds: a number with `ms`, `s`, `m` or `h`, e.g.
/// `10s`.
pub fn parse_duration_ms(s: &str) -> Result<u64, String> {
    let (n, unit) = number(s)?;
    let factor: u64 = match unit {
        "ms" => 1,
        "s" => 1_000,
        "m" => 60_000,
        "h" => 3_600_000,
        "" => return Err(format!("{s:?} has no unit: give ms, s, m or h, e.g. 10s")),
        _ => {
            return Err(format!(
                "unknown duration unit {unit:?}: give ms, s, m or h, e.g. 10s"
            ));
        }
    };
    scale(s, n, factor)
}

/// The leading decimal number and the rest.
fn number(s: &str) -> Result<(u64, &str), String> {
    let end = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
    if end == 0 {
        return Err(format!("{s:?} does not start with a number"));
    }
    let n = s[..end]
        .parse()
        .map_err(|_| format!("{s:?} is too large"))?;
    Ok((n, &s[end..]))
}

fn scale(s: &str, n: u64, factor: u64) -> Result<u64, String> {
    n.checked_mul(factor)
        .ok_or_else(|| format!("{s:?} is too large"))
}

/// A share in (0, 1]: a percentage such as `10%` or a fraction such as
/// `0.1`.
pub fn parse_share(s: &str) -> Result<f64, String> {
    let v = match s.strip_suffix('%') {
        Some(p) => p.parse::<f64>().map(|p| p / 100.0),
        None => s.parse::<f64>(),
    }
    .map_err(|_| {
        format!("{s:?} is not a share: give a percentage such as 10% or a fraction such as 0.1")
    })?;
    if v > 0.0 && v <= 1.0 {
        Ok(v)
    } else {
        Err(format!("{s:?} is not more than 0% and at most 100%"))
    }
}

/// Bytes in the largest binary unit that divides them, e.g. `128 MiB`.
pub fn size(bytes: u64) -> String {
    match binary(bytes) {
        Some((n, unit)) => format!("{n} {unit}B"),
        None if bytes == 1 => "1 byte".to_owned(),
        None => format!("{bytes} bytes"),
    }
}

/// Bytes as a value that [`parse_size`] reads back, e.g. `128Mi`.
pub fn size_flag(bytes: u64) -> String {
    match binary(bytes) {
        Some((n, unit)) => format!("{n}{unit}"),
        None => bytes.to_string(),
    }
}

/// The largest binary unit (`Ti` to `Ki`) that divides `bytes`, and the
/// count of it.
fn binary(bytes: u64) -> Option<(u64, &'static str)> {
    [
        ("Ti", 1u64 << 40),
        ("Gi", 1 << 30),
        ("Mi", 1 << 20),
        ("Ki", 1 << 10),
    ]
    .into_iter()
    .find(|&(_, factor)| bytes >= factor && bytes.is_multiple_of(factor))
    .map(|(unit, factor)| (bytes / factor, unit))
}

/// Milliseconds in the largest unit that divides them, e.g. `10s`.
pub fn duration(ms: u64) -> String {
    for (unit, factor) in [("h", 3_600_000), ("m", 60_000), ("s", 1_000)] {
        if ms >= factor && ms.is_multiple_of(factor) {
            return format!("{}{unit}", ms / factor);
        }
    }
    format!("{ms}ms")
}

/// Milliseconds since the Unix epoch as a UTC time, e.g.
/// `2026-10-25T10:00:00Z`.
pub fn utc(ms: u64) -> String {
    let secs = ms / 1000;
    let (year, month, day) = civil_from_days(secs / 86_400);
    let rem = secs % 86_400;
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

/// The proleptic Gregorian date of a day count since 1970-01-01 (Howard
/// Hinnant's `civil_from_days`, for non-negative days).
fn civil_from_days(days: u64) -> (u64, u64, u64) {
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z % 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + u64::from(month <= 2);
    (year, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_sizes() {
        assert_eq!(parse_size("4096"), Ok(4096));
        assert_eq!(parse_size("128Mi"), Ok(128 << 20));
        assert_eq!(parse_size("2Gi"), Ok(2 << 30));
        assert_eq!(parse_size("1Ti"), Ok(1 << 40));
        assert_eq!(parse_size("64Ki"), Ok(64 << 10));
        assert_eq!(parse_size("10M"), Ok(10_000_000));
        assert_eq!(parse_size("5k"), Ok(5_000));
        for bad in ["", "Mi", "12XB", "1.5Gi", "-1", "1 Mi", "99999999999Ti"] {
            assert!(parse_size(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn parses_shares() {
        assert_eq!(parse_share("10%"), Ok(0.1));
        assert_eq!(parse_share("100%"), Ok(1.0));
        assert_eq!(parse_share("0.25"), Ok(0.25));
        assert_eq!(parse_share("1"), Ok(1.0));
        for bad in ["0", "0%", "101%", "1.5", "abc", "NaN", "-10%", ""] {
            assert!(parse_share(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn parses_counts_and_durations() {
        assert_eq!(parse_count("100000000"), Ok(100_000_000));
        assert_eq!(parse_count("100M"), Ok(100_000_000));
        assert_eq!(parse_count("2G"), Ok(2_000_000_000));
        assert!(parse_count("1Mi").is_err());
        assert_eq!(parse_duration_ms("500ms"), Ok(500));
        assert_eq!(parse_duration_ms("10s"), Ok(10_000));
        assert_eq!(parse_duration_ms("2m"), Ok(120_000));
        assert_eq!(parse_duration_ms("1h"), Ok(3_600_000));
        for bad in ["10", "10x", "s", "1.5s"] {
            assert!(parse_duration_ms(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn formats_sizes_and_durations() {
        assert_eq!(size(128 << 20), "128 MiB");
        assert_eq!(size(1536), "1536 bytes");
        assert_eq!(size(1 << 30), "1 GiB");
        assert_eq!(size(3 << 10), "3 KiB");
        assert_eq!(size(1), "1 byte");
        assert_eq!(size(0), "0 bytes");
        assert_eq!(duration(10_000), "10s");
        assert_eq!(duration(1_500), "1500ms");
        assert_eq!(duration(120_000), "2m");
        assert_eq!(duration(3_600_000), "1h");
        assert_eq!(duration(0), "0ms");
    }

    #[test]
    fn size_flags_parse_back() {
        for bytes in [0, 1, 1536, 64 << 10, 128 << 20, 1 << 30, 3 << 40] {
            assert_eq!(parse_size(&size_flag(bytes)), Ok(bytes), "{bytes}");
        }
        assert_eq!(size_flag(128 << 20), "128Mi");
        for ms in [1, 500, 10_000, 120_000, 3_600_000] {
            assert_eq!(parse_duration_ms(&duration(ms)), Ok(ms), "{ms}");
        }
    }

    #[test]
    fn formats_utc_times() {
        assert_eq!(utc(0), "1970-01-01T00:00:00Z");
        assert_eq!(utc(951_782_400_000), "2000-02-29T00:00:00Z");
        assert_eq!(utc(1_761_386_400_123), "2025-10-25T10:00:00Z");
        assert_eq!(utc(4_102_444_800_000), "2100-01-01T00:00:00Z");
    }
}

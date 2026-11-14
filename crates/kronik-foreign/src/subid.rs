//! Subordinate id ranges (`/etc/subuid`, `/etc/subgid`, see subuid(5)): the
//! uids and gids that the Kronik user namespace maps to 1–65535, with 0 mapped
//! to the `kronik` user itself (docs/adr/0060-non-root-daemon-user-namespace.md).

/// Where `kronik-userns.service` pins the Kronik user namespace.
pub const USERNS_PIN: &str = "/run/kronik-userns/user";

/// The size of the range: 0 is the user itself, 1–65535 come from the range,
/// so 65535 ids would do; 65536 is what `useradd` allocates and what other
/// tools expect.
pub const COUNT: u32 = 65536;

/// The lowest id `allocate` hands out, as `SUB_UID_MIN` in login.defs(5).
pub const FLOOR: u32 = 100_000;

/// One `name:start:count` line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Range {
    pub start: u32,
    pub count: u32,
}

impl Range {
    /// One past the last id, or `None` when the range overflows `u32`.
    pub fn end(self) -> Option<u32> {
        self.start.checked_add(self.count)
    }
}

/// Every well-formed line: the owner (a name or a numeric id) and its range.
/// Comments, blank lines and malformed lines are skipped.
pub fn parse(text: &str) -> impl Iterator<Item = (&str, Range)> {
    text.lines().filter_map(|line| {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            return None;
        }
        let mut parts = line.split(':');
        let (owner, start, count) = (parts.next()?, parts.next()?, parts.next()?);
        if parts.next().is_some() || owner.is_empty() {
            return None;
        }
        let range = Range {
            start: start.parse().ok()?,
            count: count.parse().ok()?,
        };
        (range.count > 0 && range.end().is_some()).then_some((owner, range))
    })
}

/// The first qualifying authorized range above `FLOOR`, by name or numeric
/// uid; overlap with another allocation makes it unusable.
pub fn find(text: &str, user: &str, uid: u32) -> Option<Range> {
    let (index, (_, range)) = parse(text).enumerate().find(|(_, (owner, r))| {
        (*owner == user || owner.parse::<u32>() == Ok(uid)) && r.start >= FLOOR && r.count >= COUNT
    })?;
    let selected = Range {
        start: range.start,
        count: COUNT,
    };
    let end = selected.end()?;
    parse(text)
        .enumerate()
        .all(|(other, (_, r))| {
            index == other
                || r.end()
                    .is_some_and(|last| end <= r.start || last <= selected.start)
        })
        .then_some(selected)
}

/// A free range of `COUNT` ids: above `FLOOR`, above every range in the
/// file and above `max_id_in_use` (the highest uid or gid in passwd or
/// group), so it overlaps nothing. `None` when that would overflow.
pub fn allocate(text: &str, max_id_in_use: u32) -> Option<Range> {
    let mut start = FLOOR.max(max_id_in_use.checked_add(1)?);
    for (_, r) in parse(text) {
        start = start.max(r.end()?);
    }
    let range = Range {
        start,
        count: COUNT,
    };
    range.end().map(|_| range)
}

/// The line to append for `user`.
pub fn line(user: &str, r: Range) -> String {
    format!("{user}:{}:{}\n", r.start, r.count)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overlapping_allocations_are_not_namespace_authority() {
        assert_eq!(find("kronik:0:65536\n", "kronik", 1001), None);
        assert_eq!(find("kronik:99999:65536\n", "kronik", 1001), None);
        assert_eq!(
            find("kronik:200000:65536\nother:250000:65536\n", "kronik", 1001),
            None
        );
        assert_eq!(
            find("kronik:200000:65536\nkronik:200000:65536\n", "kronik", 1001),
            None
        );
        assert_eq!(
            find("1001:200000:65536\n", "unused-name", 1001),
            Some(Range {
                start: 200000,
                count: COUNT
            })
        );
    }

    const FILE: &str = "# comment\nalice:100000:65536\n\nkronik:165536:65536\nbad:line\n1001:231072:65536\nshort:300000:10\n";

    #[test]
    fn finds_by_name_or_uid_and_skips_short_or_bad_lines() {
        assert_eq!(
            find(FILE, "kronik", 999),
            Some(Range {
                start: 165_536,
                count: COUNT
            })
        );
        assert_eq!(find(FILE, "bob", 1001).map(|r| r.start), Some(231_072));
        assert_eq!(find(FILE, "short", 5), None);
        assert_eq!(find(FILE, "nobody", 7), None);
        assert_eq!(parse(FILE).count(), 4);
    }

    #[test]
    fn allocates_above_every_range_and_every_id_in_use() {
        assert_eq!(allocate("", 999).map(|r| r.start), Some(FLOOR));
        assert_eq!(allocate(FILE, 999).map(|r| r.start), Some(300_010));
        assert_eq!(allocate("", 500_000).map(|r| r.start), Some(500_001));
        assert_eq!(allocate("x:4294900000:65536\n", 0), None);
        assert_eq!(allocate("", u32::MAX), None);
        assert_eq!(line("kronik", Range { start: 1, count: 2 }), "kronik:1:2\n");
    }
}

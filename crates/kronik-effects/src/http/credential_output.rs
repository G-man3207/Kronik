//! Output-only credential recognition; request normalization never uses this plan.
use aho_corasick::automaton::{Automaton, StateID};
use aho_corasick::nfa::noncontiguous::NFA;
use aho_corasick::{Anchored, MatchKind};
use std::collections::{HashMap, VecDeque};
use zeroize::Zeroizing;

use super::{ScrubError, ScrubMatch};

const BLOCK: usize = 256;
const TOKEN_PREFIX: &[u8] = b"kronik_";
const TOKEN_BYTES: usize = 50;

pub(super) struct CredentialMatcher {
    nfa: Option<NFA>,
    matches: Vec<usize>,
    lengths: Vec<usize>,
}

struct EncodedPattern(Zeroizing<Vec<u8>>);
impl AsRef<[u8]> for EncodedPattern {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

struct Patterns<I> {
    input: I,
    error: Option<ScrubError>,
}
impl<'a, I: Iterator<Item = &'a [u8]>> Iterator for Patterns<I> {
    type Item = EncodedPattern;
    fn next(&mut self) -> Option<Self::Item> {
        if self.error.is_some() {
            return None;
        }
        let value = self.input.next()?;
        let Some(length) = value.len().checked_mul(2).and_then(|n| n.checked_add(1)) else {
            self.error = Some(ScrubError::PatternLimit);
            return None;
        };
        let mut encoded = Zeroizing::new(Vec::new());
        if encoded.try_reserve_exact(length).is_err() {
            self.error = Some(ScrubError::MatcherUnavailable);
            return None;
        }
        for &byte in value.iter().rev() {
            encoded.push(1 + (byte >> 4));
            encoded.push(17 + (byte & 15));
        }
        encoded.push(0);
        Some(EncodedPattern(encoded))
    }
}

#[derive(Default)]
pub(super) struct Scratch {
    states: Vec<StateID>,
    rightmost: Option<usize>,
}

impl CredentialMatcher {
    pub(super) fn build<'a>(
        patterns: impl Iterator<Item = &'a [u8]> + Clone,
    ) -> Result<Self, ScrubError> {
        let mut lengths = Vec::new();
        for pattern in patterns.clone() {
            lengths
                .try_reserve(1)
                .map_err(|_| ScrubError::MatcherUnavailable)?;
            lengths.push(pattern.len());
        }
        if lengths.is_empty() {
            return Ok(Self {
                nfa: None,
                matches: Vec::new(),
                lengths,
            });
        }
        let mut encoded = Patterns {
            input: patterns,
            error: None,
        };
        // Only delimiter states have outputs; prefixes cannot copy every suffix match.
        let nfa = NFA::builder()
            .match_kind(MatchKind::Standard)
            .build(&mut encoded);
        if let Some(error) = encoded.error {
            return Err(error);
        }
        let nfa = nfa.map_err(|_| ScrubError::MatcherUnavailable)?;
        let matches = compile_matches(&nfa)?;
        Ok(Self {
            nfa: Some(nfa),
            matches,
            lengths,
        })
    }

    pub(super) fn is_match(&self, bytes: &[u8]) -> bool {
        let mut token_at = 0;
        if token(bytes, &mut token_at).is_some() {
            return true;
        }
        let Some(nfa) = &self.nfa else {
            return false;
        };
        let Ok(mut state) = nfa.start_state(Anchored::No) else {
            return false;
        };
        bytes.iter().rev().any(|&byte| {
            state = step(nfa, state, byte);
            self.matches[state.as_usize()] != 0
        })
    }

    pub(super) fn matches<'a>(
        &'a self,
        bytes: &'a [u8],
        scratch: &'a mut Scratch,
    ) -> Result<Matches<'a>, ScrubError> {
        scratch.states.clear();
        scratch.rightmost = None;
        if let Some(nfa) = &self.nfa {
            let mut state = nfa
                .start_state(Anchored::No)
                .map_err(|_| ScrubError::MatcherUnavailable)?;
            for block in (0..bytes.len().div_ceil(BLOCK)).rev() {
                let after = state;
                let start = block * BLOCK;
                let end = bytes.len().min(start + BLOCK);
                for &byte in bytes[start..end].iter().rev() {
                    state = step(nfa, state, byte);
                    if scratch.rightmost.is_none() && self.matches[state.as_usize()] != 0 {
                        scratch
                            .states
                            .try_reserve_exact(block + 1)
                            .map_err(|_| ScrubError::MatcherUnavailable)?;
                        scratch.rightmost = Some(block);
                    }
                }
                if scratch.rightmost.is_some() {
                    scratch.states.push(after);
                }
            }
        }
        let mut literals = Literals {
            nfa: self.nfa.as_ref(),
            bytes,
            states: &scratch.states,
            rightmost: scratch.rightmost,
            patterns: &self.matches,
            lengths: &self.lengths,
            block: 0,
            offset: 0,
            length: 0,
            matches: [None; BLOCK],
        };
        let literal = literals.next();
        let mut token_at = 0;
        let credential = token(bytes, &mut token_at);
        Ok(Matches {
            bytes,
            literals,
            literal,
            credential,
            token_at,
            consumed: 0,
        })
    }
}

fn ensure_states<T: Clone>(values: &mut Vec<T>, needed: usize, empty: T) -> Result<(), ScrubError> {
    if needed > values.capacity() {
        let capacity = values.capacity().saturating_mul(2).max(needed);
        values
            .try_reserve_exact(capacity - values.len())
            .map_err(|_| ScrubError::MatcherUnavailable)?;
    }
    if needed > values.len() {
        values.resize(needed, empty);
    }
    Ok(())
}

/// Compile the delimiter answer once; querying failure chains per input byte is quadratic.
fn compile_matches(nfa: &NFA) -> Result<Vec<usize>, ScrubError> {
    let root = nfa
        .start_state(Anchored::No)
        .map_err(|_| ScrubError::MatcherUnavailable)?;
    let mut matches = Vec::new();
    let mut failure = Vec::new();
    let mut queue = VecDeque::new();
    let mut memo = HashMap::new();
    let mut path = Vec::new();
    ensure_states(&mut matches, root.as_usize() + 1, 0)?;
    ensure_states(&mut failure, root.as_usize() + 1, StateID::ZERO)?;
    failure[root.as_usize()] = root;
    queue
        .try_reserve(1)
        .map_err(|_| ScrubError::MatcherUnavailable)?;
    queue.push_back(root);
    while let Some(state) = queue.pop_front() {
        let terminal = nfa.next_state(Anchored::Yes, state, 0);
        matches[state.as_usize()] = if nfa.is_match(terminal) {
            nfa.match_pattern(terminal, 0).as_usize() + 1
        } else {
            matches[failure[state.as_usize()].as_usize()]
        };
        for byte in 1..=32 {
            let next = nfa.next_state(Anchored::Yes, state, byte);
            if nfa.is_dead(next) || next == root {
                continue;
            }
            ensure_states(&mut failure, next.as_usize() + 1, StateID::ZERO)?;
            if failure[next.as_usize()] != StateID::ZERO {
                continue;
            }
            ensure_states(&mut matches, next.as_usize() + 1, 0)?;
            failure[next.as_usize()] = if state == root {
                root
            } else {
                fallback(
                    nfa,
                    failure[state.as_usize()],
                    byte,
                    root,
                    &failure,
                    &mut memo,
                    &mut path,
                )?
            };
            queue
                .try_reserve(1)
                .map_err(|_| ScrubError::MatcherUnavailable)?;
            queue.push_back(next);
        }
    }
    Ok(matches)
}

fn fallback(
    nfa: &NFA,
    mut state: StateID,
    byte: u8,
    root: StateID,
    failure: &[StateID],
    memo: &mut HashMap<(StateID, u8), StateID>,
    path: &mut Vec<StateID>,
) -> Result<StateID, ScrubError> {
    path.clear();
    let next = loop {
        if let Some(&next) = memo.get(&(state, byte)) {
            break next;
        }
        let next = nfa.next_state(Anchored::Yes, state, byte);
        if !nfa.is_dead(next) {
            break next;
        }
        if state == root {
            break root;
        }
        path.try_reserve(1)
            .map_err(|_| ScrubError::MatcherUnavailable)?;
        path.push(state);
        state = failure[state.as_usize()];
    };
    memo.try_reserve(path.len())
        .map_err(|_| ScrubError::MatcherUnavailable)?;
    for &state in path.iter() {
        memo.insert((state, byte), next);
    }
    Ok(next)
}

fn step(nfa: &NFA, state: StateID, byte: u8) -> StateID {
    let state = nfa.next_state(Anchored::No, state, 1 + (byte >> 4));
    nfa.next_state(Anchored::No, state, 17 + (byte & 15))
}

fn token(bytes: &[u8], at: &mut usize) -> Option<ScrubMatch> {
    while bytes.len().saturating_sub(*at) >= TOKEN_BYTES {
        let start = *at;
        if bytes[start..].starts_with(TOKEN_PREFIX)
            && bytes[start + TOKEN_PREFIX.len()..start + TOKEN_BYTES]
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        {
            *at += 1;
            return Some(ScrubMatch {
                start,
                end: start + TOKEN_BYTES,
                pattern: None,
            });
        }
        *at += 1;
    }
    None
}

struct Literals<'a> {
    nfa: Option<&'a NFA>,
    patterns: &'a [usize],
    lengths: &'a [usize],
    bytes: &'a [u8],
    states: &'a [StateID],
    rightmost: Option<usize>,
    block: usize,
    offset: usize,
    length: usize,
    matches: [Option<ScrubMatch>; BLOCK],
}

impl Iterator for Literals<'_> {
    type Item = ScrubMatch;
    fn next(&mut self) -> Option<Self::Item> {
        let nfa = self.nfa?;
        loop {
            while self.offset < self.length {
                let matched = self.matches[self.offset].take();
                self.offset += 1;
                if matched.is_some() {
                    return matched;
                }
            }
            let rightmost = self.rightmost?;
            if self.block > rightmost {
                return None;
            }
            let start = self.block * BLOCK;
            let end = self.bytes.len().min(start + BLOCK);
            let mut state = self.states[rightmost - self.block];
            self.matches.fill(None);
            for at in (start..end).rev() {
                state = step(nfa, state, self.bytes[at]);
                if let Some(pattern) = self.patterns[state.as_usize()].checked_sub(1) {
                    let length = self.lengths[pattern];
                    self.matches[at - start] = Some(ScrubMatch {
                        start: at,
                        end: at + length,
                        pattern: Some(pattern),
                    });
                }
            }
            self.block += 1;
            self.offset = 0;
            self.length = end - start;
        }
    }
}

pub(super) struct Matches<'a> {
    bytes: &'a [u8],
    literals: Literals<'a>,
    literal: Option<ScrubMatch>,
    credential: Option<ScrubMatch>,
    token_at: usize,
    consumed: usize,
}

impl Iterator for Matches<'_> {
    type Item = ScrubMatch;
    fn next(&mut self) -> Option<Self::Item> {
        while self
            .literal
            .is_some_and(|matched| matched.start < self.consumed)
        {
            self.literal = self.literals.next();
        }
        while self
            .credential
            .is_some_and(|matched| matched.start < self.consumed)
        {
            self.credential = token(self.bytes, &mut self.token_at);
        }
        let literal_first = match (self.literal, self.credential) {
            (Some(literal), Some(credential)) => {
                literal.start < credential.start
                    || literal.start == credential.start && literal.end > credential.end
            }
            (Some(_), None) => true,
            (None, Some(_)) => false,
            (None, None) => return None,
        };
        let matched = if literal_first {
            let matched = self.literal.take()?;
            self.literal = self.literals.next();
            matched
        } else {
            let matched = self.credential.take()?;
            self.credential = token(self.bytes, &mut self.token_at);
            matched
        };
        self.consumed = matched.end;
        Some(matched)
    }
}

#[cfg(test)]
mod tests {
    use super::super::{CompiledScrubber, ScrubError, ScrubLimits, StreamScrubber};

    fn reference(input: &[u8], secrets: &[(&str, &[u8])]) -> Vec<u8> {
        let mut credentials = Vec::new();
        let mut at = 0;
        while at + 50 <= input.len() {
            if &input[at..at + 7] == b"kronik_"
                && input[at + 7..at + 50]
                    .iter()
                    .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'_' || *byte == b'-')
            {
                credentials.push(at);
            }
            at += 1;
        }
        let mut output = Vec::new();
        let mut at = 0;
        while at < input.len() {
            let credential = credentials.contains(&at);
            let mut best = credential.then_some((50, None));
            for (name, value) in secrets {
                if !value.is_empty()
                    && input[at..].starts_with(value)
                    && best.is_none_or(|(length, _)| value.len() > length)
                {
                    best = Some((value.len(), Some(*name)));
                }
            }
            match best {
                Some((length, name)) => {
                    if let Some(name) = name {
                        output.extend_from_slice(b"[secret:");
                        output.extend_from_slice(name.as_bytes());
                        output.push(b']');
                    } else {
                        output.extend_from_slice(b"[secret:token]");
                    }
                    at += length;
                }
                None => {
                    output.push(input[at]);
                    at += 1;
                }
            }
        }
        output
    }

    #[test]
    fn credentials_and_literals_share_original_leftmost_longest_order() {
        let token = format!("kronik_{}", "A-_9".repeat(10) + "abc");
        let long = format!("{token}suffix");
        let secrets = [
            ("tiny", b"A".as_slice()),
            ("prefix", b"kronik_".as_slice()),
            ("same-token", token.as_bytes()),
            ("longest", long.as_bytes()),
            ("marker", b"[secret:token]".as_slice()),
            ("duplicate", token.as_bytes()),
        ];
        let matcher = CompiledScrubber::new_output(&secrets, 4096).unwrap();
        for input in [
            format!("{token}!{long} {token}"),
            format!("[secret:token] {token} kronik_short"),
            format!("x{token}y{token}"),
            format!("{}!{token}", "A".repeat(512)),
        ] {
            assert_eq!(
                matcher
                    .scrub_if_matched(input.as_bytes(), 16384)
                    .unwrap()
                    .unwrap(),
                reference(input.as_bytes(), &secrets)
            );
        }
        assert_eq!(
            CompiledScrubber::new(&[] as &[(&str, &[u8])], 0)
                .unwrap()
                .scrub_if_matched(token.as_bytes(), 100)
                .unwrap(),
            None
        );
        assert_eq!(
            CompiledScrubber::new_output(&[] as &[(&str, &[u8])], 0)
                .unwrap()
                .scrub_if_matched(token.as_bytes(), 14)
                .unwrap(),
            Some(b"[secret:token]".to_vec())
        );
    }

    #[test]
    fn reverse_literal_queries_preserve_binary_boundaries_and_inventory_order() {
        let values = (0u8..=255).map(|byte| vec![byte]).collect::<Vec<_>>();
        let patterns = values
            .iter()
            .map(|value| ("byte", value.as_slice()))
            .collect::<Vec<_>>();
        let matcher = CompiledScrubber::new_output(&patterns, 4096).unwrap();
        let input = (0u8..=255).chain((0u8..=255).rev()).collect::<Vec<_>>();
        assert_eq!(
            matcher.scrub_if_matched(&input, 16384).unwrap().unwrap(),
            reference(&input, &patterns)
        );
        let values = [b"babab".as_slice(), b"abab", b"bab", b"ab", b"b"];
        let patterns = values
            .iter()
            .map(|value| ("ordered", *value))
            .collect::<Vec<_>>();
        let matcher = CompiledScrubber::new_output(&patterns, 4096).unwrap();
        for length in [1, 255, 256, 257, 511, 512, 513, 4096] {
            let input = b"ab".repeat(length);
            assert_eq!(
                matcher.scrub_if_matched(&input, 65536).unwrap().unwrap(),
                reference(&input, &patterns)
            );
        }
    }

    #[test]
    fn unknown_credentials_cross_stream_and_window_boundaries_without_marker_rescan() {
        let token = format!("kronik_{}", "x".repeat(43));
        let patterns = [
            ("marker-word", b"token".as_slice()),
            ("byte", b"x".as_slice()),
        ];
        let input = format!("{}{}!{}", "z".repeat(64 * 1024 - 20), token, token).into_bytes();
        let expected = reference(&input, &patterns);
        let matcher = CompiledScrubber::new_output(&patterns, 4096).unwrap();
        let mut stream = StreamScrubber::from_compiled(
            matcher,
            ScrubLimits {
                output_bytes: 128 * 1024,
                pattern_bytes: 4096,
            },
            128 * 1024,
        )
        .unwrap();
        let mut output = Vec::new();
        for chunk in input.chunks(17) {
            output.extend_from_slice(stream.push(chunk).unwrap());
        }
        output.extend_from_slice(&stream.finish().unwrap());
        assert_eq!(output, expected);
        assert!(output.ends_with(b"[secret:token]![secret:token]"));
        let empty: &[(&str, &[u8])] = &[];
        let matcher = CompiledScrubber::new_output(empty, 0).unwrap();
        assert_eq!(
            matcher.scrub_if_matched(token.as_bytes(), 13),
            Err(ScrubError::OutputLimit)
        );
        assert_eq!(
            matcher.scrub_if_matched(b"no credential", 13).unwrap(),
            None
        );
        assert!(!matcher.is_match(b"kronik_short"));
    }

    #[test]
    fn an_earlier_literal_does_not_hide_an_overlapping_credential_start() {
        let token = format!("kronik_{}", "a".repeat(43));
        let input = format!("!kronik_{token}");
        let patterns = [("prefix", b"!kronik_".as_slice())];
        let expected = b"[secret:prefix][secret:token]";
        let matcher = CompiledScrubber::new_output(&patterns, 4096).unwrap();
        assert_eq!(
            matcher
                .scrub_if_matched(input.as_bytes(), 128)
                .unwrap()
                .unwrap(),
            expected
        );
        for split in 0..=input.len() {
            let matcher = CompiledScrubber::new_output(&patterns, 4096).unwrap();
            let mut stream = StreamScrubber::from_compiled(
                matcher,
                ScrubLimits {
                    output_bytes: 128,
                    pattern_bytes: 4096,
                },
                128,
            )
            .unwrap();
            let mut output = stream.push(&input.as_bytes()[..split]).unwrap().to_vec();
            output.extend_from_slice(stream.push(&input.as_bytes()[split..]).unwrap());
            output.extend_from_slice(&stream.finish().unwrap());
            assert_eq!(output, expected, "split {split}");
        }
    }

    #[test]
    fn long_shadow_prefix_keeps_the_longest_suffix_on_a_large_input() {
        let mut values = (1..=32)
            .map(|length| vec![b'a'; length])
            .collect::<Vec<_>>();
        values.push(format!("b{}", "a".repeat(4096)).into_bytes());
        let patterns = values
            .iter()
            .map(|value| ("best", value.as_slice()))
            .collect::<Vec<_>>();
        let matcher = CompiledScrubber::new_output(&patterns, 16 * 1024).unwrap();
        let input = vec![b'a'; 256 * 1024];
        assert_eq!(
            matcher.scrub_if_matched(&input, input.len()).unwrap(),
            Some(b"[secret:best]".repeat(input.len() / 32))
        );
    }

    #[test]
    fn credential_survives_every_split_at_the_real_read_window() {
        let token = format!("kronik_{}", "a".repeat(43));
        let empty: &[(&str, &[u8])] = &[];
        for split in 0..=50 {
            let prefix = "z".repeat(64 * 1024 - split);
            let input = format!("{prefix}{token}!").into_bytes();
            let matcher = CompiledScrubber::new_output(empty, 0).unwrap();
            let mut stream = StreamScrubber::from_compiled(
                matcher,
                ScrubLimits {
                    output_bytes: 128 * 1024,
                    pattern_bytes: 0,
                },
                128 * 1024,
            )
            .unwrap();
            let mut output = stream.push(&input[..64 * 1024]).unwrap().to_vec();
            output.extend_from_slice(stream.push(&input[64 * 1024..]).unwrap());
            output.extend_from_slice(&stream.finish().unwrap());
            assert_eq!(
                output,
                format!("{prefix}[secret:token]!").as_bytes(),
                "split {split}"
            );
            let literal = CompiledScrubber::new(empty, 0).unwrap();
            let mut literal = StreamScrubber::from_compiled(
                literal,
                ScrubLimits {
                    output_bytes: 128 * 1024,
                    pattern_bytes: 0,
                },
                128 * 1024,
            )
            .unwrap();
            let mut unchanged = literal.push(&input[..64 * 1024]).unwrap().to_vec();
            unchanged.extend_from_slice(literal.push(&input[64 * 1024..]).unwrap());
            unchanged.extend_from_slice(&literal.finish().unwrap());
            assert_eq!(unchanged, input, "literal split {split}");
        }
    }
}

//! # yb-redact
//!
//! Personal data taken out of captured text before it is stored. The gateway
//! sees only [`Redactor`]; [`PatternRedactor`] is the first implementation,
//! recognising what a pattern can: email addresses, phone numbers, payment
//! card numbers (checked with Luhn), national identity numbers and secrets
//! such as API keys, tokens and private keys. Each is replaced by a marker
//! naming what was there, so a dataset keeps its shape without the value.
//!
//! A captured body is redacted through [`redact_body`]: a JSON body (or each
//! JSON event of a stream) is decoded, every string in it is redacted as the
//! text it stands for, and the body is written back. Redacting the encoded
//! text instead would read an escape such as `\n` as part of the word after
//! it, and a pattern could miss the value or cut through the escape.

use regex::{Captures, Regex};
use std::borrow::Cow;
use std::sync::OnceLock;

/// Takes personal data out of text.
pub trait Redactor: Send + Sync {
    fn redact<'a>(&self, text: &'a str) -> Cow<'a, str>;
}

/// Recognises personal data by its shape.
#[derive(Debug, Default, Clone, Copy)]
pub struct PatternRedactor;

struct Rule {
    marker: &'static str,
    pattern: Regex,
    /// Which parts of a match are values, in order and apart: all of it, some
    /// of it, or none, for shapes that are also common in ordinary text (a
    /// long number is not always a card).
    accept: fn(&str) -> Vec<(usize, usize)>,
}

fn always(found: &str) -> Vec<(usize, usize)> {
    vec![(0, found.len())]
}

fn rules() -> &'static [Rule] {
    static RULES: OnceLock<Vec<Rule>> = OnceLock::new();
    RULES.get_or_init(|| {
        let rule = |marker, pattern: &str, accept| Rule {
            marker,
            pattern: Regex::new(pattern).expect("a redaction pattern compiles"),
            accept,
        };
        // Secrets first: a key can contain what looks like a phone number.
        vec![
            rule(
                "[PRIVATE_KEY]",
                r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----",
                always,
            ),
            rule(
                "[SECRET]",
                r"\b(?:sk-[A-Za-z0-9_-]{16,}|sk-ant-[A-Za-z0-9_-]{16,}|yb_[A-Za-z0-9_-]{16,}|gh[pousr]_[A-Za-z0-9]{20,}|xox[abpors]-[A-Za-z0-9-]{10,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35})\b",
                always,
            ),
            rule(
                "[SECRET]",
                r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b",
                always,
            ),
            rule(
                "[SECRET]",
                r"(?i)\bbearer\s+[A-Za-z0-9._~+/-]{16,}=*",
                always,
            ),
            rule(
                "[EMAIL]",
                r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
                always,
            ),
            rule("[CARD]", r"\b\d+(?:[ -]\d+)*\b", card),
            rule("[NATIONAL_ID]", r"\b\d{3}-\d{2}-\d{4}\b", always),
            rule(
                "[NATIONAL_ID]",
                r"\b[A-CEGHJ-PR-TW-Z]{2}\s?\d{2}\s?\d{2}\s?\d{2}\s?[A-D]\b",
                always,
            ),
            rule(
                "[PHONE]",
                r"(?:\+\d{1,3}[ .-]?)?(?:\(\d{2,4}\)[ .-]?|\b\d{2,4}[ .-])\d{3,4}[ .-]\d{3,4}\b",
                always,
            ),
        ]
    })
}

/// The card numbers in a run of digit groups, which can carry more around a
/// card: numbers before it, a security code or an expiry after it. A card is
/// one group of 13 to 19 digits, or several groups of 3 to 6 (4-4-4-4,
/// 4-6-5 and the like), so grids of single digits are not read as cards.
/// Every window of whole groups that passes Luhn is taken, and overlapping
/// ones are joined: a number that happens to pass beside a card costs its
/// digits rather than letting part of the card through.
fn card(found: &str) -> Vec<(usize, usize)> {
    let mut groups: Vec<(usize, usize)> = Vec::new();
    let mut start = None;
    for (i, c) in found
        .char_indices()
        .chain(std::iter::once((found.len(), ' ')))
    {
        match (c.is_ascii_digit(), start) {
            (true, None) => start = Some(i),
            (false, Some(from)) => {
                groups.push((from, i));
                start = None;
            }
            _ => {}
        }
    }
    let mut spans: Vec<(usize, usize)> = Vec::new();
    for first in 0..groups.len() {
        let mut digits = 0;
        for last in first..groups.len() {
            let length = groups[last].1 - groups[last].0;
            digits += length;
            if digits > 19 {
                break;
            }
            let shaped = if first == last {
                (13..=19).contains(&length)
            } else {
                groups[first..=last]
                    .iter()
                    .all(|(from, to)| (3..=6).contains(&(to - from)))
            };
            let (from, to) = (groups[first].0, groups[last].1);
            if shaped && digits >= 13 && luhn(&found[from..to]) {
                match spans.last_mut() {
                    Some(span) if from <= span.1 => span.1 = span.1.max(to),
                    _ => spans.push((from, to)),
                }
            }
        }
    }
    spans
}

/// Payment card numbers carry a Luhn check digit; most long numbers do not.
fn luhn(candidate: &str) -> bool {
    let digits: Vec<u32> = candidate.chars().filter_map(|c| c.to_digit(10)).collect();
    if !(13..=19).contains(&digits.len()) {
        return false;
    }
    let sum: u32 = digits
        .iter()
        .rev()
        .enumerate()
        .map(|(i, &d)| {
            if i % 2 == 1 {
                let doubled = d * 2;
                if doubled > 9 {
                    doubled - 9
                } else {
                    doubled
                }
            } else {
                d
            }
        })
        .sum();
    sum.is_multiple_of(10)
}

impl Redactor for PatternRedactor {
    fn redact<'a>(&self, text: &'a str) -> Cow<'a, str> {
        let mut out = Cow::Borrowed(text);
        for rule in rules() {
            if !rule.pattern.is_match(&out) {
                continue;
            }
            let replaced = rule
                .pattern
                .replace_all(&out, |found: &Captures| {
                    let text = &found[0];
                    let mut replaced = String::with_capacity(text.len());
                    let mut kept = 0;
                    for (start, end) in (rule.accept)(text) {
                        replaced.push_str(&text[kept..start]);
                        replaced.push_str(rule.marker);
                        kept = end;
                    }
                    replaced.push_str(&text[kept..]);
                    replaced
                })
                .into_owned();
            out = Cow::Owned(replaced);
        }
        out
    }
}

/// A captured body with its personal data taken out, or the body as it came
/// when there was none. A JSON body keeps its shape with every string, key
/// and number redacted; a stream is taken line by line, each `data:` event as
/// JSON where it is; other text is redacted as text. A body that is not text
/// (an audio upload) cannot be read for personal data and is not kept.
pub fn redact_body(redactor: &dyn Redactor, body: &[u8]) -> Vec<u8> {
    if let Some(redacted) = redact_json(redactor, body) {
        return redacted.unwrap_or_else(|| body.to_vec());
    }
    let Ok(text) = std::str::from_utf8(body) else {
        return Vec::new();
    };
    let mut changed = false;
    let lines: Vec<String> = text
        .split('\n')
        .map(|line| {
            let (line, carriage) = match line.strip_suffix('\r') {
                Some(line) => (line, "\r"),
                None => (line, ""),
            };
            let (prefix, rest) = match line.strip_prefix("data:") {
                Some(rest) => ("data:", rest),
                None => ("", line),
            };
            let leading = &rest[..rest.len() - rest.trim_start().len()];
            let redacted = match redact_json(redactor, rest.trim_start().as_bytes()) {
                Some(Some(json)) => format!("{leading}{}", String::from_utf8_lossy(&json)),
                Some(None) => rest.to_string(),
                None => redactor.redact(rest).into_owned(),
            };
            changed |= redacted != rest;
            format!("{prefix}{redacted}{carriage}")
        })
        .collect();
    if changed {
        lines.join("\n").into_bytes()
    } else {
        body.to_vec()
    }
}

/// None when the body is not a JSON object or array; Some(None) when it is
/// and holds nothing to redact.
fn redact_json(redactor: &dyn Redactor, body: &[u8]) -> Option<Option<Vec<u8>>> {
    let mut value: serde_json::Value = serde_json::from_slice(body).ok()?;
    if !(value.is_object() || value.is_array()) {
        return None;
    }
    // A key given twice parses to its last value only; the body as it came
    // would keep the earlier ones unread, so it is written back instead.
    let duplicated = serde_json::from_slice::<UniqueKeys>(body).is_err();
    if !redact_value(redactor, &mut value) && !duplicated {
        return Some(None);
    }
    Some(serde_json::to_vec(&value).ok())
}

fn card_shaped(number: &serde_json::Number) -> bool {
    let digits = number.to_string();
    (13..=19).contains(&digits.len())
        && digits.bytes().all(|b| b.is_ascii_digit())
        && matches!(digits.as_bytes()[0], b'3'..=b'6')
}

/// Parses only when no object in the JSON gives a key twice.
struct UniqueKeys;

impl<'de> serde::Deserialize<'de> for UniqueKeys {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(UniqueKeysVisitor)
    }
}

struct UniqueKeysVisitor;

impl<'de> serde::de::Visitor<'de> for UniqueKeysVisitor {
    type Value = UniqueKeys;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("JSON without a repeated key")
    }

    fn visit_map<A: serde::de::MapAccess<'de>>(self, mut map: A) -> Result<UniqueKeys, A::Error> {
        let mut seen = std::collections::HashSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if !seen.insert(key) {
                return Err(serde::de::Error::custom("a key is repeated"));
            }
            map.next_value::<UniqueKeys>()?;
        }
        Ok(UniqueKeys)
    }

    fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut seq: A) -> Result<UniqueKeys, A::Error> {
        while seq.next_element::<UniqueKeys>()?.is_some() {}
        Ok(UniqueKeys)
    }

    fn visit_bool<E>(self, _: bool) -> Result<UniqueKeys, E> {
        Ok(UniqueKeys)
    }
    fn visit_i64<E>(self, _: i64) -> Result<UniqueKeys, E> {
        Ok(UniqueKeys)
    }
    fn visit_u64<E>(self, _: u64) -> Result<UniqueKeys, E> {
        Ok(UniqueKeys)
    }
    fn visit_f64<E>(self, _: f64) -> Result<UniqueKeys, E> {
        Ok(UniqueKeys)
    }
    fn visit_str<E>(self, _: &str) -> Result<UniqueKeys, E> {
        Ok(UniqueKeys)
    }
    fn visit_unit<E>(self) -> Result<UniqueKeys, E> {
        Ok(UniqueKeys)
    }
}

/// Whether anything in the value was redacted. A number that holds
/// personal data, such as a card in a tool call's arguments, becomes the
/// marker as a string.
fn redact_value(redactor: &dyn Redactor, value: &mut serde_json::Value) -> bool {
    match value {
        serde_json::Value::String(text) => match redactor.redact(text) {
            Cow::Owned(redacted) if redacted != *text => {
                *text = redacted;
                true
            }
            _ => false,
        },
        // Only a whole number shaped like a card, which a tool call's
        // arguments can carry; timestamps and counts are left as numbers.
        serde_json::Value::Number(number) if card_shaped(number) => {
            let digits = number.to_string();
            match redactor.redact(&digits) {
                Cow::Owned(redacted) if redacted != digits => {
                    *value = serde_json::Value::String(redacted);
                    true
                }
                _ => false,
            }
        }
        serde_json::Value::Array(items) => items.iter_mut().fold(false, |changed, item| {
            redact_value(redactor, item) | changed
        }),
        serde_json::Value::Object(fields) => {
            let mut changed = false;
            let redacted: serde_json::Map<String, serde_json::Value> = std::mem::take(fields)
                .into_iter()
                .map(|(key, mut field)| {
                    changed |= redact_value(redactor, &mut field);
                    let key = match redactor.redact(&key) {
                        Cow::Owned(redacted) if redacted != key => {
                            changed = true;
                            redacted
                        }
                        _ => key,
                    };
                    (key, field)
                })
                .collect();
            *fields = redacted;
            changed
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn redact(text: &str) -> String {
        PatternRedactor.redact(text).into_owned()
    }

    #[test]
    fn personal_data_is_replaced_by_what_it_was() {
        assert_eq!(redact("mail ada@example.co.uk now"), "mail [EMAIL] now");
        assert_eq!(
            redact("call +1 415-555-0134 or (020) 7946 0958"),
            "call [PHONE] or [PHONE]"
        );
        assert_eq!(redact("card 4111 1111 1111 1111 exp"), "card [CARD] exp");
        assert_eq!(redact("ssn 123-45-6789"), "ssn [NATIONAL_ID]");
        assert_eq!(redact("nino AB 12 34 56 C"), "nino [NATIONAL_ID]");
        assert_eq!(
            redact("key sk-abcdefghijklmnop1234 here"),
            "key [SECRET] here"
        );
        assert_eq!(
            redact("Authorization: Bearer abcdefghijklmnopqrstuvwxyz"),
            "Authorization: [SECRET]"
        );
        assert_eq!(
            redact("token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N"),
            "token [SECRET]"
        );
        assert_eq!(
            redact("-----BEGIN RSA PRIVATE KEY-----\nMIIE\n-----END RSA PRIVATE KEY-----"),
            "[PRIVATE_KEY]"
        );
    }

    #[test]
    fn ordinary_text_and_numbers_are_left_alone() {
        for text in [
            "The meeting is at 10:30 on 2026-09-25.",
            "Order 123456789012 shipped",
            "Version 1.2.3 of the model",
            "It costs 4500 dollars.",
        ] {
            assert_eq!(redact(text), text);
        }
    }

    fn body(value: serde_json::Value) -> serde_json::Value {
        let bytes = redact_body(&PatternRedactor, &serde_json::to_vec(&value).unwrap());
        serde_json::from_slice(&bytes).expect("a redacted body is still JSON")
    }

    #[test]
    fn values_after_an_escape_are_redacted_and_the_body_stays_json() {
        let redacted = body(serde_json::json!({"messages": [{"role": "user", "content":
            "my key:\nsk-abcdefghijklmnop1234\nssn:\n123-45-6789\nmail:\nada@example.com\ncall:\n415 555 0134\ntok:\teyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N"}]}));
        assert_eq!(
            redacted["messages"][0]["content"],
            "my key:\n[SECRET]\nssn:\n[NATIONAL_ID]\nmail:\n[EMAIL]\ncall:\n[PHONE]\ntok:\t[SECRET]"
        );
    }

    #[test]
    fn a_card_is_redacted_whole_with_what_follows_it_kept() {
        assert_eq!(redact("card 4111 1111 1111 1111 123"), "card [CARD] 123");
        assert_eq!(
            redact("card 4111 1111 1111 1111 12/26"),
            "card [CARD] 12/26"
        );
        assert_eq!(redact("card:\n4111 1111 1111 1111"), "card:\n[CARD]");
    }

    #[test]
    fn a_card_after_other_numbers_is_found_and_long_ids_are_left_whole() {
        assert_eq!(redact("x 5 4111111111111111 y"), "x 5 [CARD] y");
        assert_eq!(redact("x 3-4012888888881881 y"), "x 3-[CARD] y");
        assert_eq!(redact("order 12 4111111111111111"), "order 12 [CARD]");
        // A 19-digit id is a card only when all of it passes Luhn.
        assert_eq!(redact("id 1234567890123456789"), "id 1234567890123456789");
    }

    #[test]
    fn a_grouped_card_after_other_grouped_numbers_is_found() {
        for (text, card) in [
            ("ref 12345 3782 822463 10005", "3782 822463 10005"),
            ("acct 99887 4111-1111-1111-1111", "4111-1111-1111-1111"),
            (
                "invoice 2026 0925 4111 1111 1111 1111",
                "4111 1111 1111 1111",
            ),
        ] {
            let redacted = redact(text);
            assert!(
                redacted.contains("[CARD]") && !redacted.contains(card),
                "{text} -> {redacted}"
            );
        }
    }

    #[test]
    fn grids_timestamps_and_counts_are_not_cards() {
        assert_eq!(
            redact("1 0 1 1 0 1 0 0 1 1 1 0 1 0 1 1 0 1 1"),
            "1 0 1 1 0 1 0 0 1 1 1 0 1 0 1 1 0 1 1"
        );
        let kept = br#"{"created_ms":1727300000009,"count":4111}"#;
        assert_eq!(redact_body(&PatternRedactor, kept), kept);
    }

    #[test]
    fn a_repeated_key_cannot_hide_a_value() {
        for repeated in [
            &br#"{"note":"ada@example.com","note":"x"}"#[..],
            &b"data: {\"d\":\"ada@example.com\",\"d\":\"x\"}"[..],
        ] {
            let stored = String::from_utf8(redact_body(&PatternRedactor, repeated)).unwrap();
            assert!(!stored.contains("ada@example.com"), "{stored}");
        }
    }

    #[test]
    fn numbers_and_keys_are_redacted_too() {
        let redacted = body(
            serde_json::json!({"input": {"card": 4111111111111111u64, "count": 3},
            "metadata": {"ada@example.com": "x"}}),
        );
        assert_eq!(redacted["input"]["card"], "[CARD]");
        assert_eq!(redacted["input"]["count"], 3);
        assert_eq!(redacted["metadata"]["[EMAIL]"], "x");
    }

    #[test]
    fn a_body_with_nothing_to_redact_is_kept_byte_for_byte() {
        for kept in [
            &br#"{ "z":1.50e1, "a":"caf\u00e9\/x" }"#[..],
            &b"plain text, nothing personal\r\n"[..],
        ] {
            assert_eq!(redact_body(&PatternRedactor, kept), kept);
        }
    }

    #[test]
    fn a_body_that_is_not_text_is_not_kept() {
        assert!(redact_body(&PatternRedactor, &[0xff, 0xfe, 0x00, 0x41]).is_empty());
    }

    #[test]
    fn a_crlf_stream_keeps_its_framing() {
        let stream = b"data: {\"d\":\"ada@example.com\"}\r\n\r\n";
        let redacted = String::from_utf8(redact_body(&PatternRedactor, stream)).unwrap();
        assert_eq!(redacted, "data: {\"d\":\"[EMAIL]\"}\r\n\r\n");
    }

    #[test]
    fn a_stream_is_redacted_event_by_event() {
        let stream = b"data: {\"delta\":\"write to\\nada@example.com\"}\n\ndata: [DONE]\n";
        let redacted = String::from_utf8(redact_body(&PatternRedactor, stream)).unwrap();
        assert_eq!(
            redacted,
            "data: {\"delta\":\"write to\\n[EMAIL]\"}\n\ndata: [DONE]\n"
        );
    }
}

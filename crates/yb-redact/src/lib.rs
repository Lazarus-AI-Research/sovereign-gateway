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
    /// Which part of a match is the value: all of it, a part, or none, for
    /// shapes that are also common in ordinary text (a long number is not
    /// always a card).
    accept: fn(&str) -> Option<(usize, usize)>,
}

fn always(found: &str) -> Option<(usize, usize)> {
    Some((0, found.len()))
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
            rule("[CARD]", r"\b(?:\d[ -]?){12,18}\d\b", card),
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

/// The card number in a run of digit groups, which can carry more around the
/// card: a number before it, a security code or an expiry after it. Only whole
/// groups are tried, longest first, so a long number that merely holds a
/// valid card's digits somewhere inside it is not cut apart.
fn card(found: &str) -> Option<(usize, usize)> {
    let starts: Vec<usize> = std::iter::once(0)
        .chain(
            found
                .char_indices()
                .filter(|&(_, c)| c == ' ' || c == '-')
                .map(|(i, _)| i + 1),
        )
        .collect();
    let ends: Vec<usize> = found
        .char_indices()
        .filter(|&(_, c)| c == ' ' || c == '-')
        .map(|(i, _)| i)
        .chain(std::iter::once(found.len()))
        .collect();
    let mut windows: Vec<(usize, usize)> = starts
        .iter()
        .flat_map(|&start| {
            ends.iter()
                .filter(move |&&end| end > start)
                .map(move |&end| (start, end))
        })
        .collect();
    windows.sort_by_key(|&(start, end)| std::cmp::Reverse(end - start));
    windows
        .into_iter()
        .find(|&(start, end)| luhn(&found[start..end]))
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
                .replace_all(&out, |found: &Captures| match (rule.accept)(&found[0]) {
                    Some((start, end)) => {
                        format!("{}{}{}", &found[0][..start], rule.marker, &found[0][end..])
                    }
                    None => found[0].to_string(),
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
    if !redact_value(redactor, &mut value) {
        return Some(None);
    }
    Some(serde_json::to_vec(&value).ok())
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
        serde_json::Value::Number(number) => {
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

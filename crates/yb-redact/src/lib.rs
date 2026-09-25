//! # yb-redact
//!
//! Personal data taken out of captured text before it is stored. The gateway
//! sees only [`Redactor`]; [`PatternRedactor`] is the first implementation,
//! recognising what a pattern can: email addresses, phone numbers, payment
//! card numbers (checked with Luhn), national identity numbers and secrets
//! such as API keys, tokens and private keys. Each is replaced by a marker
//! naming what was there, so a dataset keeps its shape without the value.
//!
//! Redaction runs on captured bodies as JSON text. Every marker is plain
//! ASCII without quotes or backslashes, so a redacted body is still valid
//! JSON.

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
    /// A further check a match must pass, for shapes that are also common
    /// in ordinary text (a long number is not always a card).
    accept: fn(&str) -> bool,
}

fn always(_: &str) -> bool {
    true
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
            rule("[CARD]", r"\b(?:\d[ -]?){12,18}\d\b", luhn),
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
                    if (rule.accept)(&found[0]) {
                        rule.marker.to_string()
                    } else {
                        found[0].to_string()
                    }
                })
                .into_owned();
            out = Cow::Owned(replaced);
        }
        out
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

    #[test]
    fn a_redacted_json_body_is_still_json() {
        let body = r#"{"messages":[{"role":"user","content":"I am ada@example.com, card 4111-1111-1111-1111"}]}"#;
        let redacted = redact(body);
        assert!(redacted.contains("[EMAIL]") && redacted.contains("[CARD]"));
        let value: serde_json_check::Value = serde_json_check::from_str(&redacted);
        assert!(value.ok);
    }

    // A tiny JSON validity check without a serde dependency.
    mod serde_json_check {
        pub struct Value {
            pub ok: bool,
        }
        pub fn from_str(s: &str) -> Value {
            let mut depth = 0i32;
            let mut in_string = false;
            let mut escaped = false;
            for c in s.chars() {
                if in_string {
                    match (escaped, c) {
                        (true, _) => escaped = false,
                        (false, '\\') => escaped = true,
                        (false, '"') => in_string = false,
                        _ => {}
                    }
                    continue;
                }
                match c {
                    '"' => in_string = true,
                    '{' | '[' => depth += 1,
                    '}' | ']' => depth -= 1,
                    _ => {}
                }
            }
            Value {
                ok: depth == 0 && !in_string,
            }
        }
    }
}

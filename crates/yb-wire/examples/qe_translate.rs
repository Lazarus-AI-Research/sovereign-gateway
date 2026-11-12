//! Prints the QE Chat Completions body for an Anthropic Messages or OpenAI
//! Responses body read from stdin as `{"shape": "anthropic" | "responses",
//! "body": {...}}` (no stored responses). Used by
//! `scripts/qe-lossless-check/check.py` to record cassettes.

use std::io::Read;

fn main() {
    let mut s = String::new();
    std::io::stdin().read_to_string(&mut s).expect("stdin");
    let v: serde_json::Value = serde_json::from_str(&s).expect("json");
    let body = &v["body"];
    let chat = match v["shape"].as_str() {
        Some("anthropic") => yb_wire::qe::anthropic_to_chat(body).map(|(c, _)| c),
        Some("responses") => {
            yb_wire::qe::responses_to_chat(body, &yb_wire::qe::NoItems).map(|t| t.body)
        }
        other => panic!("unknown shape {other:?}"),
    };
    match chat {
        Ok(c) => println!("{c}"),
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    }
}

//! Aggregation between a stream of [`StreamEvent`]s and a buffered
//! [`ChatResponse`], in both directions.
//!
//! The gateway always calls upstreams in streaming mode. When the *client* asked
//! for a non-streaming response, the gateway folds the upstream SSE into a single
//! [`ChatResponse`] with [`Aggregator`]; when a streaming client is somehow
//! served by a non-streaming upstream, [`events_from_response`] expands a
//! [`ChatResponse`] back into events the encoder can stream out.

use serde_json::{Map, Value};

use crate::ir::{ChatResponse, ContentBlock, StopReason, StreamEvent, Usage};

/// Folds a sequence of [`StreamEvent`]s into one [`ChatResponse`].
///
/// Text and reasoning deltas are concatenated; each tool call accumulates its
/// streamed `partial_json` until the stream ends, when it is parsed into the
/// tool's `input` object. Usage is merged by field-wise max so it is correct
/// whether the upstream reports it incrementally or cumulatively.
#[derive(Debug, Default)]
pub struct Aggregator {
    model: String,
    text: String,
    thinking: String,
    tools: Vec<PartialTool>,
    usage: Usage,
    stop_reason: Option<StopReason>,
}

#[derive(Debug)]
struct PartialTool {
    id: String,
    name: String,
    json: String,
}

impl Aggregator {
    /// A fresh, empty aggregator.
    pub fn new() -> Self {
        Self::default()
    }

    /// Fold one event into the accumulator.
    pub fn push(&mut self, ev: &StreamEvent) {
        match ev {
            StreamEvent::MessageStart { model } => {
                if self.model.is_empty() {
                    self.model = model.clone();
                }
            }
            StreamEvent::TextDelta { text } => self.text.push_str(text),
            StreamEvent::ThinkingDelta { text } => self.thinking.push_str(text),
            StreamEvent::ToolUseStart { id, name } => self.tools.push(PartialTool {
                id: id.clone(),
                name: name.clone(),
                json: String::new(),
            }),
            StreamEvent::ToolUseDelta { partial_json } => {
                if let Some(t) = self.tools.last_mut() {
                    t.json.push_str(partial_json);
                }
            }
            StreamEvent::UsageDelta { usage } => self.usage.merge(usage),
            StreamEvent::Done { stop_reason } => self.stop_reason = Some(stop_reason.clone()),
        }
    }

    /// Fold a slice of events.
    pub fn push_all(&mut self, events: &[StreamEvent]) {
        for ev in events {
            self.push(ev);
        }
    }

    /// Finalize into a [`ChatResponse`] with the given response `id`.
    pub fn into_response(self, id: impl Into<String>) -> ChatResponse {
        let mut content = Vec::new();
        if !self.thinking.is_empty() {
            content.push(ContentBlock::Thinking { text: self.thinking, signature: None });
        }
        if !self.text.is_empty() {
            content.push(ContentBlock::Text { text: self.text });
        }
        let had_tools = !self.tools.is_empty();
        for t in self.tools {
            let input = if t.json.trim().is_empty() {
                Value::Object(Map::new())
            } else {
                serde_json::from_str(&t.json).unwrap_or_else(|_| Value::Object(Map::new()))
            };
            content.push(ContentBlock::ToolUse {
                id: t.id,
                name: t.name,
                input,
            });
        }

        // Prefer an explicit tool-use stop when tool calls are present but the
        // upstream reported a plain end-of-turn.
        let stop_reason = match self.stop_reason {
            Some(StopReason::EndTurn) | None if had_tools => StopReason::ToolUse,
            Some(sr) => sr,
            None => StopReason::EndTurn,
        };

        ChatResponse {
            id: id.into(),
            model: self.model,
            content,
            stop_reason,
            usage: self.usage,
            prompt_cache_key: None,
            prompt_cache_retention: None,
        }
    }
}

/// Expand a buffered [`ChatResponse`] into the [`StreamEvent`]s that would have
/// produced it, so a streaming client can be served from a non-streaming
/// upstream. Order: `MessageStart`, content (thinking → text → tool calls),
/// `UsageDelta`, `Done`.
pub fn events_from_response(resp: &ChatResponse) -> Vec<StreamEvent> {
    let mut events = vec![StreamEvent::MessageStart {
        model: resp.model.clone(),
    }];

    for block in &resp.content {
        match block {
            ContentBlock::Thinking { text, .. } => {
                events.push(StreamEvent::ThinkingDelta { text: text.clone() })
            }
            ContentBlock::Text { text } => {
                events.push(StreamEvent::TextDelta { text: text.clone() })
            }
            ContentBlock::ToolUse { id, name, input } => {
                events.push(StreamEvent::ToolUseStart {
                    id: id.clone(),
                    name: name.clone(),
                });
                events.push(StreamEvent::ToolUseDelta {
                    partial_json: input.to_string(),
                });
            }
            // Tool results and images do not appear in an assistant response.
            _ => {}
        }
    }

    events.push(StreamEvent::UsageDelta { usage: resp.usage });
    events.push(StreamEvent::Done {
        stop_reason: resp.stop_reason.clone(),
    });
    events
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aggregates_text_and_usage() {
        let mut agg = Aggregator::new();
        agg.push_all(&[
            StreamEvent::MessageStart { model: "m".into() },
            StreamEvent::TextDelta { text: "Hel".into() },
            StreamEvent::TextDelta { text: "lo".into() },
            StreamEvent::UsageDelta {
                usage: Usage { input_tokens: 5, output_tokens: 2, ..Default::default() },
            },
            StreamEvent::Done { stop_reason: StopReason::EndTurn },
        ]);
        let resp = agg.into_response("id-1");
        assert_eq!(resp.model, "m");
        assert_eq!(resp.content, vec![ContentBlock::text("Hello")]);
        assert_eq!(resp.usage.output_tokens, 2);
        assert_eq!(resp.stop_reason, StopReason::EndTurn);
    }

    #[test]
    fn aggregates_tool_call_json() {
        let mut agg = Aggregator::new();
        agg.push_all(&[
            StreamEvent::ToolUseStart { id: "t1".into(), name: "get_weather".into() },
            StreamEvent::ToolUseDelta { partial_json: "{\"city\":".into() },
            StreamEvent::ToolUseDelta { partial_json: "\"SF\"}".into() },
        ]);
        let resp = agg.into_response("id-2");
        assert_eq!(resp.stop_reason, StopReason::ToolUse);
        match &resp.content[0] {
            ContentBlock::ToolUse { name, input, .. } => {
                assert_eq!(name, "get_weather");
                assert_eq!(input["city"], "SF");
            }
            other => panic!("expected tool use, got {other:?}"),
        }
    }

    #[test]
    fn round_trips_through_events() {
        let resp = ChatResponse {
            id: "x".into(),
            model: "m".into(),
            content: vec![ContentBlock::text("hi")],
            stop_reason: StopReason::EndTurn,
            usage: Usage { input_tokens: 3, output_tokens: 1, ..Default::default() },
            prompt_cache_key: None,
            prompt_cache_retention: None,
        };
        let events = events_from_response(&resp);
        let mut agg = Aggregator::new();
        agg.push_all(&events);
        let back = agg.into_response("x");
        assert_eq!(back.content, resp.content);
        assert_eq!(back.usage, resp.usage);
    }
}

//! Pricing catalog and cost math. Single source of truth for per-model cost.

use crate::ids::Micros;
use serde::{Deserialize, Serialize};

/// Per-model pricing. Costs are USD per 1M tokens; cache multipliers scale the
/// input price for cache reads/writes (Anthropic-style prompt caching).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub struct ModelPrice {
    pub input_per_1m: f64,
    pub output_per_1m: f64,
    #[serde(default = "one")]
    pub cache_read_multiplier: f64,
    #[serde(default = "one")]
    pub cache_write_multiplier: f64,
}

fn one() -> f64 {
    1.0
}

impl ModelPrice {
    pub const fn new(input_per_1m: f64, output_per_1m: f64) -> Self {
        ModelPrice {
            input_per_1m,
            output_per_1m,
            cache_read_multiplier: 1.0,
            cache_write_multiplier: 1.0,
        }
    }

    /// Compute the USD-micros cost of a turn given token counts.
    pub fn cost_micros(
        &self,
        input_tokens: i64,
        output_tokens: i64,
        cache_read_tokens: i64,
        cache_write_tokens: i64,
    ) -> Micros {
        let billable_input = (input_tokens - cache_read_tokens - cache_write_tokens).max(0);
        let input_cost = billable_input as f64 * self.input_per_1m;
        let cache_read_cost =
            cache_read_tokens as f64 * self.input_per_1m * self.cache_read_multiplier;
        let cache_write_cost =
            cache_write_tokens as f64 * self.input_per_1m * self.cache_write_multiplier;
        let output_cost = output_tokens as f64 * self.output_per_1m;
        let total_per_1m = input_cost + cache_read_cost + cache_write_cost + output_cost;
        // total_per_1m is "USD per 1M" units summed across token counts; divide by 1M
        // for USD, multiply by 1M for micros — the two cancel.
        total_per_1m.round() as Micros
    }
}

/// A small built-in price table used as a fallback when a deployment carries no
/// explicit pricing. Values are approximate public list prices; override in config.
pub fn builtin_price(model: &str) -> Option<ModelPrice> {
    let m = model.to_ascii_lowercase();
    let p = |i, o| Some(ModelPrice::new(i, o));
    match m.as_str() {
        x if x.contains("gpt-4o-mini") => p(0.15, 0.60),
        x if x.contains("gpt-4o") => p(2.50, 10.0),
        x if x.contains("gpt-4.1-mini") => p(0.40, 1.60),
        x if x.contains("gpt-4.1") => p(2.00, 8.0),
        x if x.contains("o3-mini") => p(1.10, 4.40),
        x if x.contains("claude-3-5-haiku") || x.contains("claude-haiku") => p(0.80, 4.0),
        x if x.contains("claude-3-5-sonnet") || x.contains("claude-sonnet") => p(3.0, 15.0),
        x if x.contains("claude-opus") || x.contains("claude-3-opus") => p(15.0, 75.0),
        x if x.contains("gemini-1.5-flash") || x.contains("gemini-2.0-flash") => p(0.075, 0.30),
        x if x.contains("gemini-1.5-pro") || x.contains("gemini-2.5-pro") => p(1.25, 5.0),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cost_basic() {
        // 1M input @ $2.50 + 1M output @ $10 = $12.50 = 12_500_000 micros
        let price = ModelPrice::new(2.50, 10.0);
        assert_eq!(price.cost_micros(1_000_000, 1_000_000, 0, 0), 12_500_000);
    }

    #[test]
    fn cache_read_discount() {
        let mut price = ModelPrice::new(2.0, 8.0);
        price.cache_read_multiplier = 0.1;
        // 1M input of which 1M is cache-read -> 1M * 2.0 * 0.1 = 200_000 micros
        assert_eq!(price.cost_micros(1_000_000, 0, 1_000_000, 0), 200_000);
    }
}

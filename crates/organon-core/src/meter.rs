//! Measured spend of a coding-agent session, read from its transcript.
//!
//! Claude Code writes every model request's token usage into the session transcript, and now
//! and then a `cost-state` line with the session's total cost per model as it computed it.
//! Totals are authoritative but sparse (written when a session starts or resumes), so spend
//! between them is estimated: one rate per model, calibrated on the latest total, applied to
//! weighted tokens. The weights are Anthropic's published price *ratios* (cache read 0.1×,
//! cache write 1.25× for 5 minutes and 2× for 1 hour, output 5× input), not prices, so the
//! estimate follows whatever the account actually pays. On real sessions the calibrated rate
//! moved 0.6% between two totals.

use std::collections::{BTreeMap, HashMap};

use serde_json::Value;

use crate::budget::Usd;
use crate::time::epoch_seconds;

/// Token weights relative to uncached input.
const W_CACHE_READ: f64 = 0.1;
const W_CACHE_5M: f64 = 1.25;
const W_CACHE_1H: f64 = 2.0;
const W_OUTPUT: f64 = 5.0;

/// Tokens of one kind of work.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Tokens {
    pub input: u64,
    pub cache_read: u64,
    pub cache_write_5m: u64,
    pub cache_write_1h: u64,
    pub output: u64,
}

impl Tokens {
    /// Price-weighted tokens (in units of uncached input).
    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn weighted(&self) -> f64 {
        self.input as f64
            + W_CACHE_READ * self.cache_read as f64
            + W_CACHE_5M * self.cache_write_5m as f64
            + W_CACHE_1H * self.cache_write_1h as f64
            + W_OUTPUT * self.output as f64
    }

    /// What the model read for this request: everything in its context window.
    #[must_use]
    pub fn context(&self) -> u64 {
        self.input + self.cache_read + self.cache_write_5m + self.cache_write_1h
    }

    fn add(&mut self, o: &Self) {
        self.input += o.input;
        self.cache_read += o.cache_read;
        self.cache_write_5m += o.cache_write_5m;
        self.cache_write_1h += o.cache_write_1h;
        self.output += o.output;
    }
}

/// One model request.
#[derive(Debug, Clone, PartialEq)]
pub struct Request {
    pub time: i64,
    pub model: String,
    pub tokens: Tokens,
}

/// A session's cost per model as the agent computed it, at a point in time.
#[derive(Debug, Clone, PartialEq)]
pub struct CostMark {
    pub time: i64,
    pub usd: Usd,
    /// Model → (cost, tokens) at that point.
    pub models: BTreeMap<String, (Usd, Tokens)>,
}

/// Everything a transcript says about spend.
#[derive(Debug, Clone, Default)]
pub struct Session {
    pub requests: Vec<Request>,
    pub marks: Vec<CostMark>,
}

/// Spend over a stretch of a session.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct SessionSpend {
    /// Estimated money, if every model used has a calibrated rate.
    pub usd: Option<Usd>,
    pub requests: usize,
    pub by_model: BTreeMap<String, Tokens>,
    /// Context of the latest request: what every further turn re-reads.
    pub context_now: Option<u64>,
    /// Estimated cost of the latest request: roughly what the next turn will cost.
    pub last_request_usd: Option<Usd>,
}

/// Read a Claude Code transcript (JSON Lines). Lines that are not usage or cost are ignored;
/// a request streamed as several lines counts once.
#[must_use]
pub fn read_claude_code(text: &str) -> Session {
    let mut by_id: HashMap<String, usize> = HashMap::new();
    let mut s = Session::default();
    let mut last_time = 0;
    for line in text.lines() {
        let Ok(v) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        if let Some(t) = v
            .get("timestamp")
            .and_then(Value::as_str)
            .and_then(epoch_seconds)
        {
            last_time = t;
        }
        match v.get("type").and_then(Value::as_str) {
            Some("assistant") => {
                let Some(m) = v.get("message") else { continue };
                let (Some(u), Some(model)) =
                    (m.get("usage"), m.get("model").and_then(Value::as_str))
                else {
                    continue;
                };
                if model.starts_with('<') {
                    continue; // synthetic messages cost nothing
                }
                let r = Request {
                    time: last_time,
                    model: model.to_owned(),
                    tokens: usage(u),
                };
                let id = m.get("id").and_then(Value::as_str).unwrap_or_default();
                match by_id.get(id) {
                    Some(&i) if !id.is_empty() => s.requests[i] = r,
                    _ => {
                        by_id.insert(id.to_owned(), s.requests.len());
                        s.requests.push(r);
                    }
                }
            }
            Some("cost-state") => {
                let models = v
                    .get("modelUsage")
                    .and_then(Value::as_object)
                    .map(|o| {
                        o.iter()
                            .map(|(k, u)| (k.clone(), (Usd(f(u, "costUSD")), model_usage(u))))
                            .collect()
                    })
                    .unwrap_or_default();
                s.marks.push(CostMark {
                    time: last_time,
                    usd: Usd(f(&v, "totalCostUSD")),
                    models,
                });
            }
            _ => {}
        }
    }
    s
}

fn n(v: &Value, k: &str) -> u64 {
    v.get(k).and_then(Value::as_u64).unwrap_or(0)
}

fn f(v: &Value, k: &str) -> f64 {
    v.get(k).and_then(Value::as_f64).unwrap_or(0.0)
}

fn usage(u: &Value) -> Tokens {
    let cc = u.get("cache_creation");
    let (w5, w1) = match cc {
        Some(c) => (
            n(c, "ephemeral_5m_input_tokens"),
            n(c, "ephemeral_1h_input_tokens"),
        ),
        // Older transcripts: no split, count it as the 5-minute kind.
        None => (n(u, "cache_creation_input_tokens"), 0),
    };
    Tokens {
        input: n(u, "input_tokens"),
        cache_read: n(u, "cache_read_input_tokens"),
        cache_write_5m: w5,
        cache_write_1h: w1,
        output: n(u, "output_tokens"),
    }
}

fn model_usage(u: &Value) -> Tokens {
    let (w5, w1) = (
        n(u, "cacheCreationEphemeral5mInputTokens"),
        n(u, "cacheCreationEphemeral1hInputTokens"),
    );
    let total_w = n(u, "cacheCreationInputTokens");
    Tokens {
        input: n(u, "inputTokens"),
        cache_read: n(u, "cacheReadInputTokens"),
        cache_write_5m: if w5 + w1 == 0 { total_w } else { w5 },
        cache_write_1h: w1,
        output: n(u, "outputTokens"),
    }
}

impl Session {
    /// Merge another transcript of the same work (a subagent's).
    pub fn absorb(&mut self, other: Session) {
        self.requests.extend(other.requests);
        self.marks.extend(other.marks);
        self.requests.sort_by_key(|r| r.time);
        self.marks.sort_by_key(|m| m.time);
    }

    /// Dollars per weighted token, per model, from the latest total that has that model.
    #[must_use]
    pub fn rates(&self) -> BTreeMap<String, f64> {
        let mut rates = BTreeMap::new();
        for m in &self.marks {
            for (model, (usd, tokens)) in &m.models {
                let w = tokens.weighted();
                if w > 0.0 && usd.0 > 0.0 {
                    rates.insert(model.clone(), usd.0 / w);
                }
            }
        }
        rates
    }

    /// Spend from `since` (epoch seconds, inclusive) to the end of the transcript, priced with
    /// `rates` (from [`Session::rates`], possibly of an earlier part of the same transcript).
    #[must_use]
    pub fn spend_since(&self, since: i64, rates: &BTreeMap<String, f64>) -> SessionSpend {
        let mut out = SessionSpend::default();
        let mut usd = Some(0.0);
        for r in self.requests.iter().filter(|r| r.time >= since) {
            out.requests += 1;
            out.by_model
                .entry(r.model.clone())
                .or_default()
                .add(&r.tokens);
            usd = match (usd, rates.get(&r.model)) {
                (Some(u), Some(rate)) => Some(u + rate * r.tokens.weighted()),
                _ => None,
            };
        }
        out.usd = usd.map(Usd);
        let last = self.requests.last();
        out.context_now = last.map(|r| r.tokens.context());
        out.last_request_usd = last.and_then(|r| {
            rates
                .get(&r.model)
                .map(|rate| Usd(rate * r.tokens.weighted()))
        });
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(id: &str, t: &str, read: u64, out: u64) -> String {
        format!(
            r#"{{"type":"assistant","timestamp":"{t}","message":{{"id":"{id}","model":"m","usage":{{"input_tokens":2,"cache_read_input_tokens":{read},"cache_creation":{{"ephemeral_5m_input_tokens":0,"ephemeral_1h_input_tokens":100}},"output_tokens":{out}}}}}}}"#
        )
    }

    #[test]
    fn streamed_requests_count_once_and_spend_is_calibrated_on_the_total() {
        let mark = r#"{"type":"cost-state","totalCostUSD":3.0,"modelUsage":{"m":{"costUSD":3.0,"inputTokens":4,"cacheReadInputTokens":2000,"cacheCreationEphemeral1hInputTokens":200,"outputTokens":20}}}"#;
        let text = [
            req("a", "2026-11-13T10:00:00Z", 1000, 5),
            req("a", "2026-11-13T10:00:01Z", 1000, 10), // same request, streamed further
            mark.to_owned(),
            req("b", "2026-11-13T10:05:00Z", 1000, 10),
            "not json".to_owned(),
        ]
        .join("\n");
        let s = read_claude_code(&text);
        assert_eq!(s.requests.len(), 2);
        assert_eq!(s.marks.len(), 1);
        // weighted per request: 2 + 100 + 200 + 50 = 352; the total covers both: 704 → $3.
        let all = s.spend_since(0, &s.rates());
        assert!((all.usd.unwrap().0 - 3.0).abs() < 1e-9, "{all:?}");
        let later = s.spend_since(epoch_seconds("2026-11-13T10:01:00Z").unwrap(), &s.rates());
        assert!((later.usd.unwrap().0 - 1.5).abs() < 1e-9);
        assert_eq!(later.requests, 1);
        assert_eq!(later.context_now, Some(1102));
        assert!((later.last_request_usd.unwrap().0 - 1.5).abs() < 1e-9);
    }

    #[test]
    fn a_model_without_a_total_leaves_money_unknown() {
        let s = read_claude_code(&req("a", "2026-11-13T10:00:00Z", 10, 1));
        let sp = s.spend_since(0, &s.rates());
        assert_eq!(sp.usd, None);
        assert_eq!(sp.by_model["m"].output, 1);
    }
}

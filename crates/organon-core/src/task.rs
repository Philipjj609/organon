//! Tasks: a goal with a budget declared up front, a trail of what was done for it, and an
//! episode when it ends (what it cost, how it went), which is what learning learns from.

use serde::{Deserialize, Serialize};
use serde_json::json;

use organon_protocol::{Cost, Episode, EpisodeId, EpisodeType, Outcome};

use crate::budget::{Budget, Effort, Minutes, Spend};
use crate::meter::SessionSpend;
use crate::time::{epoch_seconds, rfc3339};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Task {
    pub slug: String,
    pub goal: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effort: Option<Effort>,
    pub budget: Budget,
    /// RFC 3339.
    pub started: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ended: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outcome: Option<Outcome>,
    /// What was left unknown or undone when it ended.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub left: Option<String>,
    /// Where the agent session's transcript stood when the task began, so spend is read from
    /// there on rather than from the whole session.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub meter: Option<MeterStart>,
}

/// A transcript position and the rates calibrated on everything before it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MeterStart {
    pub transcript: String,
    /// Byte offset where the task's part of the transcript begins.
    pub offset: u64,
    /// Dollars per weighted token, per model.
    #[serde(default)]
    pub rates: std::collections::BTreeMap<String, f64>,
}

/// One entry of a task's trail: an organ used, or a policy decision that was not "allow".
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum Event {
    Organ {
        time: String,
        organ: String,
        /// The subcommand, if any (`fetch`, `recall`).
        #[serde(default, skip_serializing_if = "String::is_empty")]
        what: String,
    },
    Policy {
        time: String,
        decision: crate::policy::Decision,
        reason: String,
        action: String,
    },
}

/// A short, stable name for a goal: its first words, lowercase, joined by `-`.
#[must_use]
pub fn slug(goal: &str) -> String {
    let words: Vec<String> = goal
        .split(|c: char| !c.is_alphanumeric())
        .filter(|w| !w.is_empty())
        .map(str::to_lowercase)
        .collect();
    let mut s = String::new();
    for w in words {
        if !s.is_empty() && s.len() + w.len() >= 40 {
            break;
        }
        if !s.is_empty() {
            s.push('-');
        }
        s.push_str(&w);
    }
    if s.is_empty() {
        "task".into()
    } else {
        s
    }
}

impl Task {
    #[must_use]
    pub fn new(goal: &str, effort: Option<Effort>, budget: Budget, now: i64) -> Self {
        Self {
            slug: slug(goal),
            goal: goal.trim().to_owned(),
            effort,
            budget,
            started: rfc3339(now),
            ended: None,
            outcome: None,
            left: None,
            meter: None,
        }
    }

    #[must_use]
    pub fn is_open(&self) -> bool {
        self.ended.is_none()
    }

    /// Whether this task is metered on the session with this transcript. Budgets act only in
    /// the session a task was declared in, so one session's spent budget never stops another.
    #[must_use]
    pub fn metered_in(&self, transcript: &str) -> bool {
        let norm = |p: &str| p.replace('\\', "/").to_lowercase();
        self.meter
            .as_ref()
            .is_some_and(|m| !transcript.is_empty() && norm(&m.transcript) == norm(transcript))
    }

    #[must_use]
    pub fn started_at(&self) -> i64 {
        epoch_seconds(&self.started).unwrap_or(0)
    }

    /// Spend so far (or in total, once ended). Money comes from the session meter, if any.
    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn spend(&self, session: Option<&SessionSpend>, now: i64) -> Spend {
        let end = self.ended.as_deref().and_then(epoch_seconds).unwrap_or(now);
        Spend {
            usd: session.and_then(|s| s.usd),
            minutes: Minutes((end - self.started_at()).max(0) as f64 / 60.0),
        }
    }

    /// Close the task.
    pub fn finish(&mut self, outcome: Outcome, left: Option<String>, now: i64) {
        self.ended = Some(rfc3339(now));
        self.outcome = Some(outcome);
        self.left = left.filter(|l| !l.trim().is_empty());
    }

    /// The protocol episode for this task: what it cost and how it went.
    #[must_use]
    pub fn episode(
        &self,
        spend: &Spend,
        session: Option<&SessionSpend>,
        trail: &[Event],
    ) -> Episode {
        let (tokens_in, tokens_out, model) = session.map_or((None, None, None), |s| {
            let tin = s
                .by_model
                .values()
                .map(|t| t.input + t.cache_read + t.cache_write_5m + t.cache_write_1h)
                .sum();
            let tout = s.by_model.values().map(|t| t.output).sum();
            let model = (s.by_model.len() == 1)
                .then(|| s.by_model.keys().next().cloned())
                .flatten();
            (Some(tin), Some(tout), model)
        });
        let organs: Vec<serde_json::Value> = trail
            .iter()
            .filter_map(|e| match e {
                Event::Organ { organ, what, .. } => Some(json!(format!("{organ} {what}").trim())),
                Event::Policy { .. } => None,
            })
            .collect();
        Episode {
            id: EpisodeId::of(format!("task\n{}\n{}", self.slug, self.started).as_bytes()),
            kind: EpisodeType::Task,
            task: self.goal.clone(),
            started: self.started.clone(),
            ended: self.ended.clone(),
            inputs: vec![json!({ "effort": self.effort, "budget": self.budget })],
            outputs: organs,
            outcome: self.outcome.unwrap_or_default(),
            cost: Cost {
                tokens_in,
                tokens_out,
                model,
                seconds: Some((spend.minutes.0 * 60.0).round()),
                usd: spend.usd.map(|u| (u.0 * 100.0).round() / 100.0),
                bytes: None,
            },
            trace: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::budget::Usd;

    fn budget() -> Budget {
        Budget {
            usd: Usd(5.0),
            minutes: Minutes(60.0),
        }
    }

    #[test]
    fn a_task_belongs_to_the_session_it_was_declared_in() {
        // Regression: the hook applied the newest open task to every session.
        let mut t = Task::new("x", None, budget(), 0);
        assert!(
            !t.metered_in(r"C:\a\s1.jsonl"),
            "unmetered: no session claims it"
        );
        t.meter = Some(MeterStart {
            transcript: r"C:\Users\a\s1.jsonl".into(),
            offset: 0,
            rates: std::collections::BTreeMap::new(),
        });
        assert!(t.metered_in("c:/users/a/s1.jsonl"));
        assert!(!t.metered_in(r"C:\Users\a\s2.jsonl"));
        assert!(!t.metered_in(""));
    }

    #[test]
    fn slugs_are_short_and_stable() {
        assert_eq!(
            slug("Which OCR reads code in video frames?"),
            "which-ocr-reads-code-in-video-frames"
        );
        assert!(slug(&"word ".repeat(40)).len() < 45);
        assert_eq!(slug("?!"), "task");
    }

    #[test]
    fn a_finished_task_becomes_an_episode_with_its_cost() {
        let t0 = epoch_seconds("2026-11-13T09:00:00Z").unwrap();
        let mut t = Task::new("compare OCR engines", Some(Effort::Compare), budget(), t0);
        t.finish(
            Outcome::Partial,
            Some("no benchmark on our frames".into()),
            t0 + 40 * 60,
        );
        let s = SessionSpend {
            usd: Some(Usd(4.237)),
            ..Default::default()
        };
        let spend = t.spend(Some(&s), t0 + 99 * 60);
        assert!(
            (spend.minutes.0 - 40.0).abs() < 1e-9,
            "ended tasks stop the clock"
        );
        let trail = [Event::Organ {
            time: t.started.clone(),
            organ: "organon-research".into(),
            what: "fetch".into(),
        }];
        let e = t.episode(&spend, Some(&s), &trail);
        assert_eq!(e.kind, EpisodeType::Task);
        assert_eq!(e.cost.usd, Some(4.24));
        assert_eq!(e.cost.seconds, Some(2400.0));
        assert_eq!(e.outputs, vec![json!("organon-research fetch")]);
        assert_eq!(
            e.id,
            t.episode(&spend, None, &[]).id,
            "the id names the task, not its cost"
        );
    }
}

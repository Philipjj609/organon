//! Self-audit of what is about to enter memory: a proposal and the organ output it cites.
//!
//! Models struggle to correct themselves without external feedback (arXiv 2310.01798) and
//! favour their own outputs when judging (arXiv 2404.13076). So the audit asks questions a
//! program can answer from the protocol alone: does a confident inference rest on anything,
//! was its evidence produced by someone other than the author, do the organ's messages
//! conform, and does every observation say who produced it.

use std::collections::HashMap;
use std::fmt;

use serde_json::{Map, Value};

use organon_protocol::{Basis, EvidencePolicy, Message, Observation, Proposal, ProposedClaim};

/// An inference at or above this confidence should rest on evidence.
pub const HIGH_CONFIDENCE: f32 = 0.8;

#[derive(Debug, Clone, PartialEq)]
pub enum Finding {
    /// An inferred claim with high confidence and nothing cited.
    ConfidentWithoutEvidence { claim: String, confidence: f32 },
    /// Evidence produced by the same model that wrote the proposal: no second opinion.
    SelfVerified { claim: String, model: String },
    /// A cited observation that is in none of the messages given.
    UnknownEvidence { claim: String, id: String },
    /// An observation that does not say which organ and version produced it.
    NoProducer { observation: String },
    /// A message line that breaks the protocol.
    NonConformant { line: usize, reason: String },
}

impl fmt::Display for Finding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ConfidentWithoutEvidence { claim, confidence } => write!(
                f,
                "confident without evidence ({confidence:.2}): {claim} (cite a source or observation, or lower the confidence)"
            ),
            Self::SelfVerified { claim, model } => write!(
                f,
                "self-verified: {claim} (its evidence was produced by {model}, the proposal's author; have a tool or another model check it)"
            ),
            Self::UnknownEvidence { claim, id } => {
                write!(f, "unknown evidence {id}: {claim} (ingest the organ's messages first)")
            }
            Self::NoProducer { observation } => {
                write!(f, "observation {observation} does not say what produced it")
            }
            Self::NonConformant { line, reason } => write!(f, "messages line {line}: {reason}"),
        }
    }
}

/// What the audit saw and found.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Audit {
    pub claims: usize,
    pub inferred: usize,
    pub with_evidence: usize,
    /// Stated or observed claims citing nothing (normal for a session record, not for facts
    /// about the world).
    pub stated_unsourced: usize,
    pub messages: usize,
    pub findings: Vec<Finding>,
}

/// A proposed claim, normalized from either form.
struct Proposed {
    label: String,
    basis: Basis,
    confidence: Option<f32>,
    evidence: Vec<String>,
}

fn label(about: &str, relation: &str, value: &Value) -> String {
    let v = match value {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    };
    let mut s = format!("{about} {relation} {v}");
    if s.chars().count() > 90 {
        s = s.chars().take(89).collect::<String>() + "…";
    }
    s
}

#[allow(clippy::cast_possible_truncation)]
fn normalize(p: &Proposal, c: &ProposedClaim) -> Option<Proposed> {
    match c {
        ProposedClaim::Short(items) => {
            let s = |i: usize| items.get(i).and_then(Value::as_str).unwrap_or_default();
            Some(Proposed {
                label: label(s(0), s(1), items.get(2)?),
                basis: p.basis,
                confidence: items
                    .get(3)
                    .and_then(Value::as_f64)
                    .map(|x| x as f32)
                    .or(p.confidence),
                evidence: Vec::new(),
            })
        }
        ProposedClaim::Full(o) => {
            let s = |k: &str| o.get(k).and_then(Value::as_str).unwrap_or_default();
            let basis = o
                .get("basis")
                .and_then(|b| serde_json::from_value(b.clone()).ok())
                .unwrap_or(p.basis);
            Some(Proposed {
                label: label(s("about"), s("relation"), o.get("value")?),
                basis,
                confidence: o
                    .get("confidence")
                    .and_then(Value::as_f64)
                    .map(|x| x as f32)
                    .or(p.confidence),
                evidence: evidence(o),
            })
        }
    }
}

fn evidence(o: &Map<String, Value>) -> Vec<String> {
    o.get("evidence")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect()
}

/// Audit a proposal (if any) against the organ messages it may cite (already parsed and
/// checked with `organon_protocol::check_stream`). With no messages, cited observations are not
/// checked for existence: memory checks them at digest.
#[must_use]
pub fn audit(
    proposal: Option<&Proposal>,
    messages: &[Message],
    errors: &[(usize, String)],
) -> Audit {
    let mut a = Audit {
        messages: messages.len(),
        ..Audit::default()
    };
    for (line, reason) in errors {
        a.findings.push(Finding::NonConformant {
            line: *line,
            reason: reason.clone(),
        });
    }
    let observations: HashMap<&str, &Observation> = messages
        .iter()
        .filter_map(|m| match m {
            Message::Observation(o) => Some((o.id.as_str(), o)),
            _ => None,
        })
        .collect();
    for o in observations.values() {
        if o.produced_by.organ.trim().is_empty() || o.produced_by.version.trim().is_empty() {
            a.findings.push(Finding::NoProducer {
                observation: o.id.to_string(),
            });
        }
    }
    let Some(p) = proposal else { return a };
    let auto = p.evidence == Some(EvidencePolicy::Auto);
    for c in p.claims.iter().filter_map(|c| normalize(p, c)) {
        a.claims += 1;
        let cited = !c.evidence.is_empty();
        if cited {
            a.with_evidence += 1;
        }
        match c.basis {
            Basis::Inferred => {
                a.inferred += 1;
                if let Some(conf) = c.confidence.filter(|&x| x >= HIGH_CONFIDENCE && !cited) {
                    a.findings.push(Finding::ConfidentWithoutEvidence {
                        claim: c.label.clone(),
                        confidence: conf,
                    });
                }
            }
            _ if !cited && !auto => a.stated_unsourced += 1,
            _ => {}
        }
        for id in c.evidence.iter().filter(|id| id.starts_with("o_")) {
            match observations.get(id.as_str()) {
                Some(o) if o.produced_by.model.as_deref() == Some(p.author.as_str()) => {
                    a.findings.push(Finding::SelfVerified {
                        claim: c.label.clone(),
                        model: p.author.clone(),
                    });
                }
                None if !messages.is_empty() => a.findings.push(Finding::UnknownEvidence {
                    claim: c.label.clone(),
                    id: id.clone(),
                }),
                _ => {}
            }
        }
    }
    a
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    // The protocol's own conformance fixture (a research passage).
    const MESSAGES: &str = r#"{"type":"observation","id":"o_d5dd8e5192342a98","source":"s_0123456789abcdef","kind":"passage","at":{"start":120,"end":176},"value":{"text":"Only 39-77% factual accuracy against cited sources"},"produced_by":{"organ":"organon-research","version":"0.1.0"}}"#;

    fn proposal(claims: &str) -> Proposal {
        serde_json::from_str(&format!(
            r#"{{"author":"claude-opus-5-5","message":"m","claims":{claims}}}"#
        ))
        .unwrap()
    }

    fn messages(text: &str) -> (Vec<Message>, Vec<(usize, String)>) {
        let r = organon_protocol::check_stream(Cursor::new(text)).unwrap();
        let errs = r
            .errors
            .iter()
            .map(|e| (e.line, e.reason.clone()))
            .collect();
        (r.messages, errs)
    }

    #[test]
    fn confident_inference_needs_evidence() {
        let p = proposal(
            r#"[["concept:x","mechanism","does y",0.9,"because"],["concept:x","limit","z",0.6]]"#,
        );
        let a = audit(Some(&p), &[], &[]);
        assert_eq!((a.claims, a.inferred), (2, 2));
        assert_eq!(a.findings.len(), 1, "{:?}", a.findings);
        assert!(matches!(
            a.findings[0],
            Finding::ConfidentWithoutEvidence { .. }
        ));
    }

    #[test]
    fn evidence_must_exist_and_come_from_someone_else() {
        let (msgs, errs) = messages(MESSAGES);
        assert!(errs.is_empty(), "{errs:?}");
        let p = proposal(
            r#"[{"about":"concept:x","relation":"claims","value":"y","confidence":0.9,"evidence":["o_d5dd8e5192342a98"]},
               {"about":"concept:x","relation":"claims","value":"z","confidence":0.9,"evidence":["o_bbbbbbbbbbbbbbbb"]}]"#,
        );
        let a = audit(Some(&p), &msgs, &errs);
        let kinds: Vec<_> = a
            .findings
            .iter()
            .map(|f| match f {
                Finding::NonConformant { .. } => "nonconformant",
                Finding::UnknownEvidence { .. } => "unknown",
                Finding::SelfVerified { .. } => "self",
                Finding::ConfidentWithoutEvidence { .. } => "confident",
                Finding::NoProducer { .. } => "producer",
            })
            .collect();
        assert_eq!(kinds, ["unknown"], "{:?}", a.findings);
        assert_eq!(a.with_evidence, 2);

        let own = MESSAGES.replace(
            r#""version":"0.1.0"}"#,
            r#""version":"0.1.0","model":"claude-opus-5-5"}"#,
        );
        let (msgs, errs) = messages(&own);
        assert!(errs.is_empty(), "who produced it is not part of the id");
        let a = audit(Some(&p), &msgs, &[]);
        assert!(a
            .findings
            .iter()
            .any(|f| matches!(f, Finding::SelfVerified { .. })));
    }

    #[test]
    fn stated_claims_without_sources_are_counted_not_flagged() {
        let p: Proposal = serde_json::from_str(
            r#"{"author":"a","message":"m","basis":"stated","claims":[["project:x","status","done"]]}"#,
        )
        .unwrap();
        let a = audit(Some(&p), &[], &[]);
        assert_eq!((a.stated_unsourced, a.findings.len()), (1, 0));
    }
}

#[cfg(test)]
mod conformance {
    use super::*;

    #[test]
    fn broken_messages_and_anonymous_observations_are_findings() {
        let bad = r#"{"type":"observation","id":"o_aaaaaaaaaaaaaaaa","source":"s_0123456789abcdef","kind":"passage","at":{"start":1,"end":2},"value":{"text":"x"},"produced_by":{"organ":"","version":""}}"#;
        let r = organon_protocol::check_stream(std::io::Cursor::new(bad)).unwrap();
        let errs: Vec<_> = r
            .errors
            .iter()
            .map(|e| (e.line, e.reason.clone()))
            .collect();
        let a = audit(None, &r.messages, &errs);
        assert_eq!(a.findings.len(), 2, "{:?}", a.findings);
        assert!(matches!(
            a.findings[0],
            Finding::NonConformant { line: 1, .. }
        ));
        assert!(matches!(a.findings[1], Finding::NoProducer { .. }));
    }
}

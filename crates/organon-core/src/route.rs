//! Routing: which worker does which job. Two tiers of model plus deterministic tools.
//!
//! Combining routing and cascading beats either alone, and good quality estimates are what
//! make it work (arXiv 2410.10347); a second model in a cascade helps, a third rarely does
//! (118 of 135 comparisons, arXiv 2605.06350). So: tools first, a cheap model, a strong model,
//! nothing in between. Verification goes to a different model than the producer, because
//! evaluators favour their own outputs (arXiv 2404.13076).

use serde::{Deserialize, Serialize};

use crate::policy::Policy;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Tier {
    /// A deterministic program: no model.
    Tool,
    Cheap,
    Strong,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Route {
    pub tier: Tier,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    pub why: String,
}

impl Policy {
    /// The route for a job kind (`scan`, `plan`, …).
    #[must_use]
    pub fn route(&self, job: &str) -> Option<&Route> {
        self.routes.get(job)
    }

    /// Who should verify work produced by `producer`: the `verify` route, unless that is the
    /// producer's own model, then the model of the other tier.
    #[must_use]
    pub fn verifier(&self, producer: &str) -> Option<Route> {
        let v = self.routes.get("verify")?;
        if v.model.as_deref() != Some(producer) {
            return Some(v.clone());
        }
        let other = self
            .routes
            .values()
            .filter(|r| r.tier != Tier::Tool)
            .find(|r| r.model.as_deref().is_some_and(|m| m != producer))?;
        Some(Route {
            tier: other.tier,
            model: other.model.clone(),
            why: format!("{producer} produced it, so another model checks it"),
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::policy::{Policy, DEFAULT};

    use super::*;

    #[test]
    fn scanning_is_cheap_planning_is_strong_checks_are_tools() {
        let p = Policy::from_json(DEFAULT).unwrap();
        assert_eq!(p.route("scan").unwrap().tier, Tier::Cheap);
        assert_eq!(p.route("plan").unwrap().tier, Tier::Strong);
        assert_eq!(p.route("check").unwrap().tier, Tier::Tool);
        assert!(p.route("dance").is_none());
    }

    #[test]
    fn a_producer_never_verifies_itself() {
        let p = Policy::from_json(DEFAULT).unwrap();
        let cheap = p.route("verify").unwrap().model.clone().unwrap();
        assert_ne!(
            p.verifier("claude-opus-5-5").unwrap().model.unwrap(),
            "claude-opus-5-5"
        );
        assert_ne!(p.verifier(&cheap).unwrap().model.unwrap(), cheap);
    }
}

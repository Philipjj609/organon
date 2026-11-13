//! Budgets declared up front, and where a task stands against its budget.
//!
//! A task warns at [`WARN_AT`] of its tightest limit and stops at 100%. A stop is final for
//! that task: running the same work again spends the same budget again, so exhaustion is never
//! treated as a transient failure (Paperclip's open issues #14780 and #18120 show what happens
//! when it is).

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// Money in US dollars.
#[derive(Debug, Clone, Copy, Default, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Usd(pub f64);

/// Wall-clock minutes.
#[derive(Debug, Clone, Copy, Default, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Minutes(pub f64);

impl fmt::Display for Usd {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "${:.2}", self.0)
    }
}

impl fmt::Display for Minutes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0 >= 90.0 {
            write!(f, "{:.1} h", self.0 / 60.0)
        } else {
            write!(f, "{:.0} min", self.0)
        }
    }
}

/// How much a question deserves. Effort scales with the question, by explicit rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Effort {
    Lookup,
    Compare,
    Deep,
}

impl Effort {
    pub const ALL: [Self; 3] = [Self::Lookup, Self::Compare, Self::Deep];

    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Lookup => "lookup",
            Self::Compare => "compare",
            Self::Deep => "deep",
        }
    }
}

impl fmt::Display for Effort {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Effort {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        Self::ALL
            .into_iter()
            .find(|e| e.as_str() == s)
            .ok_or_else(|| format!("unknown effort '{s}' (lookup, compare, deep)"))
    }
}

/// What a task may spend.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Budget {
    pub usd: Usd,
    pub minutes: Minutes,
}

/// What a task has spent. `usd` is `None` when nothing measured it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Serialize, Deserialize)]
pub struct Spend {
    pub usd: Option<Usd>,
    pub minutes: Minutes,
}

/// Fraction of the tightest limit at which a task is warned.
pub const WARN_AT: f64 = 0.8;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    Ok,
    Warn,
    Exhausted,
}

/// Where a task stands: the fraction used of its tightest limit, and which limit that is.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Standing {
    pub level: Level,
    pub used: f64,
    pub limit: Limit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Limit {
    Money,
    Time,
}

impl fmt::Display for Limit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Money => "money",
            Self::Time => "time",
        })
    }
}

/// Compare spend with budget. A limit of zero or less counts as unlimited.
#[must_use]
pub fn standing(budget: &Budget, spend: &Spend) -> Standing {
    let frac = |used: f64, limit: f64| (limit > 0.0).then(|| used / limit);
    let money = spend.usd.and_then(|u| frac(u.0, budget.usd.0));
    let time = frac(spend.minutes.0, budget.minutes.0);
    let (used, limit) = match (money, time) {
        (Some(m), Some(t)) if m >= t => (m, Limit::Money),
        (Some(m), None) => (m, Limit::Money),
        (_, Some(t)) => (t, Limit::Time),
        (None, None) => (0.0, Limit::Money),
    };
    let level = if used >= 1.0 {
        Level::Exhausted
    } else if used >= WARN_AT {
        Level::Warn
    } else {
        Level::Ok
    };
    Standing { level, used, limit }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn b(usd: f64, min: f64) -> Budget {
        Budget {
            usd: Usd(usd),
            minutes: Minutes(min),
        }
    }

    #[test]
    fn the_tightest_limit_decides() {
        let s = standing(
            &b(10.0, 60.0),
            &Spend {
                usd: Some(Usd(2.0)),
                minutes: Minutes(50.0),
            },
        );
        assert_eq!((s.level, s.limit), (Level::Warn, Limit::Time));
        let s = standing(
            &b(10.0, 60.0),
            &Spend {
                usd: Some(Usd(10.5)),
                minutes: Minutes(5.0),
            },
        );
        assert_eq!((s.level, s.limit), (Level::Exhausted, Limit::Money));
    }

    #[test]
    fn unmeasured_money_falls_back_to_time_and_zero_means_unlimited() {
        let s = standing(
            &b(10.0, 60.0),
            &Spend {
                usd: None,
                minutes: Minutes(30.0),
            },
        );
        assert_eq!((s.level, s.limit), (Level::Ok, Limit::Time));
        let s = standing(
            &b(0.0, 0.0),
            &Spend {
                usd: Some(Usd(99.0)),
                minutes: Minutes(999.0),
            },
        );
        assert_eq!(s.level, Level::Ok);
    }

    #[test]
    fn efforts_parse_by_name() {
        assert_eq!("deep".parse::<Effort>(), Ok(Effort::Deep));
        assert!("huge".parse::<Effort>().is_err());
    }
}

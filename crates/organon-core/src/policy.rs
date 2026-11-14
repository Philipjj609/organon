//! Policy: what an agent may do without asking, what it must ask about, and what it must not
//! do, plus the effort budgets and the model routes. One JSON file a person can read.
//!
//! This is a guard rail for an agent that means well, not a sandbox: it reads the command an
//! agent is about to run and can be fooled by indirection (`bash -c`, scripts). The agent's own
//! permission system stays the security boundary.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::budget::{Budget, Effort};
use crate::route::Route;

/// The policy shipped with organon.
pub const DEFAULT: &str = include_str!("../../../policy/default.json");

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Decision {
    Allow,
    Ask,
    Deny,
}

/// One rule. `command` matches shell commands, `path` matches files a tool would write.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Rule {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    pub decision: Decision,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Policy {
    pub efforts: BTreeMap<Effort, Budget>,
    pub routes: BTreeMap<String, Route>,
    pub rules: Vec<Rule>,
    /// Commands still allowed once a task's budget is exhausted, so it can be wrapped up.
    #[serde(default)]
    pub after_budget: Vec<String>,
}

/// What an agent is about to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action<'a> {
    Command(&'a str),
    Write { path: &'a str },
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    pub decision: Decision,
    pub reason: Option<String>,
}

impl Policy {
    /// # Errors
    /// When the JSON does not describe a policy.
    pub fn from_json(s: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(s)
    }

    /// The strictest decision any rule makes about any part of the action. No rule: allow.
    #[must_use]
    pub fn decide(&self, action: Action<'_>) -> Verdict {
        let mut best = Verdict {
            decision: Decision::Allow,
            reason: None,
        };
        let mut consider = |r: &Rule| {
            if r.decision > best.decision {
                best = Verdict {
                    decision: r.decision,
                    reason: Some(r.reason.clone()),
                };
            }
        };
        match action {
            Action::Command(cmd) => {
                for seg in segments(cmd) {
                    for r in &self.rules {
                        if r.command.as_deref().is_some_and(|p| matches(p, &seg)) {
                            consider(r);
                        }
                    }
                }
            }
            Action::Write { path } => {
                let path = path.replace('\\', "/");
                for r in &self.rules {
                    if r.path.as_deref().is_some_and(|p| glob(p, &path)) {
                        consider(r);
                    }
                }
            }
            Action::Other => {}
        }
        best
    }

    /// Whether every part of `cmd` is something allowed after the budget ran out.
    #[must_use]
    pub fn allowed_after_budget(&self, cmd: &str) -> bool {
        let segs = segments(cmd);
        !segs.is_empty()
            && segs
                .iter()
                .all(|s| self.after_budget.iter().any(|p| matches(p, s)))
    }

    /// The budget for an effort.
    #[must_use]
    pub fn budget(&self, effort: Effort) -> Option<Budget> {
        self.efforts.get(&effort).copied()
    }
}

/// Split a shell command into simple commands (at `&&`, `||`, `;`, `|`, newlines, outside
/// quotes) and each into words. Leading `VAR=value` words are dropped and the program is
/// reduced to its file name (`/usr/bin/git`, `git.exe` → `git`).
#[must_use]
pub fn segments(cmd: &str) -> Vec<Vec<String>> {
    let mut out = Vec::new();
    let mut words: Vec<String> = Vec::new();
    let mut word = String::new();
    let mut quote: Option<char> = None;
    let mut chars = cmd.chars().peekable();
    let push_word = |word: &mut String, words: &mut Vec<String>| {
        if !word.is_empty() {
            words.push(std::mem::take(word));
        }
    };
    let end = |words: &mut Vec<String>, out: &mut Vec<Vec<String>>| {
        let mut ws: Vec<String> = std::mem::take(words)
            .into_iter()
            .skip_while(|w| is_assignment(w))
            .collect();
        if let Some(p) = ws.first_mut() {
            *p = program_name(p);
        }
        if !ws.is_empty() {
            out.push(ws);
        }
    };
    while let Some(c) = chars.next() {
        match (quote, c) {
            (Some(q), c) if c == q => quote = None,
            (Some(_), c) => word.push(c),
            (None, '\'' | '"') => quote = Some(c),
            (None, '\\') => {
                if let Some(n) = chars.next() {
                    if n != '\n' {
                        word.push(n);
                    }
                }
            }
            (None, '&' | '|') => {
                if chars.peek() == Some(&c) {
                    chars.next();
                } else if c == '&' {
                    // `2>&1`, `&>` and background `&` stay inside the command.
                    word.push(c);
                    continue;
                }
                push_word(&mut word, &mut words);
                end(&mut words, &mut out);
            }
            (None, ';' | '\n') => {
                push_word(&mut word, &mut words);
                end(&mut words, &mut out);
            }
            (None, c) if c.is_whitespace() => push_word(&mut word, &mut words),
            (None, '>') => {
                // Redirections are their own words: `a>>b` → `a`, `>>`, `b`.
                push_word(&mut word, &mut words);
                let mut op = String::from('>');
                if chars.peek() == Some(&'>') {
                    chars.next();
                    op.push('>');
                }
                words.push(op);
            }
            (None, c) => word.push(c),
        }
    }
    push_word(&mut word, &mut words);
    end(&mut words, &mut out);
    out
}

fn is_assignment(w: &str) -> bool {
    w.split_once('=').is_some_and(|(k, _)| {
        !k.is_empty() && k.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
    })
}

fn program_name(p: &str) -> String {
    let base = p.rsplit(['/', '\\']).next().unwrap_or(p);
    base.strip_suffix(".exe")
        .unwrap_or(base)
        .to_ascii_lowercase()
}

/// A command pattern: the first word matches the program, the others must appear in that
/// order (not necessarily adjacent). `*` inside a word matches anything.
fn matches(pattern: &str, seg: &[String]) -> bool {
    let mut p = pattern.split_whitespace();
    let (Some(first), Some(prog)) = (p.next(), seg.first()) else {
        return false;
    };
    if !glob(first, prog) {
        return false;
    }
    let mut rest = seg[1..].iter();
    p.all(|pw| rest.any(|w| glob(pw, w)))
}

/// Wildcard match where `*` matches any run of characters (including `/`).
#[must_use]
pub fn glob(pattern: &str, s: &str) -> bool {
    let (p, s): (Vec<char>, Vec<char>) = (pattern.chars().collect(), s.chars().collect());
    let (mut pi, mut si) = (0, 0);
    let mut star: Option<(usize, usize)> = None;
    while si < s.len() {
        if pi < p.len() && p[pi] == '*' {
            star = Some((pi, si));
            pi += 1;
        } else if pi < p.len() && p[pi] == s[si] {
            pi += 1;
            si += 1;
        } else if let Some((sp, ss)) = star {
            pi = sp + 1;
            si = ss + 1;
            star = Some((sp, ss + 1));
        } else {
            return false;
        }
    }
    p[pi..].iter().all(|&c| c == '*')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> Policy {
        Policy::from_json(DEFAULT).expect("the default policy parses")
    }

    fn decide(cmd: &str) -> Decision {
        policy().decide(Action::Command(cmd)).decision
    }

    #[test]
    fn commands_split_into_programs_and_words() {
        let s = segments(
            r#"cd /x && FOO=1 /usr/bin/Git.exe commit -m "a && b" | tee log; echo hi>>f 2>&1"#,
        );
        assert_eq!(s.len(), 4, "{s:?}");
        assert_eq!(s[1], ["git", "commit", "-m", "a && b"]);
        assert_eq!(s[3], ["echo", "hi", ">>", "f", "2", ">", "&1"]);
    }

    #[test]
    fn the_strictest_part_of_a_command_wins() {
        assert_eq!(decide("cargo test && git push"), Decision::Allow);
        assert_eq!(
            decide("cargo test && git push --force origin main"),
            Decision::Ask
        );
        assert_eq!(
            decide("git push origin main --force-with-lease"),
            Decision::Ask
        );
        assert_eq!(decide("echo '{}' >> memory/log.jsonl"), Decision::Deny);
        assert_eq!(decide("cat memory/log.jsonl | head"), Decision::Allow);
    }

    #[test]
    fn generated_and_append_only_files_are_never_written_by_hand() {
        let p = policy();
        for path in [
            r"C:\Users\x\mneme-memory\memory\log.jsonl",
            "/home/x/mem/projections/graph.json",
        ] {
            assert_eq!(
                p.decide(Action::Write { path }).decision,
                Decision::Deny,
                "{path}"
            );
        }
        assert_eq!(
            p.decide(Action::Write {
                path: "/x/src/log.rs"
            })
            .decision,
            Decision::Allow
        );
        // Regression: every project's `projections/` folder was protected, not just mneme's.
        assert_eq!(
            p.decide(Action::Write {
                path: "/app/src/projections/orders.ts"
            })
            .decision,
            Decision::Allow
        );
    }

    #[test]
    fn after_the_budget_only_wrap_up_is_allowed() {
        let p = policy();
        assert!(p.allowed_after_budget("organon task done t --outcome partial"));
        assert!(p.allowed_after_budget("git add -A && git commit -m x"));
        assert!(!p.allowed_after_budget("organon-research fetch run"));
        assert!(!p.allowed_after_budget(""));
    }

    #[test]
    fn globs_match_whole_strings() {
        assert!(glob("*log.jsonl", "memory/log.jsonl"));
        assert!(!glob("*log.jsonl", "memory/log.jsonl.bak"));
        assert!(glob("--force*", "--force-with-lease"));
        assert!(glob("a*b*c", "aXXbYYc"));
        assert!(!glob("a*b*c", "aXXbYY"));
    }
}

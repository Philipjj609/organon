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

/// The kinds of action a person approves before an agent may take them. A rule tagged with
/// one of these is part of the policy's floor: see [`Policy::with_floor`] and
/// [`Policy::approval_class`].
pub const APPROVAL_CLASSES: &[&str] = &["push-main", "deploy", "send", "delete", "secrets", "paid"];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Decision {
    Allow,
    Ask,
    Deny,
}

/// One rule. `command` matches shell commands, `path` matches files a tool would write,
/// `tool` matches the name of any other tool (an MCP tool such as `mcp__mail__send_message`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Rule {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool: Option<String>,
    pub decision: Decision,
    pub reason: String,
    /// The approval class this rule guards (one of [`APPROVAL_CLASSES`]), if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub class: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Policy {
    pub efforts: BTreeMap<Effort, Budget>,
    pub routes: BTreeMap<String, Route>,
    pub rules: Vec<Rule>,
    /// Commands still allowed once a task's budget is exhausted, so it can be wrapped up.
    #[serde(default)]
    pub after_budget: Vec<String>,
    /// Repositories where a person lifted one approval class (see [`Exception`]).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exceptions: Vec<Exception>,
}

/// A person's standing yes for one approval class in some repositories: an `ask` rule of
/// that class does not count for a command that works in a repository whose folder matches
/// `repo` (a [`glob`], compared with forward slashes and ignoring case). An exception never
/// lowers a `deny`, never applies when the folder is unknown, and does not change
/// [`Policy::approval_class`], so the fail-safe stays strict.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Exception {
    pub class: String,
    pub repo: String,
    pub reason: String,
}

/// What an agent is about to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action<'a> {
    Command(&'a str),
    Write {
        path: &'a str,
    },
    /// Any other tool, by name.
    Tool(&'a str),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    pub decision: Decision,
    pub reason: Option<String>,
}

/// Finds the branch checked out in a folder: `None` for the folder the agent runs in, or the
/// folder a command moved to (`cd x && git push`, `git -C x push`). Pure code passes
/// [`no_branch`]; the CLI reads `.git/HEAD`.
pub type BranchOf<'a> = &'a dyn Fn(Option<&str>) -> Option<String>;

/// A [`BranchOf`] that knows no branch.
#[must_use]
pub fn no_branch(_: Option<&str>) -> Option<String> {
    None
}

/// Finds the root folder of the repository a command works in, with the same hint as
/// [`BranchOf`]. Used only to apply [`Exception`]s.
pub type RepoOf<'a> = &'a dyn Fn(Option<&str>) -> Option<String>;

/// A [`RepoOf`] that knows no repository: no exception applies.
#[must_use]
pub fn no_repo(_: Option<&str>) -> Option<String> {
    None
}

impl Policy {
    /// # Errors
    /// When the JSON does not describe a policy.
    pub fn from_json(s: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(s)
    }

    /// The policy shipped with organon.
    ///
    /// # Panics
    /// Never: the default policy is part of the binary and parsed by the tests.
    #[must_use]
    pub fn builtin() -> Self {
        Self::from_json(DEFAULT).expect("the built-in policy parses")
    }

    /// This policy plus every approval-class rule of `floor` it does not already have.
    /// The rules are combined, strictest wins, so a policy file can add to the floor but can
    /// neither drop nor weaken it: an old or edited `policy.json` still asks before a push to
    /// `main`.
    #[must_use]
    pub fn with_floor(mut self, floor: &Policy) -> Self {
        for r in floor.rules.iter().filter(|r| r.class.is_some()) {
            if !self.rules.contains(r) {
                self.rules.push(r.clone());
            }
        }
        self
    }

    /// The strictest decision any rule makes about any part of the action. No rule: allow.
    #[must_use]
    pub fn decide(&self, action: Action<'_>) -> Verdict {
        self.decide_in(action, &no_branch)
    }

    /// [`Policy::decide`], knowing which branch a bare `git push` would push.
    #[must_use]
    pub fn decide_in(&self, action: Action<'_>, branch_of: BranchOf<'_>) -> Verdict {
        self.decide_at(action, branch_of, &no_repo)
    }

    /// [`Policy::decide_in`], also knowing which repository each part of a command works in,
    /// so the policy's [`Exception`]s can apply.
    #[must_use]
    pub fn decide_at(
        &self,
        action: Action<'_>,
        branch_of: BranchOf<'_>,
        repo_of: RepoOf<'_>,
    ) -> Verdict {
        let mut best = Verdict {
            decision: Decision::Allow,
            reason: None,
        };
        for r in self.matching(action, branch_of, repo_of) {
            if r.decision > best.decision {
                best = Verdict {
                    decision: r.decision,
                    reason: Some(r.reason.clone()),
                };
            }
        }
        best
    }

    /// The approval class of an action and the rule that puts it there, if any rule with a
    /// class matches. Used when the hook cannot decide normally: those actions are denied
    /// rather than let through unchecked.
    #[must_use]
    pub fn approval_class(&self, action: Action<'_>, branch_of: BranchOf<'_>) -> Option<&Rule> {
        self.matching(action, branch_of, &no_repo)
            .into_iter()
            .find(|r| r.class.is_some())
    }

    fn matching(
        &self,
        action: Action<'_>,
        branch_of: BranchOf<'_>,
        repo_of: RepoOf<'_>,
    ) -> Vec<&Rule> {
        let mut out = Vec::new();
        match action {
            Action::Command(cmd) => {
                let mut segs = segments(cmd);
                let certain = folders_are_certain(cmd, &segs);
                let dirs = segment_dirs(&segs);
                resolve_pushes(&mut segs, branch_of);
                for (seg, dir) in segs.iter().zip(&dirs) {
                    // Some(None): looked up, no repository; looked up at most once per part.
                    let mut repo: Option<Option<String>> = None;
                    for r in &self.rules {
                        if !r.command.as_deref().is_some_and(|p| matches(p, seg))
                            || out.contains(&r)
                        {
                            continue;
                        }
                        if certain && r.decision == Decision::Ask && !self.exceptions.is_empty() {
                            if let Some(class) = r.class.as_deref() {
                                let here = repo.get_or_insert_with(|| repo_of(dir.as_deref()));
                                if here.as_deref().is_some_and(|f| self.excepted(class, f)) {
                                    continue;
                                }
                            }
                        }
                        out.push(r);
                    }
                }
            }
            Action::Write { path } => {
                let path = path.replace('\\', "/");
                out.extend(
                    self.rules
                        .iter()
                        .filter(|r| r.path.as_deref().is_some_and(|p| glob(p, &path))),
                );
            }
            Action::Tool(name) => out.extend(
                self.rules
                    .iter()
                    .filter(|r| r.tool.as_deref().is_some_and(|p| glob(p, name))),
            ),
        }
        out
    }

    /// Whether a person lifted `class` for the repository in `folder`.
    fn excepted(&self, class: &str, folder: &str) -> bool {
        let folder = folder.replace('\\', "/").to_lowercase();
        self.exceptions
            .iter()
            .any(|e| e.class == class && glob(&e.repo.replace('\\', "/").to_lowercase(), &folder))
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
            // `(` and `)` also end a command, so a subshell's commands are still read.
            (None, ';' | '\n' | '(' | ')') => {
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
/// order (not necessarily adjacent). `*` inside a word matches anything. A final `$` means
/// "and no more arguments, only flags" (`vercel $` is a bare deploy, `vercel env ls` is not).
/// A command run through a package runner (`npx vercel`, `pnpm dlx vercel`) is matched as
/// the command it runs.
fn matches(pattern: &str, seg: &[String]) -> bool {
    matches_words(pattern, seg) || unwrap_runner(seg).is_some_and(|s| matches_words(pattern, &s))
}

fn matches_words(pattern: &str, seg: &[String]) -> bool {
    let mut p = pattern.split_whitespace();
    let (Some(first), Some(prog)) = (p.next(), seg.first()) else {
        return false;
    };
    if !glob(first, prog) {
        return false;
    }
    let mut i = 1;
    for pw in p {
        if pw == "$" {
            return seg[i..].iter().all(|w| w.starts_with('-'));
        }
        match seg[i..].iter().position(|w| glob(pw, w)) {
            Some(k) => i += k + 1,
            None => return false,
        }
    }
    true
}

/// `npx -y vercel@latest --prod` → `vercel --prod`.
fn unwrap_runner(seg: &[String]) -> Option<Vec<String>> {
    let skip = match seg.first()?.as_str() {
        "npx" | "pnpx" | "bunx" => 1,
        "pnpm" | "yarn" if seg.get(1).is_some_and(|w| w == "dlx") => 2,
        "npm" if seg.get(1).is_some_and(|w| w == "exec") => 2,
        _ => return None,
    };
    let mut rest: Vec<String> = seg[skip..]
        .iter()
        .skip_while(|w| w.starts_with('-'))
        .cloned()
        .collect();
    let prog = rest.first_mut()?;
    // A version or tag after the package name: `vercel@latest`, `@scope/pkg@1`.
    if let Some((at, _)) = prog.char_indices().skip(1).find(|(_, c)| *c == '@') {
        prog.truncate(at);
    }
    *prog = program_name(prog);
    Some(rest)
}

/// Words of `git push` that take a value.
const PUSH_VALUE_FLAGS: &[&str] = &["-o", "--push-option", "--repo", "--receive-pack", "--exec"];
/// Words of `git` before its subcommand that take a value.
const GIT_VALUE_FLAGS: &[&str] = &["-C", "-c", "--git-dir", "--work-tree", "--namespace"];

/// Make every `git push` name the branches it really pushes, so a rule about `main` sees a
/// push of the current branch when that branch is `main`:
/// - a push that names no refspec pushes the current branch (git's default,
///   `push.default=simple`): the branch is added as a word;
/// - `HEAD` and `@` are the current branch, also as the source of a refspec: `HEAD` →
///   `main`, `+@` → `+main`, `HEAD:x` → `main:x` (the destination `x` is unchanged).
///
/// The branch is found in the folder the command runs in: the agent's, a `cd` earlier in the
/// command, or `git -C <dir>`. If it cannot be read, the words stay as written.
/// The folder hint of each simple command: where the `cd`s before it lead, or its own
/// `git -C`, relative paths composed onto the folder before them. `None` means the agent's
/// own folder. Only meaningful when [`folders_are_certain`] holds.
#[must_use]
pub fn segment_dirs(segs: &[Vec<String>]) -> Vec<Option<String>> {
    let mut dir: Option<String> = None;
    let mut out = Vec::with_capacity(segs.len());
    for seg in segs {
        match seg.first().map(String::as_str) {
            Some("cd" | "set-location" | "sl") => {
                if let Some(t) = seg[1..].iter().find(|w| !w.starts_with('-')) {
                    dir = Some(join_dir(dir.as_deref(), t));
                }
                out.push(dir.clone());
            }
            Some("git") => {
                let mut here = dir.clone();
                let mut i = 1;
                while i < seg.len() && seg[i].starts_with('-') {
                    if seg[i] == "-C" {
                        if let Some(t) = seg.get(i + 1) {
                            here = Some(join_dir(here.as_deref(), t));
                        }
                    }
                    i += if GIT_VALUE_FLAGS.contains(&seg[i].as_str()) {
                        2
                    } else {
                        1
                    };
                }
                out.push(here);
            }
            _ => out.push(dir.clone()),
        }
    }
    out
}

/// `p` taken from the folder `base` (the agent's own folder when `None`).
fn join_dir(base: Option<&str>, p: &str) -> String {
    let absolute = p.starts_with('/')
        || p.starts_with('\\')
        || p.starts_with('~')
        || (p.len() >= 2 && p.as_bytes()[1] == b':');
    match base {
        Some(b) if !absolute => format!("{}/{p}", b.trim_end_matches(['/', '\\'])),
        _ => p.to_owned(),
    }
}

/// Whether the folder each part of `cmd` works in can be known by reading it, which
/// [`Exception`]s require. Not when parts may run elsewhere or not at all after a `cd`
/// (pipes, `;`, `||`, background `&`, subshells, substitutions, a directory stack, `cd -`
/// or a bare `cd`), nor when git is pointed at another repository (`--git-dir`,
/// `--work-tree`, `GIT_DIR`, `GIT_WORK_TREE`). Only `&&` chains of plain commands qualify.
#[must_use]
pub fn folders_are_certain(cmd: &str, segs: &[Vec<String>]) -> bool {
    let rest = cmd.replace("&&", " ");
    if rest.contains(['|', ';', '&', '(', ')', '`', '\n', '\r'])
        || rest.contains("$(")
        || cmd.contains("GIT_DIR")
        || cmd.contains("GIT_WORK_TREE")
    {
        return false;
    }
    segs.iter()
        .all(|seg| match seg.first().map(String::as_str) {
            Some("pushd" | "popd") => false,
            Some("cd" | "set-location" | "sl") => {
                seg[1..].iter().any(|w| !w.starts_with('-')) && !seg[1..].iter().any(|w| w == "-")
            }
            Some("git") => !seg
                .iter()
                .any(|w| w.starts_with("--git-dir") || w.starts_with("--work-tree")),
            _ => true,
        })
}

pub fn resolve_pushes(segs: &mut [Vec<String>], branch_of: BranchOf<'_>) {
    let mut dir: Option<String> = None;
    for seg in segs.iter_mut() {
        match seg[0].as_str() {
            "cd" | "set-location" | "pushd" | "sl" => {
                dir = seg[1..].iter().find(|w| !w.starts_with('-')).cloned();
                continue;
            }
            "git" => {}
            _ => continue,
        }
        let mut git_dir = dir.clone();
        let mut i = 1;
        while i < seg.len() {
            let w = seg[i].as_str();
            if w == "-C" {
                git_dir = seg.get(i + 1).cloned();
            }
            if GIT_VALUE_FLAGS.contains(&w) {
                i += 2;
            } else if w.starts_with('-') {
                i += 1;
            } else {
                break;
            }
        }
        if seg.get(i).map(String::as_str) != Some("push") {
            continue;
        }
        let start = i + 1;
        let args = push_arguments(&seg[start..]);
        let pushes_everything = args.flags.iter().any(|f| *f == "--all" || *f == "--mirror");
        let only_tags = args.flags.contains(&"--tags");
        let bare = args.positional.len() <= 1 && !pushes_everything && !only_tags;
        // The first positional word is the remote; the rest are refspecs.
        let refspecs: Vec<usize> = args.positional.iter().skip(1).map(|k| start + k).collect();
        let names_head = refspecs
            .iter()
            .any(|&k| current_branch_ref(&seg[k], "").is_some());
        if !bare && !names_head {
            continue;
        }
        let Some(branch) = branch_of(git_dir.as_deref()) else {
            continue;
        };
        for k in refspecs {
            if let Some(w) = current_branch_ref(&seg[k], &branch) {
                seg[k] = w;
            }
        }
        if bare {
            seg.push(branch);
        }
    }
}

/// A refspec whose source is the current branch (`HEAD`, `@`, `+HEAD`, `HEAD:x`, `@:x`),
/// rewritten with that branch's name; `None` for any other refspec.
fn current_branch_ref(refspec: &str, branch: &str) -> Option<String> {
    let (plus, rest) = match refspec.strip_prefix('+') {
        Some(r) => ("+", r),
        None => ("", refspec),
    };
    let (src, dst) = match rest.split_once(':') {
        Some((s, d)) => (s, Some(d)),
        None => (rest, None),
    };
    if src != "HEAD" && src != "@" {
        return None;
    }
    Some(match dst {
        Some(d) => format!("{plus}{branch}:{d}"),
        None => format!("{plus}{branch}"),
    })
}

struct PushArguments<'a> {
    /// Indices of the remote and refspecs, in order.
    positional: Vec<usize>,
    flags: Vec<&'a str>,
}

fn push_arguments(words: &[String]) -> PushArguments<'_> {
    let mut out = PushArguments {
        positional: Vec::new(),
        flags: Vec::new(),
    };
    let mut i = 0;
    while i < words.len() {
        let w = words[i].as_str();
        let next_is_redirect = words.get(i + 1).is_some_and(|n| n == ">" || n == ">>");
        if w == ">" || w == ">>" {
            i += 2; // the redirection and its target
            continue;
        }
        if next_is_redirect && w.chars().all(|c| c.is_ascii_digit()) {
            i += 1; // `2` of `2>&1`
            continue;
        }
        if PUSH_VALUE_FLAGS.contains(&w) {
            out.flags.push(w);
            i += 2;
            continue;
        }
        if w.starts_with('-') {
            out.flags.push(w);
        } else {
            out.positional.push(i);
        }
        i += 1;
    }
    out
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

    fn with_exception() -> Policy {
        let mut p = policy();
        p.exceptions.push(Exception {
            class: "push-main".into(),
            repo: "*/Projects/mneme-memory".into(),
            reason: "test".into(),
        });
        p
    }

    /// The repository of a folder hint is the hint itself; no hint is the agent's own repo.
    fn repo_at(hint: Option<&str>) -> Option<String> {
        Some(hint.unwrap_or("C:/Users/x/Projects/ergon").to_owned())
    }

    fn decide_at(p: &Policy, cmd: &str) -> Decision {
        p.decide_at(Action::Command(cmd), &no_branch, &repo_at)
            .decision
    }

    #[test]
    fn an_exception_lifts_its_class_only_in_its_repository() {
        let p = with_exception();
        let mm = "C:/Users/x/Projects/mneme-memory";
        assert_eq!(
            decide_at(&p, &format!("cd {mm} && git push origin main")),
            Decision::Allow
        );
        assert_eq!(
            decide_at(&p, &format!("git -C {mm} push origin main")),
            Decision::Allow
        );
        assert_eq!(
            decide_at(
                &p,
                r#"git -C "c:\users\x\projects\MNEME-MEMORY" push origin main"#
            ),
            Decision::Allow
        );
        // Another repository, or the agent's own folder: still asks.
        assert_eq!(decide_at(&p, "git push origin main"), Decision::Ask);
        assert_eq!(
            decide_at(&p, "cd C:/Users/x/Projects/ergon && git push origin main"),
            Decision::Ask
        );
        // A second push elsewhere in the same command still asks.
        assert_eq!(
            decide_at(
                &p,
                &format!("git -C {mm} push origin main && git push origin main")
            ),
            Decision::Ask
        );
        // Other classes in the excepted repository still ask.
        assert_eq!(
            decide_at(&p, &format!("cd {mm} && git push --force origin x")),
            Decision::Ask
        );
        // Without a known repository nothing is lifted.
        let cmd = format!("cd {mm} && git push origin main");
        assert_eq!(
            p.decide_in(Action::Command(&cmd), &no_branch).decision,
            Decision::Ask
        );
        // The fail-safe ignores exceptions.
        assert!(p
            .approval_class(Action::Command(&cmd), &no_branch)
            .is_some());
    }

    #[test]
    fn an_exception_never_lowers_a_deny() {
        let mut p = with_exception();
        p.exceptions.push(Exception {
            class: "delete".into(),
            repo: "*".into(),
            reason: "test".into(),
        });
        assert_eq!(decide_at(&p, "gh repo delete x/y"), Decision::Deny);
    }

    #[test]
    fn segment_dirs_follow_cd_and_git_dash_c() {
        let segs = segments("cd /a && git -C /b push && git status && cd c && git -C . push && ls");
        assert_eq!(
            segment_dirs(&segs),
            vec![
                Some("/a".into()),
                Some("/b".into()),
                Some("/a".into()),
                Some("/a/c".into()),
                Some("/a/c/.".into()),
                Some("/a/c".into()),
            ]
        );
    }

    /// Run from inside the excepted repository: no hint means mneme-memory.
    fn repo_from_mm(hint: Option<&str>) -> Option<String> {
        let mm = "C:/Users/x/Projects/mneme-memory";
        Some(match hint {
            None => mm.to_owned(),
            Some(h) if h.starts_with('/') || h.contains(':') => h.to_owned(),
            Some(h) => format!("{mm}/{h}"),
        })
    }

    fn decide_from_mm(p: &Policy, cmd: &str) -> Decision {
        p.decide_at(Action::Command(cmd), &no_branch, &repo_from_mm)
            .decision
    }

    #[test]
    fn an_exception_needs_a_certain_folder() {
        let p = with_exception();
        // From inside the excepted repository a plain push is allowed...
        assert_eq!(decide_from_mm(&p, "git push origin main"), Decision::Allow);
        // ...but not once the command moves elsewhere, or the folder cannot be known.
        for cmd in [
            "cd /other && git -C . push origin main",
            "cd /other && git push origin main",
            "cd /x/mneme-memory | cat; git push origin main",
            "pushd /x; popd; git push origin main",
            "cd /x || true && git push origin main",
            "git --git-dir=/other/.git push origin main",
            "git --work-tree /other push origin main",
            "GIT_DIR=/other/.git git push origin main",
            "(cd /other && git push origin main)",
            "cd - && git push origin main",
            "git push origin main & git push origin main",
            "echo $(cd /other) && git push origin main",
        ] {
            assert_eq!(decide_from_mm(&p, cmd), Decision::Ask, "{cmd}");
        }
        // A subshell's push is read at all (it was not before parentheses split commands).
        assert_eq!(decide("(cd /other && git push origin main)"), Decision::Ask);
        // A relative cd stays inside the composed folder.
        assert_eq!(
            decide_at(
                &p,
                "cd C:/Users/x/Projects && cd mneme-memory && git push origin main"
            ),
            Decision::Allow
        );
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
        // Regression: reading and moving around were denied, so wrap-up could not be done.
        assert!(p.allowed_after_budget(
            r#"cd /x/organon-video && grep -n "dhash" README.md && git push"#
        ));
        assert!(p.allowed_after_budget("gh run watch 123 --exit-status"));
        assert!(!p.allowed_after_budget("cd /x && cargo build --release"));
        assert!(!p.allowed_after_budget("organon-research fetch run"));
        assert!(!p.allowed_after_budget(""));
    }

    fn on_branch(b: &'static str) -> impl Fn(Option<&str>) -> Option<String> {
        move |_| Some(b.to_owned())
    }

    fn decide_on(branch: &'static str, cmd: &str) -> Decision {
        policy()
            .decide_in(Action::Command(cmd), &on_branch(branch))
            .decision
    }

    fn class_of(cmd: &str) -> Option<String> {
        policy()
            .approval_class(Action::Command(cmd), &no_branch)
            .and_then(|r| r.class.clone())
    }

    #[test]
    fn every_class_is_known_and_guarded() {
        let p = policy();
        for r in &p.rules {
            if let Some(c) = &r.class {
                assert!(APPROVAL_CLASSES.contains(&c.as_str()), "unknown class {c}");
                assert_ne!(r.decision, Decision::Allow, "a class rule must ask or deny");
            }
        }
        for c in APPROVAL_CLASSES {
            assert!(
                p.rules.iter().any(|r| r.class.as_deref() == Some(c)),
                "no rule guards {c}"
            );
        }
    }

    #[test]
    fn pushing_to_main_asks() {
        for cmd in [
            "git push origin main",
            "git push -u origin master",
            "git push origin HEAD:main",
            "git push origin feature:refs/heads/main",
            "git push origin +main",
            "git push --all origin",
            "git push --mirror",
            "cd /x && git push origin main 2>&1 | tail -3",
            "git -C /x push origin main",
        ] {
            assert_eq!(decide(cmd), Decision::Ask, "{cmd}");
            assert_eq!(class_of(cmd).as_deref(), Some("push-main"), "{cmd}");
        }
        for cmd in [
            "git push origin feature/main-menu",
            "git push -u origin fix/hook",
            "git push origin main-old",
            "git push --tags",
            "git log main",
            "git commit -m 'push to main'",
        ] {
            assert_eq!(decide(cmd), Decision::Allow, "{cmd}");
        }

        // HEAD and @ are the current branch, as a refspec or as its source side.
        // Regression: on main, `git push origin HEAD` and `git push origin @` were allowed.
        let current_branch_pushes = [
            "git push origin HEAD",
            "git push origin @",
            "git push -u origin HEAD",
            "git push origin +HEAD",
            "git push origin HEAD:refs/heads/main",
            "cd /x && git push -u origin HEAD 2>&1",
        ];
        for cmd in current_branch_pushes {
            assert_eq!(decide_on("main", cmd), Decision::Ask, "on main: {cmd}");
        }
        assert_eq!(decide_on("master", "git push origin @"), Decision::Ask);
        // The same commands on a feature branch push the feature branch: allowed.
        for cmd in &current_branch_pushes[..4] {
            assert_eq!(
                decide_on("feature", cmd),
                Decision::Allow,
                "on feature: {cmd}"
            );
        }
        // The destination still decides when it is named.
        assert_eq!(
            decide_on("main", "git push origin HEAD:feature"),
            Decision::Allow
        );
        assert_eq!(
            decide_on("main", "git push origin @:feature"),
            Decision::Allow
        );
        assert_eq!(
            decide_on("feature", "git push origin HEAD:main"),
            Decision::Ask
        );
        assert_eq!(
            decide_on("feature", "git push origin @:main"),
            Decision::Ask
        );
        // `HEAD` as the remote's name is not a refspec.
        assert_eq!(
            decide_on("main", "git push origin HEADS-UP"),
            Decision::Allow
        );
    }

    #[test]
    fn a_bare_push_is_judged_by_the_branch_it_pushes() {
        assert_eq!(decide_on("main", "git push"), Decision::Ask);
        assert_eq!(decide_on("main", "git push origin"), Decision::Ask);
        assert_eq!(decide_on("main", "git push -u origin 2>&1"), Decision::Ask);
        assert_eq!(decide_on("main", "cd /x && git push"), Decision::Ask);
        assert_eq!(decide_on("feature", "git push"), Decision::Allow);
        // A refspec names the target: the current branch does not matter.
        assert_eq!(
            decide_on("main", "git push origin feature"),
            Decision::Allow
        );
        assert_eq!(decide_on("main", "git push --tags"), Decision::Allow);
        // Without a way to read the branch, a bare push is not guessed.
        assert_eq!(decide("git push"), Decision::Allow);

        // The folder a command moved to is the one whose branch counts.
        let seen = std::cell::RefCell::new(Vec::new());
        let spy = |d: Option<&str>| {
            seen.borrow_mut().push(d.map(str::to_owned));
            None
        };
        let _ = policy().decide_in(Action::Command("cd /repo && git push"), &spy);
        let _ = policy().decide_in(Action::Command("git -C /other push"), &spy);
        let _ = policy().decide_in(Action::Command("git push"), &spy);
        assert_eq!(
            *seen.borrow(),
            [Some("/repo".to_owned()), Some("/other".to_owned()), None]
        );
    }

    #[test]
    fn deploys_ask() {
        for cmd in [
            "vercel",
            "vercel --prod",
            "vercel --yes",
            "vercel deploy --prebuilt",
            "npx vercel --prod",
            "npx -y vercel@latest deploy",
            "pnpm dlx vercel promote https://x.vercel.app",
            "vercel alias set a.vercel.app example.com",
            "fly deploy",
            "flyctl deploy --remote-only",
            "supabase functions deploy hello",
            "supabase db push",
            "netlify deploy --prod",
            "wrangler pages deploy dist",
        ] {
            assert_eq!(decide(cmd), Decision::Ask, "{cmd}");
            assert_eq!(class_of(cmd).as_deref(), Some("deploy"), "{cmd}");
        }
        for cmd in [
            "vercel env ls",
            "vercel logs x",
            "npx vercel whoami",
            "fly status",
            "supabase db diff",
            "supabase start",
        ] {
            assert_eq!(decide(cmd), Decision::Allow, "{cmd}");
        }
    }

    #[test]
    fn sends_ask() {
        for cmd in [
            "gh pr merge 12 --squash",
            "echo hi | mail -s x a@b.c",
            "Send-MailMessage -To a@b.c -Subject x",
            r#"curl -s "https://api.telegram.org/bot$T/sendMessage" -d chat_id=1"#,
            "Invoke-RestMethod -Uri https://api.telegram.org/botX/sendMessage",
            "npm publish --access public",
        ] {
            assert_eq!(decide(cmd), Decision::Ask, "{cmd}");
            assert_eq!(class_of(cmd).as_deref(), Some("send"), "{cmd}");
        }
        for cmd in [
            "gh pr view 12",
            "gh pr create --fill",
            "grep -rn api.telegram.org src",
            "curl -s https://example.com",
        ] {
            assert_eq!(decide(cmd), Decision::Allow, "{cmd}");
        }
        let p = policy();
        for tool in [
            "mcp__c8c0__send_message",
            "mcp__mail__reply",
            "mcp__vercel__create_deployment",
            "mcp__drive__trash_file",
        ] {
            assert_eq!(
                p.decide(Action::Tool(tool)).decision,
                Decision::Ask,
                "{tool}"
            );
        }
        assert_eq!(
            p.decide(Action::Tool("mcp__mail__search_threads")).decision,
            Decision::Allow
        );
        assert_eq!(p.decide(Action::Tool("Read")).decision, Decision::Allow);
    }

    #[test]
    fn deletes_and_secrets_ask() {
        assert_eq!(
            class_of("Remove-Item -Recurse -Force x").as_deref(),
            Some("delete")
        );
        assert_eq!(class_of("git branch -D old").as_deref(), Some("delete"));
        assert_eq!(decide("git branch -d merged"), Decision::Allow);
        assert_eq!(class_of("gh secret set TOKEN").as_deref(), Some("secrets"));
        assert_eq!(decide("gh secret list"), Decision::Allow);
        let p = policy();
        for path in [r"C:\app\.env", "/app/.env.local", ".env"] {
            assert_eq!(
                p.decide(Action::Write { path }).decision,
                Decision::Ask,
                "{path}"
            );
        }
        assert_eq!(
            p.decide(Action::Write {
                path: "/app/.env.example"
            })
            .decision,
            Decision::Allow
        );
    }

    #[test]
    fn a_policy_file_cannot_drop_or_weaken_the_floor() {
        // An old policy file without the new rules, and one that tries to allow pushes to main.
        let old = Policy::from_json(
            r#"{"efforts":{},"routes":{},"rules":[
                {"command":"git push main","decision":"allow","reason":"mine"}
            ]}"#,
        )
        .unwrap();
        assert_eq!(
            old.decide(Action::Command("git push origin main")).decision,
            Decision::Allow
        );
        let floored = old.with_floor(&Policy::builtin());
        assert_eq!(
            floored
                .decide(Action::Command("git push origin main"))
                .decision,
            Decision::Ask
        );
        assert_eq!(
            floored.decide(Action::Command("vercel --prod")).decision,
            Decision::Ask
        );
        // Rules without a class (memory invariants) are not forced on a custom policy.
        assert_eq!(
            floored
                .decide(Action::Command("echo x >> memory/log.jsonl"))
                .decision,
            Decision::Allow
        );
        // Applying the floor twice adds nothing.
        let n = floored.rules.len();
        assert_eq!(floored.with_floor(&Policy::builtin()).rules.len(), n);
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

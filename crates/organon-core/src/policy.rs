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
pub const APPROVAL_CLASSES: &[&str] = &[
    "push-main",
    "deploy",
    "send",
    "merge",
    "delete",
    "secrets",
    "paid",
];

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
    /// Names of variables a shell env file may set without making a `merge` exception ask:
    /// glob patterns of letters, digits and `_` with `*` (for example `VERCEL_PLUGIN_*`),
    /// matched ignoring case. Empty by default, so any assignment in such a file asks; blank
    /// lines and comments never do. Checked when the policy is read: see [`env_name_allowed`].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub merge_env_names: Vec<String>,
}

/// Name prefixes (lower case) of variables a shell env file may never set to lift a `merge`:
/// they steer `gh`, git, the dynamic loader, the shell itself or credentials. A second guard
/// behind the policy's allow-list; it is not claimed to be complete, the allow-list is the
/// control.
const BARRED_PREFIXES: &[&str] = &[
    "gh_", "git_", "xdg_", "ld_", "dyld_", "bash", "github_", "ssl_", "curl_", "node_",
];

/// Exact names (lower case) barred the same way: where programs are found, what the shell
/// evaluates or runs by itself, and the special variables that take arithmetic or have side
/// effects when assigned (`OPTIND=PATH=0` sets `PATH`).
const BARRED_NAMES: &[&str] = &[
    "path",
    "pathext",
    "home",
    "userprofile",
    "appdata",
    "localappdata",
    "env",
    "prompt_command",
    "shellopts",
    "ifs",
    "ps0",
    "ps1",
    "ps2",
    "ps3",
    "ps4",
    "cdpath",
    "execignore",
    "globignore",
    "fignore",
    "gconv_path",
    "optind",
    "optarg",
    "random",
    "srandom",
    "seconds",
    "lineno",
    "histcmd",
    "epochseconds",
    "epochrealtime",
    "funcname",
    "histfile",
    "histcontrol",
    "histsize",
    "histfilesize",
    "histtimeformat",
    "histignore",
    "mail",
    "mailpath",
    "mailcheck",
    "timeformat",
    "tmout",
    "inputrc",
    "shell",
    "comspec",
    "systemroot",
    "windir",
    "tmpdir",
    "http_proxy",
    "https_proxy",
    "all_proxy",
    "ftp_proxy",
    "no_proxy",
    "proxy",
];

/// Whether a variable name is one a shell env file may never set (see [`BARRED_PREFIXES`]),
/// ignoring case: also any name ending in `_proxy`.
#[must_use]
pub fn env_name_barred(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    BARRED_PREFIXES.iter().any(|p| n.starts_with(p))
        || BARRED_NAMES.contains(&n.as_str())
        || n.ends_with("_proxy")
}

/// Whether `merge_env_names` lets a file set the variable `name`: it matches one pattern
/// (ignoring case) and is not barred.
#[must_use]
pub fn env_name_allowed(patterns: &[String], name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    !env_name_barred(&n) && patterns.iter().any(|p| glob(&p.to_ascii_lowercase(), &n))
}

/// Why `pattern` is not a fit entry for `merge_env_names`, if it is not: it holds a character
/// other than a letter, a digit, `_` or `*`, it is empty or a bare `*`, or it could match a
/// barred name or a name starting with a barred prefix.
fn bad_env_pattern(pattern: &str) -> Option<&'static str> {
    if pattern.is_empty() || pattern.chars().all(|c| c == '*') {
        return Some("is empty or only `*`");
    }
    if !pattern
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '*')
    {
        return Some("has a character other than letters, digits, `_` and `*`");
    }
    let p = pattern.to_ascii_lowercase();
    let literal_start = p.split('*').next().unwrap_or_default();
    let starts_like_a_barred_prefix = BARRED_PREFIXES.iter().any(|b| {
        if p.contains('*') {
            literal_start.starts_with(b) || b.starts_with(literal_start)
        } else {
            p.starts_with(b)
        }
    });
    let matches_a_barred_name = if p.contains('*') {
        BARRED_NAMES.iter().any(|n| glob(&p, n))
    } else {
        env_name_barred(&p)
    };
    (starts_like_a_barred_prefix || matches_a_barred_name)
        .then_some("could match a variable a shell env file may never set")
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

/// The class of the rule that guards `gh pr merge`. An exception for it lifts a command only
/// when the whole command is one of two fixed forms: see [`lone_merge`].
const MERGE_CLASS: &str = "merge";

/// What the process a command will run in inherited, read by the caller: this crate reads no
/// environment and no file.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Inherited {
    /// `GH_REPO` or `GH_HOST` is set in the environment, or a file the shell sources before
    /// each command is not provably harmless (it may set them, or anything else that points
    /// `gh` at another repository or host than its folder's).
    pub gh_target: bool,
    /// A file the shell sources before each command cannot be read, or is not provably
    /// harmless: not only blank lines, comments and plain `NAME=value` assignments.
    pub init_unsafe: bool,
}

/// The command in lower case, with the characters a shell or PowerShell removes (quotes,
/// backslash, backtick, caret) taken out, so `GH_RE""PO` and `GH_RE\PO` read as `gh_repo`.
fn squashed(text: &str) -> String {
    text.chars()
        .filter(|c| !matches!(c, '\'' | '"' | '\\' | '`' | '^'))
        .flat_map(char::to_lowercase)
        .collect()
}

/// Whether the command text names `GH_REPO` or `GH_HOST` anywhere (assignment, `export`,
/// `$env:`, `set`...), however it is quoted or cased (Windows variable names ignore case).
fn names_a_gh_target(cmd: &str, raw: &[Vec<String>]) -> bool {
    let named = |t: &str| t.contains("gh_repo") || t.contains("gh_host");
    named(&squashed(cmd)) || raw.iter().any(|ws| named(&squashed(&ws.join(" "))))
}

/// Whether `cmd` is only a plain merge, and where it runs. `None`: it is not (anything else
/// asks). `Some(None)`: `gh pr merge ...` alone, in the agent's folder. `Some(Some(dir))`:
/// `cd <dir> && gh pr merge ...`, in `dir`.
///
/// This is an allow-list over the whole command, not a search for bad words:
/// - every character is a letter, a digit, a space or one of `- _ . / : = + @ ,`, and `&` only
///   as the `&&` between the two parts. So no `$`, quote, backslash, backtick, `%`, glob or
///   history character, redirection, subshell, `;`, `|`, `||`, lone `&` or newline: nothing a
///   shell expands, rewrites or chains;
/// - the first part, if there is a second, is `cd`, `Set-Location` or `sl` and one absolute
///   path with forward slashes (`C:/...` on Windows, `/...` elsewhere; letters, digits and
///   `. _ / - +` only, no `..` component);
/// - the merge is exactly [`plain_merge`].
fn lone_merge(cmd: &str) -> Option<Option<&str>> {
    if !cmd
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || " -_./:=+@,&".contains(c))
    {
        return None;
    }
    let parts: Vec<&str> = cmd.split("&&").collect();
    if parts.iter().any(|p| p.contains('&')) {
        return None;
    }
    fn words(p: &str) -> Vec<&str> {
        p.split(' ').filter(|w| !w.is_empty()).collect()
    }
    match parts.as_slice() {
        [merge] => plain_merge(&words(merge)).then_some(None),
        [cd, merge] => match words(cd).as_slice() {
            [prog, path]
                if ["cd", "set-location", "sl"]
                    .iter()
                    .any(|p| prog.eq_ignore_ascii_case(p))
                    && is_plain_absolute_path(path)
                    && plain_merge(&words(merge)) =>
            {
                Some(Some(*path))
            }
            _ => None,
        },
        _ => None,
    }
}

/// One absolute path with forward slashes, made of letters, digits and `. _ / - +` with no `..`
/// component. On Windows it must start with a drive letter (`C:/a/b`): a `/a/b` or Git Bash
/// `/c/a/b` means one folder to Git Bash and another to PowerShell (`C:/c/a/b`), so it is not
/// accepted there. Elsewhere only `/a/b` is.
fn is_plain_absolute_path(p: &str) -> bool {
    let rest = match p.as_bytes() {
        [d, b':', b'/', ..] if cfg!(windows) && d.is_ascii_alphabetic() => &p[2..],
        [b'/', ..] if !cfg!(windows) => p,
        _ => return false,
    };
    rest.chars()
        .all(|c| c.is_ascii_alphanumeric() || "._/-+".contains(c))
        && !rest.split('/').any(|c| c == "..")
}

/// Whether `w` is exactly `gh pr merge` with at most one positional (`^[0-9]+$` or
/// `^[A-Za-z0-9._/-]+$`, not starting with `-`) and only the flags `--squash`/`-s`,
/// `--merge`/`-m`, `--rebase`, `--delete-branch`/`-d` and `--match-head-commit <sha>` (or
/// `=<sha>`, 7 to 40 hex digits). Anything else, a bundle like `-sd` included, is not plain.
fn plain_merge(w: &[&str]) -> bool {
    if w.len() < 3 || w[0] != "gh" || w[1] != "pr" || w[2] != "merge" {
        return false;
    }
    let sha = |v: &str| (7..=40).contains(&v.len()) && v.chars().all(|c| c.is_ascii_hexdigit());
    let mut positional = false;
    let mut i = 3;
    while i < w.len() {
        let a = w[i];
        match a {
            "--squash" | "-s" | "--merge" | "-m" | "--rebase" | "--delete-branch" | "-d" => {}
            "--match-head-commit" => {
                i += 1;
                if !w.get(i).is_some_and(|v| sha(v)) {
                    return false;
                }
            }
            _ if a.strip_prefix("--match-head-commit=").is_some_and(sha) => {}
            _ if !positional
                && !a.starts_with('-')
                && a.chars()
                    .all(|c| c.is_ascii_alphanumeric() || "._/-".contains(c)) =>
            {
                positional = true;
            }
            _ => return false,
        }
        i += 1;
    }
    true
}

/// Whether a simple command runs `gh` (also through `npx`).
fn runs_gh(seg: &[String]) -> bool {
    seg.first().is_some_and(|p| p == "gh")
        || unwrap_runner(seg).is_some_and(|s| s.first().is_some_and(|p| p == "gh"))
}

impl Policy {
    /// # Errors
    /// When the JSON does not describe a policy, or `merge_env_names` has a pattern that is
    /// empty, a bare `*`, uses a character other than letters, digits, `_` and `*`, or could
    /// match a variable a shell env file may never set (`LD_*`, `*_*`, `G*`, `PATH`...).
    pub fn from_json(s: &str) -> Result<Self, serde_json::Error> {
        use serde::de::Error;
        let p: Self = serde_json::from_str(s)?;
        for n in &p.merge_env_names {
            if let Some(why) = bad_env_pattern(n) {
                return Err(serde_json::Error::custom(format!(
                    "merge_env_names: \"{n}\" {why}"
                )));
            }
        }
        Ok(p)
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
    /// `main`. The floor's wrap-up commands (`after_budget`) are added the same way, so an
    /// older policy file still lets a task whose budget is spent open its pull request and
    /// close itself.
    #[must_use]
    pub fn with_floor(mut self, floor: &Policy) -> Self {
        for r in floor.rules.iter().filter(|r| r.class.is_some()) {
            if !self.rules.contains(r) {
                self.rules.push(r.clone());
            }
        }
        for c in &floor.after_budget {
            if !self.after_budget.contains(c) {
                self.after_budget.push(c.clone());
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
    /// so the policy's [`Exception`]s can apply. It assumes the process inherited nothing that
    /// steers `gh`; a caller that reads the environment uses [`Policy::decide_with_env`].
    #[must_use]
    pub fn decide_at(
        &self,
        action: Action<'_>,
        branch_of: BranchOf<'_>,
        repo_of: RepoOf<'_>,
    ) -> Verdict {
        self.decide_with_env(action, branch_of, repo_of, Inherited::default())
    }

    /// [`Policy::decide_at`] told what the process the command will run in inherited
    /// (`env`). This crate reads no environment and no file, so the caller does.
    /// `GH_REPO` and `GH_HOST` point `gh` at another repository or host than its folder's:
    /// while either is set (`env.gh_target`), or the command names either, no [`Exception`]
    /// lifts a `gh` command. An exception for the `merge` class lifts only a command that is
    /// nothing but a plain merge ([`lone_merge`]), and only while `env` is clean.
    #[must_use]
    pub fn decide_with_env(
        &self,
        action: Action<'_>,
        branch_of: BranchOf<'_>,
        repo_of: RepoOf<'_>,
        env: Inherited,
    ) -> Verdict {
        let mut best = Verdict {
            decision: Decision::Allow,
            reason: None,
        };
        for r in self.matching(action, branch_of, repo_of, env) {
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
        self.matching(action, branch_of, &no_repo, Inherited::default())
            .into_iter()
            .find(|r| r.class.is_some())
    }

    fn matching(
        &self,
        action: Action<'_>,
        branch_of: BranchOf<'_>,
        repo_of: RepoOf<'_>,
        env: Inherited,
    ) -> Vec<&Rule> {
        let mut out = Vec::new();
        match action {
            Action::Command(cmd) => {
                let parsed = split(cmd);
                let mut segs = parsed.segs.clone();
                let certain = folders_are_certain(cmd, &segs);
                let dirs = segment_dirs(&segs);
                // Computed once per command; used only when an exception could apply.
                let gh_target = env.gh_target
                    || (!self.exceptions.is_empty() && names_a_gh_target(cmd, &parsed.raw));
                let lone = if self.exceptions.is_empty() {
                    None
                } else {
                    lone_merge(cmd)
                };
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
                        if r.decision == Decision::Ask && !self.exceptions.is_empty() {
                            if let Some(class) = r.class.as_deref() {
                                // Where to look for the repository, if an exception may apply.
                                let hint: Option<Option<&str>> = if class == MERGE_CLASS {
                                    lone.filter(|_| !env.gh_target && !env.init_unsafe)
                                } else if certain && !(gh_target && runs_gh(seg)) {
                                    Some(dir.as_deref())
                                } else {
                                    None
                                };
                                if let Some(hint) = hint {
                                    let here = repo.get_or_insert_with(|| repo_of(hint));
                                    if here.as_deref().is_some_and(|f| self.excepted(class, f)) {
                                        continue;
                                    }
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

    /// Whether every part of `cmd` is something allowed after the budget ran out. A wrap-up
    /// entry must be the command's leading words exactly (`gh pr create` is `gh`, `pr`,
    /// `create` in that order at the start), never words found later among its arguments.
    #[must_use]
    pub fn allowed_after_budget(&self, cmd: &str) -> bool {
        let segs = segments(cmd);
        !segs.is_empty()
            && segs
                .iter()
                .all(|s| self.after_budget.iter().any(|p| leads_with(p, s)))
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
    split(cmd).segs
}

/// A command split into simple commands, with what [`segments`] leaves out.
struct Split {
    /// The words of each simple command, as [`segments`] returns them.
    segs: Vec<Vec<String>>,
    /// Every unquoted word of every simple command, assignments and commands made only of
    /// assignments included, with the program as written.
    raw: Vec<Vec<String>>,
}

fn split(cmd: &str) -> Split {
    let mut out = Split {
        segs: Vec::new(),
        raw: Vec::new(),
    };
    let mut words: Vec<String> = Vec::new();
    let mut word = String::new();
    let mut quote: Option<char> = None;
    let mut chars = cmd.chars().peekable();
    let push_word = |word: &mut String, words: &mut Vec<String>| {
        if !word.is_empty() {
            words.push(std::mem::take(word));
        }
    };
    let end = |words: &mut Vec<String>, out: &mut Split| {
        let all = std::mem::take(words);
        if all.is_empty() {
            return;
        }
        let mut ws: Vec<String> = all
            .iter()
            .skip_while(|w| is_assignment(w))
            .cloned()
            .collect();
        out.raw.push(all);
        if let Some(p) = ws.first_mut() {
            *p = program_name(p);
        }
        if !ws.is_empty() {
            out.segs.push(ws);
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

/// Whether `seg` begins with exactly the words of `pattern` (the first may be a glob).
fn leads_with(pattern: &str, seg: &[String]) -> bool {
    let words: Vec<&str> = pattern.split_whitespace().collect();
    !words.is_empty()
        && seg.len() >= words.len()
        && glob(words[0], &seg[0])
        && words[1..].iter().zip(&seg[1..]).all(|(p, w)| p == w)
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
    // A path the shell would expand (variables, home, globs) cannot be read from the text.
    // `..` is resolved by the shell logically (through the link it came by) but by the
    // repository lookup physically, so a path with `..` cannot be judged either.
    let literal = |w: &String| {
        !w.contains(['$', '%', '~', '*', '?', '{', '['])
            && !w.split(['/', '\\']).any(|part| part == "..")
    };
    segs.iter()
        .all(|seg| match seg.first().map(String::as_str) {
            Some("pushd" | "popd") => false,
            Some("cd" | "set-location" | "sl") => {
                let targets: Vec<&String> =
                    seg[1..].iter().filter(|w| !w.starts_with('-')).collect();
                // A relative `cd` can be redirected by CDPATH (set in the command or inherited),
                // so only an absolute target is certain.
                let absolute = |w: &&String| {
                    w.starts_with('/')
                        || w.starts_with('\\')
                        || (w.len() >= 2 && w.as_bytes()[1] == b':')
                };
                !targets.is_empty()
                    && !seg[1..].iter().any(|w| w == "-")
                    && targets.iter().all(|w| literal(w) && absolute(w))
            }
            Some("git") => {
                let mut ok = !seg
                    .iter()
                    .any(|w| w.starts_with("--git-dir") || w.starts_with("--work-tree"));
                let mut i = 1;
                while i < seg.len() && seg[i].starts_with('-') {
                    let w = seg[i].as_str();
                    // `-C<path>` attached is not followed: unknown.
                    if w.starts_with("-C") && w.len() > 2 {
                        ok = false;
                    }
                    if w == "-C" && !seg.get(i + 1).is_some_and(literal) {
                        ok = false;
                    }
                    i += if GIT_VALUE_FLAGS.contains(&w) { 2 } else { 1 };
                }
                ok
            }
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
        // As git does: the first positional word is the remote and the rest are refspecs, even
        // with `--repo`. A positional repository overrides `--repo` (git builtin/push.c), so
        // `git push --repo origin HEAD:feature` pushes the current branch to a remote named
        // `HEAD:feature`. `--repo` (a value flag) only counts when no positional word is given.
        let bare = args.positional.len() <= 1 && !pushes_everything && !only_tags;
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
        p.decide_with_env(
            Action::Command(cmd),
            &no_branch,
            &repo_at,
            Inherited::default(),
        )
        .decision
    }

    /// The decision when the environment the command inherits sets `GH_REPO` or `GH_HOST`.
    fn decide_with_gh_env(p: &Policy, cmd: &str) -> Decision {
        p.decide_with_env(
            Action::Command(cmd),
            &no_branch,
            &repo_at,
            Inherited {
                gh_target: true,
                init_unsafe: false,
            },
        )
        .decision
    }

    /// The decision when a file the shell sources cannot be judged (it has `eval`, say).
    fn decide_with_init_unsafe(p: &Policy, cmd: &str) -> Decision {
        let env = Inherited {
            gh_target: false,
            init_unsafe: true,
        };
        p.decide_with_env(Action::Command(cmd), &no_branch, &repo_at, env)
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
        p.decide_with_env(
            Action::Command(cmd),
            &no_branch,
            &repo_from_mm,
            Inherited::default(),
        )
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
            "git -C/other/repo push origin main",
            "git -C \"$OTHER_REPO\" push origin main",
            "cd $OTHER && git push origin main",
            "cd ~/other && git push origin main",
            "git -C %OTHER% push origin main",
            // `..` after a link: the shell goes back the way it came, the lookup does not.
            "cd /unapproved/link/.. && git push origin main",
            "git -C ../mneme-memory push origin main",
            r"cd C:\x\link\..\y && git push origin main",
        ] {
            assert_eq!(decide_from_mm(&p, cmd), Decision::Ask, "{cmd}");
        }
        // A subshell's push is read at all (it was not before parentheses split commands).
        assert_eq!(decide("(cd /other && git push origin main)"), Decision::Ask);
        // A relative cd may be redirected by CDPATH: unknown, so it asks.
        assert_eq!(
            decide_at(
                &p,
                "cd C:/Users/x/Projects && cd mneme-memory && git push origin main"
            ),
            Decision::Ask
        );
        assert_eq!(
            decide_from_mm(&p, "CDPATH=/unapproved cd repo && git push origin main"),
            Decision::Ask
        );
        // `git -C` with a relative path is not affected by CDPATH and still composes.
        assert_eq!(
            decide_at(
                &p,
                "cd C:/Users/x/Projects && git -C mneme-memory push origin main"
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
    fn wrap_up_after_a_budget_stop_includes_the_pull_request_and_closing_the_task() {
        let p = policy();
        for cmd in [
            "gh pr create --base main --head x --title t --body b",
            "gh pr edit 3 --body b",
            "organon task done t --outcome partial --left \"x\"",
            "git push -u origin x",
            "cat report.md",
        ] {
            assert!(p.allowed_after_budget(cmd), "{cmd}");
        }
        for cmd in [
            "gh pr merge 3",
            "codex exec -",
            "pnpm install",
            "gh api repos/x/y",
            // `create` / `edit` as argument values are not the subcommand
            "gh pr review 3 --approve --body create",
            "gh pr comment 3 --body edit",
            "gh pr merge 3 --subject create",
            "gh issue create --title x",
        ] {
            assert!(!p.allowed_after_budget(cmd), "{cmd}");
        }
        // An older policy file without them gets them from the floor.
        let mut old = policy();
        old.after_budget.retain(|c| !c.starts_with("gh pr"));
        let old = old.with_floor(&policy());
        assert!(old.allowed_after_budget("gh pr create --title t"));
    }

    #[test]
    fn push_with_repo_follows_git_a_positional_repository_wins() {
        // git builtin/push.c: `--repo` names the remote only when no positional repository is
        // given; a positional one overrides it, and the refspecs follow it.
        // On main, these all push main:
        for cmd in [
            "git push --repo origin",
            "git push --repo=origin",
            // the remote is `HEAD:feature` (a positional repository), the push is bare: main
            "git push --repo origin HEAD:feature",
            "git push --repo=origin HEAD:feature",
            // the remote is `origin`, the push is bare: main
            "git push --repo upstream origin",
            "git push --repo upstream origin main",
            "git push --repo upstream origin HEAD",
            "git push --rep origin",
            "git push --no-repo origin",
        ] {
            assert_eq!(decide_on("main", cmd), Decision::Ask, "{cmd}");
        }
        // ...and these push to feature:
        for cmd in [
            "git push --repo upstream origin HEAD:feature",
            "git push --repo=upstream origin @:feature",
            "git push --no-repo origin HEAD:feature",
        ] {
            assert_eq!(decide_on("main", cmd), Decision::Allow, "{cmd}");
        }
        // On a feature branch a bare push is the feature branch.
        assert_eq!(
            decide_on("feature", "git push --repo origin"),
            Decision::Allow
        );
        assert_eq!(
            decide_on("feature", "git push --repo origin HEAD"),
            Decision::Allow
        );
        assert_eq!(
            decide_on("feature", "git push --repo upstream origin HEAD:main"),
            Decision::Ask
        );
        // Conservative: a remote spelled like a refspec to main still asks.
        assert_eq!(
            decide_on("feature", "git push --repo origin HEAD:main"),
            Decision::Ask
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
    fn merging_a_pull_request_asks_in_its_own_class() {
        for cmd in ["gh pr merge 12 --squash", "gh pr merge 3"] {
            assert_eq!(decide(cmd), Decision::Ask, "{cmd}");
            assert_eq!(class_of(cmd).as_deref(), Some("merge"), "{cmd}");
        }
        // Only the merge itself is in the class: reading and opening pull requests is free.
        for cmd in ["gh pr view 12", "gh pr create --fill", "gh pr checks 12"] {
            assert_eq!(decide(cmd), Decision::Allow, "{cmd}");
        }
    }

    fn with_merge_exception() -> Policy {
        let mut p = policy();
        p.exceptions.push(Exception {
            class: "merge".into(),
            repo: "*/Projects/ergon".into(),
            reason: "test".into(),
        });
        p
    }

    /// The test paths are written as Windows drive paths; elsewhere they are POSIX ones.
    fn here(cmd: &str) -> String {
        if cfg!(windows) {
            cmd.to_owned()
        } else {
            cmd.replace("C:/Users/x/Projects", "/home/x/Projects")
        }
    }

    #[test]
    fn a_merge_exception_lifts_only_a_whole_command_that_is_a_plain_merge() {
        let p = with_merge_exception();
        for cmd in [
            "gh pr merge 12 --squash",
            "gh pr merge 12 --squash --delete-branch --match-head-commit abc1234",
            "gh pr merge 12 --match-head-commit=abc1234 -d",
            "gh pr merge 12 --rebase",
            "gh pr merge feat/x --merge",
            "gh pr merge --merge",
            "gh pr merge -s",
            "gh pr merge -m 12",
            "gh pr merge --squash 12 -d",
            "gh pr merge",
            "gh pr merge 12 --squash ",
            "cd C:/Users/x/Projects/ergon && gh pr merge 3 --squash --match-head-commit 0123456789abcdef0123456789abcdef01234567",
            "cd C:/Users/x/Projects/ergon && gh pr merge 3",
            "Set-Location C:/Users/x/Projects/ergon && gh pr merge 3 --squash",
            "sl C:/Users/x/Projects/ergon && gh pr merge 3 --squash",
            "cd C:/Users/x/Projects/ergon&&gh pr merge 3",
        ] {
            assert_eq!(decide_at(&p, &here(cmd)), Decision::Allow, "{cmd}");
        }
        // Every other word asks: other repositories, skipping the checks, other changes.
        for cmd in [
            "gh pr merge 12 --admin",
            "gh pr merge 12 --squash --repo Philipjj609/Koda",
            "gh pr merge 12 --repo=Philipjj609/Koda",
            "gh pr merge 12 -R Philipjj609/Koda",
            "gh pr merge 12 -RPhilipjj609/Koda",
            "gh pr merge 12 -r",
            "gh pr merge https://github.com/Philipjj609/Koda/pull/12 --squash",
            "gh pr --repo Philipjj609/Koda merge 12",
            "gh pr -R Philipjj609/Koda merge 12",
            // shorthand flags bundled with -R
            "gh pr merge 7 -sR Philipjj609/Koda",
            "gh pr merge 7 -dR Philipjj609/Koda",
            "gh pr merge 7 -sdRPhilipjj609/Koda",
            "gh pr merge 7 -sd",
            // a global flag before `pr`
            "gh -R Philipjj609/Koda pr merge 7",
            "gh --repo Philipjj609/Koda pr merge 7",
            "gh --repo=Philipjj609/Koda pr merge 7",
            // flags outside the list
            "gh pr merge 7 --auto",
            "gh pr merge 7 --disable-auto",
            "gh pr merge 7 -t title",
            "gh pr merge 7 --subject title",
            "gh pr merge 7 -b body",
            "gh pr merge 7 -F body.md",
            "gh pr merge 7 --squash=true",
            // a second positional; a positional or commit that is not literal
            "gh pr merge 7 8",
            "gh pr merge 7,8",
            "gh pr merge 7=x",
            "gh pr merge 7 --match-head-commit",
            "gh pr merge 7 --match-head-commit -R",
            "gh pr merge 7 --match-head-commit=",
            "gh pr merge 7 --match-head-commit abc123",
            "gh pr merge 7 --match-head-commit=abc123",
            "gh pr merge 7 --match-head-commit 0123456789abcdef0123456789abcdef012345678",
            "gh pr merge 7 --match-head-commit ghijklm",
            "gh pr merge 7 --",
            // not literally `gh`
            "npx gh pr merge 7",
            "gh.exe pr merge 7",
            "/usr/bin/gh pr merge 7",
            "GH pr merge 7",
            // characters outside the literal-safe set
            "gh pr merge 7 --squash 2>&1",
            "gh pr merge 7 --squash > out",
            "gh pr merge 7 --squash; true",
            "gh pr merge 7 --squash || true",
            "gh pr merge 7 --squash | cat",
            "gh pr merge 7 --squash &",
            "gh pr merge 7 --squash\n",
            "gh pr merge 7\tgh --squash",
            "(gh pr merge 7 --squash)",
            "gh pr merge '7' --squash",
            "gh pr merge \"7\" --squash",
            "gh pr merge 7 --squash # x",
            "gh pr merge ~ --squash",
            "gh pr merge * --squash",
            "gh pr merge 7 --squash $X",
            "gh pr merge $PR --squash",
            "gh pr merge `echo 7` --squash",
            "gh pr merge %PR% --squash",
            // other forms of two parts
            "echo x && gh pr merge 7",
            "git status && gh pr merge 3 --squash",
            "gh pr merge 3 --squash && git pull",
            "gh pr merge 3 && gh pr merge 4",
            "cd C:/Users/x/Projects/ergon && cd C:/Users/x/Projects/ergon && gh pr merge 3",
            "cd C:/Users/x/Projects/ergon; gh pr merge 12 --squash",
            "cd C:/Users/x/Projects/ergon || gh pr merge 12 --squash",
            "cd C:/Users/x/Projects/ergon\ngh pr merge 12 --squash",
            "cd && gh pr merge 3",
            "cd C:/Users/x/Projects/ergon extra && gh pr merge 3",
            "cd ergon && gh pr merge 3",
            "cd ./ergon && gh pr merge 3",
            "cd C:\\Users\\x\\Projects\\ergon && gh pr merge 3",
            "cd C:/Users/x/Projects/ergon/../Koda && gh pr merge 3",
            "cd C:/Users/x/Projects/ergon/.. && gh pr merge 3",
            "cd ~/Projects/ergon && gh pr merge 3",
            "cd $PWD && gh pr merge 3",
            "cd \"C:/Users/x/Projects/ergon\" && gh pr merge 3",
            "cd /c/Users/x/Projects/ergon && gh pr merge 3 --repo=x",
            "echo x | mail a@b.c",
            "npm publish",
        ] {
            assert_eq!(decide_at(&p, &here(cmd)), Decision::Ask, "{cmd}");
        }
        // A plain merge in another folder asks.
        assert_eq!(
            decide_at(
                &p,
                &here("cd C:/Users/x/Projects/Koda && gh pr merge 12 --squash")
            ),
            Decision::Ask
        );
        assert_eq!(
            decide_at(&p, "cd /c/Users/x/Projects/Koda && gh pr merge 12 --squash"),
            Decision::Ask
        );
        // So does one whose repository is unknown.
        assert_eq!(
            p.decide_in(Action::Command("gh pr merge 12 --squash"), &no_branch)
                .decision,
            Decision::Ask
        );
        // The fail-safe ignores exceptions: the merge is still in its class.
        assert_eq!(
            p.approval_class(Action::Command("gh pr merge 12 --squash"), &no_branch)
                .and_then(|r| r.class.as_deref()),
            Some("merge")
        );
    }

    #[test]
    fn a_merge_cd_target_must_mean_one_folder_to_every_shell() {
        // Git Bash reads `/c/Projects/owned` as `C:/Projects/owned`, PowerShell as
        // `C:/c/Projects/owned`; organon cannot know which shell runs the command. On Windows
        // only a drive-letter path names one folder in both; elsewhere only a `/...` path does.
        let p = with_merge_exception();
        let tail = "&& gh pr merge 7 --squash";
        for prog in ["cd", "Set-Location", "sl"] {
            let drive = format!("{prog} C:/Users/x/Projects/ergon {tail}");
            let posix = format!("{prog} /home/x/Projects/ergon {tail}");
            let git_bash = format!("{prog} /c/Users/x/Projects/ergon {tail}");
            let drive_less = format!("{prog} /Users/x/Projects/ergon {tail}");
            let lower = format!("{prog} c:/Users/x/Projects/ergon {tail}");
            let (allowed, asks) = if cfg!(windows) {
                (vec![drive, lower], vec![posix, git_bash, drive_less])
            } else {
                (vec![posix, git_bash, drive_less], vec![drive, lower])
            };
            for cmd in allowed {
                assert_eq!(decide_at(&p, &cmd), Decision::Allow, "{cmd}");
            }
            for cmd in asks {
                assert_eq!(decide_at(&p, &cmd), Decision::Ask, "{cmd}");
            }
        }
        // The exact input from the review: the folder it names is not the folder it enters.
        if cfg!(windows) {
            let q = {
                let mut q = policy();
                q.exceptions.push(Exception {
                    class: "merge".into(),
                    repo: "C:/Projects/owned".into(),
                    reason: "test".into(),
                });
                q
            };
            for cmd in [
                "Set-Location /c/Projects/owned && gh pr merge 7 --squash",
                "cd /c/Projects/owned && gh pr merge 7 --squash",
                "sl /c && gh pr merge 7",
                "cd /Projects/owned && gh pr merge 7",
                "cd C:\\Projects\\owned && gh pr merge 7",
                "cd C: && gh pr merge 7",
                "cd C:Projects/owned && gh pr merge 7",
            ] {
                let at = |h: Option<&str>| Some(h.unwrap_or("C:/Projects/owned").to_owned());
                let d = q
                    .decide_with_env(Action::Command(cmd), &no_branch, &at, Inherited::default())
                    .decision;
                assert_eq!(d, Decision::Ask, "{cmd}");
            }
        }
    }

    #[test]
    fn a_merge_exception_is_not_fooled_by_steering_the_target_in_the_same_command() {
        let p = with_merge_exception();
        assert_eq!(decide_at(&p, "gh pr merge 3"), Decision::Allow);
        // Each of these makes `gh pr merge` act on another repository than the folder's, or
        // hides what it does; none is a plain merge as a whole, so each asks.
        for cmd in [
            // an expansion that carries a URL
            "PR=https://github.com/o/r/pull/7 && gh pr merge $PR --squash",
            // the remote or git config edited by a file write
            r#"printf '[remote "upstream"]' >> .git/config && gh pr merge 7"#,
            "cp x .git/config && gh pr merge 7",
            // a different `gh`
            "hash -p /tmp/g gh && gh pr merge 7",
            "New-Item function:gh -Value {x} && gh pr merge 7",
            "alias gh=/tmp/g && gh pr merge 7",
            // an untracked change of folder
            "builtin cd C:/Users/x/Projects/Koda && gh pr merge 7",
            "Push-Location C:/Users/x/Projects/Koda && gh pr merge 7",
            "chdir C:/Users/x/Projects/Koda && gh pr merge 7",
            "pushd C:/Users/x/Projects/Koda && gh pr merge 7",
            "cd C:/Users/x/Projects/Koda && cd C:/Users/x/Projects/ergon && gh pr merge 7",
            // GH_REPO / GH_HOST, any way of writing them
            "GH_REPO=Philipjj609/Koda gh pr merge 3",
            "gh_repo=x gh pr merge 3",
            "GH_HOST=github.example.com gh pr merge 3",
            "export GH_REPO=x && gh pr merge 3",
            "export GH_REPO=x; gh pr merge 3",
            "$env:GH_REPO='x'; gh pr merge 3",
            "set GH_REPO=x&& gh pr merge 3",
            r#"export GH_RE""PO=X && gh pr merge 7"#,
            r"export GH_RE\PO=X && gh pr merge 7",
            "$env:GH_RE`PO='x' && gh pr merge 7",
            "FOO=1 gh pr merge 7",
            // the remote, the default repository, git config
            "git remote set-url origin https://github.com/Philipjj609/Koda && gh pr merge 7",
            "git config remote.origin.url x && gh pr merge 7",
            "git -c url.x.insteadOf=y fetch && gh pr merge 7",
            "gh repo set-default Philipjj609/Koda && gh pr merge 7",
            "GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=url.https://github.com/Philipjj609/Koda.insteadOf GIT_CONFIG_VALUE_0=https://github.com/Philipjj609/ergon gh pr merge 7",
            // text run as shell
            "eval \"$X\" && gh pr merge 7",
            "source ./env.sh && gh pr merge 7",
            "git fetch origin && gh pr merge 3 --squash",
            "gh pr checks 3 && gh pr merge 3 --squash",
        ] {
            assert_eq!(decide_at(&p, &here(cmd)), Decision::Ask, "{cmd}");
        }
        // GH_REPO / GH_HOST in what the process inherited, or an init file that cannot be
        // judged.
        assert_eq!(
            decide_with_gh_env(&p, "gh pr merge 3 --squash"),
            Decision::Ask
        );
        assert_eq!(
            decide_with_init_unsafe(&p, "gh pr merge 3 --squash"),
            Decision::Ask
        );
        assert_eq!(
            decide_with_init_unsafe(&p, &here("cd C:/Users/x/Projects/ergon && gh pr merge 3")),
            Decision::Ask
        );
    }

    #[test]
    fn the_environment_only_affects_gh_commands_of_other_classes() {
        // The environment is given by the caller; core reads none.
        let push = "git -C C:/Users/x/Projects/mneme-memory push origin main";
        let q = with_exception();
        assert_eq!(decide_at(&q, push), Decision::Allow);
        assert_eq!(
            decide_with_gh_env(&q, push),
            Decision::Allow,
            "git is not gh"
        );
        // A `send` exception lifts a gh command of its class, until GH_REPO / GH_HOST.
        let mut s = policy();
        s.exceptions.push(Exception {
            class: "send".into(),
            repo: "*/Projects/ergon".into(),
            reason: "test".into(),
        });
        let vis = "gh repo edit --visibility public";
        assert_eq!(decide_at(&s, vis), Decision::Allow);
        assert_eq!(decide_with_gh_env(&s, vis), Decision::Ask);
        assert_eq!(
            decide_at(&s, "GH_REPO=x/y gh repo edit --visibility public"),
            Decision::Ask
        );
        assert_eq!(decide_with_gh_env(&s, "npm publish"), Decision::Allow);
    }

    #[test]
    fn an_old_policy_that_keeps_gh_pr_merge_in_send_still_asks() {
        // A policy.json written before the merge class: the rule is `send`, so a merge
        // exception has nothing to lift. It fails safe, with or without the floor.
        let old = r#"{"efforts":{},"routes":{},"rules":[
            {"command":"gh pr merge","decision":"ask","class":"send","reason":"old"}
        ],"exceptions":[{"class":"merge","repo":"*/Projects/ergon","reason":"mine"}]}"#;
        let p = Policy::from_json(old).unwrap();
        assert_eq!(decide_at(&p, "gh pr merge 12 --squash"), Decision::Ask);
        let floored = p.with_floor(&Policy::builtin());
        assert_eq!(
            decide_at(&floored, "gh pr merge 12 --squash"),
            Decision::Ask
        );
        assert_eq!(decide_at(&floored, "gh pr merge 12 --admin"), Decision::Ask);
    }

    #[test]
    fn a_send_exception_does_not_lift_a_merge() {
        let mut p = policy();
        p.exceptions.push(Exception {
            class: "send".into(),
            repo: "*/Projects/ergon".into(),
            reason: "test".into(),
        });
        assert_eq!(decide_at(&p, "gh pr merge 12 --squash"), Decision::Ask);
        // ...and it lifts the rest of its class there, as before.
        assert_eq!(decide_at(&p, "npm publish"), Decision::Allow);
    }

    #[test]
    fn sends_ask() {
        for cmd in [
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

    fn policy_with_env_names(names: &str) -> Result<Policy, serde_json::Error> {
        let mut v: serde_json::Value = serde_json::from_str(DEFAULT).unwrap();
        v["merge_env_names"] = serde_json::from_str(names).unwrap();
        Policy::from_json(&v.to_string())
    }

    #[test]
    fn merge_env_names_are_checked_when_the_policy_is_read() {
        // The shipped policy lists none.
        assert!(Policy::builtin().merge_env_names.is_empty());
        // A policy without the field is fine too.
        assert!(
            Policy::from_json(r#"{"efforts":{},"routes":{},"rules":[]}"#)
                .unwrap()
                .merge_env_names
                .is_empty()
        );
        let ok = policy_with_env_names(r#"["VERCEL_PLUGIN_*", "MY_TOOL_MODE", "vercel_x"]"#)
            .expect("plain names and prefixes are accepted");
        assert_eq!(ok.merge_env_names.len(), 3);
        for bad in [
            "*",
            "**",
            "",
            "*_*",
            "LD_*",
            "ld_preload",
            "L*",
            "*LD_*",
            "DYLD_*",
            "G*",
            "GH_*",
            "GIT_*",
            "GITHUB_*",
            "GITHUB_TOKEN",
            "XDG_*",
            "BASH*",
            "SSL_*",
            "PATH",
            "PATH*",
            "P*",
            "PATHEXT",
            "OPTIND",
            "O*",
            "EXECIGNORE",
            "E*",
            "*_PROXY",
            "HTTPS_PROXY",
            "*PROXY",
            "R*",
            "SECONDS",
            "VERCEL-PLUGIN",
            "VERCEL PLUGIN_*",
            "VERCEL_?",
            "VERCEL_[A-Z]*",
            "VERCEL_PLUGIN=*",
            "VERCEL_\u{e9}*",
        ] {
            let e = policy_with_env_names(&format!("[{}]", serde_json::to_string(bad).unwrap()))
                .expect_err(bad);
            assert!(e.to_string().contains("merge_env_names"), "{bad}: {e}");
        }
        // One bad entry spoils the list, wherever it stands.
        assert!(policy_with_env_names(r#"["VERCEL_PLUGIN_*", "LD_*"]"#).is_err());
    }

    #[test]
    fn a_name_is_allowed_only_when_listed_and_not_barred() {
        let list = ["VERCEL_PLUGIN_*".to_string(), "OPTIND".to_string()];
        assert!(env_name_allowed(&list, "VERCEL_PLUGIN_SETUP_MODE"));
        assert!(env_name_allowed(&list, "vercel_plugin_x"));
        assert!(!env_name_allowed(&list, "VERCEL_OTHER"));
        assert!(!env_name_allowed(&[], "VERCEL_PLUGIN_SETUP_MODE"));
        // Listed but barred (a list that skipped validation): still no.
        assert!(!env_name_allowed(&list, "OPTIND"));
        for n in [
            "PATH",
            "Path",
            "PATHEXT",
            "EXECIGNORE",
            "LD_PRELOAD",
            "DYLD_FOO",
            "GCONV_PATH",
            "HTTPS_PROXY",
            "NO_PROXY",
            "MY_PROXY",
            "SSL_CERT_FILE",
            "GITHUB_TOKEN",
            "GH_TOKEN",
            "GIT_DIR",
            "OPTIND",
            "RANDOM",
            "SECONDS",
            "LINENO",
            "HISTCMD",
            "BASH_ARGV0",
            "BASH_ENV",
            "NODE_OPTIONS",
            "CURL_CA_BUNDLE",
        ] {
            assert!(env_name_barred(n), "{n}");
        }
        for n in ["VERCEL_PLUGIN_SETUP_MODE", "FOO", "MY_TOOL"] {
            assert!(!env_name_barred(n), "{n}");
        }
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

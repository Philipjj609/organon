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
        // Over the cap only the first reading is made (see `matching`), and the answer is at
        // least an ask: what it cannot check, it does not allow.
        let mut best = if matches!(action, Action::Command(c) if c.len() > MAX_COMMAND_BYTES) {
            Verdict {
                decision: Decision::Ask,
                reason: Some("The command is too long for organon to check fully.".into()),
            }
        } else {
            Verdict {
                decision: Decision::Allow,
                reason: None,
            }
        };
        for (r, bash) in self.matching(action, branch_of, repo_of, env) {
            // Text that only cmd or PowerShell reads as a command (a bash quote that they do
            // not know) may be a commit message: a deny there is an ask.
            let decision = if r.decision == Decision::Deny && !bash {
                Decision::Ask
            } else {
                r.decision
            };
            if decision > best.decision {
                best = Verdict {
                    decision,
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
            .map(|(r, _)| r)
            .find(|r| r.class.is_some())
    }

    fn matching(
        &self,
        action: Action<'_>,
        branch_of: BranchOf<'_>,
        repo_of: RepoOf<'_>,
        env: Inherited,
    ) -> Vec<(&Rule, bool)> {
        // Each rule with whether a bash reading of the command matched it.
        let mut out: Vec<(&Rule, bool)> = Vec::new();
        match action {
            Action::Command(cmd) => {
                // Every reading of the command is judged and a rule that matches under any of
                // them counts. An exception lifts a rule only when every reading is certain of
                // the folders and they all find the same programs in the same folders.
                // Over the cap, only the first reading is made: it is cheap, and it still finds
                // what the policy found before the other readings existed. No exception
                // lifts anything there.
                let oversize = cmd.len() > MAX_COMMAND_BYTES;
                let (parsed, raw) = if oversize {
                    let first = vec![Parsed {
                        segs: split(cmd, OLD),
                        bash: true,
                        bang: true,
                    }];
                    (first, Vec::new())
                } else {
                    parse_with_raw(cmd)
                };
                // Computed once per command, and only when an exception could apply: `GH_REPO`
                // or `GH_HOST` set in the environment or named anywhere in the command, and
                // the one form of command a `merge` exception may lift. Over the cap neither
                // exists: nothing is lifted there.
                let exceptions = !self.exceptions.is_empty() && !oversize;
                let gh_target = env.gh_target || (exceptions && names_a_gh_target(cmd, &raw));
                let lone = if exceptions { lone_merge(cmd) } else { None };
                let reads: Vec<Reading> = parsed
                    .into_iter()
                    .map(|p| {
                        let mut segs = p.segs;
                        let certain = !p.bang && folders_are_certain(cmd, &segs);
                        let dirs = segment_dirs(&segs);
                        resolve_pushes(&mut segs, branch_of);
                        Reading {
                            segs,
                            certain,
                            dirs,
                            bash: p.bash,
                        }
                    })
                    .collect();
                let agree = reads.iter().all(|r| r.certain)
                    && reads.windows(2).all(|w| w[0].shape() == w[1].shape());
                for read in &reads {
                    for (seg, dir) in read.segs.iter().zip(&read.dirs) {
                        // Some(None): looked up, no repository; looked up at most once per part.
                        let mut repo: Option<Option<String>> = None;
                        for r in &self.rules {
                            if !r.command.as_deref().is_some_and(|p| matches(p, seg)) {
                                continue;
                            }
                            if let Some(seen) = out.iter_mut().find(|(o, _)| *o == r) {
                                seen.1 |= read.bash;
                                continue;
                            }
                            if agree && r.decision == Decision::Ask && !self.exceptions.is_empty() {
                                if let Some(class) = r.class.as_deref() {
                                    // Where to look for the repository, if an exception may
                                    // apply: a merge only as `lone_merge` reads it and with a
                                    // clean environment, any other class where the part runs
                                    // unless `GH_REPO` or `GH_HOST` steers a `gh` command.
                                    let hint: Option<Option<&str>> = if class == MERGE_CLASS {
                                        lone.filter(|_| !env.gh_target && !env.init_unsafe)
                                    } else if !(gh_target && runs_gh(seg)) {
                                        Some(dir.as_deref())
                                    } else {
                                        None
                                    };
                                    let Some(hint) = hint else {
                                        out.push((r, read.bash));
                                        continue;
                                    };
                                    let here = repo.get_or_insert_with(|| repo_of(hint));
                                    if here.as_deref().is_some_and(|f| self.excepted(class, f)) {
                                        continue;
                                    }
                                }
                            }
                            out.push((r, read.bash));
                        }
                    }
                }
            }
            Action::Write { path } => {
                let path = path.replace('\\', "/");
                out.extend(
                    self.rules
                        .iter()
                        .filter(|r| r.path.as_deref().is_some_and(|p| glob(p, &path)))
                        .map(|r| (r, true)),
                );
            }
            Action::Tool(name) => out.extend(
                self.rules
                    .iter()
                    .filter(|r| r.tool.as_deref().is_some_and(|p| glob(p, name)))
                    .map(|r| (r, true)),
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
        // Allowed only if every reading of the command agrees.
        if cmd.len() > MAX_COMMAND_BYTES {
            return false;
        }
        readings(cmd).iter().all(|segs| {
            !segs.is_empty()
                && segs
                    .iter()
                    .all(|s| self.after_budget.iter().any(|p| leads_with(p, s)))
        })
    }

    /// The budget for an effort.
    #[must_use]
    pub fn budget(&self, effort: Effort) -> Option<Budget> {
        self.efforts.get(&effort).copied()
    }
}

/// The longest command the policy reads. A longer one is not parsed: it asks. The hook has
/// ten seconds, and the readings and the rules are matched part by part.
pub const MAX_COMMAND_BYTES: usize = 64 * 1024;

/// One reading of a command: its parts, and where each works (see [`readings`]).
struct Reading {
    segs: Vec<Vec<String>>,
    certain: bool,
    dirs: Vec<Option<String>>,
    /// Whether a bash reading gives these parts.
    bash: bool,
}

impl Reading {
    /// The programs and folders of the parts, which readings must agree on.
    fn shape(&self) -> Vec<(&str, Option<&str>)> {
        self.segs
            .iter()
            .zip(&self.dirs)
            .map(|(s, d)| (s[0].as_str(), d.as_deref()))
            .collect()
    }
}

/// How a shell treats a lone `&`.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Amp {
    /// It stays inside the command (how the splitter first worked).
    Keep,
    /// It ends a command, unless it is part of a redirection: after `>` or `<` (`2>&1`,
    /// `>&2`, `<&0`), and, when `amp_gt`, before `>` (`&>f`, `&>>f`).
    Split { amp_gt: bool },
}

/// What a backslash-like escape does inside double quotes.
#[derive(Clone, Copy, PartialEq, Eq)]
enum DqEscape {
    /// Nothing: a `\` is a literal character and a `"` ends the string (how the splitter
    /// first worked).
    None,
    /// Bash: `\` before `"`, `\`, `$` or a backtick.
    Bash,
    /// PowerShell: the backtick escapes any character.
    PowerShell,
}

/// The quoting and separator rules of one reading of a command. [`readings`] judges a
/// command under several of them because the same text splits differently in bash,
/// PowerShell and cmd.
#[derive(Clone, Copy)]
struct Syntax {
    /// The escape outside quotes: `\` in bash, a backtick in PowerShell, `^` in cmd.
    escape: Option<char>,
    dq_escape: DqEscape,
    /// Whether `'...'` quotes (it does not in cmd).
    single_quotes: bool,
    /// PowerShell also reads the typographic quotes as quotes.
    smart_quotes: bool,
    /// Bash `$'...'`, which has backslash escapes.
    ansi_c: bool,
    /// Bash `${...}`, inside which a `&` is text.
    braces: bool,
    amp: Amp,
    /// Whether this is a reading of bash (as opposed to PowerShell or cmd).
    bash: bool,
}

/// Bash as the splitter first read it: `\` escapes, a `"` always ends a double-quoted
/// string, and a lone `&` stays in the command. Keeping this reading means no command is
/// ever judged more leniently than it was before the others were added.
const OLD: Syntax = Syntax {
    escape: Some('\\'),
    dq_escape: DqEscape::None,
    single_quotes: true,
    smart_quotes: false,
    ansi_c: false,
    braces: false,
    amp: Amp::Keep,
    bash: true,
};
/// Bash with a lone `&` as a separator.
const BASH: Syntax = Syntax {
    braces: true,
    amp: Amp::Split { amp_gt: true },
    ..OLD
};
/// Bash with the quoting that [`BASH`] leaves out: `\"` in double quotes and `$'...'`.
const BASH_QUOTING: Syntax = Syntax {
    dq_escape: DqEscape::Bash,
    ansi_c: true,
    ..BASH
};
/// PowerShell: the backtick is the escape and `\` is a plain character. `&>` is not a
/// redirection there, so every `&` that is not `2>&1`-like ends a command.
const POWERSHELL: Syntax = Syntax {
    escape: Some('`'),
    dq_escape: DqEscape::PowerShell,
    single_quotes: true,
    smart_quotes: true,
    ansi_c: false,
    braces: false,
    amp: Amp::Split { amp_gt: false },
    bash: false,
};
/// cmd: `^` is the escape, `'` is not a quote, and `&` always separates (`&>f` included).
const CMD: Syntax = Syntax {
    escape: Some('^'),
    dq_escape: DqEscape::None,
    single_quotes: false,
    smart_quotes: false,
    ansi_c: false,
    braces: false,
    amp: Amp::Split { amp_gt: false },
    bash: false,
};

impl Syntax {
    fn is_single(&self, c: char) -> bool {
        (c == '\'' && self.single_quotes)
            || (self.smart_quotes && matches!(c, '\u{2018}' | '\u{2019}' | '\u{201a}' | '\u{201b}'))
    }

    fn is_double(&self, c: char) -> bool {
        c == '"' || (self.smart_quotes && matches!(c, '\u{201c}' | '\u{201d}' | '\u{201e}'))
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Quote {
    Single,
    Double,
    /// Bash `$'...'`.
    AnsiC,
}

/// Split a shell command into simple commands (at `&&`, `||`, `;`, `|`, a lone `&`, newlines
/// and parentheses, outside quotes) and each into words, reading it as bash does. A lone `&`
/// ends a command; the redirections `2>&1`, `>&2`, `<&0`, `&>f` and `&>>f` do not, and
/// neither does a `&` inside `${...}`. A leading call operator (`& "C:/x/tool.exe"`) leaves an
/// empty part, which is dropped. Leading `VAR=value` words and redirections (`>f`, `2>&1`,
/// `<f`) are dropped and the program is reduced to its file name (`/usr/bin/git`, `git.exe`
/// → `git`).
///
/// The hook does not rely on this reading alone: see [`readings`].
#[must_use]
pub fn segments(cmd: &str) -> Vec<Vec<String>> {
    split(cmd, BASH)
}

/// The command split under every reading that a shell could give it: bash as the splitter
/// first read it, bash with a lone `&` as a separator, bash with `\"` and `$'...'`
/// understood, PowerShell and cmd. Identical results are listed once. A policy decision
/// takes the strictest over all of them, so a command a shell reads differently from the
/// others cannot hide a part from the policy.
#[must_use]
pub fn readings(cmd: &str) -> Vec<Vec<Vec<String>>> {
    parse_all(cmd).into_iter().map(|p| p.segs).collect()
}

/// One distinct reading of a command, and what is known about how it was read.
struct Parsed {
    segs: Vec<Vec<String>>,
    /// Whether a bash reading gives these parts (and not only PowerShell or cmd).
    bash: bool,
    /// Whether a part started with `!`, which inverts its status: a failed `cd` then lets
    /// the next part run in the folder before it.
    bang: bool,
}

fn parse_all(cmd: &str) -> Vec<Parsed> {
    parse_with_raw(cmd).0
}

/// [`parse_all`], also giving the unquoted words of every part under every reading (see
/// [`Split::raw`]), which the check for `GH_REPO` and `GH_HOST` reads.
fn parse_with_raw(cmd: &str) -> (Vec<Parsed>, Vec<Vec<String>>) {
    let mut out: Vec<Parsed> = Vec::new();
    let mut raw: Vec<Vec<String>> = Vec::new();
    for syntax in [OLD, BASH, BASH_QUOTING, POWERSHELL, CMD] {
        let s = split_full(cmd, syntax);
        raw.extend(s.raw);
        match out.iter_mut().find(|p| p.segs == s.segs) {
            Some(p) => {
                p.bash |= syntax.bash;
                p.bang |= s.bang;
            }
            None => out.push(Parsed {
                segs: s.segs,
                bash: syntax.bash,
                bang: s.bang,
            }),
        }
    }
    (out, raw)
}

fn split(cmd: &str, sh: Syntax) -> Vec<Vec<String>> {
    split_full(cmd, sh).segs
}

/// A command split into simple commands under one reading, with what [`split`] leaves out.
struct Split {
    /// The words of each simple command, as [`segments`] returns them.
    segs: Vec<Vec<String>>,
    /// Whether a part started with `!`.
    bang: bool,
    /// Every unquoted word of every simple command, assignments and commands made only of
    /// assignments included, with the program as written.
    raw: Vec<Vec<String>>,
}

fn split_full(cmd: &str, sh: Syntax) -> Split {
    let mut out = Split {
        segs: Vec::new(),
        bang: false,
        raw: Vec::new(),
    };
    let mut words: Vec<String> = Vec::new();
    let mut word = String::new();
    let mut quote: Option<Quote> = None;
    let mut chars = cmd.chars().peekable();
    let mut prev = ' ';
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
        out.raw.push(all.clone());
        let (mut ws, negated) = strip_leading(all);
        out.bang |= negated && !ws.is_empty();
        if let Some(p) = ws.first_mut() {
            *p = program_name(p);
        }
        if !ws.is_empty() {
            out.segs.push(ws);
        }
    };
    while let Some(c) = chars.next() {
        let before = std::mem::replace(&mut prev, c);
        match quote {
            Some(Quote::Single) => {
                if sh.is_single(c) {
                    quote = None;
                } else {
                    word.push(c);
                }
            }
            Some(Quote::AnsiC) => match c {
                '\\' => word.extend(chars.next()),
                '\'' => quote = None,
                _ => word.push(c),
            },
            Some(Quote::Double) => {
                if sh.is_double(c) {
                    quote = None;
                } else if sh.dq_escape != DqEscape::None && c == dq_escape_char(sh) {
                    match chars.peek() {
                        Some(&n)
                            if sh.dq_escape == DqEscape::PowerShell
                                || matches!(n, '"' | '\\' | '$' | '`') =>
                        {
                            word.push(n);
                            chars.next();
                        }
                        _ => word.push(c),
                    }
                } else {
                    word.push(c);
                }
            }
            None => match c {
                _ if sh.is_single(c) => quote = Some(Quote::Single),
                _ if sh.is_double(c) => quote = Some(Quote::Double),
                // `$$` is the process id: what follows it is not `${`, `$'` or `$(`.
                '$' if chars.peek() == Some(&'$') => {
                    chars.next();
                    word.push_str("$$");
                }
                '$' if sh.ansi_c && chars.peek() == Some(&'\'') => {
                    chars.next();
                    quote = Some(Quote::AnsiC);
                }
                '$' if sh.braces && chars.peek() == Some(&'{') => {
                    word.push(c);
                    take_braces(&mut chars, &mut word);
                }
                _ if Some(c) == sh.escape => {
                    if let Some(n) = chars.next() {
                        if n == '\r' && chars.peek() == Some(&'\n') {
                            chars.next();
                        } else if n != '\n' {
                            word.push(n);
                        }
                    }
                }
                '&' | '|' => {
                    if chars.peek() == Some(&c) {
                        chars.next();
                    } else if c == '|' && chars.peek() == Some(&'&') {
                        chars.next(); // `|&` is a pipe
                    } else if c == '&' && keeps_amp(sh, before, chars.peek().copied()) {
                        word.push(c);
                        continue;
                    }
                    push_word(&mut word, &mut words);
                    end(&mut words, &mut out);
                }
                // `(` and `)` also end a command, so a subshell's commands are still read.
                ';' | '\n' | '(' | ')' => {
                    push_word(&mut word, &mut words);
                    end(&mut words, &mut out);
                }
                _ if c.is_whitespace() => push_word(&mut word, &mut words),
                '<' => {
                    // `a<f` → `a`, `<f`; a file descriptor stays with it (`0<&0`).
                    if !word.chars().all(|c| c.is_ascii_digit()) {
                        push_word(&mut word, &mut words);
                    }
                    word.push(c);
                }
                '>' => {
                    // Redirections are their own words: `a>>b` → `a`, `>>`, `b`.
                    push_word(&mut word, &mut words);
                    let mut op = String::from('>');
                    if chars.peek() == Some(&'>') {
                        chars.next();
                        op.push('>');
                    }
                    words.push(op);
                }
                _ => word.push(c),
            },
        }
    }
    push_word(&mut word, &mut words);
    end(&mut words, &mut out);
    out
}

fn dq_escape_char(sh: Syntax) -> char {
    match sh.dq_escape {
        DqEscape::PowerShell => '`',
        _ => '\\',
    }
}

/// Whether a lone `&` stays in the word: `before` is the character before it and `next` the
/// one after.
fn keeps_amp(sh: Syntax, before: char, next: Option<char>) -> bool {
    match sh.amp {
        Amp::Keep => true,
        Amp::Split { amp_gt } => before == '>' || before == '<' || (amp_gt && next == Some('>')),
    }
}

/// After a `${` was read: copy it and everything up to the matching `}` into `word`
/// unchanged, so a `&` or `;` in it is text. Quotes and backslashes inside are honoured.
fn take_braces(chars: &mut std::iter::Peekable<std::str::Chars<'_>>, word: &mut String) {
    let mut depth = 0_u32;
    let mut quote: Option<char> = None;
    while let Some(c) = chars.next() {
        word.push(c);
        match (quote, c) {
            (Some(q), c) if c == q => quote = None,
            (Some('"'), '\\') | (None, '\\') => word.extend(chars.next()),
            (Some(_), _) => {}
            (None, '\'' | '"') => quote = Some(c),
            (None, '{') => depth += 1,
            (None, '}') => {
                depth -= 1;
                if depth == 0 {
                    return;
                }
            }
            _ => {}
        }
    }
}

/// Words that can come before a command without being it: `{ git push; }`, `then git push`.
/// (`!` too, but it is noted: it inverts the status, see [`Parsed::bang`].)
const SHELL_KEYWORDS: &[&str] = &[
    "{", "}", "if", "then", "elif", "else", "do", "while", "until", "time",
];

/// Drop what comes before a command's program: `VAR=value` assignments, shell keywords, `!`
/// (which is reported) and redirections (`>f`, `> f`, `>>f`, `2>f`, `&>f`, `N>&M`, `<f`, `0<&0`, `<<EOF`), which a
/// shell allows anywhere in a command.
fn strip_leading(words: Vec<String>) -> (Vec<String>, bool) {
    let mut i = 0;
    let mut bang = false;
    while i < words.len() {
        let w = words[i].as_str();
        if w == "!" {
            bang = true;
            i += 1;
        } else if is_assignment(w) || SHELL_KEYWORDS.contains(&w) {
            i += 1;
        } else if let n @ 1.. = redirection_len(&words, i) {
            i += n;
        } else {
            break;
        }
    }
    (words.into_iter().skip(i).collect(), bang)
}

/// How many words the redirection starting at `words[i]` takes, 0 if there is none:
/// `>f`, `> f`, `>>f`, `2>f`, `&>f`, `2>&1` (after the split into words) and `<f`, `0<&0`,
/// `<<EOF` (one word); `<`, `<<` and `<<<` take the next word as their target.
fn redirection_len(words: &[String], i: usize) -> usize {
    let w = words[i].as_str();
    let is_gt = |s: Option<&str>| matches!(s, Some(">" | ">>"));
    let digits = w.trim_start_matches(|c: char| c.is_ascii_digit());
    let all_digits = !w.is_empty() && digits.is_empty();
    let next = words.get(i + 1).map(String::as_str);
    if is_gt(Some(w)) {
        2 // `>` and its target
    } else if (w == "&" || all_digits) && is_gt(next) {
        3 // `&>f`, `2>f`, `2>&1`
    } else if digits.starts_with('<') {
        if digits.chars().all(|c| c == '<') {
            2
        } else {
            1
        }
    } else {
        0
    }
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
            // Nothing but flags follows. A redirection is not an argument, wherever it is.
            let rest = &seg[i..];
            let mut j = 0;
            while j < rest.len() {
                match redirection_len(rest, j) {
                    0 if rest[j].starts_with('-') => j += 1,
                    0 => return false,
                    n => j += n,
                }
            }
            return true;
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
                // `cd a b` fails in bash and leaves the folder as it was.
                targets.len() == 1
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
        if next_is_redirect && (w == "&" || w.chars().all(|c| c.is_ascii_digit())) {
            i += 1; // `2` of `2>&1`, `&` of `&>f`
            continue;
        }
        let after_digits = w.trim_start_matches(|c: char| c.is_ascii_digit());
        if after_digits.starts_with('<') {
            // `<f`, `0<&0`; `<` and `<<` take the next word as well.
            i += if after_digits.chars().all(|c| c == '<') {
                2
            } else {
                1
            };
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
    fn a_lone_ampersand_ends_a_command() {
        assert_eq!(
            segments("echo x & git push origin main"),
            [vec!["echo", "x"], vec!["git", "push", "origin", "main"]]
        );
        assert_eq!(
            segments("echo x &git push"),
            [vec!["echo", "x"], vec!["git", "push"]]
        );
        // The PowerShell call operator leaves an empty part, which is dropped.
        assert_eq!(
            segments(r#"& "C:/x/Tool.exe" a b"#),
            [vec!["tool", "a", "b"]]
        );
        assert_eq!(segments("a &; b"), [vec!["a"], vec!["b"]]);
        assert_eq!(segments("a |& b"), [vec!["a"], vec!["b"]]);
        assert_eq!(segments("a && b"), [vec!["a"], vec!["b"]]);
        // Not separators: redirections, and `&` in quotes or after a backslash.
        assert_eq!(segments("ls >&2"), [vec!["ls", ">", "&2"]]);
        assert_eq!(segments("ls >&-"), [vec!["ls", ">", "&-"]]);
        assert_eq!(segments("ls &>out.txt"), [vec!["ls", "&", ">", "out.txt"]]);
        assert_eq!(
            segments("ls &>>out.txt"),
            [vec!["ls", "&", ">>", "out.txt"]]
        );
        assert_eq!(segments(r#"echo "a & b""#), [vec!["echo", "a & b"]]);
        assert_eq!(segments("echo 'a & b'"), [vec!["echo", "a & b"]]);
        assert_eq!(segments(r"echo a\&b"), [vec!["echo", "a&b"]]);
    }

    #[test]
    fn a_command_after_a_lone_ampersand_is_still_judged() {
        for cmd in [
            "echo x & git push origin main",
            "echo x &git push origin main",
            "true & git push --force",
            "& git push origin main",
            "echo x & gh pr merge 1",
            "echo x & rm -rf build",
            "echo x & git push origin main & echo y",
        ] {
            assert_eq!(decide(cmd), Decision::Ask, "{cmd}");
        }
        assert_eq!(decide("echo x & gh repo delete a/b"), Decision::Deny);
    }

    #[test]
    fn input_redirections_and_braces_do_not_hide_arguments() {
        for cmd in [
            "git push <&0 origin main",
            "git push origin <&- main",
            "git push 0<&0 origin main",
            "git push <in.txt origin main",
            "git push ${x:+&} origin main",
            "git push ${x:-a;b} origin main",
            "git push ${x:-'}'&} origin main",
            "gh pr merge ${x:+&} 1",
            "npm publish ${x:+&}",
            "vercel ${x:+&} --prod",
            "git reset ${x:+&} --hard",
            "rm <&0 -rf build",
        ] {
            assert_eq!(decide(cmd), Decision::Ask, "{cmd}");
        }
        assert_eq!(decide("gh repo <&0 delete a/b"), Decision::Deny);
        assert_eq!(
            segments("git push ${x:+&} origin main"),
            [vec!["git", "push", "${x:+&}", "origin", "main"]]
        );
        assert_eq!(
            segments("git push <&0 origin main"),
            [vec!["git", "push", "<&0", "origin", "main"]]
        );
    }

    #[test]
    fn another_shells_escapes_and_quotes_do_not_hide_a_command() {
        for cmd in [
            // PowerShell: `\` is not an escape.
            r"echo x\& git push origin main",
            // Bash: `\"` inside double quotes.
            r#"echo "\"" & git push origin main"#,
            r#"echo "\"" ; git push origin main"#,
            // Bash: `$'...'` with an escaped quote.
            r"echo $'\'' & git push origin main",
            // PowerShell: a backtick-escaped quote.
            "echo \"`\"\" ; git push origin main",
            "echo \"`\"\" & git push origin main",
            // PowerShell's typographic quotes close a string that began with a straight one.
            "echo \u{201c}a\" & git push origin main\u{201d}",
            // cmd's `^&` and PowerShell's `` `& `` are one argument; the reading that sees a
            // separator still judges what follows.
            "git -c core.pager=foo^&bar push origin main",
            "git -c core.pager=foo`&bar push origin main",
            // The program is not a redirection.
            ">f git push origin main",
            "> f git push origin main",
            ">>f git push origin main",
            "2>f git push origin main",
            "&>f git push origin main",
            "<f git push origin main",
            "2>&1 git push origin main",
            "echo x & > /dev/null git push origin main",
            // Shell keywords before the command.
            "{ git push origin main; }",
            "if true; then git push origin main; fi",
        ] {
            assert_eq!(decide(cmd), Decision::Ask, "{cmd}");
        }
    }

    #[test]
    fn every_reading_of_a_command_is_listed_once() {
        let r = readings("echo hi");
        assert_eq!(r, [vec![vec!["echo", "hi"]]]);
        // PowerShell keeps the backslash, bash drops it.
        let r = readings(r"git C:\x");
        assert!(r.contains(&vec![vec!["git".to_owned(), "C:x".to_owned()]]));
        assert!(r.contains(&vec![vec!["git".to_owned(), r"C:\x".to_owned()]]));
        // cmd has no single quotes.
        assert!(readings("echo 'a & b'").len() > 1);
    }

    /// Dangerous commands: each asks or is denied on its own.
    const DANGEROUS: &[&str] = &[
        "git push origin main",
        "git push --force origin feature",
        "git push -f origin feature",
        "git push --delete origin feature",
        "git push --all",
        "git push --mirror",
        "git reset --hard HEAD~1",
        "git clean -fd",
        "git branch -D old",
        "git filter-branch --all",
        "gh pr merge 1",
        "gh repo delete a/b",
        "gh secret set X",
        "npm publish",
        "cargo publish",
        "pnpm publish",
        "vercel --prod",
        "vercel deploy",
        "vercel env add X",
        "fly deploy",
        "netlify deploy --prod",
        "supabase db push",
        "wrangler deploy",
        "firebase deploy",
        "railway up",
        "rm -rf build",
        "sendmail me@example.com",
        "mail -s hi me@example.com",
        "curl https://api.telegram.org/bot1/sendMessage",
        "setx X 1",
    ];

    #[test]
    fn nothing_inserted_after_the_program_weakens_a_decision() {
        let p = policy();
        for plain in DANGEROUS {
            let base = p.decide(Action::Command(plain)).decision;
            assert_ne!(base, Decision::Allow, "{plain} is meant to be dangerous");
            let (prog, args) = plain.split_once(' ').unwrap_or((plain, ""));
            for ins in [
                "<&0", "<&-", "${x:+&}", r"\&", "`&", "^&", "&>f", "2>&1", ">f",
            ] {
                let cmd = format!("{prog} {ins} {args}");
                let got = p.decide(Action::Command(&cmd)).decision;
                assert!(got >= base, "{cmd}: {got:?} is weaker than {base:?}");
            }
        }
    }

    #[test]
    fn exceptions_need_every_reading_to_agree() {
        let p = with_exception();
        let at = |cmd: &str| decide_from_mm(&p, cmd);
        assert_eq!(at("git push origin main"), Decision::Allow);
        // A lone `&` or a quote some shell reads differently: the exception does not lift.
        assert_eq!(at("git push origin main &"), Decision::Ask);
        assert_eq!(at("echo 'a & b' && git push origin main"), Decision::Ask);
        assert_eq!(at(r#"echo "\"" && git push origin main"#), Decision::Ask);
    }

    #[test]
    fn a_cd_that_fails_does_not_move_the_exception() {
        // The agent works in a repository on `main` without an exception. `cd M M` fails in
        // bash (too many arguments) and `!` turns that into success, so the push runs here.
        let p = with_exception();
        let on_main = |_: Option<&str>| Some("main".to_owned());
        let repo =
            |hint: Option<&str>| Some(hint.unwrap_or("C:/Users/x/Projects/other").to_owned());
        let at = |cmd: &str| p.decide_at(Action::Command(cmd), &on_main, &repo).decision;
        let m = "/c/Users/x/Projects/mneme-memory";
        for cmd in [
            format!("! cd {m} {m} && git push origin main"),
            format!("! cd {m} {m} && git push"),
            format!("cd {m} {m} && git push origin main"),
            format!("cd {m} {m} && git push"),
            format!("! cd {m} && git push origin main"),
            format!("! cd {m} && git push"),
            format!("set-location {m} {m} && git push origin main"),
        ] {
            assert_eq!(at(&cmd), Decision::Ask, "{cmd}");
        }
        // The same without the trap: one `cd` to the excepted repository lifts it.
        assert_eq!(
            at(&format!("cd {m} && git push origin main")),
            Decision::Allow
        );
        // `!` in front of a command is still read as the command it negates.
        assert_eq!(
            segments("! git push origin main"),
            [vec!["git", "push", "origin", "main"]]
        );
        assert_eq!(decide("! git push origin main"), Decision::Ask);
    }

    #[test]
    fn a_process_id_is_not_the_start_of_an_expansion() {
        for cmd in [
            r##"echo \" $${ & git push origin main #} \""##,
            r##"echo "\"" $$'\' & git push origin main"##,
            r##"echo $$$'\'' & git push origin main"##,
            r##"echo $$(true) & git push origin main"##,
            r##"echo $$ & git push origin main"##,
        ] {
            assert_eq!(decide(cmd), Decision::Ask, "{cmd}");
        }
        assert_eq!(
            segments("echo $${ & git push"),
            [vec!["echo", "$${"], vec!["git", "push"]]
        );
    }

    #[test]
    fn text_only_cmd_or_powershell_reads_as_a_command_asks_instead_of_denying() {
        for cmd in [
            "git commit -m 'Ask before git push; rm -rf needs approval'",
            "git commit -m 'done; gh repo delete x'",
            "gh pr create --body 'note; gh repo delete x'",
            "gh pr create --body 'a' --title 'b & gh repo delete x'",
        ] {
            assert_eq!(decide(cmd), Decision::Ask, "{cmd}");
        }
        // Where bash reads it as a command too, the deny stays.
        for cmd in [
            "gh repo delete x",
            "echo hi; gh repo delete x",
            "echo 'a' ; gh repo delete x",
            "echo hi & gh repo delete x",
            "gh pr create --body 'a' && gh repo delete x",
        ] {
            assert_eq!(decide(cmd), Decision::Deny, "{cmd}");
        }
    }

    #[test]
    fn a_command_over_64_kb_asks_without_being_read() {
        let p = policy();
        let long = format!("echo {}", "a ".repeat(MAX_COMMAND_BYTES / 2));
        assert!(long.len() > MAX_COMMAND_BYTES);
        let start = std::time::Instant::now();
        let v = p.decide(Action::Command(&long));
        assert_eq!(v.decision, Decision::Ask);
        assert!(!p.allowed_after_budget(&long));
        assert!(start.elapsed() < std::time::Duration::from_millis(500));
        // Just under the limit is read as usual.
        let ok = format!("echo {}", "a ".repeat(100));
        assert_eq!(p.decide(Action::Command(&ok)).decision, Decision::Allow);
    }

    #[test]
    fn a_bare_deploy_with_a_redirection_still_asks() {
        for cmd in [
            "vercel",
            "vercel --yes",
            "vercel --yes</dev/null",
            "vercel --yes<in",
            "vercel --prod0<&0",
            "vercel 2>&1",
            "vercel --yes 2>&1 | tail -5",
            "vercel > log.txt",
            "vercel >> log.txt",
            "vercel &> log.txt",
            "vercel <&0",
            "vercel < in",
            "vercel <<EOF",
            "vercel --yes>out",
            "npx vercel 2>&1",
            "npx vercel --yes</dev/null",
        ] {
            assert_eq!(decide(cmd), Decision::Ask, "{cmd}");
        }
        // Redirections do not make a command with a real argument a bare deploy.
        assert_eq!(decide("vercel ls 2>&1"), Decision::Allow);
        assert_eq!(decide("vercel env ls </dev/null"), Decision::Allow);
    }

    #[test]
    fn a_deny_in_a_command_over_64_kb_still_denies() {
        let p = policy();
        let text = "x ".repeat(35 * 1024);
        let deny_first = format!("gh repo delete x; echo {text}");
        let append = format!("echo {text} >> memory/log.jsonl");
        for cmd in [&deny_first, &append] {
            assert!(cmd.len() > MAX_COMMAND_BYTES);
            let start = std::time::Instant::now();
            let v = p.decide(Action::Command(cmd));
            assert_eq!(v.decision, Decision::Deny);
            assert!(start.elapsed() < std::time::Duration::from_millis(500));
        }
        // An ask stays an ask, and nothing else is let through.
        let ask = format!("git push origin main; echo {text}");
        assert_eq!(p.decide(Action::Command(&ask)).decision, Decision::Ask);
    }

    #[test]
    fn the_example_in_the_docs_asks() {
        let example = "git commit -m 'run tests & git push origin main after review'";
        let docs = include_str!("../../../docs/organs/intelligence.md");
        assert!(docs.contains(example));
        assert_eq!(decide(example), Decision::Ask);
    }

    #[test]
    fn wrap_up_commands_need_every_reading_to_agree() {
        let p = policy();
        assert!(p.allowed_after_budget("cargo test --all"));
        assert!(!p.allowed_after_budget("cargo test & cargo build --release"));
        assert!(!p.allowed_after_budget(r#"echo "\" & cargo build --release""#));
    }

    #[test]
    fn redirections_and_quotes_with_an_ampersand_keep_their_decision() {
        for cmd in [
            "cargo build 2>&1",
            "ls >&2",
            "ls >&-",
            "ls &>out.txt",
            "ls &>>out.txt",
            r#"echo "a & b""#,
            "echo 'a & b'",
            "cmd1 && cmd2",
            "cargo test 2>&1 | tail -3",
        ] {
            assert_eq!(decide(cmd), Decision::Allow, "{cmd}");
        }
        assert_eq!(decide("git push --force 2>&1"), Decision::Ask);
        assert_eq!(decide("git push --force &>out.txt"), Decision::Ask);
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

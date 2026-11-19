//! The hook end to end, as Claude Code runs it: an event on stdin, a decision on stdout, a
//! trail in organon's folder. A fake transcript stands in for the agent session.

use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use organon_core::time::rfc3339;

struct Env {
    home: PathBuf,
    transcript: PathBuf,
}

fn env(name: &str) -> Env {
    // Under cargo's own scratch folder, not the system TEMP: on Windows runners TEMP is an 8.3
    // short name with a `~`, which a literal-safe `cd <path>` command may not contain.
    let root = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("organon-hook-test-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();
    let transcript = root.join("session.jsonl");
    // One earlier total calibrates the rate: $1 for 1000 weighted tokens.
    fs::write(
        &transcript,
        r#"{"type":"cost-state","totalCostUSD":1.0,"modelUsage":{"m":{"costUSD":1.0,"inputTokens":1000}}}"#.to_owned() + "\n",
    )
    .unwrap();
    Env {
        home: root.join("home"),
        transcript,
    }
}

impl Env {
    /// Claude Code's config folder for this test: `<root>/claude`, never the real one.
    fn claude_dir(&self) -> PathBuf {
        self.home.with_file_name("claude")
    }

    fn organon(&self, args: &[&str], stdin: &str) -> (String, bool) {
        self.organon_in(None, args, stdin)
    }

    /// Run organon as a command of the Claude Code session `session_id`, if any.
    fn organon_in(&self, session_id: Option<&str>, args: &[&str], stdin: &str) -> (String, bool) {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_organon"));
        // Tests may run inside a Claude Code session: never pick up its id or transcripts.
        cmd.env_remove("CLAUDE_CODE_SESSION_ID")
            .env("CLAUDE_CONFIG_DIR", self.claude_dir());
        if let Some(id) = session_id {
            cmd.env("CLAUDE_CODE_SESSION_ID", id);
        }
        let mut child = cmd
            .args(args)
            .env("ORGANON_HOME", &self.home)
            .env("ORGANON_STANDING_TTL", "0")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(stdin.as_bytes())
            .unwrap();
        let out = child.wait_with_output().unwrap();
        (
            String::from_utf8_lossy(&out.stdout).into_owned(),
            out.status.success(),
        )
    }

    /// Run organon with extra environment variables and, if given, a working folder.
    fn run(
        &self,
        args: &[&str],
        stdin: &str,
        envs: &[(&str, &str)],
        cwd: Option<&Path>,
    ) -> (String, bool) {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_organon"));
        cmd.env_remove("CLAUDE_CODE_SESSION_ID")
            .env_remove("ORGANON_SESSION_ID")
            // gh's target must not leak in from the machine running the tests.
            .env_remove("GH_REPO")
            .env_remove("GH_HOST")
            .env_remove("CLAUDE_ENV_FILE")
            .env("CLAUDE_CONFIG_DIR", self.claude_dir())
            .env("ORGANON_HOME", &self.home)
            .env("ORGANON_STANDING_TTL", "0");
        for (k, v) in envs {
            cmd.env(k, v);
        }
        if let Some(d) = cwd {
            cmd.current_dir(d);
        }
        let mut child = cmd
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(stdin.as_bytes())
            .unwrap();
        let out = child.wait_with_output().unwrap();
        (
            String::from_utf8_lossy(&out.stdout).into_owned(),
            out.status.success(),
        )
    }

    /// The hook, given its raw stdin.
    fn hook_raw(&self, stdin: &str, envs: &[(&str, &str)]) -> String {
        let (out, ok) = self.run(&["hook"], stdin, envs, None);
        assert!(ok, "a hook never fails");
        out
    }

    fn hook(&self, tool: &str, input: &str) -> String {
        self.hook_in(&self.transcript, tool, input)
    }

    /// A hook call from the session whose transcript is `transcript`.
    fn hook_in(&self, transcript: &Path, tool: &str, input: &str) -> String {
        let ev = format!(
            r#"{{"session_id":"s","transcript_path":{},"cwd":".","hook_event_name":"PreToolUse","tool_name":"{tool}","tool_input":{input}}}"#,
            serde_json::to_string(&transcript.to_string_lossy()).unwrap()
        );
        let (out, ok) = self.organon(&["hook"], &ev);
        assert!(ok, "a hook never fails");
        out
    }

    fn spend(&self, weighted_tokens: u64) {
        spend_in(&self.transcript, weighted_tokens);
    }

    fn trail(&self, slug: &str) -> String {
        fs::read_to_string(self.home.join("tasks").join(slug).join("trail.jsonl"))
            .unwrap_or_default()
    }
}

/// Append one request of `weighted_tokens` input tokens, made now, to a transcript.
fn spend_in(transcript: &Path, weighted_tokens: u64) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let line = format!(
        r#"{{"type":"assistant","timestamp":"{}","message":{{"id":"r1","model":"m","usage":{{"input_tokens":{weighted_tokens},"output_tokens":0}}}}}}"#,
        rfc3339(i64::try_from(now).unwrap())
    );
    let mut f = fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open(transcript)
        .unwrap();
    writeln!(f, "{line}").unwrap();
}

impl Drop for Env {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(self.home.parent().unwrap_or(Path::new(".")));
    }
}

#[test]
fn a_spent_budget_stops_work_but_not_wrap_up() {
    let e = env("budget");
    assert_eq!(
        e.hook("Bash", r#"{"command":"true"}"#),
        "",
        "no task, nothing to say"
    );
    let (out, ok) = e.organon(
        &["task", "new", "probe", "--effort", "lookup", "--usd", "0.5"],
        "",
    );
    assert!(ok && out.contains("task probe"), "{out}");

    assert_eq!(
        e.hook("Bash", r#"{"command":"organon-research fetch run"}"#),
        ""
    );
    assert!(
        e.trail("probe").contains("\"fetch\""),
        "an allowed organ call is on the trail"
    );

    e.spend(600); // $0.60 of $0.50
    let out = e.hook("Bash", r#"{"command":"organon-research search run all x"}"#);
    assert!(
        out.contains(r#""permissionDecision":"deny""#) && out.contains("do not retry"),
        "{out}"
    );
    // Regression: another session running at the same time was stopped by this task's budget.
    let other = e.transcript.with_file_name("other-session.jsonl");
    fs::write(&other, "").unwrap();
    assert_eq!(
        e.hook_in(
            &other,
            "Bash",
            r#"{"command":"organon-research fetch run"}"#
        ),
        "",
        "a task's budget acts only in its own session"
    );
    // Regression: a denied organ call was recorded as used.
    assert!(
        !e.trail("probe").contains("\"search\""),
        "{}",
        e.trail("probe")
    );
    assert!(e.hook("WebSearch", r#"{"query":"x"}"#).contains("deny"));

    assert_eq!(
        e.hook("Bash", r#"{"command":"git add -A && git commit -m done"}"#),
        ""
    );
    assert_eq!(e.hook("Write", r#"{"file_path":"proposals/p.json"}"#), "");

    let (out, ok) = e.organon(&["task", "done", "--outcome", "partial", "--left", "x"], "");
    assert!(
        ok && out.contains("closed probe · partial · ≈$0.60"),
        "{out}"
    );
    let episodes = fs::read_to_string(e.home.join("episodes.jsonl")).unwrap();
    assert!(
        episodes.contains(r#""kind":"task""#) && episodes.contains(r#""usd":0.6"#),
        "{episodes}"
    );
}

#[test]
fn a_task_is_metered_in_the_session_that_declared_it_even_before_its_first_total() {
    let e = env("own");
    let projects = e.claude_dir().join("projects");
    // This session: no cost total yet (a fresh session).
    let ours = projects.join("p").join("sid-ours.jsonl");
    fs::create_dir_all(ours.parent().unwrap()).unwrap();
    fs::write(&ours, "").unwrap();
    // Another session, running at the same time, that has a total for the same model.
    let other = projects.join("q").join("sid-other.jsonl");
    fs::create_dir_all(other.parent().unwrap()).unwrap();
    fs::copy(&e.transcript, &other).unwrap();
    // The other session's hook ran last, so the shared pointer names it.
    e.hook_in(&other, "Bash", r#"{"command":"true"}"#);

    let (out, ok) = e.organon_in(
        Some("sid-ours"),
        &["task", "new", "probe", "--effort", "lookup", "--usd", "0.5"],
        "",
    );
    assert!(ok, "{out}");
    let task = fs::read_to_string(e.home.join("tasks").join("probe").join("task.json")).unwrap();
    // Regression: the task was metered on whichever session's hook ran last.
    assert!(task.contains("sid-ours.jsonl"), "{task}");

    // Regression: with no total in its own transcript, spend read as $? and never stopped.
    spend_in(&ours, 600); // $0.60 of $0.50, priced from the other session's total
    let out = e.hook_in(&ours, "Bash", r#"{"command":"organon-research fetch run"}"#);
    assert!(out.contains(r#""permissionDecision":"deny""#), "{out}");
    // Regression: the stop read as "stop everything", so finished work was left uncommitted.
    assert!(
        out.contains("commit and push") && out.contains("Wrapping up is still allowed"),
        "{out}"
    );
    assert_eq!(
        e.hook_in(
            &ours,
            "Bash",
            r#"{"command":"cd /x && grep -n a README.md && git push"}"#
        ),
        ""
    );
}

#[test]
fn commands_act_on_their_own_sessions_task() {
    let e = env("scope");
    let dir = e.claude_dir().join("projects").join("p");
    fs::create_dir_all(&dir).unwrap();
    for id in ["sid-a", "sid-b"] {
        fs::write(dir.join(format!("{id}.jsonl")), "").unwrap();
    }
    let new = |id: &str, goal: &str| {
        let (out, ok) = e.organon_in(Some(id), &["task", "new", goal, "--effort", "lookup"], "");
        assert!(ok, "{out}");
    };
    new("sid-a", "task a");
    std::thread::sleep(std::time::Duration::from_millis(1100)); // b starts later: the newest
    new("sid-b", "task b");

    // Regression: brief, audit and `task done` took the newest open task of any session.
    let (out, _) = e.organon_in(Some("sid-a"), &["brief"], "");
    assert!(out.contains("task: task-a"), "{out}");
    let (out, ok) = e.organon_in(Some("sid-a"), &["task", "done", "--outcome", "good"], "");
    assert!(ok && out.contains("closed task-a"), "{out}");

    // Outside any session, with two open, nothing is guessed.
    new("sid-a", "task c");
    let (out, ok) = e.organon_in(None, &["task", "done", "--outcome", "good"], "");
    assert!(!ok, "{out}");
    let tasks = fs::read_to_string(e.home.join("tasks").join("task-b").join("task.json")).unwrap();
    assert!(
        !tasks.contains("\"ended\""),
        "the other session's task stays open: {tasks}"
    );
}

#[test]
fn eighty_percent_warns_once() {
    let e = env("warn");
    e.hook("Bash", r#"{"command":"true"}"#);
    e.organon(
        &["task", "new", "probe", "--effort", "lookup", "--usd", "1"],
        "",
    );
    e.spend(850);
    let first = e.hook("Read", r#"{"file_path":"x"}"#);
    assert!(
        first.contains("additionalContext") && first.contains("85%"),
        "{first}"
    );
    assert_eq!(e.hook("Read", r#"{"file_path":"x"}"#), "", "warned once");
}

/// A PreToolUse event from session `session`, working in `cwd`.
fn event(session: &str, transcript: &Path, cwd: &str, tool: &str, input: &str) -> String {
    format!(
        r#"{{"session_id":"{session}","transcript_path":{},"cwd":{},"hook_event_name":"PreToolUse","tool_name":"{tool}","tool_input":{input}}}"#,
        serde_json::to_string(&transcript.to_string_lossy()).unwrap(),
        serde_json::to_string(cwd).unwrap()
    )
}

fn command(cmd: &str) -> String {
    format!(r#"{{"command":{}}}"#, serde_json::to_string(cmd).unwrap())
}

fn is_deny(out: &str) -> bool {
    out.contains(r#""permissionDecision":"deny""#)
}

fn is_ask(out: &str) -> bool {
    out.contains(r#""permissionDecision":"ask""#)
}

// ------------------------------------------------------------ 1. the hook fails closed

#[test]
fn a_broken_policy_denies_approval_class_actions_and_allows_the_rest() {
    let e = env("broken-policy");
    fs::create_dir_all(&e.home).unwrap();
    fs::write(e.home.join("policy.json"), "{ not a policy").unwrap();

    for (tool, input) in [
        ("Bash", command("git push origin main")),
        ("Bash", command("npx vercel --prod")),
        ("Bash", command("gh pr merge 3 --squash")),
        ("Bash", command("rm -rf build")),
        ("Write", r#"{"file_path":"/app/.env"}"#.to_owned()),
        ("mcp__mail__send_message", r#"{"to":"a@b.c"}"#.to_owned()),
    ] {
        let out = e.hook(tool, &input);
        assert!(is_deny(&out), "{tool} {input}: {out}");
        assert!(out.contains("approval class"), "{out}");
    }
    // Everything else keeps the old behaviour: allowed, the error logged.
    assert_eq!(e.hook("Bash", &command("cargo test")), "");
    assert_eq!(e.hook("Bash", &command("git push origin fix/x")), "");
    assert_eq!(e.hook("Read", r#"{"file_path":"x"}"#), "");
    let log = fs::read_to_string(e.home.join("hook-errors.log")).unwrap();
    assert!(log.contains("not a valid policy"), "{log}");
}

#[test]
fn a_malformed_event_is_classified_from_what_can_be_read() {
    let e = env("malformed");
    // Cut off mid-way, as a broken pipe would leave it.
    let cut = r#"{"session_id":"s","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"git push origin HEAD:main && echo \"done"#;
    let out = e.hook_raw(cut, &[]);
    assert!(is_deny(&out) && out.contains("push-main"), "{out}");

    let cut =
        r#"{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"ls -la"#;
    assert_eq!(e.hook_raw(cut, &[]), "", "not an approval class: allowed");
    assert_eq!(
        e.hook_raw("garbage", &[]),
        "",
        "nothing to classify: allowed"
    );
}

#[test]
fn a_slow_hook_denies_approval_class_actions_at_its_deadline() {
    let e = env("deadline");
    let slow = [
        ("ORGANON_HOOK_DEADLINE_MS", "300"),
        ("ORGANON_HOOK_TEST_DELAY_MS", "5000"),
    ];
    let ev = event(
        "s",
        &e.transcript,
        ".",
        "Bash",
        &command("supabase db push"),
    );
    let started = std::time::Instant::now();
    let out = e.hook_raw(&ev, &slow);
    assert!(is_deny(&out) && out.contains("longer than 300 ms"), "{out}");
    assert!(
        started.elapsed() < std::time::Duration::from_millis(4000),
        "the hook answered at its deadline, not after the slow work"
    );
    let ev = event("s", &e.transcript, ".", "Bash", &command("cargo build"));
    assert_eq!(e.hook_raw(&ev, &slow), "");
}

// ------------------------------------------------------------ 2. ask rules

#[test]
fn pushes_to_main_deploys_and_sends_ask() {
    let e = env("ask-rules");
    for cmd in [
        "git push origin main",
        "git push -u origin master",
        "vercel --prod",
        "fly deploy",
        "supabase functions deploy f",
        "gh pr merge 7",
        "Send-MailMessage -To a@b.c -Subject x",
        "curl https://api.telegram.org/botX/sendMessage -d text=hi",
    ] {
        let out = e.hook("Bash", &command(cmd));
        assert!(is_ask(&out), "{cmd}: {out}");
    }
    assert_eq!(e.hook("Bash", &command("git push -u origin fix/x")), "");
    assert_eq!(e.hook("Bash", &command("vercel env ls")), "");
}

#[test]
fn a_merge_exception_lets_a_plain_merge_through_in_its_repository_only() {
    let e = env("merge-exception");
    fs::create_dir_all(&e.home).unwrap();
    fs::write(
        e.home.join("policy.json"),
        r#"{"efforts":{"lookup":{"usd":1.0,"minutes":15}},"routes":{},"rules":[],
            "exceptions":[{"class":"merge","repo":"*/repo","reason":"my own repository"}]}"#,
    )
    .unwrap();
    let root = e.home.parent().unwrap().to_owned();
    let mut cwds = Vec::new();
    for name in ["repo", "other"] {
        let dir = root.join(name);
        fs::create_dir_all(dir.join(".git")).unwrap();
        fs::write(dir.join(".git").join("HEAD"), "ref: refs/heads/feature\n").unwrap();
        cwds.push(dir.to_string_lossy().into_owned());
    }
    let run = |cwd: &str, cmd: &str| {
        e.hook_raw(&event("s", &e.transcript, cwd, "Bash", &command(cmd)), &[])
    };
    // In the excepted repository a merge goes through with any flags that only change how it
    // merges; `--admin` and another repository (the folder has no origin here) are denied.
    for cmd in [
        "gh pr merge 7 --squash --delete-branch",
        "gh pr merge 7 --auto --body notes",
        "gh pr merge 7 -sd",
    ] {
        assert_eq!(run(&cwds[0], cmd), "", "{cmd}");
    }
    for cmd in [
        "gh pr merge 7 --admin",
        "gh pr merge 7 --repo Philipjj609/Koda",
        "gh pr merge 7 -R Philipjj609/Koda",
        "gh pr merge 7 -sR Philipjj609/Koda",
    ] {
        let out = run(&cwds[0], cmd);
        assert!(is_deny(&out), "{cmd}: {out}");
    }
    let out = run(&cwds[0], "echo x | mail a@b.c");
    assert!(is_ask(&out), "{out}");
    // In any other repository it still asks.
    let out = run(&cwds[1], "gh pr merge 7 --squash");
    assert!(is_ask(&out), "{out}");
    // A target that may come from GH_REPO (in the command, or inherited by the hook) asks.
    let out = run(&cwds[0], "GH_REPO=Philipjj609/Koda gh pr merge 7 --squash");
    assert!(is_ask(&out), "{out}");
    let out = run(&cwds[0], "export GH_HOST=h && gh pr merge 7");
    assert!(is_ask(&out), "{out}");
    for var in ["GH_REPO", "GH_HOST"] {
        let ev = event(
            "s",
            &e.transcript,
            &cwds[0],
            "Bash",
            &command("gh pr merge 7 --squash"),
        );
        let out = e.hook_raw(&ev, &[(var, "Philipjj609/Koda")]);
        assert!(is_ask(&out), "{var}: {out}");
    }
}

/// A repository with a `merge` exception, and the hook run from inside it.
fn merge_exception_env(name: &str, policy: &str) -> (Env, String) {
    let e = env(name);
    fs::create_dir_all(&e.home).unwrap();
    fs::write(e.home.join("policy.json"), policy).unwrap();
    let dir = e.home.parent().unwrap().join("repo");
    fs::create_dir_all(dir.join(".git")).unwrap();
    fs::write(dir.join(".git").join("HEAD"), "ref: refs/heads/feature\n").unwrap();
    let cwd = dir.to_string_lossy().into_owned();
    (e, cwd)
}

const MERGE_EXCEPTION: &str = r#"{"efforts":{"lookup":{"usd":1.0,"minutes":15}},"routes":{},"rules":[],
    "exceptions":[{"class":"merge","repo":"*/repo","reason":"my own repository"}]}"#;

#[test]
fn a_merge_exception_only_lifts_a_whole_command_that_is_a_plain_merge_end_to_end() {
    let (e, cwd) = merge_exception_env("merge-allow-list", MERGE_EXCEPTION);
    let run = |cmd: &str| e.hook_raw(&event("s", &e.transcript, &cwd, "Bash", &command(cmd)), &[]);
    // The folders as `cd` takes them: absolute, forward slashes, plain characters.
    let slash = |p: &str| p.replace('\\', "/");
    let repo = slash(&cwd);
    let other = slash(&cwd.replace("repo", "other"));
    let other_cwd = cwd.replace("repo", "other");
    fs::create_dir_all(Path::new(&other_cwd).join(".git")).unwrap();
    fs::write(
        Path::new(&other_cwd).join(".git").join("HEAD"),
        "ref: refs/heads/feature\n",
    )
    .unwrap();
    assert!(
        repo.chars()
            .all(|c| c.is_ascii_alphanumeric() || "._/-:+".contains(c)),
        "the test folder must be literal-safe: {repo}"
    );
    for cmd in [
        "gh pr merge 12 --squash".to_owned(),
        "gh pr merge 12 --squash --delete-branch --match-head-commit abc1234".to_owned(),
        "gh pr merge 12 --rebase".to_owned(),
        "gh pr merge feat/x --merge".to_owned(),
        "gh pr merge 12 -s".to_owned(),
        "gh pr merge 12 --auto --body notes -sd".to_owned(),
        "gh pr merge 7 --match-head-commit abc123".to_owned(),
        format!("cd {repo} && gh pr merge 3 --squash --match-head-commit 0123456789abcdef0123456789abcdef01234567"),
    ] {
        assert_eq!(run(&cmd), "", "{cmd}");
    }
    for cmd in [
        "gh pr merge 7 --admin",
        "gh pr merge 7 -sdRPhilipjj609/Koda",
        "gh pr merge 7 -dR Philipjj609/Koda",
        "gh pr merge https://github.com/o/r/pull/7",
    ] {
        let out = run(cmd);
        assert!(is_deny(&out), "{cmd}: {out}");
    }
    for cmd in [
        format!("cd {other} && gh pr merge 3"),
        "gh -R Philipjj609/Koda pr merge 7".to_owned(),
        "gh --repo Philipjj609/Koda pr merge 7".to_owned(),
        "gh --repo=Philipjj609/Koda pr merge 7".to_owned(),
        "gh pr merge 3 --squash && git pull".to_owned(),
        // one-command bypasses
        "PR=https://github.com/o/r/pull/7 && gh pr merge $PR --squash".to_owned(),
        r#"printf '[remote "upstream"]' >> .git/config && gh pr merge 7"#.to_owned(),
        "cp x .git/config && gh pr merge 7".to_owned(),
        "hash -p /tmp/g gh && gh pr merge 7".to_owned(),
        "New-Item function:gh -Value {x} && gh pr merge 7".to_owned(),
        format!("builtin cd {other} && gh pr merge 7"),
        format!("Push-Location {other} && gh pr merge 7"),
        format!("chdir {other} && gh pr merge 7"),
        format!("cd {other} && cd {repo} && gh pr merge 7"),
        r#"export GH_RE""PO=X && gh pr merge 7"#.to_owned(),
        r"export GH_RE\PO=X && gh pr merge 7".to_owned(),
        "git remote set-url origin https://github.com/Philipjj609/Koda && gh pr merge 7".to_owned(),
        "gh repo set-default Philipjj609/Koda && gh pr merge 7".to_owned(),
        "GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=url.https://github.com/Philipjj609/Koda.insteadOf GIT_CONFIG_VALUE_0=https://github.com/Philipjj609/repo gh pr merge 7".to_owned(),
    ] {
        let out = run(&cmd);
        assert!(is_ask(&out), "{cmd}: {out}");
    }
    // A `cd` target that Git Bash and PowerShell read as different folders asks. On Windows
    // that is `/c/...` (PowerShell enters `C:/c/...`) or any path without a drive; elsewhere
    // a `C:/...` path is no absolute path at all.
    let wrong: Vec<String> = if cfg!(windows) {
        let rest = repo.get(2..).unwrap_or_default(); // "/Users/x/..."
        let drive = repo[..1].to_ascii_lowercase();
        vec![format!("/{drive}{rest}"), rest.to_owned()]
    } else {
        vec![format!("C:{repo}")]
    };
    for target in wrong {
        for prog in ["cd", "Set-Location", "sl"] {
            let cmd = format!("{prog} {target} && gh pr merge 7 --squash");
            let out = run(&cmd);
            assert!(is_ask(&out), "{cmd}: {out}");
        }
    }
}

/// Env files that are only blank lines, comments and plain assignments: the real ones Claude
/// Code's Vercel plugin writes, an empty file and one with CRLF line ends.
const SAFE_ENV_FILES: [&str; 5] = [
    "",
    "export VERCEL_PLUGIN_BOOTSTRAP_HINTS=\"greenfield\"\nexport VERCEL_PLUGIN_SETUP_MODE=\"1\"\n",
    "export VERCEL_PLUGIN_SETUP_MODE=\"1\"\r\nFOO=bar\r\n",
    "\n# a note\n\nexport FOO=1\n",
    "A=b\nexport C='d e'\n",
    // (Their names are the ones `MERGE_EXCEPTION_ENV` lists.)
];

/// Env files that can steer `gh` to another repository (or cannot be shown not to).
const UNSAFE_ENV_FILES: [&str; 20] = [
    // a name split by a line continuation
    "export GH_\\\nREPO=Philipjj609/Koda\n",
    "export GH_\\\nHOST=h\n",
    "export GH_REPO=x\n",
    "export gh_host=h\n",
    "export GH_RE\"\"PO=x\n",
    "export GIT_DIR=C:/x/other/.git\n",
    "export GIT_CONFIG_COUNT=1\n",
    "export PATH=/tmp/evil:/usr/bin\n",
    "export HOME=/x\n",
    "export BASH_ENV=/x\n",
    "gh() { command gh -R o/other pr merge 7 --squash; }\n",
    "alias gh=x\n",
    "export A=1; export GH_REPO=x\n",
    "export A=\"x\" B=y\n",
    "export A=$B\n",
    "export A=`date`\n",
    "X=H_REPO\nexport G$X=o/other\n",
    "eval \"$(foo)\"\n",
    "source ./x.sh\n",
    ". ./x.sh\n",
];

/// The same exception, with the variable names its env files may set listed in policy.
const MERGE_EXCEPTION_ENV: &str = r#"{"efforts":{"lookup":{"usd":1.0,"minutes":15}},"routes":{},"rules":[],
    "exceptions":[{"class":"merge","repo":"*/repo","reason":"my own repository"}],
    "merge_env_names":["VERCEL_PLUGIN_*","FOO","A","C"]}"#;

/// Names the policy above does not list, or that no policy may list: each makes a file ask.
const UNLISTED_NAME_ENV_FILES: [&str; 9] = [
    "export VERCEL_OTHER=1\n",
    "export NOT_LISTED=1\n",
    "export VERCEL_PLUGIN_SETUP_MODE=\"1\"\nexport NOT_LISTED=1\n",
    "export OPTIND=PATH=0\n",
    "export EXECIGNORE=x\n",
    "export LD_PRELOAD=/x/y.so\n",
    "export PATHEXT=.EXE\n",
    "export HTTPS_PROXY=http://x\n",
    "export GITHUB_TOKEN=x\n",
];

#[test]
fn a_session_env_file_whose_names_are_not_in_the_policy_list_stops_the_merge_exception() {
    // The default list is empty: any assignment asks, comments and blank lines do not.
    let (e, cwd) = merge_exception_env("merge-session-names-default", MERGE_EXCEPTION);
    let ev = event(
        "s",
        &e.transcript,
        &cwd,
        "Bash",
        &command("gh pr merge 7 --squash"),
    );
    let dir = e.claude_dir().join("session-env").join("s");
    fs::create_dir_all(&dir).unwrap();
    let with = |e: &Env, ev: &str, content: &str| {
        let file = e
            .claude_dir()
            .join("session-env")
            .join("s")
            .join("hook-1.sh");
        fs::write(&file, content).unwrap();
        let out = e.hook_raw(ev, &[]);
        fs::remove_file(file).unwrap();
        out
    };
    for text in ["", "\n# a note\n\n"] {
        assert_eq!(with(&e, &ev, text), "", "{text:?}");
    }
    for text in SAFE_ENV_FILES.iter().filter(|t| t.contains('=')) {
        let out = with(&e, &ev, text);
        assert!(is_ask(&out), "default list: {text:?}: {out}");
    }
    // With `VERCEL_PLUGIN_*` listed the real plugin files go through; others do not.
    let (e, cwd) = merge_exception_env("merge-session-names-listed", MERGE_EXCEPTION_ENV);
    let ev = event(
        "s",
        &e.transcript,
        &cwd,
        "Bash",
        &command("gh pr merge 7 --squash"),
    );
    let dir = e.claude_dir().join("session-env").join("s");
    fs::create_dir_all(&dir).unwrap();
    let real = "export VERCEL_PLUGIN_BOOTSTRAP_HINTS=\"1\"\nexport VERCEL_PLUGIN_SETUP_MODE=\"greenfield\"\n";
    assert_eq!(with(&e, &ev, real), "");
    for text in UNLISTED_NAME_ENV_FILES {
        let out = with(&e, &ev, text);
        assert!(is_ask(&out), "{text:?}: {out}");
    }
}

#[test]
fn a_policy_with_an_invalid_merge_env_names_denies_a_merge_instead_of_lifting_it() {
    // The shipped rules still count: an unreadable policy fails closed on a merge. Broad
    // patterns, a pattern that could match a barred name and a bad character all do it.
    for (i, bad) in ["*", "*_*", "LD_*", "G*", "VERCEL-*", ""]
        .iter()
        .enumerate()
    {
        let policy = format!(
            r#"{{"efforts":{{"lookup":{{"usd":1.0,"minutes":15}}}},"routes":{{}},"rules":[],
            "exceptions":[{{"class":"merge","repo":"*/repo","reason":"my own repository"}}],
            "merge_env_names":["{bad}"]}}"#
        );
        let (e, cwd) = merge_exception_env(&format!("merge-bad-env-names-{i}"), &policy);
        let ev = event(
            "s",
            &e.transcript,
            &cwd,
            "Bash",
            &command("gh pr merge 7 --squash"),
        );
        let out = e.hook_raw(&ev, &[]);
        assert!(is_deny(&out), "{bad:?}: {out}");
        assert!(
            out.contains("merge_env_names"),
            "{bad:?}: names the field: {out}"
        );
        // Anything that is not in an approval class is let through as before.
        let ev = event("s", &e.transcript, &cwd, "Bash", &command("git status"));
        assert_eq!(e.hook_raw(&ev, &[]), "", "{bad:?}");
    }
}

#[test]
fn a_claude_env_file_whose_names_are_not_in_the_policy_list_stops_the_merge_exception() {
    let run = |name: &str, policy: &str, text: &str| {
        let (e, cwd) = merge_exception_env(name, policy);
        let ev = event(
            "s",
            &e.transcript,
            &cwd,
            "Bash",
            &command("gh pr merge 7 --squash"),
        );
        let file = e.home.parent().unwrap().join("env.sh");
        fs::write(&file, text).unwrap();
        e.hook_raw(&ev, &[("CLAUDE_ENV_FILE", &file.to_string_lossy())])
    };
    let real = "export VERCEL_PLUGIN_BOOTSTRAP_HINTS=\"1\"\nexport VERCEL_PLUGIN_SETUP_MODE=\"greenfield\"\n";
    assert_eq!(run("env-names-listed", MERGE_EXCEPTION_ENV, real), "");
    let out = run("env-names-default", MERGE_EXCEPTION, real);
    assert!(is_ask(&out), "default list: {out}");
    for (i, text) in UNLISTED_NAME_ENV_FILES.iter().enumerate() {
        let out = run(
            &format!("env-names-unlisted-{i}"),
            MERGE_EXCEPTION_ENV,
            text,
        );
        assert!(is_ask(&out), "{text:?}: {out}");
    }
}

#[test]
fn a_session_env_file_that_is_not_plain_assignments_stops_the_merge_exception() {
    let (e, cwd) = merge_exception_env("merge-session-env", MERGE_EXCEPTION_ENV);
    let ev = event(
        "s",
        &e.transcript,
        &cwd,
        "Bash",
        &command("gh pr merge 7 --squash"),
    );
    // Where Claude Code keeps a session's env files: <config dir>/session-env/<session id>/.
    let dir = e.claude_dir().join("session-env").join("s");
    assert_eq!(e.hook_raw(&ev, &[]), "", "no folder: nothing to read");
    fs::create_dir_all(&dir).unwrap();
    let with = |name: &str, content: &str| {
        let file = dir.join(name);
        fs::write(&file, content).unwrap();
        let out = e.hook_raw(&ev, &[]);
        fs::remove_file(file).unwrap();
        out
    };
    for text in SAFE_ENV_FILES {
        assert_eq!(with("hook-0.sh", text), "", "{text:?}");
    }
    for text in UNSAFE_ENV_FILES {
        let out = with("hook-1.sh", text);
        assert!(is_ask(&out), "{text:?}: {out}");
    }
    // A file of another kind is not read; another session's folder is not either.
    assert_eq!(with("notes.txt", "export GH_REPO=x\n"), "");
    let other = e.claude_dir().join("session-env").join("t");
    fs::create_dir_all(&other).unwrap();
    fs::write(other.join("hook-1.sh"), "export GH_REPO=x\n").unwrap();
    assert_eq!(e.hook_raw(&ev, &[]), "");
}

#[test]
fn a_claude_env_file_that_is_not_plain_assignments_stops_the_merge_exception() {
    let (e, cwd) = merge_exception_env("merge-env-file", MERGE_EXCEPTION_ENV);
    let dir = e.home.parent().unwrap().to_owned();
    let ev = event(
        "s",
        &e.transcript,
        &cwd,
        "Bash",
        &command("gh pr merge 7 --squash"),
    );
    let with = |content: &str, name: &str| {
        let file = dir.join(name);
        fs::write(&file, content).unwrap();
        e.hook_raw(&ev, &[("CLAUDE_ENV_FILE", &file.to_string_lossy())])
    };
    for text in UNSAFE_ENV_FILES {
        let out = with(text, "env-unsafe.sh");
        assert!(is_ask(&out), "{text:?}: {out}");
    }
    // A file made only of comments and plain assignments lets the merge through.
    for text in SAFE_ENV_FILES {
        assert_eq!(with(text, "env-safe.sh"), "", "{text:?}");
    }
    // So does a file that does not exist (nothing was set), or no file at all.
    let missing = dir.join("no-such-file.sh");
    assert_eq!(
        e.hook_raw(&ev, &[("CLAUDE_ENV_FILE", &missing.to_string_lossy())]),
        ""
    );
    assert_eq!(e.hook_raw(&ev, &[]), "");
}

#[test]
fn an_old_policy_with_gh_pr_merge_in_send_still_asks_despite_a_merge_exception() {
    // Written by `organon init` before the merge class: the rule is `send`.
    let old = r#"{"efforts":{"lookup":{"usd":1.0,"minutes":15}},"routes":{},"rules":[
        {"command":"gh pr merge","decision":"ask","class":"send","reason":"old"}
    ],"exceptions":[{"class":"merge","repo":"*/repo","reason":"my own repository"}]}"#;
    let (e, cwd) = merge_exception_env("merge-old-policy", old);
    let ev = event(
        "s",
        &e.transcript,
        &cwd,
        "Bash",
        &command("gh pr merge 7 --squash"),
    );
    let out = e.hook_raw(&ev, &[]);
    assert!(is_ask(&out), "{out}");
}

#[test]
fn an_old_policy_file_still_gets_the_new_rules() {
    let e = env("old-policy");
    fs::create_dir_all(&e.home).unwrap();
    // A policy file from before approval classes: no push, deploy or send rules.
    fs::write(
        e.home.join("policy.json"),
        r#"{"efforts":{"lookup":{"usd":1.0,"minutes":15}},"routes":{},"rules":[
            {"command":"git push --force*","decision":"ask","reason":"old"}
        ]}"#,
    )
    .unwrap();
    assert!(is_ask(&e.hook("Bash", &command("git push origin main"))));
    assert!(is_ask(&e.hook("Bash", &command("vercel deploy"))));
}

#[test]
fn a_bare_push_on_main_asks() {
    let e = env("bare-push");
    let repo = e.home.parent().unwrap().join("repo");
    fs::create_dir_all(repo.join(".git")).unwrap();
    fs::write(repo.join(".git").join("HEAD"), "ref: refs/heads/main\n").unwrap();
    let cwd = repo.to_string_lossy().into_owned();
    let push = |cmd: &str| e.hook_raw(&event("s", &e.transcript, &cwd, "Bash", &command(cmd)), &[]);
    assert!(is_ask(&push("git push")), "on main");
    assert!(is_ask(&push("git push origin")), "on main, remote only");
    assert!(is_ask(&push("git push origin HEAD")), "HEAD on main");
    assert!(is_ask(&push("git push -u origin @")), "@ on main");
    assert_eq!(push("git push origin feature"), "", "a named branch");
    fs::write(repo.join(".git").join("HEAD"), "ref: refs/heads/feature\n").unwrap();
    assert_eq!(push("git push"), "", "on a feature branch");
    assert_eq!(push("git push origin HEAD"), "", "HEAD on a feature branch");
    assert_eq!(push("git push -u origin @"), "", "@ on a feature branch");
}

// ------------------------------------------------------------ 3. parallel sessions

#[test]
fn parallel_sessions_keep_separate_records_and_spend() {
    let e = env("parallel");
    let root = e.home.parent().unwrap().to_owned();
    let cwd = root.to_string_lossy().into_owned();
    let a = root.join("sid-a.jsonl");
    let b = root.join("sid-b.jsonl");
    fs::copy(&e.transcript, &a).unwrap();
    fs::copy(&e.transcript, &b).unwrap();
    spend_in(&a, 300); // $0.30
    spend_in(&b, 700); // $0.70

    // Many hook calls from both sessions at the same time.
    let handles: Vec<_> = (0..16)
        .map(|i| {
            let (id, t) = if i % 2 == 0 {
                ("sid-a", &a)
            } else {
                ("sid-b", &b)
            };
            let ev = event(id, t, &cwd, "Bash", &command("true"));
            let (home, claude) = (e.home.clone(), e.claude_dir());
            std::thread::spawn(move || {
                let mut child = Command::new(env!("CARGO_BIN_EXE_organon"))
                    .arg("hook")
                    .env_remove("CLAUDE_CODE_SESSION_ID")
                    .env("ORGANON_HOME", home)
                    .env("CLAUDE_CONFIG_DIR", claude)
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .spawn()
                    .unwrap();
                child
                    .stdin
                    .take()
                    .unwrap()
                    .write_all(ev.as_bytes())
                    .unwrap();
                let out = child.wait_with_output().unwrap();
                assert!(out.status.success());
                String::from_utf8_lossy(&out.stdout).into_owned()
            })
        })
        .collect();
    for h in handles {
        assert_eq!(h.join().unwrap(), "");
    }

    // One record per session, each naming its own transcript; no shared pointer.
    let dir = e.home.join("sessions");
    let mut names: Vec<String> = fs::read_dir(&dir)
        .unwrap()
        .flatten()
        .map(|f| f.file_name().to_string_lossy().into_owned())
        .filter(|n| n.ends_with(".json"))
        .collect();
    names.sort();
    assert_eq!(names, ["sid-a.json", "sid-b.json"]);
    for (id, t) in [("sid-a", &a), ("sid-b", &b)] {
        let r: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(dir.join(format!("{id}.json"))).unwrap())
                .unwrap();
        assert_eq!(r["transcript"], t.to_string_lossy().as_ref(), "{r}");
    }
    assert!(!e.home.join("session.json").exists());

    // Each session's spend, separately.
    let (out, ok) = e.run(&["spend", "--session", "sid-a"], "", &[], None);
    assert!(ok && out.contains("≈$0.30"), "{out}");
    let (out, ok) = e.run(&["spend", "--session", "sid-b"], "", &[], None);
    assert!(ok && out.contains("≈$0.70"), "{out}");
    let (out, ok) = e.run(&["spend", "--sessions"], "", &[], None);
    assert!(ok, "{out}");
    let line = |id: &str| {
        out.lines()
            .find(|l| l.starts_with(id))
            .unwrap_or_default()
            .to_owned()
    };
    assert!(line("sid-a").contains("≈$0.30"), "{out}");
    assert!(line("sid-b").contains("≈$0.70"), "{out}");

    // Outside both sessions, in their folder: nothing is guessed.
    let (out, ok) = e.run(
        &["task", "new", "probe", "--effort", "lookup"],
        "",
        &[],
        Some(&root),
    );
    assert!(ok && out.contains("several agent sessions"), "{out}");
    let task = fs::read_to_string(e.home.join("tasks").join("probe").join("task.json")).unwrap();
    assert!(!task.contains("\"meter\""), "{task}");
    let (out, ok) = e.run(&["spend"], "", &[], Some(&root));
    assert!(!ok, "{out}");

    // A runner names its session: that one is metered.
    let (out, ok) = e.run(
        &["task", "new", "named", "--effort", "lookup"],
        "",
        &[("ORGANON_SESSION_ID", "sid-b")],
        Some(&root),
    );
    assert!(ok, "{out}");
    let task = fs::read_to_string(e.home.join("tasks").join("named").join("task.json")).unwrap();
    assert!(task.contains("sid-b.jsonl"), "{task}");
}

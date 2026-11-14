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
    let root =
        std::env::temp_dir().join(format!("organon-hook-test-{name}-{}", std::process::id()));
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

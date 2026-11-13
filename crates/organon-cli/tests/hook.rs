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
    fn organon(&self, args: &[&str], stdin: &str) -> (String, bool) {
        let mut child = Command::new(env!("CARGO_BIN_EXE_organon"))
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
        let ev = format!(
            r#"{{"session_id":"s","transcript_path":{},"cwd":".","hook_event_name":"PreToolUse","tool_name":"{tool}","tool_input":{input}}}"#,
            serde_json::to_string(&self.transcript.to_string_lossy()).unwrap()
        );
        let (out, ok) = self.organon(&["hook"], &ev);
        assert!(ok, "a hook never fails");
        out
    }

    fn spend(&self, weighted_tokens: u64) {
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
            .open(&self.transcript)
            .unwrap();
        writeln!(f, "{line}").unwrap();
    }

    fn trail(&self, slug: &str) -> String {
        fs::read_to_string(self.home.join("tasks").join(slug).join("trail.jsonl"))
            .unwrap_or_default()
    }
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

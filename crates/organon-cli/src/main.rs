//! `organon`: the intelligence that coordinates the organs. A brief to start a session, tasks
//! with budgets, measured spend, a policy hook for coding agents, routes, and audits.

mod agent;
mod git;
mod home;
mod organs;

use std::fs;
use std::io::{BufReader, Read as _};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use serde_json::{json, Value};

use organon_core::audit::audit;
use organon_core::budget::{standing, Budget, Effort, Level, Minutes, Standing, Usd};
use organon_core::meter::SessionSpend;
use organon_core::policy::{segments, Action, Decision};
use organon_core::route::Tier;
use organon_core::task::{Event, Task};
use organon_core::time::rfc3339;
use organon_protocol::{check_stream, Message, Outcome, Proposal};

use crate::home::{append_line, write_json, Home};

/// Context above which every turn is expensive enough to say so.
const LARGE_CONTEXT: u64 = 200_000;
/// How often the hook re-measures a task's spend (`$ORGANON_STANDING_TTL` seconds overrides).
const STANDING_TTL_SECS: i64 = 30;

fn standing_ttl() -> i64 {
    std::env::var("ORGANON_STANDING_TTL")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(STANDING_TTL_SECS)
}

#[derive(Parser)]
#[command(
    name = "organon",
    version,
    about = "Coordinate the organs: budget, policy, routes, audit."
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// What a session should know first: organs, spend, open task, routes, policy.
    Brief,
    /// Declare, list and close tasks.
    #[command(subcommand)]
    Task(TaskCmd),
    /// Measured spend of the current agent session (or a task, or another session).
    Spend {
        #[arg(long)]
        task: Option<String>,
        #[arg(long)]
        transcript: Option<PathBuf>,
        /// A session by id (as listed by `--sessions`).
        #[arg(long)]
        session: Option<String>,
        /// Every session the hook has seen, each with its own spend.
        #[arg(long)]
        sessions: bool,
    },
    /// Who does a job: `organon route scan`, `organon route --verify <producer-model>`.
    Route {
        job: Option<String>,
        #[arg(long)]
        verify: Option<String>,
    },
    /// What the policy says about a command (`-- git push --force`) or a file write.
    Check {
        #[arg(long)]
        write: Option<String>,
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        command: Vec<String>,
    },
    /// Claude Code PreToolUse hook: reads the event on stdin, answers allow, ask or deny.
    Hook,
    /// Audit a proposal and the organ messages it cites before memory sees them.
    Audit {
        proposal: Option<PathBuf>,
        #[arg(long = "messages")]
        messages: Vec<PathBuf>,
    },
    /// Write the default policy to ~/.organon/policy.json (if absent), remember where the
    /// memory is, and show how to hook organon into Claude Code.
    Init {
        /// The memory folder (e.g. a mneme memory).
        #[arg(long)]
        memory: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum TaskCmd {
    /// Declare a task and its budget up front.
    New {
        goal: String,
        #[arg(long, default_value = "compare")]
        effort: Effort,
        /// Override the effort's money budget.
        #[arg(long)]
        usd: Option<f64>,
        /// Override the effort's time budget.
        #[arg(long)]
        minutes: Option<f64>,
    },
    /// Every task with its spend.
    List,
    /// Close a task: how it went and what is left unknown. Writes its episode.
    Done {
        slug: Option<String>,
        #[arg(long, value_parser = parse_outcome)]
        outcome: Outcome,
        #[arg(long)]
        left: Option<String>,
    },
}

fn parse_outcome(s: &str) -> Result<Outcome, String> {
    serde_json::from_value(json!(s))
        .map_err(|_| format!("unknown outcome '{s}' (good, partial, bad)"))
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("organon: {e:#}");
            ExitCode::FAILURE
        }
    }
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(0))
}

fn run(cli: Cli) -> Result<ExitCode> {
    if matches!(cli.cmd, Cmd::Hook) {
        // Even without a home folder the hook answers (with the built-in policy).
        let home = Home::locate().unwrap_or_else(|_| Home {
            root: std::env::temp_dir().join("organon"),
        });
        return Ok(hook_cmd(&home));
    }
    let home = Home::locate()?;
    match cli.cmd {
        Cmd::Brief => brief(&home),
        Cmd::Task(t) => task(&home, t),
        Cmd::Spend {
            task,
            transcript,
            session,
            sessions,
        } => spend(
            &home,
            task,
            transcript.as_deref(),
            session.as_deref(),
            sessions,
        ),
        Cmd::Route { job, verify } => route(&home, job.as_deref(), verify.as_deref()),
        Cmd::Check { write, command } => check(&home, write.as_deref(), &command.join(" ")),
        Cmd::Hook => unreachable!("handled above"),
        Cmd::Audit { proposal, messages } => audit_cmd(&home, proposal.as_deref(), &messages),
        Cmd::Init { memory } => init(&home, memory.as_deref()),
    }
}

// ---------------------------------------------------------------- rendering helpers

fn tokens(n: u64) -> String {
    #[allow(clippy::cast_precision_loss)]
    let x = n as f64;
    if n >= 1_000_000 {
        format!("{:.1}M", x / 1e6)
    } else if n >= 1_000 {
        format!("{:.0}k", x / 1e3)
    } else {
        n.to_string()
    }
}

fn money(u: Option<Usd>) -> String {
    u.map_or_else(|| "$?".into(), |u| format!("≈{u}"))
}

fn level(l: Level) -> &'static str {
    match l {
        Level::Ok => "ok",
        Level::Warn => "WARN",
        Level::Exhausted => "STOP",
    }
}

fn task_line(t: &Task, s: &Standing, ss: Option<&SessionSpend>) -> String {
    let sp = t.spend(ss, now());
    format!(
        "{} ({}) · {} of {} · {} of {} · {} ({:.0}% of {})",
        t.slug,
        t.effort.map_or("custom", Effort::as_str),
        money(sp.usd),
        t.budget.usd,
        sp.minutes,
        t.budget.minutes,
        level(s.level),
        s.used * 100.0,
        s.limit
    )
}

fn task_standing(t: &Task) -> (Standing, Option<SessionSpend>) {
    let ss = agent::task_spend(t);
    let s = standing(&t.budget, &t.spend(ss.as_ref(), now()));
    (s, ss)
}

/// The open task of the agent session this command runs in, never another session's
/// (see [`Home::current_task`]).
fn current_task(home: &Home) -> Option<Task> {
    let own = agent::own_transcript().map(|p| p.to_string_lossy().into_owned());
    home.current_task(own.as_deref())
}

// ---------------------------------------------------------------- brief

fn brief(home: &Home) -> Result<ExitCode> {
    let (policy, from_file) = home.policy()?;
    println!("organon brief · {}", rfc3339(now()));

    let found = organs::discover();
    let names: Vec<String> = found
        .iter()
        .map(|o| format!("{} {}", o.name, o.version.as_deref().unwrap_or("?")))
        .collect();
    println!(
        "organs: {}",
        if names.is_empty() {
            "none on PATH (cargo install the organ repos)".into()
        } else {
            names.join(" · ")
        }
    );

    let memory = organs::memory_name();
    if let (Some(m), Some(root)) = (found.iter().find(|o| o.name == memory), home.memory()) {
        if let Ok(out) = std::process::Command::new(&m.path)
            .arg("--root")
            .arg(&root)
            .arg("status")
            .output()
        {
            let text = String::from_utf8_lossy(&out.stdout);
            let lines: Vec<&str> = text
                .lines()
                .map(str::trim)
                .filter(|l| !l.is_empty())
                .take(2)
                .collect();
            if !lines.is_empty() {
                println!("memory: {} · {}", root.display(), lines.join(" · "));
            }
        }
    }

    if let Some(path) = agent::transcript(home, None, now()) {
        if let Ok(s) = agent::session_spend(&path) {
            println!(
                "session: {} · {} requests · context {} tokens · {} per turn now",
                money(s.usd),
                s.requests,
                s.context_now.map_or("?".into(), tokens),
                money(s.last_request_usd)
            );
            if s.context_now.is_some_and(|c| c > LARGE_CONTEXT) {
                println!(
                    "  ! every turn re-reads {} tokens: start the next independent step in a fresh session",
                    s.context_now.map_or("?".into(), tokens)
                );
            }
        }
    }

    match current_task(home) {
        Some(t) => {
            let (s, ss) = task_standing(&t);
            println!("task: {}", task_line(&t, &s, ss.as_ref()));
            if s.level == Level::Exhausted {
                println!("  ! budget spent: stop, then `organon task done {} --outcome partial --left \"…\"`", t.slug);
            }
        }
        None => {
            println!("task: none open (organon task new \"<goal>\" --effort lookup|compare|deep)")
        }
    }

    let mut tiers: Vec<(Tier, Option<String>, Vec<&str>)> = Vec::new();
    for (job, r) in &policy.routes {
        match tiers
            .iter_mut()
            .find(|(t, m, _)| *t == r.tier && *m == r.model)
        {
            Some(entry) => entry.2.push(job),
            None => tiers.push((r.tier, r.model.clone(), vec![job])),
        }
    }
    tiers.sort_by_key(|t| t.0);
    let routes: Vec<String> = tiers
        .iter()
        .map(|(t, m, jobs)| {
            let who = match (t, m) {
                (Tier::Tool, _) => "tools".to_owned(),
                (_, Some(m)) => m.clone(),
                (_, None) => format!("{t:?}").to_lowercase(),
            };
            format!("{who}: {}", jobs.join(", "))
        })
        .collect();
    println!("routes: {}", routes.join(" · "));

    let count = |d| policy.rules.iter().filter(|r| r.decision == d).count();
    println!(
        "policy: {} deny · {} ask · {}",
        count(Decision::Deny),
        count(Decision::Ask),
        if from_file {
            home.policy_path().display().to_string()
        } else {
            "built-in default (organon init to customize)".into()
        }
    );
    Ok(ExitCode::SUCCESS)
}

// ---------------------------------------------------------------- tasks

fn task(home: &Home, cmd: TaskCmd) -> Result<ExitCode> {
    let (policy, _) = home.policy()?;
    match cmd {
        TaskCmd::New {
            goal,
            effort,
            usd,
            minutes,
        } => {
            let base = policy
                .budget(effort)
                .with_context(|| format!("the policy has no budget for {effort}"))?;
            let budget = Budget {
                usd: usd.map_or(base.usd, Usd),
                minutes: minutes.map_or(base.minutes, Minutes),
            };
            let mut t = Task::new(&goal, Some(effort), budget, now());
            t.slug = home.free_slug(&t.slug);
            let located = agent::locate(home, None, now());
            if let agent::Located::Found(p) = &located {
                t.meter = agent::start(p);
            }
            home.save_task(&t)?;
            println!(
                "task {} · {effort} · budget {} and {} · warns at 80%, stops at 100%",
                t.slug, budget.usd, budget.minutes
            );
            match located {
                agent::Located::Ambiguous(here) => println!(
                    "  (several agent sessions are running in this folder ({}): not guessing which one is yours, so money is not measured, only time. Run it from the session, or set ORGANON_SESSION_ID)",
                    here.iter().map(|r| r.session_id.as_str()).collect::<Vec<_>>().join(", ")
                ),
                _ if t.meter.is_none() => {
                    println!("  (no agent transcript found: money is not measured, only time)");
                }
                _ => {}
            }
            println!(
                "close it: organon task done {} --outcome good|partial|bad [--left \"…\"]",
                t.slug
            );
        }
        TaskCmd::List => {
            let tasks = home.tasks();
            if tasks.is_empty() {
                println!("no tasks");
            }
            for t in tasks {
                let (s, ss) = task_standing(&t);
                let state = match (&t.ended, t.outcome) {
                    (None, _) => "open".to_owned(),
                    (Some(_), Some(o)) => format!("{o:?}").to_lowercase(),
                    (Some(_), None) => "closed".to_owned(),
                };
                println!("{state:8} {}", task_line(&t, &s, ss.as_ref()));
            }
        }
        TaskCmd::Done {
            slug,
            outcome,
            left,
        } => {
            let mut t = match slug {
                Some(s) => home.load_task(&s)?,
                None => current_task(home).with_context(|| {
                    let open: Vec<String> = home.open_tasks().into_iter().map(|t| t.slug).collect();
                    if open.is_empty() {
                        "no open task".to_owned()
                    } else {
                        format!(
                            "no open task of this session; open: {}. Name one: organon task done <slug>",
                            open.join(", ")
                        )
                    }
                })?,
            };
            if !t.is_open() {
                bail!("task {} is already closed", t.slug);
            }
            let ss = agent::task_spend(&t);
            t.finish(outcome, left, now());
            let spend = t.spend(ss.as_ref(), now());
            let trail = home.trail(&t.slug);
            let episode = t.episode(&spend, ss.as_ref(), &trail);
            home.save_task(&t)?;
            write_json(&home.task_dir(&t.slug).join("episode.json"), &episode)?;
            append_line(
                &home.episodes_path(),
                &serde_json::to_string(&Message::Episode(episode.clone()))?,
            )?;
            let s = standing(&t.budget, &spend);
            let organs = trail
                .iter()
                .filter(|e| matches!(e, Event::Organ { .. }))
                .count();
            println!(
                "closed {} · {} · {} of {} · {} of {} ({:.0}% of {}) · {organs} organ calls · episode {}",
                t.slug,
                format!("{outcome:?}").to_lowercase(),
                money(spend.usd),
                t.budget.usd,
                spend.minutes,
                t.budget.minutes,
                s.used * 100.0,
                s.limit,
                episode.id
            );
            if let Some(l) = &t.left {
                println!("left unknown: {l}");
            }
        }
    }
    Ok(ExitCode::SUCCESS)
}

// ---------------------------------------------------------------- spend

fn spend(
    home: &Home,
    task: Option<String>,
    transcript: Option<&Path>,
    session: Option<&str>,
    all: bool,
) -> Result<ExitCode> {
    if let Some(slug) = task {
        let t = home.load_task(&slug)?;
        let (s, ss) = task_standing(&t);
        println!("{}", task_line(&t, &s, ss.as_ref()));
        if let Some(ss) = ss {
            print_models(&ss);
        }
        return Ok(ExitCode::SUCCESS);
    }
    if all {
        let sessions = home.sessions();
        if sessions.is_empty() {
            println!("no sessions recorded yet (the hook records each session it sees)");
        }
        for r in sessions {
            let spent = agent::session_spend(Path::new(&r.transcript)).map_or_else(
                |_| "transcript unreadable".to_owned(),
                |s| format!("{} · {} requests", money(s.usd), s.requests),
            );
            println!(
                "{} · {spent} · last seen {} · {}",
                r.session_id,
                rfc3339(r.last_seen),
                r.cwd
            );
        }
        return Ok(ExitCode::SUCCESS);
    }
    let path = match (session, agent::locate(home, transcript, now())) {
        (Some(id), _) => agent::session_transcript(home, id)
            .with_context(|| format!("no session '{id}' (organon spend --sessions lists them)"))?,
        (None, agent::Located::Found(p)) => p,
        (None, agent::Located::Ambiguous(here)) => bail!(
            "several agent sessions are running in this folder: {}. Pick one with --session <id>",
            here.iter()
                .map(|r| r.session_id.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ),
        (None, agent::Located::Missing) => {
            bail!("no agent transcript found (pass --transcript or --session)")
        }
    };
    let s = agent::session_spend(&path)?;
    println!("session {}", path.display());
    println!(
        "{} · {} requests · context now {} tokens · next turn {}",
        money(s.usd),
        s.requests,
        s.context_now.map_or("?".into(), tokens),
        money(s.last_request_usd)
    );
    print_models(&s);
    println!("(≈: estimated from tokens, calibrated on the agent's own cost totals)");
    Ok(ExitCode::SUCCESS)
}

fn print_models(s: &SessionSpend) {
    for (m, t) in &s.by_model {
        println!(
            "  {m}: in {} · cache read {} · cache write {} · out {}",
            tokens(t.input),
            tokens(t.cache_read),
            tokens(t.cache_write_5m + t.cache_write_1h),
            tokens(t.output)
        );
    }
}

// ---------------------------------------------------------------- routes and policy

fn route(home: &Home, job: Option<&str>, verify: Option<&str>) -> Result<ExitCode> {
    let (policy, _) = home.policy()?;
    let show = |job: &str, r: &organon_core::route::Route| {
        let who = r
            .model
            .clone()
            .unwrap_or_else(|| "a deterministic tool".into());
        println!(
            "{job:8} {:6} {who} · {}",
            format!("{:?}", r.tier).to_lowercase(),
            r.why
        );
    };
    if let Some(p) = verify {
        let r = policy
            .verifier(p)
            .context("the policy has no verify route")?;
        show("verify", &r);
        return Ok(ExitCode::SUCCESS);
    }
    match job {
        Some(j) => show(
            j,
            policy
                .route(j)
                .with_context(|| format!("no route for '{j}'"))?,
        ),
        None => policy.routes.iter().for_each(|(j, r)| show(j, r)),
    }
    Ok(ExitCode::SUCCESS)
}

fn check(home: &Home, write: Option<&str>, command: &str) -> Result<ExitCode> {
    let (policy, _) = home.policy()?;
    let action = match write {
        Some(path) => Action::Write { path },
        None if !command.trim().is_empty() => Action::Command(command),
        None => bail!("give a command after -- or --write <path>"),
    };
    let branch_of = |hint: Option<&str>| git::branch_in(&git::folder("", hint));
    let v = policy.decide_in(action, &branch_of);
    let d = format!("{:?}", v.decision).to_lowercase();
    match v.reason {
        Some(r) => println!("{d}: {r}"),
        None => println!("{d}"),
    }
    Ok(ExitCode::from(match v.decision {
        Decision::Allow => 0,
        Decision::Ask => 1,
        Decision::Deny => 2,
    }))
}

fn init(home: &Home, memory: Option<&Path>) -> Result<ExitCode> {
    if let Some(m) = memory {
        if !m.is_dir() {
            bail!("no folder {}", m.display());
        }
        let m = std::path::absolute(m)?;
        let mut c = home.config();
        c.memory = Some(m.to_string_lossy().into_owned());
        home.save_config(&c)?;
        println!("memory: {}", c.memory.unwrap_or_default());
    }
    let path = home.policy_path();
    if path.exists() {
        println!("policy exists: {}", path.display());
    } else {
        fs::create_dir_all(&home.root)?;
        fs::write(&path, organon_core::policy::DEFAULT)?;
        println!("wrote {}", path.display());
    }
    println!(
        "To let the policy and budgets act on a Claude Code session, add to .claude/settings.json:\n{}",
        serde_json::to_string_pretty(&json!({
            "hooks": { "PreToolUse": [ { "matcher": "*", "hooks": [ { "type": "command", "command": "organon hook" } ] } ] }
        }))?
    );
    Ok(ExitCode::SUCCESS)
}

// ---------------------------------------------------------------- hook

/// Tools that cost another turn without reading or writing local files.
const SPENDING_TOOLS: &[&str] = &["Agent", "Task", "WebSearch", "WebFetch"];

/// How long the hook may take before it stops waiting for itself (`$ORGANON_HOOK_DEADLINE_MS`
/// overrides). Below Claude Code's own hook timeout, so organon, not the agent, decides what
/// a slow check means.
const HOOK_DEADLINE_MS: u64 = 8_000;

/// What the hook needs from Claude Code's event.
#[derive(Debug, Clone, Default)]
struct HookEvent {
    name: String,
    tool: String,
    command: Option<String>,
    path: Option<String>,
    transcript: String,
    session_id: String,
    cwd: String,
}

impl HookEvent {
    fn action(&self) -> Action<'_> {
        match (&self.command, &self.path) {
            (Some(c), _) => Action::Command(c),
            (None, Some(p)) => Action::Write { path: p },
            (None, None) => Action::Tool(&self.tool),
        }
    }

    fn from_json(ev: &Value) -> Self {
        let s = |k: &str| {
            ev.get(k)
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned()
        };
        let input = ev.get("tool_input").cloned().unwrap_or(Value::Null);
        let field = |k: &str| {
            input
                .get(k)
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned()
        };
        let tool = s("tool_name");
        let (command, path) = match tool.as_str() {
            "Bash" | "PowerShell" => (Some(field("command")), None),
            "Edit" | "Write" | "MultiEdit" => (None, Some(field("file_path"))),
            "NotebookEdit" => (None, Some(field("notebook_path"))),
            _ => (None, None),
        };
        Self {
            name: s("hook_event_name"),
            tool,
            command,
            path,
            transcript: s("transcript_path"),
            session_id: s("session_id"),
            cwd: s("cwd"),
        }
    }

    /// An event that is not valid JSON (cut short, or garbled) can still say what it was
    /// about: recover what can be recovered, so the fail-safe can classify it.
    fn salvage(raw: &str) -> Self {
        let tool = string_field(raw, "tool_name").unwrap_or_default();
        let command = string_field(raw, "command");
        let path = string_field(raw, "file_path").or_else(|| string_field(raw, "notebook_path"));
        Self {
            name: string_field(raw, "hook_event_name").unwrap_or_default(),
            command: command.filter(|_| matches!(tool.as_str(), "Bash" | "PowerShell" | "")),
            path,
            tool,
            transcript: String::new(),
            session_id: String::new(),
            cwd: string_field(raw, "cwd").unwrap_or_default(),
        }
    }
}

/// The value of `"key": "…"` in text that may not be valid JSON. A string cut short is taken
/// up to where it stops.
fn string_field(raw: &str, key: &str) -> Option<String> {
    let pat = format!("\"{key}\"");
    let mut from = 0;
    while let Some(k) = raw[from..].find(&pat) {
        let after = from + k + pat.len();
        from = after;
        let Some(rest) = raw[after..].trim_start().strip_prefix(':') else {
            continue;
        };
        let Some(body) = rest.trim_start().strip_prefix('"') else {
            continue;
        };
        let mut escaped = false;
        for (i, c) in body.char_indices() {
            match c {
                _ if escaped => escaped = false,
                '\\' => escaped = true,
                '"' => return serde_json::from_str(&format!("\"{}\"", &body[..i])).ok(),
                _ => {}
            }
        }
        return Some(body.replace("\\\"", "\"").replace("\\\\", "\\"));
    }
    None
}

/// The hook as Claude Code runs it. It never fails the agent's process, and its answer on an
/// internal error depends on the action: one in an approval class (push to main, deploy,
/// send, delete, secrets, paid) is **denied**, since letting it through unchecked would skip
/// the person's approval; anything else is allowed, as before. An error is a crash, a
/// panic, a malformed event, an unreadable policy, or taking longer than the deadline.
fn hook_cmd(home: &Home) -> ExitCode {
    let mut input = String::new();
    let read = std::io::stdin().read_to_string(&mut input);
    let parsed: Result<Value, _> = serde_json::from_str(&input);
    let (ev, early) = match (read, parsed) {
        (Err(e), _) => (
            HookEvent::salvage(&input),
            Some(anyhow::Error::from(e).context("reading the hook event")),
        ),
        (Ok(_), Err(e)) => (
            HookEvent::salvage(&input),
            Some(anyhow::Error::from(e).context("hook input is not JSON")),
        ),
        (Ok(_), Ok(v)) => (HookEvent::from_json(&v), None),
    };
    let outcome = match early {
        Some(e) => Err(e),
        None => hook_with_deadline(home, &ev),
    };
    match outcome {
        Ok(Some(out)) => println!("{out}"),
        Ok(None) => {}
        Err(e) => {
            let _ = append_line(
                &home.root.join("hook-errors.log"),
                &format!("{} {e:#}", rfc3339(now())),
            );
            if let Some(out) = fail_safe(home, &ev, &e) {
                println!("{out}");
            }
        }
    }
    ExitCode::SUCCESS
}

fn hook_deadline() -> std::time::Duration {
    std::time::Duration::from_millis(
        std::env::var("ORGANON_HOOK_DEADLINE_MS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(HOOK_DEADLINE_MS),
    )
}

/// Run the hook on its own thread and stop waiting at the deadline. A panic on that thread
/// arrives here as an error, like any other.
fn hook_with_deadline(home: &Home, ev: &HookEvent) -> Result<Option<String>> {
    let (tx, rx) = std::sync::mpsc::channel();
    let (home2, ev2) = (home.clone(), ev.clone());
    std::thread::spawn(move || {
        // Testing only: make the hook slow, to prove a slow hook fails closed.
        if let Some(ms) = std::env::var("ORGANON_HOOK_TEST_DELAY_MS")
            .ok()
            .and_then(|s| s.parse().ok())
        {
            std::thread::sleep(std::time::Duration::from_millis(ms));
        }
        let _ = tx.send(hook(&home2, &ev2));
    });
    let deadline = hook_deadline();
    match rx.recv_timeout(deadline) {
        Ok(r) => r,
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
            bail!("the hook took longer than {} ms", deadline.as_millis())
        }
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => bail!("the hook panicked"),
    }
}

/// The answer when the hook could not decide: deny an approval-class action, allow anything
/// else (`None`). The built-in rules always count, so a broken policy file cannot turn the
/// fail-safe off.
fn fail_safe(home: &Home, ev: &HookEvent, err: &anyhow::Error) -> Option<Value> {
    if !ev.name.is_empty() && ev.name != "PreToolUse" {
        return None;
    }
    let builtin = organon_core::policy::Policy::builtin();
    let policy = match home.policy() {
        Ok((p, _)) => p,
        Err(_) => builtin,
    };
    let branch_of = |hint: Option<&str>| git::branch_in(&git::folder(&ev.cwd, hint));
    let rule = policy.approval_class(ev.action(), &branch_of)?;
    let mut why: String = format!("{err:#}").chars().take(300).collect();
    if why.is_empty() {
        why = "unknown error".into();
    }
    Some(json!({ "hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": "deny",
        "permissionDecisionReason": format!(
            "organon could not check this action ({why}). It is in the approval class '{}' ({}), so it is denied instead of let through unchecked. Ask the user to run it, or fix organon first (details in {}).",
            rule.class.as_deref().unwrap_or("?"),
            rule.reason,
            home.root.join("hook-errors.log").display()
        ),
    }}))
}

/// The hook's normal path: the answer to print, if any.
fn hook(home: &Home, ev: &HookEvent) -> Result<Option<String>> {
    if !ev.transcript.is_empty() {
        // Bookkeeping, not part of the decision: a failure here is logged, never fatal.
        if let Err(e) = home.record_session(&ev.session_id, &ev.transcript, &ev.cwd, now()) {
            let _ = append_line(
                &home.root.join("hook-errors.log"),
                &format!("{} recording session: {e:#}", rfc3339(now())),
            );
        }
    }
    if ev.name != "PreToolUse" {
        return Ok(None);
    }
    let tool = ev.tool.as_str();
    let action = ev.action();
    let (policy, _) = home.policy()?;
    let branch_of = |hint: Option<&str>| git::branch_in(&git::folder(&ev.cwd, hint));
    let mut verdict = policy.decide_in(action, &branch_of);
    let mut context: Option<String> = None;
    let active = home.active_task_in(&ev.transcript);

    if let Some(t) = &active {
        let s = cached_standing(home, t)?;
        let wrap_up = match action {
            Action::Command(cmd) => policy.allowed_after_budget(cmd),
            _ => !SPENDING_TOOLS.contains(&tool),
        };
        if s.level == Level::Exhausted && !wrap_up && verdict.decision != Decision::Deny {
            verdict.decision = Decision::Deny;
            verdict.reason = Some(format!(
                "The budget of task '{}' is spent ({:.0}% of its {} budget). Start no new work and do not retry this. Wrapping up is still allowed and expected: edit files, read with cd/ls/cat/grep, run cargo fmt/clippy/test, commit and push with git, watch CI with gh run, digest with mneme. Then close the task with what is left: organon task done {} --outcome partial --left \"…\"",
                t.slug,
                s.used * 100.0,
                s.limit,
                t.slug
            ));
        } else if s.level == Level::Warn && warn_once(home, t)? {
            context = Some(format!(
                "organon: task '{}' has used {:.0}% of its {} budget. Finish the most valuable part, then close it.",
                t.slug,
                s.used * 100.0,
                s.limit
            ));
        }
        if verdict.decision != Decision::Allow {
            home.append_event(
                &t.slug,
                &Event::Policy {
                    time: rfc3339(now()),
                    decision: verdict.decision,
                    reason: verdict.reason.clone().unwrap_or_default(),
                    action: match action {
                        Action::Command(c) => c.chars().take(200).collect(),
                        Action::Write { path } => format!("write {path}"),
                        Action::Tool(t) => t.to_owned(),
                    },
                },
            )?;
        }
        // Only what may actually run is on the trail.
        if let (Action::Command(cmd), true) = (action, verdict.decision != Decision::Deny) {
            for seg in segments(cmd) {
                if organs::is_organ(&seg[0]) && seg[0] != "organon" {
                    home.append_event(
                        &t.slug,
                        &Event::Organ {
                            time: rfc3339(now()),
                            organ: seg[0].clone(),
                            what: seg
                                .get(1)
                                .filter(|w| !w.starts_with('-'))
                                .cloned()
                                .unwrap_or_default(),
                        },
                    )?;
                }
            }
        }
    }

    let out = match verdict.decision {
        Decision::Allow => context.map(|c| {
            json!({ "hookSpecificOutput": { "hookEventName": "PreToolUse", "additionalContext": c } })
        }),
        d => Some(json!({ "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": if d == Decision::Deny { "deny" } else { "ask" },
            "permissionDecisionReason": verdict.reason.unwrap_or_default(),
        }})),
    };
    Ok(out.map(|o| o.to_string()))
}

/// The task's standing, re-measured at most every [`STANDING_TTL_SECS`]: a stop can lag that
/// long behind the spend that caused it.
fn cached_standing(home: &Home, t: &Task) -> Result<Standing> {
    let path = home.task_dir(&t.slug).join("standing.json");
    let cached: Option<Value> = fs::read_to_string(&path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok());
    if let Some(c) = cached.filter(|c| {
        c["time"]
            .as_i64()
            .is_some_and(|x| now() - x < standing_ttl())
    }) {
        let level = match c["level"].as_str() {
            Some("warn") => Level::Warn,
            Some("exhausted") => Level::Exhausted,
            _ => Level::Ok,
        };
        let limit = if c["limit"] == "time" {
            organon_core::budget::Limit::Time
        } else {
            organon_core::budget::Limit::Money
        };
        return Ok(Standing {
            level,
            used: c["used"].as_f64().unwrap_or(0.0),
            limit,
        });
    }
    let (s, _) = task_standing(t);
    let level = match s.level {
        Level::Ok => "ok",
        Level::Warn => "warn",
        Level::Exhausted => "exhausted",
    };
    write_json(
        &path,
        &json!({ "time": now(), "level": level, "used": s.used, "limit": s.limit.to_string() }),
    )?;
    Ok(s)
}

/// True the first time a task is warned.
fn warn_once(home: &Home, t: &Task) -> Result<bool> {
    let marker = home.task_dir(&t.slug).join("warned");
    if marker.exists() {
        return Ok(false);
    }
    fs::write(marker, rfc3339(now()))?;
    Ok(true)
}

// ---------------------------------------------------------------- audit

fn audit_cmd(home: &Home, proposal: Option<&Path>, messages: &[PathBuf]) -> Result<ExitCode> {
    let p: Option<Proposal> = proposal
        .map(|path| -> Result<Proposal> {
            let text =
                fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
            serde_json::from_str(text.trim_start_matches('\u{feff}'))
                .with_context(|| format!("{} is not a proposal", path.display()))
        })
        .transpose()?;
    let mut all = Vec::new();
    let mut errors = Vec::new();
    for m in messages {
        let f = fs::File::open(m).with_context(|| format!("opening {}", m.display()))?;
        let r = check_stream(BufReader::new(f))?;
        let name = m
            .file_name()
            .map_or_else(String::new, |n| n.to_string_lossy().into_owned());
        errors.extend(
            r.errors
                .into_iter()
                .map(|e| (e.line, format!("{name}: {}", e.reason))),
        );
        all.extend(r.messages);
    }
    if p.is_none() && messages.is_empty() {
        bail!("give a proposal and/or --messages files");
    }
    let a = audit(p.as_ref(), &all, &errors);
    let what = proposal.map_or_else(|| "messages".to_owned(), |p| p.display().to_string());
    println!(
        "audit {what} · {} claims ({} inferred, {} citing evidence, {} stated without a source) · {} messages",
        a.claims, a.inferred, a.with_evidence, a.stated_unsourced, a.messages
    );
    for f in &a.findings {
        println!("  ✗ {f}");
    }
    if a.findings.is_empty() {
        println!("  ✓ nothing to fix");
    }
    if let Some(t) = current_task(home) {
        let (s, ss) = task_standing(&t);
        println!("task: {}", task_line(&t, &s, ss.as_ref()));
    }
    Ok(if a.findings.is_empty() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    })
}

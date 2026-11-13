//! `organon`: the intelligence that coordinates the organs. A brief to start a session, tasks
//! with budgets, measured spend, a policy hook for coding agents, routes, and audits.

mod agent;
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

use crate::home::{append_line, write_json, Home, SessionPointer};

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
    /// Measured spend of the current agent session (or a task).
    Spend {
        #[arg(long)]
        task: Option<String>,
        #[arg(long)]
        transcript: Option<PathBuf>,
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
    let home = Home::locate()?;
    match cli.cmd {
        Cmd::Brief => brief(&home),
        Cmd::Task(t) => task(&home, t),
        Cmd::Spend { task, transcript } => spend(&home, task, transcript.as_deref()),
        Cmd::Route { job, verify } => route(&home, job.as_deref(), verify.as_deref()),
        Cmd::Check { write, command } => check(&home, write.as_deref(), &command.join(" ")),
        Cmd::Hook => {
            // A hook must never break the agent: on any error, say nothing and allow.
            if let Err(e) = hook(&home) {
                let _ = append_line(
                    &home.root.join("hook-errors.log"),
                    &format!("{} {e:#}", rfc3339(now())),
                );
            }
            Ok(ExitCode::SUCCESS)
        }
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

    if let Some(path) = agent::transcript(home, None) {
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

    match home.active_task() {
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
            t.meter = agent::start(home);
            home.save_task(&t)?;
            println!(
                "task {} · {effort} · budget {} and {} · warns at 80%, stops at 100%",
                t.slug, budget.usd, budget.minutes
            );
            if t.meter.is_none() {
                println!("  (no agent transcript found: money is not measured, only time)");
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
                None => home.active_task().context("no open task")?,
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

fn spend(home: &Home, task: Option<String>, transcript: Option<&Path>) -> Result<ExitCode> {
    if let Some(slug) = task {
        let t = home.load_task(&slug)?;
        let (s, ss) = task_standing(&t);
        println!("{}", task_line(&t, &s, ss.as_ref()));
        if let Some(ss) = ss {
            print_models(&ss);
        }
        return Ok(ExitCode::SUCCESS);
    }
    let path = agent::transcript(home, transcript)
        .context("no agent transcript found (pass --transcript)")?;
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
    let v = policy.decide(action);
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

fn hook(home: &Home) -> Result<()> {
    let mut input = String::new();
    std::io::stdin().read_to_string(&mut input)?;
    let ev: Value = serde_json::from_str(&input).context("hook input is not JSON")?;
    let s = |k: &str| ev.get(k).and_then(Value::as_str).unwrap_or_default();
    if !s("transcript_path").is_empty() {
        home.save_session(&SessionPointer {
            transcript: s("transcript_path").into(),
            session_id: s("session_id").into(),
            cwd: s("cwd").into(),
        })?;
    }
    if s("hook_event_name") != "PreToolUse" {
        return Ok(());
    }
    let tool = s("tool_name");
    let input = ev.get("tool_input").cloned().unwrap_or(Value::Null);
    let field = |k: &str| input.get(k).and_then(Value::as_str).unwrap_or_default();
    let action = match tool {
        "Bash" | "PowerShell" => Action::Command(field("command")),
        "Edit" | "Write" | "MultiEdit" => Action::Write {
            path: field("file_path"),
        },
        "NotebookEdit" => Action::Write {
            path: field("notebook_path"),
        },
        _ => Action::Other,
    };
    let (policy, _) = home.policy()?;
    let mut verdict = policy.decide(action);
    let mut context: Option<String> = None;
    let active = home.active_task();

    if let Some(t) = &active {
        let s = cached_standing(home, t)?;
        let wrap_up = match action {
            Action::Command(cmd) => policy.allowed_after_budget(cmd),
            _ => !SPENDING_TOOLS.contains(&tool),
        };
        if s.level == Level::Exhausted && !wrap_up && verdict.decision != Decision::Deny {
            verdict.decision = Decision::Deny;
            verdict.reason = Some(format!(
                "The budget of task '{}' is spent ({:.0}% of its {} budget). Stopping is final: do not retry. Record what is left unknown and close it: organon task done {} --outcome partial --left \"…\"",
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
                        Action::Other => tool.to_owned(),
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
    if let Some(o) = out {
        println!("{o}");
    }
    Ok(())
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
    if let Some(t) = home.active_task() {
        let (s, ss) = task_standing(&t);
        println!("task: {}", task_line(&t, &s, ss.as_ref()));
    }
    Ok(if a.findings.is_empty() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    })
}

//! The coding agent's side: where its session transcript is, and reading spend from it.
//! Claude Code today; another agent needs only another way to find and read its transcript.

use std::collections::BTreeMap;
use std::fs;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use organon_core::meter::{read_claude_code, Session, SessionSpend};
use organon_core::task::{MeterStart, Task};

use crate::home::{user_home, Home, SessionRecord};

fn projects_dir() -> Option<PathBuf> {
    std::env::var_os("CLAUDE_CONFIG_DIR")
        .map(PathBuf::from)
        .or_else(|| user_home().map(|h| h.join(".claude")))
        .map(|d| d.join("projects"))
}

/// Claude Code's folder name for a project: every character that is not a letter or digit
/// becomes `-` (`C:\Users\x\proj` → `C--Users-x-proj`).
fn project_folder(cwd: &Path) -> String {
    cwd.to_string_lossy()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect()
}

/// Every Claude Code transcript, newest first.
fn transcripts() -> Vec<PathBuf> {
    let Some(dir) = projects_dir() else {
        return Vec::new();
    };
    let mut all: Vec<(PathBuf, Option<std::time::SystemTime>)> = fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .flat_map(|project| fs::read_dir(project.path()).into_iter().flatten().flatten())
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "jsonl"))
        .map(|p| {
            let t = fs::metadata(&p).and_then(|m| m.modified()).ok();
            (p, t)
        })
        .collect();
    all.sort_by_key(|a| std::cmp::Reverse(a.1));
    all.into_iter().map(|(p, _)| p).collect()
}

/// The transcript of the Claude Code session this process runs in. Claude Code names it
/// after the session id it puts in every command's environment.
pub fn own_transcript() -> Option<PathBuf> {
    let id = std::env::var("CLAUDE_CODE_SESSION_ID").ok()?;
    let name = format!("{}.jsonl", id.trim());
    transcripts()
        .into_iter()
        .find(|p| p.file_name().is_some_and(|n| n == name.as_str()))
}

/// A session counts as running if its hook ran within this many seconds.
const ACTIVE_SECS: i64 = 600;

/// Where the transcript to read was found, or why none was picked.
pub enum Located {
    Found(PathBuf),
    /// Several sessions are running in this folder and nothing says which one is calling.
    Ambiguous(Vec<SessionRecord>),
    Missing,
}

/// The transcript of a session by id: its record, else Claude Code's file of that name.
pub fn session_transcript(home: &Home, id: &str) -> Option<PathBuf> {
    if let Some(r) = home.session_record(id) {
        return Some(PathBuf::from(r.transcript));
    }
    let name = format!("{}.jsonl", id.trim());
    transcripts()
        .into_iter()
        .find(|p| p.file_name().is_some_and(|n| n == name.as_str()))
}

fn same_folder(a: &str, b: &Path) -> bool {
    let a = Path::new(a);
    match (fs::canonicalize(a), fs::canonicalize(b)) {
        (Ok(x), Ok(y)) => x == y,
        _ => a == b,
    }
}

/// The transcript to read, in this order:
/// 1. the one given;
/// 2. the calling session's own (`CLAUDE_CODE_SESSION_ID`, set by Claude Code);
/// 3. the session named by `ORGANON_SESSION_ID` (for runners and other agents);
/// 4. the one session running in the current folder, from the hook's per-session records.
///    Several running there: [`Located::Ambiguous`], never a guess;
/// 5. the newest transcript of the current folder (when no hook has recorded anything).
pub fn locate(home: &Home, explicit: Option<&Path>, now: i64) -> Located {
    if let Some(p) = explicit {
        return Located::Found(p.to_owned());
    }
    if let Some(p) = own_transcript() {
        return Located::Found(p);
    }
    if let Ok(id) = std::env::var("ORGANON_SESSION_ID") {
        return session_transcript(home, &id).map_or(Located::Missing, Located::Found);
    }
    let Ok(cwd) = std::env::current_dir() else {
        return Located::Missing;
    };
    let here: Vec<SessionRecord> = home
        .sessions()
        .into_iter()
        .filter(|r| now - r.last_seen <= ACTIVE_SECS && same_folder(&r.cwd, &cwd))
        .collect();
    match here.len() {
        1 => return Located::Found(PathBuf::from(&here[0].transcript)),
        0 => {}
        _ => return Located::Ambiguous(here),
    }
    let Some(dir) = projects_dir().map(|d| d.join(project_folder(&cwd))) else {
        return Located::Missing;
    };
    fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "jsonl"))
        .max_by_key(|p| fs::metadata(p).and_then(|m| m.modified()).ok())
        .map_or(Located::Missing, Located::Found)
}

/// [`locate`], when only a found transcript matters.
pub fn transcript(home: &Home, explicit: Option<&Path>, now: i64) -> Option<PathBuf> {
    match locate(home, explicit, now) {
        Located::Found(p) => Some(p),
        _ => None,
    }
}

/// Read a transcript from `offset` on, plus its subagents' transcripts.
pub fn read(path: &Path, offset: u64) -> Result<(Session, u64)> {
    let mut f = fs::File::open(path).with_context(|| format!("opening {}", path.display()))?;
    let len = f.metadata()?.len();
    let start = if offset <= len { offset } else { 0 };
    f.seek(SeekFrom::Start(start))?;
    let mut bytes = Vec::new();
    f.read_to_end(&mut bytes)?;
    let mut session = read_claude_code(&String::from_utf8_lossy(&bytes));
    // Subagents live next to the transcript: <session>/subagents/*.jsonl.
    let sub = path.with_extension("").join("subagents");
    for e in fs::read_dir(sub).into_iter().flatten().flatten() {
        let p = e.path();
        if p.extension().is_some_and(|x| x == "jsonl") {
            if let Ok(text) = fs::read_to_string(&p) {
                session.absorb(read_claude_code(&text));
            }
        }
    }
    Ok((session, len))
}

/// How many other transcripts to look through for a model's price.
const RATE_SOURCES: usize = 20;

/// Rates from the cost totals in other sessions' transcripts, newest first. A model's price
/// is the same in every session, and a new session may not have written a total yet.
fn known_rates(except: &Path) -> BTreeMap<String, f64> {
    let mut rates = BTreeMap::new();
    for p in transcripts()
        .into_iter()
        .filter(|p| p != except)
        .take(RATE_SOURCES)
    {
        let Ok(text) = fs::read_to_string(&p) else {
            continue;
        };
        let totals: String = text
            .lines()
            .filter(|l| l.contains("\"cost-state\""))
            .flat_map(|l| [l, "\n"])
            .collect();
        for (model, rate) in read_claude_code(&totals).rates() {
            rates.entry(model).or_insert(rate);
        }
    }
    rates
}

/// Where a new task starts in the current session, with rates calibrated on all before it
/// (or, for models this session has no total for yet, on other sessions).
pub fn start(path: &Path) -> Option<MeterStart> {
    let path = path.to_owned();
    let (session, len) = read(&path, 0).ok()?;
    let mut rates = known_rates(&path);
    rates.extend(session.rates());
    Some(MeterStart {
        transcript: path.to_string_lossy().into_owned(),
        offset: len,
        rates,
    })
}

/// A task's spend in its session so far.
pub fn task_spend(task: &Task) -> Option<SessionSpend> {
    let m = task.meter.as_ref()?;
    let (session, _) = read(Path::new(&m.transcript), m.offset).ok()?;
    let mut rates: BTreeMap<String, f64> = m.rates.clone();
    rates.extend(session.rates());
    Some(session.spend_since(task.started_at(), &rates))
}

/// The whole session's spend.
pub fn session_spend(path: &Path) -> Result<SessionSpend> {
    let (session, _) = read(path, 0)?;
    Ok(session.spend_since(i64::MIN, &session.rates()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn project_folders_follow_claude_codes_naming() {
        assert_eq!(
            project_folder(Path::new(r"C:\Users\phili\Desktop\Projects\mneme")),
            "C--Users-phili-Desktop-Projects-mneme"
        );
        assert_eq!(
            project_folder(Path::new("/home/a/my.proj")),
            "-home-a-my-proj"
        );
    }
}

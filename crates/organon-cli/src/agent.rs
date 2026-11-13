//! The coding agent's side: where its session transcript is, and reading spend from it.
//! Claude Code today; another agent needs only another way to find and read its transcript.

use std::collections::BTreeMap;
use std::fs;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use organon_core::meter::{read_claude_code, Session, SessionSpend};
use organon_core::task::{MeterStart, Task};

use crate::home::{user_home, Home};

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

/// The transcript to read: the one given, else the one the hook saw last, else the newest
/// session of the current folder.
pub fn transcript(home: &Home, explicit: Option<&Path>) -> Option<PathBuf> {
    if let Some(p) = explicit {
        return Some(p.to_owned());
    }
    if let Some(s) = home.session() {
        let p = PathBuf::from(&s.transcript);
        if p.exists() {
            return Some(p);
        }
    }
    let cwd = std::env::current_dir().ok()?;
    let dir = projects_dir()?.join(project_folder(&cwd));
    fs::read_dir(dir)
        .ok()?
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "jsonl"))
        .max_by_key(|p| fs::metadata(p).and_then(|m| m.modified()).ok())
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

/// Where a new task starts in the current session, with rates calibrated on all before it.
pub fn start(home: &Home) -> Option<MeterStart> {
    let path = transcript(home, None)?;
    let (session, len) = read(&path, 0).ok()?;
    Some(MeterStart {
        transcript: path.to_string_lossy().into_owned(),
        offset: len,
        rates: session.rates(),
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

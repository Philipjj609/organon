//! organon's own folder (`~/.organon`, or `$ORGANON_HOME`): policy, tasks, episodes, and one
//! record per agent session the hook has seen (`sessions/<id>.json`), so sessions running at
//! the same time never overwrite each other.

use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use organon_core::policy::{Policy, DEFAULT};
use organon_core::task::{Event, Task};

#[derive(Debug, Clone)]
pub struct Home {
    pub root: PathBuf,
}

/// One agent session the hook has seen: its own file, written only by its own hook calls.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SessionRecord {
    pub session_id: String,
    pub transcript: String,
    #[serde(default)]
    pub cwd: String,
    /// Epoch seconds.
    pub first_seen: i64,
    /// Epoch seconds.
    pub last_seen: i64,
}

/// A session id as a file name: letters, digits, `-` and `_` kept, anything else `_`.
pub fn session_file_name(id: &str) -> String {
    let safe: String = id
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    format!("{safe}.json")
}

/// Where things are, set once with `organon init`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Config {
    /// The memory folder (passed to the memory as `--root`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory: Option<String>,
}

pub fn user_home() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
}

impl Home {
    pub fn locate() -> Result<Self> {
        let root = match std::env::var_os("ORGANON_HOME") {
            Some(p) => PathBuf::from(p),
            None => user_home()
                .context("no home folder (set ORGANON_HOME)")?
                .join(".organon"),
        };
        Ok(Self { root })
    }

    pub fn policy_path(&self) -> PathBuf {
        self.root.join("policy.json")
    }

    /// The policy file if there is one, else the built-in default. Either way the built-in
    /// approval-class rules apply too (see [`Policy::with_floor`]): a policy file written by an
    /// older organon, or edited, still asks before a push to `main`.
    pub fn policy(&self) -> Result<(Policy, bool)> {
        let builtin = Policy::from_json(DEFAULT).context("built-in policy")?;
        let path = self.policy_path();
        if path.exists() {
            let text =
                fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
            let p = Policy::from_json(&text)
                .with_context(|| format!("{} is not a valid policy", path.display()))?;
            Ok((p.with_floor(&builtin), true))
        } else {
            Ok((builtin, false))
        }
    }

    fn tasks_dir(&self) -> PathBuf {
        self.root.join("tasks")
    }

    pub fn task_dir(&self, slug: &str) -> PathBuf {
        self.tasks_dir().join(slug)
    }

    /// A slug not used by any task yet.
    pub fn free_slug(&self, base: &str) -> String {
        (1..)
            .map(|i| {
                if i == 1 {
                    base.to_owned()
                } else {
                    format!("{base}-{i}")
                }
            })
            .find(|s| !self.task_dir(s).exists())
            .expect("an unbounded search finds a free name")
    }

    pub fn save_task(&self, t: &Task) -> Result<()> {
        let dir = self.task_dir(&t.slug);
        fs::create_dir_all(&dir)?;
        write_json(&dir.join("task.json"), t)
    }

    pub fn load_task(&self, slug: &str) -> Result<Task> {
        let p = self.task_dir(slug).join("task.json");
        let text = fs::read_to_string(&p).with_context(|| format!("no task '{slug}'"))?;
        serde_json::from_str(&text).with_context(|| format!("reading {}", p.display()))
    }

    /// Every task, oldest first.
    pub fn tasks(&self) -> Vec<Task> {
        let mut v: Vec<Task> = fs::read_dir(self.tasks_dir())
            .into_iter()
            .flatten()
            .flatten()
            .filter_map(|e| fs::read_to_string(e.path().join("task.json")).ok())
            .filter_map(|t| serde_json::from_str(&t).ok())
            .collect();
        v.sort_by(|a: &Task, b| a.started.cmp(&b.started));
        v
    }

    /// Open tasks, newest first.
    pub fn open_tasks(&self) -> Vec<Task> {
        self.tasks()
            .into_iter()
            .rev()
            .filter(Task::is_open)
            .collect()
    }

    /// The open task a command belongs to. Run in an agent session (`own` is its transcript):
    /// that session's task, else an open task no session claims; never another session's.
    /// Run outside one: the open task, if exactly one is open.
    pub fn current_task(&self, own: Option<&str>) -> Option<Task> {
        let open = self.open_tasks();
        match own {
            Some(transcript) => open
                .iter()
                .find(|t| t.metered_in(transcript))
                .or_else(|| open.iter().find(|t| t.meter.is_none()))
                .cloned(),
            None if open.len() == 1 => open.into_iter().next(),
            None => None,
        }
    }

    /// The most recently started open task of the session with this transcript.
    pub fn active_task_in(&self, transcript: &str) -> Option<Task> {
        self.tasks()
            .into_iter()
            .rev()
            .find(|t| t.is_open() && t.metered_in(transcript))
    }

    pub fn append_event(&self, slug: &str, e: &Event) -> Result<()> {
        append_line(
            &self.task_dir(slug).join("trail.jsonl"),
            &serde_json::to_string(e)?,
        )
    }

    pub fn trail(&self, slug: &str) -> Vec<Event> {
        fs::read_to_string(self.task_dir(slug).join("trail.jsonl"))
            .unwrap_or_default()
            .lines()
            .filter_map(|l| serde_json::from_str(l).ok())
            .collect()
    }

    fn sessions_dir(&self) -> PathBuf {
        self.root.join("sessions")
    }

    /// Note that the hook saw this session now. Each session has its own file, so hooks of
    /// parallel sessions never write the same file. (They used to share `session.json`, and
    /// whichever hook ran last decided which session `organon task new` metered.)
    pub fn record_session(&self, id: &str, transcript: &str, cwd: &str, now: i64) -> Result<()> {
        let id = if id.is_empty() {
            // No id given: the transcript's file name is Claude Code's session id.
            Path::new(transcript)
                .file_stem()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_default()
        } else {
            id.to_owned()
        };
        if id.is_empty() {
            return Ok(());
        }
        let dir = self.sessions_dir();
        fs::create_dir_all(&dir)?;
        let path = dir.join(session_file_name(&id));
        let first_seen = self.session_record(&id).map_or(now, |r| r.first_seen);
        write_json(
            &path,
            &SessionRecord {
                session_id: id,
                transcript: transcript.to_owned(),
                cwd: cwd.to_owned(),
                first_seen,
                last_seen: now,
            },
        )
    }

    pub fn session_record(&self, id: &str) -> Option<SessionRecord> {
        let text = fs::read_to_string(self.sessions_dir().join(session_file_name(id))).ok()?;
        serde_json::from_str(&text).ok()
    }

    /// Every session the hook has seen, most recently seen first.
    pub fn sessions(&self) -> Vec<SessionRecord> {
        let mut v: Vec<SessionRecord> = fs::read_dir(self.sessions_dir())
            .into_iter()
            .flatten()
            .flatten()
            .filter(|e| e.path().extension().is_some_and(|x| x == "json"))
            .filter_map(|e| fs::read_to_string(e.path()).ok())
            .filter_map(|t| serde_json::from_str(&t).ok())
            .collect();
        v.sort_by_key(|r: &SessionRecord| std::cmp::Reverse(r.last_seen));
        v
    }

    pub fn config(&self) -> Config {
        fs::read_to_string(self.root.join("config.json"))
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok())
            .unwrap_or_default()
    }

    pub fn save_config(&self, c: &Config) -> Result<()> {
        fs::create_dir_all(&self.root)?;
        write_json(&self.root.join("config.json"), c)
    }

    /// The memory folder: the configured one, else `$MNEME_ROOT`.
    pub fn memory(&self) -> Option<PathBuf> {
        self.config()
            .memory
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("MNEME_ROOT").map(PathBuf::from))
    }

    pub fn episodes_path(&self) -> PathBuf {
        self.root.join("episodes.jsonl")
    }
}

/// Write through a temporary file named after this process, then rename: two processes
/// writing the same file at once each rename a whole file, and neither reads half of one.
pub fn write_json(path: &Path, v: &impl Serialize) -> Result<()> {
    let tmp = path.with_extension(format!("tmp-{}", std::process::id()));
    fs::write(&tmp, serde_json::to_string_pretty(v)? + "\n")?;
    fs::rename(&tmp, path).with_context(|| format!("writing {}", path.display()))
}

pub fn append_line(path: &Path, line: &str) -> Result<()> {
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)?;
    }
    let mut f = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("opening {}", path.display()))?;
    writeln!(f, "{line}")?;
    Ok(())
}

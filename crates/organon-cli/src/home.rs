//! organon's own folder (`~/.organon`, or `$ORGANON_HOME`): policy, tasks, episodes, and a
//! pointer to the agent session the hook last saw.

use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use organon_core::policy::{Policy, DEFAULT};
use organon_core::task::{Event, Task};

pub struct Home {
    pub root: PathBuf,
}

/// The agent session the hook saw last.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionPointer {
    pub transcript: String,
    #[serde(default)]
    pub session_id: String,
    #[serde(default)]
    pub cwd: String,
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

    /// The policy file if there is one, else the built-in default.
    pub fn policy(&self) -> Result<(Policy, bool)> {
        let path = self.policy_path();
        if path.exists() {
            let text =
                fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
            let p = Policy::from_json(&text)
                .with_context(|| format!("{} is not a valid policy", path.display()))?;
            Ok((p, true))
        } else {
            Ok((
                Policy::from_json(DEFAULT).context("built-in policy")?,
                false,
            ))
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

    /// The most recently started open task.
    pub fn active_task(&self) -> Option<Task> {
        self.tasks().into_iter().rev().find(Task::is_open)
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

    pub fn session(&self) -> Option<SessionPointer> {
        let text = fs::read_to_string(self.root.join("session.json")).ok()?;
        serde_json::from_str(&text).ok()
    }

    /// Written on every hook call, so the session whose hook ran last is the one that just
    /// called organon (`organon task new` meters the session that ran it).
    pub fn save_session(&self, s: &SessionPointer) -> Result<()> {
        fs::create_dir_all(&self.root)?;
        write_json(&self.root.join("session.json"), s)
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

pub fn write_json(path: &Path, v: &impl Serialize) -> Result<()> {
    let tmp = path.with_extension("tmp");
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

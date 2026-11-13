//! Finding the organs: like git subcommands, an organ is an executable on PATH named
//! `organon-<organ>`; the memory is `mneme` (or `$ORGANON_MEMORY`). Replacing an organ is
//! putting another program with that name first on PATH.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::Command;

pub struct Organ {
    pub name: String,
    pub path: PathBuf,
    pub version: Option<String>,
}

pub fn memory_name() -> String {
    std::env::var("ORGANON_MEMORY").unwrap_or_else(|_| "mneme".into())
}

/// Whether a program name is one of ours.
pub fn is_organ(program: &str) -> bool {
    program.starts_with("organon-") || program == memory_name() || program == "organon"
}

/// Every organ on PATH (the first of each name wins, as the shell would pick it).
pub fn discover() -> Vec<Organ> {
    let memory = memory_name();
    let mut found: BTreeMap<String, PathBuf> = BTreeMap::new();
    for dir in std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default()) {
        for e in std::fs::read_dir(&dir).into_iter().flatten().flatten() {
            let path = e.path();
            let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else {
                continue;
            };
            let exe = path.extension().is_none_or(|x| x == "exe");
            if exe && (stem.starts_with("organon-") || stem == memory) && path.is_file() {
                found.entry(stem.to_owned()).or_insert(path);
            }
        }
    }
    found
        .into_iter()
        .map(|(name, path)| {
            let version = Command::new(&path)
                .arg("--version")
                .output()
                .ok()
                .filter(|o| o.status.success())
                .and_then(|o| {
                    String::from_utf8_lossy(&o.stdout)
                        .split_whitespace()
                        .last()
                        .map(str::to_owned)
                });
            Organ {
                name,
                path,
                version,
            }
        })
        .collect()
}

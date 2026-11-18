//! The one git fact the policy needs: which branch a folder has checked out, so a bare
//! `git push` on `main` is seen as a push to `main`. Read from `.git/HEAD` (no git process).

use organon_core::policy::Inherited;
use std::fs;
use std::path::{Path, PathBuf};

/// The branch checked out in `dir` (or the repository above it), if any. Follows the
/// `.git` file of a worktree to its own `HEAD`. `None` on a detached `HEAD` or outside a
/// repository.
pub fn branch_in(dir: &Path) -> Option<String> {
    let git_dir = git_dir(dir)?;
    let head = fs::read_to_string(git_dir.join("HEAD")).ok()?;
    head.trim()
        .strip_prefix("ref: refs/heads/")
        .map(str::to_owned)
}

/// The root folder of the repository (or worktree) `dir` is in, with forward slashes.
/// Used to apply the policy's exceptions.
pub fn repo_root(dir: &Path) -> Option<String> {
    // The physical folder: through symlinks and junctions, so a link into another
    // repository is judged by where it leads. A folder that does not exist, or cannot be
    // resolved, names no repository (never the one above it).
    let real = fs::canonicalize(dir).ok().filter(|d| d.is_dir())?;
    real.ancestors()
        .find(|a| a.join(".git").exists())
        .map(|a| plain_path(&a.to_string_lossy()))
}

/// A path without Windows' verbatim prefix (`\\?\C:\x` → `C:/x`), with forward slashes.
fn plain_path(p: &str) -> String {
    let p = if let Some(unc) = p.strip_prefix(r"\\?\UNC\") {
        format!(r"\\{unc}")
    } else {
        p.strip_prefix(r"\\?\").unwrap_or(p).to_owned()
    };
    p.replace('\\', "/")
}

fn git_dir(dir: &Path) -> Option<PathBuf> {
    for a in dir.ancestors() {
        let dot = a.join(".git");
        if dot.is_dir() {
            return Some(dot);
        }
        if dot.is_file() {
            let text = fs::read_to_string(&dot).ok()?;
            let target = text.trim().strip_prefix("gitdir:")?.trim();
            return Some(a.join(target)); // `join` keeps an absolute target as it is
        }
    }
    None
}

/// The folder a command works in: the agent's `cwd`, moved by a `cd` or `git -C` in the
/// command (`hint`), relative to it unless absolute.
pub fn folder(cwd: &str, hint: Option<&str>) -> PathBuf {
    let base = if cwd.is_empty() {
        std::env::current_dir().unwrap_or_default()
    } else {
        PathBuf::from(cwd)
    };
    match hint {
        Some(h) => base.join(drive_path(h)),
        None => base,
    }
}

/// A Git Bash path (`/c/Users/x`) as the Windows path it names (`C:/Users/x`); any other
/// path unchanged. Elsewhere than Windows, every path is unchanged.
fn drive_path(p: &str) -> String {
    let b = p.as_bytes();
    if cfg!(windows)
        && b.len() >= 2
        && b[0] == b'/'
        && b[1].is_ascii_alphabetic()
        && (b.len() == 2 || b[2] == b'/')
    {
        format!(
            "{}:/{}",
            char::from(b[1]).to_ascii_uppercase(),
            p.get(3..).unwrap_or("")
        )
    } else {
        p.to_owned()
    }
}

/// What the shell a command will run in inherits, as far as it decides whether an exception
/// may lift a `gh` command: `GH_REPO` or `GH_HOST` in this process's environment, and the
/// files Claude Code sources before each command (the one `CLAUDE_ENV_FILE` names, and every
/// `*.sh` in `<claude config dir>/session-env/<session id>/`). `session_id` is the hook
/// event's; `None` (the `check` command) reads no session folder, and an empty or odd one
/// (anything but letters, digits, `-`, `_`) counts as unreadable.
pub fn inherited(session_id: Option<&str>) -> Inherited {
    let config = std::env::var_os("CLAUDE_CONFIG_DIR")
        .map(PathBuf::from)
        .or_else(|| crate::home::user_home().map(|h| h.join(".claude")));
    inherited_in(
        session_id,
        config.as_deref(),
        &|k| std::env::var_os(k),
        &|p| fs::read(p),
        &|d| {
            let mut out = Vec::new();
            for e in fs::read_dir(d)? {
                let p = e?.path();
                if p.extension().is_some_and(|x| x.eq_ignore_ascii_case("sh")) {
                    out.push(p);
                }
            }
            Ok(out)
        },
    )
}

type VarOf<'a> = &'a dyn Fn(&str) -> Option<std::ffi::OsString>;
type ReadFile<'a> = &'a dyn Fn(&Path) -> std::io::Result<Vec<u8>>;
type ListShell<'a> = &'a dyn Fn(&Path) -> std::io::Result<Vec<PathBuf>>;

fn inherited_in(
    session_id: Option<&str>,
    config_dir: Option<&Path>,
    var: VarOf<'_>,
    read: ReadFile<'_>,
    list: ListShell<'_>,
) -> Inherited {
    let mut out = Inherited {
        gh_target: ["GH_REPO", "GH_HOST"].iter().any(|k| var(k).is_some()),
        init_unsafe: false,
    };
    let mut files: Vec<PathBuf> = Vec::new();
    // Not created yet is fine for the one file; any other failure says nothing can be judged.
    let mut missing_ok: Vec<PathBuf> = Vec::new();
    if let Some(f) = var("CLAUDE_ENV_FILE").filter(|f| !f.is_empty()) {
        missing_ok.push(PathBuf::from(f));
    }
    if let Some(id) = session_id {
        let plain = !id.is_empty()
            && id
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
        match (plain, config_dir) {
            (true, Some(c)) => match list(&c.join("session-env").join(id)) {
                Ok(v) => files.extend(v),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => out.init_unsafe = true,
            },
            _ => out.init_unsafe = true,
        }
    }
    for (path, missing_is_fine) in files
        .iter()
        .map(|p| (p, false))
        .chain(missing_ok.iter().map(|p| (p, true)))
    {
        match read(path) {
            Ok(bytes) => {
                let (gh, unsafe_) = judge_shell_file(&String::from_utf8_lossy(&bytes));
                out.gh_target |= gh;
                out.init_unsafe |= unsafe_;
            }
            Err(e) if missing_is_fine && e.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => {
                // Unreadable: nothing can be said, so nothing is lifted.
                out.gh_target = true;
                out.init_unsafe = true;
            }
        }
    }
    out
}

/// What a file the shell sources says, read after deleting quotes, backslash, backtick and
/// caret (which the shell removes, so `GH_RE""PO` is `GH_REPO`) and lower-casing it: whether it
/// names `GH_REPO` or `GH_HOST`, and whether it does something its text cannot show
/// (`eval`, `source`, `.` sourcing, `${`, `$(`).
fn judge_shell_file(text: &str) -> (bool, bool) {
    let t: String = text
        .chars()
        .filter(|c| !matches!(c, '\'' | '"' | '\\' | '`' | '^'))
        .flat_map(char::to_lowercase)
        .collect();
    let gh = t.contains("gh_repo") || t.contains("gh_host");
    let cs: Vec<char> = t.chars().collect();
    let dot_command = cs.iter().enumerate().any(|(i, &c)| {
        c == '.'
            && cs.get(i + 1).is_some_and(|n| n.is_whitespace())
            && (i == 0 || cs[i - 1].is_whitespace() || ";&|(".contains(cs[i - 1]))
    });
    let unsafe_ = ["eval", "source", "${", "$("].iter().any(|w| t.contains(w)) || dot_command;
    (gh, unsafe_)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn what_the_shell_inherits_is_read_from_the_environment_and_its_files() {
        use std::collections::HashMap;
        use std::ffi::OsString;
        use std::io::{Error, ErrorKind};
        let cfg = Path::new("/cfg");
        let vars = |set: &[(&'static str, &'static str)]| {
            let set = set.to_vec();
            move |k: &str| {
                set.iter()
                    .find(|(n, _)| *n == k)
                    .map(|(_, v)| OsString::from(v))
            }
        };
        // A fake disk: file path -> text; a session-env folder lists its files.
        let disk = |files: &[(&'static str, &'static str)]| {
            let files: HashMap<PathBuf, &'static str> =
                files.iter().map(|(p, t)| (PathBuf::from(p), *t)).collect();
            let f2 = files.clone();
            (
                move |p: &Path| match files.get(p) {
                    Some(t) if *t == "DENIED" => Err(Error::new(ErrorKind::PermissionDenied, "no")),
                    Some(t) => Ok(t.as_bytes().to_vec()),
                    None => Err(Error::new(ErrorKind::NotFound, "no")),
                },
                move |d: &Path| {
                    let mut v: Vec<PathBuf> = f2
                        .keys()
                        .filter(|p| p.parent() == Some(d))
                        .cloned()
                        .collect();
                    v.sort();
                    Ok(v)
                },
            )
        };
        let run = |sid: Option<&str>,
                   env: &[(&'static str, &'static str)],
                   files: &[(&'static str, &'static str)]| {
            let (r, l) = disk(files);
            inherited_in(sid, Some(cfg), &vars(env), &r, &l)
        };
        let clean = Inherited::default();
        assert_eq!(run(Some("s"), &[], &[]), clean, "no folder, nothing set");
        assert_eq!(run(None, &[], &[]), clean);
        // The process environment.
        for v in ["GH_REPO", "GH_HOST"] {
            assert!(run(Some("s"), &[(v, "x")], &[]).gh_target, "{v}");
        }
        // The file CLAUDE_ENV_FILE names.
        let e = [("CLAUDE_ENV_FILE", "/tmp/env.sh")];
        let r = run(Some("s"), &e, &[("/tmp/env.sh", "export PATH=/x\n")]);
        assert_eq!(r, clean);
        let r = run(Some("s"), &e, &[("/tmp/env.sh", "export Gh_Repo=x/y\n")]);
        assert!(r.gh_target);
        let r = run(Some("s"), &e, &[("/tmp/env.sh", "export GH_RE\"\"PO=x\n")]);
        assert!(r.gh_target, "quotes are removed before reading");
        let r = run(Some("s"), &e, &[("/tmp/env.sh", "export GH_RE\\PO=x\n")]);
        assert!(r.gh_target, "backslash too");
        assert_eq!(run(Some("s"), &e, &[]), clean, "not created yet");
        let r = run(Some("s"), &e, &[("/tmp/env.sh", "DENIED")]);
        assert!(r.gh_target && r.init_unsafe, "unreadable: nothing lifted");
        assert_eq!(
            run(Some("s"), &[("CLAUDE_ENV_FILE", "")], &[("", "DENIED")]),
            clean
        );
        // The files in the session's folder.
        let sh = |text: &'static str| [("/cfg/session-env/s/hook-1.sh", text)];
        assert_eq!(run(Some("s"), &[], &sh("export PATH=/x\n")), clean);
        assert!(run(Some("s"), &[], &sh("export GH_REPO=x\n")).gh_target);
        assert!(run(Some("s"), &[], &sh("export GH_RE\"\"PO=x\n")).gh_target);
        assert!(run(Some("s"), &[], &sh("export GH_HOST=h\n")).gh_target);
        for text in [
            "eval \"$X\"\n",
            "ev\"\"al x\n",
            "source ./x.sh\n",
            "export A=${B}\n",
            "export A=$(date)\n",
            ". ./x.sh\n",
            "export A=1; . ./x.sh\n",
        ] {
            assert!(run(Some("s"), &[], &sh(text)).init_unsafe, "{text}");
        }
        for text in ["export A=1.5 B=x. y\n", "# a. note\n"] {
            assert_eq!(run(Some("s"), &[], &sh(text)), clean, "{text}");
        }
        // Another session's files are not read; an unreadable one, or a session id that cannot
        // name a folder, lifts nothing.
        let other = [("/cfg/session-env/other/hook-1.sh", "export GH_REPO=x\n")];
        assert_eq!(run(Some("s"), &[], &other), clean);
        let r = run(Some("s"), &[], &sh("DENIED"));
        assert!(r.gh_target && r.init_unsafe);
        for id in ["", "../x", "a/b", "a b"] {
            assert!(run(Some(id), &[], &[]).init_unsafe, "{id:?}");
        }
        assert!(!run(Some("s"), &[], &[]).init_unsafe);
        // No config folder known: a session's files cannot be found.
        let (r, l) = disk(&[]);
        assert!(inherited_in(Some("s"), None, &vars(&[]), &r, &l).init_unsafe);
    }

    #[test]
    fn git_bash_paths_name_windows_drives() {
        if cfg!(windows) {
            assert_eq!(drive_path("/c/Users/x"), "C:/Users/x");
            assert_eq!(drive_path("/d"), "D:/");
        } else {
            assert_eq!(drive_path("/c/Users/x"), "/c/Users/x");
        }
        assert_eq!(drive_path("/usr/bin"), "/usr/bin");
        assert_eq!(drive_path("relative/x"), "relative/x");
    }

    #[test]
    fn finds_the_root_of_a_repository() {
        let root = std::env::temp_dir().join(format!("organon-root-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("repo").join(".git")).unwrap();
        fs::create_dir_all(root.join("repo").join("a").join("b")).unwrap();
        let real = |p: &Path| plain_path(&fs::canonicalize(p).unwrap().to_string_lossy());
        let want = real(&root.join("repo"));
        assert_eq!(
            repo_root(&root.join("repo").join("a").join("b")),
            Some(want.clone())
        );
        assert!(!want.starts_with(r"\\?") && !want.contains('\\'));
        assert_eq!(repo_root(&root.join("elsewhere")), None);
        assert_eq!(
            repo_root(&root.join("repo").join("$OTHER")),
            None,
            "missing folder"
        );

        // A link inside one repository that leads into another is judged by its target.
        fs::create_dir_all(root.join("other").join(".git")).unwrap();
        fs::create_dir_all(root.join("other").join("src")).unwrap();
        let link = root.join("repo").join("link");
        #[cfg(unix)]
        let made = std::os::unix::fs::symlink(root.join("other").join("src"), &link).is_ok();
        #[cfg(windows)]
        let made = std::os::windows::fs::symlink_dir(root.join("other").join("src"), &link).is_ok();
        if made {
            assert_eq!(repo_root(&link), Some(real(&root.join("other"))));
        } else {
            eprintln!("skipped the link case: this account cannot create symlinks");
        }
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn reads_the_branch_of_a_repo_and_of_a_worktree() {
        let root = std::env::temp_dir().join(format!("organon-git-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let repo = root.join("repo");
        fs::create_dir_all(repo.join(".git").join("worktrees").join("wt")).unwrap();
        fs::create_dir_all(repo.join("src")).unwrap();
        fs::write(repo.join(".git").join("HEAD"), "ref: refs/heads/main\n").unwrap();
        let wt_git = repo.join(".git").join("worktrees").join("wt");
        fs::write(wt_git.join("HEAD"), "ref: refs/heads/feature/x\n").unwrap();
        let wt = root.join("wt");
        fs::create_dir_all(&wt).unwrap();
        fs::write(wt.join(".git"), format!("gitdir: {}\n", wt_git.display())).unwrap();

        assert_eq!(branch_in(&repo).as_deref(), Some("main"));
        assert_eq!(branch_in(&repo.join("src")).as_deref(), Some("main"));
        assert_eq!(branch_in(&wt).as_deref(), Some("feature/x"));
        fs::write(repo.join(".git").join("HEAD"), "0123abcd\n").unwrap();
        assert_eq!(branch_in(&repo), None, "detached");
        let _ = fs::remove_dir_all(&root);
    }
}

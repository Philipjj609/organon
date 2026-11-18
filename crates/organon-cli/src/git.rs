//! The one git fact the policy needs: which branch a folder has checked out, so a bare
//! `git push` on `main` is seen as a push to `main`. Read from `.git/HEAD` (no git process).

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

/// Whether the environment a command will run in could point `gh` at another repository or
/// host than its folder's: `GH_REPO` or `GH_HOST` is set in this process (a session inherits
/// it), or the file named by `CLAUDE_ENV_FILE` (Claude Code sources it before each command)
/// mentions either. A file that is set but cannot be read for another reason than not
/// existing yet counts as yes: nothing can be said about it, so nothing is lifted.
pub fn gh_target_in_environment() -> bool {
    gh_target_in(&|k| std::env::var_os(k), &|p| fs::read(p))
}

fn gh_target_in(
    var: &dyn Fn(&str) -> Option<std::ffi::OsString>,
    read: &dyn Fn(&Path) -> std::io::Result<Vec<u8>>,
) -> bool {
    if ["GH_REPO", "GH_HOST"].iter().any(|k| var(k).is_some()) {
        return true;
    }
    let Some(file) = var("CLAUDE_ENV_FILE").filter(|f| !f.is_empty()) else {
        return false;
    };
    match read(Path::new(&file)) {
        Ok(bytes) => {
            let text = String::from_utf8_lossy(&bytes).to_lowercase();
            text.contains("gh_repo") || text.contains("gh_host")
        }
        Err(e) => e.kind() != std::io::ErrorKind::NotFound,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_environment_can_name_the_target_of_gh() {
        use std::ffi::OsString;
        use std::io::{Error, ErrorKind};
        let vars = |set: &[(&'static str, &'static str)]| {
            let set = set.to_vec();
            move |k: &str| {
                set.iter()
                    .find(|(n, _)| *n == k)
                    .map(|(_, v)| OsString::from(v))
            }
        };
        let file = |text: &'static str| move |_: &Path| Ok(text.as_bytes().to_vec());
        let never = |_: &Path| Err(Error::new(ErrorKind::NotFound, "no"));
        assert!(!gh_target_in(&vars(&[]), &never));
        assert!(gh_target_in(&vars(&[("GH_REPO", "x/y")]), &never));
        assert!(gh_target_in(&vars(&[("GH_HOST", "h")]), &never));
        let f = vars(&[("CLAUDE_ENV_FILE", "/tmp/env.sh")]);
        assert!(!gh_target_in(
            &f,
            &file(
                "export PATH=/x
"
            )
        ));
        assert!(gh_target_in(
            &f,
            &file(
                "export Gh_Repo=x/y
"
            )
        ));
        assert!(gh_target_in(
            &f,
            &file(
                "export GH_HOST=h
"
            )
        ));
        assert!(!gh_target_in(&f, &never), "not created yet");
        let denied = |_: &Path| Err(Error::new(ErrorKind::PermissionDenied, "no"));
        assert!(gh_target_in(&f, &denied), "unreadable: nothing lifted");
        assert!(!gh_target_in(&vars(&[("CLAUDE_ENV_FILE", "")]), &denied));
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

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
        Some(h) => base.join(h),
        None => base,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

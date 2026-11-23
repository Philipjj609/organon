//! The one git fact the policy needs: which branch a folder has checked out, so a bare
//! `git push` on `main` is seen as a push to `main`. Read from `.git/HEAD` (no git process).

use organon_core::policy::{env_name_allowed, Inherited};
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

/// The repository root of `dir` as [`repo_root`] finds it, or else the physical folder itself:
/// a folder that is not in a repository (such as `~/.ergon`) can still be in a territory.
pub fn root_or_folder(dir: &Path) -> Option<String> {
    repo_root(dir).or_else(|| {
        fs::canonicalize(dir)
            .ok()
            .filter(|d| d.is_dir())
            .map(|d| plain_path(&d.to_string_lossy()))
    })
}

/// The URL git itself gives the `origin` remote of the repository (or worktree) whose root
/// folder is `root` (`git remote get-url origin`: includes and `insteadOf` rewrites applied,
/// which no reading of the config file by hand gets right). `None` when there is no `origin`,
/// git is not there or fails. Variables that point git at another repository are removed.
pub fn origin_url(root: &str) -> Option<String> {
    let mut git = std::process::Command::new("git");
    git.args(["-C", root, "remote", "get-url", "origin"])
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    for var in [
        "GIT_DIR",
        "GIT_WORK_TREE",
        "GIT_COMMON_DIR",
        "GIT_CONFIG_COUNT",
        "GIT_CONFIG_PARAMETERS",
    ] {
        git.env_remove(var);
    }
    let out = git.output().ok().filter(|o| o.status.success())?;
    let url = String::from_utf8(out.stdout).ok()?;
    let url = url.trim();
    (!url.is_empty() && !url.contains('\n')).then(|| url.to_owned())
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
/// (anything but letters, digits, `-`, `_`) counts as unreadable. `allowed_names` is the
/// policy's `merge_env_names`: the variables those files may set. Only `GH_REPO` and `GH_HOST`
/// are looked for in this process's own environment; other variables in Claude Code's own
/// environment are out of scope.
pub fn inherited(session_id: Option<&str>, allowed_names: &[String]) -> Inherited {
    let config = std::env::var_os("CLAUDE_CONFIG_DIR")
        .map(PathBuf::from)
        .or_else(|| crate::home::user_home().map(|h| h.join(".claude")));
    inherited_in(
        session_id,
        config.as_deref(),
        allowed_names,
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
    allowed: &[String],
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
                // Anything not provably harmless may steer `gh`: nothing is lifted.
                if judge_shell_file(&String::from_utf8_lossy(&bytes), allowed) {
                    out.gh_target = true;
                    out.init_unsafe = true;
                }
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

/// Whether a file the shell sources before each command is NOT provably harmless.
///
/// This is an allow-list over the raw text, not a search for bad words: a shell has more ways
/// to steer `gh` (a split name, a variable, a function, an alias, `PATH`, `GIT_DIR`, git
/// config, arithmetic on a special variable) than any list of them can hold, so a file is safe
/// only if every line is one of these, and anything else, anywhere, makes the whole file
/// unsafe:
/// - the line (minus one trailing `\r`) is blank, or a comment (spaces, `#`, any text);
/// - or it is `NAME=VALUE` or `export NAME=VALUE` and nothing else, where `NAME` is
///   `[A-Za-z_][A-Za-z0-9_]*` and passes [`env_name_allowed`]: it matches one of `allowed`
///   (the policy's `merge_env_names`, empty by default, so no assignment passes) and is not
///   one of the barred names and prefixes kept in `organon_core::policy`, a second guard that
///   is deliberately not claimed to be complete;
/// - and `VALUE` is plain (`[A-Za-z0-9_./:@,+=-]*`), or one pair of double quotes, or one pair
///   of single quotes, around those characters and spaces: no `$`, backtick, `;`, `&`, `|`, `(`,
///   `{`, `<` or `>`;
/// - and the file has no backslash and no control character other than the line ends.
///
/// An empty file is safe.
fn judge_shell_file(text: &str, allowed: &[String]) -> bool {
    const PLAIN: &str = "_./:@,+=-";
    let plain = |c: char| c.is_ascii_alphanumeric() || PLAIN.contains(c);
    let value_ok = |v: &str| {
        if let Some(q) = v.chars().next().filter(|c| matches!(c, '"' | '\'')) {
            v.len() >= 2
                && v.ends_with(q)
                && v[1..v.len() - 1].chars().all(|c| plain(c) || c == ' ')
        } else {
            v.chars().all(plain)
        }
    };
    let name_ok = |n: &str| {
        let mut cs = n.chars();
        cs.next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
            && cs.all(|c| c.is_ascii_alphanumeric() || c == '_')
            && env_name_allowed(allowed, n)
    };
    if text.contains('\\') {
        return true;
    }
    let line_ok = |line: &str| {
        if line.chars().any(char::is_control) {
            return false;
        }
        if line.trim_start_matches(' ').is_empty() || line.trim_start_matches(' ').starts_with('#')
        {
            return true;
        }
        let assignment = line.strip_prefix("export ").unwrap_or(line);
        assignment
            .split_once('=')
            .is_some_and(|(n, v)| name_ok(n) && value_ok(v))
    };
    !text
        .split('\n')
        .all(|line| line_ok(line.strip_suffix('\r').unwrap_or(line)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn git(dir: &Path, args: &[&str]) {
        let ok = std::process::Command::new("git")
            .arg("-C")
            .arg(dir)
            .args(args)
            .status()
            .unwrap()
            .success();
        assert!(ok, "git {args:?}");
    }

    #[test]
    fn the_origin_url_is_what_git_says() {
        let root = std::env::temp_dir().join(format!("organon-origin-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let main = root.join("main");
        fs::create_dir_all(&main).unwrap();
        git(&main, &["init", "-q"]);
        let path = |p: &Path| plain_path(&p.to_string_lossy());
        assert_eq!(origin_url(&path(&main)), None, "no origin");
        git(
            &main,
            &["remote", "add", "origin", "git@github.com:O/R.git"],
        );
        assert_eq!(
            origin_url(&path(&main)).as_deref(),
            Some("git@github.com:O/R.git")
        );
        // `insteadOf` rewrites are applied, as `gh` sees them.
        git(
            &main,
            &[
                "config",
                "url.https://github.com/Other/Thing.git.insteadOf",
                "git@github.com:O/R.git",
            ],
        );
        assert_eq!(
            origin_url(&path(&main)).as_deref(),
            Some("https://github.com/Other/Thing.git")
        );
        let _ = fs::remove_dir_all(&root);
    }

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
        // What a policy's `merge_env_names` might list for these files.
        let allowed_names = || -> Vec<String> {
            [
                "VERCEL_PLUGIN_*",
                "FOO",
                "A",
                "B",
                "C",
                "D",
                "E",
                "PATHX",
                "GHX",
                "GITX",
                "MYHOME",
            ]
            .map(String::from)
            .to_vec()
        };
        let run = |sid: Option<&str>,
                   env: &[(&'static str, &'static str)],
                   files: &[(&'static str, &'static str)]| {
            let (r, l) = disk(files);
            let allowed = allowed_names();
            inherited_in(sid, Some(cfg), &allowed, &vars(env), &r, &l)
        };
        let clean = Inherited::default();
        assert_eq!(run(Some("s"), &[], &[]), clean, "no folder, nothing set");
        assert_eq!(run(None, &[], &[]), clean);
        // The process environment.
        for v in ["GH_REPO", "GH_HOST"] {
            assert!(run(Some("s"), &[(v, "x")], &[]).gh_target, "{v}");
        }
        // What makes a file unsafe, and what does not: the same text in the file CLAUDE_ENV_FILE
        // names and in a session-env `*.sh`.
        let harmless = [
            "",
            "\n\n",
            "export VERCEL_PLUGIN_BOOTSTRAP_HINTS=\"greenfield\"\nexport VERCEL_PLUGIN_SETUP_MODE=\"1\"\n",
            "export VERCEL_PLUGIN_SETUP_MODE=\"1\"\r\nFOO=bar\r\n",
            "# a note: gh_repo $x `y` (z); a.\n   # indented\n\nA=1.5\nexport B=x/y:z@w,v+u=t-s\nC=\nD='a b'\nE=\"a b\"\n",
            "export A=1",
            // U+2028 is no line end for the shell: still one comment.
            "# a\u{2028}export GH_REPO=x\n",
            "export PATHX=1\nexport GHX=1\nexport GITX=1\nexport MYHOME=1\n",
        ];
        let unsafe_files = [
            // a name split across lines, and the rest of the steering
            "export GH_\\\nREPO=Philipjj609/Koda\n",
            "export GH_\\\nHOST=h\n",
            "export GH_\\\r\nREPO=x\r\n",
            "export GH_REPO=x\n",
            "export Gh_Repo=x/y\n",
            "export gh_host=h\n",
            "export GH_RE\"\"PO=x\n",
            "export GH_RE\\PO=x\n",
            "export GIT_DIR=C:/x/other/.git\n",
            "export GIT_CONFIG_COUNT=1\n",
            "export XDG_CONFIG_HOME=/x\n",
            "export PATH=/tmp/evil:/usr/bin\n",
            "PATH=/x\n",
            "export path=/x\n",
            "export HOME=/x\n",
            "export USERPROFILE=/x\n",
            "export APPDATA=/x\n",
            "export LOCALAPPDATA=/x\n",
            "export BASH_ENV=/x\n",
            "export ENV=/x\n",
            "export PROMPT_COMMAND=x\n",
            "export SHELLOPTS=x\n",
            "export BASHOPTS=x\n",
            "export IFS=x\n",
            "export PS4=x\n",
            "export CDPATH=x\n",
            "gh() { command gh -R o/other pr merge 7 --squash; }\n",
            "alias gh=x\n",
            "export A=1; export GH_REPO=x\n",
            "export A=\"x\" B=y\n",
            "export A=x B=y\n",
            "export A=1.5 B=x. y\n",
            "export A=$B\n",
            "export A=${B}\n",
            "export A=$(date)\n",
            "export A=`date`\n",
            "export A='$B'\n",
            "export A=\"$B\"\n",
            "X=H_REPO\nexport G$X=o/other\n",
            "eval \"$X\"\n",
            "source ./x.sh\n",
            ". ./x.sh\n",
            "export A=1 && echo\n",
            "export A=1|x\n",
            "export A=(x)\n",
            "export A={x}\n",
            "export A=<x\n",
            "export A=>x\n",
            "export A=1 # trailing\n",
            "export A=\"x\"y\n",
            "export A=\"x\n",
            "export A=\"\n",
            "export A=\"a\"b\"\n",
            "export A\n",
            "export =1\n",
            "export 1A=1\n",
            "export  A=1\n",
            " export A=1\n",
            " A=1\n",
            "A =1\n",
            "export A=1 \n",
            "# comment with a backslash \\\n",
            "export A=1\r\r\n",
            "export A=1\rexport B=2\n",
            "export A=1\t\n",
            "# tab\tin a comment\n",
            "export A=\u{0}\n",
            "export A=\u{1b}[0m\n",
            // Names the policy does not list, however harmless they look.
            "export XYZ=1\n",
            "export vercel_plugin=1\n",
            "export VERCEL_PLUGINX=1\n",
            // Pinned: a quote inside quotes, a BOM, non-ASCII, a bare `=1`.
            "export A=\"it's\"\n",
            "export A='say \"x\"'\n",
            "\u{feff}export A=1\n",
            "export A=caf\u{e9}\n",
            "export \u{e9}A=1\n",
            "=1\n",
        ];
        let e = [("CLAUDE_ENV_FILE", "/tmp/env.sh")];
        let sh = |text: &'static str| [("/cfg/session-env/s/hook-1.sh", text)];
        for text in harmless {
            assert_eq!(
                run(Some("s"), &e, &[("/tmp/env.sh", text)]),
                clean,
                "{text:?}"
            );
            assert_eq!(run(Some("s"), &[], &sh(text)), clean, "{text:?}");
        }
        for text in unsafe_files {
            let r = run(Some("s"), &e, &[("/tmp/env.sh", text)]);
            assert!(r.gh_target && r.init_unsafe, "CLAUDE_ENV_FILE: {text:?}");
            let r = run(Some("s"), &[], &sh(text));
            assert!(r.gh_target && r.init_unsafe, "session-env: {text:?}");
        }
        assert_eq!(run(Some("s"), &e, &[]), clean, "not created yet");
        let r = run(Some("s"), &e, &[("/tmp/env.sh", "DENIED")]);
        assert!(r.gh_target && r.init_unsafe, "unreadable: nothing lifted");
        assert_eq!(
            run(Some("s"), &[("CLAUDE_ENV_FILE", "")], &[("", "DENIED")]),
            clean
        );
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
        assert!(inherited_in(Some("s"), None, &[], &vars(&[]), &r, &l).init_unsafe);
    }

    #[test]
    fn a_barred_name_is_unsafe_even_when_the_allow_list_would_match_it() {
        // `judge_shell_file` does not validate the list (the policy does at load): here the
        // list is as broad as it can be, to show the barred names are a second guard.
        let broad: Vec<String> = [
            "*", "*_*", "O*", "E*", "L*", "D*", "P*", "H*", "G*", "S*", "R*",
        ]
        .map(String::from)
        .to_vec();
        for line in [
            "export OPTIND=PATH=0",
            "OPTIND=PATH=0",
            "export EXECIGNORE=x",
            "export LD_PRELOAD=/x/y.so",
            "export LD_LIBRARY_PATH=/x",
            "export LD_AUDIT=/x",
            "export DYLD_INSERT_LIBRARIES=/x",
            "export GCONV_PATH=/x",
            "export PATHEXT=.EXE",
            "export HTTPS_PROXY=http://x",
            "export http_proxy=http://x",
            "export ALL_PROXY=x",
            "export SSL_CERT_FILE=/x",
            "export SSL_CERT_DIR=/x",
            "export GITHUB_TOKEN=x",
            "export GITHUB_ENTERPRISE_TOKEN=x",
            "export RANDOM=1",
            "export SECONDS=1",
            "export LINENO=1",
            "export HISTCMD=1",
            "export BASH_ARGV0=x",
            "export BASH_ENV=x",
            "export PATH=x",
            "export GH_REPO=o/r",
            "export GIT_DIR=x",
            "export NODE_OPTIONS=x",
        ] {
            let text = format!("{line}\n");
            assert!(judge_shell_file(&text, &broad), "{line}");
            assert!(judge_shell_file(&text, &[]), "{line}: empty list");
        }
        // A listed, unbarred name passes; the same line with an empty list does not.
        let vercel = ["VERCEL_PLUGIN_*".to_string()];
        let text = "export VERCEL_PLUGIN_SETUP_MODE=\"greenfield\"\n";
        assert!(!judge_shell_file(text, &vercel));
        assert!(judge_shell_file(text, &[]));
        assert!(
            !judge_shell_file("# only a comment\n\n", &[]),
            "no assignment: fine"
        );
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

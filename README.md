# organon

**One living intelligence, built from organs you can use, replace and improve one at a time.**

*organon* (Greek: instrument, organ; Aristotle's name for the tools of knowing) is the umbrella of a family of repositories. Each organ is its own repo, useful on its own, and speaks one shared protocol. This repo holds the architecture, the protocol, the standard every organ follows, and the `organon` binary that coordinates them.

> Living document. Every page has a **status** and **open questions**. Decisions are also recorded as claims in the memory (`project:organon`), so the "why" survives.

## The shape

Like a body: the eye doesn't see. It turns light into signal. Seeing happens further in. So three levels are kept apart:

| Level | Does | Never does | Output |
|---|---|---|---|
| **Sense** | Gets the raw signal: downloads, captions, audio, frames, pages | interpret | `Source` (bytes + metadata, hashed) |
| **Perception** | Extracts modality features: transcript segments, scene cuts, key frames, on-screen text, speakers, beats, palette | decide what it *means* | `Observation`s (typed, timestamped, located) |
| **Comprehension** | Decides what the observations mean, cross-checks them against memory, writes claims | (it's the only level that interprets) | `Proposal`s → claims in memory |

Around comprehension sit **memory** (what is known, with provenance and history), **research** (finding out what isn't known, systematically), **learning** (getting better from what happened), and the **intelligence** that coordinates them within a budget. **Expression** (diagrams, briefings) comes after these, because it depends on all of them.

## The organs

| Repo | Organ | Role | Status |
|---|---|---|---|
| [mneme](https://github.com/Philipjj609/mneme) | Memory | Claim log with provenance, git-like history, frames of understanding, recall | working (v0) |
| organon *(this)* | Intelligence + spec | Architecture, protocol, repo standard; the `organon` binary: session brief, tasks with budgets, measured spend, a policy hook for coding agents, two-tier routes, audit before memory | working (v0.1) |
| [organon-protocol](https://github.com/Philipjj609/organon-protocol) | Shared language | `Source`, `Observation`, `Claim`, `Proposal`, `Episode` types, JSON Schema, conformance fixtures | working (v0.1) |
| [organon-video](https://github.com/Philipjj609/organon-video) | Sense + perception: video | URL/file → transcript, keyframes measured (ink, repeats), moments with ★ where to look, index to read first; frames on demand; protocol messages for memory | working (v0.1) |
| [organon-research](https://github.com/Philipjj609/organon-research) | Research | Ledger of a run; keyless search + agent web search; triage with reasons; every quoted passage verified in the source; independent voices counted; challenge, saturation, export to memory | working (v0.1) |
| [organon-learning](https://github.com/Philipjj609/organon-learning) | Learning | Recall evaluated against rated and used questions; priors adopted only through a leave-one-out gate; frame slots proposed from use; hygiene (duplicates, stale, thin hubs) | working (v0.1) |
| [organon-sound](https://github.com/Philipjj609/organon-sound) | Sense + perception: sound | File, URL or organon-video folder (same source id) → transcript segments (ffmpeg's whisper filter), music spans with tempo and key, sound events (silence, whisper's annotations, YAMNet in tract); measures behind every music decision | working (v0.1) |
| [organon-vision](https://github.com/Philipjj609/organon-vision) | Sense + perception: images | File or URL → text lines and words (ocrs, pure Rust), layout blocks (text by alignment with line heights, figures from busy tiles), dominant palette (k-means in Lab), objects (YOLO on RTen when a model is present); regions in pixels; image measures shared with organon-video | working (v0.1) |
| [organon-text](https://github.com/Philipjj609/organon-text) | Sense + perception: text | Web pages (Readability → Markdown, sections located), X posts and accounts, GitHub repos + README sections, HF datasets, PDFs (pages located); took over mneme's link capture with the same anchor ids | working (v0.1) |
| [organon-express](https://github.com/Philipjj609/organon-express) | Expression | Briefings from memory: a diagram first (anchor → frame slots → linked anchors, unknown slots dashed), short text, levels to drill into, every statement citing its claim; Markdown + Mermaid and one self-contained HTML page | working (v0.1) |

## The intelligence (`organon`)

```bash
cargo install --git https://github.com/Philipjj609/organon organon
organon init --memory ~/my-memory   # policy file, memory folder, and the Claude Code hook snippet
organon brief                       # start of a session: organs, memory, spend, open task, routes
organon task new "which OCR reads code in video frames" --effort compare
organon audit proposal.json --messages messages.jsonl   # before mneme digest
organon task done --outcome partial --left "no benchmark on our own frames"
```

Design and evidence: [docs/organs/intelligence.md](docs/organs/intelligence.md).

A `merge` exception in `policy.json` (`{"class": "merge", "repo": "*/my-repo", "reason": "…"}`) lifts a command only if the whole command is exactly `gh pr merge [<number or branch>] [--squash|-s] [--merge|-m] [--rebase] [--delete-branch|-d] [--match-head-commit <sha>] [--repo|-R <owner>/<name>]`, where a `--repo`, `--repo=` or `-R` value must name the same GitHub repository as the folder's own `origin` remote (compared case-insensitively; https and ssh remote URLs, with or without `.git`; `github.com/<owner>/<name>` also works; another repository, another host, no `origin` or one that cannot be read still asks), or the same after `cd <absolute path> && ` (Bash `cd`, PowerShell `cd`, `Set-Location` or `sl`; one forward-slash path that every shell reads as the same folder: on Windows a drive-letter path such as `C:/Users/me/my-repo`, never `/c/...` or a path without a drive, which Git Bash and PowerShell read differently; elsewhere a `/...` path). Every character must be a letter, digit, space or one of `- _ . / : = + @ ,` (and `&&` between the two parts): any `$`, quote, backslash, backtick, `%`, glob, `~`, `#`, redirection, subshell, `;`, `|` or newline makes it ask, as does every other flag (`--admin`, `--auto`, `-R`/`--repo` naming another repository, bundles such as `-sd`) and any other command around it. It also asks while `GH_REPO` or `GH_HOST` is set in the hook's environment, and while any file Claude Code sources before each command (`CLAUDE_ENV_FILE`, every `<claude config dir>/session-env/<session id>/*.sh`) is not provably harmless. Those files are judged by an allow-list over the raw text, not by searching for bad words: the file must have no backslash and no control character (one trailing carriage return per line is fine), and every line must be blank, a comment (`#` and any text), or `NAME=VALUE` / `export NAME=VALUE` with nothing else on the line. `NAME` is `[A-Za-z_][A-Za-z0-9_]*` and must also be an allow-listed name: it matches a pattern in the optional policy field `"merge_env_names"`, a list of glob patterns made of letters, digits, `_` and `*`, compared case-insensitively (for example `"merge_env_names": ["VERCEL_PLUGIN_*"]`). The default list is empty, so by default any assignment line makes the merge ask; blank lines and comments never do. A second guard bars some names even when a pattern matches them, and a policy whose `merge_env_names` has a bare `*`, any other character, or a pattern that could match a barred name or prefix is rejected as invalid when it is read (the hook then fails closed: it denies approval-class actions, lets the rest through as before, and you fix the file). The barred names and prefixes include `GH_`, `GIT_`, `XDG_`, `GITHUB_`, `LD_`, `DYLD_`, `BASH`, `SSL_`, `CURL_`, `NODE_`, `PATH`, `PATHEXT`, `HOME`, `EXECIGNORE`, `GCONV_PATH`, every `*_PROXY`, and the shell variables that take arithmetic or act by themselves (`OPTIND`, `RANDOM`, `SECONDS`, `LINENO`, `HISTCMD` and the like); that bar is a safety net and is not claimed to be complete, the allow-list is the control. `VALUE` is plain (`[A-Za-z0-9_./:@,+=-]*`), or one pair of double or single quotes around those characters and spaces: no `$`, backtick, `;`, `&`, `|`, `(`, `{`, `<` or `>`. So a continuation line (`export GH_\` then `REPO=...`), a function, an alias, `GIT_DIR`, `PATH` and any name the policy does not list all make it ask; an empty file, a CRLF file, comments, and (with `"merge_env_names": ["VERCEL_PLUGIN_*"]`) lines such as `export VERCEL_PLUGIN_SETUP_MODE="1"` do not. A file that cannot be read also lifts nothing. The hook's own environment is checked only for `GH_REPO` and `GH_HOST`; other variables in Claude Code's own environment are out of scope. Limits (out of scope): a remote, alias, function or default repository changed in an EARLIER separate command is not seen; your shell profile and global git config are not inspected; wrappers such as `env`, `command` or `exec` hide `gh` from every rule. If your `policy.json` was written by `organon init` before this class existed, it still has `gh pr merge` in class `send`; remove that rule or change its class to `merge`, otherwise the exception has no effect (merges keep asking).

Each repo is published separately. Anyone can use one piece, fork it, or replace it with their own, as long as it speaks the protocol.

## Read next

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md): how the organs connect, the data flow, budgets and self-audit
- [docs/PROTOCOL.md](docs/PROTOCOL.md): the objects every organ reads and writes
- [docs/REPO-STANDARD.md](docs/REPO-STANDARD.md): how every organ repo is built
- [docs/ENGINEERING.md](docs/ENGINEERING.md): how we write code (design and Rust)
- [docs/organs/](docs/organs/): one design page per organ
- [docs/research/](docs/research/): what already exists, what it gets wrong, with sources

## License

MIT OR Apache-2.0.

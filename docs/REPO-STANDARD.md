# Repo standard: how every organ is built

Status: **v0.1**. The engineering half (how we write Rust) becomes `ENGINEERING.md` in step 2, distilled from the Uncle Bob corpus, *with* the Ousterhout counterpoint, and from idiomatic-Rust practice.

## Shape of an organ repo

```
organon-<organ>/
  README.md        what it does alone, how to install, one example, honest limits
  AGENTS.md        rules for agents working in the repo (invariants, how to test)
  skills/<organ>/SKILL.md   how an agent uses this organ cheaply (optional)
  Cargo.toml       workspace
  crates/<organ>-core    library: pure logic, typed errors, no I/O policy
  crates/<organ>-cli     binary: argument parsing, I/O, progress, exit codes
  tests/           integration tests with small fixtures checked in
  docs/DESIGN.md   status, decisions, open questions (living)
  LICENSE-MIT, LICENSE-APACHE
```

## Contract

- **CLI first.** Every capability is a subcommand. `--json` emits protocol JSONL on stdout; logs go to stderr; exit code 0 means success, 2 means a partial result, 1 means failure.
- **Speaks organon-protocol.** It depends on the protocol crate, never on another organ. Conformance tests from the protocol repo pass in CI.
- **Local-first and offline-capable** where the task allows. Network calls are explicit and named. API keys come only from the environment.
- **Deterministic by default.** Model calls are optional, declared, and recorded in `produced_by` and `cost`.
- **External tools are wrapped, not hidden.** If it uses yt-dlp, ffmpeg or Whisper, `organ doctor` reports which are present, which versions, and what is missing.
- **No third-party content in git.** Fixtures are made by us or openly licensed.

## Quality gate (CI on Linux, macOS and Windows)

`cargo fmt --check` · `cargo clippy -- -D warnings` · `cargo test` · protocol conformance · a smoke test of the CLI on a fixture.

## Versioning

SemVer per repo. Each repo states which protocol major version it speaks. Changelog per release.

## Living docs

`docs/DESIGN.md` always has **Status**, **Decisions** (with why), **Open questions**. When a decision is made, it is also written as a claim in the memory (`decision` on `project:<organ>`).

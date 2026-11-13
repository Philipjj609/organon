# Working in organon (for AI agents)

**Using it:** follow [skills/organon/SKILL.md](skills/organon/SKILL.md): `organon brief` at the start, a task with a budget, `organon audit` before digest, and `organon task done` at the end.

**Changing it:** read [docs/ENGINEERING.md](docs/ENGINEERING.md) first, then [docs/organs/intelligence.md](docs/organs/intelligence.md). This repo also holds the architecture and standards of every organ ([docs/](docs/)): change those deliberately, and record decisions as claims on `project:organon` in the memory.

**Layout:**
- `crates/organon-core`: pure logic. No files, no processes, no terminal.
  - `budget`, `meter` (transcript → spend), `policy`, `route`, `task`, `audit`, `time`.
- `crates/organon-cli` (`organon`): does the I/O.
  - `home` (`~/.organon`), `agent` (finding and reading the agent's transcript), `organs` (discovery on PATH).
- `policy/default.json`: the default policy, embedded in the binary.

**Quality gate** (CI runs it on Linux, macOS and Windows):

```bash
cargo fmt --all --check && cargo clippy --all-targets -- -D warnings && cargo test
```

Every bug fix gets a regression test. `tests/hook.rs` drives the hook end to end with a fake transcript.

**Rules:**
1. Intelligence coordinates; organs do the work. Never re-implement an organ's job here.
2. Measured or labelled: an estimate is shown as `≈`, and an unknown is shown as `?`. Never present one as a fact.
3. A hook never breaks the agent. On an error it allows and logs to `~/.organon/hook-errors.log`.
4. A budget stop is final for its task. Never make it retryable.

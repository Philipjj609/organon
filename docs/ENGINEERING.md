# Engineering: how we write code

Status: **v0.1 (2026-11-05)**. Applies to every organ repo. Sources: Philip's Uncle Bob corpus (`UNCLE_BOB_AGENT_CONTEXT.md`, distilled from his books and 226 talks) with John Ousterhout's counterpoint, the Rust API Guidelines, and what went wrong in our own first mneme code (listed at the end). These are **heuristics with a purpose**, not laws. When you break one, say which and why.

## Part 1: design

1. **Structure is the value that lasts.** Behaviour is what code does now. Structure is how cheaply it can be made to do something else. When they conflict, name the trade-off honestly. Structural debt compounds; behavioural debt doesn't. (Martin)
2. **Dependencies point inward.** Core logic (claims, frames, recall, perception rules) knows nothing about files, HTTP, terminals or models. Those are details bolted on at the edge. In practice: a `-core` crate with no I/O policy, and a `-cli` crate that does I/O. When control flows outward but the dependency must point inward, use a trait (e.g. a `Fetcher` the core calls and the CLI implements).
3. **One reason to change.** A module answers to one *actor*: the protocol, a modality, a storage format, a UI. Code serving two of them gets pulled apart by both. "Does one thing" is the wrong reading. (Martin's own restatement of SRP)
4. **Deep modules, simple interfaces, and know when to split.** Martin: small functions, few arguments. Ousterhout: many shallow pieces fragment a single idea across files. Our rule is to **split when a piece has its own reason to change or its own tests**, and to keep a reasoning unit whole even if it's 60 lines. The test is whether a reader can use the module from its interface alone.
5. **Names say what, types say what's allowed.** If a boolean parameter chooses behaviour, that's two functions or an enum. Comments say *why*; the code says *what*. Every public item gets a doc comment.
6. **Defer decisions, don't pre-build.** Leave databases, async runtimes and frameworks out until a measured need appears. Keep the escape route open (here, the format is plain JSONL behind a type).
7. **Tests are the trust mechanism.** Agents write more code than anyone can read, so tests are what we trust (Martin's current position). Logic is test-first where practical, every bug gets a regression test, and invariants get property tests. (Honest note: the empirical evidence on TDD is mixed. We do it for trust and safe refactoring, not because it's proven to be faster.)
8. **Leave it cleaner.** When touching code, fix the smell next to the change, and keep that fix inside the same change's scope.

## Part 2: Rust, not Python written in Rust

**Types carry meaning**
- Newtypes for identities and units: `ClaimId`, `SourceId`, `Seconds`, never a bare `String`/`f64` that could be confused. Use `#[serde(transparent)]` so formats don't change.
- Closed sets are `enum`s (`Basis`, `Family`, `Status`). Open sets are newtypes over `String` with a registry (`Relation`, `Kind`).
- Make invalid states unrepresentable. Use `Option`, not `""` or `-1`. Parse, don't validate: build checked types at the boundary, and trust them inside.

**Ownership**
- Take `&str`, `&[T]`, `&Path`, `impl AsRef<…>`. Return owned values. Never `.clone()` just to silence the borrow checker; restructure instead (split borrows, return indices, use an overlay).
- Prefer iterators and adapters to index loops. Return `impl Iterator` instead of collecting just to iterate later.
- No `Rc<RefCell<…>>` unless shared mutable state is the actual model.

**Errors**
- Library crates define their own error `enum` (`thiserror`). Binaries use `anyhow` with `.context(…)`.
- No `unwrap()` in library code. `expect("why this can't fail")` only for true invariants. No silent `let _ =` on a `Result`, unless it's a `write!` into a `String`.
- Errors name the thing: which line, which id, which file.

**API shape** (Rust API Guidelines)
- Conversions: `as_` (cheap, borrowed), `to_` (expensive), `into_` (consuming). Iterators: `iter()`, `into_iter()`.
- `#[must_use]` on pure functions whose result matters. More than about 4 parameters means a struct or builder.
- Library crates never `println!`. They return data; the CLI renders it.

**Data and formats**
- Serialized formats are contracts. Ids are content hashes of a canonical form, so changing that canonical form needs a version bump. Golden tests pin the bytes.
- Keep unknown fields (forward compatibility), and handle the UTF-8 BOM and CRLF on input (Windows).

**Quality gate**
- `cargo fmt`, `cargo clippy --all-targets -- -D warnings`, and `cargo test` on Linux, macOS and Windows in CI. `#![forbid(unsafe_code)]` unless justified in writing.
- Unit tests beside the code (`#[cfg(test)]`), integration tests in `tests/` with tiny checked-in fixtures, and property tests (`proptest`) for invariants like "replaying the log twice gives the same state".
- Few dependencies, each justified. Measure before optimizing, but never ship accidental O(n²) over the whole memory.

## Part 3: when an agent writes the code

The four rules (Karpathy, via the saved CLAUDE.md):
1. Think first, and ask when unsure.
2. Write the simplest thing that works.
3. Make surgical changes.
4. Define "done" as a check that passes.

Plus our own:
- **Producer ≠ verifier.** Every change comes with its tests and passes the quality gate before it's called done.
- **Don't claim what wasn't run.** If a step wasn't executed, say so.

## Our own first mistakes (mneme v0, fixed in the step-2 refactor)

- **Stringly-typed everything:** ids, kinds, relations and families were all `String`/`&str`.
- **`anyhow` inside the library**, so callers couldn't match on errors.
- **The whole state was cloned** just to stage a batch of changes.
- **A 400-line `main.rs` match** mixing parsing, logic and printing.
- **Zero tests.** Several bugs were found only by running against real data: over-stemming ("engineer" → "engine"), hubs outranking exact matches, id-like typos silently becoming text, and wrong "saved by" claims.

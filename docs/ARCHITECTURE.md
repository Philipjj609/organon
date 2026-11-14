# Architecture

Status: **outline v0.1 (2026-11-05)**. Living: revise when an organ teaches us something.

## Data flow

```
              ┌──────────────── research decides what to fetch ────────────────┐
              ▼                                                                │
  world ──► SENSE ──Source──► PERCEPTION ──Observations──► COMPREHENSION ──Proposal──► MEMORY
            (fetch)            (features)                  (meaning)                 (mneme)
                                                               ▲      ▲                 │
                                                               │      └── recall ───────┤
                                                          RESEARCH ◄────── gaps ─────────┤
                                                          LEARNING ◄──── episodes ───────┘
                                                               │
                                                      INTELLIGENCE (budget · policy · self-audit)
                                                               │
                                                          EXPRESSION (diagrams · briefings)
```

1. **Sense** produces a `Source`: raw bytes plus metadata, content-hashed, stored locally. Copyrighted content never goes into public repos.
2. **Perception** turns a source into `Observation`s: typed, *located* features (a time range, a page and region, a frame) with the tool that produced them. Deterministic where possible; small models where needed.
3. **Comprehension** reads observations cheap-first, pulls the detail it needs on demand (a frame, a passage), checks against memory, and writes a `Proposal` following the digest protocol (mneme `docs/DIGEST.md`).
4. **Memory** validates the proposal and commits claims with evidence pointing back to observations and sources.
5. **Research** starts from memory's gaps (empty frame slots, open questions) and drives the senses.
6. **Learning** reads episodes (what was asked, recalled, used, how it went, what it cost) and improves recall, frames and procedures.
7. **Intelligence** coordinates all of it within a budget, under a policy, and audits its own outputs.

## Boundaries (what makes organs interchangeable)

- An organ depends only on **organon-protocol**, never on another organ's internals.
- Organs talk through files and processes: a CLI that reads and writes **JSON Lines** of protocol objects (`--json`), plus a library crate for Rust callers. MCP servers wrap the same calls later.
- Every output carries `produced_by` (organ, version, model if any) and `cost`. Without those, nothing can be audited or learned from.
- Replacing an organ = another program that emits conformant objects. The conformance tests live in organon-protocol.

## Budget and energy

Intelligence has limits. Every operation records `cost` (`tokens_in`, `tokens_out`, `model`, `seconds`, `usd`, `bytes`). From that:

- **Effort scales with the question.** A lookup gets one recall; a comparison gets a few sources; a deep question gets a research plan. Explicit rules, not vibes (see research notes).
- **Cheapest adequate worker.** Planning and final judgement go to a strong model; scanning, extraction and checks go to cheap models or deterministic tools ("Opus plans, Haiku scans, Sonnet ships").
- **Budgets are declared up front** per task (max tokens, time, money). Organs stop at saturation or budget and report what's left unknown.

## Self-audit (the verification gap)

Research agents produce claims faster than anyone checks them. Rules:

- A claim cites a **passage or location**, not just a URL. The link must resolve and the passage must support the claim, or the claim is marked unsupported.
- **Producer ≠ verifier.** A separate pass (other model or tool) attacks central claims and has permission to reject.
- Corroboration counts only **independent** sources. Copies and paraphrases of one origin count once.
- Every run keeps its trace (plan, queries, sources seen and rejected, costs) so it can be reproduced and learned from.

## Order of building

1. memory ✓ → 2. protocol + engineering standard ✓ → 3. video (sense + perception) ✓ → 4. research v0 ✓ → 5. learning v0 ✓ → 6. intelligence wiring (budget, policy, audit) ✓ → 7. text ✓ (organon-text v0.1, 2026-11-14), sound, vision ✓ (organon-vision v0.1, 2026-11-14) → 8. expression.

## Open questions

- Should comprehension be its own repo, or live in intelligence (it's where models are called)?
- Cross-modal comprehension: when a talk shows a slide while saying something, who unifies the two, perception (aligned "moments") or comprehension?
- ~~How should organs discover each other?~~ Like git subcommands: `organon-<organ>` on PATH; the memory is `mneme` with its folder set once (`organon init --memory`). See [organs/intelligence.md](organs/intelligence.md).
- ~~Paperclip as the coordination layer?~~ Evaluated at step 6: not adopted for one person with one agent (a Node/Postgres control plane for agent companies; budget enforcement still contested). Its budget thresholds, approvals and trail were taken. Revisit if organon runs many agents around the clock.

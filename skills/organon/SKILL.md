---
name: organon
description: Run a work session with organon's intelligence - a brief at the start, a task with a budget declared up front, the cheapest adequate worker for each job, an audit before anything enters memory, and an episode at the end. Use at the start and end of any session that uses the organs (mneme, organon-research, organon-video, organon-learning).
---

# Working within a budget, under a policy, with an audit

`O=organon`.

## Start

1. `O brief`. Read it, all of it (about 8 lines): which organs exist, the memory's state, what this session has cost, how much context every turn re-reads, the open task, routes, policy.
   - If it says the context is large, do the next *independent* step in a fresh session (hand it off with a short brief). Every turn re-reads the context, so a long session gets more expensive with each turn.
2. Declare the work: `O task new "<goal>" --effort lookup|compare|deep`. Choose the effort by the question, not by the time available. Lookup: one recall or one source. Compare: a few sources or options. Deep: a research plan.

## While working

- **Route each job** (`O route` lists them):
  - `check`: a tool first (quote verification, `mneme digest`, conformance).
  - `scan`, `extract`, `verify`: the cheap model (a subagent with `model: haiku`).
  - `plan`, `judge`, `write`, `code`: the strong model.
  - Never verify with the model that produced the work: `O route --verify <model>`.
- **Policy decisions are answers.** With the hook installed, a denied action says why. A denied budget stop is final: do not retry, rephrase or work around it. Record what is left and close the task.
- `O spend` shows where the money went (per model: input, cache reads, cache writes, output).

## End

1. Write the proposal, then `O audit proposal.json --messages <organ messages.jsonl>`.
   - Fix each finding: cite an observation or source, lower a confidence you cannot back, or have another model or tool check self-verified evidence.
   - Then `mneme ingest` and `mneme digest`.
2. `O task done --outcome good|partial|bad --left "<what is still unknown>"`. The episode (cost and outcome) is what learning uses to calibrate budgets and routes.

## Rules

- A budget is declared before the work, not after.
- Unknown stays unknown: `--left` names it. A partial outcome with an honest gap beats a confident one without.
- The policy is a guard rail, not a sandbox. Do not get around it with `bash -c` or scripts. If a rule is wrong, change `~/.organon/policy.json` and say so.

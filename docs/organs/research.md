# organon-research: finding out, systematically

Status: **design v0.1**. Grounded in [../research/2026-11-05-research-systems.md](../research/2026-11-05-research-systems.md).

Not "take the first 10 results". The goal is a *traceable* answer: every central claim tied to a passage, corroborated by independent sources, challenged by its best counter-argument, and written to memory with what remains unknown.

## The loop (each stage scored separately, so we know which one broke)

1. **Frame.** Turn the question into sub-questions using memory's gaps (empty frame slots, open questions) and several *perspectives*: who would ask this, and what would they need to know? (from STORM). Declare the effort level and budget up front.
2. **Scale effort.** Lookup: 1 worker, 3–10 tool calls. Comparison: 2–4 workers, 10–15 calls each. Deep question: 10+ workers with divided responsibilities. (Anthropic's published rules, as a starting point.)
3. **Plan by source type** for each sub-question: primary (docs, repos, papers, official data), practitioners (talks, posts), critics, data.
4. **Search wide, then narrow.** Short broad queries first, then specific ones. Several engines and phrasings ("X problems", "X vs Y", "X alternative", the term in other languages). Remove duplicates.
5. **Triage sources.** Primary vs derivative; known-good vs SEO farm; conflict of interest (promo, affiliate, vendor benchmark); recency; **independence** (detect copies and paraphrases of one origin: many posts restate one article).
6. **Read deep, selectively.** Only the sources with the highest expected information gain go through the senses and perception, in full.
7. **Extract claims with passages.** Every claim carries the passage or location that supports it. **Verify**: does the link resolve, and does the passage actually say this? Published audits find 3–13% of research-agent citation URLs are hallucinated, and only 39–77% factual accuracy against the agents' own cited sources. This step is the main difference from existing tools.
8. **Challenge.** For each central claim, search specifically for its strongest counter-evidence. Keep disagreements as disagreements.
9. **Stop at saturation or budget.** Saturation means new sources add no new claims and fill no new frame slots.
10. **Write back.** Proposal to memory (claims, evidence, contradictions, open questions), a short report plus a diagram, and an episode with the full trace and cost.

## Mechanics borrowed and why

- Orchestrator with parallel workers, each with a precise brief (objective, output format, sources to use or avoid, boundaries). Vague briefs caused overlapping, misread work.
- Plans and intermediate results live in external memory (mneme), not in one context window. Runs are resumable from checkpoints.
- Producer ≠ verifier: a separate verifier attacks the claims and may reject them.

## Evaluation

About 20 representative research questions (Philip's real ones: the mom's website, Koda, Compendium topics). Score plan, retrieval, source quality, claim–passage alignment, synthesis and cost **separately**. An LLM judge with a rubric plus human spot checks. Report cost with every score.

## Open questions

- Which search backends (web APIs, GitHub, arXiv, YouTube, X) are available cheaply and legally?
- How do we score source reliability over time? Learn it from outcomes: sources whose claims held up get trusted more.
- How much of this can a cheap model do, with a strong model only planning and judging?

# Research on research systems and video understanding (2026-11-05)

Status: **first pass**: web search plus a read of four primary pages; not a systematic review yet. That review is the first job of organon-research itself.

## Research agents

**What works (Anthropic, "How we built our multi-agent research system")**
- Orchestrator + parallel subagents beat a single strong agent by 90.2% on their internal eval. Token spend explains most of the performance variance, and multi-agent setups cost about 15× the tokens of chat.
- Effort scaling rules in the prompt (1 agent / 3–10 calls → 2–4 agents / 10–15 calls → 10+ agents).
- Short broad queries first, then narrow. Early agents preferred **SEO content farms** over primary sources until given source-quality heuristics.
- Precise subagent briefs (objective, format, sources, boundaries). Vague briefs caused duplicated, misread work.
- Tool descriptions matter as much as prompts. A tool-testing agent that rewrote bad descriptions cut task time by 40%.
- Evaluation: about 20 queries is enough to start; judge end states, not paths; an LLM-judge rubric (factual accuracy, citation accuracy, completeness, source quality, tool efficiency); humans catch what automation misses.
- Reliability: resumable execution, checkpoints, tracing of decisions, plans kept in external memory.

**What fails**
- Citation hallucination: 3–13% of research-agent citation URLs don't exist; 5–18% don't resolve.
- Real links that misrepresent their source: link validity above 94%, but factual accuracy against cited sources only 39–77% in one audit.
- The **verification gap**: agents produce research artifacts faster than they can be checked; no benchmark audits the full chain claim → citation → passage → source reliability; LLM judges correlate poorly with experts and favour their own outputs; cost and harness details go unreported.
- Expert consulting benchmark (70 tasks): no agent averaged above "adequate", and each failed in its own way.
- Scoring stages separately (plan, retrieval, source evaluation, claim–evidence alignment, synthesis) shows *which* stage broke (practitioner rubric).

**Existing open systems to study before building:** GPT Researcher (MIT; parallel multi-source, citations), STORM (Stanford; perspective-guided questions, outline-first articles), MiroFlow, O-Researcher, OpenSeeker. None of them is organized around a persistent memory with provenance, independence-aware corroboration, or passage-level verification. That is our gap.

## Video understanding

- **Deep Video Discovery**: build a multi-granular database from the video's segments, then let an LLM agent *search* it with tools, adapting its plan per question. 74.2% on LVBench (76.0% with transcripts), state of the art at publication; earlier VideoTree/VideoAgent scored far lower in its comparison table.
- Keyframe selection is an active research area (query-decomposed retrieval, critic-refined targeting, scene-transition-aware extraction). The consensus direction is *select what matters for the question* rather than sample uniformly.
- Agent skills (claude-video, claudetube, claude-watch): yt-dlp + ffmpeg + captions/Whisper; frame caps; on-demand frames. Useful plumbing, no lasting comprehension.

## Implications (taken into the organ designs)
1. Passage-level evidence and verification are the core of research, not an add-on.
2. Independence of sources must be detected, not assumed.
3. Effort and budget are explicit inputs.
4. Video = layered index + search + frames on demand, not frame dumps.

## Sources
- Anthropic, How we built our multi-agent research system: https://www.anthropic.com/engineering/multi-agent-research-system
- Detecting and Correcting Reference Hallucinations in Commercial LLMs and Deep Research Agents: https://arxiv.org/html/2604.03173v1
- Autonomous Research Agents: A Survey of AI Scientists and the Verification Gap: https://arxiv.org/html/2608.05179v1
- Citation Reliability in AI Literature Reviews: https://intuitionlabs.ai/articles/citation-reliability-ai-literature-reviews
- Evaluating Deep Research Agents on Expert Consulting Work: https://arxiv.org/html/2605.17554v3
- Evaluating Deep Research Agents in 2026 (practitioner rubric): https://futureagi.com/blog/evaluating-deep-research-agents-2026/
- Where Do Deep-Research Agents Go Wrong?: https://arxiv.org/pdf/2606.02060
- GPT Researcher: https://gptr.dev/ · AstaBench (describes STORM): https://arxiv.org/pdf/2510.21652 · MiroFlow: https://arxiv.org/pdf/2602.22808
- Deep Video Discovery: https://arxiv.org/abs/2505.18079 · keyframe retrieval via tool calls: https://arxiv.org/pdf/2605.23826 · CRAFT: https://arxiv.org/pdf/2605.19075 · generalized keyframe extraction: https://arxiv.org/html/2606.29445v1 · MetaVideoAgent: https://arxiv.org/pdf/2608.04587
- claude-video: https://github.com/bradautomates/claude-video · claudetube: https://pypi.org/project/claudetube/ · claude-watch: https://github.com/alexlarcheveque/claude-watch

# organon

**One living intelligence, built from organs you can use, replace and improve one at a time.**

*organon* (Greek: instrument, organ; Aristotle's name for the tools of knowing) is the umbrella of a family of repositories. Each organ is its own repo, useful on its own, and speaks one shared protocol. This repo holds the architecture, the protocol, the standard every organ follows, and later the binary that connects them.

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
| organon *(this)* | Intelligence + spec | Architecture, protocol, repo standard; later the coordinator with budget and self-audit | outlining |
| [organon-protocol](https://github.com/Philipjj609/organon-protocol) | Shared language | `Source`, `Observation`, `Claim`, `Proposal`, `Episode` types, JSON Schema, conformance fixtures | working (v0.1) |
| [organon-video](https://github.com/Philipjj609/organon-video) | Sense + perception: video | URL/file → transcript, keyframes measured (ink, repeats), moments with ★ where to look, index to read first; frames on demand; protocol messages for memory | working (v0.1) |
| [organon-research](https://github.com/Philipjj609/organon-research) | Research | Ledger of a run; keyless search + agent web search; triage with reasons; every quoted passage verified in the source; independent voices counted; challenge, saturation, export to memory | working (v0.1) |
| [organon-learning](https://github.com/Philipjj609/organon-learning) | Learning | Recall evaluated against rated and used questions; priors adopted only through a leave-one-out gate; frame slots proposed from use; hygiene (duplicates, stale, thin hubs) | working (v0.1) |
| organon-sound | Sense + perception: sound | Speech, music (tempo, key, structure), sound events | later |
| organon-vision | Sense + perception: images | Layout, palette, typography, objects, text in images | later |
| organon-text | Sense + perception: text | Web, X, PDFs, books, repos (moves out of mneme's capture) | later |
| organon-express | Expression | Diagrams with drill-down levels + short text; briefings | after the core |

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

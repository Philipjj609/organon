# Protocol v0 (draft)

Status: **draft**. Source, Claim and Proposal exist today in mneme (`mneme-core::model`, `docs/DIGEST.md`). Observation, Episode and Cost are new. Everything is extracted into `organon-protocol` (Rust types + JSON Schema + conformance tests) in step 2.

All objects are JSON, one per line (JSONL), UTF-8. IDs are content-addressed (`s_`, `o_`, `c_`, `m_`, `e_` + 16 hex chars of SHA-256).

## Source: what a sense captured
```json
{ "id": "s_…", "kind": "youtube-video", "uri": "https://youtube.com/watch?v=…", "title": "…",
  "captured_at": "2026-11-05T10:00:00Z", "content_hash": "…",
  "files": { "captions": "captions.en.json3", "audio": "audio.m4a", "video_lowres": "video.480p.mp4" },
  "meta": { "channel": "…", "duration_s": 3725, "chapters": [ { "t": 0, "title": "Intro" } ] },
  "produced_by": { "organ": "organon-video", "version": "0.1.0", "tool": "yt-dlp 2026.10" } }
```

## Observation: a located feature, no interpretation
```json
{ "id": "o_…", "source": "s_…", "kind": "transcript_segment",
  "at": { "t0": 754.2, "t1": 761.8 },
  "value": { "text": "as you can see on this slide…", "speaker": "S1", "words": [ … ] },
  "produced_by": { "organ": "organon-video", "version": "0.1.0", "tool": "captions:manual" },
  "confidence": 0.98 }
```
Kinds start with: `transcript_segment`, `chapter`, `shot`, `keyframe` (`value.file`, `value.phash`), `screen_text` (OCR), `speaker_turn`, `moment` (an aligned window: transcript span + frames + screen text, the unit comprehension reads), `visual_cue` (a reason to look: deictic phrase, slide change, chapter start). Modalities add kinds (`beat`, `key`, `palette`, `layout_region`…); the kind registry lives in organon-protocol.

`at` locates the observation: `{t0,t1}` for time, `{page, bbox}` for documents and images, `{frame}` for a single frame.

## Proposal / Claim
As in mneme (`docs/DIGEST.md`), with one addition: evidence can point to **observations** (`{"observation": "o_…"}`), so a claim made from a video cites the exact moment and frame.

## Episode: what happened when the system did something
```json
{ "id": "e_…", "type": "recall|research|perceive|digest", "task": "…", "started": "…", "ended": "…",
  "inputs": [ … ], "outputs": [ … ], "outcome": "good|partial|bad|unknown",
  "cost": { "tokens_in": 0, "tokens_out": 0, "model": "…", "seconds": 0, "usd": 0 },
  "trace": "path/to/trace.jsonl" }
```

## Rules
- Producers never overwrite. A corrected observation is a new observation that `supersedes` the old one.
- Every object names its producer and version. Unknown fields are kept, not dropped (forward compatibility).
- Breaking changes bump the protocol major version. Organs declare which versions they speak.

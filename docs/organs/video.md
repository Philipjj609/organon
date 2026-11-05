# organon-video: seeing and hearing a video

Status: **design v0.1**. Next to build after the protocol.

Goal: give it a video (YouTube URL or file) and the intelligence can understand it, *including what is shown*, without watching every frame. It pulls images only where they matter, like a person glancing at the screen when the speaker says "look at this".

## Levels

**Sense** (`organon-video sense <url|file>`)
- yt-dlp: metadata, chapters, description, captions (manual > auto, with word timings), audio, a low-resolution video for frames. Recent yt-dlp needs deno for full YouTube support.
- No captions → speech-to-text (local Whisper / faster-whisper with word timestamps; later via organon-sound).
- Output: one `Source` with files, kept locally.

**Perception** (`organon-video perceive <source>`)
- Transcript segments, sentence-aligned, with timestamps; speaker turns when available (diarization optional).
- Shots: ffmpeg scene-change detection, one keyframe per shot, near-duplicates removed by perceptual hash.
- On-screen text: OCR of keyframes (slides, code, captions burned in), and *changes* of on-screen text.
- Visual cues, reasons to look: deictic phrases ("as you can see", "this chart", "here"), slide or text changes, chapter starts, long silences with motion.
- **Moments**: aligned windows (transcript span + keyframes + screen text + cues). These are the unit comprehension reads.
- **Layered index** (from Deep Video Discovery's multi-granular database): video → chapters → moments → frames and words. Output `index.md`: compact, about 1 line per moment, frames referenced by id, not embedded.

**On demand** (what the agent calls while comprehending)
- `frame <source> --at 12:34` or `--moment m_…` returns the image path or bytes.
- `search <source> "<query>"` returns moments matching words, screen text or cues.
- `contact-sheet <source> --chapter 3` returns one grid image of a chapter's keyframes (cheap visual overview).

## Comprehension (done by the intelligence, following the digest protocol)

Cheap-first: read `index.md` → decide which moments need eyes → fetch those frames only (a frame budget per video) → write claims with evidence `{"observation": "o_…"}` pointing to the exact moment or frame → mneme.
Provenance as in the Uncle Bob corpus: is this *by* the person or *about* them? Who is speaking in each turn?

## Validation

The Uncle Bob corpus (295 videos with captions, speaker splits and provenance labels) is ground truth for captions, segmentation and speaker attribution. A small set of slide-heavy talks tests the visual path: did we fetch the frames that carried information the transcript didn't?

## What exists (and the gap)

Agent skills like claude-video (yt-dlp + ffmpeg, frames auto-scaled under ~100), claudetube (on-demand frames) and claude-watch make an agent able to *watch once*. They have no lasting understanding: no layered index, no provenance, no memory, no learning. Research (Deep Video Discovery; keyframe-selection work like VideoTree and VideoAgent) shows that *searching* a structured index beats uniform sampling.

## Open questions

- Which OCR runs well locally on Windows (Tesseract vs a small vision model)?
- When are frames sent to a vision model vs described by a cheap captioner first?
- How do we mark claims learned from an image vs from speech, so they can be weighed differently?

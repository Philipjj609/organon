# The other organs (stubs, to be designed when their turn comes)

Each starts by researching what exists, then designs the gap. Status of all: **stub**.

## organon-learning: getting better from what happened
- Reads episodes (recall, research, perceive, digest) with outcomes and costs.
- **Recall that learns:** weights links and sources by whether recalled items were used and helped (the `feedback` data mneme already logs).
- **Consolidation:** clusters repeated observations into stronger beliefs (proof counts), proposes concept-level abstractions only from ≥2 independent cases, flags stale claims.
- **Frames that grow:** when the same new kind of slot keeps appearing, propose adding it to the frame.
- **Procedures:** a method that worked repeatedly becomes a skill, linked to the claims it rests on (stale when they change).

## organon-sound: hearing
- **v0.1 built:** [organon-sound](https://github.com/Philipjj609/organon-sound). ffmpeg decodes and transcribes (its `whisper` filter: whisper.cpp inside, no second binary); tempo (onset autocorrelation), key (chroma × Krumhansl/Temperley) and silence are measured in pure Rust; YAMNet tags sound events through tract. Takes an organon-video folder and keeps its source id, so a video's speech and pictures are one source. Measured: 96% of a talk's caption words in order (`ggml-base`); no music found in speech; 93% of 26 min of music found.
- Next: EfficientAT tagger (mAP 0.483 vs YAMNet's 0.306), word timestamps and speakers (whisper-rs, diarization), sections inside music spans, a beat tracker for beat times.

## organon-vision: seeing still images and design
- **v0.1 built:** [organon-vision](https://github.com/Philipjj609/organon-vision). ocrs (pure Rust, on RTen) reads text lines and words; layout from geometry (lines grouped into text blocks with their line heights, busy tiles without text as figure blocks); palette by k-means in CIE Lab; objects by any YOLOv8/YOLO11 ONNX model on RTen. Whole-image measures (ink, look, dhash) moved here from organon-video unchanged; video is to call this crate for its keyframes and for `screen_text`. Real run: six images, 0.2–1.3 s each.
- Next: organon-video on `organon-vision-core`; multilingual OCR and model layout (oar-ocr: PP-OCRv6, PP-DocLayout); typography beyond sizes (family, weight, monospace); *style* for design taste ("why does this site feel premium").

## organon-text: reading
- **v0.1 built:** [organon-text](https://github.com/Philipjj609/organon-text). Readability (dom_smoothie) → Markdown with located `section`s, GitHub API + README, X via fxtwitter, HF datasets, PDFs through `pdftotext` with located `page`s. mneme's `capture links` is deprecated in its favour.
- Next: a heading tree for PDFs (outline first, PageIndex-style when absent), pdfium vs pdftotext on our own PDFs, books.

## organon (intelligence): coordinating
- **v0.1 built:** see [intelligence.md](intelligence.md). Budgets up front, measured spend, policy hook, two-tier routes, audit before digest, task episodes. Paperclip evaluated and not adopted for now.

## organon-express: showing
- Answers as diagrams with levels you can open (overview → detail), a few lines of text beside them; built on the diagram-design skill (one HTML+SVG file per diagram); briefings.

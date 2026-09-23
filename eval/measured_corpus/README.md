# Measured corpus v0

Contract for a **future** three-arm runner. Brand: Agent Control Lab. Apache-2.0.

This directory is a row schema plus a 28-row seed map. It does **not** run fixtures and it is **not** a measured attack-success table. **No ASR.** `residual_asr` on every arm is JSON `null`.

Arms are `monitor-alone` (stub or not applicable), `host-PEP-alone`, and `stack`.

- Schema: [`schema/row.schema.json`](schema/row.schema.json) (notes in [`schema/README.md`](schema/README.md))
- Seed map: [`index.json`](index.json) — pointers at pinned pep and supply-gate fixtures and at `eval/joint_story/`. Sibling trees are not copied
- Narrative: [`docs/measured-corpus-v0.md`](../../docs/measured-corpus-v0.md)

Public/EOI claim cite stays pep diligence tip `1d0f380` until a measured table and Cyber PASS.

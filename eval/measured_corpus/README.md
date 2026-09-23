# Measured corpus v0

Contract for a **future** three-arm runner. Brand: Agent Control Lab. Apache-2.0.

This directory is the v1 delta on a 28-row v0 seed map, plus the `representation_mismatch` v1 row, 3 benign-twin rows, and a mediation binding. The schema accepts `measured-corpus-row-v0` and `measured-corpus-row-v1`. It does **not** run fixtures and it is **not** a measured attack-success table. **No ASR.** `residual_asr` on every arm is JSON `null`.

Arms are `monitor-alone`, `host-PEP-alone`, and `stack`. The v1 delta adds arm status `not_mediated` and optional row fields (`benign_twin_of`, counters, `table_id`, `plane`). The 28 v0 seed bodies stay v0 aside from a policy-intent denial label in host DENY notes. `representation_mismatch` is `not_mediated` on every arm. The benign twins are v1 rows with null counters and `host-PEP-alone` mapped `ALLOW`. `residual_asr` stays null. Claim cite stays `1d0f380`. `runner_implemented` stays false.

- Schema: [`schema/row.schema.json`](schema/row.schema.json) (field definitions in [`schema/README.md`](schema/README.md))
- Seed map: [`index.json`](index.json) — pointers at pinned pep and supply-gate fixtures and at `eval/joint_story/`. Sibling trees are not copied
- Mediation binding: [`binding.md`](binding.md) and [`binding.json`](binding.json) — threat to arm `status` / `decision`, using `mapped`, `stub`, `not_applicable`, and `not_mediated`
- Narrative: [`docs/measured-corpus-v0.md`](../../docs/measured-corpus-v0.md). That filename is historical (v0 seed doc). The v1 field definitions live in [`schema/README.md`](schema/README.md).

Public/EOI claim cite stays pep diligence tip `1d0f380` until a measured table and Cyber PASS.

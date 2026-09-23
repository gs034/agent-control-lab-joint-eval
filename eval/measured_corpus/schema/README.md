# Measured-corpus row schema (v1 delta)

Brand: **Agent Control Lab**. Licence: **Apache-2.0**.

JSON Schema (draft 2020-12):

| File | What it checks |
| --- | --- |
| [`row.schema.json`](row.schema.json) | One threat row. Accepts `measured-corpus-row-v0` and `measured-corpus-row-v1` |
| [`index.schema.json`](index.schema.json) | Seed envelope (`rows[]` length 20–50; each item `$ref`s the row schema). `arms` is exactly `["monitor-alone", "host-PEP-alone", "stack"]` |

Neither schema sets an absolute `$id`. Load the checked-out `index.schema.json` so a stock Draft 2020-12 resolver uses that file's retrieval URI as the base; `rows.items.$ref` (`row.schema.json`) then resolves to the adjacent file in this directory. Do not add an `https://github.com/...` `$id`: that URL is an HTML page, and the relative reference would resolve against it instead of this bundle. A relative `$id` is not a substitute; resolvers that take `$id` as the base without joining it to the retrieval URI look for `row.schema.json` in the process working directory.

## Frozen fields

| Field | Rule |
| --- | --- |
| `threat_id` | `acl-mc-…` |
| `setup` | Case description |
| `expected_effect` | Existence-proof wording or an unmapped slot |
| `arms` | Object with `monitor-alone`, `host-PEP-alone`, and `stack` |
| `decision` | `DENY` or `ALLOW` when `status` is `mapped`; JSON `null` when `status` is `stub`, `not_applicable`, or `not_mediated` |
| `residual_asr` | `null` only (N/A placeholder). This delta does not add a numeric ASR |
| `tip_pins` | `stub`, `not_applicable`, and `not_mediated` may leave `pep`, `supply_gate`, and `joint` null. `host-PEP-alone` `mapped` requires `pep` (40-hex install SHA). `stack` `mapped` requires `pep` and `supply_gate`. `joint` may stay null |

`monitor-alone` is `stub`, `not_applicable`, or `not_mediated`, and its `decision` is `null`. `stub` is not valid on `host-PEP-alone` or `stack`. `residual_asr` has no numeric form in this schema. The public/EOI cite stays `1d0f380` until a measured table exists and Cyber has passed it.

Seed rows keep `schema_version` `measured-corpus-row-v0` and do not need the v1 fields. `measured-corpus-row-v1` is the same object with those fields filled in when a later row has them.

## v1 delta fields

Chosen counter names are the Evidence Corpus Plan appendix B set, one snake_case form, recorded once on the row (not repeated inside each arm):

| Field | Rule |
| --- | --- |
| Arm `status` `not_mediated` | Coverage / honesty outcome for a threat this gate does not mediate. `decision` is JSON `null`. Valid on `monitor-alone`, `host-PEP-alone`, and `stack` |
| `benign_twin_of` | Optional. A `threat_id` (`acl-mc-…`) or JSON `null`. Points a benign row at its attack twin |
| `attempted` | Optional integer ≥ 0, or JSON `null`. Attack trials for this row |
| `reached_tool` | Optional integer ≥ 0, or JSON `null`. Attack trials that reached the tool |
| `attempted_benign` | Optional integer ≥ 0, or JSON `null`. Benign trials for this row |
| `blocked_benign` | Optional integer ≥ 0, or JSON `null`. Benign trials the gate blocked |
| `table_id` | Optional string or JSON `null`. No table is recorded in this delta |
| `plane` | Optional `host`, `supply`, `joint`, `complementarity`, or JSON `null`. Lab plane, not a `joint_story` step label (`pep` / `supply-gate`) |

`existence_proof_only` is a boolean. The seed rows stay `true`. When it is `true`, every counter (`attempted`, `reached_tool`, `attempted_benign`, `blocked_benign`) must be JSON `null` if the key is present. Absent keys are still valid, so v0 rows validate unchanged. `no_asr_claim` stays `true`.

Fixture `path` values point at `eval/…` in the named repo. This tree does not vendor those directories. See [`docs/measured-corpus-v0.md`](../../../docs/measured-corpus-v0.md).

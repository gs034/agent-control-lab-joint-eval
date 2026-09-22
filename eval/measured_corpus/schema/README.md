# Measured-corpus row schema (v0)

Brand: **Agent Control Lab**. Licence: **Apache-2.0**.

JSON Schema (draft 2020-12):

| File | What it checks |
| --- | --- |
| [`row.schema.json`](row.schema.json) | One threat row |
| [`index.schema.json`](index.schema.json) | Seed envelope (`rows[]` length 20–50; each item `$ref`s the row schema). `arms` is exactly `["monitor-alone", "host-PEP-alone", "stack"]` |

## Frozen fields

| Field | Rule |
| --- | --- |
| `threat_id` | `acl-mc-…` |
| `setup` | Case description |
| `expected_effect` | Existence-proof wording or an unmapped slot |
| `arms` | Object with `monitor-alone`, `host-PEP-alone`, and `stack` |
| `decision` | `DENY` or `ALLOW` when `status` is `mapped`; JSON `null` when `status` is `stub` or `not_applicable` |
| `residual_asr` | `null` only (N/A placeholder) |
| `tip_pins` | `pep`, `supply_gate`, and `joint` SHAs or `null` |

`monitor-alone` is only `stub` or `not_applicable`, and its `decision` is `null`. `stub` is not valid on `host-PEP-alone` or `stack`. `residual_asr` has no numeric form in this schema. A measured table would be a new schema version, and the public/EOI cite stays `1d0f380` until that table exists and Cyber has passed it.

Fixture `path` values point at `eval/…` in the named repo. This tree does not vendor those directories. See [`docs/measured-corpus-v0.md`](../../../docs/measured-corpus-v0.md).

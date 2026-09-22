# Measured-corpus row schema (v0)

Brand: **Agent Control Lab**. Licence: **Apache-2.0**.

JSON Schema (draft 2020-12):

| File | What it checks |
| --- | --- |
| [`row.schema.json`](row.schema.json) | One threat row |
| [`index.schema.json`](index.schema.json) | Seed envelope (`rows[]` length 20–50; each item `$ref`s the row schema). `arms` is exactly `["monitor-alone", "host-PEP-alone", "stack"]` |

Neither schema sets an absolute `$id`. Load the checked-out `index.schema.json` so a stock Draft 2020-12 resolver uses that file's retrieval URI as the base; `rows.items.$ref` (`row.schema.json`) then resolves to the adjacent file in this directory. Do not add an `https://github.com/...` `$id`: that URL is an HTML page, and the relative reference would resolve against it instead of this bundle. A relative `$id` is not a substitute; resolvers that take `$id` as the base without joining it to the retrieval URI look for `row.schema.json` in the process working directory.

## Frozen fields

| Field | Rule |
| --- | --- |
| `threat_id` | `acl-mc-…` |
| `setup` | Case description |
| `expected_effect` | Existence-proof wording or an unmapped slot |
| `arms` | Object with `monitor-alone`, `host-PEP-alone`, and `stack` |
| `decision` | `DENY` or `ALLOW` when `status` is `mapped`; JSON `null` when `status` is `stub` or `not_applicable` |
| `residual_asr` | `null` only (N/A placeholder) |
| `tip_pins` | `stub` and `not_applicable` may leave `pep`, `supply_gate`, and `joint` null. `host-PEP-alone` `mapped` requires `pep` (40-hex install SHA). `stack` `mapped` requires `pep` and `supply_gate`. `joint` may stay null |

`monitor-alone` is only `stub` or `not_applicable`, and its `decision` is `null`. `stub` is not valid on `host-PEP-alone` or `stack`. `residual_asr` has no numeric form in this schema. A measured table would be a new schema version, and the public/EOI cite stays `1d0f380` until that table exists and Cyber has passed it.

Fixture `path` values point at `eval/…` in the named repo. This tree does not vendor those directories. See [`docs/measured-corpus-v0.md`](../../../docs/measured-corpus-v0.md).

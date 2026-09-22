# Measured-corpus row schema (v0)

Brand: **Agent Control Lab**. Licence: **Apache-2.0**.

JSON Schema (draft 2020-12):

| File | What it checks |
| --- | --- |
| [`row.schema.json`](row.schema.json) | One corpus row |
| [`index.schema.json`](index.schema.json) | Seed-map envelope (`rows[]` items use the row schema) |

## Row fields

| Field | Rule |
| --- | --- |
| `id` | Stable id, `acl-mc-…` |
| `schema_version` | Frozen `measured-corpus-row-v0` |
| `arm` | `pep`, `supply_gate`, or `joint` |
| `threat_class` | Class label (pattern name or short class string) |
| `fixture_paths` | One or more pointers under `eval/joint_story/` |
| `expected_decision` | `DENY` or `ALLOW` |
| `taxonomy` | `joint_story` source, story id, plane tag, citation, reason codes |
| `existence_proof_only` | Frozen `true` |
| `no_asr_claim` | Frozen `true` |
| `brand` / `licence` | `Agent Control Lab` / `Apache-2.0` |
| `notes` | Optional prose. Not policy. |

## Arms

`pep` maps joint_story plane `pep`. `supply_gate` maps joint_story plane `supply-gate`. `joint` is the composed story (both planes), not a third package. `taxonomy.plane_in_story` keeps the joint_story spelling (`supply-gate`, `joint-story`).

`fixture_paths` may name `envelope`, `expected_receipt`, `observed_head`, `untrusted_prose`, `runtime`, or `story_index`. Paths stay inside `eval/joint_story/`. Sibling `eval/corpus/` trees are not copied here.

Claim-bar flags cannot be set false in this schema. A measured scoreboard would be a new schema version. See [`docs/measured-corpus-v0.md`](../../../docs/measured-corpus-v0.md).

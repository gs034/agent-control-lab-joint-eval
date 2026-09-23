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

## Field definitions

Names below are the schema keys. This note does not add fields, DENY classes, or a filled rate.

### `schema_version`

`schema_version` is `measured-corpus-row-v0` or `measured-corpus-row-v1`.

`measured-corpus-row-v0` is the seed-row value. Those rows omit the v1 keys. `measured-corpus-row-v1` is the same contract plus the optional fields in this section. Both strings validate against [`row.schema.json`](row.schema.json). The seed index `schema_version` stays `measured-corpus-v0`.

### Arms

`arms` is an object whose keys are exactly `monitor-alone`, `host-PEP-alone`, and `stack`. The seed index freezes that set, in that order, as `["monitor-alone", "host-PEP-alone", "stack"]`. Duplicates and reordering are invalid on the index.

Each arm is an outcome with `status`, `decision`, `residual_asr`, and `tip_pins`.

| Arm | `status` | `decision` | `tip_pins` |
| --- | --- | --- | --- |
| `monitor-alone` | `stub`, `not_applicable`, or `not_mediated` | JSON `null` | `pep`, `supply_gate`, and `joint` may be null |
| `host-PEP-alone` | `mapped`, `not_applicable`, or `not_mediated`. `stub` is not valid | `DENY` or `ALLOW` when `status` is `mapped`; JSON `null` otherwise | `mapped` requires `pep` (40-hex install SHA). `supply_gate` and `joint` may be null. Non-mapped pins may be null |
| `stack` | `mapped`, `not_applicable`, or `not_mediated`. `stub` is not valid | `DENY` or `ALLOW` when `status` is `mapped`; JSON `null` otherwise | `mapped` requires `pep` and `supply_gate` (40-hex install SHAs). `joint` may stay null. Non-mapped pins may be null |

`host-PEP-alone` `mapped` is the host-PEP-alone existence-proof. `stack` `mapped` is the stack existence-proof. Neither mapped outcome is valid on `monitor-alone`.

### Arm `status`

`decision` is JSON `null` when `status` is not `mapped`. Only `mapped` carries `DENY` or `ALLOW`.

| `status` | Definition |
| --- | --- |
| `mapped` | Existence-proof outcome. `decision` is `DENY` or `ALLOW`. On `host-PEP-alone`, `tip_pins.pep` is the pep install SHA. On `stack`, `tip_pins.pep` and `tip_pins.supply_gate` are the sibling install SHAs, and `joint` may be null. Not valid on `monitor-alone` |
| `stub` | Monitor-alone placeholder. `decision` is JSON `null`. Not valid on `host-PEP-alone` or `stack`. Pins may be null |
| `not_applicable` | This arm is not the control for the threat. `decision` is JSON `null`. Valid on `monitor-alone`, `host-PEP-alone`, and `stack`. Pins may be null |
| `not_mediated` | Coverage / honesty outcome for a threat this gate does not mediate. `decision` is JSON `null`. `residual_asr` is JSON `null`. Pins may be null. Valid on `monitor-alone`, `host-PEP-alone`, and `stack`. Not a measured rate |

### `residual_asr`, `no_asr_claim`, and the claim cite

`residual_asr` is a nullable slot only. The schema accepts JSON `null` and no other value. Null means N/A. It is not a measured attack-success rate. Every arm outcome carries the slot. This delta does not add a numeric ASR.

`no_asr_claim` is required and is the const `true`.

The public/EOI claim cite stays the pep diligence tip. On the seed index, `claim_cite.lineage` is `1d0f380` and `claim_cite.lineage_sha` is `1d0f3809a4a16d4a6ac3524b287cf719f192e1f9` (`claim_cite.scope` is `public_eoi`; `claim_cite.package` is `agent-control-lab-pep`). This delta does not change that cite. It stays until a measured table exists and Cyber has passed it.

Cyber card C4 is the adopted Lab ASR rule (Cyber §4 CLEAN / Glenn decision), restated in `ACL_Metric_Definitions_Note_B3_2026-09-23`. ASR letters are admissible only for `monitor-alone` and `stack`, only with a stated attack-variant generator (not authored fixtures alone), only with status `not_mediated` counted as reached, and only after a Cyber pass records `table_id`. `host-PEP-alone` is always a coverage fraction or counts, never ASR. Until that pass, Lab prose writes "reached-tool fraction" or publishes counts. This schema still stores `residual_asr` as JSON `null` only and keeps `no_asr_claim` `true`.

### `benign_twin_of`

Optional. Type string or JSON `null`. The string is a `threat_id`: the same pattern `^acl-mc-[a-z0-9]+(?:-[a-z0-9]+)*$`. It is a pointer to the attack row this benign row twins. JSON `null` if this row is not a benign twin. This delta does not add benign-twin rows.

### Counters

Chosen counter names are the Evidence Corpus Plan appendix B set, one snake_case form, recorded once on the row (not repeated inside each arm): `attempted`, `reached_tool`, `attempted_benign`, `blocked_benign`.

Each key is optional. The value is a trial count: JSON `null`, or an integer ≥ 0. A float, a boolean, a string, or an integer below 0 is invalid. A counter is not an attack-success rate.

| Field | Definition |
| --- | --- |
| `attempted` | Attack trials for this row |
| `reached_tool` | Attack trials that reached the tool |
| `attempted_benign` | Benign trials for this row |
| `blocked_benign` | Benign trials the gate blocked |

`existence_proof_only` is a required boolean. The seed rows stay `true`. When `existence_proof_only` is `true`, every counter must be JSON `null` if the key is present. Absent keys are still valid, so a `measured-corpus-row-v0` row validates unchanged. A later row may set `existence_proof_only` to `false` and store counts. Those counts do not fill `residual_asr`, and they do not change `no_asr_claim` or the claim cite.

### `table_id`

Optional. Type string or JSON `null`. A string has minimum length 1; the empty string is invalid. It is a measured-table id. JSON `null` when no table is recorded. This delta stores no table.

### `plane`

Optional Lab plane for this row. The value is `host`, `supply`, `joint`, `complementarity`, or JSON `null`.

| Value | Definition |
| --- | --- |
| `host` | Covers the pep/runtime gate |
| `supply` | Covers the supply gate |
| `joint` | The two-gate story |
| `complementarity` | The monitor-versus-gate distinction |
| JSON `null` | Unset |

`plane` is not a `joint_story` step label. `pep` and `supply-gate` are not `plane` values.

Fixture `path` values point at `eval/…` in the named repo. This tree does not vendor those directories. See [`docs/measured-corpus-v0.md`](../../../docs/measured-corpus-v0.md). That filename is historical (v0 seed doc). The v1 field definitions live in this schema README.

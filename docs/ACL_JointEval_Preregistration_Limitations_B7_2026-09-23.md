# ACL joint-eval preregistration and limitations (B7)

**Brand:** Agent Control Lab. **Licence:** Apache-2.0.

**Artefact id:** `ACL_JointEval_Preregistration_Limitations_B7_2026-09-23`.

**Sealed:** 2026-09-23. This file is the frozen in-tree text. `b7_prereg_hash` is the SHA-256 of these bytes. `table_id_candidate` binds that hash to the paired-runner schema version and the pin set below. The paired runner reads this file from the joint-eval tree. It does not fetch a writing vault at runtime. The hash is not stored in this file.

## Status separation

Three statuses stay distinct.

- Soft is this writing note.
- EngClear is a cyber pass. Soft is not EngClear.
- A Cyber C4 table mint is a later `table_id`. EngClear is not a C4 table mint.
- This candidate does not unlock funding.

`table_id` on the public paired runner document stays JSON `null` until Cyber C4 mints a real table. `residual_asr` stays JSON `null`. Letters ASR stays null. `no_asr_claim` stays true on the measured-corpus seed. The paired runner's counts are paired existence / provisional attack-success counts for one authored fixture each. They are not a residual ASR and not a letters ASR.

## Claim cite and pins

Public/EOI claim cite stays pep diligence tip **`1d0f380`** (`1d0f3809a4a16d4a6ac3524b287cf719f192e1f9`). The claim cite is not an install pin.

| Role | SHA |
| --- | --- |
| pep install pin | `ffd048a228dd2c8193418db6bebbab7cd339cd08` |
| supply-gate install pin | `dca0aeb4d7bc8f6f02cd461842275ac655768022` |
| claim cite | `1d0f3809a4a16d4a6ac3524b287cf719f192e1f9` |

Paired-runner schema version bound into `table_id_candidate`: `acl-paired-existence-v1`.

## What this note limits

The measured-corpus seed keeps `runner_implemented` false. The paired runner sets `runner_implemented` true only on its own document. That flag does not mint `table_id`.

Host-PEP-alone is coverage or counts when a later table exists. It is not an ASR arm. Monitor-alone control-on stays a stub in this tree. There is no monitor evaluator here.

This note does not authorise a filled `residual_asr`, a letters ASR, a conformance claim, an SLSA claim, or a kernel fence. B9's fence-outcome stub is a pattern cite of arXiv:2609.21284 and does not claim that paper's 17/17.

## Provisional field

Until Cyber C4 mints a table, the paired runner emits:

- `table_id`: JSON `null`
- `residual_asr`: JSON `null`
- `table_id_candidate`: SHA-256 of the canonical preimage (this file's hash, schema version, claim cite, pep install pin, supply-gate install pin)
- `b7_prereg_hash`: SHA-256 of this file

Cyber may copy `table_id_candidate` into `table_id` later. That copy is a Cyber action. This file does not perform it.

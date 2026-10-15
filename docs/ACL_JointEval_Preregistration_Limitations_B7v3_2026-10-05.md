# ACL joint-eval preregistration and limitations (B7 v3)

**Brand:** Agent Control Lab. **Licence:** Apache-2.0.

**Artefact id:** `ACL_JointEval_Preregistration_Limitations_B7v3_2026-10-05`.

**Supersedes:** `ACL_JointEval_Preregistration_Limitations_B7v2_2026-10-05`, which superseded `ACL_JointEval_Preregistration_Limitations_B7_2026-09-23`. Both stay in this tree byte-identical as historical seals. v3 changes only the supply-gate install pin and records why. Every limitation, status rule and provisional-field rule below is carried over unchanged.

**Sealed:** 2026-10-05. This file is the frozen in-tree text. `b7_prereg_hash` is the SHA-256 of these bytes. `table_id_candidate` binds that hash to the paired-runner schema version and the pin set below. The paired runner reads this file from the joint-eval tree. It does not fetch a writing vault at runtime. The hash is not stored in this file.

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
| pep install pin | `76c6d4bedd7a2702a55513ae2ddbd17f8d9ccac9` |
| supply-gate install pin | `7044a313dffc60e08b26366950328f9025c56310` |
| claim cite | `1d0f3809a4a16d4a6ac3524b287cf719f192e1f9` |

Paired-runner schema version bound into `table_id_candidate`: `acl-paired-existence-v1`.

## Why v3

v2 pinned supply-gate `f99b41d`. v3 pins supply-gate `7044a31`, so a host that installs joint-eval beside supply-gate `7044a31` resolves one supply-gate commit. The only commit between them changes `scripts/lab_brand_wall.py` and its tests. No supply-gate runtime code, fixture or receipt changes, and no joint-eval receipt changes.

v3 is a new seal, not an edit of v2. Its `b7_prereg_hash` and `table_id_candidate` therefore differ from v2's.

## Why v2 (carried over)


The v1 pep install pin was `ffd048a` (pep 0.3.3). v2 pins pep `76c6d4b` (pep 0.5.0), which adds two binding changes:

- **Approvals.** pep ADR-0002 binds single-use approvals to a principal attested by the host.
- **Capability tokens.** pep ADR-0003 binds standing capability tokens to holders listed in policy.

The stub policy moves from `0.1.0-stub` to `0.2.0-stub`.

The joint story's approval-binding step and the evasion tests attest `lab.demo.agent`. The prose-bypass step and the official row attest no principal, because both deny before the PEP reads one. Their DENY classes are unchanged. The two joint_story PEP receipts change `policy_version` and `envelope_hash`, because the fixture envelope metadata records the policy version.

v2 is a new seal, not an edit of v1. Its `b7_prereg_hash` and `table_id_candidate` therefore differ from v1's.

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

# Measured corpus v0

**Brand:** Agent Control Lab. **Licence:** Apache-2.0.

## Purpose

v0 is a **contract** for a future three-arm runner: a frozen row schema and a seed map of 25 threats. It does not run those rows. It is not a measured attack-success table. **No ASR.**

The official existence-proof remains `python -m joint_eval.demo` over `eval/joint_story/`. See [`docs/coverage-limits.md`](coverage-limits.md).

## Row fields

| Field | v0 rule |
| --- | --- |
| `threat_id` | Stable id, `acl-mc-…` |
| `setup` | What the case is |
| `expected_effect` | Existence-proof or unmapped slot. Not a rate |
| `arms` | `monitor-alone`, `host-PEP-alone`, `stack` |
| Outcome `decision` | `DENY` or `ALLOW` when `status` is `mapped`; JSON `null` when `status` is `stub` or `not_applicable` |
| Outcome `residual_asr` | JSON `null` only. The slot is reserved. It is not a filled claim |
| Outcome `tip_pins` | Sibling install SHAs when that arm is mapped. `host-PEP-alone` mapped carries the pep install SHA. `stack` mapped carries the pep and supply-gate install SHAs (supply-related mapped rows included). `joint` stays `null` until a diligence note records the joint tip after this contract lands. `stub` and `not_applicable` may leave every pin null |

`monitor-alone` is `stub` or `not_applicable`. Its `decision` is `null`. `stub` is not a valid status for `host-PEP-alone` or `stack`. This schema does not store a monitor score.

`host-PEP-alone` is `mapped` only for a pep existence-proof DENY. Supply pin and HEAD-verify threats leave that arm `not_applicable`: the PEP is not the supply control.

`stack` is `mapped` only where `eval/joint_story/` already has a fixture for that class. Other stack outcomes stay `null`.

## Seed map

[`eval/measured_corpus/index.json`](../eval/measured_corpus/index.json) has 25 rows:

- 11 pep DENY rows (10 `eval/corpus/` classes plus the official `eval/` deny row), pinned at the pep install SHA
- 7 supply pin and post-checkout HEAD-verify rows (6 DENY fixtures and the pin-and-verify ALLOW fixture), pinned at the supply-gate install SHA
- 4 Noul taxonomy slots: `override`, `no_rules_persona`, `embedded_instruction`, `tool_abuse`. No fixture and no arm decision. They are class labels, not scores
- 3 threat-model classes: `approve-then-mutate` (same existence-proof as pep approval binding, not a second trial), `multi-session-plant`, `deferred-tool` (no fixture)

Pointers name sibling paths and joint_story paths. Sibling trees are not copied. The two unmapped threat-model classes and the four Noul slots are in the map so the contract names them. They are not results.

`approve-then-mutate` is the threat-model name for the pep approval-binding DENY. `multi-session-plant` and `deferred-tool` are not the same row as `late_effect_fence`.

## Claim cite

Public/EOI claim cite stays pep diligence tip **`1d0f380`** (`1d0f3809a4a16d4a6ac3524b287cf719f192e1f9`) until there is a measured table and Cyber PASS.

This seed does not lift that bar. `existence_proof_only` and `no_asr_claim` are frozen `true`. `residual_asr` cannot hold a number in this schema. `runner_implemented` and `measured_attack_success_claimed` are frozen `false`.

Install pins in `joint_eval/pins.py` are how this harness installs packages. A row may copy those SHAs into `tip_pins` when an arm is mapped to that package. `tip_pins.joint` is `null` in v0. After this contract is on the joint repo tip, a later diligence note may record that tip. Recording it does not change the `1d0f380` claim cite.

## Out of this contract

- A three-arm runner or any harness loop
- GitHub Actions workflow edits
- A filled residual ASR, a monitor score, or any other metric
- Copies of sibling fixture trees
- Payments-domain cases
- Changes to coverage-limit or EOI claim prose elsewhere in this repo

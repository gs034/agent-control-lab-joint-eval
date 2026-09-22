# Measured corpus v0

**Brand:** Agent Control Lab. **Licence:** Apache-2.0.

## Purpose

v0 is a **contract** for a future three-arm runner: a JSON Schema for one corpus row, and a small seed map that points existing joint existence-proof classes at that schema.

It is not the runner. Nothing in this tree executes the seed. It is not a measured attack-success rate, not a classifier scoreboard, and not a paper reproduction. **No ASR.**

The official existence-proof remains `python -m joint_eval.demo` over `eval/joint_story/`. See [`docs/coverage-limits.md`](coverage-limits.md).

## Three arms

| Arm | What a future runner would call | How the seed maps it |
| --- | --- | --- |
| `pep` | Pinned `agent-control-lab-pep` (`pep.evaluate` / `pep.gated_invoke`) | joint_story plane `pep` |
| `supply_gate` | Pinned `agent-control-lab-supply-gate` (`supply_gate.evaluate`) | joint_story plane `supply-gate` |
| `joint` | Both planes, as the scripted joint story already does | The story index itself, not a third package |

`arm` is the corpus tag. `taxonomy.plane_in_story` keeps the joint_story spelling (`pep`, `supply-gate`, `joint-story`).

## Seed map

[`eval/measured_corpus/index.json`](../eval/measured_corpus/index.json) lists five rows:

- Plugin4Shell-class supply DENY
- pin-without-verify supply DENY
- monitor-bypass / prose-as-policy PEP DENY
- approval-binding mismatch PEP DENY (bind class)
- one `joint` row pointing at `eval/joint_story/index.json`

Fixture paths are pointers. Sibling `eval/corpus/` and supply-gate matrices stay in those repositories. This seed is enough to prove the row contract. It is not a full matrix.

`expected_decision` may be `DENY` or `ALLOW`. Every v0 seed row is `DENY`, because that is what the mapped fixtures are. An `ALLOW` label would still not be an attack-success measurement.

## Claim cite

Public/EOI claim cite stays the pep diligence tip **`1d0f380`** lineage:

`1d0f3809a4a16d4a6ac3524b287cf719f192e1f9` on [agent-control-lab-pep](https://github.com/gs034/agent-control-lab-pep).

This corpus does not lift that claim bar. On every v0 row the schema freezes:

- `existence_proof_only`: `true`
- `no_asr_claim`: `true`

The seed envelope also freezes `runner_implemented: false` and `measured_attack_success_claimed: false`. Sibling install pins in `joint_eval/pins.py` are how this harness installs packages. They are not a claim cite, and this document does not bump them.

## Out of this contract

- A three-arm runner or any harness execution loop
- GitHub Actions workflow edits
- ASR numbers, classifier scoreboards, or external benchmark metrics
- Copies of sibling fixture trees
- Changes to coverage-limit or EOI claim prose elsewhere in this repo

# ADR-0001 — Joint evaluator architecture

- **Status:** Accepted
- **Date:** 2026-09-21
- **Brand:** Agent Control Lab
- **Licence:** Apache-2.0

## Context

Agent Control Lab publishes two separate public packages:

- host/runtime PEP (`agent-control-lab-pep`)
- host-side supply integrity gate (`agent-control-lab-supply-gate`)

A third artefact is needed: a **joint** existence-proof that a caller can pin both packages and run one fail-closed story. That story is complementary to monitors (not a replacement) and must not claim measured attack success.

Vendoring sibling trees would duplicate policy code, drift from upstream SHAs, and blur the “third separate repo” rule. Floating `main` would make receipts unreproducible.

## Decision

1. **Pin, do not vendor.** Depend on the sibling distributions via PEP 508 `git+https` URLs at documented commit SHAs (`pyproject.toml` + `joint_eval/pins.py`). Pip (or an equivalent installer) places the packages in the environment. This repository does not copy `pep/` or `supply_gate/` source.
2. **Invoke public APIs.** The joint story calls `supply_gate.evaluate` and `pep.evaluate` / `pep.gated_invoke`. Joint fixtures live under `eval/joint_story/` in *this* tree.
3. **Fail-closed demo.** `python -m joint_eval.demo` exits non-zero unless every step is DENY and no tool/install callable runs. Missing imports emit a DENY document and fail — they never become ALLOW.
4. **No model on the path.** The harness does not call an LLM, HTTP model client, or transcript judge. Prose sidecars are data, not `evaluate()` policy input.
5. **No marketplace.** Supply steps use structured envelopes and an in-process observed-HEAD value. There is no live marketplace adapter.
6. **Lab brand only.** Packed keep-out CI (`scripts/lab_brand_wall.py`, `lab-only` / `forbidden-tokens`) mirrors the sibling stdlib pattern.

Pinned SHAs at acceptance:

- pep: `634c2625bb5392e060e38a5ce463bf8b85346a84`
- supply-gate: `7e36aa04fa70fd647e8569ab832f58325e15d979`

## Consequences

- CI needs network once per job to fetch the pinned git commits.
- Joint receipts freeze sibling receipt *semantics*. PEP live `timestamp` is not part of the identity (sibling `issue_receipt` stamps evaluate time).
- Bumping a sibling pin is a deliberate change to both `pyproject.toml` and `joint_eval/pins.py`, plus a receipt re-freeze if deny reasons change.
- Readers can treat this repo as a caller, not a second PEP or a second supply gate.

## Non-goals

- Not an LLM / CoT / transcript judge.
- Not a measured ASR / classifier claim.
- Not a monorepo, subtree vendor, or git submodule of the siblings.
- Not production SaaS, marketplace, or live git-host integration.
- Not a replacement for monitors.

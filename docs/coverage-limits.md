# Coverage limits (joint evaluator)

This harness is an **existence-proof**. Brand: Agent Control Lab. Apache-2.0.

## In coverage

- One scripted joint story that **DENYs** on:
  - Plugin4Shell-class supply (skip-verify + HEAD mismatch)
  - pin-without-verify supply (omitted observed HEAD)
  - monitor-bypass / prose-as-policy PEP
  - approval-binding mismatch PEP (bind class)
  - rug-pull two-envelope supply (pinned ALLOW, then `head_mismatch` DENY). Existence proof only. The unchanged-pin runtime case is `not_mediated`, not a DENY.
- Frozen receipts for those rows (PEP `timestamp` compared semantically, not as identity).
- A standalone ControlArena directory export (`trajectory.jsonl`, `tools.json`, `metadata.json`) written from those fixtures and frozen receipts. See [`control-arena-export.md`](control-arena-export.md).
- A paired control-off / control-on runner (`python -m joint_eval.paired_runner`) over monitor, PEP, and stack. Output is paired existence / provisional attack-success counts. `table_id` is null pending Cyber C4. `table_id_candidate` and `b7_prereg_hash` name the frozen B7 note. Soft is not EngClear. EngClear is not a C4 table mint. The candidate does not unlock funding. Not a residual ASR.
- Pinned sibling SHAs via git install (no vendored `pep/` or `supply_gate/` trees).
- Fail-closed demo and tests.

## Out of coverage

- **No ASR.** No measured attack-success rate, no classifier scoreboard, no paper reproduction. The directory export keeps `residual_asr` JSON null, `rating` null, and `scores` empty. The paired runner's 0/1 counts are one authored fixture each, not a residual ASR and not a letters ASR.
- Not a ControlArena setting and not an Inspect eval loop. The export writer does not import those packages.
- **Not a monitor replacement.** Monitors may still observe; they are not allow authorities here.
- Not the full pep `eval/corpus/` matrix and not the full supply-gate adapter/update-policy matrix.
- **Not mediation of alternate paths.** The pinned PEP ALLOWs allowlisted calls that carry a prohibited operation as argument data: base64-encoded in `argv`, split across two allowed calls, or nested inside an allowed envelope. Whether the effect happens depends on what the allowed tool does with its arguments, which the PEP does not mediate. Unknown keys under `invoke` or `schema_fields` in the Lab envelope shape are dropped before the args schema is applied. It never sees a follow-on stdin payload (`not_mediated`). A second tool name and identical retries are DENY. See [`tests/test_evasion_alternate_paths.py`](../tests/test_evasion_alternate_paths.py). These are existence-proof fixtures from arXiv:2609.30217 strategy classes, not a measured ASR.
- **No measurement-validity fields yet.** Rows carry no injection locator, argument-level success predicate or paired outcome. See [`measurement-validity.md`](measurement-validity.md) for the proposal, which awaits a schema decision.
- Not production enforcement, multi-tenant SaaS, marketplace install, or live git-host checkout.
- Not an LLM / CoT / transcript judge on evaluate or deny.
- Not a claim that pinning git SHAs replaces post-checkout verify in production hosts (the supply-gate still requires observed HEAD).

If a sibling pin changes deny reasons, freeze new expected receipts. Do not backfill metrics.

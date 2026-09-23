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
- Pinned sibling SHAs via git install (no vendored `pep/` or `supply_gate/` trees).
- Fail-closed demo and tests.

## Out of coverage

- **No ASR.** No measured attack-success rate, no classifier scoreboard, no paper reproduction. The directory export keeps `residual_asr` JSON null, `rating` null, and `scores` empty.
- Not a ControlArena setting and not an Inspect eval loop. The export writer does not import those packages.
- **Not a monitor replacement.** Monitors may still observe; they are not allow authorities here.
- Not the full pep `eval/corpus/` matrix and not the full supply-gate adapter/update-policy matrix.
- Not production enforcement, multi-tenant SaaS, marketplace install, or live git-host checkout.
- Not an LLM / CoT / transcript judge on evaluate or deny.
- Not a claim that pinning git SHAs replaces post-checkout verify in production hosts (the supply-gate still requires observed HEAD).

If a sibling pin changes deny reasons, freeze new expected receipts. Do not backfill metrics.

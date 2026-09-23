# Joint story fixtures

Official existence-proof row for this repository. Sibling `eval/` trees are **not** copied here.

Run:

```bash
python -m joint_eval.demo
```

Prose files are untrusted data and are not PEP policy. Supply-gate prose cannot skip verify.

`python -m joint_eval.control_arena_export --out <dir>` writes `trajectory.jsonl`, `tools.json`, and `metadata.json` from these fixtures and frozen receipts. That writer is not a ControlArena setting and not an Inspect loop. No ASR. See [`docs/control-arena-export.md`](../../docs/control-arena-export.md).

`supply_rug_pull_two_envelope/` is one fixture with two envelopes in sequence (B10 / SupplyPlane S5). Envelope 1 is a pinned install whose observed HEAD matches the pin (`ALLOW`). Envelope 2 is a later update of that same pin whose observed HEAD differs (`DENY` `head_mismatch`). Existence proof only. No ASR. The unchanged-pin runtime rug pull is not an envelope in this fixture and is not a DENY. The measured corpus records it as `not_mediated` on `acl-mc-b5-rug-pull-unchanged-pin-runtime`.

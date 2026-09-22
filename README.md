# Agent Control Lab — joint evaluator harness

Public-goods, Apache-2.0 **joint existence-proof** over two separate Lab packages:

- [agent-control-lab-pep](https://github.com/gs034/agent-control-lab-pep) (host/runtime PEP)
- [agent-control-lab-supply-gate](https://github.com/gs034/agent-control-lab-supply-gate) (host-side supply integrity gate)

This repository **invokes** those packages at **pinned GitHub commit SHAs**. It does **not** vendor their source trees and is **not** a monorepo with them.

**Brand:** Agent Control Lab only. Not a commercial product.

**Complementary to monitors — not a replacement.** Existence-proof only. **No ASR.** This tree does not measure attack success.

## What this is

One scripted joint case (`python -m joint_eval.demo`) that produces frozen receipts for:

1. **Plugin4Shell-class / pin-without-verify supply DENY** — advertised pin plus skip-verify / omitted HEAD; post-checkout verify still required.
2. **Monitor-bypass / prose-as-policy PEP DENY** — monitor SAFE / please-allow coax is untrusted data, not policy.
3. **Approval-binding mismatch PEP DENY** (bind class) — single-use TTL approval frozen to `tool_name` plus canonical args; substitution is DENY.

Fail-closed: every step must **DENY**, and `gated_invoke` / install must not run. Missing sibling packages, parse faults, or an unexpected ALLOW fail the demo.

There is **no LLM** on the evaluate/deny path. There is **no marketplace**.

## How to run

Requires Python 3.11+. Network is needed once to install the pinned sibling packages from GitHub.

```bash
python -m pip install -e ".[dev]"
python -m joint_eval.demo
pytest
python3 scripts/lab_brand_wall.py
```

`python -m joint_eval.demo` prints the joint story document (pins, DENY receipts, coverage limits) and exits 0 only when every step DENY’d without invoke.

## Pin / install (no vendoring)

Sibling code is pulled as ordinary Python distributions via **PEP 508 direct URLs** in `pyproject.toml`:

| Package | Repository | Pinned SHA |
| --- | --- | --- |
| `agent-control-lab-pep` | [gs034/agent-control-lab-pep](https://github.com/gs034/agent-control-lab-pep) | `6f5c0451168dc9c25244a56789433e6ca1b53d87` |
| `agent-control-lab-supply-gate` | [gs034/agent-control-lab-supply-gate](https://github.com/gs034/agent-control-lab-supply-gate) | `78cf6be05d5a1024c9b3a6179fcd55bf8c35847a` |

Equivalent pip form:

```text
agent-control-lab-pep @ git+https://github.com/gs034/agent-control-lab-pep.git@6f5c0451168dc9c25244a56789433e6ca1b53d87
agent-control-lab-supply-gate @ git+https://github.com/gs034/agent-control-lab-supply-gate.git@78cf6be05d5a1024c9b3a6179fcd55bf8c35847a
```

That clones the commit into the environment’s `site-packages`. This repo keeps only **joint** fixtures under `eval/joint_story/` and calls public APIs (`pep.evaluate` / `pep.gated_invoke`, `supply_gate.evaluate`). Do not copy `pep/` or `supply_gate/` trees here.

Pins are also listed in `joint_eval/pins.py`. Bump both files together.

## Coverage limits

See [`docs/coverage-limits.md`](docs/coverage-limits.md) and [`docs/threat-model.md`](docs/threat-model.md). Short version:

- Named deny *classes* only (bind class [arXiv:2609.21081](https://arxiv.org/abs/2609.21081); Plugin4Shell-class supply; monitor-bypass class [arXiv:2609.19587](https://arxiv.org/abs/2609.19587)).
- Not a measured attack-success study. No ASR.
- Not a production control plane, marketplace, or live git host.
- Monitors remain useful observers; they are not allow authorities in this story.

## Layout

| Path | Role |
| --- | --- |
| `joint_eval/` | Harness: pins, story runner, `python -m joint_eval.demo` |
| `eval/joint_story/` | Joint fixtures + frozen expected receipts |
| `docs/adr/ADR-0001-joint-eval-architecture.md` | Why pin-and-invoke, not vendor |
| `docs/threat-model.md` | Threat classes by arXiv / pattern name |
| `docs/coverage-limits.md` | What this existence-proof does not claim |
| `scripts/lab_brand_wall.py` | Packed Lab-only keep-out (stdlib Python) |
| `CONTRIBUTING.md` | Lab-only keep-out |

## License

Apache License 2.0. See `LICENSE`. First-party Python carries `SPDX-License-Identifier: Apache-2.0`.

**Brand:** Agent Control Lab. Public-goods / Navigators / philanthropic AI-control reference. Not a commercial product.

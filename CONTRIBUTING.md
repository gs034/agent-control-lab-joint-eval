# Contributing (Agent Control Lab)

This repository is a public-goods, Apache-2.0 **Agent Control Lab** joint evaluator harness. Contributions must stay Lab-only.

This is a **third separate repository**. It is not a monorepo with `agent-control-lab-pep` or `agent-control-lab-supply-gate`. Do not vendor those trees.

## Accept

- Lab-branded joint fixtures, receipt freezes, ADRs, threat notes, and coverage-limit docs.
- Pin bumps of the sibling Git SHAs in `pyproject.toml` **and** `joint_eval/pins.py` together.
- Diligence docs that do not invent attack-success metrics or weaken fail-closed DENY.
- Apache-2.0 SPDX on first-party Python.

## Reject

- Commercial product, bank, or marketplace adapters and live git hosts.
- Production SaaS UI.
- Brand strings, SKU language, and source trees from commercial or bank lines. CI enforces the keep-out list (`scripts/check_lab_only.sh`, workflow `lab-only` / job `forbidden-tokens`; also `scripts/lab_brand_wall.py`). Do not add those tokens to files, diffs, commit subjects, or branch names.
- Acquisition-origin notices or other-product catalogue language.
- LLM / model judges on the evaluate or deny path.
- Copying sibling `pep/` or `supply_gate/` packages into this tree.
- Measured ASR claims, marketplace integrations, or fail-open demos.

If the brand wall fails, remove the hit. Do not add a bypass in first-party docs.

Plugin4Shell-class is a threat-pattern name used in the supply-gate package. It is allowed here. It is not a vendor product.

## How to test

```bash
python -m pip install -e ".[dev]"
python -m joint_eval.demo
python -m joint_eval.control_arena_export --out /tmp/acl-control-arena-export
pytest
bash scripts/check_lab_only.sh
python3 scripts/lab_brand_wall.py
```

The Lab-only keep-out is stdlib Python (`scripts/lab_brand_wall.py`; `scripts/check_lab_only.sh` is a wrapper). Ripgrep is not required.

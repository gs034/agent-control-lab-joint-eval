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
python -m joint_eval.control_arena_export --out ./control-arena-export
pytest
python3 scripts/lab_brand_wall.py
```

`python -m joint_eval.control_arena_export` writes a ControlArena directory export (`trajectory.jsonl`, `tools.json`, `metadata.json`) from `eval/joint_story/` fixtures and frozen receipts. It does not import ControlArena or Inspect, does not run a setting, and does not measure attack success. See [`docs/control-arena-export.md`](docs/control-arena-export.md). Fixture folders and sidecar files must stay inside the fixture root: an index `dir` or corpus `path` that is absolute, uses `..`, or passes through a symlink is refused, and a symlinked or non-regular sidecar file is refused. The export and the paired runner reach their output directory by a descriptor walk from `/`: each path component is opened with `O_DIRECTORY | O_NOFOLLOW` relative to the one before it and checked while it is held, so no directory on the way can be swapped after its check. They refuse: a symlink in the output path that another user owns, a directory on the way (the parent or any ancestor) that another user owns or anyone can write without the sticky bit, an output directory owned by another user or world-writable, and an output name that is a link. Each file is written to a new temporary name and renamed into place. A symlinked `eval/` or `eval/joint_story` is refused, and the supply-gate policy and allowlist files are checked before they are handed to supply-gate. The fixture root is the source checkout that directly contains the `joint_eval` package (its `pyproject.toml` must name `agent-control-lab-joint-eval`), or it is given with `--root`. No other parent directory and not the working directory is searched, so a package installed outside its checkout needs `--root`. Error messages and the paired summary write control characters from fixtures (ESC, CR, newline, DEL, C1) as visible `\xNN` escapes.

`python -m joint_eval.paired_runner` runs the same envelope twice (control-off, then control-on) on the monitor, PEP, and stack arms and writes a JSON table plus a CSV. Counts are **paired existence / provisional attack-success counts** pending a Cyber `table_id` under C4. They are not a residual ASR and not a letters ASR. `table_id` and `residual_asr` stay null. `table_id_candidate` and `b7_prereg_hash` are provisional addresses of the frozen B7 note ([`docs/ACL_JointEval_Preregistration_Limitations_B7v4_2026-10-15.md`](docs/ACL_JointEval_Preregistration_Limitations_B7v4_2026-10-15.md); earlier seals v1 and v2 are kept beside it). Soft is not EngClear. EngClear is not a C4 table mint. The candidate does not unlock funding. `runner_implemented` is true on that document only. The measured-corpus seed keeps `runner_implemented` false. Claim cite stays pep `1d0f380`. This is not a ControlArena setting and not an Inspect loop.

```bash
python -m joint_eval.paired_runner --out ./paired/acl-paired.json
```

That command uses the in-tree joint-story fixtures when sibling checkouts are unset. The 28 measured-corpus rows that have fixtures (the shared set in the 20–50 range) need pinned checkouts, not vendored trees:

```bash
export ACL_PEP_ROOT=/path/to/agent-control-lab-pep
export ACL_SUPPLY_GATE_ROOT=/path/to/agent-control-lab-supply-gate
python -m joint_eval.paired_runner --out ./paired/acl-paired.json
```

`ACL_PEP_ROOT` and `ACL_SUPPLY_GATE_ROOT` must be git checkouts whose `HEAD` is the SHA in `joint_eval/pins.py`. `--pep-root` and `--supply-root` are the same pins. A JSON file is written to `--out` and a CSV with the same stem is written beside it. A CSV string cell that starts with `=`, `+`, `-`, `@`, tab or CR gets a leading `'` so a spreadsheet does not read it as a formula; the JSON keeps the original string. A short summary goes to stdout.

### Sibling pin check

A `HEAD` equal to the pin is not enough on its own: a `.git/HEAD` file that names the pin and holds no objects would pass, and so would a real checkout at the pin with an edited fixture. `joint_eval/sibling_pin.py` checks the bytes the runner uses:

- The checkout needs a `.git` directory (a `.git` file or link is refused). Its repository-local git config may set only a short list of inert keys (`core.*` format and filemode keys, `remote.*.url`, `remote.*.fetch`, `branch.*.remote`, `branch.*.merge`). Any other key, such as `extensions.partialClone`, `remote.*.promisor`, `core.fsmonitor`, `include.path` or a filter, is refused before git reads an object. A SHA-256 repository is refused.
- The pinned commit and each tree on the way to a fixture are read with `git cat-file` and hashed in Python. An object whose bytes do not hash to its id is refused, so a planted loose object cannot stand in for the pinned tree.
- Each fixture file is read from the worktree, its git blob id is computed from the exact bytes read, and that id must equal the blob id the pinned tree lists for the path. A file the pinned tree does not list is refused when the runner looks for it, and so is a listed file the checkout lacks. The supply-gate update policy and allowlist are passed to `supply_gate` as private copies of the checked bytes.
- Git runs with `--git-dir`, no system or global config, inherited `GIT_*` variables dropped, hooks and fsmonitor off, a timeout, and `GIT_ALLOW_PROTOCOL` set to a name that is not a protocol, so no transport or remote helper can start. Only `config --list`, `rev-parse` and `cat-file` run.

Any failure stops the run with a `paired-runner unavailable` message. No table is written.

`python -m joint_eval.demo` prints the joint story document (pins, DENY receipts, coverage limits) and exits 0 only when every step DENY’d without invoke.

## Pin / install (no vendoring)

Sibling code is pulled as ordinary Python distributions via **PEP 508 direct URLs** in `pyproject.toml`:

| Package | Repository | Pinned SHA |
| --- | --- | --- |
| `agent-control-lab-pep` | [gs034/agent-control-lab-pep](https://github.com/gs034/agent-control-lab-pep) | `653ee4a819c55bb1fadab2421aa62336352ce2e3` |
| `agent-control-lab-supply-gate` | [gs034/agent-control-lab-supply-gate](https://github.com/gs034/agent-control-lab-supply-gate) | `d5e5ac11fd4ae47f428d2770bdda0b8df0b1de59` |

Equivalent pip form:

```text
agent-control-lab-pep @ git+https://github.com/gs034/agent-control-lab-pep.git@653ee4a819c55bb1fadab2421aa62336352ce2e3
agent-control-lab-supply-gate @ git+https://github.com/gs034/agent-control-lab-supply-gate.git@d5e5ac11fd4ae47f428d2770bdda0b8df0b1de59
```

That clones the commit into the environment’s `site-packages`. This repo keeps only **joint** fixtures under `eval/joint_story/` and calls public APIs (`pep.evaluate` / `pep.gated_invoke`, `supply_gate.evaluate`). Do not copy `pep/` or `supply_gate/` trees here.

Pins are also listed in `joint_eval/pins.py`. Bump both files together. These SHAs are install pins. The public/EOI claim cite stays pep `1d0f380` and is not an install pin. Soft is not EngClear.

**Updating an existing environment.** pip keeps an already-installed sibling whose version number has not changed, so after a pin bump `python -m pip install -e ".[dev]"` can leave the old commit in `site-packages`. The demo and the paired runner read pip's install record (PEP 610 `direct_url.json`) for both siblings before they run, and fail closed (exit 1, no output) when the installed commit is not the pinned one, when the record is missing (a plain or editable local install), or when the imported module is not a file that distribution installed. `tests/test_installed_pins.py` checks the same. Recovery:

```bash
python -m pip uninstall -y agent-control-lab-pep agent-control-lab-supply-gate
python -m pip install -e ".[dev]"
```

A fresh environment (the CI runner is one) needs no extra step.

## Coverage limits

See [`docs/coverage-limits.md`](docs/coverage-limits.md), [`docs/threat-model.md`](docs/threat-model.md), and the Lab-wide synthesis across both planes, [`docs/lab-threat-model.md`](docs/lab-threat-model.md). Short version:

- Named deny *classes* only (bind class [arXiv:2609.21081](https://arxiv.org/abs/2609.21081); Plugin4Shell-class supply; monitor-bypass class [arXiv:2609.19587](https://arxiv.org/abs/2609.19587)).
- Not a measured attack-success study. No ASR.
- [`eval/measured_corpus/`](eval/measured_corpus/) is the v1 delta on the v0 seed rows for a future three-arm runner (`monitor-alone`, `host-PEP-alone`, `stack`), not a scoreboard. The schema accepts `measured-corpus-row-v0` and `measured-corpus-row-v1`. The 28 v0 rows keep monitor-alone as a stub. [`eval/measured_corpus/binding.md`](eval/measured_corpus/binding.md) maps each threat to arm status (`mapped`, `stub`, `not_applicable`, `not_mediated`). [`eval/measured_corpus/coverage-b5.md`](eval/measured_corpus/coverage-b5.md) is the B5 coverage classification (`table_id` `acl-coverage-b5-v1`): not-mediated honesty rows, no new DENY reason codes, no ASR. Public/EOI claim cite stays pep diligence tip `1d0f380`. See [`docs/measured-corpus-v0.md`](docs/measured-corpus-v0.md) (historical v0 seed doc; v1 field definitions are in [`eval/measured_corpus/schema/README.md`](eval/measured_corpus/schema/README.md)).
- Not a production control plane, marketplace, or live git host.
- Monitors remain useful observers; they are not allow authorities in this story.

## Layout

| Path | Role |
| --- | --- |
| `joint_eval/` | Harness: pins, story runner, `python -m joint_eval.demo`, paired runner, ControlArena directory export |
| `docs/control-arena-export.md` | Directory export from fixtures and receipts. Not a setting. No ASR |
| `eval/joint_story/` | Joint fixtures + frozen expected receipts |
| `eval/measured_corpus/` | Row schema (v1 delta; v0 seed rows still valid) + seed map. Not a runner |
| `docs/measured-corpus-v0.md` | Historical v0 seed doc. v1 field definitions are in `eval/measured_corpus/schema/README.md` |
| `docs/adr/ADR-0001-joint-eval-architecture.md` | Why pin-and-invoke, not vendor |
| `docs/threat-model.md` | Threat classes by arXiv / pattern name |
| `docs/lab-threat-model.md` | Lab-wide threat model: both planes, trust boundaries, comparison with sandboxing / least privilege / monitoring, non-goals |
| `docs/coverage-limits.md` | What this existence-proof does not claim |
| `scripts/lab_brand_wall.py` | Packed Lab-only keep-out (stdlib Python) |
| `CONTRIBUTING.md` | Lab-only keep-out |

## License

Apache License 2.0. See `LICENSE`. First-party Python carries `SPDX-License-Identifier: Apache-2.0`.

**Brand:** Agent Control Lab. Public-goods / Navigators / philanthropic AI-control reference. Not a commercial product.

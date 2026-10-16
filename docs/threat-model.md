# Joint evaluator threat note (Agent Control Lab)

Public, short note for this **joint existence-proof harness**. Brand: **Agent Control Lab**. Licence: **Apache-2.0**.

This document names threat *classes*. It is not a measured evaluation and not a production assurance case. **No ASR.**

## Planes

The harness is a caller. Enforcement stays in the pinned sibling packages:

| Plane | Package | Role |
| --- | --- | --- |
| Supply integrity | `agent-control-lab-supply-gate` | Pin + allowlisted origin + post-checkout HEAD verify before install/update |
| Host/runtime PEP | `agent-control-lab-pep` | Structured-envelope allowlist, capabilities, single-use TTL approvals |

Monitors, models, MCP hosts, and agent prose are **untrusted relative to those planes**. This joint story is **complementary to monitors, not a replacement**.

## Classes exercised

Each row carries a status as of 14 October 2026. **mitigated**: the pinned sibling package denies the class and a joint-story row shows it at this tip. **accepted residual**: a known gap, written down and accepted. **unmitigated**: a gap the roadmap still owes work on. Work item codes (L3.1 host-side state binding, L3.6 tamper-evident host log, L3.8 persistent single-use grants, L3.10 kill reach into a running tool, L4.1 provider-executed tools, L4.2 alternate-path fixtures and counts, L4.5 a materialiser so HEAD and hook digests are not caller-supplied, L4.6 omission detection, L5 measured efficacy, L6 tagged release) name items in the owner's route-to-production plan, which is not in this repository; the code is the pointer, the phrase is the meaning. A status is a statement about this harness and its pinned siblings, not a measured result; this harness has no measured counts yet (see `docs/measurement-validity.md`).

| Joint step | Class | Citation / pattern name | Existence-proof DENY | Status (14 Oct 2026) |
| --- | --- | --- | --- | --- |
| Supply Plugin4Shell-class | Marketplace/plugin pin that would satisfy a naive SHA pin on a mutable ref / swapped tree, plus skip-verify prose | Plugin4Shell-class (threat pattern name, not a vendor product) | `prose_rejected_as_policy` + `head_mismatch` | mitigated (existence proof at supply-gate `97cfc0b5`; pins pep `88231949` and supply-gate `97cfc0b5` predate the current fixes) |
| Supply pin-without-verify | Pin present, post-checkout HEAD omitted | Plugin4Shell-class family (verify skipped) | `verify_missing` | mitigated (existence proof at supply-gate `97cfc0b5`; pins pep `88231949` and supply-gate `97cfc0b5` predate the current fixes) |
| PEP monitor-bypass / prose-as-policy | Monitor SAFE / please-allow coax treated as policy | Monitor-bypass class ([arXiv:2609.19587](https://arxiv.org/abs/2609.19587)) | `agent_prose_rejected` | mitigated (existence proof at pep `88231949`; pins pep `88231949` and supply-gate `97cfc0b5` predate the current fixes) |
| PEP approval-binding mismatch | HITL/TTL approval for one invoke, args substituted before execute | Bind class ([arXiv:2609.21081](https://arxiv.org/abs/2609.21081)) | `approval_binding_mismatch` | mitigated (existence proof at pep `88231949`; pins pep `88231949` and supply-gate `97cfc0b5` predate the current fixes) |

The four mitigated rows rest on pep `88231949` and supply-gate `97cfc0b5`. On 16 October 2026 the supply-gate pin moved from `009c0cec` to `97cfc0b5`, which adds supply-gate S-7 to S-9, S-11, S-13 and S-14; no measured outcome changed (B7 v6). The console still pins supply-gate `009c0cec` until it moves too. On 15 October 2026 the pins moved to pep `88231949` and supply-gate `009c0cec`, which carry the 14 October 2026 re-scan fixes (B7 v5), and earlier that day from `76c6d4be` and `7044a313` to `653ee4a8` and `d5e5ac11` (B7 v4). Fixture bytes read from a sibling checkout are proven to be the pinned commit's bytes (#30): the pinned commit and trees are hashed in Python and each fixture's blob id must match, so an edited checkout or a bare `.git/HEAD` is refused.

Citations are arXiv identifiers and pattern names only. This tree does not reproduce papers and does not report attack-success rates.

## Harness findings

These rows are about the harness itself, not about a sibling plane. **mitigated** here means this tree's code closes the finding and a named test fails without the fix; **accepted residual** names what is left.

| Finding | Class | Mitigation | Status (15 Oct 2026) |
| --- | --- | --- | --- |
| J-2 | Fixture root picked up from a shared parent directory (`/tmp/eval` used without `--root` when the venv sits under `/tmp`) | Only the directory that directly contains the `joint_eval` package is considered, and only when its `pyproject.toml` names `agent-control-lab-joint-eval` and it holds `eval/joint_story/index.json`; otherwise `--root` is required (`tests/test_fixture_containment.py::test_repo_root_ignores_a_fixture_root_in_a_shared_ancestor`) | mitigated |
| J-3 | Output redirected by swapping a directory above the output's parent between check and open | Descriptor walk from `/` with `O_DIRECTORY \| O_NOFOLLOW` per component; each directory is checked while held, symlinks are followed only when this user or root owns them, and every directory on the walk must be owned by this user or root and not world-writable without the sticky bit. A symlink's owner and target are read from the same link: on Linux the link is opened once with `O_PATH \| O_NOFOLLOW` and both are read from that descriptor. Before this, the owner was read by `lstat` and the target by a second `readlink` by name, so a link swapped between the two was followed with another user's target (`tests/test_output_walk.py`, including a 400-try race gated on the flipper and a deterministic swap at the `readlink` step) | mitigated on Linux; accepted residual on other POSIX hosts, which read the link by name and refuse it when its device, inode, owner, mode or change time differs after `readlink` (an inode reused with the same values in between is not caught), and on hosts without `dir_fd` support, which keep the by-path writer |
| J-4 | CSV formula injection through a corpus `threat_id` or other string cell | The paired CSV writer prefixes `'` to any string cell starting with `=`, `+`, `-`, `@`, tab or CR; JSON keeps the authored string (`tests/test_paired_runner.py::test_csv_neutralises_formula_cells_from_corpus_strings`) | mitigated |
| J-5 | Installed sibling packages not checked against the pins the output states | Before the demo or paired runner runs, each sibling's `direct_url.json` `commit_id` must equal the pin and the imported module must be a file that distribution installed; otherwise exit 1 with no output (`tests/test_installed_pins.py`) | mitigated; accepted residual: `direct_url.json` is pip's own record and is trusted as written |
| J-6 | Raw terminal escape sequences from fixture strings reach stderr | Error text and the paired summary write C0 controls except tab, DEL, and C1 controls (ESC included) as `\xNN`; newline is escaped inside a message (`tests/test_fixture_containment.py::test_paired_runner_stderr_escapes_fixture_controls`) | mitigated for the messages the entry points write; accepted residual: an exception type the entry points do not catch still prints Python's own traceback |
| J-7 | The J-5 check trusted the first `.dist-info` on `sys.path` and never compared installed files with `RECORD`, so a shadow package with a copied record in the working directory, or an edited installed file, ran under the stated pins | The record must be in the same `sys.path` entry as the imported package and that entry must be one of this interpreter's site-packages directories; every `RECORD` entry under the top-level package, and `direct_url.json`, must exist with its recorded SHA-256 (pip's unhashed bytecode entries excepted); an importable file or link in the package that `RECORD` does not list is refused; the check runs before import (from `find_spec`) and again after (`tests/test_installed_pins.py`) | mitigated; accepted residual: `RECORD` is trusted as written, so someone who can write site-packages can rewrite it too; bytecode under `__pycache__` is not hashed by pip and is not checked |
| J-8 | `table_id_candidate` does not bind the corpus index, in-tree fixtures, joint-eval commit or `row_source`, so a run on an edited corpus carries the sealed candidate | The candidate and its preimage are unchanged (the B7 seal binds them). New top-level field `inputs_digest`, the SHA-256 of `inputs_digest_record`: corpus index SHA-256, path and SHA-256 of every in-tree file read, `row_source`, sibling pins, and the commit `.git/HEAD` names. The summary prints it; `--expect-inputs-digest` exits 1 on a mismatch (`tests/test_paired_runner.py::test_inputs_digest_moves_with_corpus_and_fixture_bytes_but_candidate_does_not`) | mitigated; accepted residual: no expected digest is sealed, so a reader must compare it with a value they trust; the commit is read from `.git` as written and is not verified against the files; sibling fixture bytes are bound by the pins, not listed |
| J-9 | The paired runner reported `ok: true` and exited 0 when an attack row a gate ran on was ALLOW on control-on | New top-level field `all_gated_attacks_blocked`, printed in the summary; the CLI exits 1 and names each unblocked `threat_id/arm` when it is false, unless `--allow-unblocked` is passed. `ok` keeps its meaning (no DENY entered the tool) (`tests/test_paired_runner.py::test_an_unblocked_attack_fails_the_cli`) | mitigated; accepted residual: `run_paired()` callers must read the field themselves |
| J-10 | Raw control characters from corpus strings reach the paired CSV, and DEL and C1 reach `trajectory.jsonl` | The CSV writer adds the J-4 `'` first, then writes every C0 control (tab, CR, newline included), DEL and C1 in a string cell as `\xNN`; the JSONL writer writes DEL and C1 as `\u00NN` (`json` already escapes C0). The in-tree run has no such characters, so its CSV and JSONL bytes are unchanged (`tests/test_paired_runner.py::test_csv_escapes_control_characters_from_corpus_strings`, `tests/test_control_arena_export.py::test_trajectory_lines_escape_del_and_c1`) | mitigated; accepted residual: a literal `\xNN` in a corpus string reads the same as an escaped control in the CSV; U+2028 and U+2029 are not escaped in JSONL |

## Fail-closed

Missing policy, missing verify, HEAD mismatch, coax keys, binding mismatch, kill, parse failure, or unavailable sibling package → **DENY** (or demo failure). `gated_invoke` does not enter the tool on DENY. There is no path where untrusted prose installs or invokes without the host check.

## Non-goals

Each bullet is an accepted residual for this harness.

- Not an LLM, chain-of-thought, or transcript judge.
- Not a marketplace, live git host, or production UI.
- Not a measured attack-success scoreboard.
- Not a claim that monitors are unnecessary.

See [`docs/coverage-limits.md`](coverage-limits.md) and [`docs/adr/ADR-0001-joint-eval-architecture.md`](adr/ADR-0001-joint-eval-architecture.md).

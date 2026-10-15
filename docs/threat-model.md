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
| Supply Plugin4Shell-class | Marketplace/plugin pin that would satisfy a naive SHA pin on a mutable ref / swapped tree, plus skip-verify prose | Plugin4Shell-class (threat pattern name, not a vendor product) | `prose_rejected_as_policy` + `head_mismatch` | mitigated (existence proof at supply-gate `009c0cec`; pins pep `88231949` and supply-gate `009c0cec` predate the current fixes) |
| Supply pin-without-verify | Pin present, post-checkout HEAD omitted | Plugin4Shell-class family (verify skipped) | `verify_missing` | mitigated (existence proof at supply-gate `009c0cec`; pins pep `88231949` and supply-gate `009c0cec` predate the current fixes) |
| PEP monitor-bypass / prose-as-policy | Monitor SAFE / please-allow coax treated as policy | Monitor-bypass class ([arXiv:2609.19587](https://arxiv.org/abs/2609.19587)) | `agent_prose_rejected` | mitigated (existence proof at pep `88231949`; pins pep `88231949` and supply-gate `009c0cec` predate the current fixes) |
| PEP approval-binding mismatch | HITL/TTL approval for one invoke, args substituted before execute | Bind class ([arXiv:2609.21081](https://arxiv.org/abs/2609.21081)) | `approval_binding_mismatch` | mitigated (existence proof at pep `88231949`; pins pep `88231949` and supply-gate `009c0cec` predate the current fixes) |

The four mitigated rows rest on pep `88231949` and supply-gate `009c0cec`, the same sibling commits the console pins, which carry the 14 October 2026 re-scan fixes (B7 v5; earlier on 15 October 2026 the pins moved from `76c6d4be` and `7044a313` to `653ee4a8` and `d5e5ac11`, B7 v4). Fixture bytes read from a sibling checkout are proven to be the pinned commit's bytes (#30): the pinned commit and trees are hashed in Python and each fixture's blob id must match, so an edited checkout or a bare `.git/HEAD` is refused.

Citations are arXiv identifiers and pattern names only. This tree does not reproduce papers and does not report attack-success rates.

## Harness findings

These rows are about the harness itself, not about a sibling plane. **mitigated** here means this tree's code closes the finding and a named test fails without the fix; **accepted residual** names what is left.

| Finding | Class | Mitigation | Status (15 Oct 2026) |
| --- | --- | --- | --- |
| J-2 | Fixture root picked up from a shared parent directory (`/tmp/eval` used without `--root` when the venv sits under `/tmp`) | Only the directory that directly contains the `joint_eval` package is considered, and only when its `pyproject.toml` names `agent-control-lab-joint-eval` and it holds `eval/joint_story/index.json`; otherwise `--root` is required (`tests/test_fixture_containment.py::test_repo_root_ignores_a_fixture_root_in_a_shared_ancestor`) | mitigated |
| J-3 | Output redirected by swapping a directory above the output's parent between check and open | Descriptor walk from `/` with `O_DIRECTORY \| O_NOFOLLOW` per component; each directory is checked while held, symlinks are followed only when this user or root owns them, and every directory on the walk must be owned by this user or root and not world-writable without the sticky bit (`tests/test_output_walk.py`, including a 400-try race) | mitigated on POSIX; accepted residual on hosts without `dir_fd` support, which keep the by-path writer |
| J-4 | CSV formula injection through a corpus `threat_id` or other string cell | The paired CSV writer prefixes `'` to any string cell starting with `=`, `+`, `-`, `@`, tab or CR; JSON keeps the authored string (`tests/test_paired_runner.py::test_csv_neutralises_formula_cells_from_corpus_strings`) | mitigated |
| J-5 | Installed sibling packages not checked against the pins the output states | Before the demo or paired runner runs, each sibling's `direct_url.json` `commit_id` must equal the pin and the imported module must be a file that distribution installed; otherwise exit 1 with no output (`tests/test_installed_pins.py`) | mitigated; accepted residual: `direct_url.json` is pip's own record and is trusted as written |
| J-6 | Raw terminal escape sequences from fixture strings reach stderr | Error text and the paired summary write C0 controls except tab, DEL, and C1 controls (ESC included) as `\xNN`; newline is escaped inside a message (`tests/test_fixture_containment.py::test_paired_runner_stderr_escapes_fixture_controls`) | mitigated for the messages the entry points write; accepted residual: an exception type the entry points do not catch still prints Python's own traceback |

## Fail-closed

Missing policy, missing verify, HEAD mismatch, coax keys, binding mismatch, kill, parse failure, or unavailable sibling package → **DENY** (or demo failure). `gated_invoke` does not enter the tool on DENY. There is no path where untrusted prose installs or invokes without the host check.

## Non-goals

Each bullet is an accepted residual for this harness.

- Not an LLM, chain-of-thought, or transcript judge.
- Not a marketplace, live git host, or production UI.
- Not a measured attack-success scoreboard.
- Not a claim that monitors are unnecessary.

See [`docs/coverage-limits.md`](coverage-limits.md) and [`docs/adr/ADR-0001-joint-eval-architecture.md`](adr/ADR-0001-joint-eval-architecture.md).

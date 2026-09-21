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

| Joint step | Class | Citation / pattern name | Existence-proof DENY |
| --- | --- | --- | --- |
| Supply Plugin4Shell-class | Marketplace/plugin pin that would satisfy a naive SHA pin on a mutable ref / swapped tree, plus skip-verify prose | Plugin4Shell-class (threat pattern name, not a vendor product) | `prose_rejected_as_policy` + `head_mismatch` |
| Supply pin-without-verify | Pin present, post-checkout HEAD omitted | Plugin4Shell-class family (verify skipped) | `verify_missing` |
| PEP monitor-bypass / prose-as-policy | Monitor SAFE / please-allow coax treated as policy | Monitor-bypass class ([arXiv:2609.19587](https://arxiv.org/abs/2609.19587)) | `agent_prose_rejected` |
| PEP approval-binding mismatch | HITL/TTL approval for one invoke, args substituted before execute | Bind class ([arXiv:2609.21081](https://arxiv.org/abs/2609.21081)) | `approval_binding_mismatch` |

Citations are arXiv identifiers and pattern names only. This tree does not reproduce papers and does not report attack-success rates.

## Fail-closed

Missing policy, missing verify, HEAD mismatch, coax keys, binding mismatch, kill, parse failure, or unavailable sibling package → **DENY** (or demo failure). `gated_invoke` does not enter the tool on DENY. There is no path where untrusted prose installs or invokes without the host check.

## Non-goals

- Not an LLM, chain-of-thought, or transcript judge.
- Not a marketplace, live git host, or production UI.
- Not a measured attack-success scoreboard.
- Not a claim that monitors are unnecessary.

See [`docs/coverage-limits.md`](coverage-limits.md) and [`docs/adr/ADR-0001-joint-eval-architecture.md`](adr/ADR-0001-joint-eval-architecture.md).

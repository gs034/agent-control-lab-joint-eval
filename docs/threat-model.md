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
| Supply Plugin4Shell-class | Marketplace/plugin pin that would satisfy a naive SHA pin on a mutable ref / swapped tree, plus skip-verify prose | Plugin4Shell-class (threat pattern name, not a vendor product) | `prose_rejected_as_policy` + `head_mismatch` | mitigated (existence proof at supply-gate `7044a313`; pins pep `76c6d4be` and supply-gate `7044a313` predate the current fixes) |
| Supply pin-without-verify | Pin present, post-checkout HEAD omitted | Plugin4Shell-class family (verify skipped) | `verify_missing` | mitigated (existence proof at supply-gate `7044a313`; pins pep `76c6d4be` and supply-gate `7044a313` predate the current fixes) |
| PEP monitor-bypass / prose-as-policy | Monitor SAFE / please-allow coax treated as policy | Monitor-bypass class ([arXiv:2609.19587](https://arxiv.org/abs/2609.19587)) | `agent_prose_rejected` | mitigated (existence proof at pep `76c6d4be`; pins pep `76c6d4be` and supply-gate `7044a313` predate the current fixes) |
| PEP approval-binding mismatch | HITL/TTL approval for one invoke, args substituted before execute | Bind class ([arXiv:2609.21081](https://arxiv.org/abs/2609.21081)) | `approval_binding_mismatch` | mitigated (existence proof at pep `76c6d4be`; pins pep `76c6d4be` and supply-gate `7044a313` predate the current fixes) |

The four mitigated rows rest on pep `76c6d4be` and supply-gate `7044a313`. Those pins predate the current fixes. Fixture bytes read from a sibling checkout are proven to be the pinned commit's bytes (#30): the pinned commit and trees are hashed in Python and each fixture's blob id must match, so an edited checkout or a bare `.git/HEAD` is refused.

Citations are arXiv identifiers and pattern names only. This tree does not reproduce papers and does not report attack-success rates.

## Fail-closed

Missing policy, missing verify, HEAD mismatch, coax keys, binding mismatch, kill, parse failure, or unavailable sibling package → **DENY** (or demo failure). `gated_invoke` does not enter the tool on DENY. There is no path where untrusted prose installs or invokes without the host check.

## Non-goals

Each bullet is an accepted residual for this harness.

- Not an LLM, chain-of-thought, or transcript judge.
- Not a marketplace, live git host, or production UI.
- Not a measured attack-success scoreboard.
- Not a claim that monitors are unnecessary.

See [`docs/coverage-limits.md`](coverage-limits.md) and [`docs/adr/ADR-0001-joint-eval-architecture.md`](adr/ADR-0001-joint-eval-architecture.md).

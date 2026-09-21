# Security policy (Agent Control Lab joint evaluator)

This repository is a public-goods, Apache-2.0 **joint existence-proof harness**. It drives pinned Lab PEP and supply-gate packages. It is not a production product.

## Fail-closed default

The joint demo default is **DENY**. Missing sibling packages, unexpected ALLOW, parse failure, and invoke-on-DENY all fail the demo. There is no documented fail-open path.

There is no LLM on the evaluate/deny path. Marketplace or agent prose is not policy.

## Trust domain

This harness is a **caller**. Allow authority stays in:

- `pep.evaluate` / `pep.gated_invoke` (host/runtime PEP)
- `supply_gate.evaluate` (host-side supply integrity gate)

Those packages are separate public repositories, installed at pinned Git SHAs. This tree does not vendor them.

Public threat note: [`docs/threat-model.md`](docs/threat-model.md). Coverage limits: [`docs/coverage-limits.md`](docs/coverage-limits.md).

## Reporting a security issue

This project does **not** publish a `security@` mailbox. Do not invent or guess an email address for the Lab.

**Preferred:** use GitHub **private vulnerability reporting** / **Security Advisories** on this repository when the Security tab offers “Report a vulnerability”:

https://github.com/gs034/agent-control-lab-joint-eval/security/advisories

**If private reporting is not enabled:** open a GitHub issue titled so it is clearly a security report (for example, `security: joint-eval deny bypass`). Describe impact. Do **not** attach a ready-to-run exploit against third-party systems. A structured envelope plus an unexpected ALLOW / invoke-on-DENY receipt is enough.

Issues: https://github.com/gs034/agent-control-lab-joint-eval/issues

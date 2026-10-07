# Diligence history — residual historical PR refs

**Date:** 2026-10-07
**Repo:** Agent Control Lab joint-eval (`agent-control-lab-joint-eval`)
**Brand:** Agent Control Lab only (Apache-2.0).

## Summary

The current `main` tip is Lab-clean for brand-wall / tip purposes. Residual keep-out material is employer-domain author/committer emails on a historical pull-request head (commit author/committer identity). Exact strings are recorded in the Lab chinese-wall vault and the Support pack, and are not spelled in this tree. They remain only on GitHub-owned historical pull-request refs (`refs/pull/*`), not on the current `main` tip tree.

Leftover dirt is GitHub-owned `refs/pull/*` only. Collaborators cannot delete `refs/pull/*` (GitHub returns HTTP 422, read-only). **Support/GC is the only path to purge `refs/pull/*`.**

This note is a diligence disclosure only. Demo ≠ eng clear ≠ funding unlock. It is not a claim about attack success rates or product readiness. No history rewrite, no force-push, and no repository recreate were performed.

## Verified refs (2026-10-07)

SHAs below were checked against the live GitHub refs (Europe/London). Findings name the ref and SHA only.

| Ref | SHA | Residual location |
| --- | --- | --- |
| `main` | `a91eaf03b6dd15d4938ed183f444581973307ebe` | None in the tip tree |
| `refs/pull/7/head` | `2fa2e730000a8224e00b3253129b59209511dd8b` | Employer-domain author/committer emails on that historical ref (commit author/committer identity). Not tip tree content |

Exact strings stay in the Lab chinese-wall vault and the Support pack under `agent-control-lab/contam-support/` (Ticket C).

## Purge path

Do not attempt to delete `refs/pull/*` with a collaborator credential. GitHub treats those refs as read-only (HTTP 422). Support/GC is the only path to purge `refs/pull/*`. The Support pack already exists under `agent-control-lab/contam-support/` (Ticket C).

## Reading guide

- Tip and release trees: treat as Lab-clean.
- Full-history or PR-ref scanners: expect residual employer-domain author/committer emails on the historical SHA above. They are not on current `main`.
- Do not copy those strings into tip files, commit subjects, or branch names.

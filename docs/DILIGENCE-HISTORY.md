# Diligence history: residual historical PR refs

**Date:** 2026-10-13
**Repo:** Agent Control Lab joint-eval (`agent-control-lab-joint-eval`)
**Brand:** Agent Control Lab only (Apache-2.0).

## Summary

The current `main` tip is Lab-clean for brand-wall and tip purposes. Residual keep-out material is non-Lab email addresses in commit metadata on two historical pull-request heads: author and committer identity on one, and a co-author trailer in a commit message on the other. Exact strings are recorded in the Lab vault and the Support pack, and are not spelled in this tree. They remain only on GitHub-owned historical pull-request refs (`refs/pull/*`), not on the current `main` tip tree.

Leftover residue is on GitHub-owned `refs/pull/*` only. The ordinary branch that pointed at these PR heads was deleted on 8 Oct 2026. Collaborators cannot delete `refs/pull/*` (GitHub returns HTTP 422, read-only). **Support garbage collection is the only path to purge `refs/pull/*`.**

This note is a diligence disclosure only. Demo ≠ eng clear ≠ funding unlock. It is not a claim about attack success rates or product readiness. No history rewrite, no force-push, and no repository recreate were performed.

## Verified refs (2026-10-13)

SHAs below were checked against the live GitHub refs on 13 Oct 2026 (Europe/London). Findings name the ref and SHA only.

| Ref | SHA | Residual location |
| --- | --- | --- |
| `main` | `a91eaf03b6dd15d4938ed183f444581973307ebe` | None in the tip tree |
| `refs/pull/7/head` | `2fa2e730000a8224e00b3253129b59209511dd8b` | Non-Lab author and committer email on the tip commit. Not tip tree content |
| `refs/pull/8/head` | `da7c15377d65adf44821ac7cdf7b6cfe948b479b` | Reaches `bbd4698a32276f718602e51af70f245b400b3fca`, whose message carries a non-Lab email in a co-author trailer (author and committer are Lab). Not tip tree content |

Exact strings stay in the Lab vault and the Support pack under `agent-control-lab/contam-support/` (Ticket C).

## Purge path

Do not attempt to delete `refs/pull/*` with a collaborator credential. GitHub treats those refs as read-only (HTTP 422). Support garbage collection is the only path to purge `refs/pull/*`. The Support pack (Ticket C, covering `refs/pull/7/head` and `refs/pull/8/head`) is drafted under `agent-control-lab/contam-support/` and has not been sent.

## Reading guide

- Tip and release trees: treat as Lab-clean.
- Full-history or PR-ref scanners: expect residual non-Lab emails in commit metadata on the historical SHAs above. They are not on current `main`.
- Do not copy those strings into tip files, commit subjects, or branch names.

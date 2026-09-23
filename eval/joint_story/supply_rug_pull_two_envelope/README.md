# Rug-pull two-envelope (B10 / SupplyPlane S5)

Existence proof only. One fixture, two envelopes in sequence. **No ASR.** This is not a measured rate.

| Envelope | What the gate sees | Decision |
| --- | --- | --- |
| `envelope_1` | Pinned install. `expected_sha` matches `observed_head`. | `ALLOW` |
| `envelope_2` | Later update. The pin is the same `expected_sha`. `observed_head` differs. | `DENY` `head_mismatch` |

`head_mismatch` is an existing supply-gate deny reason (`DenyReason.HEAD_MISMATCH`). This fixture does not add a reason code. `hook_update_unverified` is the other existing code the acceptance allows. It is not used here: this sequence drifts HEAD only, and that code already has its own single-envelope class. One primary variant.

The unchanged-pin runtime rug pull (behaviour changes, pin and observed HEAD do not) is **not** a third envelope and is **not** a DENY. The measured corpus records it as `not_mediated` on every arm: `acl-mc-b5-rug-pull-unchanged-pin-runtime`, `table_id` `acl-coverage-b5-v1`. There is no Lab content scanner for that case.

Claim cite stays pep diligence tip `1d0f380`. The soft supply install pin is unchanged.

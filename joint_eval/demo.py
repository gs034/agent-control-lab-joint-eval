# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agent Control Lab contributors
"""Print frozen joint receipts. Fail-closed: expected DENY on every step."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from joint_eval.loader import dumps_canonical
from joint_eval.pins import pin_document
from joint_eval.story import JointEvalError, dumps_story, run_joint_story


def dumps_story_unavailable(detail: str) -> str:
    return dumps_canonical(
        {
            "brand": "Agent Control Lab",
            "licence": "Apache-2.0",
            "story_id": "acl-joint-eval-existence-proof-001",
            "decision": "DENY",
            "fail_closed": True,
            "existence_proof_only": True,
            "replacement_for_monitors": False,
            "measured_attack_success_claimed": False,
            "reason": "joint_eval_unavailable",
            "detail": detail,
            "pins": pin_document(),
        }
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Agent Control Lab joint evaluator demo. "
            "Existence-proof DENY story over pinned pep + supply-gate. "
            "Complementary to monitors — not a replacement. "
            "Does not measure attack success."
        )
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=None,
        help="Repository root containing eval/joint_story/ (default: discover).",
    )
    args = parser.parse_args(argv)
    try:
        result = run_joint_story(root=args.root)
    except (JointEvalError, OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        sys.stderr.write(f"joint-eval unavailable: {exc}\n")
        sys.stdout.write(dumps_story_unavailable(str(exc)))
        return 1
    sys.stdout.write(dumps_story(result))
    if not result.ok:
        sys.stderr.write("DEMO FAIL: expected every step to DENY without invoke\n")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

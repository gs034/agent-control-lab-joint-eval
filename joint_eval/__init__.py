# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agent Control Lab contributors
"""Agent Control Lab joint evaluator harness.

Drives the public Lab PEP and supply-gate packages in one existence-proof
story. This package is not a monitor replacement, not a marketplace, and
not a model judge. There is no LLM on the evaluate/deny path.
"""

from joint_eval.pins import PEP_SHA, SUPPLY_GATE_SHA
from joint_eval.story import JointStoryResult, run_joint_story

__all__ = [
    "PEP_SHA",
    "SUPPLY_GATE_SHA",
    "JointStoryResult",
    "run_joint_story",
]

__version__ = "0.1.0"

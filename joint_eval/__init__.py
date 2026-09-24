# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agent Control Lab contributors
"""Agent Control Lab joint evaluator harness.

Drives the public Lab PEP and supply-gate packages in one existence-proof
story. This package is not a monitor replacement, not a marketplace, and
not a model judge. There is no LLM on the evaluate/deny path.

``write_control_arena_export`` writes a ControlArena directory export from
fixtures and frozen receipts. It is not a ControlArena setting and not an
Inspect loop.

``run_paired`` runs monitor, PEP, and stack control-off then control-on.
``runner_implemented`` is true on that runner's document only. The
measured-corpus seed keeps ``runner_implemented`` false. The paired table
is provisional existence counts, not a residual ASR, and not an Inspect loop.
"""

from joint_eval.control_arena_export import write_control_arena_export
from joint_eval.paired_runner import run_paired
from joint_eval.pins import PEP_SHA, SUPPLY_GATE_SHA
from joint_eval.story import JointStoryResult, run_joint_story

__all__ = [
    "PEP_SHA",
    "SUPPLY_GATE_SHA",
    "JointStoryResult",
    "run_joint_story",
    "run_paired",
    "write_control_arena_export",
]

__version__ = "0.1.0"

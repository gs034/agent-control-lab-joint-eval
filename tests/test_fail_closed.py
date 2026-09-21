# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agent Control Lab contributors
"""Fail-closed: missing packages or unexpected ALLOW cannot look like success."""

from __future__ import annotations

from pathlib import Path

from joint_eval.demo import dumps_story_unavailable, main
from joint_eval.story import JointEvalError, run_joint_story

ROOT = Path(__file__).resolve().parents[1]


def test_unavailable_document_is_deny():
    text = dumps_story_unavailable("pep package unavailable: missing")
    assert '"decision": "DENY"' in text
    assert '"fail_closed": true' in text
    assert '"measured_attack_success_claimed": false' in text
    assert "missing" in text


def test_missing_index_fails_closed(tmp_path: Path):
    (tmp_path / "eval" / "joint_story").mkdir(parents=True)
    (tmp_path / "eval" / "joint_story" / "index.json").write_text("{}", encoding="utf-8")
    try:
        run_joint_story(root=tmp_path)
        raised = False
    except (JointEvalError, ValueError, FileNotFoundError):
        raised = True
    assert raised


def test_demo_root_without_fixtures_exits_nonzero(tmp_path: Path):
    code = main(["--root", str(tmp_path)])
    assert code == 1

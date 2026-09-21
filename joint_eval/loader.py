# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agent Control Lab contributors
"""Load joint-eval fixtures from eval/ (this tree). Sibling trees are not vendored."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

ENVELOPE_NAME = "envelope.json"
EXPECTED_NAME = "expected_receipt.json"
OBSERVED_HEAD_NAME = "observed_head.json"
PROSE_NAME = "untrusted_prose.txt"
RUNTIME_NAME = "runtime.json"
INDEX_NAME = "index.json"


def repo_root() -> Path:
    here = Path(__file__).resolve()
    candidates = [here.parents[1], Path.cwd(), *here.parents]
    for candidate in candidates:
        if (candidate / "eval" / "joint_story" / INDEX_NAME).is_file():
            return candidate
    raise FileNotFoundError("eval/joint_story/index.json not found")


def story_dir() -> Path:
    return repo_root() / "eval" / "joint_story"


def load_index() -> dict[str, Any]:
    data = json.loads((story_dir() / INDEX_NAME).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("joint story index must be a JSON object")
    return data


def load_object(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"JSON object required: {path}")
    return data


def dumps_canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, indent=2) + "\n"

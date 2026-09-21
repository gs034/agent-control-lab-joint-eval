# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agent Control Lab contributors
"""Hostile-reviewer check: joint harness is not an LLM monitor path."""

from __future__ import annotations

import ast
from pathlib import Path

JOINT_DIR = Path(__file__).resolve().parents[1] / "joint_eval"

BANNED_MODULES = {
    "openai",
    "anthropic",
    "litellm",
    "together",
    "cohere",
    "requests",
    "httpx",
    "aiohttp",
    "urllib",
    "urllib3",
    "huggingface_hub",
}

BANNED_NAMES = {
    "judge",
    "llm",
    "cot",
    "transcript",
    "hitl",
    "monitor_score",
    "ask_model",
}


def test_joint_eval_sources_have_no_model_or_http_imports():
    paths = list(JOINT_DIR.glob("*.py"))
    assert paths
    for path in paths:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    root = alias.name.split(".")[0]
                    assert root not in BANNED_MODULES, f"{path.name} imports {alias.name}"
            if isinstance(node, ast.ImportFrom) and node.module:
                root = node.module.split(".")[0]
                assert root not in BANNED_MODULES, f"{path.name} imports {node.module}"


def test_no_judge_entrypoints():
    for path in JOINT_DIR.glob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        names = {node.name.lower() for node in tree.body if isinstance(node, ast.FunctionDef)}
        for banned in BANNED_NAMES:
            assert banned not in names, f"{path.name} defines {banned}"

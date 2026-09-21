# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agent Control Lab contributors
"""Sibling packages are git-SHA pins, not vendored trees."""

from __future__ import annotations

import importlib
import tomllib
from pathlib import Path

from joint_eval.pins import PEP_SHA, SUPPLY_GATE_SHA, pep_direct_url, supply_gate_direct_url

ROOT = Path(__file__).resolve().parents[1]


def test_pyproject_pins_match_module():
    data = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    deps = data["project"]["dependencies"]
    joined = "\n".join(deps)
    assert PEP_SHA in joined
    assert SUPPLY_GATE_SHA in joined
    assert pep_direct_url() in joined
    assert supply_gate_direct_url() in joined
    assert "agent-control-lab-pep @" in joined
    assert "agent-control-lab-supply-gate @" in joined


def test_sibling_source_trees_are_not_vendored():
    assert not (ROOT / "pep").exists()
    assert not (ROOT / "supply_gate").exists()


def test_imported_packages_are_not_this_repo():
    pep = importlib.import_module("pep")
    supply = importlib.import_module("supply_gate")
    pep_path = Path(pep.__file__).resolve()
    supply_path = Path(supply.__file__).resolve()
    root = ROOT.resolve()
    assert root not in pep_path.parents
    assert root not in supply_path.parents

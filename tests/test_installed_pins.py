# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agent Control Lab contributors
"""The installed sibling distributions must be the pinned commits.

A pin in pyproject.toml is a request; pip keeps an already-installed
distribution whose version number has not changed. This test reads the
installer's own record (PEP 610 ``direct_url.json``) and compares the
commit it materialised with the documented pin.
"""

from __future__ import annotations

import importlib.metadata as metadata
import json

import pytest

from joint_eval.pins import PEP_PACKAGE, PEP_SHA, SUPPLY_GATE_PACKAGE, SUPPLY_GATE_SHA


def _installed_commit(package: str) -> str:
    try:
        dist = metadata.distribution(package)
    except metadata.PackageNotFoundError:
        pytest.skip(f"{package} is not installed")
    raw = dist.read_text("direct_url.json")
    if raw is None:
        pytest.skip(f"{package} was not installed from a direct URL")
    record = json.loads(raw)
    vcs = record.get("vcs_info") or {}
    commit = vcs.get("commit_id")
    assert isinstance(commit, str) and commit, f"{package} direct_url.json has no commit_id"
    return commit


@pytest.mark.parametrize(
    ("package", "pinned"),
    [(PEP_PACKAGE, PEP_SHA), (SUPPLY_GATE_PACKAGE, SUPPLY_GATE_SHA)],
    ids=["pep", "supply_gate"],
)
def test_installed_sibling_is_the_pinned_commit(package: str, pinned: str) -> None:
    assert _installed_commit(package) == pinned

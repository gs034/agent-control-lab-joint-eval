# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agent Control Lab contributors
"""The installed sibling distributions must be the pinned commits.

A pin in pyproject.toml is a request; pip keeps an already-installed
distribution whose version number has not changed. This test reads the
installer's own record (PEP 610 ``direct_url.json``) and compares the
commit it materialised with the documented pin. Both dependencies are
declared only as direct URLs, so an installed copy without that record
is a pin that was not honoured, and fails rather than skips.
"""

from __future__ import annotations

import importlib.metadata as metadata
import json
from pathlib import Path

import pytest

from joint_eval.pins import PEP_PACKAGE, PEP_SHA, SUPPLY_GATE_PACKAGE, SUPPLY_GATE_SHA

ROOT = Path(__file__).resolve().parents[1]


def _installed_commit(package: str) -> str:
    try:
        dist = metadata.distribution(package)
    except metadata.PackageNotFoundError:
        pytest.skip(f"{package} is not installed")
    raw = dist.read_text("direct_url.json")
    assert raw is not None, f"{package} is installed but not from its pinned direct URL"
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
    installed = _installed_commit(package)
    assert installed == pinned, (
        f"{package} is installed at {installed}, pinned at {pinned}; "
        "uninstall both sibling packages and re-run pip install -e '.[dev]' (see README)"
    )


# Runtime check (J-5): an output that states the pins is produced only when
# the imported siblings are those pins.


class _Dist:
    """A real distribution with its ``direct_url.json`` replaced."""

    def __init__(self, real: metadata.Distribution, direct_url: str | None) -> None:
        self._real = real
        self._direct_url = direct_url
        self.files = real.files

    def read_text(self, name: str) -> str | None:
        if name == "direct_url.json":
            return self._direct_url
        return self._real.read_text(name)

    def locate_file(self, path):
        return self._real.locate_file(path)


def _fake_direct_url(monkeypatch: pytest.MonkeyPatch, package: str, direct_url: str | None) -> None:
    from joint_eval import pins

    real_distribution = pins.metadata.distribution

    def _distribution(name: str):
        dist = real_distribution(name)
        if name == package:
            return _Dist(dist, direct_url)
        return dist

    monkeypatch.setattr(pins.metadata, "distribution", _distribution)


def _vcs(commit: str) -> str:
    return json.dumps({"url": "https://example.invalid/x.git", "vcs_info": {"vcs": "git", "commit_id": commit}})


_WRONG = "0" * 40


@pytest.fixture
def _siblings_installed(monkeypatch: pytest.MonkeyPatch) -> None:
    pytest.importorskip("pep")
    pytest.importorskip("supply_gate")
    for package in (PEP_PACKAGE, SUPPLY_GATE_PACKAGE):
        _installed_commit(package)
    monkeypatch.delenv("ACL_PEP_ROOT", raising=False)
    monkeypatch.delenv("ACL_SUPPLY_GATE_ROOT", raising=False)


@pytest.mark.usefixtures("_siblings_installed")
@pytest.mark.parametrize("package", [PEP_PACKAGE, SUPPLY_GATE_PACKAGE], ids=["pep", "supply_gate"])
@pytest.mark.parametrize(
    "direct_url",
    [_vcs(_WRONG), None, json.dumps({"url": "file:///x", "dir_info": {"editable": True}})],
    ids=["other_commit", "no_record", "editable"],
)
def test_runs_that_state_pins_refuse_an_unpinned_sibling(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, package: str, direct_url: str | None
) -> None:
    from joint_eval import demo, paired_runner
    from joint_eval.story import JointEvalError, run_joint_story

    _fake_direct_url(monkeypatch, package, direct_url)
    with pytest.raises(JointEvalError, match="sibling pin not honoured"):
        paired_runner.run_paired(root=ROOT)
    with pytest.raises(JointEvalError, match="sibling pin not honoured"):
        run_joint_story(root=ROOT)
    out = tmp_path / "out" / "p.json"
    assert paired_runner.main(["--root", str(ROOT), "--out", str(out)]) == 1
    assert not out.exists()
    assert demo.main(["--root", str(ROOT)]) == 1


@pytest.mark.usefixtures("_siblings_installed")
def test_a_shadowing_module_is_refused() -> None:
    import types

    import pep

    from joint_eval.pins import PinMismatchError, require_installed_pin

    require_installed_pin(PEP_PACKAGE, PEP_SHA, pep)
    shadow = types.ModuleType("pep")
    shadow.__file__ = str(ROOT / "pep" / "__init__.py")
    with pytest.raises(PinMismatchError, match="not from the installed"):
        require_installed_pin(PEP_PACKAGE, PEP_SHA, shadow)

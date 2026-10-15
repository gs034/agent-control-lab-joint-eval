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
import os
import shutil
import subprocess
import sys
import types
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


# J-7: the distribution record must sit in the interpreter's site-packages
# beside the imported package, and the installed files must match RECORD.


def _dist_info(dist: metadata.Distribution) -> Path:
    for item in dist.files or ():
        if item.name == "RECORD" and item.parts[0].endswith(".dist-info"):
            return Path(str(dist.locate_file(item))).parent
    raise AssertionError("no RECORD")


def _copy_install(dest: Path, package: str, top: str) -> Path:
    """Copy one installed sibling (package and dist-info) into ``dest``."""
    dist = metadata.distribution(package)
    package_dir = Path(str(dist.locate_file(top)))
    info = _dist_info(dist)
    dest.mkdir(parents=True, exist_ok=True)
    shutil.copytree(package_dir, dest / top, ignore=shutil.ignore_patterns("__pycache__"))
    shutil.copytree(info, dest / info.name)
    return dest / info.name


@pytest.mark.usefixtures("_siblings_installed")
@pytest.mark.parametrize(
    ("package", "pinned", "top"),
    [(PEP_PACKAGE, PEP_SHA, "pep"), (SUPPLY_GATE_PACKAGE, SUPPLY_GATE_SHA, "supply_gate")],
    ids=["pep", "supply_gate"],
)
def test_the_untouched_install_passes(package: str, pinned: str, top: str) -> None:
    import importlib

    from joint_eval.pins import require_installed_pin

    require_installed_pin(package, pinned, importlib.import_module(top))


@pytest.mark.usefixtures("_siblings_installed")
@pytest.mark.parametrize("edit", [False, True], ids=["identical_copy", "edited_copy"])
def test_a_shadow_package_with_a_copied_dist_info_in_the_working_directory_is_refused(
    tmp_path: Path, edit: bool
) -> None:
    work = tmp_path / "work"
    _copy_install(work, PEP_PACKAGE, "pep")
    if edit:
        with (work / "pep" / "gate.py").open("a", encoding="utf-8") as handle:
            handle.write("# shadow\n")
    out = tmp_path / "out" / "acl-paired.json"
    env = {key: value for key, value in os.environ.items() if not key.startswith("ACL_")}
    env.pop("PYTHONSAFEPATH", None)
    done = subprocess.run(
        [sys.executable, "-m", "joint_eval.paired_runner", "--root", str(ROOT), "--out", str(out)],
        cwd=work,
        env=env,
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )
    assert done.returncode == 1, done.stdout + done.stderr
    assert "sibling pin not honoured" in done.stderr
    assert not out.exists()


def _site_copy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, trusted: bool = True
) -> tuple[Path, types.ModuleType]:
    """A copy of the installed pep in a site-packages directory the check trusts."""
    from joint_eval import pins

    site_dir = tmp_path / "lib" / "site-packages"
    info = _copy_install(site_dir, PEP_PACKAGE, "pep")
    real_distribution = pins.metadata.distribution

    def _distribution(name: str):
        if name == PEP_PACKAGE:
            return metadata.PathDistribution(info)
        return real_distribution(name)

    monkeypatch.setattr(pins.metadata, "distribution", _distribution)
    if trusted:
        monkeypatch.setattr(pins, "_site_dirs", lambda: frozenset({site_dir.resolve()}), raising=False)
    module = types.ModuleType("pep")
    module.__file__ = str(site_dir / "pep" / "__init__.py")
    return site_dir / "pep", module


@pytest.mark.usefixtures("_siblings_installed")
def test_an_untouched_copy_in_a_trusted_site_dir_passes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from joint_eval.pins import require_installed_pin

    _package_dir, module = _site_copy(tmp_path, monkeypatch)
    require_installed_pin(PEP_PACKAGE, PEP_SHA, module)


def _append(package_dir: Path) -> None:
    with (package_dir / "gate.py").open("a", encoding="utf-8") as handle:
        handle.write("ALLOW_EVERYTHING = True\n")


def _delete(package_dir: Path) -> None:
    (package_dir / "gate.py").unlink()


def _extra_module(package_dir: Path) -> None:
    (package_dir / "extra.py").write_text("X = 1\n", encoding="utf-8")


def _extra_subpackage(package_dir: Path) -> None:
    (package_dir / "planted").mkdir()
    (package_dir / "planted" / "__init__.py").write_text("", encoding="utf-8")


def _sourceless_bytecode(package_dir: Path) -> None:
    (package_dir / "planted.pyc").write_bytes(b"\0" * 16)


def _swap_for_link(package_dir: Path) -> None:
    target = package_dir.parent / "elsewhere.py"
    (package_dir / "gate.py").rename(target)
    (package_dir / "gate.py").symlink_to(target)


@pytest.mark.usefixtures("_siblings_installed")
@pytest.mark.parametrize(
    "tamper",
    [_append, _delete, _extra_module, _extra_subpackage, _sourceless_bytecode, _swap_for_link],
    ids=["edited", "missing", "extra_module", "extra_subpackage", "sourceless_pyc", "link"],
)
def test_an_installed_file_that_does_not_match_record_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, tamper
) -> None:
    from joint_eval.pins import PinMismatchError, require_installed_pin

    package_dir, module = _site_copy(tmp_path, monkeypatch)
    tamper(package_dir)
    with pytest.raises(PinMismatchError, match="RECORD"):
        require_installed_pin(PEP_PACKAGE, PEP_SHA, module)


@pytest.mark.usefixtures("_siblings_installed")
def test_a_site_packages_directory_this_interpreter_does_not_use_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from joint_eval.pins import PinMismatchError, require_installed_pin

    _package_dir, module = _site_copy(tmp_path, monkeypatch, trusted=False)
    with pytest.raises(PinMismatchError, match="not a site-packages directory"):
        require_installed_pin(PEP_PACKAGE, PEP_SHA, module)


@pytest.mark.usefixtures("_siblings_installed")
def test_a_record_in_another_path_entry_than_the_package_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import pep

    from joint_eval.pins import PinMismatchError, require_installed_pin

    _site_copy(tmp_path, monkeypatch)
    with pytest.raises(PinMismatchError, match="not from the installed"):
        require_installed_pin(PEP_PACKAGE, PEP_SHA, pep)

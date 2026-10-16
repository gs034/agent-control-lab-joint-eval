# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agent Control Lab contributors
"""Documented Git SHA pins for the sibling Lab packages.

Install is PEP 508 direct URLs in pyproject.toml (git+https @ commit).
This harness does not vendor pep or supply-gate source trees.
"""

from __future__ import annotations

import base64
import csv
import hashlib
import importlib.machinery
import json
import os
import site
import sysconfig
from importlib import metadata
from pathlib import Path, PurePosixPath
from types import ModuleType

PEP_REPO = "https://github.com/gs034/agent-control-lab-pep"
# Install pins (B7 v7): the J-5 installed-pin check refuses any other commit,
# so a host that installs joint-eval must install these sibling commits.
PEP_SHA = "365a952f32e7b5335dd42862409770c3550cc487"
PEP_PACKAGE = "agent-control-lab-pep"

SUPPLY_GATE_REPO = "https://github.com/gs034/agent-control-lab-supply-gate"
# Not the claim cite.
SUPPLY_GATE_SHA = "8cfdfac71972188aeef20714b827fa3a9c925908"
SUPPLY_GATE_PACKAGE = "agent-control-lab-supply-gate"


def pep_direct_url() -> str:
    return f"git+https://github.com/gs034/agent-control-lab-pep.git@{PEP_SHA}"


def supply_gate_direct_url() -> str:
    return (
        "git+https://github.com/gs034/agent-control-lab-supply-gate.git@"
        f"{SUPPLY_GATE_SHA}"
    )


def pin_document() -> dict[str, dict[str, str]]:
    return {
        "pep": {
            "package": PEP_PACKAGE,
            "repo": PEP_REPO,
            "sha": PEP_SHA,
            "direct_url": pep_direct_url(),
        },
        "supply_gate": {
            "package": SUPPLY_GATE_PACKAGE,
            "repo": SUPPLY_GATE_REPO,
            "sha": SUPPLY_GATE_SHA,
            "direct_url": supply_gate_direct_url(),
        },
    }


class PinMismatchError(RuntimeError):
    """An installed sibling distribution is not the commit this tree documents."""


def installed_commit(package: str) -> str:
    """The commit pip materialised for ``package``, from its PEP 610 ``direct_url.json``.

    Both siblings are declared only as git direct URLs, so an installed
    copy without that record (a plain or editable local install) is a pin
    that was not honoured.
    """
    try:
        dist = metadata.distribution(package)
    except metadata.PackageNotFoundError as exc:
        raise PinMismatchError(f"{package} is not installed") from exc
    raw = dist.read_text("direct_url.json")
    if raw is None:
        raise PinMismatchError(f"{package} is installed but not from its pinned direct URL")
    try:
        record = json.loads(raw)
    except ValueError as exc:
        raise PinMismatchError(f"{package} direct_url.json is not valid JSON") from exc
    vcs = record.get("vcs_info") if isinstance(record, dict) else None
    commit = vcs.get("commit_id") if isinstance(vcs, dict) else None
    if not isinstance(commit, str) or not commit:
        raise PinMismatchError(f"{package} direct_url.json has no commit_id")
    return commit


def require_installed_pin(package: str, pinned: str, module: ModuleType | None = None) -> None:
    """Fail closed unless ``package`` is installed at ``pinned``.

    When ``module`` (the sibling's top-level package) is given, three more
    things must hold, so a same-named package earlier on ``sys.path`` or an
    edited installed file cannot stand in for the pinned copy (J-5, J-7):

    - the distribution whose ``direct_url.json`` was read sits in the same
      ``sys.path`` entry as the imported package, and that entry is one of
      this interpreter's site-packages (or dist-packages) directories, not
      the working directory or any other path entry;
    - every file the distribution's ``RECORD`` lists under the package, and
      its ``direct_url.json``, exists and has the SHA-256 that ``RECORD``
      states (bytecode caches, which pip lists without a hash, excepted);
    - the package directory holds no importable file or link that
      ``RECORD`` does not list.
    """
    if module is None:
        _require_commit(package, pinned)
        return
    require_installed_location(package, pinned, module.__name__, getattr(module, "__file__", None))


def require_installed_location(package: str, pinned: str, name: str, location: str | None) -> None:
    """The checks of :func:`require_installed_pin` for a package found at ``location``.

    ``location`` is the package's ``__init__.py``. Callers can pass the
    origin from ``importlib.util.find_spec`` to check an installed copy
    before any of its code runs.
    """
    _require_commit(package, pinned)
    dist = metadata.distribution(package)
    if not location or Path(location).name != "__init__.py":
        raise PinMismatchError(
            f"{name} was imported from {location}, not from the installed {package} distribution"
        )
    package_dir = Path(location).resolve().parent
    entry = package_dir.parent
    base = Path(str(dist.locate_file(""))).resolve()
    if base != entry:
        raise PinMismatchError(
            f"{name} was imported from {location}, not from the installed {package} distribution "
            f"(its record is in {base})"
        )
    if entry.name not in _SITE_DIR_NAMES or entry not in _site_dirs():
        raise PinMismatchError(
            f"{name} was imported from {entry}, which is not a site-packages directory "
            f"of this interpreter, so it is not the installed {package} distribution"
        )
    _verify_record(package, dist, package_dir, Path(location).resolve())


def _require_commit(package: str, pinned: str) -> None:
    commit = installed_commit(package)
    if commit != pinned:
        raise PinMismatchError(
            f"{package} is installed at {commit}, pinned at {pinned}; "
            "uninstall both sibling packages and re-run pip install -e '.[dev]' (see README)"
        )


_SITE_DIR_NAMES = frozenset({"site-packages", "dist-packages"})


def _site_dirs() -> frozenset[Path]:
    """The directories this interpreter installs distributions into."""
    found: list[str] = []
    getsitepackages = getattr(site, "getsitepackages", None)
    if getsitepackages is not None:
        found.extend(getsitepackages())
    if site.ENABLE_USER_SITE:
        found.append(site.getusersitepackages())
    paths = sysconfig.get_paths()
    found.extend(paths[key] for key in ("purelib", "platlib") if key in paths)
    return frozenset(Path(item).resolve() for item in found if item)


def _record_digest(path: Path) -> str:
    """SHA-256 as pip writes it in ``RECORD``: urlsafe base64, no padding."""
    digest = hashlib.sha256(path.read_bytes()).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _verify_record(package: str, dist: metadata.Distribution, package_dir: Path, init: Path) -> None:
    def refuse(detail: str) -> PinMismatchError:
        return PinMismatchError(f"{package} installed files do not match its RECORD: {detail}")

    # Read RECORD itself: ``Distribution.files`` drops entries whose file is
    # missing, which would hide a deleted file.
    raw = dist.read_text("RECORD")
    if not raw:
        raise refuse("no RECORD")
    top = package_dir.name
    listed: set[Path] = set()
    for row in csv.reader(raw.splitlines()):
        if not row or not row[0]:
            continue
        item = PurePosixPath(row[0])
        parts = item.parts
        in_package = parts[0] == top
        if not in_package and not (parts[0].endswith(".dist-info") and parts[1:] == ("direct_url.json",)):
            continue
        path = Path(str(dist.locate_file(str(item))))
        if in_package:
            resolved = path.resolve()
            if resolved != package_dir and package_dir not in resolved.parents:
                raise refuse(f"{item} is outside {package_dir}")
            listed.add(resolved)
        recorded = row[1] if len(row) > 1 else ""
        if not recorded:
            if in_package and "__pycache__" in parts and path.suffix == ".pyc":
                continue
            raise refuse(f"{item} has no hash")
        mode, _, value = recorded.partition("=")
        if mode != "sha256" or not value:
            raise refuse(f"{item} hash is not sha256")
        if path.is_symlink() or not path.is_file():
            raise refuse(f"{item} is missing or not a regular file")
        if _record_digest(path) != value:
            raise refuse(f"{item} has been changed since install")
    if init not in listed:
        raise refuse(f"{init} is not listed")
    importable = tuple(importlib.machinery.all_suffixes())
    for current, dirs, names in os.walk(package_dir):
        here = Path(current)
        for name in dirs + names:
            if (here / name).is_symlink():
                raise refuse(f"{here / name} is a link")
        if here.name == "__pycache__":
            continue
        for name in names:
            if name.endswith(importable) and (here / name).resolve() not in listed:
                raise refuse(f"{here / name} is not listed")

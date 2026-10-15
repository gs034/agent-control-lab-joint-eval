# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agent Control Lab contributors
"""Documented Git SHA pins for the sibling Lab packages.

Install is PEP 508 direct URLs in pyproject.toml (git+https @ commit).
This harness does not vendor pep or supply-gate source trees.
"""

from __future__ import annotations

import json
from importlib import metadata
from pathlib import Path
from types import ModuleType

PEP_REPO = "https://github.com/gs034/agent-control-lab-pep"
PEP_SHA = "76c6d4bedd7a2702a55513ae2ddbd17f8d9ccac9"
PEP_PACKAGE = "agent-control-lab-pep"

SUPPLY_GATE_REPO = "https://github.com/gs034/agent-control-lab-supply-gate"
# Install pin (B7 v3): the B6 measured-corpus loader plus the brand-wall
# email keep-out commit. Not the claim cite.
SUPPLY_GATE_SHA = "7044a313dffc60e08b26366950328f9025c56310"
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

    When ``module`` is given, its file must also be one the distribution
    installed, so a same-named module earlier on ``sys.path`` cannot stand
    in for the pinned copy.
    """
    commit = installed_commit(package)
    if commit != pinned:
        raise PinMismatchError(
            f"{package} is installed at {commit}, pinned at {pinned}; "
            "uninstall both sibling packages and re-run pip install -e '.[dev]' (see README)"
        )
    if module is None:
        return
    location = getattr(module, "__file__", None)
    dist = metadata.distribution(package)
    installed = {Path(str(dist.locate_file(item))).resolve() for item in dist.files or ()}
    if not location or Path(location).resolve() not in installed:
        raise PinMismatchError(
            f"{module.__name__} was imported from {location}, not from the installed {package} distribution"
        )

# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agent Control Lab contributors
"""Load joint-eval fixtures from eval/ (this tree). Sibling trees are not vendored."""

from __future__ import annotations

import contextlib
import contextvars
import hashlib
import json
import os
import stat
import tomllib
from collections.abc import Iterator
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any

ENVELOPE_NAME = "envelope.json"
EXPECTED_NAME = "expected_receipt.json"
OBSERVED_HEAD_NAME = "observed_head.json"
PROSE_NAME = "untrusted_prose.txt"
RUNTIME_NAME = "runtime.json"
INDEX_NAME = "index.json"


class FixturePathError(ValueError):
    """A fixture path leaves its root, is a link, or is not a plain file or directory."""


# Set by ``record_fixture_reads``: a list that each successful read appends
# ``(path, sha256)`` to. Unset (None) outside a recording.
_READ_LOG: contextvars.ContextVar[list[tuple[Path, str]] | None] = contextvars.ContextVar(
    "joint_eval_fixture_read_log", default=None
)


@contextlib.contextmanager
def record_fixture_reads() -> Iterator[list[tuple[Path, str]]]:
    """Collect ``(path, sha256 of the bytes read)`` for every fixture read in the block.

    The paired runner uses this to digest exactly the bytes it used. Reads
    that fail are not recorded.
    """
    log: list[tuple[Path, str]] = []
    token = _READ_LOG.set(log)
    try:
        yield log
    finally:
        _READ_LOG.reset(token)


PROJECT_NAME = "agent-control-lab-joint-eval"


def repo_root() -> Path:
    """The source checkout that holds this package's fixtures.

    Only one directory is considered: the one that directly contains this
    package (``<checkout>/joint_eval/loader.py``). It counts as this
    project's checkout only when its ``pyproject.toml`` names this project
    and it holds ``eval/joint_story/index.json``. Other parent directories
    are never searched, so an installed package under ``/tmp/venv`` does not
    pick up a shared ``/tmp/eval``. The working directory is not consulted
    either. Pass ``--root`` to run against another tree, or when the package
    is installed outside its checkout.
    """
    candidate = Path(__file__).resolve().parent.parent
    if _is_this_checkout(candidate):
        return candidate
    raise FileNotFoundError(
        "joint_eval is not running from its source checkout "
        f"({PROJECT_NAME} pyproject.toml and eval/joint_story/index.json beside the package); pass --root"
    )


def _is_this_checkout(candidate: Path) -> bool:
    try:
        project = tomllib.loads(read_fixture_text(candidate / "pyproject.toml")).get("project")
    except (OSError, ValueError):
        return False
    if not isinstance(project, dict) or project.get("name") != PROJECT_NAME:
        return False
    return (candidate / "eval" / "joint_story" / INDEX_NAME).is_file()


def story_dir(root: Path | None = None) -> Path:
    """``<root>/eval/joint_story``, refusing a symlinked ``eval`` or ``joint_story``."""
    return contained_dir(repo_root() if root is None else Path(root), "eval/joint_story")


def load_index() -> dict[str, Any]:
    data = json.loads(read_fixture_text(story_dir() / INDEX_NAME))
    if not isinstance(data, dict):
        raise ValueError("joint story index must be a JSON object")
    return data


def contained_dir(root: Path, rel: object) -> Path:
    """Join a fixture-relative directory to ``root`` and refuse anything that leaves it.

    ``rel`` must be a relative path with no ``..`` segment. No component may
    be a symlink, the result must be a directory, and it must resolve under
    the resolved ``root``. Raises ``FixturePathError`` before any file is read.
    """
    if not isinstance(rel, str) or not rel.strip():
        raise FixturePathError("fixture path must be a non-empty string")
    if "\\" in rel or PurePosixPath(rel).is_absolute() or PureWindowsPath(rel).is_absolute():
        raise FixturePathError(f"fixture path must be relative: {rel}")
    if PureWindowsPath(rel).drive:
        raise FixturePathError(f"fixture path must be relative: {rel}")
    parts = PurePosixPath(rel).parts
    if any(part in {"..", ""} for part in parts):
        raise FixturePathError(f"fixture path must not contain '..': {rel}")
    base = Path(root).resolve()
    folder = base
    for part in parts:
        if part == ".":
            continue
        folder = folder / part
        if folder.is_symlink():
            raise FixturePathError(f"fixture path is a symlink: {rel}")
    if not folder.is_dir():
        raise FixturePathError(f"fixture path is not a directory: {rel}")
    resolved = folder.resolve()
    if resolved != base and base not in resolved.parents:
        raise FixturePathError(f"fixture path escapes its root: {rel}")
    return folder


def read_fixture_bytes(path: Path) -> bytes:
    """Read a regular file without following a symlink at its name."""
    path = Path(path)
    if path.is_symlink():
        raise FixturePathError(f"fixture file is a symlink: {path.name}")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    flags |= getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        if path.is_symlink():
            raise FixturePathError(f"fixture file is a symlink: {path.name}") from exc
        raise
    with os.fdopen(fd, "rb") as handle:
        info = os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode):
            raise FixturePathError(f"fixture file is not a regular file: {path.name}")
        _refuse_hard_link(info, path)
        data = handle.read()
    log = _READ_LOG.get()
    if log is not None:
        log.append((path, hashlib.sha256(data).hexdigest()))
    return data


def _refuse_hard_link(info: os.stat_result, path: Path) -> None:
    # A second name for the inode may live outside the fixture root; git never
    # checks out a hard link, so one here was planted.
    if info.st_nlink > 1:
        raise FixturePathError(f"fixture file has more than one hard link: {path.name}")


def regular_fixture_file(path: Path) -> Path:
    """Return ``path`` when it is a regular file and not a symlink, for a reader that opens by path."""
    path = Path(path)
    info = os.lstat(path)
    if stat.S_ISLNK(info.st_mode):
        raise FixturePathError(f"fixture file is a symlink: {path.name}")
    if not stat.S_ISREG(info.st_mode):
        raise FixturePathError(f"fixture file is not a regular file: {path.name}")
    _refuse_hard_link(info, path)
    return path


def read_fixture_text(path: Path) -> str:
    return read_fixture_bytes(path).decode("utf-8")


def load_object(path: Path) -> dict[str, Any]:
    data = json.loads(read_fixture_text(path))
    if not isinstance(data, dict):
        raise ValueError(f"JSON object required: {path}")
    return data


def dumps_canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, indent=2) + "\n"

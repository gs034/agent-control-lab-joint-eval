# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agent Control Lab contributors
"""Load joint-eval fixtures from eval/ (this tree). Sibling trees are not vendored."""

from __future__ import annotations

import json
import os
import stat
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


def repo_root() -> Path:
    """The source tree that holds this package's fixtures.

    The working directory is not consulted: an installed package run in a
    directory someone else prepared must not pick up that directory's
    fixtures. Pass ``--root`` to run against another tree.
    """
    here = Path(__file__).resolve()
    for candidate in here.parents:
        if (candidate / "eval" / "joint_story" / INDEX_NAME).is_file():
            return candidate
    raise FileNotFoundError("eval/joint_story/index.json not found next to joint_eval; pass --root")


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
        if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
            raise FixturePathError(f"fixture file is not a regular file: {path.name}")
        return handle.read()


def regular_fixture_file(path: Path) -> Path:
    """Return ``path`` when it is a regular file and not a symlink, for a reader that opens by path."""
    path = Path(path)
    info = os.lstat(path)
    if stat.S_ISLNK(info.st_mode):
        raise FixturePathError(f"fixture file is a symlink: {path.name}")
    if not stat.S_ISREG(info.st_mode):
        raise FixturePathError(f"fixture file is not a regular file: {path.name}")
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

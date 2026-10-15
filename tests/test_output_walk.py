# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agent Control Lab contributors
"""The output directory is reached by a descriptor walk, so no component above it can be swapped (J-3)."""

from __future__ import annotations

import os
import threading
from pathlib import Path

import pytest

from joint_eval import safe_write

POSIX = os.name == "posix" and safe_write._POSIX_FD
ROOT_USER = POSIX and os.geteuid() == 0
OTHER = 65534

pytestmark = pytest.mark.skipif(not POSIX, reason="POSIX descriptor walk")


def _write(out: Path) -> None:
    with safe_write.output_directory(out) as output:
        output.replace("a.json", "1\n")


@pytest.mark.skipif(not ROOT_USER, reason="needs lchown to plant another user's symlink")
def test_ancestor_swapped_for_another_users_symlink_after_the_check_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    victim = tmp_path / "victim"
    (victim / "b").mkdir(parents=True)
    (tmp_path / "a" / "b").mkdir(parents=True)
    out = tmp_path / "a" / "b" / "out"
    real = safe_write._require_trusted_links

    def _swap(target: Path) -> None:
        real(target)
        (tmp_path / "a").rename(tmp_path / "aside")
        (tmp_path / "a").symlink_to(victim, target_is_directory=True)
        os.lchown(tmp_path / "a", OTHER, OTHER)

    monkeypatch.setattr(safe_write, "_require_trusted_links", _swap)
    with pytest.raises(safe_write.OutputPathError, match="another user's symlink"):
        _write(out)
    assert list((victim / "b").iterdir()) == []


@pytest.mark.skipif(not ROOT_USER, reason="needs chown")
def test_ancestor_owned_by_another_user_is_refused(tmp_path: Path) -> None:
    shared = tmp_path / "shared"
    mine = shared / "mine"
    mine.mkdir(parents=True)
    os.chown(shared, OTHER, OTHER)
    with pytest.raises(safe_write.OutputPathError, match="parent is owned by another user"):
        _write(mine / "out")
    assert list(mine.iterdir()) == []


def test_ancestor_world_writable_without_sticky_is_refused(tmp_path: Path) -> None:
    shared = tmp_path / "shared"
    mine = shared / "mine"
    mine.mkdir(parents=True)
    shared.chmod(0o777)
    try:
        with pytest.raises(safe_write.OutputPathError, match="without the sticky bit"):
            _write(mine / "out")
    finally:
        shared.chmod(0o755)
    assert list(mine.iterdir()) == []


def test_walk_follows_own_symlinks_and_dotdot(tmp_path: Path) -> None:
    real = tmp_path / "real"
    (real / "deep").mkdir(parents=True)
    (tmp_path / "abs").symlink_to(real, target_is_directory=True)
    (tmp_path / "rel").symlink_to("real/deep", target_is_directory=True)
    _write(tmp_path / "abs" / "deep" / "o1")
    _write(tmp_path / "rel" / "o2")
    _write(tmp_path / "rel" / ".." / "o3")
    _write(tmp_path / "new" / "parents" / "o4")
    assert (real / "deep" / "o1" / "a.json").is_file()
    assert (real / "deep" / "o2" / "a.json").is_file()
    assert (real / "o3" / "a.json").is_file()
    assert (tmp_path / "new" / "parents" / "o4" / "a.json").is_file()


def test_symlink_loop_in_the_parent_is_refused(tmp_path: Path) -> None:
    (tmp_path / "x").symlink_to("y")
    (tmp_path / "y").symlink_to("x")
    with pytest.raises(safe_write.OutputPathError, match="too many symlinks"):
        _write(tmp_path / "x" / "out")


def test_file_in_the_parent_is_refused(tmp_path: Path) -> None:
    (tmp_path / "f").write_text("x", encoding="utf-8")
    with pytest.raises(safe_write.OutputPathError, match="not a directory"):
        _write(tmp_path / "f" / "out")


@pytest.mark.skipif(not ROOT_USER, reason="needs lchown to plant another user's symlink")
def test_racing_ancestor_swap_never_redirects(tmp_path: Path) -> None:
    """A thread flips an ancestor link between this user's directory and another user's target."""
    real = tmp_path / "real"
    victim = tmp_path / "victim"
    (real / "b").mkdir(parents=True)
    (victim / "b").mkdir(parents=True)
    ancestor = tmp_path / "a"
    ancestor.symlink_to(real, target_is_directory=True)
    stop = threading.Event()

    def _flip() -> None:
        while not stop.is_set():
            for target, owner in ((victim, OTHER), (real, os.geteuid())):
                staged = tmp_path / "staged"
                staged.symlink_to(target, target_is_directory=True)
                os.lchown(staged, owner, owner)
                os.replace(staged, ancestor)

    flipper = threading.Thread(target=_flip)
    flipper.start()
    try:
        for index in range(400):
            try:
                _write(ancestor / "b" / f"out{index}")
            except safe_write.OutputPathError:
                pass
    finally:
        stop.set()
        flipper.join()
    assert list((victim / "b").iterdir()) == []
    assert list((real / "b").iterdir())

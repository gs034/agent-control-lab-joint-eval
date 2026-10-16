# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agent Control Lab contributors
"""The output directory is reached by a descriptor walk, so no component above it can be swapped (J-3)."""

from __future__ import annotations

import errno
import os
import stat
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
    flipped = threading.Condition()
    cycles = [0]

    def _flip() -> None:
        while not stop.is_set():
            for target, owner in ((victim, OTHER), (real, os.geteuid())):
                staged = tmp_path / "staged"
                staged.symlink_to(target, target_is_directory=True)
                os.lchown(staged, owner, owner)
                os.replace(staged, ancestor)
            with flipped:
                cycles[0] += 1
                flipped.notify_all()

    flipper = threading.Thread(target=_flip)
    flipper.start()
    try:
        seen = 0
        for index in range(400):
            # Without this gate the writer can hold the interpreter for a whole
            # run while the flipper rests on the victim link: no flips, every
            # try refused, and the last assert fails for a reason that is not
            # the walk's. Waiting for a full flip cycle before each try keeps
            # the race live on every try.
            with flipped:
                assert flipped.wait_for(lambda seen=seen: cycles[0] > seen, timeout=10), "flipper stopped"
                seen = cycles[0]
            try:
                _write(ancestor / "b" / f"out{index}")
            except safe_write.OutputPathError:
                pass
    finally:
        stop.set()
        flipper.join()
    assert list((victim / "b").iterdir()) == []
    assert list((real / "b").iterdir())


def _parent_dir(path: Path) -> int:
    return os.open(path, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_CLOEXEC", 0))


def test_owner_check_and_target_read_stay_on_one_inode(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Replacing the name after the owner is known must not change the target."""
    real = tmp_path / "real"
    victim = tmp_path / "victim"
    real.mkdir()
    victim.mkdir()
    link = tmp_path / "link"
    link.symlink_to(real, target_is_directory=True)
    expected = os.readlink(link)
    swapped = False

    def _swap(info: os.stat_result) -> os.stat_result:
        nonlocal swapped
        if swapped or not stat.S_ISLNK(info.st_mode):
            return info
        swapped = True
        staged = tmp_path / "staged"
        staged.symlink_to(victim, target_is_directory=True)
        os.replace(staged, link)
        return info

    real_stat = os.stat
    real_fstat = os.fstat

    def _stat(path: str, *args: object, **kwargs: object) -> os.stat_result:
        return _swap(real_stat(path, *args, **kwargs))

    def _fstat(fd: int) -> os.stat_result:
        return _swap(real_fstat(fd))

    monkeypatch.setattr(safe_write.os, "stat", _stat)
    monkeypatch.setattr(safe_write.os, "fstat", _fstat)
    parent = _parent_dir(tmp_path)
    try:
        try:
            target: str | None = safe_write._trusted_link_target(
                parent, "link", link, OSError(errno.ELOOP, "too many levels of symbolic links")
            )
        except safe_write.OutputPathError:
            target = None
    finally:
        os.close(parent)
    assert swapped
    assert target in {None, expected}
    assert os.readlink(link) != expected


def test_fallback_returns_a_stable_owned_symlink_target(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "link"
    link.symlink_to(real, target_is_directory=True)
    expected = os.readlink(link)
    monkeypatch.setattr(safe_write, "_open_link_no_follow", lambda *_args, **_kwargs: None)
    parent = _parent_dir(tmp_path)
    try:
        target = safe_write._trusted_link_target(
            parent, "link", link, OSError(errno.ELOOP, "too many levels of symbolic links")
        )
    finally:
        os.close(parent)
    assert target == expected


def test_fallback_refuses_a_link_replaced_between_the_stats(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    real = tmp_path / "real"
    victim = tmp_path / "victim"
    real.mkdir()
    victim.mkdir()
    link = tmp_path / "link"
    link.symlink_to(real, target_is_directory=True)
    monkeypatch.setattr(safe_write, "_open_link_no_follow", lambda *_args, **_kwargs: None)
    real_readlink = os.readlink
    swapped = False

    def _swap_then_read(path: str, *args: object, **kwargs: object) -> str:
        nonlocal swapped
        if not swapped and path not in {"", b""}:
            swapped = True
            staged = tmp_path / "staged"
            staged.symlink_to(victim, target_is_directory=True)
            os.replace(staged, link)
        return real_readlink(path, *args, **kwargs)

    monkeypatch.setattr(safe_write.os, "readlink", _swap_then_read)
    parent = _parent_dir(tmp_path)
    try:
        with pytest.raises(safe_write.OutputPathError, match="another user's symlink"):
            safe_write._trusted_link_target(
                parent, "link", link, OSError(errno.ELOOP, "too many levels of symbolic links")
            )
    finally:
        os.close(parent)
    assert swapped


def _swap_link_before_readlink(
    monkeypatch: pytest.MonkeyPatch, ancestor: Path, victim: Path
) -> list[tuple[str, int | None]]:
    """Replace ``ancestor`` with another user's link to ``victim`` just before the walk's first readlink.

    This is the interleaving the 400-try race wins about one run in twenty:
    the walk has checked the owner of this user's link and is about to read
    its target.
    """
    real_readlink = os.readlink
    calls: list[tuple[str, int | None]] = []

    def _readlink(name, *args, dir_fd=None, **kwargs):  # type: ignore[no-untyped-def]
        if not calls:
            staged = ancestor.parent / "staged"
            staged.symlink_to(victim, target_is_directory=True)
            os.lchown(staged, OTHER, OTHER)
            os.replace(staged, ancestor)
        calls.append((os.fspath(name), dir_fd))
        return real_readlink(name, *args, dir_fd=dir_fd, **kwargs)

    monkeypatch.setattr(safe_write.os, "readlink", _readlink)
    return calls


@pytest.mark.skipif(not ROOT_USER, reason="needs lchown to plant another user's symlink")
def test_link_swapped_between_owner_check_and_readlink_never_redirects(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    real = tmp_path / "real"
    victim = tmp_path / "victim"
    (real / "b").mkdir(parents=True)
    (victim / "b").mkdir(parents=True)
    ancestor = tmp_path / "a"
    ancestor.symlink_to(real, target_is_directory=True)
    calls = _swap_link_before_readlink(monkeypatch, ancestor, victim)
    try:
        _write(ancestor / "b" / "out")
    except safe_write.OutputPathError:
        pass
    assert calls, "the walk did not read the ancestor link"
    assert list((victim / "b").iterdir()) == []
    if hasattr(os, "O_PATH"):
        # The link checked is the link read: the write follows this user's link.
        assert (real / "b" / "out" / "a.json").is_file()

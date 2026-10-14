# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agent Control Lab contributors
"""Write output files without trusting what is already at the output path.

A predictable output path (``/tmp/...``) lets another local user pre-create
the directory, or its parent, and plant links at the output names. On POSIX
the output directory is opened once by descriptor and every file is created
under a fresh ``O_EXCL | O_NOFOLLOW`` name relative to it, then renamed into
place, so a link is never followed and the directory cannot be swapped after
it is checked.
"""

from __future__ import annotations

import contextlib
import os
import secrets
import stat
from collections.abc import Iterator
from pathlib import Path

_POSIX_FD = (
    os.name == "posix"
    and hasattr(os, "O_NOFOLLOW")
    and hasattr(os, "O_DIRECTORY")
    and os.open in os.supports_dir_fd
    and os.mkdir in os.supports_dir_fd
)


class OutputPathError(ValueError):
    """The output location is not one this process can write safely."""


class OutputDirectory:
    """An output directory held open by descriptor (POSIX) or by path (other hosts)."""

    def __init__(self, path: Path, fd: int | None) -> None:
        self.path = path
        self._fd = fd

    def require_writable_name(self, name: str) -> None:
        """Refuse a name that already holds anything but a regular file."""
        _require_single_name(name)
        try:
            if self._fd is None:
                info = os.lstat(self.path / name)
            else:
                info = os.stat(name, dir_fd=self._fd, follow_symlinks=False)
        except FileNotFoundError:
            return
        if not stat.S_ISREG(info.st_mode):
            raise OutputPathError(f"output entry is not a regular file: {self.path / name}")

    def replace(self, name: str, body: str) -> None:
        """Write ``body`` to a fresh file and rename it over ``name``."""
        self.require_writable_name(name)
        temporary = f".{name}.{secrets.token_hex(8)}.tmp"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        flags |= getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0)
        if self._fd is None:
            fd = os.open(self.path / temporary, flags, 0o644)
        else:
            fd = os.open(temporary, flags, 0o644, dir_fd=self._fd)
        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="") as handle:
                handle.write(body)
            if self._fd is None:
                os.replace(self.path / temporary, self.path / name)
            else:
                os.replace(temporary, name, src_dir_fd=self._fd, dst_dir_fd=self._fd)
        except BaseException:
            with contextlib.suppress(OSError):
                if self._fd is None:
                    os.unlink(self.path / temporary)
                else:
                    os.unlink(temporary, dir_fd=self._fd)
            raise


@contextlib.contextmanager
def output_directory(path: Path | str) -> Iterator[OutputDirectory]:
    """Create or open ``path`` as an output directory this user owns.

    Refused (``OutputPathError``):
    - a symlink anywhere in the given path that another user owns;
    - a parent directory another user (other than root) owns, or that anyone
      can write without the sticky bit;
    - an output directory that is a symlink, owned by another user, or
      world-writable.
    """
    target = Path(path).absolute()
    if target.name in {"", ".", ".."}:
        raise OutputPathError(f"output path must name a directory: {path}")
    _require_trusted_links(target)
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise OutputPathError(f"output parent unavailable: {exc}") from exc
    if not _POSIX_FD:
        if target.is_symlink() or (target.exists() and not target.is_dir()):
            raise OutputPathError(f"output path is not a directory: {target}")
        target.mkdir(exist_ok=True)
        yield OutputDirectory(target, None)
        return
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0)
    try:
        parent_fd = os.open(target.parent.resolve(), flags)
    except OSError as exc:
        raise OutputPathError(f"output parent unavailable: {exc}") from exc
    try:
        _require_trusted_parent(parent_fd, target.parent)
        try:
            os.mkdir(target.name, 0o755, dir_fd=parent_fd)
        except FileExistsError:
            pass
        except OSError as exc:
            raise OutputPathError(f"output path unavailable: {exc}") from exc
        try:
            fd = os.open(target.name, flags | os.O_NOFOLLOW, dir_fd=parent_fd)
        except OSError as exc:
            raise OutputPathError(f"output path is not a directory: {target}") from exc
        try:
            _require_own_directory(fd, target)
            yield OutputDirectory(target, fd)
        finally:
            os.close(fd)
    finally:
        os.close(parent_fd)


def _require_single_name(name: str) -> None:
    if not name or name in {".", ".."} or "/" in name or os.sep in name:
        raise OutputPathError(f"output name must be a single file name: {name!r}")


def _require_trusted_links(target: Path) -> None:
    """A symlink in the given path is followed only when this user or root owns it."""
    if not hasattr(os, "geteuid"):
        return
    current = Path(target.anchor)
    for part in target.parts[1:]:
        current = current / part
        try:
            info = os.lstat(current)
        except FileNotFoundError:
            return
        if stat.S_ISLNK(info.st_mode) and info.st_uid not in {os.geteuid(), 0}:
            raise OutputPathError(f"output path passes through another user's symlink: {current}")


def _require_trusted_parent(fd: int, label: Path) -> None:
    info = os.fstat(fd)
    if info.st_uid not in {os.geteuid(), 0}:
        raise OutputPathError(f"output parent is owned by another user: {label}")
    mode = stat.S_IMODE(info.st_mode)
    if mode & stat.S_IWOTH and not mode & stat.S_ISVTX:
        raise OutputPathError(f"output parent is world-writable without the sticky bit: {label}")


def _require_own_directory(fd: int, label: Path) -> None:
    info = os.fstat(fd)
    if not stat.S_ISDIR(info.st_mode):
        raise OutputPathError(f"output path is not a directory: {label}")
    if info.st_uid != os.geteuid():
        raise OutputPathError(f"output directory is owned by another user: {label}")
    if stat.S_IMODE(info.st_mode) & stat.S_IWOTH:
        raise OutputPathError(f"output directory is world-writable: {label}")

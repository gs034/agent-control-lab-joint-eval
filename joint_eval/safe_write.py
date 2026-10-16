# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agent Control Lab contributors
"""Write output files without trusting what is already at the output path.

A predictable output path (``/tmp/...``) lets another local user pre-create
the directory, or its parent, and plant links at the output names. On POSIX
the output directory is opened once by descriptor and every file is created
under a fresh ``O_EXCL | O_NOFOLLOW`` name relative to it, then renamed into
place, so a link is never followed and the directory cannot be swapped after
it is checked.

Durability: each file is fsynced before its rename, and the directory is
fsynced after, so a rename that has returned survives a power loss.

Known limit, output sets: ``replace_all`` stages every file first and only
then renames them, so a failure while writing bodies leaves the previous set
untouched. The renames themselves are still one per file. A crash between two
renames leaves a mixed set (some files new, some old) on disk. POSIX has no
portable way to swap a non-empty directory in one step, so this limit is
documented rather than closed.

Group-writable directories are accepted. The threat here is another local
user; a group member shares the owner's trust on the hosts this runs on, and
hosts with umask 002 (user-private groups) create every directory 0o775, so
refusing group write would refuse the harness's own output. World write is
refused.
"""

from __future__ import annotations

import contextlib
import errno
import logging
import os
import secrets
import stat
from collections.abc import Iterable, Iterator
from pathlib import Path

_logger = logging.getLogger(__name__)

_POSIX_FD = (
    os.name == "posix"
    and hasattr(os, "O_NOFOLLOW")
    and hasattr(os, "O_DIRECTORY")
    and os.open in os.supports_dir_fd
    and os.mkdir in os.supports_dir_fd
    and os.stat in os.supports_dir_fd
    and os.readlink in os.supports_dir_fd
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
        if info.st_nlink > 1:
            # A hard link at the name means another path shares the inode. The
            # rename would detach it harmlessly, but a link planted here is a
            # sign the directory is not ours alone, so refuse.
            raise OutputPathError(
                f"output entry has more than one hard link: {self.path / name}; "
                "remove the extra link or choose a fresh directory"
            )

    def replace(self, name: str, body: str) -> None:
        """Write ``body`` to a fresh file, fsync it, rename it over ``name``, fsync the directory."""
        self.replace_all(((name, body),))

    def replace_all(self, outputs: Iterable[tuple[str, str]]) -> None:
        """Stage every file (write and fsync), then rename each into place, then fsync the directory.

        A failure before the first rename leaves the directory as it was and
        removes every staged file. See the module docstring for the limit on
        what happens between renames.
        """
        pending = list(outputs)
        names = [name for name, _body in pending]
        if len(set(names)) != len(names):
            raise OutputPathError("output names must be distinct")
        for name in names:
            self.require_writable_name(name)
        staged: list[tuple[str, str]] = []
        renamed = 0
        try:
            for name, body in pending:
                staged.append((self._stage(name, body), name))
            for temporary, name in staged:
                if self._fd is None:
                    os.replace(self.path / temporary, self.path / name)
                else:
                    os.replace(temporary, name, src_dir_fd=self._fd, dst_dir_fd=self._fd)
                renamed += 1
            staged = []
        finally:
            for temporary, _name in staged[renamed:]:
                with contextlib.suppress(OSError):
                    if self._fd is None:
                        os.unlink(self.path / temporary)
                    else:
                        os.unlink(temporary, dir_fd=self._fd)
            if renamed:
                # Renames that did happen are made durable even when a later one failed.
                self._fsync_directory()

    def _stage(self, name: str, body: str) -> str:
        """Create a fresh temporary beside ``name``, write ``body``, fsync, and return its name."""
        temporary = f".{name}.{secrets.token_hex(8)}.tmp"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        flags |= getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0)
        if self._fd is None:
            fd = os.open(self.path / temporary, flags, 0o644)
        else:
            fd = os.open(temporary, flags, 0o644, dir_fd=self._fd)
        try:
            try:
                handle = os.fdopen(fd, "w", encoding="utf-8", newline="")
            except BaseException:
                os.close(fd)
                raise
            with handle:
                info = os.fstat(handle.fileno())
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                    raise OutputPathError(f"output temporary is not a fresh regular file: {self.path / temporary}")
                handle.write(body)
                handle.flush()
                os.fsync(handle.fileno())
        except BaseException:
            with contextlib.suppress(OSError):
                if self._fd is None:
                    os.unlink(self.path / temporary)
                else:
                    os.unlink(temporary, dir_fd=self._fd)
            raise
        return temporary

    def _fsync_directory(self) -> None:
        """Make the renames durable.

        A file system that cannot fsync a directory (EINVAL, ENOTSUP, ENOTTY)
        is left as is. Any other error, EIO and ENOSPC included, propagates:
        swallowing it would claim durability that was not delivered.

        The fallback path opens the directory before that fsync. EINVAL,
        ENOTSUP, EOPNOTSUPP, and ENOTTY mean this host cannot open a directory
        that way, and the open returns quietly. EACCES and EPERM also skip
        the directory fsync, and a warning is logged so the missing durability
        is not silent. Any other error from the open is re-raised.
        """
        if self._fd is not None:
            _fsync_directory_fd(self._fd)
            return
        if not hasattr(os, "O_DIRECTORY"):
            return
        try:
            fd = os.open(self.path, os.O_RDONLY | os.O_DIRECTORY)
        except OSError as exc:
            if exc.errno not in _DIRECTORY_OPEN_QUIET:
                raise
            if exc.errno in _DIRECTORY_OPEN_PERMISSION:
                _logger.warning(
                    "directory fsync skipped for %s: [%s] %s",
                    self.path,
                    errno.errorcode.get(exc.errno, exc.errno),
                    exc.strerror,
                )
            return
        try:
            _fsync_directory_fd(fd)
        finally:
            os.close(fd)


@contextlib.contextmanager
def output_directory(path: Path | str) -> Iterator[OutputDirectory]:
    """Create or open ``path`` as an output directory this user owns.

    Refused (``OutputPathError``):
    - a symlink anywhere in the given path that another user owns;
    - a directory on the way to the output directory (its parent and every
      ancestor up to ``/``) that another user (other than root) owns, or
      that anyone can write without the sticky bit;
    - an output directory that is a symlink, owned by another user, or
      world-writable. Group write is accepted (see the module docstring).
    """
    target = Path(path).absolute()
    if target.name in {"", ".", ".."}:
        raise OutputPathError(f"output path must name a directory: {path}")
    _require_trusted_links(target)
    if not _POSIX_FD:
        try:
            target.parent.mkdir(0o755, parents=True, exist_ok=True)
        except OSError as exc:
            raise OutputPathError(f"output parent unavailable: {exc}") from exc
        if target.is_symlink() or (target.exists() and not target.is_dir()):
            raise OutputPathError(f"output path is not a directory: {target}")
        target.mkdir(exist_ok=True)
        yield OutputDirectory(target, None)
        return
    parent_fd = _open_parent(target.parent)
    try:
        try:
            os.mkdir(target.name, 0o755, dir_fd=parent_fd)
        except FileExistsError:
            pass
        except OSError as exc:
            raise OutputPathError(f"output path unavailable: {exc}") from exc
        try:
            fd = os.open(target.name, _DIR_FLAGS | os.O_NOFOLLOW, dir_fd=parent_fd)
        except OSError as exc:
            raise OutputPathError(f"output path is not a directory: {target}") from exc
        try:
            _require_own_directory(fd, target)
            yield OutputDirectory(target, fd)
        finally:
            os.close(fd)
    finally:
        os.close(parent_fd)


_DIR_FLAGS = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0)

# Same bound the Linux kernel uses for symlinks followed in one lookup.
_MAX_LINKS = 40


def _open_parent(parent: Path) -> int:
    """Open ``parent`` by descriptor, one component at a time from ``/``.

    Each component is opened relative to the descriptor of the one before it
    with ``O_DIRECTORY | O_NOFOLLOW``, and each directory reached must pass
    the parent rules (this user or root owns it; world write needs the
    sticky bit). A missing component is created (0o755). A symlink is
    followed only when this user or root owns it; its target is walked the
    same way, from ``/`` when absolute or from the directory holding the
    link otherwise. The owner and the target are taken from one open inode
    (``O_PATH | O_NOFOLLOW``), so a name swapped in between cannot change
    either. Because every step holds the directory it checked, renaming or
    replacing a component after the check cannot redirect the walk.
    """
    pending = list(parent.parts[1:])
    label = Path(parent.anchor or os.sep)
    fd = _open_anchor(label)
    links = 0
    created: str | None = None
    try:
        _require_trusted_parent(fd, label)
        while pending:
            part = pending.pop(0)
            if part in {"", "."}:
                continue
            try:
                child = os.open(part, _DIR_FLAGS | os.O_NOFOLLOW, dir_fd=fd)
            except FileNotFoundError as exc:
                if created == part:
                    raise OutputPathError(f"output parent vanished while it was created: {label / part}") from exc
                created = part
                try:
                    os.mkdir(part, 0o755, dir_fd=fd)
                except FileExistsError:
                    pass
                except OSError as exc:
                    raise OutputPathError(f"output parent unavailable: {label / part}: {exc}") from exc
                pending.insert(0, part)
                continue
            except OSError as exc:
                target = _trusted_link_target(fd, part, label / part, exc)
                links += 1
                if links > _MAX_LINKS:
                    raise OutputPathError(f"output path has too many symlinks: {parent}") from exc
                link_parts = list(Path(target).parts)
                if Path(target).is_absolute():
                    os.close(fd)
                    fd = -1
                    label = Path(link_parts[0])
                    fd = _open_anchor(label)
                    _require_trusted_parent(fd, label)
                    link_parts = link_parts[1:]
                pending[:0] = link_parts
                continue
            created = None
            os.close(fd)
            fd = child
            label = label / part
            _require_trusted_parent(fd, label)
        return fd
    except BaseException:
        if fd >= 0:
            os.close(fd)
        raise


def _open_anchor(label: Path) -> int:
    try:
        return os.open(label, _DIR_FLAGS)
    except OSError as exc:
        raise OutputPathError(f"output parent unavailable: {exc}") from exc


# open(O_PATH) is missing or this filesystem rejects the flag.
_OPATH_UNSUPPORTED = frozenset(
    code
    for code in (
        getattr(errno, "EINVAL", None),
        getattr(errno, "ENOTSUP", None),
        getattr(errno, "EOPNOTSUPP", None),
        getattr(errno, "ENOSYS", None),
    )
    if code
)


def _trusted_link_target(dir_fd: int, name: str, label: Path, error: OSError) -> str:
    """The open of ``name`` failed: return a trusted symlink's target, or refuse.

    The owner check and the target read have to describe the same inode. A
    swap between a separate stat and readlink would let the walk follow
    another user's link. Open the link with ``O_PATH | O_NOFOLLOW`` and use
    that descriptor for both: ``fstat`` for the owner, and ``readlinkat`` on
    the descriptor (an empty path) for the target.

    Where ``O_PATH`` cannot be used, stat the name, read the target, stat
    again, and refuse unless device, inode, and owner are unchanged.
    """
    opened = _open_link_no_follow(dir_fd, name, label)
    if opened is not None:
        try:
            return _trusted_target_from_fd(opened, label, error)
        finally:
            os.close(opened)
    return _trusted_link_target_recheck(dir_fd, name, label, error)


def _open_link_no_follow(dir_fd: int, name: str, label: Path) -> int | None:
    """Open ``name`` without following it. ``None`` when ``O_PATH`` is unavailable."""
    if not hasattr(os, "O_PATH"):
        return None
    flags = os.O_PATH | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    try:
        return os.open(name, flags, dir_fd=dir_fd)
    except OSError as exc:
        if exc.errno in _OPATH_UNSUPPORTED:
            return None
        raise OutputPathError(f"output parent unavailable: {label}: {exc}") from exc


def _trusted_target_from_fd(fd: int, label: Path, error: OSError) -> str:
    """Owner and target of the inode ``fd`` already refers to."""
    info = os.fstat(fd)
    _refuse_untrusted_link(info, label, error)
    try:
        # readlinkat(fd, "") returns this inode's body. readlink of
        # /proc/self/fd/<fd> names the path of the descriptor, not the body.
        return os.readlink("", dir_fd=fd)
    except OSError as exc:
        raise OutputPathError(f"output parent unavailable: {label}: {exc}") from exc


def _refuse_untrusted_link(info: os.stat_result, label: Path, error: OSError) -> None:
    if not stat.S_ISLNK(info.st_mode):
        if not stat.S_ISDIR(info.st_mode):
            raise OutputPathError(f"output parent is not a directory: {label}") from error
        raise OutputPathError(f"output parent unavailable: {label}: {error}") from error
    if info.st_uid not in {os.geteuid(), 0}:
        raise OutputPathError(f"output path passes through another user's symlink: {label}")


def _trusted_link_target_recheck(dir_fd: int, name: str, label: Path, error: OSError) -> str:
    """Stat, read, stat again. Refuse unless device, inode, and owner match."""
    try:
        before = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
    except OSError as exc:
        raise OutputPathError(f"output parent unavailable: {label}: {exc}") from exc
    _refuse_untrusted_link(before, label, error)
    try:
        target = os.readlink(name, dir_fd=dir_fd)
    except OSError as exc:
        raise OutputPathError(f"output parent unavailable: {label}: {exc}") from exc
    try:
        after = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
    except OSError as exc:
        raise OutputPathError(f"output parent unavailable: {label}: {exc}") from exc
    same = (
        before.st_dev == after.st_dev
        and before.st_ino == after.st_ino
        and before.st_uid == after.st_uid
        and stat.S_ISLNK(after.st_mode)
    )
    if not same:
        raise OutputPathError(f"output path passes through another user's symlink: {label}")
    return target


_FSYNC_UNSUPPORTED = frozenset(
    code for code in (getattr(errno, "EINVAL", None), getattr(errno, "ENOTSUP", None), getattr(errno, "ENOTTY", None)) if code
)

_DIRECTORY_OPEN_UNSUPPORTED = frozenset(
    code
    for code in (
        getattr(errno, "EINVAL", None),
        getattr(errno, "ENOTSUP", None),
        getattr(errno, "EOPNOTSUPP", None),
        getattr(errno, "ENOTTY", None),
    )
    if code
)

_DIRECTORY_OPEN_PERMISSION = frozenset(
    code for code in (getattr(errno, "EACCES", None), getattr(errno, "EPERM", None)) if code
)

_DIRECTORY_OPEN_QUIET = _DIRECTORY_OPEN_UNSUPPORTED | _DIRECTORY_OPEN_PERMISSION


def _fsync_directory_fd(fd: int) -> None:
    try:
        os.fsync(fd)
    except OSError as exc:
        if exc.errno not in _FSYNC_UNSUPPORTED:
            raise


def _require_single_name(name: str) -> None:
    if not name or name in {".", ".."} or "/" in name or os.sep in name:
        raise OutputPathError(f"output name must be a single file name: {name!r}")


def _require_trusted_links(target: Path) -> None:
    """A symlink in the given path is followed only when this user or root owns it.

    An early, by-name check for a clear message. On POSIX the descriptor walk
    in ``_open_parent`` applies the same rule again and is the one relied on.
    """
    if not hasattr(os, "geteuid"):
        return
    current = Path(target.anchor)
    for part in target.parts[1:]:
        current = current / part
        try:
            info = os.lstat(current)
        except OSError:
            # Missing, a loop, or not a directory: the walk (or the fallback
            # mkdir) reports it.
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

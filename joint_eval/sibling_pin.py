# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agent Control Lab contributors
"""Prove that fixture bytes read from a sibling checkout are the pinned commit's bytes.

A ``HEAD`` string equal to the pin is not enough. A directory with a
``.git/HEAD`` that names the pin and holds no objects passes that check,
and so does a real checkout at the pin whose fixture files were edited.

``PinnedTree`` opens a checkout once and then checks each file the paired
runner reads from it:

- The checkout must have a ``.git`` directory (not a ``.git`` file or a
  link) whose repository-local config sets only keys on a small inert
  allowlist, and ``HEAD`` must be the pin.
- The pinned commit and every tree on the way to a fixture file are read
  from the object store with ``git cat-file`` and hashed here. An object
  whose bytes do not hash to the id that names it is refused, so a
  planted or replaced loose object cannot stand in for the pinned tree.
- A fixture file is read from the worktree as before, its git blob id is
  computed here from the exact bytes read, and that id must equal the
  blob id the pinned tree lists for the path. A file the pinned tree does
  not list is refused, and so is a file the tree lists but the checkout
  lacks.

Git runs only plumbing that reads objects and config (``config --list``,
``rev-parse``, ``cat-file``). It runs with an explicit ``--git-dir``, no
system or global config, inherited ``GIT_*`` variables dropped, hooks and
fsmonitor off, and every transport blocked, so a planted promisor remote
cannot start a command during a lazy fetch. Object ids are SHA-1. A
repository that declares another object format is refused.
"""

from __future__ import annotations

import fnmatch
import hashlib
import os
import re
import stat
import subprocess
from pathlib import Path

from joint_eval.loader import read_fixture_bytes
from joint_eval.story import JointEvalError

GIT_TIMEOUT_SECONDS = 60

# Repository-local config keys a pinned checkout may carry. Anything else is
# refused before git reads an object, because a key outside this list can
# name a program (core.fsmonitor, filter.*, core.sshcommand), retarget the
# repository (core.worktree, include.path) or add a promisor remote that git
# would fetch from (extensions.partialclone, remote.*.promisor). The list is
# what ``git init``, ``git clone`` and a pip ``git+`` install write.
_INERT_KEYS = (
    "core.repositoryformatversion",
    "core.filemode",
    "core.bare",
    "core.logallrefupdates",
    "core.ignorecase",
    "core.precomposeunicode",
    "core.symlinks",
    "extensions.refstorage",
    "remote.*.url",
    "remote.*.fetch",
    "branch.*.remote",
    "branch.*.merge",
)
_FALSE_VALUES = frozenset({"", "false", "no", "off", "0"})
_REGULAR_MODES = frozenset({b"100644", b"100755"})
_TREE_MODE = b"40000"
_SHA1_HEX = re.compile(r"[0-9a-f]{40}\Z")
# Not a real protocol name: GIT_ALLOW_PROTOCOL then allows no transport at all.
_NO_TRANSPORT = "acl-no-transport"


class SiblingPinError(JointEvalError):
    """A sibling checkout or file is not provably the pinned commit. Fail closed."""


def git_object_id(kind: bytes, body: bytes) -> str:
    """The SHA-1 git object id of ``body`` stored as an object of type ``kind``."""
    return hashlib.sha1(b"%s %d\0" % (kind, len(body)) + body).hexdigest()


def git_blob_id(data: bytes) -> str:
    """The git blob id of ``data`` (what ``git hash-object`` prints)."""
    return git_object_id(b"blob", data)


class PinnedTree:
    """One sibling checkout, checked against one pinned commit."""

    def __init__(self, root: Path, pin: str, label: str) -> None:
        self.label = label
        self.pin = pin
        if not _SHA1_HEX.match(pin):
            raise SiblingPinError(f"{label} pin must be a 40-hex SHA-1 commit id: {pin}")
        path = Path(root)
        if not path.is_dir():
            raise SiblingPinError(f"{label} checkout is not a directory: {root}")
        self.root = path.resolve()
        self._git_dir = self.root / ".git"
        try:
            info = os.lstat(self._git_dir)
        except OSError as exc:
            raise SiblingPinError(f"{label} checkout has no .git directory at {root}") from exc
        if not stat.S_ISDIR(info.st_mode):
            raise SiblingPinError(
                f"{label} checkout .git must be a directory, not a file or link, at {root}"
            )
        self._require_inert_config()
        try:
            head = self._git("rev-parse", "--verify", "--quiet", "HEAD").decode("ascii", "replace").strip()
        except SiblingPinError as exc:
            raise SiblingPinError(f"{label} checkout is not a git HEAD at {root}: {exc}") from exc
        if head != pin:
            raise SiblingPinError(f"{label} checkout HEAD {head or '(none)'} does not match pin {pin}")
        commit = self._object(b"commit", pin, missing=f"{label} checkout does not hold pinned commit {pin}")
        first = commit.split(b"\n", 1)[0]
        if not first.startswith(b"tree ") or not _SHA1_HEX.match(first[5:].decode("ascii", "replace")):
            raise SiblingPinError(f"{label} pinned commit {pin} has no tree line")
        self._root_tree = first[5:].decode("ascii")
        self._trees: dict[str, dict[bytes, tuple[bytes, str]]] = {}

    def read_bytes(self, path: Path) -> bytes:
        """Read ``path`` from the worktree and prove the bytes are the pinned blob."""
        rel = self._relative(path)
        entry = self._entry(rel)
        if entry is None or entry[0] not in _REGULAR_MODES:
            raise SiblingPinError(
                f"{self.label} fixture {rel} is not a regular file in pinned commit {self.pin}"
            )
        data = read_fixture_bytes(path)
        if git_blob_id(data) != entry[1]:
            raise SiblingPinError(
                f"{self.label} fixture {rel} does not match its bytes at pinned commit {self.pin}"
            )
        return data

    def has_file(self, path: Path) -> bool:
        """Whether the pinned commit has a regular file at ``path``. The checkout must agree."""
        rel = self._relative(path)
        entry = self._entry(rel)
        pinned = entry is not None and entry[0] in _REGULAR_MODES
        present = os.path.lexists(path)
        if pinned and not present:
            raise SiblingPinError(
                f"{self.label} fixture {rel} is in pinned commit {self.pin} but missing from the checkout"
            )
        if present and not pinned:
            raise SiblingPinError(
                f"{self.label} fixture {rel} is not a regular file in pinned commit {self.pin}"
            )
        return pinned

    def _relative(self, path: Path) -> str:
        try:
            parts = Path(path).relative_to(self.root).parts
        except ValueError as exc:
            raise SiblingPinError(f"{self.label} fixture path is outside the checkout: {path}") from exc
        if not parts or any(part in {"", ".", ".."} for part in parts) or parts[0] == ".git":
            raise SiblingPinError(f"{self.label} fixture path is not a checkout file: {path}")
        return "/".join(parts)

    def _entry(self, rel: str) -> tuple[bytes, str] | None:
        parts = rel.split("/")
        tree = self._root_tree
        for part in parts[:-1]:
            entry = self._tree(tree).get(os.fsencode(part))
            if entry is None or entry[0] != _TREE_MODE:
                return None
            tree = entry[1]
        return self._tree(tree).get(os.fsencode(parts[-1]))

    def _tree(self, oid: str) -> dict[bytes, tuple[bytes, str]]:
        cached = self._trees.get(oid)
        if cached is not None:
            return cached
        body = self._object(
            b"tree", oid, missing=f"{self.label} checkout does not hold tree {oid} of pin {self.pin}"
        )
        entries: dict[bytes, tuple[bytes, str]] = {}
        index = 0
        while index < len(body):
            space = body.find(b" ", index)
            nul = body.find(b"\0", space + 1) if space >= 0 else -1
            if space < 0 or nul < 0 or nul + 21 > len(body):
                raise SiblingPinError(f"{self.label} tree {oid} of pin {self.pin} is malformed")
            entries[body[space + 1 : nul]] = (body[index:space], body[nul + 1 : nul + 21].hex())
            index = nul + 21
        self._trees[oid] = entries
        return entries

    def _object(self, kind: bytes, oid: str, *, missing: str) -> bytes:
        try:
            body = self._git("cat-file", kind.decode("ascii"), oid)
        except SiblingPinError as exc:
            raise SiblingPinError(f"{missing}: {exc}") from exc
        if git_object_id(kind, body) != oid:
            raise SiblingPinError(
                f"{self.label} object {oid} does not hash to its id; refusing the checkout"
            )
        return body

    def _require_inert_config(self) -> None:
        listed = self._git("config", "--list", "--null", "--show-scope")
        fields = listed.split(b"\0")
        read_local = False
        for index in range(0, len(fields) - 1, 2):
            scope = fields[index].decode("utf-8", "replace")
            key, _sep, value = fields[index + 1].decode("utf-8", "replace").partition("\n")
            if scope == "command" or not key:
                continue
            lowered = key.lower()
            if scope == "local" and lowered == "core.repositoryformatversion":
                read_local = True
            if lowered == "core.fsmonitor" and value.strip().lower() in _FALSE_VALUES:
                continue
            if lowered == "extensions.objectformat" and value.strip().lower() == "sha1":
                continue
            if any(fnmatch.fnmatchcase(lowered, pattern) for pattern in _INERT_KEYS):
                continue
            raise SiblingPinError(
                f"{self.label} checkout git config sets {key}, which is not on the inert "
                "allowlist; refusing to read it as the pinned tree"
            )
        # Git skips a repository whose format it does not accept and then
        # lists no local config at all, which would pass the loop above.
        if not read_local:
            raise SiblingPinError(
                f"{self.label} checkout git config was not read (no local "
                "core.repositoryformatversion); refusing to read it as the pinned tree"
            )

    def _git(self, *args: str) -> bytes:
        env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
        env.update(
            {
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_CONFIG_SYSTEM": os.devnull,
                "GIT_CONFIG_GLOBAL": os.devnull,
                "GIT_CEILING_DIRECTORIES": str(self.root.parent),
                "GIT_ALLOW_PROTOCOL": _NO_TRANSPORT,
                "GIT_PROTOCOL_FROM_USER": "0",
                "GIT_TERMINAL_PROMPT": "0",
                "GIT_NO_REPLACE_OBJECTS": "1",
                "GIT_OPTIONAL_LOCKS": "0",
            }
        )
        command = [
            "git",
            f"--git-dir={self._git_dir}",
            "-c",
            f"core.hooksPath={os.devnull}",
            "-c",
            "core.fsmonitor=false",
            *args,
        ]
        try:
            proc = subprocess.run(
                command,
                cwd=self._git_dir,
                env=env,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                timeout=GIT_TIMEOUT_SECONDS,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise SiblingPinError(f"{self.label} git {args[0]} unavailable: {exc}") from exc
        if proc.returncode != 0:
            detail = proc.stderr.decode("utf-8", "replace").strip().splitlines()
            reason = detail[-1] if detail else f"exit {proc.returncode}"
            raise SiblingPinError(f"{self.label} git {args[0]} failed: {reason}")
        return proc.stdout

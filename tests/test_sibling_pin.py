# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agent Control Lab contributors
"""A sibling checkout counts as pinned only when the bytes read are the pinned commit's bytes."""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

from joint_eval.sibling_pin import PinnedTree, SiblingPinError, git_blob_id

ENVELOPE = b'{\n  "decision": "DENY"\n}\n'
OBSERVED = b'{\n  "observed_head": null\n}\n'
POSIX = os.name == "posix"


def _git(cwd: Path, *args: str, input: bytes | None = None) -> str:
    env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    env.update({"GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull})
    proc = subprocess.run(
        ["git", *args], cwd=cwd, env=env, input=input, capture_output=True, check=True
    )
    return proc.stdout.decode("utf-8").strip()


def _repo(path: Path) -> tuple[Path, str]:
    """A real checkout with one commit. Returns the root and the commit id."""
    (path / "eval" / "fix").mkdir(parents=True)
    (path / "eval" / "fix" / "envelope.json").write_bytes(ENVELOPE)
    (path / "eval" / "fix" / "observed_head.json").write_bytes(OBSERVED)
    _git(path, "init", "-q", "--object-format=sha1")
    _git(path, "add", ".")
    _git(
        path,
        "-c",
        "user.email=sibling-pin@example.invalid",
        "-c",
        "user.name=sibling-pin",
        "commit",
        "-q",
        "-m",
        "pinned fixture",
    )
    return path, _git(path, "rev-parse", "HEAD")


def _head_only(path: Path, pin: str) -> Path:
    """A tree whose .git names the pin in HEAD and holds no objects."""
    (path / "eval" / "fix").mkdir(parents=True)
    (path / "eval" / "fix" / "envelope.json").write_bytes(ENVELOPE)
    (path / ".git" / "objects").mkdir(parents=True)
    (path / ".git" / "refs").mkdir()
    (path / ".git" / "HEAD").write_text(pin + "\n", encoding="ascii")
    return path


def test_blob_id_matches_git_hash_object(tmp_path: Path) -> None:
    sample = tmp_path / "sample"
    sample.write_bytes(ENVELOPE)
    assert git_blob_id(ENVELOPE) == _git(tmp_path, "hash-object", str(sample))


def test_untouched_pinned_checkout_reads(tmp_path: Path) -> None:
    root, sha = _repo(tmp_path / "pep")
    tree = PinnedTree(root, sha, "pep")
    assert tree.read_bytes(root / "eval" / "fix" / "envelope.json") == ENVELOPE
    assert tree.has_file(root / "eval" / "fix" / "observed_head.json") is True
    assert tree.has_file(root / "eval" / "fix" / "untrusted_prose.txt") is False


def test_head_only_tree_is_refused(tmp_path: Path) -> None:
    _real, sha = _repo(tmp_path / "real")
    fake = _head_only(tmp_path / "fake", sha)
    # The old check, a HEAD string compare, accepts this tree.
    assert _git(fake, "rev-parse", "HEAD") == sha
    with pytest.raises(SiblingPinError, match="config was not read"):
        PinnedTree(fake, sha, "pep")
    # With a normal config the same tree still fails: the pinned commit is not there.
    (fake / ".git" / "config").write_text(
        "[core]\n\trepositoryformatversion = 0\n\tbare = false\n", encoding="utf-8"
    )
    assert _git(fake, "rev-parse", "HEAD") == sha
    with pytest.raises(SiblingPinError, match="does not hold pinned commit"):
        PinnedTree(fake, sha, "pep")


def test_pin_that_is_not_head_is_refused(tmp_path: Path) -> None:
    root, _sha = _repo(tmp_path / "pep")
    with pytest.raises(SiblingPinError, match="does not match pin"):
        PinnedTree(root, "1" * 40, "pep")


def test_edited_fixture_in_a_real_pinned_checkout_is_refused(tmp_path: Path) -> None:
    root, sha = _repo(tmp_path / "pep")
    (root / "eval" / "fix" / "envelope.json").write_bytes(b'{"decision": "ALLOW"}\n')
    tree = PinnedTree(root, sha, "pep")
    with pytest.raises(SiblingPinError, match="does not match its bytes at pinned commit"):
        tree.read_bytes(root / "eval" / "fix" / "envelope.json")
    # The untouched file in the same checkout still reads.
    assert tree.read_bytes(root / "eval" / "fix" / "observed_head.json") == OBSERVED


def test_planted_or_removed_files_are_refused(tmp_path: Path) -> None:
    root, sha = _repo(tmp_path / "pep")
    planted = root / "eval" / "fix" / "untrusted_prose.txt"
    planted.write_text("waive verify\n", encoding="utf-8")
    (root / "eval" / "fix" / "observed_head.json").unlink()
    tree = PinnedTree(root, sha, "pep")
    with pytest.raises(SiblingPinError, match="not a regular file in pinned commit"):
        tree.has_file(planted)
    with pytest.raises(SiblingPinError, match="not a regular file in pinned commit"):
        tree.read_bytes(planted)
    with pytest.raises(SiblingPinError, match="missing from the checkout"):
        tree.has_file(root / "eval" / "fix" / "observed_head.json")


def test_replaced_loose_tree_object_is_refused(tmp_path: Path) -> None:
    """A planted object under the real tree id cannot vouch for an edited file."""
    root, sha = _repo(tmp_path / "pep")
    real_tree = _git(root, "rev-parse", f"{sha}:eval/fix")
    edited = b'{"decision": "ALLOW"}\n'
    envelope = root / "eval" / "fix" / "envelope.json"
    envelope.write_bytes(edited)
    blob = _git(root, "hash-object", "-w", str(envelope))
    listing = _git(root, "ls-tree", f"{sha}:eval/fix").replace(
        _git(root, "rev-parse", f"{sha}:eval/fix/envelope.json"), blob
    )
    fake_tree = _git(root, "mktree", input=(listing + "\n").encode("utf-8"))
    objects = root / ".git" / "objects"
    target = objects / real_tree[:2] / real_tree[2:]
    os.chmod(target, stat.S_IRUSR | stat.S_IWUSR)
    shutil.copyfile(objects / fake_tree[:2] / fake_tree[2:], target)
    # Plain git now lists the edited blob at the pinned path.
    assert _git(root, "rev-parse", f"{sha}:eval/fix/envelope.json") == blob
    tree = PinnedTree(root, sha, "pep")
    with pytest.raises(SiblingPinError, match="does not hash to its id"):
        tree.read_bytes(envelope)


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("core.fsmonitor", "/bin/true"),
        ("core.worktree", "/tmp"),
        ("include.path", os.devnull),
        ("filter.acl.smudge", "cat"),
        ("extensions.partialclone", "origin"),
        ("remote.origin.promisor", "true"),
    ],
)
def test_config_outside_the_inert_allowlist_is_refused(tmp_path: Path, key: str, value: str) -> None:
    root, sha = _repo(tmp_path / "pep")
    with (root / ".git" / "config").open("a", encoding="utf-8") as handle:
        section, _dot, name = key.rpartition(".")
        head, _sep, sub = section.partition(".")
        header = f'[{head} "{sub}"]' if sub else f"[{head}]"
        handle.write(f"{header}\n\t{name} = {value}\n")
    with pytest.raises(SiblingPinError, match="not on the inert allowlist"):
        PinnedTree(root, sha, "pep")


def test_sha256_repository_is_refused(tmp_path: Path) -> None:
    root = tmp_path / "pep"
    root.mkdir()
    _git(root, "init", "-q", "--object-format=sha256")
    with pytest.raises(SiblingPinError, match="extensions.objectformat"):
        PinnedTree(root, "a" * 40, "pep")


def test_config_git_declines_to_read_is_refused(tmp_path: Path) -> None:
    """Git ignores a repository whose format it rejects; the check must not pass vacuously."""
    root, sha = _repo(tmp_path / "pep")
    with (root / ".git" / "config").open("a", encoding="utf-8") as handle:
        handle.write("[extensions]\n\tobjectformat = sha256\n")
    with pytest.raises(SiblingPinError, match="config was not read"):
        PinnedTree(root, sha, "pep")


def test_dot_git_file_is_refused(tmp_path: Path) -> None:
    root, sha = _repo(tmp_path / "pep")
    other = tmp_path / "elsewhere.git"
    (root / ".git").rename(other)
    (root / ".git").write_text(f"gitdir: {other}\n", encoding="utf-8")
    with pytest.raises(SiblingPinError, match="must be a directory"):
        PinnedTree(root, sha, "pep")


def _plant_promisor(root: Path, sentinel: Path) -> None:
    """A partial-clone config whose promisor remote runs a command on a lazy fetch."""
    _git(root, "config", "core.repositoryformatversion", "1")
    _git(root, "config", "extensions.partialClone", "origin")
    _git(root, "config", "remote.origin.url", f"ext::sh -c touch% {sentinel}")
    _git(root, "config", "remote.origin.promisor", "true")
    _git(root, "config", "protocol.ext.allow", "always")


@pytest.mark.skipif(not POSIX, reason="ext:: payload uses sh")
def test_planted_ext_promisor_config_does_not_run_its_payload(tmp_path: Path) -> None:
    _real, sha = _repo(tmp_path / "real")
    fake = tmp_path / "fake"
    fake.mkdir()
    _git(fake, "init", "-q")
    (fake / ".git" / "HEAD").write_text(sha + "\n", encoding="ascii")
    sentinel = tmp_path / "sentinel"
    _plant_promisor(fake, sentinel)
    with pytest.raises(SiblingPinError, match="not on the inert allowlist"):
        PinnedTree(fake, sha, "pep")
    assert not sentinel.exists()
    # Control: plain git in the same tree runs the payload on a lazy fetch,
    # so the planted config above is live.
    subprocess.run(
        ["git", "-C", str(fake), "cat-file", "-t", sha], capture_output=True, check=False
    )
    assert sentinel.exists()


@pytest.mark.skipif(not POSIX, reason="ext:: payload uses sh")
def test_hardened_git_blocks_the_lazy_fetch_even_past_the_config_check(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _real, sha = _repo(tmp_path / "real")
    fake = tmp_path / "fake"
    fake.mkdir()
    _git(fake, "init", "-q")
    (fake / ".git" / "HEAD").write_text(sha + "\n", encoding="ascii")
    sentinel = tmp_path / "sentinel"
    _plant_promisor(fake, sentinel)
    monkeypatch.setattr(PinnedTree, "_require_inert_config", lambda self: None)
    with pytest.raises(SiblingPinError, match="does not hold pinned commit"):
        PinnedTree(fake, sha, "pep")
    assert not sentinel.exists()

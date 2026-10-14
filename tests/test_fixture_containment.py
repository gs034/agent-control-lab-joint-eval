# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agent Control Lab contributors
"""Fixture reads stay inside their root; export writes never go through a link."""

from __future__ import annotations

import json
import os
import shutil
import stat
from pathlib import Path

import pytest

from joint_eval import loader
from joint_eval.control_arena_export import (
    ControlArenaExportError,
    write_control_arena_export,
)
from joint_eval.loader import (
    FixturePathError,
    contained_dir,
    load_object,
    read_fixture_text,
)
from joint_eval.paired_runner import PairedRunnerError, run_paired
from joint_eval.story import JointEvalError, run_joint_story

ROOT = Path(__file__).resolve().parents[1]
SECRET = "secret-not-a-fixture"
POSIX = os.name == "posix"


@pytest.fixture(autouse=True)
def _clear_sibling_roots(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ACL_PEP_ROOT", raising=False)
    monkeypatch.delenv("ACL_SUPPLY_GATE_ROOT", raising=False)


def _tree(tmp_path: Path) -> Path:
    root = tmp_path / "tree"
    shutil.copytree(ROOT / "eval", root / "eval")
    return root


def _secret(tmp_path: Path, name: str, body: str) -> Path:
    outside = tmp_path / "outside"
    outside.mkdir(exist_ok=True)
    path = outside / name
    path.write_text(body, encoding="utf-8")
    return path


def _link(path: Path, target: Path) -> None:
    if path.exists() or path.is_symlink():
        path.unlink()
    path.symlink_to(target)


def _set_dir(root: Path, row_id: str, value: str) -> None:
    index_path = root / "eval" / "joint_story" / "index.json"
    index = json.loads(index_path.read_text(encoding="utf-8"))
    for row in index["rows"]:
        if row["id"] == row_id or row["dir"].rstrip("/") == row_id:
            row["dir"] = value
            break
    else:
        raise AssertionError(row_id)
    index_path.write_text(json.dumps(index), encoding="utf-8")


def _first_row_dir(root: Path) -> str:
    index = json.loads((root / "eval" / "joint_story" / "index.json").read_text(encoding="utf-8"))
    return index["rows"][0]["dir"].rstrip("/")


# Loader helpers


@pytest.mark.parametrize("rel", ["../x", "/etc", "a/../../b", "", "..", "C:\\x", "a\\..\\b"])
def test_contained_dir_refuses_escapes(tmp_path: Path, rel: str) -> None:
    (tmp_path / "a").mkdir()
    with pytest.raises(FixturePathError):
        contained_dir(tmp_path, rel)


@pytest.mark.skipif(not POSIX, reason="POSIX symlinks")
def test_contained_dir_refuses_a_symlinked_folder(tmp_path: Path) -> None:
    (tmp_path / "outside").mkdir()
    (tmp_path / "root").mkdir()
    (tmp_path / "root" / "row").symlink_to(tmp_path / "outside", target_is_directory=True)
    with pytest.raises(FixturePathError, match="symlink"):
        contained_dir(tmp_path / "root", "row")
    assert contained_dir(tmp_path, "root") == (tmp_path / "root").resolve()


@pytest.mark.skipif(not POSIX, reason="POSIX symlinks and FIFOs")
def test_fixture_readers_refuse_links_and_special_files(tmp_path: Path) -> None:
    secret = _secret(tmp_path, "creds.json", json.dumps({"token": SECRET}))
    link = tmp_path / "runtime.json"
    link.symlink_to(secret)
    with pytest.raises(FixturePathError, match="symlink"):
        load_object(link)
    with pytest.raises(FixturePathError, match="symlink"):
        read_fixture_text(link)
    fifo = tmp_path / "untrusted_prose.txt"
    os.mkfifo(fifo)
    with pytest.raises(FixturePathError, match="regular file"):
        read_fixture_text(fifo)


def test_repo_root_does_not_consult_the_working_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    planted = tmp_path / "planted"
    (planted / "eval" / "joint_story").mkdir(parents=True)
    (planted / "eval" / "joint_story" / "index.json").write_text("{}", encoding="utf-8")
    installed = tmp_path / "site" / "joint_eval" / "loader.py"
    installed.parent.mkdir(parents=True)
    monkeypatch.chdir(planted)
    monkeypatch.setattr(loader, "__file__", str(installed))
    with pytest.raises(FileNotFoundError, match="--root"):
        loader.repo_root()


# Export: sidecar symlinks (finding: sidecar files read through symlinks)


@pytest.mark.skipif(not POSIX, reason="POSIX symlinks")
@pytest.mark.parametrize(
    ("row", "name", "body"),
    [
        ("pep_monitor_bypass_prose", "untrusted_prose.txt", SECRET),
        ("pep_approval_binding", "runtime.json", json.dumps({"token": SECRET})),
        ("supply_plugin4shell_class", "envelope.json", json.dumps({"capability": SECRET})),
    ],
)
def test_export_refuses_a_symlinked_sidecar_and_writes_nothing(
    tmp_path: Path, row: str, name: str, body: str
) -> None:
    root = _tree(tmp_path)
    _link(root / "eval" / "joint_story" / row / name, _secret(tmp_path, name, body))
    out = tmp_path / "out"
    with pytest.raises(ControlArenaExportError, match="symlink"):
        write_control_arena_export(out, root=root)
    assert not out.exists()


@pytest.mark.skipif(not POSIX, reason="POSIX symlinks")
def test_export_refuses_a_symlinked_sequence_envelope_dir(tmp_path: Path) -> None:
    root = _tree(tmp_path)
    seq = root / "eval" / "joint_story" / "supply_rug_pull_two_envelope"
    moved = tmp_path / "outside-envelope"
    shutil.move(str(seq / "envelope_1"), moved)
    (seq / "envelope_1").symlink_to(moved, target_is_directory=True)
    with pytest.raises(ControlArenaExportError, match="symlink"):
        write_control_arena_export(tmp_path / "out", root=root)


# Export: output directory (finding: writes through pre-existing symlinks)


@pytest.mark.skipif(not POSIX, reason="POSIX symlinks")
@pytest.mark.parametrize("name", ["tools.json", "trajectory.jsonl", "metadata.json"])
def test_export_refuses_a_planted_link_at_an_output_name(tmp_path: Path, name: str) -> None:
    victim = _secret(tmp_path, "victim.rc", "keep me\n")
    out = tmp_path / "out"
    out.mkdir()
    (out / name).symlink_to(victim)
    with pytest.raises(ControlArenaExportError, match="not a regular file"):
        write_control_arena_export(out)
    assert victim.read_text(encoding="utf-8") == "keep me\n"
    assert [p.name for p in out.iterdir()] == [name]


@pytest.mark.skipif(not POSIX, reason="POSIX modes")
def test_export_refuses_a_world_writable_output_dir(tmp_path: Path) -> None:
    out = tmp_path / "out"
    out.mkdir()
    out.chmod(0o777)
    with pytest.raises(ControlArenaExportError, match="world-writable"):
        write_control_arena_export(out)
    assert list(out.iterdir()) == []


@pytest.mark.skipif(not hasattr(os, "geteuid") or os.geteuid() != 0, reason="needs chown")
def test_export_refuses_an_output_dir_owned_by_another_user(tmp_path: Path) -> None:
    out = tmp_path / "out"
    out.mkdir()
    os.chown(out, 65534, 65534)
    with pytest.raises(ControlArenaExportError, match="another user"):
        write_control_arena_export(out)
    assert list(out.iterdir()) == []


@pytest.mark.skipif(not POSIX, reason="POSIX symlinks")
def test_export_refuses_a_symlinked_output_dir(tmp_path: Path) -> None:
    real = tmp_path / "elsewhere"
    real.mkdir()
    (tmp_path / "out").symlink_to(real, target_is_directory=True)
    with pytest.raises(ControlArenaExportError, match="not a directory"):
        write_control_arena_export(tmp_path / "out")
    assert list(real.iterdir()) == []


def test_export_replaces_its_own_previous_files(tmp_path: Path) -> None:
    out = tmp_path / "out"
    write_control_arena_export(out)
    first = {p.name: p.read_bytes() for p in out.iterdir()}
    write_control_arena_export(out)
    second = {p.name: p.read_bytes() for p in out.iterdir()}
    assert first == second
    assert sorted(first) == ["metadata.json", "tools.json", "trajectory.jsonl"]


# Story (finding: index dir joined without containment)


@pytest.mark.parametrize("value", ["../../outside", "/etc", "pep_approval_binding/../.."])
def test_story_refuses_an_index_dir_that_leaves_the_story(tmp_path: Path, value: str) -> None:
    root = _tree(tmp_path)
    _set_dir(root, _first_row_dir(root), value)
    with pytest.raises(JointEvalError, match="fixture"):
        run_joint_story(root=root)


@pytest.mark.skipif(not POSIX, reason="POSIX symlinks")
def test_story_refuses_a_symlinked_row_folder_and_sidecar(tmp_path: Path) -> None:
    root = _tree(tmp_path)
    story = root / "eval" / "joint_story"
    row = _first_row_dir(root)
    moved = tmp_path / "outside-row"
    shutil.move(str(story / row), moved)
    (story / row).symlink_to(moved, target_is_directory=True)
    with pytest.raises(JointEvalError, match="symlink"):
        run_joint_story(root=root)

    root = _tree(tmp_path / "second")
    _link(
        root / "eval" / "joint_story" / "supply_plugin4shell_class" / "untrusted_prose.txt",
        _secret(tmp_path, "prose.txt", SECRET),
    )
    with pytest.raises(JointEvalError, match="symlink"):
        run_joint_story(root=root)


# Paired runner (finding: corpus path/dir joined without containment)


def _set_corpus_path(root: Path, old_prefix: str, value: str) -> None:
    path = root / "eval" / "measured_corpus" / "index.json"
    index = json.loads(path.read_text(encoding="utf-8"))
    changed = 0
    for row in index["rows"]:
        for fixture in row.get("fixtures") or []:
            if str(fixture.get("path", "")).startswith(old_prefix):
                fixture["path"] = value
                changed += 1
    assert changed
    path.write_text(json.dumps(index), encoding="utf-8")


@pytest.mark.parametrize("value", ["../outside/", "/etc/", "eval/../../outside/"])
def test_paired_runner_refuses_a_corpus_path_that_leaves_the_root(tmp_path: Path, value: str) -> None:
    root = _tree(tmp_path)
    _set_corpus_path(root, "eval/joint_story/", value)
    with pytest.raises(PairedRunnerError, match="fixture refused"):
        run_paired(root=root)


def test_paired_runner_pins_sequence_envelope_dirs(tmp_path: Path) -> None:
    root = _tree(tmp_path)
    seq_path = root / "eval" / "joint_story" / "supply_rug_pull_two_envelope" / "sequence.json"
    spec = json.loads(seq_path.read_text(encoding="utf-8"))
    spec["envelopes"][1]["dir"] = "../../supply_plugin4shell_class"
    seq_path.write_text(json.dumps(spec), encoding="utf-8")
    with pytest.raises((PairedRunnerError, JointEvalError), match="envelope dir must be envelope_2"):
        run_paired(root=root)


# Review follow-ups


@pytest.mark.skipif(not POSIX, reason="POSIX symlinks")
def test_export_into_a_parent_owned_by_another_user_is_refused(tmp_path: Path) -> None:
    if os.geteuid() != 0:
        pytest.skip("needs chown")
    shared = tmp_path / "shared"
    shared.mkdir()
    os.chown(shared, 65534, 65534)
    with pytest.raises(ControlArenaExportError, match="parent is owned by another user"):
        write_control_arena_export(shared / "out")
    assert list(shared.iterdir()) == []


@pytest.mark.skipif(not POSIX, reason="POSIX modes")
def test_export_into_a_world_writable_non_sticky_parent_is_refused(tmp_path: Path) -> None:
    shared = tmp_path / "shared"
    shared.mkdir()
    shared.chmod(0o777)
    with pytest.raises(ControlArenaExportError, match="without the sticky bit"):
        write_control_arena_export(shared / "out")
    sticky = tmp_path / "sticky"
    sticky.mkdir()
    sticky.chmod(0o1777)
    write_control_arena_export(sticky / "out")
    assert (sticky / "out" / "tools.json").is_file()


@pytest.mark.skipif(not POSIX, reason="POSIX symlinks")
def test_export_through_another_users_symlink_is_refused(tmp_path: Path) -> None:
    if os.geteuid() != 0:
        pytest.skip("needs lchown")
    victim = tmp_path / "victim"
    victim.mkdir()
    link = tmp_path / "link"
    link.symlink_to(victim, target_is_directory=True)
    os.lchown(link, 65534, 65534)
    with pytest.raises(ControlArenaExportError, match="another user's symlink"):
        write_control_arena_export(link / "out")
    assert list(victim.iterdir()) == []


@pytest.mark.skipif(not POSIX, reason="POSIX symlinks")
def test_output_dir_swapped_after_the_check_does_not_redirect_writes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from joint_eval import safe_write

    victim = tmp_path / "victim"
    victim.mkdir()
    out = tmp_path / "out"
    real = safe_write._require_own_directory

    def _swap(fd: int, label: Path) -> None:
        real(fd, label)
        out.rename(tmp_path / "aside")
        out.symlink_to(victim, target_is_directory=True)

    monkeypatch.setattr(safe_write, "_require_own_directory", _swap)
    write_control_arena_export(out)
    assert list(victim.iterdir()) == []
    assert (tmp_path / "aside" / "tools.json").is_file()


@pytest.mark.skipif(not POSIX, reason="POSIX symlinks")
@pytest.mark.parametrize("name", ["p.json", "p.csv"])
def test_paired_output_refuses_a_planted_link(tmp_path: Path, name: str) -> None:
    from joint_eval.paired_runner import write_paired

    victim = _secret(tmp_path, "victim.rc", "keep me\n")
    out = tmp_path / "out"
    out.mkdir()
    (out / name).symlink_to(victim)
    with pytest.raises(PairedRunnerError, match="not a regular file"):
        write_paired(run_paired(root=ROOT), out / "p.json")
    assert victim.read_text(encoding="utf-8") == "keep me\n"


@pytest.mark.skipif(not POSIX, reason="POSIX symlinks")
@pytest.mark.parametrize("name", ["allowlist.json", "update_policy.json"])
def test_paired_runner_refuses_symlinked_supply_policy_files(tmp_path: Path, name: str) -> None:
    from joint_eval.paired_runner import _supply_gated

    folder = tmp_path / "fixture"
    shutil.copytree(ROOT / "eval" / "joint_story" / "supply_plugin4shell_class", folder)
    (folder / name).symlink_to(_secret(tmp_path, name, json.dumps({"allowed_origins": [SECRET]})))
    with pytest.raises(PairedRunnerError, match="symlink"):
        _supply_gated(folder)


@pytest.mark.skipif(not POSIX, reason="POSIX symlinks")
@pytest.mark.parametrize("level", ["eval", "eval/joint_story"])
def test_symlinked_story_root_is_refused(tmp_path: Path, level: str) -> None:
    root = _tree(tmp_path)
    moved = tmp_path / "moved"
    shutil.move(str(root / level), moved)
    (root / level).symlink_to(moved, target_is_directory=True)
    with pytest.raises(JointEvalError, match="symlink"):
        run_joint_story(root=root)
    with pytest.raises(ControlArenaExportError, match="symlink"):
        write_control_arena_export(tmp_path / "out", root=root)


@pytest.mark.skipif(not POSIX, reason="POSIX symlinks")
def test_b7_note_and_fence_table_refuse_symlinks(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from joint_eval import b7_table_id, fence_outcome

    root = tmp_path / "tree"
    for module in (b7_table_id, fence_outcome):
        rel = Path(module.RELATIVE_PATH)
        target = root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        real = ROOT / rel
        copy = tmp_path / ("copy-" + rel.name)
        copy.write_bytes(real.read_bytes())
        target.symlink_to(copy)
    with pytest.raises(b7_table_id.B7TableIdError, match="symlink"):
        b7_table_id.provisional_table_id(root=root, schema_version="1")
    with pytest.raises(fence_outcome.FenceOutcomeError, match="symlink"):
        fence_outcome.load_fence_outcome(root)


def test_vendored_probe_counts_a_dangling_symlink(tmp_path: Path) -> None:
    if not POSIX:
        pytest.skip("POSIX symlinks")
    from joint_eval import fence_outcome

    data = fence_outcome.load_fence_outcome(ROOT)
    lab_paths = [row["path"] for row in data["rows"] if row.get("kind") != "registered_outcome" and row.get("path")]
    assert lab_paths
    planted = tmp_path / lab_paths[0]
    planted.parent.mkdir(parents=True, exist_ok=True)
    planted.symlink_to(tmp_path / "missing")
    with pytest.raises(fence_outcome.FenceOutcomeError, match="vendored"):
        fence_outcome.validate_fence_outcome(data, root=tmp_path)


def test_pep_official_file_path_is_accepted_and_confined(tmp_path: Path) -> None:
    """Regression: a pep_official fixture names a file, not a folder."""
    from joint_eval.paired_runner import _fixture_file

    root = tmp_path / "pep"
    (root / "eval").mkdir(parents=True)
    envelope = root / "eval" / "structured_envelope.example.json"
    envelope.write_text("{}", encoding="utf-8")
    assert _fixture_file(root, "eval/structured_envelope.example.json") == envelope.resolve()
    (root / "top.json").write_text("{}", encoding="utf-8")
    assert _fixture_file(root, "top.json").name == "top.json"
    for bad in ("../outside.json", "/etc/passwd", "eval/../../x.json", "eval/", "", "eval/.."):
        with pytest.raises(PairedRunnerError, match="fixture refused"):
            _fixture_file(root, bad)
    with pytest.raises(PairedRunnerError, match="fixture refused"):
        _fixture_file(root, "eval")


@pytest.mark.skipif(not POSIX, reason="POSIX symlinks")
def test_pep_official_file_symlink_is_refused(tmp_path: Path) -> None:
    from joint_eval.paired_runner import _fixture_file

    root = tmp_path / "pep"
    (root / "eval").mkdir(parents=True)
    (root / "eval" / "structured_envelope.example.json").symlink_to(_secret(tmp_path, "s.json", "{}"))
    with pytest.raises(PairedRunnerError, match="symlink"):
        _fixture_file(root, "eval/structured_envelope.example.json")


# Output durability and set writes (findings: no fsync, non-atomic set, hard links, group-writable)


@pytest.mark.skipif(not POSIX, reason="POSIX hard links")
def test_output_refuses_a_hard_linked_name(tmp_path: Path) -> None:
    from joint_eval import safe_write

    out = tmp_path / "out"
    out.mkdir()
    victim = _secret(tmp_path, "victim.rc", "keep me\n")
    os.link(victim, out / "tools.json")
    with pytest.raises(safe_write.OutputPathError, match="more than one hard link"):
        with safe_write.output_directory(out) as output:
            output.require_writable_name("tools.json")
    assert victim.read_text(encoding="utf-8") == "keep me\n"


@pytest.mark.skipif(not POSIX, reason="POSIX modes")
def test_group_writable_output_dir_is_accepted_under_umask_002(tmp_path: Path) -> None:
    """Pinned: user-private-group hosts (umask 002) create 0o775 directories; the harness must still write."""
    from joint_eval import safe_write

    previous = os.umask(0o002)
    try:
        out = tmp_path / "parent" / "out"
        with safe_write.output_directory(out) as output:
            output.replace("a.json", "1")
        assert stat.S_IMODE(out.parent.stat().st_mode) == 0o755, "the module creates parents with an explicit mode"
        shared = tmp_path / "shared"
        shared.mkdir()
        shared.chmod(0o775)
        with safe_write.output_directory(shared) as output:
            output.replace("a.json", "1")
        assert (shared / "a.json").read_text(encoding="utf-8") == "1"
    finally:
        os.umask(previous)


@pytest.mark.skipif(not POSIX, reason="POSIX fsync of a directory descriptor")
def test_output_files_are_fsynced_before_rename_and_the_directory_after(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from joint_eval import safe_write

    events: list[str] = []
    real_fsync = os.fsync
    real_replace = os.replace

    def _fsync(fd: int) -> None:
        events.append("dir" if stat.S_ISDIR(os.fstat(fd).st_mode) else "file")
        real_fsync(fd)

    def _replace(*args, **kwargs):
        events.append("rename")
        return real_replace(*args, **kwargs)

    monkeypatch.setattr(safe_write.os, "fsync", _fsync)
    monkeypatch.setattr(safe_write.os, "replace", _replace)
    with safe_write.output_directory(tmp_path / "out") as output:
        output.replace_all([("a.json", "1"), ("b.json", "2"), ("c.json", "3")])
    assert events.count("file") == 3, events
    assert events.index("rename") > max(i for i, e in enumerate(events) if e == "file")
    assert events.count("rename") == 3
    assert events[-1] == "dir", events


@pytest.mark.skipif(not POSIX, reason="POSIX errno values")
def test_directory_fsync_io_error_propagates_but_unsupported_is_tolerated(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import errno

    from joint_eval import safe_write

    real_fsync = os.fsync

    def _fail(code: int):
        def _fsync(fd: int) -> None:
            if stat.S_ISDIR(os.fstat(fd).st_mode):
                raise OSError(code, os.strerror(code))
            real_fsync(fd)

        return _fsync

    monkeypatch.setattr(safe_write.os, "fsync", _fail(errno.EINVAL))
    with safe_write.output_directory(tmp_path / "ok") as output:
        output.replace("a.json", "1")
    monkeypatch.setattr(safe_write.os, "fsync", _fail(errno.EIO))
    with pytest.raises(OSError, match="Input/output error"):
        with safe_write.output_directory(tmp_path / "bad") as output:
            output.replace("a.json", "1")


def test_replace_all_leaves_the_previous_set_untouched_when_a_body_write_fails(tmp_path: Path) -> None:
    from joint_eval import safe_write

    out = tmp_path / "out"
    out.mkdir()
    (out / "a.json").write_text("old a", encoding="utf-8")
    (out / "b.json").write_text("old b", encoding="utf-8")

    def bodies():
        yield ("a.json", "new a")
        raise OSError("disk full while producing the second body")

    with pytest.raises(OSError, match="disk full"):
        with safe_write.output_directory(out) as output:
            output.replace_all(bodies())
    # The generator failed before staging began, so nothing changed and nothing was staged.
    assert (out / "a.json").read_text(encoding="utf-8") == "old a"
    assert (out / "b.json").read_text(encoding="utf-8") == "old b"
    assert sorted(p.name for p in out.iterdir()) == ["a.json", "b.json"]

    # A failure while staging the second body (an unencodable string) leaves
    # the set untouched and removes the first staged temporary. This is the
    # property a per-file write-then-rename would not have.
    with pytest.raises(UnicodeEncodeError):
        with safe_write.output_directory(out) as output:
            output.replace_all([("a.json", "new a"), ("b.json", "\udcff")])
    assert (out / "a.json").read_text(encoding="utf-8") == "old a"
    assert (out / "b.json").read_text(encoding="utf-8") == "old b"
    assert sorted(p.name for p in out.iterdir()) == ["a.json", "b.json"]

    # A pre-check failure (planted directory at a name) is refused before any staging.
    (out / "c.json").mkdir()
    with pytest.raises(safe_write.OutputPathError, match="not a regular file"):
        with safe_write.output_directory(out) as output:
            output.replace_all([("a.json", "new a"), ("c.json", "new c")])
    assert (out / "a.json").read_text(encoding="utf-8") == "old a"
    assert sorted(p.name for p in out.iterdir()) == ["a.json", "b.json", "c.json"]


def test_replace_all_refuses_duplicate_names(tmp_path: Path) -> None:
    from joint_eval import safe_write

    with pytest.raises(safe_write.OutputPathError, match="distinct"):
        with safe_write.output_directory(tmp_path / "out") as output:
            output.replace_all([("a.json", "1"), ("a.json", "2")])
    assert list((tmp_path / "out").iterdir()) == []

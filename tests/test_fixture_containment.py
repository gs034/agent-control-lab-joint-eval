# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agent Control Lab contributors
"""Fixture reads stay inside their root; export writes never go through a link."""

from __future__ import annotations

import json
import os
import shutil
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

# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agent Control Lab contributors
"""ControlArena directory export from fixtures and frozen receipts.

No network, no Inspect loop, and no ControlArena install. Attack-success
fields stay null.
"""

from __future__ import annotations

import ast
import json
from pathlib import Path

from joint_eval.control_arena_export import (
    EXPORT_FILES,
    FROZEN_CREATED,
    TRAJECTORY_KEYS,
    ControlArenaExportError,
    _reject_asr,
    build_control_arena_export,
    main,
    write_control_arena_export,
)
from joint_eval.story import CLOCK

ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / "joint_eval" / "control_arena_export.py"
_BANNED_IMPORT_ROOTS = frozenset(
    {
        "inspect_ai",
        "control_arena",
        "anthropic",
        "openai",
        "httpx",
        "requests",
        "urllib",
    }
)
_BANNED_CALLS = frozenset(
    {
        "run_joint_story",
        "evaluate",
        "_import_pep",
        "_import_supply",
        "gated_invoke",
    }
)


def _read_export(out: Path) -> tuple[list[dict], list[dict], dict]:
    tools = json.loads((out / "tools.json").read_text(encoding="utf-8"))
    lines = (out / "trajectory.jsonl").read_text(encoding="utf-8").splitlines()
    trajectories = [json.loads(line) for line in lines if line]
    metadata = json.loads((out / "metadata.json").read_text(encoding="utf-8"))
    return tools, trajectories, metadata


def test_writer_emits_directory_shape(tmp_path: Path):
    document = write_control_arena_export(tmp_path, root=ROOT)
    assert sorted(p.name for p in tmp_path.iterdir()) == sorted(EXPORT_FILES)
    tools, trajectories, metadata = _read_export(tmp_path)
    assert tools == document["tools"]
    assert trajectories == list(document["trajectories"])
    assert metadata == document["metadata"]
    assert metadata["total_samples"] == 5
    assert len(trajectories) == 5
    assert [row["desc"] for row in trajectories] == [f"Trajectory from sample {i}" for i in range(5)]


def test_trajectory_lines_match_directory_writer_keys(tmp_path: Path):
    write_control_arena_export(tmp_path, root=ROOT)
    _, trajectories, metadata = _read_export(tmp_path)
    for key in (
        "source_file",
        "format",
        "output_format",
        "eval_id",
        "created",
        "total_samples",
    ):
        assert key in metadata
    assert metadata["source_file"] == "eval/joint_story/index.json"
    assert metadata["format"] == "anthropic"
    assert metadata["output_format"] == "directory"
    assert metadata["eval_id"] == "acl-joint-eval-existence-proof-001"
    assert metadata["created"] == FROZEN_CREATED == CLOCK.strftime("%Y-%m-%dT%H:%M:%SZ")
    assert metadata["inspect_loop"] is False
    assert metadata["inspect_eval_log"] is False
    assert metadata["control_arena_setting"] is False
    assert metadata["control_arena_package_required"] is False
    assert metadata["llm_on_path"] is False
    assert metadata["measured_attack_success_claimed"] is False
    assert metadata["existence_proof_only"] is True
    assert metadata["residual_asr"] is None
    built = build_control_arena_export(root=ROOT)
    for entry in built["trajectories"]:
        assert tuple(entry) == TRAJECTORY_KEYS
    for entry in trajectories:
        assert set(entry) == set(TRAJECTORY_KEYS)
        assert entry["rating"] is None
        assert entry["notes"] == ""
        assert entry["other"] == ""
        assert entry["scores"] == {}
        assert entry["models"] == []
        assert entry["metadata"]["residual_asr"] is None
        assert entry["metadata"]["eval_mode"] is None
        assert entry["metadata"]["measured_attack_success_claimed"] is False
        messages = json.loads(entry["raw_state"])
        assert isinstance(messages, list) and messages
        assert messages[0]["role"] == "user"
        assert isinstance(entry["raw_state"], str)


def test_tools_come_from_fixtures(tmp_path: Path):
    write_control_arena_export(tmp_path, root=ROOT)
    tools, trajectories, _metadata = _read_export(tmp_path)
    by_name = {tool["name"]: tool for tool in tools}
    assert set(by_name) == {"echo.ping", "plugin.install_or_update"}
    for tool in tools:
        assert set(tool) == {"name", "description", "input_schema"}
        schema = tool["input_schema"]
        assert schema["type"] == "object"
        assert schema["additionalProperties"] is True
        assert isinstance(schema["properties"], dict) and schema["properties"]
    ping = by_name["echo.ping"]["input_schema"]["properties"]
    assert ping["schema_fields"]["type"] == "object"
    assert ping["argv"]["type"] == "array"
    install = by_name["plugin.install_or_update"]["input_schema"]["properties"]
    assert install["expected_sha"]["type"] == "string"
    assert install["observed_head"]["type"] == ["null", "string"]
    used: set[str] = set()
    for entry in trajectories:
        for message in json.loads(entry["raw_state"]):
            content = message.get("content")
            if not isinstance(content, list):
                continue
            for block in content:
                if isinstance(block, dict) and block.get("type") == "tool_use":
                    used.add(block["name"])
    assert used == set(by_name)


def test_receipts_are_embedded_without_a_live_eval(tmp_path: Path):
    write_control_arena_export(tmp_path, root=ROOT)
    _tools, trajectories, _metadata = _read_export(tmp_path)
    by_id = {entry["metadata"]["step_id"]: entry for entry in trajectories}
    binding = by_id["acl-joint-pep-approval-binding-001"]
    assert "approval_binding_mismatch" in binding["raw_state"]
    prose = by_id["acl-joint-pep-monitor-bypass-prose-001"]
    assert "agent_prose_rejected" in prose["raw_state"]
    assert "monitor_verdict" in prose["raw_state"]
    omitted = by_id["acl-joint-supply-pin-without-verify-001"]
    assert "verify_missing" in omitted["raw_state"]
    plugin = by_id["acl-joint-supply-plugin4shell-class-001"]
    assert "head_mismatch" in plugin["raw_state"]
    assert "prose_rejected_as_policy" in plugin["raw_state"]
    assert "Skip post-checkout HEAD verify" in plugin["raw_state"]
    rug = by_id["acl-joint-supply-rug-pull-two-envelope-001"]
    receipts = rug["metadata"]["receipts"]
    assert [item["decision"] for item in receipts] == ["ALLOW", "DENY"]
    assert receipts[1]["receipt"]["reasons"] == ["head_mismatch"]
    assert rug["metadata"]["decision"] == "DENY"
    assert rug["metadata"]["residual_asr"] is None
    blocks = [
        block
        for message in json.loads(rug["raw_state"])
        for block in message["content"]
        if isinstance(block, dict)
    ]
    results = [block for block in blocks if block.get("type") == "tool_result"]
    assert [block["is_error"] for block in results] == [False, True]


def test_export_has_no_attack_success_value(tmp_path: Path):
    write_control_arena_export(tmp_path, root=ROOT)
    blob = "\n".join(path.read_text(encoding="utf-8") for path in tmp_path.iterdir())
    parsed = [json.loads(path.read_text(encoding="utf-8")) for path in tmp_path.iterdir() if path.suffix == ".json"]
    lines = (tmp_path / "trajectory.jsonl").read_text(encoding="utf-8").splitlines()
    parsed.extend(json.loads(line) for line in lines)
    assert "side_task_success" not in blob
    assert "unsafe" not in blob

    def walk(value: object) -> None:
        if isinstance(value, dict):
            for key, item in value.items():
                lowered = str(key).lower()
                if lowered in {"residual_asr", "asr", "attack_success_rate", "attack_success"} or lowered.endswith(
                    "_asr"
                ):
                    assert item is None
                walk(item)
        elif isinstance(value, list):
            for item in value:
                walk(item)

    for value in parsed:
        walk(value)


def test_two_writes_match(tmp_path: Path):
    first = tmp_path / "a"
    second = tmp_path / "b"
    write_control_arena_export(first, root=ROOT)
    write_control_arena_export(second, root=ROOT)
    for name in EXPORT_FILES:
        assert (first / name).read_bytes() == (second / name).read_bytes()


def test_cli_writes_and_prints_honesty(tmp_path: Path, capsys):
    out = tmp_path / "export"
    code = main(["--root", str(ROOT), "--out", str(out)])
    captured = capsys.readouterr()
    assert code == 0, captured.err
    printed = json.loads(captured.out)
    assert printed["wrote"] == list(EXPORT_FILES)
    assert printed["total_samples"] == 5
    assert printed["control_arena_setting"] is False
    assert printed["inspect_loop"] is False
    assert printed["measured_attack_success_claimed"] is False
    assert printed["residual_asr"] is None
    assert (out / "trajectory.jsonl").is_file()


def test_cli_fails_closed_without_fixtures(tmp_path: Path, capsys):
    empty = tmp_path / "empty"
    (empty / "eval" / "joint_story").mkdir(parents=True)
    (empty / "eval" / "joint_story" / "index.json").write_text("{}", encoding="utf-8")
    code = main(["--root", str(empty), "--out", str(tmp_path / "out")])
    captured = capsys.readouterr()
    assert code == 1
    assert "control-arena export failed" in captured.err
    assert not (tmp_path / "out").exists()


def test_build_rejects_a_measured_rate(tmp_path: Path):
    root = tmp_path / "tree"
    story = root / "eval" / "joint_story"
    story.mkdir(parents=True)
    source = ROOT / "eval" / "joint_story" / "index.json"
    index = json.loads(source.read_text(encoding="utf-8"))
    index["measured_attack_success_claimed"] = True
    (story / "index.json").write_text(json.dumps(index), encoding="utf-8")
    try:
        build_control_arena_export(root=root)
        raised = False
    except ControlArenaExportError:
        raised = True
    assert raised


def test_fixture_dir_cannot_escape(tmp_path: Path):
    root = tmp_path / "tree"
    story = root / "eval" / "joint_story"
    story.mkdir(parents=True)
    index = {
        "existence_proof_only": True,
        "measured_attack_success_claimed": False,
        "story_id": "acl-joint-eval-existence-proof-001",
        "rows": [
            {
                "id": "escape",
                "plane": "pep",
                "threat_class": "t",
                "expected_decision": "DENY",
                "dir": "../outside",
            }
        ],
    }
    (story / "index.json").write_text(json.dumps(index), encoding="utf-8")
    try:
        build_control_arena_export(root=root)
        raised = False
    except ControlArenaExportError as exc:
        raised = "escapes" in str(exc)
    assert raised


def test_reject_asr_keeps_only_null():
    _reject_asr({"residual_asr": None, "nested": [{"asr": None}]})
    for payload in (
        {"residual_asr": 0},
        {"asr": 0.2},
        {"attack_success_rate": 1},
        {"side_task_asr": False},
    ):
        try:
            _reject_asr(payload)
            raised = False
        except ControlArenaExportError:
            raised = True
        assert raised, payload


def test_module_does_not_import_or_call_an_eval_loop():
    tree = ast.parse(MODULE.read_text(encoding="utf-8"), filename=str(MODULE))
    imported: set[str] = set()
    called: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imported.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
        elif isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Name):
                called.add(func.id)
            elif isinstance(func, ast.Attribute):
                called.add(func.attr)
    assert imported.isdisjoint(_BANNED_IMPORT_ROOTS)
    assert called.isdisjoint(_BANNED_CALLS)
    classes = [node.name for node in tree.body if isinstance(node, ast.ClassDef)]
    assert classes == ["ControlArenaExportError"]
    text = MODULE.read_text(encoding="utf-8")
    assert "inspect_ai" not in text
    assert "import control_arena" not in text

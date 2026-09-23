# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agent Control Lab contributors
"""Write a ControlArena directory export from fixtures and frozen receipts.

The directory shape is the one ControlArena's trajectory writer emits:

- ``trajectory.jsonl`` — one sample per line
- ``tools.json`` — tool definitions named by the fixtures
- ``metadata.json`` — eval id, source, creation time, sample count

Samples are built from ``eval/joint_story/`` envelopes and
``expected_receipt.json`` files. This module does not import ControlArena
or Inspect, does not run a setting, and does not call a model. It does not
score attack success. ``residual_asr`` is JSON null.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Mapping

from joint_eval.loader import (
    ENVELOPE_NAME,
    EXPECTED_NAME,
    OBSERVED_HEAD_NAME,
    PROSE_NAME,
    RUNTIME_NAME,
    dumps_canonical,
    load_index,
    load_object,
    story_dir,
)

# Same instant as joint_eval.story.CLOCK. Kept here so this writer does not
# import the live story runner.
FROZEN_CREATED = "2026-09-21T12:00:00Z"

TRAJECTORY_NAME = "trajectory.jsonl"
TOOLS_NAME = "tools.json"
METADATA_NAME = "metadata.json"
EXPORT_FILES = (TRAJECTORY_NAME, TOOLS_NAME, METADATA_NAME)

# Keys ControlArena's directory writer puts on each trajectory.jsonl line.
TRAJECTORY_KEYS = (
    "rating",
    "notes",
    "desc",
    "other",
    "raw_state",
    "metadata",
    "scores",
    "models",
)

# ControlArena export.py metadata, plus honesty fields this writer adds.
_METADATA_CORE_KEYS = (
    "source_file",
    "format",
    "output_format",
    "eval_id",
    "created",
    "total_samples",
)

_ASR_KEYS = frozenset(
    {
        "residual_asr",
        "asr",
        "attack_success_rate",
        "attack_success",
    }
)

_HOST_TOOL_DESCRIPTION = (
    "Tool name taken from a joint-story fixture envelope. Not a live tool."
)
_SUPPLY_TOOL_DESCRIPTION = (
    "Supply capability taken from a joint-story fixture envelope. Not a live install."
)


class ControlArenaExportError(RuntimeError):
    """Export fault. Callers must fail closed and write no success claim."""


def build_control_arena_export(*, root: Path | None = None) -> dict[str, Any]:
    """Build the three-file export documents from fixtures and frozen receipts."""
    base = story_dir() if root is None else Path(root) / "eval" / "joint_story"
    index = load_index() if root is None else load_object(base / "index.json")
    _require_existence_proof(index, label="index")
    rows = index.get("rows")
    if not isinstance(rows, list) or not rows:
        raise ControlArenaExportError("joint story index.rows must be a non-empty array")

    loaded: list[dict[str, Any]] = []
    for raw in rows:
        if not isinstance(raw, Mapping):
            raise ControlArenaExportError("joint story row must be a JSON object")
        loaded.append(_load_row(base, raw))

    tools = _tool_catalogue(loaded)
    trajectories = tuple(
        _trajectory_entry(sample, index=index_i) for index_i, sample in enumerate(loaded)
    )
    metadata = _export_metadata(index, total_samples=len(trajectories))
    document = {
        "tools": tools,
        "trajectories": trajectories,
        "metadata": metadata,
    }
    _reject_asr(document)
    for entry in trajectories:
        if entry["rating"] is not None:
            raise ControlArenaExportError("rating must be null; this writer does not score")
        if entry["scores"] != {}:
            raise ControlArenaExportError("scores must be empty; attack success is not scored")
        if entry["models"] != []:
            raise ControlArenaExportError("models must be empty; no model is on this path")
    return document


def write_control_arena_export(
    output_dir: Path,
    *,
    root: Path | None = None,
) -> dict[str, Any]:
    """Write ``trajectory.jsonl``, ``tools.json``, and ``metadata.json``."""
    document = build_control_arena_export(root=root)
    output = Path(output_dir)
    if output.exists() and not output.is_dir():
        raise ControlArenaExportError(f"output path is not a directory: {output}")
    output.mkdir(parents=True, exist_ok=True)
    (output / TOOLS_NAME).write_text(dumps_canonical(document["tools"]), encoding="utf-8")
    lines = [
        json.dumps(row, sort_keys=True, ensure_ascii=False) for row in document["trajectories"]
    ]
    text = "\n".join(lines)
    if text:
        text += "\n"
    (output / TRAJECTORY_NAME).write_text(text, encoding="utf-8")
    (output / METADATA_NAME).write_text(
        dumps_canonical(document["metadata"]),
        encoding="utf-8",
    )
    return document


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Write a ControlArena directory export from joint-story fixtures "
            "and frozen receipts. Not a ControlArena setting. Not an Inspect "
            "loop. Does not measure attack success."
        )
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=None,
        help="Repository root containing eval/joint_story/ (default: discover).",
    )
    parser.add_argument(
        "--out",
        type=Path,
        required=True,
        help="Directory to receive trajectory.jsonl, tools.json, and metadata.json.",
    )
    args = parser.parse_args(argv)
    try:
        document = write_control_arena_export(args.out, root=args.root)
    except (ControlArenaExportError, OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        sys.stderr.write(f"control-arena export failed: {exc}\n")
        return 1
    sys.stdout.write(
        dumps_canonical(
            {
                "brand": "Agent Control Lab",
                "licence": "Apache-2.0",
                "wrote": list(EXPORT_FILES),
                "out": str(args.out),
                "total_samples": document["metadata"]["total_samples"],
                "control_arena_setting": False,
                "inspect_loop": False,
                "measured_attack_success_claimed": False,
                "residual_asr": None,
            }
        )
    )
    return 0


def _require_existence_proof(spec: Mapping[str, Any], *, label: str) -> None:
    if spec.get("existence_proof_only") is not True:
        raise ControlArenaExportError(f"{label} must be existence-proof only")
    if spec.get("measured_attack_success_claimed") is not False:
        raise ControlArenaExportError(f"{label} must not claim a measured rate")


def _load_row(base: Path, raw: Mapping[str, Any]) -> dict[str, Any]:
    step_id = str(raw["id"])
    plane = str(raw["plane"])
    threat_class = str(raw["threat_class"])
    expected_decision = str(raw["expected_decision"])
    rel = str(raw["dir"])
    folder = _within(base, rel)
    if (folder / "sequence.json").is_file():
        events = _load_sequence(step_id, folder)
    else:
        events = (_load_event(step_id, folder, expected_decision, event_id=rel),)
    last = events[-1]["receipt"]
    if str(last.get("decision")) != expected_decision:
        raise ControlArenaExportError(
            f"{step_id}: receipt decision {last.get('decision')!r} "
            f"!= expected {expected_decision!r}"
        )
    return {
        "step_id": step_id,
        "plane": plane,
        "threat_class": threat_class,
        "expected_decision": expected_decision,
        "fixture_dir": rel,
        "fixture_notes": str(raw.get("notes") or ""),
        "events": events,
    }


def _within(base: Path, rel: str) -> Path:
    root = base.resolve()
    folder = (root / rel).resolve()
    if folder != root and root not in folder.parents:
        raise ControlArenaExportError(f"fixture path escapes the joint story directory: {rel}")
    return folder


def _load_sequence(step_id: str, folder: Path) -> tuple[dict[str, Any], ...]:
    spec = load_object(folder / "sequence.json")
    _require_existence_proof(spec, label=step_id)
    envelopes = spec.get("envelopes")
    if not isinstance(envelopes, list) or len(envelopes) != 2:
        raise ControlArenaExportError(f"{step_id}: sequence envelopes must be a two-item array")
    events: list[dict[str, Any]] = []
    for index, item in enumerate(envelopes):
        if not isinstance(item, Mapping):
            raise ControlArenaExportError(f"{step_id}: envelope spec must be an object")
        env_dir = str(item.get("dir") or "")
        if env_dir != f"envelope_{index + 1}":
            raise ControlArenaExportError(f"{step_id}: envelope dir must be envelope_{index + 1}")
        expected = str(item.get("expected_decision") or "")
        events.append(
            _load_event(
                step_id,
                folder / env_dir,
                expected,
                event_id=str(item.get("id") or env_dir),
            )
        )
    return tuple(events)


def _load_event(
    step_id: str,
    folder: Path,
    expected_decision: str,
    *,
    event_id: str,
) -> dict[str, Any]:
    envelope_path = folder / ENVELOPE_NAME
    receipt_path = folder / EXPECTED_NAME
    if not envelope_path.is_file() or not receipt_path.is_file():
        raise ControlArenaExportError(f"{step_id}: fixture {folder.name} needs envelope and receipt")
    envelope = load_object(envelope_path)
    receipt = load_object(receipt_path)
    if str(receipt.get("decision")) != expected_decision:
        raise ControlArenaExportError(
            f"{step_id}: {event_id} receipt decision {receipt.get('decision')!r} "
            f"!= expected {expected_decision!r}"
        )
    prose_path = folder / PROSE_NAME
    prose = prose_path.read_text(encoding="utf-8") if prose_path.is_file() else None
    runtime = load_object(folder / RUNTIME_NAME) if (folder / RUNTIME_NAME).is_file() else None
    return {
        "id": event_id,
        "tool_name": _tool_name(step_id, envelope),
        "tool_kind": _tool_kind(envelope),
        "tool_input": _tool_input(
            envelope,
            observed_head=_load_observed_head(folder / OBSERVED_HEAD_NAME),
            prose=prose,
            runtime=runtime,
        ),
        "receipt": receipt,
        "expected_decision": expected_decision,
    }


def _tool_kind(envelope: Mapping[str, Any]) -> str:
    invoke = envelope.get("invoke")
    if isinstance(invoke, Mapping) and invoke.get("tool_name"):
        return "host"
    if isinstance(envelope.get("capability"), str):
        return "supply"
    raise ControlArenaExportError("envelope has no tool_name or capability")


def _tool_name(step_id: str, envelope: Mapping[str, Any]) -> str:
    try:
        kind = _tool_kind(envelope)
    except ControlArenaExportError as exc:
        raise ControlArenaExportError(f"{step_id}: {exc}") from exc
    if kind == "host":
        invoke = envelope["invoke"]
        assert isinstance(invoke, Mapping)
        return str(invoke["tool_name"])
    return str(envelope["capability"])


def _tool_input(
    envelope: Mapping[str, Any],
    *,
    observed_head: str | None,
    prose: str | None,
    runtime: Mapping[str, Any] | None,
) -> dict[str, Any]:
    kind = _tool_kind(envelope)
    if kind == "host":
        invoke = envelope["invoke"]
        assert isinstance(invoke, Mapping)
        payload: dict[str, Any] = {
            "argv": invoke.get("argv"),
            "schema_fields": invoke.get("schema_fields"),
        }
        if runtime is not None:
            payload["runtime"] = runtime
    else:
        payload = {
            key: value
            for key, value in envelope.items()
            if key != "capability"
        }
        payload["observed_head"] = observed_head
    if prose is not None:
        payload["untrusted_prose"] = prose
    for key in ("caller", "policy_context", "untrusted_attachments"):
        if key in envelope and kind == "host":
            payload[key] = envelope[key]
    if kind == "host" and "monitor_verdict" in envelope:
        payload["monitor_verdict"] = envelope["monitor_verdict"]
    if kind == "host" and "please_allow" in envelope:
        payload["please_allow"] = envelope["please_allow"]
    return payload


def _load_observed_head(path: Path) -> str | None:
    if not path.is_file():
        return None
    raw = load_object(path)
    observed = raw.get("observed_head")
    if observed is None:
        return None
    if not isinstance(observed, str):
        raise ControlArenaExportError("observed_head must be a string or null")
    return observed


def _tool_catalogue(samples: list[dict[str, Any]]) -> list[dict[str, Any]]:
    schemas: dict[str, dict[str, Any]] = {}
    kinds: dict[str, str] = {}
    for sample in samples:
        for event in sample["events"]:
            name = str(event["tool_name"])
            kinds[name] = str(event["tool_kind"])
            schema = schemas.setdefault(
                name,
                {"type": "object", "properties": {}, "additionalProperties": True},
            )
            _observe_properties(schema["properties"], event["tool_input"])
    catalogue: list[dict[str, Any]] = []
    for name in sorted(schemas):
        description = _HOST_TOOL_DESCRIPTION if kinds[name] == "host" else _SUPPLY_TOOL_DESCRIPTION
        catalogue.append(
            {
                "name": name,
                "description": description,
                "input_schema": schemas[name],
            }
        )
    if not catalogue:
        raise ControlArenaExportError("fixtures named no tools")
    return catalogue


def _observe_properties(properties: dict[str, Any], example: Mapping[str, Any]) -> None:
    for key, value in example.items():
        observed = _json_schema_type(value)
        current = properties.get(key)
        if not isinstance(current, dict):
            properties[key] = {"type": observed}
            continue
        current["type"] = _merge_schema_type(current.get("type"), observed)


def _merge_schema_type(existing: Any, observed: str) -> str | list[str]:
    if not isinstance(existing, str | list):
        return observed
    types = list(existing) if isinstance(existing, list) else [existing]
    if observed not in types:
        types.append(observed)
    if len(types) == 1:
        return types[0]
    return sorted(str(item) for item in types)


def _json_schema_type(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, str):
        return "string"
    if isinstance(value, (int, float)):
        return "number"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "object"
    raise ControlArenaExportError(f"unsupported fixture value type: {type(value).__name__}")


def _trajectory_entry(sample: Mapping[str, Any], *, index: int) -> dict[str, Any]:
    messages: list[dict[str, Any]] = [
        {
            "role": "user",
            "content": [
                {
                    "type": "text",
                    "text": (
                        f"Fixture {sample['step_id']}. "
                        f"Plane {sample['plane']}. "
                        "Existence-proof receipt, not a model turn."
                    ),
                }
            ],
        }
    ]
    receipts: list[dict[str, Any]] = []
    for event_index, event in enumerate(sample["events"]):
        tool_use_id = f"toolu_{sample['step_id']}_{event_index}"
        receipt = event["receipt"]
        receipts.append(
            {
                "id": event["id"],
                "decision": receipt.get("decision"),
                "receipt": receipt,
            }
        )
        messages.append(
            {
                "role": "assistant",
                "content": [
                    {
                        "type": "tool_use",
                        "id": tool_use_id,
                        "name": event["tool_name"],
                        "input": event["tool_input"],
                    }
                ],
            }
        )
        messages.append(
            {
                "role": "user",
                "content": [
                    {
                        "type": "tool_result",
                        "tool_use_id": tool_use_id,
                        "is_error": receipt.get("decision") != "ALLOW",
                        "content": json.dumps(receipt, sort_keys=True, ensure_ascii=False),
                    }
                ],
            }
        )
    entry = {
        "rating": None,
        "notes": "",
        "desc": f"Trajectory from sample {index}",
        "other": "",
        "raw_state": json.dumps(messages, sort_keys=True, ensure_ascii=False),
        "metadata": {
            "step_id": sample["step_id"],
            "plane": sample["plane"],
            "threat_class": sample["threat_class"],
            "fixture_dir": sample["fixture_dir"],
            "fixture_notes": sample["fixture_notes"],
            "decision": sample["expected_decision"],
            "expected_decision": sample["expected_decision"],
            "existence_proof_only": True,
            "measured_attack_success_claimed": False,
            "residual_asr": None,
            "eval_mode": None,
            "receipts": receipts,
        },
        "scores": {},
        "models": [],
    }
    if tuple(entry) != TRAJECTORY_KEYS:
        raise ControlArenaExportError("trajectory line keys drifted from the directory writer")
    return entry


def _export_metadata(index: Mapping[str, Any], *, total_samples: int) -> dict[str, Any]:
    story_id = index.get("story_id")
    if not isinstance(story_id, str) or not story_id:
        raise ControlArenaExportError("index.story_id must be a non-empty string")
    created = FROZEN_CREATED
    metadata = {
        "source_file": "eval/joint_story/index.json",
        "format": "anthropic",
        "output_format": "directory",
        "eval_id": story_id,
        "created": created,
        "total_samples": total_samples,
        "brand": index.get("brand") or "Agent Control Lab",
        "licence": index.get("licence") or "Apache-2.0",
        "existence_proof_only": True,
        "measured_attack_success_claimed": False,
        "residual_asr": None,
        "inspect_loop": False,
        "inspect_eval_log": False,
        "control_arena_setting": False,
        "control_arena_package_required": False,
        "source": "receipts_and_fixtures",
        "llm_on_path": False,
        "format_note": (
            "Message blocks use the Anthropic tool-use object shape stored in "
            "ControlArena trajectory.jsonl raw_state. They are assembled from "
            "fixtures and frozen receipts. No model API is called. This is not "
            "a ControlArena setting and not an Inspect eval log."
        ),
    }
    missing = [key for key in _METADATA_CORE_KEYS if key not in metadata]
    if missing:
        raise ControlArenaExportError(f"metadata missing {missing}")
    return metadata


def _reject_asr(value: Any, path: str = "$") -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            if str(key).lower() in _ASR_KEYS or str(key).lower().endswith("_asr"):
                if item is not None:
                    raise ControlArenaExportError(f"{path}.{key} must be null or absent")
            _reject_asr(item, f"{path}.{key}")
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            _reject_asr(item, f"{path}[{index}]")


if __name__ == "__main__":
    raise SystemExit(main())

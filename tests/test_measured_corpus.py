# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agent Control Lab contributors
"""Offline self-check for the measured-corpus v0 schema and seed map.

Does not call pep, supply_gate, or a runner. The subset checker covers only
the JSON Schema keywords this contract uses.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "eval" / "measured_corpus"
ROW_SCHEMA_PATH = CORPUS / "schema" / "row.schema.json"
INDEX_SCHEMA_PATH = CORPUS / "schema" / "index.schema.json"
INDEX_PATH = CORPUS / "index.json"

_META = frozenset({"$schema", "$id", "$defs", "title", "description", "$comment"})
_KEYWORDS = frozenset(
    {
        "type",
        "const",
        "enum",
        "required",
        "properties",
        "additionalProperties",
        "pattern",
        "minLength",
        "minItems",
        "minProperties",
        "items",
        "$ref",
    }
)
_TYPES = {
    "object": dict,
    "string": str,
    "array": list,
    "boolean": bool,
}

_ARM_FROM_PLANE = {
    "supply-gate": "supply_gate",
    "pep": "pep",
}


def _load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _resolve(schema: dict[str, Any], root: dict[str, Any]) -> dict[str, Any]:
    ref = schema.get("$ref")
    if ref is None:
        return schema
    if list(schema) != ["$ref"]:
        raise AssertionError(f"$ref must be the only key, got {sorted(schema)}")
    if not isinstance(ref, str) or not ref.startswith("#/"):
        raise AssertionError(f"unsupported $ref: {ref}")
    node: Any = root
    for part in ref[2:].split("/"):
        if not isinstance(node, dict) or part not in node:
            raise AssertionError(f"unresolved $ref: {ref}")
        node = node[part]
    if not isinstance(node, dict):
        raise AssertionError(f"$ref did not resolve to an object: {ref}")
    return node


def _validate(instance: Any, schema: dict[str, Any], root: dict[str, Any], path: str) -> list[str]:
    schema = _resolve(schema, root)
    unknown = set(schema) - _KEYWORDS - _META
    if unknown:
        return [f"{path}: unsupported schema keywords {sorted(unknown)}"]
    errors: list[str] = []
    if "const" in schema and instance != schema["const"]:
        errors.append(f"{path}: expected const {schema['const']!r}, got {instance!r}")
    if "enum" in schema and instance not in schema["enum"]:
        errors.append(f"{path}: {instance!r} not in {schema['enum']!r}")
    expected = schema.get("type")
    if expected is not None:
        py_type = _TYPES.get(expected)
        if py_type is None:
            return [f"{path}: unsupported type {expected!r}"]
        if expected == "boolean":
            ok = isinstance(instance, bool)
        else:
            ok = isinstance(instance, py_type) and not isinstance(instance, bool)
        if not ok:
            errors.append(f"{path}: expected {expected}, got {type(instance).__name__}")
            return errors
    if expected == "object":
        if schema.get("additionalProperties") is False:
            extra = set(instance) - set(schema.get("properties", {}))
            for key in sorted(extra):
                errors.append(f"{path}: additional property {key!r}")
        elif "additionalProperties" in schema:
            errors.append(f"{path}: additionalProperties only supported as false")
        for key in schema.get("required", []):
            if key not in instance:
                errors.append(f"{path}: missing required {key!r}")
        if "minProperties" in schema and len(instance) < schema["minProperties"]:
            errors.append(f"{path}: expected at least {schema['minProperties']} properties")
        for key, sub in schema.get("properties", {}).items():
            if key in instance:
                errors.extend(_validate(instance[key], sub, root, f"{path}.{key}"))
    if expected == "string":
        if "minLength" in schema and len(instance) < schema["minLength"]:
            errors.append(f"{path}: shorter than {schema['minLength']}")
        if "pattern" in schema and re.fullmatch(schema["pattern"], instance) is None:
            errors.append(f"{path}: {instance!r} does not match {schema['pattern']}")
    if expected == "array":
        if "minItems" in schema and len(instance) < schema["minItems"]:
            errors.append(f"{path}: expected at least {schema['minItems']} items")
        if "items" in schema:
            for index, item in enumerate(instance):
                errors.extend(_validate(item, schema["items"], root, f"{path}[{index}]"))
    return errors


def _assert_valid(instance: Any, schema: dict[str, Any]) -> None:
    errors = _validate(instance, schema, schema, "$")
    assert not errors, errors


def test_v0_claim_bar_and_arms_are_frozen():
    row_schema = _load(ROW_SCHEMA_PATH)
    index_schema = _load(INDEX_SCHEMA_PATH)
    props = row_schema["properties"]
    assert props["arm"]["enum"] == ["pep", "supply_gate", "joint"]
    assert props["expected_decision"]["enum"] == ["DENY", "ALLOW"]
    assert props["existence_proof_only"]["const"] is True
    assert props["no_asr_claim"]["const"] is True
    assert props["brand"]["const"] == "Agent Control Lab"
    assert props["licence"]["const"] == "Apache-2.0"
    assert index_schema["properties"]["runner_implemented"]["const"] is False
    assert index_schema["properties"]["measured_attack_success_claimed"]["const"] is False
    cite = index_schema["properties"]["claim_cite"]["properties"]
    assert cite["lineage"]["const"] == "1d0f380"
    assert cite["lineage_sha"]["const"] == "1d0f3809a4a16d4a6ac3524b287cf719f192e1f9"


def test_seed_index_and_rows_match_schema():
    index_schema = _load(INDEX_SCHEMA_PATH)
    row_schema = _load(ROW_SCHEMA_PATH)
    index = _load(INDEX_PATH)
    _assert_valid(index, index_schema)
    assert index["arms"] == ["pep", "supply_gate", "joint"]
    assert index["claim_cite"]["lineage"] == "1d0f380"
    ids = [row["id"] for row in index["rows"]]
    assert len(ids) == len(set(ids))
    arms = {row["arm"] for row in index["rows"]}
    assert arms == {"pep", "supply_gate", "joint"}
    for row in index["rows"]:
        _assert_valid(row, row_schema)
        for rel in row["fixture_paths"].values():
            path = ROOT / rel
            assert path.is_file(), rel
            assert ".." not in Path(rel).parts


def test_seed_rows_map_joint_story_classes():
    index = _load(INDEX_PATH)
    story = _load(ROOT / "eval" / "joint_story" / "index.json")
    story_rows = {row["id"]: row for row in story["rows"]}
    mapped = [row for row in index["rows"] if row["arm"] != "joint"]
    assert {row["taxonomy"]["source_row_id"] for row in mapped} == set(story_rows)
    joint_rows = [row for row in index["rows"] if row["arm"] == "joint"]
    assert len(joint_rows) == 1
    joint = joint_rows[0]
    assert "source_row_id" not in joint["taxonomy"]
    assert joint["fixture_paths"] == {"story_index": "eval/joint_story/index.json"}
    assert joint["expected_decision"] == "DENY"
    for row in mapped:
        source = story_rows[row["taxonomy"]["source_row_id"]]
        assert row["arm"] == _ARM_FROM_PLANE[source["plane"]]
        assert row["taxonomy"]["plane_in_story"] == source["plane"]
        assert row["threat_class"] == source["threat_class"]
        assert row["expected_decision"] == source["expected_decision"]
        directory = source["dir"]
        for rel in row["fixture_paths"].values():
            assert rel.startswith(f"eval/joint_story/{directory}/")

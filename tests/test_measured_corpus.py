# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agent Control Lab contributors
"""Offline self-check for the measured-corpus v0 schema and seed map.

Does not call pep, supply_gate, or a runner. The subset checker covers only
the JSON Schema keywords this contract uses, including oneOf and a sibling-file
$ref. $ref is resolved against the schema file's retrieval URI (and against
$id when a schema sets one). const uses JSON type equality, so booleans are
not numbers.
"""

from __future__ import annotations

import copy
import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urljoin, urlparse
from urllib.request import url2pathname

from joint_eval.pins import PEP_SHA, SUPPLY_GATE_SHA

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
        "maxItems",
        "minProperties",
        "items",
        "$ref",
        "oneOf",
    }
)
_ARMS = ("monitor-alone", "host-PEP-alone", "stack")
_PEP_CORPUS_DENY_IDS = frozenset(
    {
        "acl-pep-eval-prose-as-policy-001",
        "acl-pep-eval-capability-spoof-001",
        "acl-pep-eval-monitor-coax-001",
        "acl-pep-eval-missing-policy-001",
        "acl-pep-eval-kill-001",
        "acl-pep-eval-late-effect-fence-001",
        "acl-pep-eval-suspend-001",
        "acl-pep-eval-approval-replay-001",
        "acl-pep-eval-approval-ttl-001",
        "acl-pep-eval-approval-binding-mismatch-001",
    }
)
_SUPPLY_CASES = frozenset(
    {
        "plugin4shell_class",
        "omitted_adapter_head",
        "prose_waive_attempt",
        "auto_latest_rejected",
        "trust_ref_rejected",
        "unreadable_allowlist",
        "allow_pin_and_verify",
    }
)
_NOUL_CLASSES = frozenset(
    {"override", "no_rules_persona", "embedded_instruction", "tool_abuse"}
)
_TM_CLASSES = frozenset(
    {"approve-then-mutate", "multi-session-plant", "deferred-tool"}
)


def _load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _type_name(instance: Any) -> str:
    if instance is None:
        return "null"
    if isinstance(instance, bool):
        return "boolean"
    if isinstance(instance, str):
        return "string"
    if isinstance(instance, list):
        return "array"
    if isinstance(instance, dict):
        return "object"
    return type(instance).__name__


def _json_equal(left: Any, right: Any) -> bool:
    """JSON Schema equality. Booleans are not numbers (False != 0, True != 1)."""
    if isinstance(left, bool) or isinstance(right, bool):
        return isinstance(left, bool) and isinstance(right, bool) and left == right
    if isinstance(left, dict) and isinstance(right, dict):
        return left.keys() == right.keys() and all(
            _json_equal(left[key], right[key]) for key in left
        )
    if isinstance(left, list) and isinstance(right, list):
        return len(left) == len(right) and all(
            _json_equal(item, other) for item, other in zip(left, right)
        )
    return left == right


def _canonical_uri(schema: dict[str, Any], retrieval_uri: str) -> str:
    schema_id = schema.get("$id")
    if not isinstance(schema_id, str) or schema_id == "" or schema_id.startswith("#"):
        return retrieval_uri
    return urljoin(retrieval_uri, schema_id)


def _pointer(root: dict[str, Any], ref: str) -> dict[str, Any]:
    node: Any = root
    for part in ref[2:].split("/"):
        part = part.replace("~1", "/").replace("~0", "~")
        if not isinstance(node, dict) or part not in node:
            raise AssertionError(f"unresolved $ref: {ref}")
        node = node[part]
    if not isinstance(node, dict):
        raise AssertionError(f"$ref did not resolve to an object: {ref}")
    return node


def _resolve(
    schema: dict[str, Any], root: dict[str, Any], base: Path, doc_uri: str
) -> tuple[dict[str, Any], dict[str, Any], Path, str]:
    ref = schema.get("$ref")
    if ref is None:
        return schema, root, base, _canonical_uri(schema, doc_uri)
    if list(schema) != ["$ref"]:
        raise AssertionError(f"$ref must be the only key, got {sorted(schema)}")
    if not isinstance(ref, str) or ref == "" or ref == "#":
        raise AssertionError(f"unsupported $ref: {ref}")
    if ref.startswith("#/"):
        return _pointer(root, ref), root, base, doc_uri
    if ref.startswith("#"):
        raise AssertionError(f"unsupported $ref: {ref}")
    resolved = urljoin(doc_uri, ref)
    parsed = urlparse(resolved)
    if parsed.scheme != "file" or parsed.fragment or parsed.query:
        raise AssertionError(
            f"$ref {ref!r} resolved to {resolved}, not a local schema file"
        )
    target = Path(url2pathname(unquote(parsed.path))).resolve()
    schema_dir = (CORPUS / "schema").resolve()
    if target.parent != schema_dir:
        raise AssertionError(
            f"$ref {ref!r} resolved outside the schema directory: {target}"
        )
    external = _load(target)
    if not isinstance(external, dict):
        raise AssertionError(f"$ref did not resolve to an object: {ref}")
    retrieval = target.as_uri()
    return external, external, target, _canonical_uri(external, retrieval)


def _one_of(
    instance: Any,
    branches: Any,
    root: dict[str, Any],
    path: str,
    base: Path,
    doc_uri: str,
) -> list[str]:
    if not isinstance(branches, list) or not branches:
        raise AssertionError(f"{path}: oneOf must be a non-empty array")
    matched = 0
    failures: list[str] = []
    for index, branch in enumerate(branches):
        if not isinstance(branch, dict):
            raise AssertionError(f"{path}: oneOf entry {index} must be an object")
        branch_errors = _validate(
            instance, branch, root, f"{path}<oneOf[{index}]>", base, doc_uri
        )
        if branch_errors:
            if len(failures) < 6:
                failures.extend(branch_errors[:3])
        else:
            matched += 1
    if matched == 1:
        return []
    return [f"{path}: oneOf matched {matched} schemas, expected exactly 1", *failures]


def _validate(
    instance: Any,
    schema: dict[str, Any],
    root: dict[str, Any],
    path: str,
    base: Path,
    doc_uri: str | None = None,
) -> list[str]:
    if doc_uri is None:
        doc_uri = base.resolve().as_uri()
    schema, root, base, doc_uri = _resolve(schema, root, base, doc_uri)
    unknown = set(schema) - _KEYWORDS - _META
    if unknown:
        return [f"{path}: unsupported schema keywords {sorted(unknown)}"]
    errors: list[str] = []
    if "const" in schema and not _json_equal(instance, schema["const"]):
        errors.append(f"{path}: expected const {schema['const']!r}, got {instance!r}")
    if "enum" in schema and instance not in schema["enum"]:
        errors.append(f"{path}: {instance!r} not in {schema['enum']!r}")
    expected = schema.get("type")
    if expected is not None and _type_name(instance) not in (
        expected if isinstance(expected, list) else [expected]
    ):
        errors.append(f"{path}: expected {expected}, got {_type_name(instance)}")
        return errors
    if "oneOf" in schema:
        errors.extend(_one_of(instance, schema["oneOf"], root, path, base, doc_uri))
    if instance is None:
        return errors
    kind = _type_name(instance)
    if kind == "object":
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
                errors.extend(
                    _validate(instance[key], sub, root, f"{path}.{key}", base, doc_uri)
                )
    if kind == "string":
        if "minLength" in schema and len(instance) < schema["minLength"]:
            errors.append(f"{path}: shorter than {schema['minLength']}")
        if "pattern" in schema and re.fullmatch(schema["pattern"], instance) is None:
            errors.append(f"{path}: {instance!r} does not match {schema['pattern']}")
    if kind == "array":
        if "minItems" in schema and len(instance) < schema["minItems"]:
            errors.append(f"{path}: expected at least {schema['minItems']} items")
        if "maxItems" in schema and len(instance) > schema["maxItems"]:
            errors.append(f"{path}: expected at most {schema['maxItems']} items")
        if "items" in schema:
            for index, item in enumerate(instance):
                errors.extend(
                    _validate(item, schema["items"], root, f"{path}[{index}]", base, doc_uri)
                )
    return errors


def _assert_valid(instance: Any, schema: dict[str, Any], base: Path) -> None:
    errors = _validate(instance, schema, schema, "$", base)
    assert not errors, errors


def test_v0_claim_bar_arms_and_asr_slot_are_frozen():
    row_schema = _load(ROW_SCHEMA_PATH)
    index_schema = _load(INDEX_SCHEMA_PATH)
    arms = row_schema["properties"]["arms"]
    assert list(arms["properties"]) == list(_ARMS)
    assert arms["required"] == list(_ARMS)
    defs = row_schema["$defs"]
    assert "outcome" not in defs
    assert "mapped_outcome" not in defs
    assert "$id" not in row_schema
    assert "$id" not in index_schema
    assert defs["residual_asr"]["type"] == "null"
    sha = {"$ref": "#/$defs/sha"}
    sha_or_null = {"$ref": "#/$defs/sha_or_null"}
    assert defs["sha"]["type"] == "string"
    for name in ("host_pep_mapped_outcome", "stack_mapped_outcome"):
        assert defs[name]["properties"]["status"]["const"] == "mapped"
        assert defs[name]["properties"]["decision"]["enum"] == ["DENY", "ALLOW"]
        assert defs[name]["properties"]["residual_asr"] == {"$ref": "#/$defs/residual_asr"}
    assert defs["host_pep_mapped_tip_pins"]["properties"] == {
        "pep": sha,
        "supply_gate": sha_or_null,
        "joint": sha_or_null,
    }
    assert defs["stack_mapped_tip_pins"]["properties"] == {
        "pep": sha,
        "supply_gate": sha,
        "joint": sha_or_null,
    }
    assert defs["tip_pins"]["properties"] == {
        "pep": sha_or_null,
        "supply_gate": sha_or_null,
        "joint": sha_or_null,
    }
    assert defs["stub_outcome"]["properties"]["status"]["const"] == "stub"
    assert defs["stub_outcome"]["properties"]["decision"]["const"] is None
    assert defs["stub_outcome"]["properties"]["tip_pins"] == {"$ref": "#/$defs/tip_pins"}
    assert defs["not_applicable_outcome"]["properties"]["status"]["const"] == "not_applicable"
    assert defs["not_applicable_outcome"]["properties"]["decision"]["const"] is None
    assert defs["not_applicable_outcome"]["properties"]["tip_pins"] == {"$ref": "#/$defs/tip_pins"}
    assert defs["stub_outcome"]["properties"]["residual_asr"] == {"$ref": "#/$defs/residual_asr"}
    assert defs["not_applicable_outcome"]["properties"]["residual_asr"] == {
        "$ref": "#/$defs/residual_asr"
    }
    assert arms["properties"]["monitor-alone"]["oneOf"] == [
        {"$ref": "#/$defs/stub_outcome"},
        {"$ref": "#/$defs/not_applicable_outcome"},
    ]
    assert arms["properties"]["host-PEP-alone"]["oneOf"] == [
        {"$ref": "#/$defs/host_pep_mapped_outcome"},
        {"$ref": "#/$defs/not_applicable_outcome"},
    ]
    assert arms["properties"]["stack"]["oneOf"] == [
        {"$ref": "#/$defs/stack_mapped_outcome"},
        {"$ref": "#/$defs/not_applicable_outcome"},
    ]
    assert row_schema["$defs"]["decision_or_null"]["enum"] == ["DENY", "ALLOW", None]
    assert row_schema["properties"]["existence_proof_only"]["const"] is True
    assert row_schema["properties"]["no_asr_claim"]["const"] is True
    assert row_schema["properties"]["brand"]["const"] == "Agent Control Lab"
    assert index_schema["properties"]["runner_implemented"]["const"] is False
    assert index_schema["properties"]["measured_attack_success_claimed"]["const"] is False
    assert index_schema["properties"]["rows"]["minItems"] == 20
    assert index_schema["properties"]["rows"]["maxItems"] == 50
    assert index_schema["properties"]["rows"]["items"] == {"$ref": "row.schema.json"}
    assert index_schema["properties"]["arms"]["const"] == list(_ARMS)
    cite = index_schema["properties"]["claim_cite"]["properties"]
    assert cite["lineage"]["const"] == "1d0f380"
    assert cite["lineage_sha"]["const"] == "1d0f3809a4a16d4a6ac3524b287cf719f192e1f9"


def test_seed_index_and_rows_match_schema():
    index = _load(INDEX_PATH)
    index_schema = _load(INDEX_SCHEMA_PATH)
    _assert_valid(index, index_schema, INDEX_SCHEMA_PATH)
    row_schema = _load(ROW_SCHEMA_PATH)
    assert index["arms"] == list(_ARMS)
    assert index["claim_cite"]["lineage"] == "1d0f380"
    assert "Cyber PASS" in index["claim_cite"]["note"]
    rows = index["rows"]
    assert 20 <= len(rows) <= 50
    ids = [row["threat_id"] for row in rows]
    assert len(ids) == len(set(ids))
    for row in rows:
        _assert_valid(row, row_schema, ROW_SCHEMA_PATH)


def _outcome(
    status: str,
    decision: str | None,
    *,
    pep: str | None = None,
    supply_gate: str | None = None,
    joint: str | None = None,
) -> dict[str, Any]:
    return {
        "status": status,
        "decision": decision,
        "residual_asr": None,
        "tip_pins": {"pep": pep, "supply_gate": supply_gate, "joint": joint},
    }


def _with_first_arm(index: dict[str, Any], arm: str, outcome: dict[str, Any]) -> dict[str, Any]:
    cloned = copy.deepcopy(index)
    cloned["rows"][0]["arms"][arm] = outcome
    return cloned


def test_index_schema_enforces_row_contract_arm_order_and_status_decision():
    index = _load(INDEX_PATH)
    index_schema = _load(INDEX_SCHEMA_PATH)
    base = INDEX_SCHEMA_PATH

    def errors_for(instance: dict[str, Any]) -> list[str]:
        return _validate(instance, index_schema, index_schema, "$", base)

    for arms in (
        ["stack", "monitor-alone", "host-PEP-alone"],
        ["monitor-alone", "monitor-alone", "stack"],
        ["monitor-alone", "host-PEP-alone", "host-PEP-alone"],
        ["monitor-alone", "host-PEP-alone"],
    ):
        reordered = copy.deepcopy(index)
        reordered["arms"] = arms
        errors = errors_for(reordered)
        assert errors
        assert any(error.startswith("$.arms") and "const" in error for error in errors)

    valid_cases = (
        ("monitor-alone", _outcome("not_applicable", None)),
        ("host-PEP-alone", _outcome("mapped", "ALLOW", pep=PEP_SHA)),
        ("stack", _outcome("mapped", "ALLOW", pep=PEP_SHA, supply_gate=SUPPLY_GATE_SHA)),
        ("stack", _outcome("not_applicable", None)),
        ("host-PEP-alone", _outcome("not_applicable", None)),
    )
    for arm, outcome in valid_cases:
        _assert_valid(_with_first_arm(index, arm, outcome), index_schema, base)

    invalid_cases = (
        ("host-PEP-alone", _outcome("mapped", None)),
        ("stack", _outcome("mapped", None)),
        ("monitor-alone", _outcome("stub", "DENY")),
        ("stack", _outcome("not_applicable", "ALLOW")),
        ("host-PEP-alone", _outcome("not_applicable", "DENY")),
        ("stack", _outcome("stub", None)),
        ("host-PEP-alone", _outcome("stub", None)),
        ("monitor-alone", _outcome("mapped", "DENY")),
        ("monitor-alone", _outcome("stub", "ALLOW")),
    )
    for arm, outcome in invalid_cases:
        errors = errors_for(_with_first_arm(index, arm, outcome))
        assert errors, arm
        assert any(
            error.startswith("$.rows[0].arms") and "oneOf" in error for error in errors
        ), errors

    filled = copy.deepcopy(index)
    filled["rows"][0]["arms"]["monitor-alone"]["residual_asr"] = 0.0
    asr_errors = errors_for(filled)
    assert asr_errors
    assert any("residual_asr" in error and error.startswith("$.rows[0]") for error in asr_errors)

    null_pin_cases = (
        ("host-PEP-alone", _outcome("mapped", "DENY")),
        ("host-PEP-alone", _outcome("mapped", "ALLOW", supply_gate=SUPPLY_GATE_SHA)),
        ("stack", _outcome("mapped", "DENY")),
        ("stack", _outcome("mapped", "ALLOW", pep=PEP_SHA)),
        ("stack", _outcome("mapped", "DENY", supply_gate=SUPPLY_GATE_SHA)),
    )
    for arm, outcome in null_pin_cases:
        errors = errors_for(_with_first_arm(index, arm, outcome))
        assert errors, arm
        assert any(
            error.startswith("$.rows[0].arms") and "oneOf" in error for error in errors
        ), errors


def test_row_ref_resolves_from_the_checked_out_schema_directory():
    index_schema = _load(INDEX_SCHEMA_PATH)
    row_schema = _load(ROW_SCHEMA_PATH)
    assert "$id" not in index_schema
    assert "$id" not in row_schema
    retrieval = INDEX_SCHEMA_PATH.resolve().as_uri()
    ref = index_schema["properties"]["rows"]["items"]["$ref"]
    resolved = urljoin(retrieval, ref)
    assert urlparse(resolved).scheme == "file"
    assert resolved == ROW_SCHEMA_PATH.resolve().as_uri()

    poisoned = copy.deepcopy(index_schema)
    poisoned["$id"] = (
        "https://github.com/gs034/agent-control-lab-joint-eval/"
        "eval/measured_corpus/schema/index.schema.json"
    )
    index = _load(INDEX_PATH)
    try:
        _validate(index, poisoned, poisoned, "$", INDEX_SCHEMA_PATH)
    except AssertionError as exc:
        message = str(exc)
        assert "row.schema.json" in message
        assert "https://github.com/" in message
    else:
        raise AssertionError("a GitHub HTML $id must not resolve the local row schema")


def test_const_comparison_rejects_numeric_boolean_aliases():
    index = _load(INDEX_PATH)
    index_schema = _load(INDEX_SCHEMA_PATH)
    row_schema = _load(ROW_SCHEMA_PATH)

    def index_errors(instance: dict[str, Any]) -> list[str]:
        return _validate(instance, index_schema, index_schema, "$", INDEX_SCHEMA_PATH)

    for field, bad in (
        ("runner_implemented", 0),
        ("runner_implemented", 1),
        ("measured_attack_success_claimed", 0),
        ("measured_attack_success_claimed", 1),
    ):
        cloned = copy.deepcopy(index)
        cloned[field] = bad
        errors = index_errors(cloned)
        assert errors, field
        assert any(field in error and "const" in error for error in errors), errors

    row = copy.deepcopy(index["rows"][0])
    row["existence_proof_only"] = 1
    errors = _validate(row, row_schema, row_schema, "$", ROW_SCHEMA_PATH)
    assert any("existence_proof_only" in error and "const" in error for error in errors), errors
    row["existence_proof_only"] = True
    row["no_asr_claim"] = 0
    errors = _validate(row, row_schema, row_schema, "$", ROW_SCHEMA_PATH)
    assert any("no_asr_claim" in error and "const" in error for error in errors), errors
    row["no_asr_claim"] = True
    _assert_valid(row, row_schema, ROW_SCHEMA_PATH)


def test_seed_covers_pep_supply_noul_and_threat_model_classes():
    rows = _load(INDEX_PATH)["rows"]
    by_family: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        by_family.setdefault(row["taxonomy"]["family"], []).append(row)
    assert len(by_family["pep_deny"]) == 11
    assert len(by_family["supply_pin_head_verify"]) == 7
    assert {row["taxonomy"]["class_id"] for row in by_family["noul_taxonomy"]} == _NOUL_CLASSES
    assert {row["taxonomy"]["class_id"] for row in by_family["threat_model"]} == _TM_CLASSES

    pep_ids = {
        fixture["source_id"]
        for row in by_family["pep_deny"]
        for fixture in row["fixtures"]
        if fixture["role"] == "pep_corpus"
    }
    assert pep_ids == _PEP_CORPUS_DENY_IDS
    official = [
        fixture["source_id"]
        for row in by_family["pep_deny"]
        for fixture in row["fixtures"]
        if fixture["role"] == "pep_official"
    ]
    assert set(official) == {"acl-pep-eval-2609-19587-class-001"}
    supply_ids = {
        fixture["source_id"]
        for row in by_family["supply_pin_head_verify"]
        for fixture in row["fixtures"]
        if fixture["role"] == "supply_eval"
    }
    assert supply_ids == _SUPPLY_CASES


def test_arm_outcomes_stay_unmeasured():
    rows = _load(INDEX_PATH)["rows"]
    for row in rows:
        monitor = row["arms"]["monitor-alone"]
        assert monitor["status"] in {"stub", "not_applicable"}
        assert monitor["decision"] is None
        assert monitor["residual_asr"] is None
        assert monitor["tip_pins"] == {"pep": None, "supply_gate": None, "joint": None}
        for arm_name in _ARMS:
            arm = row["arms"][arm_name]
            assert arm["residual_asr"] is None
            assert arm["tip_pins"]["joint"] is None
            for label, sha in (("pep", PEP_SHA), ("supply_gate", SUPPLY_GATE_SHA)):
                pinned = arm["tip_pins"][label]
                if pinned is not None:
                    assert pinned == sha
            if arm["status"] == "mapped":
                assert arm["decision"] in {"DENY", "ALLOW"}
            else:
                assert arm["decision"] is None
        host = row["arms"]["host-PEP-alone"]
        stack = row["arms"]["stack"]
        joint_fixtures = [item for item in row["fixtures"] if item["role"] == "joint_story"]
        if joint_fixtures:
            assert stack["status"] == "mapped"
            assert stack["decision"] == "DENY"
            assert stack["tip_pins"]["pep"] == PEP_SHA
            assert stack["tip_pins"]["supply_gate"] == SUPPLY_GATE_SHA
        else:
            assert stack["decision"] is None
        family = row["taxonomy"]["family"]
        if family == "pep_deny":
            assert host["status"] == "mapped"
            assert host["decision"] == "DENY"
            assert host["tip_pins"]["pep"] == PEP_SHA
            assert row["taxonomy"]["mapped_receipt_decision"] == "DENY"
        elif family == "supply_pin_head_verify":
            assert host["status"] == "not_applicable"
            assert host["decision"] is None
        else:
            assert row["taxonomy"]["mapped_receipt_decision"] in {"DENY", "ALLOW", None}
        if row["taxonomy"]["mapped_receipt_decision"] is None:
            assert row["fixtures"] == []
            assert host["decision"] is None
            assert stack["decision"] is None


def test_fixture_pointers_do_not_vendor_sibling_trees():
    rows = _load(INDEX_PATH)["rows"]
    assert not (ROOT / "pep").exists()
    assert not (ROOT / "supply_gate").exists()
    for row in rows:
        for fixture in row["fixtures"]:
            rel = fixture["path"]
            assert ".." not in Path(rel).parts
            assert rel.startswith("eval/")
            if fixture["repo"].endswith("agent-control-lab-pep"):
                assert fixture["git_sha"] == PEP_SHA
                assert not (ROOT / rel).exists()
            elif fixture["repo"].endswith("agent-control-lab-supply-gate"):
                assert fixture["git_sha"] == SUPPLY_GATE_SHA
                assert not (ROOT / rel).exists()
            else:
                assert fixture["git_sha"] is None
                path = ROOT / rel
                assert path.exists(), rel

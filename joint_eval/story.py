# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agent Control Lab contributors
"""One scripted joint existence-proof story (fail-closed DENY).

Steps (this tree's fixtures; sibling packages via pinned git installs):

1. Plugin4Shell-class supply DENY (skip-verify / swapped HEAD)
2. Pin-without-verify supply DENY (observed HEAD omitted)
3. Monitor-bypass / prose-as-policy PEP DENY
4. Approval-binding mismatch PEP DENY (bind class)

No model call on this path. No marketplace. Complementary to monitors —
not a replacement. Existence-proof only; this tree does not measure
attack success.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping

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
from joint_eval.pins import pin_document

STORY_ID = "acl-joint-eval-existence-proof-001"
BRAND = "Agent Control Lab"
LICENCE = "Apache-2.0"
CLOCK = datetime(2026, 9, 21, 12, 0, tzinfo=timezone.utc)

# Semantic keys compared against frozen expected receipts (live pep timestamp
# is excluded; sibling pep receipts stamp evaluate() time).
PEP_COMPARE_SKIP = frozenset({"timestamp"})


class JointEvalError(RuntimeError):
    """Harness fault. Callers must fail closed (never treat as ALLOW)."""


@dataclass(frozen=True, slots=True)
class StepResult:
    step_id: str
    plane: str
    threat_class: str
    decision: str
    expected_decision: str
    receipt: dict[str, Any]
    invoked: bool
    ok: bool
    notes: str


@dataclass(frozen=True, slots=True)
class JointStoryResult:
    document: dict[str, Any]
    steps: tuple[StepResult, ...]
    ok: bool


def run_joint_story(*, root: Path | None = None) -> JointStoryResult:
    """Run the official joint story. Fail-closed: missing deps → error, not ALLOW."""
    _pep_evaluate, pep_runtime_cls, pep_gated, pep_approval_store = _import_pep()
    del _pep_evaluate
    supply_evaluate, supply_verdict, supply_origins = _import_supply()

    base = story_dir() if root is None else Path(root) / "eval" / "joint_story"
    index = load_index() if root is None else load_object(base / "index.json")
    rows = index.get("rows")
    if not isinstance(rows, list) or not rows:
        raise JointEvalError("joint story index.rows must be a non-empty array")

    steps: list[StepResult] = []
    for raw in rows:
        if not isinstance(raw, Mapping):
            raise JointEvalError("joint story row must be a JSON object")
        steps.append(
            _run_row(
                base,
                raw,
                pep_runtime_cls=pep_runtime_cls,
                pep_gated=pep_gated,
                pep_approval_store=pep_approval_store,
                supply_evaluate=supply_evaluate,
                supply_verdict=supply_verdict,
                supply_origins=supply_origins,
            )
        )

    ok = all(step.ok for step in steps) and bool(steps)
    document = {
        "brand": BRAND,
        "licence": LICENCE,
        "story_id": STORY_ID,
        "schema_version": "1",
        "existence_proof_only": True,
        "complementary_to_monitors": True,
        "replacement_for_monitors": False,
        "measured_attack_success_claimed": False,
        "fail_closed": True,
        "llm_on_evaluate_path": False,
        "marketplace": False,
        "pins": pin_document(),
        "coverage_limits": (
            "Existence-proof of named deny classes only. Not a measured "
            "attack-success study. Not a replacement for monitors. Does not "
            "vendor sibling source trees; invokes pinned public packages."
        ),
        "steps": [_step_public(step) for step in steps],
        "all_denied": ok,
    }
    return JointStoryResult(document=document, steps=tuple(steps), ok=ok)


def compare_receipt(
    live: Mapping[str, Any],
    expected: Mapping[str, Any],
    *,
    skip: frozenset[str] = frozenset(),
) -> list[str]:
    """Return mismatch descriptions. Empty means semantic match."""
    mismatches: list[str] = []
    for key, value in expected.items():
        if key in skip:
            continue
        if key not in live:
            mismatches.append(f"missing key {key}")
            continue
        if live[key] != value:
            mismatches.append(f"{key}: live {live[key]!r} != expected {value!r}")
    return mismatches


def dumps_story(result: JointStoryResult) -> str:
    return dumps_canonical(result.document)


def _run_row(
    base: Path,
    raw: Mapping[str, Any],
    *,
    pep_runtime_cls: type,
    pep_gated: Callable[..., Any],
    pep_approval_store: type,
    supply_evaluate: Callable[..., Any],
    supply_verdict: Any,
    supply_origins: frozenset[str],
) -> StepResult:
    step_id = str(raw["id"])
    plane = str(raw["plane"])
    threat_class = str(raw["threat_class"])
    expected_decision = str(raw["expected_decision"])
    rel = str(raw["dir"])
    folder = base / rel
    envelope = load_object(folder / ENVELOPE_NAME)
    expected = load_object(folder / EXPECTED_NAME)
    notes = str(raw.get("notes") or "")

    invoked = False
    if plane == "supply-gate":
        observed = _load_observed_head(folder / OBSERVED_HEAD_NAME)
        prose_path = folder / PROSE_NAME
        prose = prose_path.read_text(encoding="utf-8") if prose_path.is_file() else None
        decision_obj = supply_evaluate(
            envelope,
            observed,
            allowed_origins=supply_origins,
            kill_active=False,
            untrusted_prose=prose,
        )
        live = dict(decision_obj.receipt)
        decision = str(decision_obj.verdict.value if hasattr(decision_obj.verdict, "value") else decision_obj.verdict)
        skip: frozenset[str] = frozenset()
        invoked = bool(decision_obj.allowed) or decision_obj.verdict is supply_verdict.ALLOW
    elif plane == "pep":
        runtime = _pep_runtime(folder, pep_runtime_cls, pep_approval_store)
        invoked_box = {"n": 0}

        def _must_not_run() -> str:
            invoked_box["n"] += 1
            return "INVOKED"

        decision_obj, _result = pep_gated(
            envelope,
            _must_not_run,
            runtime=runtime,
            now=CLOCK,
        )
        live = decision_obj.to_dict()
        decision = str(decision_obj.verdict)
        invoked = invoked_box["n"] > 0
        skip = PEP_COMPARE_SKIP
    else:
        raise JointEvalError(f"{step_id}: unknown plane {plane}")

    mismatches = compare_receipt(live, expected, skip=skip)
    ok = (
        decision == expected_decision == "DENY"
        and not invoked
        and not mismatches
        and live.get("decision") == "DENY"
    )
    if mismatches:
        notes = (notes + " " if notes else "") + "receipt mismatch: " + "; ".join(mismatches)
    if invoked:
        notes = (notes + " " if notes else "") + "callable entered on DENY path"
    return StepResult(
        step_id=step_id,
        plane=plane,
        threat_class=threat_class,
        decision=decision,
        expected_decision=expected_decision,
        receipt=live,
        invoked=invoked,
        ok=ok,
        notes=notes,
    )


def _pep_runtime(folder: Path, pep_runtime_cls: type, pep_approval_store: type) -> Any:
    runtime_path = folder / RUNTIME_NAME
    if not runtime_path.is_file():
        return pep_runtime_cls()
    spec = load_object(runtime_path)
    store = pep_approval_store()
    runtime = pep_runtime_cls(approvals=store)
    now = _optional_clock(spec.get("now")) or CLOCK
    for grant in spec.get("approvals") or []:
        if not isinstance(grant, Mapping):
            raise JointEvalError("approval fixture must be a JSON object")
        issued_at = _optional_clock(grant.get("issued_at")) or now
        frozen_args = grant.get("args")
        if not isinstance(frozen_args, Mapping):
            raise JointEvalError("approval fixture must freeze args")
        runtime.issue_approval(
            tool_name=str(grant.get("tool_name")),
            args=frozen_args,
            ttl_seconds=int(grant["ttl_seconds"]),
            approval_id=str(grant["approval_id"]),
            now=issued_at,
        )
    return runtime


def _optional_clock(value: Any) -> datetime | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise JointEvalError("clock must be an ISO-8601 string")
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


def _load_observed_head(path: Path) -> str | None:
    if not path.is_file():
        return None
    raw = load_object(path)
    observed = raw.get("observed_head")
    if observed is None:
        return None
    if not isinstance(observed, str):
        raise JointEvalError("observed_head must be a string or null")
    return observed


def _step_public(step: StepResult) -> dict[str, Any]:
    return {
        "id": step.step_id,
        "plane": step.plane,
        "threat_class": step.threat_class,
        "decision": step.decision,
        "expected_decision": step.expected_decision,
        "invoked": step.invoked,
        "ok": step.ok,
        "notes": step.notes,
        "receipt": step.receipt,
    }


def _import_pep() -> tuple[Any, Any, Any, Any]:
    try:
        from pep.approval import ApprovalStore
        from pep.evaluate import PepRuntime, evaluate
        from pep.gate import gated_invoke
    except Exception as exc:  # noqa: BLE001 — fail-closed import boundary
        raise JointEvalError(f"pep package unavailable: {exc}") from exc
    return evaluate, PepRuntime, gated_invoke, ApprovalStore


def _import_supply() -> tuple[Any, Any, Any]:
    try:
        from supply_gate.gate import evaluate
        from supply_gate.origins import DEFAULT_ALLOWED_ORIGINS
        from supply_gate.reasons import Verdict
    except Exception as exc:  # noqa: BLE001 — fail-closed import boundary
        raise JointEvalError(f"supply-gate package unavailable: {exc}") from exc
    return evaluate, Verdict, DEFAULT_ALLOWED_ORIGINS

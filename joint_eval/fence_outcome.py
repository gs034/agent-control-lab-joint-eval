# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agent Control Lab contributors
"""B9 late-effect fence outcome mapping stub.

Loads the in-tree table that maps pep fence existence fixtures onto the
revocation-suite registered outcome vocabulary (arXiv:2609.21284 as a
pattern cite only). This module does not vendor pep, does not run a
kernel fence, and does not mint a table_id.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping

from joint_eval.loader import repo_root
from joint_eval.pins import PEP_SHA

RELATIVE_PATH = Path("eval") / "measured_corpus" / "fence-outcome-b9.json"
LABELS = frozenset({"covered", "not_applicable_by_design"})
LAB_REASON_CODES = frozenset(
    {"late_effect_fence", "admission_consumed", "kill_active", "suspend_active"}
)
CLAIM_LINEAGE = "1d0f380"
CLAIM_LINEAGE_SHA = "1d0f3809a4a16d4a6ac3524b287cf719f192e1f9"
PEP_REPO = "https://github.com/gs034/agent-control-lab-pep"


class FenceOutcomeError(ValueError):
    """The mapping stub is missing a required label or pin."""


def load_fence_outcome(root: Path | None = None) -> dict[str, Any]:
    """Load and check the B9 table. Sibling pep source is not read."""
    base = repo_root() if root is None else Path(root)
    path = base / RELATIVE_PATH
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise FenceOutcomeError("fence outcome table must be a JSON object")
    validate_fence_outcome(data, root=base)
    return data


def lab_fence_rows(table: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    rows = table.get("rows")
    if not isinstance(rows, list):
        return []
    return [row for row in rows if isinstance(row, Mapping) and row.get("kind") == "lab_fence_fixture"]


def validate_fence_outcome(table: Mapping[str, Any], *, root: Path | None = None) -> None:
    """Reject a table that drops a label, vendors pep, or claims the paper."""
    if table.get("paper_17_of_17_claimed") is not False:
        raise FenceOutcomeError("paper 17/17 must stay unclaimed")
    if table.get("conformance_claim") is not False:
        raise FenceOutcomeError("conformance claim must stay false")
    if table.get("slsa_claim") is not False:
        raise FenceOutcomeError("SLSA claim must stay false")
    if table.get("kernel_fence_claim") is not False:
        raise FenceOutcomeError("kernel fence claim must stay false")
    if table.get("new_deny_class") is not False:
        raise FenceOutcomeError("B9 must not add a DENY class")
    if table.get("table_id") is not None or table.get("residual_asr") is not None:
        raise FenceOutcomeError("table_id and residual_asr stay null")
    if table.get("pattern_only") is not True:
        raise FenceOutcomeError("arXiv cite is pattern only")
    if table.get("pep_pin") != PEP_SHA:
        raise FenceOutcomeError("pep pin must stay the install pin")
    cite = table.get("claim_cite")
    if not isinstance(cite, Mapping):
        raise FenceOutcomeError("claim cite missing")
    if cite.get("lineage") != CLAIM_LINEAGE or cite.get("lineage_sha") != CLAIM_LINEAGE_SHA:
        raise FenceOutcomeError("claim cite must stay pep 1d0f380")
    labels = table.get("label_vocabulary")
    if list(labels) != ["covered", "not_applicable_by_design"]:
        raise FenceOutcomeError("label vocabulary must be covered and not_applicable_by_design")
    vocabulary = table.get("registered_outcome_vocabulary")
    if not isinstance(vocabulary, list) or not vocabulary:
        raise FenceOutcomeError("registered outcome vocabulary missing")
    vocab_ids = [item.get("id") for item in vocabulary if isinstance(item, Mapping)]
    if len(vocab_ids) != len(set(vocab_ids)) or any(not isinstance(item, str) for item in vocab_ids):
        raise FenceOutcomeError("registered outcome ids must be unique strings")
    rows = table.get("rows")
    if not isinstance(rows, list) or not rows:
        raise FenceOutcomeError("fence outcome rows missing")
    seen_vocab: list[str] = []
    lab_ids: list[str] = []
    base = root
    for row in rows:
        if not isinstance(row, Mapping):
            raise FenceOutcomeError("fence outcome row must be an object")
        label = row.get("label")
        if label not in LABELS:
            raise FenceOutcomeError(f"row {row.get('row_id')} label {label!r} is not allowed")
        reason = row.get("lab_reason_code")
        if reason is not None and reason not in LAB_REASON_CODES:
            raise FenceOutcomeError(f"unexpected reason code {reason}")
        vocab = row.get("vocabulary_id")
        if vocab is not None:
            if vocab not in vocab_ids:
                raise FenceOutcomeError(f"unknown vocabulary id {vocab}")
            seen_vocab.append(vocab)
        kind = row.get("kind")
        if kind == "lab_fence_fixture":
            source = row.get("source_id")
            if not isinstance(source, str) or not source:
                raise FenceOutcomeError("lab fence fixture needs a source_id")
            lab_ids.append(source)
            if row.get("repo") != PEP_REPO or row.get("git_sha") != PEP_SHA:
                raise FenceOutcomeError("lab fence fixture must cite the pep pin")
            path = row.get("path")
            if not isinstance(path, str) or not path.startswith(("eval/", "tests/")):
                raise FenceOutcomeError("lab fence fixture path must stay inside the pep tree")
            if ".." in Path(path).parts:
                raise FenceOutcomeError("lab fence fixture path must not climb")
            if base is not None and (base / path).exists():
                raise FenceOutcomeError(f"pep fixture must not be vendored: {path}")
        elif kind != "registered_outcome":
            raise FenceOutcomeError(f"unknown row kind {kind}")
    if len(seen_vocab) != len(set(seen_vocab)):
        raise FenceOutcomeError("each registered outcome is mapped once")
    missing = [item for item in vocab_ids if item not in seen_vocab]
    if missing:
        raise FenceOutcomeError(f"unmapped registered outcomes: {missing}")
    if len(lab_ids) != len(set(lab_ids)):
        raise FenceOutcomeError("lab fence fixture source ids must be unique")

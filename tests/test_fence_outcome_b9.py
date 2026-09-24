# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agent Control Lab contributors
"""B9 fence-outcome stub. Pattern cite only. Pep source is not vendored."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from joint_eval.fence_outcome import (
    LABELS,
    FenceOutcomeError,
    lab_fence_rows,
    load_fence_outcome,
    validate_fence_outcome,
)
from joint_eval.pins import PEP_SHA

ROOT = Path(__file__).resolve().parents[1]
TABLE_PATH = ROOT / "eval" / "measured_corpus" / "fence-outcome-b9.json"
NOTE_PATH = ROOT / "eval" / "measured_corpus" / "fence-outcome-b9.md"
INDEX_PATH = ROOT / "eval" / "measured_corpus" / "index.json"
FENCE_REASONS = frozenset(
    {"late_effect_fence", "admission_consumed", "kill_active", "suspend_active"}
)


def test_table_loads_and_every_lab_fence_fixture_is_labelled() -> None:
    table = load_fence_outcome(ROOT)
    rows = lab_fence_rows(table)
    assert rows
    labels = {row["label"] for row in rows}
    assert labels <= LABELS
    assert "covered" in labels
    assert "not_applicable_by_design" in labels
    for row in rows:
        assert row["label"] in {"covered", "not_applicable_by_design"}
        assert row["lab_reason_code"] in FENCE_REASONS
        assert row["git_sha"] == PEP_SHA
        assert not (ROOT / row["path"]).exists()
    by_id = {row["source_id"]: row for row in rows}
    assert set(by_id) == {
        "acl-pep-eval-late-effect-fence-001",
        "acl-pep-eval-kill-001",
        "acl-pep-eval-suspend-001",
        "pep-test-admission-consumed",
    }
    late = by_id["acl-pep-eval-late-effect-fence-001"]
    assert late["path"] == "eval/corpus/late_effect_fence/"
    assert late["lab_reason_code"] == "late_effect_fence"
    assert late["label"] == "covered"
    assert late["vocabulary_id"] == "root_cut_and_sink_fence"
    assert by_id["acl-pep-eval-kill-001"]["lab_reason_code"] == "kill_active"
    assert by_id["acl-pep-eval-kill-001"]["label"] == "not_applicable_by_design"
    assert by_id["pep-test-admission-consumed"]["lab_reason_code"] == "admission_consumed"
    assert by_id["pep-test-admission-consumed"]["path"] == "tests/test_late_effect_fence.py"
    assert by_id["acl-pep-eval-suspend-001"]["label"] == "not_applicable_by_design"
    assert table["paper_17_of_17_claimed"] is False
    assert table["conformance_claim"] is False
    assert table["slsa_claim"] is False
    assert table["kernel_fence_claim"] is False
    assert table["new_deny_class"] is False
    assert table["table_id"] is None
    assert table["residual_asr"] is None
    assert table["claim_cite"]["lineage"] == "1d0f380"
    assert table["pep_pin"] == PEP_SHA


def test_measured_corpus_fence_fixtures_are_in_the_stub() -> None:
    index = json.loads(INDEX_PATH.read_text(encoding="utf-8"))
    table = load_fence_outcome(ROOT)
    mapped = {row["source_id"] for row in lab_fence_rows(table)}
    found = False
    for row in index["rows"]:
        codes = set(row["taxonomy"].get("reason_codes") or [])
        if not codes & FENCE_REASONS:
            continue
        found = True
        for fixture in row["fixtures"]:
            if fixture["role"] != "pep_corpus":
                continue
            assert fixture["source_id"] in mapped
            assert fixture["git_sha"] == PEP_SHA
    assert found


def test_note_does_not_claim_the_paper_result() -> None:
    text = NOTE_PATH.read_text(encoding="utf-8")
    assert "does not claim the paper's 17/17" in text
    assert "matches 17/17" not in text
    assert "17/17 pass" not in text
    assert "1d0f380" in text
    assert "not_applicable_by_design" in text
    assert "covered" in text
    assert PEP_SHA in text


def test_unknown_label_is_rejected() -> None:
    table = copy.deepcopy(load_fence_outcome(ROOT))
    table["rows"][0]["label"] = "DENY"
    with pytest.raises(FenceOutcomeError, match="label"):
        validate_fence_outcome(table, root=ROOT)

# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agent Control Lab contributors
"""B7 hash is provisional. table_id and residual_asr stay null."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from joint_eval.b7_table_id import (
    ARTEFACT_ID,
    CLAIM_LINEAGE,
    CLAIM_LINEAGE_SHA,
    HISTORICAL_ARTEFACT_IDS,
    STATUS_SEPARATION,
    provisional_table_id,
)
from joint_eval.paired_runner import (
    CLAIM_LINEAGE as RUNNER_LINEAGE,
    CLAIM_LINEAGE_SHA as RUNNER_LINEAGE_SHA,
    PAIRED_SCHEMA_VERSION,
    format_summary,
    run_paired,
)
from joint_eval.pins import PEP_SHA, SUPPLY_GATE_SHA

ROOT = Path(__file__).resolve().parents[1]
NOTE = ROOT / "docs" / f"{ARTEFACT_ID}.md"


def test_frozen_note_hash_and_candidate_are_deterministic() -> None:
    raw = NOTE.read_bytes()
    assert ARTEFACT_ID.encode("utf-8") in raw
    text = raw.decode("utf-8")
    assert "Soft is not EngClear" in text
    assert "does not unlock funding" in text
    assert "1d0f380" in text
    assert CLAIM_LINEAGE_SHA in text
    assert PEP_SHA in text
    assert SUPPLY_GATE_SHA in text
    assert PAIRED_SCHEMA_VERSION in text
    assert "writing vault at runtime" in text
    markdown_hash = hashlib.sha256(raw).hexdigest()
    fields = provisional_table_id(root=ROOT, schema_version=PAIRED_SCHEMA_VERSION)
    assert fields["b7_artefact_id"] == ARTEFACT_ID
    assert fields["b7_prereg_hash"] == markdown_hash
    assert len(fields["b7_prereg_hash"]) == 64
    preimage = fields["table_id_candidate_preimage"]
    assert preimage["b7_markdown_sha256"] == markdown_hash
    assert preimage["schema_version"] == PAIRED_SCHEMA_VERSION
    assert preimage["pep_sha"] == PEP_SHA
    assert preimage["supply_gate_sha"] == SUPPLY_GATE_SHA
    assert preimage["claim_cite_lineage"] == CLAIM_LINEAGE == RUNNER_LINEAGE
    assert preimage["claim_cite_lineage_sha"] == CLAIM_LINEAGE_SHA == RUNNER_LINEAGE_SHA
    canonical = json.dumps(preimage, sort_keys=True, separators=(",", ":")).encode("utf-8")
    assert fields["table_id_candidate"] == hashlib.sha256(canonical).hexdigest()
    assert fields["table_id_candidate"] != fields["b7_prereg_hash"]
    assert "EngClear" in fields["status_separation"]
    assert fields["status_separation"] == STATUS_SEPARATION
    again = provisional_table_id(root=ROOT, schema_version=PAIRED_SCHEMA_VERSION)
    assert again == fields


def test_paired_document_keeps_table_id_and_residual_asr_null() -> None:
    document = run_paired(root=ROOT)
    fields = provisional_table_id(root=ROOT, schema_version=PAIRED_SCHEMA_VERSION)
    assert document["table_id"] is None
    assert document["residual_asr"] is None
    assert document["letters_asr"] is False
    assert document["cyber_c4_pending"] is True
    assert document["table_id_candidate"] == fields["table_id_candidate"]
    assert document["b7_prereg_hash"] == fields["b7_prereg_hash"]
    assert document["b7_artefact_id"] == ARTEFACT_ID
    assert document["claim_cite"]["lineage"] == "1d0f380"
    assert document["claim_cite"]["lineage_sha"] == CLAIM_LINEAGE_SHA
    summary = format_summary(document)
    assert "table_id: null (pending Cyber C4)" in summary
    assert document["table_id_candidate"] in summary
    assert document["b7_prereg_hash"] in summary
    assert "Soft is not EngClear" in summary
    assert "residual_asr: null" in summary


HISTORICAL_SEALS = {
    "ACL_JointEval_Preregistration_Limitations_B7_2026-09-23": (
        "580ba16a32a95e3340ec470cdc252406e285be704744d7eaa9821dbab32da187",
        b"| pep install pin | `ffd048a228dd2c8193418db6bebbab7cd339cd08` |",
    ),
    "ACL_JointEval_Preregistration_Limitations_B7v2_2026-10-05": (
        "3b6b70b798562937f465e52a85065edf96da5b319219893032d9e5b3bd72aaaa",
        b"| supply-gate install pin | `f99b41d98f14c1e2cd66b6549e98dbc97c181ce8` |",
    ),
}


def test_earlier_b7_seals_are_retained_byte_identical() -> None:
    """v3 supersedes v2, which superseded v1; both stay as historical seals."""
    assert set(HISTORICAL_ARTEFACT_IDS) == set(HISTORICAL_SEALS)
    current = NOTE.read_text(encoding="utf-8")
    for artefact_id, (sha256, pin_row) in HISTORICAL_SEALS.items():
        raw = (ROOT / "docs" / f"{artefact_id}.md").read_bytes()
        assert hashlib.sha256(raw).hexdigest() == sha256
        assert pin_row in raw
        assert artefact_id in current
    assert f"| supply-gate install pin | `{SUPPLY_GATE_SHA}` |" in current
    assert f"| pep install pin | `{PEP_SHA}` |" in current

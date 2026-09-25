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

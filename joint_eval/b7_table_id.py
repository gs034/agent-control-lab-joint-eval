# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agent Control Lab contributors
"""Provisional table id from the frozen B7 preregistration note.

The public paired document keeps ``table_id`` and ``residual_asr`` null.
``table_id_candidate`` is a content address Cyber can adopt later. This
module reads the in-tree markdown. It does not fetch a writing vault.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from joint_eval.loader import repo_root
from joint_eval.pins import PEP_SHA, SUPPLY_GATE_SHA

ARTEFACT_ID = "ACL_JointEval_Preregistration_Limitations_B7_2026-09-23"
RELATIVE_PATH = Path("docs") / f"{ARTEFACT_ID}.md"
CLAIM_LINEAGE = "1d0f380"
CLAIM_LINEAGE_SHA = "1d0f3809a4a16d4a6ac3524b287cf719f192e1f9"
STATUS_SEPARATION = (
    "Soft is not EngClear. EngClear is not a Cyber C4 table mint. "
    "This candidate does not unlock funding. "
    "table_id and residual_asr stay null. Claim cite stays pep 1d0f380."
)


class B7TableIdError(ValueError):
    """The frozen B7 note is missing or not the sealed artefact id."""


def b7_markdown_path(root: Path | None = None) -> Path:
    base = repo_root() if root is None else Path(root)
    return base / RELATIVE_PATH


def provisional_table_id(*, root: Path | None = None, schema_version: str) -> dict[str, Any]:
    """Hash the frozen note with the schema version and the pin set.

    ``b7_prereg_hash`` is the SHA-256 of the markdown bytes.
    ``table_id_candidate`` is the SHA-256 of the canonical preimage.
    Neither value is a minted ``table_id``.
    """
    if not isinstance(schema_version, str) or not schema_version:
        raise B7TableIdError("schema_version is required")
    path = b7_markdown_path(root)
    if not path.is_file():
        raise B7TableIdError(f"frozen B7 note missing: {path}")
    raw = path.read_bytes()
    if ARTEFACT_ID.encode("utf-8") not in raw:
        raise B7TableIdError("frozen B7 note does not name its artefact id")
    markdown_hash = hashlib.sha256(raw).hexdigest()
    preimage = {
        "artefact_id": ARTEFACT_ID,
        "b7_markdown_sha256": markdown_hash,
        "claim_cite_lineage": CLAIM_LINEAGE,
        "claim_cite_lineage_sha": CLAIM_LINEAGE_SHA,
        "pep_sha": PEP_SHA,
        "schema_version": schema_version,
        "supply_gate_sha": SUPPLY_GATE_SHA,
    }
    canonical = json.dumps(preimage, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return {
        "b7_artefact_id": ARTEFACT_ID,
        "b7_prereg_hash": markdown_hash,
        "table_id_candidate": hashlib.sha256(canonical).hexdigest(),
        "table_id_candidate_preimage": preimage,
        "status_separation": STATUS_SEPARATION,
    }

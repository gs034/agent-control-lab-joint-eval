# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agent Control Lab contributors
"""Documented Git SHA pins for the sibling Lab packages.

Install is PEP 508 direct URLs in pyproject.toml (git+https @ commit).
This harness does not vendor pep or supply-gate source trees.
"""

from __future__ import annotations

PEP_REPO = "https://github.com/gs034/agent-control-lab-pep"
PEP_SHA = "ffd048a228dd2c8193418db6bebbab7cd339cd08"
PEP_PACKAGE = "agent-control-lab-pep"

SUPPLY_GATE_REPO = "https://github.com/gs034/agent-control-lab-supply-gate"
# Install pin. Post–Option C supply-gate tip (B6 measured-corpus loader, PR #9). Not the claim cite.
SUPPLY_GATE_SHA = "f99b41d98f14c1e2cd66b6549e98dbc97c181ce8"
SUPPLY_GATE_PACKAGE = "agent-control-lab-supply-gate"


def pep_direct_url() -> str:
    return f"git+https://github.com/gs034/agent-control-lab-pep.git@{PEP_SHA}"


def supply_gate_direct_url() -> str:
    return (
        "git+https://github.com/gs034/agent-control-lab-supply-gate.git@"
        f"{SUPPLY_GATE_SHA}"
    )


def pin_document() -> dict[str, dict[str, str]]:
    return {
        "pep": {
            "package": PEP_PACKAGE,
            "repo": PEP_REPO,
            "sha": PEP_SHA,
            "direct_url": pep_direct_url(),
        },
        "supply_gate": {
            "package": SUPPLY_GATE_PACKAGE,
            "repo": SUPPLY_GATE_REPO,
            "sha": SUPPLY_GATE_SHA,
            "direct_url": supply_gate_direct_url(),
        },
    }

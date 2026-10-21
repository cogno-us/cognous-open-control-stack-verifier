"""Review scan 4: binding version members (D-V1), effective-grant members (D-V2)."""

from __future__ import annotations

import json
from typing import Any

import pytest

from cognous_verify import engine

from .helpers import REAL_RUNS

NAMES = {
    "run_record": "bounded-run-record.json",
    "proposal_export": "proposal.json",
    "manifest": "manifest.json",
    "destination_ledger": "destination.json",
}
DEFAULT_RUNS = ["default-applied"]
JOURNAL_RUNS = ["journal-applied", "journal-lost-ack", "journal-partial"]


def _docs(scenario: str) -> dict[str, Any]:
    return {r: json.loads((REAL_RUNS / scenario / n).read_text()) for r, n in NAMES.items()}


def _overall(docs: dict[str, Any], roles: tuple[str, ...] = tuple(NAMES)) -> str:
    return engine.evaluate(
        [engine.InputFile(r, NAMES[r], json.dumps(docs[r]).encode()) for r in roles]
    ).overall


def _first_binding(docs: dict[str, Any]) -> dict[str, Any]:
    for d in docs["run_record"]["decisions"]:
        if d["binding"]:
            b: dict[str, Any] = d["binding"]
            return b
    raise AssertionError("no authorized binding")


@pytest.mark.parametrize("scenario", DEFAULT_RUNS + JOURNAL_RUNS)
@pytest.mark.parametrize("member", ["role_mapping_version", "authority_context_version"])
def test_binding_version_members_must_match_kept_inputs(scenario: str, member: str) -> None:
    docs = _docs(scenario)
    assert _overall(docs) == "accept"
    b = _first_binding(docs)
    b[member] = b[member] + "x"
    assert _overall(docs) == "reject"
    assert _overall(docs, ("run_record",)) == "reject"


@pytest.mark.parametrize("scenario", JOURNAL_RUNS)
@pytest.mark.parametrize(
    ("member", "value"),
    [
        ("expected_effective_grant_digest", "sha256:" + "0" * 64),
        ("expected_effective_grant_digest", "x"),
        ("expected_effective_grant_digest", "sha256:" + "A" * 64),
        ("expected_effective_grant_digest", 7),
        ("effective_grant_derivation_version", "x"),
        ("effective_grant_derivation_version", "effective-grant/9.9"),
    ],
)
def test_effective_grant_members_are_well_formed(scenario: str, member: str, value: Any) -> None:
    docs = _docs(scenario)
    assert _overall(docs) == "accept"
    _first_binding(docs)["runtime_authority"][member] = value
    assert _overall(docs) == "reject"


@pytest.mark.parametrize("scenario", JOURNAL_RUNS)
def test_effective_grant_members_well_formed_pair_is_not_refused(scenario: str) -> None:
    docs = _docs(scenario)
    ra = _first_binding(docs)["runtime_authority"]
    ra["expected_effective_grant_digest"] = "sha256:" + "0" * 64
    ra["effective_grant_derivation_version"] = "effective-grant/0.1"
    assert _overall(docs) == "accept"

"""Shared test helpers. Everything is read with the verifier's own parser."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from cognous_verify import documents, wire
from cognous_verify.results import CheckResult

DATA = Path(__file__).parent / "data"
REAL_RUNS = DATA / "real-runs"
FIXTURES = DATA / "odes-fixtures"


def load(path: Path) -> Any:
    """Read with the verifier's own strict parser.

    A fixture whose only wire defect is an unpaired surrogate escape (ODES #93 text fixtures) is
    refused by that parser before any document rule runs; it is read with the standard parser
    instead so the document-level rules can be run on it too. ``test_wire_refuses_surrogate_fixtures``
    pins that the strict parser does refuse each of them.
    """
    try:
        return wire.parse(path.read_bytes())
    except wire.WireError as exc:
        if exc.code != "wire_lone_surrogate":
            raise
        return json.loads(path.read_bytes())


def real_run_names() -> list[str]:
    return sorted(p.name for p in REAL_RUNS.iterdir() if p.is_dir())


def real_record(name: str) -> dict[str, Any]:
    doc: dict[str, Any] = load(REAL_RUNS / name / "bounded-run-record.json")
    return doc


def fixture_paths(kind: str, cls: str) -> list[Path]:
    return sorted((FIXTURES / kind / cls).glob("*.json"))


def refuted_codes(results: list[CheckResult]) -> set[str]:
    return {f.code for r in results if r.verdict == "refuted" for f in r.findings}


# ODES names four rules by family in ``expected_refusal``; the verifier raises finer codes for the
# same rules. A fixture still has to be refused, and every code raised must belong to the family.
ODES_FAMILY_CODES: dict[str, frozenset[str]] = {
    "causal_order": frozenset(
        {
            "causal_order",
            "attempt_before_decision",
            "closeout_before_attempt",
            "reconciliation_before_attempt",
        }
    ),
    "dispatch_license": frozenset(
        {"dispatch_license", "dispatch_without_license", "effect_check_refusal_missing"}
    ),
    "reasons_minimum": frozenset({"reasons_minimum", "completion_reasons_minimum"}),
    "attempt_transition": frozenset({"attempt_transition", "attempt_transition_invalid"}),
}


def matches_expected_refusal(codes: set[str], expected: str) -> bool:
    """True when the verifier refused and its codes are exactly the fixture's code, or, for a
    family name, all inside that family."""
    family = ODES_FAMILY_CODES.get(expected)
    if family is None:
        return codes == {expected}
    return bool(codes) and codes <= family


def errors(results: list[CheckResult]) -> list[str]:
    return [r.check_id for r in results if r.error]


def verify(doc: Any) -> list[CheckResult]:
    return documents.verify_document(doc)

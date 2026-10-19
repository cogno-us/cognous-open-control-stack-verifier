"""Decision-facing output: verdict, tally and could-not-check reason, apart from diagnostic text.

The report contract text lists which members a decision may rest on and which are diagnostic
(``report.DECISION_FACING``, ``report.DIAGNOSTIC``). These tests show the split holds: rewording
only diagnostic text leaves the decision-facing projection unchanged, and where the verifier and the
vendored ODES fixtures overlap the projection agrees with the fixture's expectation.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest

from cognous_verify import engine, report
from cognous_verify.results import Finding

from .helpers import (
    fixture_paths,
    load,
    matches_expected_refusal,
    real_record,
    refuted_codes,
    verify,
)

FIXED = {"generated_at": "2026-10-18T00:00:00+00:00"}


def _evaluate(doc: Any) -> engine.Evaluation:
    raw = json.dumps(doc).encode()
    return engine.evaluate([engine.InputFile("run_record", "record.json", raw)])


def _damaged() -> dict[str, Any]:
    doc = copy.deepcopy(real_record("journal-applied"))
    doc["attempts"][0]["effect_id"] = "sha256:" + "0" * 64
    return doc


def test_the_projection_names_exactly_the_decision_facing_members() -> None:
    rep = report.build(_evaluate(real_record("journal-applied")), **FIXED)
    projection = report.decision_facing(rep)
    assert set(projection) == {"overall", "summary", "checks"}
    for member in projection["checks"].values():
        assert set(member) == set(report.DECISION_FACING)
        assert set(member["tally"]) == {"confirmed", "could_not_check", "refuted", "n"}


@pytest.mark.parametrize("doc", [real_record("journal-applied"), _damaged()])
def test_rewording_only_diagnostic_text_leaves_the_decision_facing_output_unchanged(
    doc: dict[str, Any],
) -> None:
    before = report.build(_evaluate(doc), **FIXED)
    ev = _evaluate(doc)
    reworded = 0
    for r in ev.results:
        r.findings = [Finding(f.code, f.path, f"reworded: {f.message[::-1]}") for f in r.findings]
        reworded += len(r.findings)
        r.notes = [f"other words: {n}" for n in r.notes]
    ev.notes = [f"other words: {n}" for n in ev.notes]
    after = report.build(ev, **FIXED)
    if reworded:
        assert before["report_id"] != after["report_id"]  # the identifier covers the text
    assert report.decision_facing(before) == report.decision_facing(after)
    assert before["checks"] != after["checks"] or not reworded


def test_a_damaged_record_changes_the_decision_facing_output() -> None:
    clean = report.decision_facing(report.build(_evaluate(real_record("journal-applied")), **FIXED))
    damaged = report.decision_facing(report.build(_evaluate(_damaged()), **FIXED))
    assert clean != damaged
    assert clean["overall"] != "reject" and damaged["overall"] == "reject"


CASES = [
    (kind, cls, path)
    for kind in ("journal", "lifecycle")
    for cls in ("valid", "invalid")
    for path in fixture_paths(kind, cls)
]


@pytest.mark.parametrize("kind,cls,path", CASES, ids=[f"{k}-{c}-{p.stem}" for k, c, p in CASES])
def test_where_verifier_and_oracle_overlap_the_decision_facing_output_agrees(
    kind: str, cls: str, path: Path
) -> None:
    """The ODES fixture states the oracle's outcome: valid is accepted, invalid is refused with one
    code. The verifier's decision-facing output must say the same: a refuted tally exactly where the
    oracle refuses, none where it accepts."""
    fixture = load(path)
    results = verify(fixture["document"])
    journal_rules = [r for r in results if not r.check_id.startswith("v2.profile.")]
    refuted = [r for r in journal_rules if r.verdict == "refuted"]
    tally = sum(r.tally()["refuted"] for r in refuted)
    if cls == "valid":
        assert not refuted
        assert tally == 0
    elif fixture.get("refused_by") == "operation-identity":
        assert not refuted
    else:
        assert refuted and tally >= 1
        assert matches_expected_refusal(refuted_codes(journal_rules), fixture["expected_refusal"])

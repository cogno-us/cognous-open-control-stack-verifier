"""Clean traces from the real control plane are accepted; named damage is refused."""

from __future__ import annotations

import copy
from typing import Any

import pytest

from cognous_verify import wire

from .helpers import REAL_RUNS, errors, real_record, real_run_names, refuted_codes, verify


def test_there_are_fourteen_real_runs() -> None:
    assert len(real_run_names()) == 14


@pytest.mark.parametrize("name", real_run_names())
def test_clean_real_run_is_not_refuted(name: str) -> None:
    results = verify(real_record(name))
    assert refuted_codes(results) == set()
    assert errors(results) == []
    assert results[0].check_id == "v1.structure" and results[0].verdict == "confirmed"
    assert any("raw producer record" in n for n in results[0].notes)


def test_a_hold_run_reports_what_it_could_not_check() -> None:
    results = verify(real_record("default-held"))
    skipped = {r.check_id: r.reason for r in results if r.verdict == "could_not_check"}
    assert skipped["v2.journal.attempts"] == "no_items_in_record"
    assert skipped["v2.lifecycle.journal_protocol"] == "no_journal_in_record"


# --- benign changes the pinned profile treats as equal must not be refused -----------------------


def _text(name: str) -> str:
    return (REAL_RUNS / name / "bounded-run-record.json").read_text(encoding="utf-8")


@pytest.mark.parametrize("name", ["journal-applied", "default-held", "journal-lost-ack-closeout"])
def test_benign_operators_are_accepted(name: str) -> None:
    doc = wire.parse(_text(name).encode())
    # key reorder (reversed) and compact whitespace
    reordered = _reverse_keys(doc)
    compact = wire.parse_text(_dump(reordered, indent=None))
    spaced = wire.parse_text(_dump(doc, indent=4))
    for variant in (compact, spaced):
        assert refuted_codes(verify(variant)) == set()
    # escaped non-ASCII is the same text after parsing
    escaped = _text(name).replace("urn:", "\\u0075rn:")
    assert refuted_codes(verify(wire.parse(escaped.encode()))) == set()


def _reverse_keys(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: _reverse_keys(value[k]) for k in reversed(list(value))}
    if isinstance(value, list):
        return [_reverse_keys(v) for v in value]
    return value


def _dump(value: Any, indent: int | None) -> str:
    # a tiny writer so the standard json module is not the reference for what "valid" looks like
    import json

    return json.dumps(value, indent=indent)


# --- a few direct damages (the category table is exercised in test_damage.py) ----------------


def test_flipped_decision_result_is_refused() -> None:
    doc = copy.deepcopy(real_record("default-held"))
    doc["decisions"][0]["result"] = "authorized"
    assert "decision_result_inconsistent" in refuted_codes(verify(doc))


def test_dropped_start_record_is_refused() -> None:
    doc = copy.deepcopy(real_record("default-applied"))
    del doc["attempts"][0]
    assert "missing_start_record" in refuted_codes(verify(doc))


def test_structure_refusal_stops_v2_with_a_reason() -> None:
    doc = copy.deepcopy(real_record("default-applied"))
    doc["surprise"] = 1
    results = verify(doc)
    assert results[0].verdict == "refuted"
    assert {r.reason for r in results[1:]} == {"structure_refuted"}

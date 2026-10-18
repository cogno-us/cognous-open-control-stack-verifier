"""v4.ledger.rows-agree-with-attempts: a ledger row needs an attempt, and not only a failed one."""

from __future__ import annotations

import copy
from typing import Any

import pytest

from cognous_verify import ledger
from cognous_verify.results import CONFIRMED, COULD_NOT_CHECK, REFUTED

from .helpers import REAL_RUNS, load, real_record, real_run_names

CHECK = "v4.ledger.rows-agree-with-attempts"


def _ledger(name: str) -> Any:
    return load(REAL_RUNS / name / "destination.json")


def _run(record: Any, led: Any) -> Any:
    return {r.check_id: r for r in ledger.run(record, led)}[CHECK]


def _donor_row() -> dict[str, Any]:
    (row,) = _ledger("journal-applied")["effects"].values()
    return copy.deepcopy(row)


@pytest.mark.parametrize("name", real_run_names())
def test_clean_real_runs_agree(name: str) -> None:
    result = _run(real_record(name), _ledger(name))
    # a run with no ledger rows has nothing to examine (reported as not applicable)
    assert result.verdict in {CONFIRMED, COULD_NOT_CHECK}, name


def _with_donor_row(name: str) -> tuple[Any, Any]:
    led = _ledger(name)
    assert led["effects"] == {}, "the run left no ledger row"
    row = _donor_row()
    led["effects"][row["effect_id"]] = row
    led["grant_effect_counts"][row["grant_id"]] = 1
    return real_record(name), led


def test_row_for_an_effect_refused_at_effect_time_is_refused() -> None:
    record, led = _with_donor_row("journal-effect-time-refusal")
    result = _run(record, led)
    assert result.verdict == REFUTED
    assert {f.code for f in result.findings} == {"ledger_row_without_attempt"}


def test_row_for_an_effect_whose_attempt_failed_definitively_is_refused() -> None:
    record, led = _with_donor_row("journal-failed")
    result = _run(record, led)
    assert result.verdict == REFUTED
    assert {f.code for f in result.findings} == {"ledger_row_after_definitive_failure"}


@pytest.mark.parametrize(
    "statuses,refused",
    [
        (["failed"], True),
        (["failed", "failed"], True),
        (["attempted"], False),
        (["unknown"], False),
        (["acknowledged"], False),
        (["partial"], False),
        (["failed", "unknown"], False),
    ],
)
def test_one_row_against_attempt_lifecycles(statuses: list[str], refused: bool) -> None:
    record = {
        "attempts": [
            {"attempt_id": f"a{i}", "effect_id": "e1", "status": status}
            for i, status in enumerate(statuses)
        ]
    }
    row = {"effect_id": "e1", "grant_id": "g"}
    result = ledger._rows_agree_with_attempts(
        record, {"effects": {"e1": row}, "grant_effect_counts": {"g": 1}}
    )
    assert (result.verdict == REFUTED) is refused


def test_a_lifecycle_is_judged_by_its_last_row() -> None:
    record = {
        "attempts": [
            {"attempt_id": "a", "effect_id": "e1", "status": "attempted"},
            {"attempt_id": "a", "effect_id": "e1", "status": "failed"},
        ]
    }
    row = {"effect_id": "e1", "grant_id": "g"}
    result = ledger._rows_agree_with_attempts(
        record, {"effects": {"e1": row}, "grant_effect_counts": {"g": 1}}
    )
    assert result.verdict == REFUTED

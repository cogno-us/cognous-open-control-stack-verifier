"""Smoke check on the verifier's own damage operators (not the qualification measurement)."""

from __future__ import annotations

import pytest

from . import damage


@pytest.fixture(scope="module")
def outcome() -> tuple[dict[str, damage.Tally], list[tuple[str, str, str]], list[str]]:
    return damage.run_all()


def test_every_clean_run_is_accepted(outcome: tuple[object, object, list[str]]) -> None:
    assert outcome[2] == []


def test_every_mismatch_is_a_known_limit(
    outcome: tuple[object, list[tuple[str, str, str]], object],
) -> None:
    unexplained = [(n, c) for n, c, _e in outcome[1] if (n, c) not in damage.KNOWN_MISSES]
    assert unexplained == []


def test_known_misses_still_occur(
    outcome: tuple[object, list[tuple[str, str, str]], object],
) -> None:
    seen = {(n, c) for n, c, _e in outcome[1]}
    assert set(damage.KNOWN_MISSES) <= seen


def test_every_category_was_exercised(
    outcome: tuple[dict[str, damage.Tally], object, object],
) -> None:
    table = outcome[0]
    for cat in (
        "W1",
        "W2",
        "W3",
        "W4",
        "W5",
        "B",
        "S1",
        "S2",
        "S3",
        "S4",
        "I1",
        "I2",
        "I3",
        "I4",
        "I5",
        "D1",
        "D2",
        "D3",
        "D4",
        "D5",
        "J1",
        "J2",
        "T1",
        "A1",
        "A2",
        "R1",
        "R2",
        "R3",
        "R4",
        "R5",
        "X1",
        "F",
    ):
        assert table[cat].n_eff > 0, cat
    # categories whose preconditions never occur in the clean runs are reported as such
    assert table["J3"].n_eff == 0 and table["R6"].n_eff == 0


def test_mutants_that_should_parse_still_parse() -> None:
    cases = damage.load_corpus()
    benign = [o for o in damage.OPERATORS if o.category == "B"]
    for o in benign:
        for c in cases:
            m = o.fn(c, cases)
            assert m is not None and damage.wire_clean(m)

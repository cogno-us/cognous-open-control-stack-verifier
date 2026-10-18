"""Differential run against the ODES fixtures (design stage S2, acceptance c).

The fixtures are regression seeds written for rules the ODES reference validators already
implement. They show the verifier has not diverged from those validators; they are not a
measure of detection (the design keeps the two apart).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from .helpers import errors, fixture_paths, load, refuted_codes, verify

CASES = [
    (kind, cls, path)
    for kind in ("journal", "lifecycle")
    for cls in ("valid", "invalid")
    for path in fixture_paths(kind, cls)
]


def test_fixture_counts_match_the_contract_readmes() -> None:
    counts = {
        (k, c): len(fixture_paths(k, c))
        for k in ("journal", "lifecycle")
        for c in ("valid", "invalid")
    }
    assert counts == {
        ("journal", "valid"): 13,
        ("journal", "invalid"): 67,
        ("lifecycle", "valid"): 20,
        ("lifecycle", "invalid"): 31,
    }


@pytest.mark.parametrize("kind,cls,path", CASES, ids=[f"{k}-{c}-{p.stem}" for k, c, p in CASES])
def test_verifier_agrees_with_the_fixture(kind: str, cls: str, path: Path) -> None:
    fixture = load(path)
    results = verify(fixture["document"])
    assert errors(results) == []
    if cls == "valid":
        assert refuted_codes(results) == set(), fixture["fixture_id"]
    else:
        assert refuted_codes(results) == {fixture["expected_refusal"]}, fixture["fixture_id"]

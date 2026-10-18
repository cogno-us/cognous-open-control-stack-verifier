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


# A journal-valid fixture that the ODES operation-identity contract itself refuses: the capture
# rebound the ledger row to another grant after the first authorized decision (the producer's own
# collision test does that), so the ledger no longer matches that decision. The journal contract
# cannot see it; tier V2 `v2.profile.operation-identity` does, with the code the ODES sidecar
# fixture `decision-operation-binding-mismatch` (the same record) carries. Pinned both ways.
SIDECAR_REFUSED_VALID = {"profile-op-grant-mismatch-held": {"decision_operation_binding_mismatch"}}


# Profile-on invalid fixtures: the journal rules refuse them with the fixture's code exactly as
# before (the check below leaves out the sidecar checks); the sidecar checks (`v2.profile.*`) add
# corroborating codes for the same defect, pinned here so a change shows.
SIDECAR_EXTRA = {
    "profile-expired-event-without-deadline": {
        "check_event_clock_drift",
        "expired_refusal_deadline_mismatch",
    },
    "profile-lease-hold-with-another-reason": {"lease_unavailable_with_other_reasons"},
    "profile-overdue-event-without-an-open-check": {
        "check_opening_missing",
        "recovery_overdue_without_event",
    },
    "profile-overdue-event-without-deadline": {"check_event_clock_drift"},
    "profile-refusal-deadline-without-offset": {"expired_refusal_deadline_mismatch"},
    "profile-retry-after-an-ordinary-failure": {"expired_without_failed_attempt"},
    "profile-retry-without-the-expiry-refusal": {"expired_refusal_deadline_mismatch"},
}


def test_fixture_counts_match_the_contract_readmes() -> None:
    counts = {
        (k, c): len(fixture_paths(k, c))
        for k in ("journal", "lifecycle")
        for c in ("valid", "invalid")
    }
    assert counts == {
        ("journal", "valid"): 49,  # 13 default and 36 profile-on (ODES e38aace6)
        ("journal", "invalid"): 86,  # 67 default and 19 profile-on
        ("lifecycle", "valid"): 20,
        ("lifecycle", "invalid"): 31,
    }


@pytest.mark.parametrize("kind,cls,path", CASES, ids=[f"{k}-{c}-{p.stem}" for k, c, p in CASES])
def test_verifier_agrees_with_the_fixture(kind: str, cls: str, path: Path) -> None:
    fixture = load(path)
    results = verify(fixture["document"])
    assert errors(results) == []
    journal_rules = [r for r in results if not r.check_id.startswith("v2.profile.")]
    sidecar = refuted_codes([r for r in results if r.check_id.startswith("v2.profile.")])
    if cls == "valid":
        assert refuted_codes(journal_rules) == set(), fixture["fixture_id"]
        assert sidecar == SIDECAR_REFUSED_VALID.get(fixture["fixture_id"], set())
    else:
        assert refuted_codes(journal_rules) == {fixture["expected_refusal"]}, fixture["fixture_id"]
        assert sidecar == SIDECAR_EXTRA.get(fixture["fixture_id"], set()), fixture["fixture_id"]

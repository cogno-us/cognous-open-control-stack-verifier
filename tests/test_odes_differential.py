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


# An invalid fixture marked `refused_by: "operation-identity"` (ODES 0a37180f) is a derived tamper
# of a real run: the journal contract cannot see it, only the operation-identity sidecar can. The
# journal rules accept it; tier V2 `v2.profile.operation-identity` refuses it with the fixture's
# `expected_refusal`.
SIDECAR_ONLY_REFUSED = {"profile-op-grant-mismatch-held": "decision_operation_binding_mismatch"}


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


# Valid ODES fixtures whose vendored copy (0663d5a2) was completed upstream afterwards (ODES
# 01aa9fca, decision 39): the copy lacks the reasons its unreadable grant read implies, so the
# verifier refuses it under the full ``reasons_minimum`` table. The pin round replaces the copy;
# tests/test_reasons_table.py holds the completed record and shows it accepted.
STALE_VENDORED_VALID = {"reasons-0-2-label-with-a-0-2-code": {"completion_reasons_minimum"}}


def test_fixture_counts_match_the_contract_readmes() -> None:
    counts = {
        (k, c): len(fixture_paths(k, c))
        for k in ("journal", "lifecycle")
        for c in ("valid", "invalid")
    }
    assert counts == {
        # ODES 0663d5a2: 13 default, 38 profile-on (3 terminal-revocation, #94) and 2 reasons-*
        ("journal", "valid"): 53,
        # 72 default (67 + 4 input-hardening, #93, + `time-seven-fraction-digits`, #96), 21 profile-on (1 terminal-revocation) and 2 reasons-*
        ("journal", "invalid"): 95,
        ("lifecycle", "valid"): 20,
        ("lifecycle", "invalid"): 33,  # 31 + 2 input-hardening
    }


@pytest.mark.parametrize("kind,cls,path", CASES, ids=[f"{k}-{c}-{p.stem}" for k, c, p in CASES])
def test_verifier_agrees_with_the_fixture(kind: str, cls: str, path: Path) -> None:
    fixture = load(path)
    results = verify(fixture["document"])
    assert errors(results) == []
    journal_rules = [r for r in results if not r.check_id.startswith("v2.profile.")]
    sidecar = refuted_codes([r for r in results if r.check_id.startswith("v2.profile.")])
    if cls == "valid":
        stale = STALE_VENDORED_VALID.get(fixture["fixture_id"], set())
        assert refuted_codes(journal_rules) == stale, fixture["fixture_id"]
        assert sidecar == set()
    elif fixture.get("refused_by") == "operation-identity":
        # refused by the sidecar validator only: journal rules accept, the sidecar check refuses
        assert fixture["fixture_id"] in SIDECAR_ONLY_REFUSED
        assert fixture["expected_refusal"] == SIDECAR_ONLY_REFUSED[fixture["fixture_id"]]
        assert refuted_codes(journal_rules) == set(), fixture["fixture_id"]
        assert sidecar == {fixture["expected_refusal"]}, fixture["fixture_id"]
    else:
        assert "refused_by" not in fixture
        assert refuted_codes(journal_rules) == {fixture["expected_refusal"]}, fixture["fixture_id"]
        assert sidecar == SIDECAR_EXTRA.get(fixture["fixture_id"], set()), fixture["fixture_id"]

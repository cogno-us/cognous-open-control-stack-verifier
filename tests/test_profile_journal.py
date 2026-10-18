"""Opt-in profile records (operation-identity, rule-revision, freshness) in the journal rules.

ODES e38aace6 (journal contract draft revision 2) declares the profile members as optional and
ships (at 0663d5a2) 38 valid and 21 invalid ``profile-*`` fixtures from real profile-on control-plane runs. The
verifier accepts the valid ones and refuses each invalid one with the fixture's code
(``test_odes_differential``). Here: each relaxation applies only when the profile member is
present and has negative tests, the default path is pinned against its verdicts before the change,
and the member table is pinned against the vendored schema.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest

from cognous_verify import documents, profile
from cognous_verify.results import CheckResult

from .helpers import DATA, FIXTURES, errors, fixture_paths, load, refuted_codes, verify

PROFILE_VALID = [p for p in fixture_paths("journal", "valid") if p.stem.startswith("profile-")]
PROFILE_INVALID = [p for p in fixture_paths("journal", "invalid") if p.stem.startswith("profile-")]
SCHEMA = json.loads(
    (
        Path(__file__).parents[1] / "src/cognous_verify/data/control-plane-journal.schema.json"
    ).read_text()
)


def doc_of(name: str) -> dict[str, Any]:
    doc: dict[str, Any] = load(FIXTURES / "journal" / "valid" / f"{name}.json")["document"]
    return copy.deepcopy(doc)


def codes(doc: dict[str, Any]) -> set[str]:
    """Codes of the journal rules (the sidecar checks, `v2.profile.*`, are tested in test_sidecar)."""
    results = [r for r in verify(doc) if not r.check_id.startswith("v2.profile.")]
    assert errors(results) == []
    return refuted_codes(results)


def test_profile_fixture_counts() -> None:
    assert (len(PROFILE_VALID), len(PROFILE_INVALID)) == (
        38,
        21,
    )  # ODES 0663d5a2: three valid and one invalid terminal-revocation fixture added (#94)


@pytest.mark.parametrize("path", PROFILE_VALID, ids=[p.stem for p in PROFILE_VALID])
def test_every_valid_profile_record_is_not_refuted(path: Path) -> None:
    results: list[CheckResult] = verify(load(path)["document"])
    assert errors(results) == []
    journal_rules = [r for r in results if not r.check_id.startswith("v2.profile.")]
    assert refuted_codes(journal_rules) == set(), path.stem
    assert all(r.verdict != "refuted" for r in journal_rules)


def test_member_table_matches_the_vendored_schema() -> None:
    defs = {
        "decisions": "decision",
        "attempts": "control_plane_attempt",
        "refusals": "refusal",
        "resolution_checks": "resolution_check",
        "check_events": "journal_event",
    }
    for section, name in defs.items():
        props = SCHEMA["$defs"][name]["properties"]
        exclusive = {
            m
            for m, v in props.items()
            if "freshness/0.1" in v.get("description", "")
            and "operation-identity" not in v["description"]
        }
        assert exclusive == set(profile.FRESHNESS_MEMBERS[section]), section
    listed = {
        m for m, v in SCHEMA["properties"].items() if "freshness/0.1" in v.get("description", "")
    }
    assert listed == set(profile.FRESHNESS_LISTS)
    assert set(profile.PROFILE_PHASES) <= set(
        SCHEMA["$defs"]["journal_event"]["properties"]["phase"]["enum"]
    )
    assert (
        profile.PROFILE_READ_STATE
        in SCHEMA["$defs"]["resolution_input"]["properties"]["read_state"]["enum"]
    )


# ----------------------------------------------------------------------------- default path


def test_default_path_verdicts_are_the_ones_before_the_profile_change() -> None:
    """Every check (verdict, codes, denominators, reason) of every default ODES fixture and every
    clean real, orchestrator and witnessed run, as produced by the verifier at adb8927."""
    expected = json.loads((DATA / "default-path-verdicts.json").read_text())
    got: dict[str, Any] = {}
    for rel in expected:
        doc = load(DATA / rel)
        if rel.startswith("odes-fixtures/"):
            doc = doc["document"]
        got[rel] = [
            [
                x.check_id,
                x.verdict,
                sorted({f.code for f in x.findings}),
                x.checked,
                x.total,
                x.reason,
            ]
            for x in documents.verify_document(doc)
        ]
    assert got == expected
    assert len(expected) == 156


# ----------------------------------------------------------------------------- second attempt


def _expired_retry() -> dict[str, Any]:
    return doc_of("profile-expired-then-retry-dispatches")


def test_expired_attempt_is_excused_by_one_refusal_with_a_deadline() -> None:
    assert codes(_expired_retry()) == set()


def test_without_the_deadline_member_two_starts_are_refused() -> None:
    doc = _expired_retry()
    for r in doc["refusals"]:
        r.pop("deadline", None)
    assert "second_attempt_for_effect" in codes(doc)


def test_another_failure_reason_is_not_excused() -> None:
    doc = _expired_retry()
    for a in doc["attempts"]:
        if a["status"] == "failed":
            a["error"] = "destination_rejected"
    assert "second_attempt_for_effect" in codes(doc)


def test_one_refusal_excuses_one_attempt() -> None:
    doc = _expired_retry()
    extra = [copy.deepcopy(a) for a in doc["attempts"][:2]]
    for a in extra:
        a["attempt_id"] = "syn-attempt-extra"
    doc["attempts"] = [*doc["attempts"][:2], *extra, *doc["attempts"][2:]]
    assert "second_attempt_for_effect" in codes(doc)


def test_the_same_defect_in_a_record_with_no_profile_member_is_refused() -> None:
    doc = _expired_retry()
    for section in ("decisions", "attempts", "refusals", "resolution_checks", "check_events"):
        for row in doc[section]:
            for m in profile.FRESHNESS_MEMBERS[section]:
                row.pop(m, None)
    assert "second_attempt_for_effect" in codes(doc)


def test_a_profile_record_with_an_unrelated_defect_is_still_refused() -> None:
    doc = _expired_retry()
    doc["decisions"][0]["effect_id"] = "sha256:" + "0" * 64
    assert "invalid_effect_identity" in codes(doc)
    doc = _expired_retry()
    doc["decisions"][0]["result"] = "hold"
    assert "decision_result_inconsistent" in codes(doc)


# ----------------------------------------------------------------------------- observation clock


def _decoupled() -> dict[str, Any]:
    return doc_of("profile-observation-clock-decoupled")


def test_decoupled_observation_is_judged_against_the_later_clock() -> None:
    assert codes(_decoupled()) == set()


def test_observation_beyond_the_later_clock_is_still_future() -> None:
    doc = _decoupled()
    doc["reconciliations"][0]["observation"]["observed_at"] = "2026-10-05T19:30:00+00:00"
    assert "observation_time_future" in codes(doc)


def test_without_a_freshness_member_on_the_effect_the_evaluation_time_is_the_reference() -> None:
    doc = _decoupled()
    for section in ("decisions", "attempts", "refusals"):
        for row in doc[section]:
            for m in profile.FRESHNESS_MEMBERS[section]:
                row.pop(m, None)
    assert "observation_time_future" in codes(doc)


def test_a_freshness_member_on_another_effect_does_not_relax_this_one() -> None:
    doc = _decoupled()
    for section in ("decisions", "attempts", "refusals"):
        for row in doc[section]:
            for m in profile.FRESHNESS_MEMBERS[section]:
                row.pop(m, None)
    other = copy.deepcopy(doc["decisions"][0])
    other.update(effect_id="sha256:" + "1" * 64, evaluated_at="2026-10-05T19:00:00+00:00")
    assert profile.freshness_effects({**doc, "decisions": [other]}) == {other["effect_id"]}
    assert "observation_time_future" in codes(doc)


def test_staleness_stays_relative_to_the_evaluation() -> None:
    doc = _decoupled()
    doc["reconciliations"][0]["observation"]["observed_at"] = "2026-09-05T19:00:00+00:00"
    assert "observation_stale" in codes(doc)


# ----------------------------------------------------------------------------- lease hold


def test_a_lone_lease_hold_with_the_profile_clock_needs_no_journal() -> None:
    assert codes(doc_of("profile-lease-unavailable-holds")) == set()


def test_a_lease_hold_with_another_reason_or_without_the_clock_needs_a_journal() -> None:
    doc = doc_of("profile-lease-unavailable-holds")
    doc["decisions"][0]["reasons"] = ["check_lease_unavailable", "grant_revoked"]
    assert "journal_missing" in codes(doc)
    doc = doc_of("profile-lease-unavailable-holds")
    doc["decisions"][0].pop("evaluated_at")
    assert "journal_missing" in codes(doc)


# ----------------------------------------------------------------------------- phases and reads


def test_profile_phase_needs_the_deadline_and_an_opening() -> None:
    doc = doc_of("profile-expired-before-dispatch")
    event = next(e for e in doc["check_events"] if e["phase"] == "expired")
    event.pop("deadline")
    assert codes(doc) == {"profile_value_without_member"}
    doc = doc_of("profile-expired-before-dispatch")
    event = next(e for e in doc["check_events"] if e["phase"] == "expired")
    event["check_id"] = "never-opened"
    assert codes(doc) == {"journal_protocol"}


def test_a_default_record_gains_no_profile_group() -> None:
    results = verify(doc_of("profile-lease-unavailable-holds"))
    assert not any(r.check_id == "v2.journal.profile" for r in results)
    default = load(fixture_paths("journal", "valid")[0])["document"]
    assert not any(r.check_id == "v2.journal.profile" for r in verify(default))
    assert any(
        r.check_id == "v2.journal.profile"
        for r in verify(doc_of("profile-expired-before-dispatch"))
    )


def test_profile_times_need_an_offset() -> None:
    doc = doc_of("profile-expired-before-dispatch")
    doc["refusals"][0]["deadline"] = "2026-10-05T19:01:00"
    assert "timestamp_invalid" in codes(doc)

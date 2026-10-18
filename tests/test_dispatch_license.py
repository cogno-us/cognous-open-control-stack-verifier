"""Dispatch licence, completion reasons and the closed set of post-completion codes.

Every damaged record is built from a producer record (a real run or a valid fixture) by one
change; every valid control must still be accepted.

* ``dispatch_license``: a record holds no more attempt lifecycles than it holds passing
  effect-stage checks that no refusal used. With a journal the check is bound to its decision
  through the journal events, and an effect-stage check that carries reasons has exactly one
  refusal for its decision and no attempt.
* ``reasons_minimum``: a completion with no reasons over inputs that show a mandatory read
  missing is refused.
* ``reasons_match``: a completed journal check binds to a resolution check whose reasons are the
  completion's reasons plus, at most, codes the control plane appends after the journal row.
"""

from __future__ import annotations

import copy
from typing import Any

import pytest

from cognous_verify import data
from cognous_verify.results import CONFIRMED, COULD_NOT_CHECK

from .helpers import fixture_paths, load, real_record, refuted_codes, verify

BINDINGS = "v2.journal.check_bindings"


def _fixture(stem: str) -> dict[str, Any]:
    path = next(p for p in fixture_paths("journal", "valid") if p.stem == stem)
    doc: dict[str, Any] = copy.deepcopy(load(path)["document"])
    return doc


def _codes(doc: Any) -> set[str]:
    return refuted_codes(verify(doc))


def _add_lifecycle(doc: dict[str, Any], decision: dict[str, Any], suffix: str) -> None:
    """Append an attempted -> acknowledged lifecycle for ``decision`` (as the control plane writes it)."""
    start = {
        "attempt_id": f"added-attempt-{suffix}",
        "effect_id": decision["effect_id"],
        "decision_id": decision["decision_id"],
        "started_at": decision["decided_at"],
        "time_source": decision["time_source"],
        "status": "attempted",
        "acknowledgement": {},
        "error": None,
    }
    done = {**start, "status": "acknowledged", "acknowledgement": {"duplicate": False}}
    doc["attempts"].extend([start, done])


# ---------------------------------------------------------------- dispatch licence


def test_journal_refusal_deleted_and_an_attempt_added_is_refused() -> None:
    doc = _fixture("effect-time-refusal")
    assert doc["refusals"] and not doc["attempts"]
    decision = doc["decisions"][0]
    doc["refusals"].clear()
    _add_lifecycle(doc, decision, "1")
    codes = _codes(doc)
    assert "effect_check_refusal_missing" in codes or "dispatch_without_license" in codes


def test_journal_attempt_added_beside_a_kept_refusal_is_refused() -> None:
    doc = _fixture("effect-time-refusal")
    _add_lifecycle(doc, doc["decisions"][0], "1")
    assert "dispatch_without_license" in _codes(doc)


def test_default_path_attempt_without_any_effect_check_is_refused() -> None:
    doc = copy.deepcopy(real_record("default-applied"))
    doc["resolution_checks"] = [c for c in doc["resolution_checks"] if c["stage"] != "effect"]
    assert "dispatch_without_license" in _codes(doc)


def test_default_path_second_lifecycle_for_one_effect_is_still_refused() -> None:
    """The per-effect rule already refuses it; the licence rule counts across effects."""
    doc = copy.deepcopy(real_record("default-applied"))
    twin = [dict(a, attempt_id="second-lifecycle") for a in doc["attempts"]]
    doc["attempts"].extend(twin)
    assert "second_attempt_for_effect" in _codes(doc)


@pytest.mark.parametrize(
    "stem",
    [
        "reconciled-existing-single-row",
        "profile-op-worker-self-renewal-then-unrecorded-hold",
        "profile-expired-then-retry-dispatches",
        "profile-all-profiles-expired-before-dispatch",
        "profile-op-duplicate-submission-reconciled-existing",
        "profile-terminal-revocation-suspension-stays-reversible",
        "lost-ack-unknown-then-closeout",
    ],
)
def test_valid_producer_records_keep_their_licence(stem: str) -> None:
    doc = _fixture(stem)
    result = next(r for r in verify(doc) if r.check_id == BINDINGS)
    assert result.verdict in {CONFIRMED, COULD_NOT_CHECK}
    assert _codes(doc) == set()


# ---------------------------------------------------------------- reasons_minimum


def test_blank_check_reasons_over_a_missing_read_are_refused() -> None:
    doc = _fixture("effect-time-refusal")
    for check in doc["resolution_checks"]:
        if check["stage"] == "effect":
            check["reasons"] = []
    for event in doc["check_events"]:
        if event["stage"] == "effect" and event["phase"] == "completed":
            event["reasons"] = []
    doc["refusals"].clear()
    _add_lifecycle(doc, doc["decisions"][0], "1")
    assert "completion_reasons_minimum" in _codes(doc)


def test_blank_completion_over_a_missing_read_is_refused_even_with_refusal_kept() -> None:
    """The check row still lists the reasons; the completion's own floor is checked first."""
    doc = _fixture("effect-time-refusal")
    for event in doc["check_events"]:
        if event["stage"] == "effect" and event["phase"] == "completed":
            event["reasons"] = []
    assert "completion_reasons_minimum" in _codes(doc)


def test_blank_check_row_over_a_missing_read_is_refused_with_its_completion() -> None:
    doc = _fixture("effect-time-refusal")
    for check in doc["resolution_checks"]:
        if check["stage"] == "effect":
            check["reasons"] = []
    for event in doc["check_events"]:
        if event["stage"] == "effect" and event["phase"] == "completed":
            event["reasons"] = []
    assert "completion_reasons_minimum" in _codes(doc)


def test_a_cached_positive_after_an_unreadable_read_is_not_a_missing_read() -> None:
    """An unreadable grant read followed by a readable one (the cached positive) needs no reason."""
    doc = _fixture("normal-attempted-acknowledged-applied")
    event = next(
        e
        for e in doc["check_events"]
        if e["phase"] == "input" and e["stage"] == "effect" and e["input"]["input_type"] == "grant"
    )
    unreadable = copy.deepcopy(event)
    unreadable["input"]["missing"] = True
    unreadable["input"]["read_state"] = "unreadable"
    unreadable["input"]["record_commitment"] = None
    unreadable["input"]["observed"] = {}
    event["input"]["read_state"] = "cached_positive"  # as the producer writes the later read
    doc["check_events"].insert(doc["check_events"].index(event), unreadable)
    assert "completion_reasons_minimum" not in _codes(doc)


# ---------------------------------------------------------------- reasons_match


def test_empty_completion_cannot_bind_to_a_refusing_check() -> None:
    doc = _fixture("profile-terminal-revocation-refused-after-recorded-revocation")
    emptied = 0
    for event in doc["check_events"]:
        if event["phase"] == "completed" and event["reasons"]:
            event["reasons"] = []
            emptied += 1
    assert emptied
    assert "journal_unbound_completion" in _codes(doc)


def test_completion_missing_a_non_gate_reason_is_refused() -> None:
    doc = _fixture("profile-terminal-revocation-refused-after-recorded-revocation")
    for event in doc["check_events"]:
        if event["phase"] == "completed" and len(event["reasons"]) >= 1:
            event["reasons"] = event["reasons"][:-1]
            break
    # a single-reason completion is emptied above; either way the row holds a non-gate reason the
    # completion does not
    assert "journal_unbound_completion" in _codes(doc)


def test_a_strict_superset_of_gate_codes_is_accepted() -> None:
    """The row holds codes the control plane appends after the journal row: accepted."""
    doc = _fixture("profile-op-worker-self-renewal-then-unrecorded-hold")
    gate = next(iter(data.post_journal_gate_codes()))
    decision = next(d for d in doc["decisions"] if d["reasons"])
    check = next(
        c
        for c in doc["resolution_checks"]
        if c["stage"] == "decision" and sorted(c["reasons"]) == sorted(decision["reasons"])
    )
    assert decision["reasons"]
    extra = sorted({*decision["reasons"], gate})
    decision["reasons"] = extra
    check["reasons"] = extra
    assert "journal_unbound_completion" not in _codes(doc)


def test_a_row_holding_a_code_outside_the_gate_set_is_refused() -> None:
    doc = _fixture("profile-op-worker-self-renewal-then-unrecorded-hold")
    decision = next(d for d in doc["decisions"] if d["reasons"])
    check = next(
        c
        for c in doc["resolution_checks"]
        if c["stage"] == "decision" and sorted(c["reasons"]) == sorted(decision["reasons"])
    )
    extra = sorted({*decision["reasons"], "grant_revoked"})
    assert "grant_revoked" not in data.post_journal_gate_codes()
    decision["reasons"] = extra
    check["reasons"] = extra
    assert "journal_unbound_completion" in _codes(doc)


def test_the_gate_set_is_closed_and_registered() -> None:
    codes = data.post_journal_gate_codes()
    registry = data.registry_codes("runtime-authority-reasons/0.2")
    assert codes and codes <= registry
    assert "operation_renewal_unrecorded" in codes


def test_the_gate_set_digest_is_recorded_in_the_provenance_file() -> None:
    assert data.provenance_problems() == []
    files = {e["file"]: e for e in data.provenance()["files"]}
    entry = files["post-journal-gate-codes.json"]
    assert entry["sha256"].startswith("sha256:")
    assert entry["source_repo"] == "cogno-us/open-decision-evidence-standard"
    assert entry["source_revision"] == "01aa9fca0537830735fefc7c3790fdc1a36913ae"
    import hashlib

    joined = "\n".join(sorted(data.post_journal_gate_codes())).encode()
    assert entry["codes_sha256"] == "sha256:" + hashlib.sha256(joined).hexdigest()

"""Binding members, the ledger ceiling and causal order.

* ``binding_members``: ``requirement_id``, ``policy_versions``, ``role_mapping_digest``,
  ``authority_context_status`` and ``effective_max_effects`` are compared with what the decision
  captured (its own resolution inputs, the proposal export and the manifest).
* ``ledger_ceiling``: a grant's effect count may not exceed the largest ``effective_max_effects``
  among the grant's authorized decisions; every contributing ceiling is validated first.
* ``causal_order``: an attempt does not start before its decision, a closeout does not precede its
  attempt, each in its own clock domain.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest

from cognous_verify import engine, ledger
from cognous_verify.results import CheckResult

from .helpers import DATA, REAL_RUNS, fixture_paths, load, real_record, refuted_codes, verify

RUNS = DATA / "orchestrator-runs"
ADAPTER = ["adapter-applied", "adapter-lost-ack-then-land"]


def _files(
    record: Any,
    *,
    proposal: Path | None = None,
    manifest: Path | None = None,
    ledger_doc: Any | None = None,
) -> list[engine.InputFile]:
    def raw(value: Any) -> bytes:
        return json.dumps(value).encode()

    files = [engine.InputFile("run_record", "record.json", raw(record))]
    if proposal is not None:
        files.append(engine.InputFile("proposal_export", "proposal.json", proposal.read_bytes()))
    if manifest is not None:
        files.append(engine.InputFile("manifest", "manifest.json", manifest.read_bytes()))
    if ledger_doc is not None:
        files.append(engine.InputFile("destination_ledger", "ledger.json", raw(ledger_doc)))
    return files


def _refuted(results: list[CheckResult]) -> dict[str, set[str]]:
    return {r.check_id: {f.code for f in r.findings} for r in results if r.verdict == "refuted"}


def _codes(doc: Any) -> set[str]:
    return refuted_codes(verify(doc))


def _decision(doc: dict[str, Any]) -> dict[str, Any]:
    return next(d for d in doc["decisions"] if d["result"] == "authorized")


# ---------------------------------------------------------------- binding_members (inputs)


@pytest.mark.parametrize("name", ["journal-applied", "default-applied"])
def test_clean_run_agrees_with_its_captured_inputs(name: str) -> None:
    assert _codes(real_record(name)) == set()


def _mutate_binding(name: str, member: str, value: Any) -> dict[str, Any]:
    doc = copy.deepcopy(real_record(name))
    _decision(doc)["binding"][member] = value
    return doc


@pytest.mark.parametrize("name", ["journal-applied", "default-applied"])
@pytest.mark.parametrize(
    "member,value",
    [
        ("policy_versions", [{"ref": "urn:cognous:policy:refund-policy", "version": "9.9"}]),
        ("policy_versions", []),
        ("role_mapping_digest", "sha256:" + "0" * 64),
        ("authority_context_status", "interface_ratified"),
    ],
)
def test_binding_member_differing_from_the_captured_input_is_refused(
    name: str, member: str, value: Any
) -> None:
    doc = _mutate_binding(name, member, value)
    # the effect identity commits proposal, grant and revision only: no other rule refuses this
    assert "binding_member_mismatch" in _codes(doc)


def test_binding_member_check_is_silent_when_the_input_was_not_captured() -> None:
    """A trimmed record (manifest and grant only) leaves nothing to compare: not a refusal."""
    path = next(
        p
        for p in fixture_paths("journal", "valid")
        if p.stem == "normal-attempted-acknowledged-applied"
    )
    doc = copy.deepcopy(load(path)["document"])
    _decision(doc)["binding"]["policy_versions"] = [{"ref": "x", "version": "2"}]
    assert "binding_member_mismatch" not in _codes(doc)


# ---------------------------------------------------------------- binding_members (proposal)


@pytest.mark.parametrize("name", ADAPTER)
def test_binding_requirement_id_differing_from_the_proposal_is_refused(name: str) -> None:
    record = copy.deepcopy(load(RUNS / name / "bounded-run-record.json"))
    _decision(record)["binding"]["requirement_id"] = "urn:cognous:authority-requirement:other"
    results = engine.evaluate(_files(record, proposal=RUNS / name / "proposal.json")).results
    codes = _refuted(results).get("v2.identity.binding-fields", set())
    assert "binding_proposal_mismatch" in codes


@pytest.mark.parametrize("name", ADAPTER)
def test_clean_requirement_id_is_accepted(name: str) -> None:
    record = load(RUNS / name / "bounded-run-record.json")
    results = engine.evaluate(_files(record, proposal=RUNS / name / "proposal.json")).results
    assert "v2.identity.binding-fields" not in _refuted(results)


# ---------------------------------------------------------------- ledger_ceiling


def _ledger(name: str) -> Any:
    return load(RUNS / name / "destination-with-operation-digest.json")


def _counts_codes(record: Any, ledger_doc: Any) -> set[str]:
    """Findings of the counts check, run directly (the structure tier refuses a non-integer ceiling
    before the ledger tier is reached; this is the defence of the ledger tier itself)."""
    by_id = {r.check_id: r for r in ledger.run(record, ledger_doc)}
    return {f.code for f in by_id["v4.ledger.counts"].findings}


@pytest.mark.parametrize("name", ADAPTER)
def test_count_above_the_ceiling_is_refused(name: str) -> None:
    record = copy.deepcopy(load(RUNS / name / "bounded-run-record.json"))
    ledger_doc = _ledger(name)
    assert sum(ledger_doc["grant_effect_counts"].values()) >= 1
    _decision(record)["binding"]["effective_max_effects"] = 0
    assert "ledger_count_above_ceiling" in _counts_codes(record, ledger_doc)


@pytest.mark.parametrize("name", ADAPTER)
def test_count_at_the_ceiling_is_accepted(name: str) -> None:
    record = load(RUNS / name / "bounded-run-record.json")
    assert _counts_codes(record, _ledger(name)) == set()


@pytest.mark.parametrize("bad", [-1, True, 1.5, "2", None])
@pytest.mark.parametrize("name", ADAPTER[:1])
def test_every_contributing_ceiling_is_validated_before_a_maximum_is_taken(
    name: str, bad: Any
) -> None:
    """A second authorized decision of the grant with an invalid ceiling must not hide behind a
    valid larger one (``max(5, True)`` is 5 and ``max(5, "2")`` is a type error)."""
    record = copy.deepcopy(load(RUNS / name / "bounded-run-record.json"))
    first = _decision(record)
    first["binding"]["effective_max_effects"] = 5
    second = copy.deepcopy(first)
    second["decision_id"] = "second-decision"
    second["binding"]["effective_max_effects"] = bad
    record["decisions"].append(second)
    assert "ledger_ceiling_invalid" in _counts_codes(record, _ledger(name))


def test_the_largest_ceiling_among_the_grants_decisions_is_the_bound() -> None:
    name = ADAPTER[0]
    record = copy.deepcopy(load(RUNS / name / "bounded-run-record.json"))
    first = _decision(record)
    first["binding"]["effective_max_effects"] = 0
    second = copy.deepcopy(first)
    second["decision_id"] = "second-decision"
    second["binding"]["effective_max_effects"] = 1
    record["decisions"].append(second)
    assert "ledger_count_above_ceiling" not in _counts_codes(record, _ledger(name))


# ---------------------------------------------------------------- causal_order


def _first_attempt_decision(doc: dict[str, Any]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    attempts = [a for a in doc["attempts"]]
    decision = next(d for d in doc["decisions"] if d["decision_id"] == attempts[0]["decision_id"])
    return decision, attempts


@pytest.mark.parametrize(
    "name", ["journal-applied", "default-applied", "journal-lost-ack-closeout"]
)
def test_attempt_started_before_its_decision_is_refused(name: str) -> None:
    doc = copy.deepcopy(real_record(name))
    _, attempts = _first_attempt_decision(doc)
    for a in attempts:
        a["started_at"] = "2000-01-01T00:00:00+00:00"
    assert "attempt_before_decision" in _codes(doc)


def test_attempt_started_at_the_decision_instant_is_accepted() -> None:
    doc = copy.deepcopy(real_record("journal-applied"))
    decision, attempts = _first_attempt_decision(doc)
    for a in attempts:
        a["started_at"] = decision["decided_at"]
    assert "attempt_before_decision" not in _codes(doc)


def test_closeout_before_its_attempt_is_refused() -> None:
    doc = copy.deepcopy(real_record("journal-lost-ack-closeout"))
    doc["closeouts"][0]["reconciled_at"] = "2000-01-01T00:00:00+00:00"
    assert "closeout_before_attempt" in _codes(doc)


def test_closeout_is_compared_with_the_service_clock_when_the_attempt_has_one() -> None:
    doc = copy.deepcopy(real_record("journal-lost-ack-closeout"))
    for a in doc["attempts"]:
        a["recorded_at"] = "2026-10-05T19:00:17+00:00"
    assert "closeout_before_attempt" in _codes(doc)


def test_service_clock_decoupled_from_the_evaluation_clock_is_not_refused() -> None:
    """Control: freshness decouples recorded_at (service clock) from evaluated_at; both are kept
    in their own domain and the fixture stays valid."""
    path = next(
        p
        for p in fixture_paths("journal", "valid")
        if p.stem == "profile-clocks-follow-the-service-clock"
    )
    assert _codes(load(path)["document"]) == set()


def test_all_real_runs_keep_their_order() -> None:
    for run in sorted(p.name for p in REAL_RUNS.iterdir() if p.is_dir()):
        assert not _codes(real_record(run)) & {
            "attempt_before_decision",
            "closeout_before_attempt",
            "reconciliation_before_attempt",
        }, run


def test_reconciliation_closing_an_attempt_before_it_started_is_refused() -> None:
    doc = copy.deepcopy(real_record("journal-lost-ack-closeout"))
    assert doc["closeouts"]
    for a in doc["attempts"]:
        a["started_at"] = "2099-01-01T00:00:00+00:00"
    assert "reconciliation_before_attempt" in _codes(doc)

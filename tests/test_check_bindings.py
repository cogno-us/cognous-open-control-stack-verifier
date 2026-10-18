"""Verifier-side rules that tie a decision, a refusal and the journal to their resolution checks.

Written after the held-out mutation report showed these gaps (input commitments altered in a
decision, a check row resting on an unfinished journal check, checks listed effect-first).
Every damaged case is built from a real run; every real run must still be accepted.
"""

from __future__ import annotations

import copy
from typing import Any

import pytest

from cognous_verify.results import CONFIRMED, COULD_NOT_CHECK, REFUTED

from .helpers import fixture_paths, load, real_record, real_run_names, refuted_codes, verify

CHECK = "v2.journal.check_bindings"
JOURNAL_RUNS = [n for n in real_run_names() if n.startswith("journal-")]
DEFAULT_RUNS = [n for n in real_run_names() if not n.startswith("journal-")]


def _result(doc: Any) -> Any:
    return next(r for r in verify(doc) if r.check_id == CHECK)


def _codes(doc: Any) -> set[str]:
    return {f.code for f in _result(doc).findings}


@pytest.mark.parametrize("name", real_run_names())
def test_clean_real_runs_are_not_refused(name: str) -> None:
    results = verify(real_record(name))
    assert refuted_codes(results) == set()
    assert _result(real_record(name)).verdict in {CONFIRMED, COULD_NOT_CHECK}


def test_valid_fixtures_are_not_refused_by_the_group() -> None:
    for kind in ("journal",):
        for path in fixture_paths(kind, "valid"):
            doc = load(path)["document"]
            assert _result(doc).verdict in {CONFIRMED, COULD_NOT_CHECK}, path.stem


@pytest.mark.parametrize("name", [n for n in real_run_names() if "held" not in n])
def test_decision_input_altered_is_refused(name: str) -> None:
    doc = copy.deepcopy(real_record(name))
    d = next(d for d in doc["decisions"] if d["result"] == "authorized")
    d["resolution_inputs"][-1]["record_commitment"] = "sha256:" + "ab" * 32
    assert refuted_codes(verify(doc)) == {"resolution_check_mismatch"}


def test_decision_reasons_differing_from_the_check_are_refused() -> None:
    doc = copy.deepcopy(real_record("default-held-revoked"))
    doc["decisions"][0]["reasons"] = sorted([*doc["decisions"][0]["reasons"], "grant_not_active"])
    assert "resolution_check_mismatch" in _codes(doc)


def test_refusal_inputs_altered_are_refused() -> None:
    doc = copy.deepcopy(real_record("journal-effect-time-refusal"))
    assert doc["refusals"], "the run holds an effect-time refusal"
    doc["refusals"][0]["resolution_inputs"][-1]["record_commitment"] = "sha256:" + "ef" * 32
    assert refuted_codes(verify(doc)) == {"resolution_check_mismatch"}


def test_two_decisions_with_equal_inputs_each_need_their_own_check() -> None:
    doc = copy.deepcopy(real_record("default-applied"))
    twin = copy.deepcopy(doc["decisions"][0])
    twin["decision_id"] = "twin"
    doc["decisions"].append(twin)
    assert _codes(doc) == {"resolution_check_mismatch"}


@pytest.mark.parametrize("name", [n for n in JOURNAL_RUNS if "held" not in n])
@pytest.mark.parametrize("how", ["interrupted", "dropped"])
def test_check_row_without_a_completed_journal_check_is_refused(name: str, how: str) -> None:
    doc = copy.deepcopy(real_record(name))
    events = doc["check_events"]
    i = max(i for i, e in enumerate(events) if e["phase"] == "completed")
    if how == "interrupted":
        events[i]["phase"] = "interrupted"
    else:
        del events[i]
    assert refuted_codes(verify(doc)) == {"resolution_check_without_completion"}


def test_unfinished_check_without_a_row_is_valid_evidence() -> None:
    path = next(p for p in fixture_paths("journal", "valid") if "interrupted-check" in p.stem)
    doc = load(path)["document"]
    phases = {e["phase"] for e in doc["check_events"]}
    assert "interrupted" in phases
    assert _result(doc).verdict in {CONFIRMED, COULD_NOT_CHECK}
    assert refuted_codes(verify(doc)) == set()


@pytest.mark.parametrize(
    "name",
    [
        n
        for n in real_run_names()
        if n in {"default-applied", "journal-applied", "acp-run-authorized"}
    ],
)
def test_effect_check_listed_before_any_decision_check_is_refused(name: str) -> None:
    doc = copy.deepcopy(real_record(name))
    doc["resolution_checks"].reverse()
    codes = refuted_codes(verify(doc))
    assert codes in ({"effect_check_before_decision_check"}, {"resolution_checks_out_of_order"})


def test_group_waits_for_the_contract_groups() -> None:
    doc = copy.deepcopy(real_record("default-applied"))
    doc["decisions"][0]["resolution_inputs"][0]["record_commitment"] = "sha256:" + "cd" * 32
    doc["decisions"].append(copy.deepcopy(doc["decisions"][0]))  # duplicate decision id
    by_id = {r.check_id: r for r in verify(doc)}
    assert by_id["v2.journal.decisions"].verdict == REFUTED
    assert by_id[CHECK].verdict == COULD_NOT_CHECK
    assert by_id[CHECK].reason == "earlier_rules_refuted"


def test_a_check_id_changed_is_not_detectable() -> None:
    """Known limit: check ids of the journal and of the resolution checks are separate producer ids
    (the contract says so), so changing one resolution check id leaves a record that is still
    consistent by content. The verifier does not invent a link between them."""
    doc = copy.deepcopy(real_record("journal-applied"))
    doc["resolution_checks"][0]["check_id"] = "00000000-0000-4000-8000-000000000001"
    assert refuted_codes(verify(doc)) == set()

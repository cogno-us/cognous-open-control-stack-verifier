from __future__ import annotations

import copy
from typing import Any

from cognous_verify import documents
from cognous_verify.results import CONFIRMED, COULD_NOT_CHECK, REFUTED

from .helpers import fixture_paths, load, real_record, refuted_codes, verify


def test_detect_kind() -> None:
    assert documents.detect_kind([]) == (None, False)
    assert documents.detect_kind({"contract": "other"}) == (None, False)
    assert documents.detect_kind({"contract": documents.JOURNAL}) == (documents.JOURNAL, False)
    assert documents.detect_kind({"contract": documents.LIFECYCLE}) == (documents.LIFECYCLE, False)
    assert documents.detect_kind({"decisions": [], "attempts": []}) == (documents.JOURNAL, True)
    assert documents.detect_kind({"decisions": [], "attempts": [], "contract_version": "x"}) == (
        None,
        False,
    )


def test_unsupported_document_is_could_not_check() -> None:
    results = verify({"hello": "world"})
    assert len(results) == 1 and results[0].verdict == COULD_NOT_CHECK
    assert results[0].reason is not None and results[0].reason.startswith("unsupported_document")


def test_contract_version_other_than_draft_is_refused() -> None:
    doc = copy.deepcopy(real_record("default-applied"))
    doc["contract"] = documents.JOURNAL
    doc["contract_version"] = "9.9.9"
    assert refuted_codes(verify(doc)) == {"unsupported_contract_version"}


def test_internal_crash_is_an_error_not_a_verdict() -> None:
    doc: dict[str, Any] = copy.deepcopy(real_record("default-applied"))
    # a member that passes the structure check but breaks a rule: simulate with a bad callable
    result = documents._guard("v2.test", "x", 3, lambda: 1 // 0)  # type: ignore[arg-type,return-value]
    assert result.error and result.verdict == COULD_NOT_CHECK
    assert result.reason == "verifier_error:ZeroDivisionError"
    assert result.as_dict()["error"] is True
    assert doc  # keep the copy referenced


def test_delegated_rules_wait_for_earlier_rules() -> None:
    doc = copy.deepcopy(real_record("default-applied"))
    doc["decisions"][0]["decision_id"] = "x"
    doc["decisions"].append(copy.deepcopy(doc["decisions"][0]))
    results = verify(doc)
    by_id = {r.check_id: r for r in results}
    assert by_id["v2.journal.decisions"].verdict == REFUTED
    assert by_id["v2.lifecycle.control_plane_attempts"].reason == "earlier_rules_refuted"


def test_results_serialize_with_denominators() -> None:
    results = verify(real_record("journal-applied"))
    first = results[0].as_dict()
    assert first["unit"] == "document"
    assert first["tally"] == {"confirmed": 1, "could_not_check": 0, "refuted": 0, "n": 1}
    decisions = next(r for r in results if r.check_id == "v2.journal.decisions")
    assert decisions.verdict == CONFIRMED and decisions.as_dict()["tally"]["n"] == 1


def test_lifecycle_document_without_journal_reports_no_journal() -> None:
    path = next(p for p in fixture_paths("lifecycle", "valid") if "normal-attempted" in p.name)
    results = verify(load(path)["document"])
    assert any(r.reason == "no_journal_in_record" for r in results)

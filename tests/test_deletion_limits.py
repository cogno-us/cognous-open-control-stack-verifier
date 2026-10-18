"""Single-row deletions: which the record now shows, which nothing in it can show.

``tools/deletion_corpus.py`` deletes one row of one list member of every valid journal fixture and
real run (1772 deletions over 67 records). Before the fix round 2 rules the verifier accepted 74;
it now accepts 62, and the 12 it newly refuses are the deletions the dispatch licence shows (a
refusal deleted while its attempt stays, an effect-stage check deleted while its attempt stays).
What it still accepts is of two kinds, each pinned below with one example so a later change has to
say why:

* residual: the row has no counterpart in the rest of the record (a hold decision, an authorized
  decision that was never dispatched, a trailing attempt row, a vocabulary change, a profile row).
  The record without the row is a record the control plane could have produced, so nothing can
  refuse it;
* by design: the tail of the check events. A journal that stops early is an interrupted check,
  which the contract keeps as unfinished evidence.

No completeness member is added (that is a contract decision, not a verifier check).
"""

from __future__ import annotations

import copy
from typing import Any

import pytest

from cognous_verify import documents

from .helpers import fixture_paths, load, real_record


def _fixture(stem: str) -> dict[str, Any]:
    path = next(p for p in fixture_paths("journal", "valid") if p.stem == stem)
    doc: dict[str, Any] = copy.deepcopy(load(path)["document"])
    return doc


def _accepted(doc: dict[str, Any]) -> bool:
    results = documents.verify_document(doc)
    return not any(r.verdict == "refuted" or r.error for r in results)


def _without(doc: dict[str, Any], member: str, index: int) -> dict[str, Any]:
    del doc[member][index]
    return doc


NOW_REFUSED = [
    ("effect-time-refusal", "refusals", 0),
    ("profile-nonce-replay-rejected", "refusals", 0),
    ("profile-terminal-revocation-refused-after-recorded-revocation", "refusals", 1),
]

RESIDUAL = [
    ("held-decision-journal-mode", "decisions", 0),  # a hold decision
    ("profile-extension-recorded-and-applied", "decisions", 1),  # authorized, never dispatched
    ("failed-definitive-rejection", "attempts", 1),  # the trailing row of a lifecycle
    ("profile-rule-reports", "vocabulary_changes", 0),  # a vocabulary change
    ("profile-all-profiles-applied", "operation_renewals", 0),  # a profile row
    ("profile-overdue-reported-not-closed", "recovery_runs", 0),  # a profile row
]

BY_DESIGN = [("interrupted-check-is-unfinished-evidence", "check_events", 2)]


@pytest.mark.parametrize("stem,member,index", NOW_REFUSED)
def test_deleting_a_refusal_whose_attempt_stays_is_refused_for_the_fixture_with_an_attempt(
    stem: str, member: str, index: int
) -> None:
    doc = _fixture(stem)
    assert _accepted(copy.deepcopy(doc))
    assert not _accepted(_without(doc, member, index))


@pytest.mark.parametrize("name", ["default-applied", "acp-run-authorized"])
def test_deleting_the_effect_check_of_a_dispatched_attempt_is_refused(name: str) -> None:
    doc = real_record(name)
    assert _accepted(copy.deepcopy(doc))
    index = next(i for i, c in enumerate(doc["resolution_checks"]) if c["stage"] == "effect")
    assert not _accepted(_without(doc, "resolution_checks", index))


@pytest.mark.parametrize("stem,member,index", RESIDUAL)
def test_residual_deletion_is_accepted_because_nothing_in_the_record_corroborates_the_row(
    stem: str, member: str, index: int
) -> None:
    doc = _fixture(stem)
    assert _accepted(copy.deepcopy(doc))
    assert _accepted(_without(doc, member, index))


@pytest.mark.parametrize("stem,member,index", BY_DESIGN)
def test_tail_truncation_of_check_events_is_an_interrupted_check(
    stem: str, member: str, index: int
) -> None:
    doc = _fixture(stem)
    assert index == len(doc[member]) - 1
    assert _accepted(_without(doc, member, index))

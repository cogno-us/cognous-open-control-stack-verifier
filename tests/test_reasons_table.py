"""Completion reasons: the full implication table of the ODES ``reasons_minimum`` rule.

A completed journal check carries at least the reasons its own recorded input events imply
(ODES execution-attempt-lifecycle ``IMPLIED_REASONS`` / ``implied_reasons``):

* an input read ``unreadable`` that no later read of the same input rescued as
  ``cached_positive``: ``status_unreadable``;
* an input read ``nonce_mismatch``: ``status_nonce_mismatch``;
* an ``authority_context`` whose last read is missing with no read state:
  ``authority_context_missing``;
* a ``purpose`` whose last read is missing with no read state: ``purpose_unreadable``;
* any input whose last read is missing and not rescued: at least one reason.

The table is a floor. ``required_input_not_read`` is written next to ``status_unreadable`` by the
producer but implied by nothing in the record, so it is not required here.
"""

from __future__ import annotations

import copy
from typing import Any

import pytest

from .helpers import fixture_paths, load, refuted_codes, verify

CODE = "completion_reasons_minimum"
STEM = "reasons-0-2-label-with-a-0-2-code"


def _valid(stem: str) -> dict[str, Any]:
    path = next(p for p in fixture_paths("journal", "valid") if p.stem == stem)
    doc: dict[str, Any] = copy.deepcopy(load(path)["document"])
    return doc


def _codes(doc: Any) -> set[str]:
    return refuted_codes(verify(doc))


def _completed(doc: dict[str, Any]) -> dict[str, Any]:
    return next(e for e in doc["check_events"] if e["phase"] == "completed")


def _input(kind: str, ident: str, **over: Any) -> dict[str, Any]:
    row: dict[str, Any] = {
        "input_type": kind,
        "input_id": ident,
        "expected": {},
        "observed": {},
        "record_commitment": None,
        "missing": True,
        "previous_observed_at": None,
    }
    row.update(over)
    return row


def _with_inputs(inputs: list[dict[str, Any]], reasons: list[str]) -> dict[str, Any]:
    """A held record whose single check reads ``inputs`` and completes with ``reasons``."""
    doc = _valid(STEM)
    check, decision, done = doc["resolution_checks"][0], doc["decisions"][0], _completed(doc)
    plain = [e for e in doc["check_events"] if e["phase"] != "input"]
    template = next(e for e in doc["check_events"] if e["phase"] == "input")
    events = []
    for event in plain:
        if event["phase"] == "completed":
            for x in inputs:
                events.append({**copy.deepcopy(template), "input": copy.deepcopy(x)})
        events.append(event)
    doc["check_events"] = events
    check["inputs"] = copy.deepcopy(inputs)
    decision["resolution_inputs"] = copy.deepcopy(inputs)
    for holder in (check, done):
        holder["reasons"] = list(reasons)
    decision["reasons"] = ["holder_inventory_missing"]
    return doc


# ------------------------------------------------------------------ the reasons fixture


def test_the_vendored_reasons_fixture_is_accepted() -> None:
    """The vendored fixture carries the reasons its unreadable grant read implies (decision 39)."""
    doc = _valid(STEM)
    assert _completed(doc)["reasons"] == [
        "holder_inventory_missing",
        "required_input_not_read",
        "status_unreadable",
    ]
    assert _codes(doc) == set()


def test_status_unreadable_alone_is_enough_for_the_floor() -> None:
    """``required_input_not_read`` is implied by nothing in the record: not required."""
    doc = _valid(STEM)
    for holder in (doc["resolution_checks"][0], doc["decisions"][0], _completed(doc)):
        holder["reasons"] = ["holder_inventory_missing", "status_unreadable"]
    assert _codes(doc) == set()


# ------------------------------------------------------------------ one row per implication

UNREADABLE = _input("grant", "g1", read_state="unreadable")
RESCUE = _input("grant", "g1", missing=False, read_state="cached_positive")
CONTEXT = _input("authority_context", "ctx1")
PURPOSE = _input("purpose", "p1")
OTHER = ["holder_inventory_missing"]


@pytest.mark.parametrize(
    "inputs,floor",
    [
        ([UNREADABLE], "status_unreadable"),
        ([CONTEXT], "authority_context_missing"),
        ([PURPOSE], "purpose_unreadable"),
    ],
    ids=["unreadable", "authority_context_missing", "purpose_unreadable"],
)
def test_each_implied_reason_is_required_and_sufficient(
    inputs: list[dict[str, Any]], floor: str
) -> None:
    refused = _with_inputs(inputs, OTHER)
    assert CODE in _codes(refused)
    control = _with_inputs(inputs, [*OTHER, floor])
    assert CODE not in _codes(control)


def test_a_cached_positive_after_an_unreadable_read_implies_nothing() -> None:
    doc = _with_inputs([UNREADABLE, RESCUE], OTHER)
    assert CODE not in _codes(doc)


def test_a_missing_input_with_a_state_other_than_none_needs_one_reason_not_a_named_one() -> None:
    """A missing authority context that carries a read state implies no named code."""
    stated = _input("authority_context", "ctx1", read_state="unreadable")
    doc = _with_inputs([stated], OTHER)
    # unreadable still implies status_unreadable
    assert CODE in _codes(doc)
    ok = _with_inputs([stated], [*OTHER, "status_unreadable"])
    assert CODE not in _codes(ok)


def test_blank_reasons_over_any_missing_input_are_refused() -> None:
    manifest_gone = _input("manifest", "m1")
    doc = _with_inputs([manifest_gone], [])
    assert CODE in _codes(doc)


def test_present_inputs_imply_nothing() -> None:
    present = _input("grant", "g1", missing=False, record_commitment=None)
    doc = _with_inputs([present], [])
    assert CODE not in _codes(doc)


def test_a_nonce_mismatch_read_requires_its_reason() -> None:
    """Built from the producer-shaped nonce fixture: the reason removed from every row."""
    doc = _valid("profile-nonce-replay-rejected")
    assert CODE not in _codes(doc)
    for event in doc["check_events"]:
        event["reasons"] = [r for r in event["reasons"] if r != "status_nonce_mismatch"]
    assert CODE in _codes(doc)

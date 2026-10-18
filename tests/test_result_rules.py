"""Executor result rules: identity, the status matrix, and the attempt transition tables.

* ``result_identity``: a result carries the effect and decision of the attempt it names; a result
  whose status claims an attempt (failed, partial, unknown, executed, reconciled) resolves exactly
  one executor attempt row; status ``observed`` stays effect-free with a null attempt id.
* ``result_state_matrix``: every status x flags x observation combination the runtime producer
  refuses (``engine/producer_contract.py``) is refused here, validated ``state`` observations and
  route-B recovery ``status`` reports told apart.
* ``attempt_transition``: the executor and control-plane transition tables, checked over every
  pair of statuses against the ODES table recorded below.
"""

from __future__ import annotations

import copy
import itertools
from typing import Any

import pytest

from cognous_verify import rules_lifecycle

from .helpers import fixture_paths, load, refuted_codes, verify

EXECUTOR_STATUSES = (
    "attempted",
    "executed",
    "partial",
    "failed",
    "unknown",
    "denied",
    "reconciled",
)
CP_STATUSES = ("attempted", "acknowledged", "partial", "failed", "unknown")

# ODES ce289e9 (contracts/execution-attempt-lifecycle/validate.py, EXECUTOR_TRANSITIONS and
# CONTROL_PLANE_TRANSITIONS; decision 37, with executed -> unknown and partial -> unknown added by
# decision 39-P), recorded as data so the verifier stays dependency free. The control plane
# adapter appends unknown after an executed or partial row when the follow-up observation is not
# accepted, so the executor table carries those two edges.
ODES_EXECUTOR = {
    "attempted": {"executed", "partial", "failed", "unknown", "denied", "reconciled"},
    "unknown": {"executed", "partial", "failed", "reconciled"},
    "executed": {"unknown", "reconciled"},
    "partial": {"unknown", "reconciled"},
    "failed": set(),
    "denied": set(),
    "reconciled": set(),
}
ODES_CONTROL_PLANE = {
    "attempted": {"acknowledged", "unknown", "failed", "partial"},
    "unknown": {"acknowledged", "failed", "partial"},
    "acknowledged": set(),
    "partial": set(),
    "failed": set(),
}


def _lifecycle(stem: str) -> dict[str, Any]:
    path = next(p for p in fixture_paths("lifecycle", "valid") if p.stem == stem)
    doc: dict[str, Any] = copy.deepcopy(load(path)["document"])
    return doc


def _codes(doc: Any) -> set[str]:
    return refuted_codes(verify(doc))


# ---------------------------------------------------------------- result_identity


def test_result_naming_a_ghost_attempt_is_refused() -> None:
    doc = _lifecycle("executor-normal-attempted-executed-observed")
    doc["execution_result"]["attempt_id"] = "no-such-attempt"
    assert "result_attempt_unresolved" in _codes(doc)


def test_attempt_claiming_result_with_null_attempt_id_is_refused() -> None:
    doc = _lifecycle("executor-normal-attempted-executed-observed")
    doc["execution_result"]["attempt_id"] = None
    assert "result_attempt_unresolved" in _codes(doc)


@pytest.mark.parametrize("status", ["failed", "partial", "unknown", "executed", "reconciled"])
def test_every_attempt_claiming_status_needs_an_attempt(status: str) -> None:
    doc = _lifecycle("executor-normal-attempted-executed-observed")
    doc["execution_result"]["status"] = status
    doc["execution_result"]["attempt_id"] = "ghost"
    if status == "unknown":  # the earlier unknown-state rules must find nothing
        doc["execution_result"].update(observed_state="unknown", observation=None)
    assert "result_attempt_unresolved" in _codes(doc)


def test_result_with_another_effect_than_its_attempt_is_refused() -> None:
    doc = _lifecycle("executor-normal-attempted-executed-observed")
    doc["execution_result"]["effect_id"] = "another-effect"
    assert "result_binding_mismatch" in _codes(doc)


def test_result_with_another_decision_than_its_attempt_is_refused() -> None:
    doc = _lifecycle("executor-normal-attempted-executed-observed")
    doc["execution_result"]["decision_id"] = "another-decision"
    assert "result_binding_mismatch" in _codes(doc)


def test_result_carrying_its_attempts_identity_is_accepted() -> None:
    doc = _lifecycle("executor-normal-attempted-executed-observed")
    attempt = doc["attempts"][0]
    doc["execution_result"]["effect_id"] = attempt["effect_id"]
    doc["execution_result"]["decision_id"] = attempt["decision_id"]
    assert _codes(doc) == set()


def test_result_naming_a_control_plane_attempt_is_not_an_executor_attempt() -> None:
    """The attempt id lives in the executor namespace: a control-plane attempt id does not resolve."""
    doc = _lifecycle("executor-normal-attempted-executed-observed")
    doc["control_plane_attempts"] = [
        {
            "attempt_id": "cp-attempt-1",
            "effect_id": "syn-effect-1",
            "decision_id": "syn-decision-1",
            "started_at": "2026-01-01T00:00:00+00:00",
            "time_source": "test_override",
            "status": "attempted",
            "acknowledgement": {},
            "error": None,
        }
    ]
    doc["execution_result"]["attempt_id"] = "cp-attempt-1"
    assert "result_attempt_unresolved" in _codes(doc)


def test_observed_result_stays_null_attempt_id_and_effect_free() -> None:
    """Control: the effect-free reconcile of route B names no attempt and is valid."""
    doc = _lifecycle("executor-observed-effect-free-reconcile-route-b")
    assert doc["execution_result"]["attempt_id"] is None
    assert _codes(doc) == set()
    doc["execution_result"]["attempt_id"] = doc["attempts"][0]["attempt_id"]
    assert _codes(doc) & {"observed_result_claims_attempt", "effect_free_reconcile_claims_attempt"}


# ---------------------------------------------------------------- result_state_matrix


def _executed() -> dict[str, Any]:
    return _lifecycle("executor-normal-attempted-executed-observed")


@pytest.mark.parametrize(
    "change",
    [
        {"attempted": False},
        {"acknowledged": False},
        {"newly_executed": False},
        {"observed_state": "absent"},
        {"observed_state": "partial"},
    ],
    ids=["not-attempted", "not-acknowledged", "not-fresh", "observed-absent", "observed-partial"],
)
def test_executed_result_outside_the_matrix_is_refused(change: dict[str, Any]) -> None:
    doc = _executed()
    doc["execution_result"].update(change)
    if "observed_state" in change:
        doc["execution_result"]["observation"]["state"] = change["observed_state"]
    assert "result_state_matrix" in _codes(doc)


def test_fresh_execution_must_be_acknowledged() -> None:
    doc = _executed()
    doc["execution_result"].update(acknowledged=False, newly_executed=True)
    assert "result_state_matrix" in _codes(doc)


def test_acknowledgement_requires_an_attempt() -> None:
    doc = _executed()
    doc["execution_result"].update(attempted=False)
    assert "result_state_matrix" in _codes(doc)


def test_failed_result_cannot_carry_an_acknowledgement() -> None:
    doc = _executed()
    doc["attempt_events"][-1]["status"] = "failed"
    doc["execution_result"].update(status="failed", observed_state="unknown", observation=None)
    doc["execution_result"]["error"] = "rejected"
    assert "result_state_matrix" in _codes(doc)


def test_validated_observation_state_must_equal_observed_state() -> None:
    doc = _executed()
    doc["execution_result"]["observation"]["state"] = "partial"
    assert "result_state_matrix" in _codes(doc)


def test_partial_result_must_be_observed_as_partial() -> None:
    doc = _executed()
    doc["attempt_events"][-1]["status"] = "partial"
    doc["execution_result"]["status"] = "partial"
    assert "result_state_matrix" in _codes(doc)


def test_reconciled_result_is_not_a_fresh_execution() -> None:
    doc = _executed()
    doc["attempt_events"][-1]["status"] = "reconciled"
    doc["execution_result"]["status"] = "reconciled"
    assert "result_state_matrix" in _codes(doc)


@pytest.mark.parametrize(
    "stem",
    [
        "executor-normal-attempted-executed-observed",
        "executor-normal-observations-member",
        "executor-observed-effect-free-reconcile-route-b",
        "executor-unknown-ack-unobserved",
        "executor-unknown-recovery-hold-route-b",
        "executor-unknown-recovery-observation-route-b",
        "executor-unknown-recovery-separate-member-route-b",
        "executor-unknown-recovery-unavailable-route-b",
        "executor-unknown-validated-absent-after-ambiguous-dispatch",
        "executor-unknown-validated-unknown-after-ambiguous-dispatch",
        "executor-denied-attempt-event",
    ],
)
def test_valid_executor_records_pass_the_matrix(stem: str) -> None:
    assert _codes(_lifecycle(stem)) == set()


def test_route_b_recovery_report_is_not_held_to_the_validated_state_cell() -> None:
    """A recovery report carries ``status`` and no ``state``: the validated-state cell is not read."""
    doc = _lifecycle("executor-unknown-recovery-observation-route-b")
    assert "state" not in doc["execution_result"]["observation"]
    assert "result_state_matrix" not in _codes(doc)


# ---------------------------------------------------------------- attempt_transition


def test_executor_table_equals_the_odes_table() -> None:
    table = {
        (prev, nxt)
        for prev in EXECUTOR_STATUSES
        for nxt in EXECUTOR_STATUSES
        if nxt in rules_lifecycle.EXECUTOR_NEXT.get(prev, frozenset())
    }
    odes = {(p, n) for p, nxt in ODES_EXECUTOR.items() for n in nxt}
    assert table == odes


@pytest.mark.parametrize("edge", [("executed", "unknown"), ("partial", "unknown")])
def test_unknown_after_executed_or_partial_is_an_edge_in_both_tables(edge: tuple[str, str]) -> None:
    """The control plane adapter writes these two edges; the ODES table accepts them."""
    prev, nxt = edge
    assert nxt in ODES_EXECUTOR[prev]
    assert nxt in rules_lifecycle.EXECUTOR_NEXT[prev]


def test_attempted_may_close_as_reconciled() -> None:
    """The runtime writes attempted -> reconciled when the destination already holds the effect."""
    assert "reconciled" in rules_lifecycle.EXECUTOR_NEXT["attempted"]


@pytest.mark.parametrize(
    "prev,nxt",
    list(itertools.product(EXECUTOR_STATUSES, EXECUTOR_STATUSES)),
)
def test_executor_events_follow_the_table_over_every_pair(prev: str, nxt: str) -> None:
    if prev == "attempted" or nxt == "attempted":
        pytest.skip("attempted only opens an attempt (start rules)")
    doc = _lifecycle("executor-normal-attempted-executed-observed")
    doc["attempt_events"] = [
        {
            "event_id": 1,
            "attempt_id": "syn-attempt-1",
            "status": "attempted",
            "error": None,
            "created_at": 1.0,
        },
        {
            "event_id": 2,
            "attempt_id": "syn-attempt-1",
            "status": prev,
            "error": None,
            "created_at": 2.0,
        },
        {
            "event_id": 3,
            "attempt_id": "syn-attempt-1",
            "status": nxt,
            "error": None,
            "created_at": 3.0,
        },
    ]
    refused = "attempt_transition_invalid" in _codes(doc)
    allowed = nxt in rules_lifecycle.EXECUTOR_NEXT.get(prev, frozenset())
    # the first hop attempted -> prev is the table too; refuse when either hop is outside it
    first = prev in rules_lifecycle.EXECUTOR_NEXT["attempted"]
    assert refused == (not (allowed and first))


@pytest.mark.parametrize(
    "prev,nxt",
    list(itertools.product(CP_STATUSES, CP_STATUSES)),
)
def test_control_plane_rows_follow_the_odes_table_over_every_pair(prev: str, nxt: str) -> None:
    if prev == "attempted" or nxt == "attempted":
        pytest.skip("attempted only opens an attempt (start rules)")

    def row(status: str) -> dict[str, Any]:
        return {
            "attempt_id": "a1",
            "effect_id": "e1",
            "decision_id": "d1",
            "started_at": "2026-01-01T00:00:00+00:00",
            "time_source": "test_override",
            "status": status,
            "acknowledgement": {},
            "error": None,
        }

    findings = rules_lifecycle.control_plane_attempts([row("attempted"), row(prev), row(nxt)], "$")
    refused = any(f.code == "attempt_transition_invalid" for f in findings)
    first_ok = prev in ODES_CONTROL_PLANE["attempted"]
    assert refused == (not (first_ok and nxt in ODES_CONTROL_PLANE[prev]))

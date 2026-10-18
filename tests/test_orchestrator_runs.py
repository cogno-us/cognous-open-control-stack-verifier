"""Real run records of the orchestrator's candidate-component overlay (programme 2, findings F-1 and F-2).

Two producer shapes that the control plane's own capture does not cover: the atomic claim route
(the control plane record has a ``claim``-stage check and no attempt layer; the destination owns
the attempts) and the control plane adapter route over the runtime's SQLite destination (its
observation carries ``operation_digest`` inside ``destination_state``). Records are in
``tests/data/orchestrator-runs`` with the orchestrator's own ledger projection (see SOURCE.json).

What they pin: a legitimate shape is never refuted (it is accepted when the whole record is
checkable, abstained, never accepted, when part of it is not), and the narrowing does not
reach the control plane's own shape or any damage.
"""

from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

import pytest

from cognous_verify import engine, ledger
from cognous_verify.canon import canonical_bytes
from cognous_verify.results import COULD_NOT_CHECK, REFUTED

from .helpers import REAL_RUNS, load

RUNS = Path(__file__).parent / "data" / "orchestrator-runs"
ATOMIC = ("atomic-applied", "atomic-lost-ack-then-reconcile", "atomic-duplicate-dispatch")
ADAPTER = ("adapter-applied", "adapter-lost-ack-then-land", "adapter-renewal-race")
HELD = ("atomic-held-no-grant", "adapter-held")
ROLES = {
    "run_record": "bounded-run-record.json",
    "proposal_export": "proposal.json",
    "manifest": "manifest.json",
}


def _evaluate(
    name: str, ledger_file: str = "destination.json", **override: Any
) -> engine.Evaluation:
    d = RUNS / name
    files = [
        engine.InputFile(role, fname, override.get(role) or (d / fname).read_bytes())
        for role, fname in ROLES.items()
    ]
    data = override.get("destination_ledger") or (d / ledger_file).read_bytes()
    files.append(engine.InputFile("destination_ledger", ledger_file, data))
    return engine.evaluate(files)


def _by_check(ev: engine.Evaluation) -> dict[str, Any]:
    return {r.check_id: r for r in ev.results}


def _refuted(ev: engine.Evaluation) -> dict[str, set[str]]:
    return {r.check_id: {f.code for f in r.findings} for r in ev.results if r.verdict == REFUTED}


def _json(data: Any) -> bytes:
    return canonical_bytes(data)


# F-2: the atomic claim route ------------------------------------------------------------------


@pytest.mark.parametrize("name", ATOMIC)
def test_atomic_route_with_projected_ledger_is_abstained_not_refuted(name: str) -> None:
    ev = _evaluate(name)
    assert _refuted(ev) == {}
    assert ev.overall == "abstain"
    skipped = {r.check_id: r.reason for r in ev.results if r.verdict == COULD_NOT_CHECK}
    assert skipped == {"v4.ledger.rows-agree-with-attempts": "attempt_rows_not_in_record"}
    r = _by_check(ev)["v4.ledger.rows-agree-with-attempts"]
    assert r.tally() == {"confirmed": 0, "could_not_check": 1, "refuted": 0, "n": 1}


@pytest.mark.parametrize("name", HELD)
def test_held_records_with_an_empty_ledger_are_accepted(name: str) -> None:
    assert _evaluate(name).overall == "accept"


def test_atomic_route_still_refuted_on_a_row_the_decision_does_not_bind() -> None:
    led = load(RUNS / "atomic-applied" / "destination.json")
    (row,) = led["effects"].values()
    row["amount"] = 51.0
    ev = _evaluate("atomic-applied", destination_ledger=_json(led))
    assert _refuted(ev) == {"v4.ledger.row-matches-binding": {"ledger_row_differs_from_binding"}}


def test_atomic_route_still_refuted_on_a_row_without_a_decision() -> None:
    led = load(RUNS / "atomic-applied" / "destination.json")
    (row,) = led["effects"].values()
    other = copy.deepcopy(row)
    other["effect_id"] = "sha256:" + "0" * 64
    led["effects"][other["effect_id"]] = other
    led["grant_effect_counts"][other["grant_id"]] = 2
    ev = _evaluate("atomic-applied", destination_ledger=_json(led))
    assert "v4.ledger.effects-have-authorized-decisions" in _refuted(ev)


def _record(checks: list[str], **members: Any) -> dict[str, Any]:
    rec: dict[str, Any] = {
        "resolution_checks": [{"stage": s} for s in checks],
        "attempts": [],
        "observations": [],
        "reconciliations": [],
        "refusals": [],
    }
    rec.update(members)
    return rec


_LEDGER = {"effects": {"e1": {"effect_id": "e1", "grant_id": "g"}}, "grant_effect_counts": {"g": 1}}


@pytest.mark.parametrize(
    "record,verdict",
    [
        # claim route shape: not decidable from the record
        (_record(["decision", "claim"]), COULD_NOT_CHECK),
        # no claim evidence: the control plane's own shape, a row needs an attempt
        (_record(["decision"]), REFUTED),
        (_record(["decision", "effect"]), REFUTED),
        # claim evidence next to the control plane's dispatch path
        (_record(["decision", "claim", "effect"]), REFUTED),
        (_record(["decision", "claim"], refusals=[{"effect_id": "e1"}]), REFUTED),
        (
            _record(
                ["decision", "claim"],
                attempts=[{"attempt_id": "a", "effect_id": "e2", "status": "attempted"}],
            ),
            REFUTED,
        ),
        (_record(["decision", "claim"], observations=[{"effect_id": "e2"}]), REFUTED),
        (_record(["decision", "claim"], reconciliations=[{"effect_id": "e2"}]), REFUTED),
    ],
)
def test_the_narrowing_covers_only_the_claim_route_shape(
    record: dict[str, Any], verdict: str
) -> None:
    assert ledger._rows_agree_with_attempts(record, _LEDGER).verdict == verdict


def test_a_failed_attempt_is_still_refuted_on_a_claim_record() -> None:
    record = _record(
        ["decision", "claim"], attempts=[{"attempt_id": "a", "effect_id": "e1", "status": "failed"}]
    )
    r = ledger._rows_agree_with_attempts(record, _LEDGER)
    assert r.verdict == REFUTED
    assert {f.code for f in r.findings} == {"ledger_row_after_definitive_failure"}


def test_control_plane_shape_is_unchanged_for_the_effect_time_refusal_donor() -> None:
    # tests/test_ledger_attempts.py pins this on the real run; here the claim-route reading is excluded explicitly
    rec = load(REAL_RUNS / "journal-effect-time-refusal" / "bounded-run-record.json")
    assert not ledger._attempt_layer_outside_record(rec)


@pytest.mark.parametrize("name", [p.name for p in sorted(REAL_RUNS.iterdir()) if p.is_dir()])
def test_no_control_plane_run_is_read_as_the_claim_route(name: str) -> None:
    assert not ledger._attempt_layer_outside_record(
        load(REAL_RUNS / name / "bounded-run-record.json")
    )


# F-1: the runtime's operation_digest ----------------------------------------------------------


@pytest.mark.parametrize("name", ADAPTER)
def test_adapter_route_with_the_seven_member_ledger_is_abstained_not_refuted(name: str) -> None:
    ev = _evaluate(name)
    assert _refuted(ev) == {}
    assert ev.overall == "abstain"
    skipped = {r.check_id: r.reason for r in ev.results if r.verdict == COULD_NOT_CHECK}
    assert skipped == {
        "v4.ledger.observations-agree": "destination_state_has_members_outside_ledger_row"
    }


@pytest.mark.parametrize("name", ADAPTER)
def test_projection_b_with_the_digest_on_the_row_is_accepted(name: str) -> None:
    # F-1: the row carries the runtime's operation_digest (ODES destination-ledger 0.1.0-draft).
    # It was refused at ledger_shape before; the observation's destination_state now has no member
    # outside the row, so the check is confirmed and the record is accepted.
    ev = _evaluate(name, "destination-with-operation-digest.json")
    assert _refuted(ev) == {}
    assert ev.overall == "accept"
    assert all(r.verdict == "confirmed" for r in ev.results)
    assert _by_check(ev)["v4.ledger.observations-agree"].tally()["confirmed"] >= 1


@pytest.mark.parametrize("name", ADAPTER)
def test_projection_b_row_digest_replaced_is_refuted_not_hidden(name: str) -> None:
    # the optional member must not hide a mismatch: a different digest on the row is refuted
    led = load(RUNS / name / "destination-with-operation-digest.json")
    row = next(iter(led["effects"].values()))
    row["operation_digest"] = "sha256:" + "f" * 64
    ev = _evaluate(name, destination_ledger=_json(led))
    assert ev.overall == "reject"
    assert _refuted(ev) == {"v4.ledger.observations-agree": {"operation_digest_mismatch"}}


@pytest.mark.parametrize("name", ADAPTER)
def test_projection_b_malformed_row_digest_is_a_shape_refusal(name: str) -> None:
    led = load(RUNS / name / "destination-with-operation-digest.json")
    next(iter(led["effects"].values()))["operation_digest"] = "SHA256:" + "A" * 64
    ev = _evaluate(name, destination_ledger=_json(led))
    assert _refuted(ev) == {"v1.structure.ledger": {"ledger_shape"}}


def _obs_record(state: Any) -> dict[str, Any]:
    return {
        "reconciliations": [
            {
                "observation_accepted": True,
                "observation": {"state": "applied", "effect_id": "e1", "destination_state": state},
            }
        ]
    }


_ROW = {
    "effect_id": "e1",
    "grant_id": "g",
    "target": "t",
    "amount": 50.0,
    "unit": "USD",
    "payload": {},
    "state": "applied",
}
_LED = {"effects": {"e1": _ROW}, "grant_effect_counts": {"g": 1}}


@pytest.mark.parametrize(
    "state,verdict",
    [
        (dict(_ROW), None),  # equal: confirmed
        ({**_ROW, "operation_digest": "sha256:" + "1" * 64}, COULD_NOT_CHECK),
        ({**_ROW, "amount": 51.0}, REFUTED),
        ({**_ROW, "amount": 51.0, "operation_digest": "sha256:" + "1" * 64}, REFUTED),
        ({k: v for k, v in _ROW.items() if k != "unit"}, REFUTED),
        ({k: v for k, v in _ROW.items() if k != "unit"} | {"operation_digest": "x"}, REFUTED),
        (None, REFUTED),
        ("applied", REFUTED),
    ],
)
def test_observation_state_against_the_row(state: Any, verdict: str | None) -> None:
    r = ledger._observations_agree(_obs_record(state), _LED)
    assert r.verdict == (verdict or "confirmed")


_D1 = "sha256:" + "1" * 64
_D2 = "sha256:" + "2" * 64
_ROW_D = {**_ROW, "operation_digest": _D1}
_LED_D = {"effects": {"e1": _ROW_D}, "grant_effect_counts": {"g": 1}}
_MISSING = "operation_digest_not_in_destination_state"
_OUTSIDE = "destination_state_has_members_outside_ledger_row"


@pytest.mark.parametrize(
    "state,verdict,codes,reason",
    [
        (dict(_ROW_D), "confirmed", set(), None),
        ({**_ROW_D, "extensions": {"x-a": 1}}, COULD_NOT_CHECK, set(), _OUTSIDE),
        ({**_ROW_D, "other": 1}, COULD_NOT_CHECK, set(), _OUTSIDE),
        # the optional member cannot hide a mismatch, with or without further extra members
        ({**_ROW, "operation_digest": _D2}, REFUTED, {"operation_digest_mismatch"}, None),
        (
            {**_ROW, "operation_digest": _D2, "other": 1},
            REFUTED,
            {"operation_digest_mismatch"},
            None,
        ),
        (
            {**_ROW, "operation_digest": 7},
            REFUTED,
            {"operation_digest_mismatch"},
            None,
        ),
        (
            {**_ROW, "operation_digest": _D2, "amount": 51.0},
            REFUTED,
            {"operation_digest_mismatch", "observation_differs_from_ledger_row"},
            None,
        ),
        # a differing or missing row member is still refuted, digest equal or not
        (
            {**_ROW_D, "amount": 51.0},
            REFUTED,
            {"observation_differs_from_ledger_row"},
            None,
        ),
        (
            {k: v for k, v in _ROW_D.items() if k != "unit"},
            REFUTED,
            {"observation_differs_from_ledger_row"},
            None,
        ),
        # the row carries a digest the state does not: not compared, never confirmed
        (dict(_ROW), COULD_NOT_CHECK, set(), _MISSING),
        ({**_ROW, "other": 1}, COULD_NOT_CHECK, set(), _OUTSIDE),
    ],
)
def test_observation_state_against_a_row_with_a_digest(
    state: Any, verdict: str, codes: set[str], reason: str | None
) -> None:
    r = ledger._observations_agree(_obs_record(state), _LED_D)
    assert r.verdict == verdict
    assert {f.code for f in r.findings} == codes
    assert r.reason == reason


def test_row_extensions_are_ignored_by_the_observation_check() -> None:
    row = {**_ROW, "extensions": {"x-note": "n"}}
    led = {"effects": {"e1": row}, "grant_effect_counts": {"g": 1}}
    assert ledger._observations_agree(_obs_record(dict(_ROW)), led).verdict == "confirmed"
    equal = ledger._observations_agree(_obs_record(dict(row)), led)
    assert equal.verdict == "confirmed"
    other = ledger._observations_agree(_obs_record({**_ROW, "extensions": {"x-z": 1}}), led)
    assert other.verdict == COULD_NOT_CHECK


def test_a_digest_mismatch_is_refuted_on_every_observation_that_shows_it() -> None:
    record = _obs_record({**_ROW, "operation_digest": _D2})
    record["reconciliations"].append(record["reconciliations"][0])
    r = ledger._observations_agree(record, _LED_D)
    assert [f.code for f in r.findings] == ["operation_digest_mismatch"] * 2
    assert r.tally() == {"confirmed": 0, "could_not_check": 0, "refuted": 2, "n": 2}


def test_observation_with_extra_and_missing_row_each_judged_on_its_own() -> None:
    record = _obs_record({**_ROW, "operation_digest": "x"})
    record["reconciliations"].append(
        {
            "observation_accepted": True,
            "observation": {"state": "applied", "effect_id": "e2", "destination_state": dict(_ROW)},
        }
    )
    r = ledger._observations_agree(record, _LED)
    assert r.verdict == REFUTED
    assert {f.code for f in r.findings} == {"observation_without_ledger_row"}
    assert r.tally() == {"confirmed": 0, "could_not_check": 1, "refuted": 1, "n": 2}

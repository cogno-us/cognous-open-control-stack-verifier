"""Evidence check hardening: cases where a check used to confirm (or fail badly) over input it
could not support. Each case is a valid control that still passes plus the damaged input that
must now be refused or reported as could-not-check, with its stable code."""

from __future__ import annotations

import copy
import itertools
import random
from typing import Any

import pytest

from cognous_verify import engine, ledger, results, rules_lifecycle, sidecar
from cognous_verify.results import COULD_NOT_CHECK, REFUTED

from .helpers import FIXTURES, errors, load, refuted_codes, verify
from .test_orchestrator_runs import ADAPTER, RUNS, _by_check, _evaluate, _json, _refuted
from .test_sidecar import doc_of

LIFECYCLE = FIXTURES / "lifecycle" / "valid"


def lifecycle(name: str) -> dict[str, Any]:
    return copy.deepcopy(load(LIFECYCLE / f"{name}.json")["document"])


def codes(doc: dict[str, Any]) -> set[str]:
    out = verify(doc)
    assert errors(out) == []
    return refuted_codes(out)


# --- attempt lifecycle: identity fixed, terminal states closed, results bound ---------------


def _cp(*statuses: str, **row: Any) -> dict[str, Any]:
    doc = lifecycle("control-plane-normal-attempted-acknowledged")
    base = doc["control_plane_attempts"][0]
    doc["control_plane_attempts"] = [
        {**copy.deepcopy(base), "status": s, "acknowledgement": {}, **row} for s in statuses
    ]
    return doc


@pytest.mark.parametrize(
    "statuses",
    [
        ("attempted", "acknowledged"),
        ("attempted", "failed"),
        ("attempted", "partial"),
        ("attempted", "unknown", "acknowledged"),
        ("attempted", "unknown", "partial"),
        ("attempted", "unknown", "failed"),
    ],
)
def test_valid_control_plane_transitions_pass(statuses: tuple[str, ...]) -> None:
    assert codes(_cp(*statuses)) == set()


@pytest.mark.parametrize(
    "statuses",
    [
        ("attempted", "acknowledged", "acknowledged"),
        ("attempted", "acknowledged", "failed"),
        ("attempted", "failed", "acknowledged"),
        ("attempted", "partial", "acknowledged"),
        ("attempted", "unknown", "unknown"),
        ("attempted", "unknown", "attempted"),
    ],
)
def test_control_plane_attempt_transitions_that_reopen_or_double_close_are_refused(
    statuses: tuple[str, ...],
) -> None:
    doc = _cp(*statuses)
    # make the rows differ so a repeated record is not what refuses it
    for i, row in enumerate(doc["control_plane_attempts"]):
        row["acknowledgement"] = {"n": i} if row["status"] != "attempted" and i else {}
    assert "attempt_transition_invalid" in codes(doc)


def test_control_plane_attempt_cannot_switch_effect_or_decision() -> None:
    doc = _cp("attempted", "acknowledged")
    doc["control_plane_attempts"][1]["effect_id"] = "syn-effect-2"
    assert "attempt_identity_changed" in codes(doc)
    doc = _cp("attempted", "acknowledged")
    doc["control_plane_attempts"][1]["decision_id"] = "syn-decision-2"
    assert "attempt_identity_changed" in codes(doc)


@pytest.mark.parametrize(
    ("events", "valid"),
    [
        (("attempted", "executed"), True),
        (("attempted", "executed", "reconciled"), True),
        (("attempted", "partial", "unknown"), True),
        (("attempted", "unknown", "executed"), True),
        (("attempted", "denied"), True),
        (("attempted", "failed", "executed"), False),
        (("attempted", "denied", "executed"), False),
        (("attempted", "reconciled"), False),
        (("attempted", "executed", "failed"), False),
        (("attempted", "executed", "partial"), False),
        (("attempted", "reconciled", "executed"), False),
    ],
)
def test_executor_event_transitions(events: tuple[str, ...], valid: bool) -> None:
    doc = lifecycle("executor-normal-attempted-executed-observed")
    doc["attempt_events"] = [
        {
            "event_id": i + 1,
            "attempt_id": "syn-attempt-1",
            "status": s,
            "error": None,
            "created_at": 1000.0 + i,
        }
        for i, s in enumerate(events)
    ]
    assert ("attempt_transition_invalid" not in codes(doc)) is valid


@pytest.mark.parametrize("member", ["effect_id", "decision_id"])
def test_result_observation_must_name_the_attempts_effect_and_decision(member: str) -> None:
    doc = lifecycle("executor-normal-attempted-executed-observed")
    assert "result_binding_mismatch" not in codes(doc)
    doc["execution_result"]["observation"][member] = "someone-else"
    assert "result_binding_mismatch" in codes(doc)


# --- acknowledgements: a fresh claim is counted in either shape, nothing comparable abstains --


def _adapter(name: str = "adapter-applied") -> tuple[dict[str, Any], bytes]:
    d = RUNS / name
    return (
        copy.deepcopy(load(d / "bounded-run-record.json")),
        (d / "destination-with-operation-digest.json").read_bytes(),
    )


def _eval(record: dict[str, Any], led: bytes, name: str = "adapter-applied") -> engine.Evaluation:
    return _evaluate(name, run_record=_json(record), destination_ledger=led)


def _ack_check(ev: engine.Evaluation) -> results.CheckResult:
    return _by_check(ev)["v4.ledger.acknowledged-attempts-have-rows"]


def _fresh_rows(record: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        a
        for a in record["attempts"]
        if a["status"] == "acknowledged" and a["acknowledgement"].get("newly_executed") is True
    ]


def test_clean_adapter_acknowledgements_are_confirmed_against_the_row() -> None:
    record, led = _adapter()
    assert _ack_check(_eval(record, led)).verdict == "confirmed"


def test_a_second_newly_executed_acknowledgement_is_a_duplicate_effect() -> None:
    record, led = _adapter()
    dup = copy.deepcopy(_fresh_rows(record)[0])
    dup["acknowledgement"]["attempt_id"] = "00000000-0000-0000-0000-0000000000ff"
    record["attempts"].append(dup)
    ev = _eval(record, led)
    assert ev.overall == "reject"
    assert "fresh_acknowledgement_repeated" in {f.code for f in _ack_check(ev).findings}
    counters = ledger.counters(record, {"effects": {}})
    assert counters["excess_duplicate_effects"] >= 1


def test_contradictory_freshness_flags_are_refuted() -> None:
    record, led = _adapter()
    _fresh_rows(record)[0]["acknowledgement"]["duplicate"] = True
    ev = _eval(record, led)
    assert "acknowledgement_flags_contradict" in {f.code for f in _ack_check(ev).findings}


def test_an_acknowledgement_with_nothing_comparable_is_could_not_check() -> None:
    record, led = _adapter()
    _fresh_rows(record)[0]["acknowledgement"] = {}
    check = _ack_check(_eval(record, led))
    assert check.verdict == COULD_NOT_CHECK
    assert check.reason == "no_comparable_receipt"


def test_acknowledged_observation_that_differs_from_the_row_is_refuted() -> None:
    record, led = _adapter()
    state = _fresh_rows(record)[0]["acknowledgement"]["observation"]["destination_state"]
    state["amount"] = 999999
    assert "observation_differs_from_ledger_row" in {
        f.code for f in _ack_check(_eval(record, led)).findings
    }


def test_acknowledged_observation_naming_another_effect_is_refuted() -> None:
    record, led = _adapter()
    _fresh_rows(record)[0]["acknowledgement"]["observation"]["effect_id"] = "sha256:" + "0" * 64
    assert "acknowledgement_differs_from_ledger_row" in {
        f.code for f in _ack_check(_eval(record, led)).findings
    }


@pytest.mark.parametrize("name", ADAPTER)
def test_clean_adapter_runs_still_have_no_refutation(name: str) -> None:
    record, led = _adapter(name)
    assert _refuted(_eval(record, led, name)) == {}


# --- V-0: a tenant carried by one side only is a difference ----------------------------------


def test_tenant_on_only_the_binding_side_is_refuted() -> None:
    d = RUNS / "adapter-applied"
    record = copy.deepcopy(load(d / "bounded-run-record.json"))
    for dec in record["decisions"]:
        if isinstance(dec.get("binding"), dict):
            dec["binding"]["tenant_id"] = "tenant-added"
    ev = _evaluate("adapter-applied", run_record=_json(record))
    assert "binding_proposal_mismatch" in {
        f.code for r in ev.results for f in r.findings if r.verdict == REFUTED
    }


# --- profile rules ---------------------------------------------------------------------------


def test_an_operation_profile_with_no_operation_rows_confirms_nothing() -> None:
    doc = doc_of("profile-op-normal")
    for name in sidecar.OPERATION_LISTS:
        doc[name] = []
    for d in doc["decisions"]:
        ext = (d.get("binding") or {}).get("runtime_authority") or {}
        ext.pop("operation_id", None)
        ext.pop("operation_issuer", None)
    doc["operations"] = []
    out = [r for r in verify(doc) if r.check_id == sidecar.OPERATION_CHECK]
    assert [r.verdict for r in out] == [COULD_NOT_CHECK]
    assert out[0].reason == "operation_profile_without_operation_rows"


def test_an_expired_check_needs_the_failed_attempt_its_join_names() -> None:
    doc = doc_of("profile-expired-with-operation-join")
    assert not [r for r in verify(doc) if r.verdict == REFUTED]
    # an unrelated failed attempt for the same effect must not stand in for the joined one
    joined = {j["attempt_id"] for j in doc["attempt_joins"]}
    for a in doc["attempts"]:
        if a["attempt_id"] in joined:
            a["error"] = "other_error"
    extra = copy.deepcopy(doc["attempts"][0])
    extra["attempt_id"] = "unrelated-attempt"
    extra["status"] = "failed"
    extra["error"] = sidecar.CODE_EXPIRED
    doc["attempts"].append(extra)
    assert "expired_without_failed_attempt" in {
        f.code for r in verify(doc) for f in r.findings
    } or "expired_check_dispatched" in {f.code for r in verify(doc) for f in r.findings}


def test_a_dispatch_after_expiry_needs_the_expiry_error_not_any_failure() -> None:
    doc = doc_of("profile-expired-with-operation-join")
    for a in doc["attempts"]:
        if a.get("error") == sidecar.CODE_EXPIRED:
            a["error"] = "something_else"
    assert any(
        f.code in {"expired_check_dispatched", "expired_without_failed_attempt"}
        for r in verify(doc)
        for f in r.findings
    )


def test_refusal_rows_are_ordered_against_their_evaluation_pass() -> None:
    doc = doc_of("profile-expired-before-dispatch")
    rows = [r for r in doc.get("refusals", []) if "evaluated_at" in r and "recorded_at" in r]
    if not rows:
        pytest.skip("fixture carries no clocked refusal")
    rows[0]["recorded_at"] = "1999-01-01T00:00:00+00:00"
    assert "recorded_before_evaluated" in {f.code for r in verify(doc) for f in r.findings}


def test_recovery_run_ids_must_be_strings() -> None:
    doc = doc_of("profile-reaper-closes-the-dead-and-reports-the-late")
    run = doc["recovery_runs"][0]
    run["interrupted"] = [["not", "a", "string"]]
    out = verify(doc)
    assert errors(out) == []
    assert "schema_violation" in refuted_codes(out)


# --- resource bounds -------------------------------------------------------------------------


def _journal(n: int) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    events: list[dict[str, Any]] = []
    checks: list[dict[str, Any]] = []
    base = {
        "owner": "o",
        "stage": "s",
        "proposal_commitment": "p",
        "decision_id": "d",
        "effect_id": "e",
        "action_class": "a",
    }
    for i in range(n):
        cid = f"c{i}"
        events.append({"check_id": cid, "phase": "opened", **base, "input": None, "reasons": []})
        events.append({"check_id": cid, "phase": "completed", **base, "input": None, "reasons": []})
        checks.append({"check_id": cid, "stage": "s", "inputs": [], "reasons": []})
    return events, checks


def test_many_identical_checks_do_not_exhaust_the_stack() -> None:
    events, checks = _journal(1500)
    # 1500 identical completions against 1500 identical checks: matching must not recurse
    assert rules_lifecycle.journal(events, checks, "$.j") == []
    assert rules_lifecycle.journal(events, checks[:-1], "$.j") != []


def test_matching_agrees_with_brute_force() -> None:
    rng = random.Random(7)  # noqa: S311  (test data only)
    for _ in range(300):
        n = rng.randint(1, 5)
        cands = [sorted(rng.sample(range(n + 1), rng.randint(1, n + 1))) for _ in range(n)]
        brute = any(len(set(p)) == n for p in itertools.product(*cands))
        assert rules_lifecycle._all_matched(cands) is brute


def test_journal_beyond_the_completion_limit_is_could_not_check() -> None:
    events, checks = _journal(rules_lifecycle.JOURNAL_COMPLETION_LIMIT + 1)
    with pytest.raises(rules_lifecycle.LimitExceeded):
        rules_lifecycle.journal(events, checks, "$.j")


def test_findings_per_check_are_capped_and_counted() -> None:
    many = [results.Finding("c", f"$.rows[{i}]", "m") for i in range(1000)]
    r = results.make_result("x", "V2", "rows", 1000, many)
    assert len(r.findings) == results.FINDINGS_CAP
    assert r.omitted_findings == 1000 - results.FINDINGS_CAP
    assert r.tally()["refuted"] == 1000
    assert r.as_dict()["omitted_findings"] == r.omitted_findings
    few = results.make_result("x", "V2", "rows", 1000, many[:3])
    assert few.omitted_findings == 0
    assert "omitted_findings" not in few.as_dict()


def test_refuted_items_never_exceed_the_items_checked() -> None:
    many = [results.Finding("c", f"$.rows[{i}]", "m") for i in range(5)]
    r = results.make_result("x", "V3", "documents", 1, many)
    assert r.tally() == {"confirmed": 0, "could_not_check": 0, "refuted": 1, "n": 1}


def test_repeated_control_plane_rows_are_found_without_pairwise_scans() -> None:
    doc = _cp("attempted", "acknowledged")
    rows = doc["control_plane_attempts"]
    assert "repeated_record" not in codes(doc)
    rows.append(copy.deepcopy(rows[0]))
    assert "repeated_record" in codes(doc)


def test_witness_hashes_only_the_requested_prefix() -> None:
    from cognous_verify import witness

    rows = [{"n": i} for i in range(10)]
    assert witness.chain_heads(rows, 3) == witness.chain_heads(rows)[:4]

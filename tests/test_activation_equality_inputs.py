"""Freshness activation, type-strict equality, singleton inputs and zero-item profile checks.

* ``freshness_activation``: a nested ``read_state == "nonce_mismatch"`` switches the freshness
  suite on, so a record cannot show a nonce-mismatched read under an authorized decision and
  still be accepted.
* ``typed_const``: schema constants and enumerations, and the equality the record rules use for
  compared members, are type-strict (``1`` is not ``true``, ``50`` is not ``50.0``).
* ``singleton_inputs``: an input role that may be given once is refused when given twice,
  whatever the order.
* ``zero_items``: a profile check over zero items is never confirmed; it reports could-not-check
  with the reason ``no_items_in_record`` and a denominator of zero.
* an acknowledgement whose receipt cannot be compared completely is reported as unavailable.
"""

from __future__ import annotations

import copy
import json
from typing import Any

import pytest

from cognous_verify import canon, cli, engine, ledger, schema, sidecar
from cognous_verify.results import CONFIRMED, COULD_NOT_CHECK

from .helpers import DATA, fixture_paths, load, real_record, refuted_codes, verify

RUNS = DATA / "orchestrator-runs"


def _fixture(stem: str, kind: str = "journal") -> dict[str, Any]:
    path = next(p for p in fixture_paths(kind, "valid") if p.stem == stem)
    doc: dict[str, Any] = copy.deepcopy(load(path)["document"])
    return doc


def _codes(doc: Any) -> set[str]:
    return refuted_codes(verify(doc))


# ---------------------------------------------------------------- freshness_activation


def _nonce_mismatched(doc: dict[str, Any]) -> dict[str, Any]:
    """Mark the grant read nonce_mismatch in every copy of it (decision, check, journal)."""

    def mark(x: dict[str, Any]) -> None:
        if x["input_type"] == "grant":
            x["read_state"] = "nonce_mismatch"
            x["age_basis"] = "nonce_bound"

    for d in doc["decisions"]:
        for x in d["resolution_inputs"]:
            mark(x)
    for c in doc["resolution_checks"]:
        for x in c["inputs"]:
            mark(x)
    for e in doc["check_events"]:
        if e["input"] is not None:
            mark(e["input"])
    return doc


def test_nested_nonce_mismatch_under_an_authorized_decision_is_refused() -> None:
    doc = _nonce_mismatched(_fixture("normal-attempted-acknowledged-applied"))
    assert all(d["result"] == "authorized" for d in doc["decisions"])
    assert "nonce_reason_mismatch" in _codes(doc)


def test_nested_nonce_mismatch_switches_the_freshness_suite_on() -> None:
    doc = _nonce_mismatched(_fixture("normal-attempted-acknowledged-applied"))
    assert sidecar.freshness_active(doc)


def test_a_default_record_does_not_activate_the_freshness_suite() -> None:
    assert not sidecar.freshness_active(_fixture("normal-attempted-acknowledged-applied"))


def test_a_valid_nonce_replay_record_stays_valid() -> None:
    assert _codes(_fixture("profile-nonce-replay-rejected")) == set()


# ---------------------------------------------------------------- typed_const


def _violations(value: Any, schema_doc: dict[str, Any]) -> list[str]:
    return [f.code for f in schema.validate_structure(value, schema_doc)]


@pytest.mark.parametrize(
    "const,value",
    [(1, True), (True, 1), (0, False), (1, 1.0), (60, 60.0), ("1", 1), (None, False)],
)
def test_const_is_type_strict(const: Any, value: Any) -> None:
    assert _violations(value, {"const": const}) == ["schema_violation"]
    assert _violations(const, {"const": const}) == []


@pytest.mark.parametrize("option,value", [(1, True), (0, False), (60, 60.0)])
def test_enum_is_type_strict(option: Any, value: Any) -> None:
    assert _violations(value, {"enum": [option]}) == ["unknown_enum_value"]
    assert _violations(option, {"enum": [option]}) == []


def test_numeric_forms_differ_in_the_canonical_form() -> None:
    assert canon.commitment(50) != canon.commitment(50.0)
    assert canon.commitment(1) != canon.commitment(True)


def test_same_json_is_type_strict() -> None:
    assert canon.same_json({"a": [1, {"b": 2.5}]}, {"a": [1, {"b": 2.5}]})
    assert not canon.same_json(1, True)
    assert not canon.same_json(50, 50.0)
    assert not canon.same_json({"a": 1}, {"a": True})
    assert not canon.same_json([1], [1.0])
    assert not canon.same_json("1", 1)


def _applied_state(doc: dict[str, Any]) -> dict[str, Any]:
    state: dict[str, Any] = next(
        o["destination_state"] for o in doc["observations"] if o["destination_state"]
    )
    return state


def test_observation_copy_with_a_different_number_form_is_not_the_reconciled_one() -> None:
    doc = _fixture("normal-attempted-acknowledged-applied")
    state = _applied_state(doc)
    assert isinstance(state["amount"], float)
    state["amount"] = int(state["amount"])
    assert "observations_mismatch" in _codes(doc)


def test_observation_copy_with_a_boolean_for_a_number_is_not_the_reconciled_one() -> None:
    doc = _fixture("normal-attempted-acknowledged-applied")
    _applied_state(doc)["amount"] = True
    assert "observations_mismatch" in _codes(doc)


def test_lifecycle_observation_copy_with_a_different_number_form_is_refused() -> None:
    doc = _fixture("executor-normal-observations-member", "lifecycle")
    obs = doc["observations"][0]
    obs["destination_state"] = {"amount": 50.0}
    doc["execution_result"]["observation"]["destination_state"] = {"amount": 50}
    assert "observations_mismatch" in _codes(doc)


# ---------------------------------------------------------------- singleton_inputs


def _two(role: str, order: str) -> list[engine.InputFile]:
    record = json.dumps(_fixture("normal-attempted-acknowledged-applied")).encode()
    extra = json.dumps({"effects": {}, "grant_effect_counts": {}}).encode()
    a = engine.InputFile(role, "one.json", extra)
    b = engine.InputFile(role, "two.json", extra)
    rec = engine.InputFile("run_record", "record.json", record)
    return [rec, a, b] if order == "after" else [a, rec, b] if order == "between" else [a, b, rec]


@pytest.mark.parametrize("role", ["manifest", "destination_ledger", "witness", "holder_inventory"])
@pytest.mark.parametrize("order", ["after", "between", "before"])
def test_a_second_singleton_input_is_refused_whatever_the_order(role: str, order: str) -> None:
    with pytest.raises(ValueError, match="at most one"):
        engine.evaluate(_two(role, order))


def test_two_run_records_are_still_refused() -> None:
    record = json.dumps(_fixture("normal-attempted-acknowledged-applied")).encode()
    files = [engine.InputFile("run_record", f"{i}.json", record) for i in range(2)]
    with pytest.raises(ValueError, match="run_record"):
        engine.evaluate(files)


def test_an_unknown_role_is_refused() -> None:
    record = json.dumps(_fixture("normal-attempted-acknowledged-applied")).encode()
    files = [
        engine.InputFile("run_record", "r.json", record),
        engine.InputFile("labels", "l.json", b"{}"),
    ]
    with pytest.raises(ValueError, match="role"):
        engine.evaluate(files)


def test_proposal_exports_may_be_given_more_than_once() -> None:
    record = json.dumps(_fixture("normal-attempted-acknowledged-applied")).encode()
    files = [
        engine.InputFile("run_record", "r.json", record),
        engine.InputFile("proposal_export", "p1.json", b"{}"),
        engine.InputFile("proposal_export", "p2.json", b"{}"),
    ]
    engine.evaluate(files)


@pytest.mark.parametrize("flag", ["--manifest", "--ledger", "--witness", "--holder-inventory"])
def test_the_command_line_refuses_a_repeated_singleton_flag(
    flag: str, tmp_path: Any, capsys: Any
) -> None:
    record = tmp_path / "record.json"
    record.write_text(json.dumps(_fixture("normal-attempted-acknowledged-applied")))
    one, two = tmp_path / "one.json", tmp_path / "two.json"
    one.write_text("{}")
    two.write_text("{ }")
    assert cli.main([str(record), flag, str(one), flag, str(two)]) == cli.EXIT_USAGE
    assert "more than once" in capsys.readouterr().err


# ---------------------------------------------------------------- zero_items


@pytest.mark.parametrize("member", ["rule_revisions", "rule_revision_refusals"])
def test_an_empty_rule_revision_list_confirms_nothing(member: str) -> None:
    doc = _fixture("normal-attempted-acknowledged-applied")
    doc[member] = []
    out = [r for r in verify(doc) if r.check_id == sidecar.RULE_CHECK]
    assert len(out) == 1
    assert out[0].verdict == COULD_NOT_CHECK
    assert out[0].reason == "no_items_in_record"
    assert (out[0].total, out[0].checked) == (0, 0)


@pytest.mark.parametrize("member", ["age_extensions", "age_extension_refusals", "recovery_runs"])
def test_an_empty_freshness_list_confirms_nothing(member: str) -> None:
    doc = copy.deepcopy(real_record("default-applied"))  # no journal rows to count
    doc[member] = []
    out = [r for r in verify(doc) if r.check_id == sidecar.FRESHNESS_CHECK]
    assert len(out) == 1
    assert out[0].verdict == COULD_NOT_CHECK
    assert out[0].reason == "no_items_in_record"
    assert (out[0].total, out[0].checked) == (0, 0)


def test_an_empty_profile_check_is_listed_as_not_applicable_not_as_a_result() -> None:
    doc = _fixture("normal-attempted-acknowledged-applied")
    doc["rule_revisions"] = []
    record = json.dumps(doc).encode()
    ev = engine.evaluate([engine.InputFile("run_record", "r.json", record)])
    assert sidecar.RULE_CHECK not in {r.check_id for r in ev.results}
    assert sidecar.RULE_CHECK in {x["check_id"] for x in ev.not_applicable}


def test_a_profile_check_over_real_rows_still_confirms() -> None:
    out = [r for r in verify(_fixture("profile-rule-reports")) if r.check_id == sidecar.RULE_CHECK]
    assert out and out[0].verdict == CONFIRMED and out[0].total >= 1


# ---------------------------------------------------------------- acknowledgement comparison


def _adapter() -> tuple[dict[str, Any], dict[str, Any]]:
    d = RUNS / "adapter-applied"
    return (
        copy.deepcopy(load(d / "bounded-run-record.json")),
        copy.deepcopy(load(d / "destination-with-operation-digest.json")),
    )


def _ack_result(record: Any, led: Any) -> Any:
    return {r.check_id: r for r in ledger.run(record, led)}[
        "v4.ledger.acknowledged-attempts-have-rows"
    ]


def test_acknowledged_observation_with_a_member_outside_the_row_is_unavailable() -> None:
    record, led = _adapter()
    ack = next(
        a["acknowledgement"]
        for a in record["attempts"]
        if a["status"] == "acknowledged" and "observation" in a["acknowledgement"]
    )
    ack["observation"]["destination_state"]["note"] = "extra member the row does not hold"
    result = _ack_result(record, led)
    assert result.verdict == COULD_NOT_CHECK
    assert result.reason == "no_comparable_receipt"


def test_acknowledged_observation_equal_to_the_row_is_confirmed() -> None:
    record, led = _adapter()
    assert _ack_result(record, led).verdict == CONFIRMED

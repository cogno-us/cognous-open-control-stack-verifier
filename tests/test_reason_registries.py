"""Two reason registries, each row resolved by the label it names (registry follow-up from N4)."""

from __future__ import annotations

import copy
from typing import Any

from cognous_verify import data, identity, rules_journal

from .helpers import fixture_paths, load

V01 = "runtime-authority-reasons/0.1"
V02 = "runtime-authority-reasons/0.2"


def _held_record() -> dict[str, Any]:
    for path in fixture_paths("journal", "valid"):
        doc: dict[str, Any] = copy.deepcopy(load(path)["document"])
        if any(d["reasons"] and "reason_vocabulary_version" in d for d in doc["decisions"]):
            return doc
    raise AssertionError("no held fixture with a vocabulary label")


def _run(doc: dict[str, Any]) -> list[tuple[str, str]]:
    result = identity._reason_registry(doc)
    return [(f.code, f.path) for f in result.findings]


def _target(doc: dict[str, Any]) -> dict[str, Any]:
    return next(d for d in doc["decisions"] if d["reasons"] and "reason_vocabulary_version" in d)


def _only_in_02() -> str:
    return sorted(data.registry_codes(V02) - data.registry_codes(V01))[0]


def test_default_label_rows_are_unchanged() -> None:
    assert _run(_held_record()) == []


def test_a_02_only_code_under_a_01_label_is_refused() -> None:
    doc = _held_record()
    row = _target(doc)
    row["reasons"] = [_only_in_02()]
    findings = _run(doc)
    assert [c for c, _ in findings] == ["reason_code_unregistered"]


def test_a_02_only_code_under_a_02_label_is_accepted() -> None:
    doc = _held_record()
    row = _target(doc)
    row["reason_vocabulary_version"] = V02
    row["reasons"] = [_only_in_02()]
    assert _run(doc) == []


SCAN3_CODES = (
    "action_blocked",
    "missing_effect_limits",
    "missing_amount_limit",
    "effect_limit_malformed",
    "authority_limit_malformed",
)


def test_the_scan_3_default_path_codes_resolve_under_a_02_label_and_not_a_01_label() -> None:
    """Control Plane 5c474ba8 stamps label 0.2 on a row carrying one of these (a real hold with action_blocked was checked)."""
    for code in SCAN3_CODES:
        doc = _held_record()
        row = _target(doc)
        row["reason_vocabulary_version"] = V02
        row["reasons"] = [code]
        assert _run(doc) == [], code
        row["reason_vocabulary_version"] = V01
        assert [c for c, _ in _run(doc)] == ["reason_code_unregistered"], code


def test_a_02_label_still_refuses_a_code_in_neither_registry() -> None:
    doc = _held_record()
    row = _target(doc)
    row["reason_vocabulary_version"] = V02
    row["reasons"] = ["not_a_registered_code"]
    assert [c for c, _ in _run(doc)] == ["reason_code_unregistered"]


def test_an_unknown_label_is_flagged_and_its_codes_are_not_judged() -> None:
    doc = _held_record()
    row = _target(doc)
    row["reason_vocabulary_version"] = "runtime-authority-reasons/0.3"
    row["reasons"] = ["not_a_registered_code"]
    assert [c for c, _ in _run(doc)] == ["reason_vocabulary_unknown"]


def test_refusal_rows_resolve_by_their_own_label() -> None:
    doc = _held_record()
    doc["refusals"] = [
        {"reasons": [_only_in_02()], "reason_vocabulary_version": V02},
        {"reasons": [_only_in_02()], "reason_vocabulary_version": V01},
    ]
    assert _run(doc) == [("reason_code_unregistered", "$.refusals[1].reasons")]


def test_the_check_notes_name_both_digests() -> None:
    notes = identity._reason_registry(_held_record()).notes
    assert [n.split()[1] for n in notes] == [V01, V02]


# ----------------------------------------------------------------- journal rule reason_label_mismatch


def _label_findings(doc: dict[str, Any]) -> list[tuple[str, str]]:
    return [
        (f.code, f.path)
        for f in rules_journal.journal_mode(doc)
        if f.code == "reason_label_mismatch"
    ]


def test_the_zero_two_only_set_is_the_registry_difference_and_has_42_codes() -> None:
    only_02 = data.registry_codes(V02) - data.registry_codes(V01)
    assert len(only_02) == 42
    assert {
        "action_blocked",
        "missing_effect_limits",
        "missing_amount_limit",
        "effect_limit_malformed",
        "authority_limit_malformed",
    } <= only_02  # Control Plane 5c474ba8 (scan 3)
    assert "grant_revocation_recorded" in only_02  # ODES #94, Control Plane 6b8fb627
    assert "grant_revocation_recorded" not in data.registry_codes(V01)


def test_label_rule_refuses_a_zero_two_code_under_a_zero_one_label_in_every_section() -> None:
    doc = _held_record()
    code = _only_in_02()
    _target(doc)["reasons"] = [code]
    doc["refusals"] = [{"reasons": [code], "reason_vocabulary_version": V01}]
    doc["check_events"] = [{"reasons": [code], "reason_vocabulary_version": V01}]
    paths = [p for _, p in _label_findings(doc)]
    assert sorted(p.split("[")[0] for p in paths) == ["$.check_events", "$.decisions", "$.refusals"]


def test_label_rule_accepts_the_zero_two_label_and_zero_one_codes_under_either() -> None:
    doc = _held_record()
    row = _target(doc)
    row["reason_vocabulary_version"] = V02
    row["reasons"] = [_only_in_02()]
    assert _label_findings(doc) == []
    row["reasons"] = ["grant_revoked"]
    assert _label_findings(doc) == []
    row["reason_vocabulary_version"] = V01
    assert _label_findings(doc) == []


def test_label_rule_does_not_judge_codes_in_neither_registry() -> None:
    doc = _held_record()
    row = _target(doc)
    row["reason_vocabulary_version"] = V01
    row["reasons"] = ["not_a_registered_code"]
    assert _label_findings(doc) == []

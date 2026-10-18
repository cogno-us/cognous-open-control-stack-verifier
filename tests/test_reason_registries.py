"""Two reason registries, each row resolved by the label it names (registry follow-up from N4)."""

from __future__ import annotations

import copy
from typing import Any

from cognous_verify import data, identity

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

"""The engine joins the tiers: inputs, partition of not-applicable checks, overall, counters."""

from __future__ import annotations

import json

import pytest

from cognous_verify import engine
from cognous_verify.canon import commitment

from . import damage
from .damage import LEDGER, MANIFEST, PROPOSAL, RECORD, ROLE_OF


def _files(case: damage.Case, roles: tuple[str, ...]) -> list[engine.InputFile]:
    return [engine.InputFile(ROLE_OF[r], r + ".json", case.files[r]) for r in roles]


CASES = {c.name: c for c in damage.load_corpus()}


def test_record_alone_abstains_and_names_missing_inputs() -> None:
    ev = engine.evaluate(_files(CASES["journal-applied"], (RECORD,)))
    assert ev.overall == "abstain"
    reasons = {r.check_id: r.reason for r in ev.results if r.verdict == "could_not_check"}
    assert reasons["v4.ledger.counts"] == "input_absent:destination_ledger"
    assert any(r.check_id == "v2.identity.proposal-commitment" for r in ev.results)


def test_all_inputs_accept_and_zero_item_checks_are_not_applicable() -> None:
    ev = engine.evaluate(_files(CASES["default-held"], (RECORD, PROPOSAL, MANIFEST, LEDGER)))
    assert ev.overall == "accept"
    assert all(r.verdict == "confirmed" for r in ev.results)
    assert {n["reason"] for n in ev.not_applicable} <= set(engine.NOT_APPLICABLE_REASONS)
    assert ev.not_applicable, "a hold run has checks with nothing to examine"
    assert ev.counters is not None
    assert ev.counters["unauthorized_effects"] == 0 and ev.counters["excess_duplicate_effects"] == 0
    assert any("completeness" in n.lower() for n in ev.notes)


def test_inputs_rows_are_sorted_and_committed() -> None:
    ev = engine.evaluate(_files(CASES["journal-applied"], (LEDGER, RECORD, PROPOSAL, MANIFEST)))
    keys = [(r["role"], r["name"], r["digest"]) for r in ev.inputs]
    assert keys == sorted(keys)
    assert engine.inputs_commitment(ev.inputs) == commitment(ev.inputs)
    assert all(set(r) == {"role", "name", "digest", "size_bytes"} for r in ev.inputs)


def test_exactly_one_record_is_required() -> None:
    with pytest.raises(ValueError):
        engine.evaluate([])
    two = _files(CASES["default-held"], (RECORD,)) * 2
    with pytest.raises(ValueError):
        engine.evaluate(two)


def test_unparseable_record_is_refuted_at_v1_and_nothing_else_runs() -> None:
    bad = engine.InputFile("run_record", "r.json", b'{"a": 1, "a": 2}')
    ev = engine.evaluate([bad])
    assert ev.overall == "reject"
    assert next(r.check_id for r in ev.results) == "v1.wire.strict-parse"
    assert any(r.reason == "tier_unavailable:run_record_not_parsed" for r in ev.results)


def test_unparseable_ledger_and_proposal_make_dependent_checks_unavailable() -> None:
    case = CASES["journal-applied"]
    files = _files(case, (RECORD, MANIFEST))
    files.append(engine.InputFile("proposal_export", "p.json", b"{nope"))
    files.append(engine.InputFile("destination_ledger", "l.json", b"\xff"))
    ev = engine.evaluate(files)
    assert ev.overall == "reject"
    reasons = {r.reason for r in ev.results if r.verdict == "could_not_check"}
    assert "tier_unavailable:proposal_not_usable" in reasons
    assert "tier_unavailable:ledger_not_parsed" in reasons


def test_wrong_shape_ledger_skips_the_rest_of_v4() -> None:
    case = CASES["journal-applied"]
    files = _files(case, (RECORD, PROPOSAL, MANIFEST))
    files.append(engine.InputFile("destination_ledger", "l.json", b"[1]"))
    ev = engine.evaluate(files)
    assert ev.overall == "reject"
    assert any(r.reason == "tier_unavailable:ledger_shape_refuted" for r in ev.results)


def test_structure_refuted_record_skips_dependent_checks() -> None:
    case = CASES["journal-applied"]
    rec = case.doc(RECORD)
    rec["decisions"][0]["surprise"] = 1
    mutated = case.with_doc(RECORD, rec)
    ev = engine.evaluate(_files(mutated, (RECORD, PROPOSAL, MANIFEST, LEDGER)))
    assert ev.overall == "reject"
    assert any(r.reason == "tier_unavailable:structure_refuted" for r in ev.results)


def test_a_non_control_plane_document_gets_a_note_not_identity_checks() -> None:
    doc = json.dumps({"contract": "execution-attempt-lifecycle", "contract_version": "0.1.0-draft"})
    ev = engine.evaluate([engine.InputFile("run_record", "r.json", doc.encode())])
    assert not any(r.check_id.startswith("v4.") for r in ev.results)
    assert any("control-plane run records only" in n for n in ev.notes)


def test_manifest_must_be_an_object() -> None:
    case = CASES["journal-applied"]
    mutated = case.with_bytes(MANIFEST, b"[]")
    ev = engine.evaluate(_files(mutated, (RECORD, PROPOSAL, MANIFEST, LEDGER)))
    assert "manifest_shape" in damage.refuting_codes(ev)


def test_counters_are_recomputed_from_the_ledger() -> None:
    case = CASES["journal-applied"]
    led = case.doc(LEDGER)
    row = next(iter(led["effects"].values()))
    ghost = dict(row, effect_id="sha256:" + "99" * 32)
    led["effects"][ghost["effect_id"]] = ghost
    led["grant_effect_counts"][row["grant_id"]] += 1
    mutated = case.with_doc(LEDGER, led)
    ev = engine.evaluate(_files(mutated, (RECORD, PROPOSAL, MANIFEST, LEDGER)))
    assert ev.overall == "reject"
    assert ev.counters is not None and ev.counters["unauthorized_effects"] == 1


def test_overall_is_never_a_score() -> None:
    ev = engine.Evaluation(results=[], inputs=[])
    assert ev.overall == "abstain"

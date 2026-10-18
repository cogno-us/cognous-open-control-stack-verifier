"""Tier V3: witness re-derivation, against real witnesses written by the control plane.

Inputs are real: ``acp witness publish`` over every retained record, and fresh runs with the
digest published at stated points (tools/capture_witnessed_runs.py). The control plane's own
verifier (``verify_against_witness``) was replayed over the same damage, and its verdicts are
stored in ``tests/data/witnesses/cp-differential.json``: the differential test below compares the
verifier with them case by case. There is no ODES contract for the witness or the inventory, so
there are no ODES fixtures for this tier (see docs/tiers.md).
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest

from cognous_verify import engine, report, witness
from cognous_verify.canon import commitment
from cognous_verify.results import CONFIRMED, COULD_NOT_CHECK, REFUTED, CheckResult

from . import witness_mutations as mut
from .helpers import DATA, load

WITNESSES = DATA / "witnesses"
RUNS = DATA / "witnessed-runs"
INDEX = json.loads((WITNESSES / "INDEX.json").read_text())["entries"]
DIFF = json.loads((WITNESSES / "cp-differential.json").read_text())["cases"]
WITNESS_CODES = {
    "witness_chain_invalid",
    "witness_run_mismatch",
    "witness_ledger_shrunk",
    "witness_ledger_head_mismatch",
}


def _paths(name: str) -> tuple[Path, Path]:
    source, _, leaf = name.partition("/")
    if source == "witnessed-runs":
        return RUNS / leaf / "bounded-run-record.json", RUNS / leaf / "witness.jsonl"
    return DATA / source / leaf / "bounded-run-record.json", (
        WITNESSES / source / leaf / "witness.jsonl"
    )


SETS = sorted(INDEX)


def _resign(rec: dict[str, Any]) -> str:
    return commitment({k: v for k, v in rec.items() if k != "digest"})


def _lines(recs: list[dict[str, Any]]) -> bytes:
    return "".join(
        json.dumps(r, sort_keys=True, separators=(",", ":")) + "\n" for r in recs
    ).encode()


def _load_set(name: str) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    rec_path, wit_path = _paths(name)
    doc = load(rec_path)
    recs = [json.loads(x) for x in wit_path.read_text().splitlines() if x.strip()]
    return doc, recs


def _checks(doc: dict[str, Any], data: bytes) -> dict[str, CheckResult]:
    return {r.check_id: r for r in witness.witness_checks(doc, data)}


def _codes(results: dict[str, CheckResult]) -> set[str]:
    return {f.code for r in results.values() for f in r.findings}


def _verdicts(results: dict[str, CheckResult]) -> dict[str, str]:
    return {k: r.verdict for k, r in results.items()}


# ---------------------------------------------------------------------------------- clean runs


def test_corpus_size_is_what_the_docs_say() -> None:
    assert len(SETS) == 25
    assert len(DIFF) == 898


@pytest.mark.parametrize("name", SETS)
def test_real_witnesses_of_real_runs_are_confirmed(name: str) -> None:
    doc, _ = _load_set(name)
    results = _checks(doc, _paths(name)[1].read_bytes())
    assert [r.check_id for r in results.values()] == [c for c, _ in witness.WITNESS_CHECK_IDS]
    assert _verdicts(results) == dict.fromkeys(results, CONFIRMED)
    for r in results.values():
        assert r.checked == r.total and r.total > 0


def test_clean_witnessed_run_is_accepted_end_to_end() -> None:
    d = DATA / "real-runs" / "journal-applied"
    files = [
        engine.InputFile("run_record", "r.json", (d / "bounded-run-record.json").read_bytes()),
        engine.InputFile("proposal_export", "p.json", (d / "proposal.json").read_bytes()),
        engine.InputFile("manifest", "m.json", (d / "manifest.json").read_bytes()),
        engine.InputFile("destination_ledger", "l.json", (d / "destination.json").read_bytes()),
    ]
    base = engine.evaluate(files)
    assert base.overall == "accept"
    wit = (WITNESSES / "real-runs" / "journal-applied" / "witness.jsonl").read_bytes()
    ev = engine.evaluate([*files, engine.InputFile("witness", "w.jsonl", wit)])
    assert ev.overall == "accept"
    assert ev.v3 is not None and ev.v3.requested
    assert all(r.verdict == CONFIRMED for r in ev.v3.results)
    assert [i["role"] for i in ev.v3.inputs] == ["witness"]
    # the witness is a report input (role witness): inputs_digest covers it
    assert {r["role"] for r in ev.inputs} == {
        "run_record",
        "proposal_export",
        "manifest",
        "destination_ledger",
        "witness",
    }


def test_two_publications_are_both_checked() -> None:
    doc, recs = _load_set("witnessed-runs/staged-journal-applied")
    assert len(recs) == 2 and recs[1]["previous_digest"] == recs[0]["digest"]
    results = _checks(doc, _lines(recs))
    assert results["v3.witness.ledger-heads"].total == 2
    assert (
        "ledger heads re-derived over 2 witness records"
        in results["v3.witness.ledger-heads"].notes[0]
    )


def test_rows_after_the_latest_digest_are_not_intact() -> None:
    d = RUNS / "staged-journal-applied"
    doc = load(d / "bounded-run-record.json")
    results = _checks(doc, (d / "witness-first-only.jsonl").read_bytes())
    assert _codes(results) == set()
    cov = results["v3.witness.coverage"]
    assert cov.verdict == COULD_NOT_CHECK and cov.skipped > 0
    assert cov.total == len(mut.ledger_names(doc))
    assert any("not covered" in n for n in cov.notes)
    ev = engine.evaluate(
        [
            engine.InputFile("run_record", "r.json", (d / "bounded-run-record.json").read_bytes()),
            engine.InputFile("witness", "w.jsonl", (d / "witness-first-only.jsonl").read_bytes()),
        ]
    )
    assert ev.overall != "accept"


# ---------------------------------------------------------------------------------- absent witness


def _run_only(name: str = "journal-applied") -> engine.Evaluation:
    d = DATA / "real-runs" / name
    return engine.evaluate(
        [
            engine.InputFile("run_record", "r.json", (d / "bounded-run-record.json").read_bytes()),
            engine.InputFile("proposal_export", "p.json", (d / "proposal.json").read_bytes()),
            engine.InputFile("manifest", "m.json", (d / "manifest.json").read_bytes()),
            engine.InputFile("destination_ledger", "l.json", (d / "destination.json").read_bytes()),
        ]
    )


def test_no_witness_means_no_v3_tier_input_check_or_claim() -> None:
    ev = _run_only()
    assert ev.v3 is not None and not ev.v3.requested
    assert ev.v3.results == [] and ev.v3.inputs == []
    assert ev.overall == "accept"
    rep = report.build(ev, generated_at="2026-10-18T12:00:00+00:00")
    assert "x-tier-v3" not in rep["extensions"] and "x-v3-notes" not in rep["extensions"]
    assert not any(c["tier"] == "V3" or c["check_id"].startswith("v3.") for c in rep["checks"])
    assert "V3" not in rep["scope"]["tiers_run"]
    assert {i["role"] for i in rep["subject"]["inputs"]} <= {
        "run_record",
        "proposal_export",
        "manifest",
        "destination_ledger",
    }
    assert "witness_is_not_publication" not in {n["id"] for n in rep["does_not_prove"]}
    assert any("tier V3" in n and "not run" in n for n in rep["extensions"]["x-notes"])
    assert [v.code for v in _oracle().validate(rep)] == []


def test_report_without_v3_has_the_same_id_as_before_the_move() -> None:
    a = report.build(_run_only(), generated_at="2026-10-18T12:00:00+00:00")
    assert a["report_id"].startswith("vr-")


def test_an_empty_witness_holds_no_digest_and_is_could_not_check() -> None:
    doc, _ = _load_set("real-runs/journal-applied")
    for data in (b"", b"\n\n"):
        results = _checks(doc, data)
        assert _verdicts(results) == dict.fromkeys(results, COULD_NOT_CHECK)
        assert all(r.reason == "input_absent:witness_holds_no_digest" for r in results.values())
        assert _codes(results) == set()


def test_unsupported_document_kind_is_could_not_check() -> None:
    life = sorted((DATA / "odes-fixtures" / "lifecycle" / "valid").glob("*.json"))[0]
    wit = (WITNESSES / "real-runs" / "journal-applied" / "witness.jsonl").read_bytes()
    ev = engine.evaluate(
        [
            engine.InputFile("run_record", "r.json", life.read_bytes()),
            engine.InputFile("witness", "w.jsonl", wit),
        ]
    )
    assert ev.v3 is not None
    assert {r.verdict for r in ev.v3.results if r.check_id.startswith("v3.witness.")} == {
        COULD_NOT_CHECK
    }
    assert all(
        r.reason and r.reason.startswith("unsupported_document")
        for r in ev.v3.results
        if r.check_id.startswith("v3.witness.")
    )


def test_unparsable_run_record_gives_could_not_check() -> None:
    ev = engine.evaluate(
        [
            engine.InputFile("run_record", "r.json", b"{"),
            engine.InputFile("witness", "w.jsonl", b"{}\n"),
        ]
    )
    assert ev.v3 is not None
    assert {r.verdict for r in ev.v3.results} == {COULD_NOT_CHECK}
    assert ev.overall != "accept"


# ---------------------------------------------------------------------------------- differential


def _case_inputs(case: dict[str, Any]) -> tuple[dict[str, Any], bytes]:
    doc, recs = _load_set(case["set"])
    if case["record_op"]:
        op, ledger = case["record_op"]
        damaged = mut.apply_record_op(doc, op, ledger)
        assert damaged is not None
        doc = damaged
    if case["witness_op"]:
        damaged_w = mut.apply_witness_op(recs, case["witness_op"], _resign)
        assert damaged_w is not None
        recs = damaged_w
    return doc, _lines(recs)


def test_differential_against_the_control_planes_own_verifier() -> None:
    """Every case: same accept/refuse split, same codes, same unwitnessed rows as the control plane."""
    agree = {"accept": 0, "refuse": 0}
    for case in DIFF:
        doc, data = _case_inputs(case)
        results = _checks(doc, data)
        cp = case["cp"]
        label = (case["set"], case["record_op"], case["witness_op"])
        codes = _codes(results)
        assert not any(r.error for r in results.values()), label
        if not cp["ok"]:
            assert codes == set(cp["reasons"]), label
            assert any(r.verdict == REFUTED for r in results.values())
            agree["refuse"] += 1
            continue
        assert codes == set(), label
        cov = results["v3.witness.coverage"]
        extra = cp["unwitnessed_rows"]
        assert cov.skipped == len(extra), label
        for name, rows in extra.items():
            assert any(
                n.startswith(f"rows after the latest digest, not covered: {name} ({rows} of")
                for n in cov.notes
            ), label
        others = {k: v for k, v in _verdicts(results).items() if k != "v3.witness.coverage"}
        assert set(others.values()) == {CONFIRMED}, label
        agree["accept"] += 1
    assert agree == {"accept": 135, "refuse": 763}


def test_differential_reason_vocabulary_is_covered() -> None:
    seen = {r for case in DIFF for r in case["cp"]["reasons"]}
    assert seen == WITNESS_CODES


def test_every_covered_ledger_of_every_record_catches_a_drop_rewrite_and_emptying() -> None:
    n = k = 0
    for name in SETS:
        doc, recs = _load_set(name)
        data = _lines(recs)
        for ledger in recs[-1]["ledgers"]:
            for op, code in (
                ("drop_last", "witness_ledger_shrunk"),
                ("empty", "witness_ledger_shrunk"),
                ("remove", "witness_ledger_shrunk"),
                ("rewrite_first", "witness_ledger_head_mismatch"),
            ):
                damaged = mut.apply_record_op(doc, op, ledger)
                assert damaged is not None
                n += 1
                results = _checks(damaged, data)
                codes = {f.code for f in results["v3.witness.ledger-heads"].findings}
                if code in codes:
                    k += 1
    assert k == n and n > 400


def test_swapping_rows_is_a_head_mismatch() -> None:
    swapped = 0
    for name in SETS:
        doc, recs = _load_set(name)
        for ledger in recs[-1]["ledgers"]:
            damaged = mut.apply_record_op(doc, "swap_first_two", ledger)
            if damaged is None:
                continue
            swapped += 1
            results = _checks(damaged, _lines(recs))
            assert _codes(results) == {"witness_ledger_head_mismatch"}
    assert swapped > 30


def test_an_appended_row_is_unwitnessed_not_refused() -> None:
    for name in SETS:
        doc, recs = _load_set(name)
        for ledger in recs[-1]["ledgers"]:
            damaged = mut.apply_record_op(doc, "append_copy", ledger)
            assert damaged is not None
            results = _checks(damaged, _lines(recs))
            assert _codes(results) == set()
            assert results["v3.witness.coverage"].verdict == COULD_NOT_CHECK


# ---------------------------------------------------------------------------------- witness damage


@pytest.fixture(scope="module")
def staged() -> tuple[dict[str, Any], list[dict[str, Any]]]:
    return _load_set("witnessed-runs/staged-journal-applied")


def _damaged(
    staged: tuple[dict[str, Any], list[dict[str, Any]]], op: str
) -> dict[str, CheckResult]:
    doc, recs = staged
    out = mut.apply_witness_op(recs, op, _resign)
    assert out is not None
    return _checks(doc, _lines(out))


@pytest.mark.parametrize(
    ("op", "code", "check"),
    [
        ("head", "witness_chain_invalid", "v3.witness.digest-recompute"),
        ("head_resign", "witness_ledger_head_mismatch", "v3.witness.ledger-heads"),
        ("count_up_resign", "witness_ledger_shrunk", "v3.witness.ledger-heads"),
        ("count_down_resign", "witness_ledger_head_mismatch", "v3.witness.ledger-heads"),
        ("run_id_resign", "witness_run_mismatch", "v3.witness.run-id"),
        ("sequence_resign", "witness_chain_invalid", "v3.witness.chain"),
        ("previous_digest", "witness_chain_invalid", "v3.witness.chain"),
        ("previous_digest_resign", "witness_chain_invalid", "v3.witness.chain"),
        ("drop_first", "witness_chain_invalid", "v3.witness.chain"),
        ("swap", "witness_chain_invalid", "v3.witness.chain"),
        ("duplicate_last", "witness_chain_invalid", "v3.witness.chain"),
        ("digest_only", "witness_chain_invalid", "v3.witness.digest-recompute"),
    ],
)
def test_damaged_witness_is_refused_with_a_stable_code(
    staged: tuple[dict[str, Any], list[dict[str, Any]]], op: str, code: str, check: str
) -> None:
    results = _damaged(staged, op)
    assert code in {f.code for f in results[check].findings}, (op, _verdicts(results))
    assert not any(r.error for r in results.values())


def test_a_chain_defect_means_heads_are_not_compared() -> None:
    doc, recs = _load_set("witnessed-runs/staged-journal-applied")
    out = mut.apply_witness_op(recs, "previous_digest_resign", _resign)
    assert out is not None
    results = _checks(doc, _lines(out))
    heads = results["v3.witness.ledger-heads"]
    assert heads.verdict == COULD_NOT_CHECK and heads.reason == "earlier_rules_refuted"
    assert results["v3.witness.coverage"].verdict == COULD_NOT_CHECK


def test_a_consistent_rewrite_of_witness_and_record_is_accepted_the_stated_limit() -> None:
    """Whoever controls the witness can supply a matching chain: nothing here shows it was independent."""
    doc, recs = _load_set("real-runs/journal-applied")
    rewritten = copy.deepcopy(doc)
    rewritten["decisions"][0]["x-rewritten"] = 1
    heads = {
        n: witness.chain_heads(rows)[-1] for n, rows in witness.ledgers(rewritten).items() if rows
    }
    forged = copy.deepcopy(recs)
    for name, held in forged[-1]["ledgers"].items():
        held["head"] = heads[name]
    forged[-1]["digest"] = _resign(forged[-1])
    results = _checks(rewritten, _lines(forged))
    assert _verdicts(results) == dict.fromkeys(results, CONFIRMED)


@pytest.mark.parametrize(
    ("mutate", "code"),
    [
        (lambda r: {**r, "signer": "urn:x"}, "witness_record_shape"),
        (lambda r: {k: v for k, v in r.items() if k != "digest"}, "witness_record_shape"),
        (lambda r: {**r, "version": "witness-digest/0.2"}, "witness_version_unsupported"),
        (lambda r: {**r, "sequence": True}, "witness_record_shape"),
        (lambda r: {**r, "sequence": -1}, "witness_record_shape"),
        (lambda r: {**r, "run_id": ""}, "witness_record_shape"),
        (lambda r: {**r, "previous_digest": "abc"}, "witness_record_shape"),
        (lambda r: {**r, "digest": "sha256:xyz"}, "witness_record_shape"),
        (lambda r: {**r, "ledgers": []}, "witness_record_shape"),
        (lambda r: {**r, "ledgers": {"decisions": {"count": 1}}}, "witness_record_shape"),
        (
            lambda r: {**r, "ledgers": {"decisions": {"count": "1", "head": "sha256:" + "0" * 64}}},
            "witness_record_shape",
        ),
        (
            lambda r: {**r, "ledgers": {"decisions": {"count": 1, "head": "x", "keyed": 1}}},
            "witness_record_shape",
        ),
    ],
)
def test_shape_errors_are_refused_not_read_as_something_else(mutate: Any, code: str) -> None:
    doc, recs = _load_set("real-runs/journal-applied")
    bad = [mutate(recs[0])]
    results = _checks(doc, _lines(bad))
    assert code in {f.code for f in results["v3.witness.records"].findings}
    assert results["v3.witness.chain"].verdict == COULD_NOT_CHECK


def test_a_non_object_record_is_a_shape_error() -> None:
    doc, _ = _load_set("real-runs/journal-applied")
    results = _checks(doc, b"[1]\n")
    assert {f.code for f in results["v3.witness.records"].findings} == {"witness_record_shape"}


@pytest.mark.parametrize(
    ("data", "code"),
    [
        (b'{"a":1,"a":2}\n', "wire_duplicate_member"),
        (b'{"a":NaN}\n', "wire_nonfinite_constant"),
        (b"{\n", "wire_syntax"),
        (b"{} {}\n", "wire_trailing_data"),
        (b"\xef\xbb\xbf{}\n", "wire_bom"),
        (b"\xff\n", "wire_not_utf8"),
        (b" " * (8 * 1024 * 1024 + 1), "wire_too_large"),
    ],
)
def test_wire_level_refusals_apply_to_the_witness_file(data: bytes, code: str) -> None:
    doc, recs = _load_set("real-runs/journal-applied")
    results = _checks(
        doc,
        data if code in ("wire_bom", "wire_not_utf8", "wire_too_large") else _lines(recs) + data,
    )
    assert code in _codes(results)
    assert not any(r.error for r in results.values())


# ---------------------------------------------------------------------------------- holder inventory


INV = RUNS / "holder-inventory-enumerated" / "holder-inventory.json"


def _inventory(doc: Any) -> tuple[CheckResult, Any]:
    return witness.inventory_document_check(json.dumps(doc).encode())


def test_a_real_inventory_is_confirmed_and_ties_nothing_to_the_record() -> None:
    check, _ = witness.inventory_document_check(INV.read_bytes())
    assert check.verdict == CONFIRMED and check.total == 1
    d = RUNS / "holder-inventory-missing-held"
    ev = engine.evaluate(
        [
            engine.InputFile("run_record", "r.json", (d / "bounded-run-record.json").read_bytes()),
            engine.InputFile("holder_inventory", "i.json", INV.read_bytes()),
        ]
    )
    assert ev.v3 is not None
    ref = next(r for r in ev.v3.results if r.check_id == "v3.holder-inventory.record-reference")
    assert ref.verdict == COULD_NOT_CHECK and ref.total == 1
    assert ref.reason == "tier_unavailable:profile_in_force_not_in_record"
    # the record is not refused for lacking a profile it never carried
    assert not any(r.verdict == REFUTED for r in ev.results + ev.v3.results)


def test_record_with_a_missing_inventory_hold_and_no_inventory_supplied() -> None:
    d = RUNS / "holder-inventory-missing-held"
    ev = engine.evaluate(
        [
            engine.InputFile("run_record", "r.json", (d / "bounded-run-record.json").read_bytes()),
            engine.InputFile("witness", "w.jsonl", (d / "witness.jsonl").read_bytes()),
        ]
    )
    assert ev.v3 is not None
    ref = next(r for r in ev.v3.results if r.check_id == "v3.holder-inventory.record-reference")
    assert ref.reason == "input_absent:holder_inventory"
    assert ev.overall == "abstain"


def test_record_without_such_holds_has_nothing_to_tie() -> None:
    d = RUNS / "holder-inventory-enumerated"
    ev = engine.evaluate(
        [
            engine.InputFile("run_record", "r.json", (d / "bounded-run-record.json").read_bytes()),
            engine.InputFile("holder_inventory", "i.json", INV.read_bytes()),
        ]
    )
    assert ev.v3 is not None
    assert [n["check_id"] for n in ev.v3.not_applicable] == ["v3.holder-inventory.record-reference"]
    assert [r.verdict for r in ev.v3.results] == [CONFIRMED]


def test_inventory_damage_is_refused() -> None:
    base = json.loads(INV.read_text())
    cases: list[tuple[Any, str]] = []

    def edit(fn: Any) -> Any:
        doc = copy.deepcopy(base)
        fn(doc)
        return doc

    cases += [
        (edit(lambda d: d.update(signer="x")), "undeclared_member"),
        (edit(lambda d: d.pop("recorded_by")), "holder_inventory_shape"),
        (edit(lambda d: d.update(version="holder-inventory/0.2")), "unsupported_contract_version"),
        (edit(lambda d: d.update(version=2)), "holder_inventory_shape"),
        (edit(lambda d: d.update(recorded_at="2026-10-05T19:00:00")), "timestamp_invalid"),
        (edit(lambda d: d.update(extensions={"signer": "s"})), "invalid_extension_key"),
        (edit(lambda d: d["holders"][0].update(extensions=[])), "holder_inventory_shape"),
        (edit(lambda d: d.update(inventory_id="")), "holder_inventory_shape"),
        (edit(lambda d: d.update(holders={})), "holder_inventory_shape"),
        (edit(lambda d: d["holders"][0].update(kind="expired")), "unknown_enum_value"),
        (edit(lambda d: d["holders"][0].update(signer="s")), "undeclared_member"),
        (edit(lambda d: d["holders"][0].pop("enforcement_point")), "holder_inventory_shape"),
        (edit(lambda d: d["holders"][0].update(holder_id="")), "holder_inventory_shape"),
        (edit(lambda d: d["holders"][0].update(credential_ref=3)), "holder_inventory_shape"),
        (edit(lambda d: d["holders"].append(7)), "holder_inventory_shape"),
        ([1], "holder_inventory_shape"),
    ]
    for doc, code in cases:
        check, _ = _inventory(doc)
        assert check.verdict == REFUTED and code in {f.code for f in check.findings}, (doc, code)


def test_an_inventory_enumerating_nobody_claims_nothing() -> None:
    check, _ = _inventory({**json.loads(INV.read_text()), "holders": []})
    assert check.verdict == COULD_NOT_CHECK and check.skipped == 1
    assert check.reason == "not_applicable_to_input:inventory_enumerates_no_holder"


def test_inventory_wire_refusal() -> None:
    check, doc = witness.inventory_document_check(b'{"a":1,"a":2}')
    assert check.verdict == REFUTED and doc is None
    assert check.findings[0].code == "wire_duplicate_member"


def test_duplicate_holder_ids_are_not_checked_because_the_contract_is_silent() -> None:
    base = json.loads(INV.read_text())
    base["holders"].append(copy.deepcopy(base["holders"][0]))
    check, _ = _inventory(base)
    assert check.verdict == CONFIRMED


# ---------------------------------------------------------------------------------- report, CLI


def _oracle() -> Any:
    from .test_report_cli import ORACLE as oracle

    return oracle


def test_reports_with_v3_validate_against_the_odes_validator() -> None:
    oracle = _oracle()
    fixed = "2026-10-18T12:00:00+00:00"
    n = 0
    for name in SETS:
        rec_path, wit_path = _paths(name)
        files = [
            engine.InputFile("run_record", "r.json", rec_path.read_bytes()),
            engine.InputFile("witness", "w.jsonl", wit_path.read_bytes()),
        ]
        if name.endswith("holder-inventory-enumerated"):
            files.append(engine.InputFile("holder_inventory", "i.json", INV.read_bytes()))
        ev = engine.evaluate(files)
        rep = report.build(ev, generated_at=fixed)
        assert [f"{v.code} {v.path}" for v in oracle.validate(rep)] == []
        v3 = [c for c in rep["checks"] if c["tier"] == "V3"]
        assert len(v3) >= 6 and "V3" in rep["scope"]["tiers_run"]
        assert "witness" in {i["role"] for i in rep["subject"]["inputs"]}
        assert rep["extensions"]["x-v3-notes"]["witness_supplied"] is True
        assert "x-tier-v3" not in rep["extensions"]
        assert "witness_is_not_publication" in {n["id"] for n in rep["does_not_prove"]}
        assert rep["summary"]["checks"] == len(rep["checks"])
        assert engine.inputs_commitment(rep["subject"]["inputs"]) == rep["subject"]["inputs_digest"]
        n += 1
    assert n == 25


def test_damaged_reports_with_v3_validate_and_reject() -> None:
    oracle = _oracle()
    doc, recs = _load_set("real-runs/journal-applied")
    dropped = mut.apply_record_op(doc, "drop_last", "check_events")
    assert dropped is not None
    ev = engine.evaluate(
        [
            engine.InputFile("run_record", "r.json", json.dumps(dropped).encode()),
            engine.InputFile("witness", "w.jsonl", _lines(recs)),
        ]
    )
    rep = report.build(ev, generated_at="2026-10-18T12:00:00+00:00")
    assert [f"{v.code} {v.path}" for v in oracle.validate(rep)] == []
    assert rep["extensions"]["x-overall"] == "reject" == ev.overall
    refuted = [c for c in rep["checks"] if c["verdict"] == REFUTED]
    assert [f["code"] for c in refuted for f in c["findings"] if c["tier"] == "V3"] == [
        "witness_ledger_shrunk"
    ]
    assert rep["summary"]["refuted"] == len(refuted) > 0


def test_v3_section_changes_the_report_id_only_when_requested() -> None:
    d = DATA / "real-runs" / "journal-applied"
    rec = engine.InputFile("run_record", "r.json", (d / "bounded-run-record.json").read_bytes())
    w1 = engine.InputFile(
        "witness",
        "w.jsonl",
        (WITNESSES / "real-runs" / "journal-applied" / "witness.jsonl").read_bytes(),
    )
    a = report.build(engine.evaluate([rec]), generated_at="2026-10-18T12:00:00+00:00")
    b = report.build(engine.evaluate([rec, w1]), generated_at="2026-10-18T12:00:00+00:00")
    assert a["report_id"] != b["report_id"]


def test_crash_in_v3_is_an_error_not_a_verdict(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*_a: Any, **_k: Any) -> Any:
        raise RuntimeError("boom")

    monkeypatch.setattr(witness, "run_tier", boom)
    ev = engine.evaluate([engine.InputFile("run_record", "r.json", b"{}")])
    assert ev.crashed
    with pytest.raises(ValueError):
        report.build(ev)


def test_crash_inside_a_witness_check_is_an_error(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(_rows: Any) -> Any:
        raise RuntimeError("boom")

    monkeypatch.setattr(witness, "chain_heads", boom)
    doc, recs = _load_set("real-runs/journal-applied")
    results = _checks(doc, _lines(recs))
    assert results["v3.witness.ledger-heads"].error and results["v3.witness.coverage"].error


def test_crash_inside_a_digest_check_is_an_error(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(_rec: Any) -> Any:
        raise RuntimeError("boom")

    monkeypatch.setattr(witness, "record_digest", boom)
    doc, recs = _load_set("real-runs/journal-applied")
    assert _checks(doc, _lines(recs))["v3.witness.digest-recompute"].error


def test_record_without_run_id_cannot_be_compared() -> None:
    doc, recs = _load_set("real-runs/journal-applied")
    bare = {k: v for k, v in doc.items() if k != "run_id"}
    results = _checks(bare, _lines(recs))
    assert results["v3.witness.run-id"].verdict == COULD_NOT_CHECK
    assert results["v3.witness.ledger-heads"].reason == "tier_unavailable:record_has_no_run_id"


def test_cli_exit_codes_and_summary(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    from cognous_verify import cli

    d = RUNS / "staged-journal-applied"
    rec = str(d / "bounded-run-record.json")
    assert cli.main([rec, "--witness", str(d / "witness.jsonl")]) == cli.EXIT_ABSTAIN
    out = capsys.readouterr().out
    assert "tier V3" in out and "6 checks, 6 confirmed" in out
    assert cli.main([rec, "--witness", str(d / "witness-first-only.jsonl")]) == cli.EXIT_ABSTAIN
    assert "v3.witness.coverage" in capsys.readouterr().out
    doc = json.loads((d / "bounded-run-record.json").read_text())
    doc["decisions"][0]["x-rewritten"] = 1
    bad = tmp_path / "rec.json"
    bad.write_text(json.dumps(doc))
    assert cli.main([str(bad), "--witness", str(d / "witness.jsonl")]) == cli.EXIT_REFUTED
    assert "witness_ledger_head_mismatch" in capsys.readouterr().out
    assert cli.main([rec]) in (cli.EXIT_ACCEPT, cli.EXIT_ABSTAIN)
    assert "not run: no witness or holder inventory" in capsys.readouterr().out


def test_cli_json_report_carries_the_v3_section_and_the_input_digest(tmp_path: Path) -> None:
    from cognous_verify import cli

    d = RUNS / "holder-inventory-enumerated"
    out = tmp_path / "rep.json"
    code = cli.main(
        [
            str(d / "bounded-run-record.json"),
            "--witness",
            str(d / "witness.jsonl"),
            "--holder-inventory",
            str(d / "holder-inventory.json"),
            "--out",
            str(out),
            "--generated-at",
            "2026-10-18T12:00:00+00:00",
        ]
    )
    assert code == cli.EXIT_ABSTAIN
    rep = json.loads(out.read_text())
    inputs = [i for i in rep["subject"]["inputs"] if i["role"] in ("holder_inventory", "witness")]
    assert [i["role"] for i in inputs] == ["holder_inventory", "witness"]
    assert all(i["digest"].startswith("sha256:") for i in inputs)
    assert any("not that it was published" in s for s in rep["extensions"]["x-v3-notes"]["limits"])
    assert "V3" in rep["scope"]["tiers_run"]
    assert rep["summary"]["checks"] == len(rep["checks"])


def test_cli_refuses_an_output_path_that_names_the_witness(tmp_path: Path) -> None:
    from cognous_verify import cli

    d = RUNS / "staged-journal-applied"
    w = tmp_path / "w.jsonl"
    w.write_bytes((d / "witness.jsonl").read_bytes())
    assert (
        cli.main([str(d / "bounded-run-record.json"), "--witness", str(w), "--out", str(w)])
        == cli.EXIT_USAGE
    )
    assert w.read_bytes() == (d / "witness.jsonl").read_bytes()


def test_cli_unreadable_witness_is_a_usage_error(tmp_path: Path) -> None:
    from cognous_verify import cli

    d = RUNS / "staged-journal-applied"
    assert (
        cli.main([str(d / "bounded-run-record.json"), "--witness", str(tmp_path / "none")])
        == cli.EXIT_USAGE
    )

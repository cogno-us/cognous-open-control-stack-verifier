"""Differential against the ODES ``witness-digest``, ``holder-inventory`` and
``verification-report`` drafts (ODES main fe705e87, decision 27;
``verification-report`` re-vendored at 0a37180f, decision 29).

``tests/data/<contract>`` holds each contract's schema and reference validator, copied unchanged
(digests in SOURCE.json), and ``tests/data/odes-fixtures/<contract>`` its fixtures. The verifier
never imports a validator: tests load it by path as an oracle and require the verifier's own
tier V3 checks to agree with it on every fixture, except for the cases in ``*_DIVERGENCES``.
Each divergence is listed in docs/tiers.md with the reason it is kept; a test requires that every
listed divergence still diverges, so the table cannot go stale.

Code names: the ODES structure codes ``undeclared_member`` / ``schema_violation`` are the
verifier's ``witness_record_shape`` (witness) or ``holder_inventory_shape`` (inventory, with
``undeclared_member`` kept); ``unsupported_contract_version`` is ``witness_version_unsupported``
(witness) and the same name (inventory). Everything else has the same name.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from cognous_verify import witness

from .helpers import DATA, FIXTURES, fixture_paths, load


def _oracle(name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        f"odes_{name.replace('-', '_')}_oracle", DATA / name / "validate.py"
    )
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


WITNESS_ORACLE = _oracle("witness-digest")
HOLDER_ORACLE = _oracle("holder-inventory")
CONTRACTS = ("verification-report", "witness-digest", "holder-inventory")
REVISIONS = {
    "verification-report": "0a37180f",
    "witness-digest": "fe705e87",
    "holder-inventory": "fe705e87",
}


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


@pytest.mark.parametrize("contract", CONTRACTS)
def test_oracles_and_fixture_copies_match_their_recorded_digests(contract: str) -> None:
    oracle_dir, fixture_dir = DATA / contract, FIXTURES / contract
    src = json.loads((oracle_dir / "SOURCE.json").read_text())
    assert src["revision"] == REVISIONS[contract]
    for name, digest in src["sha256"].items():
        assert _sha(oracle_dir / name) == digest
    on_disk = {
        str(p.relative_to(fixture_dir)): _sha(p) for p in sorted(fixture_dir.glob("*/*.json"))
    }
    assert on_disk == src["fixtures_sha256"]


def test_fixture_counts_match_the_contract_readmes() -> None:
    counts = {
        c: (len(fixture_paths(c, "valid")), len(fixture_paths(c, "invalid"))) for c in CONTRACTS
    }
    assert counts == {
        "verification-report": (16, 87),
        "witness-digest": (7, 31),
        "holder-inventory": (6, 18),
    }


# ---------------------------------------------------------------------------------- report


@pytest.mark.parametrize("cls", ["valid", "invalid"])
def test_report_oracle_agrees_with_its_fixtures(cls: str) -> None:
    oracle = _oracle("verification-report")
    for path in fixture_paths("verification-report", cls):
        fixture = load(path)
        codes = {v.code for v in oracle.validate(fixture["document"])}
        if cls == "valid":
            assert codes == set(), fixture["fixture_id"]
        else:
            assert codes == {fixture["expected_refusal"]}, fixture["fixture_id"]


# ---------------------------------------------------------------------------------- witness

WITNESS_CODES = {
    "undeclared_member": "witness_record_shape",
    "schema_violation": "witness_record_shape",
    "unsupported_contract_version": "witness_version_unsupported",
}
# fixture id -> (ODES outcome, verifier outcome, why the verifier keeps its own)
WITNESS_DIVERGENCES = {
    "empty-witness-file": ("refused witness_holds_no_digest", "could_not_check on every check"),
    "record-without-run-id": (
        "refused witness_run_mismatch",
        "could_not_check (run-id, ledger-heads, coverage)",
    ),
    "ledger-count-zero": (
        "refused schema_violation (an entry covers at least 1 row)",
        "refused for the digest (the fixture edits the count without re-signing); a re-signed "
        "entry of count 0 over the genesis head is accepted: it covers nothing, as if omitted",
    ),
    "witness-file-is-an-object": (
        "refused schema_violation (the document is an array)",
        "accepted: one record on one line is the same bytes as a one-record JSON-lines file",
    ),
}
WITNESS_CASES = [
    (cls, p) for cls in ("valid", "invalid") for p in fixture_paths("witness-digest", cls)
]


def _witness_bytes(doc: Any) -> bytes:
    """The JSON-lines file a witness holds for an array of records (one line otherwise)."""
    rows = doc if isinstance(doc, list) else [doc]
    return "\n".join(json.dumps(r, sort_keys=True, separators=(",", ":")) for r in rows).encode()


def _verifier_witness(fixture: dict[str, Any]) -> tuple[set[str], list[str]]:
    """Refused codes (ODES names) and could-not-check check ids of the verifier's witness checks.

    With the run record the fixture carries, all six checks. Without one, only the three that
    read the witness file alone (records, digest-recompute, chain)."""
    record = fixture.get("record")
    results = witness.witness_checks(
        record if record is not None else {}, _witness_bytes(fixture["document"])
    )
    if record is None:
        results = results[:3]
    refused = {f.code for r in results if r.verdict == "refuted" for f in r.findings}
    unchecked = [r.check_id.rsplit(".", 1)[1] for r in results if r.verdict == "could_not_check"]
    return refused, unchecked


@pytest.mark.parametrize("cls,path", WITNESS_CASES, ids=[f"{c}-{p.stem}" for c, p in WITNESS_CASES])
def test_verifier_witness_checks_agree_with_the_odes_validator(cls: str, path: Path) -> None:
    fixture = load(path)
    fid = fixture["fixture_id"]
    odes = {v.code for v in WITNESS_ORACLE.validate(fixture["document"], fixture.get("record"))}
    refused, unchecked = _verifier_witness(fixture)
    if fid in WITNESS_DIVERGENCES:
        assert cls == "invalid" and odes == {fixture["expected_refusal"]}
        if fid == "witness-file-is-an-object":
            assert refused == set() and unchecked == []
        elif fid == "ledger-count-zero":
            assert refused == {"witness_chain_invalid"}
        else:
            assert refused == set() and unchecked, fid
        return
    if cls == "valid":
        assert odes == set(), fid
        assert refused == set(), fid
        coverage = fixture.get("expected_coverage")
        if fixture.get("record") is not None and coverage is not None:
            behind = [n for n, rows in coverage["unwitnessed_rows"].items() if rows]
            assert unchecked == (["coverage"] if behind else []), fid
        else:
            assert unchecked == [], fid
        return
    expected = fixture["expected_refusal"]
    assert odes == {expected}, fid
    assert refused == {WITNESS_CODES.get(expected, expected)}, fid


def test_every_listed_witness_divergence_is_a_fixture() -> None:
    ids = {load(p)["fixture_id"] for _c, p in WITNESS_CASES}
    assert set(WITNESS_DIVERGENCES) <= ids


def test_witness_extensions_are_accepted_but_never_read_as_a_signer() -> None:
    fixture = load(
        FIXTURES / "witness-digest" / "valid" / "extension-namespace-members-preserved.json"
    )
    assert _verifier_witness(fixture) == (set(), [])
    records = [dict(r) for r in fixture["document"]]
    records[0]["extensions"] = {"signer": "someone"}  # a name without x- is not an extension
    refused, _ = _verifier_witness({"document": records})
    assert refused == {"invalid_extension_key"}
    records[0]["extensions"] = {"x-proof": "claimed"}  # a lookalike under x- proves nothing
    assert witness._shape(0, records[0]) == []
    records[0]["signer"] = "someone"
    assert {f.code for f in witness._shape(0, records[0])} == {"witness_record_shape"}


# ---------------------------------------------------------------------------------- inventory

HOLDER_CODES = {
    "schema_violation": "holder_inventory_shape",
}
HOLDER_DIVERGENCES = {
    "enumerates-no-holder": (
        "valid in shape (claims nothing)",
        "could_not_check: an inventory that enumerates no holder claims nothing",
    ),
    "credential-ref-member-missing": (
        "refused schema_violation",
        "accepted: the control plane's own model defaults the member to null",
    ),
}
HOLDER_CASES = [
    (cls, p) for cls in ("valid", "invalid") for p in fixture_paths("holder-inventory", cls)
]


@pytest.mark.parametrize("cls,path", HOLDER_CASES, ids=[f"{c}-{p.stem}" for c, p in HOLDER_CASES])
def test_verifier_inventory_check_agrees_with_the_odes_validator(cls: str, path: Path) -> None:
    fixture = load(path)
    fid = fixture["fixture_id"]
    odes = {v.code for v in HOLDER_ORACLE.validate(fixture["document"])}
    result, _doc = witness.inventory_document_check(json.dumps(fixture["document"]).encode())
    refused = {f.code for f in result.findings}
    if fid in HOLDER_DIVERGENCES:
        if cls == "valid":
            assert odes == set() and result.verdict == "could_not_check", fid
        else:
            assert odes == {fixture["expected_refusal"]} and result.verdict == "confirmed", fid
        return
    if cls == "valid":
        assert odes == set() and result.verdict == "confirmed", fid
        return
    expected = fixture["expected_refusal"]
    assert odes == {expected}, fid
    assert result.verdict == "refuted" and refused == {HOLDER_CODES.get(expected, expected)}, fid


def test_every_listed_inventory_divergence_is_a_fixture() -> None:
    ids = {load(p)["fixture_id"] for _c, p in HOLDER_CASES}
    assert set(HOLDER_DIVERGENCES) <= ids


@pytest.mark.parametrize(
    "value,odes_accepts,verifier_accepts",
    [
        ("2026-10-18T12:00:00+00:00", True, True),
        ("2026-10-18T12:00:00Z", True, True),
        ("2026-10-18 12:00:00+02:00", True, True),
        ("2026-10-18T12:00:00", False, False),
        ("2026-10-18", False, False),
        ("yesterday", False, False),
        # forms Python's fromisoformat reads and the verifier's RFC 3339 profile does not
        ("2026-10-18T12:00:00+0000", True, False),
        ("20261018T120000Z", True, False),
        # forms the verifier reads (it takes a lower-case separator and zone letter)
        ("2026-10-18t12:00:00z", False, True),
    ],
)
def test_recorded_at_offset_rule_matches_except_in_stated_forms(
    value: str, odes_accepts: bool, verifier_accepts: bool
) -> None:
    doc = json.loads(
        (
            FIXTURES
            / "holder-inventory"
            / "valid"
            / "two-holders-routed-and-self-credentialed.json"
        ).read_text()
    )["document"]
    doc["recorded_at"] = value
    assert (HOLDER_ORACLE.validate(doc) == []) is odes_accepts
    result, _ = witness.inventory_document_check(json.dumps(doc).encode())
    assert (result.verdict == "confirmed") is verifier_accepts


def test_a_resigned_entry_of_count_zero_covers_nothing_and_is_not_counted() -> None:
    fixture = load(FIXTURES / "witness-digest" / "valid" / "acp-run-authorized-one-record.json")
    record = fixture["record"]
    rec = json.loads(json.dumps(fixture["document"][0]))
    rec["ledgers"]["decisions"] = {"count": 0, "head": witness.GENESIS}
    rec["digest"] = witness.record_digest(rec)
    codes = {v.code for v in WITNESS_ORACLE.validate([rec], record)}
    assert codes == {"schema_violation"}
    results = {
        r.check_id.rsplit(".", 1)[1]: r
        for r in witness.witness_checks(record, _witness_bytes([rec]))
    }
    assert results["ledger-heads"].verdict == "confirmed"
    assert results["coverage"].verdict == "could_not_check"  # the decisions row is not covered
    pairs = len(rec["ledgers"]) - 1
    assert f"{pairs} ledger heads re-derived" in results["ledger-heads"].notes[0]

"""Differential against the ODES ``destination-ledger`` 0.1.0-draft contract.

``tests/data/destination-ledger`` holds the contract's schema and reference validator, copied
unchanged (digests in SOURCE.json), and ``tests/data/odes-fixtures/destination-ledger`` its 13
valid and 48 invalid fixtures. The verifier never imports the validator; this test loads it by
path as an oracle and requires the verifier's own ledger checks to agree with it on every
fixture: the same accept or refuse, and, where the verifier has the finding, the same code.
Structure findings are the verifier's single ``ledger_shape`` code for the ODES
``undeclared_member`` / ``invalid_extension_key`` / ``schema_violation``.
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

from cognous_verify import ledger

from .helpers import DATA, FIXTURES, fixture_paths, load

ORACLE_DIR = DATA / "destination-ledger"
FIXTURE_DIR = FIXTURES / "destination-ledger"
STRUCTURE = {"undeclared_member", "invalid_extension_key", "schema_violation"}


def _oracle() -> ModuleType:
    spec = importlib.util.spec_from_file_location("odes_ledger_oracle", ORACLE_DIR / "validate.py")
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


ORACLE = _oracle()
CASES = [(cls, p) for cls in ("valid", "invalid") for p in fixture_paths("destination-ledger", cls)]


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_oracle_and_fixture_copies_match_their_recorded_digests() -> None:
    src = json.loads((ORACLE_DIR / "SOURCE.json").read_text())
    for name, digest in src["sha256"].items():
        assert _sha(ORACLE_DIR / name) == digest
    on_disk = {
        str(p.relative_to(FIXTURE_DIR)): _sha(p) for p in sorted(FIXTURE_DIR.glob("*/*.json"))
    }
    assert on_disk == src["fixtures_sha256"]


def test_fixture_counts_match_the_contract_readme() -> None:
    assert len(fixture_paths("destination-ledger", "valid")) == 13
    assert (
        len(fixture_paths("destination-ledger", "invalid")) == 48
    )  # ODES c3f97ca3: 2 hardening fixtures added (#93)


def _observations(fixture: dict[str, Any]) -> dict[str, Any]:
    return {"reconciliations": fixture.get("observations", [])}


def _verifier_codes(fixture: dict[str, Any]) -> set[str]:
    """The ODES-named refusal codes the verifier's own ledger code produces for a fixture."""
    doc = fixture["document"]
    if ledger.shape(doc):
        return {"@structure"}
    codes: set[str] = set()
    for check in (ledger._keys(doc), ledger._counts(doc)):
        codes |= {f.code for f in check.findings}
    obs = _observations(fixture)
    codes |= {f.code for f in ledger._observations_agree(obs, doc).findings}
    return codes


@pytest.mark.parametrize("cls,path", CASES, ids=[f"{c}-{p.stem}" for c, p in CASES])
def test_verifier_ledger_shape_agrees_with_the_odes_validator(cls: str, path: Path) -> None:
    fixture = load(path)
    doc = fixture["document"]
    odes = ORACLE.validate(doc, fixture.get("observations"))
    mine = _verifier_codes(fixture)
    if cls == "valid":
        assert odes == [], fixture["fixture_id"]
        assert mine == set(), fixture["fixture_id"]
        return
    expected = fixture["expected_refusal"]
    assert {v.code for v in odes} == {expected}, fixture["fixture_id"]
    if expected in STRUCTURE:
        assert mine == {"@structure"}, fixture["fixture_id"]
    else:
        # ledger_key_mismatch, ledger_count_mismatch, operation_digest_mismatch: same code names
        assert mine == {expected}, fixture["fixture_id"]


def test_the_ledger_structure_check_is_a_refusal_with_one_code() -> None:
    for p in fixture_paths("destination-ledger", "invalid"):
        fixture = load(p)
        if fixture["expected_refusal"] in STRUCTURE:
            codes = {f.code for f in ledger.shape(fixture["document"])}
            assert codes == {"ledger_shape"}, fixture["fixture_id"]

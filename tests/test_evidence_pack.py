"""Three functional smoke checks of the opt-in Evidence Pack consumer (developer spot checks, not qualification)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from cognous_verify import pack, pack_cli

DATA = Path(__file__).parent / "data" / "evidence-pack"


def _verdicts(rep: dict[str, Any]) -> dict[str, str]:
    return {c["check_id"]: c["verdict"] for c in rep["checks"]}


def test_complete_pack_commitments_confirmed_and_source_identity_never_checked() -> None:
    rep = pack.verify_bytes((DATA / "complete.pack.json").read_bytes())
    v = _verdicts(rep)
    for cid in (
        "pk.retained.input-hashes",
        "pk.retained.pack-id",
        "pk.records.source-record-refs",
        "pk.identity.proposal-payload-commitment",
        "pk.identity.manifest-digest",
        "pk.identity.binding-proposal-commitment",
        "pk.identity.effect-id",
        "pk.executor.operation-commitments",
        "pk.completeness.consistency",
    ):
        assert v[cid] == "confirmed", (cid, rep["checks"])
    assert v["pk.source.identity"] == "could_not_check"
    assert rep["overall"] == "abstain"  # never accept
    assert rep["identities"]["measured"] == []
    assert rep["execution_evidence"]["absent"] == []
    assert any(
        c.startswith("independent_execution_verification") for c in rep["unsupported_claims"]
    )


def test_tampered_commitment_is_refuted_at_the_intended_invariant(tmp_path: Path) -> None:
    doc = json.loads((DATA / "complete.pack.json").read_text(encoding="utf-8"))
    recs = doc["metadata"]["traceable_import"]["retained_sources"]["reconstruction_bundle"][
        "records"
    ]
    prop = next(r["data"] for r in recs if r["record_type"] == "runtime_proposal")
    prop["payload"]["refund_reason"] = "tampered"  # payload_commitment not updated
    path = tmp_path / "tampered.pack.json"
    path.write_text(json.dumps(doc), encoding="utf-8")
    out = tmp_path / "report.json"
    assert pack_cli.main([str(path), "--out", str(out)]) == 1
    rep = json.loads(out.read_text(encoding="utf-8"))
    codes = {f["code"] for c in rep["checks"] for f in c["findings"]}
    assert "payload_commitment_mismatch" in codes
    assert rep["overall"] == "reject"


def test_partial_pack_keeps_execution_evidence_unverified() -> None:
    rep = pack.verify_bytes((DATA / "partial.pack.json").read_bytes())
    v = _verdicts(rep)
    assert v["pk.executor.operation-commitments"] == "could_not_check"
    assert (
        next(c for c in rep["checks"] if c["check_id"] == "pk.executor.operation-commitments")[
            "reason"
        ]
        == "executor_evidence_absent"
    )
    assert (
        v["pk.identity.effect-id"] == "confirmed"
        and v["pk.completeness.consistency"] == "confirmed"
    )
    assert rep["reconstruction"]["declared_status"] == "reconstruction_partial"
    assert set(pack.EXECUTOR_KINDS) == set(rep["execution_evidence"]["absent"])
    assert rep["overall"] == "abstain"
    assert not any(c["verdict"] == "refuted" for c in rep["checks"])

"""Evidence Pack consumer: opt-in, development-only checks over one Evidence Pack file.

Input: an Evidence Pack JSON (``pack_version`` 0.2.0, strict-tenant Replay 7eb7d76e transformation) that
retains the exact Manifest and the full Replay reconstruction bundle. Everything below is recomputed
from that one file with this package's own parser and canonical form. Nothing is imported from the
Replay or Pack code, and nothing is signed, fetched or executed.

What this establishes: structural fit, commitments that agree with the retained records, and which
execution evidence is present or absent. What it cannot establish: who produced the pack, which source
revision produced it, or that any execution happened. Revisions and statuses in the pack are producer
assertions and are reported as asserted, never as measured. The pack's own semantic-validation status
is a producer-written string and is not re-executed here.

The result is its own versioned development contract (``evidence-pack-verification``). It is not an
ODES ``verification-report`` and makes no claim to conform to one. Because source identity can never be
checked, the overall result can be reject, abstain or unsupported, and never accept.
"""

from __future__ import annotations

from typing import Any

from . import generation, wire
from .canon import PROFILE_ID, commitment, digest_bytes

CONTRACT = "evidence-pack-verification"
CONTRACT_VERSION = "0.1.0-dev"
PACK_VERSION = "0.2.0"
TRANSFORMATION = (
    "agep-manifest-reconstruction-import/0.3.11-strict-tenant-replay-7eb7d76e-dev-candidate"
)
REPLAY_GENERATION = "cp2-replay-7eb7d76e-tenant-binding-dev-0.1"
COMPLETE, PARTIAL = "reconstruction_complete", "reconstruction_partial"
EXECUTOR_KINDS = (
    "execution_envelope",
    "execution_result",
    "destination_attempt",
    "destination_effect",
)

UNSUPPORTED_CLAIMS = (
    "authenticated_producer_identity: the pack carries no signature or trust anchor",
    "exact_source_revision_of_producers: revisions are caller-declared labels",
    "independent_execution_verification: executor records are source-asserted by the producer",
    "independent_custody: nothing shows who held the pack or when",
    "independent_assessor_accountability: this is a self-run developer check",
    "pack_semantic_validation_reexecuted: the pack's validator status is a producer-written string",
)
DOES_NOT_PROVE = (
    "A pack whose records were coherently rewritten and recommitted is indistinguishable from a genuine one here.",
    "Agreement between retained records is not evidence that they are genuine.",
    "Absent executor records mean execution evidence was not supplied, not that nothing executed.",
    "This is a verification result about one supplied file; it is not an attestation and authorizes nothing.",
)


class _Check:
    def __init__(self, check_id: str) -> None:
        self.check_id = check_id
        self.findings: list[dict[str, str]] = []
        self.reason: str | None = None
        self.examined = 0

    def refute(self, code: str, locator: str, detail: str) -> None:
        self.findings.append({"code": code, "locator": locator, "detail": detail})

    def cannot(self, reason: str) -> _Check:
        self.reason = reason
        return self

    def done(self) -> dict[str, Any]:
        if self.findings:
            verdict = "refuted"
        elif self.reason is not None:
            verdict = "could_not_check"
        else:
            verdict = "confirmed"
        return {
            "check_id": self.check_id,
            "verdict": verdict,
            "examined": self.examined,
            "reason": self.reason,
            "findings": self.findings,
        }


def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _by_type(records: list[Any]) -> dict[str, list[dict[str, Any]]]:
    out: dict[str, list[dict[str, Any]]] = {}
    for rec in records:
        if isinstance(rec, dict) and isinstance(rec.get("record_type"), str):
            out.setdefault(rec["record_type"], []).append(_dict(rec.get("data")))
    return out


def _unsupported(reason: str) -> dict[str, Any]:
    return {"supported": False, "reason": reason}


def _select(doc: Any) -> dict[str, Any]:
    """The supported pack parts, or ``{"supported": False, "reason": ...}``."""
    if not isinstance(doc, dict) or doc.get("pack_version") != PACK_VERSION:
        return _unsupported(f"pack_version is not {PACK_VERSION}")
    trace = _dict(_dict(doc.get("metadata")).get("traceable_import"))
    if trace.get("transformation_version") != TRANSFORMATION:
        return _unsupported(
            "transformation_version is not the supported strict-tenant 7eb7d76e profile"
        )
    if _dict(trace.get("replay_generation")).get("id") != REPLAY_GENERATION:
        return _unsupported("replay_generation id is not the supported profile")
    src = _dict(trace.get("retained_sources"))
    bundle, manifest = src.get("reconstruction_bundle"), src.get("manifest")
    if (
        not isinstance(bundle, dict)
        or not isinstance(bundle.get("records"), list)
        or manifest is None
    ):
        return _unsupported(
            "pack does not retain the Manifest and the Replay reconstruction bundle"
        )
    if not isinstance(trace.get("source_record_refs"), list) or not isinstance(
        trace.get("input_artifacts"), list
    ):
        return _unsupported("source_record_refs/input_artifacts missing")
    return {"supported": True, "pack": doc, "trace": trace, "bundle": bundle, "manifest": manifest}


def _retained_commitments(p: dict[str, Any]) -> dict[str, Any]:
    trace, doc = p["trace"], p["pack"]
    arts = [_dict(a) for a in trace["input_artifacts"]]
    c = _Check("pk.retained.input-hashes")
    mc, bc = commitment(p["manifest"]), commitment(p["bundle"])
    c.examined = 2
    if len(arts) != 2 or arts[0].get("hash") != mc:
        c.refute(
            "manifest_hash_mismatch",
            "$.metadata.traceable_import.input_artifacts[0].hash",
            "hash is not the commitment of the retained Manifest",
        )
    if len(arts) != 2 or arts[1].get("hash") != bc:
        c.refute(
            "bundle_hash_mismatch",
            "$.metadata.traceable_import.input_artifacts[1].hash",
            "hash is not the commitment of the retained reconstruction bundle",
        )
    d = _Check("pk.retained.pack-id")
    d.examined = 1
    want = (
        "agep-" + commitment({"manifest": mc, "bundle": bc, "transformation": TRANSFORMATION})[7:23]
    )
    if doc.get("pack_id") != want:
        d.refute(
            "pack_id_mismatch",
            "$.pack_id",
            "pack_id is not derived from the retained Manifest and bundle",
        )
    return {"checks": [c.done(), d.done()], "manifest_commitment": mc}


def _record_refs(p: dict[str, Any]) -> dict[str, Any]:
    c = _Check("pk.records.source-record-refs")
    refs, recs = p["trace"]["source_record_refs"], p["bundle"]["records"]
    c.examined = len(recs)
    if len(refs) != len(recs):
        c.refute(
            "record_count_mismatch",
            "$.metadata.traceable_import.source_record_refs",
            f"{len(refs)} refs for {len(recs)} retained records",
        )
    for i, (ref, rec) in enumerate(zip(refs, recs, strict=False)):
        if _dict(ref).get("hash") != commitment(rec):
            c.refute(
                "record_hash_mismatch",
                f"$.metadata.traceable_import.source_record_refs[{i}].hash",
                "hash is not the commitment of the retained record",
            )
    return c.done()


def _identity(p: dict[str, Any], manifest_commitment: str) -> list[dict[str, Any]]:
    kinds = _by_type(p["bundle"]["records"])
    proposals, decisions = kinds.get("runtime_proposal", []), kinds.get("runtime_decision", [])
    pay, man = (
        _Check("pk.identity.proposal-payload-commitment"),
        _Check("pk.identity.manifest-digest"),
    )
    bind, eff = _Check("pk.identity.binding-proposal-commitment"), _Check("pk.identity.effect-id")
    if not proposals:
        for c in (pay, man):
            c.cannot("record_absent:runtime_proposal")
    pay.examined = man.examined = len(proposals)
    for i, prop in enumerate(proposals):
        if commitment(prop.get("payload")) != prop.get("payload_commitment"):
            pay.refute(
                "payload_commitment_mismatch",
                f"$.bundle.records[runtime_proposal {i}].payload_commitment",
                "payload_commitment is not the commitment of the payload",
            )
        if prop.get("manifest_digest") != manifest_commitment:
            man.refute(
                "manifest_digest_mismatch",
                f"$.bundle.records[runtime_proposal {i}].manifest_digest",
                "manifest_digest is not the commitment of the retained Manifest",
            )
    bound = [(i, d, _dict(d.get("binding"))) for i, d in enumerate(decisions) if d.get("binding")]
    if not bound:
        bind.cannot("record_absent:runtime_decision_binding")
        eff.cannot("record_absent:runtime_decision_binding")
    bind.examined = eff.examined = len(bound)
    known = {commitment(prop) for prop in proposals}
    for i, d, b in bound:
        if b.get("proposal_commitment") not in known:
            bind.refute(
                "binding_proposal_mismatch",
                f"$.bundle.records[runtime_decision {i}].binding.proposal_commitment",
                "no retained proposal has the commitment the binding states",
            )
        want = generation.effect_identity(
            b.get("proposal_commitment"),
            b.get("grant_id"),
            b.get("grant_revision"),
            generation.binding_generation(b),
        )
        if want is None or d.get("effect_id") != want:
            eff.refute(
                "invalid_effect_identity",
                f"$.bundle.records[runtime_decision {i}].effect_id",
                "effect_id is not the commitment of {proposal, grant_id, grant_revision[, tenant generation]}",
            )
    return [pay.done(), man.done(), bind.done(), eff.done()]


def _executor(p: dict[str, Any]) -> dict[str, Any]:
    kinds = _by_type(p["bundle"]["records"])
    c = _Check("pk.executor.operation-commitments")
    envs, effects = kinds.get("execution_envelope", []), kinds.get("destination_effect", [])
    if not envs:
        return c.cannot("executor_evidence_absent").done()
    proposals = {commitment(x) for x in kinds.get("runtime_proposal", [])}
    ops = {commitment(_dict(e.get("operation"))) for e in envs}
    c.examined = len(envs) + len(effects)
    for i, e in enumerate(envs):
        op = _dict(e.get("operation"))
        if commitment(op.get("payload")) != op.get("payload_commitment"):
            c.refute(
                "operation_payload_mismatch",
                f"$.bundle.records[execution_envelope {i}].operation.payload_commitment",
                "payload_commitment is not the commitment of the operation payload",
            )
        if op.get("proposal_commitment") not in proposals:
            c.refute(
                "operation_proposal_mismatch",
                f"$.bundle.records[execution_envelope {i}].operation.proposal_commitment",
                "no retained proposal has the commitment the operation states",
            )
    for i, e in enumerate(effects):
        if e.get("operation_digest") not in ops:
            c.refute(
                "effect_operation_mismatch",
                f"$.bundle.records[destination_effect {i}].operation_digest",
                "operation_digest is not the commitment of a retained operation",
            )
    return c.done()


def _completeness(p: dict[str, Any]) -> dict[str, Any]:
    c, trace, bundle = _Check("pk.completeness.consistency"), p["trace"], p["bundle"]
    kinds = _by_type(bundle["records"])
    status, mirrored = bundle.get("status"), trace.get("reconstruction_completeness")
    claimed = _dict(trace.get("replay_semantic_validation")).get("status")
    c.examined = 3
    want = {COMPLETE: "validated_complete", PARTIAL: "validated_partial"}
    if status not in want:
        c.refute(
            "bundle_status_unknown", "$.bundle.status", "bundle status is not complete or partial"
        )
    elif mirrored != status or claimed != want[status]:
        c.refute(
            "completeness_mismatch",
            "$.metadata.traceable_import.reconstruction_completeness",
            "bundle status, pack completeness and semantic-validation status disagree",
        )
    present = [k for k in EXECUTOR_KINDS if k in kinds]
    if status == COMPLETE and len(present) != len(EXECUTOR_KINDS):
        c.refute(
            "complete_without_executor_records",
            "$.bundle.records",
            "a complete reconstruction is missing executor record kinds: "
            + ", ".join(k for k in EXECUTOR_KINDS if k not in present),
        )
    counts = _dict(trace.get("derived_counts"))
    if counts.get("executor_attempt_count") != len(
        kinds.get("destination_attempt", [])
    ) or counts.get("destination_effect_count") != len(kinds.get("destination_effect", [])):
        c.refute(
            "derived_count_mismatch",
            "$.metadata.traceable_import.derived_counts",
            "executor counts disagree with the retained records",
        )
    return c.done()


def _identities(p: dict[str, Any]) -> dict[str, Any]:
    trace, bundle = p["trace"], p["bundle"]
    gen = _dict(trace.get("replay_generation"))
    profiles = [
        {"profile_id": _dict(x).get("profile_id"), "revision": _dict(x).get("revision")}
        for x in bundle.get("producer_profiles", [])
    ]
    return {
        "asserted": {
            "replay_generation": gen,
            "producer_profiles": profiles,
            "pack_semantic_validation": trace.get("replay_semantic_validation"),
        },
        "measured": [],
        "unverified": "every revision above is a producer or caller declaration; no pin authority, "
        "signature or trust mechanism exists to check it",
    }


def verify_bytes(data: bytes, name: str = "evidence-pack.json") -> dict[str, Any]:
    """Verify one Evidence Pack file. Returns the report (``overall`` in reject/abstain/unsupported)."""
    report: dict[str, Any] = {
        "contract": CONTRACT,
        "contract_version": CONTRACT_VERSION,
        "development_only": True,
        "subject": {
            "name": name,
            "digest": digest_bytes(data),
            "canonicalization_profile": PROFILE_ID,
        },
        "checks": [],
        "unsupported_claims": list(UNSUPPORTED_CLAIMS),
        "does_not_prove": list(DOES_NOT_PROVE),
    }
    checks: list[dict[str, Any]] = report["checks"]
    try:
        doc = wire.parse(data)
    except wire.WireError as exc:
        c = _Check("pk.wire.strict-parse")
        c.refute(exc.code, "$", exc.message)
        checks.append(c.done())
        return _finish(report)
    parse_ok = _Check("pk.wire.strict-parse")
    parse_ok.examined = 1
    checks.append(parse_ok.done())
    p = _select(doc)
    if not p["supported"]:
        report["unsupported_input"] = p["reason"]
        return _finish(report)
    try:
        r = _retained_commitments(p)
        checks += r["checks"]
        checks.append(_record_refs(p))
        checks += _identity(p, r["manifest_commitment"])
        checks.append(_executor(p))
        checks.append(_completeness(p))
        report["identities"] = _identities(p)
    except (TypeError, KeyError, ValueError, AttributeError, IndexError) as exc:
        # a parseable pack whose members have the wrong type is refused, never a crash
        c = _Check("pk.structure.member-types")
        c.refute(
            "malformed_pack_member", "$", f"a member has an unsupported type ({type(exc).__name__})"
        )
        checks.append(c.done())
        return _finish(report)
    kinds = _by_type(p["bundle"]["records"])
    report["reconstruction"] = {
        "declared_status": p["bundle"].get("status"),
        "source": "producer-declared",
    }
    report["execution_evidence"] = {
        "present": [k for k in EXECUTOR_KINDS if k in kinds],
        "absent": [k for k in EXECUTOR_KINDS if k not in kinds],
        "note": "absent kinds are unevaluated, not a measured absence of execution; present kinds are source-asserted",
    }
    checks.append(_Check("pk.source.identity").cannot("no_authenticating_mechanism").done())
    return _finish(report)


def _finish(report: dict[str, Any]) -> dict[str, Any]:
    checks = report["checks"]
    tally = {
        v: sum(1 for c in checks if c["verdict"] == v)
        for v in ("confirmed", "could_not_check", "refuted")
    }
    report["summary"] = {"checks": len(checks), **tally}
    if tally["refuted"]:
        report["overall"] = "reject"
    elif "unsupported_input" in report:
        report["overall"] = "unsupported"
    else:
        report["overall"] = "abstain"  # source identity is never checkable, so never accept
    return report

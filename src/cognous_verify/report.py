"""Shape an evaluation into a ``verification-report`` document (ODES contract 0.1.0-draft).

The report is three-valued per check with explicit denominators and has no composite score.
It carries the mandatory ``does_not_prove`` block. It is a verification report, not an
attestation. A crash inside a check produces no report at all (see ``cli``), never a verdict.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from typing import Any

from . import __version__, data, documents, witness
from .canon import PROFILE_ID, commitment
from .engine import Evaluation, inputs_commitment
from .results import CheckResult

CONTRACT = "verification-report"
CONTRACT_VERSION = "0.1.0-draft"
PROFILE = "verification-report/0.1"
REPORT_KIND = "verification_report"
VERIFIER_NAME = "cognous-open-control-stack-verifier"
COMMAND = "cognous-verify"
UNSTATED = "unstated"
REASONS = ("input_absent", "tier_unavailable", "profile_ambiguous", "not_applicable_to_input")

NON_CLAIMS: tuple[tuple[str, str], ...] = (
    (
        "relative_to_pinned_controller",
        "The result holds for the controller revision (as declared by the caller; 'unstated' if "
        "none was declared), the contract draft versions and the reason registry named in "
        "subject.pinned. It does not carry to any other revision.",
    ),
    (
        "semantic_quality_not_certified",
        "No claim that a decision was correct, that a policy was adequate, or that a grant was "
        "lawfully issued. The verifier checks structure, identity and agreement between records, "
        "not whether the decisions were right.",
    ),
    (
        "receipt_source_bounded",
        "Destination checks cover only the rows in the supplied ledger snapshot. The snapshot "
        "has no sequence number, chain or signature, so completeness is not established: a "
        "dropped tail or a decision that never reached the ledger cannot be seen.",
    ),
    (
        "self_consistent_forgery_not_detected",
        "A forged set of records in which every commitment was recomputed to agree is "
        "indistinguishable from a genuine one by these checks. Agreement between records is not "
        "evidence that they are genuine.",
    ),
    (
        "not_an_attestation",
        "This is a verification report about supplied records. It is not signed, not an "
        "attestation, and authorizes nothing.",
    ),
    (
        "parse_strictness_is_refusal_not_repair",
        "An input the strict parser refuses (duplicate members, NaN or Infinity, non-UTF-8, "
        "over-size, lone surrogates) is refused and reported, never repaired and re-read.",
    ),
    (
        "no_v1_scope_claim",
        "No claim about the scope or release status of any V1 of the stack. Nothing here is a "
        "release, a publication or an endorsement.",
    ),
    (
        "differential_agreement_is_not_equivalence",
        "Agreement with a reference validator on a fixture set is a check against common-mode "
        "error. It does not show that the two implementations are equivalent.",
    ),
)


def reason_member(raw: str | None) -> str | None:
    """Map an internal reason string onto the contract's closed reason set."""
    if raw is None:
        return None
    head = raw.split(":", 1)[0]
    if head in REASONS:
        return head
    if head in ("decision_has_no_supplied_proposal", "proposal_names_no_run"):
        return "input_absent"
    if head in ("no_items_in_record", "no_journal_in_record", "unsupported_document"):
        return "not_applicable_to_input"
    if head == "rows_not_covered_by_witness":
        return "input_absent"
    return "tier_unavailable"


def check_member(r: CheckResult) -> dict[str, Any]:
    tally = r.tally()
    out: dict[str, Any] = {
        "check_id": r.check_id,
        "tier": r.tier,
        "verdict": r.verdict,
        "tally": tally,
        "could_not_check_reason": reason_member(r.reason) if tally["could_not_check"] else None,
        "findings": [
            {"code": f.code, "locator": f.path or "$", "detail": f.message or f.code}
            for f in r.findings
        ],
    }
    ext: dict[str, Any] = {"x-unit": r.unit}
    if r.reason is not None and tally["could_not_check"]:
        ext["x-reason"] = r.reason
    if r.notes:
        ext["x-notes"] = list(r.notes)
    out["extensions"] = ext
    return out


def v3_section(v3: witness.TierV3) -> dict[str, Any]:
    return {
        "requested": v3.requested,
        "inputs": list(v3.inputs),
        "checks": [check_member(r) for r in v3.results],
        "not_applicable": list(v3.not_applicable),
        "limits": list(v3.notes),
    }


def build(
    ev: Evaluation,
    *,
    generated_at: str | None = None,
    controller_revision: str | None = None,
    source_revision: str | None = None,
) -> dict[str, Any]:
    """Build the report for ``ev``. Raises ValueError for a crashed evaluation."""
    if ev.crashed:
        raise ValueError("an evaluation containing a verifier error produces no report")
    checks = [check_member(r) for r in ev.results]
    counts = {"confirmed": 0, "could_not_check": 0, "refuted": 0}
    for c in checks:
        counts[c["verdict"]] += 1
    tiers = sorted({c["tier"] for c in checks})
    inputs_digest = inputs_commitment(ev.inputs)
    when = generated_at or datetime.now(UTC).isoformat(timespec="seconds")
    body_digest = hashlib.sha256((inputs_digest + commitment(checks)).encode()).hexdigest()
    extensions: dict[str, Any] = {
        "x-overall": ev.overall,
        "x-not-applicable": list(ev.not_applicable),
        "x-notes": list(ev.notes),
    }
    if ev.counters is not None:
        extensions["x-recomputed-counters"] = ev.counters
    if ev.v3 is not None:
        # The contract's tier set has no V3 (a new tier is a major bump), so the V3 checks sit
        # here, in the checks shape, outside ``checks`` and ``summary``.
        extensions["x-tier-v3"] = v3_section(ev.v3)
        if ev.v3.requested:
            body_digest = hashlib.sha256(
                (body_digest + commitment(extensions["x-tier-v3"])).encode()
            ).hexdigest()
    return {
        "contract": CONTRACT,
        "contract_version": CONTRACT_VERSION,
        "profile": PROFILE,
        "report_kind": REPORT_KIND,
        "report_id": f"vr-{body_digest[:16]}",
        "generated_at": when,
        "verifier": {
            "name": VERIFIER_NAME,
            "version": __version__,
            "command": COMMAND,
            "source_revision": source_revision or UNSTATED,
            "canonicalization_profile": PROFILE_ID,
        },
        "subject": {
            "canonicalization_profile": PROFILE_ID,
            "inputs": list(ev.inputs),
            "inputs_digest": inputs_digest,
            "pinned": {
                "controller_revision": controller_revision or UNSTATED,
                "contract_versions": {
                    documents.JOURNAL: documents.CONTRACT_VERSION,
                    documents.LIFECYCLE: documents.CONTRACT_VERSION,
                },
                "reason_registry_digest": data.registry_digest(),
            },
        },
        "scope": {"semantic_quality": "not_assessed", "tiers_run": tiers},
        "checks": checks,
        "summary": {"checks": len(checks), **counts},
        "does_not_prove": [{"id": i, "statement": s} for i, s in NON_CLAIMS],
        "mutation_report": None,
        "extensions": extensions,
    }

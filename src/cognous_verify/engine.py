"""Run every tier over the supplied inputs and collect the checks.

Inputs are files, each with a role: one ``run_record`` (required), any number of
``proposal_export``, at most one ``manifest`` and at most one ``destination_ledger``. The
verifier reads only these. It takes no outcome label of any kind: a report is produced from
the records alone, before any expected outcome or label could be joined to it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from . import documents, identity, ledger, wire, witness
from .canon import commitment, digest_bytes
from .results import CheckResult, Finding, could_not_check, make_result, verifier_error

RUN_RECORD = "run_record"
PROPOSAL_EXPORT = "proposal_export"
MANIFEST = "manifest"
DESTINATION_LEDGER = "destination_ledger"
WITNESS = witness.WITNESS_ROLE
HOLDER_INVENTORY = witness.HOLDER_ROLE
ROLES = (RUN_RECORD, PROPOSAL_EXPORT, MANIFEST, DESTINATION_LEDGER)
# Inputs read by tier V3 only: the report contract has no input role for them, so they are named
# in the V3 section of the report and not in ``subject.inputs``.
V3_ROLES = witness.V3_ROLES


@dataclass(frozen=True)
class InputFile:
    role: str
    name: str
    data: bytes


NOT_APPLICABLE_REASONS = ("no_items_in_record", "no_journal_in_record")


@dataclass
class Evaluation:
    """Everything the checks produced, before it is shaped into a report.

    ``results`` are the checks that had something to examine or lacked an input. Checks over
    zero items in the record (no refusals, no journal, ...) are not emitted as results: they
    are listed in ``not_applicable`` with their reason, so the report still says which parts
    were not examined without letting them read as a missing input.
    """

    results: list[CheckResult]
    inputs: list[dict[str, Any]]
    counters: dict[str, Any] | None = None
    notes: list[str] = field(default_factory=list)
    not_applicable: list[dict[str, str]] = field(default_factory=list)
    v3: witness.TierV3 | None = None

    @property
    def crashed(self) -> bool:
        v3 = self.v3.results if self.v3 else []
        return any(r.error for r in [*self.results, *v3])

    def finish(self) -> Evaluation:
        """Move checks with nothing to examine out of ``results``."""
        kept: list[CheckResult] = []
        for r in self.results:
            if r.verdict == "could_not_check" and r.reason in NOT_APPLICABLE_REASONS:
                self.not_applicable.append(
                    {"check_id": r.check_id, "tier": r.tier, "unit": r.unit, "reason": r.reason}
                )
            else:
                kept.append(r)
        self.results = kept
        return self

    @property
    def overall(self) -> str:
        """Derived, never a score: reject if any check is refuted, abstain if any could not be
        checked or none ran, accept if every check that ran is confirmed. Tier V3 results count
        when a witness or inventory input was supplied (``TierV3.counted``)."""
        results = self.results + (self.v3.counted() if self.v3 else [])
        if any(r.verdict == "refuted" for r in results):
            return "reject"
        if not results or any(r.verdict != "confirmed" for r in results):
            return "abstain"
        return "accept"


def _wire_check(files: list[InputFile]) -> tuple[CheckResult, dict[int, Any]]:
    parsed: dict[int, Any] = {}
    findings: list[Finding] = []
    for i, f in enumerate(files):
        try:
            parsed[i] = wire.parse(f.data)
        except wire.WireError as exc:
            findings.append(
                Finding(
                    exc.code,
                    f"$.inputs[{i}]",
                    f"{f.role} {f.name}: {exc.message} (offset {exc.offset})",
                )
            )
    return make_result("v1.wire.strict-parse", "V1", "input files", len(files), findings), parsed


def _input_row(f: InputFile) -> dict[str, Any]:
    return {
        "role": f.role,
        "name": f.name,
        "digest": digest_bytes(f.data),
        "size_bytes": len(f.data),
    }


def _manifest_check(manifest: Any) -> CheckResult:
    findings = (
        []
        if type(manifest) is dict
        else [Finding("manifest_shape", "$", "a manifest is a JSON object")]
    )
    return make_result("v1.structure.manifest", "V1", "manifests", 1, findings)


def evaluate(files: list[InputFile]) -> Evaluation:
    """Run V1, V2 and V4 over ``files`` (exactly one run record), and V3 over the witness and
    holder inventory inputs, which only tier V3 reads."""
    core = [f for f in files if f.role not in V3_ROLES]
    ev = _evaluate(core).finish()
    ev.v3 = _tier_v3(core, files)
    return ev


def _tier_v3(core: list[InputFile], files: list[InputFile]) -> witness.TierV3:
    record_file = next(f for f in core if f.role == RUN_RECORD)
    try:
        record: Any = wire.parse(record_file.data)
    except wire.WireError:
        record = None  # reported by the wire check; V3 then has nothing to compare
    pick = {r: next(((f.name, f.data) for f in files if f.role == r), None) for r in V3_ROLES}
    kind, _raw = documents.detect_kind(record)
    try:
        return witness.run_tier(
            record,
            pick[WITNESS],
            pick[HOLDER_INVENTORY],
            contract_is_journal=kind == documents.JOURNAL,
        )
    except Exception as exc:  # a crash is an error, never a verdict
        bad = verifier_error("v3.tier", witness.V3, "witness inputs", 0, exc)
        return witness.TierV3(results=[bad], inputs=[], requested=True)


def _evaluate(files: list[InputFile]) -> Evaluation:
    records = [i for i, f in enumerate(files) if f.role == RUN_RECORD]
    if len(records) != 1:
        raise ValueError("exactly one run_record input is required")
    wire_result, parsed = _wire_check(files)
    results: list[CheckResult] = [wire_result]
    rows = sorted((_input_row(f) for f in files), key=lambda r: (r["role"], r["name"], r["digest"]))
    ev = Evaluation(results=results, inputs=rows)
    rec_index = records[0]
    if rec_index not in parsed:
        results.append(
            could_not_check(
                "v1.structure.run-record",
                "V1",
                "documents",
                1,
                "tier_unavailable:run_record_not_parsed",
            )
        )
        return ev
    record = parsed[rec_index]
    try:
        doc_results = documents.verify_document(record)
    except Exception as exc:  # a crash is an error, never a verdict
        results.append(verifier_error("v1.structure.run-record", "V1", "documents", 1, exc))
        return ev
    results.extend(doc_results)
    contract, _raw = documents.detect_kind(record)
    structure_ok = bool(doc_results) and doc_results[0].verdict == "confirmed"
    if contract != documents.JOURNAL or not structure_ok:
        if contract == documents.JOURNAL:
            results.extend(_dependent_skips("tier_unavailable:structure_refuted"))
        else:
            ev.notes.append(
                "identity and ledger checks apply to control-plane run records only; "
                "this document kind has none"
            )
        return ev
    _journal_tiers(ev, files, parsed, record)
    return ev


def _dependent_skips(reason: str) -> list[CheckResult]:
    out = [
        could_not_check(cid, "V2", unit, 0, reason)
        for cid, unit in (
            ("v2.decisions.reason-registry", "decisions and refusals"),
            ("v2.decisions.authorized-inputs-agree", "authorized decisions"),
            ("v2.decisions.recomputable-reasons", "decisions and refusals"),
            ("v2.identity.proposal-commitment", "decisions"),
        )
    ]
    out += ledger.skipped_all(reason)
    return out


def _journal_tiers(
    ev: Evaluation, files: list[InputFile], parsed: dict[int, Any], record: dict[str, Any]
) -> None:
    results = ev.results
    try:
        results.extend(identity.decision_checks(record))
    except Exception as exc:
        results.append(verifier_error("v2.decisions", "V2", "decisions", 0, exc))
    # proposals
    proposal_idx = [i for i, f in enumerate(files) if f.role == PROPOSAL_EXPORT]
    proposals: list[dict[str, Any]] | None = None
    if proposal_idx:
        parsed_p = [(files[i].name, parsed[i]) for i in proposal_idx if i in parsed]
        results.append(identity.proposal_structure(parsed_p))
        unreadable = len(proposal_idx) - len(parsed_p)
        shape_bad = results[-1].verdict == "refuted"
        if unreadable or shape_bad:
            results.extend(
                could_not_check(cid, "V2", unit, 0, "tier_unavailable:proposal_not_usable")
                for cid, unit in (
                    ("v2.identity.proposal-commitment", "decisions"),
                    ("v2.identity.effect-id", "decisions"),
                    ("v2.identity.binding-fields", "authorized decisions"),
                    ("v2.identity.horizon-times", "decisions"),
                    ("v2.identity.payload-commitment", "proposal exports"),
                    ("v2.identity.run-id", "proposal exports"),
                    ("v2.identity.manifest-digest", "proposal exports"),
                )
            )
        else:
            proposals = [doc for _, doc in parsed_p]
    manifest: Any | None = None
    man_idx = [i for i, f in enumerate(files) if f.role == MANIFEST]
    if man_idx and man_idx[0] in parsed:
        manifest = parsed[man_idx[0]]
        results.append(_manifest_check(manifest))
    if proposals is not None or not proposal_idx:
        try:
            results.extend(identity.run(record, proposals, manifest))
        except Exception as exc:
            results.append(verifier_error("v2.identity", "V2", "decisions", 0, exc))
    # ledger
    led_idx = [i for i, f in enumerate(files) if f.role == DESTINATION_LEDGER]
    if not led_idx:
        results.extend(ledger.skipped_all("input_absent:destination_ledger"))
        return
    if led_idx[0] not in parsed:
        results.extend(ledger.skipped_all("tier_unavailable:ledger_not_parsed"))
        return
    led = parsed[led_idx[0]]
    shape = ledger.structure(led)
    results.append(shape)
    if shape.verdict == "refuted":
        results.extend(ledger.skipped_all("tier_unavailable:ledger_shape_refuted"))
        return
    try:
        results.extend(ledger.run(record, led))
        ev.counters = ledger.counters(record, led)
        ev.notes.append(ledger.COMPLETENESS_NOTE)
    except Exception as exc:
        results.append(verifier_error("v4.ledger", "V4", "ledger rows", 0, exc))


def inputs_commitment(rows: list[dict[str, Any]]) -> str:
    """Commitment over the inputs list exactly as written (the report's ``inputs_digest``)."""
    return commitment(rows)

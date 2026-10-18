"""Tiers V1 (structure) and V2 (internal consistency) over one parsed document.

Two document kinds are read: a control-plane run record (the contract
``control-plane-journal``; a raw producer record carries no ``contract`` members and is
treated as that contract, which the check notes) and an ``execution-attempt-lifecycle``
document. Every rule group is its own check with its own denominator and verdict.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from . import data, profile, rules_journal, rules_lifecycle, schema, sidecar
from .results import (
    CheckResult,
    Finding,
    could_not_check,
    verifier_error,
)
from .results import (
    confirmed_or_refuted as _done,
)

JOURNAL = "control-plane-journal"
LIFECYCLE = "execution-attempt-lifecycle"
CONTRACT_VERSION = "0.1.0-draft"
V1 = "V1"
V2 = "V2"


def detect_kind(doc: Any) -> tuple[str | None, bool]:
    """Return (contract, raw). ``raw`` is True for a producer record without contract members."""
    if not isinstance(doc, dict):
        return None, False
    declared = doc.get("contract")
    if declared in (JOURNAL, LIFECYCLE):
        return str(declared), False
    if (
        declared is None
        and "contract_version" not in doc
        and "decisions" in doc
        and "attempts" in doc
    ):
        return JOURNAL, True
    return None, False


def is_journal_shaped(doc: Any) -> bool:
    """True for a record tier V3 may compare with a witness as a control-plane record store.

    That is every control-plane-journal document, and also a raw producer record (no ``contract``
    and no ``contract_version`` member) that still has ``decisions`` or ``attempts``: a raw record
    that has lost one of those two members is not recognised by ``detect_kind`` (it is
    ``unsupported_document`` for V1 and V2), but a witness can still show the loss, because a
    ledger missing from the record counts as empty. Used only when a witness is supplied; it
    changes no V1 or V2 outcome.
    """
    if detect_kind(doc)[0] == JOURNAL:
        return True
    return (
        isinstance(doc, dict)
        and "contract" not in doc
        and "contract_version" not in doc
        and ("decisions" in doc or "attempts" in doc)
    )


def _guard(
    check_id: str,
    unit: str,
    total: int,
    fn: Callable[[], list[Finding]],
    *,
    vacuous_ok: bool = False,
) -> CheckResult:
    try:
        findings = fn()
    except rules_lifecycle.LimitExceeded as exc:
        return could_not_check(
            check_id, V2, unit, total, f"tier_unavailable:input_exceeds_limit:{exc}"
        )
    except Exception as exc:  # a crash is reported as an error, never as a verdict
        return verifier_error(check_id, V2, unit, total, exc)
    if not findings and total == 0 and not vacuous_ok:
        return could_not_check(check_id, V2, unit, 0, "no_items_in_record")
    return _done(check_id, V2, unit, total, findings)


def structure(doc: Any, contract: str, raw: bool) -> CheckResult:
    """Tier V1: closed members, enums, extension names, constants, patterns."""
    notes = [f"schema sha256 {data.schema_digest(contract)}"]
    check_doc = doc
    if raw:
        check_doc = {"contract": contract, "contract_version": CONTRACT_VERSION, **doc}
        notes.append(
            "raw producer record: no contract or contract_version member; they were supplied for "
            "this check only and the record itself was not altered"
        )
    findings: list[Finding] = []
    if (
        isinstance(check_doc.get("contract_version"), str)
        and check_doc["contract_version"] != CONTRACT_VERSION
        and check_doc.get("contract") == contract
    ):
        findings.append(
            Finding(
                "unsupported_contract_version",
                "$.contract_version",
                f"this verifier implements {CONTRACT_VERSION} only",
            )
        )
    else:
        findings = schema.validate_structure(check_doc, data.schema(contract))
    result = _done("v1.structure", V1, "document", 1, findings, notes)
    return result


def _skip_all(prefix: str, reason: str, groups: list[tuple[str, str, int]]) -> list[CheckResult]:
    return [
        could_not_check(f"{prefix}{name}", V2, unit, total, reason) for name, unit, total in groups
    ]


def _journal_groups(doc: dict[str, Any]) -> list[tuple[str, str, int, Callable[[], list[Finding]]]]:
    n = len
    cp_total = n(doc["attempts"])
    groups = _base_journal_groups(doc, cp_total)
    items = profile.count_profile_items(doc)
    if items:  # only a record with a freshness value gets this group; default reports are unchanged
        groups.append(("profile", "profile values", items, lambda: profile.value_findings(doc)))
    return groups


def _base_journal_groups(
    doc: dict[str, Any], cp_total: int
) -> list[tuple[str, str, int, Callable[[], list[Finding]]]]:
    n = len
    return [
        ("decisions", "decisions", n(doc["decisions"]), lambda: rules_journal.decisions(doc)),
        (
            "references",
            "rows",
            n(doc["attempts"])
            + n(doc["refusals"])
            + n(doc.get("check_events", []))
            + n(doc["observations"])
            + n(doc["reconciliations"]),
            lambda: rules_journal.references(doc),
        ),
        ("attempts", "attempt rows", cp_total, lambda: rules_journal.attempts(doc)),
        (
            "reconciliations",
            "reconciliations",
            n(doc["reconciliations"]),
            lambda: rules_journal.reconciliations(doc),
        ),
        (
            "closeouts",
            "closeouts and attempt rows",
            n(doc["closeouts"]) + cp_total,
            lambda: rules_journal.closeouts(doc),
        ),
        ("refusals", "refusals", n(doc["refusals"]), lambda: rules_journal.refusals(doc)),
        (
            "inputs_and_times",
            "inputs and timestamps",
            rules_journal.count_inputs_and_times(doc),
            lambda: rules_journal.inputs_and_times(doc),
        ),
        (
            "journal_mode",
            "decisions and refusals",
            n(doc["decisions"]) + n(doc["refusals"]),
            lambda: rules_journal.journal_mode(doc),
        ),
        (
            "vocabulary",
            "vocabulary changes",
            n(doc.get("vocabulary_changes", [])),
            lambda: rules_journal.vocabulary(doc),
        ),
        (
            "check_ids",
            "resolution checks",
            n(doc["resolution_checks"]),
            lambda: rules_lifecycle.check_ids(doc["resolution_checks"], "$.resolution_checks"),
        ),
    ]


def _check_bindings_group(doc: dict[str, Any], earlier: list[CheckResult]) -> CheckResult:
    total = len(doc["decisions"]) + len(doc["refusals"]) + len(doc["resolution_checks"])
    unit = "decisions, refusals and resolution checks"
    if any(r.verdict == "refuted" or r.error for r in earlier):
        return could_not_check(
            "v2.journal.check_bindings", V2, unit, total, "earlier_rules_refuted"
        )
    return _guard(
        "v2.journal.check_bindings", unit, total, lambda: rules_journal.check_bindings(doc)
    )


def journal_rules(doc: dict[str, Any]) -> list[CheckResult]:
    """Tier V2 for a control-plane run record."""
    results: list[CheckResult] = []
    for name, unit, total, fn in _journal_groups(doc):
        results.append(_guard(f"v2.journal.{name}", unit, total, fn))
    refuted = any(r.verdict == "refuted" or r.error for r in results)
    attempts_total = len(doc["attempts"])
    events = doc.get("check_events")
    events_total = len(events) if events is not None else 0
    delegated = [
        ("v2.lifecycle.control_plane_attempts", "attempt rows", attempts_total),
        ("v2.lifecycle.journal_protocol", "journal events", events_total),
    ]
    if refuted:
        results += [
            could_not_check(cid, V2, unit, total, "earlier_rules_refuted")
            for cid, unit, total in delegated
        ]
        return [*results, _check_bindings_group(doc, results), *sidecar.profile_checks(doc)]
    results.append(
        _guard(
            delegated[0][0],
            delegated[0][1],
            delegated[0][2],
            lambda: rules_lifecycle.control_plane_attempts(doc["attempts"], "$.attempts"),
        )
    )
    if events is None:
        results.append(
            could_not_check(delegated[1][0], V2, delegated[1][1], 0, "no_journal_in_record")
        )
    else:
        results.append(
            _guard(
                delegated[1][0],
                delegated[1][1],
                delegated[1][2],
                lambda: [
                    # overdue and expired are freshness/0.1 phases, not the lifecycle contract's
                    *rules_lifecycle.journal(
                        [e for e in events if e["phase"] not in profile.PROFILE_PHASES],
                        doc["resolution_checks"],
                        "$.check_events",
                    ),
                ],
            )
        )
    # A verifier-side rule: it runs after the contract groups and only when they found nothing,
    # so a contract refusal code is never accompanied by a verifier-side one.
    results.append(_check_bindings_group(doc, results))
    # Opt-in profile semantics (operation identity, rule revision, freshness): one check per
    # profile that has a member in the record, none for a default record.
    results.extend(sidecar.profile_checks(doc))
    return results


def lifecycle_rules(doc: dict[str, Any]) -> list[CheckResult]:
    """Tier V2 for an execution-attempt-lifecycle document."""
    n = len
    results: list[CheckResult] = []
    results.append(
        _guard(
            "v2.lifecycle.executor_rows",
            "executor attempt rows",
            n(doc.get("attempts", [])),
            lambda: rules_lifecycle.executor_rows(doc),
        )
    )
    cp = doc.get("control_plane_attempts")
    results.append(
        _guard(
            "v2.lifecycle.control_plane_attempts",
            "attempt rows",
            n(cp or []),
            lambda: rules_lifecycle.control_plane_attempts(cp or [], "$.control_plane_attempts"),
        )
    )
    events = doc.get("resolution_journal")
    checks = doc.get("resolution_checks", [])
    if events is None:
        results.append(
            could_not_check(
                "v2.lifecycle.journal_protocol", V2, "journal events", 0, "no_journal_in_record"
            )
        )
        return results

    def _journal() -> list[Finding]:
        return [
            *rules_lifecycle.check_ids(checks, "$.resolution_checks"),
            *rules_lifecycle.journal(events, checks, "$.resolution_journal"),
        ]

    results.append(_guard("v2.lifecycle.journal_protocol", "journal events", n(events), _journal))
    return results


def verify_document(doc: Any) -> list[CheckResult]:
    """All V1 and V2 checks for one parsed document."""
    contract, raw = detect_kind(doc)
    if contract is None:
        return [
            could_not_check(
                "v1.structure",
                V1,
                "document",
                1,
                "unsupported_document: not a control-plane-journal or execution-attempt-lifecycle "
                "document",
            )
        ]
    struct = structure(doc, contract, raw)
    results = [struct]
    if struct.verdict == "refuted":
        groups: list[tuple[str, str, int]]
        if contract == JOURNAL:
            groups = [(f"journal.{n}", u, 0) for n, u, _, _ in _journal_groups_placeholder()]
            groups += [("lifecycle.control_plane_attempts", "attempt rows", 0)]
            groups += [("lifecycle.journal_protocol", "journal events", 0)]
            groups += [("journal.check_bindings", "decisions, refusals and resolution checks", 0)]
        else:
            groups = [
                ("lifecycle.executor_rows", "executor attempt rows", 0),
                ("lifecycle.control_plane_attempts", "attempt rows", 0),
                ("lifecycle.journal_protocol", "journal events", 0),
            ]
        return results + _skip_all("v2.", "structure_refuted", groups)
    if contract == JOURNAL:
        return results + journal_rules(doc)
    return results + lifecycle_rules(doc)


def _journal_groups_placeholder() -> list[tuple[str, str, int, None]]:
    names = [
        ("decisions", "decisions"),
        ("references", "rows"),
        ("attempts", "attempt rows"),
        ("reconciliations", "reconciliations"),
        ("closeouts", "closeouts and attempt rows"),
        ("refusals", "refusals"),
        ("inputs_and_times", "inputs and timestamps"),
        ("journal_mode", "decisions and refusals"),
        ("vocabulary", "vocabulary changes"),
        ("check_ids", "resolution checks"),
    ]
    return [(n, u, 0, None) for n, u in names]

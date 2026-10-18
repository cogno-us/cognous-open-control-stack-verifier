"""Opt-in profile semantics re-derived from the run record alone (tier V2, three checks).

The journal contract declares the members of the three opt-in control-plane profiles
(``operation-identity/0.1``, ``rule-revision/0.1``, ``freshness/0.1``) as optional and leaves their
meaning to the sidecar contracts of the same names. ``profile.py`` admits the members and relaxes
four journal rules; nothing there asks whether an operation id joins the right rows, whether a rule
digest resolves the way its identity row says, or whether a deadline is the opening time plus the
age bound. A record tampered only in those members was accepted. This module closes that, for the
rules a record can answer by itself.

Written here from the ODES contract texts (``tests/data/<contract>/``, revision in SOURCE.json); the
sidecar validators are test oracles, never imported. Each check runs only when a member of its
profile is present in the record, so a record without profile members gets no new check and its
report is unchanged. A profile member is read as the sidecar contract reads it; where the
sidecar defines a projection document (clock rows, input reads, reports) that a raw record does not
carry, the rule is not made here.

Not derivable from the record, hence not checked (host configuration is in no record): the
configured signer set, the declared extension limit and the resolver's capability. The signer
state of a rule revision therefore cannot be recomputed where an identity row names
``signer_not_configured``; that row is reported ``could_not_check``.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timedelta
from typing import Any

from . import profile, rules_journal
from .results import CheckResult, Finding, could_not_check, make_result, verifier_error
from .timeutil import aware

OPERATION_CHECK = "v2.profile.operation-identity"
RULE_CHECK = "v2.profile.rule-revision"
FRESHNESS_CHECK = "v2.profile.freshness"
CHECK_IDS = (OPERATION_CHECK, RULE_CHECK, FRESHNESS_CHECK)

OPERATION_LISTS = ("operations", "operation_renewals", "attempt_joins")
RULE_LISTS = ("rule_revisions", "rule_revision_refusals")
FRESHNESS_ROW_LISTS = ("age_extensions", "age_extension_refusals", "recovery_runs")

LEVELS = (
    "none",
    "revision_row_present",
    "signer_independent_and_configured",
    "digest_matches_signed_revision",
)
POLICY_UNKNOWN = "policy_status_unknown"
CODE_EXPIRED = profile.EXPIRED_REASON
CODE_OVERDUE = "check_overdue"
CODE_LEASE = profile.LEASE_REASON
CODE_NONCE = "status_nonce_mismatch"
TERMINAL = {"completed", "interrupted", "expired"}
CLOCK_MEMBERS = ("deadline", "age_bound_seconds", "extension_id", "nonce")
COMMITTED = {"acknowledged", "partial"}
POSSIBLY_COMMITTED = COMMITTED | {"unknown"}
DESTINATION_REJECTION = "operation_already_committed"
OPERATION_ID_CHARS = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._:/#-"
)

# What each check says it does not establish. Carried in the check's notes and in the report
# (``extensions['x-profile-checks']``); the report also carries the contract's optional non-claim
# id ``profile_sidecar_semantics_only`` whenever one of these checks ran (``report.PROFILE_NON_CLAIM``).
DOES_NOT_PROVE: dict[str, str] = {
    OPERATION_CHECK: (
        "does not prove that the destination committed one effect per operation (only that the "
        "record is consistent with it), that the issuer named is who issued the grant, or that "
        "the rows are complete: rows dropped together with everything that names them agree"
    ),
    RULE_CHECK: (
        "does not prove that a signer is who the row says or that a digest is the digest of the "
        "rule's bytes; the configured signer set is host configuration in no record, so rows "
        "naming signer_not_configured cannot be recomputed here"
    ),
    FRESHNESS_CHECK: (
        "does not prove that the clocks were true or that the recorded times were read when "
        "they say (a writer of the record writes both sides of every comparison), or anything "
        "that needs the host's declared extension limit, signer set or resolver capability"
    ),
}

Finder = Callable[[], list[Finding]]


def _f(code: str, path: str, message: str) -> Finding:
    return Finding(code, path, message)


def _rows(doc: dict[str, Any], name: str) -> list[Any]:
    value = doc.get(name)
    return value if type(value) is list else []


def _dicts(doc: dict[str, Any], name: str) -> list[dict[str, Any]]:
    return [x for x in _rows(doc, name) if type(x) is dict]


def _dict(value: Any) -> dict[str, Any]:
    return value if type(value) is dict else {}


# --------------------------------------------------------------------------------- activation


def operation_active(doc: dict[str, Any]) -> bool:
    if any(name in doc for name in OPERATION_LISTS):
        return True
    for d in _dicts(doc, "decisions"):
        ext = _dict(_dict(d.get("binding")).get("runtime_authority"))
        if "operation_id" in ext or "operation_issuer" in ext:
            return True
    return False


def _operation_rows_present(doc: dict[str, Any]) -> bool:
    """An operation row, renewal, join, or a decision carrying operation members exists."""
    if any(_rows(doc, name) for name in OPERATION_LISTS):
        return True
    for d in _dicts(doc, "decisions"):
        ext = _dict(_dict(d.get("binding")).get("runtime_authority"))
        if "operation_id" in ext or "operation_issuer" in ext:
            return True
    return False


def rule_active(doc: dict[str, Any]) -> bool:
    if any(name in doc for name in RULE_LISTS):
        return True
    return any("rule_identity" in x for n in ("decisions", "refusals") for x in _dicts(doc, n))


def freshness_active(doc: dict[str, Any]) -> bool:
    if any(name in doc for name in FRESHNESS_ROW_LISTS):
        return True
    if any(x.get("read_state") == "nonce_mismatch" for _, x in rules_journal.all_inputs(doc)):
        return True
    if profile.profile_phase_events(doc):
        return True
    for section in profile.FRESHNESS_MEMBERS:
        if any(profile.has_freshness(r, section) for r in _dicts(doc, section)):
            return True
    return any(
        "evaluated_at" in r
        for n in ("operations", "operation_renewals", "attempt_joins")
        for r in _dicts(doc, n)
    )


# --------------------------------------------------------------------------------- row shapes


def _is(value: Any, kinds: str) -> bool:
    """``s`` string, ``n`` string or null, ``i`` integer, ``l`` list, ``d`` object, ``o`` object or null."""
    if kinds == "s":
        return type(value) is str
    if kinds == "n":
        return value is None or type(value) is str
    if kinds == "i":
        return type(value) is int
    if kinds == "l":
        return type(value) is list
    if kinds == "d":
        return type(value) is dict
    if kinds == "o":
        return value is None or type(value) is dict
    raise ValueError(kinds)


def _shape(doc: dict[str, Any], name: str, spec: dict[str, str]) -> list[Finding]:
    """The rows this check reads carry the members it reads, of the kind it reads.

    The journal contract leaves the shape of these rows to the sidecar contract, whose closed
    member sets are not applied here (a raw record also carries the freshness clocks on them).
    """
    out: list[Finding] = []
    for i, row in enumerate(_rows(doc, name)):
        path = f"$.{name}[{i}]"
        if type(row) is not dict:
            out.append(_f("schema_violation", path, "a profile row is an object"))
            continue
        for member, kind in spec.items():
            if member not in row:
                out.append(_f("schema_violation", f"{path}.{member}", "required member missing"))
            elif not _is(row[member], kind):
                out.append(_f("schema_violation", f"{path}.{member}", "member has the wrong type"))
    return out


def _valid_operation_id(value: Any) -> bool:
    return (
        type(value) is str
        and 1 <= len(value) <= 128
        and value[0].isalnum()
        and value[0].isascii()
        and all(c in OPERATION_ID_CHARS for c in value)
    )


# --------------------------------------------------------------------------------- operation identity

OPERATION_SPEC = {
    "operation_id": "s",
    "principal_id": "s",
    "authority_domain": "s",
    "issuer": "s",
    "grant_id": "s",
    "first_grant_revision": "s",
    "admitted_at": "s",
}
RENEWAL_SPEC = {
    "renewal_id": "s",
    "operation_id": "s",
    "grant_id": "n",
    "from_revision": "n",
    "to_revision": "s",
    "written_by": "s",
    "outcome": "s",
    "refusal_code": "n",
    "recorded_at": "s",
}
JOIN_SPEC = {
    "join_id": "s",
    "operation_id": "s",
    "attempt_id": "s",
    "check_id": "s",
    "effect_id": "s",
    "decision_id": "s",
    "grant_id": "s",
    "grant_revision": "s",
    "merged_into": "n",
    "recorded_at": "s",
}


def operation_total(doc: dict[str, Any]) -> int:
    return sum(len(_rows(doc, n)) for n in (*OPERATION_LISTS, "decisions", "attempts", "refusals"))


def licensed_revisions(doc: dict[str, Any], operation_id: str) -> set[str]:
    """First revision plus every accepted renewal's ``to_revision`` (a refused renewal licenses nothing)."""
    op = next((o for o in _dicts(doc, "operations") if o["operation_id"] == operation_id), None)
    if op is None:
        return set()
    return {op["first_grant_revision"]} | {
        r["to_revision"]
        for r in _dicts(doc, "operation_renewals")
        if r["operation_id"] == operation_id and r["outcome"] == "accepted"
    }


def operation_status(
    doc: dict[str, Any],
    *,
    operation_id: str,
    principal_id: str,
    authority_domain: str,
    issuer: str,
    grant_id: str,
    grant_revision: str,
) -> str:
    """``ok``, ``not_admitted``, ``collision`` or ``renewal_unrecorded``, in the producer's order."""
    op = next((o for o in _dicts(doc, "operations") if o["operation_id"] == operation_id), None)
    if op is None:
        return "not_admitted"
    held = (op["principal_id"], op["authority_domain"], op["issuer"], op["grant_id"])
    if held != (principal_id, authority_domain, issuer, grant_id):
        return "collision"
    if grant_revision not in licensed_revisions(doc, operation_id):
        return "renewal_unrecorded"
    return "ok"


def operation_identity(doc: dict[str, Any]) -> list[Finding]:
    shape = (
        _shape(doc, "operations", OPERATION_SPEC)
        + _shape(doc, "operation_renewals", RENEWAL_SPEC)
        + _shape(doc, "attempt_joins", JOIN_SPEC)
    )
    if shape:
        return shape
    return [*_ledger_rules(doc), *_join_context_rules(doc)]


def _ledger_rules(doc: dict[str, Any]) -> list[Finding]:
    out: list[Finding] = []
    ops: dict[str, dict[str, Any]] = {}
    for i, o in enumerate(_dicts(doc, "operations")):
        p = f"$.operations[{i}]"
        if o["operation_id"] in ops:
            out.append(_f("duplicate_operation_id", p, "an operation is admitted once"))
        ops.setdefault(o["operation_id"], o)
        if aware(o["admitted_at"]) is None:
            out.append(_f("timestamp_invalid", f"{p}.admitted_at", "times need a UTC offset"))
    licensed = {oid: {o["first_grant_revision"]} for oid, o in ops.items()}
    last_to = {oid: o["first_grant_revision"] for oid, o in ops.items()}
    renewal_ids: set[str] = set()
    for i, r in enumerate(_dicts(doc, "operation_renewals")):
        p = f"$.operation_renewals[{i}]"
        if r["renewal_id"] in renewal_ids:
            out.append(_f("duplicate_renewal_id", p, "renewal ids are unique"))
        renewal_ids.add(r["renewal_id"])
        if aware(r["recorded_at"]) is None:
            out.append(_f("timestamp_invalid", f"{p}.recorded_at", "times need a UTC offset"))
        op = ops.get(r["operation_id"])
        derived = None
        if op is None:
            derived = "operation_not_admitted"
        elif r["written_by"] != op["issuer"]:
            derived = "renewal_not_written_by_grant_issuer"
        elif r["to_revision"] in licensed[r["operation_id"]]:
            derived = "renewal_revision_not_new"
        if (r["outcome"] == "accepted") != (r["refusal_code"] is None):
            out.append(
                _f(
                    "renewal_outcome_inconsistent",
                    p,
                    "outcome is accepted if and only if refusal_code is null",
                )
            )
            continue
        if op is None:
            if r["grant_id"] is not None or r["from_revision"] is not None:
                out.append(
                    _f(
                        "renewal_context_mismatch",
                        p,
                        "a renewal of an unadmitted operation carries null grant_id and from_revision",
                    )
                )
        elif r["grant_id"] != op["grant_id"] or r["from_revision"] != last_to[r["operation_id"]]:
            out.append(
                _f(
                    "renewal_context_mismatch",
                    p,
                    "grant_id is the operation's and from_revision the last accepted revision (else the first)",
                )
            )
        if r["outcome"] == "accepted":
            if derived == "operation_not_admitted":
                out.append(
                    _f(
                        "renewal_accepted_unadmitted_operation",
                        p,
                        "an accepted renewal names an admitted operation",
                    )
                )
            elif derived == "renewal_not_written_by_grant_issuer":
                out.append(
                    _f(
                        "renewal_accepted_not_by_issuer",
                        p,
                        "only the issuer recorded at admission writes an accepted renewal",
                    )
                )
            elif derived == "renewal_revision_not_new":
                out.append(
                    _f(
                        "renewal_accepted_revision_not_new",
                        p,
                        "an accepted renewal names a revision the operation does not already hold",
                    )
                )
            if op is not None:
                licensed[r["operation_id"]].add(r["to_revision"])
                last_to[r["operation_id"]] = r["to_revision"]
        elif derived is None:
            out.append(
                _f(
                    "renewal_refusal_unjustified",
                    p,
                    "a refused renewal states a defect the ledger does not show",
                )
            )
        elif r["refusal_code"] != derived:
            out.append(
                _f(
                    "renewal_refusal_code_mismatch",
                    p,
                    f"the ledger gives {derived} (checked in the producer's order)",
                )
            )
    join_ids: set[str] = set()
    attempt_ids: set[str] = set()
    check_ids: set[str] = set()
    for i, j in enumerate(_dicts(doc, "attempt_joins")):
        p = f"$.attempt_joins[{i}]"
        if j["join_id"] in join_ids:
            out.append(_f("duplicate_join_id", p, "join ids are unique"))
        join_ids.add(j["join_id"])
        if j["attempt_id"] in attempt_ids:
            out.append(_f("duplicate_attempt_join", p, "one join row per attempt"))
        attempt_ids.add(j["attempt_id"])
        if j["check_id"] in check_ids:
            out.append(_f("duplicate_join_check_id", p, "a journal check licenses one attempt"))
        check_ids.add(j["check_id"])
        if aware(j["recorded_at"]) is None:
            out.append(_f("timestamp_invalid", f"{p}.recorded_at", "times need a UTC offset"))
        op = ops.get(j["operation_id"])
        if op is None:
            out.append(
                _f(
                    "join_operation_not_admitted",
                    f"{p}.operation_id",
                    "a join names an admitted operation",
                )
            )
        else:
            if j["grant_id"] != op["grant_id"]:
                out.append(
                    _f(
                        "join_grant_mismatch",
                        f"{p}.grant_id",
                        "an operation id is stable across revisions of one grant, not across grants",
                    )
                )
            if j["grant_revision"] not in licensed_revisions(doc, j["operation_id"]):
                out.append(
                    _f(
                        "join_revision_unlicensed",
                        f"{p}.grant_revision",
                        "the revision is the operation's first or one an accepted renewal names",
                    )
                )
        target = j["merged_into"]
        if target is not None:
            if target == j["operation_id"]:
                out.append(
                    _f(
                        "merged_into_self",
                        f"{p}.merged_into",
                        "an operation is not merged into itself",
                    )
                )
            elif target not in ops:
                out.append(
                    _f(
                        "merged_into_not_admitted",
                        f"{p}.merged_into",
                        "merged_into names an admitted operation id, never an attempt id",
                    )
                )
    return out


def _join_context_rules(doc: dict[str, Any]) -> list[Finding]:
    out: list[Finding] = []
    ops = {o["operation_id"]: o for o in _dicts(doc, "operations")}
    profile_on = bool(ops)
    decisions = {d.get("decision_id"): d for d in _dicts(doc, "decisions")}
    events = _dicts(doc, "check_events")
    resolution = {(c.get("check_id"), c.get("stage")) for c in _dicts(doc, "resolution_checks")}
    rows_by_attempt: dict[str, list[dict[str, Any]]] = {}
    first_index: dict[str, int] = {}
    for k, a in enumerate(_dicts(doc, "attempts")):
        rows_by_attempt.setdefault(a.get("attempt_id"), []).append(a)  # type: ignore[arg-type]
        first_index.setdefault(a.get("attempt_id"), k)  # type: ignore[arg-type]
    joins = {j["attempt_id"]: j for j in _dicts(doc, "attempt_joins")}

    first_authorized: dict[str, dict[str, Any]] = {}
    for k, d in enumerate(_dicts(doc, "decisions")):
        binding = d.get("binding")
        if d.get("result") != "authorized" or type(binding) is not dict:
            continue
        p = f"$.decisions[{k}]"
        ext = _dict(binding.get("runtime_authority"))
        oid = ext.get("operation_id")
        if oid is None:
            if profile_on:
                out.append(
                    _f(
                        "decision_operation_id_missing",
                        p,
                        "under the profile an authorized binding carries the issuer's operation id",
                    )
                )
            continue
        op = ops.get(oid) if type(oid) is str else None
        if op is None:
            out.append(
                _f(
                    "decision_operation_unadmitted",
                    p,
                    "an authorized decision's operation id is in the ledger",
                )
            )
            continue
        first_authorized.setdefault(oid, d)
        if ext.get("operation_issuer") != op["issuer"]:
            out.append(
                _f(
                    "operation_issuer_mismatch",
                    p,
                    "the binding names the issuer recorded at admission",
                )
            )
        if (
            binding.get("principal") != op["principal_id"]
            or binding.get("grant_id") != op["grant_id"]
        ):
            out.append(
                _f(
                    "decision_operation_binding_mismatch",
                    p,
                    "principal and grant are the ones the operation was admitted under",
                )
            )
        if binding.get("grant_revision") not in licensed_revisions(doc, oid):
            out.append(
                _f(
                    "decision_revision_unlicensed",
                    p,
                    "the binding's revision is the first or an accepted renewal",
                )
            )
    for i, o in enumerate(_dicts(doc, "operations")):
        first = first_authorized.get(o["operation_id"])
        if (
            first is not None
            and first["binding"].get("grant_revision") != o["first_grant_revision"]
        ):
            out.append(
                _f(
                    "first_revision_mismatch",
                    f"$.operations[{i}]",
                    "an operation is admitted on its first authorized decision, at that decision's revision",
                )
            )

    for i, j in enumerate(_dicts(doc, "attempt_joins")):
        p = f"$.attempt_joins[{i}]"
        rows = rows_by_attempt.get(j["attempt_id"])
        if not rows:
            out.append(_f("join_attempt_missing", p, "the join names an attempt of the record"))
        elif any(
            r.get("effect_id") != j["effect_id"] or r.get("decision_id") != j["decision_id"]
            for r in rows
        ):
            out.append(
                _f("join_attempt_mismatch", p, "the join's effect and decision are the attempt's")
            )
        dec = decisions.get(j["decision_id"])
        if dec is None:
            out.append(_f("join_decision_missing", p, "the join names a decision of the record"))
        elif dec.get("result") != "authorized" or type(dec.get("binding")) is not dict:
            out.append(
                _f("join_decision_unauthorized", p, "an attempt follows an authorized decision")
            )
        else:
            binding = dec["binding"]
            if _dict(binding.get("runtime_authority")).get("operation_id") != j["operation_id"]:
                out.append(
                    _f(
                        "join_operation_mismatch",
                        p,
                        "the join's operation is the one the decision's binding carries",
                    )
                )
            if (binding.get("grant_id"), binding.get("grant_revision")) != (
                j["grant_id"],
                j["grant_revision"],
            ):
                out.append(
                    _f(
                        "join_binding_mismatch",
                        p,
                        "the join's grant id and revision are the binding's",
                    )
                )
            if dec.get("effect_id") != j["effect_id"]:
                out.append(_f("join_effect_mismatch", p, "the join's effect id is the decision's"))
        opened = [
            e
            for e in events
            if e.get("check_id") == j["check_id"]
            and e.get("stage") == "effect"
            and e.get("phase") == "opened"
        ]
        if not opened:
            out.append(
                _f(
                    "join_check_missing",
                    p,
                    "the join's check id opens an effect-stage check in the journal",
                )
            )
        else:
            if (
                opened[0].get("effect_id") != j["effect_id"]
                or opened[0].get("decision_id") != j["decision_id"]
            ):
                out.append(
                    _f(
                        "join_check_lineage",
                        p,
                        "the journal check names the join's effect and decision",
                    )
                )
            if not any(
                e.get("check_id") == j["check_id"] and e.get("phase") == "completed" for e in events
            ):
                out.append(
                    _f(
                        "join_check_not_completed",
                        p,
                        "a check that did not complete licenses no dispatch",
                    )
                )
        if (j["check_id"], "effect") not in resolution:
            out.append(
                _f(
                    "join_resolution_check_missing",
                    p,
                    "the same id names the effect-stage resolution check",
                )
            )

    if profile_on:
        for aid in rows_by_attempt:
            if aid not in joins:
                out.append(
                    _f(
                        "attempt_without_join",
                        f"$.attempts[{first_index[aid]}]",
                        "under the profile every attempt has its join row",
                    )
                )
        for k, c in enumerate(_dicts(doc, "resolution_checks")):
            if not any(
                e.get("check_id") == c.get("check_id") and e.get("stage") == c.get("stage")
                for e in events
            ):
                out.append(
                    _f(
                        "resolution_check_not_in_journal",
                        f"$.resolution_checks[{k}]",
                        "under the profile a resolution check carries the id of the journal check it was read in",
                    )
                )
    for k, x in enumerate(_dicts(doc, "refusals")):
        p = f"$.refusals[{k}]"
        cid = x.get("check_id")
        if cid is None:
            if profile_on:
                out.append(
                    _f(
                        "refusal_check_id_missing",
                        p,
                        "under the profile a refusal names the check that refused",
                    )
                )
            continue
        if (cid, "effect") not in resolution:
            out.append(
                _f(
                    "refusal_check_missing",
                    p,
                    "the refusal's check id names an effect-stage resolution check",
                )
            )
        opened = [
            e
            for e in events
            if e.get("check_id") == cid
            and e.get("stage") == "effect"
            and e.get("phase") == "opened"
        ]
        if opened and (
            opened[0].get("effect_id") != x.get("effect_id")
            or opened[0].get("decision_id") != x.get("decision_id")
        ):
            out.append(
                _f(
                    "refusal_check_lineage",
                    p,
                    "the journal check names the refusal's effect and decision",
                )
            )

    effects_by_operation: dict[str, dict[str, set[str]]] = {}
    for aid, rows in rows_by_attempt.items():
        joined = joins.get(aid)
        if joined is not None:
            by_effect = effects_by_operation.setdefault(joined["operation_id"], {})
            by_effect.setdefault(str(rows[0].get("effect_id")), set()).update(
                str(r.get("status")) for r in rows
            )
    for oid, by_effect in sorted(effects_by_operation.items()):
        if sum(bool(s & COMMITTED) for s in by_effect.values()) > 1:
            out.append(
                _f(
                    "operation_committed_twice",
                    f"$.attempts[{_first_attempt_of(rows_by_attempt, joins, oid, first_index)}]",
                    "two different effect ids both reached acknowledged or partial for one operation",
                )
            )
    for aid, rows in rows_by_attempt.items():
        last = rows[-1]
        joined = joins.get(aid)
        if (
            last.get("status") == "failed"
            and last.get("error") == DESTINATION_REJECTION
            and joined is not None
        ):
            peers = [
                s
                for eff, s in effects_by_operation.get(joined["operation_id"], {}).items()
                if eff != last.get("effect_id")
            ]
            if not any(s & POSSIBLY_COMMITTED for s in peers):
                out.append(
                    _f(
                        "rejection_without_committed_peer",
                        f"$.attempts[{first_index[aid]}]",
                        "operation_already_committed needs another effect of the operation that was acknowledged, partial or unknown",
                    )
                )
    return out


def _first_attempt_of(
    rows_by_attempt: dict[str, list[dict[str, Any]]],
    joins: dict[str, dict[str, Any]],
    operation_id: str,
    first_index: dict[str, int],
) -> int:
    return min(
        (
            first_index[a]
            for a, j in joins.items()
            if j["operation_id"] == operation_id and a in first_index
        ),
        default=0,
    )


# --------------------------------------------------------------------------------- rule revision

REVISION_SPEC = {
    "revision_id": "s",
    "rule_kind": "s",
    "rule_ref": "s",
    "from_digest": "n",
    "to_digest": "s",
    "reviser": "s",
    "signer": "n",
    "supersedes": "n",
    "recorded_at": "s",
}
REVISION_REFUSAL_SPEC = {"refusal_id": "s", "revision": "d", "reasons": "l", "recorded_at": "s"}


def revision_defects(row: dict[str, Any]) -> list[str]:
    """Why a row does not count toward adoption, without a configured signer set (none is in a record)."""
    if not row.get("signer"):
        return ["unsigned_revision_row"]
    if row["signer"] == row["reviser"]:
        return ["self_signed_revision_row"]
    return []


def counting_rows(rows: list[dict[str, Any]], rule_ref: str) -> list[dict[str, Any]]:
    own = [x for x in rows if x["rule_ref"] == rule_ref]
    valid = [x for x in own if not revision_defects(x)]
    superseded = {x["supersedes"] for x in valid if x.get("supersedes")}
    return [x for x in valid if x["revision_id"] not in superseded]


def adopted_digest(rows: list[dict[str, Any]], rule_ref: str) -> str | None:
    live = counting_rows(rows, rule_ref)
    return live[-1]["to_digest"] if live else None


def resolve_rule(
    rows: list[dict[str, Any]], rule_ref: str, observed_digest: str | None
) -> dict[str, Any]:
    """``adopted`` only when a counting row's ``to_digest`` is the observed digest; otherwise ``unknown`` and why."""
    own = [x for x in rows if x["rule_ref"] == rule_ref]
    findings: list[str] = []
    level = 1 if own else 0
    for r in own:
        findings.extend(d for d in revision_defects(r) if d not in findings)
    live = counting_rows(rows, rule_ref)
    if live:
        level = 2
    adopted = live[-1]["to_digest"] if live else None
    if not live:
        findings.append("no_signed_revision")
    if observed_digest is None:
        findings.append("observed_digest_absent")
    elif live and observed_digest != adopted:
        findings.append("digest_mismatch_with_adopted")
    state = "unknown"
    if live and observed_digest is not None and observed_digest == adopted:
        state, level = "adopted", 3
    return {
        "rule_ref": rule_ref,
        "state": state,
        "observed_digest": observed_digest,
        "adopted_digest": adopted,
        "verified_through": LEVELS[level],
        "findings": findings,
    }


def rule_revision(doc: dict[str, Any]) -> tuple[list[Finding], int]:
    """Findings and the number of identity rows that could not be recomputed."""
    shape = _shape(doc, "rule_revisions", REVISION_SPEC) + _shape(
        doc, "rule_revision_refusals", REVISION_REFUSAL_SPEC
    )
    shape += _identity_shape(doc)
    if shape:
        return shape, 0
    out = [*_revision_rules(doc), *_refusal_rules(doc)]
    identity, skipped = _identity_rules(doc)
    return out + identity, skipped


def _identity_shape(doc: dict[str, Any]) -> list[Finding]:
    out: list[Finding] = []
    for name in ("decisions", "refusals"):
        for i, row in enumerate(_dicts(doc, name)):
            if "rule_identity" not in row:
                continue
            p = f"$.{name}[{i}].rule_identity"
            ident = row["rule_identity"]
            if (
                type(ident) is not dict
                or type(ident.get("rules")) is not dict
                or type(ident.get("unknown")) is not list
            ):
                out.append(_f("schema_violation", p, "rule_identity is {rules, unknown}"))
                continue
            for ref, st in ident["rules"].items():
                if (
                    type(st) is not dict
                    or not _is(st.get("digest"), "n")
                    or "digest" not in st
                    or not _is(st.get("state"), "s")
                    or not _is(st.get("verified_through"), "s")
                    or not _is(st.get("findings"), "l")
                ):
                    out.append(
                        _f(
                            "schema_violation",
                            f"{p}.rules[{ref}]",
                            "a rule's state is {digest, state, verified_through, findings}",
                        )
                    )
                elif st["verified_through"] not in LEVELS:
                    out.append(
                        _f(
                            "unknown_enum_value",
                            f"{p}.rules[{ref}].verified_through",
                            "value not in declared set",
                        )
                    )
    return out


def _revision_rules(doc: dict[str, Any]) -> list[Finding]:
    out: list[Finding] = []
    rows = _dicts(doc, "rule_revisions")
    earlier: dict[str, int] = {}
    for i, r in enumerate(rows):
        p = f"$.rule_revisions[{i}]"
        if r["revision_id"] in earlier:
            out.append(
                _f(
                    "duplicate_revision_id",
                    p,
                    "revision ids are unique; rows are appended, never edited",
                )
            )
        if aware(r["recorded_at"]) is None:
            out.append(_f("timestamp_invalid", f"{p}.recorded_at", "times need a UTC offset"))
        signed = bool(r["signer"])
        if signed and r["signer"] == r["reviser"]:
            out.append(
                _f(
                    "self_signed_row_accepted",
                    p,
                    "a self-signed revision is refused and kept as a refusal row, never accepted",
                )
            )
        if r.get("declared_arity") is not None and r["rule_kind"] != "reason_registry":
            out.append(
                _f(
                    "declared_arity_on_non_registry_row",
                    f"{p}.declared_arity",
                    "arity is declared at signing on reason registry rows only",
                )
            )
        target = None
        unknown_target = False
        if r["supersedes"] is not None:
            j = earlier.get(r["supersedes"])
            target = rows[j] if j is not None else None
            if target is None or target["rule_ref"] != r["rule_ref"]:
                unknown_target = True
                out.append(
                    _f(
                        "supersedes_unknown",
                        f"{p}.supersedes",
                        "a row supersedes an earlier row of the same rule",
                    )
                )
        if signed and not unknown_target:
            expected = (
                target["from_digest"]
                if target is not None
                else adopted_digest(rows[:i], r["rule_ref"])
            )
            if r["from_digest"] != expected:
                out.append(
                    _f(
                        "from_digest_mismatch",
                        f"{p}.from_digest",
                        "from_digest is the digest currently adopted for the rule (or the superseded row's from_digest)",
                    )
                )
        earlier.setdefault(r["revision_id"], i)
    return out


def _refusal_rules(doc: dict[str, Any]) -> list[Finding]:
    out: list[Finding] = []
    ids = {r["revision_id"] for r in _dicts(doc, "rule_revisions")}
    seen: set[str] = set()
    for i, x in enumerate(_dicts(doc, "rule_revision_refusals")):
        p = f"$.rule_revision_refusals[{i}]"
        if x["refusal_id"] in seen:
            out.append(_f("duplicate_refusal_id", p, "refusal ids are unique"))
        seen.add(x["refusal_id"])
        rev, reasons = x["revision"], x["reasons"]
        if aware(x["recorded_at"]) is None or aware(rev.get("recorded_at")) is None:
            out.append(_f("timestamp_invalid", p, "times need a UTC offset"))
        if any(type(r) is not str for r in reasons):
            out.append(_f("schema_violation", f"{p}.reasons", "reasons are strings"))
            continue
        if reasons != sorted(set(reasons)):
            out.append(
                _f("refusal_reasons_not_canonical", f"{p}.reasons", "reasons are sorted and unique")
            )
        signer = rev.get("signer")
        self_signed = bool(signer) and signer == rev.get("reviser")
        bad = ("self_signed_revision_row" in reasons) != self_signed
        if "signer_not_configured" in reasons:
            bad = (
                bad or not signer or self_signed
            )  # the set itself is host configuration: not checkable
        bad = bad or ("rule_revision_duplicate" in reasons and rev.get("revision_id") not in ids)
        bad = bad or (
            "rule_revision_supersedes_unknown" in reasons and rev.get("supersedes") is None
        )
        bad = bad or ("rule_revision_from_digest_mismatch" in reasons and not signer)
        if bad:
            out.append(
                _f(
                    "refusal_reason_mismatch",
                    f"{p}.reasons",
                    "each reason names a defect the embedded revision shows (an unsigned row is never refused for its signer)",
                )
            )
    return out


def _identity_rules(doc: dict[str, Any]) -> tuple[list[Finding], int]:
    out: list[Finding] = []
    skipped = 0
    revisions = _dicts(doc, "rule_revisions")
    times_ok = all(aware(r["recorded_at"]) is not None for r in revisions)
    for name, stamp in (("decisions", "decided_at"), ("refusals", "recorded_at")):
        for i, row in enumerate(_dicts(doc, name)):
            if "rule_identity" not in row:
                continue
            p = f"$.{name}[{i}]"
            ident = row["rule_identity"]
            rules = ident["rules"]
            t = aware(row.get(stamp))
            if ident["unknown"] != sorted(r for r, v in rules.items() if v["state"] != "adopted"):
                out.append(
                    _f(
                        "rule_identity_unknown_mismatch",
                        f"{p}.rule_identity.unknown",
                        "unknown lists, sorted, exactly the rules whose state is not adopted",
                    )
                )
            consistent = True
            if t is None:
                out.append(_f("timestamp_invalid", f"{p}.{stamp}", "times need a UTC offset"))
            for ref, st in rules.items():
                q = f"{p}.rule_identity.rules[{ref}]"
                findings = st["findings"]
                if len(set(map(str, findings))) != len(findings):
                    out.append(_f("duplicate_finding", q, "a finding is listed once"))
                    consistent = False
                if (st["state"] == "adopted") != (
                    st["verified_through"] == "digest_matches_signed_revision"
                ):
                    out.append(
                        _f(
                            "verified_through_state_mismatch",
                            q,
                            "adopted if and only if verification reached digest_matches_signed_revision",
                        )
                    )
                    consistent = False
                    continue
                level = LEVELS.index(st["verified_through"])
                if ("no_signed_revision" in findings) != (level < 2):
                    out.append(
                        _f(
                            "finding_level_mismatch",
                            q,
                            "no_signed_revision if and only if no signed independent revision row was found",
                        )
                    )
                    consistent = False
                    continue
                absent, mismatch = (
                    "observed_digest_absent" in findings,
                    "digest_mismatch_with_adopted" in findings,
                )
                if (
                    absent != (st["digest"] is None)
                    or (mismatch and (st["digest"] is None or level != 2))
                    or (level == 2 and st["digest"] is not None and not mismatch)
                ):
                    out.append(
                        _f(
                            "observed_digest_finding_mismatch",
                            q,
                            "observed_digest_absent if and only if the digest is null; digest_mismatch_with_adopted names an observed digest that differs from the adopted one",
                        )
                    )
                    consistent = False
            if consistent and t is not None and times_ok:
                asof = [r for r in revisions if aware(r["recorded_at"]) <= t]  # type: ignore[operator]
                row_skipped = False
                for ref, st in rules.items():
                    q = f"{p}.rule_identity.rules[{ref}]"
                    if "signer_not_configured" in st["findings"]:
                        row_skipped = True  # the configured signer set is in no record
                        continue
                    res = resolve_rule(asof, ref, st["digest"])
                    if (res["state"], res["verified_through"]) != (
                        st["state"],
                        st["verified_through"],
                    ):
                        out.append(
                            _f(
                                "rule_identity_recomputed_mismatch",
                                q,
                                f"the revision rows recorded by then give {res['state']} through {res['verified_through']}",
                            )
                        )
                    elif sorted(res["findings"]) != sorted(map(str, st["findings"])):
                        out.append(
                            _f(
                                "rule_identity_findings_mismatch",
                                q,
                                f"the revision rows recorded by then give findings {res['findings']}",
                            )
                        )
                skipped += row_skipped
            out.extend(_policy_rules(row, p, rules))
    return out, skipped


def _policy_rules(row: dict[str, Any], p: str, rules: dict[str, Any]) -> list[Finding]:
    refs = [
        x.get("input_id")
        for x in row.get("resolution_inputs", [])
        if type(x) is dict and x.get("input_type") == "policy"
    ]
    if any(r not in rules for r in refs):
        return [
            _f(
                "policy_input_without_rule_identity",
                p,
                "every policy the row read has a rule identity entry",
            )
        ]
    if any(rules[r]["state"] != "adopted" for r in refs if r in rules) and (
        POLICY_UNKNOWN not in row.get("reasons", []) or row.get("result", "hold") != "hold"
    ):
        return [
            _f(
                "unadopted_policy_not_held",
                p,
                f"a policy that does not resolve to adopted holds with {POLICY_UNKNOWN}",
            )
        ]
    return []


def rule_total(doc: dict[str, Any]) -> int:
    return (
        len(_rows(doc, "rule_revisions"))
        + len(_rows(doc, "rule_revision_refusals"))
        + sum(1 for n in ("decisions", "refusals") for x in _dicts(doc, n) if "rule_identity" in x)
    )


# --------------------------------------------------------------------------------- freshness

EXTENSION_SPEC = {
    "extension_id": "s",
    "from_max_age_seconds": "i",
    "to_max_age_seconds": "i",
    "not_before": "s",
    "expires_at": "s",
    "requested_by": "s",
    "signer": "n",
    "recorded_at": "s",
}
EXTENSION_REFUSAL_SPEC = {"refusal_id": "s", "extension": "d", "reasons": "l", "recorded_at": "s"}
RECOVERY_SPEC = {
    "run_id": "s",
    "recorded_at": "s",
    "interrupted": "l",
    "overdue": "l",
    "open_count": "i",
}


def freshness_total(doc: dict[str, Any]) -> int:
    rows = sum(
        1
        for section in ("decisions", "attempts", "refusals", "resolution_checks")
        for r in _dicts(doc, section)
        if profile.has_freshness(r, section)
    )
    return rows + sum(len(_rows(doc, n)) for n in ("check_events", *FRESHNESS_ROW_LISTS))


def _deadline_is(recorded_at: Any, bound: int, deadline: Any) -> bool:
    """True when ``deadline`` is ``recorded_at`` plus ``bound`` seconds. A bound too large to
    be added to a time (it would leave the representable range) never matches: the deadline
    cannot be that instant, so the caller refutes it rather than failing."""
    try:
        return bool(_t(deadline) == _t(recorded_at) + timedelta(seconds=bound))
    except OverflowError:
        return False


def _t(value: Any) -> datetime:
    parsed = aware(value)
    if parsed is None:  # unreachable after _time_rules; a crash is an error, never a verdict
        raise ValueError("time without a UTC offset reached a comparison")
    return parsed


def freshness(doc: dict[str, Any]) -> list[Finding]:
    shape = (
        _shape(doc, "age_extensions", EXTENSION_SPEC)
        + _shape(doc, "age_extension_refusals", EXTENSION_REFUSAL_SPEC)
        + _shape(doc, "recovery_runs", RECOVERY_SPEC)
    )
    if not shape:
        for i, r in enumerate(_dicts(doc, "recovery_runs")):
            for member in ("interrupted", "overdue"):
                for k, cid in enumerate(r[member]):
                    if type(cid) is not str:
                        shape.append(
                            _f(
                                "schema_violation",
                                f"$.recovery_runs[{i}].{member}[{k}]",
                                "a check id is a string",
                            )
                        )
    if shape:
        return shape
    times = _time_rules(doc)
    if times:
        return times
    return [
        *_unique_rules(doc),
        *_event_rules(doc),
        *_extension_rules(doc),
        *_recovery_rules(doc),
        *_alias_and_reason_rules(doc),
        *_dispatch_rules(doc),
    ]


def _time_rules(doc: dict[str, Any]) -> list[Finding]:
    out: list[Finding] = []
    stamps: list[tuple[str, Any]] = []
    for i, e in enumerate(_dicts(doc, "check_events")):
        stamps += [
            (f"$.check_events[{i}].{k}", e[k])
            for k in ("recorded_at", "evaluated_at", "deadline")
            if k in e
        ]
    for i, x in enumerate(_dicts(doc, "age_extensions")):
        stamps += [
            (f"$.age_extensions[{i}].{k}", x[k])
            for k in ("not_before", "expires_at", "recorded_at", "evaluated_at")
            if k in x
        ]
    for i, x in enumerate(_dicts(doc, "age_extension_refusals")):
        stamps.append((f"$.age_extension_refusals[{i}].recorded_at", x["recorded_at"]))
        stamps += [
            (f"$.age_extension_refusals[{i}].extension.{k}", x["extension"][k])
            for k in ("not_before", "expires_at", "recorded_at", "evaluated_at")
            if k in x["extension"]
        ]
    stamps += [
        (f"$.recovery_runs[{i}].recorded_at", x["recorded_at"])
        for i, x in enumerate(_dicts(doc, "recovery_runs"))
    ]
    for section, members in (
        ("operations", ("evaluated_at", "admitted_at")),
        ("operation_renewals", ("evaluated_at", "recorded_at")),
        ("attempt_joins", ("evaluated_at", "recorded_at")),
    ):
        for i, r in enumerate(_dicts(doc, section)):
            stamps += [(f"$.{section}[{i}].{m}", r[m]) for m in members if m in r]
    for path, value in stamps:
        if aware(value) is None:
            out.append(_f("timestamp_invalid", path, "times are ISO-8601 with a UTC offset"))
    if out:
        return out
    # a row never records itself before the evaluation pass that made it (row times that carry no
    # UTC offset are refused by v2.journal.inputs_and_times and are not read here)
    for name in (
        "check_events",
        "age_extensions",
        "decisions",
        "attempts",
        "resolution_checks",
        "operation_renewals",
        "attempt_joins",
        "operations",
        "refusals",
    ):
        stamp = "admitted_at" if name == "operations" else "recorded_at"
        for i, r in enumerate(_dicts(doc, name)):
            recorded, evaluated = aware(r.get(stamp)), aware(r.get("evaluated_at"))
            if recorded is not None and evaluated is not None and recorded < evaluated:
                out.append(
                    _f(
                        "recorded_before_evaluated",
                        f"$.{name}[{i}]",
                        "recorded_at does not precede evaluated_at",
                    )
                )
    return out


def _unique_rules(doc: dict[str, Any]) -> list[Finding]:
    out: list[Finding] = []
    for name, key, code in (
        ("age_extensions", "extension_id", "duplicate_extension_id"),
        ("age_extension_refusals", "refusal_id", "duplicate_extension_refusal_id"),
        ("recovery_runs", "run_id", "duplicate_recovery_run_id"),
    ):
        seen: set[str] = set()
        for i, r in enumerate(_dicts(doc, name)):
            if r[key] in seen:
                out.append(_f(code, f"$.{name}[{i}]", f"{key} is unique within {name}"))
            seen.add(r[key])
    return out


def _event_rules(doc: dict[str, Any]) -> list[Finding]:
    out: list[Finding] = []
    groups: dict[str, list[tuple[int, dict[str, Any]]]] = {}
    for i, e in enumerate(_dicts(doc, "check_events")):
        groups.setdefault(e.get("check_id"), []).append((i, e))  # type: ignore[arg-type]
    nonces: dict[str, str] = {}
    extensions = {x["extension_id"]: x for x in _dicts(doc, "age_extensions")}
    for check_id, events in groups.items():
        first_i, opening = events[0]
        if opening.get("phase") != "opened":
            out.append(
                _f(
                    "check_opening_missing",
                    f"$.check_events[{first_i}]",
                    "the first event of a check is its opening",
                )
            )
            continue
        seen: list[str] = []
        previous = None
        for i, e in events:
            p, phase = f"$.check_events[{i}]", e.get("phase")
            if phase == "opened" and seen:
                out.append(_f("duplicate_check_opening", p, "a check is opened once"))
            elif seen and any(s in TERMINAL for s in seen):
                if phase == "expired":
                    if any(s in {"interrupted", "expired"} for s in seen):
                        out.append(
                            _f(
                                "expired_after_closed_check",
                                p,
                                "expired is allowed after completed, never after interrupted or expired",
                            )
                        )
                else:
                    out.append(
                        _f(
                            "check_event_after_close",
                            p,
                            "no event follows a terminal event, except expired after completed",
                        )
                    )
            elif phase == "overdue" and "overdue" in seen:
                out.append(_f("overdue_repeated", p, "a check is reported overdue once"))
            seen.append(phase)  # type: ignore[arg-type]
            if previous is not None and _t(e["recorded_at"]) < _t(previous["recorded_at"]):
                out.append(
                    _f(
                        "check_event_time_regression",
                        p,
                        "recorded_at does not move backwards within a check",
                    )
                )
            previous = e
            if e is opening:
                continue
            for m in CLOCK_MEMBERS:
                if e.get(m) != opening.get(m):
                    out.append(
                        _f(
                            "check_event_clock_drift",
                            f"{p}.{m}",
                            f"{m} is the opening's value on every later event of the check",
                        )
                    )
            if "evaluated_at" in e and e["evaluated_at"] != opening.get("evaluated_at"):
                out.append(
                    _f(
                        "check_event_clock_drift",
                        f"{p}.evaluated_at",
                        "evaluated_at, when present, is the opening's value",
                    )
                )
            if phase in {"overdue", "expired"}:
                want = [CODE_OVERDUE if phase == "overdue" else CODE_EXPIRED]
                if e.get("reasons") != want:
                    out.append(
                        _f(
                            "phase_reasons_mismatch",
                            f"{p}.reasons",
                            f"a {phase} event carries exactly {want[0]}",
                        )
                    )
                if not opening.get("deadline"):
                    code = (
                        "overdue_without_deadline"
                        if phase == "overdue"
                        else "expired_without_deadline"
                    )
                    out.append(_f(code, p, f"a {phase} event needs a check opened with a deadline"))
                elif _t(e["recorded_at"]) <= _t(opening["deadline"]):
                    code = (
                        "overdue_before_deadline"
                        if phase == "overdue"
                        else "expired_not_past_deadline"
                    )
                    out.append(_f(code, p, f"a {phase} event is written after the deadline"))
        po = f"$.check_events[{first_i}]"
        if ("deadline" in opening) != ("age_bound_seconds" in opening):
            out.append(
                _f(
                    "deadline_members_incomplete",
                    po,
                    "deadline and age_bound_seconds are carried together or not at all",
                )
            )
        elif "deadline" in opening:
            bound = opening["age_bound_seconds"]
            if type(bound) is not int or bound < 0:
                out.append(
                    _f(
                        "schema_violation",
                        f"{po}.age_bound_seconds",
                        "age_bound_seconds is an integer of at least 0",
                    )
                )
            elif not _deadline_is(opening["recorded_at"], bound, opening["deadline"]):
                out.append(
                    _f(
                        "deadline_mismatch",
                        po,
                        "deadline is the opening's recorded_at plus age_bound_seconds",
                    )
                )
        nonce = opening.get("nonce")
        if nonce is not None:
            if nonces.get(nonce, str(check_id)) != check_id:
                out.append(_f("nonce_reused_across_checks", po, "a nonce belongs to one check"))
            nonces.setdefault(nonce, str(check_id))
        ext = opening.get("extension_id")
        if ext is not None:
            row = extensions.get(ext)
            if row is None:
                out.append(
                    _f("extension_unknown", po, "an extension_id names an age_extensions row")
                )
                continue
            if opening.get("age_bound_seconds") != row["to_max_age_seconds"]:
                out.append(
                    _f(
                        "extension_bound_mismatch",
                        po,
                        "age_bound_seconds is the extension's to_max_age_seconds",
                    )
                )
            if "evaluated_at" in opening and not (
                _t(row["not_before"]) <= _t(opening["evaluated_at"]) < _t(row["expires_at"])
            ):
                out.append(
                    _f(
                        "extension_outside_window",
                        po,
                        "the extension window covers the evaluation pass",
                    )
                )
            if _t(row["recorded_at"]) > _t(opening["recorded_at"]):
                out.append(
                    _f(
                        "extension_recorded_after_use",
                        po,
                        "an extension recorded after the opening cannot have raised its bound",
                    )
                )
    return out


def _extension_shape_invalid(row: dict[str, Any]) -> bool:
    nb, ex = aware(row.get("not_before")), aware(row.get("expires_at"))
    if nb is None or ex is None:
        return True
    return row["to_max_age_seconds"] <= row["from_max_age_seconds"] or ex <= nb


def _extension_rules(doc: dict[str, Any]) -> list[Finding]:
    out: list[Finding] = []
    for i, x in enumerate(_dicts(doc, "age_extensions")):
        p = f"$.age_extensions[{i}]"
        if _extension_shape_invalid(x):
            out.append(
                _f(
                    "accepted_extension_invalid",
                    p,
                    "an accepted extension raises the bound and has a non-empty window",
                )
            )
        if not x["signer"]:
            out.append(
                _f(
                    "accepted_extension_unsigned",
                    p,
                    "an unsigned extension never counts; it is refused and kept as a refusal",
                )
            )
        elif x["signer"] == x["requested_by"]:
            out.append(_f("accepted_extension_self_signed", p, "the signer is not the requester"))
    accepted = {x["extension_id"] for x in _dicts(doc, "age_extensions")}
    for i, r in enumerate(_dicts(doc, "age_extension_refusals")):
        p = f"$.age_extension_refusals[{i}]"
        reasons, ext = r["reasons"], r["extension"]
        if any(type(c) is not str for c in reasons):
            out.append(_f("schema_violation", f"{p}.reasons", "reasons are strings"))
            continue
        if reasons != sorted(set(reasons)):
            out.append(
                _f(
                    "extension_refusal_reasons_not_canonical",
                    f"{p}.reasons",
                    "reasons are sorted and unique",
                )
            )
        if r["recorded_at"] != ext.get("recorded_at"):
            out.append(
                _f(
                    "extension_refusal_time_mismatch",
                    p,
                    "a refusal is recorded at the extension's own recorded_at",
                )
            )
        if not all(type(ext.get(m)) is int for m in ("from_max_age_seconds", "to_max_age_seconds")):
            out.append(
                _f("schema_violation", f"{p}.extension", "an extension's bounds are integers")
            )
            continue
        derived: set[str] = set()
        if _extension_shape_invalid(ext):
            derived.add("age_extension_invalid")
        if not ext.get("signer"):
            derived.add("age_extension_unsigned")
        elif ext["signer"] == ext.get("requested_by"):
            derived.add("age_extension_self_signed")
        if ext.get("extension_id") in accepted:
            derived.add("age_extension_invalid")  # the producer refuses a reused id as invalid
        checkable = {"age_extension_unsigned", "age_extension_self_signed", "age_extension_invalid"}
        if {c for c in reasons if c in checkable} != derived & checkable:
            out.append(
                _f(
                    "extension_refusal_reason_mismatch",
                    f"{p}.reasons",
                    "each reason names a defect the embedded extension shows (reasons that need host configuration are not checked)",
                )
            )
    return out


def _recovery_rules(doc: dict[str, Any]) -> list[Finding]:
    out: list[Finding] = []
    events: dict[tuple[Any, Any], dict[str, Any]] = {}
    for e in _dicts(doc, "check_events"):
        events.setdefault((e.get("check_id"), e.get("phase")), e)
    for i, r in enumerate(_dicts(doc, "recovery_runs")):
        p = f"$.recovery_runs[{i}]"
        overdue, interrupted = r["overdue"], r["interrupted"]
        if r["open_count"] < len(overdue):
            out.append(
                _f(
                    "recovery_run_open_count_below_overdue",
                    p,
                    "open_count includes every overdue check",
                )
            )
        oldest = r.get("oldest_open_age_seconds")
        if "oldest_open_age_seconds" in r and (oldest is None) != (r["open_count"] == 0):
            out.append(
                _f(
                    "recovery_run_oldest_age_inconsistent",
                    p,
                    "oldest_open_age_seconds is null if and only if no check is open",
                )
            )
        at = _t(r["recorded_at"])
        for cid in interrupted:
            ev = events.get((cid, "interrupted"))
            if ev is None or _t(ev["recorded_at"]) != at:
                out.append(
                    _f(
                        "recovery_interrupted_without_event",
                        p,
                        "each interrupted check has an interrupted event stamped with the pass time",
                    )
                )
        for cid in overdue:
            ev = events.get((cid, "overdue"))
            if ev is None or _t(ev["recorded_at"]) > at:
                out.append(
                    _f(
                        "recovery_overdue_without_event",
                        p,
                        "each overdue check has an overdue event written at or before the pass",
                    )
                )
    return out


def _alias_and_reason_rules(doc: dict[str, Any]) -> list[Finding]:
    out: list[Finding] = []
    for i, d in enumerate(_dicts(doc, "decisions")):
        if "evaluated_at" in d and d["evaluated_at"] != d.get("decided_at"):
            out.append(
                _f(
                    "evaluation_alias_mismatch",
                    f"$.decisions[{i}]",
                    "decided_at keeps its evaluation-time meaning: it equals evaluated_at",
                )
            )
    for i, a in enumerate(_dicts(doc, "attempts")):
        if "evaluated_at" in a and a["evaluated_at"] != a.get("started_at"):
            out.append(
                _f(
                    "evaluation_alias_mismatch",
                    f"$.attempts[{i}]",
                    "started_at keeps its evaluation-time meaning: it equals evaluated_at",
                )
            )

    def mismatched(inputs: Any) -> bool:
        return any(
            type(x) is dict and x.get("read_state") == "nonce_mismatch"
            for x in (inputs if type(inputs) is list else [])
        )

    for name, key in (
        ("decisions", "resolution_inputs"),
        ("refusals", "resolution_inputs"),
        ("resolution_checks", "inputs"),
    ):
        for i, r in enumerate(_dicts(doc, name)):
            if (CODE_NONCE in r.get("reasons", [])) != mismatched(r.get(key)):
                out.append(
                    _f(
                        "nonce_reason_mismatch",
                        f"$.{name}[{i}]",
                        f"{CODE_NONCE} is a reason if and only if an input read ended in nonce_mismatch",
                    )
                )
    attempts = _dicts(doc, "attempts")
    for i, d in enumerate(_dicts(doc, "decisions")):
        if CODE_LEASE in d.get("reasons", []):
            if d["reasons"] != [CODE_LEASE]:
                out.append(
                    _f(
                        "lease_unavailable_with_other_reasons",
                        f"$.decisions[{i}]",
                        f"{CODE_LEASE} is the only reason: no read happened",
                    )
                )
            if any(a.get("decision_id") == d.get("decision_id") for a in attempts):
                out.append(
                    _f(
                        "lease_unavailable_dispatched",
                        f"$.decisions[{i}]",
                        f"a decision held for {CODE_LEASE} has no attempt",
                    )
                )
    expired_events = {
        e.get("check_id"): e for e in _dicts(doc, "check_events") if e.get("phase") == "expired"
    }
    refusals = _dicts(doc, "refusals")
    refused = {x.get("check_id"): x for x in refusals if CODE_EXPIRED in x.get("reasons", [])}
    if set(expired_events) != set(refused):
        out.append(
            _f(
                "expired_refusal_mismatch",
                "$.refusals",
                f"a check has an expired event if and only if a refusal row with {CODE_EXPIRED} names it (check_id)",
            )
        )
    for cid, e in expired_events.items():
        x = refused.get(cid)
        if x is not None and x.get("deadline") != e.get("deadline"):
            out.append(
                _f(
                    "expired_refusal_deadline_mismatch",
                    "$.refusals",
                    "the refusal's deadline is the check's deadline",
                )
            )
        joined = {
            j.get("attempt_id") for j in _dicts(doc, "attempt_joins") if j.get("check_id") == cid
        }
        # the attempt that carries the expiry is the one the join ties to this check; an
        # unrelated failed attempt for the same effect proves nothing about this check
        if x is not None and not any(
            (a.get("attempt_id") in joined if joined else a.get("effect_id") == x.get("effect_id"))
            and a.get("status") == "failed"
            and a.get("error") == CODE_EXPIRED
            for a in attempts
        ):
            out.append(
                _f(
                    "expired_without_failed_attempt",
                    "$.attempts",
                    f"check {cid} expired and its attempt is not failed with {CODE_EXPIRED}",
                )
            )
    for i, a in enumerate(attempts):
        if a.get("error") == CODE_EXPIRED:
            if a.get("status") != "failed":
                out.append(
                    _f(
                        "expired_attempt_not_failed",
                        f"$.attempts[{i}]",
                        f"{CODE_EXPIRED} is only the error of a failed attempt",
                    )
                )
            if not any(
                x.get("effect_id") == a.get("effect_id") and CODE_EXPIRED in x.get("reasons", [])
                for x in refusals
            ):
                out.append(
                    _f(
                        "expired_attempt_without_refusal",
                        f"$.attempts[{i}]",
                        f"an attempt failed with {CODE_EXPIRED} has a refusal row for its effect",
                    )
                )
    return out


def _dispatch_rules(doc: dict[str, Any]) -> list[Finding]:
    out: list[Finding] = []
    latest: dict[Any, dict[str, Any]] = {}
    for a in _dicts(doc, "attempts"):
        latest[a.get("attempt_id")] = a
    expired = {
        e.get("check_id") for e in _dicts(doc, "check_events") if e.get("phase") == "expired"
    }
    for i, j in enumerate(_dicts(doc, "attempt_joins")):
        last_row = latest.get(j["attempt_id"])
        if (
            j["check_id"] in expired
            and last_row is not None
            and not (last_row.get("status") == "failed" and last_row.get("error") == CODE_EXPIRED)
        ):
            out.append(
                _f(
                    "expired_check_dispatched",
                    f"$.attempt_joins[{i}]",
                    "a check whose licence expired at the gate licensed no dispatch",
                )
            )
    return out


# --------------------------------------------------------------------------------- entry point


def _run(check_id: str, unit: str, total: int, fn: Finder) -> CheckResult:
    try:
        findings = fn()
    except Exception as exc:  # a crash is an error, never a verdict
        return verifier_error(check_id, "V2", unit, total, exc)
    if total == 0 and not findings:
        # a profile member over zero items confirms nothing
        return could_not_check(
            check_id, "V2", unit, 0, "no_items_in_record", notes=[DOES_NOT_PROVE[check_id]]
        )
    return make_result(check_id, "V2", unit, total, findings, notes=[DOES_NOT_PROVE[check_id]])


def profile_checks(doc: dict[str, Any]) -> list[CheckResult]:
    """The sidecar checks whose profile has a member in ``doc``; none for a default record."""
    results: list[CheckResult] = []
    if operation_active(doc) and not _operation_rows_present(doc):
        # declared but empty: nothing was checked, so nothing is confirmed
        results.append(
            could_not_check(
                OPERATION_CHECK,
                "V2",
                "operation rows, decisions, attempts and refusals",
                operation_total(doc),
                "operation_profile_without_operation_rows",
                notes=[DOES_NOT_PROVE[OPERATION_CHECK]],
            )
        )
    elif operation_active(doc):
        results.append(
            _run(
                OPERATION_CHECK,
                "operation rows, decisions, attempts and refusals",
                operation_total(doc),
                lambda: operation_identity(doc),
            )
        )
    if rule_active(doc):
        results.append(_rule_check(doc))
    if freshness_active(doc):
        results.append(
            _run(
                FRESHNESS_CHECK,
                "check events, extensions, recovery runs and clocked rows",
                freshness_total(doc),
                lambda: freshness(doc),
            )
        )
    return results


def _rule_check(doc: dict[str, Any]) -> CheckResult:
    unit = "revision rows and identity rows"
    total = rule_total(doc)
    try:
        findings, skipped = rule_revision(doc)
    except Exception as exc:
        return verifier_error(RULE_CHECK, "V2", unit, total, exc)
    if total == 0 and not findings and not skipped:
        return could_not_check(
            RULE_CHECK, "V2", unit, 0, "no_items_in_record", notes=[DOES_NOT_PROVE[RULE_CHECK]]
        )
    return make_result(
        RULE_CHECK,
        "V2",
        unit,
        total,
        findings,
        skipped=min(skipped, total),
        reason="input_absent:configured_signer_set" if skipped else None,
        notes=[DOES_NOT_PROVE[RULE_CHECK]],
    )

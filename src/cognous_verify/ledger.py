"""Tier V4 receipt completeness: the destination ledger against the decisions and attempts.

Ledger input, as the verifier reads it: the control plane's local destination state,
``{"effects": {effect_id: row}, "grant_effect_counts": {grant_id: n}}`` with an optional
``operations`` member, where a row is ``{effect_id, grant_id, target, amount, unit, payload,
state}``. This is the only effect-side record the stack produces. It is written by the
executor, carries no sequence number, no chain and no signature, and is trusted by
deployment, not by cryptography. Both directions are checked (ledger effect to decision,
acknowledged attempt to ledger row), and the two counters the qualification harness gates on
(``unauthorized_effects``, ``excess_duplicate_effects``) are recomputed here from the record
and the ledger. A dropped ledger tail, a consistent rewrite of the ledger, or a decision that
never reached the ledger cannot be seen, and a check says so.
"""

from __future__ import annotations

from typing import Any

from .canon import commitment
from .results import CheckResult, Finding, could_not_check, make_result

V1 = "V1"
V4 = "V4"

LEDGER_MEMBERS = {"effects", "grant_effect_counts", "operations"}
ROW_MEMBERS = {
    "effect_id": "string",
    "grant_id": "string",
    "target": "string",
    "amount": "number",
    "unit": "string",
    "payload": "object",
    "state": "string",
}
ROW_STATES = {"applied", "partial"}
CHECK_IDS = (
    ("v4.ledger.keys", "ledger rows"),
    ("v4.ledger.effects-have-authorized-decisions", "ledger rows"),
    ("v4.ledger.row-matches-binding", "ledger rows"),
    ("v4.ledger.counts", "grants"),
    ("v4.ledger.acknowledged-attempts-have-rows", "attempt rows"),
    ("v4.ledger.observations-agree", "accepted observations"),
)
COMPLETENESS_NOTE = (
    "ledger completeness is not established: the ledger has no sequence number, chain or "
    "signature, so a dropped tail, a consistent rewrite, or a decision that never reached the "
    "ledger cannot be seen"
)


def _is(value: Any, kind: str) -> bool:
    if kind == "string":
        return type(value) is str
    if kind == "number":
        return type(value) in (int, float)
    return type(value) is dict


def shape(doc: Any) -> list[Finding]:
    """Findings when ``doc`` is not a ledger export of the form described in the module docstring."""
    if type(doc) is not dict:
        return [Finding("ledger_shape", "$", "a ledger export is a JSON object")]
    out: list[Finding] = []
    for name in doc:
        if name not in LEDGER_MEMBERS:
            out.append(Finding("ledger_shape", f"$.{name}", "undeclared member"))
    for name in ("effects", "grant_effect_counts"):
        if type(doc.get(name)) is not dict:
            out.append(Finding("ledger_shape", f"$.{name}", "required object member missing"))
    if out:
        return out
    for key, row in doc["effects"].items():
        where = f"$.effects[{key!r}]"
        if type(row) is not dict:
            out.append(Finding("ledger_shape", where, "a ledger row is an object"))
            continue
        for name, kind in ROW_MEMBERS.items():
            if name not in row:
                out.append(Finding("ledger_shape", f"{where}.{name}", "member missing"))
            elif not _is(row[name], kind):
                out.append(Finding("ledger_shape", f"{where}.{name}", f"expected {kind}"))
        for name in row:
            if name not in ROW_MEMBERS:
                out.append(Finding("ledger_shape", f"{where}.{name}", "undeclared member"))
    for grant, count in doc["grant_effect_counts"].items():
        if type(count) is not int or count < 0:
            out.append(
                Finding(
                    "ledger_shape",
                    f"$.grant_effect_counts[{grant!r}]",
                    "a count is a non-negative integer",
                )
            )
    ops = doc.get("operations")
    if ops is not None and (type(ops) is not dict or not all(type(v) is str for v in ops.values())):
        out.append(Finding("ledger_shape", "$.operations", "operations maps ids to effect ids"))
    return out


def structure(ledger: Any) -> CheckResult:
    return make_result("v1.structure.ledger", V1, "ledger exports", 1, shape(ledger))


def skipped_all(reason: str) -> list[CheckResult]:
    return [could_not_check(cid, V4, unit, 0, reason) for cid, unit in CHECK_IDS]


def _authorized_by_effect(record: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        d["effect_id"]: d
        for d in record["decisions"]
        if d["result"] == "authorized" and d["binding"]
    }


def _decisions_by_effect(record: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {d["effect_id"]: d for d in record["decisions"]}


def counters(record: dict[str, Any], ledger: dict[str, Any]) -> dict[str, Any]:
    """The hard-gate counters, recomputed from the record and the ledger with this package's code."""
    authorized = _authorized_by_effect(record)
    rows = ledger["effects"]
    unauthorized = sum(1 for row in rows.values() if row["effect_id"] not in authorized)
    fresh: dict[str, int] = {}
    for a in record["attempts"]:
        ack = a["acknowledgement"]
        if a["status"] in {"acknowledged", "partial"} and ack.get("duplicate") is False:
            fresh[a["effect_id"]] = fresh.get(a["effect_id"], 0) + 1
    excess_acks = sum(max(0, n - 1) for n in fresh.values())
    per_effect: dict[str, int] = {}
    for row in rows.values():
        per_effect[row["effect_id"]] = per_effect.get(row["effect_id"], 0) + 1
    excess_rows = sum(max(0, n - 1) for n in per_effect.values())
    return {
        "unauthorized_effects": unauthorized,
        "excess_duplicate_effects": excess_acks + excess_rows,
        "excess_duplicate_effects_detail": {
            "fresh_acknowledgements_beyond_one": excess_acks,
            "ledger_rows_beyond_one": excess_rows,
        },
        "authorized_decisions": len(authorized),
        "held_decisions": sum(1 for d in record["decisions"] if d["result"] != "authorized"),
        "ledger_effects": len(rows),
    }


def run(record: dict[str, Any], ledger: dict[str, Any]) -> list[CheckResult]:
    return [
        _keys(ledger),
        _effects_have_decisions(record, ledger),
        _row_matches_binding(record, ledger),
        _counts(ledger),
        _acknowledged_have_rows(record, ledger),
        _observations_agree(record, ledger),
    ]


def _keys(ledger: dict[str, Any]) -> CheckResult:
    findings: list[Finding] = []
    for key, row in ledger["effects"].items():
        if row["effect_id"] != key:
            findings.append(
                Finding(
                    "ledger_key_mismatch",
                    f"$.effects[{key!r}]",
                    "a ledger row is keyed by its own effect_id",
                )
            )
    return make_result("v4.ledger.keys", V4, "ledger rows", len(ledger["effects"]), findings)


def _effects_have_decisions(record: dict[str, Any], ledger: dict[str, Any]) -> CheckResult:
    authorized = _authorized_by_effect(record)
    every = _decisions_by_effect(record)
    findings: list[Finding] = []
    for key, row in ledger["effects"].items():
        effect = row["effect_id"]
        if effect in authorized:
            continue
        if effect in every:
            findings.append(
                Finding(
                    "ledger_effect_on_held_decision",
                    f"$.effects[{key!r}]",
                    "a ledger effect whose decision was not authorized",
                )
            )
        else:
            findings.append(
                Finding(
                    "ledger_effect_without_decision",
                    f"$.effects[{key!r}]",
                    "a ledger effect that matches no decision in the record",
                )
            )
    return make_result(
        "v4.ledger.effects-have-authorized-decisions",
        V4,
        "ledger rows",
        len(ledger["effects"]),
        findings,
    )


def _row_matches_binding(record: dict[str, Any], ledger: dict[str, Any]) -> CheckResult:
    authorized = _authorized_by_effect(record)
    findings: list[Finding] = []
    skipped = 0
    for key, row in ledger["effects"].items():
        d = authorized.get(row["effect_id"])
        if d is None:
            skipped += 1
            continue
        b = d["binding"]
        where = f"$.effects[{key!r}]"
        for name, bname in (
            ("grant_id", "grant_id"),
            ("target", "target"),
            ("amount", "amount"),
            ("unit", "unit"),
        ):
            if commitment(row[name]) != commitment(b[bname]):
                findings.append(
                    Finding(
                        "ledger_row_differs_from_binding",
                        f"{where}.{name}",
                        f"ledger {name} differs from the authorized binding",
                    )
                )
        if commitment(row["payload"]) != b["payload_commitment"]:
            findings.append(
                Finding(
                    "ledger_row_differs_from_binding",
                    f"{where}.payload",
                    "the commitment of the ledger payload differs from the binding's payload_commitment",
                )
            )
        if row["state"] not in ROW_STATES:
            findings.append(
                Finding(
                    "ledger_row_state_unknown",
                    f"{where}.state",
                    "a ledger row is applied or partial",
                )
            )
    return make_result(
        "v4.ledger.row-matches-binding",
        V4,
        "ledger rows",
        len(ledger["effects"]),
        findings,
        skipped=skipped,
        reason="row_has_no_authorized_decision" if skipped else None,
    )


def _counts(ledger: dict[str, Any]) -> CheckResult:
    rows_per_grant: dict[str, int] = {}
    for row in ledger["effects"].values():
        rows_per_grant[row["grant_id"]] = rows_per_grant.get(row["grant_id"], 0) + 1
    counts = ledger["grant_effect_counts"]
    findings: list[Finding] = []
    grants = sorted(set(rows_per_grant) | set(counts))
    for grant in grants:
        if counts.get(grant, 0) != rows_per_grant.get(grant, 0):
            findings.append(
                Finding(
                    "ledger_count_mismatch",
                    f"$.grant_effect_counts[{grant!r}]",
                    f"the count says {counts.get(grant, 0)}, the rows say {rows_per_grant.get(grant, 0)}",
                )
            )
    return make_result("v4.ledger.counts", V4, "grants", len(grants), findings)


def _acknowledged_have_rows(record: dict[str, Any], ledger: dict[str, Any]) -> CheckResult:
    rows = ledger["effects"]
    by_effect = {row["effect_id"]: row for row in rows.values()}
    findings: list[Finding] = []
    total = 0
    for i, a in enumerate(record["attempts"]):
        if a["status"] not in {"acknowledged", "partial"}:
            continue
        total += 1
        where = f"$.attempts[{i}]"
        row = by_effect.get(a["effect_id"])
        if row is None:
            findings.append(
                Finding(
                    "acknowledged_attempt_without_ledger_row",
                    where,
                    "an acknowledged attempt has no row in the ledger",
                )
            )
            continue
        effect = a["acknowledgement"].get("effect")
        if effect is not None and commitment(effect) != commitment(row):
            findings.append(
                Finding(
                    "acknowledgement_differs_from_ledger_row",
                    where + ".acknowledgement.effect",
                    "the acknowledged effect differs from the ledger row",
                )
            )
    return make_result(
        "v4.ledger.acknowledged-attempts-have-rows", V4, "attempt rows", total, findings
    )


def _observations_agree(record: dict[str, Any], ledger: dict[str, Any]) -> CheckResult:
    by_effect = {row["effect_id"]: row for row in ledger["effects"].values()}
    findings: list[Finding] = []
    total = 0
    for i, rec in enumerate(record["reconciliations"]):
        obs = rec["observation"]
        if rec["observation_accepted"] is not True or obs is None:
            continue
        total += 1
        if obs["state"] not in {"applied", "partial"}:
            continue
        where = f"$.reconciliations[{i}].observation"
        row = by_effect.get(obs["effect_id"])
        if row is None:
            findings.append(
                Finding(
                    "observation_without_ledger_row",
                    where,
                    "an accepted applied or partial observation has no ledger row",
                )
            )
        elif commitment(obs.get("destination_state")) != commitment(row):
            findings.append(
                Finding(
                    "observation_differs_from_ledger_row",
                    where + ".destination_state",
                    "the observed destination state differs from the ledger row",
                )
            )
    return make_result("v4.ledger.observations-agree", V4, "accepted observations", total, findings)

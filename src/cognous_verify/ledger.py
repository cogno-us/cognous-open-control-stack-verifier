"""Tier V4 receipt completeness: the destination ledger against the decisions and attempts.

Ledger input, as the verifier reads it: the control plane's local destination state,
``{"effects": {effect_id: row}, "grant_effect_counts": {grant_id: n}}`` with an optional
``operations`` member, where a row is ``{effect_id, grant_id, target, amount, unit, payload,
state}`` with an optional ``operation_digest`` (``sha256:`` plus 64 lowercase hex) and an
optional ``extensions`` object (``x-`` names). The shape is the ODES ``destination-ledger``
0.1.0-draft contract; this package reads it from its own text and tests against that
contract's fixtures, it does not import it. This is the only effect-side record the stack produces. It is written by the
executor, carries no sequence number, no chain and no signature, and is trusted by
deployment, not by cryptography. Both directions are checked (ledger effect to decision,
acknowledged attempt to ledger row), and the two counters the qualification harness gates on
(``unauthorized_effects``, ``excess_duplicate_effects``) are recomputed here from the record
and the ledger. A dropped ledger tail, a consistent rewrite of the ledger, or a decision that
never reached the ledger cannot be seen, and a check says so.
"""

from __future__ import annotations

import re
from typing import Any

from .canon import commitment
from .results import CheckResult, Finding, could_not_check, make_result

V1 = "V1"
V4 = "V4"

LEDGER_MEMBERS = {"effects", "grant_effect_counts", "operations", "extensions"}
ROW_MEMBERS = {
    "effect_id": "string",
    "grant_id": "string",
    "target": "string",
    "amount": "number",
    "unit": "string",
    "payload": "object",
    "state": "string",
}
# Members a row may carry or omit. A row without them is exactly the seven-member row above.
ROW_OPTIONAL_MEMBERS = {
    "operation_digest": "digest",
    "extensions": "extensions",
}
OPERATION_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
EXTENSION_NAME = re.compile(r"x-[a-z0-9][a-z0-9._-]*")
ROW_STATES = {"applied", "partial"}
CHECK_IDS = (
    ("v4.ledger.keys", "ledger rows"),
    ("v4.ledger.effects-have-authorized-decisions", "ledger rows"),
    ("v4.ledger.row-matches-binding", "ledger rows"),
    ("v4.ledger.counts", "grants"),
    ("v4.ledger.rows-agree-with-attempts", "ledger rows"),
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
    if kind == "digest":
        # fullmatch, not search or `$`: a trailing newline is not part of the form
        return type(value) is str and OPERATION_DIGEST.fullmatch(value) is not None
    if kind == "extensions":
        return type(value) is dict and all(
            type(name) is str and EXTENSION_NAME.fullmatch(name) for name in value
        )
    return type(value) is dict


def _lone_surrogates(doc: Any) -> list[str]:
    """Paths of text (values and member names) that holds an unpaired surrogate."""
    found: list[str] = []
    todo: list[tuple[Any, str]] = [(doc, "$")]
    while todo:
        item, path = todo.pop()
        if type(item) is str:
            try:
                item.encode("utf-8")
            except UnicodeEncodeError:
                found.append(path)
        elif type(item) is dict:
            for key, member in item.items():
                label = key.encode("unicode_escape").decode("ascii") if type(key) is str else "?"
                try:
                    key.encode("utf-8")
                except UnicodeEncodeError:
                    found.append(f"{path}.{label}")
                todo.append((member, f"{path}.{label}"))
        elif type(item) is list:
            todo.extend((member, f"{path}[{i}]") for i, member in enumerate(item))
    return sorted(found)


def shape(doc: Any) -> list[Finding]:
    """Findings when ``doc`` is not a ledger export of the form described in the module docstring."""
    bad = _lone_surrogates(doc)
    if bad:
        return [
            Finding("ledger_shape", p, "text is not valid Unicode (unpaired surrogate)")
            for p in bad
        ]
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
        for name, kind in ROW_OPTIONAL_MEMBERS.items():
            if name in row and not _is(row[name], kind):
                out.append(Finding("ledger_shape", f"{where}.{name}", f"expected {kind}"))
        for name in row:
            if name not in ROW_MEMBERS and name not in ROW_OPTIONAL_MEMBERS:
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
    if "extensions" in doc and not _is(doc["extensions"], "extensions"):
        out.append(Finding("ledger_shape", "$.extensions", "expected extensions"))
    ops = doc.get("operations")
    if ops is not None and (type(ops) is not dict or not all(type(v) is str for v in ops.values())):
        out.append(Finding("ledger_shape", "$.operations", "operations maps ids to effect ids"))
    return out


def structure(ledger: Any) -> CheckResult:
    return make_result("v1.structure.ledger", V1, "ledger exports", 1, shape(ledger))


def skipped_all(reason: str) -> list[CheckResult]:
    return [could_not_check(cid, V4, unit, 0, reason) for cid, unit in CHECK_IDS]


def is_fresh_acknowledgement(ack: dict[str, Any]) -> bool:
    """True when the acknowledgement claims a fresh execution, in either supported shape.

    The native shape says ``duplicate: false`` (any present value other than true counts); the
    adapter shape says ``newly_executed: true``.
    Either one is a fresh execution claim, so a row in one shape cannot hide behind the other's
    counter.
    """
    # ``duplicate`` is only a duplicate claim when it is exactly true: a member that is present
    # with any other value (false, 0, null, a string) is not a claim of a duplicate, so it counts as
    # fresh instead of understating the excess.
    duplicate_claimed = ack.get("duplicate") is True
    return ("duplicate" in ack and not duplicate_claimed) or ack.get("newly_executed") is True


def contradictory_acknowledgement(ack: dict[str, Any]) -> bool:
    """True when the two freshness members, if both present, disagree with each other."""
    if "duplicate" in ack and "newly_executed" in ack:
        return (ack["duplicate"] is True) == (ack["newly_executed"] is True)
    return False


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
        if a["status"] in {"acknowledged", "partial"} and is_fresh_acknowledgement(
            a["acknowledgement"]
        ):
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
        _counts(record, ledger),
        _rows_agree_with_attempts(record, ledger),
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


def _ceilings(record: dict[str, Any]) -> dict[str, list[tuple[str, Any]]]:
    """Per grant, the ``effective_max_effects`` of each authorized decision that states one."""
    found: dict[str, list[tuple[str, Any]]] = {}
    for i, d in enumerate(record.get("decisions", [])):
        b = d.get("binding")
        if d.get("result") == "authorized" and b and "effective_max_effects" in b:
            found.setdefault(b["grant_id"], []).append(
                (f"$.decisions[{i}].binding.effective_max_effects", b["effective_max_effects"])
            )
    return found


def _valid_ceiling(value: Any) -> bool:
    return type(value) is int and value >= 0


def _counts(record: dict[str, Any], ledger: dict[str, Any]) -> CheckResult:
    """Counts equal the rows, and no grant's count exceeds its largest ceiling.

    Every ceiling that contributes is validated before a maximum is taken, so a malformed one
    cannot hide behind a valid larger one (``max(5, True)`` is 5; ``max(5, "2")`` is an error).
    """
    ceilings = _ceilings(record)
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
        stated = ceilings.get(grant, [])
        bad = [path for path, value in stated if not _valid_ceiling(value)]
        for path in bad:
            findings.append(
                Finding(
                    "ledger_ceiling_invalid",
                    path,
                    "effective_max_effects is a non-negative integer",
                )
            )
        if stated and not bad:
            ceiling = max(value for _, value in stated)
            effects = max(counts.get(grant, 0), rows_per_grant.get(grant, 0))
            if effects > ceiling:
                findings.append(
                    Finding(
                        "ledger_count_above_ceiling",
                        f"$.grant_effect_counts[{grant!r}]",
                        f"{effects} effects exceed the largest effective_max_effects ({ceiling}) "
                        "of the grant's authorized decisions",
                    )
                )
    return make_result("v4.ledger.counts", V4, "grants", len(grants), findings)


def _attempt_layer_outside_record(record: dict[str, Any]) -> bool:
    """True for a record of the atomic claim route: it holds a claim-stage check and nothing else
    of the control plane's dispatch path.

    On that route the control plane issues a claim (a ``claim``-stage resolution check) and the
    destination owns the attempt rows: the record carries no attempt, no observation, no
    reconciliation and no effect-stage check or refusal at all. The premise of the rule below
    (the control plane writes an attempt before it dispatches) does not describe it, so a row
    cannot be judged against attempts the record was never going to hold.
    """
    checks = record.get("resolution_checks", [])
    return (
        any(c["stage"] == "claim" for c in checks)
        and not any(c["stage"] == "effect" for c in checks)
        and not record.get("attempts")
        and not record.get("observations")
        and not record.get("reconciliations")
        and not record.get("refusals")
    )


def _rows_agree_with_attempts(record: dict[str, Any], ledger: dict[str, Any]) -> CheckResult:
    """A ledger row needs an attempt in the record, and not only a definitive failure.

    The control plane writes an attempt row before it dispatches, and reaches the destination
    only through an attempt, so a row for an effect that has no attempt (for example one the
    effect-time check refused) is not something this record could have produced. An attempt
    that ended ``failed`` is the adapter's assertion that the destination did not accept; a
    row for an effect whose every attempt ended that way contradicts it. An attempt whose last
    row is ``attempted``, ``unknown``, ``acknowledged`` or ``partial`` leaves a row possible.

    A record of the atomic claim route holds no attempt layer at all (see
    ``_attempt_layer_outside_record``). A row without an attempt there is not refuted and not
    confirmed: it is reported as could not check, ``attempt_rows_not_in_record``.
    """
    last: dict[str, dict[str, str]] = {}
    for a in record["attempts"]:
        last.setdefault(a["effect_id"], {})[a["attempt_id"]] = a["status"]
    outside = _attempt_layer_outside_record(record)
    findings: list[Finding] = []
    skipped = 0
    for key, row in ledger["effects"].items():
        statuses = last.get(row["effect_id"])
        where = f"$.effects[{key!r}]"
        if not statuses:
            if outside:
                skipped += 1
                continue
            findings.append(
                Finding(
                    "ledger_row_without_attempt",
                    where,
                    "a ledger row for an effect that has no attempt row in the record",
                )
            )
        elif set(statuses.values()) == {"failed"}:
            findings.append(
                Finding(
                    "ledger_row_after_definitive_failure",
                    where,
                    "a ledger row for an effect whose every attempt ended 'failed' "
                    "(a definitive rejection)",
                )
            )
    return make_result(
        "v4.ledger.rows-agree-with-attempts",
        V4,
        "ledger rows",
        len(ledger["effects"]),
        findings,
        skipped=skipped,
        reason="attempt_rows_not_in_record" if skipped else None,
    )


def _accepted_observation_effects(record: dict[str, Any]) -> set[str]:
    """Effects with an accepted applied or partial observation in the record's reconciliations."""
    out: set[str] = set()
    for rec in record["reconciliations"]:
        obs = rec["observation"]
        if (
            rec["observation_accepted"] is True
            and obs is not None
            and obs["state"] in {"applied", "partial"}
        ):
            out.add(obs["effect_id"])
    return out


def _acknowledged_have_rows(record: dict[str, Any], ledger: dict[str, Any]) -> CheckResult:
    """Every acknowledged attempt has a ledger row, and its receipt agrees with that row.

    The receipt an acknowledgement carries is read in the three shapes the stack produces:

    - the native shape, ``effect`` (compared with the row by commitment);
    - the adapter shape, ``observation.destination_state`` of an applied or partial observation
      (compared member by member, like an accepted observation, and its ``effect_id`` must be
      the attempt's);
    - the reconciliation marker ``{"reconciled_existing": true}``, which carries no receipt of its
      own: it is comparable only when the record holds an accepted applied or partial observation
      for that effect (the ``observations-agree`` check compares that observation with the row).

    An acknowledgement with none of these has nothing to compare with the row. That attempt is
    reported as could not check, ``no_comparable_receipt``, never as agreeing. Two freshness
    claims for one effect (``duplicate: false`` or ``newly_executed: true`` on more than one
    acknowledged row) and an acknowledgement whose two freshness members contradict each other
    are refuted.
    """
    rows = ledger["effects"]
    by_effect = {row["effect_id"]: row for row in rows.values()}
    observed = _accepted_observation_effects(record)
    findings: list[Finding] = []
    total = 0
    skipped = 0
    fresh_seen: dict[str, int] = {}
    for i, a in enumerate(record["attempts"]):
        if a["status"] not in {"acknowledged", "partial"}:
            continue
        total += 1
        where = f"$.attempts[{i}]"
        ack = a["acknowledgement"]
        if contradictory_acknowledgement(ack):
            findings.append(
                Finding(
                    "acknowledgement_flags_contradict",
                    where + ".acknowledgement",
                    "duplicate and newly_executed cannot both claim the same thing",
                )
            )
        if is_fresh_acknowledgement(ack):
            fresh_seen[a["effect_id"]] = fresh_seen.get(a["effect_id"], 0) + 1
            if fresh_seen[a["effect_id"]] > 1:
                findings.append(
                    Finding(
                        "fresh_acknowledgement_repeated",
                        where + ".acknowledgement",
                        "a second fresh execution is claimed for the same effect",
                    )
                )
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
        verdict = _receipt_vs_row(a, ack, row, where, observed)
        findings.extend(verdict[0])
        skipped += verdict[1]
    return make_result(
        "v4.ledger.acknowledged-attempts-have-rows",
        V4,
        "attempt rows",
        total,
        findings,
        skipped=skipped,
        reason="no_comparable_receipt" if skipped else None,
    )


def _receipt_vs_row(
    attempt: dict[str, Any],
    ack: dict[str, Any],
    row: dict[str, Any],
    where: str,
    observed: set[str],
) -> tuple[list[Finding], int]:
    """Findings and a could-not-check count (0 or 1) for one acknowledgement against its row."""
    differs = Finding(
        "acknowledgement_differs_from_ledger_row",
        where + ".acknowledgement.effect",
        "the acknowledged effect differs from the ledger row",
    )
    effect = ack.get("effect")
    if effect is not None:
        return ([] if commitment(effect) == commitment(row) else [differs]), 0
    obs = ack.get("observation")
    if type(obs) is dict and obs.get("state") in {"applied", "partial"}:
        obs_where = where + ".acknowledgement.observation"
        found: list[Finding] = []
        if obs.get("effect_id") != attempt["effect_id"]:
            found.append(
                Finding(
                    "acknowledgement_differs_from_ledger_row",
                    obs_where + ".effect_id",
                    "the acknowledged observation names a different effect than the attempt",
                )
            )
        state = obs.get("destination_state")
        if commitment(state) != commitment(row):
            refuted, abstain = _compare_state(state, row)
            for code, path, message in refuted:
                found.append(Finding(code, obs_where + path, message))
            if abstain and not found:
                # members outside the row: the receipt cannot be compared completely, so it is
                # reported unavailable rather than agreeing
                return [], 1
        return found, 0
    if ack == {"reconciled_existing": True} and attempt["effect_id"] in observed:
        return [], 0
    return [], 1


def _observations_agree(record: dict[str, Any], ledger: dict[str, Any]) -> CheckResult:
    """An accepted applied or partial observation has a row and the observed state agrees with it.

    The observed ``destination_state`` is compared member by member with the row:

    - every one of the seven required row members must be present and equal (by commitment, so
      number form counts); a missing or differing one is refuted;
    - ``operation_digest``: when the row and the state both carry it they must be equal, else
      ``operation_digest_mismatch`` (refuted). A digest the state carries and the row
      does not is a member outside the row; a digest the row carries and the state does not is not
      compared (could not check). The optional member never turns a mismatch into an abstention;
    - ``extensions`` on the row are ignored by logic and are not compared; ``extensions`` on the
      state that do not equal the row's are a member outside the row;
    - any other state member is outside the row.

    Members outside the row are not equal and not different: could not check, never confirmed.
    """
    by_effect = {row["effect_id"]: row for row in ledger["effects"].values()}
    findings: list[Finding] = []
    total = 0
    skipped = 0
    reasons: set[str] = set()
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
            continue
        state = obs.get("destination_state")
        if commitment(state) == commitment(row):
            continue
        refuted, abstain = _compare_state(state, row)
        for code, path, message in refuted:
            findings.append(Finding(code, where + path, message))
        if not refuted and abstain:
            skipped += 1
            reasons.add(abstain)
    return make_result(
        "v4.ledger.observations-agree",
        V4,
        "accepted observations",
        total,
        findings,
        skipped=skipped,
        reason=next(iter(reasons)) if len(reasons) == 1 else None,
    )


def _compare_state(
    state: Any, row: dict[str, Any]
) -> tuple[list[tuple[str, str, str]], str | None]:
    """Findings (code, path suffix, message) and the abstention reason for one observed state."""
    differs = (
        "observation_differs_from_ledger_row",
        ".destination_state",
        "the observed destination state differs from the ledger row",
    )
    if type(state) is not dict:
        return [differs], None
    refuted: list[tuple[str, str, str]] = []
    if any(k not in state or commitment(state[k]) != commitment(row[k]) for k in ROW_MEMBERS):
        refuted.append(differs)
    row_digest = row.get("operation_digest")
    if (
        row_digest is not None
        and "operation_digest" in state
        and state["operation_digest"] != row_digest
    ):
        refuted.append(
            (
                "operation_digest_mismatch",
                ".destination_state.operation_digest",
                "the row and the accepted observation's destination_state carry different "
                "operation_digest values",
            )
        )
    if refuted:
        return refuted, None
    outside = set(state) - set(ROW_MEMBERS)
    if row_digest is not None:
        outside.discard("operation_digest")
    if "extensions" in state and commitment(state["extensions"]) == commitment(
        row.get("extensions")
    ):
        outside.discard("extensions")
    if outside:
        return [], "destination_state_has_members_outside_ledger_row"
    if row_digest is not None and "operation_digest" not in state:
        return [], "operation_digest_not_in_destination_state"
    return [], None

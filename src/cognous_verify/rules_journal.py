"""Tier V2 rules of the control-plane-journal contract (0.1.0-draft).

Written from the contract text (README, "Rules"). Each function returns the findings of one
rule group over a structurally valid run record. The identity rules that need the proposal
(recomputing ``effect_id``, proposal, payload and manifest commitments) live in
``identity.py``; the rule here that needs no outside input is that ``effect_id`` of an
authorized decision is the commitment of ``{proposal, grant_id, grant_revision}`` taken from
the binding itself.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from typing import Any

from . import data, profile, rules_lifecycle
from .canon import commitment, same_json
from .results import Finding
from .timeutil import aware

REASON_CODE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
UNCERTAIN = {"attempted", "unknown", "failed"}


def _v(code: str, path: str, message: str) -> Finding:
    return Finding(code, path, message)


def all_inputs(doc: dict[str, Any]) -> Iterator[tuple[str, dict[str, Any]]]:
    for i, d in enumerate(doc["decisions"]):
        for j, x in enumerate(d["resolution_inputs"]):
            yield f"$.decisions[{i}].resolution_inputs[{j}]", x
    for i, r in enumerate(doc["refusals"]):
        for j, x in enumerate(r["resolution_inputs"]):
            yield f"$.refusals[{i}].resolution_inputs[{j}]", x
    for i, c in enumerate(doc["resolution_checks"]):
        for j, x in enumerate(c["inputs"]):
            yield f"$.resolution_checks[{i}].inputs[{j}]", x
    for i, e in enumerate(doc.get("check_events", [])):
        if e["input"] is not None:
            yield f"$.check_events[{i}].input", e["input"]


def decisions(doc: dict[str, Any]) -> list[Finding]:
    out: list[Finding] = []
    seen: set[str] = set()
    for i, d in enumerate(doc["decisions"]):
        p = f"$.decisions[{i}]"
        if d["decision_id"] in seen:
            out.append(_v("duplicate_decision_id", p, "decision ids are unique"))
        seen.add(d["decision_id"])
        binding = d["binding"]
        authorized = d["result"] == "authorized"
        if authorized != (not d["reasons"]) or authorized != (binding is not None):
            out.append(
                _v(
                    "decision_result_inconsistent",
                    p,
                    "result 'authorized' if and only if reasons is empty and a binding is present",
                )
            )
            continue
        if binding is not None:
            expected = commitment(
                {
                    "proposal": binding["proposal_commitment"],
                    "grant_id": binding["grant_id"],
                    "grant_revision": binding["grant_revision"],
                }
            )
            if d["effect_id"] != expected:
                out.append(
                    _v(
                        "invalid_effect_identity",
                        f"{p}.effect_id",
                        "effect_id is the commitment of {proposal, grant_id, grant_revision} "
                        "from the binding",
                    )
                )
            horizon = d["operation_horizon"]
            if (
                horizon is not None
                and horizon["proposal_commitment"] != binding["proposal_commitment"]
            ):
                out.append(
                    _v(
                        "horizon_binding_mismatch",
                        f"{p}.operation_horizon",
                        "the operation horizon commits to the same proposal as the binding",
                    )
                )
            if (binding.get("generation") is None) != (binding.get("tenant_id") is None):
                out.append(
                    _v(
                        "tenant_binding_incomplete",
                        f"{p}.binding",
                        "generation and tenant_id are carried together or not at all",
                    )
                )
    return out


def references(doc: dict[str, Any]) -> list[Finding]:
    out: list[Finding] = []
    by_id = {d["decision_id"]: d for d in doc["decisions"]}
    effects = {d["effect_id"] for d in doc["decisions"]}
    for section, label in (("attempts", "attempt"), ("refusals", "refusal")):
        for i, row in enumerate(doc[section]):
            p = f"$.{section}[{i}]"
            d = by_id.get(row["decision_id"])
            if d is None:
                out.append(_v("dangling_decision_reference", p, f"{label} names no known decision"))
            elif d["effect_id"] != row["effect_id"]:
                out.append(
                    _v("effect_id_mismatch", p, f"{label} effect_id differs from its decision")
                )
            elif d["result"] != "authorized" or d["binding"] is None:
                out.append(
                    _v(
                        "attempt_on_unauthorized_decision"
                        if section == "attempts"
                        else "refusal_requires_authorized_decision",
                        p,
                        f"a {label} requires an authorized decision with a binding",
                    )
                )
    for i, e in enumerate(doc.get("check_events", [])):
        if e["decision_id"] is not None:
            d = by_id.get(e["decision_id"])
            if d is None or d["effect_id"] != e["effect_id"]:
                out.append(
                    _v(
                        "journal_lineage_mismatch",
                        f"$.check_events[{i}]",
                        "a journal decision_id and effect_id must name an existing decision and effect",
                    )
                )
        if e["stage"] in {"decision", "effect"} and (e["decision_id"] is not None) != (
            e["stage"] == "effect"
        ):
            out.append(
                _v(
                    "journal_stage_binding",
                    f"$.check_events[{i}]",
                    "a decision-stage check has no decision yet; an effect-stage check names its decision",
                )
            )
    for section in ("observations", "reconciliations"):
        for i, row in enumerate(doc[section]):
            if row["effect_id"] not in effects:
                out.append(
                    _v(
                        "dangling_effect_reference",
                        f"$.{section}[{i}]",
                        "effect_id matches no decision",
                    )
                )
    return out


def attempts(doc: dict[str, Any]) -> list[Finding]:
    out: list[Finding] = []
    starts: dict[str, set[str]] = {}
    excused = profile.excused_attempts(doc)
    for i, row in enumerate(doc["attempts"]):
        p = f"$.attempts[{i}]"
        status, ack, error = row["status"], row["acknowledgement"], row.get("error")
        if status in {"attempted", "failed", "unknown"} and set(ack) - {"reconciled_existing"}:
            out.append(
                _v(
                    "attempt_acknowledgement_inconsistent",
                    p + ".acknowledgement",
                    f"a '{status}' row carries no acknowledgement",
                )
            )
        bad_error = (
            (status == "failed" and not (isinstance(error, str) and REASON_CODE.fullmatch(error)))
            or (
                status == "unknown"
                and not (
                    isinstance(error, str) and error.startswith("destination_outcome_unknown:")
                )
            )
            or (status in {"attempted", "acknowledged", "partial"} and error is not None)
        )
        if bad_error:
            out.append(
                _v(
                    "attempt_error_inconsistent",
                    p + ".error",
                    "error is null on attempted/acknowledged/partial, a reason code on failed, "
                    "and destination_outcome_unknown:<ExceptionName> on unknown",
                )
            )
        if status == "attempted" and row["attempt_id"] not in excused:
            starts.setdefault(row["effect_id"], set()).add(row["attempt_id"])
    for effect, ids in starts.items():
        if len(ids) > 1:
            out.append(
                _v(
                    "second_attempt_for_effect",
                    "$.attempts",
                    f"effect {effect} has more than one attempt lifecycle starting with 'attempted'",
                )
            )
    return out


def _accepted(rec: dict[str, Any]) -> bool:
    return bool(rec["observation_accepted"] is True)


def reconciliations(doc: dict[str, Any]) -> list[Finding]:
    out: list[Finding] = []
    freshness = profile.freshness_effects(doc)
    for i, rec in enumerate(doc["reconciliations"]):
        p = f"$.reconciliations[{i}]"
        if rec["retry_eligible"] is not False:
            out.append(
                _v(
                    "reconciliation_retry_eligible",
                    p + ".retry_eligible",
                    "retry_eligible must be false",
                )
            )
            continue
        if not _accepted(rec):
            if rec["result"] != "hold" or not rec["reasons"]:
                out.append(
                    _v(
                        "rejected_observation_not_held",
                        p,
                        "a rejected or unavailable observation is held with non-empty reasons",
                    )
                )
            continue
        if rec["reasons"]:
            out.append(
                _v(
                    "accepted_observation_has_reasons",
                    p + ".reasons",
                    "an accepted observation has no reasons",
                )
            )
            continue
        obs = rec["observation"]
        if obs is None:
            out.append(
                _v(
                    "accepted_observation_missing",
                    p + ".observation",
                    "an accepted reconciliation carries its observation",
                )
            )
            continue
        effect = rec["effect_id"]
        state = obs["state"]
        dest = obs.get("destination_state", {})
        if obs["effect_id"] != effect:
            out.append(
                _v(
                    "observation_effect_id_mismatch",
                    p + ".observation.effect_id",
                    "the observation names the reconciled effect",
                )
            )
            continue
        if state == "unknown":
            out.append(
                _v(
                    "observation_state_unknown",
                    p + ".observation.state",
                    "an observation in state unknown is never accepted",
                )
            )
            continue
        if state in {"applied", "partial"}:
            if dest.get("effect_id") != effect:
                out.append(
                    _v(
                        "destination_effect_id_mismatch",
                        p + ".observation.destination_state",
                        "positive destination evidence names the same effect",
                    )
                )
                continue
            if dest.get("state") != state:
                out.append(
                    _v(
                        "destination_state_contradiction",
                        p + ".observation.destination_state",
                        "destination_state.state equals the observation state",
                    )
                )
                continue
        elif dest:
            out.append(
                _v(
                    "absence_has_destination_state",
                    p + ".observation.destination_state",
                    "an absent observation carries an empty destination_state",
                )
            )
            continue
        maximum, tolerance = (
            rec["observation_max_age_seconds"],
            rec["observation_clock_tolerance_seconds"],
        )
        if maximum is None or maximum <= 0 or tolerance is None or tolerance < 0:
            out.append(
                _v(
                    "observation_policy_missing",
                    p,
                    "an accepted observation records its policy (max age > 0, tolerance >= 0)",
                )
            )
            continue
        observed, evaluated = aware(obs.get("observed_at")), aware(rec["evaluation_time"])
        if observed is None or evaluated is None:
            out.append(
                _v(
                    "observation_time_invalid",
                    p,
                    "observed_at and evaluation_time must be timezone-aware",
                )
            )
            continue
        age = (evaluated - observed).total_seconds()
        reference = profile.observation_reference(freshness, rec, evaluated)
        if (reference - observed).total_seconds() < -tolerance:
            out.append(
                _v(
                    "observation_time_future",
                    p,
                    "observed_at is later than evaluation_time plus the tolerance",
                )
            )
            continue
        if age > maximum:
            out.append(
                _v("observation_stale", p, "observed_at is older than the recorded maximum age")
            )
            continue
        expected = {"applied": "applied", "absent": "observed_absent", "partial": "hold"}[state]
        if rec["result"] != expected:
            out.append(
                _v(
                    "reconciliation_result_mismatch",
                    p + ".result",
                    f"an accepted '{state}' observation is recorded as '{expected}'",
                )
            )
    if out:
        return out
    accepted: dict[str, list[Any]] = {}
    for rec in doc["reconciliations"]:
        if _accepted(rec):
            accepted.setdefault(rec["effect_id"], []).append(rec["observation"])
    listed: dict[str, list[Any]] = {}
    for obs in doc["observations"]:
        listed.setdefault(obs["effect_id"], []).append(obs)
    if not same_json(accepted, listed):
        out.append(
            _v(
                "observations_mismatch",
                "$.observations",
                "observations lists exactly the accepted reconciliation observations, per effect, in order",
            )
        )
    return out


def closeouts(doc: dict[str, Any]) -> list[Finding]:
    out: list[Finding] = []
    keys: set[tuple[str, str]] = set()
    # Index the rows once so the checks below stay linear in the size of the record.
    attempt_rows = {(a["attempt_id"], a["effect_id"], a["status"]) for a in doc["attempts"]}
    observed = {
        (
            r["effect_id"],
            (r["observation"] or {}).get("state"),
            (r["observation"] or {}).get("observed_at"),
        )
        for r in doc["reconciliations"]
        if _accepted(r)
    }
    for i, c in enumerate(doc["closeouts"]):
        p = f"$.closeouts[{i}]"
        key = (c["attempt_id"], c["observed_state"])
        if key in keys:
            out.append(_v("duplicate_closeout", p, "one closeout per attempt and observed state"))
        keys.add(key)
        if (c["attempt_id"], c["effect_id"], c["original_status"]) not in attempt_rows:
            out.append(
                _v(
                    "closeout_lineage_missing",
                    p,
                    "a closeout names an attempt row with the same effect and status",
                )
            )
            continue
        if (c["effect_id"], c["observed_state"], c["observed_at"]) not in observed:
            out.append(
                _v(
                    "closeout_observation_missing",
                    p,
                    "a closeout names an accepted observation of that effect, state and time",
                )
            )
    if out:
        return out
    latest: dict[str, dict[str, Any]] = {}
    for a in doc["attempts"]:
        latest[a["attempt_id"]] = a
    reported: set[tuple[str, str]] = set()
    by_effect: dict[str, list[tuple[str, dict[str, Any]]]] = {}
    for attempt_id, a in latest.items():
        by_effect.setdefault(a["effect_id"], []).append((attempt_id, a))
    for rec in doc["reconciliations"]:
        state = (rec["observation"] or {}).get("state")
        if _accepted(rec) and state in {"applied", "partial"}:
            for attempt_id, a in by_effect.get(rec["effect_id"], []):
                if (
                    a["status"] in UNCERTAIN
                    and (attempt_id, state) not in keys
                    and (attempt_id, state) not in reported
                ):
                    reported.add((attempt_id, state))
                    out.append(
                        _v(
                            "closeout_missing",
                            "$.closeouts",
                            f"attempt {attempt_id} is still {a['status']!r}; an accepted {state!r} "
                            "observation of its effect requires a closeout",
                        )
                    )
    return out


def refusals(doc: dict[str, Any]) -> list[Finding]:
    out: list[Finding] = []
    by_id = {d["decision_id"]: d for d in doc["decisions"]}
    seen: set[str] = set()
    for i, r in enumerate(doc["refusals"]):
        p = f"$.refusals[{i}]"
        if r["refusal_id"] in seen:
            out.append(_v("duplicate_refusal_id", p, "refusal ids are unique"))
        seen.add(r["refusal_id"])
        if not r["reasons"]:
            out.append(
                _v("refusal_without_reasons", p + ".reasons", "a refusal carries typed reasons")
            )
        d = by_id.get(r["decision_id"])
        if d is not None and r["original_operation_horizon"] != d["operation_horizon"]:
            out.append(
                _v(
                    "refusal_horizon_mismatch",
                    p + ".original_operation_horizon",
                    "the original horizon equals the horizon of the refused decision",
                )
            )
        for j, change in enumerate(r["changed_inputs"]):
            if not any(
                x["input_type"] == change["input_type"] and x["input_id"] == change["input_id"]
                for x in r["resolution_inputs"]
            ):
                out.append(
                    _v(
                        "changed_input_unattributed",
                        f"{p}.changed_inputs[{j}]",
                        "a changed input is attributed to an actual read in resolution_inputs",
                    )
                )
    return out


def _stamps(doc: dict[str, Any]) -> list[tuple[str, Any]]:
    """Every timestamp the contract requires to be timezone-aware, with its path."""
    stamps: list[tuple[str, Any]] = []
    for i, d in enumerate(doc["decisions"]):
        h = d["operation_horizon"]
        if h:
            stamps += [
                (f"$.decisions[{i}].operation_horizon.{k}", h[k])
                for k in ("not_before", "expires_at")
                if h[k] is not None
            ]
        stamps.append((f"$.decisions[{i}].decided_at", d["decided_at"]))
    stamps += [
        (f"$.attempts[{i}].started_at", a["started_at"]) for i, a in enumerate(doc["attempts"])
    ]
    for i, r in enumerate(doc["refusals"]):
        stamps.append((f"$.refusals[{i}].recorded_at", r["recorded_at"]))
        for name in ("original_operation_horizon", "operation_horizon"):
            h = r[name]
            if h:
                stamps += [
                    (f"$.refusals[{i}].{name}.{k}", h[k])
                    for k in ("not_before", "expires_at")
                    if h[k] is not None
                ]
    stamps += [
        (f"$.resolution_checks[{i}].evaluated_at", c["evaluated_at"])
        for i, c in enumerate(doc["resolution_checks"])
    ]
    stamps += [
        (f"$.check_events[{i}].recorded_at", e["recorded_at"])
        for i, e in enumerate(doc.get("check_events", []))
    ]
    stamps += [
        (f"$.closeouts[{i}].{k}", c[k])
        for i, c in enumerate(doc["closeouts"])
        for k in ("observed_at", "reconciled_at")
    ]
    stamps += [
        (f"$.reconciliations[{i}].reconciled_at", r["reconciled_at"])
        for i, r in enumerate(doc["reconciliations"])
    ]
    stamps += [
        (f"$.reconciliations[{i}].evaluation_time", r["evaluation_time"])
        for i, r in enumerate(doc["reconciliations"])
        if r["evaluation_time"] is not None
    ]
    stamps += [
        (f"$.vocabulary_changes[{i}].acknowledged_at", c["acknowledged_at"])
        for i, c in enumerate(doc.get("vocabulary_changes", []))
    ]
    stamps += [(f"$.input_time_floors.{k}", v) for k, v in doc["input_time_floors"].items()]
    stamps += profile.freshness_time_stamps(doc)
    return stamps


def count_inputs_and_times(doc: dict[str, Any]) -> int:
    return sum(1 for _ in all_inputs(doc)) + len(_stamps(doc))


def inputs_and_times(doc: dict[str, Any]) -> list[Finding]:
    out: list[Finding] = []
    for p, x in all_inputs(doc):
        if x["missing"] and x["record_commitment"] is not None:
            out.append(
                _v("missing_input_commitment", p, "a missing input claims no record commitment")
            )
        if x["previous_observed_at"] is not None and aware(x["previous_observed_at"]) is None:
            out.append(
                _v(
                    "timestamp_invalid",
                    p + ".previous_observed_at",
                    "timestamps are timezone-aware",
                )
            )
    for p, s in _stamps(doc):
        if aware(s) is None:
            out.append(_v("timestamp_invalid", p, "timestamps are timezone-aware ISO-8601"))
    return out


def journal_mode(doc: dict[str, Any]) -> list[Finding]:
    """With a journal, vocabulary version and runtime authority are required; without, forbidden."""
    out: list[Finding] = []
    journal = bool(doc.get("check_events"))
    for section in ("decisions", "refusals"):
        for i, row in enumerate(doc[section]):
            has = "reason_vocabulary_version" in row
            if has and not journal and section == "decisions" and profile.is_lease_hold(row):
                continue  # freshness/0.1: refused before a check is journalled, so no journal
            if journal and not has:
                out.append(
                    _v(
                        "vocabulary_version_missing",
                        f"$.{section}[{i}]",
                        "journal mode: the reason vocabulary version is recorded on every "
                        "decision and refusal",
                    )
                )
            elif has and not journal:
                out.append(
                    _v(
                        "journal_missing",
                        f"$.{section}[{i}].reason_vocabulary_version",
                        "a vocabulary version without a resolution journal",
                    )
                )
    out.extend(_label_mismatch(doc))
    for i, d in enumerate(doc["decisions"]):
        b = d["binding"]
        if b is None:
            continue
        has = "runtime_authority" in b
        if journal and not has:
            out.append(
                _v(
                    "runtime_authority_binding_missing",
                    f"$.decisions[{i}].binding",
                    "journal mode: an authorized binding carries runtime_authority",
                )
            )
        elif has and not journal:
            out.append(
                _v(
                    "journal_missing",
                    f"$.decisions[{i}].binding.runtime_authority",
                    "runtime_authority without a resolution journal",
                )
            )
    return out


def _label_mismatch(doc: dict[str, Any]) -> list[Finding]:
    """A row labelled 0.1 holds no code that only 0.2 registers (draft revision 3).

    The codes only 0.2 registers are read from the verifier's own two vendored registries (the same
    files ``v2.decisions.reason-registry`` resolves labels against). The converse is not checked: 0.2
    is a superset, so a 0.2 label on a row of 0.1 codes states something true. Codes in neither
    registry are not judged here.
    """
    out: list[Finding] = []
    early, late_set = data.DEFAULT_REGISTRY, data.registry_codes("runtime-authority-reasons/0.2")
    late_set = late_set - data.registry_codes(early)
    for section in ("decisions", "refusals", "check_events"):
        for i, row in enumerate(doc.get(section, [])):
            if row.get("reason_vocabulary_version") != early:
                continue
            late = sorted(set(row.get("reasons", [])) & late_set)
            if late:
                out.append(
                    _v(
                        "reason_label_mismatch",
                        f"$.{section}[{i}].reason_vocabulary_version",
                        f"label {early} but the reasons include {', '.join(late)}, which only "
                        "runtime-authority-reasons/0.2 registers",
                    )
                )
    return out


def vocabulary(doc: dict[str, Any]) -> list[Finding]:
    out: list[Finding] = []
    seen: set[str] = set()
    for i, c in enumerate(doc.get("vocabulary_changes", [])):
        p = f"$.vocabulary_changes[{i}]"
        if c["change_id"] in seen:
            out.append(_v("duplicate_vocabulary_change", p, "a vocabulary change is recorded once"))
        seen.add(c["change_id"])
        if c["version"] == c["previous_version"] or (c["kind"] == "split" and len(c["codes"]) < 2):
            out.append(
                _v(
                    "invalid_vocabulary_transition",
                    p,
                    "version differs from previous_version; a split yields at least two codes",
                )
            )
    return out


# ------------------------------------------------------------------------------ check bindings
#
# Verifier-side rules, not restated by the ODES contract text but stated by its fixtures
# ("resolution inputs ... read consistently across decisions, checks and journal") and by the
# producer's write order. They tie the three places a resolution is recorded to each other:
#
# * the producer records one decision-stage resolution check per decision, from the same input
#   list the decision then keeps, so a decision's ``resolution_inputs`` and ``reasons`` equal
#   those of one decision-stage check (``resolution_check_mismatch``); likewise an effect-time
#   refusal keeps the inputs of one effect-stage check;
# * a resolution check row is written only after its evaluation completed, so with a journal
#   every row has a ``completed`` journal check; an evaluation that opened and never completed
#   (opened only, or ``interrupted``) produces no row (``resolution_check_without_completion``).
#   The contract allows unfinished journal checks as evidence; what it does not allow is a row,
#   and so a decision, resting on one;
# * an effect-stage check happens in ``execute`` on a persisted decision, whose decision-stage
#   check was recorded first (``effect_check_before_decision_check``).
#
# None of these says the inputs were read correctly or that a check is complete: they say the
# record does not contradict itself.

_CHECK_INPUT_IGNORED = {"extensions"}


def _exact_inputs(inputs: list[dict[str, Any]]) -> str:
    return commitment(
        [{k: v for k, v in x.items() if k not in _CHECK_INPUT_IGNORED} for x in inputs]
    )


def check_bindings(doc: dict[str, Any]) -> list[Finding]:
    out: list[Finding] = []
    checks = doc["resolution_checks"]
    by_stage: dict[str, list[tuple[int, str, list[str]]]] = {}
    for j, c in enumerate(checks):
        by_stage.setdefault(c["stage"], []).append((j, _exact_inputs(c["inputs"]), c["reasons"]))
    claimed: set[int] = set()

    def bind(stage: str, key: str, reasons: list[str] | None) -> bool:
        return _bind(stage, key, reasons) is not None

    def _bind(stage: str, key: str, reasons: list[str] | None) -> int | None:
        for j, k, r in by_stage.get(stage, []):
            if j not in claimed and k == key and (reasons is None or sorted(reasons) == sorted(r)):
                claimed.add(j)
                return j
        return None

    refusal_check: dict[int, int | None] = {}

    for i, d in enumerate(doc["decisions"]):
        if not bind("decision", _exact_inputs(d["resolution_inputs"]), d["reasons"]):
            out.append(
                _v(
                    "resolution_check_mismatch",
                    f"$.decisions[{i}].resolution_inputs",
                    "the decision's resolution inputs and reasons equal those of no decision-stage "
                    "resolution check",
                )
            )
    for i, r in enumerate(doc["refusals"]):
        key = _exact_inputs(r["resolution_inputs"])
        # prefer the check whose reasons the refusal states, then any check of those inputs
        same = _bind("effect", key, r["reasons"])
        refusal_check[i] = same if same is not None else _bind("effect", key, None)
        if refusal_check[i] is None:
            out.append(
                _v(
                    "resolution_check_mismatch",
                    f"$.refusals[{i}].resolution_inputs",
                    "the refusal's resolution inputs equal those of no effect-stage resolution check",
                )
            )
    events = doc.get("check_events")
    if events:
        completed = {e["check_id"] for e in events if e["phase"] == "completed"}
        if len(checks) > len(completed):
            out.append(
                _v(
                    "resolution_check_without_completion",
                    "$.resolution_checks",
                    f"{len(checks)} resolution checks but {len(completed)} completed journal "
                    "checks: a check row exists for an evaluation the journal shows unfinished",
                )
            )
    seen_decision = False
    for j, c in enumerate(checks):
        if c["stage"] == "decision":
            seen_decision = True
        elif c["stage"] == "effect" and not seen_decision:
            out.append(
                _v(
                    "effect_check_before_decision_check",
                    f"$.resolution_checks[{j}]",
                    "an effect-stage check is listed before any decision-stage check",
                )
            )
            break
    if not out:
        out.extend(_causal_order(doc))
    if not out:
        out.extend(_binding_members(doc))
    if not out:
        out.extend(_completion_reasons_minimum(doc))
    if not out:
        out.extend(_dispatch_license(doc, refusal_check))
    return out


def _not_before(later: Any, earlier: Any) -> bool:
    """True unless both stamps parse and ``later`` is strictly before ``earlier``."""
    a, b = aware(later), aware(earlier)
    return a is None or b is None or a >= b


def _causal_order(doc: dict[str, Any]) -> list[Finding]:
    """An effect is attempted after it was decided, and closed out after it was attempted.

    Each comparison stays inside one clock domain. The evaluation clock (``decided_at``,
    ``started_at``, ``evaluation_time``) is compared only between rows with the same
    ``time_source``; the service clock (``recorded_at``) only between rows that carry it. A stamp
    of one domain is never compared with a stamp of the other.
    """
    out: list[Finding] = []
    by_id = {d["decision_id"]: d for d in doc["decisions"]}
    attempts: dict[str, tuple[int, dict[str, Any]]] = {}
    for i, a in enumerate(doc["attempts"]):
        attempts.setdefault(a["attempt_id"], (i, a))
        d = by_id.get(a["decision_id"])
        if d is None:
            continue
        p = f"$.attempts[{i}]"
        if a["time_source"] == d["time_source"] and not _not_before(
            a["started_at"], d["decided_at"]
        ):
            out.append(
                _v(
                    "attempt_before_decision",
                    p + ".started_at",
                    "an attempt starts no earlier than its decision",
                )
            )
        elif (
            "recorded_at" in a
            and "recorded_at" in d
            and not _not_before(a["recorded_at"], d["recorded_at"])
        ):
            out.append(
                _v(
                    "attempt_before_decision",
                    p + ".recorded_at",
                    "an attempt is recorded no earlier than its decision",
                )
            )
    for i, c in enumerate(doc["closeouts"]):
        found = attempts.get(c["attempt_id"])
        if found is None:
            continue
        a = found[1]
        floor = a.get("recorded_at", a["started_at"])
        if not _not_before(c["reconciled_at"], floor):
            out.append(
                _v(
                    "closeout_before_attempt",
                    f"$.closeouts[{i}].reconciled_at",
                    "a closeout is reconciled no earlier than the attempt it closes",
                )
            )
        for j, rec in enumerate(doc["reconciliations"]):
            obs = rec["observation"] or {}
            if (
                _accepted(rec)
                and rec["effect_id"] == c["effect_id"]
                and obs.get("state") == c["observed_state"]
                and obs.get("observed_at") == c["observed_at"]
                and rec["evaluation_time"] is not None
                and not _not_before(rec["evaluation_time"], a["started_at"])
            ):
                out.append(
                    _v(
                        "reconciliation_before_attempt",
                        f"$.reconciliations[{j}].evaluation_time",
                        "the reconciliation a closeout rests on is evaluated no earlier than the "
                        "attempt it closes",
                    )
                )
    return out


def _binding_members(doc: dict[str, Any]) -> list[Finding]:
    """An authorized binding agrees with the inputs its own decision captured.

    Compared only for an input the decision holds a successful read of: a record that keeps just
    some of its inputs leaves the rest nothing to be compared with. ``requirement_id`` is compared
    with the id of each conflict read. ``effective_max_effects`` is not compared here: no captured
    input states it (it is bounded by the manifest and the ledger count elsewhere).
    """
    out: list[Finding] = []
    for i, d in enumerate(doc["decisions"]):
        b = d["binding"]
        if b is None:
            continue
        reads = [x for x in d["resolution_inputs"] if x.get("missing") is not True]
        where = f"$.decisions[{i}].binding"

        def mismatch(member: str, why: str, where: str = where) -> None:
            out.append(_v("binding_member_mismatch", f"{where}.{member}", why))

        # The conflict read is keyed by the requirement it was made for.
        conflict_ids = [x["input_id"] for x in reads if x["input_type"] == "conflict"]
        if conflict_ids and not all(
            same_json(b.get("requirement_id"), input_id) for input_id in conflict_ids
        ):
            mismatch("requirement_id", "differs from the conflict input the decision read")
        policies = sorted(
            (x["input_id"], x["expected"].get("version"))
            for x in reads
            if x["input_type"] == "policy" and type(x["expected"]) is dict
        )
        if policies:
            wanted = [{"ref": ref, "version": version} for ref, version in policies]
            held = b.get("policy_versions")
            ordered = sorted(held, key=lambda e: str(e.get("ref"))) if type(held) is list else held
            if not same_json(ordered, wanted):
                mismatch("policy_versions", "differs from the policy inputs the decision read")
        for kind, field, member in (
            ("role_mapping", "digest", "role_mapping_digest"),
            ("authority_context", "interface_status", "authority_context_status"),
        ):
            for x in reads:
                if (
                    x["input_type"] == kind
                    and type(x["observed"]) is dict
                    and field in x["observed"]
                ):
                    if not same_json(b.get(member), x["observed"][field]):
                        mismatch(member, f"differs from the {kind} input the decision read")
                    break
    return out


# A read of one of these inputs that the control plane could not make leaves the evaluation unable
# to authorize, so a completion that lists no reasons over such a read is refused. Approval,
# evidence, purpose and manifest reads are not in the set: a missing one is not by itself a reason.
MANDATORY_KINDS = frozenset(
    {"authority_context", "role_mapping", "grant", "identity", "mandate", "conflict", "policy"}
)


def _unread_mandatory(inputs: list[dict[str, Any]]) -> list[tuple[str, str]]:
    """Mandatory inputs the read of which is missing and never succeeded in the same check."""
    read = {(x["input_type"], x["input_id"]) for x in inputs if x.get("missing") is not True}
    return sorted(
        {
            (x["input_type"], x["input_id"])
            for x in inputs
            if x.get("missing") is True
            and x["input_type"] in MANDATORY_KINDS
            and (x["input_type"], x["input_id"]) not in read
        }
    )


def _completion_reasons_minimum(doc: dict[str, Any]) -> list[Finding]:
    out: list[Finding] = []
    for i, c in enumerate(doc["resolution_checks"]):
        if not c["reasons"] and _unread_mandatory(c["inputs"]):
            out.append(
                _v(
                    "completion_reasons_minimum",
                    f"$.resolution_checks[{i}].reasons",
                    "a check with no reasons holds a mandatory read that is missing",
                )
            )
    events = doc.get("check_events") or []
    inputs: dict[str, list[dict[str, Any]]] = {}
    for e in events:
        if e["phase"] == "input" and e["input"] is not None:
            inputs.setdefault(e["check_id"], []).append(e["input"])
    for i, e in enumerate(events):
        if (
            e["phase"] == "completed"
            and not e["reasons"]
            and _unread_mandatory(inputs.get(e["check_id"], []))
        ):
            out.append(
                _v(
                    "completion_reasons_minimum",
                    f"$.check_events[{i}].reasons",
                    "a completed check with no reasons holds a mandatory read that is missing",
                )
            )
    return out


def _dispatch_license(doc: dict[str, Any], refusal_check: dict[int, int | None]) -> list[Finding]:
    """An attempt lifecycle needs a passing effect-stage check no refusal used.

    The control plane writes one effect-stage check per ``execute`` and then either a refusal
    (when the check carries reasons) or at most one attempt lifecycle. Lifecycles excused by an
    expiry refusal (``profile.excused_attempts``) are not counted. With a journal each effect
    check is tied to its decision through the journal events; without one the counts are taken
    over the whole record.
    """
    checks = doc["resolution_checks"]
    excused = profile.excused_attempts(doc)
    lifecycles = sorted({a["attempt_id"] for a in doc["attempts"]} - excused)
    by_attempt = {a["attempt_id"]: a["decision_id"] for a in doc["attempts"]}
    events = [
        e for e in (doc.get("check_events") or []) if e["phase"] not in profile.PROFILE_PHASES
    ]
    if not events:
        passing = sum(1 for c in checks if c["stage"] == "effect" and not c["reasons"])
        used = sum(
            1 for i, j in refusal_check.items() if j is not None and not checks[j]["reasons"]
        )
        if len(lifecycles) > passing - used:
            return [
                _v(
                    "dispatch_without_license",
                    "$.attempts",
                    f"{len(lifecycles)} attempt lifecycles but {passing - used} passing "
                    "effect-stage checks no refusal used",
                )
            ]
        return []
    bound: dict[str, int] = {}
    try:
        rules_lifecycle.journal(events, checks, "$.check_events", bound)
    except rules_lifecycle.LimitExceeded:
        return []  # reported by the journal group as could-not-check
    decision_of = {e["check_id"]: e["decision_id"] for e in events if e["phase"] == "opened"}
    reasoned: dict[str, int] = {}
    passing_d: dict[str, int] = {}
    for cid, j in bound.items():
        did = decision_of.get(cid)
        if checks[j]["stage"] != "effect" or did is None:
            continue
        table = reasoned if checks[j]["reasons"] else passing_d
        table[did] = table.get(did, 0) + 1
    refused: dict[str, int] = {}
    for r in doc["refusals"]:
        refused[r["decision_id"]] = refused.get(r["decision_id"], 0) + 1
    out: list[Finding] = []
    for did in sorted(set(reasoned) | set(refused) | set(by_attempt.values())):
        c, p, r = reasoned.get(did, 0), passing_d.get(did, 0), refused.get(did, 0)
        n = sum(1 for a in lifecycles if by_attempt[a] == did)
        if r < c:
            out.append(
                _v(
                    "effect_check_refusal_missing",
                    "$.refusals",
                    f"decision {did}: {c} effect-stage checks carry reasons but {r} refusals",
                )
            )
        elif n > p - max(0, r - c):
            out.append(
                _v(
                    "dispatch_without_license",
                    "$.attempts",
                    f"decision {did}: {n} attempt lifecycles but {p - max(0, r - c)} passing "
                    "effect-stage checks no refusal used",
                )
            )
    return out

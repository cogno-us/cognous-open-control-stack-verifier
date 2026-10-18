"""Tier V2 rules of the execution-attempt-lifecycle contract (0.1.0-draft).

Written from the contract text (README, "Rules"). Each function returns the findings for one
rule group and assumes the document already passed the structural check (``schema.py``).
Journal and control-plane attempt rules are shared with the control-plane-journal contract,
which delegates to them.
"""

from __future__ import annotations

from typing import Any

from .results import Finding

JOURNAL_BINDING = (
    "owner",
    "stage",
    "proposal_commitment",
    "decision_id",
    "effect_id",
    "action_class",
)


def observation_kind(obs: Any) -> str:
    if obs is None:
        return "none"
    return "validated" if "state" in obs else "recovery"


def check_ids(rows: list[dict[str, Any]], root: str) -> list[Finding]:
    seen: set[str] = set()
    out: list[Finding] = []
    for i, row in enumerate(rows):
        if row["check_id"] in seen:
            out.append(
                Finding("duplicate_check_id", f"{root}[{i}]", "duplicate resolution check id")
            )
        seen.add(row["check_id"])
    return out


def control_plane_attempts(rows: list[dict[str, Any]], root: str) -> list[Finding]:
    out: list[Finding] = []
    lifecycles: dict[str, list[dict[str, Any]]] = {}
    for i, row in enumerate(rows):
        ack = row["acknowledgement"]
        if "reconciled_existing" in ack and ack["reconciled_existing"] is not True:
            out.append(
                Finding(
                    "invalid_reconciled_marker",
                    f"{root}[{i}].acknowledgement",
                    "reconciled_existing, when present, must be true",
                )
            )
        lifecycles.setdefault(row["attempt_id"], []).append(row)
    for attempt_id, seq in lifecycles.items():
        single = (
            len(seq) == 1
            and seq[0]["status"] in {"acknowledged", "partial"}
            and seq[0]["acknowledgement"] == {"reconciled_existing": True}
        )
        marked = any(r["acknowledgement"].get("reconciled_existing") is True for r in seq)
        if marked and not single:
            out.append(
                Finding(
                    "invalid_reconciled_marker",
                    root,
                    f"attempt {attempt_id}: reconciled_existing is only valid on a single "
                    "acknowledged or partial row",
                )
            )
        elif seq[0]["status"] != "attempted" and not single:
            out.append(
                Finding(
                    "missing_start_record",
                    root,
                    f"attempt {attempt_id} lifecycle lacks its 'attempted' start record",
                )
            )
        if len({r["started_at"] for r in seq}) > 1:
            out.append(
                Finding(
                    "attempt_started_at_changed",
                    root,
                    f"attempt {attempt_id}: started_at must be identical on every row",
                )
            )
        if any(seq[i] == seq[j] for i in range(len(seq)) for j in range(i)):
            out.append(
                Finding("repeated_record", root, f"attempt {attempt_id} lifecycle repeats a record")
            )
    return out


def _inputs_key(inputs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Inputs as compared when binding a completed journal check to a resolution check."""
    return [
        {k: v for k, v in x.items() if k not in {"previous_observed_at", "extensions"}}
        for x in inputs
    ]


def journal(events: list[dict[str, Any]], checks: list[dict[str, Any]], root: str) -> list[Finding]:
    """Journal protocol, content binding of completions to checks, and check order."""
    out: list[Finding] = []
    state: dict[str, dict[str, Any]] = {}
    completions: list[tuple[str, list[int]]] = []
    opened_at: dict[str, int] = {}
    closed_at: dict[str, int] = {}
    for seq, ev in enumerate(events):
        cid = ev["check_id"]
        where = f"{root}[{seq}]"
        if ev["phase"] == "opened":
            if cid in state:
                out.append(Finding("journal_protocol", where, "duplicate journal opening"))
                continue
            state[cid] = {"event": ev, "closed": False, "inputs": []}
            opened_at[cid] = seq
            continue
        if cid not in state or state[cid]["closed"]:
            out.append(
                Finding(
                    "journal_protocol",
                    where,
                    "journal event without an open check (missing opening or already closed)",
                )
            )
            continue
        opening = state[cid]["event"]
        if any(ev[k] != opening[k] for k in JOURNAL_BINDING):
            out.append(Finding("journal_protocol", where, "journal binding changed after opening"))
            continue
        if ev["phase"] == "input":
            if ev["input"] is None:
                out.append(Finding("journal_protocol", where, "input phase requires an input"))
                continue
            state[cid]["inputs"].append(ev["input"])
            continue
        state[cid]["closed"] = True
        if ev["phase"] == "completed":
            wanted = _inputs_key(state[cid]["inputs"])
            candidates = [
                i
                for i, row in enumerate(checks)
                if row["stage"] == ev["stage"]
                and _inputs_key(row["inputs"]) == wanted
                and set(ev["reasons"]) <= set(row["reasons"])
            ]
            if not candidates:
                out.append(
                    Finding(
                        "journal_unbound_completion",
                        where,
                        "completed journal check matches no resolution check",
                    )
                )
                continue
            completions.append((cid, candidates))
            closed_at[cid] = seq
    if out:
        return out
    # Each completed journal check needs its own resolution check (matching, not reuse).
    owner: dict[int, int] = {}

    def assign(j: int, seen: set[int]) -> bool:
        for i in completions[j][1]:
            if i not in seen:
                seen.add(i)
                if i not in owner or assign(owner[i], seen):
                    owner[i] = j
                    return True
        return False

    for j in range(len(completions)):
        if not assign(j, set()):
            return [
                Finding(
                    "journal_check_reused",
                    root,
                    "completed journal checks reuse one resolution check",
                )
            ]
    # Checks that do not overlap must be listed in journal order; overlapping ones either way.
    chosen: dict[str, int] = {}
    for cid, candidates in completions:
        previous = max(
            [chosen[o] for o in chosen if closed_at[o] < opened_at[cid]],
            default=-1,
        )
        later = [i for i in candidates if i > previous]
        if not later:
            return [
                Finding(
                    "resolution_checks_out_of_order",
                    "$.resolution_checks",
                    "non-overlapping checks are listed out of journal order",
                )
            ]
        chosen[cid] = min(later)
    return out


# --------------------------------------------------------------------------- executor rows


def _recovery(obs: dict[str, Any], result: dict[str, Any]) -> list[Finding]:
    path = "$.execution_result.observation"
    out: list[Finding] = []
    if obs["retry_eligible"] is not False:
        out.append(
            Finding(
                "recovery_retry_eligible",
                f"{path}.retry_eligible",
                "a recovery report never makes an effect retry-eligible",
            )
        )
    status = obs["status"]
    if status in {"applied", "partial"}:
        missing = [f for f in ("claim_state", "effect_id", "operation_digest") if f not in obs]
        if missing:
            out.append(
                Finding(
                    "recovery_report_incomplete",
                    path,
                    f"an '{status}' recovery report must carry " + ", ".join(missing),
                )
            )
    elif not obs.get("reason"):
        out.append(
            Finding(
                "recovery_report_incomplete",
                path,
                f"a '{status}' recovery report must carry a non-empty reason",
            )
        )
    if result["status"] == "observed" and not out:
        if (
            any(result.get(k) for k in ("attempted", "acknowledged", "newly_executed"))
            or result["attempt_id"] is not None
        ):
            out.append(
                Finding(
                    "effect_free_reconcile_claims_attempt",
                    "$.execution_result",
                    "an effect-free reconcile makes no attempt",
                )
            )
        elif result["observed_state"] != (
            status if status in {"applied", "partial"} else "unknown"
        ):
            out.append(
                Finding(
                    "recovery_state_mismatch",
                    "$.execution_result.observed_state",
                    "observed_state equals the recovery status when applied or partial, else unknown",
                )
            )
    return out


def executor_rows(doc: dict[str, Any]) -> list[Finding]:
    """Rules for runtime executor rows (``attempts``, ``attempt_events``, ``execution_result``)."""
    out: list[Finding] = []
    rows = doc.get("attempts")
    if rows is None:
        return out
    events = doc.get("attempt_events", [])
    ids = [r["attempt_id"] for r in rows]
    if len(set(ids)) != len(ids):
        out.append(Finding("duplicate_attempt_row", "$.attempts", "attempt ids are unique"))
    last_id = None
    last_time = None
    per_attempt: dict[str, list[dict[str, Any]]] = {}
    for i, ev in enumerate(events):
        if last_id is not None and ev["event_id"] <= last_id:
            out.append(
                Finding(
                    "event_order",
                    f"$.attempt_events[{i}].event_id",
                    "event_id must strictly increase",
                )
            )
        last_id = ev["event_id"]
        if last_time is not None and ev["created_at"] < last_time:
            out.append(
                Finding(
                    "event_order",
                    f"$.attempt_events[{i}].created_at",
                    "created_at must not decrease",
                )
            )
        last_time = ev["created_at"]
        per_attempt.setdefault(ev["attempt_id"], []).append(ev)
    for attempt_id in ids:
        seq = per_attempt.get(attempt_id)
        if not seq:
            out.append(
                Finding(
                    "attempt_without_events",
                    "$.attempt_events",
                    f"attempt {attempt_id} has no events",
                )
            )
            continue
        if seq[0]["status"] != "attempted":
            out.append(
                Finding(
                    "missing_start_event",
                    "$.attempt_events",
                    f"attempt {attempt_id} must start 'attempted'",
                )
            )
        if any(e["status"] == "attempted" for e in seq[1:]):
            out.append(
                Finding(
                    "repeated_start_event",
                    "$.attempt_events",
                    f"attempt {attempt_id} repeats 'attempted'",
                )
            )
    result = doc.get("execution_result")
    if result is None:
        return out
    obs = result["observation"]
    kind = observation_kind(obs)
    listed = doc.get("recovery_observations")
    if listed is not None and listed != ([obs] if kind == "recovery" else []):
        out.append(
            Finding(
                "recovery_observations_mismatch",
                "$.recovery_observations",
                "recovery_observations equals the report the result carries, or is empty",
            )
        )
        return out
    if doc.get("observations") is not None and doc["observations"] != (
        [obs] if kind == "validated" else []
    ):
        out.append(
            Finding(
                "observations_mismatch",
                "$.observations",
                "observations lists the validated observation the result carries, or is empty",
            )
        )
        return out
    if kind == "recovery" and result["status"] not in {"unknown", "observed"}:
        out.append(
            Finding(
                "recovery_observation_status",
                "$.execution_result.observation",
                "a recovery observation is carried only by results unknown or observed",
            )
        )
        return out
    if (
        result["status"] == "observed"
        and kind != "recovery"
        and (
            any(result.get(k) for k in ("attempted", "acknowledged", "newly_executed"))
            or result["attempt_id"] is not None
        )
    ):
        return [
            *out,
            Finding(
                "observed_result_claims_attempt",
                "$.execution_result",
                "result observed is effect-free: attempt_id null and no attempt flags",
            ),
        ]
    if result["status"] == "executed" and obs is None:
        return [
            *out,
            Finding(
                "executed_without_observation",
                "$.execution_result.observation",
                "result executed carries the observation that established it",
            ),
        ]
    if kind == "recovery":
        recovery_findings = _recovery(obs, result)
        if recovery_findings:
            return [*out, *recovery_findings]
    if kind == "none" and result["observed_state"] != "unknown":
        return [
            *out,
            Finding(
                "null_observation_state_mismatch",
                "$.execution_result.observed_state",
                f"observation null requires observed_state 'unknown' (got {result['observed_state']!r})",
            ),
        ]
    if result["status"] == "unknown":
        if kind == "validated":
            if obs["state"] not in {"absent", "unknown"}:
                out.append(
                    Finding(
                        "unknown_with_validated_observation",
                        "$.execution_result.observation",
                        "status unknown may carry a validated observation only in state absent or unknown",
                    )
                )
                return out
            expected = obs["state"]
        else:
            expected = "unknown"
            if kind == "recovery" and obs["status"] in {"applied", "partial"}:
                expected = obs["status"]
        if kind != "none" and result["observed_state"] != expected:
            out.append(
                Finding(
                    "unknown_state_mismatch",
                    "$.execution_result.observed_state",
                    f"status unknown with an observation requires observed_state {expected!r}",
                )
            )
            return out
    seq = per_attempt.get(result["attempt_id"])
    if result["attempt_id"] in ids and seq and result["status"] != "observed":
        terminal = seq[-1]["status"]
        if terminal == "attempted":
            out.append(
                Finding(
                    "terminal_event_missing",
                    "$.attempt_events",
                    "the attempt named by the result has no terminal event",
                )
            )
        elif terminal != result["status"] and not (
            terminal == "executed" and result["status"] == "unknown"
        ):
            out.append(
                Finding(
                    "status_terminal_mismatch",
                    "$.execution_result.status",
                    f"result status {result['status']!r} contradicts terminal event {terminal!r}",
                )
            )
    return out

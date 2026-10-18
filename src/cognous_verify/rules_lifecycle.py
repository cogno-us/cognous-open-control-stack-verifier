"""Tier V2 rules of the execution-attempt-lifecycle contract (0.1.0-draft).

Written from the contract text (README, "Rules"). Each function returns the findings for one
rule group and assumes the document already passed the structural check (``schema.py``).
Journal and control-plane attempt rules are shared with the control-plane-journal contract,
which delegates to them.
"""

from __future__ import annotations

import itertools
from typing import Any

from . import data
from .canon import CanonError, commitment, same_json
from .results import Finding

JOURNAL_BINDING = (
    "owner",
    "stage",
    "proposal_commitment",
    "decision_id",
    "effect_id",
    "action_class",
)


# A record with more completed journal checks than this is not matched (could not check).
JOURNAL_COMPLETION_LIMIT = 5000


class LimitExceeded(Exception):
    """An input exceeds a size the verifier bounds; the check reports could-not-check."""


# Control-plane attempt rows: once an attempt is acknowledged, partial or failed it is closed;
# an unknown row may only be followed by one of those; 'attempted' only opens an attempt.
CP_TERMINAL = frozenset({"acknowledged", "partial", "failed"})
CP_AFTER_UNKNOWN = frozenset({"acknowledged", "partial", "failed"})

# Executor attempt events: allowed next statuses ('attempted' only opens an attempt).
EXECUTOR_NEXT: dict[str, frozenset[str]] = {
    "attempted": frozenset({"executed", "partial", "failed", "unknown", "denied", "reconciled"}),
    "executed": frozenset({"unknown", "reconciled"}),
    "partial": frozenset({"unknown", "reconciled"}),
    "unknown": frozenset({"reconciled", "executed", "partial", "failed"}),
    "reconciled": frozenset(),
    "failed": frozenset(),
    "denied": frozenset(),
}


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
        seen_rows: set[str] = set()
        repeated = False
        for r in seq:
            key = commitment(r)
            if key in seen_rows:
                repeated = True
                break
            seen_rows.add(key)
        if repeated:
            out.append(
                Finding("repeated_record", root, f"attempt {attempt_id} lifecycle repeats a record")
            )
        out.extend(_cp_attempt_lifecycle(attempt_id, seq, root))
    return out


def _cp_attempt_lifecycle(attempt_id: str, seq: list[dict[str, Any]], root: str) -> list[Finding]:
    """Identity fixed at the first row; transitions follow the attempt state table."""
    out: list[Finding] = []
    first = seq[0]
    if any(
        (r["effect_id"], r["decision_id"]) != (first["effect_id"], first["decision_id"])
        for r in seq[1:]
    ):
        out.append(
            Finding(
                "attempt_identity_changed",
                root,
                f"attempt {attempt_id}: effect_id and decision_id are fixed by its first row",
            )
        )
    for prev, cur in itertools.pairwise(seq):
        before, after = prev["status"], cur["status"]
        if after == "attempted":
            ok = False
        elif before == "attempted":
            ok = True
        elif before == "unknown":
            ok = after in CP_AFTER_UNKNOWN
        else:
            ok = before not in CP_TERMINAL
        if not ok:
            out.append(
                Finding(
                    "attempt_transition_invalid",
                    root,
                    f"attempt {attempt_id}: a {after!r} row cannot follow {before!r}",
                )
            )
            break
    return out


def _inputs_key(inputs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Inputs as compared when binding a completed journal check to a resolution check."""
    return [
        {k: v for k, v in x.items() if k not in {"previous_observed_at", "extensions"}}
        for x in inputs
    ]


def _typed_key(inputs: list[dict[str, Any]], unique: object) -> str:
    """Canonical commitment of the comparison key: equality is type-strict (``1`` is not ``true``)."""
    try:
        return commitment(_inputs_key(inputs))
    except CanonError:
        return f"uncanonical:{id(unique)}"


def journal(
    events: list[dict[str, Any]],
    checks: list[dict[str, Any]],
    root: str,
    bound: dict[str, int] | None = None,
) -> list[Finding]:
    """Journal protocol, content binding of completions to checks, and check order.

    A completion binds to a resolution check of the same stage and inputs whose reasons are the
    completion's reasons plus, at most, codes the control plane appends after the journal row
    (``data.post_journal_gate_codes``). When ``bound`` is given it receives, for every completed
    check id, the index of the resolution check it was bound to.
    """
    out: list[Finding] = []
    gate = data.post_journal_gate_codes()
    # each resolution check's comparison key is computed once, not once per completion
    prepared = [
        (row["stage"], _typed_key(row["inputs"], row), set(row["reasons"])) for row in checks
    ]
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
            wanted = _typed_key(state[cid]["inputs"], ev)
            reasons = set(ev["reasons"])
            candidates = [
                i
                for i, (stage, key, row_reasons) in enumerate(prepared)
                if stage == ev["stage"]
                and key == wanted
                and reasons <= row_reasons
                and (row_reasons - reasons) <= gate
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
    if len(completions) > JOURNAL_COMPLETION_LIMIT:
        raise LimitExceeded(f"journal_completions>{JOURNAL_COMPLETION_LIMIT}")
    if not _all_matched([cands for _, cands in completions]):
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
    if bound is not None:
        bound.update(chosen)
    return out


def _all_matched(candidates: list[list[int]]) -> bool:
    """True when every completion can take its own resolution check (augmenting paths, iterative:
    no recursion, so the input size cannot exhaust the stack)."""
    owner: dict[int, int] = {}
    for start in range(len(candidates)):
        seen: set[int] = set()
        # each frame: (completion, next candidate position); path records the chosen check
        stack: list[tuple[int, int]] = [(start, 0)]
        chosen: list[int] = []
        found = False
        while stack:
            j, pos = stack[-1]
            options = candidates[j]
            if pos == 0:
                # a free resolution check ends the path at once (keeps identical checks linear)
                free = next((i for i in options if i not in owner and i not in seen), None)
                if free is not None:
                    seen.add(free)
                    chosen.append(free)
                    found = True
                    break
            while pos < len(options) and options[pos] in seen:
                pos += 1
            if pos == len(options):
                stack.pop()
                if chosen:
                    chosen.pop()
                continue
            i = options[pos]
            seen.add(i)
            stack[-1] = (j, pos + 1)
            chosen.append(i)
            if i not in owner:
                found = True
                break
            stack.append((owner[i], 0))
        if not found:
            return False
        # flip the path: stack frame k takes chosen[k]
        for (j, _), i in zip(stack, chosen, strict=True):
            owner[i] = j
    return True


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


ATTEMPT_REQUIRED_STATUSES = frozenset({"failed", "partial", "unknown", "executed", "reconciled"})


def _matrix_violation(result: dict[str, Any]) -> str | None:
    """The first way the result's status, flags and observation contradict one another, if any.

    The cells are the runtime producer's status matrix (``_validate_result_state``). A validated
    observation carries ``state``; a route-B recovery report carries ``status`` and no ``state``,
    so the state cell is read only for the former.
    """
    status = result["status"]
    attempted = result.get("attempted") is True
    acknowledged = result.get("acknowledged") is True
    fresh = result.get("newly_executed") is True
    state = result["observed_state"]
    obs = result["observation"]
    if status in ATTEMPT_REQUIRED_STATUSES and not attempted:
        return f"status {status!r} requires an attempted execution"
    if acknowledged and not attempted:
        return "an acknowledgement requires an attempted execution"
    if fresh and not (acknowledged and status in {"executed", "partial", "unknown"}):
        return "a fresh execution must be acknowledged and have status executed, partial or unknown"
    if status in {"denied", "failed"} and (acknowledged or fresh or state != "unknown"):
        return "a denied or failed result carries no acknowledgement and no observed effect"
    if status == "executed" and not (acknowledged and fresh and state == "applied"):
        return "an executed result is acknowledged, fresh and observed as applied"
    if status == "reconciled" and (fresh or state != "applied"):
        return "a reconciled result is observed as applied and is not a fresh execution"
    if status == "partial" and state != "partial":
        return "a partial result is observed as partial"
    if status in {"executed", "reconciled", "partial", "observed"} and type(obs) is not dict:
        return f"status {status!r} requires a retained observation"
    if observation_kind(obs) == "validated" and obs["state"] != state:
        return "the observation's state contradicts the result's observed_state"
    return None


def _result_rules(doc: dict[str, Any], rows: list[dict[str, Any]], ids: list[str]) -> list[Finding]:
    """Identity and status matrix of ``execution_result``; run when the row rules found nothing."""
    result = doc["execution_result"]
    out: list[Finding] = []
    status = result["status"]
    attempt_id = result["attempt_id"]
    if status in ATTEMPT_REQUIRED_STATUSES and ids.count(attempt_id) != 1:
        return [
            Finding(
                "result_attempt_unresolved",
                "$.execution_result.attempt_id",
                f"result status {status!r} names exactly one attempt row of the record",
            )
        ]
    row = next((r for r in rows if r["attempt_id"] == attempt_id), None)
    if row is not None:
        for member in ("effect_id", "decision_id"):
            if member in result and result[member] != row.get(member):
                out.append(
                    Finding(
                        "result_binding_mismatch",
                        f"$.execution_result.{member}",
                        f"the result's {member} differs from the attempt row it names",
                    )
                )
    if out:
        return out
    why = _matrix_violation(result)
    if why is not None:
        out.append(Finding("result_state_matrix", "$.execution_result", why))
    return out


def executor_rows(doc: dict[str, Any]) -> list[Finding]:
    """Rules for runtime executor rows, then (when those hold) the result identity and matrix."""
    out = _executor_rows(doc)
    if out or doc.get("attempts") is None or doc.get("execution_result") is None:
        return out
    return _result_rules(doc, doc["attempts"], [r["attempt_id"] for r in doc["attempts"]])


def _executor_rows(doc: dict[str, Any]) -> list[Finding]:
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
        for prev, cur in itertools.pairwise(seq):
            if cur["status"] == "attempted" or seq[0]["status"] != "attempted":
                continue  # reported above
            if cur["status"] not in EXECUTOR_NEXT.get(prev["status"], frozenset()):
                out.append(
                    Finding(
                        "attempt_transition_invalid",
                        "$.attempt_events",
                        f"attempt {attempt_id}: event {cur['status']!r} cannot follow "
                        f"{prev['status']!r}",
                    )
                )
                break
    result = doc.get("execution_result")
    if result is None:
        return out
    obs = result["observation"]
    kind = observation_kind(obs)
    listed = doc.get("recovery_observations")
    if listed is not None and not same_json(listed, [obs] if kind == "recovery" else []):
        out.append(
            Finding(
                "recovery_observations_mismatch",
                "$.recovery_observations",
                "recovery_observations equals the report the result carries, or is empty",
            )
        )
        return out
    if doc.get("observations") is not None and not same_json(
        doc["observations"], [obs] if kind == "validated" else []
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
    bound = next((r for r in rows if r["attempt_id"] == result["attempt_id"]), None)
    if bound is not None and type(obs) is dict:
        for member in ("effect_id", "decision_id"):
            if member in obs and obs[member] != bound.get(member):
                out.append(
                    Finding(
                        "result_binding_mismatch",
                        f"$.execution_result.observation.{member}",
                        f"the observation's {member} differs from the attempt row it names",
                    )
                )
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

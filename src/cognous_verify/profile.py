"""Opt-in profile members of the control-plane-journal contract (draft revision 2, ODES e38aace6).

Three opt-in control-plane profiles (``operation-identity/0.1``, ``rule-revision/0.1``,
``freshness/0.1``) add optional members, two check phases (``overdue``, ``expired``) and one read
state (``nonce_mismatch``) to the run record. The structure check admits them; this module holds
the few journal rules that a profile-on record needs to be read differently, and nothing else.

Every relaxation here applies only when a member of the named profile is present on the row it
concerns, so a record written without a profile is judged exactly as before. Where a rule is
relaxed, the part that is still checkable stays checked. The profiles' own semantics (that an
operation id joins the right rows, that a rule revision commitment recomputes, that a deadline is
the opening time plus the bound) belong to their sidecar contracts and are not checked here.

The member table below is the verifier's reading of the schema's descriptions ("owned by the opt-in
profile freshness/0.1"); a test pins it against the vendored schema.
"""

from __future__ import annotations

from typing import Any

from .results import Finding
from .timeutil import aware

FRESHNESS = "freshness/0.1"
EXPIRED_REASON = "check_expired_before_dispatch"
LEASE_REASON = "check_lease_unavailable"
PROFILE_PHASES = ("overdue", "expired")
PROFILE_READ_STATE = "nonce_mismatch"

# Members only freshness/0.1 owns, by section of the run record. (``refusals.check_id`` is shared
# with operation-identity and proves neither profile, so it is not listed.)
FRESHNESS_MEMBERS: dict[str, tuple[str, ...]] = {
    "decisions": ("evaluated_at", "recorded_at"),
    "attempts": ("evaluated_at", "recorded_at"),
    "refusals": ("evaluated_at", "deadline"),
    "resolution_checks": ("recorded_at",),
    "check_events": ("evaluated_at", "deadline", "age_bound_seconds", "extension_id", "nonce"),
}
FRESHNESS_TIMES: dict[str, tuple[str, ...]] = {
    "decisions": ("evaluated_at", "recorded_at"),
    "attempts": ("evaluated_at", "recorded_at"),
    "refusals": ("evaluated_at", "deadline"),
    "resolution_checks": ("recorded_at",),
    "check_events": ("evaluated_at", "deadline"),
}
FRESHNESS_LISTS = ("age_extensions", "age_extension_refusals", "recovery_runs")


def has_freshness(row: Any, section: str) -> bool:
    return type(row) is dict and any(m in row for m in FRESHNESS_MEMBERS[section])


def freshness_effects(doc: dict[str, Any]) -> set[str]:
    """Effect ids with a decision, attempt or refusal row that carries a freshness member."""
    out: set[str] = set()
    for section in ("decisions", "attempts", "refusals"):
        for row in doc[section]:
            if has_freshness(row, section):
                out.add(row["effect_id"])
    return out


def freshness_time_stamps(doc: dict[str, Any]) -> list[tuple[str, Any]]:
    """Freshness times present on rows, with their paths (each must carry a UTC offset)."""
    return [
        (f"$.{section}[{i}].{m}", row[m])
        for section, members in FRESHNESS_TIMES.items()
        for i, row in enumerate(doc.get(section, []))
        for m in members
        if m in row
    ]


def excused_attempts(doc: dict[str, Any]) -> set[str]:
    """Attempts whose failed start is accounted for by an effect-time expiry refusal.

    An attempt that began and then failed with ``check_expired_before_dispatch`` is the control
    plane refusing an expired check at dispatch; the retry on a fresh check is the effect's one
    counted lifecycle. The attempt is excused only if its latest row is ``failed`` with that exact
    error AND a refusal of the same effect carries that reason and the freshness ``deadline``
    member; one refusal excuses one attempt. Without ``deadline`` on the refusal, with another
    failure reason, or with more such attempts than refusals, nothing is excused.
    """
    refusals: dict[str, int] = {}
    for r in doc["refusals"]:
        if "deadline" in r and EXPIRED_REASON in r["reasons"]:
            refusals[r["effect_id"]] = refusals.get(r["effect_id"], 0) + 1
    if not refusals:
        return set()
    latest: dict[str, dict[str, Any]] = {}
    for a in doc["attempts"]:
        latest[a["attempt_id"]] = a
    excused: set[str] = set()
    for attempt_id, a in latest.items():
        if (
            a["status"] == "failed"
            and a.get("error") == EXPIRED_REASON
            and refusals.get(a["effect_id"], 0) > 0
        ):
            refusals[a["effect_id"]] -= 1
            excused.add(attempt_id)
    return excused


def is_lease_hold(decision: dict[str, Any]) -> bool:
    """A hold whose only reason is ``check_lease_unavailable``, written under freshness/0.1 (it
    carries the profile's ``evaluated_at``): the lease is refused before a check is journalled."""
    return (
        decision["result"] == "hold"
        and decision["reasons"] == [LEASE_REASON]
        and decision["binding"] is None
        and "evaluated_at" in decision
    )


def observation_reference(doc_effects: set[str], rec: dict[str, Any], evaluated: Any) -> Any:
    """The clock an observation is judged 'future' against: the evaluation time, or, for an effect
    with a freshness member, the later of it and ``reconciled_at`` (the observation clock is then
    decoupled from the evaluation pass). Staleness stays relative to the evaluation."""
    if rec["effect_id"] not in doc_effects:
        return evaluated
    reconciled = aware(rec["reconciled_at"])
    return max(evaluated, reconciled) if reconciled is not None else evaluated


def profile_phase_events(doc: dict[str, Any]) -> list[tuple[int, dict[str, Any]]]:
    return [
        (i, e) for i, e in enumerate(doc.get("check_events") or []) if e["phase"] in PROFILE_PHASES
    ]


def count_profile_items(doc: dict[str, Any]) -> int:
    """Profile phases and ``nonce_mismatch`` reads in the record (0 for every default record)."""
    from .rules_journal import all_inputs

    return len(profile_phase_events(doc)) + sum(
        1 for _p, x in all_inputs(doc) if x.get("read_state") == PROFILE_READ_STATE
    )


def value_findings(doc: dict[str, Any]) -> list[Finding]:
    """A profile value must carry its profile's member; a profile phase follows its opening."""
    from .rules_journal import all_inputs

    out: list[Finding] = []
    opened: set[str] = set()
    for i, e in enumerate(doc.get("check_events") or []):
        where = f"$.check_events[{i}]"
        if e["phase"] == "opened":
            opened.add(e["check_id"])
        elif e["phase"] in PROFILE_PHASES:
            if "deadline" not in e:
                out.append(
                    Finding(
                        "profile_value_without_member",
                        where + ".phase",
                        f"phase {e['phase']!r} belongs to {FRESHNESS} and its event carries the "
                        "profile's deadline",
                    )
                )
            elif e["check_id"] not in opened:
                out.append(
                    Finding(
                        "journal_protocol",
                        where,
                        "journal event without an open check (missing opening or already closed)",
                    )
                )
    for p, x in all_inputs(doc):
        if x.get("read_state") == PROFILE_READ_STATE and "age_basis" not in x:
            out.append(
                Finding(
                    "profile_value_without_member",
                    p + ".read_state",
                    f"read state {PROFILE_READ_STATE!r} belongs to {FRESHNESS} and its input "
                    "carries age_basis",
                )
            )
    return out

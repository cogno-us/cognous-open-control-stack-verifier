"""Tier V3: witness re-derivation, written from the witness and holder-inventory profiles.

What a witness is, as the control plane's ``witness-digest/0.1`` profile defines it: a party
other than the holder of the record-store key keeps a chain of digest records. Each record
names the run, a sequence number, the previous record's digest, and per list-valued ledger of
the record document the number of rows it covered (``count``) and the hash-chain head over
those rows (``head``). This module recomputes every one of those values from the retained
record with its own canonical form and compares them with what the witness file says.

Definitions implemented here (the profile's own text, not the stack's code):

* a ledger is every list-valued top-level member of the record document, rows in stored order;
* ``heads[0]`` is ``sha256:`` plus 64 zeros; ``heads[i+1] = commitment({"prev": heads[i],
  "row": commitment(row_i)})``; a ledger head covers exactly its first ``count`` rows;
* a witness record's ``digest`` is the commitment of the record without its ``digest``
  member; its ``sequence`` is its index; its ``previous_digest`` is the recorded ``digest`` of
  the record before it (null for the first); one run; per-ledger counts never decrease;
* empty ledgers are omitted from a record; a ledger that is missing counts as empty.

What this tier shows: the witness file matches the records it was given. What it does not and
cannot show: that the witness was published, that it was timely, or that anyone independent
of the record keeper held it (a witness file supplied by the party that supplied the records
vouches for nothing that party could rewrite). The ``witness-digest/0.1`` record has no signer
or proof member, so there is nothing to check about who published it; a record with one more
member is refused as a shape error, not read as a signature.

Holder inventory (``holder-inventory/0.1``): the run record does not carry one (it is a member
of the runtime-authority profile, which the record does not retain), so it can be supplied as
its own input and is checked against the profile's closed shape only. Nothing the contract
leaves undefined is checked (for example that holder ids are unique, or that the inventory
matches the one in force at a decision).

Reporting: since the ODES ``verification-report`` revision of 2026-10-18 (decision 27) tier ``V3``
is a tier like the others: its checks are in ``checks``, counted in ``summary``, listed in
``scope.tiers_run`` and its inputs are in ``subject.inputs`` (roles ``witness`` and
``holder_inventory``). It runs only when a witness or an inventory was supplied: with neither,
there is no V3 check, no V3 input and no ``V3`` in ``tiers_run``.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from . import wire
from .canon import commitment, digest_bytes
from .results import (
    CheckResult,
    Finding,
    could_not_check,
    make_result,
    verifier_error,
)
from .results import (
    confirmed_or_refuted as _done,
)
from .timeutil import aware

V3 = "V3"
WITNESS_VERSION = "witness-digest/0.1"
HOLDER_VERSION = "holder-inventory/0.1"
GENESIS = "sha256:" + "0" * 64
HOLDER_KINDS = ("routed", "self_credentialed", "other")
HOLDER_MISSING_REASON = "holder_inventory_missing"
WITNESS_ROLE = "witness"
HOLDER_ROLE = "holder_inventory"
V3_ROLES = (WITNESS_ROLE, HOLDER_ROLE)

WITNESS_CHECK_IDS = (
    ("v3.witness.records", "witness records"),
    ("v3.witness.digest-recompute", "witness records"),
    ("v3.witness.chain", "witness records"),
    ("v3.witness.run-id", "witness records"),
    ("v3.witness.ledger-heads", "witness records"),
    ("v3.witness.coverage", "record ledgers"),
)

RECORD_MEMBERS = ("version", "run_id", "sequence", "previous_digest", "ledgers", "digest")
LEDGER_MEMBERS = ("count", "head")
HOLDER_INVENTORY_MEMBERS = ("version", "inventory_id", "recorded_by", "recorded_at", "holders")
HOLDER_MEMBERS = ("holder_id", "kind", "enforcement_point", "credential_ref")
# Optional on a witness record, a ledger entry, an inventory and a holder: an object with ``x-``
# names (ignored by every rule here; on a witness record it is covered by ``digest`` like any
# other member). Never read as a signer or a proof.
EXTENSIONS = "extensions"
_EXTENSION_NAME = re.compile(r"x-[a-z0-9][a-z0-9._-]*")

_SHA = re.compile(r"^sha256:[0-9a-f]{64}$")

LIMITS: tuple[str, ...] = (
    "the witness is shown to match the records it was given; not that it was published, that it "
    "was published in time, or that a party independent of the record keeper held it",
    "a witness file supplied by whoever supplied the records vouches for nothing that party "
    "could rewrite, and rows appended after the latest digest are not covered",
    "only list-valued ledgers are covered; top-level scalars and dictionaries (run_id, "
    "input_time_floors) are not",
    "the witness-digest/0.1 record has no signer or proof member: nothing about who published "
    "it is checked",
    "the run record does not carry a holder inventory; a supplied inventory is checked against "
    "the profile's closed shape only, not for completeness or for being the one in force",
)


@dataclass
class TierV3:
    """The V3 part of an evaluation: results in the ``checks`` shape and the inputs it read.

    ``requested`` is False when neither input was supplied; the tier then has no results.
    """

    results: list[CheckResult]
    inputs: list[dict[str, Any]]
    requested: bool
    not_applicable: list[dict[str, str]] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------------- derivation


def ledgers(record: dict[str, Any]) -> dict[str, list[Any]]:
    """Every list-valued top-level member, in name order."""
    return {k: v for k, v in sorted(record.items()) if type(v) is list}


def chain_heads(rows: list[Any]) -> list[str]:
    """``heads[i]`` is the chain head after the first ``i`` rows."""
    heads = [GENESIS]
    for row in rows:
        heads.append(commitment({"prev": heads[-1], "row": commitment(row)}))
    return heads


def record_digest(rec: dict[str, Any]) -> str:
    return commitment({k: v for k, v in rec.items() if k != "digest"})


# ---------------------------------------------------------------------------------- parsing


def parse_witness(data: bytes) -> tuple[list[Any], list[Finding]]:
    """JSON lines to values. A line the strict parser refuses is a finding, never repaired."""
    try:
        text = wire.decode(data)
    except wire.WireError as exc:
        return [], [Finding(exc.code, "$.witness", exc.message)]
    values: list[Any] = []
    findings: list[Finding] = []
    for line in text.split("\n"):
        if not line.strip():
            continue
        index = len(values)
        try:
            values.append(wire.parse_text(line))
        except wire.WireError as exc:
            values.append(None)
            findings.append(Finding(exc.code, f"$.witness[{index}]", exc.message))
    return values, findings


def _is_count(value: Any) -> bool:
    return type(value) is int and value >= 0


def _extension_findings(where: str, rec: dict[str, Any], shape_code: str) -> list[Finding]:
    """``extensions``, when present, is an object whose names all match ``x-...``."""
    if EXTENSIONS not in rec:
        return []
    ext = rec[EXTENSIONS]
    if type(ext) is not dict:
        return [Finding(shape_code, f"{where}.{EXTENSIONS}", "extensions is an object")]
    return [
        Finding(
            "invalid_extension_key",
            f"{where}.{EXTENSIONS}.{name}",
            "an extension name starts with x-",
        )
        for name in ext
        if not _EXTENSION_NAME.fullmatch(name)
    ]


def _shape(index: int, rec: Any) -> list[Finding]:
    where = f"$.witness[{index}]"
    if type(rec) is not dict:
        return [Finding("witness_record_shape", where, "a witness record is a JSON object")]
    out: list[Finding] = []
    for name in rec:
        if name not in RECORD_MEMBERS and name != EXTENSIONS:
            out.append(Finding("witness_record_shape", f"{where}.{name}", "undeclared member"))
    for name in RECORD_MEMBERS:
        if name not in rec:
            out.append(Finding("witness_record_shape", f"{where}.{name}", "member missing"))
    if out:
        return out
    if type(rec["version"]) is not str:
        out.append(Finding("witness_record_shape", f"{where}.version", "a string"))
    elif rec["version"] != WITNESS_VERSION:
        out.append(
            Finding(
                "witness_version_unsupported",
                f"{where}.version",
                f"only {WITNESS_VERSION} is read",
            )
        )
    if type(rec["run_id"]) is not str or not rec["run_id"]:
        out.append(Finding("witness_record_shape", f"{where}.run_id", "a non-empty string"))
    out.extend(_extension_findings(where, rec, "witness_record_shape"))
    if not _is_count(rec["sequence"]):
        out.append(Finding("witness_record_shape", f"{where}.sequence", "a non-negative integer"))
    prev = rec["previous_digest"]
    if prev is not None and not (type(prev) is str and _SHA.fullmatch(prev)):
        out.append(Finding("witness_record_shape", f"{where}.previous_digest", "null or a digest"))
    if type(rec["digest"]) is not str or not _SHA.fullmatch(rec["digest"]):
        out.append(Finding("witness_record_shape", f"{where}.digest", "a sha256 digest"))
    held = rec["ledgers"]
    if type(held) is not dict:
        out.append(Finding("witness_record_shape", f"{where}.ledgers", "an object"))
        return out
    for name, entry in held.items():
        spot = f"{where}.ledgers.{name}"
        if type(entry) is not dict or not set(LEDGER_MEMBERS) <= set(entry) <= {
            *LEDGER_MEMBERS,
            EXTENSIONS,
        }:
            out.append(
                Finding("witness_record_shape", spot, "count and head (and optionally extensions)")
            )
            continue
        out.extend(_extension_findings(spot, entry, "witness_record_shape"))
        if not _is_count(entry["count"]):
            out.append(Finding("witness_record_shape", spot, "count is a non-negative integer"))
        if type(entry["head"]) is not str or not _SHA.fullmatch(entry["head"]):
            out.append(Finding("witness_record_shape", spot, "head is a sha256 digest"))
    return out


# ---------------------------------------------------------------------------------- witness checks


def _skip_group(reason: str, total: int = 0) -> list[CheckResult]:
    return [could_not_check(cid, V3, unit, total, reason) for cid, unit in WITNESS_CHECK_IDS]


def _guard(check_id: str, unit: str, total: int, fn: Callable[[], CheckResult]) -> CheckResult:
    try:
        return fn()
    except Exception as exc:  # a crash is reported as an error, never as a verdict
        return verifier_error(check_id, V3, unit, total, exc)


def _digest_findings(recs: list[dict[str, Any]]) -> list[Finding]:
    return [
        Finding(
            "witness_chain_invalid",
            f"$.witness[{i}].digest",
            "the digest does not recompute from the record's other members",
        )
        for i, rec in enumerate(recs)
        if rec["digest"] != record_digest(rec)
    ]


def _chain_findings(recs: list[dict[str, Any]]) -> list[Finding]:
    out: list[Finding] = []
    previous: dict[str, Any] | None = None
    for i, rec in enumerate(recs):
        where = f"$.witness[{i}]"
        if rec["sequence"] != i:
            out.append(
                Finding(
                    "witness_chain_invalid",
                    f"{where}.sequence",
                    f"sequence {rec['sequence']!r} is not contiguous (expected {i})",
                )
            )
        want = None if previous is None else previous["digest"]
        if rec["previous_digest"] != want:
            out.append(
                Finding(
                    "witness_chain_invalid",
                    f"{where}.previous_digest",
                    "previous_digest does not link to the record before it",
                )
            )
        if previous is not None:
            if rec["run_id"] != previous["run_id"]:
                out.append(
                    Finding(
                        "witness_chain_invalid",
                        f"{where}.run_id",
                        "run_id differs from the record before it",
                    )
                )
            for name, old in previous["ledgers"].items():
                new = rec["ledgers"].get(name)
                if new is None or new["count"] < old["count"]:
                    out.append(
                        Finding(
                            "witness_chain_invalid",
                            f"{where}.ledgers.{name}",
                            "covers fewer rows than the record before it",
                        )
                    )
        previous = rec
    return out


def _head_findings(recs: list[dict[str, Any]], doc: dict[str, Any]) -> tuple[list[Finding], int]:
    rows_by = ledgers(doc)
    cache: dict[str, list[str]] = {}
    out: list[Finding] = []
    pairs = 0
    for i, rec in enumerate(recs):
        for name, held in sorted(rec["ledgers"].items()):
            # an entry that covers no row (the profile omits empty ledgers) derives nothing
            pairs += held["count"] >= 1
            rows = rows_by.get(name, [])
            if name not in cache:
                cache[name] = chain_heads(rows)
            count = held["count"]
            where = f"$.witness[{i}].ledgers.{name}"
            if len(rows) < count:
                out.append(
                    Finding(
                        "witness_ledger_shrunk",
                        where,
                        f"the witness covers {count} rows of {name}; the record holds {len(rows)}",
                    )
                )
            elif cache[name][count] != held["head"]:
                out.append(
                    Finding(
                        "witness_ledger_head_mismatch",
                        where,
                        f"the chain head over the first {count} rows of {name} does not match "
                        "the witness",
                    )
                )
    return out, pairs


def witness_checks(doc: dict[str, Any], data: bytes) -> list[CheckResult]:
    """The six witness checks for one record document and one witness file."""
    values, parse_findings = parse_witness(data)
    total = len(values)
    if not values and not parse_findings:
        return _skip_group("input_absent:witness_holds_no_digest")
    if not values:
        return [
            *(
                [
                    make_result(
                        WITNESS_CHECK_IDS[0][0], V3, WITNESS_CHECK_IDS[0][1], 1, parse_findings
                    )
                ]
            ),
            *_skip_group("tier_unavailable:witness_not_parsed", 1)[1:],
        ]
    shape: list[Finding] = list(parse_findings)
    for i, rec in enumerate(values):
        if rec is not None:
            shape.extend(_shape(i, rec))
    first = _guard(
        WITNESS_CHECK_IDS[0][0],
        WITNESS_CHECK_IDS[0][1],
        total,
        lambda: _done(WITNESS_CHECK_IDS[0][0], V3, WITNESS_CHECK_IDS[0][1], total, shape),
    )
    if shape:
        return [first, *_skip_group("earlier_rules_refuted", total)[1:]]
    recs: list[dict[str, Any]] = values
    out = [first]
    digest = _guard(
        WITNESS_CHECK_IDS[1][0],
        WITNESS_CHECK_IDS[1][1],
        total,
        lambda: _done(
            WITNESS_CHECK_IDS[1][0], V3, WITNESS_CHECK_IDS[1][1], total, _digest_findings(recs)
        ),
    )
    chain = _guard(
        WITNESS_CHECK_IDS[2][0],
        WITNESS_CHECK_IDS[2][1],
        total,
        lambda: _done(
            WITNESS_CHECK_IDS[2][0], V3, WITNESS_CHECK_IDS[2][1], total, _chain_findings(recs)
        ),
    )
    out += [digest, chain]
    run_id = doc.get("run_id")
    if type(run_id) is not str or not run_id:
        run = could_not_check(
            WITNESS_CHECK_IDS[3][0],
            V3,
            WITNESS_CHECK_IDS[3][1],
            total,
            "tier_unavailable:record_has_no_run_id",
        )
    else:
        run = _done(
            WITNESS_CHECK_IDS[3][0],
            V3,
            WITNESS_CHECK_IDS[3][1],
            total,
            [
                Finding(
                    "witness_run_mismatch",
                    f"$.witness[{i}].run_id",
                    "the witness holds a chain for a different run than the record",
                )
                for i, rec in enumerate(recs)
                if rec["run_id"] != run_id
            ],
        )
    out.append(run)
    if run.verdict != "confirmed" and run.verdict != "refuted":
        return out + _skip_group("tier_unavailable:record_has_no_run_id", total)[4:]
    if any(r.verdict == "refuted" for r in (digest, chain, run)):
        return out + _skip_group("earlier_rules_refuted", total)[4:]
    try:
        heads, pairs = _head_findings(recs, doc)
        out.append(
            make_result(
                WITNESS_CHECK_IDS[4][0],
                V3,
                WITNESS_CHECK_IDS[4][1],
                total,
                heads,
                notes=[f"{pairs} ledger heads re-derived over {total} witness records"],
            )
        )
        out.append(_coverage(doc, recs[-1]))
    except Exception as exc:
        out.append(verifier_error(WITNESS_CHECK_IDS[4][0], V3, WITNESS_CHECK_IDS[4][1], total, exc))
        out.append(verifier_error(WITNESS_CHECK_IDS[5][0], V3, WITNESS_CHECK_IDS[5][1], 0, exc))
    return out


def _coverage(doc: dict[str, Any], latest: dict[str, Any]) -> CheckResult:
    """Rows of each non-empty record ledger that the latest witness record does not cover."""
    rows_by = {name: rows for name, rows in ledgers(doc).items() if rows}
    uncovered = [
        name
        for name, rows in rows_by.items()
        if len(rows) > latest["ledgers"].get(name, {"count": 0})["count"]
    ]
    notes = [
        f"rows after the latest digest, not covered: {name} "
        f"({len(rows_by[name]) - latest['ledgers'].get(name, {'count': 0})['count']} of "
        f"{len(rows_by[name])})"
        for name in uncovered
    ]
    return make_result(
        WITNESS_CHECK_IDS[5][0],
        V3,
        WITNESS_CHECK_IDS[5][1],
        len(rows_by),
        [],
        skipped=len(uncovered),
        reason="input_absent:rows_not_covered_by_witness",
        notes=notes,
    )


# ---------------------------------------------------------------------------------- holder inventory


def _inventory_findings(doc: Any) -> list[Finding]:
    if type(doc) is not dict:
        return [Finding("holder_inventory_shape", "$", "an inventory is a JSON object")]
    out: list[Finding] = []
    for name in doc:
        if name not in HOLDER_INVENTORY_MEMBERS and name != EXTENSIONS:
            out.append(Finding("undeclared_member", f"$.{name}", "undeclared member"))
    for name in HOLDER_INVENTORY_MEMBERS:
        if name not in doc:
            out.append(Finding("holder_inventory_shape", f"$.{name}", "member missing"))
    if out:
        return out
    out.extend(_extension_findings("$", doc, "holder_inventory_shape"))
    if type(doc["version"]) is not str:
        out.append(Finding("holder_inventory_shape", "$.version", "a string"))
    elif doc["version"] != HOLDER_VERSION:
        out.append(
            Finding("unsupported_contract_version", "$.version", f"only {HOLDER_VERSION} is read")
        )
    for name in ("inventory_id", "recorded_by"):
        if type(doc[name]) is not str or not doc[name] or len(doc[name]) > 256:
            out.append(
                Finding("holder_inventory_shape", f"$.{name}", "a string of 1 to 256 characters")
            )
    if type(doc["recorded_at"]) is not str or not doc["recorded_at"]:
        out.append(Finding("holder_inventory_shape", "$.recorded_at", "a non-empty string"))
    if type(doc["recorded_at"]) is str and doc["recorded_at"] and aware(doc["recorded_at"]) is None:
        out.append(
            Finding(
                "timestamp_invalid",
                "$.recorded_at",
                "a time with a UTC offset (a time without one is not evidence)",
            )
        )
    holders = doc["holders"]
    if type(holders) is not list or len(holders) > 10000:
        out.append(
            Finding("holder_inventory_shape", "$.holders", "a list of at most 10000 holders")
        )
        return out
    for i, holder in enumerate(holders):
        out.extend(_holder_findings(i, holder))
    return out


def _holder_findings(i: int, holder: Any) -> list[Finding]:
    where = f"$.holders[{i}]"
    if type(holder) is not dict:
        return [Finding("holder_inventory_shape", where, "a holder is an object")]
    out: list[Finding] = []
    for name in holder:
        if name not in HOLDER_MEMBERS and name != EXTENSIONS:
            out.append(Finding("undeclared_member", f"{where}.{name}", "undeclared member"))
    out.extend(_extension_findings(where, holder, "holder_inventory_shape"))
    for name in ("holder_id", "kind", "enforcement_point"):
        if name not in holder:
            out.append(Finding("holder_inventory_shape", f"{where}.{name}", "member missing"))
        elif name != "kind" and (
            type(holder[name]) is not str or not holder[name] or len(holder[name]) > 256
        ):
            out.append(
                Finding(
                    "holder_inventory_shape", f"{where}.{name}", "a string of 1 to 256 characters"
                )
            )
    if "kind" in holder and holder["kind"] not in HOLDER_KINDS:
        out.append(
            Finding(
                "unknown_enum_value",
                f"{where}.kind",
                "kind is routed, self_credentialed or other",
            )
        )
    ref = holder.get("credential_ref")
    if ref is not None and (type(ref) is not str or len(ref) > 256):
        out.append(
            Finding(
                "holder_inventory_shape",
                f"{where}.credential_ref",
                "null or a string of at most 256",
            )
        )
    return out


def inventory_document_check(data: bytes) -> tuple[CheckResult, Any]:
    """Shape check of a supplied inventory; the parsed document when it parsed."""
    cid, unit = "v3.holder-inventory.document", "inventory documents"
    try:
        doc = wire.parse(data)
    except wire.WireError as exc:
        return make_result(cid, V3, unit, 1, [Finding(exc.code, "$", exc.message)]), None
    findings = _inventory_findings(doc)
    if findings:
        return make_result(cid, V3, unit, 1, findings), doc
    if not doc["holders"]:
        return (
            make_result(
                cid,
                V3,
                unit,
                1,
                [],
                skipped=1,
                reason="not_applicable_to_input:inventory_enumerates_no_holder",
                notes=["an inventory that enumerates no holder claims nothing"],
            ),
            doc,
        )
    return _done(cid, V3, unit, 1, []), doc


def _held_for_missing_inventory(record: dict[str, Any]) -> int:
    n = 0
    for name in ("decisions", "refusals"):
        rows = record.get(name)
        if type(rows) is not list:
            continue
        for row in rows:
            reasons = row.get("reasons") if type(row) is dict else None
            if type(reasons) is list and HOLDER_MISSING_REASON in reasons:
                n += 1
    return n


def inventory_record_check(record: dict[str, Any], inventory_exists: bool | None) -> CheckResult:
    """Holds the record states for a missing inventory: the verifier cannot tie them to an inventory.

    ``inventory_exists`` is None when no inventory was supplied.
    """
    cid, unit = "v3.holder-inventory.record-reference", "decisions and refusals"
    n = _held_for_missing_inventory(record)
    if n == 0:
        return could_not_check(cid, V3, unit, 0, "no_items_in_record")
    reason = (
        "input_absent:holder_inventory"
        if inventory_exists is None
        else "tier_unavailable:profile_in_force_not_in_record"
    )
    return CheckResult(
        check_id=cid,
        tier=V3,
        verdict="could_not_check",
        unit=unit,
        checked=0,
        total=n,
        reason=reason,
        notes=[
            f"{n} rows carry {HOLDER_MISSING_REASON}; the record does not hold the profile that "
            "was in force, so they cannot be tied to the supplied inventory"
        ],
        skipped=n,
    )


# ---------------------------------------------------------------------------------- entry point


def run_tier(
    record: Any,
    witness: tuple[str, bytes] | None,
    inventory: tuple[str, bytes] | None,
    *,
    contract_is_journal: bool,
) -> TierV3:
    """Run tier V3 over the parsed run record and the optional witness and inventory inputs."""
    given = [(WITNESS_ROLE, witness), (HOLDER_ROLE, inventory)]
    inputs = [
        {"role": role, "name": item[0], "digest": digest_bytes(item[1]), "size_bytes": len(item[1])}
        for role, item in given
        if item is not None
    ]
    inputs.sort(key=lambda r: (r["role"], r["name"], r["digest"]))
    requested = witness is not None or inventory is not None
    if not requested:
        return TierV3(results=[], inputs=[], requested=False)
    results: list[CheckResult] = []
    if witness is None:
        pass  # inventory only: nothing is said about a witness nobody supplied
    elif type(record) is not dict:
        results += _skip_group("tier_unavailable:run_record_not_parsed", 1)
    elif not contract_is_journal:
        results += _skip_group(
            "unsupported_document:witness-digest/0.1 covers a control-plane record store document"
        )
    else:
        results += witness_checks(record, witness[1])
    inv_exists: bool | None = None
    if inventory is not None:
        check, _ = inventory_document_check(inventory[1])
        results.append(check)
        inv_exists = check.verdict == "confirmed"
        if type(record) is dict:
            results.append(inventory_record_check(record, inv_exists))
    elif witness is not None and type(record) is dict and contract_is_journal:
        results.append(inventory_record_check(record, None))
    tier = TierV3(results=results, inputs=inputs, requested=requested)
    kept: list[CheckResult] = []
    for r in tier.results:
        if r.verdict == "could_not_check" and r.reason in ("no_items_in_record",):
            tier.not_applicable.append(
                {"check_id": r.check_id, "tier": r.tier, "unit": r.unit, "reason": r.reason}
            )
        else:
            kept.append(r)
    tier.results = kept
    tier.notes.extend(LIMITS)
    return tier

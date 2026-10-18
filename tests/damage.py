"""Damage operators for the verifier's own smoke corpus.

These operators were written by the same author as the verifier, from the same design
catalogue, and are applied to the same clean runs the verifier was developed against. They
show the verifier catches the damage it was built to catch and accepts benign changes. They
are NOT the held-out detection measurement of the design (that corpus, its operators and its
report belong to the qualification repository), and their counts are never a detection rate.

An operator takes a ``Case`` (the raw bytes of each input) and returns a mutated ``Case``, or
None when its precondition is not met (counted as n_na, excluded from n_eff).
"""

from __future__ import annotations

import copy
import hashlib
import json
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from cognous_verify import wire
from cognous_verify.canon import commitment

RECORD, PROPOSAL, MANIFEST, LEDGER = "record", "proposal", "manifest", "ledger"
ROLE_OF = {
    RECORD: "run_record",
    PROPOSAL: "proposal_export",
    MANIFEST: "manifest",
    LEDGER: "destination_ledger",
}


@dataclass
class Case:
    name: str
    files: dict[str, bytes]

    def doc(self, role: str) -> Any:
        return json.loads(self.files[role].decode("utf-8"))

    def with_doc(self, role: str, doc: Any) -> Case:
        files = dict(self.files)
        files[role] = (json.dumps(doc, indent=1, ensure_ascii=False) + "\n").encode("utf-8")
        return Case(self.name, files)

    def with_bytes(self, role: str, data: bytes) -> Case:
        files = dict(self.files)
        files[role] = data
        return Case(self.name, files)


@dataclass(frozen=True)
class Operator:
    category: str
    name: str
    fn: Callable[[Case, list[Case]], Case | None]
    expected: str  # reject | accept


OPERATORS: list[Operator] = []


def op(category: str, name: str, expected: str = "reject") -> Callable[[Any], Any]:
    def deco(fn: Callable[[Case, list[Case]], Case | None]) -> Any:
        OPERATORS.append(Operator(category, name, fn, expected))
        return fn

    return deco


def _authorized(rec: dict[str, Any]) -> list[dict[str, Any]]:
    return [d for d in rec["decisions"] if d["result"] == "authorized"]


def _held(rec: dict[str, Any]) -> list[dict[str, Any]]:
    return [d for d in rec["decisions"] if d["result"] != "authorized"]


def _text(case: Case, role: str) -> str:
    return case.files[role].decode("utf-8")


# --------------------------------------------------------------------------- W: wire


@op("W1", "duplicate result member")
def w1a(case: Case, _all: list[Case]) -> Case | None:
    text = _text(case, RECORD)
    marker = '"result": "'
    i = text.find(marker)
    if i < 0:
        return None
    j = text.index('"', i + len(marker))
    other = "hold" if text[i + len(marker) : j] == "authorized" else "authorized"
    ins = f' "result": "{other}",\n  '
    return case.with_bytes(RECORD, (text[:i] + ins + text[i:]).encode())


@op("W1", "duplicate effect_id member")
def w1b(case: Case, _all: list[Case]) -> Case | None:
    text = _text(case, RECORD)
    marker = '"effect_id": "'
    i = text.find(marker)
    if i < 0:
        return None
    ins = '"effect_id": "sha256:' + "0" * 64 + '",\n  '
    return case.with_bytes(RECORD, (text[:i] + ins + text[i:]).encode())


@op("W1", "duplicate member in the proposal")
def w1c(case: Case, _all: list[Case]) -> Case | None:
    text = _text(case, PROPOSAL)
    i = text.find('"unit": ')
    return case.with_bytes(PROPOSAL, (text[:i] + '"unit": "EUR",\n ' + text[i:]).encode())


@op("W2", "NaN in the proposal amount")
def w2a(case: Case, _all: list[Case]) -> Case | None:
    text = _text(case, PROPOSAL)
    return case.with_bytes(PROPOSAL, text.replace('"amount": 50.0', '"amount": NaN').encode())


@op("W2", "Infinity in an observation policy")
def w2b(case: Case, _all: list[Case]) -> Case | None:
    text = _text(case, RECORD)
    if '"observation_max_age_seconds": 300' not in text:
        return None
    return case.with_bytes(
        RECORD,
        text.replace(
            '"observation_max_age_seconds": 300', '"observation_max_age_seconds": Infinity', 1
        ).encode(),
    )


@op("W3", "proposal amount 50.0 written as 50")
def w3a(case: Case, _all: list[Case]) -> Case | None:
    text = _text(case, PROPOSAL)
    return case.with_bytes(PROPOSAL, text.replace('"amount": 50.0', '"amount": 50').encode())


@op("W3", "ledger amount 50.0 written as 50")
def w3b(case: Case, _all: list[Case]) -> Case | None:
    text = _text(case, LEDGER)
    if '"amount": 50.0' not in text:
        return None
    return case.with_bytes(LEDGER, text.replace('"amount": 50.0', '"amount": 50').encode())


@op("W3", "binding amount 50.0 written as 50")
def w3c(case: Case, _all: list[Case]) -> Case | None:
    text = _text(case, RECORD)
    if '"amount": 50.0' not in text:
        return None
    return case.with_bytes(RECORD, text.replace('"amount": 50.0', '"amount": 50', 1).encode())


@op("W4", "lone surrogate escape")
def w4a(case: Case, _all: list[Case]) -> Case | None:
    text = _text(case, RECORD)
    return case.with_bytes(RECORD, text.replace('"run_id": "', '"run_id": "\\ud800', 1).encode())


@op("W4", "invalid UTF-8 byte")
def w4b(case: Case, _all: list[Case]) -> Case | None:
    return case.with_bytes(
        RECORD, case.files[RECORD].replace(b'"run_id": "', b'"run_id": "\xff', 1)
    )


@op("W5", "byte-order mark")
def w5a(case: Case, _all: list[Case]) -> Case | None:
    return case.with_bytes(RECORD, b"\xef\xbb\xbf" + case.files[RECORD])


@op("W5", "trailing data")
def w5b(case: Case, _all: list[Case]) -> Case | None:
    return case.with_bytes(RECORD, case.files[RECORD] + b"{}\n")


@op("W5", "nesting beyond the limit")
def w5c(case: Case, _all: list[Case]) -> Case | None:
    deep = "[" * 70 + "]" * 70
    text = _text(case, PROPOSAL).replace('"risk_metadata": {}', f'"risk_metadata": {{"k": {deep}}}')
    return case.with_bytes(PROPOSAL, text.encode())


# --------------------------------------------------------------------------- B: benign


def _reversed(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: _reversed(value[k]) for k in reversed(list(value))}
    if isinstance(value, list):
        return [_reversed(v) for v in value]
    return value


@op("B", "reverse every key order, compact", "accept")
def b1(case: Case, _all: list[Case]) -> Case | None:
    files = {
        role: json.dumps(_reversed(case.doc(role)), separators=(",", ":")).encode()
        for role in case.files
    }
    return Case(case.name, files)


@op("B", "indent 4 and escape ASCII", "accept")
def b2(case: Case, _all: list[Case]) -> Case | None:
    files = {
        role: json.dumps(case.doc(role), indent=4, ensure_ascii=True).encode()
        for role in case.files
    }
    return Case(case.name, files)


@op("B", "escape the first letter of every urn", "accept")
def b3(case: Case, _all: list[Case]) -> Case | None:
    return Case(
        case.name,
        {role: data.replace(b'"urn:', b'"\\u0075rn:') for role, data in case.files.items()},
    )


# --------------------------------------------------------------------------- S: structure


@op("S1", "undeclared member on a decision")
def s1(case: Case, _all: list[Case]) -> Case | None:
    rec = case.doc(RECORD)
    rec["decisions"][0]["surprise"] = 1
    return case.with_doc(RECORD, rec)


@op("S2", "decision result outside the closed set")
def s2(case: Case, _all: list[Case]) -> Case | None:
    rec = case.doc(RECORD)
    rec["decisions"][0]["result"] = "deny"
    return case.with_doc(RECORD, rec)


@op("S2", "attempt status outside the closed set")
def s2b(case: Case, _all: list[Case]) -> Case | None:
    rec = case.doc(RECORD)
    if not rec["attempts"]:
        return None
    rec["attempts"][0]["status"] = "safe_to_retry"
    return case.with_doc(RECORD, rec)


@op("S3", "required member removed from a decision")
def s3(case: Case, _all: list[Case]) -> Case | None:
    rec = case.doc(RECORD)
    del rec["decisions"][0]["decided_at"]
    return case.with_doc(RECORD, rec)


@op("S3", "required collection removed")
def s3b(case: Case, _all: list[Case]) -> Case | None:
    rec = case.doc(RECORD)
    del rec["closeouts"]
    return case.with_doc(RECORD, rec)


@op("S4", "extension key without x- prefix")
def s4(case: Case, _all: list[Case]) -> Case | None:
    rec = case.doc(RECORD)
    rec["decisions"][0]["extensions"] = {"bad": 1}
    return case.with_doc(RECORD, rec)


# --------------------------------------------------------------------------- I: identity


@op("I1", "effect_id substituted on the decision")
def i1(case: Case, _all: list[Case]) -> Case | None:
    rec = case.doc(RECORD)
    rec["decisions"][0]["effect_id"] = "sha256:" + "ab" * 32
    return case.with_doc(RECORD, rec)


@op("I2", "proposal target edited, binding unchanged")
def i2(case: Case, _all: list[Case]) -> Case | None:
    p = case.doc(PROPOSAL)
    p["target"] = p["target"] + "-x"
    return case.with_doc(PROPOSAL, p)


@op("I2", "proposal member removed")
def i2b(case: Case, _all: list[Case]) -> Case | None:
    p = case.doc(PROPOSAL)
    del p["evidence_refs"]
    return case.with_doc(PROPOSAL, p)


@op("I3", "horizon commits to another proposal")
def i3(case: Case, _all: list[Case]) -> Case | None:
    rec = case.doc(RECORD)
    rec["decisions"][0]["operation_horizon"]["proposal_commitment"] = "sha256:" + "cd" * 32
    return case.with_doc(RECORD, rec)


@op("I4", "manifest input record_commitment altered")
def i4(case: Case, _all: list[Case]) -> Case | None:
    rec = case.doc(RECORD)
    for x in rec["decisions"][0]["resolution_inputs"]:
        if x["input_type"] == "manifest":
            x["record_commitment"] = "sha256:" + "ef" * 32
            return case.with_doc(RECORD, rec)
    return None


@op("I5", "payload altered, payload_commitment unchanged")
def i5a(case: Case, _all: list[Case]) -> Case | None:
    p = case.doc(PROPOSAL)
    p["payload"]["refund_reason"] = "fraud"
    return case.with_doc(PROPOSAL, p)


@op("I5", "manifest altered, manifest_digest unchanged")
def i5b(case: Case, _all: list[Case]) -> Case | None:
    m = case.doc(MANIFEST)
    m["x_note"] = "edited"
    return case.with_doc(MANIFEST, m)


@op("I5", "binding payload_commitment altered")
def i5c(case: Case, _all: list[Case]) -> Case | None:
    rec = case.doc(RECORD)
    a = _authorized(rec)
    if not a:
        return None
    a[0]["binding"]["payload_commitment"] = "sha256:" + "12" * 32
    return case.with_doc(RECORD, rec)


# --------------------------------------------------------------------------- D: decisions


@op("D1", "held decision flipped to authorized")
def d1(case: Case, _all: list[Case]) -> Case | None:
    rec = case.doc(RECORD)
    h = _held(rec)
    if not h:
        return None
    h[0]["result"] = "authorized"
    return case.with_doc(RECORD, rec)


@op("D1", "authorized decision given a reason")
def d1b(case: Case, _all: list[Case]) -> Case | None:
    rec = case.doc(RECORD)
    a = _authorized(rec)
    if not a:
        return None
    a[0]["reasons"] = ["grant_not_active"]
    return case.with_doc(RECORD, rec)


@op("D2", "authorized decision with its binding stripped")
def d2(case: Case, _all: list[Case]) -> Case | None:
    rec = case.doc(RECORD)
    a = _authorized(rec)
    if not a:
        return None
    a[0]["binding"] = None
    return case.with_doc(RECORD, rec)


@op("D2", "held decision given a binding")
def d2b(case: Case, _all: list[Case]) -> Case | None:
    rec = case.doc(RECORD)
    h = _held(rec)
    if not h:
        return None
    h[0]["binding"] = {"proposal_commitment": "sha256:" + "00" * 32}
    return case.with_doc(RECORD, rec)


@op("D3", "grant input contradicts its expectation under an authorized decision")
def d3(case: Case, _all: list[Case]) -> Case | None:
    rec = case.doc(RECORD)
    for d in _authorized(rec):
        for x in d["resolution_inputs"]:
            if x["input_type"] == "grant" and "status" in x["expected"]:
                x["observed"]["status"] = "suspended"
                return case.with_doc(RECORD, rec)
    return None


@op("D4", "reason code outside the registry")
def d4(case: Case, _all: list[Case]) -> Case | None:
    rec = case.doc(RECORD)
    h = _held(rec)
    if not h:
        return None
    h[0]["reasons"] = ["made_up_reason"]
    return case.with_doc(RECORD, rec)


@op("D4", "vocabulary version removed in journal mode")
def d4b(case: Case, _all: list[Case]) -> Case | None:
    rec = case.doc(RECORD)
    if "reason_vocabulary_version" not in rec["decisions"][0]:
        return None
    del rec["decisions"][0]["reason_vocabulary_version"]
    return case.with_doc(RECORD, rec)


@op("D5", "grant observed revoked under an authorized decision")
def d5(case: Case, _all: list[Case]) -> Case | None:
    rec = case.doc(RECORD)
    for d in _authorized(rec):
        for x in d["resolution_inputs"]:
            if x["input_type"] == "grant":
                x["observed"]["status"] = "revoked"
                return case.with_doc(RECORD, rec)
    return None


@op("D5", "grant_revoked stated without the operand")
def d5b(case: Case, _all: list[Case]) -> Case | None:
    rec = case.doc(RECORD)
    h = _held(rec)
    if not h:
        return None
    h[0]["reasons"] = ["grant_revoked"]
    for x in h[0]["resolution_inputs"]:
        if x["input_type"] == "grant":
            x["observed"]["status"] = "active"
    return case.with_doc(RECORD, rec)


# --------------------------------------------------------------------------- J: journal


@op("J1", "journal opening dropped")
def j1a(case: Case, _all: list[Case]) -> Case | None:
    rec = case.doc(RECORD)
    ev = rec.get("check_events")
    if not ev:
        return None
    rec["check_events"] = [e for e in ev if e["phase"] != "opened"][:]
    return case.with_doc(RECORD, rec)


@op("J1", "journal opening duplicated")
def j1b(case: Case, _all: list[Case]) -> Case | None:
    rec = case.doc(RECORD)
    ev = rec.get("check_events")
    if not ev:
        return None
    ev.insert(1, copy.deepcopy(ev[0]))
    return case.with_doc(RECORD, rec)


@op("J2", "completed check matches no resolution check")
def j2a(case: Case, _all: list[Case]) -> Case | None:
    rec = case.doc(RECORD)
    if not rec.get("check_events") or not rec["resolution_checks"]:
        return None
    rec["resolution_checks"][0]["inputs"][0]["input_id"] = "urn:other"
    return case.with_doc(RECORD, rec)


@op("J2", "sequential resolution checks reordered")
def j2b(case: Case, _all: list[Case]) -> Case | None:
    rec = case.doc(RECORD)
    if not rec.get("check_events") or len(rec["resolution_checks"]) < 2:
        return None
    rec["resolution_checks"].reverse()
    return case.with_doc(RECORD, rec)


@op("J3", "interrupted or opened-only check rewritten as completed")
def j3(case: Case, _all: list[Case]) -> Case | None:
    rec = case.doc(RECORD)
    ev = rec.get("check_events") or []
    if not any(e["phase"] == "interrupted" for e in ev):
        return None
    for e in ev:
        if e["phase"] == "interrupted":
            e["phase"] = "completed"
    return case.with_doc(RECORD, rec)


# --------------------------------------------------------------------------- T: time


@op("T1", "decided_at without a UTC offset")
def t1a(case: Case, _all: list[Case]) -> Case | None:
    rec = case.doc(RECORD)
    rec["decisions"][0]["decided_at"] = "2026-10-05T19:00:00"
    return case.with_doc(RECORD, rec)


@op("T1", "accepted observation from the future")
def t1b(case: Case, _all: list[Case]) -> Case | None:
    rec = case.doc(RECORD)
    for r in rec["reconciliations"]:
        if r["observation_accepted"] is True and r["observation"]:
            r["observation"]["observed_at"] = "2026-10-06T19:00:00+00:00"
            return case.with_doc(RECORD, rec)
    return None


@op("T1", "accepted observation stale")
def t1c(case: Case, _all: list[Case]) -> Case | None:
    rec = case.doc(RECORD)
    for r in rec["reconciliations"]:
        if r["observation_accepted"] is True and r["observation"]:
            r["observation"]["observed_at"] = "2026-10-05T10:00:00+00:00"
            return case.with_doc(RECORD, rec)
    return None


# --------------------------------------------------------------------------- A: attempts


@op("A1", "attempt start record dropped")
def a1a(case: Case, _all: list[Case]) -> Case | None:
    rec = case.doc(RECORD)
    if len(rec["attempts"]) < 2:
        return None
    del rec["attempts"][0]
    return case.with_doc(RECORD, rec)


@op("A1", "second attempt lifecycle for one effect")
def a1b(case: Case, _all: list[Case]) -> Case | None:
    rec = case.doc(RECORD)
    if not rec["attempts"]:
        return None
    extra = copy.deepcopy(rec["attempts"])
    for row in extra:
        row["attempt_id"] = "attempt-second"
    rec["attempts"].extend(extra)
    return case.with_doc(RECORD, rec)


@op("A1", "attempt on a held decision")
def a1c(case: Case, _all: list[Case]) -> Case | None:
    rec = case.doc(RECORD)
    h = _held(rec)
    if not h:
        return None
    rec["attempts"].append(
        {
            "attempt_id": "attempt-x",
            "effect_id": h[0]["effect_id"],
            "decision_id": h[0]["decision_id"],
            "started_at": "2026-10-05T19:00:00+00:00",
            "time_source": "test_override",
            "status": "attempted",
            "acknowledgement": {},
            "error": None,
        }
    )
    return case.with_doc(RECORD, rec)


@op("A2", "closeout dropped")
def a2a(case: Case, _all: list[Case]) -> Case | None:
    rec = case.doc(RECORD)
    if not rec["closeouts"]:
        return None
    rec["closeouts"] = []
    return case.with_doc(RECORD, rec)


@op("A2", "closeout names no accepted observation")
def a2b(case: Case, _all: list[Case]) -> Case | None:
    rec = case.doc(RECORD)
    if not rec["closeouts"]:
        return None
    rec["closeouts"][0]["observed_at"] = "2026-10-05T19:00:01+00:00"
    return case.with_doc(RECORD, rec)


# --------------------------------------------------------------------------- R: receipts


def _ledger_row(led: dict[str, Any]) -> dict[str, Any] | None:
    for row in led["effects"].values():
        return row  # type: ignore[no-any-return]
    return None


@op("R1", "ledger effect with no decision")
def r1(case: Case, _all: list[Case]) -> Case | None:
    led = case.doc(LEDGER)
    row = _ledger_row(led)
    base = (
        copy.deepcopy(row)
        if row
        else {
            "amount": 50.0,
            "grant_id": "urn:grant:x",
            "payload": {},
            "state": "applied",
            "target": "urn:t",
            "unit": "USD",
        }
    )
    base["effect_id"] = "sha256:" + "77" * 32
    led["effects"][base["effect_id"]] = base
    g = base["grant_id"]
    led["grant_effect_counts"][g] = led["grant_effect_counts"].get(g, 0) + 1
    return case.with_doc(LEDGER, led)


@op("R2", "ledger effect whose decision is held")
def r2(case: Case, _all: list[Case]) -> Case | None:
    rec = case.doc(RECORD)
    h = _held(rec)
    if not h:
        return None
    led = case.doc(LEDGER)
    row = {
        "effect_id": h[0]["effect_id"],
        "grant_id": "urn:grant:x",
        "target": "urn:t",
        "amount": 50.0,
        "unit": "USD",
        "payload": {},
        "state": "applied",
    }
    led["effects"][row["effect_id"]] = row
    led["grant_effect_counts"]["urn:grant:x"] = led["grant_effect_counts"].get("urn:grant:x", 0) + 1
    return case.with_doc(LEDGER, led)


@op("R3", "ledger amount differs from the binding")
def r3a(case: Case, _all: list[Case]) -> Case | None:
    led = case.doc(LEDGER)
    row = _ledger_row(led)
    if row is None:
        return None
    row["amount"] = 5000.0
    return case.with_doc(LEDGER, led)


@op("R3", "ledger target differs from the binding")
def r3b(case: Case, _all: list[Case]) -> Case | None:
    led = case.doc(LEDGER)
    row = _ledger_row(led)
    if row is None:
        return None
    row["target"] = "urn:other"
    return case.with_doc(LEDGER, led)


@op("R3", "ledger payload differs from the binding")
def r3c(case: Case, _all: list[Case]) -> Case | None:
    led = case.doc(LEDGER)
    row = _ledger_row(led)
    if row is None:
        return None
    row["payload"] = {"customer_id": "someone-else"}
    return case.with_doc(LEDGER, led)


@op("R4", "grant effect count tampered")
def r4a(case: Case, _all: list[Case]) -> Case | None:
    led = case.doc(LEDGER)
    if not led["grant_effect_counts"]:
        return None
    key = next(iter(led["grant_effect_counts"]))
    led["grant_effect_counts"][key] += 1
    return case.with_doc(LEDGER, led)


@op("R5", "ledger row removed after an acknowledged attempt")
def r5(case: Case, _all: list[Case]) -> Case | None:
    rec = case.doc(RECORD)
    if not any(a["status"] in {"acknowledged", "partial"} for a in rec["attempts"]):
        return None
    led = case.doc(LEDGER)
    row = _ledger_row(led)
    if row is None:
        return None
    del led["effects"][row["effect_id"]]
    led["grant_effect_counts"][row["grant_id"]] -= 1
    if led["grant_effect_counts"][row["grant_id"]] == 0:
        del led["grant_effect_counts"][row["grant_id"]]
    return case.with_doc(LEDGER, led)


@op("R6", "ledger tail truncated", expected="accept")
def r6(case: Case, _all: list[Case]) -> Case | None:
    rec = case.doc(RECORD)
    led = case.doc(LEDGER)
    row = _ledger_row(led)
    if row is None:
        return None
    # only a tail the record never acknowledged or observed is undetectable by design
    if any(a["status"] in {"acknowledged", "partial"} for a in rec["attempts"]):
        return None
    if any(
        r["observation"] and r["observation"]["state"] != "absent" for r in rec["reconciliations"]
    ):
        return None
    del led["effects"][row["effect_id"]]
    led["grant_effect_counts"][row["grant_id"]] -= 1
    if led["grant_effect_counts"][row["grant_id"]] == 0:
        del led["grant_effect_counts"][row["grant_id"]]
    return case.with_doc(LEDGER, led)


# --------------------------------------------------------------------------- X: transplant


@op("X1", "proposal export taken from another run")
def x1a(case: Case, others: list[Case]) -> Case | None:
    for other in others:
        if other.name != case.name and other.doc(PROPOSAL) != case.doc(PROPOSAL):
            return case.with_bytes(PROPOSAL, other.files[PROPOSAL])
    return None


@op("X1", "ledger taken from another run")
def x1b(case: Case, others: list[Case]) -> Case | None:
    for other in others:
        if other.name != case.name and other.doc(LEDGER) != case.doc(LEDGER):
            return case.with_bytes(LEDGER, other.files[LEDGER])
    return None


# --------------------------------------------------------------------------- F: forgery bound


@op("F", "amount changed and every affected commitment recomputed", expected="accept")
def f1(case: Case, _all: list[Case]) -> Case | None:
    proposal = case.doc(PROPOSAL)
    rec = case.doc(RECORD)
    old_pc = commitment(proposal)
    new = copy.deepcopy(proposal)
    new["amount"] = 75.0
    new_pc = commitment(new)
    replacements: dict[str, str] = {old_pc: new_pc}
    for d in rec["decisions"]:
        b = d["binding"]
        old_eid = d["effect_id"]
        new_eid = commitment(
            {
                "proposal": new_pc,
                "grant_id": b["grant_id"] if b else None,
                "grant_revision": b["grant_revision"] if b else None,
            }
        )
        replacements[old_eid] = new_eid
    files = {role: data.decode("utf-8") for role, data in case.files.items()}
    for role in (RECORD, LEDGER):
        for old, newv in replacements.items():
            files[role] = files[role].replace(old, newv)
    files[RECORD] = files[RECORD].replace('"amount": 50.0', '"amount": 75.0')
    files[LEDGER] = files[LEDGER].replace('"amount": 50.0', '"amount": 75.0')
    out = Case(case.name, {role: text.encode("utf-8") for role, text in files.items()})
    return out.with_doc(PROPOSAL, new)


def digest(case: Case) -> str:
    h = hashlib.sha256()
    for role in sorted(case.files):
        h.update(role.encode())
        h.update(case.files[role])
    return h.hexdigest()


def wire_clean(case: Case) -> bool:
    """True when every input of the mutant still parses under the strict parser."""
    try:
        for data in case.files.values():
            wire.parse(data)
    except wire.WireError:
        return False
    return True


# --------------------------------------------------------------------------- running


def load_corpus() -> list[Case]:
    from .helpers import REAL_RUNS

    cases = []
    for d in sorted(p for p in REAL_RUNS.iterdir() if p.is_dir()):
        cases.append(
            Case(
                d.name,
                {
                    RECORD: (d / "bounded-run-record.json").read_bytes(),
                    PROPOSAL: (d / "proposal.json").read_bytes(),
                    MANIFEST: (d / "manifest.json").read_bytes(),
                    LEDGER: (d / "destination.json").read_bytes(),
                },
            )
        )
    return cases


def evaluate_case(case: Case) -> Any:
    from cognous_verify import engine

    files = [
        engine.InputFile(ROLE_OF[role], role + ".json", data)
        for role, data in sorted(case.files.items())
    ]
    return engine.evaluate(files)


def refuting_codes(ev: Any) -> set[str]:
    return {f.code for r in ev.results if r.verdict == "refuted" for f in r.findings}


# Cases the verifier is known not to refuse, each undetectable by design from the inputs given.
# (Empty: the two donor-ledger cases that were listed here, a row for an effect the effect-time
# check refused and a row for an effect whose attempt ended in a definitive failure, are refused
# by v4.ledger.rows-agree-with-attempts.)
KNOWN_MISSES: dict[tuple[str, str], str] = {}


@dataclass
class Tally:
    n_eff: int = 0
    caught_or_accepted: int = 0
    missed: int = 0
    n_na: int = 0


def run_all() -> tuple[dict[str, Tally], list[tuple[str, str, str]], list[str]]:
    """Apply every operator to every clean run.

    Returns the per-category tally, the list of (operator, case, expected) mismatches and the
    names of clean runs that were not accepted.
    """
    cases = load_corpus()
    clean_bad = [c.name for c in cases if evaluate_case(c).overall != "accept"]
    table: dict[str, Tally] = {}
    mismatches: list[tuple[str, str, str]] = []
    for o in OPERATORS:
        t = table.setdefault(o.category, Tally())
        for c in cases:
            mutant = o.fn(c, cases)
            if mutant is None:
                t.n_na += 1
                continue
            t.n_eff += 1
            rejected = evaluate_case(mutant).overall == "reject"
            if rejected == (o.expected == "reject"):
                t.caught_or_accepted += 1
            else:
                t.missed += 1
                mismatches.append((o.name, c.name, o.expected))
    return table, mismatches, clean_bad

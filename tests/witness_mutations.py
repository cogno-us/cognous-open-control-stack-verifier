"""Deterministic damage to a record document and to a witness chain, shared by the tests and the
capture tool (which replays the same descriptors through the control plane's own verifier).

A descriptor is a small JSON-able list, so a case can be stored and rebuilt. Nothing here is
verifier code: it only builds inputs.
"""

from __future__ import annotations

import copy
from collections.abc import Callable
from typing import Any

RECORD_OPS = ("drop_last", "rewrite_first", "append_copy", "swap_first_two", "empty", "remove")
WITNESS_OPS = (
    "head",
    "head_resign",
    "count_up_resign",
    "count_down_resign",
    "run_id_resign",
    "sequence_resign",
    "previous_digest",
    "previous_digest_resign",
    "drop_first",
    "swap",
    "duplicate_last",
    "digest_only",
)

Resign = Callable[[dict[str, Any]], str]


def ledger_names(doc: dict[str, Any]) -> list[str]:
    return sorted(k for k, v in doc.items() if isinstance(v, list) and v)


def apply_record_op(doc: dict[str, Any], op: str, ledger: str) -> dict[str, Any] | None:
    """The record document with one ledger damaged; None when the damage does not apply."""
    out = copy.deepcopy(doc)
    rows = out[ledger]
    if op == "drop_last":
        rows.pop()
    elif op == "rewrite_first":
        first = rows[0]
        if isinstance(first, dict):
            first["x-rewritten"] = 1
        else:
            rows[0] = [first, 1]
    elif op == "append_copy":
        rows.append(copy.deepcopy(rows[-1]))
    elif op == "swap_first_two":
        if len(rows) < 2 or rows[0] == rows[1]:
            return None
        rows[0], rows[1] = rows[1], rows[0]
    elif op == "empty":
        out[ledger] = []
    elif op == "remove":
        del out[ledger]
    else:
        raise ValueError(op)
    return out


def apply_witness_op(
    recs: list[dict[str, Any]], op: str, resign: Resign
) -> list[dict[str, Any]] | None:
    """The witness record list with its last record (or its order) damaged; None if inapplicable."""
    out = copy.deepcopy(recs)
    last = out[-1]
    name = sorted(last["ledgers"])[0] if last["ledgers"] else None
    fresh = False
    if op in ("head", "head_resign"):
        if name is None:
            return None
        h = last["ledgers"][name]["head"]
        last["ledgers"][name]["head"] = h[:-1] + ("0" if h[-1] != "0" else "1")
        fresh = op == "head_resign"
    elif op == "count_up_resign":
        if name is None:
            return None
        last["ledgers"][name]["count"] += 1
        fresh = True
    elif op == "count_down_resign":
        if name is None:
            return None
        last["ledgers"][name]["count"] -= 1
        fresh = True
    elif op == "run_id_resign":
        last["run_id"] = last["run_id"] + "-other"
        fresh = True
    elif op == "sequence_resign":
        last["sequence"] += 5
        fresh = True
    elif op in ("previous_digest", "previous_digest_resign"):
        last["previous_digest"] = "sha256:" + "1" * 64
        fresh = op == "previous_digest_resign"
    elif op == "drop_first":
        if len(out) < 2:
            return None
        out.pop(0)
    elif op == "swap":
        if len(out) < 2:
            return None
        out[0], out[1] = out[1], out[0]
    elif op == "duplicate_last":
        out.append(copy.deepcopy(last))
    elif op == "digest_only":
        last["digest"] = "sha256:" + "2" * 64
    else:
        raise ValueError(op)
    if fresh:
        last["digest"] = resign(last)
    return out

"""Cases the verifier accepts or refuses on purpose, each stated with its reason.

These came out of the held-out mutation report (qualification PR #103): detection rates that
looked like gaps and are not, or are only partly. Each test pins the behaviour so a later change
that moves it has to say why. None of them is a detection measurement.
"""

from __future__ import annotations

import copy
from typing import Any

import pytest

from cognous_verify import engine, ledger, wire
from cognous_verify.canon import canonical_bytes
from cognous_verify.results import REFUTED

from .helpers import REAL_RUNS, load

RUN = "journal-applied"


def _text(role_file: str, run: str = RUN) -> str:
    return (REAL_RUNS / run / role_file).read_text(encoding="utf-8")


def _evaluate(run: str = RUN, **replace: str) -> engine.Evaluation:
    names = {
        "run_record": "bounded-run-record.json",
        "proposal_export": "proposal.json",
        "manifest": "manifest.json",
        "destination_ledger": "destination.json",
    }
    files = []
    for role, name in names.items():
        text = replace.get(role) or _text(name, run)
        files.append(engine.InputFile(role, name, text.encode("utf-8")))
    return engine.evaluate(files)


def _refuted(ev: engine.Evaluation) -> set[str]:
    return {f.code for r in ev.results if r.verdict == REFUTED for f in r.findings}


def test_the_clean_run_is_accepted() -> None:
    assert _evaluate().overall == "accept"


# W3: number-form drift ---------------------------------------------------------------------


@pytest.mark.parametrize("form", ["50.00", "5e1", "50.0e0", "500e-1"])
@pytest.mark.parametrize(
    "role,name",
    [
        ("proposal_export", "proposal.json"),
        ("run_record", "bounded-run-record.json"),
        ("destination_ledger", "destination.json"),
    ],
)
def test_float_forms_that_the_pinned_profile_writes_alike_are_accepted(
    form: str, role: str, name: str
) -> None:
    """``50.0``, ``50.00`` and ``5e1`` are one float under the pinned profile (Python semantics:
    canonical text is ``repr``, ``50.0``), so every commitment is unchanged. The profile defines
    them equal; there is no damage to refuse, and the verifier does not invent a stricter
    profile than the pinned one."""
    text = _text(name).replace('"amount": 50.0', f'"amount": {form}')
    assert text != _text(name)
    assert canonical_bytes(wire.parse(text.encode())) == canonical_bytes(
        wire.parse(_text(name).encode())
    )
    assert _evaluate(**{role: text}).overall == "accept"


@pytest.mark.parametrize(
    "role,name",
    [
        ("proposal_export", "proposal.json"),
        ("run_record", "bounded-run-record.json"),
        ("destination_ledger", "destination.json"),
    ],
)
def test_an_integer_where_the_float_was_written_is_refused(role: str, name: str) -> None:
    """``50`` is an int, whose canonical text differs from ``50.0``: that is a real change."""
    text = _text(name).replace('"amount": 50.0', '"amount": 50')
    assert _evaluate(**{role: text}).overall == "reject"


# R6: ledger tail dropped -------------------------------------------------------------------


def _lost_ack() -> tuple[Any, Any]:
    run = "journal-lost-ack"
    return load(REAL_RUNS / run / "bounded-run-record.json"), load(
        REAL_RUNS / run / "destination.json"
    )


def _without_rows(led: Any) -> Any:
    led = copy.deepcopy(led)
    led["effects"] = {}
    led["grant_effect_counts"] = {}
    return led


def test_dropped_row_is_refused_when_the_record_holds_the_destination_observation() -> None:
    """The design expected R6 (truncated ledger tail) to be accepted. Here it is refused, and
    correctly: the lost-acknowledgement run holds an accepted `applied` observation of the
    destination, so the record itself says the row exists and the snapshot lacks it. The
    mismatch is real, not a false alarm."""
    record, led = _lost_ack()
    results = {r.check_id: r for r in ledger.run(record, _without_rows(led))}
    assert results["v4.ledger.observations-agree"].verdict == REFUTED
    assert {f.code for f in results["v4.ledger.observations-agree"].findings} == {
        "observation_without_ledger_row"
    }


def test_dropped_row_is_accepted_when_nothing_in_the_record_corroborates_it() -> None:
    """The forgery bound R6 states: with an unknown attempt and no accepted observation of the
    effect, the record does not say a row exists, and the ledger has no sequence or chain, so a
    dropped row cannot be seen. (V4 level: the other record checks are not claimed here.)"""
    record, led = _lost_ack()
    record = copy.deepcopy(record)
    record["reconciliations"] = [r for r in record["reconciliations"] if r["result"] != "applied"]
    results = ledger.run(record, _without_rows(led))
    assert [r.check_id for r in results if r.verdict == REFUTED] == []


# X1: a donor ledger with the same content ----------------------------------------------------


def test_a_donor_ledger_with_identical_content_is_not_damage() -> None:
    """Two runs of the same synthetic proposal share an effect id and produce the same ledger
    row. A ledger "taken from another run" that is content-identical to this run's own is the
    same document in other bytes; nothing in it can differ from what the record expects."""
    own = _text("destination.json")
    donor = canonical_bytes(wire.parse(own.encode())).decode("utf-8")
    assert donor != own
    assert _evaluate(destination_ledger=donor).overall == "accept"

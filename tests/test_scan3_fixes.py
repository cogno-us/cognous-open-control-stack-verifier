"""Review scan 3: emptied decisions, a skipped bindings check and a non-boolean ``duplicate``."""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest

from cognous_verify import cli, engine, ledger, rules_lifecycle

from .helpers import REAL_RUNS

NAMES = {
    "run_record": "bounded-run-record.json",
    "proposal_export": "proposal.json",
    "manifest": "manifest.json",
    "destination_ledger": "destination.json",
}


def _docs(scenario: str) -> dict[str, Any]:
    return {r: json.loads((REAL_RUNS / scenario / n).read_text()) for r, n in NAMES.items()}


def _eval(docs: dict[str, Any], roles: tuple[str, ...] = tuple(NAMES)) -> engine.Evaluation:
    return engine.evaluate(
        [engine.InputFile(r, NAMES[r], json.dumps(docs[r]).encode()) for r in roles]
    )


@pytest.mark.parametrize("scenario", ["default-held-revoked", "journal-held"])
def test_emptied_decisions_with_supplied_inputs_never_accept(scenario: str) -> None:
    docs = _docs(scenario)
    assert _eval(docs).overall == "accept"
    docs["run_record"]["decisions"] = []
    ev = _eval(docs)
    assert ev.overall == "abstain"
    skipped = {c.check_id: c.reason for c in ev.checks if c.verdict == "could_not_check"}
    for cid in (
        "v2.decisions.reason-registry",
        "v2.identity.proposal-commitment",
        "v2.identity.effect-id",
        "v4.ledger.counts",
    ):
        assert skipped[cid] == engine.NO_DECISIONS_FOR_SUPPLIED_INPUTS
    assert engine.NO_DECISIONS_FOR_SUPPLIED_INPUTS not in engine.NOT_APPLICABLE_REASONS
    assert not any(
        n["check_id"].startswith(("v2.identity", "v4.ledger")) for n in ev.not_applicable
    )


def test_emptied_decisions_with_only_a_ledger_does_not_accept() -> None:
    docs = _docs("journal-held")
    docs["run_record"]["decisions"] = []
    assert _eval(docs, ("run_record", "destination_ledger")).overall == "abstain"


def test_emptied_decisions_cli_exit_is_abstain(tmp_path: Path) -> None:
    src = REAL_RUNS / "journal-held"
    for n in ("proposal.json", "manifest.json", "destination.json"):
        (tmp_path / n).write_bytes((src / n).read_bytes())
    rec = json.loads((src / "bounded-run-record.json").read_text())
    rec["decisions"] = []
    (tmp_path / "bounded-run-record.json").write_text(json.dumps(rec))
    argv = [
        str(tmp_path / "bounded-run-record.json"),
        "--proposal", str(tmp_path / "proposal.json"),
        "--manifest", str(tmp_path / "manifest.json"),
        "--ledger", str(tmp_path / "destination.json"),
    ]  # fmt: skip
    assert cli.main(argv) == cli.EXIT_ABSTAIN


def test_no_decisions_and_nothing_supplied_is_unchanged() -> None:
    docs = _docs("journal-held")
    docs["run_record"]["decisions"] = []
    ev = _eval(docs, ("run_record",))
    assert not any(c.reason == engine.NO_DECISIONS_FOR_SUPPLIED_INPUTS for c in ev.checks)
    assert any(n["reason"] == "no_items_in_record" for n in ev.not_applicable)


def test_journal_bindings_beyond_the_limit_is_could_not_check(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    doc = json.loads((REAL_RUNS / "journal-applied" / "bounded-run-record.json").read_text())
    monkeypatch.setattr(rules_lifecycle, "JOURNAL_COMPLETION_LIMIT", 0)
    ev = engine.evaluate([engine.InputFile("run_record", "r.json", json.dumps(doc).encode())])
    by_id = {c.check_id: c for c in ev.checks}
    assert by_id["v2.journal.check_bindings"].verdict == "could_not_check"
    assert "input_exceeds_limit" in (by_id["v2.journal.check_bindings"].reason or "")


@pytest.mark.parametrize("value", [0, None, "false", [], {}, False])
def test_non_boolean_duplicate_counts_as_fresh(value: Any) -> None:
    assert ledger.is_fresh_acknowledgement({"duplicate": value}) is True


@pytest.mark.parametrize("ack", [{"duplicate": True}, {}, {"newly_executed": False}])
def test_true_duplicate_or_no_claim_is_not_fresh(ack: dict[str, Any]) -> None:
    assert ledger.is_fresh_acknowledgement(ack) is False


@pytest.mark.parametrize("value", [0, None, "false"])
def test_excess_duplicate_effects_counts_non_boolean_duplicate(value: Any) -> None:
    docs = _docs("default-applied")
    attempts = docs["run_record"]["attempts"]
    twin = copy.deepcopy(attempts)
    for row in twin:
        row["attempt_id"] = "11111111-1111-4111-8111-111111111111"
        if row["status"] == "acknowledged":
            row["acknowledgement"]["duplicate"] = value
    attempts[1]["acknowledgement"]["duplicate"] = value
    attempts.extend(twin)
    ev = _eval(docs)
    assert ev.counters is not None and ev.counters["excess_duplicate_effects"] == 1
    assert ev.overall == "reject"

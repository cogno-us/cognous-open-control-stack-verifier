"""Review scan 6, F2: a null operation_horizon on an authorized decision must not skip the
binding of the proposal's not_before / expires_at (v2.identity.horizon-times)."""

from __future__ import annotations

import copy
import json
from typing import Any

import pytest

from cognous_verify import identity
from cognous_verify.canon import commitment

from .helpers import REAL_RUNS, load, real_record, real_run_names

RUN = "journal-reconciled-existing"
TIMES = {"not_before": "2026-10-05T18:00:00+00:00", "expires_at": "2026-10-06T18:00:00+00:00"}


def _with_times(times: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    """The fixture re-derived around a proposal that carries ``times``: proposal commitment and
    effect_id recomputed and substituted through the record, horizon times stated to match."""
    record = real_record(RUN)
    proposal = copy.deepcopy(load(REAL_RUNS / RUN / "proposal.json"))
    old_commit, old_effect = commitment(proposal), record["decisions"][0]["effect_id"]
    proposal.update(times)
    new_commit = commitment(proposal)
    b = record["decisions"][0]["binding"]
    new_effect = commitment(
        {"proposal": new_commit, "grant_id": b["grant_id"], "grant_revision": b["grant_revision"]}
    )
    text = json.dumps(record).replace(old_commit, new_commit).replace(old_effect, new_effect)
    record = json.loads(text)
    record["decisions"][0]["operation_horizon"].update(times)
    return record, proposal


def _horizon(record: dict[str, Any], proposal: dict[str, Any]) -> Any:
    out = identity.run(record, [proposal], None)
    return next(r for r in out if r.check_id == "v2.identity.horizon-times")


def test_rederived_record_with_matching_times_is_accepted() -> None:
    record, proposal = _with_times(TIMES)
    assert _horizon(record, proposal).verdict == "confirmed"
    others = [r for r in identity.run(record, [proposal], None) if r.verdict == "refuted"]
    assert others == []


@pytest.mark.parametrize(
    "times", [TIMES, {"not_before": TIMES["not_before"]}, {"expires_at": TIMES["expires_at"]}]
)
def test_null_operation_horizon_is_refuted_when_proposal_has_times(times: dict[str, Any]) -> None:
    record, proposal = _with_times(times)
    record["decisions"][0]["operation_horizon"] = None
    res = _horizon(record, proposal)
    assert res.verdict == "refuted"
    assert {f.code for f in res.findings} == {"horizon_times_mismatch"}
    assert len(res.findings) == len(times)


def test_member_nulling_is_still_refuted() -> None:
    record, proposal = _with_times(TIMES)
    record["decisions"][0]["operation_horizon"]["expires_at"] = None
    assert _horizon(record, proposal).verdict == "refuted"


@pytest.mark.parametrize("name", real_run_names())
def test_legitimate_runs_stay_accepted(name: str) -> None:
    proposal_path = REAL_RUNS / name / "proposal.json"
    if not proposal_path.exists():
        pytest.skip("no proposal export")
    res = _horizon(real_record(name), load(proposal_path))
    assert res.verdict != "refuted", res.findings


def test_a_decision_without_binding_and_null_horizon_is_not_refuted() -> None:
    record, proposal = _with_times(TIMES)
    d = record["decisions"][0]
    d["operation_horizon"] = None
    d["binding"] = None
    # Unpaired (no key left to pair on): the horizon rule has nothing to check.
    assert _horizon(record, proposal).verdict != "refuted"

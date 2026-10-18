"""Opt-in profile semantics re-derived from the record (``cognous_verify.sidecar``).

Four kinds of evidence, kept apart:

* the ODES sidecar fixtures (operation-identity, rule-revision, freshness-clocks; ODES 296e6bce,
  vendored with digests) run through the ODES validator and through this verifier's own checks;
* the control plane's own functions, run over generated inputs (``cp-differential.json``);
* negative tests: a valid profile-on record from a real run, tampered only in a sidecar member,
  is accepted by every earlier rule and now refused with a stable code;
* positive tests: every untampered valid profile record is accepted by the new checks.
"""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from cognous_verify import documents, sidecar
from cognous_verify.results import CheckResult

from .helpers import DATA, FIXTURES, errors, fixture_paths, load, refuted_codes, verify

CONTRACTS = ("operation-identity", "rule-revision", "freshness-clocks")
REVISION = "0663d5a2"


def _oracle(name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        f"odes_{name.replace('-', '_')}_oracle", DATA / name / "validate.py"
    )
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


ORACLES = {name: _oracle(name) for name in CONTRACTS}


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


@pytest.mark.parametrize("contract", CONTRACTS)
def test_vendored_oracle_is_unedited(contract: str) -> None:
    oracle_dir, fixture_dir = DATA / contract, FIXTURES / contract
    src = json.loads((oracle_dir / "SOURCE.json").read_text())
    assert src["revision"] == REVISION
    assert src["contract_version"] == "0.1.0-draft"
    for name, digest in src["sha256"].items():
        assert _sha(oracle_dir / name) == digest
    on_disk = {
        str(p.relative_to(fixture_dir)): _sha(p) for p in sorted(fixture_dir.glob("*/*.json"))
    }
    assert on_disk == src["fixtures_sha256"]


def test_fixture_counts() -> None:
    counts = {
        c: (len(fixture_paths(c, "valid")), len(fixture_paths(c, "invalid"))) for c in CONTRACTS
    }
    assert counts == {
        # ODES 0663d5a2: 3 or 4 input-hardening fixtures (#93) and `time-seven-fraction-digits`
        # (#96) added to each; freshness-clocks also holds two at-the-deadline fixtures
        "operation-identity": (12, 66),
        "rule-revision": (15, 81),
        "freshness-clocks": (20, 97),
    }


# ----------------------------------------------------------------------------- the ODES sidecars


def _record(contract: str, fixture: dict[str, Any]) -> dict[str, Any]:
    """The raw record a sidecar fixture stands for: the journal members it carries plus the
    profile's own lists, which a raw record holds at top level."""
    doc = copy.deepcopy(fixture["document"])
    rec: dict[str, Any] = copy.deepcopy(fixture.get("journal") or {})
    rec["run_id"] = doc["run_id"]
    if contract == "operation-identity":
        for name in sidecar.OPERATION_LISTS:
            rec[name] = doc[name]
    elif contract == "rule-revision":
        for name in sidecar.RULE_LISTS:
            rec[name] = doc[name]
        # the sidecar's identity rows are the rule_identity members of decision and refusal rows
        sections = {"decision": ("decisions", "decision_id"), "refusal": ("refusals", "refusal_id")}
        for row in doc["identity_rows"]:
            section, key = sections[row["row_type"]]
            rows = rec.setdefault(section, [])
            target = next((r for r in rows if r.get(key) == row["row_id"]), None)
            if target is None:
                stamp = "decided_at" if section == "decisions" else "recorded_at"
                target = {key: row["row_id"], stamp: row["recorded_at"]}
                rows.append(target)
            target["rule_identity"] = row["rule_identity"]
    else:
        rec["check_events"] = doc["check_events"]
        for name in sidecar.FRESHNESS_ROW_LISTS:
            rec[name] = doc[name]
    return rec


def _findings(contract: str, rec: dict[str, Any], *, journal: bool) -> list[Any]:
    """The sidecar fixtures without a ``journal`` member exercise the document rules only (the
    ODES validator skips its journal-context rules then); a raw record always has both, so for
    those fixtures only the document-level groups are run."""
    if contract == "operation-identity":
        if journal:
            return sidecar.operation_identity(rec)
        shape = (
            sidecar._shape(rec, "operations", sidecar.OPERATION_SPEC)
            + sidecar._shape(rec, "operation_renewals", sidecar.RENEWAL_SPEC)
            + sidecar._shape(rec, "attempt_joins", sidecar.JOIN_SPEC)
        )
        return shape or sidecar._ledger_rules(rec)
    if contract == "rule-revision":
        return sidecar.rule_revision(rec)[0]
    if journal:
        return sidecar.freshness(rec)
    times = sidecar._time_rules(rec)
    if times:
        return times
    return [
        *sidecar._unique_rules(rec),
        *sidecar._event_rules(rec),
        *sidecar._extension_rules(rec),
        *sidecar._recovery_rules(rec),
    ]


def _run(contract: str, fixture: dict[str, Any]) -> list[Any]:
    return _findings(contract, _record(contract, fixture), journal="journal" in fixture)


# Fixture codes this verifier does not derive from a raw record, with the reason. Everything not
# listed here must be found (a fixture whose code is listed may still be refused for another code).
NOT_DERIVED: dict[str, dict[str, str]] = {
    "operation-identity": {
        "schema_violation": "closed member sets and types of the sidecar projection are not applied to raw rows",
        "undeclared_member": "same",
        "unknown_enum_value": "same",
        "invalid_extension_key": "same",
        "unsupported_contract_version": "a raw record carries no sidecar contract_version",
        "journal_run_mismatch": "the sidecar and the record are one document here",
    },
    "rule-revision": {
        "schema_violation": "closed member sets and types of the sidecar projection are not applied to raw rows",
        "undeclared_member": "same",
        "unknown_enum_value": "same",
        "invalid_extension_key": "same",
        "unsupported_contract_version": "a raw record carries no sidecar contract_version",
        "journal_run_mismatch": "the sidecar and the record are one document here",
        "identity_row_mismatch": "identity rows are the rule_identity members of the record's rows: one copy",
        "identity_row_time_mismatch": "same",
        "identity_row_unknown_row": "same",
        "duplicate_identity_row": "same (decision and refusal ids are unique in the journal rules)",
        "signer_not_configured": "the configured signer set is host configuration in no record",
        "refusal_reason_mismatch": "partly: a signer listed as configured needs the set (host configuration)",
        "timestamp_invalid": "partly: times inside trend and arity reports are not in the record",
        "adoption_source_missing": "trend reports are not in the record",
        "adoption_time_mismatch": "same",
        "arity_flags_mismatch": "arity reports are not in the record",
        "arity_shapes_invalid": "same",
        "declared_arity_mismatch": "same",
        "declared_from_unknown": "same",
        "declared_kind_mismatch": "recomputability reports are not in the record",
        "derived_recomputability_mismatch": "same",
        "duplicate_flagged_row": "trend reports are not in the record",
        "duplicate_report_id": "reports are not in the record",
        "flagged_count_mismatch": "trend reports are not in the record",
        "flagged_row_without_taint": "same",
        "measured_count_mismatch": "arity reports are not in the record",
        "pre_split_without_change": "trend reports are not in the record",
        "recomputability_code_not_in_row": "recomputability reports are not in the record",
        "recomputability_flag_inconsistent": "same",
        "recomputability_row_missing": "same",
        "row_not_before_adoption": "trend reports are not in the record",
        "taint_flag_inconsistent": "same",
        "taint_without_flagged_row": "same",
        "trend_annotation_incomplete": "same",
    },
    "freshness-clocks": {
        "schema_violation": "closed member sets and types of the sidecar projection are not applied to raw rows",
        "undeclared_member": "same",
        "unknown_enum_value": "same",
        "invalid_extension_key": "same",
        "unsupported_contract_version": "a raw record carries no sidecar contract_version",
        "journal_run_mismatch": "the sidecar and the record are one document here",
        "check_events_mismatch": "projection against the record: one copy here",
        "profile_rows_mismatch": "same",
        "clock_row_mismatch": "clock rows are a projection a raw record does not carry",
        "clock_row_missing": "same",
        "clock_row_unknown_row": "same",
        "duplicate_clock_row": "same",
        "duplicate_input_read": "input reads are a projection a raw record does not carry",
        "input_read_check_unknown": "same",
        "input_read_mismatch": "same",
        "input_read_missing": "same",
        "input_read_unknown_input": "same",
        "nonce_bound_without_capability": "the resolver's capability is host configuration in no record",
        "nonce_bound_without_nonce": "input reads are not in the record",
        "nonce_expected_not_check_nonce": "same",
        "nonce_members_inconsistent": "same",
        "nonce_mismatch_basis": "same",
        "accepted_extension_authority_unconfigured": "the configured signer set is in no record",
        "extension_refusal_reason_mismatch": "partly: reasons that need the signer set or the limit are host configuration",
        "recorded_before_evaluated": "the fixture edits a clock row (a projection); the record's own rows are checked, see test_recorded_before_evaluated",
        "accepted_extension_exceeds_limit": "the declared extension limit is in no record",
        "extension_reason_unexplained": "needs host configuration",
        "duplicate_report_id": "freshness reports are not in the record",
        "freshness_counts_mismatch": "same",
        "prior_attempt_not_excluded": "the journal rule second_attempt_for_effect (profile.py) is the record's check",
    },
}


def _cases(contract: str, cls: str) -> list[Path]:
    return fixture_paths(contract, cls)


@pytest.mark.parametrize("contract", CONTRACTS)
def test_the_oracle_and_the_checks_agree_on_every_valid_sidecar(contract: str) -> None:
    for path in _cases(contract, "valid"):
        fixture = load(path)
        assert (
            ORACLES[contract].validate(
                fixture["document"],
                fixture.get("journal"),
                *([fixture["signers"]] if fixture.get("signers") else []),
            )
            == []
        ), path.stem
        assert _run(contract, fixture) == [], path.stem


@pytest.mark.parametrize("contract", CONTRACTS)
def test_every_invalid_sidecar_code_is_found_or_listed_as_not_derived(contract: str) -> None:
    found: dict[str, list[str]] = {}
    missed: dict[str, list[str]] = {}
    for path in _cases(contract, "invalid"):
        fixture = load(path)
        expected = fixture["expected_refusal"]
        codes = {f.code for f in _run(contract, fixture)}
        (found if expected in codes else missed).setdefault(expected, []).append(path.stem)
    assert set(missed) <= set(NOT_DERIVED[contract]), {
        k: v for k, v in missed.items() if k not in NOT_DERIVED[contract]
    }
    # the table cannot go stale: a listed code that is now found everywhere is removed from it
    stale = [c for c in NOT_DERIVED[contract] if c not in missed]
    assert stale == [], stale


def test_detection_counts_over_the_sidecar_fixtures() -> None:
    """Numbers for docs/tiers.md: invalid fixtures refused with their code, per contract."""
    out = {}
    for contract in CONTRACTS:
        total = hit = 0
        for path in _cases(contract, "invalid"):
            fixture = load(path)
            codes = {f.code for f in _run(contract, fixture)}
            total += 1
            hit += fixture["expected_refusal"] in codes
        out[contract] = (hit, total)
    assert out == {
        "operation-identity": (51, 66),
        "rule-revision": (32, 81),
        "freshness-clocks": (54, 97),
    }


# ----------------------------------------------------------------------------- the control plane


CP = json.loads((DATA / "sidecar" / "cp-differential.json").read_text())


def test_control_plane_revision_is_recorded() -> None:
    assert len(CP["source"]["control_plane_revision"]) == 40


def test_operation_status_agrees_with_the_control_plane() -> None:
    assert len(CP["operation_status"]) == 720
    seen = set()
    for case in CP["operation_status"]:
        ledger = CP["ledgers"][case["ledger"]]
        got = sidecar.operation_status(ledger, **case["binding"])
        assert got == case["status"], case
        seen.add(got)
    assert seen == {"ok", "not_admitted", "collision", "renewal_unrecorded"}


def test_licensed_revisions_agree_with_the_control_plane() -> None:
    for case in CP["licensed_revisions"]:
        ledger = CP["ledgers"][case["ledger"]]
        assert sorted(sidecar.licensed_revisions(ledger, case["operation_id"])) == case["licensed"]


def test_rule_resolution_agrees_with_the_control_plane() -> None:
    states = set()
    for case in CP["resolve_rule"]:
        res = sidecar.resolve_rule(case["rows"], case["rule_ref"], case["observed"])
        assert (res["state"], res["verified_through"], res["adopted_digest"]) == (
            case["state"],
            case["verified_through"],
            case["adopted_digest"],
        ), case
        assert res["findings"] == case["findings"], case
        states.add((res["state"], res["verified_through"]))
    assert ("adopted", "digest_matches_signed_revision") in states
    assert len(states) >= 4


def _opening(recorded_at: str, bound: int, deadline: str) -> dict[str, Any]:
    event = {
        "check_id": "c1",
        "phase": "opened",
        "stage": "decision",
        "recorded_at": recorded_at,
        "deadline": deadline,
        "age_bound_seconds": bound,
        "reasons": [],
    }
    return {"check_events": [event]}


def test_deadline_arithmetic_agrees_with_the_control_plane() -> None:
    for case in CP["deadline"]:
        rec = _opening(case["opened"], case["bound"], case["deadline"])
        assert sidecar.freshness(rec) == [], case
        later = _opening(case["opened"], case["bound"], case["deadline"])
        # one second either way is refused
        for delta in (-1, 1):
            moved = copy.deepcopy(later)
            from datetime import timedelta

            from cognous_verify.timeutil import aware

            parsed = aware(case["deadline"])
            assert parsed is not None
            moved["check_events"][0]["deadline"] = (parsed + timedelta(seconds=delta)).isoformat()
            assert [f.code for f in sidecar.freshness(moved)] == ["deadline_mismatch"], case


# ----------------------------------------------------------------------------- real profile records

PROFILE_VALID = [p for p in fixture_paths("journal", "valid") if p.stem.startswith("profile-")]


def doc_of(name: str) -> dict[str, Any]:
    doc: dict[str, Any] = load(FIXTURES / "journal" / "valid" / f"{name}.json")["document"]
    return copy.deepcopy(doc)


def sidecar_results(results: list[CheckResult]) -> list[CheckResult]:
    return [r for r in results if r.check_id in sidecar.CHECK_IDS]


def old_codes(doc: dict[str, Any]) -> set[str]:
    """What the checks before this change said (every non-sidecar check)."""
    results = [r for r in verify(doc) if r.check_id not in sidecar.CHECK_IDS]
    assert errors(results) == []
    return refuted_codes(results)


def new_codes(doc: dict[str, Any]) -> set[str]:
    results = sidecar_results(verify(doc))
    assert errors(results) == []
    return refuted_codes(results)


@pytest.mark.parametrize("path", PROFILE_VALID, ids=[p.stem for p in PROFILE_VALID])
def test_every_untampered_valid_profile_record_is_accepted(path: Path) -> None:
    doc = load(path)["document"]
    results = verify(doc)
    assert errors(results) == []
    mine = sidecar_results(results)
    assert refuted_codes(results) == set()
    assert all(r.verdict == "confirmed" for r in mine), [(r.check_id, r.verdict) for r in mine]
    for r in mine:
        assert r.notes and "does not prove" in r.notes[0]


def test_each_profile_gets_its_check_and_no_other() -> None:
    def ids(name: str) -> set[str]:
        return {r.check_id for r in sidecar_results(verify(doc_of(name)))}

    assert ids("profile-op-normal") == {sidecar.OPERATION_CHECK}
    assert ids("profile-rule-adopted-decision-and-refusal-rows") == {sidecar.RULE_CHECK}
    assert ids("profile-deadline-at-opening-within-bound") == {sidecar.FRESHNESS_CHECK}
    assert ids("profile-all-profiles-applied") == set(sidecar.CHECK_IDS)


def test_a_default_record_gets_no_sidecar_check() -> None:
    for path in fixture_paths("journal", "valid"):
        if path.stem.startswith("profile-"):
            continue
        assert sidecar_results(verify(load(path)["document"])) == [], path.stem
    for name in ("default-applied", "journal-applied", "journal-held", "acp-run-authorized"):
        from .helpers import real_record

        assert sidecar_results(verify(real_record(name))) == [], name


def test_a_profile_member_is_what_switches_a_check_on() -> None:
    doc = doc_of("profile-op-normal")
    stripped = copy.deepcopy(doc)
    for name in sidecar.OPERATION_LISTS:
        stripped.pop(name, None)
    for d in stripped["decisions"]:
        ext = (d.get("binding") or {}).get("runtime_authority") or {}
        ext.pop("operation_id", None)
        ext.pop("operation_issuer", None)
    assert not sidecar.operation_active(stripped)
    assert sidecar.operation_active(doc)


# --- tamper only the sidecar member of a valid record: every earlier check still accepts it


def _tamper(name: str, edit: Any, expect: set[str]) -> None:
    doc = doc_of(name)
    assert new_codes(doc) == set()
    edit(doc)
    assert old_codes(doc) == set(), "the tamper must touch only what the earlier checks do not read"
    assert new_codes(doc) == expect


def test_join_naming_another_operation() -> None:
    _tamper(
        "profile-op-normal",
        lambda d: d["attempt_joins"][0].update(operation_id="op-other"),
        {"join_operation_not_admitted", "join_operation_mismatch"},
    )


def test_join_naming_another_check() -> None:
    _tamper(
        "profile-op-normal",
        lambda d: d["attempt_joins"][0].update(check_id="not-a-check"),
        {"join_check_missing", "join_resolution_check_missing"},
    )


def test_join_at_an_unlicensed_revision() -> None:
    _tamper(
        "profile-op-normal",
        lambda d: d["attempt_joins"][0].update(grant_revision="9"),
        {"join_revision_unlicensed", "join_binding_mismatch"},
    )


def test_join_effect_rewritten() -> None:
    _tamper(
        "profile-op-normal",
        lambda d: d["attempt_joins"][0].update(effect_id="sha256:" + "0" * 64),
        {"join_attempt_mismatch", "join_effect_mismatch", "join_check_lineage"},
    )


def test_join_dropped() -> None:
    _tamper(
        "profile-op-normal",
        lambda d: d.update(attempt_joins=[]),
        {"attempt_without_join"},
    )


def test_operation_row_rebound_to_another_grant() -> None:
    _tamper(
        "profile-op-normal",
        lambda d: d["operations"][0].update(grant_id="urn:other"),
        {"join_grant_mismatch", "decision_operation_binding_mismatch"},
    )


def test_operation_row_issuer_changed() -> None:
    _tamper(
        "profile-op-normal",
        lambda d: d["operations"][0].update(issuer="someone-else"),
        {"operation_issuer_mismatch"},
    )


def test_renewal_accepted_for_a_worker_writer() -> None:
    def edit(d: dict[str, Any]) -> None:
        d["operation_renewals"][0]["written_by"] = "worker"

    _tamper("profile-op-renewal-accepted", edit, {"renewal_accepted_not_by_issuer"})


def test_renewal_duplicate_id() -> None:
    def edit(d: dict[str, Any]) -> None:
        d["operation_renewals"].append(copy.deepcopy(d["operation_renewals"][0]))

    doc = doc_of("profile-op-renewal-accepted")
    edit(doc)
    assert old_codes(doc) == set()
    assert {"duplicate_renewal_id", "renewal_accepted_revision_not_new"} <= new_codes(doc)


def test_refusal_without_its_check_id() -> None:
    def edit(d: dict[str, Any]) -> None:
        d["refusals"][0].pop("check_id")

    _tamper("profile-op-effect-time-refusal-carries-check-id", edit, {"refusal_check_id_missing"})


def test_two_effects_committed_for_one_operation() -> None:
    doc = doc_of("profile-op-delayed-first-attempt-rejected-after-renewal")
    assert new_codes(doc) == set()
    rejected = [a for a in doc["attempts"] if a.get("error") == "operation_already_committed"]
    assert rejected
    # the destination's rejection names a peer; take the peer's record away
    peer_effects = {
        a["effect_id"] for a in doc["attempts"] if a["effect_id"] != rejected[0]["effect_id"]
    }
    for a in doc["attempts"]:
        if a["effect_id"] in peer_effects and a["status"] in {"acknowledged", "partial", "unknown"}:
            a["status"] = "failed"
            a["error"] = "x"
            a["acknowledgement"] = {}
    assert "rejection_without_committed_peer" in new_codes(doc)


def test_rule_revision_digest_changed() -> None:
    def edit(d: dict[str, Any]) -> None:
        d["rule_revisions"][0]["to_digest"] = "sha256:" + "f" * 64

    _tamper(
        "profile-rule-adopted-decision-and-refusal-rows",
        edit,
        {"rule_identity_recomputed_mismatch"},
    )


def test_rule_revision_signed_by_the_reviser() -> None:
    def edit(d: dict[str, Any]) -> None:
        d["rule_revisions"][0]["signer"] = d["rule_revisions"][0]["reviser"]

    _tamper(
        "profile-rule-adopted-decision-and-refusal-rows",
        edit,
        {"self_signed_row_accepted", "rule_identity_recomputed_mismatch"},
    )


def test_rule_revision_dated_after_the_decision_it_adopts() -> None:
    def edit(d: dict[str, Any]) -> None:
        d["rule_revisions"][0]["recorded_at"] = "2026-10-05T19:30:00+00:00"

    _tamper(
        "profile-rule-adopted-decision-and-refusal-rows",
        edit,
        {"rule_identity_recomputed_mismatch"},
    )


def test_rule_identity_on_a_decision_claims_a_stronger_state() -> None:
    def edit(d: dict[str, Any]) -> None:
        state = next(iter(d["decisions"][0]["rule_identity"]["rules"].values()))
        state["digest"] = "sha256:" + "e" * 64  # another digest, still claimed adopted

    _tamper(
        "profile-rule-adopted-decision-and-refusal-rows",
        edit,
        {"rule_identity_recomputed_mismatch"},
    )


def test_rule_revision_dropped() -> None:
    _tamper(
        "profile-rule-adopted-decision-and-refusal-rows",
        lambda d: d.update(rule_revisions=[]),
        {"rule_identity_recomputed_mismatch"},
    )


def test_rule_revision_supersedes_unknown() -> None:
    def edit(d: dict[str, Any]) -> None:
        d["rule_revisions"][-1]["supersedes"] = "no-such-row"

    doc = doc_of("profile-rule-unsigned-then-resigned-by-supersession")
    edit(doc)
    assert old_codes(doc) == set()
    assert "supersedes_unknown" in new_codes(doc)


def test_rule_identity_lists_a_rule_as_unknown_that_is_adopted() -> None:
    def edit(d: dict[str, Any]) -> None:
        d["decisions"][0]["rule_identity"]["unknown"] = ["urn:cognous:policy:refund-policy"]

    _tamper(
        "profile-rule-adopted-decision-and-refusal-rows",
        edit,
        {"rule_identity_unknown_mismatch"},
    )


def test_deadline_moved() -> None:
    def edit(d: dict[str, Any]) -> None:
        opening = next(e for e in d["check_events"] if e["phase"] == "opened" and "deadline" in e)
        opening["age_bound_seconds"] += 1

    # the later events of the check still carry the old bound: the same edit shows twice
    _tamper(
        "profile-deadline-at-opening-within-bound",
        edit,
        {"deadline_mismatch", "check_event_clock_drift"},
    )


def test_deadline_moved_on_every_event_of_a_check() -> None:
    def edit(d: dict[str, Any]) -> None:
        cid = next(e["check_id"] for e in d["check_events"] if "deadline" in e)
        for e in d["check_events"]:
            if e["check_id"] == cid and "deadline" in e:
                e["deadline"] = "2026-10-05T19:00:59+00:00"

    _tamper("profile-deadline-at-opening-within-bound", edit, {"deadline_mismatch"})


def test_deadline_member_dropped_from_the_opening() -> None:
    def edit(d: dict[str, Any]) -> None:
        for e in d["check_events"]:
            e.pop("age_bound_seconds", None)

    doc = doc_of("profile-deadline-at-opening-within-bound")
    edit(doc)
    assert "deadline_members_incomplete" in new_codes(doc)


def test_expired_before_the_deadline() -> None:
    def edit(d: dict[str, Any]) -> None:
        expired = next(e for e in d["check_events"] if e["phase"] == "expired")
        opening = next(
            e
            for e in d["check_events"]
            if e["check_id"] == expired["check_id"] and e["phase"] == "opened"
        )
        expired["recorded_at"] = opening["deadline"]

    doc = doc_of("profile-expired-before-dispatch")
    assert new_codes(doc) == set()
    edit(doc)
    assert "expired_not_past_deadline" in new_codes(doc)


def test_expiry_refusal_naming_another_deadline() -> None:
    def edit(d: dict[str, Any]) -> None:
        d["refusals"][0]["deadline"] = "2026-10-05T19:00:01+00:00"

    doc = doc_of("profile-expired-before-dispatch")
    edit(doc)
    assert "expired_refusal_deadline_mismatch" in new_codes(doc)


def test_extension_window_and_bound() -> None:
    doc = doc_of("profile-extension-recorded-and-applied")
    assert new_codes(doc) == set()
    ext = doc["age_extensions"][0]
    ext["to_max_age_seconds"] += 1
    assert "extension_bound_mismatch" in new_codes(doc)
    doc = doc_of("profile-extension-recorded-and-applied")
    doc["age_extensions"][0]["signer"] = doc["age_extensions"][0]["requested_by"]
    assert "accepted_extension_self_signed" in new_codes(doc)


def test_check_event_after_a_terminal_event() -> None:
    doc = doc_of("profile-deadline-at-opening-within-bound")
    last = copy.deepcopy(doc["check_events"][-1])
    last["phase"] = "input"
    doc["check_events"].append(last)
    assert "check_event_after_close" in new_codes(doc) | old_codes(doc)


def test_recorded_before_evaluated() -> None:
    doc = doc_of("profile-clocks-follow-the-service-clock")
    assert new_codes(doc) == set()
    for e in doc["check_events"]:
        if "evaluated_at" in e:
            e["recorded_at"] = "2026-10-05T18:00:00+00:00"
            break
    assert "recorded_before_evaluated" in new_codes(doc)


# ----------------------------------------------------------------------------- abstention


def test_a_row_naming_signer_not_configured_cannot_be_recomputed() -> None:
    """The configured signer set is in no record: a row that says it was not in it is not
    re-derived, and the check says so instead of accepting or refusing."""
    doc = doc_of("profile-rule-unsigned-row-resolves-unknown")
    for d in doc["decisions"] + doc["refusals"]:
        for st in (d.get("rule_identity") or {}).get("rules", {}).values():
            st["findings"] = [*st["findings"], "signer_not_configured"]
    rule = next(r for r in sidecar_results(verify(doc)) if r.check_id == sidecar.RULE_CHECK)
    assert rule.verdict == "could_not_check"
    assert rule.reason == "input_absent:configured_signer_set"
    assert rule.skipped >= 1


def test_could_not_check_is_not_an_accept() -> None:
    from cognous_verify import engine

    doc = doc_of("profile-rule-unsigned-row-resolves-unknown")
    for d in doc["decisions"] + doc["refusals"]:
        for st in (d.get("rule_identity") or {}).get("rules", {}).values():
            st["findings"] = [*st["findings"], "signer_not_configured"]
    ev = engine.Evaluation(results=verify(doc), inputs=[])
    assert ev.overall == "abstain"


# ----------------------------------------------------------------------------- robustness


def test_malformed_profile_rows_are_refused_not_crashed() -> None:
    doc = doc_of("profile-op-normal")
    doc["operations"].append({"operation_id": 7})
    results = verify(doc)
    assert errors(results) == []
    assert "schema_violation" in refuted_codes(sidecar_results(results))
    rec = doc_of("profile-op-normal")
    rec["attempt_joins"].append("not-an-object")  # the journal structure check refuses this first
    assert [f.code for f in sidecar.operation_identity(rec)] == ["schema_violation"]
    doc = doc_of("profile-rule-adopted-decision-and-refusal-rows")
    doc["decisions"][0]["rule_identity"] = {"rules": []}
    results = verify(doc)
    assert errors(results) == []
    assert "schema_violation" in refuted_codes(sidecar_results(results))
    doc = doc_of("profile-extension-recorded-and-applied")
    doc["age_extensions"][0].pop("to_max_age_seconds")
    results = verify(doc)
    assert errors(results) == []
    assert "schema_violation" in refuted_codes(sidecar_results(results))


def test_the_cli_report_carries_the_sidecar_notes(tmp_path: Path) -> None:
    from cognous_verify import engine, report

    doc = doc_of("profile-all-profiles-applied")
    data = json.dumps(doc).encode()
    ev = engine.evaluate([engine.InputFile(engine.RUN_RECORD, "record.json", data)])
    built = report.build(ev, generated_at="2026-10-18T00:00:00+00:00")
    ids = {c["check_id"] for c in built["checks"]}
    assert set(sidecar.CHECK_IDS) <= ids
    assert built["does_not_prove"]
    notes = built["extensions"]["x-profile-checks"]
    assert set(notes) == set(sidecar.CHECK_IDS)
    assert all("does not prove" in v for v in notes.values())
    assert all(isinstance(v, str) for v in notes.values())
    assert documents.JOURNAL == "control-plane-journal"


def test_the_overall_verdict_and_exit_code_follow(tmp_path: Path) -> None:
    from cognous_verify import cli, engine

    # without a proposal export the identity checks abstain, so an untampered record is `abstain`
    # (exit 3), as before this change; the tampered one is `reject` (exit 1)
    good = doc_of("profile-op-normal")
    bad = copy.deepcopy(good)
    bad["attempt_joins"][0]["operation_id"] = "op-other"
    for name, doc, overall, code in (("good", good, "abstain", 3), ("bad", bad, "reject", 1)):
        raw = json.dumps(doc).encode()
        ev = engine.evaluate([engine.InputFile(engine.RUN_RECORD, f"{name}.json", raw)])
        assert ev.overall == overall
        path = tmp_path / f"{name}.json"
        path.write_bytes(raw)
        assert (
            cli.main([str(path), "--json", "--out", str(tmp_path / f"{name}.report.json")]) == code
        )
    report = json.loads((tmp_path / "bad.report.json").read_text())
    findings = {
        f["code"]
        for c in report["checks"]
        if c["check_id"] == sidecar.OPERATION_CHECK
        for f in c["findings"]
    }
    assert findings == {"join_operation_not_admitted", "join_operation_mismatch"}


def test_the_tampered_grant_mismatch_fixture_is_refused_by_the_operation_identity_check() -> None:
    fixture = load(FIXTURES / "journal" / "invalid" / "profile-op-grant-mismatch-held.json")
    assert fixture["refused_by"] == "operation-identity"
    results = verify(fixture["document"])
    assert errors(results) == []
    assert refuted_codes([r for r in results if not r.check_id.startswith("v2.profile.")]) == set()
    mine = sidecar_results(results)
    assert refuted_codes(mine) == {fixture["expected_refusal"]}
    assert {r.check_id for r in mine if r.verdict == "refuted"} == {sidecar.OPERATION_CHECK}


def test_the_report_names_the_profile_non_claim_only_when_a_profile_check_ran() -> None:
    from cognous_verify import engine, report

    from .test_report_cli import ORACLE

    def ids(doc: dict[str, Any]) -> list[str]:
        ev = engine.evaluate(
            [engine.InputFile(engine.RUN_RECORD, "record.json", json.dumps(doc).encode())]
        )
        built = report.build(ev, generated_at="2026-10-18T00:00:00+00:00")
        assert [v.code for v in ORACLE.validate(built)] == []
        by_id = {n["id"]: n["statement"] for n in built["does_not_prove"]}
        if "profile_sidecar_semantics_only" in by_id:
            assert by_id["profile_sidecar_semantics_only"] == report.PROFILE_NON_CLAIM[1]
            assert "host-configuration rules" in by_id["profile_sidecar_semantics_only"]
        return [n["id"] for n in built["does_not_prove"]]

    assert ids(doc_of("profile-all-profiles-applied")).count("profile_sidecar_semantics_only") == 1
    default = next(
        p for p in fixture_paths("journal", "valid") if not p.stem.startswith("profile-")
    )
    assert "profile_sidecar_semantics_only" not in ids(load(default)["document"])

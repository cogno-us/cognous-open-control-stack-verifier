"""P1 D2 (Verifier-2): strict tenant-generation support, beside the unchanged legacy 0.2 path.

Fixtures under ``tests/data/p1-d2/`` are real Control Plane output (PR #109 head 5bff525a, synthetic
tenant): a run record made under the strict generation ``bounded-authorization-effect/0.3-strict-tenant``
and one made under legacy ``bounded-authorization-effect/0.2``, each with its proposal export, manifest
and destination ledger, plus the shared effect-identity vectors. The historical journal schema is
never edited: strict records are read under the successor schema ``control-plane-journal-strict-tenant``
(contract 0.1.0-draft+strict-tenant), and the two generations are never converted into each other.
"""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from cognous_verify import cli, data, engine, generation, report
from cognous_verify.canon import commitment

from .helpers import DATA

D2 = DATA / "p1-d2"
STRICT = generation.STRICT
LEGACY = generation.LEGACY


def _load(kind: str, name: str) -> Any:
    return json.loads((D2 / kind / name).read_text())


REC = {k: _load(k, "bounded-run-record.json") for k in ("strict", "legacy")}
PROP = {k: (D2 / k / "proposal.json").read_bytes() for k in ("strict", "legacy")}
MAN = {k: _load(k, "manifest.json") for k in ("strict", "legacy")}
LED = {k: (D2 / k / "destination.json").read_bytes() for k in ("strict", "legacy")}
VECTORS = json.loads((D2 / "identity-vectors.json").read_text())["vectors"]
ACTION = "urn:cognous:action:refund-issue-routine-v1"
MAX = 2**53 - 1
ABSENT = object()


def _decision(rec: dict[str, Any]) -> dict[str, Any]:
    return next(d for d in rec["decisions"] if d["result"] == "authorized")


def _evaluate(
    rec: dict[str, Any], kind: str, *, manifest: Any = "same", ledger: bool = True
) -> engine.Evaluation:
    files = [
        engine.InputFile("run_record", "r.json", json.dumps(rec).encode()),
        engine.InputFile("proposal_export", "p.json", PROP[kind]),
    ]
    if manifest == "same":
        files.append(engine.InputFile("manifest", "m.json", json.dumps(MAN[kind]).encode()))
    elif manifest is not None:
        files.append(engine.InputFile("manifest", "m.json", manifest))
    if ledger:
        files.append(engine.InputFile("destination_ledger", "d.json", LED[kind]))
    return engine.evaluate(files)


def _verdicts(ev: engine.Evaluation) -> dict[str, str]:
    return {c.check_id: c.verdict for c in ev.checks}


def _codes(ev: engine.Evaluation, check_id: str | None = None) -> set[str]:
    return {
        f.code
        for c in ev.checks
        if c.verdict == "refuted" and (check_id is None or c.check_id == check_id)
        for f in c.findings
    }


def _refuted(ev: engine.Evaluation) -> set[str]:
    return {c.check_id for c in ev.checks if c.verdict == "refuted"}


def _is_refused(ev: engine.Evaluation) -> bool:
    """Not accepted: at least one check refuted (never merely abstained for a hostile record)."""
    return ev.overall == "reject"


# 1 and 2 --------------------------------------------------------------------------------------


def test_fixtures_are_real_cp_output_of_the_two_generations() -> None:
    assert _decision(REC["strict"])["binding"]["generation"] == STRICT
    assert _decision(REC["legacy"])["binding"]["generation"] == LEGACY
    assert _decision(REC["strict"])["binding"]["tenant_id"] == "tenant-alpha"


def test_legacy_record_is_accepted_under_the_historical_path() -> None:
    ev = _evaluate(REC["legacy"], "legacy")
    assert ev.overall == "accept"
    assert _refuted(ev) == set()
    assert all(c.verdict == "confirmed" for c in ev.checks)
    structure = next(c for c in ev.checks if c.check_id == "v1.structure")
    assert f"schema sha256 {data.schema_digest('control-plane-journal')}" in structure.notes
    assert not any("strict-tenant" in n for n in structure.notes)


def test_strict_record_is_accepted_under_the_successor_path() -> None:
    ev = _evaluate(REC["strict"], "strict")
    assert ev.overall == "accept"
    assert _refuted(ev) == set()
    assert all(c.verdict == "confirmed" for c in ev.checks)
    assert len(ev.checks) == len(
        _evaluate(REC["legacy"], "legacy").checks
    )  # same checks, none skipped
    structure = next(c for c in ev.checks if c.check_id == "v1.structure")
    digest = data.schema_digest("control-plane-journal-strict-tenant")
    assert f"schema sha256 {digest}" in structure.notes
    assert any("strict-tenant successor schema" in n for n in structure.notes)


def test_strict_record_without_any_other_input_is_not_a_structure_failure() -> None:
    # the reproducer at the base: schema_violation at $.decisions[0].binding, v1.structure refuted
    ev = _evaluate(REC["strict"], "strict", manifest=None, ledger=False)
    assert "v1.structure" not in _refuted(ev)
    assert _codes(ev) == set()


def test_declared_successor_contract_version_is_read_under_the_successor_schema() -> None:
    rec = {
        "contract": "control-plane-journal",
        "contract_version": "0.1.0-draft+strict-tenant",
        **REC["strict"],
    }
    ev = _evaluate(rec, "strict")
    assert ev.overall == "accept"


def test_historical_schema_file_is_unmodified_and_successor_is_derived() -> None:
    assert data.provenance_problems() == []
    entries = {e["file"]: e for e in data.provenance()["files"]}
    historical = entries["control-plane-journal.schema.json"]
    assert historical["sha256"] == (
        "sha256:fec8e9b4d14d2be43af700c58b7e3760fb5326caa5ca493adf0d7d972a88648d"
    )
    hist = data.schema("control-plane-journal")
    assert hist["$defs"]["binding"]["properties"]["generation"] == {"enum": [LEGACY]}
    succ = data.schema("control-plane-journal-strict-tenant")
    assert succ["$defs"]["binding"]["properties"]["generation"] == {"enum": [STRICT]}
    assert {"generation", "tenant_id"} <= set(succ["$defs"]["binding"]["required"])


def test_successor_schema_matches_the_derivation_tool() -> None:
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "derive", Path(__file__).parent.parent / "tools" / "derive_strict_tenant_schema.py"
    )
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    assert (
        mod.render()
        == (data.DATA_DIR / "control-plane-journal-strict-tenant.schema.json").read_bytes()
    )


# 3: strict record interpreted as legacy -----------------------------------------------------------


def test_strict_record_declared_as_the_historical_contract_is_refused() -> None:
    rec = {"contract": "control-plane-journal", "contract_version": "0.1.0-draft", **REC["strict"]}
    ev = _evaluate(rec, "strict")
    assert _is_refused(ev)
    assert "v1.structure" in _refuted(ev)
    structure = next(c for c in ev.checks if c.check_id == "v1.structure")
    assert any(".binding" in f.path for f in structure.findings)


def test_strict_record_whose_marker_is_rewritten_to_legacy_is_refused() -> None:
    rec = copy.deepcopy(REC["strict"])
    _decision(rec)["binding"]["generation"] = LEGACY  # effect_id stays the strict one
    ev = _evaluate(rec, "strict")
    assert _is_refused(ev)
    assert "invalid_effect_identity" in _codes(ev, "v2.journal.decisions")
    assert "invalid_effect_identity" in _codes(ev, "v2.identity.effect-id")


def test_strict_record_with_marker_stripped_is_refused() -> None:
    rec = copy.deepcopy(REC["strict"])
    del _decision(rec)["binding"]["generation"]  # tenant_id remains: neither generation can be read
    ev = _evaluate(rec, "strict")
    assert _is_refused(ev)
    assert "tenant_binding_incomplete" in _codes(ev) or "invalid_effect_identity" in _codes(ev)
    rec2 = {
        "contract": "control-plane-journal",
        "contract_version": "0.1.0-draft+strict-tenant",
        **rec,
    }
    assert "v1.structure" in _refuted(_evaluate(rec2, "strict"))


# 4: legacy record marked strict ------------------------------------------------------------------


def test_legacy_record_declared_as_the_successor_contract_is_refused() -> None:
    rec = {
        "contract": "control-plane-journal",
        "contract_version": "0.1.0-draft+strict-tenant",
        **REC["legacy"],
    }
    ev = _evaluate(rec, "legacy")
    assert _is_refused(ev)
    assert "v1.structure" in _refuted(ev)


def test_legacy_record_whose_marker_is_rewritten_to_strict_is_refused() -> None:
    rec = copy.deepcopy(REC["legacy"])
    _decision(rec)["binding"]["generation"] = STRICT  # effect_id stays the legacy one
    ev = _evaluate(rec, "legacy")
    assert _is_refused(ev)
    assert "invalid_effect_identity" in _codes(ev, "v2.journal.decisions")
    assert "invalid_effect_identity" in _codes(ev, "v2.identity.effect-id")


def test_legacy_record_without_a_marker_or_tenant_keeps_the_historical_path() -> None:
    rec = copy.deepcopy(REC["legacy"])
    b = _decision(rec)["binding"]
    del (
        b["generation"],
        b["tenant_id"],
    )  # the older tenant-less binding: identity formula is unchanged
    ev = _evaluate(rec, "legacy", manifest=None, ledger=False)
    assert "v1.structure" not in _refuted(ev)
    assert "invalid_effect_identity" not in _codes(ev, "v2.journal.decisions")


def test_mixed_generations_in_one_record_are_refused() -> None:
    rec = copy.deepcopy(REC["strict"])
    other = copy.deepcopy(_decision(REC["legacy"]))
    other["decision_id"] = "mixed-legacy-decision"
    rec["decisions"].append(other)
    assert "v1.structure" in _refuted(_evaluate(rec, "strict"))
    rec = copy.deepcopy(REC["legacy"])
    other = copy.deepcopy(_decision(REC["strict"]))
    other["decision_id"] = "mixed-strict-decision"
    rec["decisions"].append(other)
    assert "v1.structure" in _refuted(_evaluate(rec, "legacy"))


# 5: wrong generation marker ---------------------------------------------------------------------


WRONG_MARKERS = [
    ("future_version", "bounded-authorization-effect/0.4-strict-tenant"),
    ("truncated", "bounded-authorization-effect/0.3"),
    ("padded", f" {STRICT}"),
    ("trailing_newline", f"{STRICT}\n"),
    ("recased", STRICT.upper()),
    ("empty", ""),
    ("null", None),
    ("bool", True),
    ("number", 3),
    ("list", [STRICT]),
    ("object", {"generation": STRICT}),
]


@pytest.mark.parametrize("name,value", WRONG_MARKERS, ids=[m[0] for m in WRONG_MARKERS])
@pytest.mark.parametrize("kind", ["strict", "legacy"])
def test_wrong_generation_marker_is_refused(kind: str, name: str, value: Any) -> None:
    rec = copy.deepcopy(REC[kind])
    _decision(rec)["binding"]["generation"] = value
    ev = _evaluate(rec, kind)
    assert _is_refused(ev), (kind, name)
    assert "v1.structure" in _refuted(ev)
    # the refusal is deterministic: V2 identity checks are not run on a record whose structure is refuted
    assert not any(
        c.verdict == "confirmed" and c.check_id.startswith("v2.identity") for c in ev.checks
    )


def test_generation_helper_is_exact_string_equality() -> None:
    class Sub(str):
        pass

    assert generation.binding_generation({"generation": STRICT}) == STRICT
    assert generation.binding_generation({"generation": LEGACY}) == LEGACY
    assert generation.binding_generation({}) == LEGACY
    bad: Any
    for bad in (Sub(STRICT), Sub(LEGACY), f"{STRICT} ", STRICT.title(), None, 1, True, [], {}):
        assert generation.binding_generation({"generation": bad}) is None
    assert generation.binding_generation(None) == LEGACY
    assert generation.effect_identity("p", "g", "1", None) is None
    assert not generation.record_uses_strict(
        {"decisions": [{"binding": {"generation": Sub(STRICT)}}]}
    )
    assert generation.record_uses_strict({"decisions": [{"binding": {"generation": STRICT}}]})
    assert not generation.record_uses_strict({"decisions": None})


# 6 and 7: effect identity -------------------------------------------------------------------------


def _flip(eid: str) -> str:
    return eid[:-1] + ("0" if eid[-1] != "0" else "1")


def test_strict_effect_identity_tamper_is_refuted() -> None:
    rec = copy.deepcopy(REC["strict"])
    d = _decision(rec)
    d["effect_id"] = _flip(d["effect_id"])
    ev = _evaluate(rec, "strict")
    assert _is_refused(ev)
    assert "invalid_effect_identity" in _codes(ev, "v2.journal.decisions")
    assert "invalid_effect_identity" in _codes(ev, "v2.identity.effect-id")


@pytest.mark.parametrize("member", ["grant_id", "grant_revision", "proposal_commitment"])
def test_strict_effect_identity_binds_every_member(member: str) -> None:
    rec = copy.deepcopy(REC["strict"])
    b = _decision(rec)["binding"]
    b[member] = b[member] + "x" if member != "proposal_commitment" else "sha256:" + "0" * 64
    ev = _evaluate(rec, "strict")
    assert _is_refused(ev)
    assert "invalid_effect_identity" in _codes(ev)


def test_strict_effect_identity_computed_with_the_legacy_algorithm_is_refuted() -> None:
    rec = copy.deepcopy(REC["strict"])
    d = _decision(rec)
    b = d["binding"]
    d["effect_id"] = commitment(
        {
            "proposal": b["proposal_commitment"],
            "grant_id": b["grant_id"],
            "grant_revision": b["grant_revision"],
        }
    )
    assert d["effect_id"] == _decision(REC["legacy"])["effect_id"]
    ev = _evaluate(rec, "strict")
    assert _is_refused(ev)
    assert "invalid_effect_identity" in _codes(ev, "v2.journal.decisions")
    assert "invalid_effect_identity" in _codes(ev, "v2.identity.effect-id")


def test_legacy_effect_identity_computed_with_the_strict_algorithm_is_refuted() -> None:
    rec = copy.deepcopy(REC["legacy"])
    d = _decision(rec)
    d["effect_id"] = _decision(REC["strict"])["effect_id"]
    ev = _evaluate(rec, "legacy")
    assert _is_refused(ev)
    assert "invalid_effect_identity" in _codes(ev)


def test_missing_tenant_on_a_strict_binding_is_refused() -> None:
    rec = copy.deepcopy(REC["strict"])
    del _decision(rec)["binding"]["tenant_id"]
    assert "v1.structure" in _refuted(_evaluate(rec, "strict"))  # inferred strict, tenant required


def test_strict_binding_tenant_must_equal_the_proposal_tenant() -> None:
    rec = copy.deepcopy(REC["strict"])
    _decision(rec)["binding"]["tenant_id"] = "tenant-beta"
    ev = _evaluate(rec, "strict")
    assert _is_refused(ev)
    assert "binding_proposal_mismatch" in _codes(ev, "v2.identity.binding-fields")


def test_shared_identity_vectors_hold_for_the_verifier() -> None:
    by_name = {v["name"]: v for v in VECTORS}
    assert set(by_name) == {"strict", "legacy-0.2", "legacy-tenantless-binding"}
    for v in VECTORS:
        pre = v["preimage"]
        assert v["expected_effect_id"] == "sha256:" + hashlib.sha256(pre.encode()).hexdigest()
        gen = generation.LEGACY if v["generation"] is None else v["generation"]
        got = generation.effect_identity(v["proposal"], v["grant_id"], v["grant_revision"], gen)
        assert got == v["expected_effect_id"], v["name"]
    assert by_name["strict"]["expected_effect_id"] == _decision(REC["strict"])["effect_id"]
    assert by_name["legacy-0.2"]["expected_effect_id"] == _decision(REC["legacy"])["effect_id"]
    assert by_name["strict"]["expected_effect_id"] != by_name["legacy-0.2"]["expected_effect_id"]
    # the strict preimage differs from the legacy one by exactly the generation member
    strict_pre = json.loads(by_name["strict"]["preimage"])
    legacy_pre = json.loads(by_name["legacy-0.2"]["preimage"])
    assert strict_pre.pop("tenant_generation") == STRICT
    assert strict_pre == legacy_pre


# 8, 9, 10 and 11: item 6 (effect_limits) coexists with strict ------------------------------------


def _limit_run(kind: str, value: Any, ceiling: Any = 1) -> engine.Evaluation:
    rec = copy.deepcopy(REC[kind])
    _decision(rec)["binding"]["effective_max_effects"] = ceiling
    man = copy.deepcopy(MAN[kind])
    act = next(a for a in man["actions"] if a["action_id"] == ACTION)
    if value is ABSENT:
        del act["effect_limits"]["max_effects"]
    else:
        act["effect_limits"]["max_effects"] = value
    return _evaluate(rec, kind, manifest=json.dumps(man).encode(), ledger=False)


def _binding_fields(ev: engine.Evaluation) -> tuple[str, list[str]]:
    c = next(c for c in ev.checks if c.check_id == "v2.identity.binding-fields")
    return c.verdict, [f.code for f in c.findings]


@pytest.mark.parametrize("limit", [1, 2, 1000, MAX])
def test_strict_valid_explicit_max_effects_is_enforced(limit: int) -> None:
    assert _binding_fields(_limit_run("strict", limit))[0] == "confirmed"


def test_strict_zero_limit_refuses_a_larger_ceiling_and_allows_zero() -> None:
    assert _binding_fields(_limit_run("strict", 0, ceiling=1)) == (
        "refuted",
        ["binding_member_mismatch"],
    )
    # a ceiling of 0 against a limit of 0 is not an overrun
    assert "binding_member_mismatch" not in _binding_fields(_limit_run("strict", 0, ceiling=0))[1]


def test_strict_ceiling_above_limit_is_refused() -> None:
    assert _binding_fields(_limit_run("strict", 1, ceiling=2)) == (
        "refuted",
        ["binding_member_mismatch"],
    )


def test_strict_missing_max_effects_is_refused() -> None:
    assert _binding_fields(_limit_run("strict", ABSENT)) == (
        "refuted",
        ["binding_member_mismatch"],
    )


MALFORMED = [
    ("null", None),
    ("true", True),
    ("false", False),
    ("string", "1"),
    ("float_integral", 1.0),
    ("float_fractional", 1.5),
    ("negative", -1),
    ("list", [1]),
    ("object", {"n": 1}),
]


@pytest.mark.parametrize("kind", ["strict", "legacy"])
@pytest.mark.parametrize("name,value", MALFORMED, ids=[m[0] for m in MALFORMED])
def test_malformed_max_effects_is_refused_in_both_generations(
    kind: str, name: str, value: Any
) -> None:
    assert _binding_fields(_limit_run(kind, value)) == ("refuted", ["binding_member_mismatch"])


@pytest.mark.parametrize("kind", ["strict", "legacy"])
def test_missing_and_overflow_max_effects_stay_refused_in_both_generations(kind: str) -> None:
    assert _binding_fields(_limit_run(kind, ABSENT)) == ("refuted", ["binding_member_mismatch"])
    ev = _limit_run(kind, MAX + 1)  # refused by the strict wire parser before any binding check
    assert _is_refused(ev)
    assert any(c.verdict == "refuted" and c.check_id.startswith("v1.wire") for c in ev.checks)


@pytest.mark.parametrize("kind", ["strict", "legacy"])
def test_missing_effect_limits_container_is_refused_in_both_generations(kind: str) -> None:
    rec = copy.deepcopy(REC[kind])
    man = copy.deepcopy(MAN[kind])
    act = next(a for a in man["actions"] if a["action_id"] == ACTION)
    del act["effect_limits"]
    ev = _evaluate(rec, kind, manifest=json.dumps(man).encode(), ledger=False)
    assert _binding_fields(ev) == ("refuted", ["binding_member_mismatch"])


@pytest.mark.parametrize("kind", ["strict", "legacy"])
def test_legacy_item6_cases_with_valid_limits_still_pass(kind: str) -> None:
    assert _binding_fields(_limit_run(kind, 1))[0] == "confirmed"


# 12: report schema stays deterministic -----------------------------------------------------------


def _report(kind: str) -> dict[str, Any]:
    ev = _evaluate(REC[kind], kind)
    return report.build(
        ev, generated_at="2026-11-04T00:00:00Z", controller_revision=None, source_revision=None
    )


@pytest.mark.parametrize("kind", ["strict", "legacy"])
def test_report_is_byte_deterministic(kind: str) -> None:
    a = json.dumps(_report(kind), sort_keys=True)
    b = json.dumps(_report(kind), sort_keys=True)
    assert a == b


def test_report_schema_is_the_same_for_both_generations() -> None:
    s, lg = _report("strict"), _report("legacy")
    assert set(s) == set(lg)
    assert s["contract"] == lg["contract"] and s["contract_version"] == lg["contract_version"]
    assert s["subject"]["pinned"] == lg["subject"]["pinned"]  # no new pinned member, no new version
    assert [c["check_id"] for c in s["checks"]] == [c["check_id"] for c in lg["checks"]]
    assert s["summary"] == lg["summary"]
    assert set(s["extensions"]) == set(lg["extensions"])
    assert s["scope"] == lg["scope"]


def test_legacy_report_has_no_strict_wording() -> None:
    assert "strict-tenant" not in json.dumps(_report("legacy"))


def test_cli_accepts_a_real_strict_run_and_a_real_legacy_run(
    capsys: pytest.CaptureFixture[str],
) -> None:
    for kind in ("strict", "legacy"):
        d = D2 / kind
        rc = cli.main(
            [
                str(d / "bounded-run-record.json"),
                "--proposal",
                str(d / "proposal.json"),
                "--manifest",
                str(d / "manifest.json"),
                "--ledger",
                str(d / "destination.json"),
                "--json",
                "--generated-at",
                "2026-11-04T00:00:00Z",
            ]
        )
        out = json.loads(capsys.readouterr().out)
        assert rc == cli.EXIT_ACCEPT, kind
        assert out["summary"]["refuted"] == 0 and out["summary"]["could_not_check"] == 0

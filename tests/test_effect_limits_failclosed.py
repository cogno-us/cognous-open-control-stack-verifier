"""csf_2a88c683d3feb63046eac3d0: a supplied manifest must state an explicit, exact-integer
``effect_limits.max_effects`` (0 .. 2**53-1) for a decision that states ``effective_max_effects``.

A missing or malformed limit is refused (``binding_member_mismatch``); it is never read as the
schema default, the control-plane default, ``proposal.effects`` or "unlimited". Without a supplied
manifest nothing is compared (unchanged). The verification-report/0.1 schema is unchanged.
"""

from __future__ import annotations

import copy
import json
from typing import Any

import pytest

from cognous_verify import engine

from .helpers import DATA

RUN = DATA / "orchestrator-runs" / "adapter-applied"
REC = json.loads((RUN / "bounded-run-record.json").read_text())
MAN = json.loads((RUN / "manifest.json").read_text())
PROP = (RUN / "proposal.json").read_bytes()
ACTION = "urn:cognous:action:refund-issue-routine-v1"
MAX = 2**53 - 1
ABSENT = object()
CHECK = "v2.identity.binding-fields"


def _decision(rec: dict[str, Any]) -> dict[str, Any]:
    return next(d for d in rec["decisions"] if d["result"] == "authorized")


def _manifest(value: Any, mode: str = "max_effects") -> bytes:
    man = copy.deepcopy(MAN)
    act = next(a for a in man["actions"] if a["action_id"] == ACTION)
    if mode == "max_effects":
        if value is ABSENT:
            del act["effect_limits"]["max_effects"]
        else:
            act["effect_limits"]["max_effects"] = value
    elif mode == "effect_limits":
        if value is ABSENT:
            del act["effect_limits"]
        else:
            act["effect_limits"] = value
    elif mode == "action_missing":
        man["actions"] = [a for a in man["actions"] if a["action_id"] != ACTION]
    elif mode == "actions":
        man["actions"] = value
    return json.dumps(man).encode()


def _binding(ceiling: Any, manifest: bytes | None) -> tuple[str, list[str]]:
    rec = copy.deepcopy(REC)
    _decision(rec)["binding"]["effective_max_effects"] = ceiling
    files = [
        engine.InputFile("run_record", "r.json", json.dumps(rec).encode()),
        engine.InputFile("proposal_export", "p.json", PROP),
    ]
    if manifest is not None:
        files.append(engine.InputFile("manifest", "m.json", manifest))
    r = next(r for r in engine.evaluate(files).results if r.check_id == CHECK)
    return r.verdict, [f.code for f in r.findings]


MALFORMED = [
    ("absent", ABSENT),
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


@pytest.mark.parametrize("name,value", MALFORMED, ids=[m[0] for m in MALFORMED])
def test_missing_or_malformed_max_effects_is_refused(name: str, value: Any) -> None:
    verdict, codes = _binding(1_000_000, _manifest(value))
    assert verdict == "refuted" and codes == ["binding_member_mismatch"], (name, verdict, codes)


@pytest.mark.parametrize("name,value", MALFORMED, ids=[m[0] for m in MALFORMED])
def test_malformed_limit_is_refused_even_when_the_ceiling_is_small(name: str, value: Any) -> None:
    # no default (e.g. 1) is inferred for the limit: a small, otherwise-plausible ceiling is not confirmed
    verdict, _ = _binding(1, _manifest(value))
    assert verdict == "refuted"


@pytest.mark.parametrize(
    "mode,value",
    [
        ("effect_limits", ABSENT),
        ("effect_limits", None),
        ("effect_limits", "x"),
        ("effect_limits", []),
        ("action_missing", None),
        ("actions", None),
        ("actions", {}),
    ],
    ids=[
        "limits_absent",
        "limits_null",
        "limits_string",
        "limits_list",
        "action_missing",
        "actions_null",
        "actions_object",
    ],
)
def test_missing_limit_container_is_refused(mode: str, value: Any) -> None:
    verdict, codes = _binding(1_000_000, _manifest(value, mode))
    assert verdict == "refuted" and "binding_member_mismatch" in codes


def test_overflow_limit_is_refused() -> None:
    # beyond the wire range the strict parser refuses the manifest (v1.wire.*) before any binding check
    files = [
        engine.InputFile("run_record", "r.json", json.dumps(REC).encode()),
        engine.InputFile("proposal_export", "p.json", PROP),
        engine.InputFile("manifest", "m.json", _manifest(MAX + 1)),
    ]
    results = engine.evaluate(files).results
    assert any(r.verdict == "refuted" and r.check_id.startswith("v1.wire") for r in results)


def test_overflow_limit_direct_is_refused_by_the_check() -> None:
    from cognous_verify import identity

    assert not identity._valid_limit(MAX + 1)
    assert not identity._valid_limit(2**64)


@pytest.mark.parametrize("limit", [0, 1, 7, MAX])
def test_valid_limit_is_accepted_and_compared(limit: int) -> None:
    ceiling = min(limit, 1)
    verdict, codes = _binding(ceiling, _manifest(limit))
    assert verdict == "confirmed" and codes == []


def test_valid_limit_zero_refuses_a_larger_ceiling() -> None:
    verdict, codes = _binding(1, _manifest(0))
    assert verdict == "refuted" and codes == ["binding_member_mismatch"]


def test_valid_larger_integer_limit_boundary() -> None:
    assert _binding(7, _manifest(7))[0] == "confirmed"
    assert _binding(8, _manifest(7))[0] == "refuted"
    assert _binding(MAX, _manifest(MAX))[0] == "confirmed"


def test_no_manifest_supplied_is_unchanged() -> None:
    assert _binding(1, None)[0] == "confirmed"


def test_unchanged_manifest_confirms() -> None:
    assert _binding(1, json.dumps(MAN).encode())[0] == "confirmed"

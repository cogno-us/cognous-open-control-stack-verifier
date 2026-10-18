from __future__ import annotations

import json
import math
from pathlib import Path
from typing import Any

import pytest

from cognous_verify import canon, wire

DATA = Path(__file__).parent / "data"


def load(name: str) -> Any:
    return json.loads((DATA / name).read_text(encoding="utf-8"))


def test_profile_id_is_the_pinned_one() -> None:
    assert canon.PROFILE_ID == "json-sort-keys-compact-utf8-no-nan-python-semantics-v0.1-proposed"
    vectors = load("cp-decision-input-commitment-vectors.json")
    assert vectors["baseline_record"]["canonicalization_profile"] == canon.PROFILE_ID


@pytest.mark.parametrize("vec", load("canon-vectors.json")["vectors"], ids=lambda v: v["id"])
def test_verifier_owned_vectors_byte_for_byte(vec: dict[str, str]) -> None:
    value = wire.parse(vec["input"].encode("utf-8"))
    out = canon.canonical_bytes(value)
    assert out == vec["canonical"].encode("utf-8")
    assert canon.commitment(value) == "sha256:" + vec["sha256"]


def test_matches_stdlib_oracle_on_nested_values() -> None:
    tricky = chr(0x2028) + '\x01\x7f"\\'
    value: dict[str, Any] = {"b": [1, 1.0, 1e100, -0.0, "é", tricky], "a": None, "c": True, "": {}}
    oracle = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    assert canon.canonical_bytes(value) == oracle.encode("utf-8")


def test_int_float_and_zero_forms_are_distinct() -> None:
    assert canon.commitment({"n": 1}) != canon.commitment({"n": 1.0})
    assert canon.commitment({"n": 0.0}) != canon.commitment({"n": -0.0})
    assert canon.commitment({"n": 1.0}) == canon.commitment({"n": 1e0})
    # no Unicode normalization
    assert canon.commitment({"s": "é"}) != canon.commitment({"s": "é"})
    # absent differs from null
    assert canon.commitment({}) != canon.commitment({"value": None})


def test_key_order_is_code_point_not_utf16() -> None:
    out = canon.canonical_text({"\U0001f600": 1, "￿": 2})
    assert out.index("￿") < out.index("\U0001f600")


@pytest.mark.parametrize(
    "bad",
    [
        {"x": math.nan},
        {"x": math.inf},
        {"x": -math.inf},
        {"x": {1}},
        {"x": b"bytes"},
        {"x": (1, 2)},
        {1: "int key"},
        {"x": "\ud800"},
        object(),
    ],
)
def test_unrepresentable_values_refused(bad: Any) -> None:
    with pytest.raises(canon.CanonError):
        canon.canonical_bytes(bad)


def test_depth_limit() -> None:
    value: Any = 1
    for _ in range(canon.MAX_DEPTH + 2):
        value = [value]
    with pytest.raises(canon.CanonError):
        canon.canonical_bytes(value)


def test_digest_bytes_prefix() -> None:
    assert canon.digest_bytes(b"") == (
        "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )


# --- control plane decision-input vectors (design S2 acceptance d) -------------------------------
# The commitment arithmetic of the pinned profile, written here from the profile text and
# checked against the control plane's own vector file. Only the arithmetic is replicated: the
# semantic rules of that record (evidence status, precedence) are tier V3 and not built.


def _obligation_payload(o: dict[str, Any]) -> dict[str, Any]:
    keys = (
        "obligation_id",
        "policy_origin_ref",
        "policy_origin_version",
        "required",
        "source_ref",
        "max_age_seconds",
        "resolution_semantics_id",
        "resolution_semantics_commitment",
    )
    return {k: o.get(k) for k in keys}


def commitment_mismatches(record: dict[str, Any]) -> list[str]:
    """Names of every stored commitment that does not equal the recomputed one."""
    bad: list[str] = []

    def check(name: str, stored: Any, value: Any) -> None:
        if stored != canon.commitment(value):
            bad.append(name)

    check("candidate", record["candidate"]["commitment"], record["candidate"]["materialized"])
    check("context", record["context"]["commitment"], record["context"]["materialized"])
    for i, p in enumerate(record["policies"]):
        check(f"policies[{i}].content", p["content_commitment"], p["content"])
        check(
            f"policies[{i}].semantics",
            p["evaluation_semantics_commitment"],
            p["evaluation_semantics"],
        )
    for i, r in enumerate(record["institutional_requirements"]):
        check(f"requirements[{i}]", r["commitment"], r["content"])
    for i, o in enumerate(record["evidence_obligations"]):
        check(f"obligations[{i}]", o["obligation_commitment"], _obligation_payload(o))
    res = record["resolver_semantics"]
    check("resolver", res["classification_semantics_commitment"], res["classification_semantics"])
    for i, e in enumerate(record["evidence_items"]):
        check(f"evidence[{i}].content", e["content_commitment"], e["content"])
        check(f"evidence[{i}].provenance", e["provenance_commitment"], e["provenance"])
    payload = {
        k: record.get(k)
        for k in (
            "profile_version",
            "canonicalization_profile",
            "commitment_algorithm",
            "candidate",
            "institutional_requirements",
            "policies",
            "evidence_obligations",
            "evidence_items",
            "context",
            "evaluation_time",
            "resolver_semantics",
            "assurance",
        )
    }
    check("decision_input", record["decision"]["input_commitment"], payload)
    check(
        "record",
        record["record_commitment"],
        {k: v for k, v in record.items() if k != "record_commitment"},
    )
    return bad


def test_baseline_record_commitments_reproduce_byte_for_byte() -> None:
    vectors = load("cp-decision-input-commitment-vectors.json")
    # parse through the verifier's own strict parser, not the standard library
    parsed = wire.parse((DATA / "cp-decision-input-commitment-vectors.json").read_bytes())
    assert parsed == vectors
    assert commitment_mismatches(parsed["baseline_record"]) == []


def test_canonicalization_vectors_from_control_plane() -> None:
    vectors = load("cp-decision-input-commitment-vectors.json")["canonicalization_vectors"]
    assert len(vectors) == 6
    for vec in vectors:
        same = canon.commitment(vec["left"]) == canon.commitment(vec["right"])
        assert same is (vec["operation"] == "equal"), vec["id"]


def test_malformed_value_vectors_are_refused() -> None:
    ids = {
        v["id"]
        for v in load("cp-decision-input-commitment-vectors.json")["malformed_value_vectors"]
    }
    assert ids == {"nan-rejected", "set-rejected", "bytes-rejected"}
    for bad in (math.nan, {1}, b"x"):
        with pytest.raises(canon.CanonError):
            canon.canonical_bytes({"v": bad})


def _apply(record: dict[str, Any], patch: dict[str, Any]) -> None:
    *parents, last = [p for p in patch["path"].split("/") if p != ""]
    node: Any = record
    for part in parents:
        node = node[int(part)] if isinstance(node, list) else node[part]
    if patch["op"] == "remove":
        del node[int(last) if isinstance(node, list) else last]
    elif isinstance(node, list):
        if last == "-":
            node.append(patch["value"])
        elif patch["op"] == "add":
            node.insert(int(last), patch["value"])
        else:
            node[int(last)] = patch["value"]
    else:
        node[last] = patch["value"]


def test_commitment_level_record_vectors() -> None:
    """Vectors with no recompute step: a patched record must show stale commitments."""
    vectors = load("cp-decision-input-commitment-vectors.json")
    baseline = vectors["baseline_record"]
    checked = 0
    for case in vectors["record_vectors"]:
        recompute = [k for k in case if k.startswith("recompute")]
        if recompute:
            continue  # semantic cases (tier V3), not replicated
        record = json.loads(json.dumps(baseline))
        for patch in case.get("patches", []):
            _apply(record, patch)
        stale = commitment_mismatches(record)
        if case["id"] == "reason-precedence-altered":
            # precedence is a rule of the record, but it sits inside the record commitment
            assert "record" in stale
        elif case["expect_valid"]:
            assert stale == [], case["id"]
        else:
            assert stale, case["id"]
        checked += 1
    assert checked == 5

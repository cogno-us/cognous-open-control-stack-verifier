"""Control Plane 0a41faa9 adds ``invalid_manifest`` to runtime-authority-reasons/0.2 (164 codes)."""

from __future__ import annotations

import copy
from typing import Any

from cognous_verify import data, identity

from .helpers import fixture_paths, load

V01 = "runtime-authority-reasons/0.1"
V02 = "runtime-authority-reasons/0.2"


def _doc_with_refusal(code: str, label: str) -> dict[str, Any]:
    for path in fixture_paths("journal", "valid"):
        doc: dict[str, Any] = copy.deepcopy(load(path)["document"])
        if doc["decisions"]:
            doc["refusals"] = [{"reasons": [code], "reason_vocabulary_version": label}]
            return doc
    raise AssertionError("no journal fixture")


def _codes(doc: dict[str, Any]) -> list[str]:
    return [f.code for f in identity._reason_registry(doc).findings]


def test_invalid_manifest_is_registered_in_02_only() -> None:
    assert "invalid_manifest" in data.registry_codes(V02)
    assert "invalid_manifest" not in data.registry_codes(V01)
    assert len(data.registry_codes(V02)) == 164


def test_a_refusal_row_with_invalid_manifest_under_02_is_not_refuted() -> None:
    assert _codes(_doc_with_refusal("invalid_manifest", V02)) == []


def test_invalid_manifest_under_a_01_label_is_still_refused() -> None:
    assert _codes(_doc_with_refusal("invalid_manifest", V01)) == ["reason_code_unregistered"]


def test_an_unknown_code_under_02_is_still_refuted() -> None:
    assert _codes(_doc_with_refusal("invalid_manifest_x", V02)) == ["reason_code_unregistered"]

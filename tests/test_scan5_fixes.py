"""Review scan 5: claim-boundary file coverage (C-T1-1), lookalike table and rule list (C-T2-4),
refusal-reason binding evidence (C-T2-1).

The forbidden words below are assembled at run time so this file does not itself contain them.
"""

from __future__ import annotations

import copy
import importlib.util
import shutil
import sys
from pathlib import Path
from typing import Any

import pytest

from cognous_verify import documents

from .helpers import fixture_paths, load, real_record, real_run_names

ROOT = Path(__file__).resolve().parent.parent


def W(text: str) -> str:
    """Drop the | markers that keep the forbidden wording out of this file's own source."""
    return text.replace("|", "")


def _load_script() -> Any:
    spec = importlib.util.spec_from_file_location(
        "check_claim_boundaries_scan5", ROOT / "scripts/check_claim_boundaries.py"
    )
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules["check_claim_boundaries_scan5"] = mod
    spec.loader.exec_module(mod)
    return mod


claims = _load_script()
CERT = "certi" + "fied"
PROD = "production" + "-ready"
CLAIM = f"The tool is {PROD} and {CERT}.\n"


def _tree(tmp_path: Path) -> Path:
    (tmp_path / "scripts").mkdir()
    shutil.copy(ROOT / "release-state.json", tmp_path / "release-state.json")
    (tmp_path / "scripts" / "claim_boundaries_allowlist.json").write_text(
        '{"excluded_paths": [], "allowed": []}'
    )
    (tmp_path / "docs").mkdir()
    return tmp_path


# ---- C-T1-1: every non-binary file is read -------------------------------------------------


@pytest.mark.parametrize(
    "name",
    ["NOTES.MD", "NOTES", "notes.mdx", "notes.tex", "notes.ipynb", "Notes.Txt", "notes.weird"],
)
def test_a_claim_in_any_text_file_name_is_found(tmp_path: Path, name: str) -> None:
    root = _tree(tmp_path)
    (root / "docs" / name).write_text(CLAIM, encoding="utf-8")
    code, msgs = claims.run(root)
    assert code == 1, msgs
    assert any(f"docs/{name}:1" in m for m in msgs), msgs


def test_binary_and_undecodable_unknown_files_are_skipped(tmp_path: Path) -> None:
    root = _tree(tmp_path)
    (root / "docs" / "blob").write_bytes(b"\x00\x01" + CLAIM.encode())
    (root / "docs" / "latin1").write_bytes(b"caf\xe9 " + CLAIM.encode())
    (root / "docs" / "image.png").write_bytes(CLAIM.encode())
    assert claims.run(root)[0] == 0


def test_a_known_text_suffix_in_upper_case_must_still_decode(tmp_path: Path) -> None:
    root = _tree(tmp_path)
    (root / "docs" / "NOTES.MD").write_bytes(b"caf\xe9\n")
    code, msgs = claims.run(root)
    assert code == 1 and any("undecodable" in m for m in msgs), msgs


def test_the_repository_still_passes_with_the_same_excused_matches() -> None:
    code, msgs = claims.run(ROOT)
    assert code == 0, msgs
    assert "2 excused matches" in msgs[-1], msgs


# ---- C-T2-4: lookalike table and rule list ---------------------------------------------------

SMALL_CAPS = {
    "ᴀ": "a", "ʙ": "b", "ᴄ": "c", "ᴅ": "d", "ᴇ": "e", "ꜰ": "f",
    "ɢ": "g", "ʜ": "h", "ɪ": "i", "ᴊ": "j", "ᴋ": "k", "ʟ": "l",
    "ᴍ": "m", "ɴ": "n", "ᴏ": "o", "ᴘ": "p", "ꞯ": "q", "ʀ": "r",
    "ꜱ": "s", "ᴛ": "t", "ᴜ": "u", "ᴠ": "v", "ᴡ": "w", "ʏ": "y",
    "ᴢ": "z",
}  # fmt: skip
CYRILLIC_MORE = {"ѵ": "v", "м": "m", "н": "h", "т": "t", "в": "b",
                 "ь": "b", "г": "r", "п": "n", "ү": "y"}  # fmt: skip
GREEK_MORE = {"τ": "t", "η": "n", "γ": "y", "ϲ": "c", "ς": "c",
              "β": "b", "ϳ": "j"}  # fmt: skip
ARMENIAN = {"ս": "u", "օ": "o", "ո": "n", "ց": "g", "հ": "h",
            "ք": "p"}  # fmt: skip
IPA = {"ɑ": "a", "ɩ": "i"}
WORDS = [
    CERT,
    "complian" + "ce",
    PROD,
    "production-" + "quality",
    "audit-" + "worthy",
    "certi" + "fies",
]


@pytest.mark.parametrize(
    "table",
    [SMALL_CAPS, CYRILLIC_MORE, GREEK_MORE, ARMENIAN, IPA],
    ids=["small-capitals", "cyrillic", "greek", "armenian", "ipa"],
)
def test_every_added_lookalike_folds_to_its_latin_letter(table: dict[str, str]) -> None:
    for ch, latin in table.items():
        assert claims._fold_line(ch) == latin, (hex(ord(ch)), latin)


@pytest.mark.parametrize(
    "table",
    [SMALL_CAPS, CYRILLIC_MORE, GREEK_MORE, ARMENIAN, IPA],
    ids=["small-capitals", "cyrillic", "greek", "armenian", "ipa"],
)
def test_a_claim_word_written_with_an_added_lookalike_is_found(table: dict[str, str]) -> None:
    covered = 0
    for ch, latin in table.items():
        word = next((w for w in WORDS if latin in w), None)
        if word is None:
            continue
        covered += 1
        text = word.replace(latin, ch, 1)
        assert claims.scan_text("x.md", text), (hex(ord(ch)), text)
    assert covered


def test_the_named_small_capital_examples_are_found() -> None:
    assert claims.scan_text("x.md", "\u1d04" + W("ertif|ied"))
    assert claims.scan_text("x.md", W("c\u1d07rti|fied"))
    assert claims.scan_text("x.md", "\ua730" + W("it for prod|uction"))  # small-cap f
    assert claims.scan_text("x.md", W("prod|uction-read\u028f"))


@pytest.mark.parametrize(
    "text",
    [
        W("ready for pr|od"),
        W("Ready for dep|loyment"),
        W("dep|loy-ready"),
        W("dep|loyment ready"),
        W("approved for dep|loyment"),
        W("cleared for dep|loy"),
        W("dep|loyment approved"),
        W("dep|loy cleared"),
        W("pr|od ready"),
        W("suitable for pr|od"),
    ],
)
def test_deploy_and_prod_forms_are_found(text: str) -> None:
    assert claims.scan_text("x.md", text), text


@pytest.mark.parametrize(
    "text",
    [
        "ready for prodigy",
        "the deployment approvals table",
        "deployed and ready to read",
        "deploy readiness is not asserted",
        "product ready check",
        "a prodrome",
        "reproduction ready",
        "not for production use",
    ],
)
def test_deploy_and_prod_rules_leave_plain_wording_alone(text: str) -> None:
    assert not claims.scan_text("x.md", text), text


# ---- C-T2-1: how refusal reasons relate to effect-stage check reasons ------------------------
# Decision (docs/tiers.md, 2026-10-22): behaviour is not changed. The captured real run keeps
# equal reasons, but the valid fixtures show profile refusals that legitimately differ (an expiry
# refusal carries check_expired_before_dispatch while its effect-stage check lists no reasons).


def _exact(xs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [{k: v for k, v in x.items() if k != "extensions"} for x in xs]


def _pairs(doc: dict[str, Any]) -> list[tuple[list[str], list[list[str]]]]:
    out = []
    for r in doc.get("refusals", []):
        checks = [
            c["reasons"]
            for c in doc["resolution_checks"]
            if c["stage"] == "effect" and _exact(c["inputs"]) == _exact(r["resolution_inputs"])
        ]
        out.append((r["reasons"], checks))
    return out


def test_every_captured_real_run_refusal_equals_its_check_reasons() -> None:
    seen = 0
    for name in real_run_names():
        path = Path(__file__).parent / "data" / "real-runs" / name / "bounded-run-record.json"
        if not path.exists():
            continue
        for reasons, checks in _pairs(real_record(name)):
            seen += 1
            assert any(sorted(reasons) == sorted(c) for c in checks), (name, reasons, checks)
    assert seen >= 1


def test_valid_fixtures_differ_only_by_the_expiry_refusal_pattern() -> None:
    differing = 0
    for path in fixture_paths("journal", "valid"):
        for reasons, checks in _pairs(load(path)["document"]):
            if any(sorted(reasons) == sorted(c) for c in checks):
                continue
            differing += 1
            assert reasons == ["check_expired_before_dispatch"] and checks == [[]], (
                path.stem,
                reasons,
                checks,
            )
    assert differing >= 1


def test_refusal_reasons_are_not_bound_to_the_check_reasons_today() -> None:
    """Pins the documented narrower binding so that changing it has to say why."""
    doc = copy.deepcopy(real_record("journal-effect-time-refusal"))
    assert doc["refusals"][0]["reasons"] == ["required_input_not_read", "status_unreadable"]
    doc["refusals"][0]["reasons"] = ["status_unreadable"]
    results = documents.verify_document(doc)
    assert not any(r.verdict == "refuted" or r.error for r in results)

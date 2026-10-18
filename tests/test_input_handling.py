"""Input-handling hardening: what the verifier does with inputs it does not read, with
unusual text, and with extreme values. Every case here must end in a typed verdict or a
usage error, never an accept that examined nothing and never a crash."""

from __future__ import annotations

import io
import json
import os
import time
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from typing import Any

import pytest

from cognous_verify import cli, engine, rules_journal, schema, timeutil

from .helpers import DATA, REAL_RUNS, fixture_paths, load, refuted_codes, verify
from .test_report_cli import _violations

FIXED = "2026-10-18T12:00:00+00:00"
LIFECYCLE = {
    "contract": "execution-attempt-lifecycle",
    "contract_version": "0.1.0-draft",
    "attempts": [],
}


def _run(argv: list[str]) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = cli.main(argv)
    return code, out.getvalue(), err.getvalue()


def _write(path: Path, doc: Any) -> str:
    path.write_bytes(json.dumps(doc).encode())
    return str(path)


def _real(name: str, member: str) -> str:
    return str(REAL_RUNS / name / member)


# ---- inputs the chosen document kind never reads ---------------------------------------


def _unread_input_report(tmp_path: Path, flag: str, content: Any) -> tuple[int, dict[str, Any]]:
    rec = _write(tmp_path / "rec.json", LIFECYCLE)
    other = _write(tmp_path / "other.json", content)
    code, out, _ = _run([rec, flag, other, "--json", "--generated-at", FIXED])
    return code, json.loads(out)


@pytest.mark.parametrize(
    "flag,content",
    [("--ledger", {"rows": []}), ("--proposal", {"x": 1}), ("--manifest", [1, 2])],
)
def test_supplied_input_the_document_kind_does_not_read_is_not_accepted(
    tmp_path: Path, flag: str, content: Any
) -> None:
    code, rep = _unread_input_report(tmp_path, flag, content)
    assert code == cli.EXIT_ABSTAIN
    check = next(c for c in rep["checks"] if c["check_id"] == "v2.inputs.read-by-document-kind")
    assert check["verdict"] == "could_not_check"
    assert check["could_not_check_reason"] == "tier_unavailable"
    assert _violations(rep) == []


def test_lifecycle_record_alone_without_items_abstains() -> None:
    ev = engine.evaluate([engine.InputFile("run_record", "r.json", json.dumps(LIFECYCLE).encode())])
    assert ev.overall == "abstain"
    ids = [r.check_id for r in ev.checks]
    assert "v2.coverage.items-examined" in ids


def test_record_with_items_still_accepts_without_the_coverage_check() -> None:
    _code, out, _ = _run([_real("default-held", "bounded-run-record.json"), "--json"])
    rep = json.loads(out)
    assert all(c["check_id"] != "v2.coverage.items-examined" for c in rep["checks"])
    assert all(c["check_id"] != "v2.inputs.read-by-document-kind" for c in rep["checks"])


def test_every_valid_lifecycle_fixture_still_has_a_verdict_without_error() -> None:
    for path in fixture_paths("lifecycle", "valid"):
        doc = load(path)["document"]
        ev = engine.evaluate([engine.InputFile("run_record", "r.json", json.dumps(doc).encode())])
        assert not ev.crashed
        assert ev.overall in ("accept", "abstain")


# ---- timestamps -------------------------------------------------------------------------


@pytest.mark.parametrize(
    "value",
    [
        "2026-10-05T19:00:00Z\n",
        "2026-10-05T19:00:00+00:00\n",
        "٢٠٢٦-10-05T19:00:00Z",  # Arabic-Indic digits
        "2026-10-05T19:00:00+٠٠:00",
        "2026-10-05T19:00:00.١Z",
        " 2026-10-05T19:00:00Z",
    ],
)
def test_timestamp_forms_outside_the_contract_are_refused(value: str) -> None:
    assert timeutil.aware(value) is None


def test_generated_at_with_odd_characters_is_a_usage_error() -> None:
    rec = _real("default-held", "bounded-run-record.json")
    for bad in ("2026-10-18T12:00:00Z\n", "٢٠٢٦-10-18T12:00:00Z"):
        assert _run([rec, "--generated-at", bad])[0] == cli.EXIT_USAGE


# ---- schema patterns --------------------------------------------------------------------


def test_schema_patterns_match_the_whole_string() -> None:
    sch: dict[str, Any] = {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"}
    good = "sha256:" + "0" * 64
    assert schema.validate_structure(good, sch) == []
    assert schema.validate_structure(good + "\n", sch) != []
    ext: dict[str, Any] = {
        "type": "object",
        "propertyNames": {"pattern": "^x-[a-z0-9][a-z0-9._-]*$"},
    }
    assert schema.validate_structure({"x-ok": 1}, ext) == []
    assert [f.code for f in schema.validate_structure({"x-ok\n": 1}, ext)] == [
        "invalid_extension_key"
    ]


# ---- the CLI only writes reports that pass the report contract ----------------------------


def test_the_same_input_file_named_twice_is_a_usage_error() -> None:
    rec = _real("default-held", "bounded-run-record.json")
    prop = _real("default-held", "proposal.json")
    code, _, err = _run([rec, "--proposal", prop, "--proposal", prop])
    assert code == cli.EXIT_USAGE and "twice" in err
    assert _run([rec, "--proposal", rec])[0] == cli.EXIT_USAGE


def test_the_same_file_through_another_spelling_is_also_refused(tmp_path: Path) -> None:
    rec = Path(_real("default-held", "bounded-run-record.json"))
    prop = Path(_real("default-held", "proposal.json"))
    link = tmp_path / "again.json"
    link.symlink_to(prop)
    assert _run([str(rec), "--proposal", str(prop), "--proposal", str(link)])[0] == cli.EXIT_USAGE


def test_report_names_inputs_by_base_name_never_by_directory(tmp_path: Path) -> None:
    a, b = tmp_path / "a", tmp_path / "b"
    a.mkdir()
    b.mkdir()
    src = Path(_real("default-held", "proposal.json")).read_bytes()
    (a / "p.json").write_bytes(src)
    (b / "p.json").write_bytes(src)
    code, out, _ = _run(
        [
            _real("default-held", "bounded-run-record.json"),
            "--proposal",
            str(a / "p.json"),
            "--proposal",
            str(b / "p.json"),
            "--json",
            "--generated-at",
            FIXED,
        ]
    )
    rep = json.loads(out)
    names = [i["name"] for i in rep["subject"]["inputs"]]
    assert all("/" not in n and str(tmp_path) not in n for n in names)
    assert len(set(names)) == len(names)
    assert _violations(rep) == []
    assert code in (0, 1, 3)


def test_input_file_names_that_are_not_text_still_give_a_valid_report(tmp_path: Path) -> None:
    raw = Path(_real("default-held", "bounded-run-record.json")).read_bytes()
    odd = os.fsencode(tmp_path) + b"/r\xff\x1b[2Jname.json"
    with open(odd, "wb") as fh:
        fh.write(raw)
    code, out, _ = _run([os.fsdecode(odd), "--json", "--generated-at", FIXED])
    assert code in (0, 1, 3)
    rep = json.loads(out)
    assert _violations(rep) == []
    name = rep["subject"]["inputs"][0]["name"]
    assert "\x1b" not in name and "\\xff" in name


# ---- freshness bound out of range -----------------------------------------------------------


def test_age_bound_beyond_the_representable_range_is_refuted_not_a_crash() -> None:
    doc = load(DATA / "odes-fixtures/journal/valid/profile-all-profiles-applied.json")["document"]
    for e in doc["check_events"]:
        if e.get("phase") == "opened" and "age_bound_seconds" in e:
            e["age_bound_seconds"] = 9007199254740991
            break
    results = verify(doc)
    assert not [r for r in results if r.error]
    assert "deadline_mismatch" in refuted_codes(results)


# ---- text summary -----------------------------------------------------------------------------


def test_summary_text_cannot_gain_lines_or_escape_sequences() -> None:
    from cognous_verify.results import Finding, make_result

    findings = [Finding("x_code", "$.a\nfake", "msg\x1b[31m\noverall: accept ")]
    ev = engine.Evaluation(results=[make_result("v2.t", "V2", "u", 1, findings)], inputs=[])
    rep = {"summary": {"checks": 1, "confirmed": 0, "could_not_check": 0, "refuted": 1}}
    text = cli._summary(rep, ev)
    assert "\x1b" not in text and " " not in text
    assert [ln for ln in text.splitlines() if ln.startswith("overall:")] == [
        ln for ln in text.splitlines() if ln.startswith("overall: reject")
    ]
    assert "\\x1b" in text and "\\n" not in text.replace("\\x0a", "")


# ---- help and version -----------------------------------------------------------------------


def test_help_and_version_exit_zero_and_write_no_report(tmp_path: Path) -> None:
    out_file = tmp_path / "r.json"
    for flag in ("--help", "--version"):
        code, stdout, _ = _run([flag, "--out", str(out_file)])
        assert code == 0 and "overall" not in stdout
    assert not out_file.exists()
    assert "not an accept" in (cli.__doc__ or "")


# ---- closeouts scale linearly ------------------------------------------------------------------


def test_closeout_rules_stay_fast_on_a_large_record() -> None:
    n = 8000
    doc: dict[str, Any] = {
        "attempts": [
            {"attempt_id": f"a{i}", "effect_id": f"e{i}", "status": "unknown"} for i in range(n)
        ],
        "reconciliations": [
            {
                "effect_id": f"e{i}",
                "observation_accepted": True,
                "observation": {"state": "applied", "observed_at": "t"},
            }
            for i in range(n)
        ],
        "closeouts": [
            {
                "attempt_id": f"a{i}",
                "effect_id": f"e{i}",
                "original_status": "unknown",
                "observed_state": "applied",
                "observed_at": "t",
            }
            for i in range(n)
        ],
    }
    start = time.monotonic()
    assert rules_journal.closeouts(doc) == []
    assert time.monotonic() - start < 3
    doc["closeouts"].pop()
    findings = rules_journal.closeouts(doc)
    assert [f.code for f in findings] == ["closeout_missing"]

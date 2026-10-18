"""Reports are checked against the ODES verification-report contract's own validator."""

from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import sys
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from cognous_verify import cli, engine, report
from cognous_verify.results import make_result, verifier_error

from . import damage
from .damage import LEDGER, MANIFEST, PROPOSAL, RECORD, ROLE_OF
from .helpers import DATA, REAL_RUNS

ORACLE_DIR = DATA / "verification-report"


def _oracle() -> ModuleType:
    spec = importlib.util.spec_from_file_location("odes_report_oracle", ORACLE_DIR / "validate.py")
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


ORACLE = _oracle()
CASES = damage.load_corpus()
FIXED = "2026-10-18T12:00:00+00:00"


def _eval(case: damage.Case, roles: tuple[str, ...] = (RECORD, PROPOSAL, MANIFEST, LEDGER)) -> Any:
    return engine.evaluate(
        [engine.InputFile(ROLE_OF[r], r + ".json", case.files[r]) for r in roles]
    )


def _violations(doc: dict[str, Any]) -> list[str]:
    return [f"{v.code} {v.path}" for v in ORACLE.validate(doc)]


def test_oracle_copy_matches_its_recorded_digest() -> None:
    src = json.loads((ORACLE_DIR / "SOURCE.json").read_text())
    for name, digest in src["sha256"].items():
        assert hashlib.sha256((ORACLE_DIR / name).read_bytes()).hexdigest() == digest


@pytest.mark.parametrize("case", CASES, ids=[c.name for c in CASES])
def test_report_for_every_clean_run_conforms(case: damage.Case) -> None:
    for roles in ((RECORD,), (RECORD, PROPOSAL), (RECORD, PROPOSAL, MANIFEST, LEDGER)):
        rep = report.build(_eval(case, roles), generated_at=FIXED)
        assert _violations(rep) == []
        assert ORACLE.overall_verdict(rep) == _eval(case, roles).overall


def test_report_for_damaged_traces_conforms_and_rejects() -> None:
    seen = 0
    for o in damage.OPERATORS:
        for c in CASES[:4]:
            m = o.fn(c, CASES)
            if m is None:
                continue
            ev = damage.evaluate_case(m)
            rep = report.build(ev, generated_at=FIXED)
            assert _violations(rep) == [], (o.name, c.name)
            assert ORACLE.overall_verdict(rep) == ev.overall
            seen += 1
    assert seen > 100


def test_report_members_that_matter() -> None:
    rep = report.build(_eval(CASES[0]), generated_at=FIXED, controller_revision="abc123")
    assert rep["verifier"]["canonicalization_profile"].endswith("python-semantics-v0.1")
    assert rep["subject"]["pinned"]["controller_revision"] == "abc123"
    assert rep["scope"]["semantic_quality"] == "not_assessed"
    assert rep["mutation_report"] is None
    assert {n["id"] for n in rep["does_not_prove"]} == {i for i, _ in report.NON_CLAIMS}
    assert len(rep["does_not_prove"]) == 8
    assert "score" not in json.dumps(rep).replace("not a score", "")
    # undeclared revisions are stated, not invented
    plain = report.build(_eval(CASES[0]), generated_at=FIXED)
    assert plain["subject"]["pinned"]["controller_revision"] == "unstated"
    assert plain["verifier"]["source_revision"] == "unstated"


def test_report_is_deterministic_for_fixed_time() -> None:
    a = report.build(_eval(CASES[0]), generated_at=FIXED)
    b = report.build(_eval(CASES[0]), generated_at=FIXED)
    assert a == b


def test_reason_mapping_is_closed() -> None:
    assert report.reason_member(None) is None
    for raw, want in [
        ("input_absent:destination_ledger", "input_absent"),
        ("tier_unavailable:x", "tier_unavailable"),
        ("decision_has_no_supplied_proposal", "input_absent"),
        ("no_items_in_record", "not_applicable_to_input"),
        ("earlier_rules_refuted", "tier_unavailable"),
        ("something_new", "tier_unavailable"),
    ]:
        assert report.reason_member(raw) == want


def test_a_crashed_evaluation_produces_no_report() -> None:
    ev = engine.Evaluation(
        results=[verifier_error("v2.x", "V2", "u", 0, RuntimeError("boom"))], inputs=[]
    )
    with pytest.raises(ValueError):
        report.build(ev)


def test_refuted_check_with_skips_keeps_reason_and_findings() -> None:
    from cognous_verify.results import Finding

    r = make_result(
        "v2.x",
        "V2",
        "u",
        3,
        [Finding("bad_thing", "$.a[0]", "m")],
        skipped=1,
        reason="input_absent:x",
    )
    m = report.check_member(r)
    assert m["verdict"] == "refuted" and m["could_not_check_reason"] == "input_absent"
    assert m["tally"] == {"confirmed": 1, "could_not_check": 1, "refuted": 1, "n": 3}


# --- CLI ----------------------------------------------------------------------------------


def _run(argv: list[str]) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = cli.main(argv)
    return code, out.getvalue(), err.getvalue()


def _args(name: str) -> list[str]:
    d = REAL_RUNS / name
    return [
        str(d / "bounded-run-record.json"),
        "--proposal",
        str(d / "proposal.json"),
        "--manifest",
        str(d / "manifest.json"),
        "--ledger",
        str(d / "destination.json"),
    ]


def test_cli_accepts_a_clean_run_and_writes_a_conforming_report(tmp_path: Path) -> None:
    out = tmp_path / "r.json"
    code, stdout, _ = _run([*_args("journal-applied"), "--out", str(out), "--generated-at", FIXED])
    assert code == cli.EXIT_ACCEPT
    assert "overall: accept" in stdout
    assert _violations(json.loads(out.read_text())) == []


def test_cli_json_prints_only_the_report() -> None:
    code, stdout, _ = _run([*_args("default-held"), "--json", "--generated-at", FIXED])
    assert code == 0
    assert _violations(json.loads(stdout)) == []


def test_cli_exit_one_when_refuted(tmp_path: Path) -> None:
    bad = tmp_path / "rec.json"
    bad.write_bytes(b'{"a": 1, "a": 2}')
    code, stdout, _ = _run([str(bad)])
    assert code == cli.EXIT_REFUTED and "REFUTED" in stdout and "wire_duplicate_member" in stdout


def test_cli_exit_three_when_only_abstaining() -> None:
    code, stdout, _ = _run([_args("journal-applied")[0]])
    assert code == cli.EXIT_ABSTAIN and "overall: abstain" in stdout


def test_cli_usage_and_input_errors(tmp_path: Path) -> None:
    assert _run([])[0] == cli.EXIT_USAGE
    assert _run([str(tmp_path / "missing.json")])[0] == cli.EXIT_USAGE
    assert _run([_args("default-held")[0], "--generated-at", "yesterday"])[0] == cli.EXIT_USAGE
    code, out, _ = _run(["--version"])
    assert code == 0 and "cognous-verify 0.1.0" in out


def test_cli_refuses_to_overwrite_an_input() -> None:
    rec = _args("default-held")[0]
    before = Path(rec).read_bytes()
    code, _, err = _run([rec, "--out", rec])
    assert code == cli.EXIT_USAGE and "names an input" in err
    assert Path(rec).read_bytes() == before


def test_cli_unwritable_out_is_a_usage_error(tmp_path: Path) -> None:
    code, _, err = _run(
        [_args("default-held")[0], "--out", str(tmp_path / "no" / "dir" / "r.json")]
    )
    assert code == cli.EXIT_USAGE and "cannot write" in err


def test_cli_crash_writes_no_report(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(files: Any) -> Any:
        raise RuntimeError("boom")

    monkeypatch.setattr(engine, "evaluate", boom)
    out = tmp_path / "r.json"
    code, _, err = _run([_args("default-held")[0], "--out", str(out)])
    assert code == cli.EXIT_CRASH and not out.exists() and "no report" in err


def test_cli_internal_check_error_writes_no_report(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    real = engine.evaluate

    def with_error(files: Any) -> Any:
        ev = real(files)
        ev.results.append(verifier_error("v2.x", "V2", "u", 0, RuntimeError("boom")))
        return ev

    monkeypatch.setattr(engine, "evaluate", with_error)
    out = tmp_path / "r.json"
    code, _, _ = _run([_args("default-held")[0], "--out", str(out)])
    assert code == cli.EXIT_CRASH and not out.exists()


def test_cli_names_colliding_inputs_by_path(tmp_path: Path) -> None:
    a, b = tmp_path / "a", tmp_path / "b"
    a.mkdir()
    b.mkdir()
    src = REAL_RUNS / "default-held" / "proposal.json"
    (a / "p.json").write_bytes(src.read_bytes())
    (b / "p.json").write_bytes(src.read_bytes())
    code, stdout, _ = _run(
        [
            _args("default-held")[0],
            "--proposal",
            str(a / "p.json"),
            "--proposal",
            str(b / "p.json"),
            "--json",
            "--generated-at",
            FIXED,
        ]
    )
    rep = json.loads(stdout)
    assert _violations(rep) == []
    assert len({i["name"] for i in rep["subject"]["inputs"]}) == 3
    assert code in (0, 1, 3)


def test_cli_has_no_label_or_expected_outcome_option() -> None:
    help_text = cli._parser().format_help().lower()
    for word in ("label", "expected", "outcome", "ground", "truth", "score"):
        assert word not in help_text.replace("not a score", "").replace("no score", "")


def test_oversize_input_is_refused_not_read_whole(tmp_path: Path) -> None:
    big = tmp_path / "big.json"
    big.write_bytes(b" " * (8 * 1024 * 1024 + 10))
    code, stdout, _ = _run([str(big)])
    assert code == cli.EXIT_REFUTED and "wire_too_large" in stdout

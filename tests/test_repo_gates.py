"""Repository gates: claim boundary, release HOLD, pinned CI, no network, no import of the stack."""

from __future__ import annotations

import importlib.util
import json
import re
import socket
import sys
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parent.parent


def _load(name: str, rel: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, ROOT / rel)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


claims = _load("check_claim_boundaries", "scripts/check_claim_boundaries.py")


def test_release_state_is_on_hold() -> None:
    state = claims.read_state(ROOT)
    assert state["publication_authorized"] is False
    assert state["production_authorized"] is False
    assert claims.on_hold(state)


def test_the_repository_passes_its_own_claim_boundary_check() -> None:
    code, msgs = claims.run(ROOT)
    assert code == 0, msgs


def test_claim_rules_catch_variants() -> None:
    cases = [
        "This is Certified.",
        "fully compliant",
        "production-ready",
        "Production   Ready",
        "ready for production",
        "enterprise‑grade",
        "cert​ified",
        "ＣＥＲＴＩＦＩＥＤ",
    ]
    for text in cases:
        assert claims.scan_text("x.md", text), text
    for text in ["semantic_quality_not_certified", "a complement", "reproduction ready"]:
        assert not claims.scan_text("x.md", text), text


def _tree(tmp_path: Path, readme: str, state: str | None, allow: str | None = None) -> Path:
    (tmp_path / "scripts").mkdir()
    (tmp_path / "README.md").write_text(readme, encoding="utf-8")
    if state is not None:
        (tmp_path / "release-state.json").write_text(state, encoding="utf-8")
    default = '{"excluded_paths": [], "allowed": []}'
    (tmp_path / "scripts" / "claim_boundaries_allowlist.json").write_text(allow or default)
    return tmp_path


def test_a_claim_fails_while_on_hold(tmp_path: Path) -> None:
    state = (ROOT / "release-state.json").read_text()
    root = _tree(tmp_path, "The verifier is production-ready.\n", state)
    code, msgs = claims.run(root)
    assert code == 1 and "README.md:1" in msgs[0]


@pytest.mark.parametrize("state", [None, "{", '{"schema": 1}', "[]"])
def test_missing_or_malformed_state_counts_as_hold(tmp_path: Path, state: str | None) -> None:
    root = _tree(tmp_path, "certified\n", state)
    code, msgs = claims.run(root)
    assert code == 1 and msgs[0].startswith("HOLD assumed")


def test_non_boolean_authorization_is_malformed(tmp_path: Path) -> None:
    state = json.loads((ROOT / "release-state.json").read_text())
    state["publication_authorized"] = "yes"
    root = _tree(tmp_path, "certified\n", json.dumps(state))
    assert claims.run(root)[0] == 1


def test_stale_allowlist_entries_are_errors(tmp_path: Path) -> None:
    state = (ROOT / "release-state.json").read_text()
    allow = json.dumps(
        {
            "excluded_paths": [],
            "allowed": [{"path": "README.md", "rule": "certified", "line": "gone", "reason": "x"}],
        }
    )
    root = _tree(tmp_path, "nothing here\n", state, allow)
    code, msgs = claims.run(root)
    assert code == 1 and msgs[0].startswith("stale allow-list entry")


def test_exact_allowlist_entry_excuses_a_match(tmp_path: Path) -> None:
    state = (ROOT / "release-state.json").read_text()
    allow = json.dumps(
        {
            "excluded_paths": [],
            "allowed": [
                {
                    "path": "README.md",
                    "rule": "certified",
                    "line": "not certified.",
                    "reason": "negation",
                }
            ],
        }
    )
    root = _tree(tmp_path, "not certified.\n", state, allow)
    assert claims.run(root)[0] == 0


def test_authorized_state_stops_enforcing(tmp_path: Path) -> None:
    state = json.loads((ROOT / "release-state.json").read_text())
    state["publication_authorized"] = state["production_authorized"] = True
    root = _tree(tmp_path, "certified\n", json.dumps(state))
    code, msgs = claims.run(root)
    assert code == 0 and "not enforced" in msgs[0]


@pytest.mark.parametrize(
    "bad",
    [
        '{"excluded_paths": []}',
        '{"excluded_paths": [{"path": "a"}], "allowed": []}',
        '{"excluded_paths": [], "allowed": [{"path": "a", "rule": "nope", "line": "l", "reason": "r"}]}',
    ],
)
def test_malformed_allowlists_are_refused(tmp_path: Path, bad: str) -> None:
    root = _tree(tmp_path, "x\n", (ROOT / "release-state.json").read_text(), bad)
    with pytest.raises(ValueError):
        claims.run(root)


# --- CI -----------------------------------------------------------------------------------


def test_workflow_pins_runner_and_actions_by_sha() -> None:
    text = (ROOT / ".github/workflows/ci.yml").read_text()
    assert "ubuntu-latest" not in re.findall(r"runs-on:\s*(\S+)", text)
    assert re.search(r"runs-on: ubuntu-24\.04\b", text)
    uses = re.findall(r"^\s*-?\s*uses:\s*(\S+)", text, flags=re.M)
    assert uses
    for ref in uses:
        assert re.fullmatch(r"[\w.-]+/[\w./-]+@[0-9a-f]{40}", ref), ref
    for version in ("3.11", "3.12", "3.13"):
        assert f'"{version}"' in text
    assert "make check" in text


def test_workflow_has_no_publish_step_and_read_only_permissions() -> None:
    text = (ROOT / ".github/workflows/ci.yml").read_text()
    assert "contents: read" in text
    for word in ("twine", "pypi", "gh release", "git tag", "upload-artifact"):
        assert word not in text.lower()


def test_network_is_disabled_in_tests() -> None:
    with pytest.raises(Exception, match=r"(?i)socket"):
        socket.create_connection(("127.0.0.1", 9), timeout=0.1)


def test_package_declares_no_runtime_dependency_and_one_command() -> None:
    import tomllib

    meta = tomllib.loads((ROOT / "pyproject.toml").read_text())
    assert meta["project"]["dependencies"] == []
    assert meta["project"]["scripts"] == {"cognous-verify": "cognous_verify.cli:main"}
    assert meta["project"]["name"] == "cognous-open-control-stack-verifier"
    assert meta["project"]["requires-python"].startswith(">=3.11")

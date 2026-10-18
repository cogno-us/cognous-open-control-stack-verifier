"""Hard properties: standard library only, nothing imported from the stack."""

from __future__ import annotations

import ast
import subprocess
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src" / "cognous_verify"
# Top-level names of the stack's components (and anything that would couple the verifier to them).
BANNED = {
    "agent_control_plane",
    "agent_replay_bundle",
    "agent_governance_evidence_pack",
    "agent_action_manifest",
    "engine",
    "odes",
    "app",
    "ocs",
    "pydantic",
    "jsonschema",
}
DYNAMIC_NAMES = {"__import__", "exec", "eval", "compile"}
DYNAMIC_ATTRS = {"import_module", "find_spec", "__import__"}


def _imports(path: Path) -> list[tuple[str, int]]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    found: list[tuple[str, int]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found += [(a.name.split(".")[0], node.lineno) for a in node.names]
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                found.append(("cognous_verify", node.lineno))
            elif node.module:
                found.append((node.module.split(".")[0], node.lineno))
    return found


def _dynamic_uses(path: Path) -> list[tuple[str, int]]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    hits: list[tuple[str, int]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            fn = node.func
            if isinstance(fn, ast.Name) and fn.id in DYNAMIC_NAMES:
                hits.append((fn.id, node.lineno))
            elif isinstance(fn, ast.Attribute) and fn.attr in DYNAMIC_ATTRS:
                hits.append((fn.attr, node.lineno))
    return hits


def test_runtime_dependencies_are_empty() -> None:
    data = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert data["project"]["dependencies"] == []
    assert data["build-system"]["requires"] == ["hatchling>=1.25"]


def test_package_imports_only_the_standard_library() -> None:
    allowed = set(sys.stdlib_module_names) | {"cognous_verify", "__future__"}
    offenders = []
    for path in sorted(SRC.rglob("*.py")):
        for name, line in _imports(path):
            if name not in allowed:
                offenders.append(f"{path.relative_to(ROOT)}:{line} imports {name}")
    assert offenders == []


def test_package_imports_nothing_from_the_stack() -> None:
    offenders = []
    for path in sorted(SRC.rglob("*.py")):
        for name, line in _imports(path):
            if name in BANNED:
                offenders.append(f"{path.relative_to(ROOT)}:{line} imports {name}")
    assert offenders == []


def test_no_dynamic_import_or_code_execution_in_package() -> None:
    offenders = []
    for path in sorted(SRC.rglob("*.py")):
        for name, line in _dynamic_uses(path):
            offenders.append(f"{path.relative_to(ROOT)}:{line} calls {name}")
    assert offenders == []


def test_tests_do_not_import_the_stack_either() -> None:
    offenders = []
    for path in sorted((ROOT / "tests").glob("*.py")):
        for name, line in _imports(path):
            if name in BANNED:
                offenders.append(f"{path.relative_to(ROOT)}:{line} imports {name}")
    assert offenders == []


def test_import_banned_names_are_detected(tmp_path: Path) -> None:
    probe = tmp_path / "probe.py"
    probe.write_text(
        "import agent_control_plane\nfrom odes.x import y\nimport importlib\n"
        "importlib.import_module('engine')\n__import__('pydantic')\n",
        encoding="utf-8",
    )
    names = {n for n, _ in _imports(probe)}
    assert {"agent_control_plane", "odes", "importlib"} <= names
    assert {n for n, _ in _dynamic_uses(probe)} == {"import_module", "__import__"}


def test_importing_the_package_loads_no_stack_module() -> None:
    code = (
        "import sys, cognous_verify, cognous_verify.wire, cognous_verify.canon\n"
        "bad = sorted(m for m in sys.modules if m.split('.')[0] in " + repr(sorted(BANNED)) + ")\n"
        "assert not bad, bad\n"
    )
    result = subprocess.run(
        [sys.executable, "-I", "-c", code], capture_output=True, text=True, check=False
    )
    assert result.returncode == 0, result.stderr

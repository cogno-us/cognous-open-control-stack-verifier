"""Vendored data: contract schemas and the reason registry, read with the verifier's own parser.

The files under ``data/`` are copied, not imported, and ``data/PROVENANCE.json`` records where
each came from and its SHA-256. ``provenance_ok`` recomputes the hashes, so a changed file is
detected by a test and named in every report.
"""

from __future__ import annotations

import hashlib
from functools import cache
from pathlib import Path
from typing import Any

from . import wire

DATA_DIR = Path(__file__).resolve().parent / "data"
SCHEMA_FILES = {
    "control-plane-journal": "control-plane-journal.schema.json",
    "execution-attempt-lifecycle": "execution-attempt-lifecycle.schema.json",
}
REGISTRY_FILE = "runtime-authority-reasons-0.1.json"


@cache
def _read(name: str) -> tuple[Any, str]:
    raw = (DATA_DIR / name).read_bytes()
    return wire.parse(raw), "sha256:" + hashlib.sha256(raw).hexdigest()


def schema(contract: str) -> dict[str, Any]:
    value: dict[str, Any] = _read(SCHEMA_FILES[contract])[0]
    return value


def schema_digest(contract: str) -> str:
    return _read(SCHEMA_FILES[contract])[1]


def registry_codes() -> frozenset[str]:
    codes: dict[str, Any] = _read(REGISTRY_FILE)[0]["codes"]
    return frozenset(codes)


def registry_version() -> str:
    version: str = _read(REGISTRY_FILE)[0]["version"]
    return version


def registry_digest() -> str:
    return _read(REGISTRY_FILE)[1]


def provenance() -> dict[str, Any]:
    value: dict[str, Any] = _read("PROVENANCE.json")[0]
    return value


def provenance_problems() -> list[str]:
    """Files whose current hash differs from PROVENANCE.json (empty when all match)."""
    problems: list[str] = []
    for entry in provenance()["files"]:
        raw = (DATA_DIR / entry["file"]).read_bytes()
        if "sha256:" + hashlib.sha256(raw).hexdigest() != entry["sha256"]:
            problems.append(entry["file"])
    return problems

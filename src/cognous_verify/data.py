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
# Two registries, each resolved by the label a row carries (reason_vocabulary_version).
REGISTRY_FILES = {
    "runtime-authority-reasons/0.1": "runtime-authority-reasons-0.1.json",
    "runtime-authority-reasons/0.2": "runtime-authority-reasons-0.2.json",
}
DEFAULT_REGISTRY = "runtime-authority-reasons/0.1"
REGISTRY_FILE = REGISTRY_FILES[DEFAULT_REGISTRY]


@cache
def _read(name: str) -> tuple[Any, str]:
    raw = (DATA_DIR / name).read_bytes()
    return wire.parse(raw), "sha256:" + hashlib.sha256(raw).hexdigest()


def schema(contract: str) -> dict[str, Any]:
    value: dict[str, Any] = _read(SCHEMA_FILES[contract])[0]
    return value


def schema_digest(contract: str) -> str:
    return _read(SCHEMA_FILES[contract])[1]


def registry_labels() -> tuple[str, ...]:
    """The registry labels this verifier can resolve (the default, 0.1, first)."""
    return tuple(REGISTRY_FILES)


def registry_codes(label: str = DEFAULT_REGISTRY) -> frozenset[str]:
    codes: dict[str, Any] = _read(REGISTRY_FILES[label])[0]["codes"]
    return frozenset(codes)


def registry_all(label: str = DEFAULT_REGISTRY) -> dict[str, Any]:
    codes: dict[str, Any] = _read(REGISTRY_FILES[label])[0]["codes"]
    return codes


def registry_version(label: str = DEFAULT_REGISTRY) -> str:
    version: str = _read(REGISTRY_FILES[label])[0]["version"]
    return version


def registry_digest(label: str = DEFAULT_REGISTRY) -> str:
    return _read(REGISTRY_FILES[label])[1]


def registry_digests() -> dict[str, str]:
    return {label: registry_digest(label) for label in REGISTRY_FILES}


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

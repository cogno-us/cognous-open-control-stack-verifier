#!/usr/bin/env python3
"""Copy an ODES contract's schema, reference validator and fixtures byte for byte as a test oracle.

Usage: vendor_oracle.py ODES_CHECKOUT CONTRACT [CONTRACT ...] --note TEXT

Writes ``tests/data/<contract>/{schema.json,validate.py,SOURCE.json}`` and
``tests/data/odes-fixtures/<contract>/{valid,invalid}/*.json`` (the destination is removed
first). SOURCE.json records the ODES repository revision and the SHA-256 of every copied file;
a test recomputes them, so a hand edit of a vendored file is visible. Nothing is imported from
the copied files by the verifier; tests load ``validate.py`` by path. Standard library only.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
from pathlib import Path

DATA = Path(__file__).resolve().parents[1] / "tests" / "data"


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def vendor(odes: Path, contract: str, note: str) -> None:
    src = odes / "contracts" / contract
    oracle, fixtures = DATA / contract, DATA / "odes-fixtures" / contract
    for dest in (oracle, fixtures):
        if dest.exists():
            shutil.rmtree(dest)
    oracle.mkdir(parents=True)
    for name in ("schema.json", "validate.py"):
        shutil.copyfile(src / name, oracle / name)
    for path in sorted((src / "fixtures").glob("*/*.json")):
        target = fixtures / path.relative_to(src / "fixtures")
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, target)
    version = json.loads((src / "schema.json").read_text(encoding="utf-8"))
    version = version.get("properties", {}).get("contract_version", {}).get("const", "0.1.0-draft")
    commit = subprocess.run(
        ["git", "-C", str(odes), "rev-parse", "HEAD"], capture_output=True, text=True, check=True
    ).stdout.strip()
    source = {
        "source": f"cogno-us/open-decision-evidence-standard contracts/{contract}",
        "revision": commit[:8],
        "contract_version": version,
        "note": note,
        "sha256": {n: sha(oracle / n) for n in ("schema.json", "validate.py")},
        "fixtures_sha256": {
            str(p.relative_to(fixtures)): sha(p) for p in sorted(fixtures.glob("*/*.json"))
        },
    }
    (oracle / "SOURCE.json").write_text(json.dumps(source, indent=1) + "\n", encoding="utf-8")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("odes", type=Path)
    ap.add_argument("contracts", nargs="+")
    ap.add_argument("--note", required=True)
    args = ap.parse_args()
    for contract in args.contracts:
        vendor(args.odes, contract, args.note)


if __name__ == "__main__":
    main()

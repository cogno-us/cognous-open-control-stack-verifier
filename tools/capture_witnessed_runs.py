"""Capture witness digests from the real control plane (development tool, not shipped).

This script RUNS the stack to produce verifier inputs; the verifier package never imports it.
It needs a control plane clone (at or after the witness-digest/0.1 and holder-inventory/0.1 change)
and its virtualenv:

    <venv-with-agent-control-plane>/bin/python tools/capture_witnessed_runs.py \
        --control-plane /path/to/cognous-control-plane --out tests/data

Two parts, both through the control plane's own code and nothing edited afterwards:

* ``witnesses/<set>/<name>/witness.jsonl``: for every retained record already in ``tests/data``
  (``real-runs`` and ``orchestrator-runs``), the public command ``acp witness publish`` over the
  record, into a fresh local file witness. The records themselves are not touched.
* ``witnessed-runs/<name>/``: fresh synthetic runs (fixed clock) with the witness published at
  stated points, plus the host's holder inventory document where the scenario has one. Uses the
  control plane's test helpers, as ``capture_real_runs.py`` does. No qualification controller
  and no ``tools/v1_validation.py`` mode is run.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


def _write(path: Path, doc: Any) -> None:
    path.write_text(json.dumps(doc, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")


def _mutations(root: Path) -> Any:
    """The shared damage module, loaded by path (``tests`` would clash with the control plane's)."""
    spec = importlib.util.spec_from_file_location(
        "witness_mutations", root.parent / "witness_mutations.py"
    )
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class _ListWitness:
    def __init__(self, records: list[dict[str, Any]]) -> None:
        self._records = records

    def history(self) -> list[dict[str, Any]]:
        return self._records

    def latest(self) -> dict[str, Any] | None:
        return self._records[-1] if self._records else None


def _differential(out: Path, cp: Path, revision: str) -> list[dict[str, Any]]:
    """Replay record and witness damage through ``verify_against_witness`` and store its verdicts."""
    import agent_control_plane.witness as W

    mut = _mutations(out)
    cases: list[dict[str, Any]] = []
    sets: list[tuple[str, Path, Path]] = []
    for source in ("real-runs", "orchestrator-runs"):
        for rec_dir in sorted(p for p in (out / source).iterdir() if p.is_dir()):
            sets.append(
                (
                    f"{source}/{rec_dir.name}",
                    rec_dir / "bounded-run-record.json",
                    out / "witnesses" / source / rec_dir.name / "witness.jsonl",
                )
            )
    for rec_dir in sorted(p for p in (out / "witnessed-runs").iterdir() if p.is_dir()):
        sets.append(
            (
                f"witnessed-runs/{rec_dir.name}",
                rec_dir / "bounded-run-record.json",
                rec_dir / "witness.jsonl",
            )
        )

    def verdict(doc: Any, records: list[dict[str, Any]]) -> dict[str, Any]:
        v = W.verify_against_witness(doc, _ListWitness(records))
        return {
            "ok": v.ok,
            "reasons": v.reasons,
            "witnessed_through": v.witnessed_through,
            "unwitnessed_rows": v.unwitnessed_rows,
        }

    for name, record_path, witness_path in sets:
        doc = json.loads(record_path.read_text(encoding="utf-8"))
        recs = [
            json.loads(line)
            for line in witness_path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        cases.append({"set": name, "record_op": None, "witness_op": None, "cp": verdict(doc, recs)})
        for ledger in mut.ledger_names(doc):
            for op in mut.RECORD_OPS:
                damaged = mut.apply_record_op(doc, op, ledger)
                if damaged is not None:
                    cases.append(
                        {
                            "set": name,
                            "record_op": [op, ledger],
                            "witness_op": None,
                            "cp": verdict(damaged, recs),
                        }
                    )
        for op in mut.WITNESS_OPS:
            damaged_w = mut.apply_witness_op(recs, op, W._record_digest)
            if damaged_w is not None:
                cases.append(
                    {
                        "set": name,
                        "record_op": None,
                        "witness_op": op,
                        "cp": verdict(doc, damaged_w),
                    }
                )
    _write(
        out / "witnesses" / "cp-differential.json",
        {
            "description": "verdicts of agent_control_plane.witness.verify_against_witness over "
            "record and witness damage described by tests/witness_mutations.py",
            "control_plane_revision": revision,
            "cases": cases,
        },
    )
    return cases


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--control-plane", required=True, type=Path)
    ap.add_argument("--out", required=True, type=Path, help="the tests/data directory")
    args = ap.parse_args()
    cp = args.control_plane.resolve()
    sys.path.insert(0, str(cp))
    sys.path.insert(0, str(cp / "src"))
    import agent_control_plane.bounded as bounded
    from agent_control_plane.witness import LocalFileWitness, publish_head
    from tests.test_bounded_authorization import NOW
    from tests.test_holder_inventory import ROUTED, SELF, configure, inventory
    from tests.test_runtime_authority import setup_flow

    bounded._now = lambda: NOW
    revision = subprocess.run(
        ["git", "-C", str(cp), "rev-parse", "HEAD"], capture_output=True, text=True, check=True
    ).stdout.strip()
    acp = Path(sys.executable).parent / "acp"
    work = Path(tempfile.mkdtemp(prefix="capture-witness-"))
    index: dict[str, Any] = {}

    # Part 1: the public command over records the verifier already holds
    for source in ("real-runs", "orchestrator-runs"):
        for rec_dir in sorted(p for p in (args.out / source).iterdir() if p.is_dir()):
            record = rec_dir / "bounded-run-record.json"
            dest = args.out / "witnesses" / source / rec_dir.name
            if dest.exists():
                shutil.rmtree(dest)
            dest.mkdir(parents=True)
            subprocess.run(
                [
                    str(acp),
                    "witness",
                    "publish",
                    str(record),
                    "--witness",
                    str(dest / "witness.jsonl"),
                ],
                capture_output=True,
                check=True,
            )
            index[f"{source}/{rec_dir.name}"] = {"producer": "acp witness publish", "records": 1}

    # Part 2: fresh runs with the witness published at stated points
    def keep(name: str, description: str, flow: Any, witness_files: dict[str, Path]) -> Path:
        d = args.out / "witnessed-runs" / name
        if d.exists():
            shutil.rmtree(d)
        d.mkdir(parents=True)
        shutil.copyfile(flow.records.path, d / "bounded-run-record.json")
        for fname, src in witness_files.items():
            shutil.copyfile(src, d / fname)
        _write(
            d / "scenario.json",
            {
                "scenario": name,
                "description": description,
                "producer": "agent-control-plane bounded workflow (test helpers, fixed clock) "
                "and agent_control_plane.witness.publish_head",
                "control_plane_revision": revision,
                "synthetic": True,
            },
        )
        index[f"witnessed-runs/{name}"] = {"description": description}
        return d

    # staged: publish after the decision, then again after execution
    p, r, f, cfg = setup_flow(work / "staged")
    w = LocalFileWitness(work / "staged-witness.jsonl")
    d = f.decide(p, now=NOW)
    publish_head(f.records.path, w)
    first = work / "staged-first.jsonl"
    shutil.copyfile(w.path, first)
    f.execute(p, d, adapter_id=p.adapter_id, now=NOW)
    mid = work / "staged-before-last.jsonl"
    shutil.copyfile(w.path, mid)
    publish_head(f.records.path, w)
    keep(
        "staged-journal-applied",
        "journal mode: digest published after the decision and again after execution "
        "(witness.jsonl holds both; witness-first-only.jsonl holds the first, so later rows are unwitnessed)",
        f,
        {"witness.jsonl": w.path, "witness-first-only.jsonl": first},
    )

    # holder inventory present and class flagged: authorized, witnessed at the end
    p, r, f, cfg = setup_flow(work / "inv")
    inv = inventory(ROUTED, SELF)
    configure(r, f, cfg, flag=True, inv=inv)
    d = f.decide(p, now=NOW)
    f.execute(p, d, adapter_id=p.adapter_id, now=NOW)
    w = LocalFileWitness(work / "inv-witness.jsonl")
    publish_head(f.records.path, w)
    out = keep(
        "holder-inventory-enumerated",
        "journal mode, class requires revocation assurance, inventory enumerates two holders: authorized and applied",
        f,
        {"witness.jsonl": w.path},
    )
    _write(out / "holder-inventory.json", inv.model_dump(mode="json"))

    # class flagged and no inventory: held with holder_inventory_missing
    p, r, f, cfg = setup_flow(work / "inv-missing")
    configure(r, f, cfg, flag=True, inv=None)
    f.decide(p, now=NOW)
    w = LocalFileWitness(work / "inv-missing-witness.jsonl")
    publish_head(f.records.path, w)
    keep(
        "holder-inventory-missing-held",
        "journal mode, class requires revocation assurance, no inventory: held with holder_inventory_missing",
        f,
        {"witness.jsonl": w.path},
    )

    cases = _differential(args.out, cp, revision)
    _write(
        args.out / "witnesses" / "INDEX.json",
        {"control_plane_revision": revision, "entries": index},
    )
    print(f"recorded {len(cases)} differential cases")
    shutil.rmtree(work)
    print(f"captured {len(index)} witnessed entries at control plane {revision}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

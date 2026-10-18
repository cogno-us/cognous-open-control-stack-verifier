"""Capture clean run records from the real control plane (development tool, not shipped).

This script RUNS the stack to produce verifier inputs; the verifier package never imports it.
It needs a control plane clone and its virtualenv:

    <venv-with-agent-control-plane>/bin/python tools/capture_real_runs.py \
        --control-plane /path/to/cognous-control-plane --out tests/data/real-runs

Scenarios use the control plane's own test helpers (synthetic proposals, resolver and
destination, a fixed clock), as the lifecycle conformance suite does. No qualification
controller and no ``tools/v1_validation.py`` mode is run. Each scenario directory holds the
persisted run record, the proposal export (the full model dump, nulls included), the manifest,
the destination ledger as the control plane's local destination wrote it, and scenario.json.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


def _write(path: Path, doc: Any) -> None:
    path.write_text(json.dumps(doc, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--control-plane", required=True, type=Path)
    ap.add_argument("--out", required=True, type=Path)
    args = ap.parse_args()
    cp = args.control_plane.resolve()
    sys.path.insert(0, str(cp))
    sys.path.insert(0, str(cp / "src"))
    import agent_control_plane.bounded as bounded
    from tests.test_bounded_authorization import NOW, manifest, proposal, resolver_for, workflow
    from tests.test_runtime_authority import setup_flow

    bounded._now = lambda: NOW  # fixed synthetic clock, as the control plane's own suite does
    revision = subprocess.run(
        ["git", "-C", str(cp), "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    work = Path(tempfile.mkdtemp(prefix="capture-"))
    scenarios: dict[str, dict[str, Any]] = {}

    def keep(name: str, description: str, flow: Any, prop: Any) -> None:
        d = args.out / name
        if d.exists():
            shutil.rmtree(d)
        d.mkdir(parents=True)
        shutil.copyfile(flow.records.path, d / "bounded-run-record.json")
        _write(d / "proposal.json", prop.model_dump(mode="json", exclude_none=False))
        _write(d / "manifest.json", manifest())
        _write(d / "destination.json", flow.destination.snapshot())
        _write(
            d / "scenario.json",
            {
                "scenario": name,
                "description": description,
                "producer": "agent-control-plane bounded workflow (test helpers, fixed clock)",
                "control_plane_revision": revision,
                "synthetic": True,
            },
        )
        scenarios[name] = {"description": description}

    # 1. default path (no runtime-authority profile): authorized and applied
    p = proposal()
    f = workflow(work / "default-applied", p)
    d = f.decide(p, now=NOW)
    f.execute(p, d, adapter_id=p.adapter_id, now=NOW)
    keep("default-applied", "default path, authorized then acknowledged and applied", f, p)

    # 2. default path: held decision (grant unreadable at decision time)
    p = proposal()
    r = resolver_for(p)
    r.statuses = {}
    f = workflow(work / "default-held", p, resolver=r)
    f.decide(p, now=NOW)
    keep("default-held", "default path, decision held, nothing dispatched", f, p)

    # 3-9. journal mode (runtime-authority profile)
    p, r, f, cfg = setup_flow(work / "journal-applied")
    d = f.decide(p, now=NOW)
    f.execute(p, d, adapter_id=p.adapter_id, now=NOW)
    keep("journal-applied", "journal mode, authorized then applied (two checks)", f, p)

    p, r, f, cfg = setup_flow(work / "journal-partial")
    d = f.decide(p, now=NOW)
    f.execute(p, d, adapter_id=p.adapter_id, now=NOW, partial=True)
    keep("journal-partial", "journal mode, partial dispatch and partial observation", f, p)

    p, r, f, cfg = setup_flow(work / "journal-lost-ack")
    d = f.decide(p, now=NOW)
    f.execute(p, d, adapter_id=p.adapter_id, now=NOW, lose_ack=True)
    keep("journal-lost-ack", "journal mode, acknowledgement lost, attempt unknown", f, p)

    p, r, f, cfg = setup_flow(work / "journal-lost-ack-closeout")
    d = f.decide(p, now=NOW)
    f.execute(p, d, adapter_id=p.adapter_id, now=NOW, lose_ack=True)
    again = bounded.BoundedAuthorizationWorkflow(
        allow_test_time=True,
        manifest=manifest(),
        resolver=r,
        destination=bounded.LocalRefundDestination(f.destination.path),
        records=bounded.BoundedRecordStore(f.records.path, "run-1"),
        observation_policy=bounded.ObservationPolicy(
            max_age_seconds=300, clock_tolerance_seconds=5
        ),
        runtime_authority_profile=cfg,
    )
    again.reconcile(d.effect_id, now=NOW)
    keep(
        "journal-lost-ack-closeout", "lost acknowledgement, then reconcile appends a closeout", f, p
    )

    p, r, f, cfg = setup_flow(work / "journal-reconciled-existing")
    d = f.decide(p, now=NOW)
    f.execute(p, d, adapter_id=p.adapter_id, now=NOW, lose_ack=True)
    again = bounded.BoundedAuthorizationWorkflow(
        allow_test_time=True,
        manifest=manifest(),
        resolver=r,
        destination=bounded.LocalRefundDestination(f.destination.path),
        records=bounded.BoundedRecordStore(f.records.path, "run-1"),
        observation_policy=bounded.ObservationPolicy(
            max_age_seconds=300, clock_tolerance_seconds=5
        ),
        runtime_authority_profile=cfg,
    )
    again.execute(p, d, adapter_id=p.adapter_id, now=NOW)
    keep(
        "journal-reconciled-existing",
        "retry after lost ack finds the effect (reconciled_existing)",
        again,
        p,
    )

    p, r, f, cfg = setup_flow(work / "journal-failed")
    d = f.decide(p, now=NOW)

    def reject(**kwargs: Any) -> None:
        raise bounded.DefinitiveDestinationRejection("synthetic_definitive_rejection")

    f.destination.apply = reject  # type: ignore[method-assign]
    f.execute(p, d, adapter_id=p.adapter_id, now=NOW)
    keep("journal-failed", "journal mode, destination definitively rejected the effect", f, p)

    p, r, f, cfg = setup_flow(work / "journal-effect-time-refusal")
    d = f.decide(p, now=NOW)
    r.grant_status = lambda ref: None
    with contextlib.suppress(PermissionError):
        f.execute(p, d, adapter_id=p.adapter_id, now=NOW)
    keep(
        "journal-effect-time-refusal",
        "journal mode, grant unreadable at effect time: refusal",
        f,
        p,
    )

    p, r, f, cfg = setup_flow(work / "journal-held")
    r.grant_status = lambda ref: None
    f.decide(p, now=NOW)
    keep("journal-held", "journal mode, decision held (status unreadable)", f, p)

    # 11-12. the public `acp run` command on the control plane's own examples (the documented real input)
    acp = Path(sys.executable).parent / "acp"
    examples = cp / "examples" / "acp_run"
    for case in ("authorized", "held"):
        run_dir = work / f"acp-{case}"
        run_dir.mkdir()
        subprocess.run(
            [
                str(acp),
                "run",
                "--manifest",
                str(examples / "manifest.json"),
                "--proposal",
                str(examples / case / "proposal.json"),
                "--authority-context",
                str(examples / case / "authority-context.json"),
                "--resolver-state",
                str(examples / case / "resolver-state.json"),
                "--store-dir",
                str(run_dir / "store"),
                "--out-dir",
                str(run_dir / "out"),
                "--now",
                "2026-10-05T19:00:00Z",
                "--format",
                "json",
            ],
            capture_output=True,
            check=False,
        )
        name = f"acp-run-{case}"
        d = args.out / name
        if d.exists():
            shutil.rmtree(d)
        d.mkdir(parents=True)
        shutil.copyfile(run_dir / "out" / "bounded-run-record.json", d / "bounded-run-record.json")
        shutil.copyfile(examples / case / "proposal.json", d / "proposal.json")
        shutil.copyfile(examples / "manifest.json", d / "manifest.json")
        shutil.copyfile(run_dir / "store" / "destination.json", d / "destination.json")
        _write(
            d / "scenario.json",
            {
                "scenario": name,
                "description": f"`acp run` on the control plane example `{case}` (--now 2026-10-05T19:00:00Z)",
                "producer": "acp run (public command)",
                "control_plane_revision": revision,
                "synthetic": True,
            },
        )
        scenarios[name] = {"description": f"acp run example {case}"}

    _write(args.out / "INDEX.json", {"control_plane_revision": revision, "scenarios": scenarios})
    shutil.rmtree(work)
    print(f"captured {len(scenarios)} scenarios at control plane {revision}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

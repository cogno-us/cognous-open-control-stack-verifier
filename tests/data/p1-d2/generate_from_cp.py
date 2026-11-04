"""Regenerate the strict and legacy fixtures from real Control Plane code (NOT run by the test suite).

    python generate_from_cp.py <control-plane-checkout> <out-dir>

Control Plane: cogno-us/cognous-control-plane PR #109 head 5bff525a8e08139e02873b409053830f42969006
(``BoundedAuthorizationWorkflow``; strict default, legacy selected with
``tenant_binding_generation=TENANT_GENERATION_LEGACY``). The tenant proposal and resolver are the
Control Plane's own synthetic test fixtures (tenant "tenant-alpha"); nothing here is a real tenant.
Writes <out-dir>/{strict,legacy}/{bounded-run-record.json,proposal.json,manifest.json,destination.json}.
"""
import json
import sys
import tempfile
from pathlib import Path

cp = Path(sys.argv[1]).resolve()
out = Path(sys.argv[2])
sys.path[:0] = [str(cp), str(cp / "src")]
from tests.test_bounded_authorization import (  # noqa: E402
    NOW, manifest, tenant_proposal, tenant_resolver_for, workflow,
)
import agent_control_plane.bounded as bounded_module  # noqa: E402
from agent_control_plane.bounded import TENANT_GENERATION_LEGACY  # noqa: E402

bounded_module._now = lambda: NOW  # the Control Plane tests fix the synthetic clock the same way

for name, kw in (("strict", {}), ("legacy", {"tenant_binding_generation": TENANT_GENERATION_LEGACY})):
    d = out / name
    d.mkdir(parents=True, exist_ok=True)
    p = tenant_proposal()
    with tempfile.TemporaryDirectory() as tmp:
        flow = workflow(Path(tmp), p, resolver=tenant_resolver_for(p), **kw)
        dec = flow.decide(p, now=NOW)
        assert dec.result == "authorized"
        flow.execute(p, dec, adapter_id=p.adapter_id, now=NOW)
        rec = json.loads(Path(tmp, "run.json").read_text())
        ledger = json.loads(Path(tmp, "destination.json").read_text())
    (d / "bounded-run-record.json").write_text(json.dumps(rec, indent=1, sort_keys=True) + "\n")
    (d / "proposal.json").write_text(json.dumps(json.loads(p.model_dump_json()), indent=1, sort_keys=True) + "\n")
    (d / "destination.json").write_text(json.dumps(ledger, indent=1, sort_keys=True) + "\n")
    (d / "manifest.json").write_text(json.dumps(manifest(), indent=1, sort_keys=True) + "\n")
    print(name, dec.binding.generation, dec.effect_id)

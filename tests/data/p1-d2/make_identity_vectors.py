"""Generate the shared effect-identity vectors from real Control Plane code (NOT run by the test suite).

    python make_identity_vectors.py <control-plane-checkout> <record.json> <out.json>

Control Plane: cogno-us/cognous-control-plane PR #109 head 5bff525a8e08139e02873b409053830f42969006.
``expected_effect_id`` is ``BoundedAuthorizationWorkflow._effect_id(binding)`` called on a real
``TenantAuthorizationBinding`` / ``AuthorizationBinding``; ``preimage`` is the canonical JSON that
function commits to (sha256 over it, prefixed ``sha256:``). The proposal commitment, grant id and
grant revision are those of the real strict CP-2 run record (synthetic tenant ``tenant-alpha``).
"""
import hashlib
import json
import sys
from pathlib import Path

cp = Path(sys.argv[1]).resolve()
sys.path[:0] = [str(cp), str(cp / "src")]
from agent_control_plane.bounded import (  # noqa: E402
    AuthorizationBinding, BoundedAuthorizationWorkflow, TenantAuthorizationBinding,
    TENANT_GENERATION_LEGACY, TENANT_GENERATION_STRICT,
)

rec = json.loads(Path(sys.argv[2]).read_text())
b = next(d["binding"] for d in rec["decisions"] if d["binding"])
fields = {k: b[k] for k in ("proposal_commitment", "grant_id", "grant_revision")}


def preimage(extra):
    return json.dumps({"proposal": fields["proposal_commitment"], "grant_id": fields["grant_id"],
                       "grant_revision": fields["grant_revision"], **extra},
                      sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def vector(name, binding, extra):
    eid = BoundedAuthorizationWorkflow._effect_id(None, binding)
    pre = preimage(extra)
    assert eid == "sha256:" + hashlib.sha256(pre.encode()).hexdigest(), name
    return {"name": name, "proposal": fields["proposal_commitment"], "grant_id": fields["grant_id"],
            "grant_revision": fields["grant_revision"],
            "generation": getattr(binding, "generation", None), "preimage": pre, "expected_effect_id": eid}


strict = TenantAuthorizationBinding(**{**b, "generation": TENANT_GENERATION_STRICT})
legacy = TenantAuthorizationBinding(**{**b, "generation": TENANT_GENERATION_LEGACY})
plain = AuthorizationBinding(**{k: v for k, v in b.items() if k not in ("generation", "tenant_id")})
doc = {
    "document": "effect-identity-vectors/1 (P1 D2)",
    "produced_by": "cogno-us/cognous-control-plane PR #109 head 5bff525a8e08139e02873b409053830f42969006, "
                   "BoundedAuthorizationWorkflow._effect_id",
    "constants": {"strict": TENANT_GENERATION_STRICT, "legacy": TENANT_GENERATION_LEGACY},
    "rule": "effect_id = sha256:<hex> of canonical JSON {proposal, grant_id, grant_revision}; the strict "
            "generation adds the member tenant_generation = the strict marker; legacy 0.2 and the older "
            "tenant-less binding add nothing.",
    "vectors": [
        vector("strict", strict, {"tenant_generation": TENANT_GENERATION_STRICT}),
        vector("legacy-0.2", legacy, {}),
        vector("legacy-tenantless-binding", plain, {}),
    ],
}
Path(sys.argv[3]).write_text(json.dumps(doc, indent=1, sort_keys=True) + "\n")
print(json.dumps(doc, indent=1, sort_keys=True))

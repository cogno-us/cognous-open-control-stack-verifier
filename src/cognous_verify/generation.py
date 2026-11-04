"""Tenant-binding generations of a Control Plane decision binding, and the effect identity each implies.

The Control Plane stamps every tenant-aware decision binding with the generation it was decided under:

* ``bounded-authorization-effect/0.2`` (legacy). A binding without ``generation`` and ``tenant_id`` is the
  older tenant-less binding and is read on this same legacy path. The historical journal schema
  (contract 0.1.0-draft) and the historical effect identity apply unchanged.
* ``bounded-authorization-effect/0.3-strict-tenant`` (strict). Only the successor journal schema
  (``control-plane-journal-strict-tenant``, contract 0.1.0-draft+strict-tenant) accepts it, and the effect identity then
  also commits to the marker: ``commitment({proposal, grant_id, grant_revision, tenant_generation})``
  where ``proposal`` is the binding's ``proposal_commitment``. The recomputation is the same one the Control
  Plane (``BoundedAuthorizationWorkflow._effect_id``) and Replay use; the commitment function is this
  package's own ``canon.commitment``, which is byte-identical to theirs (see
  ``tests/data/p1-d2/identity-vectors.json``).

The two generations are never converted into each other: a record is read under exactly the generation
its bindings state, a binding of the other generation inside it is refuted by the schema variant that was
selected, and an effect identity computed under the other generation never equals the recomputed one.
"""

from __future__ import annotations

from typing import Any

from .canon import commitment

LEGACY = "bounded-authorization-effect/0.2"
STRICT = "bounded-authorization-effect/0.3-strict-tenant"

HISTORICAL_CONTRACT_VERSION = "0.1.0-draft"
STRICT_CONTRACT_VERSION = "0.1.0-draft+strict-tenant"
STRICT_SCHEMA = "control-plane-journal-strict-tenant"


def binding_generation(binding: Any) -> str | None:
    """``LEGACY``, ``STRICT`` or None (an unknown or non-string marker). An absent marker is legacy.

    The marker is compared by exact string equality only: a padded, re-cased or subclassed string is not
    a generation.
    """
    if type(binding) is not dict or "generation" not in binding:
        return LEGACY
    value = binding["generation"]
    if type(value) is str and value in (LEGACY, STRICT):
        return value
    return None


def effect_identity(
    proposal_commitment: Any, grant_id: Any, grant_revision: Any, generation: str | None
) -> str | None:
    """The effect id a decision of ``generation`` must carry; None for an unknown generation."""
    identity = {
        "proposal": proposal_commitment,
        "grant_id": grant_id,
        "grant_revision": grant_revision,
    }
    if generation == STRICT:
        identity["tenant_generation"] = STRICT
    elif generation != LEGACY:
        return None
    return commitment(identity)


def record_uses_strict(doc: Any) -> bool:
    """True when any decision binding in a run record states the strict generation marker."""
    if type(doc) is not dict or type(doc.get("decisions")) is not list:
        return False
    for decision in doc["decisions"]:
        binding = decision.get("binding") if type(decision) is dict else None
        if (
            type(binding) is dict
            and type(binding.get("generation")) is str
            and (binding["generation"] == STRICT)
        ):
            return True
    return False

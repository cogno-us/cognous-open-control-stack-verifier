"""Derive the strict-tenant SUCCESSOR journal schema from the vendored historical schema.

    python tools/derive_strict_tenant_schema.py            # rewrite the successor file
    python tools/derive_strict_tenant_schema.py --check    # exit 1 when the file on disk differs

The historical ``control-plane-journal.schema.json`` (contract 0.1.0-draft, ODES e5fe3822) is never
edited; it keeps accepting only the legacy ``bounded-authorization-effect/0.2`` generation. The
successor is a separate file for records made under the strict tenant generation
``bounded-authorization-effect/0.3-strict-tenant`` (Control Plane PR #109). It differs from the
historical schema in exactly these places and nowhere else:

* ``$id``, ``title`` and ``description`` name the successor;
* ``contract_version`` is the constant ``0.1.0-draft+strict-tenant``;
* ``binding.generation`` accepts only the strict marker, and ``generation`` and ``tenant_id`` are
  both required in a binding (a strict decision always names its tenant).
"""

from __future__ import annotations

import copy
import json
import sys
from pathlib import Path
from typing import Any

DATA = Path(__file__).resolve().parent.parent / "src" / "cognous_verify" / "data"
SOURCE = DATA / "control-plane-journal.schema.json"
TARGET = DATA / "control-plane-journal-strict-tenant.schema.json"
STRICT = "bounded-authorization-effect/0.3-strict-tenant"
VERSION = "0.1.0-draft+strict-tenant"


def derive(historical: dict[str, Any]) -> dict[str, Any]:
    s = copy.deepcopy(historical)
    s["$id"] = s["$id"].replace(
        "contracts/control-plane-journal/schema.json",
        "contracts/control-plane-journal-strict-tenant/schema.json",
    )
    s["title"] = (
        "Control Plane journal (bounded run record) contract, strict-tenant successor " + VERSION
    )
    s["description"] = (
        "SUCCESSOR of control-plane-journal 0.1.0-draft for records made under the strict tenant "
        f"generation {STRICT} (Control Plane PR #109). The historical schema is unchanged and keeps "
        "bounded-authorization-effect/0.2. Differences: contract_version, and a binding must carry "
        "the strict generation marker and a tenant_id. " + s["description"]
    )
    s["properties"]["contract_version"] = {"const": VERSION}
    binding = s["$defs"]["binding"]
    binding["required"] = [*binding["required"], "generation", "tenant_id"]
    binding["properties"]["generation"] = {"enum": [STRICT]}
    return s


def render() -> bytes:
    historical = json.loads(SOURCE.read_bytes())
    return json.dumps(derive(historical), indent=2, ensure_ascii=False).encode() + b"\n"


def main(argv: list[str]) -> int:
    out = render()
    if "--check" in argv:
        return 0 if TARGET.exists() and TARGET.read_bytes() == out else 1
    TARGET.write_bytes(out)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

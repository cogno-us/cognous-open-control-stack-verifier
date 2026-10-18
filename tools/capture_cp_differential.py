"""Differential cases from the real control plane for the sidecar re-derivations (development tool).

Runs the control plane's own functions over generated inputs and writes their answers; the verifier
package never imports them. Needs a control plane clone and a virtualenv with ``pydantic``:

    <venv>/bin/python tools/capture_cp_differential.py --control-plane /path/to/cognous-control-plane \
        --out tests/data/sidecar/cp-differential.json

* ``operation_status`` and ``licensed_revisions``: ``agent_control_plane.operation_identity`` over
  operation ledgers and bindings.
* ``resolve_rule``: ``agent_control_plane.rule_revision.resolve_rule`` over revision rows whose
  signers are all in the configured set (a record holds no row from outside it).
* ``deadline``: the control plane's deadline text, ``freshness.iso(parse_time(opened) + bound)``.

The cases are deterministic (seeded). No store, no workflow, no network.
"""

from __future__ import annotations

import argparse
import itertools
import json
import random
import subprocess
import sys
from datetime import timedelta
from pathlib import Path


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--control-plane", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args()
    sys.path.insert(0, str(args.control_plane / "src"))
    from agent_control_plane import freshness, operation_identity, rule_revision  # type: ignore

    rng = random.Random(10)  # noqa: S311 (deterministic case generation, not security)
    revision = subprocess.run(
        ["git", "-C", str(args.control_plane), "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()

    def op(oid: str, principal: str, grant: str, rev: str, issuer: str = "iss") -> dict[str, str]:
        return {
            "operation_id": oid,
            "principal_id": principal,
            "authority_domain": "dom",
            "issuer": issuer,
            "grant_id": grant,
            "first_grant_revision": rev,
            "admitted_at": "2026-10-05T19:00:00+00:00",
        }

    def renewal(rid: str, oid: str, to_rev: str, outcome: str) -> dict[str, str | None]:
        return {
            "renewal_id": rid,
            "operation_id": oid,
            "grant_id": "g1",
            "from_revision": "1",
            "to_revision": to_rev,
            "written_by": "iss",
            "outcome": outcome,
            "refusal_code": None if outcome == "accepted" else "renewal_revision_not_new",
            "recorded_at": "2026-10-05T19:00:01+00:00",
        }

    ledgers = []
    for ops in (
        [],
        [op("o1", "p1", "g1", "1")],
        [op("o1", "p1", "g1", "1"), op("o2", "p2", "g2", "3")],
    ):
        for rens in (
            [],
            [renewal("r1", "o1", "2", "accepted")],
            [renewal("r1", "o1", "2", "refused")],
            [renewal("r1", "o1", "2", "accepted"), renewal("r2", "o1", "3", "accepted")],
        ):
            ledgers.append({"operations": ops, "operation_renewals": rens})
    bindings = []
    for oid, principal, domain, issuer, grant, rev in itertools.product(
        ("o1", "o2", "o9"),
        ("p1", "p2"),
        ("dom", "other"),
        ("iss", "other"),
        ("g1", "g2"),
        ("1", "2", "3", "4"),
    ):
        bindings.append(
            {
                "operation_id": oid,
                "principal_id": principal,
                "authority_domain": domain,
                "issuer": issuer,
                "grant_id": grant,
                "grant_revision": rev,
            }
        )
    status_cases = []
    for n, ledger in enumerate(ledgers):
        for binding in rng.sample(bindings, 60):
            status_cases.append(
                {
                    "ledger": n,
                    "binding": binding,
                    "status": operation_identity.operation_status(ledger, **binding),
                }
            )
    licensed_cases = [
        {
            "ledger": n,
            "operation_id": oid,
            "licensed": sorted(operation_identity.licensed_revisions(ledger, oid)),
        }
        for n, ledger in enumerate(ledgers)
        for oid in ("o1", "o2", "o9")
    ]

    profile = rule_revision.RuleRevisionProfile(signers=["s1", "s2"])
    digests = ["sha256:" + c * 64 for c in "abc"]
    resolve_cases = []
    seen = set()
    for _ in range(4000):
        rows = []
        for n in range(rng.randint(0, 3)):
            kind = rng.choice(("unsigned", "self", "s1", "s2"))
            reviser = "rev" if kind != "self" else "s1"
            signer = {"unsigned": None, "self": "s1", "s1": "s1", "s2": "s2"}[kind]
            rows.append(
                {
                    "revision_id": f"v{n}",
                    "rule_kind": "policy",
                    "rule_ref": rng.choice(("ra", "ra", "rb")),
                    "from_digest": rng.choice((None, *digests)),
                    "to_digest": rng.choice(digests),
                    "reviser": reviser,
                    "signer": signer,
                    "authority_ref": None,
                    "reason": "x",
                    "supersedes": rng.choice((None, None, f"v{n - 1}")) if n else None,
                    "recorded_at": "2026-10-05T19:00:00+00:00",
                }
            )
        observed = rng.choice((None, *digests, "sha256:" + "d" * 64))
        key = json.dumps([rows, observed], sort_keys=True)
        if key in seen:
            continue
        seen.add(key)
        res = rule_revision.resolve_rule(profile, rows, "ra", observed)
        resolve_cases.append(
            {
                "rows": rows,
                "rule_ref": "ra",
                "observed": observed,
                "state": res["state"],
                "verified_through": res["verified_through"],
                "findings": res["findings"],
                "adopted_digest": res["adopted_digest"],
            }
        )
        if len(resolve_cases) == 600:
            break

    deadline_cases = []
    for opened, bound in itertools.product(
        (
            "2026-10-05T19:00:00+00:00",
            "2026-10-05T19:00:00.123456+00:00",
            "2026-10-05T23:59:30+00:00",
            "2026-12-31T23:59:59.5+00:00",
            "2026-10-05T19:00:00+02:00",
            "2026-03-01T00:00:00Z",
        ),
        (0, 1, 60, 3600, 86400, 31536000),
    ):
        deadline = freshness.iso(freshness.parse_time(opened) + timedelta(seconds=bound))
        deadline_cases.append({"opened": opened, "bound": bound, "deadline": deadline})

    out = {
        "source": {
            "control_plane_revision": revision,
            "tool": "tools/capture_cp_differential.py",
            "seed": 10,
        },
        "ledgers": ledgers,
        "operation_status": status_cases,
        "licensed_revisions": licensed_cases,
        "resolve_rule": resolve_cases,
        "deadline": deadline_cases,
    }
    args.out.write_text(
        json.dumps(out, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8"
    )
    print(len(status_cases), len(licensed_cases), len(resolve_cases), len(deadline_cases))


if __name__ == "__main__":
    main()

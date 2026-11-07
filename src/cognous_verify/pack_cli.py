"""``python -m cognous_verify.pack_cli``: opt-in, development-only checks over one Evidence Pack file.

Exit codes: 1 at least one check is refuted (reject); 2 usage error or an unsupported pack profile
(nothing was verified); 3 nothing refuted but some checks could not be made (abstain); 4 crash.
There is no exit code for accept: source identity cannot be checked, so the result never reads as one.
This command does not change ``cognous-verify`` and writes no report unless ``--out`` is given.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from . import pack, wire

EXIT_REJECT, EXIT_USAGE, EXIT_ABSTAIN, EXIT_CRASH = 1, 2, 3, 4


def _summary(rep: dict[str, Any]) -> str:
    checks = rep["checks"]
    lines = [f"overall: {rep['overall']} (development only; never accept; not an attestation)"]
    lines.append(
        "checks: {checks}; confirmed {confirmed}, could not check {could_not_check}, refuted {refuted}".format(
            **rep["summary"]
        )
    )
    for c in checks:
        if c["verdict"] != "confirmed":
            lines.append(f"  {c['verdict'].upper():15} {c['check_id']} {c['reason'] or ''}")
            lines.extend(
                f"      {f['code']} at {f['locator']}: {f['detail']}" for f in c["findings"][:5]
            )
    if "unsupported_input" in rep:
        lines.append(f"unsupported input: {rep['unsupported_input']}")
    lines.append("unsupported claims: " + str(len(rep["unsupported_claims"])) + " (see report)")
    return "\n".join(lines)


def main(argv: Sequence[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="cognous-verify-pack",
        description="Development-only Evidence Pack checks. Not an attestation.",
    )
    p.add_argument("pack", help="the Evidence Pack JSON (explicitly selected)")
    p.add_argument("--out", metavar="FILE", help="write the JSON report here")
    p.add_argument("--json", action="store_true", help="print the JSON report on stdout")
    try:
        args = p.parse_args(argv)
    except SystemExit as exc:
        return EXIT_USAGE if exc.code else 0
    try:
        with open(args.pack, "rb") as fh:
            data = fh.read(wire.MAX_BYTES + 1)
    except OSError as exc:
        print(f"error: cannot read input: {exc}", file=sys.stderr)
        return EXIT_USAGE
    if args.out and os.path.exists(args.out) and os.path.samefile(args.out, args.pack):
        print("error: --out names the input file", file=sys.stderr)
        return EXIT_USAGE
    try:
        rep = pack.verify_bytes(data, Path(args.pack).name)
        text = json.dumps(rep, indent=2, ensure_ascii=False, allow_nan=False) + "\n"
    except Exception as exc:
        print(f"error: verifier crashed ({type(exc).__name__}); no report written", file=sys.stderr)
        return EXIT_CRASH
    if args.out:
        try:
            Path(args.out).write_text(text, encoding="utf-8")
        except OSError as exc:
            print(f"error: cannot write report: {exc}", file=sys.stderr)
            return EXIT_USAGE
    sys.stdout.write(text if args.json else _summary(rep) + "\n")
    return {"reject": EXIT_REJECT, "unsupported": EXIT_USAGE}.get(str(rep["overall"]), EXIT_ABSTAIN)


if __name__ == "__main__":
    sys.exit(main())

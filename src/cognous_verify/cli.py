"""``cognous-verify``: verify supplied records and write a verification report.

Exit codes: 0 every check that ran is confirmed (accept); 1 at least one check is refuted;
2 usage or input error (nothing was verified); 3 nothing refuted but some checks could not
be made (abstain); 4 the verifier crashed (no report is written).

The command takes records only. There is no option that accepts an expected outcome or any
label: the report is produced before anything could be joined to it.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from . import __version__, engine, report, wire
from .timeutil import aware

EXIT_ACCEPT, EXIT_REFUTED, EXIT_USAGE, EXIT_ABSTAIN, EXIT_CRASH = 0, 1, 2, 3, 4


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="cognous-verify",
        description=(
            "Independent verifier for Open Control Stack run records. Standard library only. "
            "Reports confirmed / could-not-check / refuted per check with denominators; no "
            "score. A verification report, not an attestation."
        ),
    )
    p.add_argument("run_record", help="the run record (JSON)")
    p.add_argument(
        "--proposal",
        action="append",
        default=[],
        metavar="FILE",
        help="proposal export (repeatable)",
    )
    p.add_argument("--manifest", metavar="FILE", help="run manifest")
    p.add_argument("--ledger", metavar="FILE", help="destination ledger snapshot")
    p.add_argument("--out", metavar="FILE", help="write the JSON report here")
    p.add_argument("--json", action="store_true", help="print the JSON report on stdout")
    p.add_argument(
        "--controller-revision",
        metavar="REV",
        help="controller revision the records came from (unstated if omitted)",
    )
    p.add_argument(
        "--source-revision",
        metavar="REV",
        help="source revision of this verifier build (unstated if omitted)",
    )
    p.add_argument(
        "--generated-at",
        metavar="TIME",
        help="report time, ISO 8601 with offset (default: now, UTC)",
    )
    p.add_argument("--version", action="version", version=f"cognous-verify {__version__}")
    return p


def _read(path: str) -> bytes:
    with open(path, "rb") as fh:
        return fh.read(wire.MAX_BYTES + 1)


def _names(entries: list[tuple[str, str]]) -> list[engine.InputFile]:
    """Name inputs by file name, falling back to the given path when file names collide."""
    base = [(role, Path(p).name) for role, p in entries]
    out = []
    for (role, path), (_r, name) in zip(entries, base, strict=True):
        clash = sum(1 for r, n in base if (r, n) == (role, name)) > 1
        out.append(engine.InputFile(role, path if clash else name, _read(path)))
    return out


def _summary(rep: dict[str, Any], ev: engine.Evaluation) -> str:
    summary = rep["summary"]
    lines = [
        f"overall: {ev.overall} (derived from the checks that ran; not a score, not an attestation)",
        "checks: {checks}; confirmed {confirmed}, could not check {could_not_check}, "
        "refuted {refuted}".format(**summary),
    ]
    for r in ev.results:
        t = r.tally()
        if r.verdict != "confirmed":
            lines.append(
                f"  {r.verdict.upper():15} {r.check_id}  "
                f"refuted {t['refuted']}/{t['n']}, could not check {t['could_not_check']}/{t['n']}"
            )
            lines.extend(f"      {f.code} at {f.path}: {f.message}" for f in r.findings[:5])
    if ev.not_applicable:
        lines.append(f"not applicable to this record: {len(ev.not_applicable)} checks")
    lines.extend(f"note: {n}" for n in ev.notes)
    lines.append("does not prove: see does_not_prove in the report")
    return "\n".join(lines)


def main(argv: Sequence[str] | None = None) -> int:
    try:
        args = _parser().parse_args(argv)
    except SystemExit as exc:
        return EXIT_USAGE if exc.code else EXIT_ACCEPT
    if args.generated_at is not None and aware(args.generated_at) is None:
        print("error: --generated-at needs a timestamp with a UTC offset", file=sys.stderr)
        return EXIT_USAGE
    entries = [("run_record", args.run_record)]
    entries += [("proposal_export", p) for p in args.proposal]
    if args.manifest:
        entries.append(("manifest", args.manifest))
    if args.ledger:
        entries.append(("destination_ledger", args.ledger))
    if args.out and any(
        os.path.exists(args.out) and os.path.samefile(args.out, p)
        for _r, p in entries
        if os.path.exists(p)
    ):
        print("error: --out names an input file", file=sys.stderr)
        return EXIT_USAGE
    try:
        files = _names(entries)
    except OSError as exc:
        print(f"error: cannot read input: {exc}", file=sys.stderr)
        return EXIT_USAGE
    try:
        ev = engine.evaluate(files)
        if ev.crashed:
            print("error: a verifier check failed internally; no report written", file=sys.stderr)
            return EXIT_CRASH
        rep = report.build(
            ev,
            generated_at=args.generated_at,
            controller_revision=args.controller_revision,
            source_revision=args.source_revision,
        )
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
    if args.json:
        sys.stdout.write(text)
    else:
        print(_summary(rep, ev))
    return {"reject": EXIT_REFUTED, "abstain": EXIT_ABSTAIN}.get(ev.overall, EXIT_ACCEPT)

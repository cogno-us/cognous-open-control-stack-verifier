"""``cognous-verify``: verify supplied records and write a verification report.

Exit codes: 0 every check that ran is confirmed (accept); 1 at least one check is refuted;
2 usage or input error (nothing was verified); 3 nothing refuted but some checks could not
be made (abstain); 4 the verifier crashed (no report is written).

``--help`` and ``--version`` print and exit 0 without verifying anything and without writing a
report: that 0 is not an accept. Do not read the exit code of a run that was only asked for its
help or version text.

The command takes records only. There is no option that accepts an expected outcome or any
label: the report is produced before anything could be joined to it.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import unicodedata
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
    p.add_argument("--manifest", action="append", default=[], metavar="FILE", help="run manifest")
    p.add_argument(
        "--ledger",
        action="append",
        default=[],
        metavar="FILE",
        help="destination ledger snapshot",
    )
    p.add_argument(
        "--witness",
        action="append",
        default=[],
        metavar="FILE",
        help="witness-digest/0.1 records, one JSON object per line (tier V3)",
    )
    p.add_argument(
        "--holder-inventory",
        action="append",
        default=[],
        metavar="FILE",
        help="holder-inventory/0.1 document (tier V3; the run record does not carry one)",
    )
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


def _printable(text: str) -> str:
    """``text`` with control, format, surrogate and line-separator characters escaped.

    Used for file names (so a name with raw bytes or control characters still yields a
    well-formed report) and for every line of the text summary (so a value taken from an
    input cannot add lines, move the cursor or imitate the summary's own lines).
    """
    out = []
    for ch in text:
        cat = unicodedata.category(ch)
        if cat[0] == "C" or cat in ("Zl", "Zp"):
            code = ord(ch)
            width = 2 if code < 0x100 else 4 if code < 0x10000 else 8
            out.append(f"\\{'xuU'[(2, 4, 8).index(width)]}{code:0{width}x}")
        else:
            out.append(ch)
    return "".join(out)


def _file_name(path: str) -> str:
    """The input's file name for the report: the base name only, never a directory."""
    raw = os.fsencode(Path(path).name)
    return _printable(raw.decode("utf-8", errors="backslashreplace"))


def _duplicates(entries: list[tuple[str, str]]) -> str | None:
    """The first path that appears twice among the inputs (same file by any spelling)."""
    seen: list[str] = []
    for _role, path in entries:
        real = os.path.realpath(path)
        for other in seen:
            same = real == other
            if not same and os.path.exists(real) and os.path.exists(other):
                same = os.path.samefile(real, other)
            if same:
                return path
        seen.append(real)
    return None


def _names(entries: list[tuple[str, str]]) -> list[engine.InputFile]:
    """Name inputs by file name; names that collide within a role get ``#2``, ``#3`` ...

    A report names inputs relative to nowhere: a base name, never a directory path.
    """
    used: set[tuple[str, str]] = set()
    out = []
    for role, path in entries:
        name = base = _file_name(path)
        n = 1
        while (role, name) in used:
            n += 1
            name = f"{base}#{n}"
        used.add((role, name))
        out.append(engine.InputFile(role, name, _read(path)))
    return out


def _summary(rep: dict[str, Any], ev: engine.Evaluation) -> str:
    summary = rep["summary"]
    lines = [
        f"overall: {ev.overall} (derived from the checks that ran; not a score, not an attestation)",
        "checks: {checks}; confirmed {confirmed}, could not check {could_not_check}, "
        "refuted {refuted}".format(**summary),
    ]
    for r in ev.checks:
        t = r.tally()
        if r.verdict != "confirmed":
            lines.append(
                f"  {r.verdict.upper():15} {r.check_id}  "
                f"refuted {t['refuted']}/{t['n']}, could not check {t['could_not_check']}/{t['n']}"
            )
            lines.extend(f"      {f.code} at {f.path}: {f.message}" for f in r.findings[:5])
    if ev.v3 is None or not ev.v3.requested:
        lines.append(
            "tier V3 (witness re-derivation) not run: no witness or holder inventory supplied"
        )
    else:
        done = sum(r.verdict == "confirmed" for r in ev.v3.results)
        lines.append(
            f"tier V3 (witness re-derivation, counted above): {len(ev.v3.results)} checks, "
            f"{done} confirmed"
        )
    if ev.not_applicable:
        lines.append(f"not applicable to this record: {len(ev.not_applicable)} checks")
    lines.extend(f"note: {n}" for n in ev.notes)
    lines.append("does not prove: see does_not_prove in the report")
    return "\n".join(_printable(line) for line in lines)


def main(argv: Sequence[str] | None = None) -> int:
    try:
        args = _parser().parse_args(argv)
    except SystemExit as exc:
        return EXIT_USAGE if exc.code else EXIT_ACCEPT
    if args.generated_at is not None and aware(args.generated_at) is None:
        print("error: --generated-at needs a timestamp with a UTC offset", file=sys.stderr)
        return EXIT_USAGE
    for flag, given in (
        ("--manifest", args.manifest),
        ("--ledger", args.ledger),
        ("--witness", args.witness),
        ("--holder-inventory", args.holder_inventory),
    ):
        if len(given) > 1:
            print(f"error: {flag} was given more than once; it takes one file", file=sys.stderr)
            return EXIT_USAGE
    entries = [("run_record", args.run_record)]
    entries += [("proposal_export", p) for p in args.proposal]
    for role, given in (
        ("manifest", args.manifest),
        ("destination_ledger", args.ledger),
        (engine.WITNESS, args.witness),
        (engine.HOLDER_INVENTORY, args.holder_inventory),
    ):
        entries += [(role, path) for path in given]
    dup = _duplicates(entries)
    if dup is not None:
        print(f"error: the same input file is named twice: {_printable(dup)}", file=sys.stderr)
        return EXIT_USAGE
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

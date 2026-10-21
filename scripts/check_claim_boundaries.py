"""Claim-boundary check: no document, source string or test says the verifier is certified,
compliant or production-ready while release-state.json is on HOLD.

A missing or malformed release-state.json counts as HOLD. A match is excused only by an exact
entry (path, rule, line text) in scripts/claim_boundaries_allowlist.json; an entry that no
longer matches anything is an error, so the list cannot rot. Standard library only.

Usage: check_claim_boundaries.py [--root DIR]
"""

from __future__ import annotations

import argparse
import html
import json
import re
import subprocess
import sys
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(
    0, str(ROOT / "src")
)  # the repository's own strict wire parser, not an installed copy

from cognous_verify import wire  # noqa: E402

ALLOWLIST = "scripts/claim_boundaries_allowlist.json"
STATE_KEYS = {"schema", "publication_authorized", "production_authorized", "basis", "note"}
SEP = r"[\s\-_]*"
END = r"(?![a-z0-9])"
RULES: dict[str, re.Pattern[str]] = {
    "certified": re.compile(r"\bcertif(?:ied|ies|ying|y|ication)\b"),
    "compliant": re.compile(r"\bcompl(?:iant|iance|y|ies|ied|ying)\b"),
    "production-ready": re.compile(
        rf"\b(?:production|prod|enterprise|audit){SEP}(?:ready|grade|quality|safe|worthy){END}"
        rf"|\b(?:ready|approved|safe|fit|suitable|cleared){SEP}for{SEP}production\b"
    ),
    "attested": re.compile(
        rf"\bsoc{SEP}[123]\b.{{0,40}}?\battest(?:ed|ation|s)?\b"
        rf"|\battest(?:ed|ation|s)?\b.{{0,40}}?\bsoc{SEP}[123]\b"
    ),
}
TEXT_SUFFIXES = {
    ".md",
    ".markdown",
    ".rst",
    ".txt",
    ".py",
    ".json",
    ".yml",
    ".yaml",
    ".toml",
    ".cfg",
    ".ini",
    ".sh",
    ".svg",
    ".xml",
    ".js",
    ".csv",
    ".html",
    ".htm",
}
# Latin lookalikes from Cyrillic and Greek (lower case, after casefold); other scripts are not folded.
CONFUSABLES = str.maketrans(
    {
        "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y", "і": "i",
        "ј": "j", "ѕ": "s", "ԁ": "d", "һ": "h", "ԛ": "q", "ԝ": "w", "к": "k", "ё": "e",
        "ο": "o", "ρ": "p", "ν": "v", "ι": "i", "α": "a", "ε": "e", "κ": "k", "υ": "u",
        "χ": "x", "ı": "i", "ɡ": "g", "ԍ": "g",
    }
)  # fmt: skip
EMPHASIS_TAG = re.compile(r"</?(?:b|i|u|s|em|strong|code|span|wbr|mark|small|big)\b[^>]*>", re.I)
TEXT_NAMES = {"Makefile"}


@dataclass(frozen=True)
class Finding:
    path: str
    line: int
    rule: str
    text: str

    def render(self) -> str:
        return f"{self.path}:{self.line}: [{self.rule}] {self.text[:160]}"


def read_state(root: Path) -> dict[str, Any]:
    try:
        # the repository's strict parser: refuses duplicate members, non-finite numbers, bad UTF-8
        state = wire.parse((root / "release-state.json").read_bytes())
    except (OSError, ValueError) as exc:
        raise ValueError(f"release-state.json unreadable: {exc}") from exc
    if type(state) is not dict or set(state) != STATE_KEYS:
        raise ValueError("release-state.json members differ from the closed set")
    for key in ("publication_authorized", "production_authorized"):
        if type(state[key]) is not bool:
            raise ValueError(f"release-state.json {key} is not a boolean")
    return state


def on_hold(state: dict[str, Any]) -> bool:
    return not (state["publication_authorized"] and state["production_authorized"])


def _is_dash(ch: str) -> bool:
    return unicodedata.category(ch) == "Pd" or ch in "\u2212\u2043\u2e3a\u2e3b\ufe63\uff0d"


def _is_invisible(ch: str) -> bool:
    """Format characters, variation selectors and combining marks carry no visible letter."""
    cp = ord(ch)
    return (
        unicodedata.category(ch) in {"Cf", "Mn", "Me"}
        or 0xFE00 <= cp <= 0xFE0F
        or 0xE0100 <= cp <= 0xE01EF
    )


def _fold_line(raw: str) -> str:
    """Fold one source line the way a reader would see it (entities, markup, lookalikes, dashes)."""
    text = EMPHASIS_TAG.sub("", html.unescape(raw))
    text = text.replace("*", "").replace("`", "").replace("~", "").replace("__", "")
    out: list[str] = []
    for ch in unicodedata.normalize("NFKD", unicodedata.normalize("NFKC", text)):
        if _is_invisible(ch):
            continue
        for low in ch.casefold():
            out.append("-" if _is_dash(low) else low.translate(CONFUSABLES))
    return "".join(out)


def scan_text(path: str, text: str) -> list[Finding]:
    """Fold each line (HTML entities, emphasis markup, NFKC, casefold, invisible characters,
    Cyrillic and Greek lookalikes, every dash variant); phrases split by any of these still match."""
    source = unicodedata.normalize("NFKC", text).split("\n")
    folded = [_fold_line(line) for line in text.split("\n")]
    norm = "\n".join(folded)
    starts: list[int] = []
    offset = 0
    for line in folded:
        starts.append(offset)
        offset += len(line) + 1
    found: set[Finding] = set()
    for rule, pattern in RULES.items():
        for m in pattern.finditer(norm):
            ln = max(1, sum(1 for st in starts if st <= m.start()))
            found.add(Finding(path, ln, rule, source[ln - 1].strip() if ln <= len(source) else ""))
    return sorted(found, key=lambda f: (f.path, f.line, f.rule))


def load_allowlist(root: Path) -> dict[str, Any]:
    data = json.loads((root / ALLOWLIST).read_text(encoding="utf-8"))
    if type(data) is not dict or set(data) != {"excluded_paths", "allowed"}:
        raise ValueError("allow-list members differ from the closed set")
    for e in data["excluded_paths"]:
        if set(e) != {"path", "reason"} or not e["reason"].strip():
            raise ValueError("excluded_paths entries need path and reason")
    for e in data["allowed"]:
        if set(e) != {"path", "rule", "line", "reason"} or not e["reason"].strip():
            raise ValueError("allowed entries need path, rule, line and reason")
        if e["rule"] not in RULES:
            raise ValueError(f"allowed entry names unknown rule {e['rule']!r}")
    return data


def tracked_files(root: Path) -> list[Path]:
    """Files git tracks or would add (not ignored); a directory walk outside a work tree."""
    try:
        out = subprocess.run(
            [
                "git",
                "-C",
                str(root),
                "ls-files",
                "-z",
                "--cached",
                "--others",
                "--exclude-standard",
            ],
            check=True,
            capture_output=True,
        ).stdout.decode()
        return sorted(root / p for p in out.split("\0") if p and (root / p).is_file())
    except (OSError, subprocess.CalledProcessError):
        skip = {
            ".git",
            ".venv",
            "venv",
            "dist",
            "build",
            ".mypy_cache",
            ".ruff_cache",
            ".pytest_cache",
        }
        return sorted(
            p for p in root.rglob("*") if p.is_file() and not skip & set(p.relative_to(root).parts)
        )


def _excluded(rel: str, excluded: list[dict[str, str]]) -> bool:
    return any(
        rel == e["path"] or (e["path"].endswith("/") and rel.startswith(e["path"]))
        for e in excluded
    )


def scan_tree(root: Path, allow: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    for path in tracked_files(root):
        rel = path.relative_to(root).as_posix()
        text_like = path.suffix in TEXT_SUFFIXES or path.name in TEXT_NAMES
        if rel == ALLOWLIST or _excluded(rel, allow["excluded_paths"]) or not text_like:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            findings.append(Finding(rel, 0, "undecodable", "text file is not UTF-8"))
            continue
        findings += scan_text(rel, text)
    return findings


def apply_allowlist(
    findings: list[Finding], allow: dict[str, Any]
) -> tuple[list[Finding], list[dict[str, str]]]:
    used: set[int] = set()
    left: list[Finding] = []
    entries = allow["allowed"]
    for f in findings:
        hit = [
            i
            for i, e in enumerate(entries)
            if e["path"] == f.path and e["rule"] == f.rule and e["line"] == f.text
        ]
        if hit:
            used.update(hit)
        else:
            left.append(f)
    return left, [e for i, e in enumerate(entries) if i not in used]


def run(root: Path) -> tuple[int, list[str]]:
    msgs: list[str] = []
    try:
        state = read_state(root)
    except ValueError as exc:
        msgs.append(f"HOLD assumed: {exc}")
        state = {"publication_authorized": False, "production_authorized": False}
    if not on_hold(state):
        msgs.append("publication and production are both authorized: claim rules not enforced")
        return 0, msgs
    allow = load_allowlist(root)
    findings = scan_tree(root, allow)
    left, stale = apply_allowlist(findings, allow)
    msgs += [f"claim boundary: {f.render()}" for f in left]
    msgs += [f"stale allow-list entry: {e['path']} [{e['rule']}] {e['line'][:80]}" for e in stale]
    if left or stale:
        return 1, msgs
    msgs.append(f"claim boundary: ok (HOLD enforced; {len(findings)} excused matches)")
    return 0, msgs


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=(__doc__ or "").split("\n")[0])
    ap.add_argument("--root", type=Path, default=ROOT)
    code, msgs = run(ap.parse_args(argv).root)
    print("\n".join(msgs))
    return code


if __name__ == "__main__":
    sys.exit(main())

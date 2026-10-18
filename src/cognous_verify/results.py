"""Result types: findings, and three-valued check results with explicit denominators."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

CONFIRMED = "confirmed"
COULD_NOT_CHECK = "could_not_check"
REFUTED = "refuted"
VERDICTS = (CONFIRMED, COULD_NOT_CHECK, REFUTED)

_ITEM = re.compile(r"^(\$(?:\.[A-Za-z_]+\[\d+\]|\.[A-Za-z_]+)?)")


@dataclass(frozen=True)
class Finding:
    """One refuted rule instance: a stable code, a path into the document, a message."""

    code: str
    path: str
    message: str

    def as_dict(self) -> dict[str, str]:
        return {"code": self.code, "path": self.path, "message": self.message}

    def item_key(self) -> str:
        """The item a finding belongs to: the path up to the first indexed member."""
        m = _ITEM.match(self.path)
        return m.group(1) if m else self.path


@dataclass
class CheckResult:
    """The outcome of one check over ``total`` items of ``unit``.

    ``refuted`` items are those named by findings (distinct item keys, capped at ``total``);
    ``skipped`` items could not be checked (for example no proposal was supplied for a
    decision); the rest are confirmed. The verdict is derived: refuted if any item is refuted,
    else could-not-check if any item was skipped, else confirmed. There is no score, and a
    check never averages anything.
    """

    check_id: str
    tier: str
    verdict: str
    unit: str
    checked: int
    total: int
    findings: list[Finding] = field(default_factory=list)
    reason: str | None = None
    notes: list[str] = field(default_factory=list)
    error: bool = False
    skipped: int = 0

    def tally(self) -> dict[str, int]:
        """Per-item counts: confirmed, could_not_check, refuted and n (at least one item)."""
        if self.verdict == COULD_NOT_CHECK and self.skipped == 0:
            n = max(self.total, 1)
            return {"confirmed": 0, "could_not_check": n, "refuted": 0, "n": n}
        refuted = len({f.item_key() for f in self.findings}) if self.findings else 0
        n = max(self.total, refuted + self.skipped, 1)
        return {
            "confirmed": n - refuted - self.skipped,
            "could_not_check": self.skipped,
            "refuted": refuted,
            "n": n,
        }

    def as_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "check_id": self.check_id,
            "tier": self.tier,
            "verdict": self.verdict,
            "unit": self.unit,
            "tally": self.tally(),
            "findings": [f.as_dict() for f in self.findings],
        }
        if self.reason is not None:
            out["reason"] = self.reason
        if self.notes:
            out["notes"] = list(self.notes)
        if self.error:
            out["error"] = True
        return out


def make_result(
    check_id: str,
    tier: str,
    unit: str,
    total: int,
    findings: list[Finding],
    *,
    skipped: int = 0,
    reason: str | None = None,
    notes: list[str] | None = None,
) -> CheckResult:
    """Build a result over ``total`` items; the verdict is derived."""
    if findings:
        verdict = REFUTED
    elif skipped or total == 0:
        verdict = COULD_NOT_CHECK
        if reason is None:
            reason = "no_items_in_record" if total == 0 else "some_items_not_checkable"
    else:
        verdict = CONFIRMED
    return CheckResult(
        check_id=check_id,
        tier=tier,
        verdict=verdict,
        unit=unit,
        checked=total - skipped if verdict != COULD_NOT_CHECK or skipped else 0,
        total=total,
        findings=findings,
        reason=reason if verdict != CONFIRMED else None,
        notes=notes or [],
        skipped=skipped,
    )


def confirmed_or_refuted(
    check_id: str,
    tier: str,
    unit: str,
    total: int,
    findings: list[Finding],
    notes: list[str] | None = None,
) -> CheckResult:
    """Build a result for a check that ran over all ``total`` items."""
    return CheckResult(
        check_id=check_id,
        tier=tier,
        verdict=REFUTED if findings else CONFIRMED,
        unit=unit,
        checked=total,
        total=total,
        findings=findings,
        notes=notes or [],
    )


def could_not_check(
    check_id: str, tier: str, unit: str, total: int, reason: str, notes: list[str] | None = None
) -> CheckResult:
    return CheckResult(
        check_id=check_id,
        tier=tier,
        verdict=COULD_NOT_CHECK,
        unit=unit,
        checked=0,
        total=total,
        reason=reason,
        notes=notes or [],
    )


def verifier_error(check_id: str, tier: str, unit: str, total: int, exc: Exception) -> CheckResult:
    """A crash inside a check. Reported as could-not-check with ``error`` set; never a detection."""
    result = could_not_check(check_id, tier, unit, total, f"verifier_error:{type(exc).__name__}")
    result.error = True
    return result

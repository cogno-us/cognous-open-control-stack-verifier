"""Result types: findings, and three-valued check results with explicit denominators."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

CONFIRMED = "confirmed"
COULD_NOT_CHECK = "could_not_check"
REFUTED = "refuted"
VERDICTS = (CONFIRMED, COULD_NOT_CHECK, REFUTED)


@dataclass(frozen=True)
class Finding:
    """One refuted rule instance: a stable code, a path into the document, a message."""

    code: str
    path: str
    message: str

    def as_dict(self) -> dict[str, str]:
        return {"code": self.code, "path": self.path, "message": self.message}


@dataclass
class CheckResult:
    """The outcome of one check.

    ``checked`` of ``total`` items of ``unit`` were examined. For ``confirmed`` and ``refuted``
    both are given; for ``could_not_check`` ``checked`` is 0 and ``reason`` says why. There is
    no score: a check is one of three verdicts and nothing is averaged.
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

    def as_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "check_id": self.check_id,
            "tier": self.tier,
            "verdict": self.verdict,
            "denominator": {"unit": self.unit, "checked": self.checked, "total": self.total},
            "findings": [f.as_dict() for f in self.findings],
        }
        if self.reason is not None:
            out["reason"] = self.reason
        if self.notes:
            out["notes"] = list(self.notes)
        if self.error:
            out["error"] = True
        return out


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

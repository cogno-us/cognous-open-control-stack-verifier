"""Strict timestamps: RFC 3339 style with a mandatory UTC offset.

A time without an offset is not evidence (the contract's rule), so it is refused here rather
than guessed at. Accepted: ``YYYY-MM-DDThh:mm:ss[.f+]`` followed by ``Z`` or ``+hh:mm`` /
``-hh:mm``; the separator may be ``T``, ``t`` or a space. Fractions beyond microseconds are
truncated (never rounded).
"""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta, timezone
from typing import Any

_PATTERN = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})[Tt ](\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?(?:([Zz])|([+-])(\d{2}):(\d{2}))$"
)


def aware(value: Any) -> datetime | None:
    """Parse a timezone-aware timestamp, or return None when malformed or without an offset."""
    if type(value) is not str:
        return None
    m = _PATTERN.match(value)
    if m is None:
        return None
    y, mo, d, h, mi, s = (int(m.group(i)) for i in range(1, 7))
    frac = m.group(7) or ""
    micro = int((frac + "000000")[:6])
    if m.group(8):
        tz = UTC
    else:
        oh, om = int(m.group(10)), int(m.group(11))
        if oh > 23 or om > 59:
            return None
        delta = timedelta(hours=oh, minutes=om)
        tz = timezone(delta if m.group(9) == "+" else -delta)
    try:
        return datetime(y, mo, d, h, mi, s, micro, tzinfo=tz)
    except ValueError:
        return None

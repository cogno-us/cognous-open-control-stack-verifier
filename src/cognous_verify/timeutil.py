"""Strict timestamps, as ODES time semantics section 1 defines an instant.

A time without an offset is not evidence (the contract's rule), so it is refused here rather
than guessed at. Accepted: ``YYYY-MM-DDThh:mm:ss[.f]`` followed by ``Z`` or ``+hh:mm`` /
``-hh:mm``. The separator is an upper-case ``T`` (not a space, not ``t``), the zone letter an
upper-case ``Z`` (not ``z``), digits are ASCII, seconds are mandatory. One to six fraction
digits; a seventh is refused, never truncated or rounded (section 1.4). A leap second
(``:60``), hour 24 and offset minutes above 59 are refused (section 1.5). RFC 3339 permits a
space and lower-case letters; the ODES contract does not, and the verifier is not more lenient
than the contract.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta, timezone
from typing import Any

# ASCII digits only (``[0-9]``, never ``\d``, which matches any Unicode digit) and the whole
# string must match (``fullmatch``: a trailing newline is not part of a timestamp).
_PATTERN = re.compile(
    r"([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})"
    r"(?:\.([0-9]{1,6}))?(?:(Z)|([+-])([0-9]{2}):([0-9]{2}))"
)


def aware(value: Any) -> datetime | None:
    """Parse a timezone-aware timestamp, or return None when malformed or without an offset."""
    if type(value) is not str:
        return None
    m = _PATTERN.fullmatch(value)
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

"""Print how the verifier fares on its own smoke corpus (development tool, not shipped).

The operators in tests/damage.py were written by the verifier's author. This is a smoke check
that the verifier catches the damage it was built for and accepts benign rewrites. It is not
the held-out qualification measurement, and its counts are not a detection rate.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tests import damage


def main() -> int:
    table, mismatches, clean_bad = damage.run_all()
    print(f"clean runs not accepted: {len(clean_bad)} of {len(damage.load_corpus())} {clean_bad}")
    print("category  n_eff  as-expected  not-as-expected  n_na")
    for cat in sorted(table):
        t = table[cat]
        print(f"{cat:8}  {t.n_eff:5}  {t.caught_or_accepted:11}  {t.missed:15}  {t.n_na:4}")
    for name, case, expected in mismatches:
        why = damage.KNOWN_MISSES.get((name, case), "UNEXPLAINED")
        print(f"not as expected ({expected}): {name} on {case}: {why}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

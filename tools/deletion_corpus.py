"""List the single-row deletions the verifier still accepts (development tool, not shipped).

For every valid journal fixture and every real run record, delete one row of one list member at a
time and run the verifier over the result. A deletion the verifier still accepts is printed with
its member and position. Rows the record's other rows do not refer to (a hold decision, a
vocabulary change, a trailing attempt row, a profile row) cannot be told from a record that never
had them; ``docs/tiers.md`` states this as a known limit and ``tests/test_deletion_limits.py``
pins one example of each kind. This is a probe of the verifier's own checks, not a detection rate.

Usage: ``python tools/deletion_corpus.py [OUT.json]`` (about a few minutes).
"""

from __future__ import annotations

import copy
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tests.helpers import fixture_paths, load, real_record, real_run_names

from cognous_verify import documents


def accepted(doc: dict[str, Any]) -> bool:
    results = documents.verify_document(copy.deepcopy(doc))
    return not any(r.verdict == "refuted" or r.error for r in results)


def sources() -> list[tuple[str, dict[str, Any]]]:
    out = [(p.stem, load(p)["document"]) for p in fixture_paths("journal", "valid")]
    out += [(f"real-run/{n}", real_record(n)) for n in real_run_names()]
    return out


def deletions(doc: dict[str, Any]) -> list[tuple[str, int, int, dict[str, Any]]]:
    rows = []
    for member, value in doc.items():
        if isinstance(value, list) and value and all(isinstance(x, dict) for x in value):
            for i in range(len(value)):
                damaged = copy.deepcopy(doc)
                del damaged[member][i]
                rows.append((member, i, len(value), damaged))
    return rows


def main(argv: list[str]) -> int:
    still: list[dict[str, Any]] = []
    total = 0
    for name, doc in sources():
        for member, index, of, damaged in deletions(doc):
            total += 1
            if accepted(damaged):
                still.append({"fixture": name, "member": member, "index": index, "of": of})
    print(f"single-row deletions: {total}; still accepted: {len(still)}")
    for member, n in sorted(Counter(r["member"] for r in still).items()):
        print(f"  {member:24} {n}")
    if argv:
        Path(argv[0]).write_text(json.dumps(still, indent=1) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

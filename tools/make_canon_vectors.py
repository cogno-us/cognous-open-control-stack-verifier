"""Generate tests/data/canon-vectors.json from Python's ``json.dumps`` as an outside oracle.

The verifier's own canonicalizer never calls this path; the vectors are written once and
committed, and tests compare the verifier's output to them byte for byte.
Run: python tools/make_canon_vectors.py > tests/data/canon-vectors.json
"""

from __future__ import annotations

import hashlib
import json
import sys

CASES: list[tuple[str, str]] = [
    ("empty-object", "{}"),
    ("empty-array", "[]"),
    ("key-order", '{"b":1,"a":2,"B":3,"_":4}'),
    ("nested-order", '{"z":{"y":1,"x":[{"b":1,"a":2}]},"a":null}'),
    ("whitespace-insignificant", ' { "a" : [ 1 , 2 ] ,\n"b" :\t true } '),
    ("int-vs-float-int", '{"n":1}'),
    ("int-vs-float-float", '{"n":1.0}'),
    ("exponent-form", '{"n":1e2,"m":1E2,"k":1.5e-7,"j":1e16,"i":123456789.123456789}'),
    ("negative-zero-int", '{"n":-0}'),
    ("negative-zero-float", '{"n":-0.0}'),
    ("float-small", '{"n":5e-324}'),
    ("non-ascii-literal", '{"s":"é ü 漢字 😀"}'),
    ("non-ascii-escaped", '{"s":"\\u00e9 \\u00fc \\u6f22\\u5b57 \\ud83d\\ude00"}'),
    ("nfc", '{"s":"\\u00e9"}'),
    ("nfd", '{"s":"e\\u0301"}'),
    ("control-chars", '{"s":"\\u0000\\u0001\\b\\f\\n\\r\\t\\u001f\\u007f"}'),
    ("quote-and-backslash", '{"s":"\\"\\\\\\/"}'),
    ("line-separators", '{"s":"\\u2028\\u2029"}'),
    ("key-order-astral", '{"\\ud83d\\ude00":1,"\\uffff":2,"a":3}'),
    ("key-with-escapes", '{"a\\nb":1,"a\\"b":2}'),
    ("true-false-null", "[true,false,null]"),
    ("array-order-kept", '[3,1,2,{"b":1,"a":2}]'),
    ("amount-fifty", '{"amount":50.0,"effects":1}'),
]


def main() -> int:
    vectors = []
    for vid, raw in CASES:
        value = json.loads(raw)
        canonical = json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
        )
        vectors.append(
            {
                "id": vid,
                "input": raw,
                "canonical": canonical,
                "sha256": hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
            }
        )
    json.dump(
        {
            "profile": "json-sort-keys-compact-utf8-no-nan-python-semantics-v0.1-proposed",
            "oracle": "python json.dumps(sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False)",
            "vectors": vectors,
        },
        sys.stdout,
        indent=1,
        ensure_ascii=True,
    )
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

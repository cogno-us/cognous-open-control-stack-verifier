from __future__ import annotations

import pytest

from cognous_verify import data, timeutil


@pytest.mark.parametrize(
    "value",
    [
        "2026-10-05T19:00:00+00:00",
        "2026-10-05T19:00:00Z",
        "2026-10-05t19:00:00z",
        "2026-10-05 19:00:00.123456+05:30",
        "2026-10-05T19:00:00-08:00",
    ],
)
def test_aware_accepts(value: str) -> None:
    assert timeutil.aware(value) is not None


@pytest.mark.parametrize(
    "value",
    [
        "2026-10-05T19:00:00",
        "2026-10-05T19:00:00.1234567Z",  # a seventh fraction digit is refused, not truncated
        "2026-10-05T19:00:60Z",  # leap second
        "2026-10-05T19:00:00+00:60",  # offset minutes 00 to 59
        "2026-10-05",
        "2026-13-05T19:00:00Z",
        "2026-10-05T25:00:00Z",
        "2026-10-05T19:00:00+25:00",
        "2026-10-05T19:00:00+05:99",
        "20261005T190000Z",
        "",
        None,
        5,
    ],
)
def test_aware_refuses(value: object) -> None:
    assert timeutil.aware(value) is None


def test_aware_offsets_compare_correctly() -> None:
    a = timeutil.aware("2026-10-05T19:00:00+00:00")
    b = timeutil.aware("2026-10-05T21:00:00+02:00")
    assert a is not None and b is not None and a == b


def test_vendored_data_matches_its_provenance() -> None:
    assert data.provenance_problems() == []
    files = {e["file"] for e in data.provenance()["files"]}
    assert files == {
        "control-plane-journal.schema.json",
        "execution-attempt-lifecycle.schema.json",
        "runtime-authority-reasons-0.1.json",
        "runtime-authority-reasons-0.2.json",
    }


def test_registry_and_schema_digests() -> None:
    assert data.registry_version() == "runtime-authority-reasons/0.1"
    assert "grant_revoked" in data.registry_codes()
    assert len(data.registry_codes()) == 121
    assert data.registry_digest().startswith("sha256:")
    assert data.registry_labels() == (
        "runtime-authority-reasons/0.1",
        "runtime-authority-reasons/0.2",
    )
    assert data.registry_version("runtime-authority-reasons/0.2") == (
        "runtime-authority-reasons/0.2"
    )
    assert len(data.registry_codes("runtime-authority-reasons/0.2")) == 158
    # the vendored 0.1 file is byte-identical at Control Plane 6b8fb627 and 3755c71a (121 codes); 0.2 (158) contains all of it
    assert data.registry_codes() <= data.registry_codes("runtime-authority-reasons/0.2")
    digests = data.registry_digests()
    assert digests["runtime-authority-reasons/0.1"] == data.registry_digest()
    assert digests["runtime-authority-reasons/0.1"] != digests["runtime-authority-reasons/0.2"]
    assert data.schema_digest("control-plane-journal").startswith("sha256:")
    assert data.schema("execution-attempt-lifecycle")["required"] == [
        "contract",
        "contract_version",
    ]

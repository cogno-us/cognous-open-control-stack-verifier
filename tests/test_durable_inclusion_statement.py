"""A report does not let journal integrity be read as durable inclusion.

The verification-report contract's ``does_not_prove`` ids are a closed set and carry no id for
durable inclusion, so the statement lives in an existing non-claim whose text is the producer's.
The projection a decision reads (verdict, tally, could-not-check reason) is unchanged by it.
"""

from __future__ import annotations

from cognous_verify import report

ID = "self_consistent_forgery_not_detected"


def _statement() -> str:
    return dict(report.NON_CLAIMS)[ID]


def test_the_statement_says_journal_integrity_is_not_durable_inclusion() -> None:
    text = " ".join(_statement().split()).lower()
    assert "durabl" in text
    assert "journal" in text
    assert "stored" in text or "retained" in text


def test_the_closed_non_claim_ids_are_unchanged() -> None:
    assert [i for i, _ in report.NON_CLAIMS] == [
        "relative_to_pinned_controller",
        "semantic_quality_not_certified",
        "receipt_source_bounded",
        "self_consistent_forgery_not_detected",
        "not_an_attestation",
        "parse_strictness_is_refusal_not_repair",
        "no_v1_scope_claim",
        "differential_agreement_is_not_equivalence",
    ]


def test_the_original_sentence_is_kept() -> None:
    assert "Agreement between records is not evidence that they are genuine." in _statement()

from __future__ import annotations

import hashlib

from REAL_VERIFIER_V15_WORKING import (
    EvidenceItem,
    SourceRecord,
    Role,
    Relation,
    Verdict,
)

from RECOVERED_TEMPORAL_SOURCE import PropositionIdentity, Scope

from REAL_VERIFIER_V15_WORKING import (
    verify_temporal_claim_v15,
)


IDENTITY_A = PropositionIdentity(
    "ENTITY-A", "EVENT-A", "CTX", "TIME"
)

IDENTITY_B = PropositionIdentity(
    "ENTITY-B", "EVENT-B", "CTX", "TIME"
)

IDENTITY_C = PropositionIdentity(
    "ENTITY-C", "EVENT-C", "CTX", "TIME"
)

SCOPE = Scope("SCOPE-1")


def evidence_text(
    relation,
    left_identity=IDENTITY_A,
    right_identity=IDENTITY_B,
    left_scope=SCOPE,
    right_scope=SCOPE,
    left_start="2024-01-01T00:00:00Z",
    left_end="2024-01-01T01:00:00Z",
    right_start="2024-01-01T02:00:00Z",
    right_end="2024-01-01T03:00:00Z",
):
    return "\n".join(
        [
            f"LEFT_ENTITY={left_identity.entity}",
            f"LEFT_EVENT={left_identity.event_or_attribute}",
            f"LEFT_CONTEXT={left_identity.context}",
            f"LEFT_PROPERTY={left_identity.target_property}",
            f"LEFT_SCOPE={left_scope.value}",
            f"LEFT_START={left_start}",
            f"LEFT_END={left_end}",
            f"RIGHT_ENTITY={right_identity.entity}",
            f"RIGHT_EVENT={right_identity.event_or_attribute}",
            f"RIGHT_CONTEXT={right_identity.context}",
            f"RIGHT_PROPERTY={right_identity.target_property}",
            f"RIGHT_SCOPE={right_scope.value}",
            f"RIGHT_START={right_start}",
            f"RIGHT_END={right_end}",
            f"RELATION={relation}",
        ]
    )


def make_source(text):
    content = text.encode("utf-8")
    digest = hashlib.sha256(content).hexdigest()

    source = SourceRecord(
        "SRC-TEMPORAL-1",
        digest,
        "TEST-AUTHORITY",
    )

    evidence = EvidenceItem(
        "E-TEMPORAL-1",
        "SRC-TEMPORAL-1",
        digest,
        "page",
        "1",
        0,
        len(content),
        Role.SUPPORTING,
    )

    return source, evidence, content


def run_case(
    name,
    claim_relation,
    evidence_relation,
    claim_left_start,
    claim_left_end,
    claim_right_start,
    claim_right_end,
    evidence_left_start,
    evidence_left_end,
    evidence_right_start,
    evidence_right_end,
    expected_state,
    expected_verdict,
    evidence_left_identity=IDENTITY_A,
    evidence_right_identity=IDENTITY_B,
    expect_exception=None,
):
    text = evidence_text(
        evidence_relation,
        left_identity=evidence_left_identity,
        right_identity=evidence_right_identity,
        left_start=evidence_left_start,
        left_end=evidence_left_end,
        right_start=evidence_right_start,
        right_end=evidence_right_end,
    )

    source, evidence, content = make_source(text)

    try:
        result = verify_temporal_claim_v15(
            "P-TEMPORAL-1",
            "TEMPORAL-RULE-1",
            claim_relation,
            IDENTITY_A,
            SCOPE,
            claim_left_start,
            claim_left_end,
            IDENTITY_B,
            SCOPE,
            claim_right_start,
            claim_right_end,
            evidence,
            source,
            content,
        )

        if expect_exception is not None:
            print(
                f"FAIL | {name} | expected exception "
                f"{expect_exception}, got result"
            )
            raise AssertionError(name)

        actual_state = result.predicate_evaluations[0].state
        actual_verdict = result.categorical_state

        ok = (
            actual_state == expected_state
            and actual_verdict == expected_verdict
        )

        print(
            f"{'PASS' if ok else 'FAIL'} | {name} | "
            f"state={actual_state} | verdict={actual_verdict}"
        )

        if not ok:
            raise AssertionError(
                f"{name}: expected "
                f"{expected_state}/{expected_verdict}, got "
                f"{actual_state}/{actual_verdict}"
            )

    except Exception as exc:
        if expect_exception is None:
            print(
                f"FAIL | {name} | unexpected "
                f"{type(exc).__name__}: {exc}"
            )
            raise

        actual = str(exc)

        ok = actual == expect_exception

        print(
            f"{'PASS' if ok else 'FAIL'} | {name} | "
            f"exception={actual}"
        )

        if not ok:
            raise AssertionError(
                f"{name}: expected exception "
                f"{expect_exception}, got {actual}"
            )


# 01 — Evidence-derived PRECEDES TRUE
run_case(
    "01_PRECEDES_TRUE",
    Relation.PRECEDES,
    "PRECEDES",
    "2024-01-01T00:00:00Z",
    "2024-01-01T01:00:00Z",
    "2024-01-01T02:00:00Z",
    "2024-01-01T03:00:00Z",
    "2024-01-01T00:00:00Z",
    "2024-01-01T01:00:00Z",
    "2024-01-01T02:00:00Z",
    "2024-01-01T03:00:00Z",
    "TRUE",
    Verdict.SUPPORTED,
)


# 02 — Evidence-derived PRECEDES FALSE
run_case(
    "02_PRECEDES_FALSE",
    Relation.PRECEDES,
    "PRECEDES",
    "2024-01-01T00:00:00Z",
    "2024-01-01T01:00:00Z",
    "2024-01-01T02:00:00Z",
    "2024-01-01T03:00:00Z",
    "2024-01-01T02:00:00Z",
    "2024-01-01T03:00:00Z",
    "2024-01-01T00:00:00Z",
    "2024-01-01T01:00:00Z",
    "FALSE",
    Verdict.NOT_SUPPORTED,
)


# 03 — Precision prevents definite PRECEDES
run_case(
    "03_PRECEDES_PRECISION_UNKNOWN",
    Relation.PRECEDES,
    "PRECEDES",
    "2024-01-01T10:00Z",
    "2024-01-01T11:00Z",
    "2024-01-01T11:00Z",
    "2024-01-01T12:00Z",
    "2024-01-01T10:00Z",
    "2024-01-01T11:00Z",
    "2024-01-01T11:00Z",
    "2024-01-01T12:00Z",
    "UNKNOWN",
    Verdict.UNKNOWN,
)


# 04 — Evidence-derived OVERLAPS TRUE
run_case(
    "04_OVERLAPS_TRUE",
    Relation.OVERLAPS,
    "OVERLAPS",
    "2024-01-01T00:00:00Z",
    "2024-01-01T02:00:00Z",
    "2024-01-01T01:00:00Z",
    "2024-01-01T03:00:00Z",
    "2024-01-01T00:00:00Z",
    "2024-01-01T02:00:00Z",
    "2024-01-01T01:00:00Z",
    "2024-01-01T03:00:00Z",
    "TRUE",
    Verdict.SUPPORTED,
)


# 05 — Evidence-derived OVERLAPS FALSE
run_case(
    "05_OVERLAPS_FALSE",
    Relation.OVERLAPS,
    "OVERLAPS",
    "2024-01-01T00:00:00Z",
    "2024-01-01T01:00:00Z",
    "2024-01-01T02:00:00Z",
    "2024-01-01T03:00:00Z",
    "2024-01-01T00:00:00Z",
    "2024-01-01T01:00:00Z",
    "2024-01-01T02:00:00Z",
    "2024-01-01T03:00:00Z",
    "FALSE",
    Verdict.NOT_SUPPORTED,
)


# 06 — Boundary-touching closed intervals overlap
run_case(
    "06_OVERLAPS_BOUNDARY",
    Relation.OVERLAPS,
    "OVERLAPS",
    "2024-01-01T00:00:00Z",
    "2024-01-01T02:00:00Z",
    "2024-01-01T02:00:00Z",
    "2024-01-01T04:00:00Z",
    "2024-01-01T00:00:00Z",
    "2024-01-01T02:00:00Z",
    "2024-01-01T02:00:00Z",
    "2024-01-01T04:00:00Z",
    "TRUE",
    Verdict.SUPPORTED,
)


# 07 — Exact CONCURRENT
run_case(
    "07_CONCURRENT_TRUE",
    Relation.CONCURRENT,
    "CONCURRENT",
    "2024-01-01T00:00:00Z",
    "2024-01-01T01:00:00Z",
    "2024-01-01T00:00:00Z",
    "2024-01-01T01:00:00Z",
    "2024-01-01T00:00:00Z",
    "2024-01-01T01:00:00Z",
    "2024-01-01T00:00:00Z",
    "2024-01-01T01:00:00Z",
    "TRUE",
    Verdict.SUPPORTED,
)


# 08 — Evidence identity mismatch must not become support
run_case(
    "08_IDENTITY_MISMATCH",
    Relation.PRECEDES,
    "PRECEDES",
    "2024-01-01T00:00:00Z",
    "2024-01-01T01:00:00Z",
    "2024-01-01T02:00:00Z",
    "2024-01-01T03:00:00Z",
    "2024-01-01T00:00:00Z",
    "2024-01-01T01:00:00Z",
    "2024-01-01T02:00:00Z",
    "2024-01-01T03:00:00Z",
    "NOT_EVALUATED",
    Verdict.NOT_EVALUATED,
    evidence_left_identity=IDENTITY_C,
)


# 09 — Malformed evidence must become a V15 ERROR verdict.
bad_text = "THIS IS NOT VALID TEMPORAL EVIDENCE"
source, evidence, content = make_source(bad_text)

result = verify_temporal_claim_v15(
    "P-TEMPORAL-1",
    "TEMPORAL-RULE-1",
    Relation.PRECEDES,
    IDENTITY_A,
    SCOPE,
    "2024-01-01T00:00:00Z",
    "2024-01-01T01:00:00Z",
    IDENTITY_B,
    SCOPE,
    "2024-01-01T02:00:00Z",
    "2024-01-01T03:00:00Z",
    evidence,
    source,
    content,
)

assert result.categorical_state == Verdict.ERROR, (
    "09_MALFORMED_EVIDENCE: expected Verdict.ERROR"
)

error_trace = [
    step
    for step in result.complete_proof_trace
    if step.get("step") == "TEMPORAL_ERROR"
]

assert error_trace, (
    "09_MALFORMED_EVIDENCE: missing TEMPORAL_ERROR trace"
)

assert error_trace[0]["reason"] == "INVALID_TEMPORAL_EVIDENCE_FORMAT", (
    "09_MALFORMED_EVIDENCE: incorrect error reason"
)

print(
    "PASS | 09_MALFORMED_EVIDENCE | "
    "state=ERROR | verdict=Verdict.ERROR | "
    "reason=INVALID_TEMPORAL_EVIDENCE_FORMAT"
)


# 10 — Unsupported relation must become a V15 ERROR verdict.
run_case(
    "10_UNSUPPORTED_RELATION",
    Relation.CAUSE,
    "PRECEDES",
    "2024-01-01T00:00:00Z",
    "2024-01-01T01:00:00Z",
    "2024-01-01T02:00:00Z",
    "2024-01-01T03:00:00Z",
    "2024-01-01T00:00:00Z",
    "2024-01-01T01:00:00Z",
    "2024-01-01T02:00:00Z",
    "2024-01-01T03:00:00Z",
    "ERROR",
    Verdict.ERROR,
    expect_exception=None,
)

print()
print("TEMPORAL V15 EVIDENCE-DERIVED CERTIFICATION COMPLETE")

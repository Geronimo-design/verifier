from __future__ import annotations

import re

from REAL_VERIFIER_V15_WORKING import (
    EvidenceItem,
    SourceRecord,
    Verdict,
    PredicateEvaluation,
    validate_evidence,
    aggregate,
    Relation,
)

from RECOVERED_TEMPORAL_SOURCE import (
    PropositionIdentity,
    Scope,
    TemporalEndpoint,
    TemporalClaim,
    TemporalEvidence,
    TemporalRelation,
    PredicateState,
    validate_temporal_interval,
    evaluate_temporal_claim_against_evidence,
)


def _map_relation(relation: Relation) -> TemporalRelation:
    mapping = {
        Relation.PRECEDES: TemporalRelation.PRECEDES,
        Relation.OVERLAPS: TemporalRelation.OVERLAPS,
        Relation.CONCURRENT: TemporalRelation.CONCURRENT,
    }
    if relation not in mapping:
        raise ValueError("UNSUPPORTED_TEMPORAL_RELATION")
    return mapping[relation]


def _map_state(state: PredicateState) -> str:
    mapping = {
        PredicateState.TRUE: "TRUE",
        PredicateState.FALSE: "FALSE",
        PredicateState.UNKNOWN: "UNKNOWN",
        PredicateState.NOT_EVALUATED: "NOT_EVALUATED",
        PredicateState.ERROR: "ERROR",
    }
    if state not in mapping:
        raise ValueError("UNMAPPED_TEMPORAL_STATE")
    return mapping[state]


_TEMPORAL_EVIDENCE_FIELDS = (
    "LEFT_ENTITY",
    "LEFT_EVENT",
    "LEFT_CONTEXT",
    "LEFT_PROPERTY",
    "LEFT_SCOPE",
    "LEFT_START",
    "LEFT_END",
    "RIGHT_ENTITY",
    "RIGHT_EVENT",
    "RIGHT_CONTEXT",
    "RIGHT_PROPERTY",
    "RIGHT_SCOPE",
    "RIGHT_START",
    "RIGHT_END",
    "RELATION",
)


def _parse_temporal_evidence_bytes(source_bytes: bytes):
    if not isinstance(source_bytes, bytes):
        raise ValueError("INVALID_SOURCE_BYTES")

    try:
        text = source_bytes.decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError("INVALID_UTF8_EVIDENCE")

    lines = text.splitlines()
    if len(lines) != len(_TEMPORAL_EVIDENCE_FIELDS):
        raise ValueError("INVALID_TEMPORAL_EVIDENCE_FORMAT")

    values = {}

    for expected_key, line in zip(_TEMPORAL_EVIDENCE_FIELDS, lines):
        if "=" not in line:
            raise ValueError("INVALID_TEMPORAL_EVIDENCE_FORMAT")

        key, value = line.split("=", 1)

        if key != expected_key:
            raise ValueError("INVALID_TEMPORAL_EVIDENCE_FORMAT")

        if value == "":
            raise ValueError("EMPTY_TEMPORAL_EVIDENCE_FIELD")

        if key in values:
            raise ValueError("DUPLICATE_TEMPORAL_EVIDENCE_FIELD")

        values[key] = value

    allowed_relation = {
        "PRECEDES": TemporalRelation.PRECEDES,
        "OVERLAPS": TemporalRelation.OVERLAPS,
        "CONCURRENT": TemporalRelation.CONCURRENT,
    }

    if values["RELATION"] not in allowed_relation:
        raise ValueError("UNSUPPORTED_TEMPORAL_RELATION")

    def identity(prefix):
        return PropositionIdentity(
            values[f"{prefix}_ENTITY"],
            values[f"{prefix}_EVENT"],
            values[f"{prefix}_CONTEXT"],
            values[f"{prefix}_PROPERTY"],
        )

    left_identity = identity("LEFT")
    right_identity = identity("RIGHT")

    left_scope = Scope(values["LEFT_SCOPE"])
    right_scope = Scope(values["RIGHT_SCOPE"])

    left_interval = validate_temporal_interval(
        values["LEFT_START"],
        values["LEFT_END"],
    )

    right_interval = validate_temporal_interval(
        values["RIGHT_START"],
        values["RIGHT_END"],
    )

    left_endpoint = TemporalEndpoint(
        identity=left_identity,
        scope=left_scope,
        interval=left_interval,
    )

    right_endpoint = TemporalEndpoint(
        identity=right_identity,
        scope=right_scope,
        interval=right_interval,
    )

    return (
        allowed_relation[values["RELATION"]],
        left_endpoint,
        right_endpoint,
        values,
    )


def verify_temporal_claim_v15(
    prop_id: str,
    rule_id: str,
    relation: Relation,
    left_identity: PropositionIdentity,
    left_scope: Scope,
    left_start: str,
    left_end: str,
    right_identity: PropositionIdentity,
    right_scope: Scope,
    right_start: str,
    right_end: str,
    evidence: EvidenceItem,
    source: SourceRecord,
    content: bytes,
):
    # V15 trust boundary: authenticate source and exact evidence bytes first.
    span = validate_evidence(evidence, source, content)

    observed = span.decode("utf-8", errors="strict")

    try:
        # Evidence-side temporal facts are derived ONLY from the authenticated span.
        (
            evidence_relation,
            evidence_left,
            evidence_right,
            evidence_fields,
        ) = _parse_temporal_evidence_bytes(span)

        claim_relation = _map_relation(relation)

        claim_left = TemporalEndpoint(
            identity=left_identity,
            scope=left_scope,
            interval=validate_temporal_interval(left_start, left_end),
        )

        claim_right = TemporalEndpoint(
            identity=right_identity,
            scope=right_scope,
            interval=validate_temporal_interval(right_start, right_end),
        )

        claim = TemporalClaim(
            proposition_id=prop_id,
            relation=claim_relation,
            left=claim_left,
            right=claim_right,
        )

        temporal_evidence = TemporalEvidence(
            predicate_id=prop_id,
            relation=evidence_relation,
            left=evidence_left,
            right=evidence_right,
        )

        disposition = evaluate_temporal_claim_against_evidence(
            claim,
            temporal_evidence,
        )

        relation_state = None
        for result in disposition.predicate_results:
            if result.predicate_id == "TEMPORAL_RELATION":
                relation_state = result.state
                break

        if relation_state is None:
            state = _map_state(
                {
                    Verdict.SUPPORTED: PredicateState.TRUE,
                    Verdict.NOT_SUPPORTED: PredicateState.FALSE,
                    Verdict.UNKNOWN: PredicateState.UNKNOWN,
                    Verdict.NOT_EVALUATED: PredicateState.NOT_EVALUATED,
                    Verdict.ERROR: PredicateState.ERROR,
                }[disposition.verdict]
            )
        else:
            state = _map_state(relation_state)

        predicate = PredicateEvaluation(
            prop_id,
            state,
            (evidence.evidence_id,),
            ("TEMPORAL_PRECISION_RELATION",),
        )

        trace = (
            {
                "step": "SOURCE_DIGEST",
                "source_id": source.source_id,
                "digest": source.content_digest,
            },
            {
                "step": "EVIDENCE_LOCATION",
                "source_id": source.source_id,
                "coordinate_type": evidence.coordinate_type,
                "coordinate_value": evidence.coordinate_value,
                "start_byte": evidence.start_byte,
                "end_byte": evidence.end_byte,
                "exact_text": observed,
            },
            {
                "step": "EVIDENCE_DERIVATION",
                "relation": evidence_relation.value,
                "left_start": evidence_fields["LEFT_START"],
                "left_end": evidence_fields["LEFT_END"],
                "right_start": evidence_fields["RIGHT_START"],
                "right_end": evidence_fields["RIGHT_END"],
            },
            {
                "step": "RULE",
                "rule_id": rule_id,
                "predicate": claim_relation.value,
                "claim_left_start": left_start,
                "claim_left_end": left_end,
                "claim_right_start": right_start,
                "claim_right_end": right_end,
            },
            {
                "step": "TEMPORAL_STATE",
                "state": state,
            },
            {
                "step": "VERDICT",
                "state": state,
            },
        )

        return aggregate(
            prop_id,
            rule_id,
            (predicate,),
            trace,
        )

    except ValueError as exc:
        predicate = PredicateEvaluation(
            prop_id,
            PredicateState.ERROR,
            (evidence.evidence_id,),
            ("TEMPORAL_INPUT_VALIDATION",),
        )

        trace = (
            {
                "step": "SOURCE_DIGEST",
                "source_id": source.source_id,
                "digest": source.content_digest,
            },
            {
                "step": "EVIDENCE_LOCATION",
                "source_id": source.source_id,
                "coordinate_type": evidence.coordinate_type,
                "coordinate_value": evidence.coordinate_value,
                "start_byte": evidence.start_byte,
                "end_byte": evidence.end_byte,
            },
            {
                "step": "TEMPORAL_ERROR",
                "error_type": type(exc).__name__,
                "reason": str(exc),
            },
            {
                "step": "TEMPORAL_STATE",
                "state": PredicateState.ERROR,
            },
            {
                "step": "VERDICT",
                "state": PredicateState.ERROR,
            },
        )

        return aggregate(
            prop_id,
            rule_id,
            (predicate,),
            trace,
        )

    return aggregate(
        prop_id,
        rule_id,
        (predicate,),
        trace,
    )

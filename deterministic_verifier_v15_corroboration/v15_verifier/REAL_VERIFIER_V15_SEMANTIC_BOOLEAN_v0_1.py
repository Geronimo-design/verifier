from __future__ import annotations
import hashlib

from dataclasses import dataclass
from enum import Enum
from typing import Optional, Tuple, Any, Union


class Verdict(str, Enum):
    SUPPORTED = "SUPPORTED"
    NOT_SUPPORTED = "NOT_SUPPORTED"
    UNKNOWN = "UNKNOWN"
    NOT_EVALUATED = "NOT_EVALUATED"
    ERROR = "ERROR"


class PredicateState(str, Enum):
    TRUE = "TRUE"
    FALSE = "FALSE"
    UNKNOWN = "UNKNOWN"
    NOT_EVALUATED = "NOT_EVALUATED"
    ERROR = "ERROR"


class Cardinality(str, Enum):
    SINGLE = "SINGLE"
    MULTI = "MULTI"


class Polarity(str, Enum):
    AFFIRMATION = "AFFIRMATION"
    NEGATION = "NEGATION"
    ABSENCE = "ABSENCE"


class TemporalRelation(str, Enum):
    PRECEDES = "PRECEDES"
    OVERLAPS = "OVERLAPS"
    CONCURRENT = "CONCURRENT"


@dataclass(frozen=True)
class PropositionIdentity:
    entity: str
    event_or_attribute: str
    context: str
    target_property: str


@dataclass(frozen=True)
class Scope:
    value: str


@dataclass(frozen=True)
class DocumentObservation:
    """Observed location/count information about a claim in a source document.

    Observation does not establish truth. It only records what was observed.
    """
    source_id: str
    occurrence_count: int
    page: Optional[int] = None
    paragraph: Optional[int] = None
    location: Optional[str] = None

@dataclass(frozen=True)
class Claim:
    proposition_id: str
    identity: PropositionIdentity
    scope: Scope
    value: str
    polarity: Polarity
    cardinality: Cardinality
    observation: Optional[DocumentObservation] = None


@dataclass(frozen=True)
class Evidence:
    predicate_id: str
    identity: PropositionIdentity
    scope: Scope
    polarity: Polarity
    values: Tuple[str, ...]


@dataclass(frozen=True)
class PredicateResult:
    predicate_id: str
    state: PredicateState


@dataclass(frozen=True)
class Disposition:
    verdict: Verdict
    reason: str
    predicate_results: Tuple[PredicateResult, ...] = ()
    lawyer_check_required: bool = False
    evidence_gap: Optional[str] = None
    review_reasons: Tuple[str, ...] = ()


class RequirementTier(Enum):
    REQUIRED = "REQUIRED"
    OPTIONAL = "OPTIONAL"
    CONDITIONAL = "CONDITIONAL"

class AuthorityEdgeType(Enum):
    SUPERSEDES = "SUPERSEDES"
    VARIES = "VARIES"
    QUALIFIES = "QUALIFIES"

@dataclass(frozen=True)
class AuthorityEdge:
    source_path_id: str
    target_path_id: str
    edge_type: AuthorityEdgeType
    is_authenticated: bool = False

# G01_AUTHORITY_VALIDATION_V1

@dataclass(frozen=True)
class AuthorityAssertion:
    """Untrusted authority assertion supported by current-verifier evidence."""
    source_path_id: str
    target_path_id: str
    edge_type: AuthorityEdgeType
    supporting_evidence: Optional[Evidence] = None


@dataclass(frozen=True)
class AuthorityValidationResult:
    edge: Optional[AuthorityEdge]
    warning: Optional[str] = None


def validate_authority_assertion(
    assertion: AuthorityAssertion,
    path_ids: set[str],
) -> AuthorityValidationResult:
    if assertion.source_path_id not in path_ids:
        return AuthorityValidationResult(None, "AUTHORITY_SOURCE_PATH_NOT_FOUND")
    if assertion.target_path_id not in path_ids:
        return AuthorityValidationResult(None, "AUTHORITY_TARGET_PATH_NOT_FOUND")
    if assertion.source_path_id == assertion.target_path_id:
        return AuthorityValidationResult(None, "AUTHORITY_SELF_REFERENCE")
    if not isinstance(assertion.edge_type, AuthorityEdgeType):
        return AuthorityValidationResult(None, "AUTHORITY_INVALID_EDGE_TYPE")
    if assertion.supporting_evidence is None:
        return AuthorityValidationResult(None, "AUTHORITY_EVIDENCE_MISSING")
    if not isinstance(assertion.supporting_evidence, Evidence):
        return AuthorityValidationResult(None, "AUTHORITY_EVIDENCE_TYPE_MISMATCH")

    expected_claim = Claim(
        proposition_id=(
            f"AUTHORITY:{assertion.source_path_id}:"
            f"{assertion.edge_type.value}:{assertion.target_path_id}"
        ),
        identity=PropositionIdentity(
            assertion.source_path_id,
            "AUTHORITY_RELATION",
            assertion.edge_type.value,
            assertion.target_path_id,
        ),
        scope=Scope("AUTHORITY"),
        value="ESTABLISHED",
        polarity=Polarity.AFFIRMATION,
        cardinality=Cardinality.SINGLE,
    )

    disposition = evaluate_claim_against_evidence(
        expected_claim,
        assertion.supporting_evidence,
    )

    if disposition.verdict is not Verdict.SUPPORTED:
        return AuthorityValidationResult(
            None,
            f"AUTHORITY_EVIDENCE_{disposition.verdict.value}",
        )

    return AuthorityValidationResult(
        AuthorityEdge(
            source_path_id=assertion.source_path_id,
            target_path_id=assertion.target_path_id,
            edge_type=assertion.edge_type,
            is_authenticated=True,
        )
    )

@dataclass(frozen=True)
class SourceIntegrityRecord:
    source_id: str
    source_digest: str
    encoding: str
    start_byte: int
    end_byte: int
    span_digest: str


@dataclass(frozen=True)
class IntegrityResult:
    valid: bool
    reason: str


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def verify_source_integrity(
    record: SourceIntegrityRecord,
    source_id: str,
    source: bytes,
) -> IntegrityResult:
    if record.source_id != source_id:
        return IntegrityResult(False, "SOURCE_ID_MISMATCH")

    try:
        source.decode(record.encoding)
    except (LookupError, UnicodeDecodeError):
        return IntegrityResult(False, "INVALID_SOURCE_ENCODING")

    if record.start_byte < 0 or record.end_byte < 0:
        return IntegrityResult(False, "NEGATIVE_BYTE_OFFSET")

    if record.start_byte > record.end_byte:
        return IntegrityResult(False, "REVERSED_BYTE_RANGE")

    if record.end_byte > len(source):
        return IntegrityResult(False, "BYTE_RANGE_OUT_OF_BOUNDS")

    if sha256_bytes(source) != record.source_digest:
        return IntegrityResult(False, "SOURCE_DIGEST_MISMATCH")

    span = source[record.start_byte:record.end_byte]

    if sha256_bytes(span) != record.span_digest:
        return IntegrityResult(False, "SPAN_DIGEST_MISMATCH")

    return IntegrityResult(True, "SOURCE_INTEGRITY_VERIFIED")


@dataclass(frozen=True)
class EvidencePathRequirement:
    path_id: str
    evidence_reference: str
    evidence: Union[Evidence, TemporalEvidence]
    tier: RequirementTier = RequirementTier.REQUIRED
    scope: Optional[str] = None
    gating_condition: Optional[Any] = None
    authority_edge: Optional[AuthorityEdge] = None
    authority_assertion: Optional[AuthorityAssertion] = None
    source_integrity_required: bool = False
    source_integrity: Optional[SourceIntegrityRecord] = None
    source_id: Optional[str] = None
    source_bytes: Optional[bytes] = None

@dataclass(frozen=True)
class MultiEvidenceBundle:
    claim_id: str
    claim: Union[Claim, TemporalClaim]
    paths: Tuple[EvidencePathRequirement, ...]

@dataclass(frozen=True)
class PathLedgerEntry:
    path_id: str
    evidence_reference: str
    tier: RequirementTier
    raw_disposition: Optional[Disposition]
    extracted_state: PredicateState
    trace_warning: Optional[str] = None
    displaced_by_authority: bool = False
    evidence_gap: Optional[str] = None

@dataclass(frozen=True)
class MultiEvidenceResult:
    claim_id: str
    public_verdict: Verdict
    reason_code: str
    forensic_ledger: Tuple[PathLedgerEntry, ...]
    lawyer_check_required: bool = False
    review_reasons: Tuple[str, ...] = ()
    evidence_gaps: Tuple[str, ...] = ()


def resolve_authority_paths(
    paths: Tuple[EvidencePathRequirement, ...],
) -> tuple[set[str], tuple[str, ...]]:
    """
    Resolve authority only from validated authority assertions.

    A caller-supplied AuthorityEdge is never trusted as authentication.
    An AuthorityAssertion must carry current-verifier Evidence that
    deterministically establishes the exact authority relation.
    """
    displaced: set[str] = set()
    warnings: list[str] = []
    path_ids = {path.path_id for path in paths}
    supersedes_edges: list[AuthorityEdge] = []

    for path in paths:
        assertion = path.authority_assertion
        raw_edge = path.authority_edge

        if assertion is None:
            if raw_edge is not None:
                warnings.append("UNAUTHENTICATED_AUTHORITY_EDGE")
            continue

        validation = validate_authority_assertion(assertion, path_ids)

        if validation.warning is not None:
            warnings.append(validation.warning)
            continue

        edge = validation.edge
        if edge is None:
            warnings.append("AUTHORITY_VALIDATION_FAILED")
            continue

        if raw_edge is not None and raw_edge != edge:
            warnings.append("AUTHORITY_EDGE_ASSERTION_MISMATCH")
            continue

        if edge.edge_type == AuthorityEdgeType.SUPERSEDES:
            supersedes_edges.append(edge)
            displaced.add(edge.target_path_id)

    for target in {e.target_path_id for e in supersedes_edges}:
        sources = {
            e.source_path_id
            for e in supersedes_edges
            if e.target_path_id == target
        }
        if len(sources) > 1:
            warnings.append("CONFLICTING_AUTHORITY_SUPERSESSION")

    graph = {}
    for edge in supersedes_edges:
        graph.setdefault(edge.source_path_id, set()).add(edge.target_path_id)

    def reaches_cycle(start: str) -> bool:
        visiting = set()
        visited = set()

        def visit(node: str) -> bool:
            if node in visiting:
                return True
            if node in visited:
                return False

            visiting.add(node)
            for nxt in graph.get(node, ()):
                if visit(nxt):
                    return True

            visiting.remove(node)
            visited.add(node)
            return False

        return visit(start)

    if any(reaches_cycle(node) for node in graph):
        warnings.append("CIRCULAR_AUTHORITY_SUPERSESSION")

    if warnings:
        return set(), tuple(sorted(set(warnings)))

    return displaced, ()


def evaluate_gating_condition(condition: Any) -> PredicateState:
    """
    Deterministically evaluate a conditional-path gate.

    Only the existing PredicateState type is accepted.  No arbitrary
    truthiness or callable execution is permitted.

    None or any other type is malformed and fails closed as
    NOT_EVALUATED.
    """
    if isinstance(condition, PredicateState):
        return condition
    return PredicateState.NOT_EVALUATED


def adjudicate_multi_evidence(bundle: MultiEvidenceBundle) -> MultiEvidenceResult:
    if not bundle.paths:
        return MultiEvidenceResult(
            claim_id=bundle.claim_id,
            public_verdict=Verdict.UNKNOWN,
            reason_code="EMPTY_EVIDENCE_BUNDLE",
            forensic_ledger=(),
            lawyer_check_required=True,
            review_reasons=("EMPTY_EVIDENCE_BUNDLE",),
            evidence_gaps=("EMPTY_EVIDENCE_BUNDLE",),
        )

    raw_records = []
    has_global_error = False

    for path_req in bundle.paths:
        if path_req.evidence is None:
            raw_disp = Disposition(
                Verdict.UNKNOWN,
                "Required evidence object is missing",
                (
                    PredicateResult(
                        "EVIDENCE_PRESENCE",
                        PredicateState.UNKNOWN,
                    ),
                ),
                lawyer_check_required=True,
                evidence_gap="MISSING_REQUIRED_EVIDENCE",
                review_reasons=("MISSING_REQUIRED_EVIDENCE",),
            )
        else:
            if path_req.source_integrity_required:
                if (
                    path_req.source_integrity is None
                    or path_req.source_id is None
                    or path_req.source_bytes is None
                ):
                    raw_disp = Disposition(
                        Verdict.NOT_EVALUATED,
                        "Required source integrity information is missing",
                        (
                            PredicateResult(
                                "SOURCE_INTEGRITY",
                                PredicateState.NOT_EVALUATED,
                            ),
                        ),
                        lawyer_check_required=True,
                        evidence_gap="SOURCE_INTEGRITY_REQUIRED",
                        review_reasons=("SOURCE_INTEGRITY_REQUIRED",),
                    )
                else:
                    integrity = verify_source_integrity(
                        path_req.source_integrity,
                        path_req.source_id,
                        path_req.source_bytes,
                    )

                    if not integrity.valid:
                        raw_disp = Disposition(
                            Verdict.NOT_EVALUATED,
                            integrity.reason,
                            (
                                PredicateResult(
                                    "SOURCE_INTEGRITY",
                                    PredicateState.NOT_EVALUATED,
                                ),
                            ),
                            lawyer_check_required=True,
                            evidence_gap=integrity.reason,
                            review_reasons=(integrity.reason,),
                        )
                    else:
                        raw_disp = None
            else:
                raw_disp = None

            if raw_disp is None:
                if isinstance(bundle.claim, TemporalClaim):
                    if isinstance(path_req.evidence, TemporalEvidence):
                        raw_disp = evaluate_temporal_claim_against_evidence(
                            bundle.claim,
                            path_req.evidence,
                        )
                    else:
                        raw_disp = Disposition(
                            Verdict.NOT_EVALUATED,
                            "Temporal claim requires authorized temporal evidence",
                            (
                                PredicateResult(
                                    "TEMPORAL_EVIDENCE_TYPE",
                                    PredicateState.NOT_EVALUATED,
                                ),
                            ),
                            lawyer_check_required=True,
                            evidence_gap="TEMPORAL_EVIDENCE_TYPE_MISMATCH",
                            review_reasons=("TEMPORAL_EVIDENCE_TYPE_MISMATCH",),
                        )
                elif isinstance(path_req.evidence, TemporalEvidence):
                    raw_disp = Disposition(
                        Verdict.NOT_EVALUATED,
                        "Ordinary claim cannot be evaluated against temporal evidence",
                        (
                            PredicateResult(
                                "TEMPORAL_EVIDENCE_TYPE",
                                PredicateState.NOT_EVALUATED,
                            ),
                        ),
                        lawyer_check_required=True,
                        evidence_gap="TEMPORAL_EVIDENCE_TYPE_MISMATCH",
                        review_reasons=("TEMPORAL_EVIDENCE_TYPE_MISMATCH",),
                    )
                else:
                    raw_disp = evaluate_claim_against_evidence(
                        bundle.claim,
                        path_req.evidence,
                    )

        if raw_disp and raw_disp.predicate_results:
            pred_states = tuple(p.state for p in raw_disp.predicate_results)
            extracted_state = reduce_and(*pred_states)
        else:
            extracted_state = PredicateState.UNKNOWN

        if extracted_state == PredicateState.ERROR:
            has_global_error = True

        raw_records.append({
            "path_req": path_req,
            "raw_disposition": raw_disp,
            "extracted_state": extracted_state,
            "trace_warning": (
                "MISSING_REQUIRED_EVIDENCE"
                if path_req.evidence is None
                else (
                    raw_disp.evidence_gap
                    if raw_disp is not None and raw_disp.evidence_gap is not None
                    else (
                        raw_disp.review_reasons[0]
                        if raw_disp is not None and raw_disp.review_reasons
                        else None
                    )
                )
            ),
            "displaced_by_authority": False,
            "conditional_gate_state": (
                evaluate_gating_condition(path_req.gating_condition)
                if path_req.tier == RequirementTier.CONDITIONAL
                else None
            ),
        })

    if has_global_error:
        ledger = tuple(
            PathLedgerEntry(
                path_id=r["path_req"].path_id,
                evidence_reference=r["path_req"].evidence_reference,
                tier=r["path_req"].tier,
                raw_disposition=r["raw_disposition"],
                extracted_state=r["extracted_state"],
                trace_warning=r["trace_warning"],
                displaced_by_authority=False,
            )
            for r in raw_records
        )

        return MultiEvidenceResult(
            claim_id=bundle.claim_id,
            public_verdict=Verdict.ERROR,
            reason_code="EVIDENCE_EVALUATION_ERROR",
            forensic_ledger=ledger,
            lawyer_check_required=True,
            review_reasons=("EVIDENCE_EVALUATION_ERROR",),
            evidence_gaps=("EVIDENCE_EVALUATION_ERROR",),
        )

    displaced_path_ids, authority_warnings = resolve_authority_paths(
        bundle.paths,
    )

    for r in raw_records:
        if r["path_req"].path_id in displaced_path_ids:
            r["displaced_by_authority"] = True
            if r["trace_warning"]:
                r["trace_warning"] += "; DISPLACED_BY_AUTHORITY"
            else:
                r["trace_warning"] = "DISPLACED_BY_AUTHORITY"

    seen_dedup_keys = set()
    active_req_entries = []
    conditional_gate_failures = []
    evidence_identity_conflict = False

    for r in raw_records:
        path_req = r["path_req"]

        # An authority-displaced path remains in the forensic ledger
        # but must not participate in conditional-gate evaluation
        # or active adjudication.
        if path_req.path_id in displaced_path_ids:
            continue

        if path_req.tier == RequirementTier.CONDITIONAL:
            gate_state = r["conditional_gate_state"]

            if gate_state == PredicateState.FALSE:
                r["trace_warning"] = (
                    "CONDITIONAL_PATH_INACTIVE"
                )
                r["conditional_active"] = False
            elif gate_state == PredicateState.TRUE:
                r["conditional_active"] = True
            else:
                r["conditional_active"] = False
                if gate_state == PredicateState.ERROR:
                    r["trace_warning"] = "CONDITIONAL_GATE_ERROR"
                    conditional_gate_failures.append(
                        PredicateState.ERROR
                    )
                elif gate_state == PredicateState.NOT_EVALUATED:
                    r["trace_warning"] = "CONDITIONAL_GATE_NOT_EVALUATED"
                    conditional_gate_failures.append(
                        PredicateState.NOT_EVALUATED
                    )
                else:
                    r["trace_warning"] = "CONDITIONAL_GATE_UNKNOWN"
                    conditional_gate_failures.append(
                        PredicateState.UNKNOWN
                    )

        if path_req.tier == RequirementTier.OPTIONAL:
            if r["extracted_state"] == PredicateState.NOT_EVALUATED:
                r["trace_warning"] = "OPTIONAL_PATH_NOT_EVALUATED"
            elif r["extracted_state"] == PredicateState.UNKNOWN:
                r["trace_warning"] = "OPTIONAL_PATH_UNKNOWN"

        # An inactive CONDITIONAL path remains in the forensic ledger
        # but must not consume an active deduplication key.
        if (
            path_req.tier == RequirementTier.CONDITIONAL
            and r.get("conditional_active") is False
        ):
            continue

        # An OPTIONAL path remains in the forensic ledger and may carry
        # its own review warning, but it must never consume an active
        # deduplication key or suppress a REQUIRED/active CONDITIONAL path.
        if path_req.tier == RequirementTier.OPTIONAL:
            continue

        dedup_key = (
            path_req.evidence_reference,
            bundle.claim_id,
            path_req.scope,
        )

        if r["path_req"].path_id in displaced_path_ids:
            continue

        if dedup_key in seen_dedup_keys:
            existing_entry = next(
                (
                    e for e in active_req_entries
                    if (
                        e["path_req"].evidence_reference,
                        bundle.claim_id,
                        e["path_req"].scope,
                    ) == dedup_key
                ),
                None,
            )

            if (
                existing_entry is not None
                and existing_entry["path_req"].evidence
                != path_req.evidence
            ):
                if r["trace_warning"]:
                    r["trace_warning"] += "; UNRESOLVED_EVIDENCE_CONFLICT"
                else:
                    r["trace_warning"] = "UNRESOLVED_EVIDENCE_CONFLICT"

                active_req_entries.append(r)
                evidence_identity_conflict = True
            else:
                if r["trace_warning"]:
                    r["trace_warning"] = (
                        r["trace_warning"]
                        + "; DUPLICATE_EVIDENCE_PATH_DEDUPLICATED"
                    )
                else:
                    r["trace_warning"] = (
                        "DUPLICATE_EVIDENCE_PATH_DEDUPLICATED"
                    )
        else:
            seen_dedup_keys.add(dedup_key)

            if path_req.tier == RequirementTier.REQUIRED:
                active_req_entries.append(r)
            elif (
                path_req.tier == RequirementTier.CONDITIONAL
                and r.get("conditional_active") is True
            ):
                active_req_entries.append(r)

    req_states = [
        e["extracted_state"]
        for e in active_req_entries
    ]

    has_true = PredicateState.TRUE in req_states
    has_false = PredicateState.FALSE in req_states
    has_unknown = PredicateState.UNKNOWN in req_states
    has_not_eval = PredicateState.NOT_EVALUATED in req_states

    if has_true and has_false:
        public_verdict = Verdict.UNKNOWN
        reason_code = "UNRESOLVED_EVIDENCE_CONFLICT"

    elif has_not_eval and not has_false:
        if not has_true and has_unknown:
            public_verdict = Verdict.NOT_EVALUATED
            reason_code = "STRUCTURAL_BLOCK_PRECEDENCE"
        else:
            public_verdict = Verdict.NOT_EVALUATED
            reason_code = "REQUIRED_PATH_NOT_EVALUATED"

    elif (
        has_true
        and not has_false
        and not has_unknown
        and not has_not_eval
    ):
        public_verdict = Verdict.SUPPORTED
        reason_code = "ALL_REQUIRED_PATHS_SUPPORTED"

    elif has_false and not has_true and not has_unknown and not has_not_eval:
        public_verdict = Verdict.NOT_SUPPORTED
        reason_code = "ALL_REQUIRED_PATHS_CONTRADICTED"

    elif (
        has_false
        and (has_unknown or has_not_eval)
        and not has_true
    ):
        public_verdict = Verdict.NOT_SUPPORTED
        reason_code = "CONTRADICTION_DOMINANCE_APPLIED"

    elif has_true and has_unknown and not has_false:
        public_verdict = Verdict.UNKNOWN
        reason_code = "INCOMPLETE_SUPPORTING_EVIDENCE"

    else:
        public_verdict = Verdict.UNKNOWN
        reason_code = "INCOMPLETE_SUPPORTING_EVIDENCE"

    if evidence_identity_conflict:
        public_verdict = Verdict.UNKNOWN
        reason_code = "UNRESOLVED_EVIDENCE_CONFLICT"

    if conditional_gate_failures:
        if PredicateState.ERROR in conditional_gate_failures:
            public_verdict = Verdict.ERROR
            reason_code = "CONDITIONAL_GATE_ERROR"
        elif PredicateState.NOT_EVALUATED in conditional_gate_failures:
            public_verdict = Verdict.NOT_EVALUATED
            reason_code = "CONDITIONAL_GATE_NOT_EVALUATED"
        else:
            public_verdict = Verdict.UNKNOWN
            reason_code = "CONDITIONAL_GATE_UNKNOWN"

    ledger = tuple(
        PathLedgerEntry(
            path_id=r["path_req"].path_id,
            evidence_reference=r["path_req"].evidence_reference,
            tier=r["path_req"].tier,
            raw_disposition=r["raw_disposition"],
            extracted_state=r["extracted_state"],
            trace_warning=r["trace_warning"],
            displaced_by_authority=r["displaced_by_authority"],
        )
        for r in raw_records
    )

    review_reasons = []
    evidence_gaps = []
    for r in raw_records:
        state = r["extracted_state"]
        if state in (PredicateState.UNKNOWN, PredicateState.NOT_EVALUATED, PredicateState.ERROR):
            if r["path_req"].tier == RequirementTier.OPTIONAL:
                review_reasons.append(r["trace_warning"] or "OPTIONAL_PATH_UNRESOLVED")
                evidence_gaps.append(r["trace_warning"] or "OPTIONAL_PATH_UNRESOLVED")
    for e in active_req_entries:
        state = e["extracted_state"]
        if state in (PredicateState.UNKNOWN, PredicateState.NOT_EVALUATED, PredicateState.ERROR):
            code = e["trace_warning"] or "REQUIRED_PATH_UNRESOLVED"
            review_reasons.append(code)
            evidence_gaps.append(code)

    for r in raw_records:
        # An authority-displaced conditional path remains in the
        # forensic ledger but cannot create an active review condition.
        if r["path_req"].path_id in displaced_path_ids:
            continue

        if r["path_req"].tier == RequirementTier.CONDITIONAL:
            gate_state = r.get("conditional_gate_state")
            if gate_state in (
                PredicateState.UNKNOWN,
                PredicateState.NOT_EVALUATED,
                PredicateState.ERROR,
            ):
                code = r["trace_warning"] or "CONDITIONAL_GATE_UNRESOLVED"
                review_reasons.append(code)
                evidence_gaps.append(code)
    if public_verdict == Verdict.UNKNOWN and reason_code == "UNRESOLVED_EVIDENCE_CONFLICT":
        review_reasons.append("UNRESOLVED_EVIDENCE_CONFLICT")
        evidence_gaps.append("UNRESOLVED_EVIDENCE_CONFLICT")
    if authority_warnings:
        public_verdict = Verdict.UNKNOWN
        reason_code = "AUTHORITY_NOT_ESTABLISHED"
        review_reasons.extend(authority_warnings)
        evidence_gaps.extend(authority_warnings)

    lawyer_check_required = bool(review_reasons)
    return MultiEvidenceResult(
        claim_id=bundle.claim_id,
        public_verdict=public_verdict,
        reason_code=reason_code,
        forensic_ledger=ledger,
        lawyer_check_required=lawyer_check_required,
        review_reasons=tuple(sorted(set(review_reasons))),
        evidence_gaps=tuple(sorted(set(evidence_gaps))),
    )


def reduce_and(*states: PredicateState) -> PredicateState:
    """
    Frozen V15 Boolean rule for AND:

        ERROR > NOT_EVALUATED > FALSE > UNKNOWN > TRUE

    FALSE wins over UNKNOWN.
    UNKNOWN wins over TRUE.
    """
    if not states:
        return PredicateState.ERROR

    if PredicateState.ERROR in states:
        return PredicateState.ERROR

    if PredicateState.NOT_EVALUATED in states:
        return PredicateState.NOT_EVALUATED

    if PredicateState.FALSE in states:
        return PredicateState.FALSE

    if PredicateState.UNKNOWN in states:
        return PredicateState.UNKNOWN

    return PredicateState.TRUE


def reduce_or(*states: PredicateState) -> PredicateState:
    """
    Frozen V15 Boolean rule for OR:

        ERROR > TRUE > NOT_EVALUATED > UNKNOWN > FALSE

    TRUE wins over NOT_EVALUATED, UNKNOWN, and FALSE.
    NOT_EVALUATED wins over UNKNOWN and FALSE.
    UNKNOWN wins over FALSE.
    """
    if not states:
        return PredicateState.ERROR

    if PredicateState.ERROR in states:
        return PredicateState.ERROR

    if PredicateState.TRUE in states:
        return PredicateState.TRUE

    if PredicateState.NOT_EVALUATED in states:
        return PredicateState.NOT_EVALUATED

    if PredicateState.UNKNOWN in states:
        return PredicateState.UNKNOWN

    return PredicateState.FALSE


def disposition_from_predicate(state: PredicateState) -> Disposition:
    if state == PredicateState.TRUE:
        return Disposition(
            Verdict.SUPPORTED,
            "predicate established the claim",
        )

    if state == PredicateState.FALSE:
        return Disposition(
            Verdict.NOT_SUPPORTED,
            "predicate contradicted the claim",
        )

    if state == PredicateState.UNKNOWN:
        return Disposition(
            Verdict.UNKNOWN,
            "required evidence did not establish the claim",
        )

    if state == PredicateState.NOT_EVALUATED:
        return Disposition(
            Verdict.NOT_EVALUATED,
            "claim could not be evaluated under the authorized semantic model",
        )

    return Disposition(
        Verdict.ERROR,
        "verification encountered an execution or input error",
    )


def verify_predicate(
    predicate_id: str,
    state: PredicateState,
) -> Disposition:
    predicate = PredicateResult(predicate_id, state)
    result = disposition_from_predicate(state)

    return Disposition(
        verdict=result.verdict,
        reason=result.reason,
        predicate_results=(predicate,),
    )


def self_test() -> None:
    assert verify_predicate(
        "P1", PredicateState.TRUE
    ).verdict == Verdict.SUPPORTED

    assert verify_predicate(
        "P2", PredicateState.FALSE
    ).verdict == Verdict.NOT_SUPPORTED

    assert verify_predicate(
        "P3", PredicateState.UNKNOWN
    ).verdict == Verdict.UNKNOWN

    assert verify_predicate(
        "P4", PredicateState.NOT_EVALUATED
    ).verdict == Verdict.NOT_EVALUATED

    assert verify_predicate(
        "P5", PredicateState.ERROR
    ).verdict == Verdict.ERROR

    assert reduce_and(
        PredicateState.TRUE,
        PredicateState.UNKNOWN,
    ) == PredicateState.UNKNOWN

    assert reduce_and(
        PredicateState.TRUE,
        PredicateState.FALSE,
    ) == PredicateState.FALSE

    assert reduce_or(
        PredicateState.FALSE,
        PredicateState.UNKNOWN,
    ) == PredicateState.UNKNOWN

    assert reduce_or(
        PredicateState.FALSE,
        PredicateState.TRUE,
    ) == PredicateState.TRUE

    print("SELF_TEST: PASS")




class EvidenceStatus(str, Enum):
    SUPPORTS = "SUPPORTS"
    CONTRADICTS = "CONTRADICTS"
    ABSENT = "ABSENT"


def disposition_from_evidence_status(
    status: EvidenceStatus,
) -> Disposition:
    if status == EvidenceStatus.SUPPORTS:
        return Disposition(
            Verdict.SUPPORTED,
            "authoritative evidence establishes the claim",
        )

    if status == EvidenceStatus.CONTRADICTS:
        return Disposition(
            Verdict.NOT_SUPPORTED,
            "authoritative evidence contradicts the claim",
        )

    if status == EvidenceStatus.ABSENT:
        return Disposition(
            Verdict.UNKNOWN,
            "required evidence was not established",
        )

    return Disposition(
        Verdict.ERROR,
        "invalid evidence status",
    )


def evidence_status_self_test() -> None:
    assert (
        disposition_from_evidence_status(
            EvidenceStatus.SUPPORTS
        ).verdict
        == Verdict.SUPPORTED
    )

    assert (
        disposition_from_evidence_status(
            EvidenceStatus.CONTRADICTS
        ).verdict
        == Verdict.NOT_SUPPORTED
    )

    assert (
        disposition_from_evidence_status(
            EvidenceStatus.ABSENT
        ).verdict
        == Verdict.UNKNOWN
    )

    assert (
        disposition_from_evidence_status(
            EvidenceStatus.SUPPORTS
        ).verdict
        != disposition_from_evidence_status(
            EvidenceStatus.ABSENT
        ).verdict
    )

    print("EVIDENCE_STATUS_SELF_TEST: PASS")

# ============================================================
# IDENTITY + SCOPE ENFORCEMENT — WORKING PROPOSAL v0.1
# ============================================================

def identities_match(a: PropositionIdentity, b: PropositionIdentity) -> bool:
    """
    Exact proposition identity matching.
    No fuzzy matching, keyword similarity, inheritance, or
    contextual inference is permitted.
    """
    return (
        a.entity == b.entity
        and a.event_or_attribute == b.event_or_attribute
        and a.context == b.context
        and a.target_property == b.target_property
    )


def scope_matches(a: Scope, b: Scope) -> bool:
    """
    Exact scope matching.
    Different scopes do not inherit proof automatically.
    """
    return a.value == b.value


def evidence_is_authorized_for_claim(
    claim: Claim,
    evidence_identity: PropositionIdentity,
    evidence_scope: Scope,
) -> bool:
    """
    Evidence may establish a claim only when BOTH:
      1. proposition identity matches exactly; and
      2. scope matches exactly.

    No implicit broader/narrower/overlapping inheritance.
    """
    return (
        identities_match(claim.identity, evidence_identity)
        and scope_matches(claim.scope, evidence_scope)
    )


def identity_scope_self_test() -> None:
    base_identity = PropositionIdentity(
        entity="contract_A",
        event_or_attribute="payment",
        context="agreement",
        target_property="amount",
    )

    exact_identity = PropositionIdentity(
        entity="contract_A",
        event_or_attribute="payment",
        context="agreement",
        target_property="amount",
    )

    different_entity = PropositionIdentity(
        entity="contract_B",
        event_or_attribute="payment",
        context="agreement",
        target_property="amount",
    )

    different_property = PropositionIdentity(
        entity="contract_A",
        event_or_attribute="payment",
        context="agreement",
        target_property="date",
    )

    different_context = PropositionIdentity(
        entity="contract_A",
        event_or_attribute="payment",
        context="invoice",
        target_property="amount",
    )

    claim_scope = Scope(value="2026-01-01/2026-12-31")
    different_scope = Scope(value="2025-01-01/2025-12-31")

    claim = Claim(
        proposition_id="P1",
        identity=base_identity,
        scope=claim_scope,
        value="1000",
        polarity=Polarity.AFFIRMATION,
        cardinality=Cardinality.SINGLE,
    )

    assert identities_match(base_identity, exact_identity)
    assert not identities_match(base_identity, different_entity)
    assert not identities_match(base_identity, different_property)
    assert not identities_match(base_identity, different_context)

    assert scope_matches(claim_scope, claim_scope)
    assert not scope_matches(claim_scope, different_scope)

    assert evidence_is_authorized_for_claim(
        claim,
        exact_identity,
        claim_scope,
    )

    assert not evidence_is_authorized_for_claim(
        claim,
        different_entity,
        claim_scope,
    )

    assert not evidence_is_authorized_for_claim(
        claim,
        different_property,
        claim_scope,
    )

    assert not evidence_is_authorized_for_claim(
        claim,
        different_context,
        claim_scope,
    )

    assert not evidence_is_authorized_for_claim(
        claim,
        exact_identity,
        different_scope,
    )

    print("IDENTITY_SCOPE_SELF_TEST: PASS")


# ============================================================
# POLARITY + CARDINALITY ENFORCEMENT — WORKING PROPOSAL v0.1
# ============================================================

def document_observation_reason(
    observation: Optional[DocumentObservation],
) -> Optional[str]:
    """Return a specific observation reason without treating observation as proof."""
    if observation is None:
        return None
    if not isinstance(observation, DocumentObservation):
        return None
    if not isinstance(observation.source_id, str) or not observation.source_id:
        return None
    if type(observation.occurrence_count) is not int:
        return None
    if observation.occurrence_count < 0:
        return None
    if observation.occurrence_count == 1:
        return "SINGLE_DOCUMENT_OCCURRENCE"
    return None


def evaluate_polarity(
    claim_polarity: Polarity,
    evidence_polarity: Polarity,
) -> PredicateState:
    """
    Explicit polarity evaluation.

    Matching affirmation/negation supports the claim.
    Opposing explicit polarity contradicts the claim.
    ABSENCE never proves either side.
    """
    if evidence_polarity == Polarity.ABSENCE:
        return PredicateState.UNKNOWN

    if claim_polarity == evidence_polarity:
        return PredicateState.TRUE

    return PredicateState.FALSE


def evaluate_value(
    claim_value: str,
    evidence_values: tuple[str, ...],
    cardinality: Cardinality,
) -> PredicateState:
    """Evaluate whether the claimed value is established."""
    if not evidence_values:
        return PredicateState.UNKNOWN
    if claim_value in evidence_values:
        return PredicateState.TRUE
    if cardinality == Cardinality.SINGLE:
        return PredicateState.FALSE
    return PredicateState.UNKNOWN


def evaluate_single_cardinality(
    claim_value: str,
    evidence_values: tuple[str, ...],
) -> PredicateState:
    """SINGLE requires exactly one distinct applicable value."""
    if not evidence_values:
        return PredicateState.UNKNOWN
    return (
        PredicateState.TRUE
        if len(set(evidence_values)) == 1
        else PredicateState.FALSE
    )


def evaluate_multi_cardinality(
    claim_value: str,
    evidence_values: tuple[str, ...],
) -> PredicateState:
    """MULTI permits multiple applicable values."""
    if not evidence_values:
        return PredicateState.UNKNOWN
    return PredicateState.TRUE



def evaluate_claim_against_evidence(
    claim: Claim,
    evidence: Evidence,
) -> Disposition:
    """
    Authoritative claim-to-evidence pipeline.

    Order:
        AUTHORIZATION -> POLARITY -> VALUE -> CARDINALITY
        -> aggregate -> disposition

    No unresolved predicate may silently become SUPPORTED.
    """

    if not evidence_is_authorized_for_claim(
        claim,
        evidence.identity,
        evidence.scope,
    ):
        result = PredicateResult(
            "AUTHORIZATION",
            PredicateState.NOT_EVALUATED,
        )
        return Disposition(
            Verdict.NOT_EVALUATED,
            "Evidence identity or scope is not authorized for claim",
            (result,),
            lawyer_check_required=True,
            evidence_gap="UNAUTHORIZED_EVIDENCE",
            review_reasons=("UNAUTHORIZED_EVIDENCE",),
        )

    authorization_state = PredicateState.TRUE

    polarity_state = evaluate_polarity(
        claim.polarity,
        evidence.polarity,
    )

    value_state = evaluate_value(
        claim.value,
        evidence.values,
        claim.cardinality,
    )

    if claim.cardinality == Cardinality.SINGLE:
        cardinality_state = evaluate_single_cardinality(
            claim.value,
            evidence.values,
        )
    else:
        cardinality_state = evaluate_multi_cardinality(
            claim.value,
            evidence.values,
        )

    predicate_results = (
        PredicateResult("AUTHORIZATION", authorization_state),
        PredicateResult("POLARITY", polarity_state),
        PredicateResult("VALUE", value_state),
        PredicateResult("CARDINALITY", cardinality_state),
    )

    aggregate = reduce_and(
        authorization_state,
        polarity_state,
        value_state,
        cardinality_state,
    )

    review_reasons = []
    evidence_gaps = []

    for predicate_name, predicate_state, gap_code in (
        ("POLARITY", polarity_state, "POLARITY_NOT_ESTABLISHED"),
        ("VALUE", value_state, "VALUE_NOT_ESTABLISHED"),
        ("CARDINALITY", cardinality_state, "CARDINALITY_NOT_ESTABLISHED"),
    ):
        if predicate_state in (
            PredicateState.UNKNOWN,
            PredicateState.NOT_EVALUATED,
            PredicateState.ERROR,
        ):
            evidence_gaps.append(gap_code)

    if aggregate == PredicateState.TRUE:
        verdict = Verdict.SUPPORTED
        reason = "Authorized evidence satisfies polarity, value, and cardinality"
    elif aggregate == PredicateState.FALSE:
        verdict = Verdict.NOT_SUPPORTED
        reason = "Authorized evidence contradicts polarity, value, or cardinality"
    elif aggregate == PredicateState.UNKNOWN:
        verdict = Verdict.UNKNOWN
        observation_reason = document_observation_reason(claim.observation)
        if observation_reason is not None:
            reason = (
                "Claim appears once in the supplied document, "
                "and the available evidence is insufficient to establish it"
            )
            review_reasons.append(observation_reason)
        else:
            reason = "Authorized evidence is insufficient to establish the claim"
        review_reasons.append("CLAIM_NOT_FULLY_EVALUATED")
    elif aggregate == PredicateState.NOT_EVALUATED:
        verdict = Verdict.NOT_EVALUATED
        reason = "Claim could not be fully evaluated"
        review_reasons.append("CLAIM_NOT_FULLY_EVALUATED")
    else:
        verdict = Verdict.ERROR
        reason = "Claim evaluation failed closed"
        review_reasons.append("EVALUATION_ERROR")

    if evidence_gaps:
        review_reasons.extend(evidence_gaps)

    lawyer_check_required = bool(review_reasons)

    return Disposition(
        verdict,
        reason,
        predicate_results,
        lawyer_check_required=lawyer_check_required,
        evidence_gap=evidence_gaps[0] if evidence_gaps else None,
        review_reasons=tuple(sorted(set(review_reasons))),
    )

def polarity_cardinality_self_test() -> None:
    # --------------------------------------------------------
    # POLARITY
    # --------------------------------------------------------

    assert (
        evaluate_polarity(
            Polarity.AFFIRMATION,
            Polarity.AFFIRMATION,
        )
        == PredicateState.TRUE
    )

    assert (
        evaluate_polarity(
            Polarity.AFFIRMATION,
            Polarity.NEGATION,
        )
        == PredicateState.FALSE
    )

    assert (
        evaluate_polarity(
            Polarity.AFFIRMATION,
            Polarity.ABSENCE,
        )
        == PredicateState.UNKNOWN
    )

    assert (
        evaluate_polarity(
            Polarity.NEGATION,
            Polarity.NEGATION,
        )
        == PredicateState.TRUE
    )

    assert (
        evaluate_polarity(
            Polarity.NEGATION,
            Polarity.AFFIRMATION,
        )
        == PredicateState.FALSE
    )

    assert (
        evaluate_polarity(
            Polarity.NEGATION,
            Polarity.ABSENCE,
        )
        == PredicateState.UNKNOWN
    )

    # --------------------------------------------------------
    # SINGLE CARDINALITY
    # --------------------------------------------------------

    assert (
        evaluate_single_cardinality(
            "1000",
            ("1000",),
        )
        == PredicateState.TRUE
    )

    assert (
        evaluate_single_cardinality(
            "1000",
            ("2000",),
        )
        == PredicateState.TRUE
    )

    assert (
        evaluate_single_cardinality(
            "1000",
            (),
        )
        == PredicateState.UNKNOWN
    )

    # Two incompatible values under SINGLE are contradictory.
    assert (
        evaluate_single_cardinality(
            "1000",
            ("1000", "2000"),
        )
        == PredicateState.FALSE
    )

    # --------------------------------------------------------
    # MULTI CARDINALITY
    # --------------------------------------------------------

    assert (
        evaluate_multi_cardinality(
            "1000",
            ("1000", "2000"),
        )
        == PredicateState.TRUE
    )

    # Absence from MULTI does not establish contradiction.
    assert (
        evaluate_multi_cardinality(
            "3000",
            ("1000", "2000"),
        )
        == PredicateState.TRUE
    )

    assert (
        evaluate_multi_cardinality(
            "1000",
            (),
        )
        == PredicateState.UNKNOWN
    )

    print("POLARITY_CARDINALITY_SELF_TEST: PASS")


# ============================================================
# TEMPORAL + PRECISION ENFORCEMENT — WORKING PROPOSAL v0.2
# ============================================================

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum


class TemporalPrecision(str, Enum):
    DATE = "DATE"
    MINUTE = "MINUTE"
    SECOND = "SECOND"
    SUBSECOND = "SUBSECOND"


@dataclass(frozen=True)
class TemporalInterval:
    start: datetime
    end: datetime
    start_precision: TemporalPrecision
    end_precision: TemporalPrecision
    start_resolution: timedelta
    end_resolution: timedelta


def parse_temporal(value: str) -> datetime:
    """
    Parse an ISO-8601 temporal value without inventing timezone data.
    """
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise ValueError("INVALID_TEMPORAL_VALUE")


def temporal_precision(value: str) -> TemporalPrecision:
    """
    Determine precision from the original supplied representation.
    Python's normalized datetime must not be used to infer omitted fields.
    """
    raw = value.strip()
    date_part, separator, time_part = raw.partition("T")

    if not separator:
        if len(date_part) == 10:
            return TemporalPrecision.DATE
        raise ValueError("INVALID_TEMPORAL_VALUE")

    if len(time_part) == 0:
        raise ValueError("INVALID_TEMPORAL_VALUE")

    clock = time_part
    if clock.endswith("Z"):
        clock = clock[:-1]
    else:
        # Remove a trailing UTC offset before inspecting fractional seconds.
        for marker in ("+", "-"):
            pos = clock.rfind(marker)
            if pos > 0:
                clock = clock[:pos]
                break

    if "." in clock:
        return TemporalPrecision.SUBSECOND

    components = clock.split(":")
    if len(components) == 2:
        return TemporalPrecision.MINUTE
    if len(components) == 3:
        return TemporalPrecision.SECOND

    raise ValueError("INVALID_TEMPORAL_VALUE")


def temporal_resolution(value: str, precision: TemporalPrecision) -> timedelta:
    """
    Return the admissible precision width.

    DATE:
        the supplied calendar date is precise, but the time within that
        date is not supplied.

    MINUTE:
        the supplied minute is precise, but seconds within that minute
        are not supplied.

    SECOND / SUBSECOND:
        the supplied value is exact at the supplied precision. No
        additional uncertainty is invented.
    """
    if precision == TemporalPrecision.DATE:
        return timedelta(days=1)

    if precision == TemporalPrecision.MINUTE:
        return timedelta(minutes=1)

    if precision in (
        TemporalPrecision.SECOND,
        TemporalPrecision.SUBSECOND,
    ):
        return timedelta(0)

    raise ValueError("INVALID_TEMPORAL_PRECISION")

def validate_temporal_interval(
    start: str,
    end: str,
) -> TemporalInterval:
    """
    Closed interval [start, end].

    The original precision of each endpoint is retained. An omitted
    temporal component is uncertainty, not an invented zero value.
    """
    start_dt = parse_temporal(start)
    end_dt = parse_temporal(end)

    if (start_dt.tzinfo is None) != (end_dt.tzinfo is None):
        raise ValueError("MIXED_TIMEZONE_AWARENESS")

    start_precision = temporal_precision(start)
    end_precision = temporal_precision(end)
    start_resolution = temporal_resolution(start, start_precision)
    end_resolution = temporal_resolution(end, end_precision)

    start_range = temporal_endpoint_range(start_dt, start_resolution)
    end_range = temporal_endpoint_range(end_dt, end_resolution)

    # The interval is definitely valid only when every admissible
    # interpretation satisfies start <= end.
    if start_range.upper <= end_range.lower:
        pass
    elif start_range.lower > end_range.upper:
        raise ValueError("INVALID_TEMPORAL_INTERVAL")
    else:
        raise ValueError("TEMPORAL_INTERVAL_ORDER_UNCERTAIN")

    return TemporalInterval(
        start_dt,
        end_dt,
        start_precision,
        end_precision,
        start_resolution,
        end_resolution,
    )


@dataclass(frozen=True)
class TemporalEndpoint:
    identity: PropositionIdentity
    scope: Scope
    interval: TemporalInterval


@dataclass(frozen=True)
class TemporalClaim:
    proposition_id: str
    relation: TemporalRelation
    left: TemporalEndpoint
    right: TemporalEndpoint


@dataclass(frozen=True)
class TemporalEvidence:
    predicate_id: str
    relation: TemporalRelation
    left: TemporalEndpoint
    right: TemporalEndpoint


@dataclass(frozen=True)
class TemporalValueRange:
    """
    Admissible values represented without inventing precision.

    DATE / MINUTE values use a half-open range:
        [lower, upper)

    SECOND / SUBSECOND values are exact singletons:
        [lower, upper] with upper_inclusive=True
    """
    lower: datetime
    upper: datetime
    upper_inclusive: bool


def temporal_endpoint_range(
    value: datetime,
    resolution: timedelta,
) -> TemporalValueRange:
    """
    Preserve exact values as singleton ranges.

    A non-zero resolution represents omitted precision as a half-open
    admissible range. No terminal instant is invented for an exact value.
    """
    if resolution == timedelta(0):
        return TemporalValueRange(
            lower=value,
            upper=value,
            upper_inclusive=True,
        )

    return TemporalValueRange(
        lower=value,
        upper=value + resolution,
        upper_inclusive=False,
    )


def _temporal_ranges_disjoint(
    left: TemporalValueRange,
    right: TemporalValueRange,
) -> bool:
    """
    Return True only when the two admissible sets have no instant in common.
    """
    if left.upper < right.lower:
        return True

    if right.upper < left.lower:
        return True

    if left.upper == right.lower and not left.upper_inclusive:
        return True

    if right.upper == left.lower and not right.upper_inclusive:
        return True

    return False


def temporal_relation_with_precision(
    relation: TemporalRelation,
    left: TemporalInterval,
    right: TemporalInterval,
) -> PredicateState:
    """
    Evaluate a temporal relation across the full admissible precision range.

    TRUE:
        the relation holds for every admissible interpretation.

    FALSE:
        the relation fails for every admissible interpretation.

    UNKNOWN:
        the result changes across admissible interpretations.

    ERROR:
        the relation is unsupported.
    """
    ls = temporal_endpoint_range(
        left.start,
        left.start_resolution,
    )
    le = temporal_endpoint_range(
        left.end,
        left.end_resolution,
    )
    rs = temporal_endpoint_range(
        right.start,
        right.start_resolution,
    )
    re = temporal_endpoint_range(
        right.end,
        right.end_resolution,
    )

    if relation == TemporalRelation.PRECEDES:
        # left.end < right.start for every admissible interpretation.
        if le.upper < rs.lower:
            return PredicateState.TRUE

        if (
            le.upper == rs.lower
            and not le.upper_inclusive
        ):
            return PredicateState.TRUE

        # left.end < right.start is impossible for every interpretation.
        if le.lower >= rs.upper:
            return PredicateState.FALSE

        return PredicateState.UNKNOWN

    if relation == TemporalRelation.OVERLAPS:
        # Closed-interval overlap:
        # left.start <= right.end
        # AND
        # right.start <= left.end
        always_overlap = (
            ls.upper <= re.lower
            and rs.upper <= le.lower
        )

        if always_overlap:
            return PredicateState.TRUE

        left_side_never_overlaps = (
            ls.lower > re.upper
            or (
                ls.lower == re.upper
                and not re.upper_inclusive
            )
        )

        right_side_never_overlaps = (
            rs.lower > le.upper
            or (
                rs.lower == le.upper
                and not le.upper_inclusive
            )
        )

        if (
            left_side_never_overlaps
            or right_side_never_overlaps
        ):
            return PredicateState.FALSE

        return PredicateState.UNKNOWN

    if relation == TemporalRelation.CONCURRENT:
        exact_same = (
            left.start_resolution == timedelta(0)
            and right.start_resolution == timedelta(0)
            and left.end_resolution == timedelta(0)
            and right.end_resolution == timedelta(0)
            and left.start == right.start
            and left.end == right.end
        )

        if exact_same:
            return PredicateState.TRUE

        if _temporal_ranges_disjoint(ls, rs):
            return PredicateState.FALSE

        if _temporal_ranges_disjoint(le, re):
            return PredicateState.FALSE

        return PredicateState.UNKNOWN

    return PredicateState.ERROR

def evaluate_temporal_claim_against_evidence(
    claim: TemporalClaim,
    evidence: TemporalEvidence,
) -> Disposition:
    """Deterministically evaluate an authorized temporal claim."""

    left_authorized = (
        identities_match(claim.left.identity, evidence.left.identity)
        and scope_matches(claim.left.scope, evidence.left.scope)
    )
    right_authorized = (
        identities_match(claim.right.identity, evidence.right.identity)
        and scope_matches(claim.right.scope, evidence.right.scope)
    )

    if not left_authorized or not right_authorized:
        return Disposition(
            Verdict.NOT_EVALUATED,
            "Temporal evidence identity or scope is not authorized for claim",
            (
                PredicateResult("LEFT_AUTHORIZATION", PredicateState.NOT_EVALUATED),
                PredicateResult("RIGHT_AUTHORIZATION", PredicateState.NOT_EVALUATED),
            ),
            lawyer_check_required=True,
            evidence_gap="UNAUTHORIZED_TEMPORAL_EVIDENCE",
            review_reasons=("UNAUTHORIZED_TEMPORAL_EVIDENCE",),
        )

    if claim.relation != evidence.relation:
        relation_state = PredicateState.FALSE
    elif claim.relation in (
        TemporalRelation.PRECEDES,
        TemporalRelation.OVERLAPS,
        TemporalRelation.CONCURRENT,
    ):
        relation_state = temporal_relation_with_precision(
            claim.relation,
            evidence.left.interval,
            evidence.right.interval,
        )
    else:
        relation_state = PredicateState.ERROR

    predicate_results = (
        PredicateResult("LEFT_AUTHORIZATION", PredicateState.TRUE),
        PredicateResult("RIGHT_AUTHORIZATION", PredicateState.TRUE),
        PredicateResult("TEMPORAL_RELATION", relation_state),
    )

    aggregate = reduce_and(
        PredicateState.TRUE,
        PredicateState.TRUE,
        relation_state,
    )

    if aggregate == PredicateState.TRUE:
        return Disposition(
            Verdict.SUPPORTED,
            "Authorized temporal evidence satisfies the temporal relation",
            predicate_results,
        )

    if aggregate == PredicateState.FALSE:
        return Disposition(
            Verdict.NOT_SUPPORTED,
            "Authorized temporal evidence contradicts the temporal relation",
            predicate_results,
        )

    if aggregate == PredicateState.ERROR:
        return Disposition(
            Verdict.ERROR,
            "Temporal verification encountered an execution or input error",
            predicate_results,
            lawyer_check_required=True,
            evidence_gap="TEMPORAL_EVALUATION_ERROR",
            review_reasons=("TEMPORAL_EVALUATION_ERROR",),
        )

    return Disposition(
        Verdict.UNKNOWN,
        "Temporal evidence did not establish the temporal relation",
        predicate_results,
        lawyer_check_required=True,
        evidence_gap="TEMPORAL_RELATION_NOT_ESTABLISHED",
        review_reasons=("TEMPORAL_RELATION_NOT_ESTABLISHED",),
    )


def temporal_precedes(
    left: TemporalInterval,
    right: TemporalInterval,
) -> bool:
    """
    Strict temporal precedence.
    """
    return left.end < right.start


def temporal_overlaps(
    left: TemporalInterval,
    right: TemporalInterval,
) -> bool:
    """
    Closed-interval overlap.

    Touching at a boundary counts as overlap because intervals
    are closed.
    """
    return (
        left.start <= right.end
        and right.start <= left.end
    )


def temporal_concurrent(
    left: TemporalInterval,
    right: TemporalInterval,
) -> bool:
    """
    Concurrent means identical start and end boundaries.
    """
    return (
        left.start == right.start
        and left.end == right.end
    )


def precision_can_change_truth(
    lower_bound: str,
    upper_bound: str,
) -> bool:
    """
    Conservative precision rule.

    If two supplied temporal values do not resolve to the same
    instant, the verifier cannot silently assume that the omitted
    precision is irrelevant.
    """
    return parse_temporal(lower_bound) != parse_temporal(upper_bound)


def temporal_precision_self_test() -> None:
    # --------------------------------------------------------
    # VALID CLOSED INTERVAL
    # --------------------------------------------------------

    interval = validate_temporal_interval(
        "2026-01-01T10:00:00+00:00",
        "2026-01-01T11:00:00+00:00",
    )

    assert interval.start < interval.end

    # --------------------------------------------------------
    # ZERO-DURATION EVENT IS PERMITTED
    # --------------------------------------------------------

    event = validate_temporal_interval(
        "2026-01-01T10:00:00+00:00",
        "2026-01-01T10:00:00+00:00",
    )

    assert event.start == event.end

    # --------------------------------------------------------
    # INVALID REVERSED INTERVAL
    # --------------------------------------------------------

    try:
        validate_temporal_interval(
            "2026-01-01T11:00:00+00:00",
            "2026-01-01T10:00:00+00:00",
        )
        raise AssertionError("REVERSED_INTERVAL_ACCEPTED")
    except ValueError as exc:
        assert str(exc) == "INVALID_TEMPORAL_INTERVAL"

    # --------------------------------------------------------
    # MIXED TIMEZONE AWARENESS MUST NOT BE INFERRED
    # --------------------------------------------------------

    try:
        validate_temporal_interval(
            "2026-01-01T10:00:00",
            "2026-01-01T11:00:00+00:00",
        )
        raise AssertionError("MIXED_TIMEZONE_AWARENESS_ACCEPTED")
    except ValueError as exc:
        assert str(exc) == "MIXED_TIMEZONE_AWARENESS"

    # --------------------------------------------------------
    # STRICT PRECEDENCE
    # --------------------------------------------------------

    first = validate_temporal_interval(
        "2026-01-01T10:00:00+00:00",
        "2026-01-01T11:00:00+00:00",
    )

    second = validate_temporal_interval(
        "2026-01-01T12:00:00+00:00",
        "2026-01-01T13:00:00+00:00",
    )

    assert temporal_precedes(first, second)
    assert not temporal_precedes(second, first)

    # --------------------------------------------------------
    # CLOSED-INTERVAL OVERLAP
    # --------------------------------------------------------

    touching = validate_temporal_interval(
        "2026-01-01T11:00:00+00:00",
        "2026-01-01T12:00:00+00:00",
    )

    assert temporal_overlaps(first, touching)

    # --------------------------------------------------------
    # CONCURRENT
    # --------------------------------------------------------

    same = validate_temporal_interval(
        "2026-01-01T10:00:00+00:00",
        "2026-01-01T11:00:00+00:00",
    )

    assert temporal_concurrent(first, same)

    # --------------------------------------------------------
    # PRECISION MUST NOT BE SILENTLY COLLAPSED
    # --------------------------------------------------------

    assert precision_can_change_truth(
        "2026-01-01T10:00:00+00:00",
        "2026-01-01T10:00:01+00:00",
    )

    print("TEMPORAL_PRECISION_SELF_TEST: PASS")


# BOOLEAN LOGIC LAYER — V15
def boolean_and(states):
    """Boolean AND delegates to the authoritative V15 reducer."""
    return reduce_and(*states)


def boolean_or(states):
    """Boolean OR delegates to the authoritative V15 reducer."""
    return reduce_or(*states)


def boolean_self_test():
    assert boolean_and([PredicateState.TRUE, PredicateState.TRUE]) == PredicateState.TRUE
    assert boolean_and([PredicateState.TRUE, PredicateState.UNKNOWN]) == PredicateState.UNKNOWN
    assert boolean_and([PredicateState.TRUE, PredicateState.FALSE]) == PredicateState.FALSE
    assert boolean_and([PredicateState.UNKNOWN, PredicateState.FALSE]) == PredicateState.FALSE

    assert boolean_or([PredicateState.FALSE, PredicateState.FALSE]) == PredicateState.FALSE
    assert boolean_or([PredicateState.FALSE, PredicateState.UNKNOWN]) == PredicateState.UNKNOWN
    assert boolean_or([PredicateState.FALSE, PredicateState.TRUE]) == PredicateState.TRUE
    assert boolean_or([PredicateState.UNKNOWN, PredicateState.TRUE]) == PredicateState.TRUE

    print("BOOLEAN_SELF_TEST: PASS")


if __name__ == "__main__":
    self_test()
    evidence_status_self_test()
    identity_scope_self_test()
    polarity_cardinality_self_test()
    temporal_precision_self_test()
    boolean_self_test()

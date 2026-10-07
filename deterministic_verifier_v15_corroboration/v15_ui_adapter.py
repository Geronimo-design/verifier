from __future__ import annotations

import hashlib
import re
import sys
from pathlib import Path
from typing import Any

BASE = Path(__file__).resolve().parent
V15_DIR = BASE / "v15_verifier"

if str(V15_DIR) not in sys.path:
    sys.path.insert(0, str(V15_DIR))

import REAL_VERIFIER_V15_WORKING as V15
import REAL_VERIFIER_V15_SEMANTIC_BOOLEAN_v0_1 as SEMANTIC
from v15_verifier.g01_working_verifier_adapter import evaluate_authority_via_working_verifier


STOP = {
    "the", "a", "an", "is", "was", "were", "are", "of", "to", "and", "in",
    "on", "for", "that", "this", "by", "from", "with", "at", "as", "it",
    "be", "has", "have", "had", "did", "not", "than", "then", "under", "into",
}

MONTHS = {
    "january": 1, "jan": 1, "february": 2, "feb": 2, "march": 3, "mar": 3,
    "april": 4, "apr": 4, "may": 5, "june": 6, "jun": 6, "july": 7, "jul": 7,
    "august": 8, "aug": 8, "september": 9, "sep": 9, "sept": 9, "october": 10,
    "oct": 10, "november": 11, "nov": 11, "december": 12, "dec": 12,
}
MONTH_PATTERN = r"(?:" + "|".join(sorted(MONTHS, key=len, reverse=True)) + r")"


def canonical_text(pages: list[str]) -> bytes:
    return "\n\f\n".join(page or "" for page in pages).encode("utf-8")


def source_for_pages(pages: list[str], pdf_sha256: str, source_id: str = "UPLOADED_DOCUMENT_TEXT"):
    content = canonical_text(pages)
    digest = V15.sha256(content)
    source = V15.SourceRecord(
        source_id=source_id,
        content_digest=digest,
        institutional_provenance=f"PDF_SHA256:{pdf_sha256}",
    )
    return source, content


def _page_offsets(pages: list[str]) -> list[int]:
    offsets = []
    cursor = 0
    separator = len("\n\f\n".encode("utf-8"))
    for index, page in enumerate(pages):
        offsets.append(cursor)
        cursor += len((page or "").encode("utf-8"))
        if index < len(pages) - 1:
            cursor += separator
    return offsets


def evidence_for_sentence(pages: list[str], page_number: int, sentence: str, source):
    if page_number < 1 or page_number > len(pages):
        return None
    page = pages[page_number - 1] or ""
    position = page.find(sentence)
    if position < 0:
        return None
    start = _page_offsets(pages)[page_number - 1] + len(page[:position].encode("utf-8"))
    end = start + len(sentence.encode("utf-8"))
    evidence_id = hashlib.sha256(
        f"{source.content_digest}|{source.source_id}|page={page_number}|"
        f"start={start}|end={end}|{sentence}".encode("utf-8")
    ).hexdigest()
    return V15.EvidenceItem(
        evidence_id=evidence_id,
        source_reference_id=source.source_id,
        source_content_digest=source.content_digest,
        coordinate_type="page",
        coordinate_value=str(page_number),
        start_byte=start,
        end_byte=end,
        evidence_role=V15.Role.SUPPORTING,
    )


def _tokens(value: str) -> set[str]:
    return {
        token for token in re.findall(r"[a-z0-9]+(?:[.,][0-9]+)?", value.lower())
        if token not in STOP and len(token) > 1
    }


def _normalize_date(y: int, m: int, d: int) -> str | None:
    from datetime import date
    try:
        return date(y, m, d).isoformat()
    except ValueError:
        return None


def _extract_dates(text: str) -> set[str]:
    found: set[str] = set()
    for m in re.finditer(r"\b(\d{4})[-/]([01]?\d)[-/]([0-3]?\d)\b", text):
        value = _normalize_date(int(m.group(1)), int(m.group(2)), int(m.group(3)))
        if value:
            found.add(value)
    for m in re.finditer(rf"\b([0-3]?\d)(?:st|nd|rd|th)?\s+({MONTH_PATTERN})\.?\s+(\d{{4}})\b", text, re.I):
        value = _normalize_date(int(m.group(3)), MONTHS[m.group(2).lower().rstrip(".")], int(m.group(1)))
        if value:
            found.add(value)
    for m in re.finditer(rf"\b({MONTH_PATTERN})\.?\s+([0-3]?\d)(?:st|nd|rd|th)?[,]?\s+(\d{{4}})\b", text, re.I):
        value = _normalize_date(int(m.group(3)), MONTHS[m.group(1).lower().rstrip(".")], int(m.group(2)))
        if value:
            found.add(value)
    return found


def _extract_amounts(text: str) -> set[str]:
    values: set[str] = set()
    for m in re.finditer(r"\b(?:R|ZAR)\s*([0-9]{1,3}(?:,[0-9]{3})*(?:\.[0-9]{1,2})?|[0-9]+(?:\.[0-9]{1,2})?)", text, re.I):
        values.add(m.group(1).replace(" ", "").replace(",", ""))
    return values


def _extract_percentages(text: str) -> set[str]:
    return {str(float(m.group(1))).rstrip("0").rstrip(".") for m in re.finditer(r"\b(\d+(?:\.\d+)?)\s*%", text)}


def _extract_quantities(text: str) -> set[str]:
    masked = re.sub(r"\b(?:R|ZAR)\s*[0-9][0-9,]*(?:\.[0-9]+)?", " ", text, flags=re.I)
    masked = re.sub(r"\d+(?:[/-]\d+){2,4}", " ", masked)
    masked = re.sub(r"\b\d+(?:\.\d+)?\s*%", " ", masked)
    values: set[str] = set()
    for raw in re.findall(r"\b\d+(?:\.\d+)?\b", masked):
        integer = int(float(raw))
        if len(raw.split(".")[0]) == 4 and 1900 <= integer <= 2200:
            continue
        values.add(raw.rstrip("0").rstrip(".") if "." in raw else raw)
    return values


def _profile(text: str) -> dict[str, set[str]]:
    return {
        "dates": _extract_dates(text),
        "amounts": _extract_amounts(text),
        "percentages": _extract_percentages(text),
        "quantities": _extract_quantities(text),
    }


def _polarity(text: str) -> str:
    lower = text.lower()
    return "negative" if re.search(
        r"\b(?:not|no|never|did not|does not|do not|was not|were not|is not|are not|cannot|can't|didn't|doesn't|wasn't|weren't)\b",
        lower,
    ) else "positive"


def _candidate_evidence(
    pages: list[str], candidate: dict[str, Any], source
):
    return evidence_for_sentence(
        pages,
        int(candidate["page"]),
        str(candidate["text"]),
        source,
    )


def verify_claim_with_v15(
    claim: str,
    pages: list[str],
    candidates: list[dict[str, Any]],
    pdf_sha256: str,
    source_id: str = "UPLOADED_DOCUMENT_TEXT",
) -> dict[str, Any]:
    """Single application entry point into the deterministic V15 verifier.

    Candidate discovery happens outside this function. No website-level verdict
    is allowed. Every accepted candidate is authenticated by V15, and the final
    aggregation is delegated to V15's candidate adjudicator.
    """
    source, content = source_for_pages(pages, pdf_sha256, source_id=source_id)
    evidence_items: list[dict[str, Any]] = []
    authentication_trace: list[dict[str, Any]] = []

    for candidate in candidates:
        evidence = _candidate_evidence(pages, candidate, source)
        if evidence is None:
            continue
        try:
            observed = V15.validate_evidence(evidence, source, content).decode("utf-8")
        except Exception as exc:
            return {
                "verdict": "ERROR",
                "reason": "SOURCE_OR_EVIDENCE_INTEGRITY_FAILURE",
                "lawyer_check_required": True,
                "proof_trace": [{"step": "V15_INTEGRATION_ERROR", "error_type": type(exc).__name__, "error": str(exc)}],
                "source_digest": source.content_digest,
                "pdf_sha256": pdf_sha256,
            }
        evidence_items.append({
            "evidence": evidence,
            "text": observed,
            "page": int(candidate["page"]),
            "score": candidate.get("score"),
        })
        authentication_trace.append({
            "step": "V15_EVIDENCE_AUTHENTICATED",
            "evidence_id": evidence.evidence_id,
            "page": int(candidate["page"]),
            "exact_text": observed,
        })

    if not evidence_items:
        return {
            "verdict": "UNKNOWN",
            "reason": "NO_AUTHENTICATED_EVIDENCE_CANDIDATE",
            "lawyer_check_required": True,
            "proof_trace": [
                {"step": "SOURCE_DIGEST", "source_id": source.source_id, "digest": source.content_digest},
                {"step": "EVIDENCE_GAP", "reason": "No candidate evidence span could be authenticated."},
            ],
            "source_digest": source.content_digest,
            "pdf_sha256": pdf_sha256,
        }

    try:
        result = V15.verify_claim_candidates(
            prop_id="UI_CLAIM",
            rule_id="V15_CANDIDATE_ADJUDICATION",
            claim_value=claim,
            evidence_items=tuple(item["evidence"] for item in evidence_items),
            evidence_texts=tuple(item["text"] for item in evidence_items),
            source=source,
            content=content,
        )
        trace = authentication_trace + list(result.complete_proof_trace)
        verdict = result.categorical_state.value
        return {
            "verdict": verdict,
            "reason": _reason_from_trace(trace, verdict),
            "lawyer_check_required": verdict in {"UNKNOWN", "NOT_EVALUATED", "ERROR"},
            "proof_trace": trace,
            "source_digest": source.content_digest,
            "pdf_sha256": pdf_sha256,
            "evidence_ids": [item["evidence"].evidence_id for item in evidence_items],
        }
    except Exception as exc:
        return {
            "verdict": "ERROR",
            "reason": "V15_VERIFICATION_FAILURE",
            "lawyer_check_required": True,
            "proof_trace": authentication_trace + [{"step": "V15_INTEGRATION_ERROR", "error_type": type(exc).__name__, "error": str(exc)}],
            "source_digest": source.content_digest,
            "pdf_sha256": pdf_sha256,
        }



def verify_claim_across_sources_with_v15(
    claim: str,
    sources: list[dict[str, Any]],
    required_independent_sources: int = 1,
) -> dict[str, Any]:
    """Verify one proposition across independently uploaded source documents.

    Each source is authenticated and adjudicated independently by V15. The
    cross-source layer only aggregates deterministic V15 outcomes and counts
    distinct authenticated source IDs. Passages from the same source never
    count as independent corroboration.
    """
    if required_independent_sources < 1:
        return {
            "verdict": "ERROR",
            "reason": "INVALID_REQUIRED_INDEPENDENT_SOURCES",
            "lawyer_check_required": True,
            "proof_trace": [{"step": "CORROBORATION_INPUT", "state": "ERROR"}],
        }
    if not sources:
        return {
            "verdict": "UNKNOWN",
            "reason": "NO_AUTHENTICATED_SOURCES",
            "lawyer_check_required": True,
            "proof_trace": [{"step": "EVIDENCE_GAP", "reason": "NO_AUTHENTICATED_SOURCES"}],
        }

    source_results = []
    trace = [{
        "step": "CROSS_SOURCE_V15_START",
        "required_independent_sources": required_independent_sources,
        "source_count": len(sources),
    }]

    for source_entry in sources:
        source_id = source_entry["source_id"]
        result = verify_claim_with_v15(
            claim,
            source_entry["pages"],
            source_entry.get("candidates", []),
            source_entry["pdf_sha256"],
            source_id=source_id,
        )
        source_results.append({
            "source_id": source_id,
            "filename": source_entry.get("filename"),
            "result": result,
        })
        trace.append({
            "step": "SOURCE_RESULT",
            "source_id": source_id,
            "filename": source_entry.get("filename"),
            "verdict": result.get("verdict"),
            "reason": result.get("reason"),
        })

    supported = [x for x in source_results if x["result"].get("verdict") == "SUPPORTED"]
    contradicted = [x for x in source_results if x["result"].get("verdict") == "NOT_SUPPORTED"]
    errors = [x for x in source_results if x["result"].get("verdict") == "ERROR"]
    evaluated = [x for x in source_results if x["result"].get("verdict") in {"SUPPORTED", "NOT_SUPPORTED"}]
    independent_supported_ids = {x["source_id"] for x in supported}
    independent_contradiction_ids = {x["source_id"] for x in contradicted}

    # Fail closed on authenticated source errors and cross-source conflict.
    if errors:
        verdict = "ERROR"
        reason = "SOURCE_VERIFICATION_ERROR"
    elif supported and contradicted:
        verdict = "UNKNOWN"
        reason = "CONFLICTING_INDEPENDENT_SOURCES"
    elif len(independent_supported_ids) >= required_independent_sources:
        verdict = "SUPPORTED"
        reason = "INDEPENDENT_CORROBORATION_ESTABLISHED"
    elif contradicted and not supported:
        verdict = "NOT_SUPPORTED"
        reason = "INDEPENDENT_EVIDENCE_CONTRADICTS_PROPOSITION"
    elif evaluated and not supported:
        verdict = "NOT_SUPPORTED"
        reason = "NO_SUPPORTING_SOURCE_ESTABLISHED"
    else:
        verdict = "UNKNOWN"
        reason = "INDEPENDENT_CORROBORATION_NOT_ESTABLISHED"

    trace.append({
        "step": "CORROBORATION_AGGREGATION",
        "supported_sources": sorted(independent_supported_ids),
        "contradicting_sources": sorted(independent_contradiction_ids),
        "authenticated_source_count": len(source_results),
        "required_independent_sources": required_independent_sources,
        "verdict": verdict,
        "reason": reason,
    })

    if verdict == "UNKNOWN" and not supported and not contradicted:
        trace.append({
            "step": "EVIDENCE_GAP",
            "reason": "INDEPENDENT_CORROBORATION_NOT_ESTABLISHED",
            "required_sources": required_independent_sources,
            "supporting_sources": len(independent_supported_ids),
        })

    return {
        "verdict": verdict,
        "reason": reason,
        "lawyer_check_required": verdict in {"UNKNOWN", "NOT_EVALUATED", "ERROR"},
        "proof_trace": trace,
        "source_results": source_results,
        "independent_supporting_sources": sorted(independent_supported_ids),
        "independent_contradicting_sources": sorted(independent_contradiction_ids),
        "required_independent_sources": required_independent_sources,
    }

def _reason_from_trace(trace: list[dict[str, Any]], verdict: str) -> str:
    for item in trace:
        if item.get("step") == "RULE" and item.get("reason"):
            return str(item["reason"])
    defaults = {
        "SUPPORTED": "The authenticated evidence establishes the proposition under the V15 deterministic rule.",
        "NOT_SUPPORTED": "Authenticated evidence materially contradicts the proposition under the V15 deterministic rule.",
        "UNKNOWN": "The authenticated evidence does not establish a single deterministic result.",
        "NOT_EVALUATED": "The proposition falls outside the currently authorised deterministic rule boundary.",
        "ERROR": "V15 could not complete verification safely.",
    }
    return defaults.get(verdict, "V15_VERIFIED")


# ---------------------------------------------------------------------------
# Structured V15 application boundary
# ---------------------------------------------------------------------------

def _semantic_disposition_to_result(disposition, claim, source, pdf_sha256, trace):
    verdict = disposition.verdict.value
    semantic_trace = list(trace)
    semantic_trace.append({
        "step": "SEMANTIC_V15_DISPOSITION",
        "verdict": verdict,
        "reason": disposition.reason,
        "evidence_gap": disposition.evidence_gap,
        "review_reasons": list(disposition.review_reasons),
    })
    for predicate in disposition.predicate_results:
        semantic_trace.append({
            "step": "SEMANTIC_PREDICATE",
            "predicate_id": predicate.predicate_id,
            "state": predicate.state.value,
        })
    return {
        "verdict": verdict,
        "reason": disposition.reason,
        "lawyer_check_required": bool(disposition.lawyer_check_required),
        "proof_trace": semantic_trace,
        "source_digest": source.content_digest,
        "pdf_sha256": pdf_sha256,
    }


def verify_semantic_claim_with_v15(
    claim_spec: dict[str, Any],
    pages: list[str],
    pdf_sha256: str,
) -> dict[str, Any]:
    """Structured semantic V15 path.

    Identity, scope, polarity, value and cardinality are explicit inputs.
    Evidence identity/scope/value metadata must also be supplied. We never
    infer those authoritative fields from keyword similarity or AI output.
    """
    required = {"proposition_id", "identity", "scope", "value", "polarity", "cardinality", "evidence"}
    missing = sorted(required - set(claim_spec))
    if missing:
        return {"verdict": "NOT_EVALUATED", "reason": f"SEMANTIC_SPEC_MISSING:{','.join(missing)}",
                "lawyer_check_required": True, "proof_trace": [{"step": "SEMANTIC_INPUT", "missing": missing}]}

    try:
        source, content = source_for_pages(pages, pdf_sha256)
        identity = SEMANTIC.PropositionIdentity(**claim_spec["identity"])
        scope = SEMANTIC.Scope(str(claim_spec["scope"]))
        polarity = SEMANTIC.Polarity(claim_spec["polarity"])
        cardinality = SEMANTIC.Cardinality(claim_spec["cardinality"])
        claim = SEMANTIC.Claim(
            proposition_id=str(claim_spec["proposition_id"]),
            identity=identity,
            scope=scope,
            value=str(claim_spec["value"]),
            polarity=polarity,
            cardinality=cardinality,
        )

        evidence_results = []
        trace = [{"step": "SEMANTIC_V15_START", "proposition_id": claim.proposition_id}]
        authenticated_source_ids = set()
        for item in claim_spec["evidence"]:
            page = int(item["page"])
            text = str(item["text"])
            evidence_item = evidence_for_sentence(pages, page, text, source)
            if evidence_item is None:
                trace.append({"step": "EVIDENCE_GAP", "page": page, "reason": "EXACT_EVIDENCE_TEXT_NOT_FOUND", "text": text})
                continue
            ev_identity = SEMANTIC.PropositionIdentity(**item["identity"])
            ev_scope = SEMANTIC.Scope(str(item["scope"]))
            ev_polarity = SEMANTIC.Polarity(item["polarity"])
            ev_values = tuple(str(v) for v in item.get("values", []))
            authenticated_source_ids.add(source.source_id)
            semantic_evidence = SEMANTIC.Evidence(
                predicate_id=claim.proposition_id,
                identity=ev_identity,
                scope=ev_scope,
                polarity=ev_polarity,
                values=ev_values,
            )
            disposition = SEMANTIC.evaluate_claim_against_evidence(claim, semantic_evidence)
            evidence_results.append(disposition)
            trace.append({
                "step": "SEMANTIC_EVIDENCE_AUTHORIZED",
                "evidence_id": evidence_item.evidence_id,
                "page": page,
                "exact_text": text,
                "identity": item["identity"],
                "scope": item["scope"],
            })

        required_independent_sources = int(claim_spec.get("required_independent_sources", 1))
        if required_independent_sources < 1:
            return {"verdict": "ERROR", "reason": "INVALID_REQUIRED_INDEPENDENT_SOURCES", "lawyer_check_required": True,
                    "proof_trace": trace + [{"step": "CORROBORATION_INPUT", "state": "ERROR"}],
                    "source_digest": source.content_digest, "pdf_sha256": pdf_sha256}
        if len(authenticated_source_ids) < required_independent_sources:
            return {"verdict": "UNKNOWN", "reason": "INDEPENDENT_CORROBORATION_NOT_ESTABLISHED", "lawyer_check_required": True,
                    "proof_trace": trace + [{"step": "EVIDENCE_GAP", "reason": "INDEPENDENT_CORROBORATION_NOT_ESTABLISHED",
                                               "required_sources": required_independent_sources,
                                               "authenticated_sources": len(authenticated_source_ids)}],
                    "source_digest": source.content_digest, "pdf_sha256": pdf_sha256}

        if not evidence_results:
            return {"verdict": "UNKNOWN", "reason": "NO_SEMANTIC_EVIDENCE", "lawyer_check_required": True,
                    "proof_trace": trace + [{"step": "VERDICT", "state": "UNKNOWN"}],
                    "source_digest": source.content_digest, "pdf_sha256": pdf_sha256}

        # Multi-evidence aggregation is intentionally fail-closed.
        verdicts = [d.verdict for d in evidence_results]
        if SEMANTIC.Verdict.ERROR in verdicts:
            final = SEMANTIC.Verdict.ERROR
        elif SEMANTIC.Verdict.SUPPORTED in verdicts and SEMANTIC.Verdict.NOT_SUPPORTED in verdicts:
            final = SEMANTIC.Verdict.UNKNOWN
        elif SEMANTIC.Verdict.SUPPORTED in verdicts:
            final = SEMANTIC.Verdict.SUPPORTED
        elif SEMANTIC.Verdict.NOT_SUPPORTED in verdicts:
            final = SEMANTIC.Verdict.NOT_SUPPORTED
        elif SEMANTIC.Verdict.NOT_EVALUATED in verdicts:
            final = SEMANTIC.Verdict.NOT_EVALUATED
        else:
            final = SEMANTIC.Verdict.UNKNOWN

        reason = next((d.reason for d in evidence_results if d.verdict == final),
                      "Semantic evidence did not establish a deterministic result")
        for d in evidence_results:
            trace.append({"step": "SEMANTIC_DISPOSITION", "verdict": d.verdict.value, "reason": d.reason,
                          "evidence_gap": d.evidence_gap, "review_reasons": list(d.review_reasons)})
        trace.append({"step": "VERDICT", "state": final.value})
        return {"verdict": final.value, "reason": reason,
                "lawyer_check_required": final in {SEMANTIC.Verdict.UNKNOWN, SEMANTIC.Verdict.NOT_EVALUATED, SEMANTIC.Verdict.ERROR},
                "proof_trace": trace, "source_digest": source.content_digest, "pdf_sha256": pdf_sha256}
    except Exception as exc:
        return {"verdict": "ERROR", "reason": "SEMANTIC_V15_INPUT_OR_VERIFICATION_ERROR",
                "lawyer_check_required": True,
                "proof_trace": [{"step": "SEMANTIC_V15_ERROR", "error_type": type(exc).__name__, "error": str(exc)}],
                "pdf_sha256": pdf_sha256}


def verify_temporal_claim_with_v15(spec: dict[str, Any], pages: list[str], pdf_sha256: str) -> dict[str, Any]:
    """Structured temporal V15 path. Temporal evidence bytes are authenticated first."""
    required = {"proposition_id", "rule_id", "relation", "left", "right", "evidence"}
    missing = sorted(required - set(spec))
    if missing:
        return {"verdict": "NOT_EVALUATED", "reason": f"TEMPORAL_SPEC_MISSING:{','.join(missing)}",
                "lawyer_check_required": True, "proof_trace": [{"step": "TEMPORAL_INPUT", "missing": missing}]}
    try:
        source, content = source_for_pages(pages, pdf_sha256)
        left, right, ev = spec["left"], spec["right"], spec["evidence"]
        evidence = evidence_for_sentence(pages, int(ev["page"]), str(ev["text"]), source)
        if evidence is None:
            return {"verdict": "UNKNOWN", "reason": "TEMPORAL_EVIDENCE_NOT_FOUND", "lawyer_check_required": True,
                    "proof_trace": [{"step": "EVIDENCE_GAP", "reason": "EXACT_TEMPORAL_EVIDENCE_TEXT_NOT_FOUND"}],
                    "source_digest": source.content_digest, "pdf_sha256": pdf_sha256}
        relation = V15.Relation(spec["relation"])
        from temporal_v15_evidence_adapter import PropositionIdentity, Scope
        result = V15.verify_temporal_claim_v15(
            str(spec["proposition_id"]), str(spec["rule_id"]), relation,
            PropositionIdentity(**left["identity"]), Scope(str(left["scope"])), str(left["start"]), str(left["end"]),
            PropositionIdentity(**right["identity"]), Scope(str(right["scope"])), str(right["start"]), str(right["end"]),
            evidence, source, content,
        )
        verdict = result.categorical_state.value
        trace = list(result.complete_proof_trace)
        return {"verdict": verdict, "reason": _reason_from_trace(trace, verdict),
                "lawyer_check_required": verdict in {"UNKNOWN", "NOT_EVALUATED", "ERROR"},
                "proof_trace": trace, "source_digest": source.content_digest, "pdf_sha256": pdf_sha256,
                "evidence_ids": [evidence.evidence_id]}
    except Exception as exc:
        return {"verdict": "ERROR", "reason": "TEMPORAL_V15_INPUT_OR_VERIFICATION_ERROR", "lawyer_check_required": True,
                "proof_trace": [{"step": "TEMPORAL_V15_ERROR", "error_type": type(exc).__name__, "error": str(exc)}],
                "pdf_sha256": pdf_sha256}



G01_CERTIFICATION_STATUS = "NOT_CERTIFIED"


def verify_authority_claim_with_v15(
    spec: dict[str, Any],
    pages: list[str],
    pdf_sha256: str,
) -> dict[str, Any]:
    """Run the repository's G01 authority candidate in review-only mode.

    The candidate is deliberately prevented from becoming a production
    verdict source until an explicit certification state is established.
    Evidence locations are resolved from the uploaded bytes and authenticated
    by the existing working V15 evidence boundary before G01 sees them.
    """
    required = {
        "target_proposition",
        "decisions",
        "propositions",
        "relationships",
        "status_evidence",
        "evidence",
    }
    missing = sorted(required - set(spec))
    if missing:
        return {
            "verdict": "NOT_EVALUATED",
            "reason": f"AUTHORITY_SPEC_MISSING:{','.join(missing)}",
            "lawyer_check_required": True,
            "proof_trace": [{"step": "G01_INPUT", "state": "NOT_EVALUATED", "missing": missing}],
            "pdf_sha256": pdf_sha256,
        }

    trace: list[dict[str, Any]] = [{
        "step": "G01_APPLICATION_DISPATCH",
        "certification_status": G01_CERTIFICATION_STATUS,
        "mode": "review_only",
    }]

    try:
        source, content = source_for_pages(pages, pdf_sha256)
        evidence_items = []
        seen_ids = set()
        for item in spec["evidence"]:
            if not isinstance(item, dict):
                return {
                    "verdict": "ERROR",
                    "reason": "AUTHORITY_EVIDENCE_ENTRY_NOT_OBJECT",
                    "lawyer_check_required": True,
                    "proof_trace": trace + [{"step": "G01_INPUT", "state": "ERROR"}],
                    "source_digest": source.content_digest,
                    "pdf_sha256": pdf_sha256,
                }
            evidence_id = str(item.get("evidence_id", ""))
            if not evidence_id or evidence_id in seen_ids:
                return {
                    "verdict": "ERROR",
                    "reason": "AUTHORITY_EVIDENCE_ID_INVALID_OR_DUPLICATE",
                    "lawyer_check_required": True,
                    "proof_trace": trace + [{"step": "G01_INPUT", "state": "ERROR", "evidence_id": evidence_id}],
                    "source_digest": source.content_digest,
                    "pdf_sha256": pdf_sha256,
                }
            seen_ids.add(evidence_id)
            page = int(item["page"])
            text = str(item["text"])
            evidence = evidence_for_sentence(pages, page, text, source)
            if evidence is None:
                trace.append({
                    "step": "EVIDENCE_GAP",
                    "evidence_id": evidence_id,
                    "page": page,
                    "reason": "EXACT_AUTHORITY_EVIDENCE_TEXT_NOT_FOUND",
                })
                continue
            # The graph's evidence_id is the caller's logical identifier, but
            # the authenticated V15 evidence object gets its own cryptographic ID.
            # Keep the graph identifier by replacing the deterministic object ID
            # only after exact source binding has been established.
            evidence = type(evidence)(
                evidence_id=evidence_id,
                source_reference_id=evidence.source_reference_id,
                source_content_digest=evidence.source_content_digest,
                coordinate_type=evidence.coordinate_type,
                coordinate_value=evidence.coordinate_value,
                start_byte=evidence.start_byte,
                end_byte=evidence.end_byte,
                evidence_role=evidence.evidence_role,
            )
            observed = V15.validate_evidence(evidence, source, content).decode("utf-8")
            evidence_items.append((source, evidence, content))
            trace.append({
                "step": "G01_EVIDENCE_AUTHENTICATED",
                "evidence_id": evidence_id,
                "page": page,
                "exact_text": observed,
            })

        expected_ids = set()
        for node in spec["decisions"]:
            expected_ids.add(node.get("evidence_id"))
        for node in spec["propositions"]:
            expected_ids.add(node.get("evidence_id"))
        for node in spec["relationships"]:
            expected_ids.add(node.get("evidence_id"))
        for node in spec["status_evidence"]:
            expected_ids.add(node.get("evidence_id"))
        missing_ids = sorted(str(x) for x in expected_ids if x and str(x) not in seen_ids)
        if missing_ids:
            return {
                "verdict": "UNKNOWN",
                "reason": "AUTHORITY_EVIDENCE_GAP",
                "lawyer_check_required": True,
                "proof_trace": trace + [{"step": "EVIDENCE_GAP", "missing_evidence_ids": missing_ids}],
                "source_digest": source.content_digest,
                "pdf_sha256": pdf_sha256,
            }

        result = evaluate_authority_via_working_verifier(
            spec["decisions"],
            spec["propositions"],
            spec["relationships"],
            spec["status_evidence"],
            str(spec["target_proposition"]),
            evidence_items,
        )
        candidate_verdict = result.categorical_state.value
        trace.extend(list(result.complete_proof_trace))
        trace.append({
            "step": "G01_CANDIDATE_RESULT",
            "candidate_verdict": candidate_verdict,
            "candidate_rule": "G01_AUTHORITY",
            "certification_status": G01_CERTIFICATION_STATUS,
        })

        # Hard certification gate. A passing candidate regression suite is not
        # itself production certification, so no G01 result can become a public
        # deterministic verdict yet.
        return {
            "verdict": "NOT_EVALUATED",
            "reason": "G01_IMPLEMENTATION_NOT_CERTIFIED",
            "lawyer_check_required": True,
            "proof_trace": trace,
            "candidate_verdict": candidate_verdict,
            "source_digest": source.content_digest,
            "pdf_sha256": pdf_sha256,
            "evidence_ids": sorted(seen_ids),
        }
    except Exception as exc:
        return {
            "verdict": "ERROR",
            "reason": "G01_AUTHORITY_CANDIDATE_ERROR",
            "lawyer_check_required": True,
            "proof_trace": trace + [{"step": "G01_CANDIDATE_ERROR", "error_type": type(exc).__name__, "error": str(exc)}],
            "pdf_sha256": pdf_sha256,
        }


def verify_claim_request_with_v15(
    claim: str,
    pages: list[str],
    candidates: list[dict[str, Any]],
    pdf_sha256: str,
    mode: str = "standard",
    structured_spec: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """The only application-level V15 dispatcher.

    No caller can select a verdict. Mode selects an authorised V15 verifier;
    the verifier alone supplies the result.
    """
    if mode == "semantic":
        if not structured_spec:
            return {"verdict": "NOT_EVALUATED", "reason": "SEMANTIC_STRUCTURED_SPEC_REQUIRED", "lawyer_check_required": True,
                    "proof_trace": [{"step": "V15_DISPATCH", "mode": mode, "state": "NOT_EVALUATED"}]}
        return verify_semantic_claim_with_v15(structured_spec, pages, pdf_sha256)
    if mode == "temporal":
        if not structured_spec:
            return {"verdict": "NOT_EVALUATED", "reason": "TEMPORAL_STRUCTURED_SPEC_REQUIRED", "lawyer_check_required": True,
                    "proof_trace": [{"step": "V15_DISPATCH", "mode": mode, "state": "NOT_EVALUATED"}]}
        return verify_temporal_claim_with_v15(structured_spec, pages, pdf_sha256)
    if mode == "authority":
        if not structured_spec:
            return {"verdict": "NOT_EVALUATED", "reason": "AUTHORITY_STRUCTURED_SPEC_REQUIRED", "lawyer_check_required": True,
                    "proof_trace": [{"step": "V15_DISPATCH", "mode": mode, "state": "NOT_EVALUATED"}]}
        return verify_authority_claim_with_v15(structured_spec, pages, pdf_sha256)
    return verify_claim_with_v15(claim, pages, candidates, pdf_sha256)

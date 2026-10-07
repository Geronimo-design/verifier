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


def source_for_pages(pages: list[str], pdf_sha256: str):
    content = canonical_text(pages)
    digest = V15.sha256(content)
    source = V15.SourceRecord(
        source_id="UPLOADED_DOCUMENT_TEXT",
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
) -> dict[str, Any]:
    """Single application entry point into the deterministic V15 verifier.

    Candidate discovery happens outside this function. No website-level verdict
    is allowed. Every accepted candidate is authenticated by V15, and the final
    aggregation is delegated to V15's candidate adjudicator.
    """
    source, content = source_for_pages(pages, pdf_sha256)
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

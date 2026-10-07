from __future__ import annotations

import hashlib
import json
import os
import re
import uuid
from dataclasses import dataclass, asdict
from datetime import date
from pathlib import Path
from typing import Any

import requests
from fastapi import FastAPI, File, Form, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pypdf import PdfReader
from v15_ui_adapter import verify_claim_request_with_v15

BASE = Path(__file__).resolve().parent
UPLOADS = BASE / "uploads"
UPLOADS.mkdir(exist_ok=True)
AUDIT = BASE / "audit"
AUDIT.mkdir(exist_ok=True)

app = FastAPI(title="Deterministic Verifier — Real Dynamic Application", version="1.3.0")
app.mount("/static", StaticFiles(directory=BASE / "static"), name="static")


@dataclass
class Candidate:
    page: int
    text: str
    score: float
    reason: str


STOP = {
    "the", "a", "an", "is", "was", "were", "are", "of", "to", "and", "in",
    "on", "for", "that", "this", "by", "from", "with", "at", "as", "it",
    "be", "has", "have", "had", "did", "not", "than", "then", "under", "into",
}

MONTHS = {
    "january": 1, "jan": 1,
    "february": 2, "feb": 2,
    "march": 3, "mar": 3,
    "april": 4, "apr": 4,
    "may": 5,
    "june": 6, "jun": 6,
    "july": 7, "jul": 7,
    "august": 8, "aug": 8,
    "september": 9, "sep": 9, "sept": 9,
    "october": 10, "oct": 10,
    "november": 11, "nov": 11,
    "december": 12, "dec": 12,
}
MONTH_PATTERN = r"(?:" + "|".join(sorted(MONTHS, key=len, reverse=True)) + r")"


def tokens(s: str) -> list[str]:
    return [
        x for x in re.findall(r"[a-z0-9]+(?:[.,][0-9]+)?", s.lower())
        if x not in STOP and len(x) > 1
    ]


def split_sentences(text: str) -> list[str]:
    text = re.sub(r"\s+", " ", text).strip()
    return [x.strip() for x in re.split(r"(?<=[.!?])\s+", text) if x.strip()]


def split_claims(text: str) -> list[str]:
    """Split a batch into independent claims, one per line or numbered/bulleted item."""
    raw = text.strip()
    if not raw:
        return []
    lines = [
        re.sub(r"^\s*(?:[-*•]|\d+[.)])\s*", "", line).strip()
        for line in raw.splitlines()
    ]
    lines = [line for line in lines if line]
    return lines if len(lines) > 1 else [raw]


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def extract_pdf(data: bytes) -> tuple[list[str], str]:
    tmp = UPLOADS / f"{uuid.uuid4().hex}.pdf"
    tmp.write_bytes(data)
    try:
        reader = PdfReader(str(tmp))
        pages = [(p.extract_text() or "") for p in reader.pages]
    finally:
        tmp.unlink(missing_ok=True)
    return pages, sha256_bytes(data)


NON_AUTHORITATIVE_HEADING = re.compile(
    r"\b(?:suggested\s+verifier\s+test\s+claims|verifier\s+test\s+claims|test\s+claims|sample\s+claims|example\s+claims)\b",
    re.I,
)


def authoritative_pages(pages: list[str]) -> list[tuple[int, list[str]]]:
    """Return sentence candidates before an explicitly labelled test/example section.

    Once a document explicitly enters a section labelled as verifier/test/example
    claims, that section and continuation pages are excluded from evidence search.
    """
    output: list[tuple[int, list[str]]] = []
    non_authoritative = False
    for page_no, page in enumerate(pages, 1):
        text = re.sub(r"\s+", " ", page).strip()
        if non_authoritative:
            continue
        match = NON_AUTHORITATIVE_HEADING.search(text)
        if match:
            text = text[:match.start()].strip()
            non_authoritative = True
        sentences = split_sentences(text)
        sentences = [s for s in sentences if "Expected:" not in s]
        if sentences:
            output.append((page_no, sentences))
    return output


def normalize_date(y: int, m: int, d: int) -> str | None:
    try:
        return date(y, m, d).isoformat()
    except ValueError:
        return None


def extract_dates(text: str) -> set[str]:
    """Extract dates and normalize them to YYYY-MM-DD."""
    found: set[str] = set()

    # 2026-09-18 / 2026/09/18
    for m in re.finditer(r"\b(\d{4})[-/]([01]?\d)[-/]([0-3]?\d)\b", text):
        value = normalize_date(int(m.group(1)), int(m.group(2)), int(m.group(3)))
        if value:
            found.add(value)

    # 18 September 2026 / 18 Sep 2026
    month_names = MONTH_PATTERN
    for m in re.finditer(
        rf"\b([0-3]?\d)(?:st|nd|rd|th)?\s+({month_names})\.?\s+(\d{{4}})\b",
        text,
        flags=re.I,
    ):
        month = MONTHS[m.group(2).lower().rstrip(".")]
        value = normalize_date(int(m.group(3)), month, int(m.group(1)))
        if value:
            found.add(value)

    # September 18, 2026 / Sep 18 2026
    for m in re.finditer(
        rf"\b({month_names})\.?\s+([0-3]?\d)(?:st|nd|rd|th)?[,]?\s+(\d{{4}})\b",
        text,
        flags=re.I,
    ):
        month = MONTHS[m.group(1).lower().rstrip(".")]
        value = normalize_date(int(m.group(3)), month, int(m.group(2)))
        if value:
            found.add(value)

    # 18/09/2026 or 18-09-2026 (avoid treating ISO as this form)
    for m in re.finditer(r"\b([0-3]?\d)[/-]([01]?\d)[/-](\d{4})\b", text):
        value = normalize_date(int(m.group(3)), int(m.group(2)), int(m.group(1)))
        if value:
            found.add(value)

    return found


def normalize_amount(raw: str) -> str:
    cleaned = raw.replace(" ", "").replace(",", "")
    return cleaned


def extract_amounts(text: str) -> set[str]:
    """Extract monetary amounts, including R425,000 and R425000.00."""
    values: set[str] = set()
    for m in re.finditer(
        r"\b(?:R|ZAR)\s*([0-9]{1,3}(?:,[0-9]{3})*(?:\.[0-9]{1,2})?|[0-9]+(?:\.[0-9]{1,2})?)",
        text,
        flags=re.I,
    ):
        values.add(normalize_amount(m.group(1)))
    return values


def extract_percentages(text: str) -> set[str]:
    values: set[str] = set()
    for m in re.finditer(r"\b(\d+(?:\.\d+)?)\s*%", text):
        values.add(str(float(m.group(1))).rstrip("0").rstrip("."))
    return values


def extract_quantities(text: str) -> set[str]:
    """Extract standalone numbers that are not part of dates or money/percentages."""
    masked = text
    masked = re.sub(r"\b(?:R|ZAR)\s*[0-9][0-9,]*(?:\.[0-9]+)?", " ", masked, flags=re.I)
    masked = re.sub(r"\d+(?:[/-]\d+){2,4}", " ", masked)
    masked = re.sub(rf"\b[0-3]?\d(?:st|nd|rd|th)?\s+{MONTH_PATTERN}\.?\s+\d{{4}}\b", " ", masked, flags=re.I)
    masked = re.sub(rf"\b{MONTH_PATTERN}\.?\s+[0-3]?\d(?:st|nd|rd|th)?[,]?\s+\d{{4}}\b", " ", masked, flags=re.I)
    masked = re.sub(r"\b\d+(?:\.\d+)?\s*%", " ", masked)
    values: set[str] = set()
    for raw in re.findall(r"\b\d+(?:\.\d+)?\b", masked):
        # Four-digit years are not quantities.
        if len(raw.split(".")[0]) == 4 and 1900 <= int(float(raw)) <= 2200:
            continue
        values.add(raw.rstrip("0").rstrip(".") if "." in raw else raw)
    return values


def extract_value_profile(text: str) -> dict[str, set[str]]:
    return {
        "dates": extract_dates(text),
        "amounts": extract_amounts(text),
        "percentages": extract_percentages(text),
        "quantities": extract_quantities(text),
    }


def find_candidates(claim: str, pages: list[str], limit: int = 12) -> list[Candidate]:
    ct = set(tokens(claim))
    profile = extract_value_profile(claim)
    out: list[Candidate] = []

    for page_no, sentences in authoritative_pages(pages):
        for sent in sentences:
            st = set(tokens(sent))
            overlap = len(ct & st) / max(1, len(ct))
            ev_profile = extract_value_profile(sent)
            value_bonus = 0.0
            if profile["dates"] and profile["dates"] & ev_profile["dates"]:
                value_bonus += 0.40
            if profile["amounts"] and profile["amounts"] & ev_profile["amounts"]:
                value_bonus += 0.40
            if profile["percentages"] and profile["percentages"] & ev_profile["percentages"]:
                value_bonus += 0.30
            if profile["quantities"] and profile["quantities"] & ev_profile["quantities"]:
                value_bonus += 0.25
            score = overlap + value_bonus
            if score > 0:
                reason = "token overlap"
                if value_bonus:
                    reason += " + exact value match"
                out.append(Candidate(page_no, sent, round(score, 4), reason))

    out.sort(key=lambda x: x.score, reverse=True)
    return out[:limit]


def ai_extract(claim: str, pages: list[str]) -> dict[str, Any] | None:
    key = os.getenv("OPENAI_API_KEY", "").strip()
    if not key:
        return None
    model = os.getenv("OPENAI_MODEL", "gpt-5.6-luna")
    joined = "\n\n".join(f"[PAGE {i+1}]\n{p}" for i, p in enumerate(pages))
    prompt = f'''You are an evidence-extraction assistant. You do NOT decide whether a legal claim is true.
Given a user claim and document text, return JSON only with candidate evidence spans that may be relevant.
Preserve exact wording. Include page number. Flag polarity (positive/negative/unclear), modality (finding/order/allegation/conditional/unclear),
and whether the text appears to directly establish the claim. Never invent text.
CLAIM: {claim}
DOCUMENT:\n{joined}'''
    payload = {"model": model, "input": prompt}
    r = requests.post(
        "https://api.openai.com/v1/responses",
        headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
        json=payload,
        timeout=90,
    )
    r.raise_for_status()
    data = r.json()
    text = data.get("output_text")
    if not text:
        chunks = []
        for item in data.get("output", []):
            for c in item.get("content", []):
                if c.get("type") in ("output_text", "text") and c.get("text"):
                    chunks.append(c["text"])
        text = "\n".join(chunks)
    try:
        return json.loads(text)
    except Exception:
        return {"raw": text, "parse_error": True}


@app.get("/", response_class=HTMLResponse)
def index():
    return FileResponse(BASE / "static" / "index.html")


@app.post("/api/verify")
async def verify(
    claims: str = Form(""),
    claim: str = Form(""),
    verification_mode: str = Form("standard"),
    verification_spec: str = Form(""),
    file: UploadFile | None = File(None),
    files: list[UploadFile] = File(default=[]),
):
    raw_claims = claims.strip() or claim.strip()
    claim_list = split_claims(raw_claims)
    if not claim_list:
        return JSONResponse({"error": "At least one claim is required."}, status_code=400)

    uploads = list(files)
    if file is not None:
        uploads.insert(0, file)
    uploads = [item for item in uploads if item is not None]
    if not uploads:
        return JSONResponse({"error": "At least one PDF evidence source is required."}, status_code=400)

    source_documents = []
    for upload in uploads:
        data = await upload.read()
        if not data:
            return JSONResponse({"error": f"Uploaded file is empty: {upload.filename or 'unnamed PDF'}"}, status_code=400)
        if not (upload.filename or "").lower().endswith(".pdf"):
            return JSONResponse({"error": "Only PDF evidence sources are accepted."}, status_code=400)
        try:
            pages, digest = extract_pdf(data)
        except Exception as e:
            return JSONResponse({"error": f"PDF extraction failed for {upload.filename}: {e}"}, status_code=422)
        if not any(p.strip() for p in pages):
            return JSONResponse({"error": f"The PDF contains no extractable text: {upload.filename}"}, status_code=422)
        source_documents.append({"filename": upload.filename or "unnamed.pdf", "pages": pages, "pdf_sha256": digest})

    if verification_mode not in {"standard", "semantic", "temporal", "authority"}:
        return JSONResponse({"error": "Unsupported verification mode."}, status_code=400)

    structured_spec = None
    if verification_spec.strip():
        try:
            structured_spec = json.loads(verification_spec)
        except json.JSONDecodeError as exc:
            return JSONResponse({"error": f"verification_spec must be valid JSON: {exc}"}, status_code=400)

    results = []
    for one_claim in claim_list:
        source_inputs = []
        candidate_views = []
        ai_views = []
        for source_index, document in enumerate(source_documents, 1):
            candidates = find_candidates(one_claim, document["pages"])
            canonical_source_digest = hashlib.sha256("\n\f\n".join(document["pages"]).encode("utf-8")).hexdigest()
            source_id = f"SOURCE_{canonical_source_digest[:16]}"
            source_inputs.append({
                "source_id": source_id,
                "filename": document["filename"],
                "pages": document["pages"],
                "pdf_sha256": document["pdf_sha256"],
                "candidates": [asdict(candidate) for candidate in candidates],
            })
            candidate_views.append({"source_id": source_id, "filename": document["filename"], "candidates": [asdict(candidate) for candidate in candidates]})
            ai = None
            ai_error = None
            try:
                ai = ai_extract(one_claim, document["pages"])
            except Exception as e:
                ai_error = str(e)
            ai_views.append({"source_id": source_id, "filename": document["filename"], "result": ai, "error": ai_error})

        required_independent_sources = 1
        if isinstance(structured_spec, dict):
            try:
                required_independent_sources = int(structured_spec.get("required_independent_sources", 1))
            except (TypeError, ValueError):
                required_independent_sources = 0

        if verification_mode == "standard":
            from v15_ui_adapter import verify_claim_across_sources_with_v15
            v15_result = verify_claim_across_sources_with_v15(
                one_claim, source_inputs, required_independent_sources=required_independent_sources
            )
        elif len(source_documents) != 1:
            v15_result = {
                "verdict": "NOT_EVALUATED",
                "reason": "MULTI_SOURCE_NOT_SUPPORTED_FOR_STRUCTURED_MODE",
                "lawyer_check_required": True,
                "proof_trace": [{"step": "V15_DISPATCH", "state": "NOT_EVALUATED", "reason": "Structured modes currently require exactly one source."}],
            }
        else:
            document = source_documents[0]
            v15_result = verify_claim_request_with_v15(
                one_claim,
                document["pages"],
                source_inputs[0]["candidates"],
                document["pdf_sha256"],
                mode=verification_mode,
                structured_spec=structured_spec,
            )
        verdict = v15_result["verdict"]
        reason = v15_result["reason"]
        trace = v15_result["proof_trace"]
        verification_id = uuid.uuid4().hex
        audit_record = {
            "verification_id": verification_id,
            "engine": "V15_APPLICATION_DISPATCHER",
            "engine_version": app.version,
            "verification_mode": verification_mode,
            "claim": one_claim,
            "sources": [{"source_id": item["source_id"], "filename": item["filename"], "source_sha256": item["pdf_sha256"], "pages": len(item["pages"])} for item in source_inputs],
            "verdict": verdict,
            "reason": reason,
            "proof_trace": trace,
        }
        (AUDIT / f"{verification_id}.json").write_text(json.dumps(audit_record, indent=2, sort_keys=True), encoding="utf-8")
        results.append({
            "verification_id": verification_id,
            "claim": one_claim,
            "verification_mode": verification_mode,
            "verdict": verdict,
            "reason": reason,
            "lawyer_check_required": verdict in {"UNKNOWN", "NOT_EVALUATED", "ERROR"},
            "sources": [{"source_id": item["source_id"], "filename": item["filename"], "candidates": item["candidates"]} for item in source_inputs],
            "proof_trace": trace,
            "ai": {
                "enabled": bool(os.getenv("OPENAI_API_KEY")),
                "sources": ai_views,
                "role": "ADVISORY ONLY — AI CANNOT SET THE VERDICT",
            },
            "corroboration": {
                "required_independent_sources": v15_result.get("required_independent_sources", required_independent_sources),
                "independent_supporting_sources": v15_result.get("independent_supporting_sources", []),
                "independent_contradicting_sources": v15_result.get("independent_contradicting_sources", []),
                "source_results": v15_result.get("source_results", []),
            },
        })

    return {
        "claim_count": len(results),
        "sources": [{"source_id": f"SOURCE_{hashlib.sha256("\n\f\n".join(item["pages"]).encode("utf-8")).hexdigest()[:16]}", "filename": item["filename"], "source_sha256": item["pdf_sha256"], "pages": len(item["pages"])} for item in source_documents],
        "results": results,
    }

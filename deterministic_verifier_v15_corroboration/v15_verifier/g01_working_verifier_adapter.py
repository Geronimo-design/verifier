from __future__ import annotations

import importlib.util
import re
import sys
from dataclasses import asdict
from pathlib import Path


WORKING_PATH = Path(__file__).with_name("REAL_VERIFIER_V15_WORKING.py")
G01_PATH = Path(__file__).with_name("REAL_VERIFIER_V15_G01_CANDIDATE.py")


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"MODULE_LOAD_FAILED:{path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _g01_source_from_working(source, content):
    return G01.Source(
        source_id=source.source_id,
        content_digest=source.content_digest,
        provenance=source.institutional_provenance,
        content=content,
    )


def _g01_evidence_from_working(evidence):
    coordinate = str(evidence.coordinate_value).strip()
    page = 0
    paragraph = 0

    match = re.fullmatch(
        r"page\s+(\d+)\s*,\s*paragraph\s+(\d+)",
        coordinate,
        flags=re.IGNORECASE,
    )
    if match:
        page = int(match.group(1))
        paragraph = int(match.group(2))
    elif evidence.coordinate_type == "page":
        page = int(coordinate)

    return G01.Evidence(
        evidence_id=evidence.evidence_id,
        source_id=evidence.source_reference_id,
        digest=evidence.source_content_digest,
        page=page,
        paragraph=paragraph,
        start_byte=evidence.start_byte,
        end_byte=evidence.end_byte,
        role=G01.Role(evidence.evidence_role.value),
    )


def authenticate_and_convert_evidence(source, evidence, content):
    """
    Existing working-verifier evidence boundary is authoritative.

    No G01 conversion occurs until validate_evidence() succeeds.
    """
    span = WORKING.validate_evidence(evidence, source, content)

    g_source = _g01_source_from_working(source, content)
    g_evidence = _g01_evidence_from_working(evidence)

    return g_source, g_evidence, span


def build_g01_registry(evidence_items):
    registry = {}

    for source, evidence, content in evidence_items:
        g_source, g_evidence, span = authenticate_and_convert_evidence(
            source, evidence, content
        )

        registry[g_evidence.evidence_id] = {
            "source": g_source,
            "evidence": g_evidence,
            "content": content,
        }

    return registry


def evaluate_authority_via_working_verifier(
    decisions,
    propositions,
    relationships,
    status_evidence,
    target_proposition,
    evidence_items,
):
    """
    Controlled bridge:

        working verifier evidence
            -> existing authentication
            -> G01 evidence registry
            -> G01 authority graph
            -> working VerdictResult
    """

    try:
        registry = build_g01_registry(evidence_items)
    except Exception as exc:
        return WORKING.VerdictResult(
            target_proposition_id=target_proposition,
            applicable_rule_id="G01_AUTHORITY",
            categorical_state=WORKING.Verdict.ERROR,
            predicate_evaluations=(
                WORKING.PredicateEvaluation(
                    predicate_id="G01_AUTHORITY",
                    state="ERROR",
                    evidence_reference_ids=(),
                    derivation_reference_ids=("G01_EVIDENCE_AUTHENTICATION",),
                ),
            ),
            complete_proof_trace=(
                {
                    "step": "G01_BRIDGE",
                    "state": "ERROR",
                    "reason": f"EVIDENCE_AUTHENTICATION_FAILURE:{type(exc).__name__}:{exc}",
                },
            ),
        )

    result = G01.evaluate_g01(
        decisions,
        propositions,
        relationships,
        status_evidence,
        target_proposition,
        registry,
    )

    disposition = result.get("disposition")

    try:
        categorical_state = WORKING.Verdict(disposition)
    except Exception:
        categorical_state = WORKING.Verdict.ERROR

    proof = result.get("proof") or {}

    evidence_ids = tuple(
        item.get("evidence_id")
        for key in (
            "decision_evidence",
            "proposition_evidence",
            "relationship_evidence",
            "status_evidence",
        )
        for item in (
            proof.get(key, [])
            if isinstance(proof.get(key, []), list)
            else [proof.get(key)]
        )
        if isinstance(item, dict) and item.get("evidence_id")
    )

    predicate = WORKING.PredicateEvaluation(
        predicate_id="G01_AUTHORITY",
        state={
            "SUPPORTED": "TRUE",
            "NOT_SUPPORTED": "FALSE",
            "UNKNOWN": "UNKNOWN",
            "NOT_EVALUATED": "UNKNOWN",
            "ERROR": "ERROR",
        }.get(disposition, "ERROR"),
        evidence_reference_ids=tuple(dict.fromkeys(evidence_ids)),
        derivation_reference_ids=("G01_AUTHORITY_GRAPH",),
    )

    trace = (
        {
            "step": "G01_AUTHORITY_GRAPH",
            "disposition": disposition,
            "reason": result.get("reason"),
            "lawyer_check_required": result.get("lawyer_check_required"),
            "lawyer_label": result.get("lawyer_label"),
            "proof": proof,
        },
    )

    return WORKING.VerdictResult(
        target_proposition_id=target_proposition,
        applicable_rule_id="G01_AUTHORITY",
        categorical_state=categorical_state,
        predicate_evaluations=(predicate,),
        complete_proof_trace=trace,
    )


WORKING = _load_module("working_verifier_adapter_target", WORKING_PATH)
G01 = _load_module("g01_authority_adapter_target", G01_PATH)

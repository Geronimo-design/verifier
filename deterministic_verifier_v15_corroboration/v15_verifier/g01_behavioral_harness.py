from __future__ import annotations
import hashlib
import importlib.util
import sys
from pathlib import Path

CANDIDATE = Path.home() / "REAL_VERIFIER_V15_G01_CANDIDATE.py"

spec = importlib.util.spec_from_file_location("g01_candidate", CANDIDATE)
mod = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = mod
spec.loader.exec_module(mod)

Source = mod.Source
Evidence = mod.Evidence
Role = mod.Role

def make_entry(eid, text):
    content = text.encode("utf-8")
    source = Source(
        source_id="SRC-" + eid,
        content_digest=hashlib.sha256(content).hexdigest(),
        provenance="TEST",
        content=content,
    )
    evidence = Evidence(
        evidence_id=eid,
        source_id=source.source_id,
        digest=source.content_digest,
        page=1,
        paragraph=1,
        start_byte=0,
        end_byte=len(content),
        role=Role.NEUTRAL,
    )
    return {
        "source": source,
        "evidence": evidence,
        "content": content,
    }

def graph(registry, rel_text=""):
    decisions = [{
        "decision_id": "D1",
        "citation": "TEST",
        "court": "Test Court",
        "court_level": "HIGH",
        "jurisdiction": "ZA",
        "decision_date": "2024-01-01",
        "opinion_status": "FINAL",
        "evidence_id": "E_DEC",
    }]
    propositions = [{
        "proposition_id": "P1",
        "proposition_text": "The proposition remains current.",
        "paragraph_scope": "1",
        "decision_id": "D1",
        "evidence_id": "E_PROP",
    }]
    relationships = []
    if rel_text:
        relationships.append({
            "relationship_id": "R1",
            "from_decision": "D1",
            "to_decision": "D1",
            "relationship_type": "OVERRULES",
            "affected_proposition": "P1",
            "affected_paragraph": "1",
            "effective_date": "2024-01-01",
            "evidence_id": "E_REL",
        })
    status = [{
        "status_evidence_id": "S1",
        "target_decision": "D1",
        "target_proposition": "P1",
        "checked_as_of": "2025-01-01",
        "subsequent_treatment": "CURRENT",
        "unresolved_relationships": [],
        "evidence_id": "E_STATUS",
    }]
    return decisions, propositions, relationships, status

registry = {}
for eid, text in [
    ("E_DEC", "Decision identity established."),
    ("E_PROP", "Proposition identified."),
    ("E_STATUS", "The decision remains good law."),
    ("E_REL", "The decision remains good law."),
]:
    registry[eid] = make_entry(eid, text)

def run(name, expected, fn):
    try:
        result = fn()
        actual = result.get("disposition")
        ok = actual == expected
        print(f"{name}={'PASS' if ok else 'FAIL'} expected={expected} actual={actual} reason={result.get('reason')}")
        return ok
    except Exception as exc:
        print(f"{name}=FAIL EXCEPTION={type(exc).__name__}:{exc}")
        return False

decisions, propositions, relationships, status = graph(registry)

results = []

# 01 Registry required
results.append(run(
    "G01-01_REGISTRY_REQUIRED", "UNKNOWN",
    lambda: mod.evaluate_g01(
        decisions, propositions, relationships, status, "P1", None)))

# 02 Valid authenticated current authority
results.append(run(
    "G01-02_VALID_CURRENT", "SUPPORTED",
    lambda: mod.evaluate_g01(
        decisions, propositions, relationships, status, "P1", registry)))

# 03 Missing registry evidence
bad_registry = dict(registry)
del bad_registry["E_STATUS"]
results.append(run(
    "G01-03_MISSING_STATUS_EVIDENCE", "UNKNOWN",
    lambda: mod.evaluate_g01(
        decisions, propositions, relationships, status, "P1", bad_registry)))

# 04 Source digest mutation
tampered = dict(registry)
x = dict(tampered["E_STATUS"])
x["content"] = b"The decision remains good law."
x["source"] = Source(
    source_id=x["source"].source_id,
    content_digest="0" * 64,
    provenance="TEST",
    content=x["content"],
)
tampered["E_STATUS"] = x
results.append(run(
    "G01-04_SOURCE_DIGEST_FAILURE", "ERROR",
    lambda: mod.evaluate_g01(
        decisions, propositions, relationships, status, "P1", tampered)))

# 05 Attribution
attr = dict(registry)
attr["E_STATUS"] = make_entry(
    "E_STATUS", "The applicant argued that the decision remains good law.")
results.append(run(
    "G01-05_ATTRIBUTION", "UNKNOWN",
    lambda: mod.evaluate_g01(
        decisions, propositions, relationships, status, "P1", attr)))

# 06 Explicit rejection
reject = dict(registry)
reject["E_STATUS"] = make_entry(
    "E_STATUS", "The court rejected the proposition that the decision remains good law.")
results.append(run(
    "G01-06_REJECTION", "NOT_SUPPORTED",
    lambda: mod.evaluate_g01(
        decisions, propositions, relationships, status, "P1", reject)))

# 07 Conflicting current/displacement status evidence
conflict = dict(registry)
conflict["E_STATUS"] = make_entry(
    "E_STATUS", "The decision remains good law. It was later overruled.")
results.append(run(
    "G01-07_CONFLICTING_STATUS", "UNKNOWN",
    lambda: mod.evaluate_g01(
        decisions, propositions, relationships, status, "P1", conflict)))

# 08 Displacement
displaced = dict(registry)
displaced["E_STATUS"] = make_entry(
    "E_STATUS", "The decision was overruled.")
results.append(run(
    "G01-08_DISPLACED", "NOT_SUPPORTED",
    lambda: mod.evaluate_g01(
        decisions, propositions, relationships, status, "P1", displaced)))

# 09 Invalid relationship evidence must not be silently discarded
rel_registry = dict(registry)
rel_registry["E_REL"] = make_entry("E_REL", "Unrelated text.")

d2 = [
    {
        "decision_id": "D1",
        "citation": "TEST-LOWER",
        "court": "High Court",
        "court_level": "HIGH",
        "jurisdiction": "ZA",
        "decision_date": "2024-01-01",
        "opinion_status": "FINAL",
        "evidence_id": "E_DEC",
    },
    {
        "decision_id": "D2",
        "citation": "TEST-HIGHER",
        "court": "Supreme Court of Appeal",
        "court_level": "SCA",
        "jurisdiction": "ZA",
        "decision_date": "2025-01-01",
        "opinion_status": "FINAL",
        "evidence_id": "E_DEC",
    },
]

p2 = [
    {
        "proposition_id": "P1",
        "proposition_text": "The proposition remains current.",
        "paragraph_scope": "1",
        "decision_id": "D1",
        "evidence_id": "E_PROP",
    }
]

r2 = [
    {
        "relationship_id": "R1",
        "from_decision": "D2",
        "to_decision": "D1",
        "relationship_type": "OVERRULES",
        "affected_proposition": "P1",
        "affected_paragraph": "1",
        "effective_date": "2025-01-01",
        "evidence_id": "E_REL",
    }
]

s2 = [
    {
        "status_evidence_id": "S1",
        "target_decision": "D1",
        "target_proposition": "P1",
        "checked_as_of": "2025-01-01",
        "subsequent_treatment": "CURRENT",
        "unresolved_relationships": [],
        "evidence_id": "E_STATUS",
    }
]

results.append(run(
    "G01-09_RELATIONSHIP_EVIDENCE", "UNKNOWN",
    lambda: mod.evaluate_g01(
        d2, p2, r2, s2, "P1", rel_registry)))

# 10 Repaired wrapper interface must accept and propagate the evidence registry
try:
    wrapped = mod.verify_current_authority(
        decisions, propositions, relationships, status, "P1", registry)
    ok10 = (
        wrapped.get("disposition") == "SUPPORTED"
        and wrapped.get("reason") == "AUTHENTICATED_CURRENT_AUTHORITY_ESTABLISHED"
        and wrapped.get("lawyer_check_required") is False
    )
    print(
        "G01-10_WRAPPER_REGISTRY_INTERFACE="
        + ("PASS" if ok10 else "FAIL")
        + f" expected=SUPPORTED actual={wrapped.get('disposition')}"
        + f" reason={wrapped.get('reason')}"
    )
    results.append(ok10)
except Exception as exc:
    print(f"G01-10_WRAPPER_REGISTRY_INTERFACE=FAIL EXCEPTION={type(exc).__name__}:{exc}")
    results.append(False)

print()
print(f"G01_TOTAL={len(results)}")
print(f"G01_PASS={sum(results)}")
print(f"G01_FAIL={len(results)-sum(results)}")
print("G01_HARNESS=COMPLETE")

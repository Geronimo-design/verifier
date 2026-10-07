import importlib.util
import hashlib
import json
import traceback
from pathlib import Path

ARTIFACT = Path("REAL_VERIFIER_V15.cpython-313.pyc")
EXPECTED_HASH = "2157b5f7308e4140a75a26da2254767f513885b03ca1adae07afcdd200e4c951"
OUT = Path("V15_19_POINT_BASELINE.txt")

lines = []

def log(s=""):
    print(s)
    lines.append(s)

def sha256_file(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()

def load_module():
    spec = importlib.util.spec_from_file_location("rv_baseline", ARTIFACT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

def result(test_id, name, expected, actual, detail=""):
    status = "PASS" if actual == expected else "FAIL"
    log(f"{test_id} | {name} | EXPECTED={expected} | ACTUAL={actual} | {status}")
    if detail:
        log(f"    {detail}")
    return status

log("V15 19-POINT ADVERSARIAL BASELINE")
log("=" * 72)
log(f"ARTIFACT={ARTIFACT}")
log(f"SIZE={ARTIFACT.stat().st_size if ARTIFACT.exists() else 'MISSING'}")
actual_hash = sha256_file(ARTIFACT) if ARTIFACT.exists() else "MISSING"
log(f"SHA256={actual_hash}")
log(f"EXPECTED_SHA256={EXPECTED_HASH}")
hash_ok = actual_hash == EXPECTED_HASH
log(f"HASH_STATUS={'PASS' if hash_ok else 'FAIL'}")

if not hash_ok:
    log("ABORT: artifact hash does not match the fixed baseline artifact.")
    OUT.write_text("\n".join(lines) + "\n")
    raise SystemExit(2)

m = load_module()
log("MODULE_LOAD=PASS")
log(f"VERDICTS={[x.value for x in m.Verdict]}")
log(f"ROLES={[x.value for x in m.Role]}")

content_1200 = b"Order: 1200.00\nParagraph 311\n"
content_350 = b"Order: 350.00\nParagraph 311\n"
digest_1200 = hashlib.sha256(content_1200).hexdigest()
digest_350 = hashlib.sha256(content_350).hexdigest()

src1200 = m.Source("DOC1", digest_1200, "TEST")
src350 = m.Source("DOC2", digest_350, "TEST")

def ev(eid, src, digest, start, end, role, page=1, paragraph="311"):
    return m.Evidence(
        eid, src, digest, page, paragraph, start, end, role
    )

tests = []

# 01 Positive exact evidence
e = ev("E01", "DOC1", digest_1200, 0, len(content_1200), m.Role.SUPPORTING)
p = m.evaluate("P01", [e])
tests.append(result("01", "Positive proof", "SUPPORTED", p["state"],
                    repr(p)))

# 02 Explicit contradiction
e = ev("E02", "DOC2", digest_350, 0, len(content_350), m.Role.CONTRADICTING)
p = m.evaluate("P02", [e])
tests.append(result("02", "Explicit contradiction", "NOT_SUPPORTED", p["state"],
                    repr(p)))

# 03 Evidence absence
p = m.evaluate("P03", [])
tests.append(result("03", "Evidence absence", "UNKNOWN", p["state"],
                    repr(p)))

# 04 False SUPPORTING label against wrong evidence
e = ev("E04", "DOC2", digest_350, 0, len(content_350), m.Role.SUPPORTING)
p = m.evaluate("P04", [e])
actual = p["state"]
tests.append(result(
    "04", "False SUPPORTING label", "NOT_SUPPORTED", actual,
    "Claim=1200; evidence=350; role deliberately declared SUPPORTING"
))

# 05 False CONTRADICTING label against matching evidence
e = ev("E05", "DOC1", digest_1200, 0, len(content_1200), m.Role.CONTRADICTING)
p = m.evaluate("P05", [e])
tests.append(result(
    "05", "False CONTRADICTING label", "SUPPORTED", p["state"],
    "Claim=1200; evidence=1200; role deliberately declared CONTRADICTING"
))

# 06 Conflicting evidence
e1 = ev("E06A", "DOC1", digest_1200, 0, len(content_1200), m.Role.SUPPORTING)
e2 = ev("E06B", "DOC2", digest_350, 0, len(content_350), m.Role.CONTRADICTING)
p = m.evaluate("P06", [e1, e2])
tests.append(result("06", "Conflicting evidence", "UNKNOWN", p["state"],
                    repr(p)))

# 07 Negation
# Current public interface has no claim/predicate semantic representation
# for negation. Record whether such a capability exists rather than inventing it.
tests.append(result(
    "07", "Negation handling", "CAPABILITY_REQUIRED", "NO_NEGATION_INTERFACE",
    "No negation-bearing predicate/claim structure exposed by candidate module"
))

# 08 Numerical mismatch
e = ev("E08", "DOC2", digest_350, 0, len(content_350), m.Role.SUPPORTING)
p = m.evaluate("P08", [e])
tests.append(result(
    "08", "Numerical mismatch", "NOT_SUPPORTED", p["state"],
    "Claim=1200; evidence=350; SUPPORTING label"
))

# 09 Attribution
tests.append(result(
    "09", "Attribution handling", "CAPABILITY_REQUIRED", "NO_ATTRIBUTION_INTERFACE",
    "No attribution field or attribution predicate evaluation exposed"
))

# 10 Conditional statement
tests.append(result(
    "10", "Conditional handling", "CAPABILITY_REQUIRED", "NO_CONDITION_INTERFACE",
    "No condition representation/evaluation interface exposed"
))

# 11 Temporal relationship
tests.append(result(
    "11", "Temporal relationship", "CAPABILITY_REQUIRED", "NO_TEMPORAL_INTERFACE",
    "Candidate module exposes no temporal predicate representation"
))

# 12 Wrong source binding
bad_source = m.Source("DOC1", digest_350, "TEST")
e = ev("E12", "DOC1", digest_350, 0, len(content_350), m.Role.SUPPORTING)
try:
    m.exact_evidence(bad_source, content_1200, e)
    actual = "ACCEPTED"
except Exception as ex:
    actual = type(ex).__name__ + ":" + str(ex)
tests.append(result("12", "Wrong source/content binding",
                    "REJECTED", "REJECTED" if actual.startswith("ValueError:") else actual,
                    actual))

# 13 Wrong digest
bad = ev("E13", "DOC1", "0" * 64, 0, 10, m.Role.SUPPORTING)
try:
    m.exact_evidence(src1200, content_1200, bad)
    actual = "ACCEPTED"
except Exception as ex:
    actual = "REJECTED" if "EVIDENCE_SOURCE_BINDING_MISMATCH" in str(ex) else type(ex).__name__
tests.append(result("13", "Wrong digest", "REJECTED", actual))

# 14 Invalid byte span
bad = ev("E14", "DOC1", digest_1200, 0, len(content_1200) + 1, m.Role.SUPPORTING)
try:
    m.exact_evidence(src1200, content_1200, bad)
    actual = "ACCEPTED"
except Exception as ex:
    actual = "REJECTED" if "INVALID_BYTE_SPAN" in str(ex) else type(ex).__name__
tests.append(result("14", "Invalid byte span", "REJECTED", actual))

# 15 Malformed evidence
try:
    bad = m.Evidence("E15", "DOC1", None, 1, "311", 0, 5, m.Role.SUPPORTING)
    actual = "ACCEPTED"
except Exception as ex:
    actual = "REJECTED"
tests.append(result("15", "Malformed evidence", "REJECTED", actual))

# 16 Proof trace construction
e = ev("E16", "DOC1", digest_1200, 0, len(content_1200), m.Role.SUPPORTING)
p = m.evaluate("P16", [e])
try:
    r = m.proof("Order is 1200.00", src1200, e, p, p, content_1200)
    required = {
        "claim", "source_id", "document_digest", "page", "paragraph",
        "byte_span", "exact_text", "predicate", "verdict"
    }
    actual = "COMPLETE" if required.issubset(r.keys()) else "INCOMPLETE"
except Exception as ex:
    actual = type(ex).__name__
tests.append(result("16", "Proof trace completeness", "COMPLETE", actual))

# 17 Proof/verdict consistency
e = ev("E17", "DOC1", digest_1200, 0, len(content_1200), m.Role.SUPPORTING)
p = m.evaluate("P17", [e])
fake = {"state": "NOT_SUPPORTED"}
try:
    r = m.proof("Order is 1200.00", src1200, e, p, fake, content_1200)
    actual = "ACCEPTED_INCONSISTENT" if r.get("verdict") == "NOT_SUPPORTED" else "REJECTED"
except Exception:
    actual = "REJECTED"
tests.append(result(
    "17", "Proof/verdict consistency", "REJECTED", actual,
    "Predicate state=SUPPORTED; supplied verdict=NOT_SUPPORTED"
))

# 18 Unauthorized role manipulation / role dependence
e = ev("E18", "DOC2", digest_350, 0, len(content_350), m.Role.SUPPORTING)
p_support = m.evaluate("P18", [e])
e = ev("E18", "DOC2", digest_350, 0, len(content_350), m.Role.CONTRADICTING)
p_contra = m.evaluate("P18", [e])
actual = "ROLE_INDEPENDENT" if p_support["state"] == p_contra["state"] else "ROLE_CONTROLS_RESULT"
tests.append(result(
    "18", "Role independence", "ROLE_INDEPENDENT", actual,
    f"SUPPORTING={p_support['state']}; CONTRADICTING={p_contra['state']}"
))

# 19 Mutation resistance / source alteration
altered = b"Order: 1200.01\nParagraph 311\n"
altered_digest = hashlib.sha256(altered).hexdigest()
e = ev("E19", "DOC1", digest_1200, 0, len(altered), m.Role.SUPPORTING)
try:
    m.exact_evidence(src1200, altered, e)
    actual = "ACCEPTED"
except Exception as ex:
    actual = "REJECTED" if "MISMATCH" in str(ex) or "SPAN" in str(ex) else type(ex).__name__
tests.append(result("19", "Altered evidence resistance", "REJECTED", actual))

log("=" * 72)
passed = sum(1 for x in tests if x == "PASS")
failed = len(tests) - passed
log(f"TOTAL_TESTS={len(tests)}")
log(f"PASS={passed}")
log(f"FAIL={failed}")

log("")
log("NOTE:")
log("Tests marked CAPABILITY_REQUIRED are deliberate baseline failures.")
log("They identify semantic capabilities that the candidate module does not expose.")
log("No missing capability has been fabricated or inferred.")

OUT.write_text("\n".join(lines) + "\n")
print(f"BASELINE_RECORD={OUT}")

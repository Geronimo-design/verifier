from pathlib import Path
import sys

BASE = Path(__file__).resolve().parent.parent
if str(BASE) not in sys.path:
    sys.path.insert(0, str(BASE))

from v15_ui_adapter import verify_claim_across_sources_with_v15


def source(source_id, text):
    # This harness uses the application candidate shape. PDF extraction is tested at the API layer.
    return {
        "source_id": source_id,
        "filename": f"{source_id}.pdf",
        "pages": [text],
        "pdf_sha256": __import__("hashlib").sha256(text.encode()).hexdigest(),
        "candidates": [{"page": 1, "text": text, "score": 1.0, "reason": "regression"}],
    }


def main():
    claim = "The defendant paid R1000."
    both = verify_claim_across_sources_with_v15(claim, [source("A", claim), source("B", claim)], 2)
    assert both["verdict"] == "SUPPORTED", both

    conflict = verify_claim_across_sources_with_v15(claim, [source("A", claim), source("B", "The defendant paid R2000.")], 2)
    assert conflict["verdict"] == "UNKNOWN", conflict

    duplicate = verify_claim_across_sources_with_v15(claim, [source("A", claim), source("A", claim)], 2)
    assert duplicate["verdict"] == "UNKNOWN", duplicate
    assert len(duplicate["independent_supporting_sources"]) == 1, duplicate

    print("CROSS_SOURCE_REGRESSION: PASS")


if __name__ == "__main__":
    main()

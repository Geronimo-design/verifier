import REAL_VERIFIER_V15_SEMANTIC_BOOLEAN_v0_1 as V

def claim():
    return V.Claim(
        "C1",
        V.PropositionIdentity("Entity-A","Event-A","Context-A","Property-A"),
        V.Scope("Scope-A"),
        "100",
        V.Polarity.AFFIRMATION,
        V.Cardinality.SINGLE,
    )

def evidence(state=V.PredicateState.TRUE):
    polarity = V.Polarity.AFFIRMATION if state is V.PredicateState.TRUE else V.Polarity.NEGATION
    values = ("100",) if state is not V.PredicateState.UNKNOWN else ()
    identity = V.PropositionIdentity("Entity-A","Event-A","Context-A","Property-A")
    if state is V.PredicateState.NOT_EVALUATED:
        identity = V.PropositionIdentity("Entity-B","Event-A","Context-A","Property-A")
    return V.Evidence("P", identity, V.Scope("Scope-A"), polarity, values)

def authority_evidence(source, target, relation, good=True):
    identity = V.PropositionIdentity(
        source, "AUTHORITY_RELATION", relation.value, target
    )
    if not good:
        identity = V.PropositionIdentity(
            source, "WRONG_RELATION", relation.value, target
        )
    return V.Evidence(
        "AUTH",
        identity,
        V.Scope("AUTHORITY"),
        V.Polarity.AFFIRMATION,
        ("ESTABLISHED",),
    )

def assertion(source, target, relation, good=True):
    return V.AuthorityAssertion(
        source, target, relation,
        authority_evidence(source, target, relation, good),
    )

def path(pid, state=V.PredicateState.TRUE, aa=None, raw_edge=None):
    return V.EvidencePathRequirement(
        pid, pid, evidence(state),
        authority_edge=raw_edge,
        authority_assertion=aa,
    )

def expect(name, result, verdict, reason):
    assert result.public_verdict is verdict, (name, result.public_verdict, verdict)
    assert result.reason_code == reason, (name, result.reason_code, reason)
    print(f"{name}: PASS")

def main():
    r = V.adjudicate_multi_evidence(V.MultiEvidenceBundle(
        "C1", claim(), (
            path("P1", V.PredicateState.FALSE),
            path("P2", V.PredicateState.TRUE,
                 assertion("P1","P2",V.AuthorityEdgeType.SUPERSEDES)),
        )
    ))
    expect("G01-01 VALID SUPERSEDES", r, V.Verdict.NOT_SUPPORTED,
           "ALL_REQUIRED_PATHS_CONTRADICTED")
    assert r.forensic_ledger[1].displaced_by_authority is True

    raw = V.AuthorityEdge("P1","P2",V.AuthorityEdgeType.SUPERSEDES,True)
    r = V.adjudicate_multi_evidence(V.MultiEvidenceBundle(
        "C1", claim(), (
            path("P1", V.PredicateState.FALSE),
            path("P2", V.PredicateState.TRUE, raw_edge=raw),
        )
    ))
    expect("G01-02 RAW AUTH EDGE REJECTED", r, V.Verdict.UNKNOWN,
           "AUTHORITY_NOT_ESTABLISHED")
    assert "UNAUTHENTICATED_AUTHORITY_EDGE" in r.evidence_gaps

    r = V.adjudicate_multi_evidence(V.MultiEvidenceBundle(
        "C1", claim(), (
            path("P1", V.PredicateState.FALSE),
            path("P2", V.PredicateState.TRUE,
                 assertion("P1","P2",V.AuthorityEdgeType.SUPERSEDES,False)),
        )
    ))
    expect("G01-03 WRONG AUTHORITY IDENTITY", r, V.Verdict.UNKNOWN,
           "AUTHORITY_NOT_ESTABLISHED")

    aa = assertion("P1","P2",V.AuthorityEdgeType.SUPERSEDES)
    bad_scope = V.Evidence(
        "AUTH", aa.supporting_evidence.identity,
        V.Scope("WRONG"), V.Polarity.AFFIRMATION, ("ESTABLISHED",)
    )
    aa = V.AuthorityAssertion("P1","P2",V.AuthorityEdgeType.SUPERSEDES,bad_scope)
    r = V.adjudicate_multi_evidence(V.MultiEvidenceBundle(
        "C1", claim(), (
            path("P1", V.PredicateState.FALSE),
            path("P2", V.PredicateState.TRUE, aa=aa),
        )
    ))
    expect("G01-04 WRONG AUTHORITY SCOPE", r, V.Verdict.UNKNOWN,
           "AUTHORITY_NOT_ESTABLISHED")

    aa = V.AuthorityAssertion(
        "P1","P2",V.AuthorityEdgeType.SUPERSEDES,
        V.Evidence(
            "AUTH",
            V.PropositionIdentity("P1","AUTHORITY_RELATION","SUPERSEDES","P2"),
            V.Scope("AUTHORITY"),
            V.Polarity.NEGATION,
            ("ESTABLISHED",),
        )
    )
    r = V.adjudicate_multi_evidence(V.MultiEvidenceBundle(
        "C1", claim(), (
            path("P1", V.PredicateState.FALSE),
            path("P2", V.PredicateState.TRUE, aa=aa),
        )
    ))
    expect("G01-05 WRONG AUTHORITY POLARITY", r, V.Verdict.UNKNOWN,
           "AUTHORITY_NOT_ESTABLISHED")

    aa = V.AuthorityAssertion(
        "P1","P2",V.AuthorityEdgeType.SUPERSEDES,
        V.Evidence(
            "AUTH",
            V.PropositionIdentity("P1","AUTHORITY_RELATION","SUPERSEDES","P2"),
            V.Scope("AUTHORITY"),
            V.Polarity.AFFIRMATION,
            ("WRONG",),
        )
    )
    r = V.adjudicate_multi_evidence(V.MultiEvidenceBundle(
        "C1", claim(), (
            path("P1", V.PredicateState.FALSE),
            path("P2", V.PredicateState.TRUE, aa=aa),
        )
    ))
    expect("G01-06 WRONG AUTHORITY VALUE", r, V.Verdict.UNKNOWN,
           "AUTHORITY_NOT_ESTABLISHED")

    cases = (
        ("G01-07 SOURCE PATH MISSING",
         assertion("X","P2",V.AuthorityEdgeType.SUPERSEDES)),
        ("G01-08 TARGET PATH MISSING",
         assertion("P1","X",V.AuthorityEdgeType.SUPERSEDES)),
        ("G01-09 SELF REFERENCE",
         assertion("P1","P1",V.AuthorityEdgeType.SUPERSEDES)),
    )
    for name, aa in cases:
        r = V.adjudicate_multi_evidence(V.MultiEvidenceBundle(
            "C1", claim(), (
                path("P1", V.PredicateState.FALSE, aa=aa),
                path("P2", V.PredicateState.TRUE),
            )
        ))
        expect(name, r, V.Verdict.UNKNOWN, "AUTHORITY_NOT_ESTABLISHED")

    for i, rel in enumerate(
        (V.AuthorityEdgeType.VARIES, V.AuthorityEdgeType.QUALIFIES), 10
    ):
        r = V.adjudicate_multi_evidence(V.MultiEvidenceBundle(
            "C1", claim(), (
                path("P1", V.PredicateState.FALSE),
                path("P2", V.PredicateState.TRUE,
                     aa=assertion("P1","P2",rel)),
            )
        ))
        expect(f"G01-{i:02d} {rel.value} NON-DISPLACING", r,
               V.Verdict.UNKNOWN, "UNRESOLVED_EVIDENCE_CONFLICT")

    r = V.adjudicate_multi_evidence(V.MultiEvidenceBundle(
        "C1", claim(), (
            path("P1", V.PredicateState.FALSE,
                 assertion("P2","P1",V.AuthorityEdgeType.SUPERSEDES)),
            path("P2", V.PredicateState.TRUE,
                 assertion("P1","P2",V.AuthorityEdgeType.SUPERSEDES)),
        )
    ))
    expect("G01-12 CONFLICTING SUPERSESSION", r, V.Verdict.UNKNOWN,
           "AUTHORITY_NOT_ESTABLISHED")

    r = V.adjudicate_multi_evidence(V.MultiEvidenceBundle(
        "C1", claim(), (
            path("P1", V.PredicateState.TRUE,
                 assertion("P1","P2",V.AuthorityEdgeType.SUPERSEDES)),
            path("P2", V.PredicateState.TRUE,
                 assertion("P2","P1",V.AuthorityEdgeType.SUPERSEDES)),
        )
    ))
    expect("G01-13 CIRCULAR SUPERSESSION", r, V.Verdict.UNKNOWN,
           "AUTHORITY_NOT_ESTABLISHED")

    r = V.adjudicate_multi_evidence(V.MultiEvidenceBundle(
        "C1", claim(), (
            path("P1", V.PredicateState.UNKNOWN,
                 assertion("P1","P2",V.AuthorityEdgeType.SUPERSEDES)),
            path("P2", V.PredicateState.TRUE),
        )
    ))
    assert r.public_verdict is not V.Verdict.SUPPORTED
    print("G01-14 AUTHORITY CANNOT CREATE SUBSTANTIVE SUPPORT: PASS")

    print("G01_AUTHORITY_REGRESSION: PASS")

if __name__ == "__main__":
    main()

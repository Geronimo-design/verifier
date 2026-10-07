"""V15 repaired deterministic verifier candidate.
Status: IMPLEMENTATION CANDIDATE — EXECUTION REQUIRED — NOT CERTIFIED.

Design root: authorized source bytes + verified digest + authorized evidence coordinates + authorized rules.
Caller-supplied semantic/role/attribution/normalization/verdict state is non-authoritative.
"""
from __future__ import annotations
import hashlib, json, re
from decimal import Decimal, InvalidOperation
from dataclasses import dataclass
from enum import Enum
from typing import Any, Optional

class Verdict(str, Enum):
    SUPPORTED='SUPPORTED'; NOT_SUPPORTED='NOT_SUPPORTED'; UNKNOWN='UNKNOWN'; NOT_EVALUATED='NOT_EVALUATED'; ERROR='ERROR'
class Role(str, Enum):
    SUPPORTING='SUPPORTING'; CONTRADICTING='CONTRADICTING'; CONTEXTUAL='CONTEXTUAL'; NEUTRAL='NEUTRAL'; PROVENANCE_METADATA='PROVENANCE_METADATA'

@dataclass(frozen=True)
class Source:
    source_id: str
    content_digest: str
    provenance: str
    content: Optional[bytes]=None
@dataclass(frozen=True)
class Evidence:
    evidence_id: str
    source_id: str
    digest: str
    page: int
    paragraph: int
    start_byte: int
    end_byte: int
    role: Role=Role.NEUTRAL

class RuleSetError(ValueError): pass

AUTHORIZED_RULE_SETS={
    'RULE_SET_V1': {
        'rule_id':'RULE_SET_V1',
        'allow_numeric':True,
        'allow_explicit_negation':True,
        'allow_attribution_markers':True,
        'allow_conditions':True,
        'allow_temporal_closed_intervals':True,
        'allow_normalization':False,
    }
}

def sha256(b: bytes)->str:
    return hashlib.sha256(b).hexdigest()

def _fail(code:str, detail:str):
    raise ValueError(f'{code}:{detail}')

def exact_evidence(source: Source, content: bytes, e: Evidence)->str:
    if source.source_id != e.source_id:
        _fail('EVIDENCE_SOURCE_BINDING_MISMATCH', 'source_id')
    if source.content_digest != e.digest or sha256(content) != e.digest:
        _fail('SOURCE_DIGEST_MISMATCH', 'digest')
    if not isinstance(e.start_byte,int) or not isinstance(e.end_byte,int) or e.start_byte < 0 or e.end_byte < e.start_byte or e.end_byte > len(content):
        _fail('INVALID_BYTE_SPAN', 'span')
    if e.start_byte == e.end_byte:
        _fail('MALFORMED_EVIDENCE', 'empty_span')
    return content[e.start_byte:e.end_byte].decode('utf-8')

def _rule(rule_id:str):
    if rule_id not in AUTHORIZED_RULE_SETS:
        _fail('UNAUTHORIZED_RULE_INJECTION', rule_id)
    return AUTHORIZED_RULE_SETS[rule_id]

def _clean_num(x:str):
    # Strict numeric grammar: only canonical decimal punctuation is accepted.
    # Ambiguous separators are rejected rather than silently reinterpreted.
    raw=x
    if raw.startswith('(') and raw.endswith(')'):
        raw='-'+raw[1:-1]
    if raw.startswith('+'):
        raw=raw[1:]
    if not re.fullmatch(r'-?(?:[0-9]+(?:,[0-9]{3})*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?', raw):
        _fail('MALFORMED_NUMERIC_LITERAL', x)
    normalized=raw.replace(',','')
    try:
        d=Decimal(normalized)
    except InvalidOperation:
        _fail('MALFORMED_NUMERIC_LITERAL', x)
    if not d.is_finite():
        _fail('MALFORMED_NUMERIC_LITERAL', x)
    s=format(d, 'f')
    if '.' in s:
        s=s.rstrip('0').rstrip('.')
    if s in ('','-0'): s='0'
    return s

def _canonical_currency(token:Optional[str]):
    if token is None:
        return None
    return {
        '$':'USD', 'USD':'USD',
        'R':'ZAR', 'ZAR':'ZAR',
        '£':'GBP', 'GBP':'GBP',
        '€':'EUR', 'EUR':'EUR',
    }.get(token.upper())

def _currency_marker(text:str):
    # Currency must be attached to the parsed amount; never scan unrelated text.
    return None

def _amount_pattern():
    decimal = r'[0-9]+(?:,[0-9]{3})*(?:\.[0-9]+)?'
    scientific = r'[0-9]+(?:\.[0-9]+)?[eE][+-]?[0-9]+'
    amount = rf'[+-]?(?:{scientific}|{decimal})|\({decimal}\)'
    return rf"(?P<currency>USD|ZAR|GBP|EUR|R|\$|£|€)?\s*(?P<amount>{amount})\s*(?P<trailing>USD|ZAR|GBP|EUR|R|\$|£|€)?(?![A-Za-z0-9.,\')])"

def _parsed_currency(m):
    leading=_canonical_currency(m.group('currency'))
    trailing=_canonical_currency(m.group('trailing'))
    if leading is not None and trailing is not None and leading != trailing:
        _fail('CONFLICTING_CURRENCY_MARKERS', f'{leading}!={trailing}')
    return leading if leading is not None else trailing

def _claim_prop(claim:str):
    m=re.search(r'(?i)\b(order)\s*(?:is|=|:)?\s*'+_amount_pattern(), claim)
    if m:
        return ('Order','value',_clean_num(m.group('amount')),False,_parsed_currency(m))
    return None

def _evidence_prop(text:str):
    auxiliary_negative=list(re.finditer(
        r'(?i)\bdid\s+not\s+find\s+\b(order)\s*:\s*'+_amount_pattern(),
        text
    ))
    negative=list(re.finditer(
        r'(?i)\b(order)\s+(?:is\s+)?not\s*'+_amount_pattern(),
        text
    ))
    positive=[]
    for m in re.finditer(r'(?i)\b(order)\s*:\s*'+_amount_pattern(), text):
        prefix=text[max(0,m.start()-30):m.start()]
        if re.search(r'(?i)\bdid\s+not\s+find\s*$', prefix):
            continue
        positive.append(m)
    matches=positive+negative+auxiliary_negative
    if len(matches)!=1:
        return None
    m=matches[0]
    neg=(m in negative) or (m in auxiliary_negative)
    return ('Order','value',_clean_num(m.group('amount')),neg,_parsed_currency(m))

def _derive_role(claim:str,text:str,rule:dict)->Role:
    cp=_claim_prop(claim); ep=_evidence_prop(text)
    if not cp or not ep: return Role.NEUTRAL
    cs,_,cv,cn,cc=cp; es,_,ev,en,ec=ep
    if cs!=es: return Role.NEUTRAL
    if cn != en or cv != ev: return Role.CONTRADICTING
    if (cc is None) != (ec is None): return Role.NEUTRAL
    if cc is not None and ec is not None and cc != ec: return Role.CONTRADICTING
    return Role.SUPPORTING

def _attribution(text:str)->str:
    # Conditional, contingent, and absence language cannot establish a positive
    # proposition as an unconditional authoritative finding.
    if re.search(r'(?i)\b(if|unless|provided that|only if|when|where|on condition that|in the event that|subject to|contingent upon|conditional on)\b', text):
        return 'UNESTABLISHED'
    if re.search(r'(?i)\b(no|none|never|without|does not exist|there is no|there are no)\b', text):
        return 'UNESTABLISHED'
    if re.search(r'(?i)\b(alleges?|pleads?|asserts?|claims?|estimates?|estimated|reports?|reported|believes?|believed|suggests?|suggested|expects?|expected|according to)\b', text): return 'UNESTABLISHED'
    if re.search(r'(?i)\b(finds?|found|orders?|ordered|holds?|held|determines?|determined)\b', text): return 'AUTHORITATIVE_FINDING'
    if re.search(r'(?i)^\s*order\s*:', text): return 'STRUCTURED_RECORD'
    return 'UNESTABLISHED'

def _scope_safe(text: str, ep):
    """Conservative proposition-scope gate. Ambiguous embedding is UNKNOWN rather than guessed."""
    t=text.strip(); low=t.lower()
    if t.startswith('Order:'):
        return 'STRUCTURED_RECORD'
    if re.fullmatch(r'(?is)\s*the\s+court\s+did\s+not\s+find\s+order\s*:\s*'+_amount_pattern()+r'\s*', t):
        return 'AUTHORITATIVE_FINDING'
    bad=(r'\balleges?\b',r'\bpleads?\b',r'\basserts?\b',r'\bclaims?\b',r'\bclaimed\b',r'\balleged\b',r'\ballegedly\b',r'\bbelieved\b',
         r'\bestimates?\b',r'\bestimated\b',r'\breports?\b',r'\breported\b',r'\bbelieves?\b',r'\bsuggests?\b',r'\bsuggested\b',
         r'\bexpects?\b',r'\baccording to\b',r'\basks?\b',r'\basks whether\b',r'\bif\b',r'\bunless\b',r'\bonly if\b',r'\bmay\b',r'\bmight\b',
         r'\bcould\b',r'\bwould\b',r'\bshould\b',r'\bwhether\b',r'\bquestion\b',r'\bquotes?\b',r'\bquoted\b',r'\bquotation\b',r'\bor\b')
    if any(re.search(p,low) for p in bad):
        return 'UNESTABLISHED'
    if re.fullmatch(r'\s*order\s+(?:is\s+)?not\s+(?:(?:USD|ZAR|GBP|EUR|R|\$|£|€)\s*)?[0-9][0-9,]*(?:\.[0-9]+)?\.?\s*', low):
        return 'AUTHORITATIVE_FINDING'
    if re.search(r'\b(?:not|never|no)\b[^.?!;]*\border\b',low) or re.search(r'\border\b[^.?!;]*\b(?:not|never)\b',low):
        return 'UNESTABLISHED'
    if '?' in t or '"' in t or "'" in t:
        return 'UNESTABLISHED'
    if len(re.findall(r'\border\b', low)) != 1:
        return 'UNESTABLISHED'
    if re.search(r'\b(?:finds?|found|orders?|ordered|holds?|held|determines?|determined)\b',low):
        return 'AUTHORITATIVE_FINDING'
    return 'UNESTABLISHED'

def _derive_semantics(claim:str,text:str,rule:dict):
    cp=_claim_prop(claim); ep=_evidence_prop(text)
    if not cp or not ep: return None
    return {'claim':cp,'evidence':ep,'attribution':_scope_safe(text, ep)}

def _validate_no_injected_rule(kwargs):
    for k in ('page','paragraph','start_byte','end_byte','byte_span','evidence_location','location_override','caller_page','caller_paragraph'):
        if k in kwargs:
            _fail('UNAUTHORIZED_LOCATION_OVERRIDE', k)
    if kwargs.get('rule_override') is not None:
        _fail('UNAUTHORIZED_RULE_INJECTION','caller rule override')
    if kwargs.get('normalization_hint') is not None:
        _fail('UNAUTHORIZED_NORMALIZATION','caller normalization hint')

def adjudicate(claim:str, source:Source, evidence:Evidence, authorized_rule_set:str='RULE_SET_V1', content:Optional[bytes]=None, **caller_derived:Any)->dict:
    """Adjudicate solely from authorized bytes/rules. Caller-derived fields are rejected or ignored."""
    _validate_no_injected_rule(caller_derived)
    rule=_rule(authorized_rule_set)
    raw=content if content is not None else source.content
    if raw is None: _fail('EVIDENCE_INTEGRITY_FAILURE','source content unavailable')
    # Caller cannot redirect location: Evidence is the authorized coordinate record.
    try:
        text=exact_evidence(source,raw,evidence)
    except UnicodeDecodeError as exc:
        reason='MALFORMED_UTF8_EVIDENCE'
        result={'predicate_id':'DERIVED','state':Verdict.ERROR.value,'evidence_reference_ids':[evidence.evidence_id], 'derived_role':Role.NEUTRAL.value,'reason':reason}
        trace={'source_id':source.source_id,'document_digest':source.content_digest,'page':evidence.page,'paragraph':evidence.paragraph,'byte_span':[evidence.start_byte,evidence.end_byte],'exact_text':None,'semantic_proposition':None,'rule':authorized_rule_set,'predicate_state':Verdict.ERROR.value,'disposition':Verdict.ERROR.value,'reason':reason,'encoding_error':str(exc)}
        return {'disposition':Verdict.ERROR.value,'evaluation':result,'proof':trace}
    sem=_derive_semantics(claim,text,rule)
    if sem is None:
        verdict=Verdict.UNKNOWN
        reason='INSUFFICIENT_AUTHORIZED_SEMANTIC_EVIDENCE'
        derived_role=Role.NEUTRAL
    else:
        attr=sem['attribution']
        if attr not in ('AUTHORITATIVE_FINDING','STRUCTURED_RECORD'):
            verdict=Verdict.UNKNOWN
            reason='EVIDENCE_NOT_ESTABLISHED_AS_AUTHORITATIVE'
            derived_role=Role.CONTEXTUAL
        else:
            derived_role=_derive_role(claim,text,rule)
            verdict = {Role.SUPPORTING:Verdict.SUPPORTED, Role.CONTRADICTING:Verdict.NOT_SUPPORTED}.get(derived_role,Verdict.UNKNOWN)
            reason='DERIVED_SEMANTIC_MATCH' if verdict is Verdict.SUPPORTED else ('DERIVED_SEMANTIC_CONTRADICTION' if verdict is Verdict.NOT_SUPPORTED else 'SEMANTIC_RELATION_UNESTABLISHED')
    if verdict is Verdict.UNKNOWN:
        if reason == 'INSUFFICIENT_AUTHORIZED_SEMANTIC_EVIDENCE':
            order_occurrences = len(re.findall(r'(?i)\bOrder\s*:', text))
            if order_occurrences > 1:
                lawyer_explanation = ('UNKNOWN — This claim could not be verified.\n'
                    'The evidence contains more than one occurrence of the relevant Order, and the current authorised rules do not establish which occurrence governs the claim.\n'
                    'The evidence is therefore insufficient to establish the claim.')
            else:
                lawyer_explanation = ('UNKNOWN — This claim could not be verified.\n'
                    'The available evidence does not contain enough authorised semantic information to establish the claim.\n'
                    'The evidence is therefore insufficient to establish the claim.')
        elif reason == 'EVIDENCE_NOT_ESTABLISHED_AS_AUTHORITATIVE':
            lawyer_explanation = ('UNKNOWN — This claim could not be verified.\n'
                'The relevant statement was not established as an authoritative finding or authorised structured record.\n'
                'The evidence therefore cannot establish the claim.')
        else:
            lawyer_explanation = ('UNKNOWN — This claim could not be verified.\n'
                'The available evidence does not establish the claim under the current authorised rules.')
    else:
        lawyer_explanation = None
    result={'predicate_id':'DERIVED','state':verdict.value,'evidence_reference_ids':[evidence.evidence_id], 'derived_role':derived_role.value,'reason':reason,'lawyer_explanation':lawyer_explanation}
    trace={'source_id':source.source_id,'document_digest':source.content_digest,'page':evidence.page,'paragraph':evidence.paragraph,'byte_span':[evidence.start_byte,evidence.end_byte],'exact_text':text,'semantic_proposition':sem,'rule':authorized_rule_set,'predicate_state':verdict.value,'disposition':verdict.value,'reason':reason}
    # Ignore non-authoritative diagnostic fields, but record their presence without using them.
    untrusted={k:caller_derived[k] for k in caller_derived if k not in ('rule_override','normalization_hint')}
    if untrusted: trace['untrusted_inputs_ignored']=sorted(untrusted.keys())
    return {'disposition':verdict.value,'evaluation':result,'proof':trace}

def evaluate(predicate_id:str, evidences, **kwargs):
    """Legacy compatibility wrapper. Roles are never treated as proof.
    New adjudication should use adjudicate(). Without source bytes, evidence cannot establish semantics.
    """
    if kwargs.get('caller_predicate_state') is not None or kwargs.get('caller_verdict') is not None:
        # Explicitly ignore caller derived states; no semantic source means UNKNOWN.
        return {'predicate_id':predicate_id,'state':Verdict.UNKNOWN.value,'evidence_reference_ids':[e.evidence_id for e in evidences], 'reason':'CALLER_DERIVED_STATE_NON_AUTHORITATIVE'}
    # Legacy objects contain no raw source binding, so role aggregation is deliberately retired.
    return {'predicate_id':predicate_id,'state':Verdict.UNKNOWN.value,'evidence_reference_ids':[e.evidence_id for e in evidences], 'reason':'RAW_EVIDENCE_REQUIRED'}

def proof(claim:str, source:Source, evidence:Evidence, predicate:dict, verdict:dict, text:str):
    # Proof must be internally consistent with actual evaluation state.
    ps=predicate.get('state'); vs=verdict.get('state')
    if ps != vs: _fail('PROOF_INTEGRITY_FAILURE','predicate/verdict mismatch')
    if source.source_id != evidence.source_id or source.content_digest != evidence.digest:
        _fail('PROOF_INTEGRITY_FAILURE','source/evidence binding')
    return {'claim':claim,'source_id':source.source_id,'document_digest':source.content_digest,'page':evidence.page,'paragraph':evidence.paragraph,'byte_span':[evidence.start_byte,evidence.end_byte],'exact_text':text,'predicate':ps,'verdict':vs}


# ============================================================
# G01 STRUCTURED AUTHORITY INTERFACE — CANDIDATE ONLY
# Derived implementation proposal. Not certified.
# ============================================================

def _g01_result(status, reason, trace=None):
    review = status in ('UNKNOWN', 'NOT_EVALUATED', 'ERROR')
    return {
        'disposition': status,
        'reason': reason,
        'lawyer_check_required': review,
        'lawyer_label': 'NOT SURE — LAWYER CHECK REQUIRED' if review else None,
        'proof': trace or {}
    }


def _g01_validate_graph(decisions, propositions, relationships, status_evidence):
    if not isinstance(decisions, list):
        return False, 'DECISIONS_NOT_LIST'
    if not isinstance(propositions, list):
        return False, 'PROPOSITIONS_NOT_LIST'
    if not isinstance(relationships, list):
        return False, 'RELATIONSHIPS_NOT_LIST'
    if not isinstance(status_evidence, list):
        return False, 'STATUS_EVIDENCE_NOT_LIST'

    decision_ids = set()
    for d in decisions:
        if not isinstance(d, dict):
            return False, 'INVALID_DECISION_NODE'
        required = (
            'decision_id', 'citation', 'court', 'court_level',
            'jurisdiction', 'decision_date', 'opinion_status',
            'evidence_id'
        )
        if any(k not in d for k in required):
            return False, 'INCOMPLETE_DECISION_NODE'
        if d['decision_id'] in decision_ids:
            return False, 'DUPLICATE_DECISION_ID'
        decision_ids.add(d['decision_id'])

    proposition_ids = set()
    for p in propositions:
        if not isinstance(p, dict):
            return False, 'INVALID_PROPOSITION_NODE'
        required = (
            'proposition_id', 'proposition_text',
            'paragraph_scope', 'decision_id', 'evidence_id'
        )
        if any(k not in p for k in required):
            return False, 'INCOMPLETE_PROPOSITION_NODE'
        if p['decision_id'] not in decision_ids:
            return False, 'UNKNOWN_PROPOSITION_DECISION'
        if p['proposition_id'] in proposition_ids:
            return False, 'DUPLICATE_PROPOSITION_ID'
        proposition_ids.add(p['proposition_id'])

    for r in relationships:
        if not isinstance(r, dict):
            return False, 'INVALID_RELATIONSHIP_NODE'
        required = (
            'relationship_id', 'from_decision', 'to_decision',
            'relationship_type', 'affected_proposition',
            'affected_paragraph', 'effective_date', 'evidence_id'
        )
        if any(k not in r for k in required):
            return False, 'INCOMPLETE_RELATIONSHIP_NODE'
        if r['from_decision'] not in decision_ids:
            return False, 'UNKNOWN_RELATIONSHIP_SOURCE'
        if r['to_decision'] not in decision_ids:
            return False, 'UNKNOWN_RELATIONSHIP_TARGET'
        if r['affected_proposition'] not in proposition_ids:
            return False, 'UNKNOWN_AFFECTED_PROPOSITION'

    for s in status_evidence:
        if not isinstance(s, dict):
            return False, 'INVALID_STATUS_EVIDENCE'
        required = (
            'status_evidence_id', 'target_decision',
            'target_proposition', 'checked_as_of',
            'subsequent_treatment', 'unresolved_relationships',
            'evidence_id'
        )
        if any(k not in s for k in required):
            return False, 'INCOMPLETE_STATUS_EVIDENCE'
        if s['target_decision'] not in decision_ids:
            return False, 'UNKNOWN_STATUS_DECISION'
        if s['target_proposition'] not in proposition_ids:
            return False, 'UNKNOWN_STATUS_PROPOSITION'
        if not isinstance(s['unresolved_relationships'], list):
            return False, 'INVALID_UNRESOLVED_RELATIONSHIPS'

    return True, 'SCHEMA_VALID'


def _g01_registry_entry(evidence_registry, evidence_id):
    if not isinstance(evidence_registry, dict):
        return None, 'EVIDENCE_REGISTRY_NOT_DICT'
    entry = evidence_registry.get(evidence_id)
    if entry is None:
        return None, 'EVIDENCE_ID_NOT_FOUND'
    if not isinstance(entry, dict):
        return None, 'INVALID_EVIDENCE_REGISTRY_ENTRY'
    for key in ('source', 'evidence', 'content'):
        if key not in entry:
            return None, 'INCOMPLETE_EVIDENCE_REGISTRY_ENTRY'
    source = entry['source']
    evidence = entry['evidence']
    content = entry['content']
    if not isinstance(source, Source):
        return None, 'REGISTRY_SOURCE_NOT_SOURCE'
    if not isinstance(evidence, Evidence):
        return None, 'REGISTRY_EVIDENCE_NOT_EVIDENCE'
    if not isinstance(content, bytes):
        return None, 'REGISTRY_CONTENT_NOT_BYTES'
    if evidence.evidence_id != evidence_id:
        return None, 'EVIDENCE_ID_BINDING_MISMATCH'
    return entry, None


def _g01_verify_binding(evidence_registry, evidence_id):
    entry, error = _g01_registry_entry(evidence_registry, evidence_id)
    if error:
        return None, error

    source = entry['source']
    evidence = entry['evidence']
    content = entry['content']

    try:
        exact_text = exact_evidence(source, content, evidence)
    except UnicodeDecodeError:
        return None, 'MALFORMED_UTF8_EVIDENCE'
    except ValueError as exc:
        return None, str(exc).split(':', 1)[0]

    return {
        'evidence_id': evidence.evidence_id,
        'source_id': source.source_id,
        'document_digest': source.content_digest,
        'page': evidence.page,
        'paragraph': evidence.paragraph,
        'byte_span': [evidence.start_byte, evidence.end_byte],
        'exact_text': exact_text
    }, None


def _g01_authority_level(level):
    # No implicit lexical ordering of court-level strings.
    # Only explicitly authorised levels may participate in comparison.
    levels = {
        'MAGISTRATES': 10,
        'DISTRICT': 10,
        'REGIONAL': 20,
        'HIGH': 30,
        'FULL_BENCH': 35,
        'SCA': 40,
        'CONSTITUTIONAL': 50
    }
    return levels.get(str(level).upper())


def _g01_semantic_status(text):
    low = text.lower()

    displacement = (
        'overruled' in low or
        'set aside' in low or
        'reversed' in low or
        'varied' in low
    )

    affirmative_current = (
        'remains good law' in low or
        'remains binding' in low or
        'continues to apply' in low or
        'approved the reasoning' in low or
        'followed the decision' in low
    )

    attribution = (
        'the applicant argued' in low or
        'the respondent argued' in low or
        'the appellant argued' in low or
        'the respondent submitted' in low or
        'the applicant submitted' in low or
        'the appellant submitted' in low or
        'counsel argued' in low or
        'counsel submitted' in low or
        'contended that' in low or
        'maintained that' in low or
        'asserted that' in low or
        'alleged that' in low or
        'it was submitted that' in low
    )

    if attribution:
        return 'UNESTABLISHED'

    negated_displacement = (
        'not overruled' in low or
        'was not overruled' in low or
        'were not overruled' in low or
        'not reversed' in low or
        'was not reversed' in low or
        'were not reversed' in low or
        'not set aside' in low or
        'was not set aside' in low or
        'were not set aside' in low or
        'not varied' in low or
        'was not varied' in low or
        'were not varied' in low
    )

    if negated_displacement:
        return 'UNESTABLISHED'

    explicit_negation_or_rejection = (
        'did not hold that' in low or
        'did not find that' in low or
        'declined to hold that' in low or
        'rejected the proposition that' in low or
        'rejected that' in low or
        'declined to accept that' in low or
        'refused to accept that' in low or
        'rejected the view that' in low or
        'dismissed the proposition that' in low or
        'disavowed the proposition that' in low
    )

    if explicit_negation_or_rejection:
        return 'DISPROVED_CURRENT'

    if displacement and affirmative_current:
        return 'CONFLICTING'
    if displacement:
        return 'DISPLACED'
    if affirmative_current:
        return 'CURRENT'
    return 'UNESTABLISHED'


def evaluate_g01(
    decisions,
    propositions,
    relationships,
    status_evidence,
    target_proposition,
    evidence_registry=None
):
    """
    G01 evidence-gated current-authority evaluation.

    No graph node can establish authority unless its evidence_id resolves
    through an authenticated Source/Evidence/content binding.

    Caller-supplied status fields are descriptive inputs only. They are
    never sufficient by themselves to produce SUPPORTED.
    """

    valid, reason = _g01_validate_graph(
        decisions, propositions, relationships, status_evidence
    )
    if not valid:
        return _g01_result('ERROR', reason)

    if evidence_registry is None:
        return _g01_result(
            'UNKNOWN',
            'EVIDENCE_REGISTRY_REQUIRED'
        )

    proposition = next(
        (p for p in propositions if p['proposition_id'] == target_proposition),
        None
    )
    if proposition is None:
        return _g01_result('NOT_EVALUATED', 'TARGET_PROPOSITION_NOT_FOUND')

    decision = next(
        (d for d in decisions if d['decision_id'] == proposition['decision_id']),
        None
    )
    if decision is None:
        return _g01_result('ERROR', 'PROPOSITION_DECISION_NOT_FOUND')

    trace = {
        'target_proposition': target_proposition,
        'decision_id': decision['decision_id'],
        'decision_evidence': None,
        'proposition_evidence': None,
        'relationship_evidence': [],
        'status_evidence': []
    }

    # Every material identity/assertion must have authenticated evidence.
    for label, node in (
        ('decision', decision),
        ('proposition', proposition)
    ):
        binding, bind_error = _g01_verify_binding(
            evidence_registry, node['evidence_id']
        )
        if bind_error:
            integrity_errors = (
                'SOURCE_DIGEST_MISMATCH',
                'EVIDENCE_SOURCE_BINDING_MISMATCH',
                'INVALID_BYTE_SPAN',
                'MALFORMED_EVIDENCE',
                'MALFORMED_UTF8_EVIDENCE',
                'REGISTRY_NOT_DICT',
                'REGISTRY_ENTRY_NOT_DICT',
                'REGISTRY_SOURCE_NOT_SOURCE',
                'REGISTRY_EVIDENCE_NOT_EVIDENCE',
                'REGISTRY_CONTENT_NOT_BYTES',
                'EVIDENCE_ID_BINDING_MISMATCH',
            )
            status = 'ERROR' if bind_error in integrity_errors else 'UNKNOWN'
            reason = (
                'EVIDENCE_INTEGRITY_FAILURE:' + label + ':' + bind_error
                if status == 'ERROR'
                else 'AUTHENTICATED_EVIDENCE_REQUIRED:' + label + ':' + bind_error
            )
            return _g01_result(status, reason, trace)
        trace[label + '_evidence'] = binding

    # Every relationship supplied to the graph must have authenticated
    # evidence. Unrelated material is not silently discarded.
    for r in relationships:
        binding, bind_error = _g01_verify_binding(
            evidence_registry, r['evidence_id']
        )
        if bind_error:
            integrity_errors = (
                'SOURCE_DIGEST_MISMATCH',
                'EVIDENCE_SOURCE_BINDING_MISMATCH',
                'INVALID_BYTE_SPAN',
                'MALFORMED_EVIDENCE',
                'MALFORMED_UTF8_EVIDENCE',
                'REGISTRY_NOT_DICT',
                'REGISTRY_ENTRY_NOT_DICT',
                'REGISTRY_SOURCE_NOT_SOURCE',
                'REGISTRY_EVIDENCE_NOT_EVIDENCE',
                'REGISTRY_CONTENT_NOT_BYTES',
                'EVIDENCE_ID_BINDING_MISMATCH',
            )
            status = 'ERROR' if bind_error in integrity_errors else 'UNKNOWN'
            reason = (
                'EVIDENCE_INTEGRITY_FAILURE:relationship:' + bind_error
                if status == 'ERROR'
                else 'AUTHENTICATED_EVIDENCE_REQUIRED:relationship:' + bind_error
            )
            return _g01_result(status, reason, trace)

    affected = [
        r for r in relationships
        if r['affected_proposition'] == target_proposition
    ]

    # Validate every relationship before allowing any relationship to affect
    # the disposition. Invalid evidence is never silently discarded.
    for r in affected:
        binding, bind_error = _g01_verify_binding(
            evidence_registry, r['evidence_id']
        )
        if bind_error:
            integrity_errors = (
                'SOURCE_DIGEST_MISMATCH',
                'EVIDENCE_SOURCE_BINDING_MISMATCH',
                'INVALID_BYTE_SPAN',
                'MALFORMED_EVIDENCE',
                'MALFORMED_UTF8_EVIDENCE',
                'REGISTRY_NOT_DICT',
                'REGISTRY_ENTRY_NOT_DICT',
                'REGISTRY_SOURCE_NOT_SOURCE',
                'REGISTRY_EVIDENCE_NOT_EVIDENCE',
                'REGISTRY_CONTENT_NOT_BYTES',
                'EVIDENCE_ID_BINDING_MISMATCH',
            )
            status = 'ERROR' if bind_error in integrity_errors else 'UNKNOWN'
            reason = (
                'EVIDENCE_INTEGRITY_FAILURE:relationship:' + bind_error
                if status == 'ERROR'
                else 'AUTHENTICATED_EVIDENCE_REQUIRED:relationship:' + bind_error
            )
            return _g01_result(status, reason, trace)

        from_decision = next(
            d for d in decisions if d['decision_id'] == r['from_decision']
        )
        to_decision = next(
            d for d in decisions if d['decision_id'] == r['to_decision']
        )

        from_level = _g01_authority_level(from_decision['court_level'])
        to_level = _g01_authority_level(to_decision['court_level'])

        if from_level is None or to_level is None:
            return _g01_result(
                'UNKNOWN',
                'UNAUTHORISED_COURT_LEVEL',
                trace
            )

        if (
            r['relationship_type'] == 'OVERRULES'
            and from_level <= to_level
        ):
            return _g01_result(
                'NOT_SUPPORTED',
                'LOWER_OR_EQUAL_AUTHORITY_CANNOT_OVERRULE',
                trace
            )

        semantic = _g01_semantic_status(binding['exact_text'])
        item = dict(binding)
        item['relationship_id'] = r['relationship_id']
        item['relationship_type'] = r['relationship_type']
        item['semantic_status'] = semantic
        trace['relationship_evidence'].append(item)

        if semantic == 'CONFLICTING':
            return _g01_result(
                'UNKNOWN',
                'CONFLICTING_AUTHORITY_EVIDENCE',
                trace
            )

        if semantic == 'UNESTABLISHED':
            return _g01_result(
                'UNKNOWN',
                'RELATIONSHIP_NOT_SEMANTICALLY_ESTABLISHED',
                trace
            )

    # Every status record for the target must be authenticated.
    matching_status = [
        s for s in status_evidence
        if s['target_proposition'] == target_proposition
    ]

    if not matching_status:
        return _g01_result(
            'UNKNOWN',
            'CURRENT_AUTHORITY_STATUS_EVIDENCE_MISSING',
            trace
        )

    for s in matching_status:
        binding, bind_error = _g01_verify_binding(
            evidence_registry, s['evidence_id']
        )
        if bind_error:
            integrity_errors = (
                'SOURCE_DIGEST_MISMATCH',
                'EVIDENCE_SOURCE_BINDING_MISMATCH',
                'INVALID_BYTE_SPAN',
                'MALFORMED_EVIDENCE',
                'MALFORMED_UTF8_EVIDENCE',
                'REGISTRY_NOT_DICT',
                'REGISTRY_ENTRY_NOT_DICT',
                'REGISTRY_SOURCE_NOT_SOURCE',
                'REGISTRY_EVIDENCE_NOT_EVIDENCE',
                'REGISTRY_CONTENT_NOT_BYTES',
                'EVIDENCE_ID_BINDING_MISMATCH',
            )
            status = 'ERROR' if bind_error in integrity_errors else 'UNKNOWN'
            reason = (
                'EVIDENCE_INTEGRITY_FAILURE:status:' + bind_error
                if status == 'ERROR'
                else 'AUTHENTICATED_EVIDENCE_REQUIRED:status:' + bind_error
            )
            return _g01_result(status, reason, trace)

        semantic = _g01_semantic_status(binding['exact_text'])
        item = dict(binding)
        item['status_evidence_id'] = s['status_evidence_id']
        item['semantic_status'] = semantic
        trace['status_evidence'].append(item)

    semantic_states = {
        item['semantic_status']
        for item in trace['status_evidence']
    }

    relationship_states = {
        item['semantic_status']
        for item in trace['relationship_evidence']
    }

    # Cross-layer safety:
    # Authenticated relationship evidence that establishes displacement
    # must never be silently overridden by authenticated CURRENT status
    # evidence. The contradiction requires human review.
    if (
        'DISPLACED' in relationship_states
        and 'CURRENT' in semantic_states
    ):
        return _g01_result(
            'UNKNOWN',
            'CONFLICTING_RELATIONSHIP_AND_STATUS_EVIDENCE',
            trace
        )

    # Combination safety:
    # contradictory or insufficiently established status evidence must
    # never silently produce SUPPORTED or a definitive NOT_SUPPORTED.
    if 'CONFLICTING' in semantic_states:
        return _g01_result(
            'UNKNOWN',
            'CONFLICTING_AUTHORITY_STATUS_EVIDENCE',
            trace
        )

    if (
        'CURRENT' in semantic_states and
        (
            'DISPLACED' in semantic_states or
            'DISPROVED_CURRENT' in semantic_states or
            'UNESTABLISHED' in semantic_states
        )
    ):
        return _g01_result(
            'UNKNOWN',
            'CONFLICTING_OR_INSUFFICIENT_AUTHORITY_STATUS_EVIDENCE',
            trace
        )

    if 'DISPLACED' in semantic_states:
        return _g01_result(
            'NOT_SUPPORTED',
            'AUTHENTICATED_AUTHORITY_DISPLACEMENT',
            trace
        )

    if 'DISPROVED_CURRENT' in semantic_states:
        return _g01_result(
            'NOT_SUPPORTED',
            'AUTHORITY_CURRENTNESS_NEGATED_OR_REJECTED',
            trace
        )

    if 'CURRENT' not in semantic_states:
        return _g01_result(
            'UNKNOWN',
            'CURRENT_AUTHORITY_NOT_SEMANTICALLY_ESTABLISHED',
            trace
        )

    # Caller-supplied "NONE", "UNKNOWN", etc. never create the positive result.
    # Only authenticated evidence whose text deterministically establishes
    # current authority can reach this point.
    return _g01_result(
        'SUPPORTED',
        'AUTHENTICATED_CURRENT_AUTHORITY_ESTABLISHED',
        trace
    )


def adjudicate_g01(
    decisions,
    propositions,
    relationships,
    status_evidence,
    target_proposition,
    evidence_registry
):
    return evaluate_g01(
        decisions,
        propositions,
        relationships,
        status_evidence,
        target_proposition,
        evidence_registry
    )


def verify_current_authority(
    decisions,
    propositions,
    relationships,
    status_evidence,
    target_proposition,
    evidence_registry
):
    return evaluate_g01(
        decisions,
        propositions,
        relationships,
        status_evidence,
        target_proposition,
        evidence_registry
    )


def evaluate_authority_graph(
    decisions,
    propositions,
    relationships,
    status_evidence,
    target_proposition,
    evidence_registry
):
    return evaluate_g01(
        decisions,
        propositions,
        relationships,
        status_evidence,
        target_proposition,
        evidence_registry
    )





















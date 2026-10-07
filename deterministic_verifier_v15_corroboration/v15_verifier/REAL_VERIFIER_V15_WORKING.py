from __future__ import annotations
from dataclasses import dataclass, asdict
from enum import Enum
from decimal import Decimal, InvalidOperation
from datetime import datetime
import hashlib, json

class Verdict(str, Enum):
    SUPPORTED='SUPPORTED'; NOT_SUPPORTED='NOT_SUPPORTED'; UNKNOWN='UNKNOWN'; NOT_EVALUATED='NOT_EVALUATED'; ERROR='ERROR'
class Role(str, Enum):
    SUPPORTING='SUPPORTING'; CONTRADICTING='CONTRADICTING'; CONTEXTUAL='CONTEXTUAL'; NEUTRAL='NEUTRAL'; PROVENANCE_METADATA='PROVENANCE_METADATA'
class Relation(str, Enum):
    EQUALS='EQUALS'; NOT_EQUALS='NOT_EQUALS'; PRECEDES='PRECEDES'; OVERLAPS='OVERLAPS'; CONCURRENT='CONCURRENT'; CAUSE='CAUSE'; NOT_CAUSE='NOT_CAUSE'
@dataclass(frozen=True)
class SourceRecord:
    source_id:str; content_digest:str; institutional_provenance:str
@dataclass(frozen=True)
class EvidenceItem:
    evidence_id:str; source_reference_id:str; source_content_digest:str; coordinate_type:str; coordinate_value:str; start_byte:int; end_byte:int; evidence_role:Role
@dataclass(frozen=True)
class Proposition:
    proposition_id:str; kind:str; value:str; rule_id:str
@dataclass(frozen=True)
class PredicateEvaluation:
    predicate_id:str; state:str; evidence_reference_ids:tuple[str,...]; derivation_reference_ids:tuple[str,...]
@dataclass(frozen=True)
class VerdictResult:
    target_proposition_id:str; applicable_rule_id:str; categorical_state:Verdict; predicate_evaluations:tuple[PredicateEvaluation,...]; complete_proof_trace:tuple[dict,...]

def sha256(data:bytes): return hashlib.sha256(data).hexdigest()
def validate_source(source, content):
    return sha256(content)==source.content_digest
def exact_span(content,start,end):
    if not (0<=start<=end<=len(content)): raise ValueError('INVALID_BYTE_SPAN')
    if start==end: raise ValueError('EMPTY_EVIDENCE_SPAN')
    return content[start:end]
def validate_evidence(e,source,content):
    if e.source_reference_id!=source.source_id: raise ValueError('SOURCE_REFERENCE_MISMATCH')
    if e.source_content_digest!=source.content_digest: raise ValueError('EVIDENCE_DIGEST_MISMATCH')
    if not validate_source(source,content): raise ValueError('SOURCE_DIGEST_MISMATCH')
    if e.coordinate_type == 'page':
        coordinate = str(e.coordinate_value).strip()
        if not coordinate.isdigit() or int(coordinate) < 1:
            raise ValueError('INVALID_PAGE_COORDINATE')
    return exact_span(content,e.start_byte,e.end_byte)
def parse_decimal(s):
    import re
    if not isinstance(s, str):
        raise ValueError('INVALID_NUMBER')
    value = s.strip()
    # Strict numeric grammar:
    #   55000
    #   55000.00
    #   55 000.00
    #   R 55 000.00
    #   R55 000.00
    # Comma grouping and malformed grouping remain rejected.
    pattern = r'(?:R\s*)?(?:\d+|\d{1,3}(?: \d{3})+)(?:\.\d+)?'
    if re.fullmatch(pattern, value) is None:
        raise ValueError('INVALID_NUMBER')
    normalized = value.replace('R', '').replace(' ', '')
    try:
        return Decimal(normalized)
    except InvalidOperation:
        raise ValueError('INVALID_NUMBER')


def parse_source_decimal(source_bytes):
    """Derive evidence-side numeric value only from verified source bytes."""
    if not isinstance(source_bytes, bytes):
        raise ValueError('INVALID_SOURCE_BYTES')
    try:
        observed = source_bytes.decode('utf-8')
    except UnicodeDecodeError:
        raise ValueError('INVALID_UTF8_EVIDENCE')
    return parse_decimal(observed)


def evaluate_relation(relation,left,right):
    if relation==Relation.EQUALS: return left==right
    if relation==Relation.NOT_EQUALS: return left!=right
    raise ValueError('UNSUPPORTED_SCALAR_RELATION')
def evaluate_numeric(relation,left,right): return evaluate_relation(relation,parse_decimal(left),parse_decimal(right))
def evaluate_temporal(relation,left,right):
    a=datetime.fromisoformat(left.replace('Z','+00:00')); b=datetime.fromisoformat(right.replace('Z','+00:00'))
    if relation==Relation.PRECEDES: return a<b
    if relation==Relation.OVERLAPS: return False
    if relation==Relation.CONCURRENT: return a==b
    raise ValueError('UNSUPPORTED_TEMPORAL_RELATION')
def aggregate(prop,rule,evidence_results,trace):
    states=[x.state for x in evidence_results]
    if 'ERROR' in states: v=Verdict.ERROR
    elif any(x.state=='TRUE' for x in evidence_results) and any(x.state=='FALSE' for x in evidence_results): v=Verdict.UNKNOWN
    elif any(x.state=='TRUE' for x in evidence_results): v=Verdict.SUPPORTED
    elif any(x.state=='FALSE' for x in evidence_results): v=Verdict.NOT_SUPPORTED
    elif any(x.state=='NOT_EVALUATED' for x in evidence_results): v=Verdict.NOT_EVALUATED
    else: v=Verdict.UNKNOWN
    return VerdictResult(prop,rule,v,tuple(evidence_results),tuple(trace))

def verify_numeric_claim(prop_id,rule_id,claim_value,evidence,source,content,relation=Relation.EQUALS):
    span=validate_evidence(evidence,source,content)
    observed=span.decode('utf-8')
    claim_numeric=parse_decimal(claim_value)
    evidence_numeric=parse_source_decimal(span)
    result=evaluate_relation(relation,claim_numeric,evidence_numeric)
    pred=PredicateEvaluation(prop_id,'TRUE' if result else 'FALSE',(evidence.evidence_id,),('NUMERIC_EQUALITY',))
    trace=({'step':'SOURCE_DIGEST','source_id':source.source_id,'digest':source.content_digest}, {'step':'EVIDENCE_LOCATION','source_id':source.source_id,'coordinate_type':evidence.coordinate_type,'coordinate_value':evidence.coordinate_value,'start_byte':evidence.start_byte,'end_byte':evidence.end_byte,'exact_text':observed}, {'step':'RULE','rule_id':rule_id,'predicate':'NUMERIC_EQUALITY','claim_value':claim_value,'observed_value':observed}, {'step':'VERDICT','state':'TRUE' if result else 'FALSE'})
    return aggregate(prop_id,rule_id,(pred,),trace)


def _semantic_boundary_state(text):
    lower=text.lower()

    # Conservative fail-closed handling adapted from the old
    # semantic verifier's polarity/NOT_EVALUATED model.
    negation_markers=(
        'not ', 'never ', 'no ', 'cannot ', 'can\'t ',
        'isn\'t ', 'wasn\'t ', 'weren\'t ', 'doesn\'t ',
        'didn\'t ', 'won\'t ', 'wouldn\'t '
    )
    attribution_markers=(
        'according to ', 'reported that ', 'reports that ',
        'alleged that ', 'allegedly ', 'claims that ',
        'claimed that ', 'believes that ', 'believed that ',
        'suggests that ', 'suggested that ',
        'expects that ', 'expected that '
    )
    conditional_markers=(
        'if ', 'unless ', 'provided that ', 'subject to ',
        'may ', 'might ', 'could ', 'possibly '
    )

    if any(marker in lower for marker in negation_markers):
        return 'NOT_EVALUATED', 'SEMANTIC_NEGATION_NOT_AUTHORIZED'

    if any(marker in lower for marker in attribution_markers):
        return 'NOT_EVALUATED', 'SEMANTIC_ATTRIBUTION_NOT_AUTHORIZED'

    if any(marker in lower for marker in conditional_markers):
        return 'NOT_EVALUATED', 'SEMANTIC_CONDITIONAL_OR_UNCERTAIN_NOT_AUTHORIZED'

    return None, None


def verify_text_claim(prop_id,rule_id,claim_value,evidence,source,content):
    span=validate_evidence(evidence,source,content)
    observed=span.decode('utf-8')

    semantic_state, semantic_reason = _semantic_boundary_state(observed)

    if semantic_state == 'NOT_EVALUATED':
        pred=PredicateEvaluation(
            prop_id,
            'NOT_EVALUATED',
            (evidence.evidence_id,),
            ('SEMANTIC_BOUNDARY',),
        )
        trace=(
            {'step':'SOURCE_DIGEST','source_id':source.source_id,'digest':source.content_digest},
            {'step':'EVIDENCE_LOCATION','source_id':source.source_id,'coordinate_type':evidence.coordinate_type,'coordinate_value':evidence.coordinate_value,'start_byte':evidence.start_byte,'end_byte':evidence.end_byte,'exact_text':observed},
            {'step':'RULE','rule_id':rule_id,'predicate':'SEMANTIC_BOUNDARY','reason':semantic_reason},
            {'step':'VERDICT','state':'NOT_EVALUATED'},
        )
        return aggregate(prop_id,rule_id,(pred,),trace)

    result=claim_value==observed
    pred=PredicateEvaluation(
        prop_id,
        'TRUE' if result else 'FALSE',
        (evidence.evidence_id,),
        ('TEXT_EQUALITY',),
    )
    trace=(
        {'step':'SOURCE_DIGEST','source_id':source.source_id,'digest':source.content_digest},
        {'step':'EVIDENCE_LOCATION','source_id':source.source_id,'coordinate_type':evidence.coordinate_type,'coordinate_value':evidence.coordinate_value,'start_byte':evidence.start_byte,'end_byte':evidence.end_byte,'exact_text':observed},
        {'step':'RULE','rule_id':rule_id,'predicate':'TEXT_EQUALITY'},
        {'step':'VERDICT','state':'TRUE' if result else 'FALSE'},
    )
    return aggregate(prop_id,rule_id,(pred,),trace)


# G01_AUTHORITY_INTEGRATION

# G01_AUTHORITY_INTEGRATION

def verify_authority_g01(
    decisions,
    propositions,
    relationships,
    status_evidence,
    target_proposition,
    evidence_items,
):
    """
    Controlled production entry point for G01 authority verification.

    Existing working-verifier evidence authentication remains the boundary.
    The G01 adapter is invoked only after authenticated evidence has been
    converted into the G01 evidence registry.
    """
    from g01_working_verifier_adapter import (
        evaluate_authority_via_working_verifier,
    )

    return evaluate_authority_via_working_verifier(
        decisions,
        propositions,
        relationships,
        status_evidence,
        target_proposition,
        evidence_items,
    )


# TEMPORAL_PRECISION_INTEGRATION
# Production entry point. Evidence-side temporal facts are derived only
# from authenticated evidence bytes by the certified temporal adapter.
def verify_temporal_claim_v15(
    prop_id,
    rule_id,
    relation,
    left_identity,
    left_scope,
    left_start,
    left_end,
    right_identity,
    right_scope,
    right_start,
    right_end,
    evidence,
    source,
    content,
):
    from temporal_v15_evidence_adapter import verify_temporal_claim_v15 as _verify

    return _verify(
        prop_id,
        rule_id,
        relation,
        left_identity,
        left_scope,
        left_start,
        left_end,
        right_identity,
        right_scope,
        right_start,
        right_end,
        evidence,
        source,
        content,
    )

# UI CANDIDATE ADJUDICATION
# This is the single deterministic adjudication boundary used by the web app.
# Candidate discovery is deliberately outside V15; candidate acceptance, semantic
# boundaries, contradiction handling, and final verdict aggregation are inside it.
def _candidate_tokens(text):
    import re
    stop = {
        'the','a','an','is','was','were','are','of','to','and','in','on','for',
        'that','this','by','from','with','at','as','it','be','has','have','had',
        'did','not','than','then','under','into'
    }
    return {x for x in re.findall(r'[a-z0-9]+(?:[.,][0-9]+)?', text.lower()) if x not in stop and len(x) > 1}


def _candidate_profile(text):
    import re
    months = {
        'january':1,'jan':1,'february':2,'feb':2,'march':3,'mar':3,'april':4,'apr':4,
        'may':5,'june':6,'jun':6,'july':7,'jul':7,'august':8,'aug':8,
        'september':9,'sep':9,'sept':9,'october':10,'oct':10,'november':11,'nov':11,
        'december':12,'dec':12
    }
    month_pattern = r'(?:' + '|'.join(sorted(months, key=len, reverse=True)) + r')'
    dates = set()
    for m in re.finditer(r'\b(\d{4})[-/]([01]?\d)[-/]([0-3]?\d)\b', text):
        try:
            from datetime import date
            dates.add(date(int(m.group(1)), int(m.group(2)), int(m.group(3))).isoformat())
        except ValueError:
            pass
    for m in re.finditer(rf'\b([0-3]?\d)(?:st|nd|rd|th)?\s+({month_pattern})\.?\s+(\d{{4}})\b', text, re.I):
        try:
            from datetime import date
            dates.add(date(int(m.group(3)), months[m.group(2).lower().rstrip('.')], int(m.group(1))).isoformat())
        except ValueError:
            pass
    for m in re.finditer(rf'\b({month_pattern})\.?\s+([0-3]?\d)(?:st|nd|rd|th)?[,]?\s+(\d{{4}})\b', text, re.I):
        try:
            from datetime import date
            dates.add(date(int(m.group(3)), months[m.group(1).lower().rstrip('.')], int(m.group(2))).isoformat())
        except ValueError:
            pass
    amounts = {
        m.group(1).replace(' ', '').replace(',', '')
        for m in re.finditer(r'\b(?:R|ZAR)\s*([0-9]{1,3}(?:,[0-9]{3})*(?:\.[0-9]{1,2})?|[0-9]+(?:\.[0-9]{1,2})?)', text, re.I)
    }
    percentages = {str(float(m.group(1))).rstrip('0').rstrip('.') for m in re.finditer(r'\b(\d+(?:\.\d+)?)\s*%', text)}
    masked = re.sub(r'\b(?:R|ZAR)\s*[0-9][0-9,]*(?:\.[0-9]+)?', ' ', text, flags=re.I)
    masked = re.sub(r'\d+(?:[/-]\d+){2,4}', ' ', masked)
    masked = re.sub(r'\b\d+(?:\.\d+)?\s*%', ' ', masked)
    quantities = set()
    for raw in re.findall(r'\b\d+(?:\.\d+)?\b', masked):
        integer = int(float(raw))
        if len(raw.split('.')[0]) == 4 and 1900 <= integer <= 2200:
            continue
        quantities.add(raw.rstrip('0').rstrip('.') if '.' in raw else raw)
    return {'dates': dates, 'amounts': amounts, 'percentages': percentages, 'quantities': quantities}


def _candidate_polarity(text):
    import re
    return 'negative' if re.search(
        r'\b(?:not|no|never|did not|does not|do not|was not|were not|is not|are not|cannot|can\'t|didn\'t|doesn\'t|wasn\'t|weren\'t)\b',
        text.lower(),
    ) else 'positive'


def verify_claim_candidates(prop_id, rule_id, claim_value, evidence_items, evidence_texts, source, content):
    """Deterministically adjudicate authenticated candidate evidence through V15.

    This function never trusts candidate metadata for the verdict. Each evidence
    item has already crossed validate_evidence(), and the final state is derived
    from the claim text plus exact authenticated evidence bytes.
    """
    if len(evidence_items) != len(evidence_texts):
        raise ValueError('EVIDENCE_TEXT_COUNT_MISMATCH')

    claim_tokens = _candidate_tokens(claim_value)
    claim_profile = _candidate_profile(claim_value)
    claim_polarity = _candidate_polarity(claim_value)
    evaluations = []
    trace = [
        {'step': 'SOURCE_DIGEST', 'source_id': source.source_id, 'digest': source.content_digest},
    ]

    for evidence, observed in zip(evidence_items, evidence_texts):
        # Re-authenticate at the V15 boundary even though the adapter already did
        # so. This keeps the engine independently fail-closed.
        validate_evidence(evidence, source, content)
        trace.append({
            'step': 'EVIDENCE_LOCATION',
            'evidence_id': evidence.evidence_id,
            'source_id': source.source_id,
            'coordinate_type': evidence.coordinate_type,
            'coordinate_value': evidence.coordinate_value,
            'start_byte': evidence.start_byte,
            'end_byte': evidence.end_byte,
            'exact_text': observed,
        })

        semantic_state, semantic_reason = _semantic_boundary_state(observed)
        if semantic_state:
            evaluations.append(PredicateEvaluation(
                prop_id, 'NOT_EVALUATED', (evidence.evidence_id,), ('SEMANTIC_BOUNDARY',)
            ))
            trace.append({'step': 'RULE', 'rule_id': rule_id, 'predicate': 'SEMANTIC_BOUNDARY', 'reason': semantic_reason})
            continue

        if claim_value.strip() == observed.strip():
            evaluations.append(PredicateEvaluation(
                prop_id, 'TRUE', (evidence.evidence_id,), ('TEXT_EXACTITY',)
            ))
            trace.append({'step': 'RULE', 'rule_id': rule_id, 'predicate': 'TEXT_EXACTITY', 'reason': 'EXACT_PROPOSITION_TEXT'})
            continue

        ev_tokens = _candidate_tokens(observed)
        overlap = len(claim_tokens & ev_tokens) / max(1, len(claim_tokens))
        ev_profile = _candidate_profile(observed)
        explicit_keys = ('dates', 'amounts', 'percentages', 'quantities')
        explicit_claim = any(claim_profile[k] for k in explicit_keys)
        value_match = all(
            not claim_profile[k] or bool(claim_profile[k] & ev_profile[k])
            for k in explicit_keys
        )
        value_conflict = any(
            claim_profile[k] and ev_profile[k] and not (claim_profile[k] & ev_profile[k])
            for k in explicit_keys
        )
        evidence_polarity = _candidate_polarity(observed)
        threshold = 0.55 if explicit_claim else 0.70

        if overlap >= threshold and value_match and claim_polarity == evidence_polarity:
            evaluations.append(PredicateEvaluation(
                prop_id, 'TRUE', (evidence.evidence_id,), ('DETERMINISTIC_PROPOSITION_MATCH',)
            ))
            trace.append({
                'step': 'RULE', 'rule_id': rule_id,
                'predicate': 'DETERMINISTIC_PROPOSITION_MATCH',
                'overlap': round(overlap, 4),
                'reason': 'CORE_TERMS_AND_EXPLICIT_VALUES_AGREE',
            })
        elif overlap >= threshold and (value_conflict or claim_polarity != evidence_polarity):
            evaluations.append(PredicateEvaluation(
                prop_id, 'FALSE', (evidence.evidence_id,), ('DETERMINISTIC_CONTRADICTION',)
            ))
            trace.append({
                'step': 'RULE', 'rule_id': rule_id,
                'predicate': 'DETERMINISTIC_CONTRADICTION',
                'overlap': round(overlap, 4),
                'reason': 'MATERIAL_VALUE_OR_POLARITY_CONFLICT',
            })
        else:
            evaluations.append(PredicateEvaluation(
                prop_id, 'NOT_EVALUATED', (evidence.evidence_id,), ('INSUFFICIENT_PROPOSITION_IDENTITY',)
            ))
            trace.append({
                'step': 'RULE', 'rule_id': rule_id,
                'predicate': 'INSUFFICIENT_PROPOSITION_IDENTITY',
                'overlap': round(overlap, 4),
                'reason': 'CANDIDATE_RELEVANCE_DOES_NOT_ESTABLISH_THE_COMPLETE_PROPOSITION',
            })

    result = aggregate(prop_id, rule_id, tuple(evaluations), trace)
    return result

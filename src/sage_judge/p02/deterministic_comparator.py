"""Simple equal-information comparator: route only pre-reviewed fact records.

No model call, NLP or inferred completion. The comparator receives the same
source bytes, reviewed mapping record, ontology, policy version and completeness
witness as the semantic-admission path.
"""
from __future__ import annotations
from hashlib import sha256
from .semantic_admission import (AdmittedFact,CompletenessDomainRule,CompletenessWitness,
                                 _SUPPORTED_COMPLETENESS_RULE_VERSIONS,
                                 ReviewedMapping,SourceRecord)

def route_preapproved_fact_r10_historical(source: SourceRecord, mapping: ReviewedMapping, *,
                           policy_version: str, signature: tuple[str,...],
                           constants: dict[str,set[str]],
                           witness: CompletenessWitness | None = None) -> AdmittedFact | None:
    """Frozen R10 comparator retained for traceability; never use in current routing."""
    if not source.eligible or mapping.source_id!=source.source_id: return None
    if mapping.source_sha256!=sha256(source.content).hexdigest() or mapping.revision_id!=source.revision_id: return None
    if mapping.review_status!="SYNTHETIC_REVIEWED" or mapping.provenance!="PREDECLARED_FIXTURE_MAPPING" or not mapping.predeclared_before_model_output: return None
    if mapping.reviewer_id!="SYNTHETIC_MAPPER_01" or mapping.authority_id!="SYNTHETIC_FIXTURE_AUTHORITY": return None
    if mapping.policy_version!=policy_version or mapping.entity!=source.entity or not source.valid_from<=mapping.as_of<=source.valid_through: return None
    if mapping.polarity not in {"+","-"} or len(mapping.arguments)!=len(signature): return None
    if any(value not in constants.get(sort,set()) for value,sort in zip(mapping.arguments,signature)): return None
    if not 0<=mapping.start_byte<mapping.end_byte<=len(source.content): return None
    try: source.content[mapping.start_byte:mapping.end_byte].decode('utf-8')
    except UnicodeDecodeError: return None
    if mapping.polarity=="-" and mapping.basis=="TRUSTED_COMPLETENESS":
        if not witness or witness.review_status!="SYNTHETIC_PREDECLARED_COMPLETE" or witness.provenance!="CONTROLLED_SYNTHETIC_FIXTURE": return None
        if (witness.authority_id!="SYNTHETIC_FIXTURE_AUTHORITY" or witness.source_id!=source.source_id
            or witness.source_sha256!=source.sha256 or witness.entity!=mapping.entity
            or witness.predicate!=mapping.predicate or witness.arguments!=mapping.arguments
            or witness.valid_through<mapping.as_of): return None
    elif mapping.basis not in {"EXPLICIT_POSITIVE","EXPLICIT_NEGATION"}: return None
    if mapping.basis=="TRUSTED_COMPLETENESS" and mapping.polarity!="-": return None
    return AdmittedFact('cmp:'+mapping.mapping_id,mapping.predicate,mapping.arguments,mapping.polarity,
      source.source_id,source.sha256,source.revision_id,(mapping.start_byte,mapping.end_byte),mapping.mapping_id,policy_version)


def route_preapproved_fact(source: SourceRecord, mapping: ReviewedMapping, **kwargs) -> AdmittedFact | None:
    """Fail-closed compatibility name; current routing must use the R11 contract."""
    return None


def route_r11_preapproved_fact(source: SourceRecord, mapping: ReviewedMapping, *,
                               policy_version: str, signature: tuple[str,...],
                               constants: dict[str,set[str]],
                               trusted_mappings: dict[str,ReviewedMapping],
                               witness: CompletenessWitness | None = None,
                               domain_rule: CompletenessDomainRule | None = None) -> AdmittedFact | None:
    """Independent direct router for the stricter R11 predeclared fixture contract."""
    if trusted_mappings.get(mapping.mapping_id)!=mapping: return None
    if any(isinstance(other,ReviewedMapping) and other.mapping_id!=mapping.mapping_id
           and other.source_id==mapping.source_id and other.source_sha256==mapping.source_sha256
           and other.revision_id==mapping.revision_id and other.start_byte==mapping.start_byte
           and other.end_byte==mapping.end_byte and other.predicate==mapping.predicate
           and other.arguments==mapping.arguments and other.polarity!=mapping.polarity
           for other in trusted_mappings.values()): return None
    if mapping.basis not in {"EXPLICIT_POSITIVE","EXPLICIT_NEGATION","TRUSTED_COMPLETENESS"}: return None
    expected={"EXPLICIT_POSITIVE":"+","EXPLICIT_NEGATION":"-","TRUSTED_COMPLETENESS":"-"}
    if mapping.polarity!=expected[mapping.basis]: return None
    if not source.eligible or mapping.source_id!=source.source_id: return None
    if mapping.source_sha256!=sha256(source.content).hexdigest() or mapping.revision_id!=source.revision_id: return None
    if (mapping.review_status!="SYNTHETIC_REVIEWED" or mapping.provenance!="PREDECLARED_FIXTURE_MAPPING"
        or mapping.predeclared_before_model_output is not True or mapping.reviewer_id!="SYNTHETIC_MAPPER_01"
        or mapping.authority_id!="SYNTHETIC_FIXTURE_AUTHORITY"): return None
    if mapping.policy_version!=policy_version or mapping.entity!=source.entity: return None
    if not source.valid_from<=mapping.as_of<=source.valid_through: return None
    if len(mapping.arguments)!=len(signature) or any(v not in constants.get(sort,set()) for v,sort in zip(mapping.arguments,signature)): return None
    if not 0<=mapping.start_byte<mapping.end_byte<=len(source.content): return None
    try: source.content[mapping.start_byte:mapping.end_byte].decode('utf-8')
    except UnicodeDecodeError: return None
    if mapping.basis=="TRUSTED_COMPLETENESS":
        if not witness or not domain_rule: return None
        if (not isinstance(domain_rule.version,str) or domain_rule.version not in _SUPPORTED_COMPLETENESS_RULE_VERSIONS
            or mapping.completeness_rule_version!=domain_rule.version
            or witness.witness_id!=mapping.completeness_witness_id
            or not isinstance(domain_rule.domain_id,str) or not domain_rule.domain_id.strip()
            or domain_rule.rule_id!=mapping.completeness_rule_id): return None
        if (domain_rule.rule_id!=mapping.completeness_rule_id
            or domain_rule.review_status!="SYNTHETIC_RULE_PREDECLARED"
            or domain_rule.provenance!="PREDECLARED_SYNTHETIC_DOMAIN_RULE"
            or domain_rule.authority_id!="SYNTHETIC_DOMAIN_RULE_AUTHORITY"
            or domain_rule.exhaustive is not True
            or domain_rule.recording_accuracy_policy!="ALL_IN_SCOPE_EVENTS_RECORDED"
            or domain_rule.availability_policy!="AUTHORITATIVE_AT_QUERY_CUTOFF"
            or domain_rule.late_event_policy!="DELAYED_UPDATES_INCLUDED_THROUGH_CUTOFF"
            or domain_rule.unrecorded_event_policy!="NO_UNRECORDED_IN_SCOPE_EVENTS"
            or domain_rule.source_id!=source.source_id
            or domain_rule.source_sha256!=source.sha256
            or domain_rule.revision_id!=source.revision_id
            or domain_rule.predicate!=mapping.predicate
            or domain_rule.event_type!="receipt_received"
            or {"receipt_received":"received"}.get(domain_rule.event_type)!=domain_rule.predicate
            or domain_rule.entity!=mapping.entity
            or domain_rule.population_scope!=mapping.entity
            or not domain_rule.coverage_start<=mapping.as_of<=domain_rule.coverage_through
            or not source.valid_from<=domain_rule.coverage_start<=domain_rule.coverage_through<=source.valid_through): return None
        if (witness.domain_rule_id!=domain_rule.rule_id or witness.revision_id!=source.revision_id
            or witness.population_scope!=domain_rule.population_scope
            or witness.coverage_start!=domain_rule.coverage_start
            or witness.coverage_through!=domain_rule.coverage_through
            or witness.event_type!=domain_rule.event_type
            or witness.review_status!="SYNTHETIC_PREDECLARED_COMPLETE"
            or witness.provenance!="CONTROLLED_SYNTHETIC_FIXTURE"
            or witness.authority_id!="SYNTHETIC_FIXTURE_AUTHORITY"
            or witness.source_id!=source.source_id or witness.source_sha256!=source.sha256
            or witness.entity!=mapping.entity or witness.predicate!=mapping.predicate
            or witness.arguments!=mapping.arguments or witness.valid_through<mapping.as_of): return None
    elif mapping.completeness_rule_id is not None or mapping.completeness_witness_id is not None:
        return None
    elif mapping.basis not in {"EXPLICIT_POSITIVE", "EXPLICIT_NEGATION"}:
        return None
    return AdmittedFact('r11cmp:'+mapping.mapping_id,mapping.predicate,mapping.arguments,mapping.polarity,
      source.source_id,source.sha256,source.revision_id,(mapping.start_byte,mapping.end_byte),mapping.mapping_id,policy_version)

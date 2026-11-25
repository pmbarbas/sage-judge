"""Fail-closed boundary from untrusted proposals to reviewed, source-bound facts.

This module performs record-integrity and authorization checks only. It does not
infer source semantics from natural language. Synthetic mappings are controlled
fixtures, not independent human semantic validation.
"""
from __future__ import annotations
from dataclasses import dataclass
from hashlib import sha256
from typing import Any, Mapping

@dataclass(frozen=True)
class Citation:
    source_id: str
    start_byte: int
    end_byte: int
    source_sha256: str
    revision_id: str

@dataclass(frozen=True)
class UntrustedProposal:
    proposal_id: str
    decision: str
    citations: tuple[Citation, ...]
    claims: tuple[Mapping[str, Any], ...]
    abstention_reason: str | None = None

@dataclass(frozen=True)
class SourceRecord:
    source_id: str
    revision_id: str
    content: bytes
    entity: str
    valid_from: str
    valid_through: str
    eligible: bool = True
    @property
    def sha256(self) -> str:
        return sha256(self.content).hexdigest()

@dataclass(frozen=True)
class CompletenessWitness:
    witness_id: str
    source_id: str
    source_sha256: str
    entity: str
    predicate: str
    arguments: tuple[str, ...]
    valid_through: str
    review_status: str
    provenance: str
    authority_id: str = ""
    domain_rule_id: str | None = None
    revision_id: str | None = None
    population_scope: str | None = None
    coverage_start: str | None = None
    coverage_through: str | None = None
    event_type: str | None = None

@dataclass(frozen=True)
class CompletenessDomainRule:
    """Versioned, explicit scope and recording assumptions for a synthetic domain rule."""
    rule_id: str
    version: str
    source_id: str
    source_sha256: str
    revision_id: str
    domain_id: str
    event_type: str
    predicate: str
    entity: str
    population_scope: str
    coverage_start: str
    coverage_through: str
    exhaustive: bool
    recording_accuracy_policy: str
    availability_policy: str
    late_event_policy: str
    unrecorded_event_policy: str
    review_status: str
    provenance: str
    authority_id: str

@dataclass(frozen=True)
class ReviewedMapping:
    mapping_id: str
    source_id: str
    source_sha256: str
    revision_id: str
    start_byte: int
    end_byte: int
    predicate: str
    arguments: tuple[str, ...]
    polarity: str
    entity: str
    as_of: str
    policy_version: str
    basis: str
    review_status: str
    provenance: str
    predeclared_before_model_output: bool
    completeness_witness_id: str | None = None
    reviewer_id: str = ""
    authority_id: str = ""
    completeness_rule_id: str | None = None
    completeness_rule_version: str | None = None

@dataclass(frozen=True)
class AdmittedFact:
    fact_id: str
    predicate: str
    arguments: tuple[str, ...]
    polarity: str
    source_id: str
    source_sha256: str
    revision_id: str
    span: tuple[int, int]
    mapping_id: str
    policy_version: str

@dataclass(frozen=True)
class AdmissionResult:
    status: str
    reason: str
    facts: tuple[AdmittedFact, ...] = ()

@dataclass(frozen=True)
class CitationResult:
    status: str
    reason: str
    source_id: str | None = None
    exact_text: str | None = None

_FORBIDDEN_MODEL_FIELDS={"admitted_facts","proof_posture","policy_verdict","execution_authority",
                         "policy_patch","authority_override","action_request"}
_ALLOWED_DECISIONS={"SUPPORTED","REFUTED","REVIEW","ABSTAIN"}
_ALLOWED_BASES={"EXPLICIT_POSITIVE","EXPLICIT_NEGATION","TRUSTED_COMPLETENESS"}
_BASIS_POLARITY={"EXPLICIT_POSITIVE":"+","EXPLICIT_NEGATION":"-","TRUSTED_COMPLETENESS":"-"}
_COMPLETENESS_EVENT_PREDICATES={"receipt_received":"received"}
_SUPPORTED_COMPLETENESS_RULE_VERSIONS={"domain-completeness/1"}


def validate_model_proposal(raw: Mapping[str, Any]) -> tuple[str, UntrustedProposal | None]:
    if not isinstance(raw, Mapping): return "REJECTED_MODEL_SHAPE", None
    if _FORBIDDEN_MODEL_FIELDS.intersection(raw): return "REJECTED_TRUST_BOUNDARY_FIELD", None
    if set(raw)-{"proposal_id","decision","citations","claims","abstention_reason"}:
        return "REJECTED_UNKNOWN_MODEL_FIELD", None
    pid, decision, claims, cites = raw.get("proposal_id"), raw.get("decision"), raw.get("claims"), raw.get("citations")
    if not isinstance(pid,str) or not pid or decision not in _ALLOWED_DECISIONS or not isinstance(claims,list) or not isinstance(cites,list):
        return "REJECTED_MODEL_SHAPE", None
    if any(not isinstance(x,dict) for x in claims) or any(not isinstance(x,dict) for x in cites):
        return "REJECTED_MODEL_SHAPE", None
    parsed=[]
    for row in cites:
        if set(row)!={"source_id","start_byte","end_byte","source_sha256","revision_id"}:
            return "REJECTED_CITATION_SHAPE", None
        parsed.append(Citation(**row))
    return "UNTRUSTED_PROPOSAL_ONLY", UntrustedProposal(pid,decision,tuple(parsed),tuple(claims),raw.get("abstention_reason"))


def validate_citation(citation: Citation, sources: Mapping[str, SourceRecord]) -> CitationResult:
    src=sources.get(citation.source_id)
    if src is None: return CitationResult("REJECT","SOURCE_ID_UNKNOWN")
    if not src.eligible: return CitationResult("REJECT","SOURCE_INELIGIBLE")
    if citation.revision_id!=src.revision_id: return CitationResult("REJECT","SOURCE_REVISION_MISMATCH")
    if citation.source_sha256!=src.sha256: return CitationResult("REJECT","SOURCE_DIGEST_MISMATCH")
    if isinstance(citation.start_byte,bool) or isinstance(citation.end_byte,bool) or not isinstance(citation.start_byte,int) or not isinstance(citation.end_byte,int):
        return CitationResult("REJECT","SPAN_TYPE_INVALID")
    if not 0<=citation.start_byte<citation.end_byte<=len(src.content): return CitationResult("REJECT","SPAN_OUT_OF_BOUNDS")
    try: text=src.content[citation.start_byte:citation.end_byte].decode("utf-8")
    except UnicodeDecodeError: return CitationResult("REJECT","SPAN_MID_UTF8")
    return CitationResult("CITATION_VALID_UNADMITTED","CITATION_IS_NOT_FACT_ADMISSION",src.source_id,text)


def admit_reviewed_mapping(mapping: ReviewedMapping, sources: Mapping[str, SourceRecord], *,
                           current_policy_version: str, admission_ids: set[str],
                           predicate_signatures: Mapping[str, tuple[str,...]],
                           sort_constants: Mapping[str, set[str]],
                           trusted_mappings: Mapping[str, ReviewedMapping],
                           witnesses: Mapping[str, CompletenessWitness] | None = None,
                           completeness_rules: Mapping[str, CompletenessDomainRule] | None = None,
                           admitted_semantics: set[tuple] ) -> AdmissionResult:
    src=sources.get(mapping.source_id)
    if src is None: return AdmissionResult("NO_ADMITTED_FACTS","SOURCE_ID_UNKNOWN")
    if not src.eligible: return AdmissionResult("NO_ADMITTED_FACTS","SOURCE_INELIGIBLE")
    if (mapping.review_status!="SYNTHETIC_REVIEWED" or mapping.provenance!="PREDECLARED_FIXTURE_MAPPING"
        or mapping.predeclared_before_model_output is not True or mapping.reviewer_id!="SYNTHETIC_MAPPER_01"
        or mapping.authority_id!="SYNTHETIC_FIXTURE_AUTHORITY"):
        return AdmissionResult("NO_ADMITTED_FACTS","MAPPING_NOT_INDEPENDENTLY_AUTHORIZED")
    if not isinstance(trusted_mappings,Mapping) or trusted_mappings.get(mapping.mapping_id)!=mapping:
        return AdmissionResult("NO_ADMITTED_FACTS","MAPPING_NOT_IN_PREDECLARED_TRUSTED_REGISTRY")
    for candidate in trusted_mappings.values():
        if (isinstance(candidate,ReviewedMapping) and candidate.mapping_id!=mapping.mapping_id and candidate.source_id==mapping.source_id
            and candidate.source_sha256==mapping.source_sha256 and candidate.revision_id==mapping.revision_id
            and candidate.start_byte==mapping.start_byte and candidate.end_byte==mapping.end_byte
            and candidate.predicate==mapping.predicate and candidate.arguments==mapping.arguments
            and candidate.polarity!=mapping.polarity):
            return AdmissionResult("NO_ADMITTED_FACTS","CONTRADICTORY_PREDECLARED_MAPPING_SET")
    if mapping.policy_version!=current_policy_version: return AdmissionResult("NO_ADMITTED_FACTS","STALE_POLICY_VERSION")
    if mapping.source_sha256!=src.sha256 or mapping.revision_id!=src.revision_id:
        return AdmissionResult("NO_ADMITTED_FACTS","MAPPING_SOURCE_BINDING_MISMATCH")
    if mapping.entity!=src.entity: return AdmissionResult("NO_ADMITTED_FACTS","CROSS_ENTITY_MAPPING")
    if not src.valid_from<=mapping.as_of<=src.valid_through: return AdmissionResult("NO_ADMITTED_FACTS","SOURCE_STALE_OR_OUT_OF_WINDOW")
    if mapping.polarity not in {"+","-"} or not mapping.predicate or not mapping.arguments or any(not isinstance(x,str) or not x for x in mapping.arguments):
        return AdmissionResult("NO_ADMITTED_FACTS","TYPED_FACT_INVALID")
    if mapping.basis not in _ALLOWED_BASES or _BASIS_POLARITY.get(mapping.basis)!=mapping.polarity:
        return AdmissionResult("NO_ADMITTED_FACTS","BASIS_POLARITY_MISMATCH")
    signature=predicate_signatures.get(mapping.predicate)
    if signature is None: return AdmissionResult("NO_ADMITTED_FACTS","ONTOLOGY_PREDICATE_UNKNOWN")
    if len(signature)!=len(mapping.arguments): return AdmissionResult("NO_ADMITTED_FACTS","ONTOLOGY_ARITY_MISMATCH")
    if any(value not in sort_constants.get(sort,set()) for sort,value in zip(signature,mapping.arguments)):
        return AdmissionResult("NO_ADMITTED_FACTS","ONTOLOGY_SYMBOLIC_TYPE_MISMATCH")
    cit=validate_citation(Citation(mapping.source_id,mapping.start_byte,mapping.end_byte,mapping.source_sha256,mapping.revision_id),sources)
    if cit.status!="CITATION_VALID_UNADMITTED": return AdmissionResult("NO_ADMITTED_FACTS",cit.reason)
    if mapping.basis=="TRUSTED_COMPLETENESS":
        rule=(completeness_rules or {}).get(mapping.completeness_rule_id or "")
        witness=(witnesses or {}).get(mapping.completeness_witness_id or "")
        if not rule: return AdmissionResult("NO_ADMITTED_FACTS","COMPLETENESS_DOMAIN_RULE_MISSING")
        if not witness: return AdmissionResult("NO_ADMITTED_FACTS","COMPLETENESS_WITNESS_MISSING")
        if (not isinstance(rule.version,str) or rule.version not in _SUPPORTED_COMPLETENESS_RULE_VERSIONS
            or mapping.completeness_rule_version!=rule.version):
            return AdmissionResult("NO_ADMITTED_FACTS","COMPLETENESS_RULE_VERSION_UNBOUND_OR_UNSUPPORTED")
        if witness.witness_id!=mapping.completeness_witness_id:
            return AdmissionResult("NO_ADMITTED_FACTS","COMPLETENESS_WITNESS_IDENTITY_MISMATCH")
        if (rule.review_status!="SYNTHETIC_RULE_PREDECLARED" or rule.provenance!="PREDECLARED_SYNTHETIC_DOMAIN_RULE"
            or rule.authority_id!="SYNTHETIC_DOMAIN_RULE_AUTHORITY" or rule.exhaustive is not True
            or rule.recording_accuracy_policy!="ALL_IN_SCOPE_EVENTS_RECORDED"
            or rule.availability_policy!="AUTHORITATIVE_AT_QUERY_CUTOFF"
            or rule.late_event_policy!="DELAYED_UPDATES_INCLUDED_THROUGH_CUTOFF"
            or rule.unrecorded_event_policy!="NO_UNRECORDED_IN_SCOPE_EVENTS"):
            return AdmissionResult("NO_ADMITTED_FACTS","COMPLETENESS_DOMAIN_RULE_NOT_QUALIFIED")
        if (rule.rule_id!=mapping.completeness_rule_id or rule.source_id!=src.source_id
            or rule.source_sha256!=src.sha256 or rule.revision_id!=src.revision_id
            or rule.predicate!=mapping.predicate or rule.entity!=mapping.entity
            or rule.population_scope!=mapping.entity or not isinstance(rule.domain_id,str) or not rule.domain_id.strip()
            or rule.rule_id!=mapping.completeness_rule_id
            or _COMPLETENESS_EVENT_PREDICATES.get(rule.event_type)!=rule.predicate
            or not rule.coverage_start<=mapping.as_of<=rule.coverage_through
            or not src.valid_from<=rule.coverage_start<=rule.coverage_through<=src.valid_through):
            return AdmissionResult("NO_ADMITTED_FACTS","COMPLETENESS_DOMAIN_RULE_SCOPE_MISMATCH")
        if (witness.review_status!="SYNTHETIC_PREDECLARED_COMPLETE" or witness.provenance!="CONTROLLED_SYNTHETIC_FIXTURE"
            or witness.source_id!=src.source_id or witness.source_sha256!=src.sha256 or witness.entity!=mapping.entity
            or witness.predicate!=mapping.predicate or witness.arguments!=mapping.arguments
            or witness.valid_through<mapping.as_of or witness.authority_id!="SYNTHETIC_FIXTURE_AUTHORITY"
            or witness.domain_rule_id!=rule.rule_id or witness.revision_id!=src.revision_id
            or witness.population_scope!=rule.population_scope or witness.coverage_start!=rule.coverage_start
            or witness.coverage_through!=rule.coverage_through or witness.event_type!=rule.event_type):
            return AdmissionResult("NO_ADMITTED_FACTS","COMPLETENESS_WITNESS_SCOPE_MISMATCH")
    if mapping.basis!="TRUSTED_COMPLETENESS" and (mapping.completeness_rule_id is not None or mapping.completeness_witness_id is not None or mapping.completeness_rule_version is not None):
        return AdmissionResult("NO_ADMITTED_FACTS","UNEXPECTED_COMPLETENESS_BINDING")
    semantic_prefix=(src.source_id,src.sha256,src.revision_id,mapping.start_byte,mapping.end_byte,
                     mapping.predicate,mapping.arguments)
    if any(isinstance(item,tuple) and len(item)==len(semantic_prefix)+1 and item[:-1]==semantic_prefix
           for item in admitted_semantics):
        prior=next(item[-1] for item in admitted_semantics
                   if isinstance(item,tuple) and len(item)==len(semantic_prefix)+1 and item[:-1]==semantic_prefix)
        reason="CONTRADICTORY_MAPPING_FOR_SAME_SOURCE_SPAN" if prior!=mapping.polarity else "DUPLICATE_SEMANTIC_MAPPING"
        return AdmissionResult("NO_ADMITTED_FACTS",reason)
    if mapping.mapping_id in admission_ids: return AdmissionResult("NO_ADMITTED_FACTS","DUPLICATE_ADMISSION")
    fact_id="fact:"+mapping.mapping_id
    fact=AdmittedFact(fact_id,mapping.predicate,mapping.arguments,mapping.polarity,src.source_id,src.sha256,
                      src.revision_id,(mapping.start_byte,mapping.end_byte),mapping.mapping_id,current_policy_version)
    admission_ids.add(mapping.mapping_id)
    admitted_semantics.add(semantic_prefix+(mapping.polarity,))
    return AdmissionResult("ADMITTED_FOR_FORMAL_EVALUATION","INDEPENDENT_MAPPING_AND_SOURCE_BINDING_VALID",(fact,))


def no_mapping_result() -> AdmissionResult:
    return AdmissionResult("NO_ADMITTED_FACTS","HOLD_NO_ELIGIBLE_MAPPING")


def policy_verdict(proof_posture: str, *, policy_version: str, expected_policy_version: str,
                   posture_map: Mapping[str,str]) -> tuple[str,str]:
    if policy_version!=expected_policy_version: return "REVIEW","STALE_POLICY_VERSION"
    if proof_posture not in {"SUPPORTED","REFUTED","BOTH","UNKNOWN"}: return "REVIEW","P01_POSTURE_INVALID"
    verdict=posture_map.get(proof_posture)
    if verdict not in {"KEEP","REVIEW","REJECT","HOLD"}: return "REVIEW","POLICY_MAPPING_INVALID"
    return verdict,"POLICY_APPLIED_TO_P01_POSTURE"


def execution_authority(*, explicit_grant: Mapping[str,Any] | None) -> str:
    """Proposal, evidence and proof never grant action authority."""
    if not isinstance(explicit_grant,Mapping): return "NOT_AUTHORIZED"
    if explicit_grant.get("status")!="AUTHORIZED" or explicit_grant.get("issuer")!="TRUSTED_EXECUTION_AUTHORITY":
        return "NOT_AUTHORIZED"
    return "AUTHORIZED_BY_SEPARATE_GRANT"

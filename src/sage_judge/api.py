"""Offline, deterministic API. It does not interpret natural language."""
from __future__ import annotations
from dataclasses import asdict
import hashlib, json
from datetime import date
from pathlib import Path
from typing import Any, Mapping

from .errors import AdjudicationError
from .p01.canonical import canonical_bytes, digest_object
from .p01.errors import EvaluationState, ValidatorResult, P01Error
from .p01.evaluate import evaluate_complete
from .p01.proof import forest_for_roots, check_proof_forest
from .p01.registry import TrustedRegistry
from .p01.sve import build_sve, validate_sve
from .p01.typed_ir import Atom, parse_theory, validate_atom
from . import __version__
from .p02.semantic_admission import (CompletenessDomainRule, CompletenessWitness,
    ReviewedMapping, SourceRecord, admit_reviewed_mapping, validate_model_proposal)

API_VERSION="sage-judge-api/0.3"
RECORD_VERSION="sage-judge-decision/0.3"
MAX_BYTES=2_000_000

def _sha(raw: bytes) -> str: return hashlib.sha256(raw).hexdigest()
def _canonical_hash(value: Any) -> str: return _sha(canonical_bytes(value))
def _fail(code: str): raise AdjudicationError(code)

def _validate_inputs(bundle: Mapping[str,Any], trusted_registry: Mapping[str,Any], policy: Mapping[str,Any], limits: Mapping[str,Any]):
    if not all(isinstance(x,Mapping) for x in (bundle,trusted_registry,policy,limits)): _fail("INPUTS_MUST_BE_OBJECTS")
    if len(canonical_bytes(bundle))+len(canonical_bytes(trusted_registry))+len(canonical_bytes(policy))>MAX_BYTES: _fail("INPUT_BYTE_LIMIT")
    if bundle.get("schema_version")!="sage-judge-bundle/0.2" or set(bundle)!={"schema_version","query","proposal"}: _fail("BUNDLE_SCHEMA_INVALID")
    if trusted_registry.get("schema_version")!="sage-judge-trust/0.2": _fail("TRUST_SCHEMA_INVALID")
    trust_fields={"schema_version","registry_id","policy_version","source_records","reviewed_mappings","mapping_routes","completeness_rules","completeness_witnesses","p01_theory"}
    if set(trusted_registry)!=trust_fields: _fail("TRUST_REGISTRY_FIELDS_INVALID")
    if policy.get("schema_version")!="sage-judge-policy/0.2" or set(policy)!={"schema_version","policy_id","expected_registry_sha256","posture_to_verdict","evidence_complete","suitability_attested"}: _fail("POLICY_SCHEMA_INVALID")
    if limits.get("max_ground_instances",100000)>100000 or limits.get("max_proof_nodes",20000)>20000: _fail("RESOURCE_LIMIT_CONFIGURATION_EXCEEDS_CAP")
    if any(isinstance(v,bool) or not isinstance(v,int) or v<1 for v in (limits.get("max_ground_instances",100000),limits.get("max_proof_nodes",20000))): _fail("RESOURCE_LIMIT_INVALID")
    if policy["expected_registry_sha256"]!=_canonical_hash(trusted_registry): _fail("TRUSTED_REGISTRY_DIGEST_MISMATCH")
    expected_postures={"SUPPORTED","REFUTED","BOTH","UNKNOWN"}
    if set(policy["posture_to_verdict"])!=expected_postures or any(v not in {"KEEP","REVIEW","HOLD"} for v in policy["posture_to_verdict"].values()): _fail("POLICY_POSTURE_MAP_INVALID")
    if not isinstance(policy["policy_id"],str) or not policy["policy_id"] or not isinstance(policy["evidence_complete"],bool) or not (policy["suitability_attested"] is None or type(policy["suitability_attested"]) is bool): _fail("POLICY_ATTESTATION_INVALID")

def _source_objects(reg: Mapping[str,Any]) -> dict[str,SourceRecord]:
    result={}
    for row in reg.get("source_records",[]):
        if set(row)!={"source_id","revision_id","content_utf8","entity","valid_from","valid_through","eligible"}: _fail("SOURCE_RECORD_SHAPE")
        if row["source_id"] in result: _fail("SOURCE_ID_DUPLICATE")
        if any(not isinstance(row[k],str) or not row[k] for k in ("source_id","revision_id","entity","valid_from","valid_through","content_utf8")) or type(row["eligible"]) is not bool: _fail("SOURCE_RECORD_VALUE_INVALID")
        try: raw=row["content_utf8"].encode("utf-8",errors="strict"); date.fromisoformat(row["valid_from"]); date.fromisoformat(row["valid_through"])
        except (AttributeError,UnicodeError,ValueError): _fail("SOURCE_TEXT_OR_DATE_INVALID")
        if row["valid_from"]>row["valid_through"]: _fail("SOURCE_WINDOW_INVALID")
        result[row["source_id"]]=SourceRecord(row["source_id"],row["revision_id"],raw,row["entity"],row["valid_from"],row["valid_through"],row["eligible"])
    if not result: _fail("SOURCE_RECORDS_EMPTY")
    return result

def _unique_ids(rows, key, error):
    if not isinstance(rows, list) or any(not isinstance(x, Mapping) or not isinstance(x.get(key), str) or not x[key] for x in rows): _fail(error)
    ids=[x[key] for x in rows]
    if len(ids)!=len(set(ids)): _fail(error)

def _route_for(routes, query, policy_version):
    if not isinstance(routes,list): _fail("TRUSTED_ROUTES_MUST_BE_STRUCTURED")
    _unique_ids(routes,"route_id","ROUTE_ID_DUPLICATE_OR_INVALID")
    matches=[]
    for route in routes:
        if set(route)!={"route_id","predicate","arguments","entity","as_of","policy_version","mapping_ids"}: _fail("TRUSTED_ROUTE_SHAPE_INVALID")
        if not isinstance(route["arguments"],list) or not all(isinstance(x,str) and x for x in route["arguments"]) or not isinstance(route["mapping_ids"],list) or not all(isinstance(x,str) and x for x in route["mapping_ids"]): _fail("TRUSTED_ROUTE_SHAPE_INVALID")
        if len(route["mapping_ids"])!=len(set(route["mapping_ids"])): _fail("TRUSTED_ROUTE_MAPPING_DUPLICATE")
        if (route["predicate"],route["arguments"],route["entity"],route["as_of"],route["policy_version"]) == (query["predicate"],query["arguments"],query["entity"],query["as_of"],policy_version): matches.append(route)
    if len(matches)!=1: _fail("TRUSTED_ROUTE_MISSING_OR_AMBIGUOUS")
    return matches[0]

def _validated_dependency_theory(query, theory_doc):
    """Validate the finite theory before using it to select evidence."""
    fields={"registry_id","version","sorts","predicates","rules","scope","ontology","population"}
    if not isinstance(theory_doc,dict) or set(theory_doc)!=fields:
        _fail("P01_THEORY_INVALID")
    for field in ("sorts","predicates"):
        rows=theory_doc[field]
        if not isinstance(rows,dict) or any(not isinstance(k,str) or not k or not isinstance(v,list) or any(not isinstance(x,str) or not x for x in v) for k,v in rows.items()):
            _fail("P01_THEORY_INVALID")
    rules=theory_doc["rules"]
    if not isinstance(rules,list) or any(not isinstance(r,dict) or not isinstance(r.get("head"),dict) or not isinstance(r.get("body"),list) or any(not isinstance(a,dict) for a in r["body"]) for r in rules):
        _fail("P01_THEORY_INVALID")
    try:
        # P01 rejects unknown predicates, bad arity/sorts, duplicate rules,
        # unsafe head variables and invalid signs before dependency analysis.
        theory=parse_theory(theory_doc)
        validate_atom(Atom("+",query["predicate"],tuple(query["arguments"])),theory.sorts,theory.predicates,allow_vars=False)
    except (P01Error,TypeError,KeyError,ValueError,AttributeError):
        _fail("P01_THEORY_INVALID")
    return theory


def _derive_demands(query, theory_doc):
    """Conservative unsigned backward closure, restricted to the query tuple.

    Both signs are considered. A reachable rule with a body-only variable
    or a differently scoped ground tuple is outside this API's fragment.
    Refuse before selecting mappings, even if that dependency has no record.
    Irrelevant other-entity rules or records do not by themselves refuse.
    """
    theory=_validated_dependency_theory(query,theory_doc)
    scope_args=tuple(query["arguments"])
    root=(query["predicate"],scope_args)
    demands={root}; pending=[root]
    by_head={}
    for rule in theory.rules:
        by_head.setdefault(rule.head.predicate,[]).append(rule)
    while pending:
        demand_pred,demand_args=pending.pop()
        for rule in by_head.get(demand_pred,[]):
            if len(rule.head.arguments)!=len(demand_args): continue
            bindings={}; compatible=True
            for term,value in zip(rule.head.arguments,demand_args):
                if term.startswith("?") and len(term)>1:
                    if term in bindings and bindings[term]!=value:
                        compatible=False; break
                    bindings[term]=value
                elif term!=value:
                    compatible=False; break
            if not compatible: continue
            for atom in rule.body:
                args=[]
                for term in atom.arguments:
                    if term.startswith("?") and len(term)>1:
                        if term not in bindings:
                            _fail("UNSUPPORTED_RULE_DEPENDENCY_UNBOUND_VARIABLE")
                        args.append(bindings[term])
                    else:
                        args.append(term)
                if tuple(args)!=scope_args:
                    _fail("UNSUPPORTED_RULE_DEPENDENCY_SCOPE")
                item=(atom.predicate,tuple(args))
                if item not in demands:
                    demands.add(item); pending.append(item)
    return demands, []

def _mapping(row: Mapping[str,Any]) -> ReviewedMapping:
    allowed=set(ReviewedMapping.__dataclass_fields__)
    if not isinstance(row,Mapping) or set(row)-allowed: _fail("MAPPING_FIELDS_INVALID")
    required={name for name,field in ReviewedMapping.__dataclass_fields__.items() if field.default is field.default_factory}
    if required-set(row): _fail("MAPPING_FIELDS_MISSING")
    try:
        values=dict(row)
        values["arguments"]=tuple(values["arguments"])
        return ReviewedMapping(**values)
    except (TypeError,KeyError): _fail("MAPPING_FIELDS_MISSING")

def _p01_registry(reg: Mapping[str,Any], facts, sources, policy: Mapping[str,Any]) -> TrustedRegistry:
    theory_doc=dict(reg["p01_theory"])
    if set(theory_doc)!={"registry_id","version","sorts","predicates","rules","scope","ontology","population"}: _fail("P01_THEORY_FIELDS_INVALID")
    rows=[]; admissions=[]; mappings=[]; source_rows=[]; source_bytes={}
    for sid,src in sorted(sources.items()):
        source_rows.append({"source_id":sid,"revision_id":src.revision_id,"path":"embedded/"+sid,
            "sha256":src.sha256,"eligible":src.eligible,"span":{"start":0,"end":len(src.content) }})
        source_bytes[sid]=src.content
    for fact in facts:
        fid=fact.fact_id; aid="admission:"+fact.mapping_id
        rows.append({"fact_id":fid,"atom":{"sign":fact.polarity,"predicate":fact.predicate,"arguments":list(fact.arguments)},
            "admission_id":aid,"source_id":fact.source_id,"mapping_id":fact.mapping_id})
        admissions.append({"admission_id":aid,"fact_id":fid,"status":"ACCEPTED"})
        mappings.append({"mapping_id":fact.mapping_id,"status":"APPROVED","predicate":fact.predicate})
    data={**theory_doc,"facts":rows,"admissions":admissions,"sources":source_rows,"mappings":mappings,"completeness_witnesses":[]}
    data["policy"]={"policy_id":policy["policy_id"],"posture_to_verdict":dict(policy["posture_to_verdict"])}
    theory=parse_theory(data)
    scope=data["scope"]
    version={"registry_id":data["registry_id"],"registry_digest":"sha256:"+_canonical_hash(reg),
      "theory_digest":digest_object({"sorts":data["sorts"],"predicates":data["predicates"],"rules":data["rules"]}),
      "source_snapshot_digest":digest_object([{ "source_id":s["source_id"],"revision_id":s["revision_id"],"sha256":s["sha256"],"eligible":s["eligible"],"span":s["span"]} for s in sorted(source_rows,key=lambda x:x["source_id"])]),
      "admission_registry_digest":digest_object({"facts":rows,"admissions":admissions,"mappings":mappings}),
      "scope_digest":digest_object(scope),"policy_digest":digest_object(data["policy"]),
      "population_digest":digest_object(data.get("population",[])),"mapping_registry_digest":digest_object(mappings),
      "ontology_digest":digest_object(data.get("ontology",{"id":"fixture-ontology-v1"})),
      "compiler_id":"sage-judge/"+__version__,"evaluator_id":"sage-judge-p01/0.2.0",
      "verifier_contract_version":"SJ01-PVC/1.1","schema_version":"SJ01-SVE/1.1"}
    return TrustedRegistry(Path("."),"sha256:"+_canonical_hash(reg),data,theory,version,
      {x["fact_id"]:x for x in rows},{x["source_id"]:x for x in source_rows},
      {x["admission_id"]:x for x in admissions},{x["mapping_id"]:x for x in mappings},source_bytes)

def adjudicate(bundle: Mapping[str,Any], trusted_registry: Mapping[str,Any], policy: Mapping[str,Any], limits: Mapping[str,Any]) -> dict[str,Any]:
    """Return a versioned decision from predeclared source mappings and real P01 reasoning."""
    _validate_inputs(bundle,trusted_registry,policy,limits)
    query=bundle["query"]
    if not isinstance(query,dict) or set(query)!={"predicate","arguments","as_of","entity"}: _fail("QUERY_SHAPE_INVALID")
    if not isinstance(query["predicate"],str) or not isinstance(query["arguments"],list) or not all(isinstance(v,str) for v in query["arguments"]): _fail("QUERY_VALUE_INVALID")
    if not isinstance(query["entity"],str) or not query["entity"] or not isinstance(query["as_of"],str): _fail("QUERY_SCOPE_INVALID")
    try: date.fromisoformat(query["as_of"])
    except ValueError: _fail("QUERY_DATE_INVALID")
    sources=_source_objects(trusted_registry)
    status,proposal=validate_model_proposal(bundle["proposal"])
    if proposal is None: _fail(status)
    for citation in proposal.citations:
        if citation.source_id not in sources or not validate_citation_result(citation,sources): _fail("PROPOSAL_CITATION_INVALID")
    _unique_ids(trusted_registry.get("source_records"),"source_id","SOURCE_ID_DUPLICATE_OR_INVALID")
    raw_mappings=trusted_registry.get("reviewed_mappings",[])
    _unique_ids(raw_mappings,"mapping_id","MAPPING_ID_DUPLICATE_OR_INVALID")
    _unique_ids(trusted_registry.get("completeness_rules",[]),"rule_id","COMPLETENESS_RULE_ID_DUPLICATE_OR_INVALID")
    _unique_ids(trusted_registry.get("completeness_witnesses",[]),"witness_id","COMPLETENESS_WITNESS_ID_DUPLICATE_OR_INVALID")
    mappings=[_mapping(row) for row in raw_mappings]
    trusted={m.mapping_id:m for m in mappings}
    route=_route_for(trusted_registry.get("mapping_routes"),query,trusted_registry["policy_version"])
    provided=route["mapping_ids"]
    demands, closure_reasons=_derive_demands(query,trusted_registry["p01_theory"])
    expected_ids=sorted(m.mapping_id for m in mappings if (m.predicate,m.arguments) in demands and m.entity==query["entity"] and m.as_of==query["as_of"] and m.policy_version==trusted_registry["policy_version"])
    selected=expected_ids
    route_mismatch=(set(provided)!=set(expected_ids) or len(provided)!=len(expected_ids))
    try:
        witnesses={x["witness_id"]:CompletenessWitness(**{**x,"arguments":tuple(x["arguments"])}) for x in trusted_registry.get("completeness_witnesses",[])}
        rules={x["rule_id"]:CompletenessDomainRule(**x) for x in trusted_registry.get("completeness_rules",[])}
    except (TypeError,KeyError): _fail("COMPLETENESS_RECORD_SHAPE_INVALID")
    facts=[]; ids=set(); semantics=set(); coverage=[]
    for mid in selected:
        m=trusted.get(mid)
        if m is None: _fail("TRUSTED_ROUTE_MAPPING_UNKNOWN")
        if m.arguments!=tuple(query["arguments"]): _fail("TRUSTED_ROUTE_QUERY_MISMATCH")
        if m.entity!=query["entity"] or m.as_of!=query["as_of"]: _fail("TRUSTED_ROUTE_SCOPE_MISMATCH")
        result=admit_reviewed_mapping(m,sources,current_policy_version=trusted_registry["policy_version"],
          admission_ids=ids,predicate_signatures=trusted_registry["p01_theory"]["predicates"],
          sort_constants=trusted_registry["p01_theory"]["sorts"],trusted_mappings=trusted,
          witnesses=witnesses,completeness_rules=rules,admitted_semantics=semantics)
        if result.status=="ADMITTED_FOR_FORMAL_EVALUATION":
            facts.extend(result.facts); coverage.append({"mapping_id":mid,"status":"ADMITTED","reason":result.reason})
        else: coverage.append({"mapping_id":mid,"status":"REJECTED","reason":result.reason})
    if not set(policy["posture_to_verdict"]) >= {"SUPPORTED","REFUTED","BOTH","UNKNOWN"}: _fail("POLICY_POSTURE_MAP_INCOMPLETE")
    registry=_p01_registry(trusted_registry,facts,sources,policy)
    atom=Atom("+",query["predicate"],tuple(query["arguments"]))
    result=evaluate_complete(registry.theory,atom,max_ground_instances=limits.get("max_ground_instances",100000),max_proof_nodes=limits.get("max_proof_nodes",20000))
    if result.state!=EvaluationState.COMPLETE or result.posture is None: _fail("P01_EVALUATION_"+result.state.value)
    sve=build_sve(registry,atom,sve_id="decision:"+_canonical_hash(bundle)[:16],max_ground_instances=limits.get("max_ground_instances",100000),max_proof_nodes=limits.get("max_proof_nodes",20000))
    checked=validate_sve(sve,registry,max_ground_instances=limits.get("max_ground_instances",100000),max_proof_nodes=limits.get("max_proof_nodes",20000))
    if checked.validator_result!=ValidatorResult.VALID: _fail("P01_PROOF_OR_SVE_INVALID")
    posture=result.posture.value
    verdict=policy["posture_to_verdict"][posture] if policy["evidence_complete"] else "REVIEW"
    if posture in {"BOTH","UNKNOWN"} or policy["suitability_attested"] is not True: verdict="REVIEW"
    excluded=[{"mapping_id":m.mapping_id,"reason":"OUTSIDE_QUERY_DEPENDENCY_CLOSURE_OR_TRUSTED_SCOPE"} for m in mappings if m.mapping_id not in set(expected_ids)]
    coverage_complete=(not route_mismatch and not closure_reasons and all(x["status"]=="ADMITTED" for x in coverage))
    if not coverage_complete or proposal.decision in {"ABSTAIN","REVIEW"}: verdict="REVIEW"
    # Citations are validated diagnostics only. They cannot select or suppress trusted mappings.
    record={"record_version":RECORD_VERSION,"api_version":API_VERSION,"bundle_sha256":_canonical_hash(bundle),
      "trusted_registry_sha256":_canonical_hash(trusted_registry),"policy_sha256":_canonical_hash(policy),
      "limits":dict(limits),
      "query":query,"proposal_status":"UNTRUSTED_PROPOSAL_ONLY","proposal_decision_advisory":proposal.decision,
      "coverage":{"snapshot_sha256":_canonical_hash(trusted_registry),"route_id":route["route_id"],"route_query":{"predicate":route["predicate"],"arguments":route["arguments"],"entity":route["entity"],"as_of":route["as_of"]},"rule_demand_closure":[{"predicate":p,"arguments":list(a)} for p,a in sorted(demands)],"expected_mapping_ids":expected_ids,"provided_route_mapping_ids":provided,"considered_mapping_ids":selected,"mapping_results":coverage,"excluded_mapping_ids":[x["mapping_id"] for x in excluded],"exclusion_reasons":excluded,"route_reconciliation":"PASS" if not route_mismatch else "FAIL_MISSING_OR_EXTRA_IDS","closure_reasons":closure_reasons,"status":"COMPLETE" if coverage_complete else "INCOMPLETE"},
      "admitted_facts":[asdict(f) for f in facts],
      "proof_posture":posture,"business_verdict":verdict,"execution_authority":"NONE",
      "p01_sve":sve,"p01_validator_result":checked.validator_result.value}
    record=json.loads(json.dumps(record,sort_keys=True,ensure_ascii=False))
    record["record_sha256"]=_canonical_hash(record)
    return record

def validate_citation_result(citation,sources):
    from .p02.semantic_admission import validate_citation
    return validate_citation(citation,sources).status=="CITATION_VALID_UNADMITTED"

def verify(record: Mapping[str,Any], trusted_registry: Mapping[str,Any], bundle: Mapping[str,Any], policy: Mapping[str,Any]) -> dict[str,Any]:
    """Recompute integrity, admission and P01 proof posture from exact inputs."""
    if not isinstance(record,dict) or record.get("record_version")!=RECORD_VERSION: return {"valid":False,"reason":"RECORD_VERSION_INVALID"}
    claimed=record.get("record_sha256"); unsigned=dict(record); unsigned.pop("record_sha256",None)
    if claimed!=_canonical_hash(unsigned): return {"valid":False,"reason":"DECISION_DIGEST_MISMATCH"}
    if record.get("trusted_registry_sha256")!=_canonical_hash(trusted_registry): return {"valid":False,"reason":"TRUSTED_REGISTRY_CHANGED"}
    if record.get("bundle_sha256")!=_canonical_hash(bundle) or record.get("policy_sha256")!=_canonical_hash(policy): return {"valid":False,"reason":"INPUT_SNAPSHOT_CHANGED"}
    try: fresh=adjudicate(bundle,trusted_registry,policy,record.get("limits",{}))
    except (AdjudicationError,KeyError,TypeError,ValueError) as exc: return {"valid":False,"reason":str(exc)}
    if fresh!=record: return {"valid":False,"reason":"RECOMPUTED_DECISION_MISMATCH"}
    return {"valid":True,"reason":"INPUTS_RECOMPUTED_AND_P01_SVE_VALID","proof_posture":fresh["proof_posture"]}

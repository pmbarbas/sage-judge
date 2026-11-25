"""Versioned SVE construction and validation against trusted local registries."""

from __future__ import annotations

import copy
from dataclasses import dataclass
from typing import Any, Mapping

from .canonical import digest_object, sve_digest
from .errors import (EvaluationState, InvalidInput, ProofBasisState,
                     ProofPosture, ValidatorResult)
from .evaluate import EvaluationResult, evaluate_complete
from .proof import check_proof_forest, forest_for_roots
from .registry import TrustedRegistry
from .typed_ir import Atom, parse_atom, validate_atom


TOP_FIELDS = {
    "schema_version", "sve_id", "created_at", "theory_id", "query", "scope",
    "version_tuple", "candidate_and_admission_refs", "proof_forest",
    "support_proof_roots", "refutation_proof_roots", "proof_basis_state",
    "proof_posture", "evaluation_state", "policy_verdict", "assumptions",
    "unknowns_and_errors", "dependency_closure", "boundary_oracle_results",
    "history", "integrity", "check_result"
}


@dataclass(frozen=True)
class SVEValidation:
    validator_result: ValidatorResult
    evaluation_state: EvaluationState
    proof_posture: ProofPosture | None
    policy_verdict: str | None
    reason_codes: tuple[str, ...]
    evaluation: EvaluationResult | None = None


def query_atom(query: Mapping[str, Any]) -> Atom:
    if set(query) != {"predicate_id", "typed_arguments", "sign_scope", "query_id"}:
        raise InvalidInput("QUERY_FIELDS_INVALID")
    if query["sign_scope"] != "BOTH_SIGNS":
        raise InvalidInput("QUERY_SIGN_SCOPE_UNSUPPORTED")
    args = query["typed_arguments"]
    if not isinstance(args, list) or not all(isinstance(item, dict) and set(item) == {"type", "value"}
                                             and isinstance(item["value"], str) for item in args):
        raise InvalidInput("QUERY_ARGUMENTS_INVALID")
    return Atom("+", query["predicate_id"], tuple(item["value"] for item in args))


def build_sve(registry: TrustedRegistry, query: Atom, *, sve_id: str,
              created_at: str = "2026-11-22T12:00:00Z",
              max_ground_instances: int = 100_000,
              max_proof_nodes: int = 20_000) -> dict[str, Any]:
    evaluation = evaluate_complete(registry.theory, query,
                                   max_ground_instances=max_ground_instances,
                                   max_proof_nodes=max_proof_nodes)
    if evaluation.state != EvaluationState.COMPLETE or evaluation.posture is None:
        raise InvalidInput("CANNOT_BUILD_SVE_WITHOUT_COMPLETE_EVALUATION")
    plus_trees, minus_trees = evaluation.roots_for(query)
    scope_digest = registry.version_tuple["scope_digest"]
    forest_plus = forest_for_roots(plus_trees, registry, scope_digest)
    forest_minus = forest_for_roots(minus_trees, registry, scope_digest)
    all_nodes = {node["node_id"]: node for node in forest_plus["nodes"] + forest_minus["nodes"]}
    policy_map = registry.policy["posture_to_verdict"]
    sve: dict[str, Any] = {
        "schema_version": "SJ01-SVE/1.1",
        "sve_id": sve_id,
        "created_at": created_at,
        "theory_id": registry.version_tuple["theory_digest"],
        "query": {"predicate_id": query.predicate,
                  "typed_arguments": [{"type": registry.theory.predicates[query.predicate][i], "value": arg}
                                      for i, arg in enumerate(query.arguments)],
                  "sign_scope": "BOTH_SIGNS", "query_id": "query:" + query.key()},
        "scope": copy.deepcopy(dict(registry.scope)),
        "version_tuple": dict(registry.version_tuple),
        "candidate_and_admission_refs": {
            "candidates": [],
            "admissions": sorted({fact["admission_id"] for atom in registry.theory.facts
                                   if atom.predicate == query.predicate
                                   for fact in registry.theory.fact_records.get(atom.key(), ())})
        },
        "proof_forest": {"nodes": [all_nodes[key] for key in sorted(all_nodes)]},
        "support_proof_roots": forest_plus["root_ids"],
        "refutation_proof_roots": forest_minus["root_ids"],
        "proof_basis_state": evaluation.proof_basis_state.value,
        "proof_posture": evaluation.posture.value,
        "evaluation_state": evaluation.state.value,
        "policy_verdict": {"policy_id": registry.policy["policy_id"],
                            "verdict": policy_map[evaluation.posture.value]},
        "assumptions": [],
        "unknowns_and_errors": [],
        "dependency_closure": {"status": "UNKNOWN", "universe_digest": None,
                                "potential_dependencies": [], "closure_attestation_ref": None,
                                "algorithm_contract_id": "full-recompute-fallback/1"},
        "boundary_oracle_results": [],
        "history": {"record_kind": "ORIGINAL", "supersedes_current_view_only": False,
                    "immutable": True},
        "integrity": {"canonicalization_id": "SJ01-CJSON/1", "object_digest": "",
                      "referenced_snapshot_digests": [registry.raw_digest,
                                                       registry.version_tuple["source_snapshot_digest"]]},
        "check_result": {"validator_result": "VALID", "checker_contract_version": "SJ01-PVC/1.1",
                         "checked_at": created_at, "trace_id": "local-reference", "reason_codes": []}
    }
    sve["integrity"]["object_digest"] = sve_digest(sve)
    return sve


def validate_sve(sve: Mapping[str, Any], registry: TrustedRegistry, *,
                 max_ground_instances: int = 100_000,
                 max_proof_nodes: int = 20_000) -> SVEValidation:
    """Recompute digest, proof roots and posture; ignore the SVE's claimed check result."""
    try:
        if not isinstance(sve, dict) or set(sve) != TOP_FIELDS:
            raise InvalidInput("SVE_TOP_LEVEL_FIELDS_INVALID")
        if sve["schema_version"] != "SJ01-SVE/1.1":
            raise InvalidInput("SVE_SCHEMA_VERSION_UNSUPPORTED")
        if not isinstance(sve["sve_id"], str) or not sve["sve_id"]:
            raise InvalidInput("SVE_ID_INVALID")
        if sve["version_tuple"] != dict(registry.version_tuple):
            raise InvalidInput("SVE_VERSION_TUPLE_MISMATCH")
        if sve["theory_id"] != registry.version_tuple["theory_digest"]:
            raise InvalidInput("SVE_THEORY_ID_MISMATCH")
        if sve["scope"] != dict(registry.scope):
            raise InvalidInput("SVE_SCOPE_MISMATCH")
        if not isinstance(sve["integrity"], dict) or sve["integrity"].get("canonicalization_id") != "SJ01-CJSON/1":
            raise InvalidInput("CANONICALIZATION_ID_INVALID")
        if sve["integrity"].get("object_digest") != sve_digest(dict(sve)):
            raise InvalidInput("SVE_DIGEST_MISMATCH")
        if registry.raw_digest not in sve["integrity"].get("referenced_snapshot_digests", []):
            raise InvalidInput("TRUSTED_REGISTRY_DIGEST_NOT_BOUND")
        if sve["evaluation_state"] not in {state.value for state in EvaluationState}:
            raise InvalidInput("EVALUATION_STATE_INVALID")
        if sve["proof_basis_state"] not in {state.value for state in ProofBasisState}:
            raise InvalidInput("PROOF_BASIS_STATE_INVALID")
        if sve["proof_posture"] not in {state.value for state in ProofPosture}:
            raise InvalidInput("PROOF_POSTURE_INVALID")
        if not isinstance(sve["support_proof_roots"], list) or not all(isinstance(x, str) for x in sve["support_proof_roots"]):
            raise InvalidInput("SUPPORT_ROOTS_INVALID")
        if not isinstance(sve["refutation_proof_roots"], list) or not all(isinstance(x, str) for x in sve["refutation_proof_roots"]):
            raise InvalidInput("REFUTATION_ROOTS_INVALID")
        if not isinstance(sve["proof_forest"], dict) or set(sve["proof_forest"]) != {"nodes"}:
            raise InvalidInput("PROOF_FOREST_INVALID")
        query = query_atom(sve["query"])
        validate_atom(query, registry.theory.sorts, registry.theory.predicates, allow_vars=False)
        expected_sorts = registry.theory.predicates[query.predicate]
        actual_sorts = tuple(item["type"] for item in sve["query"]["typed_arguments"])
        if actual_sorts != expected_sorts:
            raise InvalidInput("QUERY_ARGUMENT_TYPE_MISMATCH")
        if sve["query"]["query_id"] != "query:" + query.key():
            raise InvalidInput("QUERY_ID_DOES_NOT_BIND_QUERY")
        if sve["evaluation_state"] != EvaluationState.COMPLETE.value:
            raise InvalidInput("SVE_POSTURE_REQUIRES_COMPLETE_EVALUATION")
        references = sve["candidate_and_admission_refs"]
        if not isinstance(references, dict) or set(references) != {"candidates", "admissions"}:
            raise InvalidInput("CANDIDATE_ADMISSION_REFS_INVALID")
        if references["candidates"] != []:
            raise InvalidInput("UNSUPPORTED_CANDIDATE_REFERENCES")
        if not isinstance(references["admissions"], list) or not all(
                isinstance(value, str) for value in references["admissions"]):
            raise InvalidInput("ADMISSION_REFERENCES_INVALID")
        expected_admissions = sorted({fact["admission_id"] for atom in registry.theory.facts
                                      if atom.predicate == query.predicate
                                      for fact in registry.theory.fact_records.get(atom.key(), ())})
        if references["admissions"] != expected_admissions:
            raise InvalidInput("ADMISSION_REFERENCES_DISAGREE_WITH_TRUSTED_REGISTRY")
        policy_verdict = sve["policy_verdict"]
        if not isinstance(policy_verdict, dict) or set(policy_verdict) != {"policy_id", "verdict"}:
            raise InvalidInput("POLICY_VERDICT_SHAPE_INVALID")
        if policy_verdict["policy_id"] != registry.policy["policy_id"]:
            raise InvalidInput("POLICY_ID_MISMATCH")
    except (InvalidInput, KeyError, TypeError, AttributeError) as exc:
        return SVEValidation(ValidatorResult.INVALID, EvaluationState.INVALID_INPUT,
                             None, None, (str(exc),))

    roots_result, root_reasons, reachable = check_proof_forest(
        sve["proof_forest"], sve["support_proof_roots"], sve["refutation_proof_roots"],
        query, registry, registry.version_tuple["scope_digest"])
    if roots_result != ValidatorResult.VALID:
        return SVEValidation(roots_result, EvaluationState.COMPLETE, None, None,
                             root_reasons)

    evaluation = evaluate_complete(registry.theory, query,
                                   max_ground_instances=max_ground_instances,
                                   max_proof_nodes=max_proof_nodes)
    if evaluation.state != EvaluationState.COMPLETE or evaluation.posture is None:
        return SVEValidation(ValidatorResult.INDETERMINATE, evaluation.state,
                             None, None, evaluation.reason_codes, evaluation)
    plus_roots, minus_roots = evaluation.roots_for(query)
    if bool(plus_roots) != bool(sve["support_proof_roots"]):
        return SVEValidation(ValidatorResult.INVALID, EvaluationState.COMPLETE,
                             evaluation.posture, None, ("SUPPORT_WITNESS_SET_INCOMPLETE",), evaluation)
    if bool(minus_roots) != bool(sve["refutation_proof_roots"]):
        return SVEValidation(ValidatorResult.INVALID, EvaluationState.COMPLETE,
                             evaluation.posture, None, ("REFUTATION_WITNESS_SET_INCOMPLETE",), evaluation)
    try:
        claimed_posture = ProofPosture(sve["proof_posture"])
    except ValueError:
        return SVEValidation(ValidatorResult.INVALID, EvaluationState.COMPLETE,
                             evaluation.posture, None, ("PROOF_POSTURE_INVALID",), evaluation)
    if claimed_posture != evaluation.posture:
        return SVEValidation(ValidatorResult.INVALID, EvaluationState.COMPLETE,
                             evaluation.posture, None, ("CLAIMED_POSTURE_DISAGREES_WITH_COMPLETE_EVALUATION",), evaluation)
    claimed_policy = policy_verdict.get("verdict")
    expected_policy = registry.policy["posture_to_verdict"].get(evaluation.posture.value)
    if claimed_policy != expected_policy:
        return SVEValidation(ValidatorResult.INVALID, EvaluationState.COMPLETE,
                             evaluation.posture, expected_policy,
                             ("POLICY_VERDICT_DISAGREES_WITH_TRUSTED_POLICY",), evaluation)

    if sve["proof_basis_state"] == ProofBasisState.COMPLETE_ELEMENTARY_BASIS.value:
        if evaluation.proof_basis_state != ProofBasisState.COMPLETE_ELEMENTARY_BASIS:
            return SVEValidation(ValidatorResult.INDETERMINATE, EvaluationState.COMPLETE,
                                 evaluation.posture, expected_policy,
                                 ("CLAIMED_COMPLETE_PROOF_BASIS_NOT_RECOMPUTABLE_WITHIN_BUDGET",), evaluation)
        expected_plus = {node_id for node_id, node in _expected_root_nodes(evaluation, query, registry).items()
                         if parse_atom(node["conclusion"]).sign == "+"}
        expected_minus = {node_id for node_id, node in _expected_root_nodes(evaluation, query, registry).items()
                          if parse_atom(node["conclusion"]).sign == "-"}
        if set(sve["support_proof_roots"]) != expected_plus or set(sve["refutation_proof_roots"]) != expected_minus:
            return SVEValidation(ValidatorResult.INVALID, EvaluationState.COMPLETE,
                                 evaluation.posture, expected_policy,
                                 ("ELEMENTARY_PROOF_BASIS_ROOTS_MISMATCH",), evaluation)

    return SVEValidation(ValidatorResult.VALID, EvaluationState.COMPLETE,
                         evaluation.posture, expected_policy,
                         ("REGISTRY_AND_DIGEST_VALID", "PROOF_FOREST_VALID",
                          "POSTURE_RECOMPUTED_FROM_COMPLETE_FIXED_POINT"), evaluation)


def _expected_root_nodes(evaluation: EvaluationResult, query: Atom,
                         registry: TrustedRegistry) -> dict[str, dict[str, Any]]:
    plus, minus = evaluation.roots_for(query)
    forest = forest_for_roots(plus + minus, registry, registry.version_tuple["scope_digest"])
    return {node["node_id"]: node for node in forest["nodes"]
            if node["node_id"] in forest["root_ids"]}

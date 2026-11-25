"""Independent checker for individual proof roots and shared-node forests."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from .canonical import digest_object
from .errors import InvalidInput, RegistryInvalid, ValidatorResult
from .registry import TrustedRegistry
from .typed_ir import Atom, parse_atom, parse_theory, validate_atom


@dataclass(frozen=True)
class ProofCheck:
    result: ValidatorResult
    root_id: str | None
    conclusion: Atom | None
    reachable: frozenset[str]
    reason_codes: tuple[str, ...]


def _node_payload(node: Mapping[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in node.items() if key != "node_id"}


def expected_node_id(node: Mapping[str, Any]) -> str:
    return digest_object(_node_payload(node))


def forest_for_roots(roots: tuple[Any, ...], registry: TrustedRegistry,
                     scope_digest: str) -> dict[str, Any]:
    nodes: dict[str, dict[str, Any]] = {}
    def add(tree: Any) -> str:
        child_ids = [add(child) for child in tree.children]
        node: dict[str, Any] = {
            "kind": tree.kind,
            "conclusion": tree.atom.to_json(),
            "scope_digest": scope_digest,
            "version_digest": digest_object(dict(registry.version_tuple)),
        }
        if tree.kind == "admitted-premise":
            fact = registry.facts_by_id[tree.fact_id]
            source = registry.sources_by_id[fact["source_id"]]
            node.update({"fact_id": tree.fact_id, "admission_id": fact["admission_id"],
                         "source_ref": {"source_id": fact["source_id"],
                                        "revision_id": source["revision_id"],
                                        "sha256": source["sha256"],
                                        "span": dict(source["span"])}})
        elif tree.kind == "rule-application":
            node.update({"rule_id": tree.rule_id, "substitution": dict(sorted((tree.substitution or {}).items())),
                         "premise_ids": child_ids})
        else:
            raise InvalidInput(f"UNSUPPORTED_PROOF_NODE_KIND:{tree.kind}")
        node_id = expected_node_id(node)
        node["node_id"] = node_id
        nodes[node_id] = node
        return node_id
    root_ids = [add(root) for root in roots]
    return {"nodes": [nodes[key] for key in sorted(nodes)], "root_ids": root_ids}


def check_proof_root(root_id: str, nodes: Mapping[str, Mapping[str, Any]],
                     query: Atom, registry: TrustedRegistry,
                     scope_digest: str, version_digest: str) -> ProofCheck:
    active: set[str] = set()
    visited: set[str] = set()
    conclusions: dict[str, Atom] = {}

    def visit(node_id: str) -> Atom:
        if node_id in active:
            raise InvalidInput("PROOF_DAG_CYCLE")
        if node_id in visited:
            return conclusions[node_id]
        node = nodes.get(node_id)
        if node is None:
            raise InvalidInput("PROOF_NODE_MISSING")
        if node.get("node_id") != node_id:
            raise InvalidInput("PROOF_NODE_ID_REFERENCE_MISMATCH")
        if node.get("scope_digest") != scope_digest:
            raise InvalidInput("PROOF_SCOPE_MISMATCH")
        if node.get("version_digest") != version_digest:
            raise InvalidInput("PROOF_VERSION_MISMATCH")
        atom = parse_atom(node.get("conclusion", {}))
        validate_atom(atom, registry.theory.sorts, registry.theory.predicates, allow_vars=False)
        active.add(node_id)
        kind = node.get("kind")
        if kind == "admitted-premise":
            allowed = {"node_id", "kind", "conclusion", "scope_digest", "version_digest",
                       "fact_id", "admission_id", "source_ref"}
            if set(node) != allowed:
                raise InvalidInput("PREMISE_NODE_FIELDS_INVALID")
            fact = registry.facts_by_id.get(node["fact_id"])
            admission = registry.admissions_by_id.get(node["admission_id"])
            if not fact or not admission or admission.get("status") != "ACCEPTED":
                raise InvalidInput("UNTRUSTED_OR_UNADMITTED_PREMISE")
            if fact.get("admission_id") != node["admission_id"] or parse_atom(fact["atom"]) != atom:
                raise InvalidInput("PREMISE_ATOM_OR_ADMISSION_MISMATCH")
            source = registry.sources_by_id.get(fact["source_id"])
            if not source or source.get("eligible") is not True:
                raise InvalidInput("SOURCE_NOT_ELIGIBLE")
            expected_source_ref = {"source_id": fact["source_id"],
                                   "revision_id": source["revision_id"],
                                   "sha256": source["sha256"],
                                   "span": dict(source["span"])}
            if node["source_ref"] != expected_source_ref:
                raise InvalidInput("SOURCE_REFERENCE_MISMATCH")
            mapping = registry.mappings_by_id.get(fact["mapping_id"])
            if not mapping or mapping.get("status") != "APPROVED":
                raise InvalidInput("MAPPING_NOT_APPROVED")
            if fact["fact_id"] not in registry.theory.fact_ids.get(atom.key(), ()):
                raise InvalidInput("PREMISE_NOT_IN_ADMITTED_THEORY")
        elif kind == "rule-application":
            allowed = {"node_id", "kind", "conclusion", "scope_digest", "version_digest",
                       "rule_id", "substitution", "premise_ids"}
            if set(node) != allowed:
                raise InvalidInput("RULE_NODE_FIELDS_INVALID")
            rule = next((r for r in registry.theory.rules if r.rule_id == node.get("rule_id")), None)
            if rule is None:
                raise InvalidInput("RULE_ID_NOT_IN_TRUSTED_REGISTRY")
            premise_ids = node["premise_ids"]
            if not isinstance(premise_ids, list) or len(premise_ids) != len(rule.body):
                raise InvalidInput("RULE_PREMISE_ARITY_MISMATCH")
            child_atoms = [visit(pid) for pid in premise_ids]
            substitution = node.get("substitution")
            if not isinstance(substitution, dict):
                raise InvalidInput("RULE_SUBSTITUTION_INVALID")
            if set(substitution) != _rule_variables(rule):
                raise InvalidInput("RULE_SUBSTITUTION_VARIABLE_SET_MISMATCH")
            for variable, value in substitution.items():
                if not isinstance(value, str):
                    raise InvalidInput("RULE_SUBSTITUTION_VALUE_INVALID")
            expected_head = _instantiate(rule.head, substitution)
            expected_body = [_instantiate(body, substitution) for body in rule.body]
            if atom != expected_head or child_atoms != expected_body:
                raise InvalidInput("RULE_APPLICATION_DOES_NOT_MATCH")
        else:
            raise InvalidInput(f"UNSUPPORTED_PROOF_NODE_KIND:{kind}")
        if expected_node_id(node) != node_id:
            raise InvalidInput("PROOF_NODE_DIGEST_MISMATCH")
        active.remove(node_id)
        visited.add(node_id)
        conclusions[node_id] = atom
        return atom

    try:
        conclusion = visit(root_id)
        if conclusion != query:
            raise InvalidInput("PROOF_ROOT_QUERY_MISMATCH")
        return ProofCheck(ValidatorResult.VALID, root_id, conclusion,
                          frozenset(visited), ("INDIVIDUAL_ROOT_VALID",))
    except (InvalidInput, RegistryInvalid, KeyError, TypeError, ValueError) as exc:
        return ProofCheck(ValidatorResult.INVALID, root_id, None,
                          frozenset(visited), (str(exc),))


def check_proof_forest(forest: Mapping[str, Any], positive_roots: list[str],
                       negative_roots: list[str], query: Atom,
                       registry: TrustedRegistry, scope_digest: str) -> tuple[ValidatorResult, tuple[str, ...], frozenset[str]]:
    nodes_raw = forest.get("nodes")
    if not isinstance(nodes_raw, list):
        return ValidatorResult.INVALID, ("FOREST_NODES_MUST_BE_LIST",), frozenset()
    nodes: dict[str, Mapping[str, Any]] = {}
    for node in nodes_raw:
        if not isinstance(node, dict) or not isinstance(node.get("node_id"), str):
            return ValidatorResult.INVALID, ("FOREST_NODE_SHAPE_INVALID",), frozenset()
        if node["node_id"] in nodes:
            return ValidatorResult.INVALID, ("DUPLICATE_NODE_ID",), frozenset()
        nodes[node["node_id"]] = node
    all_roots = positive_roots + negative_roots
    if len(all_roots) != len(set(all_roots)):
        return ValidatorResult.INVALID, ("DUPLICATE_ROOT_ID",), frozenset()
    version_digest = digest_object(dict(registry.version_tuple))
    reachable: set[str] = set()
    for sign, roots in (("+", positive_roots), ("-", negative_roots)):
        signed_query = Atom(sign, query.predicate, query.arguments)
        for root in roots:
            result = check_proof_root(root, nodes, signed_query, registry,
                                      scope_digest, version_digest)
            if result.result != ValidatorResult.VALID:
                return result.result, result.reason_codes, frozenset(reachable | set(result.reachable))
            reachable.update(result.reachable)
    if reachable != set(nodes):
        return ValidatorResult.INVALID, ("UNREACHABLE_FOREST_NODE",), frozenset(reachable)
    return ValidatorResult.VALID, ("ALL_FOREST_ROOTS_VALID",), frozenset(reachable)


def _rule_variables(rule: Any) -> set[str]:
    return {term for atom in (rule.head, *rule.body) for term in atom.arguments if term.startswith("?")}


def _instantiate(atom: Atom, substitution: Mapping[str, str]) -> Atom:
    try:
        args = tuple(substitution.get(term, term) for term in atom.arguments)
    except AttributeError as exc:
        raise InvalidInput("RULE_SUBSTITUTION_INVALID") from exc
    if any(term.startswith("?") for term in args):
        raise InvalidInput("UNBOUND_RULE_VARIABLE")
    return Atom(atom.sign, atom.predicate, args)

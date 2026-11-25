"""Finite least-fixed-point evaluator with a bounded elementary proof basis."""

from __future__ import annotations

from dataclasses import dataclass
from itertools import product
from typing import Any, Iterable, Mapping

from .canonical import digest_object
from .errors import EvaluationState, InvalidInput, ProofBasisState, ProofPosture, ResourceLimit
from .registry import TrustedRegistry
from .typed_ir import Atom, Theory, ground_rules


@dataclass(frozen=True)
class ProofTree:
    atom: Atom
    kind: str
    fact_id: str | None = None
    rule_id: str | None = None
    substitution: Mapping[str, str] | None = None
    children: tuple["ProofTree", ...] = ()

    def to_json(self) -> dict[str, Any]:
        out: dict[str, Any] = {"atom": self.atom.to_json(), "kind": self.kind}
        if self.fact_id is not None:
            out["fact_id"] = self.fact_id
        if self.rule_id is not None:
            out["rule_id"] = self.rule_id
            out["substitution"] = dict(sorted((self.substitution or {}).items()))
            out["children"] = [child.to_json() for child in self.children]
        return out

    @property
    def digest(self) -> str:
        return digest_object(self.to_json())

    def contains_on_branch(self, atom: Atom) -> bool:
        if self.atom == atom:
            return True
        return any(child.contains_on_branch(atom) for child in self.children)


@dataclass(frozen=True)
class EvaluationResult:
    state: EvaluationState
    closure: frozenset[Atom]
    posture: ProofPosture | None
    positive_roots: tuple[ProofTree, ...]
    negative_roots: tuple[ProofTree, ...]
    proof_basis_state: ProofBasisState
    iterations: int
    ground_instance_count: int
    reason_codes: tuple[str, ...]

    def roots_for(self, query: Atom) -> tuple[tuple[ProofTree, ...], tuple[ProofTree, ...]]:
        plus = tuple(sorted((p for p in self.positive_roots if p.atom == Atom("+", query.predicate, query.arguments)), key=lambda p: p.digest))
        minus = tuple(sorted((p for p in self.negative_roots if p.atom == Atom("-", query.predicate, query.arguments)), key=lambda p: p.digest))
        return plus, minus


def posture_for(closure: Iterable[Atom], query: Atom) -> ProofPosture:
    have_plus = Atom("+", query.predicate, query.arguments) in closure
    have_minus = Atom("-", query.predicate, query.arguments) in closure
    if have_plus and have_minus:
        return ProofPosture.BOTH
    if have_plus:
        return ProofPosture.SUPPORTED
    if have_minus:
        return ProofPosture.REFUTED
    return ProofPosture.UNKNOWN


def evaluate_complete(theory: Theory, query: Atom, *, max_ground_instances: int = 100_000,
                      max_proof_nodes: int = 20_000) -> EvaluationResult:
    """Compute atom closure completely, then enumerate loop-free proof trees.

    A proof-node budget may make the explanation basis incomplete without changing
    the completed atom closure or its four-state posture.
    """
    try:
        from .typed_ir import validate_atom
        if query.predicate not in theory.predicates:
            raise InvalidInput("QUERY_PREDICATE_UNKNOWN")
        validate_atom(query, theory.sorts, theory.predicates, allow_vars=False)
        grounded = ground_rules(theory, max_instances=max_ground_instances)
    except ResourceLimit as exc:
        return EvaluationResult(EvaluationState.RESOURCE_LIMIT, frozenset(), None, (), (),
                                ProofBasisState.INCOMPLETE_BASIS, 0, 0, (str(exc),))
    except InvalidInput as exc:
        return EvaluationResult(EvaluationState.INVALID_INPUT, frozenset(), None, (), (),
                                ProofBasisState.INCOMPLETE_BASIS, 0, 0, (str(exc),))

    closure = set(theory.facts)
    iterations = 0
    changed = True
    while changed:
        changed = False
        iterations += 1
        for _rid, head, body in grounded:
            if all(atom in closure for atom in body) and head not in closure:
                closure.add(head)
                changed = True
        # A strict addition consumes one element of the finite signed Herbrand base.
        if iterations > len(_herbrand_base(theory)) + 1:
            return EvaluationResult(EvaluationState.INVALID_INPUT, frozenset(), None, (), (),
                                    ProofBasisState.INCOMPLETE_BASIS, iterations,
                                    len(grounded), ("FIXED_POINT_BOUND_VIOLATION",))

    proofs: dict[str, dict[str, ProofTree]] = {}
    for atom in theory.facts:
        fact_records = theory.fact_records.get(atom.key(), ())
        for record in fact_records:
            tree = ProofTree(atom, "admitted-premise", fact_id=str(record["fact_id"]))
            proofs.setdefault(atom.key(), {})[tree.digest] = tree

    proof_count = sum(len(items) for items in proofs.values())
    proof_complete = proof_count <= max_proof_nodes
    progress = True
    while progress and proof_complete:
        progress = False
        for rule_id, head, body in grounded:
            choices: list[list[ProofTree]] = []
            for atom in body:
                available = list(proofs.get(atom.key(), {}).values())
                if not available:
                    break
                choices.append(available)
            if len(choices) != len(body):
                continue
            for selected in product(*choices):
                if any(child.contains_on_branch(head) for child in selected):
                    continue
                # Recover the exact variable substitution from the ground instance.
                rule = next(r for r in theory.rules if r.rule_id == rule_id)
                substitution: dict[str, str] = {}
                for pattern, actual in zip((rule.head, *rule.body), (head, *body), strict=True):
                    for term, value in zip(pattern.arguments, actual.arguments, strict=True):
                        if term.startswith("?"):
                            prior = substitution.setdefault(term, value)
                            if prior != value:
                                break
                tree = ProofTree(head, "rule-application", rule_id=rule_id,
                                 substitution=substitution, children=tuple(selected))
                bucket = proofs.setdefault(head.key(), {})
                if tree.digest not in bucket:
                    if proof_count >= max_proof_nodes:
                        proof_complete = False
                        break
                    bucket[tree.digest] = tree
                    proof_count += 1
                    progress = True
            if not proof_complete:
                break

    plus = tuple(tree for key, values in proofs.items() for tree in values.values()
                 if tree.atom.sign == "+")
    minus = tuple(tree for key, values in proofs.items() for tree in values.values()
                  if tree.atom.sign == "-")
    return EvaluationResult(EvaluationState.COMPLETE, frozenset(closure), posture_for(closure, query),
                            tuple(sorted(plus, key=lambda p: p.digest)),
                            tuple(sorted(minus, key=lambda p: p.digest)),
                            ProofBasisState.COMPLETE_ELEMENTARY_BASIS if proof_complete else ProofBasisState.INCOMPLETE_BASIS,
                            iterations, len(grounded),
                            ("FIXED_POINT_COMPLETE", "ELEMENTARY_BASIS_COMPLETE" if proof_complete else "PROOF_BASIS_BUDGET_EXHAUSTED"))


def _herbrand_base(theory: Theory) -> set[Atom]:
    atoms: set[Atom] = set()
    for predicate, signature in theory.predicates.items():
        domains = [theory.sorts[sort] for sort in signature]
        for args in product(*domains):
            atoms.add(Atom("+", predicate, tuple(args)))
            atoms.add(Atom("-", predicate, tuple(args)))
    return atoms

"""Strict finite sorted signed-Horn data model and grounding."""

from __future__ import annotations

from dataclasses import dataclass
from itertools import product
from typing import Any, Iterable, Iterator, Mapping

from .errors import InvalidInput, ResourceLimit


@dataclass(frozen=True, order=True)
class Atom:
    sign: str
    predicate: str
    arguments: tuple[str, ...]

    def __post_init__(self) -> None:
        if self.sign not in {"+", "-"}:
            raise InvalidInput("SIGN_MUST_BE_PLUS_OR_MINUS")
        if not self.predicate:
            raise InvalidInput("EMPTY_PREDICATE_ID")

    def to_json(self) -> dict[str, Any]:
        return {"sign": self.sign, "predicate": self.predicate,
                "arguments": list(self.arguments)}

    def key(self) -> str:
        return f"{self.sign}{self.predicate}({','.join(self.arguments)})"


@dataclass(frozen=True)
class Rule:
    rule_id: str
    head: Atom
    body: tuple[Atom, ...]


@dataclass(frozen=True)
class Theory:
    sorts: Mapping[str, tuple[str, ...]]
    predicates: Mapping[str, tuple[str, ...]]
    facts: tuple[Atom, ...]
    rules: tuple[Rule, ...]
    fact_ids: Mapping[str, tuple[str, ...]]
    fact_records: Mapping[str, tuple[Mapping[str, Any], ...]]


def parse_atom(data: Mapping[str, Any]) -> Atom:
    if set(data) != {"sign", "predicate", "arguments"}:
        raise InvalidInput("ATOM_FIELDS_INVALID")
    args = data["arguments"]
    if not isinstance(args, list) or not all(isinstance(a, str) for a in args):
        raise InvalidInput("ATOM_ARGUMENTS_MUST_BE_STRING_LIST")
    return Atom(data["sign"], data["predicate"], tuple(args))


def _is_var(term: str) -> bool:
    return term.startswith("?") and len(term) > 1


def validate_atom(atom: Atom, sorts: Mapping[str, tuple[str, ...]],
                  predicates: Mapping[str, tuple[str, ...]], *, allow_vars: bool) -> dict[str, str]:
    if atom.predicate not in predicates:
        raise InvalidInput(f"UNKNOWN_PREDICATE:{atom.predicate}")
    signature = predicates[atom.predicate]
    if len(signature) != len(atom.arguments):
        raise InvalidInput(f"ARITY_MISMATCH:{atom.predicate}")
    variables: dict[str, str] = {}
    for term, sort in zip(atom.arguments, signature, strict=True):
        if sort not in sorts:
            raise InvalidInput(f"UNKNOWN_SORT:{sort}")
        if _is_var(term):
            if not allow_vars:
                raise InvalidInput("VARIABLE_IN_GROUND_ATOM")
            prior = variables.setdefault(term, sort)
            if prior != sort:
                raise InvalidInput(f"VARIABLE_SORT_CONFLICT:{term}")
        elif term not in sorts[sort]:
            raise InvalidInput(f"UNKNOWN_CONSTANT:{sort}:{term}")
    return variables


def parse_theory(registry: Mapping[str, Any]) -> Theory:
    try:
        sorts = {name: tuple(values) for name, values in registry["sorts"].items()}
        predicates = {name: tuple(sig) for name, sig in registry["predicates"].items()}
    except (KeyError, AttributeError, TypeError) as exc:
        raise InvalidInput("SIGNATURE_MALFORMED") from exc
    if any(len(values) != len(set(values)) for values in sorts.values()):
        raise InvalidInput("DUPLICATE_SORT_CONSTANT")

    rules: list[Rule] = []
    seen_rule_ids: set[str] = set()
    for item in registry.get("rules", []):
        if set(item) != {"rule_id", "head", "body"}:
            raise InvalidInput("RULE_FIELDS_INVALID")
        rid = item["rule_id"]
        if not isinstance(rid, str) or not rid or rid in seen_rule_ids:
            raise InvalidInput("RULE_ID_EMPTY_OR_DUPLICATE")
        seen_rule_ids.add(rid)
        head = parse_atom(item["head"])
        body = tuple(parse_atom(atom) for atom in item["body"])
        if not body:
            raise InvalidInput("EMPTY_BODY_RULE_UNSUPPORTED_USE_FACT")
        head_vars = validate_atom(head, sorts, predicates, allow_vars=True)
        body_vars: dict[str, str] = {}
        for atom in body:
            for name, sort in validate_atom(atom, sorts, predicates, allow_vars=True).items():
                if name in body_vars and body_vars[name] != sort:
                    raise InvalidInput(f"VARIABLE_SORT_CONFLICT:{name}")
                body_vars[name] = sort
        if not set(head_vars).issubset(body_vars):
            raise InvalidInput("UNSAFE_HEAD_VARIABLE")
        for variable, sort in head_vars.items():
            if body_vars[variable] != sort:
                raise InvalidInput(f"HEAD_BODY_SORT_MISMATCH:{variable}")
        rules.append(Rule(rid, head, body))

    fact_map: dict[str, list[Mapping[str, Any]]] = {}
    fact_ids: dict[str, list[str]] = {}
    facts: list[Atom] = []
    seen_fact_ids: set[str] = set()
    admissions = {item["admission_id"]: item for item in registry.get("admissions", [])}
    sources = {item["source_id"]: item for item in registry.get("sources", [])}
    mappings = {item["mapping_id"]: item for item in registry.get("mappings", [])}
    for fact in registry.get("facts", []):
        if set(fact) != {"fact_id", "atom", "admission_id", "source_id", "mapping_id"}:
            raise InvalidInput("FACT_FIELDS_INVALID")
        fid = fact["fact_id"]
        if not isinstance(fid, str) or not fid or fid in seen_fact_ids:
            raise InvalidInput("FACT_ID_EMPTY_OR_DUPLICATE")
        seen_fact_ids.add(fid)
        admission = admissions.get(fact["admission_id"])
        source = sources.get(fact["source_id"])
        mapping = mappings.get(fact["mapping_id"])
        if not admission or admission.get("fact_id") != fid:
            raise InvalidInput(f"ADMISSION_FACT_MISMATCH:{fid}")
        if not source or not mapping:
            raise InvalidInput(f"FACT_REGISTRY_REFERENCE_MISSING:{fid}")
        if admission.get("status") != "ACCEPTED" or source.get("eligible") is not True or mapping.get("status") != "APPROVED":
            continue
        atom = parse_atom(fact["atom"])
        validate_atom(atom, sorts, predicates, allow_vars=False)
        facts.append(atom)
        fact_map.setdefault(atom.key(), []).append(fact)
        fact_ids.setdefault(atom.key(), []).append(fid)

    return Theory(sorts, predicates, tuple(facts), tuple(rules),
                  {k: tuple(v) for k, v in fact_ids.items()},
                  {k: tuple(v) for k, v in fact_map.items()})


def ground_rules(theory: Theory, *, max_instances: int = 100_000) -> tuple[tuple[str, Atom, tuple[Atom, ...]], ...]:
    grounded: list[tuple[str, Atom, tuple[Atom, ...]]] = []
    for rule in theory.rules:
        var_sorts: dict[str, str] = {}
        for atom in (rule.head, *rule.body):
            for var, sort in validate_atom(atom, theory.sorts, theory.predicates, allow_vars=True).items():
                if var in var_sorts and var_sorts[var] != sort:
                    raise InvalidInput(f"VARIABLE_SORT_CONFLICT:{var}")
                var_sorts[var] = sort
        names = sorted(var_sorts)
        domains = [theory.sorts[var_sorts[name]] for name in names]
        for values in product(*domains):
            substitution = dict(zip(names, values, strict=True))
            def ground(atom: Atom) -> Atom:
                args = tuple(substitution.get(term, term) for term in atom.arguments)
                return Atom(atom.sign, atom.predicate, args)
            grounded.append((rule.rule_id, ground(rule.head), tuple(ground(x) for x in rule.body)))
            if len(grounded) > max_instances:
                raise ResourceLimit("GROUND_INSTANCE_LIMIT")
    return tuple(grounded)

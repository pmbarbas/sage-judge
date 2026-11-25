"""Independent local registry loading and source/admission verification."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from .canonical import digest_object, loads_strict, sha256_hex
from .errors import RegistryInvalid, RegistryUnavailable
from .typed_ir import Atom, Theory, parse_atom, parse_theory


@dataclass(frozen=True)
class TrustedRegistry:
    root: Path
    raw_digest: str
    data: Mapping[str, Any]
    theory: Theory
    version_tuple: Mapping[str, str]
    facts_by_id: Mapping[str, Mapping[str, Any]]
    sources_by_id: Mapping[str, Mapping[str, Any]]
    admissions_by_id: Mapping[str, Mapping[str, Any]]
    mappings_by_id: Mapping[str, Mapping[str, Any]]
    source_bytes: Mapping[str, bytes]

    @property
    def registry_id(self) -> str:
        return str(self.data["registry_id"])

    @property
    def scope(self) -> Mapping[str, Any]:
        return self.data["scope"]

    @property
    def policy(self) -> Mapping[str, Any]:
        return self.data["policy"]

    def resolve_fact(self, fact_id: str) -> Mapping[str, Any] | None:
        return self.facts_by_id.get(fact_id)

    def resolve_atom(self, atom: Atom) -> bool:
        return atom.key() in self.theory.fact_ids or any(
            rule.head.predicate == atom.predicate for rule in self.theory.rules
        )


def _unique(items: list[Mapping[str, Any]], field: str, label: str) -> dict[str, Mapping[str, Any]]:
    result: dict[str, Mapping[str, Any]] = {}
    for item in items:
        key = item.get(field)
        if not isinstance(key, str) or not key or key in result:
            raise RegistryInvalid(f"DUPLICATE_OR_INVALID_{label.upper()}_ID")
        result[key] = item
    return result


def load_trusted_registry(root: str | Path, filename: str,
                          expected_sha256: str) -> TrustedRegistry:
    base = Path(root).resolve()
    path = (base / filename).resolve()
    if base not in path.parents:
        raise RegistryInvalid("REGISTRY_PATH_ESCAPES_FIXTURE_ROOT")
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise RegistryUnavailable(f"REGISTRY_UNAVAILABLE:{filename}") from exc
    raw_hash = sha256_hex(raw)
    if raw_hash != expected_sha256:
        raise RegistryInvalid("TRUSTED_REGISTRY_DIGEST_MISMATCH")
    data = loads_strict(raw)
    if not isinstance(data, dict):
        raise RegistryInvalid("REGISTRY_ROOT_MUST_BE_OBJECT")

    try:
        source_rows = data["sources"]
        fact_rows = data["facts"]
        admission_rows = data["admissions"]
        mapping_rows = data["mappings"]
        rule_rows = data["rules"]
        completeness_witnesses = data["completeness_witnesses"]
        scope = data["scope"]
        policy = data["policy"]
    except KeyError as exc:
        raise RegistryInvalid(f"REGISTRY_FIELD_MISSING:{exc.args[0]}") from exc
    if completeness_witnesses != []:
        raise RegistryInvalid("CLOSED_WORLD_COMPLETENESS_UNSUPPORTED_IN_P01_R2")
    sources = _unique(source_rows, "source_id", "source")
    facts = _unique(fact_rows, "fact_id", "fact")
    admissions = _unique(admission_rows, "admission_id", "admission")
    mappings = _unique(mapping_rows, "mapping_id", "mapping")
    source_bytes: dict[str, bytes] = {}
    for sid, source in sources.items():
        rel = Path(source.get("path", ""))
        file_path = (base / rel).resolve()
        if base not in file_path.parents:
            raise RegistryInvalid("SOURCE_PATH_ESCAPES_FIXTURE_ROOT")
        try:
            content = file_path.read_bytes()
        except OSError as exc:
            raise RegistryUnavailable(f"SOURCE_BYTES_UNAVAILABLE:{sid}") from exc
        digest = sha256_hex(content)
        if digest != source.get("sha256"):
            raise RegistryInvalid(f"SOURCE_DIGEST_MISMATCH:{sid}")
        span = source.get("span")
        if not isinstance(span, dict) or set(span) != {"start", "end"}:
            raise RegistryInvalid(f"SOURCE_SPAN_INVALID:{sid}")
        start, end = span["start"], span["end"]
        if not isinstance(start, int) or not isinstance(end, int) or start < 0 or end < start or end > len(content):
            raise RegistryInvalid(f"SOURCE_SPAN_OUT_OF_BOUNDS:{sid}")
        source_bytes[sid] = content

    for fact in fact_rows:
        admission = admissions.get(fact.get("admission_id"))
        source = sources.get(fact.get("source_id"))
        mapping = mappings.get(fact.get("mapping_id"))
        if not admission or admission.get("fact_id") != fact.get("fact_id"):
            raise RegistryInvalid(f"FACT_ADMISSION_LINK_INVALID:{fact.get('fact_id')}")
        if not source or not mapping:
            raise RegistryInvalid(f"FACT_SOURCE_OR_MAPPING_MISSING:{fact.get('fact_id')}")
        if mapping.get("predicate") != fact.get("atom", {}).get("predicate"):
            raise RegistryInvalid(f"FACT_MAPPING_PREDICATE_MISMATCH:{fact.get('fact_id')}")

    theory = parse_theory(data)
    theory_digest = digest_object({"sorts": data["sorts"], "predicates": data["predicates"], "rules": rule_rows})
    source_snapshot_digest = digest_object([
        {"source_id": sid, "revision_id": source["revision_id"], "sha256": source["sha256"],
         "eligible": source["eligible"], "span": source["span"]}
        for sid, source in sorted(sources.items())
    ])
    admission_digest = digest_object({"facts": fact_rows, "admissions": admission_rows, "mappings": mapping_rows})
    version = {
        "registry_id": data["registry_id"],
        "registry_digest": "sha256:" + raw_hash,
        "theory_digest": theory_digest,
        "source_snapshot_digest": source_snapshot_digest,
        "admission_registry_digest": admission_digest,
        "scope_digest": digest_object(scope),
        "policy_digest": digest_object(policy),
        "population_digest": digest_object(data.get("population", [])),
        "mapping_registry_digest": digest_object(mapping_rows),
        "ontology_digest": digest_object(data.get("ontology", {"id": "fixture-ontology-v1"})),
        "compiler_id": "sj01-reference/0.2.0",
        "evaluator_id": "sj01-reference/0.2.0",
        "verifier_contract_version": "SJ01-PVC/1.1",
        "schema_version": "SJ01-SVE/1.1"
    }
    return TrustedRegistry(base, "sha256:" + raw_hash, data, theory, version, facts,
                           sources, admissions, mappings, source_bytes)


def parse_registry_atom(data: Mapping[str, Any]) -> Atom:
    return parse_atom(data)

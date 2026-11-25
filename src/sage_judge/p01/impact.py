"""P01-R2 conservative impact policy: full recomputation, no selector."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .errors import EvaluationState, ImpactAction
from .evaluate import EvaluationResult, evaluate_complete
from .registry import TrustedRegistry
from .typed_ir import Atom


@dataclass(frozen=True)
class RequalificationResult:
    action: ImpactAction
    old_evaluation: EvaluationResult | None
    new_evaluation: EvaluationResult | None
    changed_components: tuple[str, ...]
    reason_codes: tuple[str, ...]


def full_recompute_delta(old_registry: TrustedRegistry | None,
                         new_registry: TrustedRegistry | None,
                         query: Atom, *, delta_complete: bool,
                         max_ground_instances: int = 100_000,
                         max_proof_nodes: int = 20_000) -> RequalificationResult:
    """Never certifies no impact from an incomplete/unknown delta or closure."""
    if old_registry is None or new_registry is None or not delta_complete:
        return RequalificationResult(ImpactAction.FULL_RECOMPUTE_REQUIRED, None, None, (),
                                     ("UNKNOWN_REGISTRY_OR_DELTA", "NO_NO_IMPACT_CERTIFICATE"))
    old = evaluate_complete(old_registry.theory, query,
                            max_ground_instances=max_ground_instances,
                            max_proof_nodes=max_proof_nodes)
    new = evaluate_complete(new_registry.theory, query,
                            max_ground_instances=max_ground_instances,
                            max_proof_nodes=max_proof_nodes)
    if old.state != EvaluationState.COMPLETE or new.state != EvaluationState.COMPLETE:
        return RequalificationResult(ImpactAction.FULL_RECOMPUTE_REQUIRED, old, new, (),
                                     ("FULL_EVALUATION_INCOMPLETE", "NO_NO_IMPACT_CERTIFICATE"))

    changed: list[str] = []
    if old_registry.version_tuple != new_registry.version_tuple:
        changed.append("VERSION_TUPLE")
    if old.posture != new.posture:
        changed.append("PROOF_POSTURE")
    if old.closure != new.closure:
        changed.append("SIGNED_ATOM_CLOSURE")
    old_plus, old_minus = old.roots_for(query)
    new_plus, new_minus = new.roots_for(query)
    if {p.digest for p in old_plus} != {p.digest for p in new_plus}:
        changed.append("POSITIVE_PROOF_BASIS")
    if {p.digest for p in old_minus} != {p.digest for p in new_minus}:
        changed.append("NEGATIVE_PROOF_BASIS")
    if old.proof_basis_state != new.proof_basis_state:
        changed.append("PROOF_BASIS_COMPLETENESS")

    if changed:
        return RequalificationResult(ImpactAction.REQUALIFICATION_REQUIRED, old, new,
                                     tuple(changed), ("BOTH_SNAPSHOTS_FULLY_RECOMPUTED",))
    return RequalificationResult(ImpactAction.NO_CHANGE_CONFIRMED_BY_FULL_RECOMPUTE,
                                 old, new, (), ("IDENTICAL_VERSION_AND_RECOMPUTED_RESULT",))

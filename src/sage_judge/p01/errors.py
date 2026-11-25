"""Typed error/result vocabulary for the bounded P01 reference."""

from __future__ import annotations

from enum import StrEnum


class EvaluationState(StrEnum):
    COMPLETE = "COMPLETE"
    INDETERMINATE = "INDETERMINATE"
    INVALID_INPUT = "INVALID_INPUT"
    RESOURCE_LIMIT = "RESOURCE_LIMIT"


class ValidatorResult(StrEnum):
    VALID = "VALID"
    INVALID = "INVALID"
    INDETERMINATE = "INDETERMINATE"


class ProofPosture(StrEnum):
    SUPPORTED = "SUPPORTED"
    REFUTED = "REFUTED"
    BOTH = "BOTH"
    UNKNOWN = "UNKNOWN"


class ProofBasisState(StrEnum):
    COMPLETE_ELEMENTARY_BASIS = "COMPLETE_ELEMENTARY_BASIS"
    INCOMPLETE_BASIS = "INCOMPLETE_BASIS"


class ImpactAction(StrEnum):
    FULL_RECOMPUTE_REQUIRED = "FULL_RECOMPUTE_REQUIRED"
    REQUALIFICATION_REQUIRED = "REQUALIFICATION_REQUIRED"
    NO_CHANGE_CONFIRMED_BY_FULL_RECOMPUTE = "NO_CHANGE_CONFIRMED_BY_FULL_RECOMPUTE"


class P01Error(Exception):
    """Base class for expected, typed reference failures."""


class InvalidInput(P01Error):
    pass


class RegistryUnavailable(P01Error):
    pass


class RegistryInvalid(P01Error):
    pass


class ResourceLimit(P01Error):
    pass

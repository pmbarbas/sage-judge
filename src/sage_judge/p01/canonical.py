"""SJ01-CJSON/1 canonical JSON bytes and SHA-256 helpers."""

from __future__ import annotations

import hashlib
import json
import unicodedata
from typing import Any

from .errors import InvalidInput


def _normalize(value: Any) -> Any:
    if isinstance(value, str):
        return unicodedata.normalize("NFC", value)
    if value is None or isinstance(value, (bool, int)):
        return value
    if isinstance(value, float):
        raise InvalidInput("JSON_FLOAT_FORBIDDEN_USE_DECIMAL_STRING")
    if isinstance(value, list):
        return [_normalize(item) for item in value]
    if isinstance(value, dict):
        normalized: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise InvalidInput("OBJECT_KEY_MUST_BE_STRING")
            nkey = unicodedata.normalize("NFC", key)
            if nkey in normalized:
                raise InvalidInput("DUPLICATE_KEY_AFTER_NFC")
            normalized[nkey] = _normalize(item)
        return normalized
    raise InvalidInput(f"UNSUPPORTED_JSON_VALUE:{type(value).__name__}")


def reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        normalized = unicodedata.normalize("NFC", key)
        if normalized in result:
            raise InvalidInput("DUPLICATE_KEY_AFTER_NFC")
        result[normalized] = value
    return result


def loads_strict(data: str | bytes) -> Any:
    try:
        return json.loads(data, object_pairs_hook=reject_duplicate_pairs,
                          parse_float=lambda _: (_ for _ in ()).throw(InvalidInput("JSON_FLOAT_FORBIDDEN_USE_DECIMAL_STRING")),
                          parse_constant=lambda _: (_ for _ in ()).throw(InvalidInput("JSON_NONFINITE_NUMBER_FORBIDDEN")))
    except InvalidInput:
        raise
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise InvalidInput(f"INVALID_JSON:{exc}") from exc


def canonical_bytes(value: Any) -> bytes:
    normalized = _normalize(value)
    text = json.dumps(normalized, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False)
    return text.encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def digest_object(value: Any) -> str:
    return "sha256:" + sha256_hex(canonical_bytes(value))


def sve_digest(sve: dict[str, Any]) -> str:
    payload = _normalize(sve)
    if not isinstance(payload, dict) or "integrity" not in payload:
        raise InvalidInput("SVE_INTEGRITY_REQUIRED")
    integrity = payload["integrity"]
    if not isinstance(integrity, dict):
        raise InvalidInput("SVE_INTEGRITY_MUST_BE_OBJECT")
    integrity.pop("object_digest", None)
    return "sha256:" + sha256_hex(canonical_bytes(payload))

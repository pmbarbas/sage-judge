# Error catalogue — API 0.3

`AdjudicationError` is raised for invalid/untrusted inputs; the CLI reports an error and uses exit code 2. Errors are not converted into `UNKNOWN`.

- `INPUTS_MUST_BE_OBJECTS`, `INPUT_BYTE_LIMIT`: input object/size boundary.
- `BUNDLE_SCHEMA_INVALID`, `TRUST_SCHEMA_INVALID`, `POLICY_SCHEMA_INVALID`, `MAPPING_FIELDS_INVALID`, `SOURCE_RECORD_SHAPE`: contract shape/version failures.
- `TRUSTED_REGISTRY_DIGEST_MISMATCH`, `POLICY_POSTURE_MAP_INVALID`, `POLICY_ATTESTATION_INVALID`: caller trust/policy inconsistencies.
- `SOURCE_RECORD_VALUE_INVALID`, `SOURCE_TEXT_OR_DATE_INVALID`, `SOURCE_WINDOW_INVALID`, `SOURCE_ID_DUPLICATE`, `MAPPING_ID_DUPLICATE_OR_INVALID`, `ROUTE_ID_DUPLICATE_OR_INVALID`, `COMPLETENESS_RECORD_SHAPE_INVALID`: stable input and identity errors. `PROPOSAL_CITATION_INVALID`: proposal citation does not bind to the trusted source snapshot; a valid citation is not a premise.
- `TRUSTED_ROUTE_MISSING_OR_AMBIGUOUS`, `TRUSTED_ROUTE_MAPPING_UNKNOWN`, `TRUSTED_ROUTE_QUERY_MISMATCH`, `TRUSTED_ROUTE_SCOPE_MISMATCH`: route binding failures.
- `P01_EVALUATION_*`, `P01_PROOF_OR_SVE_INVALID`: bounded reasoning/verification failure.
- `INPUT_SNAPSHOT_CHANGED`, `TRUSTED_REGISTRY_CHANGED`, `DECISION_DIGEST_MISMATCH`, `RECOMPUTED_DECISION_MISMATCH`: replay integrity failure returned by `verify`.

Codes are diagnostic identifiers, not a stable cross-version network protocol. Callers should fail closed on unknown codes.

`TRUSTED_ROUTE_MISSING_OR_AMBIGUOUS` and `TRUSTED_ROUTE_SHAPE_INVALID` reject missing or malformed structured routes. Route membership mismatches and rejected required mappings are returned as coverage INCOMPLETE with a REVIEW advisory.

- `P01_THEORY_INVALID`: invalid typed theory/query at dependency selection.
- `UNSUPPORTED_RULE_DEPENDENCY_SCOPE`: reachable body arguments differ from the exact query tuple.
- `UNSUPPORTED_RULE_DEPENDENCY_UNBOUND_VARIABLE`: reachable body-only variable cannot be bound from the matched head.

These errors return no decision or proof; the caller must hold for review. `verify` returns invalid for unsupported inputs, even when supplied hashes match.

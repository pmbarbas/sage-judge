# Schema reference — decision v0.3 / input v0.2

- `schemas/bundle.schema.json`: user query and untrusted proposal envelope.
- `schemas/decision_record.schema.json`: record version, input hashes, query, admitted facts, four-valued P01 posture, business policy verdict, execution authority, SVE and record hash.
- `schemas/p01_sve_v1_1.schema.json`: included P01 SVE 1.1 contract, included with its P01 validator.
- Trust registry and policy contracts are described in `API_CONTRACT.md` and validated by exact keys and version checks in the API.

The caller supplies trusted registry and policy separately from the bundle. Hash binding gives integrity against accidental change, not identity or authority authentication. Schema validity does not establish semantic entailment.

Decision records from incompatible earlier implementations are not replay-compatible. P01 SVE remains 1.1; its compiler identity includes the actual package version.

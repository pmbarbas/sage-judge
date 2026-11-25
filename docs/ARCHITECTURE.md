# Architecture and trust boundaries

The library exposes two operations: `adjudicate(bundle, trusted_registry, policy, limits)` and `verify(record, trusted_registry, bundle, policy)`. The caller owns identity, query authorisation, trust root, source-to-fact review and downstream enforcement.

| Layer | Responsibility | Does not establish |
|---|---|---|
| Proposal diagnostics | Validate shape and citation byte bindings | Truth of model claims |
| Trusted registry | Versioned sources, reviewed mappings, routes and finite theory | Authenticity merely by hashing |
| Dependency coverage | Backward closure and route reconciliation | Real-world evidence universe completeness |
| Admission | Check mapping, revision, basis, scope and witnesses | Independent semantic fidelity |
| Formal engine | Finite typed signed-Horn inference | Truth of premises |
| Proof and record checks | Check derivations and recompute exact inputs | Independent source truth |
| Policy | Advisory recommendation, explicit review on incomplete coverage | Execution authority |

## Qualified fragment

Rules are typed and finite. Both signs are considered conservatively when building the backward dependency closure. Every reachable body must be groundable from the matched head and preserve the exact ordered query argument tuple. Body-only variables and different argument tuples are refused. The engine is not advertised as general cross-entity or existential reasoning. Irrelevant other-entity records do not automatically cause refusal.

A proposal cannot choose formal premises. It can trigger refusal if malformed or invalid; explicit abstention/review caps the advisory without changing the formal posture. The trusted route is reconciled against computed expected mapping identities; rejected required mappings or unresolved coverage cap the advisory at REVIEW. A record may be verifiable but still have incomplete coverage and a review verdict.

## Implementation map

`api.py`: orchestration and exact replay; `p02/semantic_admission.py`: reviewed mapping checks; `p01/typed_ir.py`, `evaluate.py`: finite reasoning; `p01/proof.py`, `sve.py`: proof and record validation; `cli.py`: fixed demos and bounded local file workflow. Internal module names reflect research lineage, not public API stability guarantees. JSON schema documentation complements executable validators.

See [API contract](API_CONTRACT.md), [limitations](LIMITATIONS.md), and [threat model](THREAT_MODEL.md).

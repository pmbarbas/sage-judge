# Extending with a domain pack

The package core is domain-neutral within its finite signed-Horn same-query-tuple fragment. To add a domain, prepare a separate trusted registry and declarative case pack containing: finite entity/sort constants; predicate signatures and signed rules; immutable source bytes and revisions; exact byte-span citations; independently reviewed source-to-fact mappings; scoped policy; and explicit resource limits.

1. Define the supported query, domain scope, dates and entity population.
2. Author source records and compute exact UTF-8 byte spans/digests.
3. Bind mappings to source revision, entity, query, polarity and basis. Do not infer a negative from missing records.
4. If using completeness, define the event/recording/availability/population/time rule and a separately identified witness; synthetic labels are not a real trust root.
5. Add controlled positive, explicit negative, missing-evidence, contradiction and stale-version cases.
6. Run the same API and verifier without domain-specific core changes; freeze expectations before execution.
7. Version every source, rule, policy and record. Recompute fully on change; no selective-impact guarantee is provided.

A caller-provided registry is not authenticated merely because it is hashed. External trust establishment, human review and business suitability are outside this candidate.

Every reachable rule must preserve the ordered query argument tuple and use no body-only variable. Cross-entity, different-argument and existential-style dependencies are outside the supported API contract and refused. A separate domain can use distinct declarative rules, sources and policy without expanding this fragment.

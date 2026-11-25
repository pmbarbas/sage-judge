# Threat model and boundaries

The candidate handles bounded local JSON and source text under a caller-chosen
trust registry. It addresses malformed schemas, stale/different source bytes,
bad UTF-8 spans, conflicting source mappings, trust-boundary field injection,
proof tampering and resource limits. It does not establish the truth of source
text, reviewer identity, source authenticity, legal authority, business-policy
validity, safe downstream action, resistance to a malicious same-user process,
or availability against host-level denial of service. A registry digest only
identifies bytes; provisioning and custody of that trust root are external to
this library. No network or inference route exists in the candidate package.


## Bounded filesystem profile

The CLI rejects noncanonical paths, symlink components, hard-linked regular files and paths escaping the selected root at validation time. This does not claim race-free protection against a concurrent same-user process replacing path components between checks and use. Use a private, non-concurrently-modified input root; hostile multi-user filesystems require OS-level isolation beyond this package. Demo selection uses a fixed allowlist.


Proposal text is not interpreted. Source-to-fact mappings remain trusted input assertions whose real-world semantics are outside this package. Registry hashes provide integrity/replay binding only, not authentication, provenance certification, or proof that the source mapping is true.

## Supported fragment

The API validates the finite theory and conservatively refuses reachable rules with body-only variables or body arguments differing from the query tuple, rather than reporting complete coverage over an omitted dependency. This is a fail-closed restriction, not general cross-entity inference.

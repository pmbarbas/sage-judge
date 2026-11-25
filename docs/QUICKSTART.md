# Quickstart

Use Python 3.11+ (this release was tested on Linux x86-64 with Python 3.13.5). No third-party package is needed for running from source.

```sh
PYTHONPATH=src python -m sage_judge --version
PYTHONPATH=src python -m sage_judge demo --case inspection_positive
PYTHONPATH=src python -m sage_judge demo --case inspection_unknown
PYTHONPATH=src python -m sage_judge demo --case inspection_conflict
```

`unsupported_dependency` deliberately refuses with exit code 2. CLI `demo` names are fixed, not arbitrary paths.

## Python API and replay

```python
import json
from pathlib import Path
from sage_judge.api import adjudicate, verify

doc = json.loads(Path("examples/inspection_conflict.json").read_text())
bundle, registry, policy = (doc[k] for k in ("bundle", "trusted_registry", "policy"))
record = adjudicate(bundle, registry, policy, doc["limits"])
assert record["proof_posture"] == "BOTH"
assert record["business_verdict"] == "REVIEW"
assert record["execution_authority"] == "NONE"
assert verify(record, registry, bundle, policy)["valid"]
```

Run with `PYTHONPATH=src` or from an installed wheel. The caller provides the authorised query, trusted registry and policy separately. The example trusts synthetic fixtures only.

For CLI file workflows, split the example into `bundle.json`, `registry.json`, and `policy.json` in an existing dedicated directory. Then run:

```sh
PYTHONPATH=src python -m sage_judge adjudicate --root ./work --bundle bundle.json --registry registry.json --policy policy.json --out decision.json
PYTHONPATH=src python -m sage_judge verify --root ./work --record decision.json --bundle bundle.json --registry registry.json --policy policy.json
```

Output must be a new file; existing files are not overwritten. CLI file adjudication uses default limits; the API can supply explicit bounded limits. Exit 0 means command success, 2 invalid input/refusal, 3 replay failed. Never treat a process exit status as business authorisation.

Build and install from an approved checkout using the commands in [Reproducibility](REPRODUCIBILITY.md).

# Reproducibility

Run the standard-library test suite from the checkout:

```sh
PYTHONPATH=src python -m unittest discover -s tests -v
mkdir -p dist
SOURCE_DATE_EPOCH=1795478400 python -c 'import sage_build_backend as b; print(b.build_wheel("dist")); print(b.build_sdist("dist"))'
```

The custom PEP 517 backend verifies a positive SHA-256 source allowlist and uses deterministic archive ordering, timestamps and metadata. Repeat in a fresh copy with an empty `dist` directory. Compare SHA-256 hashes; do not reuse an existing output file. Byte-identical builds are qualified for the tested toolchain and compression implementation, not guaranteed across all Python/zlib versions.

If pip is already available, install the exact wheel offline:

```sh
python -m pip install --no-index --no-deps --no-cache-dir --disable-pip-version-check --target ./installed dist/sage_judge-0.1.0-py3-none-any.whl
PYTHONPATH=./installed python -m sage_judge --version
PYTHONPATH=./installed python -m sage_judge demo --case inspection_conflict
```

The source archive contains the standalone tests and synthetic fixture. Extract into a clean directory and repeat the first test command. The allowlist must be regenerated only as part of an explicitly reviewed source change. No network, model or new runtime dependencies are needed. CI workflow activation is deferred pending verification of action pins and permissions; these local commands are the qualification path.

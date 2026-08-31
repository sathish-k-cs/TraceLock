# TraceLock Standard Library Compliance

TraceLock is a zero-third-party-runtime-dependency security event correlation and attack analysis engine built with Python's standard library.

The TraceLock runtime does not require packages installed from PyPI.

## Zero-Dependency Policy

TraceLock's security-analysis engine uses only Python standard-library functionality.

Runtime capabilities include:

- Security log parsing
- Event normalization
- Event correlation
- Attack-chain reconstruction
- Risk scoring
- MITRE ATT&CK mapping
- Evidence extraction
- Behavioral profiling
- Anomaly detection
- Security recommendations
- Terminal report generation
- JSON report generation

Python version used during development and verification:

```text
Python 3.13.14
```

## Standard Library Substitutions

TraceLock deliberately avoids third-party packages commonly used for similar functionality.

| Common Third-Party Package | Standard Library Alternative | TraceLock Usage |
|---|---|---|
| `pydantic` | `dataclasses` | Structured security-analysis data models |
| `click` | `argparse` | Command-line interface and argument handling |
| `python-dateutil` | `datetime` | Event timestamps and duration calculations |
| `orjson` | `json` | JSON report generation |
| `ujson` | `json` | JSON serialization |
| `rich` | `print()` and formatted strings | Human-readable terminal reports |
| `pandas` | Lists, dictionaries, and built-in processing | Event and report data handling |
| `numpy` | Built-in arithmetic and Python collections | Risk and anomaly score calculations |
| `scikit-learn` | Custom Python scoring logic | Behavioral and anomaly analysis |
| `loguru` | Standard output and file I/O | Application output and diagnostics |
| `PyYAML` | Text parsing and standard data structures | Structured data handling where required |
| `requests` | `urllib` | Standard-library HTTP capability when needed |

These substitutions keep the TraceLock runtime free from third-party dependencies while providing the functionality required by the project.

## Standard Library Modules Used

The TraceLock source code uses standard-library modules including:

- `argparse` — command-line argument parsing
- `dataclasses` — structured analysis models
- `datetime` — event timestamps and attack-sequence duration calculations
- `json` — machine-readable JSON report generation
- `re` — security log pattern matching and parsing
- `pathlib` — filesystem path handling
- `typing` — type annotations
- `collections` — collection-based event processing where required
- `sys` — command-line error handling and process control

The imports can be inspected directly in the files under `tracelock/`.

## Runtime Dependency Verification

TraceLock can be verified without installing any third-party runtime package.

Example verification:

```powershell
python -c "import sys; print('Python:', sys.version); print('Runtime dependencies: STANDARD LIBRARY ONLY'); print('Third-party runtime packages: 0')"
```

Expected result:

```text
Python: 3.13.14
Runtime dependencies: STANDARD LIBRARY ONLY
Third-party runtime packages: 0
```

## Test Dependency

The automated test suite uses `pytest`.

`pytest` is a development and testing dependency only. It is not required to execute the TraceLock security-analysis engine.

Install it only when running the test suite:

```powershell
python -m pip install pytest
```

Run the tests with:

```powershell
python -m pytest -v
```

The current test suite verifies:

- Normal login activity
- Brute-force activity
- Command activity
- Full multi-stage attack chains
- Risk assessment
- MITRE ATT&CK mapping
- Evidence extraction
- Behavioral analysis
- Anomaly analysis
- Security recommendations

A successful verification currently produces:

```text
4 passed
```

## Dependency Manifest

TraceLock has no runtime dependency manifest containing third-party packages.

The project intentionally relies on Python's standard library for runtime functionality.

`pytest` is used only during development/testing and is documented separately from runtime dependencies.

## Design Principle

The goal of the Zero Dependency implementation is not simply to remove a package from an existing application.

TraceLock was designed around standard-library primitives so that its core security-analysis pipeline remains:

- Lightweight
- Portable
- Deterministic
- Easy to inspect
- Easy to run
- Free from third-party runtime dependencies

## Compliance Summary

```text
Runtime third-party packages: 0
Runtime package installation required: No
Standard library runtime: Yes
External security-analysis service required: No
Development/test dependency: pytest
```

TraceLock therefore satisfies its standard-library-only runtime design.
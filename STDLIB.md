# TraceLock Standard Library Compliance

TraceLock is a zero-third-party-runtime-dependency security event correlation engine built entirely with Python's standard library.

## Zero-Dependency Policy

TraceLock has **zero third-party runtime dependencies**.

The core application runs using Python 3.13+ and does not require packages installed from PyPI.

Core capabilities include:

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

## Package Replacements

TraceLock deliberately avoids commonly used third-party packages by using Python standard-library functionality.

| Normally Used Package | Standard Library Replacement | TraceLock Usage |
|---|---|---|
| `pydantic` | `dataclasses` | Structured security event and analysis models |
| `requests` | `urllib` | HTTP functionality if network access is required |
| `pandas` | `csv`, `json`, lists and dictionaries | Structured log and report data processing |
| `numpy` | Built-in arithmetic and collections | Risk and anomaly score calculations |
| `scikit-learn` | Custom Python scoring logic | Behavioral and anomaly analysis |
| `rich` | `print()` and formatted strings | Terminal security reports |
| `click` | `argparse` | Command-line interface |
| `python-dateutil` | `datetime` | Event timestamps and duration calculations |
| `orjson` | `json` | JSON report generation |
| `ujson` | `json` | JSON serialization |
| `PyYAML` | `json` / text parsing | Configuration and structured-data handling |
| `loguru` | Standard `print()` / file I/O | Application output and diagnostics |

These replacements are intentionally lightweight and keep the core TraceLock runtime free of third-party dependencies.

## Standard Library Modules Used

TraceLock uses Python standard-library modules including:

- `argparse` — command-line argument parsing
- `dataclasses` — structured analysis models
- `datetime` — timestamps and attack-sequence durations
- `json` — machine-readable report generation
- `re` — security log parsing and pattern matching
- `pathlib` — filesystem path handling
- `typing` — type annotations
- `collections` — collection-based event processing where required
- `sys` — command-line error handling and process control

The exact imports can be inspected directly in the `tracelock/` source files.

## Development-Only Dependency

The test suite uses:

```text
pytest
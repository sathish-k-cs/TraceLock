# TraceLock

TraceLock is a lightweight security event correlation and attack analysis engine built in Python.

It transforms raw security logs into structured attack narratives by correlating related events, identifying security techniques, extracting evidence, profiling behavior, detecting anomalies, assessing risk, and generating actionable security recommendations.

TraceLock is designed as a **standard-library-only runtime project**. It does not require external security-analysis services or third-party runtime packages.

## Features

- Security event parsing
- Multi-event attack correlation
- Attack chain reconstruction
- Risk scoring and severity assessment
- MITRE ATT&CK technique mapping
- Security evidence extraction
- Behavioral profiling
- Behavioral anomaly detection
- Security response recommendations
- Human-readable terminal reports
- JSON report generation
- Automated analysis tests

## Analysis Pipeline

```text
Raw Security Logs
        |
        v
   Event Parser
        |
        v
  Event Correlation
        |
        v
    Attack Chain
        |
        +-------------------+
        |                   |
        v                   v
 MITRE Mapping       Evidence Extraction
        |                   |
        +---------+---------+
                  |
                  v
        Behavior Profiling
                  |
                  v
         Anomaly Detection
                  |
                  v
          Risk Assessment
                  |
                  v
    Security Recommendations
                  |
                  v
            Final Report
```

## Project Structure

```text
TraceLock/
├── tracelock/
│   ├── __init__.py
│   ├── parser.py
│   ├── correlator.py
│   ├── risk.py
│   ├── story.py
│   ├── mitre.py
│   ├── evidence.py
│   ├── behavior.py
│   ├── anomaly.py
│   ├── recommendation.py
│   ├── report.py
│   └── cli.py
├── examples/
│   ├── sample_attack.log
│   ├── normal_login.log
│   ├── brute_force.log
│   └── command_activity.log
├── tests/
│   └── test_analysis.py
├── README.md
├── STDLIB.md
├── LICENSE
└── .gitignore
```

## Requirements

### Runtime

- Python 3.13+
- Python standard library only
- No third-party runtime packages

### Testing

- `pytest` is used only for the automated test suite.
- `pytest` is a development/test dependency and is not required to run TraceLock's security-analysis engine.

TraceLock does not depend on external security-analysis APIs or services.

For details about standard-library compliance, see [`STDLIB.md`](STDLIB.md).

## Setup

Create and activate a virtual environment:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

No third-party package is required to run TraceLock.

To run the automated tests, install `pytest`:

```powershell
python -m pip install pytest
```

## Usage

Analyze a security log:

```powershell
python -m tracelock.cli examples\sample_attack.log
```

TraceLock produces a report containing:

- Attack chains
- Timeline reconstruction
- MITRE ATT&CK mappings
- Security evidence
- Behavior profile
- Anomaly analysis
- Risk factors
- Response recommendations
- Final risk conclusion

## Example Logs

### Normal Login

```powershell
python -m tracelock.cli examples\normal_login.log
```

### Brute Force Activity

```powershell
python -m tracelock.cli examples\brute_force.log
```

### Command and Privileged Activity

```powershell
python -m tracelock.cli examples\command_activity.log
```

### Full Multi-Stage Attack

```powershell
python -m tracelock.cli examples\sample_attack.log
```

## JSON Reports

TraceLock can generate a structured JSON report:

```powershell
python -m tracelock.cli examples\sample_attack.log --json reports\sample_attack.json
```

The JSON report contains structured attack-chain information suitable for further processing or integration with other security-analysis workflows.

## Testing

Run the complete automated test suite:

```powershell
python -m pytest -v
```

The test suite currently covers:

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

A successful test run currently reports:

```text
4 passed
```

## Example Detection

For a multi-stage security event sequence containing repeated authentication failures followed by successful authentication, command execution, and privileged activity, TraceLock can produce findings such as:

```text
Risk: CRITICAL
Score: 100/100

Behavior Profile:
Credential Compromise → Privilege Escalation
Confidence: 95%

Anomaly Analysis:
Score: 100/100
Severity: CRITICAL
```

The analysis represents a correlation-based security assessment. Detection results should be investigated and validated against the underlying logs and system context.

TraceLock can also generate investigation recommendations for:

- Repeated authentication failures
- Successful authentication transitions
- Commands executed after authentication
- Privileged activity
- The complete correlated attack sequence

## Detection Capabilities

### Authentication Abuse

Repeated authentication failures can be correlated as potential credential attack activity.

### Successful Access Transition

Authentication failures followed by successful authentication can indicate a possible successful credential compromise or unauthorized access.

### Post-Authentication Execution

Command execution following successful authentication can be identified as suspicious activity within a correlated sequence.

### Privileged Activity

Privileged activity following command execution can indicate possible privilege escalation or unauthorized elevated activity.

### Multi-Stage Attack Correlation

Multiple related events can be reconstructed into a single attack chain instead of being analyzed as isolated log entries.

## MITRE ATT&CK Mapping

TraceLock maps detected event patterns to relevant MITRE ATT&CK techniques, including:

- `T1110` - Brute Force
- `T1078` - Valid Accounts
- `T1059` - Command and Scripting Interpreter
- `T1068` - Exploitation for Privilege Escalation

These mappings are based on the event patterns represented in the input logs and should be validated during investigation.

## Risk Assessment

TraceLock evaluates correlated activity using security risk factors such as:

- Authentication failures
- Successful authentication
- Command execution
- Privileged activity
- Authentication-to-access transitions
- Multi-stage attack progression

The resulting assessment includes:

- Severity level
- Numerical risk score
- Contributing risk factors

## Security Recommendations

Based on detected activity, TraceLock generates prioritized recommendations such as:

- Investigating authentication failures
- Reviewing successful authentication
- Inspecting executed commands
- Investigating privileged activity
- Preserving logs
- Investigating the complete correlated attack sequence

Recommendations are assigned priorities such as `HIGH` and `URGENT`.

## Example Output

A detected multi-stage attack can produce output similar to:

```text
TRACELOCK SECURITY ANALYSIS

Attack chains detected: 1

ATTACK CHAIN #1

Risk:   CRITICAL
Score:  100/100

Behavior Profile:
Credential Compromise → Privilege Escalation
Confidence: 95%

Anomaly Analysis:
Score: 100/100
Severity: CRITICAL

Recommendations:
[HIGH] Investigate Authentication Failures
[URGENT] Investigate Successful Authentication
[HIGH] Review Executed Commands
[URGENT] Investigate Privileged Activity
[URGENT] Investigate Complete Attack Sequence
```

## Standard Library Compliance

TraceLock's security-analysis engine uses Python's standard library for runtime functionality.

The project does not require third-party packages for:

- Log parsing
- Event correlation
- Attack-chain reconstruction
- Risk assessment
- MITRE mapping
- Evidence extraction
- Behavioral analysis
- Anomaly detection
- Recommendation generation
- Terminal report generation
- JSON report generation

`pytest` is used only as a development dependency for automated testing.

See [`STDLIB.md`](STDLIB.md) for the project's standard-library compliance documentation.

## Purpose

TraceLock is a security-analysis and learning project demonstrating how raw security events can be transformed into correlated attack narratives, behavioral findings, anomaly indicators, risk assessments, and actionable recommendations.

The project focuses on explainable, deterministic analysis of structured security events rather than relying on external AI or security-analysis services.

## Security Notice

TraceLock is intended for authorized defensive security analysis, testing, education, and research.

Only analyze logs and systems that you are authorized to access.

TraceLock provides analytical findings based on supplied event data. Its results should be treated as investigation aids rather than definitive proof of compromise.

## License

TraceLock is released under the MIT License.

See [`LICENSE`](LICENSE) for the full license text.

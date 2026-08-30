# TraceLock

TraceLock is a lightweight security event correlation and attack analysis engine built in Python.

It transforms raw security logs into a structured attack narrative by correlating related events, identifying attack techniques, extracting evidence, profiling attacker behavior, detecting anomalies, assessing risk, and generating actionable security recommendations.

## Features

- Security event parsing
- Multi-event attack correlation
- Attack chain reconstruction
- Risk scoring and severity assessment
- MITRE ATT&CK technique mapping
- Evidence extraction
- Attacker behavior profiling
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
├── reports/
├── README.md
├── STDLIB.md
└── .gitignore
```

## Requirements

- Python 3.13+
- pytest for running the automated tests

TraceLock is designed to run without external security-analysis services.

## Setup

Create and activate a virtual environment:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

Install the test dependency:

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

The JSON report contains structured attack-chain information suitable for further processing or integration with other security tools.

## Testing

Run the complete automated test suite:

```powershell
python -m pytest tests\test_analysis.py -v
```

The test suite covers:

- Normal login activity
- Brute-force activity
- Command and privileged activity
- Full multi-stage attack chains

## Example Detection

For a multi-stage attack containing repeated authentication failures followed by successful authentication, command execution, and privileged activity, TraceLock can identify:

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

TraceLock also generates investigation recommendations for:

- Repeated authentication failures
- Successful authentication transitions
- Commands executed after authentication
- Privileged activity
- The complete correlated attack sequence

## Detection Capabilities

### Authentication Abuse

Repeated authentication failures can be correlated as potential credential attack activity.

### Successful Access Transition

Authentication failures followed by successful authentication can indicate a possible successful credential compromise.

### Post-Authentication Execution

Command execution following successful authentication can be identified as suspicious activity.

### Privilege Escalation Activity

Privileged activity following command execution can indicate possible privilege escalation.

### Multi-Stage Attack Correlation

Multiple related events can be reconstructed into a single attack chain instead of being analyzed as isolated log entries.

## MITRE ATT&CK Mapping

TraceLock maps detected behaviors to relevant MITRE ATT&CK techniques, including:

- T1110 - Brute Force
- T1078 - Valid Accounts
- T1059 - Command and Scripting Interpreter
- T1068 - Exploitation for Privilege Escalation

## Risk Assessment

TraceLock evaluates correlated activity using security risk factors such as:

- Authentication failures
- Successful authentication
- Command execution
- Privileged activity
- Authentication-to-access transitions
- Multi-stage attack progression

The resulting assessment includes a severity level and numerical risk score.

## Security Recommendations

Based on detected activity, TraceLock generates prioritized recommendations such as:

- Investigating authentication failures
- Reviewing successful authentication
- Inspecting executed commands
- Investigating privileged activity
- Preserving logs and investigating the complete attack sequence

Recommendations are assigned priorities such as HIGH and URGENT.

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

## Purpose

TraceLock is intended as a security-analysis and learning project demonstrating how security events can be transformed into correlated attack narratives and actionable findings.

## Security Notice

TraceLock is designed for authorized defensive security analysis, testing, education, and research.

Only analyze logs and systems that you are authorized to access.

## License

This project is provided for educational and security research purposes.
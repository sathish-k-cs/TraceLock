from dataclasses import dataclass
from datetime import timedelta

from .correlator import AttackChain


@dataclass
class AnomalyFinding:
    name: str
    score: int
    severity: str
    description: str


@dataclass
class AnomalyProfile:
    score: int
    severity: str
    findings: list[AnomalyFinding]


def analyze_anomaly(chain: AttackChain) -> AnomalyProfile:
    events = sorted(
        chain.events,
        key=lambda event: event.timestamp,
    )

    findings = []

    if not events:
        return AnomalyProfile(
            score=0,
            severity="LOW",
            findings=[],
        )

    event_types = {
        event.event_type
        for event in events
    }

    login_failures = sum(
        event.event_type == "LOGIN_FAILURE"
        for event in events
    )

    if login_failures >= 3:
        findings.append(
            AnomalyFinding(
                name="Authentication Burst",
                score=25,
                severity="HIGH",
                description=(
                    f"{login_failures} authentication failures "
                    "occurred in a short period."
                ),
            )
        )

    if {
        "LOGIN_FAILURE",
        "LOGIN_SUCCESS",
    }.issubset(event_types):

        findings.append(
            AnomalyFinding(
                name="Failure-to-Success Transition",
                score=25,
                severity="CRITICAL",
                description=(
                    "Authentication failures were followed by "
                    "successful authentication."
                ),
            )
        )

    if {
        "LOGIN_SUCCESS",
        "COMMAND_EXECUTION",
    }.issubset(event_types):

        findings.append(
            AnomalyFinding(
                name="Post-Authentication Execution",
                score=20,
                severity="HIGH",
                description=(
                    "Command execution occurred after successful "
                    "authentication."
                ),
            )
        )

    if {
        "COMMAND_EXECUTION",
        "PRIVILEGE_ACTIVITY",
    }.issubset(event_types):

        findings.append(
            AnomalyFinding(
                name="Execution-to-Privilege Transition",
                score=20,
                severity="CRITICAL",
                description=(
                    "Privileged activity followed command execution."
                ),
            )
        )

    duration = events[-1].timestamp - events[0].timestamp

    if duration <= timedelta(seconds=60) and len(events) >= 5:
        findings.append(
            AnomalyFinding(
                name="Rapid Attack Progression",
                score=15,
                severity="HIGH",
                description=(
                    f"{len(events)} related events occurred within "
                    f"{int(duration.total_seconds())} seconds."
                ),
            )
        )

    score = min(
        sum(finding.score for finding in findings),
        100,
    )

    if score >= 75:
        severity = "CRITICAL"
    elif score >= 50:
        severity = "HIGH"
    elif score >= 25:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    return AnomalyProfile(
        score=score,
        severity=severity,
        findings=findings,
    )
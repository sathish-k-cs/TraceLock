from dataclasses import dataclass
from datetime import timedelta

from .correlator import AttackChain


@dataclass
class Evidence:
    category: str
    title: str
    description: str
    severity: str


def build_evidence(chain: AttackChain) -> list[Evidence]:
    events = sorted(
        chain.events,
        key=lambda event: event.timestamp,
    )

    evidence = []

    event_types = {
        event.event_type
        for event in events
    }

    # ---------------------------------------------------------
    # INITIAL ACCESS
    # ---------------------------------------------------------

    login_failures = [
        event
        for event in events
        if event.event_type == "LOGIN_FAILURE"
    ]

    if login_failures:
        count = len(login_failures)

        severity = "HIGH" if count >= 3 else "MEDIUM"

        evidence.append(
            Evidence(
                category="INITIAL ACCESS",
                title="Credential Attack Activity",
                description=(
                    f"{count} authentication failures detected "
                    "from the correlated source."
                ),
                severity=severity,
            )
        )

    # ---------------------------------------------------------
    # ACCESS GAINED
    # ---------------------------------------------------------

    successes = [
        event
        for event in events
        if event.event_type == "LOGIN_SUCCESS"
    ]

    if successes:
        first_failure = (
            login_failures[0]
            if login_failures
            else None
        )

        first_success = successes[0]

        if first_failure:
            delay = (
                first_success.timestamp
                - first_failure.timestamp
            )

            seconds = int(delay.total_seconds())

            description = (
                "Successful authentication occurred "
                f"{seconds} seconds after the first "
                "authentication failure."
            )
        else:
            description = (
                "Successful authentication was observed "
                "within the correlated attack sequence."
            )

        evidence.append(
            Evidence(
                category="ACCESS GAINED",
                title="Authentication Transition",
                description=description,
                severity="CRITICAL",
            )
        )

    # ---------------------------------------------------------
    # EXECUTION
    # ---------------------------------------------------------

    command_events = [
        event
        for event in events
        if event.event_type == "COMMAND_EXECUTION"
    ]

    if command_events:
        evidence.append(
            Evidence(
                category="EXECUTION",
                title="Command Execution",
                description=(
                    "Command execution was observed after "
                    "authentication activity."
                ),
                severity="HIGH",
            )
        )

    # ---------------------------------------------------------
    # PRIVILEGE
    # ---------------------------------------------------------

    privilege_events = [
        event
        for event in events
        if event.event_type == "PRIVILEGE_ACTIVITY"
    ]

    if privilege_events:
        evidence.append(
            Evidence(
                category="PRIVILEGE",
                title="Privileged Activity",
                description=(
                    "Privileged activity was observed within "
                    "the correlated attack sequence."
                ),
                severity="CRITICAL",
            )
        )

    # ---------------------------------------------------------
    # CORRELATION
    # ---------------------------------------------------------

    if len(events) >= 2:
        start = events[0].timestamp
        end = events[-1].timestamp

        duration = int(
            (end - start).total_seconds()
        )

        if {
            "LOGIN_FAILURE",
            "LOGIN_SUCCESS",
            "COMMAND_EXECUTION",
            "PRIVILEGE_ACTIVITY",
        }.issubset(event_types):

            description = (
                "Authentication failures, successful access, "
                "command execution, and privileged activity "
                f"were correlated within {duration} seconds."
            )

            evidence.append(
                Evidence(
                    category="CORRELATION",
                    title="Multi-Stage Attack Sequence",
                    description=description,
                    severity="CRITICAL",
                )
            )

    return evidence
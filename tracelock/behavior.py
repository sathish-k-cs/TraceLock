from dataclasses import dataclass

from .correlator import AttackChain


@dataclass
class BehaviorProfile:
    name: str
    confidence: int
    description: str
    indicators: list[str]


def analyze_behavior(chain: AttackChain) -> BehaviorProfile:
    events = sorted(
        chain.events,
        key=lambda event: event.timestamp,
    )

    event_types = {
        event.event_type
        for event in events
    }

    login_failures = sum(
        event.event_type == "LOGIN_FAILURE"
        for event in events
    )

    has_success = "LOGIN_SUCCESS" in event_types
    has_command = "COMMAND_EXECUTION" in event_types
    has_privilege = "PRIVILEGE_ACTIVITY" in event_types

    indicators = []

    # ---------------------------------------------------------
    # CREDENTIAL ATTACK → ACCESS → EXECUTION → PRIVILEGE
    # ---------------------------------------------------------

    if (
        login_failures >= 3
        and has_success
        and has_command
        and has_privilege
    ):
        indicators.extend(
            [
                f"{login_failures} authentication failures",
                "successful authentication",
                "post-authentication command execution",
                "privileged activity",
            ]
        )

        return BehaviorProfile(
            name="Credential Compromise → Privilege Escalation",
            confidence=95,
            description=(
                "The event sequence strongly resembles a credential "
                "compromise followed by successful access, execution, "
                "and privileged activity."
            ),
            indicators=indicators,
        )

    # ---------------------------------------------------------
    # CREDENTIAL ATTACK → SUCCESSFUL ACCESS
    # ---------------------------------------------------------

    if login_failures >= 3 and has_success:
        indicators.extend(
            [
                f"{login_failures} authentication failures",
                "successful authentication",
            ]
        )

        return BehaviorProfile(
            name="Credential Attack → Successful Access",
            confidence=85,
            description=(
                "Repeated authentication failures followed by "
                "successful access indicate possible credential "
                "attack activity."
            ),
            indicators=indicators,
        )

    # ---------------------------------------------------------
    # SUCCESS → COMMAND EXECUTION
    # ---------------------------------------------------------

    if has_success and has_command:
        indicators.extend(
            [
                "successful authentication",
                "command execution",
            ]
        )

        return BehaviorProfile(
            name="Authenticated Execution",
            confidence=75,
            description=(
                "Command execution occurred after successful "
                "authentication."
            ),
            indicators=indicators,
        )

    # ---------------------------------------------------------
    # PRIVILEGED ACTIVITY
    # ---------------------------------------------------------

    if has_privilege:
        indicators.append(
            "privileged activity"
        )

        return BehaviorProfile(
            name="Privileged Activity",
            confidence=65,
            description=(
                "Privileged activity was observed in the "
                "correlated security sequence."
            ),
            indicators=indicators,
        )

    # ---------------------------------------------------------
    # GENERAL SUSPICIOUS ACTIVITY
    # ---------------------------------------------------------

    indicators = [
        event.event_type
        for event in events
    ]

    return BehaviorProfile(
        name="Suspicious Multi-Event Activity",
        confidence=50,
        description=(
            "Multiple related security events were correlated, "
            "but the sequence does not match a stronger "
            "behavioral fingerprint."
        ),
        indicators=indicators,
    )
from dataclasses import dataclass

from .correlator import AttackChain


@dataclass
class RiskAssessment:
    score: int
    level: str
    factors: list[str]


def assess_risk(chain: AttackChain) -> RiskAssessment:
    score = 0
    factors = []

    event_types = {event.event_type for event in chain.events}

    failure_count = sum(
        1
        for event in chain.events
        if event.event_type == "LOGIN_FAILURE"
    )

    if failure_count >= 5:
        score += 30
        factors.append(
            f"{failure_count} authentication failures detected"
        )
    elif failure_count >= 3:
        score += 20
        factors.append(
            f"{failure_count} authentication failures detected"
        )
    elif failure_count >= 1:
        score += 10
        factors.append(
            "Authentication failure detected"
        )

    if "LOGIN_SUCCESS" in event_types:
        score += 20
        factors.append(
            "Successful authentication occurred"
        )

    if "COMMAND_EXECUTION" in event_types:
        score += 20
        factors.append(
            "Command execution detected"
        )

    if "PRIVILEGE_ACTIVITY" in event_types:
        score += 30
        factors.append(
            "Privileged activity detected"
        )

    if {
        "LOGIN_FAILURE",
        "LOGIN_SUCCESS",
    }.issubset(event_types):
        score += 10
        factors.append(
            "Authentication failures were followed by successful access"
        )

    score = min(score, 100)

    if score >= 80:
        level = "CRITICAL"
    elif score >= 60:
        level = "HIGH"
    elif score >= 30:
        level = "MEDIUM"
    else:
        level = "LOW"

    return RiskAssessment(
        score=score,
        level=level,
        factors=factors,
    )
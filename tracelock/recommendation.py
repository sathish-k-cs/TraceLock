from dataclasses import dataclass

from .correlator import AttackChain


@dataclass
class Recommendation:
    priority: str
    title: str
    description: str


def build_recommendations(
    chain: AttackChain,
) -> list[Recommendation]:

    recommendations = []

    event_types = {
        event.event_type
        for event in chain.events
    }

    source = find_source(chain)

    if "LOGIN_FAILURE" in event_types:
        recommendations.append(
            Recommendation(
                priority="HIGH",
                title="Investigate Authentication Failures",
                description=(
                    f"Review repeated authentication failures "
                    f"associated with {source}."
                ),
            )
        )

    if {
        "LOGIN_FAILURE",
        "LOGIN_SUCCESS",
    }.issubset(event_types):

        recommendations.append(
            Recommendation(
                priority="URGENT",
                title="Investigate Successful Authentication",
                description=(
                    "Review the successful authentication that "
                    "followed the authentication failures."
                ),
            )
        )

    if "COMMAND_EXECUTION" in event_types:
        recommendations.append(
            Recommendation(
                priority="HIGH",
                title="Review Executed Commands",
                description=(
                    "Inspect commands executed after authentication "
                    "for malicious or unauthorized activity."
                ),
            )
        )

    if "PRIVILEGE_ACTIVITY" in event_types:
        recommendations.append(
            Recommendation(
                priority="URGENT",
                title="Investigate Privileged Activity",
                description=(
                    "Review privileged actions and determine whether "
                    "the account legitimately required elevated access."
                ),
            )
        )

    if {
        "LOGIN_FAILURE",
        "LOGIN_SUCCESS",
        "COMMAND_EXECUTION",
        "PRIVILEGE_ACTIVITY",
    }.issubset(event_types):

        recommendations.append(
            Recommendation(
                priority="URGENT",
                title="Investigate Complete Attack Sequence",
                description=(
                    "The correlated events indicate a possible "
                    "multi-stage compromise. Preserve logs and "
                    "investigate the affected host and account."
                ),
            )
        )

    return recommendations


def find_source(chain: AttackChain) -> str:

    for event in chain.events:
        if event.ip:
            return event.ip

    for event in chain.events:
        if event.user:
            return f"user:{event.user}"

    return "unknown"
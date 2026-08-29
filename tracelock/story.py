from dataclasses import dataclass

from .correlator import AttackChain
from .risk import RiskAssessment


@dataclass
class Story:
    title: str
    summary: str
    timeline: list[str]
    conclusion: str


def build_story(
    chain: AttackChain,
    assessment: RiskAssessment,
) -> Story:

    events = sorted(
        chain.events,
        key=lambda event: event.timestamp,
    )

    timeline = build_timeline(events)

    title = build_title(events, assessment)

    summary = build_summary(events)

    conclusion = build_conclusion(
        events,
        assessment,
    )

    return Story(
        title=title,
        summary=summary,
        timeline=timeline,
        conclusion=conclusion,
    )


def build_timeline(events) -> list[str]:
    """
    Convert raw security events into a readable attack narrative.

    The timeline deliberately preserves chronological order so that
    investigators can see how one event led to another.
    """

    timeline = []

    previous_type = None

    for event in events:

        timestamp = event.timestamp.strftime("%H:%M:%S")

        description = describe_event(event.event_type)

        stage = determine_stage(
            event.event_type,
            previous_type,
        )

        timeline.append(
            f"{timestamp}  [{stage}] {description}"
        )

        previous_type = event.event_type

    return timeline


def determine_stage(
    event_type: str,
    previous_type: str | None,
) -> str:
    """
    Assign an investigative stage to each event.
    """

    if event_type == "LOGIN_FAILURE":
        return "INITIAL ACCESS"

    if event_type == "LOGIN_SUCCESS":

        if previous_type == "LOGIN_FAILURE":
            return "ACCESS GAINED"

        return "AUTHENTICATION"

    if event_type == "COMMAND_EXECUTION":
        return "EXECUTION"

    if event_type == "PRIVILEGE_ACTIVITY":
        return "PRIVILEGE"

    if event_type == "CONNECTION":
        return "NETWORK"

    return "UNKNOWN"


def describe_event(event_type: str) -> str:

    descriptions = {
        "LOGIN_FAILURE":
            "Authentication failure detected",

        "LOGIN_SUCCESS":
            "Successful authentication detected",

        "COMMAND_EXECUTION":
            "Command execution detected",

        "PRIVILEGE_ACTIVITY":
            "Privileged activity detected",

        "CONNECTION":
            "Network connection detected",

        "UNKNOWN":
            "Unclassified security event detected",
    }

    return descriptions.get(
        event_type,
        "Security event detected",
    )


def build_title(
    events,
    assessment: RiskAssessment,
) -> str:

    event_types = {
        event.event_type
        for event in events
    }

    if {
        "LOGIN_FAILURE",
        "LOGIN_SUCCESS",
        "COMMAND_EXECUTION",
        "PRIVILEGE_ACTIVITY",
    }.issubset(event_types):

        return (
            "Credential Attack → Successful Access → "
            "Command Execution → Privileged Activity"
        )

    if {
        "LOGIN_FAILURE",
        "LOGIN_SUCCESS",
        "PRIVILEGE_ACTIVITY",
    }.issubset(event_types):

        return (
            "Possible Credential Attack With "
            "Privilege Escalation"
        )

    if {
        "LOGIN_FAILURE",
        "LOGIN_SUCCESS",
    }.issubset(event_types):

        return "Possible Authentication Attack"

    if "PRIVILEGE_ACTIVITY" in event_types:

        return "Suspicious Privileged Activity"

    if "COMMAND_EXECUTION" in event_types:

        return "Suspicious Command Execution"

    return (
        f"Suspicious Activity Detected "
        f"({assessment.level})"
    )


def build_summary(events) -> str:

    event_types = {
        event.event_type
        for event in events
    }

    failure_count = sum(
        1
        for event in events
        if event.event_type == "LOGIN_FAILURE"
    )

    if {
        "LOGIN_FAILURE",
        "LOGIN_SUCCESS",
        "COMMAND_EXECUTION",
        "PRIVILEGE_ACTIVITY",
    }.issubset(event_types):

        return (
            f"{failure_count} authentication failures were "
            "followed by successful authentication, command "
            "execution, and privileged activity from the "
            "same correlated source."
        )

    if {
        "LOGIN_FAILURE",
        "LOGIN_SUCCESS",
    }.issubset(event_types):

        return (
            f"{failure_count} authentication failures were "
            "followed by successful authentication from the "
            "same correlated source."
        )

    if "PRIVILEGE_ACTIVITY" in event_types:

        return (
            "Privileged activity was observed within the "
            "correlated security event sequence."
        )

    return (
        "Multiple related security events were observed "
        "within the correlation window."
    )


def build_conclusion(
    events,
    assessment: RiskAssessment,
) -> str:

    source = find_source(events)

    duration = calculate_duration(events)

    return (
        f"TraceLock assessed this activity as "
        f"{assessment.level} risk "
        f"({assessment.score}/100). "
        f"The correlated sequence lasted {duration} "
        f"and originated primarily from {source}."
    )


def calculate_duration(events) -> str:

    if len(events) < 2:
        return "0 seconds"

    duration = (
        events[-1].timestamp -
        events[0].timestamp
    )

    total_seconds = int(
        duration.total_seconds()
    )

    if total_seconds < 60:
        return f"{total_seconds} seconds"

    minutes, seconds = divmod(
        total_seconds,
        60,
    )

    return f"{minutes} minutes {seconds} seconds"


def find_source(events) -> str:

    for event in events:
        if event.ip:
            return event.ip

    for event in events:
        if event.user:
            return f"user:{event.user}"

    return "unknown"
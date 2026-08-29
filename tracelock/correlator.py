from dataclasses import dataclass
from datetime import timedelta

from .parser import LogEvent


@dataclass
class AttackChain:
    events: list[LogEvent]
    reason: str
    score: int


WINDOW = timedelta(minutes=5)


def same_source(first: LogEvent, second: LogEvent) -> bool:
    """
    Determine whether two events are likely related to the same source.

    Prefer IP correlation when both events contain an IP.
    Otherwise fall back to username correlation.
    """
    if first.ip and second.ip:
        return first.ip == second.ip

    if first.user and second.user:
        return first.user == second.user

    return False


def build_chains(events: list[LogEvent]) -> list[AttackChain]:
    """
    Build coherent attack chains instead of producing overlapping
    chains starting from every individual event.

    Events are sorted chronologically and grouped when they share
    a source and remain inside the correlation window.
    """

    if not events:
        return []

    events = sorted(events, key=lambda event: event.timestamp)

    chains: list[AttackChain] = []
    current_chain: list[LogEvent] = [events[0]]

    for event in events[1:]:
        first_event = current_chain[0]

        within_window = (
            event.timestamp - first_event.timestamp <= WINDOW
        )

        related_source = same_source(first_event, event)

        if within_window and related_source:
            current_chain.append(event)
        else:
            finalize_chain(current_chain, chains)
            current_chain = [event]

    finalize_chain(current_chain, chains)

    return chains


def finalize_chain(
    chain: list[LogEvent],
    chains: list[AttackChain],
) -> None:
    """
    Convert an event group into an AttackChain when it contains
    enough evidence to represent a meaningful security sequence.
    """

    if len(chain) < 2:
        return

    event_types = {event.event_type for event in chain}

    score = calculate_chain_score(event_types, chain)

    reason = explain_chain(event_types, chain)

    chains.append(
        AttackChain(
            events=chain,
            reason=reason,
            score=score,
        )
    )


def calculate_chain_score(
    event_types: set[str],
    events: list[LogEvent],
) -> int:
    """
    Calculate a risk score based on the complete attack sequence.

    Sequence-based combinations receive additional weight because
    they provide stronger evidence than isolated events.
    """

    score = 0

    failures = sum(
        1 for event in events
        if event.event_type == "LOGIN_FAILURE"
    )

    if "LOGIN_FAILURE" in event_types:
        score += 20

        if failures >= 3:
            score += 10

    if "LOGIN_SUCCESS" in event_types:
        score += 20

    if "COMMAND_EXECUTION" in event_types:
        score += 20

    if "PRIVILEGE_ACTIVITY" in event_types:
        score += 30

    # Strong sequence: failed logins → successful login.
    if {
        "LOGIN_FAILURE",
        "LOGIN_SUCCESS",
    }.issubset(event_types):
        score += 10

    # Very strong sequence: authentication attack followed by
    # privileged activity.
    if {
        "LOGIN_FAILURE",
        "LOGIN_SUCCESS",
        "PRIVILEGE_ACTIVITY",
    }.issubset(event_types):
        score += 10

    return min(score, 100)


def explain_chain(
    event_types: set[str],
    events: list[LogEvent],
) -> str:
    """
    Generate an explanation based on the complete observed sequence.
    """

    failures = sum(
        1 for event in events
        if event.event_type == "LOGIN_FAILURE"
    )

    if {
        "LOGIN_FAILURE",
        "LOGIN_SUCCESS",
        "COMMAND_EXECUTION",
        "PRIVILEGE_ACTIVITY",
    }.issubset(event_types):
        return (
            f"{failures} authentication failures were followed by "
            "successful authentication, command execution, and "
            "privileged activity from the same source."
        )

    if {
        "LOGIN_FAILURE",
        "LOGIN_SUCCESS",
        "PRIVILEGE_ACTIVITY",
    }.issubset(event_types):
        return (
            f"{failures} authentication failures were followed by "
            "successful authentication and privileged activity."
        )

    if {
        "LOGIN_FAILURE",
        "LOGIN_SUCCESS",
    }.issubset(event_types):
        return (
            f"{failures} authentication failures were followed by "
            "successful authentication from the same source."
        )

    if {
        "LOGIN_SUCCESS",
        "COMMAND_EXECUTION",
        "PRIVILEGE_ACTIVITY",
    }.issubset(event_types):
        return (
            "Successful authentication was followed by command "
            "execution and privileged activity."
        )

    if {
        "LOGIN_SUCCESS",
        "COMMAND_EXECUTION",
    }.issubset(event_types):
        return (
            "Successful authentication was followed by command execution."
        )

    if "PRIVILEGE_ACTIVITY" in event_types:
        return (
            "Privileged activity was observed within a correlated "
            "security event sequence."
        )

    if "LOGIN_FAILURE" in event_types:
        return (
            f"{failures} authentication failures originated from "
            "the same source."
        )

    return (
        "Multiple related security events originated from "
        "the same source."
    )


def merge_duplicate_chains(
    chains: list[AttackChain],
) -> list[AttackChain]:
    """
    Remove genuinely identical chains.

    This remains as a safety mechanism even though build_chains()
    now prevents the overlapping-chain problem.
    """

    unique: list[AttackChain] = []
    seen = set()

    for chain in chains:
        key = tuple(
            (
                event.timestamp,
                event.source,
                event.event_type,
                event.message,
            )
            for event in chain.events
        )

        if key in seen:
            continue

        seen.add(key)
        unique.append(chain)

    return unique
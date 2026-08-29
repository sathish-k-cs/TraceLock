import re
from dataclasses import dataclass
from datetime import datetime
from typing import Optional


@dataclass
class LogEvent:
    timestamp: datetime
    source: str
    event_type: str
    message: str
    ip: Optional[str] = None
    user: Optional[str] = None


IP_PATTERN = re.compile(
    r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
)

USER_PATTERN = re.compile(
    r"(?:user|for)\s+([A-Za-z0-9._-]+)"
)


def extract_ip(message: str) -> Optional[str]:
    match = IP_PATTERN.search(message)
    return match.group(0) if match else None


def extract_user(message: str) -> Optional[str]:
    match = USER_PATTERN.search(message, re.IGNORECASE)
    return match.group(1) if match else None


def classify_event(message: str) -> str:
    text = message.lower()

    if "failed password" in text or "authentication failure" in text:
        return "LOGIN_FAILURE"

    if "accepted password" in text or "accepted publickey" in text:
        return "LOGIN_SUCCESS"

    if "sudo" in text or "privilege" in text:
        return "PRIVILEGE_ACTIVITY"

    if "command" in text or "exec" in text:
        return "COMMAND_EXECUTION"

    if "connection" in text:
        return "CONNECTION"

    return "UNKNOWN"


def parse_line(line: str) -> Optional[LogEvent]:
    line = line.strip()

    if not line:
        return None

    parts = line.split("|", 3)

    if len(parts) != 4:
        return None

    timestamp_text, source, event_type, message = parts

    try:
        timestamp = datetime.fromisoformat(timestamp_text)
    except ValueError:
        return None

    detected_type = classify_event(message)

    if event_type.strip():
        detected_type = event_type.strip()

    return LogEvent(
        timestamp=timestamp,
        source=source.strip(),
        event_type=detected_type,
        message=message.strip(),
        ip=extract_ip(message),
        user=extract_user(message),
    )


def parse_file(path: str) -> list[LogEvent]:
    events = []

    with open(path, "r", encoding="utf-8") as file:
        for line in file:
            event = parse_line(line)

            if event is not None:
                events.append(event)

    events.sort(key=lambda event: event.timestamp)

    return events
import json
from dataclasses import asdict

from .correlator import AttackChain
from .risk import RiskAssessment
from .story import Story
from .mitre import MitreTechnique


def format_report(
    chains: list[AttackChain],
    assessments: list[RiskAssessment],
    stories: list[Story],
    mitre_mappings: list[list[MitreTechnique]],
) -> str:

    lines = []

    lines.append("=" * 70)
    lines.append("TRACELOCK SECURITY ANALYSIS")
    lines.append("=" * 70)
    lines.append("")

    lines.append(f"Attack chains detected: {len(chains)}")
    lines.append("")

    for index, (chain, assessment, story, techniques) in enumerate(
        zip(
            chains,
            assessments,
            stories,
            mitre_mappings,
        ),
        start=1,
    ):
        lines.append("-" * 70)
        lines.append(f"ATTACK CHAIN #{index}")
        lines.append("-" * 70)

        lines.append(f"Title:  {story.title}")
        lines.append(f"Risk:   {assessment.level}")
        lines.append(f"Score:  {assessment.score}/100")
        lines.append("")

        lines.append("Summary:")
        lines.append(story.summary)
        lines.append("")

        lines.append("Timeline:")

        for event in story.timeline:
            lines.append(f"  {event}")

        lines.append("")

        lines.append("MITRE ATT&CK:")

        if techniques:
            for technique in techniques:
                lines.append(
                    f"  {technique.technique_id}  "
                    f"{technique.name} "
                    f"[{technique.tactic}]"
                )
        else:
            lines.append("  No mapped techniques.")

        lines.append("")

        lines.append("Risk factors:")

        for factor in assessment.factors:
            lines.append(f"  - {factor}")

        lines.append("")

        lines.append("Conclusion:")
        lines.append(story.conclusion)
        lines.append("")

    lines.append("=" * 70)
    lines.append("END OF TRACELOCK ANALYSIS")
    lines.append("=" * 70)

    return "\n".join(lines)


def build_json_report(
    chains: list[AttackChain],
    assessments: list[RiskAssessment],
    stories: list[Story],
    mitre_mappings: list[list[MitreTechnique]],
) -> str:

    report = {
        "tool": "TraceLock",
        "chains_detected": len(chains),
        "chains": [],
    }

    for chain, assessment, story, techniques in zip(
        chains,
        assessments,
        stories,
        mitre_mappings,
    ):
        report["chains"].append(
            {
                "risk": asdict(assessment),
                "story": asdict(story),
                "mitre_attack": [
                    asdict(technique)
                    for technique in techniques
                ],
                "events": [
                    {
                        "timestamp": event.timestamp.isoformat(),
                        "source": event.source,
                        "event_type": event.event_type,
                        "message": event.message,
                        "ip": event.ip,
                        "user": event.user,
                    }
                    for event in chain.events
                ],
            }
        )

    return json.dumps(
        report,
        indent=2,
    )


def save_report(
    path: str,
    content: str,
) -> None:

    with open(
        path,
        "w",
        encoding="utf-8",
    ) as file:
        file.write(content)
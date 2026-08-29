import json
from dataclasses import asdict

from .correlator import AttackChain
from .evidence import Evidence
from .mitre import MitreTechnique
from .risk import RiskAssessment
from .story import Story


def format_report(
    chains: list[AttackChain],
    assessments: list[RiskAssessment],
    stories: list[Story],
    mitre_mappings: list[list[MitreTechnique]],
    evidence_mappings: list[list[Evidence]],
) -> str:

    lines = []

    lines.append("=" * 70)
    lines.append("TRACELOCK SECURITY ANALYSIS")
    lines.append("=" * 70)
    lines.append("")

    lines.append(f"Attack chains detected: {len(chains)}")
    lines.append("")

    for index, (chain, assessment, story) in enumerate(
        zip(chains, assessments, stories),
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

        # MITRE ATT&CK mapping
        techniques = (
            mitre_mappings[index - 1]
            if index - 1 < len(mitre_mappings)
            else []
        )

        if techniques:
            lines.append("MITRE ATT&CK:")

            for technique in techniques:
                lines.append(
                    f"  {technique.technique_id}  "
                    f"{technique.name} "
                    f"[{technique.tactic}]"
                )

            lines.append("")

        # Evidence
        evidence = (
            evidence_mappings[index - 1]
            if index - 1 < len(evidence_mappings)
            else []
        )

        if evidence:
            lines.append("Evidence:")

            for item in evidence:
                lines.append(
                    f"  [{item.severity}] "
                    f"{item.category}: "
                    f"{item.title}"
                )
                lines.append(
                    f"      {item.description}"
                )

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
    evidence_mappings: list[list[Evidence]],
) -> str:

    report = {
        "tool": "TraceLock",
        "chains_detected": len(chains),
        "chains": [],
    }

    for index, (chain, assessment, story) in enumerate(
        zip(chains, assessments, stories)
    ):
        techniques = (
            mitre_mappings[index]
            if index < len(mitre_mappings)
            else []
        )

        evidence = (
            evidence_mappings[index]
            if index < len(evidence_mappings)
            else []
        )

        report["chains"].append(
            {
                "risk": asdict(assessment),
                "story": asdict(story),
                "mitre_attack": [
                    asdict(technique)
                    for technique in techniques
                ],
                "evidence": [
                    asdict(item)
                    for item in evidence
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
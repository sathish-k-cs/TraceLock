import json
from dataclasses import asdict
from pathlib import Path

from .correlator import AttackChain
from .risk import RiskAssessment
from .story import Story
from .mitre import MitreTechnique
from .evidence import Evidence
from .behavior import BehaviorProfile
from .anomaly import AnomalyProfile
from .recommendation import Recommendation


def format_report(
    chains: list[AttackChain],
    assessments: list[RiskAssessment],
    stories: list[Story],
    mitre_mappings: list[list[MitreTechnique]],
    evidence_mappings: list[list[Evidence]],
    behavior_profiles: list[BehaviorProfile],
    anomaly_profiles: list[AnomalyProfile],
    recommendation_mappings: list[list[Recommendation]],
) -> str:

    lines = []

    lines.append("=" * 70)
    lines.append("TRACELOCK SECURITY ANALYSIS")
    lines.append("=" * 70)
    lines.append("")

    lines.append(f"Attack chains detected: {len(chains)}")
    lines.append("")

    for index, (
        chain,
        assessment,
        story,
        techniques,
        evidence_items,
        behavior,
        anomaly,
        recommendations,
    ) in enumerate(
        zip(
            chains,
            assessments,
            stories,
            mitre_mappings,
            evidence_mappings,
            behavior_profiles,
            anomaly_profiles,
            recommendation_mappings,
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

        for technique in techniques:
            lines.append(
                f"  {technique.technique_id}  "
                f"{technique.name} "
                f"[{technique.tactic}]"
            )

        lines.append("")

        lines.append("Evidence:")

        for item in evidence_items:
            lines.append(
                f"  [{item.severity}] "
                f"{item.category}: {item.title}"
            )
            lines.append(
                f"      {item.description}"
            )

        lines.append("")

        lines.append("Behavior Profile:")
        lines.append(
            f"  {behavior.name}"
        )
        lines.append(
            f"  Confidence: {behavior.confidence}%"
        )
        lines.append(
            f"  {behavior.description}"
        )

        lines.append("  Indicators:")

        for indicator in behavior.indicators:
            lines.append(
                f"    - {indicator}"
            )

        lines.append("")

        lines.append("Anomaly Analysis:")
        lines.append(
            f"  Score: {anomaly.score}/100"
        )
        lines.append(
            f"  Severity: {anomaly.severity}"
        )

        for finding in anomaly.findings:
            lines.append(
                f"  - {finding.name} "
                f"[{finding.severity}]"
            )
            lines.append(
                f"    {finding.description}"
            )

        lines.append("")

        lines.append("Recommendations:")

        for recommendation in recommendations:
            lines.append(
                f"  [{recommendation.priority}] "
                f"{recommendation.title}"
            )
            lines.append(
                f"    {recommendation.description}"
            )

        lines.append("")

        lines.append("Risk factors:")

        for factor in assessment.factors:
            lines.append(
                f"  - {factor}"
            )

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
    behavior_profiles: list[BehaviorProfile],
    anomaly_profiles: list[AnomalyProfile],
    recommendation_mappings: list[list[Recommendation]],
) -> str:

    report = {
        "tool": "TraceLock",
        "chains_detected": len(chains),
        "chains": [],
    }

    for (
        chain,
        assessment,
        story,
        techniques,
        evidence_items,
        behavior,
        anomaly,
        recommendations,
    ) in zip(
        chains,
        assessments,
        stories,
        mitre_mappings,
        evidence_mappings,
        behavior_profiles,
        anomaly_profiles,
        recommendation_mappings,
    ):
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
                    for item in evidence_items
                ],
                "behavior": asdict(behavior),
                "anomaly": asdict(anomaly),
                "events": [
                    {
                        "timestamp":
                            event.timestamp.isoformat(),
                        "source":
                            event.source,
                        "event_type":
                            event.event_type,
                        "message":
                            event.message,
                        "ip":
                            event.ip,
                        "user":
                            event.user,
                    }
                    for event in chain.events
                ],
                "recommendations": [
                    asdict(item)
                    for item in recommendations
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

    output_path = Path(path)
    output_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    output_path.write_text(
        content,
        encoding="utf-8",
    )
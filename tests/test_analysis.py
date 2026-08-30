from tracelock.parser import parse_file
from tracelock.correlator import build_chains
from tracelock.risk import assess_risk
from tracelock.story import build_story
from tracelock.mitre import map_attack_chain
from tracelock.evidence import build_evidence
from tracelock.behavior import analyze_behavior
from tracelock.anomaly import analyze_anomaly
from tracelock.recommendation import build_recommendations


def analyze(logfile):
    events = parse_file(logfile)
    chains = build_chains(events)

    results = []

    for chain in chains:
        assessment = assess_risk(chain)
        story = build_story(chain, assessment)
        mitre = map_attack_chain(chain)
        evidence = build_evidence(chain)
        behavior = analyze_behavior(chain)
        anomaly = analyze_anomaly(chain)
        recommendations = build_recommendations(chain)

        results.append({
            "assessment": assessment,
            "story": story,
            "mitre": mitre,
            "evidence": evidence,
            "behavior": behavior,
            "anomaly": anomaly,
            "recommendations": recommendations,
        })

    return events, chains, results


def test_normal_login():
    events, chains, results = analyze(
        "examples/normal_login.log"
    )

    assert len(events) > 0
    assert len(chains) == 0
    assert len(results) == 0


def test_brute_force():
    events, chains, results = analyze(
        "examples/brute_force.log"
    )

    assert len(chains) == 1

    result = results[0]

    assert result["assessment"].level == "MEDIUM"
    assert result["assessment"].score == 30

    assert any(
        technique.technique_id == "T1110"
        for technique in result["mitre"]
    )

    assert len(result["evidence"]) >= 1
    assert result["anomaly"].score > 0
    assert len(result["recommendations"]) >= 1


def test_command_activity():
    events, chains, results = analyze(
        "examples/command_activity.log"
    )

    assert len(chains) == 1

    result = results[0]

    assert result["assessment"].level == "HIGH"
    assert result["assessment"].score == 70

    assert any(
        technique.technique_id == "T1059"
        for technique in result["mitre"]
    )

    assert any(
        technique.technique_id == "T1068"
        for technique in result["mitre"]
    )

    assert result["behavior"].confidence > 0
    assert result["anomaly"].score > 0
    assert len(result["recommendations"]) >= 1


def test_full_attack_chain():
    events, chains, results = analyze(
        "examples/sample_attack.log"
    )

    assert len(chains) == 1

    result = results[0]

    assert result["assessment"].level == "CRITICAL"
    assert result["assessment"].score == 100

    technique_ids = {
        technique.technique_id
        for technique in result["mitre"]
    }

    assert technique_ids == {
        "T1110",
        "T1078",
        "T1059",
        "T1068",
    }

    assert len(result["evidence"]) == 5

    assert (
        result["behavior"].name
        == "Credential Compromise → Privilege Escalation"
    )

    assert result["behavior"].confidence == 95

    assert result["anomaly"].score == 100
    assert result["anomaly"].severity == "CRITICAL"

    assert len(result["anomaly"].findings) == 5
    assert len(result["recommendations"]) == 5
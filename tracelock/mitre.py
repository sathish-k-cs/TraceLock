from dataclasses import dataclass

from .correlator import AttackChain


@dataclass(frozen=True)
class MitreTechnique:
    technique_id: str
    name: str
    tactic: str
    reason: str


TECHNIQUES = {
    "BRUTE_FORCE": MitreTechnique(
        technique_id="T1110",
        name="Brute Force",
        tactic="Credential Access",
        reason=(
            "Repeated authentication failures may indicate "
            "attempts to guess or obtain valid credentials."
        ),
    ),

    "VALID_ACCOUNTS": MitreTechnique(
        technique_id="T1078",
        name="Valid Accounts",
        tactic="Defense Evasion / Persistence",
        reason=(
            "A successful authentication following repeated failures "
            "may indicate that valid credentials were obtained or abused."
        ),
    ),

    "COMMAND_EXECUTION": MitreTechnique(
        technique_id="T1059",
        name="Command and Scripting Interpreter",
        tactic="Execution",
        reason=(
            "Command execution after authentication can indicate "
            "post-compromise activity."
        ),
    ),

    "PRIVILEGE_ESCALATION": MitreTechnique(
        technique_id="T1068",
        name="Exploitation for Privilege Escalation",
        tactic="Privilege Escalation",
        reason=(
            "Privileged activity following authentication and execution "
            "may indicate an attempt to obtain elevated privileges."
        ),
    ),
}


def map_attack_chain(chain: AttackChain) -> list[MitreTechnique]:
    """
    Map observed event patterns to likely MITRE ATT&CK techniques.

    This is a behavioral mapping, not a claim that a specific
    technique was definitively used.
    """

    event_types = {
        event.event_type
        for event in chain.events
    }

    techniques = []

    if "LOGIN_FAILURE" in event_types:
        techniques.append(TECHNIQUES["BRUTE_FORCE"])

    if "LOGIN_SUCCESS" in event_types:
        techniques.append(TECHNIQUES["VALID_ACCOUNTS"])

    if "COMMAND_EXECUTION" in event_types:
        techniques.append(TECHNIQUES["COMMAND_EXECUTION"])

    if "PRIVILEGE_ACTIVITY" in event_types:
        techniques.append(TECHNIQUES["PRIVILEGE_ESCALATION"])

    return techniques
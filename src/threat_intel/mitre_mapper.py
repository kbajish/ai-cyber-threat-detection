from dataclasses import dataclass
from typing import Optional


@dataclass
class MitreMapping:
    technique_id:   str
    technique_name: str
    tactic:         str
    description:    str
    mitre_url:      str


ATTACK_MAP = {
    "DDoS": MitreMapping(
        technique_id   = "T1498",
        technique_name = "Network Denial of Service",
        tactic         = "Impact",
        description    = "Adversary floods network to degrade or block availability.",
        mitre_url      = "https://attack.mitre.org/techniques/T1498/"
    ),
    "PortScan": MitreMapping(
        technique_id   = "T1046",
        technique_name = "Network Service Discovery",
        tactic         = "Discovery",
        description    = "Adversary scans to enumerate open ports and services.",
        mitre_url      = "https://attack.mitre.org/techniques/T1046/"
    ),
    "Bot": MitreMapping(
        technique_id   = "T1071",
        technique_name = "Application Layer Protocol",
        tactic         = "Command and Control",
        description    = "Bot communicates with C2 over standard application protocols.",
        mitre_url      = "https://attack.mitre.org/techniques/T1071/"
    ),
    "FTP-Patator": MitreMapping(
        technique_id   = "T1110",
        technique_name = "Brute Force",
        tactic         = "Credential Access",
        description    = "Adversary attempts to gain access by brute-forcing FTP credentials.",
        mitre_url      = "https://attack.mitre.org/techniques/T1110/"
    ),
    "SSH-Patator": MitreMapping(
        technique_id   = "T1110.001",
        technique_name = "Password Guessing",
        tactic         = "Credential Access",
        description    = "Adversary attempts to guess SSH credentials systematically.",
        mitre_url      = "https://attack.mitre.org/techniques/T1110/001/"
    ),
    "Web Attack": MitreMapping(
        technique_id   = "T1190",
        technique_name = "Exploit Public-Facing Application",
        tactic         = "Initial Access",
        description    = "Adversary exploits vulnerability in internet-facing web application.",
        mitre_url      = "https://attack.mitre.org/techniques/T1190/"
    ),
    "Infiltration": MitreMapping(
        technique_id   = "T1078",
        technique_name = "Valid Accounts",
        tactic         = "Defense Evasion",
        description    = "Adversary uses valid credentials to maintain access.",
        mitre_url      = "https://attack.mitre.org/techniques/T1078/"
    ),
    "Heartbleed": MitreMapping(
        technique_id   = "T1557",
        technique_name = "Adversary-in-the-Middle",
        tactic         = "Credential Access",
        description    = "Exploitation of OpenSSL Heartbleed to extract memory contents.",
        mitre_url      = "https://attack.mitre.org/techniques/T1557/"
    ),
    "BENIGN": None,
}


def map_to_mitre(label: str) -> Optional[MitreMapping]:
    # Direct match first
    if label in ATTACK_MAP:
        return ATTACK_MAP[label]
    # Partial match fallback
    for key in ATTACK_MAP:
        if key.lower() in label.lower():
            return ATTACK_MAP[key]
    return None


if __name__ == "__main__":
    test_labels = [
        "DDoS", "PortScan", "Bot",
        "FTP-Patator", "SSH-Patator",
        "Web Attack", "Infiltration",
        "Heartbleed", "BENIGN"
    ]
    for label in test_labels:
        mapping = map_to_mitre(label)
        if mapping:
            print(f"{label:20s} → {mapping.technique_id} | {mapping.tactic}")
        else:
            print(f"{label:20s} → No mapping (benign)")
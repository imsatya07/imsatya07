"""Pure-function security heuristics. No I/O, no LLM — unit-testable."""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass


@dataclass
class Finding:
    severity: str
    rule: str
    detail: str


SSH_FAIL_RE = re.compile(
    r"Failed password for (?:invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+)"
)


def detect_ssh_bruteforce(auth_log: str, threshold: int = 5) -> list[Finding]:
    """Flag source IPs with >= threshold failed SSH logins."""
    ip_fail_counts: Counter[str] = Counter()
    for match in SSH_FAIL_RE.finditer(auth_log):
        ip_fail_counts[match.group(2)] += 1

    findings: list[Finding] = []
    for ip, count in ip_fail_counts.items():
        if count >= threshold:
            findings.append(
                Finding(
                    severity="high",
                    rule="ssh-bruteforce",
                    detail=f"{count} failed SSH logins from {ip}",
                )
            )
    return findings


PERMISSIVE_RE = re.compile(
    r"^\s*allow\s+(?P<proto>tcp|udp|any)\s+from\s+(?P<src>\S+)\s+to\s+(?P<dst>\S+)(?:\s+port\s+(?P<port>\S+))?",
    re.IGNORECASE | re.MULTILINE,
)


def detect_permissive_rules(firewall_conf: str) -> list[Finding]:
    """Flag firewall rules that accept from 0.0.0.0/0 on sensitive ports or all ports."""
    sensitive_ports = {"22", "3389", "3306", "5432", "6379", "27017"}
    findings: list[Finding] = []
    for match in PERMISSIVE_RE.finditer(firewall_conf):
        src = match.group("src")
        port = match.group("port")
        if src not in {"0.0.0.0/0", "any", "*"}:
            continue
        if port is None or port.lower() == "any":
            findings.append(
                Finding(
                    severity="critical",
                    rule="firewall-any-any",
                    detail=f"Rule allows {match.group('proto')} from {src} to all ports",
                )
            )
        elif port in sensitive_ports:
            findings.append(
                Finding(
                    severity="high",
                    rule="firewall-sensitive-port-open",
                    detail=f"Port {port} exposed to {src}",
                )
            )
    return findings

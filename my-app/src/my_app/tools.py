"""Tools exposed to the Claude agent."""

from __future__ import annotations

from pathlib import Path

from anthropic import beta_tool

from . import detectors


_DATA_ROOT: Path = Path.cwd()


def set_data_root(path: Path) -> None:
    global _DATA_ROOT
    _DATA_ROOT = path.resolve()


def _safe_path(relative: str) -> Path:
    target = (_DATA_ROOT / relative).resolve()
    if _DATA_ROOT not in target.parents and target != _DATA_ROOT:
        raise ValueError(f"Path {relative} escapes data root")
    return target


@beta_tool
def list_files() -> str:
    """List available log/config files in the triage workspace."""
    entries = sorted(p.name for p in _DATA_ROOT.iterdir() if p.is_file())
    return "\n".join(entries) if entries else "(workspace is empty)"


@beta_tool
def read_file(path: str, max_bytes: int = 20000) -> str:
    """Read a log or config file from the triage workspace.

    Args:
        path: Filename within the triage workspace.
        max_bytes: Maximum number of bytes to return (truncates long files).
    """
    target = _safe_path(path)
    data = target.read_bytes()[:max_bytes]
    return data.decode("utf-8", errors="replace")


@beta_tool
def scan_auth_log(path: str, fail_threshold: int = 5) -> str:
    """Heuristically scan an auth log for SSH brute-force patterns.

    Args:
        path: Auth log filename (e.g. auth.log).
        fail_threshold: Minimum failed logins from a single IP to flag as brute force.
    """
    content = _safe_path(path).read_text(errors="replace")
    findings = detectors.detect_ssh_bruteforce(content, threshold=fail_threshold)
    if not findings:
        return "No SSH brute-force indicators found."
    return "\n".join(f"[{f.severity}] {f.rule}: {f.detail}" for f in findings)


@beta_tool
def scan_firewall_config(path: str) -> str:
    """Heuristically scan a firewall config for overly permissive rules.

    Args:
        path: Firewall config filename.
    """
    content = _safe_path(path).read_text(errors="replace")
    findings = detectors.detect_permissive_rules(content)
    if not findings:
        return "No permissive firewall rules found."
    return "\n".join(f"[{f.severity}] {f.rule}: {f.detail}" for f in findings)


ALL_TOOLS = [list_files, read_file, scan_auth_log, scan_firewall_config]

from my_app.detectors import detect_permissive_rules, detect_ssh_bruteforce


def test_ssh_bruteforce_flags_repeated_failures():
    log = "\n".join(
        f"Apr 20 03:14:{i:02d} host sshd[1]: Failed password for invalid user root from 203.0.113.44 port 4100{i} ssh2"
        for i in range(6)
    )
    findings = detect_ssh_bruteforce(log, threshold=5)
    assert len(findings) == 1
    assert findings[0].severity == "high"
    assert "203.0.113.44" in findings[0].detail


def test_ssh_bruteforce_ignores_low_volume():
    log = (
        "Apr 20 03:14:00 host sshd[1]: Failed password for invalid user root "
        "from 198.51.100.1 port 41000 ssh2\n"
    )
    assert detect_ssh_bruteforce(log, threshold=5) == []


def test_ssh_bruteforce_respects_custom_threshold():
    log = "\n".join(
        f"Apr 20 03:14:{i:02d} host sshd[1]: Failed password for invalid user root from 203.0.113.44 port 4100{i} ssh2"
        for i in range(3)
    )
    assert detect_ssh_bruteforce(log, threshold=3)
    assert detect_ssh_bruteforce(log, threshold=4) == []


def test_firewall_detects_any_any_rule():
    conf = "allow any from 0.0.0.0/0 to 10.0.0.1 port any\n"
    findings = detect_permissive_rules(conf)
    assert len(findings) == 1
    assert findings[0].severity == "critical"
    assert findings[0].rule == "firewall-any-any"


def test_firewall_detects_sensitive_port_exposed():
    conf = "allow tcp from 0.0.0.0/0 to 10.0.0.1 port 22\n"
    findings = detect_permissive_rules(conf)
    assert len(findings) == 1
    assert findings[0].rule == "firewall-sensitive-port-open"


def test_firewall_ignores_internal_rules():
    conf = "allow tcp from 10.0.0.0/8 to 10.0.4.0/24 port 22\n"
    assert detect_permissive_rules(conf) == []

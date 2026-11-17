from datetime import datetime, timedelta

import pytest

from soc_triage.model import Event
from soc_triage.rules import RuleError, load_rules, run_rules

START = datetime(2026, 11, 10, 12, 0, 0)


def login(seconds, result="failure", user="root", ip="203.0.113.45", **extra):
    return Event(time=START + timedelta(seconds=seconds), host="web-01", user=user, ip=ip, event="login",
                 result=result, source="linux_auth", line=seconds + 1, raw=f"line {seconds}", extra=extra)


def request(seconds, path, status=200, ip="203.0.113.99", method="GET", agent="Mozilla/5.0"):
    return Event(time=START + timedelta(seconds=seconds), ip=ip, event="http_request",
                 result="failure" if status >= 400 else "success", source="web_access", line=seconds + 1,
                 raw=f"{method} {path}", extra={"method": method, "path": path.partition("?")[0], "target": path,
                                                "status": str(status), "user_agent": agent})


def fired(events, rules=None):
    return {finding.rule.id: finding for finding in run_rules(rules or load_rules().rules, events)}


def test_default_rules():
    rules = load_rules().rules
    assert len(rules) >= 8
    assert len({rule.id for rule in rules}) == len(rules)
    assert all(rule.mitre.id.startswith("T") and rule.mitre.name and rule.mitre.tactic for rule in rules)
    assert rules[0].mitre.url.startswith("https://attack.mitre.org/techniques/T")


def test_bruteforce():
    slow = [login(second * 40) for second in range(12)]
    assert "auth-password-guessing" not in fired(slow)

    fast = [login(second * 5) for second in range(12)]
    finding = fired(fast)["auth-password-guessing"]
    assert finding.count == 12 and finding.group == {"ip": "203.0.113.45"}
    assert finding.facts["peak"] == "12"
    assert len(finding.evidence) == 5 and finding.evidence[0].line == 1


def test_spraying():
    one_account = [login(second, user="root") for second in range(9)]
    assert "auth-password-spraying" not in fired(one_account)

    many = [login(second, user=f"user{second}") for second in range(7)]
    finding = fired(many)["auth-password-spraying"]
    assert finding.facts["distinct"] == "7"


def test_success_after_failures():
    failures = [login(second * 10) for second in range(6)]
    elsewhere = fired(failures + [login(100, result="success", ip="10.0.5.12")])
    assert "auth-success-after-failures" not in elsewhere

    finding = fired(failures + [login(100, result="success", user="deploy")])["auth-success-after-failures"]
    assert finding.rule.severity == "critical" and finding.count == 1
    assert finding.facts["precursors"] == "6"
    assert finding.summary == "203.0.113.45 logged in as deploy after 6 failed logins within 30 min"
    assert [event.result for event in finding.evidence] == ["failure", "failure", "success"]


def test_new_ip():
    history = [login(second * 60, result="success", user="deploy", ip="10.0.5.20") for second in range(3)]
    assert "auth-new-source-for-user" not in fired(history[:2] + [login(900, result="success", user="deploy")])

    finding = fired(history + [login(900, result="success", user="deploy")])["auth-new-source-for-user"]
    assert finding.facts == {"values": "203.0.113.45", "known": "10.0.5.20"}


def test_night():
    def sudo(hour):
        return Event(time=datetime(2026, 11, 10, hour, 30), user="deploy", event="sudo", result="success",
                     source="linux_auth", line=hour, extra={"command": "/usr/bin/id"})

    assert "admin-night-activity" not in fired([sudo(14)])
    assert fired([sudo(2)])["admin-night-activity"].group == {"user": "deploy"}


def test_web_rules():
    events = [request(1, "/.env", 404), request(2, "/wp-admin/", 404), request(3, "/backup.zip", 200),
              request(4, "/download?file=../../etc/passwd", 400), request(5, "/product/12", 200)]
    findings = fired(events)

    assert findings["web-secret-file-served"].rule.severity == "critical"
    assert findings["web-secret-file-served"].facts["values"] == "/backup.zip"
    assert findings["web-sensitive-path-probe"].count == 2
    assert findings["web-injection-attempt"].count == 1
    assert "web-not-found-burst" not in findings


def test_5xx_burst():
    events = [request(second * 3, "/api/checkout", 502, ip=f"192.0.2.{second}") for second in range(25)]
    finding = fired(events)["web-server-error-burst"]
    assert finding.group == {} and finding.count == 25


CUSTOM = """
lists:
  payroll_hosts: [fin-01, fin-02]
rules:
  - id: payroll-login-on-weekend
    title: Login to a payroll host on a weekend
    severity: medium
    mitre: {id: T1078, name: Valid Accounts, tactic: Initial Access}
    match:
      event: login
      result: success
      host: $payroll_hosts
      weekday: [sat, sun]
      ip: {not_cidr: [10.0.0.0/8]}
    group_by: user
    summary: "{user} logged in to payroll on a weekend, logins: {count}"
"""


def test_custom_rule(tmp_path):
    path = tmp_path / "payroll.yaml"
    path.write_text(CUSTOM, encoding="utf-8")
    ruleset = load_rules(extra=[path])
    assert ruleset.origins == ["built-in default.yaml", "payroll.yaml"]

    saturday = datetime(2026, 11, 14, 11, 0)
    def at(when, host="fin-01", ip="203.0.113.8"):
        return Event(time=when, host=host, user="j.karimova", ip=ip, event="login", result="success", source="windows", line=1)

    findings = fired([at(saturday), at(saturday, ip="10.0.8.31"), at(saturday, host="web-01"),
                      at(saturday - timedelta(days=1))], ruleset.rules)
    assert findings["payroll-login-on-weekend"].count == 1
    assert findings["payroll-login-on-weekend"].summary == "j.karimova logged in to payroll on a weekend, logins: 1"


@pytest.mark.parametrize("broken, message", [
    ("rules:\n  - id: x\n    title: t\n    severity: loud\n    mitre: {id: T1078}\n    match: {event: login}\n", "severity"),
    ("rules:\n  - id: x\n    title: t\n    severity: low\n    mitre: {id: brute}\n    match: {event: login}\n", "mitre.id"),
    ("rules:\n  - id: x\n    title: t\n    severity: low\n    mitre: {id: T1078}\n    match: {user: {like: a}}\n", "unknown operator"),
    ("rules:\n  - id: x\n    title: t\n    severity: low\n    mitre: {id: T1078}\n    match: {user: $nobody}\n", "not defined"),
    ("rules:\n  - id: x\n    title: t\n    severity: low\n    mitre: {id: T1078}\n    match: {path: {regex: '('}}\n", "regular expression"),
    ("rules:\n  - id: x\n    title: t\n    severity: low\n    mitre: {id: T1078}\n    match: {event: login}\n    threshold: {count: 3, window: soon}\n", "duration"),
    ("rules:\n  - id: auth-root-login\n    title: t\n    severity: low\n    mitre: {id: T1078}\n    match: {event: login}\n", "already defined"),
    ("rules: [", "not valid YAML"),
])
def test_bad_rules(tmp_path, broken, message):
    path = tmp_path / "broken.yaml"
    path.write_text(broken, encoding="utf-8")
    with pytest.raises(RuleError, match=message) as error:
        load_rules(extra=[path])
    assert "broken.yaml" in str(error.value)

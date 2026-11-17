# входы, которые когда-то роняли разбор или пропускали живой адрес в отчет

import json
import time

import pytest

from soc_triage.cli import main
from soc_triage.defang import defang_text, defang_url
from soc_triage.model import Event
from soc_triage.parsers import linux_auth, web_access, windows
from soc_triage.phishing import find_indicators, parse_eml
from soc_triage.rules import RuleError, load_rules, run_rules
from soc_triage.timeutil import parse_offset

GOOD = {"TimeCreated": "2026-11-10T02:14:00Z", "EventID": 4624, "TargetUserName": "a", "IpAddress": "10.0.0.1"}


def test_bad_tz_offset():
    text = "2026-11-10T02:14:00+99:00 host sshd[1]: Accepted password for a from 192.0.2.1 port 22 ssh2\n"
    result = linux_auth.parse(text)
    assert result.events == [] and result.skipped[0].reason == "unreadable timestamp"

    line = '192.0.2.1 - - [10/Nov/2026:13:55:36 +9999] "GET / HTTP/1.1" 200 1\n'
    assert web_access.parse(line).skipped[0].reason == "unreadable timestamp"


@pytest.mark.parametrize("record", [
    {**GOOD, "EventID": "inf"},
    {**GOOD, "EventID": "1e400"},
    {**GOOD, "TimeCreated": "/Date(99999999999999999)/"},
    {**GOOD, "TimeCreated": "/Date(-99999999999999999)/"},
    {"Event": {"System": {"EventID": 4625, "TimeCreated": {"#attributes": "x"}, "Provider": {"#attributes": 7}}}},
    {"Event": {"System": "x", "EventData": ["a"]}},
])
def test_bad_win_records(record):
    result = windows.parse(json.dumps([record, GOOD]))
    assert len(result.events) == 1 and len(result.skipped) == 1


def test_date_edge():
    record = {**GOOD, "TimeCreated": "9999-12-31T23:59:59-05:00"}
    result = windows.parse(json.dumps([record]), tz=parse_offset("+00:00"))
    assert len(result.events) == 1


def test_deep_json():
    result = windows.parse("[" * 100000)
    assert result.events == [] and result.skipped
    result = windows.parse(json.dumps(GOOD) + "\n" + "[" * 100000 + "\n" + json.dumps(GOOD) + "\n")
    assert len(result.events) == 2 and len(result.skipped) == 1


def test_huge_window(tmp_path):
    path = tmp_path / "rules.yaml"
    path.write_text(
        "rules:\n  - id: x\n    title: t\n    severity: low\n    mitre: {id: T1078}\n    match: {event: login}\n"
        "    threshold: {count: 2, window: 99999999999d}\n", encoding="utf-8")
    with pytest.raises(RuleError, match="duration"):
        load_rules([path])


def test_distinct_peak():
    def attempt(minute, user):
        from datetime import datetime, timedelta
        return Event(time=datetime(2026, 11, 10) + timedelta(minutes=minute), user=user, ip="203.0.113.45",
                     event="login", result="failure", source="linux_auth", line=minute + 1)

    events = [attempt(index, f"quick{index}") for index in range(6)]
    events += [attempt(60 * index, f"slow{index}") for index in range(1, 9)]
    finding = {item.rule.id: item for item in run_rules(load_rules().rules, events)}["auth-password-spraying"]
    assert finding.facts["distinct"] == "14" and finding.facts["peak"] == "6"
    assert "14 different accounts, up to 6 within 10 min" in finding.summary


HOSTILE_EML = b"""Received: from a.example (a.example [192.0.2.7]) by mx.example with ESMTP; Tue, 10 Nov 2026 02:00:00 -0000
Received: from b.example (b.example [192.0.2.8]) by a.example with http://relay.example; Tue, 10 Nov 2026 02:00:05 +0000
From: Billing <billing@shop.example>
To: a@recipient.example
Subject: Invoice
X-Originating-IP: [http://origin.example/x]
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="b"

--b
Content-Type: text/html

<a href='https:/\\evil.example/login'>open</a> <a href="https:other.example/x">here</a>
<a href="//third.example/y">there</a>
--b
Content-Type: application/pdf; name="www.evil.example invoice.pdf"
Content-Disposition: attachment; filename="www.evil.example invoice.pdf"

x
--b--
"""


def test_loose_urls():
    message = parse_eml(HOSTILE_EML)
    assert {link.url: link.host for link in message.links} == {
        "https://evil.example/login": "evil.example",
        "https://other.example/x": "other.example",
        "https://third.example/y": "third.example",
    }
    assert "link-login-on-other-domain" in {indicator.id for indicator in find_indicators(message)}
    assert defang_url("https:/\\evil.example/login") == "hxxps:/\\evil[.]example/login"
    assert defang_text("see https:evil.example/x") == "see hxxps:evil[.]example/x"


def test_hostile_mail_defanged(tmp_path):
    source = tmp_path / "hostile.eml"
    source.write_bytes(HOSTILE_EML)
    assert main(["eml", str(source), "--out", str(tmp_path / "out")]) == 0

    for path in (tmp_path / "out").iterdir():
        text = path.read_text(encoding="utf-8").replace('xmlns="http://www.w3.org/2000/svg"', "")
        for live in ("evil.example", "other.example", "third.example", "relay.example", "origin.example",
                     "shop.example", "http:", "https:"):
            assert live not in text, f"{live} in {path.name}"
    report = (tmp_path / "out" / "report.md").read_text(encoding="utf-8")
    assert "`www[.]evil[.]example invoice.pdf`" in report
    assert "| filename | `www[.]evil[.]example invoice.pdf` | `attachment` |" in report


def test_defang_speed():
    started = time.perf_counter()
    for text in ("a." * 100000 + "1", "a" * 200000, "a@" * 100000, "http:" * 40000):
        defang_text(text)
    assert time.perf_counter() - started < 2

import csv
import json
import re
from pathlib import Path

import pytest

from soc_triage.cli import main
from soc_triage.report.doc import Code, Document, Para, Table
from soc_triage.report.html import render_html
from soc_triage.report.markdown import render_markdown

ROOT = Path(__file__).resolve().parents[1]
DEMO = ROOT / "demo"
RUNS = {
    "auth": ["logs", "demo/auth.log"],
    "access": ["logs", "demo/access.log"],
    "windows": ["logs", "demo/windows-security.json", "--tz-offset", "+05:00"],
    "suspicious-email": ["eml", "demo/suspicious.eml"],
}


@pytest.fixture(scope="module")
def reports(tmp_path_factory):
    base = tmp_path_factory.mktemp("reports")
    for name, arguments in RUNS.items():
        command = [arguments[0], str(ROOT / arguments[1]), *arguments[2:], "--out", str(base / name)]
        assert main(command) == 0
    return base


@pytest.mark.parametrize("name", RUNS)
def test_demo_reports_fresh(reports, name):
    # в README показано то же, что получится после clone
    committed = DEMO / "reports" / name
    fresh = reports / name
    assert sorted(path.name for path in fresh.iterdir()) == sorted(path.name for path in committed.iterdir())
    for path in fresh.iterdir():
        assert path.read_bytes() == (committed / path.name).read_bytes(), f"{name}/{path.name} is out of date"


def test_log_report(reports):
    html = (reports / "auth" / "report.html").read_text(encoding="utf-8")
    markdown = (reports / "auth" / "report.md").read_text(encoding="utf-8")
    findings = json.loads((reports / "auth" / "findings.json").read_text(encoding="utf-8"))

    assert findings["findings"][0]["rule"] == "auth-success-after-failures"
    assert findings["findings"][0]["mitre"]["id"] == "T1110"
    assert findings["findings"][0]["evidence"][-1]["raw"].startswith("2026-11-10T02:")
    assert "Successful login after repeated failures" in html and "T1110" in html
    assert html.count("<svg") == 2 and "<script" not in html and "http-equiv" not in html
    assert "![Events over time](events_over_time.svg)" in markdown
    assert (reports / "auth" / "events_over_time.svg").read_text(encoding="utf-8").startswith("<svg")
    assert "not a replacement for a SIEM" in html and "not a replacement for a SIEM" in markdown


def test_events_csv(reports):
    with (reports / "access" / "events.csv").open(encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    assert list(rows[0]) == ["line", "time", "host", "user", "ip", "event", "result", "source", "details"]
    assert len(rows) == 1105
    assert {row["event"] for row in rows} == {"http_request"}


def test_eml_report_defanged(reports):
    for name in ("report.html", "report.md", "iocs.csv", "findings.json", "domains.svg", "delivery_path.svg"):
        text = (reports / "suspicious-email" / name).read_text(encoding="utf-8")
        text = re.sub(r'xmlns="http://www\.w3\.org/2000/svg"', "", text)
        assert "http://" not in text and "https://" not in text, name
        for live in ("examplebank.example", "account-check.test", "203.0.113.77", "@freemail", "promo-sender.test"):
            assert live not in text, f"{live} is not defanged in {name}"
    report = (reports / "suspicious-email" / "report.md").read_text(encoding="utf-8")
    assert "Likely phishing" in report and "hxxp://203[.]0[.]113[.]77/examplebank/verify.php?id=8841" in report


def test_no_markup_injection():
    hostile = '<img src=x onerror=alert(1)> ![x](http://evil.example/p.png) `` ` | [a](b)'
    document = Document("t", [Para(["seen: ", Code(hostile)]), Table(["value"], [[Code(hostile)]])])

    html = render_html(document)
    assert "<img" not in html and "&lt;img src=x onerror=alert(1)&gt;" in html

    markdown = render_markdown(document)
    paragraph, _, table_row = markdown.strip().split("\n\n")[0], None, markdown.strip().split("\n")[-1]
    assert paragraph.startswith("seen: ```") and paragraph.endswith("```")
    assert "\\|" in table_row and table_row.count(" | ") == 0


def test_csv_formula(tmp_path):
    log = tmp_path / "auth.log"
    log.write_text(
        "2026-11-10T02:10:01+05:00 web-01 sshd[1]: Failed password for invalid user =cmd|calc from 203.0.113.45 port 1 ssh2\n",
        encoding="utf-8",
    )
    assert main(["logs", str(log), "--out", str(tmp_path / "out")]) == 0
    with (tmp_path / "out" / "events.csv").open(encoding="utf-8", newline="") as handle:
        (row,) = list(csv.DictReader(handle))
    assert row["user"] == "'=cmd|calc"


def test_cli_errors(tmp_path, capsys):
    assert main(["logs", str(tmp_path / "missing.log")]) == 2
    assert "no such file" in capsys.readouterr().err

    noise = tmp_path / "notes.txt"
    noise.write_text("just some notes\n", encoding="utf-8")
    assert main(["logs", str(noise), "--out", str(tmp_path / "out")]) == 2
    assert "could not recognise the log format" in capsys.readouterr().err

    rules = tmp_path / "rules.yaml"
    rules.write_text("rules:\n  - id: x\n    title: t\n    severity: low\n    mitre: {id: T1}\n    match: {event: a}\n", encoding="utf-8")
    assert main(["rules", "--rules", str(rules)]) == 2
    assert "mitre.id" in capsys.readouterr().err


def test_rules_cmd(capsys):
    assert main(["rules"]) == 0
    output = capsys.readouterr().out
    assert "auth-password-guessing" in output and "T1110.001" in output


def test_no_findings(tmp_path, capsys):
    log = tmp_path / "quiet.log"
    log.write_text('192.0.2.4 - - [10/Nov/2026:13:55:41 +0500] "GET / HTTP/1.1" 200 12 "-" "Mozilla/5.0"\n', encoding="utf-8")
    assert main(["logs", str(log), "--out", str(tmp_path / "out")]) == 0
    assert "no rule fired" in capsys.readouterr().out
    assert "No rule fired" in (tmp_path / "out" / "report.html").read_text(encoding="utf-8")


def test_readme_output(tmp_path, capsys, monkeypatch):
    readme = (ROOT / "README.md").read_text(encoding="utf-8")

    assert main(["rules"]) == 0
    assert capsys.readouterr().out.strip() in readme

    monkeypatch.chdir(ROOT)
    assert main(["logs", "demo/auth.log", "--out", str(tmp_path / "auth")]) == 0
    shown = capsys.readouterr().out.strip().splitlines()[:-1]
    assert "\n".join(shown) in readme

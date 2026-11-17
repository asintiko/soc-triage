from __future__ import annotations

import csv
import json
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path

from .. import __version__
from ..model import CORE_FIELDS, Event, ParseResult
from ..parsers import LABELS
from ..rules import SEVERITIES, Finding, RuleSet
from .charts import bar_chart, time_chart
from .doc import (
    Badge, Callout, Code, CodeBlock, Document, Facts, Figure, Heading, Para, Section, Strong, Table, Title,
    code_or_dash,
)
from .html import render_html
from .markdown import render_markdown

GROUPS_PER_RULE = 10
SKIPPED_SHOWN = 10
FOOTER = f"soc-triage {__version__}. First-pass triage of one file, not a replacement for a SIEM."
_FORMULA_START = ("=", "+", "-", "@", "\t", "\r")


@dataclass
class LogAnalysis:
    name: str
    sha256: str
    fmt: str
    parsed: ParseResult
    findings: list[Finding]
    ruleset: RuleSet
    clock: str


def _stamp(moment) -> str:
    return moment.isoformat(sep=" ", timespec="seconds")


def _count(number: int) -> str:
    return f"{number:,}".replace(",", " ")


def _plural(number: int, noun: str) -> str:
    return f"{_count(number)} {noun}" + ("" if number == 1 else "s")


def _severity_line(findings: list[Finding]) -> str:
    counts = Counter(finding.rule.severity for finding in findings)
    return ", ".join(f"{counts[level]} {level}" for level in SEVERITIES if counts[level])


def _evidence_table(finding: Finding, unit: str) -> Table:
    extras = [name for name in finding.rule.fields if name not in CORE_FIELDS]
    extras = [name for name in extras if any(event.get(name) for event in finding.evidence)]
    headers = [unit, "Time", "Host", "User", "IP", "Event", "Result"]
    headers += [name.replace("_", " ").capitalize() for name in extras]
    rows = []
    for event in finding.evidence:
        row = [str(event.line), _stamp(event.time)]
        row += [code_or_dash(event.get(name)) for name in ("host", "user", "ip", "event", "result")]
        row += [code_or_dash(event.get(name)[:160]) for name in extras]
        rows.append(row)
    return Table(headers, rows, wide=True)


def _finding_section(number: int, finding: Finding, unit: str) -> Section:
    rule = finding.rule
    summary = [Strong("What was seen. ")] + [Code(text) if quoted else text for text, quoted in finding.summary_parts]
    shown = len(finding.evidence)
    label = f"Evidence: {shown} of {finding.count} matching events" if finding.count > shown else "Evidence"
    blocks = [
        Para(summary),
        Para(rule.description),
        Para([Strong("Why it fired. "), Code(" and ".join(rule.conditions)), "; ", rule.trigger_text(), "."]),
        Para(label, muted=True),
        _evidence_table(finding, unit),
        CodeBlock([f"{event.line}: {event.raw[:400]}" for event in finding.evidence], f"Raw {unit.lower()}s"),
    ]
    if rule.response:
        blocks.append(Para([Strong("What to check. "), rule.response]))
    blocks.append(Para(f"Rule {rule.id} from {rule.origin}. Technique: {rule.mitre.url}", muted=True))
    meta = [
        Code(rule.mitre.id), f" {rule.mitre.name} · {rule.mitre.tactic} · {_plural(finding.count, 'event')} · ",
        f"{_stamp(finding.first)} to {_stamp(finding.last)}",
    ]
    return Section(number, rule.severity, rule.severity.upper(), rule.title, meta, blocks)


def _charts(events: list[Event]) -> list[Figure]:
    points = [(event.time, event.result == "failure") for event in events]
    timeline = time_chart("Events over time", points, "failed or refused", "other events")
    field, title = ("ip", "Busiest source addresses") if any(event.ip for event in events) else ("user", "Most active accounts")
    totals: Counter = Counter()
    failures: Counter = Counter()
    for event in events:
        value = event.get(field)
        if value:
            totals[value] += 1
            failures[value] += event.result == "failure"
    ranked = sorted(totals.items(), key=lambda item: (-item[1], item[0]))[:10]
    rows = [(value, total, failures[value]) for value, total in ranked]
    sources = bar_chart(title, rows, "failed or refused", "other events")
    return [
        Figure("Events over time", "events_over_time.svg", timeline),
        Figure(title, "top_sources.svg", sources),
    ]


def build_document(analysis: LogAnalysis) -> Document:
    parsed = analysis.parsed
    events = parsed.events
    findings = analysis.findings
    unit = "Records" if analysis.fmt == "windows" else "Lines"
    blocks: list = []

    period = "no events"
    if events:
        period = f"{_stamp(min(event.time for event in events))} to {_stamp(max(event.time for event in events))}"
    blocks.append(Title("Log triage report", Code(analysis.name), f"{LABELS[analysis.fmt]} · {period}"))

    if findings:
        top = findings[0]
        lead = ["Start with: "] + [Code(text) if quoted else text for text, quoted in top.summary_parts] + ["."]
        blocks.append(Callout(top.rule.severity, f"{_plural(len(findings), 'finding')}: {_severity_line(findings)}", lead))
    else:
        blocks.append(Callout(
            "ok", "No rule fired",
            f"None of the {len(analysis.ruleset.rules)} rules matched this file. That does not prove nothing happened.",
        ))

    blocks.append(Facts([
        (f"{unit} read", _count(parsed.total_lines)),
        ("Events parsed", _count(len(events))),
        (f"{unit} skipped", _count(len(parsed.skipped))),
        ("Rules applied", f"{len(analysis.ruleset.rules)} from {', '.join(analysis.ruleset.origins)}"),
        ("Clock", analysis.clock),
        ("SHA-256 of the input", Code(analysis.sha256)),
    ]))

    if findings:
        blocks.append(Heading("Findings"))
        rows = []
        for number, finding in enumerate(findings, 1):
            subject = ", ".join(value for value in finding.group.values() if value)
            rows.append([
                str(number), Badge(finding.rule.severity.upper(), finding.rule.severity), finding.rule.title,
                code_or_dash(subject), Code(finding.rule.mitre.id), _count(finding.count), _stamp(finding.first),
            ])
        blocks.append(Table(["#", "Severity", "Finding", "Subject", "ATT&CK", "Events", "First seen"], rows))

    if events:
        blocks.append(Heading("Timeline and sources"))
        blocks.extend(_charts(events))

    if findings:
        blocks.append(Heading("Details"))
        per_rule: Counter = Counter()
        hidden: Counter = Counter()
        for number, finding in enumerate(findings, 1):
            per_rule[finding.rule.id] += 1
            if per_rule[finding.rule.id] > GROUPS_PER_RULE:
                hidden[finding.rule.id] += 1
                continue
            blocks.append(_finding_section(number, finding, unit[:-1]))
        for rule_id, extra in hidden.items():
            blocks.append(Para(
                f"Rule {rule_id} fired for more subjects ({extra}); they are listed in the table above and in findings.json.",
                muted=True,
            ))

    if events:
        blocks.append(Heading("Events by type"))
        kinds = Counter((event.event, event.result) for event in events)
        rows = [
            [Code(name), code_or_dash(result), _count(total)]
            for (name, result), total in sorted(kinds.items(), key=lambda item: (-item[1], item[0]))[:15]
        ]
        blocks.append(Table(["Event", "Result", "Count"], rows))
        blocks.append(Para("Every parsed event with its normalised fields is in events.csv.", muted=True))

    if parsed.skipped:
        blocks.append(Heading(f"Skipped {unit.lower()}"))
        blocks.append(Para(
            f"{_count(len(parsed.skipped))} {unit.lower()} could not be read and were left out of the analysis."
            + (f" The first {SKIPPED_SHOWN} are shown." if len(parsed.skipped) > SKIPPED_SHOWN else "")
        ))
        rows = [[str(item.line), item.reason, Code(item.text[:160])] for item in parsed.skipped[:SKIPPED_SHOWN]]
        blocks.append(Table([unit[:-1], "Reason", "Text"], rows))

    blocks.append(Heading("Rules applied"))
    fired = Counter(finding.rule.id for finding in findings)
    rows = [
        [Code(rule.id), Badge(rule.severity.upper(), rule.severity), Code(rule.mitre.id), rule.title,
         str(fired[rule.id]) if fired[rule.id] else "—"]
        for rule in analysis.ruleset.rules
    ]
    blocks.append(Table(["Rule", "Severity", "ATT&CK", "Title", "Findings"], rows))
    blocks.append(Para(
        "A finding is a lead to verify, not a verdict. The report covers one file: anything outside it, "
        "and anything none of these rules describe, is not here.",
        muted=True,
    ))
    return Document(f"Log triage: {analysis.name}", blocks)


def csv_safe(value: str) -> str:
    # чтобы excel не выполнил ячейку как формулу
    return "'" + value if value.startswith(_FORMULA_START) else value


def _finding_record(finding: Finding) -> dict:
    rule = finding.rule
    return {
        "rule": rule.id,
        "title": rule.title,
        "severity": rule.severity,
        "mitre": {"id": rule.mitre.id, "name": rule.mitre.name, "tactic": rule.mitre.tactic, "url": rule.mitre.url},
        "subject": finding.group,
        "events": finding.count,
        "first_seen": _stamp(finding.first),
        "last_seen": _stamp(finding.last),
        "summary": finding.summary,
        "facts": finding.facts,
        "conditions": rule.conditions,
        "trigger": rule.trigger_text(),
        "evidence": [event.as_dict() | {"raw": event.raw[:400]} for event in finding.evidence],
    }


def write_outputs(analysis: LogAnalysis, out: Path) -> list[Path]:
    out.mkdir(parents=True, exist_ok=True)
    document = build_document(analysis)
    written = []

    def save(name: str, text: str) -> None:
        path = out / name
        path.write_text(text, encoding="utf-8", newline="\n")
        written.append(path)

    save("report.html", render_html(document, FOOTER))
    save("report.md", render_markdown(document, FOOTER))
    for block in document.blocks:
        if isinstance(block, Figure):
            save(block.filename, block.svg + "\n")

    record = {
        "tool": f"soc-triage {__version__}",
        "input": {"name": analysis.name, "sha256": analysis.sha256, "format": analysis.fmt},
        "read": analysis.parsed.total_lines,
        "events": len(analysis.parsed.events),
        "skipped": len(analysis.parsed.skipped),
        "findings": [_finding_record(finding) for finding in analysis.findings],
    }
    save("findings.json", json.dumps(record, ensure_ascii=False, indent=2) + "\n")

    path = out / "events.csv"
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle, lineterminator="\n")
        writer.writerow(["line", "time", *CORE_FIELDS, "details"])
        for event in analysis.parsed.events:
            details = "; ".join(f"{key}={value}" for key, value in event.extra.items() if key != "message")
            row = [str(event.line), _stamp(event.time), *(event.get(name) for name in CORE_FIELDS), details]
            writer.writerow([csv_safe(cell) for cell in row])
    written.append(path)
    return written

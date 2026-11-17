from __future__ import annotations

import csv
import json
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

from .. import __version__
from ..defang import defang_email, defang_host, defang_ip, defang_text, defang_url
from ..phishing import Indicator, Message, Verdict, link_flags, registrable_domain
from ..phishing.parse import domain_of, is_ip, is_public_ip
from .charts import bar_chart
from .doc import Badge, Callout, Code, CodeBlock, Document, Facts, Figure, Heading, Para, Table, Title, code_or_dash
from .html import render_html
from .logs import csv_safe
from .markdown import render_markdown

LINKS_SHOWN = 40
TEXT_SHOWN = 1200
FOOTER = f"soc-triage {__version__}. First-pass triage of one message, not a replacement for a mail gateway or a sandbox."
_VERDICT_TONE = {"phishing": "critical", "suspicious": "medium", "clean": "ok"}
_WEIGHT_TONE = {"strong": "critical", "medium": "medium", "weak": "low"}
_RESULT_TONE = {"pass": "ok", "fail": "critical", "softfail": "medium", "permerror": "medium", "temperror": "medium"}


@dataclass
class EmlAnalysis:
    name: str
    message: Message
    indicators: list[Indicator]
    verdict: Verdict


def _shown(text: str, limit: int = 400) -> str:
    # обрезать до читаемой длины, потом обезвредить
    return defang_text(text if len(text) <= limit else text[:limit] + "…")


def _host(text: str) -> str:
    return defang_host(defang_url(text[:200]))


def _places(link) -> str:
    return defang_text(", ".join(link.places))


def _size(count: int) -> str:
    return f"{count:,} bytes".replace(",", " ")


def iocs(message: Message) -> list[tuple[str, str, str]]:
    # (тип, значение, где встретилось), без повторов
    rows: list[tuple[str, str, str]] = []
    for link in message.links:
        rows.append(("url", defang_url(link.url), _places(link)))
    for link in message.links:
        if not link.host:
            continue
        if is_ip(link.host):
            rows.append(("ip", defang_ip(link.host), "link host"))
        else:
            rows.append(("domain", defang_host(registrable_domain(link.host)), "link host"))
    for hop in message.hops:
        if hop.from_ip and is_public_ip(hop.from_ip):
            rows.append(("ip", defang_ip(hop.from_ip), "relay in Received"))
    if message.originating_ip:
        rows.append(("ip", _host(message.originating_ip), "X-Originating-IP"))
    for label, address in (
        ("From (can be forged)", message.from_address),
        ("Reply-To", message.reply_to),
        ("Return-Path", message.return_path),
    ):
        if address:
            rows.append(("email", defang_email(address), label))
    for address in message.mail_links:
        rows.append(("email", defang_email(address), "mailto link"))
    for attachment in message.attachments:
        name = _shown(attachment.filename, 200)
        rows.append(("sha256", attachment.sha256, f"attachment {name}"))
        rows.append(("md5", attachment.md5, f"attachment {name}"))
        rows.append(("filename", name, "attachment"))
    unique: dict[tuple[str, str], tuple[str, str, str]] = {}
    for row in rows:
        unique.setdefault(row[:2], row)
    return list(unique.values())


def _auth_rows(message: Message) -> list[list]:
    rows = []
    for method in ("spf", "dkim", "dmarc"):
        results = [result for result in message.auth if result.method == method]
        if not results:
            rows.append([method.upper(), Badge("not recorded", "info"), "—", "—"])
            continue
        for result in results:
            details = ", ".join(f"{name}={defang_text(value)}" for name, value in result.properties.items())
            rows.append([
                method.upper(), Badge(result.result, _RESULT_TONE.get(result.result, "info")),
                code_or_dash(details), result.source,
            ])
    return rows


def _hop_rows(message: Message) -> tuple[list[list], list[tuple[str, int, int]]]:
    rows, bars = [], []
    previous = None
    for number, hop in enumerate(message.hops, 1):
        delay = "—"
        if hop.time is not None:
            if previous is not None:
                seconds = int((hop.time - previous).total_seconds())
                delay = f"{seconds} s"
                bars.append((f"{number}. {_host(hop.by_host) or '?'}", max(seconds, 0), 0))
            else:
                bars.append((f"{number}. {_host(hop.by_host) or '?'}", 0, 0))
            previous = hop.time
        rows.append([
            str(number), code_or_dash(_host(hop.from_host)), code_or_dash(defang_ip(hop.from_ip)),
            code_or_dash(_host(hop.by_host)), code_or_dash(defang_text(hop.protocol[:40])),
            hop.time.isoformat(sep=" ", timespec="seconds") if hop.time else "—", delay,
        ])
    return rows, bars


def _domain_bars(message: Message, flags: dict[str, list[str]]) -> list[tuple[str, int, int]]:
    totals: Counter = Counter()
    flagged: Counter = Counter()
    for link in message.links:
        if not link.host:
            continue
        key = link.host if is_ip(link.host) else registrable_domain(link.host)
        totals[key] += 1
        flagged[key] += bool(flags.get(link.url))
    for address in (message.from_address, message.reply_to, message.return_path):
        if address:
            totals[registrable_domain(domain_of(address))] += 1
    ranked = sorted(totals.items(), key=lambda item: (-item[1], item[0]))[:10]
    return [(defang_ip(key) if is_ip(key) else defang_host(key), total, flagged[key]) for key, total in ranked]


def build_document(analysis: EmlAnalysis) -> Document:
    message = analysis.message
    flags = link_flags(message)
    sender = f"{message.from_name} <{message.from_address}>" if message.from_name else message.from_address
    blocks: list = [
        Title(
            "Email triage report",
            Code(_shown(message.subject, 200) or "(no subject)"),
            ["From ", code_or_dash(_shown(sender, 200)), " · file ", Code(analysis.name)],
        ),
        Callout(_VERDICT_TONE[analysis.verdict.level], analysis.verdict.label, analysis.verdict.reason),
        Facts([
            ("From", code_or_dash(_shown(sender))),
            ("Reply-To", code_or_dash(defang_email(message.reply_to) if message.reply_to else "")),
            ("Return-Path", code_or_dash(defang_email(message.return_path) if message.return_path else "")),
            ("To", code_or_dash(_shown(message.to))),
            ("Date", code_or_dash(_shown(message.date_raw, 80))),
            ("Message-ID", code_or_dash(_shown(message.message_id, 200))),
            ("Mail client", code_or_dash(_shown(message.mailer, 120))),
            ("Size", _size(message.size)),
            ("SHA-256 of the file", Code(message.sha256)),
        ]),
    ]

    blocks.append(Heading("Indicators"))
    if analysis.indicators:
        rows = []
        for indicator in analysis.indicators:
            evidence: list = []
            for position, item in enumerate(indicator.evidence):
                if position:
                    evidence.append("; ")
                evidence.append(Code(_shown(item)))
            rows.append([Badge(indicator.weight, _WEIGHT_TONE[indicator.weight]), indicator.title, evidence])
        blocks.append(Table(["Weight", "Indicator", "Evidence"], rows))
        blocks.append(Para(
            "Strong counts 3, medium 2, weak 1. The message is called phishing only with at least three "
            "indicators, one of them strong, and a score of 6 or more.",
            muted=True,
        ))
    else:
        blocks.append(Para("None of the checks matched."))

    blocks.append(Heading("Sender authentication"))
    if any(result.source == "Authentication-Results" for result in message.auth):
        if message.auth_server:
            blocks.append(Para([
                "As recorded by the receiving server ", Code(_host(message.auth_server)),
                " in the Authentication-Results header. Nothing was checked against DNS again.",
            ]))
        else:
            blocks.append(Para(
                "As recorded in the Authentication-Results header; the server that wrote it did not name itself. "
                "Nothing was checked against DNS again."
            ))
    elif message.auth:
        blocks.append(Para("Only a Received-SPF header is present; DKIM and DMARC results were not recorded."))
    else:
        blocks.append(Para(
            "The file has no Authentication-Results header, so SPF, DKIM and DMARC cannot be judged from it."
        ))
    blocks.append(Table(["Check", "Result", "Details", "Source"], _auth_rows(message)))

    blocks.append(Heading(f"Links ({len(message.links)})"))
    if message.links:
        rows = []
        for number, link in enumerate(message.links[:LINKS_SHOWN], 1):
            texts = "; ".join(link.texts[:2])
            rows.append([
                str(number), Code(defang_url(link.url)), code_or_dash(_shown(texts, 200)),
                Code(_places(link)), "; ".join(flags.get(link.url, [])) or "—",
            ])
        blocks.append(Table(["#", "URL", "Shown as", "Found in", "Notes"], rows))
        if len(message.links) > LINKS_SHOWN:
            blocks.append(Para(f"{len(message.links) - LINKS_SHOWN} more links are in iocs.csv.", muted=True))
    else:
        blocks.append(Para("The message contains no links."))

    blocks.append(Heading(f"Attachments ({len(message.attachments)})"))
    if message.attachments:
        rows = [
            [Code(_shown(item.filename, 200)), Code(item.content_type), _size(item.size), Code(item.sha256), Code(item.md5)]
            for item in message.attachments
        ]
        blocks.append(Table(["File", "Declared type", "Size", "SHA-256", "MD5"], rows))
        blocks.append(Para("Attachments were hashed, not opened or executed.", muted=True))
    else:
        blocks.append(Para("The message has no attachments."))

    hop_rows, hop_bars = _hop_rows(message)
    blocks.append(Heading("Delivery path"))
    if hop_rows:
        blocks.append(Para(
            "Received headers, oldest first. Every relay writes its own line, and the earliest ones are "
            "written by the sender's side and can be invented.",
            muted=True,
        ))
        blocks.append(Table(["Hop", "From", "Address", "By", "Protocol", "Time", "Delay"], hop_rows, wide=True))
    else:
        blocks.append(Para("The file has no Received headers."))
    blocks.append(Figure(
        "Delivery path: seconds between relays", "delivery_path.svg",
        bar_chart("Delivery path: seconds between relays", hop_bars, unit=" s"),
    ))
    blocks.append(Figure(
        "Domains the message refers to", "domains.svg",
        bar_chart("Domains the message refers to", _domain_bars(message, flags), "flagged links", "other references"),
    ))

    blocks.append(Heading("Indicators of compromise"))
    rows = [[kind, Code(value), Code(where)] for kind, value, where in iocs(message)]
    if rows:
        blocks.append(Table(["Type", "Value", "Seen in"], rows))
        blocks.append(Para(
            "Addresses are defanged: hxxp instead of http, [.] instead of a dot, [@] instead of @. "
            "The same table is in iocs.csv.",
            muted=True,
        ))
    else:
        blocks.append(Para("Nothing to list."))

    if message.text:
        excerpt = defang_text(message.text[:TEXT_SHOWN])
        blocks.append(Heading("Message text"))
        lines = [line.rstrip() for line in excerpt.split("\n")]
        label = f"First {TEXT_SHOWN} characters, defanged" if len(message.text) > TEXT_SHOWN else "Defanged"
        blocks.append(CodeBlock(lines, label))

    blocks.append(Para(
        "The verdict is a lead for the analyst, not a decision. A message with none of these signs can "
        "still be malicious, and a legitimate one can show several.",
        muted=True,
    ))
    return Document(f"Email triage: {analysis.name}", blocks)


def write_outputs(analysis: EmlAnalysis, out: Path) -> list[Path]:
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

    message = analysis.message
    table = iocs(message)
    record = {
        "tool": f"soc-triage {__version__}",
        "input": {"name": analysis.name, "sha256": message.sha256, "size": message.size},
        "verdict": {
            "level": analysis.verdict.level, "label": analysis.verdict.label,
            "reason": analysis.verdict.reason, "score": analysis.verdict.score,
        },
        "indicators": [
            {"id": item.id, "weight": item.weight, "title": item.title,
             "evidence": [_shown(text) for text in item.evidence]}
            for item in analysis.indicators
        ],
        "authentication": [
            {"check": result.method, "result": result.result, "source": result.source,
             "details": {name: defang_text(value) for name, value in result.properties.items()}}
            for result in message.auth
        ],
        "iocs": [{"type": kind, "value": value, "seen_in": where} for kind, value, where in table],
    }
    save("findings.json", json.dumps(record, ensure_ascii=False, indent=2) + "\n")

    path = out / "iocs.csv"
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle, lineterminator="\n")
        writer.writerow(["type", "value", "seen_in"])
        for row in table:
            writer.writerow([csv_safe(cell) for cell in row])
    written.append(path)
    return written

from __future__ import annotations

import argparse
import hashlib
import sys
from collections import Counter
from pathlib import Path

from . import __version__
from .parsers import LABELS, FormatError, parse_text, read_text
from .phishing import decide, find_indicators, parse_eml
from .report import eml as eml_report
from .report import logs as logs_report
from .rules import SEVERITIES, RuleError, load_rules, run_rules
from .timeutil import parse_offset


class UsageError(Exception):
    pass


def _existing_file(path: str) -> Path:
    file = Path(path)
    if not file.is_file():
        raise UsageError(f"no such file: {path}")
    return file


def _out_dir(args, source: Path) -> Path:
    return Path(args.out) if args.out else Path("triage-report") / source.stem


def _load_rules(args):
    return load_rules(
        [_existing_file(path) for path in args.rules],
        [_existing_file(path) for path in args.extra_rules],
    )


def _logs(args) -> int:
    source = _existing_file(args.file)
    zone = None
    if args.tz_offset:
        try:
            zone = parse_offset(args.tz_offset)
        except ValueError as error:
            raise UsageError(str(error)) from None
    ruleset = _load_rules(args)
    fmt, parsed = parse_text(read_text(source), args.format, year=args.year, tz=zone)
    findings = run_rules(ruleset.rules, parsed.events)
    clock = "as recorded in the log"
    if zone is not None:
        clock = f"timestamps that carry an offset are shown in UTC{args.tz_offset.strip()}; others as recorded"
    analysis = logs_report.LogAnalysis(
        name=source.name,
        sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
        fmt=fmt,
        parsed=parsed,
        findings=findings,
        ruleset=ruleset,
        clock=clock,
    )
    out = _out_dir(args, source)
    logs_report.write_outputs(analysis, out)

    unit = "records" if fmt == "windows" else "lines"
    print(f"{source.name}: {LABELS[fmt]}")
    print(f"  {parsed.total_lines} {unit} read, {len(parsed.events)} events parsed, {len(parsed.skipped)} skipped")
    if findings:
        counts = Counter(finding.rule.severity for finding in findings)
        by_level = ", ".join(f"{counts[level]} {level}" for level in SEVERITIES if counts[level])
        print(f"  {len(findings)} findings: {by_level}")
        for finding in findings[: args.top]:
            print(f"    {finding.rule.severity:<8} {finding.rule.mitre.id:<10} {finding.summary}")
        if len(findings) > args.top:
            print(f"    ... and {len(findings) - args.top} more in the report")
    else:
        print(f"  no rule fired ({len(ruleset.rules)} rules applied)")
    print(f"  report: {out / 'report.html'}")
    return 0


def _eml(args) -> int:
    source = _existing_file(args.file)
    message = parse_eml(source.read_bytes())
    indicators = find_indicators(message)
    verdict = decide(indicators)
    out = _out_dir(args, source)
    eml_report.write_outputs(eml_report.EmlAnalysis(source.name, message, indicators, verdict), out)

    print(f"{source.name}: {verdict.label}")
    print(f"  {verdict.reason}")
    for indicator in indicators[: args.top]:
        print(f"    {indicator.weight:<7} {indicator.title}")
    if len(indicators) > args.top:
        print(f"    ... and {len(indicators) - args.top} more in the report")
    print(f"  {len(message.links)} links, {len(message.attachments)} attachments, {len(message.hops)} relays")
    print(f"  report: {out / 'report.html'}")
    return 0


def _rules(args) -> int:
    ruleset = _load_rules(args)
    print(f"{len(ruleset.rules)} rules from {', '.join(ruleset.origins)}")
    for rule in ruleset.rules:
        print(f"  {rule.severity:<8} {rule.mitre.id:<10} {rule.id:<30} {rule.title}")
    return 0


def _add_rule_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--rules", action="append", default=[], metavar="FILE",
                        help="use this rule file instead of the built-in rules (repeatable)")
    parser.add_argument("--extra-rules", action="append", default=[], metavar="FILE",
                        help="add the rules from this file to the ones in use (repeatable)")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="analyzer",
        description="First-pass triage of a log file or a suspicious email. Writes an HTML and a Markdown report.",
    )
    parser.add_argument("--version", action="version", version=f"soc-triage {__version__}")
    commands = parser.add_subparsers(dest="command", required=True, metavar="{logs,eml,rules}")

    logs = commands.add_parser("logs", help="analyse a log file with the detection rules")
    logs.add_argument("file", help="auth.log / syslog, an Apache or Nginx access log, or a Windows event export (CSV, JSON)")
    logs.add_argument("--out", metavar="DIR", help="where to write the report (default: triage-report/<file name>)")
    logs.add_argument("--format", choices=["auto", "linux", "web", "windows"], default="auto",
                      help="log format (default: detect from the content)")
    logs.add_argument("--year", type=int, metavar="YYYY",
                      help="year for classic syslog timestamps, which carry none (default: the current year)")
    logs.add_argument("--tz-offset", metavar="+HH:MM",
                      help="show timestamps that carry an offset in this zone, e.g. +05:00 for an export in UTC")
    logs.add_argument("--top", type=int, default=8, metavar="N", help="findings to print to the terminal (default: 8)")
    _add_rule_options(logs)
    logs.set_defaults(run=_logs)

    eml = commands.add_parser("eml", help="analyse a saved email (.eml)")
    eml.add_argument("file", help="the .eml file")
    eml.add_argument("--out", metavar="DIR", help="where to write the report (default: triage-report/<file name>)")
    eml.add_argument("--top", type=int, default=8, metavar="N", help="indicators to print to the terminal (default: 8)")
    eml.set_defaults(run=_eml)

    rules = commands.add_parser("rules", help="list the rules in use; also checks a rule file for mistakes")
    _add_rule_options(rules)
    rules.set_defaults(run=_rules)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.run(args)
    except (UsageError, FormatError, RuleError) as error:
        print(f"analyzer: {error}", file=sys.stderr)
        return 2
    except OSError as error:
        detail = f"{error.strerror}: {error.filename}" if error.filename else str(error)
        print(f"analyzer: {detail}", file=sys.stderr)
        return 2

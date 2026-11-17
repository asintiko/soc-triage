from __future__ import annotations

import re
from datetime import timezone
from urllib.parse import unquote

from ..model import Event, ParseResult, Skipped
from ..timeutil import parse_clf, strip_tz

SOURCE = "web_access"

_QUOTED = r'(?:[^"\\]|\\.)*'
_BODY = (
    r"(?P<ip>\S+) (?P<ident>\S+) (?P<user>\S+) \[(?P<ts>[^\]]+)\] "
    rf'"(?P<request>{_QUOTED})" (?P<status>\d{{3}}) (?P<size>\S+)'
    rf'(?: "(?P<referer>{_QUOTED})" "(?P<agent>{_QUOTED})")?'
)
LINE = re.compile("^" + _BODY)
LINE_VHOST = re.compile(r"^(?P<vhost>\S+) " + _BODY)
_REQUEST = re.compile(r"^(?P<method>[A-Z]+) (?P<target>\S+)(?: (?P<protocol>HTTP/[\d.]+))?$")


def parse(text: str, *, year: int | None = None, tz: timezone | None = None) -> ParseResult:
    events: list[Event] = []
    skipped: list[Skipped] = []
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    for number, line in enumerate(lines, 1):
        line = line.rstrip("\r")
        if not line.strip():
            continue
        match = LINE.match(line) or LINE_VHOST.match(line)
        if not match:
            skipped.append(Skipped(number, "not an access log line", line[:200]))
            continue
        stamp = parse_clf(match.group("ts"))
        if stamp is None:
            skipped.append(Skipped(number, "unreadable timestamp", line[:200]))
            continue
        request = match.group("request")
        parsed = _REQUEST.match(request)
        method = parsed.group("method") if parsed else ""
        target = unquote(parsed.group("target") if parsed else request, errors="replace")
        path, _, query = target.partition("?")
        status = match.group("status")
        extra = {
            "method": method,
            "path": path,
            "target": target,
            "status": status,
            "size": "" if match.group("size") == "-" else match.group("size"),
        }
        if query:
            extra["query"] = query
        if parsed and parsed.group("protocol"):
            extra["protocol"] = parsed.group("protocol")
        referer = match.group("referer")
        if referer and referer != "-":
            extra["referer"] = referer
        agent = match.group("agent")
        if agent and agent != "-":
            extra["user_agent"] = agent
        groups = match.groupdict()
        user = match.group("user")
        events.append(
            Event(
                time=strip_tz(stamp, tz),
                host=(groups.get("vhost") or "").rsplit(":", 1)[0],
                user="" if user == "-" else user,
                ip=match.group("ip"),
                event="http_request",
                result="failure" if status >= "400" else "success",
                source=SOURCE,
                line=number,
                raw=line,
                extra=extra,
            )
        )
    return ParseResult(SOURCE, events, skipped, len(lines))

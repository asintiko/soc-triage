from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

from ..model import Event, ParseResult, Skipped
from ..timeutil import MONTHS, parse_iso, strip_tz

SOURCE = "linux_auth"

_TAIL = r"(?P<proc>[^\s\[\]:]+)(?:\[(?P<pid>\d+)\])?:\s?(?P<msg>.*)$"
HEADER_ISO = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+(?P<host>\S+)\s+" + _TAIL
)
HEADER_BSD = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<clock>\d{2}):(?P<minute>\d{2}):(?P<second>\d{2})\s+(?P<host>\S+)\s+"
    + _TAIL
)

_SSH_FAILED = re.compile(
    r"^Failed (?P<method>\S+) for (?P<invalid>invalid user )?(?P<user>.*?) from (?P<ip>\S+) port (?P<port>\d+)"
)
_SSH_ACCEPTED = re.compile(r"^Accepted (?P<method>\S+) for (?P<user>.*?) from (?P<ip>\S+) port (?P<port>\d+)")
_SSH_INVALID = re.compile(r"^Invalid user (?P<user>.*?) from (?P<ip>\S+)(?: port (?P<port>\d+))?$")
_SSH_PREAUTH = re.compile(
    r"^(?:Connection closed by|Disconnected from|Connection reset by) "
    r"(?:(?:authenticating|invalid) user (?P<user>.*?) )?(?P<ip>[0-9a-fA-F.:]+) port (?P<port>\d+) \[preauth\]"
)
_SSH_MAX_AUTH = re.compile(
    r"^error: maximum authentication attempts exceeded for (?:invalid user )?(?P<user>.*?) from (?P<ip>\S+) port"
)
_SUDO = re.compile(r"^(?P<user>\S+) : (?P<body>.+)$")
_USERADD = re.compile(r"^new user: name=(?P<user>[^,\s]+)")
_USERDEL = re.compile(r"^delete user '(?P<user>[^']+)'")
_USERMOD_GROUP = re.compile(r"^add '(?P<user>[^']+)' to group '(?P<group>[^']+)'")
_GPASSWD = re.compile(r"^user (?P<user>\S+) added by (?P<actor>\S+) to group (?P<group>\S+)")
_PASSWD = re.compile(r"password changed for (?P<user>\S+)")
_SU_OK = re.compile(r"^\(to (?P<target>\S+)\) (?P<user>\S+) on (?P<tty>\S+)")
_SU_FAILED = re.compile(r"^FAILED SU \(to (?P<target>\S+)\) (?P<user>\S+) on (?P<tty>\S+)")
_PAM_SESSION = re.compile(
    r"^pam_unix\((?P<service>[^:)]+):session\): session (?P<state>opened|closed) for user (?P<user>[^\s(]+)"
)
_PAM_AUTH_FAILURE = re.compile(r"^pam_unix\((?P<service>[^:)]+):auth\): authentication failure;(?P<rest>.*)$")
_KEY_VALUE = re.compile(r"(\w+)=(\S*)")


def _sudo(match: re.Match) -> tuple[str, str, str, str, dict[str, str]]:
    body = match.group("body")
    command = ""
    position = body.find("COMMAND=")
    if position >= 0:
        command = body[position + len("COMMAND="):].strip()
        body = body[:position]
    extra: dict[str, str] = {}
    reasons = []
    for part in (piece.strip() for piece in body.split(" ; ")):
        if not part:
            continue
        key, separator, value = part.partition("=")
        if separator and key.isupper():
            extra[{"USER": "target_user", "PWD": "cwd", "TTY": "tty"}.get(key, key.lower())] = value
        else:
            reasons.append(part.rstrip(" ;"))
    if command:
        extra["command"] = command
    if reasons:
        extra["reason"] = "; ".join(reasons)
    return "sudo", "failure" if reasons else "success", match.group("user"), "", extra


def classify(process: str, message: str) -> tuple[str, str, str, str, dict[str, str]]:
    # сообщение syslog -> (event, result, user, ip, extra)
    match = _SSH_FAILED.match(message)
    if match:
        extra = {"method": match.group("method"), "port": match.group("port")}
        if match.group("invalid"):
            extra["invalid_user"] = "yes"
        return "login", "failure", match.group("user"), match.group("ip"), extra
    match = _SSH_ACCEPTED.match(message)
    if match:
        extra = {"method": match.group("method"), "port": match.group("port")}
        return "login", "success", match.group("user"), match.group("ip"), extra
    match = _SSH_INVALID.match(message)
    if match:
        return "invalid_user", "failure", match.group("user"), match.group("ip"), {}
    match = _SSH_PREAUTH.match(message)
    if match:
        return "preauth_disconnect", "failure", match.group("user") or "", match.group("ip"), {}
    match = _SSH_MAX_AUTH.match(message)
    if match:
        return "auth_limit_exceeded", "failure", match.group("user"), match.group("ip"), {}
    if process == "sudo":
        match = _SUDO.match(message.strip())
        if match:
            return _sudo(match)
    match = _SU_FAILED.match(message)
    if match:
        return "su", "failure", match.group("user"), "", {"target_user": match.group("target")}
    match = _SU_OK.match(message)
    if match:
        return "su", "success", match.group("user"), "", {"target_user": match.group("target")}
    match = _USERADD.match(message)
    if match:
        return "account_created", "success", match.group("user"), "", {}
    match = _USERDEL.match(message)
    if match:
        return "account_deleted", "success", match.group("user"), "", {}
    match = _USERMOD_GROUP.match(message)
    if match:
        return "group_member_added", "success", match.group("user"), "", {"group": match.group("group")}
    match = _GPASSWD.match(message)
    if match:
        extra = {"group": match.group("group"), "actor": match.group("actor")}
        return "group_member_added", "success", match.group("user"), "", extra
    match = _PAM_AUTH_FAILURE.match(message)
    if match:
        pairs = dict(_KEY_VALUE.findall(match.group("rest")))
        return "pam_auth_failure", "failure", pairs.get("user", ""), pairs.get("rhost", ""), {
            "service": match.group("service")
        }
    match = _PAM_SESSION.match(message)
    if match:
        return f"session_{match.group('state')}", "", match.group("user"), "", {"service": match.group("service")}
    if process in ("passwd", "chpasswd"):
        match = _PASSWD.search(message)
        if match:
            return "password_changed", "success", match.group("user"), "", {}
    return "other", "", "", "", {}


class _YearTracker:
    # в классич. syslog нет года, ведем его сами по ходу файла
    def __init__(self, year: int | None):
        self.fixed = year is not None
        self.year = year if year is not None else datetime.now().year
        self.previous_month: int | None = None

    def stamp(self, month: int, day: int, hour: int, minute: int, second: int) -> datetime | None:
        if self.previous_month is not None and self.previous_month - month >= 6:
            self.year += 1
        try:
            stamp = datetime(self.year, month, day, hour, minute, second)
        except ValueError:
            return None
        if self.previous_month is None and not self.fixed and stamp > datetime.now() + timedelta(days=2):
            self.year -= 1
            stamp = stamp.replace(year=self.year)
        self.previous_month = month
        return stamp


def parse(text: str, *, year: int | None = None, tz: timezone | None = None) -> ParseResult:
    events: list[Event] = []
    skipped: list[Skipped] = []
    years = _YearTracker(year)
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    for number, line in enumerate(lines, 1):
        line = line.rstrip("\r")
        if not line.strip():
            continue
        match = HEADER_ISO.match(line)
        if match:
            stamp = parse_iso(match.group("ts"))
        else:
            match = HEADER_BSD.match(line)
            stamp = None
            if match and match.group("mon").lower() in MONTHS:
                stamp = years.stamp(
                    MONTHS[match.group("mon").lower()],
                    int(match.group("day")),
                    int(match.group("clock")),
                    int(match.group("minute")),
                    int(match.group("second")),
                )
        if not match:
            skipped.append(Skipped(number, "not a syslog line", line[:200]))
            continue
        if stamp is None:
            skipped.append(Skipped(number, "unreadable timestamp", line[:200]))
            continue
        process = match.group("proc")
        message = match.group("msg")
        event, result, user, ip, extra = classify(process, message)
        extra = {"process": process, **extra}
        if event == "other":
            extra["message"] = message[:300]
        events.append(
            Event(
                time=strip_tz(stamp, tz),
                host=match.group("host"),
                user=user,
                ip=ip,
                event=event,
                result=result,
                source=SOURCE,
                line=number,
                raw=line,
                extra=extra,
            )
        )
    return ParseResult(SOURCE, events, skipped, len(lines))

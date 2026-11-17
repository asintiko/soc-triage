from __future__ import annotations

import csv
import io
import json
import re
from datetime import timezone

from ..model import Event, ParseResult, Skipped
from ..timeutil import parse_any, strip_tz

SOURCE = "windows"

_ID_KEYS = ("eventid", "event_id", "id", "event id", "eventcode")
_TIME_KEYS = ("timecreated", "systemtime", "utctime", "timegenerated", "@timestamp", "date and time", "time")
_HOST_KEYS = ("computer", "machinename", "computername", "hostname")

# id события -> (событие, результат)
EVENT_NAMES: dict[int, tuple[str, str]] = {
    104: ("log_cleared", "success"),
    1102: ("log_cleared", "success"),
    4104: ("powershell_script", ""),
    4624: ("login", "success"),
    4625: ("login", "failure"),
    4634: ("logoff", ""),
    4647: ("logoff", ""),
    4648: ("explicit_credentials", "success"),
    4672: ("special_privileges", "success"),
    4688: ("process_created", "success"),
    4697: ("service_installed", "success"),
    4698: ("scheduled_task_created", "success"),
    4720: ("account_created", "success"),
    4722: ("account_enabled", "success"),
    4723: ("password_changed", "success"),
    4724: ("password_reset", "success"),
    4725: ("account_disabled", "success"),
    4726: ("account_deleted", "success"),
    4728: ("group_member_added", "success"),
    4732: ("group_member_added", "success"),
    4756: ("group_member_added", "success"),
    4729: ("group_member_removed", "success"),
    4733: ("group_member_removed", "success"),
    4757: ("group_member_removed", "success"),
    4740: ("account_locked", ""),
    4768: ("kerberos_ticket", ""),
    4769: ("kerberos_ticket", ""),
    4771: ("kerberos_preauth", "failure"),
    4776: ("credential_validation", ""),
    7045: ("service_installed", "success"),
}

_ACTOR_IS_USER = {4648, 4672, 4688, 4697, 4698, 1102, 104}
_GROUP_EVENTS = {4728, 4732, 4756, 4729, 4733, 4757}

# (раздел, ключ) в тексте сообщения -> имя поля
_MESSAGE_FIELDS = {
    ("subject", "account name"): "subjectusername",
    ("account for which logon failed", "account name"): "targetusername",
    ("new logon", "account name"): "targetusername",
    ("new account", "account name"): "targetusername",
    ("target account", "account name"): "targetusername",
    ("account whose credentials were used", "account name"): "targetusername",
    ("member", "account name"): "membername",
    ("member", "security id"): "membersid",
    ("group", "group name"): "groupname",
    ("network information", "source network address"): "ipaddress",
    ("network information", "workstation name"): "workstationname",
    ("network information", "network address"): "ipaddress",
    ("process information", "new process name"): "newprocessname",
    ("process information", "process command line"): "commandline",
    ("process information", "creator process name"): "parentprocessname",
    ("service information", "service name"): "servicename",
    ("service information", "service file name"): "servicefilename",
    ("task information", "task name"): "taskname",
    ("", "logon type"): "logontype",
    ("", "service name"): "servicename",
    ("", "service file name"): "imagepath",
}
_SECTION = re.compile(r"^(?P<name>[A-Za-z][A-Za-z ]+):\s*$")
_FIELD = re.compile(r"^(?P<indent>\s*)(?P<key>[A-Za-z][A-Za-z ]+):\s*(?P<value>.*)$")
_IPV4_OR_V6 = re.compile(r"(?<![\w.])(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F]*:[0-9a-fA-F:.]+)(?![\w.])")


def _scalar(value) -> str:
    if value is None:
        return ""
    if isinstance(value, dict):
        if "#text" in value:
            return _scalar(value["#text"])
        return ""
    if isinstance(value, list):
        return ", ".join(_scalar(item) for item in value)
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value).strip()


def _attr(node, name: str) -> str:
    attributes = node.get("#attributes") if isinstance(node, dict) else None
    return _scalar(attributes.get(name)) if isinstance(attributes, dict) else ""


def _flatten_event(event: dict) -> dict[str, str]:
    # вложенный формат evtx_dump -> плоская строка
    flat: dict[str, str] = {}
    system = event.get("System") or {}
    if isinstance(system, dict):
        flat["eventid"] = _scalar(system.get("EventID"))
        flat["timecreated"] = _attr(system.get("TimeCreated"), "SystemTime")
        flat["computer"] = _scalar(system.get("Computer"))
        flat["channel"] = _scalar(system.get("Channel"))
        flat["provider"] = _attr(system.get("Provider"), "Name")
    for section in ("EventData", "UserData"):
        data = event.get(section)
        if not isinstance(data, dict):
            continue
        stack = [data]
        while stack:
            for key, value in stack.pop().items():
                if key == "#attributes":
                    continue
                if isinstance(value, dict) and "#text" not in value:
                    stack.append(value)
                else:
                    flat.setdefault(key.lower(), _scalar(value))
    return flat


def _payload_fields(payload: str) -> dict[str, str]:
    # EvtxECmd кладет данные события json-ом в колонку Payload
    try:
        document = json.loads(payload)
    except (ValueError, TypeError, RecursionError):
        return {}
    fields: dict[str, str] = {}
    stack = [document]
    while stack:
        node = stack.pop()
        if isinstance(node, list):
            stack.extend(node)
        elif isinstance(node, dict):
            name = node.get("@Name")
            if isinstance(name, str):
                fields.setdefault(name.lower(), _scalar(node.get("#text")))
            for key, value in node.items():
                if isinstance(value, (dict, list)):
                    stack.append(value)
                elif not isinstance(name, str) and not key.startswith(("@", "#")):
                    # в UserData (напр. очистка журнала) поля названы тегами
                    fields.setdefault(key.lower(), _scalar(value))
    return fields


def _message_fields(message: str) -> dict[str, str]:
    # поля из англ. текста события, когда отдельных колонок нет
    fields: dict[str, str] = {}
    section = ""
    for line in message.replace("\r", "").split("\n"):
        if not line.strip():
            continue
        heading = _SECTION.match(line)
        if heading:
            section = heading.group("name").strip().lower()
            continue
        match = _FIELD.match(line)
        if not match:
            continue
        scope = section if match.group("indent") else ""
        name = _MESSAGE_FIELDS.get((scope, match.group("key").strip().lower()))
        if name:
            fields.setdefault(name, match.group("value").strip())
    return fields


def flatten(row: dict) -> dict[str, str]:
    if isinstance(row.get("Event"), dict):
        return _flatten_event(row["Event"])
    flat = {str(key).strip().lower(): _scalar(value) for key, value in row.items() if key is not None}
    payload = flat.get("payload", "")
    if payload.startswith("{"):
        for key, value in _payload_fields(payload).items():
            flat.setdefault(key, value)
    message = flat.get("message", "")
    if message and "targetusername" not in flat and "subjectusername" not in flat:
        for key, value in _message_fields(message).items():
            flat.setdefault(key, value)
    return flat


def _pick(flat: dict[str, str], *names: str) -> str:
    for name in names:
        value = flat.get(name, "")
        if value and value != "-":
            return value
    return ""


def _clean_ip(value: str) -> str:
    value = value.strip()
    if value in ("", "-", "LOCAL"):
        return ""
    if value.lower().startswith("::ffff:"):
        value = value[7:]
    return value


def _bare_user(value: str) -> str:
    # CORP\j.smith -> j.smith
    return value.rsplit("\\", 1)[-1]


def normalise(flat: dict[str, str], line: int, raw: str, tz: timezone | None) -> Event | str:
    # вернет событие или строку с причиной, почему запись не подошла
    raw_id = _pick(flat, *_ID_KEYS)
    try:
        event_id = int(float(raw_id))
    except (ValueError, OverflowError):
        return "no event id"
    stamp = parse_any(_pick(flat, *_TIME_KEYS))
    if stamp is None:
        return "unreadable timestamp"
    if stamp.tzinfo is None and "recordnumber" in flat and "chunknumber" in flat:
        # EvtxECmd пишет utc без пометки
        stamp = stamp.replace(tzinfo=timezone.utc)
    provider = _pick(flat, "provider", "providername", "source")
    name, result = EVENT_NAMES.get(event_id, ("other", ""))
    if event_id == 104 and provider and "eventlog" not in provider.lower():
        name, result = "other", ""
    if event_id == 7045 and provider and "service control manager" not in provider.lower():
        name, result = "other", ""

    subject = _bare_user(_pick(flat, "subjectusername"))
    target = _bare_user(_pick(flat, "targetusername", "username"))
    extra: dict[str, str] = {"event_id": str(event_id)}

    if event_id in _GROUP_EVENTS:
        user = _bare_user(_pick(flat, "membername")) or _pick(flat, "membersid")
        extra["group"] = _pick(flat, "groupname") or target
    elif event_id in _ACTOR_IS_USER:
        user = subject
        if target and target != subject:
            extra["target_user"] = target
    else:
        user = target or subject
    if subject and subject != user:
        extra["actor"] = subject

    remote_host = flat.get("remotehost", "")
    ip = _clean_ip(_pick(flat, "ipaddress", "sourceaddress", "clientaddress"))
    if not ip and remote_host:
        found = _IPV4_OR_V6.search(remote_host)
        ip = _clean_ip(found.group(0)) if found else ""

    status = _pick(flat, "status", "resultcode", "failurecode")
    if event_id in (4768, 4769, 4776) and status:
        result = "success" if status.lower() in ("0x0", "0", "0x00000000") else "failure"

    for key, sources in (
        ("channel", ("channel", "logname")),
        ("provider", ("provider", "providername", "source")),
        ("logon_type", ("logontype",)),
        ("workstation", ("workstationname", "workstation")),
        ("domain", ("targetdomainname",)),
        ("process", ("newprocessname", "processname")),
        ("parent", ("parentprocessname",)),
        ("command", ("commandline", "imagepath", "servicefilename", "scriptblocktext", "executableinfo")),
        ("service", ("servicename",)),
        ("task", ("taskname",)),
        ("status", ("status", "resultcode", "failurecode")),
        ("sub_status", ("substatus",)),
    ):
        value = _pick(flat, *sources)
        if value:
            extra[key] = value if key != "command" else value[:600]
    if name == "other":
        extra["message"] = (flat.get("mapdescription") or flat.get("message", "")).split("\n", 1)[0][:200]

    return Event(
        time=strip_tz(stamp, tz),
        host=_pick(flat, *_HOST_KEYS),
        user=user,
        ip=ip,
        event=name,
        result=result,
        source=SOURCE,
        line=line,
        raw=raw,
        extra=extra,
    )


def is_csv_header(line: str) -> bool:
    names = {name.strip().strip('"').lower() for name in re.split(r"[,;\t]", line)}
    return bool(names & set(_ID_KEYS)) and bool(names & set(_TIME_KEYS))


def _json_documents(text: str):
    # json-массив, json lines и вывод evtx_dump; отдает (строка, документ или None, текст)
    decoder = json.JSONDecoder()
    position, line, length = 0, 1, len(text)
    while position < length:
        char = text[position]
        if char in " \t\r\n,":
            if char == "\n":
                line += 1
            position += 1
            continue
        if char in "{[":
            try:
                document, end = decoder.raw_decode(text, position)
            except (ValueError, RecursionError):
                document, end = None, None
            if end is not None:
                chunk = text[position:end]
                yield line, document, chunk
                line += chunk.count("\n")
                position = end
                continue
        end = text.find("\n", position)
        end = length if end < 0 else end
        chunk = text[position:end]
        if not re.match(r"^Record \d+\s*$", chunk) and chunk.strip() not in ("]", "}"):
            yield line, None, chunk
        position = end


def _rows_from_json(text: str):
    # записи нумеруем с 1 по порядку в файле
    number = 0
    for _, document, chunk in _json_documents(text):
        if document is None:
            number += 1
            yield number, None, chunk
            continue
        if isinstance(document, dict) and not isinstance(document.get("Event"), dict):
            nested = [value for value in document.values() if isinstance(value, list) and value]
            if len(nested) == 1 and all(isinstance(item, dict) for item in nested[0]):
                document = nested[0]
        for item in document if isinstance(document, list) else [document]:
            number += 1
            try:
                compact = json.dumps(item, ensure_ascii=False, separators=(",", ":"))
            except (ValueError, RecursionError):
                compact = str(item)[:200]
            yield number, item if isinstance(item, dict) else None, compact


def _rows_from_csv(text: str):
    header = text.split("\n", 1)[0]
    delimiter = max(",;\t", key=header.count)
    reader = csv.reader(io.StringIO(text, newline=""), delimiter=delimiter)
    try:
        names = [name.strip() for name in next(reader)]
    except StopIteration:
        return
    # event viewer оставляет колонку сообщения без заголовка
    names = [name or "message" for name in names]
    while True:
        try:
            cells = next(reader)
        except StopIteration:
            return
        except csv.Error:
            yield reader.line_num, None, ""
            continue
        if not any(cell.strip() for cell in cells):
            continue
        if len(cells) == len(names) + 1 and "message" not in (name.lower() for name in names):
            names = names + ["message"]
        raw = delimiter.join(cells)
        if len(cells) < 2:
            yield reader.line_num, None, raw
            continue
        yield reader.line_num, dict(zip(names, cells)), raw


# форматы: плоский csv/json, evtx_dump, EvtxECmd, выгрузки Get-WinEvent и Event Viewer
# (в последних поля есть только в тексте сообщения)
def parse(text: str, *, year: int | None = None, tz: timezone | None = None) -> ParseResult:
    events: list[Event] = []
    skipped: list[Skipped] = []
    stripped = text.lstrip()
    is_json = stripped[:1] in ("{", "[") or stripped.startswith("Record ")
    rows = _rows_from_json(text) if is_json else _rows_from_csv(text)
    total = 0
    for line, row, raw in rows:
        total += 1
        if row is None:
            skipped.append(Skipped(line, "not a readable record", raw[:200]))
            continue
        try:
            outcome = normalise(flatten(row), line, raw[:2000], tz)
        except (AttributeError, TypeError, ValueError, OverflowError):
            outcome = "malformed record"
        if isinstance(outcome, str):
            skipped.append(Skipped(line, outcome, raw[:200]))
        else:
            events.append(outcome)
    return ParseResult(SOURCE, events, skipped, total)

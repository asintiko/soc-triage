from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

MONTH_NAMES = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")
MONTHS = {name.lower(): number for number, name in enumerate(MONTH_NAMES, 1)}

_ISO = re.compile(
    r"^\s*(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(?:[.,](\d+))?\s*(Z|z|[+-]\d{2}:?\d{2})?\s*$"
)
_CLF = re.compile(r"^\s*(\d{1,2})/([A-Za-z]{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2})(?:\s*([+-]\d{4}))?\s*$")
_US = re.compile(r"^\s*(\d{1,2})/(\d{1,2})/(\d{4}),?\s+(\d{1,2}):(\d{2}):(\d{2})\s*([AaPp][Mm])?\s*$")
_DOTTED = re.compile(r"^\s*(\d{1,2})\.(\d{1,2})\.(\d{4}),?\s+(\d{1,2}):(\d{2}):(\d{2})\s*$")
_DOTNET = re.compile(r"^\s*/Date\((-?\d+)\)/\s*$")
_OFFSET = re.compile(r"^([+-])(\d{2}):?(\d{2})$")
_DURATION = re.compile(r"^\s*(\d+)\s*([smhd]?)\s*$")
_UNIT_SECONDS = {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400}


def parse_offset(text: str) -> timezone:
    # +05:00 или -0330
    if text.strip().upper() in ("Z", "UTC"):
        return timezone.utc
    match = _OFFSET.match(text.strip())
    if not match:
        raise ValueError(f"not a UTC offset: {text!r} (expected a value such as +05:00)")
    sign = 1 if match.group(1) == "+" else -1
    return timezone(sign * timedelta(hours=int(match.group(2)), minutes=int(match.group(3))))


def _build(year, month, day, hour, minute, second, fraction="", offset=None) -> datetime | None:
    micro = int((fraction or "0")[:6].ljust(6, "0"))
    try:
        stamp = datetime(int(year), int(month), int(day), int(hour), int(minute), int(second), micro)
    except ValueError:
        return None
    if offset:
        try:
            stamp = stamp.replace(tzinfo=parse_offset(offset))
        except ValueError:
            return None
    return stamp


def parse_iso(text: str) -> datetime | None:
    match = _ISO.match(text)
    if not match:
        return None
    year, month, day, hour, minute, second, fraction, offset = match.groups()
    return _build(year, month, day, hour, minute, second, fraction or "", offset)


def parse_clf(text: str) -> datetime | None:
    # 10/Nov/2026:13:55:36 +0500
    match = _CLF.match(text)
    if not match:
        return None
    day, month_name, year, hour, minute, second, offset = match.groups()
    month = MONTHS.get(month_name.lower())
    if month is None:
        return None
    return _build(year, month, day, hour, minute, second, offset=offset)


def parse_us(text: str) -> datetime | None:
    # 11/10/2026 3:12:45 AM - так пишут powershell и event viewer (en-US)
    match = _US.match(text)
    if not match:
        return None
    month, day, year, hour, minute, second, meridiem = match.groups()
    hour = int(hour)
    if meridiem:
        hour = hour % 12 + (12 if meridiem.lower() == "pm" else 0)
    return _build(year, month, day, hour, minute, second)


def parse_dotted(text: str) -> datetime | None:
    # 10.11.2026 3:12:45, день первым
    match = _DOTTED.match(text)
    if not match:
        return None
    day, month, year, hour, minute, second = match.groups()
    return _build(year, month, day, hour, minute, second)


def parse_dotnet(text: str) -> datetime | None:
    # /Date(1794280365123)/ - ConvertTo-Json в powershell 5.1
    match = _DOTNET.match(text)
    if not match:
        return None
    try:
        return datetime.fromtimestamp(int(match.group(1)) / 1000, tz=timezone.utc)
    except (ValueError, OverflowError, OSError):
        return None


def parse_any(text: str) -> datetime | None:
    for parser in (parse_iso, parse_dotnet, parse_us, parse_dotted, parse_clf):
        stamp = parser(text)
        if stamp is not None:
            return stamp
    return None


def strip_tz(stamp: datetime, target: timezone | None = None) -> datetime:
    # убираем смещение, чтобы все события были на одних часах; если задан target - сначала переводим в него
    if stamp.tzinfo is None:
        return stamp
    if target is not None:
        try:
            stamp = stamp.astimezone(target)
        except OverflowError:
            pass
    return stamp.replace(tzinfo=None)


def parse_duration(value) -> timedelta:
    # 90, 90s, 5m, 2h, 1d
    match = _DURATION.match(str(value))
    if not match:
        raise ValueError(f"not a duration: {value!r} (expected a value such as 5m, 2h or 90s)")
    seconds = int(match.group(1)) * _UNIT_SECONDS[match.group(2)]
    if not 0 < seconds <= 366 * 86400:
        raise ValueError(f"duration must be between one second and a year: {value!r}")
    return timedelta(seconds=seconds)


def fmt_duration(span: timedelta) -> str:
    seconds = int(span.total_seconds())
    if seconds < 60:
        return f"{seconds} s"
    parts = []
    days, seconds = divmod(seconds, 86400)
    hours, seconds = divmod(seconds, 3600)
    minutes, seconds = divmod(seconds, 60)
    if days:
        parts.append(f"{days} d")
    if hours:
        parts.append(f"{hours} h")
    if minutes:
        parts.append(f"{minutes} min")
    if seconds and not days and not hours:
        parts.append(f"{seconds} s")
    return " ".join(parts)


def fmt_stamp(stamp: datetime, with_time: bool = True) -> str:
    # 10 Nov 02:14, без оглядки на локаль системы
    text = f"{stamp.day:02d} {MONTH_NAMES[stamp.month - 1]}"
    if with_time:
        text += f" {stamp.hour:02d}:{stamp.minute:02d}"
    return text

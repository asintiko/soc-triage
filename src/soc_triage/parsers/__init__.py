from __future__ import annotations

from datetime import timezone
from pathlib import Path

from ..model import ParseResult
from . import linux_auth, web_access, windows

PARSERS = {"linux": linux_auth.parse, "web": web_access.parse, "windows": windows.parse}
LABELS = {
    "linux": "Linux auth.log / syslog",
    "web": "Apache / Nginx access log",
    "windows": "Windows event log export (CSV / JSON)",
}


class FormatError(ValueError):
    pass


def read_text(path: Path) -> str:
    # powershell 5.1 пишет utf-16, остальное считаем utf-8
    data = Path(path).read_bytes()
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        return data.decode("utf-16", errors="replace")
    if data.startswith(b"\xef\xbb\xbf"):
        data = data[3:]
    return data.decode("utf-8", errors="replace")


def detect_format(text: str) -> str:
    sample = [line for line in text.split("\n")[:400] if line.strip()][:80]
    if not sample:
        raise FormatError("the file is empty")
    first = sample[0].lstrip()
    if first[:1] in ("{", "[") or first.startswith("Record "):
        return "windows"
    if windows.is_csv_header(first):
        return "windows"
    scores = {
        "web": sum(1 for line in sample if web_access.LINE.match(line) or web_access.LINE_VHOST.match(line)),
        "linux": sum(1 for line in sample if linux_auth.HEADER_ISO.match(line) or linux_auth.HEADER_BSD.match(line)),
    }
    best = max(scores, key=scores.get)
    if scores[best] == 0:
        raise FormatError("could not recognise the log format; pass --format linux, web or windows")
    return best


def parse_text(text: str, fmt: str = "auto", *, year: int | None = None, tz: timezone | None = None) -> tuple[str, ParseResult]:
    if fmt == "auto":
        fmt = detect_format(text)
    if fmt not in PARSERS:
        raise FormatError(f"unknown format {fmt!r}; expected one of: auto, {', '.join(PARSERS)}")
    return fmt, PARSERS[fmt](text, year=year, tz=tz)

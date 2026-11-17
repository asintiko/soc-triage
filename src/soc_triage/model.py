from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

CORE_FIELDS = ("host", "user", "ip", "event", "result", "source")


@dataclass
class Event:
    time: datetime
    host: str = ""
    user: str = ""
    ip: str = ""
    event: str = "other"
    result: str = ""
    source: str = ""
    line: int = 0
    raw: str = ""
    extra: dict[str, str] = field(default_factory=dict)

    def get(self, name: str) -> str:
        # сначала общие поля, потом доп. (status, path, command...)
        if name in CORE_FIELDS:
            return getattr(self, name)
        return self.extra.get(name, "")

    def as_dict(self) -> dict[str, str]:
        row = {"line": str(self.line), "time": self.time.isoformat(sep=" ", timespec="seconds")}
        for name in CORE_FIELDS:
            row[name] = getattr(self, name)
        row.update(self.extra)
        return row


@dataclass
class Skipped:
    line: int
    reason: str
    text: str


@dataclass
class ParseResult:
    source: str
    events: list[Event]
    skipped: list[Skipped]
    total_lines: int

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Sequence, Union


# все, что пришло из входного файла, заворачиваем в Code:
# ни html, ни markdown не трактуют это как разметку
@dataclass(frozen=True)
class Code:
    text: str


@dataclass(frozen=True)
class Strong:
    text: str


@dataclass(frozen=True)
class Badge:
    # метка критичности или веса, tone задает цвет
    text: str
    tone: str


Inline = Union[str, Code, Strong, Badge]
Cell = Union[Inline, Sequence[Inline]]


@dataclass
class Title:
    kicker: str
    title: Cell
    subtitle: Cell = ""


@dataclass
class Facts:
    items: list[tuple[str, Cell]]


@dataclass
class Heading:
    text: str
    level: int = 2


@dataclass
class Para:
    content: Cell
    muted: bool = False


@dataclass
class Table:
    headers: list[str]
    rows: list[list[Cell]]
    wide: bool = False


@dataclass
class Figure:
    title: str
    filename: str
    svg: str


@dataclass
class CodeBlock:
    lines: list[str]
    label: str = ""


@dataclass
class Callout:
    tone: str
    label: str
    content: Cell


@dataclass
class Section:
    # блок находки: цветная шапка + свои блоки
    number: int
    tone: str
    badge: str
    title: str
    meta: Cell
    blocks: list = field(default_factory=list)


@dataclass
class Document:
    title: str
    blocks: list


def inlines(cell: Cell) -> list[Inline]:
    if isinstance(cell, (str, Code, Strong, Badge)):
        return [cell]
    return list(cell)


def code_or_dash(value: str) -> Inline:
    return Code(value) if value else "—"

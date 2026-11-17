from __future__ import annotations

import re

from .doc import (
    Badge, Callout, Cell, Code, CodeBlock, Document, Facts, Figure, Heading, Para, Section, Strong, Table, Title,
    inlines,
)

_SPECIAL = re.compile(r"([\\`*_\[\]<>|#~])")


def _plain(text: str) -> str:
    return _SPECIAL.sub(r"\\\1", re.sub(r"\s+", " ", str(text)))


def _code(text: str, in_table: bool = False) -> str:
    # ограничитель из ` делаем длиннее любой серии ` внутри текста
    text = " ".join(text.split())
    if not text:
        return "—"
    longest = max((len(run) for run in re.findall(r"`+", text)), default=0)
    fence = "`" * (longest + 1)
    padding = " " if text.startswith("`") or text.endswith("`") or longest else ""
    if in_table:
        text = text.replace("|", "\\|")
    return f"{fence}{padding}{text}{padding}{fence}"


def _bold(text: str) -> str:
    # ** должны прилегать к тексту, пробелы по краям выносим наружу
    core = text.strip()
    if not core:
        return text
    lead = text[: len(text) - len(text.lstrip())]
    tail = text[len(text.rstrip()):]
    return f"{lead and ' '}**{_plain(core)}**{tail and ' '}"


def _inline(cell: Cell, in_table: bool = False) -> str:
    parts = []
    for item in inlines(cell):
        if isinstance(item, Code):
            parts.append(_code(item.text, in_table))
        elif isinstance(item, Strong):
            parts.append(_bold(item.text))
        elif isinstance(item, Badge):
            parts.append(f"**{_plain(item.text)}**")
        else:
            parts.append(_plain(item))
    return "".join(parts)


def _fenced(lines: list[str]) -> str:
    longest = max((len(run) for line in lines for run in re.findall(r"`+", line)), default=0)
    fence = "`" * max(3, longest + 1)
    return "\n".join([f"{fence}text", *lines, fence])


def _block(block, depth: int = 0) -> str:
    if isinstance(block, Title):
        lines = [f"# {_inline(block.title)}", "", f"*{_plain(block.kicker)}*"]
        if block.subtitle:
            lines += ["", _inline(block.subtitle)]
        return "\n".join(lines)
    if isinstance(block, Facts):
        return "\n".join(f"- **{_plain(label)}:** {_inline(value)}" for label, value in block.items)
    if isinstance(block, Heading):
        return f"{'#' * (block.level + depth)} {_plain(block.text)}"
    if isinstance(block, Para):
        return _inline(block.content)
    if isinstance(block, Table):
        head = "| " + " | ".join(_plain(name) for name in block.headers) + " |"
        rule = "|" + "|".join(" --- " for _ in block.headers) + "|"
        rows = ["| " + " | ".join(_inline(cell, in_table=True) for cell in row) + " |" for row in block.rows]
        return "\n".join([head, rule, *rows])
    if isinstance(block, Figure):
        return f"![{_plain(block.title)}]({block.filename})"
    if isinstance(block, CodeBlock):
        label = f"{_plain(block.label)}:\n\n" if block.label else ""
        return label + _fenced(block.lines)
    if isinstance(block, Callout):
        return f"> **{_plain(block.label)}**\n>\n> {_inline(block.content)}"
    if isinstance(block, Section):
        head = f"### {block.number}. {_plain(block.title)}"
        meta = f"**{_plain(block.badge)}** · {_inline(block.meta)}"
        return "\n\n".join([head, meta, *(_block(item, depth=1) for item in block.blocks)])
    raise TypeError(f"cannot render {type(block).__name__}")


def render_markdown(document: Document, footer: str = "") -> str:
    parts = [_block(block) for block in document.blocks]
    if footer:
        parts += ["---", _plain(footer)]
    return "\n\n".join(parts) + "\n"

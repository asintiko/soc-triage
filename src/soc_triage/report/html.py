from __future__ import annotations

from html import escape

from .doc import (
    Badge, Callout, Cell, Code, CodeBlock, Document, Facts, Figure, Heading, Para, Section, Strong, Table, Title,
    inlines,
)

CSS = """
:root {
  --ink: #16181d; --muted: #5b6370; --line: #e3e5e8; --page: #f6f6f4; --paper: #ffffff; --wash: #f3f4f6;
  --critical: #b42318; --high: #c2410c; --medium: #946200; --low: #33658a; --info: #5b6370; --ok: #2f6b3a;
  --sans: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
  --mono: ui-monospace, "SF Mono", SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace;
}
* { box-sizing: border-box; }
html { -webkit-text-size-adjust: 100%; }
body { margin: 0; background: var(--page); color: var(--ink); font: 15px/1.55 var(--sans); }
main { max-width: 1040px; margin: 0 auto; padding: 56px 40px 72px; background: var(--paper); min-height: 100vh;
  border-left: 1px solid var(--line); border-right: 1px solid var(--line); }
.top { padding-bottom: 28px; border-bottom: 2px solid var(--ink); margin-bottom: 28px; }
.kicker { margin: 0 0 10px; color: var(--muted); font-size: 13px; }
h1 { margin: 0; font-size: 34px; line-height: 1.15; letter-spacing: -0.02em; font-weight: 650; overflow-wrap: anywhere; }
h1 code { font-size: 0.92em; background: none; padding: 0; }
.sub { margin: 12px 0 0; color: var(--muted); }
h2 { margin: 48px 0 14px; font-size: 20px; letter-spacing: -0.01em; }
h3 { margin: 28px 0 10px; font-size: 16px; }
p { margin: 0 0 12px; max-width: 76ch; }
p.muted { color: var(--muted); font-size: 14px; }
code { font: 13px/1.5 var(--mono); background: var(--wash); padding: 1px 5px; border-radius: 3px; overflow-wrap: anywhere; }
code.nw { white-space: nowrap; }
strong { font-weight: 650; }
.facts { display: flex; flex-wrap: wrap; gap: 1px; margin: 0; background: var(--line); border: 1px solid var(--line); }
.facts div { flex: 1 1 200px; padding: 12px 14px; background: var(--paper); min-width: 0; }
.facts div.wide { flex-basis: 100%; }
.facts dt { color: var(--muted); font-size: 12.5px; margin-bottom: 2px; }
.facts dd { margin: 0; font-size: 15px; overflow-wrap: anywhere; }
.facts dd code { background: none; padding: 0; }
.scroll { overflow-x: auto; margin: 0 0 16px; }
table { border-collapse: collapse; width: 100%; font-size: 13.5px; }
th { text-align: left; font-weight: 600; color: var(--muted); font-size: 12.5px; padding: 7px 10px 7px 0;
  border-bottom: 1px solid var(--ink); white-space: nowrap; }
td { padding: 7px 10px 7px 0; border-bottom: 1px solid var(--line); vertical-align: top; }
td code { background: none; padding: 0; }
table.wide td { min-width: 72px; }
figure { margin: 0 0 20px; border: 1px solid var(--line); padding: 8px; }
figure svg { display: block; width: 100%; height: auto; }
pre { margin: 0 0 16px; padding: 12px 14px; background: var(--wash); font: 12.5px/1.6 var(--mono); overflow-x: auto;
  white-space: pre-wrap; overflow-wrap: anywhere; border-left: 2px solid var(--line); }
.label { margin: 14px 0 6px; color: var(--muted); font-size: 12.5px; }
.badge { display: inline-block; font-size: 11.5px; font-weight: 650; line-height: 1; padding: 4px 7px 3px;
  border: 1px solid currentColor; border-radius: 3px; white-space: nowrap; letter-spacing: 0.02em; }
.tone-critical { --tone: var(--critical); } .tone-high { --tone: var(--high); } .tone-medium { --tone: var(--medium); }
.tone-low { --tone: var(--low); } .tone-info { --tone: var(--info); } .tone-ok { --tone: var(--ok); }
.badge { color: var(--tone, var(--muted)); }
.callout { border-left: 4px solid var(--tone, var(--muted)); background: var(--wash); padding: 16px 18px; margin: 0 0 24px; }
.callout .verdict { display: block; font-size: 22px; font-weight: 650; letter-spacing: -0.01em; color: var(--tone); margin-bottom: 4px; }
.callout p { margin: 0; }
.finding { margin: 0 0 36px; padding: 18px 0 0 18px; border-left: 4px solid var(--tone, var(--muted));
  border-top: 1px solid var(--line); }
.finding > header { display: grid; grid-template-columns: auto 1fr; gap: 4px 12px; align-items: baseline; margin-bottom: 12px; }
.finding > header h3 { margin: 0; font-size: 18px; letter-spacing: -0.01em; }
.finding > header .meta { grid-column: 2; margin: 0; color: var(--muted); font-size: 13.5px; }
.finding .num { color: var(--muted); font-variant-numeric: tabular-nums; margin-right: 6px; }
footer { margin-top: 56px; padding-top: 16px; border-top: 1px solid var(--line); color: var(--muted); font-size: 13px; }
@media (max-width: 720px) { main { padding: 32px 18px 48px; border: 0; } h1 { font-size: 26px; } }
@media print {
  body { background: #fff; font-size: 12px; } main { border: 0; padding: 0; max-width: none; }
  .finding, figure, table { break-inside: avoid; } pre { white-space: pre-wrap; }
}
""".strip()


def _inline(cell: Cell) -> str:
    parts = []
    for item in inlines(cell):
        if isinstance(item, Code):
            # короткие значения (id техники, ip, логин) не рвем посреди слова
            short = ' class="nw"' if len(item.text) <= 26 and " " not in item.text else ""
            parts.append(f"<code{short}>{escape(item.text)}</code>")
        elif isinstance(item, Strong):
            parts.append(f"<strong>{escape(item.text)}</strong>")
        elif isinstance(item, Badge):
            parts.append(f'<span class="badge tone-{escape(item.tone, quote=True)}">{escape(item.text)}</span>')
        else:
            parts.append(escape(str(item)))
    return "".join(parts)


def _block(block) -> str:
    if isinstance(block, Title):
        subtitle = f'<p class="sub">{_inline(block.subtitle)}</p>' if block.subtitle else ""
        return f'<header class="top"><p class="kicker">{escape(block.kicker)}</p><h1>{_inline(block.title)}</h1>{subtitle}</header>'
    if isinstance(block, Facts):
        items = []
        for label, value in block.items:
            wide = ' class="wide"' if isinstance(value, Code) and len(value.text) >= 48 else ""
            items.append(f"<div{wide}><dt>{escape(label)}</dt><dd>{_inline(value)}</dd></div>")
        return f'<dl class="facts">{"".join(items)}</dl>'
    if isinstance(block, Heading):
        return f"<h{block.level}>{escape(block.text)}</h{block.level}>"
    if isinstance(block, Para):
        return f'<p class="muted">{_inline(block.content)}</p>' if block.muted else f"<p>{_inline(block.content)}</p>"
    if isinstance(block, Table):
        head = "".join(f"<th>{escape(name)}</th>" for name in block.headers)
        body = "".join("<tr>" + "".join(f"<td>{_inline(cell)}</td>" for cell in row) + "</tr>" for row in block.rows)
        kind = ' class="wide"' if block.wide else ""
        return f'<div class="scroll"><table{kind}><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>'
    if isinstance(block, Figure):
        return f"<figure>{block.svg}</figure>"
    if isinstance(block, CodeBlock):
        label = f'<p class="label">{escape(block.label)}</p>' if block.label else ""
        return f"{label}<pre>{escape(chr(10).join(block.lines))}</pre>"
    if isinstance(block, Callout):
        return (
            f'<div class="callout tone-{escape(block.tone, quote=True)}"><span class="verdict">{escape(block.label)}</span>'
            f"<p>{_inline(block.content)}</p></div>"
        )
    if isinstance(block, Section):
        inner = "\n".join(_block(item) for item in block.blocks)
        return (
            f'<section class="finding tone-{escape(block.tone, quote=True)}"><header>'
            f'<span class="badge">{escape(block.badge)}</span>'
            f'<h3><span class="num">{block.number}.</span>{escape(block.title)}</h3>'
            f'<p class="meta">{_inline(block.meta)}</p></header>\n{inner}\n</section>'
        )
    raise TypeError(f"cannot render {type(block).__name__}")


def render_html(document: Document, footer: str = "") -> str:
    body = "\n".join(_block(block) for block in document.blocks)
    tail = f"\n<footer>{escape(footer)}</footer>" if footer else ""
    return (
        '<!doctype html>\n<html lang="en">\n<head>\n<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        '<meta name="referrer" content="no-referrer">\n'
        f"<title>{escape(document.title)}</title>\n<style>\n{CSS}\n</style>\n</head>\n<body>\n<main>\n"
        f"{body}{tail}\n</main>\n</body>\n</html>\n"
    )

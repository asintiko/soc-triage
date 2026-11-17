from __future__ import annotations

from datetime import datetime, timedelta
from html import escape

from ..timeutil import fmt_duration, fmt_stamp

WIDTH = 960
INK = "#16181d"
MUTED = "#5b6370"
GRID = "#e6e8eb"
BAR = "#b4bcc8"
ACCENT = "#c2410c"
FONT = "-apple-system, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif"
MONO = "ui-monospace, 'SF Mono', Menlo, Consolas, monospace"

_BUCKETS = [
    timedelta(minutes=1), timedelta(minutes=5), timedelta(minutes=10), timedelta(minutes=15),
    timedelta(minutes=30), timedelta(hours=1), timedelta(hours=2), timedelta(hours=3),
    timedelta(hours=6), timedelta(hours=12), timedelta(days=1), timedelta(days=7),
]
_EPOCH = datetime(1970, 1, 1)
_MAX_BARS = 72


def _open(height: int, title: str) -> list[str]:
    return [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {WIDTH} {height}" width="{WIDTH}" height="{height}" '
        f'role="img" aria-label="{escape(title, quote=True)}" font-family="{FONT}" font-size="12">',
        f"<title>{escape(title)}</title>",
        f'<rect width="{WIDTH}" height="{height}" fill="#ffffff"/>',
        f'<text x="20" y="24" font-size="14" font-weight="600" fill="{INK}">{escape(title)}</text>',
    ]


def _legend(parts: list[str], flagged_label: str, other_label: str) -> None:
    x = WIDTH - 20
    for label, colour in ((other_label, BAR), (flagged_label, ACCENT)):
        width = len(label) * 6.4
        parts.append(f'<text x="{x:.0f}" y="24" text-anchor="end" fill="{MUTED}">{escape(label)}</text>')
        parts.append(f'<rect x="{x - width - 16:.0f}" y="14" width="10" height="10" fill="{colour}"/>')
        x -= width + 34


def _nice(value: int) -> int:
    # вверх до 1, 2 или 5 * 10^n
    if value <= 5:
        return max(value, 1)
    magnitude = 10 ** (len(str(value)) - 1)
    for step in (1, 2, 5, 10):
        if value <= step * magnitude:
            return step * magnitude
    return value


def pick_bucket(first: datetime, last: datetime) -> timedelta:
    span = last - first
    for bucket in _BUCKETS:
        if span / bucket <= _MAX_BARS:
            return bucket
    return _BUCKETS[-1]


def time_chart(title: str, points: list[tuple[datetime, bool]], flagged_label: str, other_label: str) -> str:
    # столбики по интервалам, отказы поверх другим цветом
    height = 280
    left, right, top, bottom = 56, 20, 50, 40
    if not points:
        parts = _open(height, title)
        parts.append(f'<text x="20" y="{height // 2}" fill="{MUTED}">No events to plot.</text></svg>')
        return "\n".join(parts)

    first = min(stamp for stamp, _ in points)
    last = max(stamp for stamp, _ in points)
    bucket = pick_bucket(first, last)
    origin = _EPOCH + ((first - _EPOCH) // bucket) * bucket
    count = int((last - origin) // bucket) + 1
    totals = [0] * count
    flagged = [0] * count
    for stamp, is_flagged in points:
        index = int((stamp - origin) // bucket)
        totals[index] += 1
        flagged[index] += is_flagged

    parts = _open(height, f"{title}, {fmt_duration(bucket)} per bar")
    _legend(parts, flagged_label, other_label)
    plot_width = WIDTH - left - right
    plot_height = height - top - bottom
    ceiling = _nice(max(totals))
    for tick in sorted({0, ceiling // 2, ceiling}):
        y = top + plot_height - plot_height * tick / ceiling
        parts.append(f'<line x1="{left}" x2="{WIDTH - right}" y1="{y:.1f}" y2="{y:.1f}" stroke="{GRID}"/>')
        parts.append(f'<text x="{left - 8}" y="{y + 4:.1f}" text-anchor="end" fill="{MUTED}">{tick}</text>')

    step = plot_width / count
    gap = 1 if step >= 4 else 0
    for index in range(count):
        if not totals[index]:
            continue
        x = left + index * step
        full = plot_height * totals[index] / ceiling
        marked = plot_height * flagged[index] / ceiling
        base = top + plot_height
        if full - marked > 0:
            parts.append(
                f'<rect x="{x:.1f}" y="{base - full:.1f}" width="{step - gap:.1f}" height="{full - marked:.1f}" fill="{BAR}"/>'
            )
        if marked > 0:
            parts.append(
                f'<rect x="{x:.1f}" y="{base - marked:.1f}" width="{step - gap:.1f}" height="{marked:.1f}" fill="{ACCENT}"/>'
            )

    labels = min(6, count)
    positions = sorted({round(i * (count - 1) / (labels - 1)) for i in range(labels)}) if labels > 1 else [0]
    with_time = bucket < timedelta(days=1)
    for position in positions:
        x = left + (position + 0.5) * step
        anchor = "start" if position == 0 else "end" if position == count - 1 and count > 1 else "middle"
        x = left if anchor == "start" else WIDTH - right if anchor == "end" else x
        text = fmt_stamp(origin + position * bucket, with_time)
        parts.append(f'<text x="{x:.1f}" y="{height - 16}" text-anchor="{anchor}" fill="{MUTED}">{text}</text>')
    parts.append("</svg>")
    return "\n".join(parts)


def bar_chart(title: str, rows: list[tuple[str, int, int]], flagged_label: str = "", other_label: str = "",
              unit: str = "") -> str:
    # строка = (подпись, всего, из них помечено)
    row_height = 26
    top = 46
    height = top + row_height * max(len(rows), 1) + 14
    parts = _open(height, title)
    if not rows:
        parts.append(f'<text x="20" y="{top + 16}" fill="{MUTED}">Nothing to plot.</text></svg>')
        return "\n".join(parts)
    if flagged_label:
        _legend(parts, flagged_label, other_label)
    label_width = min(max(max(len(label) for label, _, _ in rows) * 7.3 + 8, 110), 400)
    values = [
        f"{total}{unit}, {marked} {flagged_label}" if marked and flagged_label else f"{total}{unit}"
        for _, total, marked in rows
    ]
    start = 20 + label_width + 12
    room = WIDTH - start - 28 - max(len(value) for value in values) * 6.6
    largest = max(total for _, total, _ in rows) or 1
    for index, (label, total, marked) in enumerate(rows):
        y = top + index * row_height
        shown = label if len(label) <= 52 else label[:51] + "…"
        parts.append(
            f'<text x="{20 + label_width:.0f}" y="{y + 15}" text-anchor="end" font-family="{MONO}" fill="{INK}">{escape(shown)}</text>'
        )
        full = room * total / largest
        flagged_width = room * marked / largest
        if full - flagged_width > 0:
            parts.append(f'<rect x="{start:.1f}" y="{y + 4}" width="{full - flagged_width:.1f}" height="16" fill="{BAR}"/>')
        if flagged_width > 0:
            parts.append(
                f'<rect x="{start + full - flagged_width:.1f}" y="{y + 4}" width="{flagged_width:.1f}" height="16" fill="{ACCENT}"/>'
            )
        parts.append(f'<text x="{start + max(full, 1) + 8:.1f}" y="{y + 16}" fill="{MUTED}">{escape(values[index])}</text>')
    parts.append("</svg>")
    return "\n".join(parts)

from __future__ import annotations

import ipaddress
import re
from bisect import bisect_left, bisect_right
from collections import Counter, defaultdict
from dataclasses import dataclass, field as dataclass_field
from datetime import datetime, timedelta
from string import Formatter
from typing import Callable

from ..model import Event
from ..timeutil import fmt_duration, parse_duration

SEVERITIES = ("critical", "high", "medium", "low", "info")
WEEKDAYS = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")
EVIDENCE_LIMIT = 5

Predicate = Callable[[Event], bool]


class RuleError(ValueError):
    pass


@dataclass(frozen=True)
class Mitre:
    id: str
    name: str
    tactic: str

    @property
    def url(self) -> str:
        return "https://attack.mitre.org/techniques/" + "/".join(self.id.split(".")) + "/"


@dataclass
class Rule:
    id: str
    title: str
    severity: str
    mitre: Mitre
    description: str
    response: str
    predicate: Predicate
    conditions: list[str]
    fields: tuple[str, ...]
    group_by: tuple[str, ...] = ()
    kind: str = "each"
    count: int = 0
    window: timedelta | None = None
    field: str = ""
    min_history: int = 0
    pre_predicate: Predicate | None = None
    pre_conditions: list[str] = dataclass_field(default_factory=list)
    show: str = ""
    summary: str = ""
    origin: str = ""

    def trigger_text(self) -> str:
        # условие срабатывания словами, для отчета
        scope = f" per {', '.join(self.group_by)}" if self.group_by else ""
        if self.kind == "threshold":
            return f"at least {self.count} matching events within {fmt_duration(self.window)}{scope}"
        if self.kind == "distinct":
            return f"at least {self.count} different values of {self.field} within {fmt_duration(self.window)}{scope}"
        if self.kind == "first_seen":
            return f"a value of {self.field} not seen before{scope}, after at least {self.min_history} earlier matching events"
        if self.kind == "preceded_by":
            return (
                f"a matching event preceded within {fmt_duration(self.window)} by at least {self.count} events"
                f"{scope} where " + " and ".join(self.pre_conditions)
            )
        return f"every matching event{scope}"


@dataclass
class Finding:
    rule: Rule
    group: dict[str, str]
    count: int
    first: datetime
    last: datetime
    evidence: list[Event]
    facts: dict[str, str]
    summary_parts: list[tuple[str, bool]]

    @property
    def summary(self) -> str:
        return "".join(text for text, _ in self.summary_parts)


# условия


def _as_list(value) -> list:
    return value if isinstance(value, list) else [value]


def _fold(value) -> str:
    return str(value).casefold()


def _preview(values: list, limit: int = 6) -> str:
    shown = ", ".join(str(value) for value in values[:limit])
    return shown + (f", … ({len(values)} in total)" if len(values) > limit else "")


def _number(value) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _networks(arg, where: str) -> list:
    try:
        return [ipaddress.ip_network(str(item), strict=False) for item in _as_list(arg)]
    except ValueError as error:
        raise RuleError(f"{where}: {error}") from None


def _in_networks(value: str, networks: list) -> bool | None:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return None
    return any(address.version == network.version and address in network for network in networks)


def _regexes(arg, where: str) -> list[re.Pattern]:
    try:
        return [re.compile(str(item), re.IGNORECASE) for item in _as_list(arg)]
    except re.error as error:
        raise RuleError(f"{where}: invalid regular expression: {error}") from None


def _compare(name: str, op: str, arg, where: str) -> tuple[Predicate, str]:
    if op in ("eq", "ne"):
        want = _fold(arg)
        if op == "eq":
            return (lambda e: _fold(e.get(name)) == want), f"{name} = {arg}"
        return (lambda e: _fold(e.get(name)) != want), f"{name} ≠ {arg}"
    if op in ("in", "not_in"):
        wanted = {_fold(item) for item in _as_list(arg)}
        if op == "in":
            return (lambda e: _fold(e.get(name)) in wanted), f"{name} in [{_preview(_as_list(arg))}]"
        return (lambda e: _fold(e.get(name)) not in wanted), f"{name} not in [{_preview(_as_list(arg))}]"
    if op in ("contains", "not_contains"):
        needles = [_fold(item) for item in _as_list(arg)]
        if op == "contains":
            return (
                lambda e: any(needle in _fold(e.get(name)) for needle in needles)
            ), f"{name} contains [{_preview(_as_list(arg))}]"
        return (
            lambda e: not any(needle in _fold(e.get(name)) for needle in needles)
        ), f"{name} does not contain [{_preview(_as_list(arg))}]"
    if op in ("startswith", "endswith"):
        affixes = tuple(_fold(item) for item in _as_list(arg))
        if op == "startswith":
            return (lambda e: _fold(e.get(name)).startswith(affixes)), f"{name} starts with [{_preview(_as_list(arg))}]"
        return (lambda e: _fold(e.get(name)).endswith(affixes)), f"{name} ends with [{_preview(_as_list(arg))}]"
    if op in ("regex", "not_regex"):
        patterns = _regexes(arg, where)
        shown = " | ".join(pattern.pattern for pattern in patterns)
        shown = shown if len(shown) <= 90 else shown[:87] + "…"
        if op == "regex":
            return (lambda e: any(p.search(e.get(name)) for p in patterns)), f"{name} matches /{shown}/"
        return (lambda e: not any(p.search(e.get(name)) for p in patterns)), f"{name} does not match /{shown}/"
    if op in ("gt", "gte", "lt", "lte"):
        bound = _number(arg)
        if bound is None:
            raise RuleError(f"{where}: '{op}' needs a number, got {arg!r}")
        test = {
            "gt": lambda value: value > bound,
            "gte": lambda value: value >= bound,
            "lt": lambda value: value < bound,
            "lte": lambda value: value <= bound,
        }[op]
        sign = {"gt": ">", "gte": "≥", "lt": "<", "lte": "≤"}[op]

        def numeric(e: Event) -> bool:
            value = _number(e.get(name))
            return value is not None and test(value)

        return numeric, f"{name} {sign} {arg}"
    if op in ("cidr", "not_cidr"):
        networks = _networks(arg, where)
        if op == "cidr":
            return (lambda e: _in_networks(e.get(name), networks) is True), f"{name} inside [{_preview(_as_list(arg))}]"
        return (lambda e: _in_networks(e.get(name), networks) is False), f"{name} outside [{_preview(_as_list(arg))}]"
    if op == "exists":
        if not isinstance(arg, bool):
            raise RuleError(f"{where}: 'exists' needs true or false")
        if arg:
            return (lambda e: bool(e.get(name))), f"{name} is recorded"
        return (lambda e: not e.get(name)), f"{name} is not recorded"
    raise RuleError(f"{where}: unknown operator '{op}' for field '{name}'")


def _resolve(value, lists: dict[str, list], where: str):
    if isinstance(value, str) and value.startswith("$"):
        name = value[1:]
        if name not in lists:
            raise RuleError(f"{where}: list '{name}' is not defined under 'lists'")
        return list(lists[name])
    return value


def _minutes(text, where: str) -> int:
    match = re.match(r"^\s*(\d{1,2}):(\d{2})\s*$", str(text))
    if not match or int(match.group(1)) > 23 or int(match.group(2)) > 59:
        raise RuleError(f"{where}: time of day must look like 05:59, got {text!r}")
    return int(match.group(1)) * 60 + int(match.group(2))


def _time_of_day(value, where: str) -> tuple[Predicate, str]:
    bounds = value.get("between") if isinstance(value, dict) else value
    if not isinstance(bounds, list) or len(bounds) != 2:
        raise RuleError(f"{where}: time_of_day needs between: [start, end]")
    start, end = _minutes(bounds[0], where), _minutes(bounds[1], where)

    def inside(e: Event) -> bool:
        minute = e.time.hour * 60 + e.time.minute
        return start <= minute <= end if start <= end else minute >= start or minute <= end

    return inside, f"time of day between {bounds[0]} and {bounds[1]}"


def _weekday(value, where: str) -> tuple[Predicate, str]:
    names = [_fold(item)[:3] for item in _as_list(value)]
    unknown = [name for name in names if name not in WEEKDAYS]
    if unknown:
        raise RuleError(f"{where}: unknown weekday {unknown[0]!r}; use mon, tue, wed, thu, fri, sat, sun")
    days = {WEEKDAYS.index(name) for name in names}
    return (lambda e: e.time.weekday() in days), f"weekday in [{', '.join(names)}]"


def compile_match(spec, lists: dict[str, list], where: str) -> tuple[Predicate, list[str], set[str]]:
    # match -> (предикат, описание словами, какие поля читает)
    if not isinstance(spec, dict) or not spec:
        raise RuleError(f"{where}: 'match' must be a non-empty mapping")
    predicates: list[Predicate] = []
    wording: list[str] = []
    fields: set[str] = set()
    for key, value in spec.items():
        if key in ("any", "all"):
            if not isinstance(value, list) or not value:
                raise RuleError(f"{where}: '{key}' needs a list of condition mappings")
            branches = [compile_match(item, lists, where) for item in value]
            tests = [branch[0] for branch in branches]
            combine = any if key == "any" else all
            predicates.append(lambda e, tests=tests, combine=combine: combine(test(e) for test in tests))
            joiner = " or " if key == "any" else " and "
            wording.append("(" + joiner.join(" and ".join(branch[1]) for branch in branches) + ")")
            for branch in branches:
                fields |= branch[2]
        elif key == "not":
            test, text, used = compile_match(value, lists, where)
            predicates.append(lambda e, test=test: not test(e))
            wording.append("not (" + " and ".join(text) + ")")
            fields |= used
        elif key == "time_of_day":
            test, text = _time_of_day(value, where)
            predicates.append(test)
            wording.append(text)
        elif key == "weekday":
            test, text = _weekday(value, where)
            predicates.append(test)
            wording.append(text)
        else:
            value = _resolve(value, lists, where)
            if isinstance(value, dict):
                operations = value
            elif isinstance(value, list):
                operations = {"in": value}
            else:
                operations = {"eq": value}
            if not operations:
                raise RuleError(f"{where}: field '{key}' has no condition")
            for op, arg in operations.items():
                test, text = _compare(str(key), str(op), _resolve(arg, lists, where), where)
                predicates.append(test)
                wording.append(text)
            fields.add(str(key))
    return (lambda e: all(test(e) for test in predicates)), wording, fields


# сборка правил

_RULE_KEYS = {
    "id", "title", "severity", "mitre", "description", "response", "match", "group_by",
    "threshold", "distinct", "first_seen", "preceded_by", "show", "summary", "enabled",
}
_KINDS = ("threshold", "distinct", "first_seen", "preceded_by")


def _positive_int(value, where: str, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise RuleError(f"{where}: '{name}' must be a whole number of 1 or more")
    return value


def _window(params: dict, where: str) -> timedelta:
    try:
        return parse_duration(params.get("window", ""))
    except (ValueError, OverflowError) as error:
        raise RuleError(f"{where}: {error}") from None


def build_rule(spec, lists: dict[str, list], origin: str) -> Rule | None:
    if not isinstance(spec, dict):
        raise RuleError(f"{origin}: every rule must be a mapping")
    rule_id = str(spec.get("id", "")).strip()
    where = f"{origin}: rule '{rule_id or '?'}'"
    if not rule_id:
        raise RuleError(f"{origin}: a rule has no 'id'")
    unknown = sorted(set(spec) - _RULE_KEYS)
    if unknown:
        raise RuleError(f"{where}: unknown key '{unknown[0]}'")
    if spec.get("enabled", True) is False:
        return None
    for required in ("title", "severity", "mitre", "match"):
        if not spec.get(required):
            raise RuleError(f"{where}: '{required}' is required")
    severity = str(spec["severity"]).lower()
    if severity not in SEVERITIES:
        raise RuleError(f"{where}: severity must be one of {', '.join(SEVERITIES)}")
    mitre = spec["mitre"]
    if not isinstance(mitre, dict) or not re.match(r"^T\d{4}(\.\d{3})?$", str(mitre.get("id", ""))):
        raise RuleError(f"{where}: 'mitre.id' must be an ATT&CK technique id such as T1110 or T1110.001")

    predicate, conditions, fields = compile_match(spec["match"], lists, where)
    kinds = [kind for kind in _KINDS if kind in spec]
    if len(kinds) > 1:
        raise RuleError(f"{where}: use only one of {', '.join(_KINDS)}")
    group_by = tuple(str(name) for name in _as_list(spec.get("group_by") or []))
    rule = Rule(
        id=rule_id,
        title=str(spec["title"]).strip(),
        severity=severity,
        mitre=Mitre(str(mitre["id"]), str(mitre.get("name", "")).strip(), str(mitre.get("tactic", "")).strip()),
        description=" ".join(str(spec.get("description", "")).split()),
        response=" ".join(str(spec.get("response", "")).split()),
        predicate=predicate,
        conditions=conditions,
        fields=(),
        group_by=group_by,
        show=str(spec.get("show", "")),
        summary=str(spec.get("summary", "")).strip(),
        origin=origin,
    )
    if kinds:
        rule.kind = kinds[0]
        params = spec[rule.kind]
        if not isinstance(params, dict):
            raise RuleError(f"{where}: '{rule.kind}' must be a mapping")
        if rule.kind == "threshold":
            rule.count = _positive_int(params.get("count"), where, "threshold.count")
            rule.window = _window(params, where)
        elif rule.kind == "distinct":
            rule.field = str(params.get("field", ""))
            rule.count = _positive_int(params.get("count"), where, "distinct.count")
            rule.window = _window(params, where)
        elif rule.kind == "first_seen":
            rule.field = str(params.get("field", ""))
            rule.min_history = _positive_int(params.get("min_history", 1), where, "first_seen.min_history")
        else:
            rule.pre_predicate, rule.pre_conditions, used = compile_match(params.get("match"), lists, where)
            fields |= used
            rule.count = _positive_int(params.get("count", 1), where, "preceded_by.count")
            rule.window = _window(params, where)
        if rule.kind in ("distinct", "first_seen") and not rule.field:
            raise RuleError(f"{where}: '{rule.kind}.field' is required")
    extras = [rule.field, rule.show, *group_by]
    rule.fields = tuple(sorted(fields | {name for name in extras if name}))
    return rule


# выполнение


_OWN_VALUES = {"count", "peak", "window", "distinct", "precursors"}


def _uniq(events: list[Event], name: str) -> list[str]:
    counts = Counter(event.get(name) for event in events if event.get(name))
    return [value for value, _ in sorted(counts.items(), key=lambda item: (-item[1], item[0]))]


def _join(values: list[str], limit: int = 5) -> str:
    shown = ", ".join(values[:limit])
    return shown + (f" and {len(values) - limit} more" if len(values) > limit else "")


def _default_summary(rule: Rule) -> str:
    scope = "".join(f", {name} {{{name}}}" for name in rule.group_by)
    if rule.kind == "threshold":
        return "{count} matching events" + scope + "; up to {peak} within {window}"
    if rule.kind == "distinct":
        return "{distinct} different values of " + rule.field + scope + ", up to {peak} within {window}: {values}"
    if rule.kind == "first_seen":
        return rule.field + " not seen before" + scope + ": {values}"
    if rule.kind == "preceded_by":
        return "{count} matching events" + scope + " after {precursors} preceding events within {window}"
    return "{count} matching events" + scope


def _summary(rule: Rule, group: dict[str, str], count: int, facts: dict[str, str]) -> list[tuple[str, bool]]:
    # куски (текст, взято ли из лога), чтобы отчет пометил цитаты
    values = {"count": str(count), "window": fmt_duration(rule.window) if rule.window else "", **facts}
    values.update({name: value or "(not recorded)" for name, value in group.items()})
    template = rule.summary or _default_summary(rule)
    pieces: list[tuple[str, bool]] = []
    try:
        for literal, name, _, _ in Formatter().parse(template):
            if literal:
                pieces.append((literal, False))
            if name:
                pieces.append((values.get(name, "?"), name not in _OWN_VALUES))
    except ValueError:
        return [(template, False)]
    return pieces


def _key(event: Event, names: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(event.get(name) for name in names)


def _finding(rule: Rule, key: tuple[str, ...], matches: list[Event], evidence: list[Event],
             facts: dict[str, str], count: int | None = None) -> Finding:
    group = dict(zip(rule.group_by, key))
    if rule.show and "values" not in facts:
        facts["values"] = _join(_uniq(matches, rule.show))
    total = len(matches) if count is None else count
    return Finding(
        rule=rule,
        group=group,
        count=total,
        first=matches[0].time,
        last=matches[-1].time,
        evidence=evidence[:EVIDENCE_LIMIT],
        facts=facts,
        summary_parts=_summary(rule, group, total, facts),
    )


def _threshold(rule: Rule, key, matches: list[Event]) -> Finding | None:
    left, peak, trigger = 0, 0, None
    for right, event in enumerate(matches):
        while event.time - matches[left].time > rule.window:
            left += 1
        size = right - left + 1
        peak = max(peak, size)
        if trigger is None and size >= rule.count:
            trigger = left
    if trigger is None:
        return None
    return _finding(rule, key, matches, matches[trigger:], {"peak": str(peak)})


def _distinct(rule: Rule, key, matches: list[Event]) -> Finding | None:
    left, peak = 0, 0
    inside: Counter = Counter()
    trigger: tuple[int, int] | None = None
    for right, event in enumerate(matches):
        inside[event.get(rule.field)] += 1
        while event.time - matches[left].time > rule.window:
            value = matches[left].get(rule.field)
            inside[value] -= 1
            if not inside[value]:
                del inside[value]
            left += 1
        together = sum(1 for value in inside if value)
        peak = max(peak, together)
        if trigger is None and together >= rule.count:
            trigger = (left, right)
    if trigger is None:
        return None
    window = matches[trigger[0]: trigger[1] + 1]
    first_of_each: dict[str, Event] = {}
    for event in window:
        first_of_each.setdefault(event.get(rule.field), event)
    values = _uniq(matches, rule.field)
    facts = {"distinct": str(len(values)), "peak": str(peak), "values": _join(values)}
    return _finding(rule, key, matches, list(first_of_each.values()), facts)


def _first_seen(rule: Rule, key, matches: list[Event]) -> Finding | None:
    known: list[str] = []
    seen: set[str] = set()
    history = 0
    hits: list[Event] = []
    for event in matches:
        value = event.get(rule.field)
        if not value:
            continue
        if value not in seen:
            if history >= rule.min_history:
                hits.append(event)
            else:
                known.append(value)
            seen.add(value)
        history += 1
    if not hits:
        return None
    facts = {"values": _join(_uniq(hits, rule.field)), "known": _join(known)}
    return _finding(rule, key, hits, hits, facts)


def _preceded_by(rule: Rule, key, matches: list[Event], precursors: list[Event]) -> Finding | None:
    stamps = [event.time for event in precursors]
    hits: list[Event] = []
    most = 0
    lead: list[Event] = []
    for event in matches:
        start = bisect_left(stamps, event.time - rule.window)
        end = bisect_right(stamps, event.time)
        earlier = [item for item in precursors[start:end] if item is not event and (item.time, item.line) < (event.time, event.line)]
        if len(earlier) >= rule.count:
            if not hits:
                lead = earlier[-2:]
            hits.append(event)
            most = max(most, len(earlier))
    if not hits:
        return None
    evidence = sorted(lead + hits[: EVIDENCE_LIMIT - len(lead)], key=lambda event: (event.time, event.line))
    return _finding(rule, key, hits, evidence, {"precursors": str(most)})


def run_rules(rules: list[Rule], events: list[Event]) -> list[Finding]:
    ordered = sorted(events, key=lambda event: (event.time, event.line))
    findings: list[Finding] = []
    for rule in rules:
        groups: dict[tuple[str, ...], list[Event]] = defaultdict(list)
        for event in ordered:
            if rule.predicate(event):
                groups[_key(event, rule.group_by)].append(event)
        if not groups:
            continue
        before: dict[tuple[str, ...], list[Event]] = defaultdict(list)
        if rule.kind == "preceded_by":
            for event in ordered:
                if rule.pre_predicate(event):
                    before[_key(event, rule.group_by)].append(event)
        for key, matches in groups.items():
            if rule.kind == "threshold":
                finding = _threshold(rule, key, matches)
            elif rule.kind == "distinct":
                finding = _distinct(rule, key, matches)
            elif rule.kind == "first_seen":
                finding = _first_seen(rule, key, matches)
            elif rule.kind == "preceded_by":
                finding = _preceded_by(rule, key, matches, before.get(key, []))
            else:
                finding = _finding(rule, key, matches, matches, {})
            if finding is not None:
                findings.append(finding)
    rank = {name: position for position, name in enumerate(SEVERITIES)}
    findings.sort(key=lambda item: (rank[item.rule.severity], -item.count, item.first, item.rule.id))
    return findings

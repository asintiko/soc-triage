from __future__ import annotations

from dataclasses import dataclass
from importlib import resources
from pathlib import Path

import yaml

from .engine import Finding, Mitre, Rule, RuleError, SEVERITIES, build_rule, run_rules

__all__ = ["Finding", "Mitre", "Rule", "RuleError", "RuleSet", "SEVERITIES", "load_rules", "run_rules"]

DEFAULT_NAME = "default.yaml"


@dataclass
class RuleSet:
    rules: list[Rule]
    origins: list[str]


def _read(text: str, origin: str) -> dict:
    try:
        document = yaml.safe_load(text)
    except yaml.YAMLError as error:
        raise RuleError(f"{origin}: not valid YAML: {error}") from None
    if not isinstance(document, dict) or not isinstance(document.get("rules"), list):
        raise RuleError(f"{origin}: expected a mapping with a 'rules' list")
    lists = document.get("lists") or {}
    if not isinstance(lists, dict) or not all(isinstance(value, list) for value in lists.values()):
        raise RuleError(f"{origin}: 'lists' must map names to lists of values")
    return document


def load_rules(files: list[Path] | None = None, extra: list[Path] | None = None) -> RuleSet:
    # files или встроенный набор, плюс extra; списки из раннего файла видны в следующих
    sources: list[tuple[str, str]] = []
    if files:
        sources += [(Path(path).name, Path(path).read_text(encoding="utf-8")) for path in files]
    else:
        builtin = resources.files(__package__).joinpath(DEFAULT_NAME).read_text(encoding="utf-8")
        sources.append((f"built-in {DEFAULT_NAME}", builtin))
    sources += [(Path(path).name, Path(path).read_text(encoding="utf-8")) for path in extra or []]

    lists: dict[str, list] = {}
    rules: list[Rule] = []
    seen: dict[str, str] = {}
    for origin, text in sources:
        document = _read(text, origin)
        lists.update(document.get("lists") or {})
        for spec in document["rules"]:
            rule = build_rule(spec, lists, origin)
            if rule is None:
                continue
            if rule.id in seen:
                raise RuleError(f"{origin}: rule id '{rule.id}' is already defined in {seen[rule.id]}")
            seen[rule.id] = origin
            rules.append(rule)
    return RuleSet(rules, [origin for origin, _ in sources])

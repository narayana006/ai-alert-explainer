"""Rules: small checks that record a hard fact about an alert and vote for a label.

A rule is any callable wrapped in ``Rule``. It returns a ``RuleResult`` when
it has something to say and ``None`` when it does not apply. Rules can be
written in Python or loaded from a list of dicts (JSON) with
``rules_from_config``.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from .alert import Alert

ACT = "ACT"
WATCH = "WATCH"
IGNORE = "IGNORE"
LABELS = (ACT, WATCH, IGNORE)


@dataclass(frozen=True)
class RuleResult:
    rule: str
    label: str
    weight: float
    fact: str


@dataclass(frozen=True)
class Rule:
    name: str
    check: Callable[[Alert], RuleResult | None]

    def __call__(self, alert: Alert) -> RuleResult | None:
        return self.check(alert)


def _as_number(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value.strip().rstrip("%"))
        except ValueError:
            return None
    return None


def _text(value: Any) -> str:
    return str(value).lower()


def _compare(op: str):
    def test(actual: Any, expected: Any) -> bool:
        left, right = _as_number(actual), _as_number(expected)
        if left is None or right is None:
            return False
        return {"gt": left > right, "gte": left >= right, "lt": left < right, "lte": left <= right}[
            op
        ]

    return test


# operator -> (test(actual, expected), words used in the generated fact)
OPERATORS: dict[str, tuple[Callable[[Any, Any], bool], str]] = {
    "equals": (lambda a, e: a is not None and _text(a) == _text(e), "is"),
    "not_equals": (lambda a, e: a is None or _text(a) != _text(e), "is not"),
    "in": (lambda a, e: a is not None and _text(a) in [_text(x) for x in e], "is one of"),
    "matches": (lambda a, e: a is not None and re.search(e, str(a)) is not None, "matches"),
    "gt": (_compare("gt"), "above"),
    "gte": (_compare("gte"), "at least"),
    "lt": (_compare("lt"), "below"),
    "lte": (_compare("lte"), "at most"),
    "exists": (lambda a, e: (a is not None) == bool(e), "is present:"),
}


@dataclass(frozen=True)
class Condition:
    field: str
    op: str
    expected: Any

    def holds(self, alert: Alert) -> bool:
        return OPERATORS[self.op][0](alert.get(self.field), self.expected)

    def describe(self, alert: Alert) -> str:
        actual = alert.get(self.field)
        words = OPERATORS[self.op][1]
        if self.op in ("gt", "gte", "lt", "lte"):
            return f"{self.field} is {actual}, {words} {self.expected}"
        if self.op in ("equals", "in"):
            return f"{self.field} is {actual}"
        return f"{self.field} {words} {self.expected}"


def _validate_label(label: str) -> str:
    label = str(label).upper()
    if label not in LABELS:
        raise ValueError(f"label must be one of {', '.join(LABELS)}, not {label!r}")
    return label


def match(
    name: str,
    conditions: list[Condition],
    label: str,
    weight: float = 1.0,
    fact: str | None = None,
) -> Rule:
    """A rule that votes for ``label`` when every condition holds."""
    label = _validate_label(label)
    if weight <= 0:
        raise ValueError(f"rule {name!r}: weight must be greater than 0")
    if not conditions:
        raise ValueError(f"rule {name!r}: at least one condition is required")

    def check(alert: Alert) -> RuleResult | None:
        if not all(c.holds(alert) for c in conditions):
            return None
        text = fact or " and ".join(c.describe(alert) for c in conditions)
        return RuleResult(rule=name, label=label, weight=float(weight), fact=text)

    return Rule(name=name, check=check)


def _condition_from_config(rule_name: str, raw: Any) -> Condition:
    if not isinstance(raw, dict) or "field" not in raw:
        raise ValueError(f"rule {rule_name!r}: each condition needs a 'field'")
    ops = [key for key in raw if key != "field"]
    if len(ops) != 1 or ops[0] not in OPERATORS:
        raise ValueError(
            f"rule {rule_name!r}: a condition needs exactly one of {', '.join(OPERATORS)}"
        )
    op, expected = ops[0], raw[ops[0]]
    if op == "in" and not isinstance(expected, list):
        raise ValueError(f"rule {rule_name!r}: 'in' needs a list")
    if op == "matches":
        try:
            re.compile(expected)
        except (re.error, TypeError) as exc:
            raise ValueError(f"rule {rule_name!r}: bad regular expression: {exc}") from exc
    return Condition(field=str(raw["field"]), op=op, expected=expected)


def rules_from_config(config: Any) -> list[Rule]:
    """Build rules from a list of dicts, for example loaded from a JSON file.

    Each entry: ``{"name": ..., "when": condition or [conditions], "label":
    "ACT" | "WATCH" | "IGNORE", "weight": 1.0, "fact": "optional text"}``.
    A condition is ``{"field": "labels.env", "equals": "prod"}``; see
    ``OPERATORS`` for the other operators. All conditions must hold.
    """
    if not isinstance(config, list):
        raise ValueError("rules must be a list")
    rules = []
    for index, entry in enumerate(config, start=1):
        if not isinstance(entry, dict):
            raise ValueError(f"rule {index} is not an object")
        name = str(entry.get("name") or f"rule-{index}")
        if "label" not in entry or "when" not in entry:
            raise ValueError(f"rule {name!r}: 'when' and 'label' are required")
        when = entry["when"] if isinstance(entry["when"], list) else [entry["when"]]
        conditions = [_condition_from_config(name, raw) for raw in when]
        try:
            weight = float(entry.get("weight", 1.0))
        except (TypeError, ValueError) as exc:
            raise ValueError(f"rule {name!r}: weight must be a number") from exc
        rules.append(match(name, conditions, entry["label"], weight, entry.get("fact")))
    return rules


def default_rules() -> list[Rule]:
    """Generic rules used when you supply none: severity and resolved status only."""
    return rules_from_config(
        [
            {"name": "resolved", "when": {"field": "status", "in": ["resolved", "ok", "closed"]},
             "label": IGNORE, "weight": 3, "fact": "the alert is already resolved"},
            {"name": "severity-critical",
             "when": {"field": "severity", "in": ["critical", "page", "p1", "sev1", "error"]},
             "label": ACT},
            {"name": "severity-warning",
             "when": {"field": "severity", "in": ["warning", "warn", "p2", "p3", "sev2"]},
             "label": WATCH},
            {"name": "severity-info",
             "when": {"field": "severity", "in": ["info", "informational", "notice", "debug"]},
             "label": IGNORE},
        ]
    )


def run_rules(rules: list[Rule], alert: Alert) -> tuple[list[RuleResult], list[str]]:
    """Run every rule; a rule that raises is reported, not fatal."""
    results: list[RuleResult] = []
    errors: list[str] = []
    for rule in rules:
        try:
            result = rule(alert)
        except Exception as exc:  # a broken user rule must not lose the alert
            errors.append(f"{getattr(rule, 'name', 'rule')}: {exc}")
            continue
        if result is None:
            continue
        if result.label not in LABELS or result.weight <= 0:
            errors.append(f"{result.rule}: returned an invalid label or weight")
            continue
        results.append(result)
    return results, errors

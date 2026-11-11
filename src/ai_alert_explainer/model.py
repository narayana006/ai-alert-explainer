"""Optional model opinion behind a provider-neutral interface.

Nothing here talks to a network. A model is any object with an ``assess``
method; ``PromptModel`` adapts a plain ``complete(prompt) -> str`` function,
which you write around whatever text-generation service you use.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol

from .alert import Alert
from .rules import LABELS, RuleResult


class ModelError(Exception):
    """The model could not be reached or its reply could not be understood."""


@dataclass(frozen=True)
class ModelOpinion:
    label: str
    confidence: float  # 0.0 to 1.0, as reported by the model
    reasoning: str


class Model(Protocol):
    def assess(self, alert: Alert, rule_results: list[RuleResult]) -> ModelOpinion: ...


def build_prompt(alert: Alert, rule_results: list[RuleResult]) -> str:
    facts = "\n".join(f"- {r.fact} (rule {r.rule} says {r.label})" for r in rule_results)
    view = {k: v for k, v in alert.to_dict().items() if k != "raw"}
    return (
        "You are helping an on-call engineer decide what to do about an alert.\n"
        "Alert:\n"
        f"{json.dumps(view, indent=2, sort_keys=True, default=str)}\n\n"
        "Facts already established by rules:\n"
        f"{facts or '- none'}\n\n"
        "Reply with one JSON object and nothing else, with these keys:\n"
        '  "label": "ACT", "WATCH" or "IGNORE"\n'
        '  "confidence": a number from 0 to 1\n'
        '  "reasoning": one or two plain-English sentences\n'
    )


def parse_reply(reply: str) -> ModelOpinion:
    """Read the model's JSON reply; tolerate text or code fences around it."""
    if not isinstance(reply, str):
        raise ModelError("the model reply is not text")
    found = re.search(r"\{.*\}", reply, re.DOTALL)
    if not found:
        raise ModelError("the model reply contains no JSON object")
    try:
        data = json.loads(found.group(0))
    except json.JSONDecodeError as exc:
        raise ModelError(f"the model reply is not valid JSON: {exc.msg}") from exc
    label = str(data.get("label", "")).upper()
    if label not in LABELS:
        raise ModelError(f"the model returned an unknown label: {data.get('label')!r}")
    confidence = data.get("confidence")
    if isinstance(confidence, bool) or not isinstance(confidence, (int, float)):
        raise ModelError("the model returned no numeric confidence")
    return ModelOpinion(
        label=label,
        confidence=min(1.0, max(0.0, float(confidence))),
        reasoning=str(data.get("reasoning", "")).strip(),
    )


class PromptModel:
    """Wrap a ``complete(prompt) -> str`` function as a Model."""

    def __init__(self, complete: Callable[[str], str]):
        self._complete = complete

    def assess(self, alert: Alert, rule_results: list[RuleResult]) -> ModelOpinion:
        try:
            reply = self._complete(build_prompt(alert, rule_results))
        except Exception as exc:
            raise ModelError(f"the model call failed: {exc}") from exc
        return parse_reply(reply)
